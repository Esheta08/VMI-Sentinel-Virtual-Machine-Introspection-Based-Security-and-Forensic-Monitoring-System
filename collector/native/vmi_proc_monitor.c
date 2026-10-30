/*
 * vmi_proc_monitor.c - VMI-Sentinel native process collector (KVMI + LibVMI), v3.1
 *
 * Observes guest processes from OUTSIDE the VM. One JSON object per line on
 * stdout; diagnostics on stderr.
 *
 * Events and sources:
 *   PROCESS_OBSERVED   kvmi_snapshot   running when the monitor started
 *   PROCESS_CREATED    kvmi_cr3        new process (PID not tracked yet) seen at a
 *                                      user-mode CR3 load; identity read from the
 *                                      guest's per-CPU current_task
 *   PROCESS_EXEC       kvmi_cr3        known PID now runs a new program: new address
 *                                      space after exec()
 *   PROCESS_CREATED    kvmi_reconcile  found by the periodic task-list check
 *   PROCESS_TERMINATED kvmi_cr3        its address space was reused by another
 *                                      process (so its memory was freed)
 *   PROCESS_TERMINATED kvmi_reconcile  address space and PID absent from the task
 *                                      list; ts = first check that missed it
 *
 * Design notes / limitations (document these in the report):
 *  - The guest uses KPTI: kernel and user page tables differ by 0x1000 and are
 *    merged into one canonical DTB. We act on the USER-half CR3, written on the
 *    return to user mode, when current_task is the task being resumed and exec()
 *    has finished (so the name is final). Assumes KPTI is enabled.
 *  - Process identity is the TGID, read at pid_offset + 4 (tgid directly follows
 *    pid in task_struct for this kernel). Threads therefore map to their process.
 *  - fork() then exec() yields PROCESS_CREATED (parent's name) then PROCESS_EXEC
 *    (new program), same PID. Only the newest address space of a PID can produce
 *    PROCESS_TERMINATED; once a PID is reported terminated, its other tracked
 *    address spaces are marked silent, so one exit is counted once.
 *  - Termination via reconciliation is confirmed after MISSING_CONFIRM checks
 *    RECONCILE_SEC apart, so its timestamp is approximate.
 *  - LibVMI's page cache is flushed before each current_task read so a stale
 *    value is not reused; this adds overhead on every user-mode CR3 load.
 *  - Kernel threads have no user address space and are not reported.
 *  - Intercepting every CR3 write slows the guest; overhead not yet measured.
 *
 * Build:
 *   gcc -O2 -Wall -o vmi_proc_monitor vmi_proc_monitor.c \
 *       $(pkg-config --cflags --libs libvmi glib-2.0)
 * Run:
 *   sudo ./vmi_proc_monitor <vm-name> <kvmi-socket> [current_task-offset]
 *   e.g. sudo ./vmi_proc_monitor vmi-guest /tmp/kvmi.sock 0x1fbc0
 *   (offset from the guest System.map: grep ' current_task$')
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#define MAX_PROCS        4096
#define MAX_TASKS        65536
#define RECONCILE_SEC    2.0
#define MISSING_CONFIRM  2
#define KPTI_USER_BIT    0x1000ULL
#define DTB_MASK         (~0x1FFFULL & ~(1ULL << 63))
#define KERNEL_VA_MIN    0xffff800000000000ULL

struct proc {
    addr_t dtb;
    int pid;                    /* TGID */
    char name[32];
    int missing;
    double missing_since;
    unsigned long long seq;     /* order of tracking, larger = newer */
    int silent;                 /* PID already reported terminated: drop quietly */
};

static struct proc tracked[MAX_PROCS];
static size_t ntracked;
static struct proc current[MAX_PROCS];
static size_t ncurrent;
static unsigned long long next_seq = 1;

static volatile sig_atomic_t interrupted;
static addr_t tasks_off, name_off, pid_off, mm_off, pgd_off;
static addr_t current_task_off;          /* 0 = disabled */
static const char *vm_name;
static unsigned long long n_exec;
static unsigned long long n_cr3_events, n_created_cr3, n_created_rec, n_terminated,
                          n_reused, n_rec_ok, n_rec_skipped, n_cur_ok, n_cur_fail;

static void on_signal(int sig) { (void)sig; interrupted = 1; }

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static struct proc *find(struct proc *arr, size_t n, addr_t dtb)
{
    for (size_t i = 0; i < n; i++)
        if (arr[i].dtb == dtb)
            return &arr[i];
    return NULL;
}

static int pid_present(const struct proc *arr, size_t n, int pid)
{
    if (pid < 0)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (arr[i].pid == pid)
            return 1;
    return 0;
}

/* Is this PID tracked under another, non-silent address space? */
static int pid_tracked_elsewhere(int pid, const struct proc *except)
{
    if (pid < 0)
        return 0;
    for (size_t j = 0; j < ntracked; j++)
        if (&tracked[j] != except && !tracked[j].silent && tracked[j].pid == pid)
            return 1;
    return 0;
}

/* After reporting a PID terminated, silence its other tracked address spaces. */
static void silence_pid(int pid, size_t except)
{
    for (size_t j = 0; j < ntracked; j++)
        if (j != except && tracked[j].pid == pid)
            tracked[j].silent = 1;
}

/* Another tracked address space with the same PID that was tracked later? */
static int has_newer_same_pid(size_t i)
{
    for (size_t j = 0; j < ntracked; j++)
        if (j != i && tracked[j].pid == tracked[i].pid && tracked[j].seq > tracked[i].seq)
            return 1;
    return 0;
}

static void track_add(const struct proc *p)
{
    if (ntracked < MAX_PROCS) {
        tracked[ntracked] = *p;
        tracked[ntracked].missing = 0;
        tracked[ntracked].missing_since = 0;
        tracked[ntracked].seq = next_seq++;
        tracked[ntracked].silent = 0;
        ntracked++;
    }
}

static void track_remove(size_t i)
{
    tracked[i] = tracked[--ntracked];
}

static void json_str(const char *s)
{
    putchar('"');
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
        else if (c < 0x20) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

static void emit(const char *type, const char *source, int pid, const char *name,
                 addr_t dtb, int vcpu, double ts)
{
    printf("{\"event\":\"%s\",\"vm\":", type);
    json_str(vm_name);
    printf(",\"pid\":%d,\"name\":", pid);
    json_str(name ? name : "");
    printf(",\"dtb\":\"0x%" PRIx64 "\",\"vcpu\":%d,\"ts\":%.6f,\"source\":\"%s\"}\n",
           dtb, vcpu, ts, source);
    fflush(stdout);
}

/* Fill pid (TGID) and name of a task_struct. */
static int read_task_identity(vmi_instance_t vmi, addr_t task, struct proc *p)
{
    uint32_t tgid = 0;
    if (VMI_FAILURE == vmi_read_32_va(vmi, task + pid_off + 4, 0, &tgid))
        return 0;
    p->pid = (int)tgid;
    p->name[0] = '\0';
    char *name = vmi_read_str_va(vmi, task + name_off, 0);
    if (name) {
        strncpy(p->name, name, sizeof(p->name) - 1);
        p->name[sizeof(p->name) - 1] = '\0';
        free(name);
    }
    return 1;
}

/* Canonical DTB of a task from task->mm->pgd; 0 for kernel threads. */
static addr_t task_dtb(vmi_instance_t vmi, addr_t task)
{
    addr_t mm = 0, pgd_va = 0, dtb = 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, task + mm_off, 0, &mm) || !mm)
        return 0;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, mm + pgd_off, 0, &pgd_va) || !pgd_va)
        return 0;
    if (VMI_FAILURE == vmi_translate_kv2p(vmi, pgd_va, &dtb))
        return 0;
    return dtb & DTB_MASK;
}

/* Read all user address spaces into current[]. Returns 1 if the walk completed. */
static int snapshot(vmi_instance_t vmi)
{
    addr_t list_head = 0, cur = 0, next = 0;

    ncurrent = 0;
    vmi_pagecache_flush(vmi);
    vmi_v2pcache_flush(vmi, ~0ULL);

    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "init_task", &list_head))
        return 0;
    list_head += tasks_off;
    cur = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur, 0, &next))
        return 0;

    for (int guard = 0; guard < MAX_TASKS; guard++) {
        addr_t task = cur - tasks_off;
        addr_t dtb = task_dtb(vmi, task);

        if (dtb && ncurrent < MAX_PROCS && !find(current, ncurrent, dtb)) {
            struct proc p;
            memset(&p, 0, sizeof(p));
            p.dtb = dtb;
            if (read_task_identity(vmi, task, &p))
                current[ncurrent++] = p;
        }

        cur = next;
        if (cur == list_head)
            return 1;
        if (VMI_FAILURE == vmi_read_addr_va(vmi, cur, 0, &next))
            return 0;
    }
    return 0;
}

/* Per-CPU base (kernel GS base) of the vCPU that raised the event; 0 if unknown. */
static addr_t percpu_base(vmi_instance_t vmi, vmi_event_t *event)
{
    uint64_t base = 0;
    if (event->x86_regs)
        base = event->x86_regs->gs_base;
    if (base < KERNEL_VA_MIN)
        vmi_get_vcpureg(vmi, &base, GS_BASE, event->vcpu_id);
    if (base < KERNEL_VA_MIN)
        vmi_get_vcpureg(vmi, &base, MSR_SHADOW_GS_BASE, event->vcpu_id);
    return base >= KERNEL_VA_MIN ? base : 0;
}

/* Identity of the task being resumed on this vCPU, via per-CPU current_task. */
static int current_identity(vmi_instance_t vmi, vmi_event_t *event, struct proc *p)
{
    if (!current_task_off)
        return 0;
    addr_t base = percpu_base(vmi, event);
    addr_t task = 0;
    if (!base)
        return 0;
    vmi_pagecache_flush(vmi);
    if (VMI_FAILURE == vmi_read_addr_va(vmi, base + current_task_off, 0, &task) ||
        task < KERNEL_VA_MIN)
        return 0;
    return read_task_identity(vmi, task, p);
}

/* tracked[i]'s address space now belongs to another process: close out the old one. */
static void close_replaced(size_t i, const char *source, double ts, int still_alive)
{
    struct proc *tp = &tracked[i];
    if (!tp->silent && tp->pid >= 0 && !has_newer_same_pid(i) && !still_alive) {
        emit("PROCESS_TERMINATED", source, tp->pid, tp->name, tp->dtb, -1, ts);
        n_terminated++;
        silence_pid(tp->pid, i);
    }
}

static void reconcile(vmi_instance_t vmi)
{
    static unsigned char drop[MAX_PROCS];

    if (!snapshot(vmi)) {
        n_rec_skipped++;
        return;
    }
    n_rec_ok++;
    double t = now();
    memset(drop, 0, sizeof(drop));

    /* Pass 1: update state, mark confirmed disappearances. */
    for (size_t i = 0; i < ntracked; i++) {
        struct proc *tp = &tracked[i];
        struct proc *c = find(current, ncurrent, tp->dtb);

        if (c) {
            if (tp->pid >= 0 && c->pid != tp->pid) {
                close_replaced(i, "kvmi_reconcile", t,
                               pid_present(current, ncurrent, tp->pid));
                tp->pid = c->pid;
                memcpy(tp->name, c->name, sizeof(tp->name));
                tp->seq = next_seq++;
                tp->silent = 0;
                emit("PROCESS_CREATED", "kvmi_reconcile", c->pid, c->name, c->dtb, -1, t);
                n_created_rec++;
                n_reused++;
            } else if (tp->pid < 0) {
                tp->pid = c->pid;
                memcpy(tp->name, c->name, sizeof(tp->name));
            }
            tp->missing = 0;
            continue;
        }
        if (tp->missing++ == 0)
            tp->missing_since = t;
        if (tp->missing >= MISSING_CONFIRM)
            drop[i] = 1;
    }

    /* Pass 2: decide TERMINATED before removing anything (newest-per-PID rule). */
    for (size_t i = 0; i < ntracked; i++) {
        struct proc *tp = &tracked[i];
        if (drop[i] && !tp->silent && tp->pid >= 0 && !has_newer_same_pid(i) &&
            !pid_present(current, ncurrent, tp->pid)) {
            emit("PROCESS_TERMINATED", "kvmi_reconcile", tp->pid, tp->name,
                 tp->dtb, -1, tp->missing_since);
            n_terminated++;
            silence_pid(tp->pid, i);
        }
    }

    /* Pass 3: remove from the end so moved entries were already handled. */
    for (size_t i = ntracked; i-- > 0; )
        if (drop[i])
            track_remove(i);

    /* Address spaces the CR3 path did not report. */
    for (size_t j = 0; j < ncurrent; j++) {
        if (!find(tracked, ntracked, current[j].dtb)) {
            track_add(&current[j]);
            emit("PROCESS_CREATED", "kvmi_reconcile", current[j].pid, current[j].name,
                 current[j].dtb, -1, t);
            n_created_rec++;
        }
    }
}

static event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t value = event->reg_event.value;
    n_cr3_events++;

    /* Act only on the user-half CR3: the task is returning to user mode. */
    if (!(value & KPTI_USER_BIT))
        return VMI_EVENT_RESPONSE_NONE;

    addr_t dtb = value & DTB_MASK;
    int vcpu = (int)event->vcpu_id;
    struct proc *tp = find(tracked, ntracked, dtb);
    struct proc p;
    memset(&p, 0, sizeof(p));
    p.dtb = dtb;
    p.pid = -1;

    if (current_identity(vmi, event, &p)) {
        n_cur_ok++;
        if (tp && tp->pid == p.pid && !tp->silent)
            return VMI_EVENT_RESPONSE_NONE;          /* known process */
        int is_exec = pid_tracked_elsewhere(p.pid, tp);
        if (tp) {
            /* Address space reused: the old owner's memory was freed. */
            size_t i = (size_t)(tp - tracked);
            close_replaced(i, "kvmi_cr3", now(), 0);
            tp->pid = p.pid;
            memcpy(tp->name, p.name, sizeof(tp->name));
            tp->seq = next_seq++;
            tp->missing = 0;
            tp->silent = 0;
            n_reused++;
        } else {
            track_add(&p);
        }
        if (is_exec) {
            emit("PROCESS_EXEC", "kvmi_cr3", p.pid, p.name, dtb, vcpu, now());
            n_exec++;
        } else {
            emit("PROCESS_CREATED", "kvmi_cr3", p.pid, p.name, dtb, vcpu, now());
            n_created_cr3++;
        }
        return VMI_EVENT_RESPONSE_NONE;
    }

    /* Fallback (current_task unavailable): v2 behaviour with a list walk. */
    n_cur_fail++;
    if (tp)
        return VMI_EVENT_RESPONSE_NONE;
    snapshot(vmi);
    struct proc *c = find(current, ncurrent, dtb);
    if (c)
        p = *c;
    track_add(&p);
    emit("PROCESS_CREATED", "kvmi_cr3", p.pid, p.name, dtb, vcpu, now());
    n_created_cr3++;
    return VMI_EVENT_RESPONSE_NONE;
}

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <vm-name> <kvmi-socket> [current_task-offset]\n", argv[0]);
        return 1;
    }
    vm_name = argv[1];
    if (argc == 4)
        current_task_off = strtoull(argv[3], NULL, 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    vmi_init_data_t *init_data =
        malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
    if (!init_data)
        return 1;
    init_data->count = 1;
    init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
    init_data->entry[0].data = strdup(argv[2]);

    vmi_instance_t vmi = NULL;
    fprintf(stderr, "[monitor] waiting for VM '%s' on %s (current_task offset 0x%" PRIx64 ")\n",
            vm_name, argv[2], current_task_off);
    if (VMI_FAILURE == vmi_init_complete(&vmi, (void *)vm_name,
                                         VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                                         init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY,
                                         NULL, NULL)) {
        fprintf(stderr, "[monitor] LibVMI init failed\n");
        return 1;
    }

    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_tasks", &tasks_off) ||
        VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &name_off) ||
        VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &pid_off) ||
        VMI_FAILURE == vmi_get_offset(vmi, "linux_mm", &mm_off) ||
        VMI_FAILURE == vmi_get_offset(vmi, "linux_pgd", &pgd_off)) {
        fprintf(stderr, "[monitor] missing offsets in /etc/libvmi.conf\n");
        vmi_destroy(vmi);
        return 1;
    }

    vmi_pause_vm(vmi);
    int complete = snapshot(vmi);
    double t0 = now();
    for (size_t i = 0; i < ncurrent; i++) {
        track_add(&current[i]);
        emit("PROCESS_OBSERVED", "kvmi_snapshot", current[i].pid, current[i].name,
             current[i].dtb, -1, t0);
    }
    vmi_resume_vm(vmi);
    fprintf(stderr, "[monitor] snapshot %s: %zu address spaces\n",
            complete ? "complete" : "PARTIAL", ntracked);

    vmi_event_t cr3_event;
    memset(&cr3_event, 0, sizeof(cr3_event));
#ifdef VMI_EVENTS_VERSION
    cr3_event.version = VMI_EVENTS_VERSION;
#endif
    cr3_event.type = VMI_EVENT_REGISTER;
    cr3_event.reg_event.reg = CR3;
    cr3_event.reg_event.in_access = VMI_REGACCESS_W;
    cr3_event.callback = cr3_cb;

    if (VMI_FAILURE == vmi_register_event(vmi, &cr3_event)) {
        fprintf(stderr, "[monitor] failed to register CR3 event\n");
        vmi_destroy(vmi);
        return 1;
    }
    fprintf(stderr, "[monitor] listening (reconcile every %.1f s; Ctrl+C to stop)\n",
            RECONCILE_SEC);

    double last_reconcile = now();
    while (!interrupted) {
        if (VMI_FAILURE == vmi_events_listen(vmi, 500)) {
            fprintf(stderr, "[monitor] event listen failed\n");
            break;
        }
        if (now() - last_reconcile >= RECONCILE_SEC) {
            reconcile(vmi);
            last_reconcile = now();
        }
    }

    vmi_clear_event(vmi, &cr3_event, NULL);
    vmi_destroy(vmi);
    fprintf(stderr,
            "[monitor] stopped: %llu CR3 events | current_task ok=%llu fail=%llu | "
            "created cr3=%llu reconcile=%llu | exec=%llu | terminated=%llu | dtb_reused=%llu | "
            "reconcile ok=%llu skipped=%llu\n",
            n_cr3_events, n_cur_ok, n_cur_fail, n_created_cr3, n_created_rec, n_exec,
            n_terminated, n_reused, n_rec_ok, n_rec_skipped);
    return 0;
}
