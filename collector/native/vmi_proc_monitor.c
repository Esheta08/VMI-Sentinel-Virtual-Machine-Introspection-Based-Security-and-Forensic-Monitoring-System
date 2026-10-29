/*
 * vmi_proc_monitor.c - VMI-Sentinel native process collector (KVMI + LibVMI)
 *
 * Detects guest processes from OUTSIDE the VM using live CR3-write events.
 * Prints one JSON object per line on stdout (diagnostics go to stderr):
 *   PROCESS_OBSERVED : process already running when the monitor started
 *   PROCESS_CREATED  : address space (DTB) not seen before (after fork or exec)
 *
 * Design notes / limitations (document these in the report):
 *  - The guest kernel uses KPTI: each process has a kernel and a user page
 *    table differing by 0x1000. Both are merged into one canonical DTB.
 *  - A new DTB is resolved only when its USER-half CR3 is loaded, i.e. when
 *    the task returns to user mode. By then exec() has finished, so the
 *    process name (comm) is final. This assumes KPTI is enabled in the guest.
 *  - A process is detected when it first runs, not at the instant of fork().
 *  - fork() followed by exec() yields two events with the same PID:
 *    first the parent's name (the forked copy), then the new program's name.
 *  - Kernel threads and extra threads share an existing DTB and are not reported.
 *  - Intercepting every CR3 write slows the guest; overhead not yet measured.
 *
 * Build:
 *   gcc -O2 -Wall -o vmi_proc_monitor vmi_proc_monitor.c \
 *       $(pkg-config --cflags --libs libvmi glib-2.0)
 * Run:
 *   sudo ./vmi_proc_monitor <vm-name> <kvmi-socket>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#define MAX_SEEN      16384
#define MAX_TASKS     65536
#define KPTI_USER_BIT 0x1000ULL
#define DTB_MASK      (~0x1FFFULL & ~(1ULL << 63))

static addr_t seen[MAX_SEEN];
static size_t nseen;
static volatile sig_atomic_t interrupted;
static addr_t tasks_off, name_off, pid_off, mm_off, pgd_off;
static const char *vm_name;
static unsigned long long n_cr3_events, n_created;

static void on_signal(int sig) { (void)sig; interrupted = 1; }

static int is_seen(addr_t dtb)
{
    for (size_t i = 0; i < nseen; i++)
        if (seen[i] == dtb)
            return 1;
    return 0;
}

static void mark_seen(addr_t dtb)
{
    if (nseen < MAX_SEEN)
        seen[nseen++] = dtb;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
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

static void emit(const char *type, int pid, const char *name, addr_t dtb, int vcpu)
{
    printf("{\"event\":\"%s\",\"vm\":", type);
    json_str(vm_name);
    printf(",\"pid\":%d,\"name\":", pid);
    json_str(name ? name : "");
    printf(",\"dtb\":\"0x%" PRIx64 "\",\"vcpu\":%d,\"ts\":%.6f,\"source\":\"kvmi_cr3\"}\n",
           dtb, vcpu, now());
    fflush(stdout);
}

/* Read a task's canonical DTB from task->mm->pgd. Returns 0 for kernel threads. */
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

/*
 * Walk the guest task list.
 *  want_dtb == 0 : emit PROCESS_OBSERVED for each user address space, mark it seen.
 *  want_dtb != 0 : find the task owning want_dtb; fill out_pid/out_name, return 1.
 */
static int walk_tasks(vmi_instance_t vmi, addr_t want_dtb, int *out_pid, char **out_name)
{
    addr_t list_head = 0, cur = 0, next = 0;

    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "init_task", &list_head))
        return 0;
    list_head += tasks_off;
    cur = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur, 0, &next))
        return 0;

    for (int guard = 0; guard < MAX_TASKS; guard++) {
        addr_t task = cur - tasks_off;
        addr_t dtb = task_dtb(vmi, task);
        uint32_t pid = 0;

        if (dtb && VMI_SUCCESS == vmi_read_32_va(vmi, task + pid_off, 0, &pid)) {
            if (want_dtb == 0) {
                if (!is_seen(dtb)) {
                    char *name = vmi_read_str_va(vmi, task + name_off, 0);
                    mark_seen(dtb);
                    emit("PROCESS_OBSERVED", (int)pid, name, dtb, -1);
                    free(name);
                }
            } else if (dtb == want_dtb) {
                *out_pid = (int)pid;
                *out_name = vmi_read_str_va(vmi, task + name_off, 0);
                return 1;
            }
        }

        cur = next;
        if (cur == list_head)
            break;
        if (VMI_FAILURE == vmi_read_addr_va(vmi, cur, 0, &next))
            break;
    }
    return 0;
}

static event_response_t cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t value = event->reg_event.value;
    n_cr3_events++;

    /* Act only on the user-half CR3: the task is returning to user mode. */
    if (!(value & KPTI_USER_BIT))
        return VMI_EVENT_RESPONSE_NONE;

    addr_t dtb = value & DTB_MASK;
    if (is_seen(dtb))
        return VMI_EVENT_RESPONSE_NONE;
    mark_seen(dtb);

    int pid = -1;
    char *name = NULL;
    vmi_pagecache_flush(vmi);            /* avoid stale task_struct pages */
    vmi_v2pcache_flush(vmi, ~0ULL);
    walk_tasks(vmi, dtb, &pid, &name);   /* pid stays -1 if not resolved */
    emit("PROCESS_CREATED", pid, name, dtb, (int)event->vcpu_id);
    n_created++;
    free(name);
    return VMI_EVENT_RESPONSE_NONE;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <vm-name> <kvmi-socket>\n", argv[0]);
        return 1;
    }
    vm_name = argv[1];

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
    fprintf(stderr, "[monitor] waiting for VM '%s' on %s ...\n", vm_name, argv[2]);
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

    /* Snapshot of processes already running. */
    vmi_pause_vm(vmi);
    walk_tasks(vmi, 0, NULL, NULL);
    vmi_resume_vm(vmi);
    fprintf(stderr, "[monitor] snapshot done: %zu address spaces\n", nseen);

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
    fprintf(stderr, "[monitor] listening for live events (Ctrl+C to stop)\n");

    while (!interrupted) {
        if (VMI_FAILURE == vmi_events_listen(vmi, 500)) {
            fprintf(stderr, "[monitor] event listen failed\n");
            break;
        }
    }

    vmi_clear_event(vmi, &cr3_event, NULL);
    vmi_destroy(vmi);
    fprintf(stderr, "[monitor] stopped: %llu CR3 events, %llu new address spaces\n",
            n_cr3_events, n_created);
    return 0;
}
