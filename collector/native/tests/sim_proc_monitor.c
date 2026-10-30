/* Regression test: replays the Test A/B sequence observed on 2026-10-30 against fake guest memory.
   Build (from collector/native/tests): gcc -Wall -o sim sim_proc_monitor.c fakevmi.c $(pkg-config --cflags libvmi glib-2.0) && ./sim
   Expected summary: created=4 exec=4 terminated=4 reused=2 tracked_left=1 */
#define main monitor_main
#include "../vmi_proc_monitor.c"
#undef main
void mset(addr_t a, uint64_t v); void sset(addr_t a,const char*s); extern addr_t INIT_TASK;
enum { TASKS=0x8b8, NAME=0xbb8, PID=0x9c0, MM=0x908, PGD=0x50, CUR=0x1fbc0 };
#define DM 0xffff888000000000ULL
static addr_t order[64]; static int nord;
static void relink(void){ /* circular list init_task -> order[] -> init_task */
  addr_t prev=INIT_TASK; for(int i=0;i<nord;i++){ mset(prev+TASKS, order[i]+TASKS); prev=order[i]; } mset(prev+TASKS, INIT_TASK+TASKS); }
static addr_t mk_task(int pid,const char*name,addr_t dtb){ static addr_t next=DM+0x10000000; addr_t t=next; next+=0x2000;
  addr_t mm=t+0x1000; mset(t+MM, dtb?mm:0); mset(mm+PGD, DM+dtb); mset(t+PID,pid); mset(t+PID+4,pid); sset(t+NAME,name); return t; }
static void set_mm(addr_t t, addr_t dtb, const char*name){ addr_t mm=t+0x1000; mset(mm+PGD, DM+dtb); sset(t+NAME,name); }
static void add(addr_t t){ order[nord++]=t; relink(); }
static void del(addr_t t){ for(int i=0;i<nord;i++) if(order[i]==t){ order[i]=order[--nord]; break;} relink(); }
static x86_registers_t regs; static vmi_event_t ev;
static void cr3(addr_t t, addr_t dtb){ mset(DM+0x900000+CUR, t); regs.gs_base=DM+0x900000; ev.x86_regs=&regs; ev.vcpu_id=1; ev.reg_event.value=dtb|0x1000; cr3_cb(NULL,&ev); }
int main(void){
  tasks_off=TASKS; name_off=NAME; pid_off=PID; mm_off=MM; pgd_off=PGD; current_task_off=CUR; vm_name="sim";
  INIT_TASK=mk_task(0,"swapper",0); addr_t sh=mk_task(875,"bash",0x2ad2000); add(sh);
  snapshot(NULL); for(size_t i=0;i<ncurrent;i++){ track_add(&current[i]); }
  /* Test A: sleep 887 */
  addr_t a=mk_task(887,"bash",0x2b0c000); add(a); cr3(a,0x2b0c000); set_mm(a,0x2bcc000,"sleep"); cr3(a,0x2bcc000);
  reconcile(NULL); del(a); reconcile(NULL); reconcile(NULL);
  /* Test B: 3x /bin/true, exec address space 0x2bcc000 reused each time */
  addr_t t1=mk_task(888,"bash",0x42a6000); add(t1); cr3(t1,0x42a6000); set_mm(t1,0x2bcc000,"true"); cr3(t1,0x2bcc000); del(t1);
  addr_t t2=mk_task(889,"bash",0x2b0a000); add(t2); cr3(t2,0x2b0a000); set_mm(t2,0x2bcc000,"true"); cr3(t2,0x2bcc000); del(t2);
  addr_t t3=mk_task(890,"bash",0x2bd6000); add(t3); cr3(t3,0x2bd6000); set_mm(t3,0x2bcc000,"true"); cr3(t3,0x2bcc000); del(t3);
  reconcile(NULL); reconcile(NULL); reconcile(NULL);
  fprintf(stderr,"SUMMARY created=%llu exec=%llu terminated=%llu reused=%llu tracked_left=%zu\n", n_created_cr3,n_exec,n_terminated,n_reused,ntracked);
  return 0; }
