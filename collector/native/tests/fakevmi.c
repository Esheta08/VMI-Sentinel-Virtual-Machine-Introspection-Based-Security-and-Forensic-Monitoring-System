#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
/* tiny fake guest memory */
#define N 4096
static addr_t ka[N]; static uint64_t kv[N]; static int nk;
static addr_t sa[N]; static char sv[N][32]; static int ns;
void mset(addr_t a, uint64_t v){ for(int i=0;i<nk;i++) if(ka[i]==a){kv[i]=v;return;} ka[nk]=a;kv[nk++]=v; }
static int mget(addr_t a, uint64_t *v){ for(int i=0;i<nk;i++) if(ka[i]==a){*v=kv[i];return 1;} return 0; }
void sset(addr_t a,const char*s){ for(int i=0;i<ns;i++) if(sa[i]==a){strcpy(sv[i],s);return;} sa[ns]=a;strcpy(sv[ns++],s); }
addr_t INIT_TASK;
status_t vmi_read_addr_va(vmi_instance_t v, addr_t a, vmi_pid_t p, addr_t *o){ uint64_t x; if(!mget(a,&x)) return VMI_FAILURE; *o=x; return VMI_SUCCESS; }
status_t vmi_read_32_va(vmi_instance_t v, addr_t a, vmi_pid_t p, uint32_t *o){ uint64_t x; if(!mget(a,&x)) return VMI_FAILURE; *o=(uint32_t)x; return VMI_SUCCESS; }
char *vmi_read_str_va(vmi_instance_t v, addr_t a, vmi_pid_t p){ for(int i=0;i<ns;i++) if(sa[i]==a) return strdup(sv[i]); return NULL; }
status_t vmi_translate_kv2p(vmi_instance_t v, addr_t va, addr_t *pa){ *pa = va - 0xffff888000000000ULL; return VMI_SUCCESS; }
status_t vmi_translate_ksym2v(vmi_instance_t v, const char*s, addr_t *o){ *o=INIT_TASK; return VMI_SUCCESS; }
void vmi_pagecache_flush(vmi_instance_t v){} void vmi_v2pcache_flush(vmi_instance_t v, addr_t d){}
status_t vmi_get_vcpureg(vmi_instance_t v, uint64_t *o, reg_t r, unsigned long c){ return VMI_FAILURE; }
status_t vmi_init_complete(vmi_instance_t*a, const void*b, uint64_t c, vmi_init_data_t*d, vmi_config_t e, void*f, vmi_init_error_t*g){return VMI_FAILURE;}
status_t vmi_get_offset(vmi_instance_t v, const char*s, addr_t*o){return VMI_FAILURE;}
status_t vmi_pause_vm(vmi_instance_t v){return 0;} status_t vmi_resume_vm(vmi_instance_t v){return 0;}
status_t vmi_destroy(vmi_instance_t v){return 0;}
status_t vmi_register_event(vmi_instance_t v, vmi_event_t*e){return 0;}
status_t vmi_clear_event(vmi_instance_t v, vmi_event_t*e, void (*f)(vmi_event_t*, status_t)){return 0;}
status_t vmi_events_listen(vmi_instance_t v, uint32_t t){return 0;}
