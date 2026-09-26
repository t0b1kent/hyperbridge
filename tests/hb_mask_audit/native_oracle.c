/* Actual x86-64 execution. Single-threaded test harness; not a CPU emulator. */
#define _GNU_SOURCE
#include <cpuid.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <xmmintrin.h>
#include <stddef.h>
#include <string.h>
static sigjmp_buf env;
static volatile sig_atomic_t active, caught;
static void *fault_address;
static void handler(int sig, siginfo_t *info, void *u) {
    (void)u;
    if (!active) _Exit(128 + sig);
    caught=sig; fault_address=info->si_addr; siglongjmp(env,1);
}
int hb_mask_available(void) {
    unsigned a,b,c,d;
    if (!__get_cpuid(1,&a,&b,&c,&d) || !(c&bit_OSXSAVE) || !(c&bit_AVX))return 0;
    unsigned lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));
    if ((lo&0xe6)!=0xe6 || !__get_cpuid_count(7,0,&a,&b,&c,&d))return 0;
    return (b & ((1u<<16)|(1u<<17)|(1u<<30)|(1u<<31)))==((1u<<16)|(1u<<17)|(1u<<30)|(1u<<31));
}
extern void hb_mask_asm(const void *,void *,const void *,const void *,void *,const uint64_t *);
int hb_mask_native(const void *in, void *out, const void *rd, const void *fn,
                   void *wr, const uint64_t *k, uintptr_t *fault) {
    struct sigaction sa={0},old[3];int signals[]={SIGSEGV,SIGBUS,SIGILL};
    sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);
    for(int i=0;i<3;i++) if(sigaction(signals[i],&sa,&old[i])) return -1;
    unsigned csr=_mm_getcsr();_mm_setcsr(0x1f80);caught=0;fault_address=NULL;active=1;
    if(!sigsetjmp(env,1))hb_mask_asm(in,out,rd,fn,wr,k);
    active=0;_mm_setcsr(csr);
    for(int i=0;i<3;i++)sigaction(signals[i],&old[i],NULL);
    if(fault)*fault=(uintptr_t)fault_address;return caught;
}
