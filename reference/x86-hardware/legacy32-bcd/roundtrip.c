/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
extern void bridge(void *, void *, void *);
extern void probe32(void);
extern void check_bridge_preservation(void);
extern uint64_t expected_regs[17],observed_regs[17],saved_fsbase,saved_gsbase;
static sigjmp_buf escape;
static volatile sig_atomic_t sig, code, trap;
static volatile uint64_t cs, rip, flags, err;
static void handle(int s, siginfo_t *i, void *v) {
    ucontext_t *u=v; sig=s; code=i->si_code; trap=u->uc_mcontext.gregs[REG_TRAPNO];
    cs=u->uc_mcontext.gregs[REG_CSGSFS]&0xffff; rip=u->uc_mcontext.gregs[REG_RIP];
    flags=u->uc_mcontext.gregs[REG_EFL]; err=u->uc_mcontext.gregs[REG_ERR];
    siglongjmp(escape,1);
}
int main(void) {
    struct sigaction a={0}; a.sa_sigaction=handle; a.sa_flags=SA_SIGINFO; sigemptyset(&a.sa_mask);
    sigaction(SIGSEGV,&a,0); sigaction(SIGILL,&a,0); sigaction(SIGBUS,&a,0); sigaction(SIGFPE,&a,0);
    void *p=mmap((void*)0x20000000,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    if(p==MAP_FAILED) { printf("mmap errno=%d (%s)\n",errno,strerror(errno)); return 77; }
    if(sigsetjmp(escape,1)==0) bridge(p,probe32,(char*)p+65520);
    if(sig) { printf("TRAP signal=%d si_code=%d trapno=%d cs=%04lx rip=%016lx flags=%016lx err=%lx\n",sig,code,trap,cs,rip,flags,err); return 77; }
    printf("ROUNDTRIP marker=%08x esp=%08x\n",((uint32_t*)p)[0],((uint32_t*)p)[1]);
    if(((uint32_t*)p)[0]!=0x12345678)return 1;
    if(syscall(SYS_arch_prctl,ARCH_GET_FS,&saved_fsbase)||syscall(SYS_arch_prctl,ARCH_GET_GS,&saved_gsbase)){perror("read existing TLS bases");return 77;}
    unsigned errors=0;
    for(volatile unsigned restore=0;restore<=3;restore+=3){
        unsigned short ds0,es0,fs0,gs0,ds1,es1,fs1,gs1;
        __asm__ volatile("mov %%ds,%0; mov %%es,%1; mov %%fs,%2; mov %%gs,%3" : "=r"(ds0),"=r"(es0),"=r"(fs0),"=r"(gs0));
        ((uint32_t*)p)[27]=restore;
        if(sigsetjmp(escape,1)==0)check_bridge_preservation();
        if(sig){printf("PRESERVATION trap signal=%d code=%d vector=%d\n",sig,code,trap);return 77;}
        for(unsigned j=0;j<17;j++)if(expected_regs[j]!=observed_regs[j]){errors++;printf("PRESERVATION mismatch index=%u expected=%016lx actual=%016lx\n",j,expected_regs[j],observed_regs[j]);}
        __asm__ volatile("mov %%ds,%0; mov %%es,%1; mov %%fs,%2; mov %%gs,%3" : "=r"(ds1),"=r"(es1),"=r"(fs1),"=r"(gs1));
        uint64_t fsbase,gsbase;
        if(syscall(SYS_arch_prctl,ARCH_GET_FS,&fsbase)||syscall(SYS_arch_prctl,ARCH_GET_GS,&gsbase)){perror("verify existing TLS bases");return 77;}
        errors+=(ds0!=ds1)+(es0!=es1)+(fs0!=fs1)+(gs0!=gs1)+(fsbase!=saved_fsbase)+(gsbase!=saved_gsbase);
        printf("PRESERVATION restore_tls_mask=%u checked=16_full_GPRs+RFLAGS+DS_ES_FS_GS+FS_GS_bases cumulative_errors=%u\n",restore,errors);
    }
    return errors?1:0;
}
