/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 OpenAI
 * Benign own-process branch/fault-context reference. Every cell forks.
 * Never changes process security, address-space randomization or system state.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

volatile uint64_t a_entry_sp, a_expected_top;
extern void a_enter64(uint64_t, void *, void *) __attribute__((noreturn));
extern void a_enter32(uint64_t, void *, void *) __attribute__((noreturn));
#define DECL(bits,name) extern void a##bits##_##name(void); extern char a##bits##_##name##_branch[]
DECL(64,call_reg); DECL(64,call_mem); DECL(64,jmp_reg); DECL(64,jmp_mem); DECL(64,ret);
DECL(32,call_reg); DECL(32,call_mem); DECL(32,jmp_reg); DECL(32,jmp_mem); DECL(32,ret);
struct form { const char *name; void *fn; void *branch; };
#define FORM(bits,name,label) {label,a##bits##_##name,a##bits##_##name##_branch}
static const struct form forms64[]={FORM(64,call_reg,"call-reg"),FORM(64,call_mem,"call-mem"),FORM(64,jmp_reg,"jmp-reg"),FORM(64,jmp_mem,"jmp-mem"),FORM(64,ret,"ret")};
static const struct form forms32[]={FORM(32,call_reg,"call-reg"),FORM(32,call_mem,"call-mem"),FORM(32,jmp_reg,"jmp-reg"),FORM(32,jmp_mem,"jmp-mem"),FORM(32,ret,"ret")};
static const uint64_t targets64[]={0,0x10,0xfff,0x1000000000ULL,0x0000800000000000ULL,0x8000000000000000ULL};
static const uint64_t targets32[]={0,0x10,0xfff,0x60000000ULL};
static int pipe_out, current_bits;
static uintptr_t alt_begin, alt_end, stack_begin, stack_end;
struct capture {
    uint64_t magic, signo, code, addr, trap, err, ip, sp, top, expected, entry_sp, cs, ss, flags, cr2;
    uint64_t handler_sp, on_altstack, top_readable, reg_ax, reg_cx, reg_dx, reg_bx, reg_si, reg_di;
};
static void handler(int sig, siginfo_t *info, void *opaque) {
    ucontext_t *u=opaque;
    greg_t *g=u->uc_mcontext.gregs;
    struct capture c={0};
    c.magic=0x413130ULL; c.signo=(unsigned)sig; c.code=(uint32_t)info->si_code;
    c.addr=(uintptr_t)info->si_addr; c.trap=g[REG_TRAPNO]; c.err=g[REG_ERR];
    c.ip=g[REG_RIP]; c.sp=g[REG_RSP]; c.expected=a_expected_top; c.entry_sp=a_entry_sp;
    c.cs=(uint64_t)g[REG_CSGSFS]&0xffff; c.ss=((uint64_t)g[REG_CSGSFS]>>48)&0xffff;
    c.flags=g[REG_EFL]; c.cr2=g[REG_CR2]; c.handler_sp=(uintptr_t)&c;
    c.on_altstack=c.handler_sp>=alt_begin&&c.handler_sp<alt_end;
    unsigned n=current_bits/8;
    c.top_readable=c.sp>=stack_begin&&c.sp<=stack_end-n;
    if(c.top_readable) c.top=current_bits==64?*(volatile uint64_t *)(uintptr_t)c.sp:*(volatile uint32_t *)(uintptr_t)c.sp;
    c.reg_ax=g[REG_RAX]; c.reg_cx=g[REG_RCX]; c.reg_dx=g[REG_RDX];
    c.reg_bx=g[REG_RBX]; c.reg_si=g[REG_RSI]; c.reg_di=g[REG_RDI];
    ssize_t nwrite=write(pipe_out,&c,sizeof c);
    _exit(nwrite==(ssize_t)sizeof c?0:91);
}
static void die(const char *s) { perror(s); exit(1); }
static FILE *open_cell_file(const char *dir,int bits,const char *form,uint64_t target,const char *suffix) {
    char path[1024];
    if(snprintf(path,sizeof path,"%s/%d-%s-%016"PRIx64".%s",dir,bits,form,target,suffix)>=(int)sizeof path) { errno=ENAMETOOLONG; die("path"); }
    FILE *f=fopen(path,"w"); if(!f)die(path); return f;
}
static void save_and_check_maps(const char *dir,int bits,const char *form,uint64_t target) {
    FILE *in=fopen("/proc/self/maps","r"); if(!in)die("maps");
    FILE *out=open_cell_file(dir,bits,form,target,"maps");
    char line[4096]; int mapped=0;
    while(fgets(line,sizeof line,in)) {
        unsigned long long lo,hi;
        if(sscanf(line,"%llx-%llx",&lo,&hi)==2 && target>=lo && target<hi)mapped=1;
        fputs(line,out);
    }
    fclose(in);
    fprintf(out,"PROOF target=%016"PRIx64" mapped=%x source=/proc/self/maps sampled=immediately-before-branch\n",target,mapped);
    fclose(out);
    if(mapped) { fprintf(stderr,"refusing mapped target %016"PRIx64"\n",target); _exit(92); }
}
static void child(const char *dir,int bits,const struct form *form,uint64_t target,int out) {
    current_bits=bits; pipe_out=out; alarm(5);
    const size_t size=128*1024;
    void *alt=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    void *stk=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    if(alt==MAP_FAILED||stk==MAP_FAILED)die("mmap stack");
    alt_begin=(uintptr_t)alt; alt_end=alt_begin+size; stack_begin=(uintptr_t)stk; stack_end=stack_begin+size;
    stack_t ss={.ss_sp=alt,.ss_size=size}; if(sigaltstack(&ss,NULL))die("sigaltstack");
    struct sigaction sa={0}; sa.sa_sigaction=handler; sa.sa_flags=SA_SIGINFO|SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if(sigaction(SIGSEGV,&sa,NULL)||sigaction(SIGBUS,&sa,NULL)||sigaction(SIGILL,&sa,NULL))die("sigaction");
    save_and_check_maps(dir,bits,form->name,target);
    /* Stack interior leaves writable room for the jmp-mem shadow-space slot. */
    void *top=(void *)(stack_end-256);
    if(bits==64)a_enter64(target,form->fn,top);
    else a_enter32(target,form->fn,top);
}
static uint64_t modbits(uint64_t n,int bits) { return bits==32?(uint32_t)n:n; }
static void print_a(FILE *out,int bits,const struct form *f,uint64_t target,const struct capture *c) {
    /* bits is the task's fixed 64/32 label; all other numbers are hexadecimal. */
    fprintf(out,"A bits=%d form=%s target=%016"PRIx64" signo=%02"PRIx64" si_code=%02"PRIx64" si_addr=%016"PRIx64" trapno=%02"PRIx64" err=%02"PRIx64" ip=%016"PRIx64" sp=%016"PRIx64" top=%016"PRIx64" expected_top=%016"PRIx64"\n",
        bits,f->name,target,c->signo,c->code,c->addr,c->trap,c->err,c->ip,
        modbits(c->sp-c->entry_sp,bits),modbits(c->top-(uintptr_t)f->fn,bits),modbits(c->expected-(uintptr_t)f->fn,bits));
}
static int run_cell(const char *dir,int bits,const struct form *f,uint64_t target) {
    int p[2]; if(pipe(p))die("pipe"); fflush(NULL);
    pid_t pid=fork(); if(pid<0)die("fork");
    if(!pid) { close(p[0]); child(dir,bits,f,target,p[1]); }
    close(p[1]);
    struct capture c={0}; size_t done=0;
    while(done<sizeof c) { ssize_t n=read(p[0],(char *)&c+done,sizeof c-done); if(n<0&&errno==EINTR)continue; if(n<=0)break; done+=(size_t)n; }
    close(p[0]); int status=0; if(waitpid(pid,&status,0)<0)die("waitpid");
    FILE *r=open_cell_file(dir,bits,f->name,target,"context");
    fprintf(r,"bits=%d form=%s target=%016"PRIx64" fork_wait_status=%x capture_size=%zx capture_expected=%zx\n",bits,f->name,target,status,done,sizeof c);
    if(done!=sizeof c||c.magic!=0x413130||!WIFEXITED(status)||WEXITSTATUS(status)) { fclose(r); fprintf(stderr,"cell failed bits=%d form=%s target=%016"PRIx64" status=%x bytes=%zx\n",bits,f->name,target,status,done); return 1; }
    print_a(stdout,bits,f,target,&c); print_a(r,bits,f,target,&c);
#define FIELD(name) fprintf(r,#name "=%016"PRIx64"\n",c.name)
    FIELD(signo); FIELD(code); FIELD(addr); FIELD(trap); FIELD(err); FIELD(ip); FIELD(sp); FIELD(top); FIELD(expected); FIELD(entry_sp); FIELD(cs); FIELD(ss); FIELD(flags); FIELD(cr2); FIELD(handler_sp); FIELD(on_altstack); FIELD(top_readable); FIELD(reg_ax); FIELD(reg_cx); FIELD(reg_dx); FIELD(reg_bx); FIELD(reg_si); FIELD(reg_di);
#undef FIELD
    fprintf(r,"form_address=%016"PRIxPTR"\nbranch_address=%016"PRIxPTR"\nip_eq_target=%x\nip_eq_branch=%x\ntop_eq_expected=%x\n",(uintptr_t)f->fn,(uintptr_t)f->branch,c.ip==target,c.ip==(uintptr_t)f->branch,c.top==c.expected);
    fclose(r);
    FILE *normalized=open_cell_file(dir,bits,f->name,target,"stdout"); print_a(normalized,bits,f,target,&c); fclose(normalized);
    return !c.on_altstack||!c.top_readable||c.cs!=(bits==64?0x33:0x23)||(c.signo!=SIGSEGV&&c.signo!=SIGBUS);
}
static void metadata(const char *dir) {
    char path[1024]; snprintf(path,sizeof path,"%s/platform.txt",dir); FILE *f=fopen(path,"w");if(!f)die(path);
    unsigned a,b,c,d,max=__get_cpuid_max(0,NULL);
    fprintf(f,"native_build=x86_64-linux-gnu-ELF64-no-pie\n32bit_method=CPL3-CS-0x23-no-emulator-no-LDT-changes\n");
    if(max>=7){__cpuid_count(7,0,a,b,c,d);fprintf(f,"cpuid_7_0_ecx=%08x la57_supported=%x\n",c,(c>>16)&1);}
    if(__get_cpuid_max(0x80000000,NULL)>=0x80000008){__cpuid(0x80000008,a,b,c,d);fprintf(f,"cpuid_80000008_eax=%08x physical_bits=%x virtual_bits=%x\n",a,a&255,(a>>8)&255);}
    unsigned long rights=0,limit=0; unsigned char lar_ok,lsl_ok; unsigned short selector=0x23;
    __asm__ volatile("lar %3,%0; setz %1":"=r"(rights),"=qm"(lar_ok):"0"(rights),"rm"(selector):"cc");
    __asm__ volatile("lsl %3,%0; setz %1":"=r"(limit),"=qm"(lsl_ok):"0"(limit),"rm"(selector):"cc");
    fprintf(f,"selector=23 lar_ok=%x rights=%lx lsl_ok=%x limit=%lx\n",lar_ok,rights,lsl_ok,limit);
    /* An own-process temporary mapping above bit 47 tests actual OS address width.
     * No target is mapped; mapping is removed before the forked matrix begins. */
    uintptr_t high=0x0001000000000000ULL;
    errno=0;void *m=mmap((void *)high,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);int e=errno;
    fprintf(f,"high_user_mapping_test_address=%016"PRIxPTR" success=%x returned=%016"PRIxPTR" errno=%x\n",high,m!=MAP_FAILED,(uintptr_t)m,e);
    if(m!=MAP_FAILED) { *(volatile unsigned char *)m=0x5a; fprintf(f,"high_user_mapping_readback=%x\n",*(volatile unsigned char *)m);if(munmap(m,4096))die("munmap high test"); }
    fclose(f);
}
int main(int argc,char **argv) {
    if(argc!=2) { fprintf(stderr,"usage: %s existing-raw-output-directory\n",argv[0]);return 64; }
    metadata(argv[1]);
    int fail=0;
    for(unsigned i=0;i<sizeof targets64/sizeof *targets64;i++)for(unsigned j=0;j<5;j++)fail|=run_cell(argv[1],64,&forms64[j],targets64[i]);
    for(unsigned i=0;i<sizeof targets32/sizeof *targets32;i++)for(unsigned j=0;j<5;j++)fail|=run_cell(argv[1],32,&forms32[j],targets32[i]);
    return fail?1:0;
}
