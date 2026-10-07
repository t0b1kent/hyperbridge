/* SPDX-License-Identifier: MIT
 * Original hardware probe, 2026. No network access or foreign code.
 * The emitted instructions below are authored explicitly, not copied from a project.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <ucontext.h>
#include <unistd.h>
#if !defined(__x86_64__) || !defined(__linux__)
#error Linux x86-64 required
#endif
#define REPEATS 1000
#define OLD 0x11223344u
#define NEW 0x55667788u
static sigjmp_buf recovery;
static volatile sig_atomic_t armed, got_signal, got_code;
static volatile uintptr_t got_rip, got_address;
static const volatile unsigned char *volatile capture;
static volatile unsigned char fault_bytes[8];
static volatile sig_atomic_t capture_length;
static size_t page;
static unsigned char *rx, *wr;
static size_t arena;
static FILE *summary, *layout;
static unsigned cell;
static void fatal(const char *s) { perror(s); exit(2); }
static void serialize(void) { unsigned a=0,b,c,d; __cpuid(0,a,b,c,d); }
static void handler(int sig, siginfo_t *si, void *v) {
    if (!armed) _exit(128+sig);
    got_signal=sig; got_code=si->si_code;
    got_address=(uintptr_t)si->si_addr;
    got_rip=(uintptr_t)((ucontext_t*)v)->uc_mcontext.gregs[REG_RIP];
    for (int i=0; i<capture_length; ++i) fault_bytes[i]=capture[i];
    armed=0; siglongjmp(recovery,1);
}
static void put32(unsigned char *p,uint32_t v){memcpy(p,&v,4);}
static void rel32(unsigned char *p,unsigned char op,size_t from,size_t to) {
    p[from]=op; put32(p+from+1,(uint32_t)(int32_t)(to-(from+5)));
}
static size_t cpuid_code(unsigned char *p,size_t at) {
    /* Preserve both marker registers and SysV callee-saved RBX. */
    const unsigned char b[]={0x50,0x53,0x51,0x52,0x31,0xc0,0x0f,0xa2,0x5a,0x59,0x5b,0x58};
    memcpy(p+at,b,sizeof b); return at+sizeof b;
}
static size_t markers(unsigned char*p,size_t at) {
    p[at++]=0xb8; put32(p+at,OLD);at+=4;p[at++]=0xb9;put32(p+at,NEW);return at+4;
}
static size_t store_reg(unsigned char *p,size_t at,int w) {
    if(w==1)p[at++]=0x40;
    if(w==2)p[at++]=0x66;
    if(w==8)p[at++]=0x48;
    p[at++]=(w==1?0x88:0x89);p[at++]=0x37;return at;
}
static size_t self_store(unsigned char *p,size_t at,int w) {
    /* [RDI + 0] with explicit disp32; CS override is ignored in 64-bit mode.
     * The 8-byte form has a SIB with no index. Its length is 9 bytes, so its
     * final 8 bytes are strictly after the first byte of the current store. */
    if(w==8)p[at++]=0x2e;
    if(w==1)p[at++]=0x40;
    if(w==2)p[at++]=0x66;
    if(w==8)p[at++]=0x48;
    p[at++]=(w==1?0x88:0x89);
    p[at++]=(w==8?0xb4:0xb7);
    if(w==8)p[at++]=0x27;
    put32(p+at,0);return at+4;
}
static void bytes_for(int w,unsigned char *o,unsigned char*n) {
    const unsigned char old8[]={0x0f,0x1f,0x84,0,0,0,0,0};
    const unsigned char new8[]={0x91,0x0f,0x1f,0x80,0,0,0,0};
    if(w==1){o[0]=0x90;n[0]=0x91;}
    if(w==2){o[0]=0x66;o[1]=0x90;n[0]=0x87;n[1]=0xc8;}
    if(w==4){unsigned char a[]={0x0f,0x1f,0x40,0},b[]={0x91,0x0f,0x1f,0};memcpy(o,a,4);memcpy(n,b,4);}
    if(w==8){memcpy(o,old8,8);memcpy(n,new8,8);}
}
static void hex(const unsigned char*p,int n,char *s){for(int i=0;i<n;i++)sprintf(s+2*i,"%02x",p[i]);s[2*n]=0;}
static void map_arena(int alias) {
    arena=page*3;
    if(alias){int fd=memfd_create("original-smc-probe",MFD_CLOEXEC);if(fd<0)fatal("memfd_create");if(ftruncate(fd,(off_t)arena))fatal("ftruncate");
        rx=mmap(0,arena,PROT_READ|PROT_EXEC,MAP_SHARED,fd,0);wr=mmap(0,arena,PROT_WRITE,MAP_SHARED,fd,0);close(fd);
    }else{rx=mmap(0,arena,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);wr=rx;}
    if(rx==MAP_FAILED||wr==MAP_FAILED)fatal("mmap");
}
static void unmap_arena(void){if(wr!=rx)munmap(wr,arena);munmap(rx,arena);}
static const char *mode_name(int a){return a?"RX_plus_W_alias":"RWX";}
static const char *route_name(int r){return r==0?"fallthrough":r==1?"jmp":"call_ret";}
static const char *geom_name(int g){return g==0?"current_encoding":g==1?"next_instruction":g==2?"plus16":g==3?"plus64":"next_page";}
static void na(int a,int w,int mis,int g,int r,int ser,const char *why){
    ++cell;fprintf(summary,"%u\t%s\t%d\t%s\t%s\t%s\t%d\tNA\t0\t0\t0\t0\t0\t0\t%s\n",cell,mode_name(a),w,mis?"misaligned":"aligned",geom_name(g),route_name(r),ser,why);
}
static void run_cell(int a,int w,int mis,int g,int r,int ser) {
    if(w==1&&mis){na(a,w,mis,g,r,ser,"every_byte_is_naturally_aligned");return;}
    if(g==1&&(r||ser)){na(a,w,mis,g,r,ser,"strict_adjacent_instruction_executes_before_any_interposed_transfer_or_CPUID");return;}
    ++cell; unsigned char *image=malloc(arena); if(!image)fatal("malloc");memset(image,0x90,arena);
    unsigned char oldbytes[8]={0},newbytes[8]={0};size_t start,st,end,target,tramp=page*2+128,warm=page*2+256;
    int storelen=(w==4?2:3);size_t delta=g==2?16:g==3?64:0;
    if(g==0){int len=w==8?9:w==4?6:7;target=256+(mis?1:0);st=target+w-len;start=st-10;end=self_store(image,st,w);if(end!=target+(size_t)w)abort();
        memcpy(oldbytes,image+target,w);uint64_t value=UINT64_C(0x8877665544332211);memcpy(newbytes,&value,w);
    }else{target=(g==4?page:256)+(mis?1:0);st=target-(g==4?64:delta)-storelen;start=st-10;end=store_reg(image,st,w);bytes_for(w,oldbytes,newbytes);memcpy(image+target,oldbytes,w);image[target+w]=0xc3;}
    markers(image,start);
    size_t continuation=g==0?end:target;
    if(g==0){image[continuation]=0xb8;put32(image+continuation+1,OLD);image[continuation+5]=0xc3;}
    size_t route_at=end;
    if(g==0){ /* self-write has already executed; routes apply to the untouched successor marker. */
        continuation=end+64;image[continuation]=0xb8;put32(image+continuation+1,OLD);image[continuation+5]=0xc3;
        memset(image+end,0x90,64);
    }
    if(r==0){if(ser)route_at=cpuid_code(image,route_at);if(route_at>continuation)abort();}
    else{rel32(image,0xe9,route_at,tramp);size_t p=tramp;if(ser)p=cpuid_code(image,p);rel32(image,r==1?0xe9:0xe8,p,continuation);if(r==2)image[p+5]=0xc3;}
    size_t warmend=markers(image,warm);rel32(image,0xe9,warmend,target);
    char oh[17],nh[17];hex(oldbytes,w,oh);hex(newbytes,w,nh);
    fprintf(layout,"%u\t%zu\t%zu\t%zu\t%zu\t%zu\t%zu\t%zu\t%s\t%s\n",cell,start,st,end,target,continuation,tramp,target%(size_t)w,oh,nh);
    memcpy(wr,image,arena);serialize();
    typedef uint32_t(*func)(void*,uint64_t); func call=(func)(rx+start);func warmcall=(func)(rx+warm);
    uint64_t payload=0;memcpy(&payload,newbytes,w);unsigned oldn=0,newn=0,othern=0,faultn=0,variation=0,firstsig=0;uint32_t firstret=0;char firstbytes[17]={0};
    for(int iteration=0;iteration<REPEATS;++iteration){
        memcpy(wr+target,oldbytes,w);serialize();
        uint32_t baseline=OLD;
        if(g!=0)baseline=warmcall(0,0);
        if(baseline!=OLD){fprintf(stderr,"baseline failure cell=%u iteration=%d\n",cell,iteration);exit(3);}
        got_signal=0;got_code=0;got_rip=0;got_address=0;capture=rx+target;capture_length=w;
        volatile uint32_t result=0;
        if(sigsetjmp(recovery,1)==0){armed=1;result=call(wr+target,payload);armed=0;}
        unsigned char observed[8];for(int i=0;i<w;++i)observed[i]=got_signal?fault_bytes[i]:rx[target+i];char bh[17];hex(observed,w,bh);
        const char *outcome;
        if(got_signal){outcome="fault";++faultn;}else if(result==OLD){outcome=g==0?"old_decoded_store":"old";++oldn;}else if(result==NEW){outcome="new";++newn;}else{outcome="other";++othern;}
        if(iteration==0){firstsig=got_signal;firstret=result;strcpy(firstbytes,bh);}else if((unsigned)got_signal!=firstsig||result!=firstret||strcmp(firstbytes,bh))++variation;
        long long ripoff=got_signal?(long long)(got_rip-(uintptr_t)rx):-1;
        long long addroff=got_signal?(long long)(got_address-(uintptr_t)(wr+target)):-1;
        printf("%u\t%d\t%s\t%08x\t%d\t%d\t%lld\t%lld\t%s\n",cell,iteration,outcome,(unsigned)result,(int)got_signal,(int)got_code,ripoff,addroff,bh);
    }
    fprintf(summary,"%u\t%s\t%d\t%s\t%s\t%s\t%d\tMEASURED\t%d\t%u\t%u\t%u\t%u\t%u\t%s\n",cell,mode_name(a),w,mis?"misaligned":"aligned",geom_name(g),route_name(r),ser,REPEATS,oldn,newn,othern,faultn,variation,g==0?"current_store_uses_original_decode;successor_untouched":"target_instruction_warmed_old_before_store");
    free(image);
}
static void cross_page(int alias) {
    ++cell;map_arena(alias);memset(wr,0x90,arena);
    const unsigned char body[]={0x89,0x37,0xc3};memcpy(wr+page*2,body,sizeof body);
    unsigned char *target=wr+page-2;unsigned char initial[4]={0xaa,0xbb,0xcc,0xdd};
    typedef uint32_t(*func)(void*,uint64_t);func call=(func)(rx+page*2);
    unsigned faults=0,partial=0,variation=0;char first[9]={0};int first_sig=0,first_code=0;
    for(int i=0;i<REPEATS;++i){if(mprotect(wr+page,page,alias?PROT_WRITE:PROT_READ|PROT_WRITE|PROT_EXEC))fatal("mprotect reset");memcpy(target,initial,4);if(mprotect(wr+page,page,PROT_READ))fatal("mprotect readonly");serialize();
        got_signal=0;got_code=0;got_rip=0;got_address=0;capture=rx+page-2;capture_length=4;
        if(sigsetjmp(recovery,1)==0){armed=1;call(target,0x44332211);armed=0;}
        unsigned char observed[4];for(int j=0;j<4;++j)observed[j]=got_signal?fault_bytes[j]:rx[page-2+j];char h[9];hex(observed,4,h);
        faults+=got_signal!=0;partial+=memcmp(observed,initial,4)!=0;
        if(i==0){strcpy(first,h);first_sig=got_signal;first_code=got_code;}else if(strcmp(first,h)||first_sig!=got_signal||first_code!=got_code)++variation;
        printf("%u\t%d\t%s\t00000000\t%d\t%d\t%lld\t%lld\t%s\n",cell,i,got_signal?"fault":"unexpected_success",(int)got_signal,(int)got_code,got_signal?(long long)(got_rip-(uintptr_t)rx):-1,got_signal?(long long)(got_address-(uintptr_t)target):-1,h);
    }
    fprintf(summary,"%u\t%s\t4\tmisaligned\tcross_page_2plus2\tstore_only\t0\tMEASURED\t%d\t0\t0\t%u\t%u\t%u\tbytes_changed_on_fault=%u;initial=aabbccdd;payload=11223344\n",cell,mode_name(alias),REPEATS,REPEATS-faults,faults,variation,partial);
    fprintf(layout,"%u\t%zu\t%zu\t%zu\t%zu\t0\t0\t2\taabbccdd\t11223344\n",cell,page*2,page*2,page*2+2,page-2);
    unmap_arena();
}
static void metadata(void){unsigned a,b,c,d,max,signature,hyper;char vendor[13]={0},hv[13]={0},brand[49]={0};__cpuid(0,max,b,c,d);memcpy(vendor,&b,4);memcpy(vendor+4,&d,4);memcpy(vendor+8,&c,4);__cpuid(1,a,b,c,d);signature=a;hyper=c>>31;unsigned family=(a>>8)&15,model=(a>>4)&15;if(family==15)family+=(a>>20)&255;if(((a>>8)&15)==6||((a>>8)&15)==15)model+=((a>>16)&15)<<4;
    if(hyper){__cpuid(0x40000000,a,b,c,d);memcpy(hv,&b,4);memcpy(hv+4,&c,4);memcpy(hv+8,&d,4);}__cpuid(0x80000000,a,b,c,d);if(a>=0x80000004)for(unsigned i=0;i<3;i++){__cpuid(0x80000002+i,a,b,c,d);memcpy(brand+16*i,&a,4);memcpy(brand+16*i+4,&b,4);memcpy(brand+16*i+8,&c,4);memcpy(brand+16*i+12,&d,4);}struct utsname u;if(uname(&u))fatal("uname");
    printf("vendor=%s\nbrand=%s\nfamily=%u\nmodel=%u\nstepping=%u\ncpuid_signature=%08x\nhypervisor_present=%u\nhypervisor_vendor=%s\nos=%s\nrelease=%s\nmachine=%s\npage_bytes=%zu\nrepeats_per_executable_cell=%d\n",vendor,brand,family,model,signature&15,signature,hyper,hv,u.sysname,u.release,u.machine,page,REPEATS);
}
int main(int argc,char **argv){page=(size_t)sysconf(_SC_PAGESIZE);if(argc==2&&!strcmp(argv[1],"--metadata")){metadata();return 0;}if(argc!=3){fprintf(stderr,"usage: probe summary.tsv layout.tsv | --metadata\n");return 2;}
    alarm(890);struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);int sigs[]={SIGSEGV,SIGBUS,SIGILL,SIGTRAP};for(unsigned i=0;i<sizeof sigs/sizeof*sigs;++i)if(sigaction(sigs[i],&sa,0))fatal("sigaction");
    summary=fopen(argv[1],"w");layout=fopen(argv[2],"w");if(!summary||!layout)fatal("output");
    fprintf(summary,"cell\tmapping\twidth\talignment\tgeometry\troute\tcpuid_after_store\tstatus\trepeats\told\tnew\tother\tfaults\tvariation_vs_first\tnote\n");fprintf(layout,"cell\tentry_offset\tstore_offset\tstore_end_offset\tmodified_offset\tcontinuation_offset\ttrampoline_offset\ttarget_mod_width\told_bytes\tnew_bytes\n");printf("cell\trepeat\toutcome\treturn_eax\tsignal\tsi_code\trip_offset\tfault_address_minus_target\tbytes_at_return_or_in_handler\n");
    int widths[]={1,2,4,8};for(int a=0;a<2;++a){map_arena(a);for(unsigned w=0;w<4;++w)for(int mis=0;mis<2;++mis)for(int g=0;g<5;++g)for(int r=0;r<3;++r)for(int ser=0;ser<2;++ser)run_cell(a,widths[w],mis,g,r,ser);unmap_arena();}for(int a=0;a<2;++a)cross_page(a);
    if(fclose(summary)||fclose(layout)||fflush(stdout))fatal("flush");
    return 0;
}
