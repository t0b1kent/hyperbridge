/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <unistd.h>
#include <errno.h>
#include "build/ops.h"
#define FM 0x8d5u
#define CF 1u
#define PF 4u
#define AF 16u
#define ZF 64u
#define SF 128u
#define OF 2048u
#define SP0 0x2000e000u
struct Context { uint32_t in[8],want,before,after,out[8],frame[8],restore_tls; };
_Static_assert(sizeof(struct Context)==112,"context layout");
static struct Context *const ctx=(void*)0x20000000;
extern void bridge(void*,void*,void*);
extern void control64(int);
extern uint64_t saved_fsbase,saved_gsbase;
static sigjmp_buf jump;
struct Fault { int sig,code,trap; uint32_t error,cs,ip; };
static volatile sig_atomic_t armed;
static struct Fault fault;
static unsigned long rows,duplicates,result_checks,flag_checks,trap_checks,errors,controls,salc_checks;
static unsigned long op_rows[sizeof(ops)/sizeof(ops[0])];
static uint32_t pattern(int w,unsigned i){
    static const uint32_t fixed[]={0x89abcdef,0x76543210,0x7f4a7c15,0xd192ed03,0x133111eb,0x4f6cdd1d,0xcafebabe,1,0x80,0};
    uint32_t m=w==32?UINT32_MAX:(1u<<w)-1;
    uint32_t canonical[]={0,1,2,3,m>>1,1u<<(w-1),m,0x55555555u&m,0xaaaaaaaau&m,1,1u<<(w-1),1u<<(w/2)};
    return i<12?canonical[i]:fixed[i-12]&m;
}
static const unsigned short sel[]={0x2b,0x23,0x2b,0x2b,0,0};
static void handler(int s,siginfo_t *i,void *v){
    if(!armed)_exit(128+s);
    ucontext_t *u=v; greg_t *g=u->uc_mcontext.gregs;
    fault.sig=s;fault.code=i->si_code;fault.trap=g[REG_TRAPNO];fault.error=g[REG_ERR];fault.cs=g[REG_CSGSFS]&0xffff;fault.ip=g[REG_RIP];
    int m[]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI};
    for(int j=0;j<8;j++)ctx->out[j]=g[m[j]];
    ctx->after=g[REG_EFL];
    siglongjmp(jump,1);
}
static uint32_t mask(int w){return w==32?UINT32_MAX:(1u<<w)-1;}
static uint32_t psz(uint32_t r,int w){r&=mask(w);unsigned x=r&255;unsigned p=0;for(int k=0;k<8;k++)p^=(x>>k)&1;return (p?0:PF)|(r?0:ZF)|((r>>(w-1))?SF:0);}
static uint32_t putlow(uint32_t old,uint32_t val,int w){uint32_t m=mask(w);return (old&~m)|(val&m);}
static void fail(const struct Op *o,const char *what,uint32_t got,uint32_t expected){if(errors++<20)fprintf(stderr,"FAIL %s w=%d A=%08x B=%08x want=%04x %s got=%08x expected=%08x\n",o->name,o->width,ctx->in[0],ctx->in[3],ctx->want,what,got,expected);}
static void eq(const struct Op *o,const char *what,uint32_t got,uint32_t expected){if(got!=expected)fail(o,what,got,expected);}
static void run(const struct Op *o,int native){
    memset(&fault,0,sizeof fault);ctx->before=ctx->after=0;memset(ctx->out,0,sizeof ctx->out);memset(ctx->frame,0,sizeof ctx->frame);
    if(native){control64(o->kind==K_ADD?0:o->kind==K_SUB?1:2);return;}
    armed=1;if(sigsetjmp(jump,1)==0)bridge(ctx,o->fn,(void*)(uintptr_t)SP0);armed=0;
}
static void stack_init(const struct Op *o){
    memset((void*)(uintptr_t)(SP0-1024),0xa5,2048);
    if(o->kind==K_POPA||o->kind==K_POPAD){
        for(int j=0;j<8;j++){uint32_t v=0x12340000u+0x1111u*(j+1);if(o->width==16)((uint16_t*)(uintptr_t)SP0)[j]=v;else ((uint32_t*)(uintptr_t)SP0)[j]=v;}
    } else if(o->kind==K_POPSEG){*(uint32_t*)(uintptr_t)SP0=0xdead0000u|sel[o->seg];}
}
static void check(const struct Op *o){
    if(o->kind==K_SALC)salc_checks++;
    uint32_t a=ctx->in[0],b=ctx->in[2],f=ctx->before,r=a,ef=f,defined=FM;int tr=0,w=o->width;uint32_t m=mask(w);
    eq(o,"FLAGS_before arithmetic",f&FM,ctx->want&FM);
    eq(o,"FLAGS_before fixed",f&0xffffu&~FM,0x202u);
    switch(o->kind){
    case K_DAA:{unsigned old=a&255,v=old;int cf=(f&CF)!=0,af=(f&AF)!=0;if((old&15)>9||af){v=(v+6)&255;ef|=AF;}else ef&=~AF;if(old>0x99||cf){v=(v+0x60)&255;ef|=CF;}else ef&=~CF;r=putlow(a,v,8);ef=(ef&~(PF|ZF|SF))|psz(v,8);defined=FM&~OF;break;}
    case K_DAS:{unsigned old=a&255,v=old;int cf=(f&CF)!=0,af=(f&AF)!=0;ef&=~CF;if((old&15)>9||af){v=(v-6)&255;ef|=AF;if(cf||old<6)ef|=CF;}else ef&=~AF;if(old>0x99||cf){v=(v-0x60)&255;ef|=CF;}r=putlow(a,v,8);ef=(ef&~(PF|ZF|SF))|psz(v,8);defined=FM&~OF;break;}
    case K_AAA:case K_AAS:{unsigned v=a&65535;if((v&15)>9||(f&AF)){v=(o->kind==K_AAA?v+0x106:v-0x106)&65535;ef|=AF|CF;}else ef&=~(AF|CF);v&=0xff0f;r=putlow(a,v,16);defined=AF|CF;break;}
    case K_AAM:if(o->imm==0){tr=1;break;}r=putlow(a,(((a&255)/o->imm)<<8)|((a&255)%o->imm),16);ef=(ef&~(PF|SF|ZF))|psz(r,8);defined=PF|SF|ZF;break;
    case K_AAD:r=putlow(a,((a&255)+((a>>8)&255)*o->imm)&255,16);ef=(ef&~(PF|SF|ZF))|psz(r,8);defined=PF|SF|ZF;break;
    case K_SALC:r=putlow(a,(f&CF)?255:0,8);break;
    case K_LAHF:r=(a&~0xff00u)|(((f&0xd5u)|2u)<<8);break;
    case K_SAHF:ef=(f&~0xd5u)|((a>>8)&0xd5u);break;
    case K_ARPL:{unsigned s=ctx->in[3]&3;if((a&3)<s){r=(a&~3u)|s;ef=f|ZF;}else ef=f&~ZF;break;}
    case K_INC:case K_DEC:{a=ctx->in[o->reg];r=putlow(a,o->kind==K_INC?a+1:a-1,w);uint32_t av=a&m,rv=r&m;ef=(f&~(PF|AF|ZF|SF|OF))|psz(rv,w);if((av^1^rv)&16)ef|=AF;if(o->kind==K_INC?av==(m>>1):av==(1u<<(w-1)))ef|=OF;eq(o,"result",ctx->out[o->reg],r);r=ctx->out[0];break;}
    case K_ADD:case K_SUB:{unsigned sub=o->kind==K_SUB;uint64_t wide=sub?(uint64_t)a-b:(uint64_t)a+b;r=(uint32_t)wide;ef=(f&~FM)|psz(r,32);if(sub?a<b:wide>>32)ef|=CF;if((a^b^r)&16)ef|=AF;if(sub?((a^b)&(a^r)&0x80000000u):((~(a^b))&(a^r)&0x80000000u))ef|=OF;break;}
    case K_SHL:{unsigned n=ctx->in[1]&31;if(!n){r=a;break;}r=a<<n;ef=(f&~(CF|PF|ZF|SF|OF))|psz(r,32)|(((a>>(32-n))&1)?CF:0);defined=CF|PF|ZF|SF;if(n==1){defined|=OF;if(((r>>31)^((ef&CF)!=0))&1)ef|=OF;}break;}
    case K_PUSHA:case K_PUSHAD:{int order[]={7,6,5,4,3,2,1,0};for(int j=0;j<8;j++)eq(o,"push frame",ctx->frame[j],ctx->in[order[j]]&m);eq(o,"push ESP",ctx->out[4],ctx->in[4]-8*(w/8));break;}
    case K_POPA:case K_POPAD:{int order[]={7,6,5,-1,3,2,1,0};for(int j=0;j<8;j++)if(order[j]>=0)eq(o,"pop register",ctx->out[order[j]],putlow(ctx->in[order[j]],0x12340000u+0x1111u*(j+1),w));eq(o,"pop ESP skip",ctx->out[4],ctx->in[4]+8*(w/8));r=putlow(a,0x12348888u,w);break;}
    case K_PUSHSEG:eq(o,"push selector",ctx->frame[0]&65535,sel[o->seg]);eq(o,"push segment ESP",ctx->out[4],ctx->in[4]-w/8);break;
    case K_POPSEG:eq(o,"pop selector",ctx->frame[0],sel[o->seg]);eq(o,"pop segment ESP",ctx->out[4],ctx->in[4]+w/8);break;
    case K_BOUND:{int64_t index=w==16?(int16_t)a:(int32_t)a;int64_t lo=w==16?((int16_t*)(uintptr_t)0x20000080)[0]:((int32_t*)(uintptr_t)0x20000080)[0];int64_t hi=w==16?((int16_t*)(uintptr_t)0x20000080)[1]:((int32_t*)(uintptr_t)0x20000080)[1];tr=index<lo||index>hi;break;}
    case K_INTO:tr=(f&OF)!=0;break;
    default:abort();
    }
    if(tr){eq(o,"expected trap",fault.sig!=0,1);eq(o,"trap vector",fault.trap,o->kind==K_AAM?0:o->kind==K_BOUND?5:4);eq(o,"trap CS",fault.cs,0x23);eq(o,"trap EAX",ctx->out[0],ctx->in[0]);eq(o,"trap EDX",ctx->out[2],ctx->in[2]);trap_checks++;defined=FM;ef=f;}
    else{eq(o,"unexpected trap",fault.sig,0);eq(o,"EAX result",ctx->out[0],r);result_checks++;}
    eq(o,"defined arithmetic flags",ctx->after&defined,ef&defined);flag_checks++;
    eq(o,"nonarithmetic low16",ctx->after&0xffffu&~FM,f&0xffffu&~FM);
}
static void printrow(const struct Op *o,uint32_t a,uint32_t b,uint32_t c,int haveb,int havec,int native){
    int w=o->width,d=w/4;uint32_t m=mask(w),r1=ctx->out[0]&m,r2=ctx->out[2]&m;int haver2=0;
    switch(o->kind){case K_DAA:case K_DAS:r2=(ctx->out[0]>>8)&255;haver2=1;break;case K_AAM:r2=ctx->out[2]&m;haver2=fault.sig!=0;break;case K_INC:case K_DEC:r1=ctx->out[o->reg]&m;break;case K_PUSHA:case K_PUSHAD:r1=ctx->out[4]&m;r2=ctx->frame[3]&m;haver2=1;break;case K_POPA:case K_POPAD:r2=ctx->out[4]&m;haver2=1;break;case K_PUSHSEG:r1=ctx->frame[0]&m;r2=ctx->out[4]&m;haver2=1;break;case K_POPSEG:r1=ctx->frame[0]&m;r2=ctx->out[4]&m;haver2=1;break;default:break;}
    if(fault.sig){r2=ctx->out[2]&m;haver2=1;}
    const char *name=o->name;char n[48];if(native){snprintf(n,sizeof n,"%s.long",o->kind==K_ADD?"ADD":o->kind==K_SUB?"SUB":"SHL");name=n;}
    printf("%s %d %04x %0*x ",name,w,ctx->before&65535,d,a&m);if(haveb)printf("%0*x ",d,b&m);else printf("- ");if(havec)printf("%0*x",d,c&m);else printf("-");printf(" -> %s%0*x ",fault.sig?"TRAP ":"",d,r1);if(haver2)printf("%0*x",d,r2);else printf("-");printf(" %04x\n",ctx->after&65535);
    if(fault.sig)printf("# trap row=%lu signal=%d si_code=%d vector=%d error=%08x cs=%04x ip=%08x eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x eflags=%08x\n",rows,fault.sig,fault.code,fault.trap,fault.error,fault.cs,fault.ip,ctx->out[0],ctx->out[1],ctx->out[2],ctx->out[3],ctx->out[4],ctx->out[5],ctx->out[6],ctx->out[7],ctx->after);
    if(o->kind==K_PUSHA||o->kind==K_PUSHAD||o->kind==K_POPA||o->kind==K_POPAD){printf("# registers row=%lu",rows);for(int j=0;j<8;j++)printf(" in%d=%08x out%d=%08x",j,ctx->in[j],j,ctx->out[j]);putchar('\n');if(o->frame){printf("# stack-frame row=%lu low-to-high",rows);for(int j=0;j<8;j++)printf(" %0*x",d,ctx->frame[j]);putchar('\n');}}
}
static void one(const struct Op *o,uint32_t a,uint32_t b,uint32_t c,unsigned f,int haveb,int havec){
    static const uint32_t seed[]={0xa5a50000,0x13579bdf,0x2468ace0,0x76543210,SP0,0x11223344,0x55667788,0x99aabbcc};
    memcpy(ctx->in,seed,sizeof seed);ctx->in[0]=putlow(seed[0],a,o->width);ctx->want=0x202|(f&FM);ctx->restore_tls=0;
    if(o->kind==K_INC||o->kind==K_DEC){ctx->in[o->reg]=o->reg==4?a:putlow(seed[o->reg],a,o->width);}
    if(o->kind==K_ARPL)ctx->in[3]=b;
    if(o->kind==K_ADD||o->kind==K_SUB||o->kind==K_SHL){ctx->in[0]=a;ctx->in[2]=b;ctx->in[1]=c;}
    if(o->kind==K_BOUND){if(o->width==16){((uint16_t*)(uintptr_t)0x20000080)[0]=b;((uint16_t*)(uintptr_t)0x20000080)[1]=c;}else{((uint32_t*)(uintptr_t)0x20000080)[0]=b;((uint32_t*)(uintptr_t)0x20000080)[1]=c;}}
    if(o->kind==K_POPSEG&&o->seg>=4)ctx->restore_tls=1u<<(o->seg-4);
    stack_init(o);run(o,0);struct Context first=*ctx;struct Fault ff=fault;stack_init(o);run(o,0);
    if(memcmp(&first,ctx,sizeof first)||memcmp(&ff,&fault,sizeof fault))fail(o,"same fragment duplicate",1,0);
    duplicates++;
    check(o);rows++;op_rows[o-ops]++;printrow(o,a,b,c,haveb,havec,0);
    if(o->kind==K_ADD||o->kind==K_SUB||o->kind==K_SHL){uint32_t olda=ctx->out[0],oldd=ctx->out[2],oldf=ctx->after,oldb=ctx->before;run(o,1);eq(o,"mode EAX",ctx->out[0],olda);eq(o,"mode EDX",ctx->out[2],oldd);eq(o,"mode flags",ctx->after&65535,oldf&65535);eq(o,"mode before",ctx->before&65535,oldb&65535);controls++;rows++;printrow(o,a,b,c,haveb,havec,1);}
}
int main(int argc,char **argv){
    if(argc!=2){fprintf(stderr,"usage: %s bcd|extra|control\n",argv[0]);return 2;}
    void*p=mmap((void*)0x20000000,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);if(p==MAP_FAILED){fprintf(stderr,"mmap errno=%d (%s)\n",errno,strerror(errno));return 77;}
    if(syscall(SYS_arch_prctl,ARCH_GET_FS,&saved_fsbase)||syscall(SYS_arch_prctl,ARCH_GET_GS,&saved_gsbase)){fprintf(stderr,"read existing TLS bases errno=%d (%s)\n",errno,strerror(errno));return 77;}
    stack_t ss={0};ss.ss_sp=malloc(65536);ss.ss_size=65536;if(!ss.ss_sp||sigaltstack(&ss,0)){perror("sigaltstack");return 1;}
    struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO|SA_ONSTACK;sigemptyset(&sa.sa_mask);int signals[]={SIGSEGV,SIGILL,SIGBUS,SIGFPE};for(int j=0;j<4;j++)if(sigaction(signals[j],&sa,0)){perror("sigaction");return 1;}
    setvbuf(stdout,0,_IOFBF,1024*1024);printf("# native legacy32 oracle v1; arithmetic mask 08d5; registers 0=eax 1=ecx 2=edx 3=ebx 4=esp 5=ebp 6=esi 7=edi\n");
    for(unsigned z=0;z<sizeof ops/sizeof ops[0];z++){const struct Op*o=&ops[z];int cls=o->kind<=K_AAD?0:o->kind>=K_ADD?2:1;if(strcmp(argv[1],cls==0?"bcd":cls==1?"extra":"control"))continue;
        if(o->kind==K_DAA||o->kind==K_DAS){for(unsigned a=0;a<256;a++)for(unsigned afcf=0;afcf<4;afcf++)for(unsigned rest=0;rest<2;rest++)one(o,a,0,0,(rest?(FM&~(AF|CF)):0)|((afcf&1)?CF:0)|((afcf&2)?AF:0),0,0);}
        else if(o->kind==K_AAA||o->kind==K_AAS){for(unsigned a=0;a<65536;a++)for(unsigned af=0;af<2;af++)for(unsigned rest=0;rest<2;rest++)one(o,a,0,0,(rest?(FM&~AF):0)|(af?AF:0),0,0);}
        else if(o->kind==K_AAM||o->kind==K_AAD){unsigned max=o->imm==10?(o->kind==K_AAM?256:65536):22;for(unsigned i=0;i<max;i++)for(unsigned f=0;f<2;f++){uint32_t a=o->imm==10?i:pattern(o->kind==K_AAM?8:16,i);if(o->kind==K_AAM)a=0xa500|(a&255);one(o,a,0,o->imm,f?FM:0,0,1);}}
        else if(o->kind==K_SALC||o->kind==K_SAHF){for(unsigned a=0;a<256;a++)for(unsigned f=0;f<2;f++)one(o,o->kind==K_SAHF?(a<<8)|0x5a:a,0,0,f?FM:0,0,0);}
        else if(o->kind==K_ARPL||o->kind==K_ADD||o->kind==K_SUB){for(unsigned i=0;i<22;i++)for(unsigned j=0;j<22;j++)for(unsigned f=0;f<2;f++)one(o,pattern(o->width,i),pattern(o->width,j),0,f?FM:0,1,0);}
        else if(o->kind==K_SHL){for(unsigned i=0;i<22;i++)for(unsigned n=0;n<=65;n++)for(unsigned f=0;f<2;f++)one(o,pattern(o->width,i),0,n,f?FM:0,0,1);}
        else if(o->kind==K_BOUND){uint32_t lo[]={0,0xfffffffdu,1u<<(o->width-1),10},hi[]={3,2,mask(o->width)>>1,5};for(unsigned j=0;j<4;j++)for(unsigned i=0;i<22;i++)for(unsigned f=0;f<2;f++)one(o,pattern(o->width,i),lo[j],hi[j],f?FM:0,1,1);}
        else if(o->kind==K_INC||o->kind==K_DEC){unsigned max=o->reg==4?4:22;for(unsigned i=0;i<max;i++)for(unsigned f=0;f<2;f++)one(o,o->reg==4?SP0+i*4:pattern(o->width,i),0,0,f?FM:0,0,0);}
        else{for(unsigned i=0;i<22;i++)for(unsigned f=0;f<2;f++)one(o,pattern(o->width,i),o->kind==K_PUSHSEG?0xa5a5a5a5u:o->kind==K_POPSEG?0xdead0000u|sel[o->seg]:0,0,f?FM:0,o->kind==K_PUSHSEG||o->kind==K_POPSEG,0);}
    }
    fprintf(stderr,"rows=%lu duplicate_pairs=%lu result_checks=%lu flag_checks=%lu trap_checks=%lu mode_pairs=%lu salc_empirical_checks=%lu errors=%lu\n",rows,duplicates,result_checks,flag_checks,trap_checks,controls,salc_checks,errors);
    for(unsigned z=0;z<sizeof ops/sizeof ops[0];z++)if(op_rows[z])fprintf(stderr,"form=%s width=%d immediate=%d rows=%lu\n",ops[z].name,ops[z].width,ops[z].imm,op_rows[z]);
    return errors?1:0;
}
