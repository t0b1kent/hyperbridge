/* Original native-x87 harness. MIT License, see LICENSE. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>
#include <sys/resource.h>
#include <cpuid.h>
struct value {const char *name;uint64_t sig;uint16_t se;};
struct fx {uint16_t cw,sw;uint8_t tw,pad;uint16_t op;uint64_t ip,dp;uint32_t mx,mxmask;uint8_t st[8][16];uint8_t rest[352];} __attribute__((aligned(16)));
_Static_assert(sizeof(struct fx)==512,"FXSAVE64 layout");
struct form {const char *cls,*name;int mode,mb,out,flags,n,meta,index;void(*fn)(void*,void*,void*,void*,uint64_t*);char *insn,*probe,*resume;};
#include "build/forms.h"
#define LEN(a) (sizeof(a)/sizeof((a)[0]))
static const uint16_t cws[]={0x007f,0x047f,0x087f,0x0c7f,0x027f,0x067f,0x0a7f,0x0e7f,0x037f,0x077f,0x0b7f,0x0f7f};
static struct fx trapped_fx;
static volatile sig_atomic_t trapped,trapcode,trap_at;
static uintptr_t trigger_pc,probe_pc,resume_pc;
static void sigfpe(int sig,siginfo_t *info,void *ctx){
 (void)sig;ucontext_t*u=ctx;uintptr_t pc=(uintptr_t)u->uc_mcontext.gregs[REG_RIP];
 if(!u->uc_mcontext.fpregs || (pc!=probe_pc&&pc!=trigger_pc))_exit(119);
 const volatile unsigned char *s=(const unsigned char*)u->uc_mcontext.fpregs;unsigned char*d=(unsigned char*)&trapped_fx;
 for(unsigned i=0;i<512;i++)d[i]=s[i];
 trapped=1;trapcode=info->si_code;trap_at=pc==probe_pc?2:1;
 u->uc_mcontext.fpregs->cwd|=0x3f;u->uc_mcontext.fpregs->swd&=~0x8080;
 u->uc_mcontext.gregs[REG_RIP]=(greg_t)resume_pc;
}
static void put80(uint8_t *p,const struct value*v,int slot){
 uint64_t sig=v->sig;
 /* Distinguish identical NaN inputs from the two stack positions even after quieting. */
 if(slot && (v->se&0x7fff)==0x7fff && (sig&0x7fffffffffffffffULL))sig^=(uint64_t)slot<<8;
 memcpy(p,&sig,8);memcpy(p+8,&v->se,2);
}
static struct value ordinary(unsigned i){struct value v={"recognizable",0x8000000000000000ULL,0x3fff};unsigned n=i+1,k=0;while((n>>(k+1)))k++;v.se+=k;v.sig=(uint64_t)n<<(63-k);return v;}
static void init(struct fx*x,uint16_t cw,int n){
 memset(x,0,sizeof(*x));x->cw=cw;x->tw=n==8?255:(1u<<n)-1;x->mx=0x1f80;x->mxmask=0xffff;
 for(int i=0;i<8;i++){struct value v=ordinary(i);put80(x->st[i],&v,0);}
}
static uint16_t fulltag(const struct fx*x){
 struct fx copy=*x;uint8_t env[32] __attribute__((aligned(16)))={0};copy.cw|=0x3f;copy.sw&=~0x8080;
 __asm__ volatile("fxrstor64 %1; fnstenv %0; fninit":"=m"(env):"m"(copy):"memory","xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7","xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15","st","st(1)","st(2)","st(3)","st(4)","st(5)","st(6)","st(7)");uint16_t t;memcpy(&t,env+8,2);return t;
}
static int occupied(const struct fx*x,int i){return (x->tw>>(((x->sw>>11)+i)&7))&1;}
static void hex(const void*vp,int n){const unsigned char*p=vp;for(int i=n-1;i>=0;i--)printf("%02x",p[i]);}
static void reg(const struct fx*x,int i){if(!occupied(x,i))fputs("empty",stdout);else hex(x->st[i],10);}
static void stack(const struct fx*x){for(int i=0;i<8;i++){if(i)putchar(',');reg(x,i);}}
static unsigned cases(const struct form*f){
 switch(f->mode){
 case MODE_F32:return LEN(f32);case MODE_F64:return LEN(f64);case MODE_F80:return LEN(vals);
 case MODE_I16:return LEN(i16);case MODE_I32:return LEN(i32);case MODE_I64:return LEN(i64);case MODE_BCD:return LEN(bcd);
 case MODE_CONSTANT:return 1;case MODE_UNARY:return LEN(vals);
 case MODE_BINARY:return SPECIAL*SPECIAL+2*LEN(vals)+36;
 case MODE_PAIR_F32:return SPECIAL*LEN(f32)+LEN(vals);case MODE_PAIR_F64:return SPECIAL*LEN(f64)+LEN(vals);
 case MODE_PAIR_I16:return SPECIAL*LEN(i16)+LEN(vals);case MODE_PAIR_I32:return SPECIAL*LEN(i32)+LEN(vals);
 case MODE_TRANS:return LEN(vals)+LEN(transvals);case MODE_TRANSPAIR:return SPECIAL*SPECIAL+LEN(transvals);
 case MODE_ITER:return 16*64;
 case MODE_STACK:return 18;
 case MODE_ENV:case MODE_ENVLOAD:case MODE_RESTORE:case MODE_FXRESTORE:case MODE_ENVTRACE:return 18;
 case MODE_TRAP:return 1;
 default:abort();}
}
static const uint64_t*memvals(int mode,unsigned*len){
 switch(mode){case MODE_F32:case MODE_PAIR_F32:*len=LEN(f32);return f32;case MODE_F64:case MODE_PAIR_F64:*len=LEN(f64);return f64;case MODE_I16:case MODE_PAIR_I16:*len=LEN(i16);return i16;case MODE_I32:case MODE_PAIR_I32:*len=LEN(i32);return i32;case MODE_I64:*len=LEN(i64);return i64;default:*len=0;return NULL;}
}
static void input(const struct form*f,unsigned c,uint16_t cw,struct fx*x,uint8_t*mem){
 init(x,cw,f->n);memset(mem,0xa5,512);
 if(f->mode==MODE_UNARY){put80(x->st[0],&vals[c],0);return;}
 if(f->mode==MODE_CONSTANT)return;
 if(f->mode==MODE_BINARY){
  unsigned a,b;
  if(c<SPECIAL*SPECIAL){a=c/SPECIAL;b=c%SPECIAL;}
  else if(c<SPECIAL*SPECIAL+2*LEN(vals)){c-=SPECIAL*SPECIAL;a=c/2;b=c%2?3:2;}
  else{
   unsigned t=c-SPECIAL*SPECIAL-2*LEN(vals),p=(unsigned[]){24,53,64}[t/12],s=t%12/6?0x8000:0,d=t%6;
   struct value a0={"tie-a",0x8000000000000000ULL+(d>=3?1ULL<<(64-p):0),0x3fff|s};
   struct value b0={"tie-b",0x8000000000000000ULL+(d%3==2?1:0),(0x3fff-p)|s};
   if(d%3==0){b0.se--;b0.sig=UINT64_MAX;}
   put80(x->st[0],&a0,0);put80(x->st[1],&b0,0);return;
  }
  put80(x->st[0],&vals[a],0);put80(x->st[1],&vals[b],1);return;
 }
 if(f->mode==MODE_F80){put80(mem,&vals[c],0);return;}
 if(f->mode==MODE_BCD){put80(mem,&bcd[c],0);return;}
 unsigned nm;const uint64_t *mv=memvals(f->mode,&nm);
 if(mv){
  if(f->mode==MODE_PAIR_F32||f->mode==MODE_PAIR_F64||f->mode==MODE_PAIR_I16||f->mode==MODE_PAIR_I32){
   unsigned a,b;if(c<SPECIAL*nm){a=c/nm;b=c%nm;}else{a=c-SPECIAL*nm;b=a%nm;}put80(x->st[0],&vals[a],0);memcpy(mem,&mv[b],f->mb);
  }else memcpy(mem,&mv[c],f->mb);
  return;
 }
 if(f->mode==MODE_TRANS){put80(x->st[0],c<LEN(vals)?&vals[c]:&transvals[c-LEN(vals)],0);
  /* F2XM1 gets the 385-point central grid divided by eight: 385 valid ordinary arguments. */
  if(!strcmp(f->name,"F2XM1")&&c>=LEN(vals)&&c<LEN(vals)+385){uint16_t se;memcpy(&se,x->st[0]+8,2);if(se&0x7fff){se-=3;memcpy(x->st[0]+8,&se,2);}}
  return;}
 if(f->mode==MODE_TRANSPAIR){
  if(c<SPECIAL*SPECIAL){put80(x->st[0],&vals[c/SPECIAL],0);put80(x->st[1],&vals[c%SPECIAL],1);}
  else {c-=SPECIAL*SPECIAL;put80(x->st[0],&transvals[c],0);struct value y=ordinary(c%15);if(c%3==0)y.se|=0x8000;put80(x->st[1],&y,0);}return;
 }
 if(f->mode==MODE_ITER){
  unsigned k=c/64;struct value a={"large",0x8000000000000000ULL+123456789ULL*k,(uint16_t)(0x3fff+128+256*(k%8))};if(k>=8)a.se|=0x8000;
  struct value b={"divisor",0xc000000000000000ULL,0x3fff};put80(x->st[0],&a,0);put80(x->st[1],&b,0);return;
 }
 if(f->mode==MODE_STACK){init(x,cw,c%9);if(c>=9)x->sw=0x477f;return;}
 if(f->mode==MODE_ENV||f->mode==MODE_ENVLOAD||f->mode==MODE_RESTORE||f->mode==MODE_FXRESTORE||f->mode==MODE_ENVTRACE){
  init(x,cw,c%9);x->op=0x321;x->ip=0x12345678;x->dp=0x23456789;if(c>=9)x->sw=0x4700;
  if(f->mode==MODE_ENVLOAD||f->mode==MODE_RESTORE){
   memset(mem,0,512);uint16_t w=cw^0xc00;memcpy(mem,&w,2);w=0x4000;memcpy(mem+4,&w,2);w=fulltag(x);memcpy(mem+8,&w,2);w=0x456;memcpy(mem+18,&w,2);
   uint32_t p=0x3456789a;memcpy(mem+12,&p,4);p=0x456789ab;memcpy(mem+20,&p,4);for(int i=0;i<8;i++)memcpy(mem+28+10*i,x->st[i],10);
  }else if(f->mode==MODE_FXRESTORE){struct fx t=*x;t.cw^=0xc00;t.sw=0x4000;t.op=0x456;t.ip=0x3456789a;t.dp=0x456789ab;memcpy(mem,&t,512);}
  else if(f->mode==MODE_ENVTRACE){uint32_t z=0x3fc00000;memcpy(mem,&z,4);if(!strcmp(f->name,"TRACE_FLDCW")){uint16_t w=cw^0xc00;memcpy(mem,&w,2);}}
  return;
 }
 if(f->mode==MODE_TRAP){
  init(x,cw&~(1<<f->n),2);
  if(!strncmp(f->name,"IE_",3)){put80(x->st[0],&vals[3],0);x->tw=1;}
  if(!strncmp(f->name,"DE_",3)){put80(x->st[0],&vals[10],0);put80(x->st[1],&vals[2],1);}
  if(!strncmp(f->name,"ZE_",3)){put80(x->st[0],&vals[2],0);put80(x->st[1],&vals[0],1);}
  if(!strncmp(f->name,"OE_",3)){put80(x->st[0],&vals[15],0);put80(x->st[1],&vals[26],1);}
  if(!strncmp(f->name,"UE_",3)){put80(x->st[0],&vals[14],0);put80(x->st[1],&vals[14],1);}
  if(!strncmp(f->name,"PE_",3)){put80(x->st[0],&vals[2],0);put80(x->st[1],&vals[28],1);}
  if(!strncmp(f->name,"STACK_UNDERFLOW",15))x->tw=0;
  if(!strncmp(f->name,"STACK_OVERFLOW",14))x->tw=255;
  return;
 }
 abort();
}
static const char*ptrname(uint64_t p,int trunc,const struct form*f,const void*mem){
 static char out[4][80];static unsigned seq;char*s=out[(seq++)%4];uint64_t mask=trunc?0xffffffffULL:UINT64_MAX;p&=mask;
 if(!p)return "zero";
 if(p==0x12345678)return "seed-ip";
 if(p==0x23456789)return "seed-dp";
 if(p==0x3456789a)return "restore-ip";
 if(p==0x456789ab)return "restore-dp";
 if(p==((uintptr_t)f->insn&mask))return "instruction";
 if(p==((uintptr_t)f->probe&mask))return "probe";
 if(p>=((uintptr_t)mem&mask)&&p<(((uintptr_t)mem&mask)+512)){snprintf(s,80,"memory+%llu",(unsigned long long)(p-((uintptr_t)mem&mask)));return s;}
 /* Explicit category, never print machine addresses. Unexpected values are a validation failure. */
 return "UNMAPPED";
}
static void envprint(const struct fx*x,uint16_t ftw,const struct form*f,const void*m){printf(" FCW=%04x ATW=%02x FOP=%03x FIP=%s FDP=%s",x->cw,x->tw,x->op&0x7ff,ptrname(x->ip,0,f,m),ptrname(x->dp,0,f,m));(void)ftw;}
static void legacyenv(const uint8_t*env,const struct form*f,const void*mem){
 uint16_t cw,sw,op;uint32_t ip,dp;memcpy(&cw,env,2);memcpy(&sw,env+4,2);memcpy(&op,env+18,2);memcpy(&ip,env+12,4);memcpy(&dp,env+20,4);
 printf(" LEGACY_FCW=%04x LEGACY_FSW=%04x LEGACY_FOP=%03x LEGACY_FIP=%s LEGACY_FDP=%s",cw,sw,op&0x7ff,ptrname(ip,1,f,mem),ptrname(dp,1,f,mem));
}
static void savedmem(const struct form*f,const uint8_t*mem){
 if(f->out==512){const struct fx*x=(const struct fx*)mem;printf(" SAVED_FCW=%04x SAVED_FSW=%04x SAVED_ATW=%02x SAVED_FOP=%03x SAVED_FIP=%s SAVED_FDP=%s SAVED_STACK=",x->cw,x->sw,x->tw,x->op&0x7ff,ptrname(x->ip,0,f,mem),ptrname(x->dp,0,f,mem));stack(x);}
 else if(f->out==28||f->out==108){uint16_t cw,sw,tw,op;uint32_t ip,dp;memcpy(&cw,mem,2);memcpy(&sw,mem+4,2);memcpy(&tw,mem+8,2);memcpy(&op,mem+18,2);memcpy(&ip,mem+12,4);memcpy(&dp,mem+20,4);printf(" SAVED_FCW=%04x SAVED_FSW=%04x SAVED_FTW=%04x SAVED_FOP=%03x SAVED_FIP=%s SAVED_FDP=%s",cw,sw,tw,op&0x7ff,ptrname(ip,1,f,mem),ptrname(dp,1,f,mem));if(f->out==108){fputs(" SAVED_REG80=",stdout);for(int i=0;i<8;i++){if(i)putchar(',');hex(mem+28+10*i,10);}}}
}
static uint64_t total_rows,tag_checks,context_retries,timing_retries,max_accepted_ticks;
static int timing_diagnostics;
static uint64_t stamp(unsigned *cpu){unsigned lo,hi,aux;__asm__ volatile("rdtscp; lfence":"=a"(lo),"=d"(hi),"=c"(aux)::"memory");*cpu=aux;return ((uint64_t)hi<<32)|lo;}
/* Fixed, input-independent rejection limit in invariant-TSC ticks. */
#define MAX_CAPTURE_TICKS 5000ULL
#define MAX_CAPTURE_ATTEMPTS 128

static void execute(const struct form*f,unsigned c,unsigned ci,struct fx*carry){
 struct fx in,out[2] __attribute__((aligned(16)));uint8_t mem[512] __attribute__((aligned(64)));uint8_t beforemem[512];uint8_t env[32] __attribute__((aligned(16)))={0};uint64_t flags=0;input(f,c,cws[ci],&in,mem);
 if(f->mode==MODE_ITER&&c%64){in=*carry;in.cw=cws[ci];in.sw=0;in.tw=3;/* compact TOP into logical register order */}
 memcpy(beforemem,mem,512);memset(out,0,sizeof(out));trapped=0;trapcode=0;trap_at=0;trigger_pc=(uintptr_t)f->insn;probe_pc=(uintptr_t)f->probe;resume_pc=(uintptr_t)f->resume;
 /* An involuntary switch can destroy AMD masked FIP/FDP when the kernel saves/restores
    exception-only pointer fields. Reject the WHOLE interrupted measurement, never edit
    individual result fields. The retry uses exactly the same immutable inputs. */
 for(unsigned attempt=0;;attempt++){
  if(attempt==MAX_CAPTURE_ATTEMPTS){fprintf(stderr,"Could not isolate capture %s case=%u cw=%04x\n",f->name,c,in.cw);exit(9);}
  struct rusage before,after;unsigned cpu0,cpu1;uint64_t start,elapsed;
  if(getrusage(RUSAGE_THREAD,&before))exit(8);
  start=stamp(&cpu0);f->fn(&in,mem,out,env,&flags);elapsed=stamp(&cpu1)-start;
  if(timing_diagnostics)fprintf(stderr,"timing %s cw=%04x case=%u attempt=%u ticks=%llu migrated=%d\n",f->name,in.cw,c,attempt,(unsigned long long)elapsed,cpu0!=cpu1);
  if(getrusage(RUSAGE_THREAD,&after))exit(8);
  int switched=before.ru_nvcsw!=after.ru_nvcsw||before.ru_nivcsw!=after.ru_nivcsw;
  int delayed=(cpu0!=cpu1)||(f->mode!=MODE_TRAP&&elapsed>MAX_CAPTURE_TICKS);
  /* SIGFPE necessarily enters the kernel; its latency is not an isolation filter. */
  if(timing_diagnostics==2)delayed=0;
  if(!switched&&!delayed){if(elapsed>max_accepted_ticks)max_accepted_ticks=elapsed;break;}
  context_retries+=switched;timing_retries+=delayed;memcpy(mem,beforemem,512);memset(out,0,sizeof(out));memset(env,0,sizeof(env));trapped=0;trapcode=0;trap_at=0;
 }
 uint16_t ftw;memcpy(&ftw,env+8,2);
 if(trapped){out[0]=trapped_fx;ftw=fulltag(&out[0]);}
 else {uint16_t re=fulltag(&out[0]);tag_checks++;if(re!=ftw){fprintf(stderr,"FTW reconstruction disagreement %s %u %04x %04x\n",f->name,c,ftw,re);exit(5);}}
 if(f->mode==MODE_ITER)*carry=out[0];
 printf("%s %04x ",f->name,in.cw);reg(&in,0);putchar(' ');reg(&in,1);putchar(' ');
 if(f->mb)hex(beforemem,f->mb);else fputs("-",stdout);fputs(" -> ",stdout);if(trapped)fputs("TRAP ",stdout);
 reg(&out[0],0);putchar(' ');reg(&out[0],1);putchar(' ');
 if(f->out&&f->out<=10)hex(mem,f->out);else fputs("-",stdout);
 printf(" %04x %04x ",out[0].sw,ftw);if(f->flags)printf("%03llx",(unsigned long long)(flags&0x8d5));else putchar('-');
 if(f->meta){envprint(&out[0],ftw,f,mem);fputs(" STACK=",stdout);stack(&out[0]);printf(" CASE=%u",c);if(f->mode==MODE_STACK)printf(" BEFORE_FSW=%04x BEFORE_FTW=%04x",in.sw,fulltag(&in));}
 if(f->meta&&!trapped)legacyenv(env,f,mem);
 if(f->meta==2)savedmem(f,mem);
 if(f->mode==MODE_ITER)printf(" CHAIN=%u STEP=%u",c/64,c%64);
 if(f->mode==MODE_TRAP){printf(" SIGCODE=%d TRAP_AT=%s PRE_FSW=%04x PRE_ATW=%02x PRE_STACK=",trapcode,trap_at==2?"probe":trap_at==1?"trigger":"none",out[1].sw,out[1].tw);stack(&out[1]);}
 putchar('\n');total_rows++;
}
int main(int argc,char**argv){
 if(argc!=2&&argc!=3){fprintf(stderr,"usage: %s class|--counts\n",argv[0]);return 2;}
 unsigned ca,cb,cc,cd;if(!__get_cpuid(0x80000001,&ca,&cb,&cc,&cd)||!(cd&(1u<<27))){fprintf(stderr,"RDTSCP required for capture isolation\n");return 10;}
 if(!__get_cpuid(0x80000007,&ca,&cb,&cc,&cd)||!(cd&(1u<<8))){fprintf(stderr,"Invariant TSC required for capture isolation\n");return 10;}
 timing_diagnostics=argc==3?(!strcmp(argv[2],"--timing-unfiltered")?2:1):0;
 struct sigaction sa={0};sa.sa_sigaction=sigfpe;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);if(sigaction(SIGFPE,&sa,0))return 3;
 if(!strcmp(argv[1],"--counts")){for(unsigned i=0;i<LEN(forms);i++)printf("%s %s %u\n",forms[i].cls,forms[i].name,cases(&forms[i])*(unsigned)LEN(cws));return 0;}
 printf("# x87 native binary80 reference; MIT; format-v1\n# NAME FCW_BEFORE ST0 ST1 MEMORY_OPERAND -> [TRAP] ST0 ST1 MEMORY_RESULT FSW FTW FLAGS [metadata]\n# Input bits and sampling: inputs.json; forms: forms.json; flags mask=08d5; FTW physical-register order\n");
 for(unsigned i=0;i<LEN(forms);i++){const struct form*f=&forms[i];if(strcmp(f->cls,argv[1]))continue;printf("# FORM %s CASES_PER_CW=%u CW_COUNT=%zu EXPECTED_ROWS=%u\n",f->name,cases(f),LEN(cws),cases(f)*(unsigned)LEN(cws));
  for(unsigned ci=0;ci<LEN(cws);ci++){struct fx carry;memset(&carry,0,sizeof(carry));for(unsigned c=0;c<cases(f);c++)execute(f,c,ci,&carry);}
 }
 fprintf(stderr,"rows=%llu hardware_fulltag_reconstruction_checks=%llu\n",(unsigned long long)total_rows,(unsigned long long)tag_checks);
 fprintf(stderr,"whole_measurements_reexecuted_after_thread_context_switch=%llu timing_or_migration=%llu max_accepted_ticks=%llu\n",(unsigned long long)context_retries,(unsigned long long)timing_retries,(unsigned long long)max_accepted_ticks);
 return total_rows?0:4;
}
