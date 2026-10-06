/* Original native x86 hardware reference. MIT License (see LICENSE). */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <inttypes.h>
#include <cpuid.h>
struct input { uint8_t x[3][64]; uint32_t mx; };
struct output { uint8_t x[64]; uint32_t mx; uint32_t pad; uint64_t flags; };
struct form {
 const char *cls,*name,*enc,*er,*feature;
 int width,lane,scalar,nops,axes,imm,out_bytes,case_count,flags;
 uint64_t mask; int zero,types[3],sizes[3];
 void (*fn)(const struct input *,struct output *);
 char *resume,*fault;
};
#include "build/forms.h"
_Static_assert(offsetof(struct input,mx)==192,"assembly input layout");
_Static_assert(offsetof(struct output,mx)==64 && offsetof(struct output,flags)==72,"assembly output layout");
static volatile sig_atomic_t trapped, trap_mx, trap_code;
static volatile uintptr_t resume_ip, fault_ip;
static void on_fpe(int sig,siginfo_t *si,void *p) {
 (void)sig; ucontext_t *u=p;
 if ((uintptr_t)u->uc_mcontext.gregs[REG_RIP] != fault_ip || !u->uc_mcontext.fpregs) _exit(122);
 trapped=1;trap_mx=(sig_atomic_t)u->uc_mcontext.fpregs->mxcsr;trap_code=si->si_code;
 /* Preserve the actual fault-time MXCSR separately. Returning via sigreturn restores
    every saved register. Only mask bits are changed to permit safe continuation;
    RIP skips exactly the tested instruction, not its output stores. */
 u->uc_mcontext.fpregs->mxcsr |= 0x1f80;
 u->uc_mcontext.gregs[REG_RIP]=(greg_t)resume_ip;
}
static const uint32_t mxs[13]={0x1f80,0x3f80,0x5f80,0x7f80,0x1fc0,0x9f80,0x9fc0,0x1f00,0x1e80,0x1d80,0x1b80,0x1780,0x0f80};
/* First 16 are the exhaustive scalar special-value set. Extras are explicit boundary inputs. */
static const uint64_t F32[]={
0,0x80000000,0x3f800000,0xbf800000,0x40000000,0x7f800000,0xff800000,0x7fc01001,0xffc03002,0x7f802001,0xffa04004,0x00000001,0x007fffff,0x00800000,0x7f7fffff,0xff7fffff,
0x3f000000,0x3fc00000,0x40200000,0xbf000000,0xbfc00000,0x3effffff,0x3f7fffff,0x4affffff,0x4b800000,0x4effffff,0x4f000000,0xcf000000,0xcf000001,0x4f800000,0x5effffff,0x5f000000,0xdf000000,0x5f800000,
0x40400000,0x3f800001,0x00800001,0x80000001,0x807fffff,0x80800000,0x33000000,0x33800000,0x387fc000,0x387fe000,0x38800000,0x477fe000,0x477ff000,0x47800000,0xb3000000,0xb3800000,0xb87fe000,0xc77fe000,0xc77ff000,0xc7800000};
static const uint64_t F64[]={
0,0x8000000000000000ULL,0x3ff0000000000000ULL,0xbff0000000000000ULL,0x4000000000000000ULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8000000010001ULL,0xfff8000000030002ULL,0x7ff0000000020001ULL,0xfff4000000040004ULL,1,0x000fffffffffffffULL,0x0010000000000000ULL,0x7fefffffffffffffULL,0xffefffffffffffffULL,
0x3fe0000000000000ULL,0x3ff8000000000000ULL,0x4004000000000000ULL,0xbfe0000000000000ULL,0xbff8000000000000ULL,0x3fdfffffffffffffULL,0x41dfffffffe00000ULL,0x41e0000000000000ULL,0xc1e0000000000000ULL,0xc1e0000000100000ULL,0x41f0000000000000ULL,0x43dfffffffffffffULL,0x43e0000000000000ULL,0xc3e0000000000000ULL,0xc3e0000000000001ULL,0x47efffffe0000000ULL,0x47efffffefffffffULL,0x47effffff0000000ULL,0x36a0000000000000ULL,0x3690000000000000ULL,0x3690000000000001ULL,0x3810000000000000ULL,0x380fffffffffffffULL,0x00000000000007e8ULL,0x3fb999999999999aULL,0x4008000000000000ULL,0x3ff0000000000001ULL,0x0010000000000001ULL,0x8000000000000001ULL,0x800fffffffffffffULL,0x8010000000000000ULL};
static const uint64_t I32[]={0,1,2,3,0xffffffff,0xfffffffe,0x7fffffff,0x80000000,0x00ffffff,0x01000000,0x01000001,0xfeffffff,0xff000000,0xff000001,0x40000000,0xc0000000};
static const uint64_t I64[]={0,1,2,3,UINT64_MAX,UINT64_MAX-1,0x7fffffffffffffffULL,0x8000000000000000ULL,0x001fffffffffffffULL,0x0020000000000000ULL,0x0020000000000001ULL,0xffdfffffffffffffULL,0xffe0000000000000ULL,0xffe0000000000001ULL,0x0000000001000001ULL,0xfffffffffeffffffULL};
static const uint64_t F16[]={0,0x8000,0x3c00,0xbc00,0x4000,0x7c00,0xfc00,0x7e01,0xfe82,0x7d03,0xfd84,1,0x03ff,0x0400,0x7bff,0xfbff,0x3800,0x3e00,0x4100,0xb800,0xbe00,0x3555,0x3bff,0x3c01};
#define COUNT(x) (sizeof(x)/sizeof((x)[0]))
static uint64_t value(int type,unsigned idx,int slot,int lane) {
 const uint64_t *v;unsigned n;switch(type){
 case 0:v=F32;n=COUNT(F32);break;case 1:v=F64;n=COUNT(F64);break;case 2:v=I32;n=COUNT(I32);break;case 3:v=I64;n=COUNT(I64);break;default:v=F16;n=COUNT(F16);}
 uint64_t x=v[idx%n];
 /* Operand/lane tags change NaN payload only, preserving sign and quiet/signalling class. */
 if(type==0 && (x&0x7f800000)==0x7f800000 && (x&0x7fffff))x|=(uint64_t)(slot*256+lane*16);
 if(type==1 && (x&0x7ff0000000000000ULL)==0x7ff0000000000000ULL && (x&0xfffffffffffffULL))x|=(uint64_t)(slot*256+lane*16);
 if(type==4 && (x&0x7c00)==0x7c00 && (x&0x3ff))x=(x&~UINT64_C(0x7f))|(uint64_t)(slot*32+lane);
 return x;
}
static int type_size(int type){return type==1||type==3?8:type==4?2:4;}
static unsigned pow16(int axes){unsigned n=1;for(int j=0;j<3;j++)if(axes&(1<<j))n*=16;return n;}
static unsigned cases(const struct form*f){return f->case_count?(unsigned)f->case_count:(!strcmp(f->enc,"EVEX")||!f->scalar?64:pow16(f->axes)+64);}
static void make_input(const struct form*f,unsigned c,struct input*in){
 unsigned base=pow16(f->axes),digits=c;
 for(int s=0;s<3;s++){
  for(int j=0;j<64;j++)in->x[s][j]=(uint8_t)(0xa0+16*s+(j/4)%16);
  if(!(f->axes&(1<<s)))continue;
  int b=type_size(f->types[s]);
  if(f->scalar){
   unsigned k;
   if(!strcmp(f->enc,"EVEX"))k=f->case_count==16?(c+s*5)%16:c+s*3;
   else if(c<base){k=digits%16;digits/=16;}else{k=(c-base)+s*3;}
   uint64_t x=value(f->types[s],k,s,0);
   if(s==2 && !strncmp(f->name,"vfixupimm",9))x=UINT64_C(0x1111111111111111)*(c%16);
   memcpy(in->x[s],&x,b);
  }else{
   for(int j=0;j<64/b;j++){
    unsigned cc=c;
    if(f->case_count==16 && !f->scalar && c>=12){static const unsigned selected[]={50,54,58,60};cc=selected[c-12];}
    unsigned k=f->scalar?(cc+s*3):(cc*(2*s+1)+j*(s+1)+s*5);
    if(f->case_count==16 && (f->scalar || c<12))k=(c+s*5+j*(s+1))%16;
    if(cc>=48){
     /* Isolated non-low-lane Q/S NaN, mixed distinct NaNs, and ordinary lanes. */
     unsigned t=cc-48;
     k=2+(j+s)%3;
     if(t<12 && s==(int)(t/4) && j==1)k=(t%4<2?7:9)+(t%2);
     if(t>=12)k=7+(j+s+t)%4;
    }
    uint64_t x=value(f->types[s],k,s,j);
    if(s==2 && !strncmp(f->name,"vfixupimm",9))x=(UINT64_C(0x1111111111111111)*((c+j)%16));
    memcpy(in->x[s]+j*b,&x,b);
   }
  }
 }
}
static void hex(const uint8_t*p,int n){static const char h[]="0123456789abcdef";char buf[129];for(int i=0;i<n;i++){buf[2*i]=h[p[n-i-1]>>4];buf[2*i+1]=h[p[n-i-1]&15];}buf[2*n]=0;fputs(buf,stdout);}
extern int normal_crosscheck(const char*,int,const uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*);
static void execute(const struct form*f,struct input*in,struct output*out){
 memset(out,0,sizeof(*out));trapped=0;trap_mx=0;trap_code=0;resume_ip=(uintptr_t)f->resume;fault_ip=(uintptr_t)f->fault;
 f->fn(in,out);if(trapped)out->mx=(uint32_t)trap_mx;
}
static int check_native(void){
 unsigned a,b,c,d;if(!__get_cpuid(1,&a,&b,&c,&d)||!(c&bit_AVX)||!(c&bit_OSXSAVE))return 0;
 uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));return (lo&6)==6;
}
static int form_supported(const struct form*f){
 unsigned a,b,c,d,seven_b=0;uint32_t lo,hi;
 if(!__get_cpuid(1,&a,&b,&c,&d))return 0;
 __asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));
 unsigned one_c=c,one_d=d;
 if(__get_cpuid_count(7,0,&a,&b,&c,&d))seven_b=b;
 if(!strcmp(f->enc,"EVEX") && ((lo&0xe6)!=0xe6 || !(seven_b&(1u<<16)) || !(seven_b&(1u<<30)) || (f->width<512 && !f->scalar && !(seven_b&(1u<<31)))))return 0;
 if(!strcmp(f->feature,"avx512dq") && !(seven_b&(1u<<17)))return 0;
 if(!strcmp(f->feature,"avx512bw") && !(seven_b&(1u<<30)))return 0;
 if(!strcmp(f->feature,"fma") && !(one_c&(1u<<12)))return 0;
 if(!strcmp(f->feature,"f16c") && !(one_c&(1u<<29)))return 0;
 if(!strcmp(f->feature,"sse3") && !(one_c&1))return 0;
 if(!strcmp(f->feature,"sse4.1") && !(one_c&(1u<<19)))return 0;
 if(!strcmp(f->feature,"sse2") && !(one_d&(1u<<26)))return 0;
 if(!strcmp(f->feature,"sse") && !(one_d&(1u<<25)))return 0;
 if(!strcmp(f->feature,"mmx") && !(one_d&(1u<<23)))return 0;
 return 1;
}
int main(int argc,char**argv){
 if(argc!=2){fprintf(stderr,"usage: %s CLASS\n",argv[0]);return 2;}
 if(!check_native()){fputs("AVX with OSXSAVE required\n",stderr);return 2;}
 for(unsigned i=0;i<COUNT(FORMS);i++)if(!strcmp(FORMS[i].cls,argv[1])&&!form_supported(FORMS+i)){fprintf(stderr,"UNAVAILABLE: %s %s %d requires %s and harness AVX/OS state (EVEX: F/BW, packed128/256: VL); no data generated\n",FORMS[i].cls,FORMS[i].name,FORMS[i].width,FORMS[i].feature);return 3;}
 struct sigaction sa={0};sa.sa_sigaction=on_fpe;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);if(sigaction(SIGFPE,&sa,0)){perror("sigaction");return 2;}
 setvbuf(stdout,0,_IOFBF,1<<20);
 uint64_t lines=0,expected=0,traps=0,preserved=0,bad=0,cross=0,cross_bad=0;unsigned forms=0;
 for(unsigned i=0;i<COUNT(FORMS);i++)if(!strcmp(FORMS[i].cls,argv[1])){expected+=(uint64_t)cases(FORMS+i)*13;forms++;}
 if(!forms){fprintf(stderr,"no forms for class %s\n",argv[1]);return 2;}
 printf("# Native x86-64 reference v1; class=%s forms=%u expected_lines=%"PRIu64" MXCSR_variants=13\n",argv[1],forms,expected);
 printf("# name[imm] width [k=mask z=0|1 er=mode for EVEX] MXCSR_before X1 X2 X3 -> [TRAP] result MXCSR_after\n");
 printf("# Registers printed complete, high lane first. COMIS result=(LAHF_AH<<8)|OF; initial flags result=d701.\n");
 printf("# TRAP result is the restored native destination after skipping faulting instruction; MXCSR is fault-time signal context.\n");
 for(unsigned i=0;i<COUNT(FORMS);i++){
  const struct form*f=FORMS+i;if(strcmp(f->cls,argv[1]))continue;
  printf("# encoding=%s cases=%u\n",f->enc,cases(f));
  for(unsigned c=0;c<cases(f);c++){
   struct input in;make_input(f,c,&in);
   for(unsigned m=0;m<COUNT(mxs);m++){
    struct output out;in.mx=mxs[m];execute(f,&in,&out);
    if(f->flags){uint16_t fl=(uint16_t)(((out.flags&0xd5)<<8)|0x200|((out.flags>>11)&1));memcpy(out.x,&fl,2);}
    if(trapped){traps++;int ok=f->flags?out.x[0]==1&&out.x[1]==0xd7:memcmp(out.x,in.x[0],f->out_bytes)==0;if(ok)preserved++;else bad++;}
    if(m==0 && !trapped && (!strcmp(f->cls,"arithmetic")||!strcmp(f->cls,"fma")) && c<cases(f)){
      const uint8_t *a=in.x[0],*b=in.x[1],*cc=in.x[2];
      if(!strcmp(f->enc,"VEX")&&!strcmp(f->cls,"arithmetic")){a=in.x[1];b=f->nops==3?in.x[2]:in.x[1];}
      int v=normal_crosscheck(f->name,f->lane,a,b,cc,out.x);if(v>=0){cross++;if(!v)cross_bad++;}
    }
    if(f->imm>=0)printf("%s[%02x] %d ",f->name,f->imm,f->width);else printf("%s %d ",f->name,f->width);
    if(!strcmp(f->enc,"EVEX"))printf("k=%"PRIx64" z=%d er=%s ",f->mask,f->zero,f->er);
    printf("%04x ",in.mx);hex(in.x[0],f->sizes[0]);putchar(' ');hex(in.x[1],f->sizes[1]);putchar(' ');if(f->nops==3)hex(in.x[2],f->sizes[2]);else putchar('-');
    fputs(trapped?" -> TRAP ":" -> ",stdout);hex(out.x,f->out_bytes);printf(" %04x\n",out.mx);lines++;
   }
  }
 }
 printf("# lines=%"PRIu64" expected=%"PRIu64" traps=%"PRIu64" trap_destination_preserved=%"PRIu64" trap_preservation_failures=%"PRIu64" C_normal_crosschecks=%"PRIu64" C_mismatches=%"PRIu64"\n",lines,expected,traps,preserved,bad,cross,cross_bad);
 fprintf(stderr,"%s forms=%u lines=%"PRIu64" expected=%"PRIu64" traps=%"PRIu64" preserved=%"PRIu64" failed=%"PRIu64" C_checked=%"PRIu64" C_failed=%"PRIu64"\n",argv[1],forms,lines,expected,traps,preserved,bad,cross,cross_bad);
 return lines!=expected||bad||cross_bad;
}
