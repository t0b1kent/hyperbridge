// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>
#include <stddef.h>
struct Ctx{uint8_t d[32],a[32],b[32],out[32],maskout[32];uint8_t*mem;};
_Static_assert(offsetof(struct Ctx,mem)==160,"ABI");
#include "gather-generated.h"
static sigjmp_buf jump;static struct Ctx *active;static volatile sig_atomic_t fault,trap,err;
static void handler(int sig,siginfo_t *si,void *v){
 (void)si;ucontext_t *u=v;fault=sig;trap=u->uc_mcontext.gregs[REG_TRAPNO];err=u->uc_mcontext.gregs[REG_ERR];uint8_t*x=(uint8_t*)u->uc_mcontext.fpregs;
 if(active&&x){for(int j=0;j<16;j++){active->out[j]=x[160+j];active->maskout[j]=x[192+j];}uint32_t magic;uint64_t bv;memcpy(&magic,x+464,4);memcpy(&bv,x+512,8);for(int j=0;j<16;j++){active->out[j+16]=(magic==0x46505853&&(bv&4))?x[576+j]:0;active->maskout[j+16]=(magic==0x46505853&&(bv&4))?x[608+j]:0;}}
 siglongjmp(jump,1);
}
static void run(const struct Op*o,struct Ctx*c){fault=trap=err=0;active=c;if(sigsetjmp(jump,1)==0)o->fn(c);active=0;}
static uint64_t rd(const uint8_t*p,int n){uint64_t v=0;for(int i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void wr(uint8_t*p,int n,uint64_t v){for(int i=0;i<n;i++)p[i]=v>>(8*i);}
static void hex(const uint8_t*p,int n){for(int i=n-1;i>=0;i--)printf("%02x",p[i]);}
static uint8_t byteval(unsigned x,int p){return (uint8_t)((x*37u+11u+p*29u)^(x>>3));}
int main(void){
 if(!__builtin_cpu_supports("avx2")){fprintf(stderr,"AVX2 required\n");return 2;}
 struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);sigaction(SIGSEGV,&sa,0);sigaction(SIGBUS,&sa,0);sigaction(SIGILL,&sa,0);
 long ps=sysconf(_SC_PAGESIZE);uint8_t*area=mmap(0,ps*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(area==MAP_FAILED||mprotect(area+ps,ps,PROT_READ|PROT_WRITE))return 3;uint8_t*page=area+ps;
 const unsigned expected=sizeof(ops)/sizeof(*ops)*9*11;unsigned rows=0,checked=0,faults=0,complete=0;
 printf("# Native AVX2 gathers: full YMM destination/index/mask before and destination/mask after, MSB first. No vector arithmetic is used by the scalar checker.\n");
 printf("# name[scale].VEXwidth.case.pN width X1 X2 X3 -> RESULT MASK_AFTER FAULT TRAP ERROR VALID_LANES MEM_INPUT\n");
 printf("# VALID_LANES marks readable candidate addresses; inaccessible MEM_INPUT lanes are zero placeholders. Indices are signed and scaled. Expected rows: %u\n",expected);
 FILE*ct=fopen("gather-counts.tsv","w");if(!ct)return 4;fprintf(ct,"name\tencoding_width\telement_bytes\tindex_bytes\tscale\trows\tscalar_checked\tfaults\n");
 for(size_t z=0;z<sizeof(ops)/sizeof(*ops);z++){
  const struct Op*o=ops+z;unsigned of=0;
  for(int p=0;p<9;p++)for(int mode=0;mode<11;mode++){
   struct Ctx c={0};uint8_t vals[32]={0},want[32]={0};unsigned valid=0,onbits=0;int firstbad=o->n;int64_t indexes[8]={0};
   for(int j=0;j<ps;j++)page[j]=byteval(j,p);
   for(int j=0;j<32;j++){c.d[j]=(uint8_t)(0xc0+j+p*7);c.a[j]=(uint8_t)(0x70+j+p);c.b[j]=(uint8_t)(0x91+j*3+p);}
   c.mem=page+ps/2+(mode==1);static const int ind[8]={-64,-17,-3,0,1,9,16,31};
   for(int j=0;j<o->n;j++){
    int on=mode==3?0:(mode==2||mode==4||mode==7||mode==10)?(j%2==0|| (mode==10&&j==o->n-1)):1;
    int64_t idx=ind[(j+p)%8];if(mode==8)idx=(j%2)?-3:9;
    if(mode==3||(mode==4&&!on)||((mode==5||mode==9||mode==10)&&j==o->n-1)||(mode==6&&j==0))idx=(ps/2+64)/o->scale;
    if(mode==4&&!on&&j%4==1)idx=-idx;
    indexes[j]=idx;wr(c.a+j*o->ie,o->ie,(uint64_t)idx);
    uint64_t mask=(mode==7||mode==9||mode==10)?(on?(UINT64_C(1)<<(o->e*8-1))|0x123:0x123):on?UINT64_MAX:0x7654321;
    wr(c.b+j*o->e,o->e,mask);if(on)onbits|=1u<<j;
    intptr_t pos=(intptr_t)(c.mem-page)+idx*o->scale;
    if(pos>=0&&pos+o->e<=ps){valid|=1u<<j;for(int k=0;k<o->e;k++)vals[j*o->e+k]=byteval(pos+k,p);}else if(on&&j<firstbad)firstbad=j;
    memcpy(want+j*o->e,on?vals+j*o->e:c.d+j*o->e,o->e);
   }
   memcpy(c.out,c.d,32);memcpy(c.maskout,c.b,32);run(o,&c);
   int bad=firstbad<o->n;
   if((fault!=0)!=bad||(fault&&(fault!=SIGSEGV||trap!=14))){fprintf(stderr,"gather fault mismatch %s w%d s%d p%d mode%d sig%d trap%d\n",o->name,o->w,o->scale,p,mode,fault,trap);return 5;}
   if(!fault){
    uint8_t zero[32]={0};if(memcmp(c.out,want,32)||memcmp(c.maskout,zero,32)){fprintf(stderr,"gather model mismatch %s w%d s%d p%d mode%d out%d mask%d\n",o->name,o->w,o->scale,p,mode,memcmp(c.out,want,32),memcmp(c.maskout,zero,32));return 6;}complete++;
   }else{
    faults++;of++;
    for(int j=0;j<o->n;j++){
     uint64_t m=rd(c.maskout+j*o->e,o->e);int wason=(onbits>>j)&1,readable=(valid>>j)&1,done=m==0;
     uint64_t initial=rd(c.b+j*o->e,o->e);
     if((!wason&&m!=0)||(wason&&m!=0&&m!=initial)||(wason&&!readable&&done)||(wason&&j<firstbad&&!done)) {fprintf(stderr,"gather partial-mask invariant %s w%d s%d p%d mode%d lane%d mask%llx\n",o->name,o->w,o->scale,p,mode,j,(unsigned long long)m);return 7;}
     const uint8_t*exp=(wason&&done)?vals+j*o->e:c.d+j*o->e;
     if(memcmp(c.out+j*o->e,exp,o->e)){fprintf(stderr,"gather partial-data invariant %s w%d mode%d lane%d\n",o->name,o->w,mode,j);return 8;}
    }
    for(int j=o->n*o->e;j<32;j++)if(c.out[j]!=c.d[j]||c.maskout[j]!=c.b[j]){fprintf(stderr,"gather fault upper-preservation invariant %s w%d mode%d byte%d result%02x mask%02x\n",o->name,o->w,mode,j,c.out[j],c.maskout[j]);return 9;}
   }
   rows++;checked++;static const char*modes[]={"aligned","unaligned","partial_mask","alloff_guard","masked_guard","fault_last","fault_first","signbit_mask","duplicate_indices","fault_signbit_last","fault_partial_last"};
   printf("%s[%d].VEX%d.%s.p%d %d ",o->name,o->scale,o->w*8,modes[mode],p,o->n*o->e<=16?128:256);hex(c.d,32);printf(" ");hex(c.a,32);printf(" ");hex(c.b,32);printf(" -> ");hex(c.out,32);printf(" ");hex(c.maskout,32);printf(" FAULT=%d TRAP=%d ERROR=%d VALID_LANES=%02x MEM_INPUT=",fault,trap,err,valid);hex(vals,32);printf("\n");
   (void)indexes;
  }
  fprintf(ct,"%s\t%d\t%d\t%d\t%d\t99\t99\t%u\n",o->name,o->w*8,o->e,o->ie,o->scale,of);
 }
 fclose(ct);fprintf(stderr,"gather rows=%u expected=%u scalar_checked=%u full_results=%u fault_invariants=%u forms=%zu\n",rows,expected,checked,complete,faults,sizeof(ops)/sizeof(*ops));return rows!=expected;
}
