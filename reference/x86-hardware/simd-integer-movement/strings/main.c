/* SPDX-License-Identifier: MIT
 * Original scalar string models and native instruction capture. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <cpuid.h>
typedef struct { uint8_t z[32],a[32],b[32],rz[32],ra[32],rb[32]; int32_t la,lb; uint32_t ecx0,ecx; uint16_t flags; uint8_t *mp; uint8_t mem[64]; } Ctx;
_Static_assert(offsetof(Ctx,mp)==216,"assembly offsets");
static sigjmp_buf env;static volatile sig_atomic_t trapped;
static void handler(int s){trapped=s;siglongjmp(env,1);}
typedef struct {const char *name; int imm,vex,explicit_len,mask,mem; void(*fn)(Ctx*);} Form;
#include "forms.h"
static int execute(const Form*f,Ctx*c);
static int execute(const Form*f,Ctx*c){trapped=0;if(sigsetjmp(env,1)==0)f->fn(c);return trapped;}
static uint64_t rows,checked,upper_ok,upper_bad,unused_ok,unused_bad,model_bad,ignored7_ok,ignored7_bad;
static uint64_t agg_checked[4];
static void hex(const uint8_t*x,int n){for(int i=n-1;i>=0;i--)printf("%02x",x[i]);}
static void init(Ctx*c,int id){memset(c,0,sizeof *c);for(int i=0;i<32;i++){c->z[i]=(uint8_t)(0xd3+7*i);c->a[i]=(uint8_t)(0x51+3*i);c->b[i]=(uint8_t)(0xa7+5*i);}c->ecx0=0x13579bdf;
 if(id<68){int len=id/4,v=id%4;c->la=c->lb=len;for(int i=0;i<16;i++)c->a[i]=c->b[i]=i<len?(uint8_t)(17+7*i):0;
 if(v==1 && len)c->b[len/2]^=0x40;
 if(v>=2){for(int i=0;i<16;i++)c->a[i]=c->b[i]=(uint8_t)(17+7*i);if(len<16)c->a[len]=c->b[len]=0;if(len){c->b[len/2]=0;if(v==2)c->a[len/2]=0;}if(v==3 && len)c->b[(len+3)%16]^=0x80;}
 }else{static const uint8_t p[4][16]={{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16},{0xff,0x80,0x7f,1,0xfe,0x81,0x7e,2,0xfd,0x82,0x7d,3,0xfc,0x83,0x7c,4},{0x80,0xff,1,0x7f,0x81,0xfe,2,0x7e,0x82,0xfd,3,0x7d,0x83,0xfc,4,0x7c},{0x55,0xaa,0x55,0xaa,0x7f,0x80,0xff,1,0x55,0xaa,0x55,0xaa,0x7f,0x80,0xff,1}};
 memcpy(c->a,p[(id-68)%4],16);memcpy(c->b,p[(id-67)%4],16);c->la=c->lb=16;
 if(id>=72){static const int32_t lens[16][2]={{-1,1},{1,-1},{-8,8},{8,-8},{-16,16},{16,-16},{-17,17},{17,-17},{-255,255},{255,-255},{17,16},{16,17},{32,0},{0,32},{INT_MIN,INT_MAX},{INT_MAX,INT_MIN}};c->la=lens[id-72][0];c->lb=lens[id-72][1];}}
}
static unsigned elem(const uint8_t*p,int k,int w){return w==1?p[k]:(unsigned)p[k*2]|((unsigned)p[k*2+1]<<8);}
static int length(const uint8_t*p,int32_t x,int w,int expl){int n=16/w;if(expl){uint32_t u=x<0?0u-(uint32_t)x:(uint32_t)x;return u>(unsigned)n?n:(int)u;}int i=0;while(i<n&&elem(p,i,w))i++;return i;}
static int sval(unsigned x,int w,int sign){return sign?(w==1?(int)(int8_t)x:(int)(int16_t)x):(int)x;}
static int model(const Form*f,const Ctx*c){int imm=f->imm,w=(imm&1)?2:1,n=16/w,agg=(imm>>2)&3;

 int la=length(c->a,c->la,w,f->explicit_len),lb=length(c->b,c->lb,w,f->explicit_len);unsigned r=0;
 for(int j=0;j<n;j++){int v=0;if(agg==0){if(j<lb)for(int i=0;i<la;i++)v|=elem(c->a,i,w)==elem(c->b,j,w);}
 else if(agg==1){if(j<lb)for(int i=0;i+1<la;i+=2){int a=sval(elem(c->a,i,w),w,imm&2),b=sval(elem(c->a,i+1,w),w,imm&2),t=sval(elem(c->b,j,w),w,imm&2);v|=a<=t&&t<=b;}}
 else if(agg==2){v=(j>=la&&j>=lb)||(j<la&&j<lb&&elem(c->a,j,w)==elem(c->b,j,w));}
 else{v=1;for(int i=0;i+j<n;i++)if(i<la&&(i+j>=lb||elem(c->a,i,w)!=elem(c->b,i+j,w)))v=0;}r|=(unsigned)v<<j;}
 unsigned valid=(1u<<n)-1,pol=(imm>>4)&3;if(pol==1)r^=valid;if(pol==3)r^=(1u<<lb)-1;
 uint16_t flags=0x202|(r?1:0)|(r&1?0x800:0)|(la<n?0x80:0)|(lb<n?0x40:0);
 uint8_t z[32];memcpy(z,c->z,32);uint32_t ecx=c->ecx0;
 if(f->mask){memset(z,0,16);if(imm&64){for(int j=0;j<n;j++)if(r&(1u<<j))memset(z+j*w,255,w);}else{z[0]=r;z[1]=r>>8;}if(f->vex)memset(z+16,0,16);}
 else{ecx=n;if(r){if(imm&64){for(int j=0;j<n;j++)if(r&(1u<<j))ecx=j;}else{for(int j=n-1;j>=0;j--)if(r&(1u<<j))ecx=j;}}}
 agg_checked[agg]++;return memcmp(z,c->rz,32)==0&&ecx==c->ecx&&flags==c->flags;
}
int main(void){unsigned a,b,c,d;__cpuid(1,a,b,c,d);if(!(c&(1u<<20))||!(c&(1u<<28))){fprintf(stderr,"ERROR: SSE4.2/AVX unavailable\n");return 2;}
 struct sigaction sa={0};sa.sa_handler=handler;sigemptyset(&sa.sa_mask);sigaction(SIGSEGV,&sa,0);sigaction(SIGBUS,&sa,0);sigaction(SIGILL,&sa,0);
 printf("# Native string comparisons; X1=actual destination before and primary result=destination after: ECX/32 for index, YMM0/128 for mask. X2/X3 and all YMM snapshots are full256.\n");
 printf("# Flags initialized to 0202; lengths signed 32-bit. 72 common cases; 16 extra explicit-length cases. All 256 imm8 values; MEM=0 register,1 aligned,2 unaligned+1.\n");
 size_t nf=sizeof(forms)/sizeof(*forms);uint64_t faults=0;uint64_t expected=3*(4ULL*256*72+4ULL*256*88);
 for(size_t k=0;k<nf;k++){Form*f=forms+k;int nc=f->explicit_len?88:72;for(int id=0;id<nc;id++){Ctx x;init(&x,id);x.mp=(uint8_t*)(((uintptr_t)x.mem+15)&~(uintptr_t)15)+(f->mem==2?1:0);memcpy(x.mp,x.b,16);int sig=execute(f,&x);rows++;
 printf("%s[%02x] %d ",f->name,f->imm,f->mask?128:32);if(f->mask)hex(x.z,32);else printf("%08x",x.ecx0);putchar(' ');hex(x.a,32);putchar(' ');if(f->mem)hex(x.mp,16);else hex(x.b,32);printf(" -> ");
 if(sig){printf("FAULT=%s",sig==SIGSEGV?"SIGSEGV":sig==SIGILL?"SIGILL":"SIGBUS");faults++;}
 else{if(f->mask)hex(x.rz,32);else printf("%08x",x.ecx);printf(" FLAGS=%04x",x.flags);
  if(f->mask)printf(" ECX_AFTER=%08x",x.ecx);else{printf(" YMM0_BEFORE=");hex(x.z,32);printf(" YMM0_AFTER=");hex(x.rz,32);}}
 printf(" LA=%d LB=%d ECX0=%08x CASE=%02d MEM=%d\n",x.la,x.lb,x.ecx0,id,f->mem);
 if(sig)continue;
 uint8_t up[16]={0};if(!(f->vex&&f->mask))memcpy(up,x.z+16,16);int good=!memcmp(x.rz+16,up,16)&&!memcmp(x.ra,x.a,32)&&!memcmp(x.rb,x.b,32);if(good)upper_ok++;else upper_bad++;
 if(f->mask&&!(f->imm&64)){int u=1;for(int i=2;i<16;i++)u&=x.rz[i]==0;if(u)unused_ok++;else unused_bad++;}
 int m=model(f,&x);if(m>=0){checked++;if(!m){if(model_bad<5)fprintf(stderr,"model mismatch %s imm=%02x case=%d\n",f->name,f->imm,id);model_bad++;}}
 if(f->imm<128){Ctx y;init(&y,id);y.mp=(uint8_t*)(((uintptr_t)y.mem+15)&~(uintptr_t)15)+(f->mem==2?1:0);memcpy(y.mp,y.b,16);forms[k+128*3].fn(&y);if(!memcmp(x.rz,y.rz,32)&&x.ecx==y.ecx&&x.flags==y.flags)ignored7_ok++;else ignored7_bad++;}
 }}
 fprintf(stderr,"rows=%llu expected=%llu forms=%zu scalar_checked=%llu scalar_mismatches=%llu faults=%llu\n",(unsigned long long)rows,(unsigned long long)expected,nf,(unsigned long long)checked,(unsigned long long)model_bad,(unsigned long long)faults);
 fprintf(stderr,"aggregation_checks equal_any=%llu ranges=%llu equal_each=%llu equal_ordered=%llu\n",(unsigned long long)agg_checked[0],(unsigned long long)agg_checked[1],(unsigned long long)agg_checked[2],(unsigned long long)agg_checked[3]);
 fprintf(stderr,"upper_semantics_support=%llu counterexamples=%llu bitmask_unused_zero_support=%llu counterexamples=%llu imm7_ignored_support=%llu counterexamples=%llu\n",(unsigned long long)upper_ok,(unsigned long long)upper_bad,(unsigned long long)unused_ok,(unsigned long long)unused_bad,(unsigned long long)ignored7_ok,(unsigned long long)ignored7_bad);
 return nf!=6144||rows!=expected||model_bad||upper_bad||unused_bad||ignored7_bad||faults;
}
