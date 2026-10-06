// SPDX-License-Identifier: MIT
// Copyright (c) 2026. Original native x86 reference generator.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cpuid.h>

#define AF 0x10u
#define PF 4u
#define CF 1u
#define ZF 0x40u
#define SF 0x80u
#define OF 0x800u
#define ARITH 0x8d5u
static const uint64_t fixed[10]={0x0123456789abcdefULL,0xfedcba9876543210ULL,0x9e3779b97f4a7c15ULL,0xd1b54a32d192ed03ULL,0x94d049bb133111ebULL,0x2545f4914f6cdd1dULL,0xdeadbeefcafebabeULL,0x8000000000000001ULL,0x0000000100000080ULL,0x7fffffff00000000ULL};
static const char *names[]={"ANDN","BEXTR","BLSI","BLSMSK","BLSR","BZHI","MULX","PDEP","PEXT","RORX","SARX","SHLX","SHRX","ADCX","ADOX"};
static unsigned long long rows[15],errors[15],ruleerrors[15],undefzero[15],undefpres[15];
static uint64_t maskof(unsigned w){return w==64?UINT64_MAX:UINT32_MAX;}
static void patterns(uint64_t *v,unsigned w){uint64_t m=maskof(w);v[0]=0;v[1]=1;v[2]=2;v[3]=3;v[4]=m>>1;v[5]=1ULL<<(w-1);v[6]=m;v[7]=0x5555555555555555ULL&m;v[8]=0xaaaaaaaaaaaaaaaaULL&m;v[9]=1;v[10]=1ULL<<(w-1);v[11]=1ULL<<(w/2);for(int i=0;i<10;i++)v[12+i]=fixed[i]&m;}
struct Result {uint64_t r1,r2,pre,post;};
#define RUN(code) __asm__ volatile("pushq %[fl]\n\tpopfq\n\tpushfq\n\tpopq %[pre]\n\t" code "\n\tpushfq\n\tpopq %[post]" : "+a"(r.r1), "+d"(r.r2),[pre]"=&r"(r.pre),[post]"=&r"(r.post) : "b"(b), "c"(c), [fl]"r"(fl) : "cc","memory")
static struct Result execute(int op,unsigned w,uint64_t a,uint64_t b,uint64_t c,uint64_t fl){struct Result r={a,a,0,0};
#define WIDTH_CASE(O,S32,S64) case O: if(w==32){RUN(S32);}else{RUN(S64);} break
switch(op){
WIDTH_CASE(0,"andnl %%ebx,%%eax,%%eax","andnq %%rbx,%%rax,%%rax");
WIDTH_CASE(1,"bextrl %%ebx,%%eax,%%eax","bextrq %%rbx,%%rax,%%rax");
WIDTH_CASE(2,"blsil %%eax,%%eax","blsiq %%rax,%%rax");
WIDTH_CASE(3,"blsmskl %%eax,%%eax","blsmskq %%rax,%%rax");
WIDTH_CASE(4,"blsrl %%eax,%%eax","blsrq %%rax,%%rax");
WIDTH_CASE(5,"bzhil %%ebx,%%eax,%%eax","bzhiq %%rbx,%%rax,%%rax");
WIDTH_CASE(6,"mulxl %%ebx,%%eax,%%edx","mulxq %%rbx,%%rax,%%rdx");
WIDTH_CASE(7,"pdepl %%ebx,%%eax,%%eax","pdepq %%rbx,%%rax,%%rax");
WIDTH_CASE(8,"pextl %%ebx,%%eax,%%eax","pextq %%rbx,%%rax,%%rax");
case 9: switch(c){
#include "bmi_rorx.inc"
} break;
WIDTH_CASE(10,"sarxl %%ebx,%%eax,%%eax","sarxq %%rbx,%%rax,%%rax");
WIDTH_CASE(11,"shlxl %%ebx,%%eax,%%eax","shlxq %%rbx,%%rax,%%rax");
WIDTH_CASE(12,"shrxl %%ebx,%%eax,%%eax","shrxq %%rbx,%%rax,%%rax");
WIDTH_CASE(13,"adcxl %%ebx,%%eax","adcxq %%rbx,%%rax");
WIDTH_CASE(14,"adoxl %%ebx,%%eax","adoxq %%rbx,%%rax");
}return r;}
static uint64_t deposition(uint64_t x,uint64_t m){uint64_t r=0;while(m){uint64_t l=m&-m;if(x&1)r|=l;x>>=1;m&=m-1;}return r;}
static uint64_t extraction(uint64_t x,uint64_t m){uint64_t r=0,k=1;while(m){uint64_t l=m&-m;if(x&l)r|=k;k<<=1;m&=m-1;}return r;}
static unsigned sz(uint64_t x,unsigned w){return (x==0?ZF:0)|((x>>(w-1))?SF:0);}
static void one(int op,unsigned w,uint64_t a,uint64_t b,uint64_t c,unsigned fl){
struct Result r=execute(op,w,a,b,c,fl);uint64_t m=maskof(w),ex=0,hi=0;unsigned ef=fl,dm=ARITH,um=0;unsigned n=b&255;__uint128_t p;
switch(op){case 0:ex=(~a&b)&m;ef=sz(ex,w);dm=CF|OF|SF|ZF;um=AF|PF;break;
case 1:{unsigned s=b&255,l=(b>>8)&255;if(s<w){unsigned z=l<w-s?l:w-s;ex=z?((a>>s)&(z==64?m:(1ULL<<z)-1)):0;}ef=ex==0?ZF:0;dm=CF|OF|ZF;um=AF|PF|SF;break;}
case 2:ex=(a&-a)&m;ef=sz(ex,w)|(a?CF:0);dm=CF|OF|SF|ZF;um=AF|PF;break;
case 3:ex=(a^(a-1))&m;ef=sz(ex,w)|(a?0:CF);dm=CF|OF|SF|ZF;um=AF|PF;break;
case 4:ex=(a&(a-1))&m;ef=sz(ex,w)|(a?0:CF);dm=CF|OF|SF|ZF;um=AF|PF;break;
case 5:ex=n>=w?a:(n?a&((1ULL<<n)-1):0);ef=sz(ex,w)|(n>=w?CF:0);dm=CF|OF|SF|ZF;um=AF|PF;break;
case 6:p=(__uint128_t)a*b;ex=(uint64_t)p&m;hi=(uint64_t)(p>>w)&m;break;
case 7:ex=deposition(a,b)&m;break;case 8:ex=extraction(a,b)&m;break;
case 9:n=c&(w-1);ex=n?((a>>n)|(a<<(w-n)))&m:a;break;
case 10:n=b&(w-1);ex=w==32?(uint32_t)((int32_t)a>>n):(uint64_t)((int64_t)a>>n);break;
case 11:ex=(a<<(b&(w-1)))&m;break;case 12:ex=a>>(b&(w-1));break;
case 13:p=(__uint128_t)a+b+!!(fl&CF);ex=(uint64_t)p&m;ef=(fl&~CF)|((p>>w)?CF:0);break;
case 14:p=(__uint128_t)a+b+!!(fl&OF);ex=(uint64_t)p&m;ef=(fl&~OF)|((p>>w)?OF:0);break;}
unsigned pred=(ef&~um)|(fl&~ARITH);if(um){unsigned byte=(unsigned)ex&255;unsigned even=1;while(byte){even^=byte&1;byte>>=1;}pred|=even?PF:0;if(op==1)pred|=AF;}
int bad=(r.pre&0xffff)!=fl||((r.r1&m)!=ex)||((r.post^ef)&dm)||((r.post^r.pre)&(0xffff&~ARITH));if(op==6&&(r.r2&m)!=hi)bad=1;rows[op]++;errors[op]+=bad;ruleerrors[op]+=bad||((r.post^pred)&65535);undefzero[op]+=!(r.post&um);undefpres[op]+=!((r.post^r.pre)&um);
printf("%s %u %04x %0*llx ",names[op],w,(unsigned)r.pre&65535,w/4,(unsigned long long)a);
if(op>=2&&op<=4)printf("- -");else if(op==9)printf("- %0*llx",w/4,(unsigned long long)c);else if(op==1||op==5||(op>=10&&op<=12))printf("- %0*llx",w/4,(unsigned long long)b);else printf("%0*llx -",w/4,(unsigned long long)b);
printf(" -> %0*llx ",w/4,(unsigned long long)(r.r1&m));if(op==6)printf("%0*llx",w/4,(unsigned long long)(r.r2&m));else printf("-");printf(" %04x\n",(unsigned)r.post&65535);
}
int main(void){unsigned a,b,c,d;__cpuid_count(7,0,a,b,c,d);int bmi1=!!(b&(1u<<3)),bmi2=!!(b&(1u<<8)),adx=!!(b&(1u<<19));printf("# native x86-64 CPUID.7.0:EBX=%08x BMI1=%d BMI2=%d ADX=%d\n",b,bmi1,bmi2,adx);fprintf(stderr,"CPUID.7.0:EBX=%08x BMI1=%d BMI2=%d ADX=%d\n",b,bmi1,bmi2,adx);
for(int op=0;op<15;op++){int enabled=op<=4?bmi1:op<=12?bmi2:adx;if(!enabled){printf("# SKIP %s: CPUID feature unavailable\n",names[op]);continue;}for(unsigned w=32;w<=64;w+=32){uint64_t v[22];patterns(v,w);for(int i=0;i<22;i++){int count=op>=2&&op<=4?1:op==9?256:22;for(int j=0;j<count;j++)for(int f=0;f<2;f++)one(op,w,v[i],v[j%22],op==9?j:0,f?0xad7:0x202);}
// BEXTR explicitly covers all meaningful start/length boundaries, besides full pattern pairs.
if(op==1)for(unsigned s=0;s<=w+1;s++)for(unsigned l=0;l<=w+1;l++)for(int i=0;i<22;i++)for(int f=0;f<2;f++)one(op,w,v[i],s|(l<<8),0,f?0xad7:0x202);
}}
unsigned long long err=0;for(int op=0;op<15;op++){fprintf(stderr,"%s rows=%llu defined_matches=%llu defined_mismatches=%llu rule_matches=%llu rule_mismatches=%llu undefined_all_zero_matches=%llu undefined_preserved_matches=%llu\n",names[op],rows[op],rows[op]-errors[op],errors[op],rows[op]-ruleerrors[op],ruleerrors[op],undefzero[op],undefpres[op]);err+=errors[op];}return !!err;}
