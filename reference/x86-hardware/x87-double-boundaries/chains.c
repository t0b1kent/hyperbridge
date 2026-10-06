/* SPDX-License-Identifier: MIT. Original native-hardware register-chain oracle. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
typedef struct __attribute__((packed)){uint64_t sig;uint16_t se;} ext;
typedef struct {ext x,s,first;uint64_t native;uint16_t before,after,first_fsw;uint32_t mx;} result;
static uint64_t next(uint64_t*s){uint64_t z=(*s+=UINT64_C(0x9e3779b97f4a7c15));z=(z^(z>>30))*UINT64_C(0xbf58476d1ce4e5b9);z=(z^(z>>27))*UINT64_C(0x94d049bb133111eb);return z^(z>>31);}
static int eq(ext x,ext y){return x.sig==y.sig&&x.se==y.se;}
static int nanx(ext x){return (x.se&32767)==32767&&(x.sig&UINT64_C(0x7fffffffffffffff));}
static int fin(ext x){return (x.se&32767)!=32767;}
static const char*rcs[]={"RN","RD","RU","RZ"};
/* The loop below contains only arithmetic on ST(0), no floating-point memory stores.
 * FNSTSW after the complete chain records sticky exceptions; memory operands are constants.
 * SSE likewise keeps the intermediate in xmm0 throughout. */
#define XCHAIN(type,suf,op1,op2) __asm__ volatile("fnclex; fld" suf " %[a]; fnstsw %[before]; mov %[n],%%ecx; 1: " op1 suf " %[b]; dec %%ecx; jz 2f; " op2 suf " %[b]; dec %%ecx; jnz 1b; 2: fnstsw %[after]; fstpt %[out]" :[before]"=m"(r->before),[after]"=m"(r->after),[out]"=m"(r->x):[a]"m"(*(type*)&a),[b]"m"(*(type*)&b),[n]"r"(n):"ecx","st","cc","memory")
#define SCHAIN(type,suf,op1,op2) __asm__ volatile("ldmxcsr %[mx]; mov" suf " %[a],%%xmm0; mov %[n],%%ecx; 1: " op1 suf " %[b],%%xmm0; dec %%ecx; jz 2f; " op2 suf " %[b],%%xmm0; dec %%ecx; jnz 1b; 2: mov" suf " %%xmm0,%[out]; stmxcsr %[status]" :[out]"=m"(*(type*)&r->native),[status]"=m"(r->mx):[a]"m"(*(type*)&a),[b]"m"(*(type*)&b),[n]"r"(n),[mx]"m"(mx):"ecx","xmm0","cc","memory")
#define FIRST(type,suf,op) __asm__ volatile("fnclex; fld" suf " %[a]; " op suf " %[b]; fnstsw %[sw]; fstpt %[out]" :[sw]"=m"(r->first_fsw),[out]"=m"(r->first):[a]"m"(*(type*)&a),[b]"m"(*(type*)&b):"st","memory")
static void exec(int family,int fmt,int n,uint64_t a,uint64_t b,uint32_t mx,result*r){
 r->native=0;
 if(fmt==32){if(family==0){XCHAIN(uint32_t,"s","fmul","fdiv");SCHAIN(uint32_t,"ss","mul","div");FIRST(uint32_t,"s","fmul");}else{XCHAIN(uint32_t,"s","fadd","fsub");SCHAIN(uint32_t,"ss","add","sub");FIRST(uint32_t,"s","fadd");}__asm__ volatile("flds %1; fstpt %0":"=m"(r->s):"m"(*(uint32_t*)&r->native):"st","memory");}
 else{if(family==0){XCHAIN(uint64_t,"l","fmul","fdiv");SCHAIN(uint64_t,"sd","mul","div");FIRST(uint64_t,"l","fmul");}else{XCHAIN(uint64_t,"l","fadd","fsub");SCHAIN(uint64_t,"sd","add","sub");FIRST(uint64_t,"l","fadd");}__asm__ volatile("fldl %1; fstpt %0":"=m"(r->s):"m"(r->native):"st","memory");}
}
static const char*classes[]={"ALL","VALUE_MISMATCH","FLAGS_MISMATCH","NAN_PRESENT","FIRST_ABOVE_BASELINE_RANGE","FIRST_BELOW_BASELINE_NORMAL","RECOVERED_NORMAL_AFTER_HIGH_FIRST","RECOVERED_NORMAL_AFTER_LOW_FIRST","NORMAL_FINAL_VALUE_MISMATCH","MATCH_VALUE_AND_FLAGS"};
#define NC (sizeof(classes)/sizeof(classes[0]))
static FILE*counts,*examples;
static void record(int fam,int n,int pc,int rc,const char*src,uint64_t i,uint64_t a,uint64_t b,result*r,uint64_t*c,unsigned*l){
 int min=pc==24?-126:-1022,max=pc==24?127:1023;int fe=(r->first.se&32767)-16383,e=(r->x.se&32767)-16383;
 int equal=eq(r->x,r->s),flags=((r->after^r->mx)&63)==0,nan=nanx(r->x)||nanx(r->s),hi=fin(r->first)&&r->first.sig&&fe>max,lo=fin(r->first)&&r->first.sig&&fe<min,normal=fin(r->x)&&r->x.sig&&e>=min&&e<=max;
 int yes[NC]={1,!equal,!flags,nan,hi,lo,hi&&normal,lo&&normal,!equal&&!nan&&normal,equal&&flags};
 for(unsigned j=0;j<NC;j++)if(yes[j]){c[j]++;if(l[j]++<20)fprintf(examples,"%s,%d,%d,%s,%s,%"PRIu64",%s,%016"PRIx64",%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%04x,%04x,%04x,%08x,%d,%d\n",fam?"add_sub":"mul_div",n,pc,rcs[rc],src,i,classes[j],a,b,r->x.se,r->x.sig,r->s.se,r->s.sig,r->first.se,r->first.sig,r->before,r->after,r->first_fsw,r->mx,equal,flags);}
}
static const uint64_t edges64[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x4000000000000000),UINT64_C(0x3fe0000000000000),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),UINT64_C(0x0010000000000000),1,UINT64_C(0x000fffffffffffff),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8000000000001),UINT64_C(0x7ff0000000000123),UINT64_C(0x7fe0000000000000),UINT64_C(0x8010000000000000),UINT64_C(0x8000000000000001),UINT64_C(0x4008000000000000),UINT64_C(0x3fd5555555555555)};
static const uint32_t edges32[]={0,0x80000000,0x3f800000,0xbf800000,0x40000000,0x3f000000,0x7f7fffff,0xff7fffff,0x00800000,1,0x007fffff,0x7f800000,0xff800000,0x7fc00001,0x7f800123,0x7f000000,0x80800000,0x80000001,0x40400000,0x3eaaaaab};
static void run(int fam,int n,int pc,int rc,uint64_t count){uint16_t cw=(pc==24?0x007f:0x027f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);__asm__ volatile("fninit; fldcw %0"::"m"(cw):"memory");uint64_t c[NC]={0},ce[NC]={0},s=UINT64_C(0x434841494e533031);unsigned logged[NC]={0};result r;
 for(uint64_t i=0;i<count;i++){uint64_t a=next(&s),b=next(&s);if(pc==24){a=(uint32_t)a;b=(uint32_t)b;}exec(fam,pc==24?32:64,n,a,b,mx,&r);record(fam,n,pc,rc,"random",i,a,b,&r,c,logged);}
 unsigned ne=sizeof(edges64)/sizeof(edges64[0]);for(unsigned i=0;i<ne;i++)for(unsigned j=0;j<ne;j++){uint64_t a=pc==24?edges32[i]:edges64[i],b=pc==24?edges32[j]:edges64[j];exec(fam,pc==24?32:64,n,a,b,mx,&r);record(fam,n,pc,rc,"edge",i*ne+j,a,b,&r,ce,logged);}
 for(unsigned j=0;j<NC;j++){fprintf(counts,"%s,%d,%d,%s,%s,%"PRIu64",%"PRIu64",%"PRIu64"\n",fam?"add_sub":"mul_div",n,pc,rcs[rc],classes[j],c[j]+ce[j],c[j],ce[j]);}
 fflush(counts);fflush(examples);fprintf(stderr,"complete %s length%d PC%d %s count=%"PRIu64" mismatch=%"PRIu64"\n",fam?"add_sub":"mul_div",n,pc,rcs[rc],c[0]+ce[0],c[1]+ce[1]);}
int main(int argc,char**argv){uint64_t count=argc>1?strtoull(argv[1],0,0):1000000;char path[1024];const char*dir=argc>2?argv[2]:"raw";snprintf(path,sizeof path,"%s/chains-counts.csv",dir);counts=fopen(path,"w");snprintf(path,sizeof path,"%s/chains-examples.csv",dir);examples=fopen(path,"w");if(!counts||!examples)return 2;fprintf(counts,"family,length,pc,rounding,class,total,random,edge\n");fprintf(examples,"family,length,pc,rounding,source,index,class,a_hex,b_hex,x87_80_hex,sse_as_80_hex,separate_first_step_x87_hex,fsw_before,fsw_after,separate_first_step_fsw,mxcsr,value_equal,flags_equal\n");for(int fam=0;fam<2;fam++)for(int n=2;n<=8;n++)for(int p=0;p<2;p++)for(int rc=0;rc<4;rc++)run(fam,n,p?24:53,rc,count);fclose(counts);fclose(examples);__asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));return 0;}
