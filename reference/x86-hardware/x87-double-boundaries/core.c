/* SPDX-License-Identifier: MIT
 * Original C/x86-64 inline assembly hardware oracle, 2026.
 * No floating point reference arithmetic is implemented in C.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <cpuid.h>

typedef struct __attribute__((packed)) { uint64_t sig; uint16_t se; } ext80;
typedef struct { ext80 x,s; uint64_t sbits, memory_bits; uint16_t before,after,stored,memory_before,memory_after; uint32_t mx; } result;
enum { ADD,SUB,MUL,DIV,SUBR,DIVR,SQRT,NOPS };
static const char *opnames[]={"FADD","FSUB","FMUL","FDIV","FSUBR","FDIVR","FSQRT"};
static const char *rcnames[]={"RN","RD","RU","RZ"};
static const int pcs[]={53,24,64};
static uint64_t rng(uint64_t *s){uint64_t z=(*s+=UINT64_C(0x9e3779b97f4a7c15));z=(z^(z>>30))*UINT64_C(0xbf58476d1ce4e5b9);z=(z^(z>>27))*UINT64_C(0x94d049bb133111eb);return z^(z>>31);}
#define X87_BODY(instr,suffix,type) __asm__ volatile("fnclex\n\tfld" suffix " %[a]\n\tfnstsw %[before]\n\t" instr suffix " %[b]\n\tfnstsw %[after]\n\tfstpt %[x]\n\tfnstsw %[stored]" : [x]"=m"(r->x),[before]"=m"(r->before),[after]"=m"(r->after),[stored]"=m"(r->stored):[a]"m"(*(const type*)&a),[b]"m"(*(const type*)&b):"st","memory")
#define X87_SWITCH(suffix,type) switch(op){case ADD:X87_BODY("fadd",suffix,type);break;case SUB:X87_BODY("fsub",suffix,type);break;case MUL:X87_BODY("fmul",suffix,type);break;case DIV:X87_BODY("fdiv",suffix,type);break;case SUBR:X87_BODY("fsubr",suffix,type);break;case DIVR:X87_BODY("fdivr",suffix,type);break;case SQRT:__asm__ volatile("fnclex; fld" suffix " %[a]; fnstsw %[before]; fsqrt; fnstsw %[after]; fstpt %[x]; fnstsw %[stored]" :[x]"=m"(r->x),[before]"=m"(r->before),[after]"=m"(r->after),[stored]"=m"(r->stored):[a]"m"(*(const type*)&a):"st","memory");break;}
#define SSE_BODY(instr,suffix,type) __asm__ volatile("ldmxcsr %[control]; mov" suffix " %[a],%%xmm0; " instr suffix " %[b],%%xmm0; mov" suffix " %%xmm0,%[out]; stmxcsr %[mx]" : [out]"=m"(*(type*)&r->sbits),[mx]"=m"(r->mx):[control]"m"(mx),[a]"m"(*(const type*)&a),[b]"m"(*(const type*)&b):"xmm0","memory")
#define SSE_SWITCH(suffix,type) switch(op){case ADD:SSE_BODY("add",suffix,type);break;case SUB:case SUBR:SSE_BODY("sub",suffix,type);break;case MUL:SSE_BODY("mul",suffix,type);break;case DIV:case DIVR:SSE_BODY("div",suffix,type);break;case SQRT:SSE_BODY("sqrt",suffix,type);break;}
static void execute(int op,int fmt,uint64_t a,uint64_t b,uint32_t mx,result *r){
 r->sbits=0;
 if(fmt==32){X87_SWITCH("s",uint32_t);}else{X87_SWITCH("l",uint64_t);}
 if(op==SUBR||op==DIVR){uint64_t t=a;a=b;b=t;}
 if(op==SQRT)b=a;
 if(fmt==32){SSE_SWITCH("ss",uint32_t);__asm__ volatile("flds %1; fstpt %0":"=m"(r->s):"m"(*(uint32_t*)&r->sbits):"st","memory");}
 else{SSE_SWITCH("sd",uint64_t);__asm__ volatile("fldl %1; fstpt %0":"=m"(r->s):"m"(r->sbits):"st","memory");}
 r->memory_bits=0;
 if(fmt==32){__asm__ volatile("fnclex; fldt %[x]; fnstsw %[before]; fstps %[out]; fnstsw %[after]" :[out]"=m"(*(uint32_t*)&r->memory_bits),[before]"=m"(r->memory_before),[after]"=m"(r->memory_after):[x]"m"(r->x):"st","memory");}
 else{__asm__ volatile("fnclex; fldt %[x]; fnstsw %[before]; fstpl %[out]; fnstsw %[after]" :[out]"=m"(r->memory_bits),[before]"=m"(r->memory_before),[after]"=m"(r->memory_after):[x]"m"(r->x):"st","memory");}
}
static int same(ext80 a,ext80 b){return a.se==b.se&&a.sig==b.sig;}
static int nan80(ext80 x){return (x.se&32767)==32767&&(x.sig&UINT64_C(0x7fffffffffffffff));}
static int finite80(ext80 x){return (x.se&32767)!=32767;}
static int denormal64(uint64_t v,int fmt){return fmt==32?!(v&UINT64_C(0x7f800000))&&(v&UINT64_C(0x007fffff)):!(v&UINT64_C(0x7ff0000000000000))&&(v&UINT64_C(0x000fffffffffffff));}
static int finitebits(uint64_t v,int fmt){return fmt==32?(v&UINT64_C(0x7f800000))!=UINT64_C(0x7f800000):(v&UINT64_C(0x7ff0000000000000))!=UINT64_C(0x7ff0000000000000);}
static const char *classes[]={"ALL","VALUE_MISMATCH","FLAGS_MISMATCH","EXCEEDS_BASELINE_MAX_EXP","BELOW_BASELINE_MIN_NORMAL_EXP","SSE_SUBNORMAL_RESULT","NAN_PRESENT","NAN_SIGN_DIFFERENCE","NAN_QUIET_DIFFERENCE","NAN_PAYLOAD_DIFFERENCE","FINITE_NORMAL_VALUE_MISMATCH","FINITE_INPUTS","NONFINITE_INPUTS","EXCEEDS_DOUBLE_MAX_EXP","BELOW_DOUBLE_MIN_NORMAL_EXP","INPUT_SUBNORMAL","MATCH_VALUE_AND_FLAGS","PC64_NONNAN_VALUE_MISMATCH","MEMORY_VALUE_MISMATCH","MEMORY_FINITE_DIFFERENCE","UNDERFLOW_DOUBLE_ROUNDING_CANDIDATE","STORE_OVERFLOW","STORE_UNDERFLOW","STORE_INEXACT","GUARDED_DOMAIN","GUARDED_VALUE_MISMATCH","GUARDED_FLAGS_MISMATCH"};
#define NC (sizeof(classes)/sizeof(classes[0]))
static FILE *counts,*examples;
static void print_example(int op,int pc,int rc,int fmt,const char *source,uint64_t index,unsigned c,uint64_t a,uint64_t b,result*r){
 fprintf(examples,"%s,%d,%s,%d,%s,%"PRIu64",%s,%016"PRIx64",%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%016"PRIx64",%04x,%04x,%04x,%08x,%d,%d,%016"PRIx64",%04x,%04x\n",opnames[op],pc,rcnames[rc],fmt,source,index,classes[c],a,b,r->x.se,r->x.sig,r->s.se,r->s.sig,r->sbits,r->before,r->after,r->stored,r->mx,same(r->x,r->s),((r->after^r->mx)&63)==0,r->memory_bits,r->memory_before,r->memory_after);
}
static void record(int op,int pc,int rc,int fmt,const char*source,uint64_t index,uint64_t a,uint64_t b,result*r,uint64_t*cnt,unsigned*logged){
 int eq=same(r->x,r->s),flags=((r->after^r->mx)&63)==0,nan=nan80(r->x)||nan80(r->s);
 int e=(int)(r->x.se&32767)-16383,nz=r->x.sig!=0,fin=finite80(r->x);
 int hi=fmt==32?127:1023,lo=fmt==32?-126:-1022;
 int unary=op==SQRT,inputs_finite=finitebits(a,fmt)&&(unary||finitebits(b,fmt));
 int subinput=denormal64(a,fmt)||(!unary&&denormal64(b,fmt));
 int guarded=inputs_finite&&!subinput&&fin&&(!nz||(e>=lo&&e<=hi));
 int yes[NC]={1,!eq,!flags,fin&&nz&&e>hi,fin&&nz&&e<lo,denormal64(r->sbits,fmt),nan,nan&&((r->x.se^r->s.se)&32768),nan&&((r->x.sig^r->s.sig)&UINT64_C(0x4000000000000000)),nan&&((r->x.sig^r->s.sig)&UINT64_C(0x3fffffffffffffff)),!eq&&!nan&&fin&&nz&&e>=lo&&e<=hi,inputs_finite,!inputs_finite,fin&&nz&&e>1023,fin&&nz&&e< -1022,subinput,eq&&flags,pc==64&&!eq&&!nan,r->memory_bits!=r->sbits,!nan&&finitebits(r->memory_bits,fmt)&&finitebits(r->sbits,fmt)&&r->memory_bits!=r->sbits,pc!=64&&!nan&&fin&&nz&&e<lo&&r->memory_bits!=r->sbits,!!(r->memory_after&8),!!(r->memory_after&16),!!(r->memory_after&32),guarded,guarded&&!eq,guarded&&!flags};
 for(unsigned c=0;c<NC;c++)if(yes[c]){cnt[c]++;if(logged[c]<20){print_example(op,pc,rc,fmt,source,index,c,a,b,r);logged[c]++;}}
}
static const uint64_t edge64[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x4000000000000000),UINT64_C(0xc000000000000000),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8000000000000),UINT64_C(0xfff8000000000123),UINT64_C(0x7ff0000000000001),UINT64_C(0xfff0000000000100),1,UINT64_C(0x8000000000000001),UINT64_C(0x000fffffffffffff),UINT64_C(0x800fffffffffffff),UINT64_C(0x0010000000000000),UINT64_C(0x8010000000000000),UINT64_C(0x0010000000000001),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),UINT64_C(0x7fe0000000000000),UINT64_C(0x3fe0000000000000),UINT64_C(0xbfe0000000000000),UINT64_C(0x3ca0000000000000),UINT64_C(0x3c90000000000000),UINT64_C(0x3ff0000000000001),UINT64_C(0x3fefffffffffffff),UINT64_C(0x4340000000000000),UINT64_C(0x433fffffffffffff),UINT64_C(0x001fffffffffffff),UINT64_C(0x0020000000000000)};
static const uint32_t edge32[]={0,0x80000000,0x3f800000,0xbf800000,0x40000000,0xc0000000,0x7f800000,0xff800000,0x7fc00000,0xffc00123,0x7f800001,0xff800100,1,0x80000001,0x007fffff,0x807fffff,0x00800000,0x80800000,0x00800001,0x7f7fffff,0xff7fffff,0x7f000000,0x3f000000,0xbf000000,0x33800000,0x33000000,0x3f800001,0x3f7fffff,0x4b800000,0x4b7fffff,0x00ffffff,0x01000000};
static void run(int op,int pc,int rc,uint64_t n){
 int fmt=pc==24?32:64;uint16_t cw=(pc==24?0x007f:pc==53?0x027f:0x037f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);
 __asm__ volatile("fninit; fldcw %0; ldmxcsr %1"::"m"(cw),"m"(mx):"memory");
 uint64_t cnt[NC]={0},randomcnt[NC]={0},edgecnt[NC]={0};unsigned logged[NC]={0};result r;
 uint64_t state=UINT64_C(0x004f5241434c4531); // identical input set across operations / modes of same width
 for(uint64_t i=0;i<n;i++){uint64_t a=rng(&state),b=rng(&state);if(fmt==32){a=(uint32_t)a;b=(uint32_t)b;}execute(op,fmt,a,b,mx,&r);record(op,pc,rc,fmt,"random",i,a,b,&r,randomcnt,logged);}
 unsigned ne=sizeof(edge64)/sizeof(edge64[0]);
 for(unsigned i=0;i<ne;i++)for(unsigned j=0;j<ne;j++){uint64_t a=fmt==32?edge32[i]:edge64[i],b=fmt==32?edge32[j]:edge64[j];execute(op,fmt,a,b,mx,&r);record(op,pc,rc,fmt,"edge",i*ne+j,a,b,&r,edgecnt,logged);}
 // Every signed power of two in the source's finite normal exponent range, against +/-1 and halves.
 unsigned bias=fmt==32?127:1023,shift=fmt==32?23:52,emax=fmt==32?254:2046;
 for(unsigned e=1;e<=emax;e++)for(unsigned sign=0;sign<2;sign++)for(unsigned k=0;k<4;k++){uint64_t a=((uint64_t)e<<shift)|((uint64_t)sign<<(fmt-1));uint64_t b=((uint64_t)(bias-(k>>1))<<shift)|((uint64_t)(k&1)<<(fmt-1));execute(op,fmt,a,b,mx,&r);record(op,pc,rc,fmt,"power",((e*2+sign)*4+k),a,b,&r,edgecnt,logged);}
 for(unsigned c=0;c<NC;c++){cnt[c]=randomcnt[c]+edgecnt[c];fprintf(counts,"%s,%d,%s,%d,%s,%"PRIu64",%"PRIu64",%"PRIu64"\n",opnames[op],pc,rcnames[rc],fmt,classes[c],cnt[c],randomcnt[c],edgecnt[c]);}
 fflush(counts);fflush(examples);fprintf(stderr,"complete %s PC%d %s count=%"PRIu64" mismatch=%"PRIu64" flags=%"PRIu64"\n",opnames[op],pc,rcnames[rc],cnt[0],cnt[1],cnt[2]);
}
int main(int argc,char**argv){uint64_t n=argc>1?strtoull(argv[1],0,0):1000000;int limit=argc>2?atoi(argv[2]):7;const char*out=argc>3?argv[3]:"raw";char path[1024];
 unsigned a,b,c,d;__cpuid(0,a,b,c,d);char vendor[13];memcpy(vendor,&b,4);memcpy(vendor+4,&d,4);memcpy(vendor+8,&c,4);vendor[12]=0;__cpuid(1,a,b,c,d);if(!(d&(1u<<0))||!(d&(1u<<26))){fprintf(stderr,"x87/SSE2 unavailable\n");return 2;}fprintf(stderr,"hardware vendor=%s cpuid1_eax=%08x hypervisor=%u compiler=%s n=%"PRIu64"\n",vendor,a,c>>31,__VERSION__,n);
 snprintf(path,sizeof path,"%s/core-counts.csv",out);counts=fopen(path,"w");snprintf(path,sizeof path,"%s/core-examples.csv",out);examples=fopen(path,"w");if(!counts||!examples)return 3;
 fprintf(counts,"operation,pc,rounding,input_bits,class,total,random,edge\n");fprintf(examples,"operation,pc,rounding,input_bits,source,index,class,a_hex,b_hex,x87_80_hex,sse_as_80_hex,sse_native_hex,fsw_before,fsw_after,fsw_after_store,mxcsr,value_equal,exception_flags_equal,x87_memory_hex,fsw_memory_before,fsw_memory_after\n");
 for(int op=0;op<limit&&op<NOPS;op++)for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++)run(op,pcs[p],rc,n);
 fclose(counts);fclose(examples);__asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));return 0;}
