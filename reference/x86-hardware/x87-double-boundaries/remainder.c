/* SPDX-License-Identifier: MIT. Original composite SSE2 remainder candidate.
 * The numerical remainder is obtained by actual scalar SSE SUB instructions.
 * Integer bit operations only select exact powers-of-two divisors and branches.
 * Reference is completed x87 FPREM/FPREM1 (loop until C2=0), not one instruction.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
typedef struct __attribute__((packed)){uint64_t sig;uint16_t se;} ext;
typedef struct{ext x,s,initial;uint64_t bits;uint16_t before,after,single_before,single_after;uint32_t mx;unsigned steps,subtractions,qmag,qsigned,qx;} result;
static const char*rcs[]={"RN","RD","RU","RZ"};
static uint64_t rnd(uint64_t*s){uint64_t z=(*s+=UINT64_C(0x9e3779b97f4a7c15));z=(z^(z>>30))*UINT64_C(0xbf58476d1ce4e5b9);z=(z^(z>>27))*UINT64_C(0x94d049bb133111eb);return z^(z>>31);}
#define X87(OP,SUF,T) __asm__ volatile("fnclex; fld" SUF " %[b]; fld" SUF " %[a]; fnstsw %[pre]; xorl %%ecx,%%ecx; 1: " OP "; incl %%ecx; fnstsw %%ax; testw $0x400,%%ax; jz 2f; cmpl $128,%%ecx; jb 1b; 2: movw %%ax,%[post]; movl %%ecx,%[steps]; fstpt %[out]; fstp %%st" :[pre]"=m"(r->before),[post]"=m"(r->after),[steps]"=m"(r->steps),[out]"=m"(r->x):[a]"m"(*(T*)&a),[b]"m"(*(T*)&b):"eax","ecx","st","st(1)","cc","memory")
#define SINGLE(OP,SUF,T) __asm__ volatile("fnclex; fld" SUF " %[b]; fld" SUF " %[a]; fnstsw %[pre]; " OP "; fnstsw %[post]; fstpt %[out]; fstp %%st" :[pre]"=m"(r->single_before),[post]"=m"(r->single_after),[out]"=m"(r->initial):[a]"m"(*(T*)&a),[b]"m"(*(T*)&b):"st","st(1)","memory")
#define SSE(OP,SUF,T) __asm__ volatile("mov" SUF " %[a],%%xmm0; " OP SUF " %[b],%%xmm0; mov" SUF " %%xmm0,%[out]" :[out]"=m"(*(T*)&out):[a]"m"(*(T*)&a),[b]"m"(*(T*)&b):"xmm0","memory")
static uint64_t sub(int fmt,uint64_t a,uint64_t b){uint64_t out=0;if(fmt==32){SSE("sub","ss",uint32_t);}else{SSE("sub","sd",uint64_t);}return out;}
static uint64_t add(int fmt,uint64_t a,uint64_t b){uint64_t out=0;if(fmt==32){SSE("add","ss",uint32_t);}else{SSE("add","sd",uint64_t);}return out;}
static uint64_t invalid(int fmt){uint64_t a=0,b=0,out=0;if(fmt==32){SSE("div","ss",uint32_t);}else{SSE("div","sd",uint64_t);}return out;}
static uint64_t signxor(int fmt,uint64_t a,uint64_t mask){uint64_t out=0;if(fmt==32)__asm__ volatile("movd %1,%%xmm0; movd %2,%%xmm1; xorps %%xmm1,%%xmm0; movd %%xmm0,%0":"=m"(*(uint32_t*)&out):"m"(*(uint32_t*)&a),"m"(*(uint32_t*)&mask):"xmm0","xmm1","memory");else __asm__ volatile("movq %1,%%xmm0; movq %2,%%xmm1; xorpd %%xmm1,%%xmm0; movq %%xmm0,%0":"=m"(out):"m"(a),"m"(mask):"xmm0","xmm1","memory");return out;}
static int exponent(uint64_t v,int fmt){int p=fmt==32?23:52,bias=fmt==32?127:1023,e=(int)(v>>p);uint64_t frac=v&((UINT64_C(1)<<p)-1);return e?e-bias:(63-__builtin_clzll(frac))-(fmt==32?149:1074);}
/* x is positive finite nonzero, k >= 0. Selection is exact; overflow is used only for a comparison in FPREM1. */
static uint64_t scale_bits(uint64_t x,int fmt,int k){int p=fmt==32?23:52,bias=fmt==32?127:1023,emin=fmt==32?-126:-1022,emax=bias,minsub=fmt==32?-149:-1074;uint64_t fm=(UINT64_C(1)<<p)-1,frac=x&fm,sig;int enc=(int)(x>>p),e;
 if(enc){e=enc-bias;sig=((UINT64_C(1)<<p)|frac)<<(63-p);}else{int top=63-__builtin_clzll(frac);e=top+minsub;sig=frac<<(63-top);}e+=k;
 if(e>emax)return fmt==32?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);
 if(e>=emin)return ((uint64_t)(e+bias)<<p)|((sig>>(63-p))&fm);
 return sig>>(63-(e-minsub));
}
static void exec(int nearest,int pc,int rc,uint64_t a,uint64_t b,result*r){int fmt=pc==24?32:64;uint64_t sign=UINT64_C(1)<<(fmt-1),am=sign-1,inf=fmt==32?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);uint32_t mx=0x1f80|(rc<<13);uint16_t cw=(pc==24?0x7f:pc==53?0x27f:0x37f)|(rc<<10);__asm__ volatile("fninit; fldcw %0"::"m"(cw):"memory");
 if(fmt==32){if(nearest){SINGLE("fprem1","s",uint32_t);}else{SINGLE("fprem","s",uint32_t);}}else{if(nearest){SINGLE("fprem1","l",uint64_t);}else{SINGLE("fprem","l",uint64_t);}}
 if(fmt==32){if(nearest){X87("fprem1","s",uint32_t);}else{X87("fprem","s",uint32_t);}}else{if(nearest){X87("fprem1","l",uint64_t);}else{X87("fprem","l",uint64_t);}}
 __asm__ volatile("ldmxcsr %0"::"m"(mx):"memory");uint64_t aa=a&am,bb=b&am,out;unsigned q=0,steps=0;
 if(aa>inf||bb>inf)out=add(fmt,a,b);
 else if(aa==inf||!bb)out=invalid(fmt);
 else if(bb==inf||!aa)out=signxor(fmt,a,0);
 else{uint64_t rem=aa;while(rem>=bb){int k=exponent(rem,fmt)-exponent(bb,fmt);uint64_t divisor=scale_bits(bb,fmt,k);if(divisor>rem){--k;divisor=scale_bits(bb,fmt,k);}rem=sub(fmt,rem,divisor)&am;if(k<3)q=(q+(1u<<k))&7u;++steps;}
  if(nearest&&rem){uint64_t twice=scale_bits(rem,fmt,1);if(twice>bb||(twice==bb&&(q&1))){rem=sub(fmt,rem,bb);q=(q+1)&7;}}
  out=signxor(fmt,rem,a&sign);
 }
 r->bits=out;r->qmag=q;r->qsigned=((a^b)&sign)?(-q)&7:q;r->subtractions=steps;r->qx=((r->after>>6)&4)|((r->after>>9)&1)|((r->after>>13)&2);
 __asm__ volatile("stmxcsr %0":"=m"(r->mx));
 if(fmt==32)__asm__ volatile("fninit; flds %1; fstpt %0":"=m"(r->s):"m"(*(uint32_t*)&out):"st","memory");else __asm__ volatile("fninit; fldl %1; fstpt %0":"=m"(r->s):"m"(out):"st","memory");
}
static int eq(ext a,ext b){return a.se==b.se&&a.sig==b.sig;}
static int nanx(ext a){return(a.se&32767)==32767&&(a.sig&UINT64_C(0x7fffffffffffffff));}
static const char*classes[]={"ALL","VALUE_MISMATCH","EXCEPTION_FLAGS_MISMATCH","INVALID_OR_NONFINITE_INPUT","NAN_RESULT","X87_MULTISTEP","X87_C2_UNFINISHED","QUOTIENT_MAGNITUDE_BITS_DIFFER","QUOTIENT_SIGNED_BITS_DIFFER","SSE_INEXACT_OR_UNDERFLOW","FINITE_VALID_VALUE_MISMATCH","MORE_THAN_512_SUBTRACTIONS","SINGLE_INSTRUCTION_VALUE_MISMATCH","SINGLE_INSTRUCTION_C2_PARTIAL","SINGLE_COMPLETE_FINITE_CASE","SINGLE_COMPLETE_FINITE_VALUE_MISMATCH","SINGLE_COMPLETE_QUOTIENT_DIFF"};
#define NC (sizeof(classes)/sizeof(*classes))
static const uint64_t edge64[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x4000000000000000),UINT64_C(0xc000000000000000),UINT64_C(0x4008000000000000),UINT64_C(0xc008000000000000),UINT64_C(0x4010000000000000),UINT64_C(0x3fe0000000000000),1,UINT64_C(0x8000000000000001),UINT64_C(0x000fffffffffffff),UINT64_C(0x0010000000000000),UINT64_C(0x7fefffffffffffff),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8000000000011),UINT64_C(0xfff0000000000222)};
static const uint32_t edge32[]={0,0x80000000,0x3f800000,0xbf800000,0x40000000,0xc0000000,0x40400000,0xc0400000,0x40800000,0x3f000000,1,0x80000001,0x007fffff,0x00800000,0x7f7fffff,0x7f800000,0xff800000,0x7fc00011,0xff800222};
int main(int argc,char**argv){uint64_t n=argc>1?strtoull(argv[1],0,0):1000000;const char*dir=argc>2?argv[2]:"raw";char path[1024];snprintf(path,sizeof path,"%s/remainder-counts.csv",dir);FILE*c=fopen(path,"w");snprintf(path,sizeof path,"%s/remainder-examples.csv",dir);FILE*e=fopen(path,"w");if(!c||!e)return 2;fprintf(c,"operation,pc,rounding,class,total,random,edge\n");fprintf(e,"operation,pc,rounding,source,index,class,a_hex,b_hex,x87_80_hex,sse_80_hex,sse_native_hex,fsw_before,fsw_after,mxcsr,x87_iterations,sse_subtractions,x87_quotient_bits,candidate_q_magnitude_mod8,candidate_q_signed_mod8,single_x87_80_hex,single_fsw_before,single_fsw_after\n");int pcs[]={53,24,64};unsigned ne=sizeof(edge64)/sizeof(*edge64);
 for(int op=0;op<2;op++)for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++){int pc=pcs[p],fmt=pc==24?32:64;uint64_t seed=UINT64_C(0x52454d41494e4445),cnt[NC]={0},randomcnt[NC]={0};unsigned saved[NC]={0};
 for(uint64_t i=0;i<n+(uint64_t)ne*ne;i++){uint64_t a,b;if(i<n){a=rnd(&seed);b=rnd(&seed);if(fmt==32){a=(uint32_t)a;b=(uint32_t)b;}}else{unsigned j=(unsigned)(i-n);a=fmt==32?edge32[j/ne]:edge64[j/ne];b=fmt==32?edge32[j%ne]:edge64[j%ne];}result r={0};exec(op,pc,rc,a,b,&r);uint64_t am=(UINT64_C(1)<<(fmt-1))-1,inf=fmt==32?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000);int valid=(a&am)<inf&&(b&am)<inf&&(b&am),same=eq(r.x,r.s);unsigned qsingle=((r.single_after>>6)&4)|((r.single_after>>9)&1)|((r.single_after>>13)&2);int flags[NC]={1,!same,((r.after^r.mx)&63)!=0,!valid,nanx(r.x)||nanx(r.s),r.steps>1,!!(r.after&0x400),valid&&r.qx!=r.qmag,valid&&r.qx!=r.qsigned,!!(r.mx&0x30),valid&&!same,r.subtractions>512,!eq(r.initial,r.s),!!(r.single_after&0x400),valid&&!(r.single_after&0x400),valid&&!(r.single_after&0x400)&&!eq(r.initial,r.s),valid&&!(r.single_after&0x400)&&qsingle!=r.qmag};
 for(unsigned k=0;k<NC;k++)if(flags[k]){cnt[k]++;if(i<n)randomcnt[k]++;if(saved[k]++<20)fprintf(e,"%s,%d,%s,%s,%"PRIu64",%s,%016"PRIx64",%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%016"PRIx64",%04x,%04x,%08x,%u,%u,%u,%u,%u,%04x%016"PRIx64",%04x,%04x\n",op?"FPREM1_completed":"FPREM_completed",pc,rcs[rc],i<n?"random":"edge",i<n?i:i-n,classes[k],a,b,r.x.se,r.x.sig,r.s.se,r.s.sig,r.bits,r.before,r.after,r.mx,r.steps,r.subtractions,r.qx,r.qmag,r.qsigned,r.initial.se,r.initial.sig,r.single_before,r.single_after);}}
 for(unsigned k=0;k<NC;k++){fprintf(c,"%s,%d,%s,%s,%"PRIu64",%"PRIu64",%"PRIu64"\n",op?"FPREM1_completed":"FPREM_completed",pc,rcs[rc],classes[k],cnt[k],randomcnt[k],cnt[k]-randomcnt[k]);}fflush(c);fflush(e);fprintf(stderr,"complete remainder op%d PC%d %s value_mismatch=%"PRIu64" finite=%"PRIu64"\n",op,pc,rcs[rc],cnt[1],cnt[10]);}
 fclose(c);fclose(e);return 0;}
