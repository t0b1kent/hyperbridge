/* SPDX-License-Identifier: MIT. Original FSCALE composite-SSE2 candidate.
 * C/integer logic truncates the exponent argument and constructs exact powers of two.
 * Every numerical scaling operation executes an actual SSE MUL instruction.
 * Negative scaling applies the short residual power first, then large normal factors,
 * avoiding an unnecessary subnormal-rounding stage before a short final power.
 */
#define main core_unused_entry
#include "core.c"
#undef main
#define SCALE_X87(SUF,T) __asm__ volatile("fnclex; fld" SUF " %[b]; fld" SUF " %[a]; fnstsw %[before]; fscale; fnstsw %[after]; fstpt %[out]; fstp %%st" :[before]"=m"(r->before),[after]"=m"(r->after),[out]"=m"(r->x):[a]"m"(*(T*)&a),[b]"m"(*(T*)&b):"st","st(1)","memory")
static uint64_t multiply(int fmt,uint64_t a,uint64_t b){uint64_t out=0;if(fmt==32)__asm__ volatile("movss %1,%%xmm0; mulss %2,%%xmm0; movss %%xmm0,%0":"=m"(*(uint32_t*)&out):"m"(*(uint32_t*)&a),"m"(*(uint32_t*)&b):"xmm0","memory");else __asm__ volatile("movsd %1,%%xmm0; mulsd %2,%%xmm0; movsd %%xmm0,%0":"=m"(out):"m"(a),"m"(b):"xmm0","memory");return out;}
static int scale_integer(uint64_t b,int fmt){int p=fmt==32?23:52,bias=fmt==32?127:1023;uint64_t sign=UINT64_C(1)<<(fmt-1),u=b&(sign-1);int e=(int)(u>>p)-bias;if(e<0)return 0;int n;if(e>=12)n=4096;else n=(int)(((UINT64_C(1)<<p)|(u&((UINT64_C(1)<<p)-1)))>>(p-e));return(b&sign)?-n:n;}
static void scale_execute(int fmt,uint64_t a,uint64_t b,uint32_t mx,result*r,int*requested,unsigned*steps){
 if(fmt==32){SCALE_X87("s",uint32_t);}else{SCALE_X87("l",uint64_t);}
 __asm__ volatile("ldmxcsr %0"::"m"(mx):"memory");uint64_t inf=fmt==32?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000),sign=UINT64_C(1)<<(fmt-1),ab=b&(sign-1),out=a;int p=fmt==32?23:52,bias=fmt==32?127:1023,positive=bias,negative=1-bias;*steps=0;*requested=0;
 if(ab>inf){out=multiply(fmt,a,b);++*steps;}
 else if(ab==inf){uint64_t factor=(b&sign)?0:inf;out=multiply(fmt,a,factor);++*steps;}
 else{int n=scale_integer(b,fmt);*requested=n;int chunk=n<0?negative:positive,residual=n%chunk;
  if(residual){out=multiply(fmt,out,(uint64_t)(bias+residual)<<p);n-=residual;++*steps;}
  while(n){out=multiply(fmt,out,(uint64_t)(bias+chunk)<<p);n-=chunk;++*steps;}
  if(!*steps){out=multiply(fmt,out,(uint64_t)bias<<p);++*steps;}
 }
 r->sbits=out;__asm__ volatile("stmxcsr %0":"=m"(r->mx));
 if(fmt==32)__asm__ volatile("flds %1; fstpt %0":"=m"(r->s):"m"(*(uint32_t*)&out):"st","memory");else __asm__ volatile("fldl %1; fstpt %0":"=m"(r->s):"m"(out):"st","memory");r->memory_bits=0;
 if(fmt==32)__asm__ volatile("fnclex; fldt %3; fnstsw %1; fstps %0; fnstsw %2":"=m"(*(uint32_t*)&r->memory_bits),"=m"(r->memory_before),"=m"(r->memory_after):"m"(r->x):"st","memory");else __asm__ volatile("fnclex; fldt %3; fnstsw %1; fstpl %0; fnstsw %2":"=m"(r->memory_bits),"=m"(r->memory_before),"=m"(r->memory_after):"m"(r->x):"st","memory");
}
static uint64_t integer_input(int n,int fmt){uint64_t out=0;if(fmt==32)__asm__ volatile("cvtsi2ssl %1,%%xmm0; movss %%xmm0,%0":"=m"(*(uint32_t*)&out):"r"(n):"xmm0","memory");else __asm__ volatile("cvtsi2sdl %1,%%xmm0; movsd %%xmm0,%0":"=m"(out):"r"(n):"xmm0","memory");return out;}
static const int scale_edges[]={-4097,-4096,-2048,-1075,-1074,-1023,-1022,-255,-254,-150,-149,-128,-127,-126,-2,-1,0,1,2,126,127,128,1022,1023,1024,2048,4096,4097};
static const char*labels[]={"ALL","REGISTER_VALUE_MISMATCH","EXCEPTION_FLAGS_MISMATCH","NAN_RESULT","NONFINITE_SCALE_INPUT","ABOVE_TARGET_MAX_EXP","BELOW_TARGET_NORMAL_EXP","NARROWED_VALUE_MISMATCH","FINITE_NARROWED_VALUE_MISMATCH","FINITE_NORMAL_REFERENCE_MISMATCH"};
#define NL (sizeof(labels)/sizeof(*labels))
int main(int argc,char**argv){uint64_t n=argc>1?strtoull(argv[1],0,0):1000000;const char*dir=argc>2?argv[2]:"raw";char path[1024];snprintf(path,sizeof path,"%s/scale-counts.csv",dir);FILE*c=fopen(path,"w");snprintf(path,sizeof path,"%s/scale-examples.csv",dir);FILE*e=fopen(path,"w");if(!c||!e)return 2;fprintf(c,"operation,pc,rounding,class,total,random,edge\n");fprintf(e,"operation,pc,rounding,source,index,class,a_hex,b_hex,x87_80_hex,sse_80_hex,x87_narrowed_hex,sse_native_hex,fsw_before,fsw_after,mxcsr,fsw_store,clamped_scale,sse_multiplications\n");unsigned ne=sizeof(edge64)/sizeof(*edge64),ni=sizeof(scale_edges)/sizeof(*scale_edges);uint64_t extra=(uint64_t)ne*(ne+ni);
 for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++){int pc=pcs[p],fmt=pc==24?32:64;uint16_t cw=(pc==24?0x7f:pc==53?0x27f:0x37f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);__asm__ volatile("fninit; fldcw %0"::"m"(cw));uint64_t seed=UINT64_C(0x5343414c45303031),cnt[NL]={0},randomcnt[NL]={0};unsigned logs[NL]={0};
 for(uint64_t i=0;i<n+extra;i++){uint64_t a,b;if(i<n){a=rng(&seed);b=rng(&seed);if(fmt==32){a=(uint32_t)a;b=(uint32_t)b;}}else{unsigned j=(unsigned)(i-n),ia=j/(ne+ni),ib=j%(ne+ni);a=fmt==32?edge32[ia]:edge64[ia];b=ib<ne?(fmt==32?edge32[ib]:edge64[ib]):integer_input(scale_edges[ib-ne],fmt);}result r={0};int requested;unsigned steps;scale_execute(fmt,a,b,mx,&r,&requested,&steps);int eq=same(r.x,r.s),nan=nan80(r.x)||nan80(r.s),ex=(r.x.se&32767)-16383,lo=fmt==32?-126:-1022,hi=fmt==32?127:1023,normal=finite80(r.x)&&r.x.sig&&ex>=lo&&ex<=hi;int flags[NL]={1,!eq,((r.after^r.mx)&63)!=0,nan,!finitebits(b,fmt),finite80(r.x)&&r.x.sig&&ex>hi,finite80(r.x)&&r.x.sig&&ex<lo,r.memory_bits!=r.sbits,!nan&&finitebits(r.memory_bits,fmt)&&finitebits(r.sbits,fmt)&&r.memory_bits!=r.sbits,normal&&!nan&&!eq};
 for(unsigned k=0;k<NL;k++)if(flags[k]){cnt[k]++;if(i<n)randomcnt[k]++;if(logs[k]++<20)fprintf(e,"FSCALE_composite,%d,%s,%s,%"PRIu64",%s,%016"PRIx64",%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%016"PRIx64",%016"PRIx64",%04x,%04x,%08x,%04x,%d,%u\n",pc,rcnames[rc],i<n?"random":"edge",i<n?i:i-n,labels[k],a,b,r.x.se,r.x.sig,r.s.se,r.s.sig,r.memory_bits,r.sbits,r.before,r.after,r.mx,r.memory_after,requested,steps);}}
 for(unsigned k=0;k<NL;k++){fprintf(c,"FSCALE_composite,%d,%s,%s,%"PRIu64",%"PRIu64",%"PRIu64"\n",pc,rcnames[rc],labels[k],cnt[k],randomcnt[k],cnt[k]-randomcnt[k]);}fflush(c);fflush(e);fprintf(stderr,"complete scale PC%d %s register_mismatch=%"PRIu64" stored_finite=%"PRIu64"\n",pc,rcnames[rc],cnt[1],cnt[8]);}
 fclose(c);fclose(e);return 0;}
