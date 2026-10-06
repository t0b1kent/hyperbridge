/* SPDX-License-Identifier: MIT. Original extension of measured format candidates.
 * FXTRACT uses auxiliary finite SSE2 decomposition plus actual SSE special-value operations.
 * FLD80/FSTP80 candidate is explicitly lossy: real FSTP narrowing to IEEE, SSE move,
 * real hardware expansion. It does not claim an SSE m80 load/store opcode exists.
 */
#define main aux_unused_entry
#include "auxiliary.c"
#undef main
static ext expand_native(uint64_t raw,int fmt,uint16_t*sw){ext x;if(fmt==32)__asm__ volatile("fninit; flds %2; fnstsw %1; fstpt %0":"=m"(x),"=m"(*sw):"m"(*(uint32_t*)&raw):"st","memory");else __asm__ volatile("fninit; fldl %2; fnstsw %1; fstpt %0":"=m"(x),"=m"(*sw):"m"(raw):"st","memory");return x;}
static uint64_t move_native(uint64_t in,int fmt){uint64_t out=0;if(fmt==32)__asm__ volatile("movss %1,%%xmm0; movss %%xmm0,%0":"=m"(*(uint32_t*)&out):"m"(*(uint32_t*)&in):"xmm0","memory");else __asm__ volatile("movsd %1,%%xmm0; movsd %%xmm0,%0":"=m"(out):"m"(in):"xmm0","memory");return out;}
static uint64_t quiet_native(uint64_t in,int fmt){uint64_t zero=0,out=0;if(fmt==32)__asm__ volatile("movss %1,%%xmm0; addss %2,%%xmm0; movss %%xmm0,%0":"=m"(*(uint32_t*)&out):"m"(*(uint32_t*)&in),"m"(*(uint32_t*)&zero):"xmm0","memory");else __asm__ volatile("movsd %1,%%xmm0; addsd %2,%%xmm0; movsd %%xmm0,%0":"=m"(out):"m"(in),"m"(zero):"xmm0","memory");return out;}
static uint64_t zero_exponent_native(int fmt){uint64_t minusone=fmt==32?UINT64_C(0xbf800000):UINT64_C(0xbff0000000000000),zero=0,out=0;if(fmt==32)__asm__ volatile("movss %1,%%xmm0; divss %2,%%xmm0; movss %%xmm0,%0":"=m"(*(uint32_t*)&out):"m"(*(uint32_t*)&minusone),"m"(*(uint32_t*)&zero):"xmm0","memory");else __asm__ volatile("movsd %1,%%xmm0; divsd %2,%%xmm0; movsd %%xmm0,%0":"=m"(out):"m"(minusone),"m"(zero):"xmm0","memory");return out;}
static void full_extract(int pc,int rc,Input*i,Result*r){int fmt=pc==24?32:64;uint64_t raw=fmt==32?i->xf:i->x,am=(UINT64_C(1)<<(fmt-1))-1,inf=fmt==32?UINT64_C(0x7f800000):UINT64_C(0x7ff0000000000000),mag=raw&am;
 if(mag&&mag<inf){sse_eval(XTRACT,pc,rc,i,r);return;}
 uint32_t control=0x1f80|(rc<<13);__asm__ volatile("ldmxcsr %0"::"m"(control):"memory");uint64_t sig,exp;
 if(!mag){sig=move_native(raw,fmt);exp=zero_exponent_native(fmt);}
 else if(mag==inf){sig=move_native(raw,fmt);exp=move_native(inf,fmt);}
 else{sig=quiet_native(raw,fmt);exp=move_native(sig,fmt);}
 __asm__ volatile("stmxcsr %0":"=m"(r->mx));r->bnative=sig;r->b2native=exp;r->bwidth=fmt;r->b=expand_native(sig,fmt,&r->bexpand_sw);r->b2=expand_native(exp,fmt,&r->b2expand_sw);r->supported=1;
}
static void full_round(int pc,int rc,Input*i,Result*r){
 sse_eval(RND,pc,rc,i,r);int fmt=pc==24?32:64;
 if(r->supported){r->bnative=move_native(r->bnative,fmt);return;}
 uint32_t control=0x1f80|(rc<<13);__asm__ volatile("ldmxcsr %0"::"m"(control):"memory");uint64_t raw=quiet_native(fmt==32?i->xf:i->x,fmt);__asm__ volatile("stmxcsr %0":"=m"(r->mx));r->bnative=raw;r->bwidth=fmt;r->b=expand_native(raw,fmt,&r->bexpand_sw);r->supported=1;
}
static void lossy80(int pc,int rc,Input*i,Result*r,uint16_t*conversion){int fmt=pc==24?32:64;uint16_t cw=0x7f|(pc==24?0:pc==53?0x200:0x300)|(rc<<10);uint64_t raw=0;
 if(fmt==32)__asm__ volatile("fninit; fldcw %3; fldt %2; fstps %0; fnstsw %1":"=m"(*(uint32_t*)&raw),"=m"(*conversion):"m"(i->x80),"m"(cw):"st","memory");else __asm__ volatile("fninit; fldcw %3; fldt %2; fstpl %0; fnstsw %1":"=m"(raw),"=m"(*conversion):"m"(i->x80),"m"(cw):"st","memory");
 uint32_t control=0x1f80|(rc<<13);__asm__ volatile("ldmxcsr %0"::"m"(control):"memory");raw=move_native(raw,fmt);__asm__ volatile("stmxcsr %0":"=m"(r->mx));r->bnative=raw;r->bwidth=fmt;r->b=expand_native(raw,fmt,&r->bexpand_sw);r->supported=1;
}
static const char*labels[]={"ALL","VALUE_MISMATCH","NATIVE_OPERATION_FLAGS_MISMATCH","SOURCE_CONVERSION_EXCEPTION","NAN_RESULT","SIGNIFICAND_MISMATCH","EXPONENT_MISMATCH","EXPANSION_EXCEPTION","LOADSTORE80_IDENTITY_CHANGED"};
#define NL (sizeof(labels)/sizeof(*labels))
int main(int argc,char**argv){uint64_t n=argc>1?strtoull(argv[1],0,0):1000000;const char*dir=argc>2?argv[2]:"raw";char path[1024];snprintf(path,sizeof path,"%s/format-counts.csv",dir);FILE*c=fopen(path,"w");snprintf(path,sizeof path,"%s/format-examples.csv",dir);FILE*e=fopen(path,"w");if(!c||!e)return 2;fprintf(c,"operation,pc,rounding,class,total,random,edge\n");fprintf(e,"operation,pc,rounding,source,index,class,input64,input32,input80,A80,A80_secondary,B80,B80_secondary,B_native_hex,B2_native_hex,FSW_before,FSW_after,MXCSR,B_conversion_FSW,B_expansion_FSW,B2_expansion_FSW\n");const int ops[]={XTRACT,LD80,STP80,RND},pcs[]={53,24,64};const char*opnames[]={"FXTRACT_complete_candidate","FLD80_lossy_candidate","FSTP80_lossy_candidate","FRNDINT_SSE2_complete_candidate"},*rcs[]={"RN","RD","RU","RZ"};uint64_t edges=NE*NE+256;
 for(int oi=0;oi<4;oi++)for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++){int op=ops[oi],pc=pcs[p];rng=UINT64_C(0x464f524d41543031);uint64_t cnt[NL]={0},randomcnt[NL]={0};unsigned logs[NL]={0};
 for(uint64_t j=0;j<n+edges;j++){int edge=j>=n;uint64_t idx=edge?j-n:j;Input in;Result r={0};make_input(&in,idx,edge);x87_eval(op,pc,rc,&in,&r);uint16_t conversion=0;if(oi==0)full_extract(pc,rc,&in,&r);else if(oi==3)full_round(pc,rc,&in,&r);else lossy80(pc,rc,&in,&r,&conversion);int sigdiff=!same(r.a,r.b),expdiff=oi==0&&!same(r.a2,r.b2);int flags[NL]={1,sigdiff||expdiff,((r.post^r.mx)&63)!=0,!!(conversion&63),nan80(r.a)||nan80(r.b),sigdiff,expdiff,!!((r.bexpand_sw|r.b2expand_sw)&63),(oi==1||oi==2)&&!same(r.a,in.x80)};
 for(unsigned k=0;k<NL;k++)if(flags[k]){cnt[k]++;if(!edge)randomcnt[k]++;if(logs[k]++<20){fprintf(e,"%s,%d,%s,%s,%"PRIu64",%s,%016"PRIx64",%08x,",opnames[oi],pc,rcs[rc],edge?"edge":"random",idx,labels[k],in.x,in.xf);print_ext(e,in.x80);fputc(',',e);print_ext(e,r.a);fputc(',',e);print_ext(e,r.a2);fputc(',',e);print_ext(e,r.b);fputc(',',e);print_ext(e,r.b2);fprintf(e,",%016"PRIx64",%016"PRIx64",%04x,%04x,%08x,%04x,%04x,%04x\n",r.bnative,r.b2native,r.pre,r.post,r.mx,conversion,r.bexpand_sw,r.b2expand_sw);}}}
 for(unsigned k=0;k<NL;k++){fprintf(c,"%s,%d,%s,%s,%"PRIu64",%"PRIu64",%"PRIu64"\n",opnames[oi],pc,rcs[rc],labels[k],cnt[k],randomcnt[k],cnt[k]-randomcnt[k]);}fflush(c);fflush(e);fprintf(stderr,"complete format %s PC%d %s mismatch=%"PRIu64"\n",opnames[oi],pc,rcs[rc],cnt[1]);}
 fclose(c);fclose(e);return 0;}
