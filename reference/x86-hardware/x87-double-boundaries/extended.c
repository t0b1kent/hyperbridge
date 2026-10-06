/* SPDX-License-Identifier: MIT. Original extended-input boundary suite.
 * This tests an explicitly lossy proposed path: narrow existing m80 inputs,
 * then execute SSE. It does not pretend those inputs are originally IEEE64/32.
 */
#ifdef main
#undef main
#endif
#define main core_program_main
#include "core.c"
#undef main
static void actual(int op,ext80 a,ext80 b,ext80*out,uint16_t*before,uint16_t*after){
#define BIN80(instruction) __asm__ volatile("fnclex; fldt %[b]; fldt %[a]; fnstsw %[before]; " instruction " %%st(1),%%st; fnstsw %[after]; fstpt %[out]; fstp %%st" :[out]"=m"(*out),[before]"=m"(*before),[after]"=m"(*after):[a]"m"(a),[b]"m"(b):"st","st(1)","memory")
 switch(op){case ADD:BIN80("fadd");break;case SUB:BIN80("fsub");break;case MUL:BIN80("fmul");break;case DIV:BIN80("fdiv");break;}
}
static uint64_t narrow(ext80 a,int fmt,uint16_t*sw){uint64_t bits=0;if(fmt==32){__asm__ volatile("fnclex; fldt %[a]; fstps %[b]; fnstsw %[sw]":[b]"=m"(*(uint32_t*)&bits),[sw]"=m"(*sw):[a]"m"(a):"st","memory");}else{__asm__ volatile("fnclex; fldt %[a]; fstpl %[b]; fnstsw %[sw]":[b]"=m"(bits),[sw]"=m"(*sw):[a]"m"(a):"st","memory");}return bits;}
static ext80 random80(uint64_t*state){ext80 x;x.sig=rng(state)|UINT64_C(0x8000000000000000);uint64_t v=rng(state);x.se=(uint16_t)((v&32768)|(1+(v%32766)));return x;}
static const ext80 edge[]={
 {0,0},{0,32768},{UINT64_C(0x8000000000000000),0x3fff},{UINT64_C(0x8000000000000001),0x3fff},{UINT64_C(0x8000000000000000),0xbfff},
 {UINT64_C(0x8000000000000000),0x43ff},{UINT64_C(0x8000000000000000),0x3bcc},{UINT64_C(0x8000000000000000),0x407f},{UINT64_C(0x8000000000000000),0x3f69},
 {UINT64_C(0xffffffffffffffff),0x7ffe},{1,0},{UINT64_C(0x8000000000000000),1},{UINT64_C(0x8000000000000000),0x7fff},
 {UINT64_C(0xc000000000000111),0x7fff},{UINT64_C(0x8000000000000222),0xffff},{UINT64_C(0x8000000000000000),0x4000}};
static const char*labels[]={"ALL","VALUE_MISMATCH","OPERATION_FLAGS_MISMATCH","SOURCE_NARROWING_EXCEPTION","FINITE_NORMAL_FINAL_MISMATCH","SOURCE_EXTRA_PRECISION_IN_TARGET_RANGE"};
#define NL (sizeof(labels)/sizeof(labels[0]))
int extended_entry(int argc,char**argv){uint64_t n=argc>1?strtoull(argv[1],0,0):1000000;const char*dir=argc>2?argv[2]:"raw";char path[1024];snprintf(path,sizeof path,"%s/extended-counts.csv",dir);FILE*c=fopen(path,"w");snprintf(path,sizeof path,"%s/extended-examples.csv",dir);FILE*e=fopen(path,"w");if(!c||!e)return 2;
 fprintf(c,"operation,pc,rounding,class,total,random,edge\n");fprintf(e,"operation,pc,rounding,source,index,class,a_80_hex,b_80_hex,a_narrow_hex,b_narrow_hex,x87_80_hex,lossy_sse_as_80_hex,fsw_before,fsw_after,a_narrow_fsw,b_narrow_fsw,mxcsr\n");
 for(int op=0;op<4;op++)for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++){int pc=pcs[p],fmt=pc==24?32:64,lo=fmt==32?-126:-1022,hi=fmt==32?127:1023;uint16_t cw=(pc==24?0x7f:pc==53?0x27f:0x37f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);__asm__ volatile("fninit; fldcw %0"::"m"(cw));uint64_t seed=UINT64_C(0x455854454e444544),cnt[NL]={0},randomcnt[NL]={0};unsigned logs[NL]={0};unsigned ne=sizeof(edge)/sizeof(edge[0]);
 for(uint64_t i=0;i<n+(uint64_t)ne*ne;i++){ext80 a,b;if(i<n){a=random80(&seed);b=random80(&seed);}else{a=edge[(i-n)/ne];b=edge[(i-n)%ne];}uint16_t asw,bsw,before,after;uint64_t na=narrow(a,fmt,&asw),nb=narrow(b,fmt,&bsw);result r;execute(op,fmt,na,nb,mx,&r);ext80 x;actual(op,a,b,&x,&before,&after);int ex=(x.se&32767)-16383,ae=(a.se&32767)-16383,be=(b.se&32767)-16383;int mismatch=!same(x,r.s),normal=finite80(x)&&x.sig&&ex>=lo&&ex<=hi;int extra=finite80(a)&&finite80(b)&&ae>=lo&&ae<=hi&&be>=lo&&be<=hi&&((asw|bsw)&32);int yes[NL]={1,mismatch,((after^r.mx)&63)!=0,((asw|bsw)&63)!=0,mismatch&&normal&&!nan80(r.s),extra};
 for(unsigned k=0;k<NL;k++)if(yes[k]){cnt[k]++;if(i<n)randomcnt[k]++;if(logs[k]++<20)fprintf(e,"%s,%d,%s,%s,%"PRIu64",%s,%04x%016"PRIx64",%04x%016"PRIx64",%016"PRIx64",%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%04x,%04x,%04x,%04x,%08x\n",opnames[op],pc,rcnames[rc],i<n?"random":"edge",i<n?i:i-n,labels[k],a.se,a.sig,b.se,b.sig,na,nb,x.se,x.sig,r.s.se,r.s.sig,before,after,asw,bsw,r.mx);}
 }
 for(unsigned k=0;k<NL;k++){fprintf(c,"%s,%d,%s,%s,%"PRIu64",%"PRIu64",%"PRIu64"\n",opnames[op],pc,rcnames[rc],labels[k],cnt[k],randomcnt[k],cnt[k]-randomcnt[k]);}
 fflush(c);fflush(e);fprintf(stderr,"complete extended %s PC%d %s\n",opnames[op],pc,rcnames[rc]);}
 fclose(c);fclose(e);return 0;}

#ifndef EXTENDED_NO_MAIN
int main(int argc,char**argv){return extended_entry(argc,argv);}
#endif
