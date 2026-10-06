/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 x86-oracle contributors.
 * Original hardware-only auxiliary-operation probe. No imported source. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#if !defined(__x86_64__) || !defined(__linux__)
#error Actual Linux x86-64 hardware is required
#endif
typedef struct __attribute__((packed)){uint64_t sig;uint16_t se;} ext;
_Static_assert(sizeof(ext)==10,"x87 memory format");
enum{ABS,CHS,RND,RND41,SCALE,XTRACT,PREM,PREM1,ILD16,ILD32,ILD64,IST16,IST32,ISTP16,ISTP32,ISTP64,ISTTP16,ISTTP32,ISTTP64,LD32,LD64,LD80,ST32,ST64,STP32,STP64,STP80,COM,UCOM,COMI,UCOMI,NOP};
static const char *names[]={"FABS","FCHS","FRNDINT","FRNDINT_SSE41","FSCALE","FXTRACT","FPREM","FPREM1","FILD16","FILD32","FILD64","FIST16","FIST32","FISTP16","FISTP32","FISTP64","FISTTP16","FISTTP32","FISTTP64","FLD32","FLD64","FLD80","FST32","FST64","FSTP32","FSTP64","FSTP80","FCOM","FUCOM","FCOMI","FUCOMI"};
static const char *candidates[]={"SSE2_sign_mask","SSE2_sign_xor","SSE2_CVT_int64_finite_piecewise","SSE4.1_ROUND_current_RC","SSE2_MUL_small_scale_normal_domain","integer_decompose_SSE2_MOV_CVTSI_finite_nonzero","SSE2_MOV_quotient_zero_domain","SSE2_MOV_quotient_zero_domain","SSE2_CVTSI","SSE2_CVTSI","SSE2_CVTSI","SSE2_CVT32_low16_UNGUARDED","SSE2_CVT32","SSE2_CVT32_low16_UNGUARDED","SSE2_CVT32","SSE2_CVT64","SSE2_CVTT32_low16_UNGUARDED","SSE2_CVTT32","SSE2_CVTT64","SSE2_MOVSS","SSE2_MOVSD","UNSUPPORTED","SSE2_CVTSD2SS","SSE2_MOVSD","SSE2_CVTSD2SS","SSE2_MOVSD","UNSUPPORTED","SSE2_COMI","SSE2_UCOMI","SSE2_COMI","SSE2_UCOMI"};
static uint64_t rng;
static uint64_t next(void){uint64_t z=(rng+=UINT64_C(0x9e3779b97f4a7c15));z=(z^(z>>30))*UINT64_C(0xbf58476d1ce4e5b9);z=(z^(z>>27))*UINT64_C(0x94d049bb133111eb);return z^(z>>31);}
static ext widen64(uint64_t u){ext r={0,(uint16_t)((u>>48)&0x8000)};unsigned e=(u>>52)&2047;uint64_t m=u&UINT64_C(0xfffffffffffff);if(e==2047){r.se|=0x7fff;r.sig=UINT64_C(0x8000000000000000)|(m<<11);}else if(e){r.se|=e-1023+16383;r.sig=(m|UINT64_C(0x10000000000000))<<11;}else if(m){unsigned p=63-__builtin_clzll(m);r.se|=p-1074+16383;r.sig=m<<(63-p);}return r;}
static ext widen32(uint32_t u){ext r={0,(uint16_t)((u>>16)&0x8000)};unsigned e=(u>>23)&255;uint64_t m=u&0x7fffff;if(e==255){r.se|=0x7fff;r.sig=UINT64_C(0x8000000000000000)|(m<<40);}else if(e){r.se|=e-127+16383;r.sig=(m|0x800000)<<40;}else if(m){unsigned p=63-__builtin_clzll(m);r.se|=p-149+16383;r.sig=m<<(63-p);}return r;}
static int same(ext a,ext b){return a.sig==b.sig&&a.se==b.se;}
static int nan80(ext a){return (a.se&0x7fff)==0x7fff&&(a.sig&UINT64_C(0x7fffffffffffffff));}
static int snan80(ext a){return nan80(a)&&!(a.sig&UINT64_C(0x4000000000000000));}
static ext scalar(uint64_t u){ext a={u,0};return a;}
typedef struct{uint64_t x,y,integer;uint32_t xf,yf;ext x80;} Input;
typedef struct{ext a,a2,b,b2,reg;uint64_t mem,flags_before,flags_after,sseflags,bnative,b2native;uint16_t pre,post,bexpand_sw,b2expand_sw;uint32_t mx;unsigned supported,kind,bwidth,bchanged,quotient_tested;} Result;
static void load_source(Input *i,int s){if(s)__asm__ volatile("flds %0"::"m"(i->xf));else __asm__ volatile("fldl %0"::"m"(i->x));}
static void load_pair(Input *i,int s){if(s)__asm__ volatile("flds %0; flds %1"::"m"(i->yf),"m"(i->xf));else __asm__ volatile("fldl %0; fldl %1"::"m"(i->y),"m"(i->x));}
#define SIMPLE(OP,TEXT) case OP:__asm__ volatile(TEXT);break
#define STORE(OP,TEXT,DEST) case OP:__asm__ volatile(TEXT " %0":"=m"(DEST));break
static void x87_eval(int op,int pc,int rc,Input *i,Result *r){
 uint16_t cw=0x7f|(pc==24?0:pc==53?0x200:0x300)|(rc<<10),m16=0;uint32_t m32=0;uint64_t m64=0;
 __asm__ volatile("fninit; fldcw %0"::"m"(cw));
 if(op>=ILD16&&op<=ILD64){
  __asm__ volatile("fnstsw %0":"=m"(r->pre));
  if(op==ILD16)__asm__ volatile("filds %0"::"m"(*(int16_t*)&i->integer));
  if(op==ILD32)__asm__ volatile("fildl %0"::"m"(*(int32_t*)&i->integer));
  if(op==ILD64)__asm__ volatile("fildq %0"::"m"(i->integer));
 }else if(op>=LD32&&op<=LD80){
  __asm__ volatile("fnstsw %0":"=m"(r->pre));
  if(op==LD32)__asm__ volatile("flds %0"::"m"(i->xf));
  if(op==LD64)__asm__ volatile("fldl %0"::"m"(i->x));
  if(op==LD80)__asm__ volatile("fldt %0"::"m"(i->x80));
 }else{
  if(op==SCALE||op==PREM||op==PREM1||op>=COM)load_pair(i,pc==24);
  else if(op==STP80)__asm__ volatile("fldt %0"::"m"(i->x80));
  else load_source(i,pc==24&&!(op>=ST32&&op<=STP80));
  __asm__ volatile("fnstsw %0":"=m"(r->pre));
  if((op>=IST16&&op<=ISTTP64)||(op>=ST32&&op<=STP64))__asm__ volatile("fld %%st(0); fstpt %0":"=m"(r->reg));
  switch(op){
   SIMPLE(ABS,"fabs");SIMPLE(CHS,"fchs");SIMPLE(RND,"frndint");SIMPLE(RND41,"frndint");SIMPLE(SCALE,"fscale");SIMPLE(XTRACT,"fxtract");SIMPLE(PREM,"fprem");SIMPLE(PREM1,"fprem1");
   STORE(IST16,"fists",m16);STORE(IST32,"fistl",m32);STORE(ISTP16,"fistps",m16);STORE(ISTP32,"fistpl",m32);STORE(ISTP64,"fistpq",m64);STORE(ISTTP16,"fisttps",m16);STORE(ISTTP32,"fisttpl",m32);STORE(ISTTP64,"fisttpq",m64);
   STORE(ST32,"fsts",m32);STORE(ST64,"fstl",m64);STORE(STP32,"fstps",m32);STORE(STP64,"fstpl",m64);STORE(STP80,"fstpt",r->a);
   SIMPLE(COM,"fcom %st(1)");SIMPLE(UCOM,"fucom %st(1)");
   case COMI:__asm__ volatile("xorl %%eax,%%eax; subl $1,%%eax; pushfq; popq %0; fcomi %%st(1); pushfq; popq %1":"=r"(r->flags_before),"=r"(r->flags_after)::"eax","cc");break;
   case UCOMI:__asm__ volatile("xorl %%eax,%%eax; subl $1,%%eax; pushfq; popq %0; fucomi %%st(1); pushfq; popq %1":"=r"(r->flags_before),"=r"(r->flags_after)::"eax","cc");break;
  }
 }
 __asm__ volatile("fnstsw %0":"=m"(r->post));
 if(op>=IST16&&op<=ISTTP64){r->kind=1;if(op==IST16||op==ISTP16||op==ISTTP16)r->mem=m16;else if(op==IST32||op==ISTP32||op==ISTTP32)r->mem=m32;else r->mem=m64;r->a=scalar(r->mem);}
 else if(op>=ST32&&op<=STP64){if(op==ST32||op==STP32){r->mem=m32;r->a=widen32(m32);}else{r->mem=m64;r->a=widen64(m64);}}
 else if(op>=COM){r->kind=2;r->a=scalar(op>=COMI?r->flags_after&0x45:(r->post>>8)&0x45);}
 else if(op!=STP80){__asm__ volatile("fstpt %0":"=m"(r->a));if(op==XTRACT)__asm__ volatile("fstpt %0":"=m"(r->a2));}
 r->flags_before&=0x8d5;r->flags_after&=0x8d5;
}
#define TOINT(SUFFIX,DEST,SRC) __asm__ volatile("mov" SUFFIX " %1,%%xmm0; cvt" SUFFIX "2si %%xmm0,%0":"=r"(DEST):"m"(SRC):"xmm0")
#define TRUNCINT(SUFFIX,DEST,SRC) __asm__ volatile("mov" SUFFIX " %1,%%xmm0; cvtt" SUFFIX "2si %%xmm0,%0":"=r"(DEST):"m"(SRC):"xmm0")
static uint64_t sse_convert_int(Input *i,int s,int width,int trunc){
 uint64_t q=0;uint32_t l=0;
 if(width==64){if(s){if(trunc)TRUNCINT("ss",q,i->xf);else TOINT("ss",q,i->xf);}else{if(trunc)TRUNCINT("sd",q,i->x);else TOINT("sd",q,i->x);}}
 else{if(s){if(trunc)TRUNCINT("ss",l,i->xf);else TOINT("ss",l,i->xf);}else{if(trunc)TRUNCINT("sd",l,i->x);else TOINT("sd",l,i->x);}q=l;}
 return width==16?q&65535:q;
}
static ext sse_int_float(uint64_t q,int s,uint64_t *raw){if(s){uint32_t b;__asm__ volatile("cvtsi2ssq %1,%%xmm0; movss %%xmm0,%0":"=m"(b):"r"(q):"xmm0");*raw=b;return widen32(b);}else{uint64_t b;__asm__ volatile("cvtsi2sdq %1,%%xmm0; movsd %%xmm0,%0":"=m"(b):"r"(q):"xmm0");*raw=b;return widen64(b);}}

/* Expand the actual measured native SSE bits using FLD/FSTP hardware.
 * MXCSR is captured before this serialization. Its x87 FSW is separate. */
static void hardware_expand(Result *r,int width){
 ext before=r->b;
 if(width==32){uint32_t raw=(uint32_t)r->bnative;
  __asm__ volatile("fninit; flds %2; fnstsw %1; fstpt %0":"=m"(r->b),"=m"(r->bexpand_sw):"m"(raw));
 }else{
  __asm__ volatile("fninit; fldl %2; fnstsw %1; fstpt %0":"=m"(r->b),"=m"(r->bexpand_sw):"m"(r->bnative));
 }
 r->bwidth=width;r->bchanged=!same(before,r->b);
}
#define SSE_COMPARE(OP,SUFFIX,X,Y) __asm__ volatile("mov" SUFFIX " %1,%%xmm0; mov" SUFFIX " %2,%%xmm1; xorl %%eax,%%eax; subl $1,%%eax; " OP SUFFIX " %%xmm1,%%xmm0; pushfq; popq %0":"=r"(r->sseflags):"m"(X),"m"(Y):"eax","xmm0","xmm1","cc")
static void sse_eval(int op,int pc,int rc,Input *i,Result *r){
 uint32_t mx=0x1f80|(rc<<13),f=0;uint64_t d=0;int s=pc==24;
 __asm__ volatile("ldmxcsr %0"::"m"(mx));r->supported=1;
 switch(op){
 case ABS:case CHS:
  if(s){uint32_t mask=op==ABS?0x7fffffff:0x80000000;
   if(op==ABS)__asm__ volatile("movd %1,%%xmm0; movd %2,%%xmm1; andps %%xmm1,%%xmm0; movd %%xmm0,%0":"=m"(f):"m"(i->xf),"m"(mask):"xmm0","xmm1");
   else __asm__ volatile("movd %1,%%xmm0; movd %2,%%xmm1; xorps %%xmm1,%%xmm0; movd %%xmm0,%0":"=m"(f):"m"(i->xf),"m"(mask):"xmm0","xmm1");
   r->bnative=f;r->b=widen32(f);
  }else{uint64_t mask=op==ABS?UINT64_C(0x7fffffffffffffff):UINT64_C(0x8000000000000000);
   if(op==ABS)__asm__ volatile("movq %1,%%xmm0; movq %2,%%xmm1; andpd %%xmm1,%%xmm0; movq %%xmm0,%0":"=m"(d):"m"(i->x),"m"(mask):"xmm0","xmm1");
   else __asm__ volatile("movq %1,%%xmm0; movq %2,%%xmm1; xorpd %%xmm1,%%xmm0; movq %%xmm0,%0":"=m"(d):"m"(i->x),"m"(mask):"xmm0","xmm1");
   r->bnative=d;r->b=widen64(d);
  }break;
 case RND:{unsigned exp=s?(i->xf>>23)&255:(i->x>>52)&2047,special=s?255:2047,integral=s?150:1075;
  if(exp==special){r->supported=0;break;}if(exp>=integral){r->bnative=s?i->xf:i->x;r->b=s?widen32(i->xf):widen64(i->x);break;}
  uint64_t q=sse_convert_int(i,s,64,0);r->b=sse_int_float(q,s,&r->bnative);
  if(!(r->b.se&0x7fff)&&!r->b.sig){r->b.se=s?(i->xf>>16)&0x8000:(i->x>>48)&0x8000;r->bnative|=s?(i->xf&UINT32_C(0x80000000)):(i->x&UINT64_C(0x8000000000000000));}
  break;}

 case SCALE:{
  ext y=s?widen32(i->yf):widen64(i->y);int ey=y.se&0x7fff,ye=ey-16383;
  unsigned xe=s?(i->xf>>23)&255:(i->x>>52)&2047,maxe=s?255:2047;
  if(!xe||xe==maxe||ey==0x7fff||ye>=7){r->supported=0;break;}
  int shift=ye<0?0:(int)(y.sig>>(63-ye));if(y.se&0x8000)shift=-shift;
  if(shift < -64||shift>64||(int)xe+shift<1||(int)xe+shift>=(int)maxe){r->supported=0;break;}
  if(s){uint32_t factor=(uint32_t)(127+shift)<<23;__asm__ volatile("movss %1,%%xmm0; mulss %2,%%xmm0; movss %%xmm0,%0":"=m"(f):"m"(i->xf),"m"(factor):"xmm0");r->bnative=f;r->b=widen32(f);}
  else{uint64_t factor=(uint64_t)(1023+shift)<<52;__asm__ volatile("movsd %1,%%xmm0; mulsd %2,%%xmm0; movsd %%xmm0,%0":"=m"(d):"m"(i->x),"m"(factor):"xmm0");r->bnative=d;r->b=widen64(d);}
  break;}
 case XTRACT:{
  ext x=s?widen32(i->xf):widen64(i->x);int e=x.se&0x7fff;
  if(!x.sig||e==0x7fff){r->supported=0;break;}
  if(s){uint32_t b=(i->xf&0x80000000)|0x3f800000|((x.sig>>40)&0x7fffff);__asm__ volatile("movss %1,%%xmm0; movss %%xmm0,%0":"=m"(f):"m"(b):"xmm0");r->bnative=f;r->b=widen32(f);}
  else{uint64_t b=(i->x&UINT64_C(0x8000000000000000))|UINT64_C(0x3ff0000000000000)|((x.sig>>11)&UINT64_C(0xfffffffffffff));__asm__ volatile("movsd %1,%%xmm0; movsd %%xmm0,%0":"=m"(d):"m"(b):"xmm0");r->bnative=d;r->b=widen64(d);}
  r->b2=sse_int_float((uint64_t)(int64_t)(e-16383),s,&r->b2native);break;}
 case PREM:case PREM1:{
  ext x=s?widen32(i->xf):widen64(i->x),y=s?widen32(i->yf):widen64(i->y);
  unsigned xe=x.se&0x7fff,ye=y.se&0x7fff;
  int safe=xe!=0x7fff&&ye!=0x7fff&&y.sig;
  if(op==PREM)safe=safe&&(xe<ye||(xe==ye&&x.sig<y.sig));
  else safe=safe&&(!x.sig||xe+1<ye||(xe+1==ye&&x.sig<y.sig));
  if(!safe){r->supported=0;break;}
  if(s){__asm__ volatile("movss %1,%%xmm0; movss %%xmm0,%0":"=m"(f):"m"(i->xf):"xmm0");r->bnative=f;r->b=widen32(f);}
  else{__asm__ volatile("movsd %1,%%xmm0; movsd %%xmm0,%0":"=m"(d):"m"(i->x):"xmm0");r->bnative=d;r->b=widen64(d);}
  r->quotient_tested=1;break;}

 case RND41:if(s){__asm__ volatile("movss %1,%%xmm0; roundss $4,%%xmm0,%%xmm0; movss %%xmm0,%0":"=m"(f):"m"(i->xf):"xmm0");r->bnative=f;r->b=widen32(f);}else{__asm__ volatile("movsd %1,%%xmm0; roundsd $4,%%xmm0,%%xmm0; movsd %%xmm0,%0":"=m"(d):"m"(i->x):"xmm0");r->bnative=d;r->b=widen64(d);}break;
 case ILD16:case ILD32:case ILD64:{uint64_t q=op==ILD16?(uint64_t)(int64_t)(int16_t)i->integer:op==ILD32?(uint64_t)(int64_t)(int32_t)i->integer:i->integer;r->b=sse_int_float(q,s,&r->bnative);break;}
 case IST16:case IST32:case ISTP16:case ISTP32:case ISTP64:case ISTTP16:case ISTTP32:case ISTTP64:{int width=op==IST16||op==ISTP16||op==ISTTP16?16:op==ISTP64||op==ISTTP64?64:32;r->b=scalar(sse_convert_int(i,s,width,op>=ISTTP16));break;}
 case LD32:__asm__ volatile("movss %1,%%xmm0; movss %%xmm0,%0":"=m"(f):"m"(i->xf):"xmm0");r->bnative=f;r->b=widen32(f);break;
 case LD64:case ST64:case STP64:__asm__ volatile("movsd %1,%%xmm0; movsd %%xmm0,%0":"=m"(d):"m"(i->x):"xmm0");r->bnative=d;r->b=widen64(d);break;
 case ST32:case STP32:__asm__ volatile("movsd %1,%%xmm0; cvtsd2ss %%xmm0,%%xmm0; movss %%xmm0,%0":"=m"(f):"m"(i->x):"xmm0");r->bnative=f;r->b=widen32(f);break;
 case COM:case COMI:case UCOM:case UCOMI:
  if(s){if(op==COM||op==COMI)SSE_COMPARE("comi","ss",i->xf,i->yf);else SSE_COMPARE("ucomi","ss",i->xf,i->yf);}
  else{if(op==COM||op==COMI)SSE_COMPARE("comi","sd",i->x,i->y);else SSE_COMPARE("ucomi","sd",i->x,i->y);}
  r->sseflags&=0x8d5;r->b=scalar(r->sseflags&0x45);break;
 default:r->supported=0;break;
 }
 __asm__ volatile("stmxcsr %0":"=m"(r->mx));
 if(r->supported&&!r->kind){int width=op==LD32||op==ST32||op==STP32?32:op==LD64||op==ST64||op==STP64?64:s?32:64;hardware_expand(r,width);if(op==XTRACT){Result t={0};t.b=r->b2;t.bnative=r->b2native;hardware_expand(&t,width);r->b2=t.b;r->b2expand_sw=t.bexpand_sw;}}
}
static const uint64_t edge64[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x3fe0000000000000),UINT64_C(0xbfe0000000000000),UINT64_C(0x3ff8000000000000),UINT64_C(0xbff8000000000000),UINT64_C(0x4004000000000000),UINT64_C(0xc004000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),1,2,UINT64_C(0x000fffffffffffff),UINT64_C(0x0010000000000000),UINT64_C(0x0010000000000001),UINT64_C(0x8000000000000001),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8000000000000),UINT64_C(0xfff8000000000123),UINT64_C(0x7ff0000000000001),UINT64_C(0xfff0123456789abc),UINT64_C(0x40dfffc000000000),UINT64_C(0x40dfffe000000000),UINT64_C(0xc0e0000000000000),UINT64_C(0x41dfffffffe00000),UINT64_C(0x41e0000000000000),UINT64_C(0xc1e0000000000000),UINT64_C(0x43dfffffffffffff),UINT64_C(0x43e0000000000000),UINT64_C(0xc3e0000000000000),UINT64_C(0x433fffffffffffff),UINT64_C(0x4340000000000000),UINT64_C(0x380fffffe0000000),UINT64_C(0x3810000000000000),UINT64_C(0x36a0000000000000),UINT64_C(0x3690000000000000),UINT64_C(0x47efffffe0000000),UINT64_C(0x47f0000000000000)};
static const uint32_t edge32[]={0,0x80000000,0x3f000000,0xbf000000,0x3fc00000,0xbfc00000,0x40200000,0xc0200000,0x3f800000,0xbf800000,1,2,0x007fffff,0x00800000,0x00800001,0x80000001,0x7f7fffff,0xff7fffff,0x7f800000,0xff800000,0x7fc00000,0xffc00123,0x7f800001,0xff801234,0x46fffe00,0x46ffff00,0xc7000000,0x4effffff,0x4f000000,0xcf000000,0x5effffff,0x5f000000,0xdf000000,0x4affffff,0x4b000000,0x007fffff,0x00800000,1,0,0x7f7fffff,0x7f800000};
static const ext edge80[]={{0,0},{0,0x8000},{UINT64_C(0x8000000000000000),1},{1,0},{UINT64_C(0x7fffffffffffffff),0},{UINT64_C(0x8000000000000000),0},{UINT64_C(0xffffffffffffffff),0x7ffe},{UINT64_C(0x8000000000000000),0x7fff},{UINT64_C(0xc000000000000123),0x7fff},{UINT64_C(0x8000000000000001),0xffff},{UINT64_C(0x4000000000000000),0x3fff},{0,0x3fff},{UINT64_C(0x8000000000000000),0x43ff},{UINT64_C(0x8000000000000000),0x3bcd}};
static const uint64_t edgeint[]={
 0,1,UINT64_MAX,32767,32768,32769,(uint64_t)-32767,(uint64_t)-32768,(uint64_t)-32769,
 UINT64_C(2147483646),UINT64_C(2147483647),UINT64_C(2147483648),UINT64_C(2147483649),
 (uint64_t)-INT64_C(2147483647),(uint64_t)-INT64_C(2147483648),(uint64_t)-INT64_C(2147483649),
 UINT64_C(16777215),UINT64_C(16777216),UINT64_C(16777217),(uint64_t)-INT64_C(16777215),(uint64_t)-INT64_C(16777216),(uint64_t)-INT64_C(16777217),
 UINT64_C(9007199254740991),UINT64_C(9007199254740992),UINT64_C(9007199254740993),
 (uint64_t)-INT64_C(9007199254740991),(uint64_t)-INT64_C(9007199254740992),(uint64_t)-INT64_C(9007199254740993),
 UINT64_C(0x7ffffffffffffffe),UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000001)
};

#define NE (sizeof(edge64)/sizeof(edge64[0]))
#define E80 (sizeof(edge80)/sizeof(edge80[0]))
static void make_input(Input *i,uint64_t idx,int edge){
 memset(i,0,sizeof(*i));if(!edge){i->x=next();i->y=next();i->xf=(uint32_t)next();i->yf=(uint32_t)next();i->integer=next();i->x80.sig=next()|UINT64_C(0x8000000000000000);i->x80.se=(uint16_t)next();if(!(i->x80.se&0x7fff))i->x80.sig&=UINT64_C(0x7fffffffffffffff);}
 else if(idx<NE*NE){unsigned a=idx%NE,b=idx/NE;i->x=edge64[a];i->y=edge64[b];i->xf=edge32[a];i->yf=edge32[b];i->integer=edgeint[idx%(sizeof(edgeint)/sizeof(edgeint[0]))];i->x80=edge80[idx%E80];}
 else {unsigned k=(idx-NE*NE)/2,sgn=(idx-NE*NE)&1;i->x=((uint64_t)(k+1023)<<52)|((uint64_t)sgn<<63);i->y=UINT64_C(0x3fe0000000000000);i->xf=((uint32_t)(k+127)<<23)|(sgn<<31);i->yf=0x3f000000;i->integer=k<64?(UINT64_C(1)<<k):UINT64_MAX;if(sgn)i->integer=0-i->integer;i->x80=widen64(i->x);}
}
static uint64_t mix(uint64_t h,uint64_t x){return (h^x)*UINT64_C(0x100000001b3);}
static void print_ext(FILE *f,ext x){fprintf(f,"%04x%016" PRIx64,x.se,x.sig);}
static void example(FILE *f,int op,int pc,int rc,const char *cls,uint64_t idx,int edge,Input *i,Result *r){fprintf(f,"%s,%d,%d,%s,%s,%" PRIu64 ",%016" PRIx64 ",%016" PRIx64 ",%08x,%08x,%016" PRIx64 ",",names[op],pc,rc,cls,edge?"edge":"random",idx,i->x,i->y,i->xf,i->yf,i->integer);print_ext(f,i->x80);fputc(',',f);print_ext(f,r->a);fputc(',',f);print_ext(f,r->a2);fputc(',',f);if(r->supported)print_ext(f,r->b);else fputs("NA",f);fputc(',',f);print_ext(f,r->reg);fprintf(f,",%016" PRIx64 ",%04x,%04x,%08x,%03" PRIx64 ",%03" PRIx64 ",%03" PRIx64 ",%u,%016" PRIx64 ",%u,%04x,",r->mem,r->pre,r->post,r->mx,r->flags_before,r->flags_after,r->sseflags,r->supported,r->bnative,r->bwidth,r->bexpand_sw);print_ext(f,r->b2);fprintf(f,",%016" PRIx64 ",%04x\n",r->b2native,r->b2expand_sw);}
enum{C_VALUE,C_EXCEPT,C_NAN,C_OUTSIDE,C_SUBNORMAL,C_PARTIAL,C_UNSUP,C_INPUT_SNAN,C_NANSIGN,C_NANQUIET,C_NANPAYLOAD,C_BEXPAND,C_RFLAGS,C_RAW80,C_QFLAGS,C_NATIVE_MEMORY,C_OTHER,NCLASS};
static const char *classes[]={"value_diff","exception_flags_diff","nan_result","outside_target_exponent","target_subnormal_result","fprem_C2_partial","unsupported_candidate","input_signaling_NaN","nan_sign_diff","nan_quiet_bit_diff","nan_payload_diff","B_expansion_changed_encoding","rflags_difference","loadstore80_changed","quotient_zero_condition_flags_diff","native_memory_bits_diff","other_value_diff"};
int main(int argc,char **argv){
 uint64_t n=argc>1?strtoull(argv[1],0,10):1000000;const char *out=argc>2?argv[2]:"raw";char p[1024];
 snprintf(p,sizeof p,"%s/aux-summary.csv",out);FILE *sum=fopen(p,"w");snprintf(p,sizeof p,"%s/aux-examples.csv",out);FILE *ex=fopen(p,"w");snprintf(p,sizeof p,"%s/aux-classes.csv",out);FILE *cl=fopen(p,"w");if(!sum||!ex||!cl){perror("CSV open");return 1;}
 fprintf(sum,"operation,pc,rc,seed,random_count,edge_count,candidate,compared,value_equal,value_diff,exception_flags_diff,value_and_exception_equal,unsupported,fprem_partial,result_hash64\n");
 fprintf(ex,"operation,pc,rc,class,source,index,input64_x,input64_y,input32_x,input32_y,integer_input,input80_x,A80_or_scalar,A80_secondary,B80_or_scalar,prestore_register80,memory_result,FSW_before,FSW_after,MXCSR_after,RFLAGS_before,RFLAGS_after,SSE_RFLAGS_after,B_supported,B_native_hex,B_native_width,B_expansion_FSW,B80_secondary,B_secondary_native_hex,B_secondary_expansion_FSW\n");
 fprintf(cl,"operation,pc,rc,class,count,examples_saved\n");
 const int pcs[]={24,53,64};const uint64_t edges=NE*NE+256;
 for(int op=0;op<NOP;op++)for(unsigned pi=0;pi<3;pi++)for(int rc=0;rc<4;rc++){
  int pc=pcs[pi];uint64_t seed=UINT64_C(0x247a9c8135ef600d)^((uint64_t)(op==RND41?RND:op)<<32);rng=seed;uint64_t counts[NCLASS]={0},saved[NCLASS]={0},compared=0,equal=0,diff=0,fdiff=0,both=0,unsup=0,partial=0,hash=UINT64_C(0xcbf29ce484222325);
  for(uint64_t j=0;j<edges+n;j++){int edge=j<edges;uint64_t idx=edge?j:j-edges;Input in;Result r={0};make_input(&in,idx,edge);x87_eval(op,pc,rc,&in,&r);sse_eval(op,pc,rc,&in,&r);
   int memdiff=r.supported&&op>=ST32&&op<=STP64&&r.mem!=r.bnative;
   int mismatch=r.supported&&(!same(r.a,r.b)||(op==XTRACT&&!same(r.a2,r.b2))||memdiff),flagdiff=r.supported&&((r.post&63)!=(r.mx&63));
   if(r.supported){compared++;equal+=!mismatch;diff+=mismatch;fdiff+=flagdiff;both+=!mismatch&&!flagdiff;}else unsup++;
   int width=op==LD32||op==ST32||op==STP32?32:op==LD64||op==ST64||op==STP64?64:pc==24?32:64;
   int nan=!r.kind&&nan80(r.a),e=r.a.se&0x7fff;int outside=!r.kind&&e&&e!=0x7fff&&((e-16383)>(width==32?127:1023)||(e-16383)<(width==32?-126:-1022));int sub=!r.kind&&e&&e!=0x7fff&&(e-16383)<(width==32?-126:-1022)&&(e-16383)>=(width==32?-149:-1074);int part=(op==PREM||op==PREM1)&&(r.post&0x400);partial+=!!part;
   ext input=op==LD80||op==STP80?in.x80:op==LD32?widen32(in.xf):pc==24&&op!=LD64&&!(op>=ST32&&op<=STP80)?widen32(in.xf):widen64(in.x);int snan=!(op>=ILD16&&op<=ILD64)&&snan80(input);
   if(op==SCALE||op==PREM||op==PREM1||op>=COM){snan|=snan80(pc==24?widen32(in.yf):widen64(in.y));}
   int nans=mismatch&&nan&&nan80(r.b);
   int flags[NCLASS]={mismatch,flagdiff,nan,outside,sub,part,!r.supported,snan,nans&&((r.a.se^r.b.se)&0x8000),nans&&((r.a.sig^r.b.sig)&UINT64_C(0x4000000000000000)),nans&&((r.a.sig^r.b.sig)&UINT64_C(0x3fffffffffffffff)),r.bchanged,op>=COMI&&r.flags_after!=r.sseflags,(op==LD80||op==STP80)&&!same(in.x80,r.a),r.quotient_tested&&((r.post&0x4700)!=0),memdiff,mismatch&&!nan&&!outside};
   hash=mix(hash,in.x);hash=mix(hash,in.y);hash=mix(hash,in.xf);hash=mix(hash,in.yf);hash=mix(hash,in.x80.sig);hash=mix(hash,in.x80.se);hash=mix(hash,in.integer);hash=mix(hash,r.a.sig);hash=mix(hash,r.a.se);hash=mix(hash,r.a2.sig);hash=mix(hash,r.a2.se);hash=mix(hash,r.b.sig);hash=mix(hash,r.b.se);hash=mix(hash,r.pre);hash=mix(hash,r.post);hash=mix(hash,r.mx);hash=mix(hash,r.flags_after);hash=mix(hash,r.sseflags);hash=mix(hash,r.b2.sig);hash=mix(hash,r.b2.se);hash=mix(hash,r.b2native);hash=mix(hash,r.b2expand_sw);hash=mix(hash,r.bnative);hash=mix(hash,r.bexpand_sw);
   for(int c=0;c<NCLASS;c++)if(flags[c]){counts[c]++;if(saved[c]<20){example(ex,op,pc,rc,classes[c],idx,edge,&in,&r);saved[c]++;}}
  }
  fprintf(sum,"%s,%d,%d,%016" PRIx64 ",%" PRIu64 ",%" PRIu64 ",%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%016" PRIx64 "\n",names[op],pc,rc,seed,n,edges,candidates[op],compared,equal,diff,fdiff,both,unsup,partial,hash);
  for(int c=0;c<NCLASS;c++)fprintf(cl,"%s,%d,%d,%s,%" PRIu64 ",%" PRIu64 "\n",names[op],pc,rc,classes[c],counts[c],saved[c]);
  fflush(sum);fflush(ex);fflush(cl);
 }
 fclose(sum);fclose(ex);fclose(cl);__asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));fprintf(stderr,"aux: %d operations, 12 modes, %" PRIu64 " random + %" PRIu64 " edge cases each complete\n",NOP,n,edges);return 0;
}
