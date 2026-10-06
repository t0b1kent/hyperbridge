/* SPDX-License-Identifier: MIT. Literal remainder zero/tie/quotient audit. */
#define main remainder_original_main
#include "remainder.c"
#undef main
int main(void){
 const uint64_t f32[]={0,0x3f800000,0x40000000,0x40400000,0x40800000,0x40a00000,0x40e00000};
 const uint64_t f64[]={0,0x3ff0000000000000ULL,0x4000000000000000ULL,0x4008000000000000ULL,0x4010000000000000ULL,0x4014000000000000ULL,0x401c000000000000ULL};
 const int pcs[]={24,53,64},trunc_rem[]={0,1,0,1,0,1,1},near_rem[]={0,1,0,-1,0,1,-1};
 const unsigned trunc_q[]={0,0,1,1,2,2,3},near_q[]={0,0,1,2,2,2,4};unsigned n=0,bad=0;
 for(unsigned p=0;p<3;p++)for(int rc=0;rc<4;rc++)for(int mode=0;mode<2;mode++)for(unsigned v=0;v<7;v++)for(int sx=0;sx<2;sx++)for(int sy=0;sy<2;sy++){
  int fmt=pcs[p]==24?32:64;uint64_t sign=UINT64_C(1)<<(fmt-1),a=(fmt==32?f32[v]:f64[v])|(sx?sign:0),b=(fmt==32?f32[2]:f64[2])|(sy?sign:0);result r={0};exec(mode,pcs[p],rc,a,b,&r);
  int rem=mode?near_rem[v]:trunc_rem[v],neg=(rem<0)^sx;unsigned q=mode?near_q[v]:trunc_q[v];
  uint64_t want=(rem? (fmt==32?0x3f800000:UINT64_C(0x3ff0000000000000)):0)|(neg?sign:0);
  ext e={rem?UINT64_C(0x8000000000000000):0,(uint16_t)((rem?0x3fff:0)|(neg?0x8000:0))};
  if(r.bits!=want||!eq(r.x,e)||!eq(r.s,e)||r.qx!=q||r.qmag!=q||(r.after&0x43f)||(r.mx&63)){if(bad<8)printf("FAIL pc%d rc%d mode%d v%u sx%d sy%d got=%016"PRIx64" want=%016"PRIx64" q%u/%u\n",pcs[p],rc,mode,v,sx,sy,r.bits,want,r.qx,q);bad++;}n++;
 }
 __asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));printf("Literal remainder audit: %u cases, %u failures\n",n,bad);return bad!=0;
}
