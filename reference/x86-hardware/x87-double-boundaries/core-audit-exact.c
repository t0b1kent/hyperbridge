/* SPDX-License-Identifier: MIT. Independent tiny exact-result wrapper audit. */
#define main original_core_main
#include "core.c"
#undef main
int main(void){
 static const uint64_t fp64[]={0x4018000000000000ULL,0x4000000000000000ULL,0x4020000000000000ULL,0x4000000000000000ULL,0xc000000000000000ULL,0x3fe0000000000000ULL,0x4000000000000000ULL};
 static const uint64_t fp32[]={0x40c00000,0x40000000,0x41000000,0x40000000,0xc0000000,0x3f000000,0x40000000};
 static const ext80 exp80[]={{0xc000000000000000ULL,0x4001},{0x8000000000000000ULL,0x4000},{0x8000000000000000ULL,0x4002},{0x8000000000000000ULL,0x4000},{0x8000000000000000ULL,0xc000},{0x8000000000000000ULL,0x3ffe},{0x8000000000000000ULL,0x4000}};
 int n=0,fail=0;for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++)for(int op=0;op<NOPS;op++){
  int fmt=pcs[p]==24?32:64;uint16_t cw=(pcs[p]==24?0x007f:pcs[p]==53?0x027f:0x037f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);result r;
  __asm__ volatile("fninit; fldcw %0"::"m"(cw):"memory");
  execute(op,fmt,fmt==32?0x40800000:0x4010000000000000ULL,fmt==32?0x40000000:0x4000000000000000ULL,mx,&r);
  uint64_t expected=fmt==32?fp32[op]:fp64[op];
  int ok=same(r.x,exp80[op])&&same(r.s,exp80[op])&&r.sbits==expected&&r.memory_bits==expected&&!(r.before&63)&&!(r.after&63)&&!(r.mx&63)&&!(r.memory_after&63);
  if(!ok){fail++;printf("FAIL %s pc%d rc%d x=%04x%016"PRIx64" s=%016"PRIx64"\n",opnames[op],pcs[p],rc,r.x.se,r.x.sig,r.sbits);}n++;
 }
 __asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));printf("Independent exact test: %d cases, %d failures\n",n,fail);return fail!=0;
}
