/* SPDX-License-Identifier: MIT. Exact-value smoke tests for operand order and control. */
#define main core_main
#include "core.c"
#undef main
int main(void){
 const uint64_t expected64[]={UINT64_C(0x4024000000000000),UINT64_C(0x4018000000000000),UINT64_C(0x4030000000000000),UINT64_C(0x4010000000000000),UINT64_C(0xc018000000000000),UINT64_C(0x3fd0000000000000)};
 const uint32_t expected32[]={0x41200000,0x40c00000,0x41800000,0x40800000,0xc0c00000,0x3e800000};
 unsigned failures=0;
 puts("operation,pc,rounding,a_hex,b_hex,x87_80_hex,sse_80_hex,sse_native_hex,fsw_before,fsw_after,mxcsr,pass");
 for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++){int pc=pcs[p],fmt=pc==24?32:64;uint16_t cw=(pc==24?0x7f:pc==53?0x27f:0x37f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);__asm__ volatile("fninit; fldcw %0"::"m"(cw));for(int op=0;op<6;op++){uint64_t a=fmt==32?0x41000000:UINT64_C(0x4020000000000000),b=fmt==32?0x40000000:UINT64_C(0x4000000000000000),expected=fmt==32?expected32[op]:expected64[op];result r;execute(op,fmt,a,b,mx,&r);int pass=r.sbits==expected&&same(r.x,r.s)&&!(r.after&63)&&!(r.mx&63);failures+=!pass;printf("%s,%d,%s,%016"PRIx64",%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%016"PRIx64",%04x,%04x,%08x,%d\n",opnames[op],pc,rcnames[rc],a,b,r.x.se,r.x.sig,r.s.se,r.s.sig,r.sbits,r.before,r.after,r.mx,pass);}}
 fprintf(stderr,"selftest_failures=%u\n",failures);return failures?1:0;
}
