/* SPDX-License-Identifier: MIT. Independent literal x87 register-order test. */
#define EXTENDED_NO_MAIN
#include "extended.c"
int main(void){
 const ext80 a={UINT64_C(0x8000000000000000),0x4002},b={UINT64_C(0x8000000000000000),0x4000};
 const ext80 expect[]={{UINT64_C(0xa000000000000000),0x4002},{UINT64_C(0xc000000000000000),0x4001},{UINT64_C(0x8000000000000000),0x4003},{UINT64_C(0x8000000000000000),0x4001}};
 int checks=0,bad=0;
 for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++)for(int op=0;op<4;op++){
  uint16_t cw=(pcs[p]==24?0x007f:pcs[p]==53?0x027f:0x037f)|(rc<<10),before,after;ext80 x;
  __asm__ volatile("fninit; fldcw %0"::"m"(cw):"memory");
  actual(op,a,b,&x,&before,&after);
  if(!same(x,expect[op])||(before&63)||(after&63)){bad++;printf("FAIL %s PC%d RC%d result=%04x%016"PRIx64"\n",opnames[op],pcs[p],rc,x.se,x.sig);}checks++;
 }
 __asm__ volatile("fninit");printf("Independent extended-register exact test: %d cases, %d failures\n",checks,bad);return bad!=0;
}
