/* SPDX-License-Identifier: MIT. Small independent guarded-candidate edge check. */
#define main auxiliary_original_main
#include "auxiliary.c"
#undef main
int main(void){const int pcs[]={24,53,64};unsigned long tested=0,supported=0,errors=0,flags=0;
 for(int op=SCALE;op<=PREM1;op++)for(unsigned pi=0;pi<3;pi++)for(int rc=0;rc<4;rc++)for(unsigned a=0;a<NE;a++)for(unsigned b=0;b<NE;b++){
  Input i={0};i.x=edge64[a];i.y=edge64[b];i.xf=edge32[a];i.yf=edge32[b];Result r={0};x87_eval(op,pcs[pi],rc,&i,&r);sse_eval(op,pcs[pi],rc,&i,&r);tested++;
  if(!r.supported)continue;supported++;
  if((r.post&63)!=(r.mx&63))flags++;
  if(!same(r.a,r.b)||(op==XTRACT&&!same(r.a2,r.b2))||(r.quotient_tested&&(r.post&0x4700))){if(errors<10)printf("FAIL %s pc%d rc%d edge%u,%u\n",names[op],pcs[pi],rc,a,b);errors++;}
 }
 __asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));printf("Guarded auxiliary edge test: %lu native cases, %lu within candidate domains, %lu value/quotient-flag failures, %lu measured exception-flag differences\n",tested,supported,errors,flags);return errors!=0;
}
