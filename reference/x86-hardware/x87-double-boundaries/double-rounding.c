/* SPDX-License-Identifier: MIT. Hardware precision-sweep witnesses. */
#define main core_main
#include "core.c"
#undef main
#include "double-rounding-vectors.h"
int main(void){puts("operation,input_bits,original_random_index,pc,rounding,a_hex,b_hex,x87_80_hex,sse_80_hex,x87_stored_hex,sse_native_hex,fsw_after,mxcsr,fsw_store,stored_equal");
 for(unsigned i=0;i<sizeof(vectors)/sizeof(*vectors);i++)for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++){const struct vector*v=&vectors[i];int pc=pcs[p];uint16_t cw=(pc==24?0x7f:pc==53?0x27f:0x37f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);__asm__ volatile("fninit; fldcw %0"::"m"(cw));result r;execute(v->op,v->fmt,v->a,v->b,mx,&r);printf("%s,%d,%"PRIu64",%d,%s,%016"PRIx64",%016"PRIx64",%04x%016"PRIx64",%04x%016"PRIx64",%016"PRIx64",%016"PRIx64",%04x,%08x,%04x,%d\n",opnames[v->op],v->fmt,v->index,pc,rcnames[rc],v->a,v->b,r.x.se,r.x.sig,r.s.se,r.s.sig,r.memory_bits,r.sbits,r.after,r.mx,r.memory_after,r.memory_bits==r.sbits);}
 return 0;}
