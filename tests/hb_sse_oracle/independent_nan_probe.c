#include <stdint.h>
#include <stdio.h>
#include <immintrin.h>
int main(void) {
  uint32_t saved=_mm_getcsr();
  uint32_t a[4]={0x7fc00001,0,0,0},b[4]={0x7fc12345,0,0,0},out[4];
  for(int swap=0;swap<2;swap++) for(int mem=0;mem<2;mem++){
    const uint32_t *x=swap?b:a,*y=swap?a:b;
    _mm_setcsr(0x1f80);
    if(!mem) __asm__ volatile("movdqu (%1), %%xmm0; movdqu (%2), %%xmm1; addss %%xmm1, %%xmm0; movdqu %%xmm0, (%0)"::"r"(out),"r"(x),"r"(y):"xmm0","xmm1","memory");
    else __asm__ volatile("movdqu (%1), %%xmm0; addss (%2), %%xmm0; movdqu %%xmm0, (%0)"::"r"(out),"r"(x),"r"(y):"xmm0","memory");
    uint32_t f=_mm_getcsr();_mm_setcsr(saved);
    printf("ADDSS %s a=%08x b=%08x result=%08x exceptions=%02x\n",mem?"mem":"reg",x[0],y[0],out[0],f&63);
  }
}
