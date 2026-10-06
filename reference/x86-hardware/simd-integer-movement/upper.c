/* Original MIT code: hardware upper-half and all-register snapshot. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cpuid.h>
extern void upper_vzeroupper(const uint8_t*,uint8_t*),upper_vzeroall(const uint8_t*,uint8_t*);
static void hex(const uint8_t*p){for(int i=31;i>=0;i--)printf("%02x",p[i]);}
int main(void){unsigned a,b,c,d;if(!__get_cpuid(1,&a,&b,&c,&d)||!(c&bit_AVX)||!(c&bit_OSXSAVE))return 2;unsigned lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));if((lo&6)!=6)return 2;
 uint8_t before[512],after[512],ref[32];unsigned lines=0,bad=0;puts("# Native vzeroupper/vzeroall; every YMM0..15 before/after; expected_rows=256");
 for(int op=0;op<2;op++)for(int sample=0;sample<8;sample++){
  for(int r=0;r<16;r++)for(int j=0;j<32;j++)before[r*32+j]=(uint8_t)(1+sample*37+r*13+j*7);
  (op?upper_vzeroall:upper_vzeroupper)(before,after);
  for(int r=0;r<16;r++){memcpy(ref,before+r*32,32);memset(ref+(op?0:16),0,op?32:16);bad+=memcmp(ref,after+r*32,32)!=0;printf("%s 256 ",op?"vzeroall":"vzeroupper");hex(before+r*32);fputs(" - - -> ",stdout);hex(after+r*32);printf(" reg=ymm%d\n",r);lines++;}
 }
 printf("# rows=%u expected=256 C_checked=%u C_mismatches=%u\n",lines,lines,bad);fprintf(stderr,"upper forms=2 register_forms=32 rows=%u expected=256 C_checked=%u C_mismatches=%u\n",lines,lines,bad);return bad||lines!=256;
}
