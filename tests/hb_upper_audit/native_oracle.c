/* Linux x86-64 only: actual guest bytes execute on the host CPU, not in an emulator. */
#include <cpuid.h>
#include <stdint.h>
#include <xmmintrin.h>
extern void hb_upper_native_asm(const void*,void*,void*,const void*,uint64_t,uint64_t);
int hb_upper_native_available(void) {
    unsigned a,b,c,d;
    if (!__get_cpuid(1,&a,&b,&c,&d) || !(c & bit_OSXSAVE) || !(c & bit_AVX)) return 0;
    uint32_t lo,hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    if ((lo & 0xe6) != 0xe6) return 0;
    if (!__get_cpuid_count(7,0,&a,&b,&c,&d)) return 0;
    return (b & ((1u<<16)|(1u<<17)|(1u<<30)|(1u<<31))) == ((1u<<16)|(1u<<17)|(1u<<30)|(1u<<31));
}
void hb_upper_native(const void *in,void *out,void *mem,const void *fn,uint64_t rax,uint64_t k1) {
    unsigned saved=_mm_getcsr();
    _mm_setcsr(0x1f80);
    hb_upper_native_asm(in,out,mem,fn,rax,k1);
    _mm_setcsr(saved);
}
