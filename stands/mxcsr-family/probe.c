/* SPDX-License-Identifier: MIT
 * Public, synthetic IEEE-754 inputs only. No captured code/state/game data.
 * Compile and run on native x86_64; the caller must prove the CPU vendor.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cpuid.h>

#if !defined(__x86_64__)
#error This probe requires native x86_64
#endif

struct answer { uint32_t mxcsr, result; uint64_t flags; };

#define COMPARE_FN(name, instruction, load, width)                           \
static struct answer name(width a, width b) {                               \
    struct answer r = {0, 0, 0};                                           \
    uint32_t initial = 0x1f80, saved;                                       \
    __asm__ volatile(                                                      \
        "stmxcsr %[saved]\n\tldmxcsr %[initial]\n\t"                       \
        load " %[a], %%xmm0\n\t" load " %[b], %%xmm1\n\t"                 \
        instruction " %%xmm1, %%xmm0\n\tpushfq\n\tpopq %[flags]\n\t"     \
        "stmxcsr %[out]\n\tldmxcsr %[saved]"                              \
        : [saved] "=m"(saved), [out] "=m"(r.mxcsr),                         \
          [flags] "=&r"(r.flags)                                          \
        : [initial] "m"(initial), [a] "m"(a), [b] "m"(b)                   \
        : "xmm0", "xmm1", "cc", "memory");                              \
    return r;                                                              \
}
COMPARE_FN(ucomisd_case, "ucomisd", "movq", uint64_t)
COMPARE_FN(comisd_case, "comisd", "movq", uint64_t)
COMPARE_FN(ucomiss_case, "ucomiss", "movd", uint32_t)
COMPARE_FN(comiss_case, "comiss", "movd", uint32_t)

static struct answer arithmetic_case(unsigned which) {
    struct answer r = {0, 0, 0};
    uint32_t initial = 0x1f80, saved;
    /* IEEE boundary values: smallest normal * (1/2 + 2^-24), then +0. */
    uint32_t a = which == 0 ? 0x00800000 : 0x3f800000;
    uint32_t b = which == 0 ? 0x3f000001 : 0x33000000;
    uint32_t zero = 0;
#define ARITH(body)                                                         \
    __asm__ volatile(                                                      \
        "stmxcsr %[saved]\n\tldmxcsr %[initial]\n\t"                       \
        "movd %[a], %%xmm0\n\tmovd %[b], %%xmm1\n\t"                     \
        body "\n\tmovd %%xmm0, %[result]\n\tstmxcsr %[out]\n\t"          \
        "ldmxcsr %[saved]"                                                \
        : [saved] "=m"(saved), [out] "=m"(r.mxcsr),                         \
          [result] "=m"(r.result)                                         \
        : [initial] "m"(initial), [a] "m"(a), [b] "m"(b), [zero] "m"(zero) \
        : "xmm0", "xmm1", "xmm2", "cc", "memory")
    if (which == 0) {
        ARITH("mulss %%xmm1, %%xmm0\n\tmovd %[zero], %%xmm2\n\taddss %%xmm2, %%xmm0");
    } else if (which == 1) {
        ARITH("addss %%xmm1, %%xmm0");
    } else {
        ARITH("subss %%xmm1, %%xmm0");
    }
#undef ARITH
    return r;
}

static unsigned failed;
static void emit(const char *name, struct answer r, uint32_t expected,
                 int has_result, uint32_t expected_result) {
    unsigned pass = r.mxcsr == expected && (!has_result || r.result == expected_result);
    failed += !pass;
    printf("{\"case\":\"%s\",\"initial_mxcsr\":\"1f80\","
           "\"mxcsr\":\"%04x\",\"expected_mxcsr\":\"%04x\","
           "\"result\":\"%08x\",\"flags\":\"%llx\",\"pass\":%s}\n",
           name, r.mxcsr, expected, r.result, (unsigned long long)r.flags,
           pass ? "true" : "false");
}

int main(void) {
    unsigned eax, ebx, ecx, edx;
    char vendor[13] = {0};
    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) return 2;
    memcpy(vendor, &ebx, 4); memcpy(vendor + 4, &edx, 4); memcpy(vendor + 8, &ecx, 4);
    printf("{\"machine\":\"native_x86_64\",\"cpuid_vendor\":\"%s\"}\n", vendor);
    const uint64_t minus_one = UINT64_C(0xbff0000000000000);
    emit("ucomisd_min_subnormal_neg1", ucomisd_case(1, minus_one), 0x1f82, 0, 0);
    emit("ucomisd_max_subnormal_neg1", ucomisd_case(UINT64_C(0x000fffffffffffff), minus_one), 0x1f82, 0, 0);
    emit("ucomisd_zero_neg1", ucomisd_case(0, minus_one), 0x1f80, 0, 0);
    emit("ucomisd_quiet_nan", ucomisd_case(UINT64_C(0x7ff8000000000000), minus_one), 0x1f80, 0, 0);
    emit("ucomisd_signaling_nan", ucomisd_case(UINT64_C(0x7ff0000000000001), minus_one), 0x1f81, 0, 0);
    emit("comisd_min_subnormal_neg1", comisd_case(1, minus_one), 0x1f82, 0, 0);
    emit("comisd_quiet_nan", comisd_case(UINT64_C(0x7ff8000000000000), minus_one), 0x1f81, 0, 0);
    emit("ucomiss_min_subnormal_neg1", ucomiss_case(1, 0xbf800000), 0x1f82, 0, 0);
    emit("comiss_min_subnormal_neg1", comiss_case(1, 0xbf800000), 0x1f82, 0, 0);
    emit("mulss_tiny_inexact_then_addss_zero", arithmetic_case(0), 0x1fb2, 1, 0x00400000);
    emit("addss_inexact", arithmetic_case(1), 0x1fa0, 1, 0x3f800000);
    emit("subss_inexact", arithmetic_case(2), 0x1fa0, 1, 0x3f800000);
    return failed ? 1 : 0;
}
