#ifndef HB_CPU_FEATURES_H
#define HB_CPU_FEATURES_H

#include <stdint.h>

/* x64 adapter profile. PF numbers are the public Windows winnt.h identifiers.
 * MMX must use the effective core opt-in; the default profile leaves it off.
 * This does not claim that AVX's Wine context transport is implemented. */
#define HB_CPU_FEATURE_SIGNATURE UINT32_C(0x000306a9)

static int hb_cpu_feature_present(uint32_t feature, int mmx_opt_in)
{
    switch (feature) {
    case 3: return !!mmx_opt_in; /* PF_MMX_INSTRUCTIONS_AVAILABLE */
    case 2:  /* CMPXCHG8B */
    case 6:  /* SSE */
    case 8:  /* RDTSC */
    case 10: /* SSE2 */
    case 12: /* NX_ENABLED: retained adapter declaration; Wine uses host policy. */
    case 13: /* SSE3 */
    case 14: /* CMPXCHG16B: preserve working family; fault edge cases are separate. */
    case 23: /* FASTFAIL */
    case 32: /* RDTSCP */
    case 36: /* SSSE3 */
    case 37: /* SSE4.1 */
    case 38: /* SSE4.2 */
        return 1;
    default:
        return 0;
    }
}

typedef struct hb_cpu_feature_information {
    uint16_t architecture;
    uint16_t level;
    uint16_t revision;
    uint32_t feature_bits;
} hb_cpu_feature_information_t;

/* Only fields owned by the emulator are returned. The caller retains the
 * operating system's MaximumProcessors. This word uses Wine's AMD64 KF bit
 * assignments, not PF-number shifts and not another emulator's bit layout. */
static hb_cpu_feature_information_t hb_cpu_feature_information(int mmx_opt_in)
{
    const uint32_t signature = HB_CPU_FEATURE_SIGNATURE;
    uint32_t family = (signature >> 8) & 15;
    uint32_t model = (signature >> 4) & 15;
    hb_cpu_feature_information_t result;
    if (family == 6 || family == 15) model |= ((signature >> 16) & 15) << 4;
    if (family == 15) family += (signature >> 20) & 255;
    result.architecture = 9; /* PROCESSOR_ARCHITECTURE_AMD64 */
    result.level = (uint16_t)family;
    result.revision = (uint16_t)((model << 8) | (signature & 15));
    result.feature_bits = UINT32_C(0x01000008); /* GenuineIntel + CMOV (CPUID.1:EDX15). */
    if (hb_cpu_feature_present(8, mmx_opt_in))  result.feature_bits |= UINT32_C(0x00000002);
    if (hb_cpu_feature_present(2, mmx_opt_in))  result.feature_bits |= UINT32_C(0x00000080);
    if (hb_cpu_feature_present(3, mmx_opt_in))  result.feature_bits |= UINT32_C(0x00000100);
    if (hb_cpu_feature_present(6, mmx_opt_in))  result.feature_bits |= UINT32_C(0x00002800); /* FXSR/SSE */
    if (hb_cpu_feature_present(10, mmx_opt_in)) result.feature_bits |= UINT32_C(0x00010000);
    if (hb_cpu_feature_present(13, mmx_opt_in)) result.feature_bits |= UINT32_C(0x00080000);
    if (hb_cpu_feature_present(14, mmx_opt_in)) result.feature_bits |= UINT32_C(0x00100000);
    if (hb_cpu_feature_present(12, mmx_opt_in)) result.feature_bits |= UINT32_C(0x20000000);
    return result;
}

#endif
