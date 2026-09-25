#ifndef HB_TRANSCENDENTAL_COMPONENT_TEST_SUPPORT_H
#define HB_TRANSCENDENTAL_COMPONENT_TEST_SUPPORT_H

#include <fenv.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(__aarch64__) && !defined(__arm64__)
#error This component host-state test requires the retained ARM64 environment.
#endif

typedef struct {
    unsigned checks, failures;
    char phase[192];
} ct_stats;

typedef struct {
    uint64_t fpcr, fpsr;
    int rounding, flags, env_ok;
    fenv_t env;
} ct_host;

typedef struct { uint8_t bytes[10]; } ct_raw80;

static inline int ct_check(ct_stats *s, int condition, const char *description)
{
    ++s->checks;
    if (!condition) {
        ++s->failures;
        if (s->failures <= 32)
            fprintf(stderr, "FAIL [%s] %s\n", s->phase, description);
    }
    return condition;
}

static inline ct_raw80 ct_raw(uint16_t sign_exp, uint64_t significand)
{
    ct_raw80 result;
    for (unsigned i = 0; i < 8; ++i)
        result.bytes[i] = (uint8_t)(significand >> (8u * i));
    result.bytes[8] = (uint8_t)sign_exp;
    result.bytes[9] = (uint8_t)(sign_exp >> 8);
    return result;
}

static inline void ct_pattern(void *memory, size_t size, uint8_t seed)
{
    uint8_t *p = (uint8_t *)memory;
    for (size_t i = 0; i < size; ++i)
        p[i] = (uint8_t)(seed ^ (uint8_t)(i * 37u));
}

static inline ct_host ct_capture_host(void)
{
    ct_host h;
    memset(&h, 0, sizeof(h));
    /* Raw machine state precedes libc inspection and diagnostic formatting. */
    __asm__ __volatile__("mrs %0, fpcr\n\tmrs %1, fpsr"
                         : "=r"(h.fpcr), "=r"(h.fpsr) : : "memory");
    h.rounding = fegetround();
    h.flags = fetestexcept(FE_ALL_EXCEPT);
    h.env_ok = fegetenv(&h.env) == 0;
    return h;
}

static inline int ct_same_host(const ct_host *a, const ct_host *b)
{
    return a->env_ok && b->env_ok && a->fpcr == b->fpcr && a->fpsr == b->fpsr &&
           a->rounding == b->rounding && a->flags == b->flags &&
           memcmp(&a->env, &b->env, sizeof(a->env)) == 0;
}

static inline int ct_seed_host(unsigned rounding, unsigned sticky)
{
    static const int modes[] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    if (rounding >= 4 || sticky >= 2)
        return 0;
    int wanted = sticky ? FE_ALL_EXCEPT : 0;
    if (fesetround(modes[rounding]) || feclearexcept(FE_ALL_EXCEPT) ||
        (wanted && feraiseexcept(wanted)))
        return 0;
    /* Standard fenv flags omit IDC and cumulative saturation (QC). Exercise both
       raw sticky bits as well; restore the caller's complete environment later. */
    uint64_t fpsr;
    __asm__ __volatile__("mrs %0, fpsr" : "=r"(fpsr) : : "memory");
    fpsr &= ~UINT64_C(0x08000080);
    if (sticky)
        fpsr |= UINT64_C(0x08000080);
    __asm__ __volatile__("msr fpsr, %0" : : "r"(fpsr) : "memory");
    ct_host h = ct_capture_host();
    return h.env_ok && h.rounding == modes[rounding] && h.flags == wanted &&
           (h.fpsr & UINT64_C(0x08000080)) == (sticky ? UINT64_C(0x08000080) : 0);
}

static inline int ct_restore_host(const ct_host *saved)
{
    if (!saved->env_ok || fesetenv(&saved->env))
        return 0;
    ct_host restored = ct_capture_host();
    return ct_same_host(saved, &restored);
}

#endif
