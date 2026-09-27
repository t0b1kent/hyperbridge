/* Exact, exception-free finite x87 candidates. Guest state commit and
 * unsupported/exceptional fallback policy belong to the interpreter caller. */
#include "hb_x87_exact.h"
#include <SoftFloat-3e/platform.h>
#include <SoftFloat-3e/softfloat.h>
#include <string.h>

static uint64_t read_significand(const uint8_t raw[10]) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)raw[i] << (i * 8);
    return value;
}

static bool canonical_normal_or_zero(uint16_t sign_exp, uint64_t significand) {
    unsigned exponent = sign_exp & 0x7fffu;
    return exponent == 0 ? significand == 0 :
           exponent < 0x7fffu && (significand >> 63) != 0;
}

bool hb_x87_exact_addsub(const uint8_t lhs[10], const uint8_t rhs[10],
                        uint16_t control_word, bool subtract, uint8_t output[10]) {
    if (!lhs || !rhs || !output) return false;
    unsigned pc = (control_word >> 8) & 3u;
    if (pc == 1) return false; /* Reserved guest precision is a legacy fallback. */
    extFloat80_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.signif = read_significand(lhs);
    b.signif = read_significand(rhs);
    a.signExp = (uint16_t)(lhs[8] | (uint16_t)lhs[9] << 8);
    b.signExp = (uint16_t)(rhs[8] | (uint16_t)rhs[9] << 8);
    if (!canonical_normal_or_zero(a.signExp, a.signif) ||
        !canonical_normal_or_zero(b.signExp, b.signif)) return false;
    static const uint8_t rounding[] = {
        softfloat_round_near_even, softfloat_round_min,
        softfloat_round_max, softfloat_round_minMag
    };
    struct softfloat_state state = {
        .detectTininess = softfloat_tininess_afterRounding,
        .roundingMode = rounding[(control_word >> 10) & 3u],
        .exceptionFlags = 0,
        .roundingPrecision = pc == 0 ? 32 : pc == 2 ? 64 : 80
    };
    extFloat80_t result = subtract ? extF80_sub(&state, a, b)
                                  : extF80_add(&state, a, b);
    /* Exact subnormal results can require unmasked x87 underflow handling even
     * when this component reports no flags, so they also remain a fallback. */
    if (state.exceptionFlags ||
        !canonical_normal_or_zero(result.signExp, result.signif)) return false;
    for (unsigned i = 0; i < 8; ++i)
        output[i] = (uint8_t)(result.signif >> (i * 8));
    output[8] = (uint8_t)result.signExp;
    output[9] = (uint8_t)(result.signExp >> 8);
    return true;
}

bool hb_x87_exact_muldiv(const uint8_t lhs[10], const uint8_t rhs[10],
                        uint16_t control_word, bool divide, uint8_t output[10]) {
    if (!lhs || !rhs || !output) return false;
    unsigned pc = (control_word >> 8) & 3u;
    if (pc == 1) return false; /* Reserved guest precision is a legacy fallback. */
    extFloat80_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.signif = read_significand(lhs);
    b.signif = read_significand(rhs);
    a.signExp = (uint16_t)(lhs[8] | (uint16_t)lhs[9] << 8);
    b.signExp = (uint16_t)(rhs[8] | (uint16_t)rhs[9] << 8);
    if (!canonical_normal_or_zero(a.signExp, a.signif) ||
        !canonical_normal_or_zero(b.signExp, b.signif)) return false;
    if (divide && b.signif == 0) return false; /* Zero divisors retain legacy policy. */
    static const uint8_t rounding[] = {
        softfloat_round_near_even, softfloat_round_min,
        softfloat_round_max, softfloat_round_minMag
    };
    struct softfloat_state state = {
        .detectTininess = softfloat_tininess_afterRounding,
        .roundingMode = rounding[(control_word >> 10) & 3u],
        .exceptionFlags = 0,
        .roundingPrecision = pc == 0 ? 32 : pc == 2 ? 64 : 80
    };
    extFloat80_t result = divide ? extF80_div(&state, a, b)
                                : extF80_mul(&state, a, b);
    /* Exact subnormal results can require unmasked x87 underflow handling even
     * when this component reports no flags, so they also remain a fallback. */
    if (state.exceptionFlags ||
        !canonical_normal_or_zero(result.signExp, result.signif)) return false;
    for (unsigned i = 0; i < 8; ++i)
        output[i] = (uint8_t)(result.signif >> (i * 8));
    output[8] = (uint8_t)result.signExp;
    output[9] = (uint8_t)(result.signExp >> 8);
    return true;
}

typedef enum {
    FINITE_ADD, FINITE_SUB, FINITE_MUL, FINITE_DIV
} finite_operation_t;

static extFloat80_t finite_evaluate(struct softfloat_state* state,
                                    extFloat80_t a, extFloat80_t b,
                                    finite_operation_t operation) {
    switch (operation) {
        case FINITE_ADD: return extF80_add(state, a, b);
        case FINITE_SUB: return extF80_sub(state, a, b);
        case FINITE_MUL: return extF80_mul(state, a, b);
        case FINITE_DIV: return extF80_div(state, a, b);
    }
    /* All callers select one of the four private operations. */
    return a;
}

static bool canonical_normal(uint16_t sign_exp, uint64_t significand) {
    return (sign_exp & 0x7fffu) != 0 &&
           canonical_normal_or_zero(sign_exp, significand);
}

static bool finite_arithmetic(const uint8_t lhs[10], const uint8_t rhs[10],
                              uint16_t control_word, finite_operation_t operation,
                              hb_x87_finite_result_t* output) {
    if (!lhs || !rhs || !output) return false;
    unsigned pc = (control_word >> 8) & 3u;
    if (pc == 1) return false;
    extFloat80_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a.signif = read_significand(lhs);
    b.signif = read_significand(rhs);
    a.signExp = (uint16_t)(lhs[8] | (uint16_t)lhs[9] << 8);
    b.signExp = (uint16_t)(rhs[8] | (uint16_t)rhs[9] << 8);
    if (!canonical_normal_or_zero(a.signExp, a.signif) ||
        !canonical_normal_or_zero(b.signExp, b.signif)) return false;
    if (operation == FINITE_DIV && b.signif == 0) return false;
    static const uint8_t rounding[] = {
        softfloat_round_near_even, softfloat_round_min,
        softfloat_round_max, softfloat_round_minMag
    };
    struct softfloat_state state = {
        .detectTininess = softfloat_tininess_afterRounding,
        .roundingMode = rounding[(control_word >> 10) & 3u],
        .exceptionFlags = 0,
        .roundingPrecision = pc == 0 ? 32 : pc == 2 ? 64 : 80
    };
    extFloat80_t result = finite_evaluate(&state, a, b, operation);
    uint16_t status_bits = 0;
    if (!state.exceptionFlags) {
        if (!canonical_normal_or_zero(result.signExp, result.signif)) return false;
    } else {
        if (state.exceptionFlags != softfloat_flag_inexact ||
            !(control_word & 0x0020u) ||
            !canonical_normal(result.signExp, result.signif)) return false;
        struct softfloat_state truncated_state = {
            .detectTininess = softfloat_tininess_afterRounding,
            .roundingMode = softfloat_round_minMag,
            .exceptionFlags = 0,
            .roundingPrecision = state.roundingPrecision
        };
        /* Truncation is already the first trial under RC=3. Reuse its exact
         * value and exception flags; repeating SoftFloat cannot add evidence. */
        extFloat80_t truncated;
        if (state.roundingMode == softfloat_round_minMag) {
            truncated = result;
            truncated_state = state;
        } else {
            truncated = finite_evaluate(&truncated_state, a, b, operation);
        }
        /* A rounded minimum-normal result can hide a tiny exact result. The
         * truncation must also be normal to retain the underflow boundary. */
        if (truncated_state.exceptionFlags != softfloat_flag_inexact ||
            !canonical_normal(truncated.signExp, truncated.signif) ||
            ((result.signExp ^ truncated.signExp) & 0x8000u)) return false;
        status_bits = 0x0020u;
        /* C1 records a magnitude increment, including negative results and
         * significand carry. Compare fields, never extFloat80_t padding. */
        if (result.signExp != truncated.signExp || result.signif != truncated.signif)
            status_bits |= 0x0200u;
    }
    for (unsigned i = 0; i < 8; ++i)
        output->raw[i] = (uint8_t)(result.signif >> (i * 8));
    output->raw[8] = (uint8_t)result.signExp;
    output->raw[9] = (uint8_t)(result.signExp >> 8);
    output->status_bits = status_bits;
    return true;
}

bool hb_x87_finite_addsub(const uint8_t lhs[10], const uint8_t rhs[10],
                         uint16_t control_word, bool subtract,
                         hb_x87_finite_result_t* result) {
    return finite_arithmetic(lhs, rhs, control_word,
                             subtract ? FINITE_SUB : FINITE_ADD, result);
}

bool hb_x87_finite_muldiv(const uint8_t lhs[10], const uint8_t rhs[10],
                         uint16_t control_word, bool divide,
                         hb_x87_finite_result_t* result) {
    return finite_arithmetic(lhs, rhs, control_word,
                             divide ? FINITE_DIV : FINITE_MUL, result);
}

/* Unary finite sqrt admission. Guest state and fallback remain caller-owned. */
bool hb_x87_finite_sqrt(const uint8_t input[10], uint16_t control_word,
                       hb_x87_finite_result_t* output) {
    if (!input || !output) return false;
    unsigned pc = (control_word >> 8) & 3u;
    if (pc == 1) return false;
    extFloat80_t a;
    memset(&a, 0, sizeof(a));
    a.signif = read_significand(input);
    a.signExp = (uint16_t)(input[8] | (uint16_t)input[9] << 8);
    if (!canonical_normal_or_zero(a.signExp, a.signif) ||
        ((a.signExp & 0x8000u) && a.signif != 0)) return false;
    static const uint8_t rounding[] = {
        softfloat_round_near_even, softfloat_round_min,
        softfloat_round_max, softfloat_round_minMag
    };
    struct softfloat_state state = {
        .detectTininess = softfloat_tininess_afterRounding,
        .roundingMode = rounding[(control_word >> 10) & 3u],
        .exceptionFlags = 0,
        .roundingPrecision = pc == 0 ? 32 : pc == 2 ? 64 : 80
    };
    extFloat80_t result = extF80_sqrt(&state, a);
    uint16_t status_bits = 0;
    /* Positive inputs have positive roots; canonical signed zero keeps its sign. */
    if ((result.signExp ^ a.signExp) & 0x8000u) return false;
    if (!state.exceptionFlags) {
        if (!canonical_normal_or_zero(result.signExp, result.signif)) return false;
    } else {
        if (state.exceptionFlags != softfloat_flag_inexact ||
            !(control_word & 0x0020u) ||
            !canonical_normal(result.signExp, result.signif)) return false;
        struct softfloat_state truncated_state = {
            .detectTininess = softfloat_tininess_afterRounding,
            .roundingMode = softfloat_round_minMag,
            .exceptionFlags = 0,
            .roundingPrecision = state.roundingPrecision
        };
        extFloat80_t truncated;
        if (state.roundingMode == softfloat_round_minMag) {
            truncated = result;
            truncated_state = state;
        } else {
            truncated = extF80_sqrt(&truncated_state, a);
        }
        /* Both trials stay normal for positive normal inputs; retain the
         * explicit boundary before reporting a precision-only result. */
        if (truncated_state.exceptionFlags != softfloat_flag_inexact ||
            !canonical_normal(truncated.signExp, truncated.signif) ||
            ((result.signExp ^ truncated.signExp) & 0x8000u)) return false;
        status_bits = 0x0020u;
        /* A field difference from truncation means a magnitude increment. */
        if (result.signExp != truncated.signExp || result.signif != truncated.signif)
            status_bits |= 0x0200u;
    }
    for (unsigned i = 0; i < 8; ++i)
        output->raw[i] = (uint8_t)(result.signif >> (i * 8));
    output->raw[8] = (uint8_t)result.signExp;
    output->raw[9] = (uint8_t)(result.signExp >> 8);
    output->status_bits = status_bits;
    return true;
}
