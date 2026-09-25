/* Numerical sequencing for the selected full80 behavior. The separately
 * attributed Cephes/SoftFloat sources implement the underlying arithmetic. */
#include "hb_x87_transcendental.h"
#include <SoftFloat-3e/platform.h>
#include <SoftFloat-3e/softfloat.h>
#include <string.h>

extern float128_t cephes_f128_exp2l(float128_t);
extern float128_t cephes_f128_log2l(float128_t);
extern float128_t cephes_f128_atan2l(float128_t, float128_t);
extern float128_t cephes_f128_sinl(float128_t);
extern float128_t cephes_f128_cosl(float128_t);
extern float128_t cephes_f128_tanl(float128_t);

static extFloat80_t decode(const uint8_t raw[10]) {
    extFloat80_t value;
    memset(&value, 0, sizeof(value));
    for (unsigned i = 0; i < 8; ++i)
        value.signif |= (uint64_t)raw[i] << (8 * i);
    value.signExp = (uint16_t)(raw[8] | (uint16_t)raw[9] << 8);
    return value;
}

static void encode(extFloat80_t value, uint8_t raw[10]) {
    for (unsigned i = 0; i < 8; ++i)
        raw[i] = (uint8_t)(value.signif >> (8 * i));
    raw[8] = (uint8_t)value.signExp;
    raw[9] = (uint8_t)(value.signExp >> 8);
}

static struct softfloat_state state_from_control(uint16_t control_word) {
    static const uint8_t rounding[4] = {
        softfloat_round_near_even, softfloat_round_min,
        softfloat_round_max, softfloat_round_minMag
    };
    struct softfloat_state state = {0};
    state.detectTininess = softfloat_tininess_afterRounding;
    state.roundingMode = rounding[(control_word >> 10) & 3u];
    state.roundingPrecision = 80;
    return state;
}

static extFloat80_t evaluate_scalar(hb_x87_transcendental_op_t operation,
                                    extFloat80_t st0, extFloat80_t st1,
                                    struct softfloat_state* state) {
    const extFloat80_t one80 = {.signif = UINT64_C(0x8000000000000000),
                               .signExp = 0x3fff};
    const extFloat80_t qnan = {.signif = UINT64_C(0xc000000000000000),
                              .signExp = 0x7fff};
    const float128_t one128 = {{UINT64_C(0), UINT64_C(0x3fff000000000000)}};
    float128_t x, y, result;

    if (operation == HB_X87_TRANS_FSCALE) {
        const extFloat80_t zero = {0};
        if (extF80_eq(state, st0, zero)) {
            /* Preserve the selected wrapper's exact test, including its
             * treatment of the noncanonical positive exponent-all-ones zero. */
            if (st1.signExp == 0x7fff &&
                !(st1.signif & UINT64_C(0x7fffffffffffffff))) {
                state->exceptionFlags |= softfloat_flag_invalid;
                return qnan;
            }
            return st0;
        }
        extFloat80_t exponent = extF80_roundToInt(state, st1,
                                                  softfloat_round_minMag, false);
        y = extF80_to_f128(state, exponent);
        extFloat80_t scale = f128_to_extF80(state, cephes_f128_exp2l(y));
        return extF80_mul(state, st0, scale);
    }

    if (operation == HB_X87_TRANS_FSIN || operation == HB_X87_TRANS_FCOS ||
        operation == HB_X87_TRANS_FPTAN) {
        if ((st0.signExp & 0x7fff) == 0x7fff &&
            st0.signif == UINT64_C(0x8000000000000000)) {
            state->exceptionFlags |= softfloat_flag_invalid;
            return qnan;
        }
    }

    if (operation == HB_X87_TRANS_FYL2XP1)
        st0 = extF80_add(state, st0, one80);
    /* FPATAN's selected scalar operands are ST(1), then ST(0). */
    if (operation == HB_X87_TRANS_FPATAN) {
        y = extF80_to_f128(state, st1);
        x = extF80_to_f128(state, st0);
        return f128_to_extF80(state, cephes_f128_atan2l(y, x));
    }
    x = extF80_to_f128(state, st0);
    switch (operation) {
        case HB_X87_TRANS_F2XM1:
            result = f128_sub(state, cephes_f128_exp2l(x), one128);
            break;
        case HB_X87_TRANS_FYL2X:
        case HB_X87_TRANS_FYL2XP1:
            y = extF80_to_f128(state, st1);
            result = f128_mul(state, y, cephes_f128_log2l(x));
            break;
        case HB_X87_TRANS_FSIN:
            result = cephes_f128_sinl(x);
            break;
        case HB_X87_TRANS_FCOS:
            result = cephes_f128_cosl(x);
            break;
        case HB_X87_TRANS_FPTAN:
            result = cephes_f128_tanl(x);
            break;
        default:
            return qnan; /* Public entry validates and splits compound ops. */
    }
    return f128_to_extF80(state, result);
}

bool hb_x87_transcendental(hb_x87_transcendental_op_t operation,
                           const uint8_t st0[10], const uint8_t st1[10],
                           uint16_t control_word,
                           hb_x87_transcendental_result_t* output) {
    if ((unsigned)operation > (unsigned)HB_X87_TRANS_FSCALE || !st0 || !output)
        return false;
    bool binary = operation == HB_X87_TRANS_FYL2X || operation == HB_X87_TRANS_FYL2XP1 ||
                  operation == HB_X87_TRANS_FPATAN || operation == HB_X87_TRANS_FSCALE;
    if (binary && !st1) return false;

    extFloat80_t a = decode(st0), b = {0};
    if (binary) b = decode(st1);
    hb_x87_transcendental_result_t result;
    memset(&result, 0, sizeof(result));
    struct softfloat_state first = state_from_control(control_word);
    hb_x87_transcendental_op_t scalar = operation == HB_X87_TRANS_FSINCOS
                                        ? HB_X87_TRANS_FSIN : operation;
    encode(evaluate_scalar(scalar, a, b, &first), result.raw[0]);
    result.result_count = 1;
    result.component_flags = first.exceptionFlags;
    if (operation == HB_X87_TRANS_FSINCOS) {
        struct softfloat_state second = state_from_control(control_word);
        encode(evaluate_scalar(HB_X87_TRANS_FCOS, a, b, &second), result.raw[1]);
        result.component_flags |= second.exceptionFlags;
        result.result_count = 2;
    } else if (operation == HB_X87_TRANS_FPTAN) {
        const extFloat80_t one = {.signif = UINT64_C(0x8000000000000000),
                                 .signExp = 0x3fff};
        encode(one, result.raw[1]);
        result.result_count = 2;
    }
    result.status_set = (result.component_flags & softfloat_flag_invalid) ? 1u : 0u;
    if (operation == HB_X87_TRANS_FSIN || operation == HB_X87_TRANS_FCOS ||
        operation == HB_X87_TRANS_FSINCOS || operation == HB_X87_TRANS_FPTAN)
        result.status_clear = 0x0400u;
    memcpy(output, &result, sizeof(result));
    return true;
}
