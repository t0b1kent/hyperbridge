/* M61 cached tiny FSINCOS guest fixture. New raw sine=input/cosine=+1
 * and successful C2 clear follow the independent selected-full80 interval proof.
 * Paired legacy previews come separately from the retained M60 host diagnostic;
 * they never supply new raw answers. Lower-bound controls retain HB behavior,
 * not the donor's documented defective denormal-scaling result. Synthetic raw
 * decline pairs do not claim special transcendental correctness. Only pushed
 * cosine for masked-empty ST0 permits checked quiet-NaN preview normalization;
 * sine indefinite comes from the still-empty setter. C1 is preserved; C0/C3 and
 * inherited FIP bookkeeping are outside the new architectural claim. No timing.
 */
#pragma STDC FENV_ACCESS ON
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include "transcendental_guest_test_reference.h"
#include <fenv.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CODE UINT64_C(0x7100000)
#define PAGE_BYTES 16384u
enum { NORMAL, UNCACHED, EXCLUDED, LOWER, UPPER, PENDING, OCCUPIED, EMPTY, GROUPS };
enum { RAW, X87_STATUS, INTEGER_FLAGS, STATE, EXECUTION, HOST, DECODE, CATEGORIES };
typedef struct {uint16_t se;uint64_t sig,preview;unsigned tag;} raw_t;
typedef struct {uint64_t sine_preview,cosine_preview;unsigned sine_tag,cosine_tag;} legacy_t;
typedef struct {const char *name;raw_t input;legacy_t legacy[4];unsigned legacy_ixc;} sample_t;
typedef struct {int rc,flags;uint64_t fpcr,fpsr;} host_t;
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;} fixture_t;
#define R(se,sig,bits,tag) {UINT16_C(se),UINT64_C(sig),UINT64_C(bits),tag}
#define L(sine,cosine,sine_tag,cosine_tag) {UINT64_C(sine),UINT64_C(cosine),sine_tag,cosine_tag}
static const raw_t raw_cosine_one=R(0x3fff,0x8000000000000000,0x3ff0000000000000,0);
static const sample_t normals[]={
    {"positive_safe_lower_boundary",R(0x2001,0x8000000000000000,0x0000000000000000,0),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"negative_safe_lower_boundary",R(0xa001,0x8000000000000000,0x8000000000000000,0),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"positive_safe_lower_low_bit",R(0x2001,0x8000000000000001,0x0000000000000000,0),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"negative_safe_lower_low_bit",R(0xa001,0x8000000000000001,0x8000000000000000,0),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"positive_safe_lower_max_significand",R(0x2001,0xffffffffffffffff,0x0000000000000000,0),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"negative_safe_lower_max_significand",R(0xa001,0xffffffffffffffff,0x8000000000000000,0),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"positive_power_minus1200",R(0x3b4f,0x8000000000000000,0x0000000000000000,0),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"negative_power_minus1200",R(0xbb4f,0x8000000000000000,0x8000000000000000,0),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"positive_power_minus1200_low_bit",R(0x3b4f,0x8000000000000001,0x0000000000000000,0),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"negative_power_minus1200_low_bit",R(0xbb4f,0x8000000000000001,0x8000000000000000,0),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"positive_power_minus1000",R(0x3c17,0x8000000000000000,0x0170000000000000,0),{L(0x0170000000000000,0x3ff0000000000000,0,0),L(0x0170000000000000,0x3ff0000000000000,0,0),L(0x0170000000000000,0x3ff0000000000000,0,0),L(0x0170000000000000,0x3ff0000000000000,0,0)},1},
    {"negative_power_minus1000",R(0xbc17,0x8000000000000000,0x8170000000000000,0),{L(0x8170000000000000,0x3ff0000000000000,0,0),L(0x8170000000000000,0x3ff0000000000000,0,0),L(0x8170000000000000,0x3ff0000000000000,0,0),L(0x8170000000000000,0x3ff0000000000000,0,0)},1},
    {"positive_three_halves_minus1000",R(0x3c17,0xc000000000000000,0x0178000000000000,0),{L(0x0178000000000000,0x3ff0000000000000,0,0),L(0x0178000000000000,0x3ff0000000000000,0,0),L(0x0178000000000000,0x3ff0000000000000,0,0),L(0x0178000000000000,0x3ff0000000000000,0,0)},1},
    {"negative_three_halves_minus1000",R(0xbc17,0xc000000000000000,0x8178000000000000,0),{L(0x8178000000000000,0x3ff0000000000000,0,0),L(0x8178000000000000,0x3ff0000000000000,0,0),L(0x8178000000000000,0x3ff0000000000000,0,0),L(0x8178000000000000,0x3ff0000000000000,0,0)},1},
    {"positive_power_minus65",R(0x3fbe,0x8000000000000000,0x3be0000000000000,0),{L(0x3be0000000000000,0x3ff0000000000000,0,0),L(0x3bdfffffffffffff,0x3fefffffffffffff,0,0),L(0x3be0000000000000,0x3ff0000000000000,0,0),L(0x3bdfffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"negative_power_minus65",R(0xbfbe,0x8000000000000000,0xbbe0000000000000,0),{L(0xbbe0000000000000,0x3ff0000000000000,0,0),L(0xbbe0000000000000,0x3fefffffffffffff,0,0),L(0xbbdfffffffffffff,0x3ff0000000000000,0,0),L(0xbbdfffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"positive_three_halves_minus65",R(0x3fbe,0xc000000000000000,0x3be8000000000000,0),{L(0x3be8000000000000,0x3ff0000000000000,0,0),L(0x3be7ffffffffffff,0x3fefffffffffffff,0,0),L(0x3be8000000000000,0x3ff0000000000000,0,0),L(0x3be7ffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"negative_three_halves_minus65",R(0xbfbe,0xc000000000000000,0xbbe8000000000000,0),{L(0xbbe8000000000000,0x3ff0000000000000,0,0),L(0xbbe8000000000000,0x3fefffffffffffff,0,0),L(0xbbe7ffffffffffff,0x3ff0000000000000,0,0),L(0xbbe7ffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"positive_raw_predecessor_power_minus64",R(0x3fbe,0xffffffffffffffff,0x3bf0000000000000,0),{L(0x3bf0000000000000,0x3ff0000000000000,0,0),L(0x3befffffffffffff,0x3fefffffffffffff,0,0),L(0x3bf0000000000000,0x3ff0000000000000,0,0),L(0x3befffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"negative_raw_predecessor_power_minus64",R(0xbfbe,0xffffffffffffffff,0xbbf0000000000000,0),{L(0xbbf0000000000000,0x3ff0000000000000,0,0),L(0xbbf0000000000000,0x3fefffffffffffff,0,0),L(0xbbefffffffffffff,0x3ff0000000000000,0,0),L(0xbbefffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"positive_binary64_predecessor_power_minus64",R(0x3fbe,0xfffffffffffff800,0x3befffffffffffff,0),{L(0x3befffffffffffff,0x3ff0000000000000,0,0),L(0x3beffffffffffffe,0x3fefffffffffffff,0,0),L(0x3befffffffffffff,0x3ff0000000000000,0,0),L(0x3beffffffffffffe,0x3fefffffffffffff,0,0)},1},
    {"negative_binary64_predecessor_power_minus64",R(0xbfbe,0xfffffffffffff800,0xbbefffffffffffff,0),{L(0xbbefffffffffffff,0x3ff0000000000000,0,0),L(0xbbefffffffffffff,0x3fefffffffffffff,0,0),L(0xbbeffffffffffffe,0x3ff0000000000000,0,0),L(0xbbeffffffffffffe,0x3fefffffffffffff,0,0)},1},
    {"positive_minimum_binary64_normal",R(0x3c01,0x8000000000000000,0x0010000000000000,0),{L(0x0010000000000000,0x3ff0000000000000,0,0),L(0x0010000000000000,0x3ff0000000000000,0,0),L(0x0010000000000000,0x3ff0000000000000,0,0),L(0x0010000000000000,0x3ff0000000000000,0,0)},1},
    {"negative_minimum_binary64_normal",R(0xbc01,0x8000000000000000,0x8010000000000000,0),{L(0x8010000000000000,0x3ff0000000000000,0,0),L(0x8010000000000000,0x3ff0000000000000,0,0),L(0x8010000000000000,0x3ff0000000000000,0,0),L(0x8010000000000000,0x3ff0000000000000,0,0)},1},
};
static const sample_t uncached[]={
    {"uncached_opposite_raw_positive_zero",R(0xbb4f,0x8000000000000001,0x0000000000000000,1),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"uncached_opposite_raw_negative_zero",R(0x3b4f,0x8000000000000001,0x8000000000000000,1),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"uncached_opposite_raw_positive_power_minus65",R(0xbb4f,0x8000000000000001,0x3be0000000000000,0),{L(0x3be0000000000000,0x3ff0000000000000,0,0),L(0x3bdfffffffffffff,0x3fefffffffffffff,0,0),L(0x3be0000000000000,0x3ff0000000000000,0,0),L(0x3bdfffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"uncached_opposite_raw_negative_power_minus65",R(0x3b4f,0x8000000000000001,0xbbe0000000000000,0),{L(0xbbe0000000000000,0x3ff0000000000000,0,0),L(0xbbe0000000000000,0x3fefffffffffffff,0,0),L(0xbbdfffffffffffff,0x3ff0000000000000,0,0),L(0xbbdfffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"uncached_opposite_raw_positive_three_halves_minus65",R(0xbb4f,0x8000000000000001,0x3be8000000000000,0),{L(0x3be8000000000000,0x3ff0000000000000,0,0),L(0x3be7ffffffffffff,0x3fefffffffffffff,0,0),L(0x3be8000000000000,0x3ff0000000000000,0,0),L(0x3be7ffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"uncached_opposite_raw_negative_three_halves_minus65",R(0x3b4f,0x8000000000000001,0xbbe8000000000000,0),{L(0xbbe8000000000000,0x3ff0000000000000,0,0),L(0xbbe8000000000000,0x3fefffffffffffff,0,0),L(0xbbe7ffffffffffff,0x3ff0000000000000,0,0),L(0xbbe7ffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"uncached_opposite_raw_positive_binary64_predecessor_power_minus64",R(0xbb4f,0x8000000000000001,0x3befffffffffffff,0),{L(0x3befffffffffffff,0x3ff0000000000000,0,0),L(0x3beffffffffffffe,0x3fefffffffffffff,0,0),L(0x3befffffffffffff,0x3ff0000000000000,0,0),L(0x3beffffffffffffe,0x3fefffffffffffff,0,0)},1},
    {"uncached_opposite_raw_negative_binary64_predecessor_power_minus64",R(0x3b4f,0x8000000000000001,0xbbefffffffffffff,0),{L(0xbbefffffffffffff,0x3ff0000000000000,0,0),L(0xbbefffffffffffff,0x3fefffffffffffff,0,0),L(0xbbeffffffffffffe,0x3ff0000000000000,0,0),L(0xbbeffffffffffffe,0x3fefffffffffffff,0,0)},1},
};
static const sample_t excluded[]={
    {"excluded_positive_zero",R(0x0000,0x0000000000000000,0x0000000000000000,1),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"excluded_negative_zero",R(0x8000,0x0000000000000000,0x8000000000000000,1),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_positive_true_denormal",R(0x0000,0x0000000000000001,0x0000000000000000,2),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_negative_true_denormal",R(0x8000,0x0000000000000001,0x8000000000000000,2),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_positive_pseudo_denormal",R(0x0000,0x8000000000000000,0x0000000000000000,2),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_negative_pseudo_denormal",R(0x8000,0x8000000000000000,0x8000000000000000,2),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_positive_unsupported",R(0x3fbe,0x7fffffffffffffff,0x3be0000000000000,2),{L(0x3be0000000000000,0x3ff0000000000000,0,0),L(0x3bdfffffffffffff,0x3fefffffffffffff,0,0),L(0x3be0000000000000,0x3ff0000000000000,0,0),L(0x3bdfffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"synthetic_decline_negative_unsupported",R(0xbfbe,0x7fffffffffffffff,0xbbe0000000000000,2),{L(0xbbe0000000000000,0x3ff0000000000000,0,0),L(0xbbe0000000000000,0x3fefffffffffffff,0,0),L(0xbbdfffffffffffff,0x3ff0000000000000,0,0),L(0xbbdfffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"synthetic_decline_positive_infinity",R(0x7fff,0x8000000000000000,0x0000000000000000,2),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_negative_infinity",R(0xffff,0x8000000000000000,0x8000000000000000,2),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_positive_quiet_nan",R(0x7fff,0xc000000000000001,0x0000000000000000,2),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"synthetic_decline_negative_quiet_nan",R(0xffff,0xc000000000000001,0x8000000000000000,2),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
};
static const sample_t lower[]={
    {"positive_retained_hb_lower_binade_power",R(0x2000,0x8000000000000000,0x0000000000000000,0),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"negative_retained_hb_lower_binade_power",R(0xa000,0x8000000000000000,0x8000000000000000,0),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
    {"positive_retained_hb_below_lower_bound",R(0x2000,0xffffffffffffffff,0x0000000000000000,0),{L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0),L(0x0000000000000000,0x3ff0000000000000,1,0)},0},
    {"negative_retained_hb_below_lower_bound",R(0xa000,0xffffffffffffffff,0x8000000000000000,0),{L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0),L(0x8000000000000000,0x3ff0000000000000,1,0)},0},
};
static const sample_t upper[]={
    {"positive_excluded_upper_bound",R(0x3fbf,0x8000000000000000,0x3bf0000000000000,0),{L(0x3bf0000000000000,0x3ff0000000000000,0,0),L(0x3befffffffffffff,0x3fefffffffffffff,0,0),L(0x3bf0000000000000,0x3ff0000000000000,0,0),L(0x3befffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"negative_excluded_upper_bound",R(0xbfbf,0x8000000000000000,0xbbf0000000000000,0),{L(0xbbf0000000000000,0x3ff0000000000000,0,0),L(0xbbf0000000000000,0x3fefffffffffffff,0,0),L(0xbbefffffffffffff,0x3ff0000000000000,0,0),L(0xbbefffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"positive_excluded_above_upper_bound_low_bit",R(0x3fbf,0x8000000000000001,0x3bf0000000000000,0),{L(0x3bf0000000000000,0x3ff0000000000000,0,0),L(0x3befffffffffffff,0x3fefffffffffffff,0,0),L(0x3bf0000000000000,0x3ff0000000000000,0,0),L(0x3befffffffffffff,0x3fefffffffffffff,0,0)},1},
    {"negative_excluded_above_upper_bound_low_bit",R(0xbfbf,0x8000000000000001,0xbbf0000000000000,0),{L(0xbbf0000000000000,0x3ff0000000000000,0,0),L(0xbbf0000000000000,0x3fefffffffffffff,0,0),L(0xbbefffffffffffff,0x3ff0000000000000,0,0),L(0xbbefffffffffffff,0x3fefffffffffffff,0,0)},1},
};
static const unsigned pending_samples[]={6,7,14,15};
static const unsigned occupied_samples[]={6,14};
static const unsigned empty_samples[]={6,14};
static const uint8_t instruction[]={0xd9,0xfb};
static unsigned checks,failures,executions,group_calls[GROUPS],category_failures[CATEGORIES];
static char phase[320];

static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=24)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}

static int check(int ok,const char *what){return check_kind(ok,what,STATE);}

static void put16(uint8_t *p,uint16_t x){p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);}

static void put64(uint8_t *p,uint64_t x){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(x>>(8*i));}

static host_t host_state(void)
{
    host_t h={.rc=fegetround(),.flags=fetestexcept(FE_ALL_EXCEPT),.fpcr=0,.fpsr=0};
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ __volatile__("mrs %0, fpcr":"=r"(h.fpcr)::"memory");
    __asm__ __volatile__("mrs %0, fpsr":"=r"(h.fpsr)::"memory");
#endif
    return h;
}

static int same_host(host_t a,host_t b)
{return a.rc==b.rc&&a.flags==b.flags&&a.fpcr==b.fpcr&&a.fpsr==b.fpsr;}

static void install(hb_x87_state_t *x,unsigned p,const raw_t *v)
{
    memcpy(&x->st[p],&v->preview,8);put64(x->st_ext[p],v->sig);put16(x->st_ext[p]+8,v->se);
    x->st_ext_valid|=(uint8_t)(1u<<p);x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*p)))|(v->tag<<(2*p)));
}

static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}

static int seed_host(unsigned host,unsigned hf,const raw_t *input,unsigned group,unsigned im,unsigned occupied,unsigned host_ixc)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    int wanted=hf?(FE_INVALID|FE_DIVBYZERO):0;
    if(host_ixc)wanted|=FE_INEXACT;
    uint64_t magnitude=input->preview&UINT64_C(0x7fffffffffffffff);
    if(magnitude>UINT64_C(0x7ff0000000000000)||((group==EMPTY||occupied)&&im))wanted|=FE_INVALID;
    int ok=fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&(!wanted||feraiseexcept(wanted)==0);
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t fpsr;__asm__ __volatile__("mrs %0, fpsr":"=r"(fpsr)::"memory");
    fpsr&=~UINT64_C(0x80);__asm__ __volatile__("msr fpsr, %0"::"r"(fpsr):"memory");
#endif
    return check_kind(ok&&fegetround()==modes[host]&&fetestexcept(FE_ALL_EXCEPT)==wanted,"seed host RC/flags; explicit calibrated IXC only, no overflow/underflow/IDC preseed",HOST);
}
static void seed(fixture_t *f,const raw_t *input,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned hf,unsigned group,unsigned valid,unsigned im,unsigned occupied)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));memset(&c->x87_64,0x56,sizeof(c->x87_64));
    hb_x87_state_t *x=hb_context_x87(c);memset(x,0,sizeof(*x));x->top=(uint8_t)top;
    x->control_word=(uint16_t)(0x007fu|(pc<<8)|(rc<<10));
    x->status_word=(uint16_t)((top<<11)|0x0024u|((cc&7u)<<8)|((cc&8u)<<11)|(hf?0x80c0u:0));x->last_x87_ip=0x12345678;
    for(unsigned p=0;p<8;++p){raw_t v={0x4002,UINT64_C(0x8000000000000000)+p*UINT64_C(0x0800000000000000),UINT64_C(0x4020000000000000)+p*UINT64_C(0x0001000000000000),0};install(x,p,&v);}
    install(x,top,input);if(!valid)x->st_ext_valid&=(uint8_t)~(1u<<top);
    unsigned next=(top-1u)&7u,neighbor=(top+6u)&7u;
    if(!occupied)x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*next)))|(3u<<(2*next)));
    x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*neighbor)))|(3u<<(2*neighbor)));
    if(group==PENDING){x->control_word&=(uint16_t)~1u;x->status_word|=0x8081u;}
    if(group==OCCUPIED||group==EMPTY)x->control_word=(uint16_t)((x->control_word&~1u)|im);
    if(group==EMPTY)x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*top)))|(3u<<(2*top)));
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags.cf=(top&1)!=0;c->flags.pf=(rc&1)!=0;c->flags.af=true;c->flags.zf=(rc&2)!=0;c->flags.sf=true;c->flags.of=true;memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void expected_preview(hb_x87_state_t *x,unsigned phys,uint64_t bits,unsigned tag)
{
    memcpy(&x->st[phys],&bits,8);x->st_ext_valid&=(uint8_t)~(1u<<phys);
    x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*phys)))|(tag<<(2*phys)));
}
static void expected_top(hb_x87_state_t *x,unsigned top)
{x->top=(uint8_t)top;x->status_word=(uint16_t)((x->status_word&~0x3800u)|(top<<11));}
static unsigned expected_state(hb_context_t *expected,const raw_t *input,const legacy_t *legacy,unsigned group,unsigned im,unsigned occupied,unsigned *nan_phys)
{
    hb_x87_state_t *e=hb_context_x87(expected);unsigned top=e->top,next=(top-1u)&7u;*nan_phys=0;
    if(group==NORMAL){install(e,top,input);expected_top(e,next);install(e,next,&raw_cosine_one);e->status_word&=(uint16_t)~0x0400u;return 0;}
    if(group==EMPTY){
        e->status_word=(uint16_t)((e->status_word|0x0041u)&~0x0200u);
        if(!im){e->status_word|=0x8080u;return 1;}
        expected_preview(e,top,UINT64_C(0xfff8000000000000),2);
    }else expected_preview(e,top,legacy->sine_preview,legacy->sine_tag);
    if(occupied){
        e->status_word|=0x0241u;
        if(!im){e->status_word|=0x8080u;return 1;}
        expected_top(e,next);expected_preview(e,next,UINT64_C(0xfff8000000000000),2);
    }else{
        expected_top(e,next);
        if(group==EMPTY){expected_preview(e,next,UINT64_C(0x7ff8000000000000),2);*nan_phys|=1u<<next;}
        else expected_preview(e,next,legacy->cosine_preview,legacy->cosine_tag);
    }
    return 0;
}
static int preview_matches(const hb_x87_state_t *x,const hb_x87_state_t *e,unsigned phys,unsigned nan_phys)
{
    uint64_t actual,wanted;memcpy(&actual,&x->st[phys],8);memcpy(&wanted,&e->st[phys],8);
    int value=(nan_phys&(1u<<phys))?((actual&UINT64_C(0x7ff8000000000000))==UINT64_C(0x7ff8000000000000)):actual==wanted;
    return value&&((x->tag_word>>(2*phys))&3u)==((e->tag_word>>(2*phys))&3u);
}
static void check_state(fixture_t *f,const hb_context_t *before,hb_context_t *expected,unsigned nan_phys)
{
    hb_x87_state_t *e=hb_context_x87(expected),*x=hb_context_x87(f->ctx);unsigned top=hb_context_x87((hb_context_t*)before)->top,next=(top-1u)&7u;
    check_kind(!memcmp(x->st_ext[top],e->st_ext[top],10)&&!memcmp(x->st_ext[next],e->st_ext[next],10),"both output/partial-write physical raw80 payloads",RAW);
    check_kind(x->st_ext_valid==e->st_ext_valid,"complete raw-cache validity mask",RAW);
    int previews_ok=preview_matches(x,e,top,nan_phys)&&preview_matches(x,e,next,nan_phys);
    check_kind(previews_ok,"both previews/tags; only masked-empty pushed cosine may be a quiet NaN",RAW);
    check_kind(x->status_word==e->status_word,"exact TOP and inherited success/fault condition/sticky-bit policy",X87_STATUS);
    check_kind(!memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"integer flags and lazy state unchanged",INTEGER_FLAGS);
    for(unsigned p=0;p<8;++p)if(previews_ok&&(nan_phys&(1u<<p)))memcpy(&e->st[p],&x->st[p],8);
    e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"all physical x87 payload/cache/tag/control state and exact push ordering");
    if(f->ctx->arch==HB_ARCH_X86)expected->regs.x86.eip=f->ctx->regs.x86.eip;else expected->regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected->regs,sizeof(expected->regs)),"GPR/XMM and overlapping x86 x87 state");
    if(f->ctx->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state unchanged");
    check(f->ctx->mxcsr==before->mxcsr,"MXCSR unchanged");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks unchanged");
    check(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments unchanged");
}
/* Reviewed static migration rows; no production admission predicate.
 * IM=2 means either existing mask setting. Original data/loops remain. */
typedef struct {unsigned group;const char *name;unsigned cache,im;} migration_row_t;
static const migration_row_t migration_rows[]={
    {UNCACHED,"uncached_opposite_raw_positive_power_minus65",0u,2u},
    {UNCACHED,"uncached_opposite_raw_negative_power_minus65",0u,2u},
    {UNCACHED,"uncached_opposite_raw_positive_three_halves_minus65",0u,2u},
    {UNCACHED,"uncached_opposite_raw_negative_three_halves_minus65",0u,2u},
    {UNCACHED,"uncached_opposite_raw_positive_binary64_predecessor_power_minus64",0u,2u},
    {UNCACHED,"uncached_opposite_raw_negative_binary64_predecessor_power_minus64",0u,2u},
    {UPPER,"positive_excluded_upper_bound",1u,2u},
    {UPPER,"negative_excluded_upper_bound",1u,2u},
    {UPPER,"positive_excluded_above_upper_bound_low_bit",1u,2u},
    {UPPER,"negative_excluded_above_upper_bound_low_bit",1u,2u},
    {OCCUPIED,"positive_power_minus1200",1u,0u},
    {OCCUPIED,"positive_power_minus1200",1u,1u},
    {OCCUPIED,"positive_power_minus65",0u,0u},
    {OCCUPIED,"positive_power_minus65",0u,1u},
    {OCCUPIED,"positive_power_minus65",1u,0u},
    {OCCUPIED,"positive_power_minus65",1u,1u},
};
static bool migrated_row(unsigned group,const char *name,unsigned cache,unsigned im)
{
    for(unsigned i=0;i<sizeof(migration_rows)/sizeof(migration_rows[0]);++i){
        const migration_row_t *r=&migration_rows[i];
        if(r->group==group&&r->cache==cache&&(r->im==2u||r->im==im)&&!strcmp(r->name,name))return true;
    }
    return false;
}
static void run_case(fixture_t *f,const char *name,const raw_t *input,const legacy_t legacy[4],unsigned legacy_ixc,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned hf,unsigned group,unsigned valid,unsigned im,unsigned occupied)
{
    unsigned host=(rc+1u)&3u;
    bool migrated=migrated_row(group,name,valid,im);
    if(migrated)legacy_ixc=0;
    snprintf(phase,sizeof(phase),"%s %s %s TOP=%u CC=%u PC=%u RC=%u host=%u flags=%u group=%u cache=%u IM=%u nextoccupied=%u",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",name,top,cc,pc,rc,host,hf,group,valid,im,occupied);
    seed(f,input,top,cc,pc,rc,hf,group,valid,im,occupied);hb_context_t before,expected;memcpy(&before,f->ctx,sizeof(before));memcpy(&expected,&before,sizeof(expected));
    unsigned nan_phys=0,fault=expected_state(&expected,input,&legacy[host],group,im,occupied,&nan_phys);
    /* Component-backed numbers; guest transport/state is modeled independently.
     * Evaluate before host seeding, retaining every measured-call assertion. */
    if(migrated){
        gt_reference transport;
        if(!check(gt_transport_reference(hb_context_x87(&before),hb_context_x87(&expected),
                                         HB_X87_TRANS_FSINCOS,&transport),
                  "reviewed static-row component transport reference"))return;
        fault=transport.expected_return!=HB_OK;
        nan_phys=0;
    }
    if(!seed_host(host,hf,input,group,im,occupied,(group==NORMAL||group==EMPTY)?0:legacy_ixc))return;
    host_t wanted=host_state();hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);host_t actual=host_state();
    ++executions;++group_calls[group];check_kind(same_host(wanted,actual),"host RC/status and full ARM FPCR/FPSR unchanged",HOST);
    if(fault)check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"legacy unmasked stack fault at its original mutation boundary",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+2,"single FSINCOS completes and pushes once",EXECUTION);
    check_state(f,&before,&expected,nan_phys);
}
static void check_ir(fixture_t *f)
{
    unsigned count=0;if(!check_kind(f->func->cfg!=NULL,"IR container present",DECODE))return;
    for(size_t b=0;b<f->func->cfg->block_count;++b){hb_ir_block_t *block=f->func->cfg->blocks[b];for(size_t i=0;i<block->instr_count;++i){hb_ir_instr_t *ir=&block->instrs[i];if(ir->op!=HB_IR_X87_FSINCOS)continue;++count;check_kind(ir->guest_addr==CODE,"FSINCOS IR source address; unused operands not asserted",DECODE);}}
    check_kind(count==1,"exactly one implicit ST0 FSINCOS IR",DECODE);
}
static void run_form(hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create reusable FSINCOS context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,CODE,instruction,2)==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned two-byte FSINCOS"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(instruction,2,CODE,&d):hb_decode_x64(instruction,2,CODE,&d);
    if(!check_kind(result==HB_OK&&d.len==2&&d.opcode==HB_INS_X87_FSINCOS,"decode actual FSINCOS opcode",DECODE))goto done;
    check_kind(!d.op1.present,"decoded FSINCOS implicit ST0",DECODE);
    f.decoder=hb_decoder_create(arch,instruction,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift FSINCOS",EXECUTION))goto done;
    check_ir(&f);if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create guest runtime"))goto done;
    for(unsigned s=0;s<24;++s)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned pc=0;pc<4;++pc)for(unsigned rc=0;rc<4;++rc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&normals[s];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,pc,rc,hf,NORMAL,1,1,0);}
    if(f.jit)check_kind(native_present(&f),"admitted FSINCOS native entry exists before controls",EXECUTION);
    for(unsigned s=0;s<8;++s)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&uncached[s];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,3,cc&3u,hf,UNCACHED,0,1,0);}
    for(unsigned s=0;s<12;++s)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&excluded[s];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,3,cc&3u,hf,EXCLUDED,1,1,0);}
    for(unsigned s=0;s<4;++s)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&lower[s];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,3,cc&3u,hf,LOWER,1,1,0);}
    for(unsigned s=0;s<4;++s)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&upper[s];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,3,cc&3u,hf,UPPER,1,1,0);}
    for(unsigned i=0;i<4;++i)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&normals[pending_samples[i]];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,3,cc&3u,hf,PENDING,1,0,0);}
    for(unsigned i=0;i<2;++i)for(unsigned valid=0;valid<2;++valid)for(unsigned im=0;im<2;++im)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&normals[occupied_samples[i]];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,3,cc&3u,hf,OCCUPIED,valid,im,1);}
    for(unsigned i=0;i<2;++i)for(unsigned valid=0;valid<2;++valid)for(unsigned im=0;im<2;++im)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf){const sample_t *v=&normals[empty_samples[i]];
        run_case(&f,v->name,&v->input,v->legacy,v->legacy_ixc,top,cc,3,cc&3u,hf,EMPTY,valid,im,0);}
    uint8_t actual[2];check(hb_memory_read(f.ctx->memory,CODE,actual,2)==HB_OK&&!memcmp(actual,instruction,2),"code unchanged");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.ctx)hb_context_destroy(f.ctx);
}
static const struct{const char *name;enum hb_gate_id id;const char *value;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM,"0"},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR,"0"},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64,"0"},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS,"0"},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED,"0"},{"MACRUNNER_HB_UNCHAIN_STATS",HB_GATE_HB_UNCHAIN_STATS,"0"}};
int main(void)
{
    host_t caller=host_state();char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *s=getenv(gates[i].name);if(s&&!check((saved[i]=strdup(s))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,gates[i].value,1)==0,"select helper gate"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);if(!check(s&&!strcmp(s,gates[i].value),"effective gate"))goto done;}
    if(!check(fegetenv(&original)==0,"save caller fenv"))goto done;host_saved=1;fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host traps"))goto done;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)run_form(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
    check(executions==442368u&&group_calls[NORMAL]==393216u&&group_calls[UNCACHED]==8192u&&group_calls[EXCLUDED]==12288u&&group_calls[LOWER]==4096u&&group_calls[UPPER]==4096u&&group_calls[PENDING]==4096u&&group_calls[OCCUPIED]==8192u&&group_calls[EMPTY]==8192u,"planned actual guest partitions");
done:
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_cached_tiny_fsincos_test: %u executions (%u normal, %u uncached, %u excluded, %u lower, %u upper, %u pending, %u occupied, %u empty), %u checks, %u failures\n",executions,group_calls[NORMAL],group_calls[UNCACHED],group_calls[EXCLUDED],group_calls[LOWER],group_calls[UPPER],group_calls[PENDING],group_calls[OCCUPIED],group_calls[EMPTY],checks,failures);
    printf("failure categories: raw=%u x87_status=%u integer_flags=%u state=%u execution=%u host=%u decode=%u\n",category_failures[RAW],category_failures[X87_STATUS],category_failures[INTEGER_FLAGS],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[DECODE]);
    if(host_saved&&fesetenv(&original)!=0)return 2;
    if(!same_host(caller,host_state()))return 2;
    return failures?1:0;
}
