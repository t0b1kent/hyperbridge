/* Private exact-result bridge to the independently retained SoftFloat component. */
#ifndef HB_X87_EXACT_H
#define HB_X87_EXACT_H
#include <stdbool.h>
#include <stdint.h>

/* Returns false without writing output unless inputs and output are canonical
 * normal/zero ext80 values and the selected guest precision produces no flags.
 * This helper neither reads nor changes the host floating-point environment. */
bool hb_x87_exact_addsub(const uint8_t lhs[10], const uint8_t rhs[10],
                        uint16_t control_word, bool subtract, uint8_t output[10]);

/* The same exact-result contract; divide selects lhs/rhs, otherwise lhs*rhs.
 * A zero divisor is declined without calling the component or writing output. */
bool hb_x87_exact_muldiv(const uint8_t lhs[10], const uint8_t rhs[10],
                        uint16_t control_word, bool divide, uint8_t output[10]);

typedef struct {
    uint8_t raw[10];
    uint16_t status_bits; /* Guest PE/C1 only; exact success returns zero. */
} hb_x87_finite_result_t;

/* Admit the same exact results, or a masked precision-only normal result.
 * Both guest-RC and truncation results must be normal for the precision path.
 * False leaves the whole result untouched. Inputs may alias result->raw.
 * The caller commits raw bytes, then clears C1 and ORs status_bits into SW.
 * No host floating-point environment or guest state is accessed here. */
bool hb_x87_finite_addsub(const uint8_t lhs[10], const uint8_t rhs[10],
                         uint16_t control_word, bool subtract,
                         hb_x87_finite_result_t* result);
bool hb_x87_finite_muldiv(const uint8_t lhs[10], const uint8_t rhs[10],
                         uint16_t control_word, bool divide,
                         hb_x87_finite_result_t* result);

/* Square root of a positive canonical normal or either canonical signed zero.
 * Exact normal/zero results are admitted for either PM value; precision-only
 * normal results require PM and normal guest-RC/toward-zero trials.
 * Negative nonzero and other input classes are declined. The same untouched
 * output, raw-input alias and no-host/guest-state contract above applies. */
bool hb_x87_finite_sqrt(const uint8_t input[10], uint16_t control_word,
                       hb_x87_finite_result_t* result);
#endif
