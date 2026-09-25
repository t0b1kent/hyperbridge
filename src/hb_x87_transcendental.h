/* Private numerical adapter. Guest stack access and exception delivery stay
 * with the caller. This component has no dependency on the FEX runtime. */
#ifndef HB_X87_TRANSCENDENTAL_H
#define HB_X87_TRANSCENDENTAL_H
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    HB_X87_TRANS_F2XM1,
    HB_X87_TRANS_FYL2X,
    HB_X87_TRANS_FYL2XP1,
    HB_X87_TRANS_FPATAN,
    HB_X87_TRANS_FSIN,
    HB_X87_TRANS_FCOS,
    HB_X87_TRANS_FSINCOS,
    HB_X87_TRANS_FPTAN,
    HB_X87_TRANS_FSCALE
} hb_x87_transcendental_op_t;

typedef struct {
    /* Primary result first. FSINCOS adds cosine; FPTAN adds positive one.
     * The caller replaces the original destination before attempting a push. */
    uint8_t raw[2][10];
    uint8_t result_count;
    uint8_t component_flags; /* Outer SoftFloat flags, for diagnostics. */
    uint16_t status_set;    /* Selected donor fallback propagates invalid only. */
    uint16_t status_clear;  /* Selected instruction's condition-bit policy. */
} hb_x87_transcendental_result_t;

/* Inputs are guest ST(0) and ST(1), as ten little-endian bytes, including
 * special encodings. ST(1) is required only by FYL2X, FYL2XP1, FPATAN, FSCALE.
 * All operations use full ext80 precision and the FCW rounding mode. The
 * component preserves the selected library's numerical behavior, including
 * its documented limitations; it is not a full x87 exception implementation.
 * No guest state or host floating environment is accessed. Output may alias
 * either input; invalid arguments return false without modifying output. */
bool hb_x87_transcendental(hb_x87_transcendental_op_t operation,
                           const uint8_t st0[10], const uint8_t st1[10],
                           uint16_t control_word,
                           hb_x87_transcendental_result_t* output);
#endif
