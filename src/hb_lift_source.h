#ifndef HB_LIFT_SOURCE_H
#define HB_LIFT_SOURCE_H

#include "hb_gates.h"

/* Freeze before decoding, not afterwards: a post-decode copy could describe
 * bytes different from those that produced the IR. The input API already
 * requires code_len readable bytes. Keep the bounded optimization optional;
 * allocation failure and larger/custom decoder windows use legacy tracking.
 * Both lifters decode linearly; even zero-IR instructions and a failed final
 * decode remain covered by the consumed prefix. No optimizer can shrink it. */
static const uint8_t* hb_lift_source_begin(hb_ir_func_t* func, hb_decoder_t* dec) {
    const uint8_t* original = dec->code;
    if (!hb_gate_flag(HB_GATE_HB_DECODED_SOURCE, 0) || !original ||
        dec->pos || !dec->code_len || dec->code_len > 4096 ||
        dec->base_addr > UINT64_MAX - dec->code_len)
        return original;
    uint8_t* copy = malloc(dec->code_len);
    if (!copy) return original;
    memcpy(copy, original, dec->code_len);
    func->decoded_source = copy;
    dec->code = copy;
    return original;
}

static void hb_lift_source_end(hb_ir_func_t* func, hb_decoder_t* dec,
                               const uint8_t* original) {
    dec->code = original;
    if (!func->decoded_source) return;
    if (!dec->pos || dec->pos > dec->code_len) {
        free(func->decoded_source);
        func->decoded_source = NULL;
        return;
    }
    func->decoded_source_len = dec->pos;
    uint8_t* compact = realloc(func->decoded_source, dec->pos);
    if (compact) func->decoded_source = compact;
}

#endif
