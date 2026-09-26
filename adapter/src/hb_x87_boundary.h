#ifndef HB_X87_BOUNDARY_H
#define HB_X87_BOUNDARY_H

#include <string.h>
#include "hb_x87.h"
#include "hb_x87_wire.h"

/* Stage the entire state so rejected transfers leave both arguments unchanged.
 * TOP is taken from the incoming status, never normalized to the test's TOP. */
static inline hb_result_t hb_x87_boundary_import( hb_x87_state_t *state,
                                                const struct hb_x87_wire *value )
{
    hb_x87_state_t next;
    unsigned int physical;
    if (!state || !hb_x87_wire_valid(value) || value->operation != HB_X87_WIRE_IMPORT)
        return HB_ERR_INVALID_ARG;
    next = *state;
    next.control_word = value->control_word;
    next.status_word = value->status_word;
    next.top = (value->status_word >> 11) & 7;
    for (physical = 0; physical < 8; ++physical)
    {
        unsigned int logical = (physical + 8 - next.top) & 7;
        hb_result_t result = hb_x87_set_st_ext80(&next, logical, value->physical[physical],
                                               !!(value->abridged_tag & (1u << physical)));
        if (result != HB_OK) return result;
    }
    *state = next;
    return HB_OK;
}

static inline hb_result_t hb_x87_boundary_export( const hb_x87_state_t *state,
                                                struct hb_x87_wire *value )
{
    struct hb_x87_wire next;
    unsigned int physical;
    if (!state || state->top > 7 || !hb_x87_wire_valid(value) ||
        value->operation != HB_X87_WIRE_EXPORT) return HB_ERR_INVALID_ARG;
    next = *value;
    next.control_word = state->control_word;
    next.status_word = (state->status_word & ~0x3800u) | ((uint16_t)state->top << 11);
    next.abridged_tag = 0;
    memset(next.physical, 0, sizeof(next.physical));
    for (physical = 0; physical < 8; ++physical)
    {
        unsigned int logical = (physical + 8 - state->top) & 7;
        hb_result_t result;
        if (((state->tag_word >> (physical * 2)) & 3) != 3)
            next.abridged_tag |= 1u << physical;
        result = hb_x87_save_st_ext80(state, logical, next.physical[physical]);
        if (result != HB_OK) return result;
    }
    *value = next;
    return HB_OK;
}
#endif
