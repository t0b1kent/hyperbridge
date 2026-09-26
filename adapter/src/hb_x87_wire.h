#ifndef HB_X87_WIRE_H
#define HB_X87_WIRE_H

#include <stddef.h>
#include <stdint.h>

/* Physical x87 slots, matching the ARM64EC raw-register overlay. This is not
 * an FXSAVE image: FXSAVE orders payloads relative to TOP. No borrowed pointers. */
#define HB_X87_WIRE_VERSION 1u
#define HB_X87_WIRE_IMPORT 1u
#define HB_X87_WIRE_EXPORT 2u
struct hb_x87_wire
{
    uint32_t struct_size;
    uint32_t version;
    uint32_t operation;
    uint32_t reserved;
    uint16_t control_word;
    uint16_t status_word;
    uint8_t abridged_tag;
    uint8_t reserved_metadata[3];
    uint8_t physical[8][16]; /* Ten payload bytes, six zero reserved bytes. */
};

static inline int hb_x87_wire_valid( const struct hb_x87_wire *value )
{
    unsigned int i, j;
    if (!value || value->struct_size != sizeof(*value) ||
        value->version != HB_X87_WIRE_VERSION ||
        (value->operation != HB_X87_WIRE_IMPORT && value->operation != HB_X87_WIRE_EXPORT) ||
        value->reserved) return 0;
    for (i = 0; i < 3; ++i) if (value->reserved_metadata[i]) return 0;
    for (i = 0; i < 8; ++i)
        for (j = 10; j < 16; ++j) if (value->physical[i][j]) return 0;
    return 1;
}

_Static_assert(sizeof(struct hb_x87_wire) == 152, "fixed x87 transfer size");
_Static_assert(offsetof(struct hb_x87_wire, physical) == 24, "fixed raw offset");
#endif
