#ifndef HB_TRANSIT_H
#define HB_TRANSIT_H

#include <stdbool.h>
#include <stdint.h>

/* A direct edge is one patchable B, followed by unreachable metadata.
 * The cold branch skips the metadata and materializes PC normally. The hot
 * branch goes to the successor's body. Keeping the literal in the blob makes
 * edge discovery work for persistent-cache loads as well as fresh code. */
#define HB_TRANSIT_COLD_BRANCH 0x14000005u /* b .+20; verified with clang */
#define HB_TRANSIT_SLOT_BYTES  20u

/* Metadata is encoded as four harmless MOVZ XZR instructions, not opaque
 * data. Linear native scanners (SRA fault veto, register/dead-flag analysis)
 * must never mistake a guest-address literal for a load/store or a helper. */
static inline uint32_t hb_transit_word(uint64_t guest, unsigned part) {
    return 0xd280001fu | (part << 21) |
           ((uint32_t)((guest >> (part * 16)) & 0xffffu) << 5);
}

static inline bool hb_transit_decode(const uint32_t words[5], uint64_t* guest) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 4; i++) {
        if ((words[i + 1] & 0xffe0001fu) != (0xd280001fu | (i << 21))) return false;
        value |= (uint64_t)((words[i + 1] >> 5) & 0xffffu) << (i * 16);
    }
    if (guest) *guest = value;
    return true;
}

#endif
