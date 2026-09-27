#ifndef HB_NATIVE_ENTRY_WITNESS_H
#define HB_NATIVE_ENTRY_WITNESS_H

#include "hb_codegen.h"
#include "hb_memory.h"
#include "hb_code_witness_v1.h"

#define HB_NATIVE_ENTRY_MAX_LOAD_SITES 5u
/* Runtime-owned. Immutable after publication except release-store live=0.
 * Retired descriptors survive until an owner-thread quiescent cache reset.
 * Native code and external native pointers are invalid after that reset. */
struct hb_native_entry_descriptor {
    struct hb_native_entry_descriptor *next;
    void *owner;
    hb_memory_t *memory;
    uint64_t guest_pc, span_start;
    size_t span_len, allocation_size;
    uint32_t live, page_count;
    const hb_code_page_witness_v1 *pages[2];
    uint64_t expected[2];
    const uint64_t *invalidation_current;
    const uint64_t *invalidation_seen;
    hb_context_t *const *context_slot;
    uintptr_t native_start;
    size_t native_size;
    uint32_t prefix_size;
    uint32_t load_offsets[HB_NATIVE_ENTRY_MAX_LOAD_SITES];
    uint8_t load_widths[HB_NATIVE_ENTRY_MAX_LOAD_SITES];
    uint8_t load_count;
    uint64_t emitted_hash;
    uint8_t bytes[];
};

#endif
