/* Windows x64 code uses the canonical shared-user-data address. Wine on
 * Apple ARM64 stores the live read-only page at a different native address.
 * This independent range planner never redirects writes or partial spans.
 */
#ifndef HB_GUEST_SHARED_H
#define HB_GUEST_SHARED_H
#include <stddef.h>
#include <stdint.h>

static inline int hb_guest_shared_read_address(uint64_t guest, size_t size,
                                               uint64_t native_base, uint64_t *out)
{
    const uint64_t base = UINT64_C(0x7ffe0000), length = UINT64_C(0x1000);
    uint64_t offset;
    if (!out || !size || guest < base) return 0;
    offset = guest - base;
    if (offset >= length || size > length - offset ||
        native_base > UINT64_MAX - offset ||
        size - 1 > UINT64_MAX - (native_base + offset)) return 0;
    *out = native_base + offset;
    return 1;
}

#endif
