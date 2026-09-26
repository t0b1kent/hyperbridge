#ifndef HB_CAS128_POLICY_H
#define HB_CAS128_POLICY_H

#include <stdint.h>

/* Both intervals use exclusive ends. No pointer dereference or VM assumption. */
static inline int hb_cas128_span_has_access(uint64_t addr, uint64_t base,
                                          uint64_t size, uint32_t have,
                                          uint32_t need)
{
    if (!need || !size || addr > UINT64_MAX - 16 || base > UINT64_MAX - size)
        return 0;
    if (size < 16 || addr < base || addr - base > size - 16) return 0;
    return (have & need) == need;
}

#endif
