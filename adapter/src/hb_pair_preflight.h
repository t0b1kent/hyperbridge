#ifndef HB_PAIR_PREFLIGHT_H
#define HB_PAIR_PREFLIGHT_H

#include <stdint.h>
#include <stddef.h>

/* Non-consuming query result, never a lease or a substitute for the actual
 * memory operation. Boolean fields describe authoritative Wine VM metadata. */
struct hb_pair_page_view
{
    uint64_t base;
    uint64_t size;
    unsigned committed, readable, writable, guard;
};
typedef int (*hb_pair_page_query_fn)(void *, uint64_t, struct hb_pair_page_view *);
enum hb_pair_preflight_result
{
    HB_PAIR_PREFLIGHT_OK,
    HB_PAIR_PREFLIGHT_GUARD,
    HB_PAIR_PREFLIGHT_WRITE_FAULT,
    HB_PAIR_PREFLIGHT_UNSUPPORTED
};

/* Guard takes precedence over RO on its page. An earlier inaccessible page
 * still faults first. Only GUARD/WRITE_FAULT write the returned address.
 * Pair8 may straddle pages for ordinary access; guard transport remains one
 * Windows page. Pair16 alignment is checked by the core before this callback. */
static inline enum hb_pair_preflight_result hb_pair_preflight(
    uint64_t address, size_t size, hb_pair_page_query_fn query, void *user,
    uint64_t *failure_address )
{
    uint64_t cursor = address, end;
    if (!query || !failure_address || (size != 8 && size != 16))
        return HB_PAIR_PREFLIGHT_UNSUPPORTED;
    if (address > UINT64_MAX - (size - 1))
    {
        *failure_address = address;
        return HB_PAIR_PREFLIGHT_WRITE_FAULT;
    }
    end = address + size - 1;
    for (;;)
    {
        struct hb_pair_page_view view = {0};
        uint64_t available;
        if (!query( user, cursor, &view ) || !view.size ||
            view.size - 1 > UINT64_MAX - view.base || cursor < view.base ||
            cursor - view.base >= view.size || !view.committed)
        {
            *failure_address = cursor;
            return HB_PAIR_PREFLIGHT_WRITE_FAULT;
        }
        if (view.guard)
        {
            if ((address >> 12) != (end >> 12)) return HB_PAIR_PREFLIGHT_UNSUPPORTED;
            *failure_address = address;
            return HB_PAIR_PREFLIGHT_GUARD;
        }
        if (!view.readable || !view.writable)
        {
            *failure_address = cursor;
            return HB_PAIR_PREFLIGHT_WRITE_FAULT;
        }
        available = view.size - (cursor - view.base);
        if (available > end - cursor) return HB_PAIR_PREFLIGHT_OK;
        cursor += available; /* at most end: no wrap and strict progress */
    }
}

#endif
