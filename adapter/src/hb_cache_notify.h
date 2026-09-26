#ifndef HB_CACHE_NOTIFY_H
#define HB_CACHE_NOTIFY_H

#include <stdint.h>
#include "hb_runtime.h"

enum hb_cache_notification
{
    HB_CACHE_FLUSH,
    HB_CACHE_DIRTY,
    HB_CACHE_MAP,
    HB_CACHE_ALLOC,
    HB_CACHE_PROTECT,
    HB_CACHE_FREE,
    HB_CACHE_UNMAP,
    HB_CACHE_READ
};

static inline int hb_cache_notify_should_publish(enum hb_cache_notification event,
                                                int is_post, int32_t status)
{
    switch (event)
    {
    case HB_CACHE_FLUSH:
    case HB_CACHE_DIRTY:
        return 1;
    case HB_CACHE_READ:
        /* A failed read can still have modified part of its destination. */
        return !!is_post;
    case HB_CACHE_MAP:
    case HB_CACHE_ALLOC:
    case HB_CACHE_PROTECT:
    case HB_CACHE_FREE:
    case HB_CACHE_UNMAP:
        return is_post && status == 0;
    default:
        return 0;
    }
}

/* Claude, 25.09.2026: узкий сброс. Ядро накрывает запись без отпечатка верхней оценкой её
 * байтов (hb_jit_invalidate_guest_range, HB_INVAL_MAX_BLOCK), поэтому объявлять диапазон
 * безопасно: блок, задевающий [start, start+len), будет выселен. len == 0 — сброс всего. */
static inline int hb_cache_notify_publish_range(enum hb_cache_notification event,
                                               int is_post, int32_t status,
                                               uint64_t start, uint64_t len)
{
    if (!hb_cache_notify_should_publish(event, is_post, status)) return 0;
    /* Opus 26.09.2026: вид события передаётся в ядро для учёта выселений по видам. */
    if (!len || start > UINT64_MAX - len)
        (void)hb_jit_invalidate_guest_range_all_why(NULL, 0, UINT64_MAX, (uint32_t)event);
    else
        (void)hb_jit_invalidate_guest_range_all_why(NULL, start, len, (uint32_t)event);
    return 1;
}

static inline int hb_cache_notify_publish(enum hb_cache_notification event,
                                         int is_post, int32_t status)
{
    if (!hb_cache_notify_should_publish(event, is_post, status)) return 0;
    /* RX/unknown entries do not retain a complete byte span in the current
     * core. A narrow invalidation could miss an interior instruction byte.
     * Conservatively publish a full range, including NULL/zero-size flushes.
     * No callback frees its own or another thread's potentially active code:
     * every runtime consumes this publication at its next safe API entry. */
    (void)hb_jit_invalidate_guest_range_all_why(NULL, 0, UINT64_MAX, (uint32_t)event);
    return 1;
}

#endif
