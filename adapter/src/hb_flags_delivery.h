#ifndef HB_FLAGS_DELIVERY_H
#define HB_FLAGS_DELIVERY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

/* Owned synchronous exception DELIVERY, not continuation.
 * One state belongs to one thread for its entire lifetime. No dispatcher-stack
 * pointer is retained. Callers pass value copies made from valid contexts.
 * These atomics prevent reentrant Reset from publishing a partial snapshot;
 * they do not authorize concurrent access to another thread's state. */
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "delivery phase must be lock-free");
#define HB_FLAGS_DELIVERY_MISSING UINT32_C(0x414) /* PF, AF, DF */
#define HB_FLAGS_DELIVERY_PARAMETERS 15u
enum { HB_FD_IDLE, HB_FD_WRITING, HB_FD_READY, HB_FD_READING, HB_FD_CANCELLED };

typedef struct {
    uint64_t pc, sp, address;
    uint64_t parameters[HB_FLAGS_DELIVERY_PARAMETERS];
    uint32_t code, exception_flags, parameter_count;
    bool has_chained_record;
} hb_flags_delivery_event;

typedef struct {
    uint64_t owner; /* Stable thread identity, initialized before publication. */
    uint64_t serial, ticket;
    atomic_uint phase;
    uint32_t missing;
    hb_flags_delivery_event event;
} hb_flags_delivery;

static inline void hb_flags_delivery_init(hb_flags_delivery *s, uint64_t owner)
{
    *s = (hb_flags_delivery){0};
    s->owner = owner;
    atomic_init(&s->phase, HB_FD_IDLE);
}

static inline bool hb_flags_delivery_event_valid(const hb_flags_delivery_event *e)
{
    return e && e->pc && e->sp && e->code && e->address == e->pc &&
           !e->has_chained_record && e->parameter_count <= HB_FLAGS_DELIVERY_PARAMETERS;
}

/* Any unexpected same-thread Reset consumes the opportunity. A Reset while a
 * snapshot is being written/read invalidates that in-progress operation. */
static inline void hb_flags_delivery_invalidate(hb_flags_delivery *s)
{
    unsigned phase = atomic_load_explicit(&s->phase, memory_order_acquire);
    while (phase != HB_FD_IDLE && phase != HB_FD_CANCELLED) {
        unsigned next = phase == HB_FD_READY ? HB_FD_IDLE : HB_FD_CANCELLED;
        if (atomic_compare_exchange_strong_explicit(&s->phase, &phase, next,
                memory_order_acq_rel, memory_order_acquire)) return;
    }
}

static inline uint64_t hb_flags_delivery_arm(hb_flags_delivery *s, uint64_t owner,
                                             const hb_flags_delivery_event *e,
                                             uint32_t committed_flags)
{
    unsigned phase = HB_FD_IDLE;
    if (!s || !owner || s->owner != owner) return 0;
    if (!hb_flags_delivery_event_valid(e)) {
        hb_flags_delivery_invalidate(s);
        return 0;
    }
    if (!atomic_compare_exchange_strong_explicit(&s->phase, &phase, HB_FD_WRITING,
            memory_order_acq_rel, memory_order_acquire)) {
        hb_flags_delivery_invalidate(s); /* Ambiguous overlapping raise. */
        return 0;
    }
    if (s->serial == UINT64_MAX) {
        atomic_store_explicit(&s->phase, HB_FD_IDLE, memory_order_release);
        return 0; /* Never recycle a stale cancellation ticket. */
    }
    uint64_t ticket = ++s->serial;
    s->ticket = ticket;
    s->event = *e;
    s->missing = committed_flags & HB_FLAGS_DELIVERY_MISSING;
    phase = HB_FD_WRITING;
    if (!atomic_compare_exchange_strong_explicit(&s->phase, &phase, HB_FD_READY,
            memory_order_release, memory_order_relaxed)) {
        atomic_store_explicit(&s->phase, HB_FD_IDLE, memory_order_release);
        return 0;
    }
    return ticket;
}

static inline bool hb_flags_delivery_same(const hb_flags_delivery_event *a,
                                          const hb_flags_delivery_event *b)
{
    if (a->pc != b->pc || a->sp != b->sp || a->address != b->address ||
        a->code != b->code || a->exception_flags != b->exception_flags ||
        a->parameter_count != b->parameter_count || a->has_chained_record != b->has_chained_record)
        return false;
    for (unsigned i = 0; i < a->parameter_count; ++i)
        if (a->parameters[i] != b->parameters[i]) return false;
    return true;
}

/* Call only from Reset before invoking any guest handler. Preserve every
 * incoming bit except the three known lost bits, including debugger edits to
 * CF/ZF/SF/TF/OF and control/reserved bits. Do not modify ARM CPSR here. */
static inline bool hb_flags_delivery_consume(hb_flags_delivery *s, uint64_t owner,
        const hb_flags_delivery_event *e, uint64_t arm_pc, uint64_t arm_sp,
        bool amd64_control_present, uint32_t *incoming_flags)
{
    unsigned phase = HB_FD_READY;
    if (!s || !owner || s->owner != owner) return false;
    if (!incoming_flags || !amd64_control_present || !hb_flags_delivery_event_valid(e)) {
        hb_flags_delivery_invalidate(s);
        return false;
    }
    if (!atomic_compare_exchange_strong_explicit(&s->phase, &phase, HB_FD_READING,
            memory_order_acq_rel, memory_order_acquire)) {
        hb_flags_delivery_invalidate(s);
        return false;
    }
    bool match = arm_pc == s->event.pc && arm_sp == s->event.sp &&
                 hb_flags_delivery_same(&s->event, e);
    uint32_t missing = s->missing;
    phase = HB_FD_READING;
    if (!atomic_compare_exchange_strong_explicit(&s->phase, &phase, HB_FD_IDLE,
            memory_order_acq_rel, memory_order_acquire)) {
        atomic_store_explicit(&s->phase, HB_FD_IDLE, memory_order_release);
        return false;
    }
    if (!match) return false; /* Already consumed; no delayed contamination. */
    *incoming_flags = (*incoming_flags & ~HB_FLAGS_DELIVERY_MISSING) | missing;
    return true;
}

/* NtRaiseException returning is failure, not the normal continuation path.
 * Cancel only this raise's ticket; stale cleanup must not consume a nested one. */
static inline bool hb_flags_delivery_cancel(hb_flags_delivery *s, uint64_t owner,
                                           uint64_t ticket)
{
    unsigned phase = HB_FD_READY;
    if (!s || !owner || !ticket || s->owner != owner) return false;
    if (!atomic_compare_exchange_strong_explicit(&s->phase, &phase, HB_FD_READING,
            memory_order_acq_rel, memory_order_acquire)) return false;
    bool match = s->ticket == ticket;
    phase = HB_FD_READING;
    if (!atomic_compare_exchange_strong_explicit(&s->phase, &phase,
            match ? HB_FD_IDLE : HB_FD_READY, memory_order_acq_rel, memory_order_acquire)) {
        atomic_store_explicit(&s->phase, HB_FD_IDLE, memory_order_release);
        return false;
    }
    return match;
}
#endif
