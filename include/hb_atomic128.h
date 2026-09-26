#ifndef HB_ATOMIC128_H
#define HB_ATOMIC128_H

#include "hb_flags.h"
#include "hb_memory.h"

/* Both execution backends share the provider commit rule. The caller resolves
 * the effective address and checks architectural alignment before entry. */
static inline hb_result_t hb_atomic128_exec_provider(hb_context_t* ctx, hb_gva_t addr) {
    uint64_t expected[2] = {hb_context_read_reg_value(ctx, HB_REG_RAX),
                            hb_context_read_reg_value(ctx, HB_REG_RDX)};
    uint64_t desired[2] = {hb_context_read_reg_value(ctx, HB_REG_RBX),
                           hb_context_read_reg_value(ctx, HB_REG_RCX)};
    uint64_t observed[2];
    bool exchanged;
    hb_result_t r = hb_memory_atomic_cmpxchg128(ctx->memory, addr, expected, desired,
                                              observed, &exchanged);
    if (r != HB_OK) return r;
    if (!exchanged) {
        hb_context_write_reg_value_sized(ctx, HB_REG_RAX, observed[0], HB_SIZE_64);
        hb_context_write_reg_value_sized(ctx, HB_REG_RDX, observed[1], HB_SIZE_64);
    }
    /* Only ZF changes. Do not discard the pending producer of CF/PF/AF/SF/OF,
     * including any already-materialized or unsupported status for those bits.
     * Mark ZF materialized so later evaluation cannot resurrect its old value. */
    if (ctx->lazy_flags.pending) {
        ctx->lazy_flags.valid_mask |= HB_FLAG_BIT_ZF;
        ctx->lazy_flags.unsupported_mask &= ~(uint32_t)HB_FLAG_BIT_ZF;
        ctx->lazy_flags.materialized_mask |= HB_FLAG_BIT_ZF;
    }
    ctx->flags.zf = exchanged;
    return HB_OK;
}

#endif /* HB_ATOMIC128_H */
