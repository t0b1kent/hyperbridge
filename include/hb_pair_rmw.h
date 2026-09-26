#ifndef HB_PAIR_RMW_H
#define HB_PAIR_RMW_H

#include "hb_flags.h"
#include "hb_ir.h"

static inline bool hb_ir_pair_rmw(const hb_ir_instr_t* instr) {
    return instr && instr->op == HB_IR_CMPXCHG8B && instr->dst.type == HB_OP_MEM &&
           (instr->dst.size == HB_SIZE_64 || instr->dst.size == HB_SIZE_128);
}

static inline void hb_pair_rmw_end(hb_context_t* ctx) {
    if (!ctx) return;
    ctx->pair_rmw_active = false;
    ctx->pair_rmw_address = 0;
    ctx->pair_rmw_size = 0;
}

/* Caller has resolved EA using original registers. No guest memory is touched
 * until this function returns HB_OK. Alignment outranks observation for CX16. */
static inline hb_result_t hb_pair_rmw_begin(hb_context_t* ctx,
                                           const hb_ir_instr_t* instr,
                                           hb_gva_t addr) {
    hb_result_t r = HB_OK;
    size_t size = instr->dst.size == HB_SIZE_128 ? 16 : 8;
    hb_pair_rmw_end(ctx);
    if (size == 16 && (addr & 15u))
        r = hb_fault_general_protection(ctx, instr->guest_addr);
    else if (ctx->pair_access && ctx->mode == HB_MODE_64BIT &&
             addr <= UINT64_MAX - (size - 1)) {
        r = ctx->pair_access(ctx->pair_access_user, instr->guest_addr, addr, size, 1);
        size_t page = ctx->pair_access_page_size;
        if (r == HB_ERR_ACCESS_PENDING &&
            (!page || size > page || (addr & (page - 1)) > page - size))
            r = HB_ERR_UNSUPPORTED_FEATURE;
    }
    if (r != HB_OK) {
        ctx->pc = instr->guest_addr;
        if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eip = (uint32_t)ctx->pc;
        else ctx->regs.x64.rip = ctx->pc;
        ctx->last_result = r;
        return r;
    }
    ctx->pair_rmw_address = addr;
    ctx->pair_rmw_size = size;
    ctx->pair_rmw_active = true;
    return HB_OK;
}

/* CMPXCHG8B/16B change only ZF. Preserve pending producers of all other flags,
 * and prevent a later lazy evaluation from resurrecting the previous ZF. */
static inline void hb_pair_rmw_commit_zf(hb_context_t* ctx, bool equal) {
    if (ctx->lazy_flags.pending) {
        ctx->lazy_flags.valid_mask |= HB_FLAG_BIT_ZF;
        ctx->lazy_flags.unsupported_mask &= ~(uint32_t)HB_FLAG_BIT_ZF;
        ctx->lazy_flags.materialized_mask |= HB_FLAG_BIT_ZF;
    }
    ctx->flags.zf = equal;
}

#endif
