#ifndef HB_PACKET_FLAGS_H
#define HB_PACKET_FLAGS_H

#include "hb_flags.h"

/* Packet images and the core's live status flags are separate representations.
 * Import supersedes every deferred computation from the previous guest slice. */
static void hb_packet_flags_import(hb_context_t *ctx, uint64_t image)
{
    ctx->regs.x64.rflags = image | UINT64_C(2);
    ctx->flags.cf = !!(image & (UINT64_C(1) << 0));
    ctx->flags.pf = !!(image & (UINT64_C(1) << 2));
    ctx->flags.af = !!(image & (UINT64_C(1) << 4));
    ctx->flags.zf = !!(image & (UINT64_C(1) << 6));
    ctx->flags.sf = !!(image & (UINT64_C(1) << 7));
    ctx->flags.of = !!(image & (UINT64_C(1) << 11));
    hb_lazy_flags_clear(ctx);
}

/* Match architectural PUSHF: compute defined status bits while retaining the
 * core's chosen values for undefined bits and the packet's non-status bits. */
static hb_result_t hb_packet_flags_export(hb_context_t *ctx, uint64_t *image)
{
    hb_result_t result;
    uint64_t value;
    if (!ctx || !image) return HB_ERR_INVALID_ARG;
    result = hb_lazy_flags_materialize_available(ctx, HB_FLAG_BIT_ALL);
    if (result != HB_OK) return result;
    value = (ctx->regs.x64.rflags & ~UINT64_C(0x8d5)) | UINT64_C(2);
    value |= (uint64_t)!!ctx->flags.cf << 0;
    value |= (uint64_t)!!ctx->flags.pf << 2;
    value |= (uint64_t)!!ctx->flags.af << 4;
    value |= (uint64_t)!!ctx->flags.zf << 6;
    value |= (uint64_t)!!ctx->flags.sf << 7;
    value |= (uint64_t)!!ctx->flags.of << 11;
    ctx->regs.x64.rflags = value;
    *image = value;
    return HB_OK;
}

#endif
