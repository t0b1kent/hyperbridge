#include "hb_abi_x64_v1.h"
#include "hb_memory.h"
#include <stdlib.h>

static hb_result_t scalar_mask(uint32_t kind, uint32_t width, uint64_t *mask)
{
    switch (kind) {
    case HB_ABI_X64_GPR_V1:
        if (width != 1 && width != 2 && width != 4 && width != 8)
            return HB_ERR_INVALID_ARG;
        break;
    case HB_ABI_X64_F32_V1:
        if (width != 4) return HB_ERR_INVALID_ARG;
        break;
    case HB_ABI_X64_F64_V1:
        if (width != 8) return HB_ERR_INVALID_ARG;
        break;
    case HB_ABI_X64_NONE_V1:
        return HB_ERR_INVALID_ARG;
    default:
        return HB_ERR_UNSUPPORTED_FEATURE;
    }
    *mask = width == 8 ? UINT64_MAX : (UINT64_C(1) << (width * 8)) - 1;
    return HB_OK;
}

static void store_le64(uint8_t *dest, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) dest[i] = (uint8_t)(value >> (8 * i));
}

hb_result_t hb_abi_x64_prepare_v1(hb_context_t *ctx, uint64_t target,
                                 const hb_abi_x64_call_v1_t *call)
{
    if (!ctx || !call || !ctx->memory || ctx->arch != HB_ARCH_X64 ||
        ctx->mode != HB_MODE_64BIT)
        return HB_ERR_INVALID_ARG;
    if (call->abi_version != HB_ABI_X64_V1) return HB_ERR_UNSUPPORTED_FEATURE;
    if (call->struct_size != sizeof(*call)) return HB_ERR_INVALID_ARG;

    /* Snapshot the descriptor itself as well as the values it points at.
     * A valid host-backed descriptor can overlap the future guest frame. */
    const hb_abi_x64_call_v1_t request = *call;
    const uint64_t tail64 = request.argument_count > 4 ? request.argument_count - 4 : 0;
    if (tail64 > SIZE_MAX / sizeof(*request.stack_args)) return HB_ERR_INVALID_ARG;
    const size_t tail = (size_t)tail64;
    const size_t pad = (tail & 1) ? 8 : 0;
    if (tail > (SIZE_MAX - 40 - pad) / 8) return HB_ERR_INVALID_ARG;
    const size_t frame_bytes = 40 + 8 * tail + pad;
    const uint64_t old_rsp = ctx->regs.x64.rsp;
    if ((old_rsp & 15) || old_rsp < frame_bytes) return HB_ERR_INVALID_ARG;
    if (tail && !request.stack_args) return HB_ERR_INVALID_ARG;
    const uint64_t entry_rsp = old_rsp - frame_bytes;
    const size_t active = request.argument_count < 4 ? (size_t)request.argument_count : 4;
    uint64_t masks[4] = {0}, bits[4] = {0};
    for (size_t i = 0; i < 4; ++i) {
        const hb_abi_x64_value_v1_t value = request.slots[i];
        if (i >= active) {
            if (value.kind != HB_ABI_X64_NONE_V1 || value.width_bytes || value.bits)
                return HB_ERR_INVALID_ARG;
            continue;
        }
        hb_result_t result = scalar_mask(value.kind, value.width_bytes, &masks[i]);
        if (result != HB_OK) return result;
        bits[i] = value.bits & masks[i];
    }

    /* Reject impossible spans before allocating or scanning the tail. Besides
     * avoiding needless allocation, this bounds impossible huge-count calls. */
    if (!hb_memory_can_write_span(ctx->memory, entry_rsp, frame_bytes))
        return HB_ERR_MEMORY_FAULT;
    uint8_t *frame = calloc(frame_bytes, 1);
    if (!frame) return HB_ERR_OUT_OF_MEMORY;
    store_le64(frame, request.return_pc);
    for (size_t i = 0; i < tail; ++i) {
        const hb_abi_x64_value_v1_t value = request.stack_args[i];
        uint64_t mask;
        hb_result_t result = scalar_mask(value.kind, value.width_bytes, &mask);
        if (result != HB_OK) {
            free(frame);
            return result;
        }
        store_le64(frame + 40 + 8 * i, value.bits & mask);
    }
    hb_result_t result = hb_memory_write(ctx->memory, entry_rsp, frame, frame_bytes);
    free(frame);
    if (result != HB_OK) return HB_ERR_MEMORY_FAULT;

    uint64_t *gpr[4] = {&ctx->regs.x64.rcx, &ctx->regs.x64.rdx,
                        &ctx->regs.x64.r8, &ctx->regs.x64.r9};
    for (size_t i = 0; i < active; ++i) {
        if (request.slots[i].kind == HB_ABI_X64_GPR_V1)
            *gpr[i] = bits[i];
        else
            ctx->regs.x64.xmm[i][0] = (ctx->regs.x64.xmm[i][0] & ~masks[i]) | bits[i];
    }
    ctx->regs.x64.rsp = entry_rsp;
    ctx->regs.x64.rip = ctx->pc = target;
    return HB_OK;
}

hb_result_t hb_abi_x64_read_return_v1(const hb_context_t *ctx, uint32_t kind,
                                     uint32_t width_bytes, uint64_t *out_bits)
{
    if (!ctx || !out_bits || ctx->arch != HB_ARCH_X64 || ctx->mode != HB_MODE_64BIT)
        return HB_ERR_INVALID_ARG;
    uint64_t bits = 0;
    if (kind == HB_ABI_X64_NONE_V1) {
        if (width_bytes) return HB_ERR_INVALID_ARG;
    } else {
        uint64_t mask;
        hb_result_t result = scalar_mask(kind, width_bytes, &mask);
        if (result != HB_OK) return result;
        bits = (kind == HB_ABI_X64_GPR_V1 ? ctx->regs.x64.rax : ctx->regs.x64.xmm[0][0]) & mask;
    }
    *out_bits = bits;
    return HB_OK;
}
