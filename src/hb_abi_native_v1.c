/* Типизированная граница с нативным кодом, v1 — см. include/hb_abi_native_v1.h. */
#include "hb_abi_native_v1.h"
#include "hb_memory.h"
#include <string.h>

static hb_result_t scalar_mask(uint32_t kind, uint32_t width, uint64_t *mask)
{
    switch (kind) {
    case HB_ABI_X64_GPR_V1:
        if (width != 1 && width != 2 && width != 4 && width != 8) return HB_ERR_INVALID_ARG;
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

static int is_fp(uint32_t kind)
{
    return kind == HB_ABI_X64_F32_V1 || kind == HB_ABI_X64_F64_V1;
}

/* Проверка описателя целиком до любой записи: версия, размер, цель, счёт, каждая
 * активная позиция валидна, неактивные — NONE/0, результат NONE/0 или валидный скаляр. */
static hb_result_t validate_sig(const hb_abi_native_sig_v1_t *sig, uint64_t masks[HB_ABI_NATIVE_MAX_ARGS_V1],
                                uint64_t *ret_mask)
{
    if (!sig) return HB_ERR_INVALID_ARG;
    if (sig->abi_version != HB_ABI_NATIVE_V1) return HB_ERR_UNSUPPORTED_FEATURE;
    if (sig->struct_size != sizeof(*sig)) return HB_ERR_INVALID_ARG;
    if (sig->target_abi != HB_ABI_NATIVE_TARGET_AAPCS64_WIN_V1) return HB_ERR_UNSUPPORTED_FEATURE;
    if (sig->flags & ~HB_ABI_NATIVE_FLAG_VARIADIC_V1) return HB_ERR_INVALID_ARG;
    if (sig->reserved) return HB_ERR_INVALID_ARG;
    if (sig->flags & HB_ABI_NATIVE_FLAG_VARIADIC_V1) return HB_ERR_UNSUPPORTED_FEATURE;
    if (sig->argument_count > HB_ABI_NATIVE_MAX_ARGS_V1) return HB_ERR_INVALID_ARG;
    for (uint32_t i = 0; i < HB_ABI_NATIVE_MAX_ARGS_V1; ++i) {
        const hb_abi_native_arg_v1_t a = sig->args[i];
        if (i >= sig->argument_count) {
            if (a.kind != HB_ABI_X64_NONE_V1 || a.width_bytes) return HB_ERR_INVALID_ARG;
            masks[i] = 0;
            continue;
        }
        hb_result_t r = scalar_mask(a.kind, a.width_bytes, &masks[i]);
        if (r != HB_OK) return r;
    }
    if (sig->ret.kind == HB_ABI_X64_NONE_V1) {
        if (sig->ret.width_bytes) return HB_ERR_INVALID_ARG;
        *ret_mask = 0;
    } else {
        hb_result_t r = scalar_mask(sig->ret.kind, sig->ret.width_bytes, ret_mask);
        if (r != HB_OK) return r;
    }
    return HB_OK;
}

hb_result_t hb_abi_native_lower_v1(const hb_context_t *ctx, const hb_abi_native_sig_v1_t *sig,
                                   hb_abi_native_image_v1_t *out)
{
    uint64_t masks[HB_ABI_NATIVE_MAX_ARGS_V1], ret_mask;
    hb_abi_native_image_v1_t image;
    hb_result_t r;

    if (!ctx || !out || ctx->arch != HB_ARCH_X64 || ctx->mode != HB_MODE_64BIT)
        return HB_ERR_INVALID_ARG;
    r = validate_sig(sig, masks, &ret_mask);
    if (r != HB_OK) return r;
    if (sig->argument_count > 4) {
        if (!ctx->memory) return HB_ERR_INVALID_ARG;
        /* Адрес последнего слота хвоста не должен переворачиваться через ноль. */
        if (ctx->regs.x64.rsp > UINT64_MAX - (40ull + 8ull * (sig->argument_count - 4)))
            return HB_ERR_INVALID_ARG;
    }

    memset(&image, 0, sizeof(image));
    const uint64_t gpr[4] = {ctx->regs.x64.rcx, ctx->regs.x64.rdx, ctx->regs.x64.r8, ctx->regs.x64.r9};
    for (uint32_t i = 0; i < sig->argument_count; ++i) {
        const hb_abi_native_arg_v1_t a = sig->args[i];
        uint64_t bits;
        if (i < 4) {
            /* Позиционное правило Win64: слот i лежит ЛИБО в i-м целом регистре, ЛИБО в XMM_i. */
            bits = is_fp(a.kind) ? ctx->regs.x64.xmm[i][0] : gpr[i];
        } else {
            /* Хвост: RSP -> адрес возврата, +8 теневые 32 байта, дальше слоты по 8. */
            r = hb_memory_read_u64(ctx->memory,
                                   (hb_gva_t)(ctx->regs.x64.rsp + 8 + 32 + 8ull * (i - 4)), &bits);
            if (r != HB_OK) return HB_ERR_MEMORY_FAULT;
        }
        bits &= masks[i];
        /* AAPCS64: раздельные счётчики; переполнение любого — на стек в порядке аргументов. */
        if (is_fp(a.kind)) {
            if (image.d_count < HB_ABI_NATIVE_D_REGS_V1) image.d_bits[image.d_count++] = bits;
            else image.stack[image.stack_count++] = bits;
        } else {
            if (image.x_count < HB_ABI_NATIVE_X_REGS_V1) image.x[image.x_count++] = bits;
            else image.stack[image.stack_count++] = bits;
        }
    }
    *out = image;
    return HB_OK;
}

hb_result_t hb_abi_native_collect_return_v1(hb_context_t *ctx, const hb_abi_native_sig_v1_t *sig,
                                            uint64_t x0, uint64_t d0_bits)
{
    uint64_t masks[HB_ABI_NATIVE_MAX_ARGS_V1], ret_mask;
    hb_result_t r;
    if (!ctx || ctx->arch != HB_ARCH_X64 || ctx->mode != HB_MODE_64BIT) return HB_ERR_INVALID_ARG;
    r = validate_sig(sig, masks, &ret_mask);
    if (r != HB_OK) return r;
    if (sig->ret.kind == HB_ABI_X64_NONE_V1) return HB_OK;
    if (is_fp(sig->ret.kind))
        ctx->regs.x64.xmm[0][0] = (ctx->regs.x64.xmm[0][0] & ~ret_mask) | (d0_bits & ret_mask);
    else
        ctx->regs.x64.rax = x0 & ret_mask;
    return HB_OK;
}

hb_result_t hb_abi_native_raise_v1(const hb_abi_native_image_v1_t *image,
                                   const hb_abi_native_sig_v1_t *sig, uint64_t return_pc,
                                   hb_abi_x64_call_v1_t *out_call,
                                   hb_abi_x64_value_v1_t *out_tail, size_t tail_capacity)
{
    uint64_t masks[HB_ABI_NATIVE_MAX_ARGS_V1], ret_mask;
    hb_abi_x64_call_v1_t call;
    hb_abi_x64_value_v1_t tail[HB_ABI_NATIVE_MAX_ARGS_V1];
    uint32_t xi = 0, di = 0, si = 0;
    hb_result_t r;

    if (!image || !out_call) return HB_ERR_INVALID_ARG;
    r = validate_sig(sig, masks, &ret_mask);
    if (r != HB_OK) return r;
    const uint32_t tail_count = sig->argument_count > 4 ? sig->argument_count - 4 : 0;
    if (tail_count && (!out_tail || tail_capacity < tail_count)) return HB_ERR_INVALID_ARG;
    if (image->x_count > HB_ABI_NATIVE_X_REGS_V1 || image->d_count > HB_ABI_NATIVE_D_REGS_V1 ||
        image->stack_count > HB_ABI_NATIVE_MAX_ARGS_V1)
        return HB_ERR_INVALID_ARG;

    memset(&call, 0, sizeof(call));
    memset(tail, 0, sizeof(tail));
    for (uint32_t i = 0; i < sig->argument_count; ++i) {
        const hb_abi_native_arg_v1_t a = sig->args[i];
        uint64_t bits;
        if (is_fp(a.kind)) {
            if (di < HB_ABI_NATIVE_D_REGS_V1) { if (di >= image->d_count) return HB_ERR_INVALID_ARG; bits = image->d_bits[di++]; }
            else { if (si >= image->stack_count) return HB_ERR_INVALID_ARG; bits = image->stack[si++]; }
        } else {
            if (xi < HB_ABI_NATIVE_X_REGS_V1) { if (xi >= image->x_count) return HB_ERR_INVALID_ARG; bits = image->x[xi++]; }
            else { if (si >= image->stack_count) return HB_ERR_INVALID_ARG; bits = image->stack[si++]; }
        }
        bits &= masks[i];
        hb_abi_x64_value_v1_t v = {a.kind, a.width_bytes, bits};
        if (i < 4) call.slots[i] = v;
        else tail[i - 4] = v;
    }
    call.abi_version = HB_ABI_X64_V1;
    call.struct_size = sizeof(call);
    call.argument_count = sig->argument_count;
    call.return_pc = return_pc;
    call.stack_args = tail_count ? out_tail : NULL;
    if (tail_count) memcpy(out_tail, tail, tail_count * sizeof(*out_tail));
    *out_call = call;
    return HB_OK;
}
