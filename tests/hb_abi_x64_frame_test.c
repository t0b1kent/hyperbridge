/* Bounded synthetic call-frame regressions. No guest instructions execute.
 * Oversized-count cases have one readable source element and a complete host
 * page ending exactly at RSP. The old code fails its first out-of-page write,
 * before it can read a second element; no long loop or large allocation occurs.
 */
#include "hb_abi.h"
#include "hb_memory.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

enum { PAGE_BYTES = 16384 };
static const uint64_t BASE = 0x600000;
static unsigned checks, failures;

static void check(int ok, const char *name) {
    ++checks;
    if (!ok) { ++failures; printf("FAIL: %s\n", name); }
}

static hb_context_t *context_at(uint64_t base) {
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    if (!ctx) return NULL;
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory || hb_memory_map_private(ctx->memory, base, PAGE_BYTES,
                                             HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        hb_context_destroy(ctx); return NULL;
    }
    /* Prove the boundary used by the negative controls is the actual mapping
     * end, including the host's page-rounding behavior. */
    if (!ctx->memory->regions || ctx->memory->regions->size != PAGE_BYTES ||
        ctx->memory->regions->base != base) {
        hb_context_destroy(ctx); return NULL;
    }
    uint8_t initial[PAGE_BYTES];
    memset(initial, 0xa5, sizeof(initial));
    if (hb_memory_write(ctx->memory, base, initial, sizeof(initial)) != HB_OK) {
        hb_context_destroy(ctx); return NULL;
    }
    ctx->regs.x64.rsp = base + PAGE_BYTES;
    ctx->pc = ctx->regs.x64.rip = 0x1234000;
    ctx->regs.x64.rcx = 0x81;
    return ctx;
}

static int rejected_count(size_t count, uint64_t rsp, hb_result_t wanted) {
    hb_context_t *ctx = context_at(BASE);
    if (!ctx) return 0;
    hb_abi_x64_call_t call = {0};
    hb_context_t before;
    uint8_t old[PAGE_BYTES], now[PAGE_BYTES] = {0};
    uint64_t one_arg = 0x11223344, out = 0xbadcafe;
    ctx->regs.x64.rsp = rsp;
    call.stack_args = &one_arg;
    call.stack_arg_count = count;
    call.rcx = 1; call.rdx = 2; call.r8 = 3; call.r9 = 4;
    if (hb_memory_read(ctx->memory, BASE, old, sizeof(old)) != HB_OK) {
        hb_context_destroy(ctx); return 0;
    }
    memcpy(&before, ctx, sizeof(before));
    hb_result_t result = hb_abi_x64_call(ctx, 0x401000, &call, &out);
    printf("case=count:%zu rsp:0x%" PRIx64 " result:%d expected:%d\n", count, rsp, result, wanted);
    check(result == wanted, "frame input rejected with defined result");
    check(!memcmp(&before, ctx, sizeof(before)), "rejected frame preserves context");
    check(out == 0xbadcafe, "rejected frame preserves output");
    result = hb_memory_read(ctx->memory, BASE, now, sizeof(now));
    check(result == HB_OK, "stack still readable after rejection");
    if (result == HB_OK) check(!memcmp(old, now, sizeof(old)), "rejected frame writes no stack bytes");
    hb_context_destroy(ctx);
    return 1;
}

static int high_stack_headroom(void) {
    const uint64_t base = UINT64_MAX - 0x7fff;
    hb_context_t *ctx = context_at(base);
    if (!ctx) return 0;
    hb_abi_x64_call_t call = {0};
    ctx->memory->stack_bottom = base;
    ctx->memory->stack_top = base + PAGE_BYTES;
    hb_result_t result = hb_abi_x64_call(ctx, 0x401000, &call, NULL);
    check(result == HB_OK, "small high-address stack prepares a frame");
    check(ctx->regs.x64.rsp == base + PAGE_BYTES - 40,
          "headroom comparison does not wrap at a high stack base");
    hb_context_destroy(ctx);
    return 1;
}

static int boundary_permissions(int second_region) {
    hb_context_t *ctx = context_at(BASE);
    if (!ctx) return 0;
    const uint64_t boundary = BASE + PAGE_BYTES;
    uint8_t old[PAGE_BYTES], now[PAGE_BYTES] = {0};
    hb_abi_x64_call_t call = {0};
    hb_context_t before;
    uint64_t args[2] = {0x5501, 0x5502}, out = 0xbadcafe;
    if (second_region) {
        hb_perm_t perm = second_region == 1 ? HB_PERM_READ : HB_PERM_READ | HB_PERM_WRITE;
        if (hb_memory_map_private(ctx->memory, boundary, PAGE_BYTES, perm) != HB_OK) {
            hb_context_destroy(ctx); return 0;
        }
    }
    ctx->regs.x64.rsp = boundary + 32;
    call.stack_args = args; call.stack_arg_count = 2;
    call.shadow_space[0] = 0x51; call.shadow_space[1] = 0x52;
    call.shadow_space[2] = 0x53; call.shadow_space[3] = 0x54;
    if (hb_memory_read(ctx->memory, BASE, old, sizeof(old)) != HB_OK) {
        hb_context_destroy(ctx); return 0;
    }
    memcpy(&before, ctx, sizeof(before));
    hb_result_t result = hb_abi_x64_call(ctx, 0x401000, &call, &out);
    if (second_region == 2) {
        uint64_t actual[7] = {0};
        const uint64_t expected[7] = {0xffff0000,0x51,0x52,0x53,0x54,0x5501,0x5502};
        check(result == HB_OK, "frame can span adjacent writable regions");
        check(ctx->regs.x64.rsp == boundary - 24, "cross-region frame keeps ABI layout");
        check(hb_memory_read(ctx->memory, boundary - 24, actual, sizeof(actual)) == HB_OK,
              "cross-region frame readable");
        check(!memcmp(actual, expected, sizeof(actual)), "cross-region frame contents");
    } else {
        check(result == HB_ERR_MEMORY_FAULT, "gap/read-only frame rejected before writing");
        check(!memcmp(ctx, &before, sizeof(before)), "permission rejection preserves context");
        check(out == 0xbadcafe, "permission rejection preserves output");
        check(hb_memory_read(ctx->memory, BASE, now, sizeof(now)) == HB_OK, "first region readable");
        check(!memcmp(old, now, sizeof(old)), "permission rejection does not partially write first region");
    }
    hb_context_destroy(ctx);
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const size_t counts[] = {SIZE_MAX / 8 + 1, SIZE_MAX / 8, SIZE_MAX / 8 - 3};
    for (size_t i = 0; i < sizeof(counts)/sizeof(counts[0]); ++i)
        if (!rejected_count(counts[i], BASE + PAGE_BYTES, HB_ERR_INVALID_ARG)) return 2;
    if (!rejected_count(0, 16, HB_ERR_MEMORY_FAULT)) return 2;
    if (!high_stack_headroom()) return 2;
    for (int perm = 0; perm < 3; ++perm) if (!boundary_permissions(perm)) return 2;
    printf("x64 ABI frame: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
