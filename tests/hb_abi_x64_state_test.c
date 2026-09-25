/* Synthetic x64 call preparation only: no guest execution, Wine, or JIT. */
#include "hb_abi.h"
#include "hb_memory.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STACK_BASE UINT64_C(0x300000)
#define STACK_SIZE 0x2000u
#define CALL_TARGET UINT64_C(0x401000)
#define OUTPUT_SENTINEL UINT64_C(0x123456789abcdef0)

static unsigned checks;
static unsigned failures;

static void check(int condition, const char *name)
{
    checks++;
    if (!condition) {
        failures++;
        fprintf(stderr, "FAIL: %s\n", name);
    }
}

static hb_context_t *make_context(void)
{
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    uint8_t initial_stack[STACK_SIZE];

    if (!ctx) return NULL;
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory ||
        hb_memory_map_private(ctx->memory, STACK_BASE, STACK_SIZE,
                              HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        hb_context_destroy(ctx);
        return NULL;
    }
    memset(initial_stack, 0xa5, sizeof(initial_stack));
    if (hb_memory_write(ctx->memory, STACK_BASE, initial_stack,
                        sizeof(initial_stack)) != HB_OK) {
        hb_context_destroy(ctx);
        return NULL;
    }
    ctx->memory->stack_bottom = STACK_BASE;
    ctx->memory->stack_top = STACK_BASE + STACK_SIZE;
    memset(&ctx->regs.x64, 0x3c, sizeof(ctx->regs.x64));
    memset(ctx->ymm_hi, 0x6d, sizeof(ctx->ymm_hi));
    ctx->regs.x64.rsp = STACK_BASE + STACK_SIZE;
    ctx->regs.x64.rip = UINT64_C(0x12340000);
    ctx->regs.x64.rflags = UINT64_C(0x202);
    ctx->pc = ctx->regs.x64.rip;
    ctx->mxcsr = 0x3f80;
    return ctx;
}

static int check_rejected_call(uint64_t *xmm_args, size_t xmm_arg_count,
                               hb_result_t expected_result)
{
    hb_context_t *ctx = make_context();
    hb_context_t before;
    hb_abi_x64_call_t call = {0};
    uint8_t stack_before[STACK_SIZE], stack_after[STACK_SIZE];
    uint64_t out = OUTPUT_SENTINEL;
    hb_result_t result;

    if (!ctx) return 0;
    if (hb_memory_read(ctx->memory, STACK_BASE, stack_before,
                       sizeof(stack_before)) != HB_OK) {
        hb_context_destroy(ctx);
        return 0;
    }
    memcpy(&before, ctx, sizeof(before));
    call.rcx = 1;
    call.rdx = 2;
    call.r8 = 3;
    call.r9 = 4;
    call.xmm_args = xmm_args;
    call.xmm_arg_count = xmm_arg_count;
    result = hb_abi_x64_call(ctx, CALL_TARGET, &call, &out);

    check(result == expected_result, "nonzero XMM count is rejected explicitly");
    check(memcmp(ctx, &before, sizeof(before)) == 0,
          "rejected XMM call preserves the entire context");
    check(out == OUTPUT_SENTINEL, "rejected XMM call preserves output");
    result = hb_memory_read(ctx->memory, STACK_BASE, stack_after,
                            sizeof(stack_after));
    check(result == HB_OK, "rejected XMM call stack remains readable");
    if (result == HB_OK)
        check(memcmp(stack_before, stack_after, sizeof(stack_before)) == 0,
              "rejected XMM call preserves the entire mapped stack");
    hb_context_destroy(ctx);
    return 1;
}

static int check_integer_call(uint64_t *unused_xmm_args)
{
    hb_context_t *ctx = make_context();
    hb_context_t expected;
    hb_abi_x64_call_t call = {0};
    uint64_t stack_args[2] = {UINT64_C(0x5501), UINT64_C(0x5502)};
    uint64_t frame[7] = {0};
    const uint64_t expected_frame[7] = {
        UINT64_C(0xffff0000), 0x51, 0x52, 0x53, 0x54, 0x5501, 0x5502
    };
    uint64_t out = OUTPUT_SENTINEL;
    hb_result_t result;

    if (!ctx) return 0;
    memcpy(&expected, ctx, sizeof(expected));
    call.rcx = 1;
    call.rdx = 2;
    call.r8 = 3;
    call.r9 = 4;
    call.stack_args = stack_args;
    call.stack_arg_count = 2;
    call.xmm_args = unused_xmm_args;
    call.xmm_arg_count = 0;
    for (size_t i = 0; i < 4; i++) call.shadow_space[i] = 0x51 + i;

    expected.regs.x64.rcx = call.rcx;
    expected.regs.x64.rdx = call.rdx;
    expected.regs.x64.r8 = call.r8;
    expected.regs.x64.r9 = call.r9;
    /* CALL return address, four home slots, two stack argument slots. */
    expected.regs.x64.rsp = STACK_BASE + STACK_SIZE - sizeof(expected_frame);
    expected.regs.x64.rip = CALL_TARGET;
    expected.pc = CALL_TARGET;

    result = hb_abi_x64_call(ctx, CALL_TARGET, &call, &out);
    check(result == HB_OK, "zero XMM count preserves integer call support");
    check(out == 0, "successful integer call preserves output convention");
    check(memcmp(ctx, &expected, sizeof(expected)) == 0,
          "integer call changes only its argument registers, stack and PC");
    check((ctx->regs.x64.rsp & 15) == 8, "integer call entry stack alignment");
    result = hb_memory_read(ctx->memory, ctx->regs.x64.rsp, frame, sizeof(frame));
    check(result == HB_OK, "integer call frame is readable");
    if (result == HB_OK)
        check(memcmp(frame, expected_frame, sizeof(frame)) == 0,
              "integer call retains shadow space and stack arguments");
    hb_context_destroy(ctx);
    return 1;
}

int main(void)
{
    /* One readable element is sufficient: unsupported fields must not be read,
     * even when the advertised count is larger than any valid ABI payload. */
    uint64_t xmm_arg = UINT64_C(0x3ff0000000000000);
    const size_t counts[] = {1, 4, 5, SIZE_MAX};

    if (!check_rejected_call(NULL, 1, HB_ERR_INVALID_ARG)) return 2;
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        if (!check_rejected_call(&xmm_arg, counts[i], HB_ERR_UNSUPPORTED_FEATURE))
            return 2;
    }
    if (!check_integer_call(NULL) || !check_integer_call(&xmm_arg)) return 2;
    printf("x64 ABI state: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
