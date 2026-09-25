/* Typed scalar Win64 calls: raw bits, positional registers, a real guest RET.
 * No Wine/FEX dependency. All guest memory belongs to this test process.
 * Frame expectations use explicit little-endian bytes; neither backend is
 * used as the other's oracle. Late write errors assert no register commit,
 * not whole-memory rollback. */
#include "hb_abi_x64_v1.h"
#include "hb_abi_native_v1.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_thunk.h"
#include <fenv.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <sys/mman.h>
#endif

enum { PAGE_BYTES = 16384 };
static const uint64_t STACK = UINT64_C(0x600000);
static const uint64_t CODE = UINT64_C(0x400000);
static const uint64_t RETURN_PC = UINT64_C(0x710000);
static const uint64_t SENTINEL = UINT64_C(0xbadcafedeadbeef);
static unsigned checks, failures;
static const char *phase = "setup";

static int check(int ok, const char *message)
{
    ++checks;
    if (!ok) {
        ++failures;
        fprintf(stderr, "FAIL [%s]: %s\n", phase, message);
    }
    return ok;
}

static hb_context_t *new_context_mapped(hb_backend_t backend, int identity,
                                        uint64_t *stack_out)
{
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, backend);
    uint8_t initial[PAGE_BYTES];
    if (!ctx) { check(0, "context allocation"); return NULL; }
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory || (identity
            ? hb_memory_map(ctx->memory, 0, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE)
            : hb_memory_map_private(ctx->memory, STACK, PAGE_BYTES,
                                    HB_PERM_READ | HB_PERM_WRITE)) != HB_OK) {
        check(0, "owned stack allocation");
        hb_context_destroy(ctx);
        return NULL;
    }
    uint64_t stack = identity ? ctx->memory->regions->base : STACK;
    void *host = hb_memory_host_ptr(ctx->memory, stack, PAGE_BYTES,
                                    HB_PERM_READ | HB_PERM_WRITE);
    if (!check(host && ((uint64_t)(uintptr_t)host == stack) == identity,
               "stack mapping matches helper/direct execution configuration")) {
        hb_context_destroy(ctx); return NULL;
    }
    if (stack_out) *stack_out = stack;
    memset(initial, 0xa5, sizeof(initial));
    if (hb_memory_write(ctx->memory, stack, initial, sizeof(initial)) != HB_OK) {
        check(0, "initialize stack"); hb_context_destroy(ctx); return NULL;
    }
    memset(&ctx->regs.x64, 0x3c, sizeof(ctx->regs.x64));
    memset(ctx->ymm_hi, 0x6d, sizeof(ctx->ymm_hi));
    for (unsigned i = 0; i < 16; ++i) {
        ctx->regs.x64.xmm[i][0] = UINT64_C(0xa1b2c3d400001000) + i;
        ctx->regs.x64.xmm[i][1] = UINT64_C(0x5566778800002000) + i;
    }
    ctx->regs.x64.rsp = stack + PAGE_BYTES;
    ctx->regs.x64.rip = UINT64_C(0x1234000);
    ctx->regs.x64.rflags = 0x202;
    ctx->pc = ctx->regs.x64.rip;
    ctx->fs_base = 0x123000;
    ctx->gs_base = UINT64_C(0x100234000);
    ctx->flags.cf = 1;
    ctx->flags.zf = 1;
    ctx->mxcsr = 0x3fa1; /* Nondefault rounding plus status bits; no FP math. */
    ctx->step_limit = 64;
    ctx->block_limit = 8;
    return ctx;
}

static hb_context_t *new_context(hb_backend_t backend)
{
    return new_context_mapped(backend, 0, NULL);
}

static hb_abi_x64_value_v1_t value(uint32_t kind, uint32_t width, uint64_t bits)
{
    hb_abi_x64_value_v1_t v = {kind, width, bits};
    return v;
}

static hb_abi_x64_call_v1_t call_with_count(uint64_t count)
{
    hb_abi_x64_call_v1_t call = {0};
    call.abi_version = HB_ABI_X64_V1;
    call.struct_size = sizeof(call);
    call.argument_count = count;
    call.return_pc = RETURN_PC;
    for (unsigned i = 0; i < 4 && i < count; ++i)
        call.slots[i] = value(HB_ABI_X64_GPR_V1, 8, 0);
    return call;
}

static uint64_t low_bits(uint64_t bits, uint32_t width)
{
    switch (width) {
        case 1: return bits & UINT64_C(0xff);
        case 2: return bits & UINT64_C(0xffff);
        case 4: return bits & UINT64_C(0xffffffff);
        default: return bits;
    }
}

static void put_le64(uint8_t *dest, uint64_t bits)
{
    for (unsigned i = 0; i < 8; ++i) dest[i] = (uint8_t)(bits >> (i * 8));
}

/* Oracle for small (0..6 argument) calls. Frame sizes are fixed independently
 * of the production size calculation: 40 bytes for <=4, 56 for 5 or 6. */
static int expect_prepared_at(hb_context_t *ctx, const hb_abi_x64_call_v1_t *input,
                              uint64_t stack)
{
    hb_abi_x64_call_v1_t saved;
    hb_abi_x64_value_v1_t tail[2] = {{0}};
    hb_context_t expected;
    uint8_t before[PAGE_BYTES], after[PAGE_BYTES] = {0};
    uint8_t expected_stack[PAGE_BYTES];
    memcpy(&saved, input, sizeof(saved));
    if (!check(saved.argument_count <= 6, "bounded preparation oracle")) return 0;
    size_t tail_count = saved.argument_count > 4 ? (size_t)saved.argument_count - 4 : 0;
    if (tail_count) memcpy(tail, saved.stack_args, tail_count * sizeof(tail[0]));
    if (!check(hb_memory_read(ctx->memory, stack, before, sizeof(before)) == HB_OK,
               "read initial stack")) return 0;
    memcpy(expected_stack, before, sizeof(before));
    memcpy(&expected, ctx, sizeof(expected));
    const size_t frame_bytes = tail_count ? 56 : 40;
    const uint64_t entry = ctx->regs.x64.rsp - frame_bytes;
    const size_t start = (size_t)(entry - stack);
    memset(expected_stack + start, 0, frame_bytes);
    put_le64(expected_stack + start, saved.return_pc);
    for (size_t i = 0; i < tail_count; ++i)
        put_le64(expected_stack + start + 40 + i * 8,
                 low_bits(tail[i].bits, tail[i].width_bytes));
    uint64_t *gprs[] = {&expected.regs.x64.rcx, &expected.regs.x64.rdx,
                       &expected.regs.x64.r8, &expected.regs.x64.r9};
    for (unsigned i = 0; i < 4 && i < saved.argument_count; ++i) {
        const hb_abi_x64_value_v1_t *v = &saved.slots[i];
        uint64_t bits = low_bits(v->bits, v->width_bytes);
        if (v->kind == HB_ABI_X64_GPR_V1) *gprs[i] = bits;
        else if (v->kind == HB_ABI_X64_F32_V1)
            expected.regs.x64.xmm[i][0] =
                (expected.regs.x64.xmm[i][0] & UINT64_C(0xffffffff00000000)) | bits;
        else expected.regs.x64.xmm[i][0] = bits;
    }
    expected.regs.x64.rsp = entry;
    expected.regs.x64.rip = expected.pc = CODE;
    int rounding = fegetround(), exceptions = fetestexcept(FE_ALL_EXCEPT);
    hb_result_t result = hb_abi_x64_prepare_v1(ctx, CODE, input);
    int ok = check(result == HB_OK, "preparation succeeds");
    ok &= check(!memcmp(ctx, &expected, sizeof(expected)),
                "exact positional register changes; all other context preserved");
    ok &= check((ctx->regs.x64.rsp & 15) == 8, "entry RSP alignment");
    ok &= check(fegetround() == rounding && fetestexcept(FE_ALL_EXCEPT) == exceptions,
                "preparation preserves host FP environment");
    if (check(hb_memory_read(ctx->memory, stack, after, sizeof(after)) == HB_OK,
              "read prepared stack"))
        ok &= check(!memcmp(after, expected_stack, sizeof(after)),
                    "exact frame, zero homes/padding, untouched surrounding bytes");
    else ok = 0;
    return ok;
}

static int expect_prepared(hb_context_t *ctx, const hb_abi_x64_call_v1_t *input)
{
    return expect_prepared_at(ctx, input, STACK);
}

static void preparation_values(void)
{
    phase = "positional values";
    const uint32_t widths[] = {1, 2, 4, 8};
    hb_context_t *ctx = new_context(HB_BACKEND_INTERP);
    if (!ctx) return;
    hb_abi_x64_call_v1_t call = call_with_count(4);
    for (unsigned i = 0; i < 4; ++i)
        call.slots[i] = value(HB_ABI_X64_GPR_V1, widths[i], UINT64_C(0xfedcba9876543281));
    expect_prepared(ctx, &call);
    hb_context_destroy(ctx);
    for (unsigned kind = HB_ABI_X64_F32_V1; kind <= HB_ABI_X64_F64_V1; ++kind)
        for (unsigned position = 0; position < 4; ++position) {
            ctx = new_context(HB_BACKEND_INTERP);
            if (!ctx) return;
            call = call_with_count(4);
            uint64_t bits = kind == HB_ABI_X64_F32_V1
                ? (position & 1 ? UINT64_C(0xfeedbeef7fc12345) : UINT64_C(0xaabbccdd80000000))
                : (position & 1 ? UINT64_C(0x7ff8000000001234) : UINT64_C(0xfff0000000000000));
            call.slots[position] = value(kind, kind == HB_ABI_X64_F32_V1 ? 4 : 8, bits);
            expect_prepared(ctx, &call);
            hb_context_destroy(ctx);
        }
    phase = "small frames and mixed positions";
    for (unsigned count = 0; count <= 6; ++count) {
        ctx = new_context(HB_BACKEND_INTERP);
        if (!ctx) return;
        call = call_with_count(count);
        hb_abi_x64_value_v1_t tail[] = {
            {HB_ABI_X64_F32_V1, 4, UINT64_C(0x112233447fc54321)},
            {HB_ABI_X64_GPR_V1, 2, UINT64_C(0x887766554433ff81)}
        };
        if (count > 0) call.slots[0] = value(HB_ABI_X64_GPR_V1, 8, 0x1122);
        if (count > 1) call.slots[1] = value(HB_ABI_X64_F64_V1, 8, UINT64_C(0x8000000000000000));
        if (count > 2) call.slots[2] = value(HB_ABI_X64_GPR_V1, 4, UINT64_C(0xffeeddcc80000001));
        if (count > 3) call.slots[3] = value(HB_ABI_X64_F32_V1, 4, UINT64_C(0xfedcba9880000000));
        call.stack_args = tail; /* A readable nonnull tail is ignored for <=4. */
        ctx->memory->stack_bottom = STACK - 0x10000;
        ctx->memory->stack_top = STACK + PAGE_BYTES;
        expect_prepared(ctx, &call); /* v1 must not insert legacy headroom. */
        hb_context_destroy(ctx);
    }
}

static void expect_rejected(hb_context_t *ctx, const hb_abi_x64_call_v1_t *call,
                            hb_result_t wanted)
{
    hb_context_t before;
    uint8_t stack_before[PAGE_BYTES], stack_after[PAGE_BYTES] = {0};
    if (!check(hb_memory_read(ctx->memory, STACK, stack_before, sizeof(stack_before)) == HB_OK,
               "read stack before rejection")) return;
    memcpy(&before, ctx, sizeof(before));
    hb_result_t result = hb_abi_x64_prepare_v1(ctx, CODE, call);
    check(result == wanted, "exact preparation error code");
    check(!memcmp(ctx, &before, sizeof(before)), "rejection preserves entire context");
    if (check(hb_memory_read(ctx->memory, STACK, stack_after, sizeof(stack_after)) == HB_OK,
              "read rejected stack"))
        check(!memcmp(stack_before, stack_after, sizeof(stack_before)),
              "validation/preflight rejection writes no stack bytes");
}

static void preparation_errors(void)
{
    phase = "descriptor validation";
    for (unsigned which = 0; which < 16; ++which) {
        hb_context_t *ctx = new_context(HB_BACKEND_INTERP);
        if (!ctx) return;
        hb_abi_x64_call_v1_t call = call_with_count(1);
        hb_abi_x64_value_v1_t tail[2] = {{HB_ABI_X64_GPR_V1, 8, 1}, {99, 8, 2}};
        hb_result_t wanted = HB_ERR_INVALID_ARG;
        switch (which) {
            case 0: call.abi_version++; wanted = HB_ERR_UNSUPPORTED_FEATURE; break;
            case 1: call.struct_size--; break;
            case 2: call.struct_size++; break;
            case 3: call.slots[0].kind = 99; wanted = HB_ERR_UNSUPPORTED_FEATURE; break;
            case 4: call.slots[0].width_bytes = 3; break;
            case 5: call.slots[0] = value(HB_ABI_X64_F32_V1, 8, 0); break;
            case 6: call.slots[0] = value(HB_ABI_X64_F64_V1, 4, 0); break;
            case 7: call.slots[0] = value(HB_ABI_X64_NONE_V1, 0, 0); break;
            case 8: call.slots[1].kind = 99; break;
            case 9: call.slots[1].width_bytes = 4; break;
            case 10: call.slots[1].bits = 1; break;
            case 11: call = call_with_count(5); break; /* Required null tail. */
            case 12: call = call_with_count(6); call.stack_args = tail;
                     wanted = HB_ERR_UNSUPPORTED_FEATURE; break;
            case 13: call = call_with_count(5); call.stack_args = tail;
                     tail[0].width_bytes = 3; break;
            case 14: ctx->arch = HB_ARCH_X86; break;
            case 15: ctx->mode = HB_MODE_32BIT; break;
        }
        expect_rejected(ctx, &call, wanted);
        ctx->arch = HB_ARCH_X64; ctx->mode = HB_MODE_64BIT;
        hb_context_destroy(ctx);
    }
    hb_context_t *ctx = new_context(HB_BACKEND_INTERP);
    if (!ctx) return;
    hb_abi_x64_call_v1_t call = call_with_count(0);
    expect_rejected(ctx, NULL, HB_ERR_INVALID_ARG);
    check(hb_abi_x64_prepare_v1(NULL, CODE, &call) == HB_ERR_INVALID_ARG, "null context rejected");
    hb_memory_t *memory = ctx->memory;
    hb_context_t before;
    ctx->memory = NULL;
    memcpy(&before, ctx, sizeof(before));
    check(hb_abi_x64_prepare_v1(ctx, CODE, &call) == HB_ERR_INVALID_ARG, "missing memory rejected");
    check(!memcmp(ctx, &before, sizeof(before)), "missing-memory rejection preserves context");
    ctx->memory = memory;
    hb_context_destroy(ctx);

    phase = "bounded frame errors";
    const uint64_t counts[] = {UINT64_MAX, (uint64_t)SIZE_MAX / 8 + 5,
                              (uint64_t)SIZE_MAX / sizeof(hb_abi_x64_value_v1_t) + 5};
    hb_abi_x64_value_v1_t one = {HB_ABI_X64_GPR_V1, 8, 0x1122};
    for (unsigned i = 0; i < sizeof(counts) / sizeof(counts[0]); ++i) {
        ctx = new_context(HB_BACKEND_INTERP);
        if (!ctx) return;
        call = call_with_count(counts[i]);
        call.stack_args = &one;
        expect_rejected(ctx, &call, HB_ERR_INVALID_ARG);
        hb_context_destroy(ctx);
    }
    for (unsigned i = 0; i < 4; ++i) {
        ctx = new_context(HB_BACKEND_INTERP);
        if (!ctx) return;
        call = call_with_count(0);
        if (i == 0) ctx->regs.x64.rsp--;
        if (i == 1) ctx->regs.x64.rsp = 16;
        if (i == 2) {
            if (!check(hb_memory_protect(ctx->memory, STACK, PAGE_BYTES, HB_PERM_READ) == HB_OK,
                       "read-only stack setup")) { hb_context_destroy(ctx); continue; }
        }
        if (i == 3) ctx->regs.x64.rsp = STACK + PAGE_BYTES + 32;
        expect_rejected(ctx, &call, i < 2 ? HB_ERR_INVALID_ARG : HB_ERR_MEMORY_FAULT);
        hb_context_destroy(ctx);
    }
}

static void aliased_inputs(void)
{
    phase = "input objects overlap future frame";
    for (unsigned which = 0; which < 2; ++which) {
        hb_context_t *ctx = new_context(HB_BACKEND_INTERP);
        if (!ctx) return;
        hb_abi_x64_call_v1_t call = call_with_count(6);
        hb_abi_x64_value_v1_t tail[] = {
            {HB_ABI_X64_F64_V1, 8, UINT64_C(0x7ff800000000cafe)},
            {HB_ABI_X64_F32_V1, 4, UINT64_C(0xaabbccdd80000000)}
        };
        call.slots[1] = value(HB_ABI_X64_F64_V1, 8, UINT64_C(0xfff800000000a55a));
        call.slots[3] = value(HB_ABI_X64_GPR_V1, 2, UINT64_C(0x112233445566ff80));
        call.stack_args = tail;
        const hb_abi_x64_call_v1_t *input = &call;
        if (which == 0) {
            void *host = hb_memory_host_ptr(ctx->memory, ctx->regs.x64.rsp - sizeof(call),
                                            sizeof(call), HB_PERM_READ | HB_PERM_WRITE);
            if (!check(host != NULL, "owned descriptor alias")) { hb_context_destroy(ctx); continue; }
            memcpy(host, &call, sizeof(call));
            input = host;
        } else {
            void *host = hb_memory_host_ptr(ctx->memory, ctx->regs.x64.rsp - sizeof(tail),
                                            sizeof(tail), HB_PERM_READ | HB_PERM_WRITE);
            if (!check(host != NULL, "owned tail alias")) { hb_context_destroy(ctx); continue; }
            memcpy(host, tail, sizeof(tail));
            call.stack_args = host;
        }
        expect_prepared(ctx, input);
        hb_context_destroy(ctx);
    }
}

static void late_write_failure(void)
{
#ifdef __APPLE__
    phase = "late owned-backing write failure";
    hb_context_t *ctx = new_context(HB_BACKEND_INTERP);
    if (!ctx) return;
    void *host = hb_memory_host_ptr(ctx->memory, STACK, PAGE_BYTES,
                                    HB_PERM_READ | HB_PERM_WRITE);
    if (!check(host != NULL, "owned backing for permission mismatch")) {
        hb_context_destroy(ctx); return;
    }
    hb_abi_x64_call_v1_t call = call_with_count(0);
    hb_context_t before;
    memcpy(&before, ctx, sizeof(before));
    if (!check(mprotect(host, PAGE_BYTES, PROT_READ) == 0, "protect owned backing")) {
        hb_context_destroy(ctx); return;
    }
    /* hb_memory.c private-host path uses mach_copy_to_host/mach_vm_write,
     * which reports denied writes instead of dereferencing this read-only page. */
    check(hb_memory_can_write_span(ctx->memory, ctx->regs.x64.rsp - 40, 40),
          "guest metadata preflight still succeeds");
    hb_result_t result = hb_abi_x64_prepare_v1(ctx, CODE, &call);
    int restored = mprotect(host, PAGE_BYTES, PROT_READ | PROT_WRITE);
    check(restored == 0, "restore owned backing on every result");
    check(result == HB_ERR_MEMORY_FAULT, "late frame write reports memory fault");
    check(!memcmp(ctx, &before, sizeof(before)), "late failure does not commit registers");
    /* Deliberately no comparison of stack contents: late writes are not transactional. */
    hb_context_destroy(ctx);
#endif
}

static void return_collection(void)
{
    phase = "pure return collection";
    hb_context_t *ctx = new_context(HB_BACKEND_INTERP);
    if (!ctx) return;
    ctx->regs.x64.rax = UINT64_C(0xfedcba9876543281);
    ctx->regs.x64.xmm[0][0] = UINT64_C(0xfff800007fc12345);
    hb_memory_t *memory = ctx->memory;
    ctx->memory = NULL; /* Collection requires no guest memory. */
    hb_context_t before;
    memcpy(&before, ctx, sizeof(before));
    const struct { uint32_t kind, width; uint64_t expected; } good[] = {
        {HB_ABI_X64_NONE_V1, 0, 0},
        {HB_ABI_X64_GPR_V1, 1, 0x81}, {HB_ABI_X64_GPR_V1, 2, 0x3281},
        {HB_ABI_X64_GPR_V1, 4, 0x76543281},
        {HB_ABI_X64_GPR_V1, 8, UINT64_C(0xfedcba9876543281)},
        {HB_ABI_X64_F32_V1, 4, 0x7fc12345},
        {HB_ABI_X64_F64_V1, 8, UINT64_C(0xfff800007fc12345)}
    };
    int rounding = fegetround(), exceptions = fetestexcept(FE_ALL_EXCEPT);
    for (unsigned i = 0; i < sizeof(good) / sizeof(good[0]); ++i) {
        uint64_t out = SENTINEL;
        check(hb_abi_x64_read_return_v1(ctx, good[i].kind, good[i].width, &out) == HB_OK,
              "typed return accepted without memory");
        check(out == good[i].expected, "raw return bits and width mask");
    }
    const struct { uint32_t kind, width; hb_result_t result; } bad[] = {
        {99, 8, HB_ERR_UNSUPPORTED_FEATURE}, {HB_ABI_X64_NONE_V1, 8, HB_ERR_INVALID_ARG},
        {HB_ABI_X64_GPR_V1, 3, HB_ERR_INVALID_ARG},
        {HB_ABI_X64_F32_V1, 8, HB_ERR_INVALID_ARG},
        {HB_ABI_X64_F64_V1, 4, HB_ERR_INVALID_ARG}
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        uint64_t out = SENTINEL;
        check(hb_abi_x64_read_return_v1(ctx, bad[i].kind, bad[i].width, &out) == bad[i].result,
              "exact return-descriptor error");
        check(out == SENTINEL, "return error preserves output");
    }
    uint64_t out = SENTINEL;
    check(hb_abi_x64_read_return_v1(NULL, HB_ABI_X64_GPR_V1, 8, &out) == HB_ERR_INVALID_ARG,
          "null return context rejected");
    check(out == SENTINEL, "null-context error preserves output");
    check(hb_abi_x64_read_return_v1(ctx, HB_ABI_X64_GPR_V1, 8, NULL) == HB_ERR_INVALID_ARG,
          "null return output rejected");
    check(!memcmp(ctx, &before, sizeof(before)), "collector preserves entire context");
    check(fegetround() == rounding && fetestexcept(FE_ALL_EXCEPT) == exceptions,
          "collector preserves host FP environment");
    ctx->memory = memory;
    hb_context_destroy(ctx);
}

static int has_native_block(const hb_jit_runtime_t *jit)
{
    if (!jit || !jit->block_cache) return 0;
    for (size_t i = 0; i < jit->block_cache->size; ++i) {
        const hb_block_cache_entry_t *e = &jit->block_cache->entries[i];
        if (e->valid && e->guest_addr == CODE && e->native_code && e->native_size) return 1;
    }
    return 0;
}

/* These two guest functions contain one scalar load and a helper RET. With
 * relaxed loads disabled, an in-block LDAR or LDR + DMB ISHLD is evidence of
 * native guest-memory emission; context loads do not use this sequence. */
static unsigned native_scalar_loads(const hb_jit_runtime_t *jit)
{
    unsigned loads = 0;
    if (!jit || !jit->block_cache) return 0;
    for (size_t i = 0; i < jit->block_cache->size; ++i) {
        const hb_block_cache_entry_t *e = &jit->block_cache->entries[i];
        if (!e->valid || e->guest_addr != CODE || !e->native_code) continue;
        const uint8_t *p = e->native_code;
        for (size_t at = 0; at + 4 <= e->native_size; at += 4) {
            uint32_t instruction, next = 0;
            memcpy(&instruction, p + at, 4);
            if (at + 8 <= e->native_size) memcpy(&next, p + at + 4, 4);
            uint32_t ldar = instruction & UINT32_C(0xfffffc00);
            uint32_t ldr = instruction & UINT32_C(0xffc00000);
            if (ldar == UINT32_C(0x88dffc00) || ldar == UINT32_C(0xc8dffc00) ||
                ((ldr == UINT32_C(0xb9400000) || ldr == UINT32_C(0xf9400000)) &&
                 next == UINT32_C(0xd50339bf))) ++loads;
        }
    }
    return loads;
}

static void execute_return(hb_context_t *ctx, const uint8_t *code, size_t length,
                           uint32_t kind, uint32_t width, uint64_t expected,
                           int observe_mxcsr, uint64_t stack, int scalar_memory,
                           int direct)
{
    hb_decoder_t *decoder = NULL;
    hb_ir_func_t *func = NULL;
    hb_interpreter_t *interp = NULL;
    hb_jit_runtime_t *jit = NULL;
    hb_exec_result_t execution = {0};
    hb_result_t result;
    uint64_t entry_rsp = ctx->regs.x64.rsp, out = SENTINEL;
    uint32_t mxcsr = ctx->mxcsr;
    /* Verify every candidate encoding with the actual decoder before lifting.
     * The literal independent output checks below also detect wrong lifting. */
    size_t offset = 0;
    hb_decoded_t decoded = {0};
    while (offset < length) {
        result = hb_decode_x64(code + offset, length - offset, CODE + offset, &decoded);
        if (!check(result == HB_OK && decoded.len && decoded.len <= length - offset,
                   "candidate guest bytes decode completely")) goto done;
        offset += decoded.len;
    }
    if (!check(decoded.opcode == HB_INS_RET, "guest function ends in decoded RET")) goto done;
    if (!check(hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES,
                                    HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map private code")) goto done;
    if (!check(hb_memory_write(ctx->memory, CODE, code, length) == HB_OK, "write code") ||
        !check(hb_memory_protect(ctx->memory, CODE, PAGE_BYTES,
                                 HB_PERM_READ | HB_PERM_EXEC) == HB_OK, "protect code")) goto done;
    decoder = hb_decoder_create(HB_ARCH_X64, code, length, CODE);
    if (!check(decoder && hb_lift_func_x64(decoder, &func) == HB_OK && func,
               "lift bounded guest function")) goto done;
    if (ctx->backend == HB_BACKEND_INTERP) {
        interp = hb_interpreter_create(ctx);
        if (!check(interp != NULL, "create interpreter")) goto done;
        result = hb_interpreter_run(interp, func, &execution);
    } else {
        jit = hb_jit_runtime_create(ctx);
        if (!check(jit != NULL, "create JIT")) goto done;
        result = hb_jit_runtime_run(jit, func, &execution);
        check(has_native_block(jit), "ARM64 JIT compiled the guest entry block");
        if (scalar_memory) {
            unsigned loads = native_scalar_loads(jit);
            check(direct ? loads != 0 : loads == 0,
                  "scalar memory emission matches explicit direct/helper gates");
            printf("scalar-memory: mapping=%s width=%u native-load-sequences=%u\n",
                   direct ? "identity/direct" : "private/helper", width, loads);
        }
    }
    if (!check(result == HB_OK && execution.result == HB_OK && !execution.faulted &&
               !execution.timed_out && execution.steps_executed && execution.blocks_executed,
               "guest execution completes without fault or budget stop")) goto done;
    if (!check(ctx->pc == RETURN_PC && ctx->regs.x64.rsp == entry_rsp + 8,
               "actual RET reaches controlled external PC and pops return slot")) goto done;
    check(hb_abi_x64_read_return_v1(ctx, kind, width, &out) == HB_OK, "collect only after normal return");
    check(out == expected, "guest return matches independent bit oracle");
    check(ctx->mxcsr == mxcsr, "data movement and preparation keep guest MXCSR");
    if (observe_mxcsr) {
        uint32_t stored = 0;
        check(hb_memory_read_u32(ctx->memory, stack + 0x100, &stored) == HB_OK,
              "read guest STMXCSR result");
        check(stored == mxcsr, "guest observes caller-controlled MXCSR");
    }
done:
    if (jit) hb_jit_runtime_destroy(jit);
    if (interp) hb_interpreter_destroy(interp);
    if (decoder) hb_decoder_destroy(decoder);
    if (func) hb_ir_func_destroy(func);
}

typedef struct {
    const char *name;
    enum hb_gate_id id;
    int follows_mapping;
    char *saved;
} memory_gate_t;

static memory_gate_t memory_gates[] = {
    {"MACRUNNER_HB_JIT_DIRECT_MEM", HB_GATE_HB_JIT_DIRECT_MEM, 1, NULL},
    {"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM", HB_GATE_HB_JIT_DIRECT_SCALAR_MEM, 1, NULL},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR", HB_GATE_HB_JIT_NATIVE_MEM_IR, 1, NULL},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS", HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS, 1, NULL},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64", HB_GATE_HB_JIT_DIRECT_STACK_X64, 0, NULL},
    {"MACRUNNER_HB_TSO_RELAXED_LOADS", HB_GATE_HB_TSO_RELAXED_LOADS, 0, NULL},
    {"MACRUNNER_HB_TSO_STACK_RELAXED", HB_GATE_HB_TSO_STACK_RELAXED, 0, NULL}
};

static int configure_memory_gates(int direct)
{
    int ok = 1;
    for (size_t i = 0; i < sizeof(memory_gates) / sizeof(memory_gates[0]); ++i)
        ok &= check(setenv(memory_gates[i].name,
                          direct && memory_gates[i].follows_mapping ? "1" : "0", 1) == 0,
                    "set explicit memory execution gate");
    hb_env_refresh();
    for (size_t i = 0; i < sizeof(memory_gates) / sizeof(memory_gates[0]); ++i) {
        const char *actual = hb_gate(memory_gates[i].id);
        const char *expected = direct && memory_gates[i].follows_mapping ? "1" : "0";
        ok &= check(actual && !strcmp(actual, expected), "effective refreshed memory gate");
    }
    return ok;
}

static void guest_calls_mapped(int direct)
{
    static const uint8_t mixed[] = {0x66,0x48,0x0f,0x7e,0xc8,0x48,0x31,0xc8,
        0x4c,0x31,0xc0,0x66,0x0f,0x7e,0xda,0x48,0x31,0xd0,0xc3};
    static const uint8_t f64_second[] = {0xf2,0x0f,0x10,0xc1,0xc3};
    static const uint8_t f32_fourth[] = {0xf3,0x0f,0x10,0xc3,0xc3};
    static const uint8_t f64_fifth[] = {0xf2,0x0f,0x10,0x44,0x24,0x28,0xc3};
    static const uint8_t f32_sixth[] = {0xf3,0x0f,0x10,0x44,0x24,0x30,0xc3};
    static const uint8_t integer[] = {0x48,0x89,0xc8,0xc3};
    static const uint8_t mxcsr[] = {0x0f,0xae,0x19,0xc3};
    const uint64_t gpr = UINT64_C(0xfedcba9876543281);
    const uint64_t nan64 = UINT64_C(0x7ff8000000001234);
    const uint64_t nan32 = UINT64_C(0x7fc54321);
    for (unsigned backend_index = 0; backend_index < 2; ++backend_index)
        for (unsigned which = 0; which < 8; ++which) {
            phase = backend_index ? (direct ? "guest JIT identity/direct" : "guest JIT private/helper")
                                  : (direct ? "guest interpreter identity" : "guest interpreter private");
            uint64_t stack = 0;
            hb_context_t *ctx = new_context_mapped(
                backend_index ? HB_BACKEND_JIT : HB_BACKEND_INTERP, direct, &stack);
            if (!ctx) return;
            hb_abi_x64_call_v1_t call = call_with_count(4);
            hb_abi_x64_value_v1_t tail[2] = {
                {HB_ABI_X64_F64_V1, 8, nan64}, {HB_ABI_X64_F32_V1, 4, UINT64_C(0xaabbccdd80000000)}
            };
            const uint8_t *code = mixed;
            size_t length = sizeof(mixed);
            uint32_t kind = HB_ABI_X64_GPR_V1, width = 8;
            uint64_t expected = 0;
            switch (which) {
                case 0:
                    call.slots[0] = value(HB_ABI_X64_GPR_V1, 8, gpr);
                    call.slots[1] = value(HB_ABI_X64_F64_V1, 8, nan64);
                    call.slots[2] = value(HB_ABI_X64_GPR_V1, 4, UINT64_C(0xeeeeeeee10203040));
                    call.slots[3] = value(HB_ABI_X64_F32_V1, 4, UINT64_C(0xbbbbbbbb7fc54321));
                    expected = gpr ^ nan64 ^ UINT64_C(0x10203040) ^ nan32;
                    break;
                case 1:
                    code = f64_second; length = sizeof(f64_second);
                    call.slots[1] = value(HB_ABI_X64_F64_V1, 8, nan64);
                    kind = HB_ABI_X64_F64_V1; expected = nan64; break;
                case 2: case 3:
                    code = f32_fourth; length = sizeof(f32_fourth);
                    expected = which == 2 ? nan32 : UINT64_C(0x80000000);
                    call.slots[3] = value(HB_ABI_X64_F32_V1, 4, expected | UINT64_C(0xabcdef0100000000));
                    kind = HB_ABI_X64_F32_V1; width = 4; break;
                case 4:
                    code = f64_fifth; length = sizeof(f64_fifth);
                    call = call_with_count(5); call.stack_args = tail;
                    kind = HB_ABI_X64_F64_V1; expected = nan64; break;
                case 5:
                    code = f32_sixth; length = sizeof(f32_sixth);
                    call = call_with_count(6); call.stack_args = tail;
                    kind = HB_ABI_X64_F32_V1; width = 4; expected = UINT64_C(0x80000000); break;
                case 6:
                    code = integer; length = sizeof(integer); call = call_with_count(1);
                    call.slots[0] = value(HB_ABI_X64_GPR_V1, 8, gpr); expected = gpr; break;
                case 7:
                    code = mxcsr; length = sizeof(mxcsr); call = call_with_count(1);
                    call.slots[0] = value(HB_ABI_X64_GPR_V1, 8, stack + 0x100);
                    kind = HB_ABI_X64_NONE_V1; width = 0; break;
            }
            if (expect_prepared_at(ctx, &call, stack))
                execute_return(ctx, code, length, kind, width, expected, which == 7,
                               stack, which == 4 || which == 5, direct);
            hb_context_destroy(ctx);
        }
}

static void append_u32(uint8_t *code, size_t *length, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) code[(*length)++] = (uint8_t)(value >> (8 * i));
}

/* Independent Win64 guest: capture arguments 1..18 at [RCX], then return one
 * selected scalar. Argument 0 is the output pointer. All tail loads/stores use
 * disp32: argument 15 starts at RSP+128, beyond positive signed disp8. */
static size_t callback_code(uint8_t code[512], unsigned return_kind)
{
    size_t n = 0;
    for (unsigned argument = 1; argument < 19; ++argument) {
        if (argument == 1) { /* MOVQ RAX,XMM1: F64 */
            const uint8_t op[] = {0x66,0x48,0x0f,0x7e,0xc8};
            memcpy(code + n, op, sizeof op); n += sizeof op;
        } else if (argument == 2) { /* MOV RAX,R8: GPR */
            const uint8_t op[] = {0x4c,0x89,0xc0};
            memcpy(code + n, op, sizeof op); n += sizeof op;
        } else if (argument == 3) { /* MOVD EAX,XMM3: ignore poisoned upper F32 bits */
            const uint8_t op[] = {0x66,0x0f,0x7e,0xd8};
            memcpy(code + n, op, sizeof op); n += sizeof op;
        } else { /* MOV RAX,[RSP+disp32] */
            const uint8_t op[] = {0x48,0x8b,0x84,0x24};
            memcpy(code + n, op, sizeof op); n += sizeof op;
            append_u32(code, &n, 40 + 8 * (argument - 4));
        }
        code[n++] = 0x48; code[n++] = 0x89; code[n++] = 0x81;
        append_u32(code, &n, 8 * (argument - 1)); /* MOV [RCX+disp32],RAX */
    }
    if (return_kind == HB_ABI_X64_GPR_V1) {
        const uint8_t op[] = {0x48,0x8b,0x84,0x24};
        memcpy(code + n, op, sizeof op); n += sizeof op;
        append_u32(code, &n, 152); /* argument 18 */
    } else {
        code[n++] = return_kind == HB_ABI_X64_F64_V1 ? 0xf2 : 0xf3;
        code[n++] = 0x0f; code[n++] = 0x10; code[n++] = 0x84; code[n++] = 0x24;
        append_u32(code, &n, return_kind == HB_ABI_X64_F64_V1 ? 144 : 128);
    }
    code[n++] = 0xc3;
    return n;
}

static void native_image_callbacks(int direct)
{
    /* Literal oracle in guest argument order; never derived by lower/raise or
     * by using one execution backend as the other's expected answer. */
    static const uint64_t expected[18] = {
        UINT64_C(0x7ff8000000001234), UINT64_C(0x0123456789abcdef),
        UINT64_C(0x80000000), UINT64_C(0x89abcdef),
        UINT64_C(0x8000000000000000), UINT64_C(0x80fe),
        UINT64_C(0x7fc54321), UINT64_C(0x81),
        UINT64_C(0x7ff0000000000000), UINT64_C(0xfedcba9876543210),
        UINT64_C(0x7f800000), UINT64_C(0x80000001),
        UINT64_C(0x3ff8000000000000), UINT64_C(0x1000000020000000),
        UINT64_C(0xffc01234), UINT64_C(0x8877665544332211),
        UINT64_C(0xfff8000000005678), UINT64_C(0x13579bdf2468ace0)
    };
    static const hb_abi_native_arg_v1_t arguments[19] = {
        {HB_ABI_X64_GPR_V1,8}, {HB_ABI_X64_F64_V1,8}, {HB_ABI_X64_GPR_V1,8},
        {HB_ABI_X64_F32_V1,4}, {HB_ABI_X64_GPR_V1,4}, {HB_ABI_X64_F64_V1,8},
        {HB_ABI_X64_GPR_V1,2}, {HB_ABI_X64_F32_V1,4}, {HB_ABI_X64_GPR_V1,1},
        {HB_ABI_X64_F64_V1,8}, {HB_ABI_X64_GPR_V1,8}, {HB_ABI_X64_F32_V1,4},
        {HB_ABI_X64_GPR_V1,4}, {HB_ABI_X64_F64_V1,8}, {HB_ABI_X64_GPR_V1,8},
        {HB_ABI_X64_F32_V1,4}, {HB_ABI_X64_GPR_V1,8}, {HB_ABI_X64_F64_V1,8},
        {HB_ABI_X64_GPR_V1,8}
    };
    for (unsigned backend_index = 0; backend_index < 2; ++backend_index)
        for (unsigned which = 0; which < 4; ++which) {
            int swap_control = which == 3;
            char label[96];
            snprintf(label, sizeof label, "native-image callback %s %s case=%u",
                     backend_index ? "JIT" : "interpreter", direct ? "direct" : "helper", which);
            phase = label;
            uint64_t stack = 0;
            hb_context_t *ctx = new_context_mapped(
                backend_index ? HB_BACKEND_JIT : HB_BACKEND_INTERP, direct, &stack);
            if (!ctx) return;
            ctx->step_limit = 256;
            /* Distinct values detect both clobbers and register permutations. */
            ctx->regs.x64.rbx = UINT64_C(0x1111222233334444);
            ctx->regs.x64.rbp = UINT64_C(0x2222333344445555);
            ctx->regs.x64.rsi = UINT64_C(0x3333444455556666);
            ctx->regs.x64.rdi = UINT64_C(0x4444555566667777);
            ctx->regs.x64.r12 = UINT64_C(0x5555666677778888);
            ctx->regs.x64.r13 = UINT64_C(0x6666777788889999);
            ctx->regs.x64.r14 = UINT64_C(0x777788889999aaaa);
            ctx->regs.x64.r15 = UINT64_C(0x88889999aaaabbbb);
            hb_abi_native_image_v1_t image = {
                .x = {0, UINT64_C(0x0123456789abcdef), UINT64_C(0xaabbccdd89abcdef),
                      UINT64_C(0x88776655443380fe), UINT64_C(0x123456789abcde81),
                      UINT64_C(0xfedcba9876543210), UINT64_C(0x1122334480000001),
                      UINT64_C(0x1000000020000000)},
                .d_bits = {UINT64_C(0x7ff8000000001234), UINT64_C(0xdeadbeef80000000),
                           UINT64_C(0x8000000000000000), UINT64_C(0xabcdef017fc54321),
                           UINT64_C(0x7ff0000000000000), UINT64_C(0x123456787f800000),
                           UINT64_C(0x3ff8000000000000), UINT64_C(0xbeefcafeffc01234)},
                .stack = {UINT64_C(0x8877665544332211), UINT64_C(0xfff8000000005678),
                          UINT64_C(0x13579bdf2468ace0)},
                .x_count = 8, .d_count = 8, .stack_count = 3
            };
            image.x[0] = stack + 0x100;
            if (swap_control) {
                image.stack[0] = UINT64_C(0x13579bdf2468ace0);
                image.stack[2] = UINT64_C(0x8877665544332211);
            }
            hb_abi_native_image_v1_t saved_image;
            memcpy(&saved_image, &image, sizeof image);
            uint32_t kind = which == 1 ? HB_ABI_X64_F64_V1 :
                            which == 2 ? HB_ABI_X64_F32_V1 : HB_ABI_X64_GPR_V1;
            uint32_t width = kind == HB_ABI_X64_F32_V1 ? 4 : 8;
            uint64_t result_bits = which == 1 ? UINT64_C(0xfff8000000005678) :
                                   which == 2 ? UINT64_C(0xffc01234) :
                                   swap_control ? UINT64_C(0x8877665544332211) :
                                                  UINT64_C(0x13579bdf2468ace0);
            hb_abi_native_sig_v1_t sig = {0};
            sig.abi_version = HB_ABI_NATIVE_V1;
            sig.struct_size = sizeof sig;
            sig.target_abi = HB_ABI_NATIVE_TARGET_AAPCS64_WIN_V1;
            sig.argument_count = 19;
            sig.ret = (hb_abi_native_arg_v1_t){kind, width};
            memcpy(sig.args, arguments, sizeof arguments);
            hb_abi_x64_call_v1_t call;
            hb_abi_x64_value_v1_t tail[15];
            uint64_t preserved_gpr[] = {ctx->regs.x64.rbx, ctx->regs.x64.rbp,
                ctx->regs.x64.rsi, ctx->regs.x64.rdi, ctx->regs.x64.r12,
                ctx->regs.x64.r13, ctx->regs.x64.r14, ctx->regs.x64.r15};
            uint64_t preserved_xmm[10][2];
            memcpy(preserved_xmm, &ctx->regs.x64.xmm[6], sizeof preserved_xmm);
            if (check(hb_abi_native_raise_v1(&image, &sig, RETURN_PC, &call, tail, 15) == HB_OK,
                      "raise explicit native image") &&
                check(hb_abi_x64_prepare_v1(ctx, CODE, &call) == HB_OK,
                      "prepare raised guest callback")) {
                check(ctx->regs.x64.rsp == stack + PAGE_BYTES - 168,
                      "19-argument frame has independently specified size/alignment");
                uint8_t code[512];
                size_t length = callback_code(code, kind);
                execute_return(ctx, code, length, kind, width, result_bits, 0, stack, 1, direct);
                unsigned mismatches = 0;
                for (unsigned i = 0; i < 18; ++i) {
                    uint64_t observed = SENTINEL;
                    check(hb_memory_read_u64(ctx->memory, stack + 0x100 + 8 * i, &observed) == HB_OK,
                          "read guest-captured argument");
                    int differs = observed != expected[i];
                    mismatches += differs;
                    check(differs == (swap_control && (i == 15 || i == 17)),
                          "guest observes the independent positional bit oracle");
                }
                check(mismatches == (swap_control ? 2u : 0u),
                      "spill-swap control is detected at exactly the two changed arguments");
                const uint64_t guard_addresses[] = {stack + 0xf8, stack + 0x190};
                for (unsigned i = 0; i < 2; ++i) {
                    uint64_t guard = 0;
                    check(hb_memory_read_u64(ctx->memory, guard_addresses[i], &guard) == HB_OK,
                          "read guard adjacent to captured arguments");
                    check(guard == UINT64_C(0xa5a5a5a5a5a5a5a5),
                          "guest capture leaves adjacent guards unchanged");
                }
                uint64_t after_gpr[] = {ctx->regs.x64.rbx, ctx->regs.x64.rbp,
                    ctx->regs.x64.rsi, ctx->regs.x64.rdi, ctx->regs.x64.r12,
                    ctx->regs.x64.r13, ctx->regs.x64.r14, ctx->regs.x64.r15};
                check(!memcmp(preserved_gpr, after_gpr, sizeof after_gpr),
                      "guest nonvolatile GPR canaries survive callback");
                check(!memcmp(preserved_xmm, &ctx->regs.x64.xmm[6], sizeof preserved_xmm),
                      "guest nonvolatile XMM canaries survive callback");
                printf("native-image-callback: backend=%s mapping=%s return=%u swap=%d mismatches=%u\n",
                       backend_index ? "JIT" : "interpreter", direct ? "direct" : "helper",
                       kind, swap_control, mismatches);
            }
            check(!memcmp(&saved_image, &image, sizeof image), "native input image remains unchanged");
            hb_context_destroy(ctx);
        }
    phase = "native-image callback cleanup";
}

#include "hb_native_callback_capture.inc"
#include "hb_nested_callback_boundary.inc"

static uint64_t callback_entry_hits(const hb_jit_runtime_t *jit)
{
    if (!jit || !jit->block_cache) return 0;
    for (size_t i = 0; i < jit->block_cache->size; ++i) {
        const hb_block_cache_entry_t *entry = &jit->block_cache->entries[i];
        if (entry->valid && entry->guest_addr == CODE && entry->native_code)
            return entry->hit_count;
    }
    return 0;
}

static void reused_native_callbacks(int direct)
{
    /* Cache hit_count is diagnostic and only advances with this trace gate.
     * Enable it explicitly for the reuse witness and restore caller settings. */
    const char *hot_setting = getenv("MACRUNNER_HB_TRACE_JIT_HOT_BLOCKS");
    char *saved_hot = hot_setting ? strdup(hot_setting) : NULL;
    if (!check(!hot_setting || saved_hot, "save cache-witness trace setting")) return;
    if (!check(setenv("MACRUNNER_HB_TRACE_JIT_HOT_BLOCKS", "1", 1) == 0,
               "enable cache-witness trace counter")) { free(saved_hot); return; }
    hb_env_refresh();
    const char *effective_hot = hb_gate(HB_GATE_HB_TRACE_JIT_HOT_BLOCKS);
    check(effective_hot && !strcmp(effective_hot, "1"), "cache-witness trace counter is effective");
    /* Block 1 increments a persistent call counter; block 2 captures the five
     * scalar payloads and returns F64. Replaying block 1 during resume is visible.
     * This is a block-boundary budget stop, not a wall-clock timeout or a claim
     * that the interpreter supports generic mid-block resume. */
    static const uint8_t code[] = {
        0x48,0x8b,0x01,                  /* mov rax,[rcx] */
        0x48,0x83,0xc0,0x01,             /* add rax,1 */
        0x48,0x89,0x01,                  /* mov [rcx],rax */
        0xeb,0x00,                       /* jmp CODE+12 */
        0x66,0x48,0x0f,0x7e,0xc8,       /* movq rax,xmm1 */
        0x48,0x89,0x41,0x08,             /* capture F64 */
        0x4c,0x89,0x41,0x10,             /* capture GPR32 from r8 */
        0x66,0x0f,0x7e,0xd8,             /* movd eax,xmm3 */
        0x48,0x89,0x41,0x18,             /* capture F32 */
        0x48,0x8b,0x44,0x24,0x28,       /* mov rax,[rsp+40] */
        0x48,0x89,0x41,0x20,             /* capture GPR16 */
        0xf2,0x0f,0x10,0x44,0x24,0x30,  /* movsd xmm0,[rsp+48] */
        0x66,0x48,0x0f,0x7e,0xc0,       /* movq rax,xmm0 */
        0x48,0x89,0x41,0x28,             /* capture returned F64 */
        0xc3
    };
    static const struct {
        uint64_t f64;
        uint32_t gpr32, f32;
        uint16_t gpr16;
        uint64_t returned;
    } rows[] = {
        {UINT64_C(0x3ff8000000000000),0x10203040,0x80000000,0x807f,UINT64_C(0x7ff8000000001234)},
        {UINT64_C(0x8000000000000000),0x89abcdef,0x7fc54321,0xabcd,UINT64_C(0x8000000000000000)},
        {UINT64_C(0x7ff0000000000000),0x80000001,0x7f800000,0xffff,UINT64_C(0xfff8000000005678)},
        {UINT64_C(0xfff0000000000000),7,0xbf800000,0x1234,UINT64_C(0x3ff8000000000000)},
        {UINT64_C(0x7ff800000000abcd),0xdeadbeef,1,0x42,UINT64_C(0x0000000000000000)}
    };
    for (unsigned backend_index = 0; backend_index < 2; ++backend_index) {
        phase = backend_index ? "reused callback JIT" : "reused callback interpreter";
        uint64_t stack = 0;
        hb_context_t *ctx = new_context_mapped(
            backend_index ? HB_BACKEND_JIT : HB_BACKEND_INTERP, direct, &stack);
        hb_ir_builder_t *builder = NULL;
        hb_ir_func_t *func = NULL;
        hb_interpreter_t *interp = NULL;
        hb_jit_runtime_t *jit = NULL;
        hb_ir_block_t *continuation = NULL;
        hb_exec_result_t execution = {0}; /* Same result object across all calls. */
        if (!ctx) break;
        ctx->step_limit = 256;
        uint64_t *nonvolatile[] = {&ctx->regs.x64.rbx,&ctx->regs.x64.rbp,
            &ctx->regs.x64.rsi,&ctx->regs.x64.rdi,&ctx->regs.x64.r12,
            &ctx->regs.x64.r13,&ctx->regs.x64.r14,&ctx->regs.x64.r15};
        uint64_t saved_gpr[8], saved_xmm[10][2];
        for (unsigned i = 0; i < 8; ++i)
            saved_gpr[i] = *nonvolatile[i] = UINT64_C(0x1234567890abc000) + 0x101 * i;
        memcpy(saved_xmm, &ctx->regs.x64.xmm[6], sizeof saved_xmm);
        uint32_t saved_mxcsr = ctx->mxcsr;
        uint64_t zero = 0;
        if (!check(hb_memory_write(ctx->memory, stack + 0x100, &zero, 8) == HB_OK,
                   "initialize persistent callback counter") ||
            !check(hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES,
                                          HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
                   "map callback code once") ||
            !check(hb_memory_write(ctx->memory, CODE, code, sizeof code) == HB_OK,
                   "write callback code once") ||
            !check(hb_memory_protect(ctx->memory, CODE, PAGE_BYTES,
                                      HB_PERM_READ | HB_PERM_EXEC) == HB_OK,
                   "protect callback code once")) goto reuse_done;
        /* The production unit lifter stops at an unconditional JMP. Define
         * this two-block fixture explicitly, but decode/lift every raw guest
         * instruction with the normal APIs and one shared temporary namespace. */
        func = hb_ir_func_create(CODE, sizeof code);
        if (!check(func != NULL, "create two-block callback fixture")) goto reuse_done;
        hb_ir_block_t *entry = hb_ir_block_create(0, CODE);
        if (!check(entry != NULL, "create callback entry block")) goto reuse_done;
        hb_ir_cfg_add_block(func->cfg, entry);
        func->cfg->entry = entry;
        continuation = hb_ir_block_create(1, CODE + 12);
        if (!check(continuation != NULL, "create callback continuation block")) goto reuse_done;
        hb_ir_cfg_add_block(func->cfg, continuation);
        builder = hb_ir_builder_create(func);
        if (!check(builder != NULL, "create shared callback IR builder")) goto reuse_done;
        hb_ir_builder_set_block(builder, entry);
        for (size_t at = 0; at < sizeof code;) {
            hb_decoded_t decoded = {0};
            if (at == 12) hb_ir_builder_set_block(builder, continuation);
            if (!check(hb_decode_x64(code + at, sizeof code - at, CODE + at, &decoded) == HB_OK &&
                       decoded.len && decoded.len <= sizeof code - at,
                       "decode each reused callback instruction") ||
                !check(hb_lift_x64(&decoded, builder) == HB_OK,
                       "lift each reused callback instruction")) goto reuse_done;
            at += decoded.len;
        }
        hb_ir_builder_destroy(builder);
        builder = NULL;
        if (!check(func->cfg->block_count == 2 && entry->instr_count && continuation->instr_count,
                   "budget continuation is a distinct populated block")) goto reuse_done;
        if (backend_index) jit = hb_jit_runtime_create(ctx);
        else interp = hb_interpreter_create(ctx);
        if (!check(jit || interp, "create one executor for the whole call sequence")) goto reuse_done;
        for (unsigned round = 0; round < (backend_index ? 5u : 4u); ++round) {
            int reset_control = round == 4;
            if (reset_control) {
                hb_jit_runtime_reset(jit, ctx);
                check(jit->ctx == ctx && jit->block_cache->count == 0 && !has_native_block(jit),
                      "runtime reset clears translations but keeps the same guest context");
            }
            uint64_t entry_hits = callback_entry_hits(jit);
            if (jit && round && !reset_control)
                check(has_native_block(jit) && entry_hits > 0, "warm entry exists before next call");
            const uint64_t output = stack + 0x100;
            const uint64_t return_pc = RETURN_PC + 0x100 * round;
            uint64_t prior_payloads[5];
            if (!check(hb_memory_read(ctx->memory, output + 8, prior_payloads, sizeof prior_payloads) == HB_OK,
                       "snapshot output before fresh callback")) goto reuse_done;
            hb_abi_native_sig_v1_t sig = {
                .abi_version = HB_ABI_NATIVE_V1, .struct_size = sizeof sig,
                .target_abi = HB_ABI_NATIVE_TARGET_AAPCS64_WIN_V1, .argument_count = 6,
                .ret = {HB_ABI_X64_F64_V1,8},
                .args = {{HB_ABI_X64_GPR_V1,8},{HB_ABI_X64_F64_V1,8},{HB_ABI_X64_GPR_V1,4},
                         {HB_ABI_X64_F32_V1,4},{HB_ABI_X64_GPR_V1,2},{HB_ABI_X64_F64_V1,8}}
            };
            hb_abi_native_image_v1_t image = {
                .x = {output, UINT64_C(0xaabbccdd00000000) | rows[round].gpr32,
                              UINT64_C(0x1122334455660000) | rows[round].gpr16},
                .d_bits = {rows[round].f64, UINT64_C(0xdeadbeef00000000) | rows[round].f32,
                           rows[round].returned},
                .x_count = 3, .d_count = 3
            };
            hb_abi_x64_call_v1_t call;
            hb_abi_x64_value_v1_t tail[2];
            /* Caller releases its previous frame before a NEW call. Resume
             * below does neither this cleanup nor another prepare. */
            ctx->regs.x64.rsp = stack + PAGE_BYTES;
            ctx->block_limit = round == 2 ? 1 : 8;
            if (!check(hb_abi_native_raise_v1(&image, &sig, return_pc, &call, tail, 2) == HB_OK,
                       "raise changed arguments on reused context") ||
                !check(hb_abi_x64_prepare_v1(ctx, CODE, &call) == HB_OK,
                       "prepare a fresh frame on reused context")) goto reuse_done;
            const uint64_t entry_rsp = stack + PAGE_BYTES - 56;
            check(ctx->regs.x64.rsp == entry_rsp && ctx->pc == CODE,
                  "fresh call replaces prior return PC and restores entry frame");
            hb_result_t result = jit ? hb_jit_runtime_run(jit, func, &execution)
                                     : hb_interpreter_run(interp, func, &execution);
            if (round == 2) {
                if (!check(result == HB_ERR_BLOCK_LIMIT && execution.result == HB_ERR_BLOCK_LIMIT &&
                           execution.faulted && !execution.timed_out && execution.blocks_executed == 1,
                           "controlled block-budget stop reports the current result")) goto reuse_done;
                check(ctx->pc == CODE + 12 && ctx->regs.x64.rip == CODE + 12 &&
                      ctx->regs.x64.rsp == entry_rsp, "budget stop keeps the continuation PC and unpopped frame");
                uint64_t counter = 0, stopped_payloads[5];
                check(hb_memory_read_u64(ctx->memory, output, &counter) == HB_OK && counter == 3,
                      "first block ran exactly once before pause");
                check(hb_memory_read(ctx->memory, output + 8, stopped_payloads, sizeof stopped_payloads) == HB_OK &&
                      !memcmp(prior_payloads, stopped_payloads, sizeof prior_payloads),
                      "second block has not executed before pause");
                uint64_t paused_hits = callback_entry_hits(jit);
                ctx->block_limit = 8;
                result = jit ? hb_jit_runtime_run(jit, func, &execution)
                             : hb_interpreter_run_from(interp, func, continuation, &execution);
                if (jit) check(callback_entry_hits(jit) == paused_hits,
                               "resume does not redispatch the entry block");
            }
            if (!check(result == HB_OK && execution.result == HB_OK && !execution.faulted &&
                       !execution.timed_out && execution.steps_executed && execution.blocks_executed,
                       "reused execution returns with fresh success metadata")) goto reuse_done;
            check(ctx->pc == return_pc && ctx->regs.x64.rsp == entry_rsp + 8,
                  "actual reused RET reaches this call's return address and pops once");
            uint64_t returned = SENTINEL, observed[6] = {0};
            check(hb_abi_x64_read_return_v1(ctx, HB_ABI_X64_F64_V1, 8, &returned) == HB_OK &&
                  returned == rows[round].returned, "return value is from this call, not the previous one");
            const uint64_t expected[] = {round + 1, rows[round].f64, rows[round].gpr32,
                                        rows[round].f32, rows[round].gpr16, rows[round].returned};
            check(hb_memory_read(ctx->memory, output, observed, sizeof observed) == HB_OK &&
                  !memcmp(expected, observed, sizeof expected), "counter and every payload match this call");
            for (unsigned i = 0; i < 8; ++i)
                check(*nonvolatile[i] == saved_gpr[i], "reused callback preserves each nonvolatile GPR");
            check(!memcmp(saved_xmm, &ctx->regs.x64.xmm[6], sizeof saved_xmm),
                  "reused callback preserves nonvolatile XMM state");
            check(ctx->mxcsr == saved_mxcsr, "reused callback preserves MXCSR");
            for (unsigned i = 0; i < 2; ++i) {
                uint64_t guard = 0;
                check(hb_memory_read_u64(ctx->memory, output + (i ? 48 : -8), &guard) == HB_OK &&
                      guard == UINT64_C(0xa5a5a5a5a5a5a5a5), "reused callback preserves output guards");
            }
            if (jit) check(has_native_block(jit) && callback_entry_hits(jit) > entry_hits,
                           "same runtime records another dispatch of the cached entry");
            printf("reused-native-callback: backend=%s mapping=%s round=%u resumed=%d reset=%d counter=%llu last_result=%d\n",
                   jit ? "JIT" : "interpreter", direct ? "direct" : "helper", round,
                   round == 2, reset_control, (unsigned long long)observed[0], (int)ctx->last_result);
        }
reuse_done:
        if (jit) hb_jit_runtime_destroy(jit);
        if (interp) hb_interpreter_destroy(interp);
        if (builder) hb_ir_builder_destroy(builder);
        if (func) hb_ir_func_destroy(func);
        hb_context_destroy(ctx);
    }
    phase = "restore cache-witness trace setting";
    check((saved_hot ? setenv("MACRUNNER_HB_TRACE_JIT_HOT_BLOCKS", saved_hot, 1)
                     : unsetenv("MACRUNNER_HB_TRACE_JIT_HOT_BLOCKS")) == 0,
          "restore original cache-witness trace setting");
    hb_env_refresh();
    effective_hot = hb_gate(HB_GATE_HB_TRACE_JIT_HOT_BLOCKS);
    check(saved_hot ? effective_hot && !strcmp(saved_hot, effective_hot) : effective_hot == NULL,
          "restored trace setting is effective");
    free(saved_hot);
}

static void guest_calls(void)
{
    size_t count = sizeof(memory_gates) / sizeof(memory_gates[0]);
    size_t saved = 0;
    for (; saved < count; ++saved) {
        const char *value = getenv(memory_gates[saved].name);
        if (value && !(memory_gates[saved].saved = strdup(value))) {
            check(0, "save original environment"); goto cleanup;
        }
    }
    /* Direct x64 codegen assumes identity addresses. Private mappings require
     * explicit helper gates; the engine does not currently validate this. */
    for (int direct = 0; direct <= 1; ++direct) {
        phase = "guest memory configuration";
        if (configure_memory_gates(direct)) {
            guest_calls_mapped(direct);
            native_image_callbacks(direct);
            reused_native_callbacks(direct);
            host_captured_callbacks(direct);
            nested_callback_boundaries(direct);
        }
    }
    phase = "restore guest memory configuration";
    for (size_t i = 0; i < count; ++i)
        check((memory_gates[i].saved ? setenv(memory_gates[i].name, memory_gates[i].saved, 1)
                                    : unsetenv(memory_gates[i].name)) == 0,
              "restore original environment value/presence");
    hb_env_refresh();
    for (size_t i = 0; i < count; ++i) {
        const char *actual = hb_gate(memory_gates[i].id);
        check(memory_gates[i].saved ? actual && !strcmp(actual, memory_gates[i].saved)
                                   : actual == NULL,
              "effective gates restored");
    }
cleanup:
    for (size_t i = 0; i < saved; ++i) {
        free(memory_gates[i].saved);
        memory_gates[i].saved = NULL;
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    preparation_values();
    preparation_errors();
    aliased_inputs();
    late_write_failure();
    return_collection();
    guest_calls();
    printf("hb_abi_x64_v1_test: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
