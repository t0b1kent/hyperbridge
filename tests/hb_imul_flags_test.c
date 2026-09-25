/* MacRunner 2026-08-02 — regression test for the two/three-operand IMUL flag write.
 *
 * The defect: codegen_instr emits no inline code for MUL/IMUL — it always calls
 * hb_jit_helper_exec_mul_div_operand — and that helper's `imul r, r/m[, imm]` branch wrote the
 * result, then called hb_lazy_flags_clear() without ever setting CF/OF. Clearing the lazy record
 * declares ctx->flags authoritative, so CF/OF kept the PREVIOUS instruction's values and were
 * believed. .NET compiles `checked(a*b)` to imul + jo, so a stale OF threw OverflowException out
 * of arithmetic that never overflowed — the wall under UnityEngine.Resources:Load.
 *
 * Measured exposure before the fix: 17.5 % of 458 752 IMULs in one HK boot carried a false OF.
 *
 * The load-bearing case here is NO_OVERFLOW_WITH_POISONED_OF: flags are pre-set to 1, the multiply
 * does not overflow, and OF must come back 0. That is exactly what the old code got wrong, and a
 * test that only checked genuine overflows would have passed against the bug.
 *
 * The oracle is computed here with __int128 rather than by calling the engine, so the test cannot
 * agree with the implementation by sharing its mistake.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "hb_context.h"
#include "hb_ir.h"

extern void hb_jit_helper_exec_mul_div_operand(hb_context_t* ctx, const hb_ir_instr_t* instr);

static int g_failures;

static uint64_t trunc_to(uint64_t v, hb_size_t size) {
    switch (size) {
    case HB_SIZE_8:  return v & 0xffull;
    case HB_SIZE_16: return v & 0xffffull;
    case HB_SIZE_32: return v & 0xffffffffull;
    default:         return v;
    }
}

static int64_t sext_from(uint64_t v, hb_size_t size) {
    switch (size) {
    case HB_SIZE_8:  return (int64_t)(int8_t)v;
    case HB_SIZE_16: return (int64_t)(int16_t)v;
    case HB_SIZE_32: return (int64_t)(int32_t)v;
    default:         return (int64_t)v;
    }
}

/* Independent oracle: x86 sets CF=OF when the full signed product does not fit the destination. */
static int oracle_overflow(uint64_t lhs, uint64_t rhs, hb_size_t size) {
    __int128 full = (__int128)sext_from(trunc_to(lhs, size), size) *
                    (__int128)sext_from(trunc_to(rhs, size), size);
    __int128 fitted = (__int128)sext_from(trunc_to((uint64_t)full, size), size);
    return full != fitted;
}

static void check(const char* name, uint64_t lhs, uint64_t rhs, hb_size_t size, int poison) {
    hb_context_t ctx;
    hb_ir_instr_t instr;
    int expect, got;

    memset(&ctx, 0, sizeof(ctx));
    ctx.arch = HB_ARCH_X64;
    ctx.regs.x64.rax = lhs;
    ctx.regs.x64.rcx = rhs;
    /* Poison every status flag the multiply must define: a passing test has to prove the value was
     * WRITTEN, not merely that it happened to already be right. */
    ctx.flags.cf = ctx.flags.of = (uint8_t)(poison ? 1 : 0);

    memset(&instr, 0, sizeof(instr));
    instr.op = HB_IR_IMUL;
    instr.dst.type  = HB_OP_REG; instr.dst.size  = size; instr.dst.reg  = HB_REG_RAX;
    instr.src1.type = HB_OP_REG; instr.src1.size = size; instr.src1.reg = HB_REG_RAX;
    instr.src2.type = HB_OP_REG; instr.src2.size = size; instr.src2.reg = HB_REG_RCX;

    hb_jit_helper_exec_mul_div_operand(&ctx, &instr);

    expect = oracle_overflow(lhs, rhs, size);
    got = ctx.flags.of ? 1 : 0;
    if (got != expect) {
        printf("  FAIL %-34s size=%d lhs=0x%llx rhs=0x%llx poison=%d  of=%d expected=%d\n",
               name, (int)size, (unsigned long long)lhs, (unsigned long long)rhs, poison,
               got, expect);
        g_failures++;
        return;
    }
    if ((ctx.flags.cf ? 1 : 0) != expect) {
        printf("  FAIL %-34s CF disagrees with OF (cf=%d of=%d)\n",
               name, ctx.flags.cf ? 1 : 0, got);
        g_failures++;
        return;
    }
    printf("  ok   %-34s size=%d poison=%d of=%d\n", name, (int)size, poison, got);
}

int main(void) {
    printf("hb_imul_flags_test: two/three-operand IMUL must define CF/OF\n");

    /* THE regression case: no overflow, flags pre-poisoned to 1 -> must be cleared to 0. */
    check("no_overflow_poisoned/32",      3, 5,                    HB_SIZE_32, 1);
    check("no_overflow_poisoned/64",      3, 5,                    HB_SIZE_64, 1);
    check("no_overflow_poisoned/16",      3, 5,                    HB_SIZE_16, 1);
    check("no_overflow_poisoned/8",       3, 5,                    HB_SIZE_8,  1);

    /* Genuine overflow must still be reported, from clean and from poisoned flags alike. */
    check("overflow_clean/32",            0x7fffffffull, 2,        HB_SIZE_32, 0);
    check("overflow_poisoned/32",         0x7fffffffull, 2,        HB_SIZE_32, 1);
    check("overflow_clean/64",            0x7fffffffffffffffull, 2, HB_SIZE_64, 0);

    /* FNV-1a style hash mixing: the pattern actually seen overflowing in the HK boot. */
    check("fnv_prime_mix/32",             0xd47a1f3cull, 16777619, HB_SIZE_32, 0);

    /* Signed edges: negative operands, and the one product that fits exactly. */
    check("neg_times_pos_no_overflow/32", (uint64_t)(int64_t)-3, 5, HB_SIZE_32, 1);
    check("int_min_times_one/32",         0x80000000ull, 1,        HB_SIZE_32, 1);
    check("int_min_times_minus_one/32",   0x80000000ull, (uint64_t)(int64_t)-1, HB_SIZE_32, 0);
    check("zero_times_garbage/64",        0, 0xdeadbeefcafebabeull, HB_SIZE_64, 1);

    if (g_failures) {
        printf("hb_imul_flags_test: %d FAILURE(S)\n", g_failures);
        return 1;
    }
    printf("hb_imul_flags_test: all checks passed\n");
    return 0;
}
