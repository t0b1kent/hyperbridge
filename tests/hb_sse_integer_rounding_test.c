/* Raw SSE/VEX signed float-to-integer conversions with independent bit/answer
 * tables. Guest MXCSR exceptions are masked. This tests numerical rounding and
 * host fenv isolation, not guest exception status, DAZ/FTZ, or unmasked faults.
 * JIT entry presence proves native block execution, not native FP lowering.
 * Each instruction form is lifted once and reuses its context/runtime.
 */
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <fenv.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_BYTES = 16384 };
static const uint64_t CODE = UINT64_C(0x4000000);
static const uint64_t DATA = UINT64_C(0x8000000);
static unsigned checks, failures, executions;
static unsigned host_fenv_failures, host_round_failures, host_status_failures;
static unsigned architecture_failures, completion_failures, memory_failures;
static char phase[192] = "setup";

static int check(int ok, const char *message)
{
    ++checks;
    if (!ok) {
        ++failures;
        if (failures <= 80) fprintf(stderr, "FAIL %s: %s\n", phase, message);
    }
    return ok;
}

typedef struct {
    const char *name;
    uint32_t single;
    uint64_t dbl;
    int64_t single_answer[4], double_answer[4]; /* nearest, down, up, zero */
    int indefinite64;
} sample_t;

#define SAME(n, s, d, a, b, c, e) \
    {n, UINT32_C(s), UINT64_C(d), {a,b,c,e}, {a,b,c,e}, 0}
#define SPLIT(n, s, d, a, b) \
    {n, UINT32_C(s), UINT64_C(d), {a,a,a,a}, {b,b,b,b}, 0}
#define INDEFINITE(n, s, d) \
    {n, UINT32_C(s), UINT64_C(d), {0,0,0,0}, {0,0,0,0}, 1}
static const sample_t samples[] = {
    SAME("+0", 0x00000000, 0x0000000000000000, 0,0,0,0),
    SAME("-0", 0x80000000, 0x8000000000000000, 0,0,0,0),
    SAME("+0.5", 0x3f000000, 0x3fe0000000000000, 0,0,1,0),
    SAME("-0.5", 0xbf000000, 0xbfe0000000000000, 0,-1,0,0),
    SAME("+1.5", 0x3fc00000, 0x3ff8000000000000, 2,1,2,1),
    SAME("-1.5", 0xbfc00000, 0xbff8000000000000, -2,-2,-1,-1),
    SAME("+2.5", 0x40200000, 0x4004000000000000, 2,2,3,2),
    SAME("-2.5", 0xc0200000, 0xc004000000000000, -2,-3,-2,-2),
    SAME("+3.5", 0x40600000, 0x400c000000000000, 4,3,4,3),
    SAME("-3.5", 0xc0600000, 0xc00c000000000000, -4,-4,-3,-3),
    SAME("below +2.5", 0x401fffff, 0x4003ffffffffffff, 2,2,3,2),
    SAME("above +2.5", 0x40200001, 0x4004000000000001, 3,2,3,2),
    SAME("above -2.5", 0xc01fffff, 0xc003ffffffffffff, -2,-3,-2,-2),
    SAME("below -2.5", 0xc0200001, 0xc004000000000001, -3,-3,-2,-2),
    SAME("below +0.5", 0x3effffff, 0x3fdfffffffffffff, 0,0,1,0),
    SAME("above +0.5", 0x3f000001, 0x3fe0000000000001, 1,0,1,0),
    SAME("+2^31", 0x4f000000, 0x41e0000000000000, INT64_C(2147483648),INT64_C(2147483648),INT64_C(2147483648),INT64_C(2147483648)),
    SAME("-2^31", 0xcf000000, 0xc1e0000000000000, -INT64_C(2147483648),-INT64_C(2147483648),-INT64_C(2147483648),-INT64_C(2147483648)),
    SPLIT("largest integer below +2^31", 0x4effffff, 0x41dfffffffc00000, INT64_C(2147483520),INT64_C(2147483647)),
    SPLIT("last float below +2^63", 0x5effffff, 0x43dfffffffffffff, INT64_C(9223371487098961920),INT64_C(9223372036854774784)),
    SAME("-2^63", 0xdf000000, 0xc3e0000000000000, INT64_MIN,INT64_MIN,INT64_MIN,INT64_MIN),
    INDEFINITE("+2^63", 0x5f000000, 0x43e0000000000000),
    INDEFINITE("+infinity", 0x7f800000, 0x7ff0000000000000),
    INDEFINITE("-infinity", 0xff800000, 0xfff0000000000000),
    INDEFINITE("quiet NaN payload", 0x7fc12345, 0x7ff8123456789abc),
    INDEFINITE("signaling NaN payload", 0x7f812345, 0x7ff0123456789abc),
    {"last positive fractional precision boundary", UINT32_C(0x4affffff), UINT64_C(0x432fffffffffffff),
     {8388608,8388607,8388608,8388607},
     {INT64_C(4503599627370496),INT64_C(4503599627370495),INT64_C(4503599627370496),INT64_C(4503599627370495)}, 0},
    {"last negative fractional precision boundary", UINT32_C(0xcaffffff), UINT64_C(0xc32fffffffffffff),
     {-8388608,-8388608,-8388607,-8388607},
     {-INT64_C(4503599627370496),-INT64_C(4503599627370496),-INT64_C(4503599627370495),-INT64_C(4503599627370495)}, 0},
    SAME("smallest positive subnormal", 0x00000001, 0x0000000000000001, 0,0,1,0),
    SAME("smallest negative subnormal", 0x80000001, 0x8000000000000001, 0,-1,0,0)
};
#undef SAME
#undef SPLIT
#undef INDEFINITE

typedef struct {
    const char *name;
    int scalar, dbl, wide, truncate, vex, memory, compact;
} form_t;

static const form_t forms[] = {
    {"cvtss2si eax,xmm1", 1,0,0,0,0,0,0},
    {"cvtss2si rax,xmm1", 1,0,1,0,0,0,0},
    {"cvtsd2si eax,xmm1", 1,1,0,0,0,0,0},
    {"cvtsd2si rax,xmm1", 1,1,1,0,0,0,0},
    {"cvttss2si eax,xmm1", 1,0,0,1,0,0,0},
    {"cvttss2si rax,xmm1", 1,0,1,1,0,0,0},
    {"cvttsd2si eax,xmm1", 1,1,0,1,0,0,0},
    {"cvttsd2si rax,xmm1", 1,1,1,1,0,0,0},
    {"cvtps2dq xmm0,xmm1", 0,0,0,0,0,0,0},
    {"cvttps2dq xmm0,xmm1", 0,0,0,1,0,0,0},
    {"cvtpd2dq xmm0,xmm1", 0,1,0,0,0,0,0},
    {"cvttpd2dq xmm0,xmm1", 0,1,0,1,0,0,0},
    {"cvtss2si eax,[rcx]", 1,0,0,0,0,1,1},
    {"cvtsd2si rax,[rcx]", 1,1,1,0,0,1,1},
    {"vcvtss2si eax,xmm1", 1,0,0,0,1,0,1},
    {"vcvtsd2si rax,xmm1", 1,1,1,0,1,0,1},
    {"vcvtps2dq xmm0,xmm1", 0,0,0,0,1,0,1},
    {"vcvttpd2dq xmm0,xmm1", 0,1,0,1,1,0,1}
};

static size_t encode(const form_t *f, uint8_t code[8], int *opcode)
{
    size_t n = 0;
    unsigned prefix, op;
    if (f->scalar) {
        prefix = f->dbl ? 0xf2 : 0xf3;
        op = f->truncate ? 0x2c : 0x2d;
        *opcode = f->dbl ? (f->truncate ? HB_INS_CVTTSD2SI : HB_INS_CVTSD2SI)
                         : (f->truncate ? HB_INS_CVTTSS2SI : HB_INS_CVTSS2SI);
    } else if (f->dbl) {
        prefix = f->truncate ? 0x66 : 0xf2; op = 0xe6;
        *opcode = f->truncate ? HB_INS_CVTTPD2DQ : HB_INS_CVTPD2DQ;
    } else {
        prefix = f->truncate ? 0xf3 : 0x66; op = 0x5b;
        *opcode = f->truncate ? HB_INS_CVTTPS2DQ : HB_INS_CVTPS2DQ;
    }
    if (f->vex) {
        unsigned pp = prefix == 0x66 ? 1 : prefix == 0xf3 ? 2 : 3;
        if (f->wide) { code[n++] = 0xc4; code[n++] = 0xe1; code[n++] = 0xf8 | pp; }
        else { code[n++] = 0xc5; code[n++] = 0xf8 | pp; }
    } else {
        code[n++] = prefix;
        if (f->wide) code[n++] = 0x48;
        code[n++] = 0x0f;
    }
    code[n++] = op; code[n++] = f->memory ? 0x01 : 0xc1;
    return n;
}

static int native_entry_present(const hb_jit_runtime_t *jit)
{
    if (!jit || !jit->block_cache) return 0;
    for (size_t i = 0; i < jit->block_cache->size; ++i) {
        const hb_block_cache_entry_t *e = &jit->block_cache->entries[i];
        if (e->valid && e->guest_addr == CODE && e->native_code && e->native_size) return 1;
    }
    return 0;
}

static void put_bits(uint8_t *p, uint64_t bits, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i) p[i] = (uint8_t)(bits >> (8 * i));
}

static uint64_t answer(const sample_t *s, const form_t *f, unsigned rc)
{
    int64_t value = (f->dbl ? s->double_answer : s->single_answer)[f->truncate ? 3 : rc];
    if (f->wide) return s->indefinite64 ? UINT64_C(0x8000000000000000) : (uint64_t)value;
    if (s->indefinite64 || value < INT32_MIN || value > INT32_MAX) return UINT32_C(0x80000000);
    return (uint32_t)value;
}

static void seed(hb_context_t *ctx, unsigned rc)
{
    memset(&ctx->regs, 0x3c, sizeof(ctx->regs));
    if (ctx->arch == HB_ARCH_X86) {
        ctx->regs.x86.eip = (uint32_t)CODE; ctx->regs.x86.eflags = 0xa57;
        ctx->regs.x86.ecx = (uint32_t)(DATA + 128);
    } else {
        ctx->regs.x64.rip = CODE; ctx->regs.x64.rflags = 0xa57;
        ctx->regs.x64.rcx = DATA + 128;
    }
    memset(ctx->ymm_hi, 0x6d, sizeof(ctx->ymm_hi));
    memset(ctx->zmm_hi, 0x4b, sizeof(ctx->zmm_hi));
    memset(ctx->k, 0x39, sizeof(ctx->k));
    memset(ctx->xmm_ext, 0x51, sizeof(ctx->xmm_ext));
    memset(ctx->ymm_hi_ext, 0x62, sizeof(ctx->ymm_hi_ext));
    memset(ctx->zmm_hi_ext, 0x73, sizeof(ctx->zmm_hi_ext));
    memset(&ctx->x87_64, 0x49, sizeof(ctx->x87_64));
    ctx->flags = (hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};
    memset(&ctx->lazy_flags, 0, sizeof(ctx->lazy_flags));
    ctx->pc = CODE; ctx->mxcsr = 0x1f80u | (rc << 13);
    ctx->fs_base = UINT64_C(0x11110000); ctx->gs_base = UINT64_C(0x22220000);
    ctx->seg_cs = 0x33; ctx->seg_ds = 0x2b; ctx->seg_es = 0x31;
    ctx->seg_fs = 0x53; ctx->seg_gs = 0x61; ctx->seg_ss = 0x69;
    ctx->step_limit = 8; ctx->block_limit = 2;
    ctx->last_result = HB_OK;
}

static void check_architecture(const hb_context_t *ctx, const hb_context_t *expected)
{
    check(ctx->pc == expected->pc && !memcmp(&ctx->regs, &expected->regs, sizeof(ctx->regs)),
          "exact integer destination, PC and other GPR/XMM/x87 fields");
    /* Numerical conversion status flags are outside this milestone. RC, masks
     * and the rest of MXCSR control state must remain unchanged. */
    check((ctx->mxcsr & ~0x3fu) == expected->mxcsr, "guest MXCSR control state preserved");
    check(!memcmp(&ctx->flags, &expected->flags, sizeof(ctx->flags)) &&
          !memcmp(&ctx->lazy_flags, &expected->lazy_flags, sizeof(ctx->lazy_flags)), "guest flags preserved");
    check(!memcmp(ctx->ymm_hi, expected->ymm_hi, sizeof(ctx->ymm_hi)) &&
          !memcmp(ctx->zmm_hi, expected->zmm_hi, sizeof(ctx->zmm_hi)) &&
          !memcmp(ctx->k, expected->k, sizeof(ctx->k)) &&
          !memcmp(ctx->xmm_ext, expected->xmm_ext, sizeof(ctx->xmm_ext)) &&
          !memcmp(ctx->ymm_hi_ext, expected->ymm_hi_ext, sizeof(ctx->ymm_hi_ext)) &&
          !memcmp(ctx->zmm_hi_ext, expected->zmm_hi_ext, sizeof(ctx->zmm_hi_ext)) &&
          !memcmp(&ctx->x87_64, &expected->x87_64, sizeof(ctx->x87_64)), "upper vector, opmask and x87 state");
    check(ctx->fs_base == expected->fs_base && ctx->gs_base == expected->gs_base &&
          ctx->seg_cs == expected->seg_cs && ctx->seg_ds == expected->seg_ds && ctx->seg_es == expected->seg_es &&
          ctx->seg_fs == expected->seg_fs && ctx->seg_gs == expected->seg_gs && ctx->seg_ss == expected->seg_ss,
          "segment state preserved");
}

static void run_form(const form_t *f, hb_arch_t arch, hb_backend_t backend)
{
    static const int host_rounds[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    static const unsigned compact_samples[] = {2,3,4,5,6,7,8,9,10,11,20,21};
    uint8_t code[8], memory[64], actual_memory[64];
    int opcode;
    size_t n = encode(f, code, &opcode);
    hb_context_t *ctx = NULL, expected;
    hb_decoder_t *decoder = NULL;
    hb_ir_func_t *func = NULL;
    hb_interpreter_t *interp = NULL;
    hb_jit_runtime_t *jit = NULL;
    hb_decoded_t decoded = {0};
    snprintf(phase, sizeof(phase), "%s %s %s setup", arch == HB_ARCH_X86 ? "x86" : "x64",
             backend == HB_BACKEND_JIT ? "JIT" : "interp", f->name);
    ctx = hb_context_create(arch, backend);
    if (!check(ctx != NULL, "create context")) goto done;
    ctx->memory = hb_memory_create(0);
    if (!check(ctx->memory && hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK &&
               hb_memory_write(ctx->memory, CODE, code, n) == HB_OK &&
               hb_memory_protect(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_EXEC) == HB_OK &&
               hb_memory_map_private(ctx->memory, DATA, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
               "map private code and source memory")) goto done;
    hb_result_t decoded_result = arch == HB_ARCH_X86 ? hb_decode_x86(code,n,CODE,&decoded) : hb_decode_x64(code,n,CODE,&decoded);
    if (!check(decoded_result == HB_OK && decoded.len == n && (int)decoded.opcode == opcode,
               "actual decoder recognizes expected raw instruction")) goto done;
    decoder = hb_decoder_create(arch, code, n, CODE);
    if (!check(decoder != NULL, "create decoder")) goto done;
    hb_result_t lifted = arch == HB_ARCH_X86 ? hb_lift_func_x86(decoder,&func) : hb_lift_func_x64(decoder,&func);
    if (!check(lifted == HB_OK && func, "lift raw instruction once")) goto done;
    if (backend == HB_BACKEND_JIT) jit = hb_jit_runtime_create(ctx);
    else interp = hb_interpreter_create(ctx);
    if (!check(jit || interp, "create reusable execution runtime")) goto done;
    unsigned lanes = f->scalar ? 1 : f->dbl ? 2 : 4;
    size_t count = f->compact ? sizeof(compact_samples)/sizeof(compact_samples[0]) : sizeof(samples)/sizeof(samples[0]);
    for (unsigned host = 0; host < 4; ++host) for (unsigned rc = 0; rc < 4; ++rc)
        for (size_t first = 0; first < count; first += lanes) {
            unsigned first_index = f->compact ? compact_samples[first] : (unsigned)first;
            snprintf(phase, sizeof(phase), "%s %s %s host=%u guest=%u first=%s",
                     arch == HB_ARCH_X86 ? "x86" : "x64", backend == HB_BACKEND_JIT ? "JIT" : "interp",
                     f->name, host, rc, samples[first_index].name);
            seed(ctx, rc);
            uint8_t input[16] = {0}, output[16] = {0};
            for (unsigned lane = 0; lane < lanes; ++lane) {
                size_t pos = (first + lane) % count;
                const sample_t *s = &samples[f->compact ? compact_samples[pos] : pos];
                put_bits(input + lane * (f->dbl ? 8 : 4), f->dbl ? s->dbl : s->single, f->dbl ? 8 : 4);
                put_bits(output + lane * (f->wide ? 8 : 4), answer(s,f,rc), f->wide ? 8 : 4);
            }
            memset(memory, 0xa5, sizeof(memory));
            memcpy(memory + 16, input, sizeof(input));
            if (!check(hb_memory_write(ctx->memory, DATA + 112, memory, sizeof(memory)) == HB_OK, "seed guarded source bytes")) goto done;
            if (!f->memory) {
                if (arch == HB_ARCH_X86) memcpy(ctx->regs.x86.xmm[1], input, sizeof(input));
                else memcpy(ctx->regs.x64.xmm[1], input, sizeof(input));
            }
            memcpy(&expected, ctx, sizeof(expected));
            expected.pc = CODE + n;
            if (arch == HB_ARCH_X86) expected.regs.x86.eip = (uint32_t)expected.pc;
            else expected.regs.x64.rip = expected.pc;
            if (f->scalar) {
                uint64_t result_bits = answer(&samples[first_index], f, rc);
                if (arch == HB_ARCH_X86) expected.regs.x86.eax = (uint32_t)result_bits;
                else expected.regs.x64.rax = result_bits; /* 32-bit writes zero-extend. */
            } else {
                if (arch == HB_ARCH_X86) memcpy(expected.regs.x86.xmm[0], output, sizeof(output));
                else memcpy(expected.regs.x64.xmm[0], output, sizeof(output));
                if (f->vex) {
                    memset(expected.ymm_hi[0], 0, sizeof(expected.ymm_hi[0]));
                    memset(expected.zmm_hi[0], 0, sizeof(expected.zmm_hi[0]));
                }
            }
            if (!check(fesetround(host_rounds[host]) == 0 && feclearexcept(FE_ALL_EXCEPT) == 0 &&
                       feraiseexcept(FE_DIVBYZERO) == 0, "seed masked host rounding/status independently")) goto done;
            int host_status = fetestexcept(FE_ALL_EXCEPT);
            hb_exec_result_t execution = {0};
            hb_result_t result = jit ? hb_jit_runtime_run(jit,func,&execution) : hb_interpreter_run(interp,func,&execution);
            int actual_host_round = fegetround();
            int actual_host_status = fetestexcept(FE_ALL_EXCEPT);
            ++executions;
            if (!check(actual_host_round == host_rounds[host] && actual_host_status == host_status,
                       "guest conversion preserves host rounding and exception flags")) {
                ++host_fenv_failures;
                host_round_failures += actual_host_round != host_rounds[host];
                host_status_failures += actual_host_status != host_status;
                if (host_fenv_failures <= 8)
                    fprintf(stderr, "HOST-FENV %s: round actual=%d expected=%d status actual=0x%x expected=0x%x added=0x%x removed=0x%x\n",
                            phase, actual_host_round, host_rounds[host], actual_host_status, host_status,
                            actual_host_status & ~host_status, host_status & ~actual_host_status);
            }
            if (!check(result == HB_OK && execution.result == HB_OK && !execution.faulted && !execution.timed_out &&
                       execution.steps_executed && execution.blocks_executed, "instruction actually completes"))
                ++completion_failures;
            unsigned before_architecture = failures;
            check_architecture(ctx, &expected);
            architecture_failures += failures - before_architecture;
            if (!check(hb_memory_read(ctx->memory, DATA + 112, actual_memory, sizeof(actual_memory)) == HB_OK &&
                       !memcmp(actual_memory, memory, sizeof(memory)), "input memory and guards unchanged"))
                ++memory_failures;
        }
    if (jit) check(native_entry_present(jit), "JIT has actual native guest entry block");
done:
    if (jit) hb_jit_runtime_destroy(jit);
    if (interp) hb_interpreter_destroy(interp);
    if (decoder) hb_decoder_destroy(decoder);
    if (func) hb_ir_func_destroy(func);
    if (ctx) hb_context_destroy(ctx);
}

static const struct { const char *name; enum hb_gate_id id; } gates[] = {
    {"MACRUNNER_HB_JIT_DIRECT_MEM", HB_GATE_HB_JIT_DIRECT_MEM},
    {"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM", HB_GATE_HB_JIT_DIRECT_SCALAR_MEM},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR", HB_GATE_HB_JIT_NATIVE_MEM_IR},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS", HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64", HB_GATE_HB_JIT_DIRECT_STACK_X64},
    {"MACRUNNER_HB_TSO_RELAXED_LOADS", HB_GATE_HB_TSO_RELAXED_LOADS},
    {"MACRUNNER_HB_TSO_STACK_RELAXED", HB_GATE_HB_TSO_STACK_RELAXED}
};

int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])] = {0};
    size_t saved_count = 0;
    int changed = 0, host_saved = 0;
    fenv_t host_environment;
    for (size_t i = 0; i < sizeof(gates)/sizeof(gates[0]); ++i) {
        const char *value = getenv(gates[i].name);
        if (value && !check((saved[i] = strdup(value)) != NULL, "save original gate")) goto done;
        ++saved_count;
    }
    changed = 1;
    for (size_t i = 0; i < saved_count; ++i)
        if (!check(setenv(gates[i].name,"0",1) == 0, "select private helper-memory configuration")) goto done;
    hb_env_refresh();
    for (size_t i = 0; i < saved_count; ++i) {
        const char *value = hb_gate(gates[i].id);
        if (!check(value && !strcmp(value,"0"), "effective helper gate is zero")) goto done;
    }
    if (!check(feholdexcept(&host_environment) == 0, "save host fenv and mask host exceptions")) goto done;
    host_saved = 1;
    for (unsigned backend = 0; backend < 2; ++backend) {
        hb_backend_t selected = backend ? HB_BACKEND_JIT : HB_BACKEND_INTERP;
        for (size_t i = 0; i < sizeof(forms)/sizeof(forms[0]); ++i) run_form(&forms[i], HB_ARCH_X64, selected);
        /* Separate x86 decoder/lifter paths, using all rounding pairs and a
         * compact tie/neighbor/boundary set. REX.W forms have no x86 equivalent. */
        static const unsigned x86_forms[] = {0,2,4,6,8,10};
        for (size_t i = 0; i < sizeof(x86_forms)/sizeof(x86_forms[0]); ++i) {
            form_t f = forms[x86_forms[i]]; f.compact = 1;
            run_form(&f, HB_ARCH_X86, selected);
        }
    }
done:
    snprintf(phase, sizeof(phase), "cleanup");
    if (host_saved) check(fesetenv(&host_environment) == 0, "restore original host FP environment");
    if (changed) {
        for (size_t i = 0; i < saved_count; ++i)
            check((saved[i] ? setenv(gates[i].name,saved[i],1) : unsetenv(gates[i].name)) == 0, "restore original gate or absence");
        hb_env_refresh();
        for (size_t i = 0; i < saved_count; ++i) {
            const char *value = hb_gate(gates[i].id);
            check(saved[i] ? value && !strcmp(value,saved[i]) : !value, "effective original gate restored");
        }
    }
    for (size_t i = 0; i < saved_count; ++i) free(saved[i]);
    printf("hb_sse_integer_rounding_test: %u executions, %u checks, %u failures\n", executions, checks, failures);
    printf("failure categories: host_fenv=%u (round=%u status=%u) architecture=%u completion=%u memory=%u other=%u\n",
           host_fenv_failures, host_round_failures, host_status_failures, architecture_failures,
           completion_failures, memory_failures,
           failures - host_fenv_failures - architecture_failures - completion_failures - memory_failures);
    return failures ? 1 : 0;
}
