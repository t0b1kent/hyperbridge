/* Actual FXSAVE/FXRSTOR instructions; synthetic private guest memory only.
 * The 512-byte images are constructed independently, not by FXSAVE followed
 * by FXRSTOR. Test the engine's 0xffbf MXCSR policy and invalid-state #GP,
 * not DAZ arithmetic support or late partial writes. The image oracle covers
 * the inherited empty-x87/XMM image fields plus MXCSR; complete architectural
 * FIP/FDP serialization is not implemented and is not claimed here. */
#include <fenv.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_gates.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"

enum { PAGE_BYTES = 16384, IMAGE_BYTES = 512, IMAGE_OFFSET = 128 };
static const uint64_t CODE = 0x04400000, DATA = 0x05400000;
static unsigned passed, failed;
static char phase[128];

static int check(int value, const char *what)
{
    if (value) ++passed;
    else { ++failed; printf("FAIL %s: %s\n", phase, what); }
    return value;
}

static void put16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static void put64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static uint64_t xmm_word(unsigned reg, unsigned half, int restore)
{
    return (restore ? UINT64_C(0xe130425364758697) : UINT64_C(0x123456789abcdef0)) ^
           ((uint64_t)reg << 36) ^ ((uint64_t)half << 60);
}

static void seed_context(hb_context_t *ctx, uint32_t mxcsr, int restore, int fault)
{
    if (ctx->arch == HB_ARCH_X64) {
        ctx->regs.x64 = (hb_regs_x64_t){
            .rax = DATA + IMAGE_OFFSET, .rbx = UINT64_C(0x1122334455667788),
            .rcx = UINT64_C(0x99aabbccddeeff00), .rdx = 0x3210,
            .rsi = 0x4560, .rdi = 0x5670, .rsp = 0x06403000, .rbp = 0x06402000,
            .r8 = 0x808, .r9 = 0x909, .r10 = 0xa0a, .r11 = 0xb0b,
            .r12 = 0xc0c, .r13 = 0xd0d, .r14 = 0xe0e, .r15 = 0xf0f,
            .rip = CODE, .rflags = 0x247
        };
    } else {
        ctx->regs.x86 = (hb_regs_x86_t){
            .eax = (uint32_t)(DATA + IMAGE_OFFSET), .ebx = 0x55667788,
            .ecx = 0xddeeff00, .edx = 0x3210, .esi = 0x4560, .edi = 0x5670,
            .esp = 0x06403000, .ebp = 0x06402000, .eip = (uint32_t)CODE,
            .eflags = 0x247
        };
    }
    hb_x87_reset(hb_context_x87(ctx));
    /* Keep the successful image an independently known empty/default x87
     * image. Failed accesses must preserve a distinct previous FIP too. */
    hb_context_x87(ctx)->last_x87_ip = fault ? 0x10203040 : 0;
    unsigned count = ctx->arch == HB_ARCH_X64 ? 16 : 8;
    for (unsigned i = 0; i < count; ++i) {
        uint64_t *xmm = ctx->arch == HB_ARCH_X64 ? ctx->regs.x64.xmm[i] : ctx->regs.x86.xmm[i];
        xmm[0] = xmm_word(i, 0, 0);
        xmm[1] = xmm_word(i, 1, 0);
    }
    memset(ctx->ymm_hi, 0x7a, sizeof(ctx->ymm_hi));
    memset(ctx->zmm_hi, 0x4b, sizeof(ctx->zmm_hi));
    memset(ctx->k, 0x39, sizeof(ctx->k));
    memset(ctx->xmm_ext, 0x51, sizeof(ctx->xmm_ext));
    memset(ctx->ymm_hi_ext, 0x62, sizeof(ctx->ymm_hi_ext));
    memset(ctx->zmm_hi_ext, 0x73, sizeof(ctx->zmm_hi_ext));
    ctx->mxcsr = restore ? mxcsr ^ 0x2000u : mxcsr;
    ctx->pc = CODE;
    ctx->flags = (hb_flags_t){.zf = true, .cf = true, .pf = true};
    ctx->fs_base = 0x111000;
    ctx->gs_base = 0x222000;
    ctx->seg_cs = 0x33;
    ctx->seg_ss = 0x2b;
    ctx->step_limit = 8;
    ctx->block_limit = 2;
}

static void make_image(uint8_t image[IMAGE_BYTES], uint32_t mxcsr,
                       hb_arch_t arch, int restore)
{
    memset(image, 0, IMAGE_BYTES);
    put16(image, restore ? 0x027f : 0x037f);
    put16(image + 2, restore ? 0x0100 : 0);
    /* Empty abridged x87 tag word; all eight x87 data slots remain zero. */
    put32(image + 0x18, mxcsr);
    put32(image + 0x1c, 0xffbf);
    unsigned count = restore ? 16 : arch == HB_ARCH_X64 ? 16 : 8;
    for (unsigned i = 0; i < count; ++i) {
        put64(image + 0xa0 + 16 * i, xmm_word(i, 0, restore));
        put64(image + 0xa8 + 16 * i, xmm_word(i, 1, restore));
    }
    /* Software-reserved tail is ignored by restore and must remain in memory. */
    if (restore) memset(image + 0x1e0, 0x6c, 32);
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

static void run_case(hb_arch_t arch, hb_backend_t backend, uint32_t mxcsr,
                     int restore, int fault, int invalid, uint32_t image_mask)
{
    /* 0f ae /0 = FXSAVE [eax/rax]; /1 = FXRSTOR [eax/rax]. */
    uint8_t code[] = {0x0f, 0xae, restore ? 0x08 : 0x00};
    uint8_t original[PAGE_BYTES], expected_memory[PAGE_BYTES], actual[PAGE_BYTES];
    uint8_t image[IMAGE_BYTES];
    hb_context_t *ctx = NULL;
    hb_decoder_t *decoder = NULL;
    hb_ir_func_t *func = NULL;
    hb_interpreter_t *interp = NULL;
    hb_jit_runtime_t *jit = NULL;
    hb_exec_result_t out = {0};
    hb_result_t status;
    const int rejected = fault || invalid;
    snprintf(phase, sizeof(phase), "%s/%s/%s/%s mxcsr=%08x mask=%08x",
             arch == HB_ARCH_X64 ? "x64" : "x86", backend == HB_BACKEND_JIT ? "jit" : "interp",
             restore ? "fxrstor" : "fxsave", fault ? "permission-fault" : invalid ? "invalid-state" : "valid",
             mxcsr, image_mask);

    ctx = hb_context_create(arch, backend);
    if (!check(ctx != NULL, "create context")) goto done;
    ctx->memory = hb_memory_create(0);
    if (!check(ctx->memory != NULL, "create memory")) goto done;
    if (!check(hb_memory_map_private(ctx->memory, DATA, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
               "map private image page")) goto done;
    memset(original, 0xa5, sizeof(original));
    make_image(image, mxcsr, arch, restore);
    if (restore) put32(image + 0x1c, image_mask);
    if (restore) memcpy(original + IMAGE_OFFSET, image, sizeof(image));
    memcpy(expected_memory, original, sizeof(original));
    if (!restore && !fault) memcpy(expected_memory + IMAGE_OFFSET, image, sizeof(image));
    if (!check(hb_memory_write(ctx->memory, DATA, original, sizeof(original)) == HB_OK,
               "seed independent image/sentinels")) goto done;
    if (fault && !check(hb_memory_protect(ctx->memory, DATA, PAGE_BYTES,
                                        restore ? HB_PERM_WRITE : HB_PERM_READ) == HB_OK,
                        "protect whole operand page before access")) goto done;
    if (!check(hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK &&
               hb_memory_write(ctx->memory, CODE, code, sizeof(code)) == HB_OK &&
               hb_memory_protect(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_EXEC) == HB_OK,
               "map guest instruction")) goto done;
    seed_context(ctx, mxcsr, restore, rejected);
    if (invalid) ctx->mxcsr = 0x3f82; /* Valid current state distinct from invalid input. */
    ctx->last_fault_kind = HB_FAULT_KIND_NONE;
    ctx->last_fault_addr = UINT64_C(0x778899aabbccdd00);
    ctx->last_fault_addr_valid = 1;
    ctx->last_fault_pc = UINT64_C(0x1122334455667788);
    hb_context_t expected = *ctx;
    if (restore && !rejected) {
        expected.mxcsr = mxcsr;
        hb_x87_state_t *x87 = hb_context_x87(&expected);
        x87->control_word = 0x027f;
        x87->status_word = 0x0100;
        /* FXRSTOR now retains all eight raw zero payloads even with empty
         * tags. Architectural emptiness remains in tag_word. */
        x87->st_ext_valid = 0xff;
        unsigned count = arch == HB_ARCH_X64 ? 16 : 8;
        for (unsigned i = 0; i < count; ++i) {
            uint64_t *xmm = arch == HB_ARCH_X64 ? expected.regs.x64.xmm[i] : expected.regs.x86.xmm[i];
            xmm[0] = xmm_word(i, 0, 1);
            xmm[1] = xmm_word(i, 1, 1);
        }
    }
    decoder = hb_decoder_create(arch, code, sizeof(code), CODE);
    if (!check(decoder != NULL, "create decoder")) goto done;
    status = arch == HB_ARCH_X64 ? hb_lift_func_x64(decoder, &func) : hb_lift_func_x86(decoder, &func);
    if (!check(status == HB_OK && func != NULL, "lift actual guest instruction")) goto done;
    if (backend == HB_BACKEND_INTERP) {
        interp = hb_interpreter_create(ctx);
        if (!check(interp != NULL, "create interpreter")) goto done;
    } else {
        jit = hb_jit_runtime_create(ctx);
        if (!check(jit != NULL, "create JIT runtime")) goto done;
    }
    int host_rounding = fegetround(), host_exceptions = fetestexcept(FE_ALL_EXCEPT);
    status = backend == HB_BACKEND_INTERP ? hb_interpreter_run(interp, func, &out)
                                         : hb_jit_runtime_run(jit, func, &out);
    check(fegetround() == host_rounding && fetestexcept(FE_ALL_EXCEPT) == host_exceptions,
          "host FP environment preserved");
    if (fault) {
        check((status == HB_ERR_MEMORY_FAULT || out.result == HB_ERR_MEMORY_FAULT) && out.faulted,
              "whole-page permission fault reported");
        if (invalid) check(ctx->last_fault_kind != HB_FAULT_KIND_GENERAL_PROTECTION,
                           "image read fault precedes invalid MXCSR validation");
    } else if (invalid) {
        check((status == HB_ERR_EXEC_FAULT || out.result == HB_ERR_EXEC_FAULT) && out.faulted,
              "invalid MXCSR reports execution fault");
        check(ctx->last_fault_kind == HB_FAULT_KIND_GENERAL_PROTECTION &&
              ctx->last_fault_addr == 0 && !ctx->last_fault_addr_valid && ctx->last_fault_pc == CODE,
              "general-protection metadata identifies instruction, not a memory address");
    } else {
        check(status == HB_OK && out.result == HB_OK && !out.faulted && !out.timed_out,
              "instruction completed");
    }
    if (backend == HB_BACKEND_JIT) check(has_native_block(jit), "JIT block emitted (instruction helper allowed)");
    check(ctx->pc == CODE + (rejected ? 0 : sizeof(code)), "precise instruction/completion PC");
    if (arch == HB_ARCH_X64) expected.regs.x64.rip = CODE + (rejected ? 0 : sizeof(code));
    else expected.regs.x86.eip = (uint32_t)(CODE + (rejected ? 0 : sizeof(code)));
    check(memcmp(&ctx->regs, &expected.regs, sizeof(ctx->regs)) == 0,
          "GPRs, architectural flags, XMM and x86 x87 state match");
    check(memcmp(hb_context_x87(ctx), hb_context_x87(&expected), sizeof(hb_x87_state_t)) == 0,
          "x87 state including prior FIP matches");
    check(ctx->mxcsr == expected.mxcsr, "MXCSR exact expected value including zero");
    check(memcmp(&ctx->flags, &expected.flags, sizeof(ctx->flags)) == 0,
          "condition flags preserved");
    check(memcmp(ctx->ymm_hi, expected.ymm_hi, sizeof(ctx->ymm_hi)) == 0 &&
          memcmp(ctx->zmm_hi, expected.zmm_hi, sizeof(ctx->zmm_hi)) == 0 &&
          memcmp(ctx->k, expected.k, sizeof(ctx->k)) == 0 &&
          memcmp(ctx->xmm_ext, expected.xmm_ext, sizeof(ctx->xmm_ext)) == 0 &&
          memcmp(ctx->ymm_hi_ext, expected.ymm_hi_ext, sizeof(ctx->ymm_hi_ext)) == 0 &&
          memcmp(ctx->zmm_hi_ext, expected.zmm_hi_ext, sizeof(ctx->zmm_hi_ext)) == 0,
          "YMM/ZMM/opmask and extended registers preserved");
    check(ctx->fs_base == expected.fs_base && ctx->gs_base == expected.gs_base &&
          ctx->seg_cs == expected.seg_cs && ctx->seg_ss == expected.seg_ss,
          "unrelated segment state preserved");
    if (fault && !check(hb_memory_protect(ctx->memory, DATA, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
                        "restore test page permissions for inspection")) goto done;
    check(hb_memory_read(ctx->memory, DATA, actual, sizeof(actual)) == HB_OK &&
          memcmp(actual, expected_memory, sizeof(actual)) == 0,
          "inherited image fields, MXCSR and surrounding memory match");
done:
    if (jit) hb_jit_runtime_destroy(jit);
    if (interp) hb_interpreter_destroy(interp);
    if (func) hb_ir_func_destroy(func);
    if (decoder) hb_decoder_destroy(decoder);
    if (ctx) hb_context_destroy(ctx);
}

static void defaults(hb_arch_t arch, hb_backend_t backend)
{
    snprintf(phase, sizeof(phase), "%s/%s/defaults", arch == HB_ARCH_X64 ? "x64" : "x86",
             backend == HB_BACKEND_JIT ? "jit" : "interp");
    hb_context_t *ctx = hb_context_create(arch, backend);
    if (!check(ctx != NULL, "create context")) return;
    check(ctx->mxcsr == 0x1f80, "creation initializes MXCSR");
    ctx->mxcsr = 0;
    check(hb_context_reset(ctx) == HB_OK && ctx->mxcsr == 0x1f80, "reset initializes MXCSR after zero");
    ctx->mxcsr = 0xffbf;
    check(hb_context_reset(ctx) == HB_OK && ctx->mxcsr == 0x1f80, "reset initializes MXCSR after nondefault");
    hb_context_destroy(ctx);
}

typedef struct { const char *name; enum hb_gate_id id; char *saved; } gate_t;
static gate_t gates[] = {
    {"MACRUNNER_HB_JIT_DIRECT_MEM", HB_GATE_HB_JIT_DIRECT_MEM, NULL},
    {"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM", HB_GATE_HB_JIT_DIRECT_SCALAR_MEM, NULL},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR", HB_GATE_HB_JIT_NATIVE_MEM_IR, NULL},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS", HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS, NULL},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64", HB_GATE_HB_JIT_DIRECT_STACK_X64, NULL},
    {"MACRUNNER_HB_TSO_RELAXED_LOADS", HB_GATE_HB_TSO_RELAXED_LOADS, NULL},
    {"MACRUNNER_HB_TSO_STACK_RELAXED", HB_GATE_HB_TSO_STACK_RELAXED, NULL}
};

int main(void)
{
    static const uint32_t values[] = {
        0, 0x1f80, 0x3f80, 0x5f80, 0x7f80, 0x9f80, 0xbf80, 0xdf80, 0xff80,
        0x1f81, 0x1f82, 0x1f84, 0x1f88, 0x1f90, 0x1fa0, 0xffbf
    };
    static const uint32_t invalid_bits[] = {0x40, 0x10000, UINT32_C(0x80000000)};
    static const uint32_t untrusted_masks[] = {0, UINT32_MAX};
    const size_t gate_count = sizeof(gates) / sizeof(gates[0]);
    size_t saved = 0;
    fenv_t host_env;
    int host_saved = 0, configured = 0;
    snprintf(phase, sizeof(phase), "environment");
    if (!check(feholdexcept(&host_env) == 0, "save host FP environment and mask host traps")) goto cleanup;
    host_saved = 1;
    for (; saved < gate_count; ++saved) {
        const char *value = getenv(gates[saved].name);
        if (value && !(gates[saved].saved = strdup(value))) {
            check(0, "save gate environment"); goto cleanup;
        }
    }
    configured = 1;
    for (size_t i = 0; i < gate_count; ++i)
        if (!check(setenv(gates[i].name, "0", 1) == 0, "select checked private-memory helpers")) goto cleanup;
    hb_env_refresh();
    for (size_t i = 0; i < gate_count; ++i) {
        const char *value = hb_gate(gates[i].id);
        if (!check(value && !strcmp(value, "0"), "gate snapshot refreshed")) goto cleanup;
    }
    if (!check(fesetround(FE_DOWNWARD) == 0 && feclearexcept(FE_ALL_EXCEPT) == 0 &&
               feraiseexcept(FE_INEXACT) == 0, "seed nondefault host FP control/status")) goto cleanup;
    for (unsigned a = 0; a < 2; ++a) {
        hb_arch_t arch = a ? HB_ARCH_X64 : HB_ARCH_X86;
        for (unsigned b = 0; b < 2; ++b) {
            hb_backend_t backend = b ? HB_BACKEND_JIT : HB_BACKEND_INTERP;
            defaults(arch, backend);
            for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
                run_case(arch, backend, values[i], 0, 0, 0, 0xffbf);
                run_case(arch, backend, values[i], 1, 0, 0, 0xffbf);
            }
            run_case(arch, backend, 0x5f81, 0, 1, 0, 0xffbf);
            run_case(arch, backend, 0x5f81, 1, 1, 0, 0xffbf);
            /* The image's MXCSR_MASK is saved information, not authority to
             * change the emulator's supported-bit mask during FXRSTOR. */
            run_case(arch, backend, 0x5f81, 1, 0, 0, 0);
            for (size_t i = 0; i < sizeof(invalid_bits) / sizeof(invalid_bits[0]); ++i) {
                for (size_t m = 0; m < sizeof(untrusted_masks) / sizeof(untrusted_masks[0]); ++m)
                    run_case(arch, backend, 0x5f81 | invalid_bits[i], 1, 0, 1, untrusted_masks[m]);
                run_case(arch, backend, 0x5f81 | invalid_bits[i], 1, 1, 1, UINT32_MAX);
            }
        }
    }
cleanup:
    snprintf(phase, sizeof(phase), "environment cleanup");
    if (configured) {
        for (size_t i = 0; i < gate_count; ++i)
            check((gates[i].saved ? setenv(gates[i].name, gates[i].saved, 1) : unsetenv(gates[i].name)) == 0,
                  "restore original gate value/presence");
        hb_env_refresh();
        for (size_t i = 0; i < gate_count; ++i) {
            const char *value = hb_gate(gates[i].id);
            check(gates[i].saved ? value && !strcmp(value, gates[i].saved) : value == NULL,
                  "restored gate snapshot");
        }
    }
    for (size_t i = 0; i < saved; ++i) free(gates[i].saved);
    if (host_saved) check(fesetenv(&host_env) == 0, "restore original host FP environment");
    printf("FXSTATE_MXCSR: %u checks, %u failures\n", passed + failed, failed);
    return failed ? 1 : 0;
}
