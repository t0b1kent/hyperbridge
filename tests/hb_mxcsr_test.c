/* Raw x86/x64 LDMXCSR/STMXCSR transport, independent expected bits per instruction.
 * Private guest mappings use explicit helper-memory gates. No Wine, host x64
 * execution, or FP arithmetic is required. A native JIT block may invoke the
 * existing instruction helper; block presence does not claim native FP lowering. */
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <fenv.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_BYTES = 16384, DATA_BYTES = 2 * PAGE_BYTES };
enum { LOAD_MXCSR, STORE_MXCSR };
enum { ACCESS_RW, ACCESS_RO, ACCESS_NONE, ACCESS_MISSING };
static const uint64_t CODE = UINT64_C(0x4000000);
static unsigned checks, failures;
static const char *phase = "setup";

static int check(int ok, const char *message)
{
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL [%s]: %s\n", phase, message); }
    return ok;
}

typedef struct {
    const char *name;
    uint8_t segment;
    int addr32;
    uint8_t displacement;
    uint64_t base, segment_base, linear;
} address_case_t;

static const address_case_t addresses[] = {
    {"aligned", 0, 0, 0, UINT64_C(0x8000100), 0, UINT64_C(0x8000100)},
    {"unaligned", 0, 0, 0, UINT64_C(0x8000101), 0, UINT64_C(0x8000101)},
    {"last dword", 0, 0, 0, UINT64_C(0x8003ffc), 0, UINT64_C(0x8003ffc)},
    {"cross region", 0, 0, 0, UINT64_C(0x8003ffe), 0, UINT64_C(0x8003ffe)},
    {"addr32 high bits", 0, 1, 0, UINT64_C(0xfeed123408000100), 0, UINT64_C(0x8000100)},
    {"FS addr64", 0x64, 0, 0, UINT64_C(0x8000100), UINT64_C(0x100000000), UINT64_C(0x108000100)},
    {"GS addr64", 0x65, 0, 0, UINT64_C(0x8000100), UINT64_C(0x200000000), UINT64_C(0x208000100)},
    {"FS addr32 wrap", 0x64, 1, 0x30, UINT64_C(0xfeed1234fffffff0), UINT64_C(0x108000000), UINT64_C(0x108000020)},
    {"GS addr32 wrap", 0x65, 1, 0x30, UINT64_C(0xfeed1234fffffff0), UINT64_C(0x208000000), UINT64_C(0x208000020)}
};

static void put_u32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static int native_entry_present(const hb_jit_runtime_t *jit)
{
    if (!jit || !jit->block_cache) return 0;
    for (size_t i = 0; i < jit->block_cache->size; ++i) {
        const hb_block_cache_entry_t *entry = &jit->block_cache->entries[i];
        if (entry->valid && entry->guest_addr == CODE && entry->native_code && entry->native_size) return 1;
    }
    return 0;
}

static void seed_architecture(hb_context_t *ctx, const address_case_t *address)
{
    memset(&ctx->regs.x64, 0x3c, sizeof(ctx->regs.x64));
    for (unsigned i = 0; i < 16; ++i) {
        ctx->regs.x64.xmm[i][0] = UINT64_C(0x7ff8000000100000) + i;
        ctx->regs.x64.xmm[i][1] = UINT64_C(0x8000000000200000) + 0x101 * i;
    }
    memset(ctx->ymm_hi, 0x6d, sizeof(ctx->ymm_hi));
    memset(ctx->ymm_hi_ext, 0x7e, sizeof(ctx->ymm_hi_ext));
    memset(&ctx->x87_64, 0x39, sizeof(ctx->x87_64));
    ctx->regs.x64.rcx = address->base;
    ctx->regs.x64.rflags = 0xa57;
    ctx->regs.x64.rip = ctx->pc = CODE;
    ctx->fs_base = address->segment == 0x64 ? address->segment_base : UINT64_C(0x112233000);
    ctx->gs_base = address->segment == 0x65 ? address->segment_base : UINT64_C(0x223344000);
    ctx->seg_cs = 0x33; ctx->seg_ds = 0x2b; ctx->seg_es = 0x31;
    ctx->seg_fs = 0x53; ctx->seg_gs = 0x61; ctx->seg_ss = 0x69;
    ctx->flags.cf = true; ctx->flags.pf = true; ctx->flags.af = true;
    ctx->flags.zf = true; ctx->flags.sf = false; ctx->flags.of = true;
    memset(&ctx->lazy_flags, 0, sizeof(ctx->lazy_flags));
    ctx->step_limit = 8;
    ctx->block_limit = 2;
}

static void check_preserved(const hb_context_t *ctx, const hb_context_t *before,
                            uint32_t expected_mxcsr, uint64_t expected_pc, int verify_pc)
{
    hb_regs_x64_t expected_regs;
    memcpy(&expected_regs, &before->regs.x64, sizeof(expected_regs));
    expected_regs.rip = verify_pc ? expected_pc : ctx->regs.x64.rip;
    check(!memcmp(&ctx->regs.x64, &expected_regs, sizeof(expected_regs)),
          "all GPR/XMM/RFLAGS preserved except expected instruction PC");
    check((!verify_pc || ctx->pc == expected_pc) && ctx->mxcsr == expected_mxcsr,
          "exact MXCSR bits and applicable completion PC");
    check(!memcmp(&ctx->flags, &before->flags, sizeof(ctx->flags)) &&
          !memcmp(&ctx->lazy_flags, &before->lazy_flags, sizeof(ctx->lazy_flags)), "flags and lazy flag state preserved");
    check(!memcmp(ctx->ymm_hi, before->ymm_hi, sizeof(ctx->ymm_hi)) &&
          !memcmp(ctx->ymm_hi_ext, before->ymm_hi_ext, sizeof(ctx->ymm_hi_ext)) &&
          !memcmp(&ctx->x87_64, &before->x87_64, sizeof(ctx->x87_64)), "YMM and x87 state preserved");
    check(ctx->fs_base == before->fs_base && ctx->gs_base == before->gs_base &&
          ctx->seg_cs == before->seg_cs && ctx->seg_ds == before->seg_ds && ctx->seg_es == before->seg_es &&
          ctx->seg_fs == before->seg_fs && ctx->seg_gs == before->seg_gs && ctx->seg_ss == before->seg_ss,
          "segment state preserved");
}

static void run_case_full(const address_case_t *address, unsigned op, uint32_t value,
                          unsigned access, hb_backend_t backend, int invalid_mxcsr,
                          int preceding_nop)
{
    hb_context_t *ctx = NULL;
    hb_context_t before;
    hb_decoder_t *decoder = NULL;
    hb_ir_func_t *func = NULL;
    hb_interpreter_t *interp = NULL;
    hb_jit_runtime_t *jit = NULL;
    hb_exec_result_t execution = {0};
    hb_decoded_t decoded = {0};
    uint8_t bytes[8], expected[DATA_BYTES], actual[DATA_BYTES], decoy[DATA_BYTES];
    uint64_t page = address->linear & ~(uint64_t)(PAGE_BYTES - 1);
    uint64_t decoy_page = (uint32_t)page;
    size_t offset = (size_t)(address->linear - page), length = 0;
    int have_decoy = address->segment && address->addr32;
    int mapped = access != ACCESS_MISSING, protected = 0;
    int fault = access == ACCESS_NONE || access == ACCESS_MISSING || (op == STORE_MXCSR && access == ACCESS_RO);
    uint32_t initial_mxcsr = invalid_mxcsr ? 0x5fa1u : op == LOAD_MXCSR ? value ^ 0x6000u : value;
    int rounding = fegetround(), exceptions = fetestexcept(FE_ALL_EXCEPT);
    char label[160];
    snprintf(label, sizeof(label), "%s %s %s value=%08x access=%u nop=%d",
             backend == HB_BACKEND_JIT ? "JIT" : "interp", op == LOAD_MXCSR ? "load" : "store",
             address->name, value, access, preceding_nop);
    phase = label;
    if (preceding_nop) bytes[length++] = 0x90;
    if (address->segment) bytes[length++] = address->segment;
    if (address->addr32) bytes[length++] = 0x67;
    bytes[length++] = 0x0f; bytes[length++] = 0xae;
    bytes[length++] = (uint8_t)((address->displacement ? 0x40 : 0) | (op == LOAD_MXCSR ? 0x10 : 0x18) | 1);
    if (address->displacement) bytes[length++] = address->displacement;
    memset(expected, 0xa5, sizeof(expected));
    put_u32(expected + offset, op == LOAD_MXCSR ? value : value ^ 0x4000u);
    memset(decoy, 0x96, sizeof(decoy));

    ctx = hb_context_create(HB_ARCH_X64, backend);
    if (!check(ctx != NULL, "create context")) goto done;
    check(ctx->mxcsr == 0x1f80, "fresh context default MXCSR");
    ctx->memory = hb_memory_create(0);
    if (!check(ctx->memory != NULL, "create private memory")) goto done;
    if (mapped) {
        for (unsigned i = 0; i < 2; ++i)
            if (!check(hb_memory_map_private(ctx->memory, page + i * PAGE_BYTES, PAGE_BYTES,
                                             HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map owned data region")) goto done;
        if (!check(hb_memory_write(ctx->memory, page, expected, sizeof(expected)) == HB_OK, "initialize data bytes")) goto done;
        if (access != ACCESS_RW) {
            if (!check(hb_memory_protect(ctx->memory, page, DATA_BYTES,
                                         access == ACCESS_RO ? HB_PERM_READ : HB_PERM_NONE) == HB_OK,
                       "apply data permission restriction")) goto done;
            protected = 1;
        }
    }
    if (have_decoy) {
        if (!check(hb_memory_map_private(ctx->memory, decoy_page, DATA_BYTES,
                                         HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map incorrect low-address decoy")) goto done;
        if (!check(hb_memory_write(ctx->memory, decoy_page, decoy, sizeof(decoy)) == HB_OK, "initialize decoy")) goto done;
    }
    if (!check(hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES,
                                     HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map code") ||
        !check(hb_memory_write(ctx->memory, CODE, bytes, length) == HB_OK, "write code") ||
        !check(hb_memory_protect(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_EXEC) == HB_OK,
               "protect code")) goto done;
    if (preceding_nop && !check(hb_decode_x64(bytes, length, CODE, &decoded) == HB_OK &&
                                decoded.len == 1 && decoded.opcode == HB_INS_NOP,
                                "midblock fixture starts with decoded NOP")) goto done;
    if (!check(hb_decode_x64(bytes + preceding_nop, length - preceding_nop,
                             CODE + preceding_nop, &decoded) == HB_OK && decoded.len == length - preceding_nop &&
               decoded.opcode == (op == LOAD_MXCSR ? HB_INS_LDMXCSR : HB_INS_STMXCSR),
               "raw bytes decode as intended MXCSR instruction")) goto done;
    seed_architecture(ctx, address);
    ctx->mxcsr = initial_mxcsr;
    memcpy(&before, ctx, sizeof(before));
    decoder = hb_decoder_create(HB_ARCH_X64, bytes, length, CODE);
    if (!check(decoder && hb_lift_func_x64(decoder, &func) == HB_OK && func, "lift raw instruction")) goto done;
    hb_result_t result;
    if (backend == HB_BACKEND_INTERP) {
        interp = hb_interpreter_create(ctx);
        if (!check(interp != NULL, "create interpreter")) goto done;
        result = hb_interpreter_run(interp, func, &execution);
    } else {
        jit = hb_jit_runtime_create(ctx);
        if (!check(jit != NULL, "create JIT")) goto done;
        result = hb_jit_runtime_run(jit, func, &execution);
        check(native_entry_present(jit), "JIT compiled actual guest entry block");
    }
    if (fault) {
        check((result == HB_OK || result == HB_ERR_MEMORY_FAULT) && execution.result == HB_ERR_MEMORY_FAULT &&
              execution.faulted && !execution.timed_out, "exact memory fault without budget stop");
        check_preserved(ctx, &before, initial_mxcsr, CODE, !preceding_nop);
        if (invalid_mxcsr)
            check(ctx->last_fault_kind != HB_FAULT_KIND_GENERAL_PROTECTION,
                  "memory failure takes precedence over invalid MXCSR validation");
    } else if (invalid_mxcsr) {
        check((result == HB_OK || result == HB_ERR_EXEC_FAULT) && execution.result == HB_ERR_EXEC_FAULT &&
              execution.faulted && !execution.timed_out, "invalid MXCSR raises execution fault");
        check(ctx->last_fault_kind == HB_FAULT_KIND_GENERAL_PROTECTION && ctx->last_fault_addr == 0 &&
              !ctx->last_fault_addr_valid && ctx->last_fault_pc == CODE + preceding_nop,
              "exact #GP metadata names faulting instruction, not block start");
        /* The JIT may retain block PC while executing a helper. Fault metadata
         * is the instruction address contract for this two-instruction case. */
        check_preserved(ctx, &before, initial_mxcsr, CODE, !preceding_nop);
    } else {
        check(result == HB_OK && execution.result == HB_OK && !execution.faulted && !execution.timed_out &&
              execution.steps_executed && execution.blocks_executed, "instruction actually completes");
        check_preserved(ctx, &before, value, CODE + length, 1);
        if (op == STORE_MXCSR) put_u32(expected + offset, value);
    }
    if (protected) {
        if (!check(hb_memory_protect(ctx->memory, page, DATA_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
                   "restore owned data permissions")) goto done;
        protected = 0;
    }
    if (mapped && check(hb_memory_read(ctx->memory, page, actual, sizeof(actual)) == HB_OK, "read result bytes"))
        check(!memcmp(actual, expected, sizeof(actual)), "exact dword write or unchanged input/surrounding memory");
    if (have_decoy && check(hb_memory_read(ctx->memory, decoy_page, actual, sizeof(actual)) == HB_OK, "read decoy bytes"))
        check(!memcmp(actual, decoy, sizeof(actual)), "incorrect low address remains untouched");
    check(fegetround() == rounding && fetestexcept(FE_ALL_EXCEPT) == exceptions,
          "host FP rounding and status preserved");
done:
    if (protected && ctx && ctx->memory)
        check(hb_memory_protect(ctx->memory, page, DATA_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
              "restore permissions during cleanup");
    if (jit) hb_jit_runtime_destroy(jit);
    if (interp) hb_interpreter_destroy(interp);
    if (decoder) hb_decoder_destroy(decoder);
    if (func) hb_ir_func_destroy(func);
    if (ctx) hb_context_destroy(ctx);
    phase = "between cases";
}

static void run_case(const address_case_t *address, unsigned op, uint32_t value,
                      unsigned access, hb_backend_t backend)
{
    run_case_full(address, op, value, access, backend, 0, 0);
}

static void invalid_loads(hb_backend_t backend)
{
    /* DAZ (бит 6) объявлен с 25.09.2026 (маска 0xffff): 0x40 и 0x1fc0 допустимы. */
    static const uint32_t invalid[] = {0x10000, 0x80000000u, 0xffffffffu};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        run_case_full(&addresses[0], LOAD_MXCSR, invalid[i], ACCESS_RW, backend, 1, 0);
        run_case_full(&addresses[0], LOAD_MXCSR, invalid[i], ACCESS_NONE, backend, 1, 0);
        run_case_full(&addresses[0], LOAD_MXCSR, invalid[i], ACCESS_MISSING, backend, 1, 0);
    }
    run_case_full(&addresses[0], LOAD_MXCSR, 0x10000, ACCESS_RO, backend, 1, 0);
    run_case_full(&addresses[0], LOAD_MXCSR, 0x80015fa1u, ACCESS_RW, backend, 1, 1);
}

static void x86_instruction(hb_backend_t backend, unsigned op, uint32_t value, int invalid)
{
    const uint64_t data = UINT64_C(0x8000000);
    uint8_t code[] = {0x0f, 0xae, op == LOAD_MXCSR ? 0x11 : 0x19}; /* [ecx] */
    uint8_t expected_memory[PAGE_BYTES], actual_memory[PAGE_BYTES];
    hb_context_t *ctx = NULL, expected;
    hb_decoder_t *decoder = NULL;
    hb_ir_func_t *func = NULL;
    hb_interpreter_t *interp = NULL;
    hb_jit_runtime_t *jit = NULL;
    hb_decoded_t decoded = {0};
    hb_exec_result_t execution = {0};
    char label[128];
    int rounding = fegetround(), exceptions = fetestexcept(FE_ALL_EXCEPT);
    snprintf(label, sizeof(label), "x86 %s %s value=%08x invalid=%d",
             backend == HB_BACKEND_JIT ? "JIT" : "interp", op == LOAD_MXCSR ? "load" : "store", value, invalid);
    phase = label;
    memset(expected_memory, 0xa5, sizeof(expected_memory));
    put_u32(expected_memory + 0x100, op == LOAD_MXCSR ? value : 0x5fa1);
    ctx = hb_context_create(HB_ARCH_X86, backend);
    if (!check(ctx != NULL, "create x86 instruction context")) goto done;
    ctx->memory = hb_memory_create(0);
    if (!check(ctx->memory &&
               hb_memory_map_private(ctx->memory, data, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK &&
               hb_memory_write(ctx->memory, data, expected_memory, sizeof(expected_memory)) == HB_OK,
               "map and initialize x86 operand page")) goto done;
    if (!check(hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK &&
               hb_memory_write(ctx->memory, CODE, code, sizeof(code)) == HB_OK &&
               hb_memory_protect(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_EXEC) == HB_OK,
               "map x86 instruction bytes")) goto done;
    if (!check(hb_decode_x86(code, sizeof(code), CODE, &decoded) == HB_OK && decoded.len == sizeof(code) &&
               decoded.opcode == (op == LOAD_MXCSR ? HB_INS_LDMXCSR : HB_INS_STMXCSR),
               "actual x86 decoder recognizes isolated MXCSR instruction")) goto done;
    ctx->regs.x86.eax = 0x11112222; ctx->regs.x86.ebx = 0x33334444;
    ctx->regs.x86.ecx = (uint32_t)(data + 0x100); ctx->regs.x86.edx = 0x55556666;
    ctx->regs.x86.esi = 0x77778888; ctx->regs.x86.edi = 0x9999aaaa;
    ctx->regs.x86.esp = 0x09003000; ctx->regs.x86.ebp = 0x09002000;
    ctx->regs.x86.eip = (uint32_t)CODE; ctx->regs.x86.eflags = 0xa57;
    for (unsigned i = 0; i < 8; ++i) {
        ctx->regs.x86.xmm[i][0] = UINT64_C(0x7ff8000000100000) + i;
        ctx->regs.x86.xmm[i][1] = UINT64_C(0x8000000000200000) + 0x101 * i;
    }
    ctx->regs.x86.x87.control_word = 0x027f;
    ctx->regs.x86.x87.status_word = 0x0100;
    ctx->regs.x86.x87.last_x87_ip = 0x12345678;
    memset(ctx->ymm_hi, 0x6d, sizeof(ctx->ymm_hi));
    memset(ctx->zmm_hi, 0x4b, sizeof(ctx->zmm_hi));
    memset(ctx->k, 0x39, sizeof(ctx->k));
    memset(ctx->xmm_ext, 0x51, sizeof(ctx->xmm_ext));
    memset(ctx->ymm_hi_ext, 0x62, sizeof(ctx->ymm_hi_ext));
    memset(ctx->zmm_hi_ext, 0x73, sizeof(ctx->zmm_hi_ext));
    ctx->flags = (hb_flags_t){.cf = true, .pf = true, .af = true, .zf = true, .of = true};
    ctx->pc = CODE; ctx->mxcsr = op == LOAD_MXCSR ? 0x3fa1 : value;
    ctx->fs_base = 0x11110000; ctx->gs_base = 0x22220000;
    ctx->seg_cs = 0x33; ctx->seg_ds = 0x2b; ctx->seg_es = 0x31;
    ctx->seg_fs = 0x53; ctx->seg_gs = 0x61; ctx->seg_ss = 0x69;
    ctx->step_limit = 8; ctx->block_limit = 2;
    ctx->last_fault_addr = UINT64_C(0x778899aabbccdd00);
    ctx->last_fault_addr_valid = 1;
    ctx->last_fault_pc = UINT64_C(0x1122334455667788);
    memcpy(&expected, ctx, sizeof(expected));
    if (!invalid) {
        expected.pc = CODE + sizeof(code);
        expected.regs.x86.eip = (uint32_t)expected.pc;
        expected.mxcsr = value;
        if (op == STORE_MXCSR) put_u32(expected_memory + 0x100, value);
    }
    decoder = hb_decoder_create(HB_ARCH_X86, code, sizeof(code), CODE);
    if (!check(decoder && hb_lift_func_x86(decoder, &func) == HB_OK && func,
               "actual x86 lifter handles raw instruction")) goto done;
    hb_result_t result;
    if (backend == HB_BACKEND_INTERP) {
        interp = hb_interpreter_create(ctx);
        if (!check(interp != NULL, "create x86 interpreter")) goto done;
        result = hb_interpreter_run(interp, func, &execution);
    } else {
        jit = hb_jit_runtime_create(ctx);
        if (!check(jit != NULL, "create x86 JIT")) goto done;
        result = hb_jit_runtime_run(jit, func, &execution);
        check(native_entry_present(jit), "JIT emitted x86 guest entry block");
    }
    if (invalid) {
        check((result == HB_OK || result == HB_ERR_EXEC_FAULT) && execution.result == HB_ERR_EXEC_FAULT &&
              execution.faulted && !execution.timed_out, "x86 invalid load raises execution fault");
        check(ctx->last_fault_kind == HB_FAULT_KIND_GENERAL_PROTECTION && ctx->last_fault_addr == 0 &&
              !ctx->last_fault_addr_valid && ctx->last_fault_pc == CODE,
              "x86 #GP reports exact PC and clears stale memory-fault metadata");
    } else {
        check(result == HB_OK && execution.result == HB_OK && !execution.faulted && !execution.timed_out &&
              execution.steps_executed && execution.blocks_executed, "x86 instruction actually completes");
    }
    check(ctx->pc == expected.pc && ctx->mxcsr == expected.mxcsr &&
          !memcmp(&ctx->regs, &expected.regs, sizeof(ctx->regs)), "x86 exact PC/MXCSR with GPR/XMM/x87 preserved");
    check(!memcmp(&ctx->flags, &expected.flags, sizeof(ctx->flags)) &&
          !memcmp(&ctx->lazy_flags, &expected.lazy_flags, sizeof(ctx->lazy_flags)), "x86 condition and lazy flags preserved");
    check(!memcmp(ctx->ymm_hi, expected.ymm_hi, sizeof(ctx->ymm_hi)) &&
          !memcmp(ctx->zmm_hi, expected.zmm_hi, sizeof(ctx->zmm_hi)) &&
          !memcmp(ctx->k, expected.k, sizeof(ctx->k)) &&
          !memcmp(ctx->xmm_ext, expected.xmm_ext, sizeof(ctx->xmm_ext)) &&
          !memcmp(ctx->ymm_hi_ext, expected.ymm_hi_ext, sizeof(ctx->ymm_hi_ext)) &&
          !memcmp(ctx->zmm_hi_ext, expected.zmm_hi_ext, sizeof(ctx->zmm_hi_ext)), "x86 extended vector/opmask state preserved");
    check(ctx->fs_base == expected.fs_base && ctx->gs_base == expected.gs_base &&
          ctx->seg_cs == expected.seg_cs && ctx->seg_ds == expected.seg_ds && ctx->seg_es == expected.seg_es &&
          ctx->seg_fs == expected.seg_fs && ctx->seg_gs == expected.seg_gs && ctx->seg_ss == expected.seg_ss,
          "x86 segment state preserved");
    check(hb_memory_read(ctx->memory, data, actual_memory, sizeof(actual_memory)) == HB_OK &&
          !memcmp(actual_memory, expected_memory, sizeof(actual_memory)), "x86 exact dword result or unchanged input memory");
    check(fegetround() == rounding && fetestexcept(FE_ALL_EXCEPT) == exceptions, "x86 guest leaves host FP state unchanged");
done:
    if (jit) hb_jit_runtime_destroy(jit);
    if (interp) hb_interpreter_destroy(interp);
    if (decoder) hb_decoder_destroy(decoder);
    if (func) hb_ir_func_destroy(func);
    if (ctx) hb_context_destroy(ctx);
    phase = "between x86 cases";
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

static void context_defaults(void)
{
    static const uint32_t prior_values[] = {0, 0x3fa1, 0xffbf};
    phase = "context creation and reset";
    for (unsigned arch = 0; arch < 2; ++arch)
        for (unsigned backend = 0; backend < 2; ++backend) {
            hb_context_t *ctx = hb_context_create(arch ? HB_ARCH_X64 : HB_ARCH_X86,
                                                   backend ? HB_BACKEND_JIT : HB_BACKEND_INTERP);
            if (!check(ctx != NULL, "create x86/x64 context for defaults")) continue;
            check(ctx->mxcsr == 0x1f80, "constructor explicitly initializes architectural MXCSR default");
            for (size_t value = 0; value < sizeof(prior_values) / sizeof(prior_values[0]); ++value) {
                ctx->mxcsr = prior_values[value];
                check(hb_context_reset(ctx) == HB_OK && ctx->mxcsr == 0x1f80,
                      "reset replaces zero or modified MXCSR with architectural default");
            }
            hb_context_destroy(ctx);
        }
}

int main(void)
{
    static const uint32_t values[] = {0, 0x1f80, 0x1fbf, 0x3fa1, 0x5fa1, 0x7fa1, 0x9fa1, 0xffbf,
                                      0x1fc0, 0x9fc0, 0xffff};   /* DAZ: PhysX ставит 0x9fc0 */
    char *saved[sizeof(gates) / sizeof(gates[0])] = {0};
    size_t saved_count = 0;
    int environment_changed = 0, host_saved = 0;
    fenv_t host_environment;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (; saved_count < sizeof(gates) / sizeof(gates[0]); ++saved_count) {
        const char *old = getenv(gates[saved_count].name);
        if (old && !(saved[saved_count] = strdup(old))) { check(0, "save gate environment"); goto done; }
    }
    environment_changed = 1;
    for (size_t i = 0; i < saved_count; ++i)
        if (!check(setenv(gates[i].name, "0", 1) == 0, "disable direct guest memory")) goto done;
    hb_env_refresh();
    for (size_t i = 0; i < saved_count; ++i) {
        const char *actual = hb_gate(gates[i].id);
        if (!check(actual && !strcmp(actual, "0"), "effective helper-memory gate")) goto done;
    }
    if (!check(feholdexcept(&host_environment) == 0, "save host FP environment and mask host traps")) goto done;
    host_saved = 1;
    if (!check(fesetround(FE_UPWARD) == 0 && feraiseexcept(FE_INVALID | FE_INEXACT) == 0,
               "seed nondefault host rounding and status")) goto done;
    context_defaults();
    for (unsigned backend = 0; backend < 2; ++backend) {
        hb_backend_t selected = backend ? HB_BACKEND_JIT : HB_BACKEND_INTERP;
        for (size_t value = 0; value < sizeof(values) / sizeof(values[0]); ++value)
            for (unsigned op = 0; op < 2; ++op)
                run_case(&addresses[0], op, values[value], ACCESS_RW, selected);
        for (size_t address = 1; address < sizeof(addresses) / sizeof(addresses[0]); ++address)
            for (unsigned op = 0; op < 2; ++op)
                run_case(&addresses[address], op, op == LOAD_MXCSR ? 0x5fa1 : 0, ACCESS_RW, selected);
        run_case(&addresses[0], LOAD_MXCSR, 0x3fa1, ACCESS_RO, selected);
        for (unsigned op = 0; op < 2; ++op) {
            run_case(&addresses[0], op, 0x3fa1, ACCESS_NONE, selected);
            run_case(&addresses[0], op, 0x3fa1, ACCESS_MISSING, selected);
        }
        run_case(&addresses[0], STORE_MXCSR, 0, ACCESS_RO, selected);
        run_case(&addresses[7], STORE_MXCSR, 0, ACCESS_RO, selected);
        invalid_loads(selected);
        x86_instruction(selected, LOAD_MXCSR, 0, 0);
        x86_instruction(selected, LOAD_MXCSR, 0x5fa1, 0);
        x86_instruction(selected, STORE_MXCSR, 0, 0);
        x86_instruction(selected, LOAD_MXCSR, 0x40, 0);   /* DAZ допустим */
        x86_instruction(selected, LOAD_MXCSR, 0x10000, 1);
        x86_instruction(selected, LOAD_MXCSR, 0x80000000u, 1);
    }
done:
    phase = "cleanup";
    if (host_saved) check(fesetenv(&host_environment) == 0, "restore original host FP environment");
    if (environment_changed) {
        for (size_t i = 0; i < saved_count; ++i)
            check((saved[i] ? setenv(gates[i].name, saved[i], 1) : unsetenv(gates[i].name)) == 0,
                  "restore original gate value or absence");
        hb_env_refresh();
        for (size_t i = 0; i < saved_count; ++i) {
            const char *actual = hb_gate(gates[i].id);
            check(saved[i] ? actual && !strcmp(actual, saved[i]) : !actual, "effective gate restored");
        }
    }
    for (size_t i = 0; i < saved_count; ++i) free(saved[i]);
    printf("hb_mxcsr_test: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
