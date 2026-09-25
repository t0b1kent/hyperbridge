/* C07 preparation only: actual DIV-by-zero -> reset -> unmasked FISTP fault.
 * Reset retires context fault diagnostics, not the attached memory/configuration.
 * This does not clear metadata at every runtime entry or implement pending #MF.
 * No Wine delivery, native x86 execution, or whole-context memset oracle.
 * Planned successful traversal: 16 runtime calls, 24 resets, 8 public-setter
 * controls across x86/x64 and interpreter/JIT. Parent owns compilation/runs.
 */
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_BYTES = 16384, DIVIDE = 0, CONVERT = 1, PROGRAMS = 2 };
static const uint64_t CODE = UINT64_C(0x5700000), DATA = UINT64_C(0x6700000);
static const uint8_t code[PROGRAMS][2] = {{0xf7, 0xf1}, {0xdb, 0x19}};
static unsigned checks, failures, executions, resets, setter_controls;
static char phase[128] = "setup";

static int check(int ok, const char *what) {
    ++checks;
    if (!ok) {
        ++failures;
        if (failures <= 80) fprintf(stderr, "FAIL %s: %s\n", phase, what);
    }
    return ok;
}

typedef struct {
    hb_context_t *ctx;
    hb_memory_t *memory;
    hb_decoder_t *decoder[PROGRAMS];
    hb_ir_func_t *func[PROGRAMS];
    hb_interpreter_t *interp;
    hb_jit_runtime_t *jit;
    hb_arch_t arch;
    hb_backend_t backend;
    hb_config_t config;
} fixture_t;

static uint64_t address(unsigned program) { return CODE + program * 0x100u; }

static void check_no_fault(const hb_context_t *ctx) {
    check(ctx->last_fault_kind == HB_FAULT_KIND_NONE, "no previous fault kind");
    check(ctx->last_fault_addr == 0, "no previous fault address");
    check(ctx->last_fault_addr_valid == 0, "no previous address-valid marker");
    check(ctx->last_fault_pc == 0, "no previous fault instruction address");
}

static int reset_preserving_resources(fixture_t *f) {
    uint8_t before[16], after[16];
    if (!check(hb_memory_read(f->memory, DATA, before, sizeof(before)) == HB_OK,
               "read retained memory before reset")) return 0;
    if (!check(hb_context_reset(f->ctx) == HB_OK, "reset existing context")) return 0;
    ++resets;
    check_no_fault(f->ctx);
    check(f->ctx->last_result == HB_OK, "reset clears last execution result");
    check(f->ctx->pc == 0 && f->ctx->step_count == 0 && f->ctx->block_count == 0,
          "reset restarts PC and execution counters");
    int preserved = check(f->ctx->memory == f->memory && f->ctx->arch == f->arch &&
                          f->ctx->backend == f->backend &&
                          f->ctx->mode == (f->arch == HB_ARCH_X64 ? HB_MODE_64BIT : HB_MODE_32BIT),
                          "reset retains memory, architecture, mode and backend");
    const hb_config_t *a = &f->ctx->config, *b = &f->config;
    preserved &= check(a->hyperbridge_enabled == b->hyperbridge_enabled && a->mode == b->mode &&
                       a->arch == b->arch && a->backend == b->backend &&
                       a->cache_enabled == b->cache_enabled && a->trace_enabled == b->trace_enabled &&
                       a->fallback_enabled == b->fallback_enabled,
                       "reset retains explicit configuration fields");
    preserved &= check(f->ctx->step_limit == 32 && f->ctx->block_limit == 16,
                       "reset retains caller execution limits");
    preserved &= check(hb_memory_read(f->memory, DATA, after, sizeof(after)) == HB_OK &&
                       !memcmp(before, after, sizeof(before)), "reset preserves actual mapped bytes");
    /* Metadata failures intentionally do not stop the next real execution:
     * the baseline must expose stale classification on the conversion fault. */
    return preserved;
}

static int execute(fixture_t *f, unsigned program, hb_result_t expected) {
    if (!check(hb_context_set_pc(f->ctx, address(program)) == HB_OK, "select real guest instruction")) return 0;
    hb_exec_result_t out = {0};
    hb_result_t r = f->jit ? hb_jit_runtime_run(f->jit, f->func[program], &out)
                          : hb_interpreter_run(f->interp, f->func[program], &out);
    ++executions;
    if (expected == HB_OK)
        return check(r == HB_OK && out.result == HB_OK && !out.faulted && !out.timed_out &&
                     out.steps_executed && out.blocks_executed && f->ctx->pc == address(program) + 2,
                     "real instruction completes after context reuse");
    return check((r == HB_OK || r == expected) && out.result == expected && out.faulted && !out.timed_out,
                 "real instruction produces the expected execution fault");
}

static void check_fault(const hb_context_t *ctx, unsigned kind, uint64_t addr,
                        unsigned valid, uint64_t pc) {
    check(ctx->last_fault_kind == kind && ctx->last_fault_addr == addr &&
          ctx->last_fault_addr_valid == valid && ctx->last_fault_pc == pc,
          "new typed fault records its own kind/address/validity/instruction");
}

static int convert(fixture_t *f, int invalid) {
    static const uint8_t nan[10] = {0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0x7f};
    static const uint8_t seven[10] = {0, 0, 0, 0, 0, 0, 0, 0xe0, 1, 0x40};
    uint8_t sentinel[16], actual[16], raw[10];
    for (unsigned i = 0; i < sizeof(sentinel); ++i) sentinel[i] = (uint8_t)(0xa5u ^ i * 7u);
    if (!check(hb_memory_write(f->memory, DATA, sentinel, sizeof(sentinel)) == HB_OK,
               "seed conversion destination and guards")) return 0;
    hb_x87_state_t *x = hb_context_x87(f->ctx);
    if (!check(hb_x87_set_st_ext80(x, 0, invalid ? nan : seven, true) == HB_OK,
               "seed exact raw80 conversion operand")) return 0;
    x->control_word &= (uint16_t)~1u;
    unsigned old_top = x->top;
    uint16_t old_tags = x->tag_word;
    if (f->arch == HB_ARCH_X86) f->ctx->regs.x86.ecx = (uint32_t)DATA;
    else f->ctx->regs.x64.rcx = DATA;
    if (!execute(f, CONVERT, invalid ? HB_ERR_EXEC_FAULT : HB_OK)) return 0;
    check_no_fault(f->ctx);
    if (invalid) {
        check(x->status_word == (uint16_t)((old_top << 11) | 0x8081u),
              "unmasked invalid records IE/ES/B without new SF or PE");
        check(x->top == old_top && x->tag_word == old_tags, "unmasked conversion does not pop or retag");
        check(hb_x87_save_st_ext80(x, 0, raw) == HB_OK && !memcmp(raw, nan, sizeof(raw)),
              "unmasked conversion preserves source payload");
    } else {
        sentinel[0] = 7; sentinel[1] = 0; sentinel[2] = 0; sentinel[3] = 0;
        check(x->top == ((old_top + 1u) & 7u) &&
              ((x->tag_word >> (old_top * 2u)) & 3u) == 3u,
              "successful FISTP stores and pops after reset");
    }
    check(hb_memory_read(f->memory, DATA, actual, sizeof(actual)) == HB_OK &&
          !memcmp(actual, sentinel, sizeof(actual)), "conversion output and guard bytes match store/no-store contract");
    return 1;
}

static int native_present(fixture_t *f, unsigned program) {
    if (!f->jit || !f->jit->block_cache) return 0;
    hb_block_cache_t *cache = f->jit->block_cache;
    for (size_t i = 0; i < cache->size; ++i)
        if (cache->entries[i].valid && cache->entries[i].guest_addr == address(program) &&
            cache->entries[i].native_code && cache->entries[i].native_size) return 1;
    return 0;
}

static void run_mode(hb_arch_t arch, hb_backend_t backend) {
    fixture_t f = {.arch = arch, .backend = backend};
    snprintf(phase, sizeof(phase), "%s %s reset lifetime", arch == HB_ARCH_X86 ? "x86" : "x64",
             backend == HB_BACKEND_JIT ? "JIT" : "interpreter");
    f.ctx = hb_context_create(arch, backend);
    if (!check(f.ctx != NULL, "create reusable context")) goto done;
    f.memory = hb_memory_create(0); f.ctx->memory = f.memory;
    if (!check(f.memory && hb_memory_map_private(f.memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK &&
               hb_memory_map_private(f.memory, DATA, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
               "map owned code and retained data")) goto done;
    uint8_t initial[16]; memset(initial, 0x5a, sizeof(initial));
    if (!check(hb_memory_write(f.memory, DATA, initial, sizeof(initial)) == HB_OK, "seed retained data")) goto done;
    f.config = (hb_config_t){.hyperbridge_enabled = true, .mode = 2, .arch = arch, .backend = backend,
                            .cache_enabled = true, .trace_enabled = false, .fallback_enabled = true};
    f.ctx->config = f.config;
    if (!check(hb_context_set_step_limit(f.ctx, 32) == HB_OK && hb_context_set_block_limit(f.ctx, 16) == HB_OK,
               "set caller-owned execution limits")) goto done;
    for (unsigned i = 0; i < PROGRAMS; ++i) {
        if (!check(hb_memory_write(f.memory, address(i), code[i], sizeof(code[i])) == HB_OK,
                   "install fixed raw guest instruction")) goto done;
        hb_decoded_t d = {0};
        hb_result_t r = arch == HB_ARCH_X86 ? hb_decode_x86(code[i], 2, address(i), &d)
                                          : hb_decode_x64(code[i], 2, address(i), &d);
        if (!check(r == HB_OK && d.len == 2 && d.opcode == (i == DIVIDE ? HB_INS_DIV : HB_INS_X87_FISTP),
                   "decode actual DIV/FISTP bytes")) goto done;
        f.decoder[i] = hb_decoder_create(arch, code[i], sizeof(code[i]), address(i));
        if (!check(f.decoder[i] != NULL, "create instruction decoder")) goto done;
        r = arch == HB_ARCH_X86 ? hb_lift_func_x86(f.decoder[i], &f.func[i])
                               : hb_lift_func_x64(f.decoder[i], &f.func[i]);
        if (!check(r == HB_OK && f.func[i], "lift independent instruction function")) goto done;
    }
    if (!check(hb_memory_protect(f.memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_EXEC) == HB_OK,
               "make guest code executable")) goto done;
    if (backend == HB_BACKEND_JIT) f.jit = hb_jit_runtime_create(f.ctx);
    else f.interp = hb_interpreter_create(f.ctx);
    if (!check(f.jit || f.interp, "create persistent runtime")) goto done;
    check_no_fault(f.ctx);
    if (arch == HB_ARCH_X86) { f.ctx->regs.x86.eax = 1; f.ctx->regs.x86.edx = 0; f.ctx->regs.x86.ecx = 0; }
    else { f.ctx->regs.x64.rax = 1; f.ctx->regs.x64.rdx = 0; f.ctx->regs.x64.rcx = 0; }
    if (!execute(&f, DIVIDE, HB_ERR_EXEC_FAULT)) goto done;
    check_fault(f.ctx, HB_FAULT_KIND_DIVIDE, address(DIVIDE), 1, address(DIVIDE));
    if (!reset_preserving_resources(&f) || !reset_preserving_resources(&f)) goto done;
    if (!convert(&f, 1) || !reset_preserving_resources(&f) || !convert(&f, 0)) goto done;

    /* Public setters return the result for the caller to record. */
    f.ctx->last_result = hb_fault_null_exec(f.ctx, 0, CODE + 0x300); ++setter_controls;
    check(f.ctx->last_result == HB_ERR_EXEC_FAULT, "null-exec setter returns execution fault");
    check_fault(f.ctx, HB_FAULT_KIND_NULL_EXEC, 0, 1, CODE + 0x300);
    if (!reset_preserving_resources(&f)) goto done;
    f.ctx->last_result = hb_fault_general_protection(f.ctx, CODE + 0x400); ++setter_controls;
    check(f.ctx->last_result == HB_ERR_EXEC_FAULT, "GP setter returns execution fault");
    check_fault(f.ctx, HB_FAULT_KIND_GENERAL_PROTECTION, 0, 0, CODE + 0x400);
    if (!reset_preserving_resources(&f) || !convert(&f, 1) || !reset_preserving_resources(&f)) goto done;
    if (f.jit) check(native_present(&f, DIVIDE) && native_present(&f, CONVERT),
                     "both actual guest instructions have native entries (helpers allowed)");
done:
    if (f.jit) hb_jit_runtime_destroy(f.jit);
    if (f.interp) hb_interpreter_destroy(f.interp);
    for (unsigned i = 0; i < PROGRAMS; ++i) {
        if (f.decoder[i]) hb_decoder_destroy(f.decoder[i]);
        if (f.func[i]) hb_ir_func_destroy(f.func[i]);
    }
    if (f.ctx) hb_context_destroy(f.ctx);
}

static const struct { const char *name; enum hb_gate_id id; } gates[] = {
    {"MACRUNNER_HB_JIT_DIRECT_MEM", HB_GATE_HB_JIT_DIRECT_MEM},
    {"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM", HB_GATE_HB_JIT_DIRECT_SCALAR_MEM},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR", HB_GATE_HB_JIT_NATIVE_MEM_IR},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS", HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64", HB_GATE_HB_JIT_DIRECT_STACK_X64},
    {"MACRUNNER_HB_TSO_RELAXED_LOADS", HB_GATE_HB_TSO_RELAXED_LOADS},
    {"MACRUNNER_HB_TSO_STACK_RELAXED", HB_GATE_HB_TSO_STACK_RELAXED},
    {"MACRUNNER_HB_UNCHAIN_STATS", HB_GATE_HB_UNCHAIN_STATS}
};

int main(void) {
    enum { GATE_COUNT = sizeof(gates) / sizeof(gates[0]) };
    char *saved[GATE_COUNT] = {0}; size_t count = 0; int changed = 0;
    check(hb_context_reset(NULL) == HB_ERR_INVALID_ARG, "NULL reset rejected");
    for (size_t i = 0; i < GATE_COUNT; ++i) {
        const char *s = getenv(gates[i].name);
        if (s && !check((saved[i] = strdup(s)) != NULL, "save original gate")) goto done;
        ++count;
    }
    changed = 1;
    for (size_t i = 0; i < count; ++i)
        if (!check(setenv(gates[i].name, "0", 1) == 0, "select private helper memory policy")) goto done;
    hb_env_refresh();
    for (size_t i = 0; i < count; ++i) {
        const char *s = hb_gate(gates[i].id);
        if (!check(s && !strcmp(s, "0"), "effective helper policy")) goto done;
    }
    for (unsigned arch = 0; arch < 2; ++arch)
        for (unsigned backend = 0; backend < 2; ++backend)
            run_mode(arch ? HB_ARCH_X64 : HB_ARCH_X86, backend ? HB_BACKEND_JIT : HB_BACKEND_INTERP);
    check(executions == 16 && resets == 24 && setter_controls == 8, "all planned lifetime sequences executed");
done:
    snprintf(phase, sizeof(phase), "cleanup");
    if (changed) {
        for (size_t i = 0; i < count; ++i)
            check((saved[i] ? setenv(gates[i].name, saved[i], 1) : unsetenv(gates[i].name)) == 0,
                  "restore original gate value or absence");
        hb_env_refresh();
        for (size_t i = 0; i < count; ++i) {
            const char *s = hb_gate(gates[i].id);
            check(saved[i] ? s && !strcmp(s, saved[i]) : !s, "effective original gate restored");
        }
    }
    for (size_t i = 0; i < count; ++i) free(saved[i]);
    printf("hb_context_reset_fault_test: %u executions, %u resets, %u setter controls, %u checks, %u failures\n",
           executions, resets, setter_controls, checks, failures);
    return failures ? 1 : 0;
}
