/* Four-block native loop; each process owns one immutable gate configuration.
 * tests/hb_zero_transit_bench.py alternates processes and summarizes pairs. */
#include "hb_context.h"
#include "hb_env.h"
#include "hb_ir.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#define BASE UINT64_C(0x150800000)
#define EXIT_PC (BASE + 3 * 32 + 6)

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static void configure(const char* mode) {
    static const struct { const char* name; const char* value; } gates[] = {
        {"FAST_EXEC", "507"}, {"UNCHAIN_WALK", "0"},
        {"BLOCK_CHAIN", "1"}, {"CHAIN_PATCH", "1"}, {"CHAIN_WRITE", "1"},
        {"JIT_DIRECT_STACK_X64", "1"}, {"NO_CTX_SNAPSHOT", "1"},
        {"CHAIN_TWO_SLOTS", "1"}, {"CHAIN_AFTER_RUN", "1"},
        {"INDIRECT_IC", "1"}, {"INDIRECT_IC_RET", "1"},
        {"SMC_DIRECT_HASH", "1"}, {"L1_TABLE", "1"},
        {"L1_TABLE_BITS", "14"}, {"L1_ANY_TERM", "1"},
        {"NATIVE_FASTPATH", "1"}, {"NATIVE_FASTPATH_INLINE", "1"},
        {"CMP_MEM_NATIVE", "1"}, {"ALU_MEM_NATIVE", "1"},
        {"IMUL_NATIVE", "1"}, {"CMOV_MEM_NATIVE", "1"},
        {"LSE_ATOMICS", "1"}, {"LSE_XCHG", "1"}, {"NATIVE_NOT", "1"},
        {"NEG_NATIVE", "1"}, {"NATIVE_XMM_STORE", "1"},
        {"NATIVE_SEG_LOAD", "1"}, {"NATIVE_MULDIV", "1"},
        {"SELF_BASE_NATIVE", "1"}, {"LOAD_ALIGN_NATIVE", "1"},
        {"NATIVE_SHIFT", "1"}, {"JIT_DIRECT_MEM", "1"},
        {"NATIVE_CAS128", "1"}, {"LEAN_FRAME", "0"},
        {"NO_DEADLINE_CHECKS", "0"}, {"TEST_TRANSIT_FLIP", "0"}
    };
    for (size_t i = 0; i < sizeof(gates) / sizeof(gates[0]); ++i) {
        char name[96];
        snprintf(name, sizeof(name), "MACRUNNER_HB_%s", gates[i].name);
        setenv(name, gates[i].value, 1);
    }
    int all = !strcmp(mode, "on");
    setenv("MACRUNNER_HB_CHAIN_BODY_ENTRY", all || !strcmp(mode, "frame") ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_NO_COUNTERS", all || !strcmp(mode, "counters") ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_LAZY_PC", all || !strcmp(mode, "pc") ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_SKIP_NOP", all || !strcmp(mode, "slot") ? "1" : "0", 1);
}

static hb_ir_func_t* make_loop(void) {
    hb_ir_func_t* f = hb_ir_func_create(BASE, 0);
    hb_ir_block_t* block[4];
    static const hb_reg_t regs[] = {HB_REG_RAX, HB_REG_RBX, HB_REG_RDX, HB_REG_RCX};
    static const uint64_t values[] = {1, 3, 5, 1};
    if (!f) return NULL;
    for (unsigned i = 0; i < 4; ++i) {
        block[i] = hb_ir_block_create(i, BASE + i * 32);
        if (!block[i]) return NULL;
        hb_ir_cfg_add_block(f->cfg, block[i]);
    }
    f->cfg->entry = block[0];
    hb_ir_builder_t* builder = hb_ir_builder_create(f);
    if (!builder) return NULL;
    for (unsigned i = 0; i < 4; ++i) {
        hb_ir_builder_set_block(builder, block[i]);
        hb_ir_instr_t* ins = hb_ir_emit_binop(builder, i == 3 ? HB_IR_SUB : HB_IR_ADD,
            hb_ir_reg(regs[i], HB_SIZE_64), hb_ir_reg(regs[i], HB_SIZE_64),
            hb_ir_imm(values[i], HB_SIZE_64));
        if (!ins) return NULL;
        ins->guest_addr = BASE + i * 32;
        ins->guest_len = 4;
        ins = i == 3 ? hb_ir_emit_jcc(builder, HB_CC_NE, BASE)
                     : hb_ir_emit_jmp(builder, BASE + (i + 1) * 32);
        if (!ins) return NULL;
        ins->guest_addr = BASE + i * 32 + 4;
        ins->guest_len = i == 3 ? 2 : 5;
        hb_ir_cfg_add_edge(f->cfg, block[i], block[(i + 1) % 4]);
    }
    hb_ir_builder_destroy(builder);
    return f;
}

static int run_loop(hb_jit_runtime_t* runtime, hb_context_t* ctx,
                    hb_ir_func_t* func, uint64_t n, uint64_t* elapsed,
                    hb_exec_result_t* out) {
    ctx->pc = BASE;
    ctx->regs.x64.rip = BASE;
    ctx->regs.x64.rax = ctx->regs.x64.rbx = ctx->regs.x64.rdx = 0;
    ctx->regs.x64.rcx = n;
    ctx->last_result = HB_OK;
    uint64_t steps = 0, blocks = 0, duration = 0;
    bool execution_started = false, counters_are_dispatches = false;
    uint64_t start = now_ns();
    hb_result_t transport;
    for (;;) {
        transport = hb_jit_runtime_run(runtime, func, out);
        steps += out->steps_executed;
        blocks += out->blocks_executed;
        duration += out->duration_ns;
        execution_started |= out->execution_started;
        counters_are_dispatches |= out->counters_are_dispatches;
        /* A committed slice resumes from its published guest state. Keep
         * setup outside this loop and include every resume in the timing. */
        if (transport != HB_OK || out->result != HB_ERR_STEP_LIMIT ||
            out->faulted || !hb_exec_result_has_progress(out)) break;
    }
    *elapsed = now_ns() - start;
    out->steps_executed = steps;
    out->blocks_executed = blocks;
    out->duration_ns = duration;
    out->execution_started = execution_started;
    out->counters_are_dispatches = counters_are_dispatches;
    if (transport != HB_OK || out->result != HB_OK || out->faulted ||
        ctx->regs.x64.rax != n || ctx->regs.x64.rbx != 3 * n ||
        ctx->regs.x64.rdx != 5 * n || ctx->regs.x64.rcx ||
        ctx->pc != EXIT_PC || ctx->regs.x64.rip != EXIT_PC) {
        fprintf(stderr, "benchmark mismatch: transport=%d result=%d fault=%d "
                "pc=%#" PRIx64 " rip=%#" PRIx64 " rax=%" PRIu64 " rcx=%" PRIu64 " reason=%s\n",
                transport, out->result, out->faulted, ctx->pc, ctx->regs.x64.rip,
                ctx->regs.x64.rax, ctx->regs.x64.rcx, out->fault_reason ? out->fault_reason : "");
        return 0;
    }
    return 1;
}

static int dump_native(hb_jit_runtime_t* runtime, const char* directory) {
    char path[4096];
    if (mkdir(directory, 0700) != 0 && errno != EEXIST) return 0;
    snprintf(path, sizeof(path), "%s/manifest.json", directory);
    FILE* manifest = fopen(path, "w");
    if (!manifest) return 0;
    fprintf(manifest, "{\"arena_base\":%" PRIuPTR ",\"arena_size\":%zu,\"blocks\":[\n",
            (uintptr_t)runtime->jit_mem->executable, runtime->jit_mem->used);
    unsigned count = 0;
    for (size_t i = 0; i < runtime->block_cache->size; ++i) {
        const hb_block_cache_entry_t* entry = &runtime->block_cache->entries[i];
        if (!entry->valid || !entry->native_code) continue;
        snprintf(path, sizeof(path), "%s/block-%" PRIx64 ".bin", directory, entry->guest_addr);
        FILE* blob = fopen(path, "wb");
        if (!blob) { fclose(manifest); return 0; }
        size_t written = fwrite(entry->native_code, 1, entry->native_size, blob);
        fclose(blob);
        if (written != entry->native_size) { fclose(manifest); return 0; }
        fprintf(manifest, "%s{\"guest\":%" PRIu64 ",\"native\":%" PRIuPTR
                ",\"size\":%zu,\"file\":\"block-%" PRIx64 ".bin\"}",
                count++ ? ",\n" : "", entry->guest_addr,
                (uintptr_t)entry->native_code, entry->native_size, entry->guest_addr);
    }
    fprintf(manifest, "\n]}\n");
    fclose(manifest);
    snprintf(path, sizeof(path), "%s/arena.bin", directory);
    FILE* arena = fopen(path, "wb");
    if (!arena) return 0;
    size_t written = fwrite(runtime->jit_mem->executable, 1, runtime->jit_mem->used, arena);
    fclose(arena);
    return written == runtime->jit_mem->used;
}

int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "off";
    uint64_t iterations = argc > 2 ? strtoull(argv[2], NULL, 0) : 500000;
    if (!iterations || (strcmp(mode, "off") && strcmp(mode, "on") &&
        strcmp(mode, "frame") && strcmp(mode, "counters") &&
        strcmp(mode, "pc") && strcmp(mode, "slot"))) return 2;
    configure(mode);
    hb_env_refresh();
    hb_context_t* ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_ir_func_t* func = make_loop();
    if (!ctx || !func) return 2;
    if (!ctx->memory) ctx->memory = hb_memory_create(0);
    ctx->step_limit = ctx->block_limit = 0;
    hb_jit_runtime_t* runtime = hb_jit_runtime_create(ctx);
    if (!runtime) return 2;
    hb_exec_result_t result;
    uint64_t elapsed;
    for (unsigned warm = 0; warm < 3; ++warm)
        if (!run_loop(runtime, ctx, func, 128, &elapsed, &result)) return 1;
    if (runtime->block_cache->count != 4) {
        fprintf(stderr, "expected four separately translated blocks, got %zu\n", runtime->block_cache->count);
        return 1;
    }
    if (argc > 3 && !dump_native(runtime, argv[3])) return 2;
    uint64_t dispatches_before = runtime->guard_dispatch;
    if (!run_loop(runtime, ctx, func, iterations, &elapsed, &result)) return 1;
    printf("{\"mode\":\"%s\",\"iterations\":%" PRIu64 ",\"blocks_per_iteration\":4,"
           "\"elapsed_ns\":%" PRIu64 ",\"ns_per_iteration\":%.6f,"
           "\"reported_blocks\":%" PRIu64 ",\"native_dispatches\":%" PRIu64
           ",\"counters_are_dispatches\":%s}\n",
           mode, iterations, elapsed, (double)elapsed / (double)iterations,
           result.blocks_executed, runtime->guard_dispatch - dispatches_before,
           result.counters_are_dispatches ? "true" : "false");
    hb_jit_runtime_destroy(runtime);
    hb_ir_func_destroy(func);
    hb_context_destroy(ctx);
    return 0;
}
