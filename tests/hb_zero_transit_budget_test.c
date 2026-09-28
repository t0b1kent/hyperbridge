/* Infinite real-x86 chains must yield to their embedding dispatcher.  Every
 * completed block has two independent side effects, so replaying the completed
 * blocks in the interpreter also checks exact resume PC and partial replays. */
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "hb_codegen.h"
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

#define PAGE 16384u
#define STRIDE 32u
#define RESUMES 4u

typedef struct {
    uint8_t *code, *data, *stack;
    hb_context_t *ctx[2];
    hb_memory_t *mem[2];
    hb_jit_runtime_t *rt;
    hb_ir_func_t *func;
    unsigned blocks;
} fixture_t;

typedef struct { uint64_t steps, blocks; const char *name; } budget_t;
static const budget_t budgets[] = {
    {0, 1048576, "adapter-1Mi-blocks"}, {0, 256, "adapter-v5-256-blocks"},
    {1000000, 0, "context-default-million-steps"},
    {65536, 1048576, "adapter-fast-65536-steps"},
    {3, 0, "three-steps"}, {0, 3, "three-blocks"}, {0, 0, "unlimited"}
};
static const char *const shapes[] = {"direct-self", "direct-pair", "indirect-pair", "call-ret"};
static int force_sra, force_callret, force_ic, force_l1;
static unsigned oracle_timeout_seconds = 20;
static volatile sig_atomic_t watchdog_in_oracle;

static void timeout_handler(int sig) {
    static const char jit_message[] = "ZERO_TRANSIT_BUDGET watchdog: phase=jit infinite chain did not yield\n";
    static const char oracle_message[] = "ZERO_TRANSIT_BUDGET watchdog: phase=interpreter oracle replay timed out\n";
    (void)sig;
    if (watchdog_in_oracle)
        (void)write(STDERR_FILENO, oracle_message, sizeof(oracle_message) - 1);
    else
        (void)write(STDERR_FILENO, jit_message, sizeof(jit_message) - 1);
    _exit(124);
}

/* Only the interpreter oracle may need more wall time under background scheduling;
 * every JIT watchdog remains fixed at 20 seconds. */
static int configure_oracle_timeout(void) {
    const char *value = getenv("HB_TEST_ORACLE_TIMEOUT_SECONDS");
    unsigned seconds = 0;
    if (!value) return 1;
    for (const char *p = value; *p; ++p) {
        if (*p < '0' || *p > '9') goto invalid;
        seconds = seconds * 10 + (unsigned)(*p - '0');
        if (seconds > 3600) goto invalid;
    }
    if (!seconds) goto invalid;
    oracle_timeout_seconds = seconds;
    return 1;
invalid:
    fprintf(stderr, "HB_TEST_ORACLE_TIMEOUT_SECONDS must be an integer from 1 to 3600\n");
    return 0;
}

static void game_gates(void) {
    static const char *const gates[] = {
        "JIT_DIRECT_STACK_X64", "NO_CTX_SNAPSHOT", "CHAIN_TWO_SLOTS", "CHAIN_AFTER_RUN",
        "INDIRECT_IC", "INDIRECT_IC_RET", "SMC_DIRECT_HASH", "L1_TABLE", "L1_ANY_TERM",
        "NATIVE_FASTPATH", "NATIVE_FASTPATH_INLINE", "CMP_MEM_NATIVE", "ALU_MEM_NATIVE",
        "IMUL_NATIVE", "CMOV_MEM_NATIVE", "LSE_ATOMICS", "LSE_XCHG", "NATIVE_NOT",
        "NEG_NATIVE", "NATIVE_XMM_STORE", "NATIVE_SEG_LOAD", "NATIVE_MULDIV",
        "SELF_BASE_NATIVE", "LOAD_ALIGN_NATIVE", "NATIVE_SHIFT", "JIT_DIRECT_MEM", "NATIVE_CAS128"
    };
    for (size_t i = 0; i < sizeof(gates) / sizeof(gates[0]); ++i) {
        char name[100];
        snprintf(name, sizeof(name), "MACRUNNER_HB_%s", gates[i]);
        setenv(name, "1", 1);
    }
    setenv("MACRUNNER_HB_FAST_EXEC", "507", 1);
    setenv("MACRUNNER_HB_UNCHAIN_WALK", "0", 1);
    setenv("MACRUNNER_HB_L1_TABLE_BITS", "14", 1);
    setenv("MACRUNNER_HB_BLOCK_CHAIN", "1", 1);
    setenv("MACRUNNER_HB_CHAIN_PATCH", "1", 1);
}

static int fixture_create(fixture_t *f) {
    memset(f, 0, sizeof(*f));
    f->code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    f->data = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    f->stack = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (f->code == MAP_FAILED || f->data == MAP_FAILED || f->stack == MAP_FAILED) return 0;
    for (unsigned k = 0; k < 2; ++k) {
        f->ctx[k] = hb_context_create(HB_ARCH_X64, k ? HB_BACKEND_JIT : HB_BACKEND_INTERP);
        f->mem[k] = hb_memory_create(0);
        if (!f->ctx[k] || !f->mem[k]) return 0;
        f->ctx[k]->memory = f->mem[k];
        f->ctx[k]->config.fallback_enabled = false;
        if (hb_memory_sync_live_range(f->mem[k], (uintptr_t)f->code, PAGE, HB_PERM_READ | HB_PERM_EXEC) != HB_OK ||
            hb_memory_sync_live_range(f->mem[k], (uintptr_t)f->data, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK ||
            hb_memory_sync_live_range(f->mem[k], (uintptr_t)f->stack, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) return 0;
    }
    f->rt = hb_jit_runtime_create(f->ctx[1]);
    return f->rt != NULL;
}

static void fixture_destroy(fixture_t *f) {
    hb_jit_runtime_destroy(f->rt);
    if (f->func) hb_ir_func_destroy(f->func);
    for (unsigned k = 0; k < 2; ++k) {
        f->ctx[k]->memory = NULL;
        hb_context_destroy(f->ctx[k]);
        hb_memory_destroy(f->mem[k]);
    }
    munmap(f->code, PAGE); munmap(f->data, PAGE); munmap(f->stack, PAGE);
}

static int make_program(fixture_t *f, unsigned shape, int bare) {
    f->blocks = shape == 0 ? 1 : shape == 3 ? 3 : 2;
    memset(f->code, 0xcc, PAGE);
    f->func = hb_ir_func_create((uintptr_t)f->code, f->blocks * STRIDE);
    if (!f->func) return 0;
    for (unsigned i = 0; i < f->blocks; ++i) {
        uint8_t *dst = f->code + i * STRIDE;
        size_t n = 0;
        if (!bare) {
            const uint8_t side_effects[] = {
                0x90,                         /* nop: SKIP_NOP coverage */
                0x48,0xff,0x47,(uint8_t)(i*8), /* inc qword [rdi+i*8] */
                0x48,0xff,0xc0                 /* inc rax */
            };
            memcpy(dst, side_effects, sizeof(side_effects)); n += sizeof(side_effects);
            /* Faultable memory excludes scratch SRA by design. The repeated
             * accumulator below supplies independent resume side effects. */
            if (force_sra) memset(dst + 1, 0x90, 4);
            if (force_sra) for (unsigned reuse = 0; reuse < 5; ++reuse) {
                const uint8_t add[] = {0x49,0x01,0xc0}; /* add r8,rax */
                memcpy(dst + n, add, sizeof(add)); n += sizeof(add);
            }
        }
        if (shape == 2) {
            dst[n++] = 0xff; dst[n++] = i ? 0xe2 : 0xe3; /* jmp rdx/rbx */
        } else if (shape == 3 && i == 2) {
            dst[n++] = 0xc3;
        } else {
            unsigned target = shape == 0 ? 0 : shape == 3 ? (i == 0 ? 2 : 0) : 1 - i;
            dst[n++] = shape == 3 && i == 0 ? 0xe8 : 0xe9;
            int32_t disp = (int32_t)(target * STRIDE) - (int32_t)(i * STRIDE + n + 4);
            memcpy(dst + n, &disp, sizeof(disp)); n += sizeof(disp);
        }
        /* CALL pushes its real fallthrough. Keep that continuation at the
         * next block start by padding before CALL rather than after it. */
        if (shape == 3 && i == 0) {
            size_t call_at = n - 5;
            memmove(dst + STRIDE - 5, dst + call_at, 5);
            memset(dst + call_at, 0x90, STRIDE - 5 - call_at);
            int32_t disp = (int32_t)STRIDE;
            memcpy(dst + STRIDE - 4, &disp, sizeof(disp));
            n = STRIDE;
        }
        hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, dst, n, (uintptr_t)dst);
        hb_ir_func_t *part = NULL;
        if (!decoder || hb_lift_func_x64(decoder, &part) != HB_OK || !part ||
            !part->cfg || part->cfg->block_count != 1) {
            if (decoder) hb_decoder_destroy(decoder);
            if (part) hb_ir_func_destroy(part);
            return 0;
        }
        hb_decoder_destroy(decoder);
        hb_ir_block_t *block = part->cfg->blocks[0];
        block->id = i;
        hb_ir_cfg_add_block(f->func->cfg, block);
        part->cfg->block_count = 0; part->cfg->entry = NULL;
        hb_ir_func_destroy(part);
    }
    f->func->cfg->entry = f->func->cfg->blocks[0];
    return 1;
}

static void initialize(fixture_t *f, const budget_t *budget) {
    memset(f->data, 0, PAGE); memset(f->stack, 0, PAGE);
    for (unsigned k = 0; k < 2; ++k) {
        hb_context_t *ctx = f->ctx[k];
        hb_context_reset(ctx);
        ctx->memory = f->mem[k]; ctx->config.fallback_enabled = false;
        ctx->step_limit = k ? budget->steps : 0;
        ctx->block_limit = k ? budget->blocks : 0;
        ctx->regs.x64.rflags = 2;
        ctx->regs.x64.rbx = (uintptr_t)f->code + STRIDE;
        ctx->regs.x64.rdx = (uintptr_t)f->code;
        ctx->regs.x64.rdi = (uintptr_t)f->data;
        ctx->regs.x64.rsp = (uintptr_t)f->stack + PAGE - 128;
        ctx->pc = ctx->regs.x64.rip = (uintptr_t)f->code;
    }
}

static unsigned stitched_edges(fixture_t *f) {
    hb_block_cache_t *cache = f->rt->block_cache;
    unsigned total = 0;
    if (cache->chain_meta) for (size_t i = 0; i < cache->used_count; ++i) {
        hb_block_chain_meta_t *m = &cache->chain_meta[cache->used_slots[i]];
        total += m->target_code != NULL; total += m->slot2_target_code != NULL;
        if (!m->target_code && !m->slot2_target_code && m->transit_out) ++total;
    }
    return total;
}

static int verify_sra(fixture_t *f) {
    hb_arm64_codegen_t *cg = hb_arm64_codegen_create(f->ctx[1]);
    hb_codegen_buffer_t *buf = hb_codegen_buffer_create(65536);
    if (!cg || !buf) return 0;
    int ok = hb_arm64_codegen_block_with_cfg(cg, f->func->cfg->blocks[0], f->func->cfg, buf) == HB_OK &&
             buf->sra_mask != 0;
    printf("ZERO_TRANSIT_BUDGET_SRA mask=%x bank=%u emitted_call=%u verified=%d\n",
           (unsigned)buf->sra_mask, (unsigned)buf->sra_bank, (unsigned)buf->emitted_call, ok);
    hb_codegen_buffer_destroy(buf); hb_arm64_codegen_destroy(cg);
    return ok;
}

/* Replay from the previous boundary, never restarting a partially executed
 * invocation. Interpreter BLOCK_LIMIT is a legacy fault-shaped result; only
 * its exact architectural state serves as the oracle here. */
static int replay(fixture_t *f, uint64_t blocks) {
    hb_context_t *ctx = f->ctx[0];
    hb_interpreter_t *interp = hb_interpreter_create(ctx);
    if (!interp) return 0;
    uint64_t before = ctx->regs.x64.rax;
    int ok = 1;
    for (unsigned calls = 0; ctx->regs.x64.rax - before < blocks && calls < 16; ++calls) {
        hb_ir_block_t *start = NULL;
        for (unsigned i = 0; i < f->blocks; ++i)
            if (ctx->pc == (uintptr_t)f->code + i * STRIDE) start = f->func->cfg->blocks[i];
        if (!start) { ok = 0; break; }
        ctx->block_limit = blocks - (ctx->regs.x64.rax - before);
        hb_exec_result_t out = {0};
        hb_result_t rc = hb_interpreter_run_from(interp, f->func, start, &out);
        if ((rc != HB_OK && rc != HB_ERR_BLOCK_LIMIT) ||
            (out.result != HB_OK && out.result != HB_ERR_BLOCK_LIMIT)) { ok = 0; break; }
    }
    ok = ok && ctx->regs.x64.rax - before == blocks;
    hb_interpreter_destroy(interp);
    return ok;
}

static int run_case(unsigned shape, const budget_t *budget, int no_counters, int bare) {
    fixture_t f;
    if (!fixture_create(&f) || !make_program(&f, shape, bare)) return 2;
    initialize(&f, budget);
    if (force_sra && !verify_sra(&f)) { fixture_destroy(&f); return 1; }
    uint8_t *snapshots = malloc(4 * PAGE);
    if (!snapshots) return 2;
    unsigned bad = 0, yields = 0, chained = 0, calls = 0;
    uint64_t total_dispatches = 0, total_guest_blocks = 0;
    uint64_t max_ir = 1;
    for (unsigned i = 0; i < f.blocks; ++i)
        if (f.func->cfg->blocks[i]->instr_count > max_ir) max_ir = f.func->cfg->blocks[i]->instr_count;
    unsigned wanted = no_counters ? RESUMES : 1;
    for (; calls < wanted + 8 && yields < wanted; ++calls) {
        memcpy(snapshots, f.data, PAGE); memcpy(snapshots + PAGE, f.stack, PAGE);
        uint64_t before = f.ctx[1]->regs.x64.rax;
        uint64_t dispatch_before = f.rt->guard_dispatch;
        hb_exec_result_t out = {0};
        alarm(20);
        hb_result_t rc = hb_jit_runtime_run(f.rt, f.func, &out);
        alarm(0);
        uint64_t dispatched = f.rt->guard_dispatch - dispatch_before;
        uint64_t completed = f.ctx[1]->regs.x64.rax - before;
        int yielded = out.result == HB_ERR_STEP_LIMIT || out.result == HB_ERR_BLOCK_LIMIT;
        int failure = (rc != HB_OK && rc != HB_ERR_STEP_LIMIT && rc != HB_ERR_BLOCK_LIMIT) ||
                      (out.result != HB_OK && !yielded) ||
                      out.counters_are_dispatches != no_counters ||
                      !hb_exec_result_has_progress(&out) ||
                      f.ctx[1]->pc != f.ctx[1]->regs.x64.rip ||
                      (!bare && !completed);
        if (no_counters) {
            /* Explicit BLOCK_LIMIT retains the runtime's legacy fault shape;
             * the independent chain quantum must be a soft STEP_LIMIT yield. */
            failure |= (out.faulted && out.result != HB_ERR_BLOCK_LIMIT) || !out.execution_started;
            if (out.result == HB_ERR_STEP_LIMIT) failure |= rc != HB_OK;
            if (budget->blocks) failure |= out.blocks_executed > budget->blocks;
            if (budget->steps) failure |= out.steps_executed >= budget->steps + max_ir;
            if (out.result == HB_ERR_BLOCK_LIMIT)
                failure |= !budget->blocks || out.blocks_executed != budget->blocks;
            /* A warm chain must return within one invocation's native
             * admission quantum, independent of explicit counter limits. */
            failure |= dispatched > HB_CHAIN_POLL_QUANTUM + 1 || completed > HB_CHAIN_POLL_QUANTUM;
            /* Disabling competing native routes makes a single warm native
             * dispatch evidence that the requested IC/L1/CALLRET route ran. */
            if ((force_callret || force_ic || force_l1) && calls >= 2 &&
                (!budget->steps || budget->steps > 3) && (!budget->blocks || budget->blocks > 3))
                failure |= dispatched != 1;
        }
        if (yielded) ++yields;
        if (!bare) {
            memcpy(snapshots + 2*PAGE, f.data, PAGE);
            memcpy(snapshots + 3*PAGE, f.stack, PAGE);
            memcpy(f.data, snapshots, PAGE); memcpy(f.stack, snapshots + PAGE, PAGE);
            watchdog_in_oracle = 1;
            alarm(oracle_timeout_seconds);
            int replayed = replay(&f, completed);
            alarm(0);
            watchdog_in_oracle = 0;
            int materialized = hb_lazy_flags_materialize(f.ctx[0], HB_FLAG_BIT_ALL) == HB_OK &&
                               hb_lazy_flags_materialize(f.ctx[1], HB_FLAG_BIT_ALL) == HB_OK;
            int regs = memcmp(&f.ctx[0]->regs.x64, &f.ctx[1]->regs.x64, sizeof(hb_regs_x64_t)) != 0;
            int data = memcmp(f.data, snapshots + 2*PAGE, PAGE) != 0;
            int stack = memcmp(f.stack, snapshots + 3*PAGE, PAGE) != 0;
            failure |= !replayed || !materialized || regs || data || stack || f.ctx[0]->pc != f.ctx[1]->pc;
            if (!replayed || regs || data || stack)
                fprintf(stderr, "ZERO_TRANSIT_BUDGET_DIFF shape=%s budget=%s call=%u replay=%d regs=%d data=%d stack=%d pc=%" PRIx64 "/%" PRIx64 " completed=%" PRIu64 "\n",
                        shapes[shape], budget->name, calls, replayed, regs, data, stack,
                        f.ctx[0]->pc, f.ctx[1]->pc, completed);
            memcpy(f.data, snapshots + 2*PAGE, PAGE);
            memcpy(f.stack, snapshots + 3*PAGE, PAGE);
            if (completed > dispatched) ++chained;
        } else {
            failure |= f.ctx[1]->pc != (uintptr_t)f.code;
        }
        total_dispatches += dispatched; total_guest_blocks += completed;
        if (failure) {
            fprintf(stderr, "ZERO_TRANSIT_BUDGET_FAIL shape=%s bare=%d budget=%s call=%u rc=%d result=%d fault=%d started=%d progress=%d counters=%d completed=%" PRIu64 " dispatches=%" PRIu64 " reason=%s\n",
                    shapes[shape], bare, budget->name, calls, rc, out.result, out.faulted,
                    out.execution_started, hb_exec_result_has_progress(&out), out.counters_are_dispatches,
                    completed, dispatched, out.fault_reason ? out.fault_reason : "none");
            ++bad; break;
        }
    }
    unsigned edges = stitched_edges(&f);
    bad += yields != wanted;
    if (no_counters && !bare && (budget->blocks > 3 || budget->steps > 3 || (!budget->blocks && !budget->steps)))
        bad += chained == 0;
    if (no_counters && shape < 2) bad += edges == 0;
    printf("ZERO_TRANSIT_BUDGET shape=%s bare=%d budget=%s calls=%u yields=%u stitched=%u chained=%u guest_blocks=%" PRIu64 " dispatches=%" PRIu64 " mismatches=%u\n",
           shapes[shape], bare, budget->name, calls, yields, edges, chained,
           total_guest_blocks, total_dispatches, bad);
    free(snapshots); fixture_destroy(&f);
    return bad ? 1 : 0;
}

static int spinning_fastpath(hb_context_t *ctx, void *arg) {
    (void)arg;
    ++ctx->regs.x64.rax;
    ctx->regs.x64.rip = ctx->pc;
    return 1;
}

static int fastpath_case(void) {
    static const budget_t fastpath_budgets[] = {
        {0, 0, "unlimited"}, {3, 0, "three-steps"}, {0, 3, "three-blocks"}
    };
    fixture_t f;
    if (!fixture_create(&f) || !make_program(&f, 0, 1)) return 2;
    uint64_t addr = (uintptr_t)f.code + PAGE - 64;
    if (!hb_runtime_register_native_fastpath(addr, spinning_fastpath, NULL)) return 2;
    unsigned bad = 0;
    for (unsigned b = 0; b < sizeof(fastpath_budgets)/sizeof(fastpath_budgets[0]); ++b) {
        const budget_t *budget = &fastpath_budgets[b];
        uint64_t expected = budget->steps || budget->blocks ? 3 : HB_CHAIN_POLL_QUANTUM;
        hb_result_t expected_result = budget->blocks ? HB_ERR_BLOCK_LIMIT : HB_ERR_STEP_LIMIT;
        hb_result_t expected_transport = budget->blocks ? HB_ERR_BLOCK_LIMIT : HB_OK;
        unsigned failures = 0;
        initialize(&f, budget);
        f.ctx[1]->pc = f.ctx[1]->regs.x64.rip = addr;
        for (unsigned run = 0; run < RESUMES; ++run) {
            uint64_t before = f.ctx[1]->regs.x64.rax;
            uint64_t dispatch_before = f.rt->guard_dispatch;
            uint64_t steps_before = f.ctx[1]->step_count;
            uint64_t blocks_before = f.ctx[1]->block_count;
            hb_exec_result_t out = {0};
            alarm(20);
            hb_result_t rc = hb_jit_runtime_run(f.rt, f.func, &out);
            alarm(0);
            /* PE BeginSimulation (adapter/src/cpu.c:678) independently raises
             * STATUS_ACCESS_VIOLATION when both exported counters are zero.
             * execution_started cannot replace these ABI-visible credits. */
            failures += rc != expected_transport || out.result != expected_result ||
                        out.faulted != (budget->blocks != 0) || !out.execution_started ||
                        !out.counters_are_dispatches || !hb_exec_result_has_progress(&out) ||
                        out.blocks_executed != expected || out.steps_executed != expected ||
                        f.ctx[1]->block_count - blocks_before != expected ||
                        f.ctx[1]->step_count - steps_before != expected ||
                        f.rt->guard_dispatch != dispatch_before ||
                        f.ctx[1]->regs.x64.rax - before != expected ||
                        f.ctx[1]->pc != addr || f.ctx[1]->regs.x64.rip != addr;
        }
        bad += failures;
        printf("ZERO_TRANSIT_BUDGET_FASTPATH budget=%s resumes=%u callbacks=%" PRIu64 " dispatches=%" PRIu64 " mismatches=%u\n",
               budget->name, RESUMES, f.ctx[1]->regs.x64.rax, f.rt->guard_dispatch, failures);
    }
    fixture_destroy(&f);
    return bad ? 1 : 0;
}

static int mixed_fastpath_case(void) {
    static const budget_t mixed_budgets[] = {
        {0, 1, "native-one-block"}, {1, 0, "native-one-step"},
        {0, 2, "native-two-blocks"}, {2, 0, "native-two-steps"},
        {0, 0, "native-plus-fastpath-quantum"}
    };
    fixture_t f;
    if (!fixture_create(&f)) return 2;
    uint64_t addr = (uintptr_t)f.code + PAGE - 128;
    /* Lift the actual out-of-CFG guest jump, so SMC bytes and IR agree.
     * One JMP is one IR work credit: limits 1 and 2 isolate the boundary
     * immediately before and after the first successful C callback. */
    f.code[0] = 0xe9;
    int32_t disp = (int32_t)(addr - ((uintptr_t)f.code + 5));
    memcpy(f.code + 1, &disp, sizeof(disp));
    hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, f.code, 5, (uintptr_t)f.code);
    if (!decoder || hb_lift_func_x64(decoder, &f.func) != HB_OK || !f.func ||
        !f.func->cfg || f.func->cfg->block_count != 1 || f.func->cfg->blocks[0]->instr_count != 1) {
        if (decoder) hb_decoder_destroy(decoder);
        fixture_destroy(&f);
        return 2;
    }
    hb_decoder_destroy(decoder);
    f.blocks = 1;
    if (!hb_runtime_register_native_fastpath(addr, spinning_fastpath, NULL)) {
        fixture_destroy(&f); return 2;
    }
    /* This regression exercises runtime's lower C fastpath, not a helper
     * emitted into the native block. No compiled block in this fixture exists
     * before the refresh, and subsequent fixtures are not needed. */
    setenv("MACRUNNER_HB_NATIVE_FASTPATH_INLINE", "0", 1);
    hb_env_refresh();
    unsigned bad = 0;
    for (unsigned b = 0; b < sizeof(mixed_budgets)/sizeof(mixed_budgets[0]); ++b) {
        const budget_t *budget = &mixed_budgets[b];
        uint64_t expected = budget->blocks ? budget->blocks :
                            budget->steps ? budget->steps : HB_CHAIN_POLL_QUANTUM;
        hb_result_t expected_result = budget->blocks ? HB_ERR_BLOCK_LIMIT : HB_ERR_STEP_LIMIT;
        hb_result_t expected_transport = budget->blocks ? HB_ERR_BLOCK_LIMIT : HB_OK;
        unsigned failures = 0;
        uint64_t callback_total = 0;
        for (unsigned run = 0; run < RESUMES; ++run) {
            /* Re-enter the native jump each time, covering both a cold and
             * cached source before exercising the lower C continuation. */
            initialize(&f, budget);
            uint64_t dispatch_before = f.rt->guard_dispatch;
            hb_exec_result_t out = {0};
            alarm(20);
            hb_result_t rc = hb_jit_runtime_run(f.rt, f.func, &out);
            alarm(0);
            uint64_t callbacks = f.ctx[1]->regs.x64.rax;
            callback_total += callbacks;
            failures += rc != expected_transport || out.result != expected_result ||
                        out.faulted != (budget->blocks != 0) || !out.execution_started ||
                        !out.counters_are_dispatches || !hb_exec_result_has_progress(&out) ||
                        callbacks != expected - 1 || f.rt->guard_dispatch - dispatch_before != 1 ||
                        out.steps_executed != expected || out.blocks_executed != expected ||
                        f.ctx[1]->step_count != expected || f.ctx[1]->block_count != expected ||
                        f.ctx[1]->pc != addr || f.ctx[1]->regs.x64.rip != addr;
        }
        bad += failures;
        printf("ZERO_TRANSIT_BUDGET_MIXED_FASTPATH budget=%s runs=%u callbacks=%" PRIu64
               " public_credits_per_run=%" PRIu64 " mismatches=%u\n",
               budget->name, RESUMES, callback_total, expected, failures);
    }
    fixture_destroy(&f);
    return bad ? 1 : 0;
}

int main(int argc, char **argv) {
    const char *mode = "on";
    int no_ic = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--no-ic")) no_ic = 1;
        else if (!strcmp(argv[i], "--sra")) force_sra = 1;
        else if (!strcmp(argv[i], "--ic-only")) force_ic = 1;
        else if (!strcmp(argv[i], "--callret-only")) force_callret = 1;
        else return 2;
    }
    int on = !strcmp(mode, "on"), pc = !strcmp(mode, "pc");
    int no_counters = on || !strcmp(mode, "counters");
    if (!on && !pc && !no_counters && strcmp(mode, "off")) return 2;
    if (!configure_oracle_timeout()) return 2;
    game_gates();
    setenv("MACRUNNER_HB_CHAIN_BODY_ENTRY", on ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_NO_COUNTERS", no_counters ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_LAZY_PC", on || pc ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_SKIP_NOP", on ? "1" : "0", 1);
    force_l1 = no_ic;
    if (no_ic || force_callret) {
        setenv("MACRUNNER_HB_INDIRECT_IC", "0", 1);
        /* RET dispatch must continue after the first cold predictor miss so
         * it can fill the shadow-stack slot. INDIRECT_IC=0 still prevents
         * the competing native per-site probe from being emitted. */
        setenv("MACRUNNER_HB_INDIRECT_IC_RET", force_callret ? "1" : "0", 1);
    }
    if (force_ic || force_callret) setenv("MACRUNNER_HB_L1_TABLE", "0", 1);
    if (force_callret) setenv("MACRUNNER_HB_CALLRET", "1", 1);
    if (force_sra) setenv("MACRUNNER_HB_STATIC_REGS", "1", 1);
    signal(SIGALRM, timeout_handler);
    hb_env_refresh(); hb_memory_install_fault_handlers();
    printf("ZERO_TRANSIT_BUDGET_MODE mode=%s no_ic=%d ic_only=%d callret_only=%d sra=%d\n",
           mode, no_ic, force_ic, force_callret, force_sra);
    int rc = 0;
    for (unsigned shape = 0; shape < sizeof(shapes)/sizeof(shapes[0]) && !rc; ++shape) {
        if ((no_ic || force_ic) && shape != 2) continue;
        if (force_callret && shape != 3) continue;
        if (force_sra && shape != 1) continue;
        for (unsigned b = 0; b < sizeof(budgets)/sizeof(budgets[0]) && !rc; ++b) {
            if (!no_counters && !budgets[b].steps && !budgets[b].blocks) continue;
            rc = run_case(shape, &budgets[b], no_counters, 0);
        }
    }
    /* The bare branch takes codegen's specialized block path. */
    if (!rc && no_counters && !no_ic && !force_ic && !force_callret && !force_sra)
        rc = run_case(0, &budgets[sizeof(budgets)/sizeof(budgets[0]) - 1], no_counters, 1);
    if (!rc && no_counters && !no_ic && !force_ic && !force_callret && !force_sra)
        rc = fastpath_case();
    if (!rc && no_counters && !no_ic && !force_ic && !force_callret && !force_sra)
        rc = mixed_fastpath_case();
    return rc;
}
