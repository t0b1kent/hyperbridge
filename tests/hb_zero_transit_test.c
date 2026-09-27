/* Randomized, real-x86 multi-block oracle for shared-frame block transitions.
 * Each arm must run in a fresh process: production gates are cached. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

#define PAGE 16384u
#define CASES 32u
#define RUNS 4u
#define MAX_BLOCKS 12u

typedef struct {
    uint8_t *code, *data, *stack;
    hb_context_t *ctx[2];
    hb_memory_t *mem[2];
    hb_jit_runtime_t *rt;
} fixture_t;

typedef struct {
    uint8_t *code;
    size_t pos, start[MAX_BLOCKS], end[MAX_BLOCKS];
    struct { size_t at; unsigned target, width; } fix[24];
    unsigned count, fixes;
} program_t;

typedef struct {
    hb_regs_x64_t regs;
    hb_flags_t flags;
    uint64_t pc, blocks;
    hb_result_t transport, result;
    int faulted, counters_are_dispatches;
    uint8_t data[PAGE], stack[PAGE];
} result_t;

static uint64_t random64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return *state = x;
}

static void bytes(program_t *p, const uint8_t *src, size_t n) {
    memcpy(p->code + p->pos, src, n); p->pos += n;
}
#define BYTES(p, ...) bytes((p), (const uint8_t[]){__VA_ARGS__}, sizeof((const uint8_t[]){__VA_ARGS__}))
static void begin(program_t *p, unsigned block) {
    p->start[block] = p->pos;
    if (block + 1 > p->count) p->count = block + 1;
}
static void end(program_t *p, unsigned block) { p->end[block] = p->pos; }
static void fixup(program_t *p, unsigned target, unsigned width) {
    p->fix[p->fixes].at = p->pos;
    p->fix[p->fixes].target = target;
    p->fix[p->fixes++].width = width;
    memset(p->code + p->pos, 0, width); p->pos += width;
}
static void branch(program_t *p, unsigned op, unsigned target) {
    BYTES(p, op); fixup(p, target, 4);
}
static void conditional(program_t *p, unsigned op, unsigned target) {
    BYTES(p, 0x0f, op); fixup(p, target, 4);
}
static hb_ir_func_t *finish(program_t *p) {
    for (unsigned i = 0; i < p->fixes; ++i) {
        size_t at = p->fix[i].at;
        unsigned target = p->fix[i].target;
        size_t dest = target == MAX_BLOCKS ? PAGE - 16 : p->start[target];
        if (p->fix[i].width == 8) {
            uint64_t absolute = (uintptr_t)p->code + dest;
            memcpy(p->code + at, &absolute, 8);
        } else {
            int32_t relative = (int32_t)(dest - (at + 4));
            memcpy(p->code + at, &relative, 4);
        }
    }
    hb_ir_func_t *f = hb_ir_func_create((uintptr_t)p->code, p->pos);
    if (!f) return NULL;
    /* The public x64 lifter returns one block. Preserve that block's genuine
     * instruction provenance while assembling a dispatcher-visible function. */
    for (unsigned i = 0; i < p->count; ++i) {
        hb_decoder_t *d = hb_decoder_create(HB_ARCH_X64, p->code + p->start[i],
                                            p->end[i] - p->start[i],
                                            (uintptr_t)p->code + p->start[i]);
        hb_ir_func_t *part = NULL;
        if (!d || hb_lift_func_x64(d, &part) != HB_OK || !part ||
            !part->cfg || part->cfg->block_count != 1) {
            if (d) hb_decoder_destroy(d);
            if (part) hb_ir_func_destroy(part);
            hb_ir_func_destroy(f); return NULL;
        }
        hb_decoder_destroy(d);
        hb_ir_block_t *block = part->cfg->blocks[0];
        block->id = i;
        hb_ir_cfg_add_block(f->cfg, block);
        part->cfg->block_count = 0; part->cfg->entry = NULL;
        hb_ir_func_destroy(part);
    }
    f->cfg->entry = f->cfg->blocks[0];
    return f;
}

static hb_ir_func_t *random_program(program_t *p, unsigned seed) {
    uint64_t rng = UINT64_C(0xbce291c703ab1567) ^ seed;
    unsigned a = 1 + random64(&rng) % 63, b = 1 + random64(&rng) % 63;
    unsigned c = 1 + random64(&rng) % 63;
    unsigned disp = (unsigned)(random64(&rng) % 4) * 32;
    static const uint8_t conditions[] = {0x87, 0x86, 0x8f, 0x8e}; /* JA/JBE/JG/JLE */
    begin(p, 0);
    BYTES(p, 0x48,0x83,(seed & 2u) ? 0xe8 : 0xc0,a); /* add/sub rax,a */
    BYTES(p, 0x48,0x89,0x47,disp);           /* mov [rdi+disp],rax */
    BYTES(p, 0x48,0x83,0xf9,4);              /* cmp rcx,4 */
    conditional(p, conditions[seed % 4], 2); end(p, 0);
    begin(p, 1);
    BYTES(p, 0x48,0x83,0xc3,b);              /* add rbx,b */
    BYTES(p, 0x49,(seed & 4u) ? 0x01 : 0x31,0xd8); /* add/xor r8,rbx */
    branch(p, 0xe9, 3); end(p, 1);
    begin(p, 2);
    BYTES(p, 0x48,0x83,0xeb,c);              /* sub rbx,c */
    BYTES(p, 0x49,(seed & 8u) ? 0x31 : 0x01,0xc1); /* xor/add r9,rax */
    branch(p, 0xe9, 3); end(p, 2);
    begin(p, 3); BYTES(p, 0x56);             /* push rsi */
    if (seed & 2u) {
        BYTES(p, 0x49,0xbb); fixup(p, 7, 8); /* mov r11,callee */
        BYTES(p, 0x41,0xff,0xd3);            /* call r11 */
    } else branch(p, 0xe8, 7);              /* call callee */
    end(p, 3);
    begin(p, 4);
    if (!(seed & 1u)) BYTES(p, 0x5e);        /* pop rsi; odd callee used ret 8 */
    BYTES(p, 0x49,0xba);                      /* mov r10,loop */
    fixup(p, 5, 8); BYTES(p, 0x41,0xff,0xe2); end(p, 4); /* jmp r10 */
    begin(p, 5);
    BYTES(p, 0x48,0x8b,0x57,disp);           /* mov rdx,[rdi+disp] */
    BYTES(p, 0x48,0x01,0x57,disp + 8);       /* add [rdi+disp+8],rdx */
    BYTES(p, 0x48,0x83,0xe9,1);              /* sub rcx,1 */
    conditional(p, 0x85, 0); end(p, 5);      /* jne head */
    begin(p, 6); BYTES(p, 0x48,0x39,0xc3);   /* cmp rbx,rax: all flags defined */
    branch(p, 0xe9, MAX_BLOCKS); end(p, 6);
    begin(p, 7);
    BYTES(p, 0x55,0x48,0x89,0xe5);           /* push rbp; mov rbp,rsp */
    BYTES(p, 0x48,0x83,0xc6,c);              /* add rsi,c */
    BYTES(p, 0x48,0x89,0x77,16);             /* mov [rdi+16],rsi */
    BYTES(p, 0x5d);                           /* pop rbp */
    if (seed & 1u) BYTES(p, 0xc2,8,0);        /* ret 8: stack helper must retain target */
    else BYTES(p, 0xc3);
    end(p, 7);
    return finish(p);
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
    for (unsigned k = 0; k < 2; ++k) {
        f->ctx[k]->memory = NULL;
        hb_context_destroy(f->ctx[k]); hb_memory_destroy(f->mem[k]);
    }
    munmap(f->code, PAGE); munmap(f->data, PAGE); munmap(f->stack, PAGE);
}

static void initialize(fixture_t *f, unsigned k, unsigned seed, unsigned run) {
    hb_context_t *ctx = f->ctx[k];
    hb_context_reset(ctx);
    ctx->memory = f->mem[k]; ctx->config.fallback_enabled = false;
    ctx->step_limit = ctx->block_limit = 0;
    uint64_t rng = UINT64_C(0xca87e5f120390ab1) ^ ((uint64_t)seed << 20) ^ run;
    uint64_t *words = (uint64_t *)&ctx->regs.x64;
    for (size_t i = 0; i < sizeof(ctx->regs.x64) / sizeof(*words); ++i) words[i] = random64(&rng);
    ctx->regs.x64.rflags = 2;
    ctx->regs.x64.rcx = 6 + random64(&rng) % 11;
    ctx->regs.x64.rsp = (uintptr_t)f->stack + PAGE - 128;
    ctx->regs.x64.rbp = (uintptr_t)f->stack + PAGE - 64;
    ctx->regs.x64.rdi = (uintptr_t)f->data;
    ctx->pc = ctx->regs.x64.rip = (uintptr_t)f->code;
    for (unsigned i = 0; i < PAGE; ++i) {
        f->data[i] = (uint8_t)random64(&rng);
        f->stack[i] = (uint8_t)random64(&rng);
    }
}

static void execute(fixture_t *f, hb_ir_func_t *func, unsigned k, result_t *r) {
    hb_exec_result_t out = {0};
    r->blocks = 0; r->counters_are_dispatches = 0;
    /* A cold RET deliberately returns to the embedding dispatcher until its
     * target is cached. Drive those ordinary HB_OK boundaries just as Wine
     * does, retaining the same runtime so the graph becomes fully stitched. */
    unsigned calls;
    for (calls = 0; calls < 256; ++calls) {
        memset(&out, 0, sizeof(out));
        r->transport = k ? hb_jit_runtime_run(f->rt, func, &out) :
                           hb_runtime_run(f->ctx[k], func, HB_BACKEND_INTERP, &out);
        r->blocks += out.blocks_executed;
        r->counters_are_dispatches |= out.counters_are_dispatches;
        if (r->transport != HB_OK || out.result != HB_OK || out.faulted)
            fprintf(stderr, "ZERO_TRANSIT_RUN backend=%u rc=%d result=%d pc=%" PRIx64 " reason=%s\n",
                    k, r->transport, out.result, f->ctx[k]->pc, out.fault_reason ? out.fault_reason : "none");
        if (r->transport != HB_OK || out.result != HB_OK || out.faulted ||
            f->ctx[k]->pc < func->guest_addr || f->ctx[k]->pc >= func->guest_addr + func->guest_len) break;
    }
    if (calls == 256) r->transport = HB_ERR_INTERNAL;
    if (hb_lazy_flags_materialize(f->ctx[k], HB_FLAG_BIT_ALL) != HB_OK) r->transport = HB_ERR_INTERNAL;
    r->regs = f->ctx[k]->regs.x64; r->flags = f->ctx[k]->flags;
    r->pc = f->ctx[k]->pc; r->result = out.result; r->faulted = out.faulted;
    memcpy(r->data, f->data, PAGE); memcpy(r->stack, f->stack, PAGE);
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

static int different(const result_t *a, const result_t *b, unsigned seed, unsigned run) {
    int regs = memcmp(&a->regs, &b->regs, sizeof(a->regs)) != 0;
    int flags = memcmp(&a->flags, &b->flags, sizeof(a->flags)) != 0;
    int data = memcmp(a->data, b->data, PAGE) != 0;
    int stack = memcmp(a->stack, b->stack, PAGE) != 0;
    int bad = regs || flags || data || stack || a->pc != b->pc ||
              a->transport != HB_OK || b->transport != HB_OK ||
              a->result != HB_OK || b->result != HB_OK || a->faulted || b->faulted;
    if (bad) fprintf(stderr, "ZERO_TRANSIT_DIFF seed=%u run=%u regs=%d flags=%d data=%d stack=%d "
                     "pc=%" PRIx64 "/%" PRIx64 " result=%d/%d transport=%d/%d\n",
                     seed, run, regs, flags, data, stack, a->pc, b->pc,
                     a->result, b->result, a->transport, b->transport);
    return bad;
}

static int corpus(unsigned cases) {
    fixture_t f;
    result_t *results = calloc(2, sizeof(*results));
    if (!results || !fixture_create(&f)) return 2;
    unsigned bad = 0, checked = 0, edges = 0, chained_runs = 0;
    uint64_t reference_blocks = 0, native_dispatches = 0, evictions = 0;
    for (unsigned seed = 1; seed <= cases; ++seed) {
        hb_jit_runtime_reset(f.rt, f.ctx[1]);
        memset(f.code, 0xcc, PAGE);
        program_t p = {.code = f.code};
        hb_ir_func_t *func = random_program(&p, seed);
        if (!func) { fprintf(stderr, "ZERO_TRANSIT lift failed seed=%u\n", seed); return 2; }
        for (unsigned run = 0; run < RUNS; ++run) {
            if (run >= 2) {
                unsigned victim = run == 2 ? 2 : 7; /* direct branch, then CALL/RET target */
                uint64_t count = hb_jit_invalidate_guest_range(f.rt, (uintptr_t)f.code + p.start[victim], 1);
                evictions += count;
                if (!count) { fprintf(stderr, "ZERO_TRANSIT expected live victim seed=%u run=%u\n", seed, run); ++bad; }
            }
            for (unsigned k = 0; k < 2; ++k) {
                initialize(&f, k, seed, run);
                execute(&f, func, k, &results[k]);
            }
            ++checked;
            int mismatch = different(&results[0], &results[1], seed, run);
            bad += mismatch;
            reference_blocks += results[0].blocks;
            if (results[1].counters_are_dispatches) {
                native_dispatches += results[1].blocks;
                if (!mismatch && results[1].blocks < results[0].blocks) ++chained_runs;
                else if (!mismatch && run) {
                    fprintf(stderr, "ZERO_TRANSIT warm run did not chain seed=%u run=%u blocks=%" PRIu64
                                    " dispatches=%" PRIu64 "\n", seed, run, results[0].blocks, results[1].blocks);
                    ++bad;
                }
            }
            if (bad > 8) break;
        }
        edges += stitched_edges(&f);
        hb_jit_runtime_reset(f.rt, f.ctx[1]); hb_ir_func_destroy(func);
        if (bad > 8) break;
    }
    if (!edges) { fprintf(stderr, "ZERO_TRANSIT no stitched edges observed\n"); ++bad; }
    printf("ZERO_TRANSIT_CORPUS programs=%u cases=%u stitched=%u reference_blocks=%" PRIu64
           " native_dispatches=%" PRIu64 " chained_runs=%u evictions=%" PRIu64 " mismatches=%u\n",
           cases, checked, edges, reference_blocks, native_dispatches, chained_runs, evictions, bad);
    fixture_destroy(&f); free(results);
    return bad ? 1 : 0;
}

static void fault_initialize(fixture_t *f, uint64_t *ro) {
    initialize(f, 1, 19, 0);
    memset(f->data, 0, PAGE);
    f->ctx[1]->regs.x64.rsi = (uintptr_t)ro;
    f->ctx[1]->regs.x64.rax = UINT64_C(0x291d317e5428628a);
    f->ctx[1]->regs.x64.rbx = UINT64_C(0xabcde01234567890);
    f->ctx[1]->regs.x64.r8 = 100;
}

static int fault_case(void) {
    fixture_t f;
    if (!fixture_create(&f)) return 2;
    uint64_t *ro = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (ro == MAP_FAILED || hb_memory_sync_live_range(f.mem[1], (uintptr_t)ro, PAGE,
                                                      HB_PERM_READ | HB_PERM_WRITE) != HB_OK) return 2;
    program_t p = {.code = f.code};
    begin(&p, 0);
    BYTES(&p, 0x48,0x83,0x07,1,0x53);        /* add qword [rdi],1; push rbx */
    branch(&p, 0xe9, 1); end(&p, 0);
    begin(&p, 1);
    BYTES(&p, 0x49,0x83,0xc0,7,0x56);        /* add r8,7; push rsi */
    branch(&p, 0xe9, 2); end(&p, 1);
    begin(&p, 2);
    BYTES(&p, 0x48,0x83,0x47,8,1);           /* add qword [rdi+8],1 */
    size_t store = p.pos;
    BYTES(&p, 0x48,0x89,0x06);               /* mov [rsi],rax: fault */
    branch(&p, 0xe9, MAX_BLOCKS); end(&p, 2);
    hb_ir_func_t *func = finish(&p);
    if (!func) return 2;
    int bad = 0;
    for (unsigned warm = 0; warm < 3; ++warm) {
        hb_exec_result_t out = {0};
        fault_initialize(&f, ro);
        hb_result_t rc = hb_jit_runtime_run(f.rt, func, &out);
        if (rc != HB_OK || out.result != HB_OK || out.faulted) ++bad;
    }
    unsigned edges = stitched_edges(&f);
    if (edges < 2) ++bad;
    fault_initialize(&f, ro);
    uint64_t original = UINT64_C(0x9c3a809aad810024);
    ro[0] = original;
    uint64_t initial_rsp = f.ctx[1]->regs.x64.rsp;
    hb_regs_x64_t expected_regs = f.ctx[1]->regs.x64;
    expected_regs.r8 = 107;
    expected_regs.rsp -= 16;
    expected_regs.rip = (uintptr_t)f.code + store;
    if (hb_memory_sync_live_range(f.mem[1], (uintptr_t)ro, PAGE, HB_PERM_READ) != HB_OK ||
        mprotect(ro, PAGE, PROT_READ)) return 2;
    uint64_t exact0, map0, block0, exact1, map1, block1;
    hb_jit_fault_pc_stats(&exact0, &map0, &block0);
    hb_exec_result_t out = {0};
    hb_result_t rc = hb_jit_runtime_run(f.rt, func, &out);
    hb_jit_fault_pc_stats(&exact1, &map1, &block1);
    hb_context_t *ctx = f.ctx[1];
    uint64_t expected_pc = (uintptr_t)f.code + store;
    uint64_t *data = (uint64_t *)f.data;
    int flags_bad = hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_ALL) != HB_OK ||
                    ctx->flags.cf || ctx->flags.pf || ctx->flags.af ||
                    ctx->flags.zf || ctx->flags.sf || ctx->flags.of;
    int state_bad = rc != HB_OK || out.result != HB_ERR_MEMORY_FAULT || !out.faulted ||
                    flags_bad || memcmp(&ctx->regs.x64, &expected_regs, sizeof(expected_regs)) ||
                    ctx->pc != expected_pc || ctx->regs.x64.rip != expected_pc ||
                    ctx->regs.x64.r8 != 107 || ctx->regs.x64.rsp != initial_rsp - 16 ||
                    data[0] != 1 || data[1] != 1 || ro[0] != original ||
                    *(uint64_t *)(uintptr_t)(initial_rsp - 8) != ctx->regs.x64.rbx ||
                    *(uint64_t *)(uintptr_t)(initial_rsp - 16) != (uintptr_t)ro;
    int map_bad = exact1 != exact0 + 1 || map1 != map0 || block1 != block0;
    bad += state_bad || map_bad;
    if (mprotect(ro, PAGE, PROT_READ | PROT_WRITE) ||
        hb_memory_sync_live_range(f.mem[1], (uintptr_t)ro, PAGE,
                                  HB_PERM_READ | HB_PERM_WRITE) != HB_OK) return 2;
    /* The embedding dispatcher relifts from the precise fault PC after making
     * the page writable. The two predecessor blocks and the earlier store in
     * block three must not replay. */
    hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, f.code + store, p.end[2] - store, expected_pc);
    hb_ir_func_t *resume = NULL;
    if (!decoder || hb_lift_func_x64(decoder, &resume) != HB_OK || !resume) return 2;
    hb_decoder_destroy(decoder);
    memset(&out, 0, sizeof(out));
    rc = hb_jit_runtime_run(f.rt, resume, &out);
    int resume_bad = rc != HB_OK || out.result != HB_OK || out.faulted ||
                     ctx->pc != (uintptr_t)f.code + PAGE - 16 ||
                     ctx->regs.x64.rip != ctx->pc || ctx->regs.x64.r8 != 107 ||
                     ctx->regs.x64.rsp != initial_rsp - 16 || data[0] != 1 || data[1] != 1 ||
                     ro[0] != UINT64_C(0x291d317e5428628a);
    bad += resume_bad;
    printf("ZERO_TRANSIT_FAULT stitched=%u exact=%" PRIu64 " map=%" PRIu64 " block=%" PRIu64
           " state_bad=%d resume_bad=%d mismatches=%d\n", edges,
           exact1 - exact0, map1 - map0, block1 - block0, state_bad, resume_bad, bad);
    hb_jit_runtime_reset(f.rt, ctx); hb_ir_func_destroy(resume); hb_ir_func_destroy(func);
    fixture_destroy(&f); munmap(ro, PAGE);
    return bad ? 1 : 0;
}

static int counter_contract(int no_counters) {
    fixture_t f;
    if (!fixture_create(&f)) return 2;
    program_t p = {.code = f.code};
    begin(&p, 0); branch(&p, 0xe9, 0); end(&p, 0);
    hb_ir_func_t *func = finish(&p);
    if (!func) return 2;
    int bad = 0;
    for (unsigned block_budget = 0; block_budget < 2; ++block_budget) {
        initialize(&f, 1, 1, 0);
        hb_context_t *ctx = f.ctx[1];
        ctx->step_limit = block_budget ? 0 : 3;
        ctx->block_limit = block_budget ? 3 : 0;
        hb_regs_x64_t before = ctx->regs.x64;
        hb_exec_result_t out = {0};
        hb_result_t rc = hb_jit_runtime_run(f.rt, func, &out);
        int failed;
        if (no_counters) {
            failed = rc != HB_ERR_INVALID_ARG || out.result != HB_ERR_INVALID_ARG ||
                     out.execution_started || hb_exec_result_has_progress(&out) ||
                     ctx->step_count || ctx->block_count || memcmp(&ctx->regs.x64, &before, sizeof(before));
        } else {
            failed = out.result != (block_budget ? HB_ERR_BLOCK_LIMIT : HB_ERR_STEP_LIMIT) ||
                     out.blocks_executed != 3 || out.steps_executed != 3 ||
                     !hb_exec_result_has_progress(&out) || out.counters_are_dispatches;
        }
        bad += failed;
        if (failed) fprintf(stderr, "ZERO_TRANSIT_LIMIT mode=%d block=%u rc=%d result=%d blocks=%" PRIu64
                            " steps=%" PRIu64 " started=%d\n", no_counters, block_budget,
                            rc, out.result, out.blocks_executed, out.steps_executed, out.execution_started);
    }
    hb_exec_result_t sample = {.counters_are_dispatches = true, .blocks_executed = 1, .steps_executed = 1};
    bad += hb_exec_result_has_progress(&sample);
    sample.steps_executed = sample.blocks_executed = 0;
    sample.execution_started = true;
    bad += !hb_exec_result_has_progress(&sample);
    sample.execution_started = false; sample.counters_are_dispatches = false; sample.blocks_executed = 1;
    bad += !hb_exec_result_has_progress(&sample);
    printf("ZERO_TRANSIT_COUNTER_CONTRACT mode=%d checks=5 mismatches=%d\n", no_counters, bad);
    hb_jit_runtime_reset(f.rt, f.ctx[1]); hb_ir_func_destroy(func); fixture_destroy(&f);
    return bad ? 1 : 0;
}

/* The first block falls back before any native admission, commits memory,
 * then faults. Restoring dispatch units must not hide interpreter progress. */
static int fallback_progress_contract(int no_counters) {
    fixture_t f;
    if (!fixture_create(&f)) return 2;
    uint64_t *ro = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (ro == MAP_FAILED) return 2;
    const uint64_t original = UINT64_C(0x863172acbd503e49);
    ro[0] = original;
    if (hb_memory_sync_live_range(f.mem[1], (uintptr_t)ro, PAGE, HB_PERM_READ) != HB_OK ||
        mprotect(ro, PAGE, PROT_READ)) return 2;
    program_t p = {.code = f.code};
    begin(&p, 0);
    BYTES(&p, 0x48,0x83,0x07,1);            /* add qword [rdi],1: committed prefix */
    BYTES(&p, 0x48,0x89,0x06);              /* mov [rsi],rax: interpreter fault */
    branch(&p, 0xe9, MAX_BLOCKS); end(&p, 0);
    hb_ir_func_t *func = finish(&p);
    if (!func) return 2;
    initialize(&f, 1, 1, 0);
    memset(f.data, 0, PAGE);
    f.ctx[1]->regs.x64.rsi = (uintptr_t)ro;
    hb_exec_result_t out = {0};
    hb_result_t rc = hb_jit_runtime_run(f.rt, func, &out);
    int bad = rc != HB_OK || out.result != HB_ERR_MEMORY_FAULT || !out.faulted ||
              f.rt->guard_dispatch != 0 || *(uint64_t *)f.data != 1 || ro[0] != original ||
              !out.steps_executed || (no_counters && !out.execution_started) ||
              !hb_exec_result_has_progress(&out) ||
              out.counters_are_dispatches != no_counters;
    printf("ZERO_TRANSIT_FALLBACK_PROGRESS mode=%d native_dispatches=%" PRIu64
           " steps=%" PRIu64 " blocks=%" PRIu64 " started=%d progress=%d writes=%" PRIu64
           " result=%d transport=%d mismatches=%d\n", no_counters, f.rt->guard_dispatch,
           out.steps_executed, out.blocks_executed, out.execution_started,
           hb_exec_result_has_progress(&out), *(uint64_t *)f.data, out.result, rc, bad);
    hb_jit_runtime_reset(f.rt, f.ctx[1]); hb_ir_func_destroy(func);
    fixture_destroy(&f); munmap(ro, PAGE);
    return bad ? 1 : 0;
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
        char name[100]; snprintf(name, sizeof(name), "MACRUNNER_HB_%s", gates[i]);
        setenv(name, "1", 1);
    }
    setenv("MACRUNNER_HB_FAST_EXEC", "507", 1);
    setenv("MACRUNNER_HB_UNCHAIN_WALK", "0", 1);
    setenv("MACRUNNER_HB_L1_TABLE_BITS", "14", 1);
    setenv("MACRUNNER_HB_BLOCK_CHAIN", "1", 1);
    setenv("MACRUNNER_HB_CHAIN_PATCH", "1", 1);
}

int main(int argc, char **argv) {
    unsigned cases = CASES;
    int mode = 0, negative = 0, fault_only = 0, helper_stack = 0, one_slot = 0, mixed_lean = 0;
    int fallback_progress = 0;
    static const char *const modes[] = {"off", "on", "pc", "counters"};
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--cases") && i + 1 < argc) cases = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            const char *value = argv[++i];
            unsigned found;
            for (found = 0; found < sizeof(modes) / sizeof(modes[0]); ++found)
                if (!strcmp(value, modes[found])) break;
            if (found == sizeof(modes) / sizeof(modes[0])) return 2;
            mode = (int)found;
        } else if (!strcmp(argv[i], "--negative")) negative = 1;
        else if (!strcmp(argv[i], "--fault-only")) fault_only = 1;
        else if (!strcmp(argv[i], "--helper-stack")) helper_stack = 1;
        else if (!strcmp(argv[i], "--one-slot")) one_slot = 1;
        else if (!strcmp(argv[i], "--mixed-lean")) mixed_lean = 1;
        else if (!strcmp(argv[i], "--fallback-progress")) fallback_progress = 1;
        else { fprintf(stderr, "usage: %s [--cases N] [--mode off|on|pc|counters] [--negative] [--fault-only] [--helper-stack] [--one-slot] [--mixed-lean] [--fallback-progress]\n", argv[0]); return 2; }
    }
    int no_counters = mode == 1 || mode == 3;
    setenv("MACRUNNER_HB_CHAIN_BODY_ENTRY", mode == 1 ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_NO_COUNTERS", no_counters ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_LAZY_PC", mode == 1 || mode == 2 ? "1" : "0", 1);
    setenv("MACRUNNER_HB_CHAIN_SKIP_NOP", mode == 1 ? "1" : "0", 1);
    setenv("MACRUNNER_HB_TEST_TRANSIT_FLIP", negative ? "1" : "0", 1);
    game_gates();
    if (fallback_progress) setenv("MACRUNNER_HB_CODEGEN_FAIL_EVERY", "1", 1);
    if (helper_stack) setenv("MACRUNNER_HB_JIT_DIRECT_STACK_X64", "0", 1);
    if (one_slot) setenv("MACRUNNER_HB_CHAIN_TWO_SLOTS", "0", 1);
    if (mixed_lean) {
        /* Force real helpers in memory/stack blocks, while ALU-only leaves
         * still take LEAN_FRAME. This tests a mixed chain with actual links. */
        setenv("MACRUNNER_HB_LEAN_FRAME", "1", 1);
        setenv("MACRUNNER_HB_JIT_DIRECT_MEM", "0", 1);
        setenv("MACRUNNER_HB_JIT_DIRECT_STACK_X64", "0", 1);
    }
    hb_env_refresh(); hb_memory_install_fault_handlers();
    printf("ZERO_TRANSIT_MODE mode=%s negative=%d helper_stack=%d one_slot=%d mixed_lean=%d\n", modes[mode], negative, helper_stack, one_slot, mixed_lean);
    if (fallback_progress) return fallback_progress_contract(no_counters);
    int rc = counter_contract(no_counters);
    if (!rc && !fault_only) rc = corpus(cases);
    /* The signal test specifically requires a native faultable store. */
    if (mixed_lean) { setenv("MACRUNNER_HB_JIT_DIRECT_MEM", "1", 1); hb_env_refresh(); }
    return rc ? rc : fault_case();
}
