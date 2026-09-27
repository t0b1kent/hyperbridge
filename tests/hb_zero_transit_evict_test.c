/* Exact link revocation with UNCHAIN_WALK=0. Each frame variant is a fresh
 * process because the production gate snapshot is immutable during a run. */
#include <inttypes.h>
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
#include "hb_regalloc.h"
#include "hb_runtime.h"
#include "hb_transit.h"

#define PAGE 16384u
#define CODE_SIZE (5u * PAGE)
#define CHECK(c) do { ++checks; if (!(c)) { \
    fprintf(stderr, "TRANSIT_REVOKE fail line=%d: %s\n", __LINE__, #c); return 1; \
} } while (0)

static unsigned checks, comparisons, revocations, restitches, dynamic_off_revocations;
typedef struct {
    uint8_t *code;
    hb_memory_t *mem;
    hb_context_t *jit, *interp;
    hb_jit_runtime_t *rt;
    hb_ir_func_t *func;
    size_t start[4], len[4];
    unsigned count;
    hb_ir_block_t *retired[16];
    unsigned retired_count;
    int saved_sra;
} fixture_t;
typedef struct { uint8_t *site; uint64_t source, target; uint32_t word; } site_t;

static void rel32(uint8_t *at, const uint8_t *target) {
    int32_t d = (int32_t)(target - (at + 4)); memcpy(at, &d, sizeof(d));
}
static hb_ir_block_t *lift(fixture_t *f, unsigned i) {
    hb_decoder_t *d = hb_decoder_create(HB_ARCH_X64, f->code + f->start[i],
                                         f->len[i], (uintptr_t)f->code + f->start[i]);
    hb_ir_func_t *part = NULL;
    if (!d || hb_lift_func_x64(d, &part) != HB_OK || !part || part->cfg->block_count != 1)
        return NULL;
    hb_decoder_destroy(d);
    hb_ir_block_t *b = part->cfg->blocks[0]; b->id = i;
    part->cfg->block_count = 0; part->cfg->entry = NULL; hb_ir_func_destroy(part);
    return b;
}
static int make_program(fixture_t *f, int self) {
    memset(f->code, 0xcc, CODE_SIZE);
    f->start[0] = 0; f->start[1] = PAGE; f->start[2] = 2 * PAGE;
    f->start[3] = 2 * PAGE + 10; f->count = self ? 2 : 4;
    if (self) {
        if (f->saved_sra) {
            uint8_t *p = f->code;
            for (unsigned j = 0; j < 5; ++j) {
                p[j*4] = 0x48; p[j*4+1] = 0x83; p[j*4+2] = 0xc0; p[j*4+3] = 1;
            }
            p[20] = 0x50; p[21] = 0x58; /* helper PUSH/POP force the saved SRA bank */
            const uint8_t tail[] = {0x48,0x83,0xe9,1, 0x0f,0x85,0,0,0,0};
            memcpy(p + 22, tail, sizeof(tail)); rel32(p + 28, p);
            f->len[0] = 32; f->start[1] = 32; f->len[1] = 5;
            p[32] = 0xe9; rel32(p + 33, p + 4 * PAGE);
        } else {
            const uint8_t b[] = {0x48,0x83,0xc0,1, 0x48,0x83,0xe9,1, 0x0f,0x85,0,0,0,0};
            memcpy(f->code, b, sizeof(b)); rel32(f->code + 10, f->code);
            f->len[0] = sizeof(b); f->start[1] = sizeof(b); f->len[1] = 5;
            f->code[sizeof(b)] = 0xe9; rel32(f->code + sizeof(b) + 1, f->code + 4 * PAGE);
        }
    } else {
        for (unsigned k = 0; k < 2; ++k) {
            uint8_t *p = f->code + f->start[k];
            /* Enough reuse to select an actual scratch SRA binding. */
            for (unsigned j = 0; j < 5; ++j) {
                p[j*4] = 0x48; p[j*4+1] = 0x83; p[j*4+2] = k && !f->saved_sra ? 0xc3 : 0xc0;
                p[j*4+3] = k ? 3 : 1;
            }
            unsigned tail = 20;
            if (f->saved_sra) { p[tail++] = 0x50; p[tail++] = 0x58; }
            p[tail] = 0xe9; rel32(p + tail + 1, f->code + f->start[k+1]); f->len[k] = tail + 5;
        }
        const uint8_t tail[] = {0x48,0x83,0xe9,1, 0x0f,0x85,0,0,0,0, 0xe9,0,0,0,0};
        memcpy(f->code + 2 * PAGE, tail, sizeof(tail));
        rel32(f->code + 2 * PAGE + 6, f->code);
        rel32(f->code + 2 * PAGE + 11, f->code + 4 * PAGE);
        f->len[2] = 10; f->len[3] = 5;
    }
    f->func = hb_ir_func_create((uintptr_t)f->code, CODE_SIZE);
    CHECK(f->func != NULL);
    for (unsigned i = 0; i < f->count; ++i) {
        hb_ir_block_t *b = lift(f, i); CHECK(b != NULL); hb_ir_cfg_add_block(f->func->cfg, b);
    }
    f->func->cfg->entry = f->func->cfg->blocks[0];
    return 0;
}
static int create(fixture_t *f) {
    memset(f, 0, sizeof(*f));
    f->code = mmap(NULL, CODE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    CHECK(f->code != MAP_FAILED);
    f->mem = hb_memory_create(0); f->jit = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    f->interp = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    CHECK(f->mem && f->jit && f->interp);
    CHECK(hb_memory_sync_live_range(f->mem, (uintptr_t)f->code, CODE_SIZE,
                                    HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) == HB_OK);
    f->jit->memory = f->interp->memory = f->mem;
    f->rt = hb_jit_runtime_create(f->jit); CHECK(f->rt != NULL);
    return 0;
}
static void prepare(hb_context_t *ctx, fixture_t *f, unsigned start) {
    hb_context_reset(ctx); ctx->memory = f->mem; ctx->config.fallback_enabled = false;
    ctx->step_limit = ctx->block_limit = 0;
    uint64_t *g = (uint64_t *)&ctx->regs.x64;
    for (size_t i = 0; i < sizeof(ctx->regs.x64)/8; ++i) g[i] = UINT64_C(0x7213) + i * 19;
    ctx->regs.x64.rflags = 2; ctx->regs.x64.rcx = 9;
    if (f->saved_sra) ctx->regs.x64.rsp = (uintptr_t)f->code + 4 * PAGE;
    ctx->pc = ctx->regs.x64.rip = (uintptr_t)f->code + f->start[start];
}
static int compare(fixture_t *f, unsigned start) {
    hb_exec_result_t a = {0}, b = {0};
    hb_ir_block_t *saved_entry = f->func->cfg->entry;
    f->func->cfg->entry = f->func->cfg->blocks[start];
    prepare(f->interp, f, start); prepare(f->jit, f, start);
    CHECK(hb_runtime_run(f->interp, f->func, HB_BACKEND_INTERP, &a) == HB_OK);
    CHECK(hb_jit_runtime_run(f->rt, f->func, &b) == HB_OK);
    CHECK(a.result == HB_OK && b.result == HB_OK && !a.faulted && !b.faulted);
    CHECK(hb_lazy_flags_materialize(f->interp, HB_FLAG_BIT_ALL) == HB_OK);
    CHECK(hb_lazy_flags_materialize(f->jit, HB_FLAG_BIT_ALL) == HB_OK);
    if (memcmp(&f->interp->regs.x64, &f->jit->regs.x64, sizeof(f->jit->regs.x64))) {
        const uint64_t *a64 = (const uint64_t *)&f->interp->regs.x64;
        const uint64_t *b64 = (const uint64_t *)&f->jit->regs.x64;
        for (size_t i = 0; i < sizeof(f->jit->regs.x64)/8; ++i) if (a64[i] != b64[i])
            fprintf(stderr, "TRANSIT_REVOKE diff comparison=%u start=%u word=%zu interp=%" PRIx64 " jit=%" PRIx64 "\n",
                    comparisons, start, i, a64[i], b64[i]);
    }
    CHECK(!memcmp(&f->interp->regs.x64, &f->jit->regs.x64, sizeof(f->jit->regs.x64)));
    CHECK(!memcmp(&f->interp->flags, &f->jit->flags, sizeof(f->jit->flags)));
    CHECK(f->interp->pc == f->jit->pc); ++comparisons;
    f->func->cfg->entry = saved_entry;
    return 0;
}
static hb_block_cache_entry_t *entry(fixture_t *f, unsigned block) {
    hb_block_cache_t *c = f->rt->block_cache;
    for (size_t i = 0; i < c->used_count; ++i) {
        hb_block_cache_entry_t *e = &c->entries[c->used_slots[i]];
        if (e->valid && e->guest_addr == (uintptr_t)f->code + f->start[block]) return e;
    }
    return NULL;
}
static int verify_frame_mode(fixture_t *f, int lean, int sra, unsigned block) {
    if (!lean && !sra) return 0;
    hb_arm64_codegen_t *cg = hb_arm64_codegen_create(f->jit);
    hb_codegen_buffer_t *buf = hb_codegen_buffer_create(65536);
    CHECK(cg && buf);
    CHECK(hb_arm64_codegen_block_with_cfg(cg, f->func->cfg->blocks[block], f->func->cfg, buf) == HB_OK);
    printf("TRANSIT_REVOKE_FRAME lean=%d sra=%d mask=%x bank=%u calls=%u size=%zu nrax=%u wrrax=%u segs=%u\n",
           lean, sra, (unsigned)buf->sra_mask, (unsigned)buf->sra_bank,
           (unsigned)buf->emitted_call, buf->size, buf->sra_cnt_n[HB_REG_RAX],
           buf->sra_cnt_wr[HB_REG_RAX], (unsigned)buf->sra_seg_count);
    if (sra) {
        CHECK(buf->sra_mask && buf->sra_bank == (sra == 2 ? HB_SRA_BANK_SAVED : HB_SRA_BANK_SCRATCH));
        if (sra == 2) {
            uint32_t first; CHECK(buf->size >= 4); memcpy(&first, buf->code, 4);
            CHECK(first == 0xa9bb53f3u && buf->emitted_call);
        }
    }
    if (lean) {
        uint32_t first; CHECK(buf->size >= 4); memcpy(&first, buf->code, 4);
        if (lean == 2) {
            uint32_t fourth; CHECK(buf->size >= 16); memcpy(&fourth, buf->code + 12, 4);
            printf("TRANSIT_REVOKE_REMAP first=%08x fourth=%08x rmap=%u\n", first, fourth, buf->rmap_active);
            /* The public wrapper resets rmap_active after emission; the
             * actual MOV context destination proves this remapped frame. */
            CHECK(first == 0xa9bd53f3u && fourth != 0xaa0003f3u);
        } else CHECK(first != 0xa9bd53f3u && !buf->emitted_call);
    }
    hb_codegen_buffer_destroy(buf); hb_arm64_codegen_destroy(cg);
    return 0;
}
static hb_block_chain_meta_t *meta(fixture_t *f, hb_block_cache_entry_t *e) {
    return &f->rt->block_cache->chain_meta[e - f->rt->block_cache->entries];
}
static unsigned sites(fixture_t *f, site_t *out, unsigned max) {
    hb_block_cache_t *c = f->rt->block_cache; unsigned n = 0;
    for (size_t i = 0; i < c->used_count; ++i) {
        hb_block_cache_entry_t *e = &c->entries[c->used_slots[i]];
        if (!e->valid) continue;
        for (size_t off = 0; off + HB_TRANSIT_SLOT_BYTES <= e->native_size; off += 4) {
            uint32_t w[5]; memcpy(w, e->native_code + off, sizeof(w));
            uint64_t target;
            if (!hb_transit_decode(w, &target)) continue;
            if (n < max) out[n] = (site_t){e->native_code + off, e->guest_addr, target, w[0]};
            ++n;
        }
    }
    return n;
}
static int transit_test_revoke(fixture_t *f, unsigned victim, int require_links) {
    site_t old[32]; unsigned n = sites(f, old, 32), inbound = 0, outbound = 0;
    uint64_t pc = (uintptr_t)f->code + f->start[victim];
    CHECK(n <= 32);
    hb_block_cache_entry_t *e = entry(f, victim); CHECK(e != NULL);
    hb_block_chain_meta_t *m = f->rt->block_cache->chain_meta ? meta(f, e) : NULL;
    for (unsigned i = 0; i < n; ++i) if (old[i].word != HB_TRANSIT_COLD_BRANCH) {
        inbound += old[i].target == pc; outbound += old[i].source == pc;
    }
    if (require_links) CHECK(inbound && outbound && m && m->transit_in && m->transit_out);
    else {
        if (inbound || outbound || (m && (m->transit_in || m->transit_out)))
            fprintf(stderr, "TRANSIT_REVOKE unexpected victim=%u inbound=%u outbound=%u\n", victim, inbound, outbound);
        CHECK(!inbound && !outbound && (!m || (!m->transit_in && !m->transit_out)));
    }
    CHECK(hb_jit_invalidate_guest_range(f->rt, pc, 1) == 1);
    CHECK(entry(f, victim) == NULL);
    if (m) CHECK(!m->transit_in && !m->transit_out);
    /* Check machine words immediately, before any dispatch can reuse a body. */
    for (unsigned i = 0; i < n; ++i) if (old[i].target == pc || old[i].source == pc) {
        uint32_t now; memcpy(&now, old[i].site, sizeof(now)); CHECK(now == HB_TRANSIT_COLD_BRANCH);
        if (old[i].word != HB_TRANSIT_COLD_BRANCH) ++revocations;
    }
    return 0;
}
static int replace_b(fixture_t *f, uint8_t immediate) {
    for (unsigned j = 0; j < 5; ++j) f->code[PAGE + j*4 + 3] = immediate;
    hb_ir_block_t *b = lift(f, 1); CHECK(b != NULL);
    CHECK(f->retired_count < sizeof(f->retired)/sizeof(f->retired[0]));
    f->retired[f->retired_count++] = f->func->cfg->blocks[1]; f->func->cfg->blocks[1] = b;
    return 0;
}
static int reset(fixture_t *f) {
    hb_jit_runtime_reset(f->rt, f->jit); CHECK(f->rt->block_cache->count == 0);
    hb_block_cache_t *c = f->rt->block_cache;
    if (c->chain_meta) for (size_t i = 0; i < c->size; ++i)
        CHECK(!c->chain_meta[i].transit_in && !c->chain_meta[i].transit_out);
    for (unsigned i = 0; i < f->retired_count; ++i) hb_ir_block_destroy(f->retired[i]);
    f->retired_count = 0;
    return 0;
}
static void gates(int lean, int sra) {
    const char *on[] = {"BLOCK_CHAIN","CHAIN_PATCH","CHAIN_TWO_SLOTS","CHAIN_AFTER_RUN",
        "CHAIN_RESTITCH","CHAIN_BODY_ENTRY","CHAIN_NO_COUNTERS","CHAIN_LAZY_PC","CHAIN_SKIP_NOP",
        "NO_CTX_SNAPSHOT","JIT_DIRECT_MEM","JIT_DIRECT_STACK_X64","SMC_DIRECT_HASH"};
    for (size_t i = 0; i < sizeof(on)/sizeof(on[0]); ++i) {
        char key[96]; snprintf(key, sizeof(key), "MACRUNNER_HB_%s", on[i]); setenv(key, "1", 1);
    }
    setenv("MACRUNNER_HB_FAST_EXEC", "507", 1);
    setenv("MACRUNNER_HB_UNCHAIN_WALK", "0", 1);
    setenv("MACRUNNER_HB_SMC_FUNC_SPAN", "0", 1);
    setenv("MACRUNNER_HB_CHAIN_FORWARD_ONLY", "0", 1);
    setenv("MACRUNNER_HB_LEAN_FRAME", lean ? "1" : "0", 1);
    setenv("MACRUNNER_HB_LEAN_REMAP_ONLY", lean == 2 ? "1" : "0", 1);
    setenv("MACRUNNER_HB_STATIC_REGS", sra ? "1" : "0", 1);
    if (sra == 2) setenv("MACRUNNER_HB_JIT_DIRECT_STACK_X64", "0", 1);
    hb_env_refresh(); hb_memory_install_fault_handlers();
}
int main(int argc, char **argv) {
    int lean = argc == 2 && !strcmp(argv[1], "--lean") ? 1 :
               argc == 2 && !strcmp(argv[1], "--remap") ? 2 : 0;
    int sra = argc == 2 && !strcmp(argv[1], "--sra") ? 1 :
              argc == 2 && !strcmp(argv[1], "--sra-saved") ? 2 : 0;
    if (argc > 2 || (argc == 2 && !lean && !sra)) return 2;
    alarm(30); /* A broken self-edge must fail, not leave make test hanging. */
    gates(lean, sra); fixture_t f;
    if (create(&f)) return 1;
    f.saved_sra = sra == 2;
    if (make_program(&f, 0)) return 1;
    if (verify_frame_mode(&f, lean, sra, 0)) return 1;
    if (sra == 2 && verify_frame_mode(&f, lean, sra, 1)) return 1;
    for (unsigned pass = 0; pass < 5; ++pass) if (compare(&f, 0)) return 1;
    CHECK(entry(&f, 0));
    uint8_t *first_native = entry(&f, 0)->native_code;
    if (!lean && sra != 2) {
        /* Disabling future chaining must not prevent removal of already
         * installed incoming/outgoing branches when a live target is evicted. */
        setenv("MACRUNNER_HB_BLOCK_CHAIN", "0", 1);
        hb_runtime_set_chain_x64_disabled(true); hb_env_refresh();
        if (transit_test_revoke(&f, 1, 1)) return 1;
        ++dynamic_off_revocations;
        hb_runtime_set_chain_x64_disabled(false);
        setenv("MACRUNNER_HB_BLOCK_CHAIN", "1", 1); hb_env_refresh();
        for (unsigned pass = 0; pass < 5; ++pass) if (compare(&f, 0)) return 1;
    }
    for (unsigned cycle = 0; cycle < 4; ++cycle) {
        if (transit_test_revoke(&f, 1, !lean && sra != 2) || replace_b(&f, (uint8_t)(5 + cycle)) || compare(&f, 0)) return 1;
        for (unsigned pass = 0; pass < 3; ++pass) if (compare(&f, 0)) return 1;
        ++restitches;
        if (transit_test_revoke(&f, 0, !lean && sra != 2) || compare(&f, 0)) return 1;
        for (unsigned pass = 0; pass < 3; ++pass) if (compare(&f, 0)) return 1;
    }
    uint64_t ev_before = 0, ev_after = 0;
    hb_jit_smc_reverify_stats(NULL, NULL, &ev_before, NULL);
    /* Enter the changed target through C so SMC detects it before a chained
     * predecessor can use its old body. The old IR stays alive until reset. */
    if (replace_b(&f, 17)) return 1;
    prepare(f.jit, &f, 1);
    hb_regs_x64_t before_smc = f.jit->regs.x64;
    hb_exec_result_t smc_out = {0};
    CHECK(hb_jit_runtime_run(f.rt, f.func, &smc_out) == HB_OK);
    CHECK(smc_out.result == HB_OK && !smc_out.faulted && !hb_exec_result_has_progress(&smc_out));
    CHECK(!memcmp(&before_smc, &f.jit->regs.x64, sizeof(before_smc)));
    CHECK(f.jit->pc == (uintptr_t)f.code + PAGE);
    hb_jit_smc_reverify_stats(NULL, NULL, &ev_after, NULL);
    CHECK(ev_after > ev_before);
    if (compare(&f, 1)) return 1;
    for (unsigned pass = 0; pass < 4; ++pass) if (compare(&f, 0)) return 1;
    if (reset(&f)) return 1; hb_ir_func_destroy(f.func);
    if (make_program(&f, 1)) return 1;
    if (sra == 2 && verify_frame_mode(&f, lean, sra, 0)) return 1;
    for (unsigned pass = 0; pass < 5; ++pass) if (compare(&f, 0)) return 1;
    /* Reset rewinds the arena: this executes unrelated replacement code at the
     * original address after all old incoming/outgoing metadata was cleared. */
    CHECK(entry(&f, 0) && entry(&f, 0)->native_code == first_native);
    if (transit_test_revoke(&f, 0, !lean && sra != 2)) return 1;
    for (unsigned pass = 0; pass < 5; ++pass) if (compare(&f, 0)) return 1;
    if (reset(&f)) return 1;
    hb_ir_func_destroy(f.func); hb_jit_runtime_destroy(f.rt);
    f.jit->memory = f.interp->memory = NULL;
    hb_context_destroy(f.jit); hb_context_destroy(f.interp); hb_memory_destroy(f.mem);
    munmap(f.code, CODE_SIZE);
    alarm(0);
    printf("TRANSIT_REVOKE lean=%d sra=%d checks=%u comparisons=%u words_restored=%u restitches=%u smc_evictions=%" PRIu64 " reset_reuse=1 dynamic_off_revocations=%u mismatches=0\n",
           lean, sra, checks, comparisons, revocations, restitches, ev_after - ev_before, dynamic_off_revocations);
    return 0;
}
