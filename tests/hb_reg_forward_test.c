/* Block-local register forwarding: architectural state, including exits in the
 * middle of a chain, must agree with the interpreter. Run in separate processes
 * with REG_FORWARD/XMM_FORWARD=00,10,01,11 (the gates are cached by the engine).
 * MACRUNNER_HB_TEST_REG_FORWARD_FLIP=1 is an emitter negative control: this test
 * must then fail with exit 1, not silently accept an inactive optimization.
 * HB_REG_FORWARD_CASES selects deterministic seeds per case (default 64).
 */
#define _DARWIN_C_SOURCE 1
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

enum { PAGE = 16384, DATA_LEN = 256 };
static uint8_t *code_page, *data_page, *fault_page;
static uint64_t rng = UINT64_C(0x4398bf5043c62fe1);
static uint64_t rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng;
}

typedef struct {
    uint64_t gpr[16], xmm[16][2], yhi[16][2], zhi[16][4], mm[8], k[8];
    uint8_t mem[DATA_LEN];
    uint64_t flags;
} seed_t;

typedef struct {
    uint64_t gpr[16], xmm[16][2], yhi[16][2], zhi[16][4], mm[8], k[8];
    uint64_t xext[16][2], yext[16][2], zext[16][4];
    hb_x87_state_t x87;
    uint8_t mem[DATA_LEN];
    uint64_t flags, pc, rip, fault_pc, fault_addr;
    uint32_t mxcsr, fault_kind, fault_addr_valid;
    hb_result_t result;
    int faulted, complete, smc_evicted;
} snap_t;

/* Each comment is the exact x86 source represented by the byte sequence. */
typedef struct {
    const char *name;
    unsigned len;
    uint8_t code[96];
    unsigned fault_offset; /* zero for successful cases */
    int smc;
} case_t;

static const case_t cases[] = {
    { "gpr-chain-3", 9,
      /* add rax,rdx; add rax,rcx; add rax,rdx */
      {0x48,0x01,0xd0, 0x48,0x01,0xc8, 0x48,0x01,0xd0}, 0, 0 },
    { "gpr-chain-10", 30,
      /* add rax,rdx; add rcx,rax; add rdx,rcx; add rbx,rdx; repeat */
      {0x48,0x01,0xd0, 0x48,0x01,0xc1, 0x48,0x01,0xca, 0x48,0x01,0xd3,
       0x48,0x01,0xd8, 0x48,0x01,0xc1, 0x48,0x01,0xca, 0x48,0x01,0xd3,
       0x48,0x01,0xd8, 0x48,0x01,0xc1}, 0, 0 },
    { "gpr-alias", 12,
      /* mov rbx,rax; add rax,rdx; add rcx,rbx; add rdx,rax */
      {0x48,0x89,0xc3, 0x48,0x01,0xd0, 0x48,0x01,0xd9, 0x48,0x01,0xc2}, 0, 0 },
    { "scratch-clobber-negative", 12,
      /* mov rax,rcx; add rdx,rsi; mov rbx,rcx; add rbx,rax */
      {0x48,0x89,0xc8, 0x48,0x01,0xf2, 0x48,0x89,0xcb, 0x48,0x01,0xc3}, 0, 0 },
    { "extended-gpr-partial", 15,
      /* add r8,r9; mov r10,r8; add r11,r10; mov r8b,33h; add r8,r9 */
      {0x4d,0x01,0xc8, 0x4d,0x89,0xc2, 0x4d,0x01,0xd3, 0x41,0xb0,0x33,
       0x4d,0x01,0xc8}, 0, 0 },
    { "partial-al", 11,
      /* add rax,rdx; mov al,55h; add rcx,rax; add rax,rdx */
      {0x48,0x01,0xd0, 0xb0,0x55, 0x48,0x01,0xc1, 0x48,0x01,0xd0}, 0, 0 },
    { "partial-al-immediate-reread", 8,
      /* add rax,rdx; mov al,55h; mov rbx,rax */
      {0x48,0x01,0xd0, 0xb0,0x55, 0x48,0x89,0xc3}, 0, 0 },
    { "partial-ah", 11,
      /* add rax,rdx; mov ah,aah; add rcx,rax; add rax,rdx */
      {0x48,0x01,0xd0, 0xb4,0xaa, 0x48,0x01,0xc1, 0x48,0x01,0xd0}, 0, 0 },
    { "partial-ax", 13,
      /* add rax,rdx; mov ax,beefh; add rcx,rax; add rax,rdx */
      {0x48,0x01,0xd0, 0x66,0xb8,0xef,0xbe, 0x48,0x01,0xc1, 0x48,0x01,0xd0}, 0, 0 },
    { "zero-extend-eax", 14,
      /* add rax,rdx; mov eax,89abcdefh; add rcx,rax; add rax,rdx */
      {0x48,0x01,0xd0, 0xb8,0xef,0xcd,0xab,0x89, 0x48,0x01,0xc1, 0x48,0x01,0xd0}, 0, 0 },
    { "partial-al-add", 11,
      /* add rax,rdx; add al,cl; add rcx,rax; add rax,rdx */
      {0x48,0x01,0xd0, 0x00,0xc8, 0x48,0x01,0xc1, 0x48,0x01,0xd0}, 0, 0 },
    { "address-load-store", 20,
      /* mov rax,[rdi]; add rax,rdx; mov [rdi+8],rax; add rcx,rax;
       * mov rax,[rdi+8]; add rbx,rax */
      {0x48,0x8b,0x07, 0x48,0x01,0xd0, 0x48,0x89,0x47,0x08,
       0x48,0x01,0xc1, 0x48,0x8b,0x47,0x08, 0x48,0x01,0xc3}, 0, 0 },
    { "address-scratch-negative", 13,
      /* mov rax,[rdi+8]; mov rcx,rdi; mov rbx,[rcx]; add rax,rbx */
      {0x48,0x8b,0x47,0x08, 0x48,0x89,0xf9, 0x48,0x8b,0x19,
       0x48,0x01,0xd8}, 0, 0 },
    { "lea-index-scratch-negative", 10,
      /* lea rax,[rdi+rsi*4]; mov rbx,rsi; add rax,rbx */
      {0x48,0x8d,0x04,0xb7, 0x48,0x89,0xf3, 0x48,0x01,0xd8}, 0, 0 },
    { "helper-cpuid", 21,
      /* mov eax,0; mov ecx,0; add rbx,rax; cpuid; add rax,rbx; add rdx,rax */
      {0xb8,0,0,0,0, 0xb9,0,0,0,0, 0x48,0x01,0xc3,
       0x0f,0xa2, 0x48,0x01,0xd8, 0x48,0x01,0xc2}, 0, 0 },
    { "xmm-move-alias", 12,
      /* movaps xmm1,xmm0; movaps xmm0,xmm2; movaps xmm3,xmm1; movaps xmm4,xmm0 */
      {0x0f,0x28,0xc8, 0x0f,0x28,0xc2, 0x0f,0x28,0xd9, 0x0f,0x28,0xe0}, 0, 0 },
    { "xmm-int-chain", 20,
      /* paddd xmm0,xmm1; paddd xmm2,xmm0; psubd xmm0,xmm3;
       * pxor xmm4,xmm0; paddd xmm2,xmm4 */
      {0x66,0x0f,0xfe,0xc1, 0x66,0x0f,0xfe,0xd0, 0x66,0x0f,0xfa,0xc3,
       0x66,0x0f,0xef,0xe0, 0x66,0x0f,0xfe,0xd4}, 0, 0 },
    { "xmm-fp-chain", 16,
      /* addps xmm0,xmm1; mulps xmm2,xmm0; addss xmm0,xmm3;
       * movaps xmm4,xmm0; addps xmm2,xmm4 */
      {0x0f,0x58,0xc1, 0x0f,0x59,0xd0, 0xf3,0x0f,0x58,0xc3,
       0x0f,0x28,0xe0, 0x0f,0x58,0xd4}, 0, 0 },
    { "partial-movss-reg", 13,
      /* movaps xmm0,xmm1; movss xmm0,xmm2; movaps xmm3,xmm0; movaps xmm4,xmm1 */
      {0x0f,0x28,0xc1, 0xf3,0x0f,0x10,0xc2, 0x0f,0x28,0xd8, 0x0f,0x28,0xe1}, 0, 0 },
    { "partial-movsd-reg", 13,
      /* movaps xmm0,xmm1; movsd xmm0,xmm2; movaps xmm3,xmm0; movaps xmm4,xmm1 */
      {0x0f,0x28,0xc1, 0xf2,0x0f,0x10,0xc2, 0x0f,0x28,0xd8, 0x0f,0x28,0xe1}, 0, 0 },
    { "partial-movss-memory", 14,
      /* movaps xmm0,xmm1; movss xmm0,[rdi]; movaps xmm2,xmm0; movups [rdi+16],xmm2 */
      {0x0f,0x28,0xc1, 0xf3,0x0f,0x10,0x07, 0x0f,0x28,0xd0, 0x0f,0x11,0x57,0x10}, 0, 0 },
    { "partial-movsd-memory", 14,
      /* movaps xmm0,xmm1; movsd xmm0,[rdi]; movaps xmm2,xmm0; movups [rdi+16],xmm2 */
      {0x0f,0x28,0xc1, 0xf2,0x0f,0x10,0x07, 0x0f,0x28,0xd0, 0x0f,0x11,0x57,0x10}, 0, 0 },
    { "xmm-memory-chain", 18,
      /* movups xmm0,[rdi]; paddd xmm0,xmm1; movups [rdi+16],xmm0;
       * paddd xmm2,xmm0; movups xmm3,xmm2 */
      {0x0f,0x10,0x07, 0x66,0x0f,0xfe,0xc1, 0x0f,0x11,0x47,0x10,
       0x66,0x0f,0xfe,0xd0, 0x0f,0x10,0xda}, 0, 0 },
    { "vex-128-upper", 14,
      /* movaps xmm0,xmm1; vmovaps xmm0,xmm2; movaps xmm3,xmm0; vmovss xmm0,xmm1,xmm2 */
      {0x0f,0x28,0xc1, 0xc5,0xf8,0x28,0xc2, 0x0f,0x28,0xd8, 0xc5,0xf2,0x10,0xc2}, 0, 0 },
    { "vex-256-overwrite", 15,
      /* movaps xmm0,xmm1; vmovaps ymm0,ymm2; vpaddd ymm0,ymm0,ymm1; vmovaps ymm3,ymm0 */
      {0x0f,0x28,0xc1, 0xc5,0xfc,0x28,0xc2, 0xc5,0xfd,0xfe,0xc1, 0xc5,0xfc,0x28,0xd8}, 0, 0 },
    { "evex-zmm-helper", 16,
      /* movaps xmm0,xmm1; vmovaps zmm0,zmm2; movaps xmm3,xmm0; paddd xmm0,xmm4 */
      {0x0f,0x28,0xc1, 0x62,0xf1,0x7c,0x48,0x28,0xc2,
       0x0f,0x28,0xd8, 0x66,0x0f,0xfe,0xc4}, 0, 0 },
    { "evex-mask-helper", 16,
      /* movaps xmm0,xmm1; vmovaps xmm0{k1},xmm2; movaps xmm3,xmm0; paddd xmm0,xmm4 */
      {0x0f,0x28,0xc1, 0x62,0xf1,0x7c,0x09,0x28,0xc2,
       0x0f,0x28,0xd8, 0x66,0x0f,0xfe,0xc4}, 0, 0 },
    { "vzeroall-boundary", 13,
      /* movaps xmm0,xmm1; vzeroall; movaps xmm2,xmm0; paddd xmm2,xmm3 */
      {0x0f,0x28,0xc1, 0xc5,0xfc,0x77, 0x0f,0x28,0xd0, 0x66,0x0f,0xfe,0xd3}, 0, 0 },
    { "vzeroupper-boundary", 13,
      /* movaps xmm0,xmm1; vzeroupper; movaps xmm2,xmm0; vmovaps ymm3,ymm0 */
      {0x0f,0x28,0xc1, 0xc5,0xf8,0x77, 0x0f,0x28,0xd0, 0xc5,0xfc,0x28,0xd8}, 0, 0 },
    { "mmx-helper-boundary", 18,
      /* movaps xmm0,xmm1; add rax,rdx; movq mm0,mm1; paddb mm0,mm2;
       * movaps xmm2,xmm0; add rcx,rax */
      {0x0f,0x28,0xc1, 0x48,0x01,0xd0, 0x0f,0x6f,0xc1,
       0x0f,0xfc,0xc2, 0x0f,0x28,0xd0, 0x48,0x01,0xc1}, 0, 0 },
    { "x87-helper-boundary", 13,
      /* movaps xmm0,xmm1; fld1; fstp st(0); movaps xmm2,xmm0; add rax,rdx */
      {0x0f,0x28,0xc1, 0xd9,0xe8, 0xdd,0xd8, 0x0f,0x28,0xd0, 0x48,0x01,0xd0}, 0, 0 },
    { "branch-join", 17,
      /* add rax,rdx; test cl,1; jz +3; add rax,rbx; add rcx,rax; add rdx,rcx */
      {0x48,0x01,0xd0, 0xf6,0xc1,0x01, 0x74,0x03, 0x48,0x01,0xd8,
       0x48,0x01,0xc1, 0x48,0x01,0xca}, 0, 0 },
    { "fault-canonical-prefix", 22,
      /* add rax,rdx; add rcx,rax; paddd xmm0,xmm1; movups [rdi],xmm0;
       * mov rbx,[r15] (fault); add rax,rcx; movaps xmm2,xmm0 */
      {0x48,0x01,0xd0, 0x48,0x01,0xc1, 0x66,0x0f,0xfe,0xc1,
       0x0f,0x11,0x07, 0x49,0x8b,0x1f, 0x48,0x01,0xc8, 0x0f,0x28,0xd0}, 13, 0 },
    { "smc-retranslation", 11,
      /* mov eax,11h; add rax,rdx; add rcx,rax. Second execution changes 11h to 22h. */
      {0xb8,0x11,0,0,0, 0x48,0x01,0xd0, 0x48,0x01,0xc1}, 0, 1 },
};

static void make_seed(seed_t *s) {
    memset(s, 0, sizeof(*s));
    for (unsigned i = 0; i < 16; ++i) {
        s->gpr[i] = rnd();
        for (unsigned j = 0; j < 2; ++j) {
            s->xmm[i][j] = rnd(); s->yhi[i][j] = rnd();
        }
        for (unsigned j = 0; j < 4; ++j) {
            s->zhi[i][j] = rnd();
            /* Finite exact inputs avoid irrelevant NaN payload choices in FP cases. */
            float f = (float)(rnd() % 256 + 1) / 4.0f;
            memcpy((uint8_t *)s->xmm[i] + j * 4, &f, sizeof(f));
        }
    }
    for (unsigned i = 0; i < 8; ++i) { s->mm[i] = rnd(); s->k[i] = rnd(); }
    for (unsigned i = 0; i < DATA_LEN; ++i) s->mem[i] = (uint8_t)rnd();
    s->flags = rnd() & 0x8d5;
}

static void apply_seed(hb_context_t *c, const seed_t *s) {
    memset(&c->regs, 0, sizeof(c->regs));
    memcpy(&c->regs.x64.rax, s->gpr, sizeof(s->gpr));
    c->regs.x64.rdi = (uint64_t)(uintptr_t)(data_page + 64);
    c->regs.x64.rsp = (uint64_t)(uintptr_t)(data_page + PAGE - 256);
    c->regs.x64.r15 = (uint64_t)(uintptr_t)fault_page;
    memcpy(c->regs.x64.xmm, s->xmm, sizeof(s->xmm));
    memcpy(c->ymm_hi, s->yhi, sizeof(s->yhi));
    memcpy(c->zmm_hi, s->zhi, sizeof(s->zhi));
    memcpy(c->mm, s->mm, sizeof(s->mm));
    memcpy(c->k, s->k, sizeof(s->k));
    memset(&c->x87_64, 0, sizeof(c->x87_64));
    c->x87_64.control_word = 0x037f; c->x87_64.tag_word = 0xffff;
    c->pc = c->regs.x64.rip = (uint64_t)(uintptr_t)code_page;
    c->regs.x64.rflags = 0x202 | s->flags;
    c->flags.cf = (s->flags >> 0) & 1; c->flags.pf = (s->flags >> 2) & 1;
    c->flags.af = (s->flags >> 4) & 1; c->flags.zf = (s->flags >> 6) & 1;
    c->flags.sf = (s->flags >> 7) & 1; c->flags.of = (s->flags >> 11) & 1;
    memset(&c->lazy_flags, 0, sizeof(c->lazy_flags));
    c->mxcsr = 0x1f80;
    memcpy(data_page, s->mem, DATA_LEN);
}

static uint64_t flags_of(hb_context_t *c) {
    (void)hb_lazy_flags_materialize_available(c, HB_FLAG_BIT_ALL);
    return (uint64_t)c->flags.cf | ((uint64_t)c->flags.pf << 2) |
           ((uint64_t)c->flags.af << 4) | ((uint64_t)c->flags.zf << 6) |
           ((uint64_t)c->flags.sf << 7) | ((uint64_t)c->flags.of << 11);
}

static int execute(hb_context_t *c, hb_jit_runtime_t *rt, size_t len, snap_t *s) {
    uint64_t base = (uint64_t)(uintptr_t)code_page, end = base + len;
    for (unsigned hop = 0; hop < 16; ++hop) {
        if (c->pc < base || c->pc >= end) break;
        hb_decoder_t *d = hb_decoder_create(HB_ARCH_X64, code_page + (c->pc - base), end - c->pc, c->pc);
        hb_ir_func_t *f = NULL;
        if (!d) return 0;
        hb_result_t lift = hb_lift_func_x64(d, &f);
        hb_decoder_destroy(d);
        if (lift != HB_OK || !f || f->has_unsupported) {
            if (f) hb_ir_func_destroy(f);
            return 0;
        }
        hb_exec_result_t out;
        memset(&out, 0, sizeof(out));
        hb_result_t r = rt ? hb_jit_runtime_run(rt, f, &out) : hb_runtime_run(c, f, HB_BACKEND_INTERP, &out);
        hb_ir_func_destroy(f);
        s->result = r != HB_OK ? r : out.result;
        s->faulted = out.faulted;
        if (r != HB_OK || out.result != HB_OK || out.faulted) break;
    }
    s->complete = c->pc == end;
    return 1;
}

static int run(const case_t *t, const seed_t *in, int jit, snap_t *s) {
    memset(s, 0, sizeof(*s));
    hb_context_t *c = hb_context_create(HB_ARCH_X64, jit ? HB_BACKEND_JIT : HB_BACKEND_INTERP);
    hb_memory_t *m = hb_memory_create(0);
    if (!c || !m) return 0;
    c->memory = m; c->config.fallback_enabled = false;
    if (hb_memory_sync_live_range(m, (uint64_t)(uintptr_t)code_page, PAGE,
                                 HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
        hb_memory_sync_live_range(m, (uint64_t)(uintptr_t)data_page, PAGE,
                                 HB_PERM_READ | HB_PERM_WRITE) != HB_OK) return 0;
    hb_context_set_step_limit(c, 1000); hb_context_set_block_limit(c, 100);
    memcpy(code_page, t->code, t->len);
    apply_seed(c, in);
    hb_jit_runtime_t *rt = jit ? hb_jit_runtime_create(c) : NULL;
    if (jit && !rt) return 0;
    int ok = execute(c, rt, t->len, s);
    const char *trace = getenv("HB_REG_FORWARD_TRACE");
    if (rt && trace && !strcmp(trace, t->name)) {
        for (size_t i = 0; i < rt->block_cache->size; ++i) {
            const hb_block_cache_entry_t *e = &rt->block_cache->entries[i];
            if (!e->valid || e->guest_addr != (uint64_t)(uintptr_t)code_page || !e->native_code) continue;
            printf("NATIVE %s ", t->name);
            for (size_t j = 0; j < e->native_size; ++j) printf("%02x", ((const uint8_t *)e->native_code)[j]);
            putchar('\n');
        }
    }
    if (ok && t->smc) {
        uint64_t before = hb_jit_smc_evicted_total();
        code_page[1] = 0x22;
        apply_seed(c, in);
        ok = execute(c, rt, t->len, s);
        s->smc_evicted = !jit || hb_jit_smc_evicted_total() > before;
    }
    memcpy(s->gpr, &c->regs.x64.rax, sizeof(s->gpr));
    memcpy(s->xmm, c->regs.x64.xmm, sizeof(s->xmm));
    memcpy(s->yhi, c->ymm_hi, sizeof(s->yhi)); memcpy(s->zhi, c->zmm_hi, sizeof(s->zhi));
    memcpy(s->xext, c->xmm_ext, sizeof(s->xext)); memcpy(s->yext, c->ymm_hi_ext, sizeof(s->yext));
    memcpy(s->zext, c->zmm_hi_ext, sizeof(s->zext));
    memcpy(s->mm, c->mm, sizeof(s->mm)); memcpy(s->k, c->k, sizeof(s->k));
    memcpy(&s->x87, &c->x87_64, sizeof(s->x87)); memcpy(s->mem, data_page, DATA_LEN);
    s->flags = flags_of(c); s->pc = c->pc; s->rip = c->regs.x64.rip; s->mxcsr = c->mxcsr;
    s->fault_pc = c->last_fault_pc; s->fault_addr = c->last_fault_addr;
    s->fault_kind = c->last_fault_kind; s->fault_addr_valid = c->last_fault_addr_valid;
    if (rt) hb_jit_runtime_destroy(rt);
    c->memory = NULL; hb_context_destroy(c); hb_memory_destroy(m);
    return ok;
}

static const char *difference(const snap_t *a, const snap_t *b) {
#define FIELD(f) if (memcmp(&a->f, &b->f, sizeof(a->f))) return #f
    FIELD(gpr); FIELD(xmm); FIELD(yhi); FIELD(zhi); FIELD(xext); FIELD(yext); FIELD(zext);
    FIELD(mm); FIELD(k); FIELD(x87); FIELD(mem); FIELD(mxcsr);
    if ((a->flags ^ b->flags) & 0x8c5) return "flags"; /* AF undefined after logic. */
    FIELD(pc); FIELD(rip); FIELD(result); FIELD(faulted);
    FIELD(fault_pc); FIELD(fault_addr); FIELD(fault_kind); FIELD(fault_addr_valid);
#undef FIELD
    return NULL;
}

int main(void) {
    unsigned count = 64, total = 0, bad = 0, setup = 0;
    const char *n = getenv("HB_REG_FORWARD_CASES");
    if (n && atoi(n) > 0) count = (unsigned)atoi(n);
    code_page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    data_page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    fault_page = mmap(NULL, PAGE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code_page == MAP_FAILED || data_page == MAP_FAILED || fault_page == MAP_FAILED) return 2;
    hb_memory_install_fault_handlers();
    for (unsigned ti = 0; ti < sizeof(cases) / sizeof(cases[0]); ++ti) {
        const case_t *t = &cases[ti];
        for (unsigned i = 0; i < count; ++i) {
            seed_t seed; snap_t a, b;
            make_seed(&seed);
            int oka = run(t, &seed, 0, &a), okb = run(t, &seed, 1, &b);
            total++;
            if (!oka || !okb) {
                if (setup++ < 8) fprintf(stderr, "SETUP %s seed=%u interp=%d jit=%d\n", t->name, i, oka, okb);
                continue;
            }
            const char *why = difference(&a, &b);
            uint64_t fault_pc = (uint64_t)(uintptr_t)code_page + t->fault_offset;
            if (!why && t->fault_offset &&
                (a.result != HB_ERR_MEMORY_FAULT || b.result != HB_ERR_MEMORY_FAULT ||
                 a.pc != fault_pc || b.pc != fault_pc)) why = "fault-not-at-prefix";
            if (!why && !t->fault_offset &&
                (!a.complete || !b.complete || a.result != HB_OK || b.result != HB_OK ||
                 a.faulted || b.faulted)) why = "incomplete";
            if (!why && t->smc && !b.smc_evicted) why = "smc-no-eviction";
            if (why) {
                unsigned gi = 0;
                while (gi < 15 && a.gpr[gi] == b.gpr[gi]) ++gi;
                if (bad++ < 12) fprintf(stderr,
                    "MISMATCH %s seed=%u field=%s gpr[%u]=%016" PRIx64 "/%016" PRIx64
                    " result=%d/%d pc=%" PRIx64 "/%" PRIx64 " faultpc=%" PRIx64 "/%" PRIx64 "\n",
                    t->name, i, why, gi, a.gpr[gi], b.gpr[gi], a.result, b.result,
                    a.pc - (uint64_t)(uintptr_t)code_page, b.pc - (uint64_t)(uintptr_t)code_page,
                    a.fault_pc ? a.fault_pc - (uint64_t)(uintptr_t)code_page : 0,
                    b.fault_pc ? b.fault_pc - (uint64_t)(uintptr_t)code_page : 0);
            }
        }
    }
    printf("register-forward: cases=%u forms=%zu mismatch=%u setup=%u REG=%s XMM=%s\n",
           total, sizeof(cases) / sizeof(cases[0]), bad, setup,
           getenv("MACRUNNER_HB_REG_FORWARD") ? getenv("MACRUNNER_HB_REG_FORWARD") : "0",
           getenv("MACRUNNER_HB_XMM_FORWARD") ? getenv("MACRUNNER_HB_XMM_FORWARD") : "0");
    munmap(code_page, PAGE); munmap(data_page, PAGE); munmap(fault_page, PAGE);
    return setup ? 2 : bad ? 1 : 0;
}
