/*
 * hb_adjacent_mem64_clobber_repro.c — does the adjacent-mem64 LDP fusion fire
 * when the FIRST load overwrites the base register the SECOND load depends on?
 *
 * Standalone (not in hb_test_runner) on purpose: jit_direct_mem_enabled() and
 * jit_direct_scalar_mem_enabled() both cache their env lookup in a function-local
 * static on FIRST call (hb_arm64_codegen.c:453, :510).  In the single-process test
 * runner the first caller freezes both for the whole process, so a later test that
 * setenv()s DIRECT_MEM=1 can silently exercise the DISABLED path.  Here main()
 * sets the env before any hb_* call, so the caches initialise the way we intend.
 *
 * Reproduces the Hollow Knight mono-2.0-bdwgc.dll hash-chain walk at RVA 0x385e66:
 *     mov rdi, [rdi + 8]      ; rdi <- inner
 *     mov rbx, [rdi + 0x10]   ; MUST read inner+0x10, not outer+0x10
 * Both operands carry the textual base RDI with disps 8 and 0x10 (adjacent by 8),
 * which is exactly what adjacent_mem64_operands() matches on.
 *
 * Build: make adjacent-clobber-repro   Run: ./tests/hb_adjacent_mem64_clobber_repro
 * Exit 0 = correct behaviour, 1 = stale-base corruption reproduced.
 */
#include "hb_codegen.h"
#include "hb_memory.h"
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define HK_POISON 0xffffffff01000166ULL /* the value observed in HK, 3 runs, byte-identical */
#define CORRECT   0x00000000deadbeefULL

static uint64_t nodes[8];
static uint64_t stack[2];

/* LDP Xt1,Xt2,[Xn,#imm7] — emit_ldp_x() bakes 0xa9400000 (hb_arm64_codegen.c:205).
 * Match ONLY rn==X21, the direct-mem address register: the prologue/epilogue also
 * emit LDPs off SP (rn==31), and counting those would report "fused" on every block. */
#define DIRECT_MEM_ADDR_REG 21
static int buffer_contains_data_ldp(const hb_codegen_buffer_t* buf, uint32_t* out_word)
{
    const uint32_t* w = (const uint32_t*)buf->code;
    size_t n = buf->size / 4, i;
    for (i = 0; i < n; i++) {
        if ((w[i] & 0xffc00000u) == 0xa9400000u &&
            ((w[i] >> 5) & 0x1fu) == DIRECT_MEM_ADDR_REG) {
            if (out_word) *out_word = w[i];
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    hb_ir_func_t* func;
    hb_ir_block_t* blk;
    hb_ir_builder_t* b;
    hb_ir_instr_t *load_rdi, *load_rbx, *ret;
    hb_context_t* ctx;
    hb_codegen_buffer_t* code_buf;
    hb_arm64_codegen_t* cg;
    hb_exec_result_t out;
    uint32_t ldp_word = 0;
    int fused, bad = 0;

    /* BEFORE any hb_* call — see header comment. */
    setenv("MACRUNNER_HB_JIT_DIRECT_MEM", "1", 1);
    setenv("MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM", "1", 1);

    memset(nodes, 0, sizeof(nodes));
    memset(stack, 0, sizeof(stack));
    nodes[1] = (uint64_t)(uintptr_t)&nodes[4]; /* outer+0x08 -> inner              */
    nodes[2] = HK_POISON;                      /* outer+0x10  = what a stale base reads */
    nodes[6] = CORRECT;                        /* inner+0x10  = the correct chain head  */

    func = hb_ir_func_create(0x4600, 0);
    blk = hb_ir_block_create(0, 0x4600);
    if (!func || !blk) { fprintf(stderr, "ir alloc failed\n"); return 2; }
    hb_ir_cfg_add_block(func->cfg, blk);
    func->cfg->entry = blk;

    b = hb_ir_builder_create(func);
    if (!b) { fprintf(stderr, "builder alloc failed\n"); return 2; }
    hb_ir_builder_set_block(b, blk);
    load_rdi = hb_ir_emit_load(b, hb_ir_reg(HB_REG_RDI, HB_SIZE_64),
                               hb_ir_mem(HB_REG_RDI, HB_REG_COUNT, 1, 0x08, HB_SIZE_64));
    load_rbx = hb_ir_emit_load(b, hb_ir_reg(HB_REG_RBX, HB_SIZE_64),
                               hb_ir_mem(HB_REG_RDI, HB_REG_COUNT, 1, 0x10, HB_SIZE_64));
    ret = hb_ir_emit_ret(b);
    if (!load_rdi || !load_rbx || !ret) { fprintf(stderr, "emit failed\n"); return 2; }
    load_rdi->guest_addr = 0x4600; load_rdi->guest_len = 4;
    load_rbx->guest_addr = 0x4604; load_rbx->guest_len = 4;
    ret->guest_addr = 0x4608; ret->guest_len = 1;
    hb_ir_builder_destroy(b);

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    if (!ctx) { fprintf(stderr, "ctx alloc failed\n"); return 2; }
    ctx->memory = hb_memory_create(0);
    if (hb_memory_map(ctx->memory, (hb_gva_t)(uintptr_t)nodes, sizeof(nodes),
                      HB_PERM_READ | HB_PERM_WRITE) != HB_OK ||
        hb_memory_map(ctx->memory, (hb_gva_t)(uintptr_t)stack, sizeof(stack),
                      HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        fprintf(stderr, "map failed\n"); return 2;
    }

    /* --- 1. Did the fusion fire?  Inspect the emitted ARM64, do not assume. --- */
    ctx->pc = 0x4600;
    code_buf = hb_codegen_buffer_create(512);
    cg = hb_arm64_codegen_create(ctx);
    if (!code_buf || !cg || hb_arm64_codegen_block(cg, blk, code_buf) != HB_OK) {
        fprintf(stderr, "codegen failed\n"); return 2;
    }
    fused = buffer_contains_data_ldp(code_buf, &ldp_word);
    printf("fusion-fired = %d  (code %u bytes", fused, (unsigned)code_buf->size);
    if (fused) printf(", LDP word 0x%08x", ldp_word);
    printf(")\n");
    hb_arm64_codegen_destroy(cg);
    hb_codegen_buffer_destroy(code_buf);

    /* --- 2. Execute and check the value. --- */
    ctx->pc = 0x4600;
    ctx->regs.x64.rsp = (uint64_t)(uintptr_t)&stack[0];
    ctx->regs.x64.rdi = (uint64_t)(uintptr_t)&nodes[0];
    if (hb_runtime_run(ctx, func, HB_BACKEND_JIT, &out) != HB_OK || out.result != HB_OK) {
        fprintf(stderr, "run failed (result=%d)\n", (int)out.result); return 2;
    }

    printf("rdi = 0x%016llx (expect 0x%016llx  inner)\n",
           (unsigned long long)ctx->regs.x64.rdi, (unsigned long long)(uintptr_t)&nodes[4]);
    printf("rbx = 0x%016llx (expect 0x%016llx)\n",
           (unsigned long long)ctx->regs.x64.rbx, (unsigned long long)CORRECT);

    if (ctx->regs.x64.rdi != (uint64_t)(uintptr_t)&nodes[4]) {
        printf("FAIL: rdi did not follow the pointer\n"); bad = 1;
    }
    if (ctx->regs.x64.rbx == HK_POISON) {
        printf("FAIL: ★ STALE-BASE CORRUPTION REPRODUCED — rbx read outer+0x10, "
               "the exact HK value 0x%016llx\n", (unsigned long long)HK_POISON);
        bad = 1;
    } else if (ctx->regs.x64.rbx != CORRECT) {
        printf("FAIL: rbx wrong but not the HK poison\n"); bad = 1;
    } else {
        printf("PASS: rbx read through the NEW rdi\n");
    }

    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    return bad;
}
