/*
 * hb_vex_movd_ymm_test.c — VEX.128 MOVD/MOVQ обнуляет всё выше бита 127 приёмника (ymm_hi и
 * zmm_hi), устаревший SSE MOVD/MOVQ эти части сохраняет. Сверяются оба исполнителя: интерпретатор и JIT.
 *
 * 26.09.2026. Разностный стенд на железе ARM64 (4000 случаев x64) показал 20 расхождений из 20
 * у vmovd xmm,r32 / vmovq xmm,r64 / vmovq xmm,xmm (F3 0F 7E) / vmovq xmm,xmm (66 0F D6):
 * нативный выпуск MOVD писал 128 бит и ymm_hi приёмника оставлял прежним.
 *
 * Отрицательный контроль: собранный против ядра ДО правки, тест даёт у JIT четыре нарушения
 * (ymm_hi приёмников 0..3 не обнулены), интерпретатор чист.
 * Выход 0 — оба исполнителя верны, 1 — нарушение, 2 — отказ оснастки.
 */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

static const uint8_t code_bytes[] = {
    0xc5, 0xf9, 0x6e, 0xc1,        /* vmovd xmm0, ecx                          */
    0xc4, 0xe1, 0xf9, 0x6e, 0xc9,  /* vmovq xmm1, rcx                          */
    0xc5, 0xfa, 0x7e, 0xd0,        /* vmovq xmm2, xmm0         (VEX F3 0F 7E)  */
    0xc5, 0xf9, 0xd6, 0xc3,        /* vmovq xmm3, xmm0         (VEX 66 0F D6)  */
    0x66, 0x0f, 0x6e, 0xe1,        /* movd  xmm4, ecx          (SSE: YMM цел)  */
};

static void* alloc_live(hb_memory_t* mem, size_t size, hb_perm_t perm) {
    void* p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (hb_memory_sync_live_range(mem, (hb_gva_t)(uintptr_t)p, size, perm) != HB_OK) return NULL;
    return p;
}

int main(void) {
    int bad_total = 0;
    static const struct { hb_backend_t b; const char* n; } be[] = {
        {HB_BACKEND_INTERP, "interp"}, {HB_BACKEND_JIT, "jit"}};
    const uint64_t rcx = 0xaabbccdd11223344ull, junk = 0xdeadbeefcafef00dull;
    for (int k = 0; k < 2; k++) {
        hb_context_t* ctx = hb_context_create(HB_ARCH_X64, be[k].b);
        hb_memory_t* mem = hb_memory_create(0);
        if (!ctx || !mem) { printf("ОТКАЗ ОСНАСТКИ: контекст\n"); return 2; }
        ctx->memory = mem;
        uint8_t* code = alloc_live(mem, 16384, HB_PERM_READ | HB_PERM_EXEC | HB_PERM_WRITE);
        uint8_t* stack = alloc_live(mem, 65536, HB_PERM_READ | HB_PERM_WRITE);
        if (!code || !stack) { printf("ОТКАЗ ОСНАСТКИ: память\n"); return 2; }
        memcpy(code, code_bytes, sizeof(code_bytes));
        uint64_t base = (uint64_t)(uintptr_t)code;
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, code, sizeof(code_bytes), base);
        hb_ir_func_t* func = NULL;
        if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func) { printf("ОТКАЗ ОСНАСТКИ: лифт\n"); return 2; }
        hb_decoder_destroy(dec);
        ctx->pc = base;
        ctx->regs.x64.rip = base;
        ctx->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
        ctx->regs.x64.rcx = rcx;
        for (int r = 0; r < 5; r++) {
            ctx->regs.x64.xmm[r][0] = junk ^ (uint64_t)r;
            ctx->regs.x64.xmm[r][1] = ~junk;
            ctx->ymm_hi[r][0] = junk + (uint64_t)r;
            ctx->ymm_hi[r][1] = junk - (uint64_t)r;
            for (int q = 0; q < 4; q++) ctx->zmm_hi[r][q] = junk * (uint64_t)(r + q + 3);
        }
        hb_exec_result_t out;
        memset(&out, 0, sizeof(out));
        hb_result_t rr = hb_runtime_run(ctx, func, be[k].b, &out);
        const uint64_t want_lo[5] = { rcx & 0xffffffffu, rcx, rcx & 0xffffffffu, rcx & 0xffffffffu,
                                      rcx & 0xffffffffu };
        int bad = (rr != HB_OK);
        for (int r = 0; r < 5; r++) {
            const int vex = r < 4;
            const uint64_t hi0 = vex ? 0 : junk + (uint64_t)r, hi1 = vex ? 0 : junk - (uint64_t)r;
            int b = ctx->regs.x64.xmm[r][0] != want_lo[r] || ctx->regs.x64.xmm[r][1] != 0 ||
                    ctx->ymm_hi[r][0] != hi0 || ctx->ymm_hi[r][1] != hi1;
            for (int q = 0; q < 4; q++)
                b |= ctx->zmm_hi[r][q] != (vex ? 0 : junk * (uint64_t)(r + q + 3));
            if (b)
                printf("НАРУШЕНИЕ %s xmm%d: xmm=%016llx:%016llx ymm_hi=%016llx:%016llx zmm_hi0=%016llx (ждём старшие части %s)\n",
                       be[k].n, r, (unsigned long long)ctx->regs.x64.xmm[r][1],
                       (unsigned long long)ctx->regs.x64.xmm[r][0],
                       (unsigned long long)ctx->ymm_hi[r][1], (unsigned long long)ctx->ymm_hi[r][0],
                       (unsigned long long)ctx->zmm_hi[r][0],
                       vex ? "= 0" : "без изменений");
            bad += b;
        }
        printf("%-6s run=%d/%d/%d нарушений=%d\n", be[k].n, (int)rr, (int)out.result, (int)out.faulted, bad);
        bad_total += bad;
        hb_ir_func_destroy(func);
        hb_context_destroy(ctx);
    }
    printf("TOTAL_BAD=%d\n", bad_total);
    return bad_total ? 1 : 0;
}
