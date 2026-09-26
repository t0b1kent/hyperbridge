/*
 * hb_xmm_pair_x22_test.c — второй операнд-память у ANDPS/XORPS/ORPS не должен портить
 * старшую половину первого.
 *
 * 26.09.2026. emit_native_xmm_logic (как и INSERTPS, PUNPCK*QDQ) грузит src1 в пару x20/x22,
 * затем src2 в x21/x23 через emit_load_xmm_operand_to_pair. На прямом пути к памяти адрес
 * src2 считает emit_direct_mem_addr, а он пишет x22 при индексе и при смещении вне ±4095 —
 * RIP-относительный операнд лифтер делает АБСОЛЮТНЫМ адресом, то есть под удар шла почти
 * каждая константа-маска. Старшие 64 бита результата считались от адреса константы или от
 * индекса. В Hollow Knight это давало NaN/Inf в ~20 % матриц вершинного шейдера и чёрный
 * кадр при MACRUNNER_HB_JIT_DIRECT_MEM=1 (m33 = старшая половина адреса).
 *
 * Отрицательный контроль: собранный против ядра ДО правки, тест даёт TOTAL_BAD=6
 * (andps[rip] -> 00ec0040 00000001 = адрес маски; xorps/orps с индексом -> x22 = rcx).
 *
 * Отдельный процесс нарочно: гейты прямой памяти кешируются при первом обращении.
 * Выход 0 — интерпретатор и JIT совпадают с ожиданием, 1 — порча воспроизведена.
 */
#define _DARWIN_C_SOURCE 1
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

static const uint8_t code_bytes[] = {
    0x0f, 0x10, 0x02,                          /*  0 movups xmm0, [rdx]                       */
    0x0f, 0x54, 0x05, 0x36, 0x00, 0x00, 0x00,  /*  3 andps  xmm0, [rip+0x36] -> code+0x40     */
    0x0f, 0x11, 0x42, 0x10,                    /* 10 movups [rdx+0x10], xmm0                  */
    0x0f, 0x57, 0x4c, 0x0a, 0x20,              /* 14 xorps  xmm1, [rdx+rcx*1+0x20]            */
    0x0f, 0x11, 0x4a, 0x30,                    /* 19 movups [rdx+0x30], xmm1                  */
    0x0f, 0x56, 0x14, 0x8a,                    /* 23 orps   xmm2, [rdx+rcx*4]                 */
    0x0f, 0x11, 0x52, 0x40                     /* 27 movups [rdx+0x40], xmm2                  */
};

static void* alloc_live(hb_memory_t* mem, size_t size, hb_perm_t perm) {
    void* p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (hb_memory_sync_live_range(mem, (hb_gva_t)(uintptr_t)p, size, perm) != HB_OK) return NULL;
    return p;
}

static uint32_t f(float v) { uint32_t u; memcpy(&u, &v, 4); return u; }

int main(void) {
    int bad_total = 0;
    static const struct { hb_backend_t b; const char* n; } be[] = {
        {HB_BACKEND_INTERP, "interp"}, {HB_BACKEND_JIT, "jit"}};
    setenv("MACRUNNER_HB_JIT_DIRECT_MEM", "1", 1);   /* до первого обращения к гейтам */
    for (int k = 0; k < 2; k++) {
        hb_context_t* ctx = hb_context_create(HB_ARCH_X64, be[k].b);
        hb_memory_t* mem = hb_memory_create(0);
        ctx->memory = mem;
        uint8_t* code = alloc_live(mem, 16384, HB_PERM_READ | HB_PERM_EXEC | HB_PERM_WRITE);
        uint8_t* data = alloc_live(mem, 65536, HB_PERM_READ | HB_PERM_WRITE);
        uint8_t* stack = alloc_live(mem, 65536, HB_PERM_READ | HB_PERM_WRITE);
        if (!code || !data || !stack) { printf("alloc fail\n"); return 2; }
        memcpy(code, code_bytes, sizeof(code_bytes));
        memset(code + 0x40, 0xff, 16);                         /* маска andps: все единицы */
        uint32_t* d = (uint32_t*)(void*)(data + 0x100);
        d[0] = f(1); d[1] = f(2); d[2] = f(3); d[3] = f(4);  /* [rdx]                   */
        for (int i = 0; i < 4; i++) d[8 + i] = 0x80000000u;  /* [rdx+0x20]: маска знака */
        uint64_t base = (uint64_t)(uintptr_t)code;
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, code, sizeof(code_bytes), base);
        hb_ir_func_t* func = NULL;
        if (hb_lift_func_x64(dec, &func) != HB_OK || !func) { printf("lift fail\n"); return 3; }
        hb_decoder_destroy(dec);
        ctx->pc = base;
        ctx->regs.x64.rip = base;
        ctx->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
        ctx->regs.x64.rdx = (uint64_t)(uintptr_t)d;
        ctx->regs.x64.rcx = 0;
        ctx->regs.x64.xmm[1][0] = ((uint64_t)f(6) << 32) | f(5);
        ctx->regs.x64.xmm[1][1] = ((uint64_t)f(8) << 32) | f(7);
        ctx->regs.x64.xmm[2][0] = ((uint64_t)f(10) << 32) | f(9);
        ctx->regs.x64.xmm[2][1] = ((uint64_t)f(12) << 32) | f(11);
        hb_exec_result_t out;
        memset(&out, 0, sizeof(out));
        hb_result_t rr = hb_runtime_run(ctx, func, be[k].b, &out);
        const uint32_t exp_and[4] = {f(1), f(2), f(3), f(4)};
        const uint32_t exp_xor[4] = {f(-5), f(-6), f(-7), f(-8)};
        const uint32_t exp_or[4] = {f(9) | f(1), f(10) | f(2), f(11) | f(3), f(12) | f(4)};
        int bad_and = 0, bad_xor = 0, bad_or = 0;
        for (int i = 0; i < 4; i++) {
            bad_and += d[4 + i] != exp_and[i];
            bad_xor += d[12 + i] != exp_xor[i];
            bad_or += d[16 + i] != exp_or[i];
        }
        printf("%-6s run=%d/%d/%d andps[rip]: %08x %08x %08x %08x bad=%d | xorps[idx]: %08x %08x %08x %08x"
               " bad=%d | orps[idx*4]: %08x %08x %08x %08x bad=%d\n",
               be[k].n, (int)rr, (int)out.result, (int)out.faulted,
               d[4], d[5], d[6], d[7], bad_and, d[12], d[13], d[14], d[15], bad_xor,
               d[16], d[17], d[18], d[19], bad_or);
        bad_total += bad_and + bad_xor + bad_or + (rr != HB_OK);
        hb_ir_func_destroy(func);
        hb_context_destroy(ctx);
    }
    printf("TOTAL_BAD=%d\n", bad_total);
    return bad_total ? 1 : 0;
}
