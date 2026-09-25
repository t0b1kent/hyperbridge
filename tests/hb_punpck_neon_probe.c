/* Проба выпуска SSE: PUNPCK через NEON и узкое чтение памяти в XMM.
 *
 * ★ Приёмка (hb_test_runner) создаёт контексты этих тестов с HB_BACKEND_INTERP,
 *   поэтому её «485 passed» о выпущенном коде не говорит НИЧЕГО: нарочная порча
 *   выпуска её не роняет. Здесь эталон — сам интерпретатор: одна и та же команда
 *   исполняется обеими руками, ответ сверяется побайтно по ВСЕМ восьми XMM,
 *   чтобы поймать и порчу соседних регистров. */
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int отказов = 0, всего = 0;
static uint64_t данные[2] __attribute__((aligned(16)));

/* Прогоняет код обеими руками. `подготовка` заполняет регистры до пуска. */
static void сверка(const char* имя, const unsigned char* код, size_t длина, int с_памятью) {
    uint64_t эталон[16];
    всего++;
    for (int рука = 0; рука < 2; рука++) {
        hb_backend_t путь = рука ? HB_BACKEND_JIT : HB_BACKEND_INTERP;
        uint64_t база = (uint64_t)(uintptr_t)код;
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, (void*)код, длина, база);
        hb_ir_func_t* func = NULL;
        if (!dec || hb_lift_func_x64(dec, &func) != HB_OK) {
            printf("  ✗ %-24s не поднялось\n", имя); отказов++; return;
        }
        hb_decoder_destroy(dec);

        hb_context_t* ctx = hb_context_create(HB_ARCH_X64, путь);
        if (!ctx) { printf("  ✗ %-24s нет контекста\n", имя); отказов++; return; }
        ctx->memory = hb_memory_create(0);
        hb_memory_map(ctx->memory, (hb_gva_t)база, длина, HB_PERM_READ | HB_PERM_EXEC);
        if (с_памятью)
            hb_memory_map(ctx->memory, (hb_gva_t)(uintptr_t)данные, sizeof(данные),
                          HB_PERM_READ | HB_PERM_WRITE);
        ctx->pc = база;
        /* Разные байты во всех позициях — любая перестановка заметна.
         * Прочие регистры — узнаваемый мусор: видно, что обнулилось, а что уцелело. */
        for (int i = 0; i < 8; i++) {
            ctx->regs.x64.xmm[i][0] = 0xeeeeeeeeeeeeeeeeULL;
            ctx->regs.x64.xmm[i][1] = 0xeeeeeeeeeeeeeeeeULL;
        }
        if (!с_памятью) {
            ctx->regs.x64.xmm[0][0] = 0x0706050403020100ULL;
            ctx->regs.x64.xmm[0][1] = 0x0f0e0d0c0b0a0908ULL;
            ctx->regs.x64.xmm[1][0] = 0x1716151413121110ULL;
            ctx->regs.x64.xmm[1][1] = 0x1f1e1d1c1b1a1918ULL;
        }

        hb_exec_result_t out;
        memset(&out, 0, sizeof(out));
        int r = hb_runtime_run(ctx, func, путь, &out);
        if (r != HB_OK || out.result != HB_OK) {
            printf("  ✗ %-24s %s: отказ r=%d res=%d\n", имя,
                   рука ? "ВЫПУСК" : "эталон", r, (int)out.result);
            отказов++; hb_context_destroy(ctx); return;
        }
        uint64_t срез[16];
        for (int i = 0; i < 8; i++) {
            срез[i*2]   = ctx->regs.x64.xmm[i][0];
            срез[i*2+1] = ctx->regs.x64.xmm[i][1];
        }
        if (!рука) {
            memcpy(эталон, срез, sizeof(срез));
        } else if (memcmp(эталон, срез, sizeof(срез)) != 0) {
            printf("  ✗ %-24s РАСХОЖДЕНИЕ\n", имя);
            for (int i = 0; i < 8; i++)
                if (эталон[i*2] != срез[i*2] || эталон[i*2+1] != срез[i*2+1])
                    printf("     xmm%d  эталон %016llx:%016llx  выпуск %016llx:%016llx\n", i,
                           (unsigned long long)эталон[i*2+1], (unsigned long long)эталон[i*2],
                           (unsigned long long)срез[i*2+1], (unsigned long long)срез[i*2]);
            отказов++; hb_context_destroy(ctx); return;
        }
        hb_context_destroy(ctx);
    }
    /* печатаем тот регистр, который команда меняет: xmm0 для перестановок,
     * а для чтений — первый отличный от мусора */
    int п = 0;
    for (int i = 0; i < 8; i++)
        if (эталон[i*2] != 0xeeeeeeeeeeeeeeeeULL || эталон[i*2+1] != 0xeeeeeeeeeeeeeeeeULL) { п = i; break; }
    printf("  ✓ %-24s xmm%d = %016llx:%016llx\n", имя, п,
           (unsigned long long)эталон[п*2+1], (unsigned long long)эталон[п*2]);
}

/* movabs rax, <адрес данных> + хвост команды */
static void чтение(const char* имя, const unsigned char* хвост, size_t дл) {
    static unsigned char код[32];
    uint64_t адрес = (uint64_t)(uintptr_t)данные;
    size_t n = 0;
    код[n++] = 0x48; код[n++] = 0xb8;
    memcpy(код + n, &адрес, 8); n += 8;
    memcpy(код + n, хвост, дл); n += дл;
    сверка(имя, код, n, 1);
}

int main(void) {
    данные[0] = 0xa1a2a3a4a5a6a7a8ULL;
    данные[1] = 0xb1b2b3b4b5b6b7b8ULL;

    printf("PUNPCK через NEON (xmm0 = 00..0f, xmm1 = 10..1f):\n");
    { static unsigned char k[] = {0x66,0x0f,0x60,0xc1}; сверка("punpcklbw  (полоса 1)", k, sizeof(k), 0); }
    { static unsigned char k[] = {0x66,0x0f,0x61,0xc1}; сверка("punpcklwd  (полоса 2)", k, sizeof(k), 0); }
    { static unsigned char k[] = {0x66,0x0f,0x62,0xc1}; сверка("punpckldq  (полоса 4)", k, sizeof(k), 0); }
    { static unsigned char k[] = {0x66,0x0f,0x6c,0xc1}; сверка("punpcklqdq (полоса 8)", k, sizeof(k), 0); }
    { static unsigned char k[] = {0x66,0x0f,0x68,0xc1}; сверка("punpckhbw  (верх, 1)", k, sizeof(k), 0); }
    { static unsigned char k[] = {0x66,0x0f,0x69,0xc1}; сверка("punpckhwd  (верх, 2)", k, sizeof(k), 0); }
    { static unsigned char k[] = {0x66,0x0f,0x6a,0xc1}; сверка("punpckhdq  (верх, 4)", k, sizeof(k), 0); }
    { static unsigned char k[] = {0x66,0x0f,0x6d,0xc1}; сверка("punpckhqdq (верх, 8)", k, sizeof(k), 0); }

    printf("\nузкое чтение памяти в XMM (регистры предзаполнены 0xEE..):\n");
    { static unsigned char k[] = {0xf3,0x0f,0x10,0x00}; чтение("movss  (верх в НОЛЬ)", k, sizeof(k)); }
    { static unsigned char k[] = {0xf2,0x0f,0x10,0x00}; чтение("movsd  (верх в НОЛЬ)", k, sizeof(k)); }
    { static unsigned char k[] = {0x66,0x0f,0x6e,0x00}; чтение("movd   (верх в НОЛЬ)", k, sizeof(k)); }
    { static unsigned char k[] = {0xf3,0x0f,0x7e,0x00}; чтение("movq   (верх в НОЛЬ)", k, sizeof(k)); }
    /* ★ страховка: movlps верхнюю половину СОХРАНЯЕТ. Если выпуск начнёт обнулять
     *   её заодно со всеми, расхождение всплывёт именно здесь. */
    { static unsigned char k[] = {0x0f,0x12,0x00};      чтение("movlps (верх УЦЕЛЕЕТ)", k, sizeof(k)); }

    printf("\nитог: %d из %d сошлись\n", всего - отказов, всего);
    return отказов ? 1 : 0;
}
