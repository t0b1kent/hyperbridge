/*
 * hb_vex_ymm_move_test.c — VEX.256 перемещения память<->YMM и VEX.128 чтение в XMM: выпущенный код
 * обязан совпадать с интерпретатором — значение XMM, ymm_hi, zmm_hi и байты памяти.
 *
 * 26.09.2026. Перепись HK: после нативной SSE 69 % оставшихся вызовов интерпретатора — именно
 * эти VEX.256 LOAD/STORE. Попутно найдено: нативное 128-битное чтение не обнуляло верх YMM у
 * VEX-формы (класс 5df7992). Устаревший SSE movups — контроль: у него верх ОБЯЗАН сохраниться.
 * У каждого исполнителя свой буфер памяти с одинаковым начальным содержимым.
 * Выход 0 — всё совпало и нативный выпуск состоялся, 1 — расхождение, 2 — отказ оснастки.
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

/* Слабый символ: тест собирается и против ядра ДО правки (отрицательный контроль). */
extern uint64_t hb_codegen_native_ymm_moves_emitted(void) __attribute__((weak));
static uint64_t native_count(void) { return hb_codegen_native_ymm_moves_emitted ? hb_codegen_native_ymm_moves_emitted() : 0; }

struct form { const char* name; uint8_t bytes[10]; int len; };
static const struct form FORMS[] = {
    {"vmovups ymm0,[rdx]",       {0xc5,0xfc,0x10,0x02}, 4},
    {"vmovdqu ymm1,[rdx+0x20]",  {0xc5,0xfe,0x6f,0x4a,0x20}, 5},
    {"vmovups [rdx+0x40],ymm0",  {0xc5,0xfc,0x11,0x42,0x40}, 5},
    {"vmovdqu [rdx+0x60],ymm1",  {0xc5,0xfe,0x7f,0x4a,0x60}, 5},
    {"vmovaps ymm3,[rdx+0x80]",  {0xc5,0xfc,0x28,0x9a,0x80,0x00,0x00,0x00}, 8},
    {"vmovups xmm2,[rdx]",       {0xc5,0xf8,0x10,0x12}, 4},
    {"movups xmm4,[rdx]",        {0x0f,0x10,0x22}, 3},
    {"vmovups [rdx+0x13],ymm0",  {0xc5,0xfc,0x11,0x42,0x13}, 5},
};
#define NFORMS (sizeof(FORMS) / sizeof(FORMS[0]))

int main(void) {
    unsigned long bad = 0, cases = 0;
    hb_context_t* cs[2] = { hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP),
                            hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT) };
    hb_memory_t* ms[2] = { hb_memory_create(0), hb_memory_create(0) };
    if (!cs[0] || !cs[1] || !ms[0] || !ms[1]) { printf("ОТКАЗ ОСНАСТКИ: контекст\n"); return 2; }
    uint8_t* code = mmap(NULL, 16384 * NFORMS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* data[2] = { mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
                         mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) };
    if (code == MAP_FAILED || stack == MAP_FAILED || data[0] == MAP_FAILED || data[1] == MAP_FAILED) {
        printf("ОТКАЗ ОСНАСТКИ: mmap\n"); return 2;
    }
    for (int k = 0; k < 2; k++) {
        cs[k]->memory = ms[k];
        if (hb_memory_sync_live_range(ms[k], (hb_gva_t)(uintptr_t)code, 16384 * NFORMS,
                                      HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
            hb_memory_sync_live_range(ms[k], (hb_gva_t)(uintptr_t)stack, 65536, HB_PERM_READ | HB_PERM_WRITE) != HB_OK ||
            hb_memory_sync_live_range(ms[k], (hb_gva_t)(uintptr_t)data[k], 16384, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
            printf("ОТКАЗ ОСНАСТКИ: учёт памяти\n"); return 2;
        }
    }
    for (unsigned f = 0; f < NFORMS; f++) {
        uint8_t* at = code + 16384 * f;
        uint64_t base = (uint64_t)(uintptr_t)at;
        memcpy(at, FORMS[f].bytes, (size_t)FORMS[f].len);
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, at, (size_t)FORMS[f].len, base);
        hb_ir_func_t* func = NULL;
        if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func) { printf("ОТКАЗ ОСНАСТКИ: лифт %s\n", FORMS[f].name); return 2; }
        hb_decoder_destroy(dec);
        const uint64_t native_before = native_count();
        for (unsigned seed = 1; seed <= 16; seed++) {
            hb_exec_result_t o[2];
            hb_result_t r[2];
            for (int k = 0; k < 2; k++) {
                hb_context_t* c = cs[k];
                for (unsigned i = 0; i < 256; i++) data[k][i] = (uint8_t)(i * 37u + seed * 11u);
                c->pc = base; c->regs.x64.rip = base;
                c->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
                c->regs.x64.rdx = (uint64_t)(uintptr_t)data[k];
                for (unsigned q = 0; q < 5; q++) {
                    c->regs.x64.xmm[q][0] = 0x1111111111111111ull * (q + 1) ^ seed;
                    c->regs.x64.xmm[q][1] = 0x0101010101010101ull * (q + 7) ^ seed;
                    c->ymm_hi[q][0] = 0xa5a5a5a5a5a5a5a5ull ^ (q * 0x1000u + seed);
                    c->ymm_hi[q][1] = 0x5a5a5a5a5a5a5a5aull ^ (q * 0x2000u + seed);
                    for (unsigned z = 0; z < 4; z++) c->zmm_hi[q][z] = 0xc3c3c3c3c3c3c3c3ull ^ (q * 16u + z + seed);
                }
                memset(&o[k], 0, sizeof(o[k]));
                r[k] = hb_runtime_run(c, func, k ? HB_BACKEND_JIT : HB_BACKEND_INTERP, &o[k]);
            }
            cases++;
            int diff = r[0] != r[1] || o[0].result != o[1].result || cs[0]->pc != cs[1]->pc ||
                       memcmp(cs[0]->regs.x64.xmm, cs[1]->regs.x64.xmm, sizeof(uint64_t) * 10) != 0 ||
                       memcmp(cs[0]->ymm_hi, cs[1]->ymm_hi, sizeof(uint64_t) * 10) != 0 ||
                       memcmp(cs[0]->zmm_hi, cs[1]->zmm_hi, sizeof(uint64_t) * 20) != 0 ||
                       memcmp(data[0], data[1], 256) != 0;
            if (diff) {
                bad++;
                if (bad <= 12)
                    printf("НАРУШЕНИЕ %-26s seed=%u r=%d/%d xmm0 %016llx:%016llx/%016llx:%016llx ymm_hi0 %016llx/%016llx "
                           "zmm_hi0 %016llx/%016llx mem%s\n", FORMS[f].name, seed, (int)r[0], (int)r[1],
                           (unsigned long long)cs[0]->regs.x64.xmm[0][1], (unsigned long long)cs[0]->regs.x64.xmm[0][0],
                           (unsigned long long)cs[1]->regs.x64.xmm[0][1], (unsigned long long)cs[1]->regs.x64.xmm[0][0],
                           (unsigned long long)cs[0]->ymm_hi[0][0], (unsigned long long)cs[1]->ymm_hi[0][0],
                           (unsigned long long)cs[0]->zmm_hi[0][0], (unsigned long long)cs[1]->zmm_hi[0][0],
                           memcmp(data[0], data[1], 256) ? " РАЗНАЯ" : " одинаковая");
            }
        }
        if (FORMS[f].name[0] == 'v' && strstr(FORMS[f].name, "ymm") && native_count() == native_before)
            printf("НЕ НАТИВНО: %s\n", FORMS[f].name);
        hb_ir_func_destroy(func);
    }
    printf("случаев=%lu расхождений=%lu нативных_ymm=%llu\n", cases, bad,
           (unsigned long long)native_count());
    if (native_count() == 0) { printf("НАРУШЕНИЕ: нативный выпуск YMM не состоялся ни разу\n"); bad++; }
    printf("TOTAL_BAD=%lu\n", bad);
    return bad ? 1 : 0;
}
