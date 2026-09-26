/*
 * hb_smc_fastpath_test.c — сверка SMC по поколению защищённой страницы (MACRUNNER_HB_SMC_PROTECT).
 *
 * 26.09.2026. Блок из записываемой памяти (так живёт JIT-код Mono) сверялся хешем окна до 4 КБ
 * на КАЖДОМ входе через диспетчер: в профиле Hollow Knight это 8,5 % основного потока. С защитой
 * страница после перевода становится R|X, запись в неё даёт отказ, обработчик поднимает
 * поколение — и на входе достаточно сравнить поколение. Проверяем три вещи:
 *   1) код не менялся — вход принят БЕЗ хеша (счётчик быстрого пути растёт);
 *   2) код изменён записью — старый перевод выселен, исполняется НОВЫЙ код;
 *   3) объявление Wine о смене прав снимает учёт и возвращает странице право записи
 *      (иначе следующая запись гостя упёрлась бы в нашу защиту без хозяина).
 * Рука `off` (без аргумента защиты) — отрицательный контроль: быстрого пути нет, а новый код
 * всё равно исполняется (хеш остаётся полномочным судьёй).
 *
 * Выход 0 — всё верно; 1 — нарушение; 2 — отказ оснастки.
 */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

extern int hb_smc_query_prot(uint64_t host_addr);

#define PAGE 16384u

static hb_ir_func_t* lift_at(uint8_t* code, size_t n) {
    hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, code, n, (uint64_t)(uintptr_t)code);
    hb_ir_func_t* f = NULL;
    if (!dec) return NULL;
    if (hb_lift_func_x64(dec, &f) != HB_OK) f = NULL;
    hb_decoder_destroy(dec);
    return f;
}

/* Один проход по окну [base, base+0x40): блок кончается прямым переходом наружу. */
static int run_once(hb_jit_runtime_t* rt, hb_context_t* ctx, hb_ir_func_t* f, uint64_t base,
                    uint64_t* rax) {
    int hops;
    ctx->pc = base;
    for (hops = 0; hops < 4; hops++) {
        hb_exec_result_t out;
        memset(&out, 0, sizeof(out));
        if (hb_jit_runtime_run(rt, f, &out) != HB_OK || out.result != HB_OK) return 0;
        if (ctx->pc < base || ctx->pc >= base + 0x40) break;
    }
    *rax = ctx->regs.x64.rax & 0xffffffffu;
    return 1;
}

static void put_code(uint8_t* code, uint32_t imm) {
    uint32_t rel = 0x100u - 10u;                   /* jmp base+0x100 из конца 10-байтной пары */
    code[0] = 0xb8; memcpy(code + 1, &imm, 4);     /* mov eax, imm32 */
    code[5] = 0xe9; memcpy(code + 6, &rel, 4);     /* jmp rel32 */
}

int main(int argc, char** argv) {
    const int protect = !(argc > 1 && !strcmp(argv[1], "off"));
    uint64_t rax = 0, fast0 = 0, fast1 = 0, rearm = 0, ev0, ev1;
    int bad = 0;
    setenv("MACRUNNER_HB_SMC_PROTECT", protect ? "1" : "0", 1);   /* до первого обращения к гейту */
    hb_env_refresh();
    hb_memory_install_fault_handlers();

    hb_context_t* ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_memory_t* mem = hb_memory_create(0);
    if (!ctx || !mem) { printf("ОТКАЗ ОСНАСТКИ: контекст\n"); return 2; }
    ctx->memory = mem;
    uint8_t* code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED || stack == MAP_FAILED ||
        hb_memory_sync_live_range(mem, (hb_gva_t)(uintptr_t)code, PAGE,
                                  HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
        hb_memory_sync_live_range(mem, (hb_gva_t)(uintptr_t)stack, 65536,
                                  HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        printf("ОТКАЗ ОСНАСТКИ: память\n");
        return 2;
    }
    ctx->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
    uint64_t base = (uint64_t)(uintptr_t)code;
    hb_jit_runtime_t* rt = hb_jit_runtime_create(ctx);
    if (!rt) { printf("ОТКАЗ ОСНАСТКИ: среда JIT\n"); return 2; }

    put_code(code, 0x11111111u);
    hb_ir_func_t* f1 = lift_at(code, 10);
    if (!f1 || !run_once(rt, ctx, f1, base, &rax)) { printf("ОТКАЗ ОСНАСТКИ: первый проход\n"); return 2; }
    if (rax != 0x11111111u) { printf("НАРУШЕНИЕ: первый проход eax=%08llx\n", (unsigned long long)rax); bad++; }

    hb_jit_smc_fast_stats(&fast0, NULL);
    if (!run_once(rt, ctx, f1, base, &rax) || rax != 0x11111111u) {
        printf("НАРУШЕНИЕ: второй проход eax=%08llx\n", (unsigned long long)rax); bad++;
    }
    hb_jit_smc_fast_stats(&fast1, NULL);
    printf("быстрый путь без изменения кода: +%llu (защита %s)\n",
           (unsigned long long)(fast1 - fast0), protect ? "ВКЛ" : "ВЫКЛ");
    if (protect && fast1 == fast0) { printf("НАРУШЕНИЕ: быстрый путь не сработал\n"); bad++; }
    if (!protect && fast1 != fast0) { printf("НАРУШЕНИЕ: быстрый путь при выключенной защите\n"); bad++; }
    if (protect) {
        int prot = hb_smc_query_prot(base);
        printf("права страницы после перевода: %d (ждём 5 = R|X)\n", prot);
        if (prot != 5) { printf("НАРУШЕНИЕ: страница не защищена\n"); bad++; }
    }

    /* Запись хоста в код: при защите — отказ, обработчик поднимает поколение и отпускает. */
    ev0 = hb_jit_smc_evicted_total();
    put_code(code, 0x22222222u);
    hb_ir_func_t* f2 = lift_at(code, 10);
    if (!f2 || !run_once(rt, ctx, f2, base, &rax)) { printf("ОТКАЗ ОСНАСТКИ: третий проход\n"); return 2; }
    ev1 = hb_jit_smc_evicted_total();
    printf("после записи в код: eax=%08llx выселено=+%llu\n", (unsigned long long)rax,
           (unsigned long long)(ev1 - ev0));
    if (rax != 0x22222222u) { printf("НАРУШЕНИЕ: исполнен УСТАРЕВШИЙ перевод\n"); bad++; }
    if (ev1 == ev0) { printf("НАРУШЕНИЕ: изменение кода не выселило перевод\n"); bad++; }

    if (protect) {
        /* Перевод нового кода снова взводит защиту; четвёртый проход — снова быстрый путь. */
        if (!run_once(rt, ctx, f2, base, &rax) || rax != 0x22222222u) {
            printf("НАРУШЕНИЕ: четвёртый проход eax=%08llx\n", (unsigned long long)rax); bad++;
        }
        hb_jit_smc_fast_stats(NULL, &rearm);
        /* Объявление «protect» при неизменных наших R|X: право записи обязано вернуться. */
        (void)hb_jit_invalidate_guest_range_all_why(NULL, base, PAGE, 4u);
        int prot = hb_smc_query_prot(base);
        printf("права после объявления protect: %d (ждём 3 = R|W)\n", prot);
        if (prot != 3) { printf("НАРУШЕНИЕ: защита пережила объявление Wine\n"); bad++; }
    }
    printf("TOTAL_BAD=%d\n", bad);
    return bad ? 1 : 0;
}
