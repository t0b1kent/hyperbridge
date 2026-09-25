/* MacRunner 2026-08-16, лейн ВЫПУСК, итерация 4 — ПОЧЕМУ ПЛАВАЕТ `control_state_setjmp_family`.
 *
 * Зачем. В наборе `hb_test_runner` проверка `out.result == HB_OK` в тесте
 * `interp_x64_control_state_setjmp_family` отказывает ПРИМЕРНО В ПОЛОВИНЕ прогонов одного и того
 * же двоичного (замер: 3 отказа на 6 прогонов). Плавающий отказ нельзя ни починить, ни объявить
 * ложным, пока не названо, ЧЕМ он управляется.
 *
 * Гипотеза, которую проба проверяет. Тест отображает `frame` — массив на ХОЗЯЙСКОМ СТЕКЕ — как
 * гостевую память через `hb_memory_map` (тождественное отображение: гостевой адрес и есть
 * хозяйский). Адрес стека меняется от прогона к прогону (ASLR), значит меняется и «гостевой»
 * адрес. Если отказ управляется адресом, отказы обязаны сгруппироваться по свойству адреса.
 *
 * Как читать вывод. Проба гоняет ту же последовательность N раз В ОДНОМ процессе, сдвигая кадр
 * на 16 байт каждый раз, и печатает адрес с исходом. Внутри процесса база стека одна, поэтому
 * разброс даёт именно СМЕЩЕНИЕ; запуск пробы несколько раз добавляет разброс базы.
 *
 * ОКНО ОТКАЗА: если ни один случай не отказал, проба печатает это отдельной строкой — «ноль
 * отказов» здесь означает «условие не поймано», а не «дефекта нет» (входящее, пункт 3).
 *
 * Сборка и запуск:
 *   make -C engine/hyperbridge ctrlstate-frame-probe
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"

/* Та же последовательность, что в тесте: выгрузка и загрузка управляющих регистров SSE и x87
 * плюс три барьера. Все обращения — по [rcx+0x58] и [rcx+0x5c]. */
static const uint8_t g_code[] = {
    0x0f, 0xae, 0x59, 0x58, /* stmxcsr 0x58(%rcx) */
    0xd9, 0x79, 0x5c,       /* fnstcw  0x5c(%rcx) */
    0x0f, 0xae, 0x51, 0x58, /* ldmxcsr 0x58(%rcx) */
    0xd9, 0x69, 0x5c,       /* fldcw   0x5c(%rcx) */
    0x9b,                   /* fwait */
    0x0f, 0xae, 0xe8,       /* lfence */
    0x0f, 0xae, 0xf0,       /* mfence */
    0x0f, 0xae, 0xf8        /* sfence */
};

struct outcome {
    uint64_t frame;
    int      rc;
    int      result;
    uint32_t mxcsr;
};

static int run_once(uint8_t *frame, size_t frame_size, struct outcome *out)
{
    uint64_t base = (uint64_t)(uintptr_t)g_code;
    hb_decoder_t *dec;
    hb_ir_func_t *func = NULL;
    hb_context_t *ctx;
    hb_exec_result_t res = {0};

    memset(frame, 0xaa, frame_size);
    out->frame = (uint64_t)(uintptr_t)frame;

    dec = hb_decoder_create(HB_ARCH_X64, g_code, sizeof(g_code), base);
    if (!dec) return -1;
    if (hb_lift_func_x64(dec, &func) != HB_OK || !func) { hb_decoder_destroy(dec); return -1; }
    hb_decoder_destroy(dec);

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    if (!ctx) { hb_ir_func_destroy(func); return -1; }
    ctx->memory = hb_memory_create(0);
    hb_memory_map(ctx->memory, (hb_gva_t)base, sizeof(g_code), HB_PERM_READ | HB_PERM_EXEC);
    hb_memory_map(ctx->memory, (hb_gva_t)(uintptr_t)frame, frame_size,
                  HB_PERM_READ | HB_PERM_WRITE);
    ctx->pc = base;
    ctx->regs.x64.rcx = (uint64_t)(uintptr_t)frame;

    out->rc = (int)hb_runtime_run(ctx, func, HB_BACKEND_INTERP, &res);
    out->result = (int)res.result;
    memcpy(&out->mxcsr, frame + 0x58, sizeof(out->mxcsr));

    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    return 0;
}

int main(int argc, char **argv)
{
    const int n = (argc > 1) ? atoi(argv[1]) : 24;
    int bad = 0, good = 0, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("проба управляющего состояния: %d случаев, кадр сдвигается на 16 байт\n", n);

    for (i = 0; i < n; i++) {
        uint8_t storage[0x70 + 16 * 64];
        uint8_t *frame = storage + (size_t)i * 16;
        struct outcome o;

        if (run_once(frame, 0x70, &o) != 0) { printf("  ОСНАСТКА ОТКАЗАЛА на случае %d\n", i); return 2; }
        if (o.rc != 0 || o.result != 0) {
            bad++;
            printf("  ОТКАЗ  кадр=0x%llx  младшие16=0x%04llx  выровнен16К=%llu  rc=%d result=%d\n",
                   (unsigned long long)o.frame, (unsigned long long)(o.frame & 0xffff),
                   (unsigned long long)(o.frame & 0x3fff), o.rc, o.result);
        } else {
            good++;
            if (i < 3)
                printf("  ok     кадр=0x%llx  mxcsr=0x%x\n",
                       (unsigned long long)o.frame, o.mxcsr);
        }
    }

    printf("итог: прошло %d, отказало %d из %d\n", good, bad, n);
    if (bad == 0)
        printf("ОКНО НЕ ОТКРЫЛОСЬ: ни одного отказа — это «условие не поймано», а НЕ «дефекта нет»\n");
    return bad ? 1 : 0;
}
