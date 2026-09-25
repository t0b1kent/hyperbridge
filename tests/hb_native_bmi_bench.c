/* MacRunner 2026-08-16, лейн ВЫПУСК, итерация 5 — ПОРОГ ОКУПАЕМОСТИ: СВОЙ ВЫПУСК ПРОТИВ ПОМОЩНИКА.
 *
 * Зачем. Признак закрытия ступени 4 требует, чтобы порог «выпуск против помощника» был ИЗМЕРЕН
 * числом, а не назван словами. Свой выпуск операции стоит дороже при подготовке блока (больше
 * команд выпускается) и дешевле при исполнении (нет вызова помощника). Значит существует число
 * повторений блока, начиная с которого свой выпуск окупается. Его и меряем.
 *
 * Как. Одна и та же гостевая петля из четырёх операций BMI гоняется N раз в СВЕЖЕМ контексте,
 * поэтому в замер входит и подготовка блока, и N исполнений. Рука выбирается переменной
 * `MACRUNNER_HB_NATIVE_BMI` СНАРУЖИ (гейт читается один раз за процесс и кешируется — внутри
 * процесса его не переключить). Порог — наименьшее N, при котором рука выпуска обгоняет руку
 * помощника.
 *
 * Гостевой код взят у АССЕМБЛЕРА, а не собран руками (входящее, пункт 4):
 *   x86_64-w64-mingw32-clang -c loop.s && llvm-objdump -d loop.o
 *   c4 e2 60 f2 c1  andn eax,ebx,ecx     c4 e2 68 f3 d9  blsi   edx,ecx
 *   c4 e2 48 f3 d1  blsmsk esi,ecx       c4 e2 40 f3 c9  blsr   edi,ecx
 *   ff c9           dec ecx              75 e8           jnz петля
 *
 * ЧТО ЭТА ПРОБА НЕ УМЕЕТ — границы обязательны:
 *   * меряет ЧЕТЫРЕ операции BMI в петле, а не «выпуск вообще»; для другой операции порог свой;
 *   * машина под нагрузкой — конфаунд первого порядка (в этом проекте одна конфигурация давала
 *     87 с и 121 с от одной лишь нагрузки), поэтому берётся МЕДИАНА повторов, а руки чередуются
 *     снаружи, а не «сначала все A, потом все B»;
 *   * это не цена в игре: там блоки перемежаются чужой работой и кеш ведёт себя иначе.
 *
 * Запуск (обе руки и порог считает сценарий):
 *   make -C engine/hyperbridge native-bmi-bench
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include "hb_bench.h"

/* Итерация 10: вторая петля — CRC32 (32- и 64-битная формы). Выбирается вторым доводом
 * командной строки: `bmi` (по умолчанию) или `crc`. Помощник считает её побитовым циклом —
 * 8 витков на КАЖДЫЙ байт источника, то есть 32 и 64 витка на эту пару команд, — а ARM64 имеет
 * `CRC32C*` одной командой. Кодировки от ассемблера. */
static const uint8_t g_loop_crc[] = {
    0xf2, 0x0f, 0x38, 0xf1, 0xc3,         /* crc32l %ebx, %eax */
    0xf2, 0x48, 0x0f, 0x38, 0xf1, 0xc3,   /* crc32q %rbx, %rax */
    0xff, 0xc9,                           /* dec ecx */
    0x75, 0xf1,                           /* jnz петля */
    0xc3                                  /* ret */
};

/* Итерация 12: третья петля — сравнения плавающей точки (`comiss` + `comisd`). Выбирается
 * третьим значением второго довода: `cmp`. Нужна для замера, которого требует пункт 7 входящего:
 * сколько стоит НЫНЕШНИЙ путь установки флагов после сравнения. Обе команды идут через
 * помощника (`hb_arm64_codegen.c:6972-7027`, общий список `emit_interp_ir_helper`), своего
 * выпуска у них нет вовсе — значит `AXFLAG`/`XAFLAG` пока нечего ускорять, и это надо показать
 * числом, а не рассуждением. Кодировки от ассемблера. */
static const uint8_t g_loop_cmp[] = {
    0x0f, 0x2f, 0xc1,               /* comiss %xmm1, %xmm0 */
    0x66, 0x0f, 0x2f, 0xc1,         /* comisd %xmm1, %xmm0 */
    0xff, 0xc9,                     /* dec ecx */
    0x75, 0xf5,                     /* jnz петля */
    0xc3                            /* ret */
};

/* Итерация 15: четвёртая петля — округление (`roundps` + `roundsd`). Довод `rnd`. Нужна, чтобы
 * ОТКЛАДЫВАНИЕ `FROUND` было подкреплено числом, а не ощущением: сколько стоит нынешний путь.
 * Кодировки от ассемблера. */
static const uint8_t g_loop_rnd[] = {
    0x66, 0x0f, 0x3a, 0x08, 0xc1, 0x01,   /* roundps $1, %xmm1, %xmm0 */
    0x66, 0x0f, 0x3a, 0x0b, 0xc1, 0x02,   /* roundsd $2, %xmm1, %xmm0 */
    0xff, 0xc9,                           /* dec ecx */
    0x75, 0xf0,                           /* jnz петля */
    0xc3                                  /* ret */
};

static const uint8_t *g_code = NULL;
static size_t g_code_len = 0;

static const uint8_t g_loop[] = {
    0xc4, 0xe2, 0x60, 0xf2, 0xc1,   /* andn   eax, ebx, ecx */
    0xc4, 0xe2, 0x68, 0xf3, 0xd9,   /* blsi   edx, ecx      */
    0xc4, 0xe2, 0x48, 0xf3, 0xd1,   /* blsmsk esi, ecx      */
    0xc4, 0xe2, 0x40, 0xf3, 0xc9,   /* blsr   edi, ecx      */
    0xff, 0xc9,                     /* dec    ecx           */
    0x75, 0xe8,                     /* jnz    петля         */
    0xc3                            /* ret                  */
};

/* Один замер: свежий контекст, N витков петли, время всего вызова в наносекундах.
 * Возвращает 0 при успехе. */
static int measure(uint32_t n, uint64_t *ns_out, int *result_out)
{
    uint64_t base = (uint64_t)(uintptr_t)g_code;
    hb_decoder_t *dec;
    hb_ir_func_t *func = NULL;
    hb_context_t *ctx;
    hb_exec_result_t res = {0};
    uint64_t t0, t1;

    dec = hb_decoder_create(HB_ARCH_X64, g_code, g_code_len, base);
    if (!dec) return -1;
    if (hb_lift_func_x64(dec, &func) != HB_OK || !func) { hb_decoder_destroy(dec); return -1; }
    hb_decoder_destroy(dec);

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    if (!ctx) { hb_ir_func_destroy(func); return -1; }
    ctx->memory = hb_memory_create(0);
    hb_memory_map(ctx->memory, (hb_gva_t)base, g_code_len, HB_PERM_READ | HB_PERM_EXEC);
    ctx->pc = base;
    ctx->regs.x64.rip = base;
    ctx->regs.x64.rcx = n;
    ctx->regs.x64.rbx = 0x0f0f0f0fu;
    ctx->step_limit  = 0;   /* без потолка: петля делает 6*N шагов */
    ctx->block_limit = 0;

    t0 = hb_bench_now_ns();
    (void)hb_runtime_run(ctx, func, HB_BACKEND_JIT, &res);
    t1 = hb_bench_now_ns();

    *ns_out = t1 - t0;
    *result_out = (int)res.result;

    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    static const uint32_t ns[] = {1, 2, 4, 8, 16, 64, 256, 1024, 4096, 16384, 65536};
    const int nn = (int)(sizeof(ns) / sizeof(ns[0]));
    const int reps = (argc > 1) ? atoi(argv[1]) : 7;
    const char *arm = getenv("MACRUNNER_HB_NATIVE_BMI");
    int i, r;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && strcmp(argv[2], "rnd") == 0) {
        g_code = g_loop_rnd; g_code_len = sizeof(g_loop_rnd);
        printf("# петля округления (roundps + roundsd), оба через помощника\n");
    } else if (argc > 2 && strcmp(argv[2], "cmp") == 0) {
        g_code = g_loop_cmp; g_code_len = sizeof(g_loop_cmp);
        printf("# петля сравнений (comiss + comisd), оба через помощника\n");
    } else if (argc > 2 && strcmp(argv[2], "crc") == 0) {
        g_code = g_loop_crc; g_code_len = sizeof(g_loop_crc);
        printf("# петля CRC32 (crc32l + crc32q), гейт MACRUNNER_HB_NATIVE_CRC32\n");
    } else {
        g_code = g_loop; g_code_len = sizeof(g_loop);
    }
    printf("# рука MACRUNNER_HB_NATIVE_BMI=%s  повторов=%d  медиана\n",
           arm ? arm : "(не задана — умолчание ВКЛ)", reps);
    printf("# N\tмедиана_нс\tмин_нс\tresult\n");

    for (i = 0; i < nn; i++) {
        uint64_t samples[64];
        int result = 0, bad = 0;

        if (reps > 64) return 2;
        for (r = 0; r < reps; r++) {
            if (measure(ns[i], &samples[r], &result) != 0) { bad = 1; break; }
            if (result != 0) bad = 1;
        }
        if (bad) { printf("%u\tОСНАСТКА ОТКАЗАЛА result=%d\n", ns[i], result); return 2; }

        qsort(samples, (size_t)reps, sizeof(samples[0]), cmp_u64);
        printf("%u\t%llu\t%llu\t%d\n", ns[i],
               (unsigned long long)samples[reps / 2],
               (unsigned long long)samples[0], result);
    }
    return 0;
}
