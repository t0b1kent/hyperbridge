/* MacRunner 2026-08-16, лейн ВЫПУСК, итерация 7 — ЦЕНА БАРЬЕРОВ НА НАШЕМ ЯДРЕ.
 *
 * Зачем. Признак закрытия ступени 8 требует, чтобы цена барьеров была ИЗМЕРЕНА микропробой на
 * НАШЕМ ядре, а не взята из статей. Мы выпускаем для каждого гостевого чтения `LDR` плюс
 * `DMB ISHLD`, а для каждой записи `STLR` (`hb_arm64_codegen.c:271`, `emit_ldar_to_reg`) —
 * чтобы сохранить порядок памяти x86 (TSO) на ядре с более слабым порядком. За это платят все
 * обращения к памяти, а гейты `MACRUNNER_HB_TSO_*RELAXED` позволяют платёж снять. Сколько именно
 * снимается — вопрос числа, и здесь оно берётся.
 *
 * Что меряется. Шесть петель по одному адресу (попадание в кеш первого уровня, чтобы мерить
 * барьер, а не промах):
 *
 *     ldr              обычное чтение — основание сравнения
 *     ldr + dmb ishld  ровно то, что выпускаем мы
 *     ldar             аппаратный вариант «чтение-захват» (мы его НЕ выпускаем, см. ниже)
 *     str              обычная запись — основание
 *     stlr             то, что выпускаем мы для записи
 *     dmb ish          полный барьер, для сравнения с ishld
 *
 * Почему `LDAR` мы не выпускаем, хотя он дешевле пары: x86 разрешает НЕВЫРОВНЕННЫЕ чтения, а
 * `LDAR` на невыровненном адресе даёт SIGBUS. На этом livelock'нулось сравнение строк Mono
 * (`cmp [rdx+8], r12` при rdx, выровненном на 4). Поэтому пара `LDR`+`DMB` — не небрежность, а
 * цена невыровненности; проба меряет обе, чтобы разница была числом.
 *
 * ОКНО ОТКАЗА. Проба обязана уметь показать РАЗНИЦУ. Если бы все шесть петель дали одно и то же,
 * это значило бы, что меряется не то (компилятор выбросил тело, счётчик слишком груб) — такой
 * исход печатается отдельной строкой и числа объявляются негодными.
 *
 * Запуск: make -C engine/hyperbridge barrier-cost-probe
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hb_bench.h"

#define UNROLL 8

/* Тело петли собирается макросом, чтобы все шесть петель были одинаковы во всём, кроме
 * измеряемой команды: тот же счётчик, та же развёртка, тот же адрес. */
#define LOOP_BODY(INSN)                                                    \
    "1:\n\t" INSN INSN INSN INSN INSN INSN INSN INSN                       \
    "subs %[n], %[n], #1\n\t"                                              \
    "b.ne 1b\n\t"

#define MAKE_BENCH(name, INSN)                                             \
static uint64_t bench_##name(volatile uint32_t *p, uint64_t iters)         \
{                                                                          \
    uint64_t n = iters, t0, t1;                                            \
    uint32_t tmp = 0;                                                      \
    t0 = hb_bench_now_ns();                                                \
    __asm__ __volatile__(LOOP_BODY(INSN)                                   \
                         : [t] "=&r"(tmp), [n] "+r"(n)                     \
                         : [p] "r"(p)                                      \
                         : "cc", "memory");                                \
    t1 = hb_bench_now_ns();                                                \
    (void)tmp;                                                             \
    return t1 - t0;                                                        \
}

MAKE_BENCH(ldr,      "ldr %w[t], [%[p]]\n\t")
MAKE_BENCH(ldr_dmb,  "ldr %w[t], [%[p]]\n\tdmb ishld\n\t")
MAKE_BENCH(ldar,     "ldar %w[t], [%[p]]\n\t")
MAKE_BENCH(str,      "str %w[t], [%[p]]\n\t")
MAKE_BENCH(stlr,     "stlr %w[t], [%[p]]\n\t")
MAKE_BENCH(dmb_ish,  "ldr %w[t], [%[p]]\n\tdmb ish\n\t")

struct row { const char *name; uint64_t (*fn)(volatile uint32_t *, uint64_t); double ns; };

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    const uint64_t iters = (argc > 1) ? strtoull(argv[1], NULL, 0) : 200000;
    const int reps = 9;
    static uint32_t cell[16];
    volatile uint32_t *p = &cell[4];
    struct row rows[] = {
        { "ldr             (основание чтения)", bench_ldr,     0 },
        { "ldr + dmb ishld (выпускаем мы)",     bench_ldr_dmb, 0 },
        { "ldar            (не выпускаем)",     bench_ldar,    0 },
        { "str             (основание записи)", bench_str,     0 },
        { "stlr            (выпускаем мы)",     bench_stlr,    0 },
        { "ldr + dmb ish   (полный барьер)",    bench_dmb_ish, 0 },
    };
    const int nrows = (int)(sizeof(rows) / sizeof(rows[0]));
    double lo = 1e300, hi = -1e300;
    int i, r;

    setvbuf(stdout, NULL, _IONBF, 0);
    *p = 0x12345678u;

    /* прогрев: первый проход всегда дороже — кеш команд, частота ядра */
    for (i = 0; i < nrows; i++) (void)rows[i].fn(p, iters / 10 + 1);

    printf("цена барьеров: %llu витков × %d команд, медиана %d повторов\n",
           (unsigned long long)iters, UNROLL, reps);

    for (i = 0; i < nrows; i++) {
        double s[16];
        for (r = 0; r < reps; r++)
            s[r] = (double)rows[i].fn(p, iters) / (double)(iters * UNROLL);
        qsort(s, (size_t)reps, sizeof(s[0]), cmp_d);
        rows[i].ns = s[reps / 2];
        if (rows[i].ns < lo) lo = rows[i].ns;
        if (rows[i].ns > hi) hi = rows[i].ns;
    }

    printf("%-36s %10s %12s\n", "команда", "нс/шт", "против основания");
    for (i = 0; i < nrows; i++) {
        double base = (i < 3) ? rows[0].ns : rows[3].ns;
        printf("%-36s %10.3f %11.2fx\n", rows[i].name, rows[i].ns, rows[i].ns / base);
    }

    /* Окно: если все шесть совпали, меряется не то. */
    if (hi < lo * 1.05) {
        printf("ОКНО НЕ ОТКРЫЛОСЬ: все шесть петель в пределах 5 %% — числа НЕГОДНЫ\n");
        return 1;
    }
    printf("окно открыто: разброс между петлями %.2fx — проба различает команды\n", hi / lo);
    return 0;
}
