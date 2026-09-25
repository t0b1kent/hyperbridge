/* hb_fence_cost_bench — ЦЕНА ОГРАЖДЁННОГО КОПИРОВАНИЯ ПАМЯТИ ГОСТЯ, НАСТОЯЩИМ КОДОМ.
 *
 * ЗАЧЕМ. `scripts/цена-операции` мерит ПОВТОРЁННУЮ форму ограждения: там свой
 * `__atomic_test_and_set`, своя ячейка, свой `sigsetjmp`. Повторение всегда рискует
 * разойтись с оригиналом — ровно тот класс, из-за которого прибор цены год мерил
 * снимок 760 Б вместо 1800. Здесь зовётся НАСТОЯЩИЙ `hb_memory_read`/`hb_memory_write`
 * по НАСТОЯЩЕЙ области guest32, то есть тот самый путь, где стоит ограждение
 * (`hb_memory.c`, ветви `guest32_direct_copy_safe`).
 *
 * ЧТО ЭТИМ МЕРЯТ. Разность двух СБОРОК: с быстрым путём в `install_sig_handlers`
 * и без него. Счётчик `macrunner-hb-fence-census` говорит, сколько постановок
 * ограждения делает прогон (1 350 565 888 за 38 с стенда benchz-pe32); этот прибор
 * говорит, сколько стоит одна. Произведение — доля времени.
 *
 * ЧЕСТНОСТЬ. Пустой виток замеряется отдельно и вычитается; берётся МЕДИАНА заходов
 * и печатается разброс; результат чтения уходит в volatile, иначе оптимизатор снимет
 * весь вызов. Время — ПРОЦЕССОРНОЕ ПОТОКОВОЕ: чужая нагрузка на машине выпадает.
 *
 * Сборка (цель в Makefile — общий файл, поэтому руками):
 *   cc -O2 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *      tests/hb_fence_cost_bench.c libhyperbridge.a -o tests/hb_fence_cost_bench
 * Пуск: tests/hb_fence_cost_bench [повторов] [заходов]
 */
#include "hb_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BAZA   0x00400000u
#define RAZMER 0x00010000u

static volatile unsigned long long ponyatno;

static double sekundy(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static int sravnit(const void* a, const void* b) {
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

int main(int argc, char** argv) {
    long long n = (argc > 1) ? atoll(argv[1]) : 2000000;
    int zahodov = (argc > 2) ? atoi(argv[2]) : 7;
    hb_memory_t* mem;
    double* chteniya;
    double* zapisi;
    int z;

    hb_memory_init_environment();
    mem = hb_memory_create(0);
    if (!mem) { fprintf(stderr, "hb_memory_create отказал\n"); return 1; }
    if (hb_memory_guest32_reserve(mem) != HB_OK) {
        fprintf(stderr, "guest32 окно не выделено — путь ограждения НЕДОСТУПЕН, "
                        "число было бы измерением другого кода\n");
        return 2;
    }
    if (hb_memory_guest32_map(mem, BAZA, RAZMER, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        fprintf(stderr, "guest32_map отказал\n");
        return 3;
    }

    chteniya = calloc((size_t)zahodov, sizeof(double));
    zapisi   = calloc((size_t)zahodov, sizeof(double));
    if (!chteniya || !zapisi) return 4;

    printf("ограждённое копирование: повторов=%lld заходов=%d, время процессорное потоковое\n",
           n, zahodov);

    for (z = 0; z < zahodov; z++) {
        double t0, t1, pusto;
        long long i;
        uint32_t v = 0;

        t0 = sekundy();
        for (i = 0; i < n; i++) ponyatno += (unsigned long long)i;
        t1 = sekundy();
        pusto = t1 - t0;

        t0 = sekundy();
        for (i = 0; i < n; i++) {
            hb_memory_read(mem, BAZA + (uint32_t)((i * 4) & 0xfffc), &v, 4);
            ponyatno += v;
        }
        t1 = sekundy();
        chteniya[z] = (t1 - t0 - pusto) / (double)n * 1e9;

        t0 = sekundy();
        for (i = 0; i < n; i++) {
            v = (uint32_t)i;
            hb_memory_write(mem, BAZA + (uint32_t)((i * 4) & 0xfffc), &v, 4);
            ponyatno += (unsigned long long)i;
        }
        t1 = sekundy();
        zapisi[z] = (t1 - t0 - pusto) / (double)n * 1e9;
    }

    qsort(chteniya, (size_t)zahodov, sizeof(double), sravnit);
    qsort(zapisi, (size_t)zahodov, sizeof(double), sravnit);
    printf("  чтение 4 Б : медиана %8.2f нс   разброс %.1f %%   (мин %.2f, макс %.2f)\n",
           chteniya[zahodov / 2],
           chteniya[zahodov / 2] > 0
               ? (chteniya[zahodov - 1] - chteniya[0]) / chteniya[zahodov / 2] * 100.0 : 0.0,
           chteniya[0], chteniya[zahodov - 1]);
    printf("  запись 4 Б : медиана %8.2f нс   разброс %.1f %%   (мин %.2f, макс %.2f)\n",
           zapisi[zahodov / 2],
           zapisi[zahodov / 2] > 0
               ? (zapisi[zahodov - 1] - zapisi[0]) / zapisi[zahodov / 2] * 100.0 : 0.0,
           zapisi[0], zapisi[zahodov - 1]);
    return 0;
}
