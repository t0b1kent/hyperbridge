/* hb_probe_kill_probe.c — подопытный для теста «перепись переживает УБИЙСТВО».
 * Лейн ОСНАСТКА, 07.09.2026. Гоняется из scripts/тест-перепись-при-убийстве.sh.
 *
 * ОДИН двоичный на ОБЕ руки — правило проекта об A/B (иначе сравнивались бы разные
 * сборки, и разница могла бы быть чем угодно). Рука выбирается аргументом:
 *
 *   pulse   — перепись едет на ПУЛЬСЕ (новое поведение)
 *   atexit  — только atexit (поведение ДО правки; пульс не зовём вовсе)
 *
 * Дальше программа печатает «ГОТОВ» и виснет НАВСЕГДА. Убивает её тест, сигналом
 * KILL — ровно так, как timeout и mr-run снимают прогоны. atexit при этом не
 * наступает, и в этом весь смысл замера.
 */

#include "hb_probe.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

HB_PROBE_DEFINE(pr_ubijstvo, "hb-probe-kill-podopytnyj",
                "искусственный прибор: считает обороты цикла до убийства", NULL, 0)

int main(int argc, char **argv)
{
    int s_pulsom = (argc > 1 && strcmp(argv[1], "pulse") == 0);
    unsigned long i;

    /* Работа прибора: наблюдение идёт, явление случается изредка. После убийства
     * читатель обязан узнать из журнала ОБА факта, а не гадать по молчанию. */
    for (i = 0; i < 40; i++) {
        HB_PROBE_LOOKED(&pr_ubijstvo);
        if (i % 10 == 0) HB_PROBE_HIT(&pr_ubijstvo);
        if (s_pulsom) hb_probe_census_pulse(stderr, "period");
    }

    fprintf(stderr, "ГОТОВ\n");
    fflush(stderr);
    for (;;) sleep(1);       /* ждём KILL: штатного выхода не будет */
    return 0;
}
