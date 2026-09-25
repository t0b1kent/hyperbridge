/* hb_probe_test.c — приёмка прибора, который не может выдать неотличимый ноль.
 *
 * ЗАЧЕМ ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ. Зелёный тест сам по себе не значит ничего: он
 * может соглашаться с чем угодно, что делает код. Поэтому здесь ДВЕ руки:
 *
 *   рука A (положительная)  — настоящий классификатор обязан пройти всю батарею;
 *   рука B (отрицательная)  — та же батарея прогоняется по ПОРЧАМ классификатора,
 *                             каждая из которых воспроизводит настоящий класс лжи
 *                             из нашей истории. Батарея обязана ПОКРАСНЕТЬ на
 *                             КАЖДОЙ порче. Не покраснела хоть на одной — значит
 *                             она слепа к этому классу, и приёмка отказывает.
 *
 * Без руки B этот файл был бы тринадцатым врущим прибором.
 */

#include "hb_probe.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int provaleno = 0;
static int vsego_proverok = 0;

static void proverit(int uslovie, const char *chto)
{
    vsego_proverok++;
    if (!uslovie) {
        provaleno++;
        printf("  PROVAL: %s\n", chto);
    }
}

/* ── Батарея: та же для настоящего классификатора и для порч ─────────────────
 * Возвращает число НЕСОВПАДЕНИЙ. Ноль = классификатор различает все случаи. */
struct sluchaj {
    const char *opisanie;
    unsigned long long looked, hits, printed;
    hb_probe_state_t zhdyom;
};

static const struct sluchaj BATAREYA[] = {
    { "не смотрел",                        0,  0, 0, HB_PROBE_NOT_OBSERVED },
    { "смотрел, явления нет",             100,  0, 0, HB_PROBE_NO_EVENTS },
    { "потолок обрезал",                  100, 50, 8, HB_PROBE_EVENTS_TRUNCATED },
    { "явление есть, напечатано всё",     100,  7, 7, HB_PROBE_EVENTS },
    /* ★ 06.09.2026 — счётчик без поштучной печати. Отличать его от усечения
     * ОБЯЗАТЕЛЬНО: у усечения число НИЖНЯЯ ГРАНИЦА, у счётчика ТОЧНОЕ. Слияние
     * этих двух и было шестнадцатым враньём — оно родилось прямо в переводе. */
    { "считалось, печати нет",            100,  7, 0, HB_PROBE_EVENTS_COUNTED },
    { "hits > looked: учёт в точке решения", 0,  5, 0, HB_PROBE_INCONSISTENT },
    { "printed > hits",                    10,  1, 4, HB_PROBE_INCONSISTENT },
    { "одно наблюдение, одно явление",      1,  1, 1, HB_PROBE_EVENTS },
    { "одно наблюдение, явления нет",       1,  0, 0, HB_PROBE_NO_EVENTS },
};
#define N_BATAREYA (sizeof(BATAREYA) / sizeof(BATAREYA[0]))

typedef hb_probe_state_t (*klassifikator_t)(const hb_probe_t *);

static int progon_batarei(klassifikator_t k)
{
    unsigned i;
    int nesovpalo = 0;
    for (i = 0; i < N_BATAREYA; i++) {
        hb_probe_t p;
        memset(&p, 0, sizeof(p));
        p.name = "batareya";
        p.population = "искусственный вход батареи";
        p.looked = BATAREYA[i].looked;
        p.hits = BATAREYA[i].hits;
        p.printed = BATAREYA[i].printed;
        if (k(&p) != BATAREYA[i].zhdyom) nesovpalo++;
    }
    return nesovpalo;
}

/* ── ПОРЧИ. Каждая — настоящий класс лжи из нашей истории ─────────────────── */

/* Порча 1: два нуля слиты в один. РОВНО тот дефект, из-за которого двенадцать
 * приборов за двое суток выдали ноль, значивший «я не смотрел». */
static hb_probe_state_t porcha_slit_nuli(const hb_probe_t *p)
{
    if (p->hits > p->looked || p->printed > p->hits) return HB_PROBE_INCONSISTENT;
    if (p->hits == 0) return HB_PROBE_NO_EVENTS;          /* ← «не смотрел» исчез */
    if (p->printed < p->hits) return HB_PROBE_EVENTS_TRUNCATED;
    return HB_PROBE_EVENTS;
}

/* Порча 2: потолок усекает молча — «первые 8» подаются как полный счёт. */
static hb_probe_state_t porcha_potolok_molcha(const hb_probe_t *p)
{
    if (p->hits > p->looked || p->printed > p->hits) return HB_PROBE_INCONSISTENT;
    if (p->looked == 0) return HB_PROBE_NOT_OBSERVED;
    if (p->hits == 0) return HB_PROBE_NO_EVENTS;
    return HB_PROBE_EVENTS;                                /* ← усечение скрыто */
}

/* Порча 3: не ловит невозможное состояние — учёт в точке решения проходит мимо. */
static hb_probe_state_t porcha_ne_lovit_nesootvetstvie(const hb_probe_t *p)
{
    if (p->looked == 0 && p->hits == 0) return HB_PROBE_NOT_OBSERVED;
    if (p->hits == 0) return HB_PROBE_NO_EVENTS;
    if (p->printed < p->hits) return HB_PROBE_EVENTS_TRUNCATED;
    return HB_PROBE_EVENTS;
}

/* Порча 4: прибор, который НЕ УМЕЕТ КРАСНЕТЬ. Всегда зелено. */
static hb_probe_state_t porcha_vsegda_zelyono(const hb_probe_t *p)
{
    (void)p;
    return HB_PROBE_NO_EVENTS;
}

/* Порча 5: «не смотрел» выдаётся всегда — обратная крайность, тоже слепота. */
static hb_probe_state_t porcha_vsegda_ne_smotrel(const hb_probe_t *p)
{
    (void)p;
    return HB_PROBE_NOT_OBSERVED;
}

/* Порча 6: ПРЕЖНЯЯ редакция классификатора — счётчик без печати метится
 * «нижней границей», хотя его число ТОЧНОЕ. Это не выдуманный случай: ровно
 * так вёл себя классификатор до 06.09.2026, и первые же два прибора живости
 * флагов получили от него EVENTS-TRUNCATED при точных hits. Порча оставлена
 * здесь, чтобы возврат к прежней редакции КРАСНЕЛ, а не проходил молча. */
static hb_probe_state_t porcha_schetchik_kak_usechenie(const hb_probe_t *p)
{
    if (p->hits > p->looked || p->printed > p->hits) return HB_PROBE_INCONSISTENT;
    if (p->looked == 0) return HB_PROBE_NOT_OBSERVED;
    if (p->hits == 0) return HB_PROBE_NO_EVENTS;
    if (p->printed < p->hits) return HB_PROBE_EVENTS_TRUNCATED;  /* ← счётчик слит с усечением */
    return HB_PROBE_EVENTS;
}

struct porcha { const char *imya; klassifikator_t k; };
static const struct porcha PORCHI[] = {
    { "счётчик без печати выдан за усечение",   porcha_schetchik_kak_usechenie },
    { "слиты два нуля (не смотрел == не было)", porcha_slit_nuli },
    { "потолок усекает молча",                  porcha_potolok_molcha },
    { "не ловит hits > looked",                 porcha_ne_lovit_nesootvetstvie },
    { "всегда зелено (не умеет краснеть)",      porcha_vsegda_zelyono },
    { "всегда «не смотрел»",                    porcha_vsegda_ne_smotrel },
};
#define N_PORCHI (sizeof(PORCHI) / sizeof(PORCHI[0]))

/* ── Настоящие приборы для проверки поведения, а не только классификатора ──── */

HB_PROBE_DEFINE(pr_molchun, "hb-probe-test-molchun",
                "прибор, до которого управление не доходит НИ РАЗУ — обязан быть виден в переписи",
                NULL, 0);

HB_PROBE_DEFINE(pr_smotrel_pusto, "hb-probe-test-pusto",
                "наблюдение было, явлений нет — честный ноль, отличимый от «не смотрел»",
                NULL, 0);

HB_PROBE_DEFINE(pr_potolok, "hb-probe-test-potolok",
                "явлений больше потолка печати — число обязано быть объявлено нижней границей",
                "MACRUNNER_HB_PROBE_TEST", 3);

int main(void)
{
    unsigned i;
    int nesovpalo;

    printf("=== hb_probe: приёмка прибора, не способного выдать неотличимый ноль ===\n");

    /* ── РУКА A: настоящий классификатор обязан пройти батарею ─────────────── */
    printf("\nрука A (положительная): настоящий классификатор\n");
    nesovpalo = progon_batarei(hb_probe_state);
    proverit(nesovpalo == 0, "настоящий классификатор обязан различать все случаи батареи");
    printf("  батарея: %u случаев, несовпадений %d\n", (unsigned)N_BATAREYA, nesovpalo);

    proverit(hb_probe_selftest(stdout) == 0, "встроенная самопроверка обязана проходить");

    /* ── РУКА B: батарея обязана ПОКРАСНЕТЬ на КАЖДОЙ порче ────────────────── */
    printf("\nрука B (ОТРИЦАТЕЛЬНАЯ): батарея против порч классификатора\n");
    {
        unsigned pokrasnela = 0;
        for (i = 0; i < N_PORCHI; i++) {
            int n = progon_batarei(PORCHI[i].k);
            printf("  порча «%s»: несовпадений %d %s\n",
                   PORCHI[i].imya, n, n > 0 ? "-> ПОКРАСНЕЛА" : "-> СЛЕПА");
            if (n > 0) pokrasnela++;
        }
        proverit(pokrasnela == N_PORCHI,
                 "батарея обязана краснеть на ВСЕХ порчах — иначе она слепа к классу");
        printf("  покраснела на %u порчах из %u\n", pokrasnela, (unsigned)N_PORCHI);
    }

    /* ── Поведение настоящих приборов ─────────────────────────────────────── */
    printf("\nповедение настоящих приборов\n");

    /* pr_molchun не трогаем вовсе: он обязан остаться NOT-OBSERVED. */
    proverit(hb_probe_state(&pr_molchun) == HB_PROBE_NOT_OBSERVED,
             "нетронутый прибор = NOT-OBSERVED, а не «явления нет»");

    /* Смотрели 5 раз, явлений нет. Ноль ЧЕСТНЫЙ и отличимый. */
    for (i = 0; i < 5; i++) HB_PROBE_LOOKED(&pr_smotrel_pusto);
    proverit(hb_probe_state(&pr_smotrel_pusto) == HB_PROBE_NO_EVENTS,
             "наблюдали, явлений нет = NO-EVENTS, а не NOT-OBSERVED");
    proverit(pr_smotrel_pusto.hits == 0, "hits обязан остаться нулём");
    proverit(pr_smotrel_pusto.looked == 5, "looked обязан быть 5");

    /* Потолок 3, явлений 10: печать обрезана, счёт полный, состояние объявлено. */
    for (i = 0; i < 10; i++) {
        HB_PROBE_LOOKED(&pr_potolok);
        HB_PROBE_SAY(&pr_potolok, "sobytie=%u\n", i);
    }
    proverit(pr_potolok.hits == 10, "hits считает ВСЕ явления, потолок его не трогает");
    proverit(pr_potolok.printed == 3, "печать обязана быть ограничена потолком 3");
    proverit(hb_probe_state(&pr_potolok) == HB_PROBE_EVENTS_TRUNCATED,
             "усечение обязано быть ОБЪЯВЛЕНО, а не молчаливо");

    /* ── Перепись обязана показывать МОЛЧАЩИЙ прибор ───────────────────────── */
    printf("\nперепись\n");
    {
        char *buf = NULL;
        size_t len = 0;
        FILE *mem = open_memstream(&buf, &len);
        proverit(mem != NULL, "open_memstream обязан открыться");
        if (mem) {
            hb_probe_census(mem);
            fflush(mem);
            fclose(mem);
            proverit(buf && strstr(buf, "hb-probe-test-molchun") != NULL,
                     "МОЛЧАЩИЙ прибор обязан быть в переписи — иначе он невидим");
            proverit(buf && strstr(buf, "state=NOT-OBSERVED") != NULL,
                     "перепись обязана печатать состояние NOT-OBSERVED");
            proverit(buf && strstr(buf, "state=NO-EVENTS") != NULL,
                     "перепись обязана печатать состояние NO-EVENTS");
            proverit(buf && strstr(buf, "state=EVENTS-TRUNCATED") != NULL,
                     "перепись обязана печатать состояние EVENTS-TRUNCATED");
            proverit(buf && strstr(buf, "selftest=OK") != NULL,
                     "перепись обязана объявлять итог самопроверки");
            /* Популяция печатается РЯДОМ с числом, а не в чужом отчёте. */
            proverit(buf && strstr(buf, "counts=\"") != NULL,
                     "перепись обязана печатать популяцию рядом с числом");
            /* Ответ загрузчика: где прибор ЖИВЁТ. Соврать этим нельзя. */
            proverit(buf && strstr(buf, "where=") != NULL,
                     "перепись обязана печатать образ, из которого прибор говорит");
            proverit(buf && strstr(buf, "where=?-dladdr") == NULL,
                     "dladdr обязан ответить настоящим путём образа");
            if (buf) {
                const char *w = strstr(buf, "obraz=");
                if (w) {
                    const char *e = strchr(w, ' ');
                    printf("  образ по ответу загрузчика: %.*s\n",
                           e ? (int)(e - w) : 20, w);
                }
            }
            free(buf);
        }
    }

    /* ── МЕТКА ОБЯЗАНА БЫТЬ СПЛОШНЫМ ЛИТЕРАЛОМ ────────────────────────────────
     * Класс лжи, найденный 06.09 при переводе macrunner-hb-write-deny: печать
     * префикса как `fprintf(stderr, "macrunner-%s: ", p->name)` разрывает метку
     * на ДВА литерала, и сплошной строки `macrunner-hb-write-deny:` в двоичном
     * не остаётся. Всякая проверка доставки (`grep -a` по .so) даёт НОЛЬ при
     * полностью исправном приборе — ложный ноль, созданный самим переводом.
     * Поймал привратник раскладки; здесь стоит сторож, чтобы не вернулось. */
    printf("\nметка прибора — сплошной литерал (проверка доставки не ослепнет)\n");
    {
        char ozhid[256];
        snprintf(ozhid, sizeof(ozhid), "macrunner-%s: ", pr_potolok.name);
        proverit(pr_potolok.metka != NULL,
                 "прибор, объявленный макросом, обязан нести .metka");
        proverit(pr_potolok.metka && strcmp(pr_potolok.metka, ozhid) == 0,
                 "метка обязана быть ровно \"macrunner-<имя>: \"");
        /* Отрицательный контроль САМОЙ этой проверки: она должна уметь краснеть.
         * Заведомо неверная метка обязана НЕ совпасть — иначе проверка согласна
         * с чем угодно и не доказывает ничего. */
        proverit(strcmp("macrunner-ne-to: ", ozhid) != 0,
                 "сверка меток обязана различать разные метки");
        proverit(pr_molchun.metka && strstr(pr_molchun.metka, "hb-probe-test-molchun"),
                 "метка молчащего прибора тоже собрана и лежит целиком");
    }

    /* ── ★★★ ПУЛЬС ПЕРЕПИСИ: она обязана доехать до журнала при УБИЙСТВЕ ──────
     * Лейн ОСНАСТКА, 07.09.2026. Перепись стояла ТОЛЬКО на atexit, а прогоны
     * снимаются убийством — замер лейна ПОВТОР-2: строк `macrunner-probe` в 300
     * журналах run.log НОЛЬ при строках движка в 40 из 40. Разбор — в hb_probe.h
     * у объявления hb_probe_census_pulse. Отрицательный контроль «приборов нет
     * вовсе» живёт ОТДЕЛЬНЫМ двоичным (tests/hb_probe_zero_test.c): здесь приборы
     * уже зарегистрированы конструкторами, и тот случай отсюда недостижим. */
    printf("\nпульс переписи: доезжает до журнала без atexit\n");
    {
        char *b1 = NULL, *b2 = NULL, *b3 = NULL;
        size_t l1 = 0, l2 = 0, l3 = 0;
        FILE *m;
        unsigned bylo, stalo, k;

        /* 1. ПУЛЬС ПЕЧАТАЕТ, когда есть что сказать — БЕЗ ВСЯКОГО atexit.
         *    Счётчик двигаем нарочно: выше по файлу перепись уже печаталась явным
         *    вызовом, и пульс поверх неизменившихся чисел промолчал бы — правильно
         *    промолчал (см. проверку 3). Первая редакция этой проверки об этом
         *    забыла и покраснела на исправном механизме: тест не учитывал состояния,
         *    оставленного соседними проверками. */
        HB_PROBE_LOOKED(&pr_smotrel_pusto);
        bylo = hb_probe_census_printed_count();
        m = open_memstream(&b1, &l1);
        if (m) { hb_probe_census_pulse(m, "period"); fflush(m); fclose(m); }
        stalo = hb_probe_census_printed_count();
        proverit(l1 > 0 && stalo == bylo + 1,
                 "пульс ПЕЧАТАЕТ перепись (без всякого atexit)");
        proverit(b1 && strstr(b1, "macrunner-probe-census:") != NULL,
                 "и это настоящая перепись, а не обрывок");

        /* 2. ПОМЕЧЕНА КАК СНИМОК. Спутать снимок с итогом нельзя: это написано
         *    в самой строке, а не подразумевается. */
        proverit(b1 && strstr(b1, "final=0") != NULL,
                 "перепись по пульсу помечена final=0 — это СНИМОК, не итог");
        proverit(b1 && strstr(b1, "why=period") != NULL,
                 "в строке назван повод печати");

        /* 3. НЕ ДУБЛИРУЕТСЯ: ничего не изменилось — второй раз то же не печатаем.
         *    Иначе журнал наполнился бы одинаковыми переписями, и каждая читалась
         *    бы как новое наблюдение. */
        bylo = hb_probe_census_printed_count();
        m = open_memstream(&b2, &l2);
        if (m) {
            for (k = 0; k < 64; k++) hb_probe_census_pulse(m, "period");
            fflush(m); fclose(m);
        }
        proverit(l2 == 0 && hb_probe_census_printed_count() == bylo,
                 "64 пульса без единого изменения не напечатали НИ ОДНОЙ переписи");

        /* 4. ...НО НА СМЕНУ СОСТОЯНИЯ ОТЗЫВАЕТСЯ. Состояние и есть предмет
         *    переписи; молчащий сторож был бы не экономнее, а слепее. */
        HB_PROBE_LOOKED(&pr_molchun);   /* NOT-OBSERVED -> NO-EVENTS */
        bylo = hb_probe_census_printed_count();
        m = open_memstream(&b3, &l3);
        if (m) { hb_probe_census_pulse(m, "period"); fflush(m); fclose(m); }
        proverit(l3 > 0 && hb_probe_census_printed_count() == bylo + 1,
                 "смена состояния прибора ЗАСТАВЛЯЕТ пульс напечатать перепись");
        proverit(b3 && strstr(b3, "hb-probe-test-molchun state=NO-EVENTS") != NULL,
                 "и в ней видно НОВОЕ состояние прибора");

        /* 5. ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ПРОВЕРКИ 3: она обязана уметь краснеть.
         *    Если бы пульс печатал всегда, контроль 3 дал бы l2 > 0. Показываем,
         *    что нулевая длина здесь — не свойство потока, а решение механизма:
         *    тот же поток при изменении данных получил байты (l3 > 0). */
        proverit(l3 > 0 && l2 == 0,
                 "молчание на пульсе 3 — решение механизма, а не немой поток "
                 "(тот же способ печати дал байты на пульсе 4)");

        free(b1); free(b2); free(b3);
    }

    /* ── ПОСЛЕДНИМ: негодный прибор обязан сделать перепись НЕДЕЙСТВИТЕЛЬНОЙ ──
     * Регистрируем прибор с пустой популяцией напрямую (макрос такое не собрал бы).
     * После этого самопроверка ОБЯЗАНА провалиться, а перепись — объявить свои
     * числа нечитаемыми. Проверка стоит последней: она портит общее состояние. */
    printf("\nпоследняя проверка: негодный прибор рушит перепись целиком\n");
    {
        /* Прибор нарочно собран НЕ макросом: у него и популяция пустая, и метки
         * нет. Поле .metka перечислено явно — `-Wmissing-field-initializers`
         * поднят до ошибки намеренно, чтобы добавленное в структуру поле нельзя
         * было молча пропустить в позиционном списке. */
        static hb_probe_t negodnyj = { "negodnyj", "", NULL, __FILE__, __LINE__,
                                       0, 0, 0, 0, NULL, NULL, NULL };
        char *buf = NULL;
        size_t len = 0;
        FILE *mem;
        hb_probe_register(&negodnyj, NULL);
        proverit(hb_probe_selftest(stdout) != 0,
                 "прибор с пустой популяцией обязан валить самопроверку");
        mem = open_memstream(&buf, &len);
        if (mem) {
            hb_probe_census(mem);
            fflush(mem);
            fclose(mem);
            proverit(buf && strstr(buf, "selftest=FAILED") != NULL,
                     "перепись обязана объявить провал самопроверки");
            proverit(buf && strstr(buf, "PEREPIS NEDEJSTVITELNA") != NULL,
                     "числа обязаны быть объявлены нечитаемыми, а не «в основном верными»");
            free(buf);
        }
    }

    printf("\n%d passed, %d failed\n", vsego_proverok - provaleno, provaleno);

    /* Перепись по atexit напечатает selftest=FAILED — ЭТО ЗАДУМАНО: выше нарочно
     * зарегистрирован негодный прибор. Предупреждаем прямо, иначе задуманный отказ
     * прочитают как поломку приёмки (stderr выходит раньше stdout — тем более). */
    fprintf(stderr,
        "hb_probe_test: НИЖЕ/ВЫШЕ перепись по atexit покажет selftest=FAILED — ТАК ЗАДУМАНО:\n"
        "hb_probe_test: последняя проверка нарочно регистрирует негодный прибор, чтобы\n"
        "hb_probe_test: доказать, что перепись объявляет свои числа нечитаемыми. Итог\n"
        "hb_probe_test: приёмки — строка \"%d passed, %d failed\" и код возврата.\n",
        vsego_proverok - provaleno, provaleno);
    return provaleno ? 1 : 0;
}
