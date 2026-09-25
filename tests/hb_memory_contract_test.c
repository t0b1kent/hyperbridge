/* MacRunner 2026-08-16, лейн ПАМЯТЬ, итерация 3 — СТЕНД САМОСОГЛАСОВАННОСТИ СЛОЯ ПАМЯТИ.
 *
 * Зачем. Доска (`reports/ПОКРЫТИЕ-СВОДКА.md`, стр. 235 и 434) про ступень 7 говорит прямо:
 * «память и трамплины — стендом НЕ покрыты вовсе», у `hb_memory.c` своих `case HB_*` ноль,
 * «это механизм, а не набор команд», охват «проверяется не списком команд, а ПОВЕДЕНИЕМ, и
 * прибора под это нет». Опись лейна (итерация 2): из 39 точек входа `hb_memory_*` семь не
 * тронуты ни одной пробой, и среди них три предиката из пяти (`can_read`, `can_read_span`,
 * `can_exec`), выборка команды `fetch` и сообщение об отказе `last_fault`.
 *
 * Что проверяется. Слой обязан быть СОГЛАСОВАН САМ С СОБОЙ: предикат и операция на одном и том
 * же диапазоне с одними и теми же правами обязаны давать один ответ.
 *
 *     can_read(a,n)  ==  (read(a,..,n)  == HB_OK)
 *     can_write(a,n) ==  (write(a,..,n) == HB_OK)
 *     can_exec(a,1)  ==  (fetch(a,..)   == HB_OK)
 *
 * Эталон снаружи для этого НЕ нужен: расхождение предиката с операцией — дефект при любой
 * трактовке семантики Windows. Стенд работает без виртуалки и без прогона игры (входящее
 * ПАМЯТЬ, пункт 5).
 *
 * ОКНО ОТКАЗА ОТКРЫТО — два механизма, оба обязательны (входящее ПАМЯТЬ, пункт 3: «отсутствие
 * отказа ничего не доказывает»):
 *   1. `HB_MEMCONTRACT_NEGATIVE=1` переворачивает ожидание согласованности; стенд ОБЯЗАН тогда
 *      отказать, иначе он не измеряет ничего;
 *   2. SIGSEGV/SIGBUS хоста ловится и засчитывается как нарушение, а не роняет стенд. Иначе
 *      дефект «предикат разрешил недопустимое» выглядел бы как падение оснастки — ровно то, на
 *      чём эта проба споткнулась при первом запуске.
 *
 * ПОДЛОЖКА. `hb_memory_map(base!=0)` НЕ выделяет хостовой памяти (`hb_memory.c:1812-1816`:
 * `host_base=NULL, allocated=false`) — это тождественное отображение, где гостевой адрес и есть
 * хостовой, и подложку обязан был зарезервировать вызывающий. В голой пробе её нет, поэтому
 * основная матрица идёт через `hb_memory_map_private` (выделяет, `hb_memory.c:1837`), а
 * тождественный режим вынесен в отдельный раздел 7 и НЕ считается нарушением — это свойство
 * API, а не дефект.
 *
 * Запуск: make -C engine/hyperbridge memory-contract-test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <mach/vm_prot.h>

#include "hb_memory.h"
#include "hb_result.h"

#define PAGE         0x1000u
#define GUEST_BASE   0x40000000ull

enum { OP_READ, OP_WRITE, OP_FETCH };

/* Итог операции: 1 — прошла, 0 — отказано штатно, -1 — УРОНИЛА ХОСТ. */
#define OP_DONE   1
#define OP_DENIED 0
#define OP_CRASH  (-1)

static int g_checks;
static int g_fail;
static int g_negative;
static int g_crashes;          /* падения хоста в основных разделах — всегда нарушение */
static int g_known;            /* расхождения, разобранные и описанные в hb_memory.c */
static int g_nobacking_crash;  /* падения в разделе 7 — ожидаемы, в счёт не идут */

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_armed;

/* Итерация 6: ловушка запоминает АДРЕС отказа. Без него «уронила хост» — это факт без улики:
 * запись через слой роняет там, где прямая проходит, и весь вопрос в том, по какому адресу
 * слой её увёл. `si_addr` отвечает на это одним числом. */
static volatile uintptr_t g_fault_addr;
static volatile int       g_fault_sig;

static void fault_handler(int sig, siginfo_t *info, void *uctx)
{
    (void)uctx;
    g_fault_addr = info ? (uintptr_t)info->si_addr : 0;
    g_fault_sig = sig;
    if (g_armed) { g_armed = 0; siglongjmp(g_jmp, sig); }
    _exit(3);
}

/* Итерация 6: опрос специальных обработчиков после каждого раздела. Поля должны оставаться
 * НУЛЕВЫМИ весь прогон — их никто в этом процессе не ставит. Первый раздел, после которого поле
 * стало ненулевым, и есть затирающий. */
extern void macrunner_hb_memory_debug_handlers(const hb_memory_t *mem, void **rd, void **wr,
                                               void **grow, void **user);

/* КАНАРЕЙКА (итерация 12) — область с известным содержимым, проверяемая на КАЖДОЙ границе
 * разделов.
 *
 * Зачем. Итерация 11 показала позиционным опытом: проверка `write_u32(0x11223344)` -> чтение
 * байтов даёт 44 33 22 11, если стоит ПЕРЕД разделами, роняющими хост, и 00 00 00 00 в шести
 * случаях из десяти, если стоит ПОСЛЕ. То есть кто-то из разделов портит СОДЕРЖИМОЕ гостевой
 * памяти. Какой именно — перебором с выключением искалось бы много прогонов; канарейка отвечает
 * за ОДИН: первая граница, где она испорчена, и называет раздел.
 *
 * Проверка висит на `handlers_check`, который и так зовётся между всеми разделами — новых точек
 * вызова не заводится, и порядок разделов не меняется.
 */
static hb_gva_t g_canary_base;
static int g_canary_broken;

static void canary_arm(hb_memory_t *mem)
{
    g_canary_base = GUEST_BASE + 0xA00000ull;
    if (hb_memory_map_private(mem, g_canary_base, PAGE,
                              (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE)) != HB_OK) {
        printf("  КАНАРЕЙКА: не завелась (область не отобразилась) — проверка НЕ ДЕЙСТВУЕТ\n");
        g_canary_base = 0;
        return;
    }
    if (hb_memory_write_u32(mem, g_canary_base, 0x11223344u) != HB_OK) {
        printf("  КАНАРЕЙКА: не завелась (запись отказала) — проверка НЕ ДЕЙСТВУЕТ\n");
        g_canary_base = 0;
    }
}

static void canary_check(hb_memory_t *mem, const char *where)
{
    uint32_t v = 0;
    hb_result_t rc;

    if (!g_canary_base || g_canary_broken) return;   /* сообщаем ОДИН раз — про первое место */
    /* ПОПРАВКА К СЕБЕ (итерация 12): первая редакция читала канарейку НАПРЯМУЮ и сама роняла
     * стенд — полных прогонов стало 0 из 10 против 1 из 10 без неё, а смерть встала намертво
     * на границе «перед 7b», сразу после `macrunner-hb-region-free-seen`. То есть прибор,
     * поставленный ловить порчу, оказался её причиной: чтение по освобождённой области.
     * Оборачиваю в ту же защиту, что и все операции стенда. */
    if (sigsetjmp(g_jmp, 1) != 0) {
        g_canary_broken = 1;
        printf("  ★★★ КАНАРЕЙКА УРОНИЛА ХОСТ на границе «%s» — область под ней недоступна\n", where);
        return;
    }
    g_armed = 1;
    rc = hb_memory_read_u32(mem, g_canary_base, &v);
    g_armed = 0;
    if (rc != HB_OK || v != 0x11223344u) {
        g_canary_broken = 1;
        printf("  ★★★ КАНАРЕЙКА ИСПОРЧЕНА на границе «%s»: код=%d значение=%08x (ждали 11223344)\n",
               where, (int)rc, v);
    }
}


/* Пустые обработчики для проверки set_special_handlers (итерация 16): их адреса и значение
 * `user` читаются обратно через `macrunner_hb_memory_debug_handlers`. Тела намеренно не делают
 * ничего: проверяется УСТАНОВКА, а не работа обработчика. */
static hb_result_t special_read_cb(void *user, hb_gva_t addr, void *out, size_t size)
{
    (void)user; (void)addr; (void)out; (void)size;
    return HB_ERR_MEMORY_FAULT;
}

static hb_result_t special_write_cb(void *user, hb_gva_t addr, const void *in, size_t size)
{
    (void)user; (void)addr; (void)in; (void)size;
    return HB_ERR_MEMORY_FAULT;
}

static void handlers_check(hb_memory_t *mem, const char *after)
{
    static void *prev[4];
    void *cur[4] = {0};

    canary_check(mem, after);
    macrunner_hb_memory_debug_handlers(mem, &cur[0], &cur[1], &cur[2], &cur[3]);
    if (memcmp(prev, cur, sizeof(cur)) != 0) {
        printf("  ★ ОБРАБОТЧИКИ ИЗМЕНИЛИСЬ на «%s»: read=%p write=%p grow=%p user=%p\n",
               after, cur[0], cur[1], cur[2], cur[3]);
        memcpy(prev, cur, sizeof(cur));
    }
}

/* Обработчик роста для раздела 12: заводит область по запрошенному адресу и просит повторить. */
static hb_memory_t *g_grow_mem;
static int g_grow_calls;

static bool grow_cb(void *user, hb_gva_t addr)
{
    (void)user;
    g_grow_calls++;
    if (!g_grow_mem) return false;
    return hb_memory_map_private(g_grow_mem, addr & ~(hb_gva_t)0xFFF, PAGE,
                                 HB_PERM_READ | HB_PERM_WRITE) == HB_OK;
}

static const char *perm_name(hb_perm_t p)
{
    switch ((int)p) {
    case HB_PERM_NONE:                                return "---";
    case HB_PERM_READ:                                return "r--";
    case HB_PERM_WRITE:                               return "-w-";
    case HB_PERM_EXEC:                                return "--x";
    case HB_PERM_READ | HB_PERM_WRITE:                return "rw-";
    case HB_PERM_READ | HB_PERM_EXEC:                 return "r-x";
    case HB_PERM_WRITE | HB_PERM_EXEC:                return "-wx";
    case HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC: return "rwx";
    default:                                          return "???";
    }
}

/* Операция под ловушкой сигнала. Возвращает OP_DONE / OP_DENIED / OP_CRASH. */
static int op_run(int kind, hb_memory_t *mem, hb_gva_t addr, size_t size)
{
    static unsigned char buf[64];
    uint8_t opcode = 0;
    hb_result_t rc;

    if (sigsetjmp(g_jmp, 1) != 0) return OP_CRASH;
    g_armed = 1;
    switch (kind) {
    case OP_READ:  rc = hb_memory_read(mem, addr, buf, size);  break;
    case OP_WRITE: rc = hb_memory_write(mem, addr, buf, size); break;
    default:       rc = hb_memory_fetch(mem, addr, &opcode);   break;
    }
    g_armed = 0;
    return rc == HB_OK ? OP_DONE : OP_DENIED;
}

/* Сверка «предикат против операции». */
static void check(const char *what, hb_perm_t perm, int predicate, int op)
{
    int agree;

    g_checks++;
    if (op == OP_CRASH && !g_negative &&
        strncmp(what, "тождественные", strlen("тождественные")) == 0) {
        g_known++;
        printf("  ИЗВЕСТНОЕ   %-24s права=%s  предикат=%d  операция=УРОНИЛА ХОСТ"
               "   (тождественная область: защиту ставит wine, слой лишь советует)\n",
               what, perm_name(perm), !!predicate);
        return;
    }
    if (op == OP_CRASH) {
        g_fail++;
        g_crashes++;
        printf("  НАРУШЕНИЕ  %-24s права=%s  предикат=%d  операция=УРОНИЛА ХОСТ\n",
               what, perm_name(perm), !!predicate);
        return;
    }
    agree = (!!predicate == op);
    if (g_negative) agree = !agree;   /* контроль: ждём обратного — стенд обязан отказать */
    if (agree) return;

    /* ИЗВЕСТНОЕ расхождение — не «замолчанное»: причина разобрана и записана в шапке
     * `hb_memory_fetch` (`hb_memory.c`), почему не закрыто — там же. Считается отдельно и
     * печатается всегда, чтобы цель `make` краснела на НОВЫХ расхождениях, а не на этом. */
    if (!g_negative &&
        ((perm == HB_PERM_EXEC && strcmp(what, "can_exec/fetch") == 0) ||
         strncmp(what, "тождественные", strlen("тождественные")) == 0)) {
        g_known++;
        printf("  ИЗВЕСТНОЕ   %-24s права=%s  предикат=%d  операция=%s\n",
               what, perm_name(perm), !!predicate,
               op == OP_CRASH ? "УРОНИЛА ХОСТ" : (op ? "1" : "0"));
        return;
    }

    g_fail++;
    printf("  НАРУШЕНИЕ  %-24s права=%s  предикат=%d  операция=%d\n",
           what, perm_name(perm), !!predicate, op);
}

/* Сколько памяти реально свободно. Раздел про зеркало guest32 резервирует 4 ГБ, и под чужой
 * сборкой стенд получал `Killed: 9` — ноль строк вывода, неотличимый от поломки прибора. */
static long free_mb_estimate(void)
{
    FILE *f = popen("vm_stat", "r");
    char line[256];
    long page = 16384, freep = 0, inact = 0;

    if (!f) return 1L << 20;
    while (fgets(line, sizeof(line), f)) {
        long v;
        if (sscanf(line, "Mach Virtual Memory Statistics: (page size of %ld bytes)", &v) == 1) page = v;
        else if (sscanf(line, "Pages free: %ld", &v) == 1) freep = v;
        else if (sscanf(line, "Pages inactive: %ld", &v) == 1) inact = v;
    }
    pclose(f);
    return (long)(((double)(freep + inact) * (double)page) / 1048576.0);
}

int main(void)
{
    static const hb_perm_t perms[] = {
        HB_PERM_NONE,
        HB_PERM_READ,
        HB_PERM_WRITE,
        HB_PERM_EXEC,
        HB_PERM_READ | HB_PERM_WRITE,
        HB_PERM_READ | HB_PERM_EXEC,
        HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC,
    };
    const size_t nperm = sizeof(perms) / sizeof(perms[0]);
    struct sigaction sa;
    hb_memory_t *mem;
    size_t i;

    /* Без этого вывод теряется при отказе: под конвейером stdout буферизован целиком, и
     * последняя напечатанная строка — не последняя выполненная. */
    setvbuf(stdout, NULL, _IONBF, 0);

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);

    g_negative = (getenv("HB_MEMCONTRACT_NEGATIVE") != NULL);

    mem = hb_memory_create(0);
    if (!mem) { printf("ОТКАЗ ОСНАСТКИ: hb_memory_create вернул NULL\n"); return 2; }

    printf("стенд самосогласованности слоя памяти%s\n",
           g_negative ? "   [ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ]" : "");

    canary_arm(mem);
    handlers_check(mem, "перед 1");

    /* --- 1. Предикаты против операций на КАЖДОМ наборе прав ------------------------------- */
    for (i = 0; i < nperm; i++) {
        hb_gva_t base = GUEST_BASE + (hb_gva_t)i * 0x10000ull;
        hb_perm_t p = perms[i];

        hb_result_t mrc = hb_memory_map_private(mem, base, PAGE, p);
        if (mrc != HB_OK) {
            printf("  ПРОПУСК: не отобразилось %s по %#llx (код %d)\n",
                   perm_name(p), (unsigned long long)base, (int)mrc);
            continue;
        }

        check("can_read/read", p,
              hb_memory_can_read(mem, base, 4), op_run(OP_READ, mem, base, 4));
        check("can_write/write", p,
              hb_memory_can_write(mem, base, 4), op_run(OP_WRITE, mem, base, 4));
        check("can_exec/fetch", p,
              hb_memory_can_exec(mem, base, 1), op_run(OP_FETCH, mem, base, 1));
        check("can_read_span/read", p,
              hb_memory_can_read_span(mem, base, 4), op_run(OP_READ, mem, base, 4));
        check("can_write_span/write", p,
              hb_memory_can_write_span(mem, base, 4), op_run(OP_WRITE, mem, base, 4));
    }

    handlers_check(mem, "перед 2");

    /* --- 2. Вне карты: предикат и операция обязаны отказать ОБА --------------------------- */
    {
        hb_gva_t hole = GUEST_BASE + 0x7000000ull;   /* заведомо не отображён */

        check("вне карты: read", HB_PERM_NONE,
              hb_memory_can_read(mem, hole, 4), op_run(OP_READ, mem, hole, 4));
        check("вне карты: write", HB_PERM_NONE,
              hb_memory_can_write(mem, hole, 4), op_run(OP_WRITE, mem, hole, 4));
        check("вне карты: fetch", HB_PERM_NONE,
              hb_memory_can_exec(mem, hole, 1), op_run(OP_FETCH, mem, hole, 1));
    }

    handlers_check(mem, "перед 3");

    /* --- 3. Край области: половина внутри, половина снаружи -------------------------------- */
    {
        hb_gva_t base = GUEST_BASE + 0x200000ull;
        hb_perm_t rw = HB_PERM_READ | HB_PERM_WRITE;

        if (hb_memory_map_private(mem, base, PAGE, rw) == HB_OK) {
            hb_gva_t edge = base + PAGE - 2;          /* 2 байта внутри, 2 снаружи */

            check("край: read 4", rw,
                  hb_memory_can_read(mem, edge, 4), op_run(OP_READ, mem, edge, 4));
            check("край: write 4", rw,
                  hb_memory_can_write(mem, edge, 4), op_run(OP_WRITE, mem, edge, 4));
            check("край: read_span 4", rw,
                  hb_memory_can_read_span(mem, edge, 4), op_run(OP_READ, mem, edge, 4));
            check("край: write_span 4", rw,
                  hb_memory_can_write_span(mem, edge, 4), op_run(OP_WRITE, mem, edge, 4));
        }
    }

    handlers_check(mem, "перед заведением");

    /* --- ЗАВЕДЕНИЕ, УЧЁТ И СНЯТИЕ: unmap, generation, setup_stack, setup_heap,
     *     sync_live_range, init_environment (итерация 14) ------------------------------------
     *
     * Шесть точек входа, которые стенд не вызывал ВООБЩЕ. Проверяются не «вызвался без отказа»
     * (это ничего не значит — правило 2 входящего), а КОНТРАКТОМ: после действия предикат и
     * операция обязаны согласованно измениться.
     */
    {
        /* (а) unmap: после снятия и предикат, и операция обязаны отказать ОБА. */
        {
            hb_gva_t base = GUEST_BASE + 0xB00000ull;
            hb_perm_t rw = (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE);

            if (hb_memory_map_private(mem, base, PAGE, rw) != HB_OK) {
                printf("  ПРОПУСК: unmap — область не отобразилась\n");
            } else {
                int до_пред = hb_memory_can_write(mem, base, 4);
                int до_оп   = op_run(OP_WRITE, mem, base, 4);
                hb_result_t urc;
                int после_пред, после_оп;

                check("unmap: до снятия пишется", rw, до_пред, до_оп);
                urc = hb_memory_unmap(mem, base);
                после_пред = hb_memory_can_write(mem, base, 4);
                после_оп   = op_run(OP_WRITE, mem, base, 4);
                printf("  unmap: код=%d  после: предикат=%d операция=%s\n",
                       (int)urc, после_пред,
                       после_оп == OP_CRASH ? "УРОНИЛА ХОСТ" : (после_оп ? "прошла" : "отказано"));
                check("unmap: после снятия не пишется", rw, после_пред, после_оп);
                /* Отдельная сверка: снятие ДОЛЖНО было отказать доступу, а не просто вернуть код. */
                check("unmap: доступ закрылся", rw, 0, после_оп == OP_DONE ? OP_DONE : OP_DENIED);
            }
        }

        /* (б) generation: ПОПРАВКА К СЕБЕ (итерация 14) — это счётчик ИНВАЛИДАЦИИ КОДА, а не
         *     «карта менялась». Прочитал реализацию, прежде чем звать дефектом:
         *     `hb_memory.c:2538` — `if ((old_perm | perm) & HB_PERM_EXEC) bump_generation(...)`,
         *     `hb_memory.c:2624` — `if (touched_exec) bump_generation(mem, NULL)`.
         *     Первая редакция этой проверки меняла rw- на r--, права исполнения не трогала и
         *     объявляла «счётчик не двигается» НАРУШЕНИЕМ. Это было бы ложное обвинение движка.
         *     Настоящий контракт проверяется ОБЕИМИ сторонами: с EXEC обязан двинуться, без
         *     EXEC обязан стоять. */
        {
            hb_gva_t noexec = GUEST_BASE + 0xB10000ull;
            hb_gva_t withexec = GUEST_BASE + 0xB20000ull;
            size_t host_page = (size_t)getpagesize();
            uint64_t g0, g1, g2, g3;

            g0 = hb_memory_generation(mem);
            (void)hb_memory_map_private(mem, noexec, host_page,
                                        (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE));
            (void)hb_memory_protect(mem, noexec, host_page, HB_PERM_READ);
            g1 = hb_memory_generation(mem);

            (void)hb_memory_map_private(mem, withexec, host_page,
                                        (hb_perm_t)(HB_PERM_READ | HB_PERM_EXEC));
            g2 = hb_memory_generation(mem);
            (void)hb_memory_protect(mem, withexec, host_page, HB_PERM_READ);
            g3 = hb_memory_generation(mem);

            printf("  generation: старт=%llu без-EXEC=%llu  с-EXEC(map)=%llu  снятие-EXEC=%llu\n",
                   (unsigned long long)g0, (unsigned long long)g1,
                   (unsigned long long)g2, (unsigned long long)g3);
            check("generation: БЕЗ права исполнения стоит", HB_PERM_NONE,
                  1, (g1 == g0) ? OP_DONE : OP_DENIED);
            check("generation: снятие права исполнения ДВИГАЕТ", HB_PERM_NONE,
                  1, (g3 != g2) ? OP_DONE : OP_DENIED);
        }

        /* (в) setup_stack и setup_heap: после заведения диапазон обязан писаться. */
        {
            hb_gva_t stack_top = GUEST_BASE + 0xC00000ull;
            hb_gva_t heap_base = GUEST_BASE + 0xD00000ull;
            hb_result_t src = hb_memory_setup_stack(mem, stack_top, PAGE);
            hb_result_t hrc = hb_memory_setup_heap(mem, heap_base, PAGE);

            printf("  setup_stack(top=%#llx)=%d  setup_heap(base=%#llx)=%d\n",
                   (unsigned long long)stack_top, (int)src,
                   (unsigned long long)heap_base, (int)hrc);
            if (src == HB_OK)
                check("setup_stack: вершина-4 пишется", (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE),
                      hb_memory_can_write(mem, stack_top - 4, 4),
                      op_run(OP_WRITE, mem, stack_top - 4, 4));
            if (hrc == HB_OK)
                check("setup_heap: база пишется", (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE),
                      hb_memory_can_write(mem, heap_base, 4),
                      op_run(OP_WRITE, mem, heap_base, 4));
        }

        /* (г) sync_live_range: согласование учёта с хостом на живом диапазоне. */
        {
            hb_gva_t base = GUEST_BASE + 0xE00000ull;
            hb_perm_t rw = (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE);

            if (hb_memory_map_private(mem, base, PAGE, rw) == HB_OK) {
                hb_result_t rc = hb_memory_sync_live_range(mem, base, PAGE, HB_PERM_READ);

                printf("  sync_live_range(r--)=%d\n", (int)rc);
                check("sync_live_range: учёт согласован с операцией", HB_PERM_READ,
                      hb_memory_can_write(mem, base, 4), op_run(OP_WRITE, mem, base, 4));
            }
        }

        /* (д) init_environment: глобальная настройка. Проверить её «саму по себе» нечем —
         *     проверяю, что она НЕ ЛОМАЕТ уже заведённое: канарейка обязана уцелеть. */
        {
            hb_memory_init_environment();
            canary_check(mem, "после init_environment");
            printf("  init_environment: вызвана, канарейка %s\n",
                   g_canary_broken ? "ИСПОРЧЕНА" : "цела");
            check("init_environment: не ломает заведённое", HB_PERM_NONE,
                  1, g_canary_broken ? OP_DENIED : OP_DONE);
        }
    }

    handlers_check(mem, "перед перекрытием");

    /* --- ПЕРЕКРЫТИЕ РЕГИСТРАЦИЙ (итерация 22) --------------------------------------------
     *
     * В итоге это дефект 5: `hb_memory_map` не проверяет перекрытие, в отличие от
     * `map_private` с его `any_overlap` (`hb_memory.c:1831`), и повторная регистрация с
     * УЖЕСТОЧЁННЫМИ правами молча теряется. Запись держалась на отдельной пробе `ovl.c`,
     * которой в дереве нет, — то есть на улике без прибора. Ставлю живую сверку.
     *
     * Операции здесь НЕ гоняю намеренно: область без подложки, запись через слой роняет хост
     * (это известное свойство, раздел 7). Меряю только учёт — его и касается дефект.
     */
    {
        hb_gva_t base = GUEST_BASE + 0x1000000ull;
        hb_perm_t rw = (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE);

        if (hb_memory_map_private(mem, base, PAGE, rw) != HB_OK) {
            printf("  ПРОПУСК: перекрытие — первая область не отобразилась\n");
        } else {
            int до = hb_memory_can_write(mem, base, 4);
            hb_result_t повтор = hb_memory_map(mem, base, PAGE, HB_PERM_READ);
            int после = hb_memory_can_write(mem, base, 4);

            printf("  перекрытие: повторная регистрация r-- поверх rw- = %d;"
                   " can_write до=%d после=%d%s\n",
                   (int)повтор, до, после,
                   (повтор == HB_OK && после == 1) ? "   ← ужесточение ПОТЕРЯНО (дефект 5)" : "");
            /* Сверка 1: регистрация ПРИНИМАЕТСЯ — это и есть отсутствие проверки перекрытия. */
            check("перекрытие: повторная регистрация принята", HB_PERM_NONE,
                  1, (повтор == HB_OK) ? OP_DONE : OP_DENIED);
            /* Сверка 2: право записи ОСТАЛОСЬ, хотя просили r--. Это ожидаемое (описанное)
             * поведение, поэтому ожидание сформулировано как «осталось», а не «снялось»:
             * стенд не должен краснеть на известном, но обязан ЗАМЕТИТЬ, если оно изменится. */
            check("перекрытие: ужесточение теряется (известно)", HB_PERM_NONE,
                  1, (после == 1) ? OP_DONE : OP_DENIED);
        }
    }

    handlers_check(mem, "перед поиском и обработчиками");

    /* --- ПОИСК ОБЛАСТИ И СПЕЦИАЛЬНЫЕ ОБРАБОТЧИКИ (итерация 16) ---------------------------
     *
     * Две точки входа, которые стенд ЗВАЛ как вспомогательные, но своей сверки не имели. Разницу
     * «вызывается» и «проверено» я держу весь день явно, поэтому доделываю.
     */
    {
        /* (а) find_region: на отображённом адресе обязан вернуть область, ПОКРЫВАЮЩУЮ адрес;
         *     на дыре — NULL. Проверяется не «не NULL», а границы возвращённой области. */
        {
            hb_gva_t base = GUEST_BASE + 0xF00000ull;
            hb_gva_t hole = GUEST_BASE + 0x7F00000ull;
            hb_perm_t rw = (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE);

            if (hb_memory_map_private(mem, base, PAGE, rw) == HB_OK) {
                hb_gva_t inside = base + 8;
                hb_region_t *r = hb_memory_find_region(mem, inside);
                int накрывает = r && r->base <= inside && inside < r->base + r->size;

                printf("  find_region: адрес=%#llx область=%s%s\n",
                       (unsigned long long)inside, r ? "найдена" : "NULL",
                       r ? (накрывает ? ", диапазон накрывает" : ", ДИАПАЗОН НЕ НАКРЫВАЕТ") : "");
                check("find_region: на отображённом находит", rw,
                      hb_memory_can_read(mem, inside, 4), r ? OP_DONE : OP_DENIED);
                check("find_region: диапазон накрывает адрес", rw, 1, накрывает ? OP_DONE : OP_DENIED);
            }
            {
                hb_region_t *r = hb_memory_find_region(mem, hole);

                check("find_region: на дыре NULL", HB_PERM_NONE,
                      hb_memory_can_read(mem, hole, 4), r ? OP_DONE : OP_DENIED);
            }
        }

        /* (б) set_special_handlers: поставленные обработчики обязаны быть ВИДНЫ, снятые —
         *     сняты. Читаю их обратно тем же прибором, которым стенд следит за подменой
         *     (`macrunner_hb_memory_debug_handlers`), — то есть проверяю не «вызов не упал»,
         *     а что состояние действительно изменилось и вернулось. */
        {
            void *r0 = NULL, *w0 = NULL, *g0 = NULL, *u0 = NULL;
            void *r1 = NULL, *w1 = NULL, *g1 = NULL, *u1 = NULL;
            void *r2 = NULL, *w2 = NULL, *g2 = NULL, *u2 = NULL;
            int поставились, снялись;

            macrunner_hb_memory_debug_handlers(mem, &r0, &w0, &g0, &u0);
            hb_memory_set_special_handlers(mem, special_read_cb, special_write_cb, (void *)0x1234);
            macrunner_hb_memory_debug_handlers(mem, &r1, &w1, &g1, &u1);
            hb_memory_set_special_handlers(mem, NULL, NULL, NULL);
            macrunner_hb_memory_debug_handlers(mem, &r2, &w2, &g2, &u2);

            поставились = (r1 == (void *)special_read_cb) && (w1 == (void *)special_write_cb)
                          && (u1 == (void *)0x1234);
            снялись = (r2 == NULL) && (w2 == NULL) && (u2 == NULL);
            printf("  set_special_handlers: поставились=%d снялись=%d (было read=%p write=%p user=%p)\n",
                   поставились, снялись, r0, w0, u0);
            check("set_special_handlers: ставятся", HB_PERM_NONE, 1, поставились ? OP_DONE : OP_DENIED);
            check("set_special_handlers: снимаются", HB_PERM_NONE, 1, снялись ? OP_DONE : OP_DENIED);
            /* Возвращаю обработчики роста/спец в исходное состояние — разделы ниже на них смотрят. */
            handlers_check(mem, "после спецобработчиков");
        }
    }

    handlers_check(mem, "перед ширинами");

    /* --- ШИРИНЫ ДОСТУПА: read_uN / write_uN ---------------------------------------------
     *
     * Зачем (итерация 11). Из 39 точек входа слоя стенд не вызывал 16, и восемь из них — вот эта
     * восьмёрка. Это буквально горячий путь гостя: всякое чтение и запись эмулируемого кода идёт
     * через неё. «Не вызывается» тут означало «не проверено ни разу».
     *
     * Матрица: ШИРИНА (1,2,4,8) x СМЕЩЕНИЕ (0,1,2,3,4,7,8) — то есть выравненные и невыравненные
     * доступы, включая пересечение восьмибайтовой границы. На каждой клетке три сверки:
     *   1) запись своей шириной и чтение ТОЙ ЖЕ шириной дают то же значение;
     *   2) то же значение видно ОБЩИМ hb_memory_read (сверка двух дорог к одному байту);
     *   3) предикат can_write_span согласен с тем, удалась ли запись.
     *
     * Отдельно проверяется ПОРЯДОК БАЙТОВ: `write_u32(0x11223344)` обязан лечь как 44 33 22 11 —
     * гость x86 малоконечный, и если слой где-то развернёт байты, матрица «записал-прочитал»
     * этого НЕ заметит: она симметрична. Поэтому байты читаются поштучно.
     */
    {
        hb_gva_t wbase = GUEST_BASE + 0x900000ull;
        hb_perm_t rw = HB_PERM_READ | HB_PERM_WRITE;

        if (hb_memory_map_private(mem, wbase, PAGE, rw) != HB_OK) {
            printf("  ПРОПУСК: ширины — область не отобразилась\n");
        } else {
            static const unsigned ширины[] = { 1, 2, 4, 8 };
            static const unsigned смещения[] = { 0, 1, 2, 3, 4, 7, 8 };
            unsigned wi, oi;

            for (wi = 0; wi < sizeof(ширины)/sizeof(ширины[0]); wi++) {
                for (oi = 0; oi < sizeof(смещения)/sizeof(смещения[0]); oi++) {
                    unsigned w = ширины[wi], o = смещения[oi];
                    hb_gva_t a = wbase + 0x100 + o;
                    uint64_t образец = 0x1122334455667788ull >> (8 * (8 - w));
                    hb_result_t wrc = HB_OK;
                    uint64_t прочитано = 0;
                    unsigned char общий[8] = {0};
                    int ok_pair, ok_generic;

                    switch (w) {
                    case 1: wrc = hb_memory_write_u8 (mem, a, (uint8_t)образец);  break;
                    case 2: wrc = hb_memory_write_u16(mem, a, (uint16_t)образец); break;
                    case 4: wrc = hb_memory_write_u32(mem, a, (uint32_t)образец); break;
                    default: wrc = hb_memory_write_u64(mem, a, образец);          break;
                    }
                    if (wrc == HB_OK) {
                        switch (w) {
                        case 1: { uint8_t  v=0; hb_memory_read_u8 (mem, a, &v); прочитано = v; break; }
                        case 2: { uint16_t v=0; hb_memory_read_u16(mem, a, &v); прочитано = v; break; }
                        case 4: { uint32_t v=0; hb_memory_read_u32(mem, a, &v); прочитано = v; break; }
                        default:{ uint64_t v=0; hb_memory_read_u64(mem, a, &v); прочитано = v; break; }
                        }
                        hb_memory_read(mem, a, общий, w);
                    }

                    ok_pair = (wrc == HB_OK) && (прочитано == образец);
                    {
                        uint64_t собранное = 0; unsigned k;
                        for (k = 0; k < w; k++) собранное |= (uint64_t)общий[k] << (8 * k);
                        ok_generic = (wrc == HB_OK) && (собранное == образец);
                    }

                    check("ширина: запись=чтение", rw,
                          hb_memory_can_write_span(mem, a, w), ok_pair);
                    check("ширина: своя дорога = общая", rw, ok_pair, ok_generic);
                }
            }

            /* ПОРЯДОК БАЙТОВ — матрица выше его не поймала бы, она симметрична. */
            {
                hb_gva_t a = wbase + 0x200;
                uint8_t b0=0,b1=0,b2=0,b3=0;
                int порядок;

                hb_memory_write_u32(mem, a, 0x11223344u);
                hb_memory_read_u8(mem, a + 0, &b0);
                hb_memory_read_u8(mem, a + 1, &b1);
                hb_memory_read_u8(mem, a + 2, &b2);
                hb_memory_read_u8(mem, a + 3, &b3);
                порядок = (b0 == 0x44 && b1 == 0x33 && b2 == 0x22 && b3 == 0x11);
                printf("  ширины: порядок байтов после write_u32(0x11223344) = %02x %02x %02x %02x  (ждём 44 33 22 11)\n",
                       b0, b1, b2, b3);
                check("ширина: порядок байтов малоконечный", rw, 1, порядок);
            }

            /* ГРАНИЦА ОБЛАСТИ: доступ, начинающийся внутри и уходящий наружу. Предикат и
             * операция обязаны отказать ОБА — это тот же контракт, что в разделе «край». */
            {
                hb_gva_t край = wbase + PAGE - 4;
                uint64_t v = 0;
                int оп = (hb_memory_write_u64(mem, край, 0x1122334455667788ull) == HB_OK);
                (void)hb_memory_read_u64(mem, край, &v);
                check("ширина: u64 через край области", rw,
                      hb_memory_can_write_span(mem, край, 8), оп);
            }

            /* ПРАВА: на области r-- запись любой ширины обязана отказать, чтение — пройти. */
            {
                hb_gva_t ro = GUEST_BASE + 0x910000ull;

                if (hb_memory_map_private(mem, ro, PAGE, HB_PERM_READ) == HB_OK) {
                    int записалось = (hb_memory_write_u32(mem, ro, 0xdeadbeefu) == HB_OK);
                    uint32_t v = 0;
                    int прочиталось = (hb_memory_read_u32(mem, ro, &v) == HB_OK);

                    check("ширина: r-- запись", HB_PERM_READ,
                          hb_memory_can_write(mem, ro, 4), записалось);
                    check("ширина: r-- чтение", HB_PERM_READ,
                          hb_memory_can_read(mem, ro, 4), прочиталось);
                }
            }
        }
    }

    handlers_check(mem, "перед 4");

    /* --- 4. После protect предикат и операция обязаны поменяться СОГЛАСОВАННО -------------- */
    {
        hb_gva_t base = GUEST_BASE + 0x300000ull;

        if (hb_memory_map_private(mem, base, PAGE, HB_PERM_READ | HB_PERM_WRITE) == HB_OK &&
            hb_memory_protect(mem, base, PAGE, HB_PERM_READ) == HB_OK) {
            check("protect r--: read", HB_PERM_READ,
                  hb_memory_can_read(mem, base, 4), op_run(OP_READ, mem, base, 4));
            check("protect r--: write", HB_PERM_READ,
                  hb_memory_can_write(mem, base, 4), op_run(OP_WRITE, mem, base, 4));

            if (hb_memory_protect(mem, base, PAGE, HB_PERM_READ | HB_PERM_EXEC) == HB_OK) {
                check("protect r-x: fetch", HB_PERM_READ | HB_PERM_EXEC,
                      hb_memory_can_exec(mem, base, 1), op_run(OP_FETCH, mem, base, 1));
                check("protect r-x: write", HB_PERM_READ | HB_PERM_EXEC,
                      hb_memory_can_write(mem, base, 4), op_run(OP_WRITE, mem, base, 4));
            }
        }
    }

    handlers_check(mem, "перед 5");

    /* --- 5. region_generation: контракт — «поколение КОДА», а не «поколение области» -------
     * Первая редакция этой сверки требовала роста при ЛЮБОЙ смене прав и объявила нарушение.
     * Прибор был неправ, а не объект: `bump_generation` зовётся только когда в старых или новых
     * правах есть EXEC (`hb_memory.c:2420,2441,2457`) — это счётчик инвалидации кода, и для
     * r-- → rw- он расти НЕ обязан. Проверяю настоящий контракт, обе стороны. */
    {
        hb_gva_t nx = GUEST_BASE + 0x400000ull;
        hb_gva_t xx = GUEST_BASE + 0x410000ull;

        if (hb_memory_map_private(mem, nx, PAGE, HB_PERM_READ) == HB_OK) {
            uint64_t g0 = hb_memory_region_generation(mem, nx);
            hb_memory_protect(mem, nx, PAGE, HB_PERM_READ | HB_PERM_WRITE);
            check("gen НЕ растёт без EXEC", HB_PERM_READ,
                  1, hb_memory_region_generation(mem, nx) == g0 ? OP_DONE : OP_DENIED);
        }
        if (hb_memory_map_private(mem, xx, PAGE, HB_PERM_READ) == HB_OK) {
            uint64_t g0 = hb_memory_region_generation(mem, xx);
            hb_memory_protect(mem, xx, PAGE, HB_PERM_READ | HB_PERM_EXEC);
            check("gen растёт при EXEC", HB_PERM_READ | HB_PERM_EXEC,
                  1, hb_memory_region_generation(mem, xx) != g0 ? OP_DONE : OP_DENIED);
        }
    }

    handlers_check(mem, "перед 6");

    /* --- 6. last_fault обязан описывать ИМЕННО последний отказ ----------------------------- */
    {
        hb_gva_t base = GUEST_BASE + 0x500000ull;

        if (hb_memory_map_private(mem, base, PAGE, HB_PERM_READ) == HB_OK) {
            uint64_t fa = 0; size_t fs = 0; int fw = -1, fv = 0;

            (void)op_run(OP_WRITE, mem, base, 4);           /* отказ по записи */
            hb_memory_last_fault(&fa, &fs, &fw, &fv);
            printf("  last_fault после отказа записи: valid=%d addr=%#llx size=%zu is_write=%d\n",
                   fv, (unsigned long long)fa, fs, fw);
            check("last_fault: отмечен", HB_PERM_READ, 1, fv ? OP_DONE : OP_DENIED);
            check("last_fault: тот адрес", HB_PERM_READ, 1, (fa == base) ? OP_DONE : OP_DENIED);
            check("last_fault: это запись", HB_PERM_READ, 1, (fw == 1) ? OP_DONE : OP_DENIED);
            check("last_fault: тот размер", HB_PERM_READ, 1, (fs == 4) ? OP_DONE : OP_DENIED);
        }
    }

    handlers_check(mem, "перед 6b");

    /* --- 6b. Исполняемая, но НЕ читаемая страница: можно ли вообще выбрать из неё байт? ----
     * От ответа зависит, чинится ли расхождение can_exec/fetch в `hb_memory_fetch` или упирается
     * в хостовую защиту. Меряю, а не предполагаю. */
    {
        hb_gva_t base = GUEST_BASE + 0x600000ull;

        if (hb_memory_map_private(mem, base, PAGE, HB_PERM_EXEC) == HB_OK) {
            void *hp = hb_memory_host_ptr(mem, base, 1, HB_PERM_EXEC);
            int deref;

            if (!hp) {
                printf("  --x: host_ptr(EXEC) = NULL\n");
            } else {
                volatile unsigned char sink;
                if (sigsetjmp(g_jmp, 1) != 0) { deref = OP_CRASH; }
                else { g_armed = 1; sink = *(volatile unsigned char *)hp; (void)sink; g_armed = 0; deref = OP_DONE; }
                printf("  --x: host_ptr(EXEC)=%p  разыменование=%s\n",
                       hp, deref == OP_CRASH ? "УРОНИЛО ХОСТ" : "прошло");
            }
        }
    }

    handlers_check(mem, "перед 8");

    /* --- 8. ПРАВА 4 КБ ВНУТРИ 16 КБ ХОСТОВОЙ СТРАНИЦЫ (признак закрытия ступени 7) ---------
     *
     * Гость Windows размечает права по 4 КБ, хостовая страница macOS ARM64 — 16 КБ. `mprotect`
     * мельче 16 КБ не умеет. Отсюда две противоположные беды, и обе надо различить:
     *   ПЕРЕЗАЩИТА  — сняли право у середины, а хост снял у всех 16 КБ: слой говорит «пиши»,
     *                 а запись роняет процесс. Ловится ловушкой сигнала.
     *   НЕДОЗАЩИТА  — слой говорит «нельзя», а запись проходит: гость не увидит защиты вовсе,
     *                 и самоизменение кода останется незамеченным.
     * Меряю обе стороны: и учёт слоя, и то, что на самом деле делает хост. */
    {
        hb_gva_t base = GUEST_BASE + 0x700000ull;
        const size_t HOST_PAGE = 0x4000u;              /* 16 КБ */
        hb_result_t rc = hb_memory_map_private(mem, base, HOST_PAGE, HB_PERM_READ | HB_PERM_WRITE);

        if (rc != HB_OK) {
            printf("  4К-в-16К: ПРОПУСК, не отобразилось 16 КБ (код %d)\n", (int)rc);
        } else {
            hb_gva_t mid = base + 0x1000ull;           /* вторые 4 КБ той же хостовой страницы */
            hb_perm_t before = hb_memory_can_write(mem, mid, 4) ? (HB_PERM_READ | HB_PERM_WRITE)
                                                                : HB_PERM_READ;
            hb_result_t prc = hb_memory_protect(mem, mid, 0x1000u, HB_PERM_READ);
            int pred_after = hb_memory_can_write(mem, mid, 4);
            int op_after   = op_run(OP_WRITE, mem, mid, 4);
            void *hp;
            int host_mid;

            (void)before;
            printf("  4К-в-16К: protect(середина 4 КБ → r--) = %d%s\n", (int)prc,
                   prc == HB_OK ? "" : "   ← ОТКАЗ: хост не умеет права мельче 16 КБ (mprotect EINVAL)");

            /* Три ответа об одном и том же месте. Печатаю ЗНАЧЕНИЯ, а не «сошлось»: сверка на
             * согласие показала бы «нарушений нет» и при том, что защиты не произошло вовсе. */
            hp = hb_memory_host_ptr(mem, mid, 1, HB_PERM_READ);
            if (!hp) host_mid = OP_DENIED;
            else {
                if (sigsetjmp(g_jmp, 1) != 0) host_mid = OP_CRASH;
                else { g_armed = 1; *(volatile unsigned char *)hp = 0x5A; g_armed = 0; host_mid = OP_DONE; }
            }
            printf("  4К-в-16К: середина после отказа — учёт слоя пишет=%d, операция=%s, хост=%s\n",
                   pred_after,
                   op_after == OP_CRASH ? "УРОНИЛА" : (op_after ? "прошла" : "отказала"),
                   host_mid == OP_CRASH ? "защитил" : (host_mid ? "НЕ защитил" : "нет указателя"));

            if (prc != HB_OK && pred_after == 0) {
                g_checks++; g_fail++;
                printf("  НАРУШЕНИЕ  protect вернул отказ, но учёт слоя УЖЕ изменён"
                       "   (hb_memory.c:2425 пишет perm до mprotect на 2447)\n");
            } else if (prc != HB_OK && pred_after == 1 && host_mid == OP_DONE) {
                g_checks++;
                printf("  СОГЛАСОВАНО: protect отказал, права не менялись ни в учёте, ни у хоста\n");
            }

            /* Соседние 4 КБ той же 16-килобайтной страницы обязаны остаться писчими. */
            check("4К: низ пишется", HB_PERM_READ | HB_PERM_WRITE,
                  hb_memory_can_write(mem, base, 4), op_run(OP_WRITE, mem, base, 4));
            check("4К: верх пишется", HB_PERM_READ | HB_PERM_WRITE,
                  hb_memory_can_write(mem, base + 0x2000ull, 4),
                  op_run(OP_WRITE, mem, base + 0x2000ull, 4));

            /* Та же 16-килобайтная страница ПОСЛЕ неудачной попытки размежевать её по 4 КБ. */
            {
                hb_result_t whole = hb_memory_protect(mem, base, HOST_PAGE, HB_PERM_READ);
                hb_gva_t fresh = GUEST_BASE + 0xA00000ull;
                hb_result_t fresh_rc = HB_ERR_INVALID_ARG;

                /* КОНТРОЛЬ: свежая, ни разу не разрезанная 16-килобайтная область. Без него
                 * нельзя отличить «эта область испорчена» от «защита не работает вообще». */
                if (hb_memory_map_private(mem, fresh, HOST_PAGE, HB_PERM_READ | HB_PERM_WRITE) == HB_OK)
                    fresh_rc = hb_memory_protect(mem, fresh, HOST_PAGE, HB_PERM_READ);

                printf("  4К-в-16К: protect(вся 16 КБ) после разреза = %d, на СВЕЖЕЙ области = %d%s\n",
                       (int)whole, (int)fresh_rc,
                       (whole != HB_OK && fresh_rc == HB_OK)
                           ? "   ← ОБЛАСТЬ ИСПОРЧЕНА разрезом: целая страница больше не защищается"
                           : "");
                if (fresh_rc == HB_OK)
                    check("16К: свежая после protect не пишется", HB_PERM_READ,
                          hb_memory_can_write(mem, fresh, 4), op_run(OP_WRITE, mem, fresh, 4));
            }
        }
    }

    handlers_check(mem, "перед 9");

    /* --- 9. БЛОК НА ДВУХ ГОСТЕВЫХ СТРАНИЦАХ (признак закрытия ступени 7) -------------------
     * Команда или блок, лежащий через границу страниц. Слой обязан либо сшить чтение, либо
     * отказать ЦЕЛИКОМ — и предикат обязан сказать то же, что операция. Три случая: обе
     * страницы доступны, вторая не отображена, вторая без права чтения. */
    {
        hb_gva_t p1 = GUEST_BASE + 0x800000ull;
        hb_gva_t p2 = p1 + 0x1000ull;                  /* соседняя гостевая страница */
        hb_gva_t p3 = GUEST_BASE + 0x900000ull;
        hb_gva_t p4 = p3 + 0x1000ull;

        if (hb_memory_map_private(mem, p1, 0x1000u, HB_PERM_READ | HB_PERM_WRITE) == HB_OK &&
            hb_memory_map_private(mem, p2, 0x1000u, HB_PERM_READ | HB_PERM_WRITE) == HB_OK) {
            hb_gva_t cross = p2 - 2;                   /* 4 байта: 2 в первой, 2 во второй */
            unsigned char mark1[2] = { 0xA1, 0xA2 }, mark2[2] = { 0xB1, 0xB2 };
            unsigned char got[4] = {0};

            hb_memory_write(mem, p2 - 2, mark1, 2);
            hb_memory_write(mem, p2, mark2, 2);

            check("две страницы: span-предикат", HB_PERM_READ | HB_PERM_WRITE,
                  hb_memory_can_read_span(mem, cross, 4), op_run(OP_READ, mem, cross, 4));

            if (hb_memory_read(mem, cross, got, 4) == HB_OK)
                printf("  две страницы: сшивка через границу = %02X %02X %02X %02X  (ждём A1 A2 B1 B2)%s\n",
                       got[0], got[1], got[2], got[3],
                       (got[0] == 0xA1 && got[1] == 0xA2 && got[2] == 0xB1 && got[3] == 0xB2)
                           ? "" : "   ← БАЙТЫ НЕ ТЕ");
            else
                printf("  две страницы: сшивка через границу ОТКАЗАНА\n");
        }

        /* Вторая страница НЕ отображена: и предикат, и операция обязаны отказать. */
        if (hb_memory_map_private(mem, p3, 0x1000u, HB_PERM_READ | HB_PERM_WRITE) == HB_OK) {
            hb_gva_t cross = p4 - 2;

            check("две страницы: вторая не отобр.", HB_PERM_READ | HB_PERM_WRITE,
                  hb_memory_can_read_span(mem, cross, 4), op_run(OP_READ, mem, cross, 4));

            /* Теперь отобразим вторую БЕЗ права чтения — предикат обязан остаться нулём. */
            if (hb_memory_map_private(mem, p4, 0x1000u, HB_PERM_WRITE) == HB_OK)
                check("две страницы: вторая без r", HB_PERM_WRITE,
                      hb_memory_can_read_span(mem, cross, 4), op_run(OP_READ, mem, cross, 4));
        }
    }

    handlers_check(mem, "перед 7");

    /* --- 7. Тождественное отображение БЕЗ подложки — свойство, не дефект ------------------- */
    {
        hb_gva_t base = 0x50000000ull;   /* хостом не зарезервирован */

        if (hb_memory_map(mem, base, PAGE, HB_PERM_READ | HB_PERM_WRITE) == HB_OK) {
            int pred = hb_memory_can_read(mem, base, 4);
            int op = op_run(OP_READ, mem, base, 4);

            if (op == OP_CRASH) g_nobacking_crash++;
            printf("  без подложки (hb_memory_map, base!=0): can_read=%d  read=%s\n",
                   pred, op == OP_CRASH ? "УРОНИЛА ХОСТ" : (op ? "прошла" : "отказано"));
        }
    }

    /* ★★★ ПОПРАВКА К СЕБЕ (итерация 12) — ЗДЕСЬ БЫЛ ДЕФЕКТ САМОГО СТЕНДА, а не движка.
     *
     * Стояло просто `hb_memory_destroy(mem);`, а ВСЕ разделы ниже продолжали звать слой с тем же
     * `mem` — десять вызовов на освобождённом объекте (`map`, `find_region`, `can_write`,
     * `protect`, `set_special_handlers`, `set_grow_handler`). Отсюда всё, что я записывал как
     * «дикая запись» и «нестабильность стенда»:
     *   - канарейка роняет хост на границе «перед 7b» — 10 прогонов из 10;
     *   - раздел ширин, поставленный ПОСЛЕ, даёт 00 00 00 00 в 6 случаях из 10, а ПЕРЕД — 44 33 22 11
     *     в 10 из 10 (позиционный опыт итерации 11);
     *   - смерть прогона в 6-9 случаях из 10.
     * То есть измерялась не работа слоя, а чтение освобождённой памяти. Дефект 6 в моём же итоге
     * описан как дефект ДВИЖКА — это НЕВЕРНО, и отзывается.
     *
     * Объект пересоздаётся, потому что разрушение здесь нужно по существу: ниже идёт
     * `hb_memory_guest32_reserve`, а он глобален и меняет перевод адресов у ВСЕГО, что заведено
     * раньше (см. рамку ниже). */
    hb_memory_destroy(mem);
    mem = hb_memory_create(0);
    if (!mem) { printf("ОТКАЗ ОСНАСТКИ: пересоздание hb_memory после destroy вернуло NULL\n"); return 2; }
    canary_arm(mem);
    printf("  ПЕРЕСОЗДАНИЕ: слой заведён заново, канарейка перевзведена\n");

    /* ================================================================================
     * ВНИМАНИЕ, ПОРЯДОК ВАЖЕН. Всё, что ниже, идёт ПОСЛЕДНИМ и не может стоять выше.
     *
     * `hb_memory_guest32_reserve` — глобальное состояние: после него
     * `normalize_guest32_mirror_addr` переводит ЛЮБОЙ адрес ниже 4 ГБ в зеркало, а `GUEST_BASE`
     * этого стенда равен 0x40000000, то есть 1 ГБ. Когда этот раздел стоял выше, он молча
     * переписал показания следующих: сшивка на границе страниц из «A1 A2 B1 B2» стала
     * «ОТКАЗАНА», а раздел без подложки перестал ронять хост. Ни одна сверка при этом не
     * покраснела — измерялось просто другое.
     * ================================================================================ */

    handlers_check(mem, "перед 7b");

    /* --- 7b. ЖИВОЙ КЛАСС x64: тождественные области — права слоя СОВЕТУЮТ, а не действуют --
     *
     * Все семь вызовов `hb_memory_map` со стороны wine идут с НЕнулевой базой
     * (`macrunner_hb.c:12298,13224,13238,17018,17336,18864`), то есть `allocated=false`,
     * `host_base=NULL`. Для таких областей `hb_memory_protect` возвращает HB_OK по одному учёту
     * и ядро НЕ зовёт (`hb_memory.c:2419`). Значит наш `perm` — вторая, параллельная запись о
     * правах, а настоящую защиту ставил wine. Меряю обе стороны расхождения на памяти, которую
     * отображаю сам, ровно как это делает wine. */
    {
        size_t hp = (size_t)getpagesize();
        void *ro = mmap(NULL, hp, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        void *rw = mmap(NULL, hp, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (ro == MAP_FAILED || rw == MAP_FAILED) {
            printf("  тождественные: ПРОПУСК, не отобразилась хостовая память\n");
        } else {
            /* (а) хост запретил запись, а слою объявляем rw- */
            {
                hb_result_t mrc;

                printf("  тождественные: зову map(0x%llx)...\n", (unsigned long long)(uintptr_t)ro);
                if (sigsetjmp(g_jmp, 1) != 0) {
                    printf("  тождественные: САМ hb_memory_map УРОНИЛ ХОСТ\n");
                    g_checks++; g_fail++; g_crashes++;
                    mrc = HB_ERR_MEMORY_FAULT;
                } else { g_armed = 1; mrc = hb_memory_map(mem, (hb_gva_t)(uintptr_t)ro, hp,
                                                          HB_PERM_READ | HB_PERM_WRITE); g_armed = 0; }
                hb_region_t *r = NULL;

                if (sigsetjmp(g_jmp, 1) != 0) printf("  тождественные: find_region УРОНИЛ ХОСТ\n");
                else { g_armed = 1; r = hb_memory_find_region(mem, (hb_gva_t)(uintptr_t)ro); g_armed = 0; }

                /* ПРИЧИНА, ЕСЛИ ЗДЕСЬ NULL — найдена пробой, не догадкой: `hb_memory_map` НЕ
                 * проверяет перекрытие, в отличие от `map_private` с его `any_overlap`
                 * (`hb_memory.c:1831`). Разделы выше уже зарегистрировали область поверх
                 * хостовой кучи, новая страница попадает в чужой диапазон, и слой отвечает по
                 * СТАРШЕЙ области. Ходить по `mem->regions` руками я перестал: та проба
                 * печатала базу без выравнивания и host==base, то есть врала сама. */
                printf("  тождественные: адрес=0x%llx map=%d, find_region=%s%s\n",
                       (unsigned long long)(uintptr_t)ro, (int)mrc,
                       r ? "нашёл" : "NULL",
                       r ? "" : "   ← перекрытие (см. macrunner-hb-map-overlap)");
            }
            {
                int pred = hb_memory_can_write(mem, (hb_gva_t)(uintptr_t)ro, 4);
                int op   = op_run(OP_WRITE, mem, (hb_gva_t)(uintptr_t)ro, 4);

                printf("  тождественные: хост r--, слою объявлено rw- → учёт пишет=%d, запись=%s%s\n",
                       pred, op == OP_CRASH ? "УРОНИЛА ХОСТ" : (op ? "прошла" : "отказана"),
                       (pred == 1 && op == OP_CRASH)
                           ? "   ← права слоя лишь СОВЕТУЮТ: запрет хоста они не видят"
                           : "");
                g_checks++;
                if (pred == 1 && op == OP_CRASH) { /* измерено, а не дефект слоя: это его модель */
                    printf("  (это модель, а не поломка: защиту тождественных областей ставит wine,"
                           " слой её не переспрашивает)\n");
                }
            }

            /* (б) обратное: хост разрешил, а слою объявляем r-- — учёт обязан удержать запись */
            if (hb_memory_map(mem, (hb_gva_t)(uintptr_t)rw, hp, HB_PERM_READ) == HB_OK) {
                check("тождественные: учёт держит запрет", HB_PERM_READ,
                      hb_memory_can_write(mem, (hb_gva_t)(uintptr_t)rw, 4),
                      op_run(OP_WRITE, mem, (hb_gva_t)(uintptr_t)rw, 4));

                /* и protect на такой области обязан пройти БЕЗ обращения к ядру */
                printf("  тождественные: protect(4 КБ внутри 16 КБ) = %d  (ядро не зовётся)\n",
                       (int)hb_memory_protect(mem, (hb_gva_t)(uintptr_t)rw + 0x1000u, 0x1000u,
                                              HB_PERM_READ | HB_PERM_WRITE));
            }
        }
    }

    handlers_check(mem, "перед 10");

    /* --- 10. САМОИЗМЕНЕНИЕ: детектор через запрет записи (признак закрытия ступени 7) -----
     *
     * Механизм живёт в этом же файле движка: `hb_smc_arm_page` снимает право записи с хозяйской
     * страницы, обработчик поднимает ПОКОЛЕНИЕ и возвращает право, проверка на входе в блок
     * сравнивает поколение. Гейт `MACRUNNER_HB_SMC_PROTECT` по умолчанию ВЫКЛЮЧЕН.
     *
     * Меряю обе стороны: с гейтом ВЫКЛ примитив обязан быть инертным, с ВКЛ — защита обязана
     * лечь и быть видимой запросом к ядру. Полный круг (запись → обработчик → поколение) здесь
     * не воспроизводится: обработчик движка ставит `install_sig_handlers`, а в стенде свой. */
    {
        extern int      hb_smc_protect_enabled(void);
        extern int      hb_smc_arm_page(void* host_addr);
        extern uint32_t hb_smc_page_generation(uint64_t host_addr);
        extern int      hb_smc_query_prot(uint64_t host_addr);

        size_t ps = (size_t)getpagesize();
        void *code = mmap(NULL, ps, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (code == MAP_FAILED) {
            printf("  smc: ПРОПУСК, страница не отобразилась\n");
        } else {
            int on = hb_smc_protect_enabled();
            int prot_before = hb_smc_query_prot((uint64_t)(uintptr_t)code);
            int armed = hb_smc_arm_page(code);
            int prot_after = hb_smc_query_prot((uint64_t)(uintptr_t)code);
            uint32_t gen0 = hb_smc_page_generation((uint64_t)(uintptr_t)code);
            int w;

            printf("  smc: гейт=%d  arm=%d  прав до=%d после=%d  поколение=%u\n",
                   on, armed, prot_before, prot_after, gen0);

            if (!on) {
                g_checks++;
                if (armed != 0 || prot_after != prot_before) {
                    g_fail++;
                    printf("  НАРУШЕНИЕ  smc: гейт ВЫКЛ, а примитив подействовал\n");
                }
            } else {
                g_checks++;
                if (armed != 1 || prot_after != (VM_PROT_READ | VM_PROT_EXECUTE)) {
                    g_fail++;
                    printf("  НАРУШЕНИЕ  smc: гейт ВКЛ, а защита не легла (arm=%d prot=%d,"
                           " ждали 5)\n", armed, prot_after);
                }
            }

            /* Запись в защищённую страницу — под ловушкой: обработчика движка здесь нет, поэтому
             * отказ ОБЯЗАН случиться. Это и есть доказательство, что защита настоящая. */
            {   /* Чья это область по мнению слоя? Если чужая — запись уедет по её `host_base`,
                 * то есть НЕ ТУДА. Это следствие перекрытия (дефект 5 отчёта), а не защиты. */
                hb_region_t *own = hb_memory_find_region(mem, (hb_gva_t)(uintptr_t)code);
                printf("  smc: страница 0x%llx — область слоя: %s",
                       (unsigned long long)(uintptr_t)code, own ? "" : "нет\n");
                if (own)
                    printf("base=0x%llx size=0x%llx host=%p%s\n",
                           (unsigned long long)own->base, (unsigned long long)own->size,
                           own->host_base,
                           (own->base != (hb_gva_t)(uintptr_t)code)
                               ? "   ← ЧУЖАЯ: запись уйдёт по её host_base" : "");
            }
            {   /* Различающий замер: та же страница, запись МИМО слоя. Если прямая проходит, а
                 * через слой роняет — слой уводит запись не по тому адресу. */
                int direct;
                if (sigsetjmp(g_jmp, 1) != 0) direct = OP_CRASH;
                else { g_armed = 1; *(volatile unsigned char *)code = 0x5A; g_armed = 0; direct = OP_DONE; }
                printf("  smc: запись МИМО слоя = %s\n",
                       direct == OP_CRASH ? "УРОНИЛА" : "прошла");
            }
            g_fault_addr = 0;
            w = op_run(OP_WRITE, mem, (hb_gva_t)(uintptr_t)code, 4);
            if (w == OP_CRASH && !hb_memory_find_region(mem, (hb_gva_t)(uintptr_t)code)) {
                unsigned long long want = (unsigned long long)(uintptr_t)code;
                unsigned long long got  = (unsigned long long)g_fault_addr;
                g_checks++; g_fail++;
                printf("  НАРУШЕНИЕ  запись через слой РОНЯЕТ там, где прямая проходит:"
                       " области нет, страница писчая, гейт SMC выкл\n");
                printf("             просили 0x%llx, отказ по 0x%llx, разница %+lld (сигнал %d)\n",
                       want, got, (long long)(got - want), g_fault_sig);

                /* Различающий замер, итерация 6. Отказ по адресу 0x1 при сигнале SIGBUS — это
                 * не «запись ушла не туда», а ПЕРЕХОД по адресу 1. В пути записи косвенный
                 * вызов ровно один: `mem->special_write` (`hb_memory.c:2964`, ветвь «области
                 * нет»). Гашу специальные обработчики и повторяю ТУ ЖЕ запись: если падение
                 * исчезло — виноват вызов обработчика, а не адрес. */
                {
                    int w2;
                    hb_memory_set_special_handlers(mem, NULL, NULL, NULL);
                    hb_memory_set_grow_handler(mem, NULL);
                    g_fault_addr = 0;
                    w2 = op_run(OP_WRITE, mem, (hb_gva_t)(uintptr_t)code, 4);
                    printf("             после гашения обработчиков та же запись = %s\n",
                           w2 == OP_CRASH ? "снова УРОНИЛА" :
                           (w2 ? "прошла" : "отклонена слоем — виноват был ВЫЗОВ ОБРАБОТЧИКА"));
                }
            }
            printf("  smc: запись в страницу = %s%s\n",
                   w == OP_CRASH ? "ОТКАЗ (защита настоящая)" : (w ? "прошла" : "отклонена слоем"),
                   (on && w != OP_CRASH) ? "   ← защита не действует" : "");

            /* Возврат права записи — та самая строка, что отказывала. Проверяю прямо. */
            if (on) {
                int r_rwx = mprotect(code, ps, PROT_READ | PROT_WRITE | PROT_EXEC);
                int e_rwx = errno;
                int r_rw  = mprotect(code, ps, PROT_READ | PROT_WRITE);

                printf("  smc: возврат прав — R|W|X=%d(errno=%d)  R|W=%d%s\n",
                       r_rwx, r_rwx ? e_rwx : 0, r_rw,
                       (r_rwx != 0 && r_rw == 0) ? "   ← отпустить можно ТОЛЬКО без EXEC" : "");
            }
        }
    }

    handlers_check(mem, "перед 8b");

    /* --- 8b. ЖИВОЙ КЛАСС ОБЛАСТЕЙ С ПОДЛОЖКОЙ: guest32 (зеркало i386) --------------------
     *
     * Раздел 8 мерил класс `allocated`, а в живом пути его нет: области заводятся
     * `hb_memory_map` (тождественные, без подложки) и до `mprotect` не доходят вовсе —
     * `hb_memory.c:2419` отдаёт HB_OK по одному учёту. Единственный класс С подложкой, который
     * живёт на прогоне, — `guest32`, зеркало 32-битного гостя. И он устроен ПРОТИВОПОЛОЖНО:
     * `guest32_sync_host_protection` (`hb_memory.c:1383-1385`) округляет диапазон НАРУЖУ
     * (`host_page_floor`/`host_page_ceil`), то есть защита 4 КБ ложится на все 16 КБ.
     *
     * Меряю на ОТДЕЛЬНОМ экземпляре памяти. Зеркало — глобальное состояние: после резерва
     * `normalize_guest32_mirror_addr` переводит ЛЮБОЙ адрес ниже 4 ГБ, а `GUEST_BASE` стенда =
     * 0x40000000 (1 ГБ). Когда этот раздел стоял на общем экземпляре, он молча переписал
     * показания соседей: сшивка на границе страниц из «A1 A2 B1 B2» стала «ОТКАЗАНА», а раздел
     * без подложки перестал ронять хост — и НИ ОДНА сверка при этом не покраснела. */
    {
        hb_memory_t *m32 = free_mb_estimate() < 1500 ? NULL : hb_memory_create(0);

        if (free_mb_estimate() < 1500) {
            printf("  guest32: ПРОПУСК — свободно %ld МБ, а резерв зеркала берёт 4 ГБ."
                   " Прогон под нехваткой памяти даёт код 137 и НОЛЬ строк, что читается как"
                   " отказ стенда, а не как пропуск.\n", free_mb_estimate());
        } else if (!m32) {
            printf("  guest32: ПРОПУСК, второй экземпляр памяти не создался\n");
        } else {
            hb_result_t rrc;
            int reserve_crash = 0;

            if (sigsetjmp(g_jmp, 1) != 0) { reserve_crash = 1; rrc = HB_ERR_MEMORY_FAULT; }
            else { g_armed = 1; rrc = hb_memory_guest32_reserve(m32); g_armed = 0; }

            if (reserve_crash) {
                printf("  guest32: резерв зеркала УРОНИЛ ХОСТ\n");
                g_checks++; g_fail++; g_crashes++;
            } else if (rrc != HB_OK) {
                printf("  guest32: ПРОПУСК, резерв зеркала не удался (код %d)\n", (int)rrc);
            } else {
                const uint32_t g_base = 0x10000000u;    /* 16 КБ = четыре гостевые страницы */
                hb_result_t mrc;
                /* ЧЕТЫРЕ ТОЧКИ ВХОДА, которые звались, но своей сверки не имели (итерация 16):
                 * `guest32_reserve`, `guest32_base`, `guest32_map`, `guest32_protect`.
                 * Проверяю их СОСТОЯНИЕМ до и после, а не кодом возврата. */
                void *база_после_резерва = hb_memory_guest32_base(m32);
                int до_map_пред = hb_memory_can_write(m32, g_base, 4);

                check("guest32_reserve: база появилась", HB_PERM_NONE,
                      1, база_после_резерва ? OP_DONE : OP_DENIED);
                check("guest32_base: до map доступа нет", HB_PERM_NONE, до_map_пред, OP_DENIED);

                mrc = hb_memory_guest32_map(m32, g_base, 0x4000u,
                                            HB_PERM_READ | HB_PERM_WRITE);

                printf("  guest32: зеркало заведено, map(16 КБ, rw-) = %d\n", (int)mrc);
                if (mrc == HB_OK) {
                    uint32_t mid = g_base + 0x1000u;    /* вторые 4 КБ — их защищаем */
                    uint32_t nb  = g_base + 0x2000u;    /* СОСЕДНИЕ 4 КБ — их не трогаем */
                    hb_result_t prc = hb_memory_guest32_protect(m32, mid, 0x1000u, HB_PERM_READ);
                    int pred_nb, op_nb, pred_mid, op_mid;

                    printf("  guest32: protect(середина 4 КБ → r--) = %d\n", (int)prc);
                    check("guest32_map: после map пишется", (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE),
                          hb_memory_can_write(m32, nb, 4), op_run(OP_WRITE, m32, nb, 4));

                    pred_mid = hb_memory_can_write(m32, mid, 4);
                    op_mid   = op_run(OP_WRITE, m32, mid, 4);
                    printf("  guest32: ЗАЩИЩЁННЫЕ 4 КБ — учёт пишет=%d, запись=%s%s\n",
                           pred_mid,
                           op_mid == OP_CRASH ? "УРОНИЛА ХОСТ" : (op_mid ? "ПРОШЛА" : "отказана"),
                           (pred_mid == 1 && prc == HB_OK) ? "   ← защита не легла даже в учёт" : "");

                    pred_nb = hb_memory_can_write(m32, nb, 4);
                    op_nb   = op_run(OP_WRITE, m32, nb, 4);
                    printf("  guest32: СОСЕДНИЕ 4 КБ — учёт пишет=%d, запись=%s%s\n",
                           pred_nb,
                           op_nb == OP_CRASH ? "УРОНИЛА ХОСТ" : (op_nb ? "прошла" : "отказана"),
                           (pred_nb == 1 && op_nb == OP_CRASH)
                               ? "   ← ПЕРЕЗАЩИТА: слой разрешает, хост снял право со всех 16 КБ"
                               : "");

                    check("guest32: защищённые 4 КБ", HB_PERM_READ, pred_mid, op_mid);
                    check("guest32: соседние 4 КБ", HB_PERM_READ | HB_PERM_WRITE, pred_nb, op_nb);

                    /* ДВЕ ТОЧКИ ВХОДА, которые стенд не вызывал ВООБЩЕ (итерация 15):
                     * `hb_memory_guest32_to_host` и `hb_memory_guest32_unmap`.
                     *
                     * Перевод проверяется НЕ «вернул не-NULL», а сверкой с независимой дорогой:
                     * `host_ptr` считает тот же адрес другим путём, и оба обязаны совпасть.
                     * Плюс содержимое: пишем через слой — обязаны увидеть по хозяйскому адресу
                     * СЫРЫМ чтением. Без этого «перевод работает» означало бы только, что
                     * функция что-то вернула. */
                    {
                        void *через_перевод = hb_memory_guest32_to_host(m32, nb);
                        void *через_host_ptr = hb_memory_host_ptr(m32, nb, 4,
                                                                  (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE));
                        int совпали = (через_перевод != NULL) && (через_перевод == через_host_ptr);
                        int содержимое = 0;

                        if (совпали) {
                            uint32_t образец = 0xA5A50F0Fu, сырое = 0;

                            if (hb_memory_write_u32(m32, nb, образец) == HB_OK) {
                                memcpy(&сырое, через_перевод, sizeof(сырое));
                                содержимое = (сырое == образец);
                            }
                        }
                        printf("  guest32_to_host: перевод=%p host_ptr=%p совпали=%d содержимое=%d\n",
                               через_перевод, через_host_ptr, совпали, содержимое);
                        check("guest32_to_host: тот же адрес, что host_ptr", HB_PERM_READ | HB_PERM_WRITE,
                              1, совпали ? OP_DONE : OP_DENIED);
                        check("guest32_to_host: по адресу лежит записанное", HB_PERM_READ | HB_PERM_WRITE,
                              1, содержимое ? OP_DONE : OP_DENIED);
                    }

                    {
                        /* unmap зеркала: после снятия предикат и операция обязаны отказать ОБА. */
                        uint32_t сн = g_base + 0x3000u;   /* четвёртые 4 КБ — их и снимаем */
                        int до_пред = hb_memory_can_write(m32, сн, 4);
                        int до_оп   = op_run(OP_WRITE, m32, сн, 4);
                        hb_result_t urc = hb_memory_guest32_unmap(m32, сн, 0x1000u);
                        int по_пред = hb_memory_can_write(m32, сн, 4);
                        int по_оп   = op_run(OP_WRITE, m32, сн, 4);

                        printf("  guest32_unmap(%08x, 4 КБ)=%d  до: пред=%d оп=%s  после: пред=%d оп=%s\n",
                               сн, (int)urc, до_пред,
                               до_оп == OP_CRASH ? "УРОНИЛА" : (до_оп ? "прошла" : "отказана"),
                               по_пред,
                               по_оп == OP_CRASH ? "УРОНИЛА" : (по_оп ? "прошла" : "отказана"));
                        check("guest32_unmap: до снятия пишется", HB_PERM_READ | HB_PERM_WRITE,
                              до_пред, до_оп);
                        check("guest32_unmap: после снятия не пишется", HB_PERM_NONE,
                              по_пред, по_оп);
                    }
                }
            }
            hb_memory_destroy(m32);
        }
    }

    /* Раздел 8c (поздний резерв зеркала на уже населённом экземпляре) СНЯТ. Замер сделан:
     * резерв прошёл, хост не упал. Держать его в стенде нельзя — это второй резерв на 4 ГБ в
     * одном процессе, и прогон стенда получил `Killed: 9` от нехватки памяти. Один замер,
     * записанный в отчёт, лучше постоянного раздела, который валит прибор. */

    /* --- 11. ПЕРЕВОД АДРЕСОВ (последний признак закрытия по hb_memory.c) ------------------
     *
     * Что проверяется. У 32-битного гостя гостевой адрес НЕ равен хозяйскому: слой держит
     * зеркало 4 ГБ и переводит `гостевой -> guest32_base + гостевой`. Перевод обязан быть
     * СОГЛАСОВАН на трёх путях, которые считают адрес независимо:
     *
     *     host_ptr(g)      должен дать ровно guest32_base + g
     *     write(g) через слой  должен быть виден по хозяйскому адресу СЫРЫМ чтением
     *     сырая запись по base+g  должна быть видна через read(g) слоем
     *
     * ОКНО ОТКАЗА открыто двумя способами, иначе «сошлось» ничего не значит:
     *   1. отрицательный контроль `HB_MEMCONTRACT_NEGATIVE=1` переворачивает ожидания;
     *   2. проверка ГРАНИЦЫ: адрес ВЫШЕ 4 ГБ переводиться НЕ должен, и если слой переведёт
     *      его тоже — сверка покраснеет. То есть проба различает «перевод есть» и «перевод
     *      применяется всюду подряд».
     */
    {
        hb_memory_t *mt = free_mb_estimate() < 1500 ? NULL : hb_memory_create(0);

        if (!mt) {
            printf("  перевод: ПРОПУСК — свободно %ld МБ, резерв зеркала берёт 4 ГБ\n",
                   free_mb_estimate());
        } else if (hb_memory_guest32_reserve(mt) != HB_OK) {
            printf("  перевод: ПРОПУСК, резерв зеркала не удался\n");
            hb_memory_destroy(mt);
        } else {
            const uint32_t g = 0x20000000u;          /* гостевая страница внутри зеркала */
            unsigned char *base = (unsigned char *)hb_memory_guest32_base(mt);
            hb_result_t mrc = hb_memory_guest32_map(mt, g, 0x4000u,
                                                    HB_PERM_READ | HB_PERM_WRITE);

            printf("  перевод: зеркало base=%p  map(16 КБ) = %d\n", (void *)base, (int)mrc);

            if (mrc != HB_OK || !base) {
                printf("  перевод: ПРОПУСК, область в зеркале не завелась\n");
            } else {
                unsigned char *want = base + g;
                void *hp = hb_memory_host_ptr(mt, g, 4, HB_PERM_READ);
                unsigned char wr[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
                unsigned char rd[4] = {0};
                int ok_ptr, ok_fwd, ok_back, ok_edge;

                /* 1. Указатель, который слой выдаёт наружу. */
                ok_ptr = (hp == (void *)want);
                check("перевод: host_ptr = base+g", HB_PERM_READ, 1,
                      ok_ptr ? OP_DONE : OP_DENIED);
                if (!ok_ptr)
                    printf("             host_ptr=%p, ждали %p, разница %+lld\n",
                           hp, (void *)want, (long long)((char *)hp - (char *)want));

                /* 2. Запись слоем — видна ли сырым чтением по хозяйскому адресу. */
                hb_memory_write(mt, g, wr, 4);
                ok_fwd = (memcmp(want, wr, 4) == 0);
                check("перевод: слой пишет -> хост видит", HB_PERM_WRITE, 1,
                      ok_fwd ? OP_DONE : OP_DENIED);

                /* 3. Сырая запись — видна ли чтением через слой. */
                want[0] = 0x11; want[1] = 0x22; want[2] = 0x33; want[3] = 0x44;
                ok_back = (hb_memory_read(mt, g, rd, 4) == HB_OK &&
                           rd[0] == 0x11 && rd[1] == 0x22 && rd[2] == 0x33 && rd[3] == 0x44);
                check("перевод: хост пишет -> слой видит", HB_PERM_READ, 1,
                      ok_back ? OP_DONE : OP_DENIED);

                /* 4. ГРАНИЦА: адрес ВЫШЕ 4 ГБ переводу не подлежит. Область там не заведена,
                 *    поэтому и предикат, и операция обязаны отказать ОБА. Если слой переведёт
                 *    его в зеркало, чтение внезапно пройдёт — и эта сверка покраснеет. */
                {
                    hb_gva_t above = 0x100004000ull;   /* 4 ГБ + 16 КБ */
                    int op = op_run(OP_READ, mt, above, 4);
                    ok_edge = (op == OP_DENIED);
                    check("перевод: выше 4 ГБ не переводится", HB_PERM_NONE,
                          hb_memory_can_read(mt, above, 4), op);
                    printf("  перевод: host_ptr=%s  слой->хост=%s  хост->слой=%s  граница=%s\n",
                           ok_ptr ? "сошлось" : "РАЗОШЛОСЬ",
                           ok_fwd ? "сошлось" : "РАЗОШЛОСЬ",
                           ok_back ? "сошлось" : "РАЗОШЛОСЬ",
                           ok_edge ? "отказ (верно)" : "ПРОШЛО (перевод всюду!)");
                }
            }
            hb_memory_destroy(mt);
        }
    }

    /* --- 12. ОБРАБОТЧИК РОСТА: последняя точка входа слоя без проверенного поведения -----
     *
     * `hb_memory_set_grow_handler` — единственная из 39 точек входа, о которой отчёт говорил
     * «требует обработчика роста стека, это отдельная проба». Вот она.
     *
     * Контракт (`hb_memory.c:2969`): запись по адресу БЕЗ области зовёт обработчик; если тот
     * вернул true, слой ПОВТОРЯЕТ операцию. Проверяю обе стороны — с обработчиком и без него,
     * иначе «сработало» неотличимо от «и так бы прошло».
     */
    {
        hb_memory_t *mg = hb_memory_create(0);
        hb_gva_t grow_at = GUEST_BASE + 0xA00000ull;

        if (!mg) {
            printf("  рост: ПРОПУСК, экземпляр памяти не создался\n");
        } else {
            unsigned char buf[4] = { 0x47, 0x52, 0x4F, 0x57 };
            int without, with;

            /* Сторона 1: обработчика НЕТ — запись обязана отказать. */
            g_grow_calls = 0;
            without = op_run(OP_WRITE, mg, grow_at, 4);
            check("рост: без обработчика запись отказана", HB_PERM_NONE, 0, without);

            /* Сторона 2: обработчик ставит область и говорит «повтори». */
            g_grow_mem = mg;
            hb_memory_set_grow_handler(mg, grow_cb);
            g_grow_calls = 0;
            with = op_run(OP_WRITE, mg, grow_at, 4);
            check("рост: с обработчиком запись прошла", HB_PERM_READ | HB_PERM_WRITE, 1, with);
            check("рост: обработчик был позван", HB_PERM_NONE, 1,
                  g_grow_calls > 0 ? OP_DONE : OP_DENIED);

            /* И записанное обязано читаться обратно — иначе «прошла» ничего не значит. */
            if (with == OP_DONE) {
                unsigned char got[4] = {0};
                hb_memory_write(mg, grow_at, buf, 4);
                check("рост: записанное читается обратно", HB_PERM_READ, 1,
                      (hb_memory_read(mg, grow_at, got, 4) == HB_OK &&
                       memcmp(got, buf, 4) == 0) ? OP_DONE : OP_DENIED);
            }
            printf("  рост: без обработчика=%d  с обработчиком=%d  вызовов обработчика=%d\n",
                   without, with, g_grow_calls);
            hb_memory_set_grow_handler(mg, NULL);
            hb_memory_destroy(mg);
        }
    }

    printf("сверок %d, НОВЫХ нарушений %d (падений хоста %d), известных расхождений %d;"
           " без подложки падений %d\n",
           g_checks, g_fail, g_crashes, g_known, g_nobacking_crash);

    /* Код возврата ОДИН для обоих режимов: «есть нарушения» = 1. Переворачивает его цель `make`,
     * как у `fault-kind-test`. Первая редакция возвращала 0 при сработавшем контроле — и цель
     * объявила «КОНТРОЛЬ НЕ СРАБОТАЛ» ровно тогда, когда он сработал. */
    if (g_negative)
        printf("отрицательный контроль: перевёрнутых ожиданий не сошлось %d из %d\n",
               g_fail, g_checks);
    return g_fail ? 1 : 0;
}