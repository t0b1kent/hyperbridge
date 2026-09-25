/* MacRunner 2026-09-07, лейн ПОВТОР-3 — ПОВТОР ЗАПИСАННОГО ПОТОКА ГОСТЯ.
 *
 * Что это. Движок исполняет ТОТ ЖЕ гостевой код на ТОЙ ЖЕ памяти, что и живой
 * прогон, но без Wine, без игры, без графики и без окна: на каждой границе с
 * хостом вместо вызова подставляется ЗАПИСАННЫЙ результат.
 *
 * Зачем. Машина одна, замер держит замок на игру, и очередь из пяти работ стоит
 * пять слотов подряд. Повтор замка не держит — N замеров идут ПАРАЛЛЕЛЬНО.
 *
 * ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ НАШИХ СТЕНДОВ. Наши стенды слепы, и это измерено:
 * диспетчеризация НЕ на измеряемом пути, счёт шагов занижает в 4,7 раза
 * (project_dispatch_is_not_on_the_measured_path_on_benches_20260825). Отличие
 * ровно одно: здесь нагрузка не выдумана, а ЗАПИСАНА с живого прогона.
 *
 * ЧЕСТНОСТЬ ПРИБОРА — три числа печатаются ВСЕГДА, и по ним видно, чего стоит
 * замер:
 *   rashozhdenij   сколько раз ход исполнения разошёлся с записью;
 *   stranic_dozhat сколько страниц пришлось доводить по отказу (чего не было в
 *                  записи — значит окна записи не поймали чужую запись);
 *   propuscheno    сколько областей памяти не легло на свои адреса.
 * Повтор с большим расхождением — не «плохой результат», а НЕДЕЙСТВИТЕЛЬНЫЙ, и
 * это видно числом, а не выводится из впечатления.
 *
 * Сборка (цель в Makefile — общий файл, поэтому руками):
 *   clang -O2 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/hb_povtor.c libhyperbridge.a -o tests/hb_povtor
 */
#include "hb_record.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_thunk.h"

#include <errno.h>
#include <fcntl.h>
#define _XOPEN_SOURCE 700
#include <signal.h>
#include <sys/ucontext.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

/* ★★★★ ПОВТОР-6, ШАГ 4: ОБРАЗ ПОВТОРЯЮЩЕГО УХОДИТ В ПОЛОСУ, КОТОРОЙ В ЗАПИСИ НЕТ.
 *
 * Измерено (ПОВТОР-6): из 110 областей, не легших на свои адреса, ОБРАЗ занимал
 * не все. Разложение по тому, КТО мешает (перепись своей карты + сличение вне
 * повтора):
 *     60  ядро отказывает, в карте НИЧЕГО НЕТ   -> низ карты равен базе образа
 *     18  наш образ и куча сразу за ним          -> лечится переносом
 *     27  общий кеш dyld 0x180000000..0x300000000 -> НЕ двигается, чужой
 *      6  крупная резервация libmalloc           -> не двигается напрямую
 *
 * Первая строка — главная и она НЕ ПРО СТОЛКНОВЕНИЕ. На macOS низ адресного
 * пространства процесса равен АДРЕСУ ЗАГРУЗКИ ОБРАЗА: __PAGEZERO растягивается
 * на величину сдвига ASLR, и всё, что ниже, ядро отказывается отображать
 * (errno=12) при полностью свободной карте. Сдвиг наблюдался от 0x148000 до
 * 0x4800000, поэтому и число легших областей ПЛАВАЛО от прогона к прогону.
 *
 * Отсюда две правки, и обе нужны:
 *   1. `-segaddr` уводит сегменты в 0x170000000 — полосу, свободную во ВСЕХ
 *      трёх наших записях (перепись: 0x16ffa4000..0x180000000, 256 МБ).
 *      ★ `-image_base` и `-no_pie` для arm64 закрыты замером 10.08.2026, а
 *      `-segaddr` — НЕ закрыт и работает; потолок TLV требует, чтобы __DATA
 *      кончалась ниже 0x200000000.
 *   2. Снятие ASLR перевыполнением себя (POSIX_SPAWN_SETEXEC |
 *      _POSIX_SPAWN_DISABLE_ASLR) делает сдвиг НУЛЁМ: низ карты становится
 *      ровно 0x100000000, и области записи, лежащие с самого низа, ложатся.
 *      Гейт MACRUNNER_POVTOR_BEZ_ASLR (умолч. 1); 0 — отрицательный контроль.
 */
#define POVTOR_OBRAZ_BAZA 0x170000000ull

/* ★ Раскладка заголовка записи проверяется КОМПИЛЯТОРОМ, а не глазами.
 * Поля версии 3 (n_threads, threads_off) взяты из хвостового запаса, поэтому
 * заголовок обязан остаться ровно 256 байт: сдвинься он — старые записи
 * разбирались бы как чужие байты молча. */
typedef char povtor_zagolovok_256[(sizeof(hb_record_header_t) == 256) ? 1 : -1];
typedef char povtor_sobytie_32[(sizeof(hb_record_event_t) == 32) ? 1 : -1];

#define HOST_PAGE 16384u
#define LIFT_WINDOW 256u
/* Полоса, в которой повторяющий держит СВОЁ: саму запись и таблицу событий.
 * Выбрана вне всех полос записи HK — см. разбор у mmap записи. */
#define POVTOR_SCRATCH 0x0000500000000000ull
#define POVTOR_SCRATCH_STEP 0x0000060000000000ull

/* ─────────────────────────── разбор записи ───────────────────────────── */

typedef struct {
    uint32_t kind;
    uint32_t site;
    uint32_t tid;               /* номер потока (версия 3); у 1 и 2 всегда 0 */
    uint64_t pc;
    int      has_state;
    const hb_record_state_t* state;
    uint32_t n_writes;
    const uint8_t* writes;      /* поток { u64 addr; u32 len; байты } */
    /* ★★★ ЛЕЙН ЗАПИСЬ-ХОЗЯИНА: У ПОТОКА ЗАПИСЕЙ НЕ БЫЛО ГРАНИЦЫ.
     * `apply_writes` шёл по `n_writes` от `writes` и НИ РАЗУ не сверялся с
     * концом события: битое `n_writes` или битая длина уводили чтение за
     * пределы события и дальше по файлу — молча, потому что запись
     * отображена целиком и страницы читаются. Конец события хранится рядом с
     * началом, и каждая запись проверяется об него. */
    const uint8_t* writes_end;
    const hb_record_maprec_t* map;  /* HB_REC_MAP / HB_REC_UNMAP (версия 2) */
} rec_ev_t;

/* ★★★★ ПОВТОР-6, ШАГ 2: ПОТОКОВ БОЛЬШЕ ОДНОГО.
 *
 * Запись версии 3 несёт номер потока у каждого события. Повтор держит СВОЙ
 * контекст и СВОЮ среду JIT на каждый поток, а память гостя у них ОДНА — ровно
 * как в живом процессе. Переплетение по времени берётся из порядка событий в
 * файле: писатель обязан выдавать `seq` и писать событие под одним замком
 * (см. hb_record.h), поэтому порядок в файле И ЕСТЬ порядок во времени.
 *
 * Что от этого меняется в устройстве повтора, кроме массива контекстов:
 * ПАРА «выход — возврат от хоста» ищется ТОЛЬКО СРЕДИ СОБЫТИЙ СВОЕГО ПОТОКА.
 * Иначе событие чужого потока, вклинившееся между выходом и возвратом, рвёт
 * пару, и результат хоста не подставляется вовсе — тот же класс отказа, что
 * ПОВТОР-4 поймал на событиях карты. */
#define POVTOR_MAX_TID 256u
static uint64_t g_tid_seen = 1;             /* сколько номеров встретилось */
static uint64_t g_tid_events[POVTOR_MAX_TID];
/* Событие, уже съеденное как «возврат от хоста» своей пары. Отдельный признак
 * нужен потому, что перепрыгнуть через него индексом (k = nk + 1) нельзя: между
 * ним и текущим событием лежат события ЧУЖИХ потоков, и прыжок съел бы их. */
static uint8_t* g_consumed;

static uint8_t*  g_file;
static size_t    g_file_len;
static hb_record_header_t g_hdr;
static rec_ev_t* g_ev;
static uint64_t  g_ev_n;
static uint64_t  g_map_ev_n;      /* сколько событий карты нашлось в записи */

/* ★★★★ ЛЕЙН ЗАПИСЬ-ХОЗЯИНА, 07.09.2026 — СТРОГИЙ РЕЖИМ.
 *
 * Зачем он нужен, числом. Прогон `--sobytij 4000` на записи d6b79fb8abc954b2
 * печатал `otkazov_gostya=36` и ВОЗВРАЩАЛ НОЛЬ. То есть повтор, у которого
 * гость 36 раз упал по нулевому адресу, отчитывался успехом. Причин
 * молчаливого успеха было четыре, и все четыре — в этом файле:
 *
 *   1. `apply_writes` увеличивал `zapisej_primeneno` ДАЖЕ КОГДА
 *      `hb_memory_can_write` отказал: число «применено 427» означало
 *      «просмотрено 427», и разницы было не видно НИКАК;
 *   2. поток записей события не имел границы (см. `writes_end` выше);
 *   3. `ctx->pc == 0 || 0xffff0000` принималось за «гость ушёл к хосту»
 *      БЕЗУСЛОВНО и считалось СОВПАДЕНИЕМ — даже там, где в записи никакого
 *      внешнего возврата нет;
 *   4. разбор файла обрывался тремя разными `break` молча, и число событий
 *      просто оказывалось меньше заголовочного.
 *
 * Строгий режим (`--strogo`, гейт MACRUNNER_POVTOR_STROGO) не добавляет новой
 * ловли — он ОТКАЗЫВАЕТ там, где прежний повтор шёл дальше:
 *   • steering запрещён: расхождение = конец, а не подсказка;
 *   • синтетическая нулевая карта (дыры) не заводится;
 *   • новые области по отказу нулями НЕ заводятся;
 *   • PC=0/sentinel принимается ТОЛЬКО если в записи на этом месте стоит
 *     типизированный внешний возврат (ВЫХОД, за которым ВХОД на другом pc);
 *   • любая неудача применения записи, любой отказ гостя, любой обрыв разбора
 *     -> строка NEDEJSTVITELNO и НЕНУЛЕВОЙ код возврата.
 *
 * Снисходительные варианты остаются — но теперь они ЯВНО диагностические:
 * итоговая строка REZHIM называет режим, а `--strogo` — единственный, чей
 * PASS что-то означает. */
static int      g_strogo;             /* строгий режим */
static uint64_t g_nedejstvitelno;     /* сколько причин недействительности */
static uint64_t g_wr_otkazano;        /* записей, которые НЕ применились */
static uint64_t g_wr_bajt_otkazano;
static uint64_t g_wr_ne_legli;        /* применили, а в памяти не то */
static uint64_t g_razbor_oborvan;     /* разбор потока событий оборвался */
static const char* g_razbor_prichina = "-";
static uint64_t g_razbor_sobytij_v_fajle;
static uint64_t g_seq_ne_po_poryadku;

/* Часовой: адрес гостя, за которым следим на каждом событии. 0 = выключен. */
static uint64_t g_chasovoj;
static uint32_t g_chasovoj_n = 8;
static unsigned char g_chasovoj_pred[32];
static int      g_chasovoj_bylo;
static uint64_t g_chasovoj_izmenenij;

/* Одна причина недействительности. Печатается СРАЗУ (лог убитого прогона
 * обрывается на любом месте) и считается. */
static void nedejstvitelno(const char* chto, const char* kak,
                           unsigned long long a, unsigned long long b)
{
    g_nedejstvitelno++;
    if (g_nedejstvitelno <= 64)
        fprintf(stderr, "hb_povtor: NEDEJSTVITELNO %s: %s (0x%llx / %llu)\n",
                chto, kak, a, b);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ─────────────────────── доведение страниц по отказу ─────────────────── */

static void prov_note(uint64_t page);

static volatile uint64_t g_faults_fixed;
static volatile uint64_t g_faults_failed;
static volatile uint64_t g_faults_guest;   /* отказов, отданных движку как гостевые */
static volatile uint64_t g_faults_v_zapisi, g_faults_novye;
static volatile uintptr_t g_last_fault_page;
static volatile uint64_t g_same_fault;
static uint64_t g_fault_cap = 1000000;
static hb_memory_t* g_mem;      /* для регистрации доведённых страниц */
/* Что делал повтор в момент отказа. Без этих трёх чисел «SIGSEGV по нулю» —
 * это сообщение без адреса: не видно ни какой блок исполнялся, ни насколько
 * далеко ушёл повтор, а значит нечего и чинить. */
static volatile uint64_t g_cur_pc, g_cur_ev, g_cur_disp;

/* Отсортированный список полос ЗАПИСИ — для обработчика сигнала. Массив готов
 * заранее и только читается, поэтому обращение к нему из обработчика безопасно. */
static uint64_t* g_span_lo;
static uint64_t* g_span_hi;
static uint64_t  g_span_n;

static int v_zapisi(uintptr_t a)
{
    uint64_t lo = 0, hi = g_span_n;
    while (lo < hi) {
        uint64_t m = (lo + hi) / 2;
        if ((uint64_t)a < g_span_lo[m]) hi = m;
        else if ((uint64_t)a >= g_span_hi[m]) lo = m + 1;
        else return 1;
    }
    return 0;
}

/* Отказ по адресу, которого нет в записи. Причин ровно две, и обе НАДО ВИДЕТЬ,
 * а не глушить: либо окна записи не поймали запись хоста (тогда гость считает
 * мусор и вычисляет мимо), либо область памяти не легла на свой адрес. Страница
 * доводится нулями, чтобы работа шла дальше, и КАЖДАЯ такая доводка считается —
 * по её числу и судят, годен ли замер. */
static void fault_handler(int sig, siginfo_t* si, void* uc)
{
    uintptr_t a = (uintptr_t)si->si_addr;
    uintptr_t p = a & ~(uintptr_t)(HOST_PAGE - 1);
    (void)uc;

    /* ★★★ ГРАНИЦА, РАДИ КОТОРОЙ ПРИБОР ЧЕГО-ТО СТОИТ.
     *
     * Отказ по адресу, КОТОРЫЙ ЕСТЬ В ЗАПИСИ, — это ДЫРА ЗАПИСИ: страница
     * должна была лечь и не легла. Такую страницу доводим и СЧИТАЕМ: по этому
     * числу и судят, годен ли повтор.
     *
     * Отказ по адресу, которого в записи НЕТ (мусор вроде 0xffffffffffffffe8,
     * ноль, адрес ниже 4 ГБ в __PAGEZERO), — это обычное гостевое
     * разыменование, и место ему в гостевом пути отказа, как в живом прогоне.
     * Доотображать такое значило бы кормить гостя нулями и звать это успехом.
     *
     * Первая редакция различала их порогом 4 ГБ и умерла на первом же
     * 0xffffffffffffffe8: порог отвечал на вопрос «можно ли отобразить», а
     * нужен ответ на «есть ли это в записи». */
    if (a < 0x100000000ull || a >= 0x00007fffffff0000ull ||
        g_faults_fixed >= g_fault_cap) {
        /* ★ ОТКАЗ ПО НУЛЮ ОТДАЁТСЯ ДВИЖКУ, а не убивает повтор.
         *
         * Ровно так поступает живой прогон: signal_arm64.c сперва спрашивает
         * `hb_jit_runtime_handle_signal_fault`, и если отказ случился в выпущенном
         * коде, движок забирает его себе и возвращает управление своему кадру.
         * Без этого повтор умирал на первом же разыменовании нуля у гостя — а
         * ноль по адресу 0 доотобразить НЕЛЬЗЯ (PAGEZERO), значит это не «дыра
         * записи», а обычный гостевой отказ, который движок умеет пережить. */
        uint64_t host_pc = 0;
#if defined(__APPLE__) && defined(__aarch64__)
        {
            const ucontext_t* u = (const ucontext_t*)uc;
            if (u && u->uc_mcontext) host_pc = (uint64_t)u->uc_mcontext->__ss.__pc;
        }
#endif
        g_faults_guest++;
        /* ★ ПОВТОР-5: ГОСТЕВОЙ ОТКАЗ НАДО ВИДЕТЬ ПО АДРЕСУ, А НЕ ПО ЧИСЛУ.
         * Ровно эти отказы разводят руки замера: рука с нативной памятью ловит
         * их сигналом хоста, рука без неё проверяет права программно и сигнала
         * не получает — пути расходятся. По одному числу нельзя сказать, это
         * «недостающая область» (чинится заведением) или «гость посчитал мусор»
         * (чинится полнотой записи). Печатаем первые восемь. */
        if (g_faults_guest <= 8)
            fprintf(stderr, "hb_povtor: OTKAZ-GOSTYA n=%llu addr=%p guest_pc=0x%llx "
                    "sobytie=%llu dispatchej=%llu\n",
                    (unsigned long long)g_faults_guest, si->si_addr,
                    (unsigned long long)g_cur_pc,
                    (unsigned long long)g_cur_ev, (unsigned long long)g_cur_disp);
        if (host_pc && hb_jit_runtime_handle_signal_fault(host_pc, (uint64_t)a, sig, uc))
            return;
        g_faults_failed++;
        fprintf(stderr, "hb_povtor: OTKAZ signal=%d addr=%p ne ispravim "
                "(dovedeno=%llu) guest_pc=0x%llx host_pc=0x%llx sobytie=%llu "
                "dispatchej=%llu\n",
                sig, si->si_addr, (unsigned long long)g_faults_fixed,
                (unsigned long long)g_cur_pc, (unsigned long long)host_pc,
                (unsigned long long)g_cur_ev, (unsigned long long)g_cur_disp);
        fflush(stderr);
        _exit(97);
    }
    /* Сначала — снять защиту: страница может быть отображена, но без прав.
     * mmap MAP_FIXED по такому адресу ЗАТЁР бы содержимое, и повтор поехал бы
     * на нулях, ничего об этом не сказав. */
    /* Сторож зацикливания: одна и та же страница, доведённая много раз подряд,
     * означает, что доводка НЕ ПОМОГАЕТ, и молча крутить её — худшее, что можно
     * сделать. Считаем и отдаём отказ движку. */
    if (p == g_last_fault_page) {
        if (++g_same_fault > 64) {
            uint64_t host_pc2 = 0;
            const ucontext_t* u2 = (const ucontext_t*)uc;
            if (u2 && u2->uc_mcontext) host_pc2 = (uint64_t)u2->uc_mcontext->__ss.__pc;
            g_faults_guest++;
            if (host_pc2 && hb_jit_runtime_handle_signal_fault(host_pc2, (uint64_t)a, sig, uc))
                return;
        }
    } else {
        g_last_fault_page = p;
        g_same_fault = 0;
    }
    /* Разделяем ДВА разных случая, потому что чинят их по-разному:
     *   дыра записи   — адрес В записи есть, а страница не легла;
     *   память ПОСЛЕ  — адреса в записи нет вовсе: выделено уже во время
     *                   отрезка (новый стек, куча, отображение файла).
     * Слипшись, они дали бы одно число, по которому нельзя судить ни о полноте
     * образа, ни о длине отрезка. */
    if (v_zapisi(a)) g_faults_v_zapisi++; else g_faults_novye++;
    if (mprotect((void*)p, HOST_PAGE, PROT_READ | PROT_WRITE) == 0) {
        g_faults_fixed++;
        return;
    }
    if (mmap((void*)p, HOST_PAGE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0) != MAP_FAILED) {
        if (g_mem) hb_memory_map(g_mem, (hb_gva_t)p, HOST_PAGE,
                                 HB_PERM_READ | HB_PERM_WRITE);
        prov_note((uint64_t)p);
        g_faults_fixed++;
        return;
    }
    /* Ни снять защиту, ни отобразить — значит адрес принадлежит самому
     * повторяющему (его образ, PAGEZERO). Отдаём отказ движку, как и всё
     * прочее неисправимое: повтор обязан доработать до конца и НАЗВАТЬ числа,
     * а не умереть на середине, оставив вопрос «докуда дошёл» без ответа. */
    {
        uint64_t host_pc3 = 0;
        const ucontext_t* u3 = (const ucontext_t*)uc;
        if (u3 && u3->uc_mcontext) host_pc3 = (uint64_t)u3->uc_mcontext->__ss.__pc;
        g_faults_guest++;
        if (host_pc3 && hb_jit_runtime_handle_signal_fault(host_pc3, (uint64_t)a, sig, uc))
            return;
    }
    g_faults_failed++;
    fprintf(stderr, "hb_povtor: OTKAZ signal=%d addr=%p mmap errno=%d guest_pc=0x%llx "
            "sobytie=%llu dispatchej=%llu\n",
            sig, si->si_addr, errno, (unsigned long long)g_cur_pc,
            (unsigned long long)g_cur_ev, (unsigned long long)g_cur_disp);
    fflush(stderr);
    _exit(98);
}

static void install_fault_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;   /* NODEFER — см. урок siglongjmp */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

/* ───────────────────────── раскладка памяти ──────────────────────────── */

static uint64_t g_reg_mapped, g_reg_collided, g_reg_skipped, g_reg_denied;
static uint64_t g_bytes_mapped, g_bytes_collided;

/* ★★★ ПОВТОР-4: СПИСОК ОБЛАСТЕЙ, КОТОРЫЕ ДЕЙСТВИТЕЛЬНО ЛЕГЛИ.
 *
 * Нужен затем, чтобы память гостя можно было ВЕРНУТЬ В СНИМОК перед каждым
 * повторным проходом. Без возврата `--repeat` мерил не то же самое: проход 2
 * шёл по памяти, испорченной проходом 1, и делал 2 570 шагов вместо 7 463
 * (измерено). Сравнивать время таких проходов — сравнивать разные работы. */
static uint8_t* g_reg_ok;

/* Страницы, доведённые по отказу или заведённые как «новая область». Перед
 * повторным проходом они возвращаются в нули: свежая память Windows и есть
 * нули, и именно такой её увидит гость на следующем проходе. */
#define POVTOR_PROV_CAP 65536u
static uint64_t* g_prov_pages;
static volatile uint64_t g_prov_n;

static void prov_note(uint64_t page)
{
    if (g_prov_pages && g_prov_n < POVTOR_PROV_CAP) g_prov_pages[g_prov_n++] = page;
}

#ifdef __APPLE__
/* Свободен ли диапазон. Занятый диапазон НЕ затирается: там лежит наш
 * собственный процесс, и MAP_FIXED поверх него убил бы повторяющего. */
static int range_free(uint64_t base, uint64_t size)
{
    mach_vm_address_t region = (mach_vm_address_t)base;
    mach_vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &region, &rsize,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (kr != KERN_SUCCESS) return 1;             /* выше ничего нет */
    return region >= base + size;                 /* ближайшая область — за нами */
}
#else
static int range_free(uint64_t base, uint64_t size) { (void)base; (void)size; return 1; }
#endif

/* ★★★★ ПОВТОР-6, ШАГ 4: ПЕРЕПИСЬ СОБСТВЕННОЙ КАРТЫ ПОВТОРЯЮЩЕГО.
 *
 * «122 области не ложатся, их занимает образ повторяющего» — это было
 * УТВЕРЖДЕНИЕ, а не измерение: печатались только первые 12 столкновений и без
 * имени того, кто мешает. Чинить, не зная имени, значит двигать наугад.
 *
 * Здесь печатается ВСЯ карта нашего процесса с именем файла у каждой области
 * (proc_regionfilename). Дальше перепись сличается с таблицей областей записи
 * ВНЕ повтора, вторым счётом — и по имени видно, что движется линковкой
 * (наш образ), а что не движется никогда (общий кеш dyld, ядро).
 */
#ifdef __APPLE__
#include <libproc.h>
static int g_karta_full;   /* печатать ВСЕ вердикты укладки, а не первые 12 */

/* ★ ПРИБОР БЕЗУСЛОВНЫЙ: где лежит образ и пускает ли ядро в самый низ.
 * Проверяется ДО укладки областей — иначе MAP_FIXED затёр бы уже легшую
 * область. Печатается ВСЕГДА: без этой строки «легло 554» есть число без
 * условий, при которых оно получено (сдвиг ASLR гулял на 72 МБ). */
static void pechat_niza(void)
{
    /* ★ СНАЧАЛА спросить карту, ПОТОМ класть. Со снятым ASLR наш собственный
     * образ лежит ровно по 0x100000000, и MAP_FIXED туда затирает наш же
     * __TEXT — процесс умирает без единой строки. Поймано на себе. */
    int svobodno = range_free(0x100000000ull, HOST_PAGE);
    void* p = svobodno ? mmap((void*)(uintptr_t)0x100000000ull, HOST_PAGE,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0)
                       : MAP_FAILED;
    int ok = (p != MAP_FAILED);
    if (ok) munmap(p, (size_t)HOST_PAGE);
    printf("hb_povtor: OBRAZ main=%p polosa=0x%llx niz_0x100000000=%s (svobodno=%d) aslr_snyat=%s\n",
           (void*)(uintptr_t)&pechat_niza, (unsigned long long)POVTOR_OBRAZ_BAZA,
           ok ? "da" : "net", svobodno,
           getenv("MACRUNNER_POVTOR_ASLR_SNYAT") ? "da" : "net");
    fflush(stdout);
}

static void karta_processa(void)
{
    mach_vm_address_t addr = 0;
    uint64_t n = 0;
    char name[1024];
    for (;;) {
        mach_vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &sz,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &cnt, &obj);
        if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
        if (kr != KERN_SUCCESS) break;
        name[0] = 0;
        if (proc_regionfilename(getpid(), (uint64_t)addr, name, sizeof(name)) <= 0)
            name[0] = 0;
        printf("hb_povtor: MOYA base=0x%llx end=0x%llx size=0x%llx prot=%d max=%d %s\n",
               (unsigned long long)addr, (unsigned long long)(addr + sz),
               (unsigned long long)sz, info.protection, info.max_protection,
               name[0] ? name : "-");
        addr += sz;
        if (++n > 100000) break;
    }
    fflush(stdout);
}
#else
static int g_karta_full;
static void karta_processa(void) { }
#endif

/* Разложить ненулевые страницы области по её адресам. Нулевые страницы в
 * записи не лежат — их содержимое и есть нули. */
static void region_fill(const hb_record_region_t* r)
{
    const uint8_t* bm = g_file + r->bitmap_off;
    const uint8_t* data = g_file + r->data_off;
    uint64_t pages = (r->size + g_hdr.page_bytes - 1) / g_hdr.page_bytes;
    uint64_t k, off = 0;
    for (k = 0; k < pages; k++) {
        uint64_t plen = r->size - k * g_hdr.page_bytes;
        if (plen > g_hdr.page_bytes) plen = g_hdr.page_bytes;
        if (!(bm[k >> 3] & (1u << (k & 7)))) continue;
        memcpy((void*)(uintptr_t)(r->base + k * g_hdr.page_bytes),
               data + off, (size_t)plen);
        off += plen;
    }
}

static void map_regions(void)
{
    const hb_record_region_t* tbl =
        (const hb_record_region_t*)(g_file + g_hdr.regions_off);
    uint64_t i;

    /* Полосы записи — в отдельном отображении рядом со своей памятью, чтобы не
     * тянуть кучу в полосы гостя. Таблица уже отсортирована по базе: её так
     * заполнял обход mach_vm_region. */
    g_span_lo = (uint64_t*)mmap((void*)(POVTOR_SCRATCH + 2 * POVTOR_SCRATCH_STEP),
                                (size_t)(2 * g_hdr.n_regions + 2) * sizeof(uint64_t),
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (g_span_lo == MAP_FAILED) { g_span_lo = NULL; g_span_n = 0; }
    else {
        g_span_hi = g_span_lo + g_hdr.n_regions + 1;
        for (i = 0; i < g_hdr.n_regions; i++) {
            g_span_lo[i] = tbl[i].base;
            g_span_hi[i] = tbl[i].base + tbl[i].size;
        }
        g_span_n = g_hdr.n_regions;
    }

    /* Отметки «легло» и список доведённых страниц — тоже в своей полосе, чтобы
     * не тянуть кучу повторяющего в полосы гостя. */
    g_reg_ok = (uint8_t*)mmap((void*)(POVTOR_SCRATCH + 3 * POVTOR_SCRATCH_STEP),
                              (size_t)g_hdr.n_regions + 16,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (g_reg_ok == MAP_FAILED) g_reg_ok = NULL;
    g_prov_pages = (uint64_t*)mmap((void*)(POVTOR_SCRATCH + 4 * POVTOR_SCRATCH_STEP),
                                   POVTOR_PROV_CAP * sizeof(uint64_t),
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (g_prov_pages == MAP_FAILED) g_prov_pages = NULL;

    for (i = 0; i < g_hdr.n_regions; i++) {
        const hb_record_region_t* r = &tbl[i];
        uint64_t base = r->base & ~(uint64_t)(HOST_PAGE - 1);
        uint64_t end = (r->base + r->size + HOST_PAGE - 1) & ~(uint64_t)(HOST_PAGE - 1);
        uint64_t len = end - base;
        void* p;

        if (!(r->flags & HB_REC_REG_DUMPED)) { g_reg_skipped++; continue; }
        if (!range_free(base, len)) {
            /* Область не легла на свой адрес: там уже лежит сам повторяющий.
             * Печатаются первые — иначе «столкнулось 164» это число без имён,
             * по которому нельзя понять, потеряна ли память ГОСТЯ или чужая. */
            if (g_karta_full || g_reg_collided < 12)
                fprintf(stderr, "hb_povtor: stolknulos base=0x%llx size=0x%llx perm=%u\n",
                        (unsigned long long)r->base, (unsigned long long)r->size, r->perm);
            g_reg_collided++;
            g_bytes_collided += r->size;
            continue;
        }
        p = mmap((void*)(uintptr_t)base, (size_t)len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != base) {
            /* Отдельная ветвь от занятости: тут карта СКАЗАЛА «свободно», а ядро
             * не дало. Различать обязательно — это разные причины и разные
             * починки, а слипшись они дали бы одно число без смысла. */
            if (g_karta_full || g_reg_denied < 12)
                fprintf(stderr, "hb_povtor: ne_lozhitsya base=0x%llx size=0x%llx "
                        "perm=%u errno=%d got=%p\n",
                        (unsigned long long)r->base, (unsigned long long)r->size,
                        r->perm, errno, p);
            if (p != MAP_FAILED) munmap(p, (size_t)len);
            g_reg_denied++;
            g_bytes_collided += r->size;
            continue;
        }
        /* Разложить ненулевые страницы по карте. Нулевые страницы уже нули —
         * это и есть их содержимое, а не потеря. */
        region_fill(r);
        hb_memory_map(g_mem, (hb_gva_t)r->base, (size_t)r->size, (hb_perm_t)r->perm);
        if (g_reg_ok) g_reg_ok[i] = 1;
        if (g_karta_full)
            fprintf(stderr, "hb_povtor: leglo base=0x%llx size=0x%llx perm=%u\n",
                    (unsigned long long)r->base, (unsigned long long)r->size, r->perm);
        g_reg_mapped++;
        g_bytes_mapped += r->size;
    }
}

/* ★★★★ ПОВТОР-4: ДЫРЫ КАРТЫ ЗАВОДЯТСЯ ЗАРАНЕЕ, А НЕ ПО ОТКАЗУ.
 *
 * Измерено на записи HK: точный участок кончался на 900-м заходе, и кончался он
 * из-за РОВНО ОДНОЙ страницы (`novyh=1` уже на 950 заходах) — обращения по
 * адресу 0x114300510, которого в образе памяти нет. Страница доводилась ПО
 * ОТКАЗУ, то есть через сигнал хоста, а цена сигнала у двух рук замера РАЗНАЯ:
 * рука с нативной памятью ловит отказ сигналом (~10 мкс), рука без неё
 * проверяет права в помощнике программно и возвращает отказ дёшево. Одна
 * страница на 900 заходов — и руки уже делают разную работу (8 449 шагов
 * против 9 943), а приёмка честно отказывает.
 *
 * Отсюда ход уровня 4: не удешевлять отказ, а СНЯТЬ ЕГО ВОВСЕ. Дыры карты
 * между записанными областями заводятся нулями ДО начала замера. Нули здесь не
 * выдумка и не ухудшение: реактивный путь заводил ровно нулями, свежая память
 * Windows и есть нули — меняется только МОМЕНТ (до замера вместо во время) и
 * то, что обе руки получают ОДНУ И ТУ ЖЕ карту.
 *
 * Заводятся: (1) дыры между соседними областями не шире потолка; (2) области,
 * пропущенные записью по потолку выгрузки — они В ТАБЛИЦЕ есть, база и размер
 * известны, не было только содержимого.
 *
 * Страницы физически не выделяются: MAP_ANON отдаёт их по первому касанию.
 * 2,0 ГБ адресов при потолке 256 МБ стоят нулей резидентной памяти. */
static uint64_t g_hole_n, g_hole_bytes, g_skip_mapped, g_skip_bytes;

static uint64_t env_u64(const char* name, uint64_t def)
{
    const char* v = getenv(name);
    char* e = NULL;
    unsigned long long x;
    if (!v || !*v) return def;
    x = strtoull(v, &e, 0);
    if (e == v) return def;
    return (uint64_t)x;
}

static int hole_map_one(uint64_t base, uint64_t size, uint64_t* n, uint64_t* bytes)
{
    void* p;
    if (!size) return 0;
    if (!range_free(base, size)) return 0;
    p = mmap((void*)(uintptr_t)base, (size_t)size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != base) {
        if (p != MAP_FAILED) munmap(p, (size_t)size);
        return 0;
    }
    hb_memory_map(g_mem, (hb_gva_t)base, (size_t)size,
                  (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE));
    (*n)++;
    *bytes += size;
    return 1;
}

static void map_holes(void)
{
    const hb_record_region_t* tbl =
        (const hb_record_region_t*)(g_file + g_hdr.regions_off);
    uint64_t cap = env_u64("MACRUNNER_POVTOR_HOLE_MAX", 0x10000000ull);
    uint64_t i;

    if (!env_u64("MACRUNNER_POVTOR_HOLES", 1)) return;

    /* Пропущенные по потолку области: база и размер известны, нет содержимого. */
    for (i = 0; i < g_hdr.n_regions; i++) {
        const hb_record_region_t* r = &tbl[i];
        uint64_t base, end;
        if (r->flags & HB_REC_REG_DUMPED) continue;
        base = r->base & ~(uint64_t)(HOST_PAGE - 1);
        end = (r->base + r->size + HOST_PAGE - 1) & ~(uint64_t)(HOST_PAGE - 1);
        hole_map_one(base, end - base, &g_skip_mapped, &g_skip_bytes);
    }

    /* Дыры между соседними областями. Таблица отсортирована по базе — её так
     * заполнял обход mach_vm_region. */
    for (i = 0; i + 1 < g_hdr.n_regions; i++) {
        uint64_t end = tbl[i].base + tbl[i].size;
        uint64_t next = tbl[i + 1].base;
        uint64_t base = (end + HOST_PAGE - 1) & ~(uint64_t)(HOST_PAGE - 1);
        uint64_t top = next & ~(uint64_t)(HOST_PAGE - 1);
        if (top <= base || top - base > cap) continue;
        hole_map_one(base, top - base, &g_hole_n, &g_hole_bytes);
    }
}

/* ★★★ ВОЗВРАТ ПАМЯТИ ГОСТЯ В СНИМОК — то, без чего `--repeat` мерит разное.
 *
 * Каждая легшая область перекрывается свежим MAP_ANON (это отдаёт ей нули
 * даром, страницы физически не трогаются) и заново заполняется ненулевыми
 * страницами записи. Доведённые страницы возвращаются в нули отдельно: они
 * лежат ВНЕ записанных областей, и заполнять их неоткуда.
 *
 * Возврат делается ВНЕ замеряемого промежутка — время прохода меряется только
 * вокруг самого повтора. Полноту возврата видно числом: у всех проходов обязано
 * совпасть число шагов. Не совпало — значит состояние осталось где-то ещё, и
 * это отказ, а не «примерно то же самое». */
static void restore_memory(void)
{
    const hb_record_region_t* tbl =
        (const hb_record_region_t*)(g_file + g_hdr.regions_off);
    uint64_t i;

    for (i = 0; i < g_hdr.n_regions; i++) {
        const hb_record_region_t* r = &tbl[i];
        uint64_t base, end;
        if (!g_reg_ok || !g_reg_ok[i]) continue;
        base = r->base & ~(uint64_t)(HOST_PAGE - 1);
        end = (r->base + r->size + HOST_PAGE - 1) & ~(uint64_t)(HOST_PAGE - 1);
        if (mmap((void*)(uintptr_t)base, (size_t)(end - base),
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0) == MAP_FAILED)
            continue;
        region_fill(r);
    }
    for (i = 0; i < g_prov_n; i++)
        (void)mmap((void*)(uintptr_t)g_prov_pages[i], HOST_PAGE,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
}

/* ★★★★ ИЗМЕНЕНИЕ КАРТЫ ПАМЯТИ ИЗ ЗАПИСИ (версия 2).
 *
 * Событие HB_REC_MAP означает: в этот момент отрезка у гостя ПОЯВИЛАСЬ область.
 * Повтор заводит её нулями — содержимого в записи нет и быть не должно
 * (свежевыделенная память Windows и есть нули; всё, что записал хост, приезжает
 * окнами записи).
 *
 * HB_REC_UNMAP снимает область с УЧЁТА ДВИЖКА, но НЕ отдаёт страницы ядру.
 * Граница названа вслух: отдать их означало бы, что любое последующее обращение
 * убивает повторяющего, а выигрыш — только в верности отказа, которого мы и так
 * не проверяем. Учёт движка при этом верен: hb_memory_find_region перестаёт
 * находить область, и путь отказа гостя идёт как в живом прогоне. */
static uint64_t g_map_done, g_map_bytes, g_map_failed, g_unmap_done;

static void apply_map(const rec_ev_t* e)
{
    uint64_t base, end;
    void* q;

    if (!e->map) { g_map_failed++; return; }
    if (e->kind == HB_REC_UNMAP) {
        hb_memory_unmap(g_mem, (hb_gva_t)e->map->base);
        g_unmap_done++;
        return;
    }
    base = e->map->base & ~(uint64_t)(HOST_PAGE - 1);
    end = (e->map->base + e->map->size + HOST_PAGE - 1) & ~(uint64_t)(HOST_PAGE - 1);
    if (end <= base) { g_map_failed++; return; }
    if (hb_memory_find_region(g_mem, (hb_gva_t)base)) return;  /* уже есть */
    if (!range_free(base, end - base)) { g_map_failed++; return; }
    q = mmap((void*)(uintptr_t)base, (size_t)(end - base), PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (q == MAP_FAILED || (uint64_t)(uintptr_t)q != base) {
        if (q != MAP_FAILED) munmap(q, (size_t)(end - base));
        g_map_failed++;
        return;
    }
    hb_memory_map(g_mem, (hb_gva_t)base, (size_t)(end - base),
                  (hb_perm_t)e->map->perm);
    prov_note(base);
    g_map_done++;
    g_map_bytes += end - base;
}

/* Пройти события карты, применяя их, и вернуть индекс ПЕРВОГО события хода
 * исполнения. Нужно затем, что подстановка результата хоста смотрит на
 * СЛЕДУЮЩЕЕ событие: событие карты, вклинившееся между выходом и возвратом,
 * иначе рвёт эту пару, и вызов хоста не подставляется вовсе. Поймано на
 * синтетической записи: `hosta_primeneno` падало с 1 до 0, а расхождений
 * становилось два. Порядок при этом правильный: область обязана появиться ДО
 * того, как хост в неё запишет. */
/* ★★★★ ПОВТОР-6: ПАРА «ВЫХОД — ВОЗВРАТ ОТ ХОСТА» ИЩЕТСЯ В СВОЁМ ПОТОКЕ.
 *
 * Подстановка результата хоста смотрит на СЛЕДУЮЩЕЕ событие. При одном потоке
 * следующее событие в файле и есть следующее событие потока; при нескольких —
 * между выходом и возвратом стоят события ЧУЖИХ потоков, и «следующее по
 * файлу» рвёт пару. Тот же класс отказа ПОВТОР-4 уже ловил на событиях карты:
 * `hosta_primeneno` падало с 1 до 0, а расхождений становилось два.
 *
 * События карты СВОЕГО потока по дороге применяются (порядок «область
 * появилась ДО записи хоста в неё» обязателен); чужие события НЕ ТРОГАЮТСЯ —
 * до них дойдёт главный цикл. */
static uint64_t next_same_tid(uint64_t i, uint32_t tid)
{
    while (i < g_ev_n) {
        if (g_ev[i].tid != tid) { i++; continue; }
        if (g_ev[i].kind == HB_REC_MAP || g_ev[i].kind == HB_REC_UNMAP) {
            apply_map(&g_ev[i]);
            g_consumed[i] = 1;
            i++;
            continue;
        }
        return i;
    }
    return i;
}

/* ★ Тот же обход, но БЕЗ применения: нужен там, где надо только ПОСМОТРЕТЬ,
 * что стоит дальше, и применять события карты ещё рано. */
static uint64_t peek_maps(uint64_t i)
{
    while (i < g_ev_n &&
           (g_ev[i].kind == HB_REC_MAP || g_ev[i].kind == HB_REC_UNMAP)) i++;
    return i;
}

/* Стоит ли на месте события `k` ТИПИЗИРОВАННЫЙ внешний возврат: ВЫХОД, за
 * которым ВХОД на ДРУГОМ pc. Ровно это и значит «исполнялся хост»; равенство
 * pc означает перевод блока, а не вызов наружу (см. заголовок hb_record.h). */
static int vneshnij_vozvrat(uint64_t k)
{
    uint64_t nk;
    if (k >= g_ev_n || g_ev[k].kind != HB_REC_EXIT) return 0;
    nk = peek_maps(k + 1);
    return nk < g_ev_n && g_ev[nk].kind == HB_REC_ENTER &&
           g_ev[nk].pc != g_ev[k].pc;
}

/* ───────────────── происхождение адреса: поля, а не догадка ──────────── */

/* Где адрес живёт в ЗАПИСИ: область, права, была ли его страница ненулевой в
 * снимке, и — главное — писал ли кто-нибудь в неё за весь отрезок.
 *
 * Зачем эти три поля вместе. «Ноль» имеет ТРИ разных происхождения, и по
 * самому нулю они неразличимы:
 *   а) адреса нет в записи вовсе                  -> область не снята;
 *   б) страница была нулевой в снимке и осталась  -> значение появилось ПОЗЖЕ,
 *      и раз записей в неё нет, его положил тот, кого запись не видит;
 *   в) страница была ненулевой, но запись её потеряла -> дефект снимка.
 * Разбор ПОВТОР-4 назвал причиной (в) то, что оказалось (б) — потому что
 * различать было нечем. */
static void proishozhdenie(const char* imya, uint64_t a)
{
    const hb_record_region_t* tbl =
        (const hb_record_region_t*)(g_file + g_hdr.regions_off);
    uint64_t i, zapisej = 0, poslednyaya = 0;
    const hb_record_region_t* r = NULL;

    for (i = 0; i < g_hdr.n_regions; i++)
        if (tbl[i].base <= a && a < tbl[i].base + tbl[i].size) { r = &tbl[i]; break; }

    if (!r) {
        fprintf(stderr, "hb_povtor: PROISHOZHDENIE %s addr=0x%llx OBLASTI V ZAPISI NET\n",
                imya, (unsigned long long)a);
        return;
    }
    {
        uint64_t pg = g_hdr.page_bytes ? g_hdr.page_bytes : 4096u;
        uint64_t idx = (a - r->base) / pg;
        int nenulevaya = 0;
        if (r->bitmap_bytes && (idx >> 3) < r->bitmap_bytes)
            nenulevaya = (g_file[r->bitmap_off + (idx >> 3)] >> (idx & 7)) & 1;
        /* Все записи хоста по этому адресу за ВЕСЬ разобранный отрезок.
         * Заодно считается ОБЩЕЕ число записей и байт — их сверка с заголовком
         * и есть проверка того, что читатель идёт по потоку так же, как писатель. */
        uint64_t vsego = 0, vsego_bajt = 0, na_stranice = 0;
        uint64_t pgm = pg ? pg : 4096u;
        for (i = 0; i < g_ev_n; i++) {
            const uint8_t* p = g_ev[i].writes;
            uint32_t w;
            for (w = 0; w < g_ev[i].n_writes; w++) {
                uint64_t wa; uint32_t wl;
                if (p + 12 > g_ev[i].writes_end) break;
                memcpy(&wa, p, 8); memcpy(&wl, p + 8, 4);
                if (p + 12 + (size_t)wl > g_ev[i].writes_end) break;
                vsego++; vsego_bajt += wl;
                if (wa <= a && a < wa + wl) { zapisej++; poslednyaya = i; }
                if (wa < (a - a % pgm) + pgm && wa + wl > (a - a % pgm)) na_stranice++;
                p += (12u + wl + 7u) & ~7u;
            }
        }
        fprintf(stderr, "hb_povtor: PROISHOZHDENIE %s SVERKA zapisej_prochteno=%llu "
                "(v zagolovke %llu) bajt_prochteno=%llu (v zagolovke %llu) "
                "zapisej_v_etu_stranicu=%llu\n",
                imya, (unsigned long long)vsego,
                (unsigned long long)g_hdr.n_host_writes,
                (unsigned long long)vsego_bajt,
                (unsigned long long)g_hdr.host_write_bytes,
                (unsigned long long)na_stranice);
        fprintf(stderr, "hb_povtor: PROISHOZHDENIE %s addr=0x%llx oblast=[0x%llx+0x%llx) "
                "perm=%u flags=%u stranica=0x%llx nenulevaya_v_snimke=%d "
                "zapisej_hosta_v_etot_adres=%llu poslednyaya_na_sobytii=%llu "
                "est_v_karte_povtora=%d\n",
                imya, (unsigned long long)a, (unsigned long long)r->base,
                (unsigned long long)r->size, r->perm, r->flags,
                (unsigned long long)(a - (a % pg)), nenulevaya,
                (unsigned long long)zapisej, (unsigned long long)poslednyaya,
                g_mem ? (hb_memory_find_region(g_mem, (hb_gva_t)a) ? 1 : 0) : -1);
        if ((r->flags & HB_REC_REG_HOLES) && !nenulevaya)
            fprintf(stderr, "hb_povtor: PROISHOZHDENIE %s VNIMANIE: u oblasti flag HOLES — "
                    "'nulevaya stranica' zdes' mozhet znachit' 'ne prochitalas'\n", imya);
    }
}

/* Первое отличающееся наблюдение — со ВСЕМИ полями происхождения. */
static void pervoe_rashozhdenie(hb_context_t* ctx, const rec_ev_t* ev,
                                uint64_t k, uint64_t disp, uint64_t zahodov)
{
    uint64_t fa = 0; size_t fs = 0; int fw = 0, fv = 0;
    const uint64_t* V = &ctx->regs.x64.rax;
    static const char* NM[16] = { "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp",
                                  "r8","r9","r10","r11","r12","r13","r14","r15" };
    int q;

    hb_memory_last_fault(&fa, &fs, &fw, &fv);
    fprintf(stderr, "hb_povtor: PERVOE-RASHOZHDENIE sobytie=%llu kind=%u site=%u "
            "zhdali_pc=0x%llx stoim_pc=0x%llx zahodov=%llu disp=%llu\n",
            (unsigned long long)k, ev->kind, ev->site,
            (unsigned long long)ev->pc, (unsigned long long)ctx->pc,
            (unsigned long long)zahodov, (unsigned long long)disp);
    /* ★ `valid` печатается ВСЕГДА. Без него `otkaz=0x...` мог быть отказом
     * прошлого захода — на это уже попадались. */
    fprintf(stderr, "hb_povtor: PERVOE-RASHOZHDENIE otkaz_valid=%d otkaz_addr=0x%llx "
            "dlina=%zu zapis=%d perehodnik_stoim=%d\n",
            fv, (unsigned long long)fa, fs, fw,
            (ctx->pc >= HB_IMPORT_THUNK_BASE &&
             ctx->pc < HB_IMPORT_THUNK_BASE +
                       (uint64_t)HB_IMPORT_THUNK_MAX * HB_IMPORT_THUNK_STRIDE) ? 1 : 0);
    for (q = 0; q < 16; q++)
        fprintf(stderr, "hb_povtor: PERVOE-REG %-3s=0x%016llx%s",
                NM[q], (unsigned long long)V[q], (q % 4 == 3) ? "\n" : "  ");
    /* Байты гостя ОБОИХ адресов: где стоим и куда ждали. Разбирать переходник
     * как x86 — ошибка ПОВТОР-4; поэтому байты печатаются СЫРЫМИ, без разбора. */
    {
        uint64_t adr[2]; const char* im[2];
        int j;
        adr[0] = ctx->pc; im[0] = "stoim";
        adr[1] = ev->pc;  im[1] = "zhdali";
        for (j = 0; j < 2; j++) {
            unsigned char bb[24];
            int nb;
            for (nb = 0; nb < 24; nb++) {
                if (!hb_memory_can_read(g_mem, (hb_gva_t)(adr[j] + nb), 1)) break;
                bb[nb] = *(volatile unsigned char*)(uintptr_t)(adr[j] + nb);
            }
            fprintf(stderr, "hb_povtor: PERVOE-BAJTY %s pc=0x%llx n=%d:",
                    im[j], (unsigned long long)adr[j], nb);
            for (q = 0; q < nb; q++) fprintf(stderr, " %02x", bb[q]);
            fprintf(stderr, "\n");
        }
    }
    /* Соседние события — вид, site и pc: по ним видно, был ли тут внешний
     * возврат или перевод блока. */
    {
        uint64_t lo = k >= 3 ? k - 3 : 0, i2;
        for (i2 = lo; i2 < k + 4 && i2 < g_ev_n; i2++)
            fprintf(stderr, "hb_povtor: PERVOE-SOB %llu kind=%u site=%u pc=0x%llx nw=%u%s\n",
                    (unsigned long long)i2, g_ev[i2].kind, g_ev[i2].site,
                    (unsigned long long)g_ev[i2].pc, g_ev[i2].n_writes,
                    i2 == k ? "  <== zhdali" : "");
    }
    if (fv) proishozhdenie("otkaz", fa);
    proishozhdenie("stoim_pc", ctx->pc);
    fflush(stderr);
}

/* ───────────────────────────── кеш поднятого IR ──────────────────────── */

#define IRC_SIZE 262144u
static struct { uint64_t pc; hb_ir_func_t* func; } g_irc[IRC_SIZE];
static uint64_t g_lifts, g_lift_hits, g_lift_fail;

/* ★ Признак «этот заход — ПЕРВОЕ исполнение блока». Первое исполнение несёт
 * подъём IR и выпуск кода, повторное — только исполнение выпущенного. Без
 * такого разделения время повтора смешивает кодогенерацию с исполнением, а
 * гейты, которые мы мерим, меняют ТОЛЬКО исполнение. */
static int g_last_lift_was_miss;

static hb_ir_func_t* lift_cached(uint64_t pc)
{
    size_t h = (size_t)((pc >> 4) ^ (pc >> 17) ^ (pc >> 32)) & (IRC_SIZE - 1);
    size_t i;
    for (i = 0; i < 64; i++) {
        size_t k = (h + i) & (IRC_SIZE - 1);
        if (g_irc[k].func && g_irc[k].pc == pc) {
            g_lift_hits++; g_last_lift_was_miss = 0; return g_irc[k].func;
        }
        if (!g_irc[k].func) {
            hb_decoder_t* dec;
            hb_ir_func_t* f = NULL;
            if (!hb_memory_can_read(g_mem, (hb_gva_t)pc, 1)) { g_lift_fail++; return NULL; }
            dec = hb_decoder_create(HB_ARCH_X64, (const uint8_t*)(uintptr_t)pc,
                                    LIFT_WINDOW, pc);
            if (!dec) { g_lift_fail++; return NULL; }
            if (hb_lift_func_x64(dec, &f) != HB_OK || !f) {
                hb_decoder_destroy(dec);
                g_lift_fail++;
                return NULL;
            }
            hb_decoder_destroy(dec);
            g_irc[k].pc = pc;
            g_irc[k].func = f;
            g_lifts++;
            g_last_lift_was_miss = 1;
            return f;
        }
    }
    g_lift_fail++;
    return NULL;
}

/* ─────────────────────────── применение записи ───────────────────────── */

static uint64_t g_writes_applied, g_write_bytes;

/* ★★★ ДОСТАВКА ВНЕШНЕГО РЕЗУЛЬТАТА — ЭТО ОПЕРАЦИЯ ПОВТОРА, А НЕ ГОСТЕВОЙ STORE.
 *
 * Тонкость, из-за которой проверку нельзя ни оставить как была, ни просто снять.
 * Хост мог законно изменить содержимое страницы и ВЕРНУТЬ ей права только-чтение
 * (типичный случай: заполнили таблицу и защитили). Тогда одна проверка
 * `hb_memory_can_write` по КОНЕЧНЫМ гостевым правам запретит доставку того, что
 * в живом прогоне уже лежало в памяти, — и повтор разойдётся именно там, где
 * запись была ПРАВИЛЬНОЙ.
 *
 * Просто убрать проверку и писать по произвольному адресу тоже нельзя: тогда
 * битая запись пишет куда угодно, и K-apply перестаёт краснеть.
 *
 * Поэтому доставка идёт СВОИМ путём, с тремя условиями:
 *   1. адрес обязан лежать в ИЗВЕСТНОЙ повтору области гостя
 *      (`hb_memory_find_region`) — это отвергает чужой/несуществующий объект;
 *   2. если гостевых прав на запись нет, права снимаются на время доставки
 *      хозяйским `mprotect` и ВОЗВРАЩАЮТСЯ сразу после неё — гостевые права в
 *      слое памяти при этом НЕ меняются;
 *   3. применение проверяется ФАКТОМ: после копирования байты сверяются.
 *
 * Счётчик `zapisej_primeneno` растёт ТОЛЬКО при успехе. Отказ считается
 * отдельно и в строгом режиме делает прогон недействительным. */
static int dostavit(uint64_t a, uint32_t l, const uint8_t* src, const char** kak)
{
    void*  pg;
    size_t plen;
    int    otkryli = 0;

    if (!l) { *kak = "-"; return 1; }
    if (!hb_memory_find_region(g_mem, (hb_gva_t)a) ||
        !hb_memory_find_region(g_mem, (hb_gva_t)(a + l - 1))) {
        *kak = "adresa net v karte povtora";
        return 0;
    }
    if (!hb_memory_can_write(g_mem, (hb_gva_t)a, l)) {
        /* Гостевые права только-чтение. Это НЕ повод отвергать внешний
         * результат: он в живом прогоне уже лежал в памяти. Открываем
         * ХОЗЯЙСКИЕ права на время доставки и возвращаем их обратно. */
        uint64_t lo = a & ~(uint64_t)(HOST_PAGE - 1);
        uint64_t hi = (a + l + HOST_PAGE - 1) & ~(uint64_t)(HOST_PAGE - 1);
        pg = (void*)(uintptr_t)lo;
        plen = (size_t)(hi - lo);
        if (mprotect(pg, plen, PROT_READ | PROT_WRITE) != 0) {
            *kak = "mprotect na vremya dostavki otkazal";
            return 0;
        }
        otkryli = 1;
    }
    memcpy((void*)(uintptr_t)a, src, l);
    if (memcmp((const void*)(uintptr_t)a, src, l) != 0) {
        if (otkryli) mprotect(pg, plen, PROT_READ);
        *kak = "bajty ne legli (sverka posle kopirovaniya)";
        return 0;
    }
    if (otkryli && mprotect(pg, plen, PROT_READ) != 0) {
        /* Права не вернулись — дальше гость мог бы писать туда, куда живой не
         * мог. Это тоже недействительность, а не мелочь. */
        *kak = "prava posle dostavki ne vernulis";
        return 0;
    }
    *kak = "-";
    return 1;
}

/* Возвращает число НЕПРИМЕНЁННЫХ записей: 0 = всё доставлено. */
static uint64_t apply_writes(const rec_ev_t* e)
{
    const uint8_t* p = e->writes;
    uint64_t bad = 0;
    uint32_t k;
    for (k = 0; k < e->n_writes; k++) {
        uint64_t a;
        uint32_t l, need;
        const char* kak = "-";
        /* Граница потока — ГЛАВНАЯ проверка: битое n_writes/len уводило чтение
         * за событие и дальше по файлу молча. */
        if (p + 12 > e->writes_end) {
            nedejstvitelno("zapis sobytiya", "zagolovok zapisi ne vmeschaetsya v sobytie",
                           (unsigned long long)(uintptr_t)p, (unsigned long long)k);
            bad += (uint64_t)(e->n_writes - k);
            g_wr_otkazano += (uint64_t)(e->n_writes - k);
            break;
        }
        memcpy(&a, p, 8);
        memcpy(&l, p + 8, 4);
        if (p + 12 + (size_t)l > e->writes_end) {
            nedejstvitelno("zapis sobytiya", "payload dlinnee sobytiya", a, l);
            bad += (uint64_t)(e->n_writes - k);
            g_wr_otkazano += (uint64_t)(e->n_writes - k);
            break;
        }
        if (dostavit(a, l, p + 12, &kak)) {
            g_writes_applied++;
            g_write_bytes += l;
        } else {
            bad++;
            g_wr_otkazano++;
            g_wr_bajt_otkazano += l;
            if (g_wr_otkazano <= 16)
                fprintf(stderr, "hb_povtor: ZAPIS NE PRIMENENA addr=0x%llx len=%u prichina=%s\n",
                        (unsigned long long)a, l, kak);
            if (g_strogo)
                nedejstvitelno("primenenie zapisi hosta", kak, a, l);
        }
        need = (12u + l + 7u) & ~7u;
        p += need;
    }
    return bad;
}

static void apply_state(hb_context_t* ctx, const hb_record_state_t* st)
{
    ctx->regs.x64 = st->regs;
    ctx->flags = st->flags;
    ctx->lazy_flags = st->lazy;
    ctx->gs_base = st->gs_base;
    ctx->fs_base = st->fs_base;
}

/* ───────────────────────────── разбор файла ──────────────────────────── */

static int load(const char* path)
{
    int fd = open(path, O_RDONLY);
    off_t sz;
    const uint8_t* p;
    const uint8_t* end;
    uint64_t cap = 0;

    if (fd < 0) { perror("open"); return 0; }
    sz = lseek(fd, 0, SEEK_END);
    /* ★★★ САМА ЗАПИСЬ ЛОЖИТСЯ ПО ФИКСИРОВАННОМУ ВЫСОКОМУ АДРЕСУ.
     *
     * Первая редакция отображала её через mmap(NULL): ядро положило гигабайтный
     * файл около 0x110000000 — ровно туда, где у записанного процесса СТЕК
     * ГОСТЯ (0x1132f0000, 16,8 МБ). Область гостя после этого не ложилась, и
     * первый же push давал `JIT helper fault`, а выглядело это как «ход
     * исполнения разошёлся». То есть повторяющий своей собственной памятью
     * затирал память, которую собирался повторять.
     *
     * Полоса 0x5000_00000000 (88 ТБ) в записи HK не встречается ни разу
     * (полосы: 0x1, 0x2, 0x9, 0xc, 0x7ff, 0x87e, 0x87f, 0x2000, 0x6f00), и
     * проверка ниже отказывает вслух, если ядро всё-таки положило иначе. */
    g_file = (uint8_t*)mmap((void*)POVTOR_SCRATCH, (size_t)sz, PROT_READ,
                            MAP_PRIVATE | MAP_FIXED, fd, 0);
    close(fd);
    if (g_file == MAP_FAILED || (uint64_t)(uintptr_t)g_file != POVTOR_SCRATCH) {
        fprintf(stderr, "hb_povtor: zapis ne legla po 0x%llx (errno=%d) — OTKAZ\n",
                (unsigned long long)POVTOR_SCRATCH, errno);
        return 0;
    }
    g_file_len = (size_t)sz;

    memcpy(&g_hdr, g_file, sizeof(g_hdr));
    if (memcmp(g_hdr.magic, HB_RECORD_MAGIC, 8)) {
        fprintf(stderr, "hb_povtor: ne nasha zapis (magic)\n"); return 0;
    }
    /* ★ ВЕРСИИ ПРИНИМАЮТСЯ ОБЕ. Запись версии 1 (zapis-hk1.bin, 998 МБ) снята
     * с живой игры 07.09; переснять её нечем без нового прогона, а отказ по
     * версии превратил бы единственную живую запись в мусор. Версия 2 отличается
     * ТОЛЬКО добавленными событиями HB_REC_MAP/HB_REC_UNMAP — раскладка
     * заголовка, областей и прежних событий не тронута. Чужая раскладка всё
     * равно отвергается: magic и state_size сверяются ниже. */
    if (g_hdr.version < 1u || g_hdr.version > HB_RECORD_VERSION_MAX) {
        fprintf(stderr, "hb_povtor: versiya %u, umeyu 1..%u\n",
                g_hdr.version, HB_RECORD_VERSION_MAX);
        return 0;
    }
    if (g_hdr.state_size != sizeof(hb_record_state_t)) {
        /* Раскладка состояния разъехалась — читать её как свою значило бы
         * подставлять движку мусор и объяснять потом расхождение алгоритмом. */
        fprintf(stderr, "hb_povtor: sostoyanie %llu bajt, u menya %zu — OTKAZ\n",
                (unsigned long long)g_hdr.state_size, sizeof(hb_record_state_t));
        return 0;
    }

    /* Таблица событий — НЕ через malloc и с ЗАРАНЕЕ посчитанным потолком.
     * Куча повторяющего растёт ровно в ту полосу, где у записанного процесса
     * лежит стек гостя; отдельное отображение по фиксированному высокому адресу
     * снимает вопрос. Потолок — верхняя оценка: событие не короче 32 байт. */
    cap = (g_file_len - g_hdr.events_off) / sizeof(hb_record_event_t) + 16;
    g_ev = (rec_ev_t*)mmap((void*)(POVTOR_SCRATCH + POVTOR_SCRATCH_STEP),
                           (size_t)cap * sizeof(*g_ev), PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (g_ev == MAP_FAILED) {
        fprintf(stderr, "hb_povtor: tablica sobytij ne legla (errno=%d)\n", errno);
        return 0;
    }

    /* События разбираются ДО КОНЦА ФАЙЛА, а не по n_events из заголовка:
     * заголовок обновляется раз в 256 событий, и у убитого прогона он всегда
     * отстаёт. Расхождение печатается — молча доверять ни одному из двух чисел
     * нельзя. */
    p = g_file + g_hdr.events_off;
    end = g_file + g_file_len;
    {
    uint64_t seq_pred = 0;
    int seq_bylo = 0;
    while (p + sizeof(hb_record_event_t) <= end) {
        hb_record_event_t ev;
        const uint8_t* q;
        memcpy(&ev, p, sizeof(ev));
        /* ★ ОБРЫВ РАЗБОРА НАЗЫВАЕТСЯ ПРИЧИНОЙ. Прежде было три молчаливых
         * `break`, и обрыв выглядел как «событий просто меньше». */
        if (ev.total_len < sizeof(ev) || p + ev.total_len > end) {
            g_razbor_oborvan = 1;
            g_razbor_prichina = "total_len bitoe ili sobytie ne vmeschaetsya v fajl";
            break;
        }
        if (ev.kind != HB_REC_ENTER && ev.kind != HB_REC_EXIT &&
            ev.kind != HB_REC_MAP && ev.kind != HB_REC_UNMAP) {
            g_razbor_oborvan = 1;
            g_razbor_prichina = "neizvestnyj vid sobytiya";
            break;
        }
        if (g_ev_n == cap) {         /* потолок посчитан заранее, см. ниже */
            g_razbor_oborvan = 1;
            g_razbor_prichina = "potolok tablicy sobytij";
            break;
        }
        q = p + sizeof(ev);
        g_ev[g_ev_n].kind = ev.kind;
        g_ev[g_ev_n].site = ev.site;
        /* ★ Номер потока БЕЗ ветвления по версии: у писателей версий 1 и 2 биты
         * 8..15 поля flags нулевые, а один поток и есть поток 0. Ветвление
         * здесь было бы лишним местом, где старая запись читается иначе. */
        g_ev[g_ev_n].tid = (uint32_t)HB_REC_EV_TID(ev.flags);
        if (g_ev[g_ev_n].tid >= POVTOR_MAX_TID) g_ev[g_ev_n].tid = 0;
        if (g_ev[g_ev_n].tid + 1 > g_tid_seen) g_tid_seen = g_ev[g_ev_n].tid + 1;
        g_tid_events[g_ev[g_ev_n].tid]++;
        g_ev[g_ev_n].pc = ev.pc;
        g_ev[g_ev_n].has_state = (ev.flags & HB_REC_EV_STATE) != 0;
        g_ev[g_ev_n].state = NULL;
        if (g_ev[g_ev_n].has_state) {
            if (q + sizeof(hb_record_state_t) > p + ev.total_len) {
                g_razbor_oborvan = 1;
                g_razbor_prichina = "sostoyanie ne vmeschaetsya v sobytie";
                break;
            }
            g_ev[g_ev_n].state = (const hb_record_state_t*)q;
            q += sizeof(hb_record_state_t);
        }
        g_ev[g_ev_n].n_writes = ev.n_writes;
        g_ev[g_ev_n].writes = q;
        g_ev[g_ev_n].writes_end = p + ev.total_len;
        g_ev[g_ev_n].map = NULL;
        if (ev.kind == HB_REC_MAP || ev.kind == HB_REC_UNMAP) {
            g_map_ev_n++;
            if (ev.total_len >= sizeof(ev) + sizeof(hb_record_maprec_t))
                g_ev[g_ev_n].map = (const hb_record_maprec_t*)q;
        }
        /* ★ ПОРЯДОК СОБЫТИЙ. `seq` выдаёт писатель под одним замком, значит
         * порядок в файле И ЕСТЬ порядок во времени. Нарушение порядка —
         * признак перемешанного/склеенного файла, и молчать о нём нельзя. */
        if (seq_bylo && ev.seq <= seq_pred) g_seq_ne_po_poryadku++;
        seq_pred = ev.seq; seq_bylo = 1;
        g_ev_n++;
        p += ev.total_len;
    }
    }
    /* Сколько событий физически лежит в файле — считаем ОТДЕЛЬНО от заголовка:
     * заголовок обновляется раз в 256 событий и у убитого прогона отстаёт. */
    g_razbor_sobytij_v_fajle = g_ev_n;
    return 1;
}

/* ── контекст и среда JIT НА КАЖДЫЙ ПОТОК ─────────────────────────────── */

static hb_context_t*     g_ctx[POVTOR_MAX_TID];
static hb_jit_runtime_t* g_rt[POVTOR_MAX_TID];
static uint8_t           g_started[POVTOR_MAX_TID];
static uint64_t          g_step_limit = 10000000;
static uint64_t          g_ctx_made;

/* ★ ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ К САМОМУ РАЗДЕЛЕНИЮ КОНТЕКСТОВ.
 * MACRUNNER_POVTOR_ODIN_KONTEKST=1 сводит все потоки в контекст 0. Если после
 * этого расхождений НЕ появляется, значит потоки в записи не мешают друг другу
 * и проверка переплетения пуста — зелёный результат тогда ничего не стоит. */
static int g_odin_kontekst = -1;

static hb_context_t* ctx_for(uint32_t tid)
{
    hb_context_t* c;
    if (g_odin_kontekst < 0)
        g_odin_kontekst = (int)env_u64("MACRUNNER_POVTOR_ODIN_KONTEKST", 0);
    if (g_odin_kontekst) tid = 0;
    if (tid >= POVTOR_MAX_TID) return NULL;
    if (g_ctx[tid]) return g_ctx[tid];
    c = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    if (!c) return NULL;
    /* ПАМЯТЬ ГОСТЯ ОДНА НА ВСЕ ПОТОКИ. Дать каждому свою значило бы повторять
     * не многопоточную программу, а N однопоточных: взаимные записи потоков
     * друг другу перестали бы быть видимыми, и переплетение ничего бы не
     * проверяло. */
    c->memory = g_mem;
    hb_context_set_block_limit(c, 0);
    hb_context_set_step_limit(c, g_step_limit);
    g_ctx[tid] = c;
    g_ctx_made++;
    return c;
}

static hb_jit_runtime_t* rt_for(uint32_t tid)
{
    hb_context_t* c;
    if (g_odin_kontekst > 0) tid = 0;
    if (tid >= POVTOR_MAX_TID) return NULL;
    if (g_rt[tid]) return g_rt[tid];
    c = ctx_for(tid);
    if (!c) return NULL;
    g_rt[tid] = hb_jit_runtime_create(c);
    return g_rt[tid];
}

/* ── снятие ASLR: перевыполнить себя ОДИН раз ────────────────────────── */

#include <spawn.h>
#include <mach-o/dyld.h>
#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif
extern char** environ;

/* Возвращает 1, если перевыполнение НЕ понадобилось или не удалось (идём
 * дальше как есть). Отказ здесь не смертелен: без снятия ASLR повтор работает,
 * просто низ карты плавает — и это видно по числу легших областей. */
static void snyat_aslr(char** argv)
{
    posix_spawnattr_t at;
    char put[4096];
    uint32_t n = sizeof(put);
    const char* g = getenv("MACRUNNER_POVTOR_BEZ_ASLR");
    if (g && *g == '0') return;                    /* отрицательный контроль */
    if (getenv("MACRUNNER_POVTOR_ASLR_SNYAT")) return;   /* уже перевыполнены */
    if (_NSGetExecutablePath(put, &n) != 0) return;
    setenv("MACRUNNER_POVTOR_ASLR_SNYAT", "1", 1);
    if (posix_spawnattr_init(&at) != 0) return;
    posix_spawnattr_setflags(&at, (short)(POSIX_SPAWN_SETEXEC |
                                          _POSIX_SPAWN_DISABLE_ASLR));
    /* SETEXEC замещает ТЕКУЩИЙ процесс — возврат означает отказ. */
    (void)posix_spawn(NULL, put, NULL, &at, argv, environ);
    posix_spawnattr_destroy(&at);
    fprintf(stderr, "hb_povtor: ASLR ne snyat (errno=%d), niz karty budet plavat\n",
            errno);
}

/* ─────────────────────────────── повтор ──────────────────────────────── */

int main(int argc, char** argv)
{
    const char* path = NULL;
    int steer = 1, verbose = 0, razdelit = 0;
    int diag = 0; uint64_t diag_max = 4;
    int karta_svoyu = 0;   /* напечатать СВОЮ карту памяти до укладки областей */
    unsigned yakor;  /* 0 нет, 1 только на входах, 2 на всех событиях */
    uint64_t limit = 0, repeat = 1, rep, step_limit = 10000000;
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    uint64_t t0, t1, ns_cold = 0, ns_warm_sum = 0, warm_reps = 0;
    uint64_t steps_cold = 0, disp_cold = 0, warm_mismatch = 0;
    uint64_t ns_first = 0, ns_again = 0, n_first = 0, n_again = 0;
    uint64_t steps_first = 0, steps_again = 0;
    uint64_t dispatches = 0, steps = 0, blocks = 0;
    uint64_t div_exit = 0, div_enter = 0, host_applied = 0, lift_returns = 0;
    uint64_t guest_returns = 0, sovpalo = 0, reach_budget = 256, zastryali = 0;
    uint64_t perehodnikov = 0;   /* заходов, остановленных на арене переходников */
    /* ★ ПОВТОР-5: ОТРЕЗОК ЗАДАЁТСЯ ЗАПИСЬЮ, А НЕ ПОВЕДЕНИЕМ ПОВТОРА.
     * `--limit` считает ЗАХОДЫ, а их число зависит от того, сколько повтор
     * проблуждал: на пределе 50 000 заходов он прошёл 5 347 событий, то есть
     * девять заходов из десяти ушли в блуждание. Сравнивать две настройки по
     * такому отрезку нельзя — они видят РАЗНЫЕ куски записи. `--sobytij N`
     * задаёт отрезок числом событий, и он у всех настроек один и тот же. */
    uint64_t sob_limit = 0, sob_obr = 0;
    uint64_t sled_lo = 1, sled_hi = 0;   /* пусто: lo > hi */
    uint64_t slepok = 0xcbf29ce484222325ull;   /* FNV-1a по пути гостя */
    uint64_t slepok_pc = 0xcbf29ce484222325ull; /* тот же путь БЕЗ числа заходов */
    uint64_t dohod[9];           /* сколько заходов ушло на достижение события */
    memset(dohod, 0, sizeof(dohod));
    uint64_t novyh_oblastej = 0;
    uint64_t no_lift = 0, fallbacks = 0, run_errors = 0, res_errors = 0, step_limit_hits = 0;
    uint64_t proish_addr = 0;
    int i;

    snyat_aslr(argv);

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--no-steer")) steer = 0;
        else if (!strcmp(argv[i], "--strogo")) g_strogo = 1;
        else if (!strcmp(argv[i], "--chasovoj") && i + 1 < argc) {
            /* ★ ЧАСОВОЙ — БЕЗУСЛОВНЫЙ ЗОНД НА ЯЧЕЙКУ ГОСТЯ.
             * Именно им установлено происхождение стены: адрес называется
             * снаружи, значение печатается на КАЖДОМ событии отрезка, и первое
             * изменение видно числом, а не выводится из ветвлений. */
            char* z = NULL;
            g_chasovoj = strtoull(argv[++i], &z, 0);
            g_chasovoj_n = (z && *z == ',') ? (uint32_t)strtoul(z + 1, NULL, 0) : 8u;
            if (g_chasovoj_n == 0 || g_chasovoj_n > 32) g_chasovoj_n = 8u;
        }
        else if (!strcmp(argv[i], "--proishozhdenie") && i + 1 < argc) {
            /* Спросить происхождение адреса и выйти — БЕЗ повтора. Разбор
             * записей идёт тем же кодом, что и применение, поэтому ответ
             * нельзя разойтись с тем, что повтор делает на самом деле.
             * (Отдельный python-читатель на этом уже соврал: его шаг по потоку
             * записей выравнивался иначе, и он насчитал 412 «попаданий» с
             * длинами в 1,6 ГБ.) */
            proish_addr = strtoull(argv[++i], NULL, 0);
        }
        else if (!strcmp(argv[i], "--razdelit")) razdelit = 1;
        else if (!strcmp(argv[i], "--verbose")) verbose = 1;
        else if (!strcmp(argv[i], "--diag")) diag = 1;
        else if (!strcmp(argv[i], "--diag-max") && i + 1 < argc) diag_max = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--limit") && i + 1 < argc) limit = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--repeat") && i + 1 < argc) repeat = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--step-limit") && i + 1 < argc) step_limit = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--budget") && i + 1 < argc) reach_budget = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--sobytij") && i + 1 < argc) sob_limit = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--sled") && i + 2 < argc) { sled_lo = strtoull(argv[i+1], NULL, 0); sled_hi = strtoull(argv[i+2], NULL, 0); i += 2; }
        else if (!strcmp(argv[i], "--karta-processa")) { karta_svoyu = 1; g_karta_full = 1; }
        else path = argv[i];
    }
    if (!path) {
        fprintf(stderr, "usage: hb_povtor <zapis.bin> [--no-steer] [--limit N] "
                        "[--repeat N] [--verbose]\n");
        return 2;
    }
    if (env_u64("MACRUNNER_POVTOR_STROGO", 0)) g_strogo = 1;
    if (g_strogo) steer = 0;      /* в строгом расхождение — конец, не подсказка */
    if (!load(path)) return 2;

    /* ★ ПОЛНОТА ПОТОКА СОБЫТИЙ ПРОВЕРЯЕТСЯ ДО ПОВТОРА, а не выводится из
     * числа шагов задним числом. */
    if (g_razbor_oborvan) {
        fprintf(stderr, "hb_povtor: RAZBOR OBORVAN na sobytii %llu: %s\n",
                (unsigned long long)g_razbor_sobytij_v_fajle, g_razbor_prichina);
        if (g_strogo) nedejstvitelno("razbor potoka", g_razbor_prichina,
                                     0, (unsigned long long)g_razbor_sobytij_v_fajle);
    }
    if (g_seq_ne_po_poryadku)
        nedejstvitelno("poryadok sobytij", "seq ne rastyot", 0,
                       (unsigned long long)g_seq_ne_po_poryadku);

    if (proish_addr) {
        printf("hb_povtor: zapis=%s sobytij=%llu state_size=%llu window_bytes=%llu "
               "page_bytes=%llu n_host_writes=%llu host_write_bytes=%llu\n",
               path, (unsigned long long)g_ev_n,
               (unsigned long long)g_hdr.state_size,
               (unsigned long long)g_hdr.window_bytes,
               (unsigned long long)g_hdr.page_bytes,
               (unsigned long long)g_hdr.n_host_writes,
               (unsigned long long)g_hdr.host_write_bytes);
        fflush(stdout);
        proishozhdenie("zapros", proish_addr);
        return 0;
    }

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    if (!ctx) { fprintf(stderr, "hb_povtor: net konteksta\n"); return 2; }
    ctx->memory = hb_memory_create(0);
    g_mem = ctx->memory;
    g_ctx[0] = ctx;
    yakor = (unsigned)env_u64("MACRUNNER_POVTOR_YAKOR", 1);
    /* ★ ПРЕДЕЛ ШАГОВ НА ОДИН ЗАХОД — ОБЯЗАТЕЛЕН.
     * Без него повтор, у которого гость поехал на мусоре, крутит бесконечный
     * гостевой цикл внутри ОДНОГО захода: 97 % процессора и ни строки вывода.
     * Поймано на записи HK. Предел щедрый (10 млн шагов при типовом заходе в
     * десятки), но конечный, и его срабатывания считаются отдельно. */
    /* ★★★★ ЛЕЙН ЗАПИСЬ-ХОЗЯИНА: ПОЧЕМУ ЗДЕСЬ ПОЯВИЛСЯ ГЕЙТ.
     *
     * Контрольные точки записи — это границы блоков ЖИВОГО движка: у него кеш
     * был холодным, и он выходил наружу почти на каждом блоке (два события на
     * блок). У повтора кеш ТЁПЛЫЙ, блоки длиннее и сцеплены, поэтому он
     * ПРОСКАКИВАЕТ записанный адрес и «дойти» до него не может НИКОГДА.
     *
     * Измерено на событии 3904 (`--sled 3901 3912`): ждали выход на
     * 0x87efea136c9, а повтор за 23 захода прошёл ВСЮ функцию —
     * 0x136c6 -> 0x13434 -> ... -> 0x136eb -> 0x135f4 -> ... -> переходник
     * 0x6f0000000370 — и остановился только об арену переходников. То есть
     * повтор СПЕКУЛЯТИВНО исполнил будущий код, оставив в памяти его записи.
     *
     * Гейт задаёт число блоков на один заход. 1 = останавливаться на каждой
     * границе блока: проскок тогда не длиннее одного блока. 0 = как было. */
    hb_context_set_block_limit(ctx, (uint32_t)env_u64("MACRUNNER_POVTOR_BLOKOV", 0));
    hb_context_set_step_limit(ctx, step_limit);

    pechat_niza();
    if (karta_svoyu) karta_processa();
    map_regions();
    /* ★ СИНТЕТИЧЕСКАЯ НУЛЕВАЯ КАРТА — ТОЛЬКО В ДИАГНОСТИЧЕСКОМ РЕЖИМЕ.
     * Дыры заводятся нулями, потому что «свежая память Windows и есть нули».
     * Для строгой проверки это негодно: нулём накрывается ровно тот случай,
     * который надо ловить — ячейка, которую хост наполнил, а запись не поймала. */
    if (!g_strogo) map_holes();
    install_fault_handler();

    rt = hb_jit_runtime_create(ctx);
    if (!rt) { fprintf(stderr, "hb_povtor: net sredy JIT\n"); return 2; }
    g_rt[0] = rt;
    g_step_limit = step_limit;
    /* Признак «съедено» и признак «поток начат» — в своей полосе, не в куче:
     * куча повторяющего растёт в полосы гостя (см. разбор у mmap записи). */
    g_consumed = (uint8_t*)mmap((void*)(POVTOR_SCRATCH + 5 * POVTOR_SCRATCH_STEP),
                                (size_t)g_ev_n + 16, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    if (g_consumed == MAP_FAILED) {
        fprintf(stderr, "hb_povtor: priznak sedennogo ne lyog (errno=%d)\n", errno);
        return 2;
    }
    if (g_tid_seen > 1) {
        uint64_t q;
        printf("hb_povtor: POTOKI versiya=%u nomerov=%llu (v zagolovke %llu) sobytij:",
               g_hdr.version, (unsigned long long)g_tid_seen,
               (unsigned long long)g_hdr.n_threads);
        for (q = 0; q < g_tid_seen && q < 8; q++)
            printf(" t%llu=%llu", (unsigned long long)q,
                   (unsigned long long)g_tid_events[q]);
        printf("\n");
        fflush(stdout);
    }

    printf("hb_povtor: zapis=%s sobytij=%llu (v zagolovke %llu) oblastej=%llu "
           "lozheno=%llu stolknulos=%llu ne_leglo=%llu propuscheno=%llu bajt_lozheno=%llu\n",
           path, (unsigned long long)g_ev_n, (unsigned long long)g_hdr.n_events,
           (unsigned long long)g_hdr.n_regions, (unsigned long long)g_reg_mapped,
           (unsigned long long)g_reg_collided, (unsigned long long)g_reg_denied,
           (unsigned long long)g_reg_skipped, (unsigned long long)g_bytes_mapped);
    printf("hb_povtor: DYRY zavedeno_dyr=%llu bajt_dyr=%llu propuschennyh_zavedeno=%llu "
           "bajt_propuschennyh=%llu\n",
           (unsigned long long)g_hole_n, (unsigned long long)g_hole_bytes,
           (unsigned long long)g_skip_mapped, (unsigned long long)g_skip_bytes);
    fflush(stdout);

    if (!g_ev_n || g_ev[0].kind != HB_REC_ENTER || !g_ev[0].has_state) {
        fprintf(stderr, "hb_povtor: pervoe sobytie ne VHOD s sostoyaniem — OTKAZ\n");
        return 2;
    }

    /* ★★★ ЗАМЕР РАЗДЕЛЁН НА ХОЛОДНЫЙ И ТЁПЛЫЙ ПРОХОД — ПОВТОР-4.
     *
     * Прежде `--limit` считал заходы НАКОПИТЕЛЬНО по всем повторам, поэтому
     * `--repeat N` не делал НИЧЕГО: после первого прохода счётчик уже упирался
     * в предел. Проверено числом: repeat=1 и repeat=20 давали одни и те же
     * `dispatchej=900 shagov=7463`. Ключ, которым отделяют кодогенерацию от
     * исполнения, был мёртв.
     *
     * Теперь предел применяется К КАЖДОМУ проходу, а время первого прохода
     * (подъём IR + выпуск кода 473 блоков) отделено от времени остальных
     * (исполнение уже выпущенного). Разность и есть доля кодогенерации —
     * измеренная, а не выведенная из «шагов на блок». */
    t0 = now_ns();
    for (rep = 0; rep < repeat; rep++) {
        uint64_t k = 1;
        uint64_t disp_rep = 0, steps_rep = 0, rep_t0;
        /* Возврат памяти в снимок — ВНЕ замера прохода. */
        if (rep) restore_memory();
        memset(g_started, 0, sizeof(g_started));
        memset(g_consumed, 0, (size_t)g_ev_n);
        ctx = ctx_for(g_ev[0].tid);
        apply_state(ctx, g_ev[0].state);
        ctx->pc = g_ev[0].pc;
        g_started[g_ev[0].tid] = 1;
        rep_t0 = now_ns();

        while (k < g_ev_n && (!limit || disp_rep < limit) &&
               (!sob_limit || sob_obr < sob_limit)) {
            const rec_ev_t* ev = &g_ev[k];
            uint64_t shagov_do = 0;
            int doshli;

            /* ★ Событие, уже съеденное как возврат своей пары, НЕ СЧИТАЕТСЯ.
             * Счётчик `sob_obr` задаёт длину отрезка (`--sobytij N`), и если
             * съеденные события в него попадут, отрезок станет короче ровно на
             * их число — измерено на себе: ход исполнения на записи HK ушёл с
             * 5101 совпадения на 4483, а отрезок при том же N стал другим. */
            if (g_consumed[k]) { k++; continue; }
            sob_obr++;

            /* ★ Изменение карты памяти — НЕ контрольная точка: его `pc` несёт
             * базу области, а не адрес гостевой команды. Применяем и идём
             * дальше, не пытаясь «дойти» до него. */
            if (ev->kind == HB_REC_MAP || ev->kind == HB_REC_UNMAP) {
                apply_map(ev);
                k++;
                continue;
            }

            /* ★ КОНТЕКСТ БЕРЁТСЯ ПО ПОТОКУ СОБЫТИЯ. Память гостя у потоков
             * ОДНА (g_mem), среда JIT — своя: ровно так устроен живой процесс.
             * Первое событие потока не контрольная точка, а ЯКОРЬ: с него поток
             * начинает, поэтому состояние применяется и заход не делается. */
            ctx = ctx_for(ev->tid);
            rt = rt_for(ev->tid);
            if (!ctx || !rt) { k++; continue; }
            if (!g_started[ev->tid]) {
                if (ev->has_state) { apply_state(ctx, ev->state); ctx->pc = ev->pc; }
                g_started[ev->tid] = 1;
                k++;
                continue;
            }

            /* ★★★ ЗАПИСАННЫЕ СОБЫТИЯ — КОНТРОЛЬНЫЕ ТОЧКИ, А НЕ ПОШАГОВОЕ РАВЕНСТВО.
             *
             * Первая редакция требовала, чтобы КАЖДЫЙ возврат из диспетчера совпал
             * с очередным записанным выходом, и намерила 122 898 расхождений из
             * ~200 000. Разбор первого же расхождения показал, что это дефект
             * ПРИБОРА, а не повтора: прибор записи стоит на ДВУХ местах выхода из
             * пяти (`no_block`, `ext_xfer`), а `ret` — ещё 8,94 % диспетчеризаций
             * (база §2.1) и в записи его нет. Плюс у живого прогона кеш блоков был
             * ТЁПЛЫЙ, и цель `ret` находилась в нём; у повтора на том же месте кеш
             * холодный, он возвращается в диспетчер — та же работа, другое число
             * заходов.
             *
             * Поэтому повтор ИДЁТ ДО записанного адреса, сколько бы незаписанных
             * возвратов ни случилось по дороге, и расхождением считается только
             * то, что до него НЕ ДОШЛИ за отведённый бюджет заходов. */
            for (shagov_do = 0; ctx->pc != ev->pc && shagov_do < reach_budget;
                 shagov_do++) {
                hb_exec_result_t out;
                hb_result_t ret;
                hb_ir_func_t* f;
                uint64_t d_t0 = razdelit ? now_ns() : 0;
                g_cur_pc = ctx->pc; g_cur_ev = k; g_cur_disp = dispatches;
                g_last_lift_was_miss = 0;
                f = lift_cached(ctx->pc);
                if (!f) { no_lift++; break; }
                memset(&out, 0, sizeof(out));
                ret = hb_jit_runtime_run(rt, f, &out);
                /* Откат на интерпретатор — как в живом цикле (macrunner_hb.c). */
                if (ret == HB_OK && (out.result == HB_ERR_UNSUPPORTED_OPCODE ||
                                     out.result == HB_ERR_UNSUPPORTED_FEATURE ||
                                     out.result == HB_ERR_INTERNAL)) {
                    ctx->last_result = HB_OK;
                    memset(&out, 0, sizeof(out));
                    ret = hb_runtime_run(ctx, f, HB_BACKEND_INTERP, &out);
                    fallbacks++;
                }
                if (ret != HB_OK) run_errors++;
                if (out.result != HB_OK) {
                    res_errors++;
                    if (out.result == HB_ERR_STEP_LIMIT) step_limit_hits++;
                    if (verbose && res_errors <= 40) {
                        uint64_t fa = 0; size_t fs = 0; int fw = 0, fv = 0;
                        hb_memory_last_fault(&fa, &fs, &fw, &fv);
                        fprintf(stderr, "hb_povtor: ishod pc=0x%llx ret=%d out=%d "
                                "shagov=%llu prichina=%s otkaz_addr=0x%llx zapis=%d\n",
                                (unsigned long long)g_cur_pc, (int)ret, (int)out.result,
                                (unsigned long long)out.steps_executed,
                                out.fault_reason ? out.fault_reason : "-",
                                (unsigned long long)fa, fw);
                    }
                    /* ★ ПОВТОР-5: ОТКУДА ВЗЯЛОСЬ ЗНАЧЕНИЕ. Адрес отказа сам по
                     * себе не говорит НИЧЕГО о причине: 0x1 значит «регистр
                     * держит единицу», но какой регистр и кто её туда положил —
                     * из адреса не следует. Печатаем регистры и байты гостя у
                     * pc: по ним имя регистра читается прямо из кода. */
                    if (diag && res_errors <= diag_max) {
                        uint64_t fa = 0; size_t fs = 0; int fw = 0, fv = 0;
                        const hb_regs_x64_t* R = &ctx->regs.x64;
                        static const char* NM[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                                     "r8","r9","r10","r11","r12","r13","r14","r15"};
                        const uint64_t* V = &R->rax;
                        int q;
                        hb_memory_last_fault(&fa, &fs, &fw, &fv);
                        fprintf(stderr, "hb_povtor: DIAG pc=0x%llx otkaz=0x%llx dlina=%u zapis=%d disp=%llu sob=%llu\n",
                                (unsigned long long)g_cur_pc, (unsigned long long)fa,
                                (unsigned)fs, fw,
                                (unsigned long long)dispatches, (unsigned long long)k);
                        fprintf(stderr, "hb_povtor: DIAG-SOB zhdyom kind=%u site=%u pc=0x%llx | pred[-1] kind=%u site=%u pc=0x%llx | pred[-2] kind=%u site=%u pc=0x%llx\n",
                                ev->kind, ev->site, (unsigned long long)ev->pc,
                                k >= 1 ? g_ev[k-1].kind : 0, k >= 1 ? g_ev[k-1].site : 0,
                                k >= 1 ? (unsigned long long)g_ev[k-1].pc : 0ull,
                                k >= 2 ? g_ev[k-2].kind : 0, k >= 2 ? g_ev[k-2].site : 0,
                                k >= 2 ? (unsigned long long)g_ev[k-2].pc : 0ull);
                        for (q = 0; q < 16; q++)
                            fprintf(stderr, "hb_povtor: DIAG-REG %-3s=0x%016llx%s",
                                    NM[q], (unsigned long long)V[q], (q % 4 == 3) ? "\n" : "  ");
                        {
                            unsigned char bb[24];
                            int nb = 0;
                            for (nb = 0; nb < 24; nb++) {
                                if (!hb_memory_can_read(g_mem, (hb_gva_t)(g_cur_pc + nb), 1)) break;
                                bb[nb] = *(volatile unsigned char*)(uintptr_t)(g_cur_pc + nb);
                            }
                            fprintf(stderr, "hb_povtor: DIAG-BAJTY pc=0x%llx n=%d:",
                                    (unsigned long long)g_cur_pc, nb);
                            for (q = 0; q < nb; q++) fprintf(stderr, " %02x", bb[q]);
                            fprintf(stderr, "\n");
                        }
                        fflush(stderr);
                    }
                }
                /* ★ ШАГ ВНУТРИ СОБЫТИЯ. `--sled` показывал только границы
                 * событий, поэтому «22 захода и оказались на переходнике»
                 * оставалось без разбора: КУДА именно ушёл каждый заход, видно
                 * не было. Печать ограничена диапазоном `--sled`, поэтому
                 * сплошной нагрузкой она не становится. */
                if (sled_lo <= k && k <= sled_hi)
                    fprintf(stderr, "hb_povtor: ZAHOD sob=%llu n=%llu s_pc=0x%llx "
                            "-> pc=0x%llx shagov=%llu out=%d ret=%d prichina=%s\n",
                            (unsigned long long)k, (unsigned long long)shagov_do,
                            (unsigned long long)g_cur_pc, (unsigned long long)ctx->pc,
                            (unsigned long long)out.steps_executed, (int)out.result,
                            (int)ret, out.fault_reason ? out.fault_reason : "-");
                dispatches++;
                disp_rep++;
                steps += out.steps_executed;
                steps_rep += out.steps_executed;
                if (razdelit) {
                    uint64_t d_ns = now_ns() - d_t0;
                    if (g_last_lift_was_miss) {
                        ns_first += d_ns; n_first++; steps_first += out.steps_executed;
                    } else {
                        ns_again += d_ns; n_again++; steps_again += out.steps_executed;
                    }
                }
                blocks += out.blocks_executed;
                if ((dispatches & 0xFFFFFull) == 0) {
                    fprintf(stderr, "hb_povtor: hod dispatchej=%llu sobytie=%llu/%llu "
                            "rashozhdenij=%llu\n",
                            (unsigned long long)dispatches, (unsigned long long)k,
                            (unsigned long long)g_ev_n,
                            (unsigned long long)(div_exit + div_enter));
                    fflush(stderr);
                }
                /* Гость вернулся к хосту — заход кончился, дальше зовёт хост.
                 * Это штатное устройство цикла, а не расхождение. */
                if (ctx->pc == 0xffff0000ull || ctx->pc == 0) { guest_returns++; break; }
                /* ★★★★ ПОВТОР-5: АРЕНА ПЕРЕХОДНИКОВ ИМПОРТА — ЭТО ХОСТ, А НЕ КОД.
                 *
                 * Стена ПОВТОР-4 (pc=0x6f00000022e0, чтение по 0x1) была НЕ
                 * «непойманной записью хоста». Байты по этому pc — `50 00 00 58
                 * 00 02 1f d6`, то есть ARM64 `ldr x16,#..; br x16`: повтор
                 * разбирал переходник как команды x86 и получал `push rax` при
                 * rsp=0. Диагноз «регистр держит единицу, значит запись не
                 * поймана» описывал СЛЕДСТВИЕ.
                 *
                 * Диапазон не угадывается по полосе (классификатор по полосам
                 * соврал бы — см. заголовок файла): он ТОЧНЫЙ и объявлен самим
                 * движком в include/hb_thunk.h. Ровно та же проверка стоит
                 * первой в hb_xborder_note (hb_runtime.c) — здесь она означает
                 * то же самое: дальше исполняет НЕ наш транслятор.
                 *
                 * В живом прогоне отсюда уходят к хосту; в записи этому
                 * соответствует событие HB_REC_EXIT с site=1. Значит повтор
                 * обязан ОСТАНОВИТЬ заход и дать записи подставить результат. */
                if (ctx->pc >= HB_IMPORT_THUNK_BASE &&
                    ctx->pc < HB_IMPORT_THUNK_BASE +
                              (uint64_t)HB_IMPORT_THUNK_MAX * HB_IMPORT_THUNK_STRIDE) {
                    perehodnikov++;
                    break;
                }
                /* ★★★ ПАМЯТЬ, ПОЯВИВШАЯСЯ ПОСЛЕ СНИМКА.
                 *
                 * Образ памяти снят ОДИН раз, в начале отрезка. Всё, что гость и
                 * хост выделили позже (новый стек потока, куча, отображение
                 * файла), в записи отсутствует — и первое же обращение туда
                 * отвергается слоем памяти, а заход перестаёт двигаться вовсе:
                 * 256 заходов подряд с одним и тем же pc и одним шагом.
                 * Измерено на записи HK: адрес 0x114300510, области НЕТ в записи,
                 * ровно над верхней границей стека гостя.
                 *
                 * Заводим область нулями и ПРОДОЛЖАЕМ. Нули здесь не выдумка:
                 * свежевыделенная память Windows и есть нули; а всё, что хост в
                 * неё записал, приезжает окнами записи. КАЖДЫЙ такой случай
                 * считается отдельным числом — по нему и судят, чего стоит
                 * замер. */
                /* ★ ПОВТОР-5: ЗАХОД БЕЗ ПРОДВИЖЕНИЯ ПОВТОРЯТЬ НЕЛЬЗЯ.
                 * Условие ниже требовало `shagov <= 1`, а отказ на переходнике
                 * давал ДВА шага — и заход крутился по бюджету 256 раз на одном
                 * pc. На отрезке 1500 это 245 «дispatchей» из 1724, то есть
                 * 14 % работы замера уходило на повтор одного отказа. Считаются
                 * они отдельно (`zastryali`), а не растворяются в числе шагов. */
                if (ctx->pc == g_cur_pc && out.result != HB_OK && out.steps_executed <= 1) {
                    uint64_t fa = 0; size_t fs = 0; int fw = 0, fv = 0;
                    hb_memory_last_fault(&fa, &fs, &fw, &fv);
                    /* ★ В СТРОГОМ РЕЖИМЕ ОБЛАСТЬ НУЛЯМИ НЕ ЗАВОДИТСЯ.
                     * «Свежая память Windows и есть нули» — верно для памяти,
                     * которую никто не наполнял. Здесь же ровно наоборот:
                     * заведя нули, повтор скрывает случай «хост наполнил, а
                     * запись не поймала» — тот самый, ради которого строгий
                     * режим и нужен. */
                    if (g_strogo && fv)
                        nedejstvitelno("otkaz gostya", "adres vne karty zapisi, "
                                       "nulyami v strogom ne zavodim", fa, (unsigned long long)k);
                    if (!g_strogo &&
                        fv && fa >= 0x100000000ull && fa < 0x00007fffffff0000ull &&
                        !hb_memory_find_region(g_mem, (hb_gva_t)fa) &&
                        novyh_oblastej < 100000) {
                        uint64_t pg = fa & ~(uint64_t)(HOST_PAGE - 1);
                        void* q = mmap((void*)(uintptr_t)pg, HOST_PAGE,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
                        if (q != MAP_FAILED) {
                            hb_memory_map(g_mem, (hb_gva_t)pg, HOST_PAGE,
                                          HB_PERM_READ | HB_PERM_WRITE);
                            prov_note(pg);
                            novyh_oblastej++;
                            continue;               /* повторить тот же pc */
                        }
                    }
                    zastryali++;
                    break;
                }
                if (ctx->pc == g_cur_pc && out.result != HB_OK) { zastryali++; break; }
            }

            doshli = (ctx->pc == ev->pc);
            /* ★★★★ ПОВТОР-5: СЛЕПОК ПУТИ — ПРАВИЛЬНЫЙ СТОРОЖ ОДИНАКОВОЙ РАБОТЫ.
             *
             * Прежний сторож сравнивал `shagov`. Это НЕ мера работы, а счётчик
             * приборa: на событии 3088 обе руки идут из 0x87efee8b3f5 в
             * 0x87efee8b402 ЗА ОДИН ЗАХОД и по ОДНОМУ И ТОМУ ЖЕ пути, но рука
             * ВКЛ насчитывает 5 шагов, а ВЫКЛ — 20. Код там — цикл из пяти
             * команд на четыре оборота (`mov [rcx],sil; inc eax; inc rcx;
             * cmp eax,5; jb -13`), и число оборотов задано РЕГИСТРОМ, одним и
             * тем же у обеих рук. Значит расходится не работа, а её учёт:
             * `steps_executed` считает выпущенные шаги, и при слиянии блока
             * оборот внутри него считается один раз.
             *
             * Из-за этого приёмка ПОВТОР-4 обрывала отрезок на 2 168 событиях,
             * хотя путь совпадал и дальше. Сторож отказывал на исправном месте.
             *
             * Слепок считает то, что и есть работа: ПОСЛЕДОВАТЕЛЬНОСТЬ гостевых
             * адресов и число заходов. Совпал слепок — руки прошли один путь;
             * это сильнее равенства шагов, а не слабее: равные шаги при разном
             * пути слепок ловит, а прежний сторож нет. */
            slepok ^= (uint64_t)k;             slepok *= 0x100000001b3ull;
            slepok ^= (uint64_t)ctx->pc;       slepok *= 0x100000001b3ull;
            slepok ^= (uint64_t)dispatches;    slepok *= 0x100000001b3ull;
            /* ★ Поток входит в слепок. Иначе одно и то же множество шагов,
             * исполненное РАЗНЫМИ потоками в РАЗНОМ порядке, дало бы один и тот
             * же отпечаток — и переплетение перестало бы проверяться. */
            slepok ^= (uint64_t)ev->tid;       slepok *= 0x100000001b3ull;
            /* ★★★ ЛЕЙН ЗАПИСЬ-ХОЗЯИНА: ВТОРОЙ СЛЕПОК — ТОЛЬКО ПУТЬ ГОСТЯ.
             *
             * В слепок выше входит `dispatches`, и это делает его зависимым от
             * ГЕЙТА, который мы меряем: при MACRUNNER_POVTOR_BLOKOV=1 заход
             * равен блоку, а разбиение на блоки задаётся кодогенерацией. Руки
             * ВКЛ/ВЫКЛ тогда получают РАЗНОЕ число заходов на одном и том же
             * пути гостя, и сторож «одинаковой работы» отвергает исправный
             * замер — та же беда, что была у счёта шагов до ПОВТОР-5.
             * Измерено: на отрезке 3 250 при BLOKOV=1 руки дают
             * 0xbd70fb0e58c7a68e против 0x7ce34ec9bb953ad7 при совпадающем
             * ходе исполнения.
             *
             * Поэтому слепков ДВА: `put` (как был, путь+заходы) и `put_pc`
             * (последовательность гостевых адресов по событиям). Сторож
             * одинаковой работы обязан сравнивать `put_pc`; `put` остаётся
             * как более строгий, но гейтозависимый. */
            slepok_pc ^= (uint64_t)k;          slepok_pc *= 0x100000001b3ull;
            slepok_pc ^= (uint64_t)ctx->pc;    slepok_pc *= 0x100000001b3ull;
            /* ★ ПОВТОР-5: СЛЕД ПО СОБЫТИЯМ. Руки замера обязаны делать ОДНУ
             * работу; когда числа шагов разошлись, надо знать НЕ «на сколько», а
             * НА КАКОМ СОБЫТИИ. Печать по диапазону, а не сплошь: сплошная
             * трасса на 400 000 событиях сама становится нагрузкой. */
            if (sled_lo <= k && k <= sled_hi)
                fprintf(stderr, "hb_povtor: SLED sob=%llu disp=%llu shag=%llu "
                        "pc=0x%llx zhdali=0x%llx doshli=%d\n",
                        (unsigned long long)k, (unsigned long long)dispatches,
                        (unsigned long long)steps, (unsigned long long)ctx->pc,
                        (unsigned long long)ev->pc, doshli);
            {
                uint64_t b = shagov_do;
                if (b > 8) b = 8;
                dohod[b]++;
            }
            if (doshli) {
                sovpalo++;
            } else if ((ctx->pc == 0xffff0000ull || ctx->pc == 0) &&
                       vneshnij_vozvrat(k)) {
                /* Гость вернулся к хосту — дальше зовёт хост, и запись честно
                 * показывает следующий вход. Расхождением это не является.
                 *
                 * ★ ЛЕЙН ЗАПИСЬ-ХОЗЯИНА: подстановка была БЕЗУСЛОВНОЙ. Нулевой
                 * pc принимался за «ушли к хосту» даже там, где в записи на
                 * этом месте НИКАКОГО внешнего возврата нет, — то есть повтор
                 * сам себе выдавал разрешение и записывал это в `sovpalo`.
                 * Теперь принимается только ТИПИЗИРОВАННОЕ событие: ВЫХОД, за
                 * которым (через события карты) ВХОД на ДРУГОМ pc. */
                ctx->pc = ev->pc;
                sovpalo++;
            } else {
                if (ev->kind == HB_REC_EXIT) div_exit++; else div_enter++;
                if ((verbose || g_strogo) && (div_exit + div_enter) <= 24)
                    fprintf(stderr, "hb_povtor: NE DOSHLI do %s 0x%llx: stoim na 0x%llx "
                            "(zahodov=%llu) sobytie=%llu disp=%llu\n",
                            ev->kind == HB_REC_EXIT ? "vyhoda" : "vhoda",
                            (unsigned long long)ev->pc, (unsigned long long)ctx->pc,
                            (unsigned long long)shagov_do, (unsigned long long)k,
                            (unsigned long long)dispatches);
                /* ★ ПЕРВОЕ ОТЛИЧАЮЩЕЕСЯ НАБЛЮДЕНИЕ — С ПОЛНОЙ АТРИБУЦИЕЙ.
                 * Именно оно, а не последнее, называет границу; ПОВТОР-4 и
                 * ПОВТОР-5 оба разбирали ПОСЛЕДСТВИЕ, потому что первое
                 * расхождение печаталось одной строкой без происхождения. */
                if ((div_exit + div_enter) == 1) pervoe_rashozhdenie(ctx, ev, k, dispatches, shagov_do);
                if (g_strogo) {
                    nedejstvitelno("hod ispolneniya",
                                   ev->kind == HB_REC_EXIT ? "ne doshli do vyhoda"
                                                           : "ne doshli do vhoda",
                                   (unsigned long long)ev->pc, (unsigned long long)k);
                    break;
                }
                if (!steer) break;
                ctx->pc = ev->pc;
            }

            /* ★★★★ ПОВТОР-5: ЯКОРЬ СОСТОЯНИЯ — ход уровня 4 к стене «непойманная
             * запись хоста».
             *
             * Стена выглядела так: на 1544-м заходе гость уходил на переходник
             * 0x6f00000022e0 с rsp=0 и падал на чтении по адресу 0x1. Прежний
             * разбор назвал причину «окна записи не поймали чужую запись» и
             * поставил задачу ловить записи ШИРЕ. Ловить шире значит гнаться за
             * множеством без границы: один уровень косвенности -> два -> обход
             * графа, и каждый шаг дороже предыдущего.
             *
             * Ловить не надо вовсе. ЗАПИСЬ УЖЕ НЕСЁТ ПОЛНОЕ СОСТОЯНИЕ ГОСТЯ НА
             * КАЖДОМ СОБЫТИИ — 400 000 из 400 000 (MACRUNNER_HB_RECORD_STATE_ALL
             * по умолчанию 1). Прежний повтор брал состояние ТОЛЬКО на возврате
             * от хоста: 436 точек из 2 168. Остальные 1 732 состояния лежали в
             * файле неиспользованными, и ровно из-за этого один непойманный
             * байт уводил регистр, а регистр — управление.
             *
             * Якорь ставит записанное состояние на КАЖДОМ событии, ПОСЛЕ того,
             * как посчитано, дошёл ли гость сам. Поэтому прибор честности НЕ
             * слабеет: `sovpalo` против `rashozhdenij` по-прежнему меряет, какую
             * долю пути движок прошёл БЕЗ подсказки. Меняется одно — расхождение
             * больше не НАКАПЛИВАЕТСЯ: каждый промежуток между событиями
             * начинается с истинного состояния живого прогона.
             *
             * Гейт MACRUNNER_POVTOR_YAKOR (умолч. 1); 0 возвращает поведение
             * ПОВТОР-4 и служит отрицательным контролем. */
            if (yakor && ev->has_state &&
                (yakor == 2 || ev->kind == HB_REC_ENTER))
                apply_state(ctx, ev->state);

            /* Подстановка результата хоста: выход, за которым вход на ДРУГОЙ pc.
             * События карты между ними ПРИМЕНЯЮТСЯ и пару не рвут. */
            {
                uint64_t nk = next_same_tid(k + 1, ev->tid);
                if (ev->kind == HB_REC_EXIT && nk < g_ev_n &&
                    g_ev[nk].kind == HB_REC_ENTER && g_ev[nk].pc != ev->pc) {
                    if (apply_writes(&g_ev[nk]) && g_strogo) { k = nk + 1; break; }
                    if (g_ev[nk].has_state) apply_state(ctx, g_ev[nk].state);
                    ctx->pc = g_ev[nk].pc;
                    host_applied++;
                    /* Возврат СЪЕДЕН, но прыгать на nk+1 нельзя: между k и nk
                     * стоят события чужих потоков, и прыжок съел бы их. */
                    g_consumed[nk] = 1;
                    k++;
                } else {
                    if (ev->kind == HB_REC_ENTER && ev->n_writes &&
                        apply_writes(ev) && g_strogo) { k = nk; break; }
                    if (ev->kind == HB_REC_EXIT && nk < g_ev_n &&
                        g_ev[nk].kind == HB_REC_ENTER && g_ev[nk].pc == ev->pc)
                        lift_returns++;
                    k++;
                }
            }
            /* ★ ЧАСОВОЙ. Значение ячейки печатается на КАЖДОМ событии отрезка
             * `--sled`, и ОТДЕЛЬНО — первое изменение за весь прогон. Это тот
             * самый безусловный зонд: он отвечает на «кто положил ноль» фактом,
             * а не выводом из ветвлений. */
            if (g_chasovoj) {
                unsigned char cur[32];
                uint32_t ci;
                int chitaem = 1;
                for (ci = 0; ci < g_chasovoj_n; ci++) {
                    if (!hb_memory_can_read(g_mem, (hb_gva_t)(g_chasovoj + ci), 1)) { chitaem = 0; break; }
                    cur[ci] = *(volatile unsigned char*)(uintptr_t)(g_chasovoj + ci);
                }
                if (!chitaem) memset(cur, 0, sizeof(cur));
                if (!g_chasovoj_bylo || memcmp(cur, g_chasovoj_pred, g_chasovoj_n)) {
                    fprintf(stderr, "hb_povtor: CHASOVOJ IZMENENIE sob=%llu disp=%llu "
                            "addr=0x%llx chitaem=%d bajty:",
                            (unsigned long long)k, (unsigned long long)dispatches,
                            (unsigned long long)g_chasovoj, chitaem);
                    for (ci = 0; ci < g_chasovoj_n; ci++) fprintf(stderr, " %02x", cur[ci]);
                    fprintf(stderr, "\n");
                    memcpy(g_chasovoj_pred, cur, g_chasovoj_n);
                    g_chasovoj_bylo = 1;
                    g_chasovoj_izmenenij++;
                }
                if (sled_lo <= k && k <= sled_hi) {
                    fprintf(stderr, "hb_povtor: CHASOVOJ sob=%llu addr=0x%llx bajty:",
                            (unsigned long long)k, (unsigned long long)g_chasovoj);
                    for (ci = 0; ci < g_chasovoj_n; ci++) fprintf(stderr, " %02x", cur[ci]);
                    fprintf(stderr, "\n");
                }
            }
        }
        {
            uint64_t rep_ns = now_ns() - rep_t0;
            if (rep == 0) {
                ns_cold = rep_ns; steps_cold = steps_rep; disp_cold = disp_rep;
            } else {
                ns_warm_sum += rep_ns; warm_reps++;
                /* ★ СТОРОЖ ПОЛНОТЫ ВОЗВРАТА. Тёплый проход обязан сделать РОВНО
                 * ту же работу, что холодный. Разошлось — состояние осталось
                 * где-то ещё, и время таких проходов сравнивать нельзя. */
                if (steps_rep != steps_cold) {
                    warm_mismatch++;
                    if (warm_mismatch <= 4)
                        fprintf(stderr, "hb_povtor: PROGREV RAZOSHYOLSYA prohod=%llu "
                                "shagov=%llu protiv holodnyh %llu\n",
                                (unsigned long long)rep, (unsigned long long)steps_rep,
                                (unsigned long long)steps_cold);
                }
            }
        }
    }

    t1 = now_ns();

    printf("hb_povtor: ITOG ns=%llu dispatchej=%llu shagov=%llu blokov=%llu "
           "podnyato=%llu popadanij=%llu ne_podnyalos=%llu\n",
           (unsigned long long)(t1 - t0), (unsigned long long)dispatches,
           (unsigned long long)steps, (unsigned long long)blocks,
           (unsigned long long)g_lifts, (unsigned long long)g_lift_hits,
           (unsigned long long)g_lift_fail);
    /* ХОЛОДНЫЙ проход несёт подъём IR и выпуск кода; ТЁПЛЫЕ — только
     * исполнение выпущенного. `ns_tyoplyj` — время ОДНОГО тёплого прохода;
     * им и надо мерить гейты, меняющие качество выпущенного кода. */
    /* ★★★★ РАЗДЕЛЕНИЕ ВРЕМЕНИ: ПЕРВОЕ исполнение блока против ПОВТОРНОГО.
     *
     * Первое исполнение несёт подъём IR и выпуск кода ARM64; повторное —
     * только исполнение уже выпущенного. Гейты, которые мы мерим (нативная
     * память и прочая кодогенерация), меняют КАЧЕСТВО выпущенного кода, то
     * есть видны только во втором ведре. Смешав вёдра, получаешь заниженное
     * число и называешь его «повтор занижает». */
    if (razdelit && (n_first || n_again)) {
        printf("hb_povtor: RAZDELENIE pervyh=%llu ns_pervyh=%llu shagov_pervyh=%llu "
               "povtornyh=%llu ns_povtornyh=%llu shagov_povtornyh=%llu "
               "dolya_pervyh_pct=%.2f\n",
               (unsigned long long)n_first, (unsigned long long)ns_first,
               (unsigned long long)steps_first,
               (unsigned long long)n_again, (unsigned long long)ns_again,
               (unsigned long long)steps_again,
               (ns_first + ns_again)
                   ? 100.0 * (double)ns_first / (double)(ns_first + ns_again) : 0.0);
    }
    if (warm_reps) {
        uint64_t warm_ns = ns_warm_sum / warm_reps;
        printf("hb_povtor: PROGREV ns_holodnyj=%llu ns_tyoplyj=%llu prohodov_tyoplyh=%llu "
               "shagov_holodnyh=%llu dispatchej_holodnyh=%llu rassoglasovanij=%llu "
               "dolya_kodogeneracii_pct=%.2f\n",
               (unsigned long long)ns_cold, (unsigned long long)warm_ns,
               (unsigned long long)warm_reps, (unsigned long long)steps_cold,
               (unsigned long long)disp_cold, (unsigned long long)warm_mismatch,
               ns_cold > warm_ns
                   ? 100.0 * (double)(ns_cold - warm_ns) / (double)ns_cold : 0.0);
    }
    printf("hb_povtor: ISHODY otkatov_na_interp=%llu ret_ne_ok=%llu out_ne_ok=%llu "
           "predel_shagov=%llu zastryali=%llu novyh_oblastej=%llu perehodnikov=%llu\n",
           (unsigned long long)fallbacks, (unsigned long long)run_errors,
           (unsigned long long)res_errors, (unsigned long long)step_limit_hits,
           (unsigned long long)zastryali, (unsigned long long)novyh_oblastej,
           (unsigned long long)perehodnikov);
    printf("hb_povtor: TOCHNOST rashozhdenij_vyhoda=%llu rashozhdenij_vhoda=%llu "
           "sovpalo=%llu vozvratov_gostya=%llu hosta_primeneno=%llu perevodov=%llu zapisej_primeneno=%llu "
           "bajt=%llu stranic_dovedeno=%llu (dyr_zapisi=%llu novyh=%llu) "
           "otkazov_gostya=%llu bez_podyoma=%llu\n",
           (unsigned long long)div_exit, (unsigned long long)div_enter,
           (unsigned long long)sovpalo,
           (unsigned long long)guest_returns, (unsigned long long)host_applied, (unsigned long long)lift_returns,
           (unsigned long long)g_writes_applied, (unsigned long long)g_write_bytes,
           (unsigned long long)g_faults_fixed,
           (unsigned long long)g_faults_v_zapisi, (unsigned long long)g_faults_novye,
           (unsigned long long)g_faults_guest, (unsigned long long)no_lift);
    printf("hb_povtor: KARTA versiya=%u sobytij_karty=%llu (v zagolovke %llu) "
           "zavedeno=%llu bajt=%llu snyato=%llu ne_udalos=%llu\n",
           g_hdr.version, (unsigned long long)g_map_ev_n,
           (unsigned long long)g_hdr.n_map_events,
           (unsigned long long)g_map_done, (unsigned long long)g_map_bytes,
           (unsigned long long)g_unmap_done, (unsigned long long)g_map_failed);
    {
        uint64_t q, zhivyh = 0;
        for (q = 0; q < POVTOR_MAX_TID; q++) if (g_ctx[q]) zhivyh++;
        printf("hb_povtor: POTOKI-ITOG nomerov=%llu kontekstov=%llu odin_kontekst=%d\n",
               (unsigned long long)g_tid_seen, (unsigned long long)zhivyh,
               g_odin_kontekst > 0);
    }
    printf("hb_povtor: SLEPOK put=0x%016llx put_pc=0x%016llx dispatchej=%llu shagov=%llu blokov=%llu\n",
           (unsigned long long)slepok, (unsigned long long)slepok_pc,
           (unsigned long long)dispatches,
           (unsigned long long)steps, (unsigned long long)blocks);
    printf("hb_povtor: DOHOD sobytij=%llu zahodov_do_sobytiya: "
           "0=%llu 1=%llu 2=%llu 3=%llu 4=%llu 5=%llu 6=%llu 7=%llu 8+=%llu byudzhet=%llu\n",
           (unsigned long long)sob_obr,
           (unsigned long long)dohod[0], (unsigned long long)dohod[1],
           (unsigned long long)dohod[2], (unsigned long long)dohod[3],
           (unsigned long long)dohod[4], (unsigned long long)dohod[5],
           (unsigned long long)dohod[6], (unsigned long long)dohod[7],
           (unsigned long long)dohod[8], (unsigned long long)reach_budget);
    if (steps)
        printf("hb_povtor: ns_na_shag=%.4f\n", (double)(t1 - t0) / (double)steps);

    /* ★★★★ РЕЖИМ И ИТОГ. Прежде повтор ВСЕГДА возвращал 0 — и `otkazov_gostya=36`
     * не мешало этому ни в одной строке. Теперь режим назван, а причины
     * недействительности перечислены по одной; PASS есть только у строгого. */
    if (g_strogo) {
        if (g_faults_guest)
            nedejstvitelno("otkazy gostya", "gost' upal, a povtor shyol dal'she",
                           0, (unsigned long long)g_faults_guest);
        if (g_wr_ne_legli)
            nedejstvitelno("dostavka", "bajty ne legli", 0,
                           (unsigned long long)g_wr_ne_legli);
        /* ★ ДОВЕДЕНИЕ СТРАНИЦЫ ПО ОТКАЗУ — ТОЖЕ НЕДЕЙСТВИТЕЛЬНОСТЬ.
         * Это реактивный путь: страницы, которой в записи нет, заводятся
         * нулями прямо из обработчика сигнала. В диагностическом режиме он
         * полезен (даёт дойти дальше и назвать адрес), в строгом — маскирует
         * ровно тот случай, ради которого строгий режим и заведён. Контроль
         * K-payload показал это числом: он краснел по расхождению, а
         * `stranic_dovedeno=2` при этом оставалось незамеченным. */
        if (g_faults_fixed)
            nedejstvitelno("obraz pamyati", "stranicy dovedeny po otkazu, "
                           "v zapisi ih net", 0, (unsigned long long)g_faults_fixed);
    }
    printf("hb_povtor: REZHIM %s steering=%d dyry=%s yakor=%u "
           "zapisej_otkazano=%llu bajt_otkazano=%llu razbor_oborvan=%llu (%s) "
           "sobytij_v_fajle=%llu v_zagolovke=%llu seq_ne_po_poryadku=%llu "
           "chasovoj_izmenenij=%llu prichin_nedejstvitelnosti=%llu\n",
           g_strogo ? "STROGIJ" : "DIAGNOSTICHESKIJ", steer,
           g_strogo ? "net" : "zavodyatsya-nulyami", yakor,
           (unsigned long long)g_wr_otkazano, (unsigned long long)g_wr_bajt_otkazano,
           (unsigned long long)g_razbor_oborvan, g_razbor_prichina,
           (unsigned long long)g_razbor_sobytij_v_fajle,
           (unsigned long long)g_hdr.n_events,
           (unsigned long long)g_seq_ne_po_poryadku,
           (unsigned long long)g_chasovoj_izmenenij,
           (unsigned long long)g_nedejstvitelno);
    if (g_strogo)
        printf("hb_povtor: STROGO %s prichin=%llu\n",
               g_nedejstvitelno ? "NEDEJSTVITELNO" : "PROJDENO",
               (unsigned long long)g_nedejstvitelno);
    fflush(stdout);

    hb_jit_runtime_destroy(rt);
    /* Ненулевой код возврата — единственное, что видит скрипт приёмки. */
    if (g_strogo && g_nedejstvitelno) return 4;
    return 0;
}
