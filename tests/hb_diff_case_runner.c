#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_flags.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <ctype.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
/* `<ucontext.h>` на macOS требует _XOPEN_SOURCE и объявлен устаревшим; `mcontext_t` и
 * `ucontext_t` приходят из `<signal.h>` через `<sys/_types/_ucontext.h>` — движок
 * (`hb_memory.c`) читает контекст сигнала ровно так же. */
#include <sys/ucontext.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ★ БАЗА ЗАГРУЗКИ x64 — НАСТОЯЩАЯ (лейн РЕГИСТРЫ, 19.08).
 *
 * 0x100000 (1 МБ) не бывает у настоящего x64-PE: он грузится по 0x140000000. Разница
 * меняет ПРОВЕРЯЕМЫЙ ПУТЬ, а не только числа: гостевые адреса переходов укладываются как
 * константы, и порог короткой укладки (`MACRUNNER_HB_IMM_COMPACT`) проходит по 4 ГБ.
 * При базе 1 МБ они шли КОРОТКОЙ укладкой, а в бою идут четырёхсловной с релокацией —
 * то есть боевой путь сличением проверялся ХУЖЕ, чем неболевой.
 *
 * У 32-разрядного гостя база остаётся низкой: там весь адрес умещается в 32 бита.
 * Переопределяется HB_DIFF_BASE. */
#define HB_DIFF_CODE_BASE_X64 0x140000000ULL
#define HB_DIFF_CODE_BASE_X86 0x100000ULL
static unsigned long long hb_diff_code_base(int flat32) {
    const char* e = getenv("HB_DIFF_BASE");
    if (e && *e) return strtoull(e, NULL, 0);
    return flat32 ? HB_DIFF_CODE_BASE_X86 : HB_DIFF_CODE_BASE_X64;
}
/* ★★★★★ 06.09.2026, лейн СЛИЯНИЕ — ТОЖДЕСТВЕННОЕ ОТОБРАЖЕНИЕ ПАМЯТИ ГОСТЯ (HB_DIFF_IDENTITY=1).
 *
 * ЗАЧЕМ. Прямой путь памяти на x64 (`MACRUNNER_HB_JIT_DIRECT_MEM`, с 06.09 умолчание 1)
 * обращается к ГОСТЕВОМУ адресу как к ХОЗЯЙСКОМУ: `emit_x86_ea_to_host` на x64 выходит
 * первой строкой, а `store_perm_checked_by_host_mmu` прямо пишет «x64 — отображение
 * ТОЖДЕСТВЕННОЕ, гостевой адрес и есть хозяйский». В бою это так и есть.
 *
 * СТЕНД ЭТОГО НЕ МОДЕЛИРОВАЛ. `hb_memory_map_private` зовёт `mmap(NULL, ...)`, то есть
 * хозяйский адрес произвольный, а гостевые базы (0x70000000/0x71000000) лежат ВНУТРИ
 * четырёхгигабайтного `__PAGEZERO` и отобразить их тождественно нельзя в принципе.
 * Итог, измеренный 06.09: любое обращение прямого пути к памяти гостя даёт EXEC_FAULT,
 * то есть весь этот путь стендом НЕ ПРОВЕРЯЛСЯ НИКОГДА — ни одним корпусом.
 * Числа: корпус ФЛАГИ-mem при DIRECT_MEM=0 даёт 0 слияний (8042 отказа ZAGRUZCHIK),
 * при DIRECT_MEM=1 — 7546 слияний и 2560 «случай не исполнился».
 *
 * ЧТО ДЕЛАЕТ РЕЖИМ. Базы данных и стека поднимаются ВЫШЕ 4 ГБ, области заводятся
 * `mmap(MAP_FIXED)` по своему же адресу и регистрируются `hb_memory_map` — а такая
 * область (allocated=false, host_base=NULL) читается движком тождественно
 * (`hb_memory_read_inner`, hb_memory.c:4033: `memcpy(out, (const void*)addr, size)`).
 * То есть обе половины — интерпретатор и выпущенный код — видят ОДИН И ТОТ ЖЕ адрес,
 * как в бою.
 *
 * ГРАНИЦЫ. Режим только для x64: у 32-битного гостя своё окно (`guest32`), и адрес
 * обязан умещаться в 32 бита. Умолчание ВЫКЛ — прежние корпуса и чужие лейны не
 * затронуты ни на байт. Корпуса с ЗАШИТЫМ адресом 0x70000000 в этом режиме не годятся:
 * операнд памяти надо задавать ОТНОСИТЕЛЬНО регистра (так и делает настоящий код). */
#define HB_DIFF_DATA_BASE_LOW   0x70000000ULL
#define HB_DIFF_STACK_BASE_LOW  0x71000000ULL
/* ★ БАЗЫ ТОЖДЕСТВЕННОГО РЕЖИМА ПЕРЕОПРЕДЕЛЯЮТСЯ — `HB_DIFF_IDENT_BASE=0x...`.
 *
 * Не удобство, а ПРИБОР ДЛЯ ПОТОЛКА. 0x270000000 стоит ВПЛОТНУЮ к общему кешу dyld
 * (замер: 0x180000000..0x300000000 отображено на чтение), поэтому адрес вида
 * `DATA_BASE + случайное32` попадает В КЕШ, читается — и прямой путь проходит там, где
 * интерпретатор отказывает. Ограда накрыть кеш не может: он чужой и нужен процессу.
 * Перенос баз ВЫШЕ кеша убирает этот источник целиком, и переменная позволяет это
 * ИЗМЕРИТЬ, а не обсудить. */
static unsigned long long hb_diff_ident_base(void) {
    static unsigned long long cached;
    if (!cached) {
        const char* e = getenv("HB_DIFF_IDENT_BASE");
        cached = (e && *e) ? strtoull(e, NULL, 0) : 0x270000000ULL;
        cached &= ~0xffffffULL;   /* 16 МБ — шаг окон ниже */
        if (!cached) cached = 0x270000000ULL;
    }
    return cached;
}
#define HB_DIFF_DATA_BASE_IDENT  (hb_diff_ident_base())
#define HB_DIFF_STACK_BASE_IDENT (hb_diff_ident_base() + 0x1000000ULL)

static int hb_diff_identity_gate(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* e = getenv("HB_DIFF_IDENTITY");
        cached = (e && *e && *e != '0') ? 1 : 0;
    }
    return cached;
}

/* Активность режима ЗАВИСИТ ОТ РАЗРЯДНОСТИ, поэтому она снимается в init_context и
 * держится здесь: и засев регистров, и снимок памяти обязаны видеть ту же базу, что
 * и отображение. Внутри одного случая обе руки идут через init_context, значит
 * значение не может разъехаться между интерпретатором и выпуском. */
static int g_diff_identity_active;

#define HB_DIFF_DATA_BASE  (g_diff_identity_active ? HB_DIFF_DATA_BASE_IDENT  : HB_DIFF_DATA_BASE_LOW)
#define HB_DIFF_STACK_BASE (g_diff_identity_active ? HB_DIFF_STACK_BASE_IDENT : HB_DIFF_STACK_BASE_LOW)

/* Завести область ТОЖДЕСТВЕННО: хозяйская страница по тому же адресу, что и гостевая.
 *
 * `MAP_FIXED` берётся ОДИН РАЗ на адрес и запоминается: повторный MAP_FIXED каждый случай
 * снёс бы чужое отображение, если бы ядро успело отдать туда что-то своё (плита выпуска
 * заводится тем же mmap без адреса). Содержимое между случаями обнуляется — иначе данные
 * прошлого случая протекли бы в следующий, а прежний путь (`map_private`) отдавал свежие
 * нулевые страницы.
 *
 * Регистрация — `hb_memory_map` (не `_private`): она заводит область с allocated=false и
 * host_base=NULL, а такую движок читает тождественно (hb_memory.c:4033). */
#define HB_DIFF_IDENT_SLOTS 4
static struct { unsigned long long base; size_t size; } g_ident_slots[HB_DIFF_IDENT_SLOTS];
static int g_ident_slot_n;

/* ★ ЗАГЛУШКА ВОКРУГ ОБЛАСТЕЙ ГОСТЯ — иначе отрицательный ответ стенда НЕ ВОСПРОИЗВОДИМ.
 *
 * Прямой путь читает гостевой адрес как хозяйский и прав не проверяет. Если адрес лежит ЗА
 * пределами заведённой области, ответ зависит от того, отобразило ли ядро что-нибудь рядом
 * (плита выпуска, куча) — а это меняется от прогона к прогону. Замер это и показал: корпус
 * «настоящий x64» в тождественном режиме давал 555 и 575 отказов базы на одном двоичном.
 *
 * Поэтому вокруг обеих баз резервируется PROT_NONE, и обращение за пределы области ВСЕГДА
 * даёт хозяйский отказ. Рабочие области кладутся MAP_FIXED поверх заглушки. */
/* ★★★★ MacRunner 2026-09-07, лейн ОРАКУЛ — ОГРАДА ПО ВСЕЙ ДОСЯГАЕМОЙ ОБЛАСТИ.
 *
 * ИЗМЕРЕНО. Трёх окон выше НЕ ХВАТАЕТ, и вот чем это доказано. Случай
 * `mov rax,[rbx+rdi*2]` при засеве `rbx≈rdi≈DATA_BASE` даёт адрес
 * `0x270000000 + 2*0x270001000 = 0x750002xxx` — в 32 раза дальше любого окна. Замер по
 * полю `host_addr` нового снимка: отказ приходил ровно по `0x7500023da`, `0x7500023ea`,
 * `0x7500023fe`, `0x750001b2a`, `0x75000162e`. Отобразит ли ядро что-нибудь по этому
 * адресу к моменту N-го случая — зависит от того, докуда доросли выделения ПРОЦЕССА, а
 * это меняется от прогона к прогону. Так и плавал тождественный режим: 12 случаев из
 * 3750 (0,32 %) отвечали то отказом, то успехом.
 *
 * ОГИБАЮЩАЯ СЧИТАЕТСЯ, А НЕ УГАДЫВАЕТСЯ. Все базовые и индексные регистры засеваются
 * внутрь области данных (`init_context`), масштаб индекса не больше 8, смещение не больше
 * знакового 32-битного. Значит достижимо
 *      [ DATA_BASE - 2 ГБ , STACK_BASE + 8*(DATA_BASE + 0x1100) + 2 ГБ ]
 * что при нынешних базах даёт верх ≈ 0x1671008800. Берём с запасом до 0x1800000000.
 *
 * ★ MAP_FIXED ПО ВСЕМУ ДИАПАЗОНУ БЫЛ БЫ КАТАСТРОФОЙ: в него попадает общий кеш dyld.
 * Поэтому сначала спрашиваем ядро, что уже занято (`mach_vm_region`), и накрываем ТОЛЬКО
 * дыры. Занятое остаётся как есть — и это названная граница: сдвиг общего кеша
 * задаётся ЗАГРУЗКОЙ СИСТЕМЫ, один на все процессы, поэтому от прогона к прогону он не
 * меняется, а от перезагрузки — меняется.
 *
 * Ограда только для тождественного режима x64 (у i386 своё окно `guest32`).
 * Отключается `HB_DIFF_NO_FENCE=1` — ради A/B, а не ради «выключить проверку». */
/* Огибающая считается ОТ БАЗ, а не задаётся числом: базы переопределяемы (см. выше), и
 * зашитая константа при переносе баз молча оставила бы половину диапазона без ограды. */
static unsigned long long hb_diff_fence_lo(void) {
    unsigned long long b = hb_diff_ident_base();
    return b > 0x80000000ULL ? b - 0x80000000ULL : 0x10000ULL;   /* база − 2 ГБ (disp32) */
}
static unsigned long long hb_diff_fence_hi(void) {
    unsigned long long b = hb_diff_ident_base();
    /* стек + 8*(база + 0x1100) + 2 ГБ, с запасом вверх до границы 16 МБ */
    unsigned long long hi = b + 0x1000000ULL + 8ULL * (b + 0x1100ULL) + 0x80000000ULL;
    return (hi + 0xffffffULL) & ~0xffffffULL;
}

static unsigned long g_fence_holes;
static unsigned long long g_fence_bytes;

static int hb_diff_fence_off(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* e = getenv("HB_DIFF_NO_FENCE");
        cached = (e && *e && *e != '0') ? 1 : 0;
    }
    return cached;
}

static void hb_diff_fence(unsigned long long lo, unsigned long long hi) {
    mach_vm_address_t a = (mach_vm_address_t)lo;
    while (a < (mach_vm_address_t)hi) {
        mach_vm_address_t r = a, gap_end, next;
        mach_vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &cnt, &obj);
        if (kr != KERN_SUCCESS || r >= (mach_vm_address_t)hi) {
            gap_end = (mach_vm_address_t)hi;
            next = (mach_vm_address_t)hi;
        } else {
            gap_end = r > a ? r : a;
            next = r + sz;
        }
        if (kr == KERN_SUCCESS && r < (mach_vm_address_t)hi && getenv("HB_DIFF_FENCE_TRACE")) {
            /* ЗАНЯТОЕ — то, что оградой НЕ накрыто и потому остаётся источником
             * «адрес оказался отображён». Печатается по гейту, чтобы граница вывода
             * была видна числом, а не подразумевалась. */
            fprintf(stderr, "hb-diff-ограда-занято: 0x%llx..0x%llx (%llu МБ) prot=%d/%d\n",
                    (unsigned long long)r, (unsigned long long)(r + sz),
                    (unsigned long long)(sz >> 20), info.protection, info.max_protection);
        }
        if (gap_end > a) {
            size_t len = (size_t)(gap_end - a);
            void* p = mmap((void*)(uintptr_t)a, len, PROT_NONE,
                           MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE, -1, 0);
            if (p != MAP_FAILED && (mach_vm_address_t)(uintptr_t)p == a) {
                g_fence_holes++;
                g_fence_bytes += len;
            } else {
                fprintf(stderr, "hb-diff-ограда: дыра 0x%llx+0x%zx не накрыта (%p)\n",
                        (unsigned long long)a, len, p);
            }
        }
        a = next > a ? next : a + 0x4000;
    }
}

static void hb_diff_identity_reserve(void) {
    static int done;
    unsigned i;
    const unsigned long long okna[][2] = {
        { HB_DIFF_CODE_BASE_X64,       0x01000000ULL },   /* 16 МБ вокруг кода   */
        { HB_DIFF_DATA_BASE_IDENT,     0x02000000ULL },   /* 32 МБ вокруг данных */
        { HB_DIFF_STACK_BASE_IDENT,    0x01000000ULL },   /* 16 МБ вокруг стека  */
    };
    if (done) return;
    done = 1;
    for (i = 0; i < sizeof(okna) / sizeof(okna[0]); i++) {
        void* p = mmap((void*)(uintptr_t)okna[i][0], (size_t)okna[i][1], PROT_NONE,
                       MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE, -1, 0);
        if (p == MAP_FAILED || (unsigned long long)(uintptr_t)p != okna[i][0])
            fprintf(stderr, "hb-diff-identity: заглушка 0x%llx+0x%llx не встала (%p)\n",
                    okna[i][0], okna[i][1], p);
    }
    /* Ограда ПОСЛЕ окон: окна уже заняты и в дыры не попадут. */
    if (!hb_diff_fence_off()) hb_diff_fence(hb_diff_fence_lo(), hb_diff_fence_hi());
}

/* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ — ОБЛАСТЬ ГОСТЯ КОНЧАЕТСЯ ПОСЕРЕДИНЕ СТРАНИЦЫ.
 *
 * НАЙДЕНО ЗАМЕРОМ. После закрытия дыры №1 на `длинный-x64` осталось РОВНО 10 случаев,
 * где интерпретатор отказывает, а выпущенный код проходит. Пример из десяти:
 *     movaps xmm6,[rsp+0x21b0]   при rsp = STACK_BASE + 0x1000  ->  адрес +0x31b0
 * Область стека объявлена движку размером `HB_DIFF_STACK_SIZE` = 0x2000, а страница
 * macOS ARM64 — 0x4000. `mmap` округляет ВВЕРХ, поэтому [0x2000,0x4000) хозяином
 * ОТОБРАЖЕНО и читается, а движку про него не сказано. Интерпретатор проверяет область
 * программно и отказывает; прямой путь читает хозяйскую страницу и проходит.
 *
 * Это дефект МОДЕЛИ СТЕНДА, а не движка: в бою wine заводит области гостя страницами, и
 * область никогда не кончается посреди страницы. Гейт `HB_DIFF_PAGE_REGIONS=1` выравнивает
 * объявляемый размер до страницы (и обнуляет её целиком — иначе хвост протёк бы между
 * случаями). Умолчание ВЫКЛ: смена сдвинула бы базовые числа всех соседних лейнов, и
 * решение об этом не моё. Число названо, см. отчёт. */
static size_t hb_diff_page_size(void) {
    static size_t ps;
    if (!ps) ps = (size_t)getpagesize();
    return ps;
}

static int hb_diff_page_regions(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* e = getenv("HB_DIFF_PAGE_REGIONS");
        cached = (e && *e && *e != '0') ? 1 : 0;
    }
    return cached;
}

static size_t hb_diff_region_size(size_t size) {
    size_t ps;
    if (!hb_diff_page_regions()) return size;
    ps = hb_diff_page_size();
    return (size + ps - 1) & ~(ps - 1);
}

static hb_result_t hb_diff_map_identity(hb_memory_t* mem, unsigned long long base,
                                        size_t size, hb_perm_t perm) {
    int i;
    size = hb_diff_region_size(size);
    hb_diff_identity_reserve();
    for (i = 0; i < g_ident_slot_n; i++)
        if (g_ident_slots[i].base == base && g_ident_slots[i].size >= size) break;
    if (i == g_ident_slot_n) {
        void* p = mmap((void*)(uintptr_t)base, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED || (unsigned long long)(uintptr_t)p != base) {
            fprintf(stderr, "hb-diff-identity: mmap 0x%llx+%zu отказал (%p) — режим НЕ применим\n",
                    base, size, p);
            return HB_ERR_OUT_OF_MEMORY;
        }
        if (g_ident_slot_n < HB_DIFF_IDENT_SLOTS) {
            g_ident_slots[g_ident_slot_n].base = base;
            g_ident_slots[g_ident_slot_n].size = size;
            g_ident_slot_n++;
        }
    }
    memset((void*)(uintptr_t)base, 0, size);
    return hb_memory_map(mem, (hb_gva_t)base, size, perm);
}
#define HB_DIFF_DATA_SIZE  0x2000U
/* Итерация 546: отображаем 4 МБ при засеве 8 КБ — см. unicorn_adapter.py, там же обоснование. */
#define HB_DIFF_DATA_MAP_SIZE 0x400000U
#define HB_DIFF_STACK_SIZE 0x2000U
/* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 279 — ПРЕДЕЛ ДЛИНЫ СЛУЧАЯ.
 * Было 15 байт — ровно максимальная длина одной команды x86. С итерации 276 стенд кладёт перед
 * случаем общую преамбулу x87 (`FNINIT; FLD1; FLDPI; FLDL2E`, 8 байт), и длинные команды
 * перестали помещаться: прогон отвечал `{"ok":false,"error":"bad_hex"}`, а стенд считал это
 * отказом семантики. Так в остатке появились «не исполнившиеся» случаи, которых на деле не было.
 * 32 байта покрывают преамбулу плюс любую команду с запасом. */
/* ★ ПРЕДЕЛ ПОДНЯТ 32 -> 128 БАЙТ (лейн РЕГИСТРЫ, итерация 126).
 *
 * Зачем. Итерация 125 измерила: в корпусе закрепляется 2,0 % блоков, а в настоящем кеше
 * прогонов — 13,9 %. Это не про величину выигрыша (её берут по кешу), это про ПОЛНОТУ
 * ПРОВЕРКИ: сличение с интерпретатором гоняло путь закрепления на 71 блоке из 3510.
 *
 * Причина структурная: случай корпуса ограничен 32 байтами гостя, поэтому постоянная обвязка
 * блока весит в нём больше, а гостевое тело меньше — обращений к файлу регистров 2,20 на блок
 * против 3,14 у настоящих. Порог отбора (`n > cost`) нелинеен, и эти 1,43 раза плотности
 * дают 7 раз разницы в доле закрепляемых блоков.
 *
 * ★ ОБРЕЗКА БЫЛА МОЛЧАЛИВОЙ: разбор останавливался на пределе, а третье поле случая
 * (ожидаемое число команд) оставалось прежним — то есть длинный случай превращался в чужой,
 * и поймать это мог только входной сторож. Предел поднят вместе с буфером строки. */
#define HB_DIFF_MAX_CODE   128U
#define HB_DIFF_FNV64_OFFSET 0xcbf29ce484222325ULL
#define HB_DIFF_FNV64_PRIME  0x100000001b3ULL
#define HB_DIFF_RFLAGS_FUZZ_MASK 0xcd5ULL

typedef struct {
    hb_arch_t arch;
    uint64_t gpr[16];
    uint64_t rip;
    uint32_t eip;
    hb_flags_t flags;
    uint64_t rflags;
    uint32_t flag_mask;
    hb_result_t flag_status;
    bool lazy_pending;
    uint8_t lazy_kind;
    uint8_t lazy_width;
    uint64_t lazy_lhs;
    uint64_t lazy_rhs;
    uint64_t lazy_result;
    uint64_t lazy_count;
    uint8_t xmm[16][16];
    uint8_t ymm_hi[16][16];
    uint8_t zmm_hi[16][32];
    uint8_t xmm_ext[16][16];
    uint8_t ymm_hi_ext[16][16];
    uint8_t zmm_hi_ext[16][32];
    uint64_t k[8];
    uint32_t sse_mxcsr;
    uint64_t sse_host_control, sse_host_status;
    uint16_t x87_cw;
    uint16_t x87_sw;
    uint16_t x87_tag;
    /* СЕЛЕКТОРЫ СЕГМЕНТОВ, порядок как в hb_context.h: ES,CS,SS,DS,FS,GS.
     * Стенд их не заводил и не показывал, поэтому `mov eax, cs` у нас давал
     * ноль, а у оракула — селектор его стенда, и все 18 форм `mov r, sreg`
     * числились расхождением. Снимок обязан уметь показать то, что заведено. */
    uint16_t seg[6];
    uint8_t data[HB_DIFF_DATA_SIZE];
    uint8_t stack[HB_DIFF_STACK_SIZE];
    hb_result_t api_result;
    hb_result_t exec_result;
    /* Итерация 771: вид отказа исполнения (`ctx->last_fault_kind`) и адрес. Без них
     * пометка причины (#DE против перехода по нулю) не наблюдаема ничем, кроме прогона
     * игры, а прогоны под запретом. Стенд обязан уметь показать то, что мы завели. */
    uint32_t fault_kind;
    uint64_t fault_addr;
    /* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ — ОТКАЗ КАК ЧАСТЬ СРАВНИВАЕМОГО СОСТОЯНИЯ.
     *
     * Два поля выше СНИМАЛИСЬ и печатались с итерации 771, но НЕ СРАВНИВАЛИСЬ, а случай
     * с отказом до сравнения вообще не доходил (`ok` требовал HB_OK от обеих рук). Ещё
     * два поля отказа не снимались вовсе:
     *   `last_fault_addr_valid` — различает «адреса нет» и «адрес равен нулю»; у перехода
     *      по нулю он именно нулевой, и без признака доставка гостю неотличима;
     *   `last_fault_pc`         — адрес КОМАНДЫ, вызвавшей отказ. Это ExceptionAddress
     *      гостя. Ровно здесь лейн КРАЯ-АДРЕСОВ нашёл потерю точности на невыровненном
     *      доступе, и до сих пор проверить её общим оракулом было НЕЧЕМ.
     * Все четыре — гостевое наблюдаемое, поэтому входят в состояние. */
    uint64_t fault_pc;
    uint8_t fault_addr_valid;
    /* ХОЗЯЙСКИЙ отказ (сигнал стенда). НЕ гостевое наблюдаемое и потому НЕ сравнивается —
     * печатается как улика: по нему видно, взяла ли дверь движка отказ выпущенного кода
     * или он ушёл в ограждение стенда. Именно это различие решало, есть ли у нас вообще
     * `fault_kind` на пути прямой памяти x64. */
    int host_sig;
    int host_code;
    uint64_t host_addr;
} hb_diff_snapshot_t;

static uint64_t splitmix64_next(uint64_t* state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static bool parse_hex_bytes(const char* s, uint8_t* out, size_t max_out, size_t* out_len) {
    size_t n = 0;
    while (*s) {
        while (*s && isspace((unsigned char)*s)) s++;
        if (!*s) break;
        int hi = hex_nibble(*s++);
        if (hi < 0 || !*s) return false;
        int lo = hex_nibble(*s++);
        if (lo < 0 || n >= max_out) return false;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return n > 0;
}

static bool parse_hex(const char* s, uint8_t* out, size_t* out_len) {
    return parse_hex_bytes(s, out, HB_DIFF_MAX_CODE, out_len);
}

static void print_hex_bytes(const uint8_t* bytes, size_t len) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        putchar(hex[bytes[i] >> 4]);
        putchar(hex[bytes[i] & 0xf]);
    }
}

static uint64_t fnv1a64(const uint8_t* bytes, size_t len) {
    uint64_t h = HB_DIFF_FNV64_OFFSET;
    for (size_t i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= HB_DIFF_FNV64_PRIME;
    }
    return h;
}

static void set_flags_from_bits(hb_context_t* ctx, uint64_t bits) {
    ctx->flags.cf = (bits & 0x001) != 0;
    ctx->flags.pf = (bits & 0x004) != 0;
    ctx->flags.af = (bits & 0x010) != 0;
    ctx->flags.zf = (bits & 0x040) != 0;
    ctx->flags.sf = (bits & 0x080) != 0;
    ctx->flags.of = (bits & 0x800) != 0;
    uint64_t image = (bits & HB_DIFF_RFLAGS_FUZZ_MASK) | 0x202ULL;
    if (ctx->mode == HB_MODE_32BIT) ctx->regs.x86.eflags = (uint32_t)image;
    else ctx->regs.x64.rflags = image;
}

static uint64_t flags_to_bits(const hb_flags_t* f) {
    return (f->cf ? 0x001ULL : 0) |
           (f->pf ? 0x004ULL : 0) |
           (f->af ? 0x010ULL : 0) |
           (f->zf ? 0x040ULL : 0) |
           (f->sf ? 0x080ULL : 0) |
           (f->of ? 0x800ULL : 0);
}

static uint64_t flag_mask_to_bits(uint32_t mask) {
    uint64_t bits = 0;
    if (mask & HB_FLAG_BIT_CF) bits |= 0x001ULL;
    if (mask & HB_FLAG_BIT_PF) bits |= 0x004ULL;
    if (mask & HB_FLAG_BIT_AF) bits |= 0x010ULL;
    if (mask & HB_FLAG_BIT_ZF) bits |= 0x040ULL;
    if (mask & HB_FLAG_BIT_SF) bits |= 0x080ULL;
    if (mask & HB_FLAG_BIT_OF) bits |= 0x800ULL;
    return bits;
}

static void fill_random(uint64_t* rng, uint8_t* out, size_t len) {
    size_t off = 0;
    while (off < len) {
        uint64_t v = splitmix64_next(rng);
        size_t n = len - off < sizeof(v) ? len - off : sizeof(v);
        memcpy(out + off, &v, n);
        off += n;
    }
}

/* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ-2 — НАЧАЛЬНЫЕ ЗНАЧЕНИЯ ИЗ СТРОКИ КОРПУСА.
 *
 * ЗАЧЕМ (смета лейна ОРАКУЛ, §2.6 его отчёта). Значения регистров задаёт ЗЕРНО, поэтому
 * тот, кто пишет строку корпуса, их НЕ ЗНАЕТ и записать абсолютное ожидание не может.
 * Именно это мешало поглотить `kraya_otkazov`, у которого регистры-заполнители стоят в
 * известные значения (`0x11110000+i`).
 *
 * И это же ограничение искажает СЧЁТ. Дефект «CF через INC/DEC» (см. отчёт лейна) на
 * корпусе, где CF берётся из зерна, краснеет в 63,0 % случаев — не потому, что класс
 * такого размера, а потому, что при части зёрен УСТАРЕВШИЙ CF случайно совпадает с
 * верным. Число говорит о зерне, а не о дефекте.
 *
 * Поля именованные и разбираются вместе с `ожид-*`: `рег-rax=0x...`, `флаги=0x...`.
 * Накладываются В КОНЦЕ `init_context`, ПОСЛЕ всякой засевки (включая флаги), — иначе
 * их молча затёрло бы. Проверяется не рассуждением: заданное значение обязано появиться
 * в снимке `initial`, который печатается для каждого случая.
 *
 * Обе руки берут ОДИН И ТОТ ЖЕ набор: указатель глобальный и ставится на случай целиком. */
typedef struct {
    uint32_t zadano;      /* битовая маска регистров: бит i — регистр с номером i */
    uint64_t reg[16];
    int      flagi_est;
    uint64_t flagi;
} hb_diff_nachalo_t;

static const hb_diff_nachalo_t* g_diff_nachalo;
#include "hb_sse_oracle/runner_extension.h"

/* Имена в том же порядке, что `reg_name`/индексы снимка: rax rbx rcx rdx rsi rdi rsp rbp
 * r8..r15. Порядок НЕ архитектурный (в x86 он rax rcx rdx rbx), он наш, снимочный, и
 * менять его нельзя — по нему печатается `initial`. */
static const char* const hb_diff_reg_imena64[16] = {
    "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};
static const char* const hb_diff_reg_imena32[8] = {
    "eax","ebx","ecx","edx","esi","edi","esp","ebp"
};

static int hb_diff_reg_nomer(hb_arch_t arch, const char* imya, size_t n) {
    unsigned i;
    unsigned kolvo = (arch == HB_ARCH_X86) ? 8u : 16u;
    for (i = 0; i < kolvo; i++) {
        const char* e = (arch == HB_ARCH_X86) ? hb_diff_reg_imena32[i] : hb_diff_reg_imena64[i];
        if (strlen(e) == n && !strncmp(imya, e, n)) return (int)i;
    }
    return -1;
}

/* ★ Поля перечисляются ПОИМЁННО, а не приведением структуры к массиву. Приведение
 * работало бы (порядок полей совпадает со снимочным), но молча поехало бы при первой
 * же вставке поля в середину структуры — ровно тот класс, из-за которого в проекте
 * поля `hb_probe_t` дописывают в КОНЕЦ. */
static void hb_diff_nalozhit_nachalo(hb_context_t* ctx, const hb_diff_nachalo_t* nch) {
    unsigned i;
    if (!nch || (!nch->zadano && !nch->flagi_est)) return;
    if (ctx->mode == HB_MODE_32BIT) {
        uint32_t* p32[8] = {
            &ctx->regs.x86.eax, &ctx->regs.x86.ebx, &ctx->regs.x86.ecx, &ctx->regs.x86.edx,
            &ctx->regs.x86.esi, &ctx->regs.x86.edi, &ctx->regs.x86.esp, &ctx->regs.x86.ebp
        };
        for (i = 0; i < 8; i++)
            if (nch->zadano & (1u << i)) *p32[i] = (uint32_t)nch->reg[i];
    } else {
        uint64_t* p64[16] = {
            &ctx->regs.x64.rax, &ctx->regs.x64.rbx, &ctx->regs.x64.rcx, &ctx->regs.x64.rdx,
            &ctx->regs.x64.rsi, &ctx->regs.x64.rdi, &ctx->regs.x64.rsp, &ctx->regs.x64.rbp,
            &ctx->regs.x64.r8,  &ctx->regs.x64.r9,  &ctx->regs.x64.r10, &ctx->regs.x64.r11,
            &ctx->regs.x64.r12, &ctx->regs.x64.r13, &ctx->regs.x64.r14, &ctx->regs.x64.r15
        };
        for (i = 0; i < 16; i++)
            if (nch->zadano & (1u << i)) *p64[i] = nch->reg[i];
    }
    if (nch->flagi_est) set_flags_from_bits(ctx, nch->flagi);
}

static hb_result_t init_context(hb_context_t* ctx, uint64_t seed, const uint8_t* code, size_t code_len) {
    uint64_t rng = seed;
    uint8_t data[HB_DIFF_DATA_SIZE];
    uint8_t stack[HB_DIFF_STACK_SIZE];
    ctx->memory = hb_memory_create(0x200000);
    if (!ctx->memory) return HB_ERR_OUT_OF_MEMORY;

    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 761 — ПЛОСКОЕ ОТОБРАЖЕНИЕ ГОСТЯ В i386.
     *
     * Стенд заводил области через `hb_memory_map_private`, то есть хозяйский адрес выбирался
     * произвольно, а `ctx->guest32_base` оставался НУЛЁМ. Выпущенный код на i386 переводит
     * адрес как `guest32_base + (EA & 0xffffffff)` (`emit_x86_ea_to_host`), значит при нуле
     * он писал по ГОСТЕВОМУ адресу как по хозяйскому — и стенд падал по SIGSEGV.
     *
     * Цена была не косметическая: падал ВЕСЬ пакет, потому что случаи гонятся одним вызовом.
     * Замер: 1883 случая из 9188 (20.5 %) роняли прогон, и все — семья стека (`push`/`pop`),
     * та самая, что даёт 56.01 % нативного выпуска на i386. Разделение полное:
     * `MACRUNNER_HB_JIT_DIRECT_STACK=0` — код 0, `=1` и умолчание — код 139.
     *
     * Это дефект СТЕНДА, не движка: в живом прогоне 32-битная память гостя действительно
     * лежит плоско от `guest32_base`. Заводим здесь ту же модель — и заодно стенд начинает
     * проверять выпущенный стековый путь, которого до сих пор не касался вовсе. */
    hb_result_t r;
    const bool flat32 = (ctx->mode == HB_MODE_32BIT);
    g_diff_identity_active = (!flat32 && hb_diff_identity_gate()) ? 1 : 0;
    if (flat32) {
        r = hb_memory_guest32_reserve(ctx->memory);
        if (r != HB_OK) return r;
        ctx->guest32_base = (uint64_t)(uintptr_t)hb_memory_guest32_base(ctx->memory);
        r = hb_memory_guest32_map(ctx->memory, (uint32_t)hb_diff_code_base(1), 0x1000,
                                  HB_PERM_READ | HB_PERM_WRITE);
    } else if (g_diff_identity_active) {
        r = hb_diff_map_identity(ctx->memory, hb_diff_code_base(0), 0x1000,
                                 HB_PERM_READ | HB_PERM_WRITE);
    } else {
        r = hb_memory_map_private(ctx->memory, hb_diff_code_base(0), 0x1000,
                                  HB_PERM_READ | HB_PERM_WRITE);
    }
    if (r != HB_OK) return r;
    r = hb_memory_write(ctx->memory, hb_diff_code_base(flat32), code, code_len);
    if (r != HB_OK) return r;
    r = hb_memory_protect(ctx->memory, hb_diff_code_base(flat32), 0x1000, HB_PERM_READ | HB_PERM_EXEC);
    if (r != HB_OK) return r;
    r = flat32 ? hb_memory_guest32_map(ctx->memory, (uint32_t)HB_DIFF_DATA_BASE,
                                       HB_DIFF_DATA_MAP_SIZE, HB_PERM_READ | HB_PERM_WRITE)
        : g_diff_identity_active
               ? hb_diff_map_identity(ctx->memory, HB_DIFF_DATA_BASE, HB_DIFF_DATA_MAP_SIZE,
                                      HB_PERM_READ | HB_PERM_WRITE)
               : hb_memory_map_private(ctx->memory, HB_DIFF_DATA_BASE, HB_DIFF_DATA_MAP_SIZE,
                                       HB_PERM_READ | HB_PERM_WRITE);
    if (r != HB_OK) return r;
    r = flat32 ? hb_memory_guest32_map(ctx->memory, (uint32_t)HB_DIFF_STACK_BASE,
                                       HB_DIFF_STACK_SIZE, HB_PERM_READ | HB_PERM_WRITE)
        : g_diff_identity_active
               ? hb_diff_map_identity(ctx->memory, HB_DIFF_STACK_BASE, HB_DIFF_STACK_SIZE,
                                      HB_PERM_READ | HB_PERM_WRITE)
               : hb_memory_map_private(ctx->memory, HB_DIFF_STACK_BASE, HB_DIFF_STACK_SIZE,
                                       HB_PERM_READ | HB_PERM_WRITE);
    if (r != HB_OK) return r;
    fill_random(&rng, data, sizeof(data));
    fill_random(&rng, stack, sizeof(stack));
    /* Optional override: HB_DIFF_DATA_HEX=<seed>:<hex> lets a fuzz harness
     * pre-populate the data region deterministically (so both engines
     * see the same bytes for a given seed). The seed is encoded so the
     * fuzzer can verify the right env var was used. */
    const char* data_hex_env = getenv("HB_DIFF_DATA_HEX");
    if (data_hex_env) {
        const char* colon = strchr(data_hex_env, ':');
        if (colon) {
            uint64_t env_seed = strtoull(data_hex_env, NULL, 0);
            if (env_seed == seed) {
                const char* hex = colon + 1;
                size_t hex_len = strlen(hex);
                size_t want = sizeof(data) * 2;
                if (hex_len == want) {
                    size_t parsed = 0;
                    if (parse_hex_bytes(hex, data, sizeof(data), &parsed) && parsed == sizeof(data)) {
                        /* data replaced with fuzzer-provided bytes */
                    }
                }
            }
        }
    }
    r = hb_memory_write(ctx->memory, HB_DIFF_DATA_BASE, data, sizeof(data));
    if (r != HB_OK) return r;
    r = hb_memory_write(ctx->memory, HB_DIFF_STACK_BASE, stack, sizeof(stack));
    if (r != HB_OK) return r;

    if (ctx->mode == HB_MODE_32BIT) {
        ctx->regs.x86.eax = (uint32_t)(HB_DIFF_DATA_BASE + 0x1000);
        /* Итерация 551: базовый регистр указывает В ОБЛАСТЬ — см. unicorn_adapter.py,
         * там же обоснование. Правка ОБЯЗАНА быть в обеих реализациях (сверка 550). */
        ctx->regs.x86.ebx = (uint32_t)(HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU));
        ctx->regs.x86.ecx = (uint32_t)((splitmix64_next(&rng) & 0x0fU) + 1U);
        ctx->regs.x86.edx = 0;
        ctx->regs.x86.esi = (uint32_t)(HB_DIFF_DATA_BASE + 0x0800);
        ctx->regs.x86.edi = (uint32_t)(HB_DIFF_DATA_BASE + 0x1000);
        ctx->regs.x86.esp = (uint32_t)(HB_DIFF_STACK_BASE + 0x1000);
        ctx->regs.x86.ebp = (uint32_t)(HB_DIFF_STACK_BASE + 0x1100);
        ctx->regs.x86.eip = (uint32_t)hb_diff_code_base(1);
        /* Reset x87 state to FNINIT semantics so the tag word starts as
         * 0xFFFF (all empty), control word 0x037F, status word 0, TOP=0.
         * Without this the C-initialized fields are 0 → tag_word=0 → all
         * "valid", which diverges from the per-architecture FNINIT spec
         * the x87 interpreter (and Unicorn) expects. */
        hb_x87_fninit(&ctx->regs.x86.x87);
    } else {
        ctx->regs.x64.rax = HB_DIFF_DATA_BASE + 0x1000;
        ctx->regs.x64.rbx = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 551 */
        ctx->regs.x64.rcx = (splitmix64_next(&rng) & 0x3fU) + 1U;
        ctx->regs.x64.rdx = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 551 */
        ctx->regs.x64.rsi = HB_DIFF_DATA_BASE + 0x0400;
        ctx->regs.x64.rdi = HB_DIFF_DATA_BASE + 0x1000;
        ctx->regs.x64.rsp = HB_DIFF_STACK_BASE + 0x1000;
        ctx->regs.x64.rbp = HB_DIFF_STACK_BASE + 0x1100;
        ctx->regs.x64.r8 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.r9 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.r10 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.r11 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.r12 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.r13 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.r14 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.r15 = HB_DIFF_DATA_BASE + (splitmix64_next(&rng) & 0xFFFU);   /* итер. 552 */
        ctx->regs.x64.rip = hb_diff_code_base(0);
        /* ★ СЕЛЕКТОРЫ СЕГМЕНТОВ ЗАВОДЯТСЯ ЯВНО — ИНАЧЕ ИХ НЕТ НИ У КОГО.
         * Поля `ctx->seg_*` существуют давно и читаются `MOV r, Sreg`, но
         * стенд оставлял их нулями, и всякая такая форма отвечала нулём.
         * Значения — плоская раскладка длинного режима: код 0x08, данные 0x10;
         * они же печатаются в `initial`, и оракул берёт их ОТТУДА, а не из
         * своих констант, — иначе сравнение недействительно в обе стороны. */
        ctx->seg_cs = 0x08;
        ctx->seg_ds = ctx->seg_es = ctx->seg_ss = 0x10;
        ctx->seg_fs = ctx->seg_gs = 0x10;
    }
    ctx->pc = hb_diff_code_base(ctx->mode == HB_MODE_32BIT);
    set_flags_from_bits(ctx, splitmix64_next(&rng));
    for (unsigned i = 0; i < 16; i++) {
        if (ctx->mode == HB_MODE_32BIT) {
            uint8_t tmp[16];
            fill_random(&rng, tmp, sizeof(tmp));
            if (i < 8) memcpy(ctx->regs.x86.xmm[i], tmp, sizeof(tmp));
        } else {
            fill_random(&rng, (uint8_t*)ctx->regs.x64.xmm[i], 16);
            fill_random(&rng, (uint8_t*)ctx->xmm_ext[i], 16);
            fill_random(&rng, (uint8_t*)ctx->ymm_hi_ext[i], 16);
            fill_random(&rng, (uint8_t*)ctx->zmm_hi_ext[i], 32);
        }
        fill_random(&rng, (uint8_t*)ctx->ymm_hi[i], 16);
        fill_random(&rng, (uint8_t*)ctx->zmm_hi[i], 32);
    }
    for (unsigned i = 0; i < 8; i++) ctx->k[i] = splitmix64_next(&rng);
    /* ★ НАЧАЛЬНЫЕ ЗНАЧЕНИЯ ИЗ СТРОКИ КОРПУСА — ПОСЛЕДНИМ ДЕЙСТВИЕМ.
     * Выше по функции их затёрло бы засевкой регистров и флагов; ниже нет ничего. */
    hb_diff_nalozhit_nachalo(ctx, g_diff_nachalo);
    return hb_sse_apply(ctx);
}

static hb_result_t lift_code(hb_arch_t arch, const uint8_t* code, size_t code_len, hb_ir_func_t** out_func) {
    hb_decoder_t* dec = hb_decoder_create(arch, code, code_len, hb_diff_code_base(arch == HB_ARCH_X86));
    if (!dec) return HB_ERR_OUT_OF_MEMORY;
    hb_result_t r = arch == HB_ARCH_X86 ? hb_lift_func_x86(dec, out_func) : hb_lift_func_x64(dec, out_func);
    hb_decoder_destroy(dec);
    return r;
}

static void capture_snapshot(hb_context_t* ctx, hb_diff_snapshot_t* s,
                              hb_result_t api_result, hb_exec_result_t* exec) {
    memset(s, 0, sizeof(*s));
    s->arch = ctx->arch;
    s->sse_mxcsr = ctx->mxcsr;
    { hb_sse_host_state_t h = hb_sse_host_save();
      s->sse_host_control = h.control; s->sse_host_status = h.status; }
    s->lazy_pending = ctx->lazy_flags.pending;
    s->lazy_kind = (uint8_t)ctx->lazy_flags.kind;
    s->lazy_width = ctx->lazy_flags.width;
    s->lazy_lhs = ctx->lazy_flags.lhs;
    s->lazy_rhs = ctx->lazy_flags.rhs;
    s->lazy_result = ctx->lazy_flags.result;
    s->lazy_count = ctx->lazy_flags.count;
    s->flag_mask = ctx->lazy_flags.pending ? ctx->lazy_flags.valid_mask : HB_FLAG_BIT_ALL;
    s->flag_status = hb_lazy_flags_materialize(ctx, s->flag_mask);
    if (ctx->mode == HB_MODE_32BIT) {
        s->gpr[0] = ctx->regs.x86.eax; s->gpr[1] = ctx->regs.x86.ebx;
        s->gpr[2] = ctx->regs.x86.ecx; s->gpr[3] = ctx->regs.x86.edx;
        s->gpr[4] = ctx->regs.x86.esi; s->gpr[5] = ctx->regs.x86.edi;
        s->gpr[6] = ctx->regs.x86.esp; s->gpr[7] = ctx->regs.x86.ebp;
        s->eip = (uint32_t)ctx->pc;
        s->rflags = ctx->regs.x86.eflags;
        for (unsigned i = 0; i < 8; i++) memcpy(s->xmm[i], ctx->regs.x86.xmm[i], 16);
        s->x87_cw = ctx->regs.x86.x87.control_word;
        s->x87_sw = ctx->regs.x86.x87.status_word;
        s->x87_tag = ctx->regs.x86.x87.tag_word;
    } else {
        s->gpr[0] = ctx->regs.x64.rax; s->gpr[1] = ctx->regs.x64.rbx;
        s->gpr[2] = ctx->regs.x64.rcx; s->gpr[3] = ctx->regs.x64.rdx;
        s->gpr[4] = ctx->regs.x64.rsi; s->gpr[5] = ctx->regs.x64.rdi;
        s->gpr[6] = ctx->regs.x64.rsp; s->gpr[7] = ctx->regs.x64.rbp;
        s->gpr[8] = ctx->regs.x64.r8;  s->gpr[9] = ctx->regs.x64.r9;
        s->gpr[10] = ctx->regs.x64.r10; s->gpr[11] = ctx->regs.x64.r11;
        s->gpr[12] = ctx->regs.x64.r12; s->gpr[13] = ctx->regs.x64.r13;
        s->gpr[14] = ctx->regs.x64.r14; s->gpr[15] = ctx->regs.x64.r15;
        s->rflags = ctx->regs.x64.rflags;
        for (unsigned i = 0; i < 16; i++) memcpy(s->xmm[i], ctx->regs.x64.xmm[i], 16);
        for (unsigned i = 0; i < 16; i++) memcpy(s->xmm_ext[i], ctx->xmm_ext[i], 16);
        for (unsigned i = 0; i < 16; i++) memcpy(s->ymm_hi_ext[i], ctx->ymm_hi_ext[i], 16);
        for (unsigned i = 0; i < 16; i++) memcpy(s->zmm_hi_ext[i], ctx->zmm_hi_ext[i], 32);
    }
    /* ★ СЛОВА СОСТОЯНИЯ x87 БРАЛИСЬ ТОЛЬКО В 32-БИТНОЙ ВЕТВИ.
     * В длинном режиме стек x87 лежит в ДРУГОМ поле (`ctx->x87_64`), и снимок
     * отдавал нули, а оракул зеркалит именно снимок — значит сравнение x87 в
     * 64 битах было недействительно в обе стороны: движок держал cw=0x037f, а
     * оракулу подавался cw=0. Берём через тот же доступ, что и исполнитель. */
    {
        const hb_x87_state_t* x87 = hb_context_x87_const(ctx);
        s->x87_cw = x87->control_word;
        s->x87_sw = x87->status_word;
        s->x87_tag = x87->tag_word;
    }
    s->rip = ctx->pc;
    s->seg[0] = ctx->seg_es; s->seg[1] = ctx->seg_cs; s->seg[2] = ctx->seg_ss;
    s->seg[3] = ctx->seg_ds; s->seg[4] = ctx->seg_fs; s->seg[5] = ctx->seg_gs;
    s->flags = ctx->flags;
    for (unsigned i = 0; i < 16; i++) memcpy(s->ymm_hi[i], ctx->ymm_hi[i], 16);
    for (unsigned i = 0; i < 16; i++) memcpy(s->zmm_hi[i], ctx->zmm_hi[i], 32);
    for (unsigned i = 0; i < 8; i++) s->k[i] = ctx->k[i];
    if (ctx->memory) {
        (void)hb_memory_read(ctx->memory, HB_DIFF_DATA_BASE, s->data, sizeof(s->data));
        (void)hb_memory_read(ctx->memory, HB_DIFF_STACK_BASE, s->stack, sizeof(s->stack));
    }
    s->api_result = api_result;
    s->exec_result = exec ? exec->result : api_result;
    s->fault_kind = ctx->last_fault_kind;
    s->fault_addr = ctx->last_fault_addr;
    s->fault_pc = ctx->last_fault_pc;
    s->fault_addr_valid = ctx->last_fault_addr_valid;
}

/* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 761 — ОГРАЖДЕНИЕ ОТ ХОЗЯЙСКОГО ОТКАЗА.
 *
 * Выпущенный код на i386 читает по плоскому адресу `guest32_base + EA` без проверки прав —
 * это осознанно, в живом прогоне отказ ловит обработчик сигнала движка и превращает его в
 * гостевое исключение. У стенда такого обработчика не было, поэтому случай вроде
 * `call [0x4081e8]` (адрес принадлежит образу той программы, откуда команда извлечена, и в
 * стенде не заведён) убивал ВЕСЬ пакет: случаи гонятся одним вызовом, и с ним падали тысячи
 * невиновных. Замер: 261 случай из 9188 после починки плоского отображения.
 *
 * Здесь стенд получает свой минимальный аналог: отказ ловится, случай помечается
 * `EXEC_FAULT` и прогон продолжается. Это НЕ маскировка дефекта — код отказа виден в разрезе
 * и попадает в матрицу, как любой другой отказ. */
static sigjmp_buf hb_diff_fault_jmp;
static volatile sig_atomic_t hb_diff_fault_armed;
static volatile sig_atomic_t hb_diff_host_sig;
static volatile sig_atomic_t hb_diff_host_code;
static volatile uint64_t hb_diff_host_addr;
/* Сколько раз отказ забрала ДВЕРЬ ДВИЖКА и сколько — ограждение стенда. Разница между
 * этими двумя числами и есть ответ на вопрос «есть ли у нас вид отказа на прямом пути». */
static unsigned long hb_diff_door_taken, hb_diff_guard_taken;

/* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ — ОТКАЗ ВЫПУЩЕННОГО КОДА ОТДАЁТСЯ ДВИЖКУ.
 *
 * НАЙДЕНО ЧТЕНИЕМ И ПОДТВЕРЖДЕНО ЗАМЕРОМ. У движка есть публичная дверь
 * `hb_jit_runtime_handle_signal_fault` (`include/hb_runtime.h:291`): она принимает отказ,
 * случившийся в выпущенном блоке или в плите выпуска, и превращает его в аккуратный
 * `HB_ERR_MEMORY_FAULT` с заполненными `last_fault_kind/addr/pc`. В бою её зовёт
 * `segv_handler` wine. В движковом стенде её зовёт `safe_copy_signal_handler`
 * (`hb_memory.c:634`) — но тот обработчик СТАВИТСЯ ЛЕНИВО и ТОЛЬКО с пути `guest32`
 * (`hb_memory.c:4131`, `:4525`), то есть на x64 не ставится НИКОГДА.
 *
 * Итог до правки: любой отказ прямого пути x64 приземлялся в это самое ограждение,
 * становился `HB_ERR_EXEC_FAULT` без вида, без адреса и без pc — а интерпретатор на том
 * же случае отдавал `HB_ERR_MEMORY_FAULT` с полными полями. Сравнивать было нечего, и
 * ровно поэтому лейну КРАЯ-АДРЕСОВ пришлось строить отдельный прибор.
 *
 * Здесь ограждение сперва ПРЕДЛАГАЕТ отказ двери (тем же порядком pc, потом lr, что и в
 * wine), и уходит в longjmp только если дверь отказалась. Дверь по построению не может
 * забрать чужой отказ: она отклоняет всё, у чего pc вне блока и вне плиты. */
static void hb_diff_fault_handler(int sig, siginfo_t* info, void* uctx) {
    hb_diff_host_sig = sig;
    hb_diff_host_code = info ? info->si_code : 0;
    hb_diff_host_addr = (uint64_t)(uintptr_t)(info ? info->si_addr : NULL);
#if defined(__APPLE__) && defined(__aarch64__)
    {
        static int door_off = -1;
        if (door_off < 0) {
            const char* e = getenv("HB_DIFF_NO_ENGINE_DOOR");
            door_off = (e && *e && *e != '0') ? 1 : 0;
        }
        if (!door_off && uctx) {
            const ucontext_t* uc = (const ucontext_t*)uctx;
            if (uc->uc_mcontext) {
                uint64_t jpc = (uint64_t)uc->uc_mcontext->__ss.__pc;
                uint64_t jlr = (uint64_t)uc->uc_mcontext->__ss.__lr;
                uint64_t jaddr = hb_diff_host_addr;
                /* ★ СЧЁТ ВЕДЁТСЯ ДО ВЫЗОВА, А НЕ ПОСЛЕ. Первая редакция ставила `++` в
                 * ветке успеха — и он не исполнялся НИ РАЗУ: дверь, забрав отказ, уходит
                 * из обработчика САМА (`jit_signal_fault_claim` восстанавливает контекст),
                 * и до строки за вызовом управление не возвращается. Прибор показывал
                 * `дверь=0` при 295 забранных отказах за прогон. Замечено ровно потому,
                 * что число двери противоречило исчезновению пар `(-8,-9)`. */
                hb_diff_door_taken++;
                if (hb_jit_runtime_handle_signal_fault(jpc, jaddr, sig, uctx) ||
                    hb_jit_runtime_handle_signal_fault(jlr, jaddr, sig, uctx))
                    return;
                hb_diff_door_taken--;   /* дверь отказалась — отказ не её */
            }
        }
    }
#endif
    if (hb_diff_fault_armed) {
        hb_diff_fault_armed = 0;
        hb_diff_guard_taken++;
        siglongjmp(hb_diff_fault_jmp, sig);
    }
    _exit(139);
}

static void hb_diff_install_fault_guard(void) {
    static int done = 0;
    struct sigaction sa;
    if (done) return;
    done = 1;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = hb_diff_fault_handler;
    sigemptyset(&sa.sa_mask);
    /* SA_NODEFER: иначе второй отказ в том же прогоне уже не поймается. */
    sa.sa_flags = SA_NODEFER | SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

static hb_result_t run_backend_sse_inner(hb_arch_t arch, const uint8_t* code, size_t code_len, uint64_t seed,
                               hb_backend_t backend, hb_diff_snapshot_t* initial,
                               hb_diff_snapshot_t* final) {
    hb_ir_func_t* func = NULL;
    hb_result_t r = lift_code(arch, code, code_len, &func);
    /* ★ СНИМОК ЗАПОЛНЯЕТСЯ ВСЕГДА, даже когда исполнения не было.
     *
     * Прежде при отказе подъёма функция возвращалась НЕ ТРОНУВ `final`, и наверху лежал
     * мусор со стека. Это не замечалось только потому, что `ok` короткозамыкался на
     * `ri == HB_OK` и до сравнения не доходил. Как только отказ становится частью
     * сравниваемого состояния, мусор превратился бы в случайные расхождения — то есть
     * ровно в тот недетерминизм, который этот лейн и разбирает. */
    memset(final, 0, sizeof(*final));
    final->arch = arch;
    if (r != HB_OK) {
        final->api_result = r;
        final->exec_result = r;
        return r;
    }
    const char* dump_ir = getenv("HB_DIFF_DUMP_IR");
    if (dump_ir && strcmp(dump_ir, "1") == 0) {
        char* s = hb_ir_func_to_string(func);
        if (s) {
            fputs(s, stderr);
            free(s);
        }
        if (func->cfg && func->cfg->entry) {
            hb_ir_block_t* blk = func->cfg->entry;
            for (size_t i = 0; i < blk->instr_count; i++) {
                const hb_ir_instr_t* ins = &blk->instrs[i];
                fprintf(stderr,
                        "  instr %zu op=%u dst(type=%u reg=%u size=%u) src1(type=%u reg=%u size=%u) src2(type=%u reg=%u imm=%lld size=%u)\n",
                        i, (unsigned)ins->op,
                        (unsigned)ins->dst.type, (unsigned)ins->dst.reg, (unsigned)ins->dst.size,
                        (unsigned)ins->src1.type, (unsigned)ins->src1.reg, (unsigned)ins->src1.size,
                        (unsigned)ins->src2.type, (unsigned)ins->src2.reg,
                        (long long)ins->src2.imm, (unsigned)ins->src2.size);
            }
        }
    }
    hb_context_t* ctx = hb_context_create(arch, backend);
    if (!ctx) {
        hb_ir_func_destroy(func);
        return HB_ERR_OUT_OF_MEMORY;
    }
    r = init_context(ctx, seed, code, code_len);
    if (r == HB_OK && initial) capture_snapshot(ctx, initial, HB_OK, NULL);
    hb_exec_result_t exec;
    memset(&exec, 0, sizeof(exec));
    hb_result_t api;
    hb_diff_install_fault_guard();
    hb_diff_host_sig = 0;
    hb_diff_host_code = 0;
    hb_diff_host_addr = 0;
    if (r != HB_OK) {
        api = r;
    } else if (sigsetjmp(hb_diff_fault_jmp, 1) == 0) {
        hb_diff_fault_armed = 1;
        api = hb_runtime_run(ctx, func, backend, &exec);
        hb_diff_fault_armed = 0;
    } else {
        /* Хозяйский отказ внутри исполнения случая — см. ограждение выше. */
        memset(&exec, 0, sizeof(exec));
        exec.result = HB_ERR_EXEC_FAULT;
        api = HB_ERR_EXEC_FAULT;
    }
    /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1448 — ВОСПРОИЗВЕДЕНИЕ ЖИВОГО ПУТИ.
     *
     * Гейт `HB_DIFF_LIVE_FALLBACK=1`, умолчание ВЫКЛ — стенд без него работает как прежде.
     *
     * Зачем. Живой путь wine (`macrunner_hb.c:42237-42268`) при отказе помощника во время
     * исполнения НЕ падает, а перезапускает интерпретатором:
     *     if (out.result == UNSUPPORTED_OPCODE|UNSUPPORTED_FEATURE|INTERNAL)
     *         ret = hb_runtime_run(ctx, func, HB_BACKEND_INTERP, &out);
     * причём на ТОМ ЖЕ `ctx` и с ТОЙ ЖЕ `func`, а `hb_runtime_run(INTERP)` стартует с
     * `func->cfg->entry` — с входа функции. Стенд этого шага не делал, поэтому вопрос
     * «повторяются ли уже исполненные команды» оставался рассуждением.
     *
     * Здесь тот же шаг воспроизводится ДОСЛОВНО, чтобы ответ стал наблюдением. */
    if (backend == HB_BACKEND_JIT) {
        const char* lf = getenv("HB_DIFF_LIVE_FALLBACK");
        if (lf && lf[0] == '1') {
            int unsup = (api == HB_ERR_UNSUPPORTED_FEATURE || api == HB_ERR_UNSUPPORTED_OPCODE ||
                         api == HB_ERR_INTERNAL ||
                         exec.result == HB_ERR_UNSUPPORTED_FEATURE ||
                         exec.result == HB_ERR_UNSUPPORTED_OPCODE ||
                         exec.result == HB_ERR_INTERNAL);
            if (unsup) {
                fprintf(stderr, "macrunner-lestnica-livefb: отказ api=%d exec=%d — повторяю интерпретатором\n",
                        (int)api, (int)exec.result);
                memset(&exec, 0, sizeof(exec));
                api = hb_runtime_run(ctx, func, HB_BACKEND_INTERP, &exec);
            }
        }
    }
    capture_snapshot(ctx, final, api, &exec);
    final->host_sig = (int)hb_diff_host_sig;
    final->host_code = (int)hb_diff_host_code;
    final->host_addr = hb_diff_host_addr;
    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    return api;
}

static hb_result_t run_backend(hb_arch_t arch, const uint8_t* code, size_t code_len, uint64_t seed,
                               hb_backend_t backend, hb_diff_snapshot_t* initial,
                               hb_diff_snapshot_t* final) {
    hb_sse_host_state_t old = hb_sse_host_save();
    hb_result_t r = run_backend_sse_inner(arch, code, code_len, seed, backend, initial, final);
    hb_sse_host_restore(old);
    return r;
}
static const char* reg_name(hb_arch_t arch, unsigned i) {
    static const char* names64[16] = {
        "rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp",
        "r8","r9","r10","r11","r12","r13","r14","r15"
    };
    static const char* names32[8] = {
        "eax","ebx","ecx","edx","esi","edi","esp","ebp"
    };
    return arch == HB_ARCH_X86 ? names32[i] : names64[i];
}

static unsigned reg_count(hb_arch_t arch) {
    return arch == HB_ARCH_X86 ? 8u : 16u;
}

/* ★★★ MacRunner 2026-09-06, лейн ФЛАГИ — СЛИЧЕНИЕ ПОЗИЦИИ (rip/eip).
 *
 * НАЙДЕНО ЗАМЕРОМ, а не чтением: `MACRUNNER_HB_JCC_FUSE_FULL=1` роняет Hollow Knight на
 * +20,6 с (c0000005 -> c0000144), а сличение с интерпретатором на всех корпусах при том
 * же гейте — ЗЕЛЁНОЕ. Причина: сращивание `cmp; Jcc` меняет ровно ОДНО наблюдаемое —
 * КУДА ушёл переход, — а `snapshots_equal` поле `rip`/`eip` СНИМАЛО, но не СРАВНИВАЛО.
 *
 * То есть оракул по построению не мог увидеть неверную ветвь. Это тот же класс, что в
 * памяти проекта записан как «зелёный тест не есть отсутствие дыры»: проверка, неспособная
 * покраснеть на проверяемом дефекте, выдаёт разрешение, а не результат.
 *
 * Отрицательный контроль правки: с ней и с гейтом ВКЛ корпус обязан покраснеть, с гейтом
 * ВЫКЛ — остаться зелёным. Оба прогона в отчёте ФЛАГИ-ПЕРЕПИСЬ-И-ЗАМЕР-06.09.2026.md.
 *
 * Снять сравнение можно HB_DIFF_NO_PC=1 — на случай, если чужому лейну оно мешает; но по
 * умолчанию оно ВКЛЮЧЕНО: выключенная по умолчанию проверка не проверяет ничего. */
static int hb_diff_cmp_pc(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* e = getenv("HB_DIFF_NO_PC");
        cached = (e && *e && *e != '0') ? 0 : 1;
    }
    return cached;
}

/* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ — ТОЧНОСТЬ pc ОТКАЗА, ОТДЕЛЬНЫМ ВЫКЛЮЧАТЕЛЕМ.
 *
 * `fault_pc` — ExceptionAddress гостя. Лейн КРАЯ-АДРЕСОВ доказал прибором, что на
 * НЕВЫРОВНЕННОМ доступе он сегодня теряется: команда выпускается нативно, а исполняется
 * запасной ветвью сторожа выравнивания, то есть помощником, и состояние откатывается ко
 * входу блока. Это ЗНАЕМЫЙ дефект (`reports/ДОЛГ.md`, п.9), а не находка оракула.
 *
 * Поэтому у сравнения `fault_pc` свой выключатель — но умолчание ВКЛЮЧЕНО: выключенная по
 * умолчанию проверка не проверяет ничего. `HB_DIFF_NO_FAULT_PC=1` даёт чужому лейну
 * возможность отделить «pc не тот» от прочих расхождений, а не отменить проверку.
 *
 * ★ ГРАНИЦА, названная вслух: `fault_pc` сравнивается ТОЛЬКО когда ОБЕ руки доложили
 * отказ (`exec_result != HB_OK`). У руки без отказа поле не заполнено, и сравнивать его
 * с заполненным значило бы краснеть на самом факте расхождения кодов возврата — а он
 * уже сравнён выше и назван своим именем. */
static int hb_diff_cmp_fault_pc(void) {
    static int cached = -1;
    if (cached < 0) {
        const char* e = getenv("HB_DIFF_NO_FAULT_PC");
        cached = (e && *e && *e != '0') ? 0 : 1;
    }
    return cached;
}

static bool snapshots_equal(const hb_diff_snapshot_t* a, const hb_diff_snapshot_t* b,
                            char* field, size_t field_size) {
    /* ★★★ ОТКАЗ — ЧАСТЬ СОСТОЯНИЯ, И СРАВНИВАЕТСЯ ПЕРВЫМ.
     *
     * Первым, а не в конце, по одной причине: когда случай отказал, ИМЕННО описатель
     * отказа — самая говорящая метка расхождения. Прежде первым стоял `rip`, и потеря
     * точности pc пряталась бы за меткой `rip`, потому что у отказавшего блока `ctx->pc`
     * тоже откатывается ко входу. Ничего не убрано: `rip` сравнивается сразу следом.
     *
     * `fault_kind`, `fault_addr` и `fault_addr_valid` сравниваются ВСЕГДА: у руки без
     * отказа они нулевые, и расхождение «одна отказала, другая нет» уже поймано кодами
     * возврата выше — но пусть будет поймано и здесь, если коды почему-то сойдутся. */
    if (a->fault_kind != b->fault_kind) {
        snprintf(field, field_size, "fault_kind:%u:%u", (unsigned)a->fault_kind, (unsigned)b->fault_kind);
        return false;
    }
    if (a->fault_addr_valid != b->fault_addr_valid) {
        snprintf(field, field_size, "fault_addr_valid:%u:%u",
                 (unsigned)a->fault_addr_valid, (unsigned)b->fault_addr_valid);
        return false;
    }
    if (a->fault_addr != b->fault_addr) {
        snprintf(field, field_size, "fault_addr:0x%" PRIx64 ":0x%" PRIx64, a->fault_addr, b->fault_addr);
        return false;
    }
    if (hb_diff_cmp_fault_pc() && a->exec_result != HB_OK && b->exec_result != HB_OK &&
        a->fault_pc != b->fault_pc) {
        snprintf(field, field_size, "fault_pc:0x%" PRIx64 ":0x%" PRIx64, a->fault_pc, b->fault_pc);
        return false;
    }
    if (hb_diff_cmp_pc() && a->rip != b->rip) {
        snprintf(field, field_size, "rip:0x%" PRIx64 ":0x%" PRIx64, a->rip, b->rip);
        return false;
    }
    if (a->api_result != b->api_result) {
        snprintf(field, field_size, "api_result:%d:%d", a->api_result, b->api_result);
        return false;
    }
    if (a->exec_result != b->exec_result) {
        snprintf(field, field_size, "exec_result:%d:%d", a->exec_result, b->exec_result);
        return false;
    }
    if (a->flag_status != b->flag_status) {
        snprintf(field, field_size, "flag_status:%d:%d", a->flag_status, b->flag_status);
        return false;
    }
    for (unsigned i = 0; i < reg_count(a->arch); i++) {
        if (a->gpr[i] != b->gpr[i]) {
            snprintf(field, field_size, "reg:%s", reg_name(a->arch, i));
            return false;
        }
    }
    if (a->flag_mask != b->flag_mask) {
        snprintf(field, field_size, "flag_mask:0x%x:0x%x", a->flag_mask, b->flag_mask);
        return false;
    }
    uint64_t flag_bits_mask = flag_mask_to_bits(a->flag_mask);
    if (((flags_to_bits(&a->flags) ^ flags_to_bits(&b->flags)) & flag_bits_mask) != 0) {
        snprintf(field, field_size, "flags");
        return false;
    }
    for (unsigned i = 0; i < 16; i++) {
        if (memcmp(a->xmm[i], b->xmm[i], 16) != 0) {
            snprintf(field, field_size, "xmm%u", i);
            return false;
        }
        if (memcmp(a->ymm_hi[i], b->ymm_hi[i], 16) != 0) {
            snprintf(field, field_size, "ymm_hi%u", i);
            return false;
        }
        if (memcmp(a->zmm_hi[i], b->zmm_hi[i], 32) != 0) {
            snprintf(field, field_size, "zmm_hi%u", i);
            return false;
        }
        if (memcmp(a->xmm_ext[i], b->xmm_ext[i], 16) != 0) {
            snprintf(field, field_size, "xmm%u", i + 16);
            return false;
        }
        if (memcmp(a->ymm_hi_ext[i], b->ymm_hi_ext[i], 16) != 0) {
            snprintf(field, field_size, "ymm_hi%u", i + 16);
            return false;
        }
        if (memcmp(a->zmm_hi_ext[i], b->zmm_hi_ext[i], 32) != 0) {
            snprintf(field, field_size, "zmm_hi%u", i + 16);
            return false;
        }
    }
    for (unsigned i = 0; i < 8; i++) {
        if (a->k[i] != b->k[i]) {
            snprintf(field, field_size, "k%u", i);
            return false;
        }
    }
    for (size_t i = 0; i < sizeof(a->data); i++) {
        if (a->data[i] != b->data[i]) {
            snprintf(field, field_size, "data+0x%zx", i);
            return false;
        }
    }
    for (size_t i = 0; i < sizeof(a->stack); i++) {
        if (a->stack[i] != b->stack[i]) {
            snprintf(field, field_size, "stack+0x%zx", i);
            return false;
        }
    }
    return true;
}

static void print_regs_json(const hb_diff_snapshot_t* s) {
    putchar('{');
    for (unsigned i = 0; i < reg_count(s->arch); i++) {
        if (i) putchar(',');
        if (s->arch == HB_ARCH_X86) printf("\"%s\":\"0x%08" PRIx64 "\"", reg_name(s->arch, i), s->gpr[i] & 0xffffffffULL);
        else printf("\"%s\":\"0x%016" PRIx64 "\"", reg_name(s->arch, i), s->gpr[i]);
    }
    if (s->arch == HB_ARCH_X86) printf(",\"eip\":\"0x%08" PRIx32 "\"}", s->eip);
    else printf(",\"rip\":\"0x%016" PRIx64 "\"}", s->rip);
}

static void print_vec_array_json(const uint8_t v[16][16]) {
    putchar('[');
    for (unsigned i = 0; i < 16; i++) {
        if (i) putchar(',');
        putchar('"');
        print_hex_bytes(v[i], 16);
        putchar('"');
    }
    putchar(']');
}

static void print_zmm_hi_array_json(const uint8_t v[16][32]) {
    putchar('[');
    for (unsigned i = 0; i < 16; i++) {
        if (i) putchar(',');
        putchar('"');
        print_hex_bytes(v[i], 32);
        putchar('"');
    }
    putchar(']');
}

static void print_k_array_json(const uint64_t k[8]) {
    putchar('[');
    for (unsigned i = 0; i < 8; i++) {
        if (i) putchar(',');
        printf("\"0x%016" PRIx64 "\"", k[i]);
    }
    putchar(']');
}

static void print_flags_json(const hb_flags_t* f) {
    printf("{\"cf\":%u,\"pf\":%u,\"af\":%u,\"zf\":%u,\"sf\":%u,\"of\":%u}",
           f->cf ? 1 : 0, f->pf ? 1 : 0, f->af ? 1 : 0,
           f->zf ? 1 : 0, f->sf ? 1 : 0, f->of ? 1 : 0);
}

static void print_snapshot_json(const char* name, const hb_diff_snapshot_t* s) {
    printf("\"%s\":{\"api\":%d,\"result\":%d,\"fault_kind\":%u,\"fault_addr\":\"0x%016" PRIx64 "\","
           "\"fault_addr_valid\":%u,\"fault_pc\":\"0x%016" PRIx64 "\","
           "\"host_sig\":%d,\"host_code\":%d,\"host_addr\":\"0x%016" PRIx64 "\",\"regs\":",
           name, s->api_result, s->exec_result, (unsigned)s->fault_kind, s->fault_addr,
           (unsigned)s->fault_addr_valid, s->fault_pc,
           s->host_sig, s->host_code, s->host_addr);
    print_regs_json(s);
    printf(",\"rflags\":\"0x%016" PRIx64 "\"", s->rflags);
    printf(",\"flags\":");
    print_flags_json(&s->flags);
    printf(",\"flag_mask\":\"0x%02x\",\"flag_status\":%d", s->flag_mask, s->flag_status);
    printf(",\"lazy\":{\"pending\":%u,\"kind\":%u,\"width\":%u,"
           "\"lhs\":\"0x%016" PRIx64 "\",\"rhs\":\"0x%016" PRIx64 "\","
           "\"result\":\"0x%016" PRIx64 "\",\"count\":\"0x%016" PRIx64 "\"}",
           s->lazy_pending ? 1u : 0u, s->lazy_kind, s->lazy_width,
           s->lazy_lhs, s->lazy_rhs, s->lazy_result, s->lazy_count);
    /* РЕГИСТРЫ-МАСКИ. Снимок их брал (s->k[i] = ctx->k[i]) с самого начала,
     * а наружу НЕ ОТДАВАЛ — то есть проверить их было нечем. 04.09.2026,
     * когда класс регистров k завёлся, это стало нужно. */
    printf(",\"k\":[");
    for (unsigned _i = 0; _i < 8; _i++)
        printf("%s\"%016llx\"", _i ? "," : "", (unsigned long long)s->k[_i]);
    printf("]");
    printf(",\"xmm\":");
    print_vec_array_json(s->xmm);
    printf(",\"ymm_hi\":");
    print_vec_array_json(s->ymm_hi);
    printf(",\"zmm_hi\":");
    print_zmm_hi_array_json(s->zmm_hi);
    printf(",\"xmm_ext\":");
    print_vec_array_json(s->xmm_ext);
    printf(",\"ymm_hi_ext\":");
    print_vec_array_json(s->ymm_hi_ext);
    printf(",\"zmm_hi_ext\":");
    print_zmm_hi_array_json(s->zmm_hi_ext);
    printf(",\"k\":");
    print_k_array_json(s->k);
    printf(",\"data_hash\":\"0x%016" PRIx64 "\",\"stack_hash\":\"0x%016" PRIx64 "\"",
           fnv1a64(s->data, sizeof(s->data)), fnv1a64(s->stack, sizeof(s->stack)));
    /* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 514 — СОСТОЯНИЕ x87 И ОКНО ЗАПИСИ.
     *
     * Эталон отдаёт своё `fpu` (cw/sw), наша сторона отдавала `null`, и поэтому КАЖДОЕ
     * расхождение x87 выглядело одним непрозрачным `data_hash`. Из-за этого разбор `fstp`
     * в 513 пришлось вести восстановлением образа по хешу — метод сработал на `fnstenv`
     * и провалил контроль на `fstp`.
     *
     * Печатаем то, что в снимке УЖЕ есть: слова состояния и окно области данных по адресу,
     * куда пишут проверяемые случаи (`eax`/`rax` = DATA_BASE + 0x1000). 32 байта хватает на
     * 80-битное значение (10) и на образ окружения (28). */
    printf(",\"fpu\":{\"cw\":\"0x%04x\",\"sw\":\"0x%04x\",\"tw\":\"0x%04x\"}",
           s->x87_cw, s->x87_sw, s->x87_tag);
    printf(",\"seg\":{\"es\":%u,\"cs\":%u,\"ss\":%u,\"ds\":%u,\"fs\":%u,\"gs\":%u}",
           s->seg[0], s->seg[1], s->seg[2], s->seg[3], s->seg[4], s->seg[5]);
    printf(",\"mxcsr\":\"0x%04x\",\"host_fp_control\":\"0x%llx\",\"host_fp_status\":\"0x%llx\"",
           s->sse_mxcsr, (unsigned long long)s->sse_host_control, (unsigned long long)s->sse_host_status);
    printf(",\"data_at_1000\":\"");
    print_hex_bytes(s->data + 0x1000, 32);
    printf("\"");
    printf(",\"xmm0\":\"");
    print_hex_bytes(s->xmm[0], 16);
    printf("\",\"ymm0_hi\":\"");
    print_hex_bytes(s->ymm_hi[0], 16);
    printf("\",\"zmm0_hi\":\"");
    print_hex_bytes(s->zmm_hi[0], 32);
    printf("\"");
    if (s->arch == HB_ARCH_X86) {
        printf(",\"x87\":{\"cw\":\"0x%04x\",\"sw\":\"0x%04x\",\"tag\":\"0x%04x\"}",
               s->x87_cw, s->x87_sw, s->x87_tag);
    }
    const char* dump_memory = getenv("HB_DIFF_DUMP_MEMORY");
    if (dump_memory && strcmp(dump_memory, "1") == 0) {
        printf(",\"data\":\"");
        print_hex_bytes(s->data, sizeof(s->data));
        printf("\",\"stack\":\"");
        print_hex_bytes(s->stack, sizeof(s->stack));
        printf("\"");
    }
    printf("}");
}

/* ★★★ ОТРИЦАТЕЛЬНЫЕ КОНТРОЛИ СРАВНЕНИЯ ОТКАЗА (умолчание 0, имена с `TEST_`).
 *
 * Порча вносится в снимок РУКИ JIT после исполнения — то есть проверяется СРАВНИВАТЕЛЬ,
 * а не источник поля. Источник доказывается иначе (корпус с заведомо разными видами
 * отказа плюс движковый гейт `MACRUNNER_HB_TEST_RIPMAP_SKEW`), см. отчёт лейна.
 *
 * ★ Каждая порча СЧИТАЕТ, сколько случаев она реально тронула. Урок КРАЯ-АДРЕСОВ: порча,
 * не изменившая ничего, — не доказательство слепоты, а пустой прогон. Ноль тронутых
 * случаев обязан быть виден, а не выглядеть как «поймано ноль расхождений». */
static unsigned long g_porcha_tronuto;

static void hb_diff_porcha(hb_diff_snapshot_t* jit) {
    static int kind = -1, addr = -1, pc = -1, clean = -1, valid = -1;
    if (kind < 0) {
        const char* e;
        e = getenv("HB_DIFF_TEST_FAULT_KIND_SKEW");  kind  = (e && *e && *e != '0') ? 1 : 0;
        e = getenv("HB_DIFF_TEST_FAULT_ADDR_SKEW");  addr  = (e && *e && *e != '0') ? 1 : 0;
        e = getenv("HB_DIFF_TEST_FAULT_PC_SKEW");    pc    = (e && *e && *e != '0') ? 1 : 0;
        e = getenv("HB_DIFF_TEST_FAULT_VALID_SKEW"); valid = (e && *e && *e != '0') ? 1 : 0;
        e = getenv("HB_DIFF_TEST_FAULT_ON_CLEAN");   clean = (e && *e && *e != '0') ? 1 : 0;
    }
    /* ★★★ ПЯТАЯ ПОРЧА — ОБРАТНОГО НАПРАВЛЕНИЯ, и она здесь не для полноты.
     *
     * Четыре порчи выше бьют по случаям, где отказ ЕСТЬ. Контроль «случай БЕЗ отказа обязан
     * остаться зелёным» они не проверяют: на чистом корпусе `тронуто=0`, то есть контроль
     * НЕ ПРОВЕРИЛ НИЧЕГО и лишь выглядит как пройденный. Это ровно та инертная порча, на
     * которой лейн КРАЯ-АДРЕСОВ поймал сам себя.
     *
     * `HB_DIFF_TEST_FAULT_ON_CLEAN=1` штампует описатель отказа на руке выпуска у случаев,
     * где отказа НЕ БЫЛО. Ответ читается в обе стороны и обе стороны осмысленны:
     *   покраснело -> описатель сравнивается БЕЗУСЛОВНО, а не только при отказе;
     *   осталось зелёным -> у оракула слепое пятно на чистых случаях, и это находка.
     * Тронутые считаются тем же счётчиком, поэтому «ничего не тронул» видно числом. */
    if (!kind && !addr && !pc && !valid && !clean) return;
    if (clean) {
        if (jit->exec_result != HB_OK) return;
        g_porcha_tronuto++;
        jit->fault_kind = 7u;          /* значения, которых у чистого случая быть не может */
        jit->fault_addr = 0xdeadbeefu;
        jit->fault_pc   = 0xdeadbeefu;
        jit->fault_addr_valid = 1u;
        return;
    }
    /* Порча ставится ТОЛЬКО там, где отказ ЕСТЬ. Иначе она превратила бы в расхождение
     * каждый исправный случай, и «поймано» перестало бы что-либо значить. */
    if (jit->exec_result == HB_OK) return;
    g_porcha_tronuto++;
    if (kind) jit->fault_kind ^= 1u;
    if (addr) jit->fault_addr += 1u;      /* соседний адрес */
    if (pc)   jit->fault_pc   += 1u;      /* смещение на одну команду не даёт: длины разные */
    if (valid) jit->fault_addr_valid ^= 1u;
}

/* ★★★★ MacRunner 2026-09-07, лейн ОРАКУЛ — ОЖИДАНИЕ В СТРОКЕ КОРПУСА: ОРАКУЛ
 * СТАНОВИТСЯ ЧАСТИЧНО АБСОЛЮТНЫМ.
 *
 * ЗАЧЕМ. Дифференциальный оракул сравнивает ДВЕ НАШИ РУКИ и по построению слеп к дефекту,
 * который у обеих одинаков. Это не теория: на корпусе видов отказа `x87-опустошение` при
 * незамаскированном IM отдаёт `kind=0` НА ОБЕИХ руках, тогда как виду 6 положено
 * `HB_FAULT_KIND_FPU_STACK`. Согласие рук объявило бы это зелёным.
 *
 * Ровно из-за этой слепоты лейну КРАЯ-АДРЕСОВ пришлось строить ОТДЕЛЬНЫЙ прибор
 * `tests/kraya_otkazov.c`: там ожидание записано в самом приборе. Приёмок стало две.
 *
 * Здесь ожидание переносится В СТРОКУ КОРПУСА, именованными полями после третьего:
 *     <зерно> <код> [число-команд] [ожид-вид=N] [ожид-pc=СМЕЩЕНИЕ] [ожид-адрес=0xA]
 * `ожид-pc` — СМЕЩЕНИЕ от базы гостевого кода, а не абсолютный адрес: база зависит от
 * разрядности (`hb_diff_code_base`), и абсолютное число разъехалось бы при первой же
 * правке базы. Ожидание проверяется у ОБЕИХ рук: расхождение с ним красит случай своим
 * именем (`ожид-вид`, `ожид-pc`, `ожид-адрес`), а не именем поля сравнения рук.
 *
 * ГРАНИЦА, названная вслух: поглотить `kraya_otkazov` целиком этим НЕЛЬЗЯ — он проверяет
 * ещё и то, что команды ДО отказавшей исполнены, а команда ПОСЛЕ нет, и делает это по
 * заранее известным значениям регистров-заполнителей. У корпуса такой формы нет: значения
 * регистров задаются ЗЕРНОМ, то есть неизвестны тому, кто пишет строку. Разбор — в отчёте
 * лейна. */
typedef struct {
    long     vid;       /* -1 = не задано */
    long long pc_off;   /* -1 = не задано */
    long long adres;    /* -1 = не задано */
} hb_diff_ozhid_t;

static void run_case_line(hb_arch_t arch, uint64_t seed, const char* code_hex,
                          const hb_diff_ozhid_t* ozh) {
    uint8_t code[HB_DIFF_MAX_CODE];
    size_t code_len = 0;
    if (!parse_hex(code_hex, code, &code_len)) {
        printf("{\"ok\":false,\"error\":\"bad_hex\"}\n");
        return;
    }
    hb_diff_snapshot_t initial, interp, jit;
    memset(&initial, 0, sizeof(initial));
    memset(&interp, 0, sizeof(interp));
    memset(&jit, 0, sizeof(jit));
    hb_result_t ri = run_backend(arch, code, code_len, seed, HB_BACKEND_INTERP, &initial, &interp);
    const char* interp_only_env = getenv("HB_DIFF_INTERP_ONLY");
    bool interp_only = interp_only_env && strcmp(interp_only_env, "1") == 0;
    hb_result_t rj = HB_OK;
    if (interp_only) {
        jit = interp;
    } else {
        rj = run_backend(arch, code, code_len, seed, HB_BACKEND_JIT, NULL, &jit);
        hb_diff_porcha(&jit);
    }
    char diff[64] = {0};
    /* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ — ДЫРА №1 ЗАКРЫТА.
     *
     * Было: `ok = (ri == HB_OK && rj == HB_OK && snapshots_equal(...))`. То есть случай, где
     * ОБЕ руки отказали ОДИНАКОВО (правильное поведение!), объявлялся отказом, а случай,
     * где руки отказали ПО-РАЗНОМУ, объявлялся отказом ТЕМ ЖЕ СПОСОБОМ. Различить их было
     * нечем: `snapshots_equal` до отказавшего случая не доходил вовсе, и `diff` оставался
     * пустым. Отсюда и брались «тысячи постоянных отказов» на прежних корпусах.
     *
     * Стало: вердикт даёт СРАВНЕНИЕ, а коды возврата — часть сравниваемого состояния
     * (`api_result`, `exec_result` сверялись и раньше, теперь к ним добавлен описатель
     * отказа). Согласие рук на отказе — ЗЕЛЁНОЕ и есть проверка; расхождение рук на
     * отказе — КРАСНОЕ и названо полем.
     *
     * `исполнен` и `отказ` печатаются отдельно, чтобы «сколько случаев вообще дошло до
     * исполнения» не приходилось выводить из `ok`: покрытие и правильность — разные
     * величины, и складывать их в одно поле значит потерять обе. */
    bool ok = interp_only ? (ri == HB_OK) : snapshots_equal(&interp, &jit, diff, sizeof(diff));
    /* ★ ОЖИДАНИЕ КОРПУСА ПРОВЕРЯЕТСЯ ПОСЛЕ СРАВНЕНИЯ РУК, А НЕ ВМЕСТО НЕГО.
     *
     * Порядок важен: расхождение рук — более сильная улика (одна из них точно неправа), и
     * терять его под меткой ожидания нельзя. Поэтому ожидание проверяется только у уже
     * согласного случая, зато у ОБЕИХ рук: если обе ошиблись одинаково, ловит именно оно. */
    if (ok && ozh) {
        const hb_diff_snapshot_t* ruki[2] = { &interp, &jit };
        const char* imena[2] = { "интерп", "выпуск" };
        int ir;
        for (ir = 0; ir < (interp_only ? 1 : 2) && ok; ir++) {
            const hb_diff_snapshot_t* s = ruki[ir];
            if (ozh->vid >= 0 && (long)s->fault_kind != ozh->vid) {
                snprintf(diff, sizeof(diff), "ожид-вид[%s]:%ld:%u",
                         imena[ir], ozh->vid, (unsigned)s->fault_kind);
                ok = false;
            } else if (ozh->pc_off >= 0 &&
                       s->fault_pc != hb_diff_code_base(arch == HB_ARCH_X86) +
                                      (unsigned long long)ozh->pc_off) {
                snprintf(diff, sizeof(diff), "ожид-pc[%s]:+0x%llx:0x%" PRIx64,
                         imena[ir], (unsigned long long)ozh->pc_off, s->fault_pc);
                ok = false;
            } else if (ozh->adres >= 0 && s->fault_addr != (uint64_t)ozh->adres) {
                snprintf(diff, sizeof(diff), "ожид-адрес[%s]:0x%llx:0x%" PRIx64,
                         imena[ir], (unsigned long long)ozh->adres, s->fault_addr);
                ok = false;
            }
        }
    }
    char sse_seed_diff[64] = {0}, sse_i_diff[64] = {0}, sse_j_diff[64] = {0};
    int sse_seed_ok = hb_sse_check_seed(&initial, sse_seed_diff, sizeof(sse_seed_diff));
    int sse_i_ok = hb_sse_check_value(&interp, sse_i_diff, sizeof(sse_i_diff));
    int sse_j_ok = interp_only ? 1 : hb_sse_check_value(&jit, sse_j_diff, sizeof(sse_j_diff));
    if (g_hb_sse.touched && (!sse_seed_ok || !sse_i_ok || !sse_j_ok)) {
        if (ok) snprintf(diff, sizeof(diff), "%s", !sse_seed_ok ? sse_seed_diff : !sse_i_ok ? sse_i_diff : sse_j_diff);
        ok = false;
    }
    bool ispolnen = (ri == HB_OK) && (interp_only || rj == HB_OK);
    bool otkaz = ispolnen && (interp.exec_result != HB_OK || jit.exec_result != HB_OK);
    printf("{\"ok\":%s,\"исполнен\":%s,\"отказ\":%s,"
           "\"arch\":\"%s\",\"seed\":\"0x%016" PRIx64 "\",\"code\":\"",
           ok ? "true" : "false", ispolnen ? "true" : "false", otkaz ? "true" : "false",
           arch == HB_ARCH_X86 ? "x86" : "x64", seed);
    print_hex_bytes(code, code_len);
    printf("\",\"diff\":\"%s\",", diff);
    hb_sse_json(&interp, &jit, sse_seed_ok, sse_i_ok, sse_j_ok, interp_only);
    print_snapshot_json("initial", &initial);
    putchar(',');
    print_snapshot_json("interp", &interp);
    putchar(',');
    print_snapshot_json("jit", &jit);
    printf("}\n");
}

int main(void) {
    /* ★★★ MacRunner 2026-09-07, лейн ОРАКУЛ-2 — ЭТАЛОН ОБЯЗАН УМЕТЬ ВОЙТИ В СЕРЕДИНУ БЛОКА.
     *
     * `MACRUNNER_HB_INTERP_MIDBLOCK` в движке имеет умолчание 0 (живой путь не трогаем), но
     * для ОРАКУЛА выключенный он значит слепоту: эталон кончает на первой же переданной
     * управлении внутрь блока, а выпуск слитой единицы идёт дальше, и стенд объявляет
     * расхождение там, где расходится ОХВАТ ЭТАЛОНА, а не выпуск.
     *
     * Поэтому стенд ставит гейт САМ. `setenv(..., 0)` — не перезаписывать: явно заданный
     * снаружи ноль остаётся отрицательным контролем («стенд БЕЗ правки»).
     *
     * ★ И `setenv` ОДНОГО НЕ ХВАТАЕТ. Снимок окружения снимается КОНСТРУКТОРОМ модуля
     * (`hb_env.c:133-134`, `__attribute__((constructor))`), то есть ДО первой строки main;
     * `setenv` после него таблицу гейтов не трогает вовсе. Это ровно тот класс отказа,
     * что записан в памяти проекта как `setenv не меняет кеш гейта`. Поэтому снимок
     * пересобирается явно — `hb_env_refresh()`. */
    setenv("MACRUNNER_HB_INTERP_MIDBLOCK", "1", 0);
    hb_env_refresh();
    const char* arch_env = getenv("HB_DIFF_ARCH");
    hb_arch_t arch = (arch_env && strcmp(arch_env, "x86") == 0) ? HB_ARCH_X86 : HB_ARCH_X64;
    /* Заглушка ставится ДО первого выделения памяти движком: MAP_FIXED поверх уже занятого
     * снёс бы чужое отображение, а в самом начале там заведомо пусто. */
    if (arch != HB_ARCH_X86 && hb_diff_identity_gate()) hb_diff_identity_reserve();
    /* ★ ОГРАЖДЕНИЕ СТАВИТСЯ ЗДЕСЬ, А НЕ ПРИ ПЕРВОМ СЛУЧАЕ.
     *
     * Движок ставит свой обработчик лениво (`install_sig_handlers`, hb_memory.c) и
     * запоминает ПРЕЖНИЙ, чтобы отдать ему чужой отказ. Если ограждение стенда встанет
     * ПОСЛЕ движкового, оно затрёт его и цепочка оборвётся. Здесь — до первого
     * `hb_memory_create`, поэтому движковый обработчик (когда он ставится) окажется
     * СВЕРХУ и в конце цепочки найдёт наше. */
    hb_diff_install_fault_guard();
    char line[8192];   /* 128 байт гостя = 256 знаков + зерно и счёт */
    while (fgets(line, sizeof(line), stdin)) {
        if (!strchr(line, '\n') && !feof(stdin)) {
            int ch; while ((ch = getchar()) != '\n' && ch != EOF) {}
            printf("{\"ok\":false,\"error\":\"line-too-long\"}\n");
            continue;
        }
        char* p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;
        char* seed_s = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (!*p) continue;
        *p++ = 0;
        while (*p && isspace((unsigned char)*p)) p++;
        char* code_s = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        /* Итерация 1461: помним, ЕСТЬ ли текст после кода, ДО того как затрём разделитель
         * нулём. Без этого третье поле (ожидаемое число команд) недостижимо: цикл поиска
         * упирается в только что записанный ноль. Поймано на первой же проверке сторожа. */
        const int has_third = (*p != 0);
        *p = 0;
        char* rest = has_third ? p + 1 : p;
        /* MacRunner 2026-08-17, лейн ЛЕСТНИЦА, итерация 1461 — СТОРОЖ ВХОДА.
         *
         * Третье поле строки — ОЖИДАЕМОЕ ЧИСЛО КОМАНД в случае. Не задано — поведение прежнее.
         *
         * Зачем. Итерации 1457-1458 объявили несуществующий дефект флагов: я подал `40` как
         * `inc eax`, а в 64-битном режиме это префикс REX, и команды не было вовсе. Флаги
         * остались засеянными, что читалось как «движок не считает AF и PF». Ни `diff`, ни
         * `lazy.pending`, ни контроль различимости этого поймать не могли — все три стоят
         * ПОСЛЕ входа.
         *
         * Правило, оставшееся прозой, не работает (проверено на себе же в тот самый день).
         * Работает то, что ОТКАЗЫВАЕТ. Здесь отказ возможен: число команд знает лифтер,
         * а намерение — тот, кто подаёт случай. Расхождение = отказ, а не тихий результат. */
        long want_instrs = -1;
        hb_diff_ozhid_t ozh = { -1, -1, -1 };
        hb_sse_reset();
        hb_diff_nachalo_t nachalo;
        memset(&nachalo, 0, sizeof(nachalo));
        while (*rest && isspace((unsigned char)*rest)) rest++;
        if (*rest && *rest != '#' &&
            strcspn(rest, "= \t\r\n") == strcspn(rest, " \t\r\n")) {
            char* want_s = rest;
            while (*rest && !isspace((unsigned char)*rest)) rest++;
            if (*rest) *rest++ = 0;
            want_instrs = strtol(want_s, NULL, 0);
        }
        /* ★ ИМЕНОВАННЫЕ ПОЛЯ ОЖИДАНИЯ — разбираются ПОСЛЕ третьего и не зависят от порядка.
         *
         * Именованные, а не позиционные, ровно по той причине, по которой третье поле
         * когда-то пришлось заводить сторожем: позиция молчит о смысле, и корпус, где
         * четвёртое поле значит одно, а пятое другое, разъезжается при первой правке.
         * Неизвестное имя — ОТКАЗ строки, а не тихий пропуск: опечатка в имени иначе
         * выглядела бы как «ожидание проверено». */
        /* ★ ДЛИНА ПРЕФИКСА БЕРЁТСЯ `strlen`-ом, А НЕ ЧИСЛОМ. Имена кириллические, в UTF-8
         * буква весит два байта: «ожид-вид=» — 16 байт, а не 9 знаков. Ровно на этом
         * первая редакция резала бы значение по живому и молча читала мусор. */
        int pole_bad = 0;
        while (*rest && !pole_bad) {
            char* tok;
            while (*rest && isspace((unsigned char)*rest)) rest++;
            if (!*rest || *rest == '#') break;
            tok = rest;
            while (*rest && !isspace((unsigned char)*rest)) rest++;
            if (*rest) *rest++ = 0;
#define HB_DIFF_POLE(imya) (!strncmp(tok, imya, strlen(imya)) ? tok + strlen(imya) : NULL)
            {
                const char* v;
                int sse_field = hb_sse_parse(tok);
                if (sse_field) {
                    if (sse_field < 0) {
                        printf("{\"ok\":false,\"error\":\"sse-field\"}\n");
                        pole_bad = 1;
                    }
                }
                else if ((v = HB_DIFF_POLE("ожид-вид=")))        ozh.vid    = strtol(v, NULL, 0);
                else if ((v = HB_DIFF_POLE("ожид-pc=")))    ozh.pc_off = strtoll(v, NULL, 0);
                else if ((v = HB_DIFF_POLE("ожид-адрес="))) ozh.adres  = strtoll(v, NULL, 0);
                else if ((v = HB_DIFF_POLE("флаги="))) {
                    nachalo.flagi = strtoull(v, NULL, 0);
                    nachalo.flagi_est = 1;
                }
                else if ((v = HB_DIFF_POLE("рег-"))) {
                    /* `рег-<имя>=<значение>`: имя до '=', значение после. Неизвестное имя —
                     * ОТКАЗ строки, как и неизвестное поле: иначе опечатка в имени регистра
                     * выглядела бы как «начальное значение задано». */
                    const char* eq = strchr(v, '=');
                    int nom = eq ? hb_diff_reg_nomer(arch, v, (size_t)(eq - v)) : -1;
                    if (nom < 0) {
                        printf("{\"ok\":false,\"code\":\"%s\",\"error\":\"неизвестный-регистр\","
                               "\"поле\":\"%s\"}\n", code_s, tok);
                        fflush(stdout);
                        pole_bad = 1;
                    } else {
                        nachalo.reg[nom] = strtoull(eq + 1, NULL, 0);
                        nachalo.zadano |= (uint32_t)1u << nom;
                    }
                }
                else {
                    printf("{\"ok\":false,\"code\":\"%s\",\"error\":\"неизвестное-поле\","
                           "\"поле\":\"%s\"}\n", code_s, tok);
                    fflush(stdout);
                    pole_bad = 1;
                }
            }
#undef HB_DIFF_POLE
        }
        if (!pole_bad && !hb_sse_validate()) {
            printf("{\"ok\":false,\"error\":\"sse-version-or-input\"}\n");
            pole_bad = 1;
        }
        if (pole_bad) continue;
        uint64_t seed = strtoull(seed_s, NULL, 0);
        if (want_instrs >= 0) {
            hb_ir_func_t* chk = NULL;
            uint8_t bytes[HB_DIFF_MAX_CODE];
            size_t n = 0;
            long got = -1;
            if (parse_hex(code_s, bytes, &n) && lift_code(arch, bytes, n, &chk) == HB_OK) {
                got = (chk && chk->cfg && chk->cfg->entry)
                          ? (long)chk->cfg->entry->instr_count : 0;
                hb_ir_func_destroy(chk);
            }
            if (got != want_instrs) {
                printf("{\"ok\":false,\"code\":\"%s\",\"error\":\"instr_count\","
                       "\"ожидалось\":%ld,\"получено\":%ld,"
                       "\"подсказка\":\"в 64 битах 40+r и 48+r — префиксы REX, а не INC/DEC\"}\n",
                       code_s, want_instrs, got);
                fflush(stdout);
                continue;
            }
        }
        /* Набор действует на ОБЕ руки случая и снимается сразу после него: иначе он
         * протёк бы на следующую строку корпуса и «начальные значения» стали бы
         * зависеть от порядка строк — тот же класс, что залипший гейт в приёмке. */
        g_diff_nachalo = (nachalo.zadano || nachalo.flagi_est) ? &nachalo : NULL;
        run_case_line(arch, seed, code_s, &ozh);
        g_diff_nachalo = NULL;
        fflush(stdout);
    }

    /* ★ ИТОГ ПО ОТКАЗАМ — БЕЗУСЛОВНАЯ ПЕЧАТЬ В stderr.
     *
     * Три числа, без которых вывод об отказах недействителен:
     *   дверь   — сколько раз отказ выпущенного кода забрал ДВИЖОК (и, значит, есть
     *             `fault_kind`/`fault_addr`/`fault_pc`, которые можно сравнивать);
     *   ограждение — сколько раз он ушёл в longjmp стенда (там описателя нет);
     *   порча   — сколько случаев тронул отрицательный контроль. Ноль здесь означает
     *             «контроль не проверил ничего», а НЕ «дефекта нет». */
    fprintf(stderr, "hb-diff-отказы: дверь=%lu ограждение=%lu порча-тронуто=%lu "
                    "ограда-дыр=%lu ограда-байт=%llu\n",
            hb_diff_door_taken, hb_diff_guard_taken, g_porcha_tronuto,
            g_fence_holes, g_fence_bytes);
    fflush(stderr);

    /* MacRunner 2026-08-11, лейн ЛЕСТНИЦА, итерация 368 — КАРТА «НАТИВНО ИЛИ ПОМОЩНИК».
     *
     * По `HB_DIFF_EMIT_MAP=1` печатаем, какие операции IR встречались при выпуске и какие из них
     * ушли в помощник. Это и есть единица, сопоставимая с «>1600 команд x86» у box64: ветвь в
     * кодогенераторе бывает и у тех, кто внутри зовёт помощника, поэтому считать надо решение
     * выпуска, а не наличие ветви. */
    if (getenv("HB_DIFF_EMIT_MAP")) {
        extern unsigned hb_codegen_helper_ops_snapshot(unsigned char*, unsigned char*, unsigned);
        unsigned char hlp[512], seen[512];
        unsigned n = hb_codegen_helper_ops_snapshot(hlp, seen, 512), i, всего = 0, нативных = 0;
        fprintf(stderr, "EMIT-MAP:");
        for (i = 0; i < n; i++) {
            if (!seen[i]) continue;
            всего++;
            if (!hlp[i]) нативных++;
            fprintf(stderr, " %u:%s", i, hlp[i] ? "help" : "nat");
        }
        fprintf(stderr, "\nEMIT-MAP-ИТОГ: операций встречено=%u нативных=%u помощник=%u\n",
                всего, нативных, всего - нативных);
        {
            extern void hb_codegen_emit_flush(void);
            extern unsigned hb_codegen_emit_counts(unsigned*, unsigned*, unsigned);
            static unsigned cn[512], ch[512];
            unsigned k, вып = 0, вып_п = 0;
            hb_codegen_emit_flush();
            hb_codegen_emit_counts(cn, ch, 512);
            for (k = 0; k < 512; k++) { вып += cn[k]; вып_п += ch[k]; }
            fprintf(stderr, "EMIT-ВЫПУСКОВ: всего=%u из них помощник=%u нативно=%u (%.2f %%)\n",
                    вып, вып_п, вып - вып_п, вып ? 100.0 * (double)(вып - вып_п) / (double)вып : 0.0);
        }
        fflush(stderr);
    }

    return 0;
}
