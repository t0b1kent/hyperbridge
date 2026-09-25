/* КОРПУС АДРЕСНЫХ КРАЁВ: ОТКАЗЫ И ТОЧНОСТЬ pc — лейн КРАЯ-АДРЕСОВ, 07.09.2026.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ ПРИБОР, А НЕ СТРОКИ В hb_diff_case_runner.
 *
 * Дифференциальный стенд отбрасывает случай с отказом ПО ПОСТРОЕНИЮ:
 *     ok = (ri == HB_OK && rj == HB_OK && snapshots_equal(...))     hb_diff_case_runner.c:927
 * то есть любой отказ обеих сторон он уже считает «не ok» и до сравнения не доходит.
 * Вдобавок `fault_kind`/`fault_addr` он СНИМАЕТ и печатает, но НЕ СРАВНИВАЕТ, а свой
 * обработчик SIGSEGV/SIGBUS (`hb_diff_install_fault_guard`) перехватывает отказ раньше
 * двери движка, превращая его в EXEC_FAULT. Проверять точность pc там нечем.
 *
 * Здесь то же устройство, что у tests/fault_precision_probe.c (05.09), но предметом
 * взяты АДРЕСНЫЕ КРАЯ: доступ, начинающийся в отображённой странице и кончающийся в
 * неотображённой; доступ целиком за границей; те же края на записи; ширины 1/2/4/8/16;
 * и — главное — pc обязан назвать ТУ команду, которая отказала, при разном числе
 * предшествующих команд.
 *
 * ЧТО ПРОВЕРЯЕТСЯ В КАЖДОМ СЛУЧАЕ (числа, не статус):
 *   1. отказ доложен и это MEMORY_FAULT;
 *   2. pc == адрес отказавшей команды (нативный путь) либо вход блока (путь помощника);
 *   3. адрес отказа == ожидаемый гостевой адрес;
 *   4. команды ДО отказавшей исполнены (три регистра-заполнителя приняли новые значения);
 *   5. команда ПОСЛЕ отказавшей НЕ исполнена (rbp остался прежним).
 * Плюс контрольный случай без отказа: последний полностью отображённый доступ обязан
 * пройти. Без него «всё красное» и «всё зелёное» были бы неразличимы.
 *
 * ОТРИЦАТЕЛЬНЫЕ КОНТРОЛИ (прибор обязан ПОКРАСНЕТЬ):
 *   MACRUNNER_HB_TEST_RIPMAP_SKEW=1        — резолвер называет ПРЕДЫДУЩУЮ команду;
 *   MACRUNNER_HB_TEST_KRAYA_GRANUL_OK=1    — сторож гранула объявляет любой доступ
 *                                            безопасным, и STLR через границу даёт SIGBUS.
 * Прибор, который не краснеет от заведомой порчи, — не прибор.
 *
 * СБОРКА (из engine/hyperbridge):
 *   /usr/bin/clang -O1 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/kraya_otkazov.c libhyperbridge.a -o tests/kraya_otkazov
 *   MACRUNNER_HB_MEM_SEGV_JIT_DOOR=1 ./tests/kraya_otkazov
 * Код выхода 0 = расхождений нет; 1 = есть (все напечатаны).
 */
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define STRANICA 16384u          /* страница macOS ARM64 */

static int g_bad;
static int g_vsego;

static void check(const char* what, unsigned long long got, unsigned long long want) {
    int ok = got == want;
    g_vsego++;
    if (!ok) g_bad++;
    printf("    %-40s %s получено=%#llx ожидание=%#llx\n",
           what, ok ? "ок  " : "РАСХ", got, want);
}

/* ── сборка гостевого кода ──────────────────────────────────────────────────── */
static size_t put(uint8_t* b, size_t n, const void* s, size_t k) {
    memcpy(b + n, s, k);
    return n + k;
}

static size_t movabs(uint8_t* b, size_t n, int reg, uint64_t v) {
    uint8_t h[2] = { 0x48, (uint8_t)(0xb8 + reg) };
    n = put(b, n, h, 2);
    return put(b, n, &v, 8);
}

static size_t movimm32(uint8_t* b, size_t n, int reg, uint32_t v) {
    uint8_t h[3] = { 0x48, 0xc7, (uint8_t)(0xc0 + reg) };
    n = put(b, n, h, 3);
    return put(b, n, &v, 4);
}

/* Доступ по [rbx]: чтение в rcx/xmm1, запись из rax/xmm0. Ширина 1/2/4/8/16. */
static size_t dostup(uint8_t* b, size_t n, int shirina, int zapis) {
    static const uint8_t ld1[]  = { 0x8a, 0x0b };
    static const uint8_t ld2[]  = { 0x66, 0x8b, 0x0b };
    static const uint8_t ld4[]  = { 0x8b, 0x0b };
    static const uint8_t ld8[]  = { 0x48, 0x8b, 0x0b };
    static const uint8_t ld16[] = { 0xf3, 0x0f, 0x6f, 0x0b };
    static const uint8_t st1[]  = { 0x88, 0x03 };
    static const uint8_t st2[]  = { 0x66, 0x89, 0x03 };
    static const uint8_t st4[]  = { 0x89, 0x03 };
    static const uint8_t st8[]  = { 0x48, 0x89, 0x03 };
    static const uint8_t st16[] = { 0xf3, 0x0f, 0x7f, 0x03 };
    const uint8_t* p; size_t k;
    switch (shirina) {
        case 1:  p = zapis ? st1  : ld1;  k = zapis ? sizeof(st1)  : sizeof(ld1);  break;
        case 2:  p = zapis ? st2  : ld2;  k = zapis ? sizeof(st2)  : sizeof(ld2);  break;
        case 4:  p = zapis ? st4  : ld4;  k = zapis ? sizeof(st4)  : sizeof(ld4);  break;
        case 8:  p = zapis ? st8  : ld8;  k = zapis ? sizeof(st8)  : sizeof(ld8);  break;
        default: p = zapis ? st16 : ld16; k = zapis ? sizeof(st16) : sizeof(ld16); break;
    }
    return put(b, n, p, k);
}

/* ── один случай ────────────────────────────────────────────────────────────── */
#define ZAPOLN 0x11110000u      /* значения заполнителей: видно, что команда исполнилась */
#define HVOST  0x22220000u      /* значение хвоста: НЕ должно появиться при отказе */
#define RBP0   0x33330000ull

struct sluchaj {
    const char* imya;
    unsigned    smeshch;        /* адрес доступа = scratch + smeshch */
    int         shirina;
    int         zapis;
    int         zapolnitelej;   /* 0..3 команд между установкой базы и доступом */
    int         zhdem_otkaz;    /* 1 — обязан отказать, 0 — обязан пройти */
    int         zhdem_signal;   /* ЗАМЕРЕНО: 1 — отказ приходит сигналом из выпуска,
                                 * 0 — исполнение ушло в помощника (запасная ветвь
                                 * сторожа выравнивания либо вето прямого пути). */
};

static void progon(const struct sluchaj* s, int native_mem, uint8_t* scratch, uint8_t* codepg) {
    uint8_t code[128];
    size_t n = 0, pc_dostup;
    uint64_t base = (uint64_t)(uintptr_t)codepg;
    uint64_t adres = (uint64_t)(uintptr_t)scratch + s->smeshch;
    uint64_t ex0 = 0, ex1 = 0, nm = 0, nb = 0, fa = 0;
    size_t fs = 0; int fw = 0, fv = 0;
    hb_decoder_t* dec; hb_ir_func_t* func = NULL; hb_context_t* ctx; hb_exec_result_t out;
    int i;

    n = movabs(code, n, 3, adres);              /* rbx = адрес доступа   */
    n = movabs(code, n, 0, 0x0123456789abcdefull); /* rax = узор записи  */
    for (i = 0; i < s->zapolnitelej; i++) {
        static const int regi[3] = { 2, 6, 7 };  /* rdx, rsi, rdi */
        n = movimm32(code, n, regi[i], ZAPOLN + (unsigned)i);
    }
    pc_dostup = n;                               /* ← вот эту команду обязан назвать pc */
    n = dostup(code, n, s->shirina, s->zapis);
    n = movimm32(code, n, 5, HVOST);             /* rbp = хвост (не должен исполниться) */
    code[n++] = 0xc3;                            /* ret */

    printf("  %-52s ширина=%2d %s заполнителей=%d\n", s->imya, s->shirina,
           s->zapis ? "запись" : "чтение", s->zapolnitelej);

    memset(codepg, 0, 4096);
    memcpy(codepg, code, n);
    dec = hb_decoder_create(HB_ARCH_X64, codepg, n, base);
    if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func) {
        printf("    ОСНАСТКА: lift не удался\n"); g_bad++; return;
    }
    hb_decoder_destroy(dec);

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    ctx->memory = hb_memory_create(0);
    hb_memory_map(ctx->memory, base, 4096, HB_PERM_READ | HB_PERM_EXEC);
    /* Движку объявлена ТОЛЬКО первая страница — как и хозяину (вторая PROT_NONE).
     * Значит обе половины, интерпретатор и выпуск, видят одну и ту же границу. */
    hb_memory_map(ctx->memory, (hb_gva_t)(uintptr_t)scratch, STRANICA,
                  HB_PERM_READ | HB_PERM_WRITE);
    ctx->pc = base; ctx->regs.x64.rip = base;
    ctx->regs.x64.rbp = RBP0;
    ctx->regs.x64.rdx = 0; ctx->regs.x64.rsi = 0; ctx->regs.x64.rdi = 0;
    ctx->regs.x64.rcx = 0xC0C0;
    ctx->regs.x64.rsp = (uint64_t)(uintptr_t)scratch + 0x2000;

    hb_jit_fault_pc_stats(&ex0, &nm, &nb);
    memset(&out, 0, sizeof(out));
    hb_runtime_run(ctx, func, HB_BACKEND_JIT, &out);
    hb_jit_fault_pc_stats(&ex1, &nm, &nb);
    hb_memory_last_fault(&fa, &fs, &fw, &fv);

    if (s->zhdem_otkaz) {
        /* ★ ПУТЬ ОТКАЗА БЕРЁТСЯ ЧИСЛОМ, А НЕ ИЗ НАМЕРЕНИЯ.
         *
         * Первая редакция ждала точного pc везде, где ВКЛЮЧЕНА нативная память, и дала
         * 8 «расхождений», которых нет: невыровненный доступ ВЫПУСКАЕТСЯ нативно, но
         * ИСПОЛНЯЕТСЯ через запасную ветвь сторожа выравнивания, то есть через помощника,
         * а у помощника состояние откатывается ко входу блока. Гейт говорил «нативно»,
         * а исполнялось иначе — ровно класс «гейт в окружении ≠ работающий код».
         *
         * `hb_jit_fault_pc_stats` считает ответы КАРТЫ отказов: единица за прогон = отказ
         * пришёл сигналом из выпущенного кода. По этому числу и выбирается ожидание. Само
         * число тоже сверяется (`s->zhdem_signal`) — иначе тихий уход всех случаев в
         * помощника сделал бы проверку pc пустой, оставаясь зелёным. */
        unsigned long long karta = ex1 - ex0;
        check("путь отказа (1=сигнал из выпуска)", karta,
              native_mem ? (unsigned long long)s->zhdem_signal : 0ull);
        check("отказ доложен", out.faulted, 1);
        check("результат MEMORY_FAULT", (unsigned long long)(long long)out.result,
              (unsigned long long)(long long)HB_ERR_MEMORY_FAULT);
        /* ★ ТОЧНОСТЬ pc. На сигнальном пути карта обязана назвать саму отказавшую
         * команду; на пути помощника состояние откатывается ко ВХОДУ блока — это
         * не дефект, а известное свойство, замеренное 05.09 (fault_precision_probe). */
        check("pc = отказавшая команда", ctx->pc - base,
              karta ? (unsigned long long)pc_dostup : 0ull);
        check("адрес отказа", fa, adres);
        for (i = 0; i < s->zapolnitelej; i++) {
            static const char* imena[3] = { "rdx исполнен до отказа",
                                            "rsi исполнен до отказа",
                                            "rdi исполнен до отказа" };
            uint64_t v = (i == 0) ? ctx->regs.x64.rdx
                       : (i == 1) ? ctx->regs.x64.rsi : ctx->regs.x64.rdi;
            check(imena[i], v, ZAPOLN + (unsigned)i);
        }
        check("хвост НЕ исполнен (rbp прежний)", ctx->regs.x64.rbp, RBP0);
    } else {
        check("отказа нет", out.faulted, 0);
        check("результат OK", (unsigned long long)(long long)out.result, 0ull);
        check("хвост исполнен (rbp = узор)", ctx->regs.x64.rbp, HVOST);
    }
    (void)ex1; (void)ex0;
    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
}

/* Дверь сигналов движок открывает ЛЕНИВО — на первом копировании через окно гостя.
 * Самостоятельный двоичный без такого копирования умирает на первом отказе выпущенного
 * кода (rc=139). Открываем явно, тем же путём, что и fault_precision_probe. */
static void otkryt_dver(void) {
    hb_context_t* ctx = hb_context_create(HB_ARCH_X86, HB_BACKEND_INTERP);
    uint32_t v = 0x11223344u;
    if (!ctx) return;
    ctx->memory = hb_memory_create(0);
    if (ctx->memory) {
        hb_memory_guest32_map(ctx->memory, 0x7bde0000u, 4096, HB_PERM_READ | HB_PERM_WRITE);
        hb_memory_write(ctx->memory, 0x7bde0100u, &v, sizeof(v));
        hb_memory_read(ctx->memory, 0x7bde0100u, &v, sizeof(v));
    }
    hb_context_destroy(ctx);
}

int main(void) {
    /* Две страницы подряд: первая RW, вторая PROT_NONE. Граница между ними — ровно
     * тот 16-килобайтный рубеж, о который спотыкается доступ на краю. */
    uint8_t* scratch = mmap(NULL, 2 * STRANICA, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* codepg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    struct sluchaj tabl[64];
    size_t n = 0, i;
    int native_mem;
    const int shiriny[5] = { 1, 2, 4, 8, 16 };

    setvbuf(stdout, NULL, _IONBF, 0);
    if (scratch == MAP_FAILED || codepg == MAP_FAILED) {
        printf("ОСНАСТКА: mmap не удался\n");
        return 1;
    }
    memset(scratch, 0, 2 * STRANICA);
    if (mprotect(scratch + STRANICA, STRANICA, PROT_NONE) != 0) {
        printf("ОСНАСТКА: mprotect не удался\n");
        return 1;
    }
    otkryt_dver();

    /* Таблица случаев. Три семьи: доступ ЦЕЛИКОМ за границей, доступ ЧЕРЕЗ границу
     * (первый байт отображён, последний нет) и контрольный доступ ВПЛОТНУЮ до границы,
     * который обязан пройти. */
    for (i = 0; i < 5; i++) {
        int w = shiriny[i];
        struct sluchaj a = { "целиком за границей 16 КБ", STRANICA, w, 0, 0, 1, 1 };
        struct sluchaj b = { "целиком за границей 16 КБ", STRANICA, w, 1, 0, 1, w == 16 ? 0 : 1 };
        tabl[n++] = a; tabl[n++] = b;
        if (w > 1) {
            /* ★ ЗАМЕРЕНО, а не выведено: у 128-битного ЧТЕНИЯ сторожа выравнивания нет,
             * поэтому невыровненный доступ уходит сигналом из выпуска (путь=1), тогда как
             * узкие ширины 2/4/8 ловит сторож и уводит в помощника (путь=0). */
            struct sluchaj c = { "ЧЕРЕЗ границу 16 КБ", STRANICA - (unsigned)w + 1, w, 0, 0, 1,
                                 w == 16 ? 1 : 0 };
            struct sluchaj d = { "ЧЕРЕЗ границу 16 КБ", STRANICA - (unsigned)w + 1, w, 1, 0, 1, 0 };
            tabl[n++] = c; tabl[n++] = d;
        }
        {
            struct sluchaj e = { "вплотную ДО границы (обязан пройти)",
                                 STRANICA - (unsigned)w, w, 1, 0, 0, 0 };
            tabl[n++] = e;
        }
    }
    /* Точность pc при разном числе предшествующих команд: 0, 1, 2, 3. */
    for (i = 0; i < 4; i++) {
        struct sluchaj f = { "pc при N предшествующих командах", STRANICA, 8, 0, (int)i, 1, 1 };
        tabl[n++] = f;
    }

    for (native_mem = 1; native_mem >= 0; native_mem--) {
        printf("== %s\n", native_mem ? "нативная память ВКЛ (отказ сигналом из выпуска)"
                                     : "нативная память ВЫКЛ (отказ программный, из помощника)");
        setenv("MACRUNNER_HB_JIT_DIRECT_MEM", native_mem ? "1" : "0", 1);
        setenv("MACRUNNER_HB_JIT_NATIVE_MEM_IR", native_mem ? "1" : "0", 1);
        setenv("MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS", native_mem ? "1" : "0", 1);
        hb_arm64_codegen_gate_cache_reset();
        for (i = 0; i < n; i++) progon(&tabl[i], native_mem, scratch, codepg);
    }

    printf("%s: случаев=%zu проверок=%d расхождений=%d\n",
           g_bad ? "КРАСНЫЙ" : "ЗЕЛЁНЫЙ", n * 2, g_vsego, g_bad);
    return g_bad ? 1 : 0;
}
