/* MacRunner 2026-08-16, лейн ПАМЯТЬ, итерация 8 — СТЕНД ГРАНИЦЫ ВЫЗОВОВ (`hb_thunks.c`).
 *
 * Зачем. Вторая половина ступени 7 — «граница вызовов» — не имела прибора вовсе. Опись
 * (итерация 7) показала: из пяти признаков закрытия этот файл отвечает ровно за ОДИН —
 * передачу аргументов. Его и меряю, а про остальные четыре в отчёте сказано, что их здесь нет.
 *
 * Что проверяется — не «работает ли», а СОГЛАСОВАНО ЛИ то, что положил вызывающий, с тем, что
 * получила хозяйская функция:
 *
 *   x64   аргументы 0-3 идут в rcx/rdx/r8/r9, пятый — со стека по rsp+8+32 (возврат + теневые 32)
 *   x86   все аргументы на стеке по esp+4+i*4
 *   назад значение возвращается в rax (x64) и eax (x86)
 *
 * ОКНО ОТКАЗА открыто тремя способами (входящее, пункт 3 — «отсутствие отказа ничего не
 * доказывает»):
 *   1. `HB_THUNKCONTRACT_NEGATIVE=1` переворачивает ожидания, стенд ОБЯЗАН тогда отказать;
 *   2. на стек кладутся РАЗНЫЕ метки по соседним смещениям (rsp+32, +40, +48), поэтому ошибка
 *      смещения на одно слово не спрячется за «совпало»;
 *   3. отдельный случай с НЕДОСТУПНЫМ стеком: он показывает, отличает ли граница «аргумент
 *      равен нулю» от «аргумент прочитать не удалось».
 *
 * ЧЕГО СТЕНД НЕ УМЕЕТ — границы обязательны:
 *   * не проверяет обратные вызовы, структуры по значению, переменное число аргументов и
 *     доставку исключения — в `hb_thunks.c` этого нет вовсе (опись, итерация 7);
 *   * не проверяет плавающую точку и XMM — среди девяти подписей их нет;
 *   * зовёт хозяйскую функцию НАПРЯМУЮ через `hb_thunk_call_generated`, то есть меряет
 *     разбор аргументов, а не выпущенный переходник.
 *
 * Запуск: make -C engine/hyperbridge thunk-contract-test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "hb_context.h"
#include "hb_memory.h"
#include "hb_thunk.h"
#include "hb_abi.h"

#define STACK_BASE_X64  0x00300000ull
#define STACK_BASE_X86  0x00200000ull
#define STACK_SIZE      0x2000u

static int g_checks, g_fail, g_negative;

static void check(const char *what, unsigned long long want, unsigned long long got)
{
    int agree = (want == got);

    g_checks++;
    if (g_negative) agree = !agree;
    if (!agree) {
        g_fail++;
        printf("  РАСХОЖДЕНИЕ  %-38s ждали 0x%llx, пришло 0x%llx\n", what, want, got);
    }
}

/* --- хозяйские цели: записывают то, что до них дошло ---------------------------------- */

static uint64_t g_a0, g_a1, g_a2, g_a3, g_a4;
static unsigned g_calls;

static uint64_t target_two(uint64_t a, uint64_t b)
{
    g_calls++; g_a0 = a; g_a1 = b;
    return a ^ b;
}

static uint32_t target_five(uint64_t a0, uint64_t a1, uint32_t a2, uint64_t a3, uint64_t a4)
{
    g_calls++; g_a0 = a0; g_a1 = a1; g_a2 = a2; g_a3 = a3; g_a4 = a4;
    return 0x5A5A5A5Au;
}

static uint32_t target_one(uint32_t a) { g_calls++; g_a0 = a; return a; }
static uintptr_t target_pointer(uintptr_t a) { g_calls++; g_a0 = a; return a; }
static void target_void_one(uint32_t a) { g_calls++; g_a0 = a; }
static int32_t target_four(uintptr_t a, uintptr_t b, uint64_t c, uint64_t d)
{
    g_calls++; g_a0 = a; g_a1 = b; g_a2 = c; g_a3 = d;
    return 0;
}
static void target_void(void) { g_calls++; }
static uint32_t target_u32(void) { g_calls++; return 0x13579bdfu; }
static uint64_t target_u64(void) { g_calls++; return UINT64_C(0x1234567887654321); }

/* --- оснастка ------------------------------------------------------------------------- */

static hb_context_t *make_ctx(hb_arch_t arch, hb_gva_t stack_base, int map_stack)
{
    hb_context_t *ctx = hb_context_create(arch, HB_BACKEND_INTERP);

    if (!ctx) return NULL;
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory) { hb_context_destroy(ctx); return NULL; }
    if (map_stack &&
        hb_memory_map_private(ctx->memory, stack_base, STACK_SIZE,
                              HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        hb_context_destroy(ctx);
        return NULL;
    }
    return ctx;
}

static int call_through(hb_context_t *ctx, hb_thunk_signature_id_t sig, void *target,
                        uint64_t module_id, hb_result_t *rc_out)
{
    hb_generated_thunk_t th;
    hb_result_t rc = hb_thunk_get(ctx, module_id, sig, target, &th);

    if (rc != HB_OK) { g_fail++; printf("  ОСНАСТКА: hb_thunk_get отказал (код %d)\n", (int)rc); return 0; }
    g_calls = 0; g_a0 = g_a1 = g_a2 = g_a3 = g_a4 = 0;
    *rc_out = hb_thunk_call_generated(ctx, &th);
    return 1;
}

/* Every argument must be readable before a native function can have effects.
 * The target call counter is independent of the argument-reader implementation. */
static void expect_read_rejected(hb_context_t *ctx, hb_thunk_signature_id_t sig,
                                 void *target, hb_result_t expected, const char *label)
{
    unsigned char before[sizeof(*ctx)];
    hb_result_t rc = HB_OK;
    if (ctx->mode == HB_MODE_64BIT) ctx->regs.x64.rax = UINT64_C(0xfedcba9876543210);
    else ctx->regs.x86.eax = UINT32_C(0x76543210);
    memcpy(before, ctx, sizeof before);
    if (!call_through(ctx, sig, target, 90, &rc)) return;
    printf("  read-rejection: %s arch=%u sig=%u rc=%d calls=%u\n",
           label, (unsigned)ctx->arch, (unsigned)sig, (int)rc, g_calls);
    check("read failure: exact status", (uint64_t)(int64_t)expected, (uint64_t)(int64_t)rc);
    check("read failure: no native call", 0, g_calls);
    check("read failure: context unchanged", 0, memcmp(before, ctx, sizeof before) != 0);
}

static void checked_argument_reads(void)
{
    const uint64_t marker = UINT64_C(0xabcdef0198765432);
    const struct {
        hb_thunk_signature_id_t sig;
        void *target;
        unsigned count;
        uint64_t result;
    } cases[] = {
        {HB_THUNK_SIG_U32_U32, (void *)target_one, 1, 0},
        {HB_THUNK_SIG_U64_U64_U64, (void *)target_two, 2, 0},
        {HB_THUNK_SIG_PTR_PTR, (void *)target_pointer, 1, 0},
        {HB_THUNK_SIG_VOID_U32, (void *)target_void_one, 1, marker},
        {HB_THUNK_SIG_BOOL_HANDLE_PTR_U32_PTR_PTR, (void *)target_five, 5, 0x5a5a5a5a},
        {HB_THUNK_SIG_I32_PTR_CSTR_U64_U64, (void *)target_four, 4, 0}
    };
    for (unsigned arch_index = 0; arch_index < 2; ++arch_index) {
        int x64 = arch_index != 0;
        hb_gva_t base = x64 ? STACK_BASE_X64 : STACK_BASE_X86;
        for (size_t c = 0; c < sizeof cases / sizeof cases[0]; ++c) {
            hb_context_t *ctx = make_ctx(x64 ? HB_ARCH_X64 : HB_ARCH_X86, base, 1);
            if (!ctx) { g_fail++; return; }
            hb_result_t rc = HB_OK;
            hb_gva_t top = base + STACK_SIZE;
            uint8_t zeros[64] = {0};
            if (x64) { ctx->regs.x64.rsp = base + 0x800; ctx->regs.x64.rax = marker; }
            else { ctx->regs.x86.esp = (uint32_t)(base + 0x800); ctx->regs.x86.eax = (uint32_t)marker; }
            check("zero argument fixture", HB_OK,
                  hb_memory_write(ctx->memory, base + 0x800, zeros, sizeof zeros));
            if (call_through(ctx, cases[c].sig, cases[c].target, 90, &rc)) {
                check("readable zero: status", HB_OK, rc);
                check("readable zero: one native call", 1, g_calls);
                check("readable zero: all arguments zero", 0, g_a0 | g_a1 | g_a2 | g_a3 | g_a4);
                check("readable zero: return value", x64 ? cases[c].result : (uint32_t)cases[c].result,
                      x64 ? ctx->regs.x64.rax : ctx->regs.x86.eax);
            }
            if (!x64 || cases[c].count > 4) {
                /* Put each possible failure after a readable prefix. */
                for (unsigned slot = x64 ? 4 : 0; slot < cases[c].count; ++slot) {
                    if (x64) ctx->regs.x64.rsp = top - 40;
                    else {
                        ctx->regs.x86.esp = (uint32_t)(top - 4 - 4 * slot);
                        for (unsigned i = 0; i < slot; ++i) {
                            uint32_t v = 0x12340000u + i;
                            check("readable prefix fixture", HB_OK,
                                  hb_memory_write(ctx->memory, (hb_gva_t)ctx->regs.x86.esp + 4 + 4 * i, &v, 4));
                        }
                    }
                    expect_read_rejected(ctx, cases[c].sig, cases[c].target,
                                         HB_ERR_MEMORY_FAULT, "unmapped slot after prefix");
                }
                /* A scalar straddling the end of the mapping must also fail. */
                if (x64) ctx->regs.x64.rsp = top - 44;
                else ctx->regs.x86.esp = (uint32_t)(top - 6);
                expect_read_rejected(ctx, cases[c].sig, cases[c].target,
                                     HB_ERR_MEMORY_FAULT, "partially readable scalar");
                if (x64) ctx->regs.x64.rsp = base + 0x800;
                else ctx->regs.x86.esp = (uint32_t)(base + 0x800);
                check("deny-read fixture", HB_OK, hb_memory_protect(ctx->memory, base, STACK_SIZE, HB_PERM_WRITE));
                expect_read_rejected(ctx, cases[c].sig, cases[c].target,
                                     HB_ERR_MEMORY_FAULT, "read permission denied");
                check("restore-read fixture", HB_OK, hb_memory_protect(ctx->memory, base, STACK_SIZE,
                                                                      HB_PERM_READ | HB_PERM_WRITE));
                if (x64) {
                    ctx->regs.x64.rsp = UINT64_MAX - 39;
                    expect_read_rejected(ctx, cases[c].sig, cases[c].target,
                                         HB_ERR_INVALID_ARG, "stack address overflow");
                    ctx->regs.x64.rsp = UINT64_MAX - 43;
                    expect_read_rejected(ctx, cases[c].sig, cases[c].target,
                                         HB_ERR_INVALID_ARG, "stack span overflow");
                }
            }
            hb_memory_t *memory = ctx->memory;
            ctx->memory = NULL;
            if (!x64 || cases[c].count > 4) {
                expect_read_rejected(ctx, cases[c].sig, cases[c].target,
                                     HB_ERR_INVALID_ARG, "missing required memory");
            } else if (call_through(ctx, cases[c].sig, cases[c].target, 90, &rc)) {
                check("register-only call needs no memory", HB_OK, rc);
                check("register-only target invoked", 1, g_calls);
            }
            ctx->memory = memory;
            hb_context_destroy(ctx);
        }
        const struct { hb_thunk_signature_id_t sig; void *target; } no_args[] = {
            {HB_THUNK_SIG_VOID_VOID, (void *)target_void},
            {HB_THUNK_SIG_U32_VOID, (void *)target_u32},
            {HB_THUNK_SIG_U64_VOID, (void *)target_u64}
        };
        hb_context_t *ctx = hb_context_create(x64 ? HB_ARCH_X64 : HB_ARCH_X86, HB_BACKEND_INTERP);
        if (!ctx) { g_fail++; return; }
        for (size_t i = 0; i < sizeof no_args / sizeof no_args[0]; ++i) {
            hb_result_t rc = HB_OK;
            if (call_through(ctx, no_args[i].sig, no_args[i].target, 91, &rc)) {
                check("zero-argument call needs no memory", HB_OK, rc);
                check("zero-argument target invoked", 1, g_calls);
            }
        }
        hb_context_destroy(ctx);
    }
    hb_thunk_release(90);
    hb_thunk_release(91);
}

int main(void)
{
    hb_result_t rc = HB_OK;

    setvbuf(stdout, NULL, _IONBF, 0);
    g_negative = (getenv("HB_THUNKCONTRACT_NEGATIVE") != NULL);
    printf("стенд границы вызовов%s\n", g_negative ? "   [ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ]" : "");

    checked_argument_reads();

    /* --- 1. x64: два аргумента из регистров, значение назад в rax ---------------------- */
    {
        hb_context_t *ctx = make_ctx(HB_ARCH_X64, STACK_BASE_X64, 1);

        if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: контекст x64 не создался\n"); return 2; }
        ctx->regs.x64.rcx = 0x1111222233334444ull;
        ctx->regs.x64.rdx = 0x5555666677778888ull;
        ctx->regs.x64.rsp = STACK_BASE_X64 + 0x1000;

        if (call_through(ctx, HB_THUNK_SIG_U64_U64_U64, (void *)target_two, 1, &rc)) {
            printf("  x64 два аргумента: rc=%d вызовов=%u\n", (int)rc, g_calls);
            check("x64 аргумент 0 = rcx", 0x1111222233334444ull, g_a0);
            check("x64 аргумент 1 = rdx", 0x5555666677778888ull, g_a1);
            check("x64 значение назад в rax",
                  0x1111222233334444ull ^ 0x5555666677778888ull, ctx->regs.x64.rax);
        }
        hb_context_destroy(ctx);
    }

    /* --- 2. x64: пятый аргумент со стека, соседние смещения помечены разными числами --- */
    {
        hb_context_t *ctx = make_ctx(HB_ARCH_X64, STACK_BASE_X64, 1);
        hb_gva_t rsp = STACK_BASE_X64 + 0x800;

        if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: контекст x64 (2) не создался\n"); return 2; }
        ctx->regs.x64.rcx = 0xA0;
        ctx->regs.x64.rdx = 0xA1;
        ctx->regs.x64.r8  = 0xA2;
        ctx->regs.x64.r9  = 0xA3;
        ctx->regs.x64.rsp = rsp;

        /* Метки по соседям: ошибка на одно слово будет ВИДНА, а не спрячется. */
        { uint64_t v; v = 0xDEAD0020ull; hb_memory_write(ctx->memory, rsp + 32, &v, 8);
                     v = 0xC0DE0028ull; hb_memory_write(ctx->memory, rsp + 40, &v, 8);
                     v = 0xDEAD0030ull; hb_memory_write(ctx->memory, rsp + 48, &v, 8); }

        if (call_through(ctx, HB_THUNK_SIG_BOOL_HANDLE_PTR_U32_PTR_PTR, (void *)target_five, 2, &rc)) {
            printf("  x64 пять аргументов: rc=%d вызовов=%u  пятый=0x%llx\n",
                   (int)rc, g_calls, (unsigned long long)g_a4);
            check("x64 аргумент 0 = rcx", 0xA0, g_a0);
            check("x64 аргумент 1 = rdx", 0xA1, g_a1);
            check("x64 аргумент 2 = r8",  0xA2, g_a2);
            check("x64 аргумент 3 = r9",  0xA3, g_a3);
            check("x64 аргумент 4 = [rsp+40]", 0xC0DE0028ull, g_a4);
            check("x64 значение назад в rax", 0x5A5A5A5Au, (uint32_t)ctx->regs.x64.rax);
        }
        hb_context_destroy(ctx);
    }

    /* --- 3. x86: аргументы со стека по esp+4+i*4 --------------------------------------- */
    {
        hb_context_t *ctx = make_ctx(HB_ARCH_X86, STACK_BASE_X86, 1);
        hb_gva_t esp = STACK_BASE_X86 + 0x800;

        if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: контекст x86 не создался\n"); return 2; }
        ctx->regs.x86.esp = (uint32_t)esp;
        { uint32_t v; v = 0xBAD00000u; hb_memory_write(ctx->memory, esp,     &v, 4);  /* возврат */
                     v = 0x11110004u; hb_memory_write(ctx->memory, esp + 4, &v, 4);
                     v = 0x22220008u; hb_memory_write(ctx->memory, esp + 8, &v, 4); }

        if (call_through(ctx, HB_THUNK_SIG_U64_U64_U64, (void *)target_two, 3, &rc)) {
            printf("  x86 два аргумента: rc=%d вызовов=%u\n", (int)rc, g_calls);
            check("x86 аргумент 0 = [esp+4]", 0x11110004u, g_a0);
            check("x86 аргумент 1 = [esp+8]", 0x22220008u, g_a1);
            check("x86 значение назад в eax",
                  (uint32_t)(0x11110004u ^ 0x22220008u), ctx->regs.x86.eax);
        }
        hb_context_destroy(ctx);
    }

    /* --- 4. НЕДОСТУПНЫЙ СТЕК: отличает ли граница «ноль» от «прочитать не смог» -------- */
    {
        hb_context_t *ctx = make_ctx(HB_ARCH_X64, STACK_BASE_X64, 0);   /* стек НЕ отображён */

        if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: контекст x64 (4) не создался\n"); return 2; }
        ctx->regs.x64.rcx = 0xB0;
        ctx->regs.x64.rdx = 0xB1;
        ctx->regs.x64.r8  = 0xB2;
        ctx->regs.x64.r9  = 0xB3;
        ctx->regs.x64.rsp = STACK_BASE_X64 + 0x800;

        if (call_through(ctx, HB_THUNK_SIG_BOOL_HANDLE_PTR_U32_PTR_PTR, (void *)target_five, 4, &rc)) {
            printf("  x64 стек НЕ отображён: код возврата=%d, пятый аргумент=0x%llx\n",
                   (int)rc, (unsigned long long)g_a4);
            printf("             %s\n",
                   (rc == HB_OK && g_a4 == 0)
                       ? "★ МОЛЧАЛИВЫЙ НОЛЬ: чтение отказало, аргумент подделан нулём, код HB_OK"
                       : "граница отличает отказ чтения от нуля");
            check("unmapped x64 stack reports failure", (uint64_t)(int64_t)HB_ERR_MEMORY_FAULT,
                  (uint64_t)(int64_t)rc);
            check("unmapped x64 stack prevents target call", 0, g_calls);
        }
        hb_context_destroy(ctx);
    }

    /* --- 5. ОБРАТНАЯ СТОРОНА ГРАНИЦЫ: вызов В ГОСТЯ (`hb_abi_x64.c:7`) ------------------
     *
     * Опись итерации 7 сказала «обратных вызовов в hb_thunks.c нет». Это правда, но неполно:
     * механизм вызова В гостя существует — `hb_abi_x64_call` строит синтетический кадр Win64.
     * Файл не мой, поэтому МЕРЯЮ, а не правлю.
     *
     * Контракт, который он обязан держать (по его же комментарию, строки 12-16):
     *   [rsp]          адрес возврата
     *   [rsp+8..0x27]  теневая область 32 байта, заполняется из shadow_space
     *   [rsp+0x28...]  аргументы с пятого
     *   на входе в функцию RSP обязан быть 8 по модулю 16
     * и отдельно — «состояние гостя меняется ТОЛЬКО после того, как кадр построен».
     */
    {
        hb_context_t *ctx = make_ctx(HB_ARCH_X64, STACK_BASE_X64, 1);

        if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: контекст x64 (5) не создался\n"); return 2; }
        ctx->memory->stack_bottom = STACK_BASE_X64;
        ctx->memory->stack_top = STACK_BASE_X64 + STACK_SIZE;
        ctx->regs.x64.rsp = STACK_BASE_X64 + 0x1000;

        {
            uint64_t sargs[3] = { 0x5501, 0x5502, 0x5503 };
            hb_abi_x64_call_t call;
            uint64_t out = 0, v = 0;
            hb_result_t r;

            memset(&call, 0, sizeof(call));
            call.rcx = 0xC1; call.rdx = 0xC2; call.r8 = 0xC3; call.r9 = 0xC4;
            call.stack_args = sargs; call.stack_arg_count = 3;
            call.shadow_space[0] = 0x5F00; call.shadow_space[1] = 0x5F01;
            call.shadow_space[2] = 0x5F02; call.shadow_space[3] = 0x5F03;

            r = hb_abi_x64_call(ctx, 0x00401000ull, &call, &out);
            printf("  вызов в гостя: rc=%d rsp=0x%llx (mod16=%llu) pc=0x%llx\n",
                   (int)r, (unsigned long long)ctx->regs.x64.rsp,
                   (unsigned long long)(ctx->regs.x64.rsp & 15),
                   (unsigned long long)ctx->pc);

            if (r == HB_OK) {
                check("в гостя: rcx", 0xC1, ctx->regs.x64.rcx);
                check("в гостя: rdx", 0xC2, ctx->regs.x64.rdx);
                check("в гостя: r8",  0xC3, ctx->regs.x64.r8);
                check("в гостя: r9",  0xC4, ctx->regs.x64.r9);
                check("в гостя: pc = цель", 0x00401000ull, ctx->pc);
                check("в гостя: rip = цель", 0x00401000ull, ctx->regs.x64.rip);
                /* Выравнивание входа: RSP обязан быть 8 по модулю 16 — это НЕ «как получилось»,
                 * а требование ABI, записанное в самом файле. */
                check("в гостя: RSP на входе = 8 mod 16", 8, ctx->regs.x64.rsp & 15);

                hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp, &v);
                check("в гостя: [rsp] = адрес возврата", 0xFFFF0000ull, v);
                hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 8, &v);
                check("в гостя: теневая 0", 0x5F00ull, v);
                hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 32, &v);
                check("в гостя: теневая 3", 0x5F03ull, v);
                hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 40, &v);
                check("в гостя: аргумент 5 = [rsp+40]", 0x5501ull, v);
                hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 56, &v);
                check("в гостя: аргумент 7 = [rsp+56]", 0x5503ull, v);
            }
        }
        hb_context_destroy(ctx);
    }

    /* --- 5b. То же с ЧЁТНЫМ числом аргументов: ветвь добивки другая ---------------------
     * `align_pad = (stack_arg_count & 1) ? 8 : 0` — то есть выравнивание держится РАЗНЫМИ
     * путями для чётного и нечётного числа. Проверив только одно, я проверил половину. */
    {
        hb_context_t *ctx = make_ctx(HB_ARCH_X64, STACK_BASE_X64, 1);

        if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: контекст x64 (5b) не создался\n"); return 2; }
        ctx->memory->stack_bottom = STACK_BASE_X64;
        ctx->memory->stack_top = STACK_BASE_X64 + STACK_SIZE;
        ctx->regs.x64.rsp = STACK_BASE_X64 + 0x1000;
        {
            uint64_t sargs[2] = { 0x6601, 0x6602 };
            hb_abi_x64_call_t call;
            uint64_t out = 0, v = 0;
            hb_result_t r;

            memset(&call, 0, sizeof(call));
            call.stack_args = sargs; call.stack_arg_count = 2;
            r = hb_abi_x64_call(ctx, 0x00402000ull, &call, &out);
            printf("  вызов в гостя (чётное): rc=%d rsp mod16=%llu\n",
                   (int)r, (unsigned long long)(ctx->regs.x64.rsp & 15));
            if (r == HB_OK) {
                check("в гостя чёт: RSP = 8 mod 16", 8, ctx->regs.x64.rsp & 15);
                hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 40, &v);
                check("в гостя чёт: аргумент 5 = [rsp+40]", 0x6601ull, v);
                hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 48, &v);
                check("в гостя чёт: аргумент 6 = [rsp+48]", 0x6602ull, v);
            }
        }
        hb_context_destroy(ctx);
    }

    /* --- 6. ОТКАЗ ПОСРЕДИ ПОСТРОЕНИЯ: состояние гостя обязано остаться нетронутым --------
     * Тот же класс, что дефект 4 отчёта (учёт менялся ДО обращения к ядру). Стек НЕ отображён,
     * значит кадр построить негде. Проверяю, что вызов отказал И ничего не тронул. */
    {
        hb_context_t *ctx = make_ctx(HB_ARCH_X64, STACK_BASE_X64, 0);

        if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: контекст x64 (6) не создался\n"); return 2; }
        {
            hb_abi_x64_call_t call;
            uint64_t out = 0;
            hb_result_t r;
            uint64_t rsp0 = 0x00700000ull, pc0 = 0x00123456ull, rcx0 = 0xDEAD;

            memset(&call, 0, sizeof(call));
            call.rcx = 0xBEEF;
            ctx->regs.x64.rsp = rsp0;
            ctx->regs.x64.rcx = rcx0;
            ctx->pc = pc0;

            r = hb_abi_x64_call(ctx, 0x00401000ull, &call, &out);
            printf("  отказ посреди построения: rc=%d\n", (int)r);
            check("отказ: код = MEMORY_FAULT", (unsigned long long)(uint64_t)(int64_t)HB_ERR_MEMORY_FAULT,
                  (unsigned long long)(uint64_t)(int64_t)r);
            check("отказ: rsp не тронут", rsp0, ctx->regs.x64.rsp);
            check("отказ: rcx не тронут", rcx0, ctx->regs.x64.rcx);
            check("отказ: pc не тронут",  pc0,  ctx->pc);
        }
        hb_context_destroy(ctx);
    }

    printf("сверок %d, расхождений %d\n", g_checks, g_fail);
    if (g_negative)
        printf("отрицательный контроль: перевёрнутых ожиданий не сошлось %d из %d\n",
               g_fail, g_checks);
    return g_fail ? 1 : 0;
}
