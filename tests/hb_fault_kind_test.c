/* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 772 — сторож пометки ПРИРОДЫ ОТКАЗА.
 *
 * Зачем. `HB_ERR_EXEC_FAULT` возвращается из мест с разной гостевой семантикой: деление на
 * ноль и переполнение частного (архитектурно #DE) и переход/вызов по нулевому адресу
 * (нарушение доступа с признаком ИСПОЛНЕНИЯ). Наверху, в `macrunner_hb.c`, по этому коду
 * доставляется гостю РАЗНОЕ исключение, и различает их единственная вещь —
 * `ctx->last_fault_kind`, проставляемая `hb_fault_divide` / `hb_fault_null_exec`.
 *
 * Пометка стоит в 26 местах ДВУХ исполнителей (10+2 в интерпретаторе, 11+3 в помощнике
 * кодогенератора). Любая будущая правка деления или ветвления может тихо вернуть голое
 * `return HB_ERR_EXEC_FAULT;` — и гость начнёт получать не то исключение, причём молча.
 * Этот тест ловит такую регрессию без прогона игры.
 *
 * Отрицательный контроль обязателен: обычная команда обязана оставлять вид отказа НУЛЁМ.
 * Без него «поле заполняется» ничего не доказывает — оно могло бы стоять всегда.
 *
 * Проверка: make -C engine/hyperbridge fault-kind-test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hb_context.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include "hb_decoder.h"
#include "hb_memory.h"
#include "hb_runtime.h"

#define CODE_BASE  0x100000ULL
#define STACK_BASE 0x71000000ULL
#define STACK_SIZE 0x2000U

static int g_failures;

static hb_result_t lift(const uint8_t* code, size_t len, hb_ir_func_t** out) {
    hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, code, len, CODE_BASE);
    hb_result_t r;

    if (!dec) return HB_ERR_OUT_OF_MEMORY;
    r = hb_lift_func_x64(dec, out);
    hb_decoder_destroy(dec);
    return r;
}

static void check(const char* name, const uint8_t* code, size_t len,
                  hb_backend_t backend, hb_result_t want_result, uint32_t want_kind) {
    hb_ir_func_t* func = NULL;
    hb_context_t* ctx;
    hb_exec_result_t out;
    hb_result_t r;
    const char* who = backend == HB_BACKEND_JIT ? "jit" : "interp";

    if (lift(code, len, &func) != HB_OK) {
        printf("  ОТКАЗ  %-28s %-6s не поднялось\n", name, who);
        g_failures++;
        return;
    }
    ctx = hb_context_create(HB_ARCH_X64, backend);
    if (!ctx) { hb_ir_func_destroy(func); g_failures++; return; }
    ctx->memory = hb_memory_create(0x200000);
    hb_memory_map_private(ctx->memory, CODE_BASE, 0x1000, HB_PERM_READ | HB_PERM_WRITE);
    hb_memory_write(ctx->memory, CODE_BASE, code, len);
    hb_memory_protect(ctx->memory, CODE_BASE, 0x1000, HB_PERM_READ | HB_PERM_EXEC);
    hb_memory_map_private(ctx->memory, STACK_BASE, STACK_SIZE, HB_PERM_READ | HB_PERM_WRITE);
    ctx->regs.x64.rsp = STACK_BASE + 0x1000;
    ctx->regs.x64.rip = CODE_BASE;
    hb_context_set_pc(ctx, CODE_BASE);

    memset(&out, 0, sizeof(out));
    r = hb_runtime_run(ctx, func, backend, &out);
    (void)r;

    if (out.result != want_result || ctx->last_fault_kind != want_kind) {
        printf("  ОТКАЗ  %-28s %-6s result=%d (ждали %d)  fault_kind=%u (ждали %u)\n",
               name, who, out.result, want_result,
               (unsigned)ctx->last_fault_kind, (unsigned)want_kind);
        g_failures++;
    } else {
        printf("  ok     %-28s %-6s result=%d fault_kind=%u addr=0x%llx\n",
               name, who, out.result, (unsigned)ctx->last_fault_kind,
               (unsigned long long)ctx->last_fault_addr);
    }

    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
}

/* Отрицательный контроль САМОГО сторожа. Правило лейна: проверка, про которую не показано,
 * что она умеет провалиться, ничего не стоит (`grep -q` под pipefail отвечал «ок» на пустой
 * вход, и на это уже попадались). С `HB_FAULT_TEST_NEGATIVE=1` ожидания намеренно неверные,
 * и тест ОБЯЗАН вернуть 1. */
static uint32_t maybe_flip(uint32_t kind) {
    const char* neg = getenv("HB_FAULT_TEST_NEGATIVE");
    if (!neg || neg[0] != '1') return kind;
    return kind == HB_FAULT_KIND_DIVIDE ? HB_FAULT_KIND_NULL_EXEC : HB_FAULT_KIND_DIVIDE;
}

int main(void) {
    /* mov eax,0 ; mov ecx,0 ; div ecx      -> #DE */
    static const uint8_t div0[] = { 0xb8,0,0,0,0, 0xb9,0,0,0,0, 0xf7,0xf1 };
    /* mov eax,0 ; call rax                 -> исполнение по нулю */
    static const uint8_t call0[] = { 0xb8,0,0,0,0, 0xff,0xd0 };
    /* add rax,rbx                          -> контроль: отказа нет */
    static const uint8_t plain[] = { 0x48,0x01,0xd8 };

    printf("сторож природы отказа (итерация 772)\n");
    for (int b = 0; b < 2; b++) {
        hb_backend_t backend = b ? HB_BACKEND_JIT : HB_BACKEND_INTERP;
        check("деление на ноль", div0, sizeof(div0), backend,
              HB_ERR_EXEC_FAULT, maybe_flip(HB_FAULT_KIND_DIVIDE));
        check("вызов по нулю", call0, sizeof(call0), backend,
              HB_ERR_EXEC_FAULT, maybe_flip(HB_FAULT_KIND_NULL_EXEC));
        check("обычная команда (контроль)", plain, sizeof(plain), backend,
              HB_OK, HB_FAULT_KIND_NONE);
    }

    if (g_failures) {
        printf("ОТКАЗОВ: %d\n", g_failures);
        return 1;
    }
    printf("все шесть проверок прошли\n");
    return 0;
}
