/* MacRunner 05.09.2026 — ПРИБОР ТОЧНОСТИ СОСТОЯНИЯ НА ОТКАЗАВШЕЙ КОМАНДЕ, самостоятельный.
 *
 * Зачем отдельно от hb_test_runner. Пробы приёмки линкуются с НОВОЙ библиотекой и не могут
 * быть собраны против прежней (новые символы). Этот прибор пользуется только тем публичным
 * API, который есть в обеих (hb_runtime_run, hb_memory_last_fault, hb_jit_fault_pc_stats),
 * и потому собирается против libhyperbridge.a ЛЮБОЙ сборки. Одна и та же программа против
 * прежней и новой библиотеки — это и есть отрицательный контроль: прежняя обязана дать
 * ДРУГИЕ числа там, где схема отката была неточной.
 *
 * Три сценария, каждый печатает числа, а не статус:
 *   x64-signal   add [rbx],1 ; push rax ; mov rcx,[rdx] (отказ) ; mov [rbx],7 ; ret
 *                гейты нативной памяти ВКЛ -> отказ приходит сигналом из выпущенного кода
 *                ожидание: ячейка=1 (не 2: add один раз), rsp=rsp0-8, pc=+5, rcx нетронут
 *   x64-helper   тот же блок, нативная память ВЫКЛ -> отказ программный, из помощника
 *   i386-push    push ebx при неотображённом стеке (нативный push i386)
 *                ожидание: esp=esp0 (не esp0-4), pc=вход
 *
 * Сборка (из engine/hyperbridge, против любой libhyperbridge.a):
 *   /usr/bin/clang -O1 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/fault_precision_probe.c libhyperbridge.a -o tests/fault_precision_probe
 *   MACRUNNER_HB_MEM_SEGV_JIT_DOOR=1 ./tests/fault_precision_probe
 * Код выхода 0 = все ожидания сошлись; 1 = есть расхождения (они напечатаны).
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

static int g_bad;

static void check(const char* what, unsigned long long got, unsigned long long want) {
    int ok = got == want;
    printf("  %-34s %s  получено=%#llx  ожидание=%#llx\n", what, ok ? "ок  " : "РАСХ", got, want);
    if (!ok) g_bad++;
}

static const uint8_t code_x64[] = {
    0x48, 0x83, 0x03, 0x01,                   /* 0: add qword [rbx], 1 */
    0x50,                                     /* 4: push rax */
    0x48, 0x8b, 0x0a,                         /* 5: mov rcx, [rdx]  <- отказ */
    0x48, 0xc7, 0x03, 0x07, 0x00, 0x00, 0x00, /* 8: mov qword [rbx], 7 */
    0xc3                                      /* 15: ret */
};

static void scenario_x64(const char* name, int native_mem) {
    uint8_t* scratch = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* codepg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint64_t base, rsp0, cell = 0, slot = 0, ex0 = 0, ex1 = 0, nm = 0, nb = 0, fa = 0;
    size_t fs = 0; int fw = 0, fv = 0;
    hb_decoder_t* dec; hb_ir_func_t* func = NULL; hb_context_t* ctx; hb_exec_result_t out;

    printf("== %s\n", name);
    setenv("MACRUNNER_HB_JIT_DIRECT_MEM", native_mem ? "1" : "0", 1);
    setenv("MACRUNNER_HB_JIT_NATIVE_MEM_IR", native_mem ? "1" : "0", 1);
    setenv("MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS", native_mem ? "1" : "0", 1);
    hb_arm64_codegen_gate_cache_reset();

    memset(scratch, 0, 8192);
    memcpy(codepg, code_x64, sizeof(code_x64));
    base = (uint64_t)(uintptr_t)codepg;
    dec = hb_decoder_create(HB_ARCH_X64, codepg, sizeof(code_x64), base);
    if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func) { printf("  ОСНАСТКА: lift\n"); g_bad++; return; }
    hb_decoder_destroy(dec);
    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    ctx->memory = hb_memory_create(0);
    hb_memory_map(ctx->memory, base, 4096, HB_PERM_READ | HB_PERM_EXEC);
    hb_memory_map(ctx->memory, (hb_gva_t)(uintptr_t)scratch, 8192, HB_PERM_READ | HB_PERM_WRITE);
    rsp0 = (uint64_t)(uintptr_t)scratch + 4096 + 2048;
    ctx->pc = base; ctx->regs.x64.rip = base;
    ctx->regs.x64.rax = 0x1122334455667788ull;
    ctx->regs.x64.rbx = (uint64_t)(uintptr_t)scratch;
    ctx->regs.x64.rcx = 0xC0C0;
    ctx->regs.x64.rdx = 0x70000000ull;
    ctx->regs.x64.rsp = rsp0;
    hb_jit_fault_pc_stats(&ex0, &nm, &nb);
    memset(&out, 0, sizeof(out));
    hb_runtime_run(ctx, func, HB_BACKEND_JIT, &out);
    hb_jit_fault_pc_stats(&ex1, &nm, &nb);
    hb_memory_last_fault(&fa, &fs, &fw, &fv);
    memcpy(&cell, scratch, 8);
    memcpy(&slot, scratch + 4096 + 2048 - 8, 8);
    check("отказ доложен (faulted)", out.faulted, 1);
    check("результат MEMORY_FAULT", (unsigned long long)(long long)out.result, (unsigned long long)(long long)HB_ERR_MEMORY_FAULT);
    check("сигнальный путь (карта ответила)", ex1 - ex0, native_mem ? 1u : 0u);
    check("ячейка [rbx] (add ровно один раз)", cell, 1);
    check("rsp = rsp0 - 8 (push ровно один раз)", ctx->regs.x64.rsp - rsp0, (unsigned long long)-8);
    check("слот стека = rax", slot, 0x1122334455667788ull);
    check("rcx не тронут", ctx->regs.x64.rcx, 0xC0C0);
    check("pc = отказавшая команда (+5)", ctx->pc - base, native_mem ? 5u : 0u);
    check("адрес отказа", fa, 0x70000000ull);
    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    munmap(scratch, 8192); munmap(codepg, 4096);
}

static void scenario_i386_push(void) {
    const uint32_t code_base = 0x7bdd0000u;
    const uint32_t esp0 = 0x71000ff0u;
    uint8_t code[] = { 0x53, 0xc3 };
    uint64_t ex0 = 0, ex1 = 0, nm = 0, nb = 0, fa = 0; size_t fs = 0; int fw = 0, fv = 0;
    hb_decoder_t* dec; hb_ir_func_t* func = NULL; hb_context_t* ctx; hb_exec_result_t out;

    printf("== i386-push (нативный push, стек не отображён)\n");
    dec = hb_decoder_create(HB_ARCH_X86, code, sizeof(code), code_base);
    if (!dec || hb_lift_func_x86(dec, &func) != HB_OK || !func) { printf("  ОСНАСТКА: lift\n"); g_bad++; return; }
    hb_decoder_destroy(dec);
    ctx = hb_context_create(HB_ARCH_X86, HB_BACKEND_JIT);
    ctx->memory = hb_memory_create(0);
    hb_memory_guest32_map(ctx->memory, code_base & ~0xfffu, 4096, HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC);
    hb_memory_write(ctx->memory, code_base, code, sizeof(code));
    ctx->pc = code_base; ctx->regs.x86.eip = code_base;
    ctx->regs.x86.esp = esp0; ctx->regs.x86.ebx = 0xdeadbeefu;
    hb_jit_fault_pc_stats(&ex0, &nm, &nb);
    memset(&out, 0, sizeof(out));
    hb_runtime_run(ctx, func, HB_BACKEND_JIT, &out);
    hb_jit_fault_pc_stats(&ex1, &nm, &nb);
    hb_memory_last_fault(&fa, &fs, &fw, &fv);
    check("отказ доложен (faulted)", out.faulted, 1);
    check("результат MEMORY_FAULT", (unsigned long long)(long long)out.result, (unsigned long long)(long long)HB_ERR_MEMORY_FAULT);
    check("сигнальный путь (карта ответила)", ex1 - ex0, 1);
    check("esp не тронут", ctx->regs.x86.esp, esp0);
    check("ebx не тронут", ctx->regs.x86.ebx, 0xdeadbeefu);
    check("pc = вход (сам push)", ctx->pc, code_base);
    check("адрес отказа = esp0-4", fa, esp0 - 4);
    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
}

/* Обработчики SIGSEGV/SIGBUS движок ставит ЛЕНИВО — на первом копировании через окно
 * гостя (hb_memory.c: install_sig_handlers из пути guest32). Самостоятельный двоичный без
 * такого копирования умирает на первом же отказе выпущенного кода (проверено: rc=139, ни
 * одной строки `macrunner-hb-sig`). В приёмке дверь открывалась побочно — прежними x86-пробами.
 * Здесь открываем её явно тем же путём, чтобы прибор не зависел от порядка сценариев и
 * собирался против ЛЮБОЙ сборки библиотеки (публичного установщика нет). */
static void open_signal_door(void) {
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
    setvbuf(stdout, NULL, _IONBF, 0);
    open_signal_door();
    scenario_x64("x64-signal (нативная память: отказ сигналом из выпущенного кода)", 1);
    scenario_x64("x64-helper (память через помощника: отказ программный)", 0);
    scenario_i386_push();
    printf("%s: расхождений=%d\n", g_bad ? "КРАСНЫЙ" : "ЗЕЛЁНЫЙ", g_bad);
    return g_bad ? 1 : 0;
}
