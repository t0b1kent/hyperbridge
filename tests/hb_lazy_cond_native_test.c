/*
 * hb_lazy_cond_native_test.c — условие из отложенных флагов, посчитанное выпущенным кодом, обязано
 * совпадать с интерпретатором (hb_flags_eval_cond): Jcc, CMOVcc (32/64/16 бит) и SETcc, все 16
 * условий x86, все виды записи и ширины.
 *
 * 26.09.2026. До правки общий путь Jcc звал hb_jit_helper_eval_cond_lazy на каждый переход, не
 * слитый с производителем в том же блоке, а CMOVcc/SETcc — свои помощники (179 из 334 отсчётов
 * hb_lazy_flags_materialize в профиле HK). Матрица: запись не отложена (шесть байтов флагов) либо
 * отложена с видом ADD/SUB/CMP/AND/OR/XOR/TEST (родной путь) и INC/SHL/ADC (ветвь помощника),
 * ширины 1/2/4/8, операнды с мусором ВЫШЕ ширины (прижатие обязано его отбросить), граничные
 * значения знака и переноса. Вариант «переопределено»: CF и AF уже лежат в ctx->flags поверх
 * записи (materialized_mask — так пишет родной BMI); из операндов записи их считать нельзя.
 * Сравниваются выбранная ветвь (pc), все 16 регистров и материализованные флаги.
 *
 * Отрицательные контроли: MACRUNNER_HB_TEST_LAZY_COND_FLIP=1 (перенос ADD вместо заёма SUB) обязан
 * дать расхождения; MACRUNNER_HB_NATIVE_LAZY_COND=0 — тест обязан сообщить, что родного выпуска не
 * было. HB_LAZY_COND_QUICK=1 — 9 значений (make test), =2 — 4 значения (контрольная рука).
 * Среда JIT одна на весь прогон: hb_runtime_run заводит и сносит её (арена 128 МБ) на КАЖДЫЙ случай.
 * Выход 0 — всё совпало и родной выпуск был, 1 — расхождение, 2 — отказ оснастки.
 */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

extern uint64_t hb_codegen_native_lazy_cond_emitted(void) __attribute__((weak));
extern uint64_t hb_codegen_native_cmov_setcc_emitted(void) __attribute__((weak));
static uint64_t cond_count(void) { return hb_codegen_native_lazy_cond_emitted ? hb_codegen_native_lazy_cond_emitted() : 0; }
static uint64_t cmov_count(void) { return hb_codegen_native_cmov_setcc_emitted ? hb_codegen_native_cmov_setcc_emitted() : 0; }

static uint64_t V[] = { 0, 1, 2, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000u,
                        0xffffffffu, 0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffffffffffffull,
                        0xdeadbeef00000080ull, 0x1234567800008000ull, 0xa5a5a5a5a5a5a5a5ull };
static unsigned NV = sizeof(V) / sizeof(V[0]);
static const hb_lazy_flags_kind_t K[] = { HB_LAZY_FLAGS_ADD, HB_LAZY_FLAGS_SUB, HB_LAZY_FLAGS_CMP,
                                          HB_LAZY_FLAGS_AND, HB_LAZY_FLAGS_OR, HB_LAZY_FLAGS_XOR,
                                          HB_LAZY_FLAGS_TEST, HB_LAZY_FLAGS_INC, HB_LAZY_FLAGS_SHL,
                                          HB_LAZY_FLAGS_ADC };
#define NK (sizeof(K) / sizeof(K[0]))

/* cc_at — байт кода условия, cc_base — его основа; nv_max — сколько значений брать (CMOVcc/SETcc
 * проверяют обвязку выбора и записи, а разбор условия общий с Jcc — ему полная матрица). */
struct form { const char* name; uint8_t bytes[4]; int len; int cc_at; uint8_t cc_base; unsigned nv_max; int cmov; };
static const struct form FORMS[] = {
    {"jcc +0x10",      {0x70, 0x10},             2, 0, 0x70, 99, 0},
    {"cmovcc eax,ebx", {0x0f, 0x40, 0xc3},       3, 1, 0x40, 5,  1},
    {"cmovcc rax,rbx", {0x48, 0x0f, 0x40, 0xc3}, 4, 2, 0x40, 5,  1},
    {"cmovcc ax,bx",   {0x66, 0x0f, 0x40, 0xc3}, 4, 2, 0x40, 5,  1},
    {"setcc cl",       {0x0f, 0x90, 0xc1},       3, 1, 0x90, 5,  1},
};
#define NFORMS (sizeof(FORMS) / sizeof(FORMS[0]))

/* Результат записи ровно как у производителя: без этого SUB с result != lhs-rhs был бы нечестной записью. */
static uint64_t kind_result(hb_lazy_flags_kind_t k, uint64_t a, uint64_t b) {
    switch (k) {
        case HB_LAZY_FLAGS_ADD: return a + b;
        case HB_LAZY_FLAGS_SUB: case HB_LAZY_FLAGS_CMP: return a - b;
        case HB_LAZY_FLAGS_AND: case HB_LAZY_FLAGS_TEST: return a & b;
        case HB_LAZY_FLAGS_OR: return a | b;
        case HB_LAZY_FLAGS_XOR: return a ^ b;
        case HB_LAZY_FLAGS_INC: return a + 1;
        case HB_LAZY_FLAGS_SHL: return a << (b & 7);
        case HB_LAZY_FLAGS_ADC: return a + b + 1;
        default: return 0;
    }
}

int main(void) {
    unsigned long cases = 0, bad = 0;
    const char* quick = getenv("HB_LAZY_COND_QUICK");
    if (quick && *quick == '2') {                       /* контрольная рука: 0 1 80 8000000000000000 */
        static const uint64_t Q2[] = { 0, 1, 0x80, 0x8000000000000000ull };
        memcpy(V, Q2, sizeof(Q2));
        NV = (unsigned)(sizeof(Q2) / sizeof(Q2[0]));
    } else if (quick && *quick) {                       /* 0 1 7f 80 ff 8000 ffffffff 8000000000000000 … */
        static const uint64_t Q[] = { 0, 1, 0x7f, 0x80, 0xff, 0x8000, 0xffffffffu, 0x8000000000000000ull,
                                      0xdeadbeef00000080ull };
        memcpy(V, Q, sizeof(Q));
        NV = (unsigned)(sizeof(Q) / sizeof(Q[0]));
    }
    hb_context_t* cs[2] = { hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP),
                            hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT) };
    hb_memory_t* ms[2] = { hb_memory_create(0), hb_memory_create(0) };
    if (!cs[0] || !cs[1] || !ms[0] || !ms[1]) { printf("ОТКАЗ ОСНАСТКИ: контекст\n"); return 2; }
    const size_t code_bytes = 16384u * 16u * NFORMS;
    uint8_t* code = mmap(NULL, code_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED || stack == MAP_FAILED) { printf("ОТКАЗ ОСНАСТКИ: mmap\n"); return 2; }
    for (int k = 0; k < 2; k++) {
        cs[k]->memory = ms[k];
        if (hb_memory_sync_live_range(ms[k], (hb_gva_t)(uintptr_t)code, code_bytes,
                                      HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
            hb_memory_sync_live_range(ms[k], (hb_gva_t)(uintptr_t)stack, 65536, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
            printf("ОТКАЗ ОСНАСТКИ: учёт памяти\n"); return 2;
        }
    }
    hb_jit_runtime_t* rt = hb_jit_runtime_create(cs[1]);
    if (!rt) { printf("ОТКАЗ ОСНАСТКИ: среда JIT\n"); return 2; }
    for (unsigned f = 0; f < NFORMS; f++) {
        const struct form* F = &FORMS[f];
        const unsigned nv = NV < F->nv_max ? NV : F->nv_max;
        const uint64_t cond_before = cond_count(), cmov_before = cmov_count();
        unsigned long form_bad = 0;
        for (unsigned x = 0; x < 16; x++) {                 /* код условия x86: O NO B AE E NE BE A S NS P NP L GE LE G */
            uint8_t* at = code + 16384u * (16u * f + x);
            uint64_t base = (uint64_t)(uintptr_t)at;
            memcpy(at, F->bytes, (size_t)F->len);
            at[F->cc_at] = (uint8_t)(F->cc_base + x);
            hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, at, (size_t)F->len, base);
            hb_ir_func_t* func = NULL;
            if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func) {
                printf("ОТКАЗ ОСНАСТКИ: лифт %s cc=%x\n", F->name, x); return 2;
            }
            hb_decoder_destroy(dec);
            for (unsigned mode = 0; mode <= NK; mode++) {   /* mode == NK: запись не отложена */
                for (unsigned ovr = 0; ovr < 2; ovr++) {    /* 1: CF/AF переопределены поверх записи */
                    if (ovr && mode == NK) continue;
                    for (unsigned w = 0; w < 4; w++) {
                        static const uint8_t W[4] = {1, 2, 4, 8};
                        const unsigned nvm = ovr ? (nv < 4 ? nv : 4) : nv;
                        for (unsigned i = 0; i < nvm; i++) {
                            for (unsigned j = 0; j < nvm; j++) {
                                hb_exec_result_t o[2];
                                for (int k = 0; k < 2; k++) {
                                    hb_context_t* c = cs[k];
                                    c->pc = base; c->regs.x64.rip = base;
                                    for (unsigned r = 0; r < 16; r++)
                                        hb_context_write_reg_value(c, r, 0x0101010101010101ull * (r + 1) ^ 0x8000000000000080ull);
                                    c->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
                                    c->regs.x64.rax = 0x1111222233334444ull ^ (V[i] * 3u);
                                    c->regs.x64.rbx = 0x5555666677778888ull ^ V[j];
                                    c->regs.x64.rcx = 0x99990000aaaa00c3ull ^ (uint64_t)(i * 16u + j);
                                    memset(&c->lazy_flags, 0, sizeof(c->lazy_flags));
                                    c->flags.zf = (V[i] & 1) != 0; c->flags.sf = (V[j] & 1) != 0;
                                    c->flags.cf = (V[i] & 2) != 0; c->flags.of = (V[j] & 2) != 0;
                                    c->flags.pf = (V[i] & 4) != 0; c->flags.af = (V[j] & 4) != 0;
                                    if (mode < NK) {
                                        hb_lazy_flags_note(c, K[mode], (hb_size_t)W[w], V[i], V[j],
                                                           kind_result(K[mode], V[i], V[j]), V[j] & 7);
                                        if (ovr) {          /* как родной BMI: CF и AF уже в ctx->flags */
                                            c->lazy_flags.materialized_mask = HB_FLAG_BIT_CF | HB_FLAG_BIT_AF;
                                            c->flags.cf = ((i + j + w) & 1) != 0;
                                            c->flags.af = (j & 1) != 0;
                                        }
                                    }
                                    memset(&o[k], 0, sizeof(o[k]));
                                    if (k) hb_jit_runtime_run(rt, func, &o[k]);
                                    else hb_runtime_run(c, func, HB_BACKEND_INTERP, &o[k]);
                                }
                                cases++;
                                (void)hb_lazy_flags_materialize_available(cs[0], HB_FLAG_BIT_ALL);
                                (void)hb_lazy_flags_materialize_available(cs[1], HB_FLAG_BIT_ALL);
                                int diff = cs[0]->pc != cs[1]->pc || o[0].result != o[1].result ||
                                           memcmp(&cs[0]->flags, &cs[1]->flags, sizeof(cs[0]->flags)) != 0;
                                int reg_bad = -1;
                                for (unsigned r = 0; r < 16 && reg_bad < 0; r++)
                                    if (hb_context_read_reg_value(cs[0], r) != hb_context_read_reg_value(cs[1], r))
                                        reg_bad = (int)r;
                                if (diff || reg_bad >= 0) {
                                    bad++; form_bad++;
                                    if (bad <= 16)
                                        printf("НАРУШЕНИЕ %s cc=%x вид=%d%s w=%u a=%016llx b=%016llx | interp pc=+%llx | "
                                               "jit pc=+%llx | рег=%d %016llx/%016llx\n",
                                               F->name, x, mode < NK ? (int)K[mode] : -1, ovr ? " (CF поверх)" : "",
                                               W[w], (unsigned long long)V[i], (unsigned long long)V[j],
                                               (unsigned long long)(cs[0]->pc - base), (unsigned long long)(cs[1]->pc - base),
                                               reg_bad, reg_bad >= 0 ? (unsigned long long)hb_context_read_reg_value(cs[0], (uint64_t)reg_bad) : 0ull,
                                               reg_bad >= 0 ? (unsigned long long)hb_context_read_reg_value(cs[1], (uint64_t)reg_bad) : 0ull);
                                }
                            }
                        }
                    }
                }
            }
            /* func не освобождается: среда JIT держит выпуск по адресу гостя до конца прогона. */
        }
        const int native = F->cmov ? cmov_count() != cmov_before : cond_count() != cond_before;
        printf("%-16s значений=%u расхождений=%lu%s\n", F->name, nv, form_bad, native ? "" : "  НЕ НАТИВНО");
    }
    hb_jit_runtime_destroy(rt);
    printf("случаев=%lu расхождений=%lu родных_условий=%llu родных_cmov_setcc=%llu\n", cases, bad,
           (unsigned long long)cond_count(), (unsigned long long)cmov_count());
    if (cond_count() == 0) { printf("НАРУШЕНИЕ: родной выпуск условия не состоялся ни разу\n"); bad++; }
    if (cmov_count() == 0) { printf("НАРУШЕНИЕ: родной выпуск CMOVcc/SETcc не состоялся ни разу\n"); bad++; }
    printf("TOTAL_BAD=%lu\n", bad);
    return bad ? 1 : 0;
}
