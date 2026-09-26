/*
 * hb_bt_pending_native_test.c — нативный BT/BTS/BTR/BTC при ОТЛОЖЕННЫХ флагах обязан совпадать с
 * интерпретатором: ZF вычисляется из отложенной записи (если его можно и он ещё не вычислен),
 * CF — выбранный бит, запись флагов обнуляется целиком, SF/OF/PF/AF не трогаются.
 *
 * 26.09.2026. До правки при pending весь BT уходил помощнику-интерпретатору (перепись HK: ~19 %
 * его вызовов после нативной SSE). Матрица: pending 0/1, ширина 1/2/4/8, результаты с нулевыми
 * младшими и ненулевыми старшими битами (проверка усечения), ZF в unsupported_mask и в
 * materialized_mask, начальный ZF, значения и номера битов.
 * Выход 0 — всё совпало, 1 — расхождение, 2 — отказ оснастки.
 */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

struct form { const char* name; uint8_t bytes[6]; int len; };
static const struct form FORMS[] = {
    {"bt rax,rcx",  {0x48,0x0f,0xa3,0xc8}, 4}, {"bt eax,ecx", {0x0f,0xa3,0xc8}, 3},
    {"bt eax,5",    {0x0f,0xba,0xe0,0x05}, 4}, {"bt ax,cx",   {0x66,0x0f,0xa3,0xc8}, 4},
    {"bts rax,rcx", {0x48,0x0f,0xab,0xc8}, 4}, {"btr rax,rcx", {0x48,0x0f,0xb3,0xc8}, 4},
    {"btc eax,7",   {0x0f,0xba,0xf8,0x07}, 4}, {"btr eax,ecx", {0x0f,0xb3,0xc8}, 3},
};
#define NFORMS (sizeof(FORMS) / sizeof(FORMS[0]))
static const uint64_t RES[] = { 0, 1, 0x100, 0xff00, 0x10000, 0x100000000ull, 0x8000000000000000ull,
                                0xffffffff00000000ull, 0x80, 0x8000 };
static const uint64_t VAL[] = { 0, 0x20, 0xdeadbeefcafef00dull, 0x8000000000000001ull };
static const uint64_t BIT[] = { 5, 63, 0x47, 0xffffffffffffffc1ull };

int main(void) {
    unsigned long cases = 0, bad = 0, printed = 0;
    hb_context_t* ci = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    hb_context_t* cj = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_memory_t* mi = hb_memory_create(0);
    hb_memory_t* mj = hb_memory_create(0);
    if (!ci || !cj || !mi || !mj) { printf("ОТКАЗ ОСНАСТКИ: контекст\n"); return 2; }
    ci->memory = mi; cj->memory = mj;
    uint8_t* code = mmap(NULL, 16384 * NFORMS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED || stack == MAP_FAILED) { printf("ОТКАЗ ОСНАСТКИ: mmap\n"); return 2; }
    const hb_perm_t rwx = HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC, rw = HB_PERM_READ | HB_PERM_WRITE;
    if (hb_memory_sync_live_range(mi, (hb_gva_t)(uintptr_t)code, 16384 * NFORMS, rwx) != HB_OK ||
        hb_memory_sync_live_range(mj, (hb_gva_t)(uintptr_t)code, 16384 * NFORMS, rwx) != HB_OK ||
        hb_memory_sync_live_range(mi, (hb_gva_t)(uintptr_t)stack, 65536, rw) != HB_OK ||
        hb_memory_sync_live_range(mj, (hb_gva_t)(uintptr_t)stack, 65536, rw) != HB_OK) {
        printf("ОТКАЗ ОСНАСТКИ: учёт памяти\n"); return 2;
    }
    /* Одна среда JIT на весь тест: hb_runtime_run заводит и сносит её (арена 128 МБ) на КАЖДЫЙ
     * случай — это ~4,5 мс на случай. Каждая форма на своей странице, выпуск переиспользуется. */
    hb_jit_runtime_t* rt = hb_jit_runtime_create(cj);
    if (!rt) { printf("ОТКАЗ ОСНАСТКИ: среда JIT\n"); return 2; }
    for (unsigned f = 0; f < NFORMS; f++) {
        uint8_t* at = code + 16384 * f;
        uint64_t base = (uint64_t)(uintptr_t)at;
        memcpy(at, FORMS[f].bytes, (size_t)FORMS[f].len);
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, at, (size_t)FORMS[f].len, base);
        hb_ir_func_t* func = NULL;
        if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func) { printf("ОТКАЗ ОСНАСТКИ: лифт %s\n", FORMS[f].name); return 2; }
        hb_decoder_destroy(dec);
        for (unsigned cfg = 0; cfg < 2u * 4u * 10u * 4u * 2u; cfg++) {
            const unsigned pending = cfg & 1u, wi = (cfg >> 1) & 3u, ri = (cfg >> 3) % 10u;
            const unsigned masks = (cfg / 80u) & 3u, zf0 = (cfg / 320u) & 1u;
            static const uint8_t W[4] = {1, 2, 4, 8};
            for (unsigned v = 0; v < 4; v++) {
                for (unsigned b = 0; b < 4; b++) {
                    hb_context_t* cs[2] = {ci, cj};
                    hb_exec_result_t o[2];
                    hb_result_t r[2];
                    for (int k = 0; k < 2; k++) {
                        hb_context_t* c = cs[k];
                        c->pc = base; c->regs.x64.rip = base;
                        c->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
                        c->regs.x64.rax = VAL[v]; c->regs.x64.rcx = BIT[b];
                        c->flags.zf = zf0 != 0; c->flags.sf = true; c->flags.cf = zf0 == 0;
                        c->flags.of = false; c->flags.pf = true; c->flags.af = false;
                        memset(&c->lazy_flags, 0, sizeof(c->lazy_flags));
                        if (pending) {
                            c->lazy_flags.pending = true; c->lazy_flags.kind = HB_LAZY_FLAGS_SUB;
                            c->lazy_flags.width = W[wi]; c->lazy_flags.lhs = RES[ri] + 3;
                            c->lazy_flags.rhs = 3; c->lazy_flags.result = RES[ri];
                            c->lazy_flags.valid_mask = 0x3f;
                            c->lazy_flags.unsupported_mask = (masks & 1u) ? HB_FLAG_BIT_ZF : 0;
                            c->lazy_flags.valid_mask &= ~c->lazy_flags.unsupported_mask;
                            c->lazy_flags.materialized_mask = (masks & 2u) ? HB_FLAG_BIT_ZF : 0;
                        }
                        memset(&o[k], 0, sizeof(o[k]));
                        r[k] = k ? hb_jit_runtime_run(rt, func, &o[k]) : hb_runtime_run(c, func, HB_BACKEND_INTERP, &o[k]);
                    }
                    cases++;
                    if (r[0] != r[1] || o[0].result != o[1].result || ci->pc != cj->pc ||
                        ci->regs.x64.rax != cj->regs.x64.rax || ci->regs.x64.rcx != cj->regs.x64.rcx ||
                        memcmp(&ci->flags, &cj->flags, sizeof(ci->flags)) != 0 ||
                        memcmp(&ci->lazy_flags, &cj->lazy_flags, sizeof(ci->lazy_flags)) != 0) {
                        bad++;
                        if (printed++ < 20)
                            printf("НАРУШЕНИЕ %-12s pending=%u w=%u res=%016llx masks=%u zf0=%u rax=%016llx bit=%llx | "
                                   "interp zf%d cf%d rax=%016llx lazy.p=%d | jit zf%d cf%d rax=%016llx lazy.p=%d\n",
                                   FORMS[f].name, pending, W[wi], (unsigned long long)RES[ri], masks, zf0,
                                   (unsigned long long)VAL[v], (unsigned long long)BIT[b],
                                   ci->flags.zf, ci->flags.cf, (unsigned long long)ci->regs.x64.rax, ci->lazy_flags.pending,
                                   cj->flags.zf, cj->flags.cf, (unsigned long long)cj->regs.x64.rax, cj->lazy_flags.pending);
                    }
                }
            }
        }
        /* func не освобождается: среда JIT держит выпуск по адресу гостя до конца теста. */
    }
    hb_jit_runtime_destroy(rt);
    printf("случаев=%lu расхождений=%lu\nTOTAL_BAD=%lu\n", cases, bad, bad);
    return bad ? 1 : 0;
}
