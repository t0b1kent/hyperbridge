/*
 * hb_sse_fp_native_test.c — нативный выпуск SSE-арифметики обязан совпадать с интерпретатором
 * бит в бит на ОСОБЫХ значениях: ±0, денормали, ±inf, QNaN/SNaN с полезной нагрузкой и знаком,
 * границы int32/int64, пары NaN во всех сочетаниях.
 *
 * 26.09.2026. Выпуск (MACRUNNER_HB_NATIVE_SSE_FP, умолчание 1) заменил вызов помощника для
 * ADDSS/SUBSS/MULSS/DIVSS/MINSS/MAXSS (и формы SD, и упакованные PS и PD), COMISS/UCOMISS/COMISD/UCOMISD,
 * CVTTSS2SI/CVTTSD2SI. Случайный разностный стенд особые значения почти не порождает, поэтому
 * здесь — матрица. Эталон — интерпретатор этого же ядра.
 *
 * Сравниваются: xmm0..3, rax, шесть флагов, вся структура ленивых флагов, pc, итог.
 * Отрицательный контроль: MACRUNNER_HB_TEST_SSE_FP_NO_SLOW=1 снимает медленный путь по NaN —
 * тест обязан покраснеть (выбор NaN у ARM и у интерпретатора разный).
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
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

static const uint32_t F32[] = {
    0x00000000u, 0x80000000u, 0x00000001u, 0x80000001u, 0x007fffffu, 0x807fffffu,
    0x00800000u, 0x80800000u, 0x3f800000u, 0xbf800000u, 0x3fc00000u, 0xbf000000u,
    0x3f000000u, 0x7f7fffffu, 0xff7fffffu, 0x7f800000u, 0xff800000u, 0x7fc00000u,
    0xffc00000u, 0x7fc12345u, 0xffd54321u, 0x7f800001u, 0x7fa00000u, 0xff800123u,
    0x4f000000u, 0xcf000000u, 0x4effffffu, 0xcf000001u, 0x4f32d05eu, 0xcf32d05eu,
    0x5f000000u, 0xdf000000u, 0x5effffffu, 0x40490fdbu,
};
static const uint64_t F64[] = {
    0x0000000000000000ull, 0x8000000000000000ull, 0x0000000000000001ull, 0x800fffffffffffffull,
    0x0010000000000000ull, 0x3ff0000000000000ull, 0xbff8000000000000ull, 0x3fe0000000000000ull,
    0x7fefffffffffffffull, 0xffefffffffffffffull, 0x7ff0000000000000ull, 0xfff0000000000000ull,
    0x7ff8000000000000ull, 0xfff8000000000000ull, 0x7ff8000000012345ull, 0xfffc000000054321ull,
    0x7ff0000000000001ull, 0x7ff4000000000000ull, 0xfff0000000000123ull,
    0x41dfffffffc00000ull, 0xc1e0000000000000ull, 0x41e0000000000000ull, 0xc1e0000000200000ull,
    0x43e0000000000000ull, 0xc3e0000000000000ull, 0x43dfffffffffffffull, 0x400921fb54442d18ull,
};
#define NF32 (sizeof(F32) / sizeof(F32[0]))
#define NF64 (sizeof(F64) / sizeof(F64[0]))

struct form { const char* name; uint8_t bytes[8]; int len; int dbl; int mem; int packed; };
static const struct form FORMS[] = {
    {"addss xmm0,xmm1", {0xf3,0x0f,0x58,0xc1}, 4, 0, 0, 0}, {"subss xmm0,xmm1", {0xf3,0x0f,0x5c,0xc1}, 4, 0, 0, 0},
    {"mulss xmm0,xmm1", {0xf3,0x0f,0x59,0xc1}, 4, 0, 0, 0}, {"divss xmm0,xmm1", {0xf3,0x0f,0x5e,0xc1}, 4, 0, 0, 0},
    {"minss xmm0,xmm1", {0xf3,0x0f,0x5d,0xc1}, 4, 0, 0, 0}, {"maxss xmm0,xmm1", {0xf3,0x0f,0x5f,0xc1}, 4, 0, 0, 0},
    {"addsd xmm0,xmm1", {0xf2,0x0f,0x58,0xc1}, 4, 1, 0, 0}, {"subsd xmm0,xmm1", {0xf2,0x0f,0x5c,0xc1}, 4, 1, 0, 0},
    {"mulsd xmm0,xmm1", {0xf2,0x0f,0x59,0xc1}, 4, 1, 0, 0}, {"divsd xmm0,xmm1", {0xf2,0x0f,0x5e,0xc1}, 4, 1, 0, 0},
    {"minsd xmm0,xmm1", {0xf2,0x0f,0x5d,0xc1}, 4, 1, 0, 0}, {"maxsd xmm0,xmm1", {0xf2,0x0f,0x5f,0xc1}, 4, 1, 0, 0},
    {"addss xmm0,[rdx]", {0xf3,0x0f,0x58,0x02}, 4, 0, 1, 0}, {"subss xmm0,[rdx]", {0xf3,0x0f,0x5c,0x02}, 4, 0, 1, 0},
    {"mulss xmm0,[rdx]", {0xf3,0x0f,0x59,0x02}, 4, 0, 1, 0}, {"maxss xmm0,[rdx]", {0xf3,0x0f,0x5f,0x02}, 4, 0, 1, 0},
    {"mulsd xmm0,[rdx]", {0xf2,0x0f,0x59,0x02}, 4, 1, 1, 0}, {"addsd xmm0,[rdx]", {0xf2,0x0f,0x58,0x02}, 4, 1, 1, 0},
    {"comiss xmm0,xmm1", {0x0f,0x2f,0xc1}, 3, 0, 0, 0}, {"ucomiss xmm0,xmm1", {0x0f,0x2e,0xc1}, 3, 0, 0, 0},
    {"comiss xmm0,[rdx]", {0x0f,0x2f,0x02}, 3, 0, 1, 0}, {"comisd xmm0,xmm1", {0x66,0x0f,0x2f,0xc1}, 4, 1, 0, 0},
    {"ucomisd xmm0,xmm1", {0x66,0x0f,0x2e,0xc1}, 4, 1, 0, 0}, {"comisd xmm0,[rdx]", {0x66,0x0f,0x2f,0x02}, 4, 1, 1, 0},
    {"cvttss2si eax,xmm1", {0xf3,0x0f,0x2c,0xc1}, 4, 0, 0, 0}, {"cvttss2si rax,xmm1", {0xf3,0x48,0x0f,0x2c,0xc1}, 5, 0, 0, 0},
    {"cvttsd2si eax,xmm1", {0xf2,0x0f,0x2c,0xc1}, 4, 1, 0, 0}, {"cvttsd2si rax,xmm1", {0xf2,0x48,0x0f,0x2c,0xc1}, 5, 1, 0, 0},
    {"cvttss2si eax,[rdx]", {0xf3,0x0f,0x2c,0x02}, 4, 0, 1, 0}, {"cvttsd2si rax,[rdx]", {0xf2,0x48,0x0f,0x2c,0x02}, 5, 1, 1, 0},
    {"addps xmm0,xmm1", {0x0f,0x58,0xc1}, 3, 0, 0, 1}, {"mulps xmm0,xmm1", {0x0f,0x59,0xc1}, 3, 0, 0, 1},
    {"subps xmm0,xmm1", {0x0f,0x5c,0xc1}, 3, 0, 0, 1}, {"divps xmm0,xmm1", {0x0f,0x5e,0xc1}, 3, 0, 0, 1},
    {"minps xmm0,xmm1", {0x0f,0x5d,0xc1}, 3, 0, 0, 1}, {"maxps xmm0,xmm1", {0x0f,0x5f,0xc1}, 3, 0, 0, 1},
    {"addpd xmm0,xmm1", {0x66,0x0f,0x58,0xc1}, 4, 1, 0, 1}, {"mulpd xmm0,xmm1", {0x66,0x0f,0x59,0xc1}, 4, 1, 0, 1},
    {"maxpd xmm0,xmm1", {0x66,0x0f,0x5f,0xc1}, 4, 1, 0, 1}, {"addps xmm0,[rdx]", {0x0f,0x58,0x02}, 3, 0, 1, 1},
    {"mulps xmm0,[rdx]", {0x0f,0x59,0x02}, 3, 0, 1, 1}, {"minps xmm0,[rdx]", {0x0f,0x5d,0x02}, 3, 0, 1, 1},
    /* вторая партия: преобразования и перестановки дорожек */
    {"cvtss2sd xmm0,xmm1", {0xf3,0x0f,0x5a,0xc1}, 4, 0, 0, 0}, {"cvtsd2ss xmm0,xmm1", {0xf2,0x0f,0x5a,0xc1}, 4, 1, 0, 0},
    {"cvtss2sd xmm0,[rdx]", {0xf3,0x0f,0x5a,0x02}, 4, 0, 1, 0}, {"cvtsd2ss xmm0,[rdx]", {0xf2,0x0f,0x5a,0x02}, 4, 1, 1, 0},
    {"cvtsi2ss xmm0,eax", {0xf3,0x0f,0x2a,0xc0}, 4, 0, 0, 0}, {"cvtsi2ss xmm0,rax", {0xf3,0x48,0x0f,0x2a,0xc0}, 5, 1, 0, 0},
    {"cvtsi2sd xmm0,eax", {0xf2,0x0f,0x2a,0xc0}, 4, 0, 0, 0}, {"cvtsi2sd xmm0,rax", {0xf2,0x48,0x0f,0x2a,0xc0}, 5, 1, 0, 0},
    {"cvtsi2ss xmm0,[rdx]", {0xf3,0x0f,0x2a,0x02}, 4, 0, 1, 0}, {"cvtsi2sd xmm0,qword [rdx]", {0xf2,0x48,0x0f,0x2a,0x02}, 5, 1, 1, 0},
    {"cvtdq2pd xmm0,xmm1", {0xf3,0x0f,0xe6,0xc1}, 4, 0, 0, 1}, {"cvtps2pd xmm0,xmm1", {0x0f,0x5a,0xc1}, 3, 0, 0, 1},
    {"cvtpd2ps xmm0,xmm1", {0x66,0x0f,0x5a,0xc1}, 4, 1, 0, 1}, {"cvtdq2ps xmm0,xmm1", {0x0f,0x5b,0xc1}, 3, 0, 0, 1},
    {"cvtdq2pd xmm0,[rdx]", {0xf3,0x0f,0xe6,0x02}, 4, 0, 1, 1}, {"cvtpd2ps xmm0,[rdx]", {0x66,0x0f,0x5a,0x02}, 4, 1, 1, 1},
    {"pshufd xmm0,xmm1,0x1b", {0x66,0x0f,0x70,0xc1,0x1b}, 5, 0, 0, 1}, {"pshufd xmm0,[rdx],0x4e", {0x66,0x0f,0x70,0x02,0x4e}, 5, 0, 1, 1},
    {"pshufd xmm0,xmm0,0x00", {0x66,0x0f,0x70,0xc0,0x00}, 5, 0, 0, 1}, {"pshuflw xmm0,xmm1,0xb1", {0xf2,0x0f,0x70,0xc1,0xb1}, 5, 0, 0, 1},
    {"pshufhw xmm0,xmm1,0x1b", {0xf3,0x0f,0x70,0xc1,0x1b}, 5, 0, 0, 1}, {"shufps xmm0,xmm1,0x4e", {0x0f,0xc6,0xc1,0x4e}, 4, 0, 0, 1},
    {"shufps xmm0,[rdx],0xe4", {0x0f,0xc6,0x02,0xe4}, 4, 0, 1, 1}, {"shufpd xmm0,xmm1,0x2", {0x66,0x0f,0xc6,0xc1,0x02}, 5, 1, 0, 1},
};
#define NFORMS (sizeof(FORMS) / sizeof(FORMS[0]))

static void* alloc_live(hb_memory_t* mem, void* want, size_t size, hb_perm_t perm) {
    void* p = want ? want : mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (hb_memory_sync_live_range(mem, (hb_gva_t)(uintptr_t)p, size, perm) != HB_OK) return NULL;
    return p;
}

struct arm { hb_context_t* ctx; };

/* Одинаковое начальное состояние: всё, что не относится к случаю, — узнаваемый мусор. */
static void seed(hb_context_t* c, uint64_t base, uint8_t* stack, uint8_t* data,
                 const uint64_t x0[2], const uint64_t x1[2]) {
    c->pc = base; c->regs.x64.rip = base;
    c->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
    c->regs.x64.rax = 0xdeadbeefcafef00dull;
    c->regs.x64.rcx = 0x1111222233334444ull;
    c->regs.x64.rdx = (uint64_t)(uintptr_t)data;
    memcpy(c->regs.x64.xmm[0], x0, 16);
    memcpy(c->regs.x64.xmm[1], x1, 16);
    c->regs.x64.xmm[2][0] = 0x2222222222222222ull; c->regs.x64.xmm[2][1] = 0x2323232323232323ull;
    c->regs.x64.xmm[3][0] = 0x3333333333333333ull; c->regs.x64.xmm[3][1] = 0x3434343434343434ull;
    c->flags.zf = true; c->flags.sf = false; c->flags.cf = true;
    c->flags.of = true; c->flags.pf = false; c->flags.af = true;
    memset(&c->lazy_flags, 0, sizeof(c->lazy_flags));
    c->lazy_flags.pending = true; c->lazy_flags.kind = HB_LAZY_FLAGS_ADD; c->lazy_flags.width = 4;
    c->lazy_flags.lhs = 7; c->lazy_flags.rhs = 9; c->lazy_flags.result = 16;
    c->lazy_flags.valid_mask = 0x3f;
}

int main(void) {
    const int no_slow = getenv("MACRUNNER_HB_TEST_SSE_FP_NO_SLOW") != NULL;
    unsigned long cases = 0, bad = 0, printed = 0;
    hb_context_t* ci = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    hb_context_t* cj = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_memory_t* mi = hb_memory_create(0);
    hb_memory_t* mj = hb_memory_create(0);
    if (!ci || !cj || !mi || !mj) { printf("ОТКАЗ ОСНАСТКИ: контекст\n"); return 2; }
    ci->memory = mi; cj->memory = mj;
    uint8_t* code = mmap(NULL, 16384 * NFORMS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* data = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED || stack == MAP_FAILED || data == MAP_FAILED) { printf("ОТКАЗ ОСНАСТКИ: mmap\n"); return 2; }
    const hb_perm_t rwx = HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC, rw = HB_PERM_READ | HB_PERM_WRITE;
    if (!alloc_live(mi, code, 16384 * NFORMS, rwx) || !alloc_live(mj, code, 16384 * NFORMS, rwx) ||
        !alloc_live(mi, stack, 65536, rw) || !alloc_live(mj, stack, 65536, rw) ||
        !alloc_live(mi, data, 16384, rw) || !alloc_live(mj, data, 16384, rw)) {
        printf("ОТКАЗ ОСНАСТКИ: учёт памяти\n"); return 2;
    }
    for (unsigned f = 0; f < NFORMS; f++) {
        const struct form* fm = &FORMS[f];
        uint8_t* at = code + 16384 * f;            /* у каждой формы своя страница: без SMC-выселений */
        uint64_t base = (uint64_t)(uintptr_t)at;
        memcpy(at, fm->bytes, (size_t)fm->len);
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, at, (size_t)fm->len, base);
        hb_ir_func_t* func = NULL;
        if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func) { printf("ОТКАЗ ОСНАСТКИ: лифт %s\n", fm->name); return 2; }
        hb_decoder_destroy(dec);
        const unsigned n = fm->dbl ? (unsigned)NF64 : (unsigned)NF32;
        extern uint64_t hb_codegen_native_sse_fp_emitted(void);
        const uint64_t native_before = hb_codegen_native_sse_fp_emitted();
        for (unsigned i = 0; i < n; i++) {
            for (unsigned j = 0; j < n; j++) {
                uint64_t x0[2], x1[2];
                if (fm->dbl) {
                    x0[0] = F64[i]; x1[0] = F64[j];
                    x0[1] = fm->packed ? F64[(i + 3) % n] : 0x5a5a5a5a5a5a5a5aull;
                    x1[1] = fm->packed ? F64[(j + 5) % n] : 0xa5a5a5a5a5a5a5a5ull;
                } else {
                    x0[0] = (uint64_t)F32[i] | ((uint64_t)(fm->packed ? F32[(i + 1) % n] : 0x5a5a5a5au) << 32);
                    x1[0] = (uint64_t)F32[j] | ((uint64_t)(fm->packed ? F32[(j + 2) % n] : 0xa5a5a5a5u) << 32);
                    x0[1] = (uint64_t)(fm->packed ? F32[(i + 3) % n] : 0x6b6b6b6bu) |
                            ((uint64_t)(fm->packed ? F32[(i + 7) % n] : 0x6c6c6c6cu) << 32);
                    x1[1] = (uint64_t)(fm->packed ? F32[(j + 11) % n] : 0xb6b6b6b6u) |
                            ((uint64_t)(fm->packed ? F32[(j + 13) % n] : 0xc6c6c6c6u) << 32);
                }
                memcpy(data, x1, 16);                   /* форма с памятью читает второй операнд отсюда */
                hb_exec_result_t oi, oj;
                memset(&oi, 0, sizeof(oi)); memset(&oj, 0, sizeof(oj));
                seed(ci, base, stack, data, x0, x1);
                seed(cj, base, stack, data, x0, x1);
                if (strstr(fm->name, "cvtsi2") && !fm->mem)          /* целый источник — из rax */
                    ci->regs.x64.rax = cj->regs.x64.rax = x1[0];
                hb_result_t ri = hb_runtime_run(ci, func, HB_BACKEND_INTERP, &oi);
                hb_result_t rj = hb_runtime_run(cj, func, HB_BACKEND_JIT, &oj);
                cases++;
                int diff = ri != rj || oi.result != oj.result || ci->pc != cj->pc ||
                           memcmp(ci->regs.x64.xmm, cj->regs.x64.xmm, sizeof(uint64_t) * 8) != 0 ||
                           ci->regs.x64.rax != cj->regs.x64.rax ||
                           memcmp(&ci->flags, &cj->flags, sizeof(ci->flags)) != 0 ||
                           memcmp(&ci->lazy_flags, &cj->lazy_flags, sizeof(ci->lazy_flags)) != 0;
                if (diff) {
                    bad++;
                    if (printed++ < 24)
                        printf("НАРУШЕНИЕ %-20s a=%016llx:%016llx b=%016llx:%016llx | interp xmm0=%016llx:%016llx "
                               "rax=%016llx zf%d pf%d cf%d | jit xmm0=%016llx:%016llx rax=%016llx zf%d pf%d cf%d | r=%d/%d\n",
                               fm->name, (unsigned long long)x0[1], (unsigned long long)x0[0],
                               (unsigned long long)x1[1], (unsigned long long)x1[0],
                               (unsigned long long)ci->regs.x64.xmm[0][1], (unsigned long long)ci->regs.x64.xmm[0][0],
                               (unsigned long long)ci->regs.x64.rax, ci->flags.zf, ci->flags.pf, ci->flags.cf,
                               (unsigned long long)cj->regs.x64.xmm[0][1], (unsigned long long)cj->regs.x64.xmm[0][0],
                               (unsigned long long)cj->regs.x64.rax, cj->flags.zf, cj->flags.pf, cj->flags.cf,
                               (int)ri, (int)rj);
                }
            }
        }
        if (hb_codegen_native_sse_fp_emitted() == native_before)
            printf("НЕ НАТИВНО: %s — выпуск ушёл помощнику (совпадение проверено, скорость нет)\n", fm->name);
        hb_ir_func_destroy(func);
    }
    extern uint64_t hb_codegen_native_sse_fp_emitted(void);
    printf("случаев=%lu расхождений=%lu нативных выпусков=%llu медленный_путь=%s\n", cases, bad,
           (unsigned long long)hb_codegen_native_sse_fp_emitted(), no_slow ? "СНЯТ (контроль)" : "есть");
    if (hb_codegen_native_sse_fp_emitted() == 0) { printf("НАРУШЕНИЕ: нативный выпуск не состоялся ни разу\n"); bad++; }
    printf("TOTAL_BAD=%lu\n", bad);
    return bad ? 1 : 0;
}
