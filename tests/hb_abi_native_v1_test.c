/* MacRunner 14.09.2026, независимая линия HyperBridge — ТИПИЗИРОВАННАЯ ГРАНИЦА С НАТИВНЫМ КОДОМ
 * (пункт 4 карты паритета FEX -> HyperBridge). Оракул — КОМПИЛЯТОР ХОСТА: свидетели — обычные
 * функции C, которые записывают, что до них дошло; повозка грузит регистры/стек из образа
 * AAPCS64 и зовёт их через ассемблерную заглушку.
 *
 * СТРОКИ:
 *   К   контроль оснастки: образ «по индексу» (как грузит клей Wine: x_i <- слот i, d_i <- XMM_i)
 *       на СМЕШАННОЙ подписи ОБЯЗАН разойтись со свидетелем — иначе повозка не видит дефекта
 *       (отказ оснастки, код 2). На чисто целой подписи он ОБЯЗАН сойтись (не-пробел карты).
 *   П   понижение hb_abi_native_lower_v1: свидетель видит ровно то, что положил гость, для
 *       целых, смешанных, F32, переполнения регистров (10 целых, 10 плавающих, 9+9 вперемешку).
 *   В   результат: F64/F32/GPR32 собираются в XMM0/RAX по виду с сохранением чужих битов.
 *   О   обратное поднятие hb_abi_native_raise_v1: образ -> описатель v1 -> hb_abi_x64_prepare_v1
 *       кладёт значения в RCX/RDX/R8/R9/XMM/хвост; круг lower(raise(image)) == image.
 *   Х   отказы: неизвестный вид/ширина/версия/цель/счёт, выход не тронут.
 *   С   контракт «свежий вызов против возобновления» (пункт G4): RSP = 8 mod 16 — старый
 *       hb_abi_x64_call ПЕРЕПИСЫВАЕТ кадр (маскирует RSP, кладёт 0xFFFF0000), v1 отказывает и
 *       контекст не трогает. Известные ответы, зафиксированные числом.
 *
 * ГРАНИЦЫ: оракул — ABI Apple arm64; в позициях стека используются только 8-байтные типы
 * (Apple пакует узкие аргументы стека плотно, Windows ARM64 — слотами по 8), а узкие
 * регистровые — только БЕЗЗНАКОВЫЕ (Apple требует расширения вызывающим по знаку, Windows
 * расширяет в вызываемом; на беззнаковых оба сходятся). Агрегаты, HFA/HVA, varargs не
 * проверяются — описатель их отвергает (varargs — по флагу, виды его не выдают).
 *
 * Сборка: make -C engine/hyperbridge tests/hb_abi_native_v1_test && ./tests/hb_abi_native_v1_test
 */
#include "hb_abi_native_v1.h"
#include "hb_abi.h"
#include "hb_memory.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── заглушка вызова: образ -> x0..x7, d0..d7, стек -> blr ──────────────────────────── */
_Static_assert(offsetof(hb_abi_native_image_v1_t, x) == 0, "x at 0");
_Static_assert(offsetof(hb_abi_native_image_v1_t, d_bits) == 64, "d at 64");
_Static_assert(offsetof(hb_abi_native_image_v1_t, stack) == 128, "stack at 128");
_Static_assert(offsetof(hb_abi_native_image_v1_t, stack_count) == 288, "stack_count at 288");

void hb_test_native_invoke(const hb_abi_native_image_v1_t *image, void *fn,
                           uint64_t *x0_out, uint64_t *d0_out);
__asm__(
    ".text\n"
    ".globl _hb_test_native_invoke\n"
    ".p2align 2\n"
    "_hb_test_native_invoke:\n"
    "    stp x29, x30, [sp, #-48]!\n"
    "    stp x19, x20, [sp, #16]\n"
    "    stp x21, x22, [sp, #32]\n"
    "    mov x29, sp\n"
    "    mov x19, x0\n"            /* image */
    "    mov x20, x1\n"            /* fn */
    "    mov x21, x2\n"            /* x0_out */
    "    mov x22, x3\n"            /* d0_out */
    "    ldr w9, [x19, #288]\n"    /* stack_count */
    "    lsl x9, x9, #3\n"
    "    add x9, x9, #15\n"
    "    and x9, x9, #-16\n"
    "    sub sp, sp, x9\n"
    "    ldr w10, [x19, #288]\n"
    "    add x11, x19, #128\n"
    "    mov x12, sp\n"
    "1:  cbz w10, 2f\n"
    "    ldr x13, [x11], #8\n"
    "    str x13, [x12], #8\n"
    "    sub w10, w10, #1\n"
    "    b 1b\n"
    "2:  ldp x0, x1, [x19, #0]\n"
    "    ldp x2, x3, [x19, #16]\n"
    "    ldp x4, x5, [x19, #32]\n"
    "    ldp x6, x7, [x19, #48]\n"
    "    ldp d0, d1, [x19, #64]\n"
    "    ldp d2, d3, [x19, #80]\n"
    "    ldp d4, d5, [x19, #96]\n"
    "    ldp d6, d7, [x19, #112]\n"
    "    blr x20\n"
    "    str x0, [x21]\n"
    "    str d0, [x22]\n"
    "    mov sp, x29\n"
    "    ldp x19, x20, [sp, #16]\n"
    "    ldp x21, x22, [sp, #32]\n"
    "    ldp x29, x30, [sp], #48\n"
    "    ret\n"
);

/* ── свидетели: записывают, что до них дошло ─────────────────────────────────────── */
#define MAXP 20
static uint64_t g_seen[MAXP];
static unsigned g_seen_n;
static uint64_t dbits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }
static uint64_t fbits(float f) { uint32_t u; memcpy(&u, &f, 4); return u; }
static double bits_d(uint64_t u) { double d; memcpy(&d, &u, 8); return d; }
#define SEEN_RESET() (g_seen_n = 0, memset(g_seen, 0, sizeof g_seen))
#define SEE_U(v) (g_seen[g_seen_n++] = (v))
#define SEE_D(v) (g_seen[g_seen_n++] = dbits(v))
#define SEE_F(v) (g_seen[g_seen_n++] = fbits(v))

__attribute__((noinline)) static uint64_t w_int4(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{ SEE_U(a); SEE_U(b); SEE_U(c); SEE_U(d); return a ^ b ^ c ^ d; }
__attribute__((noinline)) static uint64_t w_mixed4(uint64_t a, double b, uint64_t c, double d)
{ SEE_U(a); SEE_D(b); SEE_U(c); SEE_D(d); return a + c; }
__attribute__((noinline)) static uint64_t w_f32mix(float a, uint64_t b, float c, uint64_t d)
{ SEE_F(a); SEE_U(b); SEE_F(c); SEE_U(d); return b + d; }
__attribute__((noinline)) static uint64_t w_six(uint64_t a, double b, uint64_t c, double d, uint64_t e, double f)
{ SEE_U(a); SEE_D(b); SEE_U(c); SEE_D(d); SEE_U(e); SEE_D(f); return a + c + e; }
__attribute__((noinline)) static uint64_t w_int10(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                                                  uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, uint64_t a9)
{ SEE_U(a0); SEE_U(a1); SEE_U(a2); SEE_U(a3); SEE_U(a4); SEE_U(a5); SEE_U(a6); SEE_U(a7); SEE_U(a8); SEE_U(a9); return a8 ^ a9; }
__attribute__((noinline)) static double w_f64x10(double a0, double a1, double a2, double a3, double a4,
                                                 double a5, double a6, double a7, double a8, double a9)
{ SEE_D(a0); SEE_D(a1); SEE_D(a2); SEE_D(a3); SEE_D(a4); SEE_D(a5); SEE_D(a6); SEE_D(a7); SEE_D(a8); SEE_D(a9); return a9; }
__attribute__((noinline)) static uint64_t w_over18(uint64_t i0, double f0, uint64_t i1, double f1, uint64_t i2, double f2,
                                                   uint64_t i3, double f3, uint64_t i4, double f4, uint64_t i5, double f5,
                                                   uint64_t i6, double f6, uint64_t i7, double f7, uint64_t i8, double f8)
{ SEE_U(i0); SEE_D(f0); SEE_U(i1); SEE_D(f1); SEE_U(i2); SEE_D(f2); SEE_U(i3); SEE_D(f3); SEE_U(i4); SEE_D(f4);
  SEE_U(i5); SEE_D(f5); SEE_U(i6); SEE_D(f6); SEE_U(i7); SEE_D(f7); SEE_U(i8); SEE_D(f8); return i8; }
__attribute__((noinline)) static uint64_t w_narrow(uint8_t a, uint16_t b, uint32_t c, uint64_t d)
{ SEE_U(a); SEE_U(b); SEE_U(c); SEE_U(d); return (uint64_t)a + b + c; }
__attribute__((noinline)) static uint64_t w_hi5(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{ SEE_U(a); SEE_U(b); SEE_U(c); SEE_U(d); SEE_U(e); return a; }
__attribute__((noinline)) static double w_ret_f64(uint64_t a, double b) { SEE_U(a); SEE_D(b); return b * 2.0 + (double)a; }
__attribute__((noinline)) static float w_ret_f32(float a, uint64_t b) { SEE_F(a); SEE_U(b); return a + (float)b; }
__attribute__((noinline)) static uint32_t w_ret_u32(uint64_t a) { SEE_U(a); return (uint32_t)a + 1u; }

/* ── оснастка ──────────────────────────────────────────────────────────────────────── */
static unsigned g_checks, g_fail;
static const char *g_row = "?";
static int check(int ok, const char *what)
{
    g_checks++;
    if (!ok) { g_fail++; printf("  РАСХОЖДЕНИЕ [%s] %s\n", g_row, what); }
    return ok;
}
static int check_eq(uint64_t want, uint64_t got, const char *what)
{
    int ok = want == got;
    g_checks++;
    if (!ok) { g_fail++; printf("  РАСХОЖДЕНИЕ [%s] %s: ждали 0x%" PRIx64 ", пришло 0x%" PRIx64 "\n", g_row, what, want, got); }
    return ok;
}

enum { PAGE_BYTES = 16384 };
static const uint64_t STACK = UINT64_C(0x600000);
static const uint64_t GARBAGE_HI = UINT64_C(0xCCCCCCCC00000000);

static hb_context_t *new_ctx(void)
{
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    if (!ctx) return NULL;
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory || hb_memory_map_private(ctx->memory, STACK, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        hb_context_destroy(ctx); return NULL;
    }
    memset(&ctx->regs.x64, 0x3c, sizeof(ctx->regs.x64));
    for (unsigned i = 0; i < 16; ++i) {
        ctx->regs.x64.xmm[i][0] = UINT64_C(0xa1b2c3d400001000) + i;
        ctx->regs.x64.xmm[i][1] = UINT64_C(0x5566778800002000) + i;
    }
    /* RSP указывает на адрес возврата, как в клее; хвост по RSP+0x28.. лежит в странице. */
    ctx->regs.x64.rsp = STACK + PAGE_BYTES - 0x400;
    ctx->regs.x64.rip = ctx->pc = UINT64_C(0x1234000);
    return ctx;
}

typedef struct { uint32_t kind; uint32_t width; uint64_t bits; } spec_t;
#define G8(v)  ((spec_t){HB_ABI_X64_GPR_V1, 8, (v)})
#define G4(v)  ((spec_t){HB_ABI_X64_GPR_V1, 4, (v)})
#define G2(v)  ((spec_t){HB_ABI_X64_GPR_V1, 2, (v)})
#define G1(v)  ((spec_t){HB_ABI_X64_GPR_V1, 1, (v)})
#define F8(v)  ((spec_t){HB_ABI_X64_F64_V1, 8, dbits(v)})
#define F4(v)  ((spec_t){HB_ABI_X64_F32_V1, 4, fbits(v)})

static hb_abi_native_sig_v1_t make_sig(const spec_t *s, unsigned n, uint32_t rk, uint32_t rw)
{
    hb_abi_native_sig_v1_t sig;
    memset(&sig, 0, sizeof sig);
    sig.abi_version = HB_ABI_NATIVE_V1;
    sig.struct_size = sizeof sig;
    sig.target_abi = HB_ABI_NATIVE_TARGET_AAPCS64_WIN_V1;
    sig.argument_count = n;
    sig.ret.kind = rk; sig.ret.width_bytes = rw;
    for (unsigned i = 0; i < n; ++i) { sig.args[i].kind = s[i].kind; sig.args[i].width_bytes = s[i].width; }
    return sig;
}

/* Гость кладёт значения по позиционному правилу Win64; в старшие биты F32 — мусор. */
static int guest_place(hb_context_t *ctx, const spec_t *s, unsigned n)
{
    uint64_t *gpr[4] = {&ctx->regs.x64.rcx, &ctx->regs.x64.rdx, &ctx->regs.x64.r8, &ctx->regs.x64.r9};
    for (unsigned i = 0; i < n; ++i) {
        uint64_t bits = s[i].bits;
        if (s[i].width < 8) bits |= (GARBAGE_HI | (UINT64_C(0xCCCCCCCC) << (8 * s[i].width))) & ~((UINT64_C(1) << (8 * s[i].width)) - 1);
        if (i < 4) {
            if (s[i].kind == HB_ABI_X64_GPR_V1) *gpr[i] = bits;
            else ctx->regs.x64.xmm[i][0] = bits;
        } else if (hb_memory_write_u64(ctx->memory, ctx->regs.x64.rsp + 8 + 32 + 8ull * (i - 4), bits) != HB_OK)
            return 0;
    }
    return 1;
}

/* Образ «по индексу» — то, что грузит клей Wine сегодня (macrunner_hb.c:20005-20017, :36615-36626). */
static void same_index_image(const hb_context_t *ctx, unsigned n, hb_abi_native_image_v1_t *img)
{
    const uint64_t gpr[4] = {ctx->regs.x64.rcx, ctx->regs.x64.rdx, ctx->regs.x64.r8, ctx->regs.x64.r9};
    memset(img, 0, sizeof *img);
    for (unsigned i = 0; i < n && i < 8; ++i) {
        uint64_t v = 0;
        if (i < 4) v = gpr[i];
        else hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 8 + 32 + 8ull * (i - 4), &v);
        img->x[i] = v;
        img->d_bits[i] = ctx->regs.x64.xmm[i][0];
    }
    for (unsigned i = 8; i < n; ++i)
        hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp + 8 + 32 + 8ull * (i - 4), &img->stack[img->stack_count++]);
    img->x_count = n < 8 ? n : 8; img->d_count = img->x_count;
}

static unsigned seen_mismatches(const spec_t *s, unsigned n)
{
    unsigned bad = 0;
    for (unsigned i = 0; i < n; ++i) if (g_seen[i] != s[i].bits) bad++;
    return bad;
}

/* Одна строка П: гость кладёт -> lower -> заглушка -> свидетель; сравнить всё. */
static void row_lower(const char *name, const spec_t *s, unsigned n, void *fn, uint32_t rk, uint32_t rw,
                      uint64_t *x0, uint64_t *d0, hb_context_t *ctx)
{
    hb_abi_native_image_v1_t img;
    hb_abi_native_sig_v1_t sig = make_sig(s, n, rk, rw);
    char what[96];
    g_row = name;
    if (!check(guest_place(ctx, s, n), "гость положил аргументы")) return;
    if (!check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK, "lower OK")) return;
    SEEN_RESET();
    hb_test_native_invoke(&img, fn, x0, d0);
    check_eq(n, g_seen_n, "свидетель получил все аргументы");
    for (unsigned i = 0; i < n; ++i) {
        snprintf(what, sizeof what, "аргумент %u (вид %u)", i, s[i].kind);
        check_eq(s[i].bits, g_seen[i], what);
    }
}

int main(void)
{
    hb_context_t *ctx = new_ctx();
    uint64_t x0 = 0, d0 = 0;
    if (!ctx) { printf("ОТКАЗ ОСНАСТКИ: нет контекста\n"); return 2; }

    /* ── К: контроль — образ «по индексу» ──────────────────────────────────────────── */
    {
        const spec_t mixed[4] = {G8(0x1111), F8(2.5), G8(0x3333), F8(4.25)};
        const spec_t ints[4]  = {G8(0xA1), G8(0xB2), G8(0xC3), G8(0xD4)};
        hb_abi_native_image_v1_t img;
        unsigned bad;
        g_row = "К-смешанная";
        guest_place(ctx, mixed, 4);
        same_index_image(ctx, 4, &img);
        SEEN_RESET(); hb_test_native_invoke(&img, (void *)w_mixed4, &x0, &d0);
        bad = seen_mismatches(mixed, 4);
        printf("К   по индексу, f(u64,double,u64,double): расхождений у свидетеля=%u из 4 "
               "(в x1 пришло 0x%" PRIx64 " вместо u64 0x3333; в d0 пришло %g вместо double 2.5, "
               "а 2.5 уехало в d1: %g)\n",
               bad, g_seen[2], bits_d(g_seen[1]), bits_d(g_seen[3]));
        if (bad == 0) { printf("ОТКАЗ ОСНАСТКИ: образ по индексу сошёлся на смешанной подписи — повозка слепа к дефекту\n"); return 2; }
        g_row = "К-целая";
        guest_place(ctx, ints, 4);
        same_index_image(ctx, 4, &img);
        SEEN_RESET(); hb_test_native_invoke(&img, (void *)w_int4, &x0, &d0);
        check_eq(0, seen_mismatches(ints, 4), "по индексу на чисто целой подписи сходится (не-пробел)");
    }

    /* ── П: понижение ───────────────────────────────────────────────────────────────── */
    {
        const spec_t s1[4] = {G8(0x1111), F8(2.5), G8(0x3333), F8(4.25)};
        row_lower("П-смешанная4", s1, 4, (void *)w_mixed4, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);
        check_eq(0x1111 + 0x3333, x0, "результат u64 в x0");

        const spec_t s2[4] = {G8(0xA1), G8(0xB2), G8(0xC3), G8(0xD4)};
        row_lower("П-целая4", s2, 4, (void *)w_int4, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);

        const spec_t s3[4] = {F4(1.5f), G8(0x77), F4(-3.25f), G8(0x88)};
        row_lower("П-F32", s3, 4, (void *)w_f32mix, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);

        const spec_t s4[6] = {G8(1), F8(2.0), G8(3), F8(4.0), G8(5), F8(6.0)};
        row_lower("П-шесть", s4, 6, (void *)w_six, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);
        check_eq(9, x0, "1+3+5");

        const spec_t s5[10] = {G8(10), G8(11), G8(12), G8(13), G8(14), G8(15), G8(16), G8(17), G8(0x1800), G8(0x1900)};
        row_lower("П-десять-целых", s5, 10, (void *)w_int10, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);
        check_eq(0x1800 ^ 0x1900, x0, "a8^a9 со стека");

        const spec_t s6[10] = {F8(0.5), F8(1.5), F8(2.5), F8(3.5), F8(4.5), F8(5.5), F8(6.5), F8(7.5), F8(8.5), F8(9.5)};
        row_lower("П-десять-плавающих", s6, 10, (void *)w_f64x10, HB_ABI_X64_F64_V1, 8, &x0, &d0, ctx);
        check_eq(dbits(9.5), d0, "a9 со стека возвращён в d0");

        spec_t s7[18];
        for (unsigned i = 0; i < 9; ++i) { s7[2 * i] = G8(0x100 + i); s7[2 * i + 1] = F8(100.0 + i); }
        row_lower("П-9+9-вперемешку", s7, 18, (void *)w_over18, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);
        {
            hb_abi_native_image_v1_t img; hb_abi_native_sig_v1_t sig = make_sig(s7, 18, HB_ABI_X64_GPR_V1, 8);
            g_row = "П-9+9-образ";
            if (check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK, "lower OK")) {
                check_eq(8, img.x_count, "x_count"); check_eq(8, img.d_count, "d_count");
                check_eq(2, img.stack_count, "stack_count: i8 и f8");
                check_eq(0x108, img.stack[0], "stack[0]=i8"); check_eq(dbits(108.0), img.stack[1], "stack[1]=f8");
            }
        }
    }

    /* ── П+: старшие половины 64-битных значений (регистры и хвост) ───────────────── */
    {
        const spec_t s8[5] = {G8(UINT64_C(0xDEADBEEF00000001)), G8(UINT64_C(0x8000000000000000)),
                              G8(UINT64_C(0x00000001FFFFFFFF)), G8(UINT64_C(0xFFFFFFFF00000000)),
                              G8(UINT64_C(0x123456789ABCDEF0))};
        row_lower("П-старшие-половины", s8, 5, (void *)w_hi5, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);
        {
            hb_abi_native_sig_v1_t sig = make_sig(s8, 5, HB_ABI_X64_GPR_V1, 8);
            g_row = "В-U64";
            ctx->regs.x64.rax = 0;
            check(hb_abi_native_collect_return_v1(ctx, &sig, UINT64_C(0xFFFFFFFF00000001), 0) == HB_OK, "collect U64 OK");
            check_eq(UINT64_C(0xFFFFFFFF00000001), ctx->regs.x64.rax, "RAX хранит все 64 бита");
        }
    }
    /* ── П+: узкие беззнаковые GPR и образ F32 — маски видны в образе, не только у свидетеля */
    {
        const spec_t s9[4] = {G1(0xA5), G2(0xBEEF), G4(0xCAFEBABE), G8(UINT64_C(0x1122334455667788))};
        hb_abi_native_image_v1_t img;
        hb_abi_native_sig_v1_t sig = make_sig(s9, 4, HB_ABI_X64_GPR_V1, 8);
        row_lower("П-узкие", s9, 4, (void *)w_narrow, HB_ABI_X64_GPR_V1, 8, &x0, &d0, ctx);
        check_eq(0xA5 + 0xBEEF + 0xCAFEBABEull, x0, "сумма узких у свидетеля");
        g_row = "П-узкие-образ";
        if (check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK, "lower OK")) {
            check_eq(0xA5, img.x[0], "x0 = байт без мусора"); check_eq(0xBEEF, img.x[1], "x1 = слово без мусора");
            check_eq(0xCAFEBABE, img.x[2], "x2 = двойное слово без мусора");
        }
        const spec_t s3[4] = {F4(1.5f), G8(0x77), F4(-3.25f), G8(0x88)};
        sig = make_sig(s3, 4, HB_ABI_X64_GPR_V1, 8);
        g_row = "П-F32-образ";
        guest_place(ctx, s3, 4);
        if (check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK, "lower OK")) {
            check_eq(fbits(1.5f), img.d_bits[0], "d0 = F32 в младших 32, старшие нули");
            check_eq(fbits(-3.25f), img.d_bits[1], "d1 = F32 в младших 32, старшие нули");
            check_eq(2, img.d_count, "d_count"); check_eq(2, img.x_count, "x_count"); check_eq(0, img.stack_count, "stack_count");
        }
    }
    /* ── П+: счёт 20 принимается, 21 отвергается ИМЕННО границей (все 20 позиций валидны) ── */
    {
        spec_t s20[20];
        hb_abi_native_image_v1_t img;
        hb_abi_native_sig_v1_t sig;
        for (unsigned i = 0; i < 20; ++i) s20[i] = G8(0x2000 + i);
        g_row = "П-счёт-20";
        sig = make_sig(s20, 20, HB_ABI_X64_GPR_V1, 8);
        guest_place(ctx, s20, 20);
        if (check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK, "20 позиций принимаются")) {
            check_eq(8, img.x_count, "x_count"); check_eq(12, img.stack_count, "12 на стеке");
            check_eq(0x2000 + 19, img.stack[11], "последний слот");
        }
        sig.argument_count = 21;
        check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_ERR_INVALID_ARG, "21 при 20 валидных -> INVALID (граница, не NONE)");
        sig.argument_count = 20; sig.flags = HB_ABI_NATIVE_FLAG_VARIADIC_V1;
        check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_ERR_UNSUPPORTED_FEATURE, "флаг VARIADIC -> UNSUPPORTED");
        sig.flags = 2u;
        check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_ERR_INVALID_ARG, "неизвестный флаг -> INVALID");
        sig.flags = 0; sig.reserved = 1;
        check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_ERR_INVALID_ARG, "reserved != 0 -> INVALID");
    }

    /* ── В: результат ───────────────────────────────────────────────────────────────── */
    {
        const spec_t r1[2] = {G8(3), F8(1.25)};
        row_lower("В-F64", r1, 2, (void *)w_ret_f64, HB_ABI_X64_F64_V1, 8, &x0, &d0, ctx);
        {
            hb_abi_native_sig_v1_t sig = make_sig(r1, 2, HB_ABI_X64_F64_V1, 8);
            uint64_t hi = ctx->regs.x64.xmm[0][1];
            ctx->regs.x64.rax = 0x5a5a;
            check(hb_abi_native_collect_return_v1(ctx, &sig, x0, d0) == HB_OK, "collect F64 OK");
            check_eq(dbits(1.25 * 2.0 + 3.0), ctx->regs.x64.xmm[0][0], "XMM0[0] = результат");
            check_eq(hi, ctx->regs.x64.xmm[0][1], "XMM0[1] не тронут"); check_eq(0x5a5a, ctx->regs.x64.rax, "RAX не тронут");
        }
        const spec_t r2[2] = {F4(0.5f), G8(2)};
        row_lower("В-F32", r2, 2, (void *)w_ret_f32, HB_ABI_X64_F32_V1, 4, &x0, &d0, ctx);
        {
            hb_abi_native_sig_v1_t sig = make_sig(r2, 2, HB_ABI_X64_F32_V1, 4);
            ctx->regs.x64.xmm[0][0] = GARBAGE_HI | 0x11111111;
            check(hb_abi_native_collect_return_v1(ctx, &sig, x0, d0) == HB_OK, "collect F32 OK");
            check_eq(GARBAGE_HI | fbits(2.5f), ctx->regs.x64.xmm[0][0], "младшие 32 XMM0 = результат, старшие сохранены");
        }
        const spec_t r3[1] = {G8(0xFFFFFFFE)};
        row_lower("В-U32", r3, 1, (void *)w_ret_u32, HB_ABI_X64_GPR_V1, 4, &x0, &d0, ctx);
        {
            hb_abi_native_sig_v1_t sig = make_sig(r3, 1, HB_ABI_X64_GPR_V1, 4);
            ctx->regs.x64.rax = 0;
            /* старшие биты x0 у 32-битного результата не определены — подсовываем мусор явно */
            check(hb_abi_native_collect_return_v1(ctx, &sig, GARBAGE_HI | 0xFFFFFFFF, 0) == HB_OK, "collect U32 OK");
            check_eq(0xFFFFFFFF, ctx->regs.x64.rax, "RAX = результат без старшего мусора");
            check_eq(0xFFFFFFFF, x0 & 0xFFFFFFFF, "свидетель вернул 0xFFFFFFFE+1");
        }
    }

    /* ── О: обратное поднятие ──────────────────────────────────────────────────────── */
    {
        const spec_t s[6] = {G8(0xAA), F8(1.5), G8(0xCC), F8(2.5), G8(0xEE), F8(3.5)};
        hb_abi_native_sig_v1_t sig = make_sig(s, 6, HB_ABI_X64_NONE_V1, 0);
        hb_abi_native_image_v1_t img, back;
        hb_abi_x64_call_v1_t call;
        hb_abi_x64_value_v1_t tail[4];
        hb_context_t *c2;
        g_row = "О-поднятие";
        memset(&img, 0, sizeof img);
        img.x[0] = 0xAA; img.x[1] = 0xCC; img.x[2] = 0xEE; img.x_count = 3;
        img.d_bits[0] = dbits(1.5); img.d_bits[1] = dbits(2.5); img.d_bits[2] = dbits(3.5); img.d_count = 3;
        if (check(hb_abi_native_raise_v1(&img, &sig, 0x710000, &call, tail, 4) == HB_OK, "raise OK")) {
            check_eq(6, call.argument_count, "argument_count");
            check_eq(0xAA, call.slots[0].bits, "slot0=rcx"); check_eq(HB_ABI_X64_GPR_V1, call.slots[0].kind, "slot0 GPR");
            check_eq(dbits(1.5), call.slots[1].bits, "slot1=xmm1"); check_eq(HB_ABI_X64_F64_V1, call.slots[1].kind, "slot1 F64");
            check_eq(0xCC, call.slots[2].bits, "slot2=r8"); check_eq(dbits(2.5), call.slots[3].bits, "slot3=xmm3");
            check(call.stack_args == tail, "хвост указывает на out_tail");
            check_eq(0x710000, call.return_pc, "return_pc перенесён");
            check_eq(8, call.slots[0].width_bytes, "ширина slot0"); check_eq(8, call.slots[1].width_bytes, "ширина slot1");
            check_eq(8, tail[0].width_bytes, "ширина tail0"); check_eq(HB_ABI_X64_F64_V1, tail[1].kind, "вид tail1");
            check_eq(0xEE, tail[0].bits, "tail0=позиция 4"); check_eq(dbits(3.5), tail[1].bits, "tail1=позиция 5");
            c2 = new_ctx();
            if (check(c2 != NULL, "второй контекст")) {
                uint64_t v;
                check(hb_abi_x64_prepare_v1(c2, 0x400000, &call) == HB_OK, "prepare_v1 принял описатель");
                check(hb_memory_read_u64(c2->memory, c2->regs.x64.rsp, &v) == HB_OK && v == 0x710000, "[rsp] = return_pc");
                check_eq(0xAA, c2->regs.x64.rcx, "RCX"); check_eq(0xCC, c2->regs.x64.r8, "R8");
                check_eq(dbits(1.5), c2->regs.x64.xmm[1][0], "XMM1"); check_eq(dbits(2.5), c2->regs.x64.xmm[3][0], "XMM3");
                check(hb_memory_read_u64(c2->memory, c2->regs.x64.rsp + 40, &v) == HB_OK && v == 0xEE, "[rsp+40]=позиция 4");
                check(hb_memory_read_u64(c2->memory, c2->regs.x64.rsp + 48, &v) == HB_OK && v == dbits(3.5), "[rsp+48]=позиция 5");
                /* круг: lower(prepared ctx) == исходный образ */
                check(hb_abi_native_lower_v1(c2, &sig, &back) == HB_OK && !memcmp(&back, &img, sizeof img), "lower(raise(image)) == image");
                hb_context_destroy(c2);
            }
        }
    }

    /* ── О+: круг через 18 позиций (x8 + d8 + 2 стека) и F32 в обе стороны ─────────── */
    {
        spec_t s18[18];
        hb_abi_native_sig_v1_t sig;
        hb_abi_native_image_v1_t img, back;
        hb_abi_x64_call_v1_t call;
        hb_abi_x64_value_v1_t tail[16];
        hb_context_t *c2;
        for (unsigned i = 0; i < 9; ++i) { s18[2 * i] = G8(0x300 + i); s18[2 * i + 1] = F8(300.0 + i); }
        s18[0] = F4(0.75f); s18[1] = G8(0x301); s18[16] = F4(-2.5f); s18[17] = G8(0x309);  /* F32 в регистре и в хвосте */
        sig = make_sig(s18, 18, HB_ABI_X64_NONE_V1, 0);
        g_row = "О-18-круг";
        guest_place(ctx, s18, 18);
        if (check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK, "lower 18 OK")) {
            check_eq(2, img.stack_count, "две позиции на стеке");
            if (check(hb_abi_native_raise_v1(&img, &sig, 0x720000, &call, tail, 16) == HB_OK, "raise 18 OK")) {
                check_eq(fbits(0.75f), call.slots[0].bits, "slot0 = F32"); check_eq(HB_ABI_X64_F32_V1, tail[12].kind, "tail12 = F32");
                check_eq(fbits(-2.5f), tail[12].bits, "tail12 биты");
                c2 = new_ctx();
                if (check(c2 != NULL, "второй контекст")) {
                    if (check(hb_abi_x64_prepare_v1(c2, 0x400000, &call) == HB_OK, "prepare_v1 принял 18 позиций") &&
                        check(hb_abi_native_lower_v1(c2, &sig, &back) == HB_OK, "lower после prepare"))
                        check(!memcmp(&back, &img, sizeof img), "круг 18 позиций: lower(prepare(raise(x))) == x");
                    hb_context_destroy(c2);
                }
            }
        }
        /* отказы raise: выходы не тронуты */
        {
            hb_abi_x64_call_v1_t sc; hb_abi_x64_value_v1_t st[16]; hb_abi_native_image_v1_t short_img;
            /* Независимый вход: отказы raise проверяются и при регрессии lower выше. */
            hb_abi_native_image_v1_t full_img = {0};
            full_img.x_count = 8; full_img.d_count = 8; full_img.stack_count = 2;
            memset(&sc, 0x5a, sizeof sc); memset(st, 0x5a, sizeof st);
            g_row = "О-отказы";
            check(hb_abi_native_raise_v1(&full_img, &sig, 0, &call, tail, 16) == HB_OK,
                  "независимый полный образ принят");
#define RAISE_REJECT(expr, code, what) do { hb_abi_x64_call_v1_t c0 = sc; hb_abi_x64_value_v1_t t0[16]; memcpy(t0, st, sizeof t0); \
            check((expr) == (code), what); check(!memcmp(&c0, &sc, sizeof sc) && !memcmp(t0, st, sizeof t0), what " — выходы не тронуты"); } while (0)
            RAISE_REJECT(hb_abi_native_raise_v1(&full_img, &sig, 0, &sc, st, 13), HB_ERR_INVALID_ARG, "tail_capacity 13 < 14 -> INVALID");
            RAISE_REJECT(hb_abi_native_raise_v1(&full_img, &sig, 0, &sc, NULL, 16), HB_ERR_INVALID_ARG, "out_tail NULL при хвосте -> INVALID");
            short_img = full_img; short_img.stack_count = 1;
            RAISE_REJECT(hb_abi_native_raise_v1(&short_img, &sig, 0, &sc, st, 16), HB_ERR_INVALID_ARG, "stack_count короче -> INVALID");
            short_img = full_img; short_img.x_count = 7;
            RAISE_REJECT(hb_abi_native_raise_v1(&short_img, &sig, 0, &sc, st, 16), HB_ERR_INVALID_ARG, "x_count короче -> INVALID");
            short_img = full_img; short_img.d_count = 3;
            RAISE_REJECT(hb_abi_native_raise_v1(&short_img, &sig, 0, &sc, st, 16), HB_ERR_INVALID_ARG, "d_count короче -> INVALID");
            short_img = full_img; short_img.x_count = 9;
            RAISE_REJECT(hb_abi_native_raise_v1(&short_img, &sig, 0, &sc, st, 16), HB_ERR_INVALID_ARG, "x_count > 8 -> INVALID");
#undef RAISE_REJECT
        }
        /* отказы collect_return: RAX/XMM0 не тронуты */
        {
            uint64_t rax0, x00;
            g_row = "В-отказы";
            sig = make_sig(s18, 18, HB_ABI_X64_F32_V1, 8);   /* F32 шириной 8 — неверно */
            rax0 = ctx->regs.x64.rax; x00 = ctx->regs.x64.xmm[0][0];
            check(hb_abi_native_collect_return_v1(ctx, &sig, 1, 2) == HB_ERR_INVALID_ARG, "ret F32/8 -> INVALID");
            sig = make_sig(s18, 18, HB_ABI_X64_GPR_V1, 8); sig.args[3].kind = 9u;
            check(hb_abi_native_collect_return_v1(ctx, &sig, 1, 2) == HB_ERR_UNSUPPORTED_FEATURE, "активный неизвестный вид -> UNSUPPORTED");
            check(ctx->regs.x64.rax == rax0 && ctx->regs.x64.xmm[0][0] == x00, "RAX/XMM0 не тронуты при отказе");
            sig = make_sig(s18, 18, HB_ABI_X64_GPR_V1, 8); ctx->mode = HB_MODE_32BIT;
            check(hb_abi_native_collect_return_v1(ctx, &sig, 1, 2) == HB_ERR_INVALID_ARG, "режим 32 бита -> INVALID");
            ctx->mode = HB_MODE_64BIT;
            check(ctx->regs.x64.rax == rax0, "RAX не тронут при отказе режима");
        }
    }

    /* ── Х: отказы ─────────────────────────────────────────────────────────────────── */
    {
        const spec_t s[2] = {G8(1), F8(2.0)};
        hb_abi_native_sig_v1_t sig;
        hb_abi_native_image_v1_t img, sentinel;
        memset(&sentinel, 0x5a, sizeof sentinel);
        g_row = "Х";
        guest_place(ctx, s, 2);
#define REJECT(mut, code, what) do { sig = make_sig(s, 2, HB_ABI_X64_GPR_V1, 8); mut; img = sentinel; \
        check(hb_abi_native_lower_v1(ctx, &sig, &img) == (code), what); \
        check(!memcmp(&img, &sentinel, sizeof img), what " — выход не тронут"); } while (0)
        REJECT(sig.args[1].kind = 7u, HB_ERR_UNSUPPORTED_FEATURE, "неизвестный вид (агрегат/varargs) -> UNSUPPORTED");
        REJECT(sig.args[0].width_bytes = 3u, HB_ERR_INVALID_ARG, "ширина 3 -> INVALID");
        REJECT(sig.abi_version = 2u, HB_ERR_UNSUPPORTED_FEATURE, "версия 2 -> UNSUPPORTED");
        REJECT(sig.target_abi = 2u, HB_ERR_UNSUPPORTED_FEATURE, "цель 2 -> UNSUPPORTED");
        REJECT(sig.argument_count = 21u, HB_ERR_INVALID_ARG, "счёт 21 -> INVALID");
        REJECT(sig.args[5].kind = HB_ABI_X64_GPR_V1, HB_ERR_INVALID_ARG, "активный вид за счётом -> INVALID");
        REJECT(sig.ret.kind = 9u, HB_ERR_UNSUPPORTED_FEATURE, "неизвестный вид результата -> UNSUPPORTED");
        REJECT(sig.struct_size = 4u, HB_ERR_INVALID_ARG, "размер структуры -> INVALID");
#undef REJECT
        {
            /* Пять активных позиций — все валидны: иначе отказ пришёл бы от проверки описателя
             * (NONE в активной позиции -> INVALID_ARG), а не от памяти, и обе проверки ниже
             * сходились бы ЛОЖНО. Поймано первым прогоном: «вне отображения» дало INVALID_ARG. */
            const spec_t s5[5] = {G8(1), F8(2.0), G8(3), F8(4.0), G8(5)};
            hb_memory_t *m = ctx->memory; sig = make_sig(s5, 5, HB_ABI_X64_GPR_V1, 8);
            guest_place(ctx, s5, 5); img = sentinel;
            check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK, "пять валидных позиций с памятью -> OK");
            check_eq(5, img.x[2] /* позиция 4 -> третий целый */, "позиция 4 легла в x2");
            ctx->memory = NULL; img = sentinel;
            check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_ERR_INVALID_ARG, "хвост без памяти -> INVALID");
            ctx->memory = m;
            ctx->regs.x64.rsp = STACK + PAGE_BYTES - 8; img = sentinel;   /* хвост за страницей */
            check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_ERR_MEMORY_FAULT, "хвост вне отображения -> MEMORY_FAULT");
            check(!memcmp(&img, &sentinel, sizeof img), "выход не тронут при отказе чтения");
            ctx->regs.x64.rsp = STACK + PAGE_BYTES - 0x400;
        }
    }

    /* Переполнение хвоста отклоняется до чтения памяти и без частичной записи. */
    {
        const struct { unsigned count; uint64_t rsp; } cases[] = {
            {5, UINT64_MAX - 39},   /* первый адрес RSP+40 переворачивается в ноль */
            {5, UINT64_MAX - 43},   /* адрес представим, но 8-байтный слот пересекает конец */
            {20, UINT64_MAX - 151}, /* переполнение адреса позднего слота */
            {20, UINT64_MAX - 164}, /* конец последнего слота пересекает конец адресов */
        };
        spec_t args[20];
        hb_abi_native_sig_v1_t sig;
        hb_abi_native_image_v1_t img, sentinel;
        uint64_t saved_rsp;
        for (unsigned i = 0; i < 20; ++i) args[i] = G8(0x400 + i);
        guest_place(ctx, args, 20);
        saved_rsp = ctx->regs.x64.rsp;
        memset(&sentinel, 0x5a, sizeof sentinel);
        sig = make_sig(args, 20, HB_ABI_X64_GPR_V1, 8);
        g_row = "Х-переполнение";
        check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK,
              "контроль: валидные 20 позиций и отображённый хвост приняты");
        for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
            hb_context_t before;
            sig = make_sig(args, cases[i].count, HB_ABI_X64_GPR_V1, 8);
            ctx->regs.x64.rsp = cases[i].rsp;
            before = *ctx; img = sentinel;
            check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_ERR_INVALID_ARG,
                  "переполнение адреса/конца хвоста -> INVALID_ARG");
            check(!memcmp(&img, &sentinel, sizeof img), "переполнение не меняет образ");
            check(!memcmp(ctx, &before, sizeof before), "переполнение не меняет контекст");
        }
        sig = make_sig(args, 4, HB_ABI_X64_GPR_V1, 8);
        ctx->regs.x64.rsp = UINT64_MAX;
        check(hb_abi_native_lower_v1(ctx, &sig, &img) == HB_OK,
              "контроль: четыре регистра не требуют чтения хвоста");
        ctx->regs.x64.rsp = saved_rsp;
    }

    /* ── С: свежий вызов против возобновления (G4, известные ответы) ───────────────── */
    {
        hb_context_t *c = new_ctx();
        g_row = "С";
        if (check(c != NULL, "контекст")) {
            const uint64_t R = STACK + PAGE_BYTES - 0x400 + 8;   /* 8 mod 16: точка внутри функции после CALL */
            hb_abi_x64_call_t legacy; hb_abi_x64_call_v1_t v1; hb_context_t before; uint64_t v;
            memset(&legacy, 0, sizeof legacy);
            c->regs.x64.rsp = R;
            check_eq(8, R & 15, "RSP = 8 mod 16");
            check(hb_abi_x64_call(c, 0x500000, &legacy, NULL) == HB_OK, "старый hb_abi_x64_call ПРИНИМАЕТ возобновлённый RSP");
            check_eq((R & ~15ull) - 40, c->regs.x64.rsp, "и ПЕРЕПИСЫВАЕТ кадр: RSP = (R&~15)-40");
            check(hb_memory_read_u64(c->memory, c->regs.x64.rsp, &v) == HB_OK && v == 0xFFFF0000, "[RSP] = 0xFFFF0000 (синтетический возврат)");
            check_eq(0x500000, c->pc, "pc = цель");
            /* v1: тот же RSP — отказ, контекст нетронут */
            c->regs.x64.rsp = R; before = *c;
            memset(&v1, 0, sizeof v1); v1.abi_version = HB_ABI_X64_V1; v1.struct_size = sizeof v1; v1.return_pc = 0x710000;
            check(hb_abi_x64_prepare_v1(c, 0x500000, &v1) == HB_ERR_INVALID_ARG, "v1 отказывает на RSP = 8 mod 16");
            check(!memcmp(c, &before, sizeof before), "v1 не тронул контекст");
            hb_context_destroy(c);
        }
    }

    printf("hb_abi_native_v1_test: %u passed, %u failed\n", g_checks - g_fail, g_fail);
    hb_context_destroy(ctx);
    return g_fail ? 1 : 0;
}
