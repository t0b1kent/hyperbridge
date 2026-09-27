/* Разностный тест родных путей CMP/TEST/ADD/SUB/AND/OR/XOR с операндом в памяти (Claude 27.09.2026).
 * Эталон — интерпретатор HB (его флаги сверены с железом корпусом Астры HBFL0001); проверяемое — JIT с
 * MACRUNNER_HB_CMP_MEM_NATIVE=1 и MACRUNNER_HB_ALU_MEM_NATIVE=1. Формы: op r,[rdi+8]; cmp/test [rdi+8],r;
 * cmp [rdi+8],imm8; 8/16/32/64 бита; адрес выровненный и невыровненный (невыровненный идёт в прежнего
 * помощника — ветвь тоже проверяется). Сверка: RAX RCX RDX RDI и шесть флагов (AF у логических — вне маски).
 * Выход 0 — всё совпало, 1 — расхождения. Отрицательный контроль: MACRUNNER_HB_TEST_MEM_NATIVE_FLIP=1. */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_flags.h"

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static uint64_t edge(void) {
    static const uint64_t e[] = { 0, 1, 2, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000u,
                                  0xffffffffu, 0x7fffffffffffffffull, 0x8000000000000000ull, ~0ull };
    return (rnd() & 1) ? rnd() : e[rnd() % (sizeof e / sizeof e[0])];
}

static void setflags(hb_context_t* c, uint64_t f) {
    c->regs.x64.rflags = f;
    memset(&c->lazy_flags, 0, sizeof c->lazy_flags);
    c->flags.cf = (f >> 0) & 1; c->flags.pf = (f >> 2) & 1; c->flags.af = (f >> 4) & 1;
    c->flags.zf = (f >> 6) & 1; c->flags.sf = (f >> 7) & 1; c->flags.of = (f >> 11) & 1;
}
static uint64_t getflags(hb_context_t* c) {
    (void)hb_lazy_flags_materialize_available(c, HB_FLAG_BIT_ALL);
    return (uint64_t)c->flags.cf | ((uint64_t)c->flags.pf << 2) | ((uint64_t)c->flags.af << 4) |
           ((uint64_t)c->flags.zf << 6) | ((uint64_t)c->flags.sf << 7) | ((uint64_t)c->flags.of << 11);
}

typedef struct { uint64_t rax, rcx, rdx, rdi, fl; uint8_t mem[64]; int ok; } snap_t;

static uint8_t* g_code;
static uint8_t* g_data;
static size_t g_page;
/* Сегменты (Claude 27.09.2026): отдельная область 256 КБ, GS = seg+0x1000, FS = seg+0x20000 — содержимое
 * у баз разное, так что перепутанный сегмент виден в значении. */
enum { SEG_LEN = 0x40000, GS_OFF = 0x1000, FS_OFF = 0x20000 };
static uint8_t* g_seg;

static snap_t run(const uint8_t* code, size_t len, const uint64_t in[4], uint64_t fl, const uint8_t mem[64],
                  int jit) {
    snap_t s; memset(&s, 0, sizeof s);
    hb_context_t* c = hb_context_create(HB_ARCH_X64, jit ? HB_BACKEND_JIT : HB_BACKEND_INTERP);
    hb_memory_t* m = hb_memory_create(0);
    c->config.fallback_enabled = false; c->memory = m;
    hb_memory_sync_live_range(m, (hb_gva_t)(uintptr_t)g_code, g_page, HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC);
    hb_memory_sync_live_range(m, (hb_gva_t)(uintptr_t)g_data, g_page, HB_PERM_READ | HB_PERM_WRITE);
    hb_memory_sync_live_range(m, (hb_gva_t)(uintptr_t)g_seg, SEG_LEN, HB_PERM_READ | HB_PERM_WRITE);
    c->gs_base = (uint64_t)(uintptr_t)(g_seg + GS_OFF);
    c->fs_base = (uint64_t)(uintptr_t)(g_seg + FS_OFF);
    memcpy(g_code, code, len);
    memcpy(g_data + 64, mem, 64);                     /* окно: [data+64, data+128) */
    memset(&c->regs, 0, sizeof c->regs);
    c->regs.x64.rax = in[0]; c->regs.x64.rcx = in[1]; c->regs.x64.rdx = in[2]; c->regs.x64.rdi = in[3];
    c->regs.x64.rsp = (uint64_t)(uintptr_t)(g_data + g_page - 256);
    c->pc = c->regs.x64.rip = (uint64_t)(uintptr_t)g_code;
    setflags(c, fl);
    c->mxcsr = 0x1f80;
    hb_context_set_step_limit(c, 1000); hb_context_set_block_limit(c, 100);
    hb_jit_runtime_t* rt = jit ? hb_jit_runtime_create(c) : NULL;
    hb_decoder_t* d = hb_decoder_create(HB_ARCH_X64, g_code, len, c->pc);
    hb_ir_func_t* f = NULL;
    if (d && hb_lift_func_x64(d, &f) == HB_OK && f && !f->has_unsupported) {
        hb_exec_result_t r; memset(&r, 0, sizeof r);
        hb_result_t xr = jit ? hb_jit_runtime_run(rt, f, &r) : hb_runtime_run(c, f, HB_BACKEND_INTERP, &r);
        s.ok = xr == HB_OK && !r.faulted && c->pc == (uint64_t)(uintptr_t)g_code + len;
    }
    if (d) hb_decoder_destroy(d);
    s.rax = c->regs.x64.rax; s.rcx = c->regs.x64.rcx; s.rdx = c->regs.x64.rdx; s.rdi = c->regs.x64.rdi;
    s.fl = getflags(c);
    memcpy(s.mem, g_data + 64, 64);
    if (rt) hb_jit_runtime_destroy(rt);
    if (f) hb_ir_func_destroy(f);
    c->memory = NULL; hb_context_destroy(c); hb_memory_destroy(m);
    return s;
}

/* Кодировка: [66][REX.W] op modrm(01,reg,111=rdi) disp8 [imm8]. */
static size_t enc(uint8_t* b, int size, uint8_t op8, uint8_t opv, int reg, int has_imm, uint8_t imm) {
    size_t n = 0;
    if (size == 16) b[n++] = 0x66;
    if (size == 64) b[n++] = 0x48;
    b[n++] = size == 8 ? op8 : opv;
    b[n++] = (uint8_t)(0x40 | (reg << 3) | 7);
    b[n++] = 0x08;
    if (has_imm) b[n++] = imm;
    return n;
}

int main(void) {
    struct form { const char* name; uint8_t op8, opv; int digit; int imm; int logic; } forms[] = {
        { "add r,[m]", 0x02, 0x03, -1, 0, 0 }, { "or r,[m]",  0x0a, 0x0b, -1, 0, 1 },
        { "and r,[m]", 0x22, 0x23, -1, 0, 1 }, { "sub r,[m]", 0x2a, 0x2b, -1, 0, 0 },
        { "xor r,[m]", 0x32, 0x33, -1, 0, 1 }, { "cmp r,[m]", 0x3a, 0x3b, -1, 0, 0 },
        { "cmp [m],r", 0x38, 0x39, -1, 0, 0 }, { "test [m],r", 0x84, 0x85, -1, 0, 1 },
        { "cmp [m],imm8", 0x80, 0x83, 7, 1, 0 },
    };
    const int sizes[] = { 8, 16, 32, 64 };
    unsigned long total = 0, bad = 0, nok = 0;
    g_page = 16384;
    g_code = mmap(NULL, g_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    g_data = mmap(NULL, g_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    g_seg = mmap(NULL, SEG_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    {   /* свой генератор: остальные разделы получают прежние случайные последовательности */
        uint64_t z = 0x2545f4914f6cdd1dull;
        for (size_t k = 0; k < SEG_LEN; k++) { z ^= z << 13; z ^= z >> 7; z ^= z << 17; g_seg[k] = (uint8_t)z; }
    }
    for (unsigned fi = 0; fi < sizeof forms / sizeof forms[0]; fi++)
        for (unsigned si = 0; si < 4; si++)
            for (int mis = 0; mis < 2; mis++)
                for (int it = 0; it < 300; it++) {
                    uint8_t code[16], mem[64];
                    int reg = (int)(rnd() % 3);                  /* eax/ecx/edx (al/cl/dl) */
                    size_t len = enc(code, sizes[si], forms[fi].op8, forms[fi].opv,
                                     forms[fi].digit >= 0 ? forms[fi].digit : reg, forms[fi].imm, (uint8_t)rnd());
                    uint64_t in[4] = { edge(), edge(), edge(), 0 };
                    uint64_t val = edge();
                    for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                    /* rdi+8 указывает на окно; невыровненный — сдвиг на 1..7 внутри окна */
                    unsigned sh = mis ? 1u + (unsigned)(rnd() % 7) : 0u;
                    in[3] = (uint64_t)(uintptr_t)(g_data + 64) + 16 + sh - 8;
                    memcpy(mem + 16 + sh, &val, sizes[si] / 8);
                    uint64_t fl = rnd() & 0x8d5;
                    snap_t a = run(code, len, in, fl, mem, 0);
                    snap_t b = run(code, len, in, fl, mem, 1);
                    uint64_t fm = forms[fi].logic ? 0x8c5 : 0x8d5;   /* AF у логических не определён */
                    total++;
                    if (!a.ok || !b.ok) { nok++; if (nok <= 5) fprintf(stderr, "RUN FAIL %s/%d mis=%d a=%d b=%d\n", forms[fi].name, sizes[si], mis, a.ok, b.ok); continue; }
                    if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || a.rdi != b.rdi ||
                        ((a.fl ^ b.fl) & fm) || memcmp(a.mem, b.mem, 64)) {
                        bad++;
                        if (bad <= 12)
                            fprintf(stderr, "MISMATCH %s/%d mis=%d: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx fl %llx/%llx\n",
                                    forms[fi].name, sizes[si], mis,
                                    (unsigned long long)a.rax, (unsigned long long)b.rax, (unsigned long long)a.rcx,
                                    (unsigned long long)b.rcx, (unsigned long long)a.rdx, (unsigned long long)b.rdx,
                                    (unsigned long long)a.fl, (unsigned long long)b.fl);
                    }
                }
    /* IMUL: imul r,[m] (0F AF), imul r,[m],imm8 (6B), imul r,r (0F AF /r mod=11), imul r,r,imm8 (6B mod=11).
     * Сверяются CF и OF: SF/ZF/PF/AF у IMUL по SDM не определены. */
    {
        const int isz[] = { 16, 32, 64 };
        for (int form = 0; form < 4; form++)
            for (unsigned si = 0; si < 3; si++)
                for (int mis = 0; mis < 2; mis++)
                    for (int it = 0; it < 300; it++) {
                        uint8_t code[16], mem[64];
                        size_t n = 0;
                        int reg = (int)(rnd() % 3), rm = (int)(rnd() % 3);
                        int memform = (form == 0 || form == 1);
                        if (!memform && mis) continue;
                        if (isz[si] == 16) code[n++] = 0x66;
                        if (isz[si] == 64) code[n++] = 0x48;
                        if (form == 0 || form == 2) { code[n++] = 0x0f; code[n++] = 0xaf; }
                        else code[n++] = 0x6b;
                        if (memform) { code[n++] = (uint8_t)(0x40 | (reg << 3) | 7); code[n++] = 0x08; }
                        else code[n++] = (uint8_t)(0xc0 | (reg << 3) | rm);
                        if (form == 1 || form == 3) code[n++] = (uint8_t)rnd();
                        uint64_t in[4] = { edge(), edge(), edge(), 0 };
                        uint64_t val = edge();
                        for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                        unsigned sh = mis ? 1u + (unsigned)(rnd() % 7) : 0u;
                        in[3] = (uint64_t)(uintptr_t)(g_data + 64) + 16 + sh - 8;
                        memcpy(mem + 16 + sh, &val, isz[si] / 8);
                        uint64_t fl = rnd() & 0x8d5;
                        snap_t a = run(code, n, in, fl, mem, 0);
                        snap_t b = run(code, n, in, fl, mem, 1);
                        total++;
                        if (!a.ok || !b.ok) { nok++; if (nok <= 5) fprintf(stderr, "RUN FAIL imul form%d/%d mis=%d a=%d b=%d\n", form, isz[si], mis, a.ok, b.ok); continue; }
                        if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || a.rdi != b.rdi ||
                            ((a.fl ^ b.fl) & 0x801) || memcmp(a.mem, b.mem, 64)) {
                            bad++;
                            if (bad <= 12)
                                fprintf(stderr, "MISMATCH imul form%d/%d mis=%d: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx fl %llx/%llx\n",
                                        form, isz[si], mis, (unsigned long long)a.rax, (unsigned long long)b.rax,
                                        (unsigned long long)a.rcx, (unsigned long long)b.rcx, (unsigned long long)a.rdx,
                                        (unsigned long long)b.rdx, (unsigned long long)a.fl, (unsigned long long)b.fl);
                        }
                    }
    }
    /* CMOVcc r,[m] (0F 40+cc /r): все 16 условий, случайные флаги; память читается всегда. */
    {
        const int csz[] = { 16, 32, 64 };
        for (int cc = 0; cc < 16; cc++)
            for (unsigned si = 0; si < 3; si++)
                for (int mis = 0; mis < 2; mis++)
                    for (int it = 0; it < 60; it++) {
                        uint8_t code[16], mem[64];
                        size_t n = 0;
                        int reg = (int)(rnd() % 3);
                        if (csz[si] == 16) code[n++] = 0x66;
                        if (csz[si] == 64) code[n++] = 0x48;
                        code[n++] = 0x0f; code[n++] = (uint8_t)(0x40 + cc);
                        code[n++] = (uint8_t)(0x40 | (reg << 3) | 7); code[n++] = 0x08;
                        uint64_t in[4] = { edge(), edge(), edge(), 0 };
                        uint64_t val = edge();
                        for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                        unsigned sh = mis ? 1u + (unsigned)(rnd() % 7) : 0u;
                        in[3] = (uint64_t)(uintptr_t)(g_data + 64) + 16 + sh - 8;
                        memcpy(mem + 16 + sh, &val, csz[si] / 8);
                        uint64_t fl = rnd() & 0x8d5;
                        snap_t a = run(code, n, in, fl, mem, 0);
                        snap_t b = run(code, n, in, fl, mem, 1);
                        total++;
                        if (!a.ok || !b.ok) { nok++; continue; }
                        if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || a.rdi != b.rdi ||
                            ((a.fl ^ b.fl) & 0x8d5) || memcmp(a.mem, b.mem, 64)) {
                            bad++;
                            if (bad <= 12)
                                fprintf(stderr, "MISMATCH cmov cc=%d/%d mis=%d: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx\n",
                                        cc, csz[si], mis, (unsigned long long)a.rax, (unsigned long long)b.rax,
                                        (unsigned long long)a.rcx, (unsigned long long)b.rcx,
                                        (unsigned long long)a.rdx, (unsigned long long)b.rdx);
                        }
                    }
    }
    /* LOCK RMW: lock add/or/and/sub/xor [m],r (01/09/21/29/31) и lock or [m],imm8 (83 /1), 32/64 бита. */
    {
        const uint8_t lop[] = { 0x01, 0x09, 0x21, 0x29, 0x31 };
        const int llogic[] = { 0, 1, 1, 0, 1 };
        const int lsz[] = { 32, 64 };
        for (int fi = 0; fi < 6; fi++)
            for (unsigned si = 0; si < 2; si++)
                for (int it = 0; it < 300; it++) {
                    uint8_t code[16], mem[64];
                    size_t n = 0;
                    int reg = (int)(rnd() % 3);
                    code[n++] = 0xf0;
                    if (lsz[si] == 64) code[n++] = 0x48;
                    if (fi < 5) { code[n++] = lop[fi]; code[n++] = (uint8_t)(0x40 | (reg << 3) | 7); code[n++] = 0x08; }
                    else { code[n++] = 0x83; code[n++] = (uint8_t)(0x40 | (1 << 3) | 7); code[n++] = 0x08; code[n++] = (uint8_t)rnd(); }
                    uint64_t in[4] = { edge(), edge(), edge(), 0 };
                    uint64_t val = edge();
                    for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                    in[3] = (uint64_t)(uintptr_t)(g_data + 64) + 16 - 8;      /* выровнено: LOCK на невыровненном — отдельная тема */
                    memcpy(mem + 16, &val, lsz[si] / 8);
                    uint64_t fl = rnd() & 0x8d5;
                    snap_t a = run(code, n, in, fl, mem, 0);
                    snap_t b = run(code, n, in, fl, mem, 1);
                    uint64_t fm = (fi == 5 || llogic[fi]) ? 0x8c5 : 0x8d5;
                    total++;
                    if (!a.ok || !b.ok) { nok++; if (nok <= 5) fprintf(stderr, "RUN FAIL lock fi=%d/%d a=%d b=%d\n", fi, lsz[si], a.ok, b.ok); continue; }
                    if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || ((a.fl ^ b.fl) & fm) || memcmp(a.mem, b.mem, 64)) {
                        bad++;
                        if (bad <= 12)
                            fprintf(stderr, "MISMATCH lock fi=%d/%d: fl %llx/%llx mem16 %llx/%llx\n", fi, lsz[si],
                                    (unsigned long long)a.fl, (unsigned long long)b.fl,
                                    (unsigned long long)*(uint64_t*)(a.mem + 16), (unsigned long long)*(uint64_t*)(b.mem + 16));
                    }
                }
    }
    /* Обмены (Claude 27.09.2026, MACRUNNER_HB_LSE_XCHG): xchg [m],r (87, с LOCK и без — неделим всегда),
     * lock xadd [m],r (0F C1), lock cmpxchg [m],r (0F B1; половина случаев — память равна аккумулятору),
     * 32/64 бита, r = rax/rcx/rdx. Сверка rax, rcx, rdx, всех шести флагов и окна памяти. */
    {
        const int xsz[] = { 32, 64 };
        for (int kind = 0; kind < 4; kind++)          /* 0 xchg, 1 lock xchg, 2 lock xadd, 3 lock cmpxchg */
            for (unsigned si = 0; si < 2; si++)
                for (int it = 0; it < 400; it++) {
                    uint8_t code[16], mem[64];
                    size_t n = 0;
                    int reg = (int)(rnd() % 3);
                    if (kind >= 1) code[n++] = 0xf0;
                    if (xsz[si] == 64) code[n++] = 0x48;
                    if (kind <= 1) code[n++] = 0x87;
                    else { code[n++] = 0x0f; code[n++] = kind == 2 ? 0xc1 : 0xb1; }
                    code[n++] = (uint8_t)(0x40 | (reg << 3) | 7);
                    code[n++] = 0x08;
                    uint64_t in[4] = { edge(), edge(), edge(), 0 };
                    uint64_t val = edge();
                    for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                    in[3] = (uint64_t)(uintptr_t)(g_data + 64) + 16 - 8;
                    if (kind == 3 && (rnd() & 1)) val = in[0];          /* совпадение с аккумулятором */
                    memcpy(mem + 16, &val, xsz[si] / 8);
                    uint64_t fl = rnd() & 0x8d5;
                    snap_t a = run(code, n, in, fl, mem, 0);
                    snap_t b = run(code, n, in, fl, mem, 1);
                    total++;
                    if (!a.ok || !b.ok) { nok++; if (nok <= 5) fprintf(stderr, "RUN FAIL xchg kind=%d/%d a=%d b=%d\n", kind, xsz[si], a.ok, b.ok); continue; }
                    if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || ((a.fl ^ b.fl) & 0x8d5) || memcmp(a.mem, b.mem, 64)) {
                        bad++;
                        if (bad <= 12)
                            fprintf(stderr, "MISMATCH xchg kind=%d/%d reg=%d: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx fl %llx/%llx mem16 %llx/%llx\n",
                                    kind, xsz[si], reg, (unsigned long long)a.rax, (unsigned long long)b.rax,
                                    (unsigned long long)a.rcx, (unsigned long long)b.rcx,
                                    (unsigned long long)a.rdx, (unsigned long long)b.rdx,
                                    (unsigned long long)a.fl, (unsigned long long)b.fl,
                                    (unsigned long long)*(uint64_t*)(a.mem + 16), (unsigned long long)*(uint64_t*)(b.mem + 16));
                    }
                }
    }
    /* NOT r / NEG r (F6/F7 /2, /3, mod=11), 8/16/32/64. У NOT флаги не меняются, у NEG — все шесть. */
    {
        const int nsz[] = { 8, 16, 32, 64 };
        for (int neg = 0; neg < 2; neg++)
            for (unsigned si = 0; si < 4; si++)
                for (int it = 0; it < 400; it++) {
                    uint8_t code[8], mem[64];
                    size_t n = 0;
                    int reg = (int)(rnd() % 3);
                    if (nsz[si] == 16) code[n++] = 0x66;
                    if (nsz[si] == 64) code[n++] = 0x48;
                    code[n++] = nsz[si] == 8 ? 0xf6 : 0xf7;
                    code[n++] = (uint8_t)(0xc0 | ((neg ? 3 : 2) << 3) | reg);
                    uint64_t in[4] = { edge(), edge(), edge(), (uint64_t)(uintptr_t)(g_data + 64) };
                    for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                    uint64_t fl = rnd() & 0x8d5;
                    snap_t a = run(code, n, in, fl, mem, 0);
                    snap_t b = run(code, n, in, fl, mem, 1);
                    total++;
                    if (!a.ok || !b.ok) { nok++; continue; }
                    if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || ((a.fl ^ b.fl) & 0x8d5)) {
                        bad++;
                        if (bad <= 12)
                            fprintf(stderr, "MISMATCH %s/%d: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx fl %llx/%llx\n",
                                    neg ? "neg" : "not", nsz[si], (unsigned long long)a.rax, (unsigned long long)b.rax,
                                    (unsigned long long)a.rcx, (unsigned long long)b.rcx, (unsigned long long)a.rdx,
                                    (unsigned long long)b.rdx, (unsigned long long)a.fl, (unsigned long long)b.fl);
                    }
                }
    }
    /* Чтения fs:/gs:[disp] (Claude 27.09.2026, MACRUNNER_HB_NATIVE_SEG_LOAD): mov r, seg:[disp32] через SIB без
     * базы и индекса (8B /r, modrm 00 reg 100, SIB 25) и moffs (A1, 8-байтовый адрес), 32/64 бита, r = rax/rcx/rdx.
     * Смещения: кратные ширине (одна команда LDR), любые до 0xffff и край 0x7ff8 (адрес через X22), отрицательные и
     * за 0xffff (эмиттер отказывается — проверяется прежний помощник). Приёмник до чтения случайный: 32-битная
     * форма обязана обнулить верх. */
    {
        unsigned long sec_total = total, sec_bad = bad, sec_nok = nok;
        for (int form = 0; form < 2; form++)            /* 0 SIB-абсолют, 1 moffs (приёмник только rax) */
            for (int seg = 0; seg < 2; seg++)           /* 0 FS, 1 GS */
                for (int wide = 0; wide < 2; wide++)
                    for (int it = 0; it < 400; it++) {
                        uint8_t code[24], mem[64];
                        size_t n = 0;
                        int reg = form ? 0 : (int)(rnd() % 3);
                        int64_t disp;
                        switch (rnd() % 5) {
                        case 0: disp = (int64_t)((rnd() % 0x1000) * (wide ? 8 : 4)); break;
                        case 1: disp = (int64_t)(rnd() % 0x10000); break;
                        case 2: disp = (int64_t)(0x7ff0 + rnd() % 0x20); break;
                        case 3: disp = -(int64_t)(1 + rnd() % 0x800); break;
                        default: disp = (int64_t)(0x10000 + rnd() % 0xf00); break;
                        }
                        code[n++] = seg ? 0x65 : 0x64;
                        if (wide) code[n++] = 0x48;
                        if (form == 0) {
                            int32_t d32 = (int32_t)disp;
                            code[n++] = 0x8b; code[n++] = (uint8_t)(0x04 | (reg << 3)); code[n++] = 0x25;
                            memcpy(code + n, &d32, 4); n += 4;
                        } else {
                            uint64_t d64 = (uint64_t)disp;
                            code[n++] = 0xa1;
                            memcpy(code + n, &d64, 8); n += 8;
                        }
                        uint64_t in[4] = { edge(), edge(), edge(), (uint64_t)(uintptr_t)(g_data + 64) };
                        for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                        uint64_t fl = rnd() & 0x8d5;
                        snap_t a = run(code, n, in, fl, mem, 0);
                        snap_t b = run(code, n, in, fl, mem, 1);
                        total++;
                        if (!a.ok || !b.ok) { nok++; if (nok <= 5) fprintf(stderr, "RUN FAIL seg form=%d seg=%d/%d disp=%lld a=%d b=%d\n", form, seg, wide ? 64 : 32, (long long)disp, a.ok, b.ok); continue; }
                        if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || ((a.fl ^ b.fl) & 0x8d5)) {
                            bad++;
                            if (bad <= 12)
                                fprintf(stderr, "MISMATCH seg form=%d %s/%d reg=%d disp=%lld: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx\n",
                                        form, seg ? "gs" : "fs", wide ? 64 : 32, reg, (long long)disp,
                                        (unsigned long long)a.rax, (unsigned long long)b.rax, (unsigned long long)a.rcx,
                                        (unsigned long long)b.rcx, (unsigned long long)a.rdx, (unsigned long long)b.rdx);
                        }
                    }
        fprintf(stderr, "SECTION seg cases=%lu mismatch=%lu run_fail=%lu\n", total - sec_total, bad - sec_bad, nok - sec_nok);
    }
    /* MUL/IMUL с одним операндом и DIV/IDIV (Claude 27.09.2026, MACRUNNER_HB_NATIVE_MULDIV): F7 /4../7, 32/64 бита,
     * операнд — rcx (чаще) / rax / rdx или [rdi+8], выровненный и нет (невыровненный идёт помощнику). Делимое
     * подобрано так, чтобы шли и быстрая ветвь (EDX < делителя, RDX = 0 / знак RAX), и все отказы: делитель 0,
     * частное не влезает, INT_MIN / -1 (#DE с обеих сторон — совпадение), 64-битное делимое шире 64 бит. Верх
     * RAX/RDX у 32-битных форм случайный: команда обязана его не читать и обнулить. Сверка RAX RCX RDX; у
     * MUL/IMUL ещё CF и OF; у деления флаги не определены и не сверяются. */
    {
        unsigned long sec_total = total, sec_bad = bad, sec_nok = nok, both_fault = 0;
        for (int opi = 0; opi < 4; opi++)            /* 0 mul, 1 imul, 2 div, 3 idiv */
            for (int wide = 0; wide < 2; wide++)
                for (int form = 0; form < 3; form++)   /* 0 регистр, 1 [rdi+8] выровнено, 2 невыровнено */
                    for (int it = 0; it < 300; it++) {
                        uint8_t code[8], mem[64];
                        size_t n = 0;
                        int digit = 4 + opi;
                        int reg = (rnd() % 4) ? 1 : ((rnd() & 1) ? 0 : 2);
                        uint64_t in[4] = { edge(), edge(), edge(), (uint64_t)(uintptr_t)(g_data + 64) + (form == 2 ? 3 : 0) };
                        uint64_t opnd = edge();
                        for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                        if (opi >= 2) {
                            unsigned mode = (unsigned)(rnd() % 8);
                            if (mode == 0) opnd = 0;
                            else if (mode == 1) opnd = ~0ull;
                            else if (mode <= 3) opnd = 1 + rnd() % 1000;
                            if (wide) {
                                if (mode == 1 && (rnd() & 1)) in[0] = 0x8000000000000000ull;
                                if (mode != 7) in[2] = opi == 2 ? 0 : (uint64_t)((int64_t)in[0] >> 63);
                            } else {
                                uint64_t d32 = opnd & 0xffffffffull, hi = edge() & 0xffffffff00000000ull;
                                if (mode == 1 && (rnd() & 1)) { in[0] &= 0xffffffff00000000ull; in[2] = hi | 0x80000000ull; }
                                else if (mode != 7)
                                    in[2] = hi | (opi == 2 ? (in[2] & 0xffffffffull) % (d32 ? d32 : 1)
                                                           : (uint64_t)(uint32_t)((int32_t)(uint32_t)in[0] >> 31));
                            }
                        }
                        if (form == 0) in[reg] = opnd;
                        else memcpy(mem + 8 + (form == 2 ? 3 : 0), &opnd, wide ? 8 : 4);
                        if (wide) code[n++] = 0x48;
                        code[n++] = 0xf7;
                        if (form == 0) code[n++] = (uint8_t)(0xc0 | (digit << 3) | reg);
                        else { code[n++] = (uint8_t)(0x40 | (digit << 3) | 7); code[n++] = 0x08; }
                        uint64_t fl = rnd() & 0x8d5;
                        snap_t a = run(code, n, in, fl, mem, 0);
                        snap_t b = run(code, n, in, fl, mem, 1);
                        uint64_t fm = opi < 2 ? 0x801 : 0;
                        total++;
                        if (!a.ok && !b.ok) both_fault++;
                        if (a.ok != b.ok || a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx || ((a.fl ^ b.fl) & fm)) {
                            bad++;
                            if (bad - sec_bad <= 12)
                                fprintf(stderr, "MISMATCH muldiv op=%d/%d form=%d reg=%d ok=%d/%d: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx fl %llx/%llx\n",
                                        opi, wide ? 64 : 32, form, reg, a.ok, b.ok, (unsigned long long)a.rax, (unsigned long long)b.rax,
                                        (unsigned long long)a.rcx, (unsigned long long)b.rcx, (unsigned long long)a.rdx,
                                        (unsigned long long)b.rdx, (unsigned long long)a.fl, (unsigned long long)b.fl);
                        }
                    }
        fprintf(stderr, "SECTION muldiv cases=%lu mismatch=%lu run_fail=%lu both_fault=%lu\n", total - sec_total, bad - sec_bad,
                nok - sec_nok, both_fault);
    }
    /* Чтение «приёмник = база» (Claude 27.09.2026, MACRUNNER_HB_SELF_BASE_NATIVE): mov r,[r] для rax/rcx/rdx,
     * 16/32/64 бита, указатель в окно со смещением 0..56 — половина выровнена (идёт LDAR), прочие уходят
     * помощнику по проверке выравнивания. 16-битная форма обязана сохранить верх регистра. */
    {
        unsigned long sec_total = total, sec_bad = bad, sec_nok = nok;
        const int ssz[] = { 16, 32, 64 };
        for (unsigned si = 0; si < 3; si++)
            for (int it = 0; it < 600; it++) {
                uint8_t code[8], mem[64];
                size_t n = 0;
                int reg = (int)(rnd() % 3);
                unsigned off = (unsigned)(rnd() % 57);
                if (rnd() & 1) off &= ~7u;
                uint64_t in[4] = { edge(), edge(), edge(), (uint64_t)(uintptr_t)(g_data + 64) };
                in[reg] = (uint64_t)(uintptr_t)(g_data + 64 + off);
                for (int k = 0; k < 64; k++) mem[k] = (uint8_t)rnd();
                if (ssz[si] == 16) code[n++] = 0x66;
                if (ssz[si] == 64) code[n++] = 0x48;
                code[n++] = 0x8b; code[n++] = (uint8_t)((reg << 3) | reg);
                uint64_t fl = rnd() & 0x8d5;
                snap_t a = run(code, n, in, fl, mem, 0);
                snap_t b = run(code, n, in, fl, mem, 1);
                total++;
                if (!a.ok || !b.ok) { nok++; continue; }
                if (a.rax != b.rax || a.rcx != b.rcx || a.rdx != b.rdx) {
                    bad++;
                    if (bad - sec_bad <= 12)
                        fprintf(stderr, "MISMATCH selfbase %d reg=%d off=%u: rax %llx/%llx rcx %llx/%llx rdx %llx/%llx\n",
                                ssz[si], reg, off, (unsigned long long)a.rax, (unsigned long long)b.rax,
                                (unsigned long long)a.rcx, (unsigned long long)b.rcx,
                                (unsigned long long)a.rdx, (unsigned long long)b.rdx);
                }
            }
        fprintf(stderr, "SECTION selfbase cases=%lu mismatch=%lu run_fail=%lu\n", total - sec_total, bad - sec_bad, nok - sec_nok);
    }
    printf("{\"cases\":%lu,\"mismatch\":%lu,\"run_fail\":%lu}\n", total, bad, nok);
    return (bad || nok) ? 1 : 0;
}
