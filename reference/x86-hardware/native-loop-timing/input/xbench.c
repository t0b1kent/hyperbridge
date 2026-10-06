/* xbench.c — x86-64 microbenchmark for comparing x86 emulators (Prism, FEX under our Wine, FEX in CrossOver).
 * Each test is a tight inline-asm loop of one idiom; the result is nanoseconds per iteration (loop overhead included,
 * see "empty"). Every test runs 5 times after a calibration pass; the median and the minimum are printed.
 * Tests that need a CPUID feature (SSE4.2 crc32) are skipped when the feature is not advertised.
 * Output lines start with "bench:". Build: x86_64-w64-mingw32-clang -O2 -static. */
#include <windows.h>
#include <cpuid.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*bench_fn)(uint64_t n);

static volatile uint64_t g_sink;
static uint32_t g_mem[16] __attribute__((aligned(64)));
static uint8_t g_src[4096] __attribute__((aligned(64)));
static uint8_t g_dst[4096] __attribute__((aligned(64)));
static const float g_f = 123.625f;
static const double g_d = 12345.625;

static void b_empty(uint64_t n) { __asm__ volatile("1: dec %0\n\tjnz 1b" : "+r"(n) :: "cc"); }

static void b_add(uint64_t n)
{
    uint64_t a = 0;
    __asm__ volatile("1: add $3, %0\n\tdec %1\n\tjnz 1b" : "+r"(a), "+r"(n) :: "cc");
    g_sink = a;
}

static void b_imul(uint64_t n)
{
    uint64_t a = 1, m = 3;
    __asm__ volatile("1: imul %2, %0\n\tdec %1\n\tjnz 1b" : "+r"(a), "+r"(n) : "r"(m) : "cc");
    g_sink = a;
}

static void b_cvttss2si(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("movss %2, %%xmm0\n\t"
                     "1: cvttss2si %%xmm0, %%eax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) : "m"(g_f) : "rax", "xmm0", "cc");
    g_sink = acc;
}

static void b_cvtss2si(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("movss %2, %%xmm0\n\t"
                     "1: cvtss2si %%xmm0, %%eax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) : "m"(g_f) : "rax", "xmm0", "cc");
    g_sink = acc;
}

static void b_cvttsd2si64(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("movsd %2, %%xmm0\n\t"
                     "1: cvttsd2si %%xmm0, %%rax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) : "m"(g_d) : "rax", "xmm0", "cc");
    g_sink = acc;
}

static void b_cvttps2dq(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm0\n\tshufps $0, %%xmm0, %%xmm0\n\tpxor %%xmm2, %%xmm2\n\t"
                     "1: cvttps2dq %%xmm0, %%xmm1\n\tpaddd %%xmm1, %%xmm2\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm2, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "xmm2", "cc", "memory");
}

static void b_cvtdq2ps(uint64_t n)
{
    __asm__ volatile("pcmpeqd %%xmm0, %%xmm0\n\txorps %%xmm2, %%xmm2\n\t"
                     "1: cvtdq2ps %%xmm0, %%xmm1\n\taddps %%xmm1, %%xmm2\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm2, %%eax\n\tmov %%eax, %1"
                     : "+r"(n) : "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "xmm2", "cc", "memory");
}

static void b_addsubps(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm1\n\tshufps $0, %%xmm1, %%xmm1\n\txorps %%xmm0, %%xmm0\n\t"
                     "1: addsubps %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_addss(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm1\n\txorps %%xmm0, %%xmm0\n\t"
                     "1: addss %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_mulps(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm1\n\tshufps $0, %%xmm1, %%xmm1\n\tmovaps %%xmm1, %%xmm0\n\t"
                     "1: mulps %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_pshufb(uint64_t n)
{
    __asm__ volatile("pcmpeqd %%xmm1, %%xmm1\n\tpsrlw $12, %%xmm1\n\tpxor %%xmm0, %%xmm0\n\t"
                     "1: pshufb %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %1"
                     : "+r"(n) : "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_div32(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("mov $7, %%ecx\n\t"
                     "1: xor %%edx, %%edx\n\tmov %k1, %%eax\n\tdiv %%ecx\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) :: "rax", "rcx", "rdx", "cc");
    g_sink = acc;
}

static void b_idiv64(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("mov $-7, %%rcx\n\t"
                     "1: mov %1, %%rax\n\tcqo\n\tidiv %%rcx\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) :: "rax", "rcx", "rdx", "cc");
    g_sink = acc;
}

static void b_crc32(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("1: crc32l %k1, %k0\n\tdec %1\n\tjnz 1b" : "+r"(acc), "+r"(n) :: "cc");
    g_sink = acc;
}

static void b_popcnt(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("1: popcnt %1, %%rax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b" : "+r"(acc), "+r"(n) :: "rax", "cc");
    g_sink = acc;
}

static void b_lock_xadd(uint64_t n)
{
    __asm__ volatile("mov $1, %%eax\n\t"
                     "1: lock xaddl %%eax, %1\n\tmov $1, %%eax\n\tdec %0\n\tjnz 1b"
                     : "+r"(n), "+m"(g_mem[0]) :: "rax", "cc", "memory");
}

static void b_call_ret(uint64_t n)
{
    __asm__ volatile("jmp 2f\n\t"
                     "3: ret\n\t"
                     "2: call 3b\n\tdec %0\n\tjnz 2b"
                     : "+r"(n) :: "cc", "memory");
}

static void b_icall(uint64_t n)
{
    __asm__ volatile("lea 3f(%%rip), %%r11\n\tjmp 2f\n\t"
                     "3: ret\n\t"
                     "2: call *%%r11\n\tdec %0\n\tjnz 2b"
                     : "+r"(n) :: "r11", "cc", "memory");
}

static void b_rep_movsb_4k(uint64_t n)
{
    __asm__ volatile("1: lea %1, %%rsi\n\tlea %2, %%rdi\n\tmov $4096, %%ecx\n\trep movsb\n\tdec %0\n\tjnz 1b"
                     : "+r"(n) : "m"(g_src), "m"(g_dst) : "rsi", "rdi", "rcx", "cc", "memory");
}

static void b_x87_fadd(uint64_t n)
{
    __asm__ volatile("fld1\n\tfld1\n\t"
                     "1: fadd %%st(1), %%st\n\tdec %0\n\tjnz 1b\n\t"
                     "fstpl %1\n\tfstp %%st(0)"
                     : "+r"(n), "=m"(g_mem[2]) :: "cc", "memory");
}

static int has_sse42(void)
{
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    return (c >> 20) & 1;
}

static double now_ns(void)
{
    static LARGE_INTEGER f;
    LARGE_INTEGER t;
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1e9 / (double)f.QuadPart;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static void run(const char *name, bench_fn fn)
{
    /* calibration: grow n until one pass takes >= 20 ms, then aim for ~150 ms per pass */
    uint64_t n = 100000;
    double t;
    for (;;)
    {
        double t0 = now_ns();
        fn(n);
        t = now_ns() - t0;
        if (t >= 20e6 || n >= (1ull << 34)) break;
        n *= 4;
    }
    n = (uint64_t)((double)n * (150e6 / t));
    if (n < 1000) n = 1000;
    double r[5];
    for (int i = 0; i < 5; i++)
    {
        double t0 = now_ns();
        fn(n);
        r[i] = (now_ns() - t0) / (double)n;
    }
    qsort(r, 5, sizeof(r[0]), cmp_d);
    printf("bench: name=%-14s iters=%-12" PRIu64 " ns_median=%8.3f ns_min=%8.3f ns_max=%8.3f\n", name, n, r[2], r[0], r[4]);
    fflush(stdout);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    char brand[49] = { 0 };
    unsigned a, b, c, d;
    for (unsigned i = 0; i < 3; i++)
    {
        __cpuid(0x80000002 + i, a, b, c, d);
        memcpy(brand + i * 16, &a, 4); memcpy(brand + i * 16 + 4, &b, 4);
        memcpy(brand + i * 16 + 8, &c, 4); memcpy(brand + i * 16 + 12, &d, 4);
    }
    printf("bench: begin version=1 brand=\"%s\" sse42=%d\n", brand, has_sse42());
    memset(g_src, 0x5a, sizeof(g_src));
    run("empty", b_empty);
    run("add", b_add);
    run("imul", b_imul);
    run("cvttss2si", b_cvttss2si);
    run("cvtss2si", b_cvtss2si);
    run("cvttsd2si64", b_cvttsd2si64);
    run("cvttps2dq", b_cvttps2dq);
    run("cvtdq2ps", b_cvtdq2ps);
    run("addsubps", b_addsubps);
    run("addss", b_addss);
    run("mulps", b_mulps);
    run("pshufb", b_pshufb);
    run("div32", b_div32);
    run("idiv64", b_idiv64);
    if (has_sse42()) run("crc32", b_crc32); else printf("bench: name=crc32 skipped=no-sse42\n");
    run("popcnt", b_popcnt);
    run("lock_xadd", b_lock_xadd);
    run("call_ret", b_call_ret);
    run("icall", b_icall);
    run("rep_movsb_4k", b_rep_movsb_4k);
    run("x87_fadd", b_x87_fadd);
    printf("bench: end\n");
    return 0;
}
