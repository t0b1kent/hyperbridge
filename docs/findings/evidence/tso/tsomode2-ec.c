/* Curator probe 2 (04.10.2026): which LOAD FORMS and which 4 KB COPY LOOPS stay fast when the thread is in the
 * hardware-TSO mode. Probe 1 showed: ld1 of four Q registers 0.42 -> 13.2 ns, ldp q after stp q +5 ns per pair,
 * single ldr q fast. This probe separates the forms and times copy loops so the emitter can pick the cheapest one.
 * ARM64EC executable, loops run natively. Arms: A = r2 as is (MACRUNNER_FEX_HW_TSO=2), T = MACRUNNER_FEX_HW_TSO=0.
 * Build: arm64ec-w64-mingw32-clang -O1 -static -march=armv8.2-a+lse -o tsomode2-ec.exe tsomode2-ec.c */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint8_t buf[4096] __attribute__((aligned(64)));
static uint8_t big[16384] __attribute__((aligned(64)));

#define LOOP(name, body)                                                     \
  __attribute__((noinline)) static void name(uint64_t n) {                   \
    register uint8_t *p __asm__("x19") = buf;                                \
    __asm__ volatile("1:\n" body "\n subs %0, %0, #1\n b.ne 1b\n"            \
                     : "+r"(n) : "r"(p)                                      \
                     : "cc", "memory", "x0", "x1", "x2", "x3", "x4", "x5",   \
                       "x6", "x7", "x8", "x9", "x10", "x11", "v0",           \
                       "v1", "v2", "v3", "v4", "v5", "v6", "v7");            \
  }

LOOP(t_empty, "nop")
LOOP(t_ldr_q_x1, "add x0,x19,#1024\n ldr q0,[x0]")
LOOP(t_ldr_q_x2, "add x0,x19,#1024\n ldr q0,[x0]\n ldr q1,[x0,#16]")
LOOP(t_ldr_q_x4, "add x0,x19,#1024\n ldr q0,[x0]\n ldr q1,[x0,#16]\n ldr q2,[x0,#32]\n ldr q3,[x0,#48]")
LOOP(t_ldp_q_x1, "add x0,x19,#1024\n ldp q0,q1,[x0]")
LOOP(t_ldp_q_x2, "add x0,x19,#1024\n ldp q0,q1,[x0]\n ldp q2,q3,[x0,#32]")
LOOP(t_ldnp_q_x1, "add x0,x19,#1024\n ldnp q0,q1,[x0]")
LOOP(t_ld1_x1, "add x0,x19,#1024\n ld1 {v0.2d},[x0]")
LOOP(t_ld1_x2, "add x0,x19,#1024\n ld1 {v0.2d,v1.2d},[x0]")
LOOP(t_ld1_x3, "add x0,x19,#1024\n ld1 {v0.2d,v1.2d,v2.2d},[x0]")
LOOP(t_ld1_x4, "add x0,x19,#1024\n ld1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]")
LOOP(t_ldp_d, "add x0,x19,#1024\n ldp d0,d1,[x0]")
LOOP(t_ldp_s, "add x0,x19,#1024\n ldp s0,s1,[x0]")
LOOP(t_ldp_x, "add x0,x19,#1024\n ldp x1,x2,[x0]")
LOOP(t_ldp_x_x4, "add x0,x19,#1024\n ldp x1,x2,[x0]\n ldp x3,x4,[x0,#16]\n ldp x5,x6,[x0,#32]\n ldp x7,x8,[x0,#48]")
LOOP(t_ldr_q_cross_line, "add x0,x19,#1080\n ldr q0,[x0]")
LOOP(t_ldr_x_cross_line, "add x0,x19,#1084\n ldr x1,[x0]")
LOOP(t_ldp_x_cross_line, "add x0,x19,#1080\n ldp x1,x2,[x0]")
LOOP(t_stp_q_only, "add x0,x19,#2048\n stp q0,q1,[x0]")
LOOP(t_str_q_x2, "add x0,x19,#2048\n str q0,[x0]\n str q1,[x0,#16]")
LOOP(t_stp_q_then_ldr_q_x2, "add x0,x19,#2112\n stp q0,q1,[x0]\n ldr q0,[x0]\n ldr q1,[x0,#16]")
LOOP(t_str_q_x2_then_ldp_q, "add x0,x19,#2176\n str q0,[x0]\n str q1,[x0,#16]\n ldp q0,q1,[x0]")
LOOP(t_st1x4_then_ldr_q_x4, "add x0,x19,#2240\n st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]\n ldr q0,[x0]\n ldr q1,[x0,#16]\n"
                            "ldr q2,[x0,#32]\n ldr q3,[x0,#48]")

#define COPY(name, body, iters)                                                              \
  __attribute__((noinline)) static void name(uint64_t n) {                                   \
    uint8_t *s = big, *d = big + 8192;                                                       \
    __asm__ volatile("1:\n mov x1,%1\n mov x2,%2\n mov x3,#" #iters "\n 2:\n" body           \
                     "\n subs x3,x3,#1\n b.ne 2b\n subs %0,%0,#1\n b.ne 1b\n"                \
                     : "+r"(n) : "r"(s), "r"(d)                                              \
                     : "cc", "memory", "x1", "x2", "x3", "x4", "x5", "v0", "v1", "v2", "v3"); \
  }

COPY(c_ldp_stp_q, "ldp q0,q1,[x1],#32\n stp q0,q1,[x2],#32", 128)
COPY(c_ldr_str_q, "ldr q0,[x1],#16\n str q0,[x2],#16", 256)
COPY(c_ldr2_stp_q, "ldr q0,[x1]\n ldr q1,[x1,#16]\n add x1,x1,#32\n stp q0,q1,[x2],#32", 128)
COPY(c_ldp_stp_x, "ldp x4,x5,[x1],#16\n stp x4,x5,[x2],#16", 256)
COPY(c_ld1x4_st1x4, "ld1 {v0.2d,v1.2d,v2.2d,v3.2d},[x1],#64\n st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x2],#64", 64)
COPY(c_ldr4_st1x4, "ldr q0,[x1]\n ldr q1,[x1,#16]\n ldr q2,[x1,#32]\n ldr q3,[x1,#48]\n add x1,x1,#64\n"
                   "st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x2],#64", 64)
COPY(c_ldnp_stnp_q, "ldnp q0,q1,[x1]\n add x1,x1,#32\n stnp q0,q1,[x2]\n add x2,x2,#32", 128)

static void *(*volatile crt_memcpy)(void *, const void *, size_t) = memcpy;
__attribute__((noinline)) static void c_crt_memcpy(uint64_t n) {
  for (; n; --n) crt_memcpy(big + 8192, big, 4096);
}
static void *(*volatile crt_memmove)(void *, const void *, size_t) = memmove;
__attribute__((noinline)) static void c_crt_memmove(uint64_t n) {
  for (; n; --n) crt_memmove(big + 8192, big, 4096);
}

struct T { const char *name; void (*fn)(uint64_t); uint64_t n; };
static struct T tests[] = {
  {"empty", t_empty, 20000000},
  {"ldr_q_x1", t_ldr_q_x1, 10000000}, {"ldr_q_x2", t_ldr_q_x2, 10000000}, {"ldr_q_x4", t_ldr_q_x4, 10000000},
  {"ldp_q_x1", t_ldp_q_x1, 5000000}, {"ldp_q_x2", t_ldp_q_x2, 5000000}, {"ldnp_q_x1", t_ldnp_q_x1, 5000000},
  {"ld1_x1", t_ld1_x1, 10000000}, {"ld1_x2", t_ld1_x2, 5000000}, {"ld1_x3", t_ld1_x3, 5000000},
  {"ld1_x4", t_ld1_x4, 5000000}, {"ldp_d", t_ldp_d, 10000000}, {"ldp_s", t_ldp_s, 10000000},
  {"ldp_x", t_ldp_x, 10000000}, {"ldp_x_x4", t_ldp_x_x4, 10000000},
  {"ldr_q_cross_line", t_ldr_q_cross_line, 10000000}, {"ldr_x_cross_line", t_ldr_x_cross_line, 10000000},
  {"ldp_x_cross_line", t_ldp_x_cross_line, 10000000},
  {"stp_q_only", t_stp_q_only, 10000000}, {"str_q_x2", t_str_q_x2, 10000000},
  {"stp_q_then_ldr_q_x2", t_stp_q_then_ldr_q_x2, 5000000}, {"str_q_x2_then_ldp_q", t_str_q_x2_then_ldp_q, 5000000},
  {"st1x4_then_ldr_q_x4", t_st1x4_then_ldr_q_x4, 5000000},
  {"copy4k_ldp_stp_q", c_ldp_stp_q, 200000}, {"copy4k_ldr_str_q", c_ldr_str_q, 200000},
  {"copy4k_ldr2_stp_q", c_ldr2_stp_q, 200000}, {"copy4k_ldp_stp_x", c_ldp_stp_x, 200000},
  {"copy4k_ld1x4_st1x4", c_ld1x4_st1x4, 200000}, {"copy4k_ldr4_st1x4", c_ldr4_st1x4, 200000},
  {"copy4k_ldnp_stnp_q", c_ldnp_stnp_q, 200000},
  {"copy4k_crt_memcpy", c_crt_memcpy, 200000}, {"copy4k_crt_memmove", c_crt_memmove, 200000},
};

int main(void) {
  LARGE_INTEGER f, a, b;
  if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) return 2;
  for (unsigned i = 0; i < sizeof(big); ++i) big[i] = (uint8_t)(i * 131u + 7u);
  printf("tsomode2: begin tests=%u\n", (unsigned)(sizeof(tests) / sizeof(tests[0])));
  for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
    double best = 1e30;
    tests[i].fn(1000);
    for (int k = 0; k < 5; ++k) {
      QueryPerformanceCounter(&a); tests[i].fn(tests[i].n); QueryPerformanceCounter(&b);
      double ns = (double)(b.QuadPart - a.QuadPart) * 1e9 / (double)f.QuadPart / (double)tests[i].n;
      if (ns < best) best = ns;
    }
    printf("tsomode2: name=%s ns=%.3f\n", tests[i].name, best);
    fflush(stdout);
  }
  printf("tsomode2: copy_ok=%d\n", memcmp(big, big + 8192, 4096) == 0);
  printf("tsomode2: end\n");
  return 0;
}
