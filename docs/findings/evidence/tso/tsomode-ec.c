/* Curator probe (04.10.2026): which ARM64 instruction classes become slow when the thread is in the
 * hardware-TSO (x86_64 compatibility) mode. Build as an ARM64EC executable so the loops run natively
 * inside an "x64" Wine process whose threads the engine admits to the mode at thread init.
 * Run the SAME exe in two arms: A = r2 as is (MACRUNNER_FEX_HW_TSO=2) and T = MACRUNNER_FEX_HW_TSO=0.
 * Build: arm64ec-w64-mingw32-clang -O1 -static -march=armv8.2-a+lse -o tsomode-ec.exe tsomode-ec.c
 * No guest x86 code is timed here; the output is ns per loop iteration, best of 5. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

static uint8_t buf[4096] __attribute__((aligned(64)));
__attribute__((noinline)) static void callee(void) { __asm__ volatile("nop"); }
static void (*volatile fptr)(void) = callee;

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
LOOP(t_gpr_spill8, "stp x0,x1,[x19]\n stp x2,x3,[x19,#16]\n stp x4,x5,[x19,#32]\n stp x6,x7,[x19,#48]\n"
                   "ldp x0,x1,[x19]\n ldp x2,x3,[x19,#16]\n ldp x4,x5,[x19,#32]\n ldp x6,x7,[x19,#48]")
LOOP(t_q_spill8, "stp q0,q1,[x19,#64]\n stp q2,q3,[x19,#96]\n stp q4,q5,[x19,#128]\n stp q6,q7,[x19,#160]\n"
                 "ldp q0,q1,[x19,#64]\n ldp q2,q3,[x19,#96]\n ldp q4,q5,[x19,#128]\n ldp q6,q7,[x19,#160]")
LOOP(t_q_store_partial_load, "str q0,[x19,#256]\n ldr x0,[x19,#256]\n ldrh w1,[x19,#264]")
LOOP(t_x2_store_q_load, "stp x0,x1,[x19,#288]\n ldr q0,[x19,#288]")
LOOP(t_x_h_store_q_load, "str x0,[x19,#320]\n strh w1,[x19,#328]\n ldr q0,[x19,#320]")
LOOP(t_byte_store_x_load, "strb w0,[x19,#353]\n ldr x1,[x19,#352]")
LOOP(t_nzcv, "mrs x0, nzcv\n msr nzcv, x0")
LOOP(t_fpcr, "mrs x0, fpcr\n msr fpcr, x0")
LOOP(t_fpsr, "mrs x0, fpsr\n msr fpsr, x0")
LOOP(t_fpcr_read, "mrs x0, fpcr")
LOOP(t_fpsr_read, "mrs x0, fpsr")
LOOP(t_fpsr_write, "mov x0,#0\n msr fpsr, x0")
LOOP(t_fpcr_write, "mov x0,#0\n msr fpcr, x0")
LOOP(t_teb_load, "ldr x0,[x18,#0x30]")
LOOP(t_udiv, "mov x0,#12345\n mov x1,#7\n udiv x2,x0,x1")
LOOP(t_fadd, "fadd d0,d0,d1")
LOOP(t_fmov_gpr, "fmov x0,d0\n fmov d1,x0")
LOOP(t_umov, "umov w0,v0.h[4]\n mov x1,v0.d[0]")
LOOP(t_ins, "mov v0.d[0],x0\n mov v0.h[4],w1")
LOOP(t_inc_mem64, "ldr x0,[x19,#408]\n add x0,x0,#1\n str x0,[x19,#408]")
LOOP(t_lse_add, "mov x0,#1\n add x1,x19,#416\n ldaddal x0,x2,[x1]")
LOOP(t_cas, "ldr x0,[x19,#424]\n add x1,x0,#1\n add x2,x19,#424\n casal x0,x1,[x2]")
LOOP(t_ldxr_stxr, "add x2,x19,#432\n ldxr x0,[x2]\n add x0,x0,#1\n stxr w1,x0,[x2]")
LOOP(t_ldar_stlr, "add x2,x19,#440\n ldar x0,[x2]\n add x0,x0,#1\n stlr x0,[x2]")
LOOP(t_st1x4_aligned, "add x0,x19,#1024\n st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]\n ld1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]")
LOOP(t_st1x4_split, "add x0,x19,#1040\n st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]\n ld1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]")
LOOP(t_st1_only_split, "add x0,x19,#1296\n st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]")
LOOP(t_ld1_only_split, "add x0,x19,#1552\n ld1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0]")
LOOP(t_fex_spill_fill16, "add x0,x19,#2064\n st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0],#64\n st1 {v4.2d,v5.2d,v6.2d,v7.2d},[x0],#64\n"
                         "st1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0],#64\n st1 {v4.2d,v5.2d,v6.2d,v7.2d},[x0],#64\n add x0,x19,#2064\n"
                         "ld1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0],#64\n ld1 {v4.2d,v5.2d,v6.2d,v7.2d},[x0],#64\n"
                         "ld1 {v0.2d,v1.2d,v2.2d,v3.2d},[x0],#64\n ld1 {v4.2d,v5.2d,v6.2d,v7.2d},[x0],#64")
LOOP(t_stp_q_split, "add x0,x19,#3120\n stp q0,q1,[x0]\n ldp q0,q1,[x0]")
LOOP(t_str_x_split, "add x2,x19,#3260\n str x0,[x2]\n ldr x1,[x2]")
LOOP(t_dmb, "dmb ish")
LOOP(t_isb, "isb")

__attribute__((noinline)) static void t_blr(uint64_t n) { for (; n; --n) fptr(); }

struct T { const char *name; void (*fn)(uint64_t); uint64_t n; };
static struct T tests[] = {
  {"empty", t_empty, 20000000}, {"gpr_spill8", t_gpr_spill8, 10000000},
  {"q_spill8", t_q_spill8, 10000000}, {"q_store_partial_load", t_q_store_partial_load, 10000000},
  {"x2_store_q_load", t_x2_store_q_load, 10000000}, {"x_h_store_q_load", t_x_h_store_q_load, 10000000},
  {"byte_store_x_load", t_byte_store_x_load, 10000000},
  {"mrs_msr_nzcv", t_nzcv, 10000000}, {"mrs_msr_fpcr", t_fpcr, 2000000},
  {"mrs_msr_fpsr", t_fpsr, 2000000}, {"mrs_fpcr", t_fpcr_read, 5000000},
  {"mrs_fpsr", t_fpsr_read, 5000000}, {"msr_fpsr", t_fpsr_write, 2000000},
  {"msr_fpcr", t_fpcr_write, 2000000}, {"teb_load", t_teb_load, 10000000},
  {"udiv", t_udiv, 10000000}, {"fadd", t_fadd, 10000000}, {"fmov_gpr", t_fmov_gpr, 10000000},
  {"umov", t_umov, 10000000}, {"ins", t_ins, 10000000}, {"inc_mem64", t_inc_mem64, 10000000},
  {"lse_ldaddal", t_lse_add, 5000000}, {"casal", t_cas, 5000000},
  {"ldxr_stxr", t_ldxr_stxr, 5000000}, {"ldar_stlr", t_ldar_stlr, 5000000},
  {"st1x4_ld1x4_aligned", t_st1x4_aligned, 5000000}, {"st1x4_ld1x4_split", t_st1x4_split, 2000000},
  {"st1x4_only_split", t_st1_only_split, 2000000}, {"ld1x4_only_split", t_ld1_only_split, 5000000},
  {"fex_spill_fill16", t_fex_spill_fill16, 2000000}, {"stp_q_split", t_stp_q_split, 2000000},
  {"str_x_split", t_str_x_split, 2000000},
  {"dmb_ish", t_dmb, 2000000}, {"isb", t_isb, 2000000}, {"blr_ret", t_blr, 10000000},
};

int main(void) {
  LARGE_INTEGER f, a, b;
  if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) return 2;
  printf("tsomode: begin tests=%u\n", (unsigned)(sizeof(tests) / sizeof(tests[0])));
  for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
    double best = 1e30;
    tests[i].fn(10000);
    for (int k = 0; k < 5; ++k) {
      QueryPerformanceCounter(&a); tests[i].fn(tests[i].n); QueryPerformanceCounter(&b);
      double ns = (double)(b.QuadPart - a.QuadPart) * 1e9 / (double)f.QuadPart / (double)tests[i].n;
      if (ns < best) best = ns;
    }
    printf("tsomode: name=%s ns=%.3f\n", tests[i].name, best);
    fflush(stdout);
  }
  printf("tsomode: end\n");
  return 0;
}
