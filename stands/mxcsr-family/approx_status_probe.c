/* SPDX-License-Identifier: MIT
 * Public synthetic inputs only. Run natively on x86-64 hardware.
 * cc -O2 -Wall -Wextra approx_status_probe.c -o approx-status
 * Each approximate RCP/RSQRT instruction must preserve all six status bits.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void run(unsigned op, const uint32_t in[4], uint32_t seed,
                uint32_t out[4], uint32_t *csr) {
  uint32_t saved;
  __asm__ volatile("stmxcsr %0" : "=m"(saved));
#define ARM(OP) __asm__ volatile("ldmxcsr %[seed]\n\tmovups %[in], %%xmm1\n\t" OP " %%xmm1, %%xmm0\n\tmovups %%xmm0, %[out]\n\tstmxcsr %[csr]" \
  : [out] "=m"(*(uint32_t (*)[4])out), [csr] "=m"(*csr) \
  : [in] "m"(*(const uint32_t (*)[4])in), [seed] "m"(seed) : "xmm0", "xmm1", "memory")
  switch (op) {
    case 0: ARM("rcpss"); break;
    case 1: ARM("rcpps"); break;
    case 2: ARM("rsqrtss"); break;
    case 3: ARM("rsqrtps"); break;
  }
#undef ARM
  __asm__ volatile("ldmxcsr %0" :: "m"(saved) : "memory");
}

int main(void) {
  static const char *ops[] = {"rcpss", "rcpps", "rsqrtss", "rsqrtps"};
  static const struct { const char *name; uint32_t bits; } cases[] = {
    {"zero", 0}, {"neg1", 0xbf800000}, {"three", 0x40400000},
    {"min_subnormal", 1}, {"quiet_nan", 0x7fc00001}, {"signaling_nan", 0x7f800001}
  };
  unsigned failed = 0;
  for (unsigned seed_status = 0; seed_status < 2; ++seed_status) {
    uint32_t seed = 0x1f80 | seed_status;
    for (unsigned op = 0; op < 4; ++op) {
      for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        uint32_t in[4], out[4], csr = 0;
        for (unsigned lane = 0; lane < 4; ++lane) in[lane] = cases[c].bits;
        run(op, in, seed, out, &csr);
        unsigned bad = csr != seed;
        failed += bad;
        printf("{\"operation\":\"%s\",\"case\":\"%s\",\"seed\":\"%04x\",\"mxcsr\":\"%04x\",\"result\":\"%08x\",\"bad\":%u}\n",
               ops[op], cases[c].name, seed, csr, out[0], bad);
      }
    }
  }
  printf("{\"cases\":48,\"failed\":%u}\n", failed);
  return failed ? 1 : 0;
}
