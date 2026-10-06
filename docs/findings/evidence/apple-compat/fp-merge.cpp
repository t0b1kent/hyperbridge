#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/sysctl.h>

struct alignas(16) Bits { uint64_t lo, hi; };
using SetCompat = int (*)(int);
static uint64_t fpcr() { uint64_t v; asm volatile("mrs %0, fpcr" : "=r"(v)); return v; }
static void fpcr(uint64_t v) { asm volatile("msr fpcr, %0\n\tisb" :: "r"(v) : "memory"); }

#define RUN(INSN, DEST) asm volatile( \
  "ldr q0, [%[d]]\n\tldr q1, [%[a]]\n\tldr q2, [%[b]]\n\t" \
  "msr fpsr, xzr\n\t" INSN "\n\tstr " DEST ", [%[o]]\n\tmrs %[f], fpsr" \
  : [f] "=r"(fpsr) : [d] "r"(&d), [a] "r"(&a), [b] "r"(&b), [o] "r"(&out), [integer] "r"(integer) \
  : "v0", "v1", "v2", "memory")
#define BINARY(NAME) \
  if (!strcmp(op, #NAME)) { \
    if (width == 32) { \
      if (alias == 0) { RUN(#NAME " s0, s1, s2", "q0"); } \
      if (alias == 1) { RUN(#NAME " s1, s1, s2", "q1"); } \
      if (alias == 2) { RUN(#NAME " s2, s1, s2", "q2"); } \
    } else { \
      if (alias == 0) { RUN(#NAME " d0, d1, d2", "q0"); } \
      if (alias == 1) { RUN(#NAME " d1, d1, d2", "q1"); } \
      if (alias == 2) { RUN(#NAME " d2, d1, d2", "q2"); } \
    } \
  }
#define UNARY(NAME) \
  if (!strcmp(op, #NAME)) { \
    if (width == 32) { \
      if (alias == 0) { RUN(#NAME " s0, s1", "q0"); } \
      else { RUN(#NAME " s1, s1", "q1"); } \
    } else { \
      if (alias == 0) { RUN(#NAME " d0, d1", "q0"); } \
      else { RUN(#NAME " d1, d1", "q1"); } \
    } \
  }
static void row(const char *arm, const char *op, int width, int alias, const char *sample, Bits a, Bits b) {
  const Bits d {0xddddddddddddddddULL, 0xd0d1d2d3d4d5d6d7ULL};
  Bits out {}; uint64_t fpsr = 0; const int64_t integer = 3;
  BINARY(fadd) BINARY(fsub) BINARY(fmul) BINARY(fdiv)
  UNARY(fsqrt) UNARY(scvtf)
  if (!strcmp(op, "scvtf-gpr")) {
    if (width == 32) { RUN("scvtf s0, %x[integer]", "q0"); }
    else { RUN("scvtf d0, %x[integer]", "q0"); }
  }
  if (!strcmp(op, "fcvt")) {
    if (width == 32) {
      if (alias == 0) { RUN("fcvt s0, d1", "q0"); }
      else { RUN("fcvt s1, d1", "q1"); }
    } else {
      if (alias == 0) { RUN("fcvt d0, s1", "q0"); }
      else { RUN("fcvt d1, s1", "q1"); }
    }
  }
  printf("ROW,%s,%s,%d,%d,%s,%016llx,%016llx,%016llx,%016llx,%016llx,%016llx,%016llx,%016llx,%016llx\n",
    arm, op, width, alias, sample, a.lo, a.hi, b.lo, b.hi, d.lo, d.hi, out.lo, out.hi, fpsr);
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const int mode = atoi(argv[1]); if (mode < 0 || mode > 2) return 3;
  const char *arm = mode == 0 ? "outside" : mode == 1 ? "compat" : "compat-fpcr111";
  const auto set = reinterpret_cast<SetCompat>(dlsym(RTLD_DEFAULT, "thread_set_x86_64_compat"));
  if (!set) return 4;
  int afp = -1; size_t size = sizeof(afp); const int sysrc = sysctlbyname("hw.optional.arm.FEAT_AFP", &afp, &size, nullptr, 0);
  const uint64_t original = fpcr(); const int rc = mode ? set(1) : -1;
  if (mode && rc) return 5;
  const uint64_t after_compat = fpcr(); const uint64_t requested = (after_compat & ~7ULL) | (mode == 2 ? 7 : 0);
  fpcr(requested); const uint64_t observed = fpcr();
  printf("META,%s,compat_call=%d,rc=%d,afp_sysrc=%d,afp=%d,original=%016llx,after_compat=%016llx,requested=%016llx,observed=%016llx\n",
    arm, mode != 0, rc, sysrc, afp, original, after_compat, requested, observed);
  for (const int width : {32, 64}) {
    Bits a {width == 32 ? 0xa1a2a3a43f800000ULL : 0x3ff0000000000000ULL, 0xa5a6a7a8a9aaabacULL};
    Bits b {width == 32 ? 0xb1b2b3b440000000ULL : 0x4000000000000000ULL, 0xb5b6b7b8b9babbbcULL};
    for (const char *op : {"fadd", "fsub", "fmul", "fdiv"}) {
      for (int alias = 0; alias < 3; ++alias) row(arm, op, width, alias, "normal", a, b);
      for (const char *sample : {"qnan-qnan", "snan-qnan", "qnan-snan", "snan-snan"}) {
        Bits na = a, nb = b;
        const bool sa = sample[0] == 's', sb = sample[5] == 's';
        if (width == 32) {
          na.lo = (na.lo & 0xffffffff00000000ULL) | (sa ? 0x7f812345 : 0x7fc12345);
          nb.lo = (nb.lo & 0xffffffff00000000ULL) | (sb ? 0xff856789 : 0xffc56789);
        } else {
          na.lo = sa ? 0x7ff00123456789abULL : 0x7ff80123456789abULL;
          nb.lo = sb ? 0xfff0056789abcdefULL : 0xfff8056789abcdefULL;
        }
        for (int alias = 0; alias < 3; ++alias) row(arm, op, width, alias, sample, na, nb);
      }
    }
    for (int alias = 0; alias < 2; ++alias) {
      row(arm, "fsqrt", width, alias, "normal", a, b);
      Bits ints = a; ints.lo = width == 32 ? (a.lo & 0xffffffff00000000ULL) | 3 : 3;
      row(arm, "scvtf", width, alias, "integer3-vector", ints, b);
      Bits convert = a; convert.lo = width == 32 ? 0x3ff0000000000000ULL : 0xa1a2a3a43f800000ULL;
      row(arm, "fcvt", width, alias, "normal", convert, b);
    }
    row(arm, "scvtf-gpr", width, 0, "integer3-gpr", a, b);
  }
  printf("END,%s,fpcr=%016llx\n", arm, fpcr()); fpcr(original); return 0;
}
