// Native NZCV observation only. The sole compatibility argument is 1.
#include <mach/mach.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>

using SetCompat = kern_return_t (*)(uint32_t);
struct Flags { uint64_t result, nzcv; };
enum Op { ADD, SUB, CMP, CMN, AND };
static const char *names[] = {"ADDS", "SUBS", "CMP", "CMN", "ANDS"};

__attribute__((noinline)) static Flags observe(Op op, unsigned width, uint64_t a, uint64_t b) {
  Flags f{};
#define BIN32(insn) asm volatile(insn " %w0, %w2, %w3\n\tmrs %1, nzcv" : "=&r"(f.result), "=&r"(f.nzcv) : "r"(a), "r"(b) : "cc")
#define BIN64(insn) asm volatile(insn " %0, %2, %3\n\tmrs %1, nzcv" : "=&r"(f.result), "=&r"(f.nzcv) : "r"(a), "r"(b) : "cc")
#define CMP32(insn) asm volatile(insn " %w1, %w2\n\tmrs %0, nzcv" : "=&r"(f.nzcv) : "r"(a), "r"(b) : "cc")
#define CMP64(insn) asm volatile(insn " %1, %2\n\tmrs %0, nzcv" : "=&r"(f.nzcv) : "r"(a), "r"(b) : "cc")
  if (width == 32) {
    switch (op) {
    case ADD: BIN32("adds"); break;
    case SUB: BIN32("subs"); break;
    case CMP: CMP32("cmp"); f.result = uint32_t(a-b); break;
    case CMN: CMP32("cmn"); f.result = uint32_t(a+b); break;
    case AND: BIN32("ands"); break;
    }
    f.result = uint32_t(f.result);
  } else {
    switch (op) {
    case ADD: BIN64("adds"); break;
    case SUB: BIN64("subs"); break;
    case CMP: CMP64("cmp"); f.result = a-b; break;
    case CMN: CMP64("cmn"); f.result = a+b; break;
    case AND: BIN64("ands"); break;
    }
  }
  return f;
}
static uint64_t mix(uint64_t v) {
  v += 0x9e3779b97f4a7c15ULL;
  v = (v ^ (v >> 30)) * 0xbf58476d1ce4e5b9ULL;
  v = (v ^ (v >> 27)) * 0x94d049bb133111ebULL;
  return v ^ (v >> 31);
}
static uint64_t write_read(uint64_t v) {
  uint64_t out;
  asm volatile("msr nzcv, %1\n\tmrs %0, nzcv" : "=&r"(out) : "r"(v) : "cc", "memory");
  return out;
}
struct Worker { bool compat; SetCompat set; int rc; };
static void *worker(void *opaque) {
  auto &w = *static_cast<Worker *>(opaque);
  w.rc = w.compat ? (w.set ? w.set(1) : -1000) : -1;
  const char *mode = w.compat ? "compat1" : "control";
  printf("MODE,%s,call=%d,arg=%d,rc=%d\n", mode, w.compat, w.compat ? 1 : 0, w.rc);
  if (w.compat && w.rc != KERN_SUCCESS) return nullptr;
  static constexpr uint64_t directed[] = {0,1,2,3,7,8,15,16,31,127,128,255,
    0x7fffffffULL,0x80000000ULL,0xffffffffULL,0xffffffffffffffffULL};
  for (unsigned width : {32u,64u}) {
    const uint64_t mask = width == 32 ? 0xffffffffULL : ~uint64_t(0);
    for (unsigned i=0; i<64; ++i) {
      const uint64_t a = (i<16 ? directed[i] : mix(i)) & mask;
      const uint64_t b = (i<16 ? directed[(i*7+6)%16] : mix(i+97)) & mask;
      for (unsigned op=0; op<5; ++op) {
        const auto f = observe(Op(op), width, a, b);
        const unsigned pf = !__builtin_parity(unsigned(f.result & 255));
        // AF is architecturally undefined for logical AND: -1, not zero.
        const int af = op == AND ? -1 : int(((a ^ b ^ f.result) >> 4) & 1);
        printf("ROW,%s,%u,%s,%u,%016llx,%016llx,%016llx,%016llx,%u,%d\n",
          mode,width,names[op],i,a,b,f.result,f.nzcv,pf,af);
      }
    }
  }
  for (unsigned bits=0; bits<4; ++bits) {
    const uint64_t requested = 0xa0000000ULL | (uint64_t(bits)<<26);
    printf("WRITE,%s,%u,%016llx,%016llx\n",mode,bits,requested,write_read(requested));
  }
  rusage before{},after{};
  getrusage(RUSAGE_SELF,&before);
  unsigned immediate_bad=0, after_yield_bad=0, yield_errors=0;
  uint64_t after_or=0;
  for (unsigned i=0; i<10000; ++i) {
    const uint64_t requested = uint64_t(i&3)<<26;
    const auto immediate = write_read(requested);
    immediate_bad += (immediate & (3ULL<<26)) != requested;
    uint64_t observed, yield_rc;
    // Read before the compiler can compare the function result. All AAPCS
    // caller-saved integer/vector registers are declared clobbered.
    asm volatile("msr nzcv, %2\n\tbl _sched_yield\n\tmrs %0, nzcv\n\tmov %1, x0"
      : "=&r"(observed), "=&r"(yield_rc) : "r"(requested)
      : "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9",
        "x10","x11","x12","x13","x14","x15","x16","x17","x30",
        "v0","v1","v2","v3","v4","v5","v6","v7","v16","v17",
        "v18","v19","v20","v21","v22","v23","v24","v25","v26",
        "v27","v28","v29","v30","v31","cc","memory");
    yield_errors += yield_rc != 0;
    after_or |= observed;
    after_yield_bad += (observed & (3ULL<<26)) != requested;
  }
  getrusage(RUSAGE_SELF,&after);
  // sched_yield is allowed to clobber flags; this is an observation, not a
  // claim that a changed flag was lost by the scheduler. Context switches
  // are process totals, not proof that every yield switched this thread.
  printf("YIELD,%s,10000,%u,%u,%u,%016llx,%ld,%ld\n",mode,immediate_bad,
    after_yield_bad,yield_errors,after_or,after.ru_nvcsw-before.ru_nvcsw,
    after.ru_nivcsw-before.ru_nivcsw);
  // The libc sched_yield wrapper changes flags. Call the public Mach trap
  // stub directly, without any rc comparison before MRS. SWITCH_OPTION_DEPress
  // is 1 in the installed SDK, timeout=1ms; the compatibility argument stays 1.
  getrusage(RUSAGE_SELF,&before);
  unsigned switch_bad=0,switch_errors=0;
  uint64_t switch_or=0;
  for (unsigned i=0; i<10000; ++i) {
    const uint64_t requested = 0xa0000000ULL | (uint64_t(i&3)<<26);
    uint64_t observed,rc;
    asm volatile("msr nzcv, %2\n\tmov x0, #0\n\tmov x1, #1\n\tmov x2, #1\n\t"
      "bl _thread_switch\n\tmrs %0, nzcv\n\tmov %1, x0"
      : "=&r"(observed), "=&r"(rc) : "r"(requested)
      : "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9",
        "x10","x11","x12","x13","x14","x15","x16","x17","x30",
        "v0","v1","v2","v3","v4","v5","v6","v7","v16","v17",
        "v18","v19","v20","v21","v22","v23","v24","v25","v26",
        "v27","v28","v29","v30","v31","cc","memory");
    switch_or |= observed;
    switch_bad += (observed & (3ULL<<26)) != (requested & (3ULL<<26));
    switch_errors += rc != KERN_SUCCESS;
  }
  getrusage(RUSAGE_SELF,&after);
  printf("SWITCH,%s,10000,%u,%u,%016llx,%ld,%ld\n",mode,switch_bad,
    switch_errors,switch_or,after.ru_nvcsw-before.ru_nvcsw,after.ru_nivcsw-before.ru_nivcsw);
  return nullptr;
}
int main() {
  const auto set = reinterpret_cast<SetCompat>(dlsym(RTLD_DEFAULT,"thread_set_x86_64_compat"));
  printf("PROBE,symbol=%d,argument_limit=1,no_wine=1,no_guest_execution=1\n",set!=nullptr);
  Worker control{false,set,0}, compat{true,set,0};
  for (auto *w : {&control,&compat}) {
    pthread_t thread;
    if (pthread_create(&thread,nullptr,worker,w)) return 2;
    if (pthread_join(thread,nullptr)) return 3;
  }
  return compat.rc == KERN_SUCCESS ? 0 : 4;
}
