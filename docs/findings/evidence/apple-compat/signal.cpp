#define main arith_baseline_main
#include "probe.cpp"
#undef main
#include <signal.h>
#include <sys/ucontext.h>
#include <unistd.h>
static volatile uintptr_t resume_pc;
static volatile uint64_t other_a,other_b,saved_flags,handler_flags,handler_token;
static volatile sig_atomic_t handler_mode,handler_hit,raw_error;
// The actual platform trampoline moves its sixth kernel argument into X19
// before calling the user handler. It later passes X19 as sigreturn arg2.
// Capture that register before a C prologue can allocate it. ABI evidence is
// abi/native-return.csv, not an assumed cookie or a token guessed from ucontext.
extern "C" void arith_signal_body(int sig,siginfo_t *,void *opaque,uintptr_t token) {
  if(!resume_pc || (sig!=SIGTRAP && sig!=SIGSEGV && sig!=SIGBUS))_exit(70);
  auto *uc=static_cast<ucontext_t *>(opaque);
  const uint64_t flags=uc->uc_mcontext->__ss.__cpsr;
  saved_flags=flags;handler_token=token;handler_hit=1;
  uc->uc_mcontext->__ss.__pc=resume_pc;
  const uint64_t a=other_a,b=other_b;
  if(handler_mode==1) {
    asm volatile("adds x16,%0,%1\n\tmrs x17,nzcv\n\tstr x17,[%2]"
      :: "r"(a),"r"(b),"r"(&handler_flags) : "x16","x17","cc","memory");
    return;
  }
  uint64_t error;
  asm volatile("adds x17,%1,%2\n\tmrs x16,nzcv\n\tstr x16,[%3]\n\t"
    "mov x0,%4\n\tmov x1,#30\n\tmov x2,%5\n\tmov x16,#184\n\t"
    "msr nzcv,%6\n\tsvc #0x80\n\tmov %0,x0"
    : "=&r"(error) : "r"(a),"r"(b),"r"(&handler_flags),"r"(uc),"r"(token),"r"(flags)
    : "x0","x1","x2","x16","x17","cc","memory");
  // Successful sigreturn resumes interrupted code and never returns here.
  // Preserve an ABI failure and return normally; do not sweep syscall args.
  raw_error=error?int(error):-1;
}
extern "C" __attribute__((naked)) void arith_signal_entry(int,siginfo_t *,void *) {
  asm volatile("mov x3,x19\n\tb _arith_signal_body");
}
static Flags sample_signal(unsigned arm,unsigned kind,uint64_t a,uint64_t b) {
  Flags f{};
  if(arm==0) {
    asm volatile("adds %0,%2,%3\n\tmrs %1,nzcv"
      : "=&r"(f.result),"=&r"(f.nzcv) : "r"(a),"r"(b) : "cc");
  } else if(kind==0) {
    asm volatile("adr x16,1f\n\tstr x16,[%4]\n\tadds %0,%2,%3\n\tbrk #0x42\n1:\tmrs %1,nzcv"
      : "=&r"(f.result),"=&r"(f.nzcv) : "r"(a),"r"(b),"r"(&resume_pc) : "x16","cc","memory");
  } else {
    asm volatile("adr x16,1f\n\tstr x16,[%4]\n\tadds %0,%2,%3\n\tldr xzr,[%5]\n1:\tmrs %1,nzcv"
      : "=&r"(f.result),"=&r"(f.nzcv) : "r"(a),"r"(b),"r"(&resume_pc),"r"(uint64_t(0)) : "x16","cc","memory");
  }
  resume_pc=0;return f;
}
static void *signal_worker(void *opaque) {
  auto &w=*static_cast<Worker *>(opaque);w.rc=w.compat?(w.set?w.set(1):-1000):-1;
  const char *mode=w.compat?"compat1":"control";
  printf("MODE,%s,call=%d,arg=%d,rc=%d\n",mode,w.compat,w.compat?1:0,w.rc);
  if(w.compat&&w.rc!=KERN_SUCCESS)return nullptr;
  static constexpr uint64_t aa[]={1,0,15,15},bb[]={0,0,1,3};
  static constexpr unsigned opposite[]={3,2,1,0};
  for(unsigned kind=0;kind<2;++kind) for(unsigned arm=0;arm<3;++arm) {
    unsigned bad=0,saved_bad=0,not_opposite=0,hit_bad=0,errors=0;
    handler_mode=arm;
    for(unsigned i=0;i<10000;++i) {
      const unsigned k=i&3;other_a=aa[opposite[k]];other_b=bb[opposite[k]];
      handler_hit=0;raw_error=0;handler_flags=0;saved_flags=0;
      const unsigned r=aa[k]+bb[k];
      const uint64_t pf=!__builtin_parity(r&255),af=((aa[k]^bb[k]^r)>>4)&1;
      const uint64_t expected=w.compat?((pf<<26)|(af<<27)):0;
      const auto f=sample_signal(arm,kind,aa[k],bb[k]);
      const bool mismatch=(f.nzcv&(3ULL<<26))!=expected;
      bad+=mismatch;
      if(arm) {
        saved_bad+=(saved_flags&(3ULL<<26))!=expected;
        not_opposite+=w.compat&&((handler_flags&(3ULL<<26))!=(expected^(3ULL<<26)));
        hit_bad+=handler_hit!=1;errors+=raw_error!=0;
      }
      if(i<16 || (mismatch&&i<32)) {
        printf("SIGNALROW,%s,%s,%u,%u,%llu,%llu,%016llx,%016llx,%016llx,%016llx,%llu,%d\n",
          mode,kind?"NULL_LOAD":"BRK",arm,i,aa[k],bb[k],expected,saved_flags,handler_flags,f.nzcv,handler_token,raw_error);
      }
    }
    printf("SIGNALSUM,%s,%s,%u,10000,%u,%u,%u,%u,%u\n",mode,kind?"NULL_LOAD":"BRK",arm,
      bad,saved_bad,not_opposite,hit_bad,errors);
  }
  return nullptr;
}
int main() {
  setvbuf(stdout,nullptr,_IOLBF,0);
  struct sigaction sa{};sa.sa_sigaction=arith_signal_entry;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);
  if(sigaction(SIGTRAP,&sa,nullptr)||sigaction(SIGSEGV,&sa,nullptr)||sigaction(SIGBUS,&sa,nullptr))return 2;
  const auto set=reinterpret_cast<SetCompat>(dlsym(RTLD_DEFAULT,"thread_set_x86_64_compat"));
  Worker control{false,set,0},compat{true,set,0};
  for(auto *w:{&control,&compat}) {
    pthread_t thread;if(pthread_create(&thread,nullptr,signal_worker,w)||pthread_join(thread,nullptr))return 3;
  }
  return compat.rc==KERN_SUCCESS?0:4;
}
