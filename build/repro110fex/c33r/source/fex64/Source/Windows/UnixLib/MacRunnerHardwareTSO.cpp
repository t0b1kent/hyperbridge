// SPDX-License-Identifier: MIT
#include "MacRunnerHardwareTSO.h"
#include <mach/mach.h>
#include <pthread.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <time.h>
#include <csignal>
#include <csetjmp>

// This library is shared by ARM64EC and WOW64: two private unixlib statics must
// not make contradictory decisions for the shared process. All initialization
// occurs at ProcessInit, before Context::InitCore, never in a signal handler.
static pthread_once_t Once = PTHREAD_ONCE_INIT;
static uint32_t Mode;
static kern_return_t (*SetCompat)(uint32_t);
// Mach-O TLV first access can allocate through __tlv_bootstrap. The bypass
// entry may run during a Wine exception: reserve native pthread TSD at startup
// instead, and use its existing per-thread storage without loader/TLV work.
static pthread_key_t AdmissionKey;
static bool Initialized;
static uint64_t Attempts, Successes, Failures;
static uint64_t LogDropped;
static constexpr uint64_t PrintLimit = 64;
static uint64_t EntryRows;
static uint64_t GuestThreads;
// Apple AFPCR is implementation-defined. Some chips/OS releases trap the EL0
// read even after x86_64 compat admission (issue #2, Apple M5, macOS 27.0.1).
static uint32_t AppleAFP;
static sigjmp_buf ProbeJump;
static volatile sig_atomic_t ProbeArmed;
static pthread_t ProbeThread;
static struct sigaction ProbePrevious;

static void ProbeHandler(int Signal, siginfo_t* Info, void* Context) {
  if (ProbeArmed && pthread_equal(pthread_self(), ProbeThread)) {
    ProbeArmed = 0;
    siglongjmp(ProbeJump, 1);
  }
  // Not the probe: behave exactly as the handler that was installed before.
  if (ProbePrevious.sa_flags & SA_SIGINFO) {
    if (ProbePrevious.sa_sigaction) ProbePrevious.sa_sigaction(Signal, Info, Context);
    return;
  }
  if (ProbePrevious.sa_handler == SIG_IGN) return;
  if (ProbePrevious.sa_handler == SIG_DFL) {
    signal(Signal, SIG_DFL); // Returning re-executes the faulting instruction.
    return;
  }
  ProbePrevious.sa_handler(Signal);
}

// Runs once, on the admitted initializing thread, before any JIT code exists.
// ForceTrap executes a permanently undefined instruction through the same guard:
// it proves the refusal path on hardware where AFPCR is readable.
static bool ProbeAppleAFPCR(bool ForceTrap) {
  struct sigaction Action {};
  Action.sa_sigaction = ProbeHandler;
  Action.sa_flags = SA_SIGINFO;
  sigemptyset(&Action.sa_mask);
  if (sigaction(SIGILL, &Action, &ProbePrevious)) return false;
  ProbeThread = pthread_self();
  volatile bool Readable = false;
  if (sigsetjmp(ProbeJump, 1) == 0) {
    ProbeArmed = 1;
    uint64_t Value = 0;
    if (ForceTrap) asm volatile("udf #0x4146" ::: "memory");
    else asm volatile("mrs %0, s3_6_c15_c2_5" : "=r"(Value) :: "memory");
    (void)Value;
    ProbeArmed = 0;
    Readable = true;
  }
  ProbeArmed = 0;
  sigaction(SIGILL, &ProbePrevious, nullptr);
  return Readable;
}

static void EntryLog(uint32_t Kind, uint32_t WindowsPid, uint32_t WindowsTid, bool GuestExecution = false) {
  const int SavedErrno = errno;
  uint64_t Tid = 0, Identity = 0;
  pthread_threadid_np(nullptr, &Tid);
  asm volatile("mrs %0, tpidrro_el0" : "=r"(Identity));
  Identity &= ~uint64_t{7};
  timespec UTC {}, Monotonic {};
  const bool UTCValid = clock_gettime(CLOCK_REALTIME, &UTC) == 0;
  const bool MonoValid = clock_gettime(CLOCK_MONOTONIC, &Monotonic) == 0;
  const char* Names[] = {"unknown", "arm64ec-thread-init", "arm64ec-jit-entry", "wow64-thread-init", "wow64-simulate"};
  char Buffer[512]; char* Out = Buffer;
  auto Text = [&](const char* Value) { while (*Value) *Out++ = *Value++; };
  auto Number = [&](uint64_t Value) {
    char Digits[20]; unsigned Count = 0;
    do { Digits[Count++] = '0' + Value % 10; Value /= 10; } while (Value);
    while (Count) *Out++ = Digits[--Count];
  };
  Text(GuestExecution ? "macrunner-fex-hwtso-guest: pid=" : "macrunner-fex-hwtso-entry: pid="); Number(getpid());
  Text(" thread="); Number(Tid); Text(" windows-pid="); Number(WindowsPid);
  Text(" windows-tid="); Number(WindowsTid); Text(" identity="); Number(Identity);
  Text(" kind="); Text(Kind < 5 ? Names[Kind] : "invalid");
  Text(" rc=0 selected="); Number(Mode);
  Text(" actual-state=NOT_READ utc_ns=");
  if (UTCValid) Number(uint64_t(UTC.tv_sec) * 1000000000ULL + UTC.tv_nsec); else Text("FAILED");
  Text(" monotonic_ns=");
  if (MonoValid) Number(uint64_t(Monotonic.tv_sec) * 1000000000ULL + Monotonic.tv_nsec); else Text("FAILED");
  Text(" clock=CLOCK_MONOTONIC\n");
  ssize_t Written; unsigned Retry = 0;
  do { Written = write(STDERR_FILENO, Buffer, Out - Buffer); } while (Written < 0 && errno == EINTR && ++Retry < 8);
  if (Written != Out - Buffer) __atomic_add_fetch(&LogDropped, 1, __ATOMIC_RELAXED);
  __atomic_add_fetch(GuestExecution ? &GuestThreads : &EntryRows, 1, __ATOMIC_RELAXED);
  errno = SavedErrno;
}

static void ThreadLog(uint64_t Tid, kern_return_t RC, uint64_t N, bool Fatal) {
  char Buffer[256]; char *Out = Buffer;
  auto Text = [&](const char *Value) { while (*Value) *Out++ = *Value++; };
  auto Number = [&](uint64_t Value) {
    char Digits[20]; unsigned Count = 0;
    do { Digits[Count++] = '0' + Value % 10; Value /= 10; } while (Value);
    while (Count) *Out++ = Digits[--Count];
  };
  Text(Fatal ? "macrunner-fex-hwtso: FATAL late-thread-admission thread=" : "macrunner-fex-hwtso: thread=");
  Number(Tid); Text(" rc=");
  if (RC < 0) { Text("-"); Number(-int64_t(RC)); } else Number(RC);
  Text(" attempt="); Number(N);
  if (Fatal) {
    Text(" selected="); Number(Mode);
    Text(" success="); Number(__atomic_load_n(&Successes, __ATOMIC_RELAXED));
    Text(" failure="); Number(__atomic_load_n(&Failures, __ATOMIC_RELAXED));
    Text(" shared-JIT-unsafe; terminating process");
  }
  Text("\n");
  // A single bounded write avoids stdio/locale locks in an exception entry.
  ssize_t Written;
  unsigned Retry = 0;
  do { Written = write(STDERR_FILENO, Buffer, Out - Buffer); } while (Written < 0 && errno == EINTR && ++Retry < 8);
  if (Written != Out - Buffer) __atomic_add_fetch(&LogDropped, 1, __ATOMIC_RELAXED);
}

static kern_return_t EnableCurrent() {
  const int SavedErrno = errno;
  const uint64_t N = __atomic_add_fetch(&Attempts, 1, __ATOMIC_RELAXED);
  const kern_return_t RC = SetCompat ? SetCompat(1) : KERN_NOT_SUPPORTED;
  __atomic_add_fetch(RC == KERN_SUCCESS ? &Successes : &Failures, 1, __ATOMIC_RELAXED);
  if (N <= PrintLimit || RC != KERN_SUCCESS) {
    uint64_t Tid = 0;
    pthread_threadid_np(nullptr, &Tid);
    ThreadLog(Tid, RC, N, false);
  }
  errno = SavedErrno;
  return RC;
}

static void Initialize() {
  const char *Value = getenv("MACRUNNER_FEX_HW_TSO");
  uint32_t Requested = 0;
  if (Value && (!strcmp(Value, "1") || !strcmp(Value, "2"))) Requested = Value[0] - '0';
  else if (Value && strcmp(Value, "0"))
    fprintf(stderr, "macrunner-fex-hwtso: invalid-gate software-only\n");
  if (Requested) {
    const int KeyRC = pthread_key_create(&AdmissionKey, nullptr);
    if (KeyRC) {
      fprintf(stderr, "macrunner-fex-hwtso: startup-TSD-failure rc=%d software-only\n", KeyRC);
      Requested = 0;
    }
  }
  if (Requested) {
    (void)pthread_getspecific(AdmissionKey); // Bind getter before any exception entry.
    (void)getpid(); // Entry metadata must not resolve a new symbol in a signal entry.
    timespec BoundClock {};
    (void)clock_gettime(CLOCK_REALTIME, &BoundClock);
    (void)clock_gettime(CLOCK_MONOTONIC, &BoundClock); // Bind both clock paths before exception entry.
    SetCompat = reinterpret_cast<decltype(SetCompat)>(dlsym(RTLD_DEFAULT, "thread_set_x86_64_compat"));
    if (EnableCurrent() == KERN_SUCCESS && pthread_setspecific(AdmissionKey, reinterpret_cast<void*>(1)) == 0) {
      Mode = Requested;
    }
  }
  const char *AFP = getenv("MACRUNNER_FEX_APPLE_AFP");
  const bool AFPRequested = AFP && !strcmp(AFP, "1");
  const char *ProbeMode = getenv("MACRUNNER_FEX_APPLE_AFP_PROBE");
  const bool ForceTrap = ProbeMode && !strcmp(ProbeMode, "trap");
  const char *ProbeResult = "not-run";
  if (Mode && AFPRequested) {
    AppleAFP = ProbeAppleAFPCR(ForceTrap) ? 1 : 0;
    ProbeResult = AppleAFP ? "read" : "sigill";
  }
  fprintf(stderr, "macrunner-fex-hwtso: apple-afp requested=%u selected-tso=%u probe=%s forced-trap=%u enabled=%u\n",
          AFPRequested ? 1u : 0u, Mode, ProbeResult, ForceTrap ? 1u : 0u, AppleAFP);
  fprintf(stderr, "macrunner-fex-hwtso: decision requested=%u selected=%u software=%u immutable=1\n",
          Requested, Mode, Mode != 2);
  fflush(stderr);
  __atomic_store_n(&Initialized, true, __ATOMIC_RELEASE);
}

extern "C" uint32_t macrunner_hwtso_admit() {
  if (!__atomic_load_n(&Initialized, __ATOMIC_ACQUIRE)) pthread_once(&Once, Initialize);
  if (!Mode) return 0;
  if (reinterpret_cast<uintptr_t>(pthread_getspecific(AdmissionKey)) & 1) {
    return Mode;
  }
  const kern_return_t RC = EnableCurrent();
  const int TSDRC = RC == KERN_SUCCESS ? pthread_setspecific(AdmissionKey, reinterpret_cast<void*>(1)) : 0;
  if (RC != KERN_SUCCESS || TSDRC) {
    uint64_t Tid = 0;
    pthread_threadid_np(nullptr, &Tid);
    ThreadLog(Tid, RC != KERN_SUCCESS ? RC : KERN_FAILURE,
              __atomic_load_n(&Attempts, __ATOMIC_RELAXED), true);
    _exit(190);
  }
  return Mode;
}

extern "C" uint32_t macrunner_hwtso_apple_afp() {
  if (!__atomic_load_n(&Initialized, __ATOMIC_ACQUIRE)) pthread_once(&Once, Initialize);
  return Mode ? AppleAFP : 0;
}

extern "C" uint32_t macrunner_hwtso_admit_entry(uint32_t Kind, uint32_t WindowsPid, uint32_t WindowsTid) {
  const uint32_t Selected = macrunner_hwtso_admit();
  if (!Selected) return 0;
  const auto Flags = reinterpret_cast<uintptr_t>(pthread_getspecific(AdmissionKey));
  if (!(Flags & 2)) {
    if (pthread_setspecific(AdmissionKey, reinterpret_cast<void*>(Flags | 2))) {
      uint64_t Tid = 0;
      pthread_threadid_np(nullptr, &Tid);
      ThreadLog(Tid, KERN_FAILURE, __atomic_load_n(&Attempts, __ATOMIC_RELAXED), true);
      _exit(190);
    }
    EntryLog(Kind, WindowsPid, WindowsTid);
  }
  // ThreadInit may prepare a native Wine-only thread. Count actual first guest
  // execution independently, when the preserving JIT guard / WOW64 simulation
  // entry is reached. ARM64EC's frontend cache is zero until this first guard.
  const auto ExecutionFlags = reinterpret_cast<uintptr_t>(pthread_getspecific(AdmissionKey));
  if ((Kind == 2 || Kind == 4) && !(ExecutionFlags & 4)) {
    if (pthread_setspecific(AdmissionKey, reinterpret_cast<void*>(ExecutionFlags | 2 | 4))) {
      uint64_t Tid = 0;
      pthread_threadid_np(nullptr, &Tid);
      ThreadLog(Tid, KERN_FAILURE, __atomic_load_n(&Attempts, __ATOMIC_RELAXED), true);
      _exit(190);
    }
    EntryLog(Kind, WindowsPid, WindowsTid, true);
  }
  return Selected;
}

__attribute__((destructor)) static void Summary() {
  fprintf(stderr, "macrunner-fex-hwtso: exit selected=%u attempts=%llu success=%llu failure=%llu print-limit=%llu log-dropped=%llu entry-rows=%llu guest-threads=%llu\n",
          Mode, (unsigned long long)__atomic_load_n(&Attempts, __ATOMIC_RELAXED),
          (unsigned long long)__atomic_load_n(&Successes, __ATOMIC_RELAXED),
          (unsigned long long)__atomic_load_n(&Failures, __ATOMIC_RELAXED),
          (unsigned long long)PrintLimit, (unsigned long long)__atomic_load_n(&LogDropped, __ATOMIC_RELAXED),
          (unsigned long long)__atomic_load_n(&EntryRows, __ATOMIC_RELAXED),
          (unsigned long long)__atomic_load_n(&GuestThreads, __ATOMIC_RELAXED));
}
