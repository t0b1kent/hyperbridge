// SPDX-License-Identifier: MIT
// fex_oracle_runner — сторона FEX JIT в оракуле «интерпретатор HB <-> JIT FEX».
//
// Родной процесс macOS arm64, БЕЗ Wine: FEXCore (копия build/hb-fex-merge-20260928/src,
// см. ../fex-src.PROVENANCE.txt) + этот запускатель. Устроен по образцу ветки _WIN32 у
// Source/Tools/TestHarnessRunner/TestHarnessRunner.cpp: заглушечный обработчик системных
// вызовов, EnableExitOnHLT, CreateThread/ExecuteThread, Reconstruct*.
//
// ВХОД (stdin, одна строка на случай, поля key=value через пробел; порождает oracle.py
// из снимка "initial" интерпретатора HB):
//   id= seed= code=<hex> rip= rflags= mxcsr= rax= rbx= rcx= rdx= rsi= rdi= rsp= rbp= r8=..r15=
//   x0=..x15=<32 hex, порядок байт памяти> y0=..y15=<32 hex, старшие 128 бит YMM> dump=0|1
// Память данных/стека НЕ передаётся: она порождается из seed ТЕМ ЖЕ splitmix64, что у
// hb_diff_case_runner (init_context: fill_random(data,0x2000); fill_random(stack,0x2000)),
// а совпадение доказывается ПО КАЖДОМУ случаю: печатаются init_data_hash/init_stack_hash,
// oracle.py сверяет их с initial.data_hash/stack_hash интерпретатора.
//
// ВЫХОД (stdout, одна JSON-строка на случай).
//
// Раскладка памяти гостя — ТОЖДЕСТВЕННАЯ (адрес гостя = адрес хозяина, как у FEX в бою и
// у hb_diff_case_runner при HB_DIFF_IDENTITY=1): код CODE_BASE (0x4000, только чтение),
// данные DATA_BASE (4 МБ), стек STACK_BASE = DATA_BASE + 16 МБ (0x4000). Базы задаются
// ORACLE_CODE_BASE / ORACLE_DATA_BASE и обязаны совпадать с HB_DIFF_BASE / HB_DIFF_IDENT_BASE.
// Вокруг — ограда PROT_NONE по той же огибающей, что у HB (hb_diff_fence_lo/hi).
//
// КОНЕЦ СЛУЧАЯ. Исполняемым для FEX объявлен ТОЛЬКО [CODE_BASE, CODE_BASE+len) через
// SyscallHandler::QueryGuestExecutableRange. Выборка команды вне него = NoExecOp ->
// Break(SIGSEGV, #PF, X86_PF_INSTR) -> при EnableExitOnHLT чистый выход из диспетчера с
// rip = адрес, куда ушло управление. Это ровно смысл HB: функция подъёма кончается там,
// где кончаются байты случая, а rip = куда ушло управление.
#include "MacHostFeatures.h"
#include "OracleRanges.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include "Interface/Context/Context.h"

#include <mach/mach.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach/mach_vm.h>
#include <mach-o/getsect.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include <atomic>
#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Счётчик FEXCore (OpcodeDispatcher.cpp, гейт MACRUNNER_FEX_DIV_OVERFLOW_DE): сколько DIV/IDIV переведено с полной
// проверкой #DE. В ответе случая — прирост за случай (mr_div_checks), в строке done — итог процесса.
extern std::atomic<uint64_t> MacRunnerDivOverflowChecks;
// То же для гейта MACRUNNER_FEX_SHLD16_CF (OpcodeDispatcher/Flags.cpp): переводы SHLD, где гейт изменил CF.
extern std::atomic<uint64_t> MacRunnerShld16CfApplied;
// То же для гейта MACRUNNER_FEX_NULL_HOST (JIT/BranchOps.cpp): выходы блока с неконстантной целью (RET/RETF/IRET,
// JMP/CALL r/m, POPF, SYSCALL), выпущенные с проверкой «хозяин != 0» (mr_null_host).
extern std::atomic<uint64_t> MacRunnerNullHostChecks;
// То же для гейта MACRUNNER_FEX_DIV_PROVEN_HIGH (OpcodeDispatcher.cpp): DIV/IDIV r32/r64, переведённые с доказанной
// старшей половиной делимого (xor edx,edx / CDQ / CQO в том же блоке), — mr_div_proven.
extern std::atomic<uint64_t> MacRunnerDivProvenHighUsed;

namespace {
constexpr uint64_t CODE_MAP = 0x14000;
constexpr uint64_t DATA_MAP = 0x4000;
constexpr uint64_t DATA_SNAP = DATA_MAP;
constexpr uint64_t STACK_MAP = 0x4000;
constexpr uint64_t STACK_SNAP = STACK_MAP;
constexpr uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;

uint64_t g_code_base, g_data_base, g_stack_base;
uint64_t g_exec_base, g_exec_end;
volatile sig_atomic_t g_exit_span;
using OracleLinkFunction = uint64_t (*)(FEXCore::Core::CpuStateFrame*, FEXCore::Context::ExitFunctionLinkData*);
OracleLinkFunction g_product_link;

// Stand frontend only. Dispatcher spills before calling the linker and fills
// again before branching to its result. Stop through FEX's ordinary spill/return
// path, before FindBlock/CompileBlock can touch an out-of-span destination.
// FEX can inline self-loops: replay therefore closes the recorded byte span,
// rather than claiming to stop after one x86 branch or one loop iteration.
uint64_t oracle_link(FEXCore::Core::CpuStateFrame* Frame, FEXCore::Context::ExitFunctionLinkData* Record) {
  const uint64_t rip = Record->GuestRIP;
  if (rip < g_exec_base || rip >= g_exec_end) {
    Frame->State.rip = rip;
    g_exit_span = 1;
    return Frame->Pointers.ThreadStopHandlerSpillSRA;
  }
  return g_product_link(Frame, Record);
}

FEXCore::Context::Context* g_ctx;
FEXCore::Core::InternalThreadState* volatile g_thread;
FEXCore::ArchHelpers::Arm64::UnalignedHandlerType g_unaligned_type = FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier;

sigjmp_buf g_jmp;
volatile sig_atomic_t g_in_case;
struct FaultRec {
  int sig;
  int code;
  uint64_t addr;
  uint64_t host_pc;
  uint64_t esr;
  int where; // 0 = jit code buffer, 1 = dispatcher, 2 = runtime (C/C++ FEX), 3 = timer
};
volatile FaultRec g_fault;
volatile uint64_t g_unaligned_fixups;
volatile uint64_t g_dispatcher_begin, g_dispatcher_end;
// Стек возвратов FEX (call-ret): у фронтендов он заводится на КАЖДЫЙ поток
// (Source/Windows/Common/CallRetStack.h, LinuxSyscalls/ThreadManager.cpp) — без него
// первый же CALL пишет по callret_sp = 0. Раскладка та же: охрана 16 КБ с обеих сторон,
// исходная точка = база + размер/4 (запас на «возврат без вызова»).
constexpr uint64_t CRS_GUARD = 16384;
volatile uint64_t g_crs_alloc, g_crs_alloc_end, g_crs_default;
volatile uint64_t g_crs_resets;

uint64_t splitmix64_next(uint64_t* state) {
  uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

void fill_random(uint64_t* rng, uint8_t* out, size_t len) {
  size_t off = 0;
  while (off < len) {
    uint64_t v = splitmix64_next(rng);
    size_t n = len - off < sizeof(v) ? len - off : sizeof(v);
    memcpy(out + off, &v, n);
    off += n;
  }
}

uint64_t fnv1a64(const uint8_t* bytes, size_t len) {
  uint64_t h = FNV_OFFSET;
  for (size_t i = 0; i < len; i++) {
    h ^= bytes[i];
    h *= FNV_PRIME;
  }
  return h;
}

int hexval(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

bool parse_hex_bytes(std::string_view s, uint8_t* out, size_t max, size_t* got) {
  if (s.size() % 2) {
    return false;
  }
  size_t n = s.size() / 2;
  if (n > max) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    int a = hexval(s[2 * i]), b = hexval(s[2 * i + 1]);
    if (a < 0 || b < 0) {
      return false;
    }
    out[i] = (uint8_t)((a << 4) | b);
  }
  *got = n;
  return true;
}

void print_hex(FILE* f, const uint8_t* p, size_t n) {
  static const char D[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    fputc(D[p[i] >> 4], f);
    fputc(D[p[i] & 15], f);
  }
}

// ---------------------------------------------------------------------------------------
// Обработчики FEXCore.
class OracleSyscallHandler final : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  OracleSyscallHandler() {
    // Как у обоих Windows-фронтендов FEX (ARM64EC/Module.cpp:645, WOW64/Module.cpp:439).
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }
  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    SyscallHits++;
    return static_cast<uint64_t>(-ENOSYS);
  }
  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t) override {
    return std::nullopt;
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    if (Address >= g_exec_base && Address < g_exec_end) {
      return {g_exec_base, g_exec_end - g_exec_base, false};
    }
    return {Address, 0, false};
  }
  uint64_t SyscallHits {};
};

class OracleSignalDelegator final : public FEXCore::SignalDelegator, public FEXCore::Allocator::FEXAllocOperators {
public:
  const FEXCore::SignalDelegatorConfig& Cfg() const {
    return GetConfig();
  }
};

// Слой настроек из окружения FEX_* (как TestEnvLoader у TestHarnessRunner).
const fextl::vector<std::pair<const char*, FEXCore::Config::ConfigOption>> EnvConfigLookup = {{
#define OPT_BASE(type, group, enum, json, default) {"FEX_" #enum, FEXCore::Config::ConfigOption::CONFIG_##enum},
#include <FEXCore/Config/ConfigValues.inl>
}};

class OracleEnvLayer final : public FEXCore::Config::Layer {
public:
  explicit OracleEnvLayer(char** envp)
    : FEXCore::Config::Layer(FEXCore::Config::LayerType::LAYER_ENVIRONMENT) {
    for (char** e = envp; e && *e; ++e) {
      std::string_view kv(*e);
      auto eq = kv.find('=');
      if (eq == std::string_view::npos || kv.substr(0, 4) != "FEX_") {
        continue;
      }
      Env.emplace_back(fextl::string(kv.substr(0, eq)), fextl::string(kv.substr(eq + 1)));
    }
    Load();
  }
  void Load() override {
    for (auto& [KeyS, ValS] : Env) {
      std::string_view Key = KeyS;
      std::string_view Value_View = ValS;
      std::optional<fextl::string> Value;
#define ENVLOADER
#include <FEXCore/Config/ConfigOptions.inl>
      fextl::string Final = Value ? *Value : fextl::string(Value_View);
      for (auto& it : EnvConfigLookup) {
        if (Key == it.first) {
          Set(it.second, Final);
          Applied.emplace_back(fextl::string(Key) + "=" + Final);
        }
      }
    }
  }
  fextl::vector<std::pair<fextl::string, fextl::string>> Env;
  fextl::vector<fextl::string> Applied;
};

void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  if (Level <= LogMan::DebugLevels::ERROR) fprintf(stderr, "fex-log %s %s\n", LogMan::DebugLevelStr(Level), Message);
}
void AssertHandler(const char* Message) {
  fprintf(stderr, "fex-assert %s\n", Message);
  fflush(nullptr);
}

// ---------------------------------------------------------------------------------------
// Сигналы хозяина.
bool pc_in_jit(uint64_t pc) {
  auto* T = g_thread;
  return T && g_ctx && g_ctx->IsAddressInCodeBuffer(T, pc);
}
bool pc_in_dispatcher(uint64_t pc) {
  return pc >= g_dispatcher_begin && pc < g_dispatcher_end;
}

#ifdef ARCHITECTURE_arm64ec
// Stand frontend only: Darwin reserves x18. Keep generated EC bytes unchanged
// and supply the two Windows TEB fields when their loads fault. No allocation,
// loader walk, initialization or guest-state reconstruction in the handler.
constexpr uint64_t EC_BITMAP_BASE = 0x600000000000ULL;
constexpr uint64_t EC_BITMAP_BYTES = 1ULL << 49; // Full uint64 RIP / 4KiB / 8 bits; virtual, never mapped.
alignas(16) uint64_t g_ec_peb[0x370 / 8] = {};
alignas(16) uint64_t g_ec_cpu_area[8] = {};
volatile sig_atomic_t g_ec_teb_loads;
volatile sig_atomic_t g_ec_bitmap_loads;
volatile sig_atomic_t g_ec_bitmap_noncanonical;

bool supply_ec_frontend_load(ucontext_t* uc, uint64_t pc, bool jit, bool disp, uint64_t fault_address) {
  if (!jit && !disp) return false;
  auto& ss = uc->uc_mcontext->__ss;
  const uint32_t op = *reinterpret_cast<const uint32_t*>(pc);
  const unsigned rt = op & 31, rn = (op >> 5) & 31;
  if (rt >= 29 || rn >= 29) return false;
  // LDR Xt,[x18,#imm12*8], exact two fields from Arm64Emitter.h.
  if ((op & 0xffc00000U) == 0xf9400000U && rn == 18) {
    const uint64_t offset = ((op >> 10) & 4095) * 8;
    if (fault_address != ss.__x[18] + offset) return false;
    uint64_t value;
    if (offset == 0x60) value = reinterpret_cast<uint64_t>(g_ec_peb);
    else if (offset == 0x1788) value = reinterpret_cast<uint64_t>(g_ec_cpu_area);
    else return false;
    ss.__x[rt] = value;
    ss.__pc = pc + 4;
    ++g_ec_teb_loads;
    return true;
  }
  // Dispatcher LDR Xt,[Xn,Xm,LSL #3] over an all-zero EC bitmap: every
  // HBCAP address denotes x86 code. The synthetic bitmap has no host mapping.
  if (disp && (op & 0xffe0fc00U) == 0xf8607800U && ss.__x[rn] == EC_BITMAP_BASE) {
    const unsigned rm = (op >> 16) & 31;
    if (rm >= 29) return false;
    const uint64_t offset = ss.__x[rm] << 3;
    if (offset >= EC_BITMAP_BYTES || fault_address != EC_BITMAP_BASE + offset) return false;
    // At this exact dispatcher instruction all static guest registers are live
    // and State.rip is the next guest PC. Redirect to the existing spill/return
    // stub; no reconstruction, allocation, translation or guest fetch here.
    // Includes same-page exits and noncanonical RET/JMP/CALL destinations.
    auto* Frame = g_thread->CurrentFrame;
    if (Frame->State.rip < g_exec_base || Frame->State.rip >= g_exec_end) {
      g_exit_span = 1;
      ss.__pc = Frame->Pointers.ThreadStopHandlerSpillSRA;
      return true;
    }
    ss.__x[rt] = 0;
    ss.__pc = pc + 4;
    ++g_ec_bitmap_loads;
    if (offset >= (1ULL << 32)) ++g_ec_bitmap_noncanonical;
    return true;
  }
  return false;
}
#endif

void host_handler(int sig, siginfo_t* info, void* uctx_) {
  auto* uc = static_cast<ucontext_t*>(uctx_);
  auto& ss = uc->uc_mcontext->__ss;
  const uint64_t pc = ss.__pc;
  const uint64_t esr = uc->uc_mcontext->__es.__esr;
  const bool jit = pc_in_jit(pc);
  const bool disp = !jit && pc_in_dispatcher(pc);

  if (!g_in_case) {
    // Отказ вне случая — это отказ запускателя, не гостя: умираем громко.
    fprintf(stderr, "fex-oracle: host signal %d outside case, pc=0x%llx addr=%p\n", sig, (unsigned long long)pc, info ? info->si_addr : nullptr);
    signal(sig, SIG_DFL);
    return;
  }

#ifdef ARCHITECTURE_arm64ec
  if ((sig == SIGSEGV || sig == SIGBUS) && info &&
      supply_ec_frontend_load(uc, pc, jit, disp, reinterpret_cast<uint64_t>(info->si_addr))) return;
#endif

  // Отказ на охране стека возвратов — как CallRetStack::HandleAccessViolation фронтендов:
  // сбросить x25 (REG_CALLRET_SP вне ARM64EC) в исходную точку и продолжить.
  if ((sig == SIGSEGV || sig == SIGBUS) && jit && info) {
    const uint64_t fa = reinterpret_cast<uint64_t>(info->si_addr);
    if (fa >= g_crs_alloc && fa < g_crs_alloc_end) {
      ss.__x[25] = g_crs_default;
      g_crs_resets = g_crs_resets + 1;
      return;
    }
  }
  // Невыровненный доступ выпущенного кода (DFSC=0x21 — alignment fault): штатный путь FEX,
  // такой же, как у фронтендов (ARM64EC/Module.cpp HandleUnalignedAccess): перешить и продолжить.
  if (sig == SIGBUS && jit && ((esr >> 26) & 0x3f) == 0x24 && (esr & 0x3f) == 0x21) {
    auto Result = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(g_thread, g_unaligned_type, pc, &ss.__x[0], true);
    if (Result) {
      ss.__pc = pc + *Result;
      g_unaligned_fixups = g_unaligned_fixups + 1;
      return;
    }
  }

  g_fault.sig = sig;
  g_fault.code = info ? info->si_code : 0;
  g_fault.addr = info ? reinterpret_cast<uint64_t>(info->si_addr) : 0;
  g_fault.host_pc = pc;
  g_fault.esr = esr;
  g_fault.where = (sig == SIGALRM || sig == SIGVTALRM) ? 3 : (jit ? 0 : (disp ? 1 : 2));
  siglongjmp(g_jmp, 1);
}

void install_handlers() {
  struct sigaction sa {};
  sa.sa_sigaction = host_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  for (int s : {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE, SIGALRM, SIGVTALRM}) {
    sigaction(s, &sa, nullptr);
  }
}

// ---------------------------------------------------------------------------------------
// Память гостя.
uint64_t g_guest_base = 0x80000000000ULL;
uint64_t host_address(uint64_t guest) { return g_guest_base + guest; }
extern "C" uint64_t Stand32GuestBase() { return g_guest_base; }
extern "C" unsigned Stand32Mutation() {
  const char* value = getenv("STAND32_MUTATION");
  if (!value) return 0;
  return !strcmp(value,"base") ? 1 : !strcmp(value,"sign") ? 2 : !strcmp(value,"carry4g") ? 3 : 0;
}
std::vector<std::pair<uint64_t,uint64_t>> g_reserved;
bool map_fixed(uint64_t base, uint64_t size, int prot) {
  base = host_address(base);
  void* p = mmap(reinterpret_cast<void*>(base), size, prot, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
  if (p == MAP_FAILED || reinterpret_cast<uint64_t>(p) != base) {
    fprintf(stderr, "fex-oracle: mmap 0x%llx+0x%llx failed (%p, errno %d)\n", (unsigned long long)base, (unsigned long long)size, p, errno);
    return false;
  }
  return true;
}

bool unowned_range_free(uint64_t lo, uint64_t hi) {
  lo = host_address(lo); hi = host_address(hi);
  const auto* pagezero = getsegbyname("__PAGEZERO");
  while (lo < hi) {
    mach_vm_address_t r = lo;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info {};
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
    if (kr == KERN_INVALID_ADDRESS) return true;
    if (kr != KERN_SUCCESS) return false;
    if (r >= hi) return true;
    // With Apple's low32 entitlement the main executable's untouched PAGEZERO
    // reservation is legally replaceable by guest mappings. A real PROT_NONE
    // allocation still has nonzero max_protection and must remain a collision.
    // Do not infer availability from a low address or current protection alone.
    const bool untouched_pagezero = !g_guest_base && pagezero &&
      pagezero->vmaddr == 0 && pagezero->vmsize <= 0x100000000ULL &&
      pagezero->initprot == VM_PROT_NONE && pagezero->maxprot == VM_PROT_NONE &&
      info.protection == VM_PROT_NONE && info.max_protection == VM_PROT_NONE &&
      lo >= static_cast<uint64_t>(getpagesize()) && hi <= pagezero->vmsize;
    if (!untouched_pagezero || !sz || r + sz <= lo) return false;
    lo = r + sz;
  }
  return true;
}

bool range_free(uint64_t lo, uint64_t hi) {
  // Every retained interval is ours for the lifetime of this process. Check
  // gaps independently: a new code arena can partly overlap an older one.
  for (const auto& [a,b] : g_reserved) {
    if (b <= lo) continue;
    if (a >= hi) break;
    if (lo < a && !unowned_range_free(lo, a)) return false;
    lo = std::max(lo, b);
    if (lo >= hi) return true;
  }
  return lo >= hi || unowned_range_free(lo, hi);
}

bool map_guest(uint64_t base, uint64_t size, int prot) {
  if (base > UINT64_MAX - size || !range_free(base, base + size) || !map_fixed(base, size, prot)) return false;
  g_reserved.emplace_back(base, base + size);
  std::sort(g_reserved.begin(), g_reserved.end());
  size_t used = 0;
  for (const auto range : g_reserved) {
    if (used && range.first <= g_reserved[used - 1].second)
      g_reserved[used - 1].second = std::max(range.second, g_reserved[used - 1].second);
    else g_reserved[used++] = range;
  }
  g_reserved.resize(used);
  return true;
}

void retain_guest(uint64_t base, uint64_t size) {
  // Release physical contents, but never expose a low32 hole to host allocators
  // between batch cases. MAP_FIXED replaces only an interval already owned.
  if (!map_fixed(base, size, PROT_NONE)) {
    fprintf(stderr, "stand32: retaining guest reservation failed\n");
    _exit(2);
  }
}

// Ограда PROT_NONE по дырам [lo,hi) — та же огибающая, что hb_diff_fence (HB): обращение
// за пределами областей гостя всегда даёт отказ хозяина, а не случайный успех.
uint64_t g_fence_bytes, g_fence_holes;
void fence(uint64_t lo, uint64_t hi) {
  mach_vm_address_t a = lo;
  while (a < hi) {
    mach_vm_address_t r = a, gap_end, next;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
    if (kr != KERN_SUCCESS || r >= hi) {
      gap_end = hi;
      next = hi;
    } else {
      gap_end = r > a ? r : a;
      next = r + sz;
    }
    if (gap_end > a) {
      void* p = mmap(reinterpret_cast<void*>(a), gap_end - a, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_FIXED | MAP_NORESERVE, -1, 0);
      if (p != MAP_FAILED && reinterpret_cast<uint64_t>(p) == a) {
        g_fence_holes++;
        g_fence_bytes += gap_end - a;
      }
    }
    a = next > a ? next : a + 0x4000;
  }
}

// ---------------------------------------------------------------------------------------
struct Case {
  uint64_t id {};
  uint64_t seed {};
  uint8_t code[65536];
  size_t code_len {};
  uint64_t rip {}, rflags {}, mxcsr {0x1f80};
  uint64_t xlen {}; // длина ИСПОЛНЯЕМОЙ части (0 = весь код); см. oracle.py: граница первого блока HB
  uint64_t fsbase {}, gsbase {}; // базы сегментов (у HB обе 0); для отдельных проб FEX
  uint64_t csbase {}, ssbase {}, dsbase {}, esbase {};
  uint64_t selectors[6] {8,16,16,16,24,32}; // CS SS DS ES FS GS
  uint8_t descriptors[48] {};
  bool have_descriptors {};
  uint64_t gpr[16] {}; // порядок FEX: rax rcx rdx rbx rsp rbp rsi rdi r8..r15
  uint8_t xmm[16][16] {};
  uint8_t ymmh[16][16] {};
  uint64_t fcw {0x37f}, fsw {}, ftw {};
  uint8_t mm[128] {};
  std::string pages;
  fextl::vector<std::pair<uint64_t, uint64_t>> mapped;
  fextl::vector<uint64_t> input_pages;
  bool dump {};
  bool have_expected_memory {};
  uint64_t expect_data {}, expect_stack {};
  fextl::vector<std::pair<uint64_t, uint64_t>> watches;
  uint32_t have {};
  // Заплаты памяти после засева (как sse-mem у hb_sse_oracle): mem=<адрес>:<hex>.
  struct Patch {
    uint64_t addr;
    uint8_t bytes[64];
    size_t len;
  } patch[8];
  unsigned npatch {};
};

// Имена HB -> индекс FEX (X86State::REG_*).
int gpr_index(std::string_view n) {
  static const char* names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                  "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
  for (int i = 0; i < 16; i++) {
    if (n == names[i]) {
      return i;
    }
  }
  return -1;
}
const char* gpr_name(int i) {
  static const char* names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                  "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
  return names[i];
}

bool parse_case(char* line, Case& c, std::string& err) {
  char* save = nullptr;
  for (char* tok = strtok_r(line, " \t\r\n", &save); tok; tok = strtok_r(nullptr, " \t\r\n", &save)) {
    char* eq = strchr(tok, '=');
    if (!eq) {
      err = std::string("no '=' in ") + tok;
      return false;
    }
    *eq = 0;
    std::string_view k(tok), v(eq + 1);
    auto num = [&](uint64_t& out) {
      out = strtoull(eq + 1, nullptr, 0);
    };
    if (k == "id") {
      num(c.id);
    } else if (k == "seed") {
      num(c.seed);
    } else if (k == "code") {
      if (!parse_hex_bytes(v, c.code, sizeof(c.code), &c.code_len) || c.code_len == 0) {
        err = "bad code";
        return false;
      }
      c.have |= 1;
    } else if (k == "rip") {
      num(c.rip);
      c.have |= 2;
    } else if (k == "rflags") {
      num(c.rflags);
      c.have |= 4;
    } else if (k == "mxcsr") {
      num(c.mxcsr);
    } else if (k == "xlen") {
      num(c.xlen);
    } else if (k == "fsbase") {
      num(c.fsbase);
    } else if (k == "gsbase") {
      num(c.gsbase);
    } else if (k == "csbase") { num(c.csbase);
    } else if (k == "ssbase") { num(c.ssbase);
    } else if (k == "dsbase") { num(c.dsbase);
    } else if (k == "esbase") { num(c.esbase);
    } else if (k == "cs") { num(c.selectors[0]);
    } else if (k == "ss") { num(c.selectors[1]);
    } else if (k == "ds") { num(c.selectors[2]);
    } else if (k == "es") { num(c.selectors[3]);
    } else if (k == "fs") { num(c.selectors[4]);
    } else if (k == "gs") { num(c.selectors[5]);
    } else if (k == "segdesc") {
      size_t got = 0;
      if (!parse_hex_bytes(v, c.descriptors, sizeof(c.descriptors), &got) || got != sizeof(c.descriptors)) {
        err = "bad segdesc"; return false;
      }
      c.have_descriptors = true;
    } else if (k == "pages") {
      c.pages = v;
    } else if (k == "fcw") {
      num(c.fcw);
    } else if (k == "fsw") {
      num(c.fsw);
    } else if (k == "ftw") {
      num(c.ftw);
    } else if (k == "mm") {
      size_t got = 0;
      if (!parse_hex_bytes(v, c.mm, sizeof(c.mm), &got) || got != sizeof(c.mm)) { err = "bad mm"; return false; }
    } else if (k == "mem") {
      auto colon = v.find(':');
      if (colon == std::string_view::npos || c.npatch >= 8) {
        err = "bad mem";
        return false;
      }
      auto& P = c.patch[c.npatch];
      P.addr = strtoull(std::string(v.substr(0, colon)).c_str(), nullptr, 0);
      if (!parse_hex_bytes(v.substr(colon + 1), P.bytes, sizeof(P.bytes), &P.len) || P.len == 0) {
        err = "bad mem bytes";
        return false;
      }
      c.npatch++;
    } else if (k == "dump") {
      c.dump = v == "1";
    } else if (k == "expect_data") {
      num(c.expect_data);
      c.have_expected_memory = true;
    } else if (k == "expect_stack") {
      num(c.expect_stack);
    } else if (k == "watch") {
      const auto colon = v.find(':');
      if (colon == std::string_view::npos || c.watches.size() >= 8192) { err = "bad watch"; return false; }
      const uint64_t A = strtoull(std::string(v.substr(0, colon)).c_str(), nullptr, 0);
      const uint64_t N = strtoull(std::string(v.substr(colon + 1)).c_str(), nullptr, 0);
      const bool Arena = (A >= g_data_base && A <= g_data_base + DATA_MAP - N) ||
                         (A >= g_stack_base && A <= g_stack_base + STACK_MAP - N);
      if (!N || N > DATA_MAP || (c.pages.empty() && !Arena)) {
        err = "watch outside arena"; return false;
      }
      c.watches.emplace_back(A, N);
    } else if (k.size() >= 2 && (k[0] == 'x' || k[0] == 'y') && k[1] >= '0' && k[1] <= '9') {
      int i = atoi(tok + 1);
      size_t got = 0;
      if (i < 0 || i > 15 || !parse_hex_bytes(v, k[0] == 'x' ? c.xmm[i] : c.ymmh[i], 16, &got) || got != 16) {
        err = std::string("bad vec ") + tok;
        return false;
      }
    } else {
      int gi = gpr_index(k);
      if (gi < 0) {
        err = std::string("unknown key ") + tok;
        return false;
      }
      num(c.gpr[gi]);
    }
  }
  if ((c.have & 7) != 7) {
    err = "missing code/rip/rflags";
    return false;
  }
  return true;
}

const char* sig_name(int s) {
  switch (s) {
  case SIGSEGV: return "SIGSEGV";
  case SIGBUS: return "SIGBUS";
  case SIGILL: return "SIGILL";
  case SIGTRAP: return "SIGTRAP";
  case SIGFPE: return "SIGFPE";
  case SIGALRM: return "SIGALRM";
  case SIGVTALRM: return "SIGVTALRM";
  default: return "?";
  }
}

bool g_dirty;
unsigned g_timeout_ms = 2000;
FEXCore::Core::CPUState::gdt_segment g_gdt[8192], g_ldt[8192];

void init_gdt() {
  memset(g_gdt, 0, sizeof(g_gdt));
  // 0x08 (как у HB) и DEFAULT_USER_CS (6, как у ARM64EC) — 64-битный код; 0x10 — данные.
  for (unsigned idx : {1u, (unsigned)FEXCore::Core::CPUState::DEFAULT_USER_CS}) {
    auto& G = g_gdt[idx];
    FEXCore::Core::CPUState::SetGDTBase(&G, 0);
    FEXCore::Core::CPUState::SetGDTLimit(&G, 0xFFFFFU);
    G.L = 0;
    G.D = 1;
    G.P = 1;
    G.S = 1;
    G.Type = 0xB;
  }
  auto& D = g_gdt[2];
  FEXCore::Core::CPUState::SetGDTBase(&D, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&D, 0xFFFFFU);
  D.P = 1;
  D.S = 1;
  D.Type = 0x3;
}

void run_case(Case& c, OracleSyscallHandler& SH) {
  g_code_base = c.rip & ~0x3fffULL;
  // Fixture arenas share the guest address space with captured images. A prior
  // sparse page or code arena may have retained part of them as PROT_NONE.
  // Reacquire owned intervals before touching them; never replace host memory.
  if (!map_guest(g_data_base, DATA_MAP, PROT_READ | PROT_WRITE) ||
      !map_guest(g_stack_base, STACK_MAP, PROT_READ | PROT_WRITE)) {
    printf("{\"id\":%" PRIu64 ",\"status\":\"host_fixture_collision\",\"state_valid\":false}\n", c.id);
    fflush(stdout);
    return;
  }
  if (!map_guest(g_code_base, CODE_MAP, PROT_READ | PROT_WRITE)) {
    printf("{\"id\":%" PRIu64 ",\"status\":\"host_code_collision\",\"state_valid\":false}\n", c.id);
    fflush(stdout);
    return;
  }
  uint8_t* code = reinterpret_cast<uint8_t*>(host_address(g_code_base));
  uint8_t* data = reinterpret_cast<uint8_t*>(host_address(g_data_base));
  uint8_t* stack = reinterpret_cast<uint8_t*>(host_address(g_stack_base));

  // Данные и стек: нули + засев тем же splitmix64, что у HB init_context.
  memset(data, 0, DATA_MAP);
  memset(stack, 0, STACK_MAP);
  uint64_t rng = c.seed;
  fill_random(&rng, data, DATA_SNAP);
  fill_random(&rng, stack, STACK_SNAP);
  // Install code after fixture initialization: a captured DLL can occupy the
  // same addresses. Captured sparse pages below then supply the real contents.
  mprotect(code, CODE_MAP, PROT_READ | PROT_WRITE);
  memset(code, 0, CODE_MAP);
  memcpy(reinterpret_cast<void*>(host_address(c.rip)), c.code, c.code_len);
  mprotect(code, CODE_MAP, PROT_READ);
  // Sparse 16KiB pages selected by the reference from the immutable guest
  // image. Batch cases retain owned virtual reservations; host mappings remain
  // collision failures and are never replaced.
  if (!c.pages.empty()) {
    FILE* f = fopen(c.pages.c_str(), "rb");
    char magic[8]; uint64_t count = 0;
    bool ok = f && fread(magic, 1, 8, f) == 8 && !memcmp(magic, "HBPAGES1", 8) &&
              fread(&count, 8, 1, f) == 1 && count <= 16384;
    for (uint64_t i = 0; ok && i < count; ++i) {
      uint64_t addr = 0; uint8_t bytes[16384];
      ok = fread(&addr, 8, 1, f) == 1 && fread(bytes, 1, sizeof(bytes), f) == sizeof(bytes) && !(addr & 16383);
      if (!ok) break;
      c.input_pages.push_back(addr);
      if (addr >= g_code_base && addr + sizeof(bytes) <= g_code_base + CODE_MAP) {
        mprotect((void*)host_address(addr), sizeof(bytes), PROT_READ | PROT_WRITE);
      } else {
        ok = map_guest(addr, sizeof(bytes), PROT_READ | PROT_WRITE);
        if (!ok) break;
        c.mapped.emplace_back(addr, sizeof(bytes));
      }
      memcpy((void*)host_address(addr), bytes, sizeof(bytes));
    }
    if (f) fclose(f);
    if (!ok) {
      for (const auto& [a, n] : c.mapped) retain_guest(a, n);
      retain_guest(g_code_base, CODE_MAP);
      printf("{\"id\":%" PRIu64 ",\"status\":\"guest_image_mapping_FAILED\",\"state_valid\":false}\n", c.id);
      fflush(stdout); return;
    }
    // Both engines execute the same selected HBCAP bytes and sentinel.
    mprotect(code, CODE_MAP, PROT_READ | PROT_WRITE);
    memcpy((void*)host_address(c.rip), c.code, c.code_len);
    // The wire input already includes the one sentinel. A second HLT here
    // corrupts the next byte of a captured code page and creates a false diff.
    // A real PE's .data can share this broad frontend code arena. Guest
    // protection is checked against captured 4KiB metadata by the oracle;
    // marking the whole 80KiB arena RO would fault valid .data stores.
    mprotect(code, CODE_MAP, PROT_READ | PROT_WRITE);
    auto owned_ranges = c.mapped;
    owned_ranges.emplace_back(g_code_base, CODE_MAP);
    for (const auto& [a, n] : c.watches) {
      const bool valid = oracle_range_covered(a, n, owned_ranges);
      if (!valid) {
        for (const auto& [a, n] : c.mapped) retain_guest(a, n);
        retain_guest(g_code_base, CODE_MAP);
        printf("{\"id\":%" PRIu64 ",\"status\":\"watch_mapping_FAILED\",\"state_valid\":false}\n", c.id);
        fflush(stdout); return;
      }
    }
  }
  for (unsigned p = 0; p < c.npatch; p++) {
    const auto& P = c.patch[p];
    const bool in_data = P.addr >= g_data_base && P.addr + P.len <= g_data_base + DATA_MAP;
    const bool in_stack = P.addr >= g_stack_base && P.addr + P.len <= g_stack_base + STACK_MAP;
    if (in_data || in_stack) {
      memcpy(reinterpret_cast<void*>(host_address(P.addr)), P.bytes, P.len);
    }
  }
  const uint64_t init_data_hash = fnv1a64(data, DATA_SNAP);
  const uint64_t init_stack_hash = fnv1a64(stack, STACK_SNAP);

  g_exec_base = c.rip;
  g_exec_end = c.rip + ((c.xlen && c.xlen <= c.code_len) ? c.xlen : c.code_len);
  // Earlier cases may have compiled a NoExec exit at this future entry RIP.
  // Invalidate AFTER mapping the new bytes and BEFORE entering a new thread.
  {
    std::scoped_lock Lock(g_ctx->GetCodeInvalidationMutex());
    g_ctx->InvalidateCodeBuffersCodeRange(g_code_base, CODE_MAP);
  }

  auto* Thread = g_ctx->CreateThread(c.rip, c.gpr[FEXCore::X86State::REG_RSP]);
  auto& S = Thread->CurrentFrame->State;
  g_product_link = reinterpret_cast<OracleLinkFunction>(Thread->CurrentFrame->Pointers.ExitFunctionLink);
  Thread->CurrentFrame->Pointers.ExitFunctionLink = reinterpret_cast<uint64_t>(oracle_link);
#ifdef ARCHITECTURE_arm64ec
  g_ec_cpu_area[0x30 / 8] = reinterpret_cast<uint64_t>(Thread->CurrentFrame);
#endif
  {
    const uint64_t Size = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
    void* A = mmap(nullptr, Size + 2 * CRS_GUARD, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (A == MAP_FAILED) {
      fprintf(stderr, "fex-oracle: call-ret stack mmap failed\n");
      _exit(6);
    }
    uint8_t* Base = static_cast<uint8_t*>(A) + CRS_GUARD;
    mprotect(Base, Size, PROT_READ | PROT_WRITE);
    Thread->CallRetStackBase = Base;
    g_crs_alloc = reinterpret_cast<uint64_t>(A);
    g_crs_alloc_end = g_crs_alloc + Size + 2 * CRS_GUARD;
    g_crs_default = reinterpret_cast<uint64_t>(Base) + Size / 4;
    S.callret_sp = g_crs_default;
  }
  for (int i = 0; i < 16; i++) {
    S.gregs[i] = c.gpr[i];
  }
  S.rip = c.rip;
  S.mxcsr = static_cast<uint32_t>(c.mxcsr);
  S.FCW = c.fcw;
  S.AbridgedFTW = c.ftw;
  memcpy(S.mm, c.mm, sizeof(c.mm));
  for (unsigned i = 0; i < 16; ++i) if (i < 11 || i > 13) S.flags[FEXCore::X86State::X87FLAG_BASE + i] = (c.fsw >> i) & 1;
  S.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (c.fsw >> 11) & 7;
  // Селекторы как у HB (init_context): cs=0x08, остальные 0x10; базы fs/gs = 0.
  // Режим декодирования FEX берёт из дескриптора CS (Frontend.cpp: GetSegmentFromIndex(cs_idx).L),
  // поэтому нужна таблица: как у ARM64EC/Module.cpp (GDT на 32 записи, LDT = та же таблица).
  S.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = g_gdt;
  S.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = g_ldt;
  const uint64_t bases[6] {c.csbase,c.ssbase,c.dsbase,c.esbase,c.fsbase,c.gsbase};
  for (unsigned i=0;i<6;++i) {
    if (c.selectors[i] > 65535 || bases[i] > UINT32_MAX) _exit(2);
    auto* descriptor = FEXCore::Core::CPUState::GetSegmentFromIndex(S, c.selectors[i]);
    if (c.have_descriptors) memcpy(descriptor, c.descriptors+8*i, 8);
    else {
      *descriptor = g_gdt[i==0 ? 1 : 2];
      FEXCore::Core::CPUState::SetGDTBase(descriptor, bases[i]);
      descriptor->D = 1;
    }
  }
  S.cs_idx=c.selectors[0]; S.ss_idx=c.selectors[1]; S.ds_idx=c.selectors[2];
  S.es_idx=c.selectors[3]; S.fs_idx=c.selectors[4]; S.gs_idx=c.selectors[5];
  S.cs_cached=c.csbase; S.ss_cached=c.ssbase; S.ds_cached=c.dsbase; S.es_cached=c.esbase;
  S.fs_cached = c.fsbase;
  S.gs_cached = c.gsbase;
  g_ctx->SetFlagsFromCompactedEFLAGS(Thread, static_cast<uint32_t>(c.rflags));
  __uint128_t xl[16], yh[16];
  for (int i = 0; i < 16; i++) {
    memcpy(&xl[i], c.xmm[i], 16);
    memcpy(&yh[i], c.ymmh[i], 16);
  }
  g_ctx->SetXMMRegistersFromState(Thread, xl, yh);
  Thread->CurrentFrame->SynchronousFaultData = {};

  memset((void*)&g_fault, 0, sizeof(g_fault));
  g_exit_span = 0;
  const uint64_t fix0 = g_unaligned_fixups;
  const uint64_t sys0 = SH.SyscallHits;
  const uint64_t divchk0 = MacRunnerDivOverflowChecks.load(std::memory_order_relaxed);
  const uint64_t shld0 = MacRunnerShld16CfApplied.load(std::memory_order_relaxed);
  const uint64_t nullhost0 = MacRunnerNullHostChecks.load(std::memory_order_relaxed);
  const uint64_t divproven0 = MacRunnerDivProvenHighUsed.load(std::memory_order_relaxed);
  g_thread = Thread;

  struct itimerval tv {};
  tv.it_value.tv_sec = g_timeout_ms / 1000;
  tv.it_value.tv_usec = (g_timeout_ms % 1000) * 1000;

  // Режим округления и FTZ гостя живут в FPCR ХОЗЯИНА (ARM64EC делит FPCR с родным кодом;
  // FEX переносит MXCSR в FPCR только на LDMXCSR/FXRSTOR — JIT/MiscOps.cpp DEF_OP(SetRoundingMode)).
  // Поэтому начальный MXCSR случая обязан попасть в FPCR до входа. Отображение то же, что у
  // SetRoundingMode: RC x86 (0 ближ.,1 вниз,2 вверх,3 к нулю) -> RMode ARM с переставленными битами,
  // FTZ (бит 15) -> FPCR.FZ (бит 24). DAZ -> FIZ только при FEAT_AFP — на M1 его нет, DAZ не переносится.
  uint64_t saved_fpcr = 0;
  uint64_t saved_fpsr = 0;
  __asm volatile("mrs %0, fpcr" : "=r"(saved_fpcr));
  __asm volatile("mrs %0, fpsr" : "=r"(saved_fpsr));
  __asm volatile("msr fpsr, xzr" ::: "memory");
  {
    const uint32_t rc = (static_cast<uint32_t>(c.mxcsr) >> 13) & 3;
    const uint64_t arm_rm = rc == 1 ? 2 : (rc == 2 ? 1 : rc);
    uint64_t fpcr = saved_fpcr & ~((3ull << 22) | (1ull << 24));
    fpcr |= arm_rm << 22;
    if (c.mxcsr & 0x8000) {
      fpcr |= 1ull << 24;
    }
    __asm volatile("msr fpcr, %0\n\tisb" ::"r"(fpcr) : "memory");
  }
  bool longjumped = false;
  if (sigsetjmp(g_jmp, 1) == 0) {
    g_in_case = 1;
    setitimer(ITIMER_VIRTUAL, &tv, nullptr);
    g_ctx->ExecuteThread(Thread);
  } else {
    longjumped = true;
  }
  struct itimerval off {};
  setitimer(ITIMER_VIRTUAL, &off, nullptr);
  g_in_case = 0;
  __asm volatile("msr fpcr, %0\n\tisb" ::"r"(saved_fpcr) : "memory");
  __asm volatile("msr fpsr, %0" ::"r"(saved_fpsr) : "memory");
  if (longjumped) {
    // Поток мог быть в режиме записи MAP_JIT (отказ посреди перешивки) — вернуть «исполнять».
    FEXCore::Allocator::JITWriteResetForResume(true);
  }

  const auto SFD = Thread->CurrentFrame->SynchronousFaultData;
  // Статус.
  const char* status = g_exit_span ? "EXIT_SPAN" : "exit";
  bool state_valid = true;
  if (longjumped) {
    if (g_fault.where == 1 && (g_fault.sig == SIGILL || g_fault.sig == SIGTRAP)) {
      // Заглушки GuestSignal_SIGILL/SIGTRAP диспетчера: SpillStaticRegs уже сделан, состояние цело.
      status = g_fault.sig == SIGILL ? "guest_sigill" : "guest_sigtrap";
    } else if (g_fault.where == 3) {
      status = "timeout";
      state_valid = false;
      if (!pc_in_jit(g_fault.host_pc) && !pc_in_dispatcher(g_fault.host_pc)) {
        g_dirty = true;
      }
    } else if (g_fault.where == 0) {
      status = "jit_fault"; // отказ памяти гостя из выпущенного кода
      state_valid = false;
    } else {
      status = "runtime_fault"; // отказ внутри FEXCore (C++) — процесс считается грязным
      state_valid = false;
      g_dirty = true;
    }
  }

  uint64_t guest_fault_rip = 0;
  if (longjumped && g_fault.where == 0) {
    guest_fault_rip = g_ctx->RestoreRIPFromHostPC(Thread, g_fault.host_pc);
  }

  const uint32_t eflags = g_ctx->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  __uint128_t ox[16], oy[16];
  g_ctx->ReconstructXMMRegisters(Thread, ox, oy);

  FILE* o = stdout;
  fprintf(o, "{\"id\":%" PRIu64 ",\"status\":\"%s\",\"state_valid\":%s", c.id, status, state_valid ? "true" : "false");
  fprintf(o, ",\"execution_limit\":{\"kind\":\"user_cpu\",\"milliseconds\":%u}", g_timeout_ms);
  fprintf(o, ",\"sfd\":{\"gen\":%u,\"sig\":%u,\"trap\":%u,\"si_code\":%u,\"err\":%u}", (unsigned)SFD.FaultToTopAndGeneratedException,
          (unsigned)SFD.Signal, (unsigned)SFD.TrapNo, (unsigned)SFD.si_code, (unsigned)SFD.err_code);
  if (longjumped) {
    fprintf(o, ",\"cpu_state_host\":\"0x%" PRIx64 "\",\"mm_host\":\"0x%" PRIx64 "\"",
            reinterpret_cast<uint64_t>(&S), reinterpret_cast<uint64_t>(S.mm));
    if (g_fault.host_pc >= 16 && pc_in_jit(g_fault.host_pc-16) && pc_in_jit(g_fault.host_pc+15)) {
      fprintf(o, ",\"jit_window_start\":\"0x%" PRIx64 "\",\"jit_window_hex\":\"", uint64_t(g_fault.host_pc-16));
      print_hex(o, reinterpret_cast<const uint8_t*>(g_fault.host_pc-16), 32);
      fprintf(o, "\"");
    }
    fprintf(o,
            ",\"host\":{\"sig\":\"%s\",\"code\":%d,\"addr\":\"0x%016" PRIx64 "\",\"pc\":\"0x%016" PRIx64 "\",\"esr\":\"0x%" PRIx64
            "\",\"where\":%d,\"guest_rip\":\"0x%016" PRIx64 "\"}",
            sig_name(g_fault.sig), g_fault.code, (uint64_t)g_fault.addr, (uint64_t)g_fault.host_pc, (uint64_t)g_fault.esr, g_fault.where,
            guest_fault_rip);
  }
  fprintf(o, ",\"rip\":\"0x%016" PRIx64 "\",\"regs\":{", S.rip);
  for (int i = 0; i < 16; i++) {
    fprintf(o, "%s\"%s\":\"0x%016" PRIx64 "\"", i ? "," : "", gpr_name(i), S.gregs[i]);
  }
  fprintf(o, "},\"rflags\":\"0x%08x\",\"mxcsr\":\"0x%08x\",\"fcw\":\"0x%04x\"", eflags, S.mxcsr, S.FCW);
  fprintf(o, ",\"x87_raw\":\"");
  print_hex(o, reinterpret_cast<const uint8_t*>(S.mm), sizeof(S.mm));
  fprintf(o, "\"");
  uint32_t Fsw = 0;
  for (unsigned i = 0; i < 16; ++i) {
    if (i >= 11 && i <= 13) continue;
    Fsw |= (S.flags[FEXCore::X86State::X87FLAG_BASE + i] & 1u) << i;
  }
  Fsw |= (S.flags[FEXCore::X86State::X87FLAG_TOP_LOC] & 7u) << 11;
  fprintf(o, ",\"x87_fsw\":%u,\"x87_abridged_ftw\":%u,\"x87_reduced\":%s", Fsw,
          unsigned(S.AbridgedFTW), FEXCore::Config::Get_X87REDUCEDPRECISION()() ? "true" : "false");
  fprintf(o, ",\"segments\":{\"selectors\":[%u,%u,%u,%u,%u,%u],\"bases\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]}",
          unsigned(S.cs_idx),unsigned(S.ss_idx),unsigned(S.ds_idx),unsigned(S.es_idx),unsigned(S.fs_idx),unsigned(S.gs_idx),
          uint64_t(S.cs_cached),uint64_t(S.ss_cached),uint64_t(S.ds_cached),uint64_t(S.es_cached),uint64_t(S.fs_cached),uint64_t(S.gs_cached));
  fprintf(o, ",\"xmm\":[");
  for (int i = 0; i < 16; i++) {
    uint8_t b[16];
    memcpy(b, &ox[i], 16);
    fprintf(o, "%s\"", i ? "," : "");
    print_hex(o, b, 16);
    fputc('"', o);
  }
  fprintf(o, "],\"ymm_hi\":[");
  for (int i = 0; i < 16; i++) {
    uint8_t b[16];
    memcpy(b, &oy[i], 16);
    fprintf(o, "%s\"", i ? "," : "");
    print_hex(o, b, 16);
    fputc('"', o);
  }
  fprintf(o, "],\"init_data_hash\":\"0x%016" PRIx64 "\",\"init_stack_hash\":\"0x%016" PRIx64 "\"", init_data_hash, init_stack_hash);
  fprintf(o, ",\"data_hash\":\"0x%016" PRIx64 "\",\"stack_hash\":\"0x%016" PRIx64 "\"", fnv1a64(data, DATA_SNAP), fnv1a64(stack, STACK_SNAP));
  fprintf(o, ",\"unaligned_fixups\":%" PRIu64 ",\"syscalls\":%" PRIu64 ",\"callret_resets\":%" PRIu64,
          (uint64_t)(g_unaligned_fixups - fix0), SH.SyscallHits - sys0, (uint64_t)g_crs_resets);
  fprintf(o, ",\"mr_div_checks\":%" PRIu64, MacRunnerDivOverflowChecks.load(std::memory_order_relaxed) - divchk0);
#ifdef ARCHITECTURE_arm64ec
  fprintf(o, ",\"ec_frontend\":\"fault-load-adapter\",\"ec_teb_loads\":%d,\"ec_bitmap_loads\":%d,\"ec_bitmap_outside_product_range\":%d", (int)g_ec_teb_loads, (int)g_ec_bitmap_loads, (int)g_ec_bitmap_noncanonical);
#endif
  fprintf(o, ",\"mr_shld16_cf\":%" PRIu64, MacRunnerShld16CfApplied.load(std::memory_order_relaxed) - shld0);
  fprintf(o, ",\"mr_null_host\":%" PRIu64, MacRunnerNullHostChecks.load(std::memory_order_relaxed) - nullhost0);
  fprintf(o, ",\"mr_div_proven\":%" PRIu64, MacRunnerDivProvenHighUsed.load(std::memory_order_relaxed) - divproven0);
  fprintf(o, ",\"written_memory\":[");
  for (size_t i = 0; i < c.watches.size(); ++i) {
    const auto [A, N] = c.watches[i];
    fprintf(o, "%s[\"0x%" PRIx64 "\",\"", i ? "," : "", A);
    print_hex(o, reinterpret_cast<const uint8_t*>(host_address(A)), N);
    fprintf(o, "\"]");
  }
  fprintf(o, "]");
  fprintf(o, ",\"memory_page_sha256\":[");
  for (size_t i = 0; i < c.input_pages.size(); ++i) {
    const uint64_t A = c.input_pages[i];
    uint8_t Digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(reinterpret_cast<const void*>(host_address(A)), 16384, Digest);
    fprintf(o, "%s[\"0x%" PRIx64 "\",\"", i ? "," : "", A);
    print_hex(o, Digest, sizeof(Digest));
    fprintf(o, "\"]");
  }
  fprintf(o, "]");
  if (c.dump || (c.have_expected_memory && (c.expect_data != fnv1a64(data, DATA_SNAP) || c.expect_stack != fnv1a64(stack, STACK_SNAP)))) {
    fprintf(o, ",\"data\":\"");
    print_hex(o, data, DATA_SNAP);
    fprintf(o, "\",\"stack\":\"");
    print_hex(o, stack, STACK_SNAP);
    fputc('"', o);
  }
  fprintf(o, "}\n");
  fflush(o);

  if (g_dirty) {
    // Отказ внутри FEXCore (C++): могли остаться захваченные блокировки (например
    // CodeInvalidationMutex на время компиляции) — никакой уборки, сразу выход (main).
    return;
  }
  // Снять переводы этого адреса: следующий случай кладёт ДРУГИЕ байты по тому же адресу.
  {
    std::scoped_lock Lock(g_ctx->GetCodeInvalidationMutex());
    g_ctx->InvalidateCodeBuffersCodeRange(g_code_base, CODE_MAP);
    g_ctx->InvalidateThreadCachedCodeRange(Thread, g_code_base, CODE_MAP);
  }
  g_thread = nullptr;
  g_ctx->DestroyThread(Thread);
  for (const auto& [a, n] : c.mapped) retain_guest(a, n);
  munmap(reinterpret_cast<void*>(g_crs_alloc), g_crs_alloc_end - g_crs_alloc);
  g_crs_alloc = g_crs_alloc_end = 0;
  retain_guest(g_code_base, CODE_MAP);
}
} // namespace

int main(int argc, char** argv, char** envp) {
  if (argc == 2 && !strcmp(argv[1], "--capabilities")) {
#ifdef STAND32_ADDRESS_SPACE32
#ifdef STAND32_X87_MUTANTS
    puts("{\"stand32_protocol\":1,\"guest_bits\":32,\"bases\":[\"0x80000000000\"],\"x87_raw80\":true,\"segments\":true,\"engine\":\"private_X87_lifter_mutants\",\"mutations\":[\"x87_rounding\",\"x87_stack_order\"]}");
#else
    puts("{\"stand32_protocol\":1,\"guest_bits\":32,\"bases\":[\"0\",\"0x80000000000\"],\"x87_raw80\":true,\"segments\":true,\"engine\":\"supplied_FEXCore\",\"mutations\":[]}");
#endif
#else
    puts("{\"stand32_protocol\":1,\"guest_bits\":32,\"bases\":[\"0\",\"0x80000000000\"],\"x87_raw80\":true,\"segments\":true,\"mutations\":[\"base\",\"sign\",\"carry4g\"]}");
#endif
    return 0;
  }
#ifdef ARCHITECTURE_arm64ec
  g_ec_peb[0x368 / 8] = EC_BITMAP_BASE;
#endif
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  const char* e;
  g_guest_base = (e = getenv("STAND32_GUEST_BASE")) ? strtoull(e, nullptr, 0) : 0x80000000000ULL;
  if (g_guest_base != 0 && g_guest_base != 0x80000000000ULL) return 2;
  g_code_base = (e = getenv("ORACLE_CODE_BASE")) ? strtoull(e, nullptr, 0) : 0x10000000ULL;
  g_data_base = (e = getenv("ORACLE_DATA_BASE")) ? strtoull(e, nullptr, 0) : 0x20000000ULL;
  g_data_base &= ~0xffffffULL;
  g_stack_base = g_data_base + 0x1000000ULL;
  if ((e = getenv("ORACLE_TIMEOUT_MS"))) {
    g_timeout_ms = (unsigned)strtoul(e, nullptr, 0);
  }
  const bool product = !((e = getenv("ORACLE_FEX_FEATURES")) && strcmp(e, "native") == 0);

  // Real cases own their guest mappings before FEX initializes its large
  // allocator/JIT reservations. Never replace an existing unrelated mapping.
  char* initial_line = nullptr;
  size_t initial_capacity = 0;
  if (getline(&initial_line, &initial_capacity, stdin) < 0) return 0;
  Case first;
  std::string initial_error;
  if (!parse_case(initial_line, first, initial_error)) {
    fprintf(stdout,"{\"status\":\"bad_input\",\"state_valid\":false}\n"); return 2;
  }
  if (!first.pages.empty()) {
    const uint64_t base = first.rip & ~0x3fffULL;
    std::vector<std::pair<uint64_t,uint64_t>> ranges {{base,base+CODE_MAP}};
    FILE* page_file = fopen(first.pages.c_str(), "rb");
    char magic[8]; uint64_t count = 0;
    bool valid = page_file && fread(magic,1,8,page_file)==8 && !memcmp(magic,"HBPAGES1",8) &&
                 fread(&count,8,1,page_file)==1 && count<=16384;
    for (uint64_t i=0; valid && i<count; ++i) {
      uint64_t a=0;
      valid=fread(&a,8,1,page_file)==1 && !(a&16383) && a<=UINT64_MAX-16384 && fseek(page_file,16384,SEEK_CUR)==0;
      if (valid) ranges.emplace_back(a,a+16384);
    }
    if (page_file) fclose(page_file);
    if (!valid) return 2;
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<uint64_t,uint64_t>> merged;
    for (const auto& [a,b] : ranges) {
      if (!merged.empty() && a<=merged.back().second) merged.back().second=std::max(b,merged.back().second);
      else merged.emplace_back(a,b);
    }
    for (const auto& [a,b] : merged) {
      if (!map_guest(a,b-a,PROT_NONE)) {
        printf("{\"id\":%" PRIu64 ",\"status\":\"guest_image_mapping_FAILED\",\"state_valid\":false,\"bad_address\":\"0x%" PRIx64 "\"}\n",first.id,a);
        return 0;
      }
    }
  }

  // Настройки FEX: умолчания FEXCore + окружение FEX_* (например FEX_MULTIBLOCK=0).
  FEXCore::Config::Initialize();
  auto EnvLayer = fextl::make_unique<OracleEnvLayer>(envp);
  auto* EnvLayerPtr = EnvLayer.get();
  FEXCore::Config::AddLayer(std::move(EnvLayer));
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");

  // Области гостя — ДО FEXCore, чтобы его выделения не легли на эти адреса.
  const uint64_t fence_lo = g_data_base > 0x80000000ULL ? g_data_base - 0x80000000ULL : 0x10000ULL;
  const uint64_t fence_hi = ((g_data_base + 0x1000000ULL + 8ULL * (g_data_base + 0x1100ULL) + 0x80000000ULL) + 0xffffffULL) & ~0xffffffULL;
  if (!range_free(g_data_base, g_data_base + DATA_MAP) ||
      !range_free(g_stack_base, g_stack_base + STACK_MAP)) {
    fprintf(stderr, "fex-oracle: guest window already occupied\n");
    fprintf(stdout,"{\"status\":\"host_address_unavailable\",\"state_valid\":false,\"base\":\"0x%" PRIx64 "\"}\n",g_guest_base);
    return 2;
  }
  if (!map_guest(g_data_base, DATA_MAP, PROT_READ | PROT_WRITE) ||
      !map_guest(g_stack_base, STACK_MAP, PROT_READ | PROT_WRITE)) {
    return 2;
  }
  if (getenv("STAND32_ENABLE_LEGACY_FENCE")) {
    // The old synthetic-oracle fence covered legitimate high HBCAP code RIPs.
    // Own arena guards only; Unicorn rejects all other data accesses first.
    fence(g_data_base - 0x4000, g_data_base);
    fence(g_data_base + DATA_MAP, g_data_base + DATA_MAP + 0x4000);
    fence(g_stack_base - 0x4000, g_stack_base);
    fence(g_stack_base + STACK_MAP, g_stack_base + STACK_MAP + 0x4000);
  }

  init_gdt();
  char Describe[1024];
  auto HostFeatures = FetchHostFeaturesMac(product, Describe, sizeof(Describe));
#ifdef STAND32_ADDRESS_SPACE32
  const auto Space = FEXCore::Core::GuestAddressSpace32::Create(g_guest_base, getpagesize());
  if (g_guest_base && !Space) return 4;
  auto CTX = g_guest_base ? FEXCore::Context::Context::CreateNewContext(HostFeatures, *Space) :
                           FEXCore::Context::Context::CreateNewContext(HostFeatures);
#else
  auto CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
#endif
  g_ctx = CTX.get();
  CTX->EnableExitOnHLT();
  auto SD = fextl::make_unique<OracleSignalDelegator>();
  auto SH = fextl::make_unique<OracleSyscallHandler>();
  CTX->SetSignalDelegator(SD.get());
  CTX->SetSyscallHandler(SH.get());
  FEXCore::Allocator::JITWriteThreadInit();
  if (!CTX->InitCore()) {
    fprintf(stderr, "fex-oracle: InitCore failed\n");
    return 3;
  }
  g_dispatcher_begin = SD->Cfg().DispatcherBegin;
  g_dispatcher_end = SD->Cfg().DispatcherEnd;
  {
    // Тип перешивки невыровненного доступа — как TSOHandlerConfig фронтендов Windows.
    bool HalfBarrier = FEXCore::Config::Get_HALFBARRIERTSOENABLED()();
    g_unaligned_type = HalfBarrier ? FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier :
                                     FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::NonAtomic;
  }
  install_handlers();

  fprintf(stderr, "fex-oracle: features %s\n", Describe);
  fprintf(stderr, "fex-oracle: code=0x%llx data=0x%llx stack=0x%llx fence=[0x%llx,0x%llx) holes=%llu bytes=%llu dispatcher=[0x%llx,0x%llx)\n",
          (unsigned long long)g_code_base, (unsigned long long)g_data_base, (unsigned long long)g_stack_base, (unsigned long long)fence_lo,
          (unsigned long long)fence_hi, (unsigned long long)g_fence_holes, (unsigned long long)g_fence_bytes,
          (unsigned long long)g_dispatcher_begin, (unsigned long long)g_dispatcher_end);
  fprintf(stderr, "fex-oracle: config multiblock=%d tso=%d halfbarrier=%d x87reduced=%d maxinst=%d smc=%d env_applied=%zu\n",
          (int)FEXCore::Config::Get_MULTIBLOCK()(), (int)FEXCore::Config::Get_TSOENABLED()(), (int)FEXCore::Config::Get_HALFBARRIERTSOENABLED()(),
          (int)FEXCore::Config::Get_X87REDUCEDPRECISION()(), (int)FEXCore::Config::Get_MAXINST()(), (int)FEXCore::Config::Get_SMCCHECKS()(),
          EnvLayerPtr->Applied.size());
  for (auto& a : EnvLayerPtr->Applied) {
    fprintf(stderr, "fex-oracle: env %s\n", a.c_str());
  }

  size_t cap = 1 << 16;
  char* line = static_cast<char*>(::malloc(cap));
  uint64_t n = 0;
  run_case(first, *SH);
  // Reservations survive the first case and every later batch case.
  free(initial_line);
  if (g_dirty) _exit(5);
  n++;
  while (true) {
    ssize_t len = getline(&line, &cap, stdin);
    if (len < 0) {
      break;
    }
    if (len <= 1 || line[0] == '#') {
      continue;
    }
    Case c;
    std::string err;
    if (!parse_case(line, c, err)) {
      printf("{\"id\":%" PRIu64 ",\"status\":\"bad_input\",\"error\":\"%s\"}\n", c.id, err.c_str());
      fflush(stdout);
      continue;
    }
    run_case(c, *SH);
    n++;
    if (g_dirty) {
      fprintf(stderr, "fex-oracle: process state dirty after case %" PRIu64 " — exiting for restart\n", c.id);
      fflush(stderr);
      _exit(5);
    }
  }
  fprintf(stderr,
          "fex-oracle: done cases=%" PRIu64 " unaligned_fixups=%" PRIu64 " mr_div_checks=%" PRIu64 " mr_shld16_cf=%" PRIu64
          " mr_null_host=%" PRIu64 " mr_div_proven=%" PRIu64 "\n",
          n, (uint64_t)g_unaligned_fixups, MacRunnerDivOverflowChecks.load(std::memory_order_relaxed),
          MacRunnerShld16CfApplied.load(std::memory_order_relaxed), MacRunnerNullHostChecks.load(std::memory_order_relaxed),
          MacRunnerDivProvenHighUsed.load(std::memory_order_relaxed));
  fflush(stderr);
  _exit(0);
}
