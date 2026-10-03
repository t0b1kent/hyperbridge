// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
#include "MacHostFeatures.h"

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

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

extern std::atomic<uint64_t> MacRunnerDivOverflowChecks;

extern std::atomic<uint64_t> MacRunnerShld16CfApplied;

extern std::atomic<uint64_t> MacRunnerNullHostChecks;

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
  int where; 
};
volatile FaultRec g_fault;
volatile uint64_t g_unaligned_fixups;
volatile uint64_t g_dispatcher_begin, g_dispatcher_end;

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

class OracleSyscallHandler final : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  OracleSyscallHandler() {
    
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

bool pc_in_jit(uint64_t pc) {
  auto* T = g_thread;
  return T && g_ctx && g_ctx->IsAddressInCodeBuffer(T, pc);
}
bool pc_in_dispatcher(uint64_t pc) {
  return pc >= g_dispatcher_begin && pc < g_dispatcher_end;
}

#ifdef ARCHITECTURE_arm64ec

constexpr uint64_t EC_BITMAP_BASE = 0x600000000000ULL;
constexpr uint64_t EC_BITMAP_BYTES = 1ULL << 49; 
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

  if (disp && (op & 0xffe0fc00U) == 0xf8607800U && ss.__x[rn] == EC_BITMAP_BASE) {
    const unsigned rm = (op >> 16) & 31;
    if (rm >= 29) return false;
    const uint64_t offset = ss.__x[rm] << 3;
    if (offset >= EC_BITMAP_BYTES || fault_address != EC_BITMAP_BASE + offset) return false;
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
    
    fprintf(stderr, "fex-oracle: host signal %d outside case, pc=0x%llx addr=%p\n", sig, (unsigned long long)pc, info ? info->si_addr : nullptr);
    signal(sig, SIG_DFL);
    return;
  }

#ifdef ARCHITECTURE_arm64ec
  if ((sig == SIGSEGV || sig == SIGBUS) && info &&
      supply_ec_frontend_load(uc, pc, jit, disp, reinterpret_cast<uint64_t>(info->si_addr))) return;
#endif

  if ((sig == SIGSEGV || sig == SIGBUS) && jit && info) {
    const uint64_t fa = reinterpret_cast<uint64_t>(info->si_addr);
    if (fa >= g_crs_alloc && fa < g_crs_alloc_end) {
      ss.__x[25] = g_crs_default;
      g_crs_resets = g_crs_resets + 1;
      return;
    }
  }

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
  g_fault.where = sig == SIGVTALRM ? 3 : (jit ? 0 : (disp ? 1 : 2));
  siglongjmp(g_jmp, 1);
}

void install_handlers() {
  struct sigaction sa {};
  sa.sa_sigaction = host_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  for (int s : {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE, SIGVTALRM}) {
    sigaction(s, &sa, nullptr);
  }
}

bool map_fixed(uint64_t base, uint64_t size, int prot) {
  void* p = mmap(reinterpret_cast<void*>(base), size, prot, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
  if (p == MAP_FAILED || reinterpret_cast<uint64_t>(p) != base) {
    fprintf(stderr, "fex-oracle: mmap 0x%llx+0x%llx failed (%p, errno %d)\n", (unsigned long long)base, (unsigned long long)size, p, errno);
    return false;
  }
  return true;
}

bool range_free(uint64_t lo, uint64_t hi) {
  mach_vm_address_t r = lo;
  mach_vm_size_t sz = 0;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t obj = MACH_PORT_NULL;
  kern_return_t kr = mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj);
  return kr != KERN_SUCCESS || r >= hi;
}

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

struct Case {
  uint64_t id {};
  uint64_t seed {};
  uint8_t code[65536];
  size_t code_len {};
  uint64_t rip {}, rflags {}, mxcsr {0x1f80};
  uint64_t xlen {}; 
  uint64_t fsbase {}, gsbase {}; 
  uint64_t gpr[16] {}; 
  uint8_t xmm[16][16] {};
  uint8_t ymmh[16][16] {};
  bool dump {};
  bool have_expected_memory {};
  uint64_t expect_data {}, expect_stack {};
  fextl::vector<std::pair<uint64_t, uint64_t>> watches;
  uint32_t have {};
  
  struct Patch {
    uint64_t addr;
    uint8_t bytes[64];
    size_t len;
  } patch[8];
  unsigned npatch {};
};

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
      if (!N || N > DATA_MAP || !((A >= g_data_base && A <= g_data_base + DATA_MAP - N) ||
                                (A >= g_stack_base && A <= g_stack_base + STACK_MAP - N))) {
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
  case SIGVTALRM: return "SIGVTALRM";
  default: return "?";
  }
}

bool g_dirty;
unsigned g_timeout_ms = 2000;
FEXCore::Core::CPUState::gdt_segment g_gdt[32];

void init_gdt() {
  memset(g_gdt, 0, sizeof(g_gdt));
  
  for (unsigned idx : {1u, (unsigned)FEXCore::Core::CPUState::DEFAULT_USER_CS}) {
    auto& G = g_gdt[idx];
    FEXCore::Core::CPUState::SetGDTBase(&G, 0);
    FEXCore::Core::CPUState::SetGDTLimit(&G, 0xFFFFFU);
    G.L = 1;
    G.D = 0;
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
  if (!range_free(g_code_base, g_code_base + CODE_MAP) ||
      !map_fixed(g_code_base, CODE_MAP, PROT_READ | PROT_WRITE)) {
    printf("{\"id\":%" PRIu64 ",\"status\":\"host_code_collision\",\"state_valid\":false}\n", c.id);
    fflush(stdout);
    return;
  }
  uint8_t* code = reinterpret_cast<uint8_t*>(g_code_base);
  uint8_t* data = reinterpret_cast<uint8_t*>(g_data_base);
  uint8_t* stack = reinterpret_cast<uint8_t*>(g_stack_base);

  mprotect(code, CODE_MAP, PROT_READ | PROT_WRITE);
  memset(code, 0, CODE_MAP);
  memcpy(reinterpret_cast<void*>(c.rip), c.code, c.code_len);
  mprotect(code, CODE_MAP, PROT_READ);
  
  memset(data, 0, DATA_MAP);
  memset(stack, 0, STACK_MAP);
  uint64_t rng = c.seed;
  fill_random(&rng, data, DATA_SNAP);
  fill_random(&rng, stack, STACK_SNAP);
  for (unsigned p = 0; p < c.npatch; p++) {
    const auto& P = c.patch[p];
    const bool in_data = P.addr >= g_data_base && P.addr + P.len <= g_data_base + DATA_MAP;
    const bool in_stack = P.addr >= g_stack_base && P.addr + P.len <= g_stack_base + STACK_MAP;
    if (in_data || in_stack) {
      memcpy(reinterpret_cast<void*>(P.addr), P.bytes, P.len);
    }
  }
  const uint64_t init_data_hash = fnv1a64(data, DATA_SNAP);
  const uint64_t init_stack_hash = fnv1a64(stack, STACK_SNAP);

  g_exec_base = c.rip;
  g_exec_end = c.rip + ((c.xlen && c.xlen <= c.code_len) ? c.xlen : c.code_len);

  {
    std::scoped_lock Lock(g_ctx->GetCodeInvalidationMutex());
    g_ctx->InvalidateCodeBuffersCodeRange(g_code_base, CODE_MAP);
  }

  auto* Thread = g_ctx->CreateThread(c.rip, c.gpr[FEXCore::X86State::REG_RSP]);
  auto& S = Thread->CurrentFrame->State;
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
  S.FCW = 0x37F;

  S.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = g_gdt;
  S.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = g_gdt;
  S.cs_cached = 0;
  S.cs_idx = 0x08;
  S.es_idx = S.ss_idx = S.ds_idx = S.fs_idx = S.gs_idx = 0x10;
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
    
    FEXCore::Allocator::JITWriteResetForResume(true);
  }

  const auto SFD = Thread->CurrentFrame->SynchronousFaultData;
  
  const char* status = "exit";
  bool state_valid = true;
  if (longjumped) {
    if (g_fault.where == 1 && (g_fault.sig == SIGILL || g_fault.sig == SIGTRAP)) {
      
      status = g_fault.sig == SIGILL ? "guest_sigill" : "guest_sigtrap";
    } else if (g_fault.where == 3) {
      status = "timeout";
      state_valid = false;
      if (!pc_in_jit(g_fault.host_pc) && !pc_in_dispatcher(g_fault.host_pc)) {
        g_dirty = true;
      }
    } else if (g_fault.where == 0) {
      status = "jit_fault"; 
      state_valid = false;
    } else {
      status = "runtime_fault"; 
      state_valid = false;
      g_dirty = true;
    }
  }

  uint64_t guest_fault_rip = 0;
  if (longjumped && g_fault.where == 0) {
    guest_fault_rip = g_ctx->RestoreRIPFromHostPC(Thread, g_fault.host_pc);
  }

  if (getenv("STAND_MUTATE_GPR")) S.gregs[0] ^= 1;
  const uint32_t eflags = g_ctx->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  __uint128_t ox[16], oy[16];
  g_ctx->ReconstructXMMRegisters(Thread, ox, oy);

  FILE* o = stdout;
  fprintf(o, "{\"id\":%" PRIu64 ",\"status\":\"%s\",\"state_valid\":%s", c.id, status, state_valid ? "true" : "false");
  fprintf(o, ",\"sfd\":{\"gen\":%u,\"sig\":%u,\"trap\":%u,\"si_code\":%u,\"err\":%u}", (unsigned)SFD.FaultToTopAndGeneratedException,
          (unsigned)SFD.Signal, (unsigned)SFD.TrapNo, (unsigned)SFD.si_code, (unsigned)SFD.err_code);
  if (longjumped) {
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
    print_hex(o, reinterpret_cast<const uint8_t*>(A), N);
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

    return;
  }
  
  {
    std::scoped_lock Lock(g_ctx->GetCodeInvalidationMutex());
    g_ctx->InvalidateCodeBuffersCodeRange(g_code_base, CODE_MAP);
    g_ctx->InvalidateThreadCachedCodeRange(Thread, g_code_base, CODE_MAP);
  }
  g_thread = nullptr;
  g_ctx->DestroyThread(Thread);
  munmap(reinterpret_cast<void*>(g_crs_alloc), g_crs_alloc_end - g_crs_alloc);
  g_crs_alloc = g_crs_alloc_end = 0;
  munmap(reinterpret_cast<void*>(g_code_base), CODE_MAP);
}
} 

int main(int argc, char** argv, char** envp) {
#ifdef ARCHITECTURE_arm64ec
  g_ec_peb[0x368 / 8] = EC_BITMAP_BASE;
#endif
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  const char* e;
  g_code_base = (e = getenv("ORACLE_CODE_BASE")) ? strtoull(e, nullptr, 0) : 0x7ffc0000000ULL;
  g_data_base = (e = getenv("ORACLE_DATA_BASE")) ? strtoull(e, nullptr, 0) : 0x80000000000ULL;
  g_data_base &= ~0xffffffULL;
  g_stack_base = g_data_base + 0x1000000ULL;
  if ((e = getenv("ORACLE_TIMEOUT_MS"))) {
    g_timeout_ms = (unsigned)strtoul(e, nullptr, 0);
  }
  const bool product = !((e = getenv("ORACLE_FEX_FEATURES")) && strcmp(e, "native") == 0);

  FEXCore::Config::Initialize();
  auto EnvLayer = fextl::make_unique<OracleEnvLayer>(envp);
  auto* EnvLayerPtr = EnvLayer.get();
  FEXCore::Config::AddLayer(std::move(EnvLayer));
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");

  const uint64_t fence_lo = g_data_base > 0x80000000ULL ? g_data_base - 0x80000000ULL : 0x10000ULL;
  const uint64_t fence_hi = ((g_data_base + 0x1000000ULL + 8ULL * (g_data_base + 0x1100ULL) + 0x80000000ULL) + 0xffffffULL) & ~0xffffffULL;
  if (!range_free(g_data_base, g_data_base + DATA_MAP) ||
      !range_free(g_stack_base, g_stack_base + STACK_MAP)) {
    fprintf(stderr, "fex-oracle: guest window already occupied\n");
    return 2;
  }
  if (!map_fixed(g_data_base, DATA_MAP, PROT_READ | PROT_WRITE) ||
      !map_fixed(g_stack_base, STACK_MAP, PROT_READ | PROT_WRITE)) {
    return 2;
  }
  if (!getenv("ORACLE_NO_FENCE")) {

    fence(g_data_base - 0x4000, g_data_base);
    fence(g_data_base + DATA_MAP, g_data_base + DATA_MAP + 0x4000);
    fence(g_stack_base - 0x4000, g_stack_base);
    fence(g_stack_base + STACK_MAP, g_stack_base + STACK_MAP + 0x4000);
  }

  init_gdt();
  char Describe[1024];
  auto HostFeatures = FetchHostFeaturesMac(product, Describe, sizeof(Describe));
  auto CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
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
