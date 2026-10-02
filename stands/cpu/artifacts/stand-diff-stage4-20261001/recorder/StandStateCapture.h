// STAND-DIFF experiment only. No product deployment. Compilation owns slot
// creation; execution only takes a bounded record after a cheap emitted gate.
#pragma once
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <mutex>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/unordered_map.h>

namespace StandStateCapture {
struct alignas(64) Slot {
  std::atomic<uint64_t> executions {0};
  uint64_t rip {};
  uint32_t records {};
};
struct Record {
  uint64_t rip, sequence, thread, fpcr, fpsr;
  uint32_t rflags, mxcsr;
  uint64_t gpr[16];
  __uint128_t xmm[16], ymm[16];
  uint32_t fsw;
  uint16_t fcw;
  uint8_t ftw, reduced;
  uint64_t mm[8][2];
  uint64_t fs_base, gs_base;
};
inline Slot Slots[262144];
inline uint32_t SlotCount;
inline uint64_t RecordCount;
inline std::mutex Lock;
inline fextl::unordered_map<uint64_t, Slot*> ByRIP;
inline void* File;
inline bool Failed;

inline bool Enabled() {
  static const bool Value = [] { const char* p = getenv("MACRUNNER_FEX_STAND_STATE"); return p && *p; }();
  return Value;
}
inline bool WindowOpen() {
  // Reuse FEX's existing clock dependency; do not add an early API-set import.
  static const auto Start = std::chrono::steady_clock::now();
  static const uint64_t DelayMs = [] {
    const char* p = getenv("MACRUNNER_FEX_STAND_DELAY_MS");
    return p ? strtoull(p, nullptr, 10) : 0ULL;
  }();
  const auto ElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - Start).count();
  return ElapsedMs >= DelayMs;
}
inline Slot* GetSlot(uint64_t RIP) {
  // Keep early blocks eligible for delayed execution sampling. No records
  // are written before the capture window, and their budget is not consumed.
  if (!Enabled()) return nullptr;
  std::lock_guard Guard(Lock);
  if (auto It = ByRIP.find(RIP); It != ByRIP.end()) return It->second;
  if (SlotCount == 262144) return nullptr;
  auto* S = &Slots[SlotCount++]; S->rip = RIP; ByRIP.emplace(RIP, S);
  return S;
}

#ifdef _WIN32
extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentProcessId(void);
extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);
extern "C" __declspec(dllimport) unsigned long long __stdcall GetTickCount64(void);
inline bool Put(const void* Data, uint32_t Size) {
  unsigned long Done = 0;
  const bool OK = WriteFile(File, Data, Size, &Done, nullptr) && Done == Size;
  if (!OK) Failed = true;
  return OK;
}
inline bool Open() {
  if (File) return !Failed;
  if (Failed) return false;
  const auto Name = fextl::fmt::format("{}.{}.hbstates", getenv("MACRUNNER_FEX_STAND_STATE"), GetCurrentProcessId());
  File = CreateFileA(Name.c_str(), 0x40000000, 1, nullptr, 2, 0x80, nullptr);
  if (!File || File == reinterpret_cast<void*>(intptr_t {-1})) { File = nullptr; Failed = true; return false; }
  const auto Metadata = fextl::fmt::format(
    "{{\"record_size\":{},\"gpr_offset\":{},\"xmm_offset\":{},\"ymm_offset\":{},\"fsw_offset\":{},\"mm_offset\":{},\"fs_base_offset\":{},\"gs_base_offset\":{},\"interval\":1,\"cap_per_block\":2,\"cap_total\":524288,\"entry_kind\":\"translated_entrypoint_first_K\",\"clock\":\"sequence_no_wallclock\"}}",
    sizeof(Record), offsetof(Record, gpr), offsetof(Record, xmm), offsetof(Record, ymm), offsetof(Record, fsw), offsetof(Record, mm), offsetof(Record, fs_base), offsetof(Record, gs_base));
  uint32_t Header[4] = {1, sizeof(Record), static_cast<uint32_t>(Metadata.size()), 0};
  return Put("HBSTATE1", 8) && Put(Header, sizeof(Header)) && Put(Metadata.data(), Metadata.size());
}

// Called only with full static guest state spilled, never from a signal handler.
inline void Capture(FEXCore::Core::CpuStateFrame* Frame, FEXCore::Context::Context* CTX, Slot* Slot) {
  uint64_t FPCR, FPSR;
  asm volatile("mrs %0, fpcr\n\tmrs %1, fpsr" : "=r"(FPCR), "=r"(FPSR));
  struct RestoreFP {
    uint64_t fpcr, fpsr;
    ~RestoreFP() { asm volatile("msr fpcr, %0\n\tmsr fpsr, %1" :: "r"(fpcr), "r"(fpsr) : "memory"); }
  } Restore {FPCR, FPSR};
  std::lock_guard Guard(Lock);
  // Private capture only: exclude startup before any per-block/total cap is consumed.
  if (!WindowOpen()) {
    // First-K gate is rearmed while the capture window is disabled.
    // Re-arm it while records are disabled, so startup cannot exhaust it.
    Slot->executions.store(0, std::memory_order_relaxed);
    return;
  }
  if (Failed || RecordCount >= 524288 || Slot->records >= 2 || !Open()) return;
  Record R {};
  const auto& S = Frame->State;
  R.rip = Slot->rip; R.sequence = ++RecordCount; R.thread = GetCurrentThreadId(); R.fpcr = FPCR; R.fpsr = FPSR;
  R.rflags = CTX->ReconstructCompactedEFLAGS(Frame->Thread, false, nullptr, 0); R.mxcsr = S.mxcsr;
  memcpy(R.gpr, S.gregs, sizeof(R.gpr));
  CTX->ReconstructXMMRegisters(Frame->Thread, R.xmm, R.ymm);
  for (unsigned i = 0; i < 16; ++i) if (i < 11 || i > 13) R.fsw |= (S.flags[FEXCore::X86State::X87FLAG_BASE + i] & 1U) << i;
  R.fsw |= (S.flags[FEXCore::X86State::X87FLAG_TOP_LOC] & 7U) << 11;
  R.fcw = S.FCW; R.ftw = S.AbridgedFTW; R.reduced = FEXCore::Config::Get_X87REDUCEDPRECISION()();
  memcpy(R.mm, S.mm, sizeof(R.mm));
  R.fs_base = S.fs_cached; R.gs_base = S.gs_cached;
  if (Put(&R, sizeof(R))) ++Slot->records;
}
#endif
} // namespace StandStateCapture
