// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|WOW64
desc: Implements the WOW64 BT module API using FEXCore
$end_info$
*/

// Thanks to André Zwing, whose ideas from https://github.com/AndreRH/hangover this code is based upon

#include <FEXCore/Core/G3LazyFIP.h>
#include <FEXCore/Core/G3CrtWatch.h> // rp6r4
#include <FEXCore/fextl/fmt.h>
#include "../../../FEXCore/Source/Interface/Core/HBX87Stats.h"
#include "../../../FEXCore/Source/Interface/Core/HBX87StateGates.h"
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/MacRunnerLazyMXCSR.h>
#include <FEXCore/Core/X87Fault.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/MacRunnerSuspend.h>
#include <FEXCore/Utils/MacRunnerXfer.h>
#include <FEXCore/Utils/MacRunnerExitScan.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>

#include "Windows/Common/Allocator.h"
#include "Windows/Common/EnvironmentVariablesHandling.h"
#include "Windows/Common/FEXUnixLib.h"
#include "Common/CallRetStack.h"
#include "Common/JITGuardPage.h"
#include "Common/Config.h"
#include "Common/Exception.h"
#include "Common/TSOHandlerConfig.h"
#include "Common/ImageTracker.h"
#include "Common/InvalidationTracker.h"
#include "Common/OvercommitTracker.h"
#include "Common/CPUFeatures.h"
#include "Common/Logging.h"
#include "Common/Module.h"
#include "Common/CRT/CRT.h"
#include "Common/PortabilityInfo.h"
#include "Common/Handle.h"
#include "DummyHandlers.h"
#include "BTInterface.h"
#include "Windows/Common/SHMStats.h"

#include <cstdint>
#include <cstdio>
#include <type_traits>
#include <atomic>
#include <mutex>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <deque>
#include <vector>
#include <shared_mutex>
#include <algorithm>
#include <filesystem>
#include <string_view>
#include <cstring>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Utils/MacRunnerXfer.h>
extern "C" IMAGE_DOS_HEADER __ImageBase;
extern "C" NTSTATUS WINAPI NtCreateThreadEx(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, HANDLE, void*, void*, ULONG, ULONG_PTR, SIZE_T,
                                            SIZE_T, void*);
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <wine/debug.h>
#include <wine/unixlib.h>

namespace ControlBits {
// When this is unset, a thread can be safely interrupted and have its context recovered
// IMPORTANT: This can only safely be written by the owning thread
static constexpr uint32_t IN_JIT {1U << 0};

// JIT entry polls this bit until it is unset, at which point CONTROL_IN_JIT will be set
static constexpr uint32_t PAUSED {1U << 1};

// When this is set, the CPU context stored in the CPU area has not yet been flushed to the FEX TLS
static constexpr uint32_t WOW_CPU_AREA_DIRTY {1U << 2};
}; // namespace ControlBits

struct TLS {
  enum class Slot : size_t {
    ENTRY_CONTEXT = WOW64_TLS_MAX_NUMBER - 1,
    CONTROL_WORD = WOW64_TLS_MAX_NUMBER - 2,
    THREAD_STATE = WOW64_TLS_MAX_NUMBER - 3,
    CACHED_CALLRET_SP = WOW64_TLS_MAX_NUMBER - 4,
  };

  _TEB* TEB;

  explicit TLS(_TEB* TEB)
    : TEB(TEB) {}

  WOW64INFO& Wow64Info() const {
    return *reinterpret_cast<WOW64INFO*>(TEB->TlsSlots[WOW64_TLS_WOW64INFO]);
  }

  std::atomic<uint32_t>& ControlWord() const {
    // TODO: Change this when libc++ gains std::atomic_ref support
    return reinterpret_cast<std::atomic<uint32_t>&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CONTROL_WORD)]);
  }

  uint32_t* ControlWordAddress() const {
    return reinterpret_cast<uint32_t*>(&TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CONTROL_WORD)]);
  }

  CONTEXT*& EntryContext() const {
    return reinterpret_cast<CONTEXT*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::ENTRY_CONTEXT)]);
  }

  FEXCore::Core::InternalThreadState*& ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState*&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::THREAD_STATE)]);
  }

  // This is used to work around user callback handling (see Wow64KiUserCallbackDispatcher in wine) unbalancing the
  // call-ret stace since user callbacks are returned from using a syscall that we can't really intercept.
  uint64_t& CachedCallRetSp() const {
    return reinterpret_cast<uint64_t&>(TEB->TlsSlots[FEXCore::ToUnderlying(Slot::CACHED_CALLRET_SP)]);
  }
};

struct FrontendThreadData {
  bool InLockedRWXRead {};
  uint32_t MRWindowSkips {}; // REGION4 EXIT_SCAN v2: window entry polls skipped in a row (HandleSuspendInterrupt)
  uint32_t MRShadowWindowSkips {}; // REGION4-0005: calls into flags windows not stopped at, in a row (HandleShadowSuspend)
  uint32_t MRStepsLeft {};         // REGION4-0006: single-instruction steps left to the end of a flags window (HandleSuspendInterrupt)
  // X87-CTX: FloatSave of the last context FEX wrote out; an import that finds FloatSave changed takes the x87 state from it
  // (Windows Server 2022: FloatSave wins whenever a Set carries CONTEXT_FLOATING_POINT).
  bool X87SnapValid {};
  WOW64_FLOATING_SAVE_AREA X87SnapFn {};
};

class WowSyscallHandler;

namespace {
namespace BridgeInstrs {
  // These directly jumped to by the guest to make system calls
  void* Syscall {};
  void* UnixCall {};
} // namespace BridgeInstrs

fextl::unique_ptr<FEXCore::Context::Context> CTX;
fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
fextl::unique_ptr<WowSyscallHandler> SyscallHandler;
fextl::unique_ptr<FEX::Windows::StatAlloc> StatAllocHandler;

std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::CPUFeatures> CPUFeatures;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;
std::optional<FEX::Windows::ImageTracker> ImageTracker;

std::mutex ThreadCreationMutex;
// Map of TIDs to their FEX thread state, `ThreadCreationMutex` must be locked when accessing
std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;

decltype(__wine_unix_call_dispatcher) WineUnixCall;

std::pair<NTSTATUS, TLS> GetThreadTLS(HANDLE Thread) {
  THREAD_BASIC_INFORMATION Info;
  const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
  return {Err, TLS {reinterpret_cast<_TEB*>(Info.TebBaseAddress)}};
}

TLS GetTLS() {
  return TLS {NtCurrentTeb()};
}

FrontendThreadData* GetFrontendThreadData(FEXCore::Core::InternalThreadState* Thread) {
  return static_cast<FrontendThreadData*>(Thread->FrontendPtr);
}

uint64_t GetWowTEB(void* TEB) {
  static constexpr size_t WowTEBOffsetMemberOffset {0x180c};
  return static_cast<uint64_t>(
    *reinterpret_cast<LONG*>(reinterpret_cast<uintptr_t>(TEB) + WowTEBOffsetMemberOffset) + reinterpret_cast<uint64_t>(TEB));
}

bool IsDispatcherAddress(uint64_t Address) {
  const auto& Config = SignalDelegator->GetConfig();
  return Address >= Config.DispatcherBegin && Address < Config.DispatcherEnd;
}

bool IsAddressInJit(uint64_t Address) {
  if (IsDispatcherAddress(Address)) {
    return true;
  }

  auto Thread = GetTLS().ThreadState();
  return Thread->CTX->IsAddressInCodeBuffer(Thread, Address);
}

// ★ CALLRET4 13.11.2026 MACRUNNER_FEX32_WARM=1|2 (MacRunnerXfer.h, apply_warm.py, DESIGN §11): warm translation.
namespace MRWarm {
struct Rec {
  uint32_t Rva;
  uint32_t Mxcsr;
  uint16_t Fcw;
  uint8_t Ftw;   // abridged tag word
  uint8_t Top;   // x87 TOP
  uint8_t Exc;   // FSW exception flags IE..PE
  uint8_t Pad[3];
};
static_assert(sizeof(Rec) == 16);
struct Image {
  uint64_t Key {};
  uint64_t Size {};
  fextl::string Name;
  std::vector<Rec> Recs;
  std::unordered_set<uint32_t> Seen;
};
constexpr uint32_t Magic = 0x3157524D; // "MRW1"
constexpr uint32_t Version = 1;
constexpr uint32_t EndMark = 0x444E4557; // "WEND"
std::mutex Lock;                           // everything below except Gate / Worker
std::map<uint64_t, Image> Live;            // base -> guest image mapped now
std::unordered_map<uint64_t, Image> Carry; // key -> image of the file not mapped (yet / any more); kept when the file is rewritten
std::deque<std::pair<uint64_t, Rec>> Queue;
std::shared_mutex Gate;                    // background translation (shared) against image unmap (exclusive)
std::atomic<FEXCore::Core::InternalThreadState*> Worker {nullptr};
bool Inited {}, WorkerStarted {};
uint64_t Identity {}, NewSinceWrite {}, Freq {1};
fextl::string Path;
uint64_t Recorded {}, Written {}, LoadedImages {}, LoadedEntries {}, RejectedFile {}, MatchedImages {}, Queued {}, Warm {}, WarmTicks {},
  Skipped {}, Other {}, OtherTicks {}, NextReport {1024};

uint64_t HashBytes(uint64_t H, const void* Data, size_t N) {
  const auto* P = static_cast<const uint8_t*>(Data);
  size_t I = 0;
  for (; I + 8 <= N; I += 8) {
    uint64_t V;
    memcpy(&V, P + I, 8);
    H = (H ^ V) * 0x100000001B3ULL;
    H ^= H >> 29;
  }
  for (; I < N; ++I) {
    H = (H ^ P[I]) * 0x100000001B3ULL;
  }
  return H;
}
uint64_t HashU64(uint64_t H, uint64_t V) {
  return HashBytes(H, &V, sizeof(V));
}
// Header identity + every executable section of a mapped image (only the image's own pages are read).
uint64_t HashImage(uint64_t Base, uint64_t H) {
  const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(RtlImageNtHeader(reinterpret_cast<HMODULE>(Base)));
  if (!Nt) {
    return 0;
  }
  H = HashU64(H, Nt->FileHeader.TimeDateStamp);
  H = HashU64(H, Nt->FileHeader.NumberOfSections);
  H = HashU64(H, Nt->FileHeader.Machine);
  const auto* Sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(reinterpret_cast<const uint8_t*>(&Nt->OptionalHeader) +
                                                                  Nt->FileHeader.SizeOfOptionalHeader);
  for (unsigned I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {
    if (!(Sec[I].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
      continue;
    }
    H = HashU64(H, Sec[I].VirtualAddress);
    H = HashBytes(H, reinterpret_cast<const void*>(Base + Sec[I].VirtualAddress), Sec[I].Misc.VirtualSize);
  }
  return H;
}
fextl::string Lower(std::string_view S) {
  fextl::string R {S};
  for (auto& C : R) {
    if (C >= 'A' && C <= 'Z') {
      C = static_cast<char>(C - 'A' + 'a');
    }
  }
  return R;
}
void Report(const char* Why) { // under Lock
  char Line[512];
  const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1,
                                    "macrunner-fex32-warm: why={} mode={} identity={:016x} loaded_images={} loaded_entries={} rejected_file={} "
                                    "matched_images={} live_images={} recorded={} written={} queued={} pending={} warm={} warm_ms={} skipped={} "
                                    "other_compiles={} other_ms={}\n",
                                    Why, FEXCore::Utils::MacRunnerWarm32(), Identity, LoadedImages, LoadedEntries, RejectedFile, MatchedImages,
                                    Live.size(), Recorded, Written, Queued, Queue.size(), Warm, WarmTicks * 1000 / Freq, Skipped, Other,
                                    OtherTicks * 1000 / Freq);
  Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
  FEX::Windows::Logging::Raw(Line);
}
// The FEX CRT shim's fread / fwrite return BYTES (not element counts): always read / write single bytes x N.
bool Rd(FILE* F, void* P, size_t N) {
  return !N || fread(P, 1, N, F) == N;
}
bool Wr(FILE* F, const void* P, size_t N) {
  return !N || fwrite(P, 1, N, F) == N;
}
void LoadFile() { // under Lock
  FILE* F = fopen(Path.c_str(), "rb");
  if (!F) {
    return;
  }
  uint32_t Hdr[2] {}, Count {}, End {};
  uint64_t Ident {};
  bool Ok = Rd(F, Hdr, sizeof(Hdr)) && Rd(F, &Ident, 8) && Rd(F, &Count, 4) && Hdr[0] == Magic &&
            Hdr[1] == Version && Ident == Identity && Count < 65536;
  std::unordered_map<uint64_t, Image> Read;
  uint64_t Entries = 0;
  for (uint32_t I = 0; Ok && I < Count; ++I) {
    Image Img;
    uint32_t NameLen {}, N {};
    Ok = Rd(F, &Img.Key, 8) && Rd(F, &Img.Size, 8) && Rd(F, &NameLen, 4) && NameLen < 1024;
    if (!Ok) {
      break;
    }
    Img.Name.resize(NameLen);
    Ok = Rd(F, Img.Name.data(), NameLen) && Rd(F, &N, 4) && N < (1U << 22);
    if (!Ok) {
      break;
    }
    Img.Recs.resize(N);
    Ok = Rd(F, Img.Recs.data(), sizeof(Rec) * size_t {N});
    for (const auto& R : Img.Recs) {
      Img.Seen.insert(R.Rva);
    }
    Entries += N;
    Read.insert_or_assign(Img.Key, std::move(Img));
  }
  Ok = Ok && Rd(F, &End, 4) && End == EndMark;
  fclose(F);
  if (!Ok) {
    ++RejectedFile;
    return;
  }
  LoadedImages = Read.size();
  LoadedEntries = Entries;
  Carry = std::move(Read);
}
void WriteFile() { // under Lock; plain overwrite (the CRT shim has no rename): a cut-off file fails the end mark and is rejected
  FILE* F = fopen(Path.c_str(), "wb");
  if (!F) {
    return;
  }
  std::vector<const Image*> All;
  std::unordered_set<uint64_t> Keys;
  for (const auto& [Base, Img] : Live) {
    if (!Img.Recs.empty() && Keys.insert(Img.Key).second) {
      All.push_back(&Img);
    }
  }
  for (const auto& [Key, Img] : Carry) {
    if (!Img.Recs.empty() && Keys.insert(Key).second) {
      All.push_back(&Img);
    }
  }
  const uint32_t Hdr[2] {Magic, Version};
  const uint32_t Count = static_cast<uint32_t>(All.size());
  bool Ok = Wr(F, Hdr, sizeof(Hdr)) && Wr(F, &Identity, 8) && Wr(F, &Count, 4);
  for (const auto* Img : All) {
    const uint32_t NameLen = static_cast<uint32_t>(Img->Name.size()), N = static_cast<uint32_t>(Img->Recs.size());
    Ok = Ok && Wr(F, &Img->Key, 8) && Wr(F, &Img->Size, 8) && Wr(F, &NameLen, 4) &&
         Wr(F, Img->Name.data(), NameLen) && Wr(F, &N, 4) &&
         Wr(F, Img->Recs.data(), sizeof(Rec) * size_t {N});
  }
  Ok = Ok && Wr(F, &EndMark, 4);
  fclose(F);
  if (Ok) {
    ++Written;
  }
}
void Init() { // under Lock
  if (Inited) {
    return;
  }
  Inited = true;
  __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(Freq));
  Freq = Freq ? Freq : 1;
  uint64_t H = HashImage(reinterpret_cast<uint64_t>(&__ImageBase), 0xCBF29CE484222325ULL);
  std::vector<std::string_view> Keys;
  for (char** E = _environ; E && *E; ++E) {
    const std::string_view S {*E};
    const bool Codegen = S.starts_with("MACRUNNER_FEX") || S.starts_with("MACRUNNER_HB_X87") || S.starts_with("FEX_");
    const bool Neutral = S.starts_with("MACRUNNER_FEX32_WARM") || S.starts_with("MACRUNNER_FEX_JIT_REPORT_EVERY") ||
                         S.starts_with("MACRUNNER_FEX_CODEBUF_") || S.find('/') != S.npos || S.find('\\') != S.npos;
    if (Codegen && !Neutral) {
      Keys.push_back(S);
    }
  }
  std::sort(Keys.begin(), Keys.end());
  for (const auto S : Keys) {
    H = HashU64(HashBytes(H, S.data(), S.size()), 0x0A);
  }
  Identity = H;
  fextl::string Dir;
  if (const char* Override = getenv("MACRUNNER_FEX32_WARM_DIR"); Override && *Override) {
    Dir = Override;
  } else {
    Dir = fextl::fmt::format("{}warm32\\", FEX::Config::GetCacheDirectory());
  }
  std::error_code Ec;
  std::filesystem::create_directories(Dir, Ec);
  Path = fextl::fmt::format("{}{}-{:016x}.mrw", Dir, Lower(FEX::Windows::BaseName(FEX::Windows::GetExecutableFilePath())), Identity);
  LoadFile();
  Report("init");
}
bool Readable(uint64_t Address) {
  MEMORY_BASIC_INFORMATION Info {};
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
    return false;
  }
  constexpr DWORD ReadableMask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  return Info.State == MEM_COMMIT && (Info.Protect & ReadableMask) && !(Info.Protect & (PAGE_GUARD | PAGE_NOACCESS));
}
NTSTATUS WINAPI WorkerMain(void*) {
  static constexpr size_t DefaultWow64CS {4};
  FEX::Windows::InitCRTThread();
  FEXCore::Allocator::JITWriteThreadInit();
  auto* Thread = CTX->CreateThread(0, 0);
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32]();
  auto& GDT = NewSegments[DefaultWow64CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 0;
  GDT.D = 1;
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];
  Frame->State.cs_idx = DefaultWow64CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);
  FEX::Windows::CallRetStack::InitializeThread(Thread);
  GetTLS().ThreadState() = Thread;
  Thread->FrontendPtr = new FrontendThreadData();
  Worker.store(Thread, std::memory_order_release);
  LARGE_INTEGER Idle {.QuadPart = -20000}; // 2 ms
  for (;;) {
    std::pair<uint64_t, Rec> Item {};
    bool Have = false;
    {
      std::scoped_lock L(Lock);
      if (!Queue.empty()) {
        Item = Queue.front();
        Queue.pop_front();
        Have = true;
      }
    }
    if (!Have) {
      NtDelayExecution(FALSE, &Idle);
      continue;
    }
    std::shared_lock G(Gate);
    const uint64_t Rip = Item.first + Item.second.Rva;
    bool Mapped = false;
    {
      std::scoped_lock L(Lock);
      const auto It = Live.find(Item.first);
      Mapped = It != Live.end() && Item.second.Rva < It->second.Size;
    }
    if (!Mapped || !Readable(Rip) || !Readable((Rip & ~uint64_t {0xFFF}) + 0x1000)) {
      std::scoped_lock L(Lock);
      ++Skipped;
      continue;
    }
    auto& S = Frame->State;
    S.FCW = Item.second.Fcw;
    S.mxcsr = Item.second.Mxcsr;
    reinterpret_cast<uint8_t*>(&S.AbridgedFTW)[0] = Item.second.Ftw;
    {
      const uint16_t ModeWord = static_cast<uint16_t>((S.FCW & 0x0F3F) | (((S.mxcsr >> 13) & 7) << 12));
      memcpy(reinterpret_cast<uint8_t*>(&S.AbridgedFTW) + 4, &ModeWord, sizeof(ModeWord));
    }
    S.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = Item.second.Top & 7;
    for (unsigned Bit = 0; Bit < 6; ++Bit) {
      S.flags[FEXCore::X86State::X87FLAG_IE_LOC + Bit] = (Item.second.Exc >> Bit) & 1;
    }
    S.flags[FEXCore::X86State::RFLAG_TF_RAW_LOC] = 0;
    S.rip = Rip;
    CTX->CompileRIP(Thread, Rip);
  }
  return STATUS_SUCCESS;
}
void StartWorker() { // under Lock
  if (WorkerStarted) {
    return;
  }
  WorkerStarted = true;
  HANDLE Handle {};
  constexpr ULONG Flags = 0x20 /* SKIP_LOADER_INIT */ | 0x2 /* SKIP_THREAD_ATTACH */ | 0x4 /* HIDE_FROM_DEBUGGER */;
  if (!NtCreateThreadEx(&Handle, 0x1FFFFF, nullptr, NtCurrentProcess(), reinterpret_cast<void*>(&WorkerMain), nullptr, Flags, 0, 0, 0,
                        nullptr)) {
    NtClose(Handle);
  }
}
void OnCompiled(void* T, uint64_t Rip, uint64_t Ticks) {
  auto* Thread = static_cast<FEXCore::Core::InternalThreadState*>(T);
  std::scoped_lock L(Lock);
  if (Thread == Worker.load(std::memory_order_acquire)) {
    ++Warm;
    WarmTicks += Ticks;
  } else {
    ++Other;
    OtherTicks += Ticks;
    if (auto It = Live.upper_bound(Rip); It != Live.begin()) {
      --It;
      if (Rip - It->first < It->second.Size) {
        const uint32_t Rva = static_cast<uint32_t>(Rip - It->first);
        if (It->second.Seen.insert(Rva).second) {
          const auto& S = Thread->CurrentFrame->State;
          Rec R {.Rva = Rva, .Mxcsr = S.mxcsr, .Fcw = S.FCW, .Ftw = reinterpret_cast<const uint8_t*>(&S.AbridgedFTW)[0],
                 .Top = static_cast<uint8_t>(S.flags[FEXCore::X86State::X87FLAG_TOP_LOC] & 7)};
          for (unsigned Bit = 0; Bit < 6; ++Bit) {
            R.Exc |= static_cast<uint8_t>((S.flags[FEXCore::X86State::X87FLAG_IE_LOC + Bit] & 1) << Bit);
          }
          It->second.Recs.push_back(R);
          ++Recorded;
          ++NewSinceWrite;
        }
      }
    }
    if (NewSinceWrite >= 2048) {
      WriteFile();
      NewSinceWrite = 0;
      Report("write");
    }
  }
  if (Warm + Other >= NextReport) {
    NextReport *= 2;
    Report("count");
  }
}
void OnImageMap(uint64_t Base, std::string_view Name) {
  if (!FEXCore::Utils::MacRunnerWarm32()) {
    return;
  }
  const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(RtlImageNtHeader(reinterpret_cast<HMODULE>(Base)));
  if (!Nt || Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
    return; // guest images only
  }
  const fextl::string LowerName = Lower(Name);
  uint64_t Key = HashBytes(0xCBF29CE484222325ULL, LowerName.data(), LowerName.size());
  Key = HashU64(HashU64(Key, Base), Nt->OptionalHeader.SizeOfImage);
  Key = HashImage(Base, Key);
  std::scoped_lock L(Lock);
  Init();
  Image Img;
  Img.Key = Key;
  Img.Size = Nt->OptionalHeader.SizeOfImage;
  Img.Name = LowerName;
  if (auto C = Carry.find(Key); C != Carry.end()) {
    Img.Recs = std::move(C->second.Recs);
    Img.Seen = std::move(C->second.Seen);
    Carry.erase(C);
    ++MatchedImages;
    if (FEXCore::Utils::MacRunnerWarm32() == 2 && !Img.Recs.empty()) {
      for (const auto& R : Img.Recs) {
        Queue.emplace_back(Base, R);
      }
      Queued += Img.Recs.size();
      StartWorker();
    }
  }
  Live.insert_or_assign(Base, std::move(Img));
}
void OnImageUnmap(uint64_t Base, uint64_t Size) {
  if (!FEXCore::Utils::MacRunnerWarm32()) {
    return;
  }
  std::unique_lock G(Gate);
  std::scoped_lock L(Lock);
  const uint64_t End = Base + std::max<uint64_t>(Size, 1);
  for (auto It = Live.lower_bound(Base); It != Live.end() && It->first < End;) {
    if (!It->second.Recs.empty()) {
      Carry.insert_or_assign(It->second.Key, std::move(It->second));
    }
    It = Live.erase(It);
  }
  std::erase_if(Queue, [&](const auto& Item) { return Item.first >= Base && Item.first < End; });
}
void Flush() {
  if (!FEXCore::Utils::MacRunnerWarm32()) {
    return;
  }
  std::scoped_lock L(Lock);
  if (Inited && NewSinceWrite) {
    WriteFile();
    NewSinceWrite = 0;
  }
  if (Inited) {
    Report("term");
  }
}
} // namespace MRWarm

void HandleImageMap(uint64_t Address, bool MainImage = false) {
  fextl::string ModulePath = FEX::Windows::GetSectionFilePath(Address);
  fextl::string ModuleName = fextl::string {FEX::Windows::BaseName(ModulePath)};
  FEX::Windows::AliasPolicy::ImageMapped(ModuleName);
  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
  MRWarm::OnImageMap(Address, ModuleName);
}

void HandleImageUnmap(uint64_t Address, uint64_t Size) {
  MRWarm::OnImageUnmap(Address, Size);
  ImageTracker->HandleImageUnmap(Address, Size);
}
} // namespace

// LAZY-FLAGS (WOW64): host FPSR accumulates the guest SSE status while JIT code runs. The
// i386 guest's MXCSR is private to it (on x86 Windows the kernel never touches user MXCSR),
// so every exit to native wow64/ntdll code folds FPSR into the shadow and every entry
// replaces FPSR with the shadow status. Status = (shadow & 0x3F) | ToMXCSR(FPSR) throughout.
static inline bool LazyMXCSROn() {
  return FEXCore::LazyMXCSR::Enabled.load(std::memory_order_relaxed);
}

// X87-CTX (17.10.2026), MACRUNNER_FEX_X87_CONTEXT=1: the i386 CONTEXT carries x87 registers in stack order, ST(0)..ST(7)
// (FloatSave.RegisterArea in FNSAVE layout, ExtendedRegisters.FloatRegisters in FXSAVE layout), while FEX's State.mm is
// indexed by physical register (TOP + i) & 7; the tags of both layouts are indexed by physical register. Without the key the
// registers were copied unrotated, RegisterArea was never filled, the full TagWord was computed from physical registers taken
// as stack order, FloatSave was not flushed to the CPU area and a FloatSave-only SetThreadContext was ignored.
// Context transfer code only: nothing in translated code.
static bool MRX87Context;
// X87-CTX P5 (MACRUNNER_FEX_X87_FAULT_STATE): restore the x87 stack state the stack pass still held in host registers.
static bool MRX87FaultState;
// MacRunner DSNATIVE 07.11 (MACRUNNER_FEX_SELF_CTX_FAST=1; default 0 = the previous code, unchanged): BTCpuGetContext,
// BTCpuSetContext and FlushThreadStateContext on the CURRENT-thread pseudo-handle without wineserver requests. Before, each
// such call made 7-8 of them (NtQueryObject for the access check, NtDuplicateObject, NtQueryInformationThread twice for the
// TEB, the wow64 context get/set through the duplicated handle, NtClose). wow64 calls these 4-5 times per kernel->user
// callback: 95 % of the callback's time in a sample of 60 000 callbacks (07.11). With the pseudo-handle: full access by
// definition, the TEB is NtCurrentTeb() (checked once at init), and Wine serves the current thread's wow64 context from its
// CPU area (ntdll/unix/signal_arm64.c get/set_thread_wow64_context, `self`) - where the duplicated handle also ends up,
// only after a server round trip. Other threads keep the full path.
static bool MRSelfCtxFast;
static std::atomic<int32_t> MRSelfCtxFastCalls;
static bool MRIsSelf(HANDLE Thread) {
  if (!MRSelfCtxFast || Thread != GetCurrentThread()) {
    return false;
  }
  const int32_t N = MRSelfCtxFastCalls.fetch_add(1, std::memory_order_relaxed) + 1;
  if (N == 1 || N == 1024 || N == 65536) {
    FEX::Windows::Logging::Raw(N == 1 ? "[macrunner-fex-selfctx] fast call 1\n" :
                               N == 1024 ? "[macrunner-fex-selfctx] fast call 1024\n" : "[macrunner-fex-selfctx] fast call 65536\n");
  }
  return true;
}
// MacRunner DSNATIVE 08.11 (MACRUNNER_FEX_CTX_DIRECT=1, needs MACRUNNER_FEX_SELF_CTX_FAST=1; default 0 = unchanged): the
// CURRENT thread's wow64 context is read and written in its CPU area directly - RtlWow64GetCurrentCpuArea gives a pointer,
// no syscall - instead of RtlWow64Get/SetThreadContext = NtQuery/SetInformationThread(ThreadWow64Context), which for the
// current thread land in exactly this field-by-field copy on the unix side (Wine dlls/ntdll/unix/signal_arm64.c
// get/set_thread_wow64_context, `self`), including the RESET_STATE flag and the exception-reporting flags. wow64 calls
// BTCpuGetContext twice and BTCpuSetContext twice per kernel->user callback: 2 + 2 + 3 + 3 = 10 syscalls -> 0.
#ifndef WOW64_TLS_CPURESERVED
#define WOW64_TLS_CPURESERVED 1
#endif
static bool MRCtxDirect;
static std::atomic<int32_t> MRCtxDirectCalls;
struct MRWow64CpuReserved {
  USHORT Flags;
  USHORT Machine;
};
static WOW64_CONTEXT* MRCpuAreaContext() {
  USHORT Machine = 0;
  WOW64_CONTEXT* WowContext = nullptr;
  if (RtlWow64GetCurrentCpuArea(&Machine, reinterpret_cast<void**>(&WowContext), nullptr) || Machine != IMAGE_FILE_MACHINE_I386) {
    return nullptr;
  }
  const int32_t N = MRCtxDirectCalls.fetch_add(1, std::memory_order_relaxed) + 1;
  if (N == 1 || N == 1024 || N == 65536) {
    FEX::Windows::Logging::Raw(N == 1 ? "[macrunner-fex-ctxdirect] direct call 1\n" :
                               N == 1024 ? "[macrunner-fex-ctxdirect] direct call 1024\n" : "[macrunner-fex-ctxdirect] direct call 65536\n");
  }
  return WowContext;
}
static NTSTATUS MRSetSelfWowContext(const WOW64_CONTEXT* Context) {
  WOW64_CONTEXT* Frame = MRCpuAreaContext();
  if (!Frame) {
    return STATUS_INVALID_PARAMETER;
  }
  const DWORD Flags = Context->ContextFlags & ~WOW64_CONTEXT_i386;
  if (Flags & (WOW64_CONTEXT_INTEGER & ~WOW64_CONTEXT_i386)) {
    Frame->Eax = Context->Eax;
    Frame->Ebx = Context->Ebx;
    Frame->Ecx = Context->Ecx;
    Frame->Edx = Context->Edx;
    Frame->Esi = Context->Esi;
    Frame->Edi = Context->Edi;
  }
  if (Flags & (WOW64_CONTEXT_CONTROL & ~WOW64_CONTEXT_i386)) {
    Frame->Esp = Context->Esp;
    Frame->Ebp = Context->Ebp;
    Frame->Eip = Context->Eip;
    Frame->EFlags = Context->EFlags;
    Frame->SegCs = Context->SegCs;
    Frame->SegSs = Context->SegSs;
    reinterpret_cast<MRWow64CpuReserved*>(NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED])->Flags |= 1; // WOW64_CPURESERVED_FLAG_RESET_STATE
  }
  if (Flags & (WOW64_CONTEXT_SEGMENTS & ~WOW64_CONTEXT_i386)) {
    Frame->SegDs = Context->SegDs;
    Frame->SegEs = Context->SegEs;
    Frame->SegFs = Context->SegFs;
    Frame->SegGs = Context->SegGs;
  }
  if (Flags & (WOW64_CONTEXT_DEBUG_REGISTERS & ~WOW64_CONTEXT_i386)) {
    Frame->Dr0 = Context->Dr0;
    Frame->Dr1 = Context->Dr1;
    Frame->Dr2 = Context->Dr2;
    Frame->Dr3 = Context->Dr3;
    Frame->Dr6 = Context->Dr6;
    Frame->Dr7 = Context->Dr7;
  }
  if (Flags & (WOW64_CONTEXT_EXTENDED_REGISTERS & ~WOW64_CONTEXT_i386)) {
    memcpy(Frame->ExtendedRegisters, Context->ExtendedRegisters, sizeof(Context->ExtendedRegisters));
  }
  if (Flags & (WOW64_CONTEXT_FLOATING_POINT & ~WOW64_CONTEXT_i386)) {
    memcpy(&Frame->FloatSave, &Context->FloatSave, sizeof(Context->FloatSave));
  }
  return STATUS_SUCCESS;
}
static NTSTATUS MRGetSelfWowContext(WOW64_CONTEXT* Context) {
  const WOW64_CONTEXT* Frame = MRCpuAreaContext();
  if (!Frame) {
    return STATUS_INVALID_PARAMETER;
  }
  const DWORD Needed = Context->ContextFlags & ~WOW64_CONTEXT_i386;
  if (Needed & (WOW64_CONTEXT_INTEGER & ~WOW64_CONTEXT_i386)) {
    Context->Eax = Frame->Eax;
    Context->Ebx = Frame->Ebx;
    Context->Ecx = Frame->Ecx;
    Context->Edx = Frame->Edx;
    Context->Esi = Frame->Esi;
    Context->Edi = Frame->Edi;
    Context->ContextFlags |= WOW64_CONTEXT_INTEGER;
  }
  if (Needed & (WOW64_CONTEXT_CONTROL & ~WOW64_CONTEXT_i386)) {
    Context->Esp = Frame->Esp;
    Context->Ebp = Frame->Ebp;
    Context->Eip = Frame->Eip;
    Context->EFlags = Frame->EFlags;
    Context->SegCs = Frame->SegCs;
    Context->SegSs = Frame->SegSs;
    Context->ContextFlags |= WOW64_CONTEXT_CONTROL;
  }
  if (Needed & (WOW64_CONTEXT_SEGMENTS & ~WOW64_CONTEXT_i386)) {
    Context->SegDs = Frame->SegDs;
    Context->SegEs = Frame->SegEs;
    Context->SegFs = Frame->SegFs;
    Context->SegGs = Frame->SegGs;
    Context->ContextFlags |= WOW64_CONTEXT_SEGMENTS;
  }
  if (Needed & (WOW64_CONTEXT_EXTENDED_REGISTERS & ~WOW64_CONTEXT_i386)) {
    memcpy(Context->ExtendedRegisters, Frame->ExtendedRegisters, sizeof(Context->ExtendedRegisters));
    Context->ContextFlags |= WOW64_CONTEXT_EXTENDED_REGISTERS;
  }
  if (Needed & (WOW64_CONTEXT_FLOATING_POINT & ~WOW64_CONTEXT_i386)) {
    memcpy(&Context->FloatSave, &Frame->FloatSave, sizeof(Context->FloatSave));
    Context->ContextFlags |= WOW64_CONTEXT_FLOATING_POINT;
  }
  if (Needed & (WOW64_CONTEXT_DEBUG_REGISTERS & ~WOW64_CONTEXT_i386)) {
    Context->Dr0 = Frame->Dr0;
    Context->Dr1 = Frame->Dr1;
    Context->Dr2 = Frame->Dr2;
    Context->Dr3 = Frame->Dr3;
    Context->Dr6 = Frame->Dr6;
    Context->Dr7 = Frame->Dr7;
  }
  // set_context_exception_reporting_flags(&ContextFlags, CONTEXT_SERVICE_ACTIVE) of the unix side
  if (!(Context->ContextFlags & WOW64_CONTEXT_EXCEPTION_REQUEST)) {
    Context->ContextFlags &= ~(WOW64_CONTEXT_EXCEPTION_REPORTING | WOW64_CONTEXT_SERVICE_ACTIVE | WOW64_CONTEXT_EXCEPTION_ACTIVE);
  } else {
    Context->ContextFlags = (Context->ContextFlags & ~(WOW64_CONTEXT_SERVICE_ACTIVE | WOW64_CONTEXT_EXCEPTION_ACTIVE)) |
                            WOW64_CONTEXT_EXCEPTION_REPORTING | WOW64_CONTEXT_SERVICE_ACTIVE;
  }
  return STATUS_SUCCESS;
}
// Measurement only (MACRUNNER_FEX_CTX_DIRECT_AB=N, N even, needs the key on): inside ONE process the direct path is switched
// off and on every N current-thread BTCpuSetContext calls (2 per kernel->user callback), batch wall time from CNTVCT; every
// 128 batches the medians per arm and the paired difference (direct batch minus the syscall batch before it), ns per batch.
static int32_t MRCtxAB = -1;
static uint32_t MRCtxABSet;
static uint64_t MRCtxABT0;
static uint32_t MRCtxABNs[8192];
static int32_t MRCtxABBatches;
static bool MRCtxABDirect = true;
static uint64_t MRCtxABTick() { uint64_t V; __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(V)); return V; }
static uint64_t MRCtxABFreq() { uint64_t V; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(V)); return V; }
static void MRCtxABSort(int32_t* V, int32_t N) {
  for (int32_t Gap = N / 2; Gap > 0; Gap /= 2) {
    for (int32_t I = Gap; I < N; I++) {
      for (int32_t J = I; J >= Gap && V[J - Gap] > V[J]; J -= Gap) {
        int32_t T = V[J]; V[J] = V[J - Gap]; V[J - Gap] = T;
      }
    }
  }
}
static void MRCtxABReport() {
  static int32_t A[4096], B[4096], D[4096];
  int32_t N = 0, Neg = 0;
  for (int32_t K = 2; 2 * K + 1 < MRCtxABBatches; K++) { // the first two pairs hold the start
    A[N] = MRCtxABNs[2 * K]; B[N] = MRCtxABNs[2 * K + 1]; D[N] = B[N] - A[N]; Neg += D[N] < 0; N++;
  }
  if (N < 8) return;
  MRCtxABSort(A, N); MRCtxABSort(B, N); MRCtxABSort(D, N);
  char Buf[512];
  snprintf(Buf, sizeof(Buf), "[macrunner-fex-ctxdirect-ab] N=%d pairs=%d ns_per_batch: A(syscalls) median=%d B(direct) median=%d | B-A per pair: "
           "median=%d p10=%d p25=%d p75=%d p90=%d min=%d max=%d negative=%d/%d\n", MRCtxAB, N, A[N / 2], B[N / 2], D[N / 2], D[N / 10],
           D[N / 4], D[3 * N / 4], D[9 * N / 10], D[0], D[N - 1], Neg, N);
  FEX::Windows::Logging::Raw(Buf);
}
static void MRCtxABTickSet() { // one current-thread BTCpuSetContext
  if (MRCtxAB <= 0) return;
  const uint32_t C = ++MRCtxABSet;
  if (C % MRCtxAB) return;
  const uint64_t T = MRCtxABTick();
  const int32_t Bt = C / MRCtxAB - 1;   // the batch that just ended
  if (Bt >= 1 && Bt < 8192) {
    MRCtxABNs[Bt] = static_cast<uint32_t>((T - MRCtxABT0) * 1000000000ull / MRCtxABFreq());
    MRCtxABBatches = Bt + 1;
    if (!(MRCtxABBatches % 128)) MRCtxABReport();
  }
  MRCtxABT0 = T;
  MRCtxABDirect = (C / MRCtxAB) & 1;   // next batch: even = syscalls (A), odd = direct (B)
}

// no I386 CPU area on this thread (not expected after thread init): the syscall path, as without the key
static NTSTATUS MRWowSet(HANDLE Thread, bool Self, WOW64_CONTEXT* Context) {
  if (Self && MRCtxDirect && MRCtxABDirect && MRSetSelfWowContext(Context) == STATUS_SUCCESS) {
    return STATUS_SUCCESS;
  }
  return RtlWow64SetThreadContext(Thread, Context);
}
static NTSTATUS MRWowGet(HANDLE Thread, bool Self, WOW64_CONTEXT* Context) {
  if (Self && MRCtxDirect && MRCtxABDirect && MRGetSelfWowContext(Context) == STATUS_SUCCESS) {
    return STATUS_SUCCESS;
  }
  return RtlWow64GetThreadContext(Thread, Context);
}
static std::pair<NTSTATUS, TLS> MRThreadTLS(HANDLE Thread, bool Self) {
  if (Self) {
    return {STATUS_SUCCESS, GetTLS()};
  }
  return GetThreadTLS(Thread);
}
// Which image wins (measured on Windows Server 2022, AMD EPYC 7763, probe x87ctx r1): with CONTEXT_FLOATING_POINT in a
// Set or a continued context, the x87 state is FloatSave's; ExtendedRegisters' x87 part counts only without it. Server 2025
// differs (its exception continue takes ExtendedRegisters, its cross-thread Set took neither); 2022 is the games' platform.
static void MRFloatSaveToXSave(const WOW64_FLOATING_SAVE_AREA& F, XSAVE_FORMAT* X) {
  X->ControlWord = static_cast<uint16_t>(F.ControlWord);
  X->StatusWord = static_cast<uint16_t>(F.StatusWord);
  X->TagWord = FEXCore::FPState::ConvertToAbridgedFTW(static_cast<uint16_t>(F.TagWord));
  X->ErrorOffset = F.ErrorOffset;
  X->ErrorSelector = static_cast<uint16_t>(F.ErrorSelector);
  X->ErrorOpcode = static_cast<uint16_t>(F.ErrorSelector >> 16);
  X->DataOffset = F.DataOffset;
  X->DataSelector = static_cast<uint16_t>(F.DataSelector);
  for (unsigned I = 0; I < 8; ++I) {
    memset(&X->FloatRegisters[I], 0, sizeof(X->FloatRegisters[I]));
    memcpy(&X->FloatRegisters[I], &F.RegisterArea[10 * I], 10);
  }
}
static bool MRFloatSaveEqual(const WOW64_FLOATING_SAVE_AREA& A, const WOW64_FLOATING_SAVE_AREA& B) {
  return (A.ControlWord & 0xffff) == (B.ControlWord & 0xffff) && (A.StatusWord & 0xffff) == (B.StatusWord & 0xffff) &&
         (A.TagWord & 0xffff) == (B.TagWord & 0xffff) && !memcmp(A.RegisterArea, B.RegisterArea, sizeof(A.RegisterArea));
}
static inline void LazyMXCSRFold(FEXCore::Core::CPUState& State, uint64_t Fpsr) {
  State.mxcsr |= FEXCore::LazyMXCSR::ToMXCSR(static_cast<uint32_t>(Fpsr));
}
static inline void LazyMXCSRFoldLive(FEXCore::Core::CPUState& State) {
  uint64_t Fpsr;
  __asm__ __volatile__("mrs %0, fpsr" : "=r"(Fpsr) : : "memory");
  LazyMXCSRFold(State, Fpsr);
}
static inline void LazyMXCSRSeed(FEXCore::Core::CPUState& State) {
  const uint64_t Fpsr = FEXCore::LazyMXCSR::ToFPSR(State.mxcsr);
  State.mxcsr &= ~0x3DU;
  __asm__ __volatile__("msr fpsr, %0" : : "r"(Fpsr) : "memory");
}

namespace Context {
void LoadStateFromWowContext(FEXCore::Core::InternalThreadState* Thread, uint64_t WowTEB, WOW64_CONTEXT* Context) {
  auto& State = Thread->CurrentFrame->State;

  // General register state

  State.gregs[FEXCore::X86State::REG_RAX] = Context->Eax;
  State.gregs[FEXCore::X86State::REG_RBX] = Context->Ebx;
  State.gregs[FEXCore::X86State::REG_RCX] = Context->Ecx;
  State.gregs[FEXCore::X86State::REG_RDX] = Context->Edx;
  State.gregs[FEXCore::X86State::REG_RSI] = Context->Esi;
  State.gregs[FEXCore::X86State::REG_RDI] = Context->Edi;
  State.gregs[FEXCore::X86State::REG_RBP] = Context->Ebp;
  State.gregs[FEXCore::X86State::REG_RSP] = Context->Esp;

  State.rip = Context->Eip;
  // EFlags mask: RF belongs to the delivered context only (FEX has no debug faults for it to suppress).
  CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags & ~0x10000U);

  State.es_idx = Context->SegEs & 0xffff;
  State.cs_idx = Context->SegCs & 0xffff;
  State.ss_idx = Context->SegSs & 0xffff;
  State.ds_idx = Context->SegDs & 0xffff;
  State.fs_idx = Context->SegFs & 0xffff;
  State.gs_idx = Context->SegGs & 0xffff;

  // The TEB is the only populated GDT entry by default
  auto GDT = State.GetSegmentFromIndex(State, (Context->SegFs & 0xffff));
  State.SetGDTBase(GDT, WowTEB);
  State.SetGDTLimit(GDT, 0xF'FFFFU);
  State.fs_cached = WowTEB;
  State.es_cached = 0;
  State.cs_cached = 0;
  State.ss_cached = 0;
  State.ds_cached = 0;

  // Floating-point register state
  const auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);
  if (MacRunnerAppleAFPEnabled || LazyMXCSROn()) State.mxcsr = XSave->MxCsr & 0xFFFFU;

  CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(XSave->XmmRegisters), nullptr);
  if (MRX87Context && (Context->ContextFlags & WOW64_CONTEXT_FLOATING_POINT) == WOW64_CONTEXT_FLOATING_POINT) {
    auto* Data = GetFrontendThreadData(Thread);
    // Merged CPU-area context (a Set from another thread): the Set's flags are gone, so a FloatSave that differs from what
    // this thread last handed out marks a FLOATING_POINT Set, and FloatSave wins. BTCpuSetContext decides by the flags.
    if (Data && Data->X87SnapValid) {
      Data->X87SnapValid = false;
      if (!MRFloatSaveEqual(Context->FloatSave, Data->X87SnapFn)) {
        MRFloatSaveToXSave(Context->FloatSave, reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters));
      }
    }
  }
  if (MRX87Context) {
    // ST(I) of this context lands in physical register (TOP + I) & 7, TOP being the context's own (handler edits included).
    const unsigned Top = (XSave->StatusWord >> 11) & 7;
    for (unsigned I = 0; I < 8; ++I) {
      memcpy(State.mm[(Top + I) & 7], &XSave->FloatRegisters[I], sizeof(State.mm[0]));
    }
  } else {
    memcpy(State.mm, XSave->FloatRegisters, sizeof(State.mm));
  }

  State.FCW = XSave->ControlWord;
  {
    // TRANS32 MODE_WORD (HBX87PCX.h): FCW and MXCSR were (re)set from the context -- keep the entry check's mode word with them.
    const uint16_t ModeWord = static_cast<uint16_t>((State.FCW & 0x0F3F) | (((State.mxcsr >> 13) & 7) << 12));
    memcpy(reinterpret_cast<uint8_t*>(&State.AbridgedFTW) + 4, &ModeWord, sizeof(ModeWord));
  }
  State.flags[FEXCore::X86State::X87FLAG_IE_LOC] = XSave->StatusWord & 1;
  State.flags[FEXCore::X86State::X87FLAG_SF_LOC] = (XSave->StatusWord >> 6) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (XSave->StatusWord >> 8) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (XSave->StatusWord >> 9) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (XSave->StatusWord >> 10) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (XSave->StatusWord >> 14) & 1;
  State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (XSave->StatusWord >> 11) & 0b111;
  if (FEXCore::HBX87::StateFix::ExceptionFlagsFor(false)) {
    // MacRunner X87-F4.2: the exception flags travel with the context, like IE.
    for (unsigned Bit = 1; Bit < 6; ++Bit) {
      State.flags[FEXCore::X86State::X87FLAG_IE_LOC + Bit] = (XSave->StatusWord >> Bit) & 1;
    }
    State.flags[FEXCore::X86State::X87FLAG_ES_LOC] = (XSave->StatusWord >> 7) & 1;
    State.flags[FEXCore::X86State::X87FLAG_B_LOC] = (XSave->StatusWord >> 15) & 1;
  }
  State.AbridgedFTW = XSave->TagWord;
}

void StoreWowContextFromState(FEXCore::Core::InternalThreadState* Thread, WOW64_CONTEXT* Context) {
  auto& State = Thread->CurrentFrame->State;

  // General register state

  Context->Eax = State.gregs[FEXCore::X86State::REG_RAX];
  Context->Ebx = State.gregs[FEXCore::X86State::REG_RBX];
  Context->Ecx = State.gregs[FEXCore::X86State::REG_RCX];
  Context->Edx = State.gregs[FEXCore::X86State::REG_RDX];
  Context->Esi = State.gregs[FEXCore::X86State::REG_RSI];
  Context->Edi = State.gregs[FEXCore::X86State::REG_RDI];
  Context->Ebp = State.gregs[FEXCore::X86State::REG_RBP];
  Context->Esp = State.gregs[FEXCore::X86State::REG_RSP];

  Context->Eip = State.rip;
  Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);

  Context->SegEs = State.es_idx;
  Context->SegCs = State.cs_idx;
  Context->SegSs = State.ss_idx;
  Context->SegDs = State.ds_idx;
  Context->SegFs = State.fs_idx;
  Context->SegGs = State.gs_idx;

  // Floating-point register state

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(Context->ExtendedRegisters);
  if (MacRunnerAppleAFPEnabled || LazyMXCSROn()) XSave->MxCsr = State.mxcsr;

  CTX->ReconstructXMMRegisters(Thread, reinterpret_cast<__uint128_t*>(XSave->XmmRegisters), nullptr);
  if (MRX87Context) {
    const unsigned Top = State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] & 7;
    for (unsigned I = 0; I < 8; ++I) {
      memcpy(&XSave->FloatRegisters[I], State.mm[(Top + I) & 7], sizeof(State.mm[0]));
    }
  } else {
    memcpy(XSave->FloatRegisters, State.mm, sizeof(State.mm));
  }

  XSave->ControlWord = State.FCW;
  XSave->StatusWord = (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) | (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
                      (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) | (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
                      (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14) |
                      (State.flags[FEXCore::X86State::X87FLAG_SF_LOC] << 6) | State.flags[FEXCore::X86State::X87FLAG_IE_LOC];
  if (FEXCore::HBX87::StateFix::ExceptionFlagsFor(false)) {
    for (unsigned Bit = 1; Bit < 6; ++Bit) {
      XSave->StatusWord |= (State.flags[FEXCore::X86State::X87FLAG_IE_LOC + Bit] & 1) << Bit;
    }
    XSave->StatusWord |= ((State.flags[FEXCore::X86State::X87FLAG_ES_LOC] & 1) << 7) | ((State.flags[FEXCore::X86State::X87FLAG_B_LOC] & 1) << 15);
  }
  XSave->TagWord = State.AbridgedFTW;

  Context->FloatSave.ControlWord = XSave->ControlWord;
  Context->FloatSave.StatusWord = XSave->StatusWord;
  if (MRX87Context) {
    // FNSAVE view of the same image: ST(I) in stack order, the full tag word from the stack-ordered registers.
    auto& Stack = *reinterpret_cast<uint64_t(*)[8][2]>(XSave->FloatRegisters);
    Context->FloatSave.TagWord = FEXCore::FPState::ConvertFromAbridgedFTW(XSave->StatusWord, Stack, XSave->TagWord); // upper 16 bits 0, as Windows
    for (unsigned I = 0; I < 8; ++I) {
      memcpy(&Context->FloatSave.RegisterArea[10 * I], &XSave->FloatRegisters[I], 10);
    }
  } else {
    Context->FloatSave.TagWord = FEXCore::FPState::ConvertFromAbridgedFTW(XSave->StatusWord, State.mm, XSave->TagWord);
  }
  Context->FloatSave.ErrorOffset = XSave->ErrorOffset;
  Context->FloatSave.ErrorSelector = XSave->ErrorSelector | (XSave->ErrorOpcode << 16);
  Context->FloatSave.DataOffset = XSave->DataOffset;
  Context->FloatSave.DataSelector = XSave->DataSelector;
  Context->FloatSave.Cr0NpxState = MRX87Context ? 0 : XSave->StatusWord | 0xffff0000; // Windows 2022/2025: 0
  if (MRX87Context) {
    if (auto* Data = GetFrontendThreadData(Thread)) {
      Data->X87SnapFn = Context->FloatSave;
      Data->X87SnapValid = true;
    }
  }
}

NTSTATUS FlushThreadStateContext(HANDLE Thread) {
  const bool Self = MRIsSelf(Thread);
  const auto [Err, TLS] = MRThreadTLS(Thread, Self);
  if (Err) {
    return Err;
  }

  WOW64_CONTEXT TmpWowContext {.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS};
  if (MRX87Context) TmpWowContext.ContextFlags |= WOW64_CONTEXT_FLOATING_POINT; // GetThreadContext(FLOATING_POINT) reads FloatSave

  Context::StoreWowContextFromState(TLS.ThreadState(), &TmpWowContext);
  return MRWowSet(Thread, Self, &TmpWowContext);
}

void ReconstructThreadState(TLS TLS, CONTEXT* Context, bool PublishedContinuation = false) {
  const auto& Config = SignalDelegator->GetConfig();
  auto* Thread = TLS.ThreadState();
  auto& State = Thread->CurrentFrame->State;

  if (!PublishedContinuation) {
    State.rip = CTX->RestoreRIPFromHostPC(Thread, Context->Pc);
  }

  // Spill all SRA GPRs
  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    State.gregs[i] = Context->X[Config.SRAGPRMapping[i]];
  }

  // Spill all SRA FPRs
  for (size_t i = 0; i < Config.SRAFPRCount; i++) {
    memcpy(State.xmm.sse.data[i], &Context->V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
  }

  // CALLRET4 folded stack engine: a fault on a step of a folded run -- the host register lags the architectural ESP by a
  // difference the faulting access itself encodes (0 everywhere else and with the key off).
  if (const int64_t MRFold = CTX->MRStackFoldDelta(Thread, Context->Pc)) {
    State.gregs[FEXCore::X86State::REG_RSP] = static_cast<uint32_t>(State.gregs[FEXCore::X86State::REG_RSP] + MRFold);
  }

  // Spill EFlags
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, true, Context->X, Context->Cpsr);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
  if (LazyMXCSROn()) {
    // TRANS32 PC_EXACT (HBX87PCX.h FpsrFixEnabled): inside a recorded x87 region (bit 63) the guest status is the recorded one;
    // the region is abandoned here.
    auto& Saved = Thread->CurrentFrame->Pointers.X87PCXSavedFPSR;
    LazyMXCSRFold(State, (Saved >> 63) ? (Saved & 0xffffffffULL) : Context->Fpsr);
    if (Saved >> 63) {
      // The region's end check will not run: callers resume through the dispatcher with this context (suspend, inline SMC), so the
      // host FPSR must lose the x87 stubs' bits here, as the end check would have done (status = mxcsr | FPSR stays the same).
      Context->Fpsr = static_cast<uint32_t>(Saved);
    }
    Saved = 0;
  }
  if (MRX87FaultState) {
    // Every caller leaves the block (exception delivery or a dispatcher restart), so CPUState may take the pending x87 state.
    FEXCore::Core::X87Fault::Materialize(Thread->CurrentFrame, Context->Pc, Context->X, reinterpret_cast<const __uint128_t*>(Context->V),
                                         Context->Sp);
  }
  FEXCore::HBX87::LazyFIP::OnLeave(State); // G3FABLE: the lazy x87 last-instruction pointer as the eager scheme would have left it
}

WOW64_CONTEXT ReconstructWowContext(TLS TLS, CONTEXT* Context) {
  if (!IsDispatcherAddress(Context->Pc)) {
    ReconstructThreadState(TLS, Context);
  } else if (LazyMXCSROn()) {
    LazyMXCSRFold(TLS.ThreadState()->CurrentFrame->State, Context->Fpsr);
  }

  WOW64_CONTEXT WowContext {
    .ContextFlags = WOW64_CONTEXT_ALL,
  };

  auto* XSave = reinterpret_cast<XSAVE_FORMAT*>(WowContext.ExtendedRegisters);
  XSave->ControlWord = 0x27f;
  XSave->MxCsr = 0x1f80;

  Context::StoreWowContextFromState(TLS.ThreadState(), &WowContext);
  return WowContext;
}

static std::optional<FEX::Windows::TSOHandlerConfig> HandlerConfig;

bool HandleUnalignedAccess(TLS TLS, CONTEXT* Context) {
  auto Thread = TLS.ThreadState();
  if (!Thread->CTX->IsAddressInCodeBuffer(Thread, Context->Pc)) {
    return false;
  }

  const auto Result =
    FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, HandlerConfig->GetUnalignedHandlerType(), Context->Pc, &Context->X0);
  Context->Pc += Result.value_or(0);
  return Result.has_value();
}

void LockJITContext(TLS TLS) {
  uint32_t Expected = TLS.ControlWord().load(), New;

  // Spin until PAUSED is unset, setting IN_JIT when that occurs
  do {
    Expected = Expected & ~ControlBits::PAUSED;
    New = (Expected | ControlBits::IN_JIT) & ~ControlBits::WOW_CPU_AREA_DIRTY;
  } while (!TLS.ControlWord().compare_exchange_weak(Expected, New, std::memory_order::relaxed));
  std::atomic_signal_fence(std::memory_order::seq_cst);

  // If the CPU area is dirty, flush it to the JIT context before reentry
  if (Expected & ControlBits::WOW_CPU_AREA_DIRTY) {
    WOW64_CONTEXT* WowContext;
    RtlWow64GetCurrentCpuArea(nullptr, reinterpret_cast<void**>(&WowContext), nullptr);
    Context::LoadStateFromWowContext(TLS.ThreadState(), GetWowTEB(NtCurrentTeb()), WowContext);
  }
}

void UnlockJITContext(TLS TLS) {
  std::atomic_signal_fence(std::memory_order::seq_cst);
  TLS.ControlWord().fetch_and(~ControlBits::IN_JIT, std::memory_order::relaxed);
}

class ScopedJITContextLock {
private:
  TLS TLSData;
  bool Acquired {};

public:
  // Context APIs can reenter from ResetToConsistentState on the owning thread.
  // That caller has already reconstructed guest state, but still owns IN_JIT.
  // Waiting for PAUSED here would prevent the owner from publishing its exit;
  // releasing IN_JIT in this nested scope would publish it too early instead.
  static inline bool PreserveOwnerReentry {true};
  static inline bool DiagnoseOwnerReentry {};
  static inline std::atomic<unsigned> RunningDiagnosticBudget {32};
  static inline std::atomic<unsigned> PausedDiagnosticBudget {32};

  ScopedJITContextLock(TLS TLSData, bool ContextAPI = false)
    : TLSData {TLSData} {
    const uint32_t Before = ContextAPI && TLSData.TEB == NtCurrentTeb()
                              ? TLSData.ControlWord().load(std::memory_order::relaxed) : 0;
    const bool OwnerReentry = Before & ControlBits::IN_JIT;
    if (OwnerReentry && DiagnoseOwnerReentry) {
      auto& Counter = Before & ControlBits::PAUSED ? PausedDiagnosticBudget : RunningDiagnosticBudget;
      unsigned Budget = Counter.load(std::memory_order::relaxed);
      while (Budget && !Counter.compare_exchange_weak(Budget, Budget - 1, std::memory_order::relaxed)) {}
      if (Budget) {
        if (Before & ControlBits::PAUSED) {
          FEX::Windows::Logging::Raw(PreserveOwnerReentry
            ? "mr-context-owner: self=1 IN_JIT=1 PAUSED=1 action=preserve\n"
            : "mr-context-owner: self=1 IN_JIT=1 PAUSED=1 action=wait\n");
        } else {
          FEX::Windows::Logging::Raw(PreserveOwnerReentry
            ? "mr-context-owner: self=1 IN_JIT=1 PAUSED=0 action=preserve\n"
            : "mr-context-owner: self=1 IN_JIT=1 PAUSED=0 action=reacquire\n");
        }
        if (Budget == 1) {
          FEX::Windows::Logging::Raw("mr-context-owner: diagnostic=DROPPED budget=32/state/process\n");
        }
      }
    }
    if (OwnerReentry && PreserveOwnerReentry) {
      return;
    }
    LockJITContext(TLSData);
    Acquired = true;
  }

  ~ScopedJITContextLock() {
    if (Acquired) {
      UnlockJITContext(TLSData);
    }
  }
};

// ★ REGION4 13.11.2026 EXIT_SCAN v2 (precise suspend). A caller compiled with MACRUNNER_FEX32_EXIT_SCAN leaves undefined status
// flags at a call whose target overwrites all of them before reading any (Decoder::MRTargetKillsFlags). From that call to the
// callee's first full flag write the guest flags exist nowhere, so a suspension there could not report them. Such a callee's entry
// poll stores at WindowSuspendFaultOffset (Decoder MRWindowEntries -> JIT EmitEntryPoint); when the guest got there by a call --
// [ESP] is a return address whose call instruction targets this RIP -- the thread is not stopped: the poll store is stepped over with
// the page still protected, and the next poll (the callee's own loop headers, the next entry, ...) suspends. Moving a suspension to
// a later boundary is always allowed. Entered without a call (a loop through the entry, a jump) the poll suspends as before, so loops
// are never skipped; at most MRWindowSkipCap skips in a row, then it suspends as before (termination). The window holds no poll
// other than the entry (no control transfer inside), and with the trap flag the caller keeps its flags (Core.cpp).
constexpr uint32_t MRWindowSkipCap = 64;
static bool MRGuestReadable(uint64_t Address, uint64_t Size) {
  for (uint64_t Page = Address & ~uint64_t {0xfff}; Page < Address + Size; Page += 0x1000) {
    MEMORY_BASIC_INFORMATION Info {};
    if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Page), MemoryBasicInformation, &Info, sizeof(Info), nullptr) ||
        Info.State != MEM_COMMIT || (Info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) || !(Info.Protect & 0xFE)) {
      return false;
    }
  }
  return true;
}
static bool MREnteredByCall(uint64_t Rip, uint64_t Esp) {
  if (!MRGuestReadable(Esp, 4)) {
    return false;
  }
  const uint32_t Ret = *reinterpret_cast<const uint32_t*>(Esp);
  if (Ret >= 6 && MRGuestReadable(Ret - 6, 6)) {
    const auto* P = reinterpret_cast<const uint8_t*>(static_cast<uint64_t>(Ret) - 6);
    if (P[1] == 0xE8 && static_cast<uint32_t>(Ret + *reinterpret_cast<const uint32_t*>(P + 2)) == static_cast<uint32_t>(Rip)) {
      return true; // call rel32
    }
    if (P[0] == 0xFF && P[1] == 0x15) { // call dword ptr [abs32] (an import call, bound by REGION4-0001 or not)
      const uint32_t Slot = *reinterpret_cast<const uint32_t*>(P + 2);
      return MRGuestReadable(Slot, 4) && *reinterpret_cast<const uint32_t*>(static_cast<uint64_t>(Slot)) == static_cast<uint32_t>(Rip);
    }
  }
  return false;
}
static bool MRSkipWindowPoll(TLS TLS, CONTEXT* Context, bool WindowEntry) {
  auto* Thread = TLS.ThreadState();
  auto* Data = GetFrontendThreadData(Thread);
  if (!Data) {
    return false;
  }
  if (!WindowEntry) {
    Data->MRWindowSkips = 0; // a real suspension follows
    return false;
  }
  const auto& Config = SignalDelegator->GetConfig();
  const uint64_t Rip = CTX->RestoreRIPFromHostPC(Thread, Context->Pc) & 0xffffffffULL;
  const uint64_t Esp =
    (Context->X[Config.SRAGPRMapping[FEXCore::X86State::REG_RSP]] + CTX->MRStackFoldDelta(Thread, Context->Pc)) & 0xffffffffULL;
  if (Data->MRWindowSkips < MRWindowSkipCap && MREnteredByCall(Rip, Esp)) {
    ++Data->MRWindowSkips;
    FEXCore::Utils::MacRunnerExitScanSkips.fetch_add(1, std::memory_order_relaxed);
    return true;
  }
  Data->MRWindowSkips = 0;
  FEXCore::Utils::MacRunnerExitScanNoSkip.fetch_add(1, std::memory_order_relaxed);
  return false;
}

void MRShadowNote(unsigned Kind); // REGION4-0005, below
bool HandleSuspendInterrupt(TLS TLS, CONTEXT* Context, uint64_t FaultAddress) {
  const uint64_t FaultPage = reinterpret_cast<uint64_t>(&TLS.ThreadState()->InterruptFaultPage);
  const bool PublishedContinuation = FaultAddress == FaultPage + FEXCore::Utils::PublishedSuspendFaultOffset;
  const bool WindowEntry = FaultAddress == FaultPage + FEXCore::Utils::WindowSuspendFaultOffset; // REGION4 EXIT_SCAN v2
  const bool Shadow = FEXCore::Utils::MacRunnerPollOnShadow();                                    // REGION4-0005
  const bool RegisterRIP = Shadow && FaultAddress == FaultPage + FEXCore::Utils::RegisterRIPSuspendFaultOffset;
  if (FaultAddress != FaultPage && !PublishedContinuation && !WindowEntry && !RegisterRIP) {
    return false;
  }
  if (MRSkipWindowPoll(TLS, Context, WindowEntry)) {
    Context->Pc += 4; // the poll is one store (JIT EmitEntryPoint); the page stays read-only for the next poll
    return true;
  }

  // ★ REGION4-0006: stepping through a flags window (HandleShadowSuspend). The exit of a single-instruction block polls here; the state
  // is exact (its flags are live at the exit). Not the last step: run the next instruction alone, the page stays protected and the
  // thread keeps IN_JIT. The last step falls through to the ordinary stop. A poll that is not a single-instruction block's exit (an
  // exception left the window) ends the stepping and stops as usual.
  auto* MRData = Shadow ? GetFrontendThreadData(TLS.ThreadState()) : nullptr;
  if (MRData && MRData->MRStepsLeft) {
    if (CTX->IsAddressInCodeBuffer(TLS.ThreadState(), Context->Pc) && (CTX->RestoreRIPFromHostPC(TLS.ThreadState(), Context->Pc), CTX->IsCurrentBlockSingleInst(TLS.ThreadState())) &&
        --MRData->MRStepsLeft) {
      uint64_t StepRIP = 0;
      if (RegisterRIP) {
        uint32_t Insn;
        memcpy(&Insn, reinterpret_cast<const void*>(Context->Pc), sizeof(Insn));
        StepRIP = (Insn & 31) == 31 ? 0 : (Context->X[Insn & 31] & 0xffffffffULL);
      }
      ReconstructThreadState(TLS, Context, PublishedContinuation);
      if (RegisterRIP) {
        TLS.ThreadState()->CurrentFrame->State.rip = StepRIP;
      }
      TLS.ThreadState()->CurrentFrame->State.callret_sp = Context->X25;
      const auto& Config = SignalDelegator->GetConfig();
      Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
      Context->X1 = 1; // ENTRY_FILL_SRA_SINGLE_INST_REG: one instruction
      MRShadowNote(9);
      return true;
    }
    MRData->MRStepsLeft = 0;
  }

  void* TmpAddress = reinterpret_cast<void*>(FaultPage);
  SIZE_T TmpSize = FEXCore::Utils::FEX_PAGE_SIZE;
  ULONG TmpProt;
  NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, PAGE_READWRITE, &TmpProt);

  // REGION4-0005: the poll of an indirect jump out of a unit stored the target (`str xT, [x28, #page + 48]`): after the jump.
  uint64_t TargetRIP = 0;
  if (RegisterRIP) {
    uint32_t Insn;
    memcpy(&Insn, reinterpret_cast<const void*>(Context->Pc), sizeof(Insn));
    TargetRIP = (Insn & 31) == 31 ? 0 : (Context->X[Insn & 31] & 0xffffffffULL);
  }

  // Entry and R4 loop-target faults use the precise host-PC mapping. A marked
  // legacy continuation was already published before its faulting store.
  ReconstructThreadState(TLS, Context, PublishedContinuation);
  if (RegisterRIP) {
    TLS.ThreadState()->CurrentFrame->State.rip = TargetRIP;
    MRShadowNote(3);
  }
  if (Shadow) {
    // Every poll ends the pending suspension's arm; the dispatcher reloads x25 from the frame.
    FEX::Windows::CallRetStack::ShadowTaken(TLS.ThreadState());
    FEX::Windows::CallRetStack::ShadowDisarm(TLS.ThreadState(), FEX::Windows::CallRetStack::ShadowOff);
    TLS.ThreadState()->CurrentFrame->State.callret_sp = Context->X25;
    if (auto* Data = GetFrontendThreadData(TLS.ThreadState())) {
      Data->MRShadowWindowSkips = 0;
    }
  }

  // Yield to the suspender
  UnlockJITContext(TLS);
  LockJITContext(TLS);

  // Adjust context to return to the dispatcher, reloading SRA from thread state
  const auto& Config = SignalDelegator->GetConfig();
  Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
  Context->X1 = 0; // Set ENTRY_FILL_SRA_SINGLE_INST_REG
  return true;
}

// ★ REGION4-0005 13.11.2026 MACRUNNER_FEX32_POLL_ON_SHADOW (FEXCore/Utils/MacRunnerSuspend.h). A fault on this thread's call-return
// stack while a suspension has armed it (CallRetStack::ShadowArm, BTCpuSuspendLocalThread):
//   translated call    `stp xA, xB, [x25, #-16]!` -- the guest push of the return address is done, the transfer is not: the context
//                      is the one before the call (RIP = the call instruction, ESP + its push). Not when EXIT_SCAN may have let the
//                      caller leave undefined flags (the callee, or a thunk it goes through, is a flags window): no stop there, the
//                      window has no poll and the next poll stops.
//   translated return  `ldp x0, x1, [x25], #16; sub x0, x0, xT` -- the pop is done: the context is the one after the return
//                      (RIP = xT), the call-return entry is popped as the ldp would have.
// Anything else (dispatcher code, unexpected forms) does not stop: the window reopens as Canceled and the suspender re-arms it. With no
// suspender waiting (PAUSED clear) the arm is stale and the window just reopens. The faulting access is retried in both cases.
void MRShadowNote(unsigned Kind) {
  const uint64_t N = FEXCore::Utils::MacRunnerShadowStats[Kind].fetch_add(1, std::memory_order_relaxed) + 1;
  if (N & (N - 1)) {
    return;
  }
  const auto& S = FEXCore::Utils::MacRunnerShadowStats;
  char Line[320];
  const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1,
                                    "macrunner-fex32-shadow: poll_on_shadow=1 arms={} stop_call={} stop_ret={} stop_jreg={} no_stop={} stale={} "
                                    "flags_window={} flags_window_cap={} performed={} steps={} stepped_windows={}\n",
                                    S[0].load(std::memory_order_relaxed), S[1].load(std::memory_order_relaxed), S[2].load(std::memory_order_relaxed),
                                    S[3].load(std::memory_order_relaxed), S[4].load(std::memory_order_relaxed), S[5].load(std::memory_order_relaxed),
                                    S[6].load(std::memory_order_relaxed), S[7].load(std::memory_order_relaxed), S[8].load(std::memory_order_relaxed),
                                    S[9].load(std::memory_order_relaxed), S[10].load(std::memory_order_relaxed));
  Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
  FEX::Windows::Logging::Raw(Line);
}
// The guest call instruction at Rip: the bytes it pushes (0 = not a call); Target = the callee of a prefix-free `E8 rel32` or
// `FF 15 [abs32]` (0 otherwise or unreadable).
static unsigned MRGuestCallPush(uint64_t Rip, uint32_t& Target) {
  Target = 0;
  if (!MRGuestReadable(Rip, 16)) {
    return 0;
  }
  const auto* P = reinterpret_cast<const uint8_t*>(Rip);
  unsigned Push = 4, Prefixes = 0;
  for (; Prefixes < 4; ++Prefixes) {
    const uint8_t B = P[Prefixes];
    if (B == 0x66) {
      Push = 2;
    } else if (!(B == 0x26 || B == 0x2E || B == 0x36 || B == 0x3E || B == 0x64 || B == 0x65 || B == 0xF2 || B == 0xF3 || B == 0x67)) {
      break;
    }
  }
  const uint8_t* Op = P + Prefixes;
  if (Op[0] == 0xE8) {
    if (!Prefixes) {
      int32_t Rel;
      memcpy(&Rel, Op + 1, sizeof(Rel));
      Target = static_cast<uint32_t>(Rip + 5 + Rel);
    }
    return Push;
  }
  if (Op[0] == 0xFF && ((Op[1] >> 3) & 7) == 2) {
    if (!Prefixes && Op[1] == 0x15) {
      uint32_t Slot;
      memcpy(&Slot, Op + 2, sizeof(Slot));
      if (MRGuestReadable(Slot, 4)) {
        Target = *reinterpret_cast<const uint32_t*>(static_cast<uint64_t>(Slot));
      }
    }
    return Push;
  }
  return 0;
}
// Conservative: true when the callee, or a thunk `FF 25 [abs32]` on the way (THUNK_SKIP follows at most two), starts a flags window.
static bool MRCallMayLeaveFlags(uint32_t Target) {
  const auto Readable = [](uint64_t Address, uint64_t Size) { return MRGuestReadable(Address, Size); };
  for (unsigned Hop = 0; Hop < 3 && Target; ++Hop) {
    if (FEXCore::Utils::MRScanKillsAllFlags(Target, Readable)) {
      return true;
    }
    if (!MRGuestReadable(Target, 6)) {
      break;
    }
    const auto* P = reinterpret_cast<const uint8_t*>(static_cast<uint64_t>(Target));
    if (P[0] != 0xFF || P[1] != 0x25) {
      break;
    }
    uint32_t Slot;
    memcpy(&Slot, P + 2, sizeof(Slot));
    if (!MRGuestReadable(Slot, 4)) {
      break;
    }
    Target = *reinterpret_cast<const uint32_t*>(static_cast<uint64_t>(Slot));
  }
  return false;
}
// REGION4-0006: guest instructions from the call's target to the first boundary where every status flag has been written since the call:
// thunk hops `FF 25 [abs32]` (at most two) + the window's instructions (MRScanOne). 0 = none found (no stepping).
static unsigned MRStepsToFlagBoundary(uint32_t Target) {
  unsigned Hops = 0;
  for (unsigned Hop = 0; Hop < 3 && Target; ++Hop) {
    unsigned Need = FEXCore::Utils::MRAllFlags;
    uint64_t Address = Target;
    for (unsigned Count = 0; Count < 24; ++Count) {
      if (Address + 16 > 0x100000000ULL || !MRGuestReadable(Address, 16)) {
        break;
      }
      const auto Step = FEXCore::Utils::MRScanOne(reinterpret_cast<const uint8_t*>(Address));
      if (!Step.Length) {
        break;
      }
      Need &= ~Step.Kills;
      if (!Need) {
#ifdef REGION4_STEP_SHORT // diagnostic negative control only: one step short (the stop then shows the caller's undefined flags)
        return Hops + Count;
#else
        return Hops + Count + 1;
#endif
      }
      Address += Step.Length;
    }
    if (!MRGuestReadable(Target, 6)) {
      return 0;
    }
    const auto* P = reinterpret_cast<const uint8_t*>(static_cast<uint64_t>(Target));
    if (P[0] != 0xFF || P[1] != 0x25) {
      return 0;
    }
    uint32_t Slot;
    memcpy(&Slot, P + 2, sizeof(Slot));
    if (!MRGuestReadable(Slot, 4)) {
      return 0;
    }
    Target = *reinterpret_cast<const uint32_t*>(static_cast<uint64_t>(Slot));
    ++Hops;
  }
  return 0;
}
static bool MRGuestIsRet(uint64_t Rip) {
  if (!MRGuestReadable(Rip, 8)) {
    return false;
  }
  const auto* P = reinterpret_cast<const uint8_t*>(Rip);
  unsigned i = 0;
  while (i < 4 && (P[i] == 0x66 || P[i] == 0xF2 || P[i] == 0xF3 || P[i] == 0x2E || P[i] == 0x3E)) {
    ++i;
  }
  return P[i] == 0xC3 || P[i] == 0xC2;
}
bool HandleShadowSuspend(TLS TLS, CONTEXT* Context, uint64_t FaultAddress) {
  namespace CRS = FEX::Windows::CallRetStack;
  if (!FEXCore::Utils::MacRunnerPollOnShadow()) {
    return false;
  }
  auto* Thread = TLS.ThreadState();
  if (!Thread || !Thread->CallRetStackBase) {
    return false;
  }
  const auto Info = CRS::GetInfoThread(Thread);
  if (FaultAddress < Info.AllocationBase || FaultAddress >= Info.AllocationEnd) {
    return false;
  }
  if (CRS::ShadowStateOf(Thread) != CRS::ShadowArmed) {
    return CRS::ShadowStaleProtection(Thread, FaultAddress); // false: growth / imbalance, the previous path
  }
  // No suspender waiting: a stale arm, reopen. (Lock busy: stop instead below -- never wait for a holder that may be suspended.)
  if (!(TLS.ControlWord().load(std::memory_order::relaxed) & ControlBits::PAUSED) && CRS::ShadowDisarm(Thread, CRS::ShadowOff)) {
    MRShadowNote(5);
    return true;
  }
  enum { None, Call, Ret } Kind = None;
  unsigned TargetReg = 0, Push = 0;
  uint64_t Rip = 0;
  const uint64_t Pc = Context->Pc;
  if (!(Pc & 3) && !IsDispatcherAddress(Pc) && CTX->IsAddressInCodeBuffer(Thread, Pc)) {
    uint32_t W, W2;
    memcpy(&W, reinterpret_cast<const void*>(Pc), sizeof(W));
    memcpy(&W2, reinterpret_cast<const void*>(Pc + 4), sizeof(W2));
    if ((W & 0xFFFF83E0U) == (0xA9800000U | (0x7EU << 15) | (25U << 5))) { // stp xA, xB, [x25, #-16]! (imm7 = -2, Rn = 25)
      Rip = CTX->RestoreRIPFromHostPC(Thread, Pc) & 0xffffffffULL;
      uint32_t Target = 0;
      Push = MRGuestCallPush(Rip, Target);
      if (Push && FEXCore::Utils::MacRunnerExitScanMask() && MRCallMayLeaveFlags(Target)) {
        auto* Data = GetFrontendThreadData(Thread);
        // ★ REGION4-0006: step to the end of the flags window instead of stopping here: push the pair (best effort; without it only one
        // return misses later), state "after the call" (RIP = the call's x86 target, the push is done), then single-instruction blocks
        // until every flag is written (HandleSuspendInterrupt counts the steps); the thread keeps IN_JIT, the page stays protected.
        if (const unsigned Steps = Data && Push == 4 ? MRStepsToFlagBoundary(Target) : 0) {
          const uint64_t Pair[2] = {(W & 31) == 31 ? 0 : Context->X[W & 31], ((W >> 10) & 31) == 31 ? 0 : Context->X[(W >> 10) & 31]};
          const bool Pushed = CRS::ShadowEmulateStore(Thread, Context->X25 - 16, Pair, 16);
          ReconstructThreadState(TLS, Context);
          auto& State = Thread->CurrentFrame->State;
          State.rip = Target;
          if (Pushed) {
            Context->X25 -= 16;
          }
          State.callret_sp = Context->X25;
          Data->MRStepsLeft = Steps;
          Data->MRShadowWindowSkips = 0;
          const auto& Config = SignalDelegator->GetConfig();
          Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
          Context->X1 = 1; // ENTRY_FILL_SRA_SINGLE_INST_REG: one instruction
          MRShadowNote(10);
          return true;
        }
        if (Data && Data->MRShadowWindowSkips < FEXCore::Utils::MRShadowWindowCap) {
          // Push the pair here and step over the stp: the window stays armed, so the callee's own return (after its flags window)
          // stops. Lock busy / slot not committed: reopen as Canceled instead (the suspender re-arms).
          const uint64_t Pair[2] = {(W & 31) == 31 ? 0 : Context->X[W & 31], ((W >> 10) & 31) == 31 ? 0 : Context->X[(W >> 10) & 31]};
          if (Data->MRShadowWindowSkips < FEXCore::Utils::MRShadowEmulateCap && CRS::ShadowEmulateStore(Thread, Context->X25 - 16, Pair, 16)) {
            Context->X25 -= 16;
            Context->Pc += 4;
            ++Data->MRShadowWindowSkips;
            MRShadowNote(8);
            return true;
          }
          if (CRS::ShadowDisarm(Thread, CRS::ShadowCanceled)) {
            ++Data->MRShadowWindowSkips;
            MRShadowNote(6);
            return true;
          }
        }
        MRShadowNote(7); // a cycle of flags-window calls only (or the lock busy): stop here (termination; flags may be undefined)
      }
      Kind = Push ? Call : None;
    } else if ((W & 0xFFFF83FFU) == (0xA8C00000U | (2U << 15) | (25U << 5)) && (W2 & 0xFFE0FFFFU) == 0xCB000000U) { // imm7 = 2, Rn = 25, Rt = x0
      // ldp x0, xB, [x25], #16 ; sub x0, x0, xT
      Rip = CTX->RestoreRIPFromHostPC(Thread, Pc) & 0xffffffffULL;
      TargetReg = (W2 >> 16) & 31;
      Kind = TargetReg != 31 && MRGuestIsRet(Rip) ? Ret : None;
    }
  }
  if (Kind == None && IsDispatcherAddress(Pc) && !(Pc & 3)) {
    uint32_t W;
    memcpy(&W, reinterpret_cast<const void*>(Pc), sizeof(W));
    if ((W & 0xFFFFFFE0U) == (0xF9000000U | (1U << 10) | (25U << 5))) { // str xT, [x25, #8]
      const uint64_t Value = (W & 31) == 31 ? 0 : Context->X[W & 31];
      if (CRS::ShadowEmulateStore(Thread, Context->X25 + 8, &Value, 8)) {
        Context->Pc += 4;
        MRShadowNote(8);
        return true;
      }
    }
  }
  if (Kind == None) {
    static std::atomic<uint32_t> Shown {0};
    if (Shown.fetch_add(1, std::memory_order_relaxed) < 8) { // which access could not stop (the first 8 per process)
      uint32_t W = 0;
      if (!(Pc & 3) && (IsDispatcherAddress(Pc) || CTX->IsAddressInCodeBuffer(Thread, Pc))) {
        memcpy(&W, reinterpret_cast<const void*>(Pc), sizeof(W));
      }
      char Line[192];
      const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-shadow-nostop: pc={:x} insn={:08x} dispatcher={} rip={:x} fault={:x}\n", Pc,
                                        W, IsDispatcherAddress(Pc) ? 1 : 0, Rip, FaultAddress);
      Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
    if (CRS::ShadowDisarm(Thread, CRS::ShadowCanceled)) {
      MRShadowNote(4);
    }
    return true; // retried (lock busy: faults again until the holder is done)
  }

  CRS::ShadowTaken(Thread);
  CRS::ShadowDisarm(Thread, CRS::ShadowOff); // busy: stays armed, the first fault after the resumption reopens it (no suspender then)
  if (auto* Data = GetFrontendThreadData(Thread)) {
    Data->MRShadowWindowSkips = 0;
  }
  void* TmpAddress = &Thread->InterruptFaultPage;
  SIZE_T TmpSize = FEXCore::Utils::FEX_PAGE_SIZE;
  ULONG TmpProt;
  NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, PAGE_READWRITE, &TmpProt);

  const uint64_t RetTarget = Kind == Ret ? (Context->X[TargetReg] & 0xffffffffULL) : 0;
  ReconstructThreadState(TLS, Context); // RIP = the call / the return instruction (host-PC mapping)
  auto& State = Thread->CurrentFrame->State;
  if (Kind == Call) {
    State.rip = Rip;
    State.gregs[FEXCore::X86State::REG_RSP] = static_cast<uint32_t>(State.gregs[FEXCore::X86State::REG_RSP] + Push);
    MRShadowNote(1);
  } else {
    State.rip = RetTarget;
    Context->X25 += 0x10;
    MRShadowNote(2);
  }
  State.callret_sp = Context->X25;

  // Yield to the suspender, then resume through the dispatcher (reloading SRA and x25 from the frame).
  UnlockJITContext(TLS);
  LockJITContext(TLS);
  const auto& Config = SignalDelegator->GetConfig();
  Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
  Context->X1 = 0; // ENTRY_FILL_SRA_SINGLE_INST_REG
  return true;
}
} // namespace Context

// Calls a 2-argument function `Func` setting the parent unwind frame information to the given SP and PC
__attribute__((naked)) extern "C" uint64_t SEHFrameTrampoline2Args(void* Arg0, void* Arg1, void* Func, uint64_t Sp, uint64_t Pc) {
  asm(".seh_proc SEHFrameTrampoline2Args;"
      "stp x3, x4, [sp, #-0x10]!;"
      ".seh_pushframe;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "blr x2;"
      "ldp x29, x30, [sp], 0x20;"
      "ret;"
      ".seh_endproc;");
}

// ★ MacRunner NATIVE32 (MRReadGuestData below): exported by ntdll (Defs/ntdll.def), not declared by the bundled winternl.h.
extern "C" NTSTATUS WINAPI NtReadVirtualMemory(HANDLE, const void*, void*, SIZE_T, SIZE_T*);

class WowSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  WowSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }

  static uint64_t HandleSyscallImpl(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) {
    if (LazyMXCSROn()) LazyMXCSRFoldLive(Frame->State);
    const uint64_t ReturnRIP = *(uint32_t*)(Frame->State.gregs[FEXCore::X86State::REG_RSP]); // Return address from the stack
    uint64_t ReturnRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP] + 4;                 // Stack pointer after popping return address
    uint64_t ReturnRAX = 0;

    if (Frame->State.rip == (uint64_t)BridgeInstrs::UnixCall) {
      struct StackLayout {
        unixlib_handle_t Handle;
        UINT32 ID;
        ULONG32 Args;
      }* StackArgs = reinterpret_cast<StackLayout*>(ReturnRSP);

      ReturnRSP += sizeof(StackLayout);

      const auto TLS = GetTLS();
      Context::UnlockJITContext(TLS);
      ReturnRAX = static_cast<uint64_t>(WineUnixCall(StackArgs->Handle, StackArgs->ID, ULongToPtr(StackArgs->Args)));
      Context::LockJITContext(TLS);
    } else if (Frame->State.rip == (uint64_t)BridgeInstrs::Syscall) {
      const uint64_t EntryRAX = Frame->State.gregs[FEXCore::X86State::REG_RAX];

      const auto TLS = GetTLS();
      Context::UnlockJITContext(TLS);
      Wow64ProcessPendingCrossProcessItems();
      ReturnRAX = static_cast<uint64_t>(Wow64SystemServiceEx(static_cast<UINT>(EntryRAX), reinterpret_cast<UINT*>(ReturnRSP + 4)));
      Context::LockJITContext(TLS);
    }
    // If a new context has been set, use it directly and don't return to the syscall caller
    if (Frame->State.rip == (uint64_t)BridgeInstrs::Syscall || Frame->State.rip == (uint64_t)BridgeInstrs::UnixCall) {
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
      Frame->State.gregs[FEXCore::X86State::REG_RSP] = ReturnRSP;
      Frame->State.rip = ReturnRIP;
    }

    // LAZY-FLAGS seed: native code ran on this thread; the guest status comes from the shadow
    // (folded above, or replaced by a context applied during the call).
    if (LazyMXCSROn()) LazyMXCSRSeed(Frame->State);
    // NORETURNEDRESULT causes this result to be ignored since we restore all registers back from memory after a syscall anyway
    return 0;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    const auto TLS = GetTLS();
    // Stash the the context pointer on the stack, as Simulate can be called from this syscall handler which would overwrite it
    CONTEXT* EntryContext = TLS.EntryContext();
    // Call the syscall handler with unwind information pointing to Simulate as its caller
    uint64_t Ret = SEHFrameTrampoline2Args(reinterpret_cast<void*>(Frame), reinterpret_cast<void*>(Args),
                                           reinterpret_cast<void*>(&HandleSyscallImpl), EntryContext->Sp, EntryContext->Pc);
    TLS.EntryContext() = EntryContext;
    return Ret;
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    return ImageTracker->LookupExecutableFileSection(Address);
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->ReprotectRWXIntervals(Start, Length);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->InvalidateAlignedInterval(Start, Length, false);
  }

  void MarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->MarkRange(Start, Length);
  }

  void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->UnmarkRange(Start, Length);
  }

  bool QueryGuestConstantData(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint32_t Size, void* Out) override {
    return InvalidationTracker->QueryConstantData(Address, Size, Out); // REGION4 MACRUNNER_FEX32_IMPORT_BIND
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    return InvalidationTracker->QueryExecutableRange(Address);
  }

  // ★ MacRunner NATIVE32: the import slot of `call [disp32]` at translation time. NtReadVirtualMemory on the current process copies
  //   under the unix side's own fault guard (no host fault in the translator) and refuses unmapped / unreadable memory.
  bool MRNative32Supported() const override {
    return true;
  }
  bool MRGuestPagePlain(uint64_t Address) override {
    return Address < (1ULL << 32) && Context::MRGuestReadable(Address, 1);
  }
  bool MRReadGuestData(uint64_t Address, void* Out, size_t Size) override {
    constexpr uint64_t GuestLimit = 1ULL << 32;
    if (Address >= GuestLimit || Size > 32 || Size > GuestLimit - Address) {
      return false;
    }
    SIZE_T Read = 0;
    return NtReadVirtualMemory(NtCurrentProcess(), reinterpret_cast<const void*>(Address), Out, Size, &Read) == STATUS_SUCCESS &&
           Read == Size;
  }

  // ★ MacRunner NATIVE32-0005: export <Name> of the 32-bit image holding AddressInModule (the decoder's FlsGetValue hint, once per
  //   process). Every read goes through NtReadVirtualMemory and stays inside SizeOfImage; a forwarder or anything unexpected -> 0.
  uint64_t MRFindGuestExport(uint64_t AddressInModule, const char* Name) override {
    MEMORY_BASIC_INFORMATION Info {};
    if (AddressInModule >= (1ULL << 32) ||
        NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(AddressInModule), MemoryBasicInformation, &Info, sizeof(Info), nullptr) ||
        Info.State != MEM_COMMIT || Info.Type != MEM_IMAGE) {
      return 0;
    }
    const uint64_t Base = reinterpret_cast<uint64_t>(Info.AllocationBase);
    uint64_t Limit = 0x1000;
    const auto Read = [&](uint64_t Rva, void* Out, size_t Size) {
      SIZE_T Got = 0;
      return Rva + Size <= Limit && NtReadVirtualMemory(NtCurrentProcess(), reinterpret_cast<const void*>(Base + Rva), Out, Size, &Got) == STATUS_SUCCESS &&
             Got == Size;
    };
    uint16_t Magic = 0;
    uint32_t NtOff = 0, Sig = 0, SizeOfImage = 0, ExportRva = 0, ExportSize = 0, NumRva = 0;
    if (!Read(0, &Magic, 2) || Magic != 0x5A4D || !Read(0x3C, &NtOff, 4) || NtOff > 0xF00 || !Read(NtOff, &Sig, 4) || Sig != 0x4550 ||
        !Read(NtOff + 24, &Magic, 2) || Magic != 0x10B || !Read(NtOff + 24 + 56, &SizeOfImage, 4) || !Read(NtOff + 24 + 92, &NumRva, 4) || !NumRva ||
        !Read(NtOff + 24 + 96, &ExportRva, 4) || !Read(NtOff + 24 + 100, &ExportSize, 4) || !ExportRva) {
      return 0;
    }
    Limit = SizeOfImage;
    uint32_t Dir[10] {};
    if (!Read(ExportRva, Dir, sizeof(Dir))) {
      return 0;
    }
    const uint32_t NumFunctions = Dir[5], NumNames = Dir[6], Functions = Dir[7], Names = Dir[8], Ordinals = Dir[9];
    const size_t NameLen = strlen(Name);
    int64_t Lo = 0, Hi = static_cast<int64_t>(NumNames) - 1;
    while (Lo <= Hi) {   // the loader's own lookup: names are sorted
      const int64_t Mid = (Lo + Hi) / 2;
      uint32_t NameRva = 0;
      char Buf[64] {};
      if (!Read(Names + Mid * 4ULL, &NameRva, 4) || NameRva >= Limit) {
        return 0;
      }
      const size_t Avail = std::min<uint64_t>(sizeof(Buf) - 1, Limit - NameRva);
      if (!Read(NameRva, Buf, Avail)) {
        return 0;
      }
      const int Cmp = strncmp(Buf, Name, NameLen + 1);
      if (Cmp == 0) {
        uint16_t Ord = 0;
        uint32_t FuncRva = 0;
        if (!Read(Ordinals + Mid * 2ULL, &Ord, 2) || Ord >= NumFunctions || !Read(Functions + Ord * 4ULL, &FuncRva, 4) || !FuncRva ||
            FuncRva >= Limit || (FuncRva >= ExportRva && FuncRva < ExportRva + ExportSize)) {
          return 0;   // forwarder or broken
        }
        return Base + FuncRva;
      }
      if (Cmp < 0) {
        Lo = Mid + 1;
      } else {
        Hi = Mid - 1;
      }
    }
    return 0;
  }

  void PreCompile() override {
    Wow64ProcessPendingCrossProcessItems();
  }

  // ★ MacRunner (HG2, MACRUNNER_FEX_HOOK_GUARD): области компиляции и смены буфера кода (Core.cpp); при выключенном гейте Enter/Leave возвращаются сразу.
  void EnterRuntimeSection(RuntimeSection Section) override {
    FEX::Windows::HookGuard::Enter(Section == RuntimeSection::Compile ? FEX::Windows::HookGuard::Path::Compile : FEX::Windows::HookGuard::Path::ClearCodeCache);
  }
  void LeaveRuntimeSection(RuntimeSection Section) override {
    FEX::Windows::HookGuard::Leave(Section == RuntimeSection::Compile ? FEX::Windows::HookGuard::Path::Compile : FEX::Windows::HookGuard::Path::ClearCodeCache);
  }
};

// ★★★ MacRunner N2b — БЕЗУСЛОВНЫЙ ЗОНД ПО ШАГАМ BTCpuProcessInit.
// Заведён потому, что прогон встаёт МЕЖДУ `macrunner-wow64: before BTCpuProcessInit`
// нашей wow64.dll и первой строкой FEX, а «after BTCpuProcessInit» не печатается вовсе.
// Средство диагностики строкой из stderr: каналы Wine (ERR/MESSAGE) до наших журналов
// не доходят — проверено, строк `err:` нет ни в одном прогоне за историю проекта.
// Печать безусловная и без гейта: гейт сделал бы зонд лотереей.
// ★ Печать ТОЛЬКО через Logging::Raw. fprintf из PE = NtTerminateProcess + __fastfail
// (Common/CRT/IO.cpp:388 + Common/Priv.h:59). Замерено: прогон умер с exit=0 и пустым
// журналом ровно на первом таком «зонде».
#define MACRUNNER_FEX_STEP(n, what)                                              \
  do {                                                                            \
    char MacRunnerStepBuf[128];                                                    \
    const char* MacRunnerStepWhat = (what);                                        \
    int MacRunnerStepPos = 0;                                                      \
    const char Prefix[] = "macrunner-fex-init: шаг=";                              \
    for (const char* S = Prefix; *S && MacRunnerStepPos < 100; ++S)                \
      MacRunnerStepBuf[MacRunnerStepPos++] = *S;                                   \
    if ((n) >= 10) MacRunnerStepBuf[MacRunnerStepPos++] = '0' + ((n) / 10);        \
    MacRunnerStepBuf[MacRunnerStepPos++] = '0' + ((n) % 10);                       \
    MacRunnerStepBuf[MacRunnerStepPos++] = ' ';                                    \
    for (const char* S = MacRunnerStepWhat; *S && MacRunnerStepPos < 120; ++S)     \
      MacRunnerStepBuf[MacRunnerStepPos++] = *S;                                   \
    MacRunnerStepBuf[MacRunnerStepPos++] = '\n';                                   \
    MacRunnerStepBuf[MacRunnerStepPos] = '\0';                                     \
    FEX::Windows::Logging::Raw(MacRunnerStepBuf);                                  \
  } while (0)

void BTCpuProcessInit() {
  MACRUNNER_FEX_STEP(0, "вход");
  FEX::Windows::InitCRTProcess();
  MACRUNNER_FEX_STEP(1, "InitCRTProcess");
  const auto ExecutablePath = FEX::Windows::GetExecutableFilePath();
  const auto ExecutableName = FEX::Windows::BaseName(ExecutablePath);
  MACRUNNER_FEX_STEP(2, "GetExecutableFilePath");
  FEX::Config::LoadConfig(fextl::string {ExecutableName}, _environ, FEX::ReadPortabilityInformation());
  MACRUNNER_FEX_STEP(3, "LoadConfig");
  FEXCore::Config::ReloadMetaLayer();
  FEX::Windows::Logging::Init();
  MACRUNNER_FEX_STEP(4, "Logging::Init");

  FEXCore::Config::Set(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
  // KEYTRIAGE 12.11.2026 (owner's decision 12.11: reduced-precision x87 is the default for 32-bit games only; 64-bit stays exact).
  // MACRUNNER_FEX32_X87_RP decides x87 precision for THIS 32-bit process and nothing else reads it:
  //   1        x87 on host doubles (FEX option X87REDUCEDPRECISION = 1), whatever FEX_X87REDUCEDPRECISION says;
  //   0        the exact path, whatever FEX_X87REDUCEDPRECISION says (a game profile / the app's "Exact" needs one key);
  //   not set  nothing changes: FEX_X87REDUCEDPRECISION alone decides, as before this patch.
  // The engine default names this key, never FEX_X87REDUCEDPRECISION: that one is read by every translator (xtajit64 too), while the
  // safety keys that go with the default (MACRUNNER_FEX32_X87_RP_INT64 / _RP_PC24) exist only in the 32-bit translator, and x64 code
  // that uses x87 at all is long double code - the class that needs the exact path.
  if (const char* RP = getenv("MACRUNNER_FEX32_X87_RP"); RP && (RP[0] == '0' || RP[0] == '1') && !RP[1]) {
    FEXCore::Config::Set(FEXCore::Config::CONFIG_X87REDUCEDPRECISION, RP);
  }
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, ExecutablePath);
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, ExecutableName);

  FEXCore::Profiler::Init("", "");
  MACRUNNER_FEX_STEP(5, "Profiler::Init");

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<WowSyscallHandler>();
  const auto NtDll = GetModuleHandleW(L"ntdll.dll");
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");
  OvercommitTracker.emplace(IsWine);
  MACRUNNER_FEX_STEP(6, "OvercommitTracker");

  // ★★★ MacRunner N2b — ПОРЯДОК ЗДЕСЬ НЕСУЩИЙ, И ОН ИЗМЕНЁН НАМЕРЕННО.
  //   1. UnixLib::Init  — клей должен быть жив ДО того, как кто-то позовёт обработчик;
  //   2. SetupHooks     — крюки 6/7 попадают в FEXCore;
  //   3. проверка       — на дарвиновской сборке отсутствие клея ФАТАЛЬНО;
  //   4. EnableJITExec(1) для ЭТОГО потока — до первого исполняемого выделения;
  //   5. CreateNewContext/InitCore — вот здесь и создаётся диспетчер, первая запись кода.
  // Апстрим звал Init ПОСЛЕ SetupHooks и ИГНОРИРОВАЛ его bool. Для нас игнорировать
  // нельзя: без клея запись в MAP_JIT упрётся в W^X, и отказ вылезет далеко от причины.
  const bool UnixLibReady = FEX::Windows::UnixLib::Init(NtDll);
  MACRUNNER_FEX_STEP(7, UnixLibReady ? "UnixLib::Init ДА" : "UnixLib::Init НЕТ");
  FEX::Windows::Allocator::SetupHooks(NtDll);
  MACRUNNER_FEX_STEP(8, "SetupHooks");

#ifdef FEX_WINE_DARWIN
  if (!UnixLibReady || !FEXCore::Allocator::EnableJITExec) {
    // ★ BTCpuProcessInit объявлен void — вернуть STATUS_ здесь НЕЛЬЗЯ. Поэтому именованный
    // отказ в stderr (каналы wine до наших журналов не доходят) и снятие процесса.
    FEX::Windows::Logging::Raw(UnixLibReady ?
                                 "macrunner-fex-НЕТ-КЛЕЯ: WOW64 — UnixLib ДА, крюк 7 НЕТ\n" :
                                 "macrunner-fex-НЕТ-КЛЕЯ: WOW64 — UnixLib НЕТ\n");
    NtTerminateProcess(NtCurrentProcess(), STATUS_NOT_SUPPORTED);
  }
  FEXCore::Allocator::JITWriteThreadInit();
  FEX::Windows::UnixLib::InitializeHardwareTSO();
  MACRUNNER_FEX_STEP(9, "JITWriteThreadInit");
#else
  (void)UnixLibReady;
#endif

  {
    auto HostFeatures = FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine, FEXCore::HostFeatures::HostTypeEnum::Wow64);
    HostFeatures.SupportsAppleAFP = MacRunnerAppleAFPEnabled;
    {
      const char* X87Context = getenv("MACRUNNER_FEX_X87_CONTEXT");
      MRX87Context = X87Context && X87Context[0] == '1' && !X87Context[1];
      const char* X87FaultState = getenv("MACRUNNER_FEX_X87_FAULT_STATE");
      MRX87FaultState = X87FaultState && X87FaultState[0] == '1' && !X87FaultState[1];
      const char* SelfCtxFast = getenv("MACRUNNER_FEX_SELF_CTX_FAST");
      if (SelfCtxFast && SelfCtxFast[0] == '1' && !SelfCtxFast[1]) {
        // the fast path takes the TEB from NtCurrentTeb(): prove once that it is what the server reports for this thread
        const auto [TebErr, TebTLS] = GetThreadTLS(GetCurrentThread());
        MRSelfCtxFast = !TebErr && TebTLS.TEB == NtCurrentTeb();
        FEX::Windows::Logging::Raw(MRSelfCtxFast ? "[macrunner-fex-selfctx] on, teb check ok\n" :
                                                   "[macrunner-fex-selfctx] TEB MISMATCH - fast path stays off\n");
        const char* CtxDirect = getenv("MACRUNNER_FEX_CTX_DIRECT");   // DSNATIVE 08.11, see MRCtxDirect
        if (MRSelfCtxFast && CtxDirect && CtxDirect[0] == '1' && !CtxDirect[1]) {
          MRCtxDirect = true;   // per call: only with an I386 CPU area on the thread, else the syscall path
          FEX::Windows::Logging::Raw("[macrunner-fex-ctxdirect] on (current-thread context in the CPU area, no syscall)\n");
          const char* AB = getenv("MACRUNNER_FEX_CTX_DIRECT_AB");
          const int32_t N = AB ? atoi(AB) : 0;
          if (N > 0 && !(N % 2)) {
            MRCtxAB = N; MRCtxABDirect = false;   // batch 0: syscalls
            FEX::Windows::Logging::Raw("[macrunner-fex-ctxdirect-ab] measuring: arms alternate every N SetContext calls\n");
          }
        }
      }
    }
    if (FEXCore::HBX87::Stats::Enabled()) {
      FEX::Windows::Logging::Raw(HostFeatures.SupportsAtomics ?
        "[hb-x87-stats-init] advertised_lse=1\n" : "[hb-x87-stats-init] advertised_lse=0; use LL/SC\n");
    }
    MACRUNNER_FEX_STEP(10, "FetchHostFeatures");
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
    if (MacRunnerHardwareTSOMode == 2) CTX->SetHardwareTSOSupport(true);
    MACRUNNER_FEX_STEP(11, "CreateNewContext");
  }

  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  MACRUNNER_FEX_STEP(12, "перед InitCore");
  CTX->InitCore();
  MACRUNNER_FEX_STEP(13, "InitCore");
  Context::HandlerConfig.emplace(*CTX);
  InvalidationTracker.emplace(*CTX, Threads);
  ImageTracker.emplace(*CTX, false);
  FEX::Windows::Logging::InitCoverage();

  auto MainModule = reinterpret_cast<__TEB*>(NtCurrentTeb())->Peb->ImageBaseAddress;
  HandleImageMap(reinterpret_cast<uint64_t>(MainModule), true);

  auto NtDllX86 = reinterpret_cast<SYSTEM_DLL_INIT_BLOCK*>(GetProcAddress(NtDll, "LdrSystemDllInitBlock"))->ntdll_handle;
  HandleImageMap(NtDllX86);

  CPUFeatures.emplace(*CTX);

  // Allocate the syscall/unixcall trampolines in the lower 2GB of the address space
  SIZE_T Size = 4;
  void* Addr = nullptr;
  NtAllocateVirtualMemory(NtCurrentProcess(), &Addr, (1U << 31) - 1, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Addr), Size, PAGE_EXECUTE);
  *reinterpret_cast<uint32_t*>(Addr) = 0x2ecd2ecd;
  BridgeInstrs::Syscall = Addr;
  BridgeInstrs::UnixCall = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Addr) + 2);

  const auto Sym = GetProcAddress(NtDll, "__wine_unix_call_dispatcher");
  if (Sym) {
    WineUnixCall = *reinterpret_cast<decltype(WineUnixCall)*>(Sym);
  }

  FEX::Windows::SetupEnvironmentVariableValues(NtDll);
  // Read once before guest execution; never initialize configuration in an
  // exception handler. Zero retains the original protocol for a control arm.
  const char* OwnerReentry = std::getenv("MACRUNNER_FEX_CONTEXT_OWNER_REENTRY");
  Context::ScopedJITContextLock::PreserveOwnerReentry = !(OwnerReentry && OwnerReentry[0] == '0' && !OwnerReentry[1]);
  const char* OwnerDiagnostic = std::getenv("MACRUNNER_FEX_CONTEXT_OWNER_DIAGNOSTIC");
  Context::ScopedJITContextLock::DiagnoseOwnerReentry = OwnerDiagnostic && OwnerDiagnostic[0] == '1' && !OwnerDiagnostic[1];

  // wow64.dll will only initialise the cross-process queue if this is set
  GetTLS().Wow64Info().CpuFlags = WOW64_CPUFLAGS_SOFTWARE;

  FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
  FEX_CONFIG_OPT(StartupSleep, STARTUPSLEEP);
  FEX_CONFIG_OPT(StartupSleepProcName, STARTUPSLEEPPROCNAME);

  if (IsWine && ProfileStats()) {
    StatAllocHandler = fextl::make_unique<FEX::Windows::StatAlloc>(FEXCore::SHMStats::AppType::WIN_WOW64);
  }

  if (FEXCore::Utils::MacRunnerWarm32()) {
    FEXCore::Utils::MRWarmCompiled = &MRWarm::OnCompiled; // CALLRET4 MACRUNNER_FEX32_WARM
  }
  if (StartupSleep() && (StartupSleepProcName().empty() || ExecutableName == StartupSleepProcName())) {
    LogMan::Msg::IFmt("[{}][{}] Sleeping for {} seconds", GetCurrentProcessId(), ExecutableName, StartupSleep());
    std::this_thread::sleep_for(std::chrono::seconds(StartupSleep()));
  }
}

void BTCpuProcessTerm(HANDLE Handle, BOOL After, ULONG Status) {
  FEXCore::HBX87::Stats::Dump();
  MRWarm::Flush(); // CALLRET4 MACRUNNER_FEX32_WARM
}

void BTCpuThreadInit() {
  static constexpr size_t DefaultWow64CS {4};
  std::scoped_lock Lock(ThreadCreationMutex);
  FEX::Windows::InitCRTThread();
  FEX::Windows::UnixLib::HardwareTSOThreadEnter(FEXHardwareTSOEntryKind::WOW64ThreadInit);
  // ★ MacRunner N2b — режим MAP_JIT ПОТОКОВЫЙ. Каждый новый поток FEX обязан назначить
  // себе «исполнять» сам: чужой поток за него этого не сделает. Ставится сразу после
  // InitCRTThread и ДО CreateThread, где пойдут первые записи кода.
  FEXCore::Allocator::JITWriteThreadInit();
  auto* Thread = CTX->CreateThread(0, 0);

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32]();

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[DefaultWow64CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 0; // L = Long Mode = 32-bit
  GDT.D = 1; // D = Default Operand Size = 32-bit

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = DefaultWow64CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);

  const auto TLS = GetTLS();
  TLS.ThreadState() = Thread;
  TLS.ControlWord().fetch_or(ControlBits::WOW_CPU_AREA_DIRTY, std::memory_order::relaxed);

  Thread->FrontendPtr = new FrontendThreadData();

  auto ThreadTID = GetCurrentThreadId();
  Threads.emplace(ThreadTID, Thread);
  if (StatAllocHandler) {
    Thread->ThreadStats = StatAllocHandler->AllocateSlot(ThreadTID);
  }
}

NTSTATUS BTCpuSuspendLocalThread(HANDLE Thread, ULONG* Count);

void BTCpuThreadTerm(HANDLE Thread, LONG ExitCode) {
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_TERMINATE)) {
    return;
  }

  auto ThreadDup = FEX::Windows::DupHandle(
    Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);

  THREAD_BASIC_INFORMATION Info;
  if (auto Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return;
  }

  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  bool Self = ThreadTID == GetCurrentThreadId();
  if (!Self) {
    // Wine 11.0 has no RtlWow64SuspendThread export. Use our existing guest
    // suspend protocol so the context is materialized and JIT locks released.
    if (BTCpuSuspendLocalThread(*ThreadDup, nullptr)) {
      return;
    }
    // Native suspend is asynchronous: synchronize before destroying target state.
    CONTEXT SuspendContext {.ContextFlags = CONTEXT_CONTROL};
    if (NtGetContextThread(*ThreadDup, &SuspendContext)) {
      return;
    }
  }

  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return;
  }

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    auto it = Threads.find(ThreadTID);
    if (it == Threads.end()) {
      // Thread already terminated
      return;
    }

    Threads.erase(it);
    if (StatAllocHandler) {
      StatAllocHandler->DeallocateSlot(TLS.ThreadState()->ThreadStats);
    }
  }
  auto ThreadState = TLS.ThreadState();

  delete GetFrontendThreadData(ThreadState);

  // GDT and LDT are mirrored, only free one.
  delete[] ThreadState->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT];

  FEX::Windows::CallRetStack::DestroyThread(ThreadState);
  CTX->DestroyThread(ThreadState);
  if (Self) {
    FEX::Windows::DeinitCRTThread();
  }
}

void* BTCpuGetBopCode() {
  return BridgeInstrs::Syscall;
}

void* __wine_get_unix_opcode() {
  return BridgeInstrs::UnixCall;
}

NTSTATUS BTCpuGetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
  if (MRIsSelf(Thread)) { // see MRSelfCtxFast
    const auto TLS = GetTLS();
    Context::ScopedJITContextLock Lk {TLS, true};
    if (NTSTATUS Err = Context::FlushThreadStateContext(Thread); Err) {
      return Err;
    }
    return MRWowGet(Thread, true, Context); // MRCtxDirect: from the CPU area, no syscall
  }

  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_GET_CONTEXT)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return Err;
  }

  Context::ScopedJITContextLock Lk {TLS, true};
  if (Err = Context::FlushThreadStateContext(*ThreadDup); Err) {
    return Err;
  }

  return RtlWow64GetThreadContext(*ThreadDup, Context);
}

NTSTATUS BTCpuSetContext(HANDLE Thread, HANDLE Process, void* Unknown, WOW64_CONTEXT* Context) {
  const bool Self = MRIsSelf(Thread); // see MRSelfCtxFast
  if (Self) MRCtxABTickSet();          // measurement only, see MRCtxAB
  if (!Self && !FEX::Windows::ValidateHandleAccess(Thread, THREAD_SET_CONTEXT)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = Self ? FEX::Windows::ScopedHandle {} :
                          FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
  const HANDLE Th = Self ? Thread : *ThreadDup;
  auto [Err, TLS] = MRThreadTLS(Th, Self);
  if (Err) {
    return Err;
  }

  // Back-up the input context incase we've been passed the CPU area (the flush below would wipe it out otherwise)
  WOW64_CONTEXT TmpContext = *Context;
  const bool FloatSaveWins = MRX87Context && (TmpContext.ContextFlags & WOW64_CONTEXT_FLOATING_POINT) == WOW64_CONTEXT_FLOATING_POINT;

  Context::ScopedJITContextLock Lk {TLS, true};
  if (Err = Context::FlushThreadStateContext(Th); Err) {
    return Err;
  }

  // Merge the input context into the CPU area then pass the full context into the JIT
  if (Err = MRWowSet(Th, Self, &TmpContext); Err) { // MRCtxDirect: into the CPU area, no syscall
    return Err;
  }

  TmpContext.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS;
  if (MRX87Context) TmpContext.ContextFlags |= WOW64_CONTEXT_FLOATING_POINT; // the import compares both x87 views

  if (Err = MRWowGet(Th, Self, &TmpContext); Err) {
    return Err;
  }
  if (FloatSaveWins) {
    // CONTEXT_FLOATING_POINT given: FloatSave is the x87 state (Windows Server 2022), ExtendedRegisters keeps XMM/MXCSR.
    MRFloatSaveToXSave(TmpContext.FloatSave, reinterpret_cast<XSAVE_FORMAT*>(TmpContext.ExtendedRegisters));
  }

  uint64_t ResetSP = 0;
  if (Thread == GetCurrentThread() && FEX::Windows::CallRetStack::TakePending(TLS.ThreadState(), ResetSP))
    TLS.CachedCallRetSp() = ResetSP;
  if (Thread == GetCurrentThread() && TLS.CachedCallRetSp()) {
    TLS.ThreadState()->CurrentFrame->State.callret_sp = TLS.CachedCallRetSp();
  }

  Context::LoadStateFromWowContext(TLS.ThreadState(), GetWowTEB(TLS.TEB), &TmpContext);
  return STATUS_SUCCESS;
}

// .seh_pushframe doesn't restore the frame pointer, so if when unwinding from RtlCaptureContext an operation is used
// that sets SP from FP, the unwound SP value will be incorrect. Wrap RtlCaptureContext so the correct FP is immediately
// restored from the stack to prevent this.
__attribute__((naked)) void BTCpuSimulate() {
  asm(".seh_proc BTCpuSimulate;"
      "sub sp, sp, #0x390;"
      ".seh_stackalloc 0x390;"
      "stp x29, x30, [sp, #-0x10]!;"
      ".seh_save_fplr_x 16;"
      ".seh_endprologue;"
      "add x0, sp, #0x10;"
      "bl RtlCaptureContext;"
      "add x0, sp, #0x10;"
      "bl BTCpuSimulateImpl;"
      "ldp x29, x30, [sp], 0x10;"
      "add sp, sp, #0x390;"
      "ret;"
      ".seh_endproc;");
}

extern "C" void BTCpuSimulateImpl(CONTEXT* entry_context) {
  FEX::Windows::UnixLib::HardwareTSOThreadEnter(FEXHardwareTSOEntryKind::WOW64Simulate);
  const auto TLS = GetTLS();
  TLS.EntryContext() = entry_context;
  TLS.CachedCallRetSp() = TLS.ThreadState()->CurrentFrame->State.callret_sp;
  FEX::Windows::CallRetStack::BeginException(TLS.ThreadState()); // frame reset already consumed by this entry

  Context::ScopedJITContextLock Lk {TLS};
  if (LazyMXCSROn()) LazyMXCSRSeed(TLS.ThreadState()->CurrentFrame->State);
  CTX->ExecuteThread(TLS.ThreadState());
}

NTSTATUS BTCpuSuspendLocalThread(HANDLE Thread, ULONG* Count) {
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_SUSPEND_RESUME)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
  THREAD_BASIC_INFORMATION Info;
  if (NTSTATUS Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return Err;
  }

  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  if (ThreadTID == GetCurrentThreadId()) {
    LogMan::Msg::DFmt("Suspending self");
    // Mark the CPU area as dirty, to force the JIT context to be restored from it on entry as it may be changed using
    // SetThreadContext (which doesn't use the BTCpu API)
    if (!(GetTLS().ControlWord().fetch_or(ControlBits::WOW_CPU_AREA_DIRTY, std::memory_order::relaxed) & ControlBits::WOW_CPU_AREA_DIRTY)) {
      if (NTSTATUS Err = Context::FlushThreadStateContext(*ThreadDup); Err) {
        return Err;
      }
    }

    return NtSuspendThread(*ThreadDup, Count);
  }

  LogMan::Msg::DFmt("Suspending thread: {:X}", ThreadTID);

  auto [Err, TLS] = GetThreadTLS(*ThreadDup);
  if (Err) {
    return Err;
  }

  std::unique_lock Lock(ThreadCreationMutex);

  // If the thread hasn't yet been initialized, suspend it without special handling as it wont yet have entered the JIT
  if (!Threads.contains(ThreadTID)) {
    LogMan::Msg::DFmt("Thread suspended: {:X}", ThreadTID);
    return NtSuspendThread(*ThreadDup, Count);
  }

  const auto* TargetState = Threads.find(ThreadTID)->second;
  uint64_t MRRounds = 0; // REGION4-0005: a long wait is reported (rounds 2^16, 2^20, 2^24) with the target's poll state
  for (;;) {
    if (FEXCore::Utils::MacRunnerPollOnShadow() && (++MRRounds == (1ULL << 16) || MRRounds == (1ULL << 20) || MRRounds == (1ULL << 24))) {
      auto* T = TLS.ThreadState();
      MEMORY_BASIC_INFORMATION Fp {}, Wn {};
      NtQueryVirtualMemory(NtCurrentProcess(), &T->InterruptFaultPage, MemoryBasicInformation, &Fp, sizeof(Fp), nullptr);
      uint64_t Lo = 0, Hi = 0;
      uint32_t St = 0, Lk = 0;
      if (T->CallRetStackBase) {
        auto* H = FEX::Windows::CallRetStack::HeaderOf(T->CallRetStackBase);
        Lo = H->Lo.load(); Hi = H->Hi.load(); St = H->ShadowState.load(); Lk = H->ShadowLock.load();
        NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<uint8_t*>(T->CallRetStackBase) + Lo, MemoryBasicInformation, &Wn, sizeof(Wn), nullptr);
      }
      char Line[256];
      const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-shadow-wait: rounds={} control={:x} fault_page_prot={:x} shadow_state={} shadow_lock={} window={:x}-{:x} window_prot={:x}\n",
                                        MRRounds, TLS.ControlWord().load(), Fp.Protect, St, Lk, Lo, Hi, Wn.Protect);
      Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
    // Another suspender may have completed while the registry lock was released.
    // Reassert PAUSED before inspecting IN_JIT and rearm the fault page if needed.
    const uint32_t Before = TLS.ControlWord().fetch_or(ControlBits::PAUSED, std::memory_order::relaxed);
    if (!(Before & ControlBits::IN_JIT)) {
      break;
    }
    if (!(Before & ControlBits::PAUSED)) {
      LogMan::Msg::DFmt("Thread {:X} is in JIT, polling for interrupt", ThreadTID);
      if (FEXCore::Utils::MacRunnerPollOnShadow()) {
        FEX::Windows::CallRetStack::ShadowArm(TLS.ThreadState(), true); // REGION4-0005: a new episode; arms the call-return stack
      }

      ULONG TmpProt = 0;
      void* TmpAddress = &TLS.ThreadState()->InterruptFaultPage;
      SIZE_T TmpSize = sizeof(TLS.ThreadState()->InterruptFaultPage);
      const NTSTATUS ProtectStatus = NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, PAGE_READONLY, &TmpProt);
      if (ProtectStatus) {
        TLS.ControlWord().fetch_and(~ControlBits::PAUSED, std::memory_order::relaxed);
        return ProtectStatus;
      }
    }
    if (FEXCore::Utils::MacRunnerPollOnShadow() && (Before & ControlBits::PAUSED)) {
      // REGION4-0005: later rounds re-arm a window the owner reopened without stopping (or the first round could not arm).
      FEX::Windows::CallRetStack::ShadowArm(TLS.ThreadState(), false);
    }

    // A guest RWX fault needs this mutex before it can reach a safe suspend
    // checkpoint. Never wait for that checkpoint while preventing its handler
    // from running. No TLS or thread-state memory is accessed outside the lock.
    Lock.unlock();
    // The Windows CRT's SwitchToThread shim is not implemented. Use the native
    // ntdll scheduler entry, which is already part of the imported NT API.
    NtYieldExecution();
    Lock.lock();
    const auto Target = Threads.find(ThreadTID);
    if (Target == Threads.end() || Target->second != TargetState) {
      return STATUS_THREAD_IS_TERMINATING;
    }
  }

  // The JIT has now been interrupted and the context stored in the thread's CPU area is up-to-date
  if (Err = NtSuspendThread(*ThreadDup, Count); Err) {
    TLS.ControlWord().fetch_and(~ControlBits::PAUSED, std::memory_order::relaxed);
    return Err;
  }

  CONTEXT TmpContext {
    .ContextFlags = CONTEXT_INTEGER,
  };

  // NtSuspendThread may return before the thread is actually suspended, so a sync operation like NtGetContextThread
  // needs to be called to ensure it is before we unset CONTROL_PAUSED
  std::ignore = NtGetContextThread(*ThreadDup, &TmpContext);

  // Mark the CPU area as dirty, to force the JIT context to be restored from it on entry as it may be changed using
  // SetThreadContext (which doesn't use the BTCpu API)
  if (!(TLS.ControlWord().fetch_or(ControlBits::WOW_CPU_AREA_DIRTY, std::memory_order::relaxed) & ControlBits::WOW_CPU_AREA_DIRTY)) {
    if (Err = Context::FlushThreadStateContext(*ThreadDup); Err) {
      return Err;
    }
  }

  LogMan::Msg::DFmt("Thread suspended: {:X}", ThreadTID);

  // Now the thread is suspended on the host, unset CONTROL_PAUSED so that NtResumeThread will
  // continue execution in the JIT
  TLS.ControlWord().fetch_and(~ControlBits::PAUSED, std::memory_order::relaxed);

  return Err;
}

// Returns true if exception dispatch should be halted and the execution context restored to Ptrs->Context
bool BTCpuResetToConsistentStateImpl(EXCEPTION_POINTERS* Ptrs) {
  auto* Context = Ptrs->ContextRecord;
  auto* Exception = Ptrs->ExceptionRecord;
  auto TLS = GetTLS();
  auto Thread = TLS.ThreadState();
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedSignalTime);

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (Context::HandleShadowSuspend(TLS, Context, FaultAddress)) { // REGION4-0005: before growth / imbalance of the same stack
      return true;
    }

    if (FEX::Windows::CallRetStack::HandleAccessViolation(Thread, FaultAddress, Context->X25, *CTX)) {
      return true;
    }

    if (OvercommitTracker && OvercommitTracker->HandleAccessViolation(FaultAddress)) {
      return true;
    }

    if (Context::HandleSuspendInterrupt(TLS, Context, FaultAddress)) {
      LogMan::Msg::DFmt("Resumed from suspend");
      return true;
    }

    if (FEX::Windows::JITGuardPage::HandleJITGuardPage(Thread, reinterpret_cast<void*>(FaultAddress), Context->X,
                                                       reinterpret_cast<__uint128_t*>(Context->V), &Context->Pc)) {
      return true;
    }

    if (Thread) {
      std::scoped_lock Lock(ThreadCreationMutex);
      FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
      uint64_t PriorResetSP = 0;
      if (FEX::Windows::CallRetStack::TakePending(Thread, PriorResetSP))
        TLS.CachedCallRetSp() = PriorResetSP; // preserve earlier frame reset without overwriting live X25
      if (InvalidationTracker->HandleRWXAccessViolation(Thread, Context->Pc, FaultAddress)) {
        uint64_t ResetSP = 0;
        if (FEX::Windows::CallRetStack::TakePending(Thread, ResetSP)) {
          TLS.CachedCallRetSp() = ResetSP;
          if (CTX->IsAddressInCodeBuffer(Thread, Context->Pc)) Context->X25 = ResetSP;
        }
        if (CTX->IsAddressInCodeBuffer(Thread, Context->Pc) && !CTX->IsCurrentBlockSingleInst(Thread) &&
            CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
          Context::ReconstructThreadState(TLS, Context);
          LogMan::Msg::DFmt("Handled inline self-modifying code: pc: {:X} rip: {:X} fault: {:X}", Context->Pc,
                            Thread->CurrentFrame->State.rip, FaultAddress);

          // Adjust context to return to the dispatcher, reloading SRA from thread state
          const auto& Config = SignalDelegator->GetConfig();
          Context->Pc = Config.AbsoluteLoopTopAddressFillSRA;
          Context->X1 = 1; // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
        } else {
          LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", Context->Pc, FaultAddress);
        }
        return true;
      }
    }
  }

  if (!Thread || !IsAddressInJit(Context->Pc)) {
    return false;
  }

  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Context::HandleUnalignedAccess(TLS, Context)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", Context->Pc);
    return true;
  }

  LogMan::Msg::DFmt("Reconstructing context");

  WOW64_CONTEXT WowContext = Context::ReconstructWowContext(TLS, Context);
  LogMan::Msg::DFmt("pc: {:X} eip: {:X}", Context->Pc, WowContext.Eip);

  // ★ CALLRET4 (12.11.2026): a fault on a fused pair of pushes / pops through the guest ESP (x8). The context above is the state
  // before the pair. x86 executes the two instructions one after the other:
  //   pushes (stp: Rt2 = first push, upper word; Rt = second, lower word)
  //     - both words in the page that faults: the first push faults -- same state, but the address is the first push's slot;
  //     - a page boundary between the words and the upper page writable: the first push is done (slot written, Esp - 4) and the
  //       second faults at the reported address, Eip = the second push (its RIP entry starts right after the pair);
  //   pops (ldp: Rt = first pop, lower word; Rt2 = second)
  //     - the fault is in the upper word across a page boundary: the first pop is done (register loaded, Esp + 4), Eip = second.
  // Anything else stays as reconstructed (a consistent, restartable state).
  if ((Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || Exception->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION ||
       Exception->ExceptionCode == EXCEPTION_STACK_OVERFLOW) &&
      Exception->NumberParameters >= 2 && !(Context->Pc & 3)) {
    uint32_t W;
    memcpy(&W, reinterpret_cast<const void*>(Context->Pc), sizeof(W));
    const unsigned Mode = (W >> 23) & 3; // 1 post-index, 2 signed offset, 3 pre-index
    const bool Load = W & 0x00400000U;
    const int32_t Imm = (static_cast<int32_t>((W >> 15) & 0x7F) - ((W & 0x00200000U) ? 0x80 : 0)) * 4;
    const bool StackPair = (W & 0xBE000000U) == 0x28000000U && ((W >> 5) & 31) == 8 &&
                           (Load ? (Mode == 1 || (Mode == 2 && Imm < 0)) : (Mode == 3 || (Mode == 2 && Imm < 0)));
    if (StackPair) {
      const uint64_t Far = static_cast<uint64_t>(Exception->ExceptionInformation[1]);
      const uint64_t Addr = (Context->X[8] + (Mode == 1 ? 0 : static_cast<int64_t>(Imm))) & 0xFFFF'FFFFULL; // the lower word
      const bool Boundary = ((Addr + 4) & 0xFFF) == 0;
      const unsigned Rt = W & 31, Rt2 = (W >> 10) & 31;
      // Eip of the second instruction of the pair: its own RIP entry is gone with the fusion, so the first one (a push / pop of a
      // register, immediate, segment or r/m32 at the reconstructed Eip) is measured. 0 = not recognised: no change below.
      uint32_t SecondEip = WowContext.Eip;
      {
        uint8_t B[12];
        memcpy(B, reinterpret_cast<const void*>(static_cast<uintptr_t>(WowContext.Eip)), sizeof(B));
        unsigned n = 0;
        bool Op16 = false;
        while (n < 3 && (B[n] == 0x66 || B[n] == 0x26 || B[n] == 0x2E || B[n] == 0x36 || B[n] == 0x3E || B[n] == 0x64 || B[n] == 0x65)) {
          Op16 |= B[n] == 0x66;
          ++n;
        }
        const uint8_t Op = B[n];
        unsigned Len = 0;
        if (!Load && ((Op >= 0x50 && Op <= 0x57) || Op == 0x06 || Op == 0x0E || Op == 0x16 || Op == 0x1E)) {
          Len = n + 1;
        } else if (Load && ((Op >= 0x58 && Op <= 0x5F) || Op == 0x07 || Op == 0x17 || Op == 0x1F)) {
          Len = n + 1;
        } else if (!Load && Op == 0x6A) {
          Len = n + 2;
        } else if (!Load && Op == 0x68) {
          Len = n + (Op16 ? 3 : 5);
        } else if (Op == 0x0F && (B[n + 1] == (Load ? 0xA1 : 0xA0) || B[n + 1] == (Load ? 0xA9 : 0xA8))) {
          Len = n + 2;
        } else if ((!Load && Op == 0xFF && ((B[n + 1] >> 3) & 7) == 6) || (Load && Op == 0x8F && ((B[n + 1] >> 3) & 7) == 0)) {
          const uint8_t M = B[n + 1];
          const unsigned Mod = M >> 6, Rm = M & 7;
          Len = n + 2;
          if (Mod != 3) {
            if (Rm == 4) {
              ++Len;
              if (Mod == 0 && (B[n + 2] & 7) == 5) {
                Len += 4;
              }
            }
            Len += Mod == 1 ? 1 : Mod == 2 ? 4 : (Mod == 0 && Rm == 5) ? 4 : 0;
          }
        }
        SecondEip += Len;
      }
      if (!Load) {
        if (!Boundary) {
          if (Far < Addr + 4) {
            Exception->ExceptionInformation[1] = Addr + 4; // the first push's slot
          }
        } else if (Far < Addr + 4 && SecondEip != WowContext.Eip) {
          MEMORY_BASIC_INFORMATION Info;
          if (!NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Addr + 4), MemoryBasicInformation, &Info, sizeof(Info), nullptr) &&
              Info.State == MEM_COMMIT && (Info.Protect == PAGE_READWRITE || Info.Protect == PAGE_EXECUTE_READWRITE)) {
            const uint32_t First = Rt2 == 31 ? 0 : static_cast<uint32_t>(Context->X[Rt2]);
            memcpy(reinterpret_cast<void*>(Addr + 4), &First, sizeof(First));
            WowContext.Esp = static_cast<uint32_t>(Addr + 4);
            WowContext.Eip = SecondEip;
          }
        }
      } else if (Boundary && Far >= Addr + 4 && Rt != 31 && Rt != 8 && SecondEip != WowContext.Eip) {
        // the first pop's destination must be a guest register (otherwise the value would be lost: keep the state before the pair)
        const auto& Config = SignalDelegator->GetConfig();
        for (size_t i = 0; i < Config.SRAGPRCount && i < 8; i++) {
          if (Config.SRAGPRMapping[i] != Rt) {
            continue;
          }
          uint32_t First;
          memcpy(&First, reinterpret_cast<const void*>(Addr), sizeof(First));
          switch (i) {
          case FEXCore::X86State::REG_RAX: WowContext.Eax = First; break;
          case FEXCore::X86State::REG_RCX: WowContext.Ecx = First; break;
          case FEXCore::X86State::REG_RDX: WowContext.Edx = First; break;
          case FEXCore::X86State::REG_RBX: WowContext.Ebx = First; break;
          case FEXCore::X86State::REG_RBP: WowContext.Ebp = First; break;
          case FEXCore::X86State::REG_RSI: WowContext.Esi = First; break;
          case FEXCore::X86State::REG_RDI: WowContext.Edi = First; break;
          default: i = 8; break;
          }
          if (i < 8) {
            WowContext.Esp = static_cast<uint32_t>(Addr + 4);
            WowContext.Eip = SecondEip;
          }
          break;
        }
      }
    }
  }

  auto& Fault = Thread->CurrentFrame->SynchronousFaultData;
  *Exception = FEX::Windows::HandleGuestException(Fault, *Exception, WowContext.Eip, WowContext.Eax, WowContext.Ecx);
  if (Exception->ExceptionCode == EXCEPTION_SINGLE_STEP) {
    WowContext.EFlags &= ~(1 << FEXCore::X86State::RFLAG_TF_RAW_LOC);
  } else if (Exception->ExceptionCode != EXCEPTION_BREAKPOINT) {
    WowContext.EFlags |= 0x10000; // EFlags mask: RF on faults, as Windows reports it; LoadStateFromWowContext keeps it out of FEX state
  }
  // wow64.dll will handle adjusting PC in the dispatched context after a breakpoint

  BTCpuSetContext(GetCurrentThread(), GetCurrentProcess(), nullptr, &WowContext);
  Context::UnlockJITContext(TLS);

  // Replace the host context with one captured before JIT entry so host code can unwind
  memcpy(Context, TLS.EntryContext(), sizeof(*Context));

  return false;
}

NTSTATUS BTCpuResetToConsistentState(EXCEPTION_POINTERS* Ptrs) {
  if (BTCpuResetToConsistentStateImpl(Ptrs)) {
    // ★★★ MacRunner N2b — ДОГОВОР ПРИ ИСКЛЮЧЕНИИ. NtContinue НЕ ВОЗВРАЩАЕТСЯ, значит
    // ни один деструктор C++ на этом пути не отработает. Если исключение застало поток
    // внутри скобки записи, глубина осталась бы ненулевой, а поток — в режиме «писать»,
    // и первый же прыжок в выпущенный код умер бы на W^X — далеко от причины.
    // Возобновляемся В ГОСТЕВОЙ КОД, значит режим exec. Ненулевая глубина здесь — это
    // улика, и она печатается (macrunner-fex-jitwrite-РАЗРЫВ), а не глотается.
    FEXCore::Allocator::JITWriteResetForResume(true);
    NtContinue(Ptrs->ContextRecord, FALSE);
  }

  return STATUS_SUCCESS;
}

void BTCpuFlushInstructionCache2(const void* Address, SIZE_T Size) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Flush)) { // MACRUNNER_FEX_HOOK_GUARD (HG3)
    return;
  }
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuFlushInstructionCacheHeavy(const void* Address, SIZE_T Size) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Flush)) { // MACRUNNER_FEX_HOOK_GUARD (HG3)
    return;
  }
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryDirty(void* Address, SIZE_T Size) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Dirty)) { // MACRUNNER_FEX_HOOK_GUARD (HG3)
    return;
  }
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpuNotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot, BOOL After, ULONG Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Alloc)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!After) {
    FEXCore::HBX87::CrtWatch::Note(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size)); // rp6r4
  }
  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    // MEM_RESET(_UNDO) ignores the passed permissions
    if (!Status && !(Type & (MEM_RESET | MEM_RESET_UNDO))) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), Prot);
    }
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt, BOOL After, ULONG Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Protect)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!After) {
    FEXCore::HBX87::CrtWatch::Note(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size)); // rp6r4
  }
  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), NewProt);
    }
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType, BOOL After, ULONG Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Free)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!After) {
    FEXCore::HBX87::CrtWatch::Note(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size)); // rp6r4
  }
  if (!After) {
    ThreadCreationMutex.lock();
  } else {
    if (!Status) {
      InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);
    }
    ThreadCreationMutex.unlock();
  }
}

NTSTATUS BTCpuNotifyMapViewOfSection(void* Unk1, void* Address, void* Unk2, SIZE_T Size, ULONG AllocType, ULONG Prot) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Map)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return STATUS_SUCCESS;
  }
  if (Address) {
    FEXCore::HBX87::CrtWatch::Note(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size)); // rp6r4
  }
  std::scoped_lock Lock(ThreadCreationMutex);
  HandleImageMap(reinterpret_cast<uint64_t>(Address));
  return STATUS_SUCCESS;
}

void BTCpuNotifyUnmapViewOfSection(void* Address, BOOL After, ULONG Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Unmap)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!After) {
    FEXCore::HBX87::CrtWatch::Note(reinterpret_cast<uint64_t>(Address), 0); // rp6r4: extent unknown -> conservative window
    ThreadCreationMutex.lock();
    auto [Start, Size] = InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
    if (Size) {
      HandleImageUnmap(Start, Size);
    }
  } else {
    ThreadCreationMutex.unlock();
  }
}

void BTCpuNotifyReadFile(HANDLE Handle, void* Address, SIZE_T Size, BOOL After, NTSTATUS Status) {
  auto* ThreadState = GetTLS().ThreadState();
  if (!InvalidationTracker || !ThreadState) {
    return;
  }

  // See arm64ec `BTCpu64NotifyReadFile` for why this like this.
  if (After && Status == STATUS_SUCCESS) {
    std::scoped_lock Lock(ThreadCreationMutex);
    InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
  }
}

void BTCpuNotifyProcessExecuteFlagsChange(ULONG Flags) {
  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->HandleProcessExecuteFlagsChange(Flags);
}

BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT Feature) {
  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

void BTCpuUpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info) {
  CPUFeatures->UpdateInformation(Info);
}
