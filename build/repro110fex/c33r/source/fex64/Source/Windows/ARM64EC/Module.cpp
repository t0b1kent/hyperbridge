#include "Common/MacRunnerHostPageGeometry.h"
// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|ARM64EC
desc: Implements the ARM64EC BT module API using FEXCore
$end_info$
*/

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Utils/MacRunnerPause.h>
#include <FEXCore/Utils/MacRunnerQpcInline.h>
#include <cstddef>
#include <cstring>
#include "../../../FEXCore/Source/Interface/Core/HBX87Stats.h"
#include "../../../FEXCore/Source/Interface/Core/HBX87StateGates.h"
#include <algorithm>
#include <atomic>
extern std::atomic<uint64_t> MacRunnerJitSMC; // ★ MacRunner Opus 19.09: определён в Core.cpp
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/MacRunnerLazyMXCSR.h>
#include <FEXCore/Core/X87Region.h>
#include <FEXCore/Core/X87Fault.h>
#include <FEXCore/Core/X87Static.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>

#include "Windows/Common/Allocator.h"
#include "Windows/Common/EnvironmentVariablesHandling.h"
#include "Windows/Common/FEXUnixLib.h"
#include "Common/CallRetStack.h"
#include "Common/JITGuardPage.h"
#include "Common/Config.h"
#include "Common/Exception.h"
#include "Common/ImageTracker.h"
#include "Common/InvalidationTracker.h"
#include "Common/OvercommitTracker.h"
#include "Common/TSOHandlerConfig.h"
#include "Common/CPUFeatures.h"
#include "Common/Logging.h"
#include "Common/Module.h"
#include "Common/CRT/CRT.h"
#include "Common/PortabilityInfo.h"
#include "Common/Handle.h"
#include "DummyHandlers.h"
#include "BTInterface.h"
#include "Windows/Common/Winctx.h"
#include "Windows/Common/SHMStats.h"

extern "C" { extern uint32_t MacRunnerEcExitDispatch; }   // TSO64: defined in FEXCore JIT/BranchOps.cpp

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <type_traits>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
// ★ MacRunner QPCJIT: in ntdll.def, not declared by the headers in use.
extern "C" NTSTATUS NTAPI NtQueryPerformanceCounter(LARGE_INTEGER* Counter, LARGE_INTEGER* Frequency);
#include <winnt.h>
#include <wine/debug.h>
#include "Common/MacRunnerJournal.h"

namespace Exception {
class ECSyscallHandler;
}

extern "C" {
extern IMAGE_DOS_HEADER __ImageBase; // Provided by the linker

extern void* ExitFunctionEC;
extern void* CheckCall;
extern void* ExitFunctionSuspendPoint;
extern void* ExitFunctionSuspendResumePoint;

void* X64ReturnInstr; // See Module.S
uintptr_t NtDllBase;

// Exports on ARM64EC point to x64 fast forward sequences to allow for redirecting to the JIT if functions are hotpatched. This LUT is from their addresses to the relative addresses of the native code exports.
uint32_t* NtDllRedirectionLUT;
uint32_t NtDllRedirectionLUTSize;

// Wine doesn't support issuing direct system calls with SVC, and unlike Windows it doesn't have a 'stable' syscall number for NtContinue
void* WineSyscallDispatcher;
uint64_t WineNtContinueSyscallId;
uint64_t WineNtAllocateVirtualMemorySyscallId;
uint64_t WineNtProtectVirtualMemorySyscallId;
uint64_t WineNtGetContextThreadSyscallId;
uint32_t MacRunnerWinctxExactMode {};
void MacRunnerWinctxApplyPendingFP(uint8_t* SavedEntry = nullptr, bool NativeReturn = false);

NTSTATUS NtContinueNative(ARM64_NT_CONTEXT* NativeContext, BOOLEAN Alert);
NTSTATUS NtGetContextThreadNative(HANDLE, ARM64_NT_CONTEXT*);
NTSTATUS NtAllocateVirtualMemoryNative(HANDLE, PVOID*, ULONG_PTR, SIZE_T*, ULONG, ULONG);
NTSTATUS NtProtectVirtualMemoryNative(HANDLE, PVOID*, SIZE_T*, ULONG, ULONG*);
static fextl::string AppConfigName {};

[[noreturn]]
void JumpSetStack(uintptr_t PC, uintptr_t SP);
}

struct ThreadCPUArea {
  static constexpr size_t TEBCPUAreaOffset = 0x1788;
  CHPE_V2_CPU_AREA_INFO* Area;

  explicit ThreadCPUArea(_TEB* TEB)
    : Area(*reinterpret_cast<CHPE_V2_CPU_AREA_INFO**>(reinterpret_cast<uintptr_t>(TEB) + TEBCPUAreaOffset)) {}

  uint64_t& EmulatorStackLimit() const {
    return Area->EmulatorStackLimit;
  }

  uint64_t& EmulatorStackBase() const {
    return Area->EmulatorStackBase;
  }

  ARM64EC_NT_CONTEXT& ContextAmd64() const {
    return *Area->ContextAmd64;
  }

  FEXCore::Core::CpuStateFrame*& StateFrame() const {
    return reinterpret_cast<FEXCore::Core::CpuStateFrame*&>(Area->EmulatorData[0]);
  }

  FEXCore::Core::InternalThreadState*& ThreadState() const {
    return reinterpret_cast<FEXCore::Core::InternalThreadState*&>(Area->EmulatorData[1]);
  }

  uint64_t& DispatcherLoopTopEnterEC() const {
    return reinterpret_cast<uint64_t&>(Area->EmulatorData[2]);
  }

  uint64_t& DispatcherLoopTopEnterECFillSRA() const {
    return reinterpret_cast<uint64_t&>(Area->EmulatorData[3]);
  }
};

struct FrontendThreadData {
  // Native thread identity, not merely a guest TID: inherited/copied frontend
  // records must never admit a different host pthread to the common JIT.
  uint64_t HardwareTSOIdentity {};
  bool InLockedRWXRead {};
  uint32_t JournalSerial {};   // MACRUNNER_API_JOURNAL: серийный номер доставленного исключения, ждущего продолжения
  uint32_t JournalMxcsrSeen {};  // 0110: последнее наблюдённое State.mxcsr потока
  uint32_t JournalMxcsrSeq {};   // 0110: последний наблюдённый MxcsrTraceSeq кадра
  bool JournalMxcsrInit {};
  // X87-CTX (MACRUNNER_FEX_X87_CONTEXT=1): guest RSPs of exceptions delivered with x87 words, innermost last; NtContinue
  // of the same context (same RSP, x64 RIP) brings the handler's control/status/tag words back (see MacRunnerX87Context).
  uint64_t MRX87DeliveredRsp[8] {};
  uint32_t MRX87DeliveredCount {};
};

namespace {
fextl::unique_ptr<FEXCore::Context::Context> CTX;
fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
fextl::unique_ptr<Exception::ECSyscallHandler> SyscallHandler;
fextl::unique_ptr<FEX::Windows::StatAlloc> StatAllocHandler;
std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::CPUFeatures> CPUFeatures;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;
std::optional<FEX::Windows::ImageTracker> ImageTracker;

std::recursive_mutex ThreadCreationMutex;
// Map of TIDs to their FEX thread state, `ThreadCreationMutex` must be locked when accessing
std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;

std::pair<NTSTATUS, ThreadCPUArea> GetThreadCPUArea(HANDLE Thread) {
  THREAD_BASIC_INFORMATION Info;
  const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
  return {Err, ThreadCPUArea(reinterpret_cast<_TEB*>(Info.TebBaseAddress))};
}

ThreadCPUArea GetCPUArea() {
  return ThreadCPUArea(NtCurrentTeb());
}

FrontendThreadData* GetFrontendThreadData(FEXCore::Core::InternalThreadState* Thread) {
  return static_cast<FrontendThreadData*>(Thread->FrontendPtr);
}

uint64_t HardwareTSOIdentity() {
  uint64_t Identity = 0;
#ifdef FEX_WINE_DARWIN
  asm volatile("mrs %0, tpidrro_el0" : "=r"(Identity));
  Identity &= ~uint64_t {7}; // Opaque Darwin readonly thread token; never a pthread_self pointer.
#endif
  return Identity;
}

extern "C" {
extern const uint64_t MacRunnerFrontendPtrOffset = offsetof(FEXCore::Core::InternalThreadState, FrontendPtr);
void MacRunnerHardwareTSOEnter() {
  FEX::Windows::UnixLib::HardwareTSOThreadEnter(FEXHardwareTSOEntryKind::ARM64ECJitEntry);
  const auto Thread = GetCPUArea().ThreadState();
  // Admission is native TSD-owned. A missing frontend cache must not reject an
  // otherwise legitimate early entry; it merely keeps that entry on the slow
  // guard. The native policy still performs exactly one syscall per pthread.
  if (Thread && Thread->FrontendPtr)
    GetFrontendThreadData(Thread)->HardwareTSOIdentity = HardwareTSOIdentity();
}
}

bool IsEmulatorStackAddress(const ThreadCPUArea CPUArea, uint64_t Address) {
  return Address <= CPUArea.EmulatorStackBase() && Address >= CPUArea.EmulatorStackLimit();
}

bool IsDispatcherAddress(uint64_t Address) {
  const auto& Config = SignalDelegator->GetConfig();
  return Address >= Config.DispatcherBegin && Address < Config.DispatcherEnd;
}


void FillNtDllLUTs(HMODULE NtDll) {
  ULONG Size;
  const auto* LoadConfig =
    reinterpret_cast<_IMAGE_LOAD_CONFIG_DIRECTORY64*>(RtlImageDirectoryEntryToData(NtDll, true, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size));
  const auto* CHPEMetadata = reinterpret_cast<IMAGE_ARM64EC_METADATA*>(LoadConfig->CHPEMetadataPointer);
  const auto* RedirectionTableBegin = reinterpret_cast<IMAGE_ARM64EC_REDIRECTION_ENTRY*>(NtDllBase + CHPEMetadata->RedirectionMetadata);
  const auto* RedirectionTableEnd = RedirectionTableBegin + CHPEMetadata->RedirectionMetadataCount;

  NtDllRedirectionLUTSize = std::prev(RedirectionTableEnd)->Source + 1;

  SIZE_T AllocSize = NtDllRedirectionLUTSize * sizeof(uint32_t);
  NtAllocateVirtualMemoryNative(NtCurrentProcess(), reinterpret_cast<void**>(&NtDllRedirectionLUT), 0, &AllocSize, MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
  for (auto It = RedirectionTableBegin; It != RedirectionTableEnd; It++) {
    NtDllRedirectionLUT[It->Source] = It->Destination;
  }
}

template<typename T>
void WriteModuleRVA(HMODULE Module, LONG RVA, T Data) {
  if (!RVA) {
    return;
  }

  void* Address = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Module) + RVA);
  void* ProtAddress = Address;
  SIZE_T ProtSize = sizeof(T);
  ULONG Prot;
  NtProtectVirtualMemoryNative(NtCurrentProcess(), &ProtAddress, &ProtSize, PAGE_READWRITE, &Prot);
  *reinterpret_cast<T*>(Address) = Data;
  NtProtectVirtualMemoryNative(NtCurrentProcess(), &ProtAddress, &ProtSize, Prot, nullptr);
}

void PatchCallChecker() {
  // See the comment for CheckCall in Module.S for why this is necessary
  const auto Module = reinterpret_cast<HMODULE>(&__ImageBase);
  ULONG Size;
  const auto* LoadConfig =
    reinterpret_cast<_IMAGE_LOAD_CONFIG_DIRECTORY64*>(RtlImageDirectoryEntryToData(Module, true, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &Size));
  const auto* CHPEMetadata = reinterpret_cast<IMAGE_ARM64EC_METADATA*>(LoadConfig->CHPEMetadataPointer);
  WriteModuleRVA(Module, CHPEMetadata->__os_arm64x_dispatch_call, &CheckCall);
  WriteModuleRVA(Module, CHPEMetadata->__os_arm64x_dispatch_icall, &CheckCall);
  WriteModuleRVA(Module, CHPEMetadata->__os_arm64x_dispatch_icall_cfg, &CheckCall);
}

// Fills in the syscall numbers necessary to call *Native variants of syscalls from FEX under wine.
void ParseWineSyscallNumbers(HMODULE NtDll) {
  ULONG Size;
  const auto* Exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(RtlImageDirectoryEntryToData(NtDll, true, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size));
  const auto* NameTable = reinterpret_cast<uint32_t*>(NtDllBase + Exports->AddressOfNames);
  const auto* FunctionTable = reinterpret_cast<uint32_t*>(NtDllBase + Exports->AddressOfFunctions);
  const auto* OrdinalTable = reinterpret_cast<uint16_t*>(NtDllBase + Exports->AddressOfNameOrdinals);
  struct SyscallEntry {
    const char* Name;
    uint32_t RVA;

    bool operator<(const SyscallEntry& Other) const {
      return RVA < Other.RVA;
    }
  };

  // Cannot use any syscalls at this stage, so rely on a stack-allocated array
  std::array<SyscallEntry, 0x200> SyscallTable;
  auto SyscallTableEnd = SyscallTable.begin();

  // Windows/Wine orders syscalls in memory by their ID, take advantage of that to find the syscall indices for those
  // which we need to manually issue. Note that all functions starting with Nt besides NtGetTickCount are syscalls.
  for (uint32_t Idx = 0; Idx < Exports->NumberOfNames; Idx++) {
    const char* Name = reinterpret_cast<const char*>(NtDllBase + NameTable[Idx]);
    if (Name[0] == 'N' && Name[1] == 't' && strcmp(Name, "NtGetTickCount") != 0) {
      *SyscallTableEnd++ = {Name, FunctionTable[OrdinalTable[Idx]]};
    }
  }

  // Sort such that index 0 is now syscall 0, etc
  std::sort(SyscallTable.begin(), SyscallTableEnd);

  for (auto it = SyscallTable.begin(); it != SyscallTableEnd; it++) {
    uint32_t CurSyscallId = static_cast<uint32_t>(std::distance(SyscallTable.begin(), it));
    if (strcmp(it->Name, "NtContinue") == 0) {
      WineNtContinueSyscallId = CurSyscallId;
    } else if (strcmp(it->Name, "NtAllocateVirtualMemory") == 0) {
      WineNtAllocateVirtualMemorySyscallId = CurSyscallId;
    } else if (strcmp(it->Name, "NtProtectVirtualMemory") == 0) {
      WineNtProtectVirtualMemorySyscallId = CurSyscallId;
    } else if (strcmp(it->Name, "NtGetContextThread") == 0) {
      WineNtGetContextThreadSyscallId = CurSyscallId;
    }
  }
}

// Syscall thunks may have been patched before FEX has loaded, the default call checker installed by ntdll into FEX will
// try to invoke the JIT when calling such patched syscalls but this obviously doesn't work before FEX is initalised.
// This function parses ntdll and sets up a custom call checker to prevent this, as such it must avoid using any syscall
// thunks itself.
void InitSyscalls() {
  // The ntdll exports called by GetModuleHandle/GetProcAddress aren't known to be patched before JIT init by any current
  // software so are safe to call, but if that changes the loader structures in the PEB could be parsed manually.
  const auto NtDll = GetModuleHandleW(L"ntdll.dll");
  NtDllBase = reinterpret_cast<uintptr_t>(NtDll);

  const auto WineSyscallDispatcherPtr = reinterpret_cast<void**>(GetProcAddress(NtDll, "__wine_syscall_dispatcher"));
  if (WineSyscallDispatcherPtr) {
    WineSyscallDispatcher = *WineSyscallDispatcherPtr;
    ParseWineSyscallNumbers(NtDll);
  }

  FillNtDllLUTs(NtDll);
  PatchCallChecker();
}

void HandleImageMap(uint64_t Address, bool MainImage = false) {
  fextl::string ModulePath = FEX::Windows::GetSectionFilePath(Address);
  fextl::string ModuleName = fextl::string {FEX::Windows::BaseName(ModulePath)};
  FEX::Windows::AliasPolicy::ImageMapped(ModuleName);
  InvalidationTracker->HandleImageMap(ModuleName, Address);
  ImageTracker->HandleImageMap(ModulePath, Address, MainImage);
}

void HandleImageUnmap(uint64_t Address, uint64_t Size) {
  ImageTracker->HandleImageUnmap(Address, Size);
}

// ★ MacRunner QPCJIT (03.11.2026) MACRUNNER_FEX_QPC_INLINE — see FEXCore/Utils/MacRunnerQpcInline.h. Runs once in ProcessInit, before
// any guest code: finds ntdll's x64-visible RtlQueryPerformanceCounter entry (the FFS, as GetProcAddress gives it to x64 code) and the
// data of ntdll's own user-mode QPC (export macrunner_ntdll_fast, QPC lane patch 0001), checks everything the inline code relies on,
// and arms the plan. Any doubt = not armed, marker why=..., FEX translates the FFS as before. Key 0: returns at once, prints nothing.
uint64_t MRQpcReadCounter(uint32_t Kind) {
  uint64_t V;
  if (Kind == 3) {
    __asm__ __volatile__("mrs %0, s3_4_c15_c10_6" : "=r"(V)::"memory");
  } else if (Kind == 2) {
    __asm__ __volatile__("mrs %0, s3_3_c14_c0_6" : "=r"(V)::"memory");
  } else {
    __asm__ __volatile__("isb\n\tmrs %0, cntvct_el0" : "=r"(V)::"memory");
  }
  return V;
}

// ★ QPCJIT stage 3: compile-time read of 8 bytes of guest memory that cannot fault in the compiler: committed, readable, not a guard
// page, inside one region (NtQueryVirtualMemory, local to the unix side of ntdll). Used only for `call/jmp qword [rip+disp]` candidates.
void MRQpcInlinePeriodic();

bool MRQpcSafeRead64(uint64_t Addr, uint64_t* Out) {
  MEMORY_BASIC_INFORMATION Info;
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Addr), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
    return false;
  }
  constexpr DWORD Readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  if (Info.State != MEM_COMMIT || (Info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) || !(Info.Protect & Readable) ||
      Addr + 8 > reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize) {
    return false;
  }
  memcpy(Out, reinterpret_cast<const void*>(Addr), sizeof(*Out));
  return true;
}

void MRQpcInlineInit(HMODULE NtDll) {
  namespace Q = FEXCore::Utils::MRQpcInline;
  static_assert(offsetof(Q::NtdllFast, qpc_counter) == 4 && offsetof(Q::NtdllFast, qpc_base_addr) == 8 &&
                  offsetof(Q::NtdllFast, qpc_mul) == 0x10 && offsetof(Q::NtdllFast, qpc_div) == 0x18 &&
                  offsetof(Q::NtdllFast, qpc_count) == 0x24 && sizeof(Q::NtdllFast) == 0x30,
                "struct macrunner_ntdll_fast (wine dlls/ntdll/unixlib.h)");
  const char* Key = getenv("MACRUNNER_FEX_QPC_INLINE");
  if (!Key || !Key[0] || (Key[0] == '0' && !Key[1])) {
    return;
  }
  const unsigned Mode = (!Key[1] && Key[0] >= '1' && Key[0] <= '9') ? static_cast<unsigned>(Key[0] - '0') : 0;
  // 1 2 9: FFS;  3 4 8: FFS + call sites;  5 6 7: the same as 3 4 in the compact form (7: wrong scale on both compact paths)
  const bool Counting = Mode == 2 || Mode == 4 || Mode == 6;
  const bool WrongFfsScale = Mode == 9 || Mode == 7, WrongSiteScale = Mode == 8 || Mode == 7;
  static constexpr uint8_t FfsHead[10] = {0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9}; // mov rax,rsp; mov [rax+20h],rbx; push rbp; pop rbp; jmp rel32
  const auto* Fast = reinterpret_cast<const Q::NtdllFast*>(GetProcAddress(NtDll, "macrunner_ntdll_fast"));
  const uint64_t Ffs = reinterpret_cast<uint64_t>(GetProcAddress(NtDll, "RtlQueryPerformanceCounter"));
  const char* Why = nullptr;
  uint64_t Body = 0, Div = 0, Gcd = 1;
  unsigned Kind = 0, Bracket = 0;
  Q::Scale S {}, SiteS {};
  if (!Mode) {
    Why = "unknown-key-value";
  } else if (!Fast) {
    Why = "no-ntdll-export"; // ntdll without the QPC lane's patch 0001: there is no ntdll fast path to agree with
  } else if (!Ffs || Ffs < NtDllBase || Ffs - NtDllBase >= NtDllRedirectionLUTSize || !NtDllRedirectionLUT[Ffs - NtDllBase]) {
    Why = "no-redirection";
  } else if (memcmp(reinterpret_cast<const void*>(Ffs), FfsHead, sizeof(FfsHead))) {
    Why = "ffs-bytes";
  } else {
    Body = NtDllRedirectionLUT[Ffs - NtDllBase] + NtDllBase;
    int32_t Rel;
    memcpy(&Rel, reinterpret_cast<const void*>(Ffs + sizeof(FfsHead)), sizeof(Rel));
    Kind = Fast->qpc_counter;
    Div = Fast->qpc_div + (WrongFfsScale ? 1 : 0);
    if (Ffs + sizeof(FfsHead) + sizeof(Rel) + static_cast<int64_t>(Rel) != Body) {
      Why = "ffs-target";
    } else if (Kind < 1 || Kind > 3) {
      Why = "ntdll-qpc-unvalidated"; // MACRUNNER_QPC_FAST=0 without the hot-key file: ntdll never validated the commpage
    } else if (!Fast->qpc_base_addr || !Fast->qpc_mul || !Fast->qpc_div) {
      Why = "ntdll-qpc-params";
    } else if (Fast->qpc_count && !Counting) {
      Why = "ntdll-qpc-count-on"; // MACRUNNER_QPC_COUNT=1 counts in ntdll; inlined calls would be missing from it (key 2 counts them here)
    } else if ((S = Q::ComputeScale(Fast->qpc_mul, Div)).Form == Q::ScaleForm::None ||
               (SiteS = Q::ComputeScale(Fast->qpc_mul, Fast->qpc_div + (WrongSiteScale ? 1 : 0))).Form == Q::ScaleForm::None) {
      Why = "scale";
    } else {
      Gcd = Q::Gcd(Fast->qpc_mul, Div);
      const uint64_t XMax = UINT64_MAX / Fast->qpc_mul;
      uint64_t X = 0x9E3779B97F4A7C15ULL;
      for (unsigned i = 0; i < 4096 && !Why; ++i) {
        uint64_t V;
        if (i < 1024) {
          V = i;
        } else if (i < 2048) {
          V = XMax - (i - 1024);
        } else {
          X ^= X << 13;
          X ^= X >> 7;
          X ^= X << 17;
          V = X % (XMax + 1);
        }
        if (Q::ApplyScale(S, V) != V * Fast->qpc_mul / Div ||
            Q::ApplyScale(SiteS, V) != V * Fast->qpc_mul / (Fast->qpc_div + (WrongSiteScale ? 1 : 0))) {
          Why = "scale-selftest";
        }
      }
      // The clock itself: the inline value must lie between two NtQueryPerformanceCounter (the syscall clock), as ntdll checks its own.
      for (unsigned i = 0; i < 64 && !Why && !WrongFfsScale; ++i) {
        LARGE_INTEGER A, B;
        NtQueryPerformanceCounter(&A, nullptr);
        const uint64_t T = MRQpcReadCounter(Kind) + *reinterpret_cast<const volatile uint64_t*>(Fast->qpc_base_addr);
        const uint64_t V = Q::ApplyScale(S, T);
        NtQueryPerformanceCounter(&B, nullptr);
        if (V < static_cast<uint64_t>(A.QuadPart) || V > static_cast<uint64_t>(B.QuadPart)) {
          Why = "bracket";
        } else {
          ++Bracket;
        }
      }
    }
  }
  auto& P = Q::G;
  if (!Why) {
    P.Mode = static_cast<uint8_t>(Mode);
    P.Kind = static_cast<uint8_t>(Kind);
    P.Ffs = Ffs;
    P.Body = Body;
    P.EnabledAddr = reinterpret_cast<uint64_t>(&Fast->qpc_enabled);
    P.BaseAddr = Fast->qpc_base_addr;
    P.CountAddr = Counting ? reinterpret_cast<uint64_t>(&Q::InlinedCalls) : 0;
    P.S = S;
    P.SiteS = SiteS;
    P.CallSite = Mode >= 3 && Mode <= 8;
    P.Compact = Mode >= 5 && Mode <= 7;
    P.SiteCountAddr = Mode == 4 || Mode == 6 ? reinterpret_cast<uint64_t>(&Q::SiteCalls) : 0;
    memcpy(P.FfsQ, reinterpret_cast<const void*>(Ffs), sizeof(P.FfsQ));
    P.SafeRead64 = MRQpcSafeRead64;
    P.Periodic = MRQpcInlinePeriodic;
    // compact form: [0] the FFS path (scale S), [1] sites whose slot holds the FFS (scale SiteS); thunk entries come at compile time
    for (unsigned i = 0; i < 2; ++i) {
      auto& E = Q::Entries[i];
      const auto& Sc = i ? SiteS : S;
      E.Ffs = Ffs;
      E.FlagAddr = P.EnabledAddr;
      E.Q0 = P.FfsQ[0];
      E.Q1 = P.FfsQ[1];
      E.BaseAddr = P.BaseAddr;
      E.Magic = Sc.Magic;
      E.Mul = Sc.Mul;
    }
    Q::EntryCount.store(2, std::memory_order_release);
    memcpy(P.FfsBytes, reinterpret_cast<const void*>(Ffs), sizeof(P.FfsBytes));
    memcpy(P.BodyBytes, reinterpret_cast<const void*>(Body), sizeof(P.BodyBytes));
    P.Armed = true;
    Why = Mode == 9 ? "TEST-WRONG-SCALE" : Mode == 8 ? "TEST-WRONG-SITE-SCALE" : Mode == 7 ? "TEST-WRONG-COMPACT-SCALE" : "ok";
  }
  char Line[512];
  std::snprintf(Line, sizeof(Line),
                "macrunner-fex-qpc-inline: key=%.4s armed=%u why=%s ffs=%llx body=%llx kind=%u mul=%llu div=%llu reduced=%llu/%llu form=%u "
                "magic=%llx shift=%u qpc_enabled=%u bracket=%u pid=%lu\n",
                Key, static_cast<unsigned>(P.Armed), Why, static_cast<unsigned long long>(Ffs), static_cast<unsigned long long>(Body), Kind,
                static_cast<unsigned long long>(Fast ? Fast->qpc_mul : 0), static_cast<unsigned long long>(Div),
                static_cast<unsigned long long>(Fast && Fast->qpc_mul ? Fast->qpc_mul / Gcd : 0), static_cast<unsigned long long>(Div / Gcd),
                static_cast<unsigned>(S.Form), static_cast<unsigned long long>(S.Magic), static_cast<unsigned>(S.Shift),
                Fast ? static_cast<unsigned>(Fast->qpc_enabled) : 0U, Bracket, static_cast<unsigned long>(GetCurrentProcessId()));
  FEX::Windows::Logging::Raw(Line);
}

void MRQpcInlineReport(const char* When) {
  namespace Q = FEXCore::Utils::MRQpcInline;
  if (!Q::G.Armed) {
    return;
  }
  char Line[448];
  const bool Counting = Q::G.Mode == 2 || Q::G.Mode == 4 || Q::G.Mode == 6;
  uint64_t Freq;
  __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(Freq));
  std::snprintf(Line, sizeof(Line),
                "macrunner-fex-qpc-inline-end: when=%s key=%u inlined=%lld sites=%llu refused=%llu site_inlined=%lld site_call=%llu site_jmp=%llu "
                "site_queries=%llu site_rejected=%llu site_reads=%llu site_read_us=%llu pid=%lu tid=%lu\n", When,
                static_cast<unsigned>(Q::G.Mode), Counting ? static_cast<long long>(Q::InlinedCalls.load(std::memory_order_relaxed)) : -1LL,
                static_cast<unsigned long long>(Q::Sites.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(Q::Refused.load(std::memory_order_relaxed)),
                Q::G.Mode == 4 || Q::G.Mode == 6 ? static_cast<long long>(Q::SiteCalls.load(std::memory_order_relaxed)) : -1LL,
                static_cast<unsigned long long>(Q::SiteCompiledCall.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(Q::SiteCompiledJmp.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(Q::SiteQueries.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(Q::SiteRejected.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(Q::SiteReads.load(std::memory_order_relaxed)),
                static_cast<unsigned long long>(Q::SiteReadTicks.load(std::memory_order_relaxed) * 1000000ULL / (Freq ? Freq : 1)), // FEX CRT: no %f
                static_cast<unsigned long>(GetCurrentProcessId()), static_cast<unsigned long>(GetCurrentThreadId()));
  FEX::Windows::Logging::Raw(Line);
}

// ★ QPCJIT: the same line while the process runs, at most every 5 s (CNTVCT), from compile time and thread exit.
void MRQpcInlinePeriodic() {
  static std::atomic<uint64_t> Last {0};
  uint64_t Now, Freq;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(Now));
  __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(Freq));
  uint64_t Prev = Last.load(std::memory_order_relaxed);
  if (Now - Prev < 5 * Freq || !Last.compare_exchange_strong(Prev, Now, std::memory_order_relaxed)) {
    return;
  }
  MRQpcInlineReport("periodic");
}
} // namespace

namespace Exception {
static std::optional<FEX::Windows::TSOHandlerConfig> HandlerConfig;
static uintptr_t KiUserExceptionDispatcher;
// Initialized during ProcessInit after CRT setup, before guest execution. The
// exception path only reads this value; it performs no environment lookup or
// first-use static initialization.
static bool MRMxcsrFlagsEnabled;
static bool MRMxcsrContextControlEnabled;
static bool MRSuspendX87MetadataEnabled;
static bool MRWinctxExact;
// X87-CTX (17.10.2026), MACRUNNER_FEX_X87_CONTEXT=1: the AMD64 CONTEXT carries ST(0)..ST(7) in stack order (FXSAVE layout)
// and FEX's State.mm is physical, (TOP + i) & 7. Without WINCTX_EXACT the packed native context and the import used the
// physical order, and the exception CONTEXT had ControlWord/StatusWord/TagWord = 0 (the ARM64EC native context has no slot
// for them). With the key: both directions rotate by TOP, and a guest exception carries the x87 words in the existing
// FLOAT-only tail that Wine's context_arm_to_x64 already applies. Context transfer code only: nothing in translated code.
static bool MRX87Context;
// X87-CTX P5 (MACRUNNER_FEX_X87_FAULT_STATE): restore the x87 stack state the stack pass still held in host registers.
static bool MRX87FaultState;
// Wine's fpcsr_to_mxcsr (dlls/ntdll/unwind.h): the MxCsr the dispatcher derives without a tail, kept identical with one.
static uint32_t MRFpcsrToMxcsr(uint32_t Fpcr, uint32_t Fpsr) {
  uint32_t R = 0;
  if (Fpsr & 0x0001) R |= 0x0001;
  if (Fpsr & 0x0002) R |= 0x0004;
  if (Fpsr & 0x0004) R |= 0x0008;
  if (Fpsr & 0x0008) R |= 0x0010;
  if (Fpsr & 0x0010) R |= 0x0020;
  if (Fpsr & 0x0080) R |= 0x0002;
  if (Fpcr & 0x0080000) R |= 0x0040;
  if (!(Fpcr & 0x0000100)) R |= 0x0080;
  if (!(Fpcr & 0x0000200)) R |= 0x0200;
  if (!(Fpcr & 0x0000400)) R |= 0x0400;
  if (!(Fpcr & 0x0000800)) R |= 0x0800;
  if (!(Fpcr & 0x0001000)) R |= 0x1000;
  if (!(Fpcr & 0x0008000)) R |= 0x0100;
  if (Fpcr & 0x0400000) R |= 0x4000;
  if (Fpcr & 0x0800000) R |= 0x2000;
  if (Fpcr & 0x1000000) R |= 0x8000;
  return R;
}

struct alignas(16) KiUserExceptionDispatcherStackLayout {
  ARM64_NT_CONTEXT Context;
  uint64_t Pad[4]; // Only present on newer Windows versions, likely for SVE.
  EXCEPTION_RECORD Rec;
  uint64_t Align;
  uint64_t Redzone[2];
};

struct alignas(16) MRWinctxDispatcherLayout {
  KiUserExceptionDispatcherStackLayout Base;
  uint8_t Reserved[MR_WINCTX_TAIL_OFFSET - sizeof(Base)];
  mr_winctx_tail Tail;
};
static_assert(sizeof(mr_winctx_tail) == 32);
static_assert(offsetof(MRWinctxDispatcherLayout, Tail) == MR_WINCTX_TAIL_OFFSET);

static void MRStoreWinctxTail(FEXCore::Core::InternalThreadState* Thread, ARM64_NT_CONTEXT& Native,
                            mr_winctx_tail& Tail, bool ResumeFlag) {
  auto& State = Thread->CurrentFrame->State;
  Tail = {};
  Tail.magic = MR_WINCTX_MAGIC;
  Tail.size = sizeof(Tail);
  Tail.version = MR_WINCTX_VERSION;
  Tail.valid = MR_WINCTX_VALID_CONTROL | MR_WINCTX_VALID_FLOAT;
  Tail.eflags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0) | (ResumeFlag ? 0x10000U : 0U);
  Tail.mxcsr = State.mxcsr;
  Tail.fcw = State.FCW;
  Tail.fsw = (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] & 7) << 11;
  Tail.fsw |= State.flags[FEXCore::X86State::X87FLAG_IE_LOC] & 1;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_SF_LOC] & 1) << 6;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] & 1) << 8;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] & 1) << 9;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] & 1) << 10;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] & 1) << 14;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_DE_LOC] & 1) << 1;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_ZE_LOC] & 1) << 2;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_OE_LOC] & 1) << 3;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_UE_LOC] & 1) << 4;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_PE_LOC] & 1) << 5;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_ES_LOC] & 1) << 7;
  Tail.fsw |= (State.flags[FEXCore::X86State::X87FLAG_B_LOC] & 1) << 15;
  Tail.ftw = State.AbridgedFTW;
  Native.ContextFlags |= MR_WINCTX_ARM_FLAG;
}

static mr_winctx_debug_state* MRDebugState() {
  const auto Area = GetCPUArea().Area;
  return Area ? reinterpret_cast<mr_winctx_debug_state*>(reinterpret_cast<uint8_t*>(Area) + MR_WINCTX_DEBUG_OFFSET) : nullptr;
}
static bool MRDebugValid(const mr_winctx_debug_state* State) {
  return State && __atomic_load_n(&State->valid, __ATOMIC_ACQUIRE) &&
    State->magic == MR_WINCTX_DEBUG_MAGIC && State->version == MR_WINCTX_DEBUG_VERSION && State->size == sizeof(*State);
}
static void MRDebugPublish(const uint64_t* Values) {
  auto* State = MRDebugState();
  if (!State) return;
  __atomic_store_n(&State->valid, 0, __ATOMIC_RELEASE);
  memcpy(State->dr, Values, sizeof(State->dr));
  mr_winctx_debug_disabled_policy(State->dr);
  State->magic = MR_WINCTX_DEBUG_MAGIC;
  State->size = sizeof(*State);
  State->version = MR_WINCTX_DEBUG_VERSION;
  __atomic_store_n(&State->valid, 1, __ATOMIC_RELEASE);
}
static uint64_t& MRDebugWord(unsigned Offset) {
  return *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(GetCPUArea().Area) + Offset);
}
static void MRDebugPack(ARM64_NT_CONTEXT& Native) {
  auto* State = MRDebugState();
  if (!MRDebugValid(State)) return;
  Native.ContextFlags |= CONTEXT_ARM64_DEBUG_REGISTERS;
  memcpy(Native.Bvr, State->dr, sizeof(State->dr));
  // Windows exposes the fixed hardware bit in an active exception snapshot,
  // while the pre-resume Get/Set request remains the server's requested value.
  if (State->dr[5] & 0xff) Native.Bvr[5] |= 0x400;
  Native.Bcr[0] = MR_WINCTX_DEBUG_ARM_MAGIC;
  Native.Bcr[1] = MR_WINCTX_DEBUG_VERSION;
  Native.Bcr[2] = sizeof(*State);
}
static_assert(sizeof(mr_winctx_debug_state) == 64);
static_assert(MR_WINCTX_DEBUG_OFFSET >= MR_WINCTX_GUEST_ENTRY_TARGET_OFFSET + sizeof(uint64_t));
static_assert(MR_WINCTX_DEBUG_OFFSET + sizeof(mr_winctx_debug_state) < MR_WINCTX_CLOSE_RETURN_PENDING_OFFSET);

static bool HandleUnalignedAccess(const ThreadCPUArea CPUArea, ARM64_NT_CONTEXT& Context, bool IsJIT) {
  auto Thread = CPUArea.ThreadState();
  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
  const auto Result =
    FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, HandlerConfig->GetUnalignedHandlerType(), Context.Pc, &Context.X0, IsJIT);
  Context.Pc += Result.value_or(0);
  return Result.has_value();
}

// x87 control/status/tag words of an AMD64 CONTEXT (FXSAVE image: TOP in StatusWord, abridged tags by physical register).
static void MRX87MetadataFromContext(FEXCore::Core::CPUState& State, const CONTEXT& Context) {
  State.FCW = MRWinctxExact ? FEXCore::Winctx::CanonicalControlWord(Context.FltSave.ControlWord) : Context.FltSave.ControlWord;
  State.flags[FEXCore::X86State::X87FLAG_IE_LOC] = Context.FltSave.StatusWord & 1;
  State.flags[FEXCore::X86State::X87FLAG_SF_LOC] = (Context.FltSave.StatusWord >> 6) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (Context.FltSave.StatusWord >> 8) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (Context.FltSave.StatusWord >> 9) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (Context.FltSave.StatusWord >> 10) & 1;
  State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (Context.FltSave.StatusWord >> 14) & 1;
  State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (Context.FltSave.StatusWord >> 11) & 0b111;
  if (MRWinctxExact || FEXCore::HBX87::StateFix::ExceptionFlagsFor(true)) {
    State.flags[FEXCore::X86State::X87FLAG_DE_LOC] = (Context.FltSave.StatusWord >> 1) & 1;
    State.flags[FEXCore::X86State::X87FLAG_ZE_LOC] = (Context.FltSave.StatusWord >> 2) & 1;
    State.flags[FEXCore::X86State::X87FLAG_OE_LOC] = (Context.FltSave.StatusWord >> 3) & 1;
    State.flags[FEXCore::X86State::X87FLAG_UE_LOC] = (Context.FltSave.StatusWord >> 4) & 1;
    State.flags[FEXCore::X86State::X87FLAG_PE_LOC] = (Context.FltSave.StatusWord >> 5) & 1;
    State.flags[FEXCore::X86State::X87FLAG_ES_LOC] = (Context.FltSave.StatusWord >> 7) & 1;
    State.flags[FEXCore::X86State::X87FLAG_B_LOC] = (Context.FltSave.StatusWord >> 15) & 1;
  }
  State.AbridgedFTW = Context.FltSave.TagWord;
}

static void LoadStateFromECContext(FEXCore::Core::InternalThreadState* Thread, CONTEXT& Context, bool HasX87Metadata = true) {
  auto& State = Thread->CurrentFrame->State;
  if (MRWinctxExact && (Context.ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
    MRDebugPublish(&Context.Dr0);

  if ((Context.ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
    // General register state
    State.gregs[FEXCore::X86State::REG_RAX] = Context.Rax;
    State.gregs[FEXCore::X86State::REG_RCX] = Context.Rcx;
    State.gregs[FEXCore::X86State::REG_RDX] = Context.Rdx;
    State.gregs[FEXCore::X86State::REG_RBX] = Context.Rbx;

    State.gregs[FEXCore::X86State::REG_RSI] = Context.Rsi;
    State.gregs[FEXCore::X86State::REG_RDI] = Context.Rdi;
    State.gregs[FEXCore::X86State::REG_R8] = Context.R8;
    State.gregs[FEXCore::X86State::REG_R9] = Context.R9;
    State.gregs[FEXCore::X86State::REG_R10] = Context.R10;
    State.gregs[FEXCore::X86State::REG_R11] = Context.R11;
    State.gregs[FEXCore::X86State::REG_R12] = Context.R12;
    State.gregs[FEXCore::X86State::REG_R13] = Context.R13;
    State.gregs[FEXCore::X86State::REG_R14] = Context.R14;
    State.gregs[FEXCore::X86State::REG_R15] = Context.R15;
    if (MRWinctxExact) State.gregs[FEXCore::X86State::REG_RBP] = Context.Rbp;
  }

  if ((Context.ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
    State.rip = Context.Rip;
    State.gregs[FEXCore::X86State::REG_RSP] = Context.Rsp;
    if (!MRWinctxExact) State.gregs[FEXCore::X86State::REG_RBP] = Context.Rbp;
    CTX->SetFlagsFromCompactedEFLAGS(Thread, Context.EFlags);
  }

  if ((Context.ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
    State.es_idx = Context.SegEs & 0xffff;
    State.cs_idx = Context.SegCs & 0xffff;
    State.ss_idx = Context.SegSs & 0xffff;
    State.ds_idx = Context.SegDs & 0xffff;
    State.fs_idx = Context.SegFs & 0xffff;
    State.gs_idx = Context.SegGs & 0xffff;

    // The TEB is the only populated GDT entry by default
#ifdef FEX_WINE_DARWIN
    uint64_t TEB;
    // Darwin can clear x18 without a fault. Load Self so Wine can retry a null
    // x18, and retain the result in a general register for both GS stores.
    __asm__ __volatile__("ldr %0, [x18, #0x30]" : "=r"(TEB) : : "memory");
#else
    const auto TEB = reinterpret_cast<uint64_t>(NtCurrentTeb());
#endif
    auto GDT = State.GetSegmentFromIndex(State, (Context.SegGs & 0xffff));
    State.SetGDTBase(GDT, TEB);
    State.SetGDTLimit(GDT, 0xF'FFFFU);
    State.gs_cached = TEB;
    State.fs_cached = 0;
    State.es_cached = 0;
    State.cs_cached = 0;
    State.ss_cached = 0;
    State.ds_cached = 0;
  }

  if ((Context.ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
    if (MRMxcsrFlagsEnabled || MacRunnerAppleAFPEnabled || MRWinctxExact ||
        FEXCore::LazyMXCSR::Enabled.load(std::memory_order_relaxed)) {
      // LAZY-FLAGS: the status bits stay in the shadow here; SyncThreadContext moves them into
      // FPSR right before the JIT entry. Readers OR both, so a shadow-held bit is never lost.
      State.mxcsr = Context.MxCsr & (MRWinctxExact ? FEXCore::Winctx::MXCSRMask : 0xFFFFU);
    }
    // Floating-point register state
    if ((Context.ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE) {
      const auto* Ymm = RtlLocateExtendedFeature(reinterpret_cast<CONTEXT_EX*>(&Context + 1), XSTATE_AVX, nullptr);
      CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(Context.FltSave.XmmRegisters),
                                    reinterpret_cast<const __uint128_t*>(Ymm));
    } else {
      CTX->SetXMMRegistersFromState(Thread, reinterpret_cast<const __uint128_t*>(Context.FltSave.XmmRegisters), nullptr);
    }
    if (MRWinctxExact) {
      // FXSAVE / AMD64 CONTEXT uses logical ST(0)..ST(7), while FEX's
      // backing array is indexed by physical x87 register. Restore the
      // destination TOP from this context, including explicit handler edits.
      const unsigned Top = (Context.FltSave.StatusWord >> 11) & 7;
      for (unsigned I = 0; I < 8; ++I) {
        memcpy(State.mm[(Top + I) & 7], &Context.FltSave.FloatRegisters[I], sizeof(State.mm[0]));
      }
    } else if (MRX87Context) {
      // A context without x87 metadata (ARM64EC native transport) keeps the thread's TOP; one with metadata brings its own.
      const unsigned Top = HasX87Metadata ? (Context.FltSave.StatusWord >> 11) & 7 : State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] & 7;
      for (unsigned I = 0; I < 8; ++I) {
        memcpy(State.mm[(Top + I) & 7], &Context.FltSave.FloatRegisters[I], sizeof(State.mm[0]));
      }
    } else {
      memcpy(State.mm, Context.FltSave.FloatRegisters, sizeof(State.mm));
    }

    if (HasX87Metadata) {
      MRX87MetadataFromContext(State, Context);
    }
  }
}

// X87-CTX (MACRUNNER_FEX_X87_CONTEXT=1, non-exact): the ARM64EC native context has no x87 group (its FloatRegisters slots
// carry LR/X6../X16/X17), so Wine's NtGetContextThread/NtSetContextThread/NtContinue exchange the x87 part of the AMD64
// CONTEXT with the thread's FEX state through MacRunnerX87Context. Layout = FXSAVE: ST(i) order, TOP in StatusWord.
static void MRX87ToContext(FEXCore::Core::InternalThreadState* Thread, CONTEXT& Context) {
  const auto& State = Thread->CurrentFrame->State;
  ARM64_NT_CONTEXT Native {};
  mr_winctx_tail Tail {};
  MRStoreWinctxTail(Thread, Native, Tail, false);
  Context.FltSave.ControlWord = Tail.fcw;
  Context.FltSave.StatusWord = Tail.fsw;
  Context.FltSave.TagWord = Tail.ftw;
  const unsigned Top = (Tail.fsw >> 11) & 7;
  for (unsigned I = 0; I < 8; ++I) {
    memset(&Context.FltSave.FloatRegisters[I], 0, sizeof(Context.FltSave.FloatRegisters[I]));
    memcpy(&Context.FltSave.FloatRegisters[I], State.mm[(Top + I) & 7], 10);
  }
}

static void MRX87FromContext(FEXCore::Core::InternalThreadState* Thread, const CONTEXT& Context) {
  auto& State = Thread->CurrentFrame->State;
  const unsigned Top = (Context.FltSave.StatusWord >> 11) & 7;
  for (unsigned I = 0; I < 8; ++I) {
    memset(State.mm[(Top + I) & 7], 0, sizeof(State.mm[0]));
    memcpy(State.mm[(Top + I) & 7], &Context.FltSave.FloatRegisters[I], 10);
  }
  MRX87MetadataFromContext(State, Context);
}

static void MRX87PushDelivered(FEXCore::Core::InternalThreadState* Thread, uint64_t Rsp) {
  auto* Data = Thread->FrontendPtr ? GetFrontendThreadData(Thread) : nullptr;
  if (!Data) return;
  auto& Count = Data->MRX87DeliveredCount;
  constexpr uint32_t Capacity = sizeof(Data->MRX87DeliveredRsp) / sizeof(Data->MRX87DeliveredRsp[0]);
  while (Count && Data->MRX87DeliveredRsp[Count - 1] <= Rsp) --Count; // unwound (or replaced) deeper deliveries
  if (Count == Capacity) {
    memmove(Data->MRX87DeliveredRsp, Data->MRX87DeliveredRsp + 1, sizeof(Data->MRX87DeliveredRsp[0]) * (Capacity - 1));
    --Count;
  }
  Data->MRX87DeliveredRsp[Count++] = Rsp;
}

// NtContinue of a context this thread was handed by RethrowGuestException: its x87 words are the handler's (registers ride
// the native overlay and SyncThreadContext places them by the TOP set here). Any other context keeps the thread's words.
static uint32_t MRX87Continue(FEXCore::Core::InternalThreadState* Thread, const CONTEXT& Context) {
  auto* Data = Thread->FrontendPtr ? GetFrontendThreadData(Thread) : nullptr;
  if (!Data) return 0;
  auto& Count = Data->MRX87DeliveredCount;
  while (Count && Data->MRX87DeliveredRsp[Count - 1] < Context.Rsp) --Count;
  if (!Count || Data->MRX87DeliveredRsp[Count - 1] != Context.Rsp || RtlIsEcCode(Context.Rip)) return 0;
  --Count;
  MRX87MetadataFromContext(Thread->CurrentFrame->State, Context);
  return 1;
}

// ★ MacRunner (Claude, 30.09.2026) — MACRUNNER_FEX_EFLAGS_KEEP=1: флаги, которые контекст ARM64EC не несёт (PF/AF/DF и
//   прочие вне NZCV+SS), после возврата из обработчика исключения — такие, какими были ДО исключения. Так делает Prism
//   (проба eflags_probe.exe, 8 случаев, ДОЛГ.md EFLAGS-ИСКЛЮЧЕНИЯ); без гейта SyncThreadContext берёт их из текущего
//   состояния JIT, которое испортил x64-код обработчика (PF теряется). Ключ — RSP гостя: продолжение исключения
//   возвращается на тот же RSP; записи с RSP ниже текущего остались от раскрученных (longjmp/unwind) кадров.
static bool MREFlagsKeep() {
  // Без статической переменной с ленивой инициализацией: её страж в этом модуле не компонуется (ld.lld: misaligned
  // ldr/str offset). Путь исключений редкий — чтение окружения на каждый вызов ничего не стоит.
  const char* Value = getenv("MACRUNNER_FEX_EFLAGS_KEEP");
  return Value && Value[0] == '1' && !Value[1];
}

static void MRPushSavedEFlags(FEXCore::Core::InternalThreadState* Thread, uint64_t Rsp, uint32_t EFlags) {
  auto& Count = Thread->MRSavedEFlagsCount;
  constexpr uint64_t Capacity = sizeof(Thread->MRSavedEFlags) / sizeof(Thread->MRSavedEFlags[0]);
  if (Count == Capacity) {
    // Переполнение (очень глубокая вложенность): отбросить самую старую запись.
    for (uint64_t I = 1; I < Capacity; ++I) {
      Thread->MRSavedEFlags[I - 1] = Thread->MRSavedEFlags[I];
    }
    --Count;
  }
  Thread->MRSavedEFlags[Count++] = {Rsp, EFlags};
}

static bool MRPopSavedEFlags(FEXCore::Core::InternalThreadState* Thread, uint64_t Rsp, uint32_t* Out) {
  auto& Count = Thread->MRSavedEFlagsCount;
  while (Count && Thread->MRSavedEFlags[Count - 1].Rsp < Rsp) {
    --Count;
  }
  if (Count && Thread->MRSavedEFlags[Count - 1].Rsp == Rsp) {
    *Out = Thread->MRSavedEFlags[--Count].EFlags;
    return true;
  }
  return false;
}

static void ReconstructThreadState(FEXCore::Core::InternalThreadState* Thread, ARM64_NT_CONTEXT& Context,
                                   bool PublishedContinuation = false) {
  const auto& Config = SignalDelegator->GetConfig();
  auto& State = Thread->CurrentFrame->State;
  const uint64_t FaultPc = Context.Pc;

  if (!PublishedContinuation) {
    State.rip = CTX->RestoreRIPFromHostPC(Thread, Context.Pc);
  }

  // Spill all SRA GPRs
  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    State.gregs[i] = Context.X[Config.SRAGPRMapping[i]];
  }

  // Spill all SRA FPRs
  for (size_t i = 0; i < Config.SRAFPRCount; i++) {
    memcpy(State.xmm.sse.data[i], &Context.V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
  }

  // Spill EFlags
  const bool StaticBank = Thread->X87Cache.Live || Thread->X87Cache.FlushActive;
  if (Thread->X87Cache.FlushActive) Context.Cpsr = uint32_t(Thread->X87Cache.SavedNZCV);
  if (StaticBank) Context.Fpsr = Thread->X87Cache.SavedFPSR;
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, true, Context.X, Context.Cpsr);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
  static_assert(sizeof(Context.V[0]) == sizeof(__uint128_t));
  const auto Cached = FEXCore::Core::X87Region::Materialize(Thread->CurrentFrame, Context.Pc, Context.X,
      reinterpret_cast<const __uint128_t*>(Context.V));
  if (Cached.State != FEXCore::Core::X87Region::Status::Failed &&
      !FEXCore::Core::X87Static::MaterializeHost(Thread->CurrentFrame, reinterpret_cast<const __uint128_t*>(Context.V))) __fastfail(7);
  if (Cached.State == FEXCore::Core::X87Region::Status::Failed) __fastfail(7); // FAST_FAIL_FATAL_APP_EXIT
  if (Cached.State == FEXCore::Core::X87Region::Status::Present || StaticBank) {
    EFlags = (EFlags & ~Cached.EFlagsMask) | Cached.EFlagsValue;
    CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);
    Context.Pc = Config.AbsoluteLoopTopAddressFillSRA;
    Context.X11 = 0; // ENTRY_FILL_SRA_SINGLE_INST_REG == TMP2 on ARM64EC.
  } else if (MRX87FaultState) {
    // Every caller leaves the block (exception delivery or a dispatcher restart), so CPUState may take the pending x87 state.
    FEXCore::Core::X87Fault::Materialize(Thread->CurrentFrame, FaultPc, Context.X, reinterpret_cast<const __uint128_t*>(Context.V),
                                         Context.Sp);
  }
}

// Reconstructs an x64 context from the input thread's state, packed into a regular ARM64 context following the ARM64EC register mapping
static ARM64_NT_CONTEXT StoreStateToPackedECContext(FEXCore::Core::InternalThreadState* Thread, uint32_t FPCR, uint32_t FPSR) {
  ARM64_NT_CONTEXT ECContext {};

  ECContext.ContextFlags = CONTEXT_ARM64_FULL;
  if (CPUFeatures->IsFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE)) {
    // This is a FEX extension and requires corresponding wine-side patches to be of use, however it is harmless to set
    // even if those patches are not used.
    ECContext.ContextFlags |= CONTEXT_ARM64_FEX_YMMSTATE;
  }

  auto& State = Thread->CurrentFrame->State;

  ECContext.X8 = State.gregs[FEXCore::X86State::REG_RAX];
  ECContext.X0 = State.gregs[FEXCore::X86State::REG_RCX];
  ECContext.X1 = State.gregs[FEXCore::X86State::REG_RDX];
  ECContext.X27 = State.gregs[FEXCore::X86State::REG_RBX];
  ECContext.Sp = State.gregs[FEXCore::X86State::REG_RSP];
  ECContext.Fp = State.gregs[FEXCore::X86State::REG_RBP];
  ECContext.X25 = State.gregs[FEXCore::X86State::REG_RSI];
  ECContext.X26 = State.gregs[FEXCore::X86State::REG_RDI];
  ECContext.X2 = State.gregs[FEXCore::X86State::REG_R8];
  ECContext.X3 = State.gregs[FEXCore::X86State::REG_R9];
  ECContext.X4 = State.gregs[FEXCore::X86State::REG_R10];
  ECContext.X5 = State.gregs[FEXCore::X86State::REG_R11];
  ECContext.X19 = State.gregs[FEXCore::X86State::REG_R12];
  ECContext.X20 = State.gregs[FEXCore::X86State::REG_R13];
  ECContext.X21 = State.gregs[FEXCore::X86State::REG_R14];
  ECContext.X22 = State.gregs[FEXCore::X86State::REG_R15];

  ECContext.Pc = State.rip;

  CTX->ReconstructXMMRegisters(Thread, reinterpret_cast<__uint128_t*>(&ECContext.V[0]), reinterpret_cast<__uint128_t*>(&ECContext.V[16]));

  const unsigned Top = (MRWinctxExact || MRX87Context) ? State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] & 7 : 0;
  const auto ST = [&](unsigned I) { return State.mm[(Top + I) & 7]; };
  ECContext.Lr = ST(0)[0];
  ECContext.X6 = ST(1)[0];
  ECContext.X7 = ST(2)[0];
  ECContext.X9 = ST(3)[0];
  ECContext.X16 = (ST(3)[1] & 0xffff) << 48 | (ST(2)[1] & 0xffff) << 32 | (ST(1)[1] & 0xffff) << 16 | (ST(0)[1] & 0xffff);
  ECContext.X10 = ST(4)[0];
  ECContext.X11 = ST(5)[0];
  ECContext.X12 = ST(6)[0];
  ECContext.X15 = ST(7)[0];
  ECContext.X17 = (ST(7)[1] & 0xffff) << 48 | (ST(6)[1] & 0xffff) << 32 | (ST(5)[1] & 0xffff) << 16 | (ST(4)[1] & 0xffff);

  // Zero all disallowed registers
  ECContext.X13 = 0;
  ECContext.X14 = 0;
  ECContext.X18 = 0;
  ECContext.X23 = 0;
  ECContext.X24 = 0;
  ECContext.X28 = 0;

  // NZCV+SS will be converted into EFlags by ntdll, the rest are lost during exception handling.
  // See HandleGuestException
  uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  ECContext.Cpsr = 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_TF_RAW_LOC)) ? (1U << 21) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_OF_RAW_LOC)) ? (1U << 28) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_CF_RAW_LOC)) ? (1U << 29) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_ZF_RAW_LOC)) ? (1U << 30) : 0;
  ECContext.Cpsr |= (EFlags & (1U << FEXCore::X86State::RFLAG_SF_RAW_LOC)) ? (1U << 31) : 0;

  ECContext.Fpcr = FPCR;
  ECContext.Fpsr = FPSR;
  if (MRWinctxExact) MRDebugPack(ECContext);
  if (FEXCore::LazyMXCSR::Enabled.load(std::memory_order_relaxed)) {
    // LAZY-FLAGS: the captured host FPSR is the guest SSE status accumulator (ARM64EC ABI:
    // Wine fpcsr_to_mxcsr). Add any shadow-held status; host IDC is not a guest DE source.
    ECContext.Fpsr = (FPSR & ~0x80U) | FEXCore::LazyMXCSR::ToFPSRWithDE(Thread->CurrentFrame->State.mxcsr & 0x3FU);
  } else if (MRMxcsrFlagsEnabled) {
    const uint32_t Flags = Thread->CurrentFrame->State.mxcsr & 0x3FU;
    // Exact inverse of Wine unwind.h:fpcsr_to_mxcsr for the six status bits.
    // Replace host status, rather than ORing potentially unrelated host IXC.
    ECContext.Fpsr = (Flags & 1U) | ((Flags & 2U) << 6) | ((Flags & 0x3CU) >> 1);
  }
  if ((MRMxcsrFlagsEnabled && MRMxcsrContextControlEnabled) || MacRunnerAppleAFPEnabled) {
      const uint32_t Mxcsr = Thread->CurrentFrame->State.mxcsr;
      // Packed EC context is a transport, not a hardware FPCR restore. Match
      // Wine unwind.h:mxcsr_to_fpcsr, including its independent DAZ/FZ bits.
      // The executable host FPCR cannot represent every guest control mode.
      ECContext.Fpcr = ((Mxcsr & 0x40U) << 13) | ((Mxcsr & 0x80U) ? 0U : 0x100U) |
                       ((Mxcsr & 0x100U) ? 0U : 0x8000U) | ((Mxcsr & 0x200U) ? 0U : 0x200U) |
                       ((Mxcsr & 0x400U) ? 0U : 0x400U) | ((Mxcsr & 0x800U) ? 0U : 0x800U) |
                       ((Mxcsr & 0x1000U) ? 0U : 0x1000U) | ((Mxcsr & 0x2000U) << 10) |
                       ((Mxcsr & 0x4000U) << 8) | ((Mxcsr & 0x8000U) << 9);
  }

  return ECContext;
}

// ★ MacRunner Opus 19.09.2026 — стек ГОСТЯ при обращении к нулевой странице.
// Падение Elden Ring 0x141E880FD (mov rax,[rcx+0x18] с rcx=0x20): у функции 98 мест вызова,
// winedbg на ARM64-хосте x64-стек не разбирает, а к сигнальному обработчику Wine доходит
// стек эмулятора, не гостя. Здесь x64-состояние уже восстановлено (Args->Context, раскладка
// ARM64EC: X8=RAX X0=RCX X1=RDX X27=RBX Sp=RSP Fp=RBP X25=RSI X26=RDI X2=R8 X3=R9 X19..X22=R12..R15).
// Читаем только [RSP, StackBase) из TEB — занятая часть стека потока. Не больше 16 раз за процесс.
static void MacRunnerLogNullPageFault(const EXCEPTION_RECORD& Rec, const ARM64_NT_CONTEXT& Ec) {
  static std::atomic<uint32_t> Count {0};
  if (Rec.ExceptionCode != EXCEPTION_ACCESS_VIOLATION || Rec.NumberParameters < 2 || Rec.ExceptionInformation[1] >= 0x10000) {
    return;
  }
  if (Count.fetch_add(1, std::memory_order_relaxed) >= 16) {
    return;
  }
  const auto* Tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
  const uint64_t Low = reinterpret_cast<uint64_t>(Tib->StackLimit);
  const uint64_t High = reinterpret_cast<uint64_t>(Tib->StackBase);
  const uint64_t Tid = GetCurrentThreadId();
  char Line[768];
  auto Emit = [&](size_t Size) {
    Line[std::min<size_t>(Size, sizeof(Line) - 1)] = 0;
    FEX::Windows::Logging::Raw(Line);
  };
  Emit(fmt::format_to_n(Line, sizeof(Line) - 1,
                        "macrunner-fex-nullfault: tid={:x} rip={:x} fault={:x} rax={:x} rcx={:x} rdx={:x} rbx={:x} rsp={:x} rbp={:x} "
                        "rsi={:x} rdi={:x} r8={:x} r9={:x} r12={:x} r13={:x} r14={:x} r15={:x} stack=[{:x},{:x})\n",
                        Tid, Ec.Pc, Rec.ExceptionInformation[1], Ec.X8, Ec.X0, Ec.X1, Ec.X27, Ec.Sp, Ec.Fp, Ec.X25, Ec.X26, Ec.X2, Ec.X3,
                        Ec.X19, Ec.X20, Ec.X21, Ec.X22, Low, High)
         .size);
  const uint64_t Rsp = Ec.Sp;
  if (Rsp < Low || Rsp >= High || (Rsp & 7)) {
    Emit(fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-nullfault-stack: tid={:x} rsp outside thread stack\n", Tid).size);
    return;
  }
  const auto* Words = reinterpret_cast<const uint64_t*>(Rsp);
  const uint64_t Available = (High - Rsp) / 8;
  for (uint64_t Row = 0; Row < 8 && Row * 8 + 8 <= Available; ++Row) {
    const auto* W = Words + Row * 8;
    Emit(fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-nullfault-stack: tid={:x} rsp+{:03x}: {:x} {:x} {:x} {:x} {:x} {:x} {:x} {:x}\n",
                          Tid, Row * 64, W[0], W[1], W[2], W[3], W[4], W[5], W[6], W[7])
           .size);
  }
  // Кандидаты в адреса возврата: слова стека внутри образа eldenring.exe [0x140000000, 0x146000000).
  unsigned Found = 0;
  for (uint64_t I = 0; I < Available && I < 0x1000 && Found < 32; ++I) {
    const uint64_t V = Words[I];
    if (V >= 0x140001000 && V < 0x146000000) {
      Emit(fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-nullfault-ret: tid={:x} rsp+{:x}={:x}\n", Tid, I * 8, V).size);
      ++Found;
    }
  }
}

static void RethrowGuestException(const EXCEPTION_RECORD& Rec, ARM64_NT_CONTEXT& Context) {
  const auto& Config = SignalDelegator->GetConfig();
  auto* Thread = GetCPUArea().ThreadState();
  auto& Fault = Thread->CurrentFrame->SynchronousFaultData;
  uint64_t GuestSp = Context.X[Config.SRAGPRMapping[static_cast<size_t>(FEXCore::X86State::REG_RSP)]];
  auto* Args = reinterpret_cast<KiUserExceptionDispatcherStackLayout*>(FEXCore::AlignDown(GuestSp, 64)) - 1;
  if (MRWinctxExact || MRX87Context) {
    Args = &(reinterpret_cast<MRWinctxDispatcherLayout*>(FEXCore::AlignDown(GuestSp, 64)) - 1)->Base;
  }

  LogMan::Msg::DFmt("Reconstructing context");
  if (!IsDispatcherAddress(Context.Pc)) {
    ReconstructThreadState(Thread, Context);
  }
  // Native Windows 2022/2025 without an attached debugger: services
  // 1/3/4/5 complete at I+3 without guest VEH/SEH/UEF delivery.
  auto& State = Thread->CurrentFrame->State;
  const uint64_t ServiceRax = State.gregs[FEXCore::X86State::REG_RAX];
  if (FEX::Windows::MRInt2DWindowsEnabled && Fault.FaultToTopAndGeneratedException &&
      Fault.Signal == FEXCore::Core::FAULT_SIGSEGV && Fault.TrapNo == FEXCore::X86State::X86_TRAPNO_GP &&
      (Fault.err_code & 2) && (Fault.err_code >> 3) == 0x2d &&
      (ServiceRax == 1 || ServiceRax == 3 || ServiceRax == 4 || ServiceRax == 5)) {
    if (FEX::Windows::MRJournal::On && FEX::Windows::MRJournal::ExcOriginOn) {
      const uint64_t Bits = (static_cast<uint64_t>(Fault.Signal) & 0xffff) |
                            ((static_cast<uint64_t>(Fault.TrapNo) & 0xffff) << 16) |
                            (static_cast<uint64_t>(static_cast<uint32_t>(Fault.err_code)) << 32);
      FEX::Windows::MRJournal::WriteOrigin(3, 3, Bits, State.rip, ServiceRax, FEX::Windows::MRJournal::NextSerial());
    }
    Fault.FaultToTopAndGeneratedException = false;
    State.rip += 3;
    auto CPUArea = GetCPUArea();
    Context.Pc = CPUArea.DispatcherLoopTopEnterECFillSRA();
    Context.Sp = CPUArea.EmulatorStackBase();
    Context.X11 = 0;
    Context.X17 = reinterpret_cast<uint64_t>(CPUArea.Area);
    return;
  }
  Args->Context = StoreStateToPackedECContext(Thread, Context.Fpcr, Context.Fpsr);
  LogMan::Msg::DFmt("pc: {:X} rip: {:X}", Context.Pc, Args->Context.Pc);
  MacRunnerLogNullPageFault(Rec, Args->Context);

  // X64 Windows always clears TF, DF and AF when handling an exception, restoring after.
  // Current ARM64EC windows can only restore NZCV+SS when returning from an exception and other flags are left untouched from the handler context.
  // TODO: Can extend wine to support this by mapping the remaining EFlags into reserved cpsr members.
  const uint32_t GuestEFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  uint32_t EFlags = GuestEFlags;
  if (MREFlagsKeep()) {
    MRPushSavedEFlags(Thread, GuestSp, EFlags);
  }
  EFlags &= ~(1 << FEXCore::X86State::RFLAG_TF_RAW_LOC);
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);

  if (MRWinctxExact) MRDebugWord(MR_WINCTX_DEBUG_RF_PENDING_OFFSET) = 0;
  uint64_t OriginPc {}, OriginRax {}, OriginFaultBits {};
  uint32_t OriginKind {}, OriginFlags {};
  if (FEX::Windows::MRJournal::On && FEX::Windows::MRJournal::ExcOriginOn) {
    OriginPc = Args->Context.Pc; OriginRax = Args->Context.X8;
    OriginFlags = Fault.FaultToTopAndGeneratedException ? 1 : 0;
    OriginFaultBits = (static_cast<uint64_t>(Fault.Signal) & 0xffff) |
                      ((static_cast<uint64_t>(Fault.TrapNo) & 0xffff) << 16) |
                      (static_cast<uint64_t>(static_cast<uint32_t>(Fault.err_code)) << 32);
    if (OriginFlags && Fault.Signal == FEXCore::Core::FAULT_SIGTRAP && Fault.TrapNo == FEXCore::X86State::X86_TRAPNO_BP) OriginKind = 1;
    else if (OriginFlags && Fault.Signal == FEXCore::Core::FAULT_SIGSEGV && Fault.TrapNo == FEXCore::X86State::X86_TRAPNO_GP && (Fault.err_code & 2)) {
      const auto Vector = Fault.err_code >> 3;
      OriginKind = Vector == 3 ? 2 : Vector == 0x2d ? 3 : 4;
    }
  }
  Args->Rec = FEX::Windows::HandleGuestException(Fault, Rec, Args->Context.Pc, Args->Context.X8, Args->Context.X0);
  if (Args->Rec.ExceptionCode == EXCEPTION_SINGLE_STEP) {
    Args->Context.Cpsr &= ~(1 << 21); // PSTATE.SS
  } else if (Args->Rec.ExceptionCode == EXCEPTION_BREAKPOINT) {
    // INT3 will set RIP to the instruction following it, undo this (any edge cases with multibyte instructions that trigger breakpoints are bugs present in Windows also)
    Args->Context.Pc -= 1;
  }

  if (!MRWinctxExact && MRX87Context) {
    // x87 words only (FLOAT): EFlags and every other group keep their native conversion; MxCsr is the value Wine derives
    // from this context's FPCR/FPSR without a tail.
    auto* WithTail = reinterpret_cast<MRWinctxDispatcherLayout*>(Args);
    MRStoreWinctxTail(Thread, Args->Context, WithTail->Tail, false);
    WithTail->Tail.valid = MR_WINCTX_VALID_FLOAT;
    WithTail->Tail.eflags = 0;
    WithTail->Tail.mxcsr = MRFpcsrToMxcsr(Args->Context.Fpcr, Args->Context.Fpsr);
    MRX87PushDelivered(Thread, Args->Context.Sp);
  }
  if (MRWinctxExact) {
    auto* Exact = reinterpret_cast<MRWinctxDispatcherLayout*>(Args);
    // RF belongs to hardware faults, not breakpoint/single-step traps.
    const bool ResumeFlag = Args->Rec.ExceptionCode != EXCEPTION_BREAKPOINT && Args->Rec.ExceptionCode != EXCEPTION_SINGLE_STEP;
    MRStoreWinctxTail(Thread, Args->Context, Exact->Tail, ResumeFlag);
    Exact->Tail.eflags = GuestEFlags | (ResumeFlag ? 0x10000U : 0U);
    if (Args->Rec.ExceptionCode == EXCEPTION_SINGLE_STEP) Exact->Tail.eflags &= ~0x100U;
  }

  if (FEX::Windows::MRJournal::On) {
    const uint32_t JSerial = FEX::Windows::MRJournal::NextSerial();
    if (auto* JData = GetFrontendThreadData(Thread)) JData->JournalSerial = JSerial;
    if (FEX::Windows::MRJournal::ExcOriginOn) FEX::Windows::MRJournal::WriteOrigin(OriginKind, OriginFlags, OriginFaultBits, OriginPc, OriginRax, JSerial);
    FEX::Windows::MRJournal::WriteExc(Args->Rec, FEX::Windows::MRJournal::ThreadView {Thread}, JSerial, true);
    if (Args->Rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && Args->Rec.NumberParameters >= 1 && Args->Rec.ExceptionInformation[0] == 8) FEX::Windows::MRJournal::Mark("NOEXEC", Args->Rec.ExceptionCode, true);
  }
  Context.Sp = reinterpret_cast<uint64_t>(Args);
  Context.Pc = KiUserExceptionDispatcher;
}

class ECSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  ECSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    ProcessPendingCrossProcessEmulatorWork();

    // Manually raise an exeption with the current JIT state packed into a native context, ntdll handles this and
    // reenters the JIT (see dlls/ntdll/signal_arm64ec.c in wine).
    uint64_t FPCR, FPSR;
    __asm volatile("mrs %[fpcr], fpcr" : [fpcr] "=r"(FPCR));
    __asm volatile("mrs %[fpsr], fpsr" : [fpsr] "=r"(FPSR));

    auto* Thread = GetCPUArea().ThreadState();
    if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::NoteMxcsr(Thread, 3);
    if (MRWinctxExact) {
      MRWinctxDispatcherLayout Exact {};
      Exact.Base.Context = StoreStateToPackedECContext(Thread, static_cast<uint32_t>(FPCR), static_cast<uint32_t>(FPSR));
      Exact.Base.Rec.ExceptionCode = STATUS_EMULATION_SYSCALL;
      Exact.Base.Context.Pc += 2;
      MRStoreWinctxTail(Thread, Exact.Base.Context, Exact.Tail, false);
      JumpSetStack(KiUserExceptionDispatcher, reinterpret_cast<uintptr_t>(&Exact));
    }
    KiUserExceptionDispatcherStackLayout DispatchArgs {
      .Context = StoreStateToPackedECContext(Thread, static_cast<uint32_t>(FPCR), static_cast<uint32_t>(FPSR)),
      .Rec = {.ExceptionCode = STATUS_EMULATION_SYSCALL}};
    // PC is expected to hold the return address after the thunk, so skip over the INT 2E/SYSCALL instruction.
    DispatchArgs.Context.Pc += 2;
    JumpSetStack(KiUserExceptionDispatcher, reinterpret_cast<uintptr_t>(&DispatchArgs));
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

  bool InvalidateGuestCallTargetPatch(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    InvalidationTracker->InvalidateCallTargetPatch(Start, Length);
    return true;
  }

  void MarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->MarkRange(Start, Length);
  }

  void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->UnmarkRange(Start, Length);
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    return InvalidationTracker->QueryExecutableRange(Address);
  }

  void PreCompile() override {
    ProcessPendingCrossProcessEmulatorWork();
  }

  // ★ MacRunner (HG2, MACRUNNER_FEX_HOOK_GUARD): области компиляции и смены буфера кода (Core.cpp); при выключенном гейте Enter/Leave возвращаются сразу.
  void EnterRuntimeSection(RuntimeSection Section) override {
    FEX::Windows::HookGuard::Enter(Section == RuntimeSection::Compile ? FEX::Windows::HookGuard::Path::Compile : FEX::Windows::HookGuard::Path::ClearCodeCache);
  }
  void LeaveRuntimeSection(RuntimeSection Section) override {
    FEX::Windows::HookGuard::Leave(Section == RuntimeSection::Compile ? FEX::Windows::HookGuard::Path::Compile : FEX::Windows::HookGuard::Path::ClearCodeCache);
  }
};
} // namespace Exception

extern "C" void SyncThreadContext(CONTEXT* Context) {
  ProcessPendingCrossProcessEmulatorWork();
  auto* Thread = GetCPUArea().ThreadState();
  // All other EFlags bits are lost when converting to/from an ARM64EC context, so merge them in from the current JIT state.
  // This is advisable over dropping their values as thread suspend/resume uses this function, and that can happen at any point in guest code.
  static constexpr uint32_t ECValidEFlagsMask {(1U << FEXCore::X86State::RFLAG_OF_RAW_LOC) | (1U << FEXCore::X86State::RFLAG_CF_RAW_LOC) |
                                               (1U << FEXCore::X86State::RFLAG_ZF_RAW_LOC) | (1U << FEXCore::X86State::RFLAG_SF_RAW_LOC) |
                                               (1U << FEXCore::X86State::RFLAG_TF_RAW_LOC)};

  uint32_t StateEFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  if (Exception::MREFlagsKeep()) {
    uint32_t Saved;
    if (Exception::MRPopSavedEFlags(Thread, Context->Rsp, &Saved)) {
      StateEFlags = Saved;
    }
  }
  const bool ExactControl = Exception::MRWinctxExact && (Context->ContextFlags & MR_WINCTX_ARM_FLAG);
  Context->ContextFlags &= ~MR_WINCTX_ARM_FLAG;
  if (!ExactControl) {
    Context->EFlags = (Context->EFlags & ECValidEFlagsMask) | (StateEFlags & ~ECValidEFlagsMask);
  }
  if (Exception::MRWinctxExact && !ExactControl &&
      (Context->ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
    // A native ARM context has no x87 group. Wine's native converter clears
    // those AMD64 bytes, which is absence, not a requested x87 reset. Keep
    // the guest-owned group while importing the represented native vectors.
    // Explicit AMD64 edits arrive through the exact tail or pending FP carrier.
    ARM64_NT_CONTEXT Native {};
    mr_winctx_tail Tail {};
    Exception::MRStoreWinctxTail(Thread, Native, Tail, false);
    Context->FltSave.ControlWord = Tail.fcw;
    Context->FltSave.StatusWord = Tail.fsw;
    Context->FltSave.TagWord = Tail.ftw;
    const unsigned Top = (Tail.fsw >> 11) & 7;
    for (unsigned I = 0; I < 8; ++I) {
      memcpy(&Context->FltSave.FloatRegisters[I], Thread->CurrentFrame->State.mm[(Top + I) & 7], 10);
    }
  }
  if (Exception::MRWinctxExact && ExactControl && GetCPUArea().Area &&
      (Context->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
    auto& Skip = Exception::MRDebugWord(MR_WINCTX_DEBUG_SKIP_RIP_OFFSET);
    if (Skip && Context->Rip != Skip) Skip = 0; // explicit continuation elsewhere
  }
  mrj_ctx64 JBefore;
  const uint32_t JFlags = Context->ContextFlags;
  if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::Snapshot(JBefore, Thread);
  Exception::LoadStateFromECContext(Thread, *Context, ExactControl || !Exception::MRSuspendX87MetadataEnabled);
  if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::ApplyDone(JBefore, *Context, JFlags, Thread);
  if (Exception::MRWinctxExact) MacRunnerWinctxApplyPendingFP();
  if (FEXCore::LazyMXCSR::Enabled.load(std::memory_order_relaxed) &&
      (Context->ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
    // LAZY-FLAGS seed: BeginSimulation enters the JIT right after this call. The applied
    // context decides the status (a handler that cleared MxCsr flags clears them here).
    auto& Mxcsr = Thread->CurrentFrame->State.mxcsr;
    const uint64_t Fpsr = FEXCore::LazyMXCSR::ToFPSR(Mxcsr);
    Mxcsr &= ~0x3DU;
    __asm__ __volatile__("msr fpsr, %0" : : "r"(Fpsr) : "memory");
  }
}

// Called only by the single-instruction IR builder after SRA spill.
// It does not allocate, raise an exception, or leave a guarded compiler frame.
// The normal Break IR executes after compiler/dispatcher guards have unwound.
extern "C" bool MacRunnerWinctxDebugActive(FEXCore::Core::CpuStateFrame* Frame) {
  if (!Exception::MRWinctxExact || !Frame || GetCPUArea().ThreadState() != Frame->Thread) return false;
  const auto* Debug = Exception::MRDebugState();
  return Exception::MRDebugValid(Debug) && (Debug->dr[5] & 0xff);
}

extern "C" bool MacRunnerWinctxExecuteBreakpoint(FEXCore::Core::CpuStateFrame* Frame, uint64_t Rip) {
  if (!Exception::MRWinctxExact || !Frame || GetCPUArea().ThreadState() != Frame->Thread) return false;
  auto* Debug = Exception::MRDebugState();
  // DIAGNOSTIC_ONLY: <=16 compiler-entry records per owned process.
  static std::atomic_uint DiagnosticEntries {0};
  if (DiagnosticEntries.fetch_add(1, std::memory_order_relaxed) < 16) {
    char Message[320];
    std::snprintf(Message, sizeof(Message), "MRDR105 HOOK rip=%llx valid=%u dr0=%llx dr7=%llx rf=%u\n",
      static_cast<unsigned long long>(Rip), static_cast<unsigned>(Exception::MRDebugValid(Debug)),
      static_cast<unsigned long long>(Debug ? Debug->dr[0] : 0),
      static_cast<unsigned long long>(Debug ? Debug->dr[5] : 0),
      static_cast<unsigned>(Frame->State.flags[FEXCore::X86State::RFLAG_RF_LOC]));
    FEX::Windows::Logging::Raw(Message);
  }
  if (!Exception::MRDebugValid(Debug)) return false;
  auto& Skip = Exception::MRDebugWord(MR_WINCTX_DEBUG_SKIP_RIP_OFFSET);
  auto& RFPending = Exception::MRDebugWord(MR_WINCTX_DEBUG_RF_PENDING_OFFSET);
  if (RFPending) {
    // Reaching this next compiler entry means the prior single instruction
    // completed. A fault cancels this marker in HandleGuestException.
    Frame->State.flags[FEXCore::X86State::RFLAG_RF_LOC] = 0;
    RFPending = 0;
  }
  if (Frame->State.flags[FEXCore::X86State::RFLAG_RF_LOC]) {
    RFPending = 1;
    return false;
  }
  if (Skip == Rip) {
    Skip = 0;
    return false;
  }
  uint64_t Matched = 0;
  const uint64_t DR7 = Debug->dr[5];
  for (unsigned Slot = 0; Slot < 4; ++Slot) {
    const auto Enabled = (DR7 >> (Slot * 2)) & 3;
    const auto RWLength = (DR7 >> (16 + Slot * 4)) & 15;
    if (Enabled && RWLength == 0 && Debug->dr[Slot] == Rip) Matched |= uint64_t{1} << Slot;
  }
  if (!Matched) return false;
  Debug->dr[4] = (Debug->dr[4] & ~uint64_t{15}) | 0xffff0ff0U | Matched;
  Skip = Rip; // Windows dispatch context clears RF; resume suppresses this fault once.
  return true;
}

extern "C" uint32_t MacRunnerWinctxCurrentFCW() {
  if (!Exception::MRWinctxExact) return UINT32_MAX;
  const auto CPUArea = GetCPUArea();
  if (!CPUArea.Area || !CPUArea.ThreadState()) return UINT32_MAX;
  return CPUArea.ThreadState()->CurrentFrame->State.FCW;
}

extern "C" uint32_t MacRunnerWinctxCurrentMXCSR() {
  if (!Exception::MRWinctxExact) return UINT32_MAX;
  const auto CPUArea = GetCPUArea();
  if (!CPUArea.Area || !CPUArea.ThreadState()) return UINT32_MAX;
  return CPUArea.ThreadState()->CurrentFrame->State.mxcsr;
}

// X87-CTX (MACRUNNER_FEX_X87_CONTEXT=1, non-exact), called by Wine's ARM64EC ntdll. Op 0: key on?  1: CONTEXT x87 part <-
// thread state (NtGetContextThread).  2: thread state <- CONTEXT x87 part (NtSetContextThread).  3: NtContinue/NtContinueEx
// of this thread (see MRX87Continue). Thread: a handle of a thread of this process, or the current-thread pseudo handle.
extern "C" uint32_t MacRunnerX87Context(HANDLE ThreadHandle, CONTEXT* Context, uint32_t Op) {
  if (!Exception::MRX87Context || Exception::MRWinctxExact) return 0;
  if (Op == 0) return 1;
  if (!Context || Op > 3) return 0;
  ThreadCPUArea CPUArea = GetCPUArea();
  if (ThreadHandle != GetCurrentThread()) {
    THREAD_BASIC_INFORMATION Info;
    if (NtQueryInformationThread(ThreadHandle, ThreadBasicInformation, &Info, sizeof(Info), nullptr) || !Info.TebBaseAddress ||
        reinterpret_cast<uintptr_t>(Info.ClientId.UniqueProcess) != GetCurrentProcessId()) return 0;
    CPUArea = ThreadCPUArea(reinterpret_cast<_TEB*>(Info.TebBaseAddress));
  }
  auto* Thread = CPUArea.Area ? CPUArea.ThreadState() : nullptr;
  if (!Thread || !Thread->CurrentFrame) return 0;
  switch (Op) {
  case 1: Exception::MRX87ToContext(Thread, *Context); return 1;
  case 2: Exception::MRX87FromContext(Thread, *Context); return 1;
  default: return Thread == GetCPUArea().ThreadState() ? Exception::MRX87Continue(Thread, *Context) : 0;
  }
}

extern "C" uint64_t MacRunnerWinctxCurrentRSP() {
  if (!Exception::MRWinctxExact) return 0;
  const auto CPUArea = GetCPUArea();
  if (!CPUArea.Area || !CPUArea.ThreadState()) return 0;
  // Live SRA registers need not be spilled to CPUState at an EC exit. The
  // assembly exit records the actual guest SP before consuming its return.
  return *reinterpret_cast<const uint64_t*>(reinterpret_cast<const uint8_t*>(CPUArea.Area) + MR_WINCTX_GUEST_ENTRY_RSP_OFFSET);
}

extern "C" uint32_t MacRunnerWinctxCaptureFP(mr_winctx_fp_snapshot* Snapshot, uint32_t Size) {
  static_assert(sizeof(mr_winctx_fp_snapshot) == 144);
  if (!Exception::MRWinctxExact || !Snapshot || Size != sizeof(*Snapshot)) return 0;
  const auto CPUArea = GetCPUArea();
  if (!CPUArea.Area || !CPUArea.ThreadState()) return 0;
  auto* Thread = CPUArea.ThreadState();
  const auto& State = Thread->CurrentFrame->State;
  // Reuse the exception serializer, including all sticky/condition x87 bits.
  // These are stack-local objects, with no allocation or loader lookup.
  ARM64_NT_CONTEXT Native {};
  mr_winctx_tail Tail {};
  Exception::MRStoreWinctxTail(Thread, Native, Tail, false);
  *Snapshot = {};
  Snapshot->mxcsr = Tail.mxcsr;
  Snapshot->fcw = Tail.fcw;
  Snapshot->fsw = Tail.fsw;
  Snapshot->ftw = Tail.ftw;
  // MacRunner CLAUDE-EXC 0112: EFlags гостя на входе в родной вызов — в зарезервированных байтах снимка (reserved[0..3], признак в reserved[4]);
  // потребитель — PE-ntdll под MACRUNNER_SETJMP_EXACT=1 (DF/AC при longjmp/RtlUnwindEx, полные флаги в RtlCaptureContext). Размер и раскладка снимка прежние.
  { const uint32_t GuestEFlags = Tail.eflags; memcpy(Snapshot->reserved, &GuestEFlags, sizeof(GuestEFlags)); Snapshot->reserved[4] = 1; }
  if (FEX::Windows::MRJournal::On) { uint8_t JSt[8][10]; const unsigned JTop = (Tail.fsw >> 11) & 7; for (unsigned I = 0; I < 8; ++I) memcpy(JSt[I], State.mm[(JTop + I) & 7], 10); FEX::Windows::MRJournal::WriteGetFP(Tail.mxcsr, Tail.fcw, Tail.fsw, Tail.ftw, JSt, FEX::Windows::MRJournal::ThreadView {Thread}); }
  const unsigned Top = (Tail.fsw >> 11) & 7;
  for (unsigned I = 0; I < 8; ++I) memcpy(Snapshot->x87[I], State.mm[(Top + I) & 7], 10);
  return 1;
}

extern "C" void MacRunnerWinctxApplyPendingFP(uint8_t* SavedEntry, bool NativeReturn) {
  if (!Exception::MRWinctxExact) return;
  const auto CPUArea = GetCPUArea();
  if (!CPUArea.Area || !CPUArea.ThreadState()) return;
  auto* PendingNV = reinterpret_cast<mr_winctx_nv_return*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_NV_RETURN_OFFSET);
  static_assert(sizeof(mr_winctx_nv_return) == 192);
  static_assert(MR_WINCTX_DEBUG_RF_PENDING_OFFSET + sizeof(uint64_t) <= MR_WINCTX_NV_RETURN_OFFSET);
  static_assert(MR_WINCTX_NV_RETURN_OFFSET + sizeof(mr_winctx_nv_return) < 0xf00);
  if (!SavedEntry) {
    // A direct guest-PC continuation bypasses the old native entry frame.
    __atomic_store_n(&PendingNV->valid, 0, __ATOMIC_RELEASE);
  } else if (NativeReturn && __atomic_load_n(&PendingNV->valid, __ATOMIC_ACQUIRE) &&
             PendingNV->magic == MR_WINCTX_NV_RETURN_MAGIC &&
             PendingNV->version == MR_WINCTX_VERSION && PendingNV->size == sizeof(*PendingNV)) {
    uint64_t EntrySP;
    memcpy(&EntrySP, SavedEntry + 656, sizeof(EntrySP));
    const auto* Tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
    const auto Limit = reinterpret_cast<uint64_t>(Tib->StackLimit);
    const auto Base = reinterpret_cast<uint64_t>(Tib->StackBase);
    // A nested native callback has a lower SP. Leave the outer continuation
    // pending until its native frame unwinds back toward the guest caller.
    if (PendingNV->native_sp >= Limit && PendingNV->native_sp <= EntrySP && EntrySP <= Base) {
      const auto Groups = __atomic_exchange_n(&PendingNV->valid, 0, __ATOMIC_ACQUIRE);
      if (Groups & MR_WINCTX_NV_INTEGER) memcpy(SavedEntry + 128, &PendingNV->rbp, sizeof(PendingNV->rbp));
      for (unsigned I = 0; I < 10; ++I) {
        if (!(Groups & (2U << I))) continue;
        const unsigned Offset = I < 2 ? 240 + I * 16 : 528 + (I - 2) * 16;
        memcpy(SavedEntry + Offset, PendingNV->xmm[I], 16);
      }
    }
  }
  auto* Shadow = reinterpret_cast<mr_winctx_fp_shadow*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_FP_SHADOW_OFFSET);
  static_assert(sizeof(mr_winctx_fp_shadow) == 416);
  static_assert(MR_WINCTX_FP_SHADOW_OFFSET + sizeof(mr_winctx_fp_shadow) < 0x1000);
  if (Shadow->magic != MR_WINCTX_FP_SHADOW_MAGIC || Shadow->version != MR_WINCTX_VERSION || Shadow->size != sizeof(*Shadow)) return;
  const auto Valid = __atomic_exchange_n(&Shadow->valid, 0, __ATOMIC_ACQUIRE);
  if (!(Valid & MR_WINCTX_VALID_FLOAT)) return;

  const auto Thread = CPUArea.ThreadState();
  CONTEXT FPContext {};
  alignas(16) __uint128_t Low[16], High[16];
  CTX->ReconstructXMMRegisters(Thread, Low, High);
  FPContext.ContextFlags = CONTEXT_FLOATING_POINT;
  FPContext.MxCsr = FPContext.FltSave.MxCsr = Shadow->mxcsr;
  FPContext.FltSave.ControlWord = Shadow->fcw;
  FPContext.FltSave.StatusWord = Shadow->fsw;
  FPContext.FltSave.TagWord = Shadow->ftw;
  memcpy(FPContext.FltSave.FloatRegisters, Shadow->x87, sizeof(Shadow->x87));
  memcpy(FPContext.FltSave.XmmRegisters, Low, sizeof(Low));
  // Import only virtual FP state. Native continuation's RIP/GPRs/NZCV and
  // the live EC XMM registers continue through their existing entry path.
  Exception::LoadStateFromECContext(Thread, FPContext);
  if (Valid & MR_WINCTX_VALID_YMM) memcpy(High, Shadow->ymm, sizeof(High));
  CTX->SetXMMRegistersFromState(Thread, Low, High);
  static unsigned Observed;
  if (__atomic_fetch_add(&Observed, 1, __ATOMIC_RELAXED) < 16) {
    char Message[128];
    snprintf(Message, sizeof(Message), "mr-winctx-native-fp-import: valid=%u cw=%04x sw=%04x tw=%02x\n", Valid, Shadow->fcw, Shadow->fsw, Shadow->ftw);
    FEX::Windows::Logging::Raw(Message);
  }
}

NTSTATUS ProcessInit() {
  InitSyscalls();

  FEX::Windows::InitCRTProcess();
  if (const char* EcExit = getenv("MACRUNNER_FEX_EC_EXIT_DISPATCH"); EcExit && EcExit[0] == '1' && !EcExit[1]) {
    MacRunnerEcExitDispatch = 1;
  }
  const char* WinctxExact = getenv("MACRUNNER_WINCTX_EXACT");
  Exception::MRWinctxExact = WinctxExact && WinctxExact[0] == '1' && !WinctxExact[1];
  MacRunnerWinctxExactMode = Exception::MRWinctxExact;
  const char* MxcsrFlags = getenv("MACRUNNER_FEX_MXCSR_FLAGS");
  Exception::MRMxcsrFlagsEnabled = MxcsrFlags && MxcsrFlags[0] == '1' && !MxcsrFlags[1];
  const char* MxcsrContextControl = getenv("MACRUNNER_FEX_MXCSR_CONTEXT_CONTROL");
  Exception::MRMxcsrContextControlEnabled = MxcsrContextControl && MxcsrContextControl[0] == '1' && !MxcsrContextControl[1];
  const char* SuspendBackedge = getenv("MACRUNNER_FEX_SUSPEND_BACKEDGE64");
  Exception::MRSuspendX87MetadataEnabled =
    SuspendBackedge && (SuspendBackedge[0] == '1' || SuspendBackedge[0] == '2') && !SuspendBackedge[1];
  const char* X87Context = getenv("MACRUNNER_FEX_X87_CONTEXT");
  Exception::MRX87Context = X87Context && X87Context[0] == '1' && !X87Context[1];
  const char* X87FaultState = getenv("MACRUNNER_FEX_X87_FAULT_STATE");
  Exception::MRX87FaultState = X87FaultState && X87FaultState[0] == '1' && !X87FaultState[1];
  FEX::Windows::MRJournal::Init(getenv("MACRUNNER_API_JOURNAL")); // полный журнал; без ключа ничего не делает
  const char* Int2DWindows=getenv("MACRUNNER_FEX_INT2D_WINDOWS");
  FEX::Windows::MRInt2DWindowsEnabled=Int2DWindows && Int2DWindows[0]=='1' && !Int2DWindows[1];
  const char* ExcOrigin=getenv("MACRUNNER_FEX_EXC_ORIGIN");
  FEX::Windows::MRJournal::ExcOriginOn=ExcOrigin && ExcOrigin[0]=='1' && !ExcOrigin[1];
  const auto ExecutablePath = FEX::Windows::GetExecutableFilePath();
  AppConfigName = FEX::Windows::BaseName(ExecutablePath);
  FEX::Config::LoadConfig(AppConfigName, _environ, FEX::ReadPortabilityInformation());
  FEXCore::Config::ReloadMetaLayer();
  FEX::Windows::Logging::Init();
  // Resolve the existing Raw path before guest execution; never in a handler.
  if (Exception::MRWinctxExact) FEX::Windows::Logging::Raw("MRDR105 PROCESS exact=1\n");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, ExecutablePath);
  FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, AppConfigName);

  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");

  FEXCore::Profiler::Init("", "");

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  SyscallHandler = fextl::make_unique<Exception::ECSyscallHandler>();

  const auto NtDll = GetModuleHandleW(L"ntdll.dll");
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");
  OvercommitTracker.emplace(IsWine);

  FEX::Windows::SetupEnvironmentVariableValues(NtDll);

  // ★★★ MacRunner N2b — тот же несущий порядок, что и в WOW64 (разбор там же).
  // Отличие ровно одно: ProcessInit здесь возвращает NTSTATUS, значит отказ можно
  // вернуть по-человечески, до создания CTX, — снимать процесс не требуется.
  const bool UnixLibReady = FEX::Windows::UnixLib::Init(NtDll);
  FEX::Windows::Allocator::SetupHooks(NtDll);

#ifdef FEX_WINE_DARWIN
  if (!UnixLibReady || !FEXCore::Allocator::EnableJITExec) {
    FEX::Windows::Logging::Raw(UnixLibReady ?
                                 "macrunner-fex-НЕТ-КЛЕЯ: ARM64EC — UnixLib ДА, крюк 7 НЕТ\n" :
                                 "macrunner-fex-НЕТ-КЛЕЯ: ARM64EC — UnixLib НЕТ\n");
    return STATUS_NOT_SUPPORTED;
  }
  FEXCore::Allocator::JITWriteThreadInit();
  FEX::Windows::UnixLib::InitializeHardwareTSO();
#else
  (void)UnixLibReady;
#endif

  {
    auto HostFeatures = FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine, FEXCore::HostFeatures::HostTypeEnum::Arm64ec);
    HostFeatures.SupportsAppleAFP = MacRunnerAppleAFPEnabled;
    if (FEXCore::HBX87::Stats::Enabled()) {
      FEX::Windows::Logging::Raw(HostFeatures.SupportsAtomics ?
        "[hb-x87-stats-init] advertised_lse=1\n" : "[hb-x87-stats-init] advertised_lse=0; use LL/SC\n");
    }
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
    if (MacRunnerHardwareTSOMode == 2) CTX->SetHardwareTSOSupport(true);
  }

  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore();
  Exception::HandlerConfig.emplace(*CTX);
  InvalidationTracker.emplace(*CTX, Threads);
  ImageTracker.emplace(*CTX, false);
  FEX::Windows::Logging::InitCoverage();

  auto MainModule = reinterpret_cast<__TEB*>(NtCurrentTeb())->Peb->ImageBaseAddress;
  HandleImageMap(reinterpret_cast<uint64_t>(MainModule), true);

  HandleImageMap(NtDllBase);

  CPUFeatures.emplace(*CTX);

  X64ReturnInstr = ::VirtualAlloc(nullptr, FEXCore::Utils::FEX_PAGE_SIZE, MEM_COMMIT | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
  InvalidationTracker->HandleMemoryProtectionNotification(reinterpret_cast<uint64_t>(X64ReturnInstr), FEXCore::Utils::FEX_PAGE_SIZE,
                                                          PAGE_EXECUTE_READ);
  *reinterpret_cast<uint8_t*>(X64ReturnInstr) = 0xc3;

  const uintptr_t KiUserExceptionDispatcherFFS = reinterpret_cast<uintptr_t>(GetProcAddress(NtDll, "KiUserExceptionDispatcher"));
  Exception::KiUserExceptionDispatcher = NtDllRedirectionLUT[KiUserExceptionDispatcherFFS - NtDllBase] + NtDllBase;
  {
    // ★ MacRunner SYNC: one marker per process, printed whatever the key (so a run proves which PAUSE it translated with)
    char Message[128];
    const char* Raw = getenv("MACRUNNER_FEX_PAUSE");
    snprintf(Message, sizeof(Message), "macrunner-fex-pause: key=%.16s isb=%u\n", Raw ? Raw : "unset", FEXCore::Utils::MacRunnerPauseIsbCount());
    FEX::Windows::Logging::Raw(Message);
  }
  MRQpcInlineInit(NtDll); // ★ MacRunner QPCJIT: key 0 returns at once

  FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
  FEX_CONFIG_OPT(StartupSleep, STARTUPSLEEP);
  FEX_CONFIG_OPT(StartupSleepProcName, STARTUPSLEEPPROCNAME);

  if (IsWine && ProfileStats()) {
    StatAllocHandler = fextl::make_unique<FEX::Windows::StatAlloc>(FEXCore::SHMStats::AppType::WIN_ARM64EC);
  }

  if (StartupSleep() && (StartupSleepProcName().empty() || AppConfigName == StartupSleepProcName())) {
    LogMan::Msg::IFmt("[{}][{}] Sleeping for {} seconds", GetCurrentProcessId(), AppConfigName, StartupSleep());
    std::this_thread::sleep_for(std::chrono::seconds(StartupSleep()));
  }

  return STATUS_SUCCESS;
}

void ProcessTerm(HANDLE Handle, BOOL After, NTSTATUS Status) {
  if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::Mark("TERM", static_cast<uint32_t>(Status), true);
  {
    static std::atomic_bool MRQpcReported {false};
    if (!MRQpcReported.exchange(true)) MRQpcInlineReport("process"); // ★ MacRunner QPCJIT (armed only)
  }
  FEXCore::HBX87::Stats::Dump();
}

class ScopedCallbackDisable {
private:
  bool Prev;

public:
  ScopedCallbackDisable() {
    const auto CPUArea = GetCPUArea();
    Prev = CPUArea.Area->InSyscallCallback;
    CPUArea.Area->InSyscallCallback = true;
  }

  ~ScopedCallbackDisable() {
    GetCPUArea().Area->InSyscallCallback = Prev;
  }
};

// Returns true if exception dispatch should be halted and the execution context restored to NativeContext
bool ResetToConsistentStateImpl(const ThreadCPUArea CPUArea, EXCEPTION_RECORD* Exception, CONTEXT* GuestContext, ARM64_NT_CONTEXT* NativeContext) {
  auto Thread = CPUArea.ThreadState();
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedSignalTime);
  LogMan::Msg::DFmt("Exception: Code: {:X} Address: {:X}", Exception->ExceptionCode, reinterpret_cast<uintptr_t>(Exception->ExceptionAddress));

  if (NativeContext->Pc == reinterpret_cast<uint64_t>(&ExitFunctionSuspendPoint)) {
    // A suspend interrupt can occur in ExitFunctionEC before InSimulation is unset and set SuspendDoorbell. If this
    // occurs then it is still our duty to cooperatively suspend with an appropriate context. To support this, after
    // unsetting InSimulation a brk #0xCAFE instruction will be raised that we can handle here.
    NativeContext->Pc = reinterpret_cast<uintptr_t>(&ExitFunctionSuspendResumePoint); // Jump to the suspend resume point.
    *CPUArea.Area->SuspendDoorbell = 0;
    if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::WriteAbsorb(4, 0, 0, 0, 0, 0);
    return true;
  }

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (FEX::Windows::CallRetStack::HandleAccessViolation(Thread, FaultAddress, NativeContext->X17, *CTX)) {
      if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::WriteAbsorb(5, FaultAddress, 0, 0, static_cast<uint32_t>(Exception->ExceptionInformation[0]), 0);
      return true;
    }

    if (FEX::Windows::JITGuardPage::HandleJITGuardPage(Thread, reinterpret_cast<void*>(FaultAddress), NativeContext->X,
                                                       reinterpret_cast<__uint128_t*>(NativeContext->V), &NativeContext->Pc)) {
      return true;
    }

    std::scoped_lock Lock(ThreadCreationMutex);
    FEX::Windows::MRJournal::CurAccess = Exception->ExceptionInformation[0];   // для записи 44 в HandleRWXAccessViolation (под ThreadCreationMutex)
    FEX::Windows::CallRetStack::BeginException(Thread);
    if (InvalidationTracker && InvalidationTracker->HandleRWXAccessViolation(Thread, NativeContext->Pc, FaultAddress)) {
      uint64_t ResetSP = 0;
      if (FEX::Windows::CallRetStack::TakePending(Thread, ResetSP) && CTX->IsAddressInCodeBuffer(Thread, NativeContext->Pc))
        NativeContext->X17 = ResetSP;
      FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
      ::MacRunnerJitSMC.fetch_add(1, std::memory_order_relaxed);
      if (CTX->IsAddressInCodeBuffer(Thread, NativeContext->Pc) && !CTX->IsCurrentBlockSingleInst(CPUArea.ThreadState()) &&
          CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEX::Windows::ProtectionPageMask, FEX::Windows::ProtectionPageSize)) {
        // If we are not patching ourself (single inst block case) and potentially patching the current block, this is inline SMC. Reconstruct the current context (before the SMC write) then single step the write to reduce it to regular SMC.
        Exception::ReconstructThreadState(Thread, *NativeContext);
        LogMan::Msg::DFmt("Handled inline self-modifying code: pc: {:X} rip: {:X} fault: {:X}", NativeContext->Pc,
                          Thread->CurrentFrame->State.rip, FaultAddress);
        NativeContext->Pc = CPUArea.DispatcherLoopTopEnterECFillSRA();
        NativeContext->Sp = CPUArea.EmulatorStackBase();
        NativeContext->X11 = 1;                                        // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
        NativeContext->X17 = reinterpret_cast<uint64_t>(CPUArea.Area); // Set EC_ENTRY_CPUAREA_REG
      } else {
        LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", NativeContext->Pc, FaultAddress);
      }

      return true;
    }
  }

  bool IsJIT = CTX->IsAddressInCodeBuffer(Thread, NativeContext->Pc);
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Exception::HandleUnalignedAccess(CPUArea, *NativeContext, IsJIT)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", NativeContext->Pc);
    if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::WriteAbsorb(7, Exception->ExceptionInformation[1], 0, 0, 0, 0);
    return true;
  }

  if (!IsJIT && !IsDispatcherAddress(NativeContext->Pc)) {
    LogMan::Msg::DFmt("Passing through exception");
    // MacRunner CLAUDE-EXC 0114 (только запись журнала): раньше все поля были нулями — не было видно ни адреса, ни гостевого RIP, ни родного PC при зацикливании «отказ -> пропуск -> повтор».
    if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::WriteAbsorb(9, Exception->NumberParameters >= 2 ? Exception->ExceptionInformation[1] : 0, Thread->CurrentFrame->State.rip,
                                                                      static_cast<uint32_t>(NativeContext->Pc), Exception->NumberParameters >= 1 ? static_cast<uint32_t>(Exception->ExceptionInformation[0]) : 0, 1);
    return false;
  }

  // The JIT (in CompileBlock) emits code to check the suspend doorbell at the start of every block, and run the following instruction if it is set:
  static constexpr uint32_t SuspendTrapMagic {0xD4395FC0}; // brk #0xCAFE
  static constexpr uint32_t SuspendContinuationMagic {0xD4395FA0}; // brk #0xCAFD
  const uint32_t Trap = Exception->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION
                          ? *reinterpret_cast<uint32_t*>(NativeContext->Pc) : 0;
  if (Exception->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION &&
      (Trap == SuspendTrapMagic || Trap == SuspendContinuationMagic)) {
    Exception::ReconstructThreadState(Thread, *NativeContext, Trap == SuspendContinuationMagic);
    *NativeContext = Exception::StoreStateToPackedECContext(Thread, NativeContext->Fpcr, NativeContext->Fpsr);
    LogMan::Msg::DFmt("Suspending: RIP: {:X} SP: {:X}", NativeContext->Pc, NativeContext->Sp);
    CPUArea.Area->InSimulation = 0;
    *CPUArea.Area->SuspendDoorbell = 0;
    return true;
  }

  if (IsEmulatorStackAddress(CPUArea, reinterpret_cast<uint64_t>(__builtin_frame_address(0)))) {
    Exception::RethrowGuestException(*Exception, *NativeContext);
    LogMan::Msg::DFmt("Rethrowing onto guest stack: {:X}", NativeContext->Sp);
    return true;
  } else {
    LogMan::Msg::EFmt("Unexpected exception in JIT code on guest stack");
    if (FEX::Windows::MRJournal::On) FEX::Windows::MRJournal::Mark("FATAL", Exception->ExceptionCode, true);
    return false;
  }
}

NTSTATUS ResetToConsistentState(EXCEPTION_RECORD* Exception, CONTEXT* GuestContext, ARM64_NT_CONTEXT* NativeContext) {
  bool Cont {};
  if (Exception::MRWinctxExact && Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && Exception->NumberParameters >= 2) {
    // A non-canonical guest address is a general-protection fault on x86: Windows reports {read, ~0}.
    const auto Address = static_cast<uint64_t>(Exception->ExceptionInformation[1]);
    const uint64_t Top = Address >> 47;
    if (Top != 0 && Top != 0x1ffff) {
      Exception->ExceptionInformation[0] = 0;
      Exception->ExceptionInformation[1] = ~static_cast<ULONG_PTR>(0);
    }
  }
  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (OvercommitTracker) {
      {
        ScopedCallbackDisable guard;
        Cont = OvercommitTracker->HandleAccessViolation(FaultAddress);
      }
      if (Cont) {
        // ★ MacRunner N2b — см. разбор в WOW64/Module.cpp: NtContinue не возвращается,
        // деструкторы скобки записи не отработают, режим восстанавливаем руками.
        FEXCore::Allocator::JITWriteResetForResume(true);
        NtContinueNative(NativeContext, false);
      }
    }
  }

  const auto CPUArea = GetCPUArea();
  if (!CPUArea.ThreadState()) {
    return STATUS_SUCCESS;
  }

  {
    ScopedCallbackDisable guard;
    Cont = ResetToConsistentStateImpl(CPUArea, Exception, GuestContext, NativeContext);
  }

  if (Cont) {
    // ★ MacRunner N2b — тот же договор на втором выходе через NtContinue.
    FEXCore::Allocator::JITWriteResetForResume(true);
    NtContinueNative(NativeContext, false);
  }

  CPUArea.Area->InSimulation = false;
  CPUArea.Area->InSyscallCallback = false;
  return STATUS_SUCCESS;
}

void NotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot, BOOL After, NTSTATUS Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Alloc)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
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

void NotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType, BOOL After, NTSTATUS Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Free)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
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

void NotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt, BOOL After, NTSTATUS Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Protect)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
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

NTSTATUS NotifyMapViewOfSection(void* Unk1, void* Address, void* Unk2, SIZE_T Size, ULONG AllocType, ULONG Prot) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Map)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return STATUS_SUCCESS;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return STATUS_SUCCESS;
  }

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    HandleImageMap(reinterpret_cast<uint64_t>(Address));
  }


  return STATUS_SUCCESS;
}

void NotifyUnmapViewOfSection(void* Address, BOOL After, NTSTATUS Status) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Unmap)) { // MACRUNNER_FEX_HOOK_GUARD (Allocator.h)
    return;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  if (!After) {
    ThreadCreationMutex.lock();
    auto [Start, Size] = InvalidationTracker->InvalidateContainingSection(reinterpret_cast<uint64_t>(Address), true);
    if (Size) {
      HandleImageUnmap(Start, Size);
    }
  } else {
    ThreadCreationMutex.unlock();
  }
}

void FlushInstructionCacheHeavy(const void* Address, SIZE_T Size) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Flush)) { // MACRUNNER_FEX_HOOK_GUARD (HG3): ClearICache самого FEX (делинкеры блоков в Erase)
    return;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpu64FlushInstructionCache(const void* Address, SIZE_T Size) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Flush)) { // MACRUNNER_FEX_HOOK_GUARD (HG3)
    return;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpu64NotifyMemoryDirty(void* Address, SIZE_T Size) {
  if (FEX::Windows::HookGuard::Suppress(FEX::Windows::HookGuard::Kind::Dirty)) { // MACRUNNER_FEX_HOOK_GUARD (HG3)
    return;
  }
  if (!InvalidationTracker || !GetCPUArea().ThreadState()) {
    return;
  }

  std::scoped_lock Lock(ThreadCreationMutex);
  InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
}

void BTCpu64NotifyReadFile(HANDLE Handle, void* Address, SIZE_T Size, BOOL After, NTSTATUS Status) {
  auto* ThreadState = GetCPUArea().ThreadState();
  if (!InvalidationTracker || !ThreadState) {
    return;
  }

  // On file read this can cause JIT code invalidations. FEX previously used to hold locks on `CodeInvalidationMutex` and `ThreadCreationMutex` while doing
  // this. This was a problem that file reads are blocking and may necessarily never return. A simple unit-test that holds a blocking read, and then tries
  // to create threads or JIT code would immediately hang.
  //
  // - PhysX msiexec installer (From Dishonored AppID 205100) did exactly this and hung forever.
  //
  // The alternative approach is to let the read progress as normal and only notify invalidation when the read actually returns. This introduces an
  // unavoidable race which by my logic is fine.
  //
  // 1) If a thread is already jitting code from the address range then in a "real" x86 environment it may see old, new, or a combination of data.
  //   - NtReadFile isn't guaranteed to return new data atomically, in order, or anything of the sort.
  // 2) The calling thread only ever sees the before code, and the after code because `NtReadFile` never leaves "kernel" space before invalidation.
  //
  // The only "gotcha" is that FEX could have write-protected the memory region when a JIT executed the code, and once the `NtReadFile` tries
  // returning data, it faults. This requires coordination between Wine and FEX in order to handle this edge case.
  //
  // Additionally, async reads are still completely untracked with invalidation, which never worked before anyway.
  // (upstream 179b4423a; MacRunner: the Wine side of the same blocking read is W1 of UPSTREAM-P1)

  if (AppConfigName == "P5R.exe") {
    // Use the locking mechanism for (Persona 5 Royal AppID 1687950) which does exactly the problem described above.
    auto& InLockedRWXRead = GetFrontendThreadData(ThreadState)->InLockedRWXRead;
    if (!After) {
      ThreadCreationMutex.lock();
      CTX->GetCodeInvalidationMutex().lock();
      if (InvalidationTracker->BeginUntrackedWriteLocked(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size))) {
        InLockedRWXRead = true;
      } else {
        CTX->GetCodeInvalidationMutex().unlock();
        ThreadCreationMutex.unlock();
      }
    } else {
      if (InLockedRWXRead) {
        InLockedRWXRead = false;
        CTX->GetCodeInvalidationMutex().unlock();
        ThreadCreationMutex.unlock();
      }
    }

    return;
  }

  if (After && Status == STATUS_SUCCESS) {
    std::scoped_lock Lock(ThreadCreationMutex);
    InvalidationTracker->InvalidateAlignedInterval(reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), false);
  }
}

NTSTATUS ThreadInit() {
  FEX::Windows::UnixLib::HardwareTSOThreadEnter(FEXHardwareTSOEntryKind::ARM64ECThreadInit);
  std::scoped_lock Lock(ThreadCreationMutex);
  FEX::Windows::InitCRTThread();
  // ★ MacRunner N2b — режим MAP_JIT потоковый, назначаем на каждом потоке FEX.
  // ★ ГРАНИЦА, названная вслух: у ARM64EC есть вход в JIT ПРЯМО из Module.S:39,52,
  // минуя ProcessInit/ThreadInit. Для таких потоков страховкой служит печать
  // `macrunner-fex-jitwrite-МИМО-INIT` в JITWriteEnter — она поймает их по факту.
  FEXCore::Allocator::JITWriteThreadInit();
  const auto CPUArea = GetCPUArea();

  static constexpr size_t EmulatorStackSize = 0x40000;
  const uint64_t EmulatorStack =
    reinterpret_cast<uint64_t>(::VirtualAlloc(nullptr, EmulatorStackSize, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE));
  CPUArea.EmulatorStackLimit() = EmulatorStack;
  CPUArea.EmulatorStackBase() = EmulatorStack + EmulatorStackSize;

  auto* Thread = CTX->CreateThread(0, 0);

  // Default segment setup.
  auto Frame = Thread->CurrentFrame;
  auto NewSegments = new FEXCore::Core::CPUState::gdt_segment[32];

  // Setup initial code-segment GDT
  auto& GDT = NewSegments[FEXCore::Core::CPUState::DEFAULT_USER_CS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
  GDT.L = 1; // L = Long Mode = 64-bit
  GDT.D = 0; // D = Default Operand SIze = Reserved

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &NewSegments[0];
  // TODO: LDTs are currently unsupported, mirror them to GDT.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &NewSegments[0];

  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  FEX::Windows::CallRetStack::InitializeThread(Thread);
  Thread->CurrentFrame->Pointers.ExitFunctionEC = reinterpret_cast<uintptr_t>(&ExitFunctionEC);
  CPUArea.StateFrame() = Thread->CurrentFrame;

  uint64_t EnterEC = Thread->CurrentFrame->Pointers.DispatcherLoopTopEnterEC;
  CPUArea.DispatcherLoopTopEnterEC() = EnterEC;

  uint64_t EnterECFillSRA = Thread->CurrentFrame->Pointers.DispatcherLoopTopEnterECFillSRA;
  CPUArea.DispatcherLoopTopEnterECFillSRA() = EnterECFillSRA;

  CPUArea.ContextAmd64() = {.ContextFlags = CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT,
                            .AMD64_SegCs = (FEXCore::Core::CPUState::DEFAULT_USER_CS << 3) | 3,
                            .AMD64_SegDs = 0x2b,
                            .AMD64_SegEs = 0x2b,
                            .AMD64_SegFs = 0x53,
                            .AMD64_SegGs = 0x2b,
                            .AMD64_SegSs = 0x2b,
                            .AMD64_EFlags = 0x202,
                            .AMD64_MxCsr = 0x1f80,
                            .AMD64_MxCsr_copy = 0x1f80,
                            .AMD64_ControlWord = 0x27f};
  Exception::LoadStateFromECContext(Thread, CPUArea.ContextAmd64().AMD64_Context);

  Thread->FrontendPtr = new FrontendThreadData();
  // Leave the cache empty until the first actual guest entry. This exercises
  // the same preserving guard used by a native entry that bypasses ThreadInit.

  {
    auto ThreadTID = GetCurrentThreadId();
    Threads.emplace(ThreadTID, Thread);
    if (StatAllocHandler) {
      Thread->ThreadStats = StatAllocHandler->AllocateSlot(ThreadTID);
    }
  }

  CPUArea.ThreadState() = Thread;
  if (Exception::MRWinctxExact) {
    auto* PendingNV = reinterpret_cast<mr_winctx_nv_return*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_NV_RETURN_OFFSET);
    __atomic_store_n(&PendingNV->valid, 0, __ATOMIC_RELEASE);
    __atomic_store_n(reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_NV_EDIT_MASK_OFFSET), 0, __ATOMIC_RELEASE);
    __atomic_store_n(reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_NV_EDIT_MASK_OFFSET), 0, __ATOMIC_RELEASE);
    Exception::MRDebugWord(MR_WINCTX_DEBUG_SKIP_RIP_OFFSET) = 0;
    Exception::MRDebugWord(MR_WINCTX_DEBUG_RF_PENDING_OFFSET) = 0;
    static_assert(MR_WINCTX_DEBUG_SKIP_RIP_OFFSET == MR_WINCTX_DEBUG_OFFSET + sizeof(mr_winctx_debug_state));
    static_assert(MR_WINCTX_DEBUG_RF_PENDING_OFFSET + sizeof(uint64_t) < MR_WINCTX_CLOSE_RETURN_PENDING_OFFSET);
    // Pull a pending Set from the server before the first guest instruction.
    // This is ThreadInit, never signal dispatch or first-use loader lookup.
    ARM64_NT_CONTEXT Debug {};
    Debug.ContextFlags = CONTEXT_ARM64_DEBUG_REGISTERS;
    const auto Status = NtGetContextThreadNative(GetCurrentThread(), &Debug);
    // DIAGNOSTIC_ONLY: normal ThreadInit, no stdio I/O or signal callbacks.
    static std::atomic_uint DiagnosticThreads {0};
    if (DiagnosticThreads.fetch_add(1, std::memory_order_relaxed) < 16) {
      auto* Before = Exception::MRDebugState();
      char Message[384];
      std::snprintf(Message, sizeof(Message), "MRDR105 INIT status=%lx flags=%lx marker=%x/%x/%x query_dr0=%llx query_dr7=%llx before_valid=%u before_dr7=%llx\n",
        static_cast<unsigned long>(Status), static_cast<unsigned long>(Debug.ContextFlags),
        static_cast<unsigned>(Debug.Bcr[0]), static_cast<unsigned>(Debug.Bcr[1]), static_cast<unsigned>(Debug.Bcr[2]),
        static_cast<unsigned long long>(Debug.Bvr[0]), static_cast<unsigned long long>(Debug.Bvr[5]),
        static_cast<unsigned>(Exception::MRDebugValid(Before)), static_cast<unsigned long long>(Before ? Before->dr[5] : 0));
      FEX::Windows::Logging::Raw(Message);
    }
    if (!Status && Debug.Bcr[0] == MR_WINCTX_DEBUG_ARM_MAGIC &&
        Debug.Bcr[1] == MR_WINCTX_DEBUG_VERSION && Debug.Bcr[2] == sizeof(mr_winctx_debug_state))
      Exception::MRDebugPublish(Debug.Bvr);
  }
  CPUArea.Area->SuspendDoorbell = reinterpret_cast<ULONG*>(&Thread->CurrentFrame->SuspendDoorbell);
  if (Exception::MRWinctxExact) {
    auto* Query = reinterpret_cast<mr_winctx_fp_query*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_FP_QUERY_OFFSET);
    static_assert(sizeof(mr_winctx_fp_query) == 48);
    static_assert(MR_WINCTX_FP_QUERY_OFFSET == MR_WINCTX_FP_SHADOW_OFFSET + sizeof(mr_winctx_fp_shadow));
    static_assert(MR_WINCTX_FP_QUERY_OFFSET + sizeof(mr_winctx_fp_query) < 0x1000);
    Query->size = sizeof(*Query);
    Query->version = MR_WINCTX_FP_QUERY_VERSION;
    Query->capabilities = MR_WINCTX_CAP_MISALIGNED_SSE;
    Query->current_fcw = reinterpret_cast<uint64_t>(&MacRunnerWinctxCurrentFCW);
    Query->current_mxcsr = reinterpret_cast<uint64_t>(&MacRunnerWinctxCurrentMXCSR);
    Query->capture_fp = reinterpret_cast<uint64_t>(&MacRunnerWinctxCaptureFP);
    Query->current_rsp = reinterpret_cast<uint64_t>(&MacRunnerWinctxCurrentRSP);
    static_assert(MR_WINCTX_GUEST_ENTRY_RSP_OFFSET == MR_WINCTX_FP_QUERY_OFFSET + sizeof(mr_winctx_fp_query));
    static_assert(MR_WINCTX_GUEST_ENTRY_RSP_OFFSET + sizeof(uint64_t) < 0xf00);
    *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_GUEST_ENTRY_RSP_OFFSET) = 0;
    static_assert(MR_WINCTX_GUEST_ENTRY_TARGET_OFFSET == MR_WINCTX_GUEST_ENTRY_RSP_OFFSET + sizeof(uint64_t));
  static_assert(MR_WINCTX_GUEST_ENTRY_XMM_OFFSET >= MR_WINCTX_DEBUG_RF_PENDING_OFFSET + sizeof(uint64_t) && MR_WINCTX_GUEST_ENTRY_XMM_OFFSET + 6 * 16 <= 0xb00); // 0114: слот XMM0-5 (Module.S ExitFunctionEC)
    *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_GUEST_ENTRY_TARGET_OFFSET) = 0;
    *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_CLOSE_RETURN_PENDING_OFFSET) = 0;
    *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(CPUArea.Area) + MR_WINCTX_RETURN_FLAGS_READY_OFFSET) = 0;
    __atomic_store_n(&Query->magic, MR_WINCTX_FP_QUERY_MAGIC, __ATOMIC_RELEASE);
  }
  return STATUS_SUCCESS;
}

NTSTATUS ThreadTerm(HANDLE Thread, LONG ExitCode) {
  if (FEXCore::Utils::MRQpcInline::G.Armed) {
    MRQpcInlinePeriodic(); // ★ QPCJIT (throttled)
  }
  if (!FEX::Windows::ValidateHandleAccess(Thread, THREAD_TERMINATE)) {
    return STATUS_ACCESS_DENIED;
  }

  auto ThreadDup = FEX::Windows::DupHandle(Thread, THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME);

  THREAD_BASIC_INFORMATION Info;
  if (auto Err = NtQueryInformationThread(*ThreadDup, ThreadBasicInformation, &Info, sizeof(Info), nullptr); Err) {
    return Err;
  }

  const auto ThreadTID = reinterpret_cast<uint64_t>(Info.ClientId.UniqueThread);
  bool Self = ThreadTID == GetCurrentThreadId();
  if (!Self) {
    CONTEXT TmpContext;
    // If we are suspending a thread that isn't ourselves, try to suspend it first so we know internal JIT locks aren't being held.
    NtSuspendThread(*ThreadDup, NULL);
    // This will wait for the thread to be suspended
    NtGetContextThread(*ThreadDup, &TmpContext);
  }

  const auto [Err, CPUArea] = GetThreadCPUArea(*ThreadDup);
  if (Err) {
    return Err;
  }

  {
    std::scoped_lock Lock(ThreadCreationMutex);
    auto it = Threads.find(ThreadTID);
    if (it == Threads.end()) {
      // Thread already terminated
      return STATUS_SUCCESS;
    }

    Threads.erase(it);
    if (StatAllocHandler) {
      StatAllocHandler->DeallocateSlot(CPUArea.ThreadState()->ThreadStats);
    }
  }
  auto ThreadState = CPUArea.ThreadState();

  delete GetFrontendThreadData(ThreadState);

  // GDT and LDT are mirrored, only free one.
  delete[] ThreadState->CurrentFrame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT];

  FEX::Windows::CallRetStack::DestroyThread(ThreadState);
  CTX->DestroyThread(ThreadState);
  ::VirtualFree(reinterpret_cast<void*>(CPUArea.EmulatorStackLimit()), 0, MEM_RELEASE);
  if (ThreadTID == GetCurrentThreadId()) {
    FEX::Windows::DeinitCRTThread();
  }

  return STATUS_SUCCESS;
}

BOOLEAN BTCpu64IsProcessorFeaturePresent(UINT Feature) {
  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

void UpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info) {
  CPUFeatures->UpdateInformation(Info);
}

// Marker: this module contains the DF write-through change (patch 0103); lets `strings` identify the loaded file.
extern "C" __attribute__((used)) const char MacRunnerDfWriteThrough0103[] = "macrunner-df-write-through-0103";

#include "Common/MacRunnerJournalImpl.inc"
