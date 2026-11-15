// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <optional>

#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/fextl/string.h>

namespace FEXCore::Context {
class Context;
}

namespace FEXCore::Core {
struct InternalThreadState;
struct CpuStateFrame;
} // namespace FEXCore::Core

namespace FEXCore::HLE {
struct SyscallArguments {
  static constexpr std::size_t MAX_ARGS = 7;
  uint64_t Argument[MAX_ARGS];
};

struct SyscallABI {
  // Expectation is that the backend will be aware of how to modify the arguments based on numbering
  // Only GPRs expected
  uint8_t NumArgs;
  // If the syscall has a return then it should be stored in the ABI specific syscall register
  // Linux = RAX
  bool HasReturn;

  int32_t HostSyscallNumber;
};

enum class SyscallOSABI {
  OS_UNKNOWN,
  OS_LINUX64,
  OS_LINUX32,
  OS_GENERIC, // No JIT-side argument handling, spill/fill all regs.
};

struct ExecutableRangeInfo {
  uint64_t Base;
  uint64_t Size;
  bool Writable;
  // ★ MacRunner (30.09.2026, MACRUNNER_FEX_ALIAS_VIEWS): writable code that page protection CANNOT watch — an executable view of a
  //   section (the RX half of a W^X double mapping). Its bytes change through ANOTHER view of the same pages, which neither the
  //   protection of this view nor a write fault can see, so the range must be validated always: validation modes 2/3 must not skip
  //   it as "whole host pages under the write trap", and the decoder's cached range (MACRUNNER_FEX_RANGE_CACHE) must not carry it.
  bool NoTrap = false;
};

class SyscallHandler;
class SourcecodeResolver;

class SyscallHandler {
public:
  virtual ~SyscallHandler() = default;

  virtual uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) = 0;

  SyscallOSABI GetOSABI() const {
    return OSABI;
  }
  virtual void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {}
  virtual void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {}
  // ★ MacRunner (MACRUNNER_FEX_MONO_BP_PRECISE): точный сброс для заплатки адреса вызова. false — не поддержано,
  //   вызывающий идёт обычным InvalidateGuestCodeRange.
  virtual bool InvalidateGuestCallTargetPatch(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
    return false;
  }
  // ★ REGION4 (MACRUNNER_FEX32_IMPORT_BIND): true + the bytes iff [Address, Address + Size) lies in one read-only, non-executable
  //   image page AND the frontend from now on invalidates every translation registered on that page (AddBlockExecutableRange)
  //   when the page stops being read-only or goes away. Called by the decoder under the compile's shared CodeInvalidationMutex.
  virtual bool QueryGuestConstantData(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint32_t Size, void* Out) {
    return false;
  }
  virtual void MarkOvercommitRange(uint64_t Start, uint64_t Length) {}
  virtual void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) {}
  virtual ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) = 0;
  virtual std::optional<ExecutableFileSectionInfo> LookupExecutableFileSection(Core::InternalThreadState* Thread, uint64_t GuestAddr) = 0;

  virtual void PreCompile() {}

  // ★ MacRunner (HG2, 30.09.2026, MACRUNNER_FEX_HOOK_GUARD): области среды выполнения FEX, внутри которых поток держит CodeInvalidationMutex (ЭТИМ или общим) и выделяет
  //   и освобождает СВОЮ память: компиляция блока/одиночного шага и смена буфера кода. Windows-обработчики поднимают на них HookGuard (Source/Windows/Common/Allocator.h):
  //   иначе хук NotifyMemory* из аллокатора FEX просит ЭКСКЛЮЗИВНЫЙ замок под своим же общим (повышение) — та же самоблокировка, что у инвалидации. По умолчанию ничего не делают.
  enum class RuntimeSection : uint32_t { Compile, ClearCodeCache };
  virtual void EnterRuntimeSection(RuntimeSection Section) {}
  virtual void LeaveRuntimeSection(RuntimeSection Section) {}

  virtual SourcecodeResolver* GetSourcecodeResolver() {
    return nullptr;
  }

  virtual void SleepThread(FEXCore::Context::Context* CTX, FEXCore::Core::CpuStateFrame* Frame) {}

  // ★ MacRunner NATIVE32 (13.11.2026, MACRUNNER_FEX32_NATIVE32): read guest DATA at translation time without the risk of a host
  //   fault (the import slot of `call [disp32]`). false = not readable / not supported: the decoder then translates the call as
  //   before. Default: not supported (stands and other frontends never fold through a slot).
  virtual bool MRReadGuestData(uint64_t Address, void* Out, size_t Size) {
    return false;
  }
  // ★ MacRunner NATIVE32: the frontend runs real guest images (their bytes and their import slots are what executes). Only then does
  //   the decoder look for marked leaves at all. Default: no -- replay / stand frontends answer executable-range queries from a
  //   recording (a query for a call target is a miss there and the page is not mapped: caught 13.11, SIGBUS in the RATIO4 replay).
  virtual bool MRNative32Supported() const {
    return false;
  }
  // ★ MacRunner NATIVE32-0005: the address of export <Name> of the 32-bit image that contains AddressInModule, or 0 (not an image,
  //   not found, forwarded, unreadable). A hint only: every use verifies the bytes at the address (mark + leaf body, write-trapped).
  virtual uint64_t MRFindGuestExport(uint64_t AddressInModule, const char* Name) {
    return 0;
  }

protected:
  SyscallOSABI OSABI;
};
} // namespace FEXCore::HLE
