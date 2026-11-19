// SPDX-License-Identifier: MIT
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/SharedCodeBufferManager.h"

#include <FEXCore/fextl/memory.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/MacRunnerXfer.h>
#include "Interface/Core/CPUBackend.h"

#ifndef _WIN32
#include <FEXCore/Utils/PrctlUtils.h>
#endif

namespace FEXCore::CPU {
static constexpr size_t INITIAL_CODE_SIZE = 1024 * 1024 * 16;
// We don't want to move above 128MB atm because that means we will have to encode longer jumps
static constexpr size_t MAX_CODE_SIZE = 1024 * 1024 * 128;

CodeBuffer::CodeBuffer(size_t Size)
  : AllocatedSize(Size) {
  Ptr = static_cast<uint8_t*>(FEXCore::Allocator::VirtualAlloc(Size, true));
  LOGMAN_THROW_A_FMT(!!Ptr, "Couldn't allocate code buffer");

  // Protect the last page of the allocated buffer to trigger SIGSEGV on write access
  const auto GuardSize = FEXCore::Utils::JITGuardPageSize();
  uintptr_t LastPageAddr = reinterpret_cast<uintptr_t>(Ptr) + Size - GuardSize;
  if (!FEXCore::Allocator::VirtualProtect(reinterpret_cast<void*>(LastPageAddr), GuardSize,
                                          FEXCore::Allocator::ProtectOptions::None)) {
    LogMan::Msg::EFmt("Failed to mprotect last page of code buffer.");
  }

  FEXCore::Allocator::VirtualName("FEXMemJIT", Ptr, Size);

  // Huge-pages reduce the amount of iTLB misses dramatically when it works.
  FEXCore::Allocator::VirtualTHPControl(Ptr, Size, FEXCore::Allocator::THPControl::Enable);

  LookupCache = fextl::make_unique<GuestToHostMap>();
  if (FEXCore::Utils::MacRunnerHeaderByPCMode()) {
    // ★ MacRunner FEXXFER: one entry per 64 bytes is more than any unit count (a unit is header + code + tail + RIP entries).
    MRUnitCapacity = Size / 64 + 1;
    MRUnitBegins = static_cast<uint32_t*>(FEXCore::Allocator::VirtualAlloc(MRUnitCapacity * sizeof(uint32_t), false));
    if (!MRUnitBegins) {
      MRUnitCapacity = 0;
    }
  }
}

void CodeBuffer::MRRecordUnit(uint64_t Offset) {
  const size_t N = MRUnitCount.load(std::memory_order_relaxed);
  if (!MRUnitBegins || N >= MRUnitCapacity || Offset >= AllocatedSize || (Offset & 15) ||
      (N && (uint64_t(MRUnitBegins[N - 1]) << 4) >= Offset)) {
    return;   // writers hold CodeBufferWriteMutex; out-of-order or overflow entries are dropped (the reader then finds no unit)
  }
  MRUnitBegins[N] = static_cast<uint32_t>(Offset >> 4);
  MRUnitCount.store(N + 1, std::memory_order_release);
}

uint64_t CodeBuffer::MRFindUnit(uintptr_t Address) const {
  const auto Base = reinterpret_cast<uintptr_t>(Ptr);
  if (!MRUnitBegins || Address < Base || Address >= Base + AllocatedSize) {
    return 0;
  }
  const uint64_t Off = Address - Base;
  size_t Lo = 0, Hi = MRUnitCount.load(std::memory_order_acquire);
  while (Lo < Hi) {   // first entry whose begin is > Off
    const size_t Mid = Lo + (Hi - Lo) / 2;
    if ((uint64_t(MRUnitBegins[Mid]) << 4) <= Off) {
      Lo = Mid + 1;
    } else {
      Hi = Mid;
    }
  }
  if (!Lo) {
    return 0;
  }
  const uint64_t Begin = Base + (uint64_t(MRUnitBegins[Lo - 1]) << 4);
  const auto* Header = reinterpret_cast<const CPUBackend::JITCodeHeader*>(Begin);
  const auto* Tail = reinterpret_cast<const CPUBackend::JITCodeTail*>(Begin + Header->OffsetToBlockTail);
  return Address < Begin + Tail->Size ? Begin : 0;
}

CodeBuffer::~CodeBuffer() {
  if (MRUnitBegins) {
    FEXCore::Allocator::VirtualFree(MRUnitBegins, MRUnitCapacity * sizeof(uint32_t));
  }
  FEXCore::Allocator::VirtualFree(Ptr, AllocatedSize);
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::AllocateNew(size_t Size) {
#ifndef _WIN32
  // MDWE (Memory-Deny-Write-Execute) is a new Linux 6.3 feature.
  // It's equivalent to systemd's `MemoryDenyWriteExecute` but implemented entirely in the kernel.
  //
  // MDWE prevents applications from creating RWX memory mappings.
  // This prevents FEX from doing anything JIT related, as FEX uses RWX for JIT memory mappings.
  //
  // A potential workaround to make FEX work with MDWE is to call mprotect every time we need to write or modify code.
  // Alternatively, FEX could use a memory mirror where one half is mapped as RW and the other is RX.
  //
  // Once MDWE is enabled with the prctl, the feature is sealed and it can /NOT/ be turned off.
  //
  // Status of MDWE is queried through prctl using `PR_GET_MDWE`:
  // -1: The kernel doesn't support MDWE
  // 0: MDWE is supported but disabled
  // >0: MDWE is enabled, hence prohibiting RWX mappings
  int MDWE = ::prctl(PR_GET_MDWE, 0, 0, 0, 0);
  if (MDWE != -1 && MDWE != 0) {
    LogMan::Msg::EFmt("MDWE was set to 0x{:x} which means FEX can't allocate executable memory", MDWE);
  }
#endif

  if (const size_t TestBytes = FEXCore::Utils::MacRunnerCodeBufTestBytes()) {
    Size = TestBytes;   // CALLRET4 test key MACRUNNER_FEX_CODEBUF_TEST_MB
  }
  auto Buffer = fextl::make_shared<CodeBuffer>(Size);

  Latest = Buffer;
  LatestOffset = 0;

  OnCodeBufferAllocated(Buffer);

  return Buffer;
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::GetLatest() {
  if (!Latest) {
    AllocateNew(INITIAL_CODE_SIZE);
  }
  return Latest;
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartLargerCodeBuffer() {
  if (!Latest) {
    // Allocate initial CodeBuffer and return it
    return GetLatest();
  }

  auto NewCodeBufferSize = GetLatest()->AllocatedSize;
  NewCodeBufferSize = std::min<size_t>(NewCodeBufferSize * 2, MAX_CODE_SIZE);
  return AllocateNew(NewCodeBufferSize);
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartMaximalCodeBuffer() {
  return AllocateNew(MAX_CODE_SIZE);
}
} // namespace FEXCore::CPU
