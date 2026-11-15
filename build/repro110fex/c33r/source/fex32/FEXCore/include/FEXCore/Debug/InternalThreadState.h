// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/vector.h>

#include <cstddef>
#include <cstdint>
#include <shared_mutex>
#include <type_traits>

namespace FEXCore {
class LookupCache;
struct JITSymbolBuffer;
} // namespace FEXCore

namespace FEXCore::Context {
class Context;
}

namespace FEXCore::CPU {
class CPUBackend;
} // namespace FEXCore::CPU

namespace FEXCore::Frontend {
class Decoder;
}

namespace FEXCore::IR {
class OpDispatchBuilder;
class PassManager;
} // namespace FEXCore::IR

namespace FEXCore::SHMStats {
struct ThreadStats;
};

namespace FEXCore::Core {

// Special-purpose replacement for std::unique_ptr to allow InternalThreadState to be standard layout.
// Since a NonMovableUniquePtr is neither copyable nor movable, its only function is to own and release the contained object.
template<typename T>
struct NonMovableUniquePtr {
  NonMovableUniquePtr() noexcept = default;
  NonMovableUniquePtr(const NonMovableUniquePtr&) = delete;
  NonMovableUniquePtr& operator=(const NonMovableUniquePtr& UPtr) = delete;

  NonMovableUniquePtr& operator=(fextl::unique_ptr<T> UPtr) noexcept {
    Ptr = UPtr.release();
    return *this;
  }

  ~NonMovableUniquePtr() {
    fextl::default_delete<T> {}(Ptr);
  }

  T* operator->() const noexcept {
    return Ptr;
  }

  std::add_lvalue_reference_t<T> operator*() const noexcept {
    return *Ptr;
  }

  T* get() const noexcept {
    return Ptr;
  }

  explicit operator bool() const noexcept {
    return Ptr != nullptr;
  }

private:
  T* Ptr = nullptr;
};
static_assert(!std::is_move_constructible_v<NonMovableUniquePtr<int>>);
static_assert(!std::is_move_assignable_v<NonMovableUniquePtr<int>>);

// Store used for unaligned LDAXR*/STLXR* emulation.
struct UnalignedExclusiveStore {
  uint64_t Addr;
  uint64_t Store;
  uint8_t Size;
};

struct alignas(FEXCore::Utils::FEX_PAGE_SIZE) InternalThreadState : public FEXCore::Allocator::FEXAllocOperators {
  FEXCore::Core::CpuStateFrame* const CurrentFrame = &BaseFrameState;

  FEXCore::Context::Context* const CTX;

  NonMovableUniquePtr<FEXCore::IR::OpDispatchBuilder> OpDispatcher;

  NonMovableUniquePtr<FEXCore::CPU::CPUBackend> CPUBackend;
  NonMovableUniquePtr<FEXCore::LookupCache> LookupCache;

  NonMovableUniquePtr<FEXCore::Frontend::Decoder> FrontendDecoder;
  NonMovableUniquePtr<FEXCore::IR::PassManager> PassManager;
  NonMovableUniquePtr<JITSymbolBuffer> SymbolBuffer;

  // This pointer is owned by the frontend.
  FEXCore::SHMStats::ThreadStats* ThreadStats {};

  UnalignedExclusiveStore ExclusiveStore;

  ///< Data pointer for exclusive use by the frontend
  void* FrontendPtr;

  static constexpr size_t CALLRET_STACK_SIZE {0x400000};

  // The low address of the call-ret stack allocation (not including guard pages)
  void* CallRetStackBase {};

  uintptr_t JITGuardPage {};
  uint64_t JITGuardOverflowArgument {};
  FEXCore::UncheckedLongJump::JumpBuf RestartJump;

  // BaseFrameState should always be at the end, directly before the interrupt fault page
  FEXCore::Core::CpuStateFrame BaseFrameState {};

  // Can be reprotected as RO to trigger an interrupt at generated code block entrypoints
  alignas(FEXCore::Utils::FEX_PAGE_SIZE) uint8_t InterruptFaultPage[FEXCore::Utils::FEX_PAGE_SIZE];

  // ★ MacRunner (MACRUNNER_FEX_EFLAGS_KEEP): полные EFlags гостя на момент доставки исключения — стек по вложенности,
  //   ключ — RSP гостя; SyncThreadContext возвращает из него PF/AF/DF после обработчика (так делает Prism).
  struct MRSavedEFlagsEntry {
    uint64_t Rsp;
    uint32_t EFlags;
  };
  // Стоит ПОСЛЕ InterruptFaultPage: вставка в середину сдвигала смещения полей, которые код читает командами с
  // масштабированным смещением (ld.lld: misaligned ldr/str offset).
  alignas(16) MRSavedEFlagsEntry MRSavedEFlags[8] {};
  uint64_t MRSavedEFlagsCount {};
  uint64_t MRSavedEFlagsPad {};

  // Explicit PE32 bank backing. Keep every existing Frame/Thread offset;
  // WOW59's isolated interrupt page precedes this cache. Native/EC page
  // protection is not made correct by this tail field.
  struct alignas(16) X87StaticCache {
    uint64_t Values[8] {};
    uint8_t FormatMask {};
    uint8_t DirtyMask {};
    uint8_t Precision {};
    uint8_t Live {};
    uint64_t SavedNZCV {};
    uint8_t FlushActive {};
    uint32_t SavedFPSR {};
    uint32_t ObservedFPSR {};
  } X87Cache {};

  // TRANS32 MACRUNNER_FEX32_X87_PC_EXACT (Interface/Core/HBX87PCX.h): block-local boxes of x87 values outside the
  // double container. Tail field: every existing Frame/Thread offset is kept.
  struct alignas(16) X87PCXBoxes {
    uint64_t Slot[4096][2] {}; // HBX87PCX.h BoxSlots
    uint32_t Next {};
    uint32_t Pad {};
    uint64_t Boxed {};
  } X87PCX {};
};
static_assert(std::is_standard_layout_v<FEXCore::Core::InternalThreadState>);
// Maximum unsigned-offset store range for fault page.
static_assert(
  (offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) - offsetof(FEXCore::Core::InternalThreadState, BaseFrameState)) <= 65520,
  "Fault page is outside of immediate range from CPU state");

} // namespace FEXCore::Core
