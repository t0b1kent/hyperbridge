// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <string_view>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::Context {
class Context;
}

namespace FEX::Windows {
/**
 * @brief Handles SMC and regular code invalidation
 */
class InvalidationTracker {
public:
  InvalidationTracker(FEXCore::Context::Context& CTX, const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads);
  void HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot);
  void HandleProcessExecuteFlagsChange(ULONG Flags);
  void HandleImageMap(std::string_view Name, uint64_t Address);
  struct InvalidateContainingSectionResult {
    uint64_t SectionStart;
    uint64_t SectionSize;
  };
  InvalidateContainingSectionResult InvalidateContainingSection(uint64_t Address, bool Free);
  void InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free);
  void ReprotectRWXIntervals(uint64_t Address, uint64_t Size);
  bool HandleRWXAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC, uint64_t FaultAddress);

  // Unprotects any RWX intervals in the input interval and invalidates code
  // NOTE: CodeInvalidationMutex must be locked when calling this, and if true is returned, kept locked until the write ends.
  bool BeginUntrackedWriteLocked(uint64_t Address, uint64_t Size);

  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRange(uint64_t Address);

  // ★ REGION4 (MACRUNNER_FEX32_IMPORT_BIND): see SyscallHandler::QueryGuestConstantData.
  bool QueryConstantData(uint64_t Address, uint32_t Size, void* Out);

  // ★ MacRunner (MACRUNNER_FEX_MONO_BP_PRECISE): точный сброс для заплатки адреса вызова — без выравнивания до страницы
  //   и без обнуления стеков возвратов.
  void InvalidateCallTargetPatch(uint64_t Address, uint64_t Size);

private:
  // ★ MacRunner (30.09.2026) — MACRUNNER_FEX_ALIAS_VIEWS: исполняемые виды НЕ-образных секций (двойное отображение W^X, .NET 7+).
  //   Их не приносит ни один хук выделения/смены прав/отображения образа: виден только сам вид.
  //   Б (ALIAS_VIEWS=1): на промахе QueryExecutableRange — NtQueryVirtualMemory; MEM_COMMIT + MEM_MAPPED + исполняемые права ->
  //     вид попадает в XIntervals, запрос повторяется ОДИН раз. БЕЗ инвалидации: запрос идёт под разделяемой CodeInvalidationMutex
  //     компиляции, а инвалидация берёт её исключительно (самоблокировка); безопасно, потому что промах и есть первая выборка.
  //   В (ALIAS_VALIDATE, по умолчанию 1 внутри ALIAS_VIEWS=1): такие виды — «только проверять»: AliasIntervals, ответ
  //     Writable = NoTrap = true, страницы НЕ защищаются (запись идёт через другой вид, защита этого вида её не видит).
  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRangeInternal(uint64_t Address);
  bool DiscoverExecutableView(uint64_t Address);
  void CollectMappedExecutableRegions(uint64_t Base, uint64_t Size, FEXCore::IntervalList<uint64_t>& Out);

  void DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC);
  void DisableSMCDetection();
  void InvalidateIntervalInternal(uint64_t Address, uint64_t Size);
  // NOTE: This assumed CodeInvalidationMutex is locked by the caller
  void InvalidateIntervalInternalLocked(uint64_t Address, uint64_t Size);

  // NOTE: If ForWriteLocked is true then this assumes CodeInvalidationMutex is locked by the caller,
  // and any code in the range will be invalidated before protection as RWX, otherwise protects as RX if false.
  bool ProtectRWXIntervalsInternal(uint64_t Address, uint64_t Size, bool ForWriteLocked);

  // Returns the correct protection for trapping (removing write) or untrapping (restoring write) an RWX interval.
  // For DEP-promoted regions (originally non-exec), uses PAGE_READONLY/PAGE_READWRITE instead of PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE.
  // NOTE: Must be called with IntervalsLock held.
  ULONG GetTrapProt(uint64_t Address) const;
  ULONG GetUntrapProt(uint64_t Address) const;

  FEXCore::IntervalList<uint64_t> XIntervals;
  FEXCore::IntervalList<uint64_t> RWXIntervals;
  // ★ REGION4: read-only image pages whose bytes are constants of some translation. Protected by IntervalsLock. A page enters
  //   BEFORE the kernel is asked about it and leaves only through a protection / free notification, never on a failed query.
  FEXCore::IntervalList<uint64_t> ConstDataIntervals;
  FEXCore::IntervalList<uint64_t> AliasIntervals; // Protected by IntervalsLock; always a subset of XIntervals; empty unless ALIAS_VALIDATE
  std::shared_mutex IntervalsLock;
  FEXCore::Context::Context& CTX;
  const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads;
  bool SMCDetectionDisabled {false};                    // Protected by IntervalsLock
  bool DEPDisabled {false};                             // Protected by IntervalsLock
  FEXCore::IntervalList<uint64_t> DEPPromotedIntervals; // Protected by IntervalsLock

  bool MonoBackpatcherDetectionPending {false};
  uint64_t MonoBase {0};
  uint64_t MonoEnd {0};
};
} // namespace FEX::Windows
