// SPDX-License-Identifier: MIT

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include "Allocator.h"
#include "InvalidationTracker.h"
#include <FEXCore/Utils/MacRunnerXfer.h>
#include "MacRunnerHostPageGeometry.h"
#include "MacRunnerProtKeep.h"
#include <windef.h>
#include <winternl.h>
#include <algorithm>
#include <atomic>
#include <cstdlib>

// ★ MacRunner (Claude, 23.09.2026) — MACRUNNER_FEX_PROT_KEEP: смена прав БЕЗ сброса переведённого кода.
//   Upstream сбрасывает весь диапазон при КАЖДОЙ смене прав, после которой память исполняемая, —
//   в том числе RWX->RX и RX->RX, когда байты не менялись и меняться незаметно не могли. Elden Ring
//   (Arxan) переключает права на крупных участках кода постоянно: 12,3 тыс. сбросов на 45 ГБ за прогон,
//   39 % компиляций — повторные (post095-game-098..102, строка macrunner-fex-jit).
//   0 — как upstream (по умолчанию), только счётчики;
//   1 — не сбрасывать уже исполняемое при переходе в исполняемое БЕЗ записи: запись туда до этого
//       была невозможна (RX), ловилась ловушкой (целые страницы хоста RWX) или проверяется кодом
//       (смешанные страницы, MACRUNNER_FEX_WRITABLE_VALIDATION >= 1). Гонок нет.
//   2 — как 1, плюс при переходе уже исполняемого в RWX целые страницы хоста не сбрасываются, а сразу
//       ставятся под ловушку записи; края со смешанными страницами сбрасываются. ОКНО ГОНКИ: запись
//       ДРУГОГО потока между системным вызовом и ловушкой не будет замечена. Arxan пишет из того же
//       потока после возврата VirtualProtect — поэтому режим отдельный, по согласию.
//   Оба режима — только при включённом отслеживании (SMC) и проверке записываемого кода; иначе как 0.
extern std::atomic<uint64_t> MacRunnerProtCalls, MacRunnerProtInvBytes, MacRunnerProtKeptBytes, MacRunnerProtTrapBytes; // Core.cpp
int MacRunnerWritableValidationMode(); // Core.cpp
int MacRunnerProtKeepMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_PROT_KEEP");
    return (Value && Value[0] >= '0' && Value[0] <= '2' && !Value[1]) ? Value[0] - '0' : 0;
  }();
  return Mode;
}

// ★ MacRunner (30.09.2026) — MACRUNNER_FEX_ALIAS_VIEWS: исполняемые виды НЕ-образных секций (двойное отображение W^X: один вид секции RW
//   пишет код, другой RX его исполняет; .NET 7+, V8). Ни NotifyMemoryAlloc, ни NotifyMemoryProtect, ни HandleImageMap такой вид не
//   приносят, и QueryExecutableRange отвечает «не исполняемо» -> «page fault on execute access» в любом режиме проверки.
//   0 (по умолчанию) — как было. 1 — Б: ленивое открытие вида на промахе QueryExecutableRange (см. DiscoverExecutableView) и В: такие
//   виды помечаются «только проверять» (AliasIntervals: Writable = NoTrap = true, страницы не защищаются).
//   MACRUNNER_FEX_ALIAS_VALIDATE=0 внутри ALIAS_VIEWS=1 оставляет только Б (вид исполняется, но правка через другой вид ловится лишь по
//   FlushInstructionCache) — для раздельной проверки слоёв.
extern std::atomic<uint64_t> MacRunnerAliasFound, MacRunnerAliasMarked, MacRunnerAliasAnswered; // Core.cpp
namespace {
bool MRAliasViewsOn() {
#ifdef FEX_WINE_DARWIN
  return FEX::Windows::AliasPolicy::Armed();
#else
  static const bool On = [] {
    const char* Value = getenv("MACRUNNER_FEX_ALIAS_VIEWS");
    return Value && Value[0] == '1' && !Value[1];
  }();
  return On;
#endif
}
bool MRAliasValidateOn() {
#ifdef FEX_WINE_DARWIN
  return FEX::Windows::AliasPolicy::Armed();
#else
  static const bool On = [] {
    if (!MRAliasViewsOn()) {
      return false;
    }
    const char* Value = getenv("MACRUNNER_FEX_ALIAS_VALIDATE");
    return !(Value && Value[0] == '0' && !Value[1]);
  }();
  return On;
#endif
}
} // namespace

// ★ MacRunner (Claude, 10.10.2026) — MACRUNNER_FEX_RWX_RECONCILE: права гостя — единственный источник истины об «RWX».
//   Upstream (и наш 0c69): при смене RWX -> PAGE_EXECUTE / PAGE_EXECUTE_READ страница ОСТАВАЛАСЬ в RWXIntervals (удаление было только в ветке «не исполняемая»).
//   HandleRWXAccessViolation считает любой отказ внутри RWX-интервала своим (ловушка SMC), возвращает странице PAGE_EXECUTE_READWRITE и «обработанный»
//   отказ повторяется — программа ЗАПИСАЛА туда, куда Windows писать не даёт (нужный AV до программы не доходил; байт записан; права стали 0x40).
//   0 (по умолчанию) — как было. 1 — (а) интервал RWX пересчитывается при каждой смене прав (RWX -> X/RX/RO/NA снимает членство);
//   (б) перед «своим» восстановлением сверяется, что страница закоммичена и несёт права, которыми ловушку ставит сам переводчик (GetTrapProt / GetUntrapProt); иначе отказ доставляется программе с исходными параметрами.
//   Внутреннее снятие ловушки по-прежнему только для страниц, которые гость сам объявил записываемыми — гостю права на запись оно не создаёт.
namespace {
bool RwxReconcileOn() {
  static const bool On = [] {
    const char* Value = getenv("MACRUNNER_FEX_RWX_RECONCILE");
    return Value && Value[0] == '1' && !Value[1];
  }();
  return On;
}
} // namespace

namespace FEX::Windows {
InvalidationTracker::InvalidationTracker(FEXCore::Context::Context& CTX, const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads)
  : CTX {CTX}
  , Threads {Threads} {
  FEX_CONFIG_OPT(SMCChecks, SMCCHECKS);
  SMCDetectionDisabled = (SMCChecks == FEXCore::Config::CONFIG_SMC_NONE);

  MEMORY_BASIC_INFORMATION Info;
  uint64_t Address = 0;

  while (VirtualQuery(reinterpret_cast<LPCVOID>(Address), &Info, sizeof(Info))) {
    uint64_t BaseAddress = reinterpret_cast<uint64_t>(Info.BaseAddress);
    if (Info.State == MEM_COMMIT) {
      HandleMemoryProtectionNotification(BaseAddress, Info.RegionSize, Info.Protect);
    }

    Address = BaseAddress + Info.RegionSize;
  }
}

static bool ProtHasExec(ULONG Prot) {
  return (Prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool ProtIsReadable(ULONG Prot) {
  return (Prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                  PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool ProtIsWritable(ULONG Prot) {
  return (Prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

void InvalidationTracker::HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot) {
  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;

  // ★ REGION4 (MACRUNNER_FEX32_IMPORT_BIND): a page whose bytes some translation holds as constants stops being plain read-only
  //   (this notification runs AFTER the change): drop every translation registered on it. Any other protection counts,
  //   executable ones included: such a page then belongs to the machinery below, which validates code spans, not this data.
#ifndef REGION4_NO_CONST_INVALIDATE // diagnostic negative control only (probe iatbind32 must then FAIL); never defined in a product build
  if (Prot != PAGE_READONLY) {
    bool DropConstData = false;
    {
      std::unique_lock Lock(IntervalsLock);
      const FEXCore::IntervalList<uint64_t>::Interval ConstInterval {AlignedBase, AlignedBase + AlignedSize};
      if (!ConstDataIntervals.Empty() && ConstDataIntervals.Intersect(ConstInterval)) {
        ConstDataIntervals.Remove(ConstInterval);
        DropConstData = true;
      }
    }
    if (DropConstData) {
      FEXCore::Utils::MacRunnerConstDataDrops.fetch_add(1, std::memory_order_relaxed);
      InvalidateIntervalInternal(AlignedBase, AlignedSize);
    }
  }
#endif

  // Что сбросить и что поставить под ловушку (MacRunnerProtKeep.h). Переполнение — сброс всего диапазона, как upstream.
  MacRunnerProtKeep::Plan Plan;
  bool InvalidateAll = false;

  // ★ MacRunner (30.09.2026, ALIAS_VIEWS, слой В): исполняемые виды секций в этом диапазоне. Спрашиваем ядро ДО IntervalsLock.
  FEXCore::IntervalList<uint64_t> AliasFound;
  if (MRAliasValidateOn() && ProtHasExec(Prot)) {
    CollectMappedExecutableRegions(AlignedBase, AlignedSize, AliasFound);
  }

  const bool NeedsInvalidate = [&]() {
    std::unique_lock Lock(IntervalsLock);

    FEXCore::IntervalList<uint64_t>::Interval ProtInterval {AlignedBase, AlignedBase + AlignedSize};

    const bool HasExec = ProtHasExec(Prot);
    const bool EffectiveExec = HasExec || (DEPDisabled && ProtIsReadable(Prot));
    const bool EffectiveRWX = EffectiveExec && ProtIsWritable(Prot);

    if (EffectiveExec) {
      const int KeepMode = MacRunnerProtKeepMode();
      if (KeepMode && !DEPDisabled && !SMCDetectionDisabled && MacRunnerWritableValidationMode() >= 1) {
        // Разбор по XIntervals ДО вставки: уже исполняемое против нового.
        Plan = MacRunnerProtKeep::Compute(XIntervals, AlignedBase, AlignedBase + AlignedSize, EffectiveRWX, KeepMode, ProtectionPageSize);
        InvalidateAll = Plan.Overflow;
      } else {
        InvalidateAll = true;
      }

      XIntervals.Insert(ProtInterval);
      if (MRAliasValidateOn()) {
        // Набор «только проверять» для этого диапазона — ровно его исполняемые виды секций.
        AliasIntervals.Remove(ProtInterval);
        if (!AliasFound.Empty()) {
          AliasIntervals.Insert(AliasFound);
          MacRunnerAliasMarked.fetch_add(1, std::memory_order_relaxed);
        }
      }
      if (EffectiveRWX) {
        LogMan::Msg::DFmt("Add SMC interval: {:X} - {:X}", AlignedBase, AlignedBase + AlignedSize);
        RWXIntervals.Insert(ProtInterval);
      } else {
        // RWX -> X / RX: гость отнял право записи; прежняя принадлежность к RWX-интервалу устарела.
        RWXIntervals.Remove(ProtInterval);
      }
      if (DEPDisabled && !HasExec) {
        DEPPromotedIntervals.Insert(ProtInterval);
      }
      return true;
    } else if (XIntervals.Intersect(ProtInterval)) {
      XIntervals.Remove(ProtInterval);
      RWXIntervals.Remove(ProtInterval);
      if (MRAliasValidateOn()) {
        AliasIntervals.Remove(ProtInterval);
      }
      if (DEPDisabled) {
        DEPPromotedIntervals.Remove(ProtInterval);
      }
      InvalidateAll = true;
      return true;
    }

    return false;
  }();

  if (!NeedsInvalidate) {
    return;
  }
  MacRunnerProtCalls.fetch_add(1, std::memory_order_relaxed);

  // IntervalsLock cannot be held during invalidation
  if (InvalidateAll) {
    MacRunnerProtInvBytes.fetch_add(AlignedSize, std::memory_order_relaxed);
    InvalidateIntervalInternal(AlignedBase, AlignedSize);
    return;
  }
  MacRunnerProtKeptBytes.fetch_add(Plan.KeptBytes, std::memory_order_relaxed);
  for (size_t I = 0; I < Plan.InvalidateCount; ++I) {
    const auto& Span = Plan.Invalidate[I];
    MacRunnerProtInvBytes.fetch_add(Span.End - Span.Begin, std::memory_order_relaxed);
    InvalidateIntervalInternal(Span.Begin, Span.End - Span.Begin);
  }
  for (size_t I = 0; I < Plan.TrapCount; ++I) {
    // Ловушка записи вместо сброса: первая же запись даст отказ, HandleRWXAccessViolation сбросит ровно
    // её страницу хоста. Код, переведённый раньше, остаётся в работе.
    const auto& Span = Plan.Trap[I];
    MacRunnerProtTrapBytes.fetch_add(Span.End - Span.Begin, std::memory_order_relaxed);
    std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
    ProtectRWXIntervalsInternal(Span.Begin, Span.End - Span.Begin, false);
  }
}

void InvalidationTracker::HandleProcessExecuteFlagsChange(ULONG Flags) {
  const bool DisableDEP = (Flags & MEM_EXECUTE_OPTION_ENABLE) != 0;

  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  std::unique_lock Lock(IntervalsLock);

  if (DisableDEP == DEPDisabled) {
    return;
  }

  DEPDisabled = DisableDEP;

  if (DisableDEP) {
    DEPPromotedIntervals.Clear();

    MEMORY_BASIC_INFORMATION Info;
    uint64_t Address = 0;

    while (VirtualQuery(reinterpret_cast<LPCVOID>(Address), &Info, sizeof(Info))) {
      uint64_t BaseAddress = reinterpret_cast<uint64_t>(Info.BaseAddress);
      if (Info.State == MEM_COMMIT && ProtIsReadable(Info.Protect) && !ProtHasExec(Info.Protect)) {
        const auto AlignedBase = BaseAddress & FEXCore::Utils::FEX_PAGE_MASK;
        const auto AlignedSize = (BaseAddress - AlignedBase + Info.RegionSize + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;
        FEXCore::IntervalList<uint64_t>::Interval ProtInterval {AlignedBase, AlignedBase + AlignedSize};

        XIntervals.Insert(ProtInterval);
        if (ProtIsWritable(Info.Protect)) {
          RWXIntervals.Insert(ProtInterval);
        }
        DEPPromotedIntervals.Insert(ProtInterval);
      }

      Address = BaseAddress + Info.RegionSize;
    }
  } else {
    for (const auto& Interval : DEPPromotedIntervals) {
      XIntervals.Remove(Interval);
      RWXIntervals.Remove(Interval);
    }
    DEPPromotedIntervals.Clear();
  }

  // Invalidate all cached code: previously-compiled blocks may contain NoExec stubs for addresses
  // that are now executable (or reference regions whose executability just changed).
  InvalidateIntervalInternalLocked(0, std::numeric_limits<uint64_t>::max());
}

void InvalidationTracker::HandleImageMap(std::string_view Name, uint64_t Address) {
  auto* Nt = RtlImageNtHeader(reinterpret_cast<HMODULE>(Address));
  auto* SectionsBegin = IMAGE_FIRST_SECTION(Nt);
  auto* SectionsEnd = SectionsBegin + Nt->FileHeader.NumberOfSections;
  uint64_t LastExecutableSectionEnd = 0;

  for (auto* Section = SectionsBegin; Section != SectionsEnd; Section++) {
    if (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      std::unique_lock Lock(IntervalsLock);

      uint64_t SectionBase = Address + Section->VirtualAddress;
      uint64_t SectionEnd = SectionBase + Section->Misc.VirtualSize;
      XIntervals.Insert({SectionBase, SectionEnd});
      LastExecutableSectionEnd = std::max(LastExecutableSectionEnd, SectionEnd);
      if (Section->Characteristics & IMAGE_SCN_MEM_WRITE) {
        LogMan::Msg::DFmt("Add image SMC interval: {:X} - {:X}", SectionBase, SectionBase + Section->Misc.VirtualSize);
        RWXIntervals.Insert({SectionBase, SectionBase + Section->Misc.VirtualSize});
      }
    }
  }

  FEX_CONFIG_OPT(MonoHacks, MONOHACKS);
  if (MonoHacks && (Name == "mono-2.0-bdwgc.dll" || Name == "mono.dll")) {
    FEX_CONFIG_OPT(MaxInst, MAXINST);
    FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
    if (Multiblock && MaxInst() >= 500) {
      // Require these settings to ensure we can safely hook all SMC sites in a single block
      CTX.MarkMonoDetected();
      MonoBackpatcherDetectionPending = true;
      MonoBase = Address;
      MonoEnd = LastExecutableSectionEnd;
    } else {
      LogMan::Msg::IFmt("Not applying mono hacks, Multiblock with MaxInst >= 500 required");
    }
  }
}

InvalidationTracker::InvalidateContainingSectionResult InvalidationTracker::InvalidateContainingSection(uint64_t Address, bool Free) {
  MEMORY_BASIC_INFORMATION Info;
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
    return {Address, 0};
  }

  const auto SectionBase = reinterpret_cast<uint64_t>(Info.AllocationBase);
  auto SectionSize = reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize - SectionBase;

  while (!NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(SectionBase + SectionSize), MemoryBasicInformation, &Info,
                               sizeof(Info), nullptr) &&
         reinterpret_cast<uint64_t>(Info.AllocationBase) == SectionBase) {
    SectionSize += Info.RegionSize;
  }

  InvalidateIntervalInternal(SectionBase, SectionSize);

  if (Free) {
    std::unique_lock Lock(IntervalsLock);
    XIntervals.Remove({SectionBase, SectionBase + SectionSize});
    RWXIntervals.Remove({SectionBase, SectionBase + SectionSize});
    if (MRAliasValidateOn()) {
      AliasIntervals.Remove({SectionBase, SectionBase + SectionSize});
    }
  }

  return {SectionBase, SectionSize};
}

void InvalidationTracker::InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free) {
  if (!Address) {
    // Match the Windows behaviour when passed a NULL base address.
    Size = std::numeric_limits<uint64_t>::max();
  }

  const auto AlignedBase = Address & FEXCore::Utils::FEX_PAGE_MASK;
  const auto AlignedSize = std::max(Size, (Address - AlignedBase + Size + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK);

  InvalidateIntervalInternal(AlignedBase, AlignedSize);

  if (Free) {
    std::unique_lock Lock(IntervalsLock);
    XIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
    RWXIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
    ConstDataIntervals.Remove({AlignedBase, AlignedBase + AlignedSize}); // REGION4: translations on it were dropped just above
    if (MRAliasValidateOn()) {
      AliasIntervals.Remove({AlignedBase, AlignedBase + AlignedSize});
    }
  }
}

// ★ REGION4 13.11.2026 (MACRUNNER_FEX32_IMPORT_BIND). Order is the proof: (1) the page enters ConstDataIntervals, (2) the kernel is
// asked, (3) the bytes are read. A protection change notifies AFTER it happened, so one that completed before (2) is seen by (2),
// and one that completes later finds the page from (1) and invalidates — waiting on CodeInvalidationMutex, which the compile that
// called us holds shared until its translation (with this page among its pages) is published. A failed query leaves the page
// registered: removing it could drop a concurrent successful registration of the same page; the cost is one empty invalidation.
bool InvalidationTracker::QueryConstantData(uint64_t Address, uint32_t Size, void* Out) {
  const uint64_t Page = Address & FEXCore::Utils::FEX_PAGE_MASK;
  if (!Size || ((Address + Size - 1) & FEXCore::Utils::FEX_PAGE_MASK) != Page) {
    return false;
  }
  const auto ReadOnlyImage = [Address]() {
    MEMORY_BASIC_INFORMATION Info;
    return !NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr) &&
           Info.State == MEM_COMMIT && Info.Type == MEM_IMAGE && Info.Protect == PAGE_READONLY;
  };
  {
    std::shared_lock Lock(IntervalsLock);
    if (!ConstDataIntervals.Query(Page).Enclosed) {
      Lock.unlock();
      if (!ReadOnlyImage()) { // cheap refusal: keeps ordinary writable data pages out of the set
        return false;
      }
      std::unique_lock Write(IntervalsLock);
      ConstDataIntervals.Insert({Page, Page + FEXCore::Utils::FEX_PAGE_SIZE});
    }
  }
  if (!ReadOnlyImage()) {
    return false;
  }
  memcpy(Out, reinterpret_cast<const void*>(Address), Size);
  return true;
}

void InvalidationTracker::ReprotectRWXIntervals(uint64_t Address, uint64_t Size) {
  ProtectRWXIntervalsInternal(Address, Size, false);
}

bool InvalidationTracker::HandleRWXAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPc, uint64_t FaultAddress) {
  const auto [NeedsInvalidate, UntrapProt] = [&](uint64_t Address) -> std::pair<bool, ULONG> {
    std::shared_lock Lock(IntervalsLock);
    if (!RWXIntervals.Query(Address).Enclosed) {
      return {false, 0};
    }
    return {true, GetUntrapProt(Address)};
  }(FaultAddress);

  if (NeedsInvalidate && RwxReconcileOn()) {
    // Отказ «свой» только если страница закоммичена и несёт права ловушки/снятой ловушки. Иначе (decommit/освобождена/устаревшее членство) отказ — программе, как есть.
    MEMORY_BASIC_INFORMATION RwxInfo;
    if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(FaultAddress), MemoryBasicInformation, &RwxInfo, sizeof(RwxInfo), nullptr) ||
        RwxInfo.State != MEM_COMMIT) {
      return false;
    }
    // Ловушку ставит только переводчик, и ровно этими правами: GetTrapProt (ждёт записи) или GetUntrapProt (уже снята другим потоком). Любые другие права
    // страницы (PAGE_EXECUTE, PAGE_NOACCESS, ...) — не наша ловушка: отказ принадлежит программе.
    const ULONG Current = RwxInfo.Protect & 0xFF;
    std::shared_lock Lock(IntervalsLock);
    // Wine represents writable image pages as EXECUTE_WRITECOPY until the first
    // write is materialized. Another thread can observe that state after our
    // successful RWX untrap and before the original store is retried. It is
    // still a writable image in our tracked interval, not a guest protection fault.
    const bool ImageCopyOnWrite = RwxInfo.Type == MEM_IMAGE && Current == PAGE_EXECUTE_WRITECOPY &&
                                  GetUntrapProt(FaultAddress) == PAGE_EXECUTE_READWRITE;
    if (Current != GetTrapProt(FaultAddress) && Current != GetUntrapProt(FaultAddress) && !ImageCopyOnWrite) {
      return false;
    }
  }

  if (NeedsInvalidate) {
    // IntervalsLock cannot be held during invalidation
    {
      std::scoped_lock Lock(CTX.GetCodeInvalidationMutex());

      // A single Darwin fault releases writes for the entire backing page.
      InvalidateIntervalInternalLocked(FaultAddress & ProtectionPageMask, ProtectionPageSize);

      // Invalidate, then unprotect the faulting page with the compilation lock held to ensure that any racing invalidations are not dropped.
      ULONG TmpProt;
      void* TmpAddress = reinterpret_cast<void*>(FaultAddress);
      SIZE_T TmpSize = 1;
      NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, UntrapProt, &TmpProt);
    }
    DetectMonoBackpatcherBlock(Thread, HostPc);
    return true;
  }
  return false;
}

bool InvalidationTracker::BeginUntrackedWriteLocked(uint64_t Address, uint64_t Size) {
  return ProtectRWXIntervalsInternal(Address, Size, true);
}

FEXCore::HLE::ExecutableRangeInfo InvalidationTracker::QueryExecutableRange(uint64_t Address) {
  auto Info = QueryExecutableRangeInternal(Address);
  // ★ MacRunner (30.09.2026, ALIAS_VIEWS, слой Б): промах — единственное место, где виден исполняемый вид секции, не пришедший ни через
  //   хук выделения, ни через смену прав, ни через образ. Запрос идёт ПОД разделяемой CodeInvalidationMutex компиляции.
  if (!Info.Size && MRAliasViewsOn() && DiscoverExecutableView(Address)) {
    Info = QueryExecutableRangeInternal(Address);
  }
  return Info;
}

FEXCore::HLE::ExecutableRangeInfo InvalidationTracker::QueryExecutableRangeInternal(uint64_t Address) {
  std::shared_lock Lock(IntervalsLock);
  const auto XResult = XIntervals.Query(Address);
  if (!XResult.Enclosed) {
    return {};
  }
  const auto RWXResult = RWXIntervals.Query(Address);
  // ★ MacRunner (30.09.2026, ALIAS_VIEWS, слой В): вид секции «только проверять» — всегда записываемый и БЕЗ ловушки; ответы для соседних
  //   адресов того же X-интервала обрываются перед его началом (как перед следующим RWX-интервалом).
  uint64_t AliasAhead = std::numeric_limits<uint64_t>::max();
  if (MRAliasValidateOn()) {
    const auto AliasResult = AliasIntervals.Query(Address);
    if (AliasResult.Enclosed) {
      const uint64_t Begin = std::max(AliasResult.Interval.Offset, XResult.Interval.Offset);
      const uint64_t End = std::min(AliasResult.Interval.End, XResult.Interval.End);
      MacRunnerAliasAnswered.fetch_add(1, std::memory_order_relaxed);
      return {Begin, End - Begin, true, true};
    }
    if (AliasResult.Size) {
      AliasAhead = AliasResult.Interval.Offset;
    }
  }
  if (RWXResult.Enclosed) {
    uint64_t Begin = RWXResult.Interval.Offset;
    if (MRAliasValidateOn() && Begin < Address) {
      // Вид «только проверять» ПОЗАДИ адреса внутри этого же RWX-интервала: ответ объявил бы его «под ловушкой» (NoTrap = false), а декодер
      // запоминает ответ и берёт его для соседних команд (и MACRUNNER_FEX_RANGE_CACHE тоже) — ответ не должен накрывать адреса другого класса.
      const auto Behind = AliasIntervals.Query(Begin);
      if ((Behind.Enclosed || Behind.Size) && Behind.Interval.Offset < Address) {
        Begin = Address;
      }
    }
    return {Begin, std::min(RWXResult.Interval.End, AliasAhead) - Begin, true};
  }
  // ★ MacRunner (Claude, 29.09.2026): незаписываемый ответ начинается с САМОГО адреса, а не с начала X-интервала.
  //   RWX-интервал может лежать в том же X-интервале ДО адреса (Stardew/CoreCLR: страница RWX 4 КБ внутри образа
  //   0x14af01000+0x3c9000); прежний ответ [начало X, следующий RWX) объявлял его незаписываемым, и кеш диапазона
  //   декодера (а с ним MACRUNNER_FEX_RANGE_CACHE и решения Mono в Frontend.cpp) снимал проверку записываемого кода:
  //   на стенде 4 перевода из 6 655 выпущены без проверки. Про адреса ниже запроса ответ ничего не утверждает.
  uint64_t End = XResult.Interval.End;
  if (RWXResult.Size && RWXResult.Size < XResult.Size) {
    End = RWXResult.Interval.Offset;
  }
  return {Address, std::min(End, AliasAhead) - Address, false};
}

// ★ MacRunner (30.09.2026, ALIAS_VIEWS, слой Б). Вызывается на промахе QueryExecutableRange, то есть из декодера, под разделяемой
// CodeInvalidationMutex. Поэтому НИКАКОЙ инвалидации здесь (InvalidateIntervalInternal берёт эту мьютекс исключительно — самоблокировка), только
// IntervalsLock, тот же порядок, что у HandleProcessExecuteFlagsChange (CodeInvalidationMutex -> IntervalsLock). Без инвалидации безопасно:
// вид, которого здесь не знали, не мог получить перевода, а заглушка NOEXEC для этого адреса — та самая компиляция, что сейчас идёт.
// Берём ТОЛЬКО исполняемые виды секций (MEM_MAPPED): образы приходят через HandleImageMap, частная память — через NotifyMemoryAlloc/Protect.
bool InvalidationTracker::DiscoverExecutableView(uint64_t Address) {
  MEMORY_BASIC_INFORMATION Info;
  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
    return false;
  }
  if (Info.State != MEM_COMMIT || Info.Type != MEM_MAPPED || !ProtHasExec(Info.Protect)) {
    return false;
  }

  // NtQueryVirtualMemory: BaseAddress — страница запрошенного адреса, RegionSize — серия страниц ДАЛЬШЕ с теми же свойствами.
  const uint64_t Base = reinterpret_cast<uint64_t>(Info.BaseAddress) & FEXCore::Utils::FEX_PAGE_MASK;
  const uint64_t End = (reinterpret_cast<uint64_t>(Info.BaseAddress) + Info.RegionSize + FEXCore::Utils::FEX_PAGE_SIZE - 1) & FEXCore::Utils::FEX_PAGE_MASK;
  const FEXCore::IntervalList<uint64_t>::Interval View {Base, End};

  // ★ MacRunner (30.09.2026, MACRUNNER_FEX_HOOK_GUARD): вставки в векторы интервалов под IntervalsLock (unique) выделяют память; если аллокатор отобразит новый кусок,
  //   хук NotifyMemoryAlloc зайдёт в HandleMemoryProtectionNotification на тот же IntervalsLock. Область — до замка, чтобы накрыть и его взятие.
  HookGuard::Scope HookGuardScope;
  std::unique_lock Lock(IntervalsLock);
  if (XIntervals.Query(Address).Enclosed) {
    return true; // другой поток успел
  }
  XIntervals.Insert(View);
  if (MRAliasValidateOn()) {
    AliasIntervals.Insert(View);
  } else if (ProtIsWritable(Info.Protect)) {
    RWXIntervals.Insert(View); // ловушку взведёт MarkGuestExecutableRange после компиляции, как для любого RWX
  }
  MacRunnerAliasFound.fetch_add(1, std::memory_order_relaxed);
  return true;
}

// ★ MacRunner (30.09.2026, ALIAS_VIEWS, слой В): подобласти [Base, Base+Size), которые СЕЙЧАС являются исполняемыми видами секций.
void InvalidationTracker::CollectMappedExecutableRegions(uint64_t Base, uint64_t Size, FEXCore::IntervalList<uint64_t>& Out) {
  const uint64_t End = Base + Size;
  uint64_t Address = Base;
  while (Address < End) {
    MEMORY_BASIC_INFORMATION Info;
    if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryBasicInformation, &Info, sizeof(Info), nullptr)) {
      break;
    }
    const uint64_t RegionBase = reinterpret_cast<uint64_t>(Info.BaseAddress);
    const uint64_t RegionEnd = RegionBase + Info.RegionSize;
    if (Info.State == MEM_COMMIT && Info.Type == MEM_MAPPED && ProtHasExec(Info.Protect)) {
      Out.Insert({std::max(Address, RegionBase), std::min(End, RegionEnd)});
    }
    if (RegionEnd <= Address) {
      break;
    }
    Address = RegionEnd;
  }
}

void InvalidationTracker::DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPc) {
  if (!MonoBackpatcherDetectionPending) {
    return;
  }

  if (!CTX.IsAddressInCodeBuffer(Thread, HostPc)) {
    return;
  }

  uint64_t RIP = CTX.RestoreRIPFromHostPC(Thread, HostPc);
  if (!RIP || RIP < MonoBase || RIP >= MonoEnd) {
    return;
  }

  static constexpr uint8_t XChgOp = 0x87;
  if (*reinterpret_cast<uint8_t*>(RIP) != XChgOp && *reinterpret_cast<uint8_t*>(RIP + 1) != XChgOp) {
    return;
  }

  uint64_t BlockEntry = CTX.GetGuestBlockEntry(Thread);
  LogMan::Msg::DFmt("Detected mono backpatcher at: {:X}", BlockEntry);
  DisableSMCDetection();
  {
    std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
    CTX.MarkMonoBackpatcherBlock(BlockEntry);
  }
  InvalidateAlignedInterval(BlockEntry, FEXCore::Utils::FEX_PAGE_SIZE, false);
}

void InvalidationTracker::DisableSMCDetection() {
  std::unique_lock Lock(IntervalsLock);
  SMCDetectionDisabled = true;
  uint64_t Address = 0;

  // Reprotect all RWX intervals as writable
  FEXCore::IntervalList<uint64_t>::QueryResult Query;
  do {
    Query = RWXIntervals.Query(Address);
    if (Query.Enclosed) {
      void* TmpAddress = reinterpret_cast<void*>(Address);
      SIZE_T TmpSize = static_cast<SIZE_T>(Query.Size);
      ULONG TmpProt;
      NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, GetUntrapProt(Address), &TmpProt);
    }
    Address += Query.Size;
  } while (Query.Size);
}

ULONG InvalidationTracker::GetTrapProt(uint64_t Address) const {
  if (DEPDisabled && DEPPromotedIntervals.Query(Address).Enclosed) {
    return PAGE_READONLY;
  }
  return PAGE_EXECUTE_READ;
}

ULONG InvalidationTracker::GetUntrapProt(uint64_t Address) const {
  if (DEPDisabled && DEPPromotedIntervals.Query(Address).Enclosed) {
    return PAGE_READWRITE;
  }
  return PAGE_EXECUTE_READWRITE;
}

void InvalidationTracker::InvalidateIntervalInternal(uint64_t Address, uint64_t Size) {
  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  InvalidateIntervalInternalLocked(Address, Size);
}

void InvalidationTracker::InvalidateCallTargetPatch(uint64_t Address, uint64_t Size) {
  std::scoped_lock CodeLock(CTX.GetCodeInvalidationMutex());
  HookGuard::Scope HookGuardScope; // MACRUNNER_FEX_HOOK_GUARD: см. Allocator.h (вектор Erased и стирание кешей под эксклюзивным замком)
  fextl::vector<uint64_t> Erased;
  CTX.MRInvalidateCodeBuffersPrecise(Address, Size, Erased);
  if (Erased.empty()) {
    return;
  }
  for (auto Thread : Threads) {
    CTX.MRInvalidateThreadCachedEntries(Thread.second, Erased);
  }
}

void InvalidationTracker::InvalidateIntervalInternalLocked(uint64_t Address, uint64_t Size) {
  // NOTE: This assumes CodeInvalidationMutex is locked by the caller
  // ★ MacRunner (30.09.2026, MACRUNNER_FEX_HOOK_GUARD): вся инвалидация под замком — сброс кешей блоков (стирание CachedCodePages освобождает память аллокатору,
  //   тот может вернуть ОС кусок -> NtFreeVirtualMemory -> NotifyMemoryFree -> InvalidateIntervalInternal на ТОМ ЖЕ замке). Подробности — Allocator.h.
  HookGuard::Scope HookGuardScope;
  CTX.InvalidateCodeBuffersCodeRange(Address, Size);
  for (auto Thread : Threads) {
    CTX.InvalidateThreadCachedCodeRange(Thread.second, Address, Size);
  }
}

bool InvalidationTracker::ProtectRWXIntervalsInternal(uint64_t Address, uint64_t Size, bool ForWriteLocked) {
  if (!Size) return false;
  // Re-arm all tracked RWX subpages sharing a host protection unit.
  const auto End = (Address + Size + ProtectionPageSize - 1) & ProtectionPageMask;
  const auto AlignedBase = Address & ProtectionPageMask;
  Address = AlignedBase;
  std::shared_lock Lock(IntervalsLock);

  if (SMCDetectionDisabled) {
    return false;
  }

  bool HitRWXInterval = false;
  do {
    const auto Query = RWXIntervals.Query(Address);
    if (Query.Enclosed) {
      if (!HitRWXInterval) {
        if (ForWriteLocked) {
          // If we are protecting as writable, then the entire range must be invalidated before any protections are
          // applied and the invalidation mutex must be locked throughout.
          // Do this lazily only when an RWX region is actually hit.
          // NOTE: This assumes CodeInvalidationMutex is locked by the caller
          // Unprotecting releases the entire host-page range, not only the caller bytes.
          InvalidateIntervalInternalLocked(AlignedBase, End - AlignedBase);
        }
        HitRWXInterval = true;
      }
      void* TmpAddress = reinterpret_cast<void*>(Address);
      SIZE_T TmpSize = static_cast<SIZE_T>(std::min(End, Address + Query.Size) - Address);
      ULONG TmpProt;
      NtProtectVirtualMemory(NtCurrentProcess(), &TmpAddress, &TmpSize, ForWriteLocked ? GetUntrapProt(Address) : GetTrapProt(Address), &TmpProt);
    } else if (!Query.Size) {
      // No more regions past `Address` in the interval list
      break;
    }

    Address += Query.Size;
  } while (Address < End);

  return HitRWXInterval;
}

} // namespace FEX::Windows
