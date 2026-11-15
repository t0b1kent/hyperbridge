// SPDX-License-Identifier: MIT
#include "MRCallRet.h"
#include "Interface/Core/MRHeaderByPC.h"
#include <FEXCore/Utils/MacRunnerXfer.h>
/*
$info$
category: glue ~ Logic that binds various parts together
meta: glue|driver ~ Emulation mainloop related glue logic
tags: glue|driver
desc: Glues Frontend, OpDispatcher and IR Opts & Compilation, LookupCache, Dispatcher and provides the Execution loop entrypoint
$end_info$
*/

#include <cstdint>
#ifdef ZYDIS_DISASSEMBLER
#include <Zydis/Zydis.h>
#endif
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/CPUID.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/HBX87CoverageIR.h"
#include "Interface/Core/HBX87IR.h"
#include "Interface/Core/HBX87Stats.h"
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include <Interface/GDBJIT/GDBJIT.h>
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Utils/Allocator.h"
#include "Utils/Allocator/HostAllocator.h"
#include <FEXCore/Utils/SpinWaitLock.h>
#include "Utils/variable_length_integer.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#ifdef ARCHITECTURE_arm64ec
extern "C" bool MacRunnerWinctxExecuteBreakpoint(FEXCore::Core::CpuStateFrame*, uint64_t);
#endif
#include <FEXCore/Core/X87Region.h>
#include <FEXCore/Core/X87Fault.h>
#include <FEXCore/Core/X87Static.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/MacRunnerWinctx.h>
#include <FEXCore/Core/MacRunnerLazyMXCSR.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/Event.h>
#include <FEXCore/Utils/File.h>
#include <FEXCore/Utils/LogManager.h>
#include "FEXCore/Utils/SignalScopeGuards.h"
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/unordered_map.h>
#include "MacRunnerRevive.h"
#include <FEXCore/fextl/sstream.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <xxhash.h>
#include <FEXCore/Utils/MacRunnerQpcInline.h>

// ★ MacRunner QPCJIT (03.11.2026) MACRUNNER_FEX_QPC_INLINE: the plan is filled by the ARM64EC frontend (Module.cpp ProcessInit) before
// any guest code runs; with the key 0 it is never armed and GenerateIR emits exactly the previous IR.
namespace FEXCore::Utils::MRQpcInline {
Plan G {};
std::atomic<uint64_t> InlinedCalls {0};
std::atomic<uint64_t> Sites {0};
std::atomic<uint64_t> Refused {0};
std::atomic<uint64_t> SiteCalls {0};
std::atomic<uint64_t> SiteCompiledCall {0};
std::atomic<uint64_t> SiteCompiledJmp {0};
std::atomic<uint64_t> SiteQueries {0};
std::atomic<uint64_t> SiteRejected {0};
std::atomic<uint64_t> SiteReads {0};
std::atomic<uint64_t> SiteReadTicks {0};
SiteEntry Entries[MaxSiteEntries] {};
std::atomic<unsigned> EntryCount {0};
} // namespace FEXCore::Utils::MRQpcInline

// ★ MacRunner Opus 19.09.2026 — счётчики JIT (только диагностика, поведение не меняют).
// Вопрос: почему главный поток при загрузке Elden Ring до 80 % занятости компилирует в FEX —
// новый код или повторная трансляция того же (после инвалидации). Печать через
// FEX::Windows::Logging::Raw (__wine_dbg_output): fprintf в PE-части FEX убивает процесс.
namespace FEX::Windows::Logging {
void Raw(const char* Message);
}
extern std::atomic<uint64_t> MacRunnerJitWalkSteps;
extern std::atomic<uint64_t> MacRunnerJitWalkCalls;
extern std::atomic<uint64_t> MacRunnerJitWalkMismatch;
int MacRunnerBlockWalkMode();
std::atomic<uint64_t> MacRunnerJitSMC {0}; // Module.cpp: HandleRWXAccessViolation == true
// ★ MacRunner (Claude, 23.09.2026) — сбросы от смены прав (InvalidationTracker.cpp, MACRUNNER_FEX_PROT_KEEP).
std::atomic<uint64_t> MacRunnerProtCalls {0}, MacRunnerProtInvBytes {0}, MacRunnerProtKeptBytes {0}, MacRunnerProtTrapBytes {0};
// ★ MacRunner (30.09.2026) — MACRUNNER_FEX_ALIAS_VIEWS (InvalidationTracker.cpp): исполняемые виды секций (двойное отображение W^X).
//   found — виды, найденные лениво на промахе QueryExecutableRange (слой Б); marked — интервалы, помеченные «только проверять»
//   при смене прав (слой В); answered — ответы QueryExecutableRange из такого интервала (Writable = NoTrap = true).
std::atomic<uint64_t> MacRunnerAliasFound {0}, MacRunnerAliasMarked {0}, MacRunnerAliasAnswered {0};
std::atomic<uint32_t> MacRunnerModuleAliasState {0}; // 0 pending, 1 publishing, 2 armed, 3 emergency-off
std::atomic<uint64_t> MacRunnerModuleAliasCount {0}, MacRunnerModuleAliasUtc100ns {0}, MacRunnerModuleAliasQpc {0};
// ★ MacRunner (30.09.2026) — MACRUNNER_FEX_HOOK_GUARD (Source/Windows/Common/Allocator.h): пропущенные оповещения хуков памяти ПО ВИДАМ
//   (0 Free, 1 Alloc, 2 Protect, 3 Map, 4 Unmap) и наибольшая глубина вложенных областей. Пропуск = FEX внутри инвалидации трогал СВОЮ память.
std::atomic<uint64_t> MacRunnerHookSuppressed[7] {}, MacRunnerHookMaxDepth {0};
// HG2: по путям (0 инвалидация, 1 компиляция, 2 смена буфера кода): входы в область и пропущенные оповещения, отнесённые к самому вложенному пути.
std::atomic<uint64_t> MacRunnerHookGuardScopes[3] {}, MacRunnerHookSuppressedByPath[3] {};
namespace {
// ★ MacRunner (HG2, 30.09.2026): область среды выполнения на время компиляции / смены буфера кода (см. SyscallHandler::EnterRuntimeSection).
struct MRRuntimeSectionGuard {
  FEXCore::HLE::SyscallHandler* Handler;
  FEXCore::HLE::SyscallHandler::RuntimeSection Section;
  MRRuntimeSectionGuard(FEXCore::HLE::SyscallHandler* H, FEXCore::HLE::SyscallHandler::RuntimeSection S)
    : Handler {H}
    , Section {S} {
    if (Handler) {
      Handler->EnterRuntimeSection(Section);
    }
  }
  ~MRRuntimeSectionGuard() {
    if (Handler) {
      Handler->LeaveRuntimeSection(Section);
    }
  }
  MRRuntimeSectionGuard(const MRRuntimeSectionGuard&) = delete;
  MRRuntimeSectionGuard& operator=(const MRRuntimeSectionGuard&) = delete;
};

std::atomic<uint64_t> MRCompiles {0}, MRInsts {0}, MRRepeats {0}, MRRaced {0}, MRIrTicks {0}, MRCgTicks {0}, MRMaxInsts {0};
// Откуда повторы: полная очистка кэша (буфер кода заполнен), частичная, одиночные компиляции,
// инвалидация диапазонов (VirtualProtect/Free/FlushInstructionCache), точечное удаление блока.
std::atomic<uint64_t> MRFlushNew {0}, MRFlushL12 {0}, MRSingle {0}, MRCodeBytes {0}, MRInvCalls {0}, MRInvBytes {0}, MRRemove {0};
std::atomic<uint64_t> MRValidated {0}, MRWritableSkipped {0};
// ★ MacRunner Opus 19.09 — побайтная проверка кода в записываемых диапазонах (writable-validation-clear, Astra 11.09):
// 0 = выключена; 1 = на ВСЕХ инструкциях из записываемого кода (как было, по умолчанию);
// 2 = только если 16-КБ страница хоста не целиком внутри RWX-интервала (смешанная страница, где mtrack слеп);
// 3 = как 2, плюс все инструкции переходов/вызовов (SETS_RIP/CALL/BLOCK_END): в 092 режим 2 выполнил устаревший
//     перевод `call` на 0x1405554E8, который Arxan переписывает (смещение 0x193 -> 0x40000193).
// У Elden Ring почти весь код записываемый (Arxan): режим 1 даёт ~300 байт ARM-кода на x86-инструкцию и
// сотни полных очисток 128-МБ буфера кода за прогон.
int MRWritableValidationMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_WRITABLE_VALIDATION");
    return (Value && Value[0] >= '0' && Value[0] <= '3' && !Value[1]) ? Value[0] - '0' : 1;
  }();
  return Mode;
}
// ★ MacRunner (Claude, 29.09.2026) — MACRUNNER_FEX_RANGE_CACHE=1: при проверке записываемого кода (GenerateIR) брать
//   ответ из диапазона, который декодер потока уже запомнил (ExecutableRangeBase/End/Writable), если команда в нём
//   целиком, вместо QueryGuestExecutableRange на КАЖДУЮ команду. Запись HK до меню: 7.8 млн таких запросов, IR в игре
//   5.0 с против 3.5 с на стенде, где ответ — просмотр вектора (гипотеза: разница — цена запроса в игре). Запомненный
//   диапазон сбрасывается инвалидацией потока (InvalidateThreadCachedCodeRange), тем же, чем живёт сам декодер.
bool MRRangeCacheOn() {
  static const bool On = [] {
    const char* Value = getenv("MACRUNNER_FEX_RANGE_CACHE");
    return Value && Value[0] == '1' && !Value[1];
  }();
  return On;
}
std::atomic<uint64_t> MRRangeQueries {0}, MRRangeCached {0};
// ★ MacRunner (30.09.2026): состояние гейта HOOK_GUARD и сумма пропусков для строки macrunner-fex-jit.
int MRHookGuardForReport() {
#if defined(_WIN32) && defined(FEX_WINE_DARWIN)
  return MacRunnerModuleAliasState.load(std::memory_order_acquire) == 2;
#else
  const char* Value = getenv("MACRUNNER_FEX_HOOK_GUARD");
  return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
#endif
}
uint64_t MRHookSuppressedTotal() {
  uint64_t Sum = 0;
  for (const auto& Counter : MacRunnerHookSuppressed) {
    Sum += Counter.load(std::memory_order_relaxed);
  }
  return Sum;
}
int MRProtKeepModeForReport() {
  const char* Value = getenv("MACRUNNER_FEX_PROT_KEEP");
  return (Value && Value[0] >= '0' && Value[0] <= '2' && !Value[1]) ? Value[0] - '0' : 0;
}

// ★ MacRunner (Claude, 23.09.2026) — MACRUNNER_FEX_REVIVE=1: ВОЗВРАТ ПЕРЕВОДА вместо повторной компиляции.
//   В прогонах Elden Ring 098..102 33–40 % компиляций — повторные: блок сброшен (смена прав, сброс по
//   диапазону), а байты гостя те же. Сброс рвёт только ВХОДЯЩИЕ связи блока (GuestToHostMap::Erase);
//   исходящие записаны под адресами целей и остаются верными, сам код лежит в буфере до его полного
//   сброса. Поэтому блок можно вернуть в работу, если байты не изменились — это сверяет хеш.
//   Условия возврата (иначе — обычная компиляция):
//     • та же карта блоков и та же эпоха буфера (полный сброс буфера или карты обнуляет таблицу:
//       GuestToHostMap::ClearCache выбрасывает записи связей без восстановления переходов);
//     • весь диапазон байтов исполняемый сейчас;
//     • классы страниц: там, где СЕЙЧАС смешанная страница хоста под запись (класс 2 — ловушка слепа),
//       блок обязан был и при компиляции быть классом 2 (с проверкой байтов в коде);
//     • хеш совпал ДО постановки ловушки и ПОСЛЕ неё (запись, успевшая до ловушки, не пройдёт).
//   Запись в таблицу — только если хеш после компиляции и после ловушки совпал и за компиляцию не было
//   полного сброса. Сбросы по диапазону идут под исключительной блокировкой и с компиляцией (разделяемой)
//   не пересекаются. Окно, общее с upstream: запись в ЕЩЁ не защищённую ловушкой целую страницу RWX
//   между декодированием и ловушкой — двойной хеш его сужает, но не закрывает.
//   ★ 29.09.2026: пометка «заплатчика» Mono (MarkMonoBackpatcherBlock) меняет перевод при тех же байтах —
//   записи помеченного блока идут через MonoBackpatcherWrite, который сбрасывает перевод пропатченного
//   места. До этой правки таблица переживала пометку, и возврат отдавал перевод, собранный ДО неё: на HK
//   17 233 заплатки Mono до меню стали простыми записями без сброса (ловушки к тому моменту сняты,
//   DisableSMCDetection), переводы пропатченных вызовов устаревали молча. Теперь пометка обнуляет таблицу.
//   MACRUNNER_FEX_REVIVE_KEEP_BP=1 — только диагностика: вернуть прежнее поведение для сравнения на одном двоичном.
int MRCodeBufMaxForReport() {
  const char* Value = getenv("MACRUNNER_FEX_CODEBUF_MAX");
  return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
}
int MRReviveMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_REVIVE");
    return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
  }();
  return Mode;
}
#if defined(MACRUNNER_PROT_4K) && MACRUNNER_PROT_4K
constexpr uint64_t MRHostPage = 0x1000;
#else
constexpr uint64_t MRHostPage = 0x4000; // как в проверке записываемого кода (GenerateIR)
#endif
constexpr uint64_t MRMaxInstSize = 15;  // декодер может заглянуть за последнюю команду
constexpr size_t MRReviveMaxEntries = size_t {1} << 21;
using MRSeg = FEX::MacRunnerRevive::Seg;
struct MRReviveEntry {
  uint64_t HostCode {};
  uint64_t HashBegin {}, HashEnd {}, Hash {};
  const void* Map {};
  uint64_t Epoch {};
  bool MonoHacks {}; // ForceFullSMCDetection зависит от режима Mono-хаков — он обязан совпасть
  fextl::vector<uint64_t> CodePages;
  fextl::vector<MRSeg> Segs;
};
std::mutex MRReviveLock;
fextl::unordered_map<uint64_t, MRReviveEntry> MRReviveTable;
std::atomic<uint64_t> MRReviveEpoch {1};
std::atomic<uint64_t> MRRevived {0}, MRReviveHashMiss {0}, MRReviveSkip {0}, MRReviveRegistered {0}, MRReviveUnstable {0};
// Заплатки Mono (MonoBackpatcherWrite), возвраты помеченного блока, обнуления таблицы при пометке.
std::atomic<uint64_t> MRBackpatchWrites {0}, MRReviveBp {0}, MRReviveBpDrops {0};
int MRReviveKeepBp() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_REVIVE_KEEP_BP");
    return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
  }();
  return Mode;
}
// ★ MacRunner (Claude, 29.09.2026) — MACRUNNER_FEX_MONO_BP_PRECISE=1: точный сброс для заплаток адреса вызова Mono.
//   Заплатчик Mono меняет 8 байт imm64 в `mov r11, imm64; call/jmp r11` (49 BB <imm64> 41 FF D3/E3). Прежний путь
//   (InvalidateGuestCodeRange -> InvalidateAlignedInterval) снимает ВСЮ страницу 4 КБ переводов и обнуляет стек
//   возвратов 4 МБ у каждого потока, в чьих L1/L2 были блоки страницы: на HK до меню 17 тыс. раз (~1.2 с потоков под
//   исключительным замком) и ~29 тыс. повторных переводов соседей. Здесь снимаются только переводы, чей охват байтов
//   гостя задевает эти 8 байт, стек возвратов не обнуляется: старый перевод отличается лишь целью вызова, возврат в
//   него исполняет вызов старой цели (трамплина Mono) — то же, что видит ядро, ещё не заметившее перекрёстную запись.
//   Любая другая запись заплатчика идёт прежним путём.
//   ★ 30.09.2026: =2 — то же и для шаблона ЧЕРЕЗ ГРАНИЦУ страницы 4 КБ (MRCallTargetPatchKind ниже); =1 — как было.
int MRMonoBpPrecise() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_MONO_BP_PRECISE");
    return (Value && (Value[0] == '1' || Value[0] == '2') && !Value[1]) ? Value[0] - '0' : 0;
  }();
  return Mode;
}
std::atomic<uint64_t> MRBpPrecise {0}, MRBpPreciseErased {0}, MRBpFallback {0}, MRBpAcross {0}, MRBpAcrossUnread {0};
bool MRIsCallTargetPatch(uint64_t Address, uint8_t Size) {
  // Только внутри одной страницы 4 КБ с самим адресом: она заведомо отображена (заплатчик в неё пишет).
  constexpr uint64_t PageMask = ~uint64_t {0xFFF};
  if (Size != 8 || ((Address - 2) & PageMask) != (Address & PageMask) || ((Address + 10) & PageMask) != (Address & PageMask)) {
    return false;
  }
  const auto* Bytes = reinterpret_cast<const uint8_t*>(Address);
  return Bytes[-2] == 0x49 && Bytes[-1] == 0xBB && Bytes[8] == 0x41 && Bytes[9] == 0xFF && (Bytes[10] == 0xD3 || Bytes[10] == 0xE3);
}
// ★ MacRunner (Claude, 30.09.2026) — MACRUNNER_FEX_MONO_BP_PRECISE=2: шаблон адреса вызова ЧЕРЕЗ ГРАНИЦУ страницы 4 КБ.
//   Запись HK ev1-CF (30.09): 58 из 17 244 заплаток (0,34 %) — тот же 49 BB <imm64> 41 FF D3/E3, но imm64 у края
//   страницы и 49 BB или 41 FF xx — на соседней (сверено по снимкам страниц записи). Проверка выше их отвергает, и каждая
//   снимает всю страницу со стеками возвратов: по модели стенда +435 повторов (8 876 против 8 441) и 65 обнулений стека
//   против 7. Соседняя страница читается, только если в ней есть переведённый код (CodePages карты потока): её байты
//   декодер уже читал, а освобождение или смена прав сняли бы её из CodePages сбросом по диапазону — он идёт под
//   исключительной CodeInvalidationMutex, которую держит вызывающий (MonoBackpatcherWrite). Кода на соседней странице
//   нет — прежний путь по странице, нового отказа нет. Сам imm64, пересекающий границу, — не этот случай.
enum class MRPatchKind { None, InPage, AcrossPage, AcrossUnread };
MRPatchKind MRCallTargetPatchKind(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint8_t Size) {
  if (MRIsCallTargetPatch(Address, Size)) {
    return MRPatchKind::InPage;
  }
  constexpr uint64_t PageMask = ~uint64_t {0xFFF};
  const uint64_t Page = Address & PageMask;
  if (Size != 8 || ((Address + 7) & PageMask) != Page) {
    return MRPatchKind::None;
  }
  const bool Prev = ((Address - 2) & PageMask) != Page;
  const bool Next = ((Address + 10) & PageMask) != Page;
  if (Prev == Next) {
    return MRPatchKind::None; // шаблон целиком в странице — уже проверен выше
  }
  const uint64_t Neighbor = Prev ? Page - 0x1000 : Page + 0x1000;
  {
    auto lk = Thread->LookupCache->Shared->AcquireReadLock();
    if (!Thread->LookupCache->Shared->CodePages.contains(Neighbor >> 12)) {
      return MRPatchKind::AcrossUnread;
    }
  }
  const auto* Bytes = reinterpret_cast<const uint8_t*>(Address);
  return (Bytes[-2] == 0x49 && Bytes[-1] == 0xBB && Bytes[8] == 0x41 && Bytes[9] == 0xFF && (Bytes[10] == 0xD3 || Bytes[10] == 0xE3)) ?
           MRPatchKind::AcrossPage :
           MRPatchKind::None;
}
// Обнуление стека возвратов при инвалидации (InvalidateThreadCachedCodeRange): число и время.
std::atomic<uint64_t> MRCallRetClears {0}, MRCallRetTicks {0};

// Разбор и правило — в MacRunnerRevive.h (проверяются тестами на хосте).
bool MRSegments(FEXCore::HLE::SyscallHandler* Handler, FEXCore::Core::InternalThreadState* Thread, uint64_t Begin, uint64_t End,
                fextl::vector<MRSeg>& Out) {
  return FEX::MacRunnerRevive::Segments(
    [&](uint64_t Address) { return Handler->QueryGuestExecutableRange(Thread, Address); }, Begin, End, MRHostPage, Out);
}
bool MRClassesAllow(const fextl::vector<MRSeg>& Then, const fextl::vector<MRSeg>& Now) {
  return FEX::MacRunnerRevive::ClassesAllow(Then, Now);
}

uint64_t MRHashGuest(uint64_t Begin, uint64_t End) {
  return XXH3_64bits(reinterpret_cast<const void*>(Begin), End - Begin);
}
constexpr unsigned MRTableBits = 21;
std::atomic<uint64_t> MRTable[size_t {1} << MRTableBits];
inline uint64_t MRTicks() {
  uint64_t Value;
  asm volatile("mrs %0, cntvct_el0" : "=r"(Value));
  return Value;
}
inline uint64_t MRFrequency() {
  uint64_t Value;
  asm volatile("mrs %0, cntfrq_el0" : "=r"(Value));
  return Value ? Value : 1;
}
// true, если этот GuestRIP уже компилировался. Таблица на 2М адресов, открытая адресация.
bool MRSeen(uint64_t Rip) {
  const uint64_t Key = Rip ? Rip : 1;
  const size_t Mask = (size_t {1} << MRTableBits) - 1;
  size_t Index = size_t((Key * 0x9E3779B97F4A7C15ull) >> (64 - MRTableBits));
  for (unsigned Probe = 0; Probe < 64; ++Probe) {
    auto& Slot = MRTable[(Index + Probe) & Mask];
    uint64_t Current = Slot.load(std::memory_order_relaxed);
    if (Current == Key) {
      return true;
    }
    if (Current == 0) {
      if (Slot.compare_exchange_strong(Current, Key, std::memory_order_relaxed)) {
        return false;
      }
      if (Current == Key) {
        return true;
      }
    }
  }
  return false;
}
// Дамп раздутых блоков: адрес гостя, число x86-инструкций, размер ARM-кода, байты x86 и до 4 КБ ARM-кода.
std::atomic<uint32_t> MRDumps {0};
void MRHexLines(const char* Tag, uint64_t Rip, const uint8_t* Data, size_t Size) {
  static constexpr char Digits[] = "0123456789abcdef";
  for (size_t Offset = 0; Offset < Size; Offset += 64) {
    char Line[256];
    auto Result = fmt::format_to_n(Line, 96, "macrunner-fex-dump-{}: rip={:x} +{:04x} ", Tag, Rip, Offset);
    size_t Length = std::min<size_t>(Result.size, 95);
    for (size_t I = Offset; I < Size && I < Offset + 64 && Length + 3 < sizeof(Line); ++I) {
      Line[Length++] = Digits[Data[I] >> 4];
      Line[Length++] = Digits[Data[I] & 15];
    }
    Line[Length++] = '\n';
    Line[Length] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
}
void MRMaybeDump(uint64_t Rip, uint64_t Insts, const uint8_t* Code, uint64_t CodeSize, uint64_t CompileIndex) {
  const bool Bloated = Insts && CodeSize / Insts > 200 && Insts >= 4;
  const bool Typical = CompileIndex == 5000;
  if (!Bloated && !Typical) {
    return;
  }
  if (MRDumps.fetch_add(1, std::memory_order_relaxed) >= 6) {
    return;
  }
  char Line[256];
  auto Result = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-dump: rip={:x} insts={} code_bytes={} per_inst={} kind={}\n", Rip,
                                 Insts, CodeSize, Insts ? CodeSize / Insts : 0, Bloated ? "bloated" : "typical");
  Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
  FEX::Windows::Logging::Raw(Line);
  if (Rip >= 0x140001000 && Rip + 96 < 0x145e00000) { // только образ eldenring.exe: чтение за пределами региона уронило бы FEX
    MRHexLines("x86", Rip, reinterpret_cast<const uint8_t*>(Rip), 96);
  }
  MRHexLines("arm", Rip, Code, std::min<uint64_t>(CodeSize, 4096));
}
void MRReport(uint64_t Compiles) {
  // ★ MacRunner (30.09.2026): MACRUNNER_FEX_JIT_REPORT_EVERY=<n> — период строки macrunner-fex-jit (по умолчанию 4096 переводов).
  //   Короткие пробы (десятки переводов) иначе не печатают её вовсе; процессы прогонов убивают, деструктор не срабатывает.
  static const uint64_t Every = [] {
    const char* Value = getenv("MACRUNNER_FEX_JIT_REPORT_EVERY");
    const uint64_t N = Value ? strtoull(Value, nullptr, 10) : 0;
    return N ? N : uint64_t {4096};
  }();
  if (Compiles % Every) {
    return;
  }
  const uint64_t Frequency = MRFrequency();
  char Line[1536]; // 1024 before the alias_* fields (30.09.2026)
  const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
    "macrunner-fex-jit: compiles={} repeats={} raced={} guest_insts={} max_insts={} ir_ms={} codegen_ms={} "
    "walk_calls={} walk_steps={} walk_mismatch={} walk_mode={} smc={} flush_new={} flush_l12={} single={} code_mb={} "
    "inv_calls={} inv_mb={} remove={} validated={} writable_skipped={} wv_mode={} "
    "prot_calls={} prot_inv_mb={} prot_kept_mb={} prot_trap_mb={} prot_keep={} "
    "revived={} revive_hash_miss={} revive_skip={} revive_registered={} revive_unstable={} revive={} codebuf_max={} "
    "callret_clears={} callret_ms={} range_queries={} range_cached={} bp_writes={} revive_bp={} revive_bp_drops={} "
    "revive_keep_bp={} bp_precise={} bp_precise_erased={} bp_fallback={} bp_precise_on={} bp_across={} bp_across_unread={} "
    "alias_found={} alias_marked={} alias_answered={} alias_module_state={} alias_module_count={} alias_module_utc_100ns={} alias_module_qpc={} "
    "hook_guard={} hook_suppressed={} hs_free={} hs_alloc={} hs_protect={} hs_map={} hs_unmap={} hs_flush={} hs_dirty={} hs_depth_max={} "
    "hg_scopes_inv={} hg_scopes_compile={} hg_scopes_clear={} hs_path_inv={} hs_path_compile={} hs_path_clear={}\n",
    Compiles, MRRepeats.load(std::memory_order_relaxed), MRRaced.load(std::memory_order_relaxed),
    MRInsts.load(std::memory_order_relaxed), MRMaxInsts.load(std::memory_order_relaxed),
    MRIrTicks.load(std::memory_order_relaxed) * 1000 / Frequency, MRCgTicks.load(std::memory_order_relaxed) * 1000 / Frequency,
    MacRunnerJitWalkCalls.load(std::memory_order_relaxed), MacRunnerJitWalkSteps.load(std::memory_order_relaxed),
    MacRunnerJitWalkMismatch.load(std::memory_order_relaxed), MacRunnerBlockWalkMode(), MacRunnerJitSMC.load(std::memory_order_relaxed),
    MRFlushNew.load(std::memory_order_relaxed), MRFlushL12.load(std::memory_order_relaxed), MRSingle.load(std::memory_order_relaxed),
    MRCodeBytes.load(std::memory_order_relaxed) >> 20, MRInvCalls.load(std::memory_order_relaxed), MRInvBytes.load(std::memory_order_relaxed) >> 20,
    MRRemove.load(std::memory_order_relaxed), MRValidated.load(std::memory_order_relaxed),
    MRWritableSkipped.load(std::memory_order_relaxed), MRWritableValidationMode(),
    MacRunnerProtCalls.load(std::memory_order_relaxed), MacRunnerProtInvBytes.load(std::memory_order_relaxed) >> 20,
    MacRunnerProtKeptBytes.load(std::memory_order_relaxed) >> 20, MacRunnerProtTrapBytes.load(std::memory_order_relaxed) >> 20,
    MRProtKeepModeForReport(), MRRevived.load(std::memory_order_relaxed), MRReviveHashMiss.load(std::memory_order_relaxed),
    MRReviveSkip.load(std::memory_order_relaxed), MRReviveRegistered.load(std::memory_order_relaxed),
    MRReviveUnstable.load(std::memory_order_relaxed), MRReviveMode(), MRCodeBufMaxForReport(),
    MRCallRetClears.load(std::memory_order_relaxed), MRCallRetTicks.load(std::memory_order_relaxed) * 1000 / Frequency,
    MRRangeQueries.load(std::memory_order_relaxed), MRRangeCached.load(std::memory_order_relaxed),
    MRBackpatchWrites.load(std::memory_order_relaxed), MRReviveBp.load(std::memory_order_relaxed),
    MRReviveBpDrops.load(std::memory_order_relaxed), MRReviveKeepBp(), MRBpPrecise.load(std::memory_order_relaxed),
    MRBpPreciseErased.load(std::memory_order_relaxed), MRBpFallback.load(std::memory_order_relaxed), MRMonoBpPrecise(),
    MRBpAcross.load(std::memory_order_relaxed), MRBpAcrossUnread.load(std::memory_order_relaxed),
    MacRunnerAliasFound.load(std::memory_order_relaxed), MacRunnerAliasMarked.load(std::memory_order_relaxed),
    MacRunnerAliasAnswered.load(std::memory_order_relaxed),
    MacRunnerModuleAliasState.load(std::memory_order_acquire), MacRunnerModuleAliasCount.load(std::memory_order_relaxed),
    MacRunnerModuleAliasUtc100ns.load(std::memory_order_relaxed), MacRunnerModuleAliasQpc.load(std::memory_order_relaxed),
    MRHookGuardForReport(), MRHookSuppressedTotal(), MacRunnerHookSuppressed[0].load(std::memory_order_relaxed),
    MacRunnerHookSuppressed[1].load(std::memory_order_relaxed), MacRunnerHookSuppressed[2].load(std::memory_order_relaxed),
    MacRunnerHookSuppressed[3].load(std::memory_order_relaxed), MacRunnerHookSuppressed[4].load(std::memory_order_relaxed),
    MacRunnerHookSuppressed[5].load(std::memory_order_relaxed), MacRunnerHookSuppressed[6].load(std::memory_order_relaxed),
    MacRunnerHookMaxDepth.load(std::memory_order_relaxed),
    MacRunnerHookGuardScopes[0].load(std::memory_order_relaxed), MacRunnerHookGuardScopes[1].load(std::memory_order_relaxed),
    MacRunnerHookGuardScopes[2].load(std::memory_order_relaxed), MacRunnerHookSuppressedByPath[0].load(std::memory_order_relaxed),
    MacRunnerHookSuppressedByPath[1].load(std::memory_order_relaxed), MacRunnerHookSuppressedByPath[2].load(std::memory_order_relaxed));
  Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
  FEX::Windows::Logging::Raw(Line);
}
} // namespace

// Для InvalidationTracker.cpp: режимы сохранения перевода опираются на проверку записываемого кода.
int MacRunnerWritableValidationMode() {
  return MRWritableValidationMode();
}

namespace FEXCore::Core::X87Static {
bool Prepare(CpuStateFrame* Frame, const X87Region::GuardRequest* Request, X87Region::GuardValues* Values) noexcept {
  if (!Frame || !Frame->Thread || !Request || !Values || !Request->Iterations ||
      !(uint8_t(Request->Op) & 0x80) || (uint8_t(Request->Op) & 0x7f) > uint8_t(X87Region::Arithmetic::Sqrt) ||
      Request->SourceA >= 8 || Request->SourceB >= 8 || Request->Destination >= 8 ||
      (Request->FPCR & 0x03c09f03U)) return false;
  const auto& State = Frame->State;
  const unsigned Top = State.flags[X86State::X87FLAG_TOP_LOC];
  const uint16_t CW = State.FCW & 0x0f3f;
  if (Top >= 8 || (CW != 0x023f && CW != 0x003f) ||
      State.flags[X86State::X87FLAG_C1_LOC] || (State.flags[X86State::RFLAG_TF_RAW_LOC] & 1U)) return false;
  InternalThreadState::X87StaticCache Cache {};
  const auto Precision = CW == 0x023f ? Format::Binary53 : Format::Binary24;
  for (unsigned Slot = 0; Slot < 8; ++Slot) {
    if ((State.AbridgedFTW & (1U << Slot)) &&
        Narrow({State.mm[Slot][0], State.mm[Slot][1]}, Precision, Cache.Values[Slot])) Cache.FormatMask |= 1U << Slot;
  }
  const unsigned A = (Top + Request->SourceA) & 7, B = (Top + Request->SourceB) & 7;
  const unsigned Required = (1U << A) | (1U << B) | (1U << ((Top + Request->Destination) & 7));
  if ((Cache.FormatMask & Required) != Required) return false;
  Cache.Precision = uint8_t(Precision); Cache.Live = 0; // Published after all eight scalar loads.
  if (FEXCore::HBX87::Stats::Enabled())
    std::atomic_ref<uint64_t>(FEXCore::HBX87::Stats::Values[Precision == Format::Binary53 ?
      FEXCore::HBX87::Stats::StaticPrepare53 : FEXCore::HBX87::Stats::StaticPrepare24]).fetch_add(1,std::memory_order_relaxed);
  Frame->Thread->X87Cache = Cache;
  *Values = {Cache.Values[A], Cache.Values[B], Precision};
  return true;
}
bool MaterializeHost(CpuStateFrame* Frame, const __uint128_t* HostQ) noexcept {
  if (!Frame || !Frame->Thread) return false;
  auto& Cache = Frame->Thread->X87Cache;
  if (!Cache.Live) { Cache.FlushActive = 0; return true; }
  if (Cache.Live != 1 || !HostQ || (Cache.DirtyMask & ~Cache.FormatMask)) return false;
  Raw80 Raw[8] {};
  for (unsigned Slot = 0; Slot < 8; ++Slot) if (Cache.DirtyMask & (1U << Slot)) {
    if (!(Frame->State.AbridgedFTW & (1U << Slot)) ||
        !WidenIEEE(uint64_t(HostQ[24 + Slot]), Format(Cache.Precision), Raw[Slot])) return false;
  }
  for (unsigned Slot = 0; Slot < 8; ++Slot) if (Cache.DirtyMask & (1U << Slot)) {
    Frame->State.mm[Slot][0] = Raw[Slot].Significand;
    Frame->State.mm[Slot][1] = Raw[Slot].SignExponent;
  }
  Cache.Live = Cache.DirtyMask = Cache.FlushActive = 0;
  return true;
}
}

namespace FEXCore::Core::X87Region {
// 0216: admission and interrupted-state materialization must agree. Only a
// Guest64 counted region proven exact at every step may represent PC64 as P53.
static bool ExactPC64Allowed(const CpuStateFrame* Frame, uint16_t CW) noexcept {
  return CW == 0x033f && FEXCore::HBX87::Guest64Enabled() && Frame->Thread &&
    static_cast<const FEXCore::Context::ContextImpl*>(Frame->Thread->CTX)->Config.Is64BitMode();
}

bool Guard(const CpuStateFrame* Frame, const GuardRequest* Request, GuardValues* Values) noexcept {
  if (Request && (uint8_t(Request->Op) & 0x80)) {
    return FEXCore::HBX87::StaticRegsEnabled() &&
      X87Static::Prepare(const_cast<CpuStateFrame*>(Frame), Request, Values);
  }
  struct EntryCounter {
    bool Active {FEXCore::HBX87::Stats::Enabled()};
    unsigned Outcome {FEXCore::HBX87::Stats::RegionReject};
    ~EntryCounter() {
      if(Active) std::atomic_ref<uint64_t>(FEXCore::HBX87::Stats::Values[Outcome]).fetch_add(1,std::memory_order_relaxed);
    }
  } Counter;
  if (!Frame || !Request || !Values || !Request->Iterations || Request->SourceA >= 8 ||
      Request->SourceB >= 8 || Request->Destination >= 8 || Request->Op > Arithmetic::Sqrt ||
      (Request->FPCR & 0x03c09f03U)) return false;
  const auto& State = Frame->State;
  const uint16_t CW = State.FCW & 0x0f3f;
  // 0212: a PC64 region may use double only when the existing P53 guard
  // proves EVERY input and intermediate result exact. This is a subset of
  // PC64 semantics, not reduced precision. All other PC64 values fall back.
  // Keep the previous Guest32/INLINE_REGION domain byte-for-byte unchanged.
  const bool ExactPC64 = ExactPC64Allowed(Frame, CW);
  if ((CW != 0x023f && CW != 0x003f && !ExactPC64) || State.flags[X86State::X87FLAG_C1_LOC] ||
      (State.flags[X86State::RFLAG_TF_RAW_LOC] & 1U) || State.flags[X86State::X87FLAG_TOP_LOC] >= 8) return false;
  const unsigned P = CW == 0x003f ? 24 : 53;
  const unsigned Bias = P == 53 ? 1023 : 127;
  const int MinExponent = 1 - int(Bias), MaxExponent = int(Bias);
  struct Input {uint64_t Bits, Magnitude; int Exponent; bool Zero, Power, Integer;};
  auto Decode = [&](unsigned Slot, Input& Out) {
    const unsigned Physical = (State.flags[X86State::X87FLAG_TOP_LOC] + Slot) & 7;
    if (!(State.AbridgedFTW & (1U << Physical))) return false;
    const auto Sig = State.mm[Physical][0], SE = State.mm[Physical][1];
    if (SE > 0xffffU) return false;
    const auto Exponent = unsigned(SE & 0x7fffU);
    const uint64_t Sign = (SE >> 15) << (P == 53 ? 63 : 31);
    if (!Exponent && !Sig) {Out = {Sign,0,0,true,false,true}; return true;}
    if (!Exponent || Exponent == 0x7fff || !(Sig >> 63) || (Sig & ((uint64_t {1} << (64-P))-1))) return false;
    const int E = int(Exponent) - 16383;
    if (E < MinExponent || E > MaxExponent) return false;
    Out = {Sign | (uint64_t(E+int(Bias)) << (P-1)) | ((Sig >> (64-P)) & ((uint64_t {1} << (P-1))-1)),
           0,E,false,Sig == (uint64_t {1} << 63),false};
    if (E >= 0 && E <= int(P) && !(Sig & ((uint64_t {1} << (63-E))-1))) {
      Out.Integer = true; Out.Magnitude = Sig >> (63-E);
    }
    return true;
  };
  Input A {}, B {};
  if (!Decode(Request->SourceA,A)) return false;
  if (Request->Op == Arithmetic::Sqrt) B = A;
  else if (!Decode(Request->SourceB,B)) return false;
  const bool Alias = Request->SourceA == Request->SourceB;
  const bool DestA = Request->Destination == Request->SourceA;
  if (!DestA && Request->Destination != Request->SourceB) return false;
  const auto& D = DestA ? A : B;
  const auto& C = DestA ? B : A;
  const uint64_t N = Request->Iterations, Limit = uint64_t {1} << P;
  auto ScaleSafe = [&](int Start, int Step) {
    const int64_t Last = int64_t(Start) + int64_t(Step) * int64_t(N);
    return Last >= MinExponent && Last <= MaxExponent;
  };
  bool Safe {};
  switch (Request->Op) {
  case Arithmetic::Add:
  case Arithmetic::Sub:
    if (Alias && Request->Op == Arithmetic::Sub) Safe = true;
    else if (Alias) Safe = D.Zero || ScaleSafe(D.Exponent,1);
    else if (A.Integer && B.Integer) {
      // Conservative absolute bound also covers C-D, which alternates two values.
      Safe = D.Magnitude <= Limit && C.Magnitude <= Limit &&
          __uint128_t(D.Magnitude) + __uint128_t(C.Magnitude) * N <= Limit;
    }
    break;
  case Arithmetic::Mul:
    if (Alias) {
      // Squaring +/-1 or zero is stable; other power-of-two exponents double.
      if (D.Zero || (D.Power && !D.Exponent)) Safe = true;
      else if (D.Power && N < 32) {
        const int64_t Last = int64_t(D.Exponent) * (int64_t {1} << N);
        Safe = Last >= MinExponent && Last <= MaxExponent;
      }
    } else Safe = D.Zero || C.Zero || (C.Power && ScaleSafe(D.Exponent,C.Exponent));
    break;
  case Arithmetic::Div:
    if (Alias) Safe = !D.Zero;
    else if (DestA) Safe = !C.Zero && (D.Zero || (C.Power && ScaleSafe(D.Exponent,-C.Exponent)));
    else if (!D.Zero && C.Power && D.Power) {
      // C / D alternates E and EC-E. Both significands stay exactly one.
      const int Other = C.Exponent-D.Exponent;
      Safe = Other >= MinExponent && Other <= MaxExponent;
    } else if (!DestA && N == 1 && C.Zero && !D.Zero) Safe = true;
    break;
  case Arithmetic::Sqrt:
    if (!DestA) return false;
    Safe = A.Zero || (!(A.Bits >> (P == 53 ? 63 : 31)) && A.Power &&
        (!A.Exponent || (N < 32 && int64_t(A.Exponent) % (int64_t {1} << N) == 0)));
    break;
  }
  if (!Safe) return false;
  *Values = {A.Bits,B.Bits,P == 53 ? Format::Binary53 : Format::Binary24};
  Counter.Outcome=P==53?FEXCore::HBX87::Stats::RegionEntry53:FEXCore::HBX87::Stats::RegionEntry24;
  return true;
}

Recovery Materialize(CpuStateFrame* Frame, uint64_t HostPC, const uint64_t* HostGPRs,
                     const __uint128_t* HostQ) noexcept {
  if (Frame) MRHeaderByPC::Resolve(Frame->Thread, HostPC, MRHeaderByPC::X87Region);   // ★ MacRunner FEXXFER (mode 0: nothing)
  const Recovery Failed {Status::Failed};
  if (!Frame || !Frame->State.InlineJITBlockHeader) return {};
  const uint64_t Begin = Frame->State.InlineJITBlockHeader;
  const auto* BlockHeader = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(Begin);
  const uint64_t TailOffset = BlockHeader->OffsetToBlockTail;
  if (TailOffset < sizeof(*BlockHeader) || Begin + TailOffset < Begin) return Failed;
  if (HostPC < Begin || HostPC >= Begin + TailOffset) return {};
  const auto* Tail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(Begin + TailOffset);
  if (!Tail->_Pad[0]) return {};
  if (Tail->_Pad[0] != TailMarker || Tail->_Pad[1] != Version || (Tail->_Pad[2] && Tail->_Pad[2] != X87Fault::TailFlag)) return Failed;
  if (Tail->Size < TailOffset + sizeof(*Tail) || Tail->Size > (uint64_t {1} << 32) || Begin + Tail->Size < Begin) return Failed;
  if (!Tail->GuestSize || Tail->RIP + Tail->GuestSize < Tail->RIP) return Failed;
  const uint64_t End = Begin + Tail->Size;
  if (Tail->OffsetToRIPEntries < sizeof(*Tail) || Tail->OffsetToRIPEntries > End - (Begin + TailOffset)) return Failed;
  uint64_t Cursor = Begin + TailOffset + Tail->OffsetToRIPEntries;
  // Decode from a bounded local copy: the legacy decoder may read 17 bytes.
  // There is no allocation or initialization on this recovery path.
  if (Tail->NumberOfRIPEntries > End - Cursor) return Failed;
  for (uint32_t i = 0; i < Tail->NumberOfRIPEntries; ++i) {
    alignas(8) uint8_t Encoded[32] {};
    const size_t Available = std::min<uint64_t>(sizeof(Encoded), End - Cursor);
    memcpy(Encoded, reinterpret_cast<const void*>(Cursor), Available);
    const auto Entry = FEXCore::Utils::vl64pair::Decode(Encoded);
    if (!Entry.Size || Entry.Size > Available) return Failed;
    Cursor += Entry.Size;
  }
  if (Cursor > UINT64_MAX - (alignof(Recipe) - 1)) return Failed;
  Cursor = (Cursor + alignof(Recipe) - 1) & ~(uint64_t(alignof(Recipe)) - 1);
  if (Cursor > End || sizeof(Header) > End - Cursor) return Failed;
  Header Extension;
  memcpy(&Extension, reinterpret_cast<const void*>(Cursor), sizeof(Extension));
  if (Extension.MagicValue != Magic || Extension.VersionValue != Version || Extension.RecordBytes != sizeof(Recipe) ||
      !Extension.Count || Extension.Count > MaxRecipes ||
      Extension.Bytes != sizeof(Header) + Extension.Count * sizeof(Recipe) || Extension.Bytes > End - Cursor) return Failed;
  Cursor += sizeof(Header);
  Recipe Selected {};
  bool Found {};
  uint32_t PreviousEnd {};
  const uint64_t Offset = HostPC - Begin;
  for (uint32_t i = 0; i < Extension.Count; ++i, Cursor += sizeof(Recipe)) {
    Recipe Entry;
    memcpy(&Entry, reinterpret_cast<const void*>(Cursor), sizeof(Entry));
    if (Entry.HostBegin < sizeof(*BlockHeader) || Entry.HostBegin < PreviousEnd || Entry.HostEnd <= Entry.HostBegin ||
        Entry.HostEnd > TailOffset || Entry.GuestRIP < Tail->RIP || Entry.GuestRIP >= Tail->RIP + Tail->GuestSize ||
        Entry.Reserved || !Entry.LogicalSlotMask ||
        (Entry.Precision != Format::Binary53 && Entry.Precision != Format::Binary24 &&
         Entry.Precision != Format::IEEE53 && Entry.Precision != Format::IEEE24) ||
        (Entry.Controls & ~(CompleteDec32 | CounterCommitted | KeepEntryFlagsIfInitial)) ||
        ((Entry.Controls & CounterCommitted) && !(Entry.Controls & CompleteDec32)) ||
        ((Entry.Controls & KeepEntryFlagsIfInitial) &&
          ((Entry.Controls & (CompleteDec32|CounterCommitted))!=(CompleteDec32|CounterCommitted) || Entry.InitialCounterHost>=31))) return Failed;
    PreviousEnd = Entry.HostEnd;
    for (unsigned Slot = 0; Slot < 8; ++Slot) {
      if ((Entry.LogicalSlotMask & (1U << Slot)) && Entry.HostQForSlot[Slot] >= 32) return Failed;
    }
    if ((Entry.Controls & CompleteDec32) &&
        (Entry.CounterGuest >= 16 || Entry.CounterHost >= 31 || Entry.CarryHost >= 31)) return Failed;
    if (Offset >= Entry.HostBegin && Offset < Entry.HostEnd) {
      Selected = Entry;
      Found = true;
    }
  }
  if (!Found) return {};
  if (!HostQ) return Failed;
  const uint16_t RequiredCW = (Selected.Precision == Format::Binary53 || Selected.Precision == Format::IEEE53) ? 0x023f : 0x003f;
  const uint16_t CW = Frame->State.FCW & 0x0f3f;
  // IEEE53 belongs to the independent static bank and retains its old domain.
  const bool ExactPC64 = Selected.Precision == Format::Binary53 && ExactPC64Allowed(Frame, CW);
  if (CW != RequiredCW && !ExactPC64) return Failed;
  const unsigned Top = Frame->State.flags[X86State::X87FLAG_TOP_LOC];
  if (Top >= 8) return Failed;
  Raw80 Values[8] {};
  for (unsigned Slot = 0; Slot < 8; ++Slot) {
    if (!(Selected.LogicalSlotMask & (1U << Slot))) continue;
    if (!(Frame->State.AbridgedFTW & (1U << ((Top + Slot) & 7)))) return Failed;
    const auto Bits = static_cast<uint64_t>(HostQ[Selected.HostQForSlot[Slot]]);
    if (Selected.Precision == Format::IEEE53 || Selected.Precision == Format::IEEE24) {
      if (!FEXCore::HBX87::StaticRegsEnabled() || !X87Static::WidenIEEE(Bits,
          Selected.Precision == Format::IEEE53 ? Format::Binary53 : Format::Binary24, Values[Slot])) return Failed;
    } else if (!Widen(Bits, Selected.Precision, Values[Slot])) return Failed;
  }
  uint32_t Before {}, After {}, CF {}, Flags {};
  bool RepairDec=Selected.Controls & CompleteDec32;
  if(Selected.Controls & KeepEntryFlagsIfInitial) {
    if(!HostGPRs || HostGPRs[Selected.InitialCounterHost]>UINT32_MAX || !HostGPRs[Selected.InitialCounterHost] ||
        uint32_t(HostGPRs[Selected.CounterHost])>HostGPRs[Selected.InitialCounterHost]) return Failed;
    RepairDec=uint32_t(HostGPRs[Selected.CounterHost])!=HostGPRs[Selected.InitialCounterHost];
  }
  if (RepairDec) {
    if (!HostGPRs || HostGPRs[Selected.CarryHost] > 1) return Failed;
    const uint32_t Counter = HostGPRs[Selected.CounterHost];
    Before = (Selected.Controls & CounterCommitted) ? Counter + 1 : Counter;
    After = Before - 1;
    CF = HostGPRs[Selected.CarryHost] ^ 1U;
    Flags = CF | ((std::popcount(After & 0xffU) % 2 == 0) << 2) |
            (((Before ^ After) & 0x10U) ? 0x10U : 0U) | ((After == 0) << 6) |
            ((After >> 31) << 7) | ((Before == 0x80000000U) << 11);
  }
  // Commit only after every extent, slot, value, and counter has been checked.
  for (unsigned Slot = 0; Slot < 8; ++Slot) {
    if (!(Selected.LogicalSlotMask & (1U << Slot))) continue;
    Frame->State.mm[(Top + Slot) & 7][0] = Values[Slot].Significand;
    Frame->State.mm[(Top + Slot) & 7][1] = Values[Slot].SignExponent;
  }
  if (RepairDec) {
    Frame->State.gregs[Selected.CounterGuest] = After;
    Frame->State.pf_raw = After;
    Frame->State.af_raw = Before;
    using Builder = FEXCore::IR::OpDispatchBuilder;
    const uint32_t NZCV = ((After >> 31) << Builder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC)) |
                          (uint32_t(After == 0) << Builder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC)) |
                          ((CF ^ 1U) << Builder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC)) |
                          (uint32_t(Before == 0x80000000U) << Builder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC));
    memcpy(&Frame->State.flags[X86State::RFLAG_NZCV_LOC], &NZCV, sizeof(NZCV));
  }
  Frame->State.rip = Selected.GuestRIP;
  return {Status::Present, Selected.GuestRIP, RepairDec ? 0x8d5U : 0U, Flags, true};
}
}

namespace FEXCore::Core::X87Fault {
// Bounded reads of the current block's tail only; no allocation, logging or lazy initialization (exception path).
bool Materialize(CpuStateFrame* Frame, uint64_t HostPC, const uint64_t* HostGPRs, const __uint128_t* HostQ, uint64_t HostSP) noexcept {
  if (Frame) MRHeaderByPC::Resolve(Frame->Thread, HostPC, MRHeaderByPC::X87Fault);   // ★ MacRunner FEXXFER (mode 0: nothing)
  if (!Frame || !Frame->State.InlineJITBlockHeader || !HostQ) return false;
  const uint64_t Begin = Frame->State.InlineJITBlockHeader;
  const auto* BlockHeader = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(Begin);
  const uint64_t TailOffset = BlockHeader->OffsetToBlockTail;
  if (TailOffset < sizeof(*BlockHeader) || Begin + TailOffset < Begin) return false;
  if (HostPC < Begin || HostPC >= Begin + TailOffset) return false;
  const auto* Tail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(Begin + TailOffset);
  if (Tail->_Pad[2] != TailFlag) return false;
  if (Tail->Size < TailOffset + sizeof(*Tail) || Tail->Size > (uint64_t {1} << 32) || Begin + Tail->Size < Begin) return false;
  const uint64_t End = Begin + Tail->Size;
  if (Tail->OffsetToRIPEntries < sizeof(*Tail) || Tail->OffsetToRIPEntries > End - (Begin + TailOffset)) return false;
  uint64_t Cursor = Begin + TailOffset + Tail->OffsetToRIPEntries;
  if (Tail->NumberOfRIPEntries > End - Cursor) return false;
  for (uint32_t i = 0; i < Tail->NumberOfRIPEntries; ++i) {
    alignas(8) uint8_t Encoded[32] {};
    const size_t Available = std::min<uint64_t>(sizeof(Encoded), End - Cursor);
    memcpy(Encoded, reinterpret_cast<const void*>(Cursor), Available);
    const auto Entry = FEXCore::Utils::vl64pair::Decode(Encoded);
    if (!Entry.Size || Entry.Size > Available) return false;
    Cursor += Entry.Size;
  }
  Cursor = (Cursor + 7) & ~uint64_t {7};
  if (Tail->_Pad[0] == X87Region::TailMarker) {
    X87Region::Header Region;
    if (Cursor > End || sizeof(Region) > End - Cursor) return false;
    memcpy(&Region, reinterpret_cast<const void*>(Cursor), sizeof(Region));
    if (Region.MagicValue != X87Region::Magic || Region.Bytes > End - Cursor) return false;
    Cursor = (Cursor + Region.Bytes + 7) & ~uint64_t {7};
  }
  Header Extension;
  if (Cursor > End || sizeof(Extension) > End - Cursor) return false;
  memcpy(&Extension, reinterpret_cast<const void*>(Cursor), sizeof(Extension));
  if (Extension.MagicValue != Magic || Extension.VersionValue != Version || Extension.RecordBytes != sizeof(Record) ||
      !Extension.Count || Extension.Count > MaxRecords || Extension.Bytes != sizeof(Header) + Extension.Count * sizeof(Record) ||
      Extension.Bytes > End - Cursor || !Extension.SpillSlotBytes) return false;
  Cursor += sizeof(Header);
  const uint64_t Offset = HostPC - Begin;
  Record Selected {};
  bool Found {};
  for (uint32_t i = 0; i < Extension.Count; ++i, Cursor += sizeof(Record)) {
    Record R;
    memcpy(&R, reinterpret_cast<const void*>(Cursor), sizeof(R));
    if (Offset >= R.HostBegin && Offset < R.HostEnd && R.HostEnd <= TailOffset) {
      Selected = R;
      Found = true;
      break;
    }
  }
  if (!Found) return false;
  const auto Read = [&](uint16_t Loc, __uint128_t& Out) {
    const uint16_t Index = Loc & 0x3fff;
    switch (Loc & 0xc000) {
    case LocQ: if (Index >= 32) return false; Out = HostQ[Index]; return true;
    case LocX: if (!HostGPRs || Index >= 31) return false; Out = HostGPRs[Index]; return true;
    case LocSpill:
      if (!HostSP) return false;
      memcpy(&Out, reinterpret_cast<const void*>(HostSP + uint64_t(Index) * Extension.SpillSlotBytes), sizeof(Out));
      return true;
    default: return false;
    }
  };
  auto& State = Frame->State;
  const unsigned OldTop = State.flags[X86State::X87FLAG_TOP_LOC] & 7;
  unsigned NewTop = (OldTop - static_cast<int8_t>(Selected.TopOffset)) & 7;
  if (Selected.Mode & Slow) {
    NewTop = OldTop;
    if (Selected.Mode & TopRelative) {
      NewTop = (OldTop - static_cast<int8_t>(Selected.TopOffset)) & 7;
    } else if (Selected.Mode & TopConstant) {
      NewTop = Selected.Top & 7;
    } else if (Selected.Mode & TopPending) {
      __uint128_t Top;
      if (!Read(Selected.Top, Top)) return false;
      NewTop = static_cast<unsigned>(Top) & 7;
    }
  }
  __uint128_t Values[8] {};
  for (unsigned i = 0; i < 8; ++i) {
    if ((Selected.ValueMask & (1U << i)) && !Read(Selected.Values[i], Values[i])) return false;
  }
  // Everything read: apply as the block's own synchronization would (values relative to the new TOP, then tags, then TOP).
  for (unsigned i = 0; i < 8; ++i) {
    if (!(Selected.ValueMask & (1U << i))) continue;
    memcpy(State.mm[(NewTop + i) & 7], &Values[i], (Selected.Mode & Values64) ? 8 : 16);
  }
  for (unsigned i = 0; i < 8; ++i) {
    const uint8_t Bit = 1U << ((NewTop + i) & 7);
    if (Selected.ValidMask & (1U << i)) State.AbridgedFTW |= Bit;
    if (Selected.InvalidMask & (1U << i)) State.AbridgedFTW &= ~Bit;
  }
  State.flags[X86State::X87FLAG_TOP_LOC] = NewTop;
  return true;
}
} // namespace FEXCore::Core::X87Fault

std::atomic<MRCallRet::ZeroHookFn> MRCallRet::ZeroHook {nullptr};
std::atomic<uint64_t> MRCallRet::Grows {0};
// ★ MacRunner FEXXFER MACRUNNER_FEX_HEADER_BY_PC (Interface/Core/MRHeaderByPC.h): resolve / probe of InlineJITBlockHeader readers.
namespace MRHeaderByPC {
namespace {
struct ReaderStats {
  std::atomic<uint64_t> Checks {}, Same {}, Diff {}, NoUnit {}, Poison {}, CtlOk {}, CtlBad {}, Printed {};
};
ReaderStats Stats[ReaderCount];
const char* const Names[ReaderCount] = {"restore_rip", "x87_region", "x87_fault", "code_buffer", "compact_loop", "unaligned_atomic"};
constexpr uint64_t PoisonValue = 0xF00DFEEDDEADBEEFULL;   // the lookup must overwrite it on every path
bool UnitContains(uint64_t Begin, uint64_t Address) {
  if (!Begin || Address < Begin) {
    return false;
  }
  const auto* Header = reinterpret_cast<const FEXCore::CPU::CPUBackend::JITCodeHeader*>(Begin);
  const auto* Tail = reinterpret_cast<const FEXCore::CPU::CPUBackend::JITCodeTail*>(Begin + Header->OffsetToBlockTail);
  return Address < Begin + Tail->Size;
}
void Print(unsigned R, const char* Why, uint64_t Address, uint64_t Stored, uint64_t Found) {
  const auto& S = Stats[R];
  char Line[384];
  const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
    "macrunner-fex-header-probe: reader={} why={} checks={} same={} diff={} nounit={} poison={} ctl_ok={} ctl_bad={} addr={:x} stored={:x} found={:x}\n",
    Names[R], Why, S.Checks.load(), S.Same.load(), S.Diff.load(), S.NoUnit.load(), S.Poison.load(), S.CtlOk.load(), S.CtlBad.load(), Address,
    Stored, Found);
  Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
  FEX::Windows::Logging::Raw(Line);
}
} // namespace

bool Lazy(FEXCore::Context::ContextImpl* CTX) {
  return FEXCore::Utils::MacRunnerHeaderByPCMode() == 1 && CTX && !CTX->CodeCache.EnableCodeCaching;
}

void Resolve(FEXCore::Core::InternalThreadState* Thread, uint64_t HostAddress, unsigned R) noexcept {
  const unsigned Mode = FEXCore::Utils::MacRunnerHeaderByPCMode();
  if (!Mode || !Thread || !Thread->CPUBackend || !Thread->CurrentFrame || R >= ReaderCount) {
    return;
  }
  if (Mode == 1) {
    if (!Lazy(static_cast<FEXCore::Context::ContextImpl*>(Thread->CTX))) {
      return;
    }
    uint64_t Found = 0;
    Thread->CPUBackend->MRFindUnitBegin(HostAddress, &Found);
    Thread->CurrentFrame->State.InlineJITBlockHeader = Found;
    return;
  }
  // Mode 2: probe only, the field stays what the entries stored.
  auto& S = Stats[R];
  const uint64_t Stored = Thread->CurrentFrame->State.InlineJITBlockHeader;
  uint64_t Found = PoisonValue;
  Thread->CPUBackend->MRFindUnitBegin(HostAddress, &Found);
  const uint64_t N = S.Checks.fetch_add(1, std::memory_order_relaxed) + 1;
  const char* Bad = nullptr;
  if (Found == PoisonValue) {
    S.Poison.fetch_add(1, std::memory_order_relaxed);
    Bad = "poison";
  } else if (Found) {
    if (Found == Stored) {
      S.Same.fetch_add(1, std::memory_order_relaxed);
    } else {
      S.Diff.fetch_add(1, std::memory_order_relaxed);
      Bad = "diff";
    }
  } else if (UnitContains(Stored, HostAddress)) {
    S.Diff.fetch_add(1, std::memory_order_relaxed);   // the stored unit contains the address, the table did not find it
    Bad = "miss";
  } else {
    S.NoUnit.fetch_add(1, std::memory_order_relaxed);
  }
  if (Stored) {
    // Negative control: the byte before the stored unit is never inside it, so the comparison above can fail.
    uint64_t Before = PoisonValue;
    Thread->CPUBackend->MRFindUnitBegin(Stored - 1, &Before);
    (Before != Stored && Before != PoisonValue ? S.CtlOk : S.CtlBad).fetch_add(1, std::memory_order_relaxed);
  }
  if (Bad && S.Printed.fetch_add(1, std::memory_order_relaxed) < 16) {
    Print(R, Bad, HostAddress, Stored, Found);
  } else if ((N & (N - 1)) == 0) {
    Print(R, "count", HostAddress, Stored, Found);
  }
}
} // namespace MRHeaderByPC

namespace FEXCore::Context {
ContextImpl::ContextImpl(const FEXCore::HostFeatures& Features)
  : HostFeatures {Features}
  , CPUID {this}
  , CodeCache {*this} {
  if (!Config.Is64BitMode()) {
    // When operating in 32-bit mode, the virtual memory we care about is only the lower 32-bits.
    Config.VirtualMemSize = 1ULL << 32;
  }

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Only initialize symbols file if enabled. Ensures we don't pollute /tmp with empty files.
    Symbols.InitFile();
  }

  uint64_t FrequencyCounter = FEXCore::GetCycleCounterFrequency();
  if (FrequencyCounter && FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM && Config.SmallTSCScale()) {
    // Scale TSC until it is at the minimum required.
    while (FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM) {
      FrequencyCounter <<= 1;
      ++Config.TSCScale;
    }
  }

  // Track atomic TSO emulation configuration.
  UpdateAtomicTSOEmulationConfig();
}

struct GetFrameBlockInfoResult {
  const CPU::CPUBackend::JITCodeHeader* InlineHeader;
  const CPU::CPUBackend::JITCodeTail* InlineTail;
};
static GetFrameBlockInfoResult GetFrameBlockInfo(FEXCore::Core::CpuStateFrame* Frame) {
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto InlineHeader = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(BlockBegin);

  if (InlineHeader) {
    auto InlineTail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail);
    return {InlineHeader, InlineTail};
  }

  return {InlineHeader, nullptr};
}

bool ContextImpl::IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && (Address + Size > InlineTail->RIP && Address < InlineTail->RIP + InlineTail->GuestSize);
}

bool ContextImpl::IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && InlineTail->SingleInst;
}

uint64_t ContextImpl::GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail ? InlineTail->RIP : 0;
}

uint64_t ContextImpl::RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) {
  MRHeaderByPC::Resolve(Thread, HostPC, MRHeaderByPC::RestoreRIP);   // ★ MacRunner FEXXFER (mode 0: nothing)
  const auto Frame = Thread->CurrentFrame;
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto [InlineHeader, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);

  if (InlineHeader) {
    // Check if the host PC is currently within a code block.
    // If it is then RIP can be reconstructed from the beginning of the code block.
    // This is currently as close as FEX can get RIP reconstructions.
    if (HostPC >= reinterpret_cast<uint64_t>(BlockBegin) && HostPC < reinterpret_cast<uint64_t>(BlockBegin + InlineTail->Size)) {

      auto RIPEntry =
        reinterpret_cast<const uint8_t*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail + InlineTail->OffsetToRIPEntries);

      // Reconstruct RIP from JIT entries for this block.
      uint64_t StartingHostPC = BlockBegin;
      uint64_t StartingGuestRIP = InlineTail->RIP;

      for (uint32_t i = 0; i < InlineTail->NumberOfRIPEntries; ++i) {
        auto Offset = FEXCore::Utils::vl64pair::Decode(RIPEntry);
        RIPEntry += Offset.Size;
        if (HostPC >= (StartingHostPC + Offset.IntegerARMPC)) {
          // We are beyond this entry, keep going forward.
          StartingHostPC += Offset.IntegerARMPC;
          StartingGuestRIP += Offset.IntegerX86RIP;
        } else {
          // Passed where the Host PC is at. Break now.
          break;
        }
      }
      return StartingGuestRIP;
    }
  }

  // Fallback to what is stored in the RIP currently.
  return Frame->State.rip;
}

uint32_t ContextImpl::ReconstructCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, bool WasInJIT, const uint64_t* HostGPRs,
                                                 uint64_t PSTATE) {
  const auto Frame = Thread->CurrentFrame;
  uint32_t EFLAGS {};

  // The bytes beginning at RFLAG_NZCV_LOC are private FEX packed
  // PSTATE storage, not architectural guest RFLAGS. Reconstruct its four
  // conditions below; never expose the private word as reserved high bits.
  // LAZY-FLAGS (EFlags mask, unconditional since 21.10.2026): this used to hold only under
  // MACRUNNER_WINCTX_EXACT, so without it a 32-bit exception context showed 0x20000246 /
  // 0x60000246 where Windows shows 0x10246. Bits 24..31 are reserved in EFLAGS; the setter below
  // rebuilds the packed word from CF/ZF/SF/OF, so nothing reads them back.
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    if (i >= X86State::RFLAG_NZCV_LOC) continue;
    switch (i) {
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_PF_RAW_LOC:
    case X86State::RFLAG_AF_RAW_LOC:
    case X86State::RFLAG_TF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_DF_RAW_LOC:
      // Intentionally do nothing.
      // These contain multiple bits which can corrupt other members when compacted.
      break;
    default: EFLAGS |= uint32_t {Frame->State.flags[i]} << i; break;
    }
  }

  uint32_t Packed_NZCV {};
  if (WasInJIT) {
    // If we were in the JIT then NZCV is in the CPU's PSTATE object.
    // Packed in to the same bit locations as RFLAG_NZCV_LOC.
    Packed_NZCV = PSTATE;

    // If we were in the JIT then PF and AF are in registers.
    // Move them to the CPUState frame now.
    Frame->State.pf_raw = HostGPRs[CPU::REG_PF.Idx()];
    Frame->State.af_raw = HostGPRs[CPU::REG_AF.Idx()];
  } else {
    // If we were not in the JIT then the NZCV state is stored in the CPUState RFLAG_NZCV_LOC.
    // SF/ZF/CF/OF are packed in a 32-bit value in RFLAG_NZCV_LOC.
    memcpy(&Packed_NZCV, &Frame->State.flags[X86State::RFLAG_NZCV_LOC], sizeof(Packed_NZCV));
  }

  uint32_t OF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC)) & 1;
  uint32_t CF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC)) & 1;
  uint32_t ZF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC)) & 1;
  uint32_t SF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC)) & 1;

  // CF is inverted in our representation, undo the invert here.
  CF ^= 1;

  // Pack in to EFLAGS
  EFLAGS |= OF << X86State::RFLAG_OF_RAW_LOC;
  EFLAGS |= CF << X86State::RFLAG_CF_RAW_LOC;
  EFLAGS |= ZF << X86State::RFLAG_ZF_RAW_LOC;
  EFLAGS |= SF << X86State::RFLAG_SF_RAW_LOC;

  // PF calculation is deferred, calculate it now.
  // Popcount the 8-bit flag and then extract the lower bit.
  uint32_t PFByte = Frame->State.pf_raw & 0xff;
  uint32_t PF = std::popcount(PFByte ^ 1) & 1;
  EFLAGS |= PF << X86State::RFLAG_PF_RAW_LOC;

  // AF calculation is deferred, calculate it now.
  // XOR with PF byte and extract bit 4.
  uint32_t AF = ((Frame->State.af_raw ^ PFByte) & (1 << 4)) ? 1 : 0;
  EFLAGS |= AF << X86State::RFLAG_AF_RAW_LOC;

  uint8_t TFByte = Frame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  EFLAGS |= (TFByte & 1) << X86State::RFLAG_TF_RAW_LOC;

  // DF is pretransformed, undo the transform from 1/-1 back to 0/1
  uint8_t DFByte = Frame->State.flags[X86State::RFLAG_DF_RAW_LOC];
  if (DFByte & 0x80) {
    EFLAGS |= 1 << X86State::RFLAG_DF_RAW_LOC;
  }

  return EFLAGS;
}

void ContextImpl::ReconstructXMMRegisters(const FEXCore::Core::InternalThreadState* Thread, __uint128_t* XMM_Low, __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;

  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.avx.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.xmm.avx.data[i][2], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.sse.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.avx_high[i][0], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(XMM_Low, Thread->CurrentFrame->State.xmm.sse.data, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetXMMRegistersFromState(FEXCore::Core::InternalThreadState* Thread, const __uint128_t* XMM_Low, const __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;
  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][2], &YMM_High[i], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.sse.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.avx_high[i][0], &YMM_High[i], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(Thread->CurrentFrame->State.xmm.sse.data, XMM_Low, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetFlagsFromCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, uint32_t EFLAGS) {
  const auto Frame = Thread->CurrentFrame;
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
      // Intentionally do nothing.
      break;
    case X86State::RFLAG_AF_RAW_LOC:
      // AF stored in bit 4 in our internal representation. It is also
      // XORed with byte 4 of the PF byte, but we write that as zero here so
      // we don't need any special handling for that.
      Frame->State.af_raw = (EFLAGS & (1U << i)) ? (1 << 4) : 0;
      break;
    case X86State::RFLAG_PF_RAW_LOC:
      // PF is inverted in our internal representation.
      Frame->State.pf_raw = (EFLAGS & (1U << i)) ? 0 : 1;
      break;
    case X86State::RFLAG_DF_RAW_LOC:
      // DF is encoded as 1/-1
      Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 0xff : 1;
      break;
    default: Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 1 : 0; break;
    }
  }

  // Calculate packed NZCV. Note CF is inverted.
  uint32_t Packed_NZCV {};
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_OF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_CF_RAW_LOC)) ? 0 : 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC);
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_ZF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_SF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC) : 0;
  memcpy(&Frame->State.flags[X86State::RFLAG_NZCV_LOC], &Packed_NZCV, sizeof(Packed_NZCV));

  // Reserved, Read-As-1, Write-as-1
  Frame->State.flags[X86State::RFLAG_RESERVED_LOC] = 1;
  // Interrupt Flag. Can't be written by CPL-3 userland.
  Frame->State.flags[X86State::RFLAG_IF_LOC] = 1;
}

bool ContextImpl::InitCore() {
  // ★ MacRunner (Claude, 23.09.2026) — MACRUNNER_FEX_CODEBUF_MAX=1: буфер кода сразу 128 МБ.
  //   Буфер растёт 16 -> 32 -> 64 -> 128 МБ, и КАЖДЫЙ рост — новый буфер с выбросом всего перевода
  //   (ClearCodeCache, flush_new). В Elden Ring 098..102 flush_new = 5–6: три из них — только рост,
  //   выброшено до 112 МБ готового кода. Upstream делает то же самое при кэше кода (строка ниже) —
  //   переключатель включает это без остального механизма кэша. Память macOS занимается по записи.
  static const bool MRCodeBufMax = [] {
    const char* Value = getenv("MACRUNNER_FEX_CODEBUF_MAX");
    return Value && Value[0] == '1' && !Value[1];
  }();
  if (CodeCache.IsGeneratingCache || FEXCore::Config::Get_ENABLECODECACHINGWIP() || MRCodeBufMax) {
    // Start with a larger code buffer to avoid resizes that would discard code
    StartMaximalCodeBuffer();
  }

  // Initialize the CPU core signal handlers & DispatcherConfig
  Dispatcher = FEXCore::CPU::Dispatcher::Create(this);

  // Set up the SignalDelegator config since core is initialized.
  SignalDelegation->SetConfig(Dispatcher->MakeSignalDelegatorConfig());

#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
  // WOW64 always needs the interrupt fault check to be enabled.
  Config.NeedsPendingInterruptFaultCheck = true;
#endif

  if (Config.GdbServer) {
    // If gdbserver is enabled then this needs to be enabled.
    Config.NeedsPendingInterruptFaultCheck = true;
  }

  if constexpr (BLOCK_DEBUGGING) {
    // If the developer wants to do any single-stepping points or watch points.
    // Add them here.
    //
    // eg:
    // BlockDebuggerTracker.AllTargetSingleStep();
    // BlockDebuggerTracker.AddSingleStepTarget(0x14000'0000ULL);
    // BlockDebuggerTracker.AddWriteWatchPoint(0x420BA5ED);
  }

  return true;
}

void ContextImpl::HandleCallback(FEXCore::Core::InternalThreadState* Thread, uint64_t RIP) {
  static_cast<ContextImpl*>(Thread->CTX)->Dispatcher->ExecuteJITCallback(Thread->CurrentFrame, RIP);
}

void ContextImpl::ExecuteThread(FEXCore::Core::InternalThreadState* Thread) {
  // Update the thread pointer for Thunk return to the latest.
  Thread->CurrentFrame->Pointers.ThunkCallbackRet = SignalDelegation->GetThunkCallbackRET();

  Dispatcher->ExecuteDispatch(Thread->CurrentFrame);

  // If it is the parent thread that died then just leave
  // TODO: This doesn't make sense when the parent thread doesn't outlive its children
}

void ContextImpl::InitializeCompiler(FEXCore::Core::InternalThreadState* Thread) {
  Thread->OpDispatcher = fextl::make_unique<FEXCore::IR::OpDispatchBuilder>(this, Thread);
  Thread->OpDispatcher->SetMultiblock(Config.Multiblock);
  Thread->LookupCache = fextl::make_unique<FEXCore::LookupCache>(this);
  Thread->FrontendDecoder = fextl::make_unique<FEXCore::Frontend::Decoder>(Thread);
  Thread->PassManager = fextl::make_unique<FEXCore::IR::PassManager>(this);

  Thread->CurrentFrame->State.L1Pointer = Thread->LookupCache->GetL1Pointer();
  Thread->CurrentFrame->State.L1Mask = Thread->LookupCache->GetScaledL1PointerMask();

  Thread->CurrentFrame->Pointers.L2Pointer = Thread->LookupCache->GetPagePointer();

  Dispatcher->InitThreadPointers(Thread);

  // Create CPU backend
  Thread->CPUBackend = FEXCore::CPU::CreateArm64JITCore(this, Thread);

  // We finalize *after* the CPU backend is initialized, as the CPU backend will
  // provide necessary register information to the register allocation pass.
  Thread->PassManager->Finalize();
}

FEXCore::Core::InternalThreadState*
ContextImpl::CreateThread(uint64_t InitialRIP, uint64_t StackPointer, const FEXCore::Core::CPUState* NewThreadState) {
  FEXCore::Core::InternalThreadState* Thread = new FEXCore::Core::InternalThreadState {
    .CTX = this,
  };
  FEXCore::Allocator::VirtualName("FEXMem_ThreadState", Thread, sizeof(*Thread));

  Thread->CurrentFrame->State.gregs[X86State::REG_RSP] = StackPointer;
  Thread->CurrentFrame->State.rip = InitialRIP;

  // Copy over the new thread state to the new object
  if (NewThreadState) {
    memcpy(&Thread->CurrentFrame->State, NewThreadState, sizeof(FEXCore::Core::CPUState));
  }

  // Set up the thread manager state
  Thread->CurrentFrame->Thread = Thread;

  InitializeCompiler(Thread);

  Thread->CurrentFrame->State.DeferredSignalRefCount.Store(0);

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Allocate a JIT symbol buffer only if enabled.
    Thread->SymbolBuffer = JITSymbols::AllocateBuffer();
  }

  return Thread;
}

void ContextImpl::DestroyThread(FEXCore::Core::InternalThreadState* Thread) {
  FEXCore::Allocator::VirtualProtect(&Thread->InterruptFaultPage, sizeof(Thread->InterruptFaultPage),
                                     Allocator::ProtectOptions::Read | Allocator::ProtectOptions::Write);
  delete Thread;
}

#ifndef _WIN32
void ContextImpl::UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child) {
  Allocator::UnlockAfterFork(LiveThread, Child);

  Profiler::PostForkAction(Child);
  if (Child) {
    if (CodeMapWriter) {
      CodeMapWriter->ResetAfterFork();
    }

    CodeInvalidationMutex.StealAndDropActiveLocks();
    if (Config.StrictInProcessSplitLocks) {
      StrictSplitLockMutex = 0;
    }
  } else {
    CodeInvalidationMutex.unlock();
    if (Config.StrictInProcessSplitLocks) {
      FEXCore::Utils::SpinWaitLock::unlock(&StrictSplitLockMutex);
    }
  }
}

void ContextImpl::LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) {
  CodeInvalidationMutex.lock();
  Allocator::LockBeforeFork(Thread);
  if (Config.StrictInProcessSplitLocks) {
    FEXCore::Utils::SpinWaitLock::lock(&StrictSplitLockMutex);
  }
}
#endif

void ContextImpl::OnCodeBufferAllocated(const fextl::shared_ptr<CPU::CodeBuffer>& Buffer) {
  if (Config.GlobalJITNaming()) {
    Symbols.RegisterJITSpace(Buffer->Ptr, Buffer->AllocatedSize);
  }

  {
    std::scoped_lock lk {CodeBufferListLock};
    CodeBufferList.emplace_back(Buffer);
  }
}

void ContextImpl::ClearCodeCache(FEXCore::Core::InternalThreadState* Thread, bool NewCodeBuffer) {
  FEXCORE_PROFILE_INSTANT("ClearCodeCache");
  // ★ MacRunner (HG2, MACRUNNER_FEX_HOOK_GUARD): новый буфер кода (VirtualAlloc исполняемой памяти) и освобождение прежнего (VirtualFree) идут через хуки NotifyMemoryAlloc/Free
  //   на замке компиляции; кандидат на ДОЛГ ER-CODEBUF-ЗАВИСАНИЕ.
  MRRuntimeSectionGuard MRSectionGuard {SyscallHandler, FEXCore::HLE::SyscallHandler::RuntimeSection::ClearCodeCache};
  (NewCodeBuffer ? MRFlushNew : MRFlushL12).fetch_add(1, std::memory_order_relaxed);
  // Возврат перевода: весь прежний код и записи связей уходят — таблица больше не годится.
  MRReviveEpoch.fetch_add(1, std::memory_order_relaxed);
  {
    std::scoped_lock ReviveLock(MRReviveLock);
    MRReviveTable.clear();
  }

  if (NewCodeBuffer) {
    // Allocate new CodeBuffer + L3 LookupCache and clear L1+L2 caches
    Thread->CPUBackend->ClearCache();
  } else {
    // Clear L1+L2 cache of this thread, and clear L3 cache across any threads using it
    auto lk = Thread->LookupCache->AcquireWriteLock();
    Thread->LookupCache->ClearCache(lk);
  }
  MRCallRet::Zero(Thread);
}

static void IRDumper(FEXCore::Core::InternalThreadState* Thread, IR::IREmitter* IREmitter, uint64_t GuestRIP) {
  FEXCore::File::File FD = FEXCore::File::File::GetStdERR();
  fextl::ostringstream out;
  auto NewIR = IREmitter->ViewIR();
  FEXCore::IR::Dump(&out, &NewIR);
  fextl::fmt::print(FD, "IR-ShouldDump-{} 0x{:x}:\n{}\n@@@@@\n", NewIR.PostRA() ? "post" : "pre", GuestRIP, out.str());
}

bool ContextImpl::CheckIfBlockIsCacheable(FEXCore::Core::InternalThreadState& Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  return Thread.FrontendDecoder->CheckIfCacheable(Thread, reinterpret_cast<const uint8_t*>(GuestRIP), GuestRIP, MaxInst);
}

ContextImpl::GenerateIRResult
ContextImpl::GenerateIR(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool ExtendedDebugInfo, uint64_t MaxInst) {
  FEXCORE_PROFILE_SCOPED("GenerateIR");

  Thread->OpDispatcher->ResetWorkingList();

  uint64_t TotalInstructions {0};
  uint64_t TotalInstructionsLength {0};

  bool HasCustomIR {};

  if (HasCustomIRHandlers.load(std::memory_order_relaxed)) {
    std::shared_lock lk(CustomIRMutex);
    auto Handler = CustomIRHandlers.find(GuestRIP);
    if (Handler != CustomIRHandlers.end()) {
      TotalInstructions = 1;
      TotalInstructionsLength = 1;
      Handler->second.Handler(GuestRIP, Thread->OpDispatcher.get());
      HasCustomIR = true;
    }
  }

  if (!HasCustomIR) {
    const auto* GuestCode = reinterpret_cast<const uint8_t*>(GuestRIP);

    Thread->FrontendDecoder->DecodeInstructionsAtEntry(Thread, GuestCode, GuestRIP, MaxInst);

    const auto* BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    const auto& CodeBlocks = BlockInfo->Blocks;

    // Invalidating the block cache does not interrupt a native branch which
    // stays inside the currently running multiblock. Writable code in such a
    // loop must still validate its bytes, even on fully trapped host pages.
    // Address order alone is not a cycle: Mono commonly puts a shared return
    // epilogue before its cold callers. Build the decoded control-flow graph
    // and remove acyclic nodes before deciding whether byte validation is
    // needed to escape a running native loop.
    fextl::vector<fextl::vector<size_t>> InternalEdges(CodeBlocks.size());
    fextl::vector<size_t> Incoming(CodeBlocks.size(), 0);
    auto AddInternalEdge = [&](size_t Source, uint64_t Target) {
      if (!BlockInfo->Is64BitMode) Target &= 0xFFFFFFFFU;
      for (size_t Index = 0; Index < CodeBlocks.size(); ++Index) {
        const auto& Destination = CodeBlocks[Index];
        if (Destination.NumInstructions && Target >= Destination.Entry && Target - Destination.Entry < Destination.Size) {
          InternalEdges[Source].push_back(Index);
          ++Incoming[Index];
          return;
        }
      }
    };
    for (size_t Index = 0; Index < CodeBlocks.size(); ++Index) {
      const auto& Candidate = CodeBlocks[Index];
      if (!Candidate.NumInstructions) continue;
      const auto& Branch = Candidate.DecodedInstructions[Candidate.NumInstructions - 1];
      if (!Branch.TableInfo) continue;
      const auto Flags = Branch.TableInfo->Flags;
      const bool Call = Flags & FEXCore::X86Tables::InstFlags::FLAGS_CALL;
      const bool SetsRIP = Flags & FEXCore::X86Tables::InstFlags::FLAGS_SETS_RIP;
      const bool EndsBlock = Flags & FEXCore::X86Tables::InstFlags::FLAGS_BLOCK_END;
      const bool Unconditional = Branch.OP == 0xE9 || Branch.OP == 0xEB;
      const bool Conditional = (Branch.OP >= 0x70 && Branch.OP <= 0x8F) || (Branch.OP >= 0xE0 && Branch.OP <= 0xE3);
      const auto& Displacement = Branch.Src[(Branch.OP >= 0xE0 && Branch.OP <= 0xE2) ? 1 : 0];
      if (SetsRIP && !Call && Displacement.IsLiteral() && (Unconditional || Conditional)) {
        AddInternalEdge(Index, Branch.PC + Branch.InstSize + Displacement.Literal());
      }
      // Calls leave this native unit. Their return cache is cleared by
      // InvalidateThreadCachedCodeRange, and linked targets are unlinked by
      // GuestToHostMap::Erase. A possible call return is therefore not an
      // uninterrupted native-loop edge (unlike a direct internal branch).
      if (!Call && ((SetsRIP && Conditional) || (!SetsRIP && !EndsBlock))) {
        AddInternalEdge(Index, Branch.PC + Branch.InstSize);
      }
    }
    fextl::vector<size_t> Acyclic;
    for (size_t Index = 0; Index < Incoming.size(); ++Index) {
      if (!Incoming[Index]) Acyclic.push_back(Index);
    }
    for (size_t Next = 0; Next < Acyclic.size(); ++Next) {
      for (const auto Target : InternalEdges[Acyclic[Next]]) {
        if (!--Incoming[Target]) Acyclic.push_back(Target);
      }
    }
    const bool HasInternalBackedge = Acyclic.size() != CodeBlocks.size();
#ifdef HB_GAMES_COMPILE_ONLY
    if (const auto Trace = getenv("VM_ARENA_TRACE_CFG_RIP"); Trace && strtoull(Trace, nullptr, 0) == GuestRIP) {
      fprintf(stderr, "vm-arena-cfg rip=%llx blocks=%zu acyclic=%zu cycle=%u\n", (unsigned long long)GuestRIP,
              CodeBlocks.size(), Acyclic.size(), unsigned(HasInternalBackedge));
      for (size_t Index = 0; Index < CodeBlocks.size(); ++Index) {
        fprintf(stderr, "vm-arena-cfg-node index=%zu rip=%llx size=%u edges=", Index,
                (unsigned long long)CodeBlocks[Index].Entry, unsigned(CodeBlocks[Index].Size));
        for (const auto Target : InternalEdges[Index]) fprintf(stderr, "%zu,", Target);
        fprintf(stderr, "\n");
      }
    }
#endif

    Thread->OpDispatcher->BeginFunction(GuestRIP, &CodeBlocks, BlockInfo->TotalInstructionCount, BlockInfo->Is64BitMode,
                                        AreMonoHacksActive() && MonoBackpatcherBlock.load(std::memory_order_relaxed) == GuestRIP);

    const auto GPRSize = Thread->OpDispatcher->GetGPROpSize();

#ifdef ZYDIS_DISASSEMBLER
    const auto ZydisMachineMode = Config.Is64BitMode ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      const uint64_t DecodedMin = Thread->FrontendDecoder->DecodedMinAddress;
      const uint64_t DecodedMax = Thread->FrontendDecoder->DecodedMaxAddress;
      LogMan::Msg::IFmt("Guest x86 Begin (RIP={:#x}, {:#x}-{:#x})", GuestRIP, DecodedMin, DecodedMax);
    }
#endif

#ifdef ARCHITECTURE_arm64ec
    const bool MRDebugBreakpoint = MaxInst == 1 && MacRunnerWinctxExecuteBreakpoint(Thread->CurrentFrame, GuestRIP);
#endif
    for (size_t j = 0; j < CodeBlocks.size(); ++j) {
      const auto& Block = CodeBlocks[j];

      // Dispatch failures and invalid instructions terminate only the decoded
      // block that contains them. Other block targets in the same multiblock
      // compilation unit are independent entry paths.
      bool HadDispatchError {false};
      bool HadInvalidInst {false};

#ifdef ZYDIS_DISASSEMBLER
      if (FEXCore::Config::Get_X86DISASSEMBLE() && CodeBlocks.size() > 1) {
        LogMan::Msg::IFmt("  Block {} Entry={:#x} NumInsts={}", j, Block.Entry, Block.NumInstructions);
      }
#endif

      bool BlockInForceTSOValidRange = false;
      auto InstForceTSOIt = ForceTSOInstructions.end();
      if (ForceTSOValidRanges.Contains({Block.Entry, Block.Entry + Block.Size})) {
        if (auto It = ForceTSOInstructions.lower_bound(Block.Entry); It != ForceTSOInstructions.end() && *It < Block.Entry + Block.Size) {
          InstForceTSOIt = It;
          BlockInForceTSOValidRange = true;
        }
      }

      // Set the block entry point
      Thread->OpDispatcher->SetNewBlockIfChanged(Block.Entry);

      // Reset any block-specific state
      Thread->OpDispatcher->StartNewBlock();

      const uint64_t InstsInBlock = Block.NumInstructions;
#ifdef ARCHITECTURE_arm64ec
      if (MRDebugBreakpoint) {
        IR::BreakDefinition Reason {};
        Reason.Signal = Core::FAULT_SIGTRAP;
        Reason.TrapNumber = X86State::X86_TRAPNO_DB;
        Reason.si_code = 1;
        // StoreContext consumes an allocated GPR. An InlineEntrypointOffset
        // is a no-op marker for accepting consumers, not a materialized value.
        // Keep a fault-boundary opcode marker and materialize this entry RIP.
        Thread->OpDispatcher->_GuestOpcode(0);
        Thread->OpDispatcher->_StoreContextGPR(GPRSize,
          Thread->OpDispatcher->_EntrypointOffset(GPRSize, 0), offsetof(Core::CPUState, rip));
        Thread->OpDispatcher->Break(Reason);
        TotalInstructions = 1;
        TotalInstructionsLength = 1;
        break;
      }
#endif
      // A PE32 bank crosses GPR leaf blocks too: their fallthrough RIP
      // and flags remain observable on asynchronous recovery.
      bool X87RecoveryBoundaries = FEXCore::HBX87::StaticRegsEnabled() && !Config.Is64BitMode();
      if (FEXCore::HBX87::RegionEnabled(!Config.Is64BitMode()) ||
          (FEXCore::HBX87::StaticRegsEnabled() && !Config.Is64BitMode())) {
        const auto FirstX87 = reinterpret_cast<uintptr_t>(X86Tables::X87F80Ops.data());
        for (size_t i = 0; i < InstsInBlock; ++i) {
          const auto Table = reinterpret_cast<uintptr_t>(Block.DecodedInstructions[i].TableInfo);
          X87RecoveryBoundaries |= Table >= FirstX87 && Table < FirstX87 + sizeof(X86Tables::X87F80Ops);
        }
      }
      if (InstsInBlock == 0) {
        // Special case for an empty instruction block.
        Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry - GuestRIP));
      }

      uint64_t BlockInstructionsLength {};
      for (size_t i = 0; i < InstsInBlock; ++i) {
        uint64_t InstAddress = Block.Entry + BlockInstructionsLength;
        const FEXCore::X86Tables::X86InstInfo* TableInfo {nullptr};
        const FEXCore::X86Tables::DecodedInst* DecodedInfo {nullptr};

        TableInfo = Block.DecodedInstructions[i].TableInfo;
        DecodedInfo = &Block.DecodedInstructions[i];

#ifdef ZYDIS_DISASSEMBLER
        if (FEXCore::Config::Get_X86DISASSEMBLE()) {
          const uint8_t* InstBytes = reinterpret_cast<const uint8_t*>(InstAddress);
          ZydisDisassembledInstruction ZydisInst;
          if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZydisMachineMode, InstAddress, InstBytes, DecodedInfo->InstSize, &ZydisInst))) {
            LogMan::Msg::IFmt("    {:#x}: {}", InstAddress, ZydisInst.text);
          } else {
            LogMan::Msg::IFmt("    {:#x}: (decode failed, {} bytes)", InstAddress, DecodedInfo->InstSize);
          }
        }
#endif

        bool IsLocked = DecodedInfo->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK;

        // Do a partial register cache flush before every instruction. This
        // prevents cross-instruction static register caching, while allowing
        // context load/stores to be optimized within a block. Theoretically,
        // this flush is not required for correctness, all mandatory flushes are
        // included in instruction-specific handlers. Instead, this is a blunt
        // heuristic to make the register cache less aggressive, as the current
        // RA generates bad code in common cases with tied registers otherwise.
        //
        // However, it makes our exception handling behaviour more predictable.
        // It is potentially correctness bearing in that sense, but that is a
        // side effect here and (if that behaviour is required) we should handle
        // that more explicitly later.
        const bool FaultBoundary = Thread->OpDispatcher->CanHaveSideEffects(TableInfo, DecodedInfo);
        Thread->OpDispatcher->FlushRegisterCache(true, false, FaultBoundary);

        if (ExtendedDebugInfo || FaultBoundary || X87RecoveryBoundaries) {
          Thread->OpDispatcher->_GuestOpcode(InstAddress - GuestRIP);
        }

        // Mixed host-page permissions can hide guest writes from write-fault tracking.
        bool ValidateWritableCode = false;
        if (Config.SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK) {
          const int ValidationMode = MRWritableValidationMode();
          if (ValidationMode) {
            FEXCore::HLE::ExecutableRangeInfo Range;
            uint64_t MRCached[3];
            Thread->FrontendDecoder->MRGetCachedRange(MRCached);
            if (MRRangeCacheOn() && MRCached[1] > MRCached[0] && InstAddress >= MRCached[0] &&
                InstAddress + std::max<uint64_t>(DecodedInfo->InstSize, 1) <= MRCached[1] && !Thread->FrontendDecoder->MRCachedNoTrap()) {
              Range = {MRCached[0], MRCached[1] - MRCached[0], MRCached[2] != 0};
              MRRangeCached.fetch_add(1, std::memory_order_relaxed);
            } else {
              Range = SyscallHandler->QueryGuestExecutableRange(Thread, InstAddress);
              MRRangeQueries.fetch_add(1, std::memory_order_relaxed);
            }
            if (Range.Writable) {
              ValidateWritableCode = true;
              // ★ MacRunner (30.09.2026, ALIAS_VIEWS): NoTrap — страница защищена от записи ЭТИМ видом, а байты меняются через ДРУГОЙ вид
              //   тех же страниц; ловушка этого не видит, поэтому пропуск «целые страницы хоста под ловушкой» здесь неверен.
              if (ValidationMode >= 2 && !Range.NoTrap) {
#if defined(MACRUNNER_PROT_4K) && MACRUNNER_PROT_4K
                constexpr uint64_t HostPage = 0x1000;
#else
                constexpr uint64_t HostPage = 0x4000;
#endif
                const uint64_t First = InstAddress & ~(HostPage - 1);
                const uint64_t Last = (InstAddress + std::max<uint64_t>(DecodedInfo->InstSize, 1) - 1) & ~(HostPage - 1);
                const bool WholeHostPagesRWX = Range.Base <= First && Last + HostPage <= Range.Base + Range.Size;
                if (HasInternalBackedge && WholeHostPagesRWX && !Thread->OpDispatcher->WritableLoopCacheExit) {
                  // This optimization is only valid when the same trapped
                  // executable range covers every decoded block. Mixed pages
                  // and NoTrap aliases retain byte validation unchanged.
                  const bool WholeUnitTrapped = std::all_of(CodeBlocks.begin(), CodeBlocks.end(), [&](const auto& B) {
                    if (!B.NumInstructions) return true;
                    const auto Begin = B.Entry & ~(HostPage - 1);
                    const auto End = (B.Entry + B.Size - 1) & ~(HostPage - 1);
                    return Range.Base <= Begin && End + HostPage <= Range.Base + Range.Size;
                  });
                  Thread->OpDispatcher->WritableLoopCacheExit = WholeUnitTrapped;
                }
                const bool ControlTransfer = TableInfo && (TableInfo->Flags & (FEXCore::X86Tables::InstFlags::FLAGS_SETS_RIP |
                                                                               FEXCore::X86Tables::InstFlags::FLAGS_CALL |
                                                                               FEXCore::X86Tables::InstFlags::FLAGS_BLOCK_END));
                ValidateWritableCode = (HasInternalBackedge && !Thread->OpDispatcher->WritableLoopCacheExit) ||
                                       !WholeHostPagesRWX || (ValidationMode == 3 && ControlTransfer);
                if (WholeHostPagesRWX && !ValidateWritableCode) {
                  MRWritableSkipped.fetch_add(1, std::memory_order_relaxed);
                }
              }
            }
          }
        }
        if (ValidateWritableCode) {
          MRValidated.fetch_add(1, std::memory_order_relaxed);
        }
        if (Config.SMCChecks == FEXCore::Config::CONFIG_SMC_FULL || Block.ForceFullSMCDetection || ValidateWritableCode) {
          auto ExistingCodePtr = reinterpret_cast<uint8_t*>(Block.Entry + BlockInstructionsLength);
          auto InstAddressReg = Thread->OpDispatcher->_EntrypointOffset(GPRSize, InstAddress - GuestRIP);
          std::array<uint8_t, 0x10> CodeOriginal;
          memcpy(CodeOriginal.data(), ExistingCodePtr, DecodedInfo->InstSize);
          auto CodeChanged = Thread->OpDispatcher->_ValidateCode(CodeOriginal, InstAddressReg, DecodedInfo->InstSize);

          auto InvalidateCodeCond = Thread->OpDispatcher->CondJump(CodeChanged);

          auto CurrentBlock = Thread->OpDispatcher->GetCurrentBlock();
          auto CodeWasChangedBlock = Thread->OpDispatcher->CreateNewCodeBlockAtEnd();
          Thread->OpDispatcher->SetTrueJumpTarget(InvalidateCodeCond, CodeWasChangedBlock);

          Thread->OpDispatcher->SetCurrentCodeBlock(CodeWasChangedBlock);
          Thread->OpDispatcher->StartNewBlock();
          Thread->OpDispatcher->_ThreadRemoveCodeEntry();
          Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, InstAddress - GuestRIP));

          auto NextOpBlock = Thread->OpDispatcher->CreateNewCodeBlockAfter(CurrentBlock);

          Thread->OpDispatcher->SetFalseJumpTarget(InvalidateCodeCond, NextOpBlock);
          Thread->OpDispatcher->SetCurrentCodeBlock(NextOpBlock);
          Thread->OpDispatcher->StartNewBlock();
        }

#ifdef ARCHITECTURE_arm64ec
        // ★ MacRunner QPCJIT: the first instruction of ntdll's RtlQueryPerformanceCounter FFS (MacRunnerQpcInline.h). Every check that
        // could make the inline path differ from the FFS it replaces refuses it; the plain translation below is then emitted unchanged.
        if (FEXCore::Utils::MRQpcInline::G.Armed && i == 0 && InstAddress == FEXCore::Utils::MRQpcInline::G.Ffs && TableInfo &&
            TableInfo->OpcodeDispatcher.OpDispatch) {
          namespace MRQ = FEXCore::Utils::MRQpcInline;
          bool Ok = MaxInst != 1 && Config.SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK && !Block.ForceFullSMCDetection &&
                    !ValidateWritableCode && !CodeCache.IsGeneratingCache && !FEXCore::Config::Get_ENABLECODECACHINGWIP();
          if (Ok) {
            const auto Range = SyscallHandler->QueryGuestExecutableRange(Thread, InstAddress);
            Ok = !Range.Writable && !Range.NoTrap && Range.Base <= InstAddress && InstAddress + sizeof(MRQ::G.FfsBytes) <= Range.Base + Range.Size;
          }
          Ok = Ok && !memcmp(reinterpret_cast<const void*>(MRQ::G.Ffs), MRQ::G.FfsBytes, sizeof(MRQ::G.FfsBytes)) &&
               !memcmp(reinterpret_cast<const void*>(MRQ::G.Body), MRQ::G.BodyBytes, sizeof(MRQ::G.BodyBytes));
          if (Ok) {
            Thread->OpDispatcher->MacRunnerQpcInline(InstAddress - GuestRIP);
            MRQ::Sites.fetch_add(1, std::memory_order_relaxed);
          } else {
            MRQ::Refused.fetch_add(1, std::memory_order_relaxed);
          }
        }
#endif
        if (TableInfo && TableInfo->OpcodeDispatcher.OpDispatch) {
          auto Fn = TableInfo->OpcodeDispatcher.OpDispatch;
          Thread->OpDispatcher->ResetHandledLock();
          Thread->OpDispatcher->ResetDecodeFailure();
          IR::ForceTSOMode ForceTSO = IR::ForceTSOMode::NoOverride;
          if (BlockInForceTSOValidRange) {
            if (InstForceTSOIt != ForceTSOInstructions.end() && *InstForceTSOIt == InstAddress) {
              ForceTSO = IR::ForceTSOMode::ForceEnabled;
            } else {
              ForceTSO = IR::ForceTSOMode::ForceDisabled;
            }
          } else if (DecodedInfo->Flags & X86Tables::DecodeFlags::FLAG_FORCE_TSO) {
            ForceTSO = IR::ForceTSOMode::ForceEnabled;
          }

          Thread->OpDispatcher->SetForceTSO(ForceTSO);
          unsigned CoverageOpcode = FEXCore::HBX87::Coverage::Opcodes;
          IR::Ref CoverageCW {};
          if (FEXCore::HBX87::Coverage::Enabled()) {
            // Table identity, not DecodedInfo->OP: the decoder tables have
            // overlapping numeric opcode spaces. Capture the pre-instruction
            // FCW even for FLDCW/FNINIT/FNSTENV, then count only after effects.
            const auto table = reinterpret_cast<uintptr_t>(TableInfo);
            const auto first = reinterpret_cast<uintptr_t>(X86Tables::X87F80Ops.data());
            if (table >= first && table < first + sizeof(X86Tables::X87F80Ops)) {
              CoverageOpcode = (table - first) / sizeof(X86Tables::X86InstInfo);
              CoverageCW = Thread->OpDispatcher->_LoadContextGPR(IR::OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, FCW));
            }
          }
          if (GPRSize == IR::OpSize::i32Bit && DecodedInfo->OPRaw >= 0xD8 && DecodedInfo->OPRaw <= 0xDF) {
            Thread->OpDispatcher->TrackX87Instruction32(DecodedInfo);
          }
          // Before MMX/x87 transitions or any destination register mutation.
          Thread->OpDispatcher->CheckLegacyVectorAlignment(DecodedInfo);
          std::invoke(Fn, Thread->OpDispatcher, DecodedInfo);
          if (!Thread->OpDispatcher->HadDecodeFailure() && CoverageOpcode < FEXCore::HBX87::Coverage::Opcodes) {
            FEXCore::HBX87::Coverage::Emit(*Thread->OpDispatcher, CoverageOpcode, CoverageCW, FEXCore::HBX87::PC24());
          }
          if (Thread->OpDispatcher->HadDecodeFailure()) {
            HadDispatchError = true;
          } else {
            if (Thread->OpDispatcher->HasHandledLock() != IsLocked) {
              HadDispatchError = true;
              LogMan::Msg::EFmt("Missing LOCK HANDLER at 0x{:x}{{'{}'}}", InstAddress, TableInfo->Name ?: "UND");
            }
            BlockInstructionsLength += DecodedInfo->InstSize;
            TotalInstructionsLength += DecodedInfo->InstSize;
            ++TotalInstructions;

            // Walk InstForceTSOIt forward past the handled instruction
            InstForceTSOIt =
              std::find_if(InstForceTSOIt, ForceTSOInstructions.end(), [&](auto Val) { return Val >= Block.Entry + BlockInstructionsLength; });
          }
        } else {
          // Invalid instruction
          if (!BlockInstructionsLength) {
            // SMC can modify block contents and patch invalid instructions to valid ones inline.
            // End blocks upon encountering them and only emit an invalid opcode exception if there are no prior instructions in the block (that could have modified it to be valid).

            if (TableInfo) {
              LogMan::Msg::EFmt("Invalid or Unknown instruction: {} 0x{:x}", TableInfo->Name ?: "UND", Block.Entry - GuestRIP);
            }

            if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::INVALID_INST ||
                Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::BAD_RELOCATION) {
              Thread->OpDispatcher->InvalidOp(DecodedInfo);
            } else if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::UNIMPLEMENTED_INST) {
              Thread->OpDispatcher->UnimplementedOp(DecodedInfo);
            } else {
              Thread->OpDispatcher->NoExecOp(DecodedInfo);
            }
          }

          HadInvalidInst = true;
        }

        const bool NeedsBlockEnd = (HadDispatchError && TotalInstructions > 0) ||
                                   (Thread->OpDispatcher->NeedsBlockEnder() && i + 1 == InstsInBlock) || HadInvalidInst;

        // If we had a dispatch error then leave early
        if (HadDispatchError && TotalInstructions == 0) {
          // Couldn't handle any instruction in op dispatcher
          Thread->OpDispatcher->DelayedDisownBuffer();
          return {std::nullopt, 0, 0, 0, 0};
        }

        if (NeedsBlockEnd) {
          // We had some instructions. Early exit
          Thread->OpDispatcher->ExitFunction(
            Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry + BlockInstructionsLength - GuestRIP));
          break;
        }


        if (Thread->OpDispatcher->FinishOp(DecodedInfo->PC + DecodedInfo->InstSize, i + 1 == InstsInBlock)) {
          break;
        }
      }
    }

#ifdef ZYDIS_DISASSEMBLER
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      LogMan::Msg::IFmt("Guest x86 End");
    }
#endif

    Thread->OpDispatcher->Finalize();

    Thread->FrontendDecoder->DelayedDisownBuffer();
  }

  IR::IREmitter* IREmitter = Thread->OpDispatcher.get();

  auto ShouldDump = Thread->OpDispatcher->ShouldDumpIR();
  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  // Run the passmanager over the IR from the dispatcher
  Thread->PassManager->Run(IREmitter);

  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  return {
    .IRView = IREmitter->ViewIR(),
    .TotalInstructions = TotalInstructions,
    .TotalInstructionsLength = TotalInstructionsLength,
    .StartAddr = Thread->FrontendDecoder->DecodedMinAddress,
    .Length = Thread->FrontendDecoder->DecodedMaxAddress - Thread->FrontendDecoder->DecodedMinAddress,
    .NeedsAddGuestCodeRanges = !HasCustomIR,
  };
}

ContextImpl::CompileCodeResult ContextImpl::CompileCode(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  if (SourcecodeResolver && Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      MappedSection->FileInfo.SourcecodeMap =
        SourcecodeResolver->GenerateMap(MappedSection->FileInfo.Filename, CodeMap::GetBaseFilename(MappedSection->FileInfo, false));
    }
  }

  // Generate IR + Meta Info
  const uint64_t MRIrStart = MRTicks();
  auto [IRView, TotalInstructions, TotalInstructionsLength, StartAddr, Length, NeedsAddGuestCodeRanges] =
    GenerateIR(Thread, GuestRIP, Config.GDBSymbols(), MaxInst);
  MRIrTicks.fetch_add(MRTicks() - MRIrStart, std::memory_order_relaxed);
  if (!IRView) {
    // OpDispatcher IR already released in this case.
    return {{}, nullptr, 0, 0, false};
  }

  // Attempt to get the CPU backend to compile this code
  // Re-check if another thread raced us in compiling this block.
  // We could lock CodeBufferWriteMutex earlier to prevent this from happening,
  // but this would increase lock contention. Redundant frontend runs aren't
  // as expensive and are easily reverted.
  if (MaxInst != 1) {
    if (auto Block = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
      // Raced to compile, release the OpDispatcher IR.
      MRRaced.fetch_add(1, std::memory_order_relaxed);
      Thread->OpDispatcher->DelayedDisownBuffer();
      return {.CompiledCode = {.BlockBegin = reinterpret_cast<uint8_t*>(Block), .EntryPoints = {{GuestRIP, reinterpret_cast<uint8_t*>(Block)}}},
              .DebugData = nullptr,
              .StartAddr = 0,
              .Length = 0,
              .NeedsAddGuestCodeRanges = false};
    }
  }

  auto DebugData = fextl::make_unique<FEXCore::Core::DebugData>();

  // If the trap flag is set we generate single instruction blocks that each check to generate a single step exception.
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];

  const uint64_t MRCgStart = MRTicks();
  auto CompiledCode = Thread->CPUBackend->CompileCode(GuestRIP, Length, TotalInstructions == 1, &*IRView, DebugData.get(), TFSet);
  MRCgTicks.fetch_add(MRTicks() - MRCgStart, std::memory_order_relaxed);
  MRCodeBytes.fetch_add(DebugData->HostCodeSize, std::memory_order_relaxed);
  MRMaybeDump(GuestRIP, TotalInstructions, CompiledCode.BlockBegin, DebugData->HostCodeSize, MRCompiles.load(std::memory_order_relaxed));
  if (MRSeen(GuestRIP)) {
    MRRepeats.fetch_add(1, std::memory_order_relaxed);
  }
  MRInsts.fetch_add(TotalInstructions, std::memory_order_relaxed);
  for (uint64_t Max = MRMaxInsts.load(std::memory_order_relaxed);
       TotalInstructions > Max && !MRMaxInsts.compare_exchange_weak(Max, TotalInstructions, std::memory_order_relaxed);) {
  }
  MRReport(MRCompiles.fetch_add(1, std::memory_order_relaxed) + 1);

  // Release the IR
  Thread->OpDispatcher->DelayedDisownBuffer();

  return {
    .CompiledCode = std::move(CompiledCode),
    .DebugData = std::move(DebugData),
    .StartAddr = StartAddr,
    .Length = Length,
    .NeedsAddGuestCodeRanges = NeedsAddGuestCodeRanges,
  };
}

uintptr_t ContextImpl::CompileBlock(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP, uint64_t MaxInst) {
  // LAZY-FLAGS: the compiler's own host FP arithmetic must not reach the guest MXCSR status.
  FEXCore::LazyMXCSR::ScopedHostFPSR PreserveGuestFPSR;
  if constexpr (BLOCK_DEBUGGING) {
    // Block debugging logic is hand-written and needs to be handled with care.
    // Force MaxInst to only be one in this case.
    MaxInst = 1;

    // If the entrypoint is part of the single step targets then single step it.
    if (BlockDebuggerTracker.IsSingleStepTarget(GuestRIP)) {
      return CompileSingleStep(Frame, GuestRIP);
    }
  }

  auto Thread = Frame->Thread;
  FEXCORE_PROFILE_SCOPED("CompileBlock");
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedJITTime);

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);
  // ★ MacRunner (HG2, MACRUNNER_FEX_HOOK_GUARD): освобождения в конце компиляции и смена буфера кода — под РАЗДЕЛЯЕМЫМ замком; хук NotifyMemory* от аллокатора FEX просил бы
  //   эксклюзивный (повышение). Объявлена ПОСЛЕ lk, значит снимается ДО него: локальные объекты, умирающие в конце функции, тоже под областью.
  MRRuntimeSectionGuard MRSectionGuard {SyscallHandler, FEXCore::HLE::SyscallHandler::RuntimeSection::Compile};

  // Is the code in the cache?
  // The backends only check L1 and L2, not L3
  if (auto HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
    return HostCode;
  }

  // ★ MacRunner — возврат перевода (MACRUNNER_FEX_REVIVE, см. MRReviveMode).
  const bool MRTrapFlag = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC] != 0;
  const bool MRRevive = MRReviveMode() && MaxInst != 1 && !MRTrapFlag && !CodeCache.IsGeneratingCache;
  const uint64_t MREpochAtStart = MRReviveEpoch.load(std::memory_order_relaxed);
  const bool MRMonoAtStart = AreMonoHacksActive();
  // Обработчик IR на адресе (переходники) мог появиться ПОСЛЕ компиляции: AddCustomIREntrypoint старый
  // перевод не сбрасывает, а новая компиляция возьмёт обработчик. Возврат его обошёл бы — не возвращаем.
  bool MRCustomIR = false;
  if (MRRevive && HasCustomIRHandlers.load(std::memory_order_relaxed)) {
    std::shared_lock CustomLock(CustomIRMutex);
    MRCustomIR = CustomIRHandlers.find(GuestRIP) != CustomIRHandlers.end();
  }
  if (MRRevive && !MRCustomIR) {
    MRReviveEntry Entry;
    bool Found = false;
    {
      std::scoped_lock ReviveLock(MRReviveLock);
      auto It = MRReviveTable.find(GuestRIP);
      if (It != MRReviveTable.end() && It->second.Epoch == MREpochAtStart && It->second.Map == Thread->LookupCache->Shared &&
          It->second.MonoHacks == MRMonoAtStart) {
        Entry = It->second;
        Found = true;
      }
    }
    if (Found) {
      fextl::vector<MRSeg> Now;
      if (!MRSegments(SyscallHandler, Thread, Entry.HashBegin, Entry.HashEnd, Now) || !MRClassesAllow(Entry.Segs, Now)) {
        MRReviveSkip.fetch_add(1, std::memory_order_relaxed);
      } else if (MRHashGuest(Entry.HashBegin, Entry.HashEnd) != Entry.Hash) {
        MRReviveHashMiss.fetch_add(1, std::memory_order_relaxed);
      } else {
        // Как при обычной компиляции: страницы блока — в карту страниц, новые страницы — под ловушку.
        const fextl::set<uint64_t> Entrypoint {GuestRIP};
        for (auto CodePage : Entry.CodePages) {
          if (Thread->LookupCache->AddBlockExecutableRange(Thread, Entrypoint, CodePage, FEXCore::Utils::FEX_PAGE_SIZE)) {
            SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
          }
        }
        if (MRMonoBpPrecise()) {
          Thread->LookupCache->MRAddSpans(Entrypoint, Entry.CodePages, Entry.HashBegin, Entry.HashEnd);
        }
        // Второй хеш — уже под ловушкой: запись, успевшая до неё, возврат не пропустит.
        if (MRHashGuest(Entry.HashBegin, Entry.HashEnd) == Entry.Hash) {
          Thread->LookupCache->AddBlockMapping(Thread, GuestRIP, Entry.CodePages, reinterpret_cast<void*>(Entry.HostCode));
          MRRevived.fetch_add(1, std::memory_order_relaxed);
          if (GuestRIP == MonoBackpatcherBlock.load(std::memory_order_relaxed)) {
            MRReviveBp.fetch_add(1, std::memory_order_relaxed);
          }
          return Entry.HostCode;
        }
        MRReviveHashMiss.fetch_add(1, std::memory_order_relaxed);
      }
    }
  }

  // Accumulate a JIT count now, as even if another thread raced us, it should count as a compile.
  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedJITCount, 1);

  auto [CompiledCode, DebugData, StartAddr, Length, NeedsAddGuestCodeRanges] = CompileCode(Thread, GuestRIP, MaxInst);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  } else if (!DebugData) {
    // DebugData wasn't populated, indicating another thread raced us for compiling this block
    return reinterpret_cast<uintptr_t>(CodePtr);
  }

  // ★ MacRunner — возврат перевода: первый хеш байтов сразу после компиляции, до ловушки записи.
  uint64_t MRHashEnd = 0, MRHashFirst = 0;
  fextl::vector<MRSeg> MRSegsAtCompile;
  if (MRRevive && !MRCustomIR && NeedsAddGuestCodeRanges && Length) {
    MRHashEnd = StartAddr + Length;
    const auto Tail = SyscallHandler->QueryGuestExecutableRange(Thread, MRHashEnd);
    if (Tail.Size && Tail.Base <= MRHashEnd && MRHashEnd < Tail.Base + Tail.Size) {
      MRHashEnd = std::min<uint64_t>(MRHashEnd + MRMaxInstSize, Tail.Base + Tail.Size);
    }
    if (MRSegments(SyscallHandler, Thread, StartAddr, MRHashEnd, MRSegsAtCompile)) {
      MRHashFirst = MRHashGuest(StartAddr, MRHashEnd);
    } else {
      MRHashEnd = 0;
    }
  }

  // The core managed to compile the code.
  if (Config.BlockJITNaming()) {
    auto FragmentBasePtr = CompiledCode.BlockBegin;

    auto GuestRIPLookup = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);

    if (DebugData->Subblocks.size()) {
      for (auto& Subblock : DebugData->Subblocks) {
        auto BlockBasePtr = FragmentBasePtr + Subblock.HostCodeOffset;
        if (GuestRIPLookup) {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                           GuestRIP - GuestRIPLookup->FileStartVA);
        } else {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, GuestRIP, Subblock.HostCodeSize);
        }
      }
    } else {
      if (GuestRIPLookup) {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                         GuestRIP - GuestRIPLookup->FileStartVA);
      } else {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, GuestRIP, CompiledCode.Size);
      }
    }
  }

  if (Config.LibraryJITNaming() || Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      if (Config.LibraryJITNaming()) {
        Symbols.RegisterNamedRegion(Thread->SymbolBuffer.get(), CodePtr, DebugData->HostCodeSize, MappedSection->FileInfo.Filename);
      }

      if (Config.GDBSymbols()) {
        GDBJITRegister(MappedSection->FileInfo, MappedSection->FileStartVA, GuestRIP, (uintptr_t)CodePtr, *DebugData);
      }
    }
  }

  // Clear any relocations that might have been generated
  if (!CodeCache.IsGeneratingCache) {
    Thread->CPUBackend->ClearRelocations();
  }

  fextl::vector<uint64_t> CodePages;

  if (NeedsAddGuestCodeRanges) {
    // Track in the guest to host map all entrypoints for all pages the compiled block touches, if any page didn't previously
    // contain code, inform the frontend so it can setup SMC detection.
    auto BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    CodePages.reserve(BlockInfo->CodePages.size());
    CodePages.insert(CodePages.end(), BlockInfo->CodePages.begin(), BlockInfo->CodePages.end());
    for (auto CodePage : BlockInfo->CodePages) {
      if (Thread->LookupCache->AddBlockExecutableRange(Thread, BlockInfo->EntryPoints, CodePage, FEXCore::Utils::FEX_PAGE_SIZE)) {
        SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
      }
    }
    // ★ MacRunner — точный сброс для заплаток Mono: охват байтов гостя этого перевода по его страницам.
    if (MRMonoBpPrecise()) {
      Thread->LookupCache->MRAddSpans(BlockInfo->EntryPoints, CodePages, StartAddr, StartAddr + Length);
    }
  }

  // Insert to lookup cache

  for (auto [GuestAddr, HostAddr] : CompiledCode.EntryPoints) {
    Thread->LookupCache->AddBlockMapping(Thread, GuestAddr, CodePages, HostAddr);
  }

  // ★ MacRunner — возврат перевода: запомнить блок, если байты не менялись с компиляции до ловушки
  //   и за это время не было полного сброса буфера.
  if (MRHashEnd) {
    if (MRHashGuest(StartAddr, MRHashEnd) == MRHashFirst && MRReviveEpoch.load(std::memory_order_relaxed) == MREpochAtStart &&
        AreMonoHacksActive() == MRMonoAtStart) {
      MRReviveEntry Entry;
      Entry.HashBegin = StartAddr;
      Entry.HashEnd = MRHashEnd;
      Entry.Hash = MRHashFirst;
      Entry.Map = Thread->LookupCache->Shared;
      Entry.Epoch = MREpochAtStart;
      Entry.MonoHacks = MRMonoAtStart;
      Entry.CodePages = CodePages;
      Entry.Segs = std::move(MRSegsAtCompile);
      std::scoped_lock ReviveLock(MRReviveLock);
      if (MRReviveTable.size() >= MRReviveMaxEntries) {
        MRReviveTable.clear();
      }
      for (auto [GuestAddr, HostAddr] : CompiledCode.EntryPoints) {
        Entry.HostCode = reinterpret_cast<uint64_t>(HostAddr);
        MRReviveTable.insert_or_assign(GuestAddr, Entry);
      }
      MRReviveRegistered.fetch_add(1, std::memory_order_relaxed);
    } else {
      MRReviveUnstable.fetch_add(1, std::memory_order_relaxed);
    }
  }

  if (CodeMapWriter) {
    auto Region = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (Region && Region->FileStartVA != 0) {
      CodeMapWriter->AppendBlock(*Region, GuestRIP);
    }
  }

  return (uintptr_t)CodePtr;
}

uintptr_t ContextImpl::CompileSingleStep(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  FEXCore::LazyMXCSR::ScopedHostFPSR PreserveGuestFPSR;
  FEXCORE_PROFILE_SCOPED("CompileSingleStep");
  MRSingle.fetch_add(1, std::memory_order_relaxed);
  auto Thread = Frame->Thread;

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);
  MRRuntimeSectionGuard MRSectionGuard {SyscallHandler, FEXCore::HLE::SyscallHandler::RuntimeSection::Compile}; // HG2, см. CompileBlock

  auto [CompiledCode, DebugData, StartAddr, Length, _] = CompileCode(Thread, GuestRIP, 1);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  }

  // Clear any relocations that might have been generated
  Thread->CPUBackend->ClearRelocations();

  return (uintptr_t)CodePtr;
}

void ContextImpl::InvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) {
  FEXCORE_PROFILE_SCOPED("InvalidateCodeBuffersCodeRange");
  MRInvCalls.fetch_add(1, std::memory_order_relaxed);
  MRInvBytes.fetch_add(Length, std::memory_order_relaxed);

  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  std::scoped_lock lk {CodeBufferListLock};
  auto it = CodeBufferList.begin();
  while (it != CodeBufferList.end()) {
    if (auto Strong = it->lock()) {
      Strong->LookupCache->InvalidateRange(Start, Length);
      it++;
    } else {
      it = CodeBufferList.erase(it);
    }
  }
}

void ContextImpl::MRInvalidateCodeBuffersPrecise(uint64_t Start, uint64_t Length, fextl::vector<uint64_t>& Erased) {
  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  const size_t Before = Erased.size();
  {
    std::scoped_lock lk {CodeBufferListLock};
    auto it = CodeBufferList.begin();
    while (it != CodeBufferList.end()) {
      if (auto Strong = it->lock()) {
        Strong->LookupCache->MRInvalidatePrecise(Start, Length, Erased);
        it++;
      } else {
        it = CodeBufferList.erase(it);
      }
    }
  }
  MRBpPreciseErased.fetch_add(Erased.size() - Before, std::memory_order_relaxed);
}

void ContextImpl::MRInvalidateThreadCachedEntries(FEXCore::Core::InternalThreadState* Thread, const fextl::vector<uint64_t>& Erased) {
  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  if (!Erased.empty()) {
    Thread->LookupCache->MRInvalidateCacheEntries(Erased);
  }
}

void ContextImpl::InvalidateThreadCachedCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  // Ensures now-modified mappings aren't cached as being in their previous non-executable state.
  // Accessing FrontendDecoder is safe as the thread's code invalidation mutex must be locked here.
  Thread->FrontendDecoder->ResetExecutableRangeCache();

  if (Thread->LookupCache->InvalidateCacheRange(Start, Length)) {
    FEXCORE_PROFILE_SCOPED("InvalidateCallRet");

    // This may cause access violations in the thread on Windows as zeroing is not atomic, this is handled by the frontend
#ifdef _WIN32
    // This private cache must not re-enter guest allocation notifications under the code lock.
    // ★ MacRunner (Claude, 23.09.2026): это 4 МБ на поток на КАЖДУЮ инвалидацию, задевшую его кэш, и под
    //   исключительной блокировкой (компиляция всех потоков стоит). Upstream здесь дешёвый VirtualDontNeed.
    //   Сколько это стоит — не мерено; счётчики callret_clears / callret_ms в строке macrunner-fex-jit.
    const uint64_t MRClearStart = MRTicks();
    if (!MRCallRet::TryZero(Thread)) {
      memset(Thread->CallRetStackBase, 0, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
    }
    MRCallRetTicks.fetch_add(MRTicks() - MRClearStart, std::memory_order_relaxed);
    MRCallRetClears.fetch_add(1, std::memory_order_relaxed);
#else
    MRCallRet::Zero(Thread);
#endif
  }
}

void ContextImpl::ThreadRemoveCodeEntryFromJit(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  // Сработала побайтная проверка: код на GuestRIP изменился после трансляции. Первые 64 — в журнал.
  if (MRRemove.fetch_add(1, std::memory_order_relaxed) < 64) {
    uint64_t Bytes = 0;
    memcpy(&Bytes, reinterpret_cast<const void*>(GuestRIP), sizeof(Bytes));
    char Line[160];
    auto Result = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-codechanged: rip={:x} now={:016x}\n", GuestRIP, Bytes);
    Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
  static_cast<ContextImpl*>(Frame->Thread->CTX)->SyscallHandler->InvalidateGuestCodeRange(Frame->Thread, GuestRIP, 1);
}

std::optional<CustomIRResult>
ContextImpl::AddCustomIREntrypoint(uintptr_t Entrypoint, CustomIREntrypointHandler Handler, void* Creator, void* Data) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::unique_lock lk(CustomIRMutex);

  auto InsertedIterator = CustomIRHandlers.emplace(Entrypoint, CustomIRHandlerEntry {Handler, Creator, Data});
  HasCustomIRHandlers = true;

  if (!InsertedIterator.second) {
    const auto& [fn, Creator, Data] = InsertedIterator.first->second;
    return CustomIRResult(Creator, Data);
  }

  return std::nullopt;
}

void ContextImpl::AddThunkTrampolineIRHandler(uintptr_t Entrypoint, uintptr_t GuestThunkEntrypoint) {
  LOGMAN_THROW_A_FMT(Entrypoint, "Tried to link null pointer address to guest function");
  LOGMAN_THROW_A_FMT(GuestThunkEntrypoint, "Tried to link address to null pointer guest function");
  if (!Config.Is64BitMode) {
    LOGMAN_THROW_A_FMT((Entrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
    LOGMAN_THROW_A_FMT((GuestThunkEntrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
  }

  LogMan::Msg::DFmt("Thunks: Adding guest trampoline from address {:#x} to guest function {:#x}", Entrypoint, GuestThunkEntrypoint);

  auto Result = AddCustomIREntrypoint(
    Entrypoint,
    [this, GuestThunkEntrypoint](uintptr_t Entrypoint, FEXCore::IR::IREmitter* emit) {
      auto IRHeader = emit->_IRHeader(emit->Invalid(), Entrypoint, 0, 0, 0, 0);
      auto Block = emit->CreateCodeNode(true, 0);
      IRHeader.first->Blocks = emit->WrapNode(Block);
      emit->SetCurrentCodeBlock(Block);

      const auto GPRSize = this->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit;

      // Thunk entry-points don't get cached, don't need to be padded.
      if (GPRSize == IR::OpSize::i64Bit) {
        IR::Ref R = emit->_StoreRegister(emit->Constant(Entrypoint), GPRSize);
        R->Reg = IR::PhysicalRegister(IR::RegClass::GPRFixed, X86State::REG_R11).Raw;
      } else {
        emit->_StoreContextFPR(GPRSize, emit->_VCastFromGPR(IR::OpSize::i64Bit, IR::OpSize::i64Bit, emit->Constant(Entrypoint)),
                               offsetof(Core::CPUState, mm[0][0]));
      }
      emit->_ExitFunction(IR::OpSize::i64Bit, emit->Constant(GuestThunkEntrypoint), IR::BranchHint::None, emit->Invalid(), emit->Invalid());
    },
    ThunkHandler, (void*)GuestThunkEntrypoint);

  if (Result.has_value()) {
    if (Result->Creator != ThunkHandler) {
      ERROR_AND_DIE_FMT("Input address for AddThunkTrampoline is already linked by another module");
    }
    if (Result->Data != (void*)GuestThunkEntrypoint) {
      // NOTE: This may happen in Vulkan thunks if the Vulkan driver resolves two different symbols
      //       to the same function (e.g. vkGetPhysicalDeviceFeatures2/vkGetPhysicalDeviceFeatures2KHR)
      LogMan::Msg::EFmt("Input address for AddThunkTrampoline is already linked elsewhere");
    }
  }
}

void ContextImpl::AddForceTSOInformation(const IntervalList<uint64_t>& ValidRanges, fextl::set<uint64_t>&& Instructions) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  ForceTSOValidRanges.Insert(ValidRanges);
  ForceTSOInstructions.merge(std::move(Instructions));
}

void ContextImpl::RemoveForceTSOInformation(uint64_t Address, uint64_t Size) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  ForceTSOValidRanges.Remove({Address, Address + Size});
  ForceTSOInstructions.erase(ForceTSOInstructions.lower_bound(Address), ForceTSOInstructions.upper_bound(Address + Size));
}

void ContextImpl::MarkMonoBackpatcherBlock(uint64_t BlockEntry) {
  MonoBackpatcherBlock.store(BlockEntry, std::memory_order_relaxed);
  // ★ MacRunner — возврат перевода: переводы, собранные до пометки, не должны вернуться (см. MRReviveMode).
  //   Вызывается под исключительной CodeInvalidationMutex, с компиляцией не пересекается.
  if (!MRReviveKeepBp()) {
    MRReviveEpoch.fetch_add(1, std::memory_order_relaxed);
    std::scoped_lock ReviveLock(MRReviveLock);
    MRReviveTable.clear();
    MRReviveBpDrops.fetch_add(1, std::memory_order_relaxed);
  }
}

void ContextImpl::RemoveCustomIREntrypoint(FEXCore::Core::InternalThreadState* Thread, uintptr_t Entrypoint) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::scoped_lock lk(CustomIRMutex);

  CustomIRHandlers.erase(Entrypoint);
  HasCustomIRHandlers = !CustomIRHandlers.empty();
  SyscallHandler->InvalidateGuestCodeRange(Thread, Entrypoint, 1);
}

void ContextImpl::MonoBackpatcherWrite(FEXCore::Core::CpuStateFrame* Frame, uint8_t Size, uint64_t Address, uint64_t Value) {
  auto Thread = Frame->Thread;
  auto CTX = static_cast<ContextImpl*>(Thread->CTX);
  MRBackpatchWrites.fetch_add(1, std::memory_order_relaxed);
  // Байты вокруг imm64 заплатка не меняет — проверка до записи равносильна проверке после.
  // Проверка через границу страницы (MRCallTargetPatchKind) — только под замком ниже.
  const int MRMode = MRMonoBpPrecise();
  MRPatchKind MRKind = MRPatchKind::None;
  bool MRPrecise = false;
  {
    auto lk = GuardSignalDeferringSection(CTX->CodeInvalidationMutex, Thread);
    if (MRMode >= 2) {
      MRKind = MRCallTargetPatchKind(Thread, Address, Size);
    } else if (MRMode == 1 && MRIsCallTargetPatch(Address, Size)) {
      MRKind = MRPatchKind::InPage;
    }
    MRPrecise = (MRMode >= 1 && MRKind == MRPatchKind::InPage) || (MRMode >= 2 && MRKind == MRPatchKind::AcrossPage);

    if (Size == 8) {
      *reinterpret_cast<uint64_t*>(Address) = Value;
    } else if (Size == 4) {
      *reinterpret_cast<uint32_t*>(Address) = Value;
    } else {
      ERROR_AND_DIE_FMT("Unexpected write size for backpatcher: {}", Size);
    }
  }

  if (MRPrecise && CTX->SyscallHandler->InvalidateGuestCallTargetPatch(Thread, Address, Size)) {
    MRBpPrecise.fetch_add(1, std::memory_order_relaxed);
    if (MRKind == MRPatchKind::AcrossPage) {
      MRBpAcross.fetch_add(1, std::memory_order_relaxed);
    }
    return;
  }
  if (MRMode) {
    MRBpFallback.fetch_add(1, std::memory_order_relaxed);
    if (MRKind == MRPatchKind::AcrossUnread) {
      MRBpAcrossUnread.fetch_add(1, std::memory_order_relaxed);
    }
  }
  CTX->SyscallHandler->InvalidateGuestCodeRange(Thread, Address, Size);
}

void ContextImpl::ConfigureAOTGen(FEXCore::Core::InternalThreadState* Thread, fextl::set<uint64_t>* ExternalBranches, uint64_t SectionMaxAddress) {
  Thread->FrontendDecoder->SetExternalBranches(ExternalBranches);
}
} // namespace FEXCore::Context
