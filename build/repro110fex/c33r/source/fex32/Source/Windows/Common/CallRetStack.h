// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/Context.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include "../../../FEXCore/Source/Interface/Core/MRCallRet.h"
#include <algorithm>
#include <shared_mutex>
#include <atomic>
#include <cstdlib>
#include <cstring>

namespace FEX::Windows::CallRetStack {
#ifdef FEX_WINE_DARWIN
// Wine reports 4 KiB Windows pages, but protection on Apple Silicon covers 16 KiB.
// Keep the committed stack and each guard on separate host protection pages.
inline constexpr uint64_t GuardSize = 16384;
#else
inline constexpr uint64_t GuardSize = FEXCore::Utils::FEX_PAGE_SIZE;
#endif
static_assert(FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE % GuardSize == 0);

struct CallRetStackInfo {
  uint64_t AllocationBase;
  uint64_t AllocationEnd;
  uint64_t DefaultLocation;
};

CallRetStackInfo GetInfoThread(FEXCore::Core::InternalThreadState* Thread) {
  uint64_t Base = reinterpret_cast<uint64_t>(Thread->CallRetStackBase);
  // Leave some room from the base for the default location to allow for underflows without constant exceptions
  return {Base - GuardSize, Base + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + GuardSize,
          Base + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4};
}

// ★ MacRunner (CLAUDE-STORE, 10.10.2026) — MACRUNNER_FEX_CALLRET_LAZY=1 (умолчание 0 = прежнее поведение, байт в байт).
//   Профиль 10.10: 69,5 мкс из 75,9 мкс VirtualProtect(RX->RWX) страницы с переводом — memset 4 МБ стека возвратов в InvalidateThreadCachedCodeRange.
//   Писать в стек может только JIT-код потока; при ключе 1 закоммичено лишь ОКНО вокруг DefaultLocation (вниз 32 КиБ, вверх 16 КиБ), остальное
//   зарезервировано PAGE_NOACCESS. Обращение за окно -> отказ доступа -> окно растёт вдвое В СТОРОНУ обращения (коммит ДО обновления границ: обнуление,
//   читающее границы, никогда не трогает незакоммиченное), SP не меняется, команда повторяется. Обнуление = memset ТОЛЬКО окна: всё, что JIT мог
//   записать, лежит внутри окна, поэтому результат тот же, что у прежнего memset на 4 МБ.
//   ДРЕЙФ: вызов в родной код кладёт запись и не снимает её (SP уходит вниз на 16 Б за вызов) — окно без возврата SP раздулось бы до 4 МБ.
//   Поэтому, когда обнуляет СВОЙ поток (стек его, JIT этого потока сейчас не исполняется), SP возвращается в DefaultLocation: после обнуления
//   предсказаний всё равно нет (нулевые записи не совпадают ни с каким адресом, ret идёт медленным путём), положение SP на корректность не влияет.
//   Окно больше 256 КиБ у своего потока после обнуления возвращается к начальному (decommit лишнего). Границы окна — на отдельной странице ЗА верхней
//   охранной (заголовок), раскладка InternalThreadState не меняется.
inline bool LazyOn() {
  static const bool On = [] {
    const char* Value = getenv("MACRUNNER_FEX_CALLRET_LAZY");
    return Value && Value[0] == '1' && !Value[1];
  }();
  return On;
}
// These allocations belong to FEX, not the guest. EC's syscall callbacks must
// not enter the guest invalidation tracker while its code lock is held. This
// is the same per-thread suppression used around EC exception recovery; it is
// independent of the optional module/alias policy. WOW native Nt* allocations
// do not pass through the guest wow64 virtual-memory notification thunks.
class PrivateAllocationScope {
#ifdef ARCHITECTURE_arm64ec
  CHPE_V2_CPU_AREA_INFO* Area {};
  bool Previous {};
#endif
public:
  PrivateAllocationScope() {
#ifdef ARCHITECTURE_arm64ec
    if (LazyOn()) {
      // Same ARM64EC ABI offset as ThreadCPUArea and Module.S. The MinGW TEB
      // declaration used by NtCurrentTeb does not name this Windows field.
      Area = *reinterpret_cast<CHPE_V2_CPU_AREA_INFO**>(reinterpret_cast<uintptr_t>(NtCurrentTeb()) + 0x1788);
      if (Area) {
        Previous = Area->InSyscallCallback;
        Area->InSyscallCallback = true;
      }
    }
#endif
  }
  ~PrivateAllocationScope() {
#ifdef ARCHITECTURE_arm64ec
    if (Area) Area->InSyscallCallback = Previous;
#endif
  }
  PrivateAllocationScope(const PrivateAllocationScope&) = delete;
  PrivateAllocationScope& operator=(const PrivateAllocationScope&) = delete;
};
inline constexpr uint64_t LazyDown = 2 * GuardSize; // 32 КиБ ниже DefaultLocation (2048 вызовов)
inline constexpr uint64_t LazyUp = GuardSize;       // 16 КиБ выше (underflow)
inline constexpr uint64_t LazyShrinkAbove = 256 * 1024;
struct LazyHeader {
  std::atomic<uint64_t> Lo; // смещения от CallRetStackBase, закоммичено [Lo, Hi)
  std::atomic<uint64_t> Hi;
  std::atomic<uint64_t> Pending; // SP, который надо положить в регистр после обработчика исключения (0 — нет)
  std::atomic<uint32_t> OwnerTid;
  // ★ REGION4-0005 POLL_ON_SHADOW (FEXCore/Utils/MacRunnerSuspend.h): the window [Lo, Hi) is no-access while ShadowState == ShadowArmed.
  // ShadowLock (bit 0 held, bit 1 a zeroing deferred to the holder) orders arming, disarming and zeroing; nobody ever waits for it.
  std::atomic<uint32_t> ShadowLock;
  std::atomic<uint32_t> ShadowState;
  // Suspension episodes: the suspender's first round of an episode bumps ArmEpisode; the owner records it in TakenEpisode when it stops.
  // Every round arms a window that is not armed while TakenEpisode != ArmEpisode (a first round that found the lock busy loses nothing;
  // a window reopened by the owner's stop is not re-armed in the same episode).
  std::atomic<uint32_t> ArmEpisode;
  std::atomic<uint32_t> TakenEpisode;
};
inline LazyHeader* HeaderOf(void* Base) {
  return reinterpret_cast<LazyHeader*>(reinterpret_cast<uintptr_t>(Base) + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + GuardSize);
}
// ★ REGION4-0005 13.11.2026. Off: the window is read-write. Armed: a suspension is pending and the window is no-access, so the
// call-return stack accesses of translated calls / returns fault (the poll). Canceled: the owner met such a fault where it cannot stop
// (not a call / return site, or a call whose callee is a flags window of EXIT_SCAN) and reopened the window; the suspender re-arms.
// The state changes only under ShadowLock, taken with try-lock by everyone: the suspender skips a round, the owner's fault handler
// stops without reopening (the next fault reopens), and a zeroing by any thread (code invalidation) is handed to the holder, who
// performs it before releasing (ShadowRelease). So no thread waits for one that may itself be suspended.
enum : uint32_t { ShadowOff = 0, ShadowArmed = 1, ShadowCanceled = 2 };
inline constexpr uint32_t ShadowHeld = 1, ShadowZeroDeferred = 2;
inline bool ShadowProtect(void* Base, uint64_t Lo, uint64_t Hi, DWORD Prot) {
  DWORD Old {};
  return Lo < Hi && ::VirtualProtect(reinterpret_cast<uint8_t*>(Base) + Lo, Hi - Lo, Prot, &Old);
}
inline bool ShadowTryLock(LazyHeader* H) {
  uint32_t W = H->ShadowLock.load(std::memory_order_relaxed);
  while (!(W & ShadowHeld)) {
    if (H->ShadowLock.compare_exchange_weak(W, W | ShadowHeld, std::memory_order_acquire, std::memory_order_relaxed)) return true;
  }
  return false;
}
inline void ZeroWindowHeld(FEXCore::Core::InternalThreadState* Thread); // below: the zeroing itself, lock held
// Release: first every zeroing that was handed over while the lock was held.
inline void ShadowRelease(FEXCore::Core::InternalThreadState* Thread, LazyHeader* H) {
  uint32_t W = H->ShadowLock.load(std::memory_order_relaxed);
  for (;;) {
    if (W & ShadowZeroDeferred) {
      if (H->ShadowLock.compare_exchange_weak(W, W & ~ShadowZeroDeferred, std::memory_order_acq_rel, std::memory_order_relaxed)) {
        ZeroWindowHeld(Thread);
        W = H->ShadowLock.load(std::memory_order_relaxed);
      }
      continue;
    }
    if (H->ShadowLock.compare_exchange_weak(W, 0, std::memory_order_release, std::memory_order_relaxed)) return;
  }
}
// The suspender, for another thread's stack: no-access window. First = the episode's first round (bumps the episode).
inline void ShadowArm(FEXCore::Core::InternalThreadState* Thread, bool First) {
  if (!LazyOn() || !Thread || !Thread->CallRetStackBase) return;
  void* Base = Thread->CallRetStackBase;
  auto* H = HeaderOf(Base);
  if (First) {
    H->ArmEpisode.fetch_add(1, std::memory_order_acq_rel);
  }
#ifndef REGION4_SHADOW_NO_ARM // diagnostic negative control only (probe shpoll32 phase conly must then never suspend)
  const auto Wanted = [H] {
    return H->ShadowState.load(std::memory_order_acquire) != ShadowArmed &&
           H->TakenEpisode.load(std::memory_order_acquire) != H->ArmEpisode.load(std::memory_order_acquire);
  };
  if (!Wanted() || !ShadowTryLock(H)) return; // busy: the next round
  if (Wanted()) {
    // Armed before the protection: a fault on it always finds the state armed (the owner then stops even with the lock held here).
    H->ShadowState.store(ShadowArmed, std::memory_order_release);
    if (ShadowProtect(Base, H->Lo.load(std::memory_order_acquire), H->Hi.load(std::memory_order_acquire), PAGE_NOACCESS)) {
      FEXCore::Utils::MacRunnerShadowStats[0].fetch_add(1, std::memory_order_relaxed);
    } else {
      H->ShadowState.store(ShadowCanceled, std::memory_order_release); // the next round tries again
    }
  }
  ShadowRelease(Thread, H);
#endif
}
// The owner, at an access it does not stop at (a call into a flags window, the dispatcher's store into the pushed entry): perform the
// access itself on the armed window -- one host page opened and closed again -- so the window stays armed and the next access polls.
// Bytes = 16 (the pair of a call's stp, Address = x25 - 16) or 8 (a store); false when the lock is busy or the slot is not committed.
inline bool ShadowEmulateStore(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, const uint64_t* Values, unsigned Bytes) {
  if (!LazyOn() || !Thread || !Thread->CallRetStackBase || (Address & 7)) return false;
  void* Base = Thread->CallRetStackBase;
  auto* H = HeaderOf(Base);
  const uint64_t B = reinterpret_cast<uint64_t>(Base);
  const uint64_t Page = Address & ~(GuardSize - 1);
  if (((Address + Bytes - 1) & ~(GuardSize - 1)) != Page || !ShadowTryLock(H)) return false;
  bool Done = false;
  if (H->ShadowState.load(std::memory_order_relaxed) == ShadowArmed && Address >= B + H->Lo.load(std::memory_order_acquire) &&
      Address + Bytes <= B + H->Hi.load(std::memory_order_acquire)) {
    DWORD Old {};
    if (::VirtualProtect(reinterpret_cast<void*>(Page), GuardSize, PAGE_READWRITE, &Old)) {
      memcpy(reinterpret_cast<void*>(Address), Values, Bytes);
      ::VirtualProtect(reinterpret_cast<void*>(Page), GuardSize, PAGE_NOACCESS, &Old);
      Done = true;
    }
  }
  ShadowRelease(Thread, H);
  return Done;
}
// The owner, when it stops (either poll): this episode is served.
inline void ShadowTaken(FEXCore::Core::InternalThreadState* Thread) {
  if (!LazyOn() || !Thread || !Thread->CallRetStackBase) return;
  auto* H = HeaderOf(Thread->CallRetStackBase);
  H->TakenEpisode.store(H->ArmEpisode.load(std::memory_order_acquire), std::memory_order_release);
}
// The owner: reopen the window (if armed) and leave NewState. Returns false when the lock is busy (nothing done; the window stays as it
// is and the next fault on it comes back here).
inline bool ShadowDisarm(FEXCore::Core::InternalThreadState* Thread, uint32_t NewState) {
  if (!LazyOn() || !Thread || !Thread->CallRetStackBase) return true;
  void* Base = Thread->CallRetStackBase;
  auto* H = HeaderOf(Base);
  if (!ShadowTryLock(H)) return false;
  if (H->ShadowState.load(std::memory_order_relaxed) == ShadowArmed) {
    ShadowProtect(Base, H->Lo.load(std::memory_order_acquire), H->Hi.load(std::memory_order_acquire), PAGE_READWRITE);
  }
  H->ShadowState.store(NewState, std::memory_order_release);
  ShadowRelease(Thread, H);
  return true;
}
inline uint32_t ShadowStateOf(FEXCore::Core::InternalThreadState* Thread) {
  return LazyOn() && Thread && Thread->CallRetStackBase ? HeaderOf(Thread->CallRetStackBase)->ShadowState.load(std::memory_order_acquire)
                                                        : ShadowOff;
}
// A fault inside the committed window while it is not armed can only come from a protection that outlived its state (orderings
// without a lock: GrowWindow's commit). Reopen it; never reset the stack pointer for it.
inline bool ShadowStaleProtection(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) {
  if (!LazyOn() || !Thread || !Thread->CallRetStackBase) return false;
  void* Base = Thread->CallRetStackBase;
  auto* H = HeaderOf(Base);
  const uint64_t B = reinterpret_cast<uint64_t>(Base), Lo = H->Lo.load(std::memory_order_acquire), Hi = H->Hi.load(std::memory_order_acquire);
  if (Address < B + Lo || Address >= B + Hi || H->ShadowState.load(std::memory_order_acquire) == ShadowArmed) return false;
  if (!ShadowTryLock(H)) return true; // retry; the holder is reopening or zeroing
  if (H->ShadowState.load(std::memory_order_relaxed) != ShadowArmed) {
    ShadowProtect(Base, Lo, Hi, PAGE_READWRITE);
  }
  ShadowRelease(Thread, H);
  return true;
}
inline uint64_t DefaultOffset() { return FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4; }
// REGION4-0005: the zeroing proper, with ShadowLock held (an armed window is opened for it and closed again over its new bounds).
inline void ZeroWindowHeld(FEXCore::Core::InternalThreadState* Thread) {
  PrivateAllocationScope CallbackGuard;
  void* Base = Thread->CallRetStackBase;
  constexpr uint64_t Size = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
  auto* H = HeaderOf(Base);
  const bool Armed = H->ShadowState.load(std::memory_order_relaxed) == ShadowArmed;
  if (Armed) {
    ShadowProtect(Base, H->Lo.load(std::memory_order_acquire), H->Hi.load(std::memory_order_acquire), PAGE_READWRITE);
  }
  uint64_t Lo = H->Lo.load(std::memory_order_acquire), Hi = H->Hi.load(std::memory_order_acquire);
  LOGMAN_THROW_A_FMT(Lo < Hi && Hi <= Size, "Invalid committed call-ret window");
  auto* P = reinterpret_cast<uint8_t*>(Base);
  const bool Owner = H->OwnerTid.load(std::memory_order_relaxed) == ::GetCurrentThreadId();
  if (Owner && (Hi - Lo) > LazyShrinkAbove) {
    const uint64_t InitLo = DefaultOffset() - LazyDown, InitHi = DefaultOffset() + LazyUp;
    // Publish each successful decommit separately. If the second fails,
    // the following memset must not touch the already decommitted first side.
    if (Lo < InitLo && ::VirtualFree(P + Lo, InitLo - Lo, MEM_DECOMMIT)) {
      Lo = InitLo;
      H->Lo.store(Lo, std::memory_order_release);
    }
    if (Hi > InitHi && ::VirtualFree(P + InitHi, Hi - InitHi, MEM_DECOMMIT)) {
      Hi = InitHi;
      H->Hi.store(Hi, std::memory_order_release);
    }
  }
  memset(P + Lo, 0, Hi - Lo);
  if (Armed) {
    ShadowProtect(Base, Lo, Hi, PAGE_NOACCESS);
  }
}
inline bool ZeroWindow(FEXCore::Core::InternalThreadState* Thread) {
  void* Base = Thread->CallRetStackBase;
  auto* H = HeaderOf(Base);
  // REGION4-0005: with the lock free, zero now; held, hand the zeroing to the holder (ShadowRelease) -- it completes it before anyone
  // changes the window's protection again. Without POLL_ON_SHADOW nobody else ever holds the lock.
  uint32_t W = H->ShadowLock.load(std::memory_order_relaxed);
  for (;;) {
    if (!(W & ShadowHeld)) {
      if (H->ShadowLock.compare_exchange_weak(W, W | ShadowHeld, std::memory_order_acquire, std::memory_order_relaxed)) {
        ZeroWindowHeld(Thread);
        ShadowRelease(Thread, H);
        break;
      }
    } else if (H->ShadowLock.compare_exchange_weak(W, W | ShadowZeroDeferred, std::memory_order_acq_rel, std::memory_order_relaxed)) {
      break;
    }
  }
  if (H->OwnerTid.load(std::memory_order_relaxed) == ::GetCurrentThreadId()) {
    const uint64_t Default = reinterpret_cast<uint64_t>(Base) + DefaultOffset();
    Thread->CurrentFrame->State.callret_sp = Default; // путь «через системный вызов»: регистр заполняется из кадра
    H->Pending.store(Default, std::memory_order_relaxed); // путь «через исключение»: регистр берётся из контекста (см. TakePending)
  }
  return true;
}
// Вызывается после обработчика исключения: если свой поток обнулял стек, положить SP в регистр контекста.
inline bool TakePending(FEXCore::Core::InternalThreadState* Thread, uint64_t& CallRetSPReg) {
  if (!LazyOn() || !Thread || !Thread->CallRetStackBase) return false;
  const uint64_t V = HeaderOf(Thread->CallRetStackBase)->Pending.exchange(0, std::memory_order_relaxed);
  if (V) CallRetSPReg = V;
  return V != 0;
}
// Scope pending resets to this SMC operation; ordinary dispatcher
// returns may already have consumed the frame value. No loop poll.
inline void BeginException(FEXCore::Core::InternalThreadState* Thread) {
  uint64_t Ignored = 0;
  TakePending(Thread, Ignored);
}
// Отказ доступа внутри самого стека, но вне закоммиченного окна: вырастить окно и повторить команду.
inline bool GrowWindow(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, FEXCore::Context::Context& Context) {
  void* Base = Thread->CallRetStackBase;
  const uint64_t B = reinterpret_cast<uint64_t>(Base), Size = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
  if (Address < B || Address >= B + Size) return false;
  // This is a rare stack-growth fault, never a guest loop poll.
  // Commit callbacks must not upgrade the shared invalidation lock.
  PrivateAllocationScope CallbackGuard;
  std::shared_lock CodeLock(Context.GetCodeInvalidationMutex());
  auto* H = HeaderOf(Base);
  // REGION4-0005: pages committed while a suspension is armed are armed too. No lock (the owner's fault handler never waits): a race
  // with an arm / disarm leaves either missed polls or a stale protection, which ShadowStaleProtection reopens.
  const DWORD Prot = H->ShadowState.load(std::memory_order_acquire) == ShadowArmed ? PAGE_NOACCESS : PAGE_READWRITE;
  uint64_t Lo = H->Lo.load(std::memory_order_acquire), Hi = H->Hi.load(std::memory_order_acquire);
  const uint64_t Off = Address - B;
  if (Off >= Lo && Off < Hi) return false; // внутри окна — не наш отказ (прежний путь)
  uint64_t NewLo = Lo, NewHi = Hi;
  if (Off < Lo) {
    const uint64_t Step = std::max<uint64_t>(Hi - Lo, Lo - (Off & ~(GuardSize - 1)));
    NewLo = Lo > Step ? Lo - Step : 0;
    NewLo &= ~(GuardSize - 1);
    if (::VirtualAlloc(reinterpret_cast<void*>(B + NewLo), Lo - NewLo, MEM_COMMIT, Prot) == nullptr) return false;
    H->Lo.store(NewLo, std::memory_order_release);
  } else {
    const uint64_t Step = std::max<uint64_t>(Hi - Lo, ((Off | (GuardSize - 1)) + 1) - Hi);
    NewHi = std::min<uint64_t>(Size, Hi + Step);
    if (::VirtualAlloc(reinterpret_cast<void*>(B + Hi), NewHi - Hi, MEM_COMMIT, Prot) == nullptr) return false;
    H->Hi.store(NewHi, std::memory_order_release);
  }
  MRCallRet::Grows.fetch_add(1, std::memory_order_relaxed);
  return true;
}

void InitializeThread(FEXCore::Core::InternalThreadState* Thread) {
  // Allocate the call-ret stack with guard pages on both sides
  const bool Lazy = LazyOn();
  PrivateAllocationScope CallbackGuard;
  const uint64_t Total = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * GuardSize + (Lazy ? GuardSize : 0); // +заголовок окна
  const void* CallRetStackAlloc = ::VirtualAlloc(nullptr, Total, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);

  LOGMAN_THROW_A_FMT(!Lazy || CallRetStackAlloc, "Call-ret stack reservation failed");
  FEXCore::Allocator::VirtualName("FEXMem_CallRetStacks", CallRetStackAlloc, Total);
  FEXCore::Allocator::VirtualTHPControl(CallRetStackAlloc, Total, FEXCore::Allocator::THPControl::Disable);

  Thread->CallRetStackBase = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(CallRetStackAlloc) + GuardSize);
  if (Lazy) {
    const uint64_t Default = GetInfoThread(Thread).DefaultLocation - reinterpret_cast<uint64_t>(Thread->CallRetStackBase);
    const uint64_t Lo = Default - LazyDown, Hi = Default + LazyUp;
    const auto Window = ::VirtualAlloc(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Thread->CallRetStackBase) + Lo), Hi - Lo, MEM_COMMIT, PAGE_READWRITE);
    const auto Header = ::VirtualAlloc(HeaderOf(Thread->CallRetStackBase), GuardSize, MEM_COMMIT, PAGE_READWRITE);
    LOGMAN_THROW_A_FMT(Window && Header, "Call-ret stack window/header commit failed");
    HeaderOf(Thread->CallRetStackBase)->Lo.store(Lo, std::memory_order_release);
    HeaderOf(Thread->CallRetStackBase)->Hi.store(Hi, std::memory_order_release);
    HeaderOf(Thread->CallRetStackBase)->OwnerTid.store(::GetCurrentThreadId(), std::memory_order_relaxed);
    MRCallRet::ZeroHook.store(&ZeroWindow, std::memory_order_release);
  } else {
    ::VirtualAlloc(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE, MEM_COMMIT, PAGE_READWRITE);
  }

  Thread->CurrentFrame->State.callret_sp = GetInfoThread(Thread).DefaultLocation;
}

void DestroyThread(FEXCore::Core::InternalThreadState* Thread) {
  PrivateAllocationScope CallbackGuard;
  auto CallRetStackInfo = GetInfoThread(Thread);
  ::VirtualFree(reinterpret_cast<void*>(CallRetStackInfo.AllocationBase), 0, MEM_RELEASE);
}

bool HandleAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t& CallRetSPReg, FEXCore::Context::Context& Context) {
  auto CallRetStackInfo = GetInfoThread(Thread);
  if (Address >= CallRetStackInfo.AllocationBase && Address < CallRetStackInfo.AllocationEnd) {
    if (LazyOn() && GrowWindow(Thread, Address, Context)) {
      return true; // окно выросло, SP не тронут: команда исполнится повторно
    }
    LogMan::Msg::DFmt("Call-ret stack inbalance: {:X}", Address);
    CallRetSPReg = CallRetStackInfo.DefaultLocation;
    return true;
  }
  return false;
}
} // namespace FEX::Windows::CallRetStack
