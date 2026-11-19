// SPDX-License-Identifier: MIT
// SPEED114 19.11 (rp6r4): watch of the guest pages the CRT-sqrt fold touches (the CRT global and the security cookie). The fold reads
// them from the translated block, the real chain reads them from its own instruction: a guard / no-access page would fault there with another
// guest EIP (and ESP). The fold is therefore taken only while both pages are plain readable memory: checked at translation time
// (SyscallHandler::MRGuestPagePlain) and, afterwards, every memory-protection / free / map notification that overlaps a watched page
// sets Tainted(), which the fold's guard reads (any non-zero -> the original call).
#pragma once
#include <atomic>
#include <cstdint>
namespace FEXCore::HBX87::CrtWatch {
constexpr unsigned MaxPages = 8;
struct State {
  std::atomic<uint32_t> Taint {0};
  std::atomic<uint32_t> Count {0};
  std::atomic<uint64_t> Pages[MaxPages] {};
};
inline State& S() { static State V; return V; }
inline const uint32_t* TaintAddress() { return reinterpret_cast<const uint32_t*>(&S().Taint); }
inline bool Tainted() { return S().Taint.load(std::memory_order_acquire) != 0; }
// Registers the page of Address (idempotent); false when the table is full (the caller must not fold then).
inline bool Register(uint64_t Address) {
  auto& St = S();
  const uint64_t Page = Address & ~uint64_t {0xfff};
  for (;;) {
    const uint32_t N = St.Count.load(std::memory_order_acquire);
    for (uint32_t i = 0; i < N; ++i) if (St.Pages[i].load(std::memory_order_acquire) == Page) return true;
    if (N >= MaxPages) return false;
    uint32_t Want = N;
    if (St.Count.compare_exchange_strong(Want, N + 1, std::memory_order_acq_rel)) { St.Pages[N].store(Page, std::memory_order_release); return true; }
  }
}
// Called by the memory notifications BEFORE the change is made (Size 0 = unknown extent: everything from Address up to MaxUnknown bytes).
inline void Note(uint64_t Address, uint64_t Size) {
  auto& St = S();
  const uint32_t N = St.Count.load(std::memory_order_acquire);
  if (!N) return;
  constexpr uint64_t MaxUnknown = 0x4000000;
  const uint64_t End = Address + (Size ? Size : MaxUnknown);
  for (uint32_t i = 0; i < N; ++i) {
    const uint64_t P = St.Pages[i].load(std::memory_order_acquire);
    if (P && Address < P + 0x1000 && End > P) { St.Taint.store(1, std::memory_order_release); return; }
  }
}
} // namespace FEXCore::HBX87::CrtWatch
