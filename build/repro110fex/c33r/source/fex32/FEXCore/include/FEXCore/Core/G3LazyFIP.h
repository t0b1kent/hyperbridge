// SPDX-License-Identifier: MIT
// G3FABLE 12.11.2026 (MacRunner contributors): lazy x87 last-instruction pointer, MACRUNNER_FEX32_X87_LAZY_FIP (default 0).
#pragma once
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/fextl/map.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
namespace FEXCore::HBX87::LazyFIP {
inline bool Enabled() {
  static const bool v = [] { const char* p = std::getenv("MACRUNNER_FEX32_X87_LAZY_FIP"); return p && p[0] == '1' && !p[1]; }();
  return v;
}
// G3FABLE RP6q (keys, default 0): FCS as a per-process constant (one 64-bit pointer store; readers resolve CS), and no eager write
// for the first x87 instruction of a segment (OnLeave resolves from the guest RIP).
inline bool FcsConst() {
  static const bool v = [] { const char* p = std::getenv("MACRUNNER_FEX32_X87_FCS_CONST"); return p && p[0] == '1' && !p[1]; }();
  return v;
}
inline bool FirstLazy() { // needs DEOPT_EXACT_RIP: a deopt must not resume past a first instruction left without host code
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_FIP_FIRST_LAZY");
    const char* q = std::getenv("MACRUNNER_FEX32_X87_DEOPT_EXACT_RIP");
    return p && p[0] == '1' && !p[1] && q && q[0] == '1' && !q[1];
  }();
  return v && Enabled();
}
struct Registry {
  std::atomic_flag Busy = ATOMIC_FLAG_INIT;
  fextl::map<uint32_t, uint32_t> Tracked; // tracked x87 instruction address -> end of its straight-line segment
  void Lock() { while (Busy.test_and_set(std::memory_order_acquire)) {} }
  void Unlock() { Busy.clear(std::memory_order_release); }
};
inline Registry& Reg() { static Registry R; return R; }
inline void BlockBegin(uint32_t Start, uint32_t End) {
  auto& R = Reg(); R.Lock();
  R.Tracked.erase(R.Tracked.lower_bound(Start), R.Tracked.lower_bound(End));
  R.Unlock();
}
inline void SetSegment(const uint32_t* PCs, size_t N, uint32_t End) {
  auto& R = Reg(); R.Lock();
  for (size_t i = 0; i < N; ++i) R.Tracked[PCs[i]] = End;
  R.Unlock();
}
// State.rip = the instruction the block was left at (a fault inside it: its own store would already have run in the eager scheme).
inline void OnLeave(FEXCore::Core::CPUState& S) {
  if (!Enabled()) return;
  const uint32_t F = S.X87LastInstruction32.IP, Rip = static_cast<uint32_t>(S.rip);
  auto& R = Reg(); R.Lock();
  if (FirstLazy()) { // RP6q: the segment's first instruction wrote nothing; the guest RIP alone names the last x87 instruction run
    // -- strictly BEFORE Rip: State.rip is an instruction that has not completed (a precise fault, or a poll at a block entry
    // whose first instruction is x87 and has not started); AMD's FXSAVE does not even carry FIP across a fault (rega 13.11).
    auto Ub = R.Tracked.lower_bound(Rip);
    if (Ub != R.Tracked.begin()) {
      --Ub;
      if (Rip < Ub->second) { S.X87LastInstruction32.IP = Ub->first; S.X87LastInstruction32.CS = S.cs_idx; S.X87LastInstruction32.Reserved = 0; }
    }
    R.Unlock();
    return;
  }
  auto It = R.Tracked.find(F);
  if (It != R.Tracked.end() && F <= Rip && Rip < It->second) {
    auto Ub = R.Tracked.upper_bound(Rip); --Ub;
    if (Ub->first >= F) { S.X87LastInstruction32.IP = Ub->first; S.X87LastInstruction32.CS = S.cs_idx; }
  }
  R.Unlock();
}
} // namespace FEXCore::HBX87::LazyFIP
