// SPDX-License-Identifier: MIT
// G3FABLE 12.11.2026 (MacRunner contributors): MACRUNNER_FEX32_X87_UNIT_SHAPE=<1..6>, default 0 (see apply_rp6.py / PHASE6.md).
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
namespace FEXCore::HBX87::UnitShape {
inline unsigned Level() {
  static const unsigned v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_UNIT_SHAPE");
    return (p && p[0] >= '1' && p[0] <= '6' && !p[1]) ? static_cast<unsigned>(p[0] - '0') : 0u;
  }();
  return v;
}
inline bool Enabled() { return Level() != 0; }
// MACRUNNER_FEX32_X87_UNIT_SHAPE_PAYLOAD=1 (default 0; a measuring option): a shape block stores the value of a register it pops
// into mm[] (the payload a real x87 leaves in the emptied register), as the slow path does.
inline bool Payload() {
  static const bool v = [] { const char* p = std::getenv("MACRUNNER_FEX32_X87_UNIT_SHAPE_PAYLOAD"); return p && p[0] == '1' && !p[1]; }();
  return v;
}
// Counters for the stands (native builds only; the PE translator has no stdio and takes no static destructor from here).
namespace Stats {
enum Counter : unsigned { Marked, Dropped, RegCells, RegBlocks, Count };
#ifndef _WIN32
struct Table {
  std::atomic<uint64_t> V[Count] {};
  ~Table() {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_UNIT_SHAPE_STATS");
    if (p && p[0] == '1') {
      std::fprintf(stderr, "g3-unit-shape-stats: marked_records=%llu dropped_records=%llu reg_cells=%llu reg_blocks=%llu\n",
                   (unsigned long long)V[Marked].load(), (unsigned long long)V[Dropped].load(), (unsigned long long)V[RegCells].load(),
                   (unsigned long long)V[RegBlocks].load());
    }
  }
};
inline void Bump(Counter C, uint64_t N = 1) {
  static Table T;
  T.V[C].fetch_add(N, std::memory_order_relaxed);
}
#else
inline void Bump(Counter, uint64_t = 1) {}
#endif
} // namespace Stats
// Guard format (PHASE6.md 5/6, agreed with X87EXACT): Mode bit 2 = RP unit, bit 7 = shape only.
inline constexpr unsigned char GuardMode = 0x84;
} // namespace FEXCore::HBX87::UnitShape
