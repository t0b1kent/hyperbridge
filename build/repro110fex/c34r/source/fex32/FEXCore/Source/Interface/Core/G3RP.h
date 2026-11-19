// SPDX-License-Identifier: MIT
// G3FABLE 12.11.2026 (MacRunner contributors): keys of the reduced-precision x87 path, default 0.
#pragma once
#include <cstdlib>
#include <cstdint>
#include <utility> // RP6s
namespace FEXCore::HBX87::RP {
inline bool KeyOn(const char* Name) { const char* p = std::getenv(Name); return p && p[0] == '1' && !p[1]; }
inline bool Int64() { static const bool v = KeyOn("MACRUNNER_FEX32_X87_RP_INT64"); return v; }
inline int PC24Mode() { static const int v = [] { const char* p = std::getenv("MACRUNNER_FEX32_X87_RP_PC24"); return (p && !p[1] && (p[0] == '1' || p[0] == '2')) ? p[0] - '0' : 0; }(); return v; }
inline bool PC24() { return PC24Mode() != 0; }
// RP6s diagnostic (default: the whole address space, i.e. no change): MACRUNNER_FEX32_X87_RP_PC24_RANGE=<lo>-<hi>, hex guest addresses.
struct PC24Ranges {
  unsigned N = 0;
  uint64_t Lo[8] {}, Hi[8] {};
};
inline const PC24Ranges& PC24RangeList() {
  static const PC24Ranges v = [] {
    PC24Ranges R;
    const char* p = std::getenv("MACRUNNER_FEX32_X87_RP_PC24_RANGE");
    if (!p || !*p) {
      R.N = 1;
      R.Lo[0] = 0;
      R.Hi[0] = ~0ULL;
      return R;
    }
    while (*p && R.N < 8) {
      char* e = nullptr;
      const uint64_t Lo = std::strtoull(p, &e, 16);
      if (e == p) break;
      uint64_t Hi = ~0ULL;
      if (e && *e == '-') {
        const char* q = e + 1;
        Hi = std::strtoull(q, &e, 16);
      }
      R.Lo[R.N] = Lo;
      R.Hi[R.N] = Hi;
      ++R.N;
      while (e && (*e == ',' || *e == ' ')) {
        ++e;
      }
      if (!e || !*e) break;
      p = e;
    }
    if (!R.N) {
      R.N = 1;
      R.Lo[0] = 0;
      R.Hi[0] = ~0ULL;
    }
    return R;
  }();
  return v;
}
inline bool PC24InRange(uint64_t Rip) {
  const auto& R = PC24RangeList();
  for (unsigned i = 0; i < R.N; ++i) {
    if (Rip >= R.Lo[i] && Rip < R.Hi[i]) return true;
  }
  return false;
}
// RP6f (A10): fist / fistp / fisttp through FRINT32X / FRINT64X - exact x86 integer indefinite (caller checks FEAT_FRINTTS).
inline bool Frint() { static const bool v = KeyOn("MACRUNNER_FEX32_X87_RP_FRINT"); return v; }
}
