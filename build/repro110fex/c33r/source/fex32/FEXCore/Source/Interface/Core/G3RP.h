// SPDX-License-Identifier: MIT
// G3FABLE 12.11.2026 (MacRunner contributors): keys of the reduced-precision x87 path, default 0.
#pragma once
#include <cstdlib>
namespace FEXCore::HBX87::RP {
inline bool KeyOn(const char* Name) { const char* p = std::getenv(Name); return p && p[0] == '1' && !p[1]; }
inline bool Int64() { static const bool v = KeyOn("MACRUNNER_FEX32_X87_RP_INT64"); return v; }
inline int PC24Mode() { static const int v = [] { const char* p = std::getenv("MACRUNNER_FEX32_X87_RP_PC24"); return (p && !p[1] && (p[0] == '1' || p[0] == '2')) ? p[0] - '0' : 0; }(); return v; }
inline bool PC24() { return PC24Mode() != 0; }
// RP6f (A10): fist / fistp / fisttp through FRINT32X / FRINT64X - exact x86 integer indefinite (caller checks FEAT_FRINTTS).
inline bool Frint() { static const bool v = KeyOn("MACRUNNER_FEX32_X87_RP_FRINT"); return v; }
}
