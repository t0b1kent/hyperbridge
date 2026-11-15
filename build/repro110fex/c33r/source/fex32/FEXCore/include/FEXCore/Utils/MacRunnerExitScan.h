// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// ★ REGION4 13.11.2026 MACRUNNER_FEX32_EXIT_SCAN: the one-instruction step of the flag scan (Decoder::MRTargetKillsFlags), shared with
// the WOW64 suspend handler, which must recognise the same windows "entry .. first full flag write" as the translator.
// One prefix-free x86-32 instruction at P (16 readable bytes): its length, the status flags it writes (bit 0 C, 1 P, 2 A, 3 Z, 4 S,
// 5 O). Only instructions whose OpcodeDispatcher handlers write (or invalidate) exactly these flags unconditionally and read none are
// listed; anything else stops the scan with "flags live". Kept deliberately small: prologues are push / mov / lea / sub / test / cmp.
#pragma once
#include <cstdint>

namespace FEXCore::Utils {
struct MRScanStep {
  uint8_t Length; // 0 = stop: unknown, reads flags, or transfers control
  uint8_t Kills;
};
inline constexpr uint8_t MRAllFlags = 0x3f, MRAllButCarry = 0x3e;
inline unsigned MRModRMLength(const uint8_t* P) { // P -> ModRM; 32-bit addressing
  const unsigned Mod = P[0] >> 6, RM = P[0] & 7;
  unsigned Length = 1;
  if (Mod != 3) {
    if (RM == 4) {
      ++Length;
      if (Mod == 0 && (P[1] & 7) == 5) Length += 4;
    }
    if (Mod == 1) Length += 1;
    else if (Mod == 2 || (Mod == 0 && RM == 5)) Length += 4;
  }
  return Length;
}
inline MRScanStep MRScanOne(const uint8_t* P) {
  unsigned Prefix = 0;
  if (P[0] == 0x64) { // fs: on a plain move only (SEH prologues: mov eax, fs:[0]; mov fs:[0], esp)
    if (P[1] != 0x8B && P[1] != 0x89 && P[1] != 0xA1 && P[1] != 0xA3) return {0, 0};
    Prefix = 1;
    ++P;
  }
  if (!Prefix && P[0] == 0x66 && P[1] == 0x90) return {2, 0}; // two-byte nop: the hot-patch pad at the entry of Wine's i386 functions
  const uint8_t B = P[0];
  const unsigned Reg = (P[1] >> 3) & 7;
  const auto Len = [Prefix](unsigned L) { return static_cast<uint8_t>(Prefix + L); };
  if (B < 0x40 && (B & 7) < 6) { // add or adc sbb and sub xor cmp
    const unsigned Kind = (B >> 3) & 7;
    if (Kind == 2 || Kind == 3 || Prefix) return {0, 0};
    return {Len((B & 7) < 4 ? 1 + MRModRMLength(P + 1) : (B & 7) == 4 ? 2 : 5), MRAllFlags};
  }
  if (B >= 0x40 && B <= 0x4F) return Prefix ? MRScanStep {0, 0} : MRScanStep {1, MRAllButCarry}; // inc / dec r32
  if (B >= 0x50 && B <= 0x5F) return Prefix ? MRScanStep {0, 0} : MRScanStep {1, 0};             // push / pop r32
  switch (B) {
  case 0x68: return Prefix ? MRScanStep {0, 0} : MRScanStep {5, 0};
  case 0x6A: return Prefix ? MRScanStep {0, 0} : MRScanStep {2, 0};
  case 0x80:
  case 0x81:
  case 0x83:
    if (Reg == 2 || Reg == 3 || Prefix) return {0, 0};
    return {Len(1 + MRModRMLength(P + 1) + (B == 0x81 ? 4 : 1)), MRAllFlags};
  case 0x84:
  case 0x85: return Prefix ? MRScanStep {0, 0} : MRScanStep {Len(1 + MRModRMLength(P + 1)), MRAllFlags};
  case 0x88:
  case 0x89:
  case 0x8A:
  case 0x8B: return {Len(1 + MRModRMLength(P + 1)), 0};
  case 0x8D: return (P[1] >> 6) == 3 || Prefix ? MRScanStep {0, 0} : MRScanStep {Len(1 + MRModRMLength(P + 1)), 0};
  case 0x90: return Prefix ? MRScanStep {0, 0} : MRScanStep {1, 0};
  case 0xA0:
  case 0xA1:
  case 0xA2:
  case 0xA3: return {Len(5), 0};
  case 0xA8: return Prefix ? MRScanStep {0, 0} : MRScanStep {2, MRAllFlags};
  case 0xA9: return Prefix ? MRScanStep {0, 0} : MRScanStep {5, MRAllFlags};
  case 0xC6:
  case 0xC7: return Reg != 0 || Prefix ? MRScanStep {0, 0} : MRScanStep {Len(1 + MRModRMLength(P + 1) + (B == 0xC7 ? 4 : 1)), 0};
  case 0xF6:
  case 0xF7:
    if (Prefix) return {0, 0};
    if (Reg == 0 || Reg == 1) return {Len(1 + MRModRMLength(P + 1) + (B == 0xF7 ? 4 : 1)), MRAllFlags}; // test
    if (Reg == 2) return {Len(1 + MRModRMLength(P + 1)), 0};                                          // not
    if (Reg == 3) return {Len(1 + MRModRMLength(P + 1)), MRAllFlags};                                 // neg
    return {0, 0};
  case 0xFE:
  case 0xFF:
    if (Prefix) return {0, 0};
    if (Reg == 0 || Reg == 1) return {Len(1 + MRModRMLength(P + 1)), MRAllButCarry}; // inc / dec r/m
    if (B == 0xFF && Reg == 6) return {Len(1 + MRModRMLength(P + 1)), 0};            // push r/m
    return {0, 0};
  case 0x0F:
    if (Prefix) return {0, 0};
    if (P[1] == 0xB6 || P[1] == 0xB7 || P[1] == 0xBE || P[1] == 0xBF || P[1] == 0x1F) return {Len(2 + MRModRMLength(P + 2)), 0}; // movzx / movsx / nop
    return {0, 0};
  default: return {0, 0};
  }
}

// Windows of the scan, scanned from Address over at most 24 listed instructions. Readable(Address, Size) answers whether the bytes
// may be read (the translator: executable and not writable; the suspend handler: committed and readable -- never stricter than the
// translator, so every window the translator relied on is recognised).
template<typename ReadableFn>
inline bool MRScanKillsAllFlags(uint64_t Address, ReadableFn&& Readable) {
  unsigned Need = MRAllFlags;
  for (unsigned Count = 0; Count < 24; ++Count) {
    constexpr uint64_t Window = 16;
    if (Address + Window > 0x100000000ULL || !Readable(Address, Window)) {
      return false;
    }
    const MRScanStep Step = MRScanOne(reinterpret_cast<const uint8_t*>(Address));
    if (!Step.Length) {
      return false;
    }
    Need &= ~Step.Kills;
    if (!Need) {
      return true;
    }
    Address += Step.Length;
  }
  return false;
}
} // namespace FEXCore::Utils
