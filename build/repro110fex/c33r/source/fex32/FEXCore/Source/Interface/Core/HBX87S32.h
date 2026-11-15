// SPDX-License-Identifier: MIT
// X87EXACT 12.11.2026 (MacRunner contributors): "S32" -- the typed binary32 path of the x87 stack pass, one mechanism for the exact
// lowering (X87EXACT) and the reduced-precision lowering (G3FABLE). Interface: MECHANISM.md par. 7 of the X87EXACT lane.
//
// A stack value is TYPED when the pass holds, next to its usual node (container / stack double), an FPR node whose low 32 bits are a
// binary32 number equal to the x87 register (IR/Passes/x87S32.inl). Arithmetic on two typed values runs in binary32 where the
// unit's guard guarantees the control word 0x003F (shared guard format: precision field 01); stores to m32, copies and sign changes
// of typed values do not depend on the word.
//
// Exact lowering, MACRUNNER_FEX32_X87_EXACT_S32=1 (default 0, with MACRUNNER_FEX32_X87_EXACT_DYN):
//  * A typed single is +-0, a normal binary32, or a BOX IN A SINGLE: the quiet NaN 0x7FE00000 | slot, sign bit = value sign, for
//    everything else (NaN, infinity, subnormal, values outside the binary32 range). fcvt d, s turns it into a container box whose
//    slot number sits in bits 29..40 (HBX87PCX.h Unbox takes both layouts), so widening needs no check.
//  * fld m32: the exponent field is tested in line (1..254: the value itself); the rest goes through the container load stub.
//  * add / sub / mul / div / sqrt: the host binary32 operation; the result's exponent field must be 4..251 (PROOF.md S32: the
//    binary32 rounding is the x87 PC24 rounding there), FSW.PE must be 1 (read once per block), otherwise the cold part -- the
//    container form of c33m on the widened operands, its result narrowed back. In units without an FPSR record the operand exponents
//    are checked BEFORE the operation, so that the host can raise no status bit but IXC.
//  * fst m32: the 32 bits as they are; a box goes through the container store stub.
// The x87 fault records name a typed value by its single (X87Fault::Record::SingleMask, format version 2).
#pragma once
#include "Interface/Core/HBX87PCX.h"
#include "Interface/Core/HBX87StateGates.h"

namespace FEXCore::HBX87::S32 {
inline bool Exact() {
#if defined(VIXL_SIMULATOR) || defined(ARCHITECTURE_arm64ec)
  return false;
#else
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_EXACT_S32");
    return p && p[0] == '1' && !p[1];
  }();
  return v && PCX::DynEnabled() && !PCX::KeepLR();
#endif
}
// The reduced-precision lowering's key belongs to G3FABLE.
inline bool RP() {
  return false;
}
// Deliberate defects for the negative control of the gates: only in a build with -DMACRUNNER_S32_MUTANTS=1 (never staged), chosen
// there by MACRUNNER_FEX32_X87_EXACT_S32_MUT=<n>. Every other build has none of them. 1 no range check of the result, 2 no FSW.PE
// check, 3 fst m32 without the box check, 4 fld m32 without the check, 5 no operand checks of the S protocol, 6 add for sub in
// the cold +-0 case, 7 narrowing without the significand check, 8 C1 not computed by the forms with the C1 duty, 9 the cold part takes any result that
// failed the range check as an exact +-0 would be taken, 10 fault records do not say which values are singles, 11 the exact
// +-0 taken by the cold part gets the wrong sign, 12 the in-line C1 compare the other way round, 13 no exponent-gap check before the
// in-line C1 of a sum.
inline unsigned Mutant() {
#ifdef MACRUNNER_S32_MUTANTS
  static const unsigned v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_EXACT_S32_MUT");
    return p ? static_cast<unsigned>(strtoul(p, nullptr, 10)) : 0u;
  }();
  return v;
#else
  return 0;
#endif
}

// FSW.PE is tracked where the container forms track it (Dispatcher/HBX87PCXStubs.inl DynPE).
inline bool PECheck() {
  return StateFix::ExceptionFlags() && !StateFix::StaticRegs32();
}
// The C++ end of the narrowing (Interpreter/Fallbacks/InterpreterFallbacks.cpp): called through the F80_I16_F80_PTR fallback ABI.
uint64_t NarrowHandlerAddress();

inline constexpr uint32_t BoxBaseS = 0x7FE00000u;
// Pointers.X87PCXS32Cold: the cold parts' stubs (Dispatcher/HBX87PCXStubs.inl).
enum Cold : uint32_t {
  ColdLoad = 0,   // fld m32 value that is not a normal binary32
  ColdFirstS = 1, // the run's first raising form, S protocol (guest status without PE)
  ColdFirst = 2,  // ... plain protocol (stand-only MACRUNNER_FEX32_X87_PC_EXACT_SAT=0)
  ColdGeneric = 3, // the entry the unit's cold code calls: operands / destination by register number (ColdDesc), then the stub
  ColdStore = 4,  // + C1 | Sat << 1
  ColdArith = 8,  // + Kop | C1 << 3 | Sat << 4
  ColdCount = 40,
};

// The descriptor word behind the cold call of a unit ("bl <trampoline>; .word descriptor; b <back>").
inline constexpr uint32_t ColdDescB = 5, ColdDescDst = 10, ColdDescStub = 15, ColdDescHasDst = 21;

inline bool IsBoxS(uint32_t b) {
  return ((b >> 23) & 0xFF) == 0xFF;
}
// Typed single that is not a box -> 80-bit, exactly.
inline PCX::Raw80 SingleTo80(uint32_t b) {
  PCX::Raw80 r {};
  const uint32_t Sign = b >> 31, E = (b >> 23) & 0xFF, M = b & 0x7FFFFF;
  if (E == 0) {
    if (M) { // not produced by the typed forms, converted exactly anyway
      const unsigned Msb = 31 - static_cast<unsigned>(__builtin_clz(M));
      r.Sig = static_cast<uint64_t>(M) << (63 - Msb);
      r.SE = static_cast<uint16_t>((Sign << 15) | (Msb + 16383 - 149));
    } else {
      r.SE = static_cast<uint16_t>(Sign << 15);
    }
    return r;
  }
  r.Sig = (1ULL << 63) | (static_cast<uint64_t>(M) << 40);
  r.SE = static_cast<uint16_t>((Sign << 15) | (E + 16383 - 127));
  return r;
}
inline PCX::Raw80 UnboxS(FEXCore::Core::CpuStateFrame* Frame, uint32_t b) {
  if (!IsBoxS(b)) {
    return SingleTo80(b);
  }
  return PCX::Unbox(Frame, (static_cast<uint64_t>(b >> 31) << 63) | PCX::BoxBase | (b & PCX::BoxIndexMask));
}
// Container or box (either layout) -> typed single. A value that is not +-0 or a binary32 with the exponent field 4..251 (the
// range the typed arithmetic results keep, so that sums of results cannot overflow) is boxed: at most one slot per call, none when
// the input already is a box.
inline uint32_t Narrow(FEXCore::Core::CpuStateFrame* Frame, uint64_t b) {
  const uint32_t Sign = static_cast<uint32_t>(b >> 63) << 31;
  if (PCX::IsBox(b)) {
    return Sign | BoxBaseS | static_cast<uint32_t>((b | (b >> 29)) & PCX::BoxIndexMask);
  }
  if ((b << 1) == 0) {
    return Sign;
  }
  const uint64_t E = (b >> 52) & 0x7FF, M = b & ((1ULL << 52) - 1);
  if (E >= 1023 - 127 + 4 && E <= 1023 - 127 + 251 && !(M & ((1ULL << 29) - 1))) {
    return Sign | static_cast<uint32_t>((E - 1023 + 127) << 23) | static_cast<uint32_t>(M >> 29);
  }
  PCX::Raw80 r = PCX::DoubleTo80(b);
  r.Pad[0] = r.Pad[1] = r.Pad[2] = 0;
  auto& B = Frame->Thread->X87PCX;
  unsigned Index = B.Next++ & PCX::BoxIndexMask;
  if (Index == PCX::IndefIndex) {
    Index = B.Next++ & PCX::BoxIndexMask;
  }
  memcpy(B.Slot[Index], &r, sizeof(r));
  B.Boxed++;
  return Sign | BoxBaseS | Index;
}
} // namespace FEXCore::HBX87::S32
