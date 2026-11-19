// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
#pragma once
#include <cstdlib>

namespace FEXCore::HBX87::StateFix {
inline bool ReadGate(const char* Name) {
  const char* Value = std::getenv(Name);
  return Value && Value[0] == '1' && Value[1] == '\0';
}
// MacRunner X87-F3 (15.10.2026): our 0038 (POP_TAG) and 0039 (STICKY_IE) are replaced by upstream FEX 21b8f8e20 and
// 4a7fda451 (unconditional). Own fix, off by default: FUCOM/FUCOMP/FUCOMPP/FUCOMI/FUCOMIP raise IE only for a signaling
// NaN (F80: the F80CmpQuiet fallback; F64/reduced precision: an integer SNaN test), and the F64 compares publish IE at all.
inline bool QuietCompare() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_QUIET_COMPARE");
  return Enabled;
}
// MacRunner X87-F4.3: C1 after FLD m32/m64, FST m32/m64, FIST/FISTP/FISTTP, FRNDINT, FSQRT, FADD/FSUB/FMUL/FDIV is the "rounded up"
// indicator: 1 when rounding increased the magnitude, otherwise 0. SoftFloat reports it as softfloat_flag_roundup.
inline bool C1Roundup() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_C1_ROUNDUP");
  return Enabled;
}
// X87EXACT 13.11.2026 (X87EXACT C1C): C1 after the instructions that are not rounding arithmetic, as the hardware sets it (reference
// artifacts/claude-lanes-20261112-x87exact/hw/x87c1m-1, Zen 5): a successful FLD / FILD / FBLD / constant load, FST / FSTP ST(i),
// FSTP m80, FCHS, FABS, FFREE, FINCSTP, FDECSTP clear it (an overflowing push sets it). Exact 32-bit path, default 0.
inline bool C1Clear() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_C1_CLEAR");
  return Enabled;
}
inline bool EnvTags() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_ENV_TAGS");
  return Enabled;
}
inline bool ExceptionFlags() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_EXCEPTION_FLAGS");
  return Enabled;
}
inline bool OrdinaryRemainder() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_ORDINARY_REMAINDER");
  return Enabled;
}
inline bool PartialRemainder() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_PARTIAL_REMAINDER");
  return Enabled;
}
inline bool Scale() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_SCALE");
  return Enabled;
}
// MacRunner X87-F4.2: the x87 exception flags DE/ZE/OE/UE/PE (and ES/B) are kept for Guest32 too, unless the PE32 register bank
// (MACRUNNER_HB_X87_STATIC_REGS) computes x87 arithmetic inline without SoftFloat, where no flag source exists.
inline bool StaticRegs32() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_STATIC_REGS");
  return Enabled;
}
inline bool ExceptionFlagsFor(bool Guest64) {
  return ExceptionFlags() && (Guest64 || !StaticRegs32());
}
inline bool ExceptionState(bool Guest64) {
  return ExceptionFlagsFor(Guest64) || OrdinaryRemainder() || PartialRemainder() || Scale();
}
inline bool InstructionPointers32() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_FIP_CS32");
  return Enabled;
}
// LAZY-FLAGS X87-CTX P5: the x87 stack pass keeps pushed values, TOP and tags in SSA values until the block exit. With this
// gate a guest fault inside the block restores them into CPUState from a per-op table in the block tail (no host code on the
// normal path). Read at translation time and by the frontends' state reconstruction.
inline bool FaultState() {
  static const bool Enabled = ReadGate("MACRUNNER_FEX_X87_FAULT_STATE");
  return Enabled;
}
// Translation-time lookup; never initialize a guard from the signal path.
inline bool WinctxExact() {
  return ReadGate("MACRUNNER_WINCTX_EXACT");
}
// SPEED114/X87EXACT 19.11.2026 (FXAM class): FXAM reports the real class of ST0 (zero, denormal, infinity, NaN, unsupported encoding) instead
// of "normal" for every occupied register. Hardware reference: the six x87c1m words after a stack overflow (Zen 5: C3:C2:C0 = 001, a NaN).
inline bool FxamClass() {
  static const bool Enabled = ReadGate("MACRUNNER_HB_X87_FIX_FXAM_CLASS");
  return Enabled;
}
}
