// SPDX-License-Identifier: MIT
#pragma once
#include "Common/SoftFloat.h"
#include "Interface/Core/HBX87StateGates.h"
#include "Interface/Core/HBX87OrdinaryRemainder.h"
#include "Interface/Core/HBX87Scale.h"
#include "Interface/Context/Context.h"

#include "Interface/Core/Interpreter/Fallbacks/FallbackOpHandler.h"
#include "Interface/IR/IR.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Core/MacRunnerWinctx.h>
#include <FEXCore/Utils/SHMStats.h>

namespace FEXCore::CPU {
FEXCORE_PRESERVE_ALL_ATTR static softfloat_state SoftFloatStateFromFCW(uint16_t FCW, bool Force80BitPrecision = false) {
  softfloat_state State {};
  State.detectTininess = softfloat_tininess_afterRounding;
  State.exceptionFlags = 0;
  State.roundingPrecision = 80;

  if (!Force80BitPrecision) {
    auto PC = (FCW >> 8) & 3;
    switch (PC) {
    case 0: State.roundingPrecision = 32; break;
    case 2: State.roundingPrecision = 64; break;
    case 3: State.roundingPrecision = 80; break;
    case 1: LOGMAN_MSG_A_FMT("Invalid x87 precision mode, {}", PC);
    }
  }

  auto RC = (FCW >> 10) & 3;
  switch (RC) {
  case 0: State.roundingMode = softfloat_round_near_even; break;
  case 1: State.roundingMode = softfloat_round_min; break;
  case 2: State.roundingMode = softfloat_round_max; break;
  case 3: State.roundingMode = softfloat_round_minMag; break;
  }

  return State;
}

FEXCORE_PRESERVE_ALL_ATTR static void HandleX87Exception(const softfloat_state& State, FEXCore::Core::CpuStateFrame* Frame,
                                                       bool PublishIEEEFlags) {
  // Check for Invalid Operation exception (bit 0 of X87 status word)
  if (State.exceptionFlags & softfloat_flag_invalid) {
    Frame->State.flags[FEXCore::X86State::X87FLAG_IE_LOC] = 1;
  }
  if (PublishIEEEFlags && FEXCore::HBX87::StateFix::C1Roundup()) {
    // MacRunner X87-F4.3: the scopes that publish IEEE flags are exactly the instructions whose C1 is the round-up indicator.
    // An invalid operation returns an indefinite, which was not rounded: C1 = 0.
    Frame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] =
      (State.exceptionFlags & (softfloat_flag_roundup | softfloat_flag_invalid)) == softfloat_flag_roundup;
  }
  // Gate first: with the key off nothing else is loaded (the Guest64 test reads three pointers).
  if (PublishIEEEFlags && FEXCore::HBX87::StateFix::ExceptionFlags() &&
      (!FEXCore::HBX87::StateFix::StaticRegs32() || static_cast<const FEXCore::Context::ContextImpl*>(Frame->Thread->CTX)->Config.Is64BitMode())) {
    // SoftFloat flags use a different numbering from the x87 status word.
    // They are sticky; neither a successful operation nor an unrelated SSE
    // operation may clear an already raised x87 exception.
    if (State.exceptionFlags & softfloat_flag_infinite) {
      Frame->State.flags[FEXCore::X86State::X87FLAG_ZE_LOC] = 1;
    }
    if (State.exceptionFlags & softfloat_flag_overflow) {
      Frame->State.flags[FEXCore::X86State::X87FLAG_OE_LOC] = 1;
    }
    if (State.exceptionFlags & softfloat_flag_underflow) {
      Frame->State.flags[FEXCore::X86State::X87FLAG_UE_LOC] = 1;
    }
    if (State.exceptionFlags & softfloat_flag_inexact) {
      Frame->State.flags[FEXCore::X86State::X87FLAG_PE_LOC] = 1;
    }
    // Preserve/serialize DE, but do not invent it from a SoftFloat flag:
    // SoftFloat has no denormal-operand flag. C1 likewise needs rounding
    // direction, not merely inexact. Delivery of unmasked traps is separate.
  }
  if (PublishIEEEFlags && FEXCore::Winctx::Enabled.load(std::memory_order_relaxed)) {
    // SoftFloat reports only this operation's flags; x87 accumulates them.
    auto& Flags = Frame->State.flags;
    if (State.exceptionFlags & softfloat_flag_infinite) Flags[FEXCore::X86State::X87FLAG_ZE_LOC] = 1;
    if (State.exceptionFlags & softfloat_flag_overflow) Flags[FEXCore::X86State::X87FLAG_OE_LOC] = 1;
    if (State.exceptionFlags & softfloat_flag_underflow) Flags[FEXCore::X86State::X87FLAG_UE_LOC] = 1;
    if (State.exceptionFlags & softfloat_flag_inexact) Flags[FEXCore::X86State::X87FLAG_PE_LOC] = 1;
    const unsigned Pending = ((Flags[FEXCore::X86State::X87FLAG_IE_LOC] & 1) |
                              ((Flags[FEXCore::X86State::X87FLAG_DE_LOC] & 1) << 1) |
                              ((Flags[FEXCore::X86State::X87FLAG_ZE_LOC] & 1) << 2) |
                              ((Flags[FEXCore::X86State::X87FLAG_OE_LOC] & 1) << 3) |
                              ((Flags[FEXCore::X86State::X87FLAG_UE_LOC] & 1) << 4) |
                              ((Flags[FEXCore::X86State::X87FLAG_PE_LOC] & 1) << 5)) & ~Frame->State.FCW & 0x3f;
    Flags[FEXCore::X86State::X87FLAG_ES_LOC] = Flags[FEXCore::X86State::X87FLAG_B_LOC] = !!Pending;
  }
}

// TRANS32 0033: x87 raises DE for a denormal source operand (an m32 / m64 denormal, or an 80-bit value with exponent 0 and a
// nonzero significand: denormal or pseudo-denormal). SoftFloat has no such flag. With DM unmasked the event is pending: ES and B.
static inline void MRRaiseDE(FEXCore::Core::CpuStateFrame* Frame) {
  auto& Flags = Frame->State.flags;
  Flags[FEXCore::X86State::X87FLAG_DE_LOC] = 1;
  if (!(Frame->State.FCW & 2)) {
    Flags[FEXCore::X86State::X87FLAG_ES_LOC] = 1;
    Flags[FEXCore::X86State::X87FLAG_B_LOC] = 1;
  }
}
static inline bool MRDETracked(FEXCore::Core::CpuStateFrame* Frame) {
  return FEXCore::HBX87::StateFix::ExceptionFlags() &&
         (!FEXCore::HBX87::StateFix::StaticRegs32() || static_cast<const FEXCore::Context::ContextImpl*>(Frame->Thread->CTX)->Config.Is64BitMode());
}
static inline void MRNoteDenormal(FEXCore::Core::CpuStateFrame* Frame, VectorRegType Src) {
  if (!MRDETracked(Frame)) return;
  uint64_t Sig;
  uint16_t SE;
  memcpy(&Sig, &Src, 8);
  memcpy(&SE, reinterpret_cast<const uint8_t*>(&Src) + 8, 2);
  if ((SE & 0x7FFF) == 0 && Sig != 0) MRRaiseDE(Frame);
}
static inline void MRNoteDenormalF32(FEXCore::Core::CpuStateFrame* Frame, uint32_t Bits) {
  if (MRDETracked(Frame) && (Bits & 0x7F800000u) == 0 && (Bits & 0x007FFFFFu) != 0) MRRaiseDE(Frame);
}
static inline void MRNoteDenormalF64(FEXCore::Core::CpuStateFrame* Frame, uint64_t Bits) {
  if (MRDETracked(Frame) && (Bits & 0x7FF0000000000000ULL) == 0 && (Bits & 0x000FFFFFFFFFFFFFULL) != 0) MRRaiseDE(Frame);
}

// Wrapper for SoftFloat state to handle X87 exceptions
// IEEE exception flags are architectural only for supported ext80 operands.
// Unsupported nonzero-exponent/J=0 encodings need x87 invalid semantics;
// SoftFloat can instead treat them as finite and raise unrelated PE/OE/UE.
// Keep their existing precise path until that separate encoding family is fixed.
static inline bool SupportedX87IEEEOperand(VectorRegType Src) {
  const X80SoftFloat Value {Src};
  return Value.Top.Exponent == 0 || (Value.Significand & (1ULL << 63)) != 0;
}

class ScopedSoftFloatState {
public:
  FEXCORE_PRESERVE_ALL_ATTR ScopedSoftFloatState(uint16_t FCW, FEXCore::Core::CpuStateFrame* Frame, bool Force80BitPrecision = false,
                                              bool PublishIEEEFlags = false)
    : State(SoftFloatStateFromFCW(FCW, Force80BitPrecision))
    , Frame(Frame)
    , PublishIEEEFlags(PublishIEEEFlags) {}

  FEXCORE_PRESERVE_ALL_ATTR ~ScopedSoftFloatState() {
    HandleX87Exception(State, Frame, PublishIEEEFlags);
  }

  // Disable copy and move to ensure RAII semantics
  ScopedSoftFloatState(const ScopedSoftFloatState&) = delete;
  ScopedSoftFloatState& operator=(const ScopedSoftFloatState&) = delete;
  ScopedSoftFloatState(ScopedSoftFloatState&&) = delete;
  ScopedSoftFloatState& operator=(ScopedSoftFloatState&&) = delete;

  softfloat_state State;

  // SoftFloat's "exact" argument requests the architectural inexact flag; it
  // does not change the rounded value. Only direct supported guest64 x87
  // conversions opt in. Composite algorithms retain their old intermediate
  // exception behaviour, and Guest32/disabled gates retain exact=false.
  bool ConversionPrecision() const {
    // MacRunner X87-F4.2: the inexact flag of a conversion costs nothing extra (SoftFloat's "exact" argument only asks for it),
    // so it follows the exception-flags key; MACRUNNER_HB_X87_FIX_CONVERSION_PE is no longer read.
    return PublishIEEEFlags && FEXCore::HBX87::StateFix::ExceptionFlags() &&
           (!FEXCore::HBX87::StateFix::StaticRegs32() ||
            static_cast<const FEXCore::Context::ContextImpl*>(Frame->Thread->CTX)->Config.Is64BitMode());
  }

private:
  FEXCore::Core::CpuStateFrame* Frame;
  // Composite cephes/remainder/scale/BCD algorithms can raise intermediate
  // SoftFloat flags that are not exceptions of the guest instruction.
  // Only direct ISA arithmetic/conversion scopes explicitly opt in.
  bool PublishIEEEFlags;
};

// TRANS32 0033 v2: DE of an 80-bit operand follows the x87 exception priority (Intel SDM vol. 1, 8.7): a NaN operand, an
// unsupported encoding (exponent != 0 with J = 0: unnormal, pseudo-infinity, pseudo-NaN), any other invalid operation and a
// divide-by-zero take precedence over the denormal-operand exception, which is then not reported. Declared AFTER the
// ScopedSoftFloatState of the handler, so its destructor runs first and sees this operation's own SoftFloat flags.
class MRDEGuard {
public:
  FEXCORE_PRESERVE_ALL_ATTR MRDEGuard(FEXCore::Core::CpuStateFrame* Frame, const softfloat_state& State, VectorRegType A)
    : Frame(Frame), State(State) { Note(A); }
  FEXCORE_PRESERVE_ALL_ATTR MRDEGuard(FEXCore::Core::CpuStateFrame* Frame, const softfloat_state& State, VectorRegType A, VectorRegType B)
    : Frame(Frame), State(State) { Note(A); Note(B); }
  FEXCORE_PRESERVE_ALL_ATTR ~MRDEGuard() {
    if (Den && !Block && !(State.exceptionFlags & (softfloat_flag_invalid | softfloat_flag_infinite)) && MRDETracked(Frame)) {
      MRRaiseDE(Frame);
    }
  }
  MRDEGuard(const MRDEGuard&) = delete;
  MRDEGuard& operator=(const MRDEGuard&) = delete;
private:
  void Note(VectorRegType V) {
    uint64_t Sig;
    uint16_t SE;
    memcpy(&Sig, &V, 8);
    memcpy(&SE, reinterpret_cast<const uint8_t*>(&V) + 8, 2);
    const uint16_t E = SE & 0x7FFF;
    if (E == 0 && Sig != 0) Den = true;
    if ((E != 0 && !(Sig >> 63)) || (E == 0x7FFF && (Sig << 1) != 0)) Block = true;
  }
  FEXCore::Core::CpuStateFrame* Frame;
  const softfloat_state& State;
  bool Den {}, Block {};
};

template<>
struct OpHandlers<IR::OP_F80CVTTO> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle4(uint16_t FCW, float src, FEXCore::Core::CpuStateFrame* Frame) {
    { uint32_t B; memcpy(&B, &src, 4); MRNoteDenormalF32(Frame, B); } // TRANS32 0033
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, true};
    return X80SoftFloat(&State.State, src);
  }

  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle8(uint16_t FCW, double src, FEXCore::Core::CpuStateFrame* Frame) {
    { uint64_t B; memcpy(&B, &src, 8); MRNoteDenormalF64(Frame, B); } // TRANS32 0033
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, true};
    return X80SoftFloat(&State.State, src);
  }
};

template<>
struct OpHandlers<IR::OP_F80CMP> {
  FEXCORE_PRESERVE_ALL_ATTR static uint64_t handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2

    bool eq, lt, nan;
    uint64_t ResultFlags = 0;

    X80SoftFloat::FCMP(&State.State, Src1, Src2, &eq, &lt, &nan);
    if (lt) {
      ResultFlags |= (1 << IR::FCMP_FLAG_LT);
    }
    if (nan) {
      ResultFlags |= (1 << IR::FCMP_FLAG_UNORDERED);
    }
    if (eq) {
      ResultFlags |= (1 << IR::FCMP_FLAG_EQ);
    }
    return ResultFlags;
  }
};

// MacRunner X87-F3: FUCOM* register forms. The only difference from OP_F80CMP is the invalid flag (IE): raised for a
// signaling NaN only, published (sticky) by ScopedSoftFloatState like every F80 fallback.
template<>
struct OpHandlers<IR::OP_F80CMPQUIET> {
  FEXCORE_PRESERVE_ALL_ATTR static uint64_t handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2

    bool eq, lt, nan;
    uint64_t ResultFlags = 0;

    X80SoftFloat::FCMPQuiet(&State.State, Src1, Src2, &eq, &lt, &nan);
    if (lt) {
      ResultFlags |= (1 << IR::FCMP_FLAG_LT);
    }
    if (nan) {
      ResultFlags |= (1 << IR::FCMP_FLAG_UNORDERED);
    }
    if (eq) {
      ResultFlags |= (1 << IR::FCMP_FLAG_EQ);
    }
    return ResultFlags;
  }
};

template<>
struct OpHandlers<IR::OP_F80CVT> {
  FEXCORE_PRESERVE_ALL_ATTR static float handle4(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    return X80SoftFloat(src).ToF32(&State.State);
  }

  FEXCORE_PRESERVE_ALL_ATTR static double handle8(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    return X80SoftFloat(src).ToF64(&State.State);
  }
};

template<>
struct OpHandlers<IR::OP_F80CVTINT> {
  FEXCORE_PRESERVE_ALL_ATTR static int16_t handle2(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    if (State.ConversionPrecision()) {
      const auto rv = extF80_to_i32(&State.State, X80SoftFloat(src), State.State.roundingMode, true);
      if (rv > INT16_MAX || rv < INT16_MIN) {
        State.State.exceptionFlags &= ~softfloat_flag_inexact;
        State.State.exceptionFlags |= softfloat_flag_invalid;
        return INT16_MIN;
      }
      return rv;
    }
    return X80SoftFloat(src).ToI16(&State.State);
  }

  FEXCORE_PRESERVE_ALL_ATTR static int32_t handle4(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    if (State.ConversionPrecision()) {
      return extF80_to_i32(&State.State, X80SoftFloat(src), State.State.roundingMode, true);
    }
    return X80SoftFloat(src).ToI32(&State.State);
  }

  FEXCORE_PRESERVE_ALL_ATTR static int64_t handle8(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    if (State.ConversionPrecision()) {
      return extF80_to_i64(&State.State, X80SoftFloat(src), State.State.roundingMode, true);
    }
    return X80SoftFloat(src).ToI64(&State.State);
  }

  FEXCORE_PRESERVE_ALL_ATTR static int16_t handle2t(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    const bool Exact = State.ConversionPrecision();
    auto rv = extF80_to_i32(&State.State, X80SoftFloat(src), softfloat_round_minMag, Exact);

    if (rv > INT16_MAX || rv < INT16_MIN) {
      if (Exact) {
        State.State.exceptionFlags &= ~softfloat_flag_inexact;
        State.State.exceptionFlags |= softfloat_flag_invalid;
      }
      ///< Indefinite value for 16-bit conversions.
      return INT16_MIN;
    } else {
      return rv;
    }
  }

  FEXCORE_PRESERVE_ALL_ATTR static int32_t handle4t(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    return extF80_to_i32(&State.State, X80SoftFloat(src), softfloat_round_minMag, State.ConversionPrecision());
  }

  FEXCORE_PRESERVE_ALL_ATTR static int64_t handle8t(uint16_t FCW, VectorRegType src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(src)};
    return extF80_to_i64(&State.State, X80SoftFloat(src), softfloat_round_minMag, State.ConversionPrecision());
  }
};

template<>
struct OpHandlers<IR::OP_F80CVTTOINT> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle2(uint16_t FCW, int16_t src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return X80SoftFloat(src);
  }

  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle4(uint16_t FCW, int32_t src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return X80SoftFloat(src);
  }
};

template<>
struct OpHandlers<IR::OP_F80ROUND> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true, SupportedX87IEEEOperand(Src1)};
    MRDEGuard MRDE {Frame, State.State, Src1}; // TRANS32 0033 v2
    if (State.ConversionPrecision()) {
      return X80SoftFloat(extF80_roundToInt(&State.State, X80SoftFloat(Src1), State.State.roundingMode, true));
    }
    return X80SoftFloat::FRNDINT(&State.State, Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80F2XM1> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1}; // TRANS32 0033 v2
    return X80SoftFloat::F2XM1(&State.State, Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80TAN> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1}; // TRANS32 0033 v2
    return X80SoftFloat::FTAN(&State.State, Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80SQRT> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(Src1)};
    MRDEGuard MRDE {Frame, State.State, Src1}; // TRANS32 0033 v2
    return X80SoftFloat::FSQRT(&State.State, Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80SIN> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1}; // TRANS32 0033 v2
    return X80SoftFloat::FSIN(&State.State, Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80COS> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1}; // TRANS32 0033 v2
    return X80SoftFloat::FCOS(&State.State, Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80SINCOS> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegPairType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1}; // TRANS32 0033 v2
    return FEXCore::MakeVectorRegPair(X80SoftFloat::FSIN(&State.State, Src1), X80SoftFloat::FCOS(&State.State, Src1));
  }
};

template<>
struct OpHandlers<IR::OP_F80XTRACT_EXP> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    MRNoteDenormal(Frame, Src1); // TRANS32 0033
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return X80SoftFloat::FXTRACT_EXP(Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80XTRACT_SIG> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, FEXCore::Core::CpuStateFrame* Frame) {
    MRNoteDenormal(Frame, Src1); // TRANS32 0033
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return X80SoftFloat::FXTRACT_SIG(Src1);
  }
};

template<>
struct OpHandlers<IR::OP_F80ADD> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(Src1) && SupportedX87IEEEOperand(Src2)};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FADD(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80SUB> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(Src1) && SupportedX87IEEEOperand(Src2)};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FSUB(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80MUL> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(Src1) && SupportedX87IEEEOperand(Src2)};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FMUL(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80DIV> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, false, SupportedX87IEEEOperand(Src1) && SupportedX87IEEEOperand(Src2)};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FDIV(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80FYL2X> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FYL2X(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80FYL2XP1> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    const X80SoftFloat One {&State.State, 1.0};
    return X80SoftFloat::FYL2X(&State.State, X80SoftFloat::FADD(&State.State, Src1, One), Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80ATAN> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FATAN(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80FPREM1> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    VectorRegType Result;
    if (FEXCore::HBX87::TryOrdinaryRemainder(FCW, Src1, Src2, true, Frame, Result)) {
      return Result;
    }
    if (FEXCore::HBX87::StateFix::PartialRemainder()) {
      // The dispatcher defers C2 to this helper only with the new gate. On
      // guard rejection retain its legacy unconditional zero publication.
      Frame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = 0;
    }
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FREM1(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80FPREM> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    VectorRegType Result;
    if (FEXCore::HBX87::TryOrdinaryRemainder(FCW, Src1, Src2, false, Frame, Result)) {
      return Result;
    }
    if (FEXCore::HBX87::StateFix::PartialRemainder()) {
      Frame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = 0;
    }
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FREM(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F80SCALE> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1, VectorRegType Src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    VectorRegType Result;
    if (FEXCore::HBX87::TryScale(FCW, Src1, Src2, Frame, Result)) {
      return Result;
    }
    ScopedSoftFloatState State {FCW, Frame, true};
    MRDEGuard MRDE {Frame, State.State, Src1, Src2}; // TRANS32 0033 v2
    return X80SoftFloat::FSCALE(&State.State, Src1, Src2);
  }
};

template<>
struct OpHandlers<IR::OP_F64SIN> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return sin(src);
  }
};

template<>
struct OpHandlers<IR::OP_F64COS> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return cos(src);
  }
};

template<>
struct OpHandlers<IR::OP_F64SINCOS> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorScalarF64Pair handle(double src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    double sin, cos;
#ifdef _WIN32
    sin = ::sin(src);
    cos = ::cos(src);
#else
    sincos(src, &sin, &cos);
#endif
    return VectorScalarF64Pair {sin, cos};
  }
};

template<>
struct OpHandlers<IR::OP_F64TAN> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return tan(src);
  }
};

template<>
struct OpHandlers<IR::OP_F64F2XM1> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return exp2(src) - 1.0;
  }
};

template<>
struct OpHandlers<IR::OP_F64ATAN> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src1, double src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return atan2(src1, src2);
  }
};

template<>
struct OpHandlers<IR::OP_F64FPREM> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src1, double src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return fmod(src1, src2);
  }
};

template<>
struct OpHandlers<IR::OP_F64FPREM1> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src1, double src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return remainder(src1, src2);
  }
};

template<>
struct OpHandlers<IR::OP_F64FYL2X> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src1, double src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return src2 * log2(src1);
  }
};

template<>
struct OpHandlers<IR::OP_F64FYL2XP1> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src1, double src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    return src2 * log2(1.0 + src1);
  }
};

template<>
struct OpHandlers<IR::OP_F64SCALE> {
  FEXCORE_PRESERVE_ALL_ATTR static double handle(double src1, double src2, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    if (src1 == 0.0) { // src1 might be +/- zero
      return src1;     // this will return negative or positive zero if when appropriate
    }
    double trun = trunc(src2);
    return src1 * exp2(trun);
  }
};

template<>
struct OpHandlers<IR::OP_F80BCDSTORE> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src1q, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    X80SoftFloat Src1 = Src1q;
    ScopedSoftFloatState State {FCW, Frame};
    bool Negative = Src1.Top.Sign;

    Src1 = X80SoftFloat::FRNDINT(&State.State, Src1);

    // Clear the Sign bit
    Src1.Top.Sign = 0;

    uint64_t Tmp = Src1.ToI64(&State.State);
    X80SoftFloat Rv;
    uint8_t* BCD = reinterpret_cast<uint8_t*>(&Rv);

    for (size_t i = 0; i < 9; ++i) {
      if (Tmp == 0) {
        // Nothing left? Just leave
        break;
      }
      // Extract the lower 100 values
      uint8_t Digit = Tmp % 100;

      // Now divide it for the next iteration
      Tmp /= 100;

      uint8_t UpperNibble = Digit / 10;
      uint8_t LowerNibble = Digit % 10;

      // Now store the BCD
      BCD[i] = (UpperNibble << 4) | LowerNibble;
    }

    // Set negative flag once converted to x87
    BCD[9] = Negative ? 0x80 : 0;

    return Rv;
  }
};

template<>
struct OpHandlers<IR::OP_F80BCDLOAD> {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType Src, FEXCore::Core::CpuStateFrame* Frame) {
    FEXCORE_PROFILE_INSTANT_INCREMENT(Frame->Thread, AccumulatedFloatFallbackCount, 1);
    uint8_t* Src1 = reinterpret_cast<uint8_t*>(&Src);
    uint64_t BCD {};
    // We walk through each uint8_t and pull out the BCD encoding
    // Each 4bit split is a digit
    // Only 0-9 is supported, A-F results in undefined data
    // | 4 bit     | 4 bit    |
    // | 10s place | 1s place |
    // EG 0x48 = 48
    // EG 0x4847 = 4847
    // This gives us an 18digit value encoded in BCD
    // The last byte lets us know if it negative or not
    for (size_t i = 0; i < 9; ++i) {
      uint8_t Digit = Src1[8 - i];
      // First shift our last value over
      BCD *= 100;

      // Add the tens place digit
      BCD += (Digit >> 4) * 10;

      // Add the ones place digit
      BCD += Digit & 0xF;
    }

    // Set negative flag once converted to x87
    bool Negative = Src1[9] & 0x80;
    X80SoftFloat Tmp;

    Tmp = BCD;
    Tmp.Top.Sign = Negative;
    return Tmp;
  }
};

} // namespace FEXCore::CPU
