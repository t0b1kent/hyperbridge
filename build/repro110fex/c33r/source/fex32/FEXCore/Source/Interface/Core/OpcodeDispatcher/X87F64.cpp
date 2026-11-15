// SPDX-License-Identifier: MIT
/*
$info$
tags: frontend|x86-to-ir, opcodes|dispatcher-implementations
desc: Handles x86/64 x87 to IR
$end_info$
*/

#include "Interface/Core/HBX87StateGates.h"
#include "Interface/Core/G3RP.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include "Interface/IR/IR.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>

#include <stddef.h>
#include <stdint.h>

namespace FEXCore::IR {
class OrderedNode;

#define OpcodeArgs [[maybe_unused]] FEXCore::X86Tables::DecodedOp Op

void OpDispatchBuilder::X87LDENVF64(OpcodeArgs) {
  _StackForceSlow();

  const auto Size = OpSizeFromSrc(Op);
  Ref Mem = MakeSegmentAddress(Op, Op->Src[0]);

  auto NewFCW = CanonicalizeX87ControlWord(_LoadMemGPR(OpSize::i16Bit, Mem, OpSize::i16Bit));
  // ignore the rounding precision, we're always 64-bit in F64.
  // extract rounding mode
  Ref roundingMode = _Bfe(OpSize::i32Bit, 3, 10, NewFCW);
  _SetRoundingMode(roundingMode, false, roundingMode);
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));

  auto NewFSW = _LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size)), Size, MemOffsetType::SXTX, 1);
  ReconstructX87StateFromFSW_Helper(NewFSW);

  {
    // FTW
    SetX87FTW(_LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size) * 2), Size, MemOffsetType::SXTX, 1));
  }
}

void OpDispatchBuilder::X87FLDCWF64(OpcodeArgs) {
  _StackForceSlow();

  Ref NewFCW = CanonicalizeX87ControlWord(LoadSourceGPR(Op, Op->Src[0], Op->Flags));
  // ignore the rounding precision, we're always 64-bit in F64.
  // extract rounding mode
  Ref roundingMode = _Bfe(OpSize::i32Bit, 3, 10, NewFCW);
  _SetRoundingMode(roundingMode, false, roundingMode);
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));
}

// F64 ops
// Float load op with memory operand
void OpDispatchBuilder::FLDF64(OpcodeArgs, IR::OpSize Width) {
  Ref Data = LoadSourceFPR_WithOpSize(Op, Op->Src[0], Width, Op->Flags);
  // Convert to 64bit float
  Ref ConvertedData = Data;
  if (Width == OpSize::i32Bit) {
    ConvertedData = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, Data);
  } else if (Width == OpSize::f80Bit) {
    ConvertedData = _F80CVT(OpSize::i64Bit, Data);
  }
  _PushStack(ConvertedData, Data, Width);
}

void OpDispatchBuilder::FBLDF64(OpcodeArgs) {
  // Read from memory
  Ref Data = LoadSourceFPR_WithOpSize(Op, Op->Src[0], OpSize::f80Bit, Op->Flags);
  Ref ConvertedData = _F80BCDLoad(Data);
  if (FEXCore::HBX87::RP::Int64()) { // G3FABLE: 18 BCD digits < 2^60 -- keep the integer exactly (upper lane)
    Ref Int = _F80CVTInt(OpSize::i64Bit, ConvertedData, false);
    ConvertedData = _VInsGPR(OpSize::i128Bit, OpSize::i64Bit, 1, _Float_FromGPR_S(OpSize::i64Bit, OpSize::i64Bit, Int), Int);
    _PushStack(ConvertedData, Invalid(), OpSize::iInvalid);
    return;
  }
  ConvertedData = _F80CVT(OpSize::i64Bit, ConvertedData);
  _PushStack(ConvertedData, Invalid(), OpSize::iInvalid);
}

void OpDispatchBuilder::FBSTPF64(OpcodeArgs) {
  if (FEXCore::HBX87::RP::Int64()) { // G3FABLE: integer route (exact lane if still valid, else the double rounded by RC)
    SaveNZCV();
    Ref Value = _ReadStackValue(0);
    Ref Lo = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, Value, 0);
    Ref Hi = _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, Value, 1);
    Ref Chk = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, _Float_FromGPR_S(OpSize::i64Bit, OpSize::i64Bit, Hi), 0);
    Ref Conv = _Float_ToGPR_S(OpSize::i64Bit, OpSize::i64Bit, Value);
    Ref Int = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, Chk, Lo, Hi, Conv);
    // int64 -> F80 exactly (as the exact-path FILD m64: the F80CVTToInt fallback ABI takes 16 / 32-bit operands only)
    auto Zero = Constant(0);
    _SubNZCV(OpSize::i64Bit, Int, Zero);
    auto Sign = _NZCVSelect(OpSize::i64Bit, CondClass::SLT, Constant(0x8000), Zero);
    auto Abs = _Neg(OpSize::i64Bit, Int, CondClass::MI);
    auto Shift = Sub(OpSize::i64Bit, Constant(63), _FindMSB(IR::OpSize::i64Bit, Abs));
    auto Mant = _Lshl(OpSize::i64Bit, Abs, Shift);
    auto Exp = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, Abs, Zero, Zero, Sub(OpSize::i64Bit, Constant(0x3fff + 63), Shift));
    Ref Bcd = _F80BCDStore(_VLoadTwoGPRs(Mant, _Or(OpSize::i64Bit, Sign, Exp)));
    StoreResultFPR_WithOpSize(Op, Op->Dest, Bcd, OpSize::f80Bit, OpSize::i8Bit);
    _PopStackDestroy();
    return;
  }
  Ref converted = _F80CVTTo(_ReadStackValue(0), OpSize::i64Bit);
  converted = _F80BCDStore(converted);
  StoreResultFPR_WithOpSize(Op, Op->Dest, converted, OpSize::f80Bit, OpSize::i8Bit);
  _PopStackDestroy();
}

void OpDispatchBuilder::FLDF64_Const(OpcodeArgs, uint64_t Num) {
  auto Data = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, Constant(Num));
  _PushStack(Data, Data, OpSize::i64Bit);
}

void OpDispatchBuilder::FILDF64(OpcodeArgs) {
  const auto ReadWidth = OpSizeFromSrc(Op);

  // Read from memory
  Ref Data = LoadSourceGPR_WithOpSize(Op, Op->Src[0], ReadWidth, Op->Flags);
  if (ReadWidth == OpSize::i16Bit) {
    Data = _Sbfe(OpSize::i64Bit, IR::OpSizeAsBits(ReadWidth), 0, Data);
  }
  Ref ConvertedData = _Float_FromGPR_S(OpSize::i64Bit, ReadWidth == OpSize::i32Bit ? OpSize::i32Bit : OpSize::i64Bit, Data);
  if (ReadWidth == OpSize::i64Bit && FEXCore::HBX87::RP::Int64()) { // G3FABLE: the exact integer rides in the upper lane
    ConvertedData = _VInsGPR(OpSize::i128Bit, OpSize::i64Bit, 1, ConvertedData, Data);
  }
  _PushStack(ConvertedData, Invalid(), OpSize::iInvalid);
}

void OpDispatchBuilder::FISTF64(OpcodeArgs, bool Truncate) {
  const auto Size = OpSizeFromSrc(Op);

  Ref data = _ReadStackValue(0);
  bool CanUseFloatReg = Size == OpSize::i64Bit;
  if (FEXCore::HBX87::RP::Frint() && CTX->HostFeatures.SupportsFRINTTS) { // G3FABLE RP6f (A10): exact integer indefinite
    const auto TSOType = CTX->IsVectorAtomicTSOEnabled() ? MemoryAccessType::DEFAULT : MemoryAccessType::NONTSO;
    // Integral double that fits the destination class; NaN / inf / out of range -> -2^31 / -2^63.
    Ref Rounded = _Vector_FToISized(OpSize::i64Bit, OpSize::i64Bit, data, !Truncate, CanUseFloatReg ? OpSize::i64Bit : OpSize::i32Bit);
    if (CanUseFloatReg && FEXCore::HBX87::RP::Int64()) {
      SaveNZCV();
      Ref Lo = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, data, 0);
      Ref Hi = _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, data, 1);
      Ref Chk = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, _Float_FromGPR_S(OpSize::i64Bit, OpSize::i64Bit, Hi), 0);
      Ref Conv = _Float_ToGPR_ZS(OpSize::i64Bit, OpSize::i64Bit, Rounded);
      Ref Int = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, Chk, Lo, Hi, Conv);
      StoreResultGPR_WithOpSize(Op, Op->Dest, Int, OpSize::i64Bit, OpSize::i8Bit, TSOType);
    } else if (CanUseFloatReg) {
      StoreResultFPR_WithOpSize(Op, Op->Dest, _Vector_FToZS(OpSize::i64Bit, OpSize::i64Bit, Rounded), OpSize::i64Bit, OpSize::i8Bit);
    } else {
      Ref Int = _Float_ToGPR_ZS(OpSize::i32Bit, OpSize::i64Bit, Rounded);
      if (Size == OpSize::i16Bit) {
        SaveNZCV();
        Int = _Select(OpSize::i32Bit, OpSize::i32Bit, CondClass::EQ, _Sbfe(OpSize::i32Bit, 16, 0, Int), Int, Int, Constant(0x8000));
      }
      StoreResultGPR_WithOpSize(Op, Op->Dest, Int, Size, OpSize::i8Bit, TSOType);
    }
  } else if (CanUseFloatReg && FEXCore::HBX87::RP::Int64()) { // G3FABLE: store the exact integer when the upper lane still is this value
    SaveNZCV();
    Ref Lo = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, data, 0);
    Ref Hi = _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, data, 1);
    Ref Chk = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, _Float_FromGPR_S(OpSize::i64Bit, OpSize::i64Bit, Hi), 0);
    Ref Conv = Truncate ? _Float_ToGPR_ZS(OpSize::i64Bit, OpSize::i64Bit, data) : _Float_ToGPR_S(OpSize::i64Bit, OpSize::i64Bit, data);
    Ref Int = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, Chk, Lo, Hi, Conv);
    StoreResultGPR_WithOpSize(Op, Op->Dest, Int, OpSize::i64Bit, OpSize::i8Bit,
                              CTX->IsVectorAtomicTSOEnabled() ? MemoryAccessType::DEFAULT : MemoryAccessType::NONTSO);
  } else if (CanUseFloatReg) {
    // If possible, it's faster to keep the data in an FPR than doing a GPR transfer.
    if (Truncate) {
      data = _Vector_FToZS(OpSize::i128Bit, OpSize::i64Bit, data);
    } else {
      data = _Vector_FToS(OpSize::i128Bit, OpSize::i64Bit, data);
    }
    StoreResultFPR_WithOpSize(Op, Op->Dest, data, OpSize::i64Bit, OpSize::i8Bit);
  } else {
    if (Truncate) {
      data = _Float_ToGPR_ZS(Size == OpSize::i32Bit ? OpSize::i32Bit : OpSize::i64Bit, OpSize::i64Bit, data);
    } else {
      data = _Float_ToGPR_S(Size == OpSize::i32Bit ? OpSize::i32Bit : OpSize::i64Bit, OpSize::i64Bit, data);
    }
    StoreResultGPR_WithOpSize(Op, Op->Dest, data, Size, OpSize::i8Bit,
                              CTX->IsVectorAtomicTSOEnabled() ? MemoryAccessType::DEFAULT : MemoryAccessType::NONTSO);
  }

  if ((Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) != 0) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FADDF64(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) { // Implicit argument case
    auto Offset = Op->OP & 7;
    auto St0 = 0;
    if (ResInST0 == OpResult::RES_STI) {
      _F80AddStack(Offset, St0);
    } else {
      _F80AddStack(St0, Offset);
    }
    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    return;
  }

  // We have one memory argument
  Ref arg {};

  if (Integer) {
    arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    if (Width == OpSize::i16Bit) {
      arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
    }
    arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
  } else if (Width == OpSize::i32Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
  } else if (Width == OpSize::i64Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  _F80AddValue(0, arg);
}

// FIXME: following is very similar to FADDF64
void OpDispatchBuilder::FMULF64(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) { // Implicit argument case
    auto offset = Op->OP & 7;
    auto st0 = 0;
    if (ResInST0 == OpResult::RES_STI) {
      _F80MulStack(offset, st0);
    } else {
      _F80MulStack(st0, offset);
    }
    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    return;
  }

  // We have one memory argument
  Ref arg {};

  if (Integer) {
    arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    if (Width == OpSize::i16Bit) {
      arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
    }
    arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
  } else if (Width == OpSize::i32Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
  } else if (Width == OpSize::i64Bit) {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  _F80MulValue(0, arg);

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FDIVF64(OpcodeArgs, IR::OpSize Width, bool Integer, bool Reverse, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) {
    const auto offset = Op->OP & 7;
    const auto st0 = 0;

    if (Reverse) {
      if (ResInST0 == OpResult::RES_STI) {
        _F80DivStack(offset, st0, offset);
      } else {
        _F80DivStack(st0, offset, st0);
      }
    } else {
      if (ResInST0 == OpResult::RES_STI) {
        _F80DivStack(offset, offset, st0);
      } else {
        _F80DivStack(st0, st0, offset);
      }
    }

    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    return;
  }

  // We have one memory argument
  Ref Arg {};

  if (Width == OpSize::i16Bit || Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
    if (Integer) {
      Arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
      if (Width == OpSize::i16Bit) {
        Arg = _Sbfe(OpSize::i64Bit, 16, 0, Arg);
      }
      Arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, Arg);
    } else if (Width == OpSize::i32Bit) {
      Arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
      Arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, Arg);
    } else if (Width == OpSize::i64Bit) {
      Arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    }
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  if (Reverse) {
    _F80DivRValue(Arg, 0);
  } else {
    _F80DivValue(0, Arg);
  }

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FSUBF64(OpcodeArgs, IR::OpSize Width, bool Integer, bool Reverse, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) {
    const auto Offset = Op->OP & 7;
    const auto St0 = 0;

    if (Reverse) {
      if (ResInST0 == OpResult::RES_STI) {
        _F80SubStack(Offset, St0, Offset);
      } else {
        _F80SubStack(St0, Offset, St0);
      }
    } else {
      if (ResInST0 == OpResult::RES_STI) {
        _F80SubStack(Offset, Offset, St0);
      } else {
        _F80SubStack(St0, St0, Offset);
      }
    }

    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    return;
  }

  // We have one memory argument
  Ref arg {};

  if (Width == OpSize::i16Bit || Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
    if (Integer) {
      arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
      if (Width == OpSize::i16Bit) {
        arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
      }
      arg = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
    } else if (Width == OpSize::i32Bit) {
      arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
      arg = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
    } else if (Width == OpSize::i64Bit) {
      arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    }
  } else {
    FEX_UNREACHABLE;
  }

  // top of stack is at offset zero
  if (Reverse) {
    _F80SubRValue(arg, 0);
  } else {
    _F80SubValue(0, arg);
  }

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

// MacRunner X87-F3: a binary64 signaling NaN (exponent all ones, quiet bit clear, fraction nonzero). With the sign
// shifted out, exactly the patterns strictly between 0xFFE0000000000000 (infinity) and 0xFFF0000000000000 (first
// quiet NaN) are signaling: one add of 2^64 - 0xFFE0000000000001 and one unsigned compare (both constants are a single
// MOVN), instead of separate exponent and fraction tests.
Ref OpDispatchBuilder::X87F64OperandIsSNaN(Ref Value) {
  Ref Bits = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, Value, 0);
  Ref Shifted = _Lshl(OpSize::i64Bit, Bits, Constant(1));
  Ref Offset = _Add(OpSize::i64Bit, Shifted, Constant(0x001FFFFFFFFFFFFFULL));
  return _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::ULT, Offset, Constant(0x000FFFFFFFFFFFFFULL), Constant(1), Constant(0));
}

void OpDispatchBuilder::FTSTF64(OpcodeArgs) {
  // We are going to clobber NZCV, make sure it's in a GPR first.
  SaveNZCV();

  // Now we do our comparison.
  _F80StackTest(0);
  // MacRunner X87-F3 (MACRUNNER_HB_X87_FIX_QUIET_COMPARE=1): FTST raises IE for any NaN; the host FCMP leaves it
  // in V. Without the key the F64 path publishes no IE at all (upstream behaviour).
  Ref Unordered {};
  if (FEXCore::HBX87::StateFix::QuietCompare()) {
    Unordered = _NZCVSelect01(CondForNZCVBit(FEXCore::X86State::RFLAG_OF_RAW_LOC, false));
  }
  ConvertNZCVToX87();
  if (Unordered) {
    SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(_Or(OpSize::i32Bit, GetRFLAG(FEXCore::X86State::X87FLAG_IE_LOC), Unordered));
  }
}

void OpDispatchBuilder::FCOMIF64(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::FCOMIFlags WhichFlags, bool PopTwice) {
  Ref arg {};
  Ref b {};

  if (Op->Src[0].IsNone()) {
    // Implicit arg
    uint8_t offset = Op->OP & 7;
    b = _ReadStackValue(offset);
  } else if (Width == OpSize::i16Bit || Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
    // Memory arg
    if (Integer) {
      arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
      if (Width == OpSize::i16Bit) {
        arg = _Sbfe(OpSize::i64Bit, 16, 0, arg);
      }
      b = _Float_FromGPR_S(OpSize::i64Bit, Width == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, arg);
    } else if (Width == OpSize::i32Bit) {
      arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
      b = _Float_FToF(OpSize::i64Bit, OpSize::i32Bit, arg);
    } else if (Width == OpSize::i64Bit) {
      b = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    }
  } else {
    FEX_UNREACHABLE;
  }

  // MacRunner X87-F3 (MACRUNNER_HB_X87_FIX_QUIET_COMPARE=1): publish IE, sticky. Ordered forms: any NaN (V after the
  // host FCMP); FUCOM*/FUCOMI* register forms: only a signaling NaN operand.
  const bool FixIE = FEXCore::HBX87::StateFix::QuietCompare();
  const bool Quiet = FixIE && Op->Src[0].IsNone() && X87QuietCompare(Op->OP);
  Ref NewIE {};
  if (Quiet) {
    NewIE = _Or(OpSize::i64Bit, X87F64OperandIsSNaN(_ReadStackValue(0)), X87F64OperandIsSNaN(b));
  }

  if (WhichFlags == FCOMIFlags::FLAGS_X87) {
    // We are going to clobber NZCV, make sure it's in a GPR first.
    SaveNZCV();

    _F80CmpValue(b);
    if (FixIE && !Quiet) {
      NewIE = _NZCVSelect01(CondForNZCVBit(FEXCore::X86State::RFLAG_OF_RAW_LOC, false));
    }
    ConvertNZCVToX87();
  } else {
    HandleNZCVWrite();
    _F80CmpValue(b);
    if (FixIE && !Quiet) {
      NewIE = _NZCVSelect01(CondForNZCVBit(FEXCore::X86State::RFLAG_OF_RAW_LOC, false));
    }
    ComissFlags(true /* InvalidateAF */);
  }
  if (NewIE) {
    SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(_Or(OpSize::i32Bit, GetRFLAG(FEXCore::X86State::X87FLAG_IE_LOC), NewIE));
  }

  if (PopTwice) {
    _PopStackDestroy();
    _PopStackDestroy();
  } else if ((Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) != 0) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::X87FXTRACTF64(OpcodeArgs) {
  // Split node into SIG and EXP while handling the special zero case.
  // i.e. if val == 0.0, then sig = 0.0, exp = -inf
  // if val == -0.0, then sig = -0.0, exp = -inf
  // if val is +/-Inf, then sig = val, exp = +inf
  // if val is NaN, then sig = val, exp = val
  // otherwise we just extract the 64-bit sig and exp as normal.
  Ref Node = _ReadStackValue(0);

  Ref Gpr = _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, Node, 0);

  // zero case
  Ref ExpZV = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, Constant(0xfff0'0000'0000'0000UL));
  Ref SigZV = Node;

  // Inf/NaN case
  Ref ExpInfOnlyV = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, Constant(0x7ff0'0000'0000'0000UL));
  Ref ExpNanV = Node;
  Ref SigInfV = Node;

  // non zero case
  Ref ExpNZ = _Bfe(OpSize::i64Bit, 11, 52, Gpr);
  ExpNZ = Sub(OpSize::i64Bit, ExpNZ, Constant(1023));
  Ref ExpNZV = _Float_FromGPR_S(OpSize::i64Bit, OpSize::i64Bit, ExpNZ);

  Ref SigNZ = _And(OpSize::i64Bit, Gpr, Constant(0x800f'ffff'ffff'ffffLL));
  SigNZ = _Or(OpSize::i64Bit, SigNZ, Constant(0x3ff0'0000'0000'0000LL));
  Ref SigNZV = _VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, SigNZ);

  SaveNZCV();

  // Mantissa non-zero => NaN (exp result = input); else Inf (exp result = +Inf)
  Ref Mantissa = _And(OpSize::i64Bit, Gpr, Constant(0x000f'ffff'ffff'ffffULL));
  _TestNZ(OpSize::i64Bit, Mantissa, Constant(~0ULL));
  Ref ExpInfV = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, ExpInfOnlyV, ExpNanV);

  // Biased exponent == 0x7ff => Inf/NaN path, else non-zero-case.
  Ref BiasedExp = _Bfe(OpSize::i64Bit, 11, 52, Gpr);
  SubWithFlags(OpSize::i64Bit, BiasedExp, 0x7ff);
  Ref ExpNZOrInf = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, ExpInfV, ExpNZV);
  Ref SigNZOrInf = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, SigInfV, SigNZV);

  // Zero folds on top.
  _TestNZ(OpSize::i64Bit, Gpr, Constant(0x7fff'ffff'ffff'ffffUL));

  Ref Sig = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, SigZV, SigNZOrInf);
  Ref Exp = _NZCVSelectV(OpSize::i64Bit, CondClass::EQ, ExpZV, ExpNZOrInf);

  _PopStackDestroy();
  _PushStack(Exp, Invalid(), OpSize::iInvalid);
  _PushStack(Sig, Invalid(), OpSize::iInvalid);
}
} // namespace FEXCore::IR
