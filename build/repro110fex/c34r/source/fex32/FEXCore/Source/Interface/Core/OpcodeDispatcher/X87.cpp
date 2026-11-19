// SPDX-License-Identifier: MIT
/*
$info$
tags: frontend|x86-to-ir, opcodes|dispatcher-implementations
desc: Handles x86/64 x87 to IR
$end_info$
*/

#include "Interface/Core/OpcodeDispatcher.h"
#include <FEXCore/Core/G3LazyFIP.h>
#include "Interface/Core/HBX87StateGates.h"
#include "Interface/Core/HBX87IR.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include "Interface/IR/IR.h"
#include "Interface/Core/Addressing.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/MacRunnerWinctx.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/FPState.h>

#include <stddef.h>
#include <stdint.h>

namespace FEXCore::IR {
class OrderedNode;
#define OpcodeArgs [[maybe_unused]] FEXCore::X86Tables::DecodedOp Op

Ref OpDispatchBuilder::CanonicalizeX87ControlWord(Ref Value) {
  if (!FEXCore::HBX87::StateFix::WinctxExact()) {
    return Value;
  }
  // Normalize the loaded state, not a save instruction or a CONTEXT header.
  // The caller has already performed the original faulting memory read.
  return _Or(OpSize::i32Bit,
             _And(OpSize::i32Bit, Value, Constant(FEXCore::Winctx::ControlWordMask)),
             Constant(FEXCore::Winctx::ControlWordFixedBits));
}

Ref OpDispatchBuilder::GetX87Top() {
  // Yes, we are storing 3 bits in a single flag register.
  // Deal with it
  return _LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC);
}

void OpDispatchBuilder::SetX87FTW(Ref FTW) {
  _StackForceSlow(); // Invalidate x87 FTW register cache

  // For the output, we want a 1-bit for each pair not equal to 11 (Empty).
  static_assert(static_cast<uint8_t>(FPState::X87Tag::Empty) == 0b11);

  // Make even bits 1 if the pair is equal to 11, and 0 otherwise.
  FTW = _AndShift(OpSize::i32Bit, FTW, FTW, ShiftType::LSR, 1);

  // Invert FTW and clear the odd bits. Even bits are 1 if the pair
  // is not equal to 11, and odd bits are 0.
  FTW = _Andn(OpSize::i32Bit, Constant(0x55555555), FTW);

  // All that's left is to compact away the odd bits. That is a Morton
  // deinterleave operation, which has a standard solution. See
  // https://stackoverflow.com/questions/3137266/how-to-de-interleave-bits-unmortonizing
  FTW = _And(OpSize::i32Bit, _Orlshr(OpSize::i32Bit, FTW, FTW, 1), Constant(0x33333333));
  FTW = _And(OpSize::i32Bit, _Orlshr(OpSize::i32Bit, FTW, FTW, 2), Constant(0x0f0f0f0f));
  FTW = _Orlshr(OpSize::i32Bit, FTW, FTW, 4);

  // ...and that's it. StoreContext implicitly does the final masking.
  _StoreContextGPR(OpSize::i8Bit, FTW, offsetof(FEXCore::Core::CPUState, AbridgedFTW));
}

void OpDispatchBuilder::SetX87Top(Ref Value) {
  _StoreContextGPR(OpSize::i8Bit, Value, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC);
}

// Float LoaD operation with memory operand
void OpDispatchBuilder::FLD(OpcodeArgs, IR::OpSize Width) {
  Ref Data = LoadSourceFPR_WithOpSize(Op, Op->Src[0], Width, Op->Flags);
  Ref ConvertedData = Data;
  // Convert to 80bit float
  if (Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
    ConvertedData = _F80CVTTo(Data, Width);
  }
  X87ClearC1(); // X87EXACT C1C
  _PushStack(ConvertedData, Data, Width);
}

// Float LoaD operation with memory operand
void OpDispatchBuilder::FLDFromStack(OpcodeArgs) {
  X87ClearC1(); // X87EXACT C1C
  _CopyPushStack(Op->OP & 7);
}

void OpDispatchBuilder::FBLD(OpcodeArgs) {
  // Read from memory
  Ref Data = LoadSourceFPR_WithOpSize(Op, Op->Src[0], OpSize::f80Bit, Op->Flags);
  Ref ConvertedData = _F80BCDLoad(Data);
  X87ClearC1(); // X87EXACT C1C
  _PushStack(ConvertedData, Invalid(), OpSize::iInvalid);
}

void OpDispatchBuilder::FBSTP(OpcodeArgs) {
  Ref converted = _F80BCDStore(_ReadStackValue(0));
  StoreResultFPR_WithOpSize(Op, Op->Dest, converted, OpSize::f80Bit, OpSize::i8Bit);
  _PopStackDestroy();
}

void OpDispatchBuilder::FLD_Const(OpcodeArgs, NamedVectorConstant K) {
  // Update TOP
  Ref Data = LoadAndCacheNamedVectorConstant(OpSize::i128Bit, K);
  X87ClearC1(); // X87EXACT C1C
  _PushStack(Data, Data, OpSize::f80Bit);
}

void OpDispatchBuilder::FILD(OpcodeArgs) {
  const auto ReadWidth = OpSizeFromSrc(Op);
  // Read from memory
  Ref Data = LoadSourceGPR_WithOpSize(Op, Op->Src[0], ReadWidth, Op->Flags);

  // 0167: the existing exact integer converter has a compact inline Guest32
  // implementation. Keep the normal push/tag path and the old IR byte-for-byte
  // when STATIC is off. FILD m64 retains its existing exact integer IR: the
  // common F80CVTToInt interpreter ABI only accepts 16/32-bit operands.
  if (!ReducedPrecisionMode &&
      FEXCore::HBX87::ExactFormsEnabled(GetGPROpSize() == OpSize::i32Bit) && ReadWidth != OpSize::i64Bit) {
    X87ClearC1(); // X87EXACT C1C
    _PushStack(_F80CVTToInt(Data, ReadWidth), Invalid(), OpSize::iInvalid);
    return;
  }

  // Sign extend to 64bits
  if (ReadWidth != OpSize::i64Bit) {
    Data = _Sbfe(OpSize::i64Bit, IR::OpSizeAsBits(ReadWidth), 0, Data);
  }

  // We're about to clobber flags to grab the sign, so save NZCV.
  SaveNZCV();

  // Extract sign and make integer absolute
  auto zero = Constant(0);
  _SubNZCV(OpSize::i64Bit, Data, zero);
  auto sign = _NZCVSelect(OpSize::i64Bit, CondClass::SLT, Constant(0x8000), zero);
  auto absolute = _Neg(OpSize::i64Bit, Data, CondClass::MI);

  // left justify the absolute integer
  auto shift = Sub(OpSize::i64Bit, Constant(63), _FindMSB(IR::OpSize::i64Bit, absolute));
  auto shifted = _Lshl(OpSize::i64Bit, absolute, shift);

  auto adjusted_exponent = Sub(OpSize::i64Bit, Constant(0x3fff + 63), shift);
  auto zeroed_exponent = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, absolute, zero, zero, adjusted_exponent);
  auto upper = _Or(OpSize::i64Bit, sign, zeroed_exponent);

  Ref ConvertedData = _VLoadTwoGPRs(shifted, upper);
  X87ClearC1(); // X87EXACT C1C
  _PushStack(ConvertedData, Invalid(), OpSize::iInvalid);
}

void OpDispatchBuilder::FST(OpcodeArgs, IR::OpSize Width) {
  LOGMAN_THROW_A_FMT(Width == OpSize::i32Bit || Width == OpSize::i64Bit || Width == OpSize::f80Bit, "Invalid store width for FST");
  const auto SourceSize = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::f80Bit;
  AddressMode A = DecodeAddress(Op, Op->Dest, MemoryAccessType::DEFAULT, false);

  A = SelectAddressMode(this, A, GetGPROpSize(), CTX->HostFeatures.SupportsTSOImm9, false, false, Width);
  _StoreStackMem(SourceSize, Width, A.Base, A.Index, OpSize::iInvalid, A.IndexType, A.IndexScale);
  if (Width == OpSize::f80Bit) { // m32 / m64 store rounding already writes C1
    X87ClearC1(); // X87EXACT C1C
  }

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FSTToStack(OpcodeArgs) {
  const uint8_t Offset = Op->OP & 7;
  if (Offset != 0) {
    _StoreStackToStack(Offset);
  }
  X87ClearC1(); // X87EXACT C1C

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

// Store integer to memory (possibly with truncation)
void OpDispatchBuilder::FIST(OpcodeArgs, bool Truncate) {
  const auto Size = OpSizeFromSrc(Op);
  Ref Data = _ReadStackValue(0);

  // For 16-bit integers, we need to manually check for overflow
  // since _F80CVTInt doesn't handle 16-bit overflow detection properly
  if (Size == OpSize::i16Bit) {
    // Extract the 80-bit float value to check for special cases
    // Get the upper 64 bits which contain sign and exponent and then the exponent from upper.
    Ref Upper = _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, Data, 1);
    Ref Exponent = _And(OpSize::i64Bit, Upper, Constant(0x7fff));

    // Check for NaN/Infinity: exponent = 0x7fff
    SaveNZCV();
    SubWithFlags(OpSize::i64Bit, Exponent, 0x7fff);
    Ref IsSpecial = _NZCVSelect01(CondClass::EQ);

    // For overflow detection, check if exponent indicates a value >= 2^15
    // Biased exponent for 2^15 is 0x3fff + 15 = 0x400e
    SubWithFlags(OpSize::i64Bit, Exponent, 0x400e);
    Ref IsOverflow = _NZCVSelect01(CondClass::UGE);

    // Set Invalid Operation flag if overflow or special value
    // The x87 exception flags are sticky. Preserve earlier result
    Ref InvalidFlag = _Or(OpSize::i64Bit, IsSpecial, IsOverflow);
    SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(_Or(OpSize::i32Bit, GetRFLAG(FEXCore::X86State::X87FLAG_IE_LOC), InvalidFlag));
  }

  Data = _F80CVTInt(Size, Data, Truncate);

  StoreResultGPR_WithOpSize(Op, Op->Dest, Data, Size, OpSize::i8Bit,
                            CTX->IsVectorAtomicTSOEnabled() ? MemoryAccessType::DEFAULT : MemoryAccessType::NONTSO);

  if ((Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) != 0) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FADD(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::OpResult ResInST0) {
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

  LOGMAN_THROW_A_FMT(Width != OpSize::f80Bit, "No 80-bit floats from memory");
  // We have one memory argument
  Ref Arg {};
  if (Integer) {
    Arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    Arg = _F80CVTToInt(Arg, Width);
  } else {
    Arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    Arg = _F80CVTTo(Arg, Width);
  }

  // top of stack is at offset zero
  _F80AddValue(0, Arg);
}

void OpDispatchBuilder::FMUL(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::OpResult ResInST0) {
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

  LOGMAN_THROW_A_FMT(Width != OpSize::f80Bit, "No 80-bit floats from memory");
  // We have one memory argument
  Ref arg {};
  if (Integer) {
    arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    arg = _F80CVTToInt(arg, Width);
  } else {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    arg = _F80CVTTo(arg, Width);
  }

  // top of stack is at offset zero
  _F80MulValue(0, arg);

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FDIV(OpcodeArgs, IR::OpSize Width, bool Integer, bool Reverse, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) {
    const uint8_t Offset = Op->OP & 7;
    const uint8_t St0 = 0;
    const uint8_t Result = (ResInST0 == OpResult::RES_STI) ? Offset : St0;

    if (Reverse ^ (ResInST0 == OpResult::RES_STI)) {
      _F80DivStack(Result, Offset, St0);
    } else {
      _F80DivStack(Result, St0, Offset);
    }

    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    return;
  }

  LOGMAN_THROW_A_FMT(Width != OpSize::f80Bit, "No 80-bit floats from memory");
  // We have one memory argument
  Ref arg {};
  if (Integer) {
    arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    arg = _F80CVTToInt(arg, Width);
  } else {
    arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    arg = _F80CVTTo(arg, Width);
  }

  // top of stack is at offset zero
  if (Reverse) {
    _F80DivRValue(arg, 0);
  } else {
    _F80DivValue(0, arg);
  }

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FSUB(OpcodeArgs, IR::OpSize Width, bool Integer, bool Reverse, OpDispatchBuilder::OpResult ResInST0) {
  if (Op->Src[0].IsNone()) {
    const auto Offset = Op->OP & 7;
    const auto St0 = 0;
    const auto Result = (ResInST0 == OpResult::RES_STI) ? Offset : St0;

    if (Reverse ^ (ResInST0 == OpResult::RES_STI)) {
      _F80SubStack(Result, Offset, St0);
    } else {
      _F80SubStack(Result, St0, Offset);
    }

    if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
      _PopStackDestroy();
    }
    return;
  }

  LOGMAN_THROW_A_FMT(Width != OpSize::f80Bit, "No 80-bit floats from memory");
  // We have one memory argument
  Ref Arg {};
  if (Integer) {
    Arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    Arg = _F80CVTToInt(Arg, Width);
  } else {
    Arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
    Arg = _F80CVTTo(Arg, Width);
  }

  // top of stack is at offset zero
  if (Reverse) {
    _F80SubRValue(Arg, 0);
  } else {
    _F80SubValue(0, Arg);
  }

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::LazyFIPEmit(uint32_t PC) {
  if (FEXCore::HBX87::LazyFIP::FcsConst()) { // RP6q: {IP, CS = 0, Reserved = 0} in one store; readers resolve CS
    _StoreContextGPR(OpSize::i64Bit, Constant(PC), offsetof(FEXCore::Core::CPUState, _pad1));
    return;
  }
  _StoreContextGPR(OpSize::i32Bit, Constant(PC), offsetof(FEXCore::Core::CPUState, X87LastInstruction32.IP));
  Ref CS = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, cs_idx));
  _StoreContextGPR(OpSize::i16Bit, CS, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.CS));
}

void OpDispatchBuilder::LazyFIPBlockBegin(uint64_t Start, uint64_t End) {
  MRLazyFipHas = false; MRLazyFipFirstDone = false; MRLazyFipSeg.clear(); MRLazyFipEnd = static_cast<uint32_t>(End);
  if (GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32() && FEXCore::HBX87::LazyFIP::Enabled()) {
    FEXCore::HBX87::LazyFIP::BlockBegin(static_cast<uint32_t>(Start), static_cast<uint32_t>(End));
  }
}

void OpDispatchBuilder::LazyFIPFlush() {
  if (!MRLazyFipHas) return;
  MRLazyFipHas = false;
  LazyFIPEmit(MRLazyFipPending);
}

void OpDispatchBuilder::TrackX87Instruction32(OpcodeArgs) {
  if (!FEXCore::HBX87::StateFix::InstructionPointers32()) {
    return;
  }
  // Secondary/SSE tables reuse raw D8..DF bytes. They must not change FIP.
  // Decoder table identity also covers the reduced-precision x87 table.
  const auto Table = reinterpret_cast<uintptr_t>(Op->TableInfo);
  const auto Full = reinterpret_cast<uintptr_t>(FEXCore::X86Tables::X87F80Ops.data());
  const auto Reduced = reinterpret_cast<uintptr_t>(FEXCore::X86Tables::X87F64Ops.data());
  if (!((Table >= Full && Table < Full + sizeof(FEXCore::X86Tables::X87F80Ops)) ||
        (Table >= Reduced && Table < Reduced + sizeof(FEXCore::X86Tables::X87F64Ops)))) {
    return;
  }
  const bool Lazy = FEXCore::HBX87::LazyFIP::Enabled();
  // Imported from GUEST32-BASE 386457d86cf32d34: control instructions
  // preserve the last computational x87 instruction in protected mode.
  const uint8_t Escape = Op->OPRaw;
  const uint8_t ModRM = Op->ModRM;
  const uint8_t Group = (ModRM >> 3) & 7;
  if ((Escape == 0xD9 && ModRM < 0xC0 && Group >= 4) ||
      (Escape == 0xDD && ModRM < 0xC0 && Group >= 4) ||
      (Escape == 0xDB && ModRM >= 0xE0 && ModRM <= 0xE4) ||
      (Escape == 0xDF && ModRM == 0xE0)) {
    if (Lazy) { // readers / other writers of the pointer: the pending value first; the segment ends here
      LazyFIPFlush();
      if (!MRLazyFipSeg.empty()) FEXCore::HBX87::LazyFIP::SetSegment(MRLazyFipSeg.data(), MRLazyFipSeg.size(), static_cast<uint32_t>(Op->PC));
      MRLazyFipSeg.clear(); MRLazyFipFirstDone = false;
    }
    return;
  }
  if (Lazy) {
    const uint32_t PC = static_cast<uint32_t>(Op->PC);
    MRLazyFipSeg.push_back(PC);
    FEXCore::HBX87::LazyFIP::SetSegment(&PC, 1, MRLazyFipEnd);
    // RP6q: FIRST_LAZY -- pending like the rest, reduced-precision instructions only (the exact path's entry-check deopt still
    // resumes by RIP entries, so its first instruction keeps the eager write)
    if (!MRLazyFipFirstDone && !(FEXCore::HBX87::LazyFIP::FirstLazy() && Table >= Reduced && Table < Reduced + sizeof(FEXCore::X86Tables::X87F64Ops))) {
      MRLazyFipFirstDone = true; MRLazyFipHas = false;
      LazyFIPEmit(PC);
    } else {
      MRLazyFipPending = PC; MRLazyFipHas = true;
    }
    return;
  }
  LazyFIPEmit(static_cast<uint32_t>(Op->PC));
}

Ref OpDispatchBuilder::GetX87FTW_Helper() {
  if (FEXCore::HBX87::StateFix::EnvTags()) {
    // MM slots and abridged FTW bits are PHYSICAL indices. Empty wins
    // regardless of stale payload; occupied slots require full classification.
    const auto D = OpSize::i64Bit;
    const auto Zero = Constant(0);
    const auto One = Constant(1);
    const auto Two = Constant(2);
    const auto Three = Constant(3);
    Ref Occupied = _LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, AbridgedFTW));
    Ref Tags = Zero;
    for (unsigned i = 0; i < 8; ++i) {
      const size_t Offset = offsetof(FEXCore::Core::CPUState, mm) + i * 16;
      Ref Mantissa = _LoadContextGPR(D, Offset);
      Ref Exponent;
      Ref IsZero;
      Ref IsSpecial;
      if (ReducedPrecisionMode) {
        Ref Magnitude = _And(D, Mantissa, Constant(0x7fffffffffffffffULL));
        Exponent = _Bfe(D, 11, 52, Magnitude);
        IsZero = _Select(D, D, CondClass::EQ, Magnitude, Zero, One, Zero);
        Ref Denormal = _Select(D, D, CondClass::EQ, Exponent, Zero, One, Zero);
        Ref NaNInf = _Select(D, D, CondClass::EQ, Exponent, Constant(0x7ff), One, Zero);
        IsSpecial = _Or(D, Denormal, NaNInf);
      } else {
        Exponent = _And(D, _LoadContextGPR(OpSize::i16Bit, Offset + 8), Constant(0x7fff));
        Ref Magnitude = _Or(D, Exponent, Mantissa);
        IsZero = _Select(D, D, CondClass::EQ, Magnitude, Zero, One, Zero);
        Ref Denormal = _Select(D, D, CondClass::EQ, Exponent, Zero, One, Zero);
        Ref NaNInf = _Select(D, D, CondClass::EQ, Exponent, Constant(0x7fff), One, Zero);
        Ref IntegerBit = _Bfe(D, 1, 63, Mantissa);
        Ref Unnormal = _Xor(D, IntegerBit, One);
        IsSpecial = _Or(D, _Or(D, Denormal, NaNInf), Unnormal);
      }
      Ref ValueTag = _Select(D, D, CondClass::EQ, IsSpecial, Zero, Zero, Two);
      ValueTag = _Select(D, D, CondClass::EQ, IsZero, Zero, ValueTag, One);
      Ref Valid = _Bfe(D, 1, i, Occupied);
      Ref Tag = _Select(D, D, CondClass::EQ, Valid, Zero, Three, ValueTag);
      Tags = _Or(D, Tags, _Lshl(D, Tag, Constant(i * 2)));
    }
    return Tags;
  }
  // AbridgedFTWIndex has 1-bit per slot (8 slots). Duplicate each bit to get
  // 2-bits per slot (16-bit result). Duplicating bits is equivalent to
  // Morton interleaving a number with itself. To interleave efficiently two
  // bytes, we use the well-known bit twiddling algorithm:
  //
  // https://graphics.stanford.edu/~seander/bithacks.html#InterleaveBMN
  Ref X = _LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, AbridgedFTW));
  X = _Orlshl(OpSize::i32Bit, X, X, 4);
  X = _And(OpSize::i32Bit, X, Constant(0x0f0f0f0f));
  X = _Orlshl(OpSize::i32Bit, X, X, 2);
  X = _And(OpSize::i32Bit, X, Constant(0x33333333));
  X = _Orlshl(OpSize::i32Bit, X, X, 1);
  X = _And(OpSize::i32Bit, X, Constant(0x55555555));
  X = _Orlshl(OpSize::i32Bit, X, X, 1);

  // The above sequence sets valid to 11 and empty to 00, so invert to finalize.
  static_assert(static_cast<uint8_t>(FPState::X87Tag::Valid) == 0b00);
  static_assert(static_cast<uint8_t>(FPState::X87Tag::Empty) == 0b11);
  return _Xor(OpSize::i32Bit, X, Constant(0xffff));
}

void OpDispatchBuilder::X87FNSTENV(OpcodeArgs) {


  // 14 bytes for 16bit
  // 2 Bytes : FCW
  // 2 Bytes : FSW
  // 2 bytes : FTW
  // 2 bytes : Instruction offset
  // 2 bytes : Instruction CS selector
  // 2 bytes : Data offset
  // 2 bytes : Data selector

  // 28 bytes for 32bit
  // 4 bytes : FCW
  // 4 bytes : FSW
  // 4 bytes : FTW
  // 4 bytes : Instruction pointer
  // 2 bytes : Instruction pointer selector
  // 2 bytes : Opcode
  // 4 bytes : data pointer offset
  // 4 bytes : data pointer selector

  // Before we store anything we need to sync our stack to the registers.
  _SyncStackToSlow();

  const auto Size = OpSizeFromSrc(Op);
  Ref Mem = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.LoadData = false});
  Mem = AppendSegmentOffset(Mem, Op->Flags);

  {
    auto FCW = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, FCW));
    _StoreMemGPR(Size, Mem, FCW, Size);
  }

  { _StoreMemGPR(Size, ReconstructFSW_Helper(), Mem, Constant(IR::OpSizeToSize(Size) * 1), Size, MemOffsetType::SXTX, 1); }

  auto ZeroConst = Constant(0);

  {
    // FTW
    _StoreMemGPR(Size, GetX87FTW_Helper(), Mem, Constant(IR::OpSizeToSize(Size) * 2), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Instruction Offset
    Ref IP = GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32() ?
      _LoadContextGPR(OpSize::i32Bit, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.IP)) : ZeroConst;
    _StoreMemGPR(Size, IP, Mem, Constant(IR::OpSizeToSize(Size) * 3), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Instruction CS selector (+ Opcode)
    Ref CS = GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32() ?
      _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.CS)) : ZeroConst;
    if (GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32() && FEXCore::HBX87::LazyFIP::FcsConst()) {
      // RP6q: CS = cs_idx when Reserved == 0 and IP != 0, else the stored CS -- without flags (sub / lsr / and / xor only).
      Ref Raw = _LoadContextGPR(OpSize::i64Bit, offsetof(FEXCore::Core::CPUState, _pad1));
      Ref IPz = _Bfe(OpSize::i64Bit, 32, 0, Raw);
      Ref Res = _Lshr(OpSize::i64Bit, Raw, Constant(48));
      Ref Nz = _Lshr(OpSize::i64Bit, _Sub(OpSize::i64Bit, Constant(0), IPz), Constant(63));
      Ref Rnz = _Lshr(OpSize::i64Bit, _Sub(OpSize::i64Bit, Constant(0), Res), Constant(63));
      Ref Use = _And(OpSize::i64Bit, Nz, _Xor(OpSize::i64Bit, Rnz, Constant(1)));
      Ref Mask = _Sub(OpSize::i64Bit, Constant(0), Use);
      Ref Cur = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, cs_idx));
      CS = _Xor(OpSize::i64Bit, CS, _And(OpSize::i64Bit, _Xor(OpSize::i64Bit, CS, Cur), Mask));
    }
    _StoreMemGPR(Size, CS, Mem, Constant(IR::OpSizeToSize(Size) * 4), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Data pointer offset
    _StoreMemGPR(Size, ZeroConst, Mem, Constant(IR::OpSizeToSize(Size) * 5), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Data pointer selector
    _StoreMemGPR(Size, ZeroConst, Mem, Constant(IR::OpSizeToSize(Size) * 6), Size, MemOffsetType::SXTX, 1);
  }
}

Ref OpDispatchBuilder::ReconstructX87StateFromFSW_Helper(Ref FSW) {
  auto Top = _Bfe(OpSize::i32Bit, 3, 11, FSW);
  SetX87Top(Top);

  auto C0 = _Bfe(OpSize::i32Bit, 1, 8, FSW);
  auto C1 = _Bfe(OpSize::i32Bit, 1, 9, FSW);
  auto C2 = _Bfe(OpSize::i32Bit, 1, 10, FSW);
  auto C3 = _Bfe(OpSize::i32Bit, 1, 14, FSW);

  SetRFLAG<FEXCore::X86State::X87FLAG_C0_LOC>(C0);
  SetRFLAG<FEXCore::X86State::X87FLAG_C1_LOC>(C1);
  SetRFLAG<FEXCore::X86State::X87FLAG_C2_LOC>(C2);
  SetRFLAG<FEXCore::X86State::X87FLAG_C3_LOC>(C3);
  if ((FEXCore::HBX87::StateFix::ExceptionState(GetGPROpSize() == OpSize::i64Bit) || FEXCore::HBX87::StateFix::WinctxExact())) {
    // MacRunner X87-F4.2: FSW bits 0..6 spread to bit 0 of bytes 32..38 with one multiply (bit i moves by 7i; no two products
    // meet, so no carries), ES (bit 7) goes to byte 39 and the eight bytes are written with one store.
    Ref Spread = _And(OpSize::i64Bit, _Mul(OpSize::i64Bit, _And(OpSize::i64Bit, FSW, Constant(0x7F)), Constant(0x0000040810204081ULL)),
                      Constant(0x0101010101010101ULL));
    Spread = _Orlshl(OpSize::i64Bit, Spread, _Bfe(OpSize::i64Bit, 1, 7, FSW), 56);
    _StoreContextGPR(OpSize::i64Bit, Spread, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_IE_LOC);
    SetRFLAG<FEXCore::X86State::X87FLAG_B_LOC>(_Bfe(OpSize::i32Bit, 1, 15, FSW));
  } else {
    SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(_Bfe(OpSize::i32Bit, 1, 0, FSW));
    SetRFLAG<FEXCore::X86State::X87FLAG_SF_LOC>(_Bfe(OpSize::i32Bit, 1, 6, FSW));
  }
  return Top;
}

void OpDispatchBuilder::X87LDENV(OpcodeArgs) {
  _StackForceSlow();

  const auto Size = OpSizeFromSrc(Op);
  Ref Mem = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.LoadData = false});
  Mem = AppendSegmentOffset(Mem, Op->Flags);

  auto NewFCW = CanonicalizeX87ControlWord(_LoadMemGPR(OpSize::i16Bit, Mem, OpSize::i16Bit));
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));

  Ref MemLocation = Add(OpSize::i64Bit, Mem, IR::OpSizeToSize(Size) * 1);
  auto NewFSW = _LoadMemGPR(Size, MemLocation, Size);
  ReconstructX87StateFromFSW_Helper(NewFSW);

  {
    // FTW
    Ref MemLocation = Add(OpSize::i64Bit, Mem, IR::OpSizeToSize(Size) * 2);
    SetX87FTW(_LoadMemGPR(Size, MemLocation, Size));
  }
  if (GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32()) {
    Ref IP = _LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size) * 3), Size, MemOffsetType::SXTX, 1);
    Ref CS = _LoadMemGPR(OpSize::i16Bit, Mem, Constant(IR::OpSizeToSize(Size) * 4), OpSize::i16Bit, MemOffsetType::SXTX, 1);
    _StoreContextGPR(OpSize::i32Bit, IP, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.IP));
    _StoreContextGPR(OpSize::i16Bit, CS, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.CS));
    if (FEXCore::HBX87::LazyFIP::FcsConst()) { // RP6q: the loaded CS is literal until the next x87 instruction
      _StoreContextGPR(OpSize::i16Bit, Constant(1), offsetof(FEXCore::Core::CPUState, X87LastInstruction32.Reserved));
    }
  }
}

void OpDispatchBuilder::X87FNSAVE(OpcodeArgs) {
  _SyncStackToSlow();

  // 14 bytes for 16bit
  // 2 Bytes : FCW
  // 2 Bytes : FSW
  // 2 bytes : FTW
  // 2 bytes : Instruction offset
  // 2 bytes : Instruction CS selector
  // 2 bytes : Data offset
  // 2 bytes : Data selector

  // 28 bytes for 32bit
  // 4 bytes : FCW
  // 4 bytes : FSW
  // 4 bytes : FTW
  // 4 bytes : Instruction pointer
  // 2 bytes : instruction pointer selector
  // 2 bytes : Opcode
  // 4 bytes : data pointer offset
  // 4 bytes : data pointer selector
  const auto Size = OpSizeFromDst(Op);
  Ref Mem = MakeSegmentAddress(Op, Op->Dest);
  Ref Top = GetX87Top();
  {
    auto FCW = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, FCW));
    _StoreMemGPR(Size, Mem, FCW, Size);
  }

  { _StoreMemGPR(Size, ReconstructFSW_Helper(), Mem, Constant(IR::OpSizeToSize(Size) * 1), Size, MemOffsetType::SXTX, 1); }

  auto ZeroConst = Constant(0);

  {
    // FTW
    _StoreMemGPR(Size, GetX87FTW_Helper(), Mem, Constant(IR::OpSizeToSize(Size) * 2), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Instruction Offset
    Ref IP = GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32() ?
      _LoadContextGPR(OpSize::i32Bit, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.IP)) : ZeroConst;
    _StoreMemGPR(Size, IP, Mem, Constant(IR::OpSizeToSize(Size) * 3), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Instruction CS selector (+ Opcode)
    Ref CS = GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32() ?
      _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.CS)) : ZeroConst;
    if (GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32() && FEXCore::HBX87::LazyFIP::FcsConst()) {
      // RP6q: CS = cs_idx when Reserved == 0 and IP != 0, else the stored CS -- without flags (sub / lsr / and / xor only).
      Ref Raw = _LoadContextGPR(OpSize::i64Bit, offsetof(FEXCore::Core::CPUState, _pad1));
      Ref IPz = _Bfe(OpSize::i64Bit, 32, 0, Raw);
      Ref Res = _Lshr(OpSize::i64Bit, Raw, Constant(48));
      Ref Nz = _Lshr(OpSize::i64Bit, _Sub(OpSize::i64Bit, Constant(0), IPz), Constant(63));
      Ref Rnz = _Lshr(OpSize::i64Bit, _Sub(OpSize::i64Bit, Constant(0), Res), Constant(63));
      Ref Use = _And(OpSize::i64Bit, Nz, _Xor(OpSize::i64Bit, Rnz, Constant(1)));
      Ref Mask = _Sub(OpSize::i64Bit, Constant(0), Use);
      Ref Cur = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, cs_idx));
      CS = _Xor(OpSize::i64Bit, CS, _And(OpSize::i64Bit, _Xor(OpSize::i64Bit, CS, Cur), Mask));
    }
    _StoreMemGPR(Size, CS, Mem, Constant(IR::OpSizeToSize(Size) * 4), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Data pointer offset
    _StoreMemGPR(Size, ZeroConst, Mem, Constant(IR::OpSizeToSize(Size) * 5), Size, MemOffsetType::SXTX, 1);
  }

  {
    // Data pointer selector
    _StoreMemGPR(Size, ZeroConst, Mem, Constant(IR::OpSizeToSize(Size) * 6), Size, MemOffsetType::SXTX, 1);
  }

  auto SevenConst = Constant(7);
  const auto LoadSize = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit;
  for (int i = 0; i < 7; ++i) {
    Ref data = _LoadContextFPRIndexed(Top, LoadSize, MMBaseOffset(), IR::OpSizeToSize(OpSize::i128Bit));
    if (ReducedPrecisionMode) {
      data = _F80CVTTo(data, OpSize::i64Bit);
    }
    _StoreMemFPR(OpSize::i128Bit, data, Mem, Constant((IR::OpSizeToSize(Size) * 7) + (10 * i)), OpSize::i8Bit, MemOffsetType::SXTX, 1);
    Top = _And(OpSize::i32Bit, Add(OpSize::i32Bit, Top, 1), SevenConst);
  }

  // The final st(7) needs a bit of special handling here
  Ref data = _LoadContextFPRIndexed(Top, LoadSize, MMBaseOffset(), IR::OpSizeToSize(OpSize::i128Bit));
  if (ReducedPrecisionMode) {
    data = _F80CVTTo(data, OpSize::i64Bit);
  }
  // ST7 broken in to two parts
  // Lower 64bits [63:0]
  // upper 16 bits [79:64]
  _StoreMemFPR(OpSize::i64Bit, data, Mem, Constant((IR::OpSizeToSize(Size) * 7) + (7 * 10)), OpSize::i8Bit, MemOffsetType::SXTX, 1);
  auto topBytes = _VDupElement(OpSize::i128Bit, OpSize::i16Bit, data, 4);
  _StoreMemFPR(OpSize::i16Bit, topBytes, Mem, Constant((IR::OpSizeToSize(Size) * 7) + (7 * 10) + 8), OpSize::i8Bit, MemOffsetType::SXTX, 1);

  // reset to default
  FNINIT(Op);
}

void OpDispatchBuilder::X87FRSTOR(OpcodeArgs) {
  _StackForceSlow();
  const auto Size = OpSizeFromSrc(Op);
  Ref Mem = MakeSegmentAddress(Op, Op->Src[0]);

  auto NewFCW = CanonicalizeX87ControlWord(_LoadMemGPR(OpSize::i16Bit, Mem, OpSize::i16Bit));
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));
  if (ReducedPrecisionMode) {
    // ignore the rounding precision, we're always 64-bit in F64.
    // extract rounding mode
    Ref roundingMode = NewFCW;
    auto roundShift = Constant(10);
    auto roundMask = Constant(3);
    roundingMode = _Lshr(OpSize::i32Bit, roundingMode, roundShift);
    roundingMode = _And(OpSize::i32Bit, roundingMode, roundMask);
    _SetRoundingMode(roundingMode, false, roundingMode);
  }

  auto NewFSW = _LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size) * 1), Size, MemOffsetType::SXTX, 1);
  Ref Top = ReconstructX87StateFromFSW_Helper(NewFSW);
  {
    // FTW
    SetX87FTW(_LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size) * 2), Size, MemOffsetType::SXTX, 1));
  }
  if (GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32()) {
    Ref IP = _LoadMemGPR(Size, Mem, Constant(IR::OpSizeToSize(Size) * 3), Size, MemOffsetType::SXTX, 1);
    Ref CS = _LoadMemGPR(OpSize::i16Bit, Mem, Constant(IR::OpSizeToSize(Size) * 4), OpSize::i16Bit, MemOffsetType::SXTX, 1);
    _StoreContextGPR(OpSize::i32Bit, IP, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.IP));
    _StoreContextGPR(OpSize::i16Bit, CS, offsetof(FEXCore::Core::CPUState, X87LastInstruction32.CS));
    if (FEXCore::HBX87::LazyFIP::FcsConst()) { // RP6q: the loaded CS is literal until the next x87 instruction
      _StoreContextGPR(OpSize::i16Bit, Constant(1), offsetof(FEXCore::Core::CPUState, X87LastInstruction32.Reserved));
    }
  }

  auto SevenConst = Constant(7);
  auto low = Constant(~0ULL);
  auto high = Constant(0xFFFF);
  Ref Mask = _VLoadTwoGPRs(low, high);
  const auto StoreSize = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit;
  for (int i = 0; i < 7; ++i) {
    Ref Reg = _LoadMemFPR(OpSize::i128Bit, Mem, Constant((IR::OpSizeToSize(Size) * 7) + (10 * i)), OpSize::i8Bit, MemOffsetType::SXTX, 1);
    // Mask off the top bits
    Reg = _VAnd(OpSize::i128Bit, Reg, Mask);
    if (ReducedPrecisionMode) {
      // Convert to double precision
      Reg = _F80CVT(OpSize::i64Bit, Reg);
    }
    _StoreContextFPRIndexed(Reg, Top, StoreSize, MMBaseOffset(), IR::OpSizeToSize(OpSize::i128Bit));

    Top = _And(OpSize::i32Bit, Add(OpSize::i32Bit, Top, 1), SevenConst);
  }

  // The final st(7) needs a bit of special handling here
  // ST7 broken in to two parts
  // Lower 64bits [63:0]
  // upper 16 bits [79:64]
  Ref Reg = _LoadMemFPR(OpSize::i64Bit, Mem, Constant((IR::OpSizeToSize(Size) * 7) + (10 * 7)), OpSize::i8Bit, MemOffsetType::SXTX, 1);
  Ref RegHigh = _LoadMemFPR(OpSize::i16Bit, Mem, Constant((IR::OpSizeToSize(Size) * 7) + (10 * 7) + 8), OpSize::i8Bit, MemOffsetType::SXTX, 1);
  Reg = _VInsElement(OpSize::i128Bit, OpSize::i16Bit, 4, 0, Reg, RegHigh);
  if (ReducedPrecisionMode) {
    Reg = _F80CVT(OpSize::i64Bit, Reg); // Convert to double precision
  }
  _StoreContextFPRIndexed(Reg, Top, StoreSize, MMBaseOffset(), IR::OpSizeToSize(OpSize::i128Bit));
}

// Load / Store Control Word
void OpDispatchBuilder::X87FSTCW(OpcodeArgs) {
  auto FCW = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, FCW));
  StoreResultGPR(Op, FCW);
}

void OpDispatchBuilder::X87FLDCW(OpcodeArgs) {
  // FIXME: Because loading control flags will affect several instructions in fast path, we might have
  // to switch for now to slow mode whenever these are manually changed.
  // Remove the next line and try DF_04.asm in fast path.
  // Full80 operations consume the current FCW at runtime. Retaining their
  // full80 stack cache across FLDCW is safe; F64 reduced precision still needs
  // the original migration. The source read remains unconditional/faulting.
  // 0219: Guest64 FAST64 also keeps the authoritative full80 SSA value across
  // FCW changes. This reuses the existing exact-state elision, not an F64
  // precision cache: FLDCW changes control, never the existing stack values.
  const bool KeepFull80 = FEXCore::HBX87::StateFix::ReadGate("MACRUNNER_HB_X87_ELIDE_REDUNDANT_STATE") ||
                          (CTX->Config.Is64BitMode() && FEXCore::HBX87::Guest64Enabled());
  if (!KeepFull80 || ReducedPrecisionMode()) {
    _StackForceSlow();
  } else if (CTX->Config.Is64BitMode() && FEXCore::HBX87::Guest64Enabled()) {
    // Keep the old context witness before the faulting FCW read while the SSA
    // values survive. The x87 pass also preserves consumed physical payloads.
    auto Sync = _SyncStackToSlow();
    Sync.first->Header.ElementSize = OpSize::i16Bit;
  }
  Ref NewFCW = CanonicalizeX87ControlWord(LoadSourceGPR(Op, Op->Src[0], Op->Flags));
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));
}

void OpDispatchBuilder::FXCH(OpcodeArgs) {
  uint8_t Offset = Op->OP & 7;
  // fxch st0, st0 is for us essentially a nop
  if (Offset != 0) {
    _F80StackXchange(Offset);
  }
  SetRFLAG<FEXCore::X86State::X87FLAG_C1_LOC>(Constant(0));
}

void OpDispatchBuilder::X87FYL2X(OpcodeArgs, bool IsFYL2XP1) {
  if (IsFYL2XP1) {
    _F80FYL2XP1Stack();
  } else {
    _F80FYL2XStack();
  }
}

// MacRunner X87-F3: register forms of the unordered compares. Op->OP = ((escape - 0xD8) << 8) | ModRM.
//   DD E0+i FUCOM, DD E8+i FUCOMP, DA E9 FUCOMPP, DB E8+i FUCOMI, DF E8+i FUCOMIP.
bool OpDispatchBuilder::X87QuietCompare(uint16_t OP) {
  const uint8_t Escape = 0xD8 + ((OP >> 8) & 7);
  const uint8_t ModRM = OP & 0xFF;
  return (Escape == 0xDD && (ModRM & 0xF0) == 0xE0) || (Escape == 0xDA && ModRM == 0xE9) ||
         ((Escape == 0xDB || Escape == 0xDF) && (ModRM & 0xF8) == 0xE8);
}

void OpDispatchBuilder::FCOMI(OpcodeArgs, IR::OpSize Width, bool Integer, OpDispatchBuilder::FCOMIFlags WhichFlags, bool PopTwice) {
  Ref arg {};
  Ref b {};

  // MacRunner X87-F3 (MACRUNNER_HB_X87_FIX_QUIET_COMPARE=1): FUCOM/FUCOMP/FUCOMPP/FUCOMI/FUCOMIP raise IE only for a
  // signaling NaN, FCOM*/FICOM*/FCOMI*/FTST for any NaN. The quiet forms use F80CmpQuiet, whose fallback raises IE
  // (sticky, like every F80 fallback) exactly by the FUCOM rule, so no IE code is emitted for them here.
  const bool Quiet = Op->Src[0].IsNone() && X87QuietCompare(Op->OP) && FEXCore::HBX87::StateFix::QuietCompare();

  Ref Res {};
  if (Op->Src[0].IsNone()) {
    // Implicit arg
    uint8_t Offset = Op->OP & 7;
    Res = Quiet ? _F80CmpQuiet(_ReadStackValue(0), _ReadStackValue(Offset)) : _F80CmpStack(Offset);
  } else {
    if (Width == OpSize::i16Bit || Width == OpSize::i32Bit || Width == OpSize::i64Bit) {
      // Memory arg
      if (Integer) {
        arg = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
        b = _F80CVTToInt(arg, Width);
      } else {
        arg = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
        b = _F80CVTTo(arg, Width);
      }
    } else {
      FEX_UNREACHABLE;
    }
    Res = _F80CmpValue(b);
  }

  Ref HostFlag_CF = _Bfe(OpSize::i64Bit, 1, FCMP_FLAG_LT, Res);
  Ref HostFlag_ZF = _Bfe(OpSize::i64Bit, 1, FCMP_FLAG_EQ, Res);
  Ref HostFlag_Unordered = _Bfe(OpSize::i64Bit, 1, FCMP_FLAG_UNORDERED, Res);
  HostFlag_CF = _Or(OpSize::i32Bit, HostFlag_CF, HostFlag_Unordered);
  HostFlag_ZF = _Or(OpSize::i32Bit, HostFlag_ZF, HostFlag_Unordered);

  if (WhichFlags == FCOMIFlags::FLAGS_X87) {
    SetRFLAG<FEXCore::X86State::X87FLAG_C0_LOC>(HostFlag_CF);
    SetRFLAG<FEXCore::X86State::X87FLAG_C1_LOC>(Constant(0));
    SetRFLAG<FEXCore::X86State::X87FLAG_C2_LOC>(HostFlag_Unordered);
    SetRFLAG<FEXCore::X86State::X87FLAG_C3_LOC>(HostFlag_ZF);
  } else {
    // OF, SF, AF, PF all undefined
    SetCFDirect(HostFlag_CF);
    SetRFLAG<FEXCore::X86State::RFLAG_ZF_RAW_LOC>(HostFlag_ZF);

    // PF is stored inverted, so invert from the host flag.
    // TODO: This could perhaps be optimized?
    auto PF = _Xor(OpSize::i32Bit, HostFlag_Unordered, Constant(1));
    SetRFLAG<FEXCore::X86State::RFLAG_PF_RAW_LOC>(PF);
  }

  // Set Invalid Operation flag when unordered (NaN comparison)
  // The x87 exception flags are sticky. Preserve earlier result
  if (!Quiet) {
    SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(_Or(OpSize::i32Bit, GetRFLAG(FEXCore::X86State::X87FLAG_IE_LOC), HostFlag_Unordered));
  }

  if (PopTwice) {
    _PopStackDestroy();
    _PopStackDestroy();
  } else if ((Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_POP) != 0) {
    _PopStackDestroy();
  }
}

void OpDispatchBuilder::FTST(OpcodeArgs) {
  Ref Res = _F80StackTest(0);

  Ref HostFlag_CF = _Bfe(OpSize::i64Bit, 1, FCMP_FLAG_LT, Res);
  Ref HostFlag_ZF = _Bfe(OpSize::i64Bit, 1, FCMP_FLAG_EQ, Res);
  Ref HostFlag_Unordered = _Bfe(OpSize::i64Bit, 1, FCMP_FLAG_UNORDERED, Res);
  HostFlag_CF = _Or(OpSize::i32Bit, HostFlag_CF, HostFlag_Unordered);
  HostFlag_ZF = _Or(OpSize::i32Bit, HostFlag_ZF, HostFlag_Unordered);

  SetRFLAG<FEXCore::X86State::X87FLAG_C0_LOC>(HostFlag_CF);
  SetRFLAG<FEXCore::X86State::X87FLAG_C1_LOC>(Constant(0));
  SetRFLAG<FEXCore::X86State::X87FLAG_C2_LOC>(HostFlag_Unordered);
  SetRFLAG<FEXCore::X86State::X87FLAG_C3_LOC>(HostFlag_ZF);

  // Set Invalid Operation flag when unordered (NaN comparison)
  // The x87 exception flags are sticky. Preserve earlier result
  SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(_Or(OpSize::i32Bit, GetRFLAG(FEXCore::X86State::X87FLAG_IE_LOC), HostFlag_Unordered));
}

void OpDispatchBuilder::X87OpHelper(OpcodeArgs, FEXCore::IR::IROps IROp, bool ZeroC2) {
  DeriveOp(Result, IROp, _F80SCALEStack());
  if (IROp == FEXCore::IR::OP_F80STACKCHANGESIGN || IROp == FEXCore::IR::OP_F80STACKABS) {
    X87ClearC1(); // X87EXACT C1C
  }
  const bool HelperPublishesC2 = FEXCore::HBX87::StateFix::PartialRemainder() &&
    (IROp == FEXCore::IR::OP_F80FPREMSTACK || IROp == FEXCore::IR::OP_F80FPREM1STACK);
  if (ZeroC2 && !HelperPublishesC2) {
    SetRFLAG<FEXCore::X86State::X87FLAG_C2_LOC>(Constant(0));
  }
}

// X87EXACT C1C (HBX87StateGates.h C1Clear): the instruction leaves C1 = 0 as on the hardware. Callers place it after the
// instruction's memory access (a fault there must still show the old C1) and before a push (an overflowing push sets C1).
void OpDispatchBuilder::X87ClearC1() {
  if (!CTX->Config.Is64BitMode() && !ReducedPrecisionMode && FEXCore::HBX87::StateFix::C1Clear()) {
    SetRFLAG<FEXCore::X86State::X87FLAG_C1_LOC>(Constant(0));
  }
}

void OpDispatchBuilder::X87ModifySTP(OpcodeArgs, bool Inc) {
  if (Inc) {
    _IncStackTop();
  } else {
    _DecStackTop();
  }
  if (Op->OPRaw == 0xD9) { // FINCSTP / FDECSTP (not FFREEP)
    X87ClearC1(); // X87EXACT C1C
  }
}

// Operations dealing with loading and storing environment pieces

// Reconstruct as a constant the Status Word of the FPU.
// We only track stack top, the stack fault flag and each of the code conditions (C flags)
// Top is 3 bits at bit 11.
// IE is 1 bit at bit 0.
// SF is 1 bit at bit 6.
// C0 is 1 bit at bit 8.
// C1 is 1 bit at bit 9.
// C2 is 1 bit at bit 10.
// C3 is 1 bit at bit 14.
// Optionally we can pass a pre calculated value for Top, otherwise we calculate it
// during the function runtime.
Ref OpDispatchBuilder::ReconstructFSW_Helper(Ref T) {
  // Start with the top value
  auto Top = T ? T : GetX87Top();
  if ((FEXCore::HBX87::StateFix::ExceptionState(GetGPROpSize() == OpSize::i64Bit) || FEXCore::HBX87::StateFix::WinctxExact())) {
    // MacRunner X87-F4.2: the flag bytes are laid out like the status word. Bytes 32..39 hold IE DE ZE OE UE PE SF ES = FSW bits
    // 0..7, bytes 40..47 hold C0 C1 C2 TOP - - C3 B = FSW bits 8..15 (TOP is three bits wide, bytes 44/45 are not flags). Every byte
    // is 0/1, so a multiply by 0x0102040810204080 gathers bit 0 of byte i into bit 56+i without carries; two loads assemble all
    // sixteen bits (upstream assembles seven of them with seven loads).
    constexpr uint32_t FlagsBase = offsetof(FEXCore::Core::CPUState, flags);
    Ref Gather = Constant(0x0102040810204080ULL);
    // SPEED114 19.11 (MACRUNNER_FEX32_X87_FSW_NOSTALL): C0 C1 C2 C3 B are read as bytes. The flag bytes were stored as bytes a few
    // instructions ago (the compare, the TOP update of a pop); one 8-byte load over them cannot be forwarded from the store buffer
    // and waits for the stores to commit. Every byte is 0/1 (as the gather multiply requires), so bit i of the result is the byte's bit 0.
    static const bool NoStall = FEXCore::HBX87::StateFix::ReadGate("MACRUNNER_FEX32_X87_FSW_NOSTALL");
    if (NoStall) {
      const auto FlagByte = [&](unsigned Loc) { return _LoadContextGPR(OpSize::i8Bit, FlagsBase + Loc); };
      Ref LowW = _And(OpSize::i64Bit, _LoadContextGPR(OpSize::i64Bit, FlagsBase + FEXCore::X86State::X87FLAG_IE_LOC), Constant(0x0101010101010101ULL));
      Ref Bits = _Lshr(OpSize::i64Bit, _Mul(OpSize::i64Bit, LowW, Gather), Constant(56));
      Ref H = FlagByte(FEXCore::X86State::X87FLAG_C0_LOC);
      H = _Orlshl(OpSize::i64Bit, H, FlagByte(FEXCore::X86State::X87FLAG_C1_LOC), 1);
      H = _Orlshl(OpSize::i64Bit, H, FlagByte(FEXCore::X86State::X87FLAG_C2_LOC), 2);
      H = _Orlshl(OpSize::i64Bit, H, FlagByte(FEXCore::X86State::X87FLAG_C3_LOC), 6);
      H = _Orlshl(OpSize::i64Bit, H, FlagByte(FEXCore::X86State::X87FLAG_B_LOC), 7);
      Bits = _Orlshl(OpSize::i64Bit, Bits, H, 8);
      return _Orlshl(OpSize::i64Bit, Bits, Top, 11);
    }
    Ref Low = _And(OpSize::i64Bit, _LoadContextGPR(OpSize::i64Bit, FlagsBase + FEXCore::X86State::X87FLAG_IE_LOC), Constant(0x0101010101010101ULL));
    Ref High = _And(OpSize::i64Bit, _LoadContextGPR(OpSize::i64Bit, FlagsBase + FEXCore::X86State::X87FLAG_C0_LOC), Constant(0xFFFF000000FFFFFFULL));
    Ref FSW = _Lshr(OpSize::i64Bit, _Mul(OpSize::i64Bit, Low, Gather), Constant(56));
    FSW = _Orlshl(OpSize::i64Bit, FSW, _Lshr(OpSize::i64Bit, _Mul(OpSize::i64Bit, High, Gather), Constant(56)), 8);
    return _Orlshl(OpSize::i64Bit, FSW, Top, 11);
  }
  Ref FSW = _Lshl(OpSize::i64Bit, Top, Constant(11));

  // We must construct the FSW from our various bits
  auto C0 = GetRFLAG(FEXCore::X86State::X87FLAG_C0_LOC);
  FSW = _Orlshl(OpSize::i64Bit, FSW, C0, 8);

  auto C1 = GetRFLAG(FEXCore::X86State::X87FLAG_C1_LOC);
  FSW = _Orlshl(OpSize::i64Bit, FSW, C1, 9);

  auto C2 = GetRFLAG(FEXCore::X86State::X87FLAG_C2_LOC);
  FSW = _Orlshl(OpSize::i64Bit, FSW, C2, 10);

  auto C3 = GetRFLAG(FEXCore::X86State::X87FLAG_C3_LOC);
  FSW = _Orlshl(OpSize::i64Bit, FSW, C3, 14);

  auto SF = GetRFLAG(FEXCore::X86State::X87FLAG_SF_LOC);
  FSW = _Orlshl(OpSize::i64Bit, FSW, SF, 6);

  auto IE = GetRFLAG(FEXCore::X86State::X87FLAG_IE_LOC);
  FSW = _Or(OpSize::i64Bit, FSW, IE);

  return FSW;
}

// Store Status Word
// There's no load Status Word instruction but you can load it through frstor
// or fldenv.
void OpDispatchBuilder::X87FNSTSW(OpcodeArgs) {
  Ref TopValue = _SyncStackToSlow();
  Ref StatusWord = ReconstructFSW_Helper(TopValue);
  StoreResultGPR(Op, StatusWord);
}

void OpDispatchBuilder::FNCLEX(OpcodeArgs) {
  if ((FEXCore::HBX87::StateFix::ExceptionState(GetGPROpSize() == OpSize::i64Bit) || FEXCore::HBX87::StateFix::WinctxExact())) {
    // MacRunner X87-F4.2: IE DE ZE OE UE PE SF ES are bytes 32..39: one store, then B.
    _StoreContextGPR(OpSize::i64Bit, _Constant(0), offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_IE_LOC);
    SetRFLAG<FEXCore::X86State::X87FLAG_B_LOC>(_Constant(0));
    return;
  }
  // Clear the exception flag bit and the stack fault flag
  SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(_Constant(0));
  SetRFLAG<FEXCore::X86State::X87FLAG_SF_LOC>(_Constant(0));
}

void OpDispatchBuilder::FNINIT(OpcodeArgs) {
  _SyncStackToSlow(); // Invalidate x87 register caches
  if (GetGPROpSize() == OpSize::i32Bit && FEXCore::HBX87::StateFix::InstructionPointers32()) {
    _StoreContextGPR(OpSize::i64Bit, Constant(0), offsetof(FEXCore::Core::CPUState, _pad1));
  }

  auto Zero = Constant(0);

  if (ReducedPrecisionMode) {
    _SetRoundingMode(Zero, false, Zero);
  }

  // Init FCW to 0x037F
  auto NewFCW = Constant(0x037F);
  _StoreContextGPR(OpSize::i16Bit, NewFCW, offsetof(FEXCore::Core::CPUState, FCW));

  // Set top to zero
  SetX87Top(Zero);
  // Tags all get marked as invalid
  _StoreContextGPR(OpSize::i8Bit, Zero, offsetof(FEXCore::Core::CPUState, AbridgedFTW));

  // Reinits the simulated stack
  _InitStack();

  SetRFLAG<FEXCore::X86State::X87FLAG_C0_LOC>(Zero);
  SetRFLAG<FEXCore::X86State::X87FLAG_C1_LOC>(Zero);
  SetRFLAG<FEXCore::X86State::X87FLAG_C2_LOC>(Zero);
  SetRFLAG<FEXCore::X86State::X87FLAG_C3_LOC>(Zero);
  if ((FEXCore::HBX87::StateFix::ExceptionState(GetGPROpSize() == OpSize::i64Bit) || FEXCore::HBX87::StateFix::WinctxExact())) {
    // MacRunner X87-F4.2: IE DE ZE OE UE PE SF ES are bytes 32..39: one store, then B.
    _StoreContextGPR(OpSize::i64Bit, Zero, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_IE_LOC);
    SetRFLAG<FEXCore::X86State::X87FLAG_B_LOC>(Zero);
  } else {
    SetRFLAG<FEXCore::X86State::X87FLAG_IE_LOC>(Zero);
    SetRFLAG<FEXCore::X86State::X87FLAG_SF_LOC>(Zero);
  }
}

void OpDispatchBuilder::X87FFREE(OpcodeArgs) {
  _InvalidateStack(Op->OP & 7);
  X87ClearC1(); // X87EXACT C1C
}

void OpDispatchBuilder::X87EMMS(OpcodeArgs) {
  // Tags all get set to 0b11
  _InvalidateStack(0xff);
}

void OpDispatchBuilder::X87FCMOV(OpcodeArgs) {
  CalculateDeferredFlags();

  uint16_t Opcode = Op->OP & 0b1111'1111'1000;
  uint8_t CC = 0;

  switch (Opcode) {
  case 0x3'C0:
    CC = 0x3; // JNC
    break;
  case 0x2'C0:
    CC = 0x2; // JC
    break;
  case 0x2'C8:
    CC = 0x4; // JE
    break;
  case 0x3'C8:
    CC = 0x5; // JNE
    break;
  case 0x2'D0:
    CC = 0x6; // JNA
    break;
  case 0x3'D0:
    CC = 0x7; // JA
    break;
  case 0x2'D8:
    CC = 0xA; // JP
    break;
  case 0x3'D8:
    CC = 0xB; // JNP
    break;
  default: LOGMAN_MSG_A_FMT("Unhandled FCMOV op: 0x{:x}", Opcode); break;
  }

  Ref VecCond = _VDupFromGPR(OpSize::i128Bit, OpSize::i64Bit, SelectCC0All1(CC));
  _F80VBSLStack(OpSize::i128Bit, VecCond, Op->OP & 7, 0);
}

void OpDispatchBuilder::X87FXAM(OpcodeArgs) {
  auto a = _ReadStackValue(0);
  Ref Result =
    ReducedPrecisionMode ? _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, a, 0) : _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, a, 1);

  // Extract the sign bit
  Result = ReducedPrecisionMode ? _Bfe(OpSize::i64Bit, 1, 63, Result) : _Bfe(OpSize::i64Bit, 1, 15, Result);
  SetRFLAG<FEXCore::X86State::X87FLAG_C1_LOC>(Result);

  auto TopValid = _StackValidTag(0);

  if (FEXCore::HBX87::StateFix::FxamClass()) {
    // SPEED114/X87EXACT FXAM class. C3:C2:C0 = 000 unsupported, 001 NaN, 010 normal, 011 infinity, 100 zero, 101 empty, 110 denormal.
    Ref Lo = ReducedPrecisionMode ? _VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, a, 0) : _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, a, 0);
    Ref Hi = ReducedPrecisionMode ? Lo : _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, a, 1);
    Ref Exp = ReducedPrecisionMode ? _Bfe(OpSize::i64Bit, 11, 52, Hi) : _Bfe(OpSize::i64Bit, 15, 0, Hi);
    Ref MaxExp = Constant(ReducedPrecisionMode ? 0x7FF : 0x7FFF);
    Ref IntBit = ReducedPrecisionMode ? Constant(1) : _Bfe(OpSize::i64Bit, 1, 63, Lo);
    Ref Frac = ReducedPrecisionMode ? _Bfe(OpSize::i64Bit, 52, 0, Lo) : _And(OpSize::i64Bit, Lo, Constant(0x7FFFFFFFFFFFFFFFULL));
    const auto Not = [&](Ref V) { return _Xor(OpSize::i64Bit, V, Constant(1)); };
    const auto And = [&](Ref A, Ref B) { return _And(OpSize::i64Bit, A, B); };
    const auto Or = [&](Ref A, Ref B) { return _Or(OpSize::i64Bit, A, B); };
    Ref IsMax = Select01(OpSize::i64Bit, CondClass::EQ, Exp, MaxExp);
    Ref IsZeroExp = Select01(OpSize::i64Bit, CondClass::EQ, Exp, Constant(0));
    Ref FracZero = Select01(OpSize::i64Bit, CondClass::EQ, Frac, Constant(0));
    Ref Valid = TopValid;
    Ref Empty = Not(Valid);
    Ref Inf = And(And(IsMax, IntBit), FracZero);
    Ref NaN = And(And(IsMax, IntBit), Not(FracZero));
    // Reduced precision keeps F64 values: an F64 denormal is a normal number of the F80 the guest believes it holds.
    Ref Normal = ReducedPrecisionMode ? Not(Or(IsMax, And(IsZeroExp, FracZero))) : And(And(Not(IsMax), Not(IsZeroExp)), IntBit);
    Ref Zero = ReducedPrecisionMode ? And(IsZeroExp, FracZero) : And(And(IsZeroExp, FracZero), Not(IntBit)); // F80 pseudo-denormal: integer bit set
    Ref Denormal = ReducedPrecisionMode ? Constant(0) : And(IsZeroExp, Not(Zero));
    Ref C3v = Or(And(ReducedPrecisionMode ? Zero : IsZeroExp, Valid), Empty);
    Ref C2v = And(Or(Or(Normal, Inf), Denormal), Valid);
    Ref C0v = Or(And(Or(NaN, Inf), Valid), Empty);
    SetRFLAG<FEXCore::X86State::X87FLAG_C0_LOC>(C0v);
    SetRFLAG<FEXCore::X86State::X87FLAG_C2_LOC>(C2v);
    SetRFLAG<FEXCore::X86State::X87FLAG_C3_LOC>(C3v);
    return;
  }

  // Claim this is a normal number
  // We don't support anything else

  // In the case of top being invalid then C3:C2:C0 is 0b101
  auto C3 = Select01(OpSize::i32Bit, CondClass::NEQ, TopValid, Constant(1));

  auto C2 = TopValid;
  auto C0 = C3; // Mirror C3 until something other than zero is supported
  SetRFLAG<FEXCore::X86State::X87FLAG_C0_LOC>(C0);
  SetRFLAG<FEXCore::X86State::X87FLAG_C2_LOC>(C2);
  SetRFLAG<FEXCore::X86State::X87FLAG_C3_LOC>(C3);
}

void OpDispatchBuilder::X87FXTRACT(OpcodeArgs) {
  auto Top = _ReadStackValue(0);

  _PopStackDestroy();
  auto Exp = _F80XTRACT_EXP(Top);
  auto Sig = _F80XTRACT_SIG(Top);
  _PushStack(Exp, Invalid(), OpSize::iInvalid);
  _PushStack(Sig, Invalid(), OpSize::iInvalid);
}

} // namespace FEXCore::IR
