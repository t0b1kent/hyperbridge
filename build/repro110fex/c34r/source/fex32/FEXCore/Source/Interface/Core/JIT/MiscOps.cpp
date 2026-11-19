// SPDX-License-Identifier: MIT
/*
$info$
tags: backend|arm64
$end_info$
*/

#ifndef _WIN32
#include <syscall.h>
#endif

#include "Interface/Context/Context.h"
#include "Interface/Core/JIT/DebugData.h"
#include "Interface/Core/JIT/JITClass.h"

#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/EnumUtils.h>

namespace FEXCore::CPU {

DEF_OP(WFET) {
  auto Op = IROp->C<IR::IROp_WFET>();
  const auto Lower = GetReg(Op->Lower);
  const auto Upper = GetReg(Op->Upper);

  // Combine registers.
  mov(ARMEmitter::Size::i64Bit, TMP1, Lower);
  bfi(ARMEmitter::Size::i64Bit, TMP1, Upper, 32, 32);
  if (CTX->Config.TSCScale) {
    // Scale back to ARM64 TSC scale if necessary
    lsr(ARMEmitter::Size::i64Bit, TMP1, TMP1, CTX->Config.TSCScale);
  }

  // Clear the exclusive monitor so it can't spuriously wake up with that event.
  clrex();

  // Execute wfet to wait until the TSC.
  wfet(TMP1);
}

// SPEED114 19.11: X87PushFault. Dest = Value; Pred == 1: Dest = 0xFFF8000000000000 (QNaN indefinite as a double), IE = SF = C1 = 1.
// (IE and SF are sticky 0/1 bytes and C1 is only ever set here, so storing 1 equals the OR the unfused sequence did.)
DEF_OP(X87PushFault) {
  const auto Op = IROp->C<IR::IROp_X87PushFault>();
  const auto Dst = GetVReg(Node);
  const auto Value = GetVReg(Op->Value);
  const auto Pred = GetReg(Op->Pred);
  using namespace ARMEmitter;
  ForwardLabel Done;
  if (Dst != Value) {
    if (IROp->Size == IR::OpSize::i128Bit) {
      mov(Dst.Q(), Value.Q());
    } else {
      mov(Dst.D(), Value.D());
    }
  }
  if (Op->Bit == 255) {
    (void)cbz(Size::i32Bit, Pred, &Done);
  } else {
    (void)tbz(Pred, Op->Bit, &Done);
  }
  movz(Size::i32Bit, TMP1, 1);
  strb(TMP1, STATE, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_IE_LOC);
  strb(TMP1, STATE, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_SF_LOC);
  strb(TMP1, STATE, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_C1_LOC);
  LoadConstant(Size::i64Bit, TMP1, 0xFFF8000000000000ULL);
  fmov(Size::i64Bit, Dst.D(), TMP1);
  (void)Bind(&Done);
}

// SPEED114 19.11: X87QuietIE. Dest = 1 when A or B is a binary64 signaling NaN (exponent all ones, quiet bit clear, fraction nonzero),
// else 0. With the sign shifted out the signaling patterns are exactly those with (bits << 1) + 0x001FFFFFFFFFFFFF < 0x000FFFFFFFFFFFFF.
// Unordered (the compare's V flag as 0/1) is 1 for every NaN, so for Unordered == 0 the answer is 0 without looking at the operands.
// NZCV is live across the op (the compare's result is converted after it): the classifying part saves and restores it.
DEF_OP(X87QuietIE) {
  const auto Op = IROp->C<IR::IROp_X87QuietIE>();
  const auto Dst = GetReg(Node);
  const auto A = GetVReg(Op->A);
  const auto B = GetVReg(Op->B);
  const auto Unordered = GetReg(Op->Unordered);
  using namespace ARMEmitter;
  ForwardLabel Done;
  if (Dst != Unordered) {
    mov(Size::i64Bit, Dst, Unordered);
  }
  (void)cbz(Size::i64Bit, Unordered, &Done);
  mrs(TMP3, SystemRegister::NZCV);
  LoadConstant(Size::i64Bit, TMP2, 0x001FFFFFFFFFFFFFULL);
  LoadConstant(Size::i64Bit, TMP4, 0x000FFFFFFFFFFFFFULL);
  fmov(Size::i64Bit, TMP1, A.D());
  lsl(Size::i64Bit, TMP1, TMP1, 1);
  add(Size::i64Bit, TMP1, TMP1, TMP2);
  cmp(Size::i64Bit, TMP1, TMP4);
  cset(Size::i64Bit, TMP1, Condition::CC_CC);
  fmov(Size::i64Bit, Dst, B.D());
  lsl(Size::i64Bit, Dst, Dst, 1);
  add(Size::i64Bit, Dst, Dst, TMP2);
  cmp(Size::i64Bit, Dst, TMP4);
  cset(Size::i64Bit, Dst, Condition::CC_CC);
  orr(Size::i64Bit, Dst, Dst, TMP1);
  msr(SystemRegister::NZCV, TMP3);
  (void)Bind(&Done);
}

// SPEED114 19.11: X87StickyIE. IE |= New (both 0/1 bytes): store 1 only when New is 1, nothing at all otherwise.
DEF_OP(X87StickyIE) {
  const auto Op = IROp->C<IR::IROp_X87StickyIE>();
  const auto New = GetReg(Op->New);
  using namespace ARMEmitter;
  ForwardLabel Done;
  (void)cbz(Size::i64Bit, New, &Done);
  movz(Size::i32Bit, TMP1, 1);
  strb(TMP1, STATE, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_IE_LOC);
  (void)Bind(&Done);
}

DEF_OP(GuestOpcode) {
  auto Op = IROp->C<IR::IROp_GuestOpcode>();
  // metadata
  DebugData->GuestOpcodes.push_back({Op->GuestEntryOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
}

// X87-CTX P5 (MACRUNNER_FEX_X87_FAULT_STATE): no host code. Turns the RA-resolved locations into host registers / spill slots
// and opens the record of the next op (its target); CompileCode keeps it after the target is emitted.
DEF_OP(X87FaultState) {
  using namespace FEXCore::Core::X87Fault;
  auto Op = IROp->C<IR::IROp_X87FaultState>();
  static_assert(offsetof(IR::IROp_X87FaultState, Value7) == offsetof(IR::IROp_X87FaultState, Value0) + 7 * sizeof(uint32_t));
  X87FaultIsOpen = false;
  if (!(Op->Mode & 0x80)) {
    return; // RA could not place every value: no record, the fault keeps today's state
  }
  const auto Location = [&](uint32_t Encoded, bool FPR, uint16_t& Out) {
    const uint32_t Kind = Encoded >> 28, Payload = Encoded & 0x0fffffffU;
    if (Kind == 1) {
      IR::PhysicalRegister Reg(IR::RegClass::Invalid, 0);
      Reg.Raw = static_cast<uint8_t>(Payload);
      const auto Class = Reg.AsRegClass();
      if (FPR && (Class == IR::RegClass::FPR || Class == IR::RegClass::FPRFixed)) {
        Out = LocQ | GetVReg(Reg).Idx();
        return true;
      }
      if (!FPR && (Class == IR::RegClass::GPR || Class == IR::RegClass::GPRFixed)) {
        Out = LocX | GetReg(Reg).Idx();
        return true;
      }
      return false;
    }
    if (Kind == 2 && Payload < (1U << 14)) {
      Out = LocSpill | Payload;
      return true;
    }
    return false;
  };
  Record R {};
  R.HostBegin = static_cast<uint32_t>(GetCursorAddress<uint8_t*>() - CodeData.BlockBegin);
  R.Mode = Op->Mode & (Slow | Values64 | TopPending | PCXValues | TopRelative);
  R.TopOffset = Op->TopOffset;
  R.ValueMask = Op->ValueMask;
  R.ValidMask = Op->ValidMask;
  R.InvalidMask = Op->InvalidMask;
  R.SingleMask = Op->SingleMask; // X87EXACT S32
  if (Op->Mode & TopPending) {
    if ((Op->Top >> 28) == 3) {
      R.Mode |= TopConstant;
      R.Top = Op->Top & 7;
    } else if (!Location(Op->Top, false, R.Top)) {
      return;
    }
  }
  const uint32_t* Values = &Op->Value0;
  for (unsigned i = 0; i < 8; ++i) {
    if ((Op->ValueMask & (1U << i)) && !Location(Values[i], true, R.Values[i])) {
      return;
    }
  }
  X87FaultOpen = R;
  X87FaultOpenTarget = Op->Target;
  X87FaultIsOpen = true;
}

DEF_OP(Fence) {
  auto Op = IROp->C<IR::IROp_Fence>();
  switch (Op->Fence) {
  case IR::FenceType::Load: dmb(ARMEmitter::BarrierScope::LD); break;
  case IR::FenceType::LoadStore: dmb(ARMEmitter::BarrierScope::SY); break;
  case IR::FenceType::Store: dmb(ARMEmitter::BarrierScope::ST); break;
  case IR::FenceType::Inst: isb(); break;
  default: LOGMAN_MSG_A_FMT("Unknown Fence: {}", Op->Fence); break;
  }
}

DEF_OP(Break) {
  auto Op = IROp->C<IR::IROp_Break>();

  // First we must reset the stack
  ResetStack();

  Core::CpuStateFrame::SynchronousFaultDataStruct State = {
    .FaultToTopAndGeneratedException = 1,
    .Signal = Op->Reason.Signal,
    .TrapNo = Op->Reason.TrapNumber,
    .si_code = Op->Reason.si_code,
    .err_code = Op->Reason.ErrorRegister,
  };

  uint64_t Constant {};
  memcpy(&Constant, &State, sizeof(State));

  LoadConstant(ARMEmitter::Size::i64Bit, TMP1, Constant);
  str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, SynchronousFaultData));

  switch (Op->Reason.Signal) {
  case Core::FAULT_SIGILL:
    ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGILL));
    br(TMP1);
    break;
  case Core::FAULT_SIGTRAP:
    ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGTRAP));
    br(TMP1);
    break;
  case Core::FAULT_SIGSEGV:
    ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGSEGV));
    br(TMP1);
    break;
  default:
    ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGTRAP));
    br(TMP1);
    break;
  }
}

DEF_OP(GetRoundingMode) {
  auto Dst = GetReg(Node);
  mrs(Dst, ARMEmitter::SystemRegister::FPCR);
  ubfx(ARMEmitter::Size::i64Bit, Dst, Dst, 22, 3);

  // FTZ is already in the correct location
  // Rounding mode is different
  //
  // Need to remap rounding mode from order nearest, pos inf, neg inf, toward
  // zero. Just swapping 01 and 10. That's a bitfield reverse. Round mode is in
  // bottom two bits. After reversing as a 32-bit operation, it'll be in [31:30]
  // and ripe for reinsertion back at 0.
  static_assert(FEXCore::ToUnderlying(IR::RoundMode::Nearest) == 0);
  static_assert(FEXCore::ToUnderlying(IR::RoundMode::NegInfinity) == 1);
  static_assert(FEXCore::ToUnderlying(IR::RoundMode::PosInfinity) == 2);
  static_assert(FEXCore::ToUnderlying(IR::RoundMode::TowardsZero) == 3);

  rbit(ARMEmitter::Size::i32Bit, TMP1, Dst);
  bfi(ARMEmitter::Size::i64Bit, Dst, TMP1, 30, 2);
}

DEF_OP(SetRoundingMode) {
  auto Op = IROp->C<IR::IROp_SetRoundingMode>();
  auto Src = GetReg(Op->RoundMode);
  auto MXCSR = GetReg(Op->MXCSR);

  // As above, setup the rounding flags in [31:30]
  rbit(ARMEmitter::Size::i32Bit, TMP2, Src);
  // and extract
  lsr(ARMEmitter::Size::i32Bit, TMP2, TMP2, 30);

  mrs(TMP1, ARMEmitter::SystemRegister::FPCR);

  // vixl simulator doesn't support anything beyond ties-to-even rounding
  if (CTX->Config.DisableVixlIndirectCalls) [[likely]] {
    // Insert the rounding flags
    bfi(ARMEmitter::Size::i64Bit, TMP1, TMP2, 22, 2);
  }

  // Insert the FTZ flag
  lsr(ARMEmitter::Size::i64Bit, TMP2, Src, 2);
  bfi(ARMEmitter::Size::i64Bit, TMP1, TMP2, 24, 1);

  if (Op->SetDAZ && HostSupportsAFP) {
    // Extract DAZ from MXCSR and insert to in FPCR.FIZ
    bfxil(ARMEmitter::Size::i64Bit, TMP1, MXCSR, 6, 1);
  }

  // Now save the new FPCR
  msr(ARMEmitter::SystemRegister::FPCR, TMP1);

  if (Op->SetDAZ && CTX->HostFeatures.SupportsAppleAFP) {
    // Apple compat ignores FPCR.FZ. MXCSR.DAZ and FTZ are independent.
    mrs(TMP1, ARMEmitter::SystemRegister::AFPCR_EL0);
    bfxil(ARMEmitter::Size::i64Bit, TMP1, MXCSR, 6, 1);
    lsr(ARMEmitter::Size::i64Bit, TMP2, MXCSR, 15);
    bfi(ARMEmitter::Size::i64Bit, TMP1, TMP2, 1, 1);
    msr(ARMEmitter::SystemRegister::AFPCR_EL0, TMP1);
  }
}

DEF_OP(PushRoundingMode) {
  auto Op = IROp->C<IR::IROp_PushRoundingMode>();
  auto Dest = GetReg(Node);

  // Save the old rounding mode
  mrs(Dest, ARMEmitter::SystemRegister::FPCR);
  if (CTX->HostFeatures.SupportsAppleAFP) {
    mrs(TMP2, ARMEmitter::SystemRegister::AFPCR_EL0);
    bfi(ARMEmitter::Size::i64Bit, Dest, TMP2, 32, 2);
  }

  // vixl simulator doesn't support anything beyond ties-to-even rounding
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    return;
  }

  // Insert the rounding flags, reversing the mode bits as above
  if (Op->RoundMode == 3) {
    orr(ARMEmitter::Size::i64Bit, TMP1, Dest, 3 << 22);
  } else if (Op->RoundMode == 0) {
    and_(ARMEmitter::Size::i64Bit, TMP1, Dest, ~(3 << 22));
  } else {
    LOGMAN_THROW_A_FMT(Op->RoundMode == 1 || Op->RoundMode == 2, "expect a valid round mode");

    and_(ARMEmitter::Size::i64Bit, TMP1, Dest, ~(3 << 22));
    orr(ARMEmitter::Size::i64Bit, TMP1, TMP1, (Op->RoundMode == 2 ? 1 : 2) << 22);
  }

  // Now save the new FPCR
  msr(ARMEmitter::SystemRegister::FPCR, TMP1);
}

DEF_OP(PushFPCRNoFlush) {
  auto Dest = GetReg(Node);
  mrs(Dest, ARMEmitter::SystemRegister::FPCR);
  if (CTX->HostFeatures.SupportsAppleAFP) {
    // Pair the temporary software DAZ/FTZ scope with PopRoundingMode.
    // FPCR has no architectural upper 32 bits; reserve bits32..33 in the token.
    mrs(TMP2, ARMEmitter::SystemRegister::AFPCR_EL0);
    bfi(ARMEmitter::Size::i64Bit, Dest, TMP2, 32, 2);
    and_(ARMEmitter::Size::i64Bit, TMP1, TMP2, ~uint64_t(3));
    msr(ARMEmitter::SystemRegister::AFPCR_EL0, TMP1);
  }
  // ARM FZ without AFP flushes inputs as well as outputs. Guest SSE controls
  // these independently through software DAZ input and FTZ output selection.
  and_(ARMEmitter::Size::i64Bit, TMP1, Dest, ~(uint64_t(1) << 24));
  if (HostSupportsAFP) {
    and_(ARMEmitter::Size::i64Bit, TMP1, TMP1, ~uint64_t(1));
  }
  msr(ARMEmitter::SystemRegister::FPCR, TMP1);
}

DEF_OP(PushFPSR) {
  auto Dest = GetReg(Node);
  mrs(Dest, ARMEmitter::SystemRegister::FPSR);
  LoadConstant(ARMEmitter::Size::i32Bit, TMP1, 0);
  msr(ARMEmitter::SystemRegister::FPSR, TMP1);
}

DEF_OP(GetFPSR) {
  // Dependency keeps the arithmetic live for exception flags. No extra
  // machine-code read of the vector is needed; ordered IR emission suffices.
  mrs(GetReg(Node), ARMEmitter::SystemRegister::FPSR);
}

DEF_OP(ReadFPSR) {
  mrs(GetReg(Node), ARMEmitter::SystemRegister::FPSR);
}

DEF_OP(PopFPSR) {
  auto Op = IROp->C<IR::IROp_PopFPSR>();
  msr(ARMEmitter::SystemRegister::FPSR, GetReg(Op->FPSR));
}

DEF_OP(PopRoundingMode) {
  auto Op = IROp->C<IR::IROp_PopRoundingMode>();
  auto Saved = GetReg(Op->FPCR);
  if (CTX->HostFeatures.SupportsAppleAFP) {
    mrs(TMP1, ARMEmitter::SystemRegister::AFPCR_EL0);
    bfxil(ARMEmitter::Size::i64Bit, TMP1, Saved, 32, 2);
    msr(ARMEmitter::SystemRegister::AFPCR_EL0, TMP1);
    and_(ARMEmitter::Size::i64Bit, TMP1, Saved, uint64_t(0xffffffff));
    msr(ARMEmitter::SystemRegister::FPCR, TMP1);
  } else {
    msr(ARMEmitter::SystemRegister::FPCR, Saved);
  }
}

DEF_OP(Print) {
  auto Op = IROp->C<IR::IROp_Print>();

  PushDynamicRegs(TMP1);
  SpillStaticRegs(TMP1);

  if (IsGPR(Op->Value)) {
    mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, GetReg(Op->Value));
    ldr(ARMEmitter::XReg::x3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.PrintValue));
  } else {
    fmov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, GetVReg(Op->Value), false);
    fmov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, GetVReg(Op->Value), true);
    ldr(ARMEmitter::XReg::x3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.PrintVectorValue));
  }

  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    if (IsGPR(Op->Value)) {
      GenerateIndirectRuntimeCall<void, uint64_t>(ARMEmitter::Reg::r3);
    } else {
      GenerateIndirectRuntimeCall<void, uint64_t, uint64_t>(ARMEmitter::Reg::r3);
    }
  } else {
    blr(ARMEmitter::Reg::r3);
  }

  FillStaticRegs();
  PopDynamicRegs();
}

DEF_OP(PrintMsg) {
  auto Op = IROp->C<IR::IROp_PrintMsg>();

  PushDynamicRegs(TMP1);
  SpillStaticRegs(TMP1);

  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, reinterpret_cast<uintptr_t>(Op->Value));
  ldr(ARMEmitter::XReg::x1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.PrintMsgValue));

  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<void, uint64_t>(ARMEmitter::Reg::r1);
  } else {
    blr(ARMEmitter::Reg::r1);
  }

  FillStaticRegs();
  PopDynamicRegs();
}

DEF_OP(ProcessorID) {
  if (CTX->HostFeatures.SupportsCPUIndexInTPIDRRO) {
    mrs(GetReg(Node), ARMEmitter::SystemRegister::TPIDRRO_EL0);
    return;
  }
#ifdef _WIN32
  else {
    // If on Windows and TPIDRRO isn't supported (like in wine), then this is a programming error.
    ERROR_AND_DIE_FMT("Unsupported");
  }
#else
  // We always need to spill x8 since we can't know if it is live at this SSA location
  uint32_t SpillMask = 1U << 8;

  // Ordering is incredibly important here
  // We must spill any overlapping registers first THEN claim we are in a syscall without invalidating state at all
  // Only spill the registers that intersect with our usage
  SpillStaticRegs(TMP1, {
                          .GPRSpillMask = SpillMask,
                          .FPRs = false,
                        });

  // Now that we are spilled, store in the state that we are in a syscall
  // Still without overwriting registers that matter
  // 16bit LoadConstant to be a single instruction
  // We must always spill at least one register (x8) so this value always has a bit set
  // This gives the signal handler a value to check to see if we are in a syscall at all
  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, SpillMask & 0xFFFF);
  str(ARMEmitter::XReg::x0, STATE, offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));

  // Allocate some temporary space for storing the uint32_t CPU and Node IDs
  sub(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, 16);

  // Load the getcpu syscall number
#if defined(ARCHITECTURE_x86_64)
  // Just to ensure the syscall number doesn't change if compiled for an x86_64 host.
  constexpr auto GetCPUSyscallNum = 0xa8;
#else
  constexpr auto GetCPUSyscallNum = SYS_getcpu;
#endif
  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r8, GetCPUSyscallNum);

  // CPU pointer in x0
  add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, ARMEmitter::Reg::rsp, 0);
  // Node in x1
  add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, ARMEmitter::Reg::rsp, 4);

  svc(0);
  // On updated signal mask we can receive a signal RIGHT HERE

  // Load the values returned by the kernel
  ldp<ARMEmitter::IndexType::OFFSET>(ARMEmitter::WReg::w0, ARMEmitter::WReg::w1, ARMEmitter::Reg::rsp);
  // Deallocate stack space
  add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, 16);

  // Now that we are done in the syscall we need to carefully peel back the state
  // First unspill the registers from before

  FillStaticRegs({
    .OptionalReg = ARMEmitter::Reg::r8,
    .OptionalReg2 = ARMEmitter::Reg::r2,
    .GPRFillMask = SpillMask,
    .FPRs = false,
  });

  // Now the registers we've spilled are back in their original host registers
  // We can safely claim we are no longer in a syscall
  str(ARMEmitter::XReg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));

  // Now store the result in the destination in the expected format
  // uint32_t Res = (node << 12) | cpu;
  // CPU is in w0
  // Node is in w1
  orr(ARMEmitter::Size::i64Bit, GetReg(Node), ARMEmitter::Reg::r0, ARMEmitter::Reg::r1, ARMEmitter::ShiftType::LSL, 12);
#endif
}

DEF_OP(RDRAND) {
  auto Op = IROp->C<IR::IROp_RDRAND>();

  mrs(GetReg(Node), Op->GetReseeded ? ARMEmitter::SystemRegister::RNDRRS : ARMEmitter::SystemRegister::RNDR);
}

DEF_OP(Yield) {
  yield();
}

DEF_OP(MonoBackpatcherWrite) {
  auto Op = IROp->C<IR::IROp_MonoBackpatcherWrite>();

  mov(ARMEmitter::Size::i64Bit, TMP3, GetReg(Op->Addr));
  mov(ARMEmitter::Size::i64Bit, TMP4, GetReg(Op->Value));

  PushDynamicRegs(TMP1);
  SpillStaticRegs(TMP1);

  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, STATE.R());
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, IR::OpSizeToSize(Op->Size));

  if (!TMP_ABIARGS) {
    mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, TMP3);
    mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r3, TMP4);
  }

#ifdef ARCHITECTURE_arm64ec
  ldr(TMP2, ARMEmitter::XReg::x18, TEB_CPU_AREA_OFFSET);
  LoadConstant(ARMEmitter::Size::i32Bit, TMP1, 1);
  strb(TMP1.W(), TMP2, CPU_AREA_IN_SYSCALL_CALLBACK_OFFSET);
#endif

  ldr(ARMEmitter::XReg::x4, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.MonoBackpatcherWrite));
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<void, void*, uint8_t, uint64_t, uint64_t>(ARMEmitter::Reg::r4);
  } else {
    blr(ARMEmitter::Reg::r4);
  }

#ifdef ARCHITECTURE_arm64ec
  ldr(TMP2, ARMEmitter::XReg::x18, TEB_CPU_AREA_OFFSET);
  strb(ARMEmitter::WReg::zr, TMP2, CPU_AREA_IN_SYSCALL_CALLBACK_OFFSET);
#endif

  FillStaticRegs();
  PopDynamicRegs();
}

} // namespace FEXCore::CPU
