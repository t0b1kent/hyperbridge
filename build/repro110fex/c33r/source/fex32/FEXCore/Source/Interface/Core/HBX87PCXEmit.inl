// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// TRANS32 MACRUNNER_FEX32_X87_PC_EXACT (HBX87PCX.h): lowering of the X87PCX* ops. Included at the BEGINNING of
// Arm64JITCore::Op_Unhandled. Scratch only: TMP1..TMP4, VTMP1, VTMP2. NZCV is written only inside the compare, saved there.
// Destinations are written last: a destination may share a register with a source the slow path still needs.
// X87EXACT S32 (Interface/Core/HBX87S32.h): the typed binary32 forms, in line. Their cold parts are queued in S32ColdSites and
// emitted after the unit's last block (HBX87S32Cold.inl). Scratch: TMP1, TMP2, VTMP1; NZCV untouched. A destination that is also
// a source is written last and only on the fast path: the cold part still needs the sources.
if (IROp->Op == IR::OP_X87PCXLOADS || IROp->Op == IR::OP_X87PCXWIDENS || IROp->Op == IR::OP_X87PCXARITHS || IROp->Op == IR::OP_X87PCXSTORES) {
  namespace PCXK = FEXCore::HBX87::PCX;
  namespace S32K = FEXCore::HBX87::S32;
  using namespace ARMEmitter;
  if (IROp->Op == IR::OP_X87PCXWIDENS) {
    // +-0, a normal binary32 or a box (a quiet NaN): exact, raises nothing; the box becomes a container box (HBX87PCX.h Unbox).
    fcvt(GetVReg(Node).D(), GetVReg(IROp->C<IR::IROp_X87PCXWidenS>()->Src).S());
    return;
  }
  const unsigned Mut = S32K::Mutant();
  const bool SatMode = PCXK::SatEnabled() && (!X87PCXUnitFpsr || X87PCXUnitS);
  // A raising form (arithmetic) opens or continues a run of x87 forms as a stub call does (CallStub below). Per-run mode: the
  // run's first raising form records FPSR -- the S protocol (Dispatcher.cpp PCXFirstS) tested in line: nothing to do when the
  // guest status already has PE. Loads and stores raise nothing on their fast paths (like the in-line load of c33m).
  auto Run = [&]() {
    if (!X87PCXLRSaved) {
      X87PCXLRSaved = true;
      X87PCXRunRecorded = false;
    }
    X87PCXRunRaises = true;
    if (PCXK::FpsrFixEnabled() && !X87PCXRunRecorded && !X87PCXUnitFpsr) {
      auto& F = S32ColdSites.emplace_back();
      F.Kind = S32ColdSite::First;
      if (SatMode) {
        F.Sub = S32K::ColdFirstS;
        ldr(TMP1.W(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.mxcsr));
        tbz_OrRestart(TMP1, 5, &F.Enter);
      } else {
        F.Sub = S32K::ColdFirst;
        b_OrRestart(&F.Enter);
      }
      (void)Bind(&F.Back);
      X87PCXRunRecorded = true;
    }
  };
  if (IROp->Op == IR::OP_X87PCXLOADS) {
    const auto Op = IROp->C<IR::IROp_X87PCXLoadS>();
    const auto Src = GetVReg(Op->Src), Dst = GetVReg(Node);
    auto& C = S32ColdSites.emplace_back();
    C.Kind = S32ColdSite::Load;
    C.A = Src.Idx();
    C.Dst = Dst.Idx();
    if (Mut != 4) {
      fmov(Size::i32Bit, TMP1, Src.S());
      add(Size::i32Bit, TMP2, TMP1, 0x800, true); // exponent + 1 in bits 23..30
      ubfx(Size::i32Bit, TMP2, TMP2, 24, 7);      // != 0 <=> 1 <= exponent <= 254
      cbz_OrRestart(Size::i32Bit, TMP2, &C.Enter);
    }
    if (Dst.Idx() != Src.Idx()) {
      mov(Dst.Q(), Src.Q());
    }
    (void)Bind(&C.Back);
    return;
  }
  if (IROp->Op == IR::OP_X87PCXSTORES) {
    const auto Op = IROp->C<IR::IROp_X87PCXStoreS>();
    const auto Src = GetVReg(Op->Src), Dst = GetVReg(Node);
    // A typed store rounds nothing; a box takes the exact handler from the store stub (integer code).
    auto& C = S32ColdSites.emplace_back();
    C.Kind = S32ColdSite::Store;
    C.Sub = ((Op->Flags & PCXK::FC1) ? 1 : 0) | (SatMode ? 2 : 0);
    C.A = Src.Idx();
    C.Dst = Dst.Idx();
    if (Mut != 3) {
      fmov(Size::i32Bit, TMP1, Src.S());
      eor(Size::i32Bit, TMP2, TMP1, 0x7F800000);
      ubfx(Size::i32Bit, TMP2, TMP2, 23, 8); // == 0 <=> exponent 255: a box
      cbz_OrRestart(Size::i32Bit, TMP2, &C.Enter);
    }
    if (Op->Flags & PCXK::FC1) {
      strb(ARMEmitter::Reg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_C1_LOC); // exact
    }
    if (Dst.Idx() != Src.Idx()) {
      mov(Dst.Q(), Src.Q());
    }
    (void)Bind(&C.Back);
    return;
  }
  // X87PCXArithS
  const auto Op = IROp->C<IR::IROp_X87PCXArithS>();
  const uint32_t Kop = Op->Kind & PCXK::OpMask;
  const auto A = GetVReg(Op->Src1), B = GetVReg(Op->Src2), Dst = GetVReg(Node);
  Run();
  auto& C = S32ColdSites.emplace_back();
  C.Kind = S32ColdSite::Arith;
  C.Sub = Kop | ((Op->Kind & PCXK::KC1) ? 8 : 0) | (SatMode ? 16 : 0);
  C.A = A.Idx();
  C.B = B.Idx();
  C.Dst = Dst.Idx();
  // A form that keeps the "compute C1" duty -- the block's last C1 writer, or one whose C1 a following instruction with a memory
  // operand may show at a fault (MACRUNNER_FEX_X87_FAULT_COVER: most arithmetic of compiled code) -- computes C1 in line from
  // the binary64 value of the same operation (below; PROOF.md T19). Until s5 such a form always took the cold part.
  const bool C1Form = (Op->Kind & PCXK::KC1) != 0;
  const bool C1Inline = C1Form && Mut != 8;
  // The host result goes straight into the destination when that overwrites no source (the cold part recomputes from them).
  const auto R = (!C1Form && Dst.Idx() != A.Idx() && Dst.Idx() != B.Idx()) ? Dst : VTMP1;
  // An exact +-0 result (x - x, a +-0 factor, a +-0 dividend, sqrt(+0)) fails the range check below. Where a +-0 host result can
  // only be exact -- add / sub always under round to nearest; mul / div / sqrt when the operand checks of the S protocol exclude
  // underflow -- the cold part takes it as it is (HBX87S32Cold.inl EnterPost; PROOF.md T17) instead of calling the stub.
  if ((SatMode || Kop == PCXK::OpAdd || Kop == PCXK::OpSub) && Mut != 1) {
    C.Post = (R.Idx() == Dst.Idx() ? 2 : 1) | (C1Form ? 4 : 0); // 4: an exact +-0 was not rounded up -- C1 = 0
  }
  ARMEmitter::ForwardLabel Operate;
  if (SatMode && Mut != 5) {
    // No FPSR record covers this unit: make sure before the operation that the host can raise no status bit but IXC.
    if (Kop == PCXK::OpMul || Kop == PCXK::OpDiv) {
      // exponents e = field - 127: mul eA + eB in [-64, 63], div eA - eB in [-64, 63] and a nonzero divisor -- the result is a
      // normal binary32 of the typed range. A +-0 factor / dividend skips the range (field 0 is no exponent): the operation is
      // exact and raises nothing (result +-0, or the NaN of a box operand: cold part). A box operand that passes raises nothing.
      fmov(Size::i32Bit, TMP1, A.S());
      fmov(Size::i32Bit, TMP2, B.S());
      ubfx(Size::i32Bit, TMP1, TMP1, 23, 8);
      ubfx(Size::i32Bit, TMP2, TMP2, 23, 8);
      if (Kop == PCXK::OpMul) {
        (void)cbz(Size::i32Bit, TMP1, &Operate);
        (void)cbz(Size::i32Bit, TMP2, &Operate);
        add(Size::i32Bit, TMP1, TMP1, TMP2);
        sub(Size::i32Bit, TMP1, TMP1, 190);
      } else {
        cbz_OrRestart(Size::i32Bit, TMP2, &C.Enter);
        (void)cbz(Size::i32Bit, TMP1, &Operate);
        sub(Size::i32Bit, TMP1, TMP1, TMP2);
        add(Size::i32Bit, TMP1, TMP1, 64);
      }
      lsr(Size::i32Bit, TMP1, TMP1, 7);
      cbnz_OrRestart(Size::i32Bit, TMP1, &C.Enter);
    } else if (Kop == PCXK::OpSqrt) {
      fmov(Size::i32Bit, TMP1, A.S());
      tbnz_OrRestart(TMP1, 31, &C.Enter); // negative: invalid (and -0: the cold part)
    } else {
      // add / sub overflow only with an operand of 2^127 and above. Typed results and constants are below 2^125 (or a box: NaN,
      // raises nothing); a loaded value (CheckA / CheckB) may be anything.
      const auto Big = [&](VRegister V) {
        fmov(Size::i32Bit, TMP1, V.S());
        ubfx(Size::i32Bit, TMP1, TMP1, 23, 8);
        add(Size::i32Bit, TMP1, TMP1, 2);
        tbnz_OrRestart(TMP1, 8, &C.Enter); // exponent field 254 or 255
      };
      if (Op->Kind & PCXK::CheckA) {
        Big(A);
      }
      if (Op->Kind & PCXK::CheckB) {
        Big(B);
      }
    }
  }
  if (C1Inline && (Kop == PCXK::OpAdd || Kop == PCXK::OpSub) && Mut != 13) {
    // C1 of a sum from its binary64 value is right while the operands' exponents differ by less than 53 (PROOF.md T19): the
    // window here is [-32, 31]; a +-0 operand makes the sum exact. Anything else: the cold part (the container form).
    ARMEmitter::ForwardLabel GapOk;
    fmov(Size::i32Bit, TMP1, A.S());
    fmov(Size::i32Bit, TMP2, B.S());
    ubfx(Size::i32Bit, TMP1, TMP1, 23, 8);
    ubfx(Size::i32Bit, TMP2, TMP2, 23, 8);
    (void)cbz(Size::i32Bit, TMP1, &GapOk);
    (void)cbz(Size::i32Bit, TMP2, &GapOk);
    sub(Size::i32Bit, TMP1, TMP1, TMP2);
    add(Size::i32Bit, TMP1, TMP1, 32);
    lsr(Size::i32Bit, TMP1, TMP1, 6);
    cbnz_OrRestart(Size::i32Bit, TMP1, &C.Enter);
    (void)Bind(&GapOk);
  }
  (void)Bind(&Operate);
  if (C1Inline) {
    // d = the binary64 value of the operation (VTMP2): exact for a product; for a sum inside the window, a quotient and a root
    // it lies on the same side of the binary32 result as the exact value. Raises nothing but IXC.
    fcvt(VTMP1.D(), A.S());
    if (Kop != PCXK::OpSqrt) {
      fcvt(VTMP2.D(), B.S());
    }
    switch (Kop) {
    case PCXK::OpAdd: fadd(VTMP2.D(), VTMP1.D(), VTMP2.D()); break;
    case PCXK::OpSub: fsub(VTMP2.D(), VTMP1.D(), VTMP2.D()); break;
    case PCXK::OpMul: fmul(VTMP2.D(), VTMP1.D(), VTMP2.D()); break;
    case PCXK::OpDiv: fdiv(VTMP2.D(), VTMP1.D(), VTMP2.D()); break;
    default: fsqrt(VTMP2.D(), VTMP1.D()); break;
    }
  }
  switch (Kop) {
  case PCXK::OpAdd: fadd(R.S(), A.S(), B.S()); break;
  case PCXK::OpSub: fsub(R.S(), A.S(), B.S()); break;
  case PCXK::OpMul: fmul(R.S(), A.S(), B.S()); break;
  case PCXK::OpDiv: fdiv(R.S(), A.S(), B.S()); break;
  default: fsqrt(R.S(), A.S()); break;
  }
  if (Mut != 1) {
    // The x87 PC24 result is this binary32 when its exponent field is 4..251 (PROOF.md S32); anything else -- +-0, tiny, huge,
    // NaN from a box operand -- is the cold part's (TMP1 = the result's bits there).
    fmov(Size::i32Bit, TMP1, R.S());
    lsr(Size::i32Bit, TMP2, TMP1, 2);
    add(Size::i32Bit, TMP2, TMP2, 0x800, true); // exponent + 4 in bits 21..28
    ubfx(Size::i32Bit, TMP2, TMP2, 24, 5);      // != 0 <=> 4 <= exponent <= 251
    cbz_OrRestart(Size::i32Bit, TMP2, C.Post ? &C.EnterPost : &C.Enter);
  }
  if (S32K::PECheck() && Mut != 2) {
    cbz_OrRestart(Size::i32Bit, GetReg(Op->PE), &C.Enter); // FSW.PE = 0: the container form sets it from the exact error term
  }
  if (R.Idx() != Dst.Idx()) {
    mov(Dst.Q(), VTMP1.Q());
  }
  if (C1Inline) {
    // C1 = rounded up: the binary32 result (still in VTMP1) is larger in magnitude than d.
    fcvt(VTMP1.D(), VTMP1.S());
    if (Mut == 12) {
      facgt(ScalarRegSize::i64Bit, VTMP1, VTMP2, VTMP1);
    } else {
      facgt(ScalarRegSize::i64Bit, VTMP1, VTMP1, VTMP2);
    }
    fmov(Size::i64Bit, TMP1, VTMP1.D());
    lsr(Size::i64Bit, TMP1, TMP1, 63);
    strb(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_C1_LOC);
  }
  (void)Bind(&C.Back);
  return;
}
if (IROp->Op == IR::OP_X87PCXARITH || IROp->Op == IR::OP_X87PCXLOAD || IROp->Op == IR::OP_X87PCXFROM80 ||
    IROp->Op == IR::OP_X87PCXTO80 || IROp->Op == IR::OP_X87PCXSTORE || IROp->Op == IR::OP_X87PCXCMP ||
    IROp->Op == IR::OP_X87PCXDEOPT || IROp->Op == IR::OP_X87PCXGUARD) {
  namespace PCXK = FEXCore::HBX87::PCX;
  using namespace ARMEmitter;
  const uint32_t C1Off = offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_C1_LOC;
  const uint32_t PEOff = offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_PE_LOC;
  constexpr uint64_t AbsMask = 0x7FFFFFFFFFFFFFFFULL;
  // Slow path: the shared dispatcher stub of this handler (Pointers.X87PCXSlow) loads ABIHandler/Func and tail-jumps.
  auto Call = [&](FEXCore::Core::FallbackHandlerIndex Index) {
    ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSlow[0]) +
                       8 * (static_cast<uint32_t>(Index) - static_cast<uint32_t>(FEXCore::Core::OPINDEX_X87PCX_ADD)));
    str<IndexType::PRE>(XReg::lr, Reg::rsp, -16);
    blr(TMP1);
    ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
  };
  // Branch to Fail unless Lo <= Field <= Hi (unsigned field, Lo <= 4095, Hi <= 65535). No NZCV.
  auto RangeOrFail = [&](ARMEmitter::Register Field, uint32_t Lo, uint32_t Hi, ARMEmitter::Register T1, ARMEmitter::Register T2,
                         ForwardLabel* Fail) {
    sub(Size::i64Bit, T1, Field, Lo);
    movz(Size::i64Bit, T2, Hi);
    sub(Size::i64Bit, T2, T2, Field);
    orr(Size::i64Bit, T1, T1, T2);
    (void)tbnz(T1, 63, Fail);
  };
  // C1 = (Err != +-0) && (sign(Err) != sign(Ref)), or == with Same. T1 may alias Ref. No NZCV.
  auto StoreC1FromErr = [&](ARMEmitter::Register Err, ARMEmitter::Register Ref, bool Same, ARMEmitter::Register T1,
                            ARMEmitter::Register T2) {
    eor(Size::i64Bit, T1, Err, Ref);
    lsr(Size::i64Bit, T1, T1, 63);
    if (Same) {
      eor(Size::i64Bit, T1, T1, 1);
    }
    lsl(Size::i64Bit, T2, Err, 1);
    clz(Size::i64Bit, T2, T2);
    lsr(Size::i64Bit, T2, T2, 6);
    bic(Size::i64Bit, T1, T1, T2);
    strb(T1, STATE, C1Off);
  };
  // PETrack units: FSW.PE |= (Err != +-0). Err survives; T clobbered. No NZCV.
  auto StorePEIfInexact = [&](ARMEmitter::Register Err, ARMEmitter::Register T) {
    ForwardLabel Exact;
    lsl(Size::i64Bit, T, Err, 1);
    (void)cbz(Size::i64Bit, T, &Exact);
    movz(Size::i64Bit, T, 1);
    strb(T, STATE, PEOff);
    (void)Bind(&Exact);
  };

  // Every form is a call into its dispatcher stub (Dispatcher/HBX87PCXStubs.inl): operands in VTMP1 / VTMP2, result in VTMP1
  // (TMP1 for compares). The site is as long as the exact path's helper call.
  // lr is parked once per run of stub calls (Pointers.X87PCXSavedLR, not the stack: spill slots stay where RA put them);
  // CompileCode restores it before the first op of the block that is not a PCX op or plain state / integer bookkeeping.
  // Per-run units call the S variants of the raising stubs (HBX87PCX.h SatEnabled).
  const bool SatMode = PCXK::SatEnabled() && (!X87PCXUnitFpsr || X87PCXUnitS);
  // X87EXACT DYN: DynBack = bytes of the word check in front of the stub (HBX87PCX.h DynCheckArith / DynCheckStore) for a site of a
  // unit whose guard does not guarantee the word; the first-call entries run into the check by themselves.
  auto CallStub = [&](uint32_t PointerOffset, bool Raises = false, uint32_t DynBack = 0) {
    // The first call of a run enters the stub's FPSR-recording entry (Pointers.X87PCXFirst, same order as Convert .. Check).
    constexpr uint32_t FirstBegin = offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXConvert[0]);
    constexpr uint32_t FirstDelta = offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXFirst[0]) - FirstBegin;
    static_assert(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXCheck[7]) - FirstBegin == 277 * 8, "first-entry table order");
    constexpr uint32_t SBegin = offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXArithS[0]);
    constexpr uint32_t FirstSDelta = offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXFirstS[0]) - SBegin;
    static_assert(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXStoreS[0]) - SBegin == 256 * 8, "S table order");
    static_assert(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXFirstS[271]) < 32760, "ldr immediate range");
    constexpr uint32_t GuardSDelta = offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXFirstS[264]) -
                                     offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXCheck[0]);
    uint32_t Offset = PointerOffset;
    if (!X87PCXLRSaved) {
      if (PCXK::KeepLR()) str(XReg::lr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedLR));
      X87PCXLRSaved = true;
      X87PCXRunRecorded = false;
    }
    // Unit mode: the entry block's guard records once for the unit. Per-run mode: the run's first raising stub records (load,
    // compare, convert and check stubs leave the host status alone; a run without a raising stub has no end check to clear a
    // record, so it must not make one); with SatEnabled that stub is an S stub and records only when the guest PE is clear.
    if (PCXK::FpsrFixEnabled() && !X87PCXRunRecorded &&
        (X87PCXUnitFpsr ? (IROp->Op == IR::OP_X87PCXGUARD && X87PCXBlockIsEntry) : Raises)) {
      Offset += (Raises && SatMode) ? FirstSDelta : (X87PCXUnitS && IROp->Op == IR::OP_X87PCXGUARD) ? GuardSDelta : FirstDelta;
      X87PCXRunRecorded = true;
    }
    ldr(TMP1, STATE, Offset);
    if (DynBack && Offset == PointerOffset) {
      sub(Size::i64Bit, TMP1, TMP1, DynBack);
    }
    blr(TMP1);
  };
  if (IROp->Op == IR::OP_X87PCXGUARD) {
    // The stub returns only when the state is as compiled. On a mismatch it drops the saved lr and the unit's spill area
    // (TMP2, check variants 4..7) and leaves through the dispatcher; the guest RIP of this block comes from the host PC
    // (the next RIP entry after the call), the unit from the block header (ThreadRemoveCodeEntryFromJit, DeoptHostPCTag).
    const auto Op = IROp->C<IR::IROp_X87PCXGuard>();
    if (Op->Mode & 0x20) { // TRANS32 0030 known-mode marker: no code (JIT.cpp pre-scan reads it)
      return;
    }
    if (Op->Mode & 0x40) { // TRANS32 GUARD_SKIP call-info marker: no code, the next call carries it
      MRCallInfo = (1ULL << 31) | (Op->Mode & 3) | (uint64_t(Op->Shape & 0x1FF) << 8);
      return;
    }
    const uint64_t SpillBytes = MRGuardNoSpill ? 0 : uint64_t {SpillSlots} * MaxSpillSlotSize;
    const bool ShapeOnly = Op->Mode & 0x80; // SHAPE v6: a shape test without the entry check
    if (ShapeOnly && !(Op->Shape & 0x100)) {
      return;
    }
    if (!ShapeOnly) {
      if (SpillBytes) {
        LoadConstant(Size::i64Bit, TMP2, SpillBytes);
      }
      // X87EXACT DYN: the check stub is chosen by the precision field (Mode bits 3..4), see Dispatcher/HBX87PCXStubs.inl.
      CallStub(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXCheck[0]) +
               8 * ((PCXK::DynEnabled() ? ((Op->Mode >> 3) & 3) : (Op->Mode & 3)) | (SpillBytes ? 4 : 0)));
    }
    if (Op->Shape & 0x100) {
      // SHAPE: valid ST(i) = (FTW rotated right by TOP) bit i must equal the compiled pattern; after the entry check (lr parked).
      // TMP1 / TMP3 (TMP2 = spill bytes on a failure), no NZCV.
      static_assert(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXShapeFail[1]) < 32760, "ldr immediate range");
      ForwardLabel ShapeOk;
      ldrb(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.AbridgedFTW));
      ldrb(TMP3, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_TOP_LOC);
      orr(Size::i32Bit, TMP1, TMP1, TMP1, ShiftType::LSL, 8);
      lsrv(Size::i32Bit, TMP1, TMP1, TMP3);
      const uint32_t Expected = Op->Shape & 0xFF;
      if (Expected && (Expected & (Expected + 1)) == 0) {
        eor(Size::i32Bit, TMP1, TMP1, Expected); // 2^k - 1: a logical immediate
      } else if (Expected) {
        movz(Size::i32Bit, TMP3, Expected);
        eor(Size::i32Bit, TMP1, TMP1, TMP3);
      }
      lsl(Size::i32Bit, TMP1, TMP1, 24); // the low 8 bits only
      (void)cbz(Size::i32Bit, TMP1, &ShapeOk);
      if (SpillBytes) {
        LoadConstant(Size::i64Bit, TMP2, SpillBytes);
      }
      if (ShapeOnly && PCXK::KeepLR()) {
        str(XReg::lr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedLR)); // no check stub parked it
      }
      ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXShapeFail[0]) + (SpillBytes ? 8 : 0));
      blr(TMP1);
      if (PCXK::DeoptExactRip()) { // RP6q: the stub never returns; the word is its return address, read by ThreadRemoveCodeEntryFromJit
        dc32(Op->ExitOffset < PCXK::DeoptRipNone ? Op->ExitOffset : PCXK::DeoptRipNone);
      }
      (void)Bind(&ShapeOk);
    }
    return;
  }
  if (IROp->Op == IR::OP_X87PCXARITH) {
    const auto Op = IROp->C<IR::IROp_X87PCXArith>();
    const auto A = GetVReg(Op->Src1), B = GetVReg(Op->Src2), Dst = GetVReg(Node);
    X87PCXRunRaises = true;
    mov(VTMP1.Q(), A.Q());
    if ((Op->Kind & PCXK::OpMask) != PCXK::OpSqrt) {
      mov(VTMP2.Q(), B.Q());
    }
    CallStub(SatMode ? offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXArithS[0]) + 8 * Op->Kind :
                       offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXArith[0]) + 8 * Op->Kind,
             true, X87PCXDynChecked ? PCXK::DynCheckArith : 0);
    mov(Dst.Q(), VTMP1.Q());
    return;
  }
  if (IROp->Op == IR::OP_X87PCXLOAD && PCXK::InlineLoadEnabled()) {
    // Normal values convert in line (fcvt / the bits themselves, raising nothing); +-0 too (InlineLoadZero). Denormal, infinity, NaN
    // (and +-0 without InlineLoadZero): 2 instructions into the thunk of this destination (Pointers.X87PCXLoadTo, raw bits in TMP1),
    // which runs the load stub. No NZCV, no host status, the destination written last.
    const auto Op = IROp->C<IR::IROp_X87PCXLoad>();
    const auto Src = GetVReg(Op->Src), Dst = GetVReg(Node);
    const bool D = Op->SrcSize == IR::OpSize::i64Bit;
    ForwardLabel Fast, Done;
    if (D) {
      fmov(Size::i64Bit, TMP1, Src.D());
      lsr(Size::i64Bit, TMP2, TMP1, 52);         // sign:exponent
      add(Size::i32Bit, TMP2, TMP2, 1);
      and_(Size::i32Bit, TMP2, TMP2, 0x7FE);     // != 0 <=> 1 <= exponent <= 2046
    } else {
      fmov(Size::i32Bit, TMP1, Src.S());
      add(Size::i32Bit, TMP2, TMP1, 0x800, true); // exponent + 1 in bits 23..30
      and_(Size::i32Bit, TMP2, TMP2, 0x7F000000); // != 0 <=> 1 <= exponent <= 254
    }
    (void)cbnz(Size::i32Bit, TMP2, &Fast);
    if (PCXK::InlineLoadZero()) {
      lsl(D ? Size::i64Bit : Size::i32Bit, TMP2, TMP1, 1);
      (void)cbz(D ? Size::i64Bit : Size::i32Bit, TMP2, &Fast);
    }
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXLoadTo[0]) + 8 * ((D ? 32 : 0) + Dst.Idx()));
    blr(TMP2);
    if (!D || Dst.Idx() != Src.Idx()) {
      (void)b(&Done);
    }
    (void)Bind(&Fast);
    if (D) {
      if (Dst.Idx() != Src.Idx()) {
        mov(Dst.Q(), Src.Q());
      }
    } else {
      fcvt(Dst.D(), Src.S());
    }
    (void)Bind(&Done);
    static_assert(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXLoadTo[63]) < 32760, "ldr immediate range");
    return;
  }
  if (IROp->Op == IR::OP_X87PCXLOAD) {
    const auto Op = IROp->C<IR::IROp_X87PCXLoad>();
    const auto Src = GetVReg(Op->Src), Dst = GetVReg(Node);
    mov(VTMP1.Q(), Src.Q());
    CallStub(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXLoad[0]) + (Op->SrcSize == IR::OpSize::i64Bit ? 8 : 0));
    mov(Dst.Q(), VTMP1.Q());
    return;
  }

  // From80 / To80: the conversion lives once in the dispatcher (Pointers.X87PCXConvert[0/1], Dispatcher.cpp); in and out
  // in VTMP1, TMP1..TMP4 clobbered, slow cases tail-jump from there into the exact handler.
  if (IROp->Op == IR::OP_X87PCXFROM80 || IROp->Op == IR::OP_X87PCXTO80) {
    const bool To = IROp->Op == IR::OP_X87PCXTO80;
    const auto Src = GetVReg(To ? IROp->C<IR::IROp_X87PCXTo80>()->Src : IROp->C<IR::IROp_X87PCXFrom80>()->X80Src);
    const auto Dst = GetVReg(Node);
    mov(VTMP1.Q(), Src.Q());
    CallStub(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXConvert[0]) + (To ? 8 : 0));
    mov(Dst.Q(), VTMP1.Q());
    return;
  }

  if (IROp->Op == IR::OP_X87PCXSTORE) {
    const auto Op = IROp->C<IR::IROp_X87PCXStore>();
    const uint32_t Index = (Op->DstSize == IR::OpSize::i64Bit ? 1 : 0) | ((Op->Flags & PCXK::FC1) ? 2 : 0) | ((Op->Flags & PCXK::FPE) ? 4 : 0);
    if (Op->DstSize != IR::OpSize::i64Bit) X87PCXRunRaises = true; // fst m32 rounds on the host (fst m64 of a container is exact)
    const auto Src = GetVReg(Op->Src), Dst = GetVReg(Node);
    mov(VTMP1.Q(), Src.Q());
    const bool StoreRaises = Op->DstSize != IR::OpSize::i64Bit;
    CallStub((SatMode && StoreRaises) ? offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXStoreS[0]) + 8 * Index :
                                        offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXStore[0]) + 8 * Index,
             StoreRaises, (X87PCXDynChecked && StoreRaises) ? PCXK::DynCheckStore : 0);
    mov(Dst.Q(), VTMP1.Q());
    return;
  }
  if (IROp->Op == IR::OP_X87PCXCMP) {
    const auto Op = IROp->C<IR::IROp_X87PCXCmp>();
    const auto A = GetVReg(Op->Src1), B = GetVReg(Op->Src2);
    const auto Dst = GetReg(Node);
    mov(VTMP1.Q(), A.Q());
    mov(VTMP2.Q(), B.Q());
    CallStub(offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXCmp[0]) + (Op->Quiet ? 8 : 0));
    mov(Size::i64Bit, Dst.X(), TMP1);
    return;
  }

  // X87PCXDeopt: the entry RIP tagged so that the handler counts it and invalidates precisely; the body is the shared
  // dispatcher handler (Dispatcher.cpp, Pointers.X87PCXDeoptHandler), here only the argument and the call.
  LoadConstant(ARMEmitter::Size::i64Bit, TMP1, Entry | PCXK::DeoptTag, CPU::Arm64Emitter::PadType::AUTOPAD);
  ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXDeoptHandler));
  str<IndexType::PRE>(XReg::lr, Reg::rsp, -16);
  blr(TMP2);
  ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
  return;
}
