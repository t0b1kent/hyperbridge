// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// TRANS32 MACRUNNER_FEX32_X87_PC_EXACT (HBX87PCX.h): the x87 container forms, generated once per dispatcher. Included in
// Dispatcher::EmitDispatcher. A JIT site moves its operands into VTMP1 / VTMP2, calls the stub with blr (lr saved by the site)
// and takes the result from VTMP1 (TMP1 for compares). Stubs clobber only TMP1..TMP4 and VTMP1 / VTMP2; the forms that need
// more (C1 / PE error terms) save two vector registers on the stack. NZCV is written only inside the compare, saved there.
// Slow cases restore the operands and tail-jump into the exact handler, which returns to the JIT site.
{
  namespace PCXK = FEXCore::HBX87::PCX;
  using namespace ARMEmitter;
  const uint32_t C1Off = offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_C1_LOC;
  const uint32_t PEOff = offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_PE_LOC;
  constexpr uint64_t AbsMask = 0x7FFFFFFFFFFFFFFFULL;
  const VRegister X(VTMP1.Idx() + 2), Y(VTMP1.Idx() + 3);
  // X87EXACT DYN (HBX87PCX.h DynEnabled): the word-dependent stubs have a word check in front of their address and read FSW.PE
  // (where the exact path publishes it) at it.
  const bool Dyn = PCXK::DynEnabled();
  const bool DynPE = Dyn && FEXCore::HBX87::StateFix::ExceptionFlags() && !FEXCore::HBX87::StateFix::StaticRegs32();
  const uint32_t DynWordOff = offsetof(FEXCore::Core::CpuStateFrame, State.AbridgedFTW) + 4;
  auto Tail = [&](uint32_t Index) {
    ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers[0].ABIHandler) +
                       Index * sizeof(FEXCore::Core::FallbackABIInfo));
    ldr(TMP4, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers[0].Func) +
                       Index * sizeof(FEXCore::Core::FallbackABIInfo));
    br(TMP1);
  };
  // C1 = (Err != +-0) && (sign(Err) != sign(Ref)), or == with Same. T1 may alias Ref.
  auto StoreC1 = [&](Register Err, Register Ref, bool Same, Register T1, Register T2) {
    eor(Size::i64Bit, T1, Err, Ref);
    lsr(Size::i64Bit, T1, T1, 63);
    if (Same) eor(Size::i64Bit, T1, T1, 1);
    lsl(Size::i64Bit, T2, Err, 1);
    clz(Size::i64Bit, T2, T2);
    lsr(Size::i64Bit, T2, T2, 6);
    bic(Size::i64Bit, T1, T1, T2);
    strb(T1, STATE, C1Off);
  };
  auto StorePE = [&](Register Err, Register T) {
    ForwardLabel Exact;
    lsl(Size::i64Bit, T, Err, 1);
    (void)cbz(Size::i64Bit, T, &Exact);
    movz(Size::i64Bit, T, 1);
    strb(T, STATE, PEOff);
    (void)Bind(&Exact);
  };

  // S variants (per-run units, HBX87PCX.h SatEnabled): before the host operation, make sure it can raise no status bit but IXC --
  // no overflow, no tiny result, no division by zero, no invalid operation, and for PC24 the same for the fcvt to binary32 --
  // otherwise take the exact handler without a host operation. Containers are +-0 or normal binary64 (a box has exponent 2047
  // and fails the range). Bounds for a nonzero x with exponent field e: 2^(e-1023) <= |x| < 2^(e-1022); allowed results
  // 2^-1022 <= |r| < 2^1023 (PC53) or 2^-126 <= |r| < 2^127 (PC24). add/sub: |r| < 2^(max e - 1021), r = 0 or |r| >= 2^(min e - 1075)
  // -> e in [53, 2044] / [949, 1148]; mul: s = eA + eB in [1024, 3067] / [1920, 2171]; div: B != 0, d = eA - eB in [-1021, 1022] /
  // [-125, 126]; sqrt: A >= 0, PC24 e in [771, 1276]. A zero operand gives an exact result (0 / B, A * 0, A + 0).
  auto SatExp = [&](VRegister V, Register Raw, Register E, ForwardLabel* IfZero) {
    fmov(Size::i64Bit, Raw, V.D());
    lsl(Size::i64Bit, E, Raw, 1);
    (void)cbz(Size::i64Bit, E, IfZero);
    ubfx(Size::i64Bit, E, Raw, 52, 11);
  };
  auto SatRange = [&](Register E, Register T, int32_t Lo, int32_t Hi, ForwardLabel* Fail) { // fail unless Lo <= E <= Hi
    if (Lo >= 0) sub(Size::i64Bit, T, E, Lo);
    else add(Size::i64Bit, T, E, -Lo);
    (void)tbnz(T, 63, Fail);
    if (Hi + 1 >= 0) sub(Size::i64Bit, T, E, Hi + 1);
    else add(Size::i64Bit, T, E, -(Hi + 1));
    (void)tbz(T, 63, Fail);
  };
  auto SatChecks = [&](uint32_t Kop, bool P24, ForwardLabel* Fail) { // A = VTMP1, B = VTMP2; clobbers TMP1..TMP3
    ForwardLabel Ok;
    switch (Kop) {
    case PCXK::OpAdd:
    case PCXK::OpSub: {
      ForwardLabel AZero;
      SatExp(VTMP1, TMP1, TMP2, &AZero);
      SatRange(TMP2, TMP1, P24 ? 949 : 53, P24 ? 1148 : 2044, Fail);
      (void)Bind(&AZero);
      SatExp(VTMP2, TMP1, TMP2, &Ok);
      SatRange(TMP2, TMP1, P24 ? 949 : 53, P24 ? 1148 : 2044, Fail);
      break;
    }
    case PCXK::OpMul:
      SatExp(VTMP1, TMP1, TMP2, &Ok);
      SatExp(VTMP2, TMP1, TMP3, &Ok);
      add(Size::i64Bit, TMP2, TMP2, TMP3);
      SatRange(TMP2, TMP1, P24 ? 1920 : 1024, P24 ? 2171 : 3067, Fail);
      break;
    case PCXK::OpDiv:
      SatExp(VTMP2, TMP1, TMP3, Fail); // B = +-0: division by zero or invalid
      SatExp(VTMP1, TMP1, TMP2, &Ok);
      sub(Size::i64Bit, TMP2, TMP2, TMP3);
      SatRange(TMP2, TMP1, P24 ? -125 : -1021, P24 ? 126 : 1022, Fail);
      break;
    default:
      SatExp(VTMP1, TMP1, TMP2, &Ok);
      (void)tbnz(TMP1, 63, Fail); // negative: invalid
      if (P24) SatRange(TMP2, TMP1, 771, 1276, Fail);
      break;
    }
    (void)Bind(&Ok);
  };

  // ---- X87EXACT DYN (HBX87PCX.h DynEnabled), control word 0x033F (PC64, RN, all masked; MXCSR RN, FZ = 0): the binary64 result
  // when the host operation is exact -- then it is the 64-bit result as well, PE untouched, C1 = 0 (PROOF.md T2) -- otherwise the
  // exact handler. Entered by a branch from an arithmetic stub (operands in VTMP1 / VTMP2, TMP1..TMP4 free). [SV][Kop][C1]
  BackwardLabel DynPC64[2][5][2];
  if (Dyn) {
    for (uint32_t SV = 0; SV < 2; ++SV) {
      if (SV && !PCXK::SatEnabled()) break;
      for (uint32_t Kop = 0; Kop <= PCXK::OpSqrt; ++Kop) {
        for (uint32_t C1 = 0; C1 < 2; ++C1) {
          (void)Bind(&DynPC64[SV][Kop][C1]);
          ForwardLabel Slow, SlowRestore;
          if (SV) SatChecks(Kop, false, &Slow);
          if (Kop == PCXK::OpDiv || Kop == PCXK::OpSqrt) {
            fmov(Size::i64Bit, TMP1, VTMP1.D()); // exact remainder needs |A| >= 2^-863
            ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
            sub(Size::i64Bit, TMP2, TMP2, 160);
            (void)tbnz(TMP2, 63, &Slow);
          }
          stp<IndexType::PRE>(X.Q(), Y.Q(), Reg::rsp, -32);
          switch (Kop) {
          case PCXK::OpAdd: fadd(X.D(), VTMP1.D(), VTMP2.D()); break;
          case PCXK::OpSub: fsub(X.D(), VTMP1.D(), VTMP2.D()); break;
          case PCXK::OpMul: fmul(X.D(), VTMP1.D(), VTMP2.D()); break;
          case PCXK::OpDiv: fdiv(X.D(), VTMP1.D(), VTMP2.D()); break;
          default: fsqrt(X.D(), VTMP1.D()); break;
          }
          fmov(Size::i64Bit, TMP1, X.D());
          ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
          sub(Size::i64Bit, TMP2, TMP2, 108); // exponent field in [108, 2046]: a container, and the error terms below are exact
          (void)tbnz(TMP2, 63, &SlowRestore);
          add(Size::i64Bit, TMP2, TMP2, 109);
          (void)tbnz(TMP2, 11, &SlowRestore);
          switch (Kop) { // Y = the exact error term of X (the same terms as Error53 below)
          case PCXK::OpMul: fnmsub(Y.D(), VTMP1.D(), VTMP2.D(), X.D()); break;
          case PCXK::OpDiv: fmsub(Y.D(), X.D(), VTMP2.D(), VTMP1.D()); break;
          case PCXK::OpSqrt: fmsub(Y.D(), X.D(), X.D(), VTMP1.D()); break;
          default: {
            ForwardLabel BBig, End;
            fmov(Size::i64Bit, TMP2, VTMP1.D());
            fmov(Size::i64Bit, TMP3, VTMP2.D());
            and_(Size::i64Bit, TMP2, TMP2, AbsMask);
            and_(Size::i64Bit, TMP3, TMP3, AbsMask);
            sub(Size::i64Bit, TMP2, TMP2, TMP3);
            (void)tbnz(TMP2, 63, &BBig);
            fsub(Y.D(), X.D(), VTMP1.D()); // z = r - A
            if (Kop == PCXK::OpAdd) fsub(Y.D(), VTMP2.D(), Y.D()); // err = B - z
            else fadd(Y.D(), VTMP2.D(), Y.D());                     // -err = B + z
            (void)b(&End);
            (void)Bind(&BBig);
            if (Kop == PCXK::OpAdd) fsub(Y.D(), X.D(), VTMP2.D()); // z = r - B
            else fadd(Y.D(), X.D(), VTMP2.D());                     // z = r + B (first operand -B)
            fsub(Y.D(), VTMP1.D(), Y.D());                          // err = A - z
            (void)Bind(&End);
            break;
          }
          }
          fmov(Size::i64Bit, TMP2, Y.D());
          lsl(Size::i64Bit, TMP2, TMP2, 1);
          (void)cbnz(Size::i64Bit, TMP2, &SlowRestore); // inexact in binary64: the 64-bit result differs
          if (C1) strb(Reg::zr, STATE, C1Off);
          mov(VTMP1.Q(), X.Q());
          ldp<IndexType::POST>(X.Q(), Y.Q(), Reg::rsp, 32);
          ret();
          (void)Bind(&SlowRestore);
          {
            // Exact +-0 (PROOF.md T5), TMP1 = the host result's bits: add / sub: any +-0 host result; mul: a +-0 operand; div: a +-0
            // dividend (never reached: the dividend check above); sqrt: only of +-0 (the same). A box operand gives a NaN, not +-0.
            ForwardLabel NotZero;
            lsl(Size::i64Bit, TMP2, TMP1, 1);
            (void)cbnz(Size::i64Bit, TMP2, &NotZero);
            if (Kop == PCXK::OpMul || Kop == PCXK::OpDiv) {
              fmov(Size::i64Bit, TMP2, VTMP1.D());
              lsl(Size::i64Bit, TMP2, TMP2, 1);
              if (Kop == PCXK::OpMul) {
                ForwardLabel ZeroOperand;
                (void)cbz(Size::i64Bit, TMP2, &ZeroOperand);
                fmov(Size::i64Bit, TMP2, VTMP2.D());
                lsl(Size::i64Bit, TMP2, TMP2, 1);
                (void)cbnz(Size::i64Bit, TMP2, &NotZero); // +-0 from two nonzero operands: underflow
                (void)Bind(&ZeroOperand);
              } else {
                (void)cbnz(Size::i64Bit, TMP2, &NotZero);
              }
            }
            if (C1) strb(Reg::zr, STATE, C1Off);
            mov(VTMP1.Q(), X.Q());
            ldp<IndexType::POST>(X.Q(), Y.Q(), Reg::rsp, 32);
            ret();
            (void)Bind(&NotZero);
          }
          ldp<IndexType::POST>(X.Q(), Y.Q(), Reg::rsp, 32);
          (void)Bind(&Slow);
          Tail(FEXCore::Core::OPINDEX_X87PCX_ADD + Kop);
        }
      }
    }
  }

  // ---- arithmetic: one stub per Kind byte the stack pass can produce (SV = 1: the S variant) ----
  const bool ZeroFast = PCXK::ZeroFastEnabled(); // TRANS32 0032: exact +-0 results leave from SlowRestore (HBX87PCX.h)
  for (uint32_t SV = 0; SV < 2; ++SV) {
  if (SV && !PCXK::SatEnabled()) break;
  for (uint32_t K = 0; K < 256; ++K) {
    const uint32_t Kop = K & PCXK::OpMask;
    const bool P24 = K & PCXK::K24, C1 = K & PCXK::KC1, CA = K & PCXK::CheckA, CB = K & PCXK::CheckB, PE = K & PCXK::KPE;
    if (Kop > PCXK::OpSqrt || (!P24 && (CA || CB)) || (Kop == PCXK::OpSqrt && CB)) continue;
    ForwardLabel DynCold, DynColdPE;
    if (SV) {
      PCXFirstS(K);
    } else {
      PCXFirst(2 + K);
    }
    if (Dyn) {
      // The word check, DynCheckArith bytes in front of the stub's address: the word this form is exact for, else the cold part after
      // the stub. Run by the sites of units whose guard does not guarantee the word (they enter here) and by first-call entries.
      ldrh(TMP1, STATE, DynWordOff);
      sub(Size::i64Bit, TMP1, TMP1, P24 ? 0x003F : 0x023F);
      (void)cbnz(Size::i64Bit, TMP1, &DynCold);
    }
    if (SV) {
      X87PCXArithSAddress[K] = GetCursorAddress<uint64_t>();
    } else {
      X87PCXArithAddress[K] = GetCursorAddress<uint64_t>();
    }
    if (DynPE && !PE) { // FSW.PE = 0: the PE-tracking sibling
      ldrb(TMP2, STATE, PEOff);
      (void)cbz(Size::i64Bit, TMP2, &DynColdPE);
    }
    const bool Wide = C1 || PE;
    const auto R = Wide ? X : VTMP1;
    ForwardLabel Slow, SlowRestore;
    if (SV) SatChecks(Kop, P24, &Slow);
    if (P24 && CA) {
      fmov(Size::i64Bit, TMP1, VTMP1.D());
      lsl(Size::i64Bit, TMP1, TMP1, 35);
      (void)cbnz(Size::i64Bit, TMP1, &Slow);
    }
    if (P24 && CB) {
      fmov(Size::i64Bit, TMP1, VTMP2.D());
      lsl(Size::i64Bit, TMP1, TMP1, 35);
      (void)cbnz(Size::i64Bit, TMP1, &Slow);
    }
    if (Wide && (Kop == PCXK::OpDiv || Kop == PCXK::OpSqrt)) {
      fmov(Size::i64Bit, TMP1, VTMP1.D()); // exact remainder needs |A| >= 2^-863
      ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
      sub(Size::i64Bit, TMP2, TMP2, 160);
      (void)tbnz(TMP2, 63, &Slow);
    }
    if (Wide) {
      stp<IndexType::PRE>(X.Q(), Y.Q(), Reg::rsp, -32);
    } else {
      fmov(Size::i64Bit, TMP3, VTMP1.D()); // operands for the slow restore
      fmov(Size::i64Bit, TMP4, VTMP2.D());
    }
    switch (Kop) {
    case PCXK::OpAdd: fadd(R.D(), VTMP1.D(), VTMP2.D()); break;
    case PCXK::OpSub: fsub(R.D(), VTMP1.D(), VTMP2.D()); break;
    case PCXK::OpMul: fmul(R.D(), VTMP1.D(), VTMP2.D()); break;
    case PCXK::OpDiv: fdiv(R.D(), VTMP1.D(), VTMP2.D()); break;
    default: fsqrt(R.D(), VTMP1.D()); break;
    }
    fmov(Size::i64Bit, TMP1, R.D()); // r53 bits
    // Exact error term of the binary64 result X (bits TMP1) with A = VTMP1, B = VTMP2; temp Y, TMP2..TMP4.
    auto Error53 = [&]() {
      switch (Kop) {
      case PCXK::OpMul:
        fnmsub(Y.D(), VTMP1.D(), VTMP2.D(), X.D());
        fmov(Size::i64Bit, TMP2, Y.D());
        if (PE) StorePE(TMP2, TMP3);
        if (C1) StoreC1(TMP2, TMP1, false, TMP3, TMP4);
        break;
      case PCXK::OpDiv:
        fmsub(Y.D(), X.D(), VTMP2.D(), VTMP1.D());
        fmov(Size::i64Bit, TMP2, Y.D());
        if (PE) StorePE(TMP2, TMP3);
        fmov(Size::i64Bit, TMP3, VTMP1.D());
        if (C1) StoreC1(TMP2, TMP3, false, TMP3, TMP4);
        break;
      case PCXK::OpSqrt:
        fmsub(Y.D(), X.D(), X.D(), VTMP1.D());
        fmov(Size::i64Bit, TMP2, Y.D());
        if (PE) StorePE(TMP2, TMP3);
        if (C1) StoreC1(TMP2, TMP1, false, TMP3, TMP4);
        break;
      default: {
        ForwardLabel BBig, End;
        fmov(Size::i64Bit, TMP2, VTMP1.D());
        fmov(Size::i64Bit, TMP3, VTMP2.D());
        and_(Size::i64Bit, TMP2, TMP2, AbsMask);
        and_(Size::i64Bit, TMP3, TMP3, AbsMask);
        sub(Size::i64Bit, TMP2, TMP2, TMP3);
        (void)tbnz(TMP2, 63, &BBig);
        fsub(Y.D(), X.D(), VTMP1.D()); // z = r - A
        if (Kop == PCXK::OpAdd) fsub(Y.D(), VTMP2.D(), Y.D()); // err = B - z
        else fadd(Y.D(), VTMP2.D(), Y.D());                     // -err = B + z
        fmov(Size::i64Bit, TMP2, Y.D());
        if (PE) StorePE(TMP2, TMP3);
        if (C1) StoreC1(TMP2, TMP1, Kop == PCXK::OpSub, TMP3, TMP4);
        (void)b(&End);
        (void)Bind(&BBig);
        if (Kop == PCXK::OpAdd) fsub(Y.D(), X.D(), VTMP2.D()); // z = r - B
        else fadd(Y.D(), X.D(), VTMP2.D());                     // z = r + B (first operand -B)
        fsub(Y.D(), VTMP1.D(), Y.D());                          // err = A - z
        fmov(Size::i64Bit, TMP2, Y.D());
        if (PE) StorePE(TMP2, TMP3);
        if (C1) StoreC1(TMP2, TMP1, false, TMP3, TMP4);
        (void)Bind(&End);
        break;
      }
      }
    };
    if (!P24) {
      ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
      sub(Size::i64Bit, TMP2, TMP2, 108); // exponent field in [108, 2046]
      (void)tbnz(TMP2, 63, &SlowRestore);
      add(Size::i64Bit, TMP2, TMP2, 109);
      (void)tbnz(TMP2, 11, &SlowRestore);
      if (Wide) Error53();
    } else {
      const auto S = Wide ? Y : VTMP2; // narrow forms: B is saved in TMP4
      fcvt(S.S(), R.D());
      fmov(Size::i32Bit, TMP2, S.S());
      ubfx(Size::i64Bit, TMP2, TMP2, 23, 8);
      sub(Size::i64Bit, TMP2, TMP2, 2); // float exponent field in [2, 254]
      (void)tbnz(TMP2, 63, &SlowRestore);
      add(Size::i64Bit, TMP2, TMP2, 3);
      (void)tbnz(TMP2, 8, &SlowRestore);
      if (!Wide) {
        fcvt(R.D(), S.S());
      } else {
        ForwardLabel Same53, Done24;
        fcvt(Y.D(), Y.S()); // r24
        fmov(Size::i64Bit, TMP2, Y.D());
        eor(Size::i64Bit, TMP3, TMP2, TMP1);
        (void)cbz(Size::i64Bit, TMP3, &Same53);
        if (PE) {
          movz(Size::i64Bit, TMP4, 1);
          strb(TMP4, STATE, PEOff);
        }
        if (C1) {
          and_(Size::i64Bit, TMP3, TMP2, AbsMask);
          and_(Size::i64Bit, TMP4, TMP1, AbsMask);
          sub(Size::i64Bit, TMP3, TMP4, TMP3); // |r53| - |r24| < 0 iff rounded up
          lsr(Size::i64Bit, TMP3, TMP3, 63);
          strb(TMP3, STATE, C1Off);
        }
        mov(X.Q(), Y.Q());
        (void)b(&Done24);
        (void)Bind(&Same53);
        Error53(); // r24 == r53: the binary64 error term decides
        (void)Bind(&Done24);
      }
    }
    if (Wide) {
      mov(VTMP1.Q(), X.Q());
      ldp<IndexType::POST>(X.Q(), Y.Q(), Reg::rsp, 32);
    }
    ret();
    (void)Bind(&SlowRestore);
    if (ZeroFast && Kop != PCXK::OpSqrt) {
      // 0032: TMP1 = the host result's bits (R); operands: VTMP1 / VTMP2 (Wide forms) or TMP3 / TMP4 (narrow forms).
      ForwardLabel NotZero;
      lsl(Size::i64Bit, TMP2, TMP1, 1);
      (void)cbnz(Size::i64Bit, TMP2, &NotZero);
      if (Kop == PCXK::OpMul || Kop == PCXK::OpDiv) {
        if (Wide) {
          fmov(Size::i64Bit, TMP2, VTMP1.D());
          lsl(Size::i64Bit, TMP2, TMP2, 1);
        } else {
          lsl(Size::i64Bit, TMP2, TMP3, 1);
        }
        if (Kop == PCXK::OpMul) {
          ForwardLabel ZeroOperand;
          (void)cbz(Size::i64Bit, TMP2, &ZeroOperand);
          if (Wide) {
            fmov(Size::i64Bit, TMP2, VTMP2.D());
            lsl(Size::i64Bit, TMP2, TMP2, 1);
          } else {
            lsl(Size::i64Bit, TMP2, TMP4, 1);
          }
          (void)cbnz(Size::i64Bit, TMP2, &NotZero); // +-0 from two nonzero operands: underflow
          (void)Bind(&ZeroOperand);
        } else {
          (void)cbnz(Size::i64Bit, TMP2, &NotZero); // div: only a +-0 dividend (a +-0 divisor gives a NaN, not +-0)
        }
      }
      if (Wide) {
        if (C1) strb(Reg::zr, STATE, C1Off); // exact: not rounded up; PE untouched
        mov(VTMP1.Q(), X.Q());
        ldp<IndexType::POST>(X.Q(), Y.Q(), Reg::rsp, 32);
      } // narrow forms: VTMP1 = R = +-0 already
      ret();
      (void)Bind(&NotZero);
    }
    if (Wide) {
      ldp<IndexType::POST>(X.Q(), Y.Q(), Reg::rsp, 32);
    } else {
      fmov(Size::i64Bit, VTMP1.D(), TMP3);
      fmov(Size::i64Bit, VTMP2.D(), TMP4);
    }
    (void)Bind(&Slow);
    Tail(FEXCore::Core::OPINDEX_X87PCX_ADD + Kop); // ADD SUB MUL DIV SQRT are consecutive
    if (Dyn) {
      // TMP1 = word - this form's word (nonzero). The other binary64 word: the sibling stub after its word check (to PC24 with both
      // operand checks, to PC53 without); 0x033F: the PC64 form; anything else: the exact handler. Operands still in VTMP1 / VTMP2.
      const uint32_t Table = SV ? offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXArithS[0]) :
                                  offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXArith[0]);
      const uint32_t Sibling = P24 ? (K & ~(PCXK::K24 | PCXK::CheckA | PCXK::CheckB)) :
                                     (K | PCXK::K24 | PCXK::CheckA | (Kop != PCXK::OpSqrt ? PCXK::CheckB : 0));
      ForwardLabel NotSibling, DynSlow;
      (void)Bind(&DynCold);
      if (P24) sub(Size::i64Bit, TMP2, TMP1, 0x200);
      else add(Size::i64Bit, TMP2, TMP1, 0x200);
      (void)cbnz(Size::i64Bit, TMP2, &NotSibling);
      ldr(TMP1, STATE, Table + 8 * Sibling);
      br(TMP1);
      (void)Bind(&NotSibling);
      sub(Size::i64Bit, TMP2, TMP1, P24 ? 0x300 : 0x100);
      (void)cbnz(Size::i64Bit, TMP2, &DynSlow);
      (void)b(&DynPC64[SV][Kop][C1 ? 1 : 0]);
      (void)Bind(&DynSlow);
      Tail(FEXCore::Core::OPINDEX_X87PCX_ADD + Kop);
      if (DynPE && !PE) {
        (void)Bind(&DynColdPE);
        ldr(TMP1, STATE, Table + 8 * (K | PCXK::KPE));
        br(TMP1);
      }
    }
  }
  }

  // ---- loads: m32 / m64 bits in VTMP1 -> container (exact path: inline conversion, no flag) ----
  BackwardLabel LoadBody[2];
  for (uint32_t D = 0; D < 2; ++D) {
    PCXFirst(258 + D);
    X87PCXLoadAddress[D] = GetCursorAddress<uint64_t>();
    (void)Bind(&LoadBody[D]);
    ForwardLabel Slow, Fast;
    if (D) {
      fmov(Size::i64Bit, TMP1, VTMP1.D());
      lsl(Size::i64Bit, TMP2, TMP1, 1);
      (void)cbz(Size::i64Bit, TMP2, &Fast);
      ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
      sub(Size::i64Bit, TMP2, TMP2, 1);
      (void)tbnz(TMP2, 63, &Slow);
      add(Size::i64Bit, TMP2, TMP2, 2);
      (void)tbnz(TMP2, 11, &Slow);
      (void)Bind(&Fast);
      ret();
    } else {
      fmov(Size::i32Bit, TMP1, VTMP1.S());
      lsl(Size::i32Bit, TMP2, TMP1, 1);
      (void)cbz(Size::i32Bit, TMP2, &Fast);
      ubfx(Size::i64Bit, TMP2, TMP1, 23, 8);
      sub(Size::i64Bit, TMP2, TMP2, 1);
      (void)tbnz(TMP2, 63, &Slow);
      add(Size::i64Bit, TMP2, TMP2, 2);
      (void)tbnz(TMP2, 8, &Slow);
      (void)Bind(&Fast);
      fcvt(VTMP1.D(), VTMP1.S());
      ret();
    }
    (void)Bind(&Slow);
    Tail(D ? FEXCore::Core::OPINDEX_X87PCX_LOAD8 : FEXCore::Core::OPINDEX_X87PCX_LOAD4);
  }
  // In-line loads (HBX87PCX.h InlineLoadEnabled): the slow case by destination register. Raw bits in TMP1; lr of the block on the
  // host stack around the stub (as the emitter's slow handler calls do); the stub may tail-jump into the exact handler.
  if (PCXK::InlineLoadEnabled()) {
    for (uint32_t D = 0; D < 2; ++D) {
      for (uint32_t N = 0; N < 32; ++N) {
        X87PCXLoadToAddress[D * 32 + N] = GetCursorAddress<uint64_t>();
        if (D) {
          fmov(Size::i64Bit, VTMP1.D(), TMP1);
        } else {
          fmov(Size::i32Bit, VTMP1.S(), TMP1);
        }
        str<IndexType::PRE>(XReg::lr, Reg::rsp, -16);
        (void)bl(&LoadBody[D]);
        ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
        mov(VRegister(N).Q(), VTMP1.Q());
        ret();
      }
    }
  }

  // ---- stores: container in VTMP1 -> m32 / m64 bits in VTMP1. Index = D | C1 << 1 | PE << 2 (SV = 1: S variant of fst m32,
  // value checked into 2^-126 <= |v| < 2^127 before the fcvt; fst m64 has no host operation and is the same stub) ----
  for (uint32_t SV = 0; SV < 2; ++SV) {
  if (SV && !PCXK::SatEnabled()) break;
  for (uint32_t I = 0; I < 8; ++I) {
    const bool D = I & 1, C1 = I & 2, PE = I & 4;
    if (SV && D) {
      X87PCXStoreSAddress[I] = X87PCXStoreAddress[I];
      X87PCXFirstSAddress[256 + I] = X87PCXFirstAddress[260 + I];
      continue;
    }
    ForwardLabel Slow, Zero, DynColdPE;
    if (SV) {
      PCXFirstS(256 + I);
    } else {
      PCXFirst(260 + I);
    }
    if (Dyn && !D) {
      // The word check, DynCheckStore bytes in front of the stub's address: fst m32 rounds by RC only (PROOF.md T7) -- fast for RN
      // with all exceptions masked and MXCSR RN / FZ = 0 under any PC.
      ldrh(TMP1, STATE, DynWordOff);
      and_(Size::i64Bit, TMP1, TMP1, ~0x300ULL);
      sub(Size::i64Bit, TMP1, TMP1, 0x3F);
      (void)cbnz(Size::i64Bit, TMP1, &Slow);
    }
    if (SV) {
      X87PCXStoreSAddress[I] = GetCursorAddress<uint64_t>();
    } else {
      X87PCXStoreAddress[I] = GetCursorAddress<uint64_t>();
    }
    if (DynPE && !D && !PE) { // FSW.PE = 0: the PE-tracking sibling
      ldrb(TMP2, STATE, PEOff);
      (void)cbz(Size::i64Bit, TMP2, &DynColdPE);
    }
    fmov(Size::i64Bit, TMP1, VTMP1.D());
    ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
    add(Size::i64Bit, TMP3, TMP2, 1);
    (void)tbnz(TMP3, 11, &Slow); // box
    if (D) {
      if (C1) strb(Reg::zr, STATE, C1Off); // the container is exactly the register value
      ret();
    } else {
      lsl(Size::i64Bit, TMP3, TMP1, 1);
      (void)cbz(Size::i64Bit, TMP3, &Zero);
      if (SV) SatRange(TMP2, TMP3, 897, 1149, &Slow);
      fcvt(VTMP2.S(), VTMP1.D());
      fmov(Size::i32Bit, TMP2, VTMP2.S());
      ubfx(Size::i64Bit, TMP3, TMP2, 23, 8);
      sub(Size::i64Bit, TMP3, TMP3, 2);
      (void)tbnz(TMP3, 63, &Slow);
      add(Size::i64Bit, TMP3, TMP3, 3);
      (void)tbnz(TMP3, 8, &Slow);
      if (C1 || PE) {
        fcvt(VTMP1.D(), VTMP2.S()); // the value bits stay in TMP1
        fmov(Size::i64Bit, TMP2, VTMP1.D());
        and_(Size::i64Bit, TMP2, TMP2, AbsMask);
        and_(Size::i64Bit, TMP3, TMP1, AbsMask);
        sub(Size::i64Bit, TMP3, TMP3, TMP2); // |v| - |stored|: < 0 iff rounded up, != 0 iff inexact
        if (PE) StorePE(TMP3, TMP2);
        if (C1) {
          lsr(Size::i64Bit, TMP3, TMP3, 63);
          strb(TMP3, STATE, C1Off);
        }
      }
      mov(VTMP1.Q(), VTMP2.Q());
      ret();
      (void)Bind(&Zero);
      fcvt(VTMP1.S(), VTMP1.D());
      if (C1) strb(Reg::zr, STATE, C1Off);
      ret();
    }
    (void)Bind(&Slow);
    Tail(D ? FEXCore::Core::OPINDEX_X87PCX_STORE8 : FEXCore::Core::OPINDEX_X87PCX_STORE4);
    if (DynPE && !D && !PE) {
      (void)Bind(&DynColdPE);
      ldr(TMP1, STATE, (SV ? offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXStoreS[0]) :
                             offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXStore[0])) + 8 * (I | 4));
      br(TMP1);
    }
  }
  }

  // ---- deopt from a host PC: TMP1 = host PC after the guard's call | DeoptHostPCTag. Entered from a check stub with lr
  // restored and the stack as at the unit's entry (spill area dropped); C++ sets State.rip; leaves through the dispatcher. ----
  BackwardLabel DeoptFromPC;
  (void)Bind(&DeoptFromPC);
  PushDynamicRegs(TMP4);
  SpillStaticRegs(TMP4);
  mov(Size::i64Bit, Reg::r1, TMP1);
  mov(Size::i64Bit, Reg::r0, STATE.R());
  ldr(XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.ThreadRemoveCodeEntryFromJIT));
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<void, void*, void*>(Reg::r2);
  } else {
    blr(Reg::r2);
  }
  FillStaticRegs();
  PopDynamicRegs();
  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
  br(TMP1);

  // ---- entry check: returns when FCW (PC/RC/masks), FSW.PE (mode bit1) and MXCSR (RC, FZ) are as compiled; otherwise
  // deopts (never returns): the site parked lr in Pointers.X87PCXSavedLR. Mode bit2: TMP2 = the unit's spill bytes.
  // Scratch TMP1, TMP3 (TMP2 is an input). ----
  BackwardLabel CheckBody[8];
  for (uint32_t M = 0; M < 8; ++M) {
    PCXFirst(270 + M);
    X87PCXCheckAddress[M] = GetCursorAddress<uint64_t>();
    (void)Bind(&CheckBody[M]);
    // X87EXACT DYN: M & 3 = the guard's precision field (shared guard format): 0 no word check, 1 word 0x003F, 2 0x023F, 3 0x033F;
    // FSW.PE is not checked (the forms read it). A mismatch deopts as before: the unit is recompiled for the word it meets.
    if (Dyn && (M & 3) == 0) {
      ret();
      continue;
    }
    ForwardLabel Fail;
    const bool MRMW = PCXK::ModeWordEnabled(); // TRANS32 MODE_WORD: FCW and MXCSR RC / FZ in one kept word, compared by sub (NZCV kept)
    if (MRMW) {
      ldrh(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.AbridgedFTW) + 4);
      sub(Size::i64Bit, TMP1, TMP1, Dyn ? ((M & 3) == 1 ? 0x003F : (M & 3) == 2 ? 0x023F : 0x033F) : (M & 1) ? 0x003F : 0x023F);
    } else {
    ldrh(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.FCW));
    movz(Size::i64Bit, TMP3, 0x0F3F);
    and_(Size::i64Bit, TMP1, TMP1, TMP3);
    movz(Size::i64Bit, TMP3, (M & 1) ? 0x003F : 0x023F);
    eor(Size::i64Bit, TMP1, TMP1, TMP3);
    }
    if ((M & 2) && !Dyn) {
      ldrb(TMP3, STATE, PEOff);
      eor(Size::i64Bit, TMP3, TMP3, 1);
      orr(Size::i64Bit, TMP1, TMP1, TMP3);
    }
    if (!MRMW) {
      ldr(TMP3.W(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.mxcsr));
      and_(Size::i64Bit, TMP3, TMP3, 0xE000);
      orr(Size::i64Bit, TMP1, TMP1, TMP3);
    }
    (void)cbnz(Size::i64Bit, TMP1, &Fail);
    ret();
    (void)Bind(&Fail);
    mov(Size::i64Bit, TMP3, Reg::r30);
    ldr(XReg::lr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedLR));
    str(XReg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR)); // the unit is left: no live record
    if (M & 4) {
      add(Size::i64Bit, XReg::rsp, XReg::rsp, TMP2, ExtendedType::LSL_64, 0);
    }
    orr(Size::i64Bit, TMP1, TMP3, PCXK::DeoptHostPCTag);
    (void)b(&DeoptFromPC);
  }
  if (PCXK::UnitSEnabled()) {
    for (uint32_t M = 0; M < 8; ++M) {
      PCXGuardS(M);
      (void)b(&CheckBody[M]);
    }
  }
  // ---- SHAPE (HBX87PCX.h ShapeEnabled): the guard's in-line shape check failed (after its entry check returned, so lr is parked
  // in Pointers.X87PCXSavedLR); the same deopt as a failed entry check, tagged with ShapeDeoptTag. V = 1: TMP2 = spill bytes. ----
  for (uint32_t V = 0; V < 2; ++V) {
    X87PCXShapeFailAddress[V] = GetCursorAddress<uint64_t>();
    mov(Size::i64Bit, TMP3, Reg::r30);
    ldr(XReg::lr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedLR));
    str(XReg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR)); // the unit is left: no live record
    if (V) {
      add(Size::i64Bit, XReg::rsp, XReg::rsp, TMP2, ExtendedType::LSL_64, 0);
    }
    orr(Size::i64Bit, TMP1, TMP3, PCXK::DeoptHostPCTag | PCXK::ShapeDeoptTag);
    (void)b(&DeoptFromPC);
  }
  // ---- deopt and exit: TMP1 = tagged unit entry, TMP2 = guest RIP to continue at. Entered with br from the start of a
  // block (no dynamic value is live there); leaves through the dispatcher loop like an exit to a non-linked target. ----
  X87PCXDeoptExitAddress = GetCursorAddress<uint64_t>();
  str<IndexType::PRE>(TMP2, Reg::rsp, -16);
  PushDynamicRegs(TMP4);
  SpillStaticRegs(TMP4);
  mov(Size::i64Bit, Reg::r1, TMP1); // TMP1 may be x0, TMP2 x1: TMP2 is already on the stack
  mov(Size::i64Bit, Reg::r0, STATE.R());
  ldr(XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.ThreadRemoveCodeEntryFromJIT));
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<void, void*, void*>(Reg::r2);
  } else {
    blr(Reg::r2);
  }
  FillStaticRegs();
  PopDynamicRegs();
  ldr<IndexType::POST>(TMP2, Reg::rsp, 16);
  str(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
  br(TMP1);

  // ---- end of a run (HBX87PCX.h FpsrFixEnabled): status bits raised since the run's first call that were clear then are the x87
  // stubs' own; put FPSR back, then restore the block's lr (Pointers.X87PCXSavedLR) and return through the saved address. No NZCV.
  // Called at the end of a run that calls an arithmetic or fst m32 stub, or (unit mode) before every exit of the unit; the site
  // stores lr to Pointers.X87PCXSavedLR first. A record without bit 63 (none live) is left alone. ----
  // Unit exit (unit mode): every exit op leaves the unit and none reads lr, so the check returns with a plain ret.
  X87PCXUnitExitAddress = GetCursorAddress<uint64_t>();
  {
    ForwardLabel Keep, Done;
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
    (void)tbz(TMP2, 63, &Done);
    mrs(TMP1, SystemRegister::FPSR);
    bic(Size::i64Bit, TMP1, TMP1, TMP2);
    and_(Size::i64Bit, TMP1, TMP1, 0x1f);
    (void)cbz(Size::i64Bit, TMP1, &Keep);
    and_(Size::i64Bit, TMP2, TMP2, 0xffffffffULL);
    msr(SystemRegister::FPSR, TMP2);
    (void)Bind(&Keep);
    str(XReg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
    (void)Bind(&Done);
    ret();
  }
  X87PCXRunEndAddress = GetCursorAddress<uint64_t>();
  {
    ForwardLabel Keep, Done;
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
    (void)tbz(TMP2, 63, &Done);
    mrs(TMP1, SystemRegister::FPSR);
    bic(Size::i64Bit, TMP1, TMP1, TMP2);
    and_(Size::i64Bit, TMP1, TMP1, 0x1f);
    (void)cbz(Size::i64Bit, TMP1, &Keep);
    and_(Size::i64Bit, TMP2, TMP2, 0xffffffffULL);
    msr(SystemRegister::FPSR, TMP2);
    (void)Bind(&Keep);
    str(XReg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
    (void)Bind(&Done);
    mov(Size::i64Bit, TMP3, Reg::r30);
    ldr(XReg::lr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedLR));
    ret(TMP3);
  }

  // ---- compares: VTMP1 ? VTMP2 -> F80Cmp flag word in TMP1 ----
  for (uint32_t Q = 0; Q < 2; ++Q) {
    PCXFirst(268 + Q);
    X87PCXCmpAddress[Q] = GetCursorAddress<uint64_t>();
    ForwardLabel Slow;
    fmov(Size::i64Bit, TMP1, VTMP1.D());
    ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
    add(Size::i64Bit, TMP2, TMP2, 1);
    (void)tbnz(TMP2, 11, &Slow);
    fmov(Size::i64Bit, TMP1, VTMP2.D());
    ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
    add(Size::i64Bit, TMP2, TMP2, 1);
    (void)tbnz(TMP2, 11, &Slow);
    mrs(TMP3, SystemRegister::NZCV);
    fcmp(VTMP1.D(), VTMP2.D());
    cset(Size::i64Bit, TMP1, Condition::CC_MI);
    cset(Size::i64Bit, TMP2, Condition::CC_EQ);
    msr(SystemRegister::NZCV, TMP3);
    lsl(Size::i64Bit, TMP1, TMP1, IR::FCMP_FLAG_LT);
    orr(Size::i64Bit, TMP1, TMP1, TMP2, ShiftType::LSL, IR::FCMP_FLAG_EQ);
    ret();
    (void)Bind(&Slow);
    Tail(Q ? FEXCore::Core::OPINDEX_X87PCX_CMPQUIET : FEXCore::Core::OPINDEX_X87PCX_CMP);
  }

  // ---- X87EXACT S32 (Interface/Core/HBX87S32.h): the cold parts of the typed binary32 forms. Operands and result are singles in
  // VTMP1 (VTMP2); TMP1..TMP4 are clobbered. Called through the generic entry below from the unit's cold code (HBX87S32Cold.inl) after the
  // typed form's own checks failed; the container stubs are entered behind their word checks where the unit's guard guarantees the word.
  if (FEXCore::HBX87::S32::Exact()) {
    namespace S32K = FEXCore::HBX87::S32;
    const unsigned S32Mut = S32K::Mutant();
    // The record prologue of a run's first raising form (Dispatcher.cpp PCXFirstS / PCXFirst), then straight back.
    {
      const uint64_t KeepS = X87PCXFirstSAddress[0], Keep = X87PCXFirstAddress[0];
      PCXFirstS(0);
      X87PCXS32ColdAddress[S32K::ColdFirstS] = X87PCXFirstSAddress[0];
      ret();
      PCXFirst(0);
      X87PCXS32ColdAddress[S32K::ColdFirst] = X87PCXFirstAddress[0];
      ret();
      X87PCXFirstSAddress[0] = KeepS;
      X87PCXFirstAddress[0] = Keep;
    }
    // The generic entry of every cold part. The unit's cold code is "bl <trampoline>; b <back>; .word descriptor": operands and
    // destination are register NUMBERS in the descriptor (HBX87S32.h ColdDesc*), moved here through three small tables; the stub
    // named by the descriptor does the work. Three indirect branches more than a direct call -- on cold paths only -- for cold
    // parts of 3 words instead of 6..7 instructions per form.
    {
      BackwardLabel MoveA, MoveB, MoveD;
      ForwardLabel AfterA, AfterB, AfterD;
      const uint64_t TableA = GetCursorAddress<uint64_t>();
      (void)Bind(&MoveA);
      for (uint32_t n = 0; n < 32; ++n) {
        mov(VTMP1.Q(), VRegister(n).Q());
        (void)b(&AfterA);
      }
      (void)Bind(&MoveB);
      for (uint32_t n = 0; n < 32; ++n) {
        mov(VTMP2.Q(), VRegister(n).Q());
        (void)b(&AfterB);
      }
      (void)Bind(&MoveD);
      for (uint32_t n = 0; n < 32; ++n) {
        mov(VRegister(n).Q(), VTMP1.Q());
        (void)b(&AfterD);
      }
      if (GetCursorAddress<uint64_t>() - TableA != 3 * 32 * 8) { // the entry indexes the tables by 8 bytes per register
        ERROR_AND_DIE_FMT("S32 cold tables: an entry is not two instructions");
      }
      X87PCXS32ColdAddress[S32K::ColdGeneric] = GetCursorAddress<uint64_t>();
      ldr(TMP1.W(), ARMEmitter::Reg::r30, 4); // the descriptor: the word behind the unit's "b <back>"
      str<IndexType::PRE>(XReg::lr, Reg::rsp, -16);
      str(TMP1, Reg::rsp, 8);
      and_(Size::i64Bit, TMP2, TMP1, 31);
      (void)adr(TMP3, &MoveA);
      add(Size::i64Bit, TMP3, TMP3, TMP2, ShiftType::LSL, 3);
      br(TMP3);
      (void)Bind(&AfterA);
      ubfx(Size::i64Bit, TMP2, TMP1, S32K::ColdDescB, 5);
      (void)adr(TMP3, &MoveB);
      add(Size::i64Bit, TMP3, TMP3, TMP2, ShiftType::LSL, 3);
      br(TMP3);
      (void)Bind(&AfterB);
      ubfx(Size::i64Bit, TMP2, TMP1, S32K::ColdDescStub, 6);
      const uint32_t TableOffset = static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, X87PCXS32Cold[0]));
      add(Size::i64Bit, TMP3, STATE.R(), TableOffset >> 12, true); // a tail field of the frame, beyond a scaled ldr offset
      add(Size::i64Bit, TMP3, TMP3, TMP2, ShiftType::LSL, 3);
      ldr(TMP3, TMP3, TableOffset & 0xFFF);
      blr(TMP3);
      ldr(TMP1, Reg::rsp, 8);
      ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
      (void)tbz(TMP1, S32K::ColdDescHasDst, &AfterD);
      ubfx(Size::i64Bit, TMP2, TMP1, S32K::ColdDescDst, 5);
      (void)adr(TMP3, &MoveD);
      add(Size::i64Bit, TMP3, TMP3, TMP2, ShiftType::LSL, 3);
      br(TMP3);
      (void)Bind(&AfterD);
      ret(); // to the unit's "b <back>"
    }
    // Narrowing, slow end: container / box in VTMP1.D -> typed single in VTMP1.S by HBX87S32.h Narrow (a new box slot when the
    // value is not a binary32 of the typed range). The F80_I16_F80_PTR fallback ABI of the From80 slow path with another function;
    // it returns to lr, i.e. into the unit's cold code.
    BackwardLabel NarrowSlow;
    (void)Bind(&NarrowSlow);
    ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers[0].ABIHandler) +
                       FEXCore::Core::OPINDEX_X87PCX_FROM80 * sizeof(FEXCore::Core::FallbackABIInfo));
    LoadConstant(Size::i64Bit, TMP4, S32K::NarrowHandlerAddress());
    br(TMP1);
    // Narrowing, fast end, entered with lr on the stack: +-0 and binary32 numbers of the typed range (exponent field 4..251).
    BackwardLabel NarrowReturn;
    (void)Bind(&NarrowReturn);
    {
      ForwardLabel Fast, Slow;
      fmov(Size::i64Bit, TMP1, VTMP1.D());
      lsl(Size::i64Bit, TMP2, TMP1, 1);
      (void)cbz(Size::i64Bit, TMP2, &Fast);
      ubfx(Size::i64Bit, TMP2, TMP1, 52, 11);
      sub(Size::i64Bit, TMP2, TMP2, 1023 - 127 + 4);
      (void)tbnz(TMP2, 63, &Slow);
      sub(Size::i64Bit, TMP2, TMP2, 248);
      (void)tbz(TMP2, 63, &Slow);
      if (S32Mut != 7) {
        lsl(Size::i64Bit, TMP2, TMP1, 35); // more than 24 significant bits: not a binary32
        (void)cbnz(Size::i64Bit, TMP2, &Slow);
      }
      (void)Bind(&Fast);
      fcvt(VTMP1.S(), VTMP1.D());
      ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
      ret();
      (void)Bind(&Slow);
      ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
      (void)b(&NarrowSlow);
    }
    // fld m32 of a value that is not a normal binary32: +-0 is itself, the rest goes through the container load stub (the same
    // flags as the container path) and comes back as a box in a single.
    X87PCXS32ColdAddress[S32K::ColdLoad] = GetCursorAddress<uint64_t>();
    {
      ForwardLabel NotZero;
      fmov(Size::i32Bit, TMP1, VTMP1.S());
      lsl(Size::i32Bit, TMP2, TMP1, 1);
      (void)cbnz(Size::i32Bit, TMP2, &NotZero);
      ret();
      (void)Bind(&NotZero);
      str<IndexType::PRE>(XReg::lr, Reg::rsp, -16);
      BackwardLabel LoadStub {reinterpret_cast<uint8_t*>(X87PCXLoadAddress[0])};
      (void)bl(&LoadStub);
      ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
      (void)b(&NarrowSlow);
    }
    // fst m32 of a box: the container store stub, through its word check (fst m32 depends on the rounding control only).
    for (uint32_t Sat = 0; Sat < 2; ++Sat) {
      for (uint32_t C1 = 0; C1 < 2; ++C1) {
        X87PCXS32ColdAddress[S32K::ColdStore + (C1 | (Sat << 1))] = GetCursorAddress<uint64_t>();
        fcvt(VTMP1.D(), VTMP1.S());
        BackwardLabel StoreStub {reinterpret_cast<uint8_t*>(((Sat && PCXK::SatEnabled()) ? X87PCXStoreSAddress : X87PCXStoreAddress)[C1 ? 2 : 0] -
                                                            PCXK::DynCheckStore)};
        (void)b(&StoreStub);
      }
    }
    // Arithmetic. First the exact results that need no rounding (an operand +-0, no box, nothing at 2^125 and above), then the
    // container form of c33m on the widened operands -- it reads FSW.PE itself, computes C1 and takes the exact handler where it
    // must -- and its result narrowed back.
    for (uint32_t Sat = 0; Sat < 2; ++Sat) {
      for (uint32_t C1 = 0; C1 < 2; ++C1) {
        for (uint32_t Kop = 0; Kop <= PCXK::OpSqrt; ++Kop) {
          X87PCXS32ColdAddress[S32K::ColdArith + (Kop | (C1 << 3) | (Sat << 4))] = GetCursorAddress<uint64_t>();
          ForwardLabel General;
          // W's exponent field is at most 251 (so W is no box), else General. Clobbers T.
          auto Small = [&](Register W, Register T) {
            ubfx(Size::i32Bit, T, W, 23, 8);
            add(Size::i32Bit, T, T, 4);
            lsr(Size::i32Bit, T, T, 8);
            (void)cbnz(Size::i32Bit, T, &General);
          };
          auto SignedZero = [&]() { // +-0 with the sign of A xor B
            eor(Size::i32Bit, TMP1, TMP1, TMP2);
            and_(Size::i32Bit, TMP1, TMP1, 0x80000000);
            fmov(Size::i32Bit, VTMP1.S(), TMP1);
          };
          fmov(Size::i32Bit, TMP1, VTMP1.S());
          if (Kop != PCXK::OpSqrt) {
            fmov(Size::i32Bit, TMP2, VTMP2.S());
          }
          switch (Kop) {
          case PCXK::OpAdd:
          case PCXK::OpSub: { // 0 + b, a + 0, 0 + 0: the host operation is exact and follows the same sign rules
            ForwardLabel Zero;
            lsl(Size::i32Bit, TMP3, TMP1, 1);
            (void)cbz(Size::i32Bit, TMP3, &Zero);
            lsl(Size::i32Bit, TMP3, TMP2, 1);
            (void)cbnz(Size::i32Bit, TMP3, &General);
            (void)Bind(&Zero);
            Small(TMP1, TMP3);
            Small(TMP2, TMP3);
            if (Kop == PCXK::OpAdd || S32Mut == 6) {
              fadd(VTMP1.S(), VTMP1.S(), VTMP2.S());
            } else {
              fsub(VTMP1.S(), VTMP1.S(), VTMP2.S());
            }
            break;
          }
          case PCXK::OpMul: { // 0 * b, a * 0
            ForwardLabel Zero;
            lsl(Size::i32Bit, TMP3, TMP1, 1);
            (void)cbz(Size::i32Bit, TMP3, &Zero);
            lsl(Size::i32Bit, TMP3, TMP2, 1);
            (void)cbnz(Size::i32Bit, TMP3, &General);
            (void)Bind(&Zero);
            Small(TMP1, TMP3);
            Small(TMP2, TMP3);
            SignedZero();
            break;
          }
          case PCXK::OpDiv: // 0 / b, b a nonzero number
            lsl(Size::i32Bit, TMP3, TMP1, 1);
            (void)cbnz(Size::i32Bit, TMP3, &General);
            ubfx(Size::i32Bit, TMP3, TMP2, 23, 8);
            (void)cbz(Size::i32Bit, TMP3, &General);
            Small(TMP2, TMP3);
            SignedZero();
            break;
          default: // sqrt(+-0) = +-0
            lsl(Size::i32Bit, TMP3, TMP1, 1);
            (void)cbnz(Size::i32Bit, TMP3, &General);
            break;
          }
          if (C1) {
            strb(Reg::zr, STATE, C1Off); // exact: not rounded up; PE untouched
          }
          ret();
          (void)Bind(&General);
          str<IndexType::PRE>(XReg::lr, Reg::rsp, -16);
          fcvt(VTMP1.D(), VTMP1.S());
          if (Kop != PCXK::OpSqrt) {
            fcvt(VTMP2.D(), VTMP2.S());
          }
          const uint32_t Kc = Kop | PCXK::K24 | (C1 ? PCXK::KC1 : 0);
          BackwardLabel Form {reinterpret_cast<uint8_t*>(((Sat && PCXK::SatEnabled()) ? X87PCXArithSAddress : X87PCXArithAddress)[Kc])};
          (void)bl(&Form);
          (void)b(&NarrowReturn);
        }
      }
    }
  }
}
