// SPDX-License-Identifier: MIT
// X87EXACT S32 (Interface/Core/HBX87S32.h): the cold parts of the unit's typed binary32 forms, emitted after its last block
// (Arm64JITCore::CompileCode). One trampoline per unit into the generic cold stub (Dispatcher/HBX87PCXStubs.inl); each cold part
// is "bl <trampoline>; b <back>; .word descriptor" -- operands and destination as register numbers (HBX87S32.h ColdDesc*); the
// stub reads the word behind its return address and returns to the bl's own successor, so the return predictor stays right.
// There is no guest memory access and no suspend poll in here -- nothing in this code faults -- so it needs no host -> guest
// mapping; lr is dead between the operations of translated code (HBX87PCX.h).
if (!S32ColdSites.empty()) {
  namespace S32K = FEXCore::HBX87::S32;
  ARMEmitter::BackwardLabel Trampoline;
  (void)Bind(&Trampoline);
  {
    // The stub table is a tail field of the frame, beyond the 32760-byte range of a scaled ldr offset.
    const uint32_t Offset = static_cast<uint32_t>(offsetof(FEXCore::Core::CpuStateFrame, X87PCXS32Cold[0])) + 8 * S32K::ColdGeneric;
    add(ARMEmitter::Size::i64Bit, TMP1, STATE.R(), Offset >> 12, true);
    ldr(TMP1, TMP1, Offset & 0xFFF);
    br(TMP1);
  }
  for (auto& C : S32ColdSites) {
    if (C.Kind == S32ColdSite::Arith && C.Post) {
      // The host result failed the range check (TMP1 = its bits) in a form where a +-0 result can only be exact
      // (HBX87PCXEmit.inl): +-0 is the result -- nothing rounded, nothing raised, FSW.PE as it was. Anything else: the stub.
      BindOrRestart(&C.EnterPost);
      ARMEmitter::ForwardLabel General;
      if (S32K::Mutant() != 9) {
        lsl(ARMEmitter::Size::i32Bit, TMP2, TMP1, 1);
        (void)cbnz(ARMEmitter::Size::i32Bit, TMP2, &General);
      }
      if (S32K::Mutant() == 11) { // the negative control of this branch: the +-0 with the wrong sign
        fneg(ARMEmitter::VRegister(C.Dst).S(), (C.Post & 3) == 1 ? VTMP1.S() : ARMEmitter::VRegister(C.Dst).S());
      } else if ((C.Post & 3) == 1) {
        mov(ARMEmitter::VRegister(C.Dst).Q(), VTMP1.Q());
      }
      if (C.Post & 4) { // a form with the C1 duty: an exact result was not rounded up
        strb(ARMEmitter::Reg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.flags) + FEXCore::X86State::X87FLAG_C1_LOC);
      }
      if (b(&C.Back) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("S32 cold part out of branch range");
      }
      (void)Bind(&General);
    }
    BindOrRestart(&C.Enter);
    uint32_t Index = C.Sub;
    bool HasDst = true;
    if (C.Kind == S32ColdSite::Load) {
      // +-0 is common in data and is itself: no call. TMP1 = the value's bits (the form's check left them there).
      ARMEmitter::ForwardLabel NotZero;
      lsl(ARMEmitter::Size::i32Bit, TMP2, TMP1, 1);
      (void)cbnz(ARMEmitter::Size::i32Bit, TMP2, &NotZero);
      if (C.Dst != C.A) {
        mov(ARMEmitter::VRegister(C.Dst).Q(), ARMEmitter::VRegister(C.A).Q());
      }
      if (b(&C.Back) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("S32 cold part out of branch range");
      }
      (void)Bind(&NotZero);
      Index = S32K::ColdLoad;
    } else if (C.Kind == S32ColdSite::Store) {
      Index = S32K::ColdStore + C.Sub;
    } else if (C.Kind == S32ColdSite::Arith) {
      Index = S32K::ColdArith + C.Sub;
    } else {
      HasDst = false;
    }
    if (bl(&Trampoline) == ARMEmitter::BranchEncodeSucceeded::Failure) {
      ERROR_AND_DIE_FMT("S32 cold part out of branch range");
    }
    if (b(&C.Back) == ARMEmitter::BranchEncodeSucceeded::Failure) {
      ERROR_AND_DIE_FMT("S32 cold part out of branch range");
    }
    dc32(uint32_t {C.A} | (uint32_t {C.B} << S32K::ColdDescB) | (uint32_t {C.Dst} << S32K::ColdDescDst) | (Index << S32K::ColdDescStub) |
         (HasDst ? 1u << S32K::ColdDescHasDst : 0u));
  }
}
S32ColdSites.clear();
