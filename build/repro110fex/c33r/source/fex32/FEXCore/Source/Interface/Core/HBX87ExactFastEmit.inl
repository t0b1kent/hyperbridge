// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// TRANS32 0035 (stage b1 of the cheap exact path, MACRUNNER_FEX32_X87_EXACT_FAST >= 1, default 0, Guest32): FST/FSTP m32/m64 of the
// exact path (F80CVT; ABI F32_I16_F80 / F64_I16_F80) calls the integer dispatcher stub Pointers.X87ExactCvt[D] (Dispatcher.cpp)
// instead of the ABI handler; the stub tail-jumps into the unchanged handler itself when the fast path does not apply. The site is the
// helper call minus its Func load (the stub loads the pair). Included in Arm64JITCore::Op_Unhandled after HBX87PCXEmit.inl (the HB
// store modes of HBX87StoreEmit.inl, when on, come first).
if (IROp->Op == IR::OP_F80CVT && (IROp->Size == IR::OpSize::i32Bit || IROp->Size == IR::OpSize::i64Bit) &&
    !CTX->Config.Is64BitMode() && FEXCore::HBX87::PCX::ExactFastLevel() >= 1) {
  using namespace ARMEmitter;
  const bool D = IROp->Size == IR::OpSize::i64Bit;
  const auto Src = GetVReg(IROp->Args[0]);
  const auto Dst = GetVReg(Node);
  str<IndexType::PRE>(XReg::lr, Reg::rsp, -16);
  mov(VTMP1.Q(), Src.Q());
  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87ExactCvt[0]) + (D ? 8 : 0));
  blr(TMP1);
  ldr<IndexType::POST>(XReg::lr, Reg::rsp, 16);
  if (D) fmov(Dst.D(), VTMP1.D());
  else fmov(Dst.S(), VTMP1.S());
  return;
}
