  // STAND32 deliberate mutant: FRNDINT ignores the captured rounding mode.
  const char* Mutation = std::getenv("STAND32_MUTATION");
  if (IROp == FEXCore::IR::OP_F80ROUNDSTACK && Mutation && std::string_view{Mutation} == "x87_rounding") {
    _StackForceSlow();
    _StoreContextGPR(OpSize::i16Bit, Constant(0x037f), offsetof(FEXCore::Core::CPUState, FCW));
  }
