      // Private mutation control. These alter emitted ARM64 instructions,
      // never the reported result or Unicorn. Disabled means ordinary FEX.
      auto StandMark = [&] {
        std::fprintf(stderr, "STAND_MUTATION_EMIT mode=%s op=%s\n", StandMutation, IR::GetName(IROp->Op));
      };
      if (StandMutation && !strcmp(StandMutation,"sign_extend") && IROp->Op==IR::IROps::OP_SBFE) {
        auto Op=IROp->C<IR::IROp_Sbfe>();
        ubfx(ConvertSize(IROp),GetReg(CodeNode),GetReg(Op->Src),Op->lsb,Op->Width);
        StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"operand_width") && IROp->Size==IR::OpSize::i64Bit &&
          (IROp->Op==IR::IROps::OP_ADD || IROp->Op==IR::IROps::OP_SUB || IROp->Op==IR::IROps::OP_ADDSHIFT)) {
        if (IROp->Op==IR::IROps::OP_ADD) Op_Add(IROp,CodeNode);
        else if (IROp->Op==IR::IROps::OP_SUB) Op_Sub(IROp,CodeNode);
        else Op_AddShift(IROp,CodeNode);
        mov(ARMEmitter::Size::i32Bit,GetReg(CodeNode),GetReg(CodeNode));
        StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"store_omitted") &&
          (IROp->Op==IR::IROps::OP_STOREMEM || IROp->Op==IR::IROps::OP_STOREMEMTSO || IROp->Op==IR::IROps::OP_STOREMEMPAIR)) {
        nop();StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"register_write_omitted") &&
          (IROp->Op==IR::IROps::OP_COPY ||
           (IROp->Op==IR::IROps::OP_CONSTANT && IROp->C<IR::IROp_Constant>()->Constant==0) ||
           IROp->Op==IR::IROps::OP_VECTORIMM)) {
        nop();StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"sse_rounding") && IROp->Op==IR::IROps::OP_FLOAT_TOGPR_ZS) {
        auto Op=IROp->C<IR::IROp_Float_ToGPR_ZS>();
        if (Op->SrcElementSize==IR::OpSize::i64Bit) {
          frintn(VTMP1.D(),GetVReg(Op->Scalar).D());fcvtzs(ConvertSize(IROp),GetReg(CodeNode),VTMP1.D());
        } else {
          frintn(VTMP1.S(),GetVReg(Op->Scalar).S());fcvtzs(ConvertSize(IROp),GetReg(CodeNode),VTMP1.S());
        }
        StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"sse_rounding") && IROp->Op==IR::IROps::OP_VECTOR_FTOS) {
        Op_Vector_FToZS(IROp,CodeNode);StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"sse_rounding") && IROp->Op==IR::IROps::OP_VECTOR_FTOZS) {
        Op_Vector_FToS(IROp,CodeNode);StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"sse_rounding") && IROp->Op==IR::IROps::OP_FLOAT_TOGPR_S) {
        auto Op=IROp->C<IR::IROp_Float_ToGPR_S>();
        if (Op->SrcElementSize==IR::OpSize::i64Bit) fcvtzs(ConvertSize(IROp),GetReg(CodeNode),GetVReg(Op->Scalar).D());
        else fcvtzs(ConvertSize(IROp),GetReg(CodeNode),GetVReg(Op->Scalar).S());
        StandMark();continue;
      }
      if (StandMutation && !strcmp(StandMutation,"flags") &&
          (IROp->Op==IR::IROps::OP_SUBNZCV || IROp->Op==IR::IROps::OP_ADDNZCV || IROp->Op==IR::IROps::OP_TESTNZ || IROp->Op==IR::IROps::OP_TESTZ)) {
        if (IROp->Op==IR::IROps::OP_SUBNZCV) Op_SubNZCV(IROp,CodeNode);
        else if (IROp->Op==IR::IROps::OP_ADDNZCV) Op_AddNZCV(IROp,CodeNode);
        else if (IROp->Op==IR::IROps::OP_TESTNZ) Op_TestNZ(IROp,CodeNode);
        else Op_TestZ(IROp,CodeNode);
        mrs(TMP1,ARMEmitter::SystemRegister::NZCV);
        eor(ARMEmitter::Size::i64Bit,TMP1,TMP1,1ULL<<30);
        msr(ARMEmitter::SystemRegister::NZCV,TMP1);
        StandMark();continue;
      }
