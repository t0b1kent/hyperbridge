#ifdef _WIN32
        if (auto* Slot = StandStateCapture::GetSlot(BlockStartRIP)) {
          // TMP1-4 are scratch at an external entrypoint; all guest static
          // registers and NZCV stay untouched on the cheap path. Atomic counter
          // makes the Nth-execution gate coherent across producer threads.
          ARMEmitter::ForwardLabel SkipStandState;
          LoadConstant(ARMEmitter::Size::i64Bit, TMP1, reinterpret_cast<uint64_t>(&Slot->executions));
          LoadConstant(ARMEmitter::Size::i64Bit, TMP2, 1);
          ldaddal(ARMEmitter::SubRegSize::i64Bit, TMP2, TMP3, TMP1);
          lsr(ARMEmitter::Size::i64Bit, TMP4, TMP3, 1);
          (void)cbnz(ARMEmitter::Size::i64Bit, TMP4, &SkipStandState);
          PushDynamicRegs(TMP1);
          SpillStaticRegs(TMP1);
          mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, STATE);
          LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, reinterpret_cast<uint64_t>(CTX));
          LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, reinterpret_cast<uint64_t>(Slot));
          LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r4, reinterpret_cast<uint64_t>(StandStateCapture::Capture));
          if (!CTX->Config.DisableVixlIndirectCalls) GenerateIndirectRuntimeCall<void, void*, void*, void*>(ARMEmitter::Reg::r4);
          else blr(ARMEmitter::Reg::r4);
          FillStaticRegs();
          PopDynamicRegs();
          (void)Bind(&SkipStandState);
        }
#endif
