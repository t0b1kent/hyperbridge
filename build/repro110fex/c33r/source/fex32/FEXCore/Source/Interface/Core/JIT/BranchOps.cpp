// SPDX-License-Identifier: MIT
/*
$info$
tags: backend|arm64
$end_info$
*/

#include "Interface/Context/Context.h"
#include "FEXCore/IR/IR.h"
#include "Interface/Core/LookupCache.h"

#include "Interface/Core/JIT/JITClass.h"
#include "Interface/Core/HBX87PCX.h"

#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/fextl/fmt.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>

#include <FEXCore/Core/MacRunnerWinctx.h>

// FEX::Windows::Logging::Raw (__wine_dbg_output): fprintf in the PE part of FEX kills the process (see Core.cpp).
namespace FEX::Windows::Logging {
void Raw(const char* Message);
}

// ★ MacRunner Claude 29.09.2026: MACRUNNER_FEX_NULL_HOST=1 keeps a block exit to a non-constant target (RET, RETF,
// IRET, JMP/CALL r/m, also POPF and SYSCALL, whose next RIP is not inline) from jumping to host 0. The call-ret stack
// pop and the inline L1 lookup in ExitFunction match the guest address alone, and an empty entry is {guest 0, host 0}:
// the call-ret stack is zeroed on invalidation (Core.cpp, JIT.cpp), a call without a known return block pushes {0, 0},
// unused L1 entries are zero. A branch to guest 0 matched such an entry and went to host 0 (HB<->FEX oracle 28.09,
// FEX-RET0: `push 0; ret`, ESR 0x82000006). The gate checks the host candidate instead of refusing guest 0 (which may
// be mapped): host 0 takes the L1 miss path, i.e. the full lookup through the dispatcher, whose L2 lookup already
// rejects a zero host (Dispatcher.cpp), so a fetch at an unmapped 0 becomes the guest's own fault. Not covered:
// InvalidateCache keeps the HostCode of an L1 entry (LookupCache.h), so guest 0 can still match {0, old host} and run
// that stale block. Unset or any other value keeps the upstream sequence. MacRunnerNullHostChecks counts such exits
// translated with the check; a macrunner-fex-null-host line is printed when it reaches 1, 2, 4, 8, ...
std::atomic<uint64_t> MacRunnerNullHostChecks {0};
int MacRunnerNullHostMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_NULL_HOST");
    return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
  }();
  return Mode;
}

namespace {
void MacRunnerCountNullHostCheck(uint64_t Entry, FEXCore::IR::BranchHint Hint) {
  const uint64_t Checks = MacRunnerNullHostChecks.fetch_add(1, std::memory_order_relaxed) + 1;
  if ((Checks & (Checks - 1)) == 0) {
    const char* HintName = Hint == FEXCore::IR::BranchHint::Call   ? "call" :
                           Hint == FEXCore::IR::BranchHint::Return ? "ret" :
                                                                     "jmp";
    char Line[160];
    const auto Result =
      fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-null-host: checks={} entry={:x} hint={}\n", Checks, Entry, HintName);
    Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
}
} // namespace

namespace FEXCore::CPU {

DEF_OP(CallbackReturn) {
  // spill back to CTX
  SpillStaticRegs(TMP1);

  // First we must reset the stack
  ResetStack();

  // We can now lower the ref counter again

  ldr(ARMEmitter::WReg::w2, STATE, offsetof(FEXCore::Core::CpuStateFrame, SignalHandlerRefCounter));
  sub(ARMEmitter::Size::i32Bit, ARMEmitter::Reg::r2, ARMEmitter::Reg::r2, 1);
  str(ARMEmitter::WReg::w2, STATE, offsetof(FEXCore::Core::CpuStateFrame, SignalHandlerRefCounter));

  // We need to adjust an additional 8 bytes to get back to the original "misaligned" RSP state
  ldr(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.gregs[X86State::REG_RSP]));
  add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, ARMEmitter::Reg::r2, 8);
  str(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.gregs[X86State::REG_RSP]));

  PopCalleeSavedRegisters();

  // Return to the thunk
  ret();
}

void Arm64JITCore::EmitLoopCacheExit(bool NonzeroGuestRIP) {
  // TMP3 holds the guest continuation. Reuse the ordinary indirect branch's
  // per-thread L1 lookup: invalidation clears its guest tag before a stale
  // translation can be reused. Preserve NZCV and every guest register.
  ARMEmitter::ForwardLabel Miss;
  if (NonzeroGuestRIP) {
    ldp<ARMEmitter::IndexType::OFFSET>(TMP1, TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.L1Pointer));
    and_(ARMEmitter::Size::i64Bit, TMP2, TMP2, TMP3, ARMEmitter::ShiftType::LSL,
         FEXCore::ilog2(sizeof(LookupCache::LookupCacheEntry)));
    add(TMP1, TMP1, TMP2);
    ldp<ARMEmitter::IndexType::OFFSET>(TMP2, TMP1, TMP1, 0);
    sub(TMP1, TMP1, TMP3);
    (void)cbnz(ARMEmitter::Size::i64Bit, TMP1, &Miss);
    (void)cbz(ARMEmitter::Size::i64Bit, TMP2, &Miss);
    br(TMP2);
    (void)Bind(&Miss);
  }
  // Guest zero must use the dispatcher: invalidation uses a zero guest tag,
  // and an old nonzero host pointer alone does not establish a valid entry.
  str(TMP3, STATE_PTR(CpuStateFrame, State.rip));
  ldr(TMP2, STATE_PTR(CpuStateFrame, Pointers.DispatcherLoopTop));
  br(TMP2);
}

DEF_OP(ExitFunction) {
  auto Op = IROp->C<IR::IROp_ExitFunction>();
  if (Op->Hint == IR::BranchHint::Call && FEXCore::HBX87::PCX::GuardSkipStats()) {
    // TRANS32 GUARD_SKIP_STATS: the call's class for the callee's entry counters (and the census): 1 / 2 = PCX caller with the mode
    // known (shape known / not), 3 = PCX caller, mode unknown, 4 = non-PCX caller; bits 4..5 mode, 8..15 shape.
    uint32_t V = 4;
    if (MRUnitPCX) {
      V = !(MRCallInfo & (1ULL << 31)) ? 3 : (((MRCallInfo >> 8) & 0x100) ? 1 : 2) | ((MRCallInfo & 3) << 4) | (((MRCallInfo >> 8) & 0xFF) << 8);
    }
    movz(ARMEmitter::Size::i32Bit, TMP1, V & 0xFFFF);
    strh(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.AbridgedFTW) + 2);
  }

  ResetStack();

  if (CTX->HostFeatures.IsInstCountCI) [[unlikely]] {
    // Emit function end marker
    udf(0x420F);
  }

  uint64_t NewRIP;

  if (Op->Hint == IR::BranchHint::RevalidateLoop) {
    // Link to a compiled entry, not an internal label: the exit-lowered IR
    // does not retain a backedge for register allocation/constant propagation.
    // Page invalidation restores the slow branch through the ordinary link map.
    const bool Constant = IsInlineConstant(Op->NewRIP, &NewRIP) || IsInlineEntrypointOffset(Op->NewRIP, &NewRIP);
    LOGMAN_THROW_A_FMT(Constant, "Writable loop exit requires a constant guest target");
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
    if (MRShadowPollOn()) {
      MREmitShadowExitPoll(NewRIP); // REGION4-0005: the loop re-enters the unit's (unpolled) entry
    }
#endif
    if (NewRIP >= Entry && NewRIP - Entry <= UINT32_MAX) {
      // BL carries the record in LR. The shared slow stub tags it before
      // entering the existing linker; a hot linked site becomes a plain B.
      bl_OrRestart(&LoopDispatcherLabel);
      PendingLoopLinkRecords.push_back(GetCursorAddress<uint64_t>());
      dc32(static_cast<uint32_t>(NewRIP - Entry));
      dc32(0); // Original slow B, filled after the forward label is bound.
      return;
    }
    InsertGuestRIPMove(TMP3, NewRIP);
    EmitLoopCacheExit(NewRIP != 0);
    return;
  }

#ifdef ARCHITECTURE_arm64ec
  if (MRGuestDebugSingleInstruction) {
    // Guest DEBUG is not guest TF. Execute one instruction, then return to
    // the normal dispatcher without linking or reading any block/ret cache.
    // The following instruction is checked before execution by Break IR.
    if (IsInlineConstant(Op->NewRIP, &NewRIP) || IsInlineEntrypointOffset(Op->NewRIP, &NewRIP)) {
      InsertGuestRIPMove(TMP1, NewRIP);
      str(TMP1, STATE_PTR(CpuStateFrame, State.rip));
    } else {
      const auto RipReg = GetReg(Op->NewRIP);
      str(RipReg.X(), STATE_PTR(CpuStateFrame, State.rip));
    }
    ldr(TMP2, STATE_PTR(CpuStateFrame, Pointers.DispatcherLoopTop));
    br(TMP2);
    return;
  }
#endif
  if constexpr (Context::BLOCK_DEBUGGING) {
    // Skip block linking when BLOCK_DEBUGGING as it adds overhead and is unncessary.
    // This is a debug only feature and doesn't need caching help.
    bool IsInlineRIP = IsInlineConstant(Op->NewRIP, &NewRIP) || IsInlineEntrypointOffset(Op->NewRIP, &NewRIP);
    ARMEmitter::ForwardLabel l_ExitLink;
    if (IsInlineRIP) {
      ldr(TMP1, &l_ExitLink);
      str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    } else {
      auto RipReg = GetReg(Op->NewRIP);
      str(RipReg.X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    }
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    br(TMP2);

    if (IsInlineRIP) {
      BindOrRestart(&l_ExitLink);
      dc64(NewRIP);
    }

    return;
  }

  if (IsInlineConstant(Op->NewRIP, &NewRIP) || IsInlineEntrypointOffset(Op->NewRIP, &NewRIP)) {
#ifdef ARCHITECTURE_arm64ec
    if (NewRIP < EC_CODE_BITMAP_MAX_ADDRESS && RtlIsEcCode(NewRIP)) {
      str(REG_CALLRET_SP, STATE_PTR(CpuStateFrame, State.callret_sp));
      add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, StaticRegisters[X86State::REG_RSP], 0);
      InsertGuestRIPMove(EC_CALL_CHECKER_PC_REG, NewRIP);
      ldr(TMP2, STATE_PTR(CpuStateFrame, Pointers.ExitFunctionEC));
      br(TMP2);
    } else {
#endif
      // In order to support direct branches without constantly hitting the L1 cache, we emit a call to a block linker,
      // this will compile the branch target block when it is hit and replace the branch to the linker at the callsite
      // with a direct branch to the destination block. Upon invalidation of the target block the backpatch is undone.
      //
      // In addition, to avoid needing to lookup in the cache for returns and any indirect branch prediction penalty,
      // a shadow stack of <GuestReturnRIP, HostReturnPC> pairs is maintained, acting as a first level cache for any
      // return operations. As the guest may not balance calls and returns exactly, an exception handler is expected to
      // be installed by the frontend, to reset the shadow stack to the middle of its valid bounds on overflow/underflow.
      // This shadow stack is also cleared on block invalidation operations or codebuffer switches, to ensure all pointed-to
      // host code is always valid.

      // This code will be backpatched by Arm64JITCore_ExitFunctionLink, below is an enumeration of all the possible cases.
      // Jump thunks are emitted in JIT.cpp after compilation of the entire multiblock.
      //
      // Call with known return block - unlinked
      //    00: adr TMP1, 0xC
      //    04: stp RetReg, TMP1, [SpReg, -0x10]!
      //    08: bl JmpThunk00
      //    JmpThunk00:
      //    00: b 0x8
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode
      //    18: GuestRIP
      //    20: CallerOffset
      //
      // Call with known return block after backpatching - linked in branch immediate range
      //    00: adr TMP1, 0xC
      //    04: stp RetReg, TMP1, [SpReg, -0x10]!
      //    08: bl HostCode                                        - MODIFIED
      //
      // Call with known return block after backpatching - linked out of range
      //    00: adr TMP1, 0xC
      //    04: stp RetReg, TMP1, [SpReg, -0x10]!
      //    08: bl JmpThunk00
      //    JmpThunk00:
      //    00: ldr TMP1, 0x10                                     - MODIFIED 2nd
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode                                           - MODIFIED 1st
      //    18: GuestRIP
      //    20: CallerOffset
      //
      // Jump - unlinked
      //    00: b JmpThunk00
      //    JmpThunk00:
      //    00: b 0x8
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode
      //    18: GuestRIP
      //    20: CallerOffset
      //
      // Jump after backpatching - linked in branch immediate range
      //    00: b HostCode                                         - MODIFIED
      //
      // Jump after backpatching - linked out of range
      //    00: b JmpThunk00
      //    JmpThunk00:
      //    00: ldr TMP1, 0x10                                     - MODIFIED 2nd
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode                                           - MODIFIED 1st
      //    18: GuestRIP
      //    20: CallerOffset

      ARMEmitter::ForwardLabel l_BranchHost;
      ARMEmitter::ForwardLabel l_CallReturn;
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
      if (Op->Hint != IR::BranchHint::Call && MRShadowPollOn()) {
        MREmitShadowExitPoll(NewRIP); // REGION4-0005: a direct jump / fall-through / conditional exit (a call polls by its stp)
      }
#endif
      if (Op->Hint == IR::BranchHint::Call) {
        if (!Op->CallReturnBlock.IsInvalid()) {
          auto CallReturnAddressReg = GetReg(Op->CallReturnAddress).X();
          PendingCallReturnTargetLabel = &CallReturnTargets.try_emplace(Op->CallReturnBlock.ID()).first->second;
          (void)adr(TMP1, &l_CallReturn);
          stp<ARMEmitter::IndexType::PRE>(CallReturnAddressReg, TMP1, REG_CALLRET_SP, -0x10);
        } else {
          stp<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::zr, ARMEmitter::XReg::zr, REG_CALLRET_SP, -0x10);
        }
      } else if (Op->Hint == IR::BranchHint::CheckTF) {
        ARMEmitter::ForwardLabel TFUnset;
        ldrb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));
        (void)cbz(ARMEmitter::Size::i32Bit, TMP1, &TFUnset);
        InsertGuestRIPMove(TMP1, NewRIP);
        str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
        ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
        blr(TMP2);
        (void)Bind(&TFUnset);
      }

      EmitLinkedBranch(NewRIP, Op->Hint == IR::BranchHint::Call);
      (void)Bind(&l_CallReturn);
#ifdef ARCHITECTURE_arm64ec
    }
#endif
  } else {
    ARMEmitter::ForwardLabel SkipFullLookup;
    auto RipReg = GetReg(Op->NewRIP);
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
    if (Op->Hint != IR::BranchHint::Call && Op->Hint != IR::BranchHint::Return && MRShadowPollOn()) {
      MREmitShadowExitPollReg(RipReg); // REGION4-0005: an indirect jump (a call / return polls by its stp / ldp)
    }
#endif

    if (Op->Hint == IR::BranchHint::Call && MRICActive && !Op->CallReturnBlock.IsInvalid() &&
        (MRICAll || std::find(MRICAbsExits.begin(), MRICAbsExits.end(), IR->GetID(Node).Value) != MRICAbsExits.end())) {
      // ★ PARITY32 MACRUNNER_FEX32_ICALL_IC v2 (MacRunnerXfer.h): inline target cache. The call-return entry is pushed first (host
      // return = the site's return point, kept in TMP2), then ONE load takes the site's pair {guest target, host offset}. Guest
      // half == target: branch to return point + offset (the cached target's host code; for an empty / delinked / frozen pair the
      // offset names the site's own miss stub). Otherwise the miss stub (end of the unit) -> the dispatcher's shared stub with
      // TMP1 = the pair as loaded and TMP3 = guest half - target. adr/stp/ldr/sub/cbnz/add/blr only: NZCV and guest registers kept.
      auto CallReturnAddressReg = GetReg(Op->CallReturnAddress).X();
      PendingCallReturnTargetLabel = &CallReturnTargets.try_emplace(Op->CallReturnBlock.ID()).first->second;
      auto& Site = MRICSites.emplace_back();
      ARMEmitter::ForwardLabel l_CallReturn;
      (void)adr(TMP2, &l_CallReturn);
      stp<ARMEmitter::IndexType::PRE>(CallReturnAddressReg, TMP2, REG_CALLRET_SP, -0x10);
      ldr(TMP1, &Site.Pair);
      sub(ARMEmitter::Size::i32Bit, TMP3, TMP1, RipReg);
      cbnz_OrRestart(ARMEmitter::Size::i32Bit, TMP3, &Site.Miss);
      add(ARMEmitter::Size::i64Bit, TMP4, TMP2, TMP1, ARMEmitter::ShiftType::ASR, 32);
      blr(TMP4);
      (void)Bind(&l_CallReturn);
      Site.ReturnAddr = GetCursorAddress<uint8_t*>();
      return;
    }

    if (Op->Hint == IR::BranchHint::Return) {
      // Both cached call-return labels and L1 targets enter through
      // EmitEntryPoint, before its suspend poll. Internal branches alone can
      // skip that prefix; GuestTargetSuspendChecks covers their cycles.
      // Keep the old publication for the legacy/synthetic-boundary mode.
      if ((!GuestTargetSuspendChecks || !CurrentBlockHasGuestBoundary) && FEXCore::Utils::MacRunnerSuspendBackedgeEnabled()) {
        EmitSuspendInterruptCheckAt(RipReg);
      }
      // First try to pop from the call-ret stack, otherwise follow the normal path (but ending in a ret)
      ldp<ARMEmitter::IndexType::POST>(TMP1, TMP2, REG_CALLRET_SP, 0x10);
      sub(TMP1, TMP1, RipReg.X());
      if (MRHotFallthrough & 2) {
        // PARITY32 HOT_FALLTHROUGH 2: the hit falls through to the return. The miss (and, with MACRUNNER_FEX_NULL_HOST=1, a matched
        // entry with host 0) goes to the stub at the end of the unit and on to the dispatcher's shared L1 probe.
        auto& Stub = MRRetMissStubs.emplace_back(MRMissStub {{}, {}, RipReg.Idx()});
        cbnz_OrRestart(ARMEmitter::Size::i64Bit, TMP1, &Stub.Miss);
        if (MacRunnerNullHostMode()) {
          cbz_OrRestart(ARMEmitter::Size::i64Bit, TMP2, &Stub.Miss);
          MacRunnerCountNullHostCheck(Entry, Op->Hint);
        }
        ret(TMP2);
        return;
      }
      (void)cbz(ARMEmitter::Size::i64Bit, TMP1, &SkipFullLookup);
    }

    // L1 Cache
    ldp<ARMEmitter::IndexType::OFFSET>(TMP1, TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.L1Pointer));

    // Calculate (tmp1 + ((ripreg & L1_ENTRIES_MASK) << 4)) for the address
    // L1Mask is pre-shifted.
    and_(ARMEmitter::Size::i64Bit, TMP2, TMP2, RipReg, ARMEmitter::ShiftType::LSL, FEXCore::ilog2(sizeof(LookupCache::LookupCacheEntry)));
    add(TMP1, TMP1, TMP2);

    ldp<ARMEmitter::IndexType::OFFSET>(TMP2, TMP1, TMP1, 0);

    // Note: sub+cbnz used over cmp+br to preserve flags.
    sub(TMP1, TMP1, RipReg.X());
    if ((MRHotFallthrough & 4) && Op->Hint != IR::BranchHint::Return && Op->Hint != IR::BranchHint::Call) {
      // PARITY32 HOT_FALLTHROUGH 4, indirect jmp: the L1 hit falls through to `br`; the miss (and a host 0 with NULL_HOST) goes to
      // `str rip; b <unit veneer: dispatcher>` at the end of the unit.
      auto& Stub = MRJmpMissStubs.emplace_back(MRMissStub {{}, {}, RipReg.Idx()});
      cbnz_OrRestart(ARMEmitter::Size::i64Bit, TMP1, &Stub.Miss);
      if (MacRunnerNullHostMode()) {
        cbz_OrRestart(ARMEmitter::Size::i64Bit, TMP2, &Stub.Miss);
        MacRunnerCountNullHostCheck(Entry, Op->Hint);
      }
      br(TMP2);
      return;
    }
    if ((MRHotFallthrough & 4) && Op->Hint == IR::BranchHint::Call) {
      // PARITY32 HOT_FALLTHROUGH 4, indirect call without the inline cache: the L1 hit falls through; the miss stub (end of the
      // unit) loads the dispatcher, stores RIP and comes back to the call.
      auto& Stub = MRCallMissStubs.emplace_back(MRMissStub {{}, {}, RipReg.Idx()});
      cbnz_OrRestart(ARMEmitter::Size::i64Bit, TMP1, &Stub.Miss);
      BindOrRestart(&Stub.Back);
    } else {
      (void)cbz(ARMEmitter::Size::i64Bit, TMP1, &SkipFullLookup);
      ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
      str(RipReg.X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    }

    (void)Bind(&SkipFullLookup);
    if (MacRunnerNullHostMode()) {
      // ★ MacRunner (MACRUNNER_FEX_NULL_HOST=1, see the top of this file): TMP2 is the host target taken from the
      // call-ret stack or from L1, or DispatcherLoopTop after an L1 miss. A matched empty entry gives 0: take the L1 miss
      // path instead. Only STATE-relative loads/stores, no host addresses in the emitted code.
      ARMEmitter::ForwardLabel ValidHost;
      (void)cbnz(ARMEmitter::Size::i64Bit, TMP2, &ValidHost);
      ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
      str(RipReg.X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
      (void)Bind(&ValidHost);
      MacRunnerCountNullHostCheck(Entry, Op->Hint);
    }
    if (Op->Hint == IR::BranchHint::Call) {
      ARMEmitter::ForwardLabel l_CallReturn;
      if (!Op->CallReturnBlock.IsInvalid()) {
        auto CallReturnAddressReg = GetReg(Op->CallReturnAddress).X();
        PendingCallReturnTargetLabel = &CallReturnTargets.try_emplace(Op->CallReturnBlock.ID()).first->second;
        (void)adr(TMP1, &l_CallReturn);
        stp<ARMEmitter::IndexType::PRE>(CallReturnAddressReg, TMP1, REG_CALLRET_SP, -0x10);
      } else {
        stp<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::zr, ARMEmitter::XReg::zr, REG_CALLRET_SP, -0x10);
      }
      blr(TMP2);
      (void)Bind(&l_CallReturn);
    } else if (Op->Hint == IR::BranchHint::Return) {
      ret(TMP2);
    } else {
      br(TMP2);
    }
  }
}

DEF_OP(Jump) {
  const auto Op = IROp->C<IR::IROp_Jump>();

  PendingTargetLabel = MRBranchTarget(Op->TargetBlock); // TRANS32 0030: guard label unless the mode is known on this edge
  auto Target = IR->GetOp<IR::IROp_CodeBlock>(Op->TargetBlock);
  PendingSuspendRIP = FEXCore::Utils::MacRunnerSuspendBackedgeEnabled() &&
                              Target->GuestEntryOffset != FEXCore::Utils::NoGuestSuspendBoundary
                        ? std::optional<uint64_t> {Entry + Target->GuestEntryOffset} : std::nullopt;
}

DEF_OP(CondJump) {
  auto Op = IROp->C<IR::IROp_CondJump>();

  auto TrueTargetLabel = MRBranchTarget(Op->TrueBlock); // TRANS32 0030
  auto FalseTargetLabel = MRBranchTarget(Op->FalseBlock);
  auto TrueBlock = IR->GetOp<IR::IROp_CodeBlock>(Op->TrueBlock);
  auto FalseBlock = IR->GetOp<IR::IROp_CodeBlock>(Op->FalseBlock);
  const bool GuestBoundary = TrueBlock->GuestEntryOffset != FEXCore::Utils::NoGuestSuspendBoundary &&
                             FalseBlock->GuestEntryOffset != FEXCore::Utils::NoGuestSuspendBoundary;

  // The same condition emitter selects the cold continuation and the hot edge.
  // Loads, branches and stores below preserve NZCV and every allocated register.
  auto EmitCondition = [&](ARMEmitter::BiDirectionalLabel* Target) {
    if (Op->FromNZCV) {
      b_OrRestart(MapCC(Op->Cond), Target);
    } else {
    uint64_t Const;
    const bool isConst = IsInlineConstant(Op->Cmp2, &Const);

    auto Reg = GetReg(Op->Cmp1);
    const auto Size = Op->CompareSize == IR::OpSize::i32Bit ? ARMEmitter::Size::i32Bit : ARMEmitter::Size::i64Bit;

    LOGMAN_THROW_A_FMT(IsGPR(Op->Cmp1), "CondJump: Expected GPR");
    LOGMAN_THROW_A_FMT(isConst, "CondJump: Expected constant source");

    if (Op->Cond == IR::CondClass::EQ) {
      LOGMAN_THROW_A_FMT(Const == 0, "CondJump: Expected 0 source");
      cbz_OrRestart(Size, Reg, Target);
    } else if (Op->Cond == IR::CondClass::NEQ) {
      LOGMAN_THROW_A_FMT(Const == 0, "CondJump: Expected 0 source");
      cbnz_OrRestart(Size, Reg, Target);
    } else if (Op->Cond == IR::CondClass::TSTZ) {
      LOGMAN_THROW_A_FMT(Const < 64, "CondJump: Expected valid bit source");
      tbz_OrRestart(Reg, Const, Target);
    } else if (Op->Cond == IR::CondClass::TSTNZ) {
      LOGMAN_THROW_A_FMT(Const < 64, "CondJump: Expected valid bit source");
      tbnz_OrRestart(Reg, Const, Target);
    } else {
      LOGMAN_THROW_A_FMT(false, "CondJump expected simple condition");
    }
    }
  };

#ifdef ARCHITECTURE_arm64ec
  if (FEXCore::Utils::MacRunnerSuspendBackedgeEnabled() && !GuestTargetSuspendChecks && GuestBoundary &&
      (TrueTargetLabel->Backward.Location || FalseTargetLabel->Backward.Location)) {
    ARMEmitter::ForwardLabel Cold, Publish;
    ARMEmitter::BiDirectionalLabel Taken;
    ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
    cbnz(ARMEmitter::Size::i32Bit, TMP2.W(), &Cold);
    // Hot paths branch straight to their guest blocks. Neither traverses the
    // cold publication; both backwards outcomes share this single poll.
    EmitCondition(TrueTargetLabel);
    b_OrRestart(FalseTargetLabel);
    Bind(&Cold);
    EmitCondition(&Taken);
    LoadConstant(ARMEmitter::Size::i64Bit, TMP1, Entry + FalseBlock->GuestEntryOffset);
    b(&Publish);
    BindOrRestart(&Taken);
    LoadConstant(ARMEmitter::Size::i64Bit, TMP1, Entry + TrueBlock->GuestEntryOffset);
    Bind(&Publish);
    str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    brk(0xCAFD);
    // Normally the trap transfers to the dispatcher. Preserve branch semantics
    // even if the trap handler returns immediately after the BRK.
    EmitCondition(TrueTargetLabel);
    b_OrRestart(FalseTargetLabel);
    PendingTargetLabel = nullptr;
    PendingSuspendRIP.reset();
    return;
  }
#endif
  EmitCondition(TrueTargetLabel);

  PendingTargetLabel = FalseTargetLabel;
  PendingSuspendRIP = FEXCore::Utils::MacRunnerSuspendBackedgeEnabled() && GuestBoundary
                        ? std::optional<uint64_t> {Entry + FalseBlock->GuestEntryOffset} : std::nullopt;
}

DEF_OP(Syscall) {
  auto Op = IROp->C<IR::IROp_Syscall>();
  // Arguments are passed as follows:
  // X0: SyscallHandler
  // X1: ThreadState
  // X2: Pointer to SyscallArguments

  PushDynamicRegs(TMP1);

  uint32_t GPRSpillMask = ~0U;
  uint32_t FPRSpillMask = ~0U;

  SpillStaticRegs(TMP1, {
                          .GPRSpillMask = GPRSpillMask,
                          .FPRSpillMask = FPRSpillMask,
                        });

  // Now that we are spilled, store in the state that we are in a syscall
  // Still without overwriting registers that matter
  // 16bit LoadConstant to be a single instruction
  // This gives the signal handler a value to check to see if we are in a syscall at all
  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, GPRSpillMask & 0xFFFF);
  str(ARMEmitter::XReg::x0, STATE, offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));

  uint64_t SPOffset = AlignUp(FEXCore::HLE::SyscallArguments::MAX_ARGS * 8, 16);
  sub(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, SPOffset);
  for (uint32_t i = 0; i < FEXCore::HLE::SyscallArguments::MAX_ARGS; ++i) {
    if (Op->Header.Args[i].IsInvalid()) {
      continue;
    }
    str(GetReg(Op->Header.Args[i]).X(), ARMEmitter::Reg::rsp, i * 8);
  }

  ldr(ARMEmitter::XReg::x0, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.SyscallHandlerObj));
  ldr(ARMEmitter::XReg::x3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.SyscallHandlerFunc));
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, STATE.R());

  // SP supporting move
  add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, ARMEmitter::Reg::rsp, 0);
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<uint64_t, void*, void*, void*>(ARMEmitter::Reg::r3);
  } else {
    blr(ARMEmitter::Reg::r3);
  }

  add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, SPOffset);

  // Result is now in x0
  // Fix the stack and any values that were stepped on
  FillStaticRegs({
    .OptionalReg = ARMEmitter::Reg::r1,
    .OptionalReg2 = ARMEmitter::Reg::r2,
    .GPRFillMask = GPRSpillMask,
    .FPRFillMask = FPRSpillMask,
  });

  // Now the registers we've spilled are back in their original host registers
  // We can safely claim we are no longer in a syscall
  str(ARMEmitter::XReg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, InSyscallInfo));

  PopDynamicRegs();

  const auto OSABI = CTX->SyscallHandler->GetOSABI();

  if (OSABI != FEXCore::HLE::SyscallOSABI::OS_GENERIC) {
    // Move result to its destination register.
    // Only if `NORETURNEDRESULT` wasn't set, otherwise we might overwrite the CPUState refilled with `FillStaticRegs`
    mov(ARMEmitter::Size::i64Bit, GetReg(Node), ARMEmitter::Reg::r0);
  }
}

DEF_OP(Thunk) {
  auto Op = IROp->C<IR::IROp_Thunk>();
  // Arguments are passed as follows:
  // X0: CTX
  // X1: Args (from guest stack)

  // spill to ctx before ra64 spill
  SpillStaticRegs(TMP1, {
                          .NZCV = false,
                        });

  PushDynamicRegs(TMP1);

  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, GetReg(Op->ArgPtr));

  InsertNamedThunkRelocation(ARMEmitter::Reg::r2, Op->ThunkNameHash);
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<void, void*, void*>(ARMEmitter::Reg::r2);
  } else {
    blr(ARMEmitter::Reg::r2);
  }

  PopDynamicRegs();

  // load from ctx after ra64 refill
  FillStaticRegs({
    .NZCV = false,
  });
}

DEF_OP(ValidateCode) {
  auto Op = IROp->C<IR::IROp_ValidateCode>();
  auto OldCode = Op->CodeOriginal.data();
  auto Base = GetReg(Op->Header.Args[0]).X();
  int len = Op->CodeLength;
  int Offset = 0;
  ARMEmitter::ForwardLabel Fail;

  const auto Dst = GetReg(Node);

  auto EmitCheck = [&](size_t Size, auto&& LoadData) {
    while (len >= Size) {
      LoadData();
      sub(ARMEmitter::Size::i64Bit, TMP1, TMP1, TMP2);
      cbnz_OrRestart(ARMEmitter::Size::i64Bit, TMP1, &Fail);
      len -= Size;
      Offset += Size;
    }
  };

  EmitCheck(8, [&]() {
    ldr(TMP1, Base, Offset);
    LoadConstant(ARMEmitter::Size::i64Bit, TMP2, *(const uint64_t*)(OldCode + Offset));
  });

  EmitCheck(4, [&]() {
    ldr(TMP1.W(), Base, Offset);
    LoadConstant(ARMEmitter::Size::i32Bit, TMP2, *(const uint32_t*)(OldCode + Offset));
  });

  EmitCheck(2, [&]() {
    ldrh(TMP1.W(), Base, Offset);
    LoadConstant(ARMEmitter::Size::i32Bit, TMP2, *(const uint16_t*)(OldCode + Offset));
  });

  EmitCheck(1, [&]() {
    ldrb(TMP1.W(), Base, Offset);
    LoadConstant(ARMEmitter::Size::i32Bit, TMP2, *(const uint8_t*)(OldCode + Offset));
  });

  ARMEmitter::ForwardLabel End;
  LoadConstant(ARMEmitter::Size::i32Bit, Dst, 0);
  b_OrRestart(&End);
  BindOrRestart(&Fail);
  LoadConstant(ARMEmitter::Size::i32Bit, Dst, 1);
  BindOrRestart(&End);
}

DEF_OP(ThreadRemoveCodeEntry) {
  PushDynamicRegs(TMP4);
  SpillStaticRegs(TMP4);

  // Arguments are passed as follows:
  // X0: Thread
  // X1: RIP
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, STATE.R());

  // TODO: Relocations don't seem to be wired up to this...?
  LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, Entry, CPU::Arm64Emitter::PadType::AUTOPAD);

  ldr(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.ThreadRemoveCodeEntryFromJIT));
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<void, void*, void*>(ARMEmitter::Reg::r2);
  } else {
    blr(ARMEmitter::Reg::r2);
  }
  FillStaticRegs();

  // Fix the stack and any values that were stepped on
  PopDynamicRegs();
}

DEF_OP(CPUID) {
  auto Op = IROp->C<IR::IROp_CPUID>();

  isb();
  mov(ARMEmitter::Size::i64Bit, TMP2, GetReg(Op->Function));
  mov(ARMEmitter::Size::i64Bit, TMP3, GetReg(Op->Leaf));

  PushDynamicRegs(TMP4);
  SpillStaticRegs(TMP4);

  // x0 = CPUID Handler
  // x1 = CPUID Function
  // x2 = CPUID Leaf
  ldr(ARMEmitter::XReg::x0, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDObj));
  ldr(ARMEmitter::XReg::x3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDFunction));

  if (!TMP_ABIARGS) {
    mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, TMP2);
    mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, TMP3);
  }

  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<__uint128_t, void*, uint64_t, uint64_t>(ARMEmitter::Reg::r3);
  } else {
    blr(ARMEmitter::Reg::r3);
  }

  if (!TMP_ABIARGS) {
    mov(ARMEmitter::Size::i64Bit, TMP1, ARMEmitter::Reg::r0);
    mov(ARMEmitter::Size::i64Bit, TMP2, ARMEmitter::Reg::r1);
  }

  FillStaticRegs();

  PopDynamicRegs();

  // Results are in x0, x1
  // Results want to be 4xi32 scalars
  mov(ARMEmitter::Size::i32Bit, GetReg(Op->OutEAX), TMP1);
  mov(ARMEmitter::Size::i32Bit, GetReg(Op->OutECX), TMP2);
  ubfx(ARMEmitter::Size::i64Bit, GetReg(Op->OutEBX), TMP1, 32, 32);
  ubfx(ARMEmitter::Size::i64Bit, GetReg(Op->OutEDX), TMP2, 32, 32);
}

DEF_OP(XGetBV) {
  auto Op = IROp->C<IR::IROp_XGetBV>();

  PushDynamicRegs(TMP4);
  SpillStaticRegs(TMP4);

  mov(ARMEmitter::Size::i32Bit, ARMEmitter::Reg::r1, GetReg(Op->Function));

  // x0 = CPUID Handler
  // x1 = XCR Function
  ldr(ARMEmitter::XReg::x0, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDObj));
  ldr(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.XCRFunction));
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<uint64_t, void*, uint32_t>(ARMEmitter::Reg::r2);
  } else {
    blr(ARMEmitter::Reg::r2);
  }

  if (!TMP_ABIARGS) {
    mov(ARMEmitter::Size::i64Bit, TMP1, ARMEmitter::Reg::r0);
  }

  FillStaticRegs();

  PopDynamicRegs();

  // Results are in x0, need to split into i32 parts
  mov(ARMEmitter::Size::i32Bit, GetReg(Op->OutEAX), TMP1);
  ubfx(ARMEmitter::Size::i64Bit, GetReg(Op->OutEDX), TMP1, 32, 32);
}

} // namespace FEXCore::CPU
