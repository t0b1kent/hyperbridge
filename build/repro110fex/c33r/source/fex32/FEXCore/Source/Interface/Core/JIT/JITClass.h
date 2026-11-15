// SPDX-License-Identifier: MIT
/*
$info$
tags: backend|arm64
$end_info$
*/

#pragma once

#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IntrusiveIRList.h"
#include "Interface/IR/RegisterAllocationData.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X87Fault.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/Utils/MacRunnerSuspend.h>
#include <FEXCore/Utils/MacRunnerXfer.h>

#include <CodeEmitter/Emitter.h>

#include <array>
#include <cstdint>
#include <functional>
#include <list>
#include <optional>
#include <utility>
#include <variant>

namespace FEXCore::Core {
struct InternalThreadState;
}
namespace FEXCore::Context {
struct ExitFunctionLinkData;
}
namespace FEXCore::IR {
class RegisterAllocationPass;
}

namespace FEXCore::CPU {
class Arm64JITCore final : public CPUBackend, public Arm64Emitter {
public:
  explicit Arm64JITCore(FEXCore::Context::ContextImpl* ctx, FEXCore::Core::InternalThreadState* Thread);
  ~Arm64JITCore() override;

  [[nodiscard]]
  CPUBackend::CompiledCode CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst, const FEXCore::IR::IRListView* IR,
                                       FEXCore::Core::DebugData* DebugData, bool CheckTF) override;

  void ClearCache() override;

  void ClearRelocations() override {
    Relocations.clear();
  }

private:
  const bool HostSupportsSVE128 {};
  const bool HostSupportsSVE256 {};
  const bool HostSupportsAVX256 {};
  const bool HostSupportsRPRES {};
  const bool HostSupportsAFP {};
  const bool HostSupportsHardwareScalarMerge {};

  struct RestartOptions {
    enum class Control : uint64_t {
      Incoming = 0,
      EnableFarARM64Jumps = 1,
      NeedsLargerJITSpace = 2,
    };
  };

  // FEXCore makes assumptions in the JIT about certain conditions being true.
  // In the rare case when those assumptions are broken, FEX needs to safely restart the JIT.
  RestartOptions RestartControl {};
  bool RequiresFarARM64Jumps {};
#ifdef ARCHITECTURE_arm64ec
  // Only uncached single-instruction code generated while guest DR is armed.
  bool MRGuestDebugSingleInstruction {};
#endif
  // Default to 6 instructions per SSA node.
  uint32_t SSANodeMultiplier {24};

  ARMEmitter::BiDirectionalLabel* PendingTargetLabel {};
  std::optional<uint64_t> PendingSuspendRIP {};
  bool GuestTargetSuspendChecks {};
  bool CurrentBlockHasGuestBoundary {};
  ARMEmitter::ForwardLabel LoopDispatcherLabel;
  fextl::vector<uint64_t> PendingLoopLinkRecords;
  struct PendingGuestSuspendTrap {
    uint64_t GuestOffset;
    ARMEmitter::ForwardLabel Label;
  };
  fextl::vector<PendingGuestSuspendTrap> PendingGuestSuspendTraps;
  // X87-CTX P5: fault records of the block being compiled. A marker opens one; it is kept once its target op is emitted.
  fextl::vector<FEXCore::Core::X87Fault::Record> X87FaultRecords;
  FEXCore::Core::X87Fault::Record X87FaultOpen {};
  uint32_t X87FaultOpenTarget {};
  bool X87FaultIsOpen {};
  // TRANS32 PC_EXACT: lr is parked in Pointers.X87PCXSavedLR across a run of x87 stub calls; restored before any other op.
  bool X87PCXLRSaved {};
  // TRANS32 PC_EXACT: the current run calls a stub whose host arithmetic can raise FPSR status (arithmetic, fst m32).
  bool X87PCXRunRaises {};
  bool X87PCXRunRecorded {}; // TRANS32 PC_EXACT: this run already entered a FPSR-recording stub
  bool X87PCXUnitS {};
  uint64_t MRCallInfo {};     // TRANS32 GUARD_SKIP: the current block's call info (1 << 31 | mode | shape << 8), 0 = unknown
  bool MRGuardNoSpill {};     // TRANS32 GUARD_SKIP: the guard is emitted before the spill area is allocated
  bool MRUnitPCX {};          // TRANS32 GUARD_SKIP: this unit is PC_EXACT
  void MRModeWordRefresh();   // TRANS32 MODE_WORD (JIT/MemoryOps.cpp)
  void MRModeWordAfterGPRStore(uint32_t Offset, uint32_t Bytes, ARMEmitter::Register Src);
  bool MRSkipHeaderStore {};  // TRANS32 GUARD_SKIP: EmitEntryPoint without the header store (done on both paths before)       // TRANS32 PC_EXACT: unit mode, no internal back-edge -> S stubs, saturating entry, inline exit check
  // TRANS32 PC_EXACT unit mode (lazy MXCSR): the unit raises FPSR in x87 stubs and has no SSE status writer and no native
  // transition inside; FPSR is recorded once by the entry checks of its entry blocks and checked once before each exit.
  bool X87PCXUnitFpsr {};
  bool X87PCXDynChecked {}; // X87EXACT DYN: arithmetic / fst m32 sites enter the stubs through the word check
  // X87EXACT S32 (Interface/Core/HBX87S32.h): cold parts of the unit's typed forms, emitted after its last block
  // (Interface/Core/HBX87S32Cold.inl). Enter: the form's failed checks; Back: behind the form. EnterPost (arithmetic, Post != 0):
  // the failed range check of the host result where a +-0 result is exact -- Post 1: the result is in VTMP1, 2: in Dst already.
  struct S32ColdSite {
    enum : uint8_t { Load, Store, Arith, First };
    ARMEmitter::ForwardLabel Enter, EnterPost;
    ARMEmitter::BackwardLabel Back;
    uint8_t Kind {}, Sub {}, A {}, B {}, Dst {}, Post {};
  };
  fextl::vector<S32ColdSite> S32ColdSites;
  bool X87PCXBlockIsEntry {};
  void EmitLoopCacheExit(bool NonzeroGuestRIP);
  ARMEmitter::BiDirectionalLabel* PendingCallReturnTargetLabel {};
  FEXCore::Context::ContextImpl* CTX {};
  const FEXCore::IR::IRListView* IR {};
  uint64_t Entry {};
  CPUBackend::CompiledCode CodeData {};

  fextl::vector<ARMEmitter::BiDirectionalLabel> JumpTargets;

  ARMEmitter::BiDirectionalLabel* JumpTarget(IR::OrderedNodeWrapper Node) {
    auto Block = IR->GetOp<IR::IROp_CodeBlock>(Node);
    return &JumpTargets[Block->ID];
  }
  // TRANS32 0030 (JIT.cpp): per-edge guard targets. MRGuardInfo[ID] = 1 << 31 | guard shape (0x1FF) for a block whose first op is a
  // guard; MRKnownInfo[ID] = 1 << 31 | end shape (0x1FF) for a block whose mode is known at its end (marker 0x20).
  bool MRGEOn {};
  uint32_t MRCurBlock {};
  fextl::vector<ARMEmitter::BiDirectionalLabel> MRGuardLabels;
  fextl::vector<uint32_t> MRGuardInfo, MRKnownInfo;
  fextl::vector<bool> MRNeedGL;
  bool MRSkipOK(uint32_t From, uint32_t To) const {
    if (!(MRKnownInfo[From] >> 31)) return false;
    if (!(MRGuardInfo[To] & 0x100)) return true;
    return (MRKnownInfo[From] & 0x100) && (MRKnownInfo[From] & 0xFF) == (MRGuardInfo[To] & 0xFF);
  }
  ARMEmitter::BiDirectionalLabel* MRBranchTarget(IR::OrderedNodeWrapper Node) {
    auto Block = IR->GetOp<IR::IROp_CodeBlock>(Node);
    if (MRGEOn && (MRGuardInfo[Block->ID] >> 31) && !MRSkipOK(MRCurBlock, Block->ID)) return &MRGuardLabels[Block->ID];
    return &JumpTargets[Block->ID];
  }

  fextl::map<IR::NodeID, ARMEmitter::BiDirectionalLabel> CallReturnTargets;

  struct PendingJumpThunk {
    uint64_t CallerAddress;
    uint64_t GuestRIP;
    ARMEmitter::ForwardLabel Label;
    uint64_t CallInfo {}; // TRANS32 GUARD_SKIP: one more record word (the caller's mode / shape at a call)
  };
  fextl::vector<PendingJumpThunk> PendingJumpThunks;

  Utils::PoolBufferWithTimedRetirement<uint8_t*, 5000, 500> TempCodeBufferAllocator;

  static uint64_t ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, FEXCore::Context::ExitFunctionLinkData* Record);

  [[nodiscard]]
  ARMEmitter::Register GetReg(IR::PhysicalRegister Reg) const {
    const auto RegClass = Reg.AsRegClass();

    LOGMAN_THROW_A_FMT(RegClass == IR::RegClass::GPRFixed || RegClass == IR::RegClass::GPR, "Unexpected Class: {}", Reg.Class);

    if (RegClass == IR::RegClass::GPRFixed) {
      return StaticRegisters[Reg.Reg];
    } else if (RegClass == IR::RegClass::GPR) {
      return GeneralRegisters[Reg.Reg];
    }

    FEX_UNREACHABLE;
  }

  [[nodiscard]]
  ARMEmitter::Register GetReg(IR::Ref Node) const {
    return GetReg(IR::PhysicalRegister(Node));
  }

  [[nodiscard]]
  ARMEmitter::Register GetReg(IR::OrderedNodeWrapper Wrap) const {
    return GetReg(IR::PhysicalRegister(Wrap));
  }

  [[nodiscard]]
  ARMEmitter::VRegister GetVReg(IR::PhysicalRegister Reg) const {
    const auto RegClass = Reg.AsRegClass();

    LOGMAN_THROW_A_FMT(RegClass == IR::RegClass::FPRFixed || RegClass == IR::RegClass::FPR, "Unexpected Class: {}", Reg.Class);

    if (RegClass == IR::RegClass::FPRFixed) {
      return StaticFPRegisters[Reg.Reg];
    } else if (RegClass == IR::RegClass::FPR) {
      return GeneralFPRegisters[Reg.Reg];
    }

    FEX_UNREACHABLE;
  }

  [[nodiscard]]
  ARMEmitter::VRegister GetVReg(IR::Ref Node) const {
    return GetVReg(IR::PhysicalRegister(Node));
  }

  [[nodiscard]]
  ARMEmitter::VRegister GetVReg(IR::OrderedNodeWrapper Wrap) const {
    return GetVReg(IR::PhysicalRegister(Wrap));
  }

  [[nodiscard]]
  static IR::RegClass GetRegClass(IR::Ref Node) {
    return IR::PhysicalRegister(Node).AsRegClass();
  }

  [[nodiscard]]
  ARMEmitter::Register GetZeroableReg(IR::OrderedNodeWrapper Src) const {
    uint64_t Const;
    if (IsInlineConstant(Src, &Const)) {
      LOGMAN_THROW_A_FMT(Const == 0, "Only valid constant");
      return ARMEmitter::Reg::zr;
    } else {
      return GetReg(Src);
    }
  }

  // Converts IR-base shift type to ARMEmitter shift type.
  // Will be a no-op, only a type conversion since the two definitions match.
  [[nodiscard]]
  static ARMEmitter::ShiftType ConvertIRShiftType(IR::ShiftType Shift) {
    return Shift == IR::ShiftType::LSL ? ARMEmitter::ShiftType::LSL :
           Shift == IR::ShiftType::LSR ? ARMEmitter::ShiftType::LSR :
           Shift == IR::ShiftType::ASR ? ARMEmitter::ShiftType::ASR :
                                         ARMEmitter::ShiftType::ROR;
  }

  [[nodiscard]]
  static ARMEmitter::Size ConvertSize(const IR::IROp_Header* Op) {
    return Op->Size == IR::OpSize::i64Bit ? ARMEmitter::Size::i64Bit : ARMEmitter::Size::i32Bit;
  }

  [[nodiscard]]
  static ARMEmitter::Size ConvertSize48(const IR::IROp_Header* Op) {
    LOGMAN_THROW_A_FMT(Op->Size == IR::OpSize::i32Bit || Op->Size == IR::OpSize::i64Bit, "Invalid size");
    return ConvertSize(Op);
  }

  [[nodiscard]]
  static ARMEmitter::Size ConvertSize(IR::OpSize Size) {
    return Size == IR::OpSize::i64Bit ? ARMEmitter::Size::i64Bit : ARMEmitter::Size::i32Bit;
  }

  [[nodiscard]]
  static ARMEmitter::SubRegSize ConvertSubRegSize16(IR::OpSize ElementSize) {
    LOGMAN_THROW_A_FMT(ElementSize == IR::OpSize::i8Bit || ElementSize == IR::OpSize::i16Bit || ElementSize == IR::OpSize::i32Bit ||
                         ElementSize == IR::OpSize::i64Bit || ElementSize == IR::OpSize::i128Bit,
                       "Invalid size");
    return ElementSize == IR::OpSize::i8Bit  ? ARMEmitter::SubRegSize::i8Bit :
           ElementSize == IR::OpSize::i16Bit ? ARMEmitter::SubRegSize::i16Bit :
           ElementSize == IR::OpSize::i32Bit ? ARMEmitter::SubRegSize::i32Bit :
           ElementSize == IR::OpSize::i64Bit ? ARMEmitter::SubRegSize::i64Bit :
                                               ARMEmitter::SubRegSize::i128Bit;
  }

  [[nodiscard]]
  static ARMEmitter::SubRegSize ConvertSubRegSize16(const IR::IROp_Header* Op) {
    return ConvertSubRegSize16(Op->ElementSize);
  }

  [[nodiscard]]
  static ARMEmitter::SubRegSize ConvertSubRegSize8(IR::OpSize ElementSize) {
    LOGMAN_THROW_A_FMT(ElementSize != IR::OpSize::i128Bit, "Invalid size");
    return ConvertSubRegSize16(ElementSize);
  }

  [[nodiscard]]
  static ARMEmitter::SubRegSize ConvertSubRegSize8(const IR::IROp_Header* Op) {
    return ConvertSubRegSize8(Op->ElementSize);
  }

  [[nodiscard]]
  static ARMEmitter::SubRegSize ConvertSubRegSize4(const IR::IROp_Header* Op) {
    LOGMAN_THROW_A_FMT(Op->ElementSize != IR::OpSize::i64Bit, "Invalid size");
    return ConvertSubRegSize8(Op);
  }

  [[nodiscard]]
  static ARMEmitter::SubRegSize ConvertSubRegSize248(const IR::IROp_Header* Op) {
    LOGMAN_THROW_A_FMT(Op->ElementSize != IR::OpSize::i8Bit, "Invalid size");
    return ConvertSubRegSize8(Op);
  }

  [[nodiscard]]
  static ARMEmitter::VectorRegSizePair ConvertSubRegSizePair16(const IR::IROp_Header* Op) {
    return ARMEmitter::ToVectorSizePair(ConvertSubRegSize16(Op));
  }

  [[nodiscard]]
  static ARMEmitter::VectorRegSizePair ConvertSubRegSizePair8(const IR::IROp_Header* Op) {
    LOGMAN_THROW_A_FMT(Op->ElementSize != IR::OpSize::i128Bit, "Invalid size");
    return ConvertSubRegSizePair16(Op);
  }

  [[nodiscard]]
  static ARMEmitter::VectorRegSizePair ConvertSubRegSizePair248(const IR::IROp_Header* Op) {
    LOGMAN_THROW_A_FMT(Op->ElementSize != IR::OpSize::i8Bit, "Invalid size");
    return ConvertSubRegSizePair8(Op);
  }

  [[nodiscard]]
  static ARMEmitter::Condition MapCC(IR::CondClass Cond) {
    switch (Cond) {
    case IR::CondClass::EQ: return ARMEmitter::Condition::CC_EQ;
    case IR::CondClass::NEQ: return ARMEmitter::Condition::CC_NE;
    case IR::CondClass::SGE: return ARMEmitter::Condition::CC_GE;
    case IR::CondClass::SLT: return ARMEmitter::Condition::CC_LT;
    case IR::CondClass::SGT: return ARMEmitter::Condition::CC_GT;
    case IR::CondClass::SLE: return ARMEmitter::Condition::CC_LE;
    case IR::CondClass::UGE: return ARMEmitter::Condition::CC_CS;
    case IR::CondClass::ULT: return ARMEmitter::Condition::CC_CC;
    case IR::CondClass::UGT: return ARMEmitter::Condition::CC_HI;
    case IR::CondClass::ULE: return ARMEmitter::Condition::CC_LS;
    case IR::CondClass::FLU: return ARMEmitter::Condition::CC_LT;
    case IR::CondClass::FGE: return ARMEmitter::Condition::CC_GE;
    case IR::CondClass::FLEU: return ARMEmitter::Condition::CC_LE;
    case IR::CondClass::FGT: return ARMEmitter::Condition::CC_GT;
    case IR::CondClass::FU:
    case IR::CondClass::VS: return ARMEmitter::Condition::CC_VS;
    case IR::CondClass::FNU:
    case IR::CondClass::VC: return ARMEmitter::Condition::CC_VC;
    case IR::CondClass::MI: return ARMEmitter::Condition::CC_MI;
    case IR::CondClass::PL: return ARMEmitter::Condition::CC_PL;
    default: LOGMAN_MSG_A_FMT("Unsupported compare type"); return ARMEmitter::Condition::CC_NV;
    }
  }

  [[nodiscard]]
  static bool IsFPR(IR::RegClass Class) {
    return Class == IR::RegClass::FPR || Class == IR::RegClass::FPRFixed;
  }

  [[nodiscard]]
  static bool IsGPR(IR::RegClass Class) {
    return Class == IR::RegClass::GPR || Class == IR::RegClass::GPRFixed;
  }

  [[nodiscard]]
  static bool IsGPR(IR::Ref Node) {
    return IsGPR(GetRegClass(Node));
  }

  [[nodiscard]]
  static bool IsFPR(IR::Ref Node) {
    return IsFPR(GetRegClass(Node));
  }

  [[nodiscard]]
  static bool IsGPR(IR::OrderedNodeWrapper Wrap) {
    return IsGPR(IR::PhysicalRegister(Wrap).AsRegClass());
  }

  [[nodiscard]]
  static bool IsFPR(IR::OrderedNodeWrapper Wrap) {
    return IsFPR(IR::PhysicalRegister(Wrap).AsRegClass());
  }

  [[nodiscard]]
  ARMEmitter::ExtendedMemOperand GenerateMemOperand(IR::OpSize AccessSize, ARMEmitter::Register Base, IR::OrderedNodeWrapper Offset,
                                                    IR::MemOffsetType OffsetType, uint8_t OffsetScale);

  [[nodiscard]]
  ARMEmitter::Register ApplyMemOperand(IR::OpSize AccessSize, ARMEmitter::Register Base, ARMEmitter::Register Tmp,
                                       IR::OrderedNodeWrapper Offset, IR::MemOffsetType OffsetType, uint8_t OffsetScale);

  // NOTE: Will use TMP1 as a way to encode immediates that happen to fall outside
  //       the limits of the scalar plus immediate variant of SVE load/stores.
  //
  //       TMP1 is safe to use again once this memory operand is used with its
  //       equivalent loads or stores that this was called for.
  [[nodiscard]]
  ARMEmitter::SVEMemOperand GenerateSVEMemOperand(IR::OpSize AccessSize, ARMEmitter::Register Base, IR::OrderedNodeWrapper Offset,
                                                  IR::MemOffsetType OffsetType, uint8_t OffsetScale);

  [[nodiscard]]
  bool IsInlineConstant(const IR::OrderedNodeWrapper& Node, uint64_t* Value = nullptr) const;
  [[nodiscard]]
  bool IsInlineEntrypointOffset(const IR::OrderedNodeWrapper& WNode, uint64_t* Value) const;

  struct LiveRange {
    uint32_t Begin;
    uint32_t End;
  };

  void EmitLinkedBranch(uint64_t GuestRIP, bool Call) {
    PendingJumpThunks.push_back({GetCursorAddress<uint64_t>(), GuestRIP, {}, Call ? MRCallInfo : 0});
    auto& Thunk = PendingJumpThunks.back();
    BindOrRestart(&Thunk.Label);
    if (Call) {
      bl_OrRestart(&Thunk.Label);
    } else {
      b_OrRestart(&Thunk.Label);
    }
  }

  // Restart helpers
  template<ARMEmitter::IsLabel T>
  void bl_OrRestart(T* Label) {
    if (bl(Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    // We can support this but currently unnecessary.
    ERROR_AND_DIE_FMT("Tried to branch larger than 128MB away!");
    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void b_OrRestart(T* Label) {
    if (b(Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    // We can support this but currently unnecessary.
    ERROR_AND_DIE_FMT("Tried to branch larger than 128MB away!");
    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void b_OrRestart(ARMEmitter::Condition Cond, T* Label) {
    if (RequiresFarARM64Jumps) {
      ARMEmitter::ForwardLabel Skip {};
      // Wrap a manual Cond check around an unconditional branch; this can encode larger offsets
      (void)b(InvertCondition(Cond), &Skip);
      if (b(Label) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("Tried to branch larger than 128MB away!");
      }

      (void)Bind(&Skip);
      return;
    }

    if (b(Cond, Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void cbz_OrRestart(ARMEmitter::Size s, ARMEmitter::Register rt, T* Label) {
    if (RequiresFarARM64Jumps) {
      ARMEmitter::ForwardLabel Skip {};
      // Wrap a manual Cond check around an unconditional branch; this can encode larger offsets
      (void)cbnz(s, rt, &Skip);
      if (b(Label) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("Tried to branch larger than 128MB away!");
      }

      (void)Bind(&Skip);
      return;
    }

    if (cbz(s, rt, Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void cbnz_OrRestart(ARMEmitter::Size s, ARMEmitter::Register rt, T* Label) {
    if (RequiresFarARM64Jumps) {
      ARMEmitter::ForwardLabel Skip {};
      // Wrap a manual Cond check around an unconditional branch; this can encode larger offsets
      (void)cbz(s, rt, &Skip);
      if (b(Label) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("Tried to branch larger than 128MB away!");
      }

      (void)Bind(&Skip);
      return;
    }

    if (cbnz(s, rt, Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void tbz_OrRestart(ARMEmitter::Register rt, uint32_t Bit, T* Label) {
    if (RequiresFarARM64Jumps) {
      ARMEmitter::ForwardLabel Skip {};
      // Wrap a manual Cond check around an unconditional branch; this can encode larger offsets
      (void)tbnz(rt, Bit, &Skip);
      if (b(Label) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("Tried to branch larger than 128MB away!");
      }

      (void)Bind(&Skip);
      return;
    }

    if (tbz(rt, Bit, Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void tbnz_OrRestart(ARMEmitter::Register rt, uint32_t Bit, T* Label) {
    if (RequiresFarARM64Jumps) {
      ARMEmitter::ForwardLabel Skip {};
      // Wrap a manual Cond check around an unconditional branch; this can encode larger offsets
      (void)tbz(rt, Bit, &Skip);
      if (b(Label) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("Tried to branch larger than 128MB away!");
      }

      (void)Bind(&Skip);
      return;
    }

    if (tbnz(rt, Bit, Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void adr_OrRestart(ARMEmitter::Register rd, T* Label) {
    if (RequiresFarARM64Jumps) {
      if (LongAddressGen(rd, Label) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("Unable to encode long ADR.");
      }
      return;
    }
    if (adr(rd, Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void adrp_OrRestart(ARMEmitter::Register rd, T* Label) {
    if (RequiresFarARM64Jumps) {
      if (LongAddressGen(rd, Label) == ARMEmitter::BranchEncodeSucceeded::Failure) {
        ERROR_AND_DIE_FMT("Unable to encode long ADRP.");
      }
      return;
    }
    if (adrp(rd, Label) == ARMEmitter::BranchEncodeSucceeded::Success) {
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  template<ARMEmitter::IsLabel T>
  void BindOrRestart(T* Label) {
    if (Bind(Label)) {
      return;
    }

    if (RequiresFarARM64Jumps) {
      // This should have been caught before this point.
      ERROR_AND_DIE_FMT("Unhandled long bind");
      return;
    }

    FEXCore::UncheckedLongJump::LongJump(ThreadState->RestartJump, FEXCore::ToUnderlying(RestartOptions::Control::EnableFarARM64Jumps));
  }

  IR::RegisterAllocationPass* RAPass {};
  FEXCore::Core::DebugData* DebugData {};

  void ResetStack();
  /**
   * @name Relocations
   * @{ */

  /**
   * @brief A literal pair relocation object for named symbol literals
   */
  struct NamedSymbolLiteralPair {
    ARMEmitter::ForwardLabel Loc;
    uint64_t Lit;
    Relocation MoveABI {};
  };

  /**
   * @brief Inserts a thunk relocation
   *
   * @param Reg - The GPR to move the thunk handler in to
   * @param Sum - The hash of the thunk
   */
  void InsertNamedThunkRelocation(ARMEmitter::Register Reg, const IR::SHA256Sum& Sum);

  /**
   * @brief Inserts a guest GPR move relocation
   *
   * @param Reg - The GPR to move the guest RIP in to
   * @param Constant - The guest RIP that will be relocated
   */
  void InsertGuestRIPMove(ARMEmitter::Register Reg, uint64_t Constant);

  /**
   * @brief Inserts a named symbol as a literal in memory
   *
   * Need to use `PlaceNamedSymbolLiteral` with the return value to place the literal in the desired location
   *
   * @param Op The named symbol to place
   *
   * @return A temporary `NamedSymbolLiteralPair`
   */
  NamedSymbolLiteralPair InsertNamedSymbolLiteral(FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op);

  /**
   * @brief Inserts a relocation for a constant value relative to the guest entrypoint
   *
   * @param Reg - The GPR to move the guest RIP in to
   * @param Constant - The guest RIP that will be relocated
   */
  NamedSymbolLiteralPair InsertGuestRIPLiteral(uint64_t GuestRIP);

  /**
   * @brief Place the named symbol literal relocation in memory
   *
   * @param Lit - Which literal to place
   */
  void PlaceNamedSymbolLiteral(NamedSymbolLiteralPair Lit);

  // ★ MacRunner FEXXFER, TRANS32 port to the WOW64 translator (FEXCore/Utils/MacRunnerXfer.h); empty / false with every key 0.
  // Code block ids that are a CALL's return block (RET_NOPOLL).
  fextl::vector<bool> MRReturnBlocks;
  bool MRRetNoPollActive {};
  // HEADER_BY_PC mode 1 in effect for this compile: entries do not store InlineJITBlockHeader (MRHeaderByPC.h).
  bool MRHeaderLazy {};
  // RET_NOPOLL: per return block, the out-of-line polled entry stub (registered as the block's entry point) and its body label.
  struct MRRetEntryStub {
    uint64_t GuestRIP;
    uint64_t GuestOffset;
    ARMEmitter::BiDirectionalLabel Body;
  };
  std::list<MRRetEntryStub> MRRetEntryStubs;
  void MREmitSpillAllocation();
  // PARITY32 HOT_FALLTHROUGH (MacRunnerXfer.h): the mask in effect for this compile and the out-of-line miss stubs
  // (std::list keeps labels in place). Ret: `mov TMP3, rip; ldr; add; br` to the dispatcher's shared probe. Jmp: `str rip; b veneer`.
  // Call: dispatcher + RIP, then back after the cbnz.
  unsigned MRHotFallthrough {};
  // CALLRET4 MACRUNNER_FEX32_STACK_ENGINE (MacRunnerXfer.h): state of the current IR block. Based: x19 = ESP at the start of the run,
  // x8 = x19 + MRSEDelta. Aliases: registers that hold a copy of ESP made by RMWHandle (`ret imm`), each = x19 + its delta.
  bool MRStackEngine {};
  bool MRSEBased {};
  int32_t MRSEDelta {};
  struct MRSEAliasT {
    uint8_t Reg;
    int32_t Delta;
    bool Dirty; // the register itself was not updated after a pop through it (emitted only if something else reads it)
  };
  MRSEAliasT MRSEAlias[2] {};
  unsigned MRSEAliases {};
  bool MRStackEngineOp(IR::Ref BlockNode, const IR::IROp_Header* IROp, IR::Ref Node);
  // folded form (key value 4): plan of the current run
  bool MRStackFold {};
  unsigned MRSFKind {};      // 0 none, 1 pushes, 2 pops
  unsigned MRSFEvents {};    // handled operations still to come
  int32_t MRSFDelta {};      // architectural ESP - ESP at the start of the run, before the next step
  int32_t MRSFTotal {};      // the same after the whole run
  bool MRSFFirstPop {};
  uint8_t MRSFAlias {0xFF};  // register of the copy of ESP made for `ret imm` (never materialised inside the run)
  bool MRStackFoldOp(IR::Ref BlockNode, const IR::IROp_Header* IROp, IR::Ref Node);
  // architectural ESP - host x8 right now (0 outside a run): pushes move ESP below the x8 of the run's start; a run of pops has
  // moved x8 to its final value with the first pop
  int64_t MRSFBias() const {
    if (!MRSFEvents || !MRSFKind) {
      return 0;
    }
    return MRSFKind == 1 ? MRSFDelta : (MRSFFirstPop ? 0 : MRSFDelta - MRSFTotal);
  }
  bool MRSFPlan(IR::Ref BlockNode, IR::Ref From);
  unsigned MRSECountAhead(IR::Ref BlockNode, IR::Ref From);
  void MRSEEnd(bool Flush = true);
  uint32_t MRRetMissDelta {};              // dispatcher's shared return-miss probe - Pointers.ExitFunctionLinker (0 = not emitted)
  struct MRMissStub {
    ARMEmitter::ForwardLabel Miss;
    ARMEmitter::BiDirectionalLabel Back;
    uint32_t RipIdx;
  };
  std::list<MRMissStub> MRRetMissStubs, MRJmpMissStubs, MRCallMissStubs;
  ARMEmitter::ForwardLabel MRDispVeneer;   // the unit's `ldr TMP2, DispatcherLoopTop; br TMP2`
  // PARITY32 ICALL_IC v2: per indirect-call site the out-of-line miss stub (`bl veneer; b Ret`) followed by its 8-byte pair literal.
  struct MRICSite {
    ARMEmitter::ForwardLabel Miss;         // cbnz from the inline check (and the pair's initial host offset: an empty pair "hits" here)
    ARMEmitter::ForwardLabel Pair;         // the 64-bit {guest, host offset} literal (right after the stub's `b Ret`, 8-byte aligned)
    uint8_t* ReturnAddr;                   // l_CallReturn of the site (temp buffer address)
  };
  std::list<MRICSite> MRICSites;
  ARMEmitter::ForwardLabel MRICVeneer;     // the unit's `ldr TMP1, ExitFunctionLinker; add TMP1, #delta; br TMP1`
  uint32_t MRICDelta {};                   // dispatcher's shared IC stub - Pointers.ExitFunctionLinker
  bool MRICActive {};
  bool MRICAll {};                         // mode 1: every indirect call with a return block; mode 2: only the exits in MRICAbsExits
  fextl::vector<uint32_t> MRICAbsExits;    // IR ids of the ExitFunction ops whose target was loaded from a constant address
  unsigned MRRetNoPollMode {};             // PARITY32: MacRunnerRetNoPollMode() while MRRetNoPollActive, else 0

  fextl::vector<FEXCore::CPU::Relocation> Relocations;

  /**
   * Returns any relocations generated since the last call to TakeRelocations.
   *
   * GuestBaseAddress must match the base virtual address to which the
   * input x86 binary is mapped.
   */
  fextl::vector<FEXCore::CPU::Relocation> TakeRelocations(uint64_t GuestBaseAddress) override;

  /**  @} */

  uint32_t SpillSlots {};
  using OpType = void (Arm64JITCore::*)(const IR::IROp_Header* IROp, IR::Ref Node);

  using ScalarFMAOpCaller =
    std::function<void(ARMEmitter::VRegister Dst, ARMEmitter::VRegister Src1, ARMEmitter::VRegister Src2, ARMEmitter::VRegister Src3)>;
  void VFScalarFMAOperation(IR::OpSize OpSize, IR::OpSize ElementSize, ScalarFMAOpCaller ScalarEmit, ARMEmitter::VRegister Dst,
                            ARMEmitter::VRegister Upper, ARMEmitter::VRegister Vector1, ARMEmitter::VRegister Vector2,
                            ARMEmitter::VRegister Addend);
  using ScalarBinaryOpCaller = std::function<void(ARMEmitter::VRegister Dst, ARMEmitter::VRegister Src1, ARMEmitter::VRegister Src2)>;
  void VFScalarOperation(IR::OpSize OpSize, IR::OpSize ElementSize, bool ZeroUpperBits, ScalarBinaryOpCaller ScalarEmit,
                         ARMEmitter::VRegister Dst, ARMEmitter::VRegister Vector1, ARMEmitter::VRegister Vector2,
                         bool AllowHardwareScalarMerge = false);
  using ScalarUnaryOpCaller = std::function<void(ARMEmitter::VRegister Dst, std::variant<ARMEmitter::VRegister, ARMEmitter::Register> SrcVar)>;
  void VFScalarUnaryOperation(IR::OpSize OpSize, IR::OpSize ElementSize, bool ZeroUpperBits, ScalarUnaryOpCaller ScalarEmit,
                              ARMEmitter::VRegister Dst, ARMEmitter::VRegister Vector1,
                              std::variant<ARMEmitter::VRegister, ARMEmitter::Register> Vector2);

  void Emulate128BitGather(IR::OpSize Size, IR::OpSize ElementSize, ARMEmitter::VRegister Dst, ARMEmitter::VRegister IncomingDst,
                           std::optional<ARMEmitter::Register> BaseAddr, ARMEmitter::VRegister VectorIndexLow,
                           std::optional<ARMEmitter::VRegister> VectorIndexHigh, ARMEmitter::VRegister MaskReg, IR::OpSize VectorIndexSize,
                           size_t DataElementOffsetStart, size_t IndexElementOffsetStart, uint8_t OffsetScale, IR::OpSize AddrSize);

  void EmitTFCheck();

  void EmitSuspendInterruptCheck();
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
  void EmitSuspendInterruptFaultCheck(bool PublishedContinuation);
  // REGION4-0005 MACRUNNER_FEX32_POLL_ON_SHADOW (MacRunnerSuspend.h): polls of jump exits (calls / returns poll through x25)
  bool MRShadowPollOn() const;
  void MREmitShadowExitPoll(uint64_t GuestRIP);
  void MREmitShadowExitPollReg(ARMEmitter::Register GuestRIP);
#endif
  void EmitSuspendInterruptCheckAt(uint64_t GuestRIP);
  void EmitSuspendInterruptCheckAt(ARMEmitter::Register GuestRIP);

  void EmitEntryPoint(ARMEmitter::BackwardLabel& HeaderLabel, bool CheckTF, uint64_t GuestRIP);

#define DEF_OP(x) void Op_##x(IR::IROp_Header const* IROp, IR::Ref Node)

  ///< Unhandled handler
  DEF_OP(Unhandled);

  ///< No-op Handler
  DEF_OP(NoOp);

#define IROP_DISPATCH_DEFS
#include <FEXCore/IR/IRDefines_Dispatch.inc>
#undef DEF_OP
};

#define DEF_OP(x) void Arm64JITCore::Op_##x(IR::IROp_Header const* IROp, IR::Ref Node)

[[nodiscard]]
fextl::unique_ptr<CPUBackend> CreateArm64JITCore(FEXCore::Context::ContextImpl* ctx, FEXCore::Core::InternalThreadState* Thread);

} // namespace FEXCore::CPU
