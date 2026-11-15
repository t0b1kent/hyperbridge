// SPDX-License-Identifier: MIT
/*
$info$
tags: ir|opts
$end_info$
*/

#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/MacRunnerLazyMXCSR.h>
#include "Interface/Core/HBX87StateGates.h" // TRANS32 0033
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/MacRunnerSuspend.h>
#include <FEXCore/Utils/MacRunnerXfer.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/fextl/deque.h>
#include <FEXCore/fextl/vector.h>

#include <cstdlib>
#include <cstring>

// Flag bit flags
#define FLAG_V (1U << 0)
#define FLAG_C (1U << 1)
#define FLAG_Z (1U << 2)
#define FLAG_N (1U << 3)
#define FLAG_P (1U << 4)
#define FLAG_A (1U << 5)

#define FLAG_ZCV (FLAG_Z | FLAG_C | FLAG_V)
#define FLAG_NZCV (FLAG_N | FLAG_ZCV)
#define FLAG_ALL (FLAG_NZCV | FLAG_A | FLAG_P)

namespace FEXCore::IR {

struct FlagInfoUnpacked {
  // Set of flags read by the instruction.
  unsigned Read;

  // Set of flags written by the instruction. Happens AFTER the reads.
  unsigned Write;

  // If true, the instruction can be be eliminated if its flag writes can all be
  // eliminated.
  bool CanEliminate;

  // If set, the opcode can be replaced with Replacement if its flag writes can
  // all be eliminated, or ReplacementNoWrite if its register write can be
  // eliminated.
  IROps Replacement;
  IROps ReplacementNoWrite;

  // Needs speical handling
  bool Special;
};

struct FlagInfo {
  uint64_t Raw;

  static constexpr struct FlagInfo Pack(struct FlagInfoUnpacked F) {
    uint64_t R = F.Read | (F.Write << 8) | (F.CanEliminate << 16) | (((uint64_t)F.Replacement) << 32) |
                 ((uint64_t)F.ReplacementNoWrite << 48) | (F.Special ? (1ull << 63) : 0);
    return {.Raw = R};
  }

  bool Trivial() const {
    return Raw == 0;
  }

  unsigned Read() const {
    return Bits(0, 8);
  }

  unsigned Write() const {
    return Bits(8, 8);
  }

  bool CanEliminate() const {
    return Bits(16, 1);
  }

  bool Special() const {
    return Bits(63, 1);
  }

  IROps Replacement() const {
    return (IROps)Bits(32, 16);
  }

  IROps ReplacementNoWrite() const {
    return (IROps)Bits(48, 16);
  }

private:
  unsigned Bits(unsigned Start, unsigned Count) const {
    return (Raw >> Start) & ((1u << Count) - 1);
  }
};

struct BlockInfo {
  fextl::vector<uint32_t> Predecessors;
  Ref Node;
  uint8_t Flags;
  bool InWorklist;
  uint32_t EmissionOrder {};
};

struct ControlFlowGraph {
  fextl::vector<BlockInfo> BlockMap;
  IRListView& IR;

  void Init(fextl::deque<uint32_t>& Worklist, uint32_t BlockCount) {
    BlockMap.resize(BlockCount);

    for (unsigned ID = 0; ID < BlockCount; ++ID) {
      // Add the block with conservative flags and already in the worklist.
      auto Info = BlockInfo {{}, nullptr, FLAG_ALL, true};

      // Add some initial capacity
      Info.Predecessors.reserve(2);

      BlockMap[ID] = std::move(Info);
      Worklist.push_back(ID);
    }
  }

  BlockInfo* Get(uint32_t Block) {
    return &BlockMap[Block];
  }

  BlockInfo* Get(IROp_CodeBlock* Block) {
    return &BlockMap[Block->ID];
  }

  BlockInfo* Get(OrderedNodeWrapper Block) {
    return Get(IR.GetOp<IR::IROp_CodeBlock>(Block));
  }

  void RecordEdge(uint32_t From, OrderedNodeWrapper To) {
    auto Info = Get(To);
    Info->Predecessors.push_back(From);
  }

  bool SuspendEdge(IROp_CodeBlock* From, OrderedNodeWrapper To) {
    auto Target = IR.GetOp<IR::IROp_CodeBlock>(To);
    return FEXCore::Utils::MacRunnerSuspendBackedgeExactFlags() &&
           Target->GuestEntryOffset != FEXCore::Utils::NoGuestSuspendBoundary &&
           Get(Target)->EmissionOrder <= Get(From)->EmissionOrder;
  }

  bool SuspendEdge(IROp_CodeBlock* From, const IROp_CondJump* Op) {
    return SuspendEdge(From, Op->TrueBlock) || SuspendEdge(From, Op->FalseBlock);
  }

  void AddWorklist(fextl::deque<uint32_t>& Worklist, uint32_t Block) {
    auto Info = Get(Block);
    if (!Info->InWorklist) {
      Info->InWorklist = true;
      Worklist.push_front(Block);
    }
  }
};

class DeadFlagCalculationEliminination final : public FEXCore::IR::Pass {
public:
  DeadFlagCalculationEliminination() {
    const char* Enabled = std::getenv("MACRUNNER_FEX_PRECISE_MEM_FLAGS");
    PreciseMemoryFlags = Enabled && std::strcmp(Enabled, "1") == 0;
    LazyFPStatus = FEXCore::LazyMXCSR::Enabled.load(std::memory_order_relaxed);
    X87Status = FEXCore::HBX87::StateFix::ExceptionFlags() || FEXCore::HBX87::StateFix::C1Roundup(); // TRANS32 0033
    CmpZC = FEXCore::Utils::MacRunnerCmpZCEnabled();
  }
  void Run(IREmitter* IREmit) override;

private:
  bool CmpZC {};
  static bool ZeroExtendedOperand(IRListView& CurrentIR, OrderedNodeWrapper Arg, OpSize Size, bool* IsConstant, uint64_t* Constant);
  static void NarrowCompareZC(IREmitter* IREmit, IRListView& CurrentIR, Ref CodeNode, IROp_Header* IROp);
  bool PreciseMemoryFlags {};
  // LAZY-FLAGS: under MACRUNNER_FEX_LAZY_MXCSR=1 the host FPSR is the guest MXCSR status, so a
  // guest SSE operation with a dead destination still has an architectural effect (x86 raises
  // the sticky flag anyway). Such IR must not be removed as dead code.
  bool LazyFPStatus {};
  static bool MayRaiseFPStatus(IROps Op);
  // TRANS32 0033: with x87 exception-flag tracking, an x87 operation raises its sticky flags (and sets C1) whether or not its
  // result is used: x87 IR with a dead destination must not be removed (stand/pecheck32b: fdiv; fstp st(0) lost PE).
  bool X87Status {};
  static bool MayRaiseX87Status(IROps Op);
  static bool MayFaultGuestMemory(IROps Op);
  FlagInfo Classify(IROp_Header* Node);
  unsigned FlagsForCondClassType(CondClass Cond);
  bool EliminateDeadCode(IREmitter* IREmit, Ref CodeNode, IROp_Header* IROp);
  void FoldBranch(IREmitter* IREmit, IRListView& CurrentIR, IROp_CondJump* Op, Ref CodeNode, bool PreserveFlags);
  CondClass X86ToArmFloatCond(CondClass X86);
  bool ProcessBlock(IREmitter* IREmit, IRListView& CurrentIR, Ref Block, ControlFlowGraph& CFG);
  void OptimizeParity(IREmitter* IREmit, IRListView& CurrentIR, ControlFlowGraph& CFG);
};

bool DeadFlagCalculationEliminination::MayFaultGuestMemory(IROps Op) {
  // A guest-memory fault observes the architectural flags even when normal
  // control flow overwrites them before its next explicit flag reader.
  // Keep host context/spill/fill accesses and non-faulting prefetch separate.
  switch (Op) {
  case OP_LOADMEM:
  case OP_LOADMEMPAIR:
  case OP_STOREMEM:
  case OP_STOREMEMPAIR:
  case OP_STOREMEMX87SVEOPTPREDICATE:
  case OP_LOADMEMX87SVEOPTPREDICATE:
  case OP_LOADMEMTSO:
  case OP_STOREMEMTSO:
  case OP_VLOADVECTORMASKED:
  case OP_VSTOREVECTORMASKED:
  case OP_VLOADVECTORGATHERMASKED:
  case OP_VLOADVECTORGATHERMASKEDQPS:
  case OP_VLOADVECTORELEMENT:
  case OP_VSTOREVECTORELEMENT:
  case OP_VBROADCASTFROMMEM:
  case OP_PUSH:
  case OP_PUSHTWO:
  case OP_RMWHANDLE:
  case OP_POP:
  case OP_POPTWO:
  case OP_MEMSET:
  case OP_MEMCPY:
  case OP_CACHELINECLEAR:
  case OP_CACHELINECLEAN:
  case OP_CACHELINEZERO:
  case OP_VSTORENONTEMPORAL:
  case OP_VSTORENONTEMPORALPAIR:
  case OP_VLOADNONTEMPORAL:
  case OP_CAS:
  case OP_CASPAIR:
  case OP_ATOMICSWAP:
  case OP_ATOMICFETCHADD:
  case OP_ATOMICFETCHSUB:
  case OP_ATOMICFETCHAND:
  case OP_ATOMICFETCHCLR:
  case OP_ATOMICFETCHOR:
  case OP_ATOMICFETCHXOR:
  case OP_ATOMICFETCHNEG:
    return true;
  default:
    return false;
  }
}

unsigned DeadFlagCalculationEliminination::FlagsForCondClassType(CondClass Cond) {
  switch (Cond) {
  case CondClass::AL: return 0;

  case CondClass::MI:
  case CondClass::PL: return FLAG_N;

  case CondClass::EQ:
  case CondClass::NEQ: return FLAG_Z;

  case CondClass::UGE:
  case CondClass::ULT: return FLAG_C;

  case CondClass::VS:
  case CondClass::VC:
  case CondClass::FU:
  case CondClass::FNU: return FLAG_V;

  case CondClass::UGT:
  case CondClass::ULE: return FLAG_Z | FLAG_C;

  case CondClass::SGE:
  case CondClass::SLT:
  case CondClass::FLU:
  case CondClass::FGE: return FLAG_N | FLAG_V;

  case CondClass::SGT:
  case CondClass::SLE:
  case CondClass::FLEU:
  case CondClass::FGT: return FLAG_N | FLAG_Z | FLAG_V;

  default: LOGMAN_THROW_A_FMT(false, "unknown cond class type"); return FLAG_NZCV;
  }
}

static constexpr FlagInfo ClassifyConst(IROps Op) {
  switch (Op) {
  case OP_ANDWITHFLAGS:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .Replacement = OP_AND,
      .ReplacementNoWrite = OP_TESTNZ,
    });

  case OP_ADDWITHFLAGS:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .Replacement = OP_ADD,
      .ReplacementNoWrite = OP_ADDNZCV,
    });

  case OP_SUBWITHFLAGS:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .Replacement = OP_SUB,
      .ReplacementNoWrite = OP_SUBNZCV,
    });

  case OP_ADCWITHFLAGS:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .Replacement = OP_ADC,
      .ReplacementNoWrite = OP_ADCNZCV,
    });

  case OP_ADCZEROWITHFLAGS:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .Replacement = OP_ADCZERO,
    });

  case OP_SBBWITHFLAGS:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .Replacement = OP_SBB,
      .ReplacementNoWrite = OP_SBBNZCV,
    });

  case OP_SHIFTFLAGS:
    // _ShiftFlags conditionally sets NZCV+PF, which we model here as a
    // read-modify-write. Logically, it also conditionally makes AF undefined,
    // which we model by omitting AF from both Read and Write sets (since
    // "cond ? AF : undef" may be optimized to "AF").
    return FlagInfo::Pack({
      .Read = FLAG_NZCV | FLAG_P,
      .Write = FLAG_NZCV | FLAG_P,
      .CanEliminate = true,
    });

  case OP_ROTATEFLAGS:
    // _RotateFlags conditionally sets CV, again modeled as RMW.
    return FlagInfo::Pack({
      .Read = FLAG_C | FLAG_V,
      .Write = FLAG_C | FLAG_V,
      .CanEliminate = true,
    });

  case OP_RDRAND: return FlagInfo::Pack({.Write = FLAG_NZCV});

  case OP_ADDNZCV:
  case OP_SUBNZCV:
  case OP_TESTNZ:
  case OP_FCMP:
  case OP_FCMPE:
  case OP_STORENZCV:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });

  case OP_AXFLAG:
    // Per the Arm spec, axflag reads Z/V/C but not N. It writes all flags.
    return FlagInfo::Pack({
      .Read = FLAG_ZCV,
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });

  case OP_CMPPAIRZ:
    return FlagInfo::Pack({
      .Write = FLAG_Z,
      .CanEliminate = true,
    });

  case OP_CARRYINVERT:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_C,
      .CanEliminate = true,
    });

  case OP_SETSMALLNZV:
    return FlagInfo::Pack({
      .Write = FLAG_N | FLAG_Z | FLAG_V,
      .CanEliminate = true,
    });

  case OP_LOADNZCV: return FlagInfo::Pack({.Read = FLAG_NZCV});

  case OP_ADC:
  case OP_ADCZERO:
  case OP_SBB: return FlagInfo::Pack({.Read = FLAG_C});

  case OP_ADCNZCV:
  case OP_SBBNZCV:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });

  case OP_LOADPF: return FlagInfo::Pack({.Read = FLAG_P});
  case OP_LOADAF: return FlagInfo::Pack({.Read = FLAG_A});
  case OP_STOREPF: return FlagInfo::Pack({.Write = FLAG_P, .CanEliminate = true});
  case OP_STOREAF: return FlagInfo::Pack({.Write = FLAG_A, .CanEliminate = true});

  case OP_NZCVSELECT:
  case OP_NZCVSELECTV:
  case OP_NZCVSELECTINCREMENT:
  case OP_NEG:
  case OP_CONDJUMP:
  case OP_CONDSUBNZCV:
  case OP_CONDADDNZCV:
  case OP_RMIFNZCV:
  case OP_UDIV:
  case OP_INVALIDATEFLAGS: return FlagInfo::Pack({.Special = true});
  default: return FlagInfo::Pack({});
  }
}

constexpr auto FlagInfos = [] {
  std::array<FlagInfo, OP_LAST> ret = {};

  for (unsigned i = 0; i < OP_LAST; ++i) {
    ret[i] = ClassifyConst(IROps(i));
  }

  return ret;
}();

FlagInfo DeadFlagCalculationEliminination::Classify(IROp_Header* IROp) {
  FlagInfo Info = FlagInfos[IROp->Op];
  if (PreciseMemoryFlags && MayFaultGuestMemory(IROp->Op)) {
    Info.Raw |= FLAG_ALL;
  }
  if (!Info.Special()) {
    return Info;
  }

  switch (IROp->Op) {
  case OP_UDIV: {
    // A checked quotient can fault before its architectural commit. Preserve
    // the complete prefix flags there; ordinary UDIV keeps the old empty mask.
    auto Op = IROp->C<IR::IROp_UDiv>();
    return FlagInfo::Pack({.Read = Op->OverflowBlock.IsInvalid() ? 0u : FLAG_ALL});
  }
  case OP_NZCVSELECT:
  case OP_NZCVSELECTINCREMENT: {
    auto Op = IROp->C<IR::IROp_NZCVSelect>();
    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_NZCVSELECTV: {
    auto Op = IROp->C<IR::IROp_NZCVSelectV>();
    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_NEG: {
    auto Op = IROp->C<IR::IROp_Neg>();
    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_CONDJUMP: {
    auto Op = IROp->C<IR::IROp_CondJump>();
    if (!Op->FromNZCV) {
      return FlagInfo::Pack({});
    }

    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_CONDSUBNZCV:
  case OP_CONDADDNZCV: {
    auto Op = IROp->C<IR::IROp_CondAddNZCV>();
    return FlagInfo::Pack({
      .Read = FlagsForCondClassType(Op->Cond),
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });
  }

  case OP_RMIFNZCV: {
    auto Op = IROp->C<IR::IROp_RmifNZCV>();

    static_assert(FLAG_N == (1 << 3), "rmif mask lines up with our bits");
    static_assert(FLAG_Z == (1 << 2), "rmif mask lines up with our bits");
    static_assert(FLAG_C == (1 << 1), "rmif mask lines up with our bits");
    static_assert(FLAG_V == (1 << 0), "rmif mask lines up with our bits");

    return FlagInfo::Pack({
      .Write = Op->Mask,
      .CanEliminate = true,
    });
  }

  case OP_INVALIDATEFLAGS: {
    auto Op = IROp->C<IR::IROp_InvalidateFlags>();
    unsigned Flags = 0;

    // TODO: Make this translation less silly
    if (Op->Flags & (1u << X86State::RFLAG_SF_RAW_LOC)) {
      Flags |= FLAG_N;
    }

    if (Op->Flags & (1u << X86State::RFLAG_ZF_RAW_LOC)) {
      Flags |= FLAG_Z;
    }

    if (Op->Flags & (1u << X86State::RFLAG_CF_RAW_LOC)) {
      Flags |= FLAG_C;
    }

    if (Op->Flags & (1u << X86State::RFLAG_OF_RAW_LOC)) {
      Flags |= FLAG_V;
    }

    if (Op->Flags & (1u << X86State::RFLAG_PF_RAW_LOC)) {
      Flags |= FLAG_P;
    }

    if (Op->Flags & (1u << X86State::RFLAG_AF_RAW_LOC)) {
      Flags |= FLAG_A;
    }

    // The mental model of InvalidateFlags is writing undefined values to all
    // of the selected flags, allowing the write-after-write optimizations to
    // optimize invalidate-after-write for free.
    return FlagInfo::Pack({
      .Write = Flags,
      .CanEliminate = true,
    });
  }

  default: LOGMAN_THROW_A_FMT(false, "invalid special op"); FEX_UNREACHABLE;
  }

  FEX_UNREACHABLE;
}

// IR lowered to host FP arithmetic, comparison or conversion whose x86 source instruction
// raises MXCSR status. RCP/RSQRT estimates are excluded: x86 raises nothing for them.
bool DeadFlagCalculationEliminination::MayRaiseX87Status(IROps Op) { // TRANS32 0033
  switch (Op) {
  case OP_F80ADD:
  case OP_F80SUB:
  case OP_F80MUL:
  case OP_F80DIV:
  case OP_F80SQRT:
  case OP_F80CVT:
  case OP_F80CVTINT:
  case OP_F80CVTTO:
  case OP_F80CMP:
  case OP_F80CMPQUIET:
  case OP_F80ROUND:
  case OP_F80F2XM1:
  case OP_F80TAN:
  case OP_F80SIN:
  case OP_F80COS:
  case OP_F80SINCOS:
  case OP_F80ATAN:
  case OP_F80FYL2X:
  case OP_F80FYL2XP1:
  case OP_F80FPREM:
  case OP_F80FPREM1:
  case OP_F80SCALE:
  case OP_F80XTRACT_EXP:
  case OP_F80XTRACT_SIG:
  case OP_F80BCDSTORE: return true; // 64-bit line: no PC_EXACT (X87PCX*) IR ops
  default: return false;
  }
}

bool DeadFlagCalculationEliminination::MayRaiseFPStatus(IROps Op) {
  switch (Op) {
  case OP_FCMP:
  case OP_FCMPE:
  case OP_FLOAT_TOGPR_S:
  case OP_FLOAT_TOGPR_ZS:
  case OP_FLOAT_FROMGPR_S:
  case OP_FLOAT_FTOF:
  case OP_VFADDSCALARINSERT:
  case OP_VFSUBSCALARINSERT:
  case OP_VFMULSCALARINSERT:
  case OP_VFDIVSCALARINSERT:
  case OP_VFMINSCALARINSERT:
  case OP_VFMAXSCALARINSERT:
  case OP_VFSQRTSCALARINSERT:
  case OP_VFTOFSCALARINSERT:
  case OP_VSTOFVECTORINSERT:
  case OP_VSTOFGPRINSERT:
  case OP_VFTOISCALARINSERT:
  case OP_VFCMPSCALARINSERT:
  case OP_VFMLASCALARINSERT:
  case OP_VFMLSSCALARINSERT:
  case OP_VFNMLASCALARINSERT:
  case OP_VFNMLSSCALARINSERT:
  case OP_VFSQRT:
  case OP_VFADD:
  case OP_VFADDP:
  case OP_VFADDV:
  case OP_VFSUB:
  case OP_VFMUL:
  case OP_VFDIV:
  case OP_VFMIN:
  case OP_VFMAX:
  case OP_VFCMPEQ:
  case OP_VFCMPNEQ:
  case OP_VFCMPLT:
  case OP_VFCMPGT:
  case OP_VFCMPLE:
  case OP_VFCMPORD:
  case OP_VFCMPUNO:
  case OP_VFCADD:
  case OP_VFMLA:
  case OP_VFMLS:
  case OP_VFNMLA:
  case OP_VFNMLS:
  case OP_VECTOR_STOF:
  case OP_VECTOR_FTOS:
  case OP_VECTOR_FTOZS:
  case OP_VECTOR_FTOF:
  case OP_VFCVTL2:
  case OP_VFCVTN2:
  case OP_VECTOR_FTOI:
  case OP_VECTOR_FTOISIZED:
  case OP_VECTOR_F64TOI32: return true;
  default: return false;
  }
}

// ★ MacRunner FEXXFER MACRUNNER_FEX_CMP_ZC: is the value of Arg zero-extended from Size (no bits above Size)?
// Zero-extending GPR loads of exactly that width (ldrb / ldrh, also the TSO forms) and constants that fit.
bool DeadFlagCalculationEliminination::ZeroExtendedOperand(IRListView& CurrentIR, OrderedNodeWrapper Arg, OpSize Size, bool* IsConstant,
                                                          uint64_t* Constant) {
  const uint64_t Mask = Size == OpSize::i8Bit ? 0xFFULL : (Size == OpSize::i16Bit ? 0xFFFFULL : 0);
  if (!Mask) {
    return false;
  }
  auto Op = CurrentIR.GetOp<IR::IROp_Header>(Arg);
  switch (Op->Op) {
  case OP_LOADMEM: return Op->Size == Size && Op->C<IR::IROp_LoadMem>()->Class == RegClass::GPR;
  case OP_LOADMEMTSO: return Op->Size == Size && Op->C<IR::IROp_LoadMemTSO>()->Class == RegClass::GPR;
  case OP_CONSTANT: {
    const uint64_t Value = static_cast<uint64_t>(Op->C<IR::IROp_Constant>()->Constant);
    if (Value > Mask) {
      return false;
    }
    *IsConstant = true;
    *Constant = Value;
    return true;
  }
  case OP_INLINECONSTANT: {
    const uint64_t Value = static_cast<uint64_t>(Op->C<IR::IROp_InlineConstant>()->Constant);
    if (Value > Mask) {
      return false;
    }
    *IsConstant = true;
    *Constant = Value;
    return true;
  }
  default: return false;
  }
}

// ★ MacRunner FEXXFER MACRUNNER_FEX_CMP_ZC: called for a live SubNZCV of 8/16 bits whose N and V are dead. For zero-extended
// operands the 32-bit difference is zero exactly when the narrow one is, and borrows exactly when the narrow one does, so the
// 32-bit compare gives the same Z and C as the shifted form (the JIT's `lsl #(32-bits)` on both sides). Src2 that is a
// constant up to 4095 becomes an inline immediate (`cmp w, #imm`); a larger constant stays in its register (still exact).
void DeadFlagCalculationEliminination::NarrowCompareZC(IREmitter* IREmit, IRListView& CurrentIR, Ref CodeNode, IROp_Header* IROp) {
  bool Src1Constant = false, Src2Constant = false;
  uint64_t Src1Value = 0, Src2Value = 0;
  if (!ZeroExtendedOperand(CurrentIR, IROp->Args[0], IROp->Size, &Src1Constant, &Src1Value) || Src1Constant) {
    return;
  }
  if (!ZeroExtendedOperand(CurrentIR, IROp->Args[1], IROp->Size, &Src2Constant, &Src2Value)) {
    return;
  }
  if (Src2Constant && Src2Value > 4095 && CurrentIR.GetOp<IR::IROp_Header>(IROp->Args[1])->Op == OP_INLINECONSTANT) {
    return;   // an inline immediate the 32-bit cmp cannot encode
  }
  if (Src2Constant && Src2Value <= 4095) {
    IREmit->SetWriteCursorBefore(CodeNode);
    Ref Imm = IREmit->_InlineConstant(Src2Value);
    IREmit->ReplaceNodeArgument(CodeNode, 1, Imm);
  }
  IROp->Size = OpSize::i32Bit;
}

// General purpose dead code elimination. Returns whether flag handling should
// be skipped (because it was removed or could not possibly affect flags).
bool DeadFlagCalculationEliminination::EliminateDeadCode(IREmitter* IREmit, Ref CodeNode, IROp_Header* IROp) {
  // Can't remove anything used or with side effects.
  if (CodeNode->GetUses() > 0 || IR::HasSideEffects(IROp->Op) ||
      (PreciseMemoryFlags && MayFaultGuestMemory(IROp->Op)) || (LazyFPStatus && MayRaiseFPStatus(IROp->Op)) ||
      (X87Status && MayRaiseX87Status(IROp->Op))) {
    return false;
  }

  IREmit->Remove(CodeNode);
  return true;
}

CondClass DeadFlagCalculationEliminination::X86ToArmFloatCond(CondClass X86) {
  // Table of x86 condition codes that map to arm64 condition codes, in the
  // sense that fcmp+axflag+branch(x86) is equivalent to fcmp+branch(arm).
  //
  // E would be "equal or unordered", no condition code.
  // G would be "greater than or less than", no condition code.
  //
  // SF/OF conditions are trivial and therefore shouldn't actually be generated
  switch (X86) {
  case CondClass::UGE /* A  */: return CondClass::FGE /* GE */;
  case CondClass::UGT /* AE */: return CondClass::FGT /* GT */;
  case CondClass::ULT /* B  */: return CondClass::SLT /* LT */;
  case CondClass::ULE /* BE */: return CondClass::SLE /* LE */;
  case CondClass::SLE /* LE */: return CondClass::SLE /* LE */;
  default: return CondClass::AL;
  }
}

void DeadFlagCalculationEliminination::FoldBranch(IREmitter* IREmit, IRListView& CurrentIR, IROp_CondJump* Op, Ref CodeNode,
                                                bool PreserveFlags) {
  // Skip past StoreRegisters at the end -- they don't touch flags.
  auto PrevWrap = CodeNode->Header.Previous;
  while (CurrentIR.GetOp<IR::IROp_Header>(PrevWrap)->Op == OP_STOREREGISTER ||
         CurrentIR.GetOp<IR::IROp_Header>(PrevWrap)->Op == OP_STOREPF || CurrentIR.GetOp<IR::IROp_Header>(PrevWrap)->Op == OP_STOREAF) {
    PrevWrap = CurrentIR.GetNode(PrevWrap)->Header.Previous;
  }

  auto Prev = CurrentIR.GetOp<IR::IROp_Header>(PrevWrap);
  if (Prev->Op == OP_AXFLAG) {
    // AXFLAG's guest representation is also required by reconstruction.
    if (PreserveFlags) {
      return;
    }
    // Pattern match a branch fed by AXFLAG.
    CondClass ArmCond = X86ToArmFloatCond(Op->Cond);
    if (ArmCond == CondClass::AL) {
      return;
    }

    Op->Cond = ArmCond;
  } else if (Prev->Op == OP_SUBNZCV) {
    // Pattern match a branch fed by a compare. We could also handle bit tests
    // here, but tbz/tbnz has a limited offset range which we don't have a way to
    // deal with yet. Let's hope that's not a big deal.
    if (!(Op->Cond == CondClass::NEQ || Op->Cond == CondClass::EQ) || (Prev->Size < OpSize::i32Bit)) {
      return;
    }

    auto SecondArg = CurrentIR.GetOp<IR::IROp_Header>(Prev->Args[1]);
    if (SecondArg->Op != OP_INLINECONSTANT || SecondArg->C<IR::IROp_InlineConstant>()->Constant != 0) {
      return;
    }

    // We've matched. Fold the compare into branch.
    IREmit->ReplaceNodeArgument(CodeNode, 0, CurrentIR.GetNode(Prev->Args[0]));
    IREmit->ReplaceNodeArgument(CodeNode, 1, CurrentIR.GetNode(Prev->Args[1]));
    Op->FromNZCV = false;
    Op->CompareSize = Prev->Size;
  } else {
    return;
  }

  // The compare/test/axflag sets flags but does not write registers. Flags are
  // dead after the jump. The jump does not read flags anymore.  There is no
  // intervening instruction. Therefore the compare is dead.
  // The branch may still use CBZ/CBNZ, but an asynchronous context reader also
  // consumes flags at a suspend edge. Keep the original guest flag producer.
  if (!PreserveFlags) {
    IREmit->Remove(CurrentIR.GetNode(PrevWrap));
  }
}

/**
 * @brief This pass removes dead code locally.
 */
bool DeadFlagCalculationEliminination::ProcessBlock(IREmitter* IREmit, IRListView& CurrentIR, Ref Block, ControlFlowGraph& CFG) {
  uint32_t FlagsRead = FLAG_ALL;

  // Reverse iteration is not yet working with the iterators
  auto BlockIROp = CurrentIR.GetOp<IR::IROp_CodeBlock>(Block);

  // We grab these nodes this way so we can iterate easily
  auto CodeBegin = CurrentIR.at(BlockIROp->Begin);
  auto CodeLast = CurrentIR.at(BlockIROp->Last);

  // Advance past EndBlock to get at the exit.
  --CodeLast;

  // Initialize the FlagsRead mask according to the exit instruction.
  auto [ExitNode, ExitOp] = CodeLast();
  if (ExitOp->Op == IR::OP_CONDJUMP) {
    auto Op = ExitOp->C<IR::IROp_CondJump>();
    FlagsRead = CFG.Get(Op->TrueBlock)->Flags | CFG.Get(Op->FalseBlock)->Flags;
    if (CFG.SuspendEdge(BlockIROp, Op)) {
      FlagsRead = FLAG_ALL;
    }
  } else if (ExitOp->Op == IR::OP_JUMP) {
    FlagsRead = CFG.Get(ExitOp->Args[0])->Flags;
    if (CFG.SuspendEdge(BlockIROp, ExitOp->Args[0])) {
      FlagsRead = FLAG_ALL;
    }
  }

  // Iterate the block in reverse
  while (true) {
    auto [CodeNode, IROp] = CodeLast();

    // Optimizing flags can cause earlier flag reads to become dead but dead
    // flag reads should not impede optimiation of earlier dead flag writes.
    // We must DCE as we go to ensure we converge in a single iteration.
    if (!EliminateDeadCode(IREmit, CodeNode, IROp)) {
      // Optimiation algorithm: For each flag written...
      //
      //  If the flag has a later read (per FlagsRead), remove the flag from
      //  FlagsRead, since the reader is covered by this write.
      //
      //  Else, there is no later read, so remove the flag write (if we can).
      //  This is the active part of the optimization.
      //
      // Then, add each flag read to FlagsRead.
      //
      // This order is important: instructions that read-modify-write flags
      // (like adcs) first read flags, then write flags. Since we're iterating
      // the block backwards, that means we handle the write first.
      struct FlagInfo Info = Classify(IROp);

      if (!Info.Trivial()) {
        bool Eliminated = false;

        if ((FlagsRead & Info.Write()) == 0) {
          if ((Info.CanEliminate() || Info.Replacement()) && CodeNode->GetUses() == 0 &&
              !(LazyFPStatus && MayRaiseFPStatus(IROp->Op)) && !(X87Status && MayRaiseX87Status(IROp->Op))) {
            IREmit->Remove(CodeNode);
            Eliminated = true;
          } else if (Info.Replacement()) {
            IROp->Op = Info.Replacement();
          }
        } else if (Info.ReplacementNoWrite() && CodeNode->GetUses() == 0) {
          IROp->Op = Info.ReplacementNoWrite();
        }

        // ★ MacRunner FEXXFER MACRUNNER_FEX_CMP_ZC=1 (MacRunnerXfer.h): an 8/16-bit compare with only ZF/CF live and
        // zero-extended operands becomes a 32-bit compare (no shifts, an inline immediate). Monotone with the worklist:
        // FlagsRead only shrinks, so a rewrite made here stays valid at the fixed point.
        if (!Eliminated && CmpZC && IROp->Op == OP_SUBNZCV && IROp->Size < OpSize::i32Bit && !(FlagsRead & (FLAG_N | FLAG_V))) {
          NarrowCompareZC(IREmit, CurrentIR, CodeNode, IROp);
        }

        // If we don't care about the sign or carry, we can optimize testnz.
        // Carry is inverted between testz and testnz so we check that too. Note
        // this flag is outside of the if, since the TestNZ might result from
        // optimizing AndWithFlags, and we need to converge locally in a single
        // iteration.
        if (IROp->Op == OP_TESTNZ && IROp->Size < OpSize::i32Bit && !(FlagsRead & (FLAG_N | FLAG_C))) {
          IROp->Op = OP_TESTZ;
        }

        FlagsRead &= ~Info.Write();

        // If we eliminated the instruction, we eliminate its read too. This
        // check is required to ensure the pass converges locally in a single
        // iteration.
        if (!Eliminated) {
          FlagsRead |= Info.Read();
        }
      }
    }

    // Iterate in reverse
    if (CodeLast == CodeBegin) {
      break;
    }
    --CodeLast;
  }

  // For the purposes of global propagation, the content of our progress doesn't
  // matter -- only the difference in our final FlagsRead contributes to changes
  // in the predecessors.
  uint32_t OldFlagsRead = CFG.Get(BlockIROp->ID)->Flags;
  CFG.Get(BlockIROp->ID)->Flags = FlagsRead;
  return (OldFlagsRead != FlagsRead);
}

void DeadFlagCalculationEliminination::OptimizeParity(IREmitter* IREmit, IRListView& CurrentIR, ControlFlowGraph& CFG) {
  // Mapping for flags inside this pass.
  const uint8_t PARTIAL = 0;
  const uint8_t FULL = 1;

  // Initialize conservatively: all blocks need full parity. This initialization
  // matters for proper handling of backedges.
  for (auto [Block, BlockHeader] : CurrentIR.GetBlocks()) {
    auto ID = BlockHeader->C<IROp_CodeBlock>()->ID;
    CFG.Get(ID)->Flags = FULL;
  }

  for (auto [Block, BlockHeader] : CurrentIR.GetBlocks()) {
    const auto ID = BlockHeader->C<IROp_CodeBlock>()->ID;
    const auto& Predecessors = CFG.Get(ID)->Predecessors;
    bool Full = false;

    if (BlockHeader->C<IROp_CodeBlock>()->EntryPoint || Predecessors.empty()) {
      // External entrants can carry a full-byte PF, regardless of internal predecessors.
      Full = true;
    } else {
      // If any predecessor needs full parity at the end, we need full parity.
      for (auto Pred : Predecessors) {
        Full |= (CFG.Get(Pred)->Flags == FULL);
      }
    }

    for (auto [CodeNode, IROp] : CurrentIR.GetCode(Block)) {
      if (IROp->Op == OP_STOREPF) {
        auto Op = IROp->C<IR::IROp_StorePF>();
        auto Generator = CurrentIR.GetOp<IR::IROp_Header>(Op->Value);

        // Determine if we only write 0/1 to the parity flag.
        Full = true;
        if (Generator->Op == OP_NZCVSELECT) {
          auto C0 = CurrentIR.GetOp<IR::IROp_Header>(Generator->Args[0]);
          auto C1 = CurrentIR.GetOp<IR::IROp_Header>(Generator->Args[1]);
          if (C0->Op == C1->Op && C0->Op == OP_INLINECONSTANT) {
            auto IC0 = CurrentIR.GetOp<IR::IROp_InlineConstant>(Generator->Args[0]);
            auto IC1 = CurrentIR.GetOp<IR::IROp_InlineConstant>(Generator->Args[1]);

            // We need the full 8 if the constant has upper bits set.
            Full = (IC0->Constant | IC1->Constant) & ~1;
          }
        }
      } else if (IROp->Op == OP_PARITY && !Full) {
        // Eliminate parity calculations if it's only 1-bit.
        auto Parity = IROp->C<IROp_Parity>();
        Ref Value = CurrentIR.GetNode(Parity->Raw);

        if (Parity->Invert) {
          IREmit->SetWriteCursor(CodeNode);
          Value = IREmit->_Xor(OpSize::i32Bit, Value, IREmit->_InlineConstant(1));
        }

        IREmit->ReplaceUsesWithAfter(CodeNode, Value, CurrentIR.at(CodeNode));
        IREmit->Remove(CodeNode);
      }
    }

    // Record our final state for our successors to read.
    CFG.Get(ID)->Flags = Full ? FULL : PARTIAL;
  }
}

void DeadFlagCalculationEliminination::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::DFE");

  auto CurrentIR = IREmit->ViewIR();
  fextl::deque<uint32_t> Worklist;

  // Initialize CFG
  ControlFlowGraph CFG {.IR = CurrentIR};
  CFG.Init(Worklist, CurrentIR.GetHeader()->BlockCount);

  // Gather CFG
  uint32_t EmissionOrder = 0;
  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    auto Block = BlockHeader->C<IROp_CodeBlock>();
    auto CodeLast = CurrentIR.at(Block->Last);
    --CodeLast;
    auto [ExitNode, ExitOp] = CodeLast();
    if (ExitOp->Op == IR::OP_CONDJUMP) {
      auto Op = ExitOp->C<IR::IROp_CondJump>();

      CFG.RecordEdge(Block->ID, Op->TrueBlock);
      CFG.RecordEdge(Block->ID, Op->FalseBlock);
    } else if (ExitOp->Op == IR::OP_JUMP) {
      CFG.RecordEdge(Block->ID, ExitOp->Args[0]);
    }

    CFG.Get(Block->ID)->Node = BlockNode;
    CFG.Get(Block->ID)->EmissionOrder = EmissionOrder++;
    for (auto [CodeNode, CodeOp] : CurrentIR.GetCode(BlockNode)) {
      if (CodeOp->Op == OP_UDIV) {
        auto Op = CodeOp->C<IROp_UDiv>();
        if (!Op->OverflowBlock.IsInvalid()) {
          CFG.RecordEdge(Block->ID, Op->OverflowBlock);
        }
      }
    }
  }

  // After processing a block, if we made progress, we must process its
  // predecessors to propagate globally. A block will be reprocessed only if
  // there is a loop backedge.
  for (; !Worklist.empty(); Worklist.pop_back()) {
    auto Block = Worklist.back();
    auto Info = CFG.Get(Block);
    Info->InWorklist = false;

    if (ProcessBlock(IREmit, CurrentIR, Info->Node, CFG)) {
      for (auto Pred : Info->Predecessors) {
        CFG.AddWorklist(Worklist, Pred);
      }
    }
  }

  // Fold compares into branches now that we're otherwise optimized. This needs
  // to run after eliminating carries etc and it needs the global flag metadata.
  // But it only needs to run once, we don't do it in the loop.
  for (auto [Block, _] : CurrentIR.GetBlocks()) {
    // Grab the jump
    auto BlockIROp = CurrentIR.GetOp<IR::IROp_CodeBlock>(Block);
    auto CodeLast = CurrentIR.at(BlockIROp->Last);
    --CodeLast;

    auto [ExitNode, ExitOp] = CodeLast();
    if (ExitOp->Op == IR::OP_CONDJUMP) {
      auto Op = ExitOp->CW<IR::IROp_CondJump>();
      uint32_t FlagsOut = CFG.Get(Op->TrueBlock)->Flags | CFG.Get(Op->FalseBlock)->Flags;

      const bool PreserveFlags = CFG.SuspendEdge(BlockIROp, Op);
      if (((FlagsOut & FLAG_NZCV) == 0 || PreserveFlags) && Op->FromNZCV) {
        FoldBranch(IREmit, CurrentIR, Op, ExitNode, PreserveFlags);
      }
    }
  }

  if (CurrentIR.GetHeader()->ReadsParity) {
    OptimizeParity(IREmit, CurrentIR, CFG);
  }
}

fextl::unique_ptr<Pass> CreateDeadFlagCalculationEliminination() {
  return fextl::make_unique<DeadFlagCalculationEliminination>();
}

} // namespace FEXCore::IR
