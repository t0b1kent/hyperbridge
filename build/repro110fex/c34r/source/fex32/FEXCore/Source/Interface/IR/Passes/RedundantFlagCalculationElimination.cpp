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
#include "Interface/IR/RegisterAllocationData.h" // INT32G B9: PhysicalRegister of a fixed-register store

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
#include <FEXCore/fextl/unordered_map.h>
#include "Interface/IR/RegisterAllocationData.h"
#include <array>
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
    if (!FEXCore::Utils::MacRunnerSuspendBackedgeExactFlags() || Target->GuestEntryOffset == FEXCore::Utils::NoGuestSuspendBoundary) {
      return false;
    }
    const uint32_t Order = Get(Target)->EmissionOrder;
    if (Order <= Get(From)->EmissionOrder) {
      return true;
    }
    // ★ REGION4-0004 13.11.2026 MACRUNNER_FEX32_SUSPEND_FWD_EXACT=1: the JIT polls a loop header at the START of the target block
    // (JIT.cpp GuestSuspendTargets), so the poll also runs when the header is entered by a forward edge or fallthrough. Flags must then
    // be exact on that edge too: every edge into a block that has a back edge counts as a suspend edge (a superset of the JIT's
    // targets). Cost: the flags of the forward path into a loop, once per entry into the loop, never per iteration.
    if (!FEXCore::Utils::MacRunnerSuspendFwdExact()) {
      return false;
    }
    for (const auto Pred : Get(Target)->Predecessors) {
      if (Get(Pred)->EmissionOrder >= Order) {
        return true;
      }
    }
    return false;
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
    const char* AtBranch = std::getenv("MACRUNNER_FEX32_FLAGS_AT_BRANCH"); // INT32G B9, default off
    FlagsAtBranch = AtBranch && std::strcmp(AtBranch, "1") == 0;
    const char* KeepLoads = std::getenv("MACRUNNER_FEX_KEEP_GUEST_LOADS"); // INT32G: a guest load is never dead code, default off
    KeepGuestLoads = KeepLoads && std::strcmp(KeepLoads, "1") == 0;
    const char* Preshift = std::getenv("MACRUNNER_FEX32_NARROW_PRESHIFT"); // INT32G B5-1, default off
    NarrowPreshift = Preshift && std::strcmp(Preshift, "1") == 0;
  }
  void Run(IREmitter* IREmit) override;

private:
  bool KeepGuestLoads {};
  bool NarrowPreshift {};
  static void PreshiftNarrowCompare(IREmitter* IREmit, IRListView& CurrentIR, Ref CodeNode, IROp_Header* IROp);
  bool FlagsAtBranch {};
  void SinkFlagsToBranch(IREmitter* IREmit, IRListView& CurrentIR, Ref Block);
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
  fextl::vector<bool> X87HeldValues; // RP6j: ids named by held x87 fault records (kept through DCE for RA)
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
  case OP_F80BCDSTORE:
  case OP_X87PCXARITH:
  // TRANS32 0033 v3: NOT OP_X87PCXLOAD -- the PC_EXACT pass leaves memory-operand conversions dead by design (Gothic world capture:
  // +174 M / +296 M executed load sequences per window when kept, +0.4 / +0.7 % host instructions); a guest load whose value is
  // really dead in a PCX unit raises nothing, as before 0033 (exact path F80CVTTO stays kept).
  case OP_X87PCXSTORE:
  case OP_X87PCXCMP: return true;
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

// INT32G B5-1 (MACRUNNER_FEX32_NARROW_PRESHIFT): SubNZCV of 8 / 16 bits is what the JIT emits as `lsl t, a, #s ; cmp t, b, lsl #s`
// (s = 32 - bits): a compare of a << s with b << s.  The same compare with BOTH operands shifted beforehand is a plain 32-bit
// SubNZCV - same N, Z, C, V - that the core runs in one micro-operation and fuses with the branch behind it.  Taken when the
// second operand is a constant: it is shifted here (zero becomes an inline immediate), so no instruction is added.  A register
// second operand would need a second `lsl`: left as it is.
void DeadFlagCalculationEliminination::PreshiftNarrowCompare(IREmitter* IREmit, IRListView& CurrentIR, Ref CodeNode, IROp_Header* IROp) {
  const unsigned Bits = IR::OpSizeAsBits(IROp->Size);
  const unsigned Shift = 32 - Bits;
  const uint64_t Mask = (1ULL << Bits) - 1;
  Ref Src1 = CurrentIR.GetNode(IROp->Args[0]);
  Ref Src2 = CurrentIR.GetNode(IROp->Args[1]);
  auto Src2Op = CurrentIR.GetOp<IR::IROp_Header>(IROp->Args[1]);

  const auto ConstantOf = [](IROp_Header* Op, uint64_t* Value) {
    if (Op->Op == OP_CONSTANT) {
      *Value = static_cast<uint64_t>(Op->C<IR::IROp_Constant>()->Constant);
      return true;
    }
    if (Op->Op == OP_INLINECONSTANT) {
      *Value = static_cast<uint64_t>(Op->C<IR::IROp_InlineConstant>()->Constant);
      return true;
    }
    return false;
  };
  auto Src1Op = CurrentIR.GetOp<IR::IROp_Header>(IROp->Args[0]);
  uint64_t Value1 = 0, Value2 = 0;
  const bool Const1 = ConstantOf(Src1Op, &Value1), Const2 = ConstantOf(Src2Op, &Value2);
  if (!Const2) {
    return;
  }
  // Never an instruction more.  The shifted constant takes the place of the unshifted one, so the unshifted one must have no
  // other user (the frontend pools constants: `and al, 5 ; cmp al, 5`, or PF raw `sub w26, wA, wC` when c is no immediate of
  // `sub`).  Zero needs no register at all.
  const uint64_t Shifted1 = (Value1 & Mask) << Shift, Shifted2 = (Value2 & Mask) << Shift;
  if ((Shifted2 != 0 && Src2->GetUses() != 1) || (Const1 && Shifted1 != 0 && Src1->GetUses() != 1)) {
    return;
  }

  IREmit->SetWriteCursorBefore(CodeNode);
  // The first operand.  A constant zero stays what it is: the JIT emits it as wzr and it may have no register at all (an
  // inline constant), so it must not become the operand of a shift.
  if (!Const1) {
    IREmit->ReplaceNodeArgument(CodeNode, 0, IREmit->_Lshl(OpSize::i32Bit, Src1, IREmit->_InlineConstant(Shift)));
  } else if (Shifted1 != 0) {
    IREmit->ReplaceNodeArgument(CodeNode, 0, IREmit->_Constant(Shifted1));
    IREmit->Remove(Src1); // its only user was this compare
  }
  // The second operand, shifted at compile time (zero: the immediate of `cmp w, #0`).
  IREmit->ReplaceNodeArgument(CodeNode, 1, Shifted2 == 0 ? IREmit->_InlineConstant(0) : IREmit->_Constant(Shifted2));
  // An unshifted constant without a user left would be a dead `mov`: the dead-code step of the pass has already run.
  if (Src2->GetUses() == 0) {
    IREmit->Remove(Src2);
  }
  IROp->Size = OpSize::i32Bit;
}

// General purpose dead code elimination. Returns whether flag handling should
// be skipped (because it was removed or could not possibly affect flags).
bool DeadFlagCalculationEliminination::EliminateDeadCode(IREmitter* IREmit, Ref CodeNode, IROp_Header* IROp) {
  // Can't remove anything used or with side effects.
  if (!X87HeldValues.empty()) {
    const uint32_t Id = IREmit->ViewIR().GetID(CodeNode).Value;
    if (Id < X87HeldValues.size() && X87HeldValues[Id]) {
      return false; // RP6j
    }
  }
  // A dead result can still probe a guest page (_chkstk). Accesses to the
  // thread state via FormContextAddress do not access guest pages.
  bool GuestLoad = false;
  if (KeepGuestLoads && MayFaultGuestMemory(IROp->Op)) {
    GuestLoad = true;
    if (IROp->Op == OP_LOADMEM || IROp->Op == OP_LOADMEMTSO) {
      auto View = IREmit->ViewIR();
      GuestLoad = View.GetOp<IR::IROp_Header>(IROp->Args[0])->Op != OP_FORMCONTEXTADDRESS;
    }
  }
  if (CodeNode->GetUses() > 0 || IR::HasSideEffects(IROp->Op) || GuestLoad ||
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

  // RP6j: values of held x87 fault records
  X87HeldValues.clear();
  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      if (IROp->Op != OP_X87FAULTSTATE || !(IROp->C<IROp_X87FaultState>()->Mode & 0x40)) {
        continue;
      }
      const auto* Marker = IROp->C<IROp_X87FaultState>();
      const uint32_t* Values = &Marker->Value0;
      const auto Keep = [&](uint32_t Id) {
        if (!Id) return;
        if (X87HeldValues.size() <= Id) X87HeldValues.resize(Id + 1, false);
        X87HeldValues[Id] = true;
      };
      for (unsigned i = 0; i < 8; ++i) {
        if (Marker->ValueMask & (1U << i)) Keep(Values[i]);
      }
      if (Marker->Mode & 4) Keep(Marker->Top);
    }
  }

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

  // INT32G B5-1 (MACRUNNER_FEX32_NARROW_PRESHIFT=1): every compare with a constant that is STILL narrow now - after the liveness
  // of the flags has converged, so that MACRUNNER_FEX32_CMP_ZC (cheaper, needs N and V dead) has had its last chance - becomes
  // a plain 32-bit compare of operands shifted to the top of the word; all four flags are the same bits.
  if (NarrowPreshift) {
    for (auto [Block, BlockHeader] : CurrentIR.GetBlocks()) {
      for (auto [CodeNode, IROp] : CurrentIR.GetCode(Block)) {
        if (IROp->Op == OP_SUBNZCV && IROp->Size < OpSize::i32Bit) {
          PreshiftNarrowCompare(IREmit, CurrentIR, CodeNode, IROp);
        }
      }
    }
  }

  // INT32G B9 (MACRUNNER_FEX32_FLAGS_AT_BRANCH=1): last, so that it sees the final flag operations and branches.
  if (FlagsAtBranch) {
    for (auto [Block, _] : CurrentIR.GetBlocks()) {
      SinkFlagsToBranch(IREmit, CurrentIR, Block);
    }
  }
}

// INT32G B9 (MATH4): bring the block's NZCV producer and the CondJump that reads it together, so that the host fuses the
// flag-setting instruction and b.cond into one micro-operation.  The register cache's flush (guest registers, PF/AF raw)
// otherwise sits between them.  Nothing is added or removed: the same operations in another order.  Conditions: see INT32G
// apply_fex9.py.
void DeadFlagCalculationEliminination::SinkFlagsToBranch(IREmitter* IREmit, IRListView& CurrentIR, Ref Block) {
  auto BlockIROp = CurrentIR.GetOp<IR::IROp_CodeBlock>(Block);
  auto CodeBegin = CurrentIR.at(BlockIROp->Begin);
  auto CodeLast = CurrentIR.at(BlockIROp->Last);
  --CodeLast; // the exit

  auto [ExitNode, ExitOp] = CodeLast();
  if (ExitOp->Op != IR::OP_CONDJUMP || !ExitOp->C<IR::IROp_CondJump>()->FromNZCV || CodeLast == CodeBegin) {
    return;
  }
  --CodeLast;

  constexpr size_t MaxBetween = 24;
  Ref Between[MaxBetween]; // from the jump backwards
  size_t NumBetween = 0;
  Ref Producer = nullptr;
  IROp_Header* ProducerOp = nullptr;

  while (true) {
    auto [Node, Op] = CodeLast();
    const FlagInfo Info = Classify(Op);
    if (Info.Write() & FLAG_NZCV) {
      Producer = Node;
      ProducerOp = Op;
      break;
    }

    // Between the producer and the jump only register and context traffic may stand: writes and loads of fixed registers
    // (guest registers, PF, AF), writes of the context, constants, markers of guest instructions.  None of them touches
    // NZCV, can fault or raises floating-point status; arithmetic and context loads stay where they are (their results
    // live in temporaries, and the allocator would pick other temporaries for them once the producer's operands live longer).
    bool Traffic = false;
    switch (Op->Op) {
    case OP_STOREREGISTER:
    case OP_STOREPF:
    case OP_STOREAF:
    case OP_STORECONTEXT:
    case OP_LOADREGISTER:
    case OP_LOADPF:
    case OP_LOADAF:
    case OP_CONSTANT:
    case OP_INLINECONSTANT:
    case OP_GUESTOPCODE: Traffic = true; break;
    // INT32G B5-1: the value of a fixed-register write that also stands between (checked below): PF raw of a narrow compare.
    case OP_ADD:
    case OP_SUB:
    case OP_AND:
    case OP_OR:
    case OP_XOR:
    case OP_NOT: Traffic = NarrowPreshift; break;
    default: break;
    }
    if (!Traffic || (Info.Read() & FLAG_NZCV) || NumBetween == MaxBetween || CodeLast == CodeBegin) {
      return;
    }
    Between[NumBetween++] = Node;
    --CodeLast;
  }

  switch (ProducerOp->Op) {
  case OP_SUBNZCV:
  case OP_ADDNZCV:
  case OP_TESTNZ:
  case OP_SUBWITHFLAGS:
  case OP_ADDWITHFLAGS:
  case OP_ANDWITHFLAGS: break;
  default: return; // not one fusable flag-setting host instruction
  }
  if (ProducerOp->Size < OpSize::i32Bit || (Classify(ProducerOp).Read() & FLAG_NZCV)) {
    return; // the narrow forms are emitted with a shifted operand, which the core does not fuse with the branch
  }

  // A context write between must write a value that existed before the producer (a constant made between would sit in a
  // temporary: see above).
  for (size_t k = 0; k < NumBetween; ++k) {
    auto Op = CurrentIR.GetOp<IR::IROp_Header>(Between[k]);
    if (Op->Op != OP_STORECONTEXT) {
      continue;
    }
    Ref Value = CurrentIR.GetNode(Op->Args[0]);
    for (size_t j = k + 1; j < NumBetween; ++j) {
      if (Between[j] == Value) {
        return;
      }
    }
  }

  // INT32G B5-1: arithmetic between is allowed only as the value of one fixed-register write that stands between, behind it.
  for (size_t k = 0; k < NumBetween; ++k) {
    auto Op = CurrentIR.GetOp<IR::IROp_Header>(Between[k]);
    if (Op->Op != OP_ADD && Op->Op != OP_SUB && Op->Op != OP_AND && Op->Op != OP_OR && Op->Op != OP_XOR && Op->Op != OP_NOT) {
      continue;
    }
    bool Written = false;
    for (size_t j = 0; j < k && !Written; ++j) {
      auto User = CurrentIR.GetOp<IR::IROp_Header>(Between[j]);
      Written = (User->Op == OP_STOREREGISTER || User->Op == OP_STOREPF || User->Op == OP_STOREAF) && CurrentIR.GetNode(User->Args[0]) == Between[k];
    }
    if (!Written || Between[k]->GetUses() != 1) {
      return;
    }
  }

  // Markers right in front of the jump stay where they are.
  size_t First = 0;
  while (First < NumBetween && CurrentIR.GetOp<IR::IROp_Header>(Between[First])->Op == OP_GUESTOPCODE) {
    ++First;
  }

  // Dependents (register writes of the producer's own value) and independents; the last independent that emits code (a
  // write or a constant: markers and fixed-register loads emit nothing and need not be crossed).
  bool Dependent[MaxBetween] {};
  size_t LastIndependent = NumBetween, NumDependents = 0;
  for (size_t k = NumBetween; k-- > First;) {
    auto Op = CurrentIR.GetOp<IR::IROp_Header>(Between[k]);
    bool UsesProducer = false;
    const uint8_t Args = IR::GetArgs(Op->Op);
    for (uint8_t i = 0; i < Args; ++i) {
      UsesProducer |= CurrentIR.GetNode(Op->Args[i]) == Producer;
    }
    if (UsesProducer) {
      if (Op->Op != OP_STOREREGISTER && Op->Op != OP_STOREPF && Op->Op != OP_STOREAF) {
        return; // the producer's value goes somewhere else
      }
      Dependent[k] = true;
      ++NumDependents;
    } else if (Op->Op == OP_STOREREGISTER || Op->Op == OP_STOREPF || Op->Op == OP_STOREAF || Op->Op == OP_STORECONTEXT || Op->Op == OP_CONSTANT ||
               Op->Op == OP_ADD || Op->Op == OP_SUB || Op->Op == OP_AND || Op->Op == OP_OR || Op->Op == OP_XOR || Op->Op == OP_NOT) {
      LastIndependent = k;
    }
  }
  if (LastIndependent == NumBetween || NumDependents > 1) {
    // Nothing that emits code between, but dependents: already as close as it gets.  Two dependents (`dec esi`: the result is
    // PF raw and the new esi): one of them stays a `mov` between the producer and the jump whatever the order, no gain.
    return;
  }

  // Fixed registers: read directly by the producer, written by the dependents that will move.
  constexpr uint8_t PFReg = 0xfe, AFReg = 0xff; // markers, not register numbers
  const auto FixedRead = [&](IROp_Header* Op, uint8_t* Reg) {
    if (Op->Op == OP_LOADREGISTER) {
      auto Load = Op->C<IR::IROp_LoadRegister>();
      *Reg = PhysicalRegister(Load->Class == RegClass::FPR ? RegClass::FPRFixed : RegClass::GPRFixed, uint8_t(Load->Reg)).Raw;
      return true;
    }
    if (Op->Op == OP_LOADPF || Op->Op == OP_LOADAF) {
      *Reg = Op->Op == OP_LOADPF ? PFReg : AFReg;
      return true;
    }
    return false;
  };
  const auto FixedWrite = [&](Ref Node, IROp_Header* Op, uint8_t* Reg) {
    if (Op->Op == OP_STOREREGISTER) {
      *Reg = Node->Reg;
      return true;
    }
    if (Op->Op == OP_STOREPF || Op->Op == OP_STOREAF) {
      *Reg = Op->Op == OP_STOREPF ? PFReg : AFReg;
      return true;
    }
    return false;
  };

  // MovedReads: the fixed registers the producer's arguments are, or may live in.  An argument that is a fixed-register load
  // is that register; an argument that an earlier StoreRegister / StorePF / StoreAF of this block wrote to a fixed register
  // may have been allocated right there (the allocator coalesces such stores).  If an independent wrote or freshly loaded
  // such a register in front of the producer, the allocator would have to copy the argument away first.
  constexpr size_t MaxMovedReads = 8, MaxScan = 512;
  uint8_t MovedReads[MaxMovedReads], MovedWrites[MaxBetween];
  size_t NumMovedReads = 0, NumMovedWrites = 0;
  const uint8_t ProducerArgs = IR::GetArgs(ProducerOp->Op);
  for (uint8_t i = 0; i < ProducerArgs; ++i) {
    uint8_t Reg;
    if (FixedRead(CurrentIR.GetOp<IR::IROp_Header>(ProducerOp->Args[i]), &Reg)) {
      if (NumMovedReads == MaxMovedReads) {
        return;
      }
      MovedReads[NumMovedReads++] = Reg;
    }
  }
  const auto StoresProducerArg = [&](IROp_Header* Op) { // a fixed-register write of one of the producer's arguments
    Ref Value = CurrentIR.GetNode(Op->Args[0]);
    for (uint8_t i = 0; i < ProducerArgs; ++i) {
      if (CurrentIR.GetNode(ProducerOp->Args[i]) == Value) {
        return true;
      }
    }
    return false;
  };
  {
    auto Scan = CodeLast; // at the producer
    for (size_t n = 0; Scan != CodeBegin; ++n) {
      if (n == MaxScan) {
        return;
      }
      --Scan;
      auto [Node, Op] = Scan();
      uint8_t Reg;
      if (FixedWrite(Node, Op, &Reg) && StoresProducerArg(Op)) {
        if (NumMovedReads == MaxMovedReads) {
          return;
        }
        MovedReads[NumMovedReads++] = Reg;
      }
    }
  }
  for (size_t k = NumBetween; k-- > First;) { // ... and between: `cmp eax, 0` / `mov ebx, eax` leaves the argument in ebx too
    auto Op = CurrentIR.GetOp<IR::IROp_Header>(Between[k]);
    uint8_t Reg;
    if (!Dependent[k] && FixedWrite(Between[k], Op, &Reg) && StoresProducerArg(Op)) {
      if (NumMovedReads == MaxMovedReads) {
        return;
      }
      MovedReads[NumMovedReads++] = Reg;
    }
  }

  // The allocator merges `mov r, X` with an operation right behind it that overwrites r (x86 two-address code:
  // `mov ebx, eax` / `and ebx, 0x200` becomes `ands w6, w4, #0x200`).  Nothing may be put between those two.
  {
    auto Prev = CodeLast; // at the producer
    while (Prev != CodeBegin) {
      --Prev;
      auto [Node, Op] = Prev();
      if (Op->Op == OP_LOADREGISTER || Op->Op == OP_LOADPF || Op->Op == OP_LOADAF || Op->Op == OP_INLINECONSTANT) {
        continue;
      }
      if (Op->Op == OP_STOREREGISTER) {
        for (size_t k = NumBetween; k-- > First;) {
          if (Dependent[k] && CurrentIR.GetOp<IR::IROp_Header>(Between[k])->Op == OP_STOREREGISTER && Between[k]->Reg == Node->Reg) {
            return;
          }
        }
      }
      break;
    }
  }
  for (size_t k = NumBetween; k-- > LastIndependent + 1;) {
    uint8_t Reg;
    if (Dependent[k] && FixedWrite(Between[k], CurrentIR.GetOp<IR::IROp_Header>(Between[k]), &Reg)) {
      MovedWrites[NumMovedWrites++] = Reg;
    }
  }
  const auto In = [](uint8_t Reg, const uint8_t* Set, size_t Num) {
    for (size_t i = 0; i < Num; ++i) {
      if (Set[i] == Reg) {
        return true;
      }
    }
    return false;
  };

  for (size_t k = NumBetween; k-- > LastIndependent;) {
    if (Dependent[k]) {
      continue;
    }
    Ref Node = Between[k];
    auto Op = CurrentIR.GetOp<IR::IROp_Header>(Node);
    uint8_t Reg;
    if (FixedWrite(Node, Op, &Reg) &&
        (In(Reg, MovedWrites, NumMovedWrites) || (In(Reg, MovedReads, NumMovedReads) && !StoresProducerArg(Op)))) {
      return; // would change the order of two writes of one register, or overwrite a register that holds the producer's argument
    }
    if (FixedRead(Op, &Reg) && (In(Reg, MovedWrites, NumMovedWrites) || In(Reg, MovedReads, NumMovedReads))) {
      return; // reads a register a moved dependent writes, or is a fresh load of a register that holds the producer's argument
    }
    const uint8_t Args = IR::GetArgs(Op->Op);
    for (uint8_t i = 0; i < Args; ++i) {
      if (FixedRead(CurrentIR.GetOp<IR::IROp_Header>(Op->Args[i]), &Reg) && In(Reg, MovedWrites, NumMovedWrites)) {
        return;
      }
    }
  }

  // The producer and the dependents that stood before the last independent go behind it, in their order.
  const uintptr_t ListBegin = CurrentIR.GetListData();
  Ref Anchor = LastIndependent == 0 ? ExitNode : Between[LastIndependent - 1];
  IREmit->RemovePostRA(Producer); // unlink only: uses and arguments stay as they are
  Anchor->prepend(ListBegin, Producer);
  for (size_t k = NumBetween; k-- > LastIndependent + 1;) {
    if (Dependent[k]) {
      IREmit->RemovePostRA(Between[k]);
      Anchor->prepend(ListBegin, Between[k]);
    }
  }
}

fextl::unique_ptr<Pass> CreateDeadFlagCalculationEliminination() {
  return fextl::make_unique<DeadFlagCalculationEliminination>();
}

// ---- CALLRET4 13.11.2026: MACRUNNER_FEX32_SLOT_FORWARD (see MacRunnerXfer.h) --------------------------------------------------
namespace {
class MRSlotForward final : public Pass {
public:
  explicit MRSlotForward(unsigned Level)
    : Level {Level} {}
  void Run(IREmitter* IREmit) override;

private:
  unsigned Level;
  // a value known to be `Root + Off`, Root = the ID of the node that first read a guest register (0 = not known)
  struct Sym {
    uint32_t Root {};
    int32_t Off {};
  };
  struct Slot {
    uint32_t Root;
    int32_t Off;
    uint32_t Size;
    RegClass Class;
    Ref Value;
    uint32_t Pos;      // position of the store in the block
    uint32_t Canon;    // the value's node (a read of a guest register: the node the register held then)
    Ref Store;         // the storing operation
    Ref FloatCopy;     // the integer value moved to a vector register right after the store (made on demand)
  };
  // operations with side effects that neither write guest memory nor leave the block's code for other code
  static bool Benign(IROps Op) {
    switch (Op) {
    case OP_INVALIDATEFLAGS:
    case OP_GUESTOPCODE:
    case OP_STOREREGISTER:
    case OP_STOREPF:
    case OP_STOREAF:
    case OP_STORECONTEXT:
    case OP_STORECONTEXTPAIR:
    case OP_STORECONTEXTINDEXED:
    case OP_LOADCONTEXTPAIR:
    case OP_STORENZCV:
    case OP_RMWHANDLE:
    case OP_INLINEENTRYPOINTOFFSET:
    case OP_INLINECONSTANT:
    case OP_ADDWITHFLAGS:
    case OP_ADDNZCV:
    case OP_SETSMALLNZV:
    case OP_CARRYINVERT:
    case OP_AXFLAG:
    case OP_RMIFNZCV:
    case OP_CONDADDNZCV:
    case OP_CONDSUBNZCV:
    case OP_ADCWITHFLAGS:
    case OP_ADCZEROWITHFLAGS:
    case OP_SBBWITHFLAGS:
    case OP_ADCNZCV:
    case OP_SBBNZCV:
    case OP_SUBWITHFLAGS:
    case OP_CMPPAIRZ:
    case OP_SUBNZCV:
    case OP_ANDWITHFLAGS:
    case OP_TESTNZ:
    case OP_TESTZ:
    case OP_SHIFTFLAGS:
    case OP_ROTATEFLAGS:
    case OP_FCMP:
    case OP_FCMPE:
    case OP_X87PCXARITH:
    case OP_X87PCXSTORE:
    case OP_X87PCXCMP:
    // x87 stack and control operations: they work on the x87 state in the context / host FPCR, never on guest memory
    // (StoreStackMem, the one that writes guest memory, is not here)
    case OP_SYNCSTACKTOSLOW:
    case OP_STACKFORCESLOW:
    case OP_INITSTACK:
    case OP_INCSTACKTOP:
    case OP_DECSTACKTOP:
    case OP_INVALIDATESTACK:
    case OP_PUSHSTACK:
    case OP_COPYPUSHSTACK:
    case OP_STORESTACKTOSTACK:
    case OP_POPSTACKDESTROY:
    case OP_F80ADDSTACK:
    case OP_F80ADDVALUE:
    case OP_F80SUBSTACK:
    case OP_F80SUBVALUE:
    case OP_F80SUBRVALUE:
    case OP_F80MULSTACK:
    case OP_F80MULVALUE:
    case OP_F80DIVSTACK:
    case OP_F80DIVVALUE:
    case OP_F80DIVRVALUE:
    case OP_F80STACKXCHANGE:
    case OP_F80STACKCHANGESIGN:
    case OP_F80STACKABS:
    case OP_F80PTANSTACK:
    case OP_F80ATANSTACK:
    case OP_F80FPREMSTACK:
    case OP_F80FPREM1STACK:
    case OP_F80SCALESTACK:
    case OP_F80ROUNDSTACK:
    case OP_F80F2XM1STACK:
    case OP_F80SINSTACK:
    case OP_F80COSSTACK:
    case OP_F80SINCOS:
    case OP_F80SINCOSSTACK:
    case OP_F80SQRTSTACK:
    case OP_X87FAULTSTATE:
    case OP_HBX87FASTCW:
    case OP_HBX87FAST:
    case OP_X87PCXGUARD:
    case OP_X87PCXDEOPT:
    case OP_F80CMPVALUE:
    case OP_F80CMPQUIET:
    case OP_F80FYL2XSTACK:
    case OP_F80FYL2XP1STACK:
    case OP_F80VBSLSTACK:
    case OP_F64SINCOS:
    case OP_SETROUNDINGMODE:
    case OP_PUSHROUNDINGMODE:
    case OP_PUSHFPCRNOFLUSH:
    case OP_PUSHFPSR:
    case OP_GETFPSR:
    case OP_READFPSR:
    case OP_POPFPSR:
    case OP_POPROUNDINGMODE:
    case OP_VALIDATECODE:
    case OP_TELEMETRYSETVALUE:
    case OP_BEGINBLOCK:
    case OP_ENDBLOCK:
    case OP_DUMMY: return true;
    default: return false;
    }
  }
};

void MRSlotForward::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::MRSlotForward");
  auto CurrentIR = IREmit->ViewIR();
  fextl::unordered_map<uint32_t, Sym> SymOf;
  fextl::vector<Slot> Slots;
  std::array<Sym, 16> RegSym {};
  uint64_t FwdGPR = 0, FwdFPR = 0, Mismatch = 0, Stores = 0, Held = 0, Skipped = 0, Conv = 0, FloatHolds = 0;
  // a 32-bit integer load of a recorded slot whose value is no longer in a register for free: if its only use is the conversion
  // to a double (fild / fisub ...: exact, independent of the rounding mode), the conversion is made at the STORE from the
  // register that holds the value there, and both the load and the conversion at the load go away
  struct PendingLoad {
    Ref Load;
    Ref Store;
    Ref Value;
  };
  fextl::unordered_map<uint32_t, PendingLoad> Pending;
  fextl::unordered_map<uint32_t, uint32_t> SkippedLoads; // diagnostic: not forwarded load -> 1
  fextl::unordered_map<uint32_t, uint32_t> LastUse; // node ID -> position of its last use in the block
  // node ID -> every use is a scalar float conversion (it reads the low element only): a 4-byte float forwarded to such a load
  // needs no zeroing copy (VMov of 4 bytes is movi + ins, two or three instructions)
  fextl::unordered_map<uint32_t, bool> LowOnly;
  std::array<uint32_t, 16> RegNode {};              // guest register -> the node whose value the register holds now (0: unknown)
  fextl::unordered_map<uint32_t, uint32_t> Canon;   // a later read of a guest register -> that node
  const auto CanonOf = [&](uint32_t ID) {
    const auto It = Canon.find(ID);
    return It == Canon.end() ? ID : It->second;
  };
  uint32_t Pos = 0;
  const unsigned Hold = FEXCore::Utils::MacRunnerSlotForward32Hold();

  const auto GetSym = [&](OrderedNodeWrapper W) -> Sym {
    if (W.IsInvalid()) {
      return {};
    }
    const auto It = SymOf.find(W.ID().Value);
    return It == SymOf.end() ? Sym {} : It->second;
  };
  const auto ConstOf = [&](OrderedNodeWrapper W, int64_t* C) {
    const auto* H = IREmit->GetOpHeader(W);
    if (H->Op == OP_CONSTANT) {
      *C = static_cast<int64_t>(H->C<IROp_Constant>()->Constant);
      return true;
    }
    if (H->Op == OP_INLINECONSTANT) {
      *C = H->C<IROp_InlineConstant>()->Constant;
      return true;
    }
    return false;
  };
  // the slot an access addresses: {Root != 0, Off} or {} (not `register value + constant`)
  const auto SlotOf = [&](OrderedNodeWrapper Addr, OrderedNodeWrapper Offset, MemOffsetType Type, uint8_t Scale) -> Sym {
    Sym A = GetSym(Addr);
    if (!A.Root) {
      return {};
    }
    if (!Offset.IsInvalid()) {
      int64_t C;
      if (Type != MemOffsetType::SXTX || Scale != 1 || !ConstOf(Offset, &C) || C < -0x100000 || C > 0x100000) {
        return {};
      }
      A.Off += static_cast<int32_t>(C);
    }
    return A;
  };
  // a store of Size bytes to the slot S: everything it may overlap is forgotten (another Root may be the same memory)
  const auto Written = [&](Sym S, uint32_t Size) {
    for (size_t i = 0; i < Slots.size();) {
      const auto& X = Slots[i];
      if (X.Root != S.Root || (S.Off < X.Off + static_cast<int32_t>(X.Size) && X.Off < S.Off + static_cast<int32_t>(Size))) {
        Slots[i] = Slots.back();
        Slots.pop_back();
      } else {
        ++i;
      }
    }
  };
  const auto Record = [&](Sym S, uint32_t Size, RegClass Class, OrderedNodeWrapper Value, Ref Store) {
    if (Value.IsInvalid() || (Size != 1 && Size != 2 && Size != 4 && Size != 8 && Size != 16)) {
      return;
    }
    // a value that a later non-SSA operation rewrites in place is not a value to keep
    const auto ValueOp = IREmit->GetOpHeader(Value)->Op;
    if (ValueOp == OP_RMWHANDLE || ValueOp == OP_ALLOCATEGPR || ValueOp == OP_ALLOCATEGPRAFTER || ValueOp == OP_ALLOCATEFPR ||
        ValueOp == OP_INLINECONSTANT || ValueOp == OP_INLINEENTRYPOINTOFFSET) {
      return;
    }
    Slots.push_back(Slot {S.Root, S.Off, Size, Class, IREmit->UnwrapNode(Value), Pos, CanonOf(Value.ID().Value), Store, nullptr});
    ++Stores;
  };

  // MACRUNNER_FEX_X87_FAULT_STATE markers name nodes by raw ID (the memory operation they describe, the x87 values held in SSA):
  // a removed load takes its own marker with it, and a marker that names a replaced node is pointed at the replacement
  fextl::vector<Ref> Markers;
  const auto Renamed = [&](uint32_t OldID, Ref New, bool DropTarget) {
    const uint32_t NewID = New ? CurrentIR.GetID(New).Value : 0;
    for (auto& M : Markers) {
      if (!M) {
        continue;
      }
      auto W = IREmit->GetOpHeader(IREmit->WrapNode(M))->CW<IROp_X87FaultState>();
      if (DropTarget && W->Target == OldID) {
        IREmit->Remove(M);
        M = nullptr;
        continue;
      }
      if (New) {
        uint32_t* V = &W->Value0;
        for (unsigned i = 0; i < 8; ++i) {
          if ((V[i] & 0x7fffffffU) == OldID && V[i]) {
            V[i] = (V[i] & 0x80000000U) | NewID;
          }
        }
        if ((W->Top & 0x7fffffffU) == OldID && W->Top) {
          W->Top = (W->Top & 0x80000000U) | NewID;
        }
      }
    }
  };
  // the load goes away, and with it an address node that nothing else uses (a register read left without uses would make the
  // register allocator preserve it with a copy)
  const auto RemoveLoad = [&](Ref Node, const IROp_Header* Op) {
    const auto AddrW = Op->Args[0];
    IREmit->Remove(Node);
    if (!AddrW.IsInvalid()) {
      const Ref Addr = IREmit->UnwrapNode(AddrW);
      const auto AddrOp = IREmit->GetOpHeader(AddrW)->Op;
      if (Addr->NumUses == 0 && (AddrOp == OP_LOADREGISTER || AddrOp == OP_ADD || AddrOp == OP_SUB)) {
        IREmit->Remove(Addr);
      }
    }
  };
  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    SymOf.clear();
    Slots.clear();
    RegSym.fill(Sym {});
    LastUse.clear();
    LowOnly.clear();
    RegNode.fill(0);
    Canon.clear();
    Pending.clear();
    SkippedLoads.clear();
    Pos = 0;
    Markers.clear();
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      ++Pos;
      if (IROp->Op == OP_X87FAULTSTATE) {
        Markers.push_back(CodeNode);
      }
      const auto NumArgs = IR::GetArgs(IROp->Op);
      for (unsigned a = 0; a < NumArgs; ++a) {
        if (!IROp->Args[a].IsInvalid()) {
          const uint32_t ArgID = IROp->Args[a].ID().Value;
          LastUse[ArgID] = Pos;
          const bool Low = IROp->Op == OP_FLOAT_FTOF;
          const auto It = LowOnly.find(ArgID);
          if (It == LowOnly.end()) {
            LowOnly[ArgID] = Low;
          } else {
            It->second &= Low;
          }
        }
      }
    }
    Pos = 0;
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      const uint32_t ID = CurrentIR.GetID(CodeNode).Value;
      ++Pos;
      if (!SkippedLoads.empty()) {
        const auto NA = IR::GetArgs(IROp->Op);
        for (unsigned a = 0; a < NA; ++a) {
          if (!IROp->Args[a].IsInvalid() && SkippedLoads.erase(IROp->Args[a].ID().Value) && static_cast<unsigned>(IROp->Op) < 512) {
            FEXCore::Utils::MRSFwdSkipUser[static_cast<unsigned>(IROp->Op)].fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
      switch (IROp->Op) {
      case OP_LOADREGISTER: {
        const auto Op = IROp->C<IROp_LoadRegister>();
        if (Op->Class == RegClass::GPR && Op->Reg < RegSym.size()) {
          if (!RegSym[Op->Reg].Root) {
            RegSym[Op->Reg] = Sym {ID, 0};
          }
          SymOf[ID] = RegSym[Op->Reg];
          if (!RegNode[Op->Reg]) {
            RegNode[Op->Reg] = ID;
          } else {
            Canon[ID] = RegNode[Op->Reg];
          }
        }
        break;
      }
      case OP_STOREREGISTER: {
        const auto Reg = PhysicalRegister(CodeNode);
        if (Reg.AsRegClass() == RegClass::GPRFixed && Reg.Reg < RegSym.size()) {
          RegSym[Reg.Reg] = GetSym(IROp->C<IROp_StoreRegister>()->Value);
          RegNode[Reg.Reg] = CanonOf(IROp->C<IROp_StoreRegister>()->Value.ID().Value);
        }
        break;
      }
      case OP_ADD:
      case OP_SUB:
      case OP_ADDWITHFLAGS:
      case OP_SUBWITHFLAGS: {
        const Sym A = GetSym(IROp->Args[0]);
        int64_t C;
        if (A.Root && IROp->Size == OpSize::i32Bit && ConstOf(IROp->Args[1], &C) && C > -0x100000 && C < 0x100000) {
          const bool IsAdd = IROp->Op == OP_ADD || IROp->Op == OP_ADDWITHFLAGS;
          SymOf[ID] = Sym {A.Root, A.Off + static_cast<int32_t>(IsAdd ? C : -C)};
        }
        break;
      }
      case OP_FLOAT_FROMGPR_S: {
        const auto Op = IROp->C<IROp_Float_FromGPR_S>();
        const auto It = Op->Src.IsInvalid() ? Pending.end() : Pending.find(Op->Src.ID().Value);
        if (It != Pending.end() && Op->Header.ElementSize == OpSize::i64Bit && Op->SrcElementSize == OpSize::i32Bit && It->second.Load->NumUses == 1) {
          const PendingLoad P = It->second;
          Pending.erase(It);
          IREmit->SetWriteCursor(P.Store);
          const Ref Early = IREmit->_Float_FromGPR_S(OpSize::i64Bit, OpSize::i32Bit, P.Value);
          IREmit->ReplaceUsesWithAfter(CodeNode, Early, CodeNode);
          Renamed(ID, Early, false);
          Renamed(CurrentIR.GetID(P.Load).Value, nullptr, true);
          IREmit->Remove(CodeNode);
          RemoveLoad(P.Load, IREmit->GetOpHeader(IREmit->WrapNode(P.Load)));
          ++Conv;
          --Skipped;
        }
        break;
      }
      case OP_RMWHANDLE: {
        const Sym A = GetSym(IROp->Args[0]);
        if (A.Root) {
          SymOf[ID] = A;
        }
        break;
      }
      case OP_PUSH: {
        const auto Op = IROp->C<IROp_Push>();
        Sym A = GetSym(Op->Addr);
        const uint32_t Size = IR::OpSizeToSize(Op->ValueSize);
        if (!A.Root) {
          Slots.clear();
          break;
        }
        A.Off -= static_cast<int32_t>(Size);
        if (Level < 2) {
          Slots.clear(); // the push itself can raise (guard page)
        } else {
          Written(A, Size);
        }
        Record(A, Size, RegClass::GPR, Op->Value, CodeNode);
        SymOf[ID] = A;
        break;
      }
      case OP_POP: {
        const auto Op = IROp->C<IROp_Pop>();
        const uint32_t Size = IR::OpSizeToSize(Op->Size);
        if (Level < 2) {
          Slots.clear();
        }
        // the pop rewrites its address node in place
        const auto It = SymOf.find(Op->InoutAddr.ID().Value);
        if (It != SymOf.end()) {
          It->second.Off += static_cast<int32_t>(Size);
        }
        SymOf.erase(Op->OutValue.ID().Value);
        break;
      }
      case OP_STOREMEM: {
        const auto Op = IROp->C<IROp_StoreMem>();
        const Sym S = SlotOf(Op->Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);
        const uint32_t Size = IR::OpSizeToSize(IROp->Size);
        if (!S.Root) {
          Slots.clear();
          break;
        }
        if (Level < 2) {
          // strict: this store can raise unless it rewrites exactly a recorded slot
          bool Known = false;
          for (const auto& X : Slots) {
            Known |= X.Root == S.Root && X.Off == S.Off && X.Size == Size;
          }
          if (!Known) {
            Slots.clear();
          }
        }
        Written(S, Size);
        Record(S, Size, Op->Class, Op->Value, CodeNode);
        break;
      }
      case OP_LOADMEM: {
        const auto Op = IROp->C<IROp_LoadMem>();
        const Sym S = SlotOf(Op->Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);
        const uint32_t Size = IR::OpSizeToSize(IROp->Size);
        Slot* Hit = nullptr;
        bool Overlap = false;
        if (S.Root) {
          for (auto& X : Slots) {
            if (X.Root != S.Root) {
              continue;
            }
            if (X.Off == S.Off && ((X.Size == Size && (X.Class == Op->Class || (X.Class == RegClass::GPR && Size == 4))) ||
                                   (X.Size > Size && X.Class == RegClass::GPR && Op->Class == RegClass::GPR && X.Size <= 4))) {
              // the same bytes: same class and size; the low bytes of a wider integer store; an integer store read as a float
              Hit = &X;
            } else if (S.Off < X.Off + static_cast<int32_t>(X.Size) && X.Off < S.Off + static_cast<int32_t>(Size)) {
              Overlap = true;
            }
          }
        }
        bool Forwardable = Hit && ((Op->Class == RegClass::GPR && Size <= 4) || (Op->Class == RegClass::FPR && Size >= 4));
        bool Free = false;
        int FromReg = -1;
        bool FloatHeld = false;
        if (Forwardable) {
          // is the value in a register here anyway?
          for (unsigned r = 0; r < RegNode.size() && !Free && Hit->Class == RegClass::GPR; ++r) {
            if (RegNode[r] == Hit->Canon) {
              Free = true;
              FromReg = static_cast<int>(r); // a guest register holds the value right now: read it from there
            }
          }
          if (!Free) {
            const auto It = LastUse.find(CurrentIR.GetID(Hit->Value).Value);
            Free = It != LastUse.end() && It->second > Pos;
          }
          // an integer value read as a float: the copy to a vector register is made at the store (vector registers are
          // plentiful), the integer register is not held
          const bool ViaFloatCopy = !Free && Hit->Class == RegClass::GPR && Op->Class == RegClass::FPR;
          if (ViaFloatCopy) {
            if (!Hit->FloatCopy) {
              IREmit->SetWriteCursor(Hit->Store);
              Hit->FloatCopy = IREmit->_VCastFromGPR(OpSize::i32Bit, OpSize::i32Bit, Hit->Value);
            }
            IREmit->ReplaceUsesWithAfter(CodeNode, Hit->FloatCopy, CodeNode);
            Renamed(ID, Hit->FloatCopy, true);
            RemoveLoad(CodeNode, IROp);
            ++FwdFPR;
            break;
          }
          // a float value read back as a float (fstp m32; fld m32 ...): held in a vector register, of which there are many
          FloatHeld = !Free && Hit->Class == RegClass::FPR && Op->Class == RegClass::FPR;
          if (!Free && !FloatHeld && Pos - Hit->Pos > Hold) {
            Forwardable = false;
            ++Skipped;
            SkippedLoads[ID] = 1;
            if (Op->Class == RegClass::GPR && Size == 4 && Hit->Size == 4 && CodeNode->NumUses == 1) {
              Pending[ID] = PendingLoad {CodeNode, Hit->Store, Hit->Value};
            }
          }
        }
        if (Forwardable) {
          Held += !Free && !FloatHeld;
          FloatHolds += FloatHeld;
          Ref Value = Hit->Value;
          IREmit->SetWriteCursor(CodeNode);
          if (FromReg >= 0) {
            Value = IREmit->_LoadRegister(static_cast<uint32_t>(FromReg), RegClass::GPR, OpSize::i32Bit);
            Canon[CurrentIR.GetID(Value).Value] = RegNode[FromReg];
          }
          Ref New;
          if (Op->Class == RegClass::GPR) {
            New = IREmit->_Bfe(OpSize::i32Bit, static_cast<uint8_t>(Size * 8), 0, Value);
            ++FwdGPR;
          } else if (Hit->Class == RegClass::GPR) {
            New = IREmit->_VCastFromGPR(OpSize::i32Bit, OpSize::i32Bit, Value); // 32 bits of an integer register read as a float
            ++FwdFPR;
          } else {
            const auto Low = LowOnly.find(ID);
            New = (Low != LowOnly.end() && Low->second) ? Value : IREmit->_VMov(IROp->Size, Value);
            ++FwdFPR;
          }
          IREmit->ReplaceUsesWithAfter(CodeNode, New, CodeNode);
          Renamed(ID, New, true);
          RemoveLoad(CodeNode, IROp);
        } else {
          Mismatch += Overlap || (Hit && Free);
          if (Level < 2) {
            Slots.clear(); // strict: this load can raise
          }
        }
        break;
      }
      default: {
        const bool MayRaise = IROp->Op == OP_LOADMEMTSO || IROp->Op == OP_LOADMEMPAIR || IROp->Op == OP_DIV || IROp->Op == OP_UDIV ||
                              IROp->Op == OP_VLOADVECTORMASKED || IROp->Op == OP_VLOADVECTORELEMENT || IROp->Op == OP_VBROADCASTFROMMEM ||
                              IROp->Op == OP_VLOADNONTEMPORAL || IROp->Op == OP_PREFETCH || IROp->Op == OP_VLOADVECTORGATHERMASKED ||
                              IROp->Op == OP_VLOADVECTORGATHERMASKEDQPS;
        if ((IR::HasSideEffects(IROp->Op) && !Benign(IROp->Op) && !MayRaise) || (MayRaise && Level < 2)) {
          Slots.clear();
        }
        break;
      }
      }
    }
  }
  if (FwdGPR | FwdFPR | Mismatch | Stores | Skipped | Conv) {
    FEXCore::Utils::MRSFwdGPR.fetch_add(FwdGPR, std::memory_order_relaxed);
    FEXCore::Utils::MRSFwdFPR.fetch_add(FwdFPR, std::memory_order_relaxed);
    FEXCore::Utils::MRSFwdMismatch.fetch_add(Mismatch, std::memory_order_relaxed);
    FEXCore::Utils::MRSFwdStores.fetch_add(Stores, std::memory_order_relaxed);
    FEXCore::Utils::MRSFwdHeld.fetch_add(Held, std::memory_order_relaxed);
    FEXCore::Utils::MRSFwdSkipped.fetch_add(Skipped, std::memory_order_relaxed);
    FEXCore::Utils::MRSFwdConv.fetch_add(Conv, std::memory_order_relaxed);
    FEXCore::Utils::MRSFwdFloatHeld.fetch_add(FloatHolds, std::memory_order_relaxed);
  }
}
} // namespace

fextl::unique_ptr<Pass> CreateMRSlotForwardPass(unsigned Level) {
  return fextl::make_unique<MRSlotForward>(Level);
}

} // namespace FEXCore::IR
