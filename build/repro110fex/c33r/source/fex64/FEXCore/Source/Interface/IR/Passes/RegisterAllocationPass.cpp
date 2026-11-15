// SPDX-License-Identifier: MIT
/*
$info$
tags: ir|opts
$end_info$
*/

#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Interface/IR/Passes.h"
#include "Interface/Core/CPUID.h"
#include <FEXCore/Core/MacRunnerLazyMXCSR.h>
#include "Interface/Core/HBX87StateGates.h" // TRANS32 0033
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/fextl/vector.h>
#include <bit>
#include <cstdint>
#include <cstdlib>
#include <array>
#include <cstdlib>

using namespace FEXCore;

static bool MRX87FaultCoverRA() {
  static const bool v = [] { const char* p = getenv("MACRUNNER_FEX_X87_FAULT_COVER"); return p && p[0] == '1'; }();
  return v;
}

namespace FEXCore::IR {
namespace {
  // Same guest-memory family as 0176. A fault reads the old architectural
  // stack and PF/AF state even without explicit loads in the normal IR path.
  bool MayFaultGuestMemoryForFlags(IROps Op) {
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

  // A scalar conversion already clears its unused lanes. When the legacy SSE
  // destination is proven zero, inserting into that zero vector is redundant.
  // Keep guest register stores in place: memory faults still observe the state
  // preceding the conversion. Only the conversion's unused merge input changes.
  bool FoldZeroCVTSI(IREmitter* Emit) {
    const char* Enabled = std::getenv("MACRUNNER_FEX_HW_CVTSI_ZERO");
    const char* ScalarMerge = std::getenv("MACRUNNER_FEX_HW_SCALAR_MERGE");
    if (!Enabled || Enabled[0] != '1' || Enabled[1] != '\0' ||
        (ScalarMerge && ScalarMerge[0] == '1')) {
      return false;
    }

    auto View = Emit->ViewIR();
    fextl::vector<bool> IsZero(View.GetSSACount(), false);
    fextl::vector<Ref> Conversions;
    for (auto [BlockNode, BlockHeader] : View.GetBlocks()) {
      std::fill(IsZero.begin(), IsZero.end(), false);
      std::array<bool, 32> RegisterZero {};
      for (auto [Node, Header] : View.GetCode(BlockNode)) {
        const auto ID = View.GetID(Node).Value;
        const auto ZeroSource = [&](OrderedNodeWrapper Value) {
          return !Value.IsInvalid() && IsZero[Value.ID().Value];
        };

        if (Header->Op == OP_LOADNAMEDVECTORCONSTANT) {
          IsZero[ID] = Header->Size == OpSize::i128Bit &&
                       Header->C<IROp_LoadNamedVectorConstant>()->Constant == NamedVectorConstant::NAMED_VECTOR_ZERO;
        } else if (Header->Op == OP_LOADREGISTER) {
          const auto Op = Header->C<IROp_LoadRegister>();
          IsZero[ID] = Op->Class == RegClass::FPR && Op->Reg < RegisterZero.size() &&
                       Header->Size == OpSize::i128Bit && RegisterZero[Op->Reg];
        } else if (Header->Op == OP_STOREREGISTER) {
          const auto Register = PhysicalRegister(Node);
          if (Register.AsRegClass() == RegClass::FPRFixed && Register.Reg < RegisterZero.size()) {
            RegisterZero[Register.Reg] = Header->Size == OpSize::i128Bit &&
                                         ZeroSource(Header->C<IROp_StoreRegister>()->Value);
          }
        } else if (Header->Op == OP_VSTOFGPRINSERT) {
          const auto Op = Header->C<IROp_VSToFGPRInsert>();
          if (Header->Size == OpSize::i128Bit && !Op->ZeroUpperBits &&
              (Header->ElementSize == OpSize::i32Bit || Header->ElementSize == OpSize::i64Bit) &&
              (Op->SrcElementSize == OpSize::i32Bit || Op->SrcElementSize == OpSize::i64Bit) && ZeroSource(Op->Vector)) {
            Conversions.push_back(Node);
          }
        } else if (Header->Op == OP_VSTOFVECTORINSERT) {
          const auto Op = Header->C<IROp_VSToFVectorInsert>();
          if (Header->Size == OpSize::i128Bit && !Op->ZeroUpperBits && !Op->HasTwoElements &&
              (Header->ElementSize == OpSize::i32Bit || Header->ElementSize == OpSize::i64Bit) && ZeroSource(Op->Vector1)) {
            Conversions.push_back(Node);
          }
        } else if (Header->Op != OP_GUESTOPCODE && HasSideEffects(Header->Op)) {
          // Unknown effects do not transport a register proof through a call,
          // fault barrier, or other operation outside this narrow fold.
          RegisterZero.fill(false);
        }
      }
    }

    for (auto Node : Conversions) {
      const auto Header = View.GetOp<IROp_Header>(Node);
      Emit->SetWriteCursorBefore(Node);
      Ref Result;
      Ref MergeInput;
      if (Header->Op == OP_VSTOFGPRINSERT) {
        const auto Op = Header->C<IROp_VSToFGPRInsert>();
        MergeInput = View.GetNode(Op->Vector);
        Result = Emit->_Float_FromGPR_S(Header->ElementSize, Op->SrcElementSize, Op->Src);
      } else {
        const auto Op = Header->C<IROp_VSToFVectorInsert>();
        MergeInput = View.GetNode(Op->Vector1);
        Result = Emit->_Vector_SToF(Header->ElementSize, Header->ElementSize, Op->Vector2);
      }
      Emit->ReplaceUsesWithAfter(Node, Result, Node);
      Emit->Remove(Node);
      // A dead static load otherwise pins the destination for RA, generating
      // copies to preserve a value which no guest operation actually reads.
      if (MergeInput->NumUses == 0 && View.GetOp<IROp_Header>(MergeInput)->Op == OP_LOADREGISTER) {
        Emit->Remove(MergeInput);
      }
    }
    return !Conversions.empty();
  }

  struct RegisterClassData {
    uint32_t Available;
    uint32_t Count;

    // If bit R of Available is 0, then RegToSSA[R] is the node currently
    // allocated to R. Else, RegToSSA[R] is UNDEFINED, no need to clear this
    // when freeing registers.
    Ref RegToSSA[32];
  };

  IR::RegClass GetRegClassFromNode(const IR::IROp_Header* IROp) {
    const auto Class = IR::GetRegClass(IROp->Op);
    if (Class != IR::RegClass::Complex) {
      return Class;
    }

    // Complex register class handling
    switch (IROp->Op) {
    case IR::OP_LOADCONTEXT: return IROp->C<IR::IROp_LoadContext>()->Class;
    case IR::OP_LOADREGISTER: return IROp->C<IR::IROp_LoadRegister>()->Class;
    case IR::OP_LOADCONTEXTINDEXED: return IROp->C<IR::IROp_LoadContextIndexed>()->Class;
    case IR::OP_LOADMEM:
    case IR::OP_LOADMEMTSO: return IROp->C<IR::IROp_LoadMem>()->Class;
    case IR::OP_FILLREGISTER: return IROp->C<IR::IROp_FillRegister>()->Class;
    default: return IR::RegClass::Invalid;
    }
  }
} // Anonymous namespace

void RegisterAllocationPass::SetNumPairRegs(uint32_t NumRegs) {
  LOGMAN_THROW_A_FMT((NumRegs % 2) == 0, "Number of pair regs must be even. (Given: {})", NumRegs);
  PairRegs = NumRegs;
}

class ConstrainedRAPass final : public RegisterAllocationPass {
public:
  explicit ConstrainedRAPass(const FEXCore::CPUIDEmu* CPUID)
    : CPUID {CPUID} {}
  void Run(IREmitter* IREmit) override;
  void AddRegisters(IR::RegClass Class, uint32_t RegisterCount) override;
  bool TryPostRAMerge(Ref LastNode, Ref CodeNode, IROp_Header* IROp);

private:
  RegisterClassData Classes[IR::NumClasses];

  IREmitter* IREmit {};
  IRListView* IR {};
  const FEXCore::CPUIDEmu* CPUID {};

  // Map of nodes to their preferred register, to coalesce load/store reg.
  fextl::vector<PhysicalRegister> PreferredReg;

  // Map of assigned registers. Does not grow beyond the initial set.
  fextl::vector<PhysicalRegister> SSAToReg;

  // Maps defs to their assigned spill slot + 1, or 0 if not spilled.
  fextl::vector<unsigned> SpillSlots;

  // Next-use distance relative to the block end of each source, last first.
  fextl::vector<uint32_t> SourcesNextUses;

  // Sources that have been seen
  fextl::vector<bool> Seen;

  // SourcesNextUses is read backwards, this tracks the index
  int64_t SourceIndex {};

  static bool Rematerializable(const IROp_Header* IROp) {
    return IROp->Op == OP_CONSTANT;
  }

  Ref InsertFill(Ref Node) {
    const auto* IROp = IR->GetOp<IROp_Header>(Node);

    // Remat if we can
    if (Rematerializable(IROp)) {
      const auto* Op = IROp->C<IR::IROp_Constant>();
      const uint64_t Const = Op->Constant;
      return IREmit->_Constant(Const, Op->Pad, Op->MaxBytes);
    }

    // Otherwise fill from stack
    const uint32_t SlotPlusOne = SpillSlots[IR->GetID(Node).Value];
    LOGMAN_THROW_A_FMT(SlotPlusOne >= 1, "Node must have been spilled");

    const auto RegClass = GetRegClassFromNode(IROp);
    return IREmit->_FillRegister(IROp->Size, IROp->ElementSize, SlotPlusOne - 1, RegClass);
  }

  // X87-CTX P5: the marker just passed, resolved at its target op (after that op's fills, before its kills).
  Ref PendingX87FaultState {};
  void ResolveX87FaultState(Ref Marker, Ref Target);
  void CheckX87FaultStateDest(Ref Marker, Ref Target);

  // IP of next-use of each source. IPs are measured from the end of the
  // block, so we don't need to size the block up-front.
  fextl::vector<uint32_t> NextUses;

  bool AnySpilled {};
  bool CVTSIZeroFolded {};
  bool LazyDeadDefs {};
  bool HoistedStaticCopy {};

  bool IsValidArg(OrderedNodeWrapper Arg) const {
    if (Arg.IsInvalid()) {
      return false;
    }

    auto Op = IR->GetOp<IROp_Header>(Arg)->Op;
    return Op != OP_INLINECONSTANT && Op != OP_INLINEENTRYPOINTOFFSET;
  }

  RegisterClassData* GetClass(PhysicalRegister Reg) {
    return &Classes[Reg.Class];
  }
  const RegisterClassData* GetClass(PhysicalRegister Reg) const {
    return &Classes[Reg.Class];
  }

  static uint32_t GetRegBits(PhysicalRegister Reg) {
    return 1U << Reg.Reg;
  }

  bool IsInRegisterFile(Ref Node) const {
    auto ID = IR->GetID(Node).Value;
    LOGMAN_THROW_A_FMT(ID < SSAToReg.size(), "Only old nodes looked up");

    const PhysicalRegister Reg = SSAToReg[ID];
    const RegisterClassData* Class = GetClass(Reg);

    return (Class->Available & GetRegBits(Reg)) == 0 && Class->RegToSSA[Reg.Reg] == Node;
  }

  void FreeReg(PhysicalRegister Reg) {
    RegisterClassData* Class = GetClass(Reg);
    uint32_t RegBits = GetRegBits(Reg);

    LOGMAN_THROW_A_FMT(!(Class->Available & RegBits), "Register double-free");

    Class->Available |= RegBits;
  }

  bool HasSource(IROp_Header* I, PhysicalRegister Reg) {
    int NumArgs = IR::GetRAArgs(I->Op);
    for (int s = 0; s < NumArgs; ++s) {
      if (I->Args[s].IsImmediate()) {
        // When spilling for a destination, we'll see register sources
        if (PhysicalRegister(I->Args[s]) == Reg) {
          return true;
        }
      } else {
        // When spilling for SRA correctness, we'll see SSA sources. This is
        // pretty obscure.
        auto V = I->Args[s];
        V.ClearKill();

        if (IsValidArg(V) && SSAToReg[V.ID().Value] == Reg) {
          return true;
        }
      }
    }

    return false;
  }

  Ref DecodeSRANode(const IROp_Header* IROp, Ref Node) {
    if (IROp->Op == OP_LOADREGISTER || IROp->Op == OP_LOADPF || IROp->Op == OP_LOADAF) {
      return Node;
    } else if (IROp->Op == OP_STOREREGISTER) {
      auto V = IROp->C<IR::IROp_StoreRegister>()->Value;
      V.ClearKill();
      return IR->GetNode(V);
    } else if (IROp->Op == OP_STOREPF || IROp->Op == OP_STOREAF) {
      auto V = IROp->C<IR::IROp_StorePF>()->Value;
      V.ClearKill();
      return IR->GetNode(V);
    }

    return nullptr;
  }

  PhysicalRegister DecodeSRAReg(const IROp_Header* IROp, Ref Node) const {
    uint8_t FlagOffset = Classes[FEXCore::ToUnderlying(RegClass::GPRFixed)].Count - 2;

    if (IROp->Op == OP_STOREREGISTER) {
      return PhysicalRegister(Node);
    } else if (IROp->Op == OP_LOADPF || IROp->Op == OP_STOREPF) {
      return PhysicalRegister {RegClass::GPRFixed, FlagOffset};
    } else if (IROp->Op == OP_LOADAF || IROp->Op == OP_STOREAF) {
      return PhysicalRegister {RegClass::GPRFixed, uint8_t(FlagOffset + 1)};
    } else {
      const IROp_LoadRegister* Op = IROp->C<IR::IROp_LoadRegister>();

      LOGMAN_THROW_A_FMT(Op->Class == RegClass::GPR || Op->Class == RegClass::FPR, "SRA classes");
      if (Op->Class == RegClass::FPR) {
        return PhysicalRegister {RegClass::FPRFixed, uint8_t(Op->Reg)};
      } else {
        return PhysicalRegister {RegClass::GPRFixed, uint8_t(Op->Reg)};
      }
    }
  }

  bool IsTrivial(Ref Node, const IROp_Header* Header) const {
    switch (Header->Op) {
    case OP_ALLOCATEGPR: return true;
    case OP_ALLOCATEGPRAFTER: return true;
    case OP_ALLOCATEFPR: return true;
    case OP_RMWHANDLE: return PhysicalRegister(Node) == PhysicalRegister(Header->Args[0]);
    case OP_LOADREGISTER: return PhysicalRegister(Node) == DecodeSRAReg(Header, Node);
    case OP_STOREREGISTER: return PhysicalRegister(Header->Args[0]) == DecodeSRAReg(Header, Node);
    default: return false;
    }
  }

  // Helper macro to walk the set bits b in a 32-bit word x, using ffs to get
  // the next set bit and then clearing on each iteration.
#define foreach_bit(b, x) for (uint32_t __x = (x), b; ((b) = __builtin_ffs(__x) - 1, __x); __x &= ~(1 << (b)))

  void CalculateNextUses(IROp_CodeBlock* BlockIROp, IROp_Header* Until) {
    SourcesNextUses.clear();
    NextUses.resize(IR->GetSSACount(), 0);

    // IP relative to the end of the block.
    uint32_t IP = 1;

    // We grab these nodes this way so we can iterate easily
    auto CodeBegin = IR->at(BlockIROp->Begin);
    auto CodeLast = IR->at(BlockIROp->Last);

    while (1) {
      auto [CodeNode, IROp] = CodeLast();
      if (IROp == Until) {
        break;
      }
      // End of iteration gunk

      const int NumArgs = IR::GetRAArgs(IROp->Op);
      for (int i = NumArgs - 1; i >= 0; --i) {
        auto V = IROp->Args[i];
        V.ClearKill();

        if (IsValidArg(V)) {
          const uint32_t Index = V.ID().Value;

          SourcesNextUses.push_back(NextUses[Index]);
          NextUses[Index] = IP;
        }
      }

      // IP is relative to block end and we iterate backwards, so increment.
      // X87-CTX P5 markers emit no code: distances (and so spill choices) stay those of the block without them.
      if (IROp->Op != OP_X87FAULTSTATE) {
        ++IP;
      }

      // Rest is iteration gunk
      if (CodeLast == CodeBegin) {
        break;
      }
      --CodeLast;
    }

    SourceIndex = SourcesNextUses.size();
  }

  void SpillReg(RegisterClassData* Class, IROp_CodeBlock* Block, IROp_Header* Exclude) {
    // We're about to use next-use information, so calculate it.
    if (!AnySpilled) {
      CalculateNextUses(Block, Exclude);
    }

    // Find the best node to spill according to the "furthest-first" heuristic.
    // Since we defined IPs relative to the end of the block, the furthest
    // next-use has the /smallest/ unsigned IP.
    Ref Candidate = nullptr;
    uint32_t BestDistance = UINT32_MAX;
    uint8_t BestReg = ~0;
    uint32_t Allocated = ((1u << Class->Count) - 1) & ~Class->Available;

    foreach_bit(i, Allocated) {
      Ref Node = Class->RegToSSA[i];
      auto Reg = SSAToReg[IR->GetID(Node).Value];

      LOGMAN_THROW_A_FMT(Node != nullptr, "Invariant3");
      LOGMAN_THROW_A_FMT(Reg.Reg == i, "Invariant4");

      // Skip any source used by the current instruction, it is unspillable.
      if (!HasSource(Exclude, Reg)) {
        uint32_t NextUse = NextUses[IR->GetID(Node).Value];

        // Prioritize remat over spilling. It is typically cheaper to remat a
        // constant multiple times than to spill a single value.
        if (!Rematerializable(IR->GetOp<IROp_Header>(Node))) {
          NextUse += 100000;
        }

        if (NextUse < BestDistance) {
          BestDistance = NextUse;
          BestReg = i;
          Candidate = Node;
        }
      }
    }

    LOGMAN_THROW_A_FMT(Candidate != nullptr, "must've found something..");

    PhysicalRegister Reg = SSAToReg[IR->GetID(Candidate).Value];
    LOGMAN_THROW_A_FMT(Reg.Reg == BestReg, "Invariant6");

    IROp_Header* Header = IR->GetOp<IROp_Header>(Candidate);
    uint32_t Value = IR->GetID(Candidate).Value;
    bool Spilled = !SpillSlots.empty() && SpillSlots[Value] != 0;

    // If we already spilled the Candidate, we don't need to spill again.
    // Similarly, if we can rematerialize the instruction, we don't spill it.
    if (!Spilled && Header->Op != OP_CONSTANT) {
      LOGMAN_THROW_A_FMT(Reg.AsRegClass() == GetRegClassFromNode(Header), "Consistent");

      // SpillSlots allocation is deferred.
      if (SpillSlots.empty()) {
        SpillSlots.resize(IR->GetSSACount(), 0);
      }

      // TODO: we should colour spill slots
      uint32_t Slot = IR->GetHeader()->SpillSlots++;

      // We must map here in case we're spilling something we shuffled.
      auto SpillOp = IREmit->_SpillRegister(OrderedNodeWrapper::FromImmediate(Reg.Raw), Slot, Reg.AsRegClass());
      SpillOp.first->Header.Size = Header->Size;
      SpillOp.first->Header.ElementSize = Header->ElementSize;
      SpillSlots[Value] = Slot + 1;
    }

    // Now that we've spilled the value, take it out of the register file
    FreeReg(Reg);
    AnySpilled = true;
  }

  void RemapReg(Ref Node, PhysicalRegister Reg) {
    RegisterClassData* Class = GetClass(Reg);
    Class->RegToSSA[Reg.Reg] = Node;

    uint32_t Index = IR->GetID(Node).Value;
    if (Index < SSAToReg.size()) {
      SSAToReg[Index] = Reg;
    }
  }

  // Record a given assignment of register Reg to Node.
  void SetReg(Ref Node, PhysicalRegister Reg) {
    RegisterClassData* Class = GetClass(Reg);
    uint32_t RegBits = GetRegBits(Reg);

    LOGMAN_THROW_A_FMT((Class->Available & RegBits) == RegBits, "Precondition");

    Class->Available &= ~RegBits;

    RemapReg(Node, Reg);
    Node->Reg = Reg.Raw;
  }

  // Assign a register for a given Node, spilling if necessary.
  void AssignReg(IROp_Header* IROp, IROp_CodeBlock* Block, Ref CodeNode, IROp_Header* Pivot) {
    const uint32_t Node = IR->GetID(CodeNode).Value;

    // Prioritize preferred registers.
    if (Node < PreferredReg.size()) {
      if (PhysicalRegister Reg = PreferredReg[Node]; !Reg.IsInvalid()) {
        RegisterClassData* Class = GetClass(Reg);
        uint32_t RegBits = GetRegBits(Reg);

        // The folded scalar operation does not read its old SIMD destination.
        // Move a still-live old definition before producing the new value,
        // rather than producing a temporary and copying it at StoreRegister.
        if (CVTSIZeroFolded && Reg.AsRegClass() == RegClass::FPRFixed &&
            (IROp->Op == OP_FLOAT_FROMGPR_S || (IROp->Op == OP_VECTOR_STOF && IROp->Size == IROp->ElementSize)) &&
            (Class->Available & RegBits) != RegBits && !HasSource(IROp, Reg)) {
          Ref Old = Class->RegToSSA[Reg.Reg];
          const auto Header = IR->GetOp<IROp_Header>(Old);
          IREmit->SetWriteCursorBefore(CodeNode);
          Ref Copy = IREmit->_VMov(Header->Size, OrderedNodeWrapper::FromImmediate(Reg.Raw));
          FreeReg(Reg);
          auto CopyHeader = IR->GetOp<IROp_Header>(Copy);
          const RegClass CopyClassType = GetRegClassFromNode(CopyHeader);
          auto CopyClass = &Classes[FEXCore::ToUnderlying(CopyClassType)];

          // The current instruction's killed sources have already been freed.
          // Its destination may reuse them after reading, but this preservation
          // copy runs before that read. Keep those sources out of its free set.
          uint32_t ReservedSources = 0;
          for (int s = 0; s < IR::GetRAArgs(IROp->Op); ++s) {
            auto Source = PhysicalRegister(IROp->Args[s]);
            if (Source.AsRegClass() == CopyClassType) {
              ReservedSources |= CopyClass->Available & GetRegBits(Source);
            }
          }
          CopyClass->Available &= ~ReservedSources;
          AssignReg(CopyHeader, Block, Copy, Pivot);
          CopyClass->Available |= ReservedSources;
          RemapReg(Old, PhysicalRegister(Copy));
          HoistedStaticCopy = true;
        }

        if ((Class->Available & RegBits) == RegBits) {
          SetReg(CodeNode, Reg);
          return;
        }
      }
    }

    // Try to handle tied registers. This can fail, the JIT will insert moves.
    if (int TiedIdx = IR::TiedSource(IROp->Op); TiedIdx >= 0) {
      auto Reg = PhysicalRegister(IROp->Args[TiedIdx]);
      RegisterClassData* Class = GetClass(Reg);
      uint32_t RegBits = GetRegBits(Reg);

      if (Reg.AsRegClass() != RegClass::GPRFixed && Reg.AsRegClass() != RegClass::FPRFixed && (Class->Available & RegBits) == RegBits) {
        SetReg(CodeNode, Reg);
        return;
      }
    }

    // Try to coalesce reserved pairs. Just a heuristic to remove some moves.
    if (IROp->Op == OP_ALLOCATEGPR && IROp->C<IROp_AllocateGPR>()->ForPair) {
      uint32_t Available = Classes[FEXCore::ToUnderlying(RegClass::GPR)].Available;

      // Only choose base register R if R and R + 1 are both free
      Available &= (Available >> 1);

      // Only consider aligned registers in the pair region
      constexpr uint32_t EVEN_BITS = 0x55555555;
      Available &= (EVEN_BITS & ((1u << PairRegs) - 1));

      if (Available) {
        unsigned Reg = std::countr_zero(Available);
        SetReg(CodeNode, PhysicalRegister(RegClass::GPR, Reg));
        return;
      }
    } else if (IROp->Op == OP_ALLOCATEGPRAFTER) {
      uint32_t Available = Classes[FEXCore::ToUnderlying(RegClass::GPR)].Available;
      auto After = PhysicalRegister(IROp->Args[0]);
      if ((After.Reg & 1) == 0 && Available & (1ull << (After.Reg + 1))) {
        SetReg(CodeNode, PhysicalRegister(RegClass::GPR, After.Reg + 1));
        return;
      }
    }

    RegClass ClassType = GetRegClassFromNode(IROp);
    RegisterClassData* Class = &Classes[FEXCore::ToUnderlying(ClassType)];

    // Spill to make room in the register file.
    if (!Class->Available) {
      IREmit->SetWriteCursorBefore(CodeNode);
      SpillReg(Class, Block, Pivot);
    }

    // Assign a free register in the appropriate class.
    LOGMAN_THROW_A_FMT(Class->Available != 0, "Post-condition of spilling");
    unsigned Reg = std::countr_zero(Class->Available);
    SetReg(CodeNode, PhysicalRegister(ClassType, Reg));
  }
};

void ConstrainedRAPass::AddRegisters(IR::RegClass Class, uint32_t RegisterCount) {
  LOGMAN_THROW_A_FMT(RegisterCount <= 31, "Up to 31 regs supported");

  Classes[FEXCore::ToUnderlying(Class)].Count = RegisterCount;
}

static bool KillMove(const IROp_Header* LastOp, IROp_Header* IROp, Ref LastNode, Ref CodeNode) {
  // 32-bit moves in x86_64 are represented as a Bfe, detect them.
  if (LastOp->Op == OP_BFE && LastOp->C<IR::IROp_Bfe>()->lsb == 0 && LastOp->C<IR::IROp_Bfe>()->Width == 32) {
    auto Op = IROp->Op;

    if (Op == OP_AND) {
      // Rewrite "mov wA, wB; and xA, xA, xC" into "and wA, wB, wC", since
      // ((b & 0xffffffff) & c) == (b & c) & 0xffffffff.
      IROp->Size = OpSize::i32Bit;
      return true;
    } else if (IROp->Size == OpSize::i32Bit) {
      return Op == OP_OR || Op == OP_XOR || Op == OP_AND || Op == OP_SUB || Op == OP_LSHL || Op == OP_LSHR || Op == OP_ASHR;
    }
  }

  return LastOp->Op == OP_STOREREGISTER;
}

static bool IsSignext(const IROp_Header* IROp, OrderedNodeWrapper Src, OpSize Size) {
  if (IROp->Op == OP_SBFE) {
    auto Sbfe = IROp->C<IR::IROp_Sbfe>();
    return Sbfe->Width == 1 && Sbfe->lsb == (IR::OpSizeAsBits(Size) - 1) && Sbfe->Src == Src;
  } else {
    return false;
  }
}

static bool IsZero(const IROp_Header* IROp) {
  return IROp->Op == OP_CONSTANT && IROp->C<IROp_Constant>()->Constant == 0;
}

bool ConstrainedRAPass::TryPostRAMerge(Ref LastNode, Ref CodeNode, IROp_Header* IROp) {
  auto LastOp = IR->GetOp<IROp_Header>(LastNode);

  if (IROp->Op == OP_PUSH && LastOp->Op == OP_PUSH) {
    auto SP = PhysicalRegister(CodeNode);
    auto Push = IR->GetOp<IROp_Push>(CodeNode);
    auto LastPush = IR->GetOp<IROp_Push>(LastNode);

    if (LastOp->Size == IROp->Size && LastPush->ValueSize == Push->ValueSize && SP == PhysicalRegister(LastNode) &&
        SP == PhysicalRegister(IROp->Args[1]) && SP == PhysicalRegister(LastOp->Args[1]) && SP != PhysicalRegister(IROp->Args[0]) &&
        SP != PhysicalRegister(LastOp->Args[0]) && Push->ValueSize >= OpSize::i32Bit) {

      IREmit->SetWriteCursorBefore(LastNode);
      IREmit->_PushTwo(IROp->Size, Push->ValueSize, IROp->Args[0], LastOp->Args[0], IROp->Args[1]);
      IREmit->RemovePostRA(CodeNode);
      return true;
    }
  } else if (IROp->Op == OP_POP) {
    auto SP = PhysicalRegister(IROp->Args[0]);

    if (LastOp->Op == OP_POP && LastOp->Size == IROp->Size && IROp->Size >= OpSize::i32Bit && SP == PhysicalRegister(LastOp->Args[0])) {
      IREmit->SetWriteCursorBefore(LastNode);
      IREmit->_PopTwo(IROp->Size, IROp->Args[0], LastOp->Args[1], IROp->Args[1]);
      IREmit->RemovePostRA(CodeNode);
      return true;
    }
  } else if ((IROp->Op == OP_DIV || IROp->Op == OP_UDIV) && IROp->Size >= OpSize::i32Bit) {
    // If Upper came from a sign/zero extension, we only need a 64-bit division.
    auto Op = IROp->CW<IR::IROp_Div>();
    if (!Op->Upper.IsInvalid() && PhysicalRegister(Op->Upper) == PhysicalRegister(LastNode)) {
      if (IROp->Op == OP_DIV ? IsSignext(LastOp, Op->Lower, IROp->Size) : IsZero(LastOp)) {
        Op->Upper.SetInvalid();
        return PhysicalRegister(LastNode) == PhysicalRegister(Op->OutRemainder);
      }
    }
  } else if (IROp->Op == OP_XGETBV && PhysicalRegister(IROp->Args[0]) == PhysicalRegister(LastNode) && LastOp->Op == OP_CONSTANT) {
    // Try to constant fold
    uint64_t ConstantFunction = LastOp->C<IROp_Constant>()->Constant;
    auto Op = IROp->CW<IR::IROp_XGetBV>();
    if (CPUID->DoesXCRFunctionReportConstantData(ConstantFunction)) {
      const auto Result = CPUID->RunXCRFunction(ConstantFunction);
      IREmit->SetWriteCursorBefore(CodeNode);
      IREmit->_Constant(Result.eax).Node->Reg = PhysicalRegister(Op->OutEAX).Raw;
      IREmit->_Constant(Result.edx).Node->Reg = PhysicalRegister(Op->OutEDX).Raw;
      IREmit->RemovePostRA(CodeNode);
      return false;
    }
  } else if (IROp->Op == OP_CPUID && PhysicalRegister(IROp->Args[0]) == PhysicalRegister(LastNode) && LastOp->Op == OP_CONSTANT) {
    // Try to constant fold. As a limitation of merging only 2 instructions, we
    // can only handle constant functions, not constant leafs. This could be
    // lifted if we generalized at a (significant) complexity cost.
    uint64_t ConstantFunction = LastOp->C<IROp_Constant>()->Constant;
    auto Op = IROp->CW<IR::IROp_CPUID>();

    const auto SupportsConstant = CPUID->DoesFunctionReportConstantData(ConstantFunction);
    if (SupportsConstant.SupportsConstantFunction == CPUIDEmu::SupportsConstant::CONSTANT &&
        SupportsConstant.NeedsLeaf != CPUIDEmu::NeedsLeafConstant::NEEDSLEAFCONSTANT) {
      const auto Result = CPUID->RunFunction(ConstantFunction, 0 /* leaf */);

      IREmit->SetWriteCursorBefore(CodeNode);
      IREmit->_Fence(IR::FenceType::Inst);
      IREmit->_Constant(Result.eax).Node->Reg = PhysicalRegister(Op->OutEAX).Raw;
      IREmit->_Constant(Result.ebx).Node->Reg = PhysicalRegister(Op->OutEBX).Raw;
      IREmit->_Constant(Result.ecx).Node->Reg = PhysicalRegister(Op->OutECX).Raw;
      IREmit->_Constant(Result.edx).Node->Reg = PhysicalRegister(Op->OutEDX).Raw;
      IREmit->RemovePostRA(CodeNode);
      return false;
    }
  }

  // Merge moves that are immediately consumed.
  //
  // x86 code inserts such moves to workaround x86's 2-address code. Because
  // arm64 is 3-address code, we can optimize these out.
  //
  // Note we rely on the short-circuiting here.
  if (PhysicalRegister(LastNode) == PhysicalRegister(CodeNode) && KillMove(LastOp, IROp, LastNode, CodeNode)) {
    LOGMAN_THROW_A_FMT(!PhysicalRegister(CodeNode).IsInvalid(), "invariant");

    int NumArgs = IR::GetRAArgs(IROp->Op);
    for (int s = 0; s < NumArgs; ++s) {
      if (IROp->Args[s].IsImmediate() && PhysicalRegister(IROp->Args[s]) == PhysicalRegister(LastNode)) {
        IROp->Args[s].SetImmediate(PhysicalRegister(LastOp->Args[0]).Raw);
      }
    }

    return true;
  }

  return false;
}

void ConstrainedRAPass::Run(IREmitter* IREmit_) {
  FEXCORE_PROFILE_SCOPED("PassManager::RA");

  const char* RMWFlagsMode = std::getenv("MACRUNNER_FEX_RMW_FLAGS_AFTER_STORE");
  const bool PreciseRMWFlags = RMWFlagsMode && RMWFlagsMode[0] == '1' && !RMWFlagsMode[1];

  CVTSIZeroFolded = FoldZeroCVTSI(IREmit_);
  LazyDeadDefs = FEXCore::LazyMXCSR::Enabled.load(std::memory_order_relaxed) ||
                 FEXCore::HBX87::StateFix::ExceptionFlags() || FEXCore::HBX87::StateFix::C1Roundup(); // TRANS32 0033: kept dead x87 defs
  IREmit = IREmit_;
  auto IR_ = IREmit->ViewIR();
  IR = &IR_;

  PreferredReg.resize(IR->GetSSACount(), PhysicalRegister::Invalid());
  SSAToReg.resize(IR->GetSSACount(), PhysicalRegister::Invalid());
  Seen.resize(IR->GetSSACount(), false);

  for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
    // Spilling is local, so reset this per-block
    AnySpilled = false;

    // At the start of each block, all registers are available.
    for (auto& Class : Classes) {
      Class.Available = (1u << Class.Count) - 1;
    }

    auto BlockIROp = BlockHeader->CW<IR::IROp_CodeBlock>();

    // Backwards pass: analyze kill bits and SRA affinities
    {
      // Reverse iteration is not yet working with the iterators
      // We grab these nodes this way so we can iterate easily
      auto CodeBegin = IR->at(BlockIROp->Begin);
      auto CodeLast = IR->at(BlockIROp->Last);

      while (1) {
        auto [CodeNode, IROp] = CodeLast();
        // End of iteration gunk

        // Record preferred registers for SRA. We also record the Node accessing
        // each register, used below. Since we initialized Class->Available,
        // RegToSSA is otherwise undefined so we can stash our temps there.
        if (auto Node = DecodeSRANode(IROp, CodeNode); Node != nullptr) {
          auto Reg = DecodeSRAReg(IROp, CodeNode);

          PreferredReg[IR->GetID(Node).Value] = Reg;
          GetClass(Reg)->RegToSSA[Reg.Reg] = CodeNode;
        }

        // PUSH produces the new SP only after its store succeeds. POP's
        // writeback similarly commits together with its load. An unchanged
        // copy of the old architectural SP may therefore be tied to that
        // writeback, provided no other reader/fault intervenes before the
        // matching architectural store. POP-to-memory uses LoadMem/StoreMem
        // and must retain the ordinary barrier.
        bool AtomicPopSP = false;
        auto& FixedGPR = Classes[FEXCore::ToUnderlying(RegClass::GPRFixed)];
        if (IROp->Op == OP_POP) {
          auto Address = IROp->C<IROp_Pop>()->InoutAddr;
          Address.ClearKill();
          const auto AddressNode = IR->GetNode(Address);
          const auto Preferred = PreferredReg[IR->GetID(AddressNode).Value];
          const auto AddressOp = IR->GetOp<IROp_Header>(AddressNode);
          if (Preferred == PhysicalRegister {RegClass::GPRFixed, FEXCore::X86State::REG_RSP} &&
              AddressOp->Op == OP_RMWHANDLE) {
            auto Input = AddressOp->C<IROp_RMWHandle>()->Value;
            Input.ClearKill();
            const auto InputOp = IR->GetOp<IROp_Header>(Input);
            const auto NextAccess = FixedGPR.RegToSSA[FEXCore::X86State::REG_RSP];
            AtomicPopSP = InputOp->Op == OP_LOADREGISTER &&
                          InputOp->C<IROp_LoadRegister>()->Class == RegClass::GPR &&
                          InputOp->C<IROp_LoadRegister>()->Reg == FEXCore::X86State::REG_RSP &&
                          DecodeSRANode(IR->GetOp<IROp_Header>(NextAccess), NextAccess) == AddressNode;
          }
        }
        const bool AtomicPushSP = IROp->Op == OP_PUSH;
        if (MayFaultGuestMemoryForFlags(IROp->Op) && IROp->Op != OP_RMWHANDLE && !AtomicPopSP && !AtomicPushSP) {
          // A memory fault can replay the current x86 instruction. Do not
          // coalesce a later stack-pointer commit into a producer before
          // that fault (notably POP into memory).
          Classes[FEXCore::ToUnderlying(RegClass::GPRFixed)].RegToSSA[FEXCore::X86State::REG_RSP] = CodeNode;
        }
        if (PreciseRMWFlags && MayFaultGuestMemoryForFlags(IROp->Op)) {
          // The implicit fault reader forbids hoisting an AF/PF assignment
          // across memory, including assignment of a faultable load's result.
          // Keep the other fixed-register affinities unchanged.
          auto& Fixed = Classes[FEXCore::ToUnderlying(RegClass::GPRFixed)];
          Fixed.RegToSSA[Fixed.Count - 2] = CodeNode;
          Fixed.RegToSSA[Fixed.Count - 1] = CodeNode;
        }

        // Coalescing an SRA store is equivalent to hoisting the store,
        // implying write-after-write and read-after-write hazards. We can only
        // coalesce if there is no intervening load/store.
        //
        // Since we're walking backwards, RegToSSA tracks
        // the first load/store after CodeNode. That first instruction is the
        // store in question iff there is no intervening load/store.
        //
        // Reset PreferredReg if that is not the case, ensuring SRA correctness.
        if (auto Reg = PreferredReg[IR->GetID(CodeNode).Value]; !Reg.IsInvalid()) {
          auto Node = GetClass(Reg)->RegToSSA[Reg.Reg];
          IROp_Header* Header = IR->GetOp<IROp_Header>(Node);

          if (CodeNode != DecodeSRANode(Header, Node)) {
            PreferredReg[IR->GetID(CodeNode).Value] = PhysicalRegister::Invalid();
          }
        }

        // Permit PUSH's own result affinity, but never hoist an unrelated SP
        // producer from before the faulting store.
        if (AtomicPushSP) {
          FixedGPR.RegToSSA[FEXCore::X86State::REG_RSP] = CodeNode;
        }

        const int NumArgs = IR::GetRAArgs(IROp->Op);
        for (int i = NumArgs - 1; i >= 0; --i) {
          const auto& Arg = IROp->Args[i];
          if (!Arg.IsInvalid()) {
            const uint32_t Index = Arg.ID().Value;
            if (!Seen[Index]) {
              Seen[Index] = true;
              IROp->Args[i].SetKill();
            }
          }
        }

        // Rest is iteration gunk
        if (CodeLast == CodeBegin) {
          break;
        }
        --CodeLast;
      }
    }

    // NextUses currently contains first use distances, the exact initialization
    // assumed by the forward pass. Do not reset it.

    // Last nontrivial instruction, for merging as we go.
    Ref LastNode = nullptr;

    // Forward pass: Assign registers, spilling & optimizing as we go.
    for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
      bool AnySpilledBeforeThisInstruction = AnySpilled;

      // These do not read or write registers, and must be skipped for merging.
      // Since we'd be doing this check anyway for merging, do the check now so
      // we can skip the rest of the logic too.
      if (IROp->Op == OP_GUESTOPCODE || IROp->Op == OP_INLINECONSTANT) {
        // MACRUNNER_FEX_X87_FAULT_COVER: an inline constant (address offset, constant address) between a fault marker and its
        // memory op is an argument of that op; the marker stays pending for it instead of being dropped.
        if (IROp->Op == OP_GUESTOPCODE || !MRX87FaultCoverRA()) {
          PendingX87FaultState = nullptr;
        }
        continue;
      }
      if (IROp->Op == OP_X87FAULTSTATE) {
        PendingX87FaultState = CodeNode;
        continue;
      }

      // Static registers must be consistent at SRA load/store. Evict to ensure.
      if (auto Node = DecodeSRANode(IROp, CodeNode); Node != nullptr) {
        auto Reg = DecodeSRAReg(IROp, CodeNode);
        RegisterClassData* Class = &Classes[Reg.Class];

        if (!(Class->Available & (1u << Reg.Reg))) {
          Ref Old = Class->RegToSSA[Reg.Reg];

          if (Old != Node) {
            // Before inserting instructions, we need to set the cursor and
            // reset LastNode so we don't merge across an inserted copy.
            // Otherwise, we would erroneously miss the copy when determining if
            // we can merge, and end up unsoundly merging a mov+xchg sequence.
            IREmit->SetWriteCursorBefore(CodeNode);
            LastNode = nullptr;

            Ref Copy;

            if (Reg.AsRegClass() == RegClass::FPRFixed) {
              IROp_Header* Header = IR->GetOp<IROp_Header>(Old);
              Copy = IREmit->_VMov(Header->Size, OrderedNodeWrapper::FromImmediate(Reg.Raw));
            } else {
              Copy = IREmit->_Copy(OrderedNodeWrapper::FromImmediate(Reg.Raw));
            }

            FreeReg(Reg);
            AssignReg(IR->GetOp<IROp_Header>(Copy), BlockIROp, Copy, IROp);
            RemapReg(Old, PhysicalRegister(Copy));
          }
        }
      }

      // Fill all sources that are not already in the register file.
      //
      // This happens before freeing killed sources, since we need all sources in
      // the register file simultaneously.
      //
      // Also update next-use info, again only relevant if we've spilled.
      int NumArgs = IR::GetRAArgs(IROp->Op);

      if (AnySpilledBeforeThisInstruction) {
        for (int s = 0; s < NumArgs; ++s) {
          auto V = IROp->Args[s];
          V.ClearKill();

          if (!IsValidArg(V)) {
            continue;
          }

          Ref Old = IR->GetNode(V);

          SourceIndex--;
          LOGMAN_THROW_A_FMT(SourceIndex >= 0, "Consistent source count");
          NextUses[V.ID().Value] = SourcesNextUses[SourceIndex];

          if (!IsInRegisterFile(Old)) {
            IREmit->SetWriteCursorBefore(CodeNode);
            LastNode = nullptr;

            Ref Fill = InsertFill(Old);

            AssignReg(IR->GetOp<IROp_Header>(Fill), BlockIROp, Fill, IROp);
            RemapReg(Old, PhysicalRegister(Fill));
          }
        }
      }

      Ref X87FaultState = PendingX87FaultState;
      PendingX87FaultState = nullptr;
      if (X87FaultState) {
        ResolveX87FaultState(X87FaultState, CodeNode);
      }

      for (int s = 0; s < NumArgs; ++s) {
        if (IROp->Args[s].IsInvalid()) {
          continue;
        }

        bool Kill = IROp->Args[s].HasKill();
        IROp->Args[s].ClearKill();
        Ref Node = IR->GetNode(IROp->Args[s]);
        auto ID = IR->GetID(Node).Value;
        auto Reg = SSAToReg[ID];

        if (!Reg.IsInvalid()) {
          if (Kill) {
            LOGMAN_THROW_A_FMT(IsInRegisterFile(Node), "sources in file");
            FreeReg(Reg);
          }

          IROp->Args[s].SetImmediate(Reg.Raw);
        }
      }

      // Assign destinations.
      HoistedStaticCopy = false;
      if (GetHasDest(IROp->Op) && PhysicalRegister(CodeNode).IsInvalid()) {
        AssignReg(IROp, BlockIROp, CodeNode, IROp);
      }
      if (X87FaultState) {
        CheckX87FaultStateDest(X87FaultState, CodeNode);
      }
      if (HoistedStaticCopy) {
        LastNode = nullptr;
      }

      if (IsTrivial(CodeNode, IROp)) {
        // Delete instructions that only exist for RA
        IREmit->RemovePostRA(CodeNode);
      } else if (LastNode && TryPostRAMerge(LastNode, CodeNode, IROp)) {
        // Merge adjacent instructions
        IREmit->RemovePostRA(LastNode);
        LastNode = nullptr;
      } else {
        LastNode = CodeNode;
      }
      // LAZY-FLAGS: a pure FP op survives the dead-code pass with zero uses only because the
      // lazy MXCSR key keeps it for its host FPSR effect. Release its destination at once.
      if (LazyDeadDefs && GetHasDest(IROp->Op) && CodeNode->GetUses() == 0 && !IR::HasSideEffects(IROp->Op) &&
          !IsTrivial(CodeNode, IROp)) {
        if (auto Reg = PhysicalRegister(CodeNode); !Reg.IsInvalid() && IsInRegisterFile(CodeNode)) {
          FreeReg(Reg);
        }
      }
    }

    if (AnySpilled) {
      LOGMAN_THROW_A_FMT(SourceIndex == 0, "Consistent source count in block");
    }
  }

  PreferredReg.clear();
  SSAToReg.clear();
  SpillSlots.clear();
  NextUses.clear();
  Seen.clear();

  IR->GetHeader()->PostRA = true;
}

// Location encoding written back into the X87FaultState marker: 0 = unrecoverable; kind in bits 28..31.
namespace X87FaultLoc {
  constexpr uint32_t Register = 1U << 28; // | PhysicalRegister::Raw
  constexpr uint32_t Spill = 2U << 28;    // | slot
  constexpr uint32_t Constant = 3U << 28; // | low 8 bits of the constant (TOP only)
} // namespace X87FaultLoc

void ConstrainedRAPass::ResolveX87FaultState(Ref Marker, Ref Target) {
  auto* Op = IR->GetOp<IROp_X87FaultState>(Marker);
  Op->Mode |= 0x80;
  const bool OnTarget = IR->GetID(Target).Value == Op->Target;
  const auto Resolve = [&](uint32_t ID) -> uint32_t {
    if (!ID || !OnTarget || ID >= SSAToReg.size()) {
      return 0;
    }
    OrderedNodeWrapper Wrapped;
    Wrapped.NodeOffset = ID * sizeof(OrderedNode);
    Ref Node = IR->GetNode(Wrapped);
    const auto* Header = IR->GetOp<IROp_Header>(Node);
    // In the register file (the target's own killed sources are freed only after this point).
    const PhysicalRegister Reg = SSAToReg[ID];
    if (!Reg.IsInvalid() && IsInRegisterFile(Node)) {
      return X87FaultLoc::Register | Reg.Raw;
    }
    if (!SpillSlots.empty() && SpillSlots[ID]) {
      return X87FaultLoc::Spill | (SpillSlots[ID] - 1);
    }
    if (Header->Op == OP_CONSTANT) {
      return X87FaultLoc::Constant | (Header->C<IROp_Constant>()->Constant & 0xff);
    }
    return 0;
  };
  bool Complete = OnTarget;
  if (Op->Mode & 4) {
    Op->Top = Resolve(Op->Top);
    Complete &= Op->Top != 0;
  } else {
    Op->Top = 0;
  }
  uint32_t* Values = &Op->Value0;
  for (unsigned i = 0; i < 8; ++i) {
    if (Op->ValueMask & (1U << i)) {
      Values[i] = Resolve(Values[i]);
      Complete &= Values[i] != 0;
    } else {
      Values[i] = 0;
    }
  }
  if (!Complete) {
    Op->Mode = 0; // incomplete: no table entry, the fault keeps today's state
  }
}

// The target's own destination may reuse a register freed by a kill at the target; a value recorded there is then unsafe.
void ConstrainedRAPass::CheckX87FaultStateDest(Ref Marker, Ref Target) {
  auto* Op = IR->GetOp<IROp_X87FaultState>(Marker);
  if (!(Op->Mode & 0x80) || !GetHasDest(IR->GetOp<IROp_Header>(Target)->Op)) {
    return;
  }
  const uint32_t Dest = X87FaultLoc::Register | PhysicalRegister(Target).Raw;
  const uint32_t* Values = &Op->Value0;
  bool Clash = (Op->Mode & 4) && Op->Top == Dest;
  for (unsigned i = 0; i < 8; ++i) {
    Clash |= (Op->ValueMask & (1U << i)) && Values[i] == Dest;
  }
  if (Clash) {
    Op->Mode = 0;
  }
}

fextl::unique_ptr<IR::Pass> CreateRegisterAllocationPass(const CPUIDEmu* CPUID) {
  return fextl::make_unique<ConstrainedRAPass>(CPUID);
}
} // namespace FEXCore::IR
