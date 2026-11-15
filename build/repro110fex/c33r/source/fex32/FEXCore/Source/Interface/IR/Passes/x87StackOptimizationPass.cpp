// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
#include "Interface/Core/HBX87IR.h"
#include "Interface/Core/HBX87StateGates.h"
#include "Interface/Core/HBX87PCX.h"
#include "Interface/Core/HBX87S32.h" // X87EXACT S32
#include "Interface/Core/G3RP.h"
#include "Interface/Core/G3UnitShape.h"
#include "FEXCore/Utils/LogManager.h"
#include "Interface/Core/Interpreter/Fallbacks/FallbackOpHandler.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "FEXCore/IR/IR.h"
#include "FEXCore/Utils/Profiler.h"
#include "FEXCore/Core/HostFeatures.h"
#include "Interface/Core/Addressing.h"

#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/unordered_set.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdint.h>

// This file adds a pass to process X87 stack instructions.
// These instructions are marked in IR.json with `X87: true` and are generated
// by X87 guest instructions.
// The way is works is that there's a virtual stack `StackData`, where we load and store
// and apply the operations in a block of code. Once the block finishes, we emit the necessary operations
// that we recorded onto the virtual stack. This allows us to save a lot of code movement
// to and from stack registers, top management and valid flags. It also allows us to
// perform memcpy optimizations like the one performed in STORESTACKMEM.
//
// By default we run on the fast path - i.e. we assume all values are in the stack and we have a complete
// stack overview. However, if we encounter a value that's not in the virtual stack - maybe it was added
// to the stack in a previous block, we move onto the slow path which loads and stores values to the stack
// registers.
// Once in a slow path, we won't return to the fast pass until the beginning of the following block.

namespace FEXCore::IR {
static bool MRX87FaultCover();
static bool IsGuestMemoryOp(const IRListView& IR, const IROp_Header* Op);

// FIXME(pmatos): copy from OpcodeDispatcher.h
static uint32_t MMBaseOffset() {
  return static_cast<uint32_t>(offsetof(Core::CPUState, mm[0][0]));
}

// Similar helper to the one in OpcodeDispatcher.h except we do not
// need to handle flags, etc.
template<typename T>
static void DeriveOp(Ref& RefV, IROps NewOp, IREmitter::IRPair<T> Expr) {
  Expr.first->Header.Op = NewOp;
  RefV = Expr;
}

enum class StackSlot { UNUSED, INVALID, VALID };
// FixedSizeStack is a model of the x87 Stack where each element in this
// fixed size stack lives at an offset from top. The top of the stack is at
// index 0.
template<typename T>
class FixedSizeStack {
public:
  struct StackSlotEntry final {
    StackSlot Type = StackSlot::UNUSED;
    T Value = T::Invalid;
  };

  static constexpr uint8_t size = 8;

  // Real top as an offset from stored top value (or the one at the beginning of the block)
  // For example, if we start and push a value to our simulated stack, because we don't
  // update top straight away the TopOffset is 1.
  // If SlowPath is true, then TopOffset is always zero.
  int8_t TopOffset = 0;

  FixedSizeStack() = default;

  void push(const T& Value) {
    rotate();
    buffer.front() = {StackSlot::VALID, Value};
    dirty.front() = true;
    seeded.front() = false;
  }

  // Rotate the elements with the direction controlled by Right
  void rotate(bool Right = true) {
    if (Right) {
      std::rotate(buffer.begin(), buffer.end() - 1, buffer.end());
      std::rotate(dirty.begin(), dirty.end() - 1, dirty.end());
      std::rotate(seeded.begin(), seeded.end() - 1, seeded.end());
      TopOffset++;
    } else {
      std::rotate(buffer.begin(), buffer.begin() + 1, buffer.end());
      std::rotate(dirty.begin(), dirty.begin() + 1, dirty.end());
      std::rotate(seeded.begin(), seeded.begin() + 1, seeded.end());
      TopOffset--;
    }
  }

  void pop() {
    buffer.front() = {StackSlot::INVALID, T::Invalid};
    dirty.front() = true;
    seeded.front() = false;
    rotate(false);
  }

  const StackSlotEntry& top(size_t Offset = 0) const {
    return buffer[Offset];
  }

  void setTop(const T& Value, size_t Offset = 0) {
    buffer[Offset] = {StackSlot::VALID, Value};
    dirty[Offset] = true;
    seeded[Offset] = false;
  }

  bool isValid(size_t Offset) const {
    return buffer[Offset].Type == StackSlot::VALID;
  }

  void clear() {
    buffer.fill({StackSlot::UNUSED, T::Invalid});
    dirty.fill(false);
    seeded.fill(false);
    TopOffset = 0;
  }

  void dump() const {
    LogMan::Msg::DFmt("-- Stack");

    for (size_t i = 0; i < buffer.size(); i++) {
      const auto& [Valid, Element] = buffer[i];
      if (Valid == StackSlot::VALID) {
        LogMan::Msg::DFmt("| ST{}: 0x{:x}", i, (uintptr_t)(Element.StackDataNode));
      } else if (Valid == StackSlot::INVALID) {
        LogMan::Msg::DFmt("| ST{}: INVALID", i);
      }
    }
    LogMan::Msg::DFmt("--");
  }

  void setTagInvalid(size_t Index) {
    buffer[Index].Type = StackSlot::INVALID;
    dirty[Index] = true;
    seeded[Index] = false;
  }

  // SHAPE: a slot typed at the block start from the unit's known shape, matching CPUState (not dirty).
  void seed(size_t Offset, StackSlot Type, const T& Value) {
    buffer[Offset] = {Type, Value};
    dirty[Offset] = false;
    seeded[Offset] = true;
  }
  // SHAPE: typed only by the start shape (no op of this block has written the slot).
  bool isSeeded(size_t Offset) const {
    return seeded[Offset];
  }
  void setValue(size_t Offset, const T& Value) {
    buffer[Offset].Value = Value;
  }

  // X87-CTX P5: the slot (value or tag) differs from CPUState until the next synchronization.
  bool isDirty(size_t Offset) const {
    return dirty[Offset];
  }

  // All slots now match CPUState (their stores are scheduled); the entries stay as a value cache.
  void markClean() {
    dirty.fill(false);
  }

  // Returns a mask to set in AbridgedTagWord
  uint8_t getValidMask() const {
    uint8_t Mask = 0;
    for (size_t i = 0; i < buffer.size(); i++) {
      if (buffer[i].Type == StackSlot::VALID) {
        Mask |= 1U << i;
      }
    }
    return Mask;
  }

  // Returns a mask to set in AbridgedTagWord
  uint8_t getInvalidMask() const {
    uint8_t Mask = 0;
    for (size_t i = 0; i < buffer.size(); i++) {
      if (buffer[i].Type == StackSlot::INVALID) {
        Mask |= 1U << i;
      }
    }
    return Mask;
  }

private:
  std::array<StackSlotEntry, size> buffer {};
  std::array<bool, size> dirty {};
  std::array<bool, size> seeded {};
};

// G3FABLE: MACRUNNER_FEX32_X87_RP_PC24 -- round an RP arithmetic result to a 24-bit significand when FCW says PC = 24, RC = nearest.
// RP2: Rnd / Odd / Msk are block-cached selections on FCW (0x0FFFFFFF / 1 / ~0x1FFFFFFF under PC24 + RN, else 0 / 0 / ~0).
template<typename Emitter>
static Ref G3RoundPC24(Emitter* IREmit, Ref V, Ref& Rnd, Ref& Odd, Ref& Msk, Ref& Vm) {
  const auto C = [&](uint64_t v) { return IREmit->_Constant(static_cast<int64_t>(v)); };
  if (!Rnd) {
    // M = all ones when FCW has PC = 24 and RC = nearest, else 0 -- no host flags involved
    Ref Pc = IREmit->_And(OpSize::i64Bit, IREmit->_Lshr(OpSize::i64Bit, IREmit->_LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, FCW)), C(8)), C(15));
    Ref M = IREmit->_Ashr(OpSize::i64Bit, IREmit->_Sub(OpSize::i64Bit, Pc, C(1)), C(63));
    Rnd = IREmit->_And(OpSize::i64Bit, M, C(0x0FFFFFFFULL));
    Odd = IREmit->_And(OpSize::i64Bit, M, C(1));
    Msk = IREmit->_Xor(OpSize::i64Bit, IREmit->_And(OpSize::i64Bit, M, C(0x1FFFFFFFULL)), C(~0ULL));
  }
  if (FEXCore::HBX87::RP::PC24Mode() == 2) { // RP3 prototype: fcvt d->s->d, selected by the block-cached FCW mask
    if (!Vm) Vm = IREmit->_VDupFromGPR(OpSize::i64Bit, OpSize::i64Bit, IREmit->_Neg(OpSize::i64Bit, Odd));
    Ref Rt = IREmit->_Float_FToF(OpSize::i64Bit, OpSize::i32Bit, IREmit->_Float_FToF(OpSize::i32Bit, OpSize::i64Bit, V));
    return IREmit->_VBSL(OpSize::i64Bit, Vm, Rt, V);
  }
  Ref Bits = IREmit->_VExtractToGPR(OpSize::i64Bit, OpSize::i64Bit, V, 0);
  Ref T = IREmit->_Add(OpSize::i64Bit, IREmit->_Add(OpSize::i64Bit, Bits, Rnd), IREmit->_And(OpSize::i64Bit, IREmit->_Lshr(OpSize::i64Bit, Bits, C(29)), Odd));
  return IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, IREmit->_And(OpSize::i64Bit, T, Msk));
}

class X87StackOptimization final : public Pass {
public:
  X87StackOptimization(const FEXCore::HostFeatures& Features, OpSize GPROpSize)
    : Features(Features)
    , GPROpSize(GPROpSize) {
    FEX_CONFIG_OPT(ReducedPrecision, X87REDUCEDPRECISION);
    ReducedPrecisionMode = ReducedPrecision;
    BaseReducedPrecision = ReducedPrecision;
    FaultStateEnabled = FEXCore::HBX87::StateFix::FaultState();
  }
  void Run(IREmitter* Emit) override;

private:
  const FEXCore::HostFeatures& Features;
  const OpSize GPROpSize;
  bool ReducedPrecisionMode;
  // TRANS32 MACRUNNER_FEX32_X87_PC_EXACT (HBX87PCX.h): a PCX block keeps containers on the stack (ReducedPrecisionMode
  // paths for the stack itself) while CPUState keeps the 80-bit format (conversions at every context access).
  bool BaseReducedPrecision = false;
  uint8_t PCXMode = 0;
  bool PCXBlock = false;
  bool PCXC1 = false;
  bool PCXPE = false;
  bool PCXReadsState = false; // the block loads mm[] / AbridgedFTW from CPUState (FXSAVE, FNSTENV ...)
  // SHAPE (HBX87PCX.h ShapeEnabled): the block's start shape is known (StackData seeded, see Run). ShapeRef: the valid bits that
  // CPUState holds (or will, once the pending flushes are done), by offset from the TOP the TOP cache holds.
  bool ShapeBlock = false;
  bool G3PayloadBlock = false; // G3FABLE UNIT_SHAPE_PAYLOAD: this shape block stores popped values
  uint8_t ShapeRef = 0;
  // SHAPE_LAG (HBX87PCX.h ShapeLagEnabled): LagOn for the unit; LagKeepPending at a carrying block's end: TOP / tags not written.
  bool LagOn = false;
  bool LagKeepPending = false;
  // G3FABLE UNIT_SHAPE level 6: at a carrying block's end with the lag kept, the cells (from the lagging CPUState TOP) that leave
  // in SRA FPR 8 + cell instead of mm[].
  uint8_t G3RegCells = 0;
  bool G3Hold = false; // RP6d: this unit's lag shape blocks mark their fault records (RA holds the values to the target op)
  void G3StoreCell(Ref Value, unsigned Cell) {
    Ref R = IREmit->_StoreRegister(Value, OpSize::i128Bit);
    R->Reg = PhysicalRegister(RegClass::FPRFixed, static_cast<uint8_t>(8 + (Cell & 7))).Raw;
  }
  Ref MaterializeSeed(uint8_t Offset);
  Ref PendingC1 {};
  bool PCXEligible(const IRListView& IR, Ref BlockNode);
  Ref PCXArith(unsigned Kind, Ref A, Ref B);
  void PCXNoteC1Writer(Ref Node);
  bool IsPCXContainer(const IRListView& IR, Ref Node) const;
#include "Interface/IR/Passes/x87S32.inl" // X87EXACT S32: the type layer
  FEX_CONFIG_OPT(DisableVixlIndirectCalls, DISABLE_VIXL_INDIRECT_RUNTIME_CALLS);

  // Helpers
  Ref RotateRight8(uint32_t V, Ref Amount);

  void F80SplitStore_Helper(const IROp_StoreStackMem* Op, Ref StackNode, Ref AddrNode, Ref Offset, OpSize Align, MemOffsetType OffsetType,
                            uint8_t OffsetScale) {
    IREmit->_StoreMemFPR(OpSize::i64Bit, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
    auto Upper = IREmit->_VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, StackNode, 1);

    // Store the Upper part of the register (the remaining 2 bytes) into memory.
    AddressMode A {.Base = AddrNode,
                   .Index = Op->Offset.IsInvalid() ? nullptr : Offset,
                   .Offset = 8,
                   .IndexType = MemOffsetType::SXTX,
                   .IndexScale = OffsetScale,
                   .AddrSize = OpSize::i64Bit};
    A = SelectAddressMode(IREmit, A, GPROpSize, Features.SupportsTSOImm9, false, false, OpSize::i16Bit);
    IREmit->_StoreMemGPR(OpSize::i16Bit, Upper, A.Base, A.Index, OpSize::i64Bit, MemOffsetType::SXTX, A.IndexScale);
  }

  void Store80BitToMem(const IROp_StoreStackMem* Op, Ref StackNode, Ref AddrNode, Ref Offset, OpSize Align, MemOffsetType OffsetType,
                       uint8_t OffsetScale) {
    if (Features.SupportsSVE()) {
      AddressMode A {.Base = AddrNode,
                     .Index = Op->Offset.IsInvalid() ? nullptr : Offset,
                     .IndexType = MemOffsetType::SXTX,
                     .IndexScale = OffsetScale,
                     .AddrSize = OpSize::i64Bit};
      AddrNode = LoadEffectiveAddress(IREmit, A, GPROpSize, false);
      IREmit->_StoreMemX87SVEOptPredicate(OpSize::i128Bit, OpSize::i16Bit, StackNode, AddrNode);
    } else {
      F80SplitStore_Helper(Op, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
    }
  }

  void StoreStackMem_Helper(const IRListView& IR, const IROp_StoreStackMem* Op, Ref StackNode) {
    LOGMAN_THROW_A_FMT(!ReducedPrecisionMode, "Full precision mode expected.");

    Ref AddrNode = IR.GetNode(Op->Addr);
    Ref Offset = IR.GetNode(Op->Offset);
    OpSize Align = Op->Align;
    MemOffsetType OffsetType = Op->OffsetType;
    uint8_t OffsetScale = Op->OffsetScale;

    // Normal Precision Mode
    switch (Op->StoreSize) {
    case OpSize::i32Bit:
    case OpSize::i64Bit: {
      // 0219: establish precision provenance while arguments still name SSA
      // nodes. Register allocation later rewrites them to physical registers.
      // ElementSize is unused by scalar F80CVT/fallback; iUnsized is an exact
      // significand-lattice annotation, without changing IR layout or opcode.
      bool ProvenLowBits = false;
      bool ProvenRoundedPack = false;
      if (GPROpSize == OpSize::i64Bit && FEXCore::HBX87::Guest64Enabled()) {
        const unsigned ClearBits = Op->StoreSize == OpSize::i64Bit ? 11 : 40;
        unsigned Budget = 16;
        auto ClearLowBits = [&](auto&& Self, Ref Source, unsigned Rounds, bool RoundedOnly) -> bool {
          if (!Budget) return false;
          --Budget;
          const auto Producer = IR.GetOp<IROp_Header>(Source);
          auto Arg = [&](unsigned Index) -> Ref {
            const auto Wrapper = Producer->Args[Index];
            return Wrapper.IsImmediate() || Wrapper.IsInvalid() ? Ref {} : IR.GetNode(Wrapper);
          };
          if (Producer->Op == OP_F80ROUND) {
            const auto Input = Arg(0);
            return Rounds < 3 && Input && Self(Self, Input, Rounds + 1, RoundedOnly);
          }
          if (Producer->Op == OP_F80CVTTO) {
            const auto Width = Producer->C<IROp_F80CVTTo>()->SrcSize;
            return (!RoundedOnly || Rounds) &&
                   (Width == OpSize::i32Bit || (ClearBits == 11 && Width == OpSize::i64Bit));
          }
          if (Producer->Op == OP_VBSL) {
            // Bitwise selection preserves zero low bits independently of its
            // mask, when both alternatives have them. Keep the stack fault
            // selection, tag/status updates and subsequent exception handling.
            const auto TrueValue = Arg(1), FalseValue = Arg(2);
            return TrueValue && FalseValue &&
                   Self(Self, TrueValue, Rounds, RoundedOnly) && Self(Self, FalseValue, Rounds, RoundedOnly);
          }
          if (Producer->Op == OP_VLOADTWOGPRS) {
            const auto Low = Arg(0), High = Arg(1);
            if (!Low || !High) return false;
            const auto LowOp = IR.GetOp<IROp_Header>(Low);
            const auto HighOp = IR.GetOp<IROp_Header>(High);
            // Exact indefinite RAW80 used by the stack-fault path. It has
            // zero low bits and is still rejected by the exponent guard.
            return LowOp->Op == OP_CONSTANT && HighOp->Op == OP_CONSTANT &&
                   LowOp->template C<IROp_Constant>()->Constant == UINT64_C(0xc000000000000000) &&
                   HighOp->template C<IROp_Constant>()->Constant == UINT64_C(0xffff);
          }
          return false;
        };
        ProvenLowBits = ClearLowBits(ClearLowBits, StackNode, 0, false);
        if (ProvenLowBits) {
          Budget = 16;
          ProvenRoundedPack = ClearLowBits(ClearLowBits, StackNode, 0, true);
        }
      }
      auto StoreValue = IREmit->_F80CVT(Op->StoreSize, StackNode);
      if (ProvenLowBits) StoreValue.first->Header.ElementSize = OpSize::iUnsized;
      // Same-or-wider binary source after FRNDINT: finite results are zero or
      // representable integers, hence no target subnormal/overflow/rounding.
      // The other admitted alternative is the stack-fault quiet indefinite.
      if (ProvenRoundedPack) StoreValue.first->Header.ElementSize = OpSize::i16Bit;
      StackNode = StoreValue;
      IREmit->_StoreMemFPR(Op->StoreSize, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }

    case OpSize::f80Bit: {
      Store80BitToMem(Op, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }
    default: ERROR_AND_DIE_FMT("Unsupported x87 size");
    }
  }

  // Performs a store to memory from a value the stack passed in as StackNode.
  // This is the version dealing with the reduced precision case.
  void StoreStackMem_Reduced_Helper(const IRListView& IR, const IROp_StoreStackMem* Op, Ref StackNode) {
    LOGMAN_THROW_A_FMT(ReducedPrecisionMode, "Reduced precision mode expected.");

    Ref AddrNode = IR.GetNode(Op->Addr);
    Ref Offset = IR.GetNode(Op->Offset);
    OpSize Align = Op->Align;
    MemOffsetType OffsetType = Op->OffsetType;
    uint8_t OffsetScale = Op->OffsetScale;

    switch (Op->StoreSize) {
    case OpSize::i32Bit: {
      StackNode = IREmit->_Float_FToF(OpSize::i32Bit, OpSize::i64Bit, StackNode);
      [[fallthrough]];
    }
    case OpSize::i64Bit: {
      IREmit->_StoreMemFPR(Op->StoreSize, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }

    case OpSize::f80Bit: {
      StackNode = IREmit->_F80CVTTo(StackNode, OpSize::i64Bit);
      Store80BitToMem(Op, StackNode, AddrNode, Offset, Align, OffsetType, OffsetScale);
      break;
    }
    default: ERROR_AND_DIE_FMT("Unsupported x87 size");
    }
  }

  // Handles a Unary operation.
  // Takes the op we are handling, the Node for the reduced precision case and the node for the normal case.
  // Depending on the type of Op64, we might need to pass a couple of extra constant arguments, this happens
  // when VFOp64 is true.
  void HandleUnop(IROps Op64, bool VFOp64, IROps Op80);
  void HandleBinopValue(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, bool MarkDestValid, uint8_t StackOffset,
                        Ref ValueNode, bool Reverse = false);
  void HandleBinopStack(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, uint8_t StackOffset1, uint8_t StackOffset2,
                        bool Reverse = false);

  // Top Management Helpers
  /// Set the valid tag for Value as valid (if Valid is true), or invalid (if Valid is false).
  void SetX87ValidTag(uint8_t Offset, bool Valid);
  // Generates slow code to load/store a value from an offset from the top of the stack
  Ref LoadStackValueAtOffset_Slow(uint8_t Offset = 0);
  void StoreStackValueAtOffset_Slow(Ref Value, uint8_t Offset = 0, bool SetValid = true);
  // Update Top value in slow path for a pop
  void UpdateTopForPop_Slow(bool InvalidateTag = true);
  void UpdateTopForPush_Slow();
  // Synchronizes the current simulated stack with the actual values.
  // Returns a new value for Top, that's synchronized between the simulated stack
  // and the actual FPU stack.
  Ref SynchronizeStackValues();
  // Moves us from the fast to the slow path if ShouldMigrate is true.
  void MigrateToSlowPathIf(bool ShouldMigrate);
  // Top Cache Management
  Ref GetTopWithCache_Slow();
  Ref GetOffsetTopWithCache_Slow(uint8_t Offset, bool Reverse = false);
  Ref GetOffsetTopAddressWithCache_Slow(uint8_t Offset);
  void SetTopWithCache_Slow(Ref Value);
  Ref GetX87ValidTag_Slow(uint8_t Offset);
  // Resets fields to initial values
  void Reset();

  // x87 stack fault (#IS) on push.
  // A push lands in the slot at offset 7 from the current top. If that slot is still
  // tagged valid the push overflows the register stack, which is a masked invalid
  // operation: IE and SF latch, C1 says "overflow" (as opposed to underflow) and the
  // destination is loaded with the QNaN indefinite instead of the requested value.
  enum class PushOverflow {
    No,      // statically known not to overflow
    Yes,     // statically known to overflow
    Runtime, // Pred holds a 0/1 value that has to be tested at runtime
  };
  PushOverflow GetPushOverflow(Ref& Pred);
  void SetX87Flag(uint32_t FlagLoc, Ref Value);
  Ref GetX87Flag(uint32_t FlagLoc);
  Ref GetIndefiniteValue();
  // Applies the masked #IS above and returns the value that should actually be pushed.
  Ref ApplyPushOverflow(Ref Value);

  struct StackMemberInfo {
    constexpr StackMemberInfo() = default;
    constexpr StackMemberInfo(Ref Data)
      : StackDataNode(Data) {}
    constexpr StackMemberInfo(Ref Data, Ref Source, OpSize Size)
      : StackDataNode(Data)
      , Source({Size, Source}) {}
    Ref StackDataNode {}; // Reference to the data in the Stack.
                          // This is the source data node in the stack format, possibly converted to 64/80 bits.
    struct StackMemberData final {
      OpSize Size;
      Ref Node;
    };

    static const StackMemberInfo Invalid;

    // Tuple is only valid if we have information about the Source of the Stack Data Node.
    // In it's valid then OpSize is the original source size and Ref is the original source node.
    std::optional<StackMemberData> Source {};
    // SHAPE: a valid slot of a known start shape whose value is still in mm[] (no node yet): its offset from the TOP that the
    // block's TOP cache holds (the block start's, or the last synchronization's).
    int8_t SeedOffset = -1;
  };

  // StackData, TopCache need to be always properly set to ensure
  // they reflect the current state of the FPU. This sync only makes sense while
  // taking the fast path. Once in the slow path, these don't make sense anymore
  // and we are syncing everything.

  // Index on vector is offset to top value at start of block
  // If slow path is true, then StackData is always empty.
  FixedSizeStack<StackMemberInfo> StackData;

  void InvalidateCaches();
  void InvalidateCachedRegs();

  // Path Migration helper management
  std::optional<StackMemberInfo> MigrateToSlowPath_IfInvalid(uint8_t Offset = 0);
  Ref LoadStackValue(uint8_t Offset = 0);
  void StoreStackValue(Ref Value, uint8_t Offset = 0, bool SetValid = false);
  void StackPop();

  // Cache for Constants
  // ConstantPoll[i] has IREmit->_Constant(i);
  std::array<Ref, 8> ConstantPool {};
  Ref GetConstant(ssize_t Offset);

  // Cached value for Top
  // If slowpath is false, then TopCache is nullptr.
  bool FlushTopPending = false;
  // MACRUNNER_FEX_X87_FAULT_COVER: pushes minus pops since TOP in CPUState was last current (slow path); 99 = unknown.
  int SlowTopDelta = 0;
  std::array<bool, 8> FlushValuesPending {};
  bool FlushValidPending = false;
  bool PreserveConsumedSlots = false;
  void FlushCachedRegs();

  Ref GetFTW();

  Ref FTWCached {};
  Ref G3Rnd {}, G3Odd {}, G3Msk {}, G3Vm {}; // G3FABLE RP2: block-cached PC24 rounding constants
  std::array<Ref, 8> TopOffsetCache {};
  std::array<Ref, 8> TopOffsetAddressCache {};
  std::array<Ref, 8> TopValueCache {};
  std::array<StackSlot, 8> TopValidCache {};

  // Are we on the slow path?
  // Once we enter the slow path, we never come out.
  // This just simplifies the code atm. If there's a need to return to the fast path in the future
  // we can implement that but I would expect that there would be very few cases where that's necessary.
  // On the slow path TopCache is always the last obtained version of top.
  // TopOffset is ignored
  bool SlowPath = false;

  // Keeping IREmitter not to pass arguments around
  IREmitter* IREmit = nullptr;

  // X87-CTX P5 (MACRUNNER_FEX_X87_FAULT_STATE): what this pass still holds in SSA values instead of CPUState at the start of a
  // guest instruction, for the guest-memory ops inside it (X87FaultState markers, resolved by RA, tabled by the JIT).
  struct FaultSnapshot {
    Ref GuestOp {};
    bool Slow {};
    uint8_t TopOffset {};
    uint8_t ValueMask {};
    uint8_t ValidMask {};
    uint8_t InvalidMask {};
    uint8_t SingleMask {}; // X87EXACT S32: Values[i] is the single of a typed member
    Ref Top {};
    std::array<Ref, 8> Values {};
    bool TopRel {};
  };
  bool FaultStateEnabled = false;
  fextl::vector<FaultSnapshot> FaultSnapshots;
  // Stores of x87 state this pass emits inside an instruction: after one, CPUState no longer holds the pre-instruction state.
  fextl::vector<Ref> FlushNodes;
  void NoteFlush(Ref Node) {
    if (FaultStateEnabled) {
      FlushNodes.push_back(Node);
    }
  }
  void CaptureFaultState(Ref GuestOp);
  void InsertFaultMarkers(const IRListView& IR, Ref BlockNode);
};

inline const X87StackOptimization::StackMemberInfo X87StackOptimization::StackMemberInfo::Invalid {nullptr};

inline void X87StackOptimization::InvalidateCaches() {
  InvalidateCachedRegs();
  ConstantPool.fill(nullptr);
}

inline void X87StackOptimization::InvalidateCachedRegs() {
  FlushCachedRegs();
  FTWCached = {};
  G3Rnd = {}; G3Odd = {}; G3Msk = {}; G3Vm = {};
  TopOffsetCache.fill(nullptr);
  TopOffsetAddressCache.fill(nullptr);
  TopValueCache.fill(nullptr);
  TopValidCache.fill(StackSlot::UNUSED);
}

inline void X87StackOptimization::Reset() {
  SlowPath = false;
  PreserveConsumedSlots = false;
  StackData.clear();
  InvalidateCaches();
  FaultSnapshots.clear();
  FlushNodes.clear();
  SlowTopDelta = 0;
}

inline Ref X87StackOptimization::GetConstant(ssize_t Offset) {
  if (Offset < 0 || Offset >= X87StackOptimization::ConstantPool.size()) {
    // not dealt by pool
    return IREmit->_Constant(Offset);
  }
  if (ConstantPool[Offset] == nullptr) {

    ConstantPool[Offset] = IREmit->_Constant(Offset);
  }
  return ConstantPool[Offset];
}

inline void X87StackOptimization::MigrateToSlowPathIf(bool ShouldMigrate) {
  if (ShouldMigrate && !SlowPath) {
    SynchronizeStackValues();
    StackData.clear();
    SlowPath = true;
    if (!(MRX87FaultCover() && FlushTopPending)) { // RP6h: a TOP left pending by the migration keeps its known shift
      SlowTopDelta = 0;
    }
  }
}

inline Ref X87StackOptimization::GetTopWithCache_Slow() {
  if (!TopOffsetCache[0]) {
    TopOffsetCache[0] = IREmit->_LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC);
  }
  return TopOffsetCache[0];
}

inline Ref X87StackOptimization::GetOffsetTopWithCache_Slow(uint8_t Offset, bool Reverse) {
  if (Reverse) {
    Offset = 8 - Offset;
  }

  Offset &= 7;

  if (TopOffsetCache[Offset]) {
    return TopOffsetCache[Offset];
  }

  auto* OffsetTop = GetTopWithCache_Slow();
  if (Offset != 0) {
    OffsetTop = IREmit->_And(OpSize::i32Bit, IREmit->Add(OpSize::i32Bit, OffsetTop, Offset), GetConstant(7));
    // GetTopWithCache_Slow already sets the cache so we don't need to set it here for offset == 0
    TopOffsetCache[Offset] = OffsetTop;
  }

  return OffsetTop;
}

inline Ref X87StackOptimization::GetOffsetTopAddressWithCache_Slow(uint8_t Offset) {
  if (TopOffsetAddressCache[Offset]) {
    return TopOffsetAddressCache[Offset];
  }

  Ref OffsetRef = GetOffsetTopWithCache_Slow(Offset);
  TopOffsetAddressCache[Offset] = IREmit->_FormContextAddress(OpSize::i64Bit, OffsetRef, 16);

  return TopOffsetAddressCache[Offset];
}

inline void X87StackOptimization::SetTopWithCache_Slow(Ref Value) {
  InvalidateCachedRegs();
  TopOffsetCache[0] = Value;
  FlushTopPending = true;
  SlowTopDelta = 99;
}

inline Ref X87StackOptimization::GetFTW() {
  if (!FTWCached) {
    FTWCached = IREmit->_LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, AbridgedFTW));
  }
  return FTWCached;
}

inline void X87StackOptimization::SetX87ValidTag(uint8_t Offset, bool Valid) {
  TopValidCache[Offset] = Valid ? StackSlot::VALID : StackSlot::INVALID;
  FlushValidPending = true;
}

inline Ref X87StackOptimization::GetX87ValidTag_Slow(uint8_t Offset) {
  switch (TopValidCache[Offset]) {
  case StackSlot::UNUSED:
    return IREmit->_And(OpSize::i32Bit, IREmit->_Lshr(OpSize::i32Bit, GetFTW(), GetOffsetTopWithCache_Slow(Offset)), GetConstant(1));
  case StackSlot::INVALID: return GetConstant(0);
  case StackSlot::VALID: return GetConstant(1);
  }
}

inline void X87StackOptimization::SetX87Flag(uint32_t FlagLoc, Ref Value) {
  NoteFlush(IREmit->_StoreContextGPR(OpSize::i8Bit, Value, offsetof(FEXCore::Core::CPUState, flags) + FlagLoc));
}

inline Ref X87StackOptimization::GetX87Flag(uint32_t FlagLoc) {
  return IREmit->_LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, flags) + FlagLoc);
}

inline Ref X87StackOptimization::GetIndefiniteValue() {
  if (PCXBlock) {
    return IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, IREmit->_Constant(static_cast<int64_t>(FEXCore::HBX87::PCX::IndefBox)));
  }
  if (ReducedPrecisionMode) {
    // QNaN indefinite expressed as a double.
    return IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, IREmit->_Constant(static_cast<int64_t>(0xFFF8000000000000ULL)));
  }
  // 80-bit QNaN indefinite: sign 1, exponent 0x7FFF, significand 0xC000000000000000.
  return IREmit->_VLoadTwoGPRs(IREmit->_Constant(static_cast<int64_t>(0xC000000000000000ULL)), IREmit->_Constant(0xFFFF));
}

X87StackOptimization::PushOverflow X87StackOptimization::GetPushOverflow(Ref& Pred) {
  const StackSlot Tag = SlowPath ? TopValidCache[7] : StackData.top(7).Type;

  if (Tag == StackSlot::VALID) {
    return PushOverflow::Yes;
  }
  if (Tag == StackSlot::INVALID) {
    return PushOverflow::No;
  }

  if (SlowPath) {
    Pred = GetX87ValidTag_Slow(7);
    return PushOverflow::Runtime;
  }

  // Fast path with an untouched slot. Untouched means this block has neither written
  // that register nor flushed Top, so the tag word and Top still in the context are
  // exactly the ones this block started with and can be read directly. Deliberately
  // not via the *_Slow caches - those are only maintained once on the slow path.
  Ref Top =
    IREmit->_LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC);
  Ref FTW = IREmit->_LoadContextGPR(OpSize::i8Bit, offsetof(FEXCore::Core::CPUState, AbridgedFTW));

  // Slot = (Top - TopOffset - 1) mod 8, written as an addition to keep the constant positive.
  const uint32_t Bias = static_cast<uint32_t>(-(StackData.TopOffset + 1)) & 7;
  Ref Slot = IREmit->_And(OpSize::i32Bit, IREmit->_Add(OpSize::i32Bit, Top, GetConstant(Bias)), GetConstant(7));
  Pred = IREmit->_And(OpSize::i32Bit, IREmit->_Lshr(OpSize::i32Bit, FTW, Slot), GetConstant(1));
  return PushOverflow::Runtime;
}

Ref X87StackOptimization::ApplyPushOverflow(Ref Value) {
  Ref Pred {};
  switch (GetPushOverflow(Pred)) {
  case PushOverflow::No: return Value;

  case PushOverflow::Yes:
    SetX87Flag(FEXCore::X86State::X87FLAG_IE_LOC, GetConstant(1));
    SetX87Flag(FEXCore::X86State::X87FLAG_SF_LOC, GetConstant(1));
    SetX87Flag(FEXCore::X86State::X87FLAG_C1_LOC, GetConstant(1));
    return GetIndefiniteValue();

  case PushOverflow::Runtime: {
    // IE and SF are sticky, so they are OR'd in. C1 is only ever set here - a
    // successful push is left alone so that a C1 written by the instruction itself
    // (FXTRACT, FSINCOS, ...) is not clobbered.
    SetX87Flag(FEXCore::X86State::X87FLAG_IE_LOC,
               IREmit->_Or(OpSize::i32Bit, GetX87Flag(FEXCore::X86State::X87FLAG_IE_LOC), Pred));
    SetX87Flag(FEXCore::X86State::X87FLAG_SF_LOC,
               IREmit->_Or(OpSize::i32Bit, GetX87Flag(FEXCore::X86State::X87FLAG_SF_LOC), Pred));
    SetX87Flag(FEXCore::X86State::X87FLAG_C1_LOC,
               IREmit->_Or(OpSize::i32Bit, GetX87Flag(FEXCore::X86State::X87FLAG_C1_LOC), Pred));

    const auto RegSize = (ReducedPrecisionMode && !FEXCore::HBX87::RP::Int64()) ? OpSize::i64Bit : OpSize::i128Bit;
    Ref Mask = IREmit->_VDupFromGPR(RegSize, OpSize::i64Bit, IREmit->_Neg(OpSize::i64Bit, Pred));
    if (Ref MRSingle = S32Of(Value)) { // X87EXACT S32: a typed value stays typed -- the indefinite as a box in a single
      return S32Make(IREmit->_VBSL(OpSize::i64Bit, Mask, S32Indefinite(), MRSingle));
    }
    return IREmit->_VBSL(RegSize, Mask, GetIndefiniteValue(), Value);
  }
  }

  return Value;
}

inline Ref X87StackOptimization::LoadStackValueAtOffset_Slow(uint8_t Offset) {
  OrderedNode* TopOffsetAddress = GetOffsetTopAddressWithCache_Slow(Offset);
  auto Size = (ReducedPrecisionMode && !FEXCore::HBX87::RP::Int64()) ? OpSize::i64Bit : OpSize::i128Bit;
  if (!TopValueCache[Offset]) {
    if (PCXBlock) {
      Ref Raw = IREmit->_LoadMemFPR(OpSize::i128Bit, TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), OpSize::i128Bit,
                                    MemOffsetType::SXTX, 1);
      TopValueCache[Offset] = IREmit->_X87PCXFrom80(Raw);
    } else {
      TopValueCache[Offset] = IREmit->_LoadMemFPR(Size, TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1);
    }
  }
  return TopValueCache[Offset];
}

inline void X87StackOptimization::StoreStackValueAtOffset_Slow(Ref Value, uint8_t Offset, bool SetValid) {
  TopValueCache[Offset] = Value;
  FlushValuesPending[Offset] = true;
  // mark it valid
  // In some cases we might already know it has been previously set as valid so we don't need to do it again
  if (SetValid) {
    SetX87ValidTag(Offset, true);
  }
}

inline Ref X87StackOptimization::RotateRight8(uint32_t V, Ref Amount) {
  return IREmit->_Lshr(OpSize::i32Bit, GetConstant(V | (V << 8)), Amount);
}

// SHAPE: the value of a seeded slot, loaded at the write cursor from mm[] (nothing has been stored there since: only dirty slots
// are). The slot's dirty state is kept.
Ref X87StackOptimization::MaterializeSeed(uint8_t Offset) {
  const auto& Entry = StackData.top(Offset);
  if (Entry.Type != StackSlot::VALID || Entry.Value.StackDataNode || Entry.Value.SeedOffset < 0) {
    return Entry.Value.StackDataNode;
  }
  Ref Address = GetOffsetTopAddressWithCache_Slow(static_cast<uint8_t>(Entry.Value.SeedOffset));
  Ref Value {};
  if (PCXBlock) {
    Ref Raw = IREmit->_LoadMemFPR(OpSize::i128Bit, Address, IREmit->_InlineConstant(MMBaseOffset()), OpSize::i128Bit, MemOffsetType::SXTX, 1);
    Value = IREmit->_X87PCXFrom80(Raw);
  } else { // v5: the exact path's own representation (LoadStackValueAtOffset_Slow)
    const auto Size = (ReducedPrecisionMode && !FEXCore::HBX87::RP::Int64()) ? OpSize::i64Bit : OpSize::i128Bit;
    Value = IREmit->_LoadMemFPR(Size, Address, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1);
  }
  StackData.setValue(Offset, StackMemberInfo {Value});
  return Value;
}

inline std::optional<X87StackOptimization::StackMemberInfo> X87StackOptimization::MigrateToSlowPath_IfInvalid(uint8_t Offset) {
  if (ShapeBlock && !SlowPath) {
    MaterializeSeed(Offset);
  }
  const auto& [Valid, StackMember] = StackData.top(Offset);
  MigrateToSlowPathIf(Valid != StackSlot::VALID);
  if (Valid == StackSlot::VALID) {
    return StackMember;
  }
  return {};
}

inline Ref X87StackOptimization::LoadStackValue(uint8_t Offset) {
  const auto& StackValue = MigrateToSlowPath_IfInvalid(Offset);
  return SlowPath ? LoadStackValueAtOffset_Slow(Offset) : StackValue->StackDataNode;
}

inline void X87StackOptimization::StoreStackValue(Ref Value, uint8_t Offset, bool SetValid) {
  if (SlowPath) {
    StoreStackValueAtOffset_Slow(Value, Offset, SetValid);
  } else {
    StackData.setTop(StackMemberInfo {Value}, Offset);
  }
}

inline void X87StackOptimization::StackPop() {
  if (SlowPath) {
    // Every consuming pop destroys the old ST0 (upstream 21b8f8e20: UpdateTopForPop_Slow invalidates by default).
    // FINCSTP calls UpdateTopForPop_Slow(false) and preserves the physical tag.
    UpdateTopForPop_Slow();
  } else {
    if (PreserveConsumedSlots) {
      // FLDCW's original slow path materialized this physical payload even
      // when the consuming pop made its tag empty. Preserve those bytes
      // without dropping the full80 SSA value or storing on every arithmetic.
      const auto& [Valid, Member] = StackData.top(0);
      if (Valid == StackSlot::VALID) {
        Ref Top = GetOffsetTopWithCache_Slow(StackData.TopOffset, true);
        NoteFlush(IREmit->_StoreContextFPRIndexed(Member.StackDataNode, Top, OpSize::i128Bit,
                                                MMBaseOffset(), IR::OpSizeToSize(OpSize::i128Bit)));
      }
    } else if (G3PayloadBlock) {
      const auto& [Valid, Member] = StackData.top(0);
      if (Valid == StackSlot::VALID && StackData.isDirty(0) && Member.StackDataNode) {
        const auto Size = (ReducedPrecisionMode && !FEXCore::HBX87::RP::Int64()) ? OpSize::i64Bit : OpSize::i128Bit;
        Ref Top = GetOffsetTopWithCache_Slow(StackData.TopOffset, true);
        NoteFlush(IREmit->_StoreContextFPRIndexed(Member.StackDataNode, Top, Size, MMBaseOffset(), IR::OpSizeToSize(OpSize::i128Bit)));
      }
    }
    StackData.pop();
  }
}


void X87StackOptimization::HandleUnop(IROps Op64, bool VFOp64, IROps Op80) {
  Ref St0 = LoadStackValue();
  Ref Value {};
  if (Op80 == IR::OP_F80SQRT && S32Sqrt(St0)) { // X87EXACT S32
    return;
  }

  if (PCXBlock) {
    Value = PCXArith(FEXCore::HBX87::PCX::OpSqrt, St0, St0);
  } else if (ReducedPrecisionMode) {
    if (VFOp64) {
      DeriveOp(Value, Op64, IREmit->_VFSqrt(OpSize::i64Bit, OpSize::i64Bit, St0));
      if (FEXCore::HBX87::RP::PC24() && Op64 == IR::OP_VFSQRT) Value = G3RoundPC24(IREmit, Value, G3Rnd, G3Odd, G3Msk, G3Vm);
    } else {
      DeriveOp(Value, Op64, IREmit->_F64SIN(St0));
    }
  } else {
    if (FEXCore::HBX87::ArithmeticEnabled(GPROpSize == OpSize::i32Bit) && Op80 == IR::OP_F80SQRT) {
      Value = FEXCore::HBX87::Emit(*IREmit, Op80, St0, St0, GPROpSize == OpSize::i32Bit);
    } else {
      DeriveOp(Value, Op80, IREmit->_F80SQRT(St0));
    }
  }

  StoreStackValue(Value);
}


void X87StackOptimization::HandleBinopValue(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, bool MarkDestValid,
                                            uint8_t StackOffset, Ref ValueNode, bool Reverse) {
  LOGMAN_THROW_A_FMT(!Reverse || VFOp64, "There are no reverse operations using non VFOp64 ops");
  auto StackNode = LoadStackValue(StackOffset);
  if (S32Binop(Op80, DestStackOffset, MarkDestValid, StackOffset, StackNode, ValueNode, Reverse)) { // X87EXACT S32
    return;
  }

  Ref Node = {};
  if (PCXBlock) {
    const unsigned K = Op80 == OP_F80ADD ? FEXCore::HBX87::PCX::OpAdd :
                       Op80 == OP_F80SUB ? FEXCore::HBX87::PCX::OpSub :
                       Op80 == OP_F80MUL ? FEXCore::HBX87::PCX::OpMul : FEXCore::HBX87::PCX::OpDiv;
    LOGMAN_THROW_A_FMT(Op80 == OP_F80ADD || Op80 == OP_F80SUB || Op80 == OP_F80MUL || Op80 == OP_F80DIV, "PCX binop");
    Node = Reverse ? PCXArith(K, ValueNode, StackNode) : PCXArith(K, StackNode, ValueNode);
  } else if (ReducedPrecisionMode) {
    if (Reverse) {
      DeriveOp(Node, Op64, IREmit->_VFAdd(OpSize::i64Bit, OpSize::i64Bit, ValueNode, StackNode));
      if (FEXCore::HBX87::RP::PC24()) Node = G3RoundPC24(IREmit, Node, G3Rnd, G3Odd, G3Msk, G3Vm);
    } else {
      if (VFOp64) {
        DeriveOp(Node, Op64, IREmit->_VFAdd(OpSize::i64Bit, OpSize::i64Bit, StackNode, ValueNode));
        if (FEXCore::HBX87::RP::PC24()) Node = G3RoundPC24(IREmit, Node, G3Rnd, G3Odd, G3Msk, G3Vm);
      } else {
        DeriveOp(Node, Op64, IREmit->_F64FPREM(StackNode, ValueNode));
      }
    }
  } else {
    if (FEXCore::HBX87::ArithmeticEnabled(GPROpSize == OpSize::i32Bit) && FEXCore::HBX87::Supports(Op80)) {
      Node = FEXCore::HBX87::Emit(*IREmit, Op80,
        Reverse ? ValueNode : StackNode, Reverse ? StackNode : ValueNode, GPROpSize == OpSize::i32Bit);
    } else {
    if (Reverse) {
      DeriveOp(Node, Op80, IREmit->_F80Add(ValueNode, StackNode));
    } else {
      DeriveOp(Node, Op80, IREmit->_F80Add(StackNode, ValueNode));
    }
    }
  }

  StoreStackValue(Node, DestStackOffset, MarkDestValid && StackOffset != DestStackOffset);
}

void X87StackOptimization::HandleBinopStack(IROps Op64, bool VFOp64, IROps Op80, uint8_t DestStackOffset, uint8_t StackOffset1,
                                            uint8_t StackOffset2, bool Reverse) {
  auto StackNode = LoadStackValue(StackOffset2);
  HandleBinopValue(Op64, VFOp64, Op80, DestStackOffset, StackOffset2 != DestStackOffset, StackOffset1, StackNode, Reverse);
}

inline void X87StackOptimization::UpdateTopForPop_Slow(bool InvalidateTag) {
  const auto PopContainer = [](auto& container) {
    const auto begin = std::begin(container);
    std::rotate(begin, std::next(begin), std::end(container));
  };

  if (InvalidateTag) {
    SetX87ValidTag(0, false);
  }

  // Pop the top of the x87 stack
  GetOffsetTopWithCache_Slow(1);
  PopContainer(TopOffsetCache);
  PopContainer(TopOffsetAddressCache);
  PopContainer(TopValueCache);
  PopContainer(FlushValuesPending);
  PopContainer(TopValidCache);
  FlushTopPending = true;
  if (SlowTopDelta != 99) ++SlowTopDelta;
}

inline void X87StackOptimization::UpdateTopForPush_Slow() {
  const auto PushContainer = [](auto& container) {
    const auto end = std::end(container);
    std::rotate(std::begin(container), std::prev(end), end);
  };

  // Push the top of the x87 stack
  GetOffsetTopWithCache_Slow(1, true);
  PushContainer(TopOffsetCache);
  PushContainer(TopOffsetAddressCache);
  PushContainer(TopValueCache);
  PushContainer(FlushValuesPending);
  PushContainer(TopValidCache);
  FlushTopPending = true;
  if (SlowTopDelta != 99) --SlowTopDelta;
}

void X87StackOptimization::FlushCachedRegs() {
  if (FlushTopPending) {
    NoteFlush(IREmit->_StoreContextGPR(OpSize::i8Bit, TopOffsetCache[0], offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC));
    FlushTopPending = false;
    SlowTopDelta = 0;
  }

  auto Size = (ReducedPrecisionMode && !FEXCore::HBX87::RP::Int64()) ? OpSize::i64Bit : OpSize::i128Bit;
  for (size_t i = 0; i < FlushValuesPending.size(); i++) {
    if (FlushValuesPending[i]) {
      OrderedNode* TopOffsetAddress = GetOffsetTopAddressWithCache_Slow(i);
      if (PCXBlock) {
        Ref Raw = IREmit->_X87PCXTo80(TopValueCache[i]);
        NoteFlush(IREmit->_StoreMemFPR(OpSize::i128Bit, Raw, TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), OpSize::i128Bit,
                                       MemOffsetType::SXTX, 1));
      } else {
      NoteFlush(IREmit->_StoreMemFPR(Size, TopValueCache[i], TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1));
      }
      // store
      FlushValuesPending[i] = false;
    }
  }

  if (FlushValidPending) {
    uint8_t ValidMask = 0;
    uint8_t InvalidMask = 0;
    for (auto It = TopValidCache.rbegin(); It != TopValidCache.rend(); It++) {
      ValidMask <<= 1;
      InvalidMask <<= 1;
      if (*It == StackSlot::VALID) {
        ValidMask |= 1;
      } else if (*It == StackSlot::INVALID) {
        InvalidMask |= 1;
      }
    }

    if (ValidMask || InvalidMask) {
      Ref NewFTW = [&]() {
        if (ValidMask == 0xff || InvalidMask == 0xff) {
          // If InvalidMask == 0xff then ValidMask = 0
          return GetConstant(ValidMask);
        } else {
          Ref NewFTW = GetFTW();
          Ref RotAmount {};
          if (std::popcount(ValidMask) == 1) {
            uint8_t BitIdx = std::countr_zero(ValidMask);
            Ref RegMask = IREmit->_Lshl(OpSize::i32Bit, GetConstant(1), GetOffsetTopWithCache_Slow(BitIdx));
            NewFTW = IREmit->_Or(OpSize::i32Bit, NewFTW, RegMask);
          } else if (ValidMask) {
            RotAmount = IREmit->_Sub(OpSize::i32Bit, GetConstant(8), GetTopWithCache_Slow());
            // perform a rotate right on mask by top
            NewFTW = IREmit->_Or(OpSize::i32Bit, NewFTW, RotateRight8(ValidMask, RotAmount));
          }

          if (std::popcount(InvalidMask) == 1) {
            uint8_t BitIdx = std::countr_zero(InvalidMask);
            Ref RegMask = IREmit->_Lshl(OpSize::i32Bit, GetConstant(1), GetOffsetTopWithCache_Slow(BitIdx));
            NewFTW = IREmit->_Andn(OpSize::i32Bit, NewFTW, RegMask);
          } else if (InvalidMask) {
            if (!RotAmount) {
              RotAmount = IREmit->_Sub(OpSize::i32Bit, GetConstant(8), GetTopWithCache_Slow());
            }
            NewFTW = IREmit->_Andn(OpSize::i32Bit, NewFTW, RotateRight8(InvalidMask, RotAmount));
          }
          return NewFTW;
        }
      }();

      NoteFlush(IREmit->_StoreContextGPR(OpSize::i8Bit, NewFTW, offsetof(FEXCore::Core::CPUState, AbridgedFTW)));
      FTWCached = NewFTW;
    }

    FlushValidPending = false;
  }
}

// We synchronize stack values in a few occasions but one of the most important of those,
// is when we move from fast to a slow path and need to make sure that the context is properly
// written.
Ref X87StackOptimization::SynchronizeStackValues() {
  if (SlowPath) {
    return GetTopWithCache_Slow();
  }
  if (ShapeBlock) {
    // Values of moved seeds first, from the frame their offsets name (TOP moves below).
    for (size_t i = 0; i < StackData.size; ++i) {
      if (StackData.isDirty(i) ||
          (G3RegCells && ((G3RegCells >> ((i - static_cast<unsigned>(StackData.TopOffset)) & 7)) & 1))) {
        MaterializeSeed(i);
      }
    }
  }

  // Store new top which is now the original top minus recorded top offset
  // Careful with underflow wraparound.
  const auto TopOffset = StackData.TopOffset;

  if (TopOffset != 0) {
    Ref NewTop = GetOffsetTopWithCache_Slow(TopOffset, true);
    if (LagKeepPending) { // SHAPE_LAG: the TOP cache moves (values below are stored by the new TOP), CPUState TOP keeps its lag
      InvalidateCachedRegs();
      TopOffsetCache[0] = NewTop;
    } else {
      const bool DeltaKnown = !FlushTopPending && SlowTopDelta == 0; // RP6h: nothing pending before -> the shift is the model's
      SetTopWithCache_Slow(NewTop);
      if (DeltaKnown && MRX87FaultCover()) {
        SlowTopDelta = -TopOffset; // slow delta = TOP change (push -1); the model's TopOffset counts pushes (+1)
      }
    }
  }
  StackData.TopOffset = 0;

  // Before leaving we need to write the current values in the stack to
  // context so that the values are correct. Copy SourceDataNode in the
  // stack to the respective mmX register.
  Ref TopValue = GetTopWithCache_Slow();
  for (size_t i = 0; i < StackData.size; ++i) {
    const auto& [Valid, StackMember] = StackData.top(i);

    // SHAPE: a slot that did not change is in mm[] already.
    if (Valid == StackSlot::VALID && G3RegCells && ((G3RegCells >> ((i - static_cast<unsigned>(TopOffset)) & 7)) & 1) &&
        StackMember.StackDataNode) {
      G3StoreCell(StackMember.StackDataNode, (i - static_cast<unsigned>(TopOffset)) & 7); // level 6: leaves in its register
    } else if (Valid == StackSlot::VALID && (!ShapeBlock || StackData.isDirty(i))) {
      StoreStackValueAtOffset_Slow(StackMember.StackDataNode, i, false);
    }
  }
  if (ShapeBlock) {
    // Every slot is typed. Tags: only those whose validity differs from what CPUState holds (ShapeRef, moved with TOP); a pending
    // entry from an earlier synchronization at the same TOP stays (it is part of what CPUState will hold).
    const uint8_t Cur = StackData.getValidMask();
    const unsigned K = static_cast<unsigned>(TopOffset) & 7;
    const uint8_t Ref8 = static_cast<uint8_t>(((ShapeRef << K) | (ShapeRef >> ((8 - K) & 7))) & 0xFF);
    const uint8_t Changed = Cur ^ Ref8;
    for (size_t i = 0; i < StackData.size; ++i) {
      if ((Changed >> i) & 1) {
        TopValidCache[i] = ((Cur >> i) & 1) ? StackSlot::VALID : StackSlot::INVALID;
      }
      const auto& Entry = StackData.top(i);
      if (Entry.Type == StackSlot::VALID && !Entry.Value.StackDataNode && Entry.Value.SeedOffset >= 0) {
        StackMemberInfo Seed {};
        Seed.SeedOffset = static_cast<int8_t>(i); // the TOP cache now holds the new TOP
        StackData.setValue(i, Seed);
      }
    }
    ShapeRef = Cur;
    if (Changed && !LagKeepPending) { // SHAPE_LAG: the tag word keeps its lag
      FlushValidPending = true;
    }
  } else { // Set valid tags
    uint8_t ValidMask = StackData.getValidMask();
    uint8_t InvalidMask = StackData.getInvalidMask();
    for (auto& Elem : TopValidCache) {
      Elem = (ValidMask & 1) ? StackSlot::VALID : ((InvalidMask & 1) ? StackSlot::INVALID : StackSlot::UNUSED);

      ValidMask >>= 1;
      InvalidMask >>= 1;
    }
    FlushValidPending = true;
  }
  StackData.markClean();

  return TopValue;
}

// TRANS32 MACRUNNER_FEX32_X87_PC_EXACT (HBX87PCX.h): per-block admission. Only forms with an exact container lowering;
// anything else keeps the whole block on the exact 80-bit path (CPUState stays 80-bit, so blocks mix freely).
bool X87StackOptimization::PCXEligible(const IRListView& IR, Ref BlockNode) {
  namespace St = FEXCore::HBX87::PCX::Stats;
  fextl::vector<uint32_t> Reads;
  unsigned Sites = 0;
  // A store that changes the state the unit was admitted for (FCW, MXCSR, FSW.PE) or writes the x87 registers in CPUState.
  constexpr uint32_t FcwOff = offsetof(FEXCore::Core::CPUState, FCW);
  constexpr uint32_t MxOff = offsetof(FEXCore::Core::CPUState, mxcsr);
  constexpr uint32_t PeOff = offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_PE_LOC;
  constexpr uint32_t MmOff = offsetof(FEXCore::Core::CPUState, mm);
  const auto StateStore = [&](uint32_t Off, uint32_t Bytes) {
    const auto Hits = [&](uint32_t A, uint32_t L) { return Off < A + L && A < Off + Bytes; };
    return Hits(FcwOff, 2) || Hits(MxOff, 4) || Hits(PeOff, 1) || Hits(MmOff, sizeof(FEXCore::Core::CPUState::mm));
  };
  constexpr uint32_t FtwOff = offsetof(FEXCore::Core::CPUState, AbridgedFTW);
  PCXReadsState = false;
  for (auto [Node, Op] : IR.GetCode(BlockNode)) {
    {
      const auto Reads = [&](uint32_t Off, uint32_t Bytes) {
        return (Off < MmOff + sizeof(FEXCore::Core::CPUState::mm) && MmOff < Off + Bytes) || (Off <= FtwOff && FtwOff < Off + Bytes);
      };
      if ((Op->Op == OP_LOADCONTEXT && Reads(Op->C<IROp_LoadContext>()->Offset, IR::OpSizeToSize(Op->Size))) ||
          (Op->Op == OP_LOADCONTEXTPAIR && Reads(Op->C<IROp_LoadContextPair>()->Offset, 2 * IR::OpSizeToSize(Op->Size))) ||
          Op->Op == OP_LOADCONTEXTINDEXED) {
        PCXReadsState = true;
      }
    }
    if (Op->Op == OP_STORECONTEXT && StateStore(Op->C<IROp_StoreContext>()->Offset, IR::OpSizeToSize(Op->Size))) {
      St::Bump(St::BlockState);
      return false;
    }
    if (Op->Op == OP_STORECONTEXTPAIR && StateStore(Op->C<IROp_StoreContextPair>()->Offset, 2 * IR::OpSizeToSize(Op->Size))) {
      St::Bump(St::BlockState);
      return false;
    }
    switch (Op->Op) {
    case OP_PUSHSTACK:
    case OP_COPYPUSHSTACK:
    case OP_POPSTACKDESTROY:
    case OP_STACKVALIDTAG:
    case OP_STORESTACKTOSTACK:
    case OP_F80STACKXCHANGE:
    case OP_F80STACKCHANGESIGN:
    case OP_F80STACKABS:
    case OP_F80ADDSTACK:
    case OP_F80SUBSTACK:
    case OP_F80MULSTACK:
    case OP_F80DIVSTACK:
    case OP_F80ADDVALUE:
    case OP_F80SUBVALUE:
    case OP_F80SUBRVALUE:
    case OP_F80MULVALUE:
    case OP_F80DIVVALUE:
    case OP_F80DIVRVALUE:
    case OP_F80SQRTSTACK:
    case OP_F80CMPSTACK:
    case OP_F80CMPVALUE:
    case OP_F80STACKTEST:
    case OP_INCSTACKTOP:
    case OP_DECSTACKTOP:
    case OP_INVALIDATESTACK:
    case OP_SYNCSTACKTOSLOW:
    case OP_STORESTACKMEM: ++Sites; break;
    case OP_READSTACKVALUE: Reads.push_back(IR.GetID(Node).Value); break;
    case OP_F80CVTTO: {
      const auto S = Op->C<IROp_F80CVTTo>()->SrcSize;
      if (S != OpSize::i32Bit && S != OpSize::i64Bit) { St::Bump(St::BlockOp); return false; }
      ++Sites;
      break;
    }
    case OP_F80CVTTOINT: {
      const auto S = Op->C<IROp_F80CVTToInt>()->SrcSize;
      if (S != OpSize::i16Bit && S != OpSize::i32Bit) { St::Bump(St::BlockOp); return false; }
      break;
    }
    case OP_F80CMPQUIET:
    case OP_F80CMP: break;
    case OP_F80CVT:
    case OP_F80CVTINT:
    case OP_F80ROUND:
    case OP_F80XTRACT_EXP:
    case OP_F80XTRACT_SIG:
    case OP_F80BCDLOAD:
    case OP_F80BCDSTORE:
    case OP_F80SIN:
    case OP_F80COS:
    case OP_F80SINCOS:
    case OP_F80TAN:
    case OP_F80ATAN:
    case OP_F80FPREM:
    case OP_F80FPREM1:
    case OP_F80SCALE:
    case OP_F80F2XM1:
    case OP_F80FYL2X:
    case OP_F80FYL2XP1:
    case OP_F80ADD:
    case OP_F80SUB:
    case OP_F80MUL:
    case OP_F80DIV:
    case OP_F80SQRT:
    case OP_HBX87FAST:
    case OP_HBX87FASTCW:
    case OP_STACKFORCESLOW: St::Bump(St::BlockOp); return false;
    default:
      if (LoweredX87(Op->Op)) { St::Bump(St::BlockOp); return false; }
      break;
    }
    if (!Reads.empty() && Op->Op != OP_F80CMPQUIET && Op->Op != OP_F80CMP) {
      const uint8_t NumArgs = IR::GetArgs(Op->Op);
      for (uint8_t i = 0; i < NumArgs; ++i) {
        if (Op->Args[i].IsInvalid() || Op->Args[i].IsImmediate()) continue;
        if (std::find(Reads.begin(), Reads.end(), Op->Args[i].ID().Value) != Reads.end()) { St::Bump(St::BlockRead); return false; }
      }
    }
  }
  if (!Sites) { St::Bump(St::BlockNoX87); return false; }
  // Block size cap from the box slots only (HBX87PCX.h BoxSlots): a site creates at most 3 boxes per execution (From80 of its stack
  // operands, the load of a memory operand, the result), and every box of the block must keep its slot until the block ends, so
  // 3 * Sites < BoxSlots - 1 (1300 admits every block of the Gothic world corpus). The old cap of 48 dated from the inline forms (code growth) and kept the hottest x87 blocks exact
  // (fmodex mixing, PhysX dot products). MACRUNNER_FEX32_X87_PC_EXACT_SITES=<n> (stands only) sets another one, 0 = none.
  static const unsigned MaxSites = [] {
    const char* p = getenv("MACRUNNER_FEX32_X87_PC_EXACT_SITES");
    return p ? static_cast<unsigned>(strtoul(p, nullptr, 10)) : 1300u;
  }();
  static_assert(3 * 1300 < FEXCore::HBX87::PCX::BoxSlots - 1, "box slots");
  if (MaxSites && Sites + Reads.size() > MaxSites) { St::Bump(St::BlockSites); return false; }
  return true;
}

bool X87StackOptimization::IsPCXContainer(const IRListView& IR, Ref Node) const {
  switch (IR.GetOp<IROp_Header>(Node)->Op) {
  case OP_X87PCXLOAD:
  case OP_X87PCXWIDENS: // X87EXACT S32
  case OP_X87PCXFROM80:
  case OP_X87PCXARITH:
  case OP_FLOAT_FROMGPR_S: return true;
  default: return false;
  }
}

// A later x87 write of C1 makes the pending writer's C1 dead unless a context load observed it in between.
void X87StackOptimization::PCXNoteC1Writer(Ref Node) {
  namespace PCX = FEXCore::HBX87::PCX;
  if (!PCXC1) return;
  if (PendingC1) {
    auto IR = IREmit->ViewIR();
    auto* H = IR.GetOp<IROp_Header>(PendingC1);
    if (H->Op == OP_X87PCXARITH) {
      H->CW<IROp_X87PCXArith>()->Kind &= static_cast<uint8_t>(~PCX::KC1);
    } else if (H->Op == OP_X87PCXLOAD) {
      H->CW<IROp_X87PCXLoad>()->Flags &= static_cast<uint8_t>(~PCX::FC1);
    } else if (H->Op == OP_X87PCXSTORE) {
      H->CW<IROp_X87PCXStore>()->Flags &= static_cast<uint8_t>(~PCX::FC1);
    } else if (H->Op == OP_X87PCXARITHS) { // X87EXACT S32
      H->CW<IROp_X87PCXArithS>()->Kind &= static_cast<uint8_t>(~PCX::KC1);
    } else if (H->Op == OP_X87PCXSTORES) {
      H->CW<IROp_X87PCXStoreS>()->Flags &= static_cast<uint8_t>(~PCX::FC1);
    }
  }
  PendingC1 = Node;
}

Ref X87StackOptimization::PCXArith(unsigned Kind, Ref A, Ref B) {
  namespace PCX = FEXCore::HBX87::PCX;
  unsigned K = Kind;
  if (PCXC1) K |= PCX::KC1;
  if (PCXPE) K |= PCX::KPE;
  if (PCXMode == PCX::PC24) {
    // Operands provably <= 24 significand bits need no runtime check: float loads and PC24 results.
    auto IR = IREmit->ViewIR();
    auto Narrow = [&](Ref V) {
      const auto* H = IR.GetOp<IROp_Header>(V);
      return (H->Op == OP_X87PCXLOAD && H->C<IROp_X87PCXLoad>()->SrcSize == OpSize::i32Bit) ||
             (H->Op == OP_X87PCXARITH && (H->C<IROp_X87PCXArith>()->Kind & PCX::K24)) ||
             H->Op == OP_X87PCXWIDENS; // X87EXACT S32: a widened single (a box fails the stub's result check, as any box)
    };
    K |= PCX::K24;
    if (!Narrow(A)) K |= PCX::CheckA;
    if (Kind != PCX::OpSqrt && !Narrow(B)) K |= PCX::CheckB;
  }
  auto Node = IREmit->_X87PCXArith(A, B, static_cast<uint8_t>(K));
  PCXNoteC1Writer(Node);
  return Node;
}

void X87StackOptimization::Run(IREmitter* Emit) {
  FEXCORE_PROFILE_SCOPED("PassManager::x87StackOpt");

  auto CurrentIR = Emit->ViewIR();
  auto* HeaderOp = CurrentIR.GetHeader();
  LOGMAN_THROW_A_FMT(HeaderOp->Header.Op == OP_IRHEADER, "First op wasn't IRHeader");

  if (!HeaderOp->HasX87) {
    // If there is no x87 in this, just early exit.
    return;
  }

  // Initialize IREmit member
  IREmit = Emit;
  PCXMode = HeaderOp->X87PCX & FEXCore::HBX87::PCX::PCMask;
  // PE is architectural only where the exact path publishes it (HandleX87Exception, F80Fallbacks.h).
  PCXPE = (HeaderOp->X87PCX & FEXCore::HBX87::PCX::PETrack) && FEXCore::HBX87::StateFix::ExceptionFlags() &&
          !FEXCore::HBX87::StateFix::StaticRegs32();
  PCXC1 = PCXMode && FEXCore::HBX87::StateFix::C1Roundup();

  // SHAPE (HBX87PCX.h ShapeEnabled, not with XBLOCK): the stack shape (valid ST(i), bit i) at each block's start, from the guarded
  // unit entry over internal edges. -2 = not reached, -1 = unknown (another entry point, a call-return landing, a merge of
  // different shapes, an x87 block that is not PCX or reads the x87 state from CPUState). A PCX block that does not read that state
  // and whose start shape is known is seeded. The effects follow the pass's own tag semantics (fast and slow path agree on them):
  // a binop whose destination is one of its operands leaves the tag, FXCH leaves both, FST ST(0) is a no-op.
  struct SInfo {
    bool PCX = false, Reads = false, N = false;
    bool X = false, Rd = false, St = false;
    bool EP = false;      // v7: entry point
    int16_t Root = -2;    // v7: the unit entry test's shape (validated run start) // v5: has an x87 stack op; reads mm[] / the tag word from CPUState; stores TOP / tag / mm[]
    int16_t Start = -2, End = -2;
    bool FloatRet = false;         // SHAPE level 2: a call-return landing that reads ST(0) first (the callee returned a value)
    uint32_t CallLanding = ~0U;    // SHAPE level 2: this block's call-return landing (a pseudo edge in Succ)
    uint8_t NSucc = 0;
    uint32_t Succ[2] {};
    Ref Guard {};
    Ref Block {};
  };
  fextl::unordered_map<uint32_t, SInfo> SB;
  fextl::vector<uint32_t> SOrder;
  // G3FABLE UNIT_SHAPE (level >= 2): a reduced-precision 32-bit unit uses the same dataflow from its mode-0x84 guard; its blocks
  // are never PCX containers (CPUState and the stack hold the same doubles).
  const bool G3Shape = !PCXMode && BaseReducedPrecision && GPROpSize == OpSize::i32Bit && FEXCore::HBX87::UnitShape::Level() >= 2;
  const bool ShapeMode = (PCXMode && FEXCore::HBX87::PCX::ShapeEnabled()) || G3Shape;
  if (ShapeMode) {
    fextl::vector<std::pair<uint32_t, uint32_t>> Landings; // (landing block, calling block)
    fextl::unordered_map<uint32_t, Ref> EntryGuard;          // SHAPE level 2: entry points (not the unit entry) with an entry check
    fextl::unordered_map<uint32_t, uint64_t> EntryRIP;
    const bool ShapeL2 = G3Shape ? FEXCore::HBX87::UnitShape::Level() >= 4 : FEXCore::HBX87::PCX::ShapeLevel() >= 2;
    for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
      auto* BlockOp = BlockHeader->C<FEXCore::IR::IROp_CodeBlock>();
      SInfo I {};
      I.Block = BlockNode;
      I.PCX = !G3Shape && PCXEligible(CurrentIR, BlockNode);
      I.Reads = !G3Shape && PCXReadsState;
      I.Start = BlockOp->EntryPoint ? -1 : -2;
      I.EP = BlockOp->EntryPoint;
      const uint32_t ThisId = CurrentIR.GetID(BlockNode).Value;
      {
        constexpr uint32_t VTop = offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC;
        constexpr uint32_t VFtw = offsetof(FEXCore::Core::CPUState, AbridgedFTW);
        constexpr uint32_t VMm = offsetof(FEXCore::Core::CPUState, mm);
        const auto InMmFtw = [&](uint32_t Off, uint32_t Bytes) {
          return (Off <= VFtw && VFtw < Off + Bytes) || (Off < VMm + sizeof(FEXCore::Core::CPUState::mm) && VMm < Off + Bytes);
        };
        const auto InState = [&](uint32_t Off, uint32_t Bytes) { return InMmFtw(Off, Bytes) || (Off <= VTop && VTop < Off + Bytes); };
        for (auto [Node, Op] : CurrentIR.GetCode(BlockNode)) {
          I.X = I.X || LoweredX87(Op->Op);
          if ((Op->Op == OP_LOADCONTEXT && InMmFtw(Op->C<IROp_LoadContext>()->Offset, IR::OpSizeToSize(Op->Size))) ||
              (Op->Op == OP_LOADCONTEXTPAIR && InMmFtw(Op->C<IROp_LoadContextPair>()->Offset, 2 * IR::OpSizeToSize(Op->Size))) ||
              Op->Op == OP_LOADCONTEXTINDEXED) {
            I.Rd = true;
          }
          if ((Op->Op == OP_STORECONTEXT && InState(Op->C<IROp_StoreContext>()->Offset, IR::OpSizeToSize(Op->Size))) ||
              (Op->Op == OP_STORECONTEXTPAIR && InState(Op->C<IROp_StoreContextPair>()->Offset, 2 * IR::OpSizeToSize(Op->Size))) ||
              Op->Op == OP_STORECONTEXTINDEXED) {
            I.St = true;
          }
        }
        I.N = !I.PCX && !I.X && !I.Rd && !I.St; // c33k chain: no PCXNoX87
      }
      for (auto [Node, Op] : CurrentIR.GetCode(BlockNode)) {
        if (Op->Op == OP_X87PCXGUARD && (Op->C<IROp_X87PCXGuard>()->Shape & 0x100) && !(Op->C<IROp_X87PCXGuard>()->Mode & 0x60)) {
          I.Guard = Node;
          I.Start = Op->C<IROp_X87PCXGuard>()->Shape & 0xFF;
        } else if (Op->Op == OP_X87PCXGUARD && !(Op->C<IROp_X87PCXGuard>()->Mode & 0x60) && ShapeL2 && BlockOp->EntryPoint &&
                   !EntryGuard.contains(ThisId)) {
          EntryGuard[ThisId] = Node;
          EntryRIP[ThisId] = HeaderOp->OriginalRIP + BlockOp->GuestEntryOffset;
        } else if (Op->Op == OP_EXITFUNCTION && !Op->C<IROp_ExitFunction>()->CallReturnBlock.IsInvalid()) {
          Landings.push_back({CurrentIR.GetID(CurrentIR.GetNode(Op->C<IROp_ExitFunction>()->CallReturnBlock)).Value, ThisId});
        }
      }
      auto Last = CurrentIR.at(BlockOp->Last);
      --Last;
      auto [LastNode, LastOp] = Last();
      if (LastOp->Op == OP_JUMP) {
        I.Succ[I.NSucc++] = CurrentIR.GetID(CurrentIR.GetNode(LastOp->C<IROp_Jump>()->TargetBlock)).Value;
      } else if (LastOp->Op == OP_CONDJUMP) {
        I.Succ[I.NSucc++] = CurrentIR.GetID(CurrentIR.GetNode(LastOp->C<IROp_CondJump>()->TrueBlock)).Value;
        I.Succ[I.NSucc++] = CurrentIR.GetID(CurrentIR.GetNode(LastOp->C<IROp_CondJump>()->FalseBlock)).Value;
      }
      const uint32_t Id = CurrentIR.GetID(BlockNode).Value;
      SB[Id] = I;
      SOrder.push_back(Id);
    }
    for (const auto& [Id, Caller] : Landings) {
      if (auto It = SB.find(Id); It != SB.end() && !It->second.Guard) {
        It->second.Start = -1;
      }
    }
    // Entry offsets a block reads before it writes them (its demand on the start shape).
    const auto Demand = [&](Ref Block) -> uint8_t {
      int Top = 0;
      unsigned Need = 0, Written = 0;
      const auto Rd = [&](unsigned i) {
        const int E = static_cast<int>(i) - Top;
        if (E >= 0 && E < 8 && !((Written >> E) & 1)) Need |= 1U << E;
      };
      const auto Wr = [&](unsigned i) {
        const int E = static_cast<int>(i) - Top;
        if (E >= 0 && E < 8) Written |= 1U << E;
      };
      for (auto [Node, Op] : CurrentIR.GetCode(Block)) {
        switch (Op->Op) {
        case OP_PUSHSTACK: ++Top; break;
        case OP_COPYPUSHSTACK: Rd(Op->C<IROp_CopyPushStack>()->StackLocation); ++Top; break;
        case OP_POPSTACKDESTROY:
        case OP_INCSTACKTOP: --Top; break;
        case OP_DECSTACKTOP: ++Top; break;
        case OP_STORESTACKTOSTACK: Rd(0); Wr(Op->C<IROp_StoreStackToStack>()->StackLocation); break;
        case OP_F80STACKXCHANGE: Rd(0); Rd(Op->C<IROp_F80StackXchange>()->SrcStack); break;
        case OP_F80ADDSTACK: Rd(Op->C<IROp_F80AddStack>()->SrcStack1); Rd(Op->C<IROp_F80AddStack>()->SrcStack2); break;
        case OP_F80MULSTACK: Rd(Op->C<IROp_F80MulStack>()->SrcStack1); Rd(Op->C<IROp_F80MulStack>()->SrcStack2); break;
        case OP_F80SUBSTACK: Rd(Op->C<IROp_F80SubStack>()->SrcStack1); Rd(Op->C<IROp_F80SubStack>()->SrcStack2); break;
        case OP_F80DIVSTACK: Rd(Op->C<IROp_F80DivStack>()->SrcStack1); Rd(Op->C<IROp_F80DivStack>()->SrcStack2); break;
        case OP_F80ADDVALUE: Rd(Op->C<IROp_F80AddValue>()->SrcStack); break;
        case OP_F80SUBVALUE: Rd(Op->C<IROp_F80SubValue>()->SrcStack); break;
        case OP_F80SUBRVALUE: Rd(Op->C<IROp_F80SubRValue>()->SrcStack); break;
        case OP_F80MULVALUE: Rd(Op->C<IROp_F80MulValue>()->SrcStack); break;
        case OP_F80DIVVALUE: Rd(Op->C<IROp_F80DivValue>()->SrcStack); break;
        case OP_F80DIVRVALUE: Rd(Op->C<IROp_F80DivRValue>()->SrcStack); break;
        case OP_F80CMPSTACK: Rd(0); Rd(Op->C<IROp_F80CmpStack>()->SrcStack); break;
        case OP_F80STACKTEST: Rd(Op->C<IROp_F80StackTest>()->SrcStack); break;
        case OP_READSTACKVALUE: Rd(Op->C<IROp_ReadStackValue>()->StackLocation); break;
        case OP_F80SQRTSTACK:
        case OP_F80STACKCHANGESIGN:
        case OP_F80STACKABS:
        case OP_F80CMPVALUE:
        case OP_STORESTACKMEM: Rd(0); break;
        case OP_INVALIDATESTACK: {
          const unsigned L = Op->C<IROp_InvalidateStack>()->StackLocation;
          if (L == 0xff) Written = 0xFF; else Wr(L);
          break;
        }
        default: break;
        }
      }
      return static_cast<uint8_t>(Need);
    };
    // Compile-only stands (MACRUNNER_FEX32_X87_PC_EXACT_ASSUME) know no entry state: the unit entry assumes its first block's demand.
    static const bool MRAssume = getenv("MACRUNNER_FEX32_X87_PC_EXACT_ASSUME") != nullptr;
    if (MRAssume) {
      for (auto& [Id, I] : SB) {
        if (I.Guard && I.Start >= 0) I.Start = Demand(I.Block);
      }
    }
    fextl::vector<uint32_t> PseudoCallers; // v7: callers given a pseudo edge for the hint run
    for (auto& [Id, I] : SB) {
      if (I.Guard) I.Root = I.Start;
    }
    if (ShapeL2) {
      // Entry points with an entry check: the learned shape, else (a call-return landing) the shape the calling block leaves, one
      // value more when the landing reads ST(0) first (the callee returned a value: cdecl leaves the rest of the stack as it was).
      fextl::unordered_map<uint32_t, uint32_t> CallerOf;
      for (const auto& [Id, Caller] : Landings) {
        CallerOf[Id] = Caller;
      }
      // v7 hint run: every landing takes its calling block's end (pseudo edge), a guarded entry point also its internal predecessors'
      // shapes, a learned entry what was learned. Only the validated run below seeds anything.
      for (auto& [Id, I] : SB) {
        if (I.Guard) {
          continue; // the unit entry's own test
        }
        const bool Guarded = EntryGuard.contains(Id);
        unsigned Count = 0;
        uint8_t Learned = 0;
        if (Guarded && FEXCore::HBX87::PCX::ShapeLearnedOf(EntryRIP[Id], Count, Learned)) {
          I.Start = Count >= FEXCore::HBX87::PCX::ShapeLimit ? -1 : Learned;
          continue;
        }
        if (auto C = CallerOf.find(Id); C != CallerOf.end()) {
          auto& Caller = SB[C->second];
          if (Caller.NSucc < 2) {
            I.Start = -2;
            I.FloatRet = Demand(I.Block) & 1;
            Caller.CallLanding = Id;
            Caller.Succ[Caller.NSucc++] = Id;
            PseudoCallers.push_back(C->second);
          }
          continue;
        }
        if (Guarded) {
          I.Start = -2;
        }
      }
    }
    const auto Effect = [&](const SInfo& I, int16_t Start) -> int16_t {
      if (Start < 0 || I.N) {
        return Start;
      }
      // v4: exact-path blocks too; only a block that writes TOP / the tag word / mm[] in CPUState itself is unknown.
      unsigned R = static_cast<unsigned>(Start);
      constexpr uint32_t ShTop = offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC;
      constexpr uint32_t ShFtw = offsetof(FEXCore::Core::CPUState, AbridgedFTW);
      constexpr uint32_t ShMm = offsetof(FEXCore::Core::CPUState, mm);
      const auto ShTouch = [&](uint32_t Off, uint32_t Bytes) {
        return (Off <= ShTop && ShTop < Off + Bytes) || (Off <= ShFtw && ShFtw < Off + Bytes) ||
               (Off < ShMm + sizeof(FEXCore::Core::CPUState::mm) && ShMm < Off + Bytes);
      };
      const auto Valid = [&](unsigned i) { R |= 1U << (i & 7); };
      for (auto [Node, Op] : CurrentIR.GetCode(I.Block)) {
        switch (Op->Op) {
        case OP_PUSHSTACK:
        case OP_COPYPUSHSTACK: R = ((R << 1) | 1) & 0xFF; break;
        case OP_POPSTACKDESTROY: R >>= 1; break;
        case OP_INCSTACKTOP: R = (R >> 1) | ((R & 1) << 7); break;
        case OP_DECSTACKTOP: R = ((R << 1) | (R >> 7)) & 0xFF; break;
        case OP_STORESTACKTOSTACK: {
          const unsigned L = Op->C<IROp_StoreStackToStack>()->StackLocation;
          if (L != 0) Valid(L);
          break;
        }
        case OP_INVALIDATESTACK: {
          const unsigned L = Op->C<IROp_InvalidateStack>()->StackLocation;
          R = L == 0xff ? 0 : (R & ~(1U << (L & 7)));
          break;
        }
        case OP_F80SUBSTACK: {
          const auto* S = Op->C<IROp_F80SubStack>();
          if (S->DstStack != S->SrcStack1 && S->DstStack != S->SrcStack2) Valid(S->DstStack);
          break;
        }
        case OP_F80DIVSTACK: {
          const auto* S = Op->C<IROp_F80DivStack>();
          if (S->DstStack != S->SrcStack1 && S->DstStack != S->SrcStack2) Valid(S->DstStack);
          break;
        }
        case OP_F80ADDVALUE: if (Op->C<IROp_F80AddValue>()->SrcStack != 0) Valid(0); break;
        case OP_F80SUBVALUE: if (Op->C<IROp_F80SubValue>()->SrcStack != 0) Valid(0); break;
        case OP_F80SUBRVALUE: if (Op->C<IROp_F80SubRValue>()->SrcStack != 0) Valid(0); break;
        case OP_F80MULVALUE: if (Op->C<IROp_F80MulValue>()->SrcStack != 0) Valid(0); break;
        case OP_F80DIVVALUE: if (Op->C<IROp_F80DivValue>()->SrcStack != 0) Valid(0); break;
        case OP_F80DIVRVALUE: if (Op->C<IROp_F80DivRValue>()->SrcStack != 0) Valid(0); break;
        case OP_F80ADDSTACK:
        case OP_F80MULSTACK:
        case OP_F80STACKXCHANGE:
        case OP_F80SQRTSTACK:
        case OP_F80STACKCHANGESIGN:
        case OP_F80STACKABS:
        case OP_STACKVALIDTAG:
        case OP_READSTACKVALUE:
        case OP_F80CMPSTACK:
        case OP_F80CMPVALUE:
        case OP_F80STACKTEST:
        case OP_SYNCSTACKTOSLOW:
        case OP_STORESTACKMEM:
        case OP_F80CVTTO:
        case OP_F80CVTTOINT:
        case OP_F80CMP:
        case OP_F80CMPQUIET:
        case OP_F80FPREMSTACK:
        case OP_F80FPREM1STACK:
        case OP_F80SCALESTACK:
        case OP_F80SINSTACK:
        case OP_F80COSSTACK:
        case OP_F80F2XM1STACK:
        case OP_F80ROUNDSTACK:
        case OP_STACKFORCESLOW: break;
        case OP_F80FYL2XSTACK:
        case OP_F80FYL2XP1STACK:
        case OP_F80ATANSTACK: R >>= 1; break;
        case OP_F80PTANSTACK:
        case OP_F80SINCOSSTACK: R = ((R << 1) | 1) & 0xFF; break;
        case OP_INITSTACK: R = 0; break;
        case OP_F80VBSLSTACK: {
          const auto* S = Op->C<IROp_F80VBSLStack>();
          if (S->SrcStack1 && S->SrcStack2) Valid(0);
          break;
        }
        case OP_STORECONTEXT:
          if (ShTouch(Op->C<IROp_StoreContext>()->Offset, IR::OpSizeToSize(Op->Size))) return -1;
          break;
        case OP_STORECONTEXTPAIR:
          if (ShTouch(Op->C<IROp_StoreContextPair>()->Offset, 2 * IR::OpSizeToSize(Op->Size))) return -1;
          break;
        case OP_STORECONTEXTINDEXED: return -1;
        default:
          if (LoweredX87(Op->Op)) {
            return -1; // not modelled
          }
          break;
        }
      }
      return static_cast<int16_t>(R);
    };
    const auto Meet = [](int16_t A, int16_t B) -> int16_t {
      if (A == -2) return B;
      if (B == -2) return A;
      return A == B ? A : -1;
    };
    const auto RunFix = [&]() {
    for (bool Changed = true; Changed;) {
      Changed = false;
      for (const auto Id : SOrder) {
        auto& I = SB[Id];
        if (I.Start == -2) {
          continue;
        }
        const int16_t End = Effect(I, I.Start);
        if (End != I.End) {
          I.End = End;
          Changed = true;
        }
        for (uint8_t k = 0; k < I.NSucc; ++k) {
          auto It = SB.find(I.Succ[k]);
          if (It == SB.end()) {
            continue;
          }
          const bool Ret = I.CallLanding == I.Succ[k] && It->second.FloatRet && End >= 0;
          const int16_t S = Meet(It->second.Start, Ret ? static_cast<int16_t>(((End << 1) | 1) & 0xFF) : End);
          if (S != It->second.Start) {
            It->second.Start = S;
            Changed = true;
          }
        }
      }
    }
    };
    RunFix();
    if (ShapeL2) {
      // v7 validated run: from the unit entry's test and from guarded entry points with a hint (their check tests it); unguarded
      // entry points unknown; no pseudo edges.
      fextl::unordered_map<uint32_t, int16_t> Hint;
      for (auto& [Id, I] : SB) {
        Hint[Id] = I.Start;
      }
      for (const auto C : PseudoCallers) {
        SB[C].NSucc--;
        SB[C].CallLanding = ~0U;
      }
      for (auto& [Id, I] : SB) {
        I.End = -2;
        if (I.Guard && !EntryGuard.contains(Id)) {
          I.Start = I.Root;
        } else if (auto G = EntryGuard.find(Id); G != EntryGuard.end() && Hint[Id] >= 0) {
          I.Guard = G->second;
          I.Start = Hint[Id];
        } else {
          I.Guard = {};
          I.Start = I.EP ? -1 : -2;
        }
      }
      RunFix();
    }
    if (G3Shape && FEXCore::HBX87::UnitShape::Level() == 2) {
      // G3FABLE level 2: only the guarded entry block keeps its (back-edge-agreed) shape.
      for (auto& [Id, I] : SB) {
        if (!I.Guard && I.Start >= 0) I.Start = -1;
      }
    }
    // The guarded entry block's shape is re-checked on every execution, also from its own back-edges: without agreement there, no
    // check (and nothing below it is known).
    // v4: a test only where a block that uses the shape (PCX, not reading the x87 state) is reachable from it through known shapes.
    const auto Useful = [&](uint32_t From) {
      fextl::vector<uint32_t> Work {From};
      fextl::unordered_set<uint32_t> Seen {From};
      while (!Work.empty()) {
        const uint32_t Id = Work.back();
        Work.pop_back();
        const auto& B = SB[Id];
        if (B.Start < 0) continue;
        if (B.X && !B.Rd && !B.St && !(B.PCX && B.Reads)) return true;
        if (B.End < 0) continue;
        for (uint8_t k = 0; k < B.NSucc; ++k) {
          if (Seen.insert(B.Succ[k]).second) Work.push_back(B.Succ[k]);
        }
      }
      return false;
    };
    for (auto& [Id, I] : SB) {
      if (I.Guard) {
        const bool Test = I.Start >= 0 && Useful(Id);
        auto* G3G = CurrentIR.GetOp<IROp_Header>(I.Guard)->CW<IROp_X87PCXGuard>();
        G3G->Shape = static_cast<uint16_t>((G3G->Shape & 0xF000) | (Test ? (0x100 | I.Start) : 0)); // version nibble kept
      }
    }
  }
  // TRANS32 GUARD_SKIP: a block's call-info marker (X87PCXGuard mode 0x40, Core.cpp) takes its end shape -- the stack shape at its call.
  if (ShapeMode) {
    for (auto& [Id, I] : SB) {
      if (I.End < 0) continue;
      for (auto [Node, Op] : CurrentIR.GetCode(I.Block)) {
        if (Op->Op == OP_X87PCXGUARD && (Op->C<IROp_X87PCXGuard>()->Mode & 0x60)) { // 0x40 call marker, 0x20 known-mode marker
          auto* G3G = CurrentIR.GetOp<IROp_Header>(Node)->CW<IROp_X87PCXGuard>();
          G3G->Shape = static_cast<uint16_t>((G3G->Shape & 0xF000) | 0x100 | I.End); // version nibble kept
        }
      }
    }
  }
  // SHAPE_LAG (stage B): which blocks accept a lag, which carry one, and the lag (TOP offset mod 8, memory tags by the memory TOP).
  struct LagInfo {
    bool Cap = false, Acc = false, Carry = false;
    int8_t Net = 0;
    uint8_t D = 0, M = 0;   // start lag (acceptors)
    uint8_t Dp = 0, Mp = 0; // lag left at the end (predicted)
    uint8_t W = 0;          // level 6: start-frame offsets (mod 8) the block may write
    uint8_t R = 0, Rp = 0;  // level 6: cells in registers at the start (acceptors) / left in registers at the end
  };
  const bool G3RegOn = G3Shape && FEXCore::HBX87::UnitShape::Level() >= 6;
  const auto G3Ror8 = [](unsigned V, unsigned K) -> uint8_t {
    K &= 7;
    return static_cast<uint8_t>(((V >> K) | (V << ((8 - K) & 7))) & 0xFF);
  };
  fextl::unordered_map<uint32_t, LagInfo> Lag;
  LagOn = ShapeMode && (G3Shape ? FEXCore::HBX87::UnitShape::Level() >= 5 : FEXCore::HBX87::PCX::ShapeLagEnabled()) && FaultStateEnabled;
  G3Hold = G3Shape && LagOn;
  if (LagOn) {
    fextl::unordered_map<uint32_t, uint32_t> Pos;
    fextl::unordered_map<uint32_t, fextl::vector<uint32_t>> Preds;
    for (uint32_t k = 0; k < SOrder.size(); ++k) {
      Pos[SOrder[k]] = k;
    }
    for (const auto Id : SOrder) {
      const auto& I = SB[Id];
      for (uint8_t k = 0; k < I.NSucc; ++k) {
        Preds[I.Succ[k]].push_back(Id);
      }
    }
    for (const auto Id : SOrder) {
      const auto& I = SB[Id];
      auto& L = Lag[Id];
      L.Cap = I.X && !I.Rd && !I.St && !(I.PCX && I.Reads) && I.Start >= 0 && I.End >= 0;
      int Net = 0;
      if (L.Cap && G3RegOn) {
        // The slots the fast path may write (setTop / push), as offsets from the block's start TOP. Anything not modelled: all.
        int T = 0;
        unsigned W = 0;
        const auto Wr = [&](unsigned i) { W |= 1U << ((static_cast<int>(i) - T) & 7); };
        for (auto [Node, Op] : CurrentIR.GetCode(I.Block)) {
          switch (Op->Op) {
          case OP_PUSHSTACK:
          case OP_COPYPUSHSTACK: ++T; Wr(0); break;
          case OP_POPSTACKDESTROY:
          case OP_INCSTACKTOP: --T; break;
          case OP_DECSTACKTOP: ++T; break;
          case OP_STORESTACKTOSTACK: Wr(Op->C<IROp_StoreStackToStack>()->StackLocation); break;
          case OP_F80STACKXCHANGE: Wr(0); Wr(Op->C<IROp_F80StackXchange>()->SrcStack); break;
          case OP_F80ADDSTACK: Wr(Op->C<IROp_F80AddStack>()->SrcStack1); break;
          case OP_F80MULSTACK: Wr(Op->C<IROp_F80MulStack>()->SrcStack1); break;
          case OP_F80SUBSTACK: Wr(Op->C<IROp_F80SubStack>()->DstStack); break;
          case OP_F80DIVSTACK: Wr(Op->C<IROp_F80DivStack>()->DstStack); break;
          case OP_F80ADDVALUE:
          case OP_F80SUBVALUE:
          case OP_F80SUBRVALUE:
          case OP_F80MULVALUE:
          case OP_F80DIVVALUE:
          case OP_F80DIVRVALUE:
          case OP_F80SQRTSTACK:
          case OP_F80STACKCHANGESIGN:
          case OP_F80STACKABS:
          case OP_F80SINSTACK:
          case OP_F80COSSTACK:
          case OP_F80F2XM1STACK:
          case OP_F80ROUNDSTACK:
          case OP_F80VBSLSTACK:
          case OP_F80FPREMSTACK:
          case OP_F80FPREM1STACK:
          case OP_F80SCALESTACK: Wr(0); break;
          case OP_F80PTANSTACK:
          case OP_F80SINCOSSTACK: Wr(0); ++T; Wr(0); break;
          case OP_F80FYL2XSTACK:
          case OP_F80FYL2XP1STACK:
          case OP_F80ATANSTACK: Wr(1); --T; break;
          case OP_INVALIDATESTACK:
          case OP_STACKVALIDTAG:
          case OP_READSTACKVALUE:
          case OP_F80CMPSTACK:
          case OP_F80CMPVALUE:
          case OP_F80STACKTEST:
          case OP_STORESTACKMEM: break;
          default:
            if (LoweredX87(Op->Op)) W = 0xFF;
            break;
          }
        }
        L.W = static_cast<uint8_t>(W);
      }
      if (L.Cap) {
        for (auto [Node, Op] : CurrentIR.GetCode(I.Block)) {
          switch (Op->Op) {
          case OP_PUSHSTACK:
          case OP_COPYPUSHSTACK:
          case OP_DECSTACKTOP:
          case OP_F80PTANSTACK:
          case OP_F80SINCOSSTACK: ++Net; break;
          case OP_POPSTACKDESTROY:
          case OP_INCSTACKTOP:
          case OP_F80FYL2XSTACK:
          case OP_F80FYL2XP1STACK:
          case OP_F80ATANSTACK: --Net; break;
          case OP_INITSTACK:
          case OP_STACKFORCESLOW: L.Cap = false; break;
          case OP_SYNCSTACKTOSLOW:
            if (!I.PCX || I.Reads) {
              L.Cap = false; // synchronizes: the lag ends inside the block
            }
            break;
          default: break;
          }
        }
      }
      L.Net = static_cast<int8_t>(Net);
    }
    for (const auto Id : SOrder) {
      const auto& I = SB[Id];
      auto& L = Lag[Id];
      const auto PIt = Preds.find(Id);
      L.Acc = L.Cap && !I.EP && !I.Guard && PIt != Preds.end() && !PIt->second.empty();
      for (size_t k = 0; L.Acc && k < PIt->second.size(); ++k) {
        const uint32_t Pr = PIt->second[k];
        L.Acc = Pos[Pr] < Pos[Id] && Lag[Pr].Cap; // forward edges only: no suspend poll between them
      }
    }
    for (bool Changed = true; Changed;) {
      Changed = false;
      for (const auto Id : SOrder) {
        const auto& I = SB[Id];
        auto& L = Lag[Id];
        L.Carry = L.Cap && I.NSucc > 0;
        for (uint8_t k = 0; L.Carry && k < I.NSucc; ++k) {
          const auto It = Lag.find(I.Succ[k]);
          L.Carry = It != Lag.end() && It->second.Acc;
        }
      }
      for (const auto Id : SOrder) {
        const auto& I = SB[Id];
        auto& L = Lag[Id];
        if (L.Acc) {
          bool First = true;
          for (const uint32_t Pr : Preds[Id]) {
            const auto& LP = Lag[Pr];
            if (First) {
              L.D = LP.Dp;
              L.M = LP.Mp;
              L.R = LP.Rp;
              First = false;
            } else if (LP.Dp != L.D || LP.Mp != L.M || LP.Rp != L.R) {
              L.Acc = false; // predecessors leave different lags
              Changed = true;
              break;
            }
          }
        }
        const uint8_t Din = L.Acc ? L.D : 0;
        const uint8_t Min = L.Acc ? L.M : static_cast<uint8_t>(I.Start);
        L.Dp = L.Carry ? static_cast<uint8_t>((Din + L.Net) & 7) : 0;
        L.Mp = L.Carry ? Min : static_cast<uint8_t>(I.End);
        // level 6: cells = offsets from the lagging TOP. In registers at the end: what came in one or may have been written, and
        // is valid at the end.
        L.Rp = (L.Carry && G3RegOn) ?
                 static_cast<uint8_t>(((L.Acc ? L.R : 0) | G3Ror8(L.W, Din)) & G3Ror8(static_cast<uint8_t>(I.End), L.Dp)) : 0;
      }
    }
  }
  // Run optimization proper
  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    // Each time we deal with a new block we need to start over.
    // The optimization should run per-block
    Reset();
    ShapeBlock = false;
    if (ShapeMode) {
      const auto& I = SB[CurrentIR.GetID(BlockNode).Value];
      PCXBlock = I.PCX;
      PCXReadsState = I.Reads;
      ShapeBlock = I.X && !I.Rd && !I.St && !(PCXBlock && I.Reads) && I.Start >= 0;
      if (ShapeBlock) {
        FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::BlocksShape);
        // SHAPE_LAG: an acceptor starts with the lag its predecessors leave -- CPUState TOP is the true TOP + D (D pushes not yet
        // written), CPUState tags are M by that TOP; ST(i) is mm[(memory TOP - D + i) & 7].
        uint8_t LagD = 0;
        uint8_t LagM = static_cast<uint8_t>(I.Start);
        if (LagOn) {
          const auto LIt = Lag.find(CurrentIR.GetID(BlockNode).Value);
          if (LIt != Lag.end() && LIt->second.Acc) {
            LagD = LIt->second.D;
            LagM = LIt->second.M;
            if (LagD || LagM != static_cast<uint8_t>(I.Start)) {
              FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::BlocksLag);
            }
          }
        }
        ShapeRef = LagM;
        for (uint8_t i = 0; i < 8; ++i) {
          if ((I.Start >> i) & 1) {
            StackMemberInfo Seed {};
            Seed.SeedOffset = static_cast<int8_t>((i - LagD) & 7);
            StackData.seed(i, StackSlot::VALID, Seed);
          } else {
            StackData.seed(i, StackSlot::INVALID, StackMemberInfo::Invalid);
          }
        }
        StackData.TopOffset = static_cast<int8_t>(LagD);
        if (G3RegOn && LagOn) {
          const auto LIt = Lag.find(CurrentIR.GetID(BlockNode).Value);
          if (LIt != Lag.end() && LIt->second.Acc && LIt->second.R) {
            IREmit->SetCurrentCodeBlock(BlockNode);
            for (auto [FirstNode, FirstOp] : CurrentIR.GetCode(BlockNode)) {
              if (FirstOp->Op == OP_BEGINBLOCK) {
                IREmit->SetWriteCursor(FirstNode); // after the block's begin marker
              } else {
                IREmit->SetWriteCursorBefore(FirstNode);
              }
              break;
            }
            FEXCore::HBX87::UnitShape::Stats::Bump(FEXCore::HBX87::UnitShape::Stats::RegBlocks);
            for (uint8_t c = 0; c < 8; ++c) {
              if (!((LIt->second.R >> c) & 1)) continue;
              FEXCore::HBX87::UnitShape::Stats::Bump(FEXCore::HBX87::UnitShape::Stats::RegCells);
              const uint8_t i = static_cast<uint8_t>((c + LagD) & 7);
              LOGMAN_THROW_A_FMT((I.Start >> i) & 1, "G3 level 6: register cell not valid at the block start");
              StackData.setTop(StackMemberInfo {IREmit->_LoadRegister(8 + c, RegClass::FPR, OpSize::i128Bit)}, i);
            }
          }
        }
      }
    } else {
      PCXBlock = PCXMode && PCXEligible(CurrentIR, BlockNode);
    }
    if (PCXMode) {
      FEXCore::HBX87::PCX::Stats::Bump(PCXBlock ? FEXCore::HBX87::PCX::Stats::BlocksPCX : FEXCore::HBX87::PCX::Stats::BlocksExact);
    }
    ReducedPrecisionMode = PCXBlock || BaseReducedPrecision;
    S32BlockBegin(CurrentIR.GetHeader()->X87PCX); // X87EXACT S32
    G3PayloadBlock = G3Shape && ShapeBlock && FEXCore::HBX87::UnitShape::Payload();
    PendingC1 = {};

    IREmit->SetCurrentCodeBlock(BlockNode);
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      if (FaultStateEnabled && IROp->Op == OP_GUESTOPCODE) {
        CaptureFaultState(CodeNode);
        continue;
      }
      if (PCXBlock) {
        constexpr uint32_t C1Off = offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_C1_LOC;
        const auto Covers = [&](uint32_t Off, OpSize Sz) {
          return Off <= C1Off && C1Off < Off + IR::OpSizeToSize(Sz);
        };
        if (IROp->Op == OP_LOADCONTEXT) {
          if (Covers(IROp->C<IROp_LoadContext>()->Offset, IROp->Size)) {
            PendingC1 = {}; // observed: the last writer keeps its C1
          }
          continue;
        }
        if (IROp->Op == OP_LOADCONTEXTPAIR) {
          const auto* Op = IROp->C<IROp_LoadContextPair>();
          if (Op->Offset <= C1Off && C1Off < Op->Offset + 2 * IR::OpSizeToSize(IROp->Size)) {
            PendingC1 = {};
          }
          continue;
        }
        if (IROp->Op == OP_STORECONTEXT) {
          if (Covers(IROp->C<IROp_StoreContext>()->Offset, IROp->Size)) {
            PCXNoteC1Writer({});
          }
          continue;
        }
        // MACRUNNER_FEX_X87_FAULT_COVER: a fault at a guest memory op shows FSW in the context, so it observes C1 like FNSTSW:
        // the C1 writer before it keeps its C1.
        if (PendingC1 && MRX87FaultCover() && IsGuestMemoryOp(CurrentIR, IROp)) {
          PendingC1 = {};
        }
        if (IROp->Op == OP_F80CVTTO) {
          const auto* Op = IROp->C<IROp_F80CVTTo>();
          IREmit->SetWriteCursor(CodeNode);
          // Not a C1 writer: the exact path converts loads inline (Dispatcher::EmitF*ToExtF80) without touching FSW.
          Ref Loaded = S32Load(CurrentIR.GetNode(Op->X80Src), Op->SrcSize); // X87EXACT S32: typed when m32
          IREmit->ReplaceUsesWithAfter(CodeNode, Loaded, CodeNode);
          IREmit->Remove(CodeNode);
          continue;
        }
        if (IROp->Op == OP_F80CVTTOINT) {
          // FIADD/FISUB/FIMUL/FIDIV/FICOM m16/m32: exact in binary64; the instruction's own result writes C1.
          const auto* Op = IROp->C<IROp_F80CVTToInt>();
          IREmit->SetWriteCursor(CodeNode);
          Ref Src = CurrentIR.GetNode(Op->Src);
          if (Op->SrcSize == OpSize::i16Bit) {
            Src = IREmit->_Sbfe(OpSize::i64Bit, 16, 0, Src);
          } else {
            Src = IREmit->_Sbfe(OpSize::i64Bit, 32, 0, Src);
          }
          auto Converted = IREmit->_Float_FromGPR_S(OpSize::i64Bit, OpSize::i64Bit, Src);
          IREmit->ReplaceUsesWithAfter(CodeNode, Converted, CodeNode);
          IREmit->Remove(CodeNode);
          continue;
        }
        if (IROp->Op == OP_F80CMPQUIET || IROp->Op == OP_F80CMP) {
          IREmit->SetWriteCursor(CodeNode);
          auto Cmp = IREmit->_X87PCXCmp(CurrentIR.GetNode(IROp->Args[0]), CurrentIR.GetNode(IROp->Args[1]), IROp->Op == OP_F80CMPQUIET ? 1 : 0);
          IREmit->ReplaceUsesWithAfter(CodeNode, Cmp, CodeNode);
          IREmit->Remove(CodeNode);
          continue;
        }
      }
      if (!LoweredX87(IROp->Op)) {
        continue;
      }
      IREmit->SetWriteCursor(CodeNode);
      switch (IROp->Op) {
      case OP_F80ADDSTACK: {
        const auto* Op = IROp->C<IROp_F80AddStack>();
        HandleBinopStack(OP_VFADD, true, OP_F80ADD, Op->SrcStack1, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80SUBSTACK: {
        const auto* Op = IROp->C<IROp_F80SubStack>();
        HandleBinopStack(OP_VFSUB, true, OP_F80SUB, Op->DstStack, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80MULSTACK: {
        const auto* Op = IROp->C<IROp_F80MulStack>();
        HandleBinopStack(OP_VFMUL, true, OP_F80MUL, Op->SrcStack1, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80DIVSTACK: {
        const auto* Op = IROp->C<IROp_F80DivStack>();
        HandleBinopStack(OP_VFDIV, true, OP_F80DIV, Op->DstStack, Op->SrcStack1, Op->SrcStack2);
        break;
      }

      case OP_F80FPREMSTACK: {
        HandleBinopStack(OP_F64FPREM, false, OP_F80FPREM, 0, 0, 1);
        break;
      }

      case OP_F80FPREM1STACK: {
        HandleBinopStack(OP_F64FPREM1, false, OP_F80FPREM1, 0, 0, 1);
        break;
      }

      case OP_F80SCALESTACK: {
        HandleBinopStack(OP_F64SCALE, false, OP_F80SCALE, 0, 0, 1);
        break;
      }

      case OP_F80FYL2XSTACK: {
        HandleBinopStack(OP_F64FYL2X, false, OP_F80FYL2X, 1, 0, 1);
        StackPop();
        break;
      }

      case OP_F80FYL2XP1STACK: {
        HandleBinopStack(OP_F64FYL2XP1, false, OP_F80FYL2XP1, 1, 0, 1);
        StackPop();
        break;
      }

      case OP_F80ATANSTACK: {
        HandleBinopStack(OP_F64ATAN, false, OP_F80ATAN, 1, 1, 0);
        StackPop();
        break;
      }

      case OP_F80ADDVALUE: {
        const auto* Op = IROp->C<IROp_F80AddValue>();
        HandleBinopValue(OP_VFADD, true, OP_F80ADD, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src));
        break;
      }

      case OP_F80SUBRVALUE:
      case OP_F80SUBVALUE: {
        const auto* Op = IROp->C<IROp_F80SubValue>();
        HandleBinopValue(OP_VFSUB, true, OP_F80SUB, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src), IROp->Op == OP_F80SUBRVALUE);
        break;
      }

      case OP_F80DIVRVALUE:
      case OP_F80DIVVALUE: {
        const auto* Op = IROp->C<IROp_F80DivValue>();
        HandleBinopValue(OP_VFDIV, true, OP_F80DIV, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src), IROp->Op == OP_F80DIVRVALUE);
        break;
      }

      case OP_F80MULVALUE: {
        const auto* Op = IROp->C<IROp_F80MulValue>();
        HandleBinopValue(OP_VFMUL, true, OP_F80MUL, 0, true, Op->SrcStack, CurrentIR.GetNode(Op->X80Src));
        break;
      }

      case OP_F80SQRTSTACK: {
        HandleUnop(OP_VFSQRT, true, OP_F80SQRT);
        break;
      }

      case OP_F80SINSTACK: {
        HandleUnop(OP_F64SIN, false, OP_F80SIN);
        break;
      }

      case OP_F80COSSTACK: {
        HandleUnop(OP_F64COS, false, OP_F80COS);
        break;
      }

      case OP_F80F2XM1STACK: {
        HandleUnop(OP_F64F2XM1, false, OP_F80F2XM1);
        break;
      }


      case OP_F80PTANSTACK: {
        HandleUnop(OP_F64TAN, false, OP_F80TAN);
        Ref OneConst {};
        if (ReducedPrecisionMode) {
          OneConst = IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, GetConstant(0x3FF0000000000000));
        } else {
          OneConst = IREmit->_LoadNamedVectorConstant(OpSize::i128Bit, NamedVectorConstant::NAMED_VECTOR_X87_ONE);
        }

        if (SlowPath) {
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(OneConst);
        } else {
          StackData.push(StackMemberInfo {OneConst});
        }
        break;
      }

      case OP_F80SINCOSSTACK: {
        Ref St0 = LoadStackValue();

        Ref SinValue {};
        Ref CosValue {};

        if (ReducedPrecisionMode) {
          SinValue = IREmit->_F64SIN(St0);
          CosValue = IREmit->_F64COS(St0);
        }
#ifdef VIXL_SIMULATOR
        else if (DisableVixlIndirectCalls() == 0) {
          SinValue = IREmit->_F80SIN(St0);
          CosValue = IREmit->_F80COS(St0);
        }
#endif
        else {
          SinValue = IREmit->_AllocateFPR(OpSize::i128Bit, OpSize::i128Bit);
          CosValue = IREmit->_AllocateFPR(OpSize::i128Bit, OpSize::i128Bit);
          IREmit->_F80SINCOS(St0, SinValue, CosValue);
        }

        // Push values
        if (SlowPath) {
          StoreStackValueAtOffset_Slow(SinValue, 0, false);
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(CosValue, 0, true);
        } else {
          StackData.setTop(StackMemberInfo {SinValue});
          StackData.push(StackMemberInfo {CosValue});
        }
        break;
      }

      case OP_INITSTACK: {
        StackData.clear();
        InvalidateCachedRegs();
        break;
      }

      case OP_INVALIDATESTACK: {
        const auto* Op = IROp->C<IROp_ReadStackValue>();
        auto Offset = Op->StackLocation;

        if (Offset != 0xff) { // invalidate single offset
          if (SlowPath) {
            SetX87ValidTag(Offset, false);
          } else {
            StackData.setTagInvalid(Offset);
          }
        } else { // invalidate all
          if (SlowPath) {
            TopValidCache.fill(StackSlot::INVALID);
            FlushValidPending = true;
          } else {
            for (size_t i = 0; i < StackData.size; i++) {
              StackData.setTagInvalid(i);
            }
          }
        }
        break;
      }

      case OP_PUSHSTACK: {
        const auto* Op = IROp->C<IROp_PushStack>();
        auto* SourceNode = CurrentIR.GetNode(Op->X80Src);
        if (PCXBlock && !IsPCXContainer(CurrentIR, SourceNode)) {
          Ref MRConst = S32Const(CurrentIR, SourceNode); // X87EXACT S32: fld1 / fldz as typed constants
          SourceNode = MRConst ? MRConst : Ref(IREmit->_X87PCXFrom80(SourceNode));
        }

        // SHAPE: the original is kept only where key 1 keeps it (overflow known without the start shape), see apply_shape2.py.
        const bool MRKnownWithoutShape = !ShapeBlock || SlowPath || !StackData.isSeeded(7);
        // Must be evaluated before Top moves.
        Ref PushedNode = ApplyPushOverflow(SourceNode);
        // When the value can be the indefinite instead of the loaded one, the tracked
        // original is no longer what lands in the register, so drop that optimization.
        const bool KeepOriginal = !Op->OriginalValue.IsInvalid() && PushedNode == SourceNode && MRKnownWithoutShape;

        if (SlowPath) {
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(PushedNode);
        } else {
          if (!KeepOriginal) {
            // No original value to track - just push the converted data
            StackData.push(StackMemberInfo {PushedNode});
          } else {
            auto* OriginalNode = CurrentIR.GetNode(Op->OriginalValue);
            StackData.push(StackMemberInfo {PushedNode, OriginalNode, Op->LoadSize});
          }
        }
        break;
      }

      case OP_COPYPUSHSTACK: {
        const auto* Op = IROp->C<IROp_CopyPushStack>();
        auto Offset = Op->StackLocation;
        auto Value = MigrateToSlowPath_IfInvalid(Offset);

        if (SlowPath) {
          Ref St0 = LoadStackValueAtOffset_Slow(Offset);
          St0 = ApplyPushOverflow(St0);
          UpdateTopForPush_Slow();
          StoreStackValueAtOffset_Slow(St0);
        } else {
          const bool MRKnownWithoutShape = !ShapeBlock || !StackData.isSeeded(7); // SHAPE: as PUSHSTACK
          Ref Pushed = ApplyPushOverflow(Value->StackDataNode);
          if (Pushed == Value->StackDataNode && MRKnownWithoutShape) {
            StackData.push(*Value);
          } else {
            StackData.push(StackMemberInfo {Pushed});
          }
        }
        break;
      }

      case OP_READSTACKVALUE: {
        const auto* Op = IROp->C<IROp_ReadStackValue>();
        auto Offset = Op->StackLocation;
        Ref NewValue = LoadStackValue(Offset);

        IREmit->ReplaceUsesWithAfter(CodeNode, NewValue, CodeNode);
        break;
      }

      case OP_STACKVALIDTAG: {
        // Returns 0 if value is valid and 1 otherwise.
        const auto* Op = IROp->C<IROp_StackValidTag>();
        auto Offset = Op->StackLocation;
        if (ShapeBlock && !SlowPath) { // SHAPE: the tag is known, the value is not needed
          IREmit->ReplaceUsesWithAfter(CodeNode, GetConstant(StackData.top(Offset).Type == StackSlot::VALID ? 1 : 0), CodeNode);
          break;
        }
        auto Value = MigrateToSlowPath_IfInvalid(Offset);

        Ref Tag {};
        if (SlowPath) {
          Tag = GetX87ValidTag_Slow(Offset);
        } else {
          Tag = Value ? GetConstant(1) : GetConstant(0);
        }

        IREmit->ReplaceUsesWithAfter(CodeNode, Tag, CodeNode);
        break;
      }

      case OP_STORESTACKMEM: {
        const auto* Op = IROp->C<IROp_StoreStackMem>();
        const auto& Value = MigrateToSlowPath_IfInvalid();
        Ref StackNode = SlowPath ? LoadStackValueAtOffset_Slow() : Value->StackDataNode;
        Ref AddrNode = CurrentIR.GetNode(Op->Addr);
        Ref Offset = CurrentIR.GetNode(Op->Offset);
        OpSize Align = Op->Align;
        MemOffsetType OffsetType = Op->OffsetType;
        uint8_t OffsetScale = Op->OffsetScale;

        // On the fast path we can optimize memory copies.
        // If we are doing:
        // fld dword [rax]
        // fst dword [rbx]
        // We can optimize this to:
        // ldr w2, [x0]
        // str w2, [x1]
        // or similar. As long as the source size and dest size are one and the same.
        // This will avoid any conversions between source and stack element size and conversion back.
        OpSize StoreSize = Op->StoreSize;
        LOGMAN_THROW_A_FMT(Op->StoreSize == OpSize::i32Bit || Op->StoreSize == OpSize::i64Bit || Op->StoreSize == OpSize::f80Bit,
                           "Invalid store size in x87 store stack mem");
        if (!SlowPath && Value->Source && Value->Source->Size == StoreSize) {
          Ref SourceValue = Value->Source->Node;
          if (Op->StoreSize == OpSize::f80Bit) {
            Store80BitToMem(Op, SourceValue, AddrNode, Offset, Align, OffsetType, OffsetScale);
          } else {
            IREmit->_StoreMemFPR(StoreSize, SourceValue, AddrNode, Offset, Align, OffsetType, OffsetScale);
          }
          break;
        }

        if (S32Store(StackNode, StoreSize, AddrNode, Offset, Align, OffsetType, OffsetScale)) { // X87EXACT S32
          break;
        }
        if (PCXBlock) {
          if (StoreSize == OpSize::f80Bit) {
            Store80BitToMem(Op, IREmit->_X87PCXTo80(StackNode), AddrNode, Offset, Align, OffsetType, OffsetScale);
          } else {
            auto Stored = IREmit->_X87PCXStore(StackNode, StoreSize, (PCXC1 ? FEXCore::HBX87::PCX::FC1 : 0) |
                                                                     (PCXPE ? FEXCore::HBX87::PCX::FPE : 0));
            PCXNoteC1Writer(Stored);
            IREmit->_StoreMemFPR(StoreSize, Stored, AddrNode, Offset, Align, OffsetType, OffsetScale);
          }
          break;
        }
        if (ReducedPrecisionMode) {
          StoreStackMem_Reduced_Helper(CurrentIR, Op, StackNode);
          break;
        }

        StoreStackMem_Helper(CurrentIR, Op, StackNode);
        break;
      }

      case OP_STORESTACKTOSTACK: { // stores top of stack in another place in stack.
        const auto* Op = IROp->C<IROp_StoreStackToStack>();
        auto Offset = Op->StackLocation;

        if (Offset != 0) {
          auto Value = MigrateToSlowPath_IfInvalid();

          // Need to store st0 to stack location - basically a copy.
          if (SlowPath) {
            StoreStackValueAtOffset_Slow(LoadStackValueAtOffset_Slow(), Offset);
          } else {
            StackData.setTop(*Value, Offset);
          }
        }
        break;
      }
      case OP_POPSTACKDESTROY: {
        StackPop();
        break;
      }

      case OP_F80STACKXCHANGE: {
        const auto* Op = IROp->C<IROp_F80StackXchange>();
        auto Offset = Op->SrcStack;

        if (Offset == 0) {
          // No-op
          break;
        }

        if (ShapeBlock && !SlowPath) { // both slots move: their values must exist first
          MaterializeSeed(0);
          MaterializeSeed(Offset);
        }
        const auto [ValidTop, StackMemberTop] = StackData.top(0);
        const auto [ValidOffset, StackMemberOffset] = StackData.top(Offset);

        if (ValidTop != StackSlot::VALID || ValidOffset != StackSlot::VALID) {
          // Slow path: do actual memory operations
          Ref ValueTop = LoadStackValue();
          Ref ValueOffset = LoadStackValue(Offset);
          StoreStackValue(ValueOffset);
          StoreStackValue(ValueTop, Offset);
        } else {
          // Fast path: swap complete StackMemberInfo preserving Source metadata
          StackData.setTop(StackMemberOffset, 0);
          StackData.setTop(StackMemberTop, Offset);
        }
        break;
      }

      case OP_F80STACKCHANGESIGN: {
        Ref Value = LoadStackValue();
        if (S32Sign(Value, false)) { // X87EXACT S32
          break;
        }

        // We need a couple of intermediate instructions to change the sign
        // of a value
        Ref ResultNode {};
        if (PCXBlock) {
          // Bitwise: FPCR.AH does not keep a box's sign.
          Ref Sign = IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, GetConstant(static_cast<int64_t>(0x8000000000000000ULL)));
          ResultNode = IREmit->_VXor(OpSize::i64Bit, Value, Sign);
        } else if (ReducedPrecisionMode) {
          ResultNode = IREmit->_VFNeg(OpSize::i64Bit, OpSize::i64Bit, Value);
        } else {
          Ref HelperNode = IREmit->_LoadNamedVectorConstant(OpSize::i128Bit, IR::NamedVectorConstant::NAMED_VECTOR_F80_SIGN_MASK);
          ResultNode = IREmit->_VXor(OpSize::i128Bit, Value, HelperNode);
        }
        StoreStackValue(ResultNode);
        break;
      }

      case OP_F80STACKABS: {
        Ref Value = LoadStackValue();
        if (S32Sign(Value, true)) { // X87EXACT S32
          break;
        }

        Ref ResultNode {};
        if (PCXBlock) {
          Ref Sign = IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, GetConstant(static_cast<int64_t>(0x8000000000000000ULL)));
          ResultNode = IREmit->_VAndn(OpSize::i64Bit, Value, Sign);
        } else if (ReducedPrecisionMode) {
          ResultNode = IREmit->_VFAbs(OpSize::i64Bit, OpSize::i64Bit, Value);
        } else {
          // Intermediate insts
          Ref HelperNode = IREmit->_LoadNamedVectorConstant(OpSize::i128Bit, IR::NamedVectorConstant::NAMED_VECTOR_F80_SIGN_MASK);
          ResultNode = IREmit->_VAndn(OpSize::i128Bit, Value, HelperNode);
        }
        StoreStackValue(ResultNode);
        break;
      }

      case OP_F80CMPSTACK: {
        const auto* Op = IROp->C<IROp_F80CmpStack>();
        auto Offset = Op->SrcStack;
        Ref StackValue1 = LoadStackValue();
        Ref StackValue2 = LoadStackValue(Offset);

        Ref CmpNode {};
        if (PCXBlock) {
          CmpNode = IREmit->_X87PCXCmp(StackValue1, StackValue2, 0);
        } else if (ReducedPrecisionMode) {
          CmpNode = IREmit->_FCmp(OpSize::i64Bit, StackValue1, StackValue2);
        } else {
          CmpNode = IREmit->_F80Cmp(StackValue1, StackValue2);
        }

        IREmit->ReplaceUsesWithAfter(CodeNode, CmpNode, CodeNode);
        break;
      }
      case OP_F80STACKTEST: {
        const auto* Op = IROp->C<IROp_F80StackTest>();
        auto Offset = Op->SrcStack;
        auto StackNode = LoadStackValue(Offset);
        Ref ZeroConst = IREmit->_VCastFromGPR((ReducedPrecisionMode && !FEXCore::HBX87::RP::Int64()) ? OpSize::i64Bit : OpSize::i128Bit, OpSize::i64Bit, GetConstant(0));

        Ref CmpNode {};
        if (PCXBlock) {
          CmpNode = IREmit->_X87PCXCmp(StackNode, ZeroConst, 0);
        } else if (ReducedPrecisionMode) {
          CmpNode = IREmit->_FCmp(OpSize::i64Bit, StackNode, ZeroConst);
        } else {
          CmpNode = IREmit->_F80Cmp(StackNode, ZeroConst);
        }
        IREmit->ReplaceUsesWithAfter(CodeNode, CmpNode, CodeNode);
        break;
      }


      case OP_F80CMPVALUE: {
        const auto* Op = IROp->C<IROp_F80CmpValue>();
        const auto& Value = CurrentIR.GetNode(Op->X80Src);
        auto StackNode = LoadStackValue();

        Ref CmpNode {};
        if (PCXBlock) {
          CmpNode = IREmit->_X87PCXCmp(StackNode, Value, 0);
        } else if (ReducedPrecisionMode) {
          CmpNode = IREmit->_FCmp(OpSize::i64Bit, StackNode, Value);
        } else {
          CmpNode = IREmit->_F80Cmp(StackNode, Value);
        }
        IREmit->ReplaceUsesWithAfter(CodeNode, CmpNode, CodeNode);
        break;
      }

      case OP_SYNCSTACKTOSLOW: {
        if (!ReducedPrecisionMode && GPROpSize == OpSize::i64Bit &&
            FEXCore::HBX87::Guest64Enabled() && IROp->ElementSize == OpSize::i16Bit) {
          PreserveConsumedSlots = true;
        }
        // TRANS32 PC_EXACT: FNSTSW needs TOP and the flag bytes, not the registers. A PCX block that never reads mm[] / the tag word
        // from CPUState and is on the fast path takes TOP as an SSA value (CPUState TOP moved by the model's offset) and synchronizes
        // nothing: the model stays relative to CPUState, so push checks of an unknown ST(7) and the fault records stay valid.
        // (Synchronizing here with the stores left pending made both stale: stand/x87fsw32.c T1 / T2 / T3, 08.11.)
        if (PCXBlock && !PCXReadsState && !SlowPath) {
          const int8_t Off = StackData.TopOffset;
          Ref NewTop = Off ? GetOffsetTopWithCache_Slow(static_cast<uint8_t>(Off), true) : GetTopWithCache_Slow();
          IREmit->ReplaceUsesWithAfter(CodeNode, NewTop, CodeNode);
          break;
        }
        // This synchronizes stack values but doesn't necessarily moves us off the FastPath!
        Ref NewTop = SynchronizeStackValues();
        // A PCX block on the slow path keeps its caches pending to its end (no To80 per FNSTSW; slow-path fault records cover them).
        if (!PCXBlock || PCXReadsState) {
          FlushCachedRegs();
        }
        IREmit->ReplaceUsesWithAfter(CodeNode, NewTop, CodeNode);
        break;
      }

      case OP_STACKFORCESLOW: {
        MigrateToSlowPathIf(true);
        InvalidateCachedRegs();
        break;
      }

      case OP_INCSTACKTOP: {
        if (SlowPath) {
          UpdateTopForPop_Slow(false);
        } else {
          StackData.rotate(false);
        }
        break;
      }

      case OP_DECSTACKTOP: {
        if (SlowPath) {
          UpdateTopForPush_Slow();
        } else {
          StackData.rotate(true);
        }
        break;
      }

      case OP_F80ROUNDSTACK: {
        Ref St0 = LoadStackValue();

        Ref Value {};
        if (ReducedPrecisionMode) {
          Value = IREmit->_Vector_FToI(OpSize::i64Bit, OpSize::i64Bit, St0, RoundMode::Host);
        } else {
          Value = IREmit->_F80Round(St0);
        }
        StoreStackValue(Value);
        break;
      }

      case OP_F80VBSLSTACK: {
        const auto* Op = IROp->C<IROp_F80VBSLStack>();

        auto StackOffset1 = Op->SrcStack1;
        auto StackOffset2 = Op->SrcStack2;
        Ref Value1 = LoadStackValue(StackOffset1);
        Ref Value2 = LoadStackValue(StackOffset2);

        Ref StackNode = IREmit->_VBSL(OpSize::i128Bit, CurrentIR.GetNode(Op->VectorMask), Value1, Value2);
        StoreStackValue(StackNode, 0, StackOffset1 && StackOffset2);
        break;
      }

      default: LOGMAN_THROW_A_FMT(false, "IROp was expected to be lowered");
      }
      IREmit->Remove(CodeNode);
    }

    auto Last = CurrentIR.at(BlockIROp->Last);
    --Last;
    auto [LastCodeNode, LastIROp] = Last();
    LOGMAN_THROW_A_FMT(IsBlockExit(LastIROp->Op), "must be exit");
    if (FaultStateEnabled) {
      InsertFaultMarkers(CurrentIR, BlockNode);
    }
    IREmit->SetWriteCursorBefore(LastCodeNode);
    // SHAPE_LAG: a carrying block keeps TOP / tags pending when its model is the predicted lag; otherwise it synchronizes and then
    // writes CPUState to exactly that lag (its successors are compiled for it).
    const LagInfo* MRLag = nullptr;
    if (LagOn) {
      const auto LIt = Lag.find(CurrentIR.GetID(BlockNode).Value);
      if (LIt != Lag.end() && LIt->second.Carry) {
        MRLag = &LIt->second;
      }
    }
    LagKeepPending = MRLag && ShapeBlock && !SlowPath && (static_cast<uint8_t>(StackData.TopOffset) & 7) == MRLag->Dp &&
                     ShapeRef == MRLag->Mp;
    if (LagKeepPending && G3RegOn) { // level 6: every predicted register cell must hold a value
      for (unsigned c = 0; c < 8; ++c) {
        if (((MRLag->Rp >> c) & 1) && StackData.top((c + MRLag->Dp) & 7).Type != StackSlot::VALID) LagKeepPending = false;
      }
    }
    G3RegCells = (LagKeepPending && G3RegOn) ? MRLag->Rp : 0;
    SynchronizeStackValues();
    G3RegCells = 0;
    FlushCachedRegs();
    if (MRLag && !LagKeepPending && G3RegOn && MRLag->Rp) {
      // level 6, the block left its model (slow path, another TOP): everything is in mm[] now; the successors expect the
      // predicted cells in their registers (cell c = ST((c + Dp) & 7) of the true TOP).
      const auto Size = (ReducedPrecisionMode && !FEXCore::HBX87::RP::Int64()) ? OpSize::i64Bit : OpSize::i128Bit;
      for (unsigned c = 0; c < 8; ++c) {
        if (!((MRLag->Rp >> c) & 1)) continue;
        Ref Address = GetOffsetTopAddressWithCache_Slow(static_cast<uint8_t>((c + MRLag->Dp) & 7));
        G3StoreCell(IREmit->_LoadMemFPR(Size, Address, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1), c);
      }
    }
    if (MRLag) {
      if (LagKeepPending) {
        FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::LagKeep);
      } else if (MRLag->Dp != 0 || MRLag->Mp != static_cast<uint8_t>(SB[CurrentIR.GetID(BlockNode).Value].End)) {
        FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::LagRelag);
        Ref TrueTop = GetTopWithCache_Slow();
        Ref MemTop = IREmit->_And(OpSize::i32Bit, IREmit->Add(OpSize::i32Bit, TrueTop, MRLag->Dp), GetConstant(7));
        NoteFlush(IREmit->_StoreContextGPR(OpSize::i8Bit, MemTop,
                                           offsetof(FEXCore::Core::CPUState, flags) + FEXCore::X86State::X87FLAG_TOP_LOC));
        Ref Tags = RotateRight8(MRLag->Mp, IREmit->_Sub(OpSize::i32Bit, GetConstant(8), MemTop));
        NoteFlush(IREmit->_StoreContextGPR(OpSize::i8Bit, Tags, offsetof(FEXCore::Core::CPUState, AbridgedFTW)));
      }
    }
    LagKeepPending = false;
  }
}

// MACRUNNER_FEX_X87_FAULT_COVER (default 0): fault records that also cover memory ops behind an inline constant (RA) and slow-path
// blocks with a pending TOP (recorded as a shift from CPUState TOP instead of a TOP value that is no longer live at the fault).
static bool MRX87FaultCover() {
  static const bool v = [] { const char* p = getenv("MACRUNNER_FEX_X87_FAULT_COVER"); return p && p[0] == '1'; }();
  return v;
}
static bool MRX87FaultHold() {
  static const bool v = [] { const char* p = getenv("MACRUNNER_FEX_X87_FAULT_HOLD"); return p && p[0] == '1' && !p[1]; }();
  return v;
}
void X87StackOptimization::CaptureFaultState(Ref GuestOp) {
  FaultSnapshot S {.GuestOp = GuestOp};
  const bool CachesPending =
    FlushTopPending || FlushValidPending || std::any_of(FlushValuesPending.begin(), FlushValuesPending.end(), [](bool P) { return P; });
  if (!SlowPath) {
    if (CachesPending) {
      return; // transient, never seen at an instruction boundary: no table entry, a fault keeps today's state
    }
    S.TopOffset = static_cast<uint8_t>(StackData.TopOffset);
    for (size_t i = 0; i < StackData.size; ++i) {
      const auto& Entry = StackData.top(i);
      if (!StackData.isDirty(i)) {
        continue;
      }
      if (Entry.Type == StackSlot::VALID) {
        S.ValueMask |= 1U << i;
        S.ValidMask |= 1U << i;
        S.Values[i] = Entry.Value.StackDataNode;
        if (Ref MRTwin = S32Of(S.Values[i])) { // X87EXACT S32: the record names the single, not its widening
          S.Values[i] = MRTwin;
          S.SingleMask |= 1U << i;
        }
      } else if (Entry.Type == StackSlot::INVALID) {
        S.InvalidMask |= 1U << i;
      }
    }
    if (LagOn && ShapeBlock) {
      // SHAPE_LAG: CPUState may hold an older tag pattern (ShapeRef, by the cached TOP) for slots this block did not write.
      const uint8_t Cur = StackData.getValidMask();
      const unsigned K = static_cast<unsigned>(StackData.TopOffset) & 7;
      const uint8_t Ref8 = static_cast<uint8_t>(((ShapeRef << K) | (ShapeRef >> ((8 - K) & 7))) & 0xFF);
      const uint8_t Changed = Cur ^ Ref8;
      for (size_t i = 0; i < StackData.size; ++i) {
        if (StackData.isDirty(i) || !((Changed >> i) & 1)) {
          continue;
        }
        if ((Cur >> i) & 1) {
          S.ValidMask |= 1U << i;
        } else {
          S.InvalidMask |= 1U << i;
        }
      }
    }
    if (!S.ValueMask && !S.ValidMask && !S.InvalidMask && !S.TopOffset) {
      return;
    }
  } else {
    S.Slow = true;
    if (FlushTopPending && MRX87FaultCover() && SlowTopDelta != 99) {
      S.TopRel = true;
      S.TopOffset = static_cast<uint8_t>(-SlowTopDelta);
    } else if (FlushTopPending) {
      S.Top = TopOffsetCache[0];
    }
    for (size_t i = 0; i < 8; ++i) {
      if (FlushValuesPending[i]) {
        S.ValueMask |= 1U << i;
        S.Values[i] = TopValueCache[i];
      }
      if (FlushValidPending && TopValidCache[i] == StackSlot::VALID) {
        S.ValidMask |= 1U << i;
      } else if (FlushValidPending && TopValidCache[i] == StackSlot::INVALID) {
        S.InvalidMask |= 1U << i;
      }
    }
    if (!S.Top && !S.TopRel && !S.ValueMask && !S.ValidMask && !S.InvalidMask) {
      return;
    }
  }
  FaultSnapshots.push_back(S);
}

static bool IsGuestMemoryOp(const IRListView& IR, const IROp_Header* Op) {
  switch (Op->Op) {
  case OP_LOADMEM: return IR.GetOp<IROp_Header>(Op->C<IROp_LoadMem>()->Addr)->Op != OP_FORMCONTEXTADDRESS;
  case OP_STOREMEM: return IR.GetOp<IROp_Header>(Op->C<IROp_StoreMem>()->Addr)->Op != OP_FORMCONTEXTADDRESS;
  case OP_LOADMEMPAIR:
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
  case OP_ATOMICFETCHNEG: return true;
  default: return false;
  }
}

// Before the end-of-block synchronization: one marker per guest-memory op of an instruction that starts with pending state,
// until this pass stores x87 state inside that instruction (CPUState then already holds what a fault must see).
void X87StackOptimization::InsertFaultMarkers(const IRListView& IR, Ref BlockNode) {
  if (FaultSnapshots.empty()) {
    return;
  }
  size_t Next = 0;
  const FaultSnapshot* Current = nullptr;
  const auto ID = [&](Ref Node) {
    return Node ? IR.GetID(Node).Value : 0U;
  };
  for (auto [Node, Op] : IR.GetCode(BlockNode)) {
    if (Op->Op == OP_GUESTOPCODE) {
      Current = Next < FaultSnapshots.size() && FaultSnapshots[Next].GuestOp == Node ? &FaultSnapshots[Next++] : nullptr;
      continue;
    }
    if (!Current) {
      continue;
    }
    if (std::find(FlushNodes.begin(), FlushNodes.end(), Node) != FlushNodes.end()) {
      Current = nullptr;
      continue;
    }
    if (!IsGuestMemoryOp(IR, Op)) {
      continue;
    }
    const auto& S = *Current;
    const uint8_t Mode = (S.Slow ? 1 : 0) | (PCXBlock ? 16 : (ReducedPrecisionMode ? 2 : 0)) | (S.Top ? 4 : 0) | (S.TopRel ? 32 : 0) |
                         (((G3Hold && ShapeBlock) || MRX87FaultHold()) ? 0x40 : 0);
    IREmit->SetWriteCursorBefore(Node);
    IREmit->_X87FaultState(ID(Node), static_cast<uint8_t>(Mode | ((S.SingleMask || (PCXBlock && LagOn && ShapeBlock)) ? 0x40 : 0)), S.TopOffset, S.ValueMask, S.ValidMask,
                           S.InvalidMask, ID(S.Top), ID(S.Values[0]), ID(S.Values[1]), ID(S.Values[2]), ID(S.Values[3]), ID(S.Values[4]),
                           ID(S.Values[5]), ID(S.Values[6]), ID(S.Values[7]),
                           FEXCore::HBX87::S32::Mutant() == 10 ? uint8_t {0} : S.SingleMask); // X87EXACT S32: SingleMask
  }
}

fextl::unique_ptr<Pass> CreateX87StackOptimizationPass(const HostFeatures& Features, OpSize GPROpSize) {
  return fextl::make_unique<X87StackOptimization>(Features, GPROpSize);
}
} // namespace FEXCore::IR
