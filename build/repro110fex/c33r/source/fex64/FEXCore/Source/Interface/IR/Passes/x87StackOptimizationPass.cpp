// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
#include "Interface/Core/HBX87IR.h"
#include "Interface/Core/HBX87StateGates.h"
#include "FEXCore/Utils/LogManager.h"
#include "Interface/Core/Interpreter/Fallbacks/FallbackOpHandler.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "FEXCore/IR/IR.h"
#include "FEXCore/Utils/Profiler.h"
#include "FEXCore/Core/HostFeatures.h"
#include "Interface/Core/Addressing.h"

#include <FEXCore/fextl/vector.h>
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
  }

  // Rotate the elements with the direction controlled by Right
  void rotate(bool Right = true) {
    if (Right) {
      std::rotate(buffer.begin(), buffer.end() - 1, buffer.end());
      std::rotate(dirty.begin(), dirty.end() - 1, dirty.end());
      TopOffset++;
    } else {
      std::rotate(buffer.begin(), buffer.begin() + 1, buffer.end());
      std::rotate(dirty.begin(), dirty.begin() + 1, dirty.end());
      TopOffset--;
    }
  }

  void pop() {
    buffer.front() = {StackSlot::INVALID, T::Invalid};
    dirty.front() = true;
    rotate(false);
  }

  const StackSlotEntry& top(size_t Offset = 0) const {
    return buffer[Offset];
  }

  void setTop(const T& Value, size_t Offset = 0) {
    buffer[Offset] = {StackSlot::VALID, Value};
    dirty[Offset] = true;
  }

  bool isValid(size_t Offset) const {
    return buffer[Offset].Type == StackSlot::VALID;
  }

  void clear() {
    buffer.fill({StackSlot::UNUSED, T::Invalid});
    dirty.fill(false);
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
};

class X87StackOptimization final : public Pass {
public:
  X87StackOptimization(const FEXCore::HostFeatures& Features, OpSize GPROpSize)
    : Features(Features)
    , GPROpSize(GPROpSize) {
    FEX_CONFIG_OPT(ReducedPrecision, X87REDUCEDPRECISION);
    ReducedPrecisionMode = ReducedPrecision;
    FaultStateEnabled = FEXCore::HBX87::StateFix::FaultState();
  }
  void Run(IREmitter* Emit) override;

private:
  const FEXCore::HostFeatures& Features;
  const OpSize GPROpSize;
  bool ReducedPrecisionMode;
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
    SlowTopDelta = 0;
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

    const auto RegSize = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit;
    Ref Mask = IREmit->_VDupFromGPR(RegSize, OpSize::i64Bit, IREmit->_Neg(OpSize::i64Bit, Pred));
    return IREmit->_VBSL(RegSize, Mask, GetIndefiniteValue(), Value);
  }
  }

  return Value;
}

inline Ref X87StackOptimization::LoadStackValueAtOffset_Slow(uint8_t Offset) {
  OrderedNode* TopOffsetAddress = GetOffsetTopAddressWithCache_Slow(Offset);
  auto Size = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit;
  if (!TopValueCache[Offset]) {
    TopValueCache[Offset] = IREmit->_LoadMemFPR(Size, TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1);
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

inline std::optional<X87StackOptimization::StackMemberInfo> X87StackOptimization::MigrateToSlowPath_IfInvalid(uint8_t Offset) {
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
    }
    StackData.pop();
  }
}


void X87StackOptimization::HandleUnop(IROps Op64, bool VFOp64, IROps Op80) {
  Ref St0 = LoadStackValue();
  Ref Value {};

  if (ReducedPrecisionMode) {
    if (VFOp64) {
      DeriveOp(Value, Op64, IREmit->_VFSqrt(OpSize::i64Bit, OpSize::i64Bit, St0));
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

  Ref Node = {};
  if (ReducedPrecisionMode) {
    if (Reverse) {
      DeriveOp(Node, Op64, IREmit->_VFAdd(OpSize::i64Bit, OpSize::i64Bit, ValueNode, StackNode));
    } else {
      if (VFOp64) {
        DeriveOp(Node, Op64, IREmit->_VFAdd(OpSize::i64Bit, OpSize::i64Bit, StackNode, ValueNode));
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

  auto Size = ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit;
  for (size_t i = 0; i < FlushValuesPending.size(); i++) {
    if (FlushValuesPending[i]) {
      OrderedNode* TopOffsetAddress = GetOffsetTopAddressWithCache_Slow(i);
      NoteFlush(IREmit->_StoreMemFPR(Size, TopValueCache[i], TopOffsetAddress, IREmit->_InlineConstant(MMBaseOffset()), Size, MemOffsetType::SXTX, 1));
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

  // Store new top which is now the original top minus recorded top offset
  // Careful with underflow wraparound.
  const auto TopOffset = StackData.TopOffset;

  if (TopOffset != 0) {
    Ref NewTop = GetOffsetTopWithCache_Slow(TopOffset, true);
    SetTopWithCache_Slow(NewTop);
  }
  StackData.TopOffset = 0;

  // Before leaving we need to write the current values in the stack to
  // context so that the values are correct. Copy SourceDataNode in the
  // stack to the respective mmX register.
  Ref TopValue = GetTopWithCache_Slow();
  for (size_t i = 0; i < StackData.size; ++i) {
    const auto& [Valid, StackMember] = StackData.top(i);

    if (Valid == StackSlot::VALID) {
      StoreStackValueAtOffset_Slow(StackMember.StackDataNode, i, false);
    }
  }
  { // Set valid tags
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

  // Run optimization proper
  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    // Each time we deal with a new block we need to start over.
    // The optimization should run per-block
    Reset();

    IREmit->SetCurrentCodeBlock(BlockNode);
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      if (FaultStateEnabled && IROp->Op == OP_GUESTOPCODE) {
        CaptureFaultState(CodeNode);
        continue;
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

        // Must be evaluated before Top moves.
        Ref PushedNode = ApplyPushOverflow(SourceNode);
        // When the value can be the indefinite instead of the loaded one, the tracked
        // original is no longer what lands in the register, so drop that optimization.
        const bool KeepOriginal = !Op->OriginalValue.IsInvalid() && PushedNode == SourceNode;

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
          Ref Pushed = ApplyPushOverflow(Value->StackDataNode);
          if (Pushed == Value->StackDataNode) {
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

        // We need a couple of intermediate instructions to change the sign
        // of a value
        Ref ResultNode {};
        if (ReducedPrecisionMode) {
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

        Ref ResultNode {};
        if (ReducedPrecisionMode) {
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
        if (ReducedPrecisionMode) {
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
        Ref ZeroConst = IREmit->_VCastFromGPR(ReducedPrecisionMode ? OpSize::i64Bit : OpSize::i128Bit, OpSize::i64Bit, GetConstant(0));

        Ref CmpNode {};
        if (ReducedPrecisionMode) {
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
        if (ReducedPrecisionMode) {
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
        // This synchronizes stack values but doesn't necessarily moves us off the FastPath!
        Ref NewTop = SynchronizeStackValues();
        FlushCachedRegs();
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
    SynchronizeStackValues();
    FlushCachedRegs();
  }
}

// MACRUNNER_FEX_X87_FAULT_COVER (default 0): fault records that also cover memory ops behind an inline constant (RA) and slow-path
// blocks with a pending TOP (recorded as a shift from CPUState TOP instead of a TOP value that is no longer live at the fault).
static bool MRX87FaultCover() {
  static const bool v = [] { const char* p = getenv("MACRUNNER_FEX_X87_FAULT_COVER"); return p && p[0] == '1'; }();
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
      } else if (Entry.Type == StackSlot::INVALID) {
        S.InvalidMask |= 1U << i;
      }
    }
    if (!S.ValueMask && !S.InvalidMask && !S.TopOffset) {
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
    const uint8_t Mode = (S.Slow ? 1 : 0) | (ReducedPrecisionMode ? 2 : 0) | (S.Top ? 4 : 0) | (S.TopRel ? 32 : 0);
    IREmit->SetWriteCursorBefore(Node);
    IREmit->_X87FaultState(ID(Node), Mode, S.TopOffset, S.ValueMask, S.ValidMask, S.InvalidMask, ID(S.Top), ID(S.Values[0]),
                           ID(S.Values[1]), ID(S.Values[2]), ID(S.Values[3]), ID(S.Values[4]), ID(S.Values[5]), ID(S.Values[6]),
                           ID(S.Values[7]));
  }
}

fextl::unique_ptr<Pass> CreateX87StackOptimizationPass(const HostFeatures& Features, OpSize GPROpSize) {
  return fextl::make_unique<X87StackOptimization>(Features, GPROpSize);
}
} // namespace FEXCore::IR
