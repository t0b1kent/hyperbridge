// SPDX-License-Identifier: MIT
// X87EXACT 12.11.2026 (MacRunner contributors): the type layer of "S32" (Interface/Core/HBX87S32.h), included inside class
// X87StackOptimization. A stack member is typed when its StackDataNode is a widening node made by S32Make: S32Twin maps that node
// to the FPR node holding the same value as a binary32 (the "single"). StackDataNode stays valid for every other reader -- flush
// to CPUState, seeds, TOP / tag lag, values in host registers, the slow path -- and a widening nobody reads is removed as dead
// code, so only the functions below look at the single. The type travels with the node through fld st(i), fxch and fst st(i).
// The lowering is the only mode-specific part: "exact" = X87EXACT (PCX blocks), "RP" = G3FABLE (S32::RP(), not written yet).
bool S32Block = false;   // typed values may be made in this block
bool S32ArithOK = false; // ... and typed arithmetic: the unit's guard guarantees the control word 0x003F (precision field 01)
fextl::unordered_map<Ref, Ref> S32Twin; // widening node -> single, of the current block
Ref S32PEValue {};       // exact lowering: FSW.PE as loaded once in the current block

void S32BlockBegin(uint8_t HeaderPCX) {
  namespace PCX = FEXCore::HBX87::PCX;
  S32Twin.clear();
  S32PEValue = nullptr;
  S32Block = PCXBlock && FEXCore::HBX87::S32::Exact();
  // The container forms of such a block are compiled for PC24 without a word check (HBX87PCX.h: not DynW64, not DynPoly).
  S32ArithOK = S32Block && PCXMode == PCX::PC24 && !(HeaderPCX & (PCX::DynW64 | PCX::DynPoly));
}
Ref S32Of(Ref Wide) const {
  if (!S32Block || !Wide) {
    return nullptr;
  }
  const auto It = S32Twin.find(Wide);
  return It == S32Twin.end() ? nullptr : It->second;
}
// The stack node of a typed value: its widening (exact: a container or a box, RP: the stack double).
Ref S32Make(Ref Single) {
  Ref Wide = IREmit->_X87PCXWidenS(Single);
  S32Twin.emplace(Wide, Single);
  return Wide;
}
// Exact lowering: a typed arithmetic result or constant is below 2^125 in magnitude (or a box); a loaded value may be anything.
bool S32Bounded(Ref Single) {
  const auto Op = IREmit->ViewIR().GetOp<IROp_Header>(Single)->Op;
  return Op == OP_X87PCXARITHS || Op == OP_VCASTFROMGPR;
}
Ref S32PE() {
  if (!S32PEValue) {
    S32PEValue = GetX87Flag(FEXCore::X86State::X87FLAG_PE_LOC);
  }
  return S32PEValue;
}
// The x87 indefinite as a typed value: the box in a single of HBX87PCX.h IndefIndex, negative (ApplyPushOverflow: a push that
// overflows the register stack loads it instead of the value; with an unknown stack shape that is decided at run time).
Ref S32Indefinite() {
  return IREmit->_VCastFromGPR(OpSize::i32Bit, OpSize::i32Bit,
                               GetConstant(static_cast<int64_t>(0x80000000u | FEXCore::HBX87::S32::BoxBaseS | FEXCore::HBX87::PCX::IndefIndex)));
}
// fld m32 / m64 of a PCX block (F80CVTTo): the value's stack node.
Ref S32Load(Ref Src, OpSize SrcSize) {
  if (!S32Block || SrcSize != OpSize::i32Bit) {
    return IREmit->_X87PCXLoad(Src, SrcSize, 0);
  }
  return S32Make(IREmit->_X87PCXLoadS(Src));
}
// fld1 / fldz: the stack node of a typed constant, or nullptr.
Ref S32Const(const IRListView& IR, Ref SourceNode) {
  if (!S32Block) {
    return nullptr;
  }
  const auto* H = IR.GetOp<IROp_Header>(SourceNode);
  if (H->Op != OP_LOADNAMEDVECTORCONSTANT) {
    return nullptr;
  }
  const auto K = H->C<IROp_LoadNamedVectorConstant>()->Constant;
  if (K != NamedVectorConstant::NAMED_VECTOR_X87_ONE && K != NamedVectorConstant::NAMED_VECTOR_ZERO) {
    return nullptr;
  }
  return S32Make(IREmit->_VCastFromGPR(OpSize::i32Bit, OpSize::i32Bit, GetConstant(K == NamedVectorConstant::NAMED_VECTOR_X87_ONE ? 0x3F800000 : 0)));
}
Ref S32ArithExact(unsigned Kop, Ref A, Ref B) {
  namespace PCX = FEXCore::HBX87::PCX;
  unsigned K = Kop | PCX::K24;
  if (PCXC1) {
    K |= PCX::KC1;
  }
  // CheckA / CheckB: the operand may be 2^125 or more (a sum with it can overflow binary32).
  if (!S32Bounded(A)) {
    K |= PCX::CheckA;
  }
  if (Kop != PCX::OpSqrt && !S32Bounded(B)) {
    K |= PCX::CheckB;
  }
  auto Node = IREmit->_X87PCXArithS(A, B, S32PE(), static_cast<uint8_t>(K));
  PCXNoteC1Writer(Node);
  return Node;
}
// fadd / fsub / fmul / fdiv with both operands typed. StackNode = the stack operand's node, ValueNode = the other operand's.
bool S32Binop(IROps Op80, uint8_t DestStackOffset, bool MarkDestValid, uint8_t StackOffset, Ref StackNode, Ref ValueNode, bool Reverse) {
  namespace PCX = FEXCore::HBX87::PCX;
  if (!S32ArithOK || (Op80 != OP_F80ADD && Op80 != OP_F80SUB && Op80 != OP_F80MUL && Op80 != OP_F80DIV)) {
    return false;
  }
  Ref A = S32Of(StackNode), B = S32Of(ValueNode);
  if (!A || !B) {
    return false;
  }
  const unsigned Kop = Op80 == OP_F80ADD ? PCX::OpAdd : Op80 == OP_F80SUB ? PCX::OpSub : Op80 == OP_F80MUL ? PCX::OpMul : PCX::OpDiv;
  Ref R = S32ArithExact(Kop, Reverse ? B : A, Reverse ? A : B);
  StoreStackValue(S32Make(R), DestStackOffset, MarkDestValid && StackOffset != DestStackOffset);
  return true;
}
bool S32Sqrt(Ref St0) {
  Ref A = S32ArithOK ? S32Of(St0) : nullptr;
  if (!A) {
    return false;
  }
  StoreStackValue(S32Make(S32ArithExact(FEXCore::HBX87::PCX::OpSqrt, A, A)));
  return true;
}
// fchs / fabs: the sign bit of the single (of a box as well: its sign bit is the value's sign).
bool S32Sign(Ref Value, bool Abs) {
  Ref S = S32Of(Value);
  if (!S) {
    return false;
  }
  Ref Sign = IREmit->_VCastFromGPR(OpSize::i64Bit, OpSize::i64Bit, GetConstant(0x80000000LL));
  Ref R = Abs ? Ref(IREmit->_VAndn(OpSize::i64Bit, S, Sign)) : Ref(IREmit->_VXor(OpSize::i64Bit, S, Sign));
  StoreStackValue(S32Make(R));
  return true;
}
// fst(p) m32 of a typed value: the 32 bits as they are -- exact under any control word, C1 = 0.
bool S32Store(Ref StackNode, OpSize StoreSize, Ref AddrNode, Ref Offset, OpSize Align, MemOffsetType OffsetType, uint8_t OffsetScale) {
  Ref S = StoreSize == OpSize::i32Bit ? S32Of(StackNode) : nullptr;
  if (!S) {
    return false;
  }
  auto Stored = IREmit->_X87PCXStoreS(S, PCXC1 ? FEXCore::HBX87::PCX::FC1 : 0);
  PCXNoteC1Writer(Stored);
  IREmit->_StoreMemFPR(OpSize::i32Bit, Stored, AddrNode, Offset, Align, OffsetType, OffsetScale);
  return true;
}
