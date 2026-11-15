// SPDX-License-Identifier: MIT
/*
$info$
tags: frontend|x86-to-ir, opcodes|dispatcher-implementations
desc: Handles x86/64 ops to IR, no-pf opt, local-flags opt
$end_info$
*/

#include "FEXCore/Core/HostFeatures.h"
#include "FEXCore/Utils/Telemetry.h"
#include "Interface/Context/Context.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>

#include <FEXHeaderUtils/BitUtils.h>
#include <FEXCore/fextl/fmt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>

// FEX::Windows::Logging::Raw (__wine_dbg_output): fprintf in the PE part of FEX kills the process (see Core.cpp).
namespace FEX::Windows::Logging {
void Raw(const char* Message);
}

// ★ MacRunner Claude 29.09.2026: MACRUNNER_FEX_DIV_OVERFLOW_DE=1 makes DIV/IDIV raise #DE when the quotient does not
// fit the destination, not only when the divisor is zero (HB<->FEX oracle 28.09, class FEX-DIV-OVERFLOW). Unset or any
// other value keeps the zero-divisor check alone. MacRunnerDivOverflowChecks counts DIV/IDIV translations that carry
// the full check; a macrunner-fex-div-overflow-de line is printed when it reaches 1, 2, 4, 8, ...
std::atomic<uint64_t> MacRunnerDivOverflowChecks {0};
int MacRunnerDivOverflowMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_DIV_OVERFLOW_DE");
    return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
  }();
  return Mode;
}

// ★ MacRunner Claude 29.09.2026: MACRUNNER_FEX_DIV_PROVEN_HIGH=1 lets DIV/IDIV r32/r64 use the plain n-bit division
// when the high half of the dividend is known: the DIV follows `xor edx, edx` / `xor rdx, rdx` directly, or the IDIV
// follows CDQ/CQO of the same size directly, in the same block (the usual compiler idioms). Then the JIT needs neither
// the 2n-bit dividend nor its runtime check (sbfx/eor/cbz or cbz, and the LDIV/LUDIV call behind it), and with
// MACRUNNER_FEX_DIV_OVERFLOW_DE=1 the #DE condition is only "divisor 0", plus "INT_MIN / -1" for IDIV. Upstream folds
// the same case only when the extension is the IR node right before the division (TryPostRAMerge), which the
// zero-divisor branch in front of every DIV/IDIV prevents. Unset or any other value keeps the previous sequence.
// MacRunnerDivProvenHighUsed counts such translations; a macrunner-fex-div-proven-high line is printed at 1, 2, 4, ...
std::atomic<uint64_t> MacRunnerDivProvenHighUsed {0};
int MacRunnerDivProvenHighMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_DIV_PROVEN_HIGH");
    return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
  }();
  return Mode;
}

// A faulting unlocked RMW store must still expose the previous guest flags.
// This diagnostic mode commits the existing flag recipe only after the store.
static bool MacRunnerRMWFlagsAfterStore() {
  static const bool Enabled = [] {
    const char* Value = getenv("MACRUNNER_FEX_RMW_FLAGS_AFTER_STORE");
    return Value && Value[0] == '1' && !Value[1];
  }();
  return Enabled;
}

// Experimental only: leave the accepted engine and the existing gate-off IR untouched.
// Proven register DIV/IDIV branches to cold #DE blocks before either output is written.
// ARM zero division does not trap; signed overflow also needs an explicit check.
int MacRunnerDivFastMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_DIV_FAST");
    // 1.1.0: a variable that is not set means mode 8. A value that is set keeps its old meaning: 1..7 select that mode,
    // 0 (and anything that is not exactly one digit 1..8) switches the fast path off.
    if (!Value) {
      return 8;
    }
    return (Value && (Value[0] == '1' || Value[0] == '2' || Value[0] == '3' || Value[0] == '4' || Value[0] == '5' || Value[0] == '6' || Value[0] == '7' || Value[0] == '8') && !Value[1]) ? Value[0] - '0' : 0;
  }();
  return Mode;
}
std::atomic<uint64_t> MacRunnerDivFastUsed {0};

// MacRunner CLAUDE-EXC 11.10.2026 (0108): MACRUNNER_FEX_KUSD_XLATE=1 translates an ABSOLUTE memory operand (disp32 without base/index/segment,
// or a 64-bit moffs) that is really loaded or stored and points into the canonical KUSER_SHARED_DATA page 0x7ffe0000..0x7ffe0fff to Wine's host
// alias 0x7ffe0000000. macOS arm64 keeps a 4 GB PAGEZERO, so the canonical address is unmappable and every such access faults (SIGBUS, DFSC 0x06)
// and is emulated by the unix signal handler (about 5 us per read, measured 11.10). With the key the JIT reads the alias directly: no fault, no
// emulation. Not rewritten: LEA (an address VALUE), immediates, register-based addresses. Unset or any other value keeps the previous translation.
// MacRunnerKusdXlateCount counts rewritten operands; a macrunner-fex-kusd-xlate line is printed at 1, 2, 4, 8, ...
std::atomic<uint64_t> MacRunnerKusdXlateCount {0};
int MacRunnerKusdXlateMode() {
  static const int Mode = [] {
    const char* Value = getenv("MACRUNNER_FEX_KUSD_XLATE");
    return (Value && Value[0] == '1' && !Value[1]) ? 1 : 0;
  }();
  return Mode;
}
constexpr uint64_t MacRunnerKusdCanonical = 0x7ffe0000ULL;
constexpr uint64_t MacRunnerKusdAlias = 0x7ffe0000000ULL;
constexpr uint64_t MacRunnerKusdSize = 0x1000ULL;

namespace FEXCore::IR {

using X86Tables::OpToIndex;

// Called only for operands that really access memory (see the comment at MacRunnerKusdXlateMode).
static void MacRunnerKusdRewrite(AddressMode& A, bool Is64BitMode, IR::OpSize GPRSize) {
  if (!Is64BitMode || A.Segment || A.Base || A.Index || A.AddrSize != GPRSize || !MacRunnerKusdXlateMode()) {
    return;
  }
  if (static_cast<uint64_t>(A.Offset) - MacRunnerKusdCanonical >= MacRunnerKusdSize) {
    return;
  }
  A.Offset += static_cast<int64_t>(MacRunnerKusdAlias - MacRunnerKusdCanonical);
  const uint64_t N = MacRunnerKusdXlateCount.fetch_add(1, std::memory_order_relaxed) + 1;
  if ((N & (N - 1)) == 0) {
    char Line[160];
    const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-kusd-xlate: n={} address={:x}\n", N, static_cast<uint64_t>(A.Offset));
    Line[Result.size < sizeof(Line) ? Result.size : sizeof(Line) - 1] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
}

#define OpcodeArgs [[maybe_unused]] FEXCore::X86Tables::DecodedOp Op

void OpDispatchBuilder::SyscallOp(OpcodeArgs, bool IsSyscallInst) {
  constexpr size_t SyscallArgs = 7;
  using SyscallArray = std::array<uint64_t, SyscallArgs>;

  size_t NumArguments {};
  const SyscallArray* GPRIndexes {};
  static constexpr SyscallArray GPRIndexes_64 = {
    FEXCore::X86State::REG_RAX, FEXCore::X86State::REG_RDI, FEXCore::X86State::REG_RSI, FEXCore::X86State::REG_RDX,
    FEXCore::X86State::REG_R10, FEXCore::X86State::REG_R8,  FEXCore::X86State::REG_R9,
  };
  static constexpr SyscallArray GPRIndexes_32 = {
    FEXCore::X86State::REG_RAX, FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_RCX, FEXCore::X86State::REG_RDX,
    FEXCore::X86State::REG_RSI, FEXCore::X86State::REG_RDI, FEXCore::X86State::REG_RBP,
  };

  const auto OSABI = CTX->SyscallHandler->GetOSABI();
  if (OSABI == FEXCore::HLE::SyscallOSABI::OS_LINUX64) {
    NumArguments = GPRIndexes_64.size();
    GPRIndexes = &GPRIndexes_64;
  } else if (OSABI == FEXCore::HLE::SyscallOSABI::OS_LINUX32) {
    NumArguments = GPRIndexes_32.size();
    GPRIndexes = &GPRIndexes_32;
  } else if (OSABI == FEXCore::HLE::SyscallOSABI::OS_GENERIC) {
    // All registers will be spilled before the syscall and filled afterwards so no JIT-side argument handling is necessary.
    NumArguments = 0;
    GPRIndexes = nullptr;
  } else {
    ERROR_AND_DIE_FMT("Unhandled OSABI syscall");
  }

  // Calculate flags early.
  CalculateDeferredFlags();

  const auto GPRSize = GetGPROpSize();
  auto NewRIP = GetRelocatedPC(Op, -Op->InstSize);
  _StoreContextGPR(GPRSize, NewRIP, offsetof(FEXCore::Core::CPUState, rip));

  Ref Arguments[SyscallArgs] {
    InvalidNode, InvalidNode, InvalidNode, InvalidNode, InvalidNode, InvalidNode, InvalidNode,
  };
  for (size_t i = 0; i < NumArguments; ++i) {
    Arguments[i] = LoadGPRRegister(GPRIndexes->at(i));
  }

  if (IsSyscallInst) {
    // If this is the `Syscall` instruction rather than `int 0x80` then we need to do some additional work.
    // RCX = RIP after this instruction
    // R11 = EFlags
    // Calculate flags.
    CalculateDeferredFlags();

    auto RFLAG = GetPackedRFLAG();
    StoreGPRRegister(X86State::REG_R11, RFLAG, OpSize::i64Bit);

    auto RIPAfterInst = GetRelocatedPC(Op);
    StoreGPRRegister(X86State::REG_RCX, RIPAfterInst, OpSize::i64Bit);
  }

  FlushRegisterCache();
  auto SyscallOp = _Syscall(Arguments[0], Arguments[1], Arguments[2], Arguments[3], Arguments[4], Arguments[5], Arguments[6]);

  // Generic ABI doesn't store result in RAX.
  if (OSABI != FEXCore::HLE::SyscallOSABI::OS_GENERIC) {
    StoreGPRRegister(X86State::REG_RAX, SyscallOp);
  }

  if (Op->TableInfo->Flags & X86Tables::InstFlags::FLAGS_BLOCK_END) {
    // RIP could have been updated after coming back from the Syscall.
    NewRIP = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, rip));
    ExitFunction(NewRIP);
  }
}

void OpDispatchBuilder::ThunkOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  uint8_t* sha256 = (uint8_t*)(Op->PC + 2);

  if (Is64BitMode) {
    // x86-64 ABI puts the function argument in RDI
    Thunk(LoadGPRRegister(X86State::REG_RDI), *reinterpret_cast<SHA256Sum*>(sha256));
  } else {
    // x86 fastcall ABI puts the function argument in ECX
    Thunk(LoadGPRRegister(X86State::REG_RCX), *reinterpret_cast<SHA256Sum*>(sha256));
  }

  auto NewRIP = Pop(GPRSize);

  // Store the new RIP
  ExitFunction(NewRIP, BranchHint::Return);
  BlockSetRIP = true;
}

void OpDispatchBuilder::LEAOp(OpcodeArgs) {
  // LEA specifically ignores segment prefixes
  const auto SrcSize = OpSizeFromSrc(Op);
  const auto OpAddr = X86Tables::DecodeFlags::GetOpAddr(Op->Flags, 0);
  OpSize DstSize {};

  if (Is64BitMode) {
    DstSize = OpAddr == X86Tables::DecodeFlags::FLAG_OPERAND_SIZE_LAST  ? OpSize::i16Bit :
              OpAddr == X86Tables::DecodeFlags::FLAG_WIDENING_SIZE_LAST ? OpSize::i64Bit :
                                                                          OpSize::i32Bit;
  } else {
    DstSize = OpAddr == X86Tables::DecodeFlags::FLAG_OPERAND_SIZE_LAST ? OpSize::i16Bit : OpSize::i32Bit;
  }

  auto Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], SrcSize, Op->Flags, {.LoadData = false, .AllowUpperGarbage = SrcSize > DstSize});
  StoreResultGPR_WithOpSize(Op, Op->Dest, Src, DstSize);
}

void OpDispatchBuilder::NOPOp(OpcodeArgs) {}

void OpDispatchBuilder::RETOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();

  Ref SP = _RMWHandle(LoadGPRRegister(X86State::REG_RSP));
  Ref NewRIP = Pop(GPRSize, SP);

  if (Op->OP == 0xC2) {
    auto Offset = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    SP = Add(GPRSize, SP, Offset);
  }

  // Store the new stack pointer
  StoreGPRRegister(X86State::REG_RSP, SP);

  // Store the new RIP
  ExitFunction(NewRIP, BranchHint::Return);
  BlockSetRIP = true;
}

/*
stack contains:
Size of each member is 64-bit, 32-bit, or 16-bit depending on operating size
RIP
CS
EFLAGS
RSP
SS
*/
void OpDispatchBuilder::IRETOp(OpcodeArgs) {
  // Operand Size override unsupported!
  if ((Op->Flags & X86Tables::DecodeFlags::FLAG_OPERAND_SIZE) != 0) {
    LogMan::Msg::EFmt("IRET only implemented for 64bit and 32bit sizes");
    DecodeFailure = true;
    return;
  }

  const auto GPRSize = GetGPROpSize();

  Ref SP = _RMWHandle(LoadGPRRegister(X86State::REG_RSP));

  // RIP (64/32/16 bits)
  auto NewRIP = Pop(GPRSize, SP);
  // CS (lower 16 used)
  auto NewSegmentCS = Pop(GPRSize, SP);
  _StoreContextGPR(OpSize::i16Bit, NewSegmentCS, offsetof(FEXCore::Core::CPUState, cs_idx));
  UpdatePrefixFromSegment(NewSegmentCS, FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX);

  // eflags (lower 16 used)
  SetPackedRFLAG(false, Pop(GPRSize, SP));

  if (Is64BitMode) {
    // RSP and SS only happen in 64-bit mode or if this is a CPL mode jump!
    // FEX doesn't support a CPL mode switch, so don't need to worry about this on 32-bit
    StoreGPRRegister(X86State::REG_RSP, Pop(GPRSize, SP));

    // ss
    auto NewSegmentSS = Pop(GPRSize, SP);
    _StoreContextGPR(OpSize::i16Bit, NewSegmentSS, offsetof(FEXCore::Core::CPUState, ss_idx));
    UpdatePrefixFromSegment(NewSegmentSS, FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX);
  } else {
    // Store the stack in 32-bit mode
    StoreGPRRegister(X86State::REG_RSP, SP);
  }

  ExitFunction(NewRIP);
  BlockSetRIP = true;
}

void OpDispatchBuilder::CallbackReturnOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  // Store the new RIP
  _CallbackReturn();
  auto NewRIP = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, rip));
  // This ExitFunction won't actually get hit but needs to exist
  ExitFunction(NewRIP);
  BlockSetRIP = true;
}

void OpDispatchBuilder::SecondaryALUOp(OpcodeArgs) {
  FEXCore::IR::IROps IROp, AtomicIROp;
#define OPD(group, prefix, Reg) (((group - FEXCore::X86Tables::TYPE_GROUP_1) << 6) | (prefix) << 3 | (Reg))
  switch (Op->OP) {
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x80), 0):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x81), 0):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x83), 0):
    IROp = FEXCore::IR::IROps::OP_ADD;
    AtomicIROp = FEXCore::IR::IROps::OP_ATOMICFETCHADD;
    break;
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x80), 1):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x81), 1):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x83), 1):
    IROp = FEXCore::IR::IROps::OP_OR;
    AtomicIROp = FEXCore::IR::IROps::OP_ATOMICFETCHOR;
    break;
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x80), 4):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x81), 4):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x83), 4):
    IROp = FEXCore::IR::IROps::OP_ANDWITHFLAGS;
    AtomicIROp = FEXCore::IR::IROps::OP_ATOMICFETCHAND;
    break;
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x80), 5):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x81), 5):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x83), 5):
    IROp = FEXCore::IR::IROps::OP_SUB;
    AtomicIROp = FEXCore::IR::IROps::OP_ATOMICFETCHSUB;
    break;
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x80), 6):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x81), 6):
  case OPD(FEXCore::X86Tables::TYPE_GROUP_1, OpToIndex(0x83), 6):
    IROp = FEXCore::IR::IROps::OP_XOR;
    AtomicIROp = FEXCore::IR::IROps::OP_ATOMICFETCHXOR;
    break;
  default:
    IROp = FEXCore::IR::IROps::OP_LAST;
    AtomicIROp = FEXCore::IR::IROps::OP_LAST;
    LogMan::Msg::EFmt("Unknown ALU Op: 0x{:x}", Op->OP);
    DecodeFailure = true;
    return;
  };
#undef OPD

  ALUOp(Op, IROp, AtomicIROp, 1);
}

void OpDispatchBuilder::ADCOp(OpcodeArgs, uint32_t SrcIndex) {
  // Calculate flags early.
  CalculateDeferredFlags();

  Ref Src = LoadSourceGPR(Op, Op->Src[SrcIndex], Op->Flags, {.AllowUpperGarbage = true});
  const auto Size = OpSizeFromDst(Op);
  const auto OpSize = std::max(OpSize::i32Bit, Size);

  Ref Before {};
  if (DestIsLockedMem(Op)) {
    auto ALUOp = IncrementByCarry(OpSize, Src);
    HandledLock = true;

    Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
    Before = _AtomicFetchAdd(Size, ALUOp, DestMem);
  } else {
    Before = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  }

  Ref Result;
  if (!DestIsLockedMem(Op) && Op->Src[SrcIndex].IsLiteral() && Op->Src[SrcIndex].Literal() == 0 && Size >= OpSize::i32Bit) {
    HandleNZCV_RMW();
    RectifyCarryInvert(true);
    Result = _AdcZeroWithFlags(OpSize, Before);
    SetRFLAG<FEXCore::X86State::RFLAG_AF_RAW_LOC>(Before);
    CalculatePF(Result);
    CFInverted = false;
  } else {
    Result = CalculateFlags_ADC(Size, Before, Src);
  }

  if (!DestIsLockedMem(Op)) {
    StoreResultGPR(Op, Result);
  }
}

void OpDispatchBuilder::SBBOp(OpcodeArgs, uint32_t SrcIndex) {
  // Calculate flags early.
  CalculateDeferredFlags();

  Ref Src = LoadSourceGPR(Op, Op->Src[SrcIndex], Op->Flags, {.AllowUpperGarbage = true});
  const auto Size = OpSizeFromDst(Op);
  const auto OpSize = std::max(OpSize::i32Bit, Size);

  Ref Result {};
  Ref Before {};
  if (DestIsLockedMem(Op)) {
    HandledLock = true;

    Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
    auto SrcPlusCF = IncrementByCarry(OpSize, Src);
    Before = _AtomicFetchSub(Size, SrcPlusCF, DestMem);
  } else {
    Before = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  }

  Result = CalculateFlags_SBB(Size, Before, Src);

  if (!DestIsLockedMem(Op)) {
    StoreResultGPR(Op, Result);
  }
}

void OpDispatchBuilder::SALCOp(OpcodeArgs) {
  CalculateDeferredFlags();

  auto Result = NZCVSelect(OpSize::i32Bit, CondClass::UGE /* CF = 1 */, _InlineConstant(0xffffffff), _InlineConstant(0));

  StoreResultGPR(Op, Result);
}

void OpDispatchBuilder::PUSHOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);

  Push(Size, LoadSourceGPR(Op, Op->Src[0], Op->Flags));
}

void OpDispatchBuilder::PUSHREGOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);

  Push(Size, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}));
}

void OpDispatchBuilder::PUSHAOp(OpcodeArgs) {
  // 32bit only
  const auto Size = OpSizeFromSrc(Op);

  Ref OldSP = _Copy(LoadGPRRegister(X86State::REG_RSP));

  Push(Size, LoadGPRRegister(X86State::REG_RAX));
  Push(Size, LoadGPRRegister(X86State::REG_RCX));
  Push(Size, LoadGPRRegister(X86State::REG_RDX));
  Push(Size, LoadGPRRegister(X86State::REG_RBX));
  Push(Size, OldSP);
  Push(Size, LoadGPRRegister(X86State::REG_RBP));
  Push(Size, LoadGPRRegister(X86State::REG_RSI));
  Push(Size, LoadGPRRegister(X86State::REG_RDI));
}

void OpDispatchBuilder::PUSHSegmentOp(OpcodeArgs, uint32_t SegmentReg) {
  const auto SrcSize = OpSizeFromSrc(Op);
  const auto DstSize = OpSizeFromDst(Op);

  Ref Src {};
  if (!Is64BitMode) {
    switch (SegmentReg) {
    case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX: {
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, es_idx));
      break;
    }
    case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX: {
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, cs_idx));
      break;
    }
    case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX: {
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, ss_idx));
      break;
    }
    case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX: {
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, ds_idx));
      break;
    }
    case FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX: {
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, fs_idx));
      break;
    }
    case FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX: {
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, gs_idx));
      break;
    }
    default: FEX_UNREACHABLE;
    }
  } else {
    switch (SegmentReg) {
    case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX:
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, es_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX:
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, cs_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX:
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, ss_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX:
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, ds_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX:
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, fs_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX:
      Src = _LoadContextGPR(SrcSize, offsetof(FEXCore::Core::CPUState, gs_cached));
      break;
    default: FEX_UNREACHABLE;
    }
  }

  // Store our value to the new stack location
  // AMD hardware zexts segment selector to 32bit
  // Intel hardware inserts segment selector
  Push(DstSize, Src);
}

void OpDispatchBuilder::POPOp(OpcodeArgs) {
  if (IsOperandMem(Op->Dest, false)) {
    const auto Size = OpSizeFromSrc(Op);
    const auto GPRSize = GetGPROpSize();
    const auto Bytes = IR::OpSizeToSize(Size);
    Ref OldSP = LoadGPRRegister(X86State::REG_RSP);
    Ref Value = _LoadMemGPRAutoTSO(Size, {.Base = OldSP, .AddrSize = GPRSize, .NonTSO = true});
    Ref NewSP = Add(GPRSize, OldSP, Bytes);
    auto Address = DecodeAddress(Op, Op->Dest, MemoryAccessType::DEFAULT, false);

    // POP computes a memory destination using the incremented SP, but a
    // faulting destination store must leave the architectural SP unchanged.
    const auto& Dst = Op->Dest;
    if ((Dst.IsGPRDirect() && Dst.Data.GPR.GPR == X86State::REG_RSP) ||
        ((Dst.IsGPRIndirect() || Dst.IsGPRIndirectRelocation()) && Dst.Data.GPRIndirect.GPR == X86State::REG_RSP) ||
        ((Dst.IsSIB() || Dst.IsSIBRelocation()) && Dst.Data.SIB.Base == X86State::REG_RSP)) {
      Address.Base = Add(GPRSize, Address.Base, Bytes);
    }
    if ((Dst.IsSIB() || Dst.IsSIBRelocation()) && Dst.Data.SIB.Index == X86State::REG_RSP) {
      Address.Index = NewSP;
    }
    _StoreMemGPRAutoTSO(Size, Address, Value);
    StoreGPRRegister(X86State::REG_RSP, NewSP);
    return;
  }
  Ref Value = Pop(OpSizeFromSrc(Op));
  StoreResultGPR(Op, Value);
}

void OpDispatchBuilder::POPAOp(OpcodeArgs) {
  // 32bit only
  const auto Size = OpSizeFromSrc(Op);

  Ref SP = _RMWHandle(LoadGPRRegister(X86State::REG_RSP));

  StoreGPRRegister(X86State::REG_RDI, Pop(Size, SP), Size);
  StoreGPRRegister(X86State::REG_RSI, Pop(Size, SP), Size);
  StoreGPRRegister(X86State::REG_RBP, Pop(Size, SP), Size);

  // Skip loading RSP because it'll be correct at the end
  SP = _RMWHandle(Add(OpSize::i64Bit, SP, IR::OpSizeToSize(Size)));

  StoreGPRRegister(X86State::REG_RBX, Pop(Size, SP), Size);
  StoreGPRRegister(X86State::REG_RDX, Pop(Size, SP), Size);
  StoreGPRRegister(X86State::REG_RCX, Pop(Size, SP), Size);
  StoreGPRRegister(X86State::REG_RAX, Pop(Size, SP), Size);

  // Store the new stack pointer
  StoreGPRRegister(X86State::REG_RSP, SP);
}

void OpDispatchBuilder::POPSegmentOp(OpcodeArgs, uint32_t SegmentReg) {
  const auto SrcSize = OpSizeFromSrc(Op);
  const auto DstSize = OpSizeFromDst(Op);

  auto NewSegment = Pop(SrcSize);

  switch (SegmentReg) {
  case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX:
    _StoreContextGPR(DstSize, NewSegment, offsetof(FEXCore::Core::CPUState, es_idx));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX:
    _StoreContextGPR(DstSize, NewSegment, offsetof(FEXCore::Core::CPUState, cs_idx));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX:
    // Unset the 'active' bit in the packed TF, skipping the single step exception after this instruction
    SetRFLAG<FEXCore::X86State::RFLAG_TF_RAW_LOC>(_And(OpSize::i32Bit, GetRFLAG(FEXCore::X86State::RFLAG_TF_RAW_LOC), Constant(1)));
    _StoreContextGPR(DstSize, NewSegment, offsetof(FEXCore::Core::CPUState, ss_idx));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX:
    _StoreContextGPR(DstSize, NewSegment, offsetof(FEXCore::Core::CPUState, ds_idx));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX:
    _StoreContextGPR(DstSize, NewSegment, offsetof(FEXCore::Core::CPUState, fs_idx));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX:
    _StoreContextGPR(DstSize, NewSegment, offsetof(FEXCore::Core::CPUState, gs_idx));
    break;
  default: break; // Do nothing
  }

  UpdatePrefixFromSegment(NewSegment, SegmentReg);
}

void OpDispatchBuilder::LEAVEOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  const auto OperandSize = (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_OPERAND_SIZE) ? OpSize::i16Bit : GPRSize;

  // First we move RBP in to RSP and then behave effectively like a pop
  auto SP = _RMWHandle(LoadGPRRegister(X86State::REG_RBP));
  auto NewGPR = Pop(OperandSize, SP);

  // Store the new stack pointer
  StoreGPRRegister(X86State::REG_RSP, SP, GPRSize);

  // Store what we loaded to RBP
  StoreGPRRegister(X86State::REG_RBP, NewGPR, OperandSize);
}

void OpDispatchBuilder::CALLOp(OpcodeArgs) {
  if (MRN32Folds) [[unlikely]] {
    if (const auto It = MRN32Folds->find(Op->PC); It != MRN32Folds->end()) {
      MRN32EmitFold(Op, It->second, false);
      return;
    }
  }
  CALLOpPlain(Op);
}

void OpDispatchBuilder::CALLOpPlain(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();

  BlockSetRIP = true;

  // Call instruction only uses up to 32-bit signed displacement
  const int64_t TargetOffset = Op->Src[0].Literal();

  const auto ConstantPC = GetRelocatedPC(Op);

  // Push the return address.
  Push(GPRSize, ConstantPC);

  if (TargetOffset != 0) {
    // Store the RIP
    const uint64_t NextRIP = Op->PC + Op->InstSize;

    MRKillFlagsBeforeCall(Op->PC); // REGION4 EXIT_SCAN
    ExitRelocatedPC(Op, TargetOffset, BranchHint::Call, ConstantPC, [&]() {
      auto CallReturnJumpTarget = JumpTargets.find(NextRIP);
      if (CallReturnJumpTarget != JumpTargets.end() && CallReturnJumpTarget->second.IsEntryPoint) {
        return CallReturnJumpTarget->second.BlockEntry;
      }
      return InvalidNode;
    }());
  } else {
    NeedsBlockEnd = true;
  }
}

void OpDispatchBuilder::CALLAbsoluteOp(OpcodeArgs) {
  if (MRN32Folds) [[unlikely]] {
    if (const auto It = MRN32Folds->find(Op->PC); It != MRN32Folds->end()) {
      MRN32EmitFold(Op, It->second, true);
      return;
    }
  }
  CALLAbsoluteOpPlain(Op);
}

void OpDispatchBuilder::CALLAbsoluteOpPlain(OpcodeArgs) {
  BlockSetRIP = true;

  if (Op->Src[0].IsLiteral()) {
    // ★ REGION4 MACRUNNER_FEX32_IMPORT_BIND: the decoder bound the slot (Decoder::MRBindImport) — a direct call, as CALLOp.
    const auto GPRSize = GetGPROpSize();
    const auto ConstantPC = GetRelocatedPC(Op);
    Push(GPRSize, ConstantPC);
    const uint64_t NextRIP = Op->PC + Op->InstSize;
    MRKillFlagsBeforeCall(Op->PC); // REGION4 EXIT_SCAN
    ExitFunction(_InlineEntrypointOffset(GPRSize, static_cast<int64_t>(Op->Src[0].Literal()) - static_cast<int64_t>(Entry)), BranchHint::Call, ConstantPC, [&]() {
      auto CallReturnJumpTarget = JumpTargets.find(NextRIP);
      if (CallReturnJumpTarget != JumpTargets.end() && CallReturnJumpTarget->second.IsEntryPoint) {
        return CallReturnJumpTarget->second.BlockEntry;
      }
      return InvalidNode;
    }());
    return;
  }

  const auto Size = OpSizeFromSrc(Op);
  Ref JMPPCOffset = LoadSourceGPR(Op, Op->Src[0], Op->Flags);

  // Push the return address.
  auto ConstantPC = GetRelocatedPC(Op);
  Push(Size, ConstantPC);

  // Store the RIP
  const uint64_t NextRIP = Op->PC + Op->InstSize;
  ExitFunction(JMPPCOffset, BranchHint::Call, ConstantPC, [&]() {
    auto CallReturnJumpTarget = JumpTargets.find(NextRIP);
    if (CallReturnJumpTarget != JumpTargets.end() && CallReturnJumpTarget->second.IsEntryPoint) {
      return CallReturnJumpTarget->second.BlockEntry;
    }
    return InvalidNode;
  }());
}

// ★ MacRunner NATIVE32 13.11.2026 (MACRUNNER_FEX32_NATIVE32, FEXCore/Utils/MacRunnerNative32.h): the call to a marked i386 Wine leaf
// becomes the leaf's architectural effect (no push of the return address, no unit exit, no return). Every path that is not the
// leaf's fast path leaves through the ORIGINAL call translation before anything is written: a slot that no longer holds the
// leaf (IAT hook), TlsGetValue with an expansion-slot index (only ecx and the flags of `cmp ecx, 64` are set then: the leaf
// body recomputes both identically). Memory accesses are the leaf's own (same address modes, same TSO class: ESP-based ones non-TSO, TEB ones
// through FS); registers and flags get the values the leaf body leaves (eax / ecx; flags of `cmp ecx, 64` for TlsGetValue).
void OpDispatchBuilder::MRN32EmitFold(OpcodeArgs, const FEXCore::Utils::MRN32Fold& Fold, bool Absolute) {
  // A call is normally the last instruction of its block, where the pending lazy FIP is stored; the side exits below need it.
  LazyFIPFlush();

  // ONE slow block per fold, whatever the number of side exits, laid out RIGHT BEFORE the call's return block: the JIT binds a
  // call's return landing at the start of the block emitted next after the call (JIT.cpp PendingCallReturnTargetLabel), so a
  // slow block at the end of the unit, or a second call site, got no landing -- caught 13.11 on TlsGetValue with an expansion
  // index (ILLEGAL_INSTRUCTION on the return). Layout: [guard] [fast ...] [slow: original call] [return block]; the fast path
  // reaches the return block with one `b` over the slow block, the slow call returns by falling through into it.
  Ref SlowBlock = nullptr;
  const auto SideExit = [&](auto&& EmitBranch) {
    auto CurrentBlock = GetCurrentBlock();
    auto CJ = EmitBranch();
    if (!SlowBlock) {
      SlowBlock = CreateNewCodeBlockAfter(CurrentBlock);
      SetCurrentCodeBlock(SlowBlock);
      StartNewBlock();
      if (Absolute) {
        CALLAbsoluteOpPlain(Op);
      } else {
        CALLOpPlain(Op);
      }
    }
    SetTrueJumpTarget(CJ, SlowBlock);
    auto FastBlock = CreateNewCodeBlockAfter(CurrentBlock);
    SetFalseJumpTarget(CJ, FastBlock);
    SetCurrentCodeBlock(FastBlock);
    StartNewBlock();
    BlockSetRIP = false;
    NeedsBlockEnd = false;
  };

  // NATIVE32-0005: the guard the decoder chose (MacRunnerNative32.h, MRN32Guard). None: `call rel32`, or a slot that is a constant
  // of this translation (read-only image page, REGION4 const-data page of the unit) -- nothing is checked at run time.
  switch (Fold.Guard) {
  case FEXCore::Utils::MRN32Guard::Slot: {
    // Writable slot: the slot load is the call's own operand load (same fault, same address); it must still hold the leaf.
    // (A non-NZCV CondJump compares with zero only -- cbz / cbnz: the difference is what is tested.)
    Ref SlotValue = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    Ref Differs = Sub(OpSize::i32Bit, SlotValue, Fold.Target);
    SideExit([&] { return CondJump(Differs, CondClass::NEQ); });
    break;
  }
  case FEXCore::Utils::MRN32Guard::Eax: {
    // `call eax` speculated on the leaf: any other value takes the original indirect call, before anything is written.
    Ref Differs = Sub(OpSize::i32Bit, LoadGPRRegister(X86State::REG_RAX), Fold.Target);
    SideExit([&] { return CondJump(Differs, CondClass::NEQ); });
    break;
  }
  case FEXCore::Utils::MRN32Guard::None: break;
  }

  // No push / pop of the return address: the slot below ESP is dead by the x86 Windows ABI (exception and APC dispatch write
  // below ESP at any time), and storing it cost 4 of the fold's ~16 host instructions (mov/movk/sub/str, measured 13.11).
  // Consequence, by construction and named: after a folded call [esp - 4] keeps what it held; on an unusable stack the
  // folded SetLastError / TlsGetValue fault reading the argument at [esp] (the call would fault writing [esp - 4]), at the
  // call instruction with the registers before it; a folded GetLastError touches no stack at all.

  const auto TEB = [&](int64_t Offset) {
    AddressMode A {};
    A.Segment = GetSegment(X86Tables::DecodeFlags::FLAG_FS_PREFIX);
    A.Offset = Offset;
    A.AddrSize = OpSize::i32Bit;
    A.NonTSO = false;
    return A;
  };
  // NATIVE32-0005: the TEB through an FS base loaded ONCE per IR block (TEB(...) loads it per access; dump 13.11: two loads in a row).
  const auto TEBAt = [&](Ref FsBase, int64_t Offset) {
    AddressMode A {};
    A.Base = FsBase;
    A.Offset = Offset;
    A.AddrSize = OpSize::i32Bit;
    A.NonTSO = false;
    return A;
  };
  const auto StackTop = [&] {
    AddressMode A {};
    A.Base = LoadGPRRegister(X86State::REG_RSP);
    A.AddrSize = OpSize::i32Bit;
    A.NonTSO = true;   // ESP-based, as the leaf's `movl 4(%esp), r`
    return A;
  };

  switch (Fold.Id) {
  case 1: { // GetLastError: movl %fs:0x34, %eax
    StoreGPRRegister(X86State::REG_RAX, _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEB(0x34), OpSize::i32Bit));
    break;
  }
  case 2: { // SetLastError: movl 4(%esp), %eax; movl %eax, %fs:0x34; (ret $4)
    Ref Value = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, StackTop(), OpSize::i32Bit);
    StoreGPRRegister(X86State::REG_RAX, Value);
    _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEB(0x34), Value, OpSize::i32Bit);
    StoreGPRRegister(X86State::REG_RSP, Add(OpSize::i32Bit, LoadGPRRegister(X86State::REG_RSP), 4));
    break;
  }
  case 3: { // TlsGetValue: movl 4(%esp), %ecx; cmpl $64, %ecx; jae <kernelbase>; movl $0, %fs:0x34; movl %fs:0xe10(,%ecx,4), %eax; (ret $4)
    Ref Index = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, StackTop(), OpSize::i32Bit);
    StoreGPRRegister(X86State::REG_RCX, Index);
    CalculateFlags_SUB(OpSize::i32Bit, Index, Constant(64));
    CalculateDeferredFlags();
    SideExit([&] {
      FlushRegisterCache();
      const auto Cond = DecodeNZCVCondition(0x3); // JAE / JNC
      return CondJumpNZCV(*Cond);
    });
    {
      // NATIVE32-0005: one FS base for both TEB accesses; the slot address as one add-with-shift (32-bit, as the leaf's address).
      Ref Fs = GetSegment(X86Tables::DecodeFlags::FLAG_FS_PREFIX);
      _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEBAt(Fs, 0x34), Constant(0), OpSize::i32Bit);
      Ref SlotBase = _AddShift(OpSize::i32Bit, Fs, LoadGPRRegister(X86State::REG_RCX), ShiftType::LSL, 2);
      StoreGPRRegister(X86State::REG_RAX, _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEBAt(SlotBase, 0xe10), OpSize::i32Bit));
    }
    StoreGPRRegister(X86State::REG_RSP, Add(OpSize::i32Bit, LoadGPRRegister(X86State::REG_RSP), 4));
    break;
  }
  case 4: { // FlsGetValue: movl 4(%esp), %ecx; movl %fs:0xfb4, %edx; leal -1(%ecx), %eax; cmpl $15, %eax; jae <kernelbase>;
            //              testl %edx, %edx; je <kernelbase>; movl 8(%edx), %eax; testl %eax, %eax; je 1f; movl 4(%eax,%ecx,4), %eax;
            //           1: movl $0, %fs:0x34; (ret $4)                                                              (NATIVE32-0005)
    // eax is written only after the last side exit: the original call (for `call eax`: THROUGH eax) must see it unchanged. ecx and
    // edx are written before (the leaf body -- the only callee once a guard passed -- writes them again identically), and are the
    // carriers across the side exits: an IR value does not live across blocks here (the TlsGetValue fold reloads ecx the same way;
    // caught 13.11: a value carried across a side exit read garbage -- ecx = 0x1f2000, every chain call wrong, probe n32fold2).
    // The chunk test of the leaf (`testl %eax, %eax; je 1f`) is a select, not an exit: chunk 0 -> eax 0, and the value load reads the
    // chunk slot itself (readable, no effect) instead of [4 + 4 * index].
    {
      Ref Index = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, StackTop(), OpSize::i32Bit);
      StoreGPRRegister(X86State::REG_RCX, Index);
      StoreGPRRegister(X86State::REG_RDX, _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEB(0xfb4), OpSize::i32Bit));
      CalculateFlags_SUB(OpSize::i32Bit, Sub(OpSize::i32Bit, Index, 1), Constant(15));
      CalculateDeferredFlags();
      SideExit([&] {
        const auto Cond = DecodeNZCVCondition(0x3); // JAE / JNC
        return CondJumpNZCV(*Cond);
      });
    }
    SideExit([&] { return CondJump(LoadGPRRegister(X86State::REG_RDX), CondClass::EQ); });
    {
      // The leaf's final flags are those of `testl %eax, %eax` on the chunk: set them FIRST and let both selects read that one
      // compare (dump 13.11: three compares with zero and a three-add address select before). Chunk 0: the value load reads the
      // TEB itself (TEB + 4 + 4 * index, index 1..15: inside the TEB, readable, no effect) and eax gets 0, as the leaf's `je 1f`.
      Ref Fls = LoadGPRRegister(X86State::REG_RDX);
      AddressMode ChunkA {};
      ChunkA.Base = Fls;
      ChunkA.Offset = 8;
      ChunkA.AddrSize = OpSize::i32Bit;
      ChunkA.NonTSO = false;
      Ref Chunk = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, ChunkA, OpSize::i32Bit);
      CalculateFlags_Logical(OpSize::i32Bit, Chunk);
      Ref Fs = GetSegment(X86Tables::DecodeFlags::FLAG_FS_PREFIX);
      Ref Base = NZCVSelect(OpSize::i32Bit, CondClass::NEQ, Chunk, Fs);
      Ref ValueBase = _AddShift(OpSize::i32Bit, Base, LoadGPRRegister(X86State::REG_RCX), ShiftType::LSL, 2);
      Ref Loaded = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEBAt(ValueBase, 4), OpSize::i32Bit);
      Ref Value = NZCVSelect(OpSize::i32Bit, CondClass::NEQ, Loaded, Constant(0));
      _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEBAt(Fs, 0x34), Constant(0), OpSize::i32Bit);
      StoreGPRRegister(X86State::REG_RAX, Value);
    }
    StoreGPRRegister(X86State::REG_RSP, Add(OpSize::i32Bit, LoadGPRRegister(X86State::REG_RSP), 4));
    break;
  }
  case 5:   // RtlEnterCriticalSection (NATIVE32-0007)
  case 6: { // RtlLeaveCriticalSection
    // Flags: the inline paths end with `xorl %eax, %eax` (ZF PF set, CF OF SF clear, AF undefined), so the cmp / inc / dec flags
    // before it are dead there and are not computed: the branches are flag-free compares. At a continuation label (a `jmp` into a C
    // function, which reads no flags) the arithmetic flags are dead by the C ABI and are left as they were (named consequence: at
    // that one instruction a context read shows the caller's flags, not those of the cmpl / decl).
    // The block the fast path ends in (the dispatcher closes it with the jump to the return block), the return block itself
    // (other paths jump there / name it as their call's return), and the post-lock continuation in the leaf.
    const uint64_t NextRIP = Op->PC + Op->InstSize;
    const auto RetIt = JumpTargets.find(NextRIP);
    LOGMAN_THROW_A_FMT(RetIt != JumpTargets.end() && RetIt->second.IsEntryPoint, "NATIVE32: fold without a return block");
    const Ref RetBlock = RetIt->second.BlockEntry;
    const uint64_t Mid = Fold.Target + FEXCore::Utils::MRN32LeafMidExit(Fold.Id);
    const auto GPRSize = GetGPROpSize();
    // xorl %eax, %eax exactly as ALUOp emits the zero idiom (flags: zero result, AF undefined, carry inverted).
    const auto XorEaxEax = [&] {
      Ref Zero = LoadGPRRegister(X86State::REG_RAX);
      HandleNZ00Write();
      InvalidateAF();
      CalculatePF(SubWithFlags(OpSize::i32Bit, Zero, Zero));
      CFInverted = true;
      FlushRegisterCache();
      StoreGPRRegister(X86State::REG_RAX, Constant(0));
    };
    const auto RetPop = [&] { StoreGPRRegister(X86State::REG_RSP, Add(OpSize::i32Bit, LoadGPRRegister(X86State::REG_RSP), 4)); };
    const auto Field = [&](Ref Base, int64_t Offset) {
      AddressMode A {};
      A.Base = Base;
      A.Offset = Offset;
      A.AddrSize = OpSize::i32Bit;
      A.NonTSO = false;
      return A;
    };
    // A call-like exit into the leaf at its continuation label: return address pushed (as the call did), call-return entry for the
    // return block (its landing jumps there: JIT PendingCallReturnTargetLabel -- this block is never the last of the unit).
    const auto MidExit = [&] {
      const auto ConstantPC = GetRelocatedPC(Op);
      Push(GPRSize, ConstantPC);
      ExitFunction(_InlineEntrypointOffset(GPRSize, static_cast<int64_t>(Mid) - static_cast<int64_t>(Entry)), BranchHint::Call, ConstantPC, RetBlock);
    };
    // Two-way branch inside the fold: returns {taken block, fall block}, both new, laid out after the current one (before the slow
    // block, which stays right before the return block).
    const auto Branch = [&](auto&& EmitBranch) {
      auto Cur = GetCurrentBlock();
      auto CJ = EmitBranch();
      Ref Taken = CreateNewCodeBlockAfter(Cur);
      Ref Fall = CreateNewCodeBlockAfter(Cur);
      SetTrueJumpTarget(CJ, Taken);
      SetFalseJumpTarget(CJ, Fall);
      return std::pair {Taken, Fall};
    };
    const auto Enter = [&](Ref Block) {
      SetCurrentCodeBlock(Block);
      StartNewBlock();
    };

    {
      Ref Crit = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, StackTop(), OpSize::i32Bit);
      StoreGPRRegister(X86State::REG_RCX, Crit);
      if (Fold.Id == 5) {
        // cmpl $0, 0x14(%ecx); jne slow -- before anything is written: the original call.
        Ref Spin = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(Crit, 0x14), OpSize::i32Bit);
        SideExit([&] { return CondJump(Spin, CondClass::NEQ); });
      } else {
        // cmpl $1, 8(%ecx); jne slow -- the original call; the flags of the cmp are dead on every path that goes on (see below).
        Ref Rec = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(Crit, 8), OpSize::i32Bit);
        SideExit([&] { return CondJump(Sub(OpSize::i32Bit, Rec, 1), CondClass::NEQ); });
      }
    }

    if (Fold.Id == 5) {
      // movl %fs:0x24, %edx; lock incl 4(%ecx); jne held
      Ref Crit = LoadGPRRegister(X86State::REG_RCX);
      Ref Tid = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, TEB(0x24), OpSize::i32Bit);
      StoreGPRRegister(X86State::REG_RDX, Tid);
      Ref Old = _AtomicFetchAdd(OpSize::i32Bit, Constant(1), Add(OpSize::i32Bit, Crit, 4));
      // The flags of the `incl` are overwritten on every path that goes on (cmpl / xorl): only ZF decides, as a value.
      auto [Held, Free] = Branch([&] { return CondJump(Add(OpSize::i32Bit, Old, 1), CondClass::NEQ); });

      // held: cmpl %edx, 0xc(%ecx); jne contended; incl 8(%ecx); xorl %eax, %eax; ret $4
      Enter(Held);
      Ref Owner = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(LoadGPRRegister(X86State::REG_RCX), 0xc), OpSize::i32Bit);
      auto [Contended, Recursive] = Branch([&] { return CondJump(Sub(OpSize::i32Bit, Owner, LoadGPRRegister(X86State::REG_RDX)), CondClass::NEQ); });
      Enter(Recursive);
      {
        Ref C = LoadGPRRegister(X86State::REG_RCX);
        Ref Count = _LoadMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(C, 8), OpSize::i32Bit);
        _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(C, 8), Add(OpSize::i32Bit, Count, 1), OpSize::i32Bit);
        XorEaxEax();
        RetPop();
        Jump(RetBlock);
      }
      Enter(Contended);
      MidExit();   // jmp native32_enter_cs_contended (flags of the cmpl, ecx / edx set, LockCount incremented)

      // free: movl %edx, 0xc(%ecx); movl $1, 8(%ecx); xorl %eax, %eax; ret $4 -- the dispatcher jumps to the return block
      Enter(Free);
      Ref C = LoadGPRRegister(X86State::REG_RCX);
      _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(C, 0xc), LoadGPRRegister(X86State::REG_RDX), OpSize::i32Bit);
      _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(C, 8), Constant(1), OpSize::i32Bit);
      XorEaxEax();
      RetPop();
    } else {
      // movl $0, 8(%ecx); movl $0, 0xc(%ecx); lock decl 4(%ecx); jns wake; xorl %eax, %eax; ret $4
      Ref Crit = LoadGPRRegister(X86State::REG_RCX);
      _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(Crit, 8), Constant(0), OpSize::i32Bit);
      _StoreMemAutoTSO(RegClass::GPR, OpSize::i32Bit, Field(Crit, 0xc), Constant(0), OpSize::i32Bit);
      Ref Old = _AtomicFetchAdd(OpSize::i32Bit, Constant(0xFFFFFFFFULL), Add(OpSize::i32Bit, Crit, 4));
      // jns: the decremented count is not negative -> someone waits (bit 31 of the new value clear)
      auto [Wake, Free] = Branch([&] { return CondJumpBit(Sub(OpSize::i32Bit, Old, 1), 31, false); });
      Enter(Wake);
      MidExit();   // jmp native32_leave_cs_wake (flags of the decl, ecx set, the section released)
      Enter(Free);
      XorEaxEax();
      RetPop();
    }
    BlockSetRIP = false;
    NeedsBlockEnd = false;
    break;
  }
  default: LOGMAN_MSG_A_FMT("NATIVE32: unknown leaf id {}", Fold.Id); break;
  }

  const uint64_t N = FEXCore::Utils::MRN32FoldCount.fetch_add(1, std::memory_order_relaxed) + 1;
  FEXCore::Utils::MRN32FoldsById[Fold.Id < 7 ? Fold.Id : 0].fetch_add(1, std::memory_order_relaxed);
  FEXCore::Utils::MRN32FoldsByGuard[static_cast<unsigned>(Fold.Guard) % 3].fetch_add(1, std::memory_order_relaxed);
  if ((N & (N - 1)) == 0) {
    char Line[400];
    const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
                                         "macrunner-fex32-native32: folds={} getlasterror={} setlasterror={} tlsgetvalue={} flsgetvalue={} entercs={} leavecs={} refused={} slot_unreadable={} "
                                         "guard_none={} guard_slot={} guard_eax={} fls_hint={:#x} mask={:#x}\n",
                                         N, FEXCore::Utils::MRN32FoldsById[1].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsById[2].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsById[3].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsById[4].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsById[5].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsById[6].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32Refused.load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32SlotUnreadable.load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsByGuard[0].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsByGuard[1].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FoldsByGuard[2].load(std::memory_order_relaxed),
                                         FEXCore::Utils::MRN32FlsHint.load(std::memory_order_relaxed),
                                         FEXCore::Utils::MacRunnerNative32Mask());
    Line[Result.size < sizeof(Line) ? Result.size : sizeof(Line) - 1] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
}

std::optional<CondClass> OpDispatchBuilder::DecodeNZCVCondition(uint8_t OP) {
  switch (OP) {
  case 0x0: { // JO - Jump if OF == 1
    return CondClass::FU;
  }
  case 0x1: { // JNO - Jump if OF == 0
    return CondClass::FNU;
  }
  case 0x2: { // JC - Jump if CF == 1
    return CFInverted ? CondClass::ULT : CondClass::UGE;
  }
  case 0x3: { // JNC - Jump if CF == 0
    return CFInverted ? CondClass::UGE : CondClass::ULT;
  }
  case 0x4: { // JE - Jump if ZF == 1
    return CondClass::EQ;
  }
  case 0x5: { // JNE - Jump if ZF == 0
    return CondClass::NEQ;
  }
  case 0x6: { // JNA - Jump if CF == 1 || ZF == 1
    // With CF, we want (C == 0 || Z == 1). By De Morgan's, that's
    // equivalent to !(C == 1 && Z == 0). That's .ls
    RectifyCarryInvert(true);
    return CondClass::ULE;
  }
  case 0x7: { // JA - Jump if CF == 0 && ZF == 0
    // With CF inverted, we want (C == 1 && Z == 0). That's .hi
    RectifyCarryInvert(true);
    return CondClass::UGT;
  }
  case 0x8: { // JS - Jump if SF == 1
    return CondClass::MI;
  }
  case 0x9: { // JNS - Jump if SF == 0
    return CondClass::PL;
  }
  case 0xC: { // SF <> OF
    return CondClass::SLT;
  }
  case 0xD: { // SF = OF
    return CondClass::SGE;
  }
  case 0xE: { // ZF = 1 || SF <> OF
    return CondClass::SLE;
  }
  case 0xF: { // ZF = 0 && SF = OF
    return CondClass::SGT;
  }
  default:
    // Other conditions do not map directly, caller gets to deal with it.
    return std::nullopt;
  }
}

static bool ParityJumpIsJP(uint8_t OP) {
  LOGMAN_THROW_A_FMT(OP == 0xA || OP == 0xB, "JP or JNP");
  return OP == 0xA;
}

Ref OpDispatchBuilder::SelectCC0All1(uint8_t OP) {
  if (auto Cond = DecodeNZCVCondition(OP); Cond) {
    // Use raw select since DecodeNZCVCondition handles the carry invert
    return _NZCVSelect(OpSize::i64Bit, *Cond, _InlineConstant(~0ULL), _InlineConstant(0));
  } else {
    // Raw value contains inverted PF in bottom bit
    return _Sbfe(OpSize::i64Bit, 1, 0, LoadPFRaw(false, ParityJumpIsJP(OP)));
  }
}

void OpDispatchBuilder::SETccOp(OpcodeArgs) {
  CalculateDeferredFlags();

  Ref SrcCond;
  if (auto Cond = DecodeNZCVCondition(Op->OP & 0xf); Cond) {
    // Use raw select since DecodeNZCVCondition handles the carry invert
    SrcCond = _NZCVSelect01(*Cond);
  } else {
    SrcCond = LoadPFRaw(true, ParityJumpIsJP(Op->OP & 0xf));
  }

  StoreResultGPR(Op, SrcCond);
}

void OpDispatchBuilder::CMOVOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  const auto OP = Op->OP & 0xF;
  const auto ResultSize = std::max(OpSize::i32Bit, OpSizeFromSrc(Op));

  CalculateDeferredFlags();

  // Destination is always a GPR.
  Ref Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, GPRSize, Op->Flags);
  Ref Src {}, SrcCond {};
  if (Op->Src[0].IsGPR()) {
    Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], GPRSize, Op->Flags);
  } else {
    Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
  }

  if (auto Cond = DecodeNZCVCondition(OP); Cond) {
    // Use raw select since DecodeNZCVCondition handles the carry invert
    SrcCond = _NZCVSelect(ResultSize, *Cond, Src, Dest);
  } else {
    // Raw value contains inverted PF in bottom bit
    Ref Cmp = LoadPFRaw(false, ParityJumpIsJP(OP));
    SaveNZCV();

    // Because we're only clobbering NZCV internally, we ignore all carry flag
    // shenanigans and just use the raw test and raw select.
    _TestNZ(OpSize::i32Bit, Cmp, _InlineConstant(1));
    SrcCond = _NZCVSelect(ResultSize, CondClass::NEQ, Src, Dest);
  }

  StoreResultGPR(Op, SrcCond);
}

void OpDispatchBuilder::CondJUMPOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  BlockSetRIP = true;

  // Jump instruction only uses up to 32-bit signed displacement
  int64_t TargetOffset = Op->Src[0].Literal();
  uint64_t InstRIP = Op->PC + Op->InstSize;
  uint64_t Target = InstRIP + TargetOffset;

  if (GetGPROpSize() == OpSize::i32Bit) {
    // If the GPRSize is 4 then we need to be careful about PC wrapping
    if (TargetOffset < 0 && -TargetOffset > InstRIP) {
      // Invert the signed value if we are underflowing
      TargetOffset = 0x1'0000'0000ULL + TargetOffset;
    } else if (TargetOffset >= 0 && Target >= 0x1'0000'0000ULL) {
      // We are overflowing, wrap around
      TargetOffset = TargetOffset - 0x1'0000'0000ULL;
    }
    Target &= 0xFFFFFFFFU;
  }

  FlushRegisterCache();
  auto TrueBlock = JumpTargets.find(Target);
  auto FalseBlock = JumpTargets.find(Op->PC + Op->InstSize);

  auto CurrentBlock = GetCurrentBlock();

  {
    IRPair<IR::IROp_CondJump> CondJump_;
    auto OP = Op->OP & 0xF;
    auto Cond = DecodeNZCVCondition(OP);
    if (Cond) {
      CondJump_ = CondJumpNZCV(*Cond);
    } else {
      LOGMAN_THROW_A_FMT(OP == 0xA || OP == 0xB, "only PF left");
      CondJump_ = CondJumpBit(LoadPFRaw(false, false), 0, OP == 0xB);
    }

    // Taking branch block
    if (TrueBlock != JumpTargets.end() && !(WritableLoopCacheExit && Target <= Op->PC)) {
      SetTrueJumpTarget(CondJump_, TrueBlock->second.BlockEntry);
    } else {
      // Make sure to start a new block after ending this one
      auto JumpTarget = CreateNewCodeBlockAtEnd();
      SetTrueJumpTarget(CondJump_, JumpTarget);
      SetCurrentCodeBlock(JumpTarget);
      StartNewBlock();

      // Store the new RIP
      ExitRelocatedPC(Op, TargetOffset);
    }

    // Failure to take branch
    if (FalseBlock != JumpTargets.end()) {
      SetFalseJumpTarget(CondJump_, FalseBlock->second.BlockEntry);
    } else {
      // Make sure to start a new block after ending this one
      // Place it after this block for fallthrough optimization
      auto JumpTarget = CreateNewCodeBlockAfter(CurrentBlock);
      SetFalseJumpTarget(CondJump_, JumpTarget);
      SetCurrentCodeBlock(JumpTarget);
      StartNewBlock();

      // Leave block & store the new RIP
      ExitRelocatedPC(Op);
    }
  }
}

void OpDispatchBuilder::CondJUMPRCXOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  BlockSetRIP = true;
  auto JcxGPRSize = GetGPROpSize();
  JcxGPRSize = (Op->Flags & X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE) ? (JcxGPRSize >> 1) : JcxGPRSize;

  uint64_t Target = Op->PC + Op->InstSize + Op->Src[0].Literal();

  Ref CondReg = LoadGPRRegister(X86State::REG_RCX, JcxGPRSize);

  auto TrueBlock = JumpTargets.find(Target);
  auto FalseBlock = JumpTargets.find(Op->PC + Op->InstSize);

  auto CurrentBlock = GetCurrentBlock();

  {
    auto CondJump_ = CondJump(CondReg, CondClass::EQ);

    // Taking branch block
    if (TrueBlock != JumpTargets.end() && !(WritableLoopCacheExit && Target <= Op->PC)) {
      SetTrueJumpTarget(CondJump_, TrueBlock->second.BlockEntry);
    } else {
      // Make sure to start a new block after ending this one
      auto JumpTarget = CreateNewCodeBlockAtEnd();
      SetTrueJumpTarget(CondJump_, JumpTarget);
      SetCurrentCodeBlock(JumpTarget);
      StartNewBlock();

      // Store the new RIP
      ExitRelocatedPC(Op, Op->Src[0].Literal());
    }

    // Failure to take branch
    if (FalseBlock != JumpTargets.end()) {
      SetFalseJumpTarget(CondJump_, FalseBlock->second.BlockEntry);
    } else {
      // Make sure to start a new block after ending this one
      // Place it after the current block for fallthrough behavior
      auto JumpTarget = CreateNewCodeBlockAfter(CurrentBlock);
      SetFalseJumpTarget(CondJump_, JumpTarget);
      SetCurrentCodeBlock(JumpTarget);
      StartNewBlock();

      // Leave block & store the new RIP
      ExitRelocatedPC(Op);
    }
  }
}

void OpDispatchBuilder::LoopOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  bool CheckZF = Op->OP != 0xE2;
  bool ZFTrue = Op->OP == 0xE1;

  BlockSetRIP = true;
  auto SrcSize = (Op->Flags & X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE) ? OpSize::i32Bit : OpSize::i64Bit;
  auto OpSize = SrcSize == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit;

  if (!Is64BitMode) {
    // RCX size is 32-bit or 16-bit when executing in 32-bit mode.
    SrcSize = IR::SizeToOpSize(IR::OpSizeToSize(SrcSize) >> 1);
    OpSize = OpSize::i32Bit;
  }

  uint64_t Target = Op->PC + Op->InstSize + Op->Src[1].Literal();

  Ref CondReg = LoadSourceGPR_WithOpSize(Op, Op->Src[0], SrcSize, Op->Flags);
  CondReg = Sub(OpSize, CondReg, 1);
  StoreResultGPR(Op, Op->Src[0], CondReg);

  // If LOOPE then jumps to target if RCX != 0 && ZF == 1
  // If LOOPNE then jumps to target if RCX != 0 && ZF == 0
  //
  // To handle efficiently, smash RCX to zero if ZF is wrong (1 csel).
  if (CheckZF) {
    const auto cond = ZFTrue ? CondClass::EQ : CondClass::NEQ;
    CondReg = NZCVSelect(OpSize, cond, CondReg, _InlineConstant(0));
  }

  CalculateDeferredFlags();
  auto TrueBlock = JumpTargets.find(Target);
  auto FalseBlock = JumpTargets.find(Op->PC + Op->InstSize);

  {
    auto CondJump_ = CondJump(CondReg);

    // Taking branch block
    if (TrueBlock != JumpTargets.end() && !(WritableLoopCacheExit && Target <= Op->PC)) {
      SetTrueJumpTarget(CondJump_, TrueBlock->second.BlockEntry);
    } else {
      // Make sure to start a new block after ending this one
      auto JumpTarget = CreateNewCodeBlockAtEnd();
      SetTrueJumpTarget(CondJump_, JumpTarget);
      SetCurrentCodeBlock(JumpTarget);
      StartNewBlock();

      // Store the new RIP
      ExitRelocatedPC(Op, Op->Src[1].Literal());
    }

    // Failure to take branch
    if (FalseBlock != JumpTargets.end()) {
      SetFalseJumpTarget(CondJump_, FalseBlock->second.BlockEntry);
    } else {
      // Make sure to start a new block after ending this one
      // Place after this block for fallthrough behavior
      auto JumpTarget = CreateNewCodeBlockAfter(GetCurrentBlock());
      SetFalseJumpTarget(CondJump_, JumpTarget);
      SetCurrentCodeBlock(JumpTarget);
      StartNewBlock();

      // Leave block & store the new RIP
      ExitRelocatedPC(Op);
    }
  }
}

void OpDispatchBuilder::JUMPOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  BlockSetRIP = true;

  // Jump instruction only uses up to 32-bit signed displacement
  int64_t TargetOffset = Op->Src[0].Literal();
  uint64_t InstRIP = Op->PC + Op->InstSize;
  uint64_t TargetRIP = InstRIP + TargetOffset;

  if (GetGPROpSize() == OpSize::i32Bit) {
    // If the GPRSize is 4 then we need to be careful about PC wrapping
    if (TargetOffset < 0 && -TargetOffset > InstRIP) {
      // Invert the signed value if we are underflowing
      TargetOffset = 0x1'0000'0000ULL + TargetOffset;
    } else if (TargetOffset >= 0 && TargetRIP >= 0x1'0000'0000ULL) {
      // We are overflowing, wrap around
      TargetOffset = TargetOffset - 0x1'0000'0000ULL;
    }

    TargetRIP &= 0xFFFFFFFFU;
  }

  CalculateDeferredFlags();
  // This is just an unconditional relative literal jump
  if (Multiblock) {
    auto JumpBlock = JumpTargets.find(TargetRIP);
    if (JumpBlock != JumpTargets.end() && !(WritableLoopCacheExit && TargetRIP <= Op->PC)) {
      Jump(GetNewJumpBlock(TargetRIP));
    } else {
      // If the block isn't a jump target then we need to create an exit block
      auto Jump_ = Jump();

      // Place after this block for fallthrough behavior
      auto JumpTarget = CreateNewCodeBlockAfter(GetCurrentBlock());
      SetJumpTarget(Jump_, JumpTarget);
      SetCurrentCodeBlock(JumpTarget);
      StartNewBlock();
      ExitRelocatedPC(Op, TargetOffset);
    }
  } else {
    ExitRelocatedPC(Op, TargetOffset);
  }
}

void OpDispatchBuilder::JUMPAbsoluteOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  BlockSetRIP = true;
  // This is just an unconditional jump
  // This uses ModRM to determine its location
  // No way to use this effectively in multiblock
  if (Op->Src[0].IsLiteral()) {
    // ★ REGION4 MACRUNNER_FEX32_IMPORT_BIND: bound slot (Decoder::MRBindImport) — a direct jump out of the unit.
    ExitFunction(_InlineEntrypointOffset(GetGPROpSize(), static_cast<int64_t>(Op->Src[0].Literal()) - static_cast<int64_t>(Entry)));
    return;
  }
  auto RIPOffset = LoadSourceGPR(Op, Op->Src[0], Op->Flags);

  // Store the new RIP
  ExitFunction(RIPOffset);
}

void OpDispatchBuilder::JUMPFARIndirectOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  BlockSetRIP = true;
  // This is just an unconditional jump
  // This uses ModRM to determine its location
  // No way to use this effectively in multiblock
  Ref Src = MakeSegmentAddress(Op, Op->Dest);
  AddressMode SrcCS = {.Base = Src, .Offset = 4, .AddrSize = OpSize::i64Bit};
  auto RIPOffset = _LoadMemGPRAutoTSO(OpSize::i32Bit, Src, OpSize::i8Bit);
  auto NewSegmentCS = _LoadMemGPRAutoTSO(OpSize::i16Bit, SrcCS, OpSize::i8Bit);

  // Set up the new CSSegment.
  _StoreContextGPR(OpSize::i16Bit, NewSegmentCS, offsetof(FEXCore::Core::CPUState, cs_idx));
  UpdatePrefixFromSegment(NewSegmentCS, FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX);

  // Store the new RIP
  ExitFunction(RIPOffset);
}

void OpDispatchBuilder::CALLFARIndirectOp(OpcodeArgs) {
  const auto SrcSize = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REX_WIDENING ? OpSize::i64Bit : OpSize::i32Bit;

  // Calculate flags early.
  CalculateDeferredFlags();

  BlockSetRIP = true;

  Ref Src = MakeSegmentAddress(Op, Op->Dest);
  AddressMode SrcCS = {.Base = Src, .Offset = 4, .AddrSize = OpSize::i64Bit};
  auto RIPOffset = _LoadMemGPRAutoTSO(OpSize::i32Bit, Src, OpSize::i8Bit);
  auto NewSegmentCS = _LoadMemGPRAutoTSO(OpSize::i16Bit, SrcCS, OpSize::i8Bit);
  auto CurrentCS = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, cs_idx));

  auto NewRIP = GetRelocatedPC(Op);

  // Push the current CS
  Push(SrcSize, CurrentCS);

  // Push the return address.
  Push(SrcSize, NewRIP);

  // Set up the new CSSegment.
  _StoreContextGPR(OpSize::i16Bit, NewSegmentCS, offsetof(FEXCore::Core::CPUState, cs_idx));
  UpdatePrefixFromSegment(NewSegmentCS, FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX);

  // Store the new RIP
  ExitFunction(RIPOffset);
}

void OpDispatchBuilder::RETFARIndirectOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  const auto SrcSize = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REX_WIDENING ? OpSize::i64Bit : OpSize::i32Bit;

  Ref SP = _RMWHandle(LoadGPRRegister(X86State::REG_RSP));
  Ref NewRIP = Pop(SrcSize, SP);
  Ref NewSegmentCS = Pop(SrcSize, SP);

  // Optional SP offset.
  if (Op->Src[0].IsLiteral()) {
    SP = Add(GPRSize, SP, Op->Src[0].Literal());
  }

  // Store the new stack pointer
  StoreGPRRegister(X86State::REG_RSP, SP);

  _StoreContextGPR(OpSize::i16Bit, NewSegmentCS, offsetof(FEXCore::Core::CPUState, cs_idx));
  UpdatePrefixFromSegment(NewSegmentCS, FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX);

  // Store the new RIP
  ExitFunction(NewRIP);
  BlockSetRIP = true;
}

void OpDispatchBuilder::TESTOp(OpcodeArgs, uint32_t SrcIndex) {
  // TEST is an instruction that does an AND between the sources
  // Result isn't stored in result, only writes to flags
  Ref Src = LoadSourceGPR(Op, Op->Src[SrcIndex], Op->Flags, {.AllowUpperGarbage = true});
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});

  const auto Size = OpSizeFromDst(Op);
  LOGMAN_THROW_A_FMT(Size >= IR::OpSize::i8Bit && Size <= IR::OpSize::i64Bit, "Invalid size");

  uint64_t Const;
  bool AlwaysNonnegative = false;
  if (IsValueConstant(WrapNode(Src), &Const)) {
    // Optimize out masking constants
    if (Const == (Size == OpSize::i64Bit ? ~0ULL : ((1ull << IR::OpSizeAsBits(Size)) - 1))) {
      Src = Dest;
    }

    // Optimize test with non-sign bits
    AlwaysNonnegative = (Const & (1ull << (IR::OpSizeAsBits(Size) - 1))) == 0;
  }

  if (Dest == Src) {
    // Optimize out the AND.
    SetNZP_ZeroCV(Size, Src);
  } else if (Size < OpSize::i32Bit && AlwaysNonnegative) {
    // If we know the result is always nonnegative, we can use a 32-bit test.
    auto Res = _And(OpSize::i32Bit, Dest, Src);
    CalculatePF(Res);
    SetNZ_ZeroCV(OpSize::i32Bit, Res);
  } else {
    HandleNZ00Write();
    CalculatePF(_AndWithFlags(Size, Dest, Src));
  }

  InvalidateAF();
}

void OpDispatchBuilder::ARPLOp(OpcodeArgs) {
  // ARPL r/m16, r16
  // If the RPL field in the destination selector is less privileged than the
  // RPL field in the source selector, then adjust destination RPL to match
  // source RPL and set ZF=1. Otherwise ZF=0 and destination is unchanged.
  //
  // Only ZF is modified by ARPL.
  constexpr auto Size = OpSize::i16Bit;

  Ref Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, Size, Op->Flags, {.AllowUpperGarbage = true});
  Ref Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], Size, Op->Flags, {.AllowUpperGarbage = true});

  // RPL is the low two bits of the selector.
  Ref DestRPL = _Bfe(OpSize::i32Bit, 2, 0, Dest);
  Ref SrcRPL = _Bfe(OpSize::i32Bit, 2, 0, Src);

  // NeedUpdate is 1 when DestRPL < SrcRPL, else 0.
  Ref NeedUpdate = _Select(OpSize::i32Bit, OpSize::i32Bit, CondClass::ULT, DestRPL, SrcRPL, Constant(1), Constant(0));
  SetRFLAG<FEXCore::X86State::RFLAG_ZF_RAW_LOC>(NeedUpdate);

  // Compute adjusted destination selector: (Dest & ~3) | SrcRPL.
  auto NewDest = _Bfxil(OpSize::i32Bit, 2, 0, Dest, SrcRPL);

  // Conditionally select updated selector based on NeedUpdate.
  Ref FinalDest = _Select(OpSize::i32Bit, OpSize::i32Bit, CondClass::NEQ, NeedUpdate, Constant(0), NewDest, Dest);
  StoreResultGPR_WithOpSize(Op, Op->Dest, FinalDest, Size);
}

void OpDispatchBuilder::RecordDivisorZeroExtension(FEXCore::X86Tables::DecodedOp Op, bool FullZeroExtension) {
  if (MacRunnerDivFastMode() < 7 || !MacRunnerDivProvenHighMode() || !FullZeroExtension ||
      !Op->Dest.IsGPR() || Op->Dest.Data.GPR.HighBits) {
    return;
  }
  const auto Dest = Op->Dest.Data.GPR.GPR;
  if (Dest != X86State::REG_RAX && Dest != X86State::REG_RDX) {
    // Record only the identity of the completed architectural write. A memory
    // source must finish its normal load first; no value or SSA Ref crosses a block.
    MacRunnerDivZeroExtEnd = Op->PC + Op->InstSize;
    MacRunnerDivZeroExtRegister = Dest;
  }
}

void OpDispatchBuilder::MOVSXDOp(OpcodeArgs) {
  // This instruction is a bit special
  // if SrcSize == 2
  //  Then lower 16 bits of destination is written without changing the upper 48 bits
  // else /* Size == 4 */
  //  if REX_WIDENING:
  //   Sext(32, Src)
  //  else
  //   Zext(32, Src)
  //
  auto Size = std::min<IR::OpSize>(OpSize::i32Bit, OpSizeFromSrc(Op));
  bool Sext = (Size != OpSize::i16Bit) && Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REX_WIDENING;

  Ref Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], Size, Op->Flags, {.AllowUpperGarbage = Sext});
  if (Size == OpSize::i16Bit) {
    // This'll make sure to insert in to the lower 16bits without modifying upper bits
    StoreResultGPR_WithOpSize(Op, Op->Dest, Src, Size);
  } else if (Sext) {
    // With REX.W then Sext
    Src = _Sbfe(OpSize::i64Bit, IR::OpSizeAsBits(Size), 0, Src);
    StoreResultGPR(Op, Src);
  } else {
    // Without REX.W then Zext (store result implicitly zero extends)
    StoreResultGPR(Op, Src);
  }
  RecordDivisorZeroExtension(Op, !Sext && Size == OpSize::i32Bit);
}

void OpDispatchBuilder::MOVSXOp(OpcodeArgs) {
  // Load garbage in upper bits, since we're sign extending anyway
  const auto Size = OpSizeFromSrc(Op);
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

  // Sign-extend to DstSize and zero-extend to the register size, using a fast
  // path for 32-bit dests where the native 32-bit Sbfe zero extends the top.
  const auto DstSize = OpSizeFromDst(Op);
  Src = _Sbfe(DstSize == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, IR::OpSizeAsBits(Size), 0, Src);
  StoreResultGPR(Op, Op->Dest, Src);
  RecordDivisorZeroExtension(Op, DstSize == OpSize::i32Bit);
}

void OpDispatchBuilder::MOVZXOp(OpcodeArgs) {
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
  // Store result implicitly zero extends
  StoreResultGPR(Op, Src);
  RecordDivisorZeroExtension(Op, OpSizeFromDst(Op) >= OpSize::i32Bit);
  // Unlike a generic r32 write, MOVZX8/16 proves an int32-positive divisor.
  // Record after the load/write completed, never before a possible memory fault.
  if (MacRunnerDivFastMode() >= 8 && MacRunnerDivProvenHighMode() && Op->Dest.IsGPR() &&
      OpSizeFromDst(Op) >= OpSize::i32Bit && OpSizeFromSrc(Op) <= OpSize::i16Bit) {
    MacRunnerDivPositive32End = Op->PC + Op->InstSize;
    MacRunnerDivPositive32Register = Op->Dest.Data.GPR.GPR;
  }
}

void OpDispatchBuilder::CMPOp(OpcodeArgs, uint32_t SrcIndex) {
  // CMP is an instruction that does a SUB between the sources
  // Result isn't stored in result, only writes to flags
  Ref Src = LoadSourceGPR(Op, Op->Src[SrcIndex], Op->Flags, {.AllowUpperGarbage = true});
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  CalculateFlags_SUB(OpSizeFromSrc(Op), Dest, Src);
}

void OpDispatchBuilder::CQOOp(OpcodeArgs) {
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Size = OpSizeFromSrc(Op);
  Ref Upper = _Sbfe(std::max(OpSize::i32Bit, Size), 1, GetSrcBitSize(Op) - 1, Src);

  StoreResultGPR(Op, Upper);

  // ★ MacRunner (MACRUNNER_FEX_DIV_PROVEN_HIGH=1): EDX:EAX / RDX:RAX is now the sign extension of EAX / RAX. An IDIV of
  // the same size that starts right after this instruction, in this block, divides a sign-extended dividend.
  if (MacRunnerDivProvenHighMode() && Size >= OpSize::i32Bit) {
    if (MacRunnerDivFastMode() >= 2 && MacRunnerDivConstEnd == Op->PC) {
      MacRunnerDivConstEnd = Op->PC + Op->InstSize;
    }
    if (MacRunnerDivFastMode() >= 6 && MacRunnerDivZeroExtEnd == Op->PC) {
      MacRunnerDivZeroExtEnd = Op->PC + Op->InstSize;
    }
    MacRunnerSignExtEnd = Op->PC + Op->InstSize;
    MacRunnerSignExtSize = Size;
    // A full adjacent MOV is unchanged by CDQ/CQO unless its source is RDX.
    // Only retain the register identity, never an SSA Ref across the guard.
    if (MacRunnerDivFastMode() && MacRunnerDivLowerEnd == Op->PC && MacRunnerDivLowerSize == Size) {
      MacRunnerDivLowerEnd = Op->PC + Op->InstSize;
    }
  }
}

void OpDispatchBuilder::XCHGOp(OpcodeArgs) {
  // Load both the source and the destination
  if (Op->OP == 0x90 && Op->Src[0].IsGPR() && Op->Src[0].Data.GPR.GPR == FEXCore::X86State::REG_RAX && Op->Dest.IsGPR() &&
      Op->Dest.Data.GPR.GPR == FEXCore::X86State::REG_RAX) {
    // This is one heck of a sucky special case
    // If we are the 0x90 XCHG opcode (Meaning source is GPR RAX)
    // and destination register is ALSO RAX
    // and in this very specific case we are 32bit or above
    // Then this is a no-op
    // This is because 0x90 without a prefix is technically `xchg eax, eax`
    // But this would result in a zext on 64bit, which would ruin the no-op nature of the instruction
    // So x86-64 spec mandates this special case that even though it is a 32bit instruction and
    // is supposed to zext the result, it is a true no-op
    //
    // x86 spec text here:
    //
    //    XCHG (E)AX, (E)AX (encoded instruction byte is 90H) is an alias for
    //    NOP regardless of data size prefixes, including REX.W.
    //
    // Note that also includes 16-bit so we don't gate this on size. The
    // sequence (66 90) is a valid two-byte nop that we also ignore.
    if (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX) {
      // If this instruction has a REP prefix then this is architecturally
      // defined to be a `PAUSE` instruction. On older processors this ends up
      // being a true `REP NOP` which is why they stuck this here.
      _Yield();
    }
    return;
  }

  // AllowUpperGarbage: OK to allow as it will be overwritten by StoreResult.
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  if (DestIsMem(Op)) {
    HandledLock = (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK) != 0;

    Ref Dest = MakeSegmentAddress(Op, Op->Dest);
    if (IsMonoBackpatcherBlock) {
      _MonoBackpatcherWrite(OpSizeFromSrc(Op), Src, Dest);
    } else {
      auto Result = _AtomicSwap(OpSizeFromSrc(Op), Src, Dest);
      StoreResultGPR(Op, Op->Src[0], Result);
    }
  } else {
    // AllowUpperGarbage: OK to allow as it will be overwritten by StoreResult.
    Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});

    // Swap the contents
    // Order matters here since we don't want to swap context contents for one that effects the other
    StoreResultGPR(Op, Op->Dest, Src);
    StoreResultGPR(Op, Op->Src[0], Dest);
  }
}

void OpDispatchBuilder::CDQOp(OpcodeArgs) {
  const auto DstSize = OpSizeFromDst(Op);
  const auto SrcSize = DstSize / 2;
  Ref Src = LoadGPRRegister(X86State::REG_RAX, SrcSize, 0, true);

  Src = _Sbfe(DstSize <= OpSize::i32Bit ? OpSize::i32Bit : OpSize::i64Bit, IR::OpSizeAsBits(SrcSize), 0, Src);

  StoreResultGPR_WithOpSize(Op, Op->Dest, Src, DstSize);
}

void OpDispatchBuilder::SAHFOp(OpcodeArgs) {
  // Extract AH
  Ref Src = LoadGPRRegister(X86State::REG_RAX, OpSize::i8Bit, 8);

  // Clear bits that aren't supposed to be set
  Src = _Andn(OpSize::i64Bit, Src, Constant(0b101000));

  // Set the bit that is always set here
  Src = _Or(OpSize::i64Bit, Src, _InlineConstant(0b10));

  // Store the lower 8 bits in to RFLAGS
  SetPackedRFLAG(true, Src);
}
void OpDispatchBuilder::LAHFOp(OpcodeArgs) {
  // Load the lower 8 bits of the Rflags register
  auto RFLAG = GetPackedRFLAG(0xFF);

  // Store the lower 8 bits of the rflags register in to AH
  StoreGPRRegister(X86State::REG_RAX, RFLAG, OpSize::i8Bit, 8);
}

void OpDispatchBuilder::FLAGControlOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  switch (Op->OP) {
  case 0xF5: // CMC
    CarryInvert();
    break;
  case 0xF8: // CLC
    SetCFInverted(Constant(1));
    break;
  case 0xF9: // STC
    SetCFInverted(Constant(0));
    break;
  case 0xFC: // CLD
    // Transformed
    StoreDF(Constant(1));
    break;
  case 0xFD: // STD
    StoreDF(Constant(-1));
    break;
  }
}


void OpDispatchBuilder::MOVSegOp(OpcodeArgs, bool ToSeg) {
  // In x86-64 mode the accesses to the segment registers end up being constant zero moves
  // Aside from FS/GS
  // In x86-64 mode the accesses to segment registers can actually still touch the segments
  // These write to the selector portion of the register
  //
  // FS and GS are specially handled here though
  // AMD documentation is /wrong/ in this regard
  // AMD documentation claims that the MOV to SReg and POP SReg registers will load a 32bit
  // value in to the HIDDEN portions of the FS and GS registers /OR/ ignored if a null selector is
  // selected for the registers
  // This statement is actually untrue, the instructions will /actually/ load 16bits in to the selector portion of the register!
  // Tested on a Zen+ CPU, the selector is the portion that is modified!
  // We don't currently support FS/GS selector modifying, so this needs to be asserted out
  // The loads here also load the selector, NOT the base

  if (ToSeg) {
    Ref Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], OpSize::i16Bit, Op->Flags);

    switch (Op->Dest.Data.GPR.GPR) {
    case FEXCore::X86State::REG_RAX: // ES
    case FEXCore::X86State::REG_R8:  // ES
      _StoreContextGPR(OpSize::i16Bit, Src, offsetof(FEXCore::Core::CPUState, es_idx));
      UpdatePrefixFromSegment(Src, FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX);
      break;
    case FEXCore::X86State::REG_RBX: // DS
    case FEXCore::X86State::REG_R11: // DS
      _StoreContextGPR(OpSize::i16Bit, Src, offsetof(FEXCore::Core::CPUState, ds_idx));
      UpdatePrefixFromSegment(Src, FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX);
      break;
    case FEXCore::X86State::REG_RCX: // CS
    case FEXCore::X86State::REG_R9:  // CS
      // CPL3 can't write to this
      Break(FEXCore::IR::BreakDefinition {
        .ErrorRegister = 0,
        .Signal = SIGILL,
        .TrapNumber = 0,
        .si_code = 0,
      });
      break;
    case FEXCore::X86State::REG_RDX: // SS
    case FEXCore::X86State::REG_R10: // SS
      _StoreContextGPR(OpSize::i16Bit, Src, offsetof(FEXCore::Core::CPUState, ss_idx));
      UpdatePrefixFromSegment(Src, FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX);
      break;
    case FEXCore::X86State::REG_RBP: // GS
    case FEXCore::X86State::REG_R13: // GS
      if (!Is64BitMode) {
        _StoreContextGPR(OpSize::i16Bit, Src, offsetof(FEXCore::Core::CPUState, gs_idx));
        UpdatePrefixFromSegment(Src, FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX);
      } else {
        LogMan::Msg::EFmt("We don't support modifying GS selector in 64bit mode!");
        DecodeFailure = true;
      }
      break;
    case FEXCore::X86State::REG_RSP: // FS
    case FEXCore::X86State::REG_R12: // FS
      if (!Is64BitMode) {
        _StoreContextGPR(OpSize::i16Bit, Src, offsetof(FEXCore::Core::CPUState, fs_idx));
        UpdatePrefixFromSegment(Src, FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX);
      } else {
        LogMan::Msg::EFmt("We don't support modifying FS selector in 64bit mode!");
        DecodeFailure = true;
      }
      break;
    default: UnimplementedOp(Op); return;
    }
  } else {
    Ref Segment {};

    switch (Op->Src[0].Data.GPR.GPR) {
    case FEXCore::X86State::REG_RAX: // ES
    case FEXCore::X86State::REG_R8:  // ES
      Segment = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, es_idx));
      break;
    case FEXCore::X86State::REG_RBX: // DS
    case FEXCore::X86State::REG_R11: // DS
      Segment = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, ds_idx));
      break;
    case FEXCore::X86State::REG_RCX: // CS
    case FEXCore::X86State::REG_R9:  // CS
      Segment = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, cs_idx));
      break;
    case FEXCore::X86State::REG_RDX: // SS
    case FEXCore::X86State::REG_R10: // SS
      Segment = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, ss_idx));
      break;
    case FEXCore::X86State::REG_RBP: // GS
    case FEXCore::X86State::REG_R13: // GS
      if (Is64BitMode) {
        Segment = Constant(0);
      } else {
        Segment = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, gs_idx));
      }
      break;
    case FEXCore::X86State::REG_RSP: // FS
    case FEXCore::X86State::REG_R12: // FS
      if (Is64BitMode) {
        Segment = Constant(0);
      } else {
        Segment = _LoadContextGPR(OpSize::i16Bit, offsetof(FEXCore::Core::CPUState, fs_idx));
      }
      break;
    default: UnimplementedOp(Op); return;
    }
    if (DestIsMem(Op)) {
      // If the destination is memory then we always store 16-bits only
      StoreResultGPR_WithOpSize(Op, Op->Dest, Segment, OpSize::i16Bit);
    } else {
      // If the destination is a GPR then we follow register storing rules
      StoreResultGPR(Op, Segment);
    }
  }
}

void OpDispatchBuilder::MOVOffsetOp(OpcodeArgs) {
  switch (Op->OP) {
  case 0xA0:
  case 0xA1: {
    // Source is memory(literal)
    // Dest is GPR
    auto Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.ForceLoad = true});
    StoreResultGPR(Op, Op->Dest, Src);
    break;
  }
  case 0xA2:
  case 0xA3: {
    // Source is GPR
    // Dest is memory(literal)
    Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

    // This one is a bit special since the destination is a literal
    // So the destination gets stored in Src[1]
    StoreResultGPR(Op, Op->Src[1], Src);
    break;
  }
  }
}

void OpDispatchBuilder::CPUIDOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();

  Ref Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], GPRSize, Op->Flags);
  Ref Leaf = LoadGPRRegister(X86State::REG_RCX);

  Ref RAX = _AllocateGPR(false);
  Ref RBX = _AllocateGPR(false);
  Ref RCX = _AllocateGPR(false);
  Ref RDX = _AllocateGPR(false);

  _CPUID(Src, Leaf, RAX, RBX, RCX, RDX);

  StoreGPRRegister(X86State::REG_RAX, RAX);
  StoreGPRRegister(X86State::REG_RBX, RBX);
  StoreGPRRegister(X86State::REG_RCX, RCX);
  StoreGPRRegister(X86State::REG_RDX, RDX);
}

uint32_t OpDispatchBuilder::GetConstantShift(X86Tables::DecodedOp Op, bool Is1Bit) {
  if (Is1Bit) {
    return 1;
  } else {
    // x86 masks the shift by 0x3F or 0x1F depending on size of op
    const auto Size = OpSizeFromSrc(Op);
    uint64_t Mask = Size == OpSize::i64Bit ? 0x3F : 0x1F;

    return Op->Src[1].Literal() & Mask;
  }
}

void OpDispatchBuilder::XGetBVOp(OpcodeArgs) {
  Ref Function = LoadGPRRegister(X86State::REG_RCX);

  auto RAX = _AllocateGPR(false);
  auto RDX = _AllocateGPR(false);
  _XGetBV(Function, RAX, RDX);

  StoreGPRRegister(X86State::REG_RAX, RAX);
  StoreGPRRegister(X86State::REG_RDX, RDX);
}

void OpDispatchBuilder::SHLOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);
  auto Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  auto Src = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

  Ref Result = _Lshl(Size == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, Dest, Src);
  HandleShift(Op, Result, Dest, ShiftType::LSL, Src);
}

void OpDispatchBuilder::SHLImmediateOp(OpcodeArgs, bool SHL1Bit) {
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});

  uint64_t Shift = GetConstantShift(Op, SHL1Bit);
  const auto Size = GetSrcBitSize(Op);

  Ref Result = _Lshl(Size == 64 ? OpSize::i64Bit : OpSize::i32Bit, Dest, Constant(Shift));

  CalculateFlags_ShiftLeftImmediate(OpSizeFromSrc(Op), Result, Dest, Shift);
  CalculateDeferredFlags();
  StoreResultGPR(Op, Result);
}

void OpDispatchBuilder::SHROp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);
  auto Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = Size >= OpSize::i32Bit});
  auto Src = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

  auto ALUOp = _Lshr(std::max(OpSize::i32Bit, Size), Dest, Src);
  HandleShift(Op, ALUOp, Dest, ShiftType::LSR, Src);
}

void OpDispatchBuilder::SHRImmediateOp(OpcodeArgs, bool SHR1Bit) {
  const auto Size = GetSrcBitSize(Op);
  auto Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = Size >= 32});

  uint64_t Shift = GetConstantShift(Op, SHR1Bit);
  auto ALUOp = _Lshr(Size == 64 ? OpSize::i64Bit : OpSize::i32Bit, Dest, Constant(Shift));

  CalculateFlags_ShiftRightImmediate(OpSizeFromSrc(Op), ALUOp, Dest, Shift);
  CalculateDeferredFlags();
  StoreResultGPR(Op, ALUOp);
}

void OpDispatchBuilder::SHLDOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  const auto Size = GetSrcBitSize(Op);

  // Allow garbage on the Src if it will be ignored by the Lshr below
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = Size >= 32});
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags);

  // Allow garbage on the shift, we're masking it anyway.
  Ref Shift = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

  // x86 masks the shift by 0x3F or 0x1F depending on size of op.
  if (Size == 64) {
    Shift = _And(OpSize::i64Bit, Shift, _InlineConstant(0x3F));
  } else {
    Shift = _And(OpSize::i64Bit, Shift, _InlineConstant(0x1F));
  }

  // a64 masks the bottom bits, so if we're using a native 32/64-bit shift, we
  // can negate to do the subtract (it's congruent), which saves a constant.
  auto ShiftRight = Size >= 32 ? _Neg(OpSize::i64Bit, Shift) : Sub(OpSize::i64Bit, Constant(Size), Shift);

  auto Tmp1 = _Lshl(OpSize::i64Bit, Dest, Shift);
  auto Tmp2 = _Lshr(Size == 64 ? OpSize::i64Bit : OpSize::i32Bit, Src, ShiftRight);

  Ref Res = _Or(OpSize::i64Bit, Tmp1, Tmp2);

  // If shift count was zero then output doesn't change
  // Needs to be checked for the 32bit operand case
  // where shift = 0 and the source register still gets Zext
  //
  // TODO: With a backwards pass ahead-of-time, we could stick this in the
  // if(shift) used for flags.
  //
  // TODO: This whole function wants to be wrapped in the if. Maybe b/w pass is
  // a good idea after all.
  Res = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, Shift, Constant(0), Dest, Res);

  HandleShift(Op, Res, Dest, ShiftType::LSL, Shift);
}

void OpDispatchBuilder::SHLDImmediateOp(OpcodeArgs) {
  uint64_t Shift = GetConstantShift(Op, false);
  const auto Size = GetSrcBitSize(Op);

  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = Size >= 32});
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = Size >= 32});

  if (Shift != 0) {
    Ref Res {};
    if (Size < 32) {
      Ref ShiftLeft = Constant(Shift);
      auto ShiftRight = Size - Shift;

      auto Tmp1 = _Lshl(OpSize::i64Bit, Dest, ShiftLeft);
      Ref Tmp2 = ShiftRight ? _Lshr(OpSize::i32Bit, Src, Constant(ShiftRight)) : Src;

      Res = _Or(OpSize::i64Bit, Tmp1, Tmp2);
    } else {
      // 32-bit and 64-bit SHLD behaves like an EXTR where the lower bits are filled from the source.
      Res = _Extr(OpSizeFromSrc(Op), Dest, Src, Size - Shift);
    }

    CalculateFlags_ShiftLeftImmediate(OpSizeFromSrc(Op), Res, Dest, Shift, true);
    CalculateDeferredFlags();
    StoreResultGPR(Op, Res);
  } else if (Shift == 0 && Size == 32) {
    // Ensure Zext still occurs
    StoreResultGPR(Op, Dest);
  }
}

void OpDispatchBuilder::SHRDOp(OpcodeArgs) {
  // Calculate flags early.
  // This instruction conditionally generates flags so we need to insure sane state going in.
  CalculateDeferredFlags();

  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags);

  Ref Shift = LoadGPRRegister(X86State::REG_RCX);

  const auto Size = GetDstBitSize(Op);

  // x86 masks the shift by 0x3F or 0x1F depending on size of op
  if (Size == 64) {
    Shift = _And(OpSize::i64Bit, Shift, _InlineConstant(0x3F));
  } else {
    Shift = _And(OpSize::i64Bit, Shift, _InlineConstant(0x1F));
  }

  auto ShiftLeft = Sub(OpSize::i64Bit, Constant(Size), Shift);

  auto Tmp1 = _Lshr(Size == 64 ? OpSize::i64Bit : OpSize::i32Bit, Dest, Shift);
  auto Tmp2 = _Lshl(OpSize::i64Bit, Src, ShiftLeft);

  Ref Res = _Or(OpSize::i64Bit, Tmp1, Tmp2);

  // If shift count was zero then output doesn't change
  // Needs to be checked for the 32bit operand case
  // where shift = 0 and the source register still gets Zext
  Res = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, Shift, Constant(0), Dest, Res);

  HandleShift(Op, Res, Dest, ShiftType::LSR, Shift);
}

void OpDispatchBuilder::SHRDImmediateOp(OpcodeArgs) {
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags);

  uint64_t Shift = GetConstantShift(Op, false);
  const auto Size = GetSrcBitSize(Op);

  if (Shift != 0) {
    Ref Res {};
    if (Size < 32) {
      Ref ShiftRight = Constant(Shift);
      auto ShiftLeft = Constant(Size - Shift);

      auto Tmp1 = _Lshr(OpSize::i32Bit, Dest, ShiftRight);
      auto Tmp2 = _Lshl(OpSize::i64Bit, Src, ShiftLeft);

      Res = _Or(OpSize::i64Bit, Tmp1, Tmp2);
    } else {
      // 32-bit and 64-bit SHRD behaves like an EXTR where the upper bits are filled from the source.
      Res = _Extr(OpSizeFromSrc(Op), Src, Dest, Shift);
    }

    StoreResultGPR(Op, Res);
    CalculateFlags_ShiftRightDoubleImmediate(OpSizeFromSrc(Op), Res, Dest, Shift);
  } else if (Shift == 0 && Size == 32) {
    // Ensure Zext still occurs
    StoreResultGPR(Op, Dest);
  }
}

void OpDispatchBuilder::ASHROp(OpcodeArgs, bool Immediate, bool SHR1Bit) {
  const auto Size = OpSizeFromSrc(Op);
  const auto OpSize = std::max(OpSize::i32Bit, OpSizeFromDst(Op));

  // If Size < 4, then we Sbfe the Dest so we can have garbage.
  // Otherwise, if Size = Opsize, then both are 4 or 8 and match the a64
  // semantics directly, so again we can have garbage. The only case where we
  // need zero-extension here is when the sizes mismatch.
  auto Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = (OpSize == Size) || (Size < OpSize::i32Bit)});

  if (Size < OpSize::i32Bit) {
    Dest = _Sbfe(OpSize::i64Bit, IR::OpSizeAsBits(Size), 0, Dest);
  }

  if (Immediate) {
    uint64_t Shift = GetConstantShift(Op, SHR1Bit);
    Ref Result = _Ashr(OpSize, Dest, Constant(Shift));

    CalculateFlags_SignShiftRightImmediate(OpSizeFromSrc(Op), Result, Dest, Shift);
    CalculateDeferredFlags();
    StoreResultGPR(Op, Result);
  } else {
    auto Src = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});
    Ref Result = _Ashr(OpSize, Dest, Src);

    HandleShift(Op, Result, Dest, ShiftType::ASR, Src);
  }
}

void OpDispatchBuilder::RotateOp(OpcodeArgs, bool Left, bool IsImmediate, bool Is1Bit) {
  CalculateDeferredFlags();

  const uint32_t Size = GetSrcBitSize(Op);
  const auto OpSize = Size == 64 ? OpSize::i64Bit : OpSize::i32Bit;
  uint64_t UnmaskedConst {};

  // x86 masks the shift by 0x3F or 0x1F depending on size of op. But it's
  // equivalent to mask to the actual size of the op, that way we can bound
  // things tighter for 8-bit later in the function.
  uint64_t Mask = Size == 8 ? 7 : (Size == 64 ? 0x3F : 0x1F);

  ArithRef UnmaskedSrc;
  if (Is1Bit || IsImmediate) {
    UnmaskedConst = GetConstantShift(Op, Is1Bit);
    UnmaskedSrc = ARef(UnmaskedConst);
  } else {
    UnmaskedSrc = ARef(LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true}));
  }
  auto Src = UnmaskedSrc.And(Mask);

  // We fill the upper bits so we allow garbage on load.
  auto Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});

  if (Size < 32) {
    // ARM doesn't support 8/16bit rotates. Emulate with an insert
    // StoreResult truncates back to a 8/16 bit value
    Dest = _Bfi(OpSize, Size, Left ? (32 - Size) : Size, Dest, Dest);
  }

  // To rotate 64-bits left, right-rotate by (64 - Shift) = -Shift mod 64.
  auto Res = _Ror(OpSize, Dest, (Left ? Src.Neg() : Src).Ref());
  StoreResultGPR(Op, Res);

  if (Is1Bit || IsImmediate) {
    if (UnmaskedSrc.C) {
      // Extract the last bit shifted in to CF
      SetCFDirect(Res, Left ? 0 : Size - 1, true);

      // For ROR, OF is the XOR of the new CF bit and the most significant bit of the result.
      // For ROL, OF is the LSB and MSB XOR'd together.
      // OF is architecturally only defined for 1-bit rotate.
      if (UnmaskedSrc.C == 1) {
        auto NewOF = _XorShift(OpSize, Res, Res, ShiftType::LSR, Left ? Size - 1 : 1);
        SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(NewOF, Left ? 0 : Size - 2, true);
      }
    }
  } else {
    HandleNZCVWrite();
    RectifyCarryInvert(true);

    // We deferred the masking for 8-bit to the flag section, do it here.
    if (Size == 8) {
      Src = UnmaskedSrc.And(0x1F);
    }

    _RotateFlags(OpSizeFromSrc(Op), Res, Src.Ref(), Left);
  }
}

void OpDispatchBuilder::ANDNBMIOp(OpcodeArgs) {
  auto Src1 = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Src2 = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

  auto Dest = _Andn(OpSizeFromSrc(Op), Src2, Src1);

  StoreResultGPR(Op, Dest);
  CalculateFlags_Logical(OpSizeFromSrc(Op), Dest);
}

void OpDispatchBuilder::BEXTRBMIOp(OpcodeArgs) {
  // Essentially (Src1 >> Start) & ((1 << Length) - 1)
  // along with some edge-case handling and flag setting.

  LOGMAN_THROW_A_FMT(Op->InstSize >= 4, "No masking needed");
  auto Src1 = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Src2 = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

  const auto Size = OpSizeFromSrc(Op);
  const auto SrcSize = IR::OpSizeAsBits(Size);
  const auto MaxSrcBit = SrcSize - 1;
  auto MaxSrcBitOp = Constant(MaxSrcBit);

  // Shift the operand down to the starting bit
  auto Start = _Bfe(OpSizeFromSrc(Op), 8, 0, Src2);
  auto Shifted = _Lshr(Size, Src1, Start);

  // Shifts larger than operand size need to be set to zero.
  auto SanitizedShifted = _Select(Size, Size, CondClass::ULE, Start, MaxSrcBitOp, Shifted, Constant(0));

  // Now handle the length specifier.
  auto Length = _Bfe(Size, 8, 8, Src2);

  // Now build up the mask
  // (1 << Length) - 1 = ~(~0 << Length)
  auto AllOnes = Constant(~0ull);
  auto InvertedMask = _Lshl(Size, AllOnes, Length);

  // Now put it all together and make the result.
  auto Masked = _Andn(Size, SanitizedShifted, InvertedMask);

  // Sanitize the length. If it is above the max, we don't do the masking.
  auto Dest = _Select(Size, Size, CondClass::ULE, Length, MaxSrcBitOp, Masked, SanitizedShifted);

  // Finally store the result.
  StoreResultGPR(Op, Dest);

  // ZF is set properly. CF and OF are defined as being set to zero. SF, PF, and
  // AF are undefined.
  SetNZ_ZeroCV(GetOpSize(Dest), Dest);
  InvalidatePF_AF();
}

void OpDispatchBuilder::BLSIBMIOp(OpcodeArgs) {
  // Equivalent to performing: SRC & -SRC
  LOGMAN_THROW_A_FMT(Op->InstSize >= 4, "No masking needed");
  const auto Size = OpSizeFromSrc(Op);

  auto Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto NegatedSrc = _Neg(Size, Src);
  auto Result = _And(Size, Src, NegatedSrc);

  StoreResultGPR(Op, Result);

  // CF is cleared if Src is zero, otherwise it's set. However, Src is zero iff
  // Result is zero, so we can test the result instead. So, CF is just the
  // inverted ZF.
  //
  // ZF/SF/OF set as usual.
  SetNZ_ZeroCV(Size, Result);
  InvalidatePF_AF();
  SetCFInverted(GetRFLAG(X86State::RFLAG_ZF_RAW_LOC));
}

void OpDispatchBuilder::BLSMSKBMIOp(OpcodeArgs) {
  // Equivalent to: (Src - 1) ^ Src
  LOGMAN_THROW_A_FMT(Op->InstSize >= 4, "No masking needed");
  const auto Size = OpSizeFromSrc(Op);

  auto Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Result = _Xor(Size, Sub(Size, Src, 1), Src);

  StoreResultGPR(Op, Result);
  InvalidatePF_AF();

  // CF set according to the Src
  auto CFInv = To01(Size, Src);

  // The output of BLSMSK is always nonzero, so TST will clear Z (along with C
  // and O) while setting S.
  SetNZ_ZeroCV(Size, Result);
  SetCFInverted(CFInv);
}

void OpDispatchBuilder::BLSRBMIOp(OpcodeArgs) {
  // Equivalent to: (Src - 1) & Src
  LOGMAN_THROW_A_FMT(Op->InstSize >= 4, "No masking needed");
  const auto Size = OpSizeFromSrc(Op);

  auto Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Result = _And(Size, Sub(Size, Src, 1), Src);

  StoreResultGPR(Op, Result);

  auto CFInv = To01(Size, Src);

  SetNZ_ZeroCV(Size, Result);
  SetCFInverted(CFInv);
  InvalidatePF_AF();
}

// Handles SARX, SHLX, and SHRX
void OpDispatchBuilder::BMI2Shift(OpcodeArgs) {
  // In the event the source is a memory operand, use the
  // exact width instead of the GPR size.
  const auto GPRSize = GetGPROpSize();
  const auto Size = OpSizeFromSrc(Op);
  const auto SrcSize = Op->Src[0].IsGPR() ? GPRSize : Size;

  auto Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], SrcSize, Op->Flags);
  auto Shift = LoadSourceGPR_WithOpSize(Op, Op->Src[1], GPRSize, Op->Flags, {.AllowUpperGarbage = true});

  Ref Result;
  if (Op->OP == 0x6F7) {
    // SARX
    Result = _Ashr(Size, Src, Shift);
  } else if (Op->OP == 0x5F7) {
    // SHLX
    Result = _Lshl(Size, Src, Shift);
  } else {
    // SHRX
    Result = _Lshr(Size, Src, Shift);
  }

  StoreResultGPR(Op, Result);
}

void OpDispatchBuilder::BZHI(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);
  const auto OperandSize = IR::OpSizeAsBits(Size);

  // In 32-bit mode we only look at bottom 32-bit, no 8 or 16-bit BZHI so no
  // need to zero-extend sources
  auto Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

  auto Index = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

  // Clear the high bits specified by the index. A64 only considers bottom bits
  // of the shift, so we don't need to mask bottom 8-bits ourselves.
  // Out-of-bounds results ignored after.
  auto Mask = _Lshl(Size, Constant(-1), Index);
  auto MaskResult = _Andn(Size, Src, Mask);

  // If the index is above OperandSize, we don't clear anything. BZHI only
  // considers the bottom 8-bits, so we really want to know if the bottom 8-bits
  // have their top bits set. Test exactly that.
  //
  // Because we're clobbering flags internally we ignore all carry invert
  // shenanigans and use the raw versions here.
  _TestNZ(OpSize::i64Bit, Index, Constant(0xFF & ~(OperandSize - 1)));
  auto Result = _NZCVSelect(Size, CondClass::NEQ, Src, MaskResult);
  StoreResultGPR(Op, Result);

  auto CFInv = _NZCVSelect01(CondClass::EQ);

  InvalidatePF_AF();
  SetNZ_ZeroCV(Size, Result);
  SetCFInverted(CFInv);
}

void OpDispatchBuilder::RORX(OpcodeArgs) {
  const auto SrcSize = OpSizeFromSrc(Op);
  const auto SrcSizeBits = IR::OpSizeAsBits(SrcSize);
  const auto Amount = Op->Src[1].Literal() & (SrcSizeBits - 1);
  const auto GPRSize = GetGPROpSize();

  const auto DoRotation = Amount != 0 && Amount < SrcSizeBits;
  const auto IsSameGPR = Op->Src[0].IsGPR() && Op->Dest.IsGPR() && Op->Src[0].Data.GPR.GPR == Op->Dest.Data.GPR.GPR;
  const auto SrcSizeIsGPRSize = SrcSize == GPRSize;

  // If we don't need to rotate and our source is the same as the destination
  // then we don't need to do anything at all. We still need to be careful,
  // since 32-bit operations on 64-bit mode still need to zero-extend the
  // destination register. So also compare source size and GPR size.
  //
  // Very unlikely, but hey, we can do nothing faster.
  if (!DoRotation && IsSameGPR && SrcSizeIsGPRSize) [[unlikely]] {
    return;
  }

  auto Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Result = Src;
  if (DoRotation) [[likely]] {
    Result = _Ror(OpSizeFromSrc(Op), Src, _InlineConstant(Amount));
  }

  StoreResultGPR(Op, Result);
}

void OpDispatchBuilder::MULX(OpcodeArgs) {
  // RDX is the implied source operand in the instruction
  const auto OpSize = OpSizeFromSrc(Op);

  // Src1 can be a memory operand, so ensure we constrain to the
  // absolute width of the access in that scenario.
  const auto GPRSize = GetGPROpSize();
  const auto Src1Size = Op->Src[1].IsGPR() ? GPRSize : OpSize;

  Ref Src1 = LoadSourceGPR_WithOpSize(Op, Op->Src[1], Src1Size, Op->Flags);
  Ref Src2 = LoadGPRRegister(X86State::REG_RDX, GPRSize);

  // As per the Intel Software Development Manual, if the destination and
  // first operand correspond to the same register, then the result
  // will be the high half of the multiplication result.
  if (Op->Dest.Data.GPR.GPR == Op->Src[0].Data.GPR.GPR) {
    Ref ResultHi = _UMulH(OpSize, Src1, Src2);
    StoreResultGPR(Op, Op->Dest, ResultHi);
  } else {
    Ref ResultLo = _UMul(OpSize, Src1, Src2);
    Ref ResultHi = _UMulH(OpSize, Src1, Src2);

    StoreResultGPR(Op, Op->Src[0], ResultLo);
    StoreResultGPR(Op, Op->Dest, ResultHi);
  }
}

void OpDispatchBuilder::PDEP(OpcodeArgs) {
  LOGMAN_THROW_A_FMT(Op->InstSize >= 4, "No masking needed");
  auto Input = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Mask = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});
  auto Result = _PDep(OpSizeFromSrc(Op), Input, Mask);

  StoreResultGPR(Op, Op->Dest, Result);
}

void OpDispatchBuilder::PEXT(OpcodeArgs) {
  LOGMAN_THROW_A_FMT(Op->InstSize >= 4, "No masking needed");
  auto Input = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Mask = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});
  auto Result = _PExt(OpSizeFromSrc(Op), Input, Mask);

  StoreResultGPR(Op, Op->Dest, Result);
}

void OpDispatchBuilder::ADXOp(OpcodeArgs) {
  const auto OpSize = OpSizeFromSrc(Op);

  // Only 32/64-bit anyway so allow garbage, we use 32-bit ops.
  auto Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  auto Before = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});

  // Handles ADCX and ADOX
  const bool IsADCX = Op->OP == 0x1F6;
  auto Zero = Constant(0);

  // Before we go trashing NZCV, save the current NZCV state.
  Ref OldNZCV = GetNZCV();

  // We want to use arm64 adc. For ADOX, copy the overflow flag into CF.  For
  // ADCX, we just rectify the carry.
  if (IsADCX) {
    RectifyCarryInvert(false);
  } else {
    // If overflow, 0 - 0 sets carry. Else, forces carry to 0.
    _CondSubNZCV(OpSize::i32Bit, Zero, Zero, CondClass::FU, 0x0 /* nzcv */);
  }

  // Do the actual add.
  HandleNZCV_RMW();
  auto Result = _AdcWithFlags(OpSize, Src, Before);
  StoreResultGPR(Op, Result);

  // Now restore all flags except the one we're updating.
  if (CTX->HostFeatures.SupportsFlagM) {
    // For ADOX, we need to copy the new carry into the overflow flag. If carry is clear (ULT with uninverted
    // carry), 0 - 0 clears overflow. Else, force overflow on.
    if (!IsADCX) {
      _CondSubNZCV(OpSize::i32Bit, Zero, Zero, CondClass::ULT, 0x1 /* nzcV */);
    }

    _RmifNZCV(OldNZCV, 28, IsADCX ? 0xd /* NzcV */ : 0xe /* NZCv */);
  } else {
    // For either operation, insert the new flag into the old NZCV.
    bool SavedCFInvert = CFInverted;
    CFInverted = false;
    Ref OutputCF = GetRFLAG(X86State::RFLAG_CF_RAW_LOC, IsADCX);
    CFInverted = IsADCX ? true : SavedCFInvert;

    Ref NewNZCV = _Bfi(OpSize::i32Bit, 1, IsADCX ? 29 : 28, OldNZCV, OutputCF);
    SetNZCV(NewNZCV);
  }
}

void OpDispatchBuilder::RCROp1Bit(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  // We expliclty mask for <32-bit so allow garbage
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  const auto Size = GetSrcBitSize(Op);
  auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);
  Ref Res;

  // Our new CF will be bit 0 of the source. Set upfront to avoid a move.
  SetCFDirect(Dest, 0, true);

  uint32_t Shift = 1;

  if (Size == 32 || Size == 64) {
    // Rotate and insert CF in the upper bit
    Res = _Extr(OpSizeFromSrc(Op), CF, Dest, Shift);
  } else {
    // Res = Src >> Shift
    Res = _Bfe(OpSize::i32Bit, Size - Shift, Shift, Dest);

    // inject the CF
    Res = _Orlshl(OpSize::i32Bit, Res, CF, Size - Shift);
  }

  StoreResultGPR(Op, Res);

  // OF is the top two MSBs XOR'd together
  // Only when Shift == 1, it is undefined otherwise
  SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(_XorShift(OpSize::i64Bit, Res, Res, ShiftType::LSR, 1), Size - 2, true);
}

void OpDispatchBuilder::RCROp8x1Bit(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags);
  const auto SizeBit = GetSrcBitSize(Op);
  auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

  // Our new CF will be bit (Shift - 1) of the source
  SetCFDirect(Dest, 0, true);

  // Rotate and insert CF in the upper bit
  Ref Res = _Bfe(OpSize::i32Bit, 7, 1, Dest);
  Res = _Bfi(OpSize::i32Bit, 1, 7, Res, CF);

  StoreResultGPR(Op, Res);

  // OF is the top two MSBs XOR'd together
  SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(_XorShift(OpSize::i32Bit, Res, Res, ShiftType::LSR, 1), SizeBit - 2, true);
}

void OpDispatchBuilder::RCROp(OpcodeArgs) {
  const auto Size = GetSrcBitSize(Op);

  if (Size == 8 || Size == 16) {
    RCRSmallerOp(Op);
    return;
  }

  const auto Mask = (Size == 64) ? 0x3F : 0x1F;

  // Calculate flags early.
  CalculateDeferredFlags();
  const auto OpSize = OpSizeFromSrc(Op);

  Ref Src = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});
  uint64_t Const;
  if (IsValueConstant(WrapNode(Src), &Const)) {
    Const &= Mask;
    if (!Const) {
      ZeroShiftResult(Op);
      return;
    }

    Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});

    // Res = Src >> Shift
    Ref Res = _Lshr(OpSize, Dest, Src);
    auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

    // Constant folded version of the above, with fused shifts.
    if (Const > 1) {
      Res = _Orlshl(OpSize, Res, Dest, Size + 1 - Const);
    }

    // Our new CF will be bit (Shift - 1) of the source.
    SetCFDirect(Dest, Const - 1, true);

    // Since shift != 0 we can inject the CF
    Res = _Orlshl(OpSize, Res, CF, Size - Const);

    // OF is the top two MSBs XOR'd together
    // Only when Shift == 1, it is undefined otherwise
    if (Const == 1) {
      auto Xor = _XorShift(OpSize, Res, Res, ShiftType::LSR, 1);
      SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(Xor, Size - 2, true);
    }

    StoreResultGPR(Op, Res);
    return;
  }

  Ref SrcMasked = _And(OpSize, Src, _InlineConstant(Mask));
  Calculate_ShiftVariable(
    Op, SrcMasked,
    [this, Op, Size, OpSize]() {
      // Rematerialize loads to avoid crossblock liveness
      Ref Src = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});
      Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});

      // Res = Src >> Shift
      Ref Res = _Lshr(OpSize, Dest, Src);
      auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

      // Res |= (Dest << (Size - Shift + 1));
      // Expressed as Res | ((Src << (Size - Shift)) << 1) to get correct
      // behaviour for Shift without clobbering NZCV. Then observe that modulo
      // Size, Size - Shift = -Shift so we can use a simple Neg.
      //
      // The masking of Lshl means we don't need mask the source, since:
      //
      //  -(x & Mask) & Mask = (-x) & Mask
      Ref NegSrc = _Neg(OpSize, Src);
      Res = _Orlshl(OpSize, Res, _Lshl(OpSize, Dest, NegSrc), 1);

      // Our new CF will be bit (Shift - 1) of the source. this is hoisted up to
      // avoid the need to copy the source. Again, the Lshr absorbs the masking.
      auto NewCF = _Lshr(OpSize, Dest, Sub(OpSize, Src, 1));
      SetCFDirect(NewCF, 0, true);

      // Since shift != 0 we can inject the CF
      Res = _Or(OpSize, Res, _Lshl(OpSize, CF, NegSrc));

      // OF is the top two MSBs XOR'd together
      // Only when Shift == 1, it is undefined otherwise
      auto Xor = _XorShift(OpSize, Res, Res, ShiftType::LSR, 1);
      SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(Xor, Size - 2, true);

      StoreResultGPR(Op, Res);
    },
    OpSizeFromSrc(Op) == OpSize::i32Bit ? std::make_optional(&OpDispatchBuilder::ZeroShiftResult) : std::nullopt);
}

void OpDispatchBuilder::RCRSmallerOp(OpcodeArgs) {
  CalculateDeferredFlags();

  const auto Size = GetSrcBitSize(Op);

  // x86 masks the shift by 0x3F or 0x1F depending on size of op
  auto Src = ARef(LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true}));
  Src = Src.And(0x1F);

  // CF only changes if we actually shifted. OF undefined if we didn't shift.
  // The result is unchanged if we didn't shift. So branch over the whole thing.
  Calculate_ShiftVariable(Op, Src.Ref(), [this, Op, Size]() {
    // Rematerialized to avoid crossblock liveness
    auto Src = ARef(LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true}));
    Src = Src.And(0x1F);

    auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

    Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags);
    Ref Tmp {};

    // Insert the incoming value across the temporary 64bit source
    // Make sure to insert at <BitSize> + 1 offsets
    // We need to cover 32bits plus the amount that could rotate in

    if (Size == 8) {
      // 8-bit optimal cascade
      // Cascade: 0
      //   Data: -> [7:0]
      //   CF:   -> [8:8]
      // Cascade: 1
      //   Data: -> [16:9]
      //   CF:   -> [17:17]
      // Cascade: 2
      //   Data: -> [25:18]
      //   CF:   -> [26:26]
      // Cascade: 3
      //   Data: -> [34:27]
      //   CF:   -> [35:35]
      // Cascade: 4
      //   Data: -> [43:36]
      //   CF:   -> [44:44]

      // Insert CF, Destination already at [7:0]
      Tmp = _Bfi(OpSize::i64Bit, 1, 8, Dest, CF);

      // First Cascade, copies 9 bits from itself.
      Tmp = _Bfi(OpSize::i64Bit, 9, 9, Tmp, Tmp);

      // Second cascade, copies 18 bits from itself.
      Tmp = _Bfi(OpSize::i64Bit, 18, 18, Tmp, Tmp);

      // Final cascade, copies 9 bits again from itself.
      Tmp = _Bfi(OpSize::i64Bit, 9, 36, Tmp, Tmp);
    } else {
      // 16-bit optimal cascade
      // Cascade: 0
      //   Data: -> [15:0]
      //   CF:   -> [16:16]
      // Cascade: 1
      //   Data: -> [32:17]
      //   CF:   -> [33:33]
      // Cascade: 2
      //   Data: -> [49:34]
      //   CF:   -> [50:50]

      // Insert CF, Destination already at [15:0]
      Tmp = _Bfi(OpSize::i64Bit, 1, 16, Dest, CF);

      // First Cascade, copies 17 bits from itself.
      Tmp = _Bfi(OpSize::i64Bit, 17, 17, Tmp, Tmp);

      // Final Cascade, copies 17 bits from itself again.
      Tmp = _Bfi(OpSize::i64Bit, 17, 34, Tmp, Tmp);
    }

    // Entire bitfield has been setup. Just extract the 8 or 16bits we need.
    // 64-bit shift used because we want to rotate in our cascaded upper bits
    // rather than zeroes.
    Ref Res = _Lshr(OpSize::i64Bit, Tmp, Src.Ref());

    StoreResultGPR(Op, Res);

    // Our new CF will be bit (Shift - 1) of the source. 32-bit Lshr masks the
    // same as x86, but if we constant fold we must mask ourselves.
    if (Src.IsConstant) {
      SetCFDirect(Tmp, (Src.C & 0x1f) - 1, true);
    } else {
      auto NewCF = _Lshr(OpSize::i32Bit, Tmp, Sub(OpSize::i32Bit, Src.Ref(), 1));
      SetCFDirect(NewCF, 0, true);
    }

    // OF is the top two MSBs XOR'd together
    // Only when Shift == 1, it is undefined otherwise
    if (!Src.IsConstant || Src.C == 1) {
      auto NewOF = _XorShift(OpSize::i32Bit, Res, Res, ShiftType::LSR, 1);
      SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(NewOF, Size - 2, true);
    }
  });
}

void OpDispatchBuilder::RCLOp1Bit(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags);
  const auto Size = GetSrcBitSize(Op);
  const auto OpSize = Size == 64 ? OpSize::i64Bit : OpSize::i32Bit;
  auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

  // Rotate left and insert CF in to lowest bit
  // TODO: Use `adc Res, xzr, Dest, lsl 1` to save an instruction
  Ref Res = _Orlshl(OpSize, CF, Dest, 1);

  // Our new CF will be the top bit of the source
  SetCFDirect(Dest, Size - 1, true);

  // OF is the top two MSBs XOR'd together
  // Top two MSBs is CF and top bit of result
  SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(_Xor(OpSize, Res, Dest), Size - 1, true);

  StoreResultGPR(Op, Res);
}

void OpDispatchBuilder::RCLOp(OpcodeArgs) {
  const auto Size = GetSrcBitSize(Op);

  if (Size == 8 || Size == 16) {
    RCLSmallerOp(Op);
    return;
  }

  const auto Mask = (Size == 64) ? 0x3F : 0x1F;

  // Calculate flags early.
  CalculateDeferredFlags();

  Ref Src = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});
  const auto OpSize = OpSizeFromSrc(Op);

  uint64_t Const;
  if (IsValueConstant(WrapNode(Src), &Const)) {
    Const &= Mask;
    if (!Const) {
      ZeroShiftResult(Op);
      return;
    }

    // Res = Src << Shift
    Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
    Ref Res = _Lshl(OpSize, Dest, Src);
    auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

    // Res |= (Src << (Size - Shift + 1));
    if (Const > 1) {
      Res = _Orlshr(OpSize, Res, Dest, Size + 1 - Const);
    }

    // Our new CF will be bit (Shift - 1) of the source
    SetCFDirect(Dest, Size - Const, true);

    // Since Shift != 0 we can inject the CF
    Res = _Orlshl(OpSize, Res, CF, Const - 1);

    // OF is the top two MSBs XOR'd together
    // Only when Shift == 1, it is undefined otherwise
    if (Const == 1) {
      auto NewOF = _Xor(OpSize, Res, Dest);
      SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(NewOF, Size - 1, true);
    }

    StoreResultGPR(Op, Res);
    return;
  }

  Ref SrcMasked = _And(OpSize, Src, _InlineConstant(Mask));
  Calculate_ShiftVariable(
    Op, SrcMasked,
    [this, Op, Size, OpSize]() {
      // Rematerialized to avoid crossblock liveness
      Ref Src = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

      // Res = Src << Shift
      Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
      Ref Res = _Lshl(OpSize, Dest, Src);
      auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

      // Res |= (Dest >> (Size - Shift + 1)), expressed as
      // Res | ((Dest >> (-Shift)) >> 1), since Size - Shift = -Shift mod
      // Size. The shift aborbs the masking.
      auto NegSrc = _Neg(OpSize, Src);
      Res = _Orlshr(OpSize, Res, _Lshr(OpSize, Dest, NegSrc), 1);

      // Our new CF will be bit (Shift - 1) of the source
      auto NewCF = _Lshr(OpSize, Dest, NegSrc);
      SetCFDirect(NewCF, 0, true);

      // Since Shift != 0 we can inject the CF. Shift absorbs the masking.
      Ref CFShl = Sub(OpSize, Src, 1);
      auto TmpCF = _Lshl(OpSize, CF, CFShl);
      Res = _Or(OpSize, Res, TmpCF);

      // OF is the top two MSBs XOR'd together
      // Only when Shift == 1, it is undefined otherwise
      //
      // Note that NewCF has garbage in the upper bits, but we ignore them here
      // and mask as part of the set after.
      auto NewOF = _XorShift(OpSize, Res, NewCF, ShiftType::LSL, Size - 1);
      SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(NewOF, Size - 1, true);

      StoreResultGPR(Op, Res);
    },
    OpSizeFromSrc(Op) == OpSize::i32Bit ? std::make_optional(&OpDispatchBuilder::ZeroShiftResult) : std::nullopt);
}

void OpDispatchBuilder::RCLSmallerOp(OpcodeArgs) {
  CalculateDeferredFlags();

  const auto Size = GetSrcBitSize(Op);

  // x86 masks the shift by 0x3F or 0x1F depending on size of op
  auto Src = ARef(LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true}));
  Src = Src.And(0x1F);

  // CF only changes if we actually shifted. OF undefined if we didn't shift.
  // The result is unchanged if we didn't shift. So branch over the whole thing.
  Calculate_ShiftVariable(Op, Src.Ref(), [this, Op, Size]() {
    // Rematerialized to avoid crossblock liveness
    auto Src = ARef(LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true}));
    Src = Src.And(0x1F);
    Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags);

    auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);

    Ref Tmp = Constant(0);

    for (size_t i = 0; i < (32 + Size + 1); i += (Size + 1)) {
      // Insert incoming value
      Tmp = _Bfi(OpSize::i64Bit, Size, 63 - i - Size, Tmp, Dest);

      // Insert CF
      Tmp = _Bfi(OpSize::i64Bit, 1, 63 - i, Tmp, CF);
    }

    // Insert incoming value
    Tmp = _Bfi(OpSize::i64Bit, Size, 0, Tmp, Dest);

    // The data is now set up like this
    // [Data][CF]:[Data][CF]:[Data][CF]:[Data][CF]
    // Shift 1 more bit that expected to get our result
    // Shifting to the right will now behave like a rotate to the left
    // Which we emulate with a _Ror
    Ref Res = _Ror(OpSize::i64Bit, Tmp, Src.Neg().Ref());

    StoreResultGPR(Op, Res);

    // Our new CF is now at the bit position that we are shifting
    // Either 0 if CF hasn't changed (CF is living in bit 0)
    // or higher
    auto NewCF = _Ror(OpSize::i64Bit, Tmp, Src.Presub(63).Ref());
    SetCFDirect(NewCF, 0, true);

    // OF is the XOR of the NewCF and the MSB of the result
    // Only defined for 1-bit rotates.
    if (!Src.IsConstant || Src.C == 1) {
      auto NewOF = _XorShift(OpSize::i64Bit, NewCF, Res, ShiftType::LSR, Size - 1);
      SetRFLAG<FEXCore::X86State::RFLAG_OF_RAW_LOC>(NewOF, 0, true);
    }
  });
}

void OpDispatchBuilder::BTOp(OpcodeArgs, uint32_t SrcIndex, BTAction Action) {
  Ref Value;
  ArithRef Src;
  bool IsNonconstant = Op->Src[SrcIndex].IsGPR();

  const uint32_t Size = GetDstBitSize(Op);
  const uint32_t Mask = Size - 1;

  if (IsNonconstant) {
    // Because we mask explicitly with And/Bfe/Sbfe after, we can allow garbage here.
    Src = ARef(LoadSourceGPR(Op, Op->Src[SrcIndex], Op->Flags, {.AllowUpperGarbage = true}));
  } else {
    // Can only be an immediate
    // Masked by operand size
    Src = ARef(Op->Src[SrcIndex].Literal() & Mask);
  }

  if (Op->Dest.IsGPR()) {
    // When the destination is a GPR, we don't care about garbage in the upper bits.
    // Load the full register.
    auto Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, GetGPROpSize(), Op->Flags);
    Value = Dest;

    // Get the bit selection from the src. We need to mask for 8/16-bit, but
    // rely on the implicit masking of Lshr for native sizes.
    unsigned LshrSize = std::max<uint8_t>(IR::OpSizeToSize(OpSize::i32Bit), Size / 8);
    auto BitSelect = (Size == (LshrSize * 8)) ? Src : Src.And(Mask);
    auto LshrOpSize = IR::SizeToOpSize(LshrSize);

    // AMD: OF/SF/ZF/AF/PF undefined.
    // Intel: OF/SF/AF/PF undefined. ZF must be preserved.
    // We choose to preserve ZF/OF/SF since we just use an rmif
    // to insert into CF directly. We could optimize perhaps.
    //
    // Set CF before the action to save a move, except for complements where we
    // can reuse the invert.
    if (Action != BTAction::BTComplement) {
      if (IsNonconstant) {
        Value = _Lshr(IR::SizeToOpSize(LshrSize), Value, BitSelect.Ref());
      }

      SetRFLAG(Value, X86State::RFLAG_CF_RAW_LOC, Src.IsConstant ? Src.C : 0, true);
      CFInverted = false;
    }

    switch (Action) {
    case BTAction::BTNone: {
      /* Nothing to do */
      break;
    }

    case BTAction::BTClear: {
      Dest = _Andn(LshrOpSize, Dest, BitSelect.MaskBit(LshrOpSize).Ref());
      StoreResultGPR(Op, Dest);
      break;
    }

    case BTAction::BTSet: {
      Dest = _Or(LshrOpSize, Dest, BitSelect.MaskBit(LshrOpSize).Ref());
      StoreResultGPR(Op, Dest);
      break;
    }

    case BTAction::BTComplement: {
      Dest = _Xor(LshrOpSize, Dest, BitSelect.MaskBit(LshrOpSize).Ref());

      if (IsNonconstant) {
        Value = _Lshr(LshrOpSize, Dest, BitSelect.Ref());
      } else {
        Value = Dest;
      }

      SetRFLAG(Value, X86State::RFLAG_CF_RAW_LOC, Src.IsConstant ? Src.C : 0, true);
      CFInverted = true;

      StoreResultGPR(Op, Dest);
      break;
    }
    }
  } else {
    // Load the address to the memory location
    Ref Dest = MakeSegmentAddress(Op, Op->Dest);
    // 0203: byte-sized atomics lose the architectural operand's permission
    // footprint. Keep the complete 16/32/64-bit word for the entire BT family.
    // This value is selected during ordinary lifting, never in a signal handler.
    const char* ExactValue = std::getenv("MACRUNNER_FEX_SPLIT_ATOMIC_EXACT");
    const bool ExactFootprint = ExactValue && ExactValue[0] == '1' && ExactValue[1] == 0;
    const OpSize MemorySize = ExactFootprint ? IR::SizeToOpSize(Size / 8) : OpSize::i8Bit;
    const unsigned IndexBits = ExactFootprint ? (Size == 16 ? 4 : Size == 32 ? 5 : 6) : 3;
    // Get the bit selection from the src
    auto BitSelect = Src.Bfe(0, IndexBits);

    // Address is provided as bits we want BYTE offsets
    // Extract Signed offset
    Src = Src.Sbfe(IndexBits, Size - IndexBits);
    if (ExactFootprint) Src = Src.Lshl(IndexBits - 3);

    // Get the address offset by shifting out the size of the op (To shift out the bit selection)
    // Then use that to index in to the memory location by size of op
    AddressMode Address = {.Base = Dest, .Index = Src.Ref(), .AddrSize = OpSize::i64Bit};

    switch (Action) {
    case BTAction::BTNone: {
      Value = _LoadMemGPRAutoTSO(MemorySize, Address, MemorySize);
      break;
    }

    case BTAction::BTClear: {
      Ref BitMask = BitSelect.MaskBit(OpSize::i64Bit).Ref();

      if (DestIsLockedMem(Op)) {
        HandledLock = true;
        Value = _AtomicFetchCLR(MemorySize, BitMask, LoadEffectiveAddress(this, Address, GetGPROpSize(), true));
      } else {
        Value = _LoadMemGPRAutoTSO(MemorySize, Address, MemorySize);

        auto Modified = _Andn(OpSize::i64Bit, Value, BitMask);
        _StoreMemGPRAutoTSO(MemorySize, Address, Modified, MemorySize);
      }
      break;
    }

    case BTAction::BTSet: {
      Ref BitMask = BitSelect.MaskBit(OpSize::i64Bit).Ref();

      if (DestIsLockedMem(Op)) {
        HandledLock = true;
        Value = _AtomicFetchOr(MemorySize, BitMask, LoadEffectiveAddress(this, Address, GetGPROpSize(), true));
      } else {
        Value = _LoadMemGPRAutoTSO(MemorySize, Address, MemorySize);

        auto Modified = _Or(OpSize::i64Bit, Value, BitMask);
        _StoreMemGPRAutoTSO(MemorySize, Address, Modified, MemorySize);
      }
      break;
    }

    case BTAction::BTComplement: {
      Ref BitMask = BitSelect.MaskBit(OpSize::i64Bit).Ref();

      if (DestIsLockedMem(Op)) {
        HandledLock = true;
        Value = _AtomicFetchXor(MemorySize, BitMask, LoadEffectiveAddress(this, Address, GetGPROpSize(), true));
      } else {
        Value = _LoadMemGPRAutoTSO(MemorySize, Address, MemorySize);

        auto Modified = _Xor(OpSize::i64Bit, Value, BitMask);
        _StoreMemGPRAutoTSO(MemorySize, Address, Modified, MemorySize);
      }
      break;
    }
    }

    // Now shift in to the correct bit location
    if (!BitSelect.IsDefinitelyZero()) {
      Value = _Lshr(std::max(OpSize::i32Bit, GetOpSize(Value)), Value, BitSelect.Ref());
    }

    // AMD: OF/SF/ZF/AF/PF undefined.
    // Intel: OF/SF/AF/PF undefined. ZF must be preserved.
    // We choose to preserve ZF/OF/SF since we just use an rmif
    // to insert into CF directly. We could optimize perhaps.
    SetCFDirect(Value, 0, true);
  }
}

void OpDispatchBuilder::IMUL1SrcOp(OpcodeArgs) {
  /* We're just going to sign-extend the non-garbage anyway.. */
  Ref Src1 = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  Ref Src2 = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

  const auto Size = OpSizeFromSrc(Op);
  const auto SizeBits = IR::OpSizeAsBits(Size);

  Ref Dest {};
  Ref ResultHigh {};
  switch (Size) {
  case OpSize::i8Bit:
  case OpSize::i16Bit: {
    Src1 = _Sbfe(OpSize::i64Bit, SizeBits, 0, Src1);
    Src2 = _Sbfe(OpSize::i64Bit, SizeBits, 0, Src2);
    Dest = _Mul(OpSize::i64Bit, Src1, Src2);
    ResultHigh = _Sbfe(OpSize::i64Bit, SizeBits, SizeBits, Dest);
    break;
  }
  case OpSize::i32Bit: {
    ResultHigh = _SMull(Src1, Src2);
    ResultHigh = _Sbfe(OpSize::i64Bit, SizeBits, SizeBits, ResultHigh);
    // Flipped order to save a move
    Dest = _Mul(OpSize::i32Bit, Src1, Src2);
    break;
  }
  case OpSize::i64Bit: {
    ResultHigh = _MulH(OpSize::i64Bit, Src1, Src2);
    // Flipped order to save a move
    Dest = _Mul(OpSize::i64Bit, Src1, Src2);
    break;
  }
  default: FEX_UNREACHABLE;
  }

  StoreResultGPR(Op, Dest);
  CalculateFlags_MUL(Size, Dest, ResultHigh);
}

void OpDispatchBuilder::IMUL2SrcOp(OpcodeArgs) {
  Ref Src1 = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
  Ref Src2 = LoadSourceGPR(Op, Op->Src[1], Op->Flags, {.AllowUpperGarbage = true});

  const auto Size = OpSizeFromSrc(Op);
  const auto SizeBits = IR::OpSizeAsBits(Size);

  Ref Dest {};
  Ref ResultHigh {};

  switch (Size) {
  case OpSize::i8Bit:
  case OpSize::i16Bit: {
    Src1 = _Sbfe(OpSize::i64Bit, SizeBits, 0, Src1);
    Src2 = ARef(Src2).Sbfe(0, SizeBits).Ref();
    Dest = _Mul(OpSize::i64Bit, Src1, Src2);
    ResultHigh = _Sbfe(OpSize::i64Bit, SizeBits, SizeBits, Dest);
    break;
  }
  case OpSize::i32Bit: {
    ResultHigh = _SMull(Src1, Src2);
    ResultHigh = _Sbfe(OpSize::i64Bit, SizeBits, SizeBits, ResultHigh);
    // Flipped order to save a move
    Dest = _Mul(OpSize::i32Bit, Src1, Src2);
    break;
  }
  case OpSize::i64Bit: {
    ResultHigh = _MulH(OpSize::i64Bit, Src1, Src2);
    // Flipped order to save a move
    Dest = _Mul(OpSize::i64Bit, Src1, Src2);
    break;
  }
  default: FEX_UNREACHABLE;
  }

  StoreResultGPR(Op, Dest);
  CalculateFlags_MUL(Size, Dest, ResultHigh);
}

void OpDispatchBuilder::IMULOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);
  const auto SizeBits = IR::OpSizeAsBits(Size);

  Ref Src1 = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  Ref Src2 = LoadGPRRegister(X86State::REG_RAX);

  if (Size != OpSize::i64Bit) {
    Src1 = _Sbfe(OpSize::i64Bit, SizeBits, 0, Src1);
    Src2 = _Sbfe(OpSize::i64Bit, SizeBits, 0, Src2);
  }

  // 64-bit special cased to save a move
  Ref Result {};
  if (Size < OpSize::i64Bit) {
    Result = _Mul(OpSize::i64Bit, Src1, Src2);
  }
  Ref ResultHigh {};
  if (Size == OpSize::i8Bit) {
    // Result is stored in AX
    StoreGPRRegister(X86State::REG_RAX, Result, OpSize::i16Bit);
    ResultHigh = _Sbfe(OpSize::i64Bit, 8, 8, Result);
  } else if (Size == OpSize::i16Bit) {
    // 16bits stored in AX
    // 16bits stored in DX
    StoreGPRRegister(X86State::REG_RAX, Result, Size);
    ResultHigh = _Sbfe(OpSize::i64Bit, 16, 16, Result);
    StoreGPRRegister(X86State::REG_RDX, ResultHigh, Size);
  } else if (Size == OpSize::i32Bit) {
    // 32bits stored in EAX
    // 32bits stored in EDX
    // Make sure they get Zext correctly
    auto LocalResult = _Bfe(OpSize::i64Bit, 32, 0, Result);
    auto LocalResultHigh = _Bfe(OpSize::i64Bit, 32, 32, Result);
    ResultHigh = _Sbfe(OpSize::i64Bit, 32, 32, Result);
    Result = _Sbfe(OpSize::i64Bit, 32, 0, Result);
    StoreGPRRegister(X86State::REG_RAX, LocalResult);
    StoreGPRRegister(X86State::REG_RDX, LocalResultHigh);
  } else if (Size == OpSize::i64Bit) {
    if (!Is64BitMode) {
      LogMan::Msg::EFmt("Doesn't exist in 32bit mode");
      DecodeFailure = true;
      return;
    }
    // 64bits stored in RAX
    // 64bits stored in RDX
    ResultHigh = _MulH(OpSize::i64Bit, Src1, Src2);
    Result = _Mul(OpSize::i64Bit, Src1, Src2);
    StoreGPRRegister(X86State::REG_RAX, Result);
    StoreGPRRegister(X86State::REG_RDX, ResultHigh);
  }

  CalculateFlags_MUL(Size, Result, ResultHigh);
}

void OpDispatchBuilder::MULOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);
  const auto SizeBits = IR::OpSizeAsBits(Size);

  Ref Src1 = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  Ref Src2 = LoadGPRRegister(X86State::REG_RAX);
  Ref Result {};

  if (Size != OpSize::i64Bit) {
    Src1 = _Bfe(OpSize::i64Bit, SizeBits, 0, Src1);
    Src2 = _Bfe(OpSize::i64Bit, SizeBits, 0, Src2);
    Result = _UMul(OpSize::i64Bit, Src1, Src2);
  }
  Ref ResultHigh {};

  if (Size == OpSize::i8Bit) {
    // Result is stored in AX
    StoreGPRRegister(X86State::REG_RAX, Result, OpSize::i16Bit);
    ResultHigh = _Bfe(OpSize::i64Bit, 8, 8, Result);
  } else if (Size == OpSize::i16Bit) {
    // 16bits stored in AX
    // 16bits stored in DX
    StoreGPRRegister(X86State::REG_RAX, Result, Size);
    ResultHigh = _Bfe(OpSize::i64Bit, 16, 16, Result);
    StoreGPRRegister(X86State::REG_RDX, ResultHigh, Size);
  } else if (Size == OpSize::i32Bit) {
    // 32bits stored in EAX
    // 32bits stored in EDX
    Ref ResultLow = _Bfe(OpSize::i64Bit, 32, 0, Result);
    ResultHigh = _Bfe(OpSize::i64Bit, 32, 32, Result);
    StoreGPRRegister(X86State::REG_RAX, ResultLow);
    StoreGPRRegister(X86State::REG_RDX, ResultHigh);
  } else if (Size == OpSize::i64Bit) {
    if (!Is64BitMode) {
      LogMan::Msg::EFmt("Doesn't exist in 32bit mode");
      DecodeFailure = true;
      return;
    }
    // 64bits stored in RAX
    // 64bits stored in RDX
    //
    // Calculate high first to allow better RA.
    ResultHigh = _UMulH(OpSize::i64Bit, Src1, Src2);
    Result = _UMul(OpSize::i64Bit, Src1, Src2);
    StoreGPRRegister(X86State::REG_RAX, Result);
    StoreGPRRegister(X86State::REG_RDX, ResultHigh);
  }

  CalculateFlags_UMUL(ResultHigh);
}

void OpDispatchBuilder::NOTOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);
  const auto SizeBits = IR::OpSizeAsBits(Size);
  LOGMAN_THROW_A_FMT(Size >= IR::OpSize::i8Bit && Size <= IR::OpSize::i64Bit, "Invalid size");

  Ref MaskConst {};
  if (Size == OpSize::i64Bit) {
    MaskConst = Constant(~0ULL);
  } else {
    MaskConst = Constant((1ULL << SizeBits) - 1);
  }

  if (DestIsLockedMem(Op)) {
    HandledLock = true;
    Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
    // Result unused
    _AtomicFetchXor(Size, MaskConst, DestMem);
  } else if (!Op->Dest.IsGPR()) {
    // GPR version plays fast and loose with sizes, be safe for memory tho.
    Ref Src = LoadSourceGPR(Op, Op->Dest, Op->Flags);
    Src = _Xor(OpSize::i64Bit, Src, MaskConst);
    StoreResultGPR(Op, Src);
  } else {
    // Specially handle high bits so we can invert in place with the correct
    // mask and a larger type.
    auto Dest = Op->Dest;
    if (Dest.Data.GPR.HighBits) {
      LOGMAN_THROW_A_FMT(Size == OpSize::i8Bit, "Only 8-bit GPRs get high bits");
      MaskConst = Constant(0xFF00);
      Dest.Data.GPR.HighBits = false;
    }

    // Always load full size, we explicitly want the upper bits to get the
    // insert behaviour for free/implicitly.
    const auto GPRSize = GetGPROpSize();
    Ref Src = LoadSourceGPR_WithOpSize(Op, Dest, GPRSize, Op->Flags);

    // For 8/16-bit, use 64-bit invert so we invert in place, while getting
    // insert behaviour. For 32-bit, use 32-bit invert to zero the upper bits.
    const auto EffectiveSize = Size == OpSize::i32Bit ? OpSize::i32Bit : GPRSize;

    // If we're inverting the whole thing, use Not instead of Xor to save a constant.
    if (Size >= OpSize::i32Bit) {
      Src = _Not(EffectiveSize, Src);
    } else {
      Src = _Xor(EffectiveSize, Src, MaskConst);
    }

    // Always store 64-bit, the Not/Xor correctly handle the upper bits and this
    // way we can delete the store.
    StoreResultGPR_WithOpSize(Op, Dest, Src, GPRSize);
  }
}

void OpDispatchBuilder::XADDOp(OpcodeArgs) {
  Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.LoadData = false});
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
  Ref Result;

  if (Op->Dest.IsGPR()) {
    // If this is a GPR then we can just do an Add
    Result = CalculateFlags_ADD(OpSizeFromSrc(Op), Dest, Src);

    // Previous value in dest gets stored in src
    StoreResultGPR(Op, Op->Src[0], Dest);

    // Calculated value gets stored in dst (order is important if dst is same as src)
    StoreResultGPR(Op, Result);
  } else {
    HandledLock = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK;
    Dest = AppendSegmentOffset(Dest, Op->Flags);
    auto Before = _AtomicFetchAdd(OpSizeFromSrc(Op), Src, Dest);
    CalculateFlags_ADD(OpSizeFromSrc(Op), Before, Src);
    StoreResultGPR(Op, Op->Src[0], Before);
  }
}

void OpDispatchBuilder::PopcountOp(OpcodeArgs) {
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = CTX->HostFeatures.SupportsCSSC || GetSrcSize(Op) >= 4});
  Src = _Popcount(OpSizeFromSrc(Op), Src);
  StoreResultGPR(Op, Src);

  // We need to set ZF while clearing the rest of NZCV. The result of a popcount
  // is in the range [0, 63]. In particular, it is always positive. So a
  // combined NZ test will correctly zero SF/CF/OF while setting ZF.
  SetNZ_ZeroCV(OpSize::i32Bit, Src);
  ZeroPF_AF();
}

Ref OpDispatchBuilder::CalculateAFForDecimal(Ref A) {
  auto Nibble = _And(OpSize::i64Bit, A, Constant(0xF));
  auto Greater = Select01(OpSize::i64Bit, CondClass::UGT, Nibble, Constant(9));

  return _Or(OpSize::i64Bit, LoadAF(), Greater);
}

void OpDispatchBuilder::DAAOp(OpcodeArgs) {
  CalculateDeferredFlags();
  auto AL = LoadGPRRegister(X86State::REG_RAX, OpSize::i8Bit);
  auto CFInv = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC, true);
  auto AF = CalculateAFForDecimal(AL);

  // CF |= (AL > 0x99);
  CFInv = _And(OpSize::i64Bit, CFInv, Select01(OpSize::i64Bit, CondClass::ULE, AL, Constant(0x99)));

  // AL = AF ? (AL + 0x6) : AL;
  AL = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::NEQ, AF, Constant(0), Add(OpSize::i64Bit, AL, 0x6), AL);

  // AL = CF ? (AL + 0x60) : AL;
  AL = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, CFInv, Constant(0), Add(OpSize::i64Bit, AL, 0x60), AL);

  // SF, ZF, PF set according to result. CF set per above. OF undefined.
  StoreGPRRegister(X86State::REG_RAX, AL, OpSize::i8Bit);
  SetNZ_ZeroCV(OpSize::i8Bit, AL);
  SetCFInverted(CFInv);
  CalculatePF(AL);
  SetAFAndFixup(AF);
}

void OpDispatchBuilder::DASOp(OpcodeArgs) {
  CalculateDeferredFlags();
  auto AL = LoadGPRRegister(X86State::REG_RAX, OpSize::i8Bit);
  auto CF = GetRFLAG(FEXCore::X86State::RFLAG_CF_RAW_LOC);
  auto AF = CalculateAFForDecimal(AL);

  // CF |= (AL > 0x99);
  CF = _Or(OpSize::i64Bit, CF, Select01(OpSize::i64Bit, CondClass::UGT, AL, Constant(0x99)));

  // NewCF = CF | (AF && (Borrow from AL - 6))
  auto NewCF = _Or(OpSize::i32Bit, CF, _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::ULT, AL, Constant(6), AF, CF));

  // AL = AF ? (AL - 0x6) : AL;
  AL = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::NEQ, AF, Constant(0), Sub(OpSize::i64Bit, AL, 0x6), AL);

  // AL = CF ? (AL - 0x60) : AL;
  AL = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::NEQ, CF, Constant(0), Sub(OpSize::i64Bit, AL, 0x60), AL);

  // SF, ZF, PF set according to result. CF set per above. OF undefined.
  StoreGPRRegister(X86State::REG_RAX, AL, OpSize::i8Bit);
  SetNZ_ZeroCV(OpSize::i8Bit, AL);
  SetCFDirect(NewCF);
  CalculatePF(AL);
  SetAFAndFixup(AF);
}

void OpDispatchBuilder::AAAOp(OpcodeArgs) {
  auto A = LoadGPRRegister(X86State::REG_RAX);
  auto AF = CalculateAFForDecimal(A);

  // CF = AF, OF/SF/ZF/PF undefined
  SetCFDirect_InvalidateNZV(AF);
  SetAFAndFixup(AF);
  CalculateDeferredFlags();

  // AX = CF ? (AX + 0x106) : 0
  A = NZCVSelect(OpSize::i32Bit, CondClass::UGE /* CF = 1 */, Add(OpSize::i32Bit, A, 0x106), A);

  // AL = AL & 0x0F
  A = _And(OpSize::i32Bit, A, Constant(0xFF0F));
  StoreGPRRegister(X86State::REG_RAX, A, OpSize::i16Bit);
}

void OpDispatchBuilder::AASOp(OpcodeArgs) {
  auto A = LoadGPRRegister(X86State::REG_RAX);
  auto AF = CalculateAFForDecimal(A);

  // CF = AF, OF/SF/ZF/PF undefined
  SetCFDirect_InvalidateNZV(AF);
  SetAFAndFixup(AF);
  CalculateDeferredFlags();

  // AX = CF ? (AX - 0x106) : 0
  A = NZCVSelect(OpSize::i32Bit, CondClass::UGE /* CF = 1 */, Sub(OpSize::i32Bit, A, 0x106), A);

  // AL = AL & 0x0F
  A = _And(OpSize::i32Bit, A, Constant(0xFF0F));
  StoreGPRRegister(X86State::REG_RAX, A, OpSize::i16Bit);
}

void OpDispatchBuilder::AAMOp(OpcodeArgs) {
  auto AL = LoadGPRRegister(X86State::REG_RAX, OpSize::i8Bit);
  auto Imm8 = Constant(Op->Src[0].Literal() & 0xFF);
  Ref Quotient = _AllocateGPR(true);
  Ref Remainder = _AllocateGPR(true);
  _UDiv(OpSize::i64Bit, AL, Invalid(), Imm8, Quotient, Remainder, Invalid());
  auto Res = _AddShift(OpSize::i64Bit, Remainder, Quotient, ShiftType::LSL, 8);
  StoreGPRRegister(X86State::REG_RAX, Res, OpSize::i16Bit);

  SetNZ_ZeroCV(OpSize::i8Bit, Res);
  CalculatePF(Res);
  InvalidateAF();
}

void OpDispatchBuilder::AADOp(OpcodeArgs) {
  auto A = LoadGPRRegister(X86State::REG_RAX);
  auto AH = _Lshr(OpSize::i32Bit, A, Constant(8));
  auto Imm8 = Constant(Op->Src[0].Literal() & 0xFF);
  auto NewAL = Add(OpSize::i64Bit, A, _Mul(OpSize::i64Bit, AH, Imm8));
  auto Result = _And(OpSize::i64Bit, NewAL, Constant(0xFF));
  StoreGPRRegister(X86State::REG_RAX, Result, OpSize::i16Bit);

  SetNZ_ZeroCV(OpSize::i8Bit, Result);
  CalculatePF(Result);
  InvalidateAF();
}

void OpDispatchBuilder::XLATOp(OpcodeArgs) {
  Ref Src = MakeSegmentAddress(X86State::REG_RBX, Op->Flags, X86Tables::DecodeFlags::FLAG_DS_PREFIX);
  Ref Offset = LoadGPRRegister(X86State::REG_RAX, OpSize::i8Bit);

  AddressMode A = {.Base = Src, .Index = Offset, .AddrSize = OpSize::i64Bit};
  auto Res = _LoadMemGPRAutoTSO(OpSize::i8Bit, A, OpSize::i8Bit);

  StoreGPRRegister(X86State::REG_RAX, Res, OpSize::i8Bit);
}

void OpDispatchBuilder::ReadSegmentReg(OpcodeArgs, OpDispatchBuilder::Segment Seg) {
  // 64-bit only
  // Doesn't hit the segment register optimization
  const auto Size = OpSizeFromSrc(Op);
  Ref Src {};
  if (Seg == Segment::FS) {
    Src = _LoadContextGPR(Size, offsetof(FEXCore::Core::CPUState, fs_cached));
  } else {
    Src = _LoadContextGPR(Size, offsetof(FEXCore::Core::CPUState, gs_cached));
  }

  StoreResultGPR(Op, Src);
}

void OpDispatchBuilder::WriteSegmentReg(OpcodeArgs, OpDispatchBuilder::Segment Seg) {
  // Documentation claims that the 32-bit version of this instruction inserts in to the lower 32-bits of the segment
  // This is incorrect and it instead zero extends the 32-bit value to 64-bit
  const auto Size = OpSizeFromDst(Op);
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
  if (Seg == Segment::FS) {
    _StoreContextGPR(Size, Src, offsetof(FEXCore::Core::CPUState, fs_cached));
  } else {
    _StoreContextGPR(Size, Src, offsetof(FEXCore::Core::CPUState, gs_cached));
  }
}

void OpDispatchBuilder::EnterOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  const auto OperandSize = (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_OPERAND_SIZE) ? OpSize::i16Bit : GPRSize;
  const uint64_t Value = Op->Src[0].Literal();

  const uint16_t AllocSpace = Value & 0xFFFF;
  const uint8_t Level = (Value >> 16) & 0x1F;

  const auto PushValue = [&](IR::OpSize Size, Ref Src) -> Ref {
    auto OldSP = LoadGPRRegister(X86State::REG_RSP);
    auto NewSP = _Push(GPRSize, Size, Src, OldSP);

    // Store the new stack pointer
    StoreGPRRegister(X86State::REG_RSP, NewSP);
    return NewSP;
  };

  auto OldBP = LoadGPRRegister(X86State::REG_RBP);
  auto NewSP = PushValue(OperandSize, OldBP);
  auto temp_RBP = NewSP;

  if (Level > 0) {
    for (uint8_t i = 1; i < Level; ++i) {
      auto MemLoc = Sub(GPRSize, OldBP, i * IR::OpSizeToSize(OperandSize));
      auto Mem = _LoadMemGPR(OperandSize, MemLoc, OperandSize);
      NewSP = PushValue(OperandSize, Mem);
    }
    NewSP = PushValue(OperandSize, temp_RBP);
  }
  NewSP = Sub(GPRSize, NewSP, AllocSpace);
  StoreGPRRegister(X86State::REG_RSP, NewSP);
  StoreGPRRegister(X86State::REG_RBP, temp_RBP);
}

void OpDispatchBuilder::SGDTOp(OpcodeArgs) {
  auto DestAddress = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.LoadData = false});

  // Store an emulated value in the format of:
  // uint16_t Limit;
  // {uint32_t,uint64_t} Base;
  //
  // Limit is always 0
  // Base is always in kernel space at: 0xFFFFFFFFFFFE0000ULL
  //
  // Operand size prefix is ignored on this instruction, size purely depends on operating mode.
  uint64_t GDTAddress = 0xFFFFFFFFFFFE0000ULL;
  auto GDTStoreSize = OpSize::i64Bit;
  if (!Is64BitMode) {
    // Mask off upper bits if 32-bit result.
    GDTAddress &= ~0U;
    GDTStoreSize = OpSize::i32Bit;
  }

  _StoreMemGPRAutoTSO(OpSize::i16Bit, DestAddress, Constant(0));
  _StoreMemGPRAutoTSO(GDTStoreSize, AddressMode {.Base = DestAddress, .Offset = 2, .AddrSize = OpSize::i64Bit}, Constant(GDTAddress));
}

void OpDispatchBuilder::SIDTOp(OpcodeArgs) {
  auto DestAddress = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.LoadData = false});

  // See SGDTOp, matches Linux in reported values
  uint64_t IDTAddress = 0xFFFFFE0000000000ULL;
  auto IDTStoreSize = OpSize::i64Bit;
  if (!Is64BitMode) {
    // Mask off upper bits if 32-bit result.
    IDTAddress &= ~0U;
    IDTStoreSize = OpSize::i32Bit;
  }

  _StoreMemGPRAutoTSO(OpSize::i16Bit, DestAddress, Constant(0xfff));
  _StoreMemGPRAutoTSO(IDTStoreSize, AddressMode {.Base = DestAddress, .Offset = 2, .AddrSize = OpSize::i64Bit}, Constant(IDTAddress));
}

void OpDispatchBuilder::SMSWOp(OpcodeArgs) {
  const bool IsMemDst = DestIsMem(Op);

  IR::OpSize DstSize {OpSize::iInvalid};
  Ref Const = Constant((1U << 31) | ///< PG - Paging
                       (0U << 30) | ///< CD - Cache Disable
                       (0U << 29) | ///< NW - Not Writethrough (Legacy, now ignored)
                       ///< [28:19] - Reserved
                       (1U << 18) | ///< AM - Alignment Mask
                       ///< 17 - Reserved
                       (1U << 16) | ///< WP - Write Protect
                       ///< [15:6] - Reserved
                       (1U << 5) | ///< NE - Numeric Error
                       (1U << 4) | ///< ET - Extension Type (Legacy, now reserved and 1)
                       (0U << 3) | ///< TS - Task Switched
                       (0U << 2) | ///< EM - Emulation
                       (1U << 1) | ///< MP - Monitor Coprocessor
                       (1U << 0)); ///< PE - Protection Enabled
  const auto OpAddr = X86Tables::DecodeFlags::GetOpAddr(Op->Flags, 0);
  if (Is64BitMode) {
    DstSize = OpAddr == X86Tables::DecodeFlags::FLAG_OPERAND_SIZE_LAST  ? OpSize::i16Bit :
              OpAddr == X86Tables::DecodeFlags::FLAG_WIDENING_SIZE_LAST ? OpSize::i64Bit :
                                                                          OpSize::i32Bit;

    if (!IsMemDst && DstSize == OpSize::i32Bit) {
      // Special-case version of `smsw ebx`. This instruction does an insert in to the lower 32-bits on 64-bit hosts.
      // Override and insert.
      auto Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, GetGPROpSize(), Op->Flags);
      Const = _Bfi(OpSize::i64Bit, 32, 0, Dest, Const);
      DstSize = OpSize::i64Bit;
    }
  } else {
    DstSize = OpAddr == X86Tables::DecodeFlags::FLAG_OPERAND_SIZE_LAST ? OpSize::i16Bit : OpSize::i32Bit;
  }

  if (IsMemDst) {
    // Memory destinatino always writes only 16-bits.
    DstSize = OpSize::i16Bit;
  }

  StoreResultGPR_WithOpSize(Op, Op->Dest, Const, DstSize);
}

OpDispatchBuilder::CycleCounterPair OpDispatchBuilder::CycleCounter(bool SelfSynchronizingLoads) {
  Ref CounterLow {};
  Ref CounterHigh {};
  auto Counter = _CycleCounter(SelfSynchronizingLoads);
  if (CTX->Config.TSCScale) {
    CounterLow = _Lshl(OpSize::i32Bit, Counter, Constant(CTX->Config.TSCScale));
    CounterHigh = _Lshr(OpSize::i64Bit, Counter, Constant(32 - CTX->Config.TSCScale));
  } else {
    CounterLow = _Bfe(OpSize::i64Bit, 32, 0, Counter);
    CounterHigh = _Bfe(OpSize::i64Bit, 32, 32, Counter);
  }

  return {
    .CounterLow = CounterLow,
    .CounterHigh = CounterHigh,
  };
}

void OpDispatchBuilder::RDTSCOp(OpcodeArgs) {
  auto Counter = CycleCounter(false);
  StoreGPRRegister(X86State::REG_RAX, Counter.CounterLow);
  StoreGPRRegister(X86State::REG_RDX, Counter.CounterHigh);
}

void OpDispatchBuilder::INCOp(OpcodeArgs) {
  Ref Dest;
  Ref Result;
  const auto Size = GetSrcBitSize(Op);
  const bool IsLocked = DestIsLockedMem(Op);
  const bool StoredBeforeFlags = !IsLocked && !Op->Dest.IsGPR() && MacRunnerRMWFlagsAfterStore();

  if (IsLocked) {
    HandledLock = true;

    Ref DestAddress = MakeSegmentAddress(Op, Op->Dest);
    Dest = _AtomicFetchAdd(OpSizeFromSrc(Op), Constant(1), DestAddress);
  } else {
    Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = Size >= 32});
  }

  if (StoredBeforeFlags) {
    Result = Add(std::max(OpSizeFromSrc(Op), OpSize::i32Bit), Dest, 1);
    StoreResultGPR(Op, Result);
  }

  CalculateDeferredFlags();

  if (Size < 32 && CTX->HostFeatures.SupportsFlagM) {
    // Addition producing upper garbage
    Result = Add(OpSize::i32Bit, Dest, 1);
    CalculatePF(Result);
    CalculateAF(Dest, Constant(1));

    // Correctly set NZ flags, preserving C
    HandleNZCV_RMW();
    _SetSmallNZV(OpSizeFromSrc(Op), Result);

    // Fix up V flag. INC overflows only when incrementing a positive and
    // getting a negative. So compare the sign bits to calculate V.
    _RmifNZCV(_Andn(OpSize::i32Bit, Result, Dest), Size - 1, 1);
  } else {
    Result = CalculateFlags_ADD(OpSizeFromSrc(Op), Dest, Constant(1), false);
  }

  if (!IsLocked && !StoredBeforeFlags) {
    StoreResultGPR(Op, Result);
  }
}

void OpDispatchBuilder::DECOp(OpcodeArgs) {
  Ref Dest;
  Ref Result;
  const auto Size = GetSrcBitSize(Op);
  const bool IsLocked = DestIsLockedMem(Op);
  const bool StoredBeforeFlags = !IsLocked && !Op->Dest.IsGPR() && MacRunnerRMWFlagsAfterStore();

  if (IsLocked) {
    HandledLock = true;

    Ref DestAddress = MakeSegmentAddress(Op, Op->Dest);

    // Use Add instead of Sub to avoid a NEG
    Dest = _AtomicFetchAdd(OpSizeFromSrc(Op), Constant(Size == 64 ? -1 : ((1ULL << Size) - 1)), DestAddress);
  } else {
    Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = Size >= 32});
  }

  if (StoredBeforeFlags) {
    Result = Sub(std::max(OpSizeFromSrc(Op), OpSize::i32Bit), Dest, 1);
    StoreResultGPR(Op, Result);
  }

  CalculateDeferredFlags();

  if (Size < 32 && CTX->HostFeatures.SupportsFlagM) {
    // Subtraction producing upper garbage
    Result = Sub(OpSize::i32Bit, Dest, 1);
    CalculatePF(Result);
    CalculateAF(Dest, Constant(1));

    // Correctly set NZ flags, preserving C
    HandleNZCV_RMW();
    _SetSmallNZV(OpSizeFromSrc(Op), Result);

    // Fix up V flag. DEC overflows only when decrementing a negative and
    // getting a positive. So compare the sign bits to calculate V.
    _RmifNZCV(_Andn(OpSize::i32Bit, Dest, Result), Size - 1, 1);
  } else {
    Result = CalculateFlags_SUB(OpSizeFromSrc(Op), Dest, Constant(1), false);
  }

  if (!IsLocked && !StoredBeforeFlags) {
    StoreResultGPR(Op, Result);
  }
}

void OpDispatchBuilder::STOSOp(OpcodeArgs) {
  if (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE) {
    LogMan::Msg::EFmt("STOSOp: Can't handle address size override (OP: 0x{:04X}, Flags: 0x{:08X})", Op->OP, Op->Flags);
    DecodeFailure = true;
    return;
  }

  const auto Size = OpSizeFromSrc(Op);
  const bool Repeat = (Op->Flags & (FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX | FEXCore::X86Tables::DecodeFlags::FLAG_REPNE_PREFIX)) != 0;

  if (!Repeat) {
    // Src is used only for a store of the same size so allow garbage
    Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

    // Only ES prefix
    Ref Dest = MakeSegmentAddress(X86State::REG_RDI, 0, X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);

    // Store to memory where RDI points
    if (CTX->IsMemcpyAtomicTSOEnabled()) {
      _StoreMemGPRAutoTSO(Size, Dest, Src, Size);
    } else {
      _StoreMem(RegClass::GPR, Size, Src, Dest, Invalid(), OpSize::i8Bit, MemOffsetType::SXTX, 1);
    }

    // Offset the pointer
    Ref TailDest = LoadGPRRegister(X86State::REG_RDI);
    StoreGPRRegister(X86State::REG_RDI, OffsetByDir(TailDest, IR::OpSizeToSize(Size)));
  } else {
    // FEX doesn't support partial faulting REP instructions.
    // Converting this to a `MemSet` IR op optimizes this quite significantly in our codegen.
    // If FEX is to gain support for faulting REP instructions, then this implementation needs to change significantly.
    Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    Ref Dest = LoadGPRRegister(X86State::REG_RDI);

    // Only ES prefix
    auto Segment = GetSegment(0, FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);

    Ref Counter = LoadGPRRegister(X86State::REG_RCX);

    auto Result = _MemSet(CTX->IsAtomicTSOEnabled(), Size, Segment ?: InvalidNode, Dest, Src, Counter, LoadDir(1));
    StoreGPRRegister(X86State::REG_RCX, Constant(0));
    StoreGPRRegister(X86State::REG_RDI, Result);
  }
}

void OpDispatchBuilder::MOVSOp(OpcodeArgs) {
  if (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE) {
    LogMan::Msg::EFmt("MOVSOp: Can't handle address size override (OP: 0x{:04X}, Flags: 0x{:08X})", Op->OP, Op->Flags);
    DecodeFailure = true;
    return;
  }

  // RA now can handle these to be here, to avoid DF accesses
  const auto Size = OpSizeFromSrc(Op);

  if (Op->Flags & (FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX | FEXCore::X86Tables::DecodeFlags::FLAG_REPNE_PREFIX)) {
    auto SrcAddr = LoadGPRRegister(X86State::REG_RSI);
    auto DstAddr = LoadGPRRegister(X86State::REG_RDI);
    auto Counter = LoadGPRRegister(X86State::REG_RCX);

    auto DstSegment = GetSegment(0, FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);
    auto SrcSegment = GetSegment(Op->Flags, FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX);

    if (DstSegment) {
      DstAddr = Add(OpSize::i64Bit, DstAddr, DstSegment);
    }

    if (SrcSegment) {
      SrcAddr = Add(OpSize::i64Bit, SrcAddr, SrcSegment);
    }

    Ref Result_Src = _AllocateGPR(false);
    Ref Result_Dst = _AllocateGPR(false);
    _MemCpy(CTX->IsAtomicTSOEnabled(), Size, DstAddr, SrcAddr, Counter, LoadDir(1), Result_Dst, Result_Src);

    if (DstSegment) {
      Result_Dst = Sub(OpSize::i64Bit, Result_Dst, DstSegment);
    }

    if (SrcSegment) {
      Result_Src = Sub(OpSize::i64Bit, Result_Src, SrcSegment);
    }

    StoreGPRRegister(X86State::REG_RCX, Constant(0));
    StoreGPRRegister(X86State::REG_RDI, Result_Dst);
    StoreGPRRegister(X86State::REG_RSI, Result_Src);
  } else {
    Ref RSI = MakeSegmentAddress(X86State::REG_RSI, Op->Flags, X86Tables::DecodeFlags::FLAG_DS_PREFIX);
    Ref RDI = MakeSegmentAddress(X86State::REG_RDI, 0, X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);

    if (CTX->IsMemcpyAtomicTSOEnabled()) {
      auto Src = _LoadMemGPRAutoTSO(Size, RSI, Size);

      // Store to memory where RDI points
      _StoreMemGPRAutoTSO(Size, RDI, Src, Size);
    } else {
      auto Src = _LoadMem(RegClass::GPR, Size, RSI, Invalid(), OpSize::i8Bit, MemOffsetType::SXTX, 1);
      _StoreMem(RegClass::GPR, Size, Src, RDI, Invalid(), OpSize::i8Bit, MemOffsetType::SXTX, 1);
    }

    RSI = OffsetByDir(RSI, IR::OpSizeToSize(Size));
    RDI = OffsetByDir(RDI, IR::OpSizeToSize(Size));

    StoreGPRRegister(X86State::REG_RSI, RSI);
    StoreGPRRegister(X86State::REG_RDI, RDI);
  }
}

IR::OpSize OpDispatchBuilder::GetStringOpSize(X86Tables::DecodedOp Op) const {
  LOGMAN_THROW_A_FMT(Is64BitMode || !(Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE), "Invalid modifier on 32bit address");
  return !Is64BitMode || (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE) ? OpSize::i32Bit : OpSize::i64Bit;
}

void OpDispatchBuilder::CMPSOp(OpcodeArgs) {
  if (!Is64BitMode && (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE)) {
    LogMan::Msg::EFmt("CMPSOp: Address size override (0x67) not supported in 32-bit mode (OP: 0x{:04X}).", Op->OP);
    DecodeFailure = true;
    return;
  }

  const auto Size = OpSizeFromSrc(Op);
  OpSize AddrSize = GetStringOpSize(Op);

  bool Repeat = Op->Flags & (FEXCore::X86Tables::DecodeFlags::FLAG_REPNE_PREFIX | FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX);
  if (!Repeat) {
    Ref Src_RSI = LoadGPRRegister(X86State::REG_RSI, AddrSize);
    Ref Src_RDI = LoadGPRRegister(X86State::REG_RDI, AddrSize);

    Ref Dest_RSI = AppendSegmentOffset(Src_RSI, Op->Flags, X86Tables::DecodeFlags::FLAG_DS_PREFIX);
    Ref Dest_RDI = AppendSegmentOffset(Src_RDI, 0, X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);

    auto Src1 = _LoadMemGPRAutoTSO(Size, Dest_RDI, Size);
    auto Src2 = _LoadMemGPRAutoTSO(Size, Dest_RSI, Size);

    CalculateFlags_SUB(OpSizeFromSrc(Op), Src2, Src1);

    Dest_RDI = OffsetByDir(Src_RDI, IR::OpSizeToSize(Size));
    if (Is64BitMode && AddrSize == OpSize::i32Bit) {
      Dest_RDI = _Bfe(OpSize::i64Bit, 32, 0, Dest_RDI);
      StoreGPRRegister(X86State::REG_RDI, Dest_RDI);
    } else {
      StoreGPRRegister(X86State::REG_RDI, Dest_RDI, AddrSize);
    }

    Dest_RSI = OffsetByDir(Src_RSI, IR::OpSizeToSize(Size));
    if (Is64BitMode && AddrSize == OpSize::i32Bit) {
      Dest_RSI = _Bfe(OpSize::i64Bit, 32, 0, Dest_RSI);
      StoreGPRRegister(X86State::REG_RSI, Dest_RSI);
    } else {
      StoreGPRRegister(X86State::REG_RSI, Dest_RSI, AddrSize);
    }
  } else {
    // Calculate flags early.
    CalculateDeferredFlags();

    bool REPE = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX;

    // If rcx = 0, skip the whole loop.
    Ref Counter = LoadGPRRegister(X86State::REG_RCX);
    auto OuterJump = CondJump(Counter, CondClass::EQ);

    auto BeforeLoop = CreateNewCodeBlockAfter(GetCurrentBlock());
    SetFalseJumpTarget(OuterJump, BeforeLoop);
    SetCurrentCodeBlock(BeforeLoop);
    StartNewBlock();

    ForeachDirection([this, Op, Size, AddrSize, REPE](int32_t PtrDir) {
      IRPair<IROp_CondJump> InnerJump;
      auto JumpIntoLoop = Jump();

      // Setup for the loop
      auto LoopHeader = CreateNewCodeBlockAfter(GetCurrentBlock());
      SetCurrentCodeBlock(LoopHeader);
      StartNewBlock();
      SetJumpTarget(JumpIntoLoop, LoopHeader);

      // Working loop
      {
        Ref Src_RSI = LoadGPRRegister(X86State::REG_RSI, AddrSize);
        Ref Src_RDI = LoadGPRRegister(X86State::REG_RDI, AddrSize);

        Ref Dest_RSI = AppendSegmentOffset(Src_RSI, Op->Flags, X86Tables::DecodeFlags::FLAG_DS_PREFIX);
        Ref Dest_RDI = AppendSegmentOffset(Src_RDI, 0, X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);

        auto Src1 = _LoadMemGPRAutoTSO(Size, Dest_RDI, Size);
        auto Src2 = _LoadMemGPR(Size, Dest_RSI, Size);

        // We'll calculate PF/AF after the loop, so use them as temporaries here.
        StoreRegister(Core::CPUState::PF_AS_GREG, false, Src1);
        StoreRegister(Core::CPUState::AF_AS_GREG, false, Src2);

        Ref TailCounter = LoadGPRRegister(X86State::REG_RCX);

        // Decrement counter
        TailCounter = SubWithFlags(OpSize::i64Bit, TailCounter, 1);

        // Store the counter since we don't have phis
        StoreGPRRegister(X86State::REG_RCX, TailCounter);

        Dest_RDI = Add(AddrSize, Src_RDI, PtrDir * static_cast<int32_t>(IR::OpSizeToSize(Size)));
        if (Is64BitMode && AddrSize == OpSize::i32Bit) {
          Dest_RDI = _Bfe(OpSize::i64Bit, 32, 0, Dest_RDI);
          StoreGPRRegister(X86State::REG_RDI, Dest_RDI);
        } else {
          StoreGPRRegister(X86State::REG_RDI, Dest_RDI, AddrSize);
        }

        Dest_RSI = Add(AddrSize, Src_RSI, PtrDir * static_cast<int32_t>(IR::OpSizeToSize(Size)));
        if (Is64BitMode && AddrSize == OpSize::i32Bit) {
          Dest_RSI = _Bfe(OpSize::i64Bit, 32, 0, Dest_RSI);
          StoreGPRRegister(X86State::REG_RSI, Dest_RSI);
        } else {
          StoreGPRRegister(X86State::REG_RSI, Dest_RSI, AddrSize);
        }

        // If TailCounter != 0, compare sources.
        // If TailCounter == 0, set ZF iff that would break.
        _CondSubNZCV(OpSize::i64Bit, Src2, Src1, CondClass::NEQ, REPE ? 0 : (1 << 2) /* Z */);
        CachedNZCV = nullptr;
        NZCVDirty = false;
        InnerJump = CondJumpNZCV(REPE ? CondClass::EQ : CondClass::NEQ);

        // Jump back to the start if we have more work to do
        SetTrueJumpTarget(InnerJump, LoopHeader);
      }

      // Make sure to start a new block after ending this one
      auto LoopEnd = CreateNewCodeBlockAfter(GetCurrentBlock());
      SetFalseJumpTarget(InnerJump, LoopEnd);
      SetCurrentCodeBlock(LoopEnd);
      StartNewBlock();
    });

    // Make sure to start a new block after ending this one
    {
      // Grab the sources from the last iteration so we can set flags.
      auto Src1 = LoadGPR(Core::CPUState::PF_AS_GREG);
      auto Src2 = LoadGPR(Core::CPUState::AF_AS_GREG);
      CalculateFlags_SUB(OpSizeFromSrc(Op), Src2, Src1);
    }
    auto Jump_ = Jump();

    auto Exit = CreateNewCodeBlockAfter(GetCurrentBlock());
    SetJumpTarget(Jump_, Exit);
    SetTrueJumpTarget(OuterJump, Exit);
    SetCurrentCodeBlock(Exit);
    StartNewBlock();
  }
}

void OpDispatchBuilder::LODSOp(OpcodeArgs) {
  if (!Is64BitMode && (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE)) {
    LogMan::Msg::EFmt("LODSOp: Address size override (0x67) not supported in 32-bit mode (OP: 0x{:04X}).", Op->OP);
    DecodeFailure = true;
    return;
  }

  const auto Size = OpSizeFromSrc(Op);
  OpSize AddrSize = GetStringOpSize(Op);

  const bool Repeat = (Op->Flags & (FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX | FEXCore::X86Tables::DecodeFlags::FLAG_REPNE_PREFIX)) != 0;

  if (!Repeat) {
    Ref Src_RSI = LoadGPRRegister(X86State::REG_RSI, AddrSize);
    Ref Dest_RSI = AppendSegmentOffset(Src_RSI, 0, X86Tables::DecodeFlags::FLAG_DS_PREFIX, true);

    auto Src = _LoadMemGPRAutoTSO(Size, Dest_RSI, Size);

    StoreResultGPR(Op, Src);

    // Offset the pointer
    Ref TailDest_RSI = OffsetByDir(Src_RSI, IR::OpSizeToSize(Size));
    if (Is64BitMode && AddrSize == OpSize::i32Bit) {
      TailDest_RSI = _Bfe(OpSize::i64Bit, 32, 0, TailDest_RSI);
      StoreGPRRegister(X86State::REG_RSI, TailDest_RSI);
    } else {
      StoreGPRRegister(X86State::REG_RSI, TailDest_RSI, AddrSize);
    }
  } else {
    // Calculate flags early. because end of block
    CalculateDeferredFlags();

    ForeachDirection([this, Op, Size, AddrSize](int32_t PtrDir) {
      // XXX: Theoretically LODS could be optimized to
      // RSI += {-}(RCX * Size)
      // RAX = [RSI - Size]
      // But this might violate the case of an application scanning pages for read permission and catching the fault
      // May or may not matter

      auto JumpStart = Jump();
      // Make sure to start a new block after ending this one
      auto LoopStart = CreateNewCodeBlockAfter(GetCurrentBlock());
      SetJumpTarget(JumpStart, LoopStart);
      SetCurrentCodeBlock(LoopStart);
      StartNewBlock();

      Ref Counter = LoadGPRRegister(X86State::REG_RCX);

      // Can we end the block?

      // We leave if RCX = 0
      auto CondJump_ = CondJump(Counter, CondClass::EQ);

      auto LoopTail = CreateNewCodeBlockAfter(LoopStart);
      SetFalseJumpTarget(CondJump_, LoopTail);
      SetCurrentCodeBlock(LoopTail);
      StartNewBlock();

      // Working loop
      {
        Ref Src_RSI = LoadGPRRegister(X86State::REG_RSI, AddrSize);
        Ref Dest_RSI = AppendSegmentOffset(Src_RSI, 0, X86Tables::DecodeFlags::FLAG_DS_PREFIX, true);

        auto Src = _LoadMemGPRAutoTSO(Size, Dest_RSI, Size);

        StoreResultGPR(Op, Src);

        Ref TailCounter = LoadGPRRegister(X86State::REG_RCX);
        Ref TailDest_RSI = LoadGPRRegister(X86State::REG_RSI);

        // Decrement counter
        TailCounter = Sub(OpSize::i64Bit, TailCounter, 1);

        // Store the counter since we don't have phis
        StoreGPRRegister(X86State::REG_RCX, TailCounter);

        // Offset the pointer
        TailDest_RSI = Add(AddrSize, TailDest_RSI, PtrDir * static_cast<int32_t>(IR::OpSizeToSize(Size)));
        if (Is64BitMode && AddrSize == OpSize::i32Bit) {
          TailDest_RSI = _Bfe(OpSize::i64Bit, 32, 0, TailDest_RSI);
          StoreGPRRegister(X86State::REG_RSI, TailDest_RSI);
        } else {
          StoreGPRRegister(X86State::REG_RSI, TailDest_RSI, AddrSize);
        }

        // Jump back to the start, we have more work to do
        Jump(LoopStart);
      }
      // Make sure to start a new block after ending this one
      auto LoopEnd = CreateNewCodeBlockAfter(LoopTail);
      SetTrueJumpTarget(CondJump_, LoopEnd);
      SetCurrentCodeBlock(LoopEnd);
      StartNewBlock();
    });
  }
}

void OpDispatchBuilder::SCASOp(OpcodeArgs) {
  if (!Is64BitMode && (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE)) {
    LogMan::Msg::EFmt("SCASOp: Address size override (0x67) not supported in 32-bit mode (OP: 0x{:04X}).", Op->OP);
    DecodeFailure = true;
    return;
  }

  const auto Size = OpSizeFromSrc(Op);
  OpSize AddrSize = GetStringOpSize(Op);
  const bool Repeat = (Op->Flags & (FEXCore::X86Tables::DecodeFlags::FLAG_REPNE_PREFIX | FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX)) != 0;

  if (!Repeat) {
    Ref Src_RDI = LoadGPRRegister(X86State::REG_RDI, AddrSize);
    Ref Dest_RDI = AppendSegmentOffset(Src_RDI, 0, X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);

    auto Src1 = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
    auto Src2 = _LoadMemGPRAutoTSO(Size, Dest_RDI, Size);

    CalculateFlags_SUB(OpSizeFromSrc(Op), Src1, Src2);

    Ref TailDest_RDI = OffsetByDir(Src_RDI, IR::OpSizeToSize(Size));
    if (Is64BitMode && AddrSize == OpSize::i32Bit) {
      TailDest_RDI = _Bfe(OpSize::i64Bit, 32, 0, TailDest_RDI);
      StoreGPRRegister(X86State::REG_RDI, TailDest_RDI);
    } else {
      StoreGPRRegister(X86State::REG_RDI, TailDest_RDI, AddrSize);
    }
  } else {
    // Calculate flags early. because end of block
    CalculateDeferredFlags();

    ForeachDirection([this, Op, Size, AddrSize](int32_t Dir) {
      bool REPE = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REP_PREFIX;

      auto JumpStart = Jump();
      // Make sure to start a new block after ending this one
      auto LoopStart = CreateNewCodeBlockAfter(GetCurrentBlock());
      SetJumpTarget(JumpStart, LoopStart);
      SetCurrentCodeBlock(LoopStart);
      StartNewBlock();

      Ref Counter = LoadGPRRegister(X86State::REG_RCX);

      // Can we end the block?
      // We leave if RCX = 0
      auto CondJump_ = CondJump(Counter, CondClass::EQ);
      IRPair<IROp_CondJump> InternalCondJump;

      auto LoopTail = CreateNewCodeBlockAfter(LoopStart);
      SetFalseJumpTarget(CondJump_, LoopTail);
      SetCurrentCodeBlock(LoopTail);
      StartNewBlock();

      // Working loop
      {
        Ref Src_RDI = LoadGPRRegister(X86State::REG_RDI, AddrSize);
        Ref Dest_RDI = AppendSegmentOffset(Src_RDI, 0, X86Tables::DecodeFlags::FLAG_ES_PREFIX, true);

        auto Src1 = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
        auto Src2 = _LoadMemGPRAutoTSO(Size, Dest_RDI, Size);

        CalculateFlags_SUB(OpSizeFromSrc(Op), Src1, Src2);

        // Calculate flags early.
        CalculateDeferredFlags();

        Ref TailCounter = LoadGPRRegister(X86State::REG_RCX);
        Ref Src_RDI_Tail = LoadGPRRegister(X86State::REG_RDI, AddrSize);

        // Decrement counter
        TailCounter = Sub(OpSize::i64Bit, TailCounter, 1);

        // Store the counter since we don't have phis
        StoreGPRRegister(X86State::REG_RCX, TailCounter);

        Ref TailDest_RDI = Add(AddrSize, Src_RDI_Tail, Dir * static_cast<int32_t>(IR::OpSizeToSize(Size)));
        if (Is64BitMode && AddrSize == OpSize::i32Bit) {
          TailDest_RDI = _Bfe(OpSize::i64Bit, 32, 0, TailDest_RDI);
          StoreGPRRegister(X86State::REG_RDI, TailDest_RDI);
        } else {
          StoreGPRRegister(X86State::REG_RDI, TailDest_RDI, AddrSize);
        }

        CalculateDeferredFlags();
        InternalCondJump = CondJumpNZCV(REPE ? CondClass::EQ : CondClass::NEQ);

        // Jump back to the start if we have more work to do
        SetTrueJumpTarget(InternalCondJump, LoopStart);
      }
      // Make sure to start a new block after ending this one
      auto LoopEnd = CreateNewCodeBlockAfter(LoopTail);
      SetTrueJumpTarget(CondJump_, LoopEnd);

      SetFalseJumpTarget(InternalCondJump, LoopEnd);

      SetCurrentCodeBlock(LoopEnd);
      StartNewBlock();
    });
  }
}

void OpDispatchBuilder::BSWAPOp(OpcodeArgs) {
  Ref Dest;
  const auto Size = OpSizeFromSrc(Op);
  if (Size == OpSize::i16Bit) {
    // BSWAP of 16bit is undef. ZEN+ causes the lower 16bits to get zero'd
    Dest = Constant(0);
  } else {
    Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, GetGPROpSize(), Op->Flags);
    Dest = _Rev(Size, Dest);
  }
  StoreResultGPR(Op, Dest);
}

void OpDispatchBuilder::PUSHFOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);

  Ref Flags = GetPackedRFLAG();
  const char* Exact = std::getenv("MACRUNNER_WINCTX_EXACT");
  if (Exact && Exact[0] == '1' && !Exact[1]) {
    // PUSHF(D/Q) does not put RF or VM into its stack image.
    Flags = _And(OpSize::i64Bit, Flags, Constant(~0x30000ULL));
  }
  Push(Size, Flags);
}

void OpDispatchBuilder::POPFOp(OpcodeArgs) {
  const auto Size = OpSizeFromSrc(Op);
  Ref Src = Pop(Size);
  const char* Exact = std::getenv("MACRUNNER_WINCTX_EXACT");
  if (Exact && Exact[0] == '1' && !Exact[1]) {
    // POPF(D/Q) cannot set RF/VM from its operand in the supported user mode.
    Src = _And(OpSize::i64Bit, Src, Constant(~0x30000ULL));
  }

  // Add back our flag constants
  // Bit 1 is always 1
  // Bit 9 is always 1 because we always have interrupts enabled

  Src = _Or(OpSize::i64Bit, Src, Constant(0x202));

  SetPackedRFLAG(false, Src);

  auto NewRIP = GetRelocatedPC(Op);
  ExitFunction(NewRIP, BranchHint::CheckTF);
  BlockSetRIP = true;
}

void OpDispatchBuilder::NEGOp(OpcodeArgs) {
  HandledLock = (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK) != 0;

  const auto Size = OpSizeFromSrc(Op);
  auto ZeroConst = Constant(0);

  if (DestIsLockedMem(Op)) {
    Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
    Ref Dest = _AtomicFetchNeg(Size, DestMem);
    CalculateFlags_SUB(Size, ZeroConst, Dest);
  } else {
    Ref Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
    Ref Result = CalculateFlags_SUB(Size, ZeroConst, Dest);

    StoreResultGPR(Op, Result);
  }
}

// x86 raises #DE when the divisor is zero. AArch64's UDIV/SDIV do not trap at all -
// they quietly produce a zero quotient - so the check has to be materialised here,
// otherwise a guest that expects STATUS_INTEGER_DIVIDE_BY_ZERO silently continues
// with a wrong value.
//
// The fault reports the address of the dividing instruction itself, so a handler that
// fixes the divisor up and returns EXCEPTION_CONTINUE_EXECUTION re-runs it.
void OpDispatchBuilder::RaiseDivideErrorIfZero(FEXCore::X86Tables::DecodedOp Op, Ref Divisor) {
  CalculateDeferredFlags();
  RaiseDivideErrorIf(Op, Divisor, CondClass::EQ);
}

// ★ MacRunner Claude 29.09.2026 (MACRUNNER_FEX_DIV_OVERFLOW_DE=1): x86 also raises #DE when the quotient does not fit
// the destination (SDM, DIV/IDIV); UDIV/SDIV silently truncate it. The condition is built without dividing and covers
// the zero divisor as well:
//   DIV:  quotient >= 2^n  <=>  high half of the dividend >= divisor (unsigned).
//   IDIV: with A = |dividend| and B = |divisor| the quotient overflows iff A >= B * 2^(n-1) when it is positive and
//         A >= B * (2^(n-1) + 1) when it is negative (-2^(n-1) still fits). B = 0 makes the threshold 0.
//         Up to n = 32 the dividend fits 64 bits. For n = 64, A is the 128-bit |RDX:RAX| and the threshold is the
//         pair (B >> 1 : B << 63 | (negative ? B : 0)); adding B to B << 63 never carries, since B <= 2^63.
// Divisor must be the clean (no upper garbage) value the division itself uses. Returns 1 when #DE is due, else 0.
Ref OpDispatchBuilder::DivideErrorCondition(FEXCore::X86Tables::DecodedOp Op, Ref Divisor, bool Signed) {
  const auto Size = OpSizeFromSrc(Op);
  const uint8_t Bits = IR::OpSizeAsBits(Size);
  Ref Fault {};

  if (!Signed) {
    // High half of the dividend: AH, DX, EDX or RDX. Up to 32 bits a 32-bit compare ignores any garbage above.
    Ref High = Size == OpSize::i8Bit ? LoadGPRRegister(X86State::REG_RAX, OpSize::i8Bit, 8) : LoadGPRRegister(X86State::REG_RDX, Size);
    Fault = Select01(Size == OpSize::i64Bit ? OpSize::i64Bit : OpSize::i32Bit, CondClass::UGE, High, Divisor);
  } else if (Size != OpSize::i64Bit) {
    // Sign-extended AX, DX:AX or EDX:EAX.
    Ref Dividend {};
    if (Size == OpSize::i8Bit) {
      Dividend = _Sbfe(OpSize::i64Bit, 16, 0, LoadGPRRegister(X86State::REG_RAX));
    } else {
      Ref Low = _Bfe(OpSize::i64Bit, Bits, 0, LoadGPRRegister(X86State::REG_RAX));
      Dividend = _Orlshl(OpSize::i64Bit, Low, LoadGPRRegister(X86State::REG_RDX), Bits);
      if (Size == OpSize::i16Bit) {
        Dividend = _Sbfe(OpSize::i64Bit, 32, 0, Dividend);
      }
    }
    Ref SignedDivisor = _Sbfe(OpSize::i64Bit, Bits, 0, Divisor);

    Ref DividendSign = _Ashr(OpSize::i64Bit, Dividend, Constant(63));
    Ref DivisorSign = _Ashr(OpSize::i64Bit, SignedDivisor, Constant(63));
    Ref A = _Sub(OpSize::i64Bit, _Xor(OpSize::i64Bit, Dividend, DividendSign), DividendSign);
    Ref B = _Sub(OpSize::i64Bit, _Xor(OpSize::i64Bit, SignedDivisor, DivisorSign), DivisorSign);
    // B * 2^(n-1), plus B when the quotient is negative.
    Ref Threshold = _Add(OpSize::i64Bit, _Lshl(OpSize::i64Bit, B, Constant(Bits - 1)),
                         _And(OpSize::i64Bit, B, _Xor(OpSize::i64Bit, DividendSign, DivisorSign)));
    Fault = Select01(OpSize::i64Bit, CondClass::UGE, A, Threshold);
  } else {
    Ref Low = LoadGPRRegister(X86State::REG_RAX);
    Ref High = LoadGPRRegister(X86State::REG_RDX);

    Ref DividendSign = _Ashr(OpSize::i64Bit, High, Constant(63));
    Ref DivisorSign = _Ashr(OpSize::i64Bit, Divisor, Constant(63));
    // |RDX:RAX|: the low half negates as usual, the high half takes the carry only when the low half is zero.
    Ref ALow = _Sub(OpSize::i64Bit, _Xor(OpSize::i64Bit, Low, DividendSign), DividendSign);
    Ref XHigh = _Xor(OpSize::i64Bit, High, DividendSign);
    Ref AHigh = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::EQ, Low, Constant(0), _Sub(OpSize::i64Bit, XHigh, DividendSign), XHigh);
    Ref B = _Sub(OpSize::i64Bit, _Xor(OpSize::i64Bit, Divisor, DivisorSign), DivisorSign);
    // Threshold B * 2^63, plus B when the quotient is negative, as a 128-bit pair.
    Ref TLow = _Or(OpSize::i64Bit, _Lshl(OpSize::i64Bit, B, Constant(63)),
                   _And(OpSize::i64Bit, B, _Xor(OpSize::i64Bit, DividendSign, DivisorSign)));
    Ref THigh = _Lshr(OpSize::i64Bit, B, Constant(1));
    // A >= T  <=>  AHigh > THigh || (AHigh == THigh && ALow >= TLow)
    Ref HighAbove = Select01(OpSize::i64Bit, CondClass::UGT, AHigh, THigh);
    Ref HighEqual = Select01(OpSize::i64Bit, CondClass::EQ, AHigh, THigh);
    Ref LowAtLeast = Select01(OpSize::i64Bit, CondClass::UGE, ALow, TLow);
    Fault = _Or(OpSize::i64Bit, HighAbove, _And(OpSize::i64Bit, HighEqual, LowAtLeast));
  }

  const uint64_t Checks = MacRunnerDivOverflowChecks.fetch_add(1, std::memory_order_relaxed) + 1;
  if ((Checks & (Checks - 1)) == 0) {
    char Line[160];
    const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-div-overflow-de: checks={} rip={:x} op={} size={}\n",
                                         Checks, Op->PC, Signed ? "idiv" : "div", unsigned {Bits});
    Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
  return Fault;
}

// ★ MacRunner (MACRUNNER_FEX_DIV_PROVEN_HIGH=1, see the top of this file): true when the high half of the r32/r64
// dividend is known here: this DIV starts right after a `xor edx, edx` / `xor rdx, rdx`, or this IDIV right after a
// CDQ/CQO of the same size, in the same block — nothing can change RAX/RDX in between. A jump target between them
// starts a new block and clears the record. Counts and reports the translations it proves.
void OpDispatchBuilder::InvalidateMacRunnerDivHighOnWrite(uint8_t Index) {
  if (MacRunnerDivFastMode() < 8) {
    return;
  }
  if (Index == GPR0Index + MacRunnerDivPositive32Register) {
    MacRunnerDivPositive32End = 0;
  }
  // StoreContext is an architectural cached write, not a cache flush. Any
  // partial write is already merged into the complete guest-register value.
  if (Index == GPR0Index + X86State::REG_RDX) {
    MacRunnerZeroRDXEnd = 0;
    MacRunnerSignExtEnd = 0;
    MacRunnerSignExtSize = OpSize::iInvalid;
  } else if (Index == GPR0Index + X86State::REG_RAX) {
    MacRunnerSignExtEnd = 0;
    MacRunnerSignExtSize = OpSize::iInvalid;
  }
}

bool OpDispatchBuilder::DivHighHalfProven(FEXCore::X86Tables::DecodedOp Op, bool Signed) {
  const auto Size = OpSizeFromSrc(Op);
  if (!MacRunnerDivProvenHighMode() || Size < OpSize::i32Bit) {
    return false;
  }

  bool Proven = false;
  const bool BlockLifetime = MacRunnerDivFastMode() >= 8;
  if (Signed) {
    Proven = MacRunnerSignExtEnd != 0 &&
             (MacRunnerSignExtEnd == Op->PC || (BlockLifetime && MacRunnerSignExtEnd < Op->PC)) &&
             MacRunnerSignExtSize == Size;
  } else {
    Proven = MacRunnerZeroRDXEnd != 0 &&
             (MacRunnerZeroRDXEnd == Op->PC || (BlockLifetime && MacRunnerZeroRDXEnd < Op->PC));
  }

  if (Proven) {
    const uint64_t Used = MacRunnerDivProvenHighUsed.fetch_add(1, std::memory_order_relaxed) + 1;
    if ((Used & (Used - 1)) == 0) {
      char Line[160];
      const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-div-proven-high: used={} rip={:x} op={} size={}\n",
                                           Used, Op->PC, Signed ? "idiv" : "div", unsigned {IR::OpSizeAsBits(Size)});
      Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
  }
  return Proven;
}

// ★ MacRunner (MACRUNNER_FEX_DIV_OVERFLOW_DE=1 with a proven high half, DivHighHalfProven): the quotient can only
// overflow for IDIV INT_MIN / -1, so #DE is due iff divisor == 0, or (IDIV) dividend == INT_MIN and divisor == -1.
// x == 0 is taken as CLZ(x) >> log2(n): no compare, NZCV untouched, no 2n-bit arithmetic. Same result as
// DivideErrorCondition for every proven dividend. Returns 1 when #DE is due, else 0.
Ref OpDispatchBuilder::DivideErrorConditionProven(FEXCore::X86Tables::DecodedOp Op, Ref Divisor, bool Signed) {
  const auto Size = OpSizeFromSrc(Op);
  const uint64_t Log2Bits = Size == OpSize::i64Bit ? 6 : 5;
  auto IsZero = [&](Ref Value) {
    return _Lshr(OpSize::i64Bit, _CountLeadingZeroes(Size, Value), Constant(Log2Bits));
  };

  Ref Fault = IsZero(Divisor);
  if (Signed) {
    const uint64_t IntMin = uint64_t {1} << (IR::OpSizeAsBits(Size) - 1);
    Ref NotIntMin = _Xor(Size, LoadGPRRegister(X86State::REG_RAX), Constant(IntMin));
    Ref NotMinusOne = _Add(Size, Divisor, Constant(1));
    Fault = _Or(OpSize::i64Bit, Fault, IsZero(_Or(Size, NotIntMin, NotMinusOne)));
  }
  return Fault;
}

// MacRunner (MACRUNNER_FEX_DIV_OVERFLOW_DE): the value a register keeps written back — the old one when #DE is due.
// Without a condition (the gate is off) the new value as is, and no IR is emitted.
Ref OpDispatchBuilder::KeepOnDivideError(Ref Fault, Ref Old, Ref New) {
  return Fault ? _Select(GetGPROpSize(), OpSize::i64Bit, CondClass::NEQ, Fault, Constant(0), Old, New) : New;
}

void OpDispatchBuilder::RaiseDivideErrorIf(FEXCore::X86Tables::DecodedOp Op, Ref Value, CondClass Cond, bool ClassifyCause,
                                         bool ColdTail, uint16_t KnownCause, OpSize CompareSize) {
  const auto GPRSize = GetGPROpSize();

  const auto PreviousBlock = GetCurrentBlock();
  auto FaultBlock = CreateNewCodeBlockAfter(PreviousBlock);
  // Inserting the continuation second after PreviousBlock places it before the
  // fault block. The normal branch falls through, rather than jumping over #DE.
  auto ContinueBlock = ColdTail ? CreateNewCodeBlockAfter(PreviousBlock) : CreateNewCodeBlockAfter(FaultBlock);

  CondJump(Value, Constant(0), FaultBlock, ContinueBlock, Cond, CompareSize);

  // Signal/si_code follow the INTO (#OF) precedent: SIGSEGV is only the transport
  // that hands control back to the host fault handler, TrapNumber carries the x86
  // meaning and is what the Windows/Linux frontends decode.
  auto Raise = [&](uint16_t Cause) {
    auto NewRIP = GetRelocatedPC(Op, -Op->InstSize);
    _StoreContextGPR(GPRSize, NewRIP, offsetof(FEXCore::Core::CPUState, rip));

    Break(FEXCore::IR::BreakDefinition {
      .ErrorRegister = Cause,
      .Signal = Core::FAULT_SIGSEGV,
      .TrapNumber = X86State::X86_TRAPNO_DE,
      .si_code = 0x80,
    });
  };

  SetCurrentCodeBlock(FaultBlock);
  StartNewBlock();
  if (ClassifyCause) {
    // ★ MacRunner (MACRUNNER_FEX_DIV_OVERFLOW_DE=1): the processor raises one #DE for both causes; Windows then tells
    // them apart by the divisor — zero is STATUS_INTEGER_DIVIDE_BY_ZERO, anything else is a quotient overflow,
    // STATUS_INTEGER_OVERFLOW (measured under Prism, Windows 11 ARM 26200, x64 and WOW64, 8 to 64 bits). This block
    // runs only when #DE is due, and then the divisor and RAX/RDX are unchanged (KeepOnDivideError), so the divisor is
    // read again here to pick the cause: ErrorRegister 0 for a zero divisor, 1 for an overflow (Windows Exception.h).
    auto ZeroBlock = CreateNewCodeBlockAfter(FaultBlock);
    auto OverflowBlock = CreateNewCodeBlockAfter(ZeroBlock);
    CondJump(LoadSourceGPR(Op, Op->Dest, Op->Flags), Constant(0), ZeroBlock, OverflowBlock, CondClass::EQ);

    SetCurrentCodeBlock(ZeroBlock);
    StartNewBlock();
    Raise(0);

    SetCurrentCodeBlock(OverflowBlock);
    StartNewBlock();
    Raise(1);
  } else {
    Raise(KnownCause);
  }

  SetCurrentCodeBlock(ContinueBlock);
  StartNewBlock();
}

void OpDispatchBuilder::RaiseProvenDivideErrorBeforeWrite(FEXCore::X86Tables::DecodedOp Op, bool Signed) {
  const auto Size = OpSizeFromSrc(Op);
  // These conditions are established by the caller; memory divisors retain the
  // old single-read implementation, because FEX SSA definitions are block-local.
  LOGMAN_THROW_A_FMT(Op->Dest.IsGPR() && Size >= OpSize::i32Bit, "DIV-FAST requires a proven register dividend");
  const bool ConstantDivisor = MacRunnerDivFastMode() >= 2 && MacRunnerDivConstEnd == Op->PC &&
                               !Op->Dest.Data.GPR.HighBits && Op->Dest.Data.GPR.GPR == MacRunnerDivConstRegister;
  const uint64_t DivisorValue = Size == OpSize::i32Bit ? uint32_t(MacRunnerDivConstValue) : MacRunnerDivConstValue;
  const bool ZeroExtendedDivisor = MacRunnerDivFastMode() >= 6 && Size == OpSize::i64Bit &&
                                  MacRunnerDivZeroExtEnd == Op->PC && !Op->Dest.Data.GPR.HighBits &&
                                  Op->Dest.Data.GPR.GPR == MacRunnerDivZeroExtRegister;
  const bool KnownNonzero = ConstantDivisor && DivisorValue != 0;
  const bool NeedsSignedOverflow = Signed && !ZeroExtendedDivisor && (!ConstantDivisor || DivisorValue ==
    (Size == OpSize::i32Bit ? uint64_t(UINT32_MAX) : UINT64_MAX));
  CalculateDeferredFlags();
  // Native W-register operations ignore upper garbage. Match the zero guard's
  // width explicitly, then the same register needs no cleaning MOV in either block.
  if (MacRunnerDivFastMode() == 3 && Signed && !ConstantDivisor) {
    // D+1 modulo the operand width is 0 or 1 exactly for D=-1 or D=0.
    // Keep both special divisors in one cold branch without touching NZCV.
    const auto PreviousBlock = GetCurrentBlock();
    auto SpecialBlock = CreateNewCodeBlockAfter(PreviousBlock);
    auto ContinueBlock = CreateNewCodeBlockAfter(PreviousBlock);
    Ref PlusOne = _Add(Size, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}), Constant(1));
    Ref NotSpecial = _Lshr(Size, PlusOne, Constant(1));
    CondJump(NotSpecial, Constant(0), SpecialBlock, ContinueBlock, CondClass::EQ, Size);

    SetCurrentCodeBlock(SpecialBlock);
    StartNewBlock();
    RaiseDivideErrorIf(Op, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}),
                       CondClass::EQ, false, true, 0, Size);
    // A nonzero special divisor is exactly -1, so only the dividend test remains.
    const uint64_t IntMin = uint64_t {1} << (IR::OpSizeAsBits(Size) - 1);
    Ref NotIntMin = _Xor(Size, LoadGPRRegister(X86State::REG_RAX), Constant(IntMin));
    RaiseDivideErrorIf(Op, NotIntMin, CondClass::EQ, false, true, 1, Size);
    Jump(ContinueBlock);
    SetCurrentCodeBlock(ContinueBlock);
    StartNewBlock();
  } else {
    if (!KnownNonzero) {
      RaiseDivideErrorIf(Op, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}),
                         CondClass::EQ, false, true, 0, Size);
    }
    if (NeedsSignedOverflow) {
      // Only INT_MIN needs the -1 test. Keep it out of line so ordinary
      // dividends, including division by -1, take the same two-instruction guard.
      // Both predicates are flag-neutral; #DE retains the exact prefix state.
      const auto PreviousBlock = GetCurrentBlock();
      auto IntMinBlock = CreateNewCodeBlockAfter(PreviousBlock);
      auto ContinueBlock = CreateNewCodeBlockAfter(PreviousBlock);
      const uint64_t IntMin = uint64_t {1} << (IR::OpSizeAsBits(Size) - 1);
      Ref NotIntMin = _Xor(Size, LoadGPRRegister(X86State::REG_RAX), Constant(IntMin));
      CondJump(NotIntMin, Constant(0), IntMinBlock, ContinueBlock, CondClass::EQ, Size);

      SetCurrentCodeBlock(IntMinBlock);
      StartNewBlock();
      Ref NotMinusOne = _Add(Size, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}), Constant(1));
      RaiseDivideErrorIf(Op, NotMinusOne, CondClass::EQ, false, true, 1, Size);
      // INT_MIN divided by any nonzero divisor other than -1 is representable.
      Jump(ContinueBlock);

      SetCurrentCodeBlock(ContinueBlock);
      StartNewBlock();
    }
  }
  const uint64_t Used = MacRunnerDivFastUsed.fetch_add(1, std::memory_order_relaxed) + 1;
  if ((Used & (Used - 1)) == 0) {
    if (MacRunnerDivFastMode() >= 2) {
      char Line[192];
      const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
        "macrunner-fex-div-fast: used={} rip={:x} op={} size={} mode={} constant-proof={} zero-check={} signed-overflow-check={} flags-preserved=1\n",
        Used, Op->PC, Signed ? "idiv" : "div", unsigned {IR::OpSizeAsBits(Size)}, MacRunnerDivFastMode(), ConstantDivisor, !KnownNonzero, NeedsSignedOverflow);
      Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
      return;
    }
    char Line[160];
    const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
      "macrunner-fex-div-fast: used={} rip={:x} op={} size={} cold-tail=1 flags-preserved=1\n",
      Used, Op->PC, Signed ? "idiv" : "div", unsigned {IR::OpSizeAsBits(Size)});
    Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
}

void OpDispatchBuilder::RaiseUnsigned32DivideErrorBeforeWrite(FEXCore::X86Tables::DecodedOp Op) {
  LOGMAN_THROW_A_FMT(Op->Dest.IsGPR() && OpSizeFromSrc(Op) == OpSize::i32Bit, "DIV-FAST general high requires unsigned r32");
  CalculateDeferredFlags();
  const bool CombinedGuard = MacRunnerDivFastMode() >= 3;
  if (!CombinedGuard) {
    RaiseDivideErrorIf(Op, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}),
                       CondClass::EQ, false, true, 0, OpSize::i32Bit);
  }
  // Both operands are unsigned 32-bit values. Their 64-bit difference is in
  // [-(2^32-1), 2^32-1], so its sign bit proves high < divisor without NZCV.
  // Reload in this continuation: FEX SSA definitions do not cross blocks.
  Ref High = _Bfe(OpSize::i64Bit, 32, 0, LoadGPRRegister(X86State::REG_RDX));
  Ref Divisor = _Bfe(OpSize::i64Bit, 32, 0,
                     LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}));
  Ref Fits = _Bfe(OpSize::i64Bit, 1, 63, _Sub(OpSize::i64Bit, High, Divisor));
  // High >= divisor already includes every zero divisor. Classify its cause
  // only in the cold fault block; both guest outputs and NZCV stay unchanged.
  RaiseDivideErrorIf(Op, Fits, CondClass::EQ, CombinedGuard, true, 1, OpSize::i64Bit);
  const uint64_t Used = MacRunnerDivFastUsed.fetch_add(1, std::memory_order_relaxed) + 1;
  if ((Used & (Used - 1)) == 0) {
    char Line[176];
    const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
      "macrunner-fex-div-fast: used={} rip={:x} op=div size=32 high=general cold-tail=1 flags-preserved=1\n", Used, Op->PC);
    Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
}

void OpDispatchBuilder::DIVOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  auto Size = OpSizeFromSrc(Op);

  if (Size == OpSize::i64Bit && !Is64BitMode) {
    LogMan::Msg::EFmt("Doesn't exist in 32bit mode");
    DecodeFailure = true;
    return;
  }

  // ★ MacRunner (MACRUNNER_FEX_DIV_OVERFLOW_DE=1): the divisor is read ONCE and the check, the division and the
  // write-back stay in one block; the #DE branch follows the write-back, which keeps RAX/RDX when #DE is due. The path
  // below reads a memory divisor again after its branch, so another thread can change it between check and division.
  const bool OverflowDE = MacRunnerDivOverflowMode();
  // ★ MacRunner (MACRUNNER_FEX_DIV_PROVEN_HIGH=1): decided before the zero-divisor branch below ends the block.
  const bool ProvenHigh = DivHighHalfProven(Op, false);
  const bool L4 = OverflowDE && MacRunnerDivFastMode() && Op->Dest.IsGPR() &&
                  (ProvenHigh || Size == OpSize::i32Bit);
  // Save the proven register identity before the cold guard clears block facts.
  const uint32_t LowerSource = L4 && ProvenHigh && MacRunnerDivLowerEnd == Op->PC && MacRunnerDivLowerSize == Size ?
                                 MacRunnerDivLowerSource : X86State::REG_RAX;
  Ref Divisor {};
  Ref Fault {};
  if (L4) {
    if (ProvenHigh) {
      RaiseProvenDivideErrorBeforeWrite(Op, false);
    } else {
      RaiseUnsigned32DivideErrorBeforeWrite(Op);
    }
    Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  } else if (OverflowDE) {
    CalculateDeferredFlags();
    Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags);
    Fault = ProvenHigh ? DivideErrorConditionProven(Op, Divisor, false) : DivideErrorCondition(Op, Divisor, false);
    // Divide by 1 when the result is thrown away: the 128-bit helper must never see a zero divisor.
    Divisor = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::NEQ, Fault, Constant(0), Constant(1), Divisor);
  } else {
    // Fault before anything is written back. The load is clean (no upper garbage) so a
    // plain compare against zero is valid for every operand size.
    RaiseDivideErrorIfZero(Op, LoadSourceGPR(Op, Op->Dest, Op->Flags));

    // Rematerialised after the branch: FEX IR only allows defs local to a single block.
    // This loads the divisor. 32-bit/64-bit paths mask inside the JIT, 8/16 do not.
    Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = Size >= OpSize::i32Bit});
  }

  Ref Quotient = _AllocateGPR(true);
  Ref Remainder = _AllocateGPR(true);

  if (Size == OpSize::i8Bit) {
    Ref Src1 = LoadGPRRegister(X86State::REG_RAX, OpSize::i16Bit);

    _UDiv(OpSize::i16Bit, Src1, Invalid(), Divisor, Quotient, Remainder, Invalid());

    // AX[15:0] = concat<URem[7:0]:UDiv[7:0]>
    auto ResultAX = _Bfi(GPRSize, 8, 8, Quotient, Remainder);
    StoreGPRRegister(X86State::REG_RAX, KeepOnDivideError(Fault, Src1, ResultAX), OpSize::i16Bit);
  } else {
    Ref Src1 = LoadGPRRegister(X86State::REG_RAX);
    Ref Src2 = LoadGPRRegister(X86State::REG_RDX);

    // Read the unchanged MOV source again in this continuation, not a predecessor SSA value.
    Ref Lower = LowerSource == X86State::REG_RAX ? Src1 : LoadGPRRegister(LowerSource);
    // A proven zero high half needs no 2n-bit dividend: plain UDIV/MSUB of the operand size, no runtime check.
    _UDiv(Size, Lower, ProvenHigh ? Invalid() : Src2, Divisor, Quotient, Remainder, Invalid());

    if (Size == OpSize::i32Bit) {
      // FAST with invalid Upper emits W-register UDIV/MSUB. General unsigned
      // FAST first proves high < divisor, so its X-register quotient/remainder
      // fit in32bits too. Both paths need no two BFE copy nodes.
      if (!L4) {
        Quotient = _Bfe(OpSize::i32Bit, IR::OpSizeAsBits(Size), 0, Quotient);
        Remainder = _Bfe(OpSize::i32Bit, IR::OpSizeAsBits(Size), 0, Remainder);
      }
      Size = OpSize::iInvalid;
    }

    StoreGPRRegister(X86State::REG_RAX, KeepOnDivideError(Fault, Src1, Quotient), Size);
    StoreGPRRegister(X86State::REG_RDX, KeepOnDivideError(Fault, Src2, Remainder), Size);
  }

  if (OverflowDE && !L4) {
    RaiseDivideErrorIf(Op, Fault, CondClass::NEQ, true);
  }
}

bool OpDispatchBuilder::TryIDivZeroHighPositive32(FEXCore::X86Tables::DecodedOp Op) {
  if (MacRunnerDivFastMode() < 8 || !MacRunnerDivOverflowMode() || OpSizeFromSrc(Op) != OpSize::i32Bit ||
      !Op->Dest.IsGPR() || MacRunnerDivPositive32End == 0 || MacRunnerDivPositive32End > Op->PC ||
      Op->Dest.Data.GPR.GPR != MacRunnerDivPositive32Register || !DivHighHalfProven(Op, false)) {
    return false;
  }

  // RDX=0 makes EDX:EAX a nonnegative 64-bit dividend. MOVZX8/16 makes
  // the int32 divisor nonnegative. UDIV32 is exact; q[31] is precisely #DE.
  // Both checks happen before quotient/remainder are architecturally committed.
  CalculateDeferredFlags();
  RaiseDivideErrorIf(Op, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}),
                     CondClass::EQ, false, true, 0, OpSize::i32Bit);
  const auto ContinueBlock = GetCurrentBlock();
  auto OverflowBlock = CreateNewCodeBlockAfter(ContinueBlock);
  SetCurrentCodeBlock(OverflowBlock);
  StartNewBlock();
  _StoreContextGPR(GetGPROpSize(), GetRelocatedPC(Op, -Op->InstSize), offsetof(FEXCore::Core::CPUState, rip));
  Break(FEXCore::IR::BreakDefinition {
    .ErrorRegister = 1,
    .Signal = Core::FAULT_SIGSEGV,
    .TrapNumber = X86State::X86_TRAPNO_DE,
    .si_code = 0x80,
  });
  SetCurrentCodeBlock(ContinueBlock);
  StartNewBlock();

  const Ref Lower = LoadGPRRegister(X86State::REG_RAX);
  const Ref Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  const Ref Q = _AllocateGPR(true);
  const Ref R = _AllocateGPR(true);
  _UDiv(OpSize::i32Bit, Lower, Invalid(), Divisor, Q, R, OverflowBlock);
  StoreGPRRegister(X86State::REG_RAX, Q, OpSize::iInvalid);
  StoreGPRRegister(X86State::REG_RDX, R, OpSize::iInvalid);
  return true;
}

void OpDispatchBuilder::IDIVOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  auto Size = OpSizeFromSrc(Op);

  if (Size == OpSize::i64Bit && !Is64BitMode) {
    LogMan::Msg::EFmt("Doesn't exist in 32bit mode");
    DecodeFailure = true;
    return;
  }

  // ★ MacRunner (MACRUNNER_FEX_DIV_OVERFLOW_DE=1): one read of the divisor, the #DE branch after the write-back — see
  // DIVOp. The divide-by-1 substitute also keeps INT128_MIN / -1 away from the 128-bit helper.
  const bool OverflowDE = MacRunnerDivOverflowMode();
  if (OverflowDE && TryIDivZeroHighPositive32(Op)) {
    return;
  }
  // ★ MacRunner (MACRUNNER_FEX_DIV_PROVEN_HIGH=1): decided before the zero-divisor branch below ends the block.
  const bool ProvenHigh = DivHighHalfProven(Op, true);
  const bool L4 = OverflowDE && ProvenHigh && MacRunnerDivFastMode() && Op->Dest.IsGPR();
  const uint32_t LowerSource = L4 && MacRunnerDivLowerEnd == Op->PC && MacRunnerDivLowerSize == Size ?
                                 MacRunnerDivLowerSource : X86State::REG_RAX;
  const bool LiteralDivisor = L4 && MacRunnerDivConstEnd == Op->PC && !Op->Dest.Data.GPR.HighBits &&
                              Op->Dest.Data.GPR.GPR == MacRunnerDivConstRegister;
  const bool ZeroExtendedDivisor = L4 && MacRunnerDivFastMode() >= 6 && Size == OpSize::i64Bit &&
                                  MacRunnerDivZeroExtEnd == Op->PC && !Op->Dest.Data.GPR.HighBits &&
                                  Op->Dest.Data.GPR.GPR == MacRunnerDivZeroExtRegister;
  if (L4 && MacRunnerDivFastMode() >= 4 && !LiteralDivisor && !ZeroExtendedDivisor) {
    // The special set is unchanged from FAST3; only valid -1 arithmetic differs.
    CalculateDeferredFlags();
    const auto Entry = GetCurrentBlock();
    // Keep FAST4 as the same-image control; FAST5 changes only block layout.
    const bool ForwardLayout = MacRunnerDivFastMode() >= 5;
    auto First = CreateNewCodeBlockAfter(Entry);
    auto Second = CreateNewCodeBlockAfter(Entry);
    auto Third = CreateNewCodeBlockAfter(Entry);
    auto Special = ForwardLayout ? Third : First;
    auto Join = ForwardLayout ? First : Second;
    auto Normal = ForwardLayout ? Second : Third;
    Ref D = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
    Ref NotSpecial = _Lshr(Size, _Add(Size, D, Constant(1)), Constant(1));
    // Use the adjacent Special block as fallthrough for the forward layout.
    CondJump(NotSpecial, Constant(0), ForwardLayout ? Normal : Special,
             ForwardLayout ? Special : Normal, ForwardLayout ? CondClass::NEQ : CondClass::EQ, Size);
    const auto StoreSize = Size == OpSize::i32Bit ? OpSize::iInvalid : Size;
    auto Lower = [&]() { return LoadGPRRegister(LowerSource); };
    auto Write = [&](Ref Q, Ref R) {
      StoreGPRRegister(X86State::REG_RAX, Q, StoreSize);
      StoreGPRRegister(X86State::REG_RDX, R, StoreSize);
    };

    SetCurrentCodeBlock(Normal);
    StartNewBlock();
    Ref Q = _AllocateGPR(true);
    Ref R = _AllocateGPR(true);
    _Div(Size, Lower(), Invalid(), LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}), Q, R);
    Write(Q, R);
    Jump(Join);

    SetCurrentCodeBlock(Special);
    StartNewBlock();
    RaiseDivideErrorIf(Op, LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true}),
                       CondClass::EQ, false, true, 0, Size);
    const uint64_t IntMin = uint64_t {1} << (IR::OpSizeAsBits(Size) - 1);
    Ref NotMin = _Xor(Size, LoadGPRRegister(X86State::REG_RAX), Constant(IntMin));
    RaiseDivideErrorIf(Op, NotMin, CondClass::EQ, false, true, 1, Size);
    // Nonzero special D is exactly -1; after the MIN guard Q=-A and R=0.
    Write(_Sub(Size, Constant(0), Lower()), Constant(0));
    Jump(Join);

    SetCurrentCodeBlock(Join);
    StartNewBlock();
    const uint64_t Used = MacRunnerDivFastUsed.fetch_add(1, std::memory_order_relaxed) + 1;
    if ((Used & (Used - 1)) == 0) {
      char Line[192];
      const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
        "macrunner-fex-div-fast: used={} rip={:x} op=idiv size={} mode={} constant-proof=false zero-check=1 signed-overflow-check=1 cold-minus-one-neg=1 flags-preserved=1\n",
        Used, Op->PC, unsigned {IR::OpSizeAsBits(Size)}, MacRunnerDivFastMode());
      Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
    return;
  }
  // A 2n-bit signed dividend fits SDIV64 when n <= 32. Check the full
  // quotient after dividing; the wide host operation never raises a host #DE.
  // Proven dividends retain the separately validated cold guards.
  const bool QuotientFit = OverflowDE && !ProvenHigh && MacRunnerDivFastMode() && Size != OpSize::i64Bit;
  Ref Divisor {};
  Ref Fault {};
  if (L4) {
    RaiseProvenDivideErrorBeforeWrite(Op, true);
    Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  } else if (QuotientFit) {
    // Pre-instruction flags are still needed on #DE. Successful DIV flags
    // are undefined; this is the existing exception-state preservation.
    CalculateDeferredFlags();
    Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags);
  } else if (OverflowDE) {
    CalculateDeferredFlags();
    Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags);
    Fault = ProvenHigh ? DivideErrorConditionProven(Op, Divisor, true) : DivideErrorCondition(Op, Divisor, true);
    Divisor = _Select(OpSize::i64Bit, OpSize::i64Bit, CondClass::NEQ, Fault, Constant(0), Constant(1), Divisor);
  } else {
    // See RaiseDivideErrorIfZero: SDIV does not trap on a zero divisor either.
    RaiseDivideErrorIfZero(Op, LoadSourceGPR(Op, Op->Dest, Op->Flags));

    // Rematerialised after the branch: FEX IR only allows defs local to a single block.
    // This loads the divisor
    Divisor = LoadSourceGPR(Op, Op->Dest, Op->Flags);
  }

  Ref Quotient = _AllocateGPR(true);
  Ref Remainder = _AllocateGPR(true);
  auto CheckSignedQuotient = [&](Ref SignedDivisor) {
    const auto Bits = IR::OpSizeAsBits(Size);
    Ref ZeroDivisor = _Lshr(OpSize::i64Bit, _CountLeadingZeroes(OpSize::i64Bit, SignedDivisor), Constant(6));
    Ref NarrowQuotient = _Sbfe(OpSize::i64Bit, Bits, 0, Quotient);
    Fault = _Or(OpSize::i64Bit, ZeroDivisor, _Xor(OpSize::i64Bit, Quotient, NarrowQuotient));
    // INT64_MIN / -1 returns INT64_MIN on ARM; it cannot fit any of the
    // 8/16/32-bit x86 destinations and therefore takes the same fault tail.
    const uint64_t Used = MacRunnerDivFastUsed.fetch_add(1, std::memory_order_relaxed) + 1;
    if ((Used & (Used - 1)) == 0) {
      char Line[160];
      const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
        "macrunner-fex-div-fast: used={} rip={:x} op=idiv size={} quotient-fit=1 flags-preserved=1\n",
        Used, Op->PC, unsigned {Bits});
      Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
  };

  if (Size == OpSize::i8Bit) {
    Ref Src1 = LoadGPRRegister(X86State::REG_RAX);
    Src1 = _Sbfe(OpSize::i64Bit, 16, 0, Src1);
    Divisor = _Sbfe(OpSize::i64Bit, 8, 0, Divisor);

    _Div(OpSize::i64Bit, Src1, Invalid(), Divisor, Quotient, Remainder);
    if (QuotientFit) {
      CheckSignedQuotient(Divisor);
    }

    // AX[15:0] = concat<URem[7:0]:UDiv[7:0]>
    auto ResultAX = _Bfi(GPRSize, 8, 8, Quotient, Remainder);
    StoreGPRRegister(X86State::REG_RAX, KeepOnDivideError(Fault, Src1, ResultAX), OpSize::i16Bit);
  } else {
    Ref Src1 = LoadGPRRegister(X86State::REG_RAX);
    Ref Src2 = LoadGPRRegister(X86State::REG_RDX);

    // A proven sign-extended dividend needs no 2n-bit dividend: plain SDIV/MSUB of the operand size, no runtime check
    // and no LDIV call. INT_MIN / -1 gives the same truncated quotient and a zero remainder either way.
    if (QuotientFit) {
      const auto Bits = IR::OpSizeAsBits(Size);
      Ref Low = _Bfe(OpSize::i64Bit, Bits, 0, Src1);
      Ref Dividend = _Orlshl(OpSize::i64Bit, Low, Src2, Bits);
      if (Size == OpSize::i16Bit) {
        Dividend = _Sbfe(OpSize::i64Bit, 32, 0, Dividend);
      }
      Divisor = _Sbfe(OpSize::i64Bit, Bits, 0, Divisor);
      _Div(OpSize::i64Bit, Dividend, Invalid(), Divisor, Quotient, Remainder);
      CheckSignedQuotient(Divisor);
    } else {
      Ref Lower = LowerSource == X86State::REG_RAX ? Src1 : LoadGPRRegister(LowerSource);
      _Div(Size, Lower, ProvenHigh ? Invalid() : Src2, Divisor, Quotient, Remainder);
    }

    if (Size == OpSize::i32Bit) {
      // See DIV: proven i32 SDIV/MSUB also write W-register outputs.
      if (!L4) {
        Quotient = _Bfe(OpSize::i32Bit, IR::OpSizeAsBits(Size), 0, Quotient);
        Remainder = _Bfe(OpSize::i32Bit, IR::OpSizeAsBits(Size), 0, Remainder);
      }
      Size = OpSize::iInvalid;
    }

    StoreGPRRegister(X86State::REG_RAX, KeepOnDivideError(Fault, Src1, Quotient), Size);
    StoreGPRRegister(X86State::REG_RDX, KeepOnDivideError(Fault, Src2, Remainder), Size);
  }

  if (OverflowDE && !L4) {
    RaiseDivideErrorIf(Op, Fault, CondClass::NEQ, true);
  }
}

void OpDispatchBuilder::BSFOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  const auto DstSize = OpSizeFromDst(Op) == OpSize::i16Bit ? OpSize::i16Bit : GPRSize;
  Ref Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, DstSize, Op->Flags, {.AllowUpperGarbage = true});
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

  // Find the LSB of this source
  auto Result = _FindLSB(OpSizeFromSrc(Op), Src);

  // OF, SF, AF, PF, CF all undefined
  // ZF is set to 1 if the source was zero
  SetZ_InvalidateNCV(OpSizeFromSrc(Op), Src);

  // If Src was zero then the destination doesn't get modified.
  //
  // Although Intel does not guarantee that semantic, AMD does and Intel
  // hardware satisfies it. We provide the stronger AMD behaviour as
  // applications might rely on that in the wild.
  auto SelectOp = NZCVSelect(GPRSize, CondClass::EQ, Dest, Result);
  StoreResultGPR_WithOpSize(Op, Op->Dest, SelectOp, DstSize);
}

void OpDispatchBuilder::BSROp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  const auto DstSize = OpSizeFromDst(Op) == OpSize::i16Bit ? OpSize::i16Bit : GPRSize;
  Ref Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, DstSize, Op->Flags, {.AllowUpperGarbage = true});
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

  // Find the MSB of this source
  auto Result = _FindMSB(OpSizeFromSrc(Op), Src);

  // OF, SF, AF, PF, CF all undefined
  // ZF is set to 1 if the source was zero
  SetZ_InvalidateNCV(OpSizeFromSrc(Op), Src);

  // If Src was zero then the destination doesn't get modified
  auto SelectOp = NZCVSelect(GPRSize, CondClass::EQ, Dest, Result);
  StoreResultGPR_WithOpSize(Op, Op->Dest, SelectOp, DstSize);
}

void OpDispatchBuilder::CMPXCHGOp(OpcodeArgs) {
  // CMPXCHG ModRM, reg, {RAX}
  // MemData = *ModRM.dest
  // if (RAX == MemData)
  //    modRM.dest = reg;
  //    ZF = 1
  // else
  //    ZF = 0
  // RAX = MemData
  //
  // CASL Xs, Xt, Xn
  // MemData = *Xn
  // if (MemData == Xs)
  //    *Xn = Xt
  // Xs = MemData

  const auto GPRSize = GetGPROpSize();
  auto Size = OpSizeFromSrc(Op);

  if (Op->Dest.IsGPR()) {
    // This is our source register
    Ref Src2 = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});
    Ref Src3 = LoadGPRRegister(X86State::REG_RAX);

    // If the destination is also the accumulator, we get some algebraic
    // simplifications. Not sure if this is actually hit but it's in
    // InstCountCI.
    bool Trivial = Op->Dest.Data.GPR.GPR == X86State::REG_RAX && !Op->Dest.IsGPRDirect() && !Op->Dest.Data.GPR.HighBits;

    Ref Src1 {};
    Ref Src1Lower {};

    if (GPRSize == OpSize::i64Bit && Size == OpSize::i32Bit) {
      Src1 = LoadSourceGPR_WithOpSize(Op, Op->Dest, GPRSize, Op->Flags, {.AllowUpperGarbage = true});
      Src1Lower = Trivial ? Src1 : _Bfe(GPRSize, IR::OpSizeAsBits(Size), 0, Src1);
    } else {
      Src1 = LoadSourceGPR_WithOpSize(Op, Op->Dest, Size, Op->Flags, {.AllowUpperGarbage = true});
      Src1Lower = Src1;
    }

    // Compare RAX with the destination, setting flags accordingly.
    CalculateFlags_SUB(OpSizeFromSrc(Op), Src3, Src1Lower);
    CalculateDeferredFlags();

    if (!Trivial) {
      if (GPRSize == OpSize::i64Bit && Size == OpSize::i32Bit) {
        // This allows us to only hit the ZEXT case on failure
        Ref RAXResult = NZCVSelect(OpSize::i64Bit, CondClass::EQ, Src3, Src1Lower);

        StoreGPRRegister(X86State::REG_RAX, RAXResult);
      } else {
        StoreGPRRegister(X86State::REG_RAX, Src1Lower, Size);
      }
    }

    // Op1 = RAX == Op1 ? Op2 : Op1
    // If they match then set the rm operand to the input
    // else don't set the rm operand
    Ref Src2Lower = Src2;
    if (GPRSize == OpSize::i64Bit && Size == OpSize::i32Bit) {
      Src2Lower = _Bfe(GPRSize, IR::OpSizeAsBits(Size), 0, Src2);
    }
    Ref DestResult = Trivial ? Src2Lower : NZCVSelect(OpSize::i64Bit, CondClass::EQ, Src2Lower, Src1);

    // Store in to GPR Dest
    if (GPRSize == OpSize::i64Bit && Size == OpSize::i32Bit) {
      StoreResultGPR_WithOpSize(Op, Op->Dest, DestResult, GPRSize);
    } else {
      StoreResultGPR(Op, DestResult);
    }
  } else {
    Ref Src2 = LoadSourceGPR(Op, Op->Src[0], Op->Flags);
    HandledLock = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK;

    auto Src3 = LoadGPRRegister(X86State::REG_RAX);
    auto Src3Lower = _Bfe(OpSize::i64Bit, OpSizeAsBits(Size), 0, Src3);

    // If this is a memory location then we want the pointer to it
    Ref Src1 = MakeSegmentAddress(Op, Op->Dest);

    // DataSrc = *Src1
    // if (DataSrc == Src3) { *Src1 == Src2; } Src2 = DataSrc
    // This will write to memory! Careful!
    // Third operand must be a calculated guest memory address
    Ref CASResult = _CAS(Size, Src3, Src2, Src1);
    Ref RAXResult = CASResult;

    CalculateFlags_SUB(OpSizeFromSrc(Op), Src3Lower, CASResult);
    CalculateDeferredFlags();

    if (GPRSize == OpSize::i64Bit && Size == OpSize::i32Bit) {
      // This allows us to only hit the ZEXT case on failure
      RAXResult = _NZCVSelect(OpSize::i64Bit, CondClass::EQ, Src3, CASResult);
      Size = OpSize::i64Bit;
    }

    // RAX gets the result of the CAS op
    StoreGPRRegister(X86State::REG_RAX, RAXResult, Size);
  }
}

void OpDispatchBuilder::CMPXCHGPairOp(OpcodeArgs) {
  // Calculate flags early.
  CalculateDeferredFlags();

  // REX.W used to determine if it is 16byte or 8byte
  // Unlike CMPXCHG, the destination can only be a memory location
  const auto Size = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REX_WIDENING ? OpSize::i64Bit : OpSize::i32Bit;

  HandledLock = (Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK) != 0;

  // If this is a memory location then we want the pointer to it
  Ref Src1 = MakeSegmentAddress(Op, Op->Dest);

  // Load the full 64-bit registers, all the users ignore the upper 32-bits for
  // 32-bit only cmpxchg. This saves some zero extension.
  Ref Expected_Lower = LoadGPRRegister(X86State::REG_RAX);
  Ref Expected_Upper = LoadGPRRegister(X86State::REG_RDX);
  Ref Desired_Lower = LoadGPRRegister(X86State::REG_RBX);
  Ref Desired_Upper = LoadGPRRegister(X86State::REG_RCX);

  // ssa0 = Expected
  // ssa1 = Desired
  // ssa2 = MemoryLocation

  // DataSrc = *MemSrc
  // if (DataSrc == Expected) { *MemSrc == Desired; } Expected = DataSrc
  // This will write to memory! Careful!
  // Third operand must be a calculated guest memory address

  Ref Result_Lower = _AllocateGPR(true);
  Ref Result_Upper = _AllocateGPRAfter(Result_Lower);
  _CASPair(Size, Expected_Lower, Expected_Upper, Desired_Lower, Desired_Upper, Src1, Result_Lower, Result_Upper);

  HandleNZCV_RMW();
  _CmpPairZ(Size, Result_Lower, Result_Upper, Expected_Lower, Expected_Upper);
  CalculateDeferredFlags();

  auto UpdateIfNotZF = [this](auto Reg, auto Value) {
    // Always use 64-bit csel to preserve existing upper bits. If we have a
    // 32-bit cmpxchg in a 64-bit context, Value will be zeroed in upper bits.
    StoreGPRRegister(Reg, NZCVSelect(OpSize::i64Bit, CondClass::NEQ, Value, LoadGPRRegister(Reg)));
  };

  UpdateIfNotZF(X86State::REG_RAX, Result_Lower);
  UpdateIfNotZF(X86State::REG_RDX, Result_Upper);
}

void OpDispatchBuilder::CreateJumpBlocks(const fextl::vector<FEXCore::Frontend::Decoder::DecodedBlocks>* Blocks) {
  Ref PrevCodeBlock {};
  for (auto& Target : *Blocks) {
    auto CodeNode = CreateCodeNode(Target.IsEntryPoint, Target.Entry - Entry);

    JumpTargets.try_emplace(Target.Entry, JumpTargetInfo {CodeNode, false, Target.IsEntryPoint});

    if (PrevCodeBlock) {
      LinkCodeBlocks(PrevCodeBlock, CodeNode);
    }

    PrevCodeBlock = CodeNode;
  }
}

void OpDispatchBuilder::BeginFunction(uint64_t RIP, const fextl::vector<FEXCore::Frontend::Decoder::DecodedBlocks>* Blocks,
                                      uint32_t NumInstructions, bool _Is64BitMode, bool MonoBackpatcherBlock) {
  WritableLoopCacheExit = false;
  Entry = RIP;
  Is64BitMode = _Is64BitMode;
  LOGMAN_THROW_A_FMT(Is64BitMode == CTX->Config.Is64BitMode, "Expected operating mode to not change at runtime!");
  IsMonoBackpatcherBlock = MonoBackpatcherBlock;
  auto IRHeader = _IRHeader(InvalidNode, RIP, 0, NumInstructions, 0, 0);
  CreateJumpBlocks(Blocks);

  auto Block = GetNewJumpBlock(RIP);
  SetCurrentCodeBlock(Block);
  IRHeader.first->Blocks = Block->Wrapped(DualListData.ListBegin());
  CurrentHeader = IRHeader.first;
}

void OpDispatchBuilder::Finalize() {
  // This usually doesn't emit any IR but in the case of hitting the block instruction limit it will
  FlushRegisterCache();
  const auto GPRSize = GetGPROpSize();

  // Node 0 is invalid node
  Ref RealNode = reinterpret_cast<Ref>(GetNode(1));

  const FEXCore::IR::IROp_Header* IROp = RealNode->Op(DualListData.DataBegin());
  LOGMAN_THROW_A_FMT(IROp->Op == OP_IRHEADER, "First op in function must be our header");

  // Let's walk the jump blocks and see if we have handled every block target
  for (auto& Handler : JumpTargets) {
    if (Handler.second.HaveEmitted) {
      continue;
    }

    // We haven't emitted. Dump out to the dispatcher
    SetCurrentCodeBlock(Handler.second.BlockEntry);
    ExitFunction(_InlineEntrypointOffset(GPRSize, Handler.first - Entry));
  }
}

uint8_t OpDispatchBuilder::GetDstSize(X86Tables::DecodedOp Op) const {
  const uint32_t DstSizeFlag = X86Tables::DecodeFlags::GetSizeDstFlags(Op->Flags);
  LOGMAN_THROW_A_FMT(DstSizeFlag != 0 && DstSizeFlag != X86Tables::DecodeFlags::SIZE_MASK, "Invalid destination size for op");
  return 1u << (DstSizeFlag - 1);
}

uint8_t OpDispatchBuilder::GetSrcSize(X86Tables::DecodedOp Op) const {
  const uint32_t SrcSizeFlag = X86Tables::DecodeFlags::GetSizeSrcFlags(Op->Flags);
  LOGMAN_THROW_A_FMT(SrcSizeFlag != 0 && SrcSizeFlag != X86Tables::DecodeFlags::SIZE_MASK, "Invalid destination size for op");
  return 1u << (SrcSizeFlag - 1);
}

uint32_t OpDispatchBuilder::GetSrcBitSize(X86Tables::DecodedOp Op) const {
  return GetSrcSize(Op) * 8;
}

uint32_t OpDispatchBuilder::GetDstBitSize(X86Tables::DecodedOp Op) const {
  return GetDstSize(Op) * 8;
}

Ref OpDispatchBuilder::GetSegment(uint32_t Flags, uint32_t DefaultPrefix, bool Override) {
  const auto GPRSize = GetGPROpSize();
  uint32_t Prefix = Flags & FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS;

  if (Is64BitMode) {
    if (Prefix == FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX) {
      return _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, fs_cached));
    } else if (Prefix == FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX) {
      return _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, gs_cached));
    }
    // If there was any other segment in 64bit then it is ignored
  } else {
    if (Prefix == FEXCore::X86Tables::DecodeFlags::FLAG_NO_PREFIX || Override) {
      // If there was no prefix then use the default one if available
      // Or the argument only uses a specific prefix (with override set)
      Prefix = DefaultPrefix;
    }
    // With the segment register optimization we store the GDT bases directly in the segment register to remove indexed loads
    Ref SegmentResult {};
    switch (Prefix) {
    [[likely]] case FEXCore::X86Tables::DecodeFlags::FLAG_NO_PREFIX:
      return nullptr;
    case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX:
      SegmentResult = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, es_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX:
      SegmentResult = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, cs_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX:
      SegmentResult = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, ss_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX:
      SegmentResult = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, ds_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX:
      SegmentResult = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, fs_cached));
      break;
    case FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX:
      SegmentResult = _LoadContextGPR(GPRSize, offsetof(FEXCore::Core::CPUState, gs_cached));
      break;
    default: FEX_UNREACHABLE;
    }

    CheckLegacySegmentRead(SegmentResult, Prefix);
    return SegmentResult;
  }
  return nullptr;
}

Ref OpDispatchBuilder::AppendSegmentOffset(Ref Value, uint32_t Flags, uint32_t DefaultPrefix, bool Override) {
  auto Segment = GetSegment(Flags, DefaultPrefix, Override);
  if (Segment) {
    Value = Add(std::max(OpSize::i32Bit, std::max(GetOpSize(Value), GetOpSize(Segment))), Value, Segment);
  }

  return Value;
}


void OpDispatchBuilder::CheckLegacySegmentRead(Ref NewNode, uint32_t SegmentReg) {
#ifndef FEX_DISABLE_TELEMETRY
  if (SegmentReg == FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX || SegmentReg == FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX) {
    // FS and GS segments aren't considered legacy.
    return;
  }

  if (!(SegmentsNeedReadCheck & SegmentReg)) {
    // If the block has done multiple reads of a segment register then skip redundant read checks.
    // Segment write will cause another read check.
    return;
  }

  if (CTX->Config.DisableTelemetry()) {
    // Telemetry disabled at runtime.
    return;
  }

  FEXCore::Telemetry::TelemetryType TelemIndex {};
  switch (SegmentReg) {
  case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_USES_32BIT_SEGMENT_ES;
    SegmentsNeedReadCheck &= ~FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX;
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_USES_32BIT_SEGMENT_CS;
    SegmentsNeedReadCheck &= ~FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX;
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_USES_32BIT_SEGMENT_SS;
    SegmentsNeedReadCheck &= ~FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX;
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_USES_32BIT_SEGMENT_DS;
    SegmentsNeedReadCheck &= ~FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX;
    break;
  default: FEX_UNREACHABLE;
  }

  // Will set the telemetry value if NewNode is != 0
  _TelemetrySetValue(NewNode, TelemIndex);
  // Telemetry will dirty flags, and user code does not expect LoadSource to clobber flags, fix that up here as this is an edge case.
  CalculateDeferredFlags();
#endif
}

void OpDispatchBuilder::CheckLegacySegmentWrite(Ref NewNode, uint32_t SegmentReg) {
#ifndef FEX_DISABLE_TELEMETRY
  if (SegmentReg == FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX || SegmentReg == FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX) {
    // FS and GS segments aren't considered legacy.
    return;
  }

  if (CTX->Config.DisableTelemetry()) {
    // Telemetry disabled at runtime.
    return;
  }

  FEXCore::Telemetry::TelemetryType TelemIndex {};
  switch (SegmentReg) {
  case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_WRITES_32BIT_SEGMENT_ES;
    SegmentsNeedReadCheck |= FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX;
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_WRITES_32BIT_SEGMENT_CS;
    SegmentsNeedReadCheck |= FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX;
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_WRITES_32BIT_SEGMENT_SS;
    SegmentsNeedReadCheck |= FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX;
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX:
    TelemIndex = FEXCore::Telemetry::TelemetryType::TYPE_WRITES_32BIT_SEGMENT_DS;
    SegmentsNeedReadCheck |= FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX;
    break;
  default: FEX_UNREACHABLE;
  }

  // Will set the telemetry value if NewNode is != 0
  _TelemetrySetValue(NewNode, TelemIndex);
  // Telemetry will dirty flags, and user code does not expect LoadSource to clobber flags, fix that up here as this is an edge case.
  CalculateDeferredFlags();
#endif
}

void OpDispatchBuilder::UpdatePrefixFromSegment(Ref Segment, uint32_t SegmentReg) {
  // Use BFE to extract the selector index in bits [15,3] of the segment register.
  // In some cases the upper 16-bits of the 32-bit GPR contain garbage to ignore.
  auto GDT = _Bfe(OpSize::i32Bit, 1, 2, Segment);
  // Fun quirk, if we mask the selector then it is premultiplied by 8 which we need to do for accessing anyway.
  auto SegmentOffset = _And(OpSize::i32Bit, Segment, _Constant(0xfff8));
  Ref SegmentBase = _LoadContextGPRIndexed(GDT, OpSize::i64Bit, offsetof(FEXCore::Core::CPUState, segment_arrays[0]), 8);
  Ref NewSegment = _LoadMemGPR(OpSize::i64Bit, SegmentBase, SegmentOffset, OpSize::i8Bit, MemOffsetType::UXTW, 1);
  CheckLegacySegmentWrite(NewSegment, SegmentReg);

  // Extract the 32-bit base from the GDT segment.
  auto Upper32 = _Lshr(OpSize::i64Bit, NewSegment, _Constant(32));
  auto Masked = _And(OpSize::i32Bit, Upper32, _Constant(0xFF00'0000));
  Ref Merged = _Orlshr(OpSize::i32Bit, Masked, NewSegment, 16);
  NewSegment = _Bfi(OpSize::i32Bit, 8, 16, Merged, Upper32);

  switch (SegmentReg) {
  case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX:
    _StoreContextGPR(OpSize::i32Bit, NewSegment, offsetof(FEXCore::Core::CPUState, es_cached));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX:
    _StoreContextGPR(OpSize::i32Bit, NewSegment, offsetof(FEXCore::Core::CPUState, cs_cached));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX:
    _StoreContextGPR(OpSize::i32Bit, NewSegment, offsetof(FEXCore::Core::CPUState, ss_cached));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX:
    _StoreContextGPR(OpSize::i32Bit, NewSegment, offsetof(FEXCore::Core::CPUState, ds_cached));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX:
    _StoreContextGPR(OpSize::i32Bit, NewSegment, offsetof(FEXCore::Core::CPUState, fs_cached));
    break;
  case FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX:
    _StoreContextGPR(OpSize::i32Bit, NewSegment, offsetof(FEXCore::Core::CPUState, gs_cached));
    break;
  default: break; // Do nothing
  }
}

uint64_t OpDispatchBuilder::CalcAddress(const X86Tables::DecodedOp& Op, const X86Tables::DecodedOperand& Operand, bool IsLoad) {
  if constexpr (!Context::BLOCK_DEBUGGING) {
    LOGMAN_MSG_A_FMT("Tried to calculate address without block debugging enabled!");
    FEX_UNREACHABLE;
  }

  const auto GPRSize = GetGPROpSize();
  const auto GPRMask = GPRSize == OpSize::i64Bit ? ~0ULL : ~0U;

  // This makes the assumption that InternalThreadState is synchronized at the point of call!
  uint64_t Ptr {};
  if (Operand.IsLiteral()) {
    Ptr = Operand.Literal();

    if (Operand.Data.Literal.Size != 8 && IsLoad) {
      // zero extend
      uint64_t width = Operand.Data.Literal.Size * 8;
      Ptr &= ((1ULL << width) - 1);
    }
  } else if (Operand.IsGPR()) {
    // Not a memory source.
    return ~0ULL;
  } else if (Operand.IsGPRDirect()) {
    Ptr = Thread->CurrentFrame->State.gregs[Operand.Data.GPR.GPR] & GPRMask;
  } else if (Operand.IsGPRIndirect() || Operand.IsGPRIndirectRelocation()) {
    Ptr = Thread->CurrentFrame->State.gregs[Operand.Data.GPR.GPR] & GPRMask;
    Ptr += static_cast<int32_t>(Operand.Data.GPRIndirect.Displacement);
  } else if (Operand.IsRIPRelative() || Operand.IsRIPRelativeRelocation()) {
    // 64-bit is RIP relative, while 32-bit is absolute.
    if (Is64BitMode) {
      Ptr = Op->PC + Op->InstSize + static_cast<int32_t>(Operand.Data.RIPLiteral.Value) - Entry;
    } else {
      Ptr = Operand.Data.RIPLiteral.Value;
    }
  } else if (Operand.IsSIB() || Operand.IsSIBRelocation()) {
    const bool IsVSIB = IsLoad && ((Op->Flags & X86Tables::DecodeFlags::FLAG_VSIB_BYTE) != 0);
    if (IsVSIB) {
      // TODO: Unhandled.
      return ~0ULL;
    }
    if (Operand.Data.SIB.Base != FEXCore::X86State::REG_INVALID) {
      Ptr = Thread->CurrentFrame->State.gregs[Operand.Data.SIB.Base] & GPRMask;
    }

    if (Operand.Data.SIB.Index != FEXCore::X86State::REG_INVALID) {
      Ptr += (Thread->CurrentFrame->State.gregs[Operand.Data.SIB.Index] * Operand.Data.SIB.Scale) & GPRMask;
    }

    Ptr += static_cast<int32_t>(Operand.Data.SIB.Offset);
  }

  auto AppendSegment = [&](uint64_t Ptr, uint32_t Flags, uint32_t DefaultPrefix = FEXCore::X86Tables::DecodeFlags::FLAG_NO_PREFIX,
                           bool Override = false) -> uint64_t {
    uint32_t Prefix = Flags & FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS;

    if (Is64BitMode) {
      if (Prefix == FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX) {
        return Ptr + Thread->CurrentFrame->State.fs_cached;
      } else if (Prefix == FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX) {
        return Ptr + Thread->CurrentFrame->State.gs_cached;
      }
      // If there was any other segment in 64bit then it is ignored
    } else {
      if (Prefix == FEXCore::X86Tables::DecodeFlags::FLAG_NO_PREFIX || Override) {
        // If there was no prefix then use the default one if available
        // Or the argument only uses a specific prefix (with override set)
        Prefix = DefaultPrefix;
      }
      // With the segment register optimization we store the GDT bases directly in the segment register to remove indexed loads
      switch (Prefix) {
      [[likely]] case FEXCore::X86Tables::DecodeFlags::FLAG_NO_PREFIX:
        return Ptr;
      case FEXCore::X86Tables::DecodeFlags::FLAG_ES_PREFIX: return Ptr + Thread->CurrentFrame->State.es_cached;
      case FEXCore::X86Tables::DecodeFlags::FLAG_CS_PREFIX: return Ptr + Thread->CurrentFrame->State.cs_cached;
      case FEXCore::X86Tables::DecodeFlags::FLAG_SS_PREFIX: return Ptr + Thread->CurrentFrame->State.ss_cached;
      case FEXCore::X86Tables::DecodeFlags::FLAG_DS_PREFIX: return Ptr + Thread->CurrentFrame->State.ds_cached;
      case FEXCore::X86Tables::DecodeFlags::FLAG_FS_PREFIX: return Ptr + Thread->CurrentFrame->State.fs_cached;
      case FEXCore::X86Tables::DecodeFlags::FLAG_GS_PREFIX: return Ptr + Thread->CurrentFrame->State.gs_cached;
      default: FEX_UNREACHABLE;
      }
    }

    return Ptr;
  };

  return AppendSegment(Ptr, Op->Flags);
};

AddressMode OpDispatchBuilder::DecodeAddress(const X86Tables::DecodedOp& Op, const X86Tables::DecodedOperand& Operand,
                                             MemoryAccessType AccessType, bool IsLoad) {
  const auto GPRSize = GetGPROpSize();

  AddressMode A {};
  A.Segment = GetSegment(Op->Flags);
  A.AddrSize = (Op->Flags & X86Tables::DecodeFlags::FLAG_ADDRESS_SIZE) != 0 ? (GPRSize >> 1) : GPRSize;
  A.NonTSO = AccessType == MemoryAccessType::NONTSO || AccessType == MemoryAccessType::STREAM;

  if (Operand.IsLiteral()) {
    A.Offset = Operand.Literal();

    if (Operand.Data.Literal.Size != 8 && IsLoad) {
      // zero extend
      uint64_t width = Operand.Data.Literal.Size * 8;
      A.Offset &= ((1ULL << width) - 1);
    }
  } else if (Operand.IsGPR()) {
    // Not an address, let the caller deal with it
    A.AddrSize = GPRSize;
  } else if (Operand.IsGPRDirect()) {
    A.Base = LoadGPRRegister(Operand.Data.GPR.GPR, GPRSize);
    A.NonTSO |= IsNonTSOReg(AccessType, Operand.Data.GPR.GPR);
  } else if (Operand.IsGPRIndirect() || Operand.IsGPRIndirectRelocation()) {
    A.Base = LoadGPRRegister(Operand.Data.GPRIndirect.GPR, GPRSize);
    if (Operand.IsGPRIndirectRelocation()) {
      A.Base = Add(GPRSize, _EntrypointOffset(GPRSize, Operand.Data.GPRIndirect.Displacement), A.Base);
    } else {
      A.Offset = static_cast<int32_t>(Operand.Data.GPRIndirect.Displacement);
    }
    A.NonTSO |= IsNonTSOReg(AccessType, Operand.Data.GPRIndirect.GPR);
  } else if (Operand.IsRIPRelative() || Operand.IsRIPRelativeRelocation()) {
    if (Is64BitMode) {
      A.Base = GetRelocatedPC(Op, static_cast<int32_t>(Operand.Data.RIPLiteral.Value));
    } else {
      // 32bit this isn't RIP relative but instead absolute
      if (Operand.IsRIPRelativeRelocation()) {
        A.Base = _EntrypointOffset(GPRSize, Operand.Data.RIPLiteral.Value);
      } else {
        A.Offset = Operand.Data.RIPLiteral.Value;
      }
    }
  } else if (Operand.IsSIB() || Operand.IsSIBRelocation()) {
    const bool IsVSIB = IsLoad && ((Op->Flags & X86Tables::DecodeFlags::FLAG_VSIB_BYTE) != 0);

    if (Operand.Data.SIB.Base != FEXCore::X86State::REG_INVALID) {
      A.Base = LoadGPRRegister(Operand.Data.SIB.Base, GPRSize);
    }

    // NOTE: VSIB cannot have the index * scale portion calculated ahead of time,
    //       since the index in this case is a vector. So, we can't just apply the scale
    //       to it, since this needs to be applied to each element in the index register
    //       after said element has been sign extended. So, we pass this through for the
    //       instruction implementation to handle.
    //
    //       What we do handle though, is the applying the displacement value to
    //       the base register (if a base register is provided), since this is a
    //       part of the address calculation that can be done ahead of time.
    if (!IsVSIB && Operand.Data.SIB.Index != FEXCore::X86State::REG_INVALID) {
      A.Index = LoadGPRRegister(Operand.Data.SIB.Index, GPRSize);
      A.IndexScale = Operand.Data.SIB.Scale;
    }

    if (Operand.IsSIBRelocation()) {
      auto EPOffset = _EntrypointOffset(GPRSize, Operand.Data.SIB.Offset);
      if (A.Base) {
        A.Base = Add(GPRSize, EPOffset, A.Base);
      } else {
        A.Base = EPOffset;
      }
    } else {
      A.Offset = static_cast<int32_t>(Operand.Data.SIB.Offset);
    }

    A.NonTSO |= IsNonTSOReg(AccessType, Operand.Data.SIB.Base) || IsNonTSOReg(AccessType, Operand.Data.SIB.Index);
  } else if (Operand.IsLiteralRelocation()) {
    A.Base = _EntrypointOffset(GPRSize, Operand.Data.LiteralRelocation.EntrypointOffset);
  } else {
    LOGMAN_MSG_A_FMT("Unknown Src Type: {}\n", Operand.Type);
  }

  return A;
}


Ref OpDispatchBuilder::LoadSource_WithOpSize(RegClass Class, const X86Tables::DecodedOp& Op, const X86Tables::DecodedOperand& Operand,
                                             IR::OpSize OpSize, uint32_t Flags, const LoadSourceOptions& Options) {
  auto [Align, LoadData, ForceLoad, AccessType, AllowUpperGarbage] = Options;
  AddressMode A = DecodeAddress(Op, Operand, AccessType, true /* IsLoad */);

  Ref Result {};
  if (Operand.IsGPR()) {
    const auto gpr = Operand.Data.GPR.GPR;
    const auto highIndex = Operand.Data.GPR.HighBits ? 1 : 0;

    if (gpr >= FEXCore::X86State::REG_MM_0) {
      LOGMAN_THROW_A_FMT(OpSize == OpSize::i64Bit, "full");

      if (MMXState != MMXState_MMX) {
        ChgStateX87_MMX();
      }

      A.Base = LoadContext(OpSize::i64Bit, MM0Index + gpr - FEXCore::X86State::REG_MM_0);
    } else if (gpr >= FEXCore::X86State::REG_XMM_0) {
      const auto gprIndex = gpr - X86State::REG_XMM_0;

      // Load the full register size if it is a XMM register source.
      A.Base = LoadXMMRegister(gprIndex);

      // Now extract the subregister if it was a partial load /smaller/ than SSE size
      // TODO: Instead of doing the VMov implicitly on load, hunt down all use cases that require partial loads and do it after load.
      // We don't have information here to know if the operation needs zero upper bits or can contain data.
      if (!AllowUpperGarbage && OpSize < OpSize::i128Bit) {
        A.Base = _VMov(OpSize, A.Base);
      }
    } else {
      A.Base = LoadGPRRegister(gpr, OpSize, highIndex ? 8 : 0, AllowUpperGarbage);
    }
  }

  const bool ShouldLoad = (IsOperandMem(Operand, true) && LoadData) || ForceLoad;
  if (ShouldLoad) {
    MacRunnerKusdRewrite(A, Is64BitMode, GetGPROpSize());
    if (OpSize == OpSize::f80Bit) {
      Ref MemSrc = LoadEffectiveAddress(this, A, GetGPROpSize(), true);
      if (CTX->HostFeatures.SupportsSVE()) {
        Result = _LoadMemX87SVEOptPredicate(OpSize::i128Bit, OpSize::i16Bit, MemSrc);
      } else {
        // For X87 extended doubles, Split the load.
        auto Res = _LoadMem(Class, OpSize::i64Bit, MemSrc, Align == OpSize::iInvalid ? OpSize : Align);
        Result = _VLoadVectorElement(OpSize::i128Bit, OpSize::i16Bit, Res, 4, Add(OpSize::i64Bit, MemSrc, 8));
      }
    } else {
      Result = _LoadMemAutoTSO(Class, OpSize, A, Align == OpSize::iInvalid ? OpSize : Align);
    }
  } else {
    Result = LoadEffectiveAddress(this, A, GetGPROpSize(), false, AllowUpperGarbage);
  }

  if constexpr (Context::BLOCK_DEBUGGING) {
    if (ShouldLoad && CTX->BlockDebuggerTracker.IsSingleStepTarget(Entry)) {
      uint64_t Ptr = CalcAddress(Op, Operand, true);
      if (CTX->BlockDebuggerTracker.ContainsReadWatchPoint(Ptr, OpSizeToSize(OpSize))) {
        // It's up to the developer if they want more advanced debugging logic here.
        LogMan::Msg::IFmt("Entrypoint 0x{:x} will hit read watch: [0x{:x}, 0x{:x})", Entry, Ptr, Ptr + OpSizeToSize(OpSize));
      }
    }
  }

  return Result;
}

Ref OpDispatchBuilder::LoadGPRRegister(uint32_t GPR, IR::OpSize Size, uint8_t Offset, bool AllowUpperGarbage) {
  const auto GPRSize = GetGPROpSize();
  if (Size == OpSize::iInvalid) {
    Size = GPRSize;
  }
  Ref Reg = LoadGPR(GPR);

  if ((!AllowUpperGarbage && (Size != GPRSize)) || Offset != 0) {
    // Extract the subregister if requested.
    const auto OpSize = std::max(OpSize::i32Bit, Size);
    if (AllowUpperGarbage) {
      Reg = _Lshr(OpSize, Reg, Constant(Offset));
    } else {
      Reg = _Bfe(OpSize, IR::OpSizeAsBits(Size), Offset, Reg);
    }
  }
  return Reg;
}

void OpDispatchBuilder::StoreGPRRegister(uint32_t GPR, const Ref Src, IR::OpSize Size, uint8_t Offset) {
  const auto GPRSize = GetGPROpSize();
  if (Size == OpSize::iInvalid) {
    Size = GPRSize;
  }

  Ref Reg = Src;
  if (Size != GPRSize || Offset != 0) {
    // Need to do an insert if not automatic size or zero offset.
    Reg = ARef(Reg).BfiInto(LoadGPRRegister(GPR), Offset, IR::OpSizeAsBits(Size));
  }

  StoreRegister(GPR, false, Reg);
}

void OpDispatchBuilder::StoreXMMRegister(uint32_t XMM, const Ref Src) {
  StoreRegister(XMM, true, Src);
}

Ref OpDispatchBuilder::LoadSource(RegClass Class, const X86Tables::DecodedOp& Op, const X86Tables::DecodedOperand& Operand, uint32_t Flags,
                                  const LoadSourceOptions& Options) {
  const auto OpSize = OpSizeFromSrc(Op);
  return LoadSource_WithOpSize(Class, Op, Operand, OpSize, Flags, Options);
}

void OpDispatchBuilder::StoreResult_WithOpSize(RegClass Class, FEXCore::X86Tables::DecodedOp Op, const X86Tables::DecodedOperand& Operand,
                                               Ref Src, IR::OpSize OpSize, IR::OpSize Align, MemoryAccessType AccessType) {
  if (Operand.IsGPR()) {
    // 8Bit and 16bit destination types store their result without effecting the upper bits
    // 32bit ops ZEXT the result to 64bit
    const auto GPRSize = GetGPROpSize();

    const auto gpr = Operand.Data.GPR.GPR;
    if (gpr >= FEXCore::X86State::REG_MM_0) {
      LOGMAN_THROW_A_FMT(OpSize == OpSize::i64Bit, "full");
      LOGMAN_THROW_A_FMT(Class == RegClass::FPR, "MMX is floaty");

      if (MMXState != MMXState_MMX) {
        ChgStateX87_MMX();
      }

      uint8_t Index = MM0Index + gpr - FEXCore::X86State::REG_MM_0;
      StoreContext(Index, Src);
      RegCache.Partial |= (1ull << (uint64_t)Index);
    } else if (gpr >= FEXCore::X86State::REG_XMM_0) {
      const auto gprIndex = gpr - X86State::REG_XMM_0;
      const auto VectorSize = GetGuestVectorLength();

      auto Result = Src;
      if (OpSize != VectorSize) {
        // Partial writes can come from FPRs.
        // TODO: Fix the instructions doing partial writes rather than dealing with it here.

        LOGMAN_THROW_A_FMT(Class != RegClass::GPR, "Partial writes from GPR not allowed. Instruction: {}", Op->TableInfo->Name);

        // XMM-size is handled in implementations.
        if (VectorSize != OpSize::i256Bit || OpSize != OpSize::i128Bit) {
          auto SrcVector = LoadXMMRegister(gprIndex);
          Result = _VInsElement(VectorSize, OpSize, 0, 0, SrcVector, Src);
        }
      }

      StoreXMMRegister(gprIndex, Result);
    } else {
      if (GPRSize == OpSize::i64Bit && OpSize == OpSize::i32Bit) {
        // If the Source IR op is 64 bits, we need to zext the upper bits
        // For all other sizes, the upper bits are guaranteed to already be zero
        Ref Value = GetOpSize(Src) == OpSize::i64Bit ? ARef(Src).Bfe(0, 32).Ref() : Src;
        StoreGPRRegister(gpr, Value, GPRSize);

        LOGMAN_THROW_A_FMT(!Operand.Data.GPR.HighBits, "Can't handle 32bit store to high 8bit register");
      } else {
        LOGMAN_THROW_A_FMT(!(GPRSize == OpSize::i32Bit && OpSize > OpSize::i32Bit), "Oops had a {} GPR load", OpSize);

        if (GPRSize != OpSize) {
          // if the GPR isn't the full size then we need to insert.
          // eg:
          // mov al, 2 ; Move in to lower 8-bits.
          // mov ah, 2 ; Move in to upper 8-bits of 16-bit reg.
          // mov ax, 2 ; Move in to lower 16-bits of reg.
          StoreGPRRegister(gpr, Src, OpSize, Operand.Data.GPR.HighBits * 8);
        } else {
          StoreGPRRegister(gpr, Src, std::min(GPRSize, OpSize));
        }
      }
    }
    return;
  }

  AddressMode A = DecodeAddress(Op, Operand, AccessType, false /* IsLoad */);
  MacRunnerKusdRewrite(A, Is64BitMode, GetGPROpSize());

  if (OpSize == OpSize::f80Bit) {
    Ref MemStoreDst = LoadEffectiveAddress(this, A, GetGPROpSize(), true);
    if (CTX->HostFeatures.SupportsSVE()) {
      _StoreMemX87SVEOptPredicate(OpSize::i128Bit, OpSize::i16Bit, Src, MemStoreDst);
    } else {
      // For X87 extended doubles, split before storing
      _StoreMemFPR(OpSize::i64Bit, MemStoreDst, Src, Align);
      auto Upper = _VExtractToGPR(OpSize::i128Bit, OpSize::i64Bit, Src, 1);
      _StoreMemGPR(OpSize::i16Bit, Upper, MemStoreDst, Constant(8), std::min(Align, OpSize::i64Bit), MemOffsetType::SXTX, 1);
    }
  } else {
    _StoreMemAutoTSO(Class, OpSize, A, Src, Align == OpSize::iInvalid ? OpSize : Align);
  }

  if constexpr (Context::BLOCK_DEBUGGING) {
    if (CTX->BlockDebuggerTracker.IsSingleStepTarget(Entry)) {
      uint64_t Ptr = CalcAddress(Op, Operand, false);
      if (CTX->BlockDebuggerTracker.ContainsWriteWatchPoint(Ptr, OpSizeToSize(OpSize))) {
        // It's up to the developer if they want more advanced debugging logic here.
        LogMan::Msg::IFmt("Entrypoint 0x{:x} will hit write watch: [0x{:x}, 0x{:x})", Entry, Ptr, Ptr + OpSizeToSize(OpSize));
      }
    }
  }
}

void OpDispatchBuilder::StoreResult(RegClass Class, X86Tables::DecodedOp Op, const X86Tables::DecodedOperand& Operand, Ref Src,
                                    IR::OpSize Align, MemoryAccessType AccessType) {
  StoreResult_WithOpSize(Class, Op, Operand, Src, OpSizeFromDst(Op), Align, AccessType);
}

void OpDispatchBuilder::StoreResult(RegClass Class, X86Tables::DecodedOp Op, Ref Src, IR::OpSize Align, MemoryAccessType AccessType) {
  StoreResult(Class, Op, Op->Dest, Src, Align, AccessType);
}

OpDispatchBuilder::OpDispatchBuilder(FEXCore::Context::ContextImpl* ctx, FEXCore::Core::InternalThreadState* Thread)
  : IREmitter {ctx->OpDispatcherAllocator, ctx->HostFeatures.SupportsTSOImm9}
  , CTX {ctx}
  , Thread {Thread} {
  if (CTX->HostFeatures.SupportsAVX && CTX->HostFeatures.SupportsSVE256) {
    SaveAVXStateFunc = &OpDispatchBuilder::SaveAVXState;
    RestoreAVXStateFunc = &OpDispatchBuilder::RestoreAVXState;
    DefaultAVXStateFunc = &OpDispatchBuilder::DefaultAVXState;
  } else if (CTX->HostFeatures.SupportsAVX) {
    SaveAVXStateFunc = &OpDispatchBuilder::AVX128_SaveAVXState;
    RestoreAVXStateFunc = &OpDispatchBuilder::AVX128_RestoreAVXState;
    DefaultAVXStateFunc = &OpDispatchBuilder::AVX128_DefaultAVXState;
  }
}

void OpDispatchBuilder::ResetWorkingList() {
  IREmitter::ReownOrClaimBuffer();

  JumpTargets.clear();
  BlockSetRIP = false;
  DecodeFailure = false;
  ShouldDump = false;
  CurrentCodeBlock = nullptr;
  RegCache.Written = 0;
  RegCache.Cached = 0;
  ResetMacRunnerDivFacts();
}

void OpDispatchBuilder::UnhandledOp(OpcodeArgs) {
  DecodeFailure = true;
}

void OpDispatchBuilder::MOVGPROp(OpcodeArgs, uint32_t SrcIndex) {
  // StoreResult will store with the same size as the input, so we allow upper
  // garbage on the input. The zero extension would be pointless.
  Ref Src = LoadSourceGPR(Op, Op->Src[SrcIndex], Op->Flags, {.Align = OpSize::i8Bit, .AllowUpperGarbage = true});
  StoreResultGPR(Op, Src, OpSize::i8Bit);
  if (MacRunnerDivFastMode() && MacRunnerDivProvenHighMode() && Op->Dest.IsGPR() && !Op->Dest.Data.GPR.HighBits &&
      OpSizeFromDst(Op) >= OpSize::i32Bit) {
    const auto Dest = Op->Dest.Data.GPR.GPR;
    const auto& Source = Op->Src[SrcIndex];
    if (MacRunnerDivFastMode() >= 6) {
      if (OpSizeFromDst(Op) == OpSize::i32Bit && Dest != X86State::REG_RAX && Dest != X86State::REG_RDX) {
        // Every completed full r32 write clears its architectural upper 32 bits.
        // Therefore this divisor cannot be -1 at IDIV64, but it may still be zero.
        // Record identity/PC only: a memory-source MOV must complete normally first.
        MacRunnerDivZeroExtEnd = Op->PC + Op->InstSize;
        MacRunnerDivZeroExtRegister = Dest;
      } else if (MacRunnerDivZeroExtEnd == Op->PC && Dest != MacRunnerDivZeroExtRegister &&
                 ((Dest == X86State::REG_RAX && (Source.IsGPR() || Source.IsLiteral())) ||
                  (Dest == X86State::REG_RDX && Source.IsLiteral() && Source.Literal() == 0))) {
        // Only the explicit adjacent dividend-prefix MOVs extend the proof.
        MacRunnerDivZeroExtEnd = Op->PC + Op->InstSize;
      } else {
        MacRunnerDivZeroExtEnd = 0;
      }
    }
    if (MacRunnerDivFastMode() >= 2) {
      uint64_t Value {};
      if (Dest != X86State::REG_RAX && Dest != X86State::REG_RDX && Source.IsLiteral()) {
        // Use the loaded literal, including C7 imm32 sign extension. A 32-bit
        // destination architecturally clears the upper half of the register.
        MacRunnerDivConstEnd = 0;
        if (IsValueConstant(WrapNode(Src), &Value)) {
          MacRunnerDivConstEnd = Op->PC + Op->InstSize;
          MacRunnerDivConstValue = OpSizeFromDst(Op) == OpSize::i32Bit ? uint32_t(Value) : Value;
          MacRunnerDivConstRegister = Dest;
        }
      } else if (MacRunnerDivConstEnd == Op->PC && Dest != MacRunnerDivConstRegister &&
                 ((Dest == X86State::REG_RAX && (Source.IsGPR() || Source.IsLiteral())) ||
                  (Dest == X86State::REG_RDX && Source.IsLiteral() && Source.Literal() == 0))) {
        MacRunnerDivConstEnd = Op->PC + Op->InstSize;
      }
    }
    if (Dest == X86State::REG_RAX && Source.IsGPR() && !Source.Data.GPR.HighBits &&
        Source.Data.GPR.GPR != X86State::REG_RAX && Source.Data.GPR.GPR != X86State::REG_RDX &&
        OpSizeFromSrc(Op) == OpSizeFromDst(Op)) {
      MacRunnerDivLowerEnd = Op->PC + Op->InstSize;
      MacRunnerDivLowerSize = OpSizeFromDst(Op);
      MacRunnerDivLowerSource = Source.Data.GPR.GPR;
    }
    if (Dest == X86State::REG_RDX && Op->Src[SrcIndex].IsLiteral() && Op->Src[SrcIndex].Literal() == 0) {
      MacRunnerZeroRDXEnd = Op->PC + Op->InstSize;
      if (MacRunnerDivLowerEnd == Op->PC) {
        MacRunnerDivLowerEnd = Op->PC + Op->InstSize;
      }
    } else if (Dest == X86State::REG_RAX && MacRunnerZeroRDXEnd != 0 && MacRunnerZeroRDXEnd == Op->PC) {
      // The measured xbench idiom inserts MOV EAX between XOR EDX and DIV ECX.
      // This single adjacent MOV cannot change RDX. Do not extend sign proofs:
      // changing RAX after CDQ/CQO could invalidate the high-half relationship.
      MacRunnerZeroRDXEnd = Op->PC + Op->InstSize;
    }
  }
}

void OpDispatchBuilder::MOVGPRNTOp(OpcodeArgs) {
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.Align = OpSize::i8Bit});
  StoreResultGPR(Op, Src, OpSize::i8Bit, MemoryAccessType::STREAM);
}

void OpDispatchBuilder::ALUOp(OpcodeArgs, FEXCore::IR::IROps ALUIROp, FEXCore::IR::IROps AtomicFetchOp, unsigned SrcIdx) {
  // On x86, the canonical way to zero a register is XOR with itself. Detect and
  // emit optimal arm64 assembly.
  if (!DestIsLockedMem(Op) && ALUIROp == FEXCore::IR::IROps::OP_XOR && Op->Dest.IsGPR() && Op->Src[SrcIdx].IsGPR() &&
      Op->Dest.Data.GPR == Op->Src[SrcIdx].Data.GPR) {

    // Set flags for zero result with inverted carry. We subtract an arbitrary
    // register from itself to get the zero, since `subs wzr, #0` is not
    // encodable. This is optimal and works regardless of the opsize.
    auto Zero = LoadGPR(Op->Dest.Data.GPR.GPR);
    HandleNZ00Write();
    InvalidateAF();
    CalculatePF(SubWithFlags(OpSize::i32Bit, Zero, Zero));
    CFInverted = true;
    FlushRegisterCache();

    // Move 0 into the register
    StoreResultGPR(Op, Constant(0));

    // ★ MacRunner (MACRUNNER_FEX_DIV_PROVEN_HIGH=1): `xor edx, edx` / `xor rdx, rdx` zeroes all of RDX. A DIV that
    // starts right after it, in this block, divides a zero-extended dividend (DivHighHalfProven).
    if (MacRunnerDivProvenHighMode() && Op->Dest.Data.GPR.GPR == X86State::REG_RDX && !Op->Dest.Data.GPR.HighBits &&
        OpSizeFromDst(Op) >= OpSize::i32Bit) {
      if (MacRunnerDivFastMode() >= 2 && MacRunnerDivConstEnd == Op->PC) {
        MacRunnerDivConstEnd = Op->PC + Op->InstSize;
      }
      MacRunnerZeroRDXEnd = Op->PC + Op->InstSize;
      if (MacRunnerDivFastMode() && MacRunnerDivLowerEnd == Op->PC) {
        MacRunnerDivLowerEnd = Op->PC + Op->InstSize;
      }
    }
    return;
  }

  auto Size = OpSizeFromDst(Op);
  auto ResultSize = Size;

  auto RoundedSize = Size;
  if (ALUIROp != FEXCore::IR::IROps::OP_ANDWITHFLAGS) {
    RoundedSize = std::max(OpSize::i32Bit, RoundedSize);
  }

  // X86 basic ALU ops just do the operation between the destination and a single source
  Ref Src = LoadSourceGPR(Op, Op->Src[SrcIdx], Op->Flags, {.AllowUpperGarbage = true});

  // Try to eliminate the masking after 8/16-bit operations with constants, by
  // promoting to a full size operation that preserves the upper bits.
  uint64_t Const;
  bool IsConst = IsValueConstant(WrapNode(Src), &Const);
  if (Size < OpSize::i32Bit && !DestIsLockedMem(Op) && Op->Dest.IsGPR() && !Op->Dest.Data.GPR.HighBits && IsConst &&
      (ALUIROp == IR::IROps::OP_XOR || ALUIROp == IR::IROps::OP_OR || ALUIROp == IR::IROps::OP_ANDWITHFLAGS)) {

    RoundedSize = ResultSize = GetGPROpSize();
    LOGMAN_THROW_A_FMT(Const < (1ull << IR::OpSizeAsBits(Size)), "does not clobber");

    // For AND, we can play the same trick but we instead need the upper bits of
    // the constant to be all-1s instead of all-0s to preserve. We also can't
    // use andwithflags in this case, since we've promoted to 64-bit so the
    // negate flag would be wrong, but using the regular logical operation path
    // instead still ends up a net win for uops.
    //
    // In the common case where the constant is of the form (1 << x) - 1, the
    // adjusted constant here will inline into the arm64 and instruction, so if
    // flags are not needed, we save an instruction overall.
    if (ALUIROp == IR::IROps::OP_ANDWITHFLAGS) {
      Src = Constant(Const | ~((1ull << IR::OpSizeAsBits(Size)) - 1));
      ALUIROp = IR::IROps::OP_AND;
    }
  }

  Ref Result {};
  Ref Dest {};

  if (DestIsLockedMem(Op)) {
    HandledLock = true;
    Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
    DeriveOp(FetchOp, AtomicFetchOp, _AtomicFetchAdd(Size, Src, DestMem));
    Dest = FetchOp;
  } else {
    Dest = LoadSourceGPR(Op, Op->Dest, Op->Flags, {.AllowUpperGarbage = true});
  }

  const auto OpSize = RoundedSize;
  const bool StoredBeforeFlags = !DestIsLockedMem(Op) && !Op->Dest.IsGPR() && MacRunnerRMWFlagsAfterStore();
  if (StoredBeforeFlags && ALUIROp == IR::IROps::OP_ANDWITHFLAGS) {
    ALUIROp = IR::IROps::OP_AND;
  }
  uint64_t Mask = Size == OpSize::i64Bit ? ~0ull : ((1ull << IR::OpSizeAsBits(Size)) - 1);
  if (IsConst && Const == Mask && !DestIsLockedMem(Op) && ALUIROp == IR::IROps::OP_XOR && Size >= OpSize::i32Bit) {
    Result = _Not(OpSize, Dest);
  } else if (IsConst && Const == Mask && !DestIsLockedMem(Op) && ALUIROp == IR::IROps::OP_AND) {
    Result = Dest;
  } else if (StoredBeforeFlags && ALUIROp == IR::IROps::OP_ADD) {
    // The stored result must use the arithmetic emitter's immediate contract.
    // DeriveOp(_AndWithFlags) can inline a negative logical immediate that is
    // not encodable by ADD. It was dead before the flags result replaced it.
    Result = Add(OpSize, Dest, Src);
  } else if (StoredBeforeFlags && ALUIROp == IR::IROps::OP_SUB) {
    Result = Sub(OpSize, Dest, Src);
  } else {
    DeriveOp(ALUOp, ALUIROp, _AndWithFlags(OpSize, Dest, Src));
    Result = ALUOp;
  }

  if (StoredBeforeFlags) {
    StoreResultGPR_WithOpSize(Op, Op->Dest, Result, ResultSize, OpSize::iInvalid, MemoryAccessType::DEFAULT);
  }

  // Flags set. In the precise RMW mode the faultable store has completed.
  switch (ALUIROp) {
  case FEXCore::IR::IROps::OP_ADD: Result = CalculateFlags_ADD(Size, Dest, Src); break;
  case FEXCore::IR::IROps::OP_SUB: Result = CalculateFlags_SUB(Size, Dest, Src); break;
  case FEXCore::IR::IROps::OP_XOR:
  case FEXCore::IR::IROps::OP_AND:
  case FEXCore::IR::IROps::OP_OR: {
    CalculateFlags_Logical(Size, Result);
    break;
  }
  case FEXCore::IR::IROps::OP_ANDWITHFLAGS: {
    HandleNZ00Write();
    CalculatePF(Result);
    InvalidateAF();
    break;
  }
  default: break;
  }

  if (!DestIsLockedMem(Op) && !StoredBeforeFlags) {
    StoreResultGPR_WithOpSize(Op, Op->Dest, Result, ResultSize, OpSize::iInvalid, MemoryAccessType::DEFAULT);
  }
}

void OpDispatchBuilder::LSLOp(OpcodeArgs) {
  // Emulate by always returning failure, this deviates from both Linux and Windows but
  // shouldn't be depended on by anything.
  SetRFLAG<FEXCore::X86State::RFLAG_ZF_RAW_LOC>(Constant(0));
}

void OpDispatchBuilder::INTOp(OpcodeArgs) {
  IR::BreakDefinition Reason;
  bool SetRIPToNext = false;

  switch (Op->OP) {
  case 0xCD: { // INT imm8
    uint8_t Literal = Op->Src[0].Literal();

    const char* Exact = std::getenv("MACRUNNER_WINCTX_EXACT");
    if (Literal == 3 && Exact && Exact[0] == '1' && !Exact[1] &&
        (CTX->HostFeatures.HostType == FEXCore::HostFeatures::HostTypeEnum::Arm64ec ||
         CTX->HostFeatures.HostType == FEXCore::HostFeatures::HostTypeEnum::Wow64)) {
      Reason.ErrorRegister = 0;
      Reason.Signal = Core::FAULT_SIGTRAP;
      Reason.TrapNumber = X86State::X86_TRAPNO_BP;
      Reason.si_code = 0x80;
      SetRIPToNext = true;
      break;
    }

    if (CTX->HostFeatures.HostType == FEXCore::HostFeatures::HostTypeEnum::Linux) {
      constexpr uint8_t SYSCALL_LITERAL = 0x80;
      if (Literal == SYSCALL_LITERAL) {
        if (Is64BitMode) [[unlikely]] {
          LogMan::Msg::EFmt("[Unsupported] Trying to execute 32-bit syscall from a 64-bit process.");
          UnhandledOp(Op);
          return;
        }
        // Syscall on linux
        SyscallOp(Op, false);
        return;
      }
    } else if (CTX->HostFeatures.HostType == FEXCore::HostFeatures::HostTypeEnum::Wow64 ||
               CTX->HostFeatures.HostType == FEXCore::HostFeatures::HostTypeEnum::Arm64ec) {
      constexpr uint8_t SYSCALL_LITERAL = 0x2E;
      if (Literal == SYSCALL_LITERAL) {
        // Can be used for both 64-bit and 32-bit syscalls on windows
        SyscallOp(Op, false);
        return;
      }

      if (CTX->HostFeatures.HostType == FEXCore::HostFeatures::HostTypeEnum::Arm64ec) {
        // This is used when QueryPerformanceCounter is called on recent Windows versions, it causes CNTVCT to be written into RAX.
        constexpr uint8_t GET_CNTVCT_LITERAL = 0x81;
        if (Literal == GET_CNTVCT_LITERAL) {
          StoreGPRRegister(X86State::REG_RAX, _CycleCounter(false));
          return;
        }
      }
    }

    Reason.ErrorRegister = Literal << 3 | (0b010);
    Reason.Signal = Core::FAULT_SIGSEGV;
    // GP is raised when task-gate isn't setup to be valid
    Reason.TrapNumber = X86State::X86_TRAPNO_GP;
    Reason.si_code = 0x80;
    break;
  }
  case 0xCE: // INTO
    Reason.ErrorRegister = 0;
    Reason.Signal = Core::FAULT_SIGSEGV;
    Reason.TrapNumber = X86State::X86_TRAPNO_OF;
    Reason.si_code = 0x80;
    break;
  case 0xF1: // INT1
    Reason.ErrorRegister = 0;
    Reason.Signal = Core::FAULT_SIGTRAP;
    Reason.TrapNumber = X86State::X86_TRAPNO_DB;
    Reason.si_code = 1;
    SetRIPToNext = true;
    break;
  case 0xF4: { // HLT
    Reason.ErrorRegister = 0;
    Reason.Signal = Core::FAULT_SIGSEGV;
    Reason.TrapNumber = X86State::X86_TRAPNO_GP;
    Reason.si_code = 0x80;
    break;
  }
  case 0x0B: // UD2
    Reason.ErrorRegister = 0;
    Reason.Signal = Core::FAULT_SIGILL;
    Reason.TrapNumber = X86State::X86_TRAPNO_UD;
    Reason.si_code = 2;
    break;
  case 0xCC: // INT3
    Reason.ErrorRegister = 0;
    Reason.Signal = Core::FAULT_SIGTRAP;
    Reason.TrapNumber = X86State::X86_TRAPNO_BP;
    Reason.si_code = 0x80;
    SetRIPToNext = true;
    break;
  default: FEX_UNREACHABLE;
  }

  // Calculate flags early.
  FlushRegisterCache();

  const auto GPRSize = GetGPROpSize();

  if (SetRIPToNext) {
    BlockSetRIP = SetRIPToNext;

    // We want to set RIP to the next instruction after INT3/INT1
    auto NewRIP = GetRelocatedPC(Op);
    _StoreContextGPR(GPRSize, NewRIP, offsetof(FEXCore::Core::CPUState, rip));
  } else if (Op->OP != 0xCE) {
    auto NewRIP = GetRelocatedPC(Op, -Op->InstSize);
    _StoreContextGPR(GPRSize, NewRIP, offsetof(FEXCore::Core::CPUState, rip));
  }

  if (Op->OP == 0xCE) { // Conditional to only break if Overflow == 1
    CalculateDeferredFlags();

    // If condition doesn't hold then keep going
    // CondClass::FNU means OF == 0
    auto CondJump_ = CondJumpNZCV(CondClass::FNU);
    auto FalseBlock = CreateNewCodeBlockAfter(GetCurrentBlock());
    SetFalseJumpTarget(CondJump_, FalseBlock);
    SetCurrentCodeBlock(FalseBlock);
    StartNewBlock();

    auto NewRIP = GetRelocatedPC(Op);
    _StoreContextGPR(GPRSize, NewRIP, offsetof(FEXCore::Core::CPUState, rip));
    Break(Reason);

    // Make sure to start a new block after ending this one
    auto JumpTarget = CreateNewCodeBlockAfter(FalseBlock);
    SetTrueJumpTarget(CondJump_, JumpTarget);
    SetCurrentCodeBlock(JumpTarget);
    StartNewBlock();
  } else {
    BlockSetRIP = true;
    Break(Reason);
  }
}

void OpDispatchBuilder::TZCNT(OpcodeArgs) {
  // _FindTrailingZeroes ignores upper garbage so we don't need to mask
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

  Src = _FindTrailingZeroes(OpSizeFromSrc(Op), Src);
  StoreResultGPR(Op, Src);

  CalculateFlags_ZCNT(OpSizeFromSrc(Op), Src);
}

void OpDispatchBuilder::LZCNT(OpcodeArgs) {
  // _CountLeadingZeroes clears upper garbage so we don't need to mask
  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.AllowUpperGarbage = true});

  auto Res = _CountLeadingZeroes(OpSizeFromSrc(Op), Src);
  StoreResultGPR(Op, Res);
  CalculateFlags_ZCNT(OpSizeFromSrc(Op), Res);
}

void OpDispatchBuilder::MOVBEOp(OpcodeArgs) {
  const auto GPRSize = GetGPROpSize();
  const auto SrcSize = OpSizeFromSrc(Op);

  Ref Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.Align = OpSize::i8Bit});

  if (DestIsMem(Op) || SrcSize != OpSize::i16Bit) {
    Src = _Rev(SrcSize, Src);
    StoreResultGPR(Op, Op->Dest, Src);
  } else {
    Src = _Rev(std::max(OpSize::i32Bit, SrcSize), Src);
    // 16-bit does an insert.
    // Rev of 16-bit value as 32-bit replaces the result in the upper 16-bits of the result.
    // bfxil the 16-bit result in to the GPR.
    Ref Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, GPRSize, Op->Flags);
    auto Result = _Bfxil(GPRSize, 16, 16, Dest, Src);
    StoreResultGPR_WithOpSize(Op, Op->Dest, Result, GPRSize);
  }
}

void OpDispatchBuilder::CLWBOrTPause(OpcodeArgs) {
  if (DestIsMem(Op)) {
    Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
    _CacheLineClean(DestMem);
  } else {
    if (!CTX->HostFeatures.SupportsWFXT) {
      UnimplementedOp(Op);
    } else {
      auto RAX = LoadGPRRegister(X86State::REG_RAX);
      auto RDX = LoadGPRRegister(X86State::REG_RDX);

      // Incoming source register is unused.
      _WFET(RDX, RAX);

      // OF, SF, ZF, AF, PF, CF all zero.
      // CF is used if the OS deadline is set, which we don't do anything with.
      ZeroPF_AF();
      ZeroNZCV();
    }
  }
}

void OpDispatchBuilder::CLFLUSHOPT(OpcodeArgs) {
  Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
  _CacheLineClear(DestMem, false);
}

void OpDispatchBuilder::LoadFenceOrXRSTOR(OpcodeArgs) {
  // 0xE8 signifies LFENCE
  if (Op->ModRM == 0xE8) {
    _Fence(FenceType::Load);
  } else {
    XRstorOpImpl(Op);
  }
}

void OpDispatchBuilder::MemFenceOrXSAVEOPT(OpcodeArgs) {
  if (Op->ModRM == 0xF0) {
    // 0xF0 is MFENCE
    _Fence(FenceType::LoadStore);
  } else {
    XSaveOp(Op);
  }
}

void OpDispatchBuilder::StoreFenceOrCLFlush(OpcodeArgs) {
  if (Op->ModRM == 0xF8) {
    // 0xF8 is SFENCE
    _Fence(FenceType::Store);
  } else {
    // This is a CLFlush
    Ref DestMem = MakeSegmentAddress(Op, Op->Dest);
    _CacheLineClear(DestMem, true);
  }
}

void OpDispatchBuilder::UMonitorOrCLRSSBSY(OpcodeArgs) {
  if (DestIsMem(Op) || !CTX->HostFeatures.SupportsWFXT) {
    // CLRSSBSY
    UnimplementedOp(Op);
  } else {
    // Explicit NOP implementation of umonitor.
  }
}

void OpDispatchBuilder::UMWaitOp(OpcodeArgs) {
  if (DestIsMem(Op) || !CTX->HostFeatures.SupportsWFXT) {
    UnimplementedOp(Op);
  } else {
    // Explicit NOP implementation of umwait.
    // Still zero flags.
    //
    // OF, SF, ZF, AF, PF, CF all zero.
    ZeroPF_AF();
    ZeroNZCV();
  }
}

void OpDispatchBuilder::CLZeroOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsCLZERO) {
    UnimplementedOp(Op);
    return;
  }
  Ref DestMem = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.LoadData = false});
  _CacheLineZero(DestMem);
}

void OpDispatchBuilder::Prefetch(OpcodeArgs, bool ForStore, bool Stream, uint8_t Level) {
  if (Op->Src[0].IsGPR()) {
    // NOP instance.
    return;
  }

  Ref DestMem = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.LoadData = false});
  _Prefetch(ForStore, Stream, Level, DestMem, Invalid(), MemOffsetType::SXTX, 1);
}

void OpDispatchBuilder::RDTSCPOp(OpcodeArgs) {
  // RDTSCP is slightly different than RDTSC
  // IA32_TSC_AUX is returned in RCX
  // All previous loads are globally visible
  //  - Explicitly does not wait for stores to be globally visible
  //  - Explicitly use an MFENCE before this instruction if you want this behaviour
  // This instruction is not an execution fence, so subsequent instructions can execute after this
  //  - Explicitly use an LFENCE after RDTSCP if you want to block this behaviour
  if (CTX->HostFeatures.HostType != FEXCore::HostFeatures::HostTypeEnum::Linux && !CTX->HostFeatures.SupportsCPUIndexInTPIDRRO) {
    // RDTSCP is unsupported on Win32 platforms if TPIDRRO isn't supported.
    UnimplementedOp(Op);
    return;
  }
  auto Counter = CycleCounter(true);

  auto ID = _ProcessorID();
  StoreGPRRegister(X86State::REG_RAX, Counter.CounterLow);
  StoreGPRRegister(X86State::REG_RCX, ID);
  StoreGPRRegister(X86State::REG_RDX, Counter.CounterHigh);
}

void OpDispatchBuilder::RDPIDOp(OpcodeArgs) {
  if (CTX->HostFeatures.HostType != FEXCore::HostFeatures::HostTypeEnum::Linux && !CTX->HostFeatures.SupportsCPUIndexInTPIDRRO) {
    // RDTSCP is unsupported on Win32 platforms if TPIDRRO isn't supported.
    UnimplementedOp(Op);
    return;
  }
  StoreResultGPR(Op, _ProcessorID());
}

void OpDispatchBuilder::CRC32(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsCRC) {
    UnimplementedOp(Op);
    return;
  }
  const auto GPRSize = GetGPROpSize();
  const auto SrcSize = OpSizeFromSrc(Op);

  // Destination GPR size is always 4 or 8 bytes depending on widening
  const auto DstSize = Op->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_REX_WIDENING ? OpSize::i64Bit : OpSize::i32Bit;
  Ref Dest = LoadSourceGPR_WithOpSize(Op, Op->Dest, GPRSize, Op->Flags);

  // Incoming memory is 8, 16, 32, or 64
  Ref Src {};
  if (Op->Src[0].IsGPR()) {
    Src = LoadSourceGPR_WithOpSize(Op, Op->Src[0], SrcSize, Op->Flags, {.AllowUpperGarbage = true});
  } else {
    Src = LoadSourceGPR(Op, Op->Src[0], Op->Flags, {.Align = OpSize::i8Bit});
  }
  auto Result = _CRC32(Dest, Src, SrcSize);
  StoreResultGPR_WithOpSize(Op, Op->Dest, Result, DstSize);
}

void OpDispatchBuilder::RDRANDOp(OpcodeArgs, bool Reseed) {
  if (!CTX->HostFeatures.SupportsRAND) {
    UnimplementedOp(Op);
    return;
  }

  StoreResultGPR(Op, _RDRAND(Reseed));

  // If the rng number is valid then NZCV is 0b0000, otherwise NZCV is 0b0100
  auto CF_inv = GetRFLAG(X86State::RFLAG_ZF_RAW_LOC);

  // OF, SF, ZF, AF, PF all zero. CF indicates if valid.
  ZeroPF_AF();

  if (!CTX->HostFeatures.SupportsFlagM) {
    ZeroNZCV();
    SetCFInverted(CF_inv);
  } else {
    // Accelerated path. Invalid is 0 or 1, so set NZCV with a single rmif.
    HandleNZCVWrite();
    _RmifNZCV(CF_inv, (64 - 1) /* rotate bit 0 into bit 1 = C */, 0xf);
    CFInverted = true;
  }
}

void OpDispatchBuilder::BreakOp(OpcodeArgs, FEXCore::IR::BreakDefinition BreakDefinition) {
  const auto GPRSize = GetGPROpSize();

  // We don't actually support this instruction
  // Multiblock may hit it though
  _StoreContextGPR(GPRSize, GetRelocatedPC(Op, -Op->InstSize), offsetof(FEXCore::Core::CPUState, rip));
  Break(BreakDefinition);


  if (Multiblock) {
    auto NextBlock = CreateNewCodeBlockAfter(GetCurrentBlock());
    SetCurrentCodeBlock(NextBlock);
    StartNewBlock();
  } else {
    BlockSetRIP = true;
  }
}

void OpDispatchBuilder::UnimplementedOp(OpcodeArgs) {
  BreakOp(Op, FEXCore::IR::BreakDefinition {
                .ErrorRegister = 0,
                .Signal = SIGILL,
                .TrapNumber = X86State::X86_TRAPNO_UD,
                .si_code = 2, ///< ILL_ILLOPN
              });
}

void OpDispatchBuilder::PermissionRestrictedOp(OpcodeArgs) {
  BreakOp(Op, FEXCore::IR::BreakDefinition {
                .ErrorRegister = 0,
                .Signal = SIGSEGV,
                .TrapNumber = X86State::X86_TRAPNO_GP,
                .si_code = 0x80,
              });
}

void OpDispatchBuilder::InvalidOp(OpcodeArgs) {
  BreakOp(Op, FEXCore::IR::BreakDefinition {
                .ErrorRegister = 0,
                .Signal = SIGILL,
                .TrapNumber = 0,
                .si_code = 0,
              });
}

void OpDispatchBuilder::NoExecOp(OpcodeArgs) {
  BreakOp(Op, FEXCore::IR::BreakDefinition {
                .ErrorRegister = X86State::X86_PF_PROT | X86State::X86_PF_USER | X86State::X86_PF_INSTR,
                .Signal = Core::FAULT_SIGSEGV,
                .TrapNumber = X86State::X86_TRAPNO_PF,
                .si_code = 2, // SEGV_ACCERR
              });
}

#undef OpcodeArgs
} // namespace FEXCore::IR
