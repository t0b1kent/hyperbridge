// SPDX-License-Identifier: MIT
#include "Interface/Core/MRCallRet.h"
#include "Interface/Core/MRHeaderByPC.h"
int MacRunnerNullHostMode();   // ★ MacRunner, defined in BranchOps.cpp (global namespace)
// Modifications (c) 2026 MacRunner contributors, MIT
#include "Interface/Core/HBX87Proof.h"
#ifdef ARCHITECTURE_arm64ec
#include "Windows/Common/Winctx.h"
namespace FEXCore::Core { struct CpuStateFrame; }
extern "C" uint32_t MacRunnerWinctxExactMode;
extern "C" bool MacRunnerWinctxDebugActive(FEXCore::Core::CpuStateFrame*);
#endif
/*
$info$
glossary: Splatter ~ a code generator backend that concatenates configurable macros instead of doing isel
glossary: IR ~ Intermediate Representation, our high-level opcode representation, loosely modeling arm64
glossary: SSA ~ Single Static Assignment, a form of representing IR in memory
glossary: Basic Block ~ A block of instructions with no control flow, terminated by control flow
glossary: Fragment ~ A Collection of basic blocks, possibly an entire guest function or a subset of it
tags: backend|arm64
desc: Main glue logic of the arm64 splatter backend
$end_info$
*/

#include "Interface/Context/Context.h"
#include "Interface/Core/ArchHelpers/HardwareScalarMerge.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/Interpreter/InterpreterOps.h"
#include "Interface/Core/JIT/DebugData.h"
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"

#include "Utils/MemberFunctionToPointer.h"
#include "Utils/variable_length_integer.h"

#include <FEXCore/Core/MacRunnerLazyMXCSR.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/X87Region.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/Telemetry.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include <cstdio>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <unistd.h>

namespace FEX::Windows::Logging {
void Raw(const char* Message);
}

namespace {
struct DivRem {
  uint64_t Quotient;
  uint64_t Remainder;
};

static struct DivRem LUDIV(uint64_t SrcHigh, uint64_t SrcLow, uint64_t Divisor) {
  __uint128_t Source = (static_cast<__uint128_t>(SrcHigh) << 64) | SrcLow;

  return {
    .Quotient = (uint64_t)(Source / Divisor),
    .Remainder = (uint64_t)(Source % Divisor),
  };
}

static struct DivRem
LDIV(uint64_t SrcHigh, uint64_t SrcLow, int64_t Divisor) {
  __int128_t Source = (static_cast<__uint128_t>(SrcHigh) << 64) | SrcLow;

  return {
    .Quotient = (uint64_t)(Source / Divisor),
    .Remainder = (uint64_t)(Source % Divisor),
  };
}

static void
PrintValue(uint64_t Value) {
  LogMan::Msg::DFmt("Value: 0x{:x}", Value);
}

static void PrintMsg(const char* Value) {
  LogMan::Msg::DFmt("{}", Value);
}

static void PrintVectorValue(uint64_t Value, uint64_t ValueUpper) {
  LogMan::Msg::DFmt("Value: 0x{:016x}'{:016x}", ValueUpper, Value);
}
} // namespace

namespace FEXCore::CPU {

void Arm64JITCore::Op_Unhandled(const IR::IROp_Header* IROp, IR::Ref Node) {
#include "Interface/Core/HBX87Emit.inl"
  FallbackInfo Info;
  if (!InterpreterOps::GetFallbackHandler(IROp, &Info)) {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_MSG_A_FMT("Unhandled IR Op: {}", FEXCore::IR::GetName(IROp->Op));
#endif
  } else {
    auto FillF80x2Result = [&](auto DstLo, auto DstHi) {
      mov(DstLo.Q(), VTMP1.Q());
      mov(DstHi.Q(), VTMP2.Q());
    };

    auto FillF64x2Result = [&](auto DstLo, auto DstHi) {
      fmov(DstLo.D(), VTMP1.D());
      fmov(DstHi.D(), VTMP2.D());
    };

    auto FillF80Result = [&]() {
      const auto Dst = GetVReg(Node);
      mov(Dst.Q(), VTMP1.Q());
    };

    auto FillF64Result = [&]() {
      const auto Dst = GetVReg(Node);
      fmov(Dst.D(), VTMP1.D());
    };

    auto FillF32Result = [&]() {
      const auto Dst = GetVReg(Node);
      fmov(Dst.S(), VTMP1.S());
    };

    auto FillI64Result = [&]() {
      const auto Dst = GetReg(Node);
      mov(Dst.X(), TMP1);
    };

    auto FillI32Result = [&]() {
      const auto Dst = GetReg(Node);
      mov(Dst.W(), TMP1.W());
    };

    auto FillI16Result = [&]() {
      const auto Dst = GetReg(Node);
      mov(Dst.W(), TMP1.W());
    };

    switch (Info.ABI) {
    case FABI_F80_I16_F32_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      fmov(VTMP1.S(), Src1.S());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F80_I16_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      fmov(VTMP1.D(), Src1.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F80_I16_I16_PTR:
    case FABI_F80_I16_I32_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // tmp2 (x1/x11): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetReg(IROp->Args[0]);

      // Need to sign or zero extend this for the dispatcher handler.
      if (Info.ABI == FABI_F80_I16_I16_PTR) {
        sxth(ARMEmitter::Size::i32Bit, TMP2, Src1);
      } else {
        mov(ARMEmitter::Size::i32Bit, TMP2, Src1);
      }

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F32_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF32Result();
    } break;

    case FABI_F64_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64Result();
    } break;

    case FABI_F64_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      fmov(VTMP1.D(), Src1.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64Result();
    } break;
    case FABI_F64x2_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source
      // vtmp2 (v1/v16): vector source
#ifdef VIXL_SIMULATOR
      LOGMAN_THROW_A_FMT(CTX->Config.DisableVixlIndirectCalls, "Vector register pairs unsupported by simulator currently");
#endif
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto DstLo = GetVReg(IROp->Args[1]);
      const auto DstHi = GetVReg(IROp->Args[2]);

      fmov(VTMP1.D(), Src1.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64x2Result(DstLo, DstHi);
    } break;

    case FABI_F64_F64_F64_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto Src2 = GetVReg(IROp->Args[1]);

      fmov(VTMP1.D(), Src1.D());
      fmov(VTMP2.D(), Src2.D());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF64Result();
    } break;

    case FABI_I16_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI16Result();
    } break;

    case FABI_I32_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI32Result();
    } break;

    case FABI_I64_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): source
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI64Result();
    } break;

    case FABI_I64_I16_F80_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto Src2 = GetVReg(IROp->Args[1]);
      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI64Result();
    } break;

    case FABI_F80_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_F80x2_I16_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v16): vector source 2
#ifdef VIXL_SIMULATOR
      LOGMAN_THROW_A_FMT(CTX->Config.DisableVixlIndirectCalls, "Vector register pairs unsupported by simulator currently");
#endif
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto DstLo = GetVReg(IROp->Args[1]);
      const auto DstHi = GetVReg(IROp->Args[2]);

      mov(VTMP1.Q(), Src1.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80x2Result(DstLo, DstHi);
    } break;

    case FABI_F80_I16_F80_F80_PTR: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(IROp->Args[0]);
      const auto Src2 = GetVReg(IROp->Args[1]);

      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());

      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP1);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillF80Result();
    } break;

    case FABI_I32_I64_I64_V128_V128_I16: {
      // Linux Reg/Win32 Reg:
      // stack: FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      // tmp1 (x0/x10): source 1
      // tmp2 (x1/x11): source 2
      // tmp3 (x2/x12): source 3
      const auto Op = IROp->C<IR::IROp_VPCMPESTRX>();
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP1, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));

      stp<ARMEmitter::IndexType::PRE>(TMP1, ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto SrcRAX = GetReg(Op->RAX);
      const auto SrcRDX = GetReg(Op->RDX);
      const auto Control = Op->Control;

      mov(TMP1, SrcRAX.X());
      mov(TMP2, SrcRDX.X());
      movz(ARMEmitter::Size::i32Bit, TMP3, Control);

      const auto Src1 = GetVReg(Op->LHS);
      const auto Src2 = GetVReg(Op->RHS);

      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());

      blr(TMP4);

      ldp<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::zr, ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI32Result();
    } break;
    case FABI_I32_V128_V128_I16: {
      // Linux Reg/Win32 Reg:
      // tmp4 (x4/x13): FallbackHandler
      // x30: return
      // vtmp1 (v0/v16): vector source 1
      // vtmp2 (v1/v17): vector source 2
      // tmp1 (x0/x10): source 1
      const auto Op = IROp->C<IR::IROp_VPCMPISTRX>();
      str<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, -16);

      const auto Src1 = GetVReg(Op->LHS);
      const auto Src2 = GetVReg(Op->RHS);
      const auto Control = Op->Control;

      mov(VTMP1.Q(), Src1.Q());
      mov(VTMP2.Q(), Src2.Q());
      movz(ARMEmitter::Size::i32Bit, TMP1, Control);

      ldr(TMP2, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, ABIHandler));
      ldr(TMP4, FALLBACK_HANDLER_OFFSET(Info.HandlerIndex, Func));
      blr(TMP2);

      ldr<ARMEmitter::IndexType::POST>(ARMEmitter::XReg::lr, ARMEmitter::Reg::rsp, 16);
      FillI32Result();
    } break;
    case FABI_UNKNOWN:
    default:
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
      LOGMAN_MSG_A_FMT("Unhandled IR Fallback ABI: {} {}", FEXCore::IR::GetName(IROp->Op), ToUnderlying(Info.ABI));
#endif
      break;
    }
  }
}

struct CompactLoopLinkData {
  uint32_t GuestOffset;
  uint32_t UnlinkedBranch;
};

static void CompactLoopDelinker(FEXCore::Context::ExitFunctionLinkData* OpaqueRecord) {
  const auto Record = reinterpret_cast<CompactLoopLinkData*>(OpaqueRecord);
  auto Caller = reinterpret_cast<uint32_t*>(Record) - 1;
  FEXCore::Allocator::ScopedJITWrite JITWrite;
  std::atomic_ref<uint32_t>(*Caller).store(Record->UnlinkedBranch, std::memory_order::relaxed);
  ARMEmitter::Emitter::ClearICache(Caller, sizeof(*Caller));
}

// ★ MacRunner FEXXFER MACRUNNER_FEX_ICALL_IC: link record of one inline-cache site (offsets relative to the record, see CompileCode).
struct MRICLinkRecord {
  int32_t TagOffset;
  int32_t SiteOffset;
  int32_t FillOffset;
  int32_t Pad;
};

static void MRICDelinker(FEXCore::Context::ExitFunctionLinkData* OpaqueRecord) {
  auto* R = reinterpret_cast<uint8_t*>(OpaqueRecord);
  const auto* Rec = reinterpret_cast<const MRICLinkRecord*>(R);
  auto* Site = reinterpret_cast<uint32_t*>(R + Rec->SiteOffset);
  const auto Fill = reinterpret_cast<uintptr_t>(R + Rec->FillOffset);
  uint32_t BranchInst = 0;
  ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
  BranchEmit.bl(Fill / 4 - reinterpret_cast<uintptr_t>(Site) / 4);
  FEXCore::Allocator::ScopedJITWrite JITWrite;
  std::atomic_ref<uint32_t>(*Site).store(BranchInst, std::memory_order::relaxed);
  ARMEmitter::Emitter::ClearICache(Site, sizeof(*Site));
}

static void DirectBlockDelinker(FEXCore::Context::ExitFunctionLinkData* Record, bool Call) {
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uintptr_t CallerAddress = JumpThunkStartAddress + Record->CallerOffset;
  auto BranchOffset = JumpThunkStartAddress / 4 - CallerAddress / 4;

  // Replace the patched callsite with a branch to the jump thunk.
  uint32_t BranchInst = 0;
  ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
  if (Call) {
    BranchEmit.bl(BranchOffset);
  } else {
    BranchEmit.b(BranchOffset);
  }

  // ★ MacRunner N2b: пишем ОДНО слово прямо в выпущенный код. Временный BranchInst лежит
  // на обычном стеке и скобки не требует — она нужна ровно вокруг store и sync.
  {
    FEXCore::Allocator::ScopedJITWrite JITWrite;
    std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(CallerAddress)).store(BranchInst, std::memory_order::relaxed);
    ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(CallerAddress), 4);
  }
}

static void IndirectBlockDelinker(FEXCore::Context::ExitFunctionLinkData* Record) {
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uint32_t BranchInst = 0;
  ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
  // Restore branch +2 instructions to jump to the linker block
  BranchEmit.b(0x2);

  // ★ MacRunner N2b — то же самое для косвенного расцепления.
  FEXCore::Allocator::ScopedJITWrite JITWrite;
  std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(JumpThunkStartAddress)).store(BranchInst, std::memory_order::relaxed);
  ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(JumpThunkStartAddress), 4);

  // No need to reset HostCode here as the exit linker pointer is stored separately, and if the block is relinked it will be updated.
}

uint64_t Arm64JITCore::ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, FEXCore::Context::ExitFunctionLinkData* Record) {
  FEXCore::LazyMXCSR::ScopedHostFPSR PreserveGuestFPSR;
  auto Thread = Frame->Thread;
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  uintptr_t HostCode {};
  const bool MRIC = reinterpret_cast<uintptr_t>(Record) & 2;   // ★ MacRunner FEXXFER ICALL_IC record (the IC linker stub sets bit 1)
  const bool CompactLoop = !MRIC && (reinterpret_cast<uintptr_t>(Record) & 1);
  auto LoopRecord = reinterpret_cast<CompactLoopLinkData*>(reinterpret_cast<uintptr_t>(Record) & ~uintptr_t {1});
  uint64_t GuestRip;
  if (CompactLoop) {
    if (FEXCore::Utils::MacRunnerHeaderByPCMode() == 2) {
      // ★ MacRunner FEXXFER probe; in mode 1 the unit's loop-dispatcher stub has just stored the header itself.
      MRHeaderByPC::Resolve(Thread, reinterpret_cast<uint64_t>(LoopRecord), MRHeaderByPC::CompactLoop);
    }
    const auto Header = reinterpret_cast<const JITCodeHeader*>(Frame->State.InlineJITBlockHeader);
    const auto Tail = reinterpret_cast<const JITCodeTail*>(reinterpret_cast<const uint8_t*>(Header) + Header->OffsetToBlockTail);
    GuestRip = Tail->RIP + LoopRecord->GuestOffset;
  } else if (MRIC) {
    GuestRip = Frame->State.rip;   // the IC fill stub stored the call target
  } else {
    GuestRip = Record->GuestRIP;
  }

  if (TFSet) {
    // If TF is set, the cache must be skipped as different code needs to be generated.
    Frame->State.rip = GuestRip;
    return Frame->Pointers.DispatcherLoopTop;
  } else {
    {
      // Guard the LookupCache lock with the code invalidation mutex, to avoid issues with forking
      auto lk_inval =
        GuardSignalDeferringSection<std::shared_lock>(static_cast<Context::ContextImpl*>(Thread->CTX)->CodeInvalidationMutex, Thread);
      HostCode = Thread->LookupCache->FindBlock(Thread, GuestRip);
    }
    if (!HostCode) {
      // Hold a reference to the code buffer, to avoid linking unmapped code if compilation triggers a recreation.
      auto CodeBuffer = static_cast<Arm64JITCore*>(Thread->CPUBackend.get())->CurrentCodeBuffer;
      HostCode = static_cast<Context::ContextImpl*>(Thread->CTX)->CompileBlock(Frame, GuestRip, 0);
      if (Thread->LookupCache->Shared != CodeBuffer->LookupCache.get()) {
        return HostCode;
      }
    }
  }

  // See ExitFunction in BranchOps.cpp for an assembly level view of the handled cases.
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uintptr_t CallerAddress = CompactLoop ? reinterpret_cast<uintptr_t>(LoopRecord) - 4 : JumpThunkStartAddress + Record->CallerOffset;
  auto BranchOffset = HostCode / 4 - CallerAddress / 4;

  uint32_t ExpectedKnownCallMarkerInst = 0;
  ARMEmitter::Emitter ExpectedKnownCallMarkerEmit(reinterpret_cast<uint8_t*>(&ExpectedKnownCallMarkerInst), 4);
  ExpectedKnownCallMarkerEmit.adr(TMP1, 0xC);

  // Guard the LookupCache lock with the code invalidation mutex, to avoid issues with forking
  auto lk_inval = GuardSignalDeferringSection<std::shared_lock>(static_cast<Context::ContextImpl*>(Thread->CTX)->CodeInvalidationMutex, Thread);

  // Invalidation may revoke the target while lookup/compilation drops the lock.
  // Re-enter the dispatcher rather than publish an untracked stale link.
  if (Thread->LookupCache->FindBlock(Thread, GuestRip) != HostCode) {
    Frame->State.rip = GuestRip;
    return Frame->Pointers.DispatcherLoopTop;
  }

  // Lock here is necessary to prevent simultaneous linking and delinking
  auto lk = Thread->LookupCache->AcquireWriteLock();

  // ★★★ MacRunner N2b — ОДНА скобка на обе ветви сцепления, а не по одной на ветвь.
  // Открыта ПОСЛЕ AcquireWriteLock (порядок замков не меняем) и живёт до возврата.
  // Покрывает: store команды ветвления в прямой ветви, Record->HostCode и store ldr в
  // косвенной, обе синхронизации кеша. ★ Record и его inline-данные лежат В ТОМ ЖЕ
  // отображении JIT, что и код, — писать их в режиме «исполнять» нельзя так же, как код.
  // ★ Открыть ДО CompileBlock выше нельзя: там своя, вложенная запись, и внешняя скобка
  // растянулась бы на всю компиляцию блока.
  FEXCore::Allocator::ScopedJITWrite JITWrite;

  if (MRIC) {
    // ★ MacRunner FEXXFER ICALL_IC: fill the tag once (first target), link the site's bl to the target's host code while the tag names
    // it; the delinker points the bl back to the fill stub (the tag stays, so the next hit relinks the same target).
    auto* R = reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(Record) & ~uintptr_t {3});
    const auto* Rec = reinterpret_cast<const MRICLinkRecord*>(R);
    auto* Tag = reinterpret_cast<uint64_t*>(R + Rec->TagOffset);
    auto* Site = reinterpret_cast<uint32_t*>(R + Rec->SiteOffset);
    uint64_t Cur = std::atomic_ref<uint64_t>(*Tag).load(std::memory_order::acquire);
    if (!Cur && GuestRip) {
      std::atomic_ref<uint64_t>(*Tag).store(GuestRip, std::memory_order::release);
      Cur = GuestRip;
    }
    const auto SiteOffset = HostCode / 4 - reinterpret_cast<uintptr_t>(Site) / 4;
    {
      // ★ counters: calls into the IC linker (fill + relink after delinking) and links made; printed at powers of two.
      static std::atomic<uint64_t> Calls {0}, Links {0};
      const uint64_t N = Calls.fetch_add(1, std::memory_order_relaxed) + 1;
      const uint64_t L = Links.load(std::memory_order_relaxed) + (Cur == GuestRip && GuestRip ? 1 : 0);
      if (Cur == GuestRip && GuestRip) Links.fetch_add(1, std::memory_order_relaxed);
      if ((N & (N - 1)) == 0) {
        char Line[160];
        const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex-icall-ic: linker_calls={} links={} tag={:x} target={:x}\n", N, L, Cur, GuestRip);
        Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
        FEX::Windows::Logging::Raw(Line);
      }
    }
    if (Cur == GuestRip && GuestRip && ARMEmitter::Emitter::IsInt26(SiteOffset)) {
      uint32_t BranchInst = 0;
      ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
      BranchEmit.bl(SiteOffset);
      Thread->LookupCache->AddBlockLink(GuestRip, reinterpret_cast<FEXCore::Context::ExitFunctionLinkData*>(R), MRICDelinker, lk);
      std::atomic_ref<uint32_t>(*Site).store(BranchInst, std::memory_order::relaxed);
      ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(Site), 4);
    }
    return HostCode;
  }

  if (CompactLoop) {
    // Separately mapped cached code may be outside B's range. In that case
    // keep the slow site unchanged and use the resolved entry for this visit.
    if (ARMEmitter::Emitter::IsInt26(BranchOffset)) {
      uint32_t BranchInst = 0;
      ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
      BranchEmit.b(BranchOffset);
      Thread->LookupCache->AddBlockLink(GuestRip, reinterpret_cast<FEXCore::Context::ExitFunctionLinkData*>(LoopRecord),
                                       CompactLoopDelinker, lk);
      std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(CallerAddress)).store(BranchInst, std::memory_order::relaxed);
      ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(CallerAddress), 4);
    }
    return HostCode;
  }

  // For non-calls, this would extend into the block's code, however that's fine as an out-of-range adr would never
  // be generated avoiding any false positives.
  uintptr_t KnownCallMarkerAddr = CallerAddress - 0x8;
  uint32_t KnownCallMarkerInst = *reinterpret_cast<uint32_t*>(KnownCallMarkerAddr);
  if (ARMEmitter::Emitter::IsInt26(BranchOffset)) {
    // Directly patch the callsite with the appropriate branch instruction.
    uint32_t BranchInst = 0;
    ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);

    if (KnownCallMarkerInst == ExpectedKnownCallMarkerInst) {
      BranchEmit.bl(BranchOffset);
      Thread->LookupCache->AddBlockLink(
        GuestRip, Record, [](FEXCore::Context::ExitFunctionLinkData* Record) { DirectBlockDelinker(Record, true); }, lk);
    } else {
      BranchEmit.b(BranchOffset);
      Thread->LookupCache->AddBlockLink(
        GuestRip, Record, [](FEXCore::Context::ExitFunctionLinkData* Record) { DirectBlockDelinker(Record, false); }, lk);
    }

    std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(CallerAddress)).store(BranchInst, std::memory_order::relaxed);
    ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(CallerAddress), 4);
  } else {
    // This case is common between calls and jumps as the thunk callsite can be left untouched.
    std::atomic_ref<uint64_t>(Record->HostCode).store(HostCode, std::memory_order::seq_cst);
#ifdef ARCHITECTURE_arm64
    // Make memory write visible to other threads reading the same location
    asm volatile("dc cvau, %0; dsb ish" : : "r"(Record->HostCode) :);
#endif

    uint32_t LdrInst = 0;
    ARMEmitter::Emitter LdrEmit(reinterpret_cast<uint8_t*>(&LdrInst), 4);
    LdrEmit.ldr(TMP1, reinterpret_cast<uint64_t>(&Record->HostCode) - JumpThunkStartAddress);
    std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(JumpThunkStartAddress)).store(LdrInst, std::memory_order::relaxed);
    ARMEmitter::Emitter::ClearICache(reinterpret_cast<void*>(JumpThunkStartAddress), 4);

    Thread->LookupCache->AddBlockLink(GuestRip, Record, IndirectBlockDelinker, lk);
  }

  return HostCode;
}

void Arm64JITCore::Op_NoOp(const IR::IROp_Header* IROp, IR::Ref Node) {}

Arm64JITCore::Arm64JITCore(FEXCore::Context::ContextImpl* ctx, FEXCore::Core::InternalThreadState* Thread)
  : CPUBackend(*ctx, Thread)
  , Arm64Emitter(ctx)
  , HostSupportsSVE128 {ctx->HostFeatures.SupportsSVE128}
  , HostSupportsSVE256 {ctx->HostFeatures.SupportsSVE256}
  , HostSupportsAVX256 {ctx->HostFeatures.SupportsAVX && ctx->HostFeatures.SupportsSVE256}
  , HostSupportsRPRES {ctx->HostFeatures.SupportsRPRES}
  , HostSupportsAFP {ctx->HostFeatures.SupportsAFP}
  , HostSupportsHardwareScalarMerge {HardwareScalarMergeRequested() && ctx->HasHardwareTSOSupport() && ProbeHardwareScalarMerge()}
  , CTX {ctx}
  , TempCodeBufferAllocator(ctx->CPUBackendAllocator, 0) {

#ifdef ARCHITECTURE_arm64ec
  // Bounded startup proof of the feature path, before guest code or signals.
  static std::atomic_flag Announced = ATOMIC_FLAG_INIT;
  if (!Announced.test_and_set(std::memory_order_relaxed)) {
    char Line[128];
    const auto Result = fmt::format_to_n(Line, sizeof(Line) - 1,
      "mr-suspend-backedge: gate={} atomics={} checkpoint=CAFD\n",
      FEXCore::Utils::MacRunnerSuspendBackedgeMode(), ctx->HostFeatures.SupportsAtomics ? 1 : 0);
    Line[std::min<size_t>(Result.size, sizeof(Line) - 1)] = 0;
    FEX::Windows::Logging::Raw(Line);
  }
#endif

  if (HardwareScalarMergeRequested()) {
    LogMan::Msg::IFmt("ARITH_SCALAR_MERGE thread_probe={} hardware_tso={} bounded_cases=72",
                     HostSupportsHardwareScalarMerge, ctx->HasHardwareTSOSupport());
  }

  RAPass = Thread->PassManager->GetPass<IR::RegisterAllocationPass>("RA");

  RAPass->AddRegisters(IR::RegClass::GPR, GeneralRegisters.size());
  RAPass->AddRegisters(IR::RegClass::GPRFixed, StaticRegisters.size());
  RAPass->AddRegisters(IR::RegClass::FPR, GeneralFPRegisters.size());
  RAPass->AddRegisters(IR::RegClass::FPRFixed, StaticFPRegisters.size());
  RAPass->SetNumPairRegs(PairRegisters);

  {
    // Set up pointers that the JIT needs to load

    // Common
    auto& Ptrs = ThreadState->CurrentFrame->Pointers;

    Ptrs.PrintValue = reinterpret_cast<uint64_t>(PrintValue);
    Ptrs.PrintVectorValue = reinterpret_cast<uint64_t>(PrintVectorValue);
    Ptrs.PrintMsgValue = reinterpret_cast<uint64_t>(PrintMsg);

    Ptrs.ThreadRemoveCodeEntryFromJIT = reinterpret_cast<uintptr_t>(&Context::ContextImpl::ThreadRemoveCodeEntryFromJit);
    Ptrs.MonoBackpatcherWrite = reinterpret_cast<uint64_t>(&Context::ContextImpl::MonoBackpatcherWrite);
    Ptrs.CPUIDObj = reinterpret_cast<uint64_t>(&CTX->CPUID);

    {
      FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::CPUIDEmu::RunFunction);
      Ptrs.CPUIDFunction = PMF.GetConvertedPointer();
    }

    {
      FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::CPUIDEmu::RunXCRFunction);
      Ptrs.XCRFunction = PMF.GetConvertedPointer();
    }

    {
      FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::HLE::SyscallHandler::HandleSyscall);
      Ptrs.SyscallHandlerObj = reinterpret_cast<uint64_t>(CTX->SyscallHandler);
      Ptrs.SyscallHandlerFunc = PMF.GetVTableEntry(CTX->SyscallHandler);
    }
    Ptrs.ExitFunctionLink = reinterpret_cast<uintptr_t>(&Arm64JITCore::ExitFunctionLink);
    Ptrs.LUDIV = reinterpret_cast<uint64_t>(LUDIV);
    Ptrs.LDIV = reinterpret_cast<uint64_t>(LDIV);
  }

  CurrentCodeBuffer = SharedCodeBuffers.GetLatest();
  ThreadState->LookupCache->Shared = CurrentCodeBuffer->LookupCache.get();
}

void Arm64JITCore::ClearCache() {
  // NOTE: Holding on to the reference here is required to ensure validity of the WriteLock mutex
  auto PrevCodeBuffer = CurrentCodeBuffer;
  auto lk = PrevCodeBuffer->LookupCache->AcquireWriteLock();

  auto CodeBuffer = GetEmptySharedCodeBuffer();
  SetBuffer(CodeBuffer->Ptr, CodeBuffer->AllocatedSize);

  ThreadState->LookupCache->ChangeGuestToHostMapping(*PrevCodeBuffer, *CurrentCodeBuffer->LookupCache, lk);
}

Arm64JITCore::~Arm64JITCore() {}

bool Arm64JITCore::IsInlineConstant(const IR::OrderedNodeWrapper& WNode, uint64_t* Value) const {
  if (WNode.IsImmediate()) {
    return false;
  }

  auto OpHeader = IR->GetOp<IR::IROp_Header>(WNode);

  if (OpHeader->Op == IR::IROps::OP_INLINECONSTANT) {
    auto Op = OpHeader->C<IR::IROp_InlineConstant>();
    if (Value) {
      *Value = Op->Constant;
    }
    return true;
  } else {
    return false;
  }
}

bool Arm64JITCore::IsInlineEntrypointOffset(const IR::OrderedNodeWrapper& WNode, uint64_t* Value) const {
  if (WNode.IsImmediate()) {
    return false;
  }

  auto OpHeader = IR->GetOp<IR::IROp_Header>(WNode);

  if (OpHeader->Op == IR::IROps::OP_INLINEENTRYPOINTOFFSET) {
    auto Op = OpHeader->C<IR::IROp_InlineEntrypointOffset>();
    if (Value) {
      uint64_t Mask = ~0ULL;
      const auto Size = OpHeader->Size;
      if (Size == IR::OpSize::i32Bit) {
        Mask = 0xFFFF'FFFFULL;
      }
      *Value = (Entry + Op->Offset) & Mask;
    }
    return true;
  } else {
    return false;
  }
}

void Arm64JITCore::EmitTFCheck() {
  ARMEmitter::ForwardLabel l_TFUnset;
  ARMEmitter::ForwardLabel l_TFBlocked;

  // Note that this needs to be before the below suspend checks, as X86 checks this flag immediately after executing an instruction.
  ldrb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));

  (void)cbz(ARMEmitter::Size::i32Bit, TMP1, &l_TFUnset);

  // X86 semantically checks TF after executing each instruction, so e.g. setting a context with TF set will execute a single instruction
  // and then raise an exception. However on the FEX side this is simpler to implement by checking at the start of each instruction, handle this by having bit 1 being unset in the flag state indicate that TF is blocked for a single instruction.
  (void)tbz(TMP1, 1, &l_TFBlocked);

  // Block TF for a single instruction when the frontend jumps to a new context by unsetting bit 1.
  ldrb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));
  and_(ARMEmitter::Size::i32Bit, TMP1, TMP1, ~(1 << 1));
  strb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));

  Core::CpuStateFrame::SynchronousFaultDataStruct State = {
    .FaultToTopAndGeneratedException = 1,
    .Signal = Core::FAULT_SIGTRAP,
    .TrapNo = X86State::X86_TRAPNO_DB,
    .si_code = 2,
    .err_code = 0,
  };

  uint64_t Constant {};
  memcpy(&Constant, &State, sizeof(State));

  LoadConstant(ARMEmitter::Size::i64Bit, TMP1, Constant);
  str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, SynchronousFaultData));
  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.GuestSignal_SIGTRAP));
  br(TMP1);

  (void)Bind(&l_TFBlocked);
  // If TF was blocked for this instruction, unblock it for the next.
  LoadConstant(ARMEmitter::Size::i32Bit, TMP1, 0b11);
  strb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));
  (void)Bind(&l_TFUnset);
}

#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
void Arm64JITCore::EmitSuspendInterruptFaultCheck(bool PublishedContinuation) {
  if (CTX->Config.NeedsPendingInterruptFaultCheck) {
    constexpr size_t InterruptPageOffset =
      offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) - offsetof(FEXCore::Core::InternalThreadState, BaseFrameState);
    static_assert(InterruptPageOffset + FEXCore::Utils::PublishedSuspendFaultOffset <= 65520);
    const size_t Offset = InterruptPageOffset + (PublishedContinuation ? FEXCore::Utils::PublishedSuspendFaultOffset : 0);
    if (Offset <= 32760) {
      str(ARMEmitter::XReg::zr, STATE, Offset);
    } else {
      str(ARMEmitter::QReg::q0, STATE, Offset);
    }
  }
}
#endif

void Arm64JITCore::EmitSuspendInterruptCheck() {
  if (CTX->Config.NeedsPendingInterruptFaultCheck) {
    // Trigger a fault if there are any pending interrupts
    // Used only for suspend on WIN32 at the moment
    constexpr size_t InterruptPageOffset =
      offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) - offsetof(FEXCore::Core::InternalThreadState, BaseFrameState);
    if constexpr (InterruptPageOffset <= 32760) {
      str(ARMEmitter::XReg::zr, STATE, InterruptPageOffset);
    } else {
      // Need to use vector 128-bit store for this range.
      // Doesn't matter which register we use to store.
      str(ARMEmitter::QReg::q0, STATE, InterruptPageOffset);
    }
  }

#ifdef ARCHITECTURE_arm64ec
  static constexpr uint16_t SuspendMagic {0xCAFE};

  ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
  ARMEmitter::ForwardLabel l_NoSuspend;
  (void)cbz(ARMEmitter::Size::i32Bit, TMP2, &l_NoSuspend);
  brk(SuspendMagic);
  (void)Bind(&l_NoSuspend);
#endif
}

#if defined(MACRUNNER_FEXXFER_CODEDUMP)
// FEXXFER diagnostic build only (build-diag, -DMACRUNNER_FEXXFER_CODEDUMP=1; never staged into an engine). Copy of the GAPS fx1d
// dump: MACRUNNER_FEX_CODEDUMP=<windows path>, MACRUNNER_FEX_CODEDUMP_RANGE=<lo hex>-<hi hex>: records "HBCD", u32 size, u64 guest
// entry, u64 host, the host bytes.
static void MRCodeDump(uint64_t Entry, const uint8_t* Host, uint64_t Size) {
  static void* File = reinterpret_cast<void*>(-2);
  static uint64_t Lo = 0, Hi = 0;
  if (File == reinterpret_cast<void*>(-2)) {
    File = nullptr;
    const char* Path = getenv("MACRUNNER_FEX_CODEDUMP");
    const char* Range = getenv("MACRUNNER_FEX_CODEDUMP_RANGE");
    if (Path && Range) {
      char* End = nullptr; Lo = strtoull(Range, &End, 16); Hi = (End && *End == '-') ? strtoull(End + 1, nullptr, 16) : 0;
      HANDLE H = CreateFileA(Path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      File = (H == INVALID_HANDLE_VALUE) ? nullptr : H;
    }
  }
  if (!File || Entry < Lo || Entry >= Hi) return;
  struct { char Magic[4]; uint32_t Size; uint64_t Entry, Host; } Rec = {{'H', 'B', 'C', 'D'}, static_cast<uint32_t>(Size), Entry, reinterpret_cast<uint64_t>(Host)};
  DWORD W = 0;
  WriteFile(File, &Rec, sizeof(Rec), &W, nullptr);
  WriteFile(File, Host, static_cast<DWORD>(Size), &W, nullptr);
}
#endif

// These new safepoints publish a completed guest continuation. brk #0xCAFD
// differs from entrypoint #0xCAFE: its RIP must not be guessed from host PC.
void Arm64JITCore::EmitSuspendInterruptCheckAt(uint64_t GuestRIP) {
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
  if (CTX->Config.NeedsPendingInterruptFaultCheck) {
    LoadConstant(ARMEmitter::Size::i64Bit, TMP1, GuestRIP);
    str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    EmitSuspendInterruptFaultCheck(true);
    return;
  }
#endif
#ifdef ARCHITECTURE_arm64ec
  ARMEmitter::ForwardLabel Continue;
  ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
  cbz(ARMEmitter::Size::i32Bit, TMP2.W(), &Continue);
  LoadConstant(ARMEmitter::Size::i64Bit, TMP1, GuestRIP);
  str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
  brk(0xCAFD);
  Bind(&Continue);
#endif
}

void Arm64JITCore::EmitSuspendInterruptCheckAt(ARMEmitter::Register GuestRIP) {
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
  if (CTX->Config.NeedsPendingInterruptFaultCheck) {
    str(GuestRIP.X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    EmitSuspendInterruptFaultCheck(true);
    return;
  }
#endif
#ifdef ARCHITECTURE_arm64ec
  ARMEmitter::ForwardLabel Continue;
  // Before the call-ret pop: TMP2 still has no live host target.
  ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
  cbz(ARMEmitter::Size::i32Bit, TMP2.W(), &Continue);
  str(GuestRIP.X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
  brk(0xCAFD);
  Bind(&Continue);
#endif
}

// ★ FEXXFER diagnostic build only (-DMACRUNNER_FEXXFER_CODEDUMP; never in a product engine): MACRUNNER_FEXXFER_DIAG_CEILING=<mask>
// measures the CEILING of items 3/4 on stands that neither fault nor suspend: 1 = no InlineJITBlockHeader store at block
// entries (exceptions would see a stale header), 2 = no suspend poll at block entries (suspension would wait for a backedge).
// Unsafe by construction; in product builds this is the constant 0 and the emitted code is unchanged.
#if defined(MACRUNNER_FEXXFER_CODEDUMP)
static unsigned MRDiagCeiling() {
  static const unsigned Mask = [] {
    const char* V = getenv("MACRUNNER_FEXXFER_DIAG_CEILING");
    return V && V[0] >= '0' && V[0] <= '3' && !V[1] ? unsigned(V[0] - '0') : 0U;
  }();
  return Mask;
}
#else
static constexpr unsigned MRDiagCeiling() {
  return 0;
}
#endif

void Arm64JITCore::EmitEntryPoint(ARMEmitter::BackwardLabel& HeaderLabel, bool CheckTF, uint64_t GuestRIP, ARMEmitter::BiDirectionalLabel* NoPollLabel) {
  // Get the address of the JITCodeHeader and store in to the core state.
  // Two instruction cost, each 1 cycle.
  if (!(MRDiagCeiling() & 1) && !MRHeaderLazy) {   // MacRunner FEXXFER HEADER_BY_PC=1: found by host PC instead (MRHeaderByPC.h)
    adr_OrRestart(TMP1, &HeaderLabel);
    str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
  }

#ifdef ARCHITECTURE_arm64ec
  if (MacRunnerWinctxExactMode && !MRGuestDebugSingleInstruction) {
    // All compiled entry points participate: direct links, L1/L2 hits and
    // call/return cache targets must not bypass an armed guest breakpoint.
    // This guard precedes spill-stack allocation and preserves live NZCV.
    ARMEmitter::ForwardLabel NoGuestDebug;
    (void)cbz(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::x18, &NoGuestDebug);
    ldr(TMP1, ARMEmitter::XReg::x18, 0x1788);
    (void)cbz(ARMEmitter::Size::i64Bit, TMP1, &NoGuestDebug);
    ldr(TMP2.W(), TMP1, MR_WINCTX_DEBUG_OFFSET + offsetof(mr_winctx_debug_state, valid));
    (void)cbz(ARMEmitter::Size::i32Bit, TMP2, &NoGuestDebug);
    ldr(TMP1, TMP1, MR_WINCTX_DEBUG_OFFSET + offsetof(mr_winctx_debug_state, dr[5]));
    ubfx(ARMEmitter::Size::i64Bit, TMP1, TMP1, 0, 8);
    (void)cbz(ARMEmitter::Size::i64Bit, TMP1, &NoGuestDebug);
    InsertGuestRIPMove(TMP1, GuestRIP);
    str(TMP1, STATE_PTR(CpuStateFrame, State.rip));
    ldr(TMP2, STATE_PTR(CpuStateFrame, Pointers.DispatcherLoopTop));
    br(TMP2);
    (void)Bind(&NoGuestDebug);
  }
#endif
  if (CheckTF) {
    EmitTFCheck();
  }

  if (SpillSlots) {
    const auto TotalSpillSlotsSize = SpillSlots * MaxSpillSlotSize;

    if (ARMEmitter::IsImmAddSub(TotalSpillSlotsSize)) {
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, TotalSpillSlotsSize);
    } else {
      LoadConstant(ARMEmitter::Size::i64Bit, TMP1, TotalSpillSlotsSize);
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::rsp, ARMEmitter::XReg::rsp, TMP1, ARMEmitter::ExtendedType::LSL_64, 0);
    }
  }

#ifdef ARCHITECTURE_arm64ec
  if (MRDiagCeiling() & 2) {
    // FEXXFER diagnostic ceiling only (see MRDiagCeiling): no entry poll.
  } else if ((FEXCore::Utils::MacRunnerHotFallthroughMask() & 1) && !CTX->Config.NeedsPendingInterruptFaultCheck) {
    // MacRunner HOT_FALLTHROUGH 1: the poll falls through when no suspend is pending; the trap stub at the end of the unit maps to this
    // entry's guest RIP exactly like the inline brk did (same registers, spill area already allocated).
    PendingGuestSuspendTraps.push_back({GuestRIP - Entry, {}});
    ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
    cbnz_OrRestart(ARMEmitter::Size::i32Bit, TMP2, &PendingGuestSuspendTraps.back().Label);
  } else
#endif
  EmitSuspendInterruptCheck();
  if (NoPollLabel) {
    // MacRunner RET_LANDING: call-return landings enter here, AFTER the poll (header and spill area are set by the landing).
    BindOrRestart(NoPollLabel);
  }
}

// MacRunner RET_LANDING (MacRunnerSuspend.h): emitted right after the call's bl/blr, i.e. where a return that matched the call-return
// stack lands. Same effect as entering the return block through EmitEntryPoint, minus the suspend poll. Not used when the entry has
// extra guards (TF single-step, the WINCTX exact debug guard) or when the return block is not an entry point.
void Arm64JITCore::MREmitReturnLanding(IR::OrderedNodeWrapper ReturnBlock) {
  if (!FEXCore::Utils::MacRunnerRetLandingEnabled() || !MRHeaderLabel || MRCheckTF) {
    return;
  }
#ifdef ARCHITECTURE_arm64ec
  if (MacRunnerWinctxExactMode && !MRGuestDebugSingleInstruction) {
    return;
  }
#endif
  if (!IR->GetOp<IR::IROp_CodeBlock>(ReturnBlock)->EntryPoint) {
    return;
  }
  auto* NoPoll = &CallReturnNoPollTargets.try_emplace(ReturnBlock.ID()).first->second;
  if (!MRHeaderLazy) {
    adr_OrRestart(TMP1, MRHeaderLabel);
    str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
  }
  if (SpillSlots) {
    const auto TotalSpillSlotsSize = SpillSlots * MaxSpillSlotSize;
    if (ARMEmitter::IsImmAddSub(TotalSpillSlotsSize)) {
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, TotalSpillSlotsSize);
    } else {
      LoadConstant(ARMEmitter::Size::i64Bit, TMP1, TotalSpillSlotsSize);
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::rsp, ARMEmitter::XReg::rsp, TMP1, ARMEmitter::ExtendedType::LSL_64, 0);
    }
  }
  b_OrRestart(NoPoll);
  PendingCallReturnTargetLabel = nullptr;   // the landing never falls through into the next block
}

// ★ MacRunner FEXXFER MACRUNNER_FEX_RIP_LITERAL (MacRunnerXfer.h): use a literal when mov/movk needs three or four
// instructions (counted the way LoadConstant can: movz over non-zero halfwords or movn over non-0xffff ones).
bool Arm64JITCore::MRUseRipLiteral(IR::Ref Node, uint64_t Value) const {
  const unsigned Mask = FEXCore::Utils::MacRunnerRipLiteralMask();
  if (!Mask || RequiresFarARM64Jumps) {
    return false;
  }
  unsigned NonZero = 0, NonOnes = 0;
  for (unsigned i = 0; i < 4; ++i) {
    const uint16_t Half = static_cast<uint16_t>(Value >> (16 * i));
    NonZero += Half != 0;
    NonOnes += Half != 0xFFFF;
  }
  if (std::min(NonZero, NonOnes) < 3) {
    return false;
  }
  if (Mask & 2) {
    return true;
  }
  return (Mask & 1) && std::find(MRCallReturnAddresses.begin(), MRCallReturnAddresses.end(), Value) != MRCallReturnAddresses.end();
}

void Arm64JITCore::MREmitSpillAllocation() {
  if (SpillSlots) {
    const auto TotalSpillSlotsSize = SpillSlots * MaxSpillSlotSize;
    if (ARMEmitter::IsImmAddSub(TotalSpillSlotsSize)) {
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, TotalSpillSlotsSize);
    } else {
      LoadConstant(ARMEmitter::Size::i64Bit, TMP1, TotalSpillSlotsSize);
      sub(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::rsp, ARMEmitter::XReg::rsp, TMP1, ARMEmitter::ExtendedType::LSL_64, 0);
    }
  }
}

CPUBackend::CompiledCode Arm64JITCore::CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst, const FEXCore::IR::IRListView* IR,
                                                   FEXCore::Core::DebugData* DebugData, bool CheckTF) {
  FEXCORE_PROFILE_SCOPED("Arm64::CompileCode");
#if defined(HB_GAMES_COMPILE_ONLY)
  extern void HBStandObserveRelocations(unsigned Phase, uint64_t Size, uint64_t Capacity);
  HBStandObserveRelocations(0, Relocations.size(), Relocations.capacity());
#endif

  const auto PrevNumAllocations = Relocations.size();

#ifdef ARCHITECTURE_arm64ec
  MRGuestDebugSingleInstruction = SingleInst && MacRunnerWinctxDebugActive(ThreadState->CurrentFrame);
#endif
  this->Entry = Entry;
  this->DebugData = DebugData;
  this->IR = IR;
  RequiresFarARM64Jumps = false;
  // Darwin single-vector TSO loads enlarge validation exits. Reserve the
  // measured first-restart capacity up front; the guard still handles outliers.
  // Keep the release-0160 estimate unchanged when the host-page gate is off.
  SSANodeMultiplier = FEXCore::Utils::JITGuardPageSize() == FEXCore::Utils::FEX_PAGE_SIZE ? 24 : 48;
  if (FEXCore::HBX87::StaticRegsEnabled() && !CTX->Config.Is64BitMode()) SSANodeMultiplier = 256;

  // Prepare restart via long jump in case branch encoding fails.
  // This uses UncheckedLongJump since we don't implement std::longjmp in WoA setups
  switch (static_cast<RestartOptions::Control>(FEXCore::UncheckedLongJump::SetJump(ThreadState->RestartJump))) {
  case RestartOptions::Control::Incoming:
    // Nothing
    break;
  case RestartOptions::Control::EnableFarARM64Jumps: RequiresFarARM64Jumps = true; break;
  case RestartOptions::Control::NeedsLargerJITSpace:
    // Get rid of the claimed buffer immediately, we can't fit in it at all.
    TempCodeBufferAllocator.UnclaimBuffer();
    SSANodeMultiplier *= 2;
    break;
  default: LOGMAN_MSG_A_FMT("Unhandled Arm64 restart condition!");
  }

  uint32_t SSACount = IR->GetSSACount();
  JumpTargets.clear();
  CallReturnTargets.clear();
  PendingJumpThunks.clear();
  LoopDispatcherLabel = {};
  PendingLoopLinkRecords.clear();
  PendingGuestSuspendTraps.clear();
  MRL1MissStubs.clear();
  // ★ MacRunner FEXXFER (MacRunnerXfer.h): per-compile state; nothing is scanned or emitted with every key 0.
  MRRipLiterals.clear();
  MRRetEntryStubs.clear();
  MRHeaderLazy = MRHeaderByPC::Lazy(CTX);
  MRICSites.clear();
  MRICLinkerLabel = {};
  MRICActive = FEXCore::Utils::MacRunnerICallICEnabled() && !::MacRunnerNullHostMode() && !RequiresFarARM64Jumps &&
               !CTX->CodeCache.EnableCodeCaching;
  MRCallReturnAddresses.clear();
  MRReturnBlocks.clear();
  MRRetNoPollActive = FEXCore::Utils::MacRunnerRetNoPollEnabled() && !CheckTF && !CTX->Config.NeedsPendingInterruptFaultCheck &&
                      !FEXCore::Utils::MacRunnerRetLandingEnabled();
#ifdef ARCHITECTURE_arm64ec
  if (MacRunnerWinctxExactMode && !MRGuestDebugSingleInstruction) {
    MRRetNoPollActive = false;   // the WINCTX exact guard runs before the poll in every entry; keep that entry form
  }
#endif
  if (MRRetNoPollActive || (FEXCore::Utils::MacRunnerRipLiteralMask() & 1)) {
    MRReturnBlocks.assign(IR->GetHeader()->BlockCount, false);
    for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
      for (auto [CodeNode, CodeOp] : IR->GetCode(BlockNode)) {
        if (CodeOp->Op != IR::OP_EXITFUNCTION) {
          continue;
        }
        const auto Exit = CodeOp->C<IR::IROp_ExitFunction>();
        if (Exit->Hint != IR::BranchHint::Call) {
          continue;
        }
        // After register allocation the GPR arguments (CallReturnAddress) no longer name IR nodes, so the return address is
        // taken from the return block: its guest entry is the instruction after the CALL, i.e. the pushed address.
        if (!Exit->CallReturnBlock.IsInvalid()) {
          const auto Block = IR->GetOp<IR::IROp_CodeBlock>(Exit->CallReturnBlock);
          MRReturnBlocks[Block->ID] = true;
          const uint64_t Mask = CTX->Config.Is64BitMode() ? ~0ULL : 0xFFFF'FFFFULL;
          MRCallReturnAddresses.push_back((Entry + Block->GuestEntryOffset) & Mask);
        }
      }
    }
  }
  JumpTargets.resize(IR->GetHeader()->BlockCount, {});
  GuestTargetSuspendChecks = FEXCore::Utils::MacRunnerSuspendBackedgeEnabled();
  // Every cycle has a backwards edge in emitted block order. Put one precise
  // safepoint at each guest target of those edges, shared by all predecessors.
  // The target RIP is already known there; conditional edges no longer need
  // two copies of the cold continuation-selection path.
  std::vector<uint32_t> BlockOrder(JumpTargets.size());
  std::vector<bool> GuestSuspendTargets(JumpTargets.size(), false);
  if (GuestTargetSuspendChecks) {
    uint32_t Order = 0;
    std::vector<std::vector<uint32_t>> Edges(JumpTargets.size());
    std::vector<uint32_t> Incoming(JumpTargets.size());
    for (auto [Node, Header] : IR->GetBlocks()) {
      BlockOrder[Header->C<IR::IROp_CodeBlock>()->ID] = Order++;
      const auto Source = Header->C<IR::IROp_CodeBlock>();
      auto AddEdge = [&](IR::OrderedNodeWrapper TargetNode) {
        const auto Target = IR->GetOp<IR::IROp_CodeBlock>(TargetNode);
        Edges[Source->ID].push_back(Target->ID);
        ++Incoming[Target->ID];
      };
      for (auto [CodeNode, Op] : IR->GetCode(Node)) {
        if (Op->Op == IR::OP_JUMP) {
          AddEdge(Op->C<IR::IROp_Jump>()->TargetBlock);
        } else if (Op->Op == IR::OP_CONDJUMP) {
          AddEdge(Op->C<IR::IROp_CondJump>()->TrueBlock);
          AddEdge(Op->C<IR::IROp_CondJump>()->FalseBlock);
        }
      }
    }
    std::vector<uint32_t> Acyclic;
    for (uint32_t ID = 0; ID < Incoming.size(); ++ID) {
      if (!Incoming[ID]) Acyclic.push_back(ID);
    }
    for (size_t Next = 0; Next < Acyclic.size(); ++Next) {
      for (const auto Target : Edges[Acyclic[Next]]) {
        if (!--Incoming[Target]) Acyclic.push_back(Target);
      }
    }
    for (auto [Node, Header] : IR->GetBlocks()) {
      const auto Source = Header->C<IR::IROp_CodeBlock>();
      auto MarkTarget = [&](IR::OrderedNodeWrapper TargetNode) {
        const auto Target = IR->GetOp<IR::IROp_CodeBlock>(TargetNode);
        // Backwards address/layout order can merely lead to a common exit.
        // Poll only edges that remain after removing the acyclic graph.
        if (Incoming[Source->ID] && Incoming[Target->ID] &&
            Target->GuestEntryOffset != FEXCore::Utils::NoGuestSuspendBoundary &&
            BlockOrder[Target->ID] <= BlockOrder[Source->ID]) {
          GuestSuspendTargets[Target->ID] = true;
        }
      };
      for (auto [CodeNode, Op] : IR->GetCode(Node)) {
        if (Op->Op == IR::OP_JUMP) {
          MarkTarget(Op->C<IR::IROp_Jump>()->TargetBlock);
        } else if (Op->Op == IR::OP_CONDJUMP) {
          const auto Jump = Op->C<IR::IROp_CondJump>();
          // An exit stub on the other arm must not suppress the real loop.
          MarkTarget(Jump->TrueBlock);
          MarkTarget(Jump->FalseBlock);
        }
      }
    }
  }
  Relocations.resize(PrevNumAllocations, FEXCore::CPU::Relocation::Default()); // Discard any relocations generated from a previous attempt

  CodeData.EntryPoints.clear();

  // Fairly excessive buffer range to make sure we don't overflow
  // One page baseline, plus SSANodeMultipler bytes, plus another page for guard page.
  const auto GuardSize = FEXCore::Utils::JITGuardPageSize();
  const uint32_t DesiredBufferRange = AlignUp(FEXCore::Utils::FEX_PAGE_SIZE + GuardSize + SSACount * SSANodeMultiplier, GuardSize);

  // JIT output is first written to a temporary buffer and later relocated to the CodeBuffer.
  // This minimizes lock contention of CodeBufferWriteMutex.
  auto TempCodeBufferInfo = TempCodeBufferAllocator.ReownOrClaimBufferWithSize(DesiredBufferRange);
  auto TempCodeBuffer = TempCodeBufferInfo.Ptr;
  const uint32_t UsableBufferRange = TempCodeBufferInfo.Size - GuardSize;

  SetBuffer(TempCodeBuffer, UsableBufferRange);

  ThreadState->JITGuardPage = reinterpret_cast<uintptr_t>(TempCodeBuffer) + UsableBufferRange;
  ThreadState->JITGuardOverflowArgument = FEXCore::ToUnderlying(RestartOptions::Control::NeedsLargerJITSpace);

  CodeData.BlockBegin = GetCursorAddress<uint8_t*>();

  // Put the code header at the start of the data block.
  ARMEmitter::BackwardLabel JITCodeHeaderLabel {};
  (void)Bind(&JITCodeHeaderLabel);
  MRHeaderLabel = &JITCodeHeaderLabel;   // MacRunner RET_LANDING
  MRCheckTF = CheckTF;
  CallReturnNoPollTargets.clear();
  JITCodeHeader* CodeHeader = GetCursorAddress<JITCodeHeader*>();
  CursorIncrement(sizeof(JITCodeHeader));

  auto CodeBegin = GetCursorAddress<uint8_t*>();

  // AAPCS64
  // r30      = LR
  // r29      = FP
  // r19..r28 = Callee saved
  // r18      = Platform Register (Matters if we target Windows or iOS)
  // r16..r17 = Inter-procedure scratch
  //  r9..r15 = Temp
  //  r8      = Indirect Result
  //  r0...r7 = Parameter/Results
  //
  //  FPRS:
  //  v8..v15 = (lower 64bits) Callee saved

  // Our allocation:
  // X0 = ThreadState
  // X1 = MemBase
  //
  // X1-X3 = Temp
  // X4-r18 = RA

  SpillSlots = IR->SpillSlots();

  PendingTargetLabel = nullptr;
  PendingCallReturnTargetLabel = nullptr;
  PendingSuspendRIP.reset();

  std::vector<FEXCore::Core::X87Region::Recipe> X87Recipes;
  X87FaultRecords.clear();
  X87FaultIsOpen = false;
  auto EmitIR = [&](const IR::IROp_Header* IROp, IR::Ref CodeNode) {
    switch (IROp->Op) {
#define REGISTER_OP(op, x) case FEXCore::IR::IROps::OP_##op: Op_##x(IROp, CodeNode); break
#define IROP_DISPATCH_DISPATCH
#include <FEXCore/IR/IRDefines_Dispatch.inc>
#undef REGISTER_OP
    default: Op_Unhandled(IROp, CodeNode); break;
    }
  };
#include "Interface/Core/HBX87RegionEmit.inl"
  for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    CurrentBlockHasGuestBoundary = BlockIROp->GuestEntryOffset != FEXCore::Utils::NoGuestSuspendBoundary;
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_THROW_A_FMT(BlockIROp->Header.Op == IR::OP_CODEBLOCK, "IR type failed to be a code block");
#endif

    auto BlockStartHostCode = GetCursorAddress<uint8_t*>();
    {
      const auto Node = IR->GetID(BlockNode);
      const auto Target = &JumpTargets[BlockIROp->ID];

      // if there's a pending branch, and it is not fall-through
      if (PendingTargetLabel && PendingTargetLabel != Target) {
        if (PendingTargetLabel->Backward.Location && !(GuestTargetSuspendChecks && PendingSuspendRIP)) {
          if (PendingSuspendRIP) {
            EmitSuspendInterruptCheckAt(*PendingSuspendRIP);
          } else {
            EmitSuspendInterruptCheck();
          }
        }
        b_OrRestart(PendingTargetLabel);
        PendingTargetLabel = nullptr;
      }

      if (BlockIROp->EntryPoint) {
        uint64_t BlockStartRIP = Entry + BlockIROp->GuestEntryOffset;

        const auto IsReturnTarget = CallReturnTargets.try_emplace(Node).first;
        if (PendingTargetLabel) {
          // If there is a fallthrough branch to this block, skip over the entrypoint code.
          b_OrRestart(Target);
        } else if (PendingCallReturnTargetLabel && PendingCallReturnTargetLabel != &IsReturnTarget->second) {
          // If we just emitted a call, but the block we're now emitting is not the return block so don't fallthrough.
          b_OrRestart(PendingCallReturnTargetLabel);
        }
        PendingCallReturnTargetLabel = nullptr;

        BindOrRestart(&IsReturnTarget->second);
        const bool MRNoPollEntry = MRRetNoPollActive && MRReturnBlocks[BlockIROp->ID];
        if (!MRNoPollEntry) {
          CodeData.EntryPoints.emplace(BlockStartRIP, GetCursorAddress<uint8_t*>());
        }
        DebugData->GuestOpcodes.push_back({BlockIROp->GuestEntryOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});

        if (MRNoPollEntry) {
          // ★ MacRunner FEXXFER MACRUNNER_FEX_RET_NOPOLL (MacRunnerXfer.h): the return landing and the fall-through after the
          // call enter here without the poll (no TF check / WINCTX guard in this mode, see MRRetNoPollActive). The block's
          // entry point for L1, links and the dispatcher is the polled stub emitted after the unit's code.
          auto& Stub = MRRetEntryStubs.emplace_back(MRRetEntryStub {BlockStartRIP, BlockIROp->GuestEntryOffset, {}});
          if (!(MRDiagCeiling() & 1) && !MRHeaderLazy) {
            adr_OrRestart(TMP1, &JITCodeHeaderLabel);
            str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
          }
          MREmitSpillAllocation();
          BindOrRestart(&Stub.Body);
        } else {
          EmitEntryPoint(JITCodeHeaderLabel, CheckTF, BlockStartRIP,
                         FEXCore::Utils::MacRunnerRetLandingEnabled() ? &CallReturnNoPollTargets.try_emplace(Node).first->second : nullptr);
        }
      }

      if (PendingCallReturnTargetLabel) {
        // If there is still a pending call return target, then the block we're emitting is not the return block so don't fallthrough.
        b_OrRestart(PendingCallReturnTargetLabel);
        PendingCallReturnTargetLabel = nullptr;
      }
      PendingTargetLabel = nullptr;

      PendingSuspendRIP.reset();

      if (GuestSuspendTargets[BlockIROp->ID]) {
        // This is an exact guest boundary, before any instruction in the target.
        // Record its host-PC mapping before the poll, so the existing entrypoint
        // trap restores this RIP without materializing it in every cold path.
        DebugData->GuestOpcodes.push_back({BlockIROp->GuestEntryOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
#ifdef ARCHITECTURE_arm64ec
        if (CTX->Config.NeedsPendingInterruptFaultCheck) {
          BindOrRestart(Target);
          EmitSuspendInterruptCheck();
        } else {
          // Keep the cold trap out of the fallthrough path. Each stub gets
          // its own guest mapping below; unset doorbells never take a branch.
          PendingGuestSuspendTraps.push_back({BlockIROp->GuestEntryOffset, {}});
          BindOrRestart(Target);
          ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
          cbnz_OrRestart(ARMEmitter::Size::i32Bit, TMP2, &PendingGuestSuspendTraps.back().Label);
        }
#else
        BindOrRestart(Target);
        EmitSuspendInterruptCheck();
#endif
      } else {
        BindOrRestart(Target);
      }
    }

    if (!EmitX87Region(BlockNode, BlockIROp)) {
      // Conservatively materialize before unqualified IR. Qualified regions
      // and their leaf links keep the eight physical registers authoritative.
      // Leaf GPR bookkeeping can carry the bank between separately compiled
      // register regions. Everything else is an explicit legacy boundary.
      bool GPROnly = true;
      for (auto [CodeNode,IROp] : IR->GetCode(BlockNode)) {
        switch (IROp->Op) {
        case IR::OP_BEGINBLOCK:case IR::OP_ENDBLOCK:case IR::OP_GUESTOPCODE:
        case IR::OP_INLINECONSTANT:case IR::OP_CONSTANT:
        case IR::OP_STOREREGISTER:case IR::OP_ADD:case IR::OP_SUB:case IR::OP_AND:
        case IR::OP_OR:case IR::OP_XOR:case IR::OP_JUMP:case IR::OP_CONDJUMP: break;
        default:GPROnly=false;break;
        }
      }
      if (!GPROnly) SpillX87StaticBank();
      for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
        EmitIR(IROp, CodeNode);
        if (X87FaultIsOpen && IROp->Op != IR::OP_X87FAULTSTATE) {
          if (IR->GetID(CodeNode).Value == X87FaultOpenTarget) {
            // X87-CTX P5: the record covers the target op (and RA fills placed right before it).
            X87FaultOpen.HostEnd = static_cast<uint32_t>(GetCursorAddress<uint8_t*>() - CodeData.BlockBegin);
            if (X87FaultOpen.HostEnd > X87FaultOpen.HostBegin && X87FaultRecords.size() < FEXCore::Core::X87Fault::MaxRecords) {
              X87FaultRecords.push_back(X87FaultOpen);
            } else if (X87FaultOpen.HostEnd > X87FaultOpen.HostBegin) {
              static std::atomic<uint32_t> MRDropped {0};
              if (MRDropped.fetch_add(1, std::memory_order_relaxed) < 8) {
                char Line[128];
                auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-x87fault-record-dropped: rip={:x} records={}\n",
                                            IR->GetHeader()->OriginalRIP, X87FaultRecords.size());
                Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
                FEX::Windows::Logging::Raw(Line);
              }
            }
            X87FaultIsOpen = false;
          } else if (IROp->Op == IR::OP_GUESTOPCODE) {
            X87FaultIsOpen = false; // the target was merged away by RA
          }
        }
      }
    }
    X87FaultIsOpen = false;

    DebugData->Subblocks.push_back({static_cast<uint32_t>(BlockStartHostCode - CodeData.BlockBegin),
                                    static_cast<uint32_t>(GetCursorAddress<uint8_t*>() - BlockStartHostCode)});
  }

  // Make sure last branch is generated. It certainly can't be eliminated here.
  if (PendingTargetLabel) {
    if (PendingTargetLabel->Backward.Location && !(GuestTargetSuspendChecks && PendingSuspendRIP)) {
      if (PendingSuspendRIP) {
        EmitSuspendInterruptCheckAt(*PendingSuspendRIP);
      } else {
        EmitSuspendInterruptCheck();
      }
    }
    b_OrRestart(PendingTargetLabel);
  }
  PendingTargetLabel = nullptr;

  ARMEmitter::ForwardLabel l_ExitLink;
  for (auto& PendingJumpThunk : PendingJumpThunks) {
    // Align as 64-bit atomics are used on the HostCode field.
    Align(8);

    ARMEmitter::ForwardLabel l_DoLink;
    uint64_t ThunkAddress = GetCursorAddress<uint64_t>();
    BindOrRestart(&PendingJumpThunk.Label);
    b_OrRestart(&l_DoLink);
    br(TMP1);
    BindOrRestart(&l_DoLink);
    ldr(TMP1, &l_ExitLink);
    blr(TMP1);

    // This is a ExitFunctionLinkData struct
    BindOrRestart(&l_ExitLink);
    dc64(0);                                                                   // HostCode
    PlaceNamedSymbolLiteral(InsertGuestRIPLiteral(PendingJumpThunk.GuestRIP)); // GuestRIP
    dc64(PendingJumpThunk.CallerAddress - ThunkAddress);                       // CallerOffset
  }

  BindOrRestart(&l_ExitLink);
  PlaceNamedSymbolLiteral(InsertNamedSymbolLiteral(RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER));

  if (!PendingLoopLinkRecords.empty()) {
    BindOrRestart(&LoopDispatcherLabel);
    if (MRHeaderLazy) {
      // MacRunner FEXXFER HEADER_BY_PC=1: ExitFunctionLink reads the compact record's unit from the header (cold: first link only).
      adr_OrRestart(TMP1, &JITCodeHeaderLabel);
      str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
    }
    orr(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::lr, ARMEmitter::XReg::lr, 1);
    ldr(TMP1, STATE_PTR(CpuStateFrame, Pointers.ExitFunctionLinker));
    br(TMP1);
    for (const auto Address : PendingLoopLinkRecords) {
      auto Record = reinterpret_cast<CompactLoopLinkData*>(Address);
      // Binding above patches the forward B; never retain its placeholder.
      Record->UnlinkedBranch = *(reinterpret_cast<const uint32_t*>(Record) - 1);
    }
  }

  for (auto& Stub : MRL1MissStubs) {   // MacRunner HOT_FALLTHROUGH 4 (MacRunnerSuspend.h)
    BindOrRestart(&Stub.Miss);
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    str(ARMEmitter::Register(Stub.RipIdx).X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    b_OrRestart(&Stub.Back);
  }
  MRL1MissStubs.clear();
  for (auto& Stub : MRRetEntryStubs) {
    // ★ MacRunner FEXXFER MACRUNNER_FEX_RET_NOPOLL: the polled entry of a return block = the inline entry of EmitEntryPoint
    // (header, spill area, poll in the same form), then into the body. Its own host->guest mapping names the block's RIP.
    CodeData.EntryPoints.emplace(Stub.GuestRIP, GetCursorAddress<uint8_t*>());
    DebugData->GuestOpcodes.push_back({Stub.GuestOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
    if (!MRHeaderLazy) {
      adr_OrRestart(TMP1, &JITCodeHeaderLabel);
      str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
    }
    MREmitSpillAllocation();
#ifdef ARCHITECTURE_arm64ec
    if (FEXCore::Utils::MacRunnerHotFallthroughMask() & 1) {
      PendingGuestSuspendTraps.push_back({Stub.GuestOffset, {}});
      ldr(TMP2.W(), STATE_PTR(CpuStateFrame, SuspendDoorbell));
      cbnz_OrRestart(ARMEmitter::Size::i32Bit, TMP2, &PendingGuestSuspendTraps.back().Label);
    } else
#endif
    EmitSuspendInterruptCheck();
    b_OrRestart(&Stub.Body);
  }
  MRRetEntryStubs.clear();
  for (auto& Site : MRICSites) {
    // ★ MacRunner FEXXFER MACRUNNER_FEX_ICALL_IC: out-of-line part of one site (see BranchOps.cpp). Miss with an empty tag: shadow push
    // and the fill call; Fill (also the site bl's unlinked target): RIP to the context, ExitFunctionLink through the shared IC linker
    // stub (LR | 2 = this record); a filled tag that differs: the ordinary L1 lookup and blr, returning through a one-branch trampoline
    // so the return-stack prediction stays right. Only and/add/sub/ldp/cb(n)z: NZCV and every guest register are preserved.
    const auto Rip = ARMEmitter::Register(Site.RipIdx).X();
    const auto Ra = ARMEmitter::Register(Site.RaIdx).X();
    ARMEmitter::BackwardLabel Ret {};
    Ret.Location = Site.ReturnAddr;
    ARMEmitter::ForwardLabel Poly, Found, PolyRet;
    BindOrRestart(&Site.Miss);
    ldr(TMP1, &Site.Tag);
    cbnz_OrRestart(ARMEmitter::Size::i64Bit, TMP1, &Poly);
    adr_OrRestart(TMP1, &Ret);
    stp<ARMEmitter::IndexType::PRE>(Ra, TMP1, REG_CALLRET_SP, -0x10);
    Site.FillAddr = GetCursorAddress<uint8_t*>();
    BindOrRestart(&Site.Fill);
    str(Rip, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    bl_OrRestart(&MRICLinkerLabel);
    Site.Record = GetCursorAddress<uint8_t*>();
    dc32(0);   // TagOffset   (patched below, relative to the record)
    dc32(0);   // SiteOffset
    dc32(0);   // FillOffset
    dc32(0);
    BindOrRestart(&Poly);
    ldp<ARMEmitter::IndexType::OFFSET>(TMP1, TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.L1Pointer));
    and_(ARMEmitter::Size::i64Bit, TMP2, TMP2, Rip, ARMEmitter::ShiftType::LSL, FEXCore::ilog2(sizeof(LookupCache::LookupCacheEntry)));
    add(TMP1, TMP1, TMP2);
    ldp<ARMEmitter::IndexType::OFFSET>(TMP2, TMP1, TMP1, 0);
    sub(TMP1, TMP1, Rip);
    (void)cbz(ARMEmitter::Size::i64Bit, TMP1, &Found);
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    str(Rip, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    (void)Bind(&Found);
    (void)adr(TMP1, &PolyRet);
    stp<ARMEmitter::IndexType::PRE>(Ra, TMP1, REG_CALLRET_SP, -0x10);
    blr(TMP2);
    (void)Bind(&PolyRet);
    b_OrRestart(&Ret);
  }
  if (!MRICSites.empty()) {
    BindOrRestart(&MRICLinkerLabel);
    orr(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::lr, ARMEmitter::XReg::lr, 2);
    ldr(TMP1, STATE_PTR(CpuStateFrame, Pointers.ExitFunctionLinker));
    br(TMP1);
  }
  for (auto& Trap : PendingGuestSuspendTraps) {
    BindOrRestart(&Trap.Label);
    DebugData->GuestOpcodes.push_back({Trap.GuestOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
    brk(0xCAFE);
  }
  if (!MRRipLiterals.empty()) {
    // ★ MacRunner FEXXFER MACRUNNER_FEX_RIP_LITERAL: the unit's guest-RIP literals (8-byte aligned data, never executed).
    Align(8);
    for (auto& Lit : MRRipLiterals) {
      PlaceNamedSymbolLiteral(Lit);
    }
    MRRipLiterals.clear();
  }
  if (!MRICSites.empty()) {
    // ★ MacRunner FEXXFER MACRUNNER_FEX_ICALL_IC: the tags (8-byte aligned, written only by ExitFunctionLink) and the record offsets.
    Align(8);
    for (auto& Site : MRICSites) {
      uint8_t* TagAddr = GetCursorAddress<uint8_t*>();
      BindOrRestart(&Site.Tag);
      dc64(0);
      auto* Rec = reinterpret_cast<int32_t*>(Site.Record);
      Rec[0] = static_cast<int32_t>(TagAddr - Site.Record);
      Rec[1] = static_cast<int32_t>(Site.SiteBl - Site.Record);
      Rec[2] = static_cast<int32_t>(Site.FillAddr - Site.Record);
    }
    MRICSites.clear();
  }

  // CodeSize not including the header or tail data.
  const uint64_t CodeOnlySize = GetCursorAddress<uint8_t*>() - CodeBegin;

  // Add the JitCodeTail (written later)
  Align(alignof(JITCodeTail));
  const auto JITBlockTailLocation = GetCursorAddress<uint8_t*>();
  CodeHeader->OffsetToBlockTail = JITBlockTailLocation - CodeData.BlockBegin;

  JITCodeTail JITBlockTail {
    .RIP = Entry,
    .GuestSize = Size,
    .SpinLockFutex = 0,
    .SingleInst = SingleInst,
  };

  // Entries that live after the JITCodeTail.
  // These entries correlate JIT code regions with guest RIP regions.
  // Using these entries FEX is able to reconstruct the guest RIP accurately when an instruction cause a signal fault.
  // Packed using two variable length integer entries to ensure the size isn't too large.
  // These smaller sizes means that each entry is relative to each other instead of absolute offset from the start of the JIT block.
  // When reconstructing the RIP, each entry must be walked linearly and accumulated with the previous entries.
  // This is a trade-off between compression inside the JIT code space and execution time when reconstruction the RIP.
  // RIP reconstruction when faulting is less likely so we are requiring the accumulation.
  //
  // struct {
  //   // The Host PC offset from the previous entry.
  //   FEXCore::Utils::vl64 HostPCOffset;
  //   // How much to offset the RIP from the previous entry.
  //   FEXCore::Utils::vl64 GuestRIPOffset;
  // };

  const auto JITRIPEntriesBegin = JITBlockTailLocation + sizeof(JITBlockTail);
  auto JITRIPEntriesLocation = JITRIPEntriesBegin;

  {
    // Store the RIP entries.
    JITBlockTail.NumberOfRIPEntries = 0;
    JITBlockTail.OffsetToRIPEntries = JITRIPEntriesBegin - JITBlockTailLocation;
    uintptr_t CurrentRIPOffset = 0;
    uint64_t CurrentPCOffset = 0;
    auto EmitRIPDelta = [&](int64_t HostDelta, int64_t GuestDelta) {
      JITRIPEntriesLocation += FEXCore::Utils::vl64pair::Encode(JITRIPEntriesLocation, HostDelta, GuestDelta);
      ++JITBlockTail.NumberOfRIPEntries;
    };

    for (size_t i = 0; i < DebugData->GuestOpcodes.size(); i++) {
      const auto& GuestOpcode = DebugData->GuestOpcodes[i];
      int64_t HostPCOffset = GuestOpcode.HostEntryOffset - CurrentPCOffset;
      int64_t GuestRIPOffset = GuestOpcode.GuestEntryOffset - CurrentRIPOffset;

      // The existing format jumps from 2 to 9 bytes at a guest delta of 32.
      // Several short deltas at the SAME host boundary encode that mapping
      // more compactly. Recovery consumes all coincident entries, so neither
      // the preceding instruction nor any byte of the new one changes RIP.
      const auto OriginalSize = FEXCore::Utils::vl64pair::EncodedSize(HostPCOffset, GuestRIPOffset);
      const bool CanSplit = OriginalSize > 2 && HostPCOffset >= 0 && HostPCOffset <= 508 && !(HostPCOffset & 3) &&
                            GuestRIPOffset >= -128 && GuestRIPOffset <= 124;
      if (CanSplit) {
        const auto Step = GuestRIPOffset >= 0 ? 31 : 32;
        const auto Magnitude = GuestRIPOffset >= 0 ? GuestRIPOffset : -GuestRIPOffset;
        auto SplitSize = 2 * ((Magnitude + Step - 1) / Step);
        const bool SmallFirst = HostPCOffset >= 4 && HostPCOffset <= 64 && GuestRIPOffset > 8 &&
                                1 + 2 * ((GuestRIPOffset - 8 + 30) / 31) < SplitSize;
        if (SmallFirst) SplitSize = 1 + 2 * ((GuestRIPOffset - 8 + 30) / 31);
        if (SplitSize < OriginalSize) {
          if (SmallFirst) {
            EmitRIPDelta(HostPCOffset, 8);
            HostPCOffset = 0;
            GuestRIPOffset -= 8;
          }
          while (GuestRIPOffset) {
            const auto Part = std::clamp<int64_t>(GuestRIPOffset, -32, 31);
            EmitRIPDelta(HostPCOffset, Part);
            HostPCOffset = 0;
            GuestRIPOffset -= Part;
          }
        } else {
          EmitRIPDelta(HostPCOffset, GuestRIPOffset);
        }
      } else {
        EmitRIPDelta(HostPCOffset, GuestRIPOffset);
      }

      CurrentPCOffset = GuestOpcode.HostEntryOffset;
      CurrentRIPOffset = GuestOpcode.GuestEntryOffset;
    }
  }

  SetCursorOffset(JITRIPEntriesLocation - CodeData.BlockBegin);
  if (!X87Recipes.empty()) {
    using namespace FEXCore::Core::X87Region;
    Align(alignof(Recipe));
    const Header Extension {Magic,Version,sizeof(Recipe),uint32_t(X87Recipes.size()),
      uint32_t(sizeof(Header)+X87Recipes.size()*sizeof(Recipe))};
    for (size_t i=0;i<sizeof(Extension);i+=8) {
      uint64_t Word;
      memcpy(&Word,reinterpret_cast<const uint8_t*>(&Extension)+i,8);
      dc64(Word);
    }
    for (const auto& Recipe : X87Recipes) for (size_t i=0;i<sizeof(Recipe);i+=8) {
      if(i==offsetof(FEXCore::Core::X87Region::Recipe,GuestRIP)) {
        PlaceNamedSymbolLiteral(InsertGuestRIPLiteral(Recipe.GuestRIP));
        continue;
      }
      uint64_t Word;
      memcpy(&Word,reinterpret_cast<const uint8_t*>(&Recipe)+i,8);
      dc64(Word);
    }
    JITBlockTail._Pad[0]=TailMarker;
    JITBlockTail._Pad[1]=Version;
  }
  if (!X87FaultRecords.empty()) {
    // X87-CTX P5: after the RIP entries and the X87Region extension; flagged in _Pad[2].
    using namespace FEXCore::Core::X87Fault;
    Align(8);
    const FEXCore::Core::X87Fault::Header Extension {Magic, Version, sizeof(Record), uint32_t(X87FaultRecords.size()),
                                      uint32_t(sizeof(FEXCore::Core::X87Fault::Header) + X87FaultRecords.size() * sizeof(Record)), MaxSpillSlotSize, 0};
    for (size_t i = 0; i < sizeof(Extension); i += 8) {
      uint64_t Word;
      memcpy(&Word, reinterpret_cast<const uint8_t*>(&Extension) + i, 8);
      dc64(Word);
    }
    for (const auto& R : X87FaultRecords) {
      for (size_t i = 0; i < sizeof(R); i += 8) {
        uint64_t Word;
        memcpy(&Word, reinterpret_cast<const uint8_t*>(&R) + i, 8);
        dc64(Word);
      }
    }
    JITBlockTail._Pad[2] = TailFlag;
  }
  Align();

  CodeData.Size = GetCursorAddress<uint8_t*>() - CodeData.BlockBegin;

  // Finalize and write block tail data
  JITBlockTail.Size = CodeData.Size;
  {
    auto PrevCur = GetCursorOffset();
    memcpy(JITBlockTailLocation, &JITBlockTail, sizeof(JITBlockTail));
    SetCursorOffset(JITBlockTailLocation - CodeData.BlockBegin + offsetof(JITCodeTail, RIP));
    PlaceNamedSymbolLiteral(InsertGuestRIPLiteral(JITBlockTail.RIP));
    SetCursorOffset(PrevCur);
  }

  // Migrate the compile output from temporary storage to the actual CodeBuffer.
  // This can block progress in other compiling threads, so the duration of the lock should be as small as possible.
  {
    auto CodeBufferLock = std::unique_lock {SharedCodeBuffers.CodeBufferWriteMutex};

    // ★ MacRunner N2b — скобка записи открывается ЗДЕСЬ, а не перед memcpy ниже.
    // Причина: Align16B() тоже ПИШЕТ (выравнивающие слова) прямо в боевой CodeBuffer,
    // и SetCursorOffset/SetBuffer работают уже по нему. Открыть перед memcpy — значит
    // отдать записи выравнивания в режим «исполнять», то есть в W^X-отказ.
    // Держится через memcpy и закрывается ПОСЛЕ ClearICache ниже, до публикации.
    FEXCore::Allocator::ScopedJITWrite JITWrite;

    // Query size of generated code
    const auto TempSize = GetCursorOffset();

    // Bring CodeBuffer up to date
    {
      LOGMAN_THROW_A_FMT(CurrentCodeBuffer->LookupCache.get() == ThreadState->LookupCache->Shared, "INVARIANT VIOLATED: SharedLookupCache "
                                                                                                   "doesn't match up!\n");
      if (auto Prev = CheckCodeBufferUpdate()) {
        MRCallRet::Zero(ThreadState);
        auto lk = ThreadState->LookupCache->AcquireWriteLock();
        ThreadState->LookupCache->ChangeGuestToHostMapping(*Prev, *CurrentCodeBuffer->LookupCache, lk);
      }

      // NOTE: 16-byte alignment of the new cursor offset must be preserved for block linking records
      SetBuffer(CurrentCodeBuffer->Ptr, CurrentCodeBuffer->AllocatedSize);
      SetCursorOffset(SharedCodeBuffers.LatestOffset);
      Align16B();
      if ((GetCursorOffset() + TempSize) > CurrentCodeBuffer->UsableSize()) {
        CTX->ClearCodeCache(ThreadState);
      }

      SharedCodeBuffers.LatestOffset = GetCursorOffset();
    }

    // Adjust host addresses
    const auto Delta = GetCursorAddress<uint8_t*>() - CodeData.BlockBegin;
    CodeData.BlockBegin += Delta;
    for (auto& EntryPoint : CodeData.EntryPoints) {
      EntryPoint.second += Delta;
    }
    CodeBegin += Delta;

    for (std::size_t Idx = PrevNumAllocations; Idx != Relocations.size(); ++Idx) {
      Relocations[Idx].Header.Offset += SharedCodeBuffers.LatestOffset;
    }

    // Copy over CodeBuffer contents
    memcpy(GetCursorAddress<uint8_t*>(), TempCodeBuffer, TempSize);
    if (FEXCore::Utils::MacRunnerHeaderByPCMode()) {
      // MacRunner FEXXFER HEADER_BY_PC: publish the unit to the buffer's table after its bytes (MRHeaderByPC.h).
      CurrentCodeBuffer->MRRecordUnit(static_cast<uint64_t>(CodeData.BlockBegin - CurrentCodeBuffer->Ptr));
    }
    SetCursorOffset(SharedCodeBuffers.LatestOffset + TempSize);

    SharedCodeBuffers.LatestOffset = GetCursorOffset();

    // ★ MacRunner N2b — синхронизация кеша команд ПЕРЕНЕСЕНА СЮДА, внутрь скобки записи.
    // Спецификация Астры §1 требует именно этого: публикация кода допустима только после
    // sync И возврата в режим исполнения, то есть sync обязан лежать во владении скобки.
    // Прежнее место — сразу после DelayedDisownBuffer ниже; перенос его ни с чем не
    // ссорит: DelayedDisownBuffer отпускает ВРЕМЕННЫЙ буфер, а не тот, что мы издали.
    ClearICache(CodeBegin, CodeOnlySize);
  }

  TempCodeBufferAllocator.DelayedDisownBuffer();
#if defined(HB_GAMES_COMPILE_ONLY)
  HBStandObserveRelocations(1, Relocations.size(), Relocations.capacity());
#endif

#ifdef VIXL_DISASSEMBLER
  if (Disassemble() & FEXCore::Config::Disassemble::STATS) {
    auto HeaderOp = IR->GetHeader();
    LOGMAN_THROW_A_FMT(HeaderOp->Header.Op == IR::OP_IRHEADER, "First op wasn't IRHeader");

    LogMan::Msg::IFmt("RIP: 0x{:x}", Entry);
    LogMan::Msg::IFmt("Guest Code instructions: {}", HeaderOp->NumHostInstructions);
    LogMan::Msg::IFmt("Host Code instructions: {}", CodeOnlySize >> 2);
    LogMan::Msg::IFmt("Blow-up Amt: {}x", double(CodeOnlySize >> 2) / double(HeaderOp->NumHostInstructions));
  }

  if (Disassemble() & FEXCore::Config::Disassemble::BLOCKS) {
    const auto DisasmBegin = reinterpret_cast<const vixl::aarch64::Instruction*>(CodeBegin);
    const auto DisasmEnd = reinterpret_cast<const vixl::aarch64::Instruction*>(CodeBegin + CodeOnlySize);
    LogMan::Msg::IFmt("Disassemble Begin");
    for (auto PCToDecode = DisasmBegin; PCToDecode < DisasmEnd; PCToDecode += 4) {
      DisasmDecoder->Decode(PCToDecode);
      auto Output = Disasm->GetOutput();
      LogMan::Msg::IFmt("{}", Output);
    }
    LogMan::Msg::IFmt("Disassemble End");
  }
#endif

  DebugData->HostCodeSize = CodeData.Size;
#if defined(HB_GAMES_COMPILE_ONLY)
  extern void HBStandObserveCodeSize(uint64_t Size);
  HBStandObserveCodeSize(CodeOnlySize);
#endif
  DebugData->Relocations = &Relocations;
#if defined(MACRUNNER_FEXXFER_CODEDUMP)
  MRCodeDump(Entry, CodeData.BlockBegin, CodeData.Size);
#endif

  this->IR = nullptr;

  return std::move(CodeData);
}

void Arm64JITCore::ResetStack() {
  if (SpillSlots == 0) {
    return;
  }

  const auto TotalSpillSlotsSize = SpillSlots * MaxSpillSlotSize;

  if (ARMEmitter::IsImmAddSub(TotalSpillSlotsSize)) {
    add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, ARMEmitter::Reg::rsp, TotalSpillSlotsSize);
  } else {
    // Too big to fit in a 12bit immediate
    LoadConstant(ARMEmitter::Size::i64Bit, TMP1, TotalSpillSlotsSize);
    add(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::rsp, ARMEmitter::XReg::rsp, TMP1, ARMEmitter::ExtendedType::LSL_64, 0);
  }
}

fextl::unique_ptr<CPUBackend> CreateArm64JITCore(FEXCore::Context::ContextImpl* ctx, FEXCore::Core::InternalThreadState* Thread) {
  return fextl::make_unique<Arm64JITCore>(ctx, Thread);
}

} // namespace FEXCore::CPU
