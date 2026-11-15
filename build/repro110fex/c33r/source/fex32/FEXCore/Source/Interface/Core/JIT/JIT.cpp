// SPDX-License-Identifier: MIT
#include "Interface/Core/MRCallRet.h"
#include "Interface/Core/MRHeaderByPC.h"
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
#include <FEXCore/Utils/MacRunnerXfer.h>
#include <FEXCore/Utils/MacRunnerSuspend.h>
#include "Interface/Core/Frontend.h"
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
#include <atomic>
#include <mutex>
#include <unordered_map>
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

#include "Interface/Core/HBX87PCX.h"
#include "Interface/Core/HBX87S32.h" // X87EXACT S32
namespace FEXCore::CPU {

void Arm64JITCore::Op_Unhandled(const IR::IROp_Header* IROp, IR::Ref Node) {
#include "Interface/Core/HBX87Emit.inl"
#include "Interface/Core/HBX87PCXEmit.inl"
#include "Interface/Core/HBX87ExactFastEmit.inl" // TRANS32 0035
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

// TRANS32 GUARD_SKIP: with the key, CallerOffset's upper half carries the caller's call info (JIT.cpp jump thunks).
// ★ PARITY32 MACRUNNER_FEX32_ICALL_IC v2: a site's link record is its 64-bit pair {guest target : 32, host offset : 32}; the two
// instructions before it are the miss stub (`bl veneer; b Ret`), and `b Ret` names the site's return point, the base of the offset.
static uint8_t* MRICRetOf(uint8_t* Pair) {
  const uint32_t B = *reinterpret_cast<const uint32_t*>(Pair - 4);
  LOGMAN_THROW_A_FMT((B >> 26) == 0b000101, "MRIC record layout");
  const int64_t Words = (static_cast<int64_t>(B & 0x03FFFFFFU) << 38) >> 38;
  return Pair - 4 + Words * 4;
}
static uint64_t MRICMake(uint32_t Guest, uintptr_t Host, const uint8_t* Ret) {
  return (static_cast<uint64_t>(static_cast<uint32_t>(static_cast<int32_t>(static_cast<int64_t>(Host) - reinterpret_cast<intptr_t>(Ret)))) << 32) | Guest;
}
static uint64_t MRICTicks() {
  uint64_t V;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(V));
  return V;
}
// Votes of the sampled misses and the re-tag history of the sites that ever missed (keyed by the pair's address; guarded by MRICLock).
struct MRICVote {
  uint32_t Cand;       // frozen site: the target of its last sparse sample
  uint8_t Fast;        // re-tags in a row that came sooner than ~3 us after the previous one
  uint64_t LastRetag;
};
static std::mutex MRICLock;
static std::unordered_map<uintptr_t, MRICVote> MRICVotes;
// The miss stub's `bl` (Pair - 8) goes to the unit veneer, or -- frozen site -- to the `orr lr, lr, #1` right before it.
static bool MRICFrozen(const uint8_t* Pair8) {
  static const uint32_t Marker = [] {
    uint32_t W = 0;
    ARMEmitter::Emitter E(reinterpret_cast<uint8_t*>(&W), 4);
    E.orr(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::lr, ARMEmitter::XReg::lr, 1);
    return W;
  }();
  const auto* Bl = reinterpret_cast<const uint32_t*>(Pair8 - 8);
  const int64_t Words = (static_cast<int64_t>(*Bl & 0x03FFFFFFU) << 38) >> 38;
  return *(Bl + Words) == Marker;
}
static void MRICSetFrozen(uint8_t* Pair8, bool Freeze) {
  // One instruction of the miss stub is rewritten (atomic; both targets are valid entries of the same veneer).
  auto* Bl = reinterpret_cast<uint32_t*>(Pair8 - 8);
  const int64_t Words = ((static_cast<int64_t>(*Bl & 0x03FFFFFFU) << 38) >> 38) + (Freeze ? -1 : 1);
  uint32_t BranchInst = 0;
  ARMEmitter::Emitter BranchEmit(reinterpret_cast<uint8_t*>(&BranchInst), 4);
  BranchEmit.bl(Words);
  std::atomic_ref<uint32_t>(*Bl).store(BranchInst, std::memory_order::relaxed);
  ARMEmitter::Emitter::ClearICache(Bl, 4);
}

static void MRICDelinker(FEXCore::Context::ExitFunctionLinkData* OpaqueRecord) {
  // The cached target's code went away: keep the guest half, point the host half back at the site's miss stub (a later call of that
  // target "hits", lands in the stub and is relinked). One atomic 64-bit store; no code is patched.
  auto* Pair8 = reinterpret_cast<uint8_t*>(OpaqueRecord);
  auto* Pair = reinterpret_cast<uint64_t*>(Pair8);
  const uint8_t* Ret = MRICRetOf(Pair8);
  FEXCore::Allocator::ScopedJITWrite JITWrite;
  const uint64_t Old = std::atomic_ref<uint64_t>(*Pair).load(std::memory_order::acquire);
  if (static_cast<uint32_t>(Old) > 1) {
    std::atomic_ref<uint64_t>(*Pair).store(MRICMake(static_cast<uint32_t>(Old), reinterpret_cast<uintptr_t>(Pair8 - 8), Ret), std::memory_order::release);
  }
}

static int64_t MRCallerOffset(const FEXCore::Context::ExitFunctionLinkData* Record) {
  return FEXCore::HBX87::PCX::GuardSkipEnabled() ? int64_t(int32_t(uint32_t(uint64_t(Record->CallerOffset)))) : Record->CallerOffset;
}

static void DirectBlockDelinker(FEXCore::Context::ExitFunctionLinkData* Record, bool Call) {
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uintptr_t CallerAddress = JumpThunkStartAddress + MRCallerOffset(Record);
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

// TRANS32 GUARD_SKIP (HBX87PCX.h): the second entry of a call's target when the caller's mode / shape at the call (the upper half
// of the thunk's CallerOffset) match the target's guard (the 16 data bytes before its entry); otherwise the entry itself. Only the entry's own page is read.
static uintptr_t MRGuardSkipTarget(const FEXCore::Context::ExitFunctionLinkData* Record, uintptr_t HostCode, bool IsCall) {
  namespace PCXK = FEXCore::HBX87::PCX;
  if (PCXK::GuardSkipStats() && PCXK::Stats::EveryMs()) {
    PCXK::Stats::Tick(); // the stats line with the run-time call counters (they are not bumped through Stats::Bump)
  }
  if (!IsCall) {
    return HostCode;
  }
  const uint64_t Info = uint64_t(Record->CallerOffset) >> 32;
  bool Tagged = (HostCode & 0xFFF) >= 16;
  const uint32_t* W = reinterpret_cast<const uint32_t*>(HostCode) - 4;
  Tagged = Tagged && W[0] == PCXK::GuardSkipMagic && (W[0] ^ W[1] ^ W[2] ^ 0xA5A5A5A5u) == W[3];
  if (!Tagged) {
    PCXK::Stats::Bump(PCXK::Stats::LinksGuardedTarget);
    return HostCode;
  }
  if (!(Info & (1ULL << 31))) {
    PCXK::Stats::Bump(PCXK::Stats::LinksGuardedCaller);
    return HostCode;
  }
  const uint32_t CalleeMode = W[1] & 0xFF, CalleeTest = (W[1] >> 8) & 1, CalleeShape = W[1] >> 16;
  const uint32_t CallerMode = Info & 3, CallerShape = (Info >> 8) & 0x1FF;
  if (!(CalleeMode & 0x80) && (CalleeMode & 3) != CallerMode) {
    PCXK::Stats::Bump(PCXK::Stats::LinksGuardedMode);
    return HostCode;
  }
  if (CalleeTest && (!(CallerShape & 0x100) || (CallerShape & 0xFF) != (CalleeShape & 0xFF))) {
    PCXK::Stats::Bump(PCXK::Stats::LinksGuardedShape);
    return HostCode;
  }
  if ((CalleeMode & 0x80) && !CalleeTest) {
    return HostCode; // nothing to skip
  }
  PCXK::Stats::Bump(PCXK::Stats::LinksFast);
  return HostCode + static_cast<intptr_t>(static_cast<int32_t>(W[2]));
}

uint64_t Arm64JITCore::ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, FEXCore::Context::ExitFunctionLinkData* Record) {
  FEXCore::LazyMXCSR::ScopedHostFPSR PreserveGuestFPSR;
  auto Thread = Frame->Thread;
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  uintptr_t HostCode {};
  const bool MRIC = reinterpret_cast<uintptr_t>(Record) & 2;   // ★ PARITY32 ICALL_IC record (the dispatcher's shared IC stub sets bit 1)
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
    GuestRip = Frame->State.rip;   // the shared IC stub stored the call target
    if (!GuestRip || GuestRip > UINT32_MAX) {
      return Frame->Pointers.DispatcherLoopTop;   // never a cached target: the dispatcher's own lookup decides (fault at 0 etc.)
    }
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

  if (MRIC && !HostCode) {
    Frame->State.rip = GuestRip;   // PARITY32: nothing to link; let the dispatcher handle the target
    return Frame->Pointers.DispatcherLoopTop;
  }

  // See ExitFunction in BranchOps.cpp for an assembly level view of the handled cases.
  uintptr_t JumpThunkStartAddress = reinterpret_cast<uintptr_t>(Record) - 0x10;
  uintptr_t CallerAddress = CompactLoop ? reinterpret_cast<uintptr_t>(LoopRecord) - 4 : MRIC ? 0 : JumpThunkStartAddress + MRCallerOffset(Record);
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
    // ★ PARITY32 ICALL_IC v2: the shared stub comes here when the site's pair is empty (fill), names this target but is delinked
    // (relink), on one miss in 64 of a live site (re-tag onto the new target), or on one miss in 4096 of a frozen site (thaw vote).
    // The pair changes by one atomic 64-bit store; freezing / thawing rewrites one `bl` of the site's miss stub.
    auto* Pair8 = reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(Record) & ~uintptr_t {3});
    auto* Pair = reinterpret_cast<uint64_t*>(Pair8);
    const uint8_t* Ret = MRICRetOf(Pair8);
    const int64_t Dist = static_cast<int64_t>(HostCode) - reinterpret_cast<intptr_t>(Ret);
    const bool Reach = Dist >= INT32_MIN && Dist <= INT32_MAX;
    const uint64_t Old = std::atomic_ref<uint64_t>(*Pair).load(std::memory_order::acquire);
    const uint32_t Cur = static_cast<uint32_t>(Old);
    const uint32_t Target = static_cast<uint32_t>(GuestRip);
    const bool Frozen = MRICFrozen(Pair8);
    unsigned What = 0;   // 1 fill / relink, 2 re-tag, 3 freeze, 4 thaw + re-tag
    if (Cur == 0 || Cur == Target) {
      What = Reach ? 1 : 0;
    } else if (Reach) {
      std::scoped_lock Guard(MRICLock);
      if (MRICVotes.size() > 65536) {
        MRICVotes.clear();
      }
      auto& V = MRICVotes[reinterpret_cast<uintptr_t>(Pair8)];
      if (Frozen) {
        // A sparse sample (one miss in 4096) of a frozen site: the same target twice in a row thaws it onto that target.
        if (V.Cand == Target) {
          V = {};
          What = 4;
        } else {
          V.Cand = Target;
        }
      } else {
        // A sampled miss (one in 64) of a live site: re-tag onto the new target. Four re-tags in a row each sooner than ~3 us after
        // the previous one = the site flips faster than re-tagging pays: freeze it on its current target.
        static const uint64_t FastTicks = [] {
          uint64_t Freq;
          __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(Freq));
          return Freq * 3 / 1000000;
        }();
        const uint64_t Now = MRICTicks();
        V.Fast = (V.LastRetag && Now - V.LastRetag < FastTicks) ? V.Fast + 1 : 0;
        V.LastRetag = Now;
        if (V.Fast >= 4) {
          V = {};
          What = 3;
        } else {
          What = 2;
        }
      }
    }
    {
      // counters: calls into the IC linker and what they did; printed at powers of two.
      static std::atomic<uint64_t> Calls {0}, Links {0}, Retags {0}, Freezes {0};
      const uint64_t N = Calls.fetch_add(1, std::memory_order_relaxed) + 1;
      const uint64_t L = Links.fetch_add(What == 1 ? 1 : 0, std::memory_order_relaxed) + (What == 1 ? 1 : 0);
      const uint64_t R = Retags.fetch_add(What == 2 || What == 4 ? 1 : 0, std::memory_order_relaxed) + (What == 2 || What == 4 ? 1 : 0);
      const uint64_t Z = Freezes.fetch_add(What == 3 ? 1 : 0, std::memory_order_relaxed) + (What == 3 ? 1 : 0);
      if ((N & (N - 1)) == 0) {
        char Line[192];
        const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-icall-ic: linker_calls={} links={} retags={} freezes={} tag={:x} target={:x}\n", N, L, R, Z, Cur, GuestRip);
        Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
        FEX::Windows::Logging::Raw(Line);
      }
    }
    if (What == 4) {
      MRICSetFrozen(Pair8, false);
    }
    if (What == 1 || What == 2 || What == 4) {
      Thread->LookupCache->AddBlockLink(GuestRip, reinterpret_cast<FEXCore::Context::ExitFunctionLinkData*>(Pair8), MRICDelinker, lk);
      std::atomic_ref<uint64_t>(*Pair).store(MRICMake(Target, HostCode, Ret), std::memory_order::release);
    } else if (What == 3) {
      MRICSetFrozen(Pair8, true);   // the pair keeps its target: that one still hits, the others take the L1 path unsampled
    }
    return HostCode;
  }

  if (!CompactLoop && FEXCore::HBX87::PCX::GuardSkipEnabled()) {
    // TRANS32 GUARD_SKIP: a call whose caller mode / shape match the target's guard links to (and continues at) the second entry.
    const bool MRIsCall = *reinterpret_cast<uint32_t*>(CallerAddress - 0x8) == ExpectedKnownCallMarkerInst;
    const uintptr_t MRSkip = MRGuardSkipTarget(Record, HostCode, MRIsCall);
    if (MRSkip != HostCode) {
      HostCode = MRSkip;
      BranchOffset = HostCode / 4 - CallerAddress / 4;
    }
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

#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
// ★ REGION4-0005 13.11.2026 MACRUNNER_FEX32_POLL_ON_SHADOW (MacRunnerSuspend.h). No poll at unit entries; a jump out of the unit polls
// with one store. Direct target: two RIP entries around the store map its host PC (and only it) to the target, so the handler's
// ordinary entry-poll path restores "after the jump" (all of the jump's instruction is done). Indirect target: the store writes the
// target register at page + RegisterRIPSuspendFaultOffset and the handler reads the register named by the faulting instruction.
bool Arm64JITCore::MRShadowPollOn() const {
  return CTX->Config.NeedsPendingInterruptFaultCheck && FEXCore::Utils::MacRunnerPollOnShadow();
}
void Arm64JITCore::MREmitShadowExitPoll(uint64_t GuestRIP) {
#ifndef REGION4_SHADOW_NO_EXIT_POLLS // diagnostic negative control only (probe shpoll32 phases jreg / jfar must then never suspend)
  constexpr size_t InterruptPageOffset =
    offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) - offsetof(FEXCore::Core::InternalThreadState, BaseFrameState);
  static_assert(InterruptPageOffset <= 32760);
  const auto Here = GetCursorAddress<uint8_t*>() - CodeData.BlockBegin;
  const uint64_t Before = DebugData->GuestOpcodes.empty() ? 0 : DebugData->GuestOpcodes.back().GuestEntryOffset;
  DebugData->GuestOpcodes.push_back({GuestRIP - Entry, Here});
  str(ARMEmitter::XReg::zr, STATE, InterruptPageOffset);
  DebugData->GuestOpcodes.push_back({Before, Here + 4});
#endif
}
void Arm64JITCore::MREmitShadowExitPollReg(ARMEmitter::Register GuestRIP) {
#ifndef REGION4_SHADOW_NO_EXIT_POLLS
  constexpr size_t Offset = offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) -
                            offsetof(FEXCore::Core::InternalThreadState, BaseFrameState) + FEXCore::Utils::RegisterRIPSuspendFaultOffset;
  static_assert(Offset <= 32760 && Offset % 8 == 0);
  str(GuestRIP.X(), STATE, Offset);
#endif
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

void Arm64JITCore::EmitEntryPoint(ARMEmitter::BackwardLabel& HeaderLabel, bool CheckTF, uint64_t GuestRIP) {
  // Get the address of the JITCodeHeader and store in to the core state.
  // Two instruction cost, each 1 cycle.
  if (!MRHeaderLazy && !MRSkipHeaderStore) {   // MacRunner FEXXFER HEADER_BY_PC=1: found by host PC instead (MRHeaderByPC.h)
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

#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
  if (MRShadowPollOn()) {
    return; // ★ REGION4-0005 POLL_ON_SHADOW: no entry poll (calls, returns and jump exits poll)
  }
  // ★ REGION4 EXIT_SCAN v2: the entry of a flags window polls at WindowSuspendFaultOffset (same one store, another offset).
  if (CTX->Config.NeedsPendingInterruptFaultCheck && FEXCore::Utils::MacRunnerExitScanMask()) {
    const auto* MRBI = ThreadState->FrontendDecoder->GetDecodedBlockInfo();
    if (MRBI && MRBI->MRWindowEntriesUnit == Entry && MRBI->MRWindowEntries.contains(GuestRIP)) {
      constexpr size_t InterruptPageOffset =
        offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) - offsetof(FEXCore::Core::InternalThreadState, BaseFrameState);
      constexpr size_t Offset = InterruptPageOffset + FEXCore::Utils::WindowSuspendFaultOffset;
      static_assert(Offset <= 32760 || (Offset <= 65520 && Offset % 16 == 0));
      if constexpr (Offset <= 32760) {
        str(ARMEmitter::XReg::zr, STATE, Offset);
      } else {
        str(ARMEmitter::QReg::q0, STATE, Offset);
      }
      FEXCore::Utils::MacRunnerExitScanWindowPolls.fetch_add(1, std::memory_order_relaxed);
      return;
    }
  }
#endif
  EmitSuspendInterruptCheck();
}

#if defined(MACRUNNER_FEXXFER_CODEDUMP)
// FEXXFER/TRANS32 diagnostic build only (-DMACRUNNER_FEXXFER_CODEDUMP=1; never staged into a product engine). Copy of the FEXXFER
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

// TRANS32 PC_EXACT: ops that may run while lr is parked by a run of x87 stub calls. None of them reads lr or leaves the block;
// an op that calls a helper saves and restores whatever lr holds. A fault inside the window sees lr = the JIT address after
// the last stub call, the same kind of value lr holds anywhere in FEX JIT code (after a guest call's bl or a helper's blr).
// Block exits, branches, calls and everything else restore lr first, so the state between blocks is unchanged.
// Ops that may write the host FPSR (SSE arithmetic, conversions, compares): under the lazy MXCSR they end a run, so that the FPSR
// comparison at its end sees only the stub calls' own status bits (FEXCore::HBX87::PCX::FpsrFixEnabled).
static bool MRX87PCXWritesFPSR(const FEXCore::IR::IROp_Header* IROp) {
  using namespace FEXCore::IR;
  switch (IROp->Op) {
  // (F80CVTTo is not here: the exact path converts m32/m64/int to 80 bits with integer code, Dispatcher::Emit*ToExtF80.)
  case OP_FLOAT_FTOF: case OP_VECTOR_FTOISIZED: case OP_FCMPE: case OP_VFSUBSCALARINSERT: case OP_VSTOFGPRINSERT:
  // Readers and writers of the guest status itself (STMXCSR/FXSAVE fold, LDMXCSR seed, scoped status of one owned operation): a
  // run or a recorded unit must end before them, or they would see (or overwrite) the x87 stubs' bits.
  case OP_READFPSR: case OP_GETFPSR: case OP_PUSHFPSR: case OP_POPFPSR: case OP_SETROUNDINGMODE:
    return true;
  // A 64-bit integer source in 32-bit guest code is the x87 stack pass's fild (sign-extended m16/m32): exact, no status.
  case OP_FLOAT_FROMGPR_S: return IROp->C<IROp_Float_FromGPR_S>()->SrcElementSize != OpSize::i64Bit;
  default: return false;
  }
}
// Unit mode (FPSR recorded once per unit, put back at the unit's exits when the x87 stubs raised new bits) is correct only when no
// other op of the unit can raise a status bit itself: that bit would be put back too (08.11: an inexact divss/sqrtss/divps sharing a
// unit with x87 lost its MXCSR.PE). Default deny: the generated list holds the IR ops whose arm64 emitter has no floating-point data
// processing and no helper call, plus the F80 softfloat fallbacks (tools/gen_fpsr_safe.py over JIT/*.cpp and F80Fallbacks.h);
// everything else -- SSE/AVX arithmetic, conversions, compares, F64 (libm) fallbacks, HBX87FAST, native transitions -- keeps the
// unit in per-run mode, where runs end at any such op.
static bool MRX87PCXUnitSafe(const FEXCore::IR::IROp_Header* IROp) {
  using namespace FEXCore::IR;
  switch (IROp->Op) {
#include "Interface/Core/JIT/HBX87PCXFpsrSafe.inl"
  case OP_X87PCXARITH: case OP_X87PCXLOAD: case OP_X87PCXFROM80: case OP_X87PCXTO80: case OP_X87PCXSTORE: case OP_X87PCXCMP:
  case OP_X87PCXLOADS: case OP_X87PCXWIDENS: case OP_X87PCXARITHS: case OP_X87PCXSTORES: // X87EXACT S32
  case OP_X87PCXGUARD:
    return true;
  case OP_FLOAT_FROMGPR_S: return IROp->C<IROp_Float_FromGPR_S>()->SrcElementSize == OpSize::i64Bit;   // fild m16/m32: exact
  default: return false;
  }
}
static bool MRX87PCXKeepsLR(FEXCore::IR::IROps Op) {
  using namespace FEXCore::IR;
  switch (Op) {
  case OP_LOADMEM: case OP_STOREMEM: case OP_LOADMEMTSO: case OP_STOREMEMTSO: case OP_LOADMEMPAIR: case OP_STOREMEMPAIR:
  case OP_ADDSHIFT: case OP_ANDSHIFT: case OP_MUL: case OP_UMUL: case OP_RMIFNZCV: case OP_SETSMALLNZV: case OP_AXFLAG:
  case OP_ADDNZCV: case OP_SUBNZCV: case OP_TESTNZ: case OP_STORENZCV: case OP_SELECT: case OP_NZCVSELECT: case OP_COPY:
  case OP_VEXTRACTTOGPR: case OP_VINSGPR: case OP_FLOAT_FTOF: case OP_PUSH: case OP_POP:
  case OP_FORMCONTEXTADDRESS: case OP_ENTRYPOINTOFFSET: case OP_SUBWITHFLAGS: case OP_ADDWITHFLAGS: case OP_ANDWITHFLAGS:
  case OP_ORLSHL: case OP_STOREREGISTER: case OP_LOADREGISTER: case OP_STOREPF: case OP_STOREAF: case OP_LOADAF: case OP_LOADDF:
  case OP_INVALIDATEFLAGS: case OP_VXOR: case OP_VANDN: case OP_VAND: case OP_VOR: case OP_PUSHTWO: case OP_POPTWO:
  case OP_LOADNZCV: case OP_FINDMSB: case OP_TESTZ: case OP_CARRYINVERT: case OP_ADC: case OP_F80CVTTO: case OP_VECTOR_FTOISIZED:
  case OP_FCMPE: case OP_VFSUBSCALARINSERT: case OP_VSTOFGPRINSERT: case OP_INLINEENTRYPOINTOFFSET: case OP_LOADPF:
  case OP_VLOADTWOGPRS: case OP_RMWHANDLE:
  case OP_X87PCXARITH: case OP_X87PCXLOAD: case OP_X87PCXFROM80: case OP_X87PCXTO80: case OP_X87PCXSTORE: case OP_X87PCXCMP:
  case OP_X87PCXLOADS: case OP_X87PCXWIDENS: case OP_X87PCXARITHS: case OP_X87PCXSTORES: // X87EXACT S32
  case OP_X87PCXGUARD: case OP_GUESTOPCODE: case OP_X87FAULTSTATE: case OP_LOADCONTEXT: case OP_STORECONTEXT:
  case OP_LOADCONTEXTINDEXED: case OP_STORECONTEXTINDEXED: case OP_LOADCONTEXTPAIR: case OP_STORECONTEXTPAIR: case OP_CONSTANT:
  case OP_INLINECONSTANT: case OP_ADD: case OP_SUB: case OP_AND: case OP_ANDN: case OP_OR: case OP_XOR: case OP_LSHL: case OP_LSHR:
  case OP_ASHR: case OP_BFE: case OP_SBFE: case OP_BFI: case OP_NEG: case OP_NOT: case OP_VBSL: case OP_VDUPFROMGPR:
  case OP_VCASTFROMGPR: case OP_VMOV: case OP_LOADNAMEDVECTORCONSTANT: case OP_FLOAT_FROMGPR_S: return true;
  default: return false;
  }
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
  // ★ MacRunner FEXXFER (MacRunnerXfer.h), TRANS32 port: per-compile state; nothing is scanned or emitted with every key 0.
  MRRetEntryStubs.clear();
  MRHeaderLazy = MRHeaderByPC::Lazy(CTX);
  // PARITY32 HOT_FALLTHROUGH: per-compile state. Bit 2 needs the dispatcher's shared return-miss probe within add-immediate reach
  // of Pointers.ExitFunctionLinker (it is emitted right after the linker stub).
  MRRetMissStubs.clear();
  MRJmpMissStubs.clear();
  MRCallMissStubs.clear();
  MRDispVeneer = {};
  MRHotFallthrough = FEXCore::Utils::MacRunnerHotFallthrough32Mask();
  MRStackFold = FEXCore::Utils::MacRunnerStackFold32() && !CTX->Config.Is64BitMode;
  MRStackEngine = MRStackFold || (FEXCore::Utils::MacRunnerStackEngine32() && !CTX->Config.Is64BitMode && GeneralRegisters.size() &&
                                  GeneralRegisters.back() != ARMEmitter::Reg::r19);
  if (MRStackEngine) {
    // CALLRET4: one line per process when the key is on, then the counters at powers of two of runs
    static std::atomic<uint64_t> MRSaidRuns {0};
    const uint64_t Runs = FEXCore::Utils::MRSERuns.load(std::memory_order_relaxed);
    uint64_t Said = MRSaidRuns.load(std::memory_order_relaxed);
    if ((Said == 0 || Runs >= Said * 2) && MRSaidRuns.compare_exchange_strong(Said, std::max<uint64_t>(Runs, 1))) {
      char Line[320];
      const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-stack-engine: on={} runs={} steps={} rebases={} singles={}\n", FEXCore::Utils::MacRunnerStackEngine32Min() - 1, Runs,
                                        FEXCore::Utils::MRSESteps.load(std::memory_order_relaxed), FEXCore::Utils::MRSERebases.load(std::memory_order_relaxed),
                                        FEXCore::Utils::MRSESingles.load(std::memory_order_relaxed));
      Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
      // the six operations that most often ended a run
      uint32_t Top[6] {}, TopOp[6] {};
      for (unsigned o = 0; o < 512; ++o) {
        uint32_t c = FEXCore::Utils::MRSEEndOps[o].load(std::memory_order_relaxed), op = o;
        for (unsigned k = 0; k < 6 && c; ++k) {
          if (c > Top[k]) {
            std::swap(c, Top[k]);
            std::swap(op, TopOp[k]);
          }
        }
      }
      const auto Res2 = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-stack-engine-ends: {}={} {}={} {}={} {}={} {}={} {}={}\n",
                                         FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[0])), Top[0], FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[1])), Top[1],
                                         FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[2])), Top[2], FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[3])), Top[3],
                                         FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[4])), Top[4], FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[5])), Top[5]);
      Line[std::min<size_t>(Res2.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
  }
  if (FEXCore::Utils::MacRunnerSlotForward32() && !CTX->Config.Is64BitMode) {
    // CALLRET4: one line per process when the key is on, then the counters at powers of two of forwarded loads
    static std::atomic<uint64_t> MRSaidFwd {0};
    const uint64_t Fwd = FEXCore::Utils::MRSFwdGPR.load(std::memory_order_relaxed) + FEXCore::Utils::MRSFwdFPR.load(std::memory_order_relaxed);
    uint64_t Said = MRSaidFwd.load(std::memory_order_relaxed);
    if ((Said == 0 || Fwd >= Said * 2) && MRSaidFwd.compare_exchange_strong(Said, std::max<uint64_t>(Fwd, 1))) {
      char Line[240];
      const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-slot-forward: on={} hold={} gpr={} fpr={} conv={} floatheld={} held={} skipped={} mismatch={} stores={}\n",
                                        FEXCore::Utils::MacRunnerSlotForward32(), FEXCore::Utils::MacRunnerSlotForward32Hold(), FEXCore::Utils::MRSFwdGPR.load(std::memory_order_relaxed),
                                        FEXCore::Utils::MRSFwdFPR.load(std::memory_order_relaxed), FEXCore::Utils::MRSFwdConv.load(std::memory_order_relaxed), FEXCore::Utils::MRSFwdFloatHeld.load(std::memory_order_relaxed),
                                        FEXCore::Utils::MRSFwdHeld.load(std::memory_order_relaxed),
                                        FEXCore::Utils::MRSFwdSkipped.load(std::memory_order_relaxed), FEXCore::Utils::MRSFwdMismatch.load(std::memory_order_relaxed),
                                        FEXCore::Utils::MRSFwdStores.load(std::memory_order_relaxed));
      Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
      uint32_t Top[6] {}, TopOp[6] {};
      for (unsigned o = 0; o < 512; ++o) {
        uint32_t c = FEXCore::Utils::MRSFwdSkipUser[o].load(std::memory_order_relaxed), op = o;
        for (unsigned k = 0; k < 6 && c; ++k) {
          if (c > Top[k]) {
            std::swap(c, Top[k]);
            std::swap(op, TopOp[k]);
          }
        }
      }
      const auto Res2 = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-slot-forward-skipped-users: {}={} {}={} {}={} {}={} {}={} {}={}\n",
                                         FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[0])), Top[0], FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[1])), Top[1],
                                         FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[2])), Top[2], FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[3])), Top[3],
                                         FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[4])), Top[4], FEXCore::IR::GetName(static_cast<IR::IROps>(TopOp[5])), Top[5]);
      Line[std::min<size_t>(Res2.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
  }
  MRRetMissDelta = 0;
  if (MRHotFallthrough & 2) {
    const uint64_t Probe = CTX->Dispatcher ? CTX->Dispatcher->GetMRRetMissAddress() : 0;
    const uint64_t Linker = CTX->Dispatcher ? CTX->Dispatcher->GetExitFunctionLinkerAddress() : 0;
    if (Probe > Linker && Probe - Linker < 4096) {
      MRRetMissDelta = static_cast<uint32_t>(Probe - Linker);
    } else {
      MRHotFallthrough &= ~2U;
    }
  }
  {
    // PARITY32: one line per process when the key is on (proof that the key reached this translator; key 0 prints nothing)
    static const bool MRSaidH = [this] {
      const unsigned V = MRHotFallthrough;
      if (V) {
        char Line[96];
        const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-parity: hot_fallthrough={}\n", V);
        Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
        FEX::Windows::Logging::Raw(Line);
      }
      return true;
    }();
    (void)MRSaidH;
  }
  // PARITY32 ICALL_IC: per-compile state; needs the dispatcher's shared stub within add-immediate reach of the linker stub.
  MRICSites.clear();
  MRICVeneer = {};
  MRICDelta = 0;
  MRICActive = false;
  if (FEXCore::Utils::MacRunnerICallIC32Enabled() && !RequiresFarARM64Jumps && !CTX->CodeCache.EnableCodeCaching && CTX->Dispatcher) {
    const uint64_t Stub = CTX->Dispatcher->GetMRICMissAddress();
    const uint64_t Linker = CTX->Dispatcher->GetExitFunctionLinkerAddress();
    if (Stub > Linker && Stub - Linker < 4096) {
      MRICDelta = static_cast<uint32_t>(Stub - Linker);
      MRICActive = true;
    }
  }
  MRICAll = FEXCore::Utils::MacRunnerICallIC32Mode() == 1;
  MRICAbsExits.clear();
  if (MRICActive && !MRICAll) {
    // Mode 2: an indirect CALL qualifies when its target register was last written, in its block, by a load from an address that
    // was itself last written by a constant (`call [disp32]`). A wrong guess only changes which path the site uses, never the result.
    const auto Slot = [](FEXCore::IR::PhysicalRegister R) -> int {
      if (R.IsInvalid()) return -1;
      const auto C = R.AsRegClass();
      return C == FEXCore::IR::RegClass::GPR ? static_cast<int>(R.Reg) : C == FEXCore::IR::RegClass::GPRFixed ? 32 + static_cast<int>(R.Reg) : -1;
    };
    for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
      uint8_t Kind[64] {};   // per physical GPR: 1 = holds a constant, 2 = loaded from a constant address
      for (auto [CodeNode, CodeOp] : IR->GetCode(BlockNode)) {
        if (CodeOp->Op == IR::OP_EXITFUNCTION) {
          const auto Exit = CodeOp->C<IR::IROp_ExitFunction>();
          if (Exit->Hint == IR::BranchHint::Call && !Exit->CallReturnBlock.IsInvalid() && !IsInlineConstant(Exit->NewRIP) && Exit->NewRIP.IsImmediate()) {
            const int S = Slot(FEXCore::IR::PhysicalRegister(Exit->NewRIP));
            if (S >= 0 && S < 64 && Kind[S] == 2) {
              MRICAbsExits.push_back(IR->GetID(CodeNode).Value);
            }
          }
          continue;
        }
        uint8_t K = 0;
        if (CodeOp->Op == IR::OP_CONSTANT) {
          K = 1;
        } else if (CodeOp->Op == IR::OP_LOADMEM || CodeOp->Op == IR::OP_LOADMEMTSO) {
          const auto Addr = CodeOp->Op == IR::OP_LOADMEM ? CodeOp->C<IR::IROp_LoadMem>()->Addr : CodeOp->C<IR::IROp_LoadMemTSO>()->Addr;
          const auto Offset = CodeOp->Op == IR::OP_LOADMEM ? CodeOp->C<IR::IROp_LoadMem>()->Offset : CodeOp->C<IR::IROp_LoadMemTSO>()->Offset;
          if (Offset.IsInvalid() && Addr.IsImmediate()) {
            const int A = Slot(FEXCore::IR::PhysicalRegister(Addr));
            K = (A >= 0 && A < 64 && Kind[A] == 1) ? 2 : 0;
          }
        }
        if (FEXCore::IR::GetHasDest(CodeOp->Op)) {
          const int D = Slot(FEXCore::IR::PhysicalRegister(CodeNode));
          if (D >= 0 && D < 64) Kind[D] = K;
        }
      }
    }
  }
  {
    // PARITY32: one line per process when the key is on (proof that the key reached this translator; key 0 prints nothing)
    static const bool MRSaidI = [this] {
      const unsigned V = MRICActive ? FEXCore::Utils::MacRunnerICallIC32Mode() : (FEXCore::Utils::MacRunnerICallIC32Enabled() && !RequiresFarARM64Jumps ? 9u : 0u);
      if (V) {
        char Line[96];
        const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-parity: icall_ic={}\n", V);
        Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
        FEX::Windows::Logging::Raw(Line);
      }
      return true;
    }();
    (void)MRSaidI;
  }
  MRReturnBlocks.clear();
  // TRANS32: the 64-bit original also required !NeedsPendingInterruptFaultCheck (ARM64EC polls by doorbell). WOW64 always polls by
  // a store to the interrupt fault page; the stub below polls with that same store (EmitSuspendInterruptCheck), so it is kept.
  MRRetNoPollActive = FEXCore::Utils::MacRunnerRetNoPollEnabled() && !CheckTF;
#ifdef ARCHITECTURE_arm64ec
  if (MacRunnerWinctxExactMode && !MRGuestDebugSingleInstruction) {
    MRRetNoPollActive = false;   // the WINCTX exact guard runs before the poll in every entry; keep that entry form
  }
#endif
  MRRetNoPollMode = MRRetNoPollActive ? FEXCore::Utils::MacRunnerRetNoPollMode() : 0;   // PARITY32
  {
    // PARITY32: one line per process when the key is on (proof that the key reached this translator; key 0 prints nothing)
    static const bool MRSaidR = [this] {
      const unsigned V = MRRetNoPollMode > 1 ? MRRetNoPollMode : 0u;
      if (V) {
        char Line[96];
        const auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-parity: ret_nopoll={}\n", V);
        Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
        FEX::Windows::Logging::Raw(Line);
      }
      return true;
    }();
    (void)MRSaidR;
  }
  if (MRRetNoPollActive) {
    MRReturnBlocks.assign(IR->GetHeader()->BlockCount, false);
    for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
      for (auto [CodeNode, CodeOp] : IR->GetCode(BlockNode)) {
        if (CodeOp->Op != IR::OP_EXITFUNCTION) {
          continue;
        }
        const auto Exit = CodeOp->C<IR::IROp_ExitFunction>();
        if (Exit->Hint == IR::BranchHint::Call && !Exit->CallReturnBlock.IsInvalid()) {
          MRReturnBlocks[IR->GetOp<IR::IROp_CodeBlock>(Exit->CallReturnBlock)->ID] = true;
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
  S32ColdSites.clear(); // X87EXACT S32
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
  X87PCXUnitFpsr = false;
  // X87EXACT DYN: the unit's guard does not guarantee the word its PC24 / PC53 sites are compiled for (HBX87PCX.h DynW64 / DynPoly).
  X87PCXDynChecked = FEXCore::HBX87::PCX::DynEnabled() &&
                     (IR->GetHeader()->X87PCX & (FEXCore::HBX87::PCX::DynW64 | FEXCore::HBX87::PCX::DynPoly)) != 0;
  if (FEXCore::HBX87::PCX::FpsrFixEnabled() && IR->GetHeader()->X87PCX) {
    bool Raises = false, Other = false;
    unsigned RaisingForms = 0;
    IR::IROps OtherOp {};
    for (auto [UBlock, UHeader] : IR->GetBlocks()) {
      for (auto [UNode, UOp] : IR->GetCode(UBlock)) {
        if (UOp->Op == IR::OP_X87PCXARITH || UOp->Op == IR::OP_X87PCXARITHS || // X87EXACT S32: a raising form as well
            (UOp->Op == IR::OP_X87PCXSTORE && UOp->C<IR::IROp_X87PCXStore>()->DstSize != IR::OpSize::i64Bit)) {
          Raises = true;
          ++RaisingForms;
        }
        if (!MRX87PCXUnitSafe(UOp)) {
          if (!Other) OtherOp = UOp->Op;
          Other = true;
        }
      }
    }
    X87PCXUnitFpsr = Raises && !Other && !FEXCore::HBX87::PCX::ForcePerRun();
    X87PCXUnitS = false;
    if (X87PCXUnitFpsr && FEXCore::HBX87::PCX::UnitSEnabled()) {
      // An internal back-edge: a jump to a block at or before the current one in emission order.
      bool Loop = false;
      for (auto [UBlock, UHeader] : IR->GetBlocks()) {
        const auto Self = UHeader->C<IR::IROp_CodeBlock>()->ID;
        for (auto [UNode, UOp] : IR->GetCode(UBlock)) {
          if (UOp->Op == IR::OP_JUMP) {
            Loop |= IR->GetOp<IR::IROp_CodeBlock>(UOp->C<IR::IROp_Jump>()->TargetBlock)->ID <= Self;
          } else if (UOp->Op == IR::OP_CONDJUMP) {
            const auto J = UOp->C<IR::IROp_CondJump>();
            Loop |= IR->GetOp<IR::IROp_CodeBlock>(J->TrueBlock)->ID <= Self || IR->GetOp<IR::IROp_CodeBlock>(J->FalseBlock)->ID <= Self;
          }
        }
      }
      X87PCXUnitS = !Loop && RaisingForms <= FEXCore::HBX87::PCX::UnitSMaxRaising();
    }
    // Stand diagnostics: which op keeps a raising unit in per-run mode (first 48 units).
    static const bool FpsrModeLog = getenv("MACRUNNER_FEX32_X87_PC_EXACT_FPSRLOG") != nullptr;
    static std::atomic<uint32_t> FpsrModePrinted {0};
    if (FpsrModeLog && Raises && Other && FpsrModePrinted.fetch_add(1, std::memory_order_relaxed) < 48) {
      char Line[160];
      auto Res = fmt::format_to_n(Line, sizeof(Line) - 1, "macrunner-fex32-x87pcx-fpsrmode: rip={:x} per-run, first {}\n",
                                  IR->GetHeader()->OriginalRIP, FEXCore::IR::GetName(OtherOp));
      Line[std::min<size_t>(Res.size, sizeof(Line) - 1)] = 0;
      FEX::Windows::Logging::Raw(Line);
    }
  }
  // TRANS32 GUARD_ENTRY (HBX87PCX.h GuardEntryEnabled): the guard op an entry block emitted ahead of its internal label.
  const bool MRGuardEntry = FEXCore::HBX87::PCX::GuardEntryEnabled() && !FEXCore::HBX87::StaticRegsEnabled() &&
                            !FEXCore::HBX87::RegionEnabled(!CTX->Config.Is64BitMode());
  IR::Ref MRGuardPrologueNode {};
  // TRANS32 GUARD_SKIP (HBX87PCX.h GuardSkipEnabled): second entry after an entry block's guard; call thunks carry the caller's info.
  const bool MRGuardSkip = FEXCore::HBX87::PCX::GuardSkipEnabled() && !FEXCore::HBX87::StaticRegsEnabled() &&
                           !FEXCore::HBX87::RegionEnabled(!CTX->Config.Is64BitMode());
  const bool MRGuardSkipStats = MRGuardSkip && FEXCore::HBX87::PCX::GuardSkipStats();
  // TRANS32 0031 GUARD_EDGE (HBX87PCX.h GuardEdgeEnabled): the guard of every guarded block in front of its internal label.
  const bool MRGuardEdge = FEXCore::HBX87::PCX::GuardEdgeEnabled() && !FEXCore::HBX87::StaticRegsEnabled() &&
                           !FEXCore::HBX87::RegionEnabled(!CTX->Config.Is64BitMode());
  MRUnitPCX = IR->GetHeader()->X87PCX != 0;
  // TRANS32 0030: per-edge guard targets (JITClass.h MRBranchTarget). Which blocks start with a guard, which end with the mode known,
  // and which guard labels some Jump / CondJump needs (a GUARD_SKIP entry block emits its guard copy only then).
  MRGEOn = (MRGuardEntry || MRGuardSkip || MRGuardEdge) && MRUnitPCX;
  MRGuardLabels.clear();
  MRGuardInfo.clear();
  MRKnownInfo.clear();
  MRNeedGL.clear();
  if (MRGEOn) {
    const size_t NB = IR->GetHeader()->BlockCount;
    MRGuardLabels.resize(NB);
    MRGuardInfo.assign(NB, 0);
    MRKnownInfo.assign(NB, 0);
    MRNeedGL.assign(NB, false);
    for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
      const auto ID = BlockHeader->C<IR::IROp_CodeBlock>()->ID;
      bool First = true;
      for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
        if (IROp->Op == IR::OP_BEGINBLOCK) continue;
        if (IROp->Op == IR::OP_X87PCXGUARD) {
          const auto* G = IROp->C<IR::IROp_X87PCXGuard>();
          if (First && !(G->Mode & 0xE0)) MRGuardInfo[ID] = (1U << 31) | (G->Shape & 0x1FF);
          if (G->Mode & 0x20) MRKnownInfo[ID] = (1U << 31) | (G->Shape & 0x1FF);
        }
        First = false;
      }
    }
    for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
      MRCurBlock = BlockHeader->C<IR::IROp_CodeBlock>()->ID;
      for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
        uint32_t ToIDs[2] {};
        unsigned NT = 0;
        if (IROp->Op == IR::OP_JUMP) ToIDs[NT++] = IR->GetOp<IR::IROp_CodeBlock>(IROp->C<IR::IROp_Jump>()->TargetBlock)->ID;
        if (IROp->Op == IR::OP_CONDJUMP) {
          ToIDs[NT++] = IR->GetOp<IR::IROp_CodeBlock>(IROp->C<IR::IROp_CondJump>()->TrueBlock)->ID;
          ToIDs[NT++] = IR->GetOp<IR::IROp_CodeBlock>(IROp->C<IR::IROp_CondJump>()->FalseBlock)->ID;
        }
        for (unsigned t = 0; t < NT; ++t) {
          const auto To = ToIDs[t];
          if (!(MRGuardInfo[To] >> 31)) continue;
          if (MRSkipOK(MRCurBlock, To)) {
            FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::EdgesSkip);
          } else {
            MRNeedGL[To] = true;
            FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::EdgesGuard);
          }
        }
      }
    }
  }
  for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    X87PCXBlockIsEntry = BlockIROp->EntryPoint;
    MRGuardPrologueNode = {};
    MRCallInfo = 0;
    CurrentBlockHasGuestBoundary = BlockIROp->GuestEntryOffset != FEXCore::Utils::NoGuestSuspendBoundary;
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_THROW_A_FMT(BlockIROp->Header.Op == IR::OP_CODEBLOCK, "IR type failed to be a code block");
#endif

    auto BlockStartHostCode = GetCursorAddress<uint8_t*>();
    {
      const auto Node = IR->GetID(BlockNode);
      const auto Target = &JumpTargets[BlockIROp->ID];
      // TRANS32 0030: this block's guard label (branches that must run its guard), bound in front of its guard or at Target.
      MRCurBlock = BlockIROp->ID;
      ARMEmitter::BiDirectionalLabel* MRGL = MRGEOn && (MRGuardInfo[BlockIROp->ID] >> 31) ? &MRGuardLabels[BlockIROp->ID] : nullptr;
      bool MRGLBound = false;
      [[maybe_unused]] auto* const MRPend = PendingTargetLabel;

      // if there's a pending branch, and it is not fall-through
      if (PendingTargetLabel && PendingTargetLabel != Target && PendingTargetLabel != MRGL) {
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
        // TRANS32 GUARD_SKIP: an entry block whose first op is the guard, which nothing falls into (its data bytes go before it).
        IR::Ref MRSkipGuard {};
        const IR::IROp_Header* MRSkipGuardOp {};
        uint32_t* MRSkipData {};
        if (MRGuardSkip && !(MRRetNoPollActive && MRReturnBlocks[BlockIROp->ID]) &&
            !(!PendingTargetLabel && PendingCallReturnTargetLabel == &IsReturnTarget->second)) {
          for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
            if (IROp->Op == IR::OP_BEGINBLOCK) {
              continue;
            }
            if (IROp->Op == IR::OP_X87PCXGUARD && !(IROp->C<IR::IROp_X87PCXGuard>()->Mode & 0x60)) {
              MRSkipGuard = CodeNode;
              MRSkipGuardOp = IROp;
            }
            break;
          }
        }
        if (PendingTargetLabel) {
          // If there is a fallthrough branch to this block, skip over the entrypoint code (TRANS32 0030: to the guard if it needs it).
          b_OrRestart(MRGL && PendingTargetLabel == MRGL ? MRGL : Target);
        } else if (PendingCallReturnTargetLabel && PendingCallReturnTargetLabel != &IsReturnTarget->second) {
          // If we just emitted a call, but the block we're now emitting is not the return block so don't fallthrough.
          b_OrRestart(PendingCallReturnTargetLabel);
        }
        PendingCallReturnTargetLabel = nullptr;

        // TRANS32 GUARD_SKIP layout: [second entry: (stats) header, b after-guard] [16 data bytes] [entry: header, (stats) guard]
        // [after-guard: unit-mode FPSR record, TF check, spill area]. Nothing falls into the second entry (see the scan above).
        ARMEmitter::ForwardLabel MRAfterGuard;
        uint8_t* MRFastEntry {};
        if (MRSkipGuard) {
          MRFastEntry = GetCursorAddress<uint8_t*>();
          if (MRGuardSkipStats) {
            strh(ARMEmitter::Reg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.AbridgedFTW) + 2);
            LoadConstant(ARMEmitter::Size::i64Bit, TMP3,
                         reinterpret_cast<uint64_t>(&FEXCore::HBX87::PCX::Stats::Values[FEXCore::HBX87::PCX::Stats::CallsLinked]));
            LoadConstant(ARMEmitter::Size::i64Bit, TMP1, 1);
            stadd(ARMEmitter::SubRegSize::i64Bit, TMP1, TMP3);
          }
          if (!MRHeaderLazy) {
            adr_OrRestart(TMP1, &JITCodeHeaderLabel);
            str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
          }
          (void)b(&MRAfterGuard);
          MRSkipData = GetCursorAddress<uint32_t*>(); // filled below, once the entry's address is known
          dc32(0);
          dc32(0);
          dc32(0);
          dc32(0);
        }
        BindOrRestart(&IsReturnTarget->second);
        // PARITY32 form 2: the unit's own entry (the address the unit was compiled for) keeps the ordinary polled, published entry.
        const bool MRNoPollEntry = MRRetNoPollActive && MRReturnBlocks[BlockIROp->ID] && !(MRRetNoPollMode == 2 && BlockIROp->GuestEntryOffset == 0);
        if (!MRNoPollEntry) {
          CodeData.EntryPoints.emplace(BlockStartRIP, GetCursorAddress<uint8_t*>());
        }
        DebugData->GuestOpcodes.push_back({BlockIROp->GuestEntryOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});

        if (MRSkipGuard) {
          const auto MRNormalEntry = GetCursorAddress<uint8_t*>();
          if (!MRHeaderLazy) { // the deopt of a failed check finds its unit by this header
            adr_OrRestart(TMP1, &JITCodeHeaderLabel);
            str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
          }
          if (MRGuardSkipStats) {
            constexpr uint32_t ClassOff = offsetof(FEXCore::Core::CpuStateFrame, State.AbridgedFTW) + 2;
            ldrh(TMP1, STATE, ClassOff);
            strh(ARMEmitter::Reg::zr, STATE, ClassOff);
            and_(ARMEmitter::Size::i64Bit, TMP1, TMP1, 7);
            LoadConstant(ARMEmitter::Size::i64Bit, TMP3,
                         reinterpret_cast<uint64_t>(&FEXCore::HBX87::PCX::Stats::Values[FEXCore::HBX87::PCX::Stats::CallsC0]));
            add(ARMEmitter::Size::i64Bit, TMP3, TMP3, TMP1, ARMEmitter::ShiftType::LSL, 3);
            LoadConstant(ARMEmitter::Size::i64Bit, TMP1, 1);
            stadd(ARMEmitter::SubRegSize::i64Bit, TMP1, TMP3);
          }
          X87PCXLRSaved = false;
          X87PCXRunRaises = false;
          X87PCXRunRecorded = false;
          MRGuardNoSpill = true; // the spill area is allocated after the guard
          EmitIR(MRSkipGuardOp, MRSkipGuard);
          MRGuardNoSpill = false;
          X87PCXLRSaved = false;
          X87PCXRunRaises = false;
          MRGuardPrologueNode = MRSkipGuard;
          (void)Bind(&MRAfterGuard);
          const auto* MRG = MRSkipGuardOp->C<IR::IROp_X87PCXGuard>();
          if (!(MRG->Mode & 0x80) && FEXCore::HBX87::PCX::FpsrFixEnabled() && X87PCXUnitFpsr) {
            // The record the guard's stub makes on the first path (Dispatcher.cpp PCXFirst / PCXGuardS): a live record is kept.
            ARMEmitter::ForwardLabel Done;
            ldr(TMP3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
            (void)tbnz(TMP3, 63, &Done);
            if (X87PCXUnitS) {
              ARMEmitter::ForwardLabel SetPE;
              ldr(TMP3.W(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.mxcsr));
              (void)tbnz(TMP3, 5, &Done);
              mrs(TMP3, ARMEmitter::SystemRegister::FPSR);
              (void)tbnz(TMP3, 4, &SetPE);
              orr(ARMEmitter::Size::i64Bit, TMP3, TMP3, 1ULL << 63);
              str(TMP3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
              (void)b(&Done);
              (void)Bind(&SetPE);
              ldr(TMP3.W(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.mxcsr));
              orr(ARMEmitter::Size::i32Bit, TMP3, TMP3, 0x20);
              str(TMP3.W(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.mxcsr));
            } else {
              mrs(TMP3, ARMEmitter::SystemRegister::FPSR);
              orr(ARMEmitter::Size::i64Bit, TMP3, TMP3, 1ULL << 63);
              str(TMP3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
            }
            (void)Bind(&Done);
          }
          const uint32_t W0 = FEXCore::HBX87::PCX::GuardSkipMagic;
          const uint32_t W1 = uint32_t(MRG->Mode) | (uint32_t((MRG->Shape & 0x100) ? 1 : 0) << 8) | (uint32_t(MRG->Shape & 0xFF) << 16);
          const uint32_t W2 = static_cast<uint32_t>(static_cast<int32_t>(MRFastEntry - MRNormalEntry));
          MRSkipData[0] = W0;
          MRSkipData[1] = W1;
          MRSkipData[2] = W2;
          MRSkipData[3] = W0 ^ W1 ^ W2 ^ 0xA5A5A5A5u;
          MRSkipHeaderStore = true; // EmitEntryPoint below: both paths stored the header already
          FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::GuardsEntry);
        }

        if (MRNoPollEntry) {
          // ★ MacRunner FEXXFER MACRUNNER_FEX_RET_NOPOLL (MacRunnerXfer.h): the return landing and the fall-through after the
          // call enter here without the poll (no TF check / WINCTX guard in this mode, see MRRetNoPollActive). The block's
          // entry point for L1, links and the dispatcher is the polled stub emitted after the unit's code.
          if (!MRHeaderLazy) {
            adr_OrRestart(TMP1, &JITCodeHeaderLabel);
            str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
          }
          MREmitSpillAllocation();
          if (MRRetNoPollMode != 2) {
            // (PARITY32 form 2: not published, no stub: only the return landing and the fall-through after the call come here.)
            auto& Stub = MRRetEntryStubs.emplace_back(MRRetEntryStub {BlockStartRIP, BlockIROp->GuestEntryOffset, {}});
            BindOrRestart(&Stub.Body);
          }
        } else {
          EmitEntryPoint(JITCodeHeaderLabel, CheckTF, BlockStartRIP);
          MRSkipHeaderStore = false;
          if (MRSkipGuard && MRGL && MRNeedGL[BlockIROp->ID]) {
            // TRANS32 0030: the GUARD_SKIP guard sits before the spill area; internal edges that need it run a copy here.
            b_OrRestart(Target);
            BindOrRestart(MRGL);
            MRGLBound = true;
            X87PCXLRSaved = false;
            X87PCXRunRaises = false;
            X87PCXRunRecorded = false;
            EmitIR(MRSkipGuardOp, MRSkipGuard);
            X87PCXLRSaved = false;
            X87PCXRunRaises = false;
          }
        }
      }

      if (PendingCallReturnTargetLabel) {
        // If there is still a pending call return target, then the block we're emitting is not the return block so don't fallthrough.
        b_OrRestart(PendingCallReturnTargetLabel);
        PendingCallReturnTargetLabel = nullptr;
      }
      PendingTargetLabel = nullptr;

      PendingSuspendRIP.reset();

      // TRANS32 GUARD_ENTRY: an entry block whose first op is the PC_EXACT guard gets it here -- after the entry-point code, before
      // the label internal jumps and fall-throughs target -- and its body skips the op.
      if ((MRGuardEntry || MRGuardEdge) && BlockIROp->EntryPoint && !MRGuardPrologueNode) {
        for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
          if (IROp->Op == IR::OP_BEGINBLOCK) {
            continue;
          }
          if (IROp->Op == IR::OP_X87PCXGUARD && !(IROp->C<IR::IROp_X87PCXGuard>()->Mode & 0x60)) {
            if (MRGL) { // TRANS32 0030: branches that need the guard enter here
              BindOrRestart(MRGL);
              MRGLBound = true;
            }
            X87PCXLRSaved = false;
            X87PCXRunRaises = false;
            X87PCXRunRecorded = false;
            EmitIR(IROp, CodeNode);
            X87PCXLRSaved = false; // the guard raises nothing: no run end check is owed
            X87PCXRunRaises = false;
            MRGuardPrologueNode = CodeNode;
            FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::GuardsEntry);
          }
          break;
        }
      }

      if (MRGuardEdge && !BlockIROp->EntryPoint && MRGL && !MRGuardPrologueNode) {
        // TRANS32 0031 GUARD_EDGE: a guarded block without an entry point -- [guard label: guard] [internal label]. A fall-through from a
        // block whose mode is known (PendingTargetLabel == Target, see MRBranchTarget) jumps over the guard.
        for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
          if (IROp->Op == IR::OP_BEGINBLOCK) {
            continue;
          }
          if (IROp->Op == IR::OP_X87PCXGUARD && !(IROp->C<IR::IROp_X87PCXGuard>()->Mode & 0xE0)) {
            if (MRPend == Target) {
              b_OrRestart(Target);
            }
            BindOrRestart(MRGL);
            MRGLBound = true;
            X87PCXLRSaved = false;
            X87PCXRunRaises = false;
            X87PCXRunRecorded = false;
            EmitIR(IROp, CodeNode);
            X87PCXLRSaved = false;
            X87PCXRunRaises = false;
            MRGuardPrologueNode = CodeNode;
            FEXCore::HBX87::PCX::Stats::Bump(FEXCore::HBX87::PCX::Stats::GuardsEdge);
          }
          break;
        }
      }
      if (MRGL && !MRGLBound) {
        BindOrRestart(MRGL); // TRANS32 0030: the guard is in the body (or no edge needs the copy): the guard label is Target
      }
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
      X87PCXLRSaved = false;
      X87PCXRunRaises = false;
      MRSEEnd(false); // CALLRET4: a run never crosses an IR block
      MRSFKind = 0;
      MRSFEvents = 0;
      for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
        if (MRGuardPrologueNode && CodeNode == MRGuardPrologueNode) {
          continue; // TRANS32 GUARD_ENTRY: emitted ahead of the internal label
        }
        if (X87PCXLRSaved && (!MRX87PCXKeepsLR(IROp->Op) || (FEXCore::HBX87::PCX::FpsrFixEnabled() && MRX87PCXWritesFPSR(IROp)))) {
          // TRANS32 PC_EXACT: end of a run of x87 stub calls (HBX87PCXEmit.inl CallStub).
          const bool KeepLR = FEXCore::HBX87::PCX::KeepLR();
          if (FEXCore::HBX87::PCX::FpsrFixEnabled() && X87PCXRunRaises && !X87PCXUnitFpsr) {
            // Status bits the run raised that were clear at its start are the x87 stubs' own: the shared run-end stub puts FPSR back
            // (and, with the parked lr of the stand-only KEEPLR, restores lr itself).
            // With SatEnabled a run that started with PE in the guest status has no record: the check is skipped inline.
            ARMEmitter::ForwardLabel NoRecord;
            if (FEXCore::HBX87::PCX::SatEnabled()) {
              ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
              (void)tbz(TMP1, 63, &NoRecord);
            }
            ldr(TMP1, STATE, KeepLR ? offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXRunEnd) :
                                      offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXUnitExit));
            blr(TMP1);
            (void)Bind(&NoRecord);
          } else if (KeepLR) {
            ldr(ARMEmitter::XReg::lr, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedLR));
          }
          X87PCXLRSaved = false;
          X87PCXRunRaises = false;
        }
        if (X87PCXUnitFpsr && (IROp->Op == IR::OP_EXITFUNCTION || IROp->Op == IR::OP_BREAK || IROp->Op == IR::OP_THREADREMOVECODEENTRY)) {
          // TRANS32 PC_EXACT unit mode: the unit is left here; the unit-exit stub checks the record (no exit op reads lr). A unit-S
          // unit that started with PE in the guest status has no record: the check is skipped inline.
          ARMEmitter::ForwardLabel NoRecord;
          if (X87PCXUnitS) {
            ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXSavedFPSR));
            (void)tbz(TMP1, 63, &NoRecord);
          }
          ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.X87PCXUnitExit));
          blr(TMP1);
          (void)Bind(&NoRecord);
        }
        if (!MRStackEngine || !MRStackEngineOp(BlockNode, IROp, CodeNode)) {
          EmitIR(IROp, CodeNode);
        }
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

#include "Interface/Core/HBX87S32Cold.inl" // X87EXACT S32: the cold parts of the typed forms

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
    // TRANS32 GUARD_SKIP: the caller's mode / shape at a call ride in the upper half of CallerOffset (a unit is far below 2 GiB).
    dc64(MRGuardSkip ? (uint64_t(uint32_t(int32_t(int64_t(PendingJumpThunk.CallerAddress - ThunkAddress)))) | (PendingJumpThunk.CallInfo << 32)) :
                       (PendingJumpThunk.CallerAddress - ThunkAddress)); // CallerOffset
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

  // PARITY32 HOT_FALLTHROUGH miss stubs (MacRunnerXfer.h; see ExitFunction in BranchOps.cpp).
  for (auto& Stub : MRRetMissStubs) {
    // Return miss: the target into TMP3, then the dispatcher's shared L1 probe (Dispatcher.cpp, MRRetMissAddress), which ends in `ret`.
    BindOrRestart(&Stub.Miss);
    mov(TMP3, ARMEmitter::Register(Stub.RipIdx).X());
    ldr(TMP1, STATE_PTR(CpuStateFrame, Pointers.ExitFunctionLinker));
    add(ARMEmitter::Size::i64Bit, TMP1, TMP1, MRRetMissDelta);
    br(TMP1);
  }
  MRRetMissStubs.clear();
  for (auto& Stub : MRCallMissStubs) {
    BindOrRestart(&Stub.Miss);
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    str(ARMEmitter::Register(Stub.RipIdx).X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    b_OrRestart(&Stub.Back);
  }
  MRCallMissStubs.clear();
  if (!MRJmpMissStubs.empty()) {
    for (auto& Stub : MRJmpMissStubs) {
      BindOrRestart(&Stub.Miss);
      str(ARMEmitter::Register(Stub.RipIdx).X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
      b_OrRestart(&MRDispVeneer);
    }
    BindOrRestart(&MRDispVeneer);
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    br(TMP2);
    MRJmpMissStubs.clear();
  }
  if (!MRICSites.empty()) {
    // ★ PARITY32 MACRUNNER_FEX32_ICALL_IC v2: out-of-line part of the unit's sites. Per site 2 instructions + the 8-byte pair:
    //   Miss:    bl  <unit veneer>           LR = PolyRet; the shared stub makes it the host return of the pushed call-ret entry
    //   PolyRet: b   <site return point>     so the callee's ret is predicted (the bl pushed PolyRet)
    //   Pair:    .quad {guest 0, offset of Miss from the return point}   written only by ExitFunctionLink (atomic 64-bit stores)
    // and once per unit the veneer to the dispatcher's shared stub (a fixed distance after the exit linker stub).
    for (auto& Site : MRICSites) {
      ARMEmitter::BackwardLabel Ret {};
      Ret.Location = Site.ReturnAddr;
      Align(8);
      const auto MissAddr = GetCursorAddress<uint8_t*>();
      BindOrRestart(&Site.Miss);
      bl_OrRestart(&MRICVeneer);
      b_OrRestart(&Ret);
      BindOrRestart(&Site.Pair);
      dc64(static_cast<uint64_t>(static_cast<uint32_t>(static_cast<int32_t>(MissAddr - Site.ReturnAddr))) << 32);
    }
    // Veneer. A frozen site's stub calls the instruction BEFORE it (`orr lr, lr, #1`): the shared stub then knows the site by LR bit 0.
    orr(ARMEmitter::Size::i64Bit, ARMEmitter::XReg::lr, ARMEmitter::XReg::lr, 1);
    BindOrRestart(&MRICVeneer);
    ldr(TMP4, STATE_PTR(CpuStateFrame, Pointers.ExitFunctionLinker));
    add(ARMEmitter::Size::i64Bit, TMP4, TMP4, MRICDelta);
    br(TMP4);
    MRICSites.clear();
  }
  for (auto& Stub : MRRetEntryStubs) {
    // ★ MacRunner FEXXFER MACRUNNER_FEX_RET_NOPOLL: the polled entry of a return block = the inline entry of EmitEntryPoint
    // (header, spill area, poll in the same form - on WOW64 the store to the interrupt fault page), then into the body. Its own
    // host->guest mapping names the block's RIP, so a suspend fault in the stub restores the block's entry state.
    CodeData.EntryPoints.emplace(Stub.GuestRIP, GetCursorAddress<uint8_t*>());
    DebugData->GuestOpcodes.push_back({Stub.GuestOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
    if (!MRHeaderLazy) {
      adr_OrRestart(TMP1, &JITCodeHeaderLabel);
      str(TMP1, STATE, offsetof(FEXCore::Core::CPUState, InlineJITBlockHeader));
    }
    MREmitSpillAllocation();
    EmitSuspendInterruptCheck();
    b_OrRestart(&Stub.Body);
  }
  MRRetEntryStubs.clear();
  for (auto& Trap : PendingGuestSuspendTraps) {
    BindOrRestart(&Trap.Label);
    DebugData->GuestOpcodes.push_back({Trap.GuestOffset, GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
    brk(0xCAFE);
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
    // X87EXACT S32: a table with singles carries the version that says so; any other table is byte for byte as before.
    const bool MRAnySingle = std::any_of(X87FaultRecords.begin(), X87FaultRecords.end(), [](const auto& R) { return R.SingleMask != 0; });
    const FEXCore::Core::X87Fault::Header Extension {Magic, MRAnySingle ? VersionSingles : Version, sizeof(Record), uint32_t(X87FaultRecords.size()),
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
