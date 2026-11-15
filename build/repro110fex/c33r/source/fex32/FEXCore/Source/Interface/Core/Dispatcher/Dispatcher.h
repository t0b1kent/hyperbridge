// SPDX-License-Identifier: MIT
#pragma once

#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/Interpreter/InterpreterOps.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/fextl/memory.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace FEXCore {
struct GuestSigAction;
struct SignalDelegatorConfig;
} // namespace FEXCore

namespace FEXCore::Core {
struct CpuStateFrame;
struct InternalThreadState;
} // namespace FEXCore::Core

namespace FEXCore::Context {
class ContextImpl;
}

namespace FEXCore::CPU {

#define STATE_PTR(STATE_TYPE, FIELD) STATE.R(), offsetof(FEXCore::Core::STATE_TYPE, FIELD)
#define STATE_PTR_IDX(STATE_TYPE, FIELD, INDEX) STATE.R(), ARRAY_OFFSETOF(FEXCore::Core::STATE_TYPE, FIELD, INDEX)
#define FALLBACK_HANDLER_OFFSET(INDEX, FIELD) \
  STATE.R(),                                  \
    (ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers, INDEX) + offsetof(FEXCore::Core::FallbackABIInfo, FIELD))

class Dispatcher final : public Arm64Emitter {
public:
  static fextl::unique_ptr<Dispatcher> Create(FEXCore::Context::ContextImpl* CTX);

  Dispatcher(FEXCore::Context::ContextImpl* ctx);
  ~Dispatcher();

  void InitThreadPointers(FEXCore::Core::InternalThreadState* Thread);

#ifdef VIXL_SIMULATOR
  void ExecuteDispatch(FEXCore::Core::CpuStateFrame* Frame);
  void ExecuteJITCallback(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP);
#else
  void ExecuteDispatch(FEXCore::Core::CpuStateFrame* Frame) {
    DispatchPtr(Frame, false);
  }

  void ExecuteJITCallback(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP) {
    CallbackPtr(Frame, RIP);
  }
#endif

  uint64_t GetExitFunctionLinkerAddress() const {
    return ExitFunctionLinkerAddress;
  }

  // ★ PARITY32 HOT_FALLTHROUGH 2: the shared return-miss L1 probe; 0 = not emitted (bit off).
  uint64_t GetMRRetMissAddress() const {
    return MRRetMissAddress;
  }

  // ★ PARITY32 ICALL_IC: the shared miss / fill / relink stub of the inline target cache; 0 = not emitted (key 0).
  uint64_t GetMRICMissAddress() const {
    return MRICMissAddress;
  }

  SignalDelegatorConfig MakeSignalDelegatorConfig() const;

protected:
  FEXCore::Context::ContextImpl* CTX;

  uint64_t MRRetMissAddress {};   // ★ PARITY32 HOT_FALLTHROUGH 2 (emitted only when the bit is on)
  uint64_t MRICMissAddress {};      // ★ PARITY32 ICALL_IC (emitted only when the key is on)

  using AsmDispatch = void (*)(FEXCore::Core::CpuStateFrame* Frame, bool SingleInst);
  using JITCallback = void (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP);

  AsmDispatch DispatchPtr;
  JITCallback CallbackPtr;
private:
  /**
   * @name Dispatch Helper functions
   * @{ */
  uint64_t ThreadStopHandlerAddress {};
  uint64_t ThreadStopHandlerAddressSpillSRA {};
  uint64_t AbsoluteLoopTopAddress {};
  uint64_t AbsoluteLoopTopAddressFillSRA {};
  uint64_t AbsoluteLoopTopAddressEnterEC {};
  uint64_t AbsoluteLoopTopAddressEnterECFillSRA {};
  uint64_t ThreadPauseHandlerAddress {};
  uint64_t ThreadPauseHandlerAddressSpillSRA {};
  uint64_t ExitFunctionLinkerAddress {};
  uint64_t SignalHandlerReturnAddress {};
  uint64_t SignalHandlerReturnAddressRT {};
  uint64_t GuestSignal_SIGILL {};
  uint64_t GuestSignal_SIGTRAP {};
  uint64_t GuestSignal_SIGSEGV {};

  uint64_t PauseReturnInstruction {};
  std::array<uint64_t, FallbackABI::FABI_UNKNOWN> ABIPointers {};
  /**  @} */

  uint64_t Start {};
  uint64_t End {};

  // Long division helpers
  uint64_t LUDIVHandlerAddress {};
  uint64_t LDIVHandlerAddress {};
  // TRANS32 MACRUNNER_FEX32_X87_PC_EXACT: shared deopt of an entry check (HBX87PCXEmit.inl)
  uint64_t X87PCXDeoptHandlerAddress {};
  uint64_t X87PCXSlowAddress[13] {};
  uint64_t X87PCXS32ColdAddress[40] {}; // X87EXACT S32 (HBX87S32.h Cold)
  uint64_t X87PCXConvertAddress[2] {};
  uint64_t X87PCXArithAddress[256] {};
  uint64_t X87PCXLoadAddress[2] {};
  uint64_t X87PCXStoreAddress[8] {};
  uint64_t X87PCXCmpAddress[2] {};
  uint64_t X87PCXCheckAddress[8] {};
  uint64_t X87PCXDeoptExitAddress {};
  uint64_t X87PCXFirstAddress[278] {};
  uint64_t X87PCXRunEndAddress {};
  uint64_t X87PCXUnitExitAddress {};
  uint64_t X87PCXArithSAddress[256] {};
  uint64_t X87PCXStoreSAddress[8] {};
  uint64_t X87PCXFirstSAddress[272] {};
  uint64_t X87PCXLoadToAddress[64] {};
  uint64_t X87PCXShapeFailAddress[2] {};
  uint64_t X87ExactCvtAddress[2] {}; // TRANS32 0035

  // F64 reduced-precision shared handlers
  uint64_t F64SinHandlerAddress {};
  uint64_t F64CosHandlerAddress {};
  uint64_t F64TanHandlerAddress {};
  uint64_t F64F2XM1HandlerAddress {};
  uint64_t F64ScaleHandlerAddress {};
  uint64_t F64AtanHandlerAddress {};
  uint64_t F64FYL2XHandlerAddress {};
  uint64_t F64FYL2XP1HandlerAddress {};
  uint64_t F64FPREMHandlerAddress {};
  uint64_t F64FPREM1HandlerAddress {};

  void EmitDispatcher();
  uint64_t GenerateABICall(FallbackABI ABI);

  // Inline softfloat conversion emitters - avoid FPCR save/restore overhead
  // These emit ARM64 code that performs the conversion using only integer ops
  void EmitI16ToExtF80();
  void EmitI32ToExtF80();
  void EmitF32ToExtF80();
  void EmitF64ToExtF80();

  // Shared label set for the LUT-based F64 log2 path used by both FYL2X and
  // FYL2XP1. The pool is emitted once via EmitF64Log2Constants.
  struct F64Log2Constants {
    ARMEmitter::ForwardLabel One;
    ARMEmitter::ForwardLabel A0, A1, A2, A3, A4, A5, A6, A7;
    ARMEmitter::ForwardLabel Table;
  };

  void EmitF64Sin();
  void EmitF64Cos();
  void EmitF64Tan();
  void EmitF64F2XM1();
  void EmitF64Scale();
  void EmitF64Atan();
  void EmitF64FYL2X(F64Log2Constants& C);
  void EmitF64FYL2XP1(F64Log2Constants& C);
  void EmitF64Log2Constants(F64Log2Constants& C);
  void EmitF64FPREM();
  void EmitF64FPREM1();

  FEX_CONFIG_OPT(DisableL2Cache, DISABLEL2CACHE);
};

} // namespace FEXCore::CPU
