// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// TRANS32 MACRUNNER_FEX32_X87_PC_EXACT slow paths: unbox the container/box operands, call the unchanged 80-bit SoftFloat
// handler (same flags, C1 and IE as the exact path), rebox. Containers travel in the low 64 bits of the vector argument.
#pragma once
#include "Interface/Core/HBX87PCX.h"
#include "Interface/Core/HBX87S32.h" // X87EXACT S32
#include "Interface/Core/Interpreter/Fallbacks/F80Fallbacks.h"

namespace FEXCore::CPU::X87PCXOps {
namespace PCX = FEXCore::HBX87::PCX;

static inline uint64_t Lo(VectorRegType v) {
  uint64_t x;
  memcpy(&x, &v, sizeof(x));
  return x;
}
static inline VectorRegType FromLo(uint64_t x) {
  uint64_t Pair[2] = {x, 0};
  VectorRegType v;
  memcpy(&v, Pair, sizeof(v));
  return v;
}
static inline VectorRegType To80(const PCX::Raw80& r) {
  VectorRegType v;
  memcpy(&v, &r, sizeof(v));
  return v;
}
static inline PCX::Raw80 From80(VectorRegType v) {
  PCX::Raw80 r;
  memcpy(&r, &v, sizeof(r));
  return r;
}
static inline VectorRegType U(FEXCore::Core::CpuStateFrame* F, VectorRegType v) {
  return To80(PCX::Unbox(F, Lo(v)));
}
static inline VectorRegType R(FEXCore::Core::CpuStateFrame* F, VectorRegType v80) {
  return FromLo(PCX::Rebox(F, From80(v80)));
}

template<IR::IROps Op>
struct Binary {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType A, VectorRegType B, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(Op == IR::OP_F80ADD ? PCX::Stats::SlowAdd : Op == IR::OP_F80SUB ? PCX::Stats::SlowSub : Op == IR::OP_F80MUL ? PCX::Stats::SlowMul : PCX::Stats::SlowDiv);
    return R(F, OpHandlers<Op>::handle(FCW, U(F, A), U(F, B), F));
  }
};
struct Sqrt {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t FCW, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowSqrt);
    return R(F, OpHandlers<IR::OP_F80SQRT>::handle(FCW, U(F, A), F));
  }
};
struct FromF80 {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowFrom80);
    return R(F, A);
  }
};
struct ToF80 {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowTo80);
    return U(F, A);
  }
};
// The F32/F64 -> F80 ABIs are inline conversions in the dispatcher (they never call Func): the raw bits travel in the
// low lanes of an F80-ABI vector argument instead. The exact path converts loads with Dispatcher::EmitF32ToExtF80 /
// EmitF64ToExtF80: exact, NaN quieted (| 0xC000...), no x87 flag and no C1 is written. These are the same conversions.
static inline PCX::Raw80 LoadF32To80(uint32_t b) {
  PCX::Raw80 r {};
  const uint16_t Sign = static_cast<uint16_t>((b >> 31) << 15);
  const uint32_t E = (b >> 23) & 0xFF, M = b & 0x7FFFFF;
  if (E == 0xFF) {
    r.Sig = M ? ((static_cast<uint64_t>(M) << 40) | 0xC000000000000000ULL) : 0x8000000000000000ULL;
    r.SE = Sign | 0x7FFF;
  } else if (E == 0) {
    if (M) {
      const unsigned Msb = 31 - __builtin_clz(M);
      r.Sig = static_cast<uint64_t>(M) << (63 - Msb);
      r.SE = static_cast<uint16_t>(Sign | (Msb - 149 + 16383));
    } else {
      r.SE = Sign;
    }
  } else {
    r.Sig = static_cast<uint64_t>(M | 0x800000) << 40;
    r.SE = static_cast<uint16_t>(Sign | (E + 0x3F80));
  }
  return r;
}
static inline PCX::Raw80 LoadF64To80(uint64_t b) {
  if (((b >> 52) & 0x7FF) != 0x7FF) return PCX::DoubleTo80(b);
  PCX::Raw80 r {};
  const uint64_t M = b & ((1ULL << 52) - 1);
  r.Sig = M ? ((M << 11) | 0xC000000000000000ULL) : 0x8000000000000000ULL;
  r.SE = static_cast<uint16_t>(((b >> 63) << 15) | 0x7FFF);
  return r;
}
struct Load {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle4(uint16_t, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowLoad4);
    uint32_t Bits;
    memcpy(&Bits, &A, sizeof(Bits));
    MRNoteDenormalF32(F, Bits); // TRANS32 0033
    return FromLo(PCX::Rebox(F, LoadF32To80(Bits)));
  }
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle8(uint16_t, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowLoad8);
    MRNoteDenormalF64(F, Lo(A)); // TRANS32 0033
    return FromLo(PCX::Rebox(F, LoadF64To80(Lo(A))));
  }
};
struct Store {
  FEXCORE_PRESERVE_ALL_ATTR static float handle4(uint16_t FCW, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowStore4);
    return OpHandlers<IR::OP_F80CVT>::handle4(FCW, U(F, A), F);
  }
  FEXCORE_PRESERVE_ALL_ATTR static double handle8(uint16_t FCW, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowStore8);
    return OpHandlers<IR::OP_F80CVT>::handle8(FCW, U(F, A), F);
  }
};
template<IR::IROps Op>
struct Compare {
  FEXCORE_PRESERVE_ALL_ATTR static uint64_t handle(uint16_t FCW, VectorRegType A, VectorRegType B, FEXCore::Core::CpuStateFrame* F) {
    PCX::Stats::Bump(PCX::Stats::SlowCmp);
    return OpHandlers<Op>::handle(FCW, U(F, A), U(F, B), F);
  }
};
// X87EXACT S32 (Interface/Core/HBX87S32.h): container / box -> typed single in the low 32 bits of the result.
struct NarrowS {
  FEXCORE_PRESERVE_ALL_ATTR static VectorRegType handle(uint16_t, VectorRegType A, FEXCore::Core::CpuStateFrame* F) {
    return FromLo(FEXCore::HBX87::S32::Narrow(F, Lo(A)));
  }
};
} // namespace FEXCore::CPU::X87PCXOps
