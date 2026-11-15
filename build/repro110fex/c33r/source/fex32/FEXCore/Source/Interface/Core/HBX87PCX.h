// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// TRANS32 07.11.2026 MACRUNNER_FEX32_X87_PC_EXACT (default 0, Guest32 only).
//
// A compilation unit whose entry state has FCW & 0x0F3F == 0x023F (PC53, RN, all masked) or 0x003F (PC24, RN, all masked),
// FSW.PE == 1 and MXCSR RC == 0 / FZ == 0, and that contains no instruction changing FCW / the x87 environment / MXCSR, is
// compiled with the x87 stack in host double registers ("containers"). Every entry block re-checks that state (CondJump to a
// deopt block: invalidate + exit to the dispatcher, recompiled for the then-current state; after Limit deopts the entry RIP
// stays exact). CPUState keeps the full 80-bit format: values are converted exactly at block boundaries.
//
// Container domain: +-0 and normal doubles. Every other x87 value (NaN, infinity, out-of-range or >53-bit significands,
// 80-bit specials) lives in a block-local box: a quiet NaN 0x7FFC... | index, sign bit = value sign, the 80-bit payload in
// Thread->X87PCX.Slot[index] (index 63 = the x87 indefinite, no slot). Fast paths compute with host double arithmetic and
// leave on any result outside the guarded range to a slow path that calls the unchanged 80-bit SoftFloat handler on the
// exact (unboxed) operands, then reboxes. Values: PC53 = binary64 with exponent guard; PC24 = binary64 on <=24-bit
// significands then fcvt (innocuous double rounding, 53 >= 2*24+2), float exponent guard. C1 (round-up indicator under
// MACRUNNER_HB_X87_FIX_C1_ROUNDUP) from exact error terms. PE is already 1 by the entry condition.
#pragma once
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/MacRunnerLazyMXCSR.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace FEX::Windows::Logging {
void Raw(const char* Message);
}

namespace FEXCore::HBX87::PCX {
inline bool Enabled() {
#ifdef VIXL_SIMULATOR
  return false;
#else
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT");
    return p && p[0] == '1' && !p[1];
  }();
  return v;
#endif
}

enum Mode : uint8_t { Off = 0, PC53 = 1, PC24 = 2, PCMask = 3, DynExact = 0x08, DynW64 = 0x10, DynPoly = 0x20, PETrack = 0x40, GuardAll = 0x80 };
// X87EXACT DYN unit flavours (IR header X87PCX; HBX87PCX.h DynEnabled): DynW64 -- container unit whose guard guarantees the word 0x033F
// (its sites call PC24-kind stubs through their word check); DynPoly -- container unit whose guard checks no word (the sites do);
// DynExact -- exact (80-bit SoftFloat) unit that only carries the guard for 0x033F.
// PETrack: admitted with FSW.PE == 0 - inexact-capable fast forms set PE from the exact error term; the entry check skips PE.

// X87PCXArith Kind
enum KindBits : uint8_t { OpAdd = 0, OpSub = 1, OpMul = 2, OpDiv = 3, OpSqrt = 4, OpMask = 7, K24 = 8, KC1 = 16, CheckA = 32, CheckB = 64, KPE = 128 };
// X87PCXLoad / X87PCXStore Flags
enum FlagBits : uint8_t { FC1 = 1, FPE = 2 };

inline constexpr uint64_t BoxBase = 0x7FFC000000000000ULL;
inline constexpr unsigned IndefIndex = 63;
// Box slots: a box's slot is reused after BoxSlots - 1 later creations (Rebox); the pass caps a block's x87 sites so that one
// block execution creates fewer (x87StackOptimizationPass.cpp PCXEligible: at most 3 creations per site).
inline constexpr unsigned BoxSlots = 4096;
inline constexpr uint64_t BoxIndexMask = BoxSlots - 1;
inline constexpr uint64_t IndefBox = 0xFFFC00000000003FULL;
inline constexpr uint64_t DeoptTag = 1ULL << 63;
// The argument is the host PC right after an entry check's call (bits 63:62 set): unit and guest RIP come from the block.
inline constexpr uint64_t DeoptHostPCTag = 3ULL << 62;
// Lazy MXCSR (MACRUNNER_FEX_LAZY_MXCSR): the host FPSR is the guest's SSE status, and x87 never touches MXCSR. A run of x87 stub
// calls reads FPSR at its start (HBX87PCXEmit.inl CallStub) and, if its host arithmetic raised status bits that were clear, puts
// FPSR back at its end (Arm64JITCore::CompileCode); ops that write FPSR end a run. MACRUNNER_FEX32_X87_PC_EXACT_FPSR=0 (stands
// only) leaves it out.
// lr is dead in translated code between operations (every reader sets it first: bl/blr of calls and links, ret x1 of guest
// returns; CallbackReturn pops it), so stub calls do not park it. MACRUNNER_FEX32_X87_PC_EXACT_KEEPLR=1 (stands only) parks it
// per run as before (Pointers.X87PCXSavedLR).
inline bool KeepLR() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_KEEPLR");
    return p && p[0] == '1' && !p[1];
  }();
  return v;
}
// X87EXACT DYN, 12.11.2026: MACRUNNER_FEX32_X87_EXACT_DYN=1 (default 0, with PC_EXACT). Exactness without the cliff of c33m, where
// a unit first run under a control word other than 0x023F / 0x003F, or whose word changed twice, stays on SoftFloat for good.
//  * Forms. The stubs whose result depends on the control word (arithmetic, fsqrt, fst m32) have a word check in front of their
//    address (DynCheckArith / DynCheckStore bytes): word 0x003F (PC24) / 0x023F (PC53) -- the binary64 forms of c33m, a stub of the
//    other word jumps to its sibling (to PC24 with both operand checks); 0x033F (PC64) -- the binary64 result when the host
//    operation is exact (zero error term: then it is the 64-bit result too, PE untouched, C1 = 0), otherwise the exact handler; any
//    other word (directed rounding, unmasked exceptions, MXCSR RC / FZ) -- the exact handler. fst m32 depends on RC only.
//    FSW.PE is read by the stubs: PE = 0 sends a form to its PE-tracking sibling (so units are compiled without PETrack).
//  * Guard = predictor (shared guard format: X87PCXGuard Mode bits 3..4 = precision field: 01 word 0x003F, 10 0x023F, 11 0x033F,
//    00 no word check). A unit is compiled for the word it is first run under and its sites enter the stubs AFTER the word check
//    (no extra instruction: the guard and c33m's re-checks after writers guarantee the word). A failed guard recompiles the unit for
//    the new word. After Limit failures the unit is compiled with field 00 (DynPoly): its sites enter THROUGH the word check and
//    the unit serves every word -- it is not left exact.
//  * Under 0x033F a unit is a container unit (DynW64, sites through the word check) only when each of its arithmetic operations is
//    an add / sub / mul of two stack leaves -- values straight from float memory, 16-bit integers, 0, 1 (a product of two floats has
//    48 bits, exact in binary64; a result of arithmetic fed into arithmetic, a quotient or a root usually is not, and then costs an
//    attempt, a box and the exact handler). Units without arithmetic qualify. Any other unit stays exact but guarded (DynExact), so
//    that it is recompiled when the word changes. Other words: exact, no guard, as c33m.
// The word is constant while a container block runs (blocks that write FCW / MXCSR / FSW.PE stay exact), which keeps the pass's static
// operand facts true under whichever word a DynPoly block runs. Turns the mode word's keepers on; excludes the GUARD_* keys.
// Proofs: artifacts/claude-lanes-20261112-x87exact/PROOF.md (T1, T2, T3, T5, T7).
inline bool DynEnabled() {
#if defined(VIXL_SIMULATOR) || defined(ARCHITECTURE_arm64ec)
  return false;
#else
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_EXACT_DYN");
    return p && p[0] == '1' && !p[1];
  }();
  return v && Enabled();
#endif
}
inline constexpr uint32_t DynCheckArith = 12; // bytes of the word check in front of an arithmetic stub
inline constexpr uint32_t DynCheckStore = 16; // ... of an fst m32 stub
// MACRUNNER_FEX32_X87_EXACT_DYN_ASSUME_POLY=1 (compile-only stands): every admitted unit as after Limit guard failures.
inline bool DynAssumePoly() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_EXACT_DYN_ASSUME_POLY");
    return p && p[0] == '1' && !p[1];
  }();
  return v;
}
// MACRUNNER_FEX32_X87_PC_EXACT_GUARD_ENTRY=1 (default 0): an entry block's guard runs only on entries from outside the unit (JIT.cpp
// emits it between the entry-point code and the internal jump label). Not with the stand-only KEEPLR.
inline bool GuardEntryEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_GUARD_ENTRY");
    return p && p[0] == '1' && !p[1];
  }();
  return v && Enabled() && !KeepLR() && !DynEnabled();
}
// MACRUNNER_FEX32_X87_PC_EXACT_GUARD_EDGE=1 (default 0): every guarded block (with or without an entry point) has its guard in front
// of its internal label; branches enter after it only when the mode is known on the edge (0030 / 0031, JIT.cpp). Not with KEEPLR.
inline bool GuardEdgeEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_GUARD_EDGE");
    return p && p[0] == '1' && !p[1];
  }();
  return v && Enabled() && !KeepLR() && !DynEnabled();
}
// MACRUNNER_FEX32_X87_PC_EXACT_GUARD_SKIP=1 (default 0): calls from a PC_EXACT unit with a known mode (and shape) link to a second
// entry after the callee's guard when the callee was guarded for the same mode (and shape). See Core.cpp / JIT.cpp ExitFunctionLink.
inline bool GuardSkipEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_GUARD_SKIP");
    return p && p[0] == '1' && !p[1];
  }();
  return v && Enabled() && !KeepLR() && !DynEnabled();
}
// MACRUNNER_FEX32_X87_PC_EXACT_GUARD_SKIP_STATS=1 (stands / capture only): calls by class, counted at the callee's entries.
inline bool GuardSkipStats() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_GUARD_SKIP_STATS");
    return p && p[0] == '1' && !p[1];
  }();
  return v && GuardSkipEnabled();
}
inline constexpr uint32_t GuardSkipMagic = 0x534B5047u; // "GPKS": 16 data bytes before an entry with a second entry after its guard
// MACRUNNER_FEX32_X87_PC_EXACT_MODE_WORD=1 (default 0): the entry check reads the mode word ((FCW & 0x0F3F) | MXCSR RC / FZ << 12,
// CPUState padding at AbridgedFTW + 4) that every FCW / MXCSR writer keeps (JIT/MemoryOps.cpp, Dispatcher.cpp entry, WOW64 Module.cpp,
// CoreState.h). 32-bit only: the ARM64EC side compiles no PC_EXACT unit.
inline bool ModeWordEnabled() {
#ifdef ARCHITECTURE_arm64ec
  return false;
#else
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_MODE_WORD");
    return p && p[0] == '1' && !p[1];
  }();
  return (v || DynEnabled()) && Enabled(); // X87EXACT DYN reads the word in the guard and in the form stubs
#endif
}
inline bool FpsrFixEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_FPSR");
    return !(p && p[0] == '0' && !p[1]);
  }();
  return v && FEXCore::LazyMXCSR::Enabled.load(std::memory_order_relaxed);
}
// MACRUNNER_FEX32_X87_PC_EXACT_ZERO_FAST=1 (default 0, TRANS32 0032): an arithmetic container stub whose result-range check failed
// returns an exact +-0 itself (add / sub: any +-0 host result; mul: a +-0 operand; div: a +-0 dividend) instead of the exact handler.
// TRANS32 0035 MACRUNNER_FEX32_X87_EXACT_FAST (default 0, Guest32): the cheap exact path. 1 = FST/FSTP m32/m64 of the exact path
// (F80CVT) through the integer dispatcher stubs Pointers.X87ExactCvt (Dispatcher.cpp, HBX87ExactFastEmit.inl); 2 = + binary F80,
// 3 = + compares (stages b2 / b3, not built: 2 and 3 act as 1). Independent of MACRUNNER_FEX32_X87_PC_EXACT.
inline unsigned ExactFastLevel() {
#ifdef VIXL_SIMULATOR
  return 0;
#else
  static const unsigned v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_EXACT_FAST");
    return (p && p[0] >= '0' && p[0] <= '3' && !p[1]) ? static_cast<unsigned>(p[0] - '0') : 0u;
  }();
  return v;
#endif
}
inline bool ZeroFastEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_ZERO_FAST");
    return p && p[0] == '1' && !p[1];
  }();
  return v && Enabled();
}
// Per-run units (an SSE op, a status reader or a native transition in the unit) call S variants of the raising stubs (arithmetic,
// fst m32): before the host operation they check the operands' exponents so that the fast path can raise no status bit but IXC
// (Dispatcher/HBX87PCXStubs.inl); a run that starts with PE already in the guest status then needs no FPSR record and no end
// check (Dispatcher.cpp PCXFirstS). MACRUNNER_FEX32_X87_PC_EXACT_SAT=0 (stands only) keeps the per-run form of 0003 v6.
inline bool SatEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_SAT");
    return !(p && p[0] == '0' && !p[1]);
  }();
  return v && FpsrFixEnabled() && !KeepLR();
}
// Unit-S: a unit-mode unit without an internal back-edge (one execution = one pass, typically a call-heavy function) pays the unit
// record at its entry and the check at every exit on each call (08.11: 7.6 ns per execution at PE = 1). It calls the S stubs and
// records only when the guest PE is clear; its exits check the record inline. Loop units keep plain unit mode (their record is paid
// once per many iterations; the S operand checks would cost on each). MACRUNNER_FEX32_X87_PC_EXACT_UNITS=0 (stands only): off.
inline bool UnitSEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_UNITS");
    return !(p && p[0] == '0' && !p[1]);
  }();
  return v && SatEnabled();
}
// Unit-S pays the S operand checks on every raising form of every execution (08.11 bench: ~0.6 ns each), plain unit mode pays the
// record and the exit check once per execution (~5.3 ns more at PE = 1): unit-S only for units with at most this many raising forms
// (arithmetic, fst m32). MACRUNNER_FEX32_X87_PC_EXACT_UNITS_MAX=<n> (stands only), default 8.
inline unsigned UnitSMaxRaising() {
  static const unsigned v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_UNITS_MAX");
    return p ? static_cast<unsigned>(strtoul(p, nullptr, 10)) : 8u;
  }();
  return v;
}
// MACRUNNER_FEX32_X87_PC_EXACT_INLINE_LOAD=1 (default 0): a PCX load (fld m32 / m64) checks the value in line -- +-0 and normal
// values convert in place (fcvt / move), the stub is called only for its slow cases (denormal, infinity, NaN: exact handler). The
// ideal number of load stub calls is the number of such values. Not with the stand-only KEEPLR (its lr parking is per run).
inline bool InlineLoadEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_INLINE_LOAD");
    return p && (p[0] == '1' || p[0] == '2') && !p[1];
  }();
  return v && !KeepLR();
}
// +-0 goes to the thunk with key 1 (the in-line check is 4 instructions, every load site grows by 4 / 5: Gothic world corpus +1.30 %
// code, 0 blocks over the stand-games growth limit); MACRUNNER_FEX32_X87_PC_EXACT_INLINE_LOAD=2 (stands only) checks it in line as
// well (+2 instructions per site on the non-normal path only: +1.97 %, 25 blocks over the limit), calls = denormal / inf / NaN only.
inline bool InlineLoadZero() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_INLINE_LOAD");
    return p && p[0] == '2' && !p[1];
  }();
  return v;
}
// MACRUNNER_FEX32_X87_PC_EXACT_PERRUN=1 (stands only): no unit mode -- every unit per-run, so stands and hardware rows run the S stubs.
inline bool ForcePerRun() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_PERRUN");
    return p && p[0] == '1' && !p[1];
  }();
  return v;
}
// Deopts per entry RIP after which it stays exact (MACRUNNER_FEX32_X87_PC_EXACT_LIMIT for stands, default 2).
inline unsigned Limit() {
  static const unsigned v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_LIMIT");
    const unsigned long n = p ? std::strtoul(p, nullptr, 10) : 2;
    return static_cast<unsigned>(n == 0 ? 2 : (n > 256 ? 256 : n));
  }();
  return v;
}

struct Raw80 {
  uint64_t Sig;
  uint16_t SE;
  uint16_t Pad[3];
};
static_assert(sizeof(Raw80) == 16);

inline bool IsBox(uint64_t b) {
  return ((b >> 52) & 0x7FF) == 0x7FF;
}

// Exact container (non-box) -> 80-bit.
inline Raw80 DoubleTo80(uint64_t b) {
  Raw80 r {};
  const uint64_t Sign = b >> 63;
  const uint64_t E = (b >> 52) & 0x7FF;
  const uint64_t M = b & ((1ULL << 52) - 1);
  if (E == 0) {
    if (M) { // not produced by PCX, converted exactly anyway
      const unsigned Msb = 63 - __builtin_clzll(M);
      r.Sig = M << (63 - Msb);
      r.SE = static_cast<uint16_t>((Sign << 15) | (Msb - 1074 + 16383));
    } else {
      r.SE = static_cast<uint16_t>(Sign << 15);
    }
    return r;
  }
  r.Sig = (1ULL << 63) | (M << 11);
  r.SE = static_cast<uint16_t>((Sign << 15) | (E - 1023 + 16383));
  return r;
}

// 80-bit -> container when it is exactly +-0 or a normal double.
inline bool F80ToDouble(const Raw80& r, uint64_t& Out) {
  const uint64_t Sign = r.SE >> 15;
  const unsigned Ex = r.SE & 0x7FFF;
  if (Ex == 0 && r.Sig == 0) {
    Out = Sign << 63;
    return true;
  }
  if (!(r.Sig >> 63) || (r.Sig & 0x7FF)) {
    return false;
  }
  const int E = static_cast<int>(Ex) - 16383;
  if (E < -1022 || E > 1023) {
    return false;
  }
  Out = (Sign << 63) | (static_cast<uint64_t>(E + 1023) << 52) | ((r.Sig >> 11) & ((1ULL << 52) - 1));
  return true;
}

inline Raw80 Unbox(FEXCore::Core::CpuStateFrame* Frame, uint64_t b) {
  if (!IsBox(b)) {
    return DoubleTo80(b);
  }
  // X87EXACT S32: a box widened from a single (fcvt d, s of 0x7FE00000 | slot) has its slot number in bits 29..40.
  const unsigned Index = (b | (b >> 29)) & BoxIndexMask;
  Raw80 r {};
  if (Index == IndefIndex) {
    r.Sig = 0xC000000000000000ULL;
    r.SE = 0x7FFF;
  } else {
    memcpy(&r, Frame->Thread->X87PCX.Slot[Index], sizeof(r));
  }
  r.SE = static_cast<uint16_t>((r.SE & 0x7FFF) | ((b >> 63) << 15));
  r.Pad[0] = r.Pad[1] = r.Pad[2] = 0;
  return r;
}

inline uint64_t Rebox(FEXCore::Core::CpuStateFrame* Frame, Raw80 r) {
  uint64_t Out;
  r.Pad[0] = r.Pad[1] = r.Pad[2] = 0;
  if (F80ToDouble(r, Out)) {
    return Out;
  }
  auto& B = Frame->Thread->X87PCX;
  unsigned Index = B.Next++ & BoxIndexMask; // 0..4095 but the indefinite's 63; a block creates at most 3900 (pass limit)
  if (Index == IndefIndex) {
    Index = B.Next++ & BoxIndexMask;
  }
  memcpy(B.Slot[Index], &r, sizeof(r));
  B.Boxed++;
  return (static_cast<uint64_t>(r.SE >> 15) << 63) | BoxBase | Index;
}

// Diagnostics (bounded): one stderr line when a counter reaches a power of two.
namespace Stats {
enum Id : unsigned {
  UnitsPCX, UnitNoX87, UnitFCW, UnitPE, UnitMXCSR, UnitLimit, UnitInst, BlocksPCX, BlocksExact,
  BlockNoX87, BlockOp, BlockRead, BlockSites, BlockState,
  SlowAdd, SlowSub, SlowMul, SlowDiv, SlowSqrt, SlowFrom80, SlowTo80, SlowLoad4, SlowLoad8, SlowStore4, SlowStore8, SlowCmp, BlocksShape, ShapeDeopts, BlocksLag, LagKeep, LagRelag, GuardsEntry,
  LinksFast, LinksGuardedTarget, LinksGuardedCaller, LinksGuardedMode, LinksGuardedShape,
  CallsC0, CallsC1, CallsC2, CallsC3, CallsC4, CallsC5, CallsC6, CallsC7, CallsLinked, EdgesSkip, EdgesGuard, GuardsEdge, Count
};
inline const char* const Names[Count] = {"units_pcx", "unit_no_x87", "unit_fcw", "unit_pe", "unit_mxcsr", "unit_limit", "units_guard_all",
                                         "blocks_pcx", "blocks_exact", "block_no_x87", "block_op", "block_read", "block_sites",
                                         "block_state", "slow_add", "slow_sub", "slow_mul", "slow_div", "slow_sqrt",
                                         "slow_from80", "slow_to80", "slow_load4", "slow_load8", "slow_store4", "slow_store8", "slow_cmp",
                                         "blocks_shape", "shape_deopts", "blocks_lag", "lag_keep", "lag_relag", "guards_entry",
                                         "links_fast", "links_guarded_target", "links_guarded_caller", "links_guarded_mode", "links_guarded_shape",
                                         "calls_other", "calls_pcx_shape", "calls_pcx_noshape", "calls_pcx_modeunk", "calls_nonpcx", "calls_c5",
                                         "calls_c6", "calls_c7", "calls_linked", "edges_skip", "edges_guard", "guards_edge"};
inline std::atomic<uint64_t> Values[Count];
inline void Print(unsigned Which, uint64_t N) {
  char Line[96] = "macrunner-fex32-x87pcx-stat: ";
  size_t L = strlen(Line);
  for (const char* p = Names[Which]; *p && L < 70; ++p) Line[L++] = *p;
  Line[L++] = '=';
  char Digits[24];
  int D = 0;
  do { Digits[D++] = char('0' + N % 10); N /= 10; } while (N && D < 20);
  while (D) Line[L++] = Digits[--D];
  Line[L++] = '\n';
  Line[L] = 0;
  FEX::Windows::Logging::Raw(Line);
}
// MACRUNNER_FEX32_X87_PC_EXACT_STATS_EVERY=<seconds>: one line with every counter and the wall clock (ms since the Unix epoch) per
// period, at the first bump after it (the clock is read on every 1024th bump).
inline uint64_t EveryMs() {
  static const uint64_t v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_STATS_EVERY");
    return p ? static_cast<uint64_t>(strtoull(p, nullptr, 10)) * 1000 : 0;
  }();
  return v;
}
inline std::atomic<uint64_t> EveryNext {0};
inline std::atomic<uint64_t> EveryBumps {0};
inline void PrintAll(uint64_t NowMs) {
  char Line[2048] = "macrunner-fex32-x87pcx-stats: t_ms=";
  size_t L = strlen(Line);
  const auto Num = [&](uint64_t N) {
    char Digits[24];
    int D = 0;
    do { Digits[D++] = char('0' + N % 10); N /= 10; } while (N && D < 20);
    while (D && L < sizeof(Line) - 2) Line[L++] = Digits[--D];
  };
  Num(NowMs);
  for (unsigned i = 0; i < Count; ++i) {
    if (L + 40 >= sizeof(Line)) break;
    Line[L++] = ' ';
    for (const char* p = Names[i]; *p; ++p) Line[L++] = *p;
    Line[L++] = '=';
    Num(Values[i].load(std::memory_order_relaxed));
  }
  Line[L++] = '\n';
  Line[L] = 0;
  FEX::Windows::Logging::Raw(Line);
}
inline void Tick() {
  const uint64_t Now = static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  uint64_t Next = EveryNext.load(std::memory_order_relaxed);
  if (Now >= Next && EveryNext.compare_exchange_strong(Next, Now + EveryMs(), std::memory_order_relaxed)) {
    PrintAll(Now);
  }
}
inline void Bump(unsigned Which) {
  const uint64_t N = Values[Which].fetch_add(1, std::memory_order_relaxed) + 1;
  if ((N & (N - 1)) == 0 && N <= (1ULL << 24)) Print(Which, N);
  if (EveryMs() && (EveryBumps.fetch_add(1, std::memory_order_relaxed) & 1023) == 0) Tick();
}
} // namespace Stats

// Entry RIPs that deoptimized: open addressing, (RIP << 8) | count.
inline std::atomic<uint64_t> DeoptTable[4096];
inline std::atomic<uint64_t> DeoptCount {0};
inline unsigned DeoptsOf(uint64_t RIP) {
  const uint64_t Key = RIP & 0xFFFFFFFFULL;
  for (unsigned i = 0; i < 16; ++i) {
    const uint64_t V = DeoptTable[(Key * 0x9E3779B1ULL + i) & 4095].load(std::memory_order_relaxed);
    if (!V) return 0;
    if ((V >> 8) == Key) return V & 0xFF;
  }
  return Limit(); // table crowded: stay exact
}
inline void NoteDeopt(uint64_t RIP) {
  DeoptCount.fetch_add(1, std::memory_order_relaxed);
  const uint64_t Key = RIP & 0xFFFFFFFFULL;
  for (unsigned i = 0; i < 16; ++i) {
    auto& Slot = DeoptTable[(Key * 0x9E3779B1ULL + i) & 4095];
    uint64_t V = Slot.load(std::memory_order_relaxed);
    while (true) {
      if (!V) {
        if (Slot.compare_exchange_weak(V, (Key << 8) | 1, std::memory_order_relaxed)) return;
        continue;
      }
      if ((V >> 8) != Key) break;
      const uint64_t N = (V & 0xFF) < 255 ? V + 1 : V;
      if (Slot.compare_exchange_weak(V, N, std::memory_order_relaxed)) return;
    }
  }
}
// MACRUNNER_FEX32_X87_PC_EXACT_SHAPE=1 (default 0): the unit entry's x87 stack shape as compiled, re-checked at the entry, known
// across the unit's internal edges (x87StackOptimizationPass.cpp). Not with XBLOCK (the shadow keeps its own path).
// Level 1: the unit entry; level 2: also entry points inside the unit (call-return landings and learned entries).
inline unsigned ShapeLevel() {
  static const unsigned v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_SHAPE");
    return (p && (p[0] == '1' || p[0] == '2') && !p[1]) ? static_cast<unsigned>(p[0] - '0') : 0u;
  }();
  return v;
}
// G3FABLE RP6q: MACRUNNER_FEX32_X87_DEOPT_EXACT_RIP=1 -- a failed shape check resumes at Entry + ExitOffset (data word after its call).
inline bool DeoptExactRip() {
  static const bool v = [] { const char* p = std::getenv("MACRUNNER_FEX32_X87_DEOPT_EXACT_RIP"); return p && p[0] == '1' && !p[1]; }();
  return v;
}
inline constexpr uint32_t DeoptRipNone = 0x00FFFFFFu; // the word when ExitOffset does not fit: the RIP entries decide (old rule)
inline bool ShapeEnabled() {
  return ShapeLevel() != 0;
}
// MACRUNNER_FEX32_X87_PC_EXACT_SHAPE_LAG=1 (default 0, with SHAPE): stage B -- CPUState TOP / tag word lag the stack over forward
// internal edges of a unit; written at exits, backward edges, the slow path; fault records carry the lag (x87StackOptimizationPass).
inline bool ShapeLagEnabled() {
  static const bool v = [] {
    const char* p = std::getenv("MACRUNNER_FEX32_X87_PC_EXACT_SHAPE_LAG");
    return p && p[0] == '1' && !p[1];
  }();
  return v && ShapeEnabled();
}
// With DeoptHostPCTag: the entry check that failed was the stack shape (Dispatcher/HBX87PCXStubs.inl X87PCXShapeFail).
inline constexpr uint64_t ShapeDeoptTag = 1ULL << 61;
inline constexpr unsigned ShapeLimit = 2; // shape deopts of an entry RIP after which it is compiled without the shape
inline std::atomic<uint64_t> ShapeDeoptTable[1024];
inline unsigned ShapeDeoptsOf(uint64_t RIP) {
  const uint64_t Key = RIP & 0xFFFFFFFFULL;
  for (unsigned i = 0; i < 16; ++i) {
    const uint64_t V = ShapeDeoptTable[(Key * 0x9E3779B1ULL + i) & 1023].load(std::memory_order_relaxed);
    if (!V) return 0;
    if ((V >> 8) == Key) return V & 0xFF;
  }
  return ShapeLimit; // table crowded: no shape
}
// SHAPE level 2: per entry RIP inside units, the shape seen on the last failed check there and how often it failed:
// (RIP << 24) | (count << 8) | shape.
inline std::atomic<uint64_t> ShapeLearnTable[1024];
inline bool ShapeLearnedOf(uint64_t RIP, unsigned& Count, uint8_t& Shape) {
  const uint64_t Key = RIP & 0xFFFFFFFFULL;
  for (unsigned i = 0; i < 16; ++i) {
    const uint64_t V = ShapeLearnTable[(Key * 0x9E3779B1ULL + i) & 1023].load(std::memory_order_relaxed);
    if (!V) return false;
    if ((V >> 24) == Key) {
      Count = (V >> 8) & 0xFF;
      Shape = V & 0xFF;
      return true;
    }
  }
  Count = ShapeLimit; // table crowded: no shape
  Shape = 0;
  return true;
}
inline void NoteShapeLanding(uint64_t RIP, uint8_t Shape) {
  Stats::Bump(Stats::ShapeDeopts);
  const uint64_t Key = RIP & 0xFFFFFFFFULL;
  for (unsigned i = 0; i < 16; ++i) {
    auto& Slot = ShapeLearnTable[(Key * 0x9E3779B1ULL + i) & 1023];
    uint64_t V = Slot.load(std::memory_order_relaxed);
    while (true) {
      if (!V) {
        if (Slot.compare_exchange_weak(V, (Key << 24) | (1ULL << 8) | Shape, std::memory_order_relaxed)) return;
        continue;
      }
      if ((V >> 24) != Key) break;
      const uint64_t C = (V >> 8) & 0xFF;
      const uint64_t N = (Key << 24) | ((C < 255 ? C + 1 : C) << 8) | Shape;
      if (Slot.compare_exchange_weak(V, N, std::memory_order_relaxed)) return;
    }
  }
}
inline void NoteShapeDeopt(uint64_t RIP) {
  Stats::Bump(Stats::ShapeDeopts);
  const uint64_t Key = RIP & 0xFFFFFFFFULL;
  for (unsigned i = 0; i < 16; ++i) {
    auto& Slot = ShapeDeoptTable[(Key * 0x9E3779B1ULL + i) & 1023];
    uint64_t V = Slot.load(std::memory_order_relaxed);
    while (true) {
      if (!V) {
        if (Slot.compare_exchange_weak(V, (Key << 8) | 1, std::memory_order_relaxed)) return;
        continue;
      }
      if ((V >> 8) != Key) break;
      const uint64_t N = (V & 0xFF) < 255 ? V + 1 : V;
      if (Slot.compare_exchange_weak(V, N, std::memory_order_relaxed)) return;
    }
  }
}
} // namespace FEXCore::HBX87::PCX
