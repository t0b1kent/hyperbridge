// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
#pragma once
#include <cstdlib>
#include <cstdint>
#include <atomic>

namespace FEXCore::Utils {
// Read during IR construction/code generation, never from a signal handler.
inline unsigned MacRunnerSuspendBackedgeMode() {
#ifdef ARCHITECTURE_arm64ec
  static const unsigned Mode = [] {
    const char* Value = std::getenv("MACRUNNER_FEX_SUSPEND_BACKEDGE64");
    return Value && (Value[0] == '1' || Value[0] == '2') && !Value[1]
             ? static_cast<unsigned>(Value[0] - '0') : 0U;
  }();
  return Mode;
#elif defined(_WIN32)
  // WOW suspension protects InterruptFaultPage and waits for IN_JIT to clear.
  // Pure guest loops must reach a precise boundary even without a new entry.
  // Preserve context-visible flags there; no retired environment key is needed.
  return 2;
#else
  return 0;
#endif
}
// ★ REGION4-0004 MACRUNNER_FEX32_SUSPEND_FWD_EXACT=1: exact flags also on forward edges into loop headers (their poll runs there too;
// probe hdrfwd32: without it 0 of ~4 600 suspensions at a forward-entered header show x86 flags). Default 0 = previous code.
inline bool MacRunnerSuspendFwdExact() {
  static const bool On = [] {
    const char* Value = std::getenv("MACRUNNER_FEX32_SUSPEND_FWD_EXACT");
    return Value && Value[0] == '1' && !Value[1];
  }();
  return On;
}
inline bool MacRunnerSuspendBackedgeEnabled() {
  return MacRunnerSuspendBackedgeMode() != 0;
}
// Mode 1 keeps the existing guest-visible flag liveness; mode 2 also retains
// flags that are dead for the guest but observable in a suspended context.
inline bool MacRunnerSuspendBackedgeExactFlags() {
  return MacRunnerSuspendBackedgeMode() == 2;
}
// Synthesized blocks inside one x86 instruction have no guest continuation PC.
// Decoder-created blocks always supply an explicit relative guest address.
inline constexpr uint32_t NoGuestSuspendBoundary = UINT32_MAX;
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
inline constexpr size_t PublishedSuspendFaultOffset = 16;
// ★ REGION4 EXIT_SCAN v2: the entry poll of a block that starts a flags window (Frontend MRWindowEntries). Same single store as the
// ordinary poll, another offset in the same page: the handler does not suspend there when the block was entered by a call
// (the caller may have left undefined flags, MACRUNNER_FEX32_EXIT_SCAN), and the next poll suspends instead.
inline constexpr size_t WindowSuspendFaultOffset = 32;
// ★ REGION4-0005 POLL_ON_SHADOW: the poll of an indirect jump out of a unit is `str <guest target>, [page + 48]`; the handler takes the
// continuation RIP from the stored register (the instruction is complete, only the transfer is left).
inline constexpr size_t RegisterRIPSuspendFaultOffset = 48;
#endif
// ★ REGION4-0005 13.11.2026 MACRUNNER_FEX32_POLL_ON_SHADOW=1 (WOW64 only, needs MACRUNNER_FEX_CALLRET_LAZY=1). While a thread is being
// suspended, the suspender also makes the committed window of its call-return stack (x25) no-access: the `stp [x25, #-16]!` of every
// call and the `ldp [x25], #16` of every return are then the poll. The poll at unit entries goes away; exits by a jump (direct,
// indirect, fall-through, writable-loop revalidation) get one store each. Every cycle of execution either stays in a unit (back edge
// -> loop header poll) or leaves it by a call, a return or a jump. Contexts: at a call "before the call" (RIP = the call, ESP before
// its push), at a return "after the return" (RIP = the popped target), at a jump "after the jump". Default 0 = previous code.
// Counters (line macrunner-fex32-shadow, printed by the WOW64 handler at powers of two): 0 arms (window made no-access), 1 stops at a
// call, 2 stops at a return, 3 stops at an indirect jump exit (register RIP), 4 no stop (Canceled: not a call / return site, or a
// flags window), 5 stale arm reopened (no suspender waiting), 6 Canceled by an EXIT_SCAN flags window, 7 stopped at such a call after
// MRShadowWindowCap of them in a row (termination: a cycle of flags-window calls only; its flags may be undefined, as at the v2 cap),
// 8 accesses performed by the handler on the armed window (flags-window calls, the dispatcher's store into the pushed entry),
// 9 single-instruction steps taken inside flags windows, 10 flags windows stepped through (REGION4-0006).
inline std::atomic<uint64_t> MacRunnerShadowStats[11] {};
// Consecutive flags-window calls not stopped at: the first MRShadowEmulateCap are performed by the handler on the armed window (two
// protection calls each; the callee's return then stops), the next ones up to MRShadowWindowCap reopen the window (Canceled: the thread
// runs to the suspender's next round), then it stops at such a call (termination).
inline constexpr uint32_t MRShadowEmulateCap = 64, MRShadowWindowCap = 128;
inline bool MacRunnerPollOnShadow() {
#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
  static const bool On = [] {
    const char* Value = std::getenv("MACRUNNER_FEX32_POLL_ON_SHADOW");
    const char* Lazy = std::getenv("MACRUNNER_FEX_CALLRET_LAZY");
    return Value && Value[0] == '1' && !Value[1] && Lazy && Lazy[0] == '1' && !Lazy[1];
  }();
  return On;
#else
  return false;
#endif
}
}
