// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// ★ MacRunner FEXXFER (03.11.2026): cheaper control transfers in translated code. Every key defaults to 0 = the previous
// emitted code byte for byte; read once during IR passes / code generation, never from a signal handler.
// ★ TRANS32 07.11.2026: this tree builds the WOW64 translator (xtajit.dll) and its 32-bit native stands; CMP_ZC, RET_NOPOLL and
// HEADER_BY_PC are read there too, under their own names MACRUNNER_FEX32_CMP_ZC / _RET_NOPOLL / _HEADER_BY_PC (independent of the
// 64-bit keys; default 0 = previous code). RIP_LITERAL stays ARM64EC only: a 32-bit guest RIP never needs more than movz+movk.
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdlib>

namespace FEXCore::Utils {
namespace MRXferDetail {
inline unsigned ReadMask(const char* Name, unsigned Max) {
  const char* Value = std::getenv(Name);
  if (!Value || Value[0] < '0' || Value[0] > '9' || Value[1]) {
    return 0;
  }
  const unsigned V = static_cast<unsigned>(Value[0] - '0');
  return V <= Max ? V : 0;
}
} // namespace MRXferDetail

// MACRUNNER_FEX_CMP_ZC=1 (item 1): an 8/16-bit compare (SubNZCV) whose live flags are only ZF/CF and whose operands are a
// zero-extending load of that width and a constant / another such load is emitted as a 32-bit compare: `ldrb; cmp w, #imm`
// instead of `mov w, #imm; ldrb; lsl #24; cmp w, w, lsl #24`. ZF and CF of the two forms are equal for zero-extended
// operands; SF/OF are not, so the rewrite needs N and V dead (the flag pass's own liveness, which already treats every unit
// exit, suspend edge and - with MACRUNNER_FEX_PRECISE_MEM_FLAGS=1 - every guest memory access as reading all flags).
inline bool MacRunnerCmpZCEnabled() {
#if 1   // TRANS32: every build of this tree
  static const bool On = MRXferDetail::ReadMask("MACRUNNER_FEX32_CMP_ZC", 1) == 1;
  return On;
#else
  return false;
#endif
}

// ★ REGION4 13.11.2026 MACRUNNER_FEX32_IMPORT_BIND=<mask>: 1 = `call dword ptr [abs32]`, 2 = `jmp dword ptr [abs32]` whose slot is in a
// read-only non-executable image page (an import address table) are translated as a direct call / jump to the slot's value.
// The page becomes a page of the unit; the frontend invalidates on any protection change away from PAGE_READONLY and on free.
// ★ REGION4 13.11.2026 MACRUNNER_FEX32_EXIT_SCAN=1: a CALL whose target (direct, or bound by IMPORT_BIND) provably overwrites every
// status flag before reading any does not materialise the caller's flags (Decoder::MRTargetKillsFlags). Off with
// MACRUNNER_FEX_REVIVE=1 for the same reason as IMPORT_BIND: the caller's own bytes do not cover the callee's.
inline std::atomic<uint64_t> MacRunnerExitScanDead {0}, MacRunnerExitScanLive {0};
// Why a scan ended live: 0 = bytes not executable / past 4 GB, 1 = writable code range, 2 = first instruction not listed, 3 = a later one.
inline std::atomic<uint64_t> MacRunnerExitScanWhy[4] {};
// v2 (precise suspend): window entry polls emitted; suspend faults at them skipped (entered by a call), not skipped (no call /
// cap), skipped at the dispatcher poll.
inline std::atomic<uint64_t> MacRunnerExitScanWindowPolls {0}, MacRunnerExitScanSkips {0}, MacRunnerExitScanNoSkip {0}, MacRunnerExitScanDispSkips {0};
inline unsigned MacRunnerExitScanMask() {
  static const unsigned Mask = [] {
    const char* Revive = std::getenv("MACRUNNER_FEX_REVIVE");
    return Revive && Revive[0] == '1' && !Revive[1] ? 0u : MRXferDetail::ReadMask("MACRUNNER_FEX32_EXIT_SCAN", 1);
  }();
  return Mask;
}

// Counters for the macrunner-fex-jit line: slots bound as call / jmp, slots refused by the frontend, pages dropped by a notification.
inline std::atomic<uint64_t> MacRunnerImportBound[2] {}, MacRunnerImportRefused {0}, MacRunnerConstDataDrops {0};
// Not with MACRUNNER_FEX_REVIVE=1: a revived translation is matched by the hash of its own code bytes, which does not cover the slot.
// ★ REGION4-0003 13.11.2026 MACRUNNER_FEX32_THUNK_SKIP=1: a direct call or a bound call / jump whose target is an import thunk
// (`jmp dword ptr [abs32]` with the slot in a read-only image page) goes to the thunk's target (Decoder::MRFollowThunks). Off with
// MACRUNNER_FEX_REVIVE=1 for the same reason as IMPORT_BIND.
inline std::atomic<uint64_t> MacRunnerThunkSkipped {0}, MacRunnerThunkRefused {0};
inline bool MacRunnerThunkSkip() {
  static const bool On = [] {
    const char* Revive = std::getenv("MACRUNNER_FEX_REVIVE");
    return !(Revive && Revive[0] == '1' && !Revive[1]) && MRXferDetail::ReadMask("MACRUNNER_FEX32_THUNK_SKIP", 1) == 1;
  }();
  return On;
}

inline unsigned MacRunnerImportBindMask() {
  static const unsigned Mask = [] {
    const char* Revive = std::getenv("MACRUNNER_FEX_REVIVE");
    return Revive && Revive[0] == '1' && !Revive[1] ? 0u : MRXferDetail::ReadMask("MACRUNNER_FEX32_IMPORT_BIND", 3);
  }();
  return Mask;
}

// MACRUNNER_FEX_RIP_LITERAL=<mask> (item 2): guest-RIP constants (EntrypointOffset) that need three or four mov/movk are
// loaded from a PC-relative literal in the unit (one `ldr x, lit`, relocation RELOC_GUEST_RIP_LITERAL as the existing
// literals): 1 = the return address pushed by CALL, 2 = every other such constant (RIP-relative data addresses).
inline unsigned MacRunnerRipLiteralMask() {
#ifdef ARCHITECTURE_arm64ec
  static const unsigned Mask = MRXferDetail::ReadMask("MACRUNNER_FEX_RIP_LITERAL", 3);
  return Mask;
#else
  return 0;
#endif
}

// MACRUNNER_FEX_RET_NOPOLL=1 (item 4, first step): a block that is the return block of a CALL in the same unit is laid out
// without the suspend poll inline: the call-return-stack landing (and the fall-through after `bl`) enters header + spill +
// body; every other entry (L1, block links, dispatcher) goes through an out-of-line entry stub that stores the header,
// allocates the spill area, polls exactly as the inline entry did, and branches into the body. No branch is added on the
// return path (MACRUNNER_FEX_RET_LANDING added one and gained nothing). Suspend latency stays bounded: an unpolled landing
// needs a matching call-return-stack entry, i.e. a prior CALL through a polled entry; the run of consecutive unpolled
// landings is at most the call-return-stack depth, and loops inside bodies keep their backedge polls.
inline bool MacRunnerRetNoPollEnabled() {
#if 1   // TRANS32: every build of this tree
  static const bool On = MRXferDetail::ReadMask("MACRUNNER_FEX32_RET_NOPOLL", 2) != 0;   // PARITY32: 2 = the unpublished form
  return On;
#else
  return false;
#endif
}
// MACRUNNER_FEX_HEADER_BY_PC=<mode> (item 3): 1 = block entries no longer store InlineJITBlockHeader (`adr; str [x28]`, 2 per entry);
// every reader resolves the unit from the host PC through the code buffer's unit table (MRHeaderByPC.h) on its own rare path.
// 2 = probe only: entries keep the store, every reader ALSO resolves and compares (same / diff / no unit / poison / control) and
// prints macrunner-fex-header-probe lines; the emitted code is that of mode 0. Mode 1 stays off while FEX code caching is on
// (mapped cache units are not in the table).
inline unsigned MacRunnerHeaderByPCMode() {
#if 1   // TRANS32: every build of this tree
  static const unsigned Mode = MRXferDetail::ReadMask("MACRUNNER_FEX32_HEADER_BY_PC", 2);
  return Mode;
#else
  return 0;
#endif
}
// ★ PARITY32 12.11.2026 MACRUNNER_FEX32_HOT_FALLTHROUGH=<mask> (default 0 = previous code): the 32-bit form of the 64-bit
// MACRUNNER_FEX_HOT_FALLTHROUGH bits 2 and 4. 2 = return: a call-return-stack hit falls through to `ret`; a miss goes through a
// 4-instruction stub to one shared L1 probe in the dispatcher (no inline probe at the site). 4 = indirect jmp / call: an L1 hit
// falls through, a miss is out of line. Bit 1 (entry poll) is ignored: the WOW64 poll is a store without a branch.
inline unsigned MacRunnerHotFallthrough32Mask() {
  static const unsigned Mask = MRXferDetail::ReadMask("MACRUNNER_FEX32_HOT_FALLTHROUGH", 7) & 6;
  return Mask;
}
// ★ PARITY32 12.11.2026 MACRUNNER_FEX32_ICALL_IC (default 0 = previous code): inline target cache of an indirect CALL with a
// known return block (the idea of MACRUNNER_FEX_ICALL_IC, relaid for the 32-bit translator). v2: the cache is ONE 64-bit literal
// per site, {guest target : 32, host offset from the site's return point : 32}, read by a single load:
//   adr; stp (call-return entry); ldr x pair; sub w (guest half - target); cbnz miss; add host = return point + offset; blr
// so the check and the branch target always come from the same value: the pair is rewritten atomically (no code is patched), which
// makes RE-TAGGING safe. A site whose target changed is re-tagged on a sampled miss (one miss in 64 reaches the linker); a site that
// flips faster than re-tagging pays (four re-tags in a row each sooner than ~3 us after the previous one) is frozen on its current
// target: that target still hits, the others take the shared L1 path, and one miss in 4096 is a vote to thaw it (the same new target
// twice in a row). Off with far jumps and FEX code caching.
// 1 = every such site; 2 = only sites whose target is loaded from an absolute address (`call [disp32]`: import table, global function
// pointer -- one target by construction), so a polymorphic `call reg` / `call [reg + ...]` keeps the plain L1 path.
inline unsigned MacRunnerICallIC32Mode() {
  static const unsigned Mode = MRXferDetail::ReadMask("MACRUNNER_FEX32_ICALL_IC", 2);
  return Mode;
}
inline bool MacRunnerICallIC32Enabled() {
  return MacRunnerICallIC32Mode() != 0;
}
// ★ PARITY32 12.11.2026 MACRUNNER_FEX32_RET_NOPOLL form: 1 = TRANS32 (the return block's published entry is an out-of-line stub:
// header, spill area, poll, branch into the body: +1 instruction per return block on WOW64 with HEADER_BY_PC, more without);
// 2 = a return block that is not the unit's own entry gets NO published entry point: no stub and no poll (-1 instruction per
// return block against key 0). It is reached only through its call-return-stack landing and the fall-through after the call;
// every other transfer to that guest address (return miss, indirect branch, a direct branch from another unit) finds no block
// and compiles a unit of its own with the ordinary polled entry. Suspend latency is bounded as in form 1: a landing needs a
// matching CALL, the CALL entered its target through a polled entry, loops inside bodies keep their backedge polls.
inline unsigned MacRunnerRetNoPollMode() {
  static const unsigned Mode = MRXferDetail::ReadMask("MACRUNNER_FEX32_RET_NOPOLL", 2);
  return Mode;
}
// ★ CALLRET4 12.11.2026 MACRUNNER_FEX32_STACK_ENGINE=1 (default 0 = previous code): software stack engine. x86 cores rename the
// stack pointer in push / pop / call / ret (stack engine); ARM64 write-back forms (`str w, [x8, #-4]!`, `ldr w, [x8], #4`) make every
// one of them a 1-cycle link of ONE serial chain through the guest ESP register. With the key, inside an IR block a run of two or
// more such steps is addressed from a copy of ESP taken at the start of the run (x19, removed from the allocator's set):
//   push:  stur w, [x19, #d-4] ; sub w8, w19, #-(d-4)        pop:  ldur w, [x19, #d] ; add w8, w19, #(d+4)
//   add / sub esp, imm:  add w8, w19, #(d +/- imm)             ret imm (pop through a copy of ESP): the same from x19
// INVARIANT: x8 holds the architectural ESP before and after every guest instruction, and inside a push / pop exactly as the
// write-back form does (the memory access first, the new ESP after it: an access that faults leaves ESP unchanged). x19 is only an
// alternative base for addresses; nothing reads it but this code, a run never crosses an IR block, a helper call or any operation
// outside a short list of plain ones. So every exit (fault, suspend, context capture, block exit, SMC exit) sees ESP in x8 as before.
// Value: 1 = a run starts at two or more steps ahead in the block, 2 = at three or more, 3 = at four or more (fewer added
// instructions, fewer links removed).
inline unsigned MacRunnerStackEngine32Min() {
  static const unsigned Min = [] {
    const unsigned V = MRXferDetail::ReadMask("MACRUNNER_FEX32_STACK_ENGINE", 4);
    return V ? V + 1 : 0u;
  }();
  return Min;
}
// Value 4 = FOLDED form, no added instructions and no second register: a run of pushes addresses its slots from the ESP of its
// start (`stur w, [x8, #-4k]`) and its LAST push carries the whole update (`str w, [x8, #-D]!`); a run of pops makes the whole
// update with its FIRST pop (`ldr w, [x8], #D`) and reads the others below the new ESP (`ldur w, [x8, #-(D-4k)]`); `ret imm` and
// a trailing `add esp, imm` are part of D. Inside such a run x8 is NOT the architectural ESP; the only place that can look there
// is a fault on one of the run's own accesses (nothing else that can fault, read ESP or leave the block is allowed inside a run),
// and that access tells the difference by its form: an access through x8 with a NEGATIVE offset and no write-back is emitted by
// nothing else (ordinary guest accesses below ESP go through a temporary), so the reconstruction (MRStackFoldDelta, called where
// the guest context is rebuilt from the host one) adds: store -> offset + bytes stored, load -> offset.
inline bool MacRunnerStackFold32() {
  return MacRunnerStackEngine32Min() == 5;
}
inline bool MacRunnerStackEngine32() {
  return MacRunnerStackEngine32Min() != 0;
}
// ★ CALLRET4 13.11.2026 MACRUNNER_FEX32_SLOT_FORWARD (default 0 = previous code): store-to-load forwarding of stack slots inside an
// IR block (pass MRSlotForward, after the x87 pass, before register allocation). A slot is an address `register value + constant`
// (ESP at some point of the block, or another guest register: EBP frames); a StoreMem / Push to it records (value, size, class); a
// later LoadMem of exactly that slot, size and class takes the value from the register instead of memory (GPR: zero-extending
// move of the stored width, FPR: VMov of the stored width). The store itself is never removed, memory is always written.
// What forgets the recorded slots:
//   a store through an address that is not `the same register value + constant` (it may alias), a store that overlaps,
//   any operation that can write guest memory or leave to other code (atomics, MemSet / MemCpy, syscall, thunk, CPUID, fence ...);
//   value 1 (strict): additionally every operation that can raise a guest exception between the store and the load (any other
//     guest memory access, a division): an exception handler that rewrites the slot and resumes is then still observed;
//   value 2: other loads and non-overlapping stores through the same register value do not forget (a handler rewriting the
//     slot of the faulting frame between the store and the load of ONE block would not be observed).
// Another thread writing the slot between the store and the load: reading one's own store is what an x86 store buffer does (TSO),
// and operations that drain the store buffer (locked operations, fences) forget the slots.
inline unsigned MacRunnerSlotForward32() {
  static const unsigned Level = MRXferDetail::ReadMask("MACRUNNER_FEX32_SLOT_FORWARD", 2);
  return Level;
}
// counters of the pass: loads forwarded (GPR, FPR), loads of a recorded slot with another size or class (not forwarded)
inline std::atomic<uint64_t> MRSFwdGPR {0}, MRSFwdFPR {0}, MRSFwdMismatch {0}, MRSFwdStores {0}, MRSFwdHeld {0}, MRSFwdSkipped {0}, MRSFwdConv {0}, MRSFwdFloatHeld {0};
// diagnostic: the operation that first uses a load that was NOT forwarded because its value is no longer in a register (index: IR op)
inline std::atomic<uint32_t> MRSFwdSkipUser[512] {};
// A forwarded value must still be in a register at the load. It is there for free when it has a later use anyway or when it is a
// guest register that is not rewritten in between; otherwise the register allocator has to hold it longer (copies, spills in a
// block that is short of registers). MACRUNNER_FEX32_SLOT_FORWARD_HOLD=N (0..9, default 0): such a load is forwarded only when it
// is at most 4*N IR operations after the store.
inline unsigned MacRunnerSlotForward32Hold() {
  static const unsigned Hold = MRXferDetail::ReadMask("MACRUNNER_FEX32_SLOT_FORWARD_HOLD", 9) * 4;
  return Hold;
}
// counters (line macrunner-fex32-stack-engine at powers of two of Runs): runs started, steps emitted from the base, re-bases
// (offset out of range), single steps left in the write-back form.
inline std::atomic<uint64_t> MRSERuns {0}, MRSESteps {0}, MRSERebases {0}, MRSESingles {0};
// IR operations that ended an open run (index = IR op), for the diagnostic line
inline std::atomic<uint32_t> MRSEEndOps[512] {};
} // namespace FEXCore::Utils
