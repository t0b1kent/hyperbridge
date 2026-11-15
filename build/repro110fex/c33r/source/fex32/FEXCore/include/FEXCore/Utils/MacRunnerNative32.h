// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// ★ MacRunner NATIVE32 13.11.2026 MACRUNNER_FEX32_NATIVE32=<mask of leaf ids> (default 0 = previous code): call folding (L3) of
// the marked i386 Wine leaves (L2 mark, dlls/kernel32/thread.c NATIVE32_LEAF). A `call rel32` / `call [disp32]` (32-bit guest,
// no prefixes) whose target T starts with
//     8B FF                      mov edi, edi            (hot-patch point, as on Windows)
//     0F 1F 84 00 48 42 id 00    nopl 0x00<id>4248(%eax,%eax,1)   (the mark: one 8-byte NOP)
// followed by EXACTLY the body bytes of leaf <id> below is not translated as a call: the call is replaced by IR with the leaf's
// architectural effect (registers, flags, TEB fields, ESP) -- no push of the return address, no unit exit, no return. The block
// layout stays that of a call (the return address remains a block / entry point of the unit), so the fold's fast path falls
// through into it and the slow path -- the ORIGINAL call translation -- returns into it exactly as before. Why it is exact:
//   * the bytes are known, not guessed: the body is compared byte for byte at translation time AFTER the write trap on T's
//     pages is armed, and T's pages join the unit's code pages: a detour / hot patch written over the entry (or any other
//     change of these bytes) invalidates the caller's translation and the next translation sees no mark (no fold);
//   * `call [disp32]` (import table) keeps the load of the slot (same fault as the call) and a compare with T: a slot that
//     points elsewhere (IAT hook) takes the original call;
//   * off the leaf's fast path (TlsGetValue index >= 64) the original call is executed; before it only ecx and the flags of
//     `cmp ecx, 64` were set, which the leaf body sets again identically;
//   * the return-address slot below ESP is not written: dead by the x86 Windows ABI (exception / APC dispatch overwrites
//     memory below ESP at any time). Named consequence: on an unusable stack a folded SetLastError / TlsGetValue faults
//     reading its argument at [esp] -- at the call instruction, registers as before it -- where the call would fault writing
//     [esp - 4]; a folded GetLastError touches no stack;
//   * no suspend point inside a fold (cooperative suspension polls at unit entries and backedges only).
// Mask bits: 1 << (id - 1). Folded: 1 GetLastError, 2 SetLastError, 3 TlsGetValue, 4 FlsGetValue (NATIVE32-0005),
// 5 RtlEnterCriticalSection, 6 RtlLeaveCriticalSection (ntdll i386, NATIVE32-0006 marks; NATIVE32-0007 folds). All = 63.
//
// ★ NATIVE32-0007 (13.11.2026): the critical-section leaves change memory with a locked instruction in the middle, so a path that
// leaves the fold AFTER it cannot be the original call (the increment would happen twice). Such a path continues IN the leaf: the
// return address is pushed and the unit exits, as a call, to the leaf's own label that the x86 jump would reach (contention:
// `jmp native32_enter_cs_contended`; a waiter: `jmp native32_leave_cs_wake`), with the registers and flags the leaf has there.
// The label's offset comes from the template (its rel8 is compared), the bytes at the label are executed as they are. Paths that
// leave before the locked instruction (spin count set, recursion count != 1) take the original call. Fast paths: Enter free and
// Enter recursive by the owner, Leave with recursion 1 and no waiter -- the same loads / stores / locked add, in the same order.
//
// ★ NATIVE32-0005 (13.11.2026, on the c33q stack: REGION4 IMPORT_BIND / THUNK_SKIP, CALLRET4): which guard a fold needs is decided by
// what is known by construction, not checked on every call:
//   * `call rel32` -- the target is in the instruction bytes: no guard;
//   * `call [disp32]` whose slot lies in a read-only image page (an import address table): the slot's value is a constant of the
//     translation exactly as REGION4-0001 binds it (SyscallHandler::QueryGuestConstantData: the page joins this unit's pages and
//     InvalidationTracker drops every translation on it when its protection stops being PAGE_READONLY -- VirtualProtect + write,
//     or a page left writable). Bound by REGION4 (operand already a literal) or queried here when the bind key is off: no guard.
//     The 7 host instructions of the slot guard of 0004 (slot address, load, T, sub, cbnz) are gone;
//   * `call [disp32]` through a writable slot (a function pointer in .data): the guard of 0004 stays (load + compare);
//   * `call eax` within the first 3 instructions after a folded TlsGetValue -- the MSVC 8 CRT `FLS_GETVALUE` shape of _getptd():
//     `call [TlsGetValue]; push [__flsindex]; call eax` -- speculates eax == the FlsGetValue leaf of the module that holds the
//     TlsGetValue leaf (its export, SyscallHandler::MRFindGuestExport, looked up once per process): guard `eax == T` (sub + cbnz);
//     anything else takes the original indirect call. The leaf's bytes are verified and write-trapped as for every fold.
#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace FEXCore::Utils {

constexpr uint32_t MRN32FoldableMask = 0x3F;  // ids 1..6

inline uint32_t MacRunnerNative32Mask() {
  static const uint32_t Mask = [] {
    const char* V = std::getenv("MACRUNNER_FEX32_NATIVE32");
    if (!V || !*V) {
      return 0u;
    }
    char* End = nullptr;
    const unsigned long N = std::strtoul(V, &End, 0);
    return (End && !*End) ? static_cast<uint32_t>(N) & MRN32FoldableMask : 0u;
  }();
  return Mask;
}

constexpr uint8_t MRN32Prefix[8] = {0x8B, 0xFF, 0x0F, 0x1F, 0x84, 0x00, 0x48, 0x42};   // + id, 0x00
constexpr size_t MRN32PrefixSize = 10;

struct MRN32Leaf {
  uint8_t Id;
  uint8_t BodySize;
  uint8_t Body[64];
  uint8_t MidExit {};   // NATIVE32-0007: offset from the entry of the label a post-lock exit continues at (0: none)
};

// Body bytes after the 10-byte prefix, up to and including the fast path's `ret` (kernel32.dll i386, NATIVE32-0003).
inline constexpr MRN32Leaf MRN32Leaves[] = {
  // GetLastError: movl %fs:0x34,%eax; ret
  {1, 7, {0x64, 0xA1, 0x34, 0x00, 0x00, 0x00, 0xC3}},
  // SetLastError: movl 4(%esp),%eax; movl %eax,%fs:0x34; ret $4
  {2, 13, {0x8B, 0x44, 0x24, 0x04, 0x64, 0xA3, 0x34, 0x00, 0x00, 0x00, 0xC2, 0x04, 0x00}},
  // TlsGetValue: movl 4(%esp),%ecx; cmpl $64,%ecx; jae +0x16 (to the tail jmp after ret); movl $0,%fs:0x34;
  //              movl %fs:0xe10(,%ecx,4),%eax; ret $4
  {3, 31, {0x8B, 0x4C, 0x24, 0x04, 0x83, 0xF9, 0x40, 0x73, 0x16, 0x64, 0xC7, 0x05, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x64, 0x8B, 0x04, 0x8D, 0x10, 0x0E, 0x00, 0x00, 0xC2, 0x04, 0x00}},
  // FlsGetValue: movl 4(%esp),%ecx; movl %fs:0xfb4,%edx; leal -1(%ecx),%eax; cmpl $15,%eax; jae +0x1d; testl %edx,%edx; je +0x19;
  //              movl 8(%edx),%eax; testl %eax,%eax; je +4; movl 4(%eax,%ecx,4),%eax; movl $0,%fs:0x34; ret $4   (NATIVE32-0005)
  {4, 48, {0x8B, 0x4C, 0x24, 0x04, 0x64, 0x8B, 0x15, 0xB4, 0x0F, 0x00, 0x00, 0x8D, 0x41, 0xFF, 0x83, 0xF8, 0x0F, 0x73, 0x1D, 0x85, 0xD2, 0x74,
           0x19, 0x8B, 0x42, 0x08, 0x85, 0xC0, 0x74, 0x04, 0x8B, 0x44, 0x88, 0x04, 0x64, 0xC7, 0x05, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0xC2, 0x04, 0x00}},
  // RtlEnterCriticalSection (ntdll, NATIVE32-0002 leaf + 0006 mark): movl 4(%esp),%ecx; cmpl $0,0x14(%ecx); jne +0x2e (slow);
  //   movl %fs:0x24,%edx; lock incl 4(%ecx); jne +0xf; movl %edx,0xc(%ecx); movl $1,8(%ecx); xorl %eax,%eax; ret $4;
  //   cmpl %edx,0xc(%ecx); jne +8 (-> 0x3d: jmp contended); incl 8(%ecx); xorl %eax,%eax; ret $4
  {5, 51, {0x8B, 0x4C, 0x24, 0x04, 0x83, 0x79, 0x14, 0x00, 0x75, 0x2E, 0x64, 0x8B, 0x15, 0x24, 0x00, 0x00, 0x00, 0xF0, 0xFF, 0x41, 0x04,
           0x75, 0x0F, 0x89, 0x51, 0x0C, 0xC7, 0x41, 0x08, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC2, 0x04, 0x00, 0x39, 0x51, 0x0C, 0x75,
           0x08, 0xFF, 0x41, 0x08, 0x31, 0xC0, 0xC2, 0x04, 0x00}, 0x3D},
  // RtlLeaveCriticalSection: movl 4(%esp),%ecx; cmpl $1,8(%ecx); jne +0x19 (slow); movl $0,8(%ecx); movl $0,0xc(%ecx);
  //   lock decl 4(%ecx); jns +0xa (-> 0x32: jmp wake); xorl %eax,%eax; ret $4
  {6, 35, {0x8B, 0x4C, 0x24, 0x04, 0x83, 0x79, 0x08, 0x01, 0x75, 0x19, 0xC7, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x41, 0x0C, 0x00,
           0x00, 0x00, 0x00, 0xF0, 0xFF, 0x49, 0x04, 0x79, 0x0A, 0x31, 0xC0, 0xC2, 0x04, 0x00}, 0x32},
};

constexpr size_t MRN32MaxSize = MRN32PrefixSize + 64;

// The mark alone (10 bytes at P, readable): its id, or 0.
inline uint32_t MRN32MarkId(const uint8_t* P) {
  if (std::memcmp(P, MRN32Prefix, sizeof(MRN32Prefix)) != 0 || P[9] != 0) {
    return 0;
  }
  return P[8];
}

// NATIVE32-0007: offset of the post-lock continuation label of leaf <Id>, or 0.
inline uint32_t MRN32LeafMidExit(uint32_t Id) {
  for (const auto& L : MRN32Leaves) {
    if (L.Id == Id) {
      return L.MidExit;
    }
  }
  return 0;
}

// Total size (prefix + body) of leaf <Id>, or 0 when the id is not known.
inline size_t MRN32LeafSize(uint32_t Id) {
  for (const auto& L : MRN32Leaves) {
    if (L.Id == Id) {
      return MRN32PrefixSize + L.BodySize;
    }
  }
  return 0;
}

// The whole leaf (MRN32LeafSize(Id) bytes at P, readable): true when P is exactly leaf <Id>.
inline bool MRN32LeafMatches(const uint8_t* P, uint32_t Id) {
  if (MRN32MarkId(P) != Id) {
    return false;
  }
  for (const auto& L : MRN32Leaves) {
    if (L.Id == Id) {
      return std::memcmp(P + MRN32PrefixSize, L.Body, L.BodySize) == 0;
    }
  }
  return false;
}

// One folded call site of the unit being translated (filled by the decoder, used by CALLOp / CALLAbsoluteOp).
enum class MRN32Guard : uint8_t {
  None,   // target known by construction: `call rel32`, or a slot of a read-only image page (a const-data page of the unit)
  Slot,   // writable slot: load it (the call's own operand load) and compare with T
  Eax,    // `call eax` speculated on T: compare eax with T
};
struct MRN32Fold {
  uint32_t Id;
  uint64_t Target;    // T, the leaf entry
  uint64_t Slot;      // MRN32Guard::Slot: the slot address; else 0
  uint64_t Size;      // bytes of the leaf compared at translation time
  MRN32Guard Guard {MRN32Guard::None};
};

// counters (line macrunner-fex32-native32 at powers of two of Folds): folds emitted per id, candidates refused (mark seen,
// bytes or key did not allow), slot reads refused by the frontend.
inline std::atomic<uint64_t> MRN32FoldCount {0}, MRN32FoldsById[7] {}, MRN32Refused {0}, MRN32SlotUnreadable {0};
// NATIVE32-0005: folds by guard (none / slot / eax); the FlsGetValue leaf for `call eax` speculation: 0 = not looked up yet,
// 1 = looked up, none, else its address.
inline std::atomic<uint64_t> MRN32FoldsByGuard[3] {}, MRN32FlsHint {0}, MRN32FlsLookupMisses {0};

} // namespace FEXCore::Utils
