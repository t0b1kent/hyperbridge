// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// LAZY-FLAGS X87-CTX P5 (MACRUNNER_FEX_X87_FAULT_STATE): fault-time restoration of the x87 stack state that the x87 stack pass
// keeps in SSA values (pushed values, TOP, tags) until the block exit. One record per guest-memory op that starts with such
// pending state; it lives in the block tail after the RIP entries (and after the X87Region extension when present). Nothing is
// emitted into the code path.
#pragma once
#include <cstdint>
#include <FEXCore/Utils/CompilerDefs.h>

namespace FEXCore::Core {
struct CpuStateFrame;
namespace X87Fault {
inline constexpr uint32_t Magic = 0x46373858; // X87F
inline constexpr uint16_t Version = 1;
inline constexpr uint8_t TailFlag = 0x5f;    // JITCodeTail::_Pad[2]
// Records per compiled unit (one per guest memory op with pending x87 state). 4096 dropped records silently in units with more such
// ops (TRANS32 08.11, stand/x87rec32.c); a unit is at most MaxInst instructions (default 5000), a few memory ops each.
inline constexpr uint32_t MaxRecords = 65536;
// Location of one value at the faulting op. Kind in bits 14..15.
enum LocKind : uint16_t { LocNone = 0, LocQ = 1U << 14, LocX = 2U << 14, LocSpill = 3U << 14 };
enum ModeBits : uint8_t { Slow = 1, Values64 = 2, TopPending = 4, TopConstant = 8, TopRelative = 32 }; // 16 is TRANS32 PCXValues
// TopRelative (MACRUNNER_FEX_X87_FAULT_COVER): slow path, TOP = (CPUState TOP - (int8_t)TopOffset) & 7, no TOP value to read.
struct Header {
  uint32_t MagicValue;
  uint16_t VersionValue;
  uint16_t RecordBytes;
  uint32_t Count;
  uint32_t Bytes;          // header + records
  uint32_t SpillSlotBytes; // host stack bytes per spill slot
  uint32_t Reserved;
};
struct Record {
  uint32_t HostBegin;  // offset from the block begin: [HostBegin, HostEnd) is the op (and the fills RA put before it)
  uint32_t HostEnd;
  uint8_t Mode;
  uint8_t TopOffset;   // fast path: TOP = (CPUState TOP - (int8_t)TopOffset) & 7
  uint8_t ValueMask;   // ST(i) whose value is pending, i relative to the new TOP
  uint8_t ValidMask;   // tags to set
  uint8_t InvalidMask; // tags to clear
  uint8_t Reserved;
  uint16_t Top;        // slow path, TopPending: location of TOP (or the constant with TopConstant)
  uint16_t Values[8];
};
static_assert(sizeof(Header) == 24 && sizeof(Record) == 32);

// Called during state reconstruction for a fault at HostPC in the current block, before exporting the context and only on a
// path that leaves the block (exception delivery, or a restart through the dispatcher). Writes the pending x87 state into
// Frame->State. Returns true when a record applied; false leaves the state untouched.
FEX_DEFAULT_VISIBILITY bool Materialize(CpuStateFrame* Frame, uint64_t HostPC, const uint64_t* HostGPRs, const __uint128_t* HostQ,
                                        uint64_t HostSP) noexcept;
} // namespace X87Fault
} // namespace FEXCore::Core
