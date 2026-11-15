// SPDX-License-Identifier: MIT
// Modifications (c) 2026 MacRunner contributors, MIT
// ★ MacRunner FEXXFER MACRUNNER_FEX_HEADER_BY_PC (FEXCore/Utils/MacRunnerXfer.h), item 3.
// Every reader of CPUState::InlineJITBlockHeader is given the host PC (or a host address inside the unit) and calls Resolve first:
//   mode 0: nothing (the field is what the last block entry stored, as before);
//   mode 1: the field becomes the unit containing the address (code buffer unit table), 0 when there is none;
//   mode 2: the field is NOT changed; the unit is looked up into a poisoned output and compared with the stored field (probe).
// Why mode 1 gives every reader the block it got before: entries are the only writers, every way into a unit's code passes one
// (direct links, L1, dispatcher, call-return landings - all bound to an entry), so while the PC is inside unit U the stored field
// is U. Where the PC is outside every unit (a C++ helper), the readers only use the field after checking that the PC lies inside
// it (RestoreRIPFromHostPC, both Materialize) or are reached only for PCs inside the code buffer (IsCurrentBlockSingleInst /
// IsAddressInCurrentBlock / GetGuestBlockEntry after IsAddressInCodeBuffer or RestoreRIPFromHostPC), so 0 gives the same result.
// The one reader on a normal path, ExitFunctionLink's compact loop record, is entered from the unit's own loop-dispatcher stub,
// which stores the header itself in mode 1 (cold: once per first link).
#pragma once
#include <cstdint>

namespace FEXCore::Core {
struct InternalThreadState;
}
namespace FEXCore::Context {
class ContextImpl;
}

namespace MRHeaderByPC {
enum Reader : unsigned { RestoreRIP, X87Region, X87Fault, CodeBufferCheck, CompactLoop, UnalignedAtomic, ReaderCount };
// Mode 1 in effect for this context (off while FEX code caching is on: mapped cache units are not in the table).
bool Lazy(FEXCore::Context::ContextImpl* CTX);
void Resolve(FEXCore::Core::InternalThreadState* Thread, uint64_t HostAddress, unsigned Reader) noexcept;
} // namespace MRHeaderByPC
