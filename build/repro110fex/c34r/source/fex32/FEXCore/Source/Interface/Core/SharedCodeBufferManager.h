// SPDX-License-Identifier: MIT
/*
$info$
category: Thread shared code buffer management
tags: backend|shared
$end_info$
*/
#pragma once

#include <FEXCore/fextl/memory.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace FEXCore {
struct GuestToHostMap;
}

namespace FEXCore::CPU {
struct CodeBuffer {
  uint8_t* Ptr;
  size_t AllocatedSize; // including guard page; see UsableSize()

  fextl::unique_ptr<GuestToHostMap> LookupCache;

  // ★ MacRunner FEXXFER MACRUNNER_FEX_HEADER_BY_PC (MacRunnerXfer.h): begins of the compiled units of this buffer, (offset >> 4),
  // appended in increasing order under CodeBufferWriteMutex right after the unit's bytes are copied; the count is published with a
  // release store, so a reader (any thread, also an exception handler) sees only complete entries. Buffers are never reused from
  // offset 0 (a new generation is a new CodeBuffer), so the table is append-only for its whole life. Null with the key 0.
  uint32_t* MRUnitBegins {};
  size_t MRUnitCapacity {};
  std::atomic<size_t> MRUnitCount {0};
  void MRRecordUnit(uint64_t Offset);
  // Begin of the unit whose [header, header + tail Size) contains Address, or 0.
  uint64_t MRFindUnit(uintptr_t Address) const;

  CodeBuffer(size_t Size);
  CodeBuffer(const CodeBuffer&) = delete;
  CodeBuffer& operator=(const CodeBuffer&) = delete;
  CodeBuffer(CodeBuffer&& oth) = delete;
  CodeBuffer& operator=(CodeBuffer&&) = delete;

  ~CodeBuffer();

  /// Returns the number of bytes available for storing code
  size_t UsableSize() const {
    return AllocatedSize - FEXCore::Utils::JITGuardPageSize();
  }
};

/**
 * A manager that coordinates access to the CodeBuffer used for compiling new code across threads.
 *
 * The CodeBuffer is managed as a partially persistent data structure:
 * - Exactly one CodeBuffer is now designated as "active", which means data can be appended to it
 * - Lossy modifications to the active CodeBuffer will not invalidate any data in use by other threads (which is what enables save CodeBuffer sharing across threads)
 * - Instead, such lossy modifications trigger a new "version" of the data in the modifying thread. Old versions of the CodeBuffer persist as read-only data for use by the other threads.
 * - The other threads can update their version of the CodeBuffer. This will decrease the reference count and eventually trigger deallocation of the old version
 */
class SharedCodeBufferManager {
public:
  // Get the CodeBuffer that was most recently allocated.
  // This is the only CodeBuffer that data may be written to.
  fextl::shared_ptr<CodeBuffer> GetLatest();

  // Allocate a new CodeBuffer with geometric growth up to an internal maximum.
  // Subsequent calls to GetLatest will point to the returned buffer.
  fextl::shared_ptr<CodeBuffer> StartLargerCodeBuffer();

  // Allocate a new CodeBuffer with maximum internal size.
  // Subsequent calls to GetLatest will point to the returned buffer.
  fextl::shared_ptr<CodeBuffer> StartMaximalCodeBuffer();

  // Write offset into the latest CodeBuffer
  std::size_t LatestOffset {};

  // Protects writes to the latest CodeBuffer and changes to LatestOffset
  FEXCore::ForkableUniqueMutex CodeBufferWriteMutex;

  // ★ CALLRET4 MACRUNNER_FEX_CODEBUF_KEEP: full buffers kept alive (never freed). Written under CodeBufferWriteMutex: slot first,
  // then the count with a release store; readers (any thread, exception handlers) load the count with acquire, read [0, count).
  static constexpr uint32_t MRKeptMax = 8;
  fextl::shared_ptr<CodeBuffer> MRKept[MRKeptMax];
  std::atomic<uint32_t> MRKeptCount {0};

  virtual void OnCodeBufferAllocated(const std::shared_ptr<CodeBuffer>&) {};

private:
  fextl::shared_ptr<CodeBuffer> Latest;

  fextl::shared_ptr<CodeBuffer> AllocateNew(size_t Size);
};
} // namespace FEXCore::CPU
