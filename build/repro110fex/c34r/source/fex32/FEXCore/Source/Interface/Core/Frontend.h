// SPDX-License-Identifier: MIT
#pragma once

#include "Interface/Core/X86Tables/X86Tables.h"
#include "Interface/IR/IR.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Utils/ThreadPoolAllocator.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/robin_map.h>
#include <FEXCore/Utils/MacRunnerNative32.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace FEXCore::Context {
class ContextImpl;
}
namespace FEXCore::HLE {
enum class SyscallOSABI;
}

namespace FEXCore::Frontend {
class Decoder final {
public:
  enum class DecodedBlockStatus {
    SUCCESS,
    INVALID_INST,
    NOEXEC_INST,
    PARTIAL_DECODE_INST,
    BAD_RELOCATION,
    UNIMPLEMENTED_INST,
  };

  // New Frontend decoding
  struct DecodedBlocks final {
    uint64_t Entry {};
    uint64_t Size {};
    uint64_t NumInstructions {};
    FEXCore::X86Tables::DecodedInst* DecodedInstructions;
    DecodedBlockStatus BlockStatus;
    bool IsEntryPoint {};
    bool ForceFullSMCDetection {};
  };

  struct DecodedBlockInformation final {
    uint64_t TotalInstructionCount;
    bool Is64BitMode {};
    fextl::vector<DecodedBlocks> Blocks;
    fextl::set<uint64_t> EntryPoints;
    fextl::set<uint64_t> CodePages; // Start addresses of all pages touching the block
    fextl::set<uint64_t> MRFlagsDeadCalls; // REGION4 EXIT_SCAN: PCs of CALLs whose target kills every status flag before reading any
    fextl::set<uint64_t> MRWindowEntries;  // REGION4 EXIT_SCAN v2: entry points of this unit that start such a window
    uint64_t MRWindowEntriesUnit {};       // the unit entry the set was computed for (the JIT checks it)
    // ★ MacRunner NATIVE32 (MACRUNNER_FEX32_NATIVE32): folded call sites of this unit, by the address of the CALL.
    fextl::robin_map<uint64_t, FEXCore::Utils::MRN32Fold> Native32Folds;
    struct MRInlineCall {
      uint64_t Target;
      uint64_t Return;
      const FEXCore::X86Tables::DecodedInst* Insts;
      uint32_t Num;
    };
    fextl::map<uint64_t, MRInlineCall> MRInlineCalls;
  };

  Decoder(FEXCore::Core::InternalThreadState* Thread);
  bool CheckIfCacheable(FEXCore::Core::InternalThreadState&, const uint8_t* InstStream, uint64_t PC, uint64_t MaxInst);

  void DecodeInstructionsAtEntry(FEXCore::Core::InternalThreadState* Thread, const uint8_t* InstStream, uint64_t PC, uint64_t MaxInst);

  const DecodedBlockInformation* GetDecodedBlockInfo() const {
    return &BlockInfo;
  }

  uint64_t DecodedMinAddress {};
  uint64_t DecodedMaxAddress {~0ULL};

  void SetExternalBranches(fextl::set<uint64_t>* v) {
    ExternalBranches = v;
  }

  void DelayedDisownBuffer() {
    PoolObject.DelayedDisownBuffer();
  }

  void ResetExecutableRangeCache() {
    ExecutableRangeBase = ExecutableRangeEnd = 0;
    ExecutableRangeNoTrap = false;
  }

  // ★ MacRunner (Claude, 29.09.2026) — MACRUNNER_FEX_RANGE_CACHE: диапазон, запомненный декодером (ответ QueryGuestExecutableRange),
  //   для проверки записываемого кода в GenerateIR без повторного запроса на каждую команду.
  void MRGetCachedRange(uint64_t* Out) const {
    Out[0] = ExecutableRangeBase;
    Out[1] = ExecutableRangeEnd;
    Out[2] = ExecutableRangeWritable;
  }
  // ★ MacRunner (30.09.2026, MACRUNNER_FEX_ALIAS_VIEWS): the cached range is an alias view (ExecutableRangeInfo::NoTrap); Core.cpp then
  //   asks the tracker for every instruction instead of using the cached answer.
  bool MRCachedNoTrap() const {
    return ExecutableRangeNoTrap;
  }

private:
  // To pass any information from instruction prefixes
  // down into the actual instruction handling machinery.
  struct DecodedHeader {
    uint8_t vvvv; // Encoded operand in a VEX prefix.
    bool w;       // VEX.W bit.
    bool L;       // VEX.L bit (if set then 256 bit operation, if unset then scalar or 128-bit operation)
  };

  FEXCore::Core::InternalThreadState* Thread;
  FEXCore::Context::ContextImpl* CTX;
  const FEXCore::HLE::SyscallOSABI OSABI {};

  FEX_CONFIG_OPT(EnableCodeCacheValidation, ENABLECODECACHEVALIDATION);

  DecodedBlockStatus DecodeInstructionImpl(uint64_t PC);
  DecodedBlockStatus DecodeInstruction(uint64_t PC);

  void BranchTargetInMultiblockRange();
  void MRBindImport(); // REGION4 MACRUNNER_FEX32_IMPORT_BIND
  uint32_t MRFollowThunks(uint32_t Target); // REGION4-0003 MACRUNNER_FEX32_THUNK_SKIP
  void MRScanCallTarget(); // REGION4 MACRUNNER_FEX32_EXIT_SCAN
  bool MRTargetKillsFlags(uint64_t Target, bool CountStats = true);
  bool IsBranchMonoTailcall(uint64_t NumInstructions) const;
  bool InstCanContinue() const;

  void AddBranchTarget(uint64_t Target);

  // CALLRET4: the callee of the CALL in DecodeInst is a straight-line leaf -> record it for translation in place (true = taken).
  bool MRTryInlineCall(uint64_t InstEnd);
  // CALLRET4: decodes a straight-line leaf starting at Target into the free slots of the decode buffer; number of instructions
  // including the final `ret`, 0 if it is not such a leaf within Budget instructions. DecodedSize is left unchanged.
  uint32_t MRScanLeaf(uint64_t Target, unsigned Budget);
  void MRAddCodePage(uint64_t Page);
  const uint8_t* MREntryStream {};

  bool CheckRangeExecutable(uint64_t Address, uint64_t Size);

  uint8_t ReadByte();
  std::optional<uint8_t> PeekByte(uint8_t Offset);
  std::pair<uint64_t, bool> ReadData(uint8_t Size);

  void SkipBytes(uint8_t Size) {
    InstructionSize += Size;
  }

  DecodedBlockStatus NormalOp(const FEXCore::X86Tables::X86InstInfo* Info, uint16_t Op, DecodedHeader Options = {});
  DecodedBlockStatus NormalOpHeader(const FEXCore::X86Tables::X86InstInfo* Info, uint16_t Op);

  void DecodeREXIfValid(int8_t ExpectedOffset = -1);

  static constexpr size_t DefaultDecodedBufferSize = 0x10000;
  FEXCore::X86Tables::DecodedInst* DecodedBuffer {};
  Utils::PoolBufferWithTimedRetirement<FEXCore::X86Tables::DecodedInst*, 5000, 500> PoolObject;
  size_t DecodedSize {};

  uint64_t ExecutableRangeBase {};
  uint64_t ExecutableRangeEnd {};
  bool ExecutableRangeWritable {};
  bool ExecutableRangeNoTrap {};
  bool HitNonExecutableRange {};
  bool HitBadRelocation {};

  struct DecodeStream {
    // Original instruction stream RIP location.
    const uint8_t* InstStream;

    // Adjusted location for FEX actually decodes from.
    const uint8_t* AdjustedInstStream;

    DecodeStream& operator-=(size_t offset) noexcept {
      InstStream -= offset;
      AdjustedInstStream -= offset;
      return *this;
    }

    DecodeStream& operator+=(size_t offset) noexcept {
      InstStream += offset;
      AdjustedInstStream += offset;
      return *this;
    }
  };

  DecodeStream InstStream;
  IR::OpSize GetGPROpSize() const {
    return BlockInfo.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit;
  }

  static constexpr size_t MAX_INST_SIZE = 15;
  uint8_t InstructionSize {};
  std::array<uint8_t, MAX_INST_SIZE> Instruction;
  uint8_t LastEscapePrefix {};
  FEXCore::X86Tables::DecodedInst* DecodeInst;

  // This is for multiblock data tracking
  uint64_t EntryPoint {};
  uint64_t MaxCondBranchForward {};
  uint64_t MaxCondBranchBackwards {~0ULL};
  uint64_t SectionMaxAddress {~0ULL};
  uint64_t SectionMinAddress {};
  uint64_t NextBlockStartAddress {~0ULL};

  DecodedBlockInformation BlockInfo;
  fextl::set<uint64_t> CurrentBlockTargets;
  fextl::set<uint64_t> BlocksToDecode;
  fextl::set<uint64_t> VisitedBlocks;
  fextl::set<uint64_t>* ExternalBranches {nullptr};

  const fextl::robin_map<uint32_t, GuestRelocationType>* Relocations {nullptr};

  // ModRM rm decoding
  using DecodeModRMPtr = void (FEXCore::Frontend::Decoder::*)(X86Tables::DecodedOperand* Operand, X86Tables::ModRMDecoded ModRM);
  void DecodeModRM_16(X86Tables::DecodedOperand* Operand, X86Tables::ModRMDecoded ModRM);
  void DecodeModRM_64(X86Tables::DecodedOperand* Operand, X86Tables::ModRMDecoded ModRM);

  static constexpr std::array<DecodeModRMPtr, 2> DecodeModRMs_Disp {
    &FEXCore::Frontend::Decoder::DecodeModRM_64,
    &FEXCore::Frontend::Decoder::DecodeModRM_16,
  };

  const std::array<X86Tables::X86InstInfo, X86Tables::MAX_X87_TABLE_SIZE>* X87Table;

  const std::array<X86Tables::X86InstInfo, X86Tables::MAX_VEX_TABLE_SIZE>* VEXTable {};
  const std::array<X86Tables::X86InstInfo, X86Tables::MAX_VEX_GROUP_TABLE_SIZE>* VEXTableGroup {};

  const DecodeStream AdjustAddrForSpecialRegion(const uint8_t* _InstStream, uint64_t EntryPoint, uint64_t RIP);
};
} // namespace FEXCore::Frontend
