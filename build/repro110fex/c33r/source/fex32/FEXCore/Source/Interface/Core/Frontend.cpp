// SPDX-License-Identifier: MIT
/*
$info$
tags: frontend|x86-meta-blocks
desc: Extracts instruction & block meta info, frontend multiblock logic
$end_info$
*/

#include "Interface/Context/Context.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include "Interface/Core/LookupCache.h"

#include <array>
#include <algorithm>
#include <cstring>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MacRunnerXfer.h>
#include <FEXCore/Utils/MacRunnerExitScan.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/Telemetry.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/fextl/set.h>

namespace FEXCore::Frontend {
#include "Interface/Core/VSyscall/VSyscall.inc"

using namespace FEXCore::X86Tables;

static uint32_t MapModRMToReg(uint8_t REX, uint8_t bits, bool HighBits, bool HasREX, bool HasXMM, bool HasMM, uint8_t InvalidOffset = 16) {
  using GPRArray = std::array<uint32_t, 16>;

  static constexpr GPRArray GPR8BitHighIndexes = {
    // Classical ordering?
    FEXCore::X86State::REG_RAX, FEXCore::X86State::REG_RCX, FEXCore::X86State::REG_RDX, FEXCore::X86State::REG_RBX,
    FEXCore::X86State::REG_RAX, FEXCore::X86State::REG_RCX, FEXCore::X86State::REG_RDX, FEXCore::X86State::REG_RBX,
    FEXCore::X86State::REG_R8,  FEXCore::X86State::REG_R9,  FEXCore::X86State::REG_R10, FEXCore::X86State::REG_R11,
    FEXCore::X86State::REG_R12, FEXCore::X86State::REG_R13, FEXCore::X86State::REG_R14, FEXCore::X86State::REG_R15,
  };

  uint8_t Offset = (REX << 3) | bits;

  if (Offset == InvalidOffset) {
    return FEXCore::X86State::REG_INVALID;
  }

  if (HasXMM) {
    return FEXCore::X86State::REG_XMM_0 + Offset;
  } else if (HasMM) {
    return FEXCore::X86State::REG_MM_0 + bits; // Ignore REX extension for MMX registers
  } else if (!(HighBits && !HasREX)) {
    return FEXCore::X86State::REG_RAX + Offset;
  }

  return GPR8BitHighIndexes[Offset];
}

static uint32_t MapVEXToReg(uint8_t vvvv, bool HasXMM) {
  if (HasXMM) {
    return FEXCore::X86State::REG_XMM_0 + vvvv;
  } else {
    return FEXCore::X86State::REG_RAX + vvvv;
  }
}

Decoder::Decoder(FEXCore::Core::InternalThreadState* Thread)
  : Thread {Thread}
  , CTX {static_cast<FEXCore::Context::ContextImpl*>(Thread->CTX)}
  , OSABI {CTX->SyscallHandler ? CTX->SyscallHandler->GetOSABI() : FEXCore::HLE::SyscallOSABI::OS_UNKNOWN}
  , PoolObject {CTX->FrontendAllocator, sizeof(FEXCore::X86Tables::DecodedInst) * DefaultDecodedBufferSize} {

  FEX_CONFIG_OPT(ReducedPrecision, X87REDUCEDPRECISION);
  if (ReducedPrecision) {
    X87Table = &FEXCore::X86Tables::X87F64Ops;
  } else {
    X87Table = &FEXCore::X86Tables::X87F80Ops;
  }

  if (CTX->HostFeatures.SupportsAVX && CTX->HostFeatures.SupportsSVE256) {
    VEXTable = &FEXCore::X86Tables::VEXTableOps;
    VEXTableGroup = &FEXCore::X86Tables::VEXTableGroupOps;
  } else if (CTX->HostFeatures.SupportsAVX) {
    VEXTable = &FEXCore::X86Tables::VEXTableOps_AVX128;
    VEXTableGroup = &FEXCore::X86Tables::VEXTableGroupOps_AVX128;
  }
}

bool Decoder::CheckRangeExecutable(uint64_t Address, uint64_t Size) {
  // Check for wraparound
  if (Address + Size < Address) {
    return false;
  }

  while (Address < ExecutableRangeBase || Address + Size > ExecutableRangeEnd) {
    auto RangeInfo = CTX->SyscallHandler->QueryGuestExecutableRange(Thread, Address);
    ExecutableRangeBase = RangeInfo.Base;
    ExecutableRangeEnd = RangeInfo.Base + RangeInfo.Size;
    ExecutableRangeWritable = RangeInfo.Writable;
    ExecutableRangeNoTrap = RangeInfo.NoTrap;

    if (RangeInfo.Size == 0) {
      return false;
    }

    uint64_t RangeRemainingSize = ExecutableRangeEnd - Address;
    if (Size > RangeRemainingSize) {
      Size -= RangeRemainingSize;
      Address += RangeRemainingSize;
    }
  }

  return true;
}

uint8_t Decoder::ReadByte() {
  std::optional<uint8_t> Byte = PeekByte(0);
  if (!Byte || InstructionSize == MAX_INST_SIZE) {
    HitNonExecutableRange = true;
    // Pretend we read 0, the main decode loop will see HitNonExecutableRange and rollback the instruction.
    return 0;
  }

  Instruction[InstructionSize] = *Byte;
  InstructionSize++;
  return *Byte;
}

std::optional<uint8_t> Decoder::PeekByte(uint8_t Offset) {
  uint64_t ByteAddress = reinterpret_cast<uint64_t>(InstStream.InstStream + InstructionSize + Offset);
  if (CheckRangeExecutable(ByteAddress, 1)) {
    return InstStream.AdjustedInstStream[InstructionSize + Offset];
  } else {
    return std::nullopt;
  }
}

std::pair<uint64_t, bool> Decoder::ReadData(uint8_t Size) {
  LOGMAN_THROW_A_FMT(Size != 0 && Size <= sizeof(uint64_t), "Unknown data size to read");

  uint64_t Res = 0;
  uint64_t Address = reinterpret_cast<uint64_t>(InstStream.InstStream + InstructionSize);
  if (CheckRangeExecutable(Address, Size)) {
    std::memcpy(&Res, &InstStream.AdjustedInstStream[InstructionSize], Size);
  } else {
    HitNonExecutableRange = true;
    // See PeekByte, this specific case may cause some executable memory to read as 0 but it doesn't matter as the entire instruction will be rolled back anyway.
    Res = 0;
  }


#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  for (size_t i = 0; i < Size; ++i) {
    ReadByte();
  }
#else
  SkipBytes(Size);
#endif

  if (Relocations) {
    uint32_t SectionOffset = static_cast<uint32_t>(Address - SectionMinAddress);
    if (auto It = Relocations->find(SectionOffset); It != Relocations->end()) {
      if (It->second == GuestRelocationType::Rel32 && Size == 4) {
        return {static_cast<int64_t>(static_cast<int32_t>(Res) - static_cast<int32_t>(EntryPoint)), true};
      } else if (It->second == GuestRelocationType::Rel64 && Size == 8) {
        return {static_cast<int64_t>(Res) - static_cast<int64_t>(EntryPoint), true};
      } else {
        HitBadRelocation = true;
        Res = 0;
      }
    }
  }

  return {Res, false};
}

void Decoder::DecodeModRM_16(X86Tables::DecodedOperand* Operand, X86Tables::ModRMDecoded ModRM) {
  // 16bit modrm behaves similar to SIB but encoded directly in modrm
  // mod != 0b11 case
  // RM    | Result
  // ===============
  // 0b000 | [BX + SI]
  // 0b001 | [BX + DI]
  // 0b010 | [BP + SI]
  // 0b011 | [BP + DI]
  // 0b100 | [SI]
  // 0b101 | [DI]
  // 0b110 | {[BP], disp16}
  // 0b111 | [BX]
  // if mod = 0b00
  //    0b110 = disp16
  // if mod = 0b01
  //    All encodings gain 8bit displacement
  //    0b110 = [BP] + disp8
  // if mod = 0b10
  //    All encodings gain 16bit displacement
  //    0b110 = [BP] + disp16
  uint32_t Literal {};
  uint8_t DisplacementSize {};
  if ((ModRM.mod == 0 && ModRM.rm == 0b110) || ModRM.mod == 0b10) {
    DisplacementSize = 2;
  } else if (ModRM.mod == 0b01) {
    DisplacementSize = 1;
  }
  if (DisplacementSize) {
    bool IsRelocation = false;
    std::tie(Literal, IsRelocation) = ReadData(DisplacementSize);
    LOGMAN_THROW_A_FMT(!IsRelocation, "1/2 byte relocations unsupported");
    if (DisplacementSize == 1) {
      Literal = static_cast<int8_t>(Literal);
    }
  }

  Operand->Type = DecodedOperand::OpType::SIB;
  Operand->Data.SIB.Scale = 1;
  Operand->Data.SIB.Offset = Literal;

  // Only called when ModRM.mod != 0b11
  struct Encodings {
    uint8_t Base;
    uint8_t Index;
  };
  constexpr static std::array<Encodings, 24> Lookup = {{
    // Mod = 0b00
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_RSI},
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_RDI},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_RSI},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_RDI},
    {FEXCore::X86State::REG_RSI, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RDI, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_INVALID, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_INVALID},
    // Mod = 0b01
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_RSI},
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_RDI},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_RSI},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_RDI},
    {FEXCore::X86State::REG_RSI, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RDI, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_INVALID},
    // Mod = 0b10
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_RSI},
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_RDI},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_RSI},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_RDI},
    {FEXCore::X86State::REG_RSI, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RDI, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RBP, FEXCore::X86State::REG_INVALID},
    {FEXCore::X86State::REG_RBX, FEXCore::X86State::REG_INVALID},
  }};

  uint8_t LookupIndex = ModRM.mod << 3 | ModRM.rm;
  auto it = Lookup[LookupIndex];
  Operand->Data.SIB.Base = it.Base;
  Operand->Data.SIB.Index = it.Index;
}

void Decoder::DecodeModRM_64(X86Tables::DecodedOperand* Operand, X86Tables::ModRMDecoded ModRM) {
  uint8_t Displacement {};
  // Do we have an offset?
  if (ModRM.mod == 0b01) {
    Displacement = 1;
  } else if (ModRM.mod == 0b10) {
    Displacement = 4;
  } else if (ModRM.mod == 0 && ModRM.rm == 0b101) {
    Displacement = 4;
  }

  // Calculate SIB
  bool HasSIB = ((ModRM.mod != 0b11) && (ModRM.rm == 0b100));

  if (HasSIB) {
    FEXCore::X86Tables::SIBDecoded SIB;
    if (DecodeInst->Flags & DecodeFlags::FLAG_DECODED_SIB) {
      SIB.Hex = DecodeInst->SIB;
    } else {
      // Haven't yet grabbed SIB, pull it now
      DecodeInst->SIB = ReadByte();
      SIB.Hex = DecodeInst->SIB;
      DecodeInst->Flags |= DecodeFlags::FLAG_DECODED_SIB;
    }

    // If the SIB base is 0b101, aka BP or R13 then we have a 32bit displacement
    if (ModRM.mod == 0b00 && ModRM.rm == 0b100 && SIB.base == 0b101) {
      Displacement = 4;
    }

    // SIB
    Operand->Type = DecodedOperand::OpType::SIB;
    Operand->Data.SIB.Scale = 1 << SIB.scale;

    // The invalid encoding types are described at Table 1-12. "promoted nsigned is always non-zero"
    {
      // If we have a VSIB byte (as opposed to SIB), then the index register is a vector.
      // DecodeInst->TableInfo may be null in the case of 3DNow! ModRM decoding.
      const bool IsIndexVector = DecodeInst->TableInfo && (DecodeInst->TableInfo->Flags & InstFlags::FLAGS_VEX_VSIB) != 0;
      uint8_t InvalidSIBIndex = 0b100; ///< SIB Index where there is no register encoding.
      if (IsIndexVector) {
        DecodeInst->Flags |= X86Tables::DecodeFlags::FLAG_VSIB_BYTE;
        InvalidSIBIndex = ~0; ///< No Invalid SIB Index with Index Vectors.
      }

      const uint8_t IndexREX = (DecodeInst->Flags & DecodeFlags::FLAG_REX_XGPR_X) != 0 ? 1 : 0;
      const uint8_t BaseREX = (DecodeInst->Flags & DecodeFlags::FLAG_REX_XGPR_B) != 0 ? 1 : 0;

      Operand->Data.SIB.Index = MapModRMToReg(IndexREX, SIB.index, false, false, IsIndexVector, false, InvalidSIBIndex);
      Operand->Data.SIB.Base = MapModRMToReg(BaseREX, SIB.base, false, false, false, false, ModRM.mod == 0 ? 0b101 : 16);
    }

    LOGMAN_THROW_A_FMT(Displacement <= 4, "Number of bytes should be <= 4 for literal src");

    if (Displacement) {
      auto [Literal, IsRelocation] = ReadData(Displacement);
      if (IsRelocation) {
        Operand->Type = DecodedOperand::OpType::SIBRelocation;
      }
      if (Displacement == 1) {
        Literal = static_cast<int8_t>(Literal);
      }
      Operand->Data.SIB.Offset = Literal;
    }
  } else if (ModRM.mod == 0) {
    // Explained in Table 1-14. "Operand Addressing Using ModRM and SIB Bytes"
    if (ModRM.rm == 0b101) {
      // 32bit Displacement
      auto [Literal, IsRelocation] = ReadData(4);
      Operand->Type = IsRelocation ? DecodedOperand::OpType::RIPRelativeRelocation : DecodedOperand::OpType::RIPRelative;
      Operand->Data.RIPLiteral.Value = Literal;
    } else {
      // Register-direct addressing
      Operand->Type = DecodedOperand::OpType::GPRDirect;
      Operand->Data.GPR.GPR = MapModRMToReg(DecodeInst->Flags & DecodeFlags::FLAG_REX_XGPR_B ? 1 : 0, ModRM.rm, false, false, false, false);
    }
  } else {
    uint8_t DisplacementSize = ModRM.mod == 1 ? 1 : 4;
    auto [Literal, IsRelocation] = ReadData(DisplacementSize);
    if (DisplacementSize == 1) {
      Literal = static_cast<int8_t>(Literal);
    }

    Operand->Type = IsRelocation ? DecodedOperand::OpType::GPRIndirectRelocation : DecodedOperand::OpType::GPRIndirect;
    Operand->Data.GPRIndirect.GPR = MapModRMToReg(DecodeInst->Flags & DecodeFlags::FLAG_REX_XGPR_B ? 1 : 0, ModRM.rm, false, false, false, false);
    Operand->Data.GPRIndirect.Displacement = Literal;
  }
}

Decoder::DecodedBlockStatus Decoder::NormalOp(const FEXCore::X86Tables::X86InstInfo* Info, uint16_t Op, DecodedHeader Options) {
  if (Info->Type == FEXCore::X86Tables::TYPE_ARCH_DISPATCHER) [[unlikely]] {
    // Dispatcher Op.
    // TODO: Move this in to `NormalOpHeader`, Dispatch tables have a bug currently where some subtables don't inherit flags correctly.
    // Can be seen by running FEX asm tests if this is removed.
    return NormalOp(&Info->OpcodeDispatcher.Indirect[BlockInfo.Is64BitMode ? 1 : 0], Op);
  }

  DecodeInst->OP = Op;
  DecodeInst->TableInfo = Info;

  if (Info->Type == FEXCore::X86Tables::TYPE_UNKNOWN) {
    return DecodedBlockStatus::INVALID_INST;
  }

  if (Info->Type == FEXCore::X86Tables::TYPE_INVALID) {
    return DecodedBlockStatus::INVALID_INST;
  }

  if (!(Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SUPPORTS_LOCK) && (DecodeInst->Flags & DecodeFlags::FLAG_LOCK)) {
    // Instruction has lock prefix but doesn't support lock.
    return DecodedBlockStatus::UNIMPLEMENTED_INST;
  }

  LOGMAN_THROW_A_FMT(!(Info->Type >= FEXCore::X86Tables::TYPE_GROUP_1 && Info->Type <= FEXCore::X86Tables::TYPE_GROUP_P), "Group Ops "
                                                                                                                          "should have "
                                                                                                                          "been decoded "
                                                                                                                          "before this!");

  uint8_t DestSize {};
  const bool HasWideningDisplacement =
    (FEXCore::X86Tables::DecodeFlags::GetOpAddr(DecodeInst->Flags, 0) & FEXCore::X86Tables::DecodeFlags::FLAG_WIDENING_SIZE_LAST) != 0 ||
    (Options.w && BlockInfo.Is64BitMode);
  const bool HasNarrowingDisplacement =
    (FEXCore::X86Tables::DecodeFlags::GetOpAddr(DecodeInst->Flags, 0) & FEXCore::X86Tables::DecodeFlags::FLAG_OPERAND_SIZE_LAST) != 0;

  const bool HasXMMFlags = (Info->Flags & InstFlags::FLAGS_XMM_FLAGS) != 0;
  bool HasXMMSrc =
    HasXMMFlags && !HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_SRC_GPR) && !HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_MMX_SRC);
  bool HasXMMDst =
    HasXMMFlags && !HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_DST_GPR) && !HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_MMX_DST);
  bool HasMMSrc =
    HasXMMFlags && !HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_SRC_GPR) && HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_MMX_SRC);
  bool HasMMDst =
    HasXMMFlags && !HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_DST_GPR) && HAS_XMM_SUBFLAG(Info->Flags, InstFlags::FLAGS_SF_MMX_DST);

  // Is ModRM present via explicit instruction encoded or REX?
  const bool HasMODRM = !!(Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_MODRM);

  const bool HasREX = !!(DecodeInst->Flags & DecodeFlags::FLAG_REX_PREFIX);
  const bool Has16BitAddressing = !BlockInfo.Is64BitMode && DecodeInst->Flags & DecodeFlags::FLAG_ADDRESS_SIZE;

  if (Options.w && (Info->Flags & InstFlags::FLAGS_REX_W_0)) {
    return DecodedBlockStatus::INVALID_INST;
  } else if (!Options.w && (Info->Flags & InstFlags::FLAGS_REX_W_1)) {
    return DecodedBlockStatus::INVALID_INST;
  }

  if (Options.L && (Info->Flags & InstFlags::FLAGS_VEX_L_0)) {
    return DecodedBlockStatus::INVALID_INST;
  } else if (!Options.L && (Info->Flags & InstFlags::FLAGS_VEX_L_1)) {
    return DecodedBlockStatus::INVALID_INST;
  }

  const bool UseVEXL = Options.L && !(Info->Flags & InstFlags::FLAGS_VEX_L_IGNORE);

  // This is used for ModRM register modification
  // For both modrm.reg and modrm.rm(when mod == 0b11) when value is >= 0b100
  // then it changes from expected registers to the high 8bits of the lower registers
  // Bit annoying to support
  // In the case of no modrm (REX in byte situation) then it is unaffected
  bool Is8BitSrc {};
  bool Is8BitDest {};

  // If we require ModRM and haven't decoded it yet, do it now
  // Some instructions have to read modrm upfront, others do it later
  if (HasMODRM && !(DecodeInst->Flags & DecodeFlags::FLAG_DECODED_MODRM)) {
    DecodeInst->ModRM = ReadByte();
    DecodeInst->Flags |= DecodeFlags::FLAG_DECODED_MODRM;
  }

  // New instruction size decoding
  {
    // Decode destinations first
    const auto DstSizeFlag = FEXCore::X86Tables::InstFlags::GetSizeDstFlags(Info->Flags);
    const auto SrcSizeFlag = FEXCore::X86Tables::InstFlags::GetSizeSrcFlags(Info->Flags);

    if (DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_8BIT) {
      DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_8BIT);
      DestSize = 1;
      Is8BitDest = true;
    } else if (DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_16BIT) {
      DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_16BIT);
      DestSize = 2;
    } else if (DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_128BIT) {
      if (UseVEXL) {
        DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_256BIT);
        DestSize = 32;
      } else {
        DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_128BIT);
        DestSize = 16;
      }
    } else if (DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_256BIT) {
      DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_256BIT);
      DestSize = 32;
    } else if (HasNarrowingDisplacement &&
               (DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_DEF || DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_64BITDEF)) {
      // See table 1-2. Operand-Size Overrides for this decoding
      // If the default operating mode is 32bit and we have the operand size flag then the operating size drops to 16bit
      DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_16BIT);
      DestSize = 2;
    } else if ((HasXMMDst || HasMMDst || BlockInfo.Is64BitMode) && (HasWideningDisplacement || DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_64BIT ||
                                                                    DstSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_64BITDEF)) {
      DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_64BIT);
      DestSize = 8;
    } else {
      DecodeInst->Flags |= DecodeFlags::GenSizeDstSize(DecodeFlags::SIZE_32BIT);
      DestSize = 4;
    }

    // Decode sources
    if (SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_8BIT) {
      DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_8BIT);
      Is8BitSrc = true;
    } else if (SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_16BIT) {
      DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_16BIT);
    } else if (SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_128BIT) {
      if (UseVEXL) {
        DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_256BIT);
      } else {
        DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_128BIT);
      }
    } else if (SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_256BIT) {
      DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_256BIT);
    } else if (HasNarrowingDisplacement &&
               (SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_DEF || SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_64BITDEF)) {
      // See table 1-2. Operand-Size Overrides for this decoding
      // If the default operating mode is 32bit and we have the operand size flag then the operating size drops to 16bit
      DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_16BIT);
    } else if ((HasXMMSrc || HasMMSrc || BlockInfo.Is64BitMode) && (HasWideningDisplacement || SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_64BIT ||
                                                                    SrcSizeFlag == FEXCore::X86Tables::InstFlags::SIZE_64BITDEF)) {
      DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_64BIT);
    } else {
      DecodeInst->Flags |= DecodeFlags::GenSizeSrcSize(DecodeFlags::SIZE_32BIT);
    }
  }

  auto* CurrentDest = &DecodeInst->Dest;

  if (HAS_NON_XMM_SUBFLAG(Info->Flags, FEXCore::X86Tables::InstFlags::FLAGS_SF_DST_RAX) ||
      HAS_NON_XMM_SUBFLAG(Info->Flags, FEXCore::X86Tables::InstFlags::FLAGS_SF_DST_RDX)) {
    // Some instructions hardcode their destination as RAX
    CurrentDest->Type = DecodedOperand::OpType::GPR;
    CurrentDest->Data.GPR.HighBits = false;
    CurrentDest->Data.GPR.GPR =
      HAS_NON_XMM_SUBFLAG(Info->Flags, FEXCore::X86Tables::InstFlags::FLAGS_SF_DST_RAX) ? FEXCore::X86State::REG_RAX : FEXCore::X86State::REG_RDX;
    CurrentDest = &DecodeInst->Src[0];
  } else if (HAS_NON_XMM_SUBFLAG(Info->Flags, FEXCore::X86Tables::InstFlags::FLAGS_SF_REX_IN_BYTE)) {
    LOGMAN_THROW_A_FMT(!HasMODRM, "This instruction shouldn't have ModRM!");

    // If the REX is in the byte that means the lower nibble of the OP contains the destination GPR
    // This also means that the destination is always a GPR on these ones
    // ADDITIONALLY:
    // If there is a REX prefix then that allows extended GPR usage
    CurrentDest->Type = DecodedOperand::OpType::GPR;
    DecodeInst->Dest.Data.GPR.HighBits = (Is8BitDest && !HasREX && (Op & 0b111) >= 0b100);
    CurrentDest->Data.GPR.GPR =
      MapModRMToReg(DecodeInst->Flags & DecodeFlags::FLAG_REX_XGPR_B ? 1 : 0, Op & 0b111, Is8BitDest, HasREX, false, false);

    if (CurrentDest->Data.GPR.GPR == FEXCore::X86State::REG_INVALID) {
      return DecodedBlockStatus::INVALID_INST;
    }
  }

  uint8_t Bytes = Info->MoreBytes;

  if ((Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_DISPLACE_SIZE_MUL_2) && HasWideningDisplacement) {
    Bytes <<= 1;
  }
  if ((Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_DISPLACE_SIZE_DIV_2) && HasNarrowingDisplacement) {
    Bytes >>= 1;
  }

  if ((Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_MEM_OFFSET) && (DecodeInst->Flags & DecodeFlags::FLAG_ADDRESS_SIZE)) {
    // If we have a memory offset and have the address size override then divide it just like narrowing displacement
    Bytes >>= 1;
  }

  auto ModRMOperand = [&](FEXCore::X86Tables::DecodedOperand& GPR, FEXCore::X86Tables::DecodedOperand& NonGPR, bool HasXMMGPR,
                          bool HasXMMNonGPR, bool HasMMGPR, bool HasMMNonGPR, bool GPR8Bit, bool NonGPR8Bit) {
    FEXCore::X86Tables::ModRMDecoded ModRM;
    ModRM.Hex = DecodeInst->ModRM;

    if (ModRM.reg != 0b000 && (Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SF_MOD_ZERO_REG)) {
      return false;
    }

    if (ModRM.mod == 0b11 && (Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SF_MOD_MEM_ONLY)) {
      return false;
    }

    if (ModRM.mod != 0b11 && (Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SF_MOD_REG_ONLY)) {
      return false;
    }

    // Decode the GPR source first
    GPR.Type = DecodedOperand::OpType::GPR;
    GPR.Data.GPR.HighBits = (GPR8Bit && ModRM.reg >= 0b100 && !HasREX);
    GPR.Data.GPR.GPR = MapModRMToReg(DecodeInst->Flags & DecodeFlags::FLAG_REX_XGPR_R ? 1 : 0, ModRM.reg, GPR8Bit, HasREX, HasXMMGPR, HasMMGPR);

    if (GPR.Data.GPR.GPR == FEXCore::X86State::REG_INVALID) {
      return false;
    }

    // ModRM.mod == 0b11 == Register
    // ModRM.Mod != 0b11 == Register-direct addressing
    if (ModRM.mod == 0b11) {
      NonGPR.Type = DecodedOperand::OpType::GPR;
      NonGPR.Data.GPR.HighBits = (NonGPR8Bit && ModRM.rm >= 0b100 && !HasREX);
      NonGPR.Data.GPR.GPR =
        MapModRMToReg(DecodeInst->Flags & DecodeFlags::FLAG_REX_XGPR_B ? 1 : 0, ModRM.rm, NonGPR8Bit, HasREX, HasXMMNonGPR, HasMMNonGPR);
      if (NonGPR.Data.GPR.GPR == FEXCore::X86State::REG_INVALID) {
        return false;
      }
    } else {
      // Only decode if we haven't pre-decoded
      if (NonGPR.IsNone()) {
        auto Disp = DecodeModRMs_Disp[Has16BitAddressing];
        (this->*Disp)(&NonGPR, ModRM);
      }
    }

    return true;
  };

  size_t CurrentSrc = 0;

  const auto VEXOperand = Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_VEX_SRC_MASK;
  if (VEXOperand == FEXCore::X86Tables::InstFlags::FLAGS_VEX_NO_OPERAND && Options.vvvv) {
    return DecodedBlockStatus::INVALID_INST;
  }

  if (VEXOperand == FEXCore::X86Tables::InstFlags::FLAGS_VEX_1ST_SRC) {
    DecodeInst->Src[CurrentSrc].Type = DecodedOperand::OpType::GPR;
    DecodeInst->Src[CurrentSrc].Data.GPR.HighBits = false;

    // If we have XMM flags at all, then SRC 1 cannot be a GPR. The only case where
    // this is possible is with BMI1 and BMI2 instructions (which are all GPR-based
    // and don't use XMM flags)
    DecodeInst->Src[CurrentSrc].Data.GPR.GPR = MapVEXToReg(Options.vvvv, HasXMMFlags);

    ++CurrentSrc;
  }

  if (Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_MODRM) {
    if (Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SF_MOD_DST) {
      if (!ModRMOperand(DecodeInst->Src[CurrentSrc], DecodeInst->Dest, HasXMMSrc, HasXMMDst, HasMMSrc, HasMMDst, Is8BitSrc, Is8BitDest)) {
        return DecodedBlockStatus::INVALID_INST;
      }
    } else {
      if (!ModRMOperand(DecodeInst->Dest, DecodeInst->Src[CurrentSrc], HasXMMDst, HasXMMSrc, HasMMDst, HasMMSrc, Is8BitDest, Is8BitSrc)) {
        return DecodedBlockStatus::INVALID_INST;
      }
    }
    ++CurrentSrc;
  }

  if (VEXOperand == FEXCore::X86Tables::InstFlags::FLAGS_VEX_2ND_SRC) {
    DecodeInst->Src[CurrentSrc].Type = DecodedOperand::OpType::GPR;
    DecodeInst->Src[CurrentSrc].Data.GPR.HighBits = false;
    DecodeInst->Src[CurrentSrc].Data.GPR.GPR = MapVEXToReg(Options.vvvv, HasXMMSrc);
    ++CurrentSrc;
  }

  if (HAS_NON_XMM_SUBFLAG(Info->Flags, FEXCore::X86Tables::InstFlags::FLAGS_SF_SRC_RAX)) {
    DecodeInst->Src[CurrentSrc].Type = DecodedOperand::OpType::GPR;
    DecodeInst->Src[CurrentSrc].Data.GPR.HighBits = false;
    DecodeInst->Src[CurrentSrc].Data.GPR.GPR = FEXCore::X86State::REG_RAX;
    ++CurrentSrc;
  } else if (HAS_NON_XMM_SUBFLAG(Info->Flags, FEXCore::X86Tables::InstFlags::FLAGS_SF_SRC_RCX)) {
    DecodeInst->Src[CurrentSrc].Type = DecodedOperand::OpType::GPR;
    DecodeInst->Src[CurrentSrc].Data.GPR.HighBits = false;
    DecodeInst->Src[CurrentSrc].Data.GPR.GPR = FEXCore::X86State::REG_RCX;
    ++CurrentSrc;
  }

  if (VEXOperand == FEXCore::X86Tables::InstFlags::FLAGS_VEX_DST) {
    CurrentDest->Type = DecodedOperand::OpType::GPR;
    CurrentDest->Data.GPR.HighBits = false;
    CurrentDest->Data.GPR.GPR = MapVEXToReg(Options.vvvv, HasXMMDst);
  }

  if (Bytes != 0) {
    LOGMAN_THROW_A_FMT(Bytes <= 8, "Number of bytes should be <= 8 for literal src");


    auto [Literal, IsRelocation] = ReadData(Bytes);
    if (IsRelocation) {
      DecodeInst->Src[CurrentSrc].Type = DecodedOperand::OpType::LiteralRelocation;
      DecodeInst->Src[CurrentSrc].Data.LiteralRelocation.EntrypointOffset = Literal;
    } else {
      DecodeInst->Src[CurrentSrc].Data.Literal.Size = Bytes;

      if ((Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SRC_SEXT) ||
          (DecodeFlags::GetSizeDstFlags(DecodeInst->Flags) == DecodeFlags::SIZE_64BIT &&
           Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SRC_SEXT64BIT)) {
        if (Bytes == 1) {
          Literal = static_cast<int8_t>(Literal);
        } else if (Bytes == 2) {
          Literal = static_cast<int16_t>(Literal);
        } else {
          Literal = static_cast<int32_t>(Literal);
        }
        DecodeInst->Src[CurrentSrc].Data.Literal.Size = DestSize;
      }

      DecodeInst->Src[CurrentSrc].Type = DecodedOperand::OpType::Literal;
      DecodeInst->Src[CurrentSrc].Data.Literal.Value = Literal;
    }

    Bytes = 0;
  }

  if ((DecodeInst->Flags & DecodeFlags::FLAG_LOCK) && DecodeInst->Dest.IsGPR()) {
    // Instruction has lock prefix, but the destination isn't memory, this is invalid.
    return DecodedBlockStatus::UNIMPLEMENTED_INST;
  }

  LOGMAN_THROW_A_FMT(Bytes == 0, "Inst at 0x{:x}: 0x{:04x} '{}' Had an instruction of size {} with {} remaining", DecodeInst->PC,
                     DecodeInst->OP, DecodeInst->TableInfo->Name ?: "UND", InstructionSize, Bytes);
  DecodeInst->InstSize = InstructionSize;
  return DecodedBlockStatus::SUCCESS;
}

Decoder::DecodedBlockStatus Decoder::NormalOpHeader(const FEXCore::X86Tables::X86InstInfo* Info, uint16_t Op) {
  DecodeInst->OPRaw = DecodeInst->OP = Op;
  DecodeInst->TableInfo = Info;

  if (Info->Type == FEXCore::X86Tables::TYPE_UNKNOWN) {
    return DecodedBlockStatus::INVALID_INST;
  }

  if (Info->Type == FEXCore::X86Tables::TYPE_INVALID) {
    return DecodedBlockStatus::INVALID_INST;
  }

  LOGMAN_THROW_A_FMT(Info->Type != FEXCore::X86Tables::TYPE_REX_PREFIX, "REX PREFIX should have been decoded before this!");

  // A normal instruction is the most likely.
  if (Info->Type == FEXCore::X86Tables::TYPE_INST) [[likely]] {
    return NormalOp(Info, Op);
  } else if (Info->Type == FEXCore::X86Tables::TYPE_ARCH_DISPATCHER) [[unlikely]] {
    // Dispatcher Op.
    return NormalOp(&Info->OpcodeDispatcher.Indirect[BlockInfo.Is64BitMode ? 1 : 0], Op);
  } else if (Info->Type >= FEXCore::X86Tables::TYPE_GROUP_1 && Info->Type <= FEXCore::X86Tables::TYPE_GROUP_11) {
    uint8_t ModRMByte = ReadByte();
    DecodeInst->ModRM = ModRMByte;
    DecodeInst->Flags |= DecodeFlags::FLAG_DECODED_MODRM;

    FEXCore::X86Tables::ModRMDecoded ModRM;
    ModRM.Hex = DecodeInst->ModRM;

#define OPD(group, prefix, Reg) (((group - FEXCore::X86Tables::TYPE_GROUP_1) << 6) | (prefix) << 3 | (Reg))
    Op = OPD(Info->Type, Info->MoreBytes, ModRM.reg);
    return NormalOp(&PrimaryInstGroupOps[Op], Op);
#undef OPD
  } else if (Info->Type >= FEXCore::X86Tables::TYPE_GROUP_6 && Info->Type <= FEXCore::X86Tables::TYPE_GROUP_P) {
#define OPD(group, prefix, Reg) (((group - FEXCore::X86Tables::TYPE_GROUP_6) << 5) | (prefix) << 3 | (Reg))
    constexpr uint16_t PF_NONE = 0;
    constexpr uint16_t PF_F3 = 1;
    constexpr uint16_t PF_66 = 2;
    constexpr uint16_t PF_F2 = 3;

    uint16_t PrefixType = PF_NONE;
    if (LastEscapePrefix == 0xF3) {
      PrefixType = PF_F3;
    } else if (LastEscapePrefix == 0xF2) {
      PrefixType = PF_F2;
    } else if (LastEscapePrefix == 0x66) {
      PrefixType = PF_66;
    }

    // We have ModRM
    uint8_t ModRMByte = ReadByte();
    DecodeInst->ModRM = ModRMByte;
    DecodeInst->Flags |= DecodeFlags::FLAG_DECODED_MODRM;

    FEXCore::X86Tables::ModRMDecoded ModRM;
    ModRM.Hex = DecodeInst->ModRM;

    uint16_t LocalOp = OPD(Info->Type, PrefixType, ModRM.reg);
    const FEXCore::X86Tables::X86InstInfo* LocalInfo = &SecondInstGroupOps[LocalOp];
#undef OPD
    if (LocalInfo->Type == FEXCore::X86Tables::TYPE_SECOND_GROUP_MODRM && ModRM.mod == 0b11) {
      // Everything in this group is privileged instructions aside from XGETBV
      constexpr std::array<uint8_t, 8> RegToField = {
        255, 0, 1, 2, 255, 255, 255, 3,
      };
      uint8_t Field = RegToField[ModRM.reg];
      if (Field == 255) {
        return DecodedBlockStatus::INVALID_INST;
      }

      LocalOp = (Field << 3) | ModRM.rm;
      return NormalOp(&SecondModRMTableOps[LocalOp], LocalOp);
    } else {
      return NormalOp(&SecondInstGroupOps[LocalOp], LocalOp);
    }
  } else if (Info->Type == FEXCore::X86Tables::TYPE_X87_TABLE_PREFIX) {
    // We have ModRM
    uint8_t ModRMByte = ReadByte();
    DecodeInst->ModRM = ModRMByte;
    DecodeInst->Flags |= DecodeFlags::FLAG_DECODED_MODRM;

    uint16_t X87Op = ((Op - 0xD8) << 8) | ModRMByte;
    return NormalOp(&(*X87Table)[X87Op], X87Op);
  } else if (Info->Type == FEXCore::X86Tables::TYPE_VEX_TABLE_PREFIX) {
    if (!VEXTable) {
      // AVX not enabled.
      return DecodedBlockStatus::INVALID_INST;
    }

    uint16_t map_select = 1;
    uint16_t pp = 0;
    const uint8_t Byte1 = ReadByte();
    DecodedHeader options {};

    if ((Byte1 & 0b10000000) == 0) {
      if (!BlockInfo.Is64BitMode) {
        return DecodedBlockStatus::INVALID_INST;
      }

      DecodeInst->Flags |= DecodeFlags::FLAG_REX_XGPR_R;
    }

    if (Op == 0xC5) { // Two byte VEX
      pp = Byte1 & 0b11;
      const uint8_t vvvv = ((Byte1 & 0b01111000) >> 3);
      if (!BlockInfo.Is64BitMode && vvvv <= 0b0111) {
        // Invalid on 32-bit, can't use the high registers.
        return DecodedBlockStatus::INVALID_INST;
      }
      options.vvvv = 15 - vvvv;
      options.L = (Byte1 & 0b100) != 0;
    } else { // 0xC4 = Three byte VEX
      const uint8_t Byte2 = ReadByte();
      pp = Byte2 & 0b11;
      map_select = Byte1 & 0b11111;
      const uint8_t vvvv = ((Byte2 & 0b01111000) >> 3);
      if (!BlockInfo.Is64BitMode && vvvv <= 0b0111) {
        // Invalid on 32-bit, can't use the high registers.
        return DecodedBlockStatus::INVALID_INST;
      }
      options.vvvv = 15 - vvvv;
      options.w = (Byte2 & 0b10000000) != 0;
      options.L = (Byte2 & 0b100) != 0;
      if ((Byte1 & 0b01000000) == 0) {
        if (!BlockInfo.Is64BitMode) {
          return DecodedBlockStatus::INVALID_INST;
        }
        DecodeInst->Flags |= DecodeFlags::FLAG_REX_XGPR_X;
      }
      if (BlockInfo.Is64BitMode && (Byte1 & 0b00100000) == 0) {
        DecodeInst->Flags |= DecodeFlags::FLAG_REX_XGPR_B;
      }
      if (options.w) {
        DecodeInst->Flags |= DecodeFlags::FLAG_OPTION_AVX_W;
      }
      if (!(map_select >= 1 && map_select <= 3)) {
        return DecodedBlockStatus::INVALID_INST;
      }
    }

    uint16_t VEXOp = ReadByte();
#define OPD(map_select, pp, opcode) (((map_select - 1) << 10) | (pp << 8) | (opcode))
    Op = OPD(map_select, pp, VEXOp);
#undef OPD

    const FEXCore::X86Tables::X86InstInfo* LocalInfo = &(*VEXTable)[Op];

    if (LocalInfo->Type >= FEXCore::X86Tables::TYPE_VEX_GROUP_12 && LocalInfo->Type <= FEXCore::X86Tables::TYPE_VEX_GROUP_17) {
      // We have ModRM
      uint8_t ModRMByte = ReadByte();
      DecodeInst->ModRM = ModRMByte;
      DecodeInst->Flags |= DecodeFlags::FLAG_DECODED_MODRM;

      FEXCore::X86Tables::ModRMDecoded ModRM;
      ModRM.Hex = DecodeInst->ModRM;

#define OPD(group, pp, opcode) (((group - TYPE_VEX_GROUP_12) << 4) | (pp << 3) | (opcode))
      Op = OPD(LocalInfo->Type, pp, ModRM.reg);
#undef OPD
      return NormalOp(&(*VEXTableGroup)[Op], Op, options);
    } else {
      return NormalOp(LocalInfo, Op, options);
    }
  } else if (Info->Type == FEXCore::X86Tables::TYPE_GROUP_EVEX) {
    FEXCORE_TELEMETRY_SET(TYPE_USES_EVEX_OPS, 1);
    // EVEX unsupported
    return DecodedBlockStatus::INVALID_INST;
  }

  LOGMAN_MSG_A_FMT("Invalid instruction decoding type");
  FEX_UNREACHABLE;
}

Decoder::DecodedBlockStatus Decoder::DecodeInstructionImpl(uint64_t PC) {
  InstructionSize = 0;
  LastEscapePrefix = 0;
  Instruction.fill(0);

  DecodeInst = &DecodedBuffer[DecodedSize];
  memset(DecodeInst, 0, sizeof(DecodedInst));
  DecodeInst->PC = PC;

  for (;;) {
    if (InstructionSize >= MAX_INST_SIZE) {
      return DecodedBlockStatus::INVALID_INST;
    }
    uint8_t Op = ReadByte();
    switch (Op) {
    case 0x0F: { // Escape Op
      uint8_t EscapeOp = ReadByte();
      switch (EscapeOp) {
      case 0x0F:
        [[unlikely]] { // 3DNow!
          DecodeREXIfValid(-2);
          // 3DNow! Instruction Encoding: 0F 0F [ModRM] [SIB] [Displacement] [Opcode]
          // Decode ModRM
          uint8_t ModRMByte = ReadByte();
          DecodeInst->ModRM = ModRMByte;
          DecodeInst->Flags |= DecodeFlags::FLAG_DECODED_MODRM;

          FEXCore::X86Tables::ModRMDecoded ModRM;
          ModRM.Hex = DecodeInst->ModRM;

          const bool Has16BitAddressing = !BlockInfo.Is64BitMode && DecodeInst->Flags & DecodeFlags::FLAG_ADDRESS_SIZE;

          // All 3DNow! instructions have the second argument as the rm handler
          // We need to decode it upfront to get the displacement out of the way
          if (ModRM.mod != 0b11) {
            auto Disp = DecodeModRMs_Disp[Has16BitAddressing];
            (this->*Disp)(&DecodeInst->Src[0], ModRM);
          }

          // Take a peek at the op just past the displacement
          uint8_t LocalOp = ReadByte();
          return NormalOpHeader(&FEXCore::X86Tables::DDDNowOps[LocalOp], LocalOp);
          break;
        }
      case 0x38: { // F38 Table!
        DecodeREXIfValid(-2);
        constexpr uint16_t PF_38_NONE = 0;
        constexpr uint16_t PF_38_66 = (1U << 0);
        constexpr uint16_t PF_38_F2 = (1U << 1);
        constexpr uint16_t PF_38_F3 = (1U << 2);

        uint16_t Prefix = PF_38_NONE;
        if (DecodeInst->Flags & DecodeFlags::FLAG_OPERAND_SIZE) {
          Prefix |= PF_38_66;
        }
        if (DecodeInst->Flags & DecodeFlags::FLAG_REPNE_PREFIX) {
          Prefix |= PF_38_F2;
        }
        if (DecodeInst->Flags & DecodeFlags::FLAG_REP_PREFIX) {
          Prefix |= PF_38_F3;
        }

        uint16_t LocalOp = (Prefix << 8) | ReadByte();

        bool NoOverlay66 = (FEXCore::X86Tables::H0F38TableOps[LocalOp].Flags & InstFlags::FLAGS_NO_OVERLAY66) != 0;
        if (LastEscapePrefix == 0x66 && NoOverlay66) { // Operand Size
          // Remove prefix so it doesn't effect calculations.
          // This is only an escape prefix rather than modifier now
          DecodeInst->Flags &= ~DecodeFlags::FLAG_OPERAND_SIZE;
          DecodeFlags::PopOpAddrIf(&DecodeInst->Flags, DecodeFlags::FLAG_OPERAND_SIZE_LAST);
        }
        return NormalOpHeader(&FEXCore::X86Tables::H0F38TableOps[LocalOp], LocalOp);
        break;
      }
      case 0x3A: { // F3A Table!
        DecodeREXIfValid(-2);
        constexpr uint16_t PF_3A_NONE = 0;
        constexpr uint16_t PF_3A_66 = (1 << 0);
        constexpr uint16_t PF_3A_REX = (1 << 1);

        uint16_t Prefix = PF_3A_NONE;
        if (LastEscapePrefix == 0x66) { // Operand Size
          Prefix = PF_3A_66;
        }

        if (DecodeInst->Flags & DecodeFlags::FLAG_REX_WIDENING) {
          Prefix |= PF_3A_REX;
        }

        uint16_t LocalOp = (Prefix << 8) | ReadByte();
        return NormalOpHeader(&FEXCore::X86Tables::H0F3ATableOps[LocalOp], LocalOp);
        break;
      }
      default:
        [[likely]] { // Two byte table!
          // x86-64 abuses three legacy prefixes to extend the table encodings
          // 0x66 - Operand Size prefix
          // 0xF2 - REPNE prefix
          // 0xF3 - REP prefix
          // If any of these three prefixes are used then it falls down the subtable
          // Additionally: If you hit repeat of differnt prefixes then only the LAST one before this one works for subtable selection

          bool NoOverlay = (FEXCore::X86Tables::SecondBaseOps[EscapeOp].Flags & InstFlags::FLAGS_NO_OVERLAY) != 0;
          bool NoOverlay66 = (FEXCore::X86Tables::SecondBaseOps[EscapeOp].Flags & InstFlags::FLAGS_NO_OVERLAY66) != 0;

          DecodeREXIfValid(-2);
          if (NoOverlay) { // This section of the table ignores prefix extention
            return NormalOpHeader(&FEXCore::X86Tables::SecondBaseOps[EscapeOp], EscapeOp);
          } else if (LastEscapePrefix == 0xF3) { // REP
            // Remove prefix so it doesn't effect calculations.
            // This is only an escape prefix rather tan modifier now
            DecodeInst->Flags &= ~DecodeFlags::FLAG_REP_PREFIX;
            return NormalOpHeader(&FEXCore::X86Tables::RepModOps[EscapeOp], EscapeOp);
          } else if (LastEscapePrefix == 0xF2) { // REPNE
            // Remove prefix so it doesn't effect calculations.
            // This is only an escape prefix rather tan modifier now
            DecodeInst->Flags &= ~DecodeFlags::FLAG_REPNE_PREFIX;
            return NormalOpHeader(&FEXCore::X86Tables::RepNEModOps[EscapeOp], EscapeOp);
          } else if (LastEscapePrefix == 0x66 && !NoOverlay66) { // Operand Size
            // Remove prefix so it doesn't effect calculations.
            // This is only an escape prefix rather tan modifier now
            DecodeInst->Flags &= ~DecodeFlags::FLAG_OPERAND_SIZE;
            DecodeFlags::PopOpAddrIf(&DecodeInst->Flags, DecodeFlags::FLAG_OPERAND_SIZE_LAST);
            return NormalOpHeader(&FEXCore::X86Tables::OpSizeModOps[EscapeOp], EscapeOp);
          } else {
            return NormalOpHeader(&FEXCore::X86Tables::SecondBaseOps[EscapeOp], EscapeOp);
          }
          break;
        }
      }
      break;
    }
    case 0x66: // Operand Size prefix
      DecodeInst->Flags |= DecodeFlags::FLAG_OPERAND_SIZE;
      LastEscapePrefix = Op;
      DecodeFlags::PushOpAddr(&DecodeInst->Flags, DecodeFlags::FLAG_OPERAND_SIZE_LAST);
      break;
    case 0x67: // Address Size override prefix
      DecodeInst->Flags |= DecodeFlags::FLAG_ADDRESS_SIZE;
      break;
    case 0x26: // ES legacy prefix
      if (!BlockInfo.Is64BitMode) {
        DecodeInst->Flags = (DecodeInst->Flags & ~FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS) | DecodeFlags::FLAG_ES_PREFIX;
      }
      break;
    case 0x2E: // CS legacy prefix
      if (!BlockInfo.Is64BitMode) {
        DecodeInst->Flags = (DecodeInst->Flags & ~FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS) | DecodeFlags::FLAG_CS_PREFIX;
      }
      break;
    case 0x36: // SS legacy prefix
      if (!BlockInfo.Is64BitMode) {
        DecodeInst->Flags = (DecodeInst->Flags & ~FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS) | DecodeFlags::FLAG_SS_PREFIX;
      }
      break;
    case 0x3E: // DS legacy prefix
      if (!BlockInfo.Is64BitMode) {
        DecodeInst->Flags = (DecodeInst->Flags & ~FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS) | DecodeFlags::FLAG_DS_PREFIX;
      }
      break;
    case 0xF0: // LOCK prefix
      DecodeInst->Flags |= DecodeFlags::FLAG_LOCK;
      break;
    case 0xF2: // REPNE prefix
      DecodeInst->Flags |= DecodeFlags::FLAG_REPNE_PREFIX;
      LastEscapePrefix = Op;
      break;
    case 0xF3: // REP prefix
      DecodeInst->Flags |= DecodeFlags::FLAG_REP_PREFIX;
      LastEscapePrefix = Op;
      break;
    case 0x64: // FS prefix
      DecodeInst->Flags = (DecodeInst->Flags & ~FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS) | DecodeFlags::FLAG_FS_PREFIX;
      break;
    case 0x65: // GS prefix
      DecodeInst->Flags = (DecodeInst->Flags & ~FEXCore::X86Tables::DecodeFlags::FLAG_SEGMENTS) | DecodeFlags::FLAG_GS_PREFIX;
      break;
    default:
      [[likely]] { // Default base table
        const X86InstInfo* Info = &FEXCore::X86Tables::BaseOps[Op];
        if (Info->Type == FEXCore::X86Tables::TYPE_ARCH_DISPATCHER) {
          Info = &Info->OpcodeDispatcher.Indirect[BlockInfo.Is64BitMode ? 1 : 0];
        }

        if (Info->Type == FEXCore::X86Tables::TYPE_REX_PREFIX) {
          DecodeInst->REXIndex = InstructionSize;
        } else {
          DecodeREXIfValid();
          return NormalOpHeader(Info, Op);
        }

        break;
      }
    }
  }

  if (DecodeInst->Dest.IsGPR()) {
    return DecodedBlockStatus::INVALID_INST;
  }

  return DecodedBlockStatus::SUCCESS;
}

void Decoder::DecodeREXIfValid(int8_t ExpectedOffset) {
  LOGMAN_THROW_A_FMT(ExpectedOffset < 0, "Expecting an negative offset for the REX offset!");
  const int8_t REXIndex = InstructionSize + ExpectedOffset;

  if (DecodeInst->REXIndex != 0 && DecodeInst->REXIndex == REXIndex) {
    const uint8_t Op = Instruction[REXIndex - 1];
    DecodeInst->Flags |= DecodeFlags::FLAG_REX_PREFIX;

    // Widening displacement
    if (Op & 0b1000) {
      DecodeInst->Flags |= DecodeFlags::FLAG_REX_WIDENING;
      DecodeFlags::PushOpAddr(&DecodeInst->Flags, DecodeFlags::FLAG_WIDENING_SIZE_LAST);
    }

    // XGPR_B bit set
    if (Op & 0b0001) {
      DecodeInst->Flags |= DecodeFlags::FLAG_REX_XGPR_B;
    }

    // XGPR_X bit set
    if (Op & 0b0010) {
      DecodeInst->Flags |= DecodeFlags::FLAG_REX_XGPR_X;
    }

    // XGPR_R bit set
    if (Op & 0b0100) {
      DecodeInst->Flags |= DecodeFlags::FLAG_REX_XGPR_R;
    }
  }
}

Decoder::DecodedBlockStatus Decoder::DecodeInstruction(uint64_t PC) {
  // Will be set if DecodeInstructionImpl tries to read non-executable memory
  HitNonExecutableRange = false;
  HitBadRelocation = false;
  auto ErrorDuringDecoding = DecodeInstructionImpl(PC);

  if (ErrorDuringDecoding != DecodedBlockStatus::SUCCESS || HitNonExecutableRange || HitBadRelocation) [[unlikely]] {
    // Put an invalid instruction in the stream so the core can raise SIGILL if hit
    // Error while decoding instruction. We don't know the table or instruction size
    const auto InstSize = DecodeInst->InstSize;
    DecodeInst->TableInfo = nullptr;
    DecodeInst->InstSize = 0;

    // A decode error can be caused by substituting zero for an inaccessible
    // instruction byte, so the instruction fetch fault takes priority.
    if (HitNonExecutableRange) {
      return InstSize ? DecodedBlockStatus::PARTIAL_DECODE_INST : DecodedBlockStatus::NOEXEC_INST;
    }

    if (HitBadRelocation) {
      return DecodedBlockStatus::BAD_RELOCATION;
    }

    return ErrorDuringDecoding;
  } else if (!DecodeInst->TableInfo || (DecodeInst->TableInfo->Type == TYPE_INST && !DecodeInst->TableInfo->OpcodeDispatcher.OpDispatch)) {
    // If there wasn't an error during decoding but we have no dispatcher for the instruction then claim invalid instruction.
    return DecodedBlockStatus::INVALID_INST;
  }

  if (CTX->AreMonoHacksActive()) {
    // Unity uses a standard SPSC ringbuffer with cached read/write pointers and thread waiting flags at the following
    // offsets, which are consistent between 32-bit and 64-bit Unity versions from 2015 onwards.
    auto IsKnownAtomicDisplacement = [](uint64_t Displacement) {
      return Displacement == 0x80 || Displacement == 0x84 || Displacement == 0xC0 || Displacement == 0xC4;
    };

    if (DecodeInst->OP == 0x8b && DecodeInst->Src[0].IsGPRIndirect() &&
        IsKnownAtomicDisplacement(DecodeInst->Src[0].Data.GPRIndirect.Displacement)) {
      DecodeInst->Flags |= X86Tables::DecodeFlags::FLAG_FORCE_TSO;
    }
    if (DecodeInst->OP == 0x89 && DecodeInst->Dest.IsGPRIndirect() && IsKnownAtomicDisplacement(DecodeInst->Dest.Data.GPRIndirect.Displacement)) {
      DecodeInst->Flags |= X86Tables::DecodeFlags::FLAG_FORCE_TSO;
    }
  }

  return DecodedBlockStatus::SUCCESS;
}

// ★ REGION4 13.11.2026 (MACRUNNER_FEX32_IMPORT_BIND, MacRunnerXfer.h). Exactly `FF 15 disp32` / `FF 25 disp32`: no prefixes (so no
// segment override, 32-bit operand and address size), the operand is the absolute slot address. The handler answers only for a
// read-only non-executable image page and from then on invalidates this unit when that stops being true, so the slot's value is
// a constant of the translation exactly like the instruction bytes are. The operand becomes a literal: the dispatcher's
// CALLAbsoluteOp / JUMPAbsoluteOp never see a literal otherwise.
void Decoder::MRBindImport() {
  static const unsigned Mask = FEXCore::Utils::MacRunnerImportBindMask();
  if (DecodeInst->OPRaw == 0xE8 && DecodeInst->InstSize == 5 && DecodeInst->Src[0].IsLiteral() && DecodeInst->Src[0].Literal() != 0 &&
      !BlockInfo.Is64BitMode) {
    // REGION4-0003 THUNK_SKIP: `call rel32` to an import thunk -> a call to the thunk's final target, encoded as the rel32 a call
    // instruction at this PC would carry (the dispatcher's CALLOp wraps it to 32 bits as for any call).
    const uint32_t Next = static_cast<uint32_t>(DecodeInst->PC + 5);
    const uint32_t Target = static_cast<uint32_t>(Next + DecodeInst->Src[0].Literal());
    const uint32_t Final = MRFollowThunks(Target);
    if (Final != Target) {
      DecodeInst->Src[0].Data.Literal.Value = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(Final - Next)));
    }
    return;
  }
  if (!Mask || BlockInfo.Is64BitMode || DecodeInst->InstSize != 6 || DecodeInst->OPRaw != 0xFF || !DecodeInst->Src[0].IsRIPRelative()) {
    return;
  }
  const unsigned Bit = DecodeInst->ModRM == 0x15 ? 1u : DecodeInst->ModRM == 0x25 ? 2u : 0u;
  if (!(Mask & Bit)) {
    return;
  }
  const uint64_t Slot = static_cast<uint32_t>(DecodeInst->Src[0].Data.RIPLiteral.Value);
  uint32_t Target {};
  if ((Slot & 3) || !CTX->SyscallHandler->QueryGuestConstantData(Thread, Slot, sizeof(Target), &Target) || !Target) {
    FEXCore::Utils::MacRunnerImportRefused.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  FEXCore::Utils::MacRunnerImportBound[Bit - 1].fetch_add(1, std::memory_order_relaxed);
  BlockInfo.CodePages.insert(Slot & FEXCore::Utils::FEX_PAGE_MASK);
  DecodeInst->Src[0].Type = DecodedOperand::OpType::Literal;
  DecodeInst->Src[0].Data.Literal.Value = MRFollowThunks(Target); // REGION4-0003: the bound target may itself be a thunk
  DecodeInst->Src[0].Data.Literal.Size = 4;
}

// ★ REGION4 13.11.2026 REGION4-0003 MACRUNNER_FEX32_THUNK_SKIP=1 (MacRunnerXfer.h). Target is an import thunk when its bytes are exactly
// `FF 25 disp32` (`jmp dword ptr [abs32]`, no prefix) in executable, not writable code and the slot is a read-only image page
// (QueryGuestConstantData, as MRBindImport). Then a call / bound jump there goes straight to the slot's value: architecturally the
// thunk's jmp changes nothing but EIP. The thunk's bytes become bytes of this unit (page in CodePages, write trap armed before they
// are read, as for the unit's own code) and the slot's page a const-data page of this unit. Up to two hops. Off under the trap flag
// (x86 would single-step the thunk), while generating the code cache (relocations) and with MACRUNNER_FEX_REVIVE=1.
uint32_t Decoder::MRFollowThunks(uint32_t Target) {
  static const bool On = FEXCore::Utils::MacRunnerThunkSkip();
  if (!On || BlockInfo.Is64BitMode || Relocations || Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC]) {
    return Target;
  }
#ifdef _WIN32
  const auto SavedBase = ExecutableRangeBase, SavedEnd = ExecutableRangeEnd;
  const bool SavedWritable = ExecutableRangeWritable, SavedNoTrap = ExecutableRangeNoTrap;
  for (unsigned Hop = 0; Hop < 2; ++Hop) {
    const uint64_t Address = Target;
    if (Address + 6 > 0x100000000ULL || !CheckRangeExecutable(Address, 6) || ExecutableRangeWritable) {
      break;
    }
#ifndef REGION4_THUNK_NO_PAGES // diagnostic negative control only (probe thunkskip32 rewrites a thunk: it must then go stale)
    for (uint64_t Page : {Address & FEXCore::Utils::FEX_PAGE_MASK, (Address + 5) & FEXCore::Utils::FEX_PAGE_MASK}) {
      if (BlockInfo.CodePages.insert(Page).second) {
        CTX->SyscallHandler->MarkGuestExecutableRange(Thread, Page, FEXCore::Utils::FEX_PAGE_SIZE);
      }
    }
#endif
    const auto* P = reinterpret_cast<const uint8_t*>(Address);
    if (P[0] != 0xFF || P[1] != 0x25) {
      break;
    }
    uint32_t Slot {};
    memcpy(&Slot, P + 2, sizeof(Slot));
    uint32_t Next {};
    if ((Slot & 3) || !CTX->SyscallHandler->QueryGuestConstantData(Thread, Slot, sizeof(Next), &Next) || !Next) {
      FEXCore::Utils::MacRunnerThunkRefused.fetch_add(1, std::memory_order_relaxed);
      break;
    }
    BlockInfo.CodePages.insert(Slot & FEXCore::Utils::FEX_PAGE_MASK);
    FEXCore::Utils::MacRunnerThunkSkipped.fetch_add(1, std::memory_order_relaxed);
    Target = Next;
  }
  ExecutableRangeBase = SavedBase;
  ExecutableRangeEnd = SavedEnd;
  ExecutableRangeWritable = SavedWritable;
  ExecutableRangeNoTrap = SavedNoTrap;
#endif
  return Target;
}

// ★ REGION4 13.11.2026 (MACRUNNER_FEX32_EXIT_SCAN, MacRunnerXfer.h). One prefix-free x86-32 instruction at P (16 readable bytes):
// its length, the status flags it writes (bit 0 C, 1 P, 2 A, 3 Z, 4 S, 5 O) and whether the scan may continue past it.
// Only instructions whose OpcodeDispatcher handlers write (or invalidate) exactly these flags unconditionally and read none are
// listed; anything else stops the scan with "flags live". Kept deliberately small: prologues are push / mov / lea / sub / test / cmp.
// (MRScanStep / MRScanOne live in FEXCore/Utils/MacRunnerExitScan.h: the WOW64 suspend handler runs the same scan.)
using FEXCore::Utils::MRScanStep;
using FEXCore::Utils::MRScanOne;
using FEXCore::Utils::MRAllFlags;

bool Decoder::MRTargetKillsFlags(uint64_t Target, bool CountStats) {
#ifdef REGION4_SCAN_ALWAYS_DEAD // diagnostic negative control only (probe flagscan32 must then differ); never defined in a product build
  return true;
#endif
#ifdef _WIN32
  // The range cache describes the instruction stream being decoded; BranchTargetInMultiblockRange reads it right after us.
  const auto SavedBase = ExecutableRangeBase, SavedEnd = ExecutableRangeEnd;
  const bool SavedWritable = ExecutableRangeWritable, SavedNoTrap = ExecutableRangeNoTrap;
  bool Dead = false;
  unsigned Need = MRAllFlags;
  uint64_t Address = Target;
  for (unsigned Count = 0; Count < 24; ++Count) {
    constexpr uint64_t Window = 16; // >= the longest listed instruction (fs: + opcode + ModRM + SIB + disp32 + imm32 = 12)
    if (Address + Window > 0x100000000ULL || !CheckRangeExecutable(Address, Window) || ExecutableRangeWritable) {
      if (CountStats) FEXCore::Utils::MacRunnerExitScanWhy[ExecutableRangeWritable ? 1 : 0].fetch_add(1, std::memory_order_relaxed);
      break;
    }
    for (uint64_t Page : {Address & FEXCore::Utils::FEX_PAGE_MASK, (Address + Window - 1) & FEXCore::Utils::FEX_PAGE_MASK}) {
#ifndef REGION4_SCAN_NO_PAGES // diagnostic negative control only (the rewritten callee of flagscan32 must then get stale flags)
      if (BlockInfo.CodePages.insert(Page).second) {
        // As for the unit's own bytes: the write trap is armed before the bytes are read.
        CTX->SyscallHandler->MarkGuestExecutableRange(Thread, Page, FEXCore::Utils::FEX_PAGE_SIZE);
      }
#endif
    }
    const MRScanStep Step = MRScanOne(reinterpret_cast<const uint8_t*>(Address));
    if (!Step.Length) {
      if (CountStats) FEXCore::Utils::MacRunnerExitScanWhy[Count ? 3 : 2].fetch_add(1, std::memory_order_relaxed);
      break;
    }
    Need &= ~Step.Kills;
    if (!Need) {
      Dead = true;
      break;
    }
    Address += Step.Length;
  }
  ExecutableRangeBase = SavedBase;
  ExecutableRangeEnd = SavedEnd;
  ExecutableRangeWritable = SavedWritable;
  ExecutableRangeNoTrap = SavedNoTrap;
  return Dead;
#else
  return false; // guest bytes outside the unit are not addressable in the native stands
#endif
}

// Direct `call rel32` (E8, no prefix, not the get-PC form) or a call bound by MRBindImport (its operand is a literal by now).
void Decoder::MRScanCallTarget() {
  static const unsigned Mask = FEXCore::Utils::MacRunnerExitScanMask();
  if (!Mask || BlockInfo.Is64BitMode) {
    return;
  }
  uint64_t Target {};
  if (DecodeInst->OPRaw == 0xE8 && DecodeInst->InstSize == 5 && DecodeInst->Src[0].IsLiteral() && DecodeInst->Src[0].Literal() != 0) {
    Target = static_cast<uint32_t>(DecodeInst->PC + 5 + DecodeInst->Src[0].Literal());
  } else if (DecodeInst->OPRaw == 0xFF && DecodeInst->ModRM == 0x15 && DecodeInst->InstSize == 6 && DecodeInst->Src[0].IsLiteral()) {
    Target = static_cast<uint32_t>(DecodeInst->Src[0].Literal());
  } else {
    return;
  }
  if (MRTargetKillsFlags(Target)) {
    BlockInfo.MRFlagsDeadCalls.insert(DecodeInst->PC);
    FEXCore::Utils::MacRunnerExitScanDead.fetch_add(1, std::memory_order_relaxed);
  } else {
    FEXCore::Utils::MacRunnerExitScanLive.fetch_add(1, std::memory_order_relaxed);
  }
}

void Decoder::BranchTargetInMultiblockRange() {
  if (!CTX->Config.Multiblock) {
    return;
  }

  // If the RIP setting is conditional AND within our symbol range then it can be considered for multiblock
  uint64_t TargetRIP = 0;
  const auto GPRSize = GetGPROpSize();
  bool Conditional = true;
  const auto InstEnd = DecodeInst->PC + DecodeInst->InstSize;

  if (DecodeInst->TableInfo->Flags & FEXCore::X86Tables::InstFlags::FLAGS_CALL) {
    if (ExecutableRangeWritable && CTX->AreMonoHacksActive()) {
      // Mono generated code often contains noreturn calls with garbage following them, and calls are always backpatched
      // after CIL compilation leading to n recompiles for a multiblock with n calls. Choose to minimize stutters over
      // raw performance and disable tracking past calls for mono generated code.
      return;
    }

    AddBranchTarget(InstEnd);
    BlockInfo.EntryPoints.emplace(InstEnd);
    return;
  }

  // Calls are handled above
  switch (DecodeInst->OP) {
  case 0x70 ... 0x7F:   // Conditional JUMP
  case 0x80 ... 0x8F: { // More conditional
    // Source is a literal
    // auto RIPOffset = LoadSource(Op, Op->Src[0], Op->Flags);
    // auto RIPTargetConst = Constant(Op->PC + Op->InstSize);
    // Target offset is PC + InstSize + Literal
    TargetRIP = InstEnd + DecodeInst->Src[0].Literal();
    break;
  }
  case 0xE9:
  case 0xEB: // Both are unconditional JMP instructions
    TargetRIP = InstEnd + DecodeInst->Src[0].Literal();
    Conditional = false;
    break;
  case 0xC2: // RET imm
  case 0xC3: // RET
  default: return; break;
  }

  if (GPRSize == IR::OpSize::i32Bit) {
    // If we are running a 32bit guest then wrap around addresses that go above 32bit
    TargetRIP &= 0xFFFFFFFFU;
  }

  if (Conditional) {
    // If we are conditional then a target can be the instruction past the conditional instruction
    AddBranchTarget(InstEnd);
  }

  // If the target RIP is x86 code within the symbol ranges then we are golden
  // Forbid distant branches to have the cost code better match the guest code layout, avoiding massive (range-wise) code
  // blocks in highly fragmented guest code. Such branches are often not-taken branches to garbage in obfuscated code.
  constexpr uint64_t MAX_FORWARD_BRANCH_DIST = FEXCore::Utils::FEX_PAGE_SIZE * 4;
  bool ValidMultiblockMember = TargetRIP >= EntryPoint && TargetRIP < std::min(InstEnd + MAX_FORWARD_BRANCH_DIST, SectionMaxAddress);

#ifdef ARCHITECTURE_arm64ec
  ValidMultiblockMember = ValidMultiblockMember && !RtlIsEcCode(TargetRIP);
#endif

  if (ValidMultiblockMember) {
    // Update our conditional branch ranges before we return
    if (Conditional) {
      MaxCondBranchForward = std::max(MaxCondBranchForward, TargetRIP);
      MaxCondBranchBackwards = std::min(MaxCondBranchBackwards, TargetRIP);
    }

    AddBranchTarget(TargetRIP);
  } else {
    if (ExternalBranches) {
      ExternalBranches->insert(TargetRIP);
    }
  }
}

bool Decoder::IsBranchMonoTailcall(uint64_t NumInstructions) const {
  // While the mono call backpatching block can easily be detected due it being the only one to contain SMC-faulting
  // atomics, that can't be said for the tailcall jump backpatcher which has changed several times across versions and
  // can be partially inlined. To work around this, instead detect the tailcall site itself and force full non-signal-based
  // SMC detection for that single block.
  if (!ExecutableRangeWritable) {
    // We only care about jitted code
    return false;
  }

  // See mini-{amd64,x86}.c in the mono codebase, specifically where METHOD_JUMP patches are emitted.
  if (GetGPROpSize() == IR::OpSize::i32Bit) {
    // Matches:
    // LEAVE
    // <none> / NOP / MOV EAX, EAX / LEA EBP, [EBP+0]
    // JMP imm32
    if (DecodeInst->OP != 0xE9 || NumInstructions < 2) {
      return false;
    }

    auto PrevInst = std::prev(DecodeInst);
    if (PrevInst->OP == 0xC9) {
      return true;
    }

    if (NumInstructions < 3 || std::prev(PrevInst)->OP != 0xC9) {
      return false;
    }

    return PrevInst->OP == 0x90 || (PrevInst->OP == 0x8B && PrevInst->ModRM == 0xC0) ||
           (PrevInst->OP == 0x8D && PrevInst->ModRM == 0x6D && PrevInst->Src[1].IsLiteral() && PrevInst->Src[1].Literal() == 0);
  } else {
    FEXCore::X86Tables::ModRMDecoded ModRM;
    ModRM.Hex = DecodeInst->ModRM;
    if (DecodeInst->OPRaw == 0xFF && ModRM.reg == 4 && DecodeInst->Src[0].IsGPR()) {
      if (DecodeInst->Src[0].Data.GPR.GPR == FEXCore::X86State::REG_RAX) {
        // Found in versions of mono from 2024 onwards - matches:
        // REX.W JMP rax
        return (DecodeInst->Flags & (DecodeFlags::FLAG_REX_PREFIX | DecodeFlags::FLAG_REX_WIDENING | DecodeFlags::FLAG_REX_XGPR_B |
                                     DecodeFlags::FLAG_REX_XGPR_X | DecodeFlags::FLAG_REX_XGPR_R)) ==
               (DecodeFlags::FLAG_REX_PREFIX | DecodeFlags::FLAG_REX_WIDENING);
      } else if (NumInstructions > 1 && DecodeInst->Src[0].Data.GPR.GPR == FEXCore::X86State::REG_R11) {
        // Found in older versions of mono - match:
        // MOV r11, imm64
        // JMP r11
        auto PrevInst = std::prev(DecodeInst);
        return PrevInst->OP == 0xBB && PrevInst->Dest.IsGPR() && PrevInst->Dest.Data.GPR.GPR == FEXCore::X86State::REG_R11;
      }
    }
  }

  return false;
}

bool Decoder::InstCanContinue() const {
  if (DecodeInst->PC + DecodeInst->InstSize == NextBlockStartAddress) {
    return false;
  }

  if (!(DecodeInst->TableInfo->Flags & (FEXCore::X86Tables::InstFlags::FLAGS_BLOCK_END | FEXCore::X86Tables::InstFlags::FLAGS_SETS_RIP))) {
    return true;
  }

  uint64_t TargetRIP = 0;
  const auto GPRSize = GetGPROpSize();

  if (DecodeInst->OP == 0xE8) { // Call - immediate target
    const uint64_t NextRIP = DecodeInst->PC + DecodeInst->InstSize;
    TargetRIP = DecodeInst->PC + DecodeInst->InstSize + DecodeInst->Src[0].Literal();

    if (GPRSize == IR::OpSize::i32Bit) {
      // If we are running a 32bit guest then wrap around addresses that go above 32bit
      TargetRIP &= 0xFFFFFFFFU;
    }

    if (TargetRIP == NextRIP) {
      // Optimize the case that the instruction is jumping just after itself.
      // This is a GOT calculation which we can optimize out.
      // Optimization occurs inside of the OpDispatcher implementation
      return true;
    }
  }

  return false;
}

void Decoder::AddBranchTarget(uint64_t Target) {
  if (VisitedBlocks.contains(Target)) {
    return;
  }

  auto BlockSuccIt = std::lower_bound(BlockInfo.Blocks.begin(), BlockInfo.Blocks.end(), Target,
                                      [](const auto& a, uint64_t Address) { return a.Entry < Address; });

  LOGMAN_THROW_A_FMT(BlockSuccIt == BlockInfo.Blocks.end() || BlockSuccIt->Entry != Target, "unexpected");

  if (BlockSuccIt != BlockInfo.Blocks.begin()) {
    auto BlockIt = std::prev(BlockSuccIt);
    if (BlockIt->Entry + BlockIt->Size > Target) {
      uint64_t SplitIdx = 0;
      uint64_t SplitAddr = BlockIt->Entry;
      // Find the instruction boundary of the split
      for (; SplitIdx < BlockIt->NumInstructions && SplitAddr < Target; SplitIdx++) {
        SplitAddr += BlockIt->DecodedInstructions[SplitIdx].InstSize;
      }
      uint64_t SplitOffset = SplitAddr - BlockIt->Entry;

      LOGMAN_THROW_A_FMT(SplitIdx != 0, "unexpected");

      if (SplitAddr == Target) {
        // Split at the boundary
        DecodedBlocks SplitBlock {
          .Entry = SplitAddr,
          .Size = BlockIt->Size - SplitOffset,
          .NumInstructions = BlockIt->NumInstructions - SplitIdx,
          .DecodedInstructions = BlockIt->DecodedInstructions + SplitIdx,
          .BlockStatus = BlockIt->BlockStatus,
        };

        BlockIt->Size = SplitOffset;
        BlockIt->NumInstructions = SplitIdx;

        BlockInfo.Blocks.insert(BlockSuccIt, SplitBlock);
      } // else misaligned, leave as a branch out of the block

      // If we split a block then the target has already been visited as part of that, if it was
      // misaligned the jump will just leave the multiblock, mark it as visited to avoid running
      // this code path again and just bail out early.
      VisitedBlocks.insert(Target);
      return;
    }
  }

  CurrentBlockTargets.insert(Target);
  if (Target >= DecodeInst->PC + DecodeInst->InstSize && Target < NextBlockStartAddress) {
    NextBlockStartAddress = Target;
  }
}

const Decoder::DecodeStream Decoder::AdjustAddrForSpecialRegion(const uint8_t* _InstStream, uint64_t EntryPoint, uint64_t RIP) {
  constexpr uint64_t VSyscall_Base = 0xFFFF'FFFF'FF60'0000ULL;
  constexpr uint64_t VSyscall_End = VSyscall_Base + 0x1000;

  if (OSABI == FEXCore::HLE::SyscallOSABI::OS_LINUX64 && RIP >= VSyscall_Base && RIP < VSyscall_End) {
    // VSyscall
    // This doesn't exist on AArch64 and on x86_64 hosts this is emulated with faults to a region mapped with --xp permissions
    // Offset     0: vgettimeofday
    // Offset 0x400: vtime
    // Offset 0x800: vgetcpu
    uint64_t Offset = RIP - VSyscall_Base;
    return DecodeStream {
      .InstStream = _InstStream - EntryPoint + RIP,
      .AdjustedInstStream = VSyscallData + Offset,
    };
  }

  return DecodeStream {
    .InstStream = _InstStream - EntryPoint + RIP,
    .AdjustedInstStream = _InstStream - EntryPoint + RIP,
  };
}

bool Decoder::CheckIfCacheable(FEXCore::Core::InternalThreadState& Thread, const uint8_t* InstStream, uint64_t PC, uint64_t MaxInst) {
  DecodeInstructionsAtEntry(&Thread, InstStream, PC, MaxInst);
  bool Uncacheable = HitBadRelocation;
  DelayedDisownBuffer();
  return !Uncacheable;
}

void Decoder::DecodeInstructionsAtEntry(FEXCore::Core::InternalThreadState* Thread, const uint8_t* _InstStream, uint64_t PC, uint64_t MaxInst) {
  FEXCORE_PROFILE_SCOPED("DecodeInstructions");
  BlockInfo.TotalInstructionCount = 0;
  BlockInfo.Blocks.clear();
  BlockInfo.Native32Folds.clear();
  VisitedBlocks.clear();
  // Reset internal state management
  DecodedSize = 0;
  MaxCondBranchForward = 0;
  MaxCondBranchBackwards = ~0ULL;
  DecodedBuffer = PoolObject.ReownOrClaimBuffer();

  // Decode operating mode from thread's CS segment.
  const auto CSSegment = Core::CPUState::GetSegmentFromIndex(Thread->CurrentFrame->State, Thread->CurrentFrame->State.cs_idx);
  BlockInfo.Is64BitMode = CSSegment->L == 1;
  LOGMAN_THROW_A_FMT(BlockInfo.Is64BitMode == CTX->Config.Is64BitMode, "Expected operating mode to not change at runtime!");

  EntryPoint = PC;
  BlockInfo.EntryPoints = {PC};

  uint64_t TotalInstructions {};

  SectionMinAddress = 0;
  SectionMaxAddress = ~0ULL;
  Relocations = nullptr;

  if (CTX->GetCodeCache().IsGeneratingCache || EnableCodeCacheValidation) {
    // If generating cache, attempt to load section bounds and relocations
    if (auto SectionInfo = CTX->SyscallHandler->LookupExecutableFileSection(Thread, EntryPoint)) {
      SectionMinAddress = SectionInfo->FileStartVA;
      SectionMaxAddress = SectionInfo->EndVA;
      Relocations = &SectionInfo->FileInfo.Relocations;
    }
  }

  DecodedMinAddress = EntryPoint;
  DecodedMaxAddress = EntryPoint;

  // Entry is a jump target
  BlocksToDecode = {PC};
  BlockInfo.MRFlagsDeadCalls.clear(); // REGION4 EXIT_SCAN
  BlockInfo.MRWindowEntries.clear();
  BlockInfo.MRWindowEntriesUnit = PC;

#ifdef _WIN32
  BlockInfo.CodePages.clear();
  const auto AddCodePage = [&](uint64_t Page) {
    if (BlockInfo.CodePages.insert(Page).second) {
      // CompileBlock holds CodeInvalidationMutex shared through publication.
      // Arm the write trap BEFORE reading instruction bytes: a writer whose
      // previous fault already unprotected this page must fault again and wait
      // for publication, then invalidate the translation before its store.
      // Protecting only after CompileCode can publish a translation of old bytes.
      CTX->SyscallHandler->MarkGuestExecutableRange(Thread, Page, FEXCore::Utils::FEX_PAGE_SIZE);
    }
  };
#else
  uint64_t CurrentCodePage = PC & FEXCore::Utils::FEX_PAGE_MASK;
  BlockInfo.CodePages = {CurrentCodePage};
#endif

  if (MaxInst == 0) {
    MaxInst = CTX->Config.MaxInstPerBlock;
  }

  bool EntryBlock {true};
  bool FinalInstruction {false};

  // ★ MacRunner NATIVE32 (MACRUNNER_FEX32_NATIVE32, FEXCore/Utils/MacRunnerNative32.h): a `call rel32` / `call [disp32]` whose
  //   target is exactly a marked i386 Wine leaf is recorded as a fold and does not end the block. Everything that is not certain
  //   keeps the plain call: prefixes, writable caller code (JIT / unpacked), code-cache generation (relocations), a slot that
  //   cannot be read safely, a target outside an executable range, bytes that differ from the leaf template.
  const uint32_t MRN32Mask =
    BlockInfo.Is64BitMode || !CTX->SyscallHandler->MRNative32Supported() ? 0 : FEXCore::Utils::MacRunnerNative32Mask();
  // NATIVE32-0005: the return block of the last folded TlsGetValue of this unit: a `call eax` among its first instructions is the
  // CRT's FLS_GETVALUE shape and is speculated on the FlsGetValue leaf (MacRunnerNative32.h).
  uint64_t MRN32FlsHintBlock = ~0ULL;
  const auto MRN32TryFold = [&](uint64_t BlockEntry, uint64_t InstInBlock) -> bool {
    using namespace FEXCore::X86Tables::DecodeFlags;
    const auto* Info = DecodeInst->TableInfo;
    if (!Info || !(Info->Flags & FEXCore::X86Tables::InstFlags::FLAGS_CALL) || Relocations || HitBadRelocation ||
        CTX->GetCodeCache().IsGeneratingCache) {
      return false;
    }
    if (DecodeInst->Flags & (FLAG_OPERAND_SIZE | FLAG_ADDRESS_SIZE | FLAG_SEGMENTS | FLAG_LOCK | FLAG_REP_PREFIX | FLAG_REPNE_PREFIX)) {
      return false;
    }
    if (ExecutableRangeWritable || ExecutableRangeNoTrap) {
      return false;
    }
    const uint64_t NextRIP = DecodeInst->PC + DecodeInst->InstSize;
    uint64_t Slot = 0, Target = 0;
    auto Guard = FEXCore::Utils::MRN32Guard::None;
    if (DecodeInst->OP == 0xE8 && DecodeInst->Src[0].IsLiteral()) {
      // (REGION4-0003 THUNK_SKIP may have rewritten the rel32 to the thunk's final target: that target is what is folded.)
      Target = (NextRIP + DecodeInst->Src[0].Literal()) & 0xFFFFFFFFULL;
      if (Target == NextRIP) {
        return false;   // `call $+5` (GOT computation): the next instruction is not a callee
      }
    } else if (DecodeInst->OPRaw == 0xFF && DecodeInst->ModRM == 0x15 && DecodeInst->InstSize == 6 && DecodeInst->Src[0].IsLiteral()) {
      // NATIVE32-0005: REGION4-0001 IMPORT_BIND bound the slot (Decoder::MRBindImport): its page is a const-data page of this unit and
      // the operand is the slot's value (thunks followed). No guard: the value is a constant of the translation.
      Target = static_cast<uint64_t>(DecodeInst->Src[0].Literal()) & 0xFFFFFFFFULL;
    } else if (DecodeInst->OPRaw == 0xFF && ((DecodeInst->ModRM >> 3) & 7) == 2 && DecodeInst->Src[0].IsRIPRelative()) {
      Slot = static_cast<uint64_t>(DecodeInst->Src[0].Data.RIPLiteral.Value) & 0xFFFFFFFFULL;
      uint32_t Value = 0;
      // NATIVE32-0005: a slot of a read-only image page is a constant of the translation by the same mechanism (REGION4's const-data
      // pages); the bind key, when on, already asked and was refused -- do not ask twice.
      if (!(FEXCore::Utils::MacRunnerImportBindMask() & 1) && !(Slot & 3) &&
          CTX->SyscallHandler->QueryGuestConstantData(Thread, Slot, sizeof(Value), &Value) && Value) {
        BlockInfo.CodePages.insert(Slot & FEXCore::Utils::FEX_PAGE_MASK);
        Target = Value;
        Slot = 0;
      } else if (CTX->SyscallHandler->MRReadGuestData(Slot, &Value, sizeof(Value))) {
        Target = Value;
        Guard = FEXCore::Utils::MRN32Guard::Slot;   // writable slot: load + compare at run time
      } else {
        FEXCore::Utils::MRN32SlotUnreadable.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
    } else if (DecodeInst->OPRaw == 0xFF && DecodeInst->ModRM == 0xD0 && DecodeInst->InstSize == 2 && BlockEntry == MRN32FlsHintBlock &&
               InstInBlock <= 3) {
      // NATIVE32-0005: `call eax` right after a folded TlsGetValue: speculate the FlsGetValue leaf; guard eax == T at run time.
      const uint64_t Hint = FEXCore::Utils::MRN32FlsHint.load(std::memory_order_acquire);
      if (Hint <= 1) {
        return false;
      }
      Target = Hint;
      Guard = FEXCore::Utils::MRN32Guard::Eax;
    } else {
      return false;
    }
    // The decoder's range cache belongs to the caller's code: keep it across the look at the target.
    const uint64_t SavedBase = ExecutableRangeBase, SavedEnd = ExecutableRangeEnd;
    const bool SavedWritable = ExecutableRangeWritable, SavedNoTrap = ExecutableRangeNoTrap;
    const auto Restore = [&] {
      ExecutableRangeBase = SavedBase;
      ExecutableRangeEnd = SavedEnd;
      ExecutableRangeWritable = SavedWritable;
      ExecutableRangeNoTrap = SavedNoTrap;
    };
    bool Folded = false;
    if (CheckRangeExecutable(Target, FEXCore::Utils::MRN32PrefixSize) && !ExecutableRangeWritable && !ExecutableRangeNoTrap) {
      const auto* Bytes = reinterpret_cast<const uint8_t*>(Target);
      const uint32_t Id = FEXCore::Utils::MRN32MarkId(Bytes);
      const uint64_t Size = Id ? FEXCore::Utils::MRN32LeafSize(Id) : 0;
      if (Size && (MRN32Mask & (1U << (Id - 1))) && CheckRangeExecutable(Target, Size) && !ExecutableRangeWritable && !ExecutableRangeNoTrap) {
        // The fold depends on these bytes: arm the write trap on their pages BEFORE the comparison that decides it (as for the
        // unit's own instruction bytes), then compare. A later write invalidates this unit through its code pages.
#ifdef _WIN32
        AddCodePage(Target & FEXCore::Utils::FEX_PAGE_MASK);
        AddCodePage((Target + Size - 1) & FEXCore::Utils::FEX_PAGE_MASK);
#else
        BlockInfo.CodePages.insert(Target & FEXCore::Utils::FEX_PAGE_MASK);
        BlockInfo.CodePages.insert((Target + Size - 1) & FEXCore::Utils::FEX_PAGE_MASK);
#endif
        if (FEXCore::Utils::MRN32LeafMatches(Bytes, Id)) {
          BlockInfo.Native32Folds[DecodeInst->PC] = FEXCore::Utils::MRN32Fold {Id, Target, Slot, Size, Guard};
          Folded = true;
          if (Id == 3 && (MRN32Mask & 8)) {
            // NATIVE32-0005: the FlsGetValue leaf of the same module, by its export (once per process; a hint: verified at use).
            //   A TlsGetValue leaf outside kernel32 (a byte copy in some other module) has no such export: not cached, retried by
            //   the next TlsGetValue fold; after 64 refusals the lookup stops for the process (hint 1 = none).
            uint64_t Hint = FEXCore::Utils::MRN32FlsHint.load(std::memory_order_acquire);
            if (!Hint) {
              const uint64_t Found = CTX->SyscallHandler->MRFindGuestExport(Target, "FlsGetValue");
              if (Found) {
                FEXCore::Utils::MRN32FlsHint.compare_exchange_strong(Hint, Found, std::memory_order_acq_rel);
              } else if (FEXCore::Utils::MRN32FlsLookupMisses.fetch_add(1, std::memory_order_relaxed) >= 63) {
                FEXCore::Utils::MRN32FlsHint.compare_exchange_strong(Hint, 1, std::memory_order_acq_rel);
              }
            }
            MRN32FlsHintBlock = NextRIP;
          }
        }
      }
      if (Id && !Folded) {
        FEXCore::Utils::MRN32Refused.fetch_add(1, std::memory_order_relaxed);
      }
    }
    Restore();
    return Folded;
  };

  while (!FinalInstruction && !BlocksToDecode.empty()) {
    auto BlockDecodeIt = BlocksToDecode.begin();
    uint64_t RIPToDecode = *BlockDecodeIt;
    BlocksToDecode.erase(BlockDecodeIt);
    VisitedBlocks.emplace(RIPToDecode);

    auto BlockSuccIt = std::lower_bound(BlockInfo.Blocks.begin(), BlockInfo.Blocks.end(), RIPToDecode,
                                        [](const auto& a, uint64_t Address) { return a.Entry < Address; });

    LOGMAN_THROW_A_FMT(BlockSuccIt == BlockInfo.Blocks.end() || BlockSuccIt->Entry != RIPToDecode, "unexpected");

    NextBlockStartAddress = ~0ULL;
    if (!BlocksToDecode.empty()) {
      // We just erased the lowest, the front is then the second lowest
      NextBlockStartAddress = *BlocksToDecode.begin();
    }
    if (BlockSuccIt != BlockInfo.Blocks.end() && BlockSuccIt->Entry < NextBlockStartAddress) {
      NextBlockStartAddress = BlockSuccIt->Entry;
    }
    LOGMAN_THROW_A_FMT(NextBlockStartAddress > RIPToDecode, "unexpected");

    // Insert the block now so it can be looked up and split if necessary on a backward edge
    auto BlockIt = BlockInfo.Blocks.emplace(BlockSuccIt);

    BlockIt->Entry = RIPToDecode;
    BlockIt->Size = 0;
    BlockIt->IsEntryPoint = EntryBlock;

    uint64_t PCOffset = 0;
    uint64_t BlockStartOffset = DecodedSize;
    bool EraseBlock = true; // Unset once the block contains an instruction

    BlockIt->DecodedInstructions = &DecodedBuffer[BlockStartOffset];
    BlockIt->NumInstructions = 0;

    // Do a bit of pointer math to figure out where we are in code
    InstStream = AdjustAddrForSpecialRegion(_InstStream, EntryPoint, RIPToDecode);

    while (1) {
      InstructionSize = 0;

      // MAX_INST_SIZE assumes worst case
      auto OpAddress = RIPToDecode + PCOffset;
      auto OpMaxAddress = OpAddress + MAX_INST_SIZE;

      auto OpMinPage = OpAddress & FEXCore::Utils::FEX_PAGE_MASK;
      auto OpMaxPage = OpMaxAddress & FEXCore::Utils::FEX_PAGE_MASK;

#ifdef _WIN32
      // This also covers PeekByte below and operands crossing a page boundary.
      AddCodePage(OpMinPage);
      AddCodePage(OpMaxPage);
#endif

      if (!EntryBlock && OpMinPage == OpMaxPage && PeekByte(0).value_or(0) == 0 && PeekByte(1).value_or(0) == 0) [[unlikely]] {
        // End the multiblock early if we hit 2 consecutive null bytes (add [rax], al) in the same page with the
        // assumption we are most likely trying to explore garbage code.
        break;
      }

#ifndef _WIN32
      if (OpMinPage != CurrentCodePage) {
        CurrentCodePage = OpMinPage;
        BlockInfo.CodePages.insert(CurrentCodePage);
      }

      if (OpMaxPage != CurrentCodePage) {
        CurrentCodePage = OpMaxPage;
        BlockInfo.CodePages.insert(CurrentCodePage);
      }
#endif

      BlockIt->BlockStatus = DecodeInstruction(OpAddress);
      if (HitBadRelocation) {
        BlockInfo.TotalInstructionCount = 0;
        BlockInfo.Blocks = {*BlockIt};
        BlockInfo.EntryPoints.clear();
        BlockInfo.CodePages.clear();
        BlockInfo.Native32Folds.clear();
        return;
      }
      uint64_t OpEndAddress = OpAddress + DecodeInst->InstSize;

      DecodedMinAddress = std::min(DecodedMinAddress, OpAddress);
      DecodedMaxAddress = std::max(DecodedMaxAddress, OpEndAddress);

      if (OpEndAddress > NextBlockStartAddress) {
        // This instruction would overlap with another so skip adding it to the multiblock
        break;
      }

      EraseBlock = false; // Block contains at least one valid instruction, so unset erase
      ++TotalInstructions;
      ++DecodedSize;
      ++BlockIt->NumInstructions;
      BlockIt->Size += DecodeInst->InstSize;

      // Can not continue this block at all on invalid instruction
      if (BlockIt->BlockStatus != DecodedBlockStatus::SUCCESS) [[unlikely]] {
        if (!EntryBlock && BlockIt->BlockStatus != DecodedBlockStatus::BAD_RELOCATION) {
          // In multiblock configurations, we can early terminate any non-entrypoint blocks with the expectation that this won't get hit.
          // Improves compile-times.
          // Just need to undo additions that this block decoding has caused.
          TotalInstructions -= BlockIt->NumInstructions;
          DecodedSize = BlockStartOffset;
          InstStream -= PCOffset;
          EraseBlock = true;
        } else {
          LogMan::Msg::EFmt("{} instruction in entry block: {:X}",
                            BlockIt->BlockStatus == DecodedBlockStatus::INVALID_INST       ? "Invalid" :
                            BlockIt->BlockStatus == DecodedBlockStatus::NOEXEC_INST        ? "NoExec" :
                            BlockIt->BlockStatus == DecodedBlockStatus::BAD_RELOCATION     ? "BadRelocation" :
                            BlockIt->BlockStatus == DecodedBlockStatus::UNIMPLEMENTED_INST ? "Unimplemented" :
                                                                                             "PartialDecode",
                            OpAddress);
        }
        break;
      }

      MRBindImport(); // REGION4: before anything reads the operand of this instruction
      MRScanCallTarget();

      // Check if we need to end the entire multiblock
      FinalInstruction = DecodedSize >= MaxInst || DecodedSize >= DefaultDecodedBufferSize || TotalInstructions >= MaxInst;
      if (FinalInstruction) {
        break;
      }

      // ★ MacRunner NATIVE32: a folded call keeps the block layout of a call: the block ends here and the return address stays an
      //   entry point of the unit, so the fold's fast path falls through into it and every slow path (the original call) returns
      //   into the same unit exactly as before (call-return landing, inline target cache).
      if (MRN32Mask && MRN32TryFold(BlockIt->Entry, BlockIt->NumInstructions)) {
        // NATIVE32-0005: a fold with NO slow path (GetLastError / SetLastError, no guard) is a straight-line instruction: nothing
        // returns to its next address, so the block goes on (no block end, no entry point there, no `b` over an entry header).
        const auto& Fold = BlockInfo.Native32Folds[DecodeInst->PC];
        if (Fold.Guard == FEXCore::Utils::MRN32Guard::None && (Fold.Id == 1 || Fold.Id == 2)) {
          if (DecodeInst->PC + DecodeInst->InstSize == NextBlockStartAddress) {
            break;   // the next block starts right after the fold: fall into it
          }
          PCOffset += DecodeInst->InstSize;
          InstStream += DecodeInst->InstSize;
          continue;
        }
      }

      if (!InstCanContinue()) {
        if (DecodeInst->TableInfo->Flags & FEXCore::X86Tables::InstFlags::FLAGS_SETS_RIP) {
          // If we have multiblock enabled
          // If the branch target is within our multiblock range then we can keep going on
          // We don't want to short circuit this since we want to calculate our ranges still
          // NOTE: This will invalidate BlockIt, this is fine as we immediately break from the loop and EraseBlock cannot be true
          BlockIt->ForceFullSMCDetection = CTX->AreMonoHacksActive() && IsBranchMonoTailcall(BlockIt->NumInstructions);
          BranchTargetInMultiblockRange();
        }

        break;
      }

      PCOffset += DecodeInst->InstSize;
      InstStream += DecodeInst->InstSize;
    }

    // NOTE: BlockIt is only valid here in the EraseBlock case
    if (EraseBlock) {
      BlockInfo.Blocks.erase(BlockIt);
    } else {
      BlocksToDecode.merge(CurrentBlockTargets);
    }

    CurrentBlockTargets.clear();
    EntryBlock = false;
  }

  BlockInfo.TotalInstructionCount = TotalInstructions;

  for (auto& Block : BlockInfo.Blocks) {
    Block.IsEntryPoint = BlockInfo.EntryPoints.contains(Block.Entry);
  }

  // ★ REGION4 EXIT_SCAN v2 (precise suspend): entry points of this unit whose own first instructions overwrite every status flag before
  // reading any -- the windows a flags-dead call (MRScanCallTarget in some caller) may enter with undefined flags. The JIT marks
  // their entry poll (WindowSuspendFaultOffset); the WOW64 suspend handler does not stop the thread there when it came by a call.
  if (FEXCore::Utils::MacRunnerExitScanMask() && !BlockInfo.Is64BitMode) {
    for (auto& Block : BlockInfo.Blocks) {
      if (Block.IsEntryPoint && MRTargetKillsFlags(Block.Entry, false)) {
        BlockInfo.MRWindowEntries.insert(Block.Entry);
      }
    }
  }
}

} // namespace FEXCore::Frontend
