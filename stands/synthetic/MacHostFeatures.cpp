// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
#include "Common/HostFeatures.h"
#include "MacHostFeatures.h"

#include <FEXCore/Core/HostFeatures.h>
#include <sys/sysctl.h>
#include <cstdio>
#include <cstring>

namespace {
int Feat(const char* Name) {
  char Full[128];
  snprintf(Full, sizeof(Full), "hw.optional.arm.%s", Name);
  int Value = 0;
  size_t Size = sizeof(Value);
  if (sysctlbyname(Full, &Value, &Size, nullptr, 0) != 0) {
    return 0;
  }
  return Value;
}
uint64_t Field(uint64_t Value, unsigned Offset) {
  return (Value & 0xF) << Offset;
}
} 

namespace FEX {
class CPUFeaturesMac final : public CPUFeatures {
public:
  explicit CPUFeaturesMac(bool Product) {
    uint64_t ISAR0v = 0, ISAR1v = 0, ISAR2v = 0, PFR0v = 0, PFR1v = 0, MMFR1v = 0, MMFR2v = 0;
    if (Product) {
      
      if (Feat("FEAT_LSE")) {
        ISAR0v |= 2ull << 20;
      }
      if (Feat("FEAT_FlagM")) {
        uint64_t Level = Feat("FEAT_FlagM2") ? 2 : 1;
        ISAR0v |= Level << 52;
      }
      if (Feat("FEAT_LRCPC")) {
        uint64_t Level = Feat("FEAT_LRCPC2") ? 2 : 1;
        ISAR1v |= Level << 20;
      }
    } else {
      ISAR0v |= Field(Feat("FEAT_PMULL") ? 2 : (Feat("FEAT_AES") ? 1 : 0), 4);
      ISAR0v |= Field(Feat("FEAT_SHA1"), 8);
      ISAR0v |= Field(Feat("FEAT_SHA512") ? 2 : (Feat("FEAT_SHA256") ? 1 : 0), 12);
      ISAR0v |= Field(Feat("FEAT_CRC32"), 16);
      ISAR0v |= Field(Feat("FEAT_LSE") ? 2 : 0, 20);
      ISAR0v |= Field(Feat("FEAT_RDM"), 28);
      ISAR0v |= Field(Feat("FEAT_SHA3"), 32);
      ISAR0v |= Field(Feat("FEAT_DotProd"), 44);
      ISAR0v |= Field(Feat("FEAT_FHM"), 48);
      ISAR0v |= Field(Feat("FEAT_FlagM2") ? 2 : (Feat("FEAT_FlagM") ? 1 : 0), 52);

      ISAR1v |= Field(Feat("FEAT_DPB2") ? 2 : (Feat("FEAT_DPB") ? 1 : 0), 0);
      ISAR1v |= Field(Feat("FEAT_JSCVT"), 12);
      ISAR1v |= Field(Feat("FEAT_FCMA"), 16);
      ISAR1v |= Field(Feat("FEAT_LRCPC2") ? 2 : (Feat("FEAT_LRCPC") ? 1 : 0), 20);
      ISAR1v |= Field(Feat("FEAT_FRINTTS"), 32);
      ISAR1v |= Field(Feat("FEAT_SB"), 36);
      ISAR1v |= Field(Feat("FEAT_BF16"), 44);
      ISAR1v |= Field(Feat("FEAT_I8MM"), 52);

      ISAR2v |= Field(Feat("FEAT_WFxT") ? 2 : 0, 0);
      ISAR2v |= Field(Feat("FEAT_RPRES"), 4);
      ISAR2v |= Field(Feat("FEAT_CSSC"), 52);

      PFR0v |= Field(1, 0) | Field(1, 4); 
      PFR0v |= Field(Feat("FEAT_FP16") ? 1 : 0, 16);
      PFR0v |= Field(Feat("FEAT_FP16") ? 1 : 0, 20);
      PFR0v |= Field(Feat("FEAT_DIT"), 48);
      PFR0v |= Field(Feat("FEAT_CSV2"), 56);
      PFR0v |= Field(Feat("FEAT_CSV3"), 60);

      PFR1v |= Field(Feat("FEAT_BTI"), 0);
      PFR1v |= Field(Feat("FEAT_SSBS") ? 2 : 0, 4);

      MMFR1v |= Field(Feat("FEAT_AFP"), 44);
      MMFR2v |= Field(Feat("FEAT_LSE2"), 32);
    }

    uint64_t DCZIDv = 0;
    __asm volatile("mrs %[r], dczid_el0" : [r] "=r"(DCZIDv));

    ISAR0.SetReg(ISAR0v);
    ISAR1.SetReg(ISAR1v);
    ISAR2.SetReg(ISAR2v);
    PFR0.SetReg(PFR0v);
    PFR1.SetReg(PFR1v);
    MMFR1.SetReg(MMFR1v);
    MMFR2.SetReg(MMFR2v);
    DCZID.SetReg(DCZIDv);
    FillFeatureFlags();
    Regs = {ISAR0v, ISAR1v, ISAR2v, PFR0v, PFR1v, MMFR1v, MMFR2v, DCZIDv};
  }
  struct {
    uint64_t ISAR0, ISAR1, ISAR2, PFR0, PFR1, MMFR1, MMFR2, DCZID;
  } Regs {};
};
} 

FEXCore::HostFeatures FetchHostFeaturesMac(bool Product, char* Describe, size_t DescribeSize) {
  FEX::CPUFeaturesMac Features(Product);
  
  
  const uint64_t CTR = 0;
  
  const uint64_t MIDR = 0;
  FEXCore::HostFeatures HostFeatures = {};
  
  FEX::FetchHostFeatures(Features, HostFeatures, /*SupportsCacheMaintenanceOps=*/!Product, CTR, MIDR);
  HostFeatures.SupportsCPUIndexInTPIDRRO = false;
  if (Product) {
    
    HostFeatures.SupportsSVE128 = false;
    HostFeatures.SupportsSVE256 = false;
    HostFeatures.HostType = FEXCore::HostFeatures::HostTypeEnum::Arm64ec;
    
    HostFeatures.Supports3DNow = false;
  } else {
    HostFeatures.HostType = FEXCore::HostFeatures::HostTypeEnum::Linux;
  }
  if (Describe) {
    snprintf(Describe, DescribeSize,
             "mode=%s ISAR0=%016llx ISAR1=%016llx ISAR2=%016llx PFR0=%016llx MMFR2=%016llx DCZID=%llx CTR=%llx "
             "atomics=%d rcpc=%d tsoimm9=%d flagm=%d flagm2=%d frintts=%d afp=%d sve128=%d avx=%d crc=%d aes=%d sha=%d "
             "pmull128=%d fcma=%d clzero=%d dcline=%u icline=%u float_exc=%d 3dnow=%d preserve_all=%d hosttype=%d",
             Product ? "product" : "native", (unsigned long long)Features.Regs.ISAR0, (unsigned long long)Features.Regs.ISAR1,
             (unsigned long long)Features.Regs.ISAR2, (unsigned long long)Features.Regs.PFR0,
             (unsigned long long)Features.Regs.MMFR2, (unsigned long long)Features.Regs.DCZID, (unsigned long long)CTR,
             HostFeatures.SupportsAtomics, HostFeatures.SupportsRCPC, HostFeatures.SupportsTSOImm9, HostFeatures.SupportsFlagM,
             HostFeatures.SupportsFlagM2, HostFeatures.SupportsFRINTTS, HostFeatures.SupportsAFP, HostFeatures.SupportsSVE128,
             HostFeatures.SupportsAVX, HostFeatures.SupportsCRC, HostFeatures.SupportsAES, HostFeatures.SupportsSHA,
             HostFeatures.SupportsPMULL_128Bit, HostFeatures.SupportsFCMA, HostFeatures.SupportsCLZERO,
             (unsigned)HostFeatures.DCacheLineSize, (unsigned)HostFeatures.ICacheLineSize, HostFeatures.SupportsFloatExceptions,
             HostFeatures.Supports3DNow, HostFeatures.SupportsPreserveAllABI, (int)HostFeatures.HostType);
  }
  return HostFeatures;
}
