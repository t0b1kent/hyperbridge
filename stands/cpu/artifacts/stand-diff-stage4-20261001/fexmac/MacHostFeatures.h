#pragma once
#include <FEXCore/Core/HostFeatures.h>
#include <cstddef>

// Mode: "product" — ровно тот набор, что видит FEX продукта под Wine на macOS
//                   (engine/wine/dlls/ntdll/unix/system.c: get_core_id_regs_arm64, ветка __APPLE__):
//                   ISAR0 = LSE + FlagM(2), ISAR1 = LRCPC(2), остальные ID-регистры НУЛЕВЫЕ,
//                   CTR/MIDR не заданы; далее как Source/Windows/Common/CPUFeatures.cpp
//                   (SVE выкл., CPUIndexInTPIDRRO выкл., HostType=Arm64ec, 3DNow выкл.).
//       "native"  — все возможности M1 по sysctl hw.optional.arm.FEAT_* (как FEX на родном Linux).
FEXCore::HostFeatures FetchHostFeaturesMac(bool Product, char* Describe, size_t DescribeSize);
