// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <cstdint>

enum class FEXUnixLibFunctions : uint32_t {
  SetHardwareTSOControl,
  SetKernelUnalignedAtomicControl,
  Madvise,
  SetVMAName,
  GetSHMStatsVMA,
  DeleteSHMStatsFile,
  // MacRunner N2 2026-09-07 (Darwin W^X).
  // Дописано ПОСЛЕ DeleteSHMStatsFile и ПЕРЕД MAX. Это не выбор по вкусу: таблица
  // __wine_unix_call_funcs спутника CrossOver, снятая otool, содержит РОВНО восемь
  // указателей именно в этом порядке — индексы 0-5 совпадают с апстримом, новые идут
  // следом. Порядок 0-5 менять нельзя: заголовок требует совпадения между wow64,
  // arm64ec и Linux.
  MarkJITMemory,
  EnableJITExec,
  HardwareTSOThreadEnter,
  // MacRunner 1.1.1: Apple AFPCR is used only after the unix half has read it
  // on the admitted initializing thread (SIGILL-guarded probe). Returns
  // STATUS_SUCCESS when readable, STATUS_NOT_SUPPORTED otherwise.
  QueryAppleAFP,
  MAX,
};

// Structures for passing arguments to unix library handlers.
// This must match between wow64, arm64ec, and Linux.
struct FEXUnixLib_SetHardwareTSOControlArgs {
  bool Enable;
};
static_assert(sizeof(FEXUnixLib_SetHardwareTSOControlArgs) == 1);

enum class FEXHardwareTSOEntryKind : uint32_t {
  ARM64ECThreadInit = 1,
  ARM64ECJitEntry = 2,
  WOW64ThreadInit = 3,
  WOW64Simulate = 4,
};
struct FEXUnixLib_HardwareTSOThreadEnterArgs {
  FEXHardwareTSOEntryKind Kind;
  uint32_t WindowsPid;
  uint32_t WindowsTid;
};
static_assert(sizeof(FEXUnixLib_HardwareTSOThreadEnterArgs) == 12);

// These match the prctl flag values for PR_ARM64_SET_UNALIGN_ATOMIC
static constexpr uint64_t FEX_UNALIGN_ATOMIC_EMULATE = 1ULL << 0;
static constexpr uint64_t FEX_UNALIGN_ATOMIC_BACKPATCH = 1ULL << 1;
static constexpr uint64_t FEX_UNALIGN_ATOMIC_STRICT_SPLIT_LOCKS = 1ULL << 2;

struct FEXUnixLib_SetKernelUnalignedAtomicControl {
  uint64_t Flags;
};
static_assert(sizeof(FEXUnixLib_SetKernelUnalignedAtomicControl) == 8);

struct FEXUnixLib_Madvise {
  const void* Addr;
  size_t Size;
  int32_t Advise;
  uint32_t pad;
};
static_assert(sizeof(FEXUnixLib_Madvise) == 24);

struct FEXUnixLib_SetVMAName {
  const void* Addr;
  size_t Size;
  const char* Name;
};
static_assert(sizeof(FEXUnixLib_SetVMAName) == 24);

struct FEXUnixLib_GetSHMStatsVMA {
  void* SHMBase;
  uint32_t MapSize;
  uint32_t MaxSize;
};
static_assert(sizeof(FEXUnixLib_GetSHMStatsVMA) == 16);

// MacRunner N2: раскладка выведена из дизассемблера спутника CrossOver, не из головы.
//   _handler_mark_jit_memory: ldp x8, x1, [x0]  -> два 64-битных поля, адрес и длина
//   _handler_enable_jit_exec: ldr w0, [x0]      -> одно 32-битное поле
struct FEXUnixLib_MarkJITMemory {
  void* Addr;
  size_t Size;
};
static_assert(sizeof(FEXUnixLib_MarkJITMemory) == 16);

struct FEXUnixLib_EnableJITExec {
  // 1 = страницы MAP_JIT исполняемые (запись запрещена),
  // 0 = страницы MAP_JIT записываемые (исполнение запрещено).
  // Состояние ПОТОКОВОЕ: действует на вызывающий поток, не на процесс.
  int32_t Enable;
};
static_assert(sizeof(FEXUnixLib_EnableJITExec) == 4);
