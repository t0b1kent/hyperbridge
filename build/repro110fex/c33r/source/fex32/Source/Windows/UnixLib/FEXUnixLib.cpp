// SPDX-License-Identifier: MIT
#include <cstdint>
#include <type_traits>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#ifndef __APPLE__
#include <sys/prctl.h>
#endif
#include <unistd.h>

#ifdef __APPLE__
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <pthread.h>
#include "MacRunnerHardwareTSO.h"
// Для проверки обработчика 6: фактические права области, а не наше предположение о них.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

#include "FEXUnixLib.h"

// Equivalent to C++23's std::to_underlying.
template<typename Enum>
[[nodiscard]]
constexpr std::underlying_type_t<Enum> ToUnderlying(Enum e) noexcept {
  return static_cast<std::underlying_type_t<Enum>>(e);
}

using NTSTATUS = int32_t;
using unixlib_entry_t = NTSTATUS (*)(void*);

constexpr NTSTATUS STATUS_SUCCESS = 0;
constexpr NTSTATUS STATUS_INVALID_PARAMETER = 0xC000000D;
constexpr NTSTATUS STATUS_NOT_SUPPORTED = 0xC00000BB;
constexpr NTSTATUS STATUS_INTERNAL_ERROR = 0xC00000E5;

#ifdef __APPLE__
// ===========================================================================================
// MacRunner N2 2026-09-07 — дарвиновская половина клея.
//
// Написана по спецификации reports/FEX-KLEY-SPEC-8-OBRABOTCHIKOV.md, снятой дизассемблером
// с работающего спутника CrossOver. До этого захода исходника клея не существовало НИГДЕ:
// двоичный собран 07.09 в 15:25 вне репозитория, пересобрать его было нечем. Копия того
// двоичного лежит в artifacts/KLEY-FEX-BEZ-ISHODNIKA-070926/.
//
// Почему это вообще нужно: macOS отказывает в RWX КАТЕГОРИЧЕСКИ — и через mmap, и через
// mprotect (замер тремя руками, reports/FEX-N3-lab/rwx_probe*.c, errno=13 EACCES; право
// com.apple.security.cs.allow-unsigned-executable-memory запрет НЕ снимает). Законных дорог
// ровно две: (A) MAP_JIT + pthread_jit_write_protect_np — ею идут FEX и CrossOver;
// (B) RW -> запись -> mprotect RX — ею идёт HyperBridge. Обработчики 6 и 7 — это дорога (A).
//
// Отличие от снятого двоичного НАМЕРЕННОЕ и одно: их обработчик 6 отбрасывает результат
// mmap (`bl _mmap / mov w0,#0 / ret`), то есть рапортует успех даже при неудаче разметки.
// Здесь результат проверяется. Молчаливый ложный успех — худший из возможных отказов:
// он выглядит как работающая разметка и уводит диагностику на несколько дней.
// ===========================================================================================

// Метка для сверки развёрнутого двоичного: `strings -a <файл> | grep macrunner-fex-glue`.
// Правило проекта: гейт, активность которого не доказана, считается выключенным, — поэтому
// у клея должна быть опознавательная строка, переживающая линковку.
__attribute__((used)) static const char MacRunnerGlueMarker[] = "macrunner-fex-glue-darwin-v1";

// ★★★ MacRunner N2b — ЗОНД ЗАГРУЗКИ. Печатает В МОМЕНТ dlopen, безусловно.
//
// ЗАЧЕМ ЗАВЕДЁН. Обработчики 6 и 7 молчали, и «молчит» было неотличимо от двух разных
// вещей: (а) до них не доходит управление, (б) загружен ЧУЖОЙ спутник. Разобрало
// сличение UUID: `sample` показал в процессе xtajit.so с UUID 67AE71B2…, а это
// engine/wine/dist/lib/wine/aarch64-unix/xtajit.so — спутник HYPERBRIDGE, тогда как наш
// клей имеет UUID 3454B40B…. Печать `macrunner-cpu-backend-load: unix=<overlay>/…` при
// этом сообщала НАМЕРЕНИЕ загрузчика, а не факт: virtual.c:1203 записывает unix_path
// модулю ТОЛЬКО ОДИН РАЗ (`if (!builtin->unix_path)`), а `dlsym` затем спокойно находит
// `__wine_unix_call_funcs` и у чужого спутника — то есть подмена даёт ЛОЖНЫЙ УСПЕХ.
//
// Конструктор — единственный способ ответить «загрузили ли ИМЕННО МЕНЯ», не полагаясь
// на то, что до какого-либо обработчика дошли.
__attribute__((constructor)) static void MacRunnerGlueAnnounce(void) {
  fprintf(stderr, "macrunner-fex-glue: загружен клей FEX, таблица на 9 мест, pid=%d\n", (int)getpid());
  fflush(stderr);
}

// Печать безусловная, в stderr: каналы wine (ERR/MESSAGE) до наших журналов не доходят,
// проверено — строк `err:` нет НИ В ОДНОМ прогоне за всю историю проекта.
static uint64_t MarkJITCount {};
static uint64_t JITExecCount {};

static NTSTATUS FEXUnixLib_SetHardwareTSOControlHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetHardwareTSOControlArgs*>(_Args);
  if (!Args->Enable) return STATUS_NOT_SUPPORTED; // Active shared-JIT policy cannot be undone.
  const auto Mode = macrunner_hwtso_admit();
  // Deliberately nonzero even when enabled: older PE halves treat this as a
  // failed probe and retain software TSO. The original one-byte ABI is intact.
  return Mode ? static_cast<NTSTATUS>(Mode) : STATUS_NOT_SUPPORTED;
}

// 1-5: механизма в ядре macOS НЕТ. Это не недоделка — соответствующих вызовов не существует,
// и нативная сборка Mach-O их не откроет. Возврат совпадает с CrossOver, включая пятый:
// у прежнего нашего двоичного пятый возвращал 0, и это было расхождение с эталоном.
//   1 SetKernelUnalignedAtomicControl — prctl(0x46455849) есть только в ЗАПЛАТЕ FEX к ядру
//     Linux, её нет даже в обычном Linux;
//   2 Madvise — зовётся только под MADV_HUGEPAGE; прозрачных огромных страниц в macOS нет;
//   3 SetVMAName — подписи областей в /proc/maps, чистая диагностика;
//   4/5 GetSHMStatsVMA / DeleteSHMStatsFile — телеметрия через shm_open("/fex-<pid>-stats").
static NTSTATUS FEXUnixLib_SetKernelUnalignedAtomicControlHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}
static NTSTATUS FEXUnixLib_MadviseHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}
static NTSTATUS FEXUnixLib_SetVMANameHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}
static NTSTATUS FEXUnixLib_GetSHMStatsVMAHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}
static NTSTATUS FEXUnixLib_DeleteSHMStatsFileHandler(void* _Args) {
  return STATUS_NOT_SUPPORTED;
}

// ★★★ ПЕРЕПИСАНО 07.09.2026 ПОСЛЕ ЗАМЕРА. Прежняя редакция была построчным переносом
// CrossOver: mmap(Addr, Size, RWX, MAP_ANON|MAP_PRIVATE|MAP_FIXED|MAP_JIT). Замер эту
// конструкцию УБИЛ, и причина внешняя, не наша.
//
//   XNU bsd/kern/kern_mman.c:403-423 — MAP_JIT вместе с MAP_FIXED разрешён ТОЛЬКО когда
//   страница карты процесса 4096 и карта не exotic; иначе EINVAL, безусловно.
//
// Проба reports/FEX-N2-lab/rwx_probe.c на этой машине (страница 16384):
//     MAP_JIT без MAP_FIXED              -> ok, prot=7 max=7, код вернул 42, затем 43
//     MAP_JIT|MAP_FIXED поверх RW        -> EINVAL
//     MAP_JIT|MAP_FIXED поверх PROT_NONE -> EINVAL
//     RWX без MAP_JIT (контроль)         -> EACCES
//
// CrossOver обходит это ОТДЕЛЬНЫМ ПЕРЕЗАПУСКОМ в 4К-процесс
// (_posix_spawnattr_set_4k_page_size_np). Нам эта дорога закрыта не по незнанию:
// reports/FEX-N2-lab/spawn4k_probe.c даёт posix_spawn rc=88 на ТРЁХ разных двоичных,
// включая системный /bin/echo, тогда как тот же spawn без атрибута работает. Требуется
// право com.apple.private.4k-pages либо cross-architecture-support (XNU
// mach_loader.c:985-1025), которого у нас нет.
//
// ОТСЮДА НОВЫЙ ДОГОВОР: отображение с MAP_JIT делает САМ Wine при выделении
// (virtual.c, map_view, VPROT_MACRUNNER_JIT), потому что только там адрес ещё не
// зафиксирован и его может выбрать ядро. Обработчику 6 остаётся ПРОВЕРКА, и это не
// уступка: без неё «разметил» и «не разметил» дают одинаковый успех, а именно на этом
// эталон CrossOver и слеп (его обработчик 6 возвращает 0, не глядя на результат mmap).
static NTSTATUS FEXUnixLib_MarkJITMemoryHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_MarkJITMemory*>(_Args);
  const uint64_t N = __atomic_add_fetch(&MarkJITCount, 1, __ATOMIC_RELAXED);

  mach_vm_address_t Addr = reinterpret_cast<mach_vm_address_t>(Args->Addr);
  mach_vm_size_t Size = 0;
  vm_region_basic_info_data_64_t Info {};
  mach_msg_type_number_t Count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t Object = MACH_PORT_NULL;

  const kern_return_t KR = mach_vm_region(mach_task_self(), &Addr, &Size, VM_REGION_BASIC_INFO_64,
                                          reinterpret_cast<vm_region_info_t>(&Info), &Count, &Object);

  // Годной считаем область, которая (а) найдена, (б) НАКРЫВАЕТ весь запрошенный диапазон
  // целиком — mach_vm_region умеет вернуть СЛЕДУЮЩУЮ область, если по адресу пусто, —
  // и (в) имеет max_protection = RWX, что и есть признак отображения с MAP_JIT.
  const bool Covers = (KR == KERN_SUCCESS) && (Addr <= reinterpret_cast<mach_vm_address_t>(Args->Addr)) &&
                      (Addr + Size >= reinterpret_cast<mach_vm_address_t>(Args->Addr) + Args->Size);
  const bool Ok = Covers && ((Info.max_protection & VM_PROT_ALL) == VM_PROT_ALL) && (Info.protection & VM_PROT_EXECUTE);

  if (N <= 8 || !Ok) {
    fprintf(stderr,
            "macrunner-fex-markjit: addr=%p size=%zu kr=%d обл=%p+0x%llx prot=%d max=%d "
            "накрывает=%d ok=%d n=%llu jit_wp_supported=%d\n",
            Args->Addr, Args->Size, KR, reinterpret_cast<void*>(Addr), (unsigned long long)Size, Info.protection,
            Info.max_protection, Covers ? 1 : 0, Ok ? 1 : 0, (unsigned long long)N,
            pthread_jit_write_protect_supported_np() ? 1 : 0);
    fflush(stderr);
  }

  // ★ Отказ здесь — НАСТОЯЩИЙ отказ, а не молчаливый ноль эталона: если область не
  // MAP_JIT, то первая же запись кода упрётся в W^X, и лучше узнать это здесь.
  return Ok ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
}

static NTSTATUS FEXUnixLib_EnableJITExecHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_EnableJITExec*>(_Args);

  // ★ ПОТОКОВОЕ состояние. pthread_jit_write_protect_np действует на ВЫЗЫВАЮЩИЙ поток и
  // сразу на ВСЕ области MAP_JIT процесса. Значит поток, который пишет код, обязан сам
  // открыть запись и сам закрыть её — чужой поток за него этого не сделает, и наоборот:
  // открыв запись, он лишает СЕБЯ права исполнять JIT-код до обратного переключения.
  pthread_jit_write_protect_np(Args->Enable);

  const uint64_t N = __atomic_add_fetch(&JITExecCount, 1, __ATOMIC_RELAXED);
  if (N <= 4 || (N & 0xFFFFF) == 0) {
    fprintf(stderr, "macrunner-fex-jitexec: enable=%d n=%llu\n", Args->Enable, (unsigned long long)N);
    fflush(stderr);
  }
  return STATUS_SUCCESS;
}

#else // !__APPLE__

#ifndef PR_GET_MEM_MODEL
#define PR_GET_MEM_MODEL 0x6d4d444c
#endif
#ifndef PR_SET_MEM_MODEL
#define PR_SET_MEM_MODEL 0x4d4d444c
#endif
#ifndef PR_SET_MEM_MODEL_DEFAULT
#define PR_SET_MEM_MODEL_DEFAULT 0
#endif
#ifndef PR_SET_MEM_MODEL_TSO
#define PR_SET_MEM_MODEL_TSO 1
#endif
#ifndef PR_ARM64_SET_UNALIGN_ATOMIC
#define PR_ARM64_SET_UNALIGN_ATOMIC 0x46455849
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

static NTSTATUS FEXUnixLib_SetHardwareTSOControlHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetHardwareTSOControlArgs*>(_Args);
  if (Args->Enable) {
    int ret = prctl(PR_GET_MEM_MODEL, 0, 0, 0, 0);
    if (ret == PR_SET_MEM_MODEL_DEFAULT) {
      return prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO, 0, 0, 0) ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
    }
    return ret == PR_SET_MEM_MODEL_TSO ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
  }

  prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_DEFAULT, 0, 0, 0);
  return STATUS_SUCCESS;
}

static NTSTATUS FEXUnixLib_SetKernelUnalignedAtomicControlHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetKernelUnalignedAtomicControl*>(_Args);
  return prctl(PR_ARM64_SET_UNALIGN_ATOMIC, Args->Flags, 0, 0, 0) == 0 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

static NTSTATUS FEXUnixLib_MadviseHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_Madvise*>(_Args);
  return madvise(const_cast<void*>(Args->Addr), Args->Size, Args->Advise) == 0 ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
}

static NTSTATUS FEXUnixLib_SetVMANameHandler(void* _Args) {
  auto Args = reinterpret_cast<const FEXUnixLib_SetVMAName*>(_Args);
  return prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<unsigned long>(Args->Addr), Args->Size, Args->Name) == 0 ?
           STATUS_SUCCESS :
           STATUS_INTERNAL_ERROR;
}

constexpr static int USER_PERMS = S_IRWXU | S_IRWXG | S_IRWXO;
static inline void* InitializeSHM(uint32_t MapSize, uint32_t MaxSize) {
  void* Base {};
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";
  int fd = shm_open(Name.c_str(), O_CREAT | O_TRUNC | O_RDWR, USER_PERMS);

  if (fd == -1) {
    return nullptr;
  }

  if (ftruncate(fd, MapSize) == -1) {
    goto err;
  }

  // Reserve a region of MAX_STATS_SIZE so we can grow the allocation buffer.
  // Number of thread slots when ThreadStatsHeader == 64bytes and ThreadStats == 40bytes:
  // 1 page: 99 slots
  // 1 MB: 26211 slots
  // 128 MB: 3355440 slots
  Base = mmap(nullptr, MaxSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (Base == MAP_FAILED) {
    Base = nullptr;
    goto err;
  }

  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<void*>(Base), MaxSize, "FEXMem_Misc");

  // Allocate a small working shared space for now, grow as necessary.
  {
    auto SharedBase = mmap(Base, MapSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      ::munmap(Base, MaxSize);
      Base = nullptr;
      goto err;
    }
  }

err:
  close(fd);

  return Base;
}

static inline bool AllocateMoreSlots(void* SHMBase, uint32_t NewSize) {
  bool Result {};
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";

  // When allocating more slots, open the fd without O_TRUNC | O_CREAT.
  int fd = shm_open(Name.c_str(), O_RDWR, USER_PERMS);
  if (fd == -1) {
    return false;
  }

  if (ftruncate(fd, NewSize) == -1) {
    goto err;
  }

  {
    auto SharedBase = mmap(SHMBase, NewSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      goto err;
    }
  }

  Result = true;

err:
  close(fd);
  return Result;
}

static NTSTATUS FEXUnixLib_GetSHMStatsVMAHandler(void* _Args) {
  auto Args = reinterpret_cast<FEXUnixLib_GetSHMStatsVMA*>(_Args);
  if (Args->SHMBase == nullptr) {
    Args->SHMBase = InitializeSHM(Args->MapSize, Args->MaxSize);
    return Args->SHMBase ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
  }

  return AllocateMoreSlots(Args->SHMBase, Args->MapSize) ? STATUS_SUCCESS : STATUS_INTERNAL_ERROR;
}

static NTSTATUS FEXUnixLib_DeleteSHMStatsFileHandler(void* _Args) {
  const std::string Name = "fex-" + std::to_string(getpid()) + "-stats";
  shm_unlink(Name.c_str());
  return STATUS_SUCCESS;
}

// На Linux кодовый буфер и так RWX, переключать нечего — оба новых обработчика
// успешные пустышки. Это НЕ отказ: делать здесь нечего по устройству платформы.
static NTSTATUS FEXUnixLib_MarkJITMemoryHandler(void* _Args) {
  return STATUS_SUCCESS;
}
static NTSTATUS FEXUnixLib_EnableJITExecHandler(void* _Args) {
  return STATUS_SUCCESS;
}

#endif // __APPLE__

// ★★★★ MacRunner N2d 07.09.2026 — ОПОЗНАВАТЕЛЬНЫЙ ЗНАК ТАБЛИЦЫ. Закрывает подмену спутника.
//
// ЧТО ИЗМЕРЕНО, ради чего он появился. Две руки, различавшиеся ТОЛЬКО тем, лежит ли на
// пути загрузки unix-половина HyperBridge (dist/lib/wine/aarch64-unix/xtajit.so):
//
//   прибор                              спутник HB убран   спутник HB на месте
//   macrunner-fex-glue (наш конструктор)        1                  0
//   macrunner-fex-jitexec (наш крюк 7)          4                  0
//   macrunner-fex-call7 «вернулся УСПЕХ»        2                  2   <-- ЛОЖНЫЙ УСПЕХ
//   шаг=13 InitCore                             1                  0
//   наибольшее n у jit-mprotect-skip            4             196 608   <-- клин
//
// Третья строка и есть дефект: PE-сторона получила STATUS_SUCCESS от обработчика,
// который НЕ ИСПОЛНЯЛСЯ. Механика: у обоих спутников есть символ
// __wine_unix_call_funcs, virtual.c:1203 пишет модулю unix_path ОДИН раз, dlsym у
// чужого спутника находит таблицу — и вызовы уходят в НЕЁ. Молчаливая работа с чужой
// таблицей неотличима от своей ровно до момента, когда что-нибудь встанет.
//
// Знак экспортируется с ВИДИМОСТЬЮ ПО УМОЛЧАНИЮ: ntdll ищет его тем же dlsym, что и
// саму таблицу, и без него таблицу НЕ ОТДАЁТ (get_builtin_unix_funcs). Отказ громкий:
// FEX печатает «НЕТ-КЛЕЯ» и завершает процесс — это лучше, чем идти дальше вслепую.
//
// Значение несёт число мест в таблице: если раскладка разойдётся, разойдётся и знак.
extern "C" __attribute__((visibility("default")))
const unsigned long long __fex_darwin_unixlib_abi =
    0x4645584d52000000ULL | (unsigned long long)ToUnderlying(FEXUnixLibFunctions::MAX);

static NTSTATUS FEXUnixLib_HardwareTSOThreadEnterHandler(void* _Args) {
#ifdef __APPLE__
  if (!_Args) return STATUS_INVALID_PARAMETER;
  const auto* Args = static_cast<const FEXUnixLib_HardwareTSOThreadEnterArgs*>(_Args);
  const auto Kind = static_cast<uint32_t>(Args->Kind);
  if (Kind < 1 || Kind > 4) return STATUS_INVALID_PARAMETER;
  const auto Mode = macrunner_hwtso_admit_entry(Kind, Args->WindowsPid, Args->WindowsTid);
  return Mode ? static_cast<NTSTATUS>(Mode) : STATUS_NOT_SUPPORTED;
#else
  return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS FEXUnixLib_QueryAppleAFPHandler(void*) {
#ifdef __APPLE__
  return macrunner_hwtso_apple_afp() ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
#else
  return STATUS_NOT_SUPPORTED;
#endif
}

extern "C" const unixlib_entry_t __wine_unix_call_funcs[] = {
  FEXUnixLib_SetHardwareTSOControlHandler,
  FEXUnixLib_SetKernelUnalignedAtomicControlHandler,
  FEXUnixLib_MadviseHandler,
  FEXUnixLib_SetVMANameHandler,
  FEXUnixLib_GetSHMStatsVMAHandler,
  FEXUnixLib_DeleteSHMStatsFileHandler,
  FEXUnixLib_MarkJITMemoryHandler,
  FEXUnixLib_EnableJITExecHandler,
  FEXUnixLib_HardwareTSOThreadEnterHandler,
  FEXUnixLib_QueryAppleAFPHandler,
};

static_assert(sizeof(__wine_unix_call_funcs) / sizeof(__wine_unix_call_funcs[0]) == ToUnderlying(FEXUnixLibFunctions::MAX));
