/*
 * Unix side of MacRunner x86-64-on-ARM64EC HyperBridge CPU module.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#ifdef __APPLE__
# include <mach/mach.h>
# include <mach/mach_vm.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/unixlib.h"

#include "hb_context.h"
#include "hb_cpuid.h"
#include "hb_guest_shared.h"
#include "hb_syscall_stub.h"
#include "hb_decoder.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include "hb_ir_reuse.h"
#include "hb_memory.h"
#include "hb_result.h"
#include "hb_runtime.h"
#include "hb_cooperative_yield.h"

_Static_assert( HB_PE_COUNTER_FREE_YIELD == HB_ERR_STEP_LIMIT, "PE yield reason must match core" );
#include "hb_cache_notify.h"
#include "hb_cas128_policy.h"
#include "hb_packet_flags.h"
#include "hb_thread_lifetime.h"
#include "hb_pair_preflight.h"

#include "xtajit64_exec.h"
#include "xtajit64_x87.h"
#include "hb_x87_boundary.h"
#include "xtajit64_exec_fetch.h"
#include "xtajit64_exec_fetch_window.h"
#include "exec_page_query_v1.h"

#define XTAJIT64_DEFAULT_MAX_CODE_BYTES 4096u
#define XTAJIT64_HB_IMPORT_BASE 0x00006f0000000000ULL
#define XTAJIT64_HB_IMPORT_SIZE (4096ULL * 0x10ULL)

/* Claude 25.09: переменные окружения читаются ОДИН раз на процесс. Прежде getenv стоял на каждом
 * вызове симуляции (профиль загрузки сборок HK: ~4 % главного потока в __findenv_locked). */
static BOOL trace_xtajit64_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *value = getenv( "MACRUNNER_HB_TRACE_XTAJIT64" );
        cached = value && value[0] && value[0] != '0';
    }
    return cached;
}

static BOOL xtajit64_use_jit_backend(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *value = getenv( "MACRUNNER_XTAJIT64_BACKEND" );

        if (!value || !*value) value = getenv( "MACRUNNER_HB_BACKEND" );
        cached = !(value && (!strcasecmp( value, "interp" ) || !strcasecmp( value, "interpreter" ) ||
                             !strcasecmp( value, "off" ) || !strcmp( value, "0" )));
    }
    return cached;
}

static pthread_mutex_t process_mutex = PTHREAD_MUTEX_INITIALIZER;
static hb_memory_t *process_memory;
static BOOL process_ready;
static __thread hb_context_t *thread_ctx;
static __thread hb_jit_runtime_t *thread_jit;
/* Per-host-thread evidence from the memory callbacks. Fetch lookahead failures
 * are cleared before guest execution and never reported as data faults. */
static __thread struct xtajit64_fault_record thread_fault;

static unsigned int fast_exec_flags(void);

/* Claude, 25.09.2026 — ПОКОЛЕНИЕ КАРТЫ ПАМЯТИ (бит 32 MACRUNNER_HB_FAST_EXEC).
 * Растёт на КАЖДОМ уведомлении alloc/map/protect/free/unmap. Сторожевая страница появляется
 * только через эти вызовы, поэтому ответ «на странице нет PAGE_GUARD, она выделена» верен до
 * следующего уведомления; касание сторожа Wine снимает его — страница становится только
 * свободнее, и кешированный ответ остаётся верным. */
static uint64_t vm_map_generation = 1;

#define GUARD_FREE_SLOTS 64u
struct guard_free_slot { uint64_t page; uint64_t generation; };
static __thread struct guard_free_slot guard_free_cache[GUARD_FREE_SLOTS];

static BOOL guard_free_cached( uint64_t page )
{
    struct guard_free_slot *slot = &guard_free_cache[(page >> 12) & (GUARD_FREE_SLOTS - 1)];
    return slot->page == page &&
           slot->generation == __atomic_load_n( &vm_map_generation, __ATOMIC_ACQUIRE );
}

static void guard_free_remember( uint64_t page, uint64_t generation )
{
    struct guard_free_slot *slot = &guard_free_cache[(page >> 12) & (GUARD_FREE_SLOTS - 1)];
    slot->page = page;
    slot->generation = generation;
}

/* Claude 28.09.2026 — ТОЧНОЕ ГАШЕНИЕ КЕША СТРАНИЦ (гейт MACRUNNER_HB_VMCACHE_RANGE, умолчание 0).
 *
 * Кеш «страница выделена, доступна, без сторожа» у прямой записи/чтения (direct_access_pages_ok) держит
 * ключом vm_map_generation, а оно растёт на КАЖДОМ уведомлении alloc/map/protect/free/unmap — любое
 * выделение в процессе гасит ответ для всех страниц всех потоков. HK, геймплей (fPp1, sample 20 с):
 * помощник записи hb_jit_helper_store_sized -> native_write -> NtQueryVirtualMemory (get_basic_memory_info:
 * блокировка виртуальной памяти Wine + pthread_sigmask) — ~1,8 % главного потока и ~5 % UnityGfxDeviceWorker;
 * уведомлений ~83 тыс. за прогон (inval-why: 163 периода по 512).
 * Здесь каждое такое уведомление пишется в кольцо диапазонов с порядковым номером; ответ кеша верен,
 * пока ни один диапазон ПОСЛЕ его номера не задел страницу. Длина 0 (освобождение без размера,
 * неизвестная область) задевает всё — как прежнее поколение. Кольцо переполнено, запись не дописана
 * или переписана — промах (запрос, как раньше). Допущение то же, что у поколения: сторож и снятие
 * доступа приходят только через эти уведомления. */
#define VM_INVAL_RING 256u
struct vm_inval_rec { uint64_t start, end, seq; };
static struct vm_inval_rec vm_inval_ring[VM_INVAL_RING];
static uint64_t vm_inval_seq;

static int vmcache_range_enabled( void )
{
    static int enabled = -1;
    if (enabled < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_VMCACHE_RANGE" );
        enabled = (v && v[0] && v[0] != '0') ? 1 : 0;
    }
    return enabled;
}

static void vm_inval_record( uint64_t start, uint64_t len )
{
    uint64_t seq = __atomic_add_fetch( &vm_inval_seq, 1, __ATOMIC_ACQ_REL );
    struct vm_inval_rec *r = &vm_inval_ring[seq & (VM_INVAL_RING - 1)];
    uint64_t lo = start & ~UINT64_C(4095);
    uint64_t hi = (len && start + len > start) ? ((start + len + 4095) & ~UINT64_C(4095)) : UINT64_MAX;
    if (!len) lo = 0;
    __atomic_store_n( &r->seq, 0, __ATOMIC_RELAXED );
    __atomic_thread_fence( __ATOMIC_RELEASE );
    __atomic_store_n( &r->start, lo, __ATOMIC_RELAXED );
    __atomic_store_n( &r->end, hi, __ATOMIC_RELAXED );
    __atomic_store_n( &r->seq, seq, __ATOMIC_RELEASE );
}

/* TRUE — страницу [page, page+4096) после номера since не задел ни один записанный диапазон. */
static BOOL vm_page_untouched_since( uint64_t page, uint64_t since, uint64_t *now_out )
{
    uint64_t now = __atomic_load_n( &vm_inval_seq, __ATOMIC_ACQUIRE ), s;
    *now_out = now;
    if (now - since >= VM_INVAL_RING) return FALSE;
    for (s = since + 1; s <= now; s++)
    {
        const struct vm_inval_rec *r = &vm_inval_ring[s & (VM_INVAL_RING - 1)];
        uint64_t lo, hi;
        if (__atomic_load_n( &r->seq, __ATOMIC_ACQUIRE ) != s) return FALSE;
        lo = __atomic_load_n( &r->start, __ATOMIC_RELAXED );
        hi = __atomic_load_n( &r->end, __ATOMIC_RELAXED );
        __atomic_thread_fence( __ATOMIC_ACQUIRE );
        if (__atomic_load_n( &r->seq, __ATOMIC_RELAXED ) != s) return FALSE;
        if (page < hi && page + 4096 > lo) return FALSE;
    }
    return TRUE;
}

/* Сброс по диапазону (бит 16 MACRUNNER_HB_FAST_EXEC): только задетые байты. */
static void publish_cache_range(enum hb_cache_notification event, BOOL is_post,
                                NTSTATUS status, uint64_t start, uint64_t len)
{
    if (event != HB_CACHE_FLUSH && event != HB_CACHE_DIRTY && event != HB_CACHE_READ)
    {
        if (vmcache_range_enabled()) vm_inval_record( start, len );
        __atomic_add_fetch( &vm_map_generation, 1, __ATOMIC_ACQ_REL );
    }
    if (fast_exec_flags() & 16)
        (void)hb_cache_notify_publish_range(event, is_post, (int32_t)status, start, len);
    else
        (void)hb_cache_notify_publish(event, is_post, (int32_t)status);
}

static void publish_cache_notification(enum hb_cache_notification event, BOOL is_post,
                                       NTSTATUS status, const char *reason)
{
    const char *trace;
    uint64_t calls;

    if (!hb_cache_notify_publish(event, is_post, (int32_t)status)) return;
    trace = getenv("MACRUNNER_HB_TRACE_CACHE");
    if (!trace || !trace[0] || trace[0] == '0') return;
    hb_jit_inval_all_stats(&calls, NULL, NULL);
    fprintf(stderr, "hyperbridge-cache: reason=%s policy=all start=0 size=ffffffffffffffff sequence=%llu\n",
            reason, (unsigned long long)calls);
}

static hb_result_t record_memory_fault( hb_gva_t addr, unsigned int access )
{
    hb_gva_t pair_address;
    size_t pair_size;
    /* An internal pair read is architecturally a write-intent access. The
     * core exposes only the currently active operation, never last pending. */
    if (!access && thread_ctx &&
        hb_context_get_pair_rmw_intent( thread_ctx, &pair_address, &pair_size ) &&
        addr >= pair_address && addr - pair_address < pair_size)
        access = 1;
    memset( &thread_fault, 0, sizeof(thread_fault) );
    thread_fault.valid = 1;
    thread_fault.exception_code = STATUS_ACCESS_VIOLATION;
    thread_fault.access = access;
    thread_fault.address = addr;
    return HB_ERR_MEMORY_FAULT;
}

/* #GP(0) has no data address. Match Wine's x64 signal mapping: a read AV
 * at UINT64_MAX, without inventing a faulting memory operand. */
static void reset_precise_fault( hb_context_t *ctx )
{
    ctx->last_fault_kind = HB_FAULT_KIND_NONE;
    ctx->last_fault_pc = 0;
    ctx->last_fault_addr = 0;
    ctx->last_fault_addr_valid = 0;
}

static BOOL publish_general_protection_fault( struct xtajit64_simulate_params *params,
                                             hb_context_t *ctx, hb_result_t result )
{
    if (!params || !ctx || params->faulted != 1 || result != HB_ERR_EXEC_FAULT ||
        ctx->last_fault_kind != HB_FAULT_KIND_GENERAL_PROTECTION ||
        ctx->last_fault_addr_valid || ctx->last_fault_addr)
        return FALSE;

    memset( &thread_fault, 0, sizeof(thread_fault) );
    thread_fault.valid = 1;
    thread_fault.exception_code = STATUS_ACCESS_VIOLATION;
    thread_fault.access = 0;
    thread_fault.address = UINT64_MAX;
    thread_fault.pc = ctx->last_fault_pc;
    ctx->pc = ctx->last_fault_pc;
    params->context.rip = ctx->last_fault_pc;
    params->status = STATUS_ACCESS_VIOLATION;
    return TRUE;
}

static NTSTATUS status_from_hb( hb_result_t result )
{
    switch (result)
    {
    case HB_OK: return STATUS_SUCCESS;
    case HB_ERR_OUT_OF_MEMORY: return STATUS_NO_MEMORY;
    case HB_ERR_MEMORY_FAULT: return STATUS_ACCESS_VIOLATION;
    case HB_ERR_UNSUPPORTED_OPCODE:
    case HB_ERR_UNSUPPORTED_FEATURE: return STATUS_ILLEGAL_INSTRUCTION;
    case HB_ERR_INVALID_ARG: return STATUS_INVALID_PARAMETER;
    default: return STATUS_UNSUCCESSFUL;
    }
}

static hb_perm_t protect_to_perm( ULONG protect )
{
    hb_perm_t perm = HB_PERM_NONE;
    ULONG p = protect & 0xff;

    if (p == PAGE_NOACCESS) return HB_PERM_NONE;
    if (p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
        p == PAGE_EXECUTE_WRITECOPY)
        perm = (hb_perm_t)(perm | HB_PERM_READ);
    if (p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY)
        perm = (hb_perm_t)(perm | HB_PERM_WRITE);
    if (p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY)
        perm = (hb_perm_t)(perm | HB_PERM_EXEC);
    return perm;
}

static size_t native_page_size(void)
{
    static size_t page_size;

    if (!page_size) page_size = (size_t)getpagesize();
    return page_size;
}

static hb_gva_t page_floor( hb_gva_t addr )
{
    size_t page = native_page_size();
    return addr & ~((hb_gva_t)page - 1);
}

static size_t page_span( hb_gva_t addr, size_t size )
{
    size_t page = native_page_size();
    hb_gva_t base = page_floor( addr );
    hb_gva_t end = addr + size;
    hb_gva_t aligned_end;

    if (!size || end < addr) return 0;
    aligned_end = (end + page - 1) & ~((hb_gva_t)page - 1);
    return (size_t)(aligned_end - base);
}

static BOOL is_ec_code_ptr( ULONG_PTR ptr )
{
    TEB *teb = NtCurrentTeb();
    const UINT64 *map;
    ULONG_PTR page;

    if (!teb || !teb->Peb || !teb->Peb->EcCodeBitMap) return FALSE;
    map = (const UINT64 *)teb->Peb->EcCodeBitMap;
    page = ptr >> 12; /* Wine EcCodeBitMap uses Windows 4 KiB pages. */
    return (map[page / 64] >> (page & 63)) & 1;
}

/* Claude 27.09.2026 — РОДНЫЕ БЫСТРЫЕ ПУТИ WINE (гейт MACRUNNER_HB_NATIVE_FASTPATH, умолчание 0).
 *
 * Перепись меню HK (выходы диспетчера наружу по цели): главный поток — RtlLeaveCriticalSection
 * 3,66 млн, RtlEnterCriticalSection 2,91 млн, RtlAllocateHeap 1,78 млн, GetCurrentThreadId 1,23 млн
 * за прогон; рабочий поток — TlsGetValue 5,3 млн. Каждый такой вызов из x64 в ARM64EC-код Wine — это
 * выход из JIT, переход unix->PE, упаковка контекста, родной вызов и обратный вход через simulate.
 * Здесь их короткие пути исполняются прямо в диспетчере (hb_runtime_register_native_fastpath), по
 * семантике Wine (ntdll/sync.c, kernelbase/thread.c, kernel32/thread.c); всё, что требует ожидания,
 * пробуждения или выделения памяти, по-прежнему уходит в настоящую функцию.
 *
 * Адреса: x64-вид таблицы экспорта в памяти (ARM64X-исправления уже применены загрузчиком) даёт
 * заглушку FFS «mov rax,rsp; mov [rax+20h],rbx; push rbp; pop rbp; jmp rel32»; её цель — та самая
 * EC-функция, куда выходит диспетчер. Заглушка другого вида — функция не подключается. */
static int nfp_gate(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_NATIVE_FASTPATH" );
        cached = (v && v[0] && v[0] != '0') ? 1 : 0;
        fprintf( stderr, "macrunner-gate: MACRUNNER_HB_NATIVE_FASTPATH=%d\n", cached );
    }
    return cached;
}

/* x64 RET после обслуженного вызова: rax — результат, адрес возврата снят со стека гостя. */
static inline void nfp_return( hb_context_t *ctx, uint64_t rax )
{
    uint64_t rsp = ctx->regs.x64.rsp;
    uint64_t ret = *(const volatile uint64_t *)(uintptr_t)rsp;
    ctx->regs.x64.rax = rax;
    ctx->regs.x64.rsp = rsp + 8;
    ctx->regs.x64.rip = ret;
    ctx->pc = ret;
}

static inline HANDLE nfp_tid_handle( TEB *teb )
{
    return ULongToHandle( HandleToULong( teb->ClientId.UniqueThread ) );
}

static int nfp_get_current_thread_id( hb_context_t *ctx, void *arg )
{
    TEB *teb = NtCurrentTeb();
    (void)arg;
    if (!teb) return 0;
    nfp_return( ctx, HandleToULong( teb->ClientId.UniqueThread ) );
    return 1;
}

static int nfp_tls_get_value( hb_context_t *ctx, void *arg )
{
    TEB *teb = NtCurrentTeb();
    DWORD index = (DWORD)ctx->regs.x64.rcx;
    (void)arg;
    if (!teb || index >= TLS_MINIMUM_AVAILABLE) return 0;   /* слоты расширения — настоящей функцией */
    teb->LastErrorValue = 0;                                  /* TlsGetValue: SetLastError( ERROR_SUCCESS ) */
    nfp_return( ctx, (uint64_t)(ULONG_PTR)teb->TlsSlots[index] );
    return 1;
}

static int nfp_tls_set_value( hb_context_t *ctx, void *arg )
{
    TEB *teb = NtCurrentTeb();
    DWORD index = (DWORD)ctx->regs.x64.rcx;
    (void)arg;
    if (!teb || index >= TLS_MINIMUM_AVAILABLE) return 0;
    teb->TlsSlots[index] = (void *)(ULONG_PTR)ctx->regs.x64.rdx;
    nfp_return( ctx, TRUE );
    return 1;
}

/* macrunner_try_enter_crit из ntdll/sync.c: захват свободной секции или повтор владельцем. */
static int nfp_crit_try( RTL_CRITICAL_SECTION *crit, HANDLE tid )
{
    LONG expected = -1;
    if (__atomic_compare_exchange_n( &crit->LockCount, &expected, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ))
    {
        crit->OwningThread = tid;
        crit->RecursionCount = 1;
        return 1;
    }
    if (crit->OwningThread == tid)
    {
        __atomic_add_fetch( &crit->LockCount, 1, __ATOMIC_SEQ_CST );
        crit->RecursionCount++;
        return 1;
    }
    return 0;
}

static int nfp_enter_cs( hb_context_t *ctx, void *arg )
{
    RTL_CRITICAL_SECTION *crit = (RTL_CRITICAL_SECTION *)(ULONG_PTR)ctx->regs.x64.rcx;
    TEB *teb = NtCurrentTeb();
    (void)arg;
    if (!crit || !teb || ((ULONG_PTR)crit & 7)) return 0;
    if (!nfp_crit_try( crit, nfp_tid_handle( teb ) )) return 0;   /* занята другим — ждать будет Wine */
    nfp_return( ctx, STATUS_SUCCESS );
    return 1;
}

static int nfp_try_enter_cs( hb_context_t *ctx, void *arg )
{
    RTL_CRITICAL_SECTION *crit = (RTL_CRITICAL_SECTION *)(ULONG_PTR)ctx->regs.x64.rcx;
    TEB *teb = NtCurrentTeb();
    (void)arg;
    if (!crit || !teb || ((ULONG_PTR)crit & 7)) return 0;
    nfp_return( ctx, nfp_crit_try( crit, nfp_tid_handle( teb ) ) );
    return 1;
}

static int nfp_leave_cs( hb_context_t *ctx, void *arg )
{
    RTL_CRITICAL_SECTION *crit = (RTL_CRITICAL_SECTION *)(ULONG_PTR)ctx->regs.x64.rcx;
    TEB *teb = NtCurrentTeb();
    HANDLE tid;
    LONG rec, expected = 0;
    (void)arg;
    if (!crit || !teb || ((ULONG_PTR)crit & 7)) return 0;
    tid = nfp_tid_handle( teb );
    rec = crit->RecursionCount;
    if (rec > 1 && crit->OwningThread == tid)
    {
        crit->RecursionCount = rec - 1;
        __atomic_sub_fetch( &crit->LockCount, 1, __ATOMIC_SEQ_CST );
    }
    else if (rec == 1 && crit->OwningThread == tid)
    {
        /* Ждущих нет только при LockCount == 0; иначе их будит настоящая функция. */
        if (__atomic_load_n( &crit->LockCount, __ATOMIC_SEQ_CST ) != 0) return 0;
        crit->RecursionCount = 0;
        crit->OwningThread = 0;
        if (!__atomic_compare_exchange_n( &crit->LockCount, &expected, -1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ))
        {
            /* Ждущий пришёл между проверкой и обменом: вернуть состояние, отпустит Wine. */
            crit->OwningThread = tid;
            crit->RecursionCount = 1;
            return 0;
        }
    }
    else return 0;
    nfp_return( ctx, STATUS_SUCCESS );
    return 1;
}

static void *nfp_export( void *base, const char *name )
{
    const IMAGE_DOS_HEADER *dos = base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *dir;
    const IMAGE_EXPORT_DIRECTORY *exp;
    const DWORD *names, *funcs;
    const WORD *ords;
    DWORD i;

    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)((const char *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) return NULL;
    exp = (const IMAGE_EXPORT_DIRECTORY *)((const char *)base + dir->VirtualAddress);
    names = (const DWORD *)((const char *)base + exp->AddressOfNames);
    ords = (const WORD *)((const char *)base + exp->AddressOfNameOrdinals);
    funcs = (const DWORD *)((const char *)base + exp->AddressOfFunctions);
    for (i = 0; i < exp->NumberOfNames; i++)
    {
        DWORD rva;
        if (strcmp( (const char *)base + names[i], name )) continue;
        if (ords[i] >= exp->NumberOfFunctions) return NULL;
        rva = funcs[ords[i]];
        if (rva >= dir->VirtualAddress && rva < dir->VirtualAddress + dir->Size) return NULL;   /* пересылка */
        return (char *)base + rva;
    }
    return NULL;
}

static uint64_t nfp_ffs_target( const void *ffs )
{
    static const unsigned char pattern[10] = { 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9 };
    int32_t rel;
    if (!ffs || memcmp( ffs, pattern, sizeof(pattern) )) return 0;
    memcpy( &rel, (const unsigned char *)ffs + 10, 4 );
    return (uint64_t)(uintptr_t)((const unsigned char *)ffs + 14) + (int64_t)rel;
}

static void *nfp_module( const WCHAR *want )
{
    TEB *teb = NtCurrentTeb();
    PEB_LDR_DATA *ldr;
    LIST_ENTRY *head, *e;
    size_t wlen = 0;

    while (want[wlen]) wlen++;
    if (!teb || !teb->Peb || !(ldr = teb->Peb->LdrData)) return NULL;
    head = &ldr->InLoadOrderModuleList;
    for (e = head->Flink; e && e != head; e = e->Flink)
    {
        LDR_DATA_TABLE_ENTRY *m = CONTAINING_RECORD( e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
        size_t i;
        if (!m->BaseDllName.Buffer || m->BaseDllName.Length != wlen * sizeof(WCHAR)) continue;
        for (i = 0; i < wlen; i++)
        {
            WCHAR a = m->BaseDllName.Buffer[i], b = want[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (a != b) break;
        }
        if (i == wlen) return m->DllBase;
    }
    return NULL;
}

static int nfp_state;   /* 0 — не подключено, 1 — идёт поиск, 2 — готово */

static void nfp_add( void *module, const char *mname, const char *fname, hb_native_fastpath_fn fn )
{
    void *ffs = nfp_export( module, fname );
    uint64_t target = nfp_ffs_target( ffs );
    int ok = target && is_ec_code_ptr( (ULONG_PTR)target ) &&
             hb_runtime_register_native_fastpath( target, fn, NULL );
    fprintf( stderr, "macrunner-hb-nfp: %s!%s заглушка=%p цель=%#llx %s\n", mname, fname, ffs,
             (unsigned long long)target, ok ? "подключено" : "НЕ подключено" );
}

static void nfp_discover(void)
{
    int expected = 0;
    void *ntdll, *kernel32, *kernelbase;

    if (!nfp_gate() || __atomic_load_n( &nfp_state, __ATOMIC_ACQUIRE ) == 2) return;
    if (!__atomic_compare_exchange_n( &nfp_state, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE )) return;
    /* WCHAR явно: в unix-коде на macOS L"" — это 4-байтный wchar_t, а имена в загрузчике — UTF-16. */
    static const WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
    static const WCHAR kernel32W[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
    static const WCHAR kernelbaseW[] = {'k','e','r','n','e','l','b','a','s','e','.','d','l','l',0};
    ntdll = nfp_module( ntdllW );
    kernel32 = nfp_module( kernel32W );
    kernelbase = nfp_module( kernelbaseW );
    if (!ntdll || !kernel32 || !kernelbase)
    {
        __atomic_store_n( &nfp_state, 0, __ATOMIC_RELEASE );   /* ещё не загружены — повторим позже */
        return;
    }
    nfp_add( ntdll, "ntdll", "RtlEnterCriticalSection", nfp_enter_cs );
    nfp_add( ntdll, "ntdll", "RtlLeaveCriticalSection", nfp_leave_cs );
    nfp_add( ntdll, "ntdll", "RtlTryEnterCriticalSection", nfp_try_enter_cs );
    nfp_add( kernel32, "kernel32", "GetCurrentThreadId", nfp_get_current_thread_id );
    nfp_add( kernelbase, "kernelbase", "TlsGetValue", nfp_tls_get_value );
    nfp_add( kernelbase, "kernelbase", "TlsSetValue", nfp_tls_set_value );
    __atomic_store_n( &nfp_state, 2, __ATOMIC_RELEASE );
}

static unsigned int fast_exec_flags(void);

/* Claude, 25.09.2026 — ПРЯМОЙ ДОСТУП вместо копии через ядро (бит 8 MACRUNNER_HB_FAST_EXEC).
 * mach_vm_read/mach_vm_write на КАЖДОЕ обращение гостя — это вызов ядра (профиль HK: главная
 * статья после снятия проверки EXEC). Гость и хост делят одно адресное пространство, поэтому
 * читаем и пишем прямо. Отказ страницы ловит та же потоковая страховка Wine, что у cmpxchg128
 * (ntdll_set_exception_jmp_buf): обработчик Wine сам восстанавливает маску сигналов через
 * sigreturn ДО прыжка, поэтому берём _setjmp без сохранения маски — без системного вызова.
 * Выровненные 1/2/4/8 байт — одной инструкцией (атомарность одиночной копии x86, как M67). */
/* Порядок памяти x86 (TSO): гостевое чтение — acquire (LDAR), гостевая запись — release (STLR).
 * mach_vm_write прежде давал полный барьер попутно; прямой доступ обязан дать его сам. */
/* Claude 26.09: обычные загрузка/сохранение плюс барьеры, а НЕ ldapr/stlr. Замер HK (прогон
 * hk-vm8jqirf): побайтное чтение `ldaprb` из зарезервированной страницы (PROT_NONE, на macOS это
 * SIGBUS) зацикливалось в обработчике Wine — поток 100 % на одной команде, тогда как memcpy по той
 * же странице отказывал штатно через jmp_buf. Для порядка памяти x86 равнозначно: чтение гостя —
 * загрузка + dmb ishld (acquire), запись гостя — dmb ish (release) + сохранение. */
#define DIRECT_COPY(type, mo_load, mo_store) \
    do { \
        type v_; \
        if ((mo_store) == __ATOMIC_RELEASE) __atomic_thread_fence( __ATOMIC_RELEASE ); \
        v_ = *(const volatile type *)src; \
        if ((mo_load) == __ATOMIC_ACQUIRE) __atomic_thread_fence( __ATOMIC_ACQUIRE ); \
        *(volatile type *)dst = v_; \
    } while (0)
static __attribute__((noinline)) BOOL direct_copy_guarded( void *dst, const void *src, size_t size,
                                                           BOOL guest_is_dst )
{
    jmp_buf jmp;
    const int mo_load = guest_is_dst ? __ATOMIC_RELAXED : __ATOMIC_ACQUIRE;
    const int mo_store = guest_is_dst ? __ATOMIC_RELEASE : __ATOMIC_RELAXED;
    if (_setjmp( jmp )) return FALSE;   /* Wine уже снял страховку перед прыжком */
    ntdll_set_exception_jmp_buf( jmp );
    if (size == 8 && !((uintptr_t)src & 7) && !((uintptr_t)dst & 7))
        DIRECT_COPY( uint64_t, mo_load, mo_store );
    else if (size == 4 && !((uintptr_t)src & 3) && !((uintptr_t)dst & 3))
        DIRECT_COPY( uint32_t, mo_load, mo_store );
    else if (size == 2 && !((uintptr_t)src & 1) && !((uintptr_t)dst & 1))
        DIRECT_COPY( uint16_t, mo_load, mo_store );
    else if (size == 1)
        DIRECT_COPY( uint8_t, mo_load, mo_store );
    else
    {
        __atomic_thread_fence( __ATOMIC_SEQ_CST );
        memcpy( dst, src, size );
        __atomic_thread_fence( __ATOMIC_SEQ_CST );
    }
    ntdll_set_exception_jmp_buf( NULL );
    return TRUE;
}

/* Claude 26.09 — ПРЯМОЙ ДОСТУП ТОЛЬКО К ПРОВЕРЕННЫМ СТРАНИЦАМ (бит 8).
 * Набор Astra (55 случаев) на бите 8 давал 0/10 в stack-restart, rep-restart, guard-scalar,
 * flags-state, nested-continue: касание сторожевой/зарезервированной страницы прямым чтением
 * уходит в обработчик Wine, который СНИМАЕТ сторож (или растит стек) — побочный эффект, которого
 * у mach_vm_read нет. Поэтому прямо копируем только страницы «выделена, без сторожа» из кеша
 * поколения карты памяти; промах — один запрос NtQueryVirtualMemory; сомнительная — прежний путь. */
/* Свой кеш: у предпроверки (бит 32) в кеш «без сторожа» попадают и PAGE_NOACCESS-страницы,
 * а прямое чтение такой страницы уходит в SIGBUS, который Wine отдаёт гостю мимо jmp_buf
 * (guard-scalar на флагах 8+32 зависал). Здесь — только выделенные ДОСТУПНЫЕ без сторожа. */
static __thread struct guard_free_slot direct_ok_cache[GUARD_FREE_SLOTS];

static BOOL direct_access_pages_ok( uint64_t addr, size_t size )
{
    uint64_t page = addr & ~UINT64_C(4095), last = (addr + size - 1) & ~UINT64_C(4095);
    for (;;)
    {
        struct guard_free_slot *slot = &direct_ok_cache[(page >> 12) & (GUARD_FREE_SLOTS - 1)];
        BOOL hit;
        if (vmcache_range_enabled())
        {
            uint64_t now = 0;
            hit = slot->page == page && vm_page_untouched_since( page, slot->generation, &now );
            if (hit) slot->generation = now;
        }
        else
            hit = slot->page == page &&
                  slot->generation == __atomic_load_n( &vm_map_generation, __ATOMIC_ACQUIRE );
        if (!hit)
        {
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T returned = 0;
            /* Номер берётся ДО запроса: уведомление посреди запроса даст промах в следующий раз. */
            uint64_t generation = vmcache_range_enabled() ?
                __atomic_load_n( &vm_inval_seq, __ATOMIC_ACQUIRE ) :
                __atomic_load_n( &vm_map_generation, __ATOMIC_ACQUIRE );
            if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)page, MemoryBasicInformation,
                                      &mbi, sizeof(mbi), &returned ) || returned < sizeof(mbi))
                return FALSE;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return FALSE;
            slot->page = page;
            slot->generation = generation;
        }
        if (page == last) return TRUE;
        page += 4096;
    }
}

static hb_result_t native_read( void *user, hb_gva_t addr, void *out, size_t size )
{
    (void)user;
    if (!size) return HB_OK;
    if (!addr) return record_memory_fault( addr, 0 );
#ifdef __APPLE__
    if (fast_exec_flags() & 8)
    {
        uint64_t native_addr = addr;
        int shared = hb_guest_shared_read_address( addr, size, WINE_USER_SHARED_DATA_ADDRESS, &native_addr );
        if (shared || direct_access_pages_ok( addr, size ))
            return direct_copy_guarded( out, (const void *)(uintptr_t)native_addr, size, FALSE ) ?
                   HB_OK : record_memory_fault( addr, 0 );
    }
    {
        uint64_t native_addr = addr;
        mach_vm_size_t copied = 0;
        (void)hb_guest_shared_read_address( addr, size, WINE_USER_SHARED_DATA_ADDRESS, &native_addr );
        kern_return_t kr = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)native_addr,
                                                   (mach_vm_size_t)size,
                                                   (mach_vm_address_t)(uintptr_t)out, &copied );
        return (kr == KERN_SUCCESS && copied == size) ? HB_OK : record_memory_fault( addr, 0 );
    }
#else
    memcpy( out, (const void *)(uintptr_t)addr, size );
    return HB_OK;
#endif
}

static hb_result_t native_write( void *user, hb_gva_t addr, const void *in, size_t size )
{
    (void)user;
    if (!size) return HB_OK;
    if (!addr) return record_memory_fault( addr, 1 );
#ifdef __APPLE__
    if ((fast_exec_flags() & 8) && direct_access_pages_ok( addr, size ))
        return direct_copy_guarded( (void *)(uintptr_t)addr, in, size, TRUE ) ?
               HB_OK : record_memory_fault( addr, 1 );
    return mach_vm_write( mach_task_self(), (mach_vm_address_t)addr,
                          (vm_offset_t)(uintptr_t)in,
                          (mach_msg_type_number_t)size ) == KERN_SUCCESS ?
           HB_OK : record_memory_fault( addr, 1 );
#else
    memcpy( (void *)(uintptr_t)addr, in, size );
    return HB_OK;
#endif
}

#if defined(__APPLE__) && defined(__aarch64__)
typedef unsigned __int128 hb_native_word128 __attribute__((may_alias));

/* Keep this C frame and its faulting instruction outside generated JIT code.
 * Wine's Unix guard returns through normal signal return before longjmp. */
static __attribute__((noinline)) hb_result_t native_guarded_cmpxchg128(
    void *address, const uint64_t expected[2], const uint64_t desired[2],
    uint64_t observed[2], bool *exchanged )
{
    hb_native_word128 before, after;
    bool replaced;

    if (!__atomic_always_lock_free(16, 0)) return HB_ERR_UNSUPPORTED_FEATURE;
    before = ((hb_native_word128)expected[1] << 64) | expected[0];
    after = ((hb_native_word128)desired[1] << 64) | desired[0];
    __TRY
    {
        replaced = __atomic_compare_exchange_n( (hb_native_word128 *)address, &before,
                                                after, false, __ATOMIC_SEQ_CST,
                                                __ATOMIC_SEQ_CST );
    }
    __EXCEPT
    {
        /* Wine already popped this guard before longjmp; never pop twice. */
        return HB_ERR_MEMORY_FAULT;
    }
    __ENDTRY
    observed[0] = (uint64_t)before;
    observed[1] = (uint64_t)(before >> 64);
    *exchanged = replaced;
    return HB_OK;
}

static hb_result_t native_atomic_cmpxchg128(
    void *user, hb_gva_t addr, const uint64_t expected[2], const uint64_t desired[2],
    uint64_t observed[2], bool *exchanged )
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returned = 0;
    mach_vm_address_t region = addr;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr;
    hb_result_t result;
    uint64_t local_observed[2];
    bool local_exchanged;

    (void)user;
    if (!expected || !desired || !observed || !exchanged ||
        (addr & 15) || addr > UINT64_MAX - 16) return HB_ERR_INVALID_ARG;
    if (!addr) return record_memory_fault( addr, 1 );
    if (!__atomic_always_lock_free(16, 0)) return HB_ERR_UNSUPPORTED_FEATURE;

    /* Query Wine's page policy before touching its identity-mapped address.
     * V3 presently transports ordinary AV only. Do not consume PAGE_GUARD or
     * mislabel it as an ordinary AV while its delivery contract is unresolved. */
    if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)addr,
                              MemoryBasicInformation, &mbi, sizeof(mbi), &returned ) ||
        returned < sizeof(mbi)) return record_memory_fault( addr, 1 );
    if (mbi.Protect & PAGE_GUARD) return HB_ERR_UNSUPPORTED_FEATURE;
    if (mbi.State != MEM_COMMIT ||
        !hb_cas128_span_has_access( addr, (uintptr_t)mbi.BaseAddress, mbi.RegionSize,
                                   protect_to_perm(mbi.Protect), HB_PERM_READ | HB_PERM_WRITE ))
        return record_memory_fault( addr, 1 );

    kr = mach_vm_region( mach_task_self(), &region, &region_size,
                         VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object );
    if (object != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), object );
    if (kr != KERN_SUCCESS || count < VM_REGION_BASIC_INFO_COUNT_64 ||
        !hb_cas128_span_has_access( addr, region, region_size, info.protection,
                                   VM_PROT_READ | VM_PROT_WRITE ))
        return record_memory_fault( addr, 1 );

    /* Preflight is not a mapping lease. A protection/unmap race that faults at
     * the actual CAS is contained by Wine's existing per-thread Unix guard. */
    result = native_guarded_cmpxchg128( (void *)(uintptr_t)addr, expected, desired,
                                      local_observed, &local_exchanged );
    if (result == HB_ERR_MEMORY_FAULT) return record_memory_fault( addr, 1 );
    if (result != HB_OK) return result;
    if (local_exchanged && (info.protection & VM_PROT_EXECUTE))
        publish_cache_range( HB_CACHE_DIRTY, TRUE, STATUS_SUCCESS, addr, 16 );
    observed[0] = local_observed[0];
    observed[1] = local_observed[1];
    *exchanged = local_exchanged;
    return HB_OK;
}

/* Opt-in integration evidence only. Allocate private native pages and exercise
 * the same guarded primitive as the provider, including an enclosing guard.
 * No guest mapping, public export, handler installation, or callback is added. */
static BOOL native_cas128_guard_selftest(void)
{
    struct xtajit64_fault_record saved_fault = thread_fault;
    const uint64_t expected[2] = {UINT64_C(0x1122334455667788), UINT64_C(0x8877665544332211)};
    const uint64_t desired[2] = {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)};
    const uint64_t poison[2] = {UINT64_C(0xdead1234abcd5678), UINT64_C(0x0123dead4567beef)};
    mach_vm_address_t pages = 0;
    const size_t page = native_page_size();
    uint64_t observed[2];
    bool exchanged;
    hb_result_t result;
    volatile unsigned checks = 0, failures = 0;
    volatile int inner_returned = 0, outer_caught = 0;
    void *good = NULL, *bad = NULL;
    kern_return_t kr;

#define CAS128_CHECK(condition) do { ++checks; if (!(condition)) ++failures; } while (0)
    CAS128_CHECK( __atomic_always_lock_free(16, 0) );
    CAS128_CHECK( page && page <= UINT64_MAX / 2 );
    if (failures) goto done;
    kr = mach_vm_allocate( mach_task_self(), &pages, page * 2, VM_FLAGS_ANYWHERE );
    CAS128_CHECK( kr == KERN_SUCCESS );
    if (kr != KERN_SUCCESS) goto done;
    good = (void *)(uintptr_t)pages;
    bad = (void *)(uintptr_t)(pages + page);
    memcpy( good, expected, sizeof(expected) );
    kr = mach_vm_protect( mach_task_self(), pages + page, page, FALSE, VM_PROT_NONE );
    CAS128_CHECK( kr == KERN_SUCCESS );
    if (kr != KERN_SUCCESS) goto done;

    memcpy( observed, poison, sizeof(observed) ); exchanged = true;
    result = native_guarded_cmpxchg128( bad, expected, desired, observed, &exchanged );
    CAS128_CHECK( result == HB_ERR_MEMORY_FAULT );
    CAS128_CHECK( !memcmp(observed, poison, sizeof(observed)) && exchanged );
    result = native_guarded_cmpxchg128( good, expected, desired, observed, &exchanged );
    CAS128_CHECK( result == HB_OK && exchanged && !memcmp(observed, expected, sizeof(observed)) );
    CAS128_CHECK( !memcmp(good, desired, sizeof(desired)) );
    memcpy( observed, poison, sizeof(observed) ); exchanged = true;
    result = native_guarded_cmpxchg128( bad, expected, desired, observed, &exchanged );
    CAS128_CHECK( result == HB_ERR_MEMORY_FAULT );
    CAS128_CHECK( !memcmp(observed, poison, sizeof(observed)) && exchanged );
    result = native_guarded_cmpxchg128( good, expected, poison, observed, &exchanged );
    CAS128_CHECK( result == HB_OK && !exchanged && !memcmp(observed, desired, sizeof(observed)) );
    CAS128_CHECK( !memcmp(good, desired, sizeof(desired)) );

    memcpy( observed, poison, sizeof(observed) ); exchanged = true;
    __TRY
    {
        result = native_guarded_cmpxchg128( bad, expected, desired, observed, &exchanged );
        inner_returned = result == HB_ERR_MEMORY_FAULT &&
                         !memcmp(observed, poison, sizeof(observed)) && exchanged;
        *(volatile uint64_t *)bad = UINT64_C(0x1020304050607080);
    }
    __EXCEPT
    {
        outer_caught = 1;
    }
    __ENDTRY
    CAS128_CHECK( inner_returned == 1 && outer_caught == 1 );

done:
    if (pages) CAS128_CHECK( mach_vm_deallocate(mach_task_self(), pages, page * 2) == KERN_SUCCESS );
    thread_fault = saved_fault;
    fprintf( stderr, "hyperbridge-cas128-selftest: checks=%u failures=%u inner=%d outer=%d\n",
             checks, failures, inner_returned, outer_caught );
    fflush( stderr );
#undef CAS128_CHECK
    return failures == 0;
}
#endif

static uint64_t simulate_block_limit(void)
{
    static int have;
    static uint64_t cached;
    if (!__atomic_load_n( &have, __ATOMIC_ACQUIRE ))
    {
        const char *value = getenv( "MACRUNNER_HB_XTAJIT64_BLOCK_LIMIT" );
        char *end = NULL;
        unsigned long long parsed;
        uint64_t result = 0;

        if (value && *value)
        {
            errno = 0;
            parsed = strtoull( value, &end, 0 );
            if (!(errno != 0 || end == value || (end && *end != '\0'))) result = (uint64_t)parsed;
        }
        cached = result;
        __atomic_store_n( &have, 1, __ATOMIC_RELEASE );
    }
    return cached;
}

/* Claude, 25.09.2026 — FAST EXEC (замер, по умолчанию выключен). Биты MACRUNNER_HB_FAST_EXEC:
 *   1 — профиль EXEC исполняется пакетно: код читается прямо из памяти процесса (fetch_code),
 *       поднимается целым куском до 4 КБ, без запроса защиты и копии байтов перед КАЖДОЙ
 *       инструкцией и без наблюдателя EXEC; лимит — не 256 единиц, а 1 Мi блоков за вызов.
 *       Страница кода проверяется так же, как в прежних профилях 3/7 (чтение через
 *       process_memory), — это договор FEX: защита учитывается при переводе, а не на каждом шаге.
 *   2 — блоки с CALL/RET исполняются JIT, а не интерпретатором.
 *   4 — без запроса Wine перед каждым скалярным/парным обращением к данным (сторожевые
 *       страницы данных тогда ловятся только обычным отказом).
 *   8 — native_read/native_write: прямой доступ под страховкой Wine вместо mach_vm_read/write.
 *  16 — сброс переводов по ДИАПАЗОНУ из уведомления, а не всего адресного пространства.
 *  32 — кеш «страница без PAGE_GUARD» до следующего уведомления о карте памяти (scalar_preaccess).
 * Точность исключений на сторожевых страницах в быстром режиме НЕ заявляется. */
static unsigned int fast_exec_flags(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *value = getenv( "MACRUNNER_HB_FAST_EXEC" );
        cached = value && *value ? (int)(strtoul( value, NULL, 0 ) & 16383u) : 0;
        if (cached)
        {
            fprintf( stderr, "hyperbridge-fast-exec: flags=%d\n", cached );
            fflush( stderr );
        }
    }
    return (unsigned int)cached;
}

static __thread uint64_t fast_stat_blocks, fast_stat_steps, fast_stat_calls, fast_stat_next;
static __thread uint64_t fast_stat_lifts, fast_stat_stub, fast_stat_stub_empty;

/* Claude 26.09: гистограмма гостевых адресов входа в цикл симуляции (MACRUNNER_HB_PC_HIST=1) —
 * чтобы увидеть, где крутится поток при застревании. Раз в 2^20 входов печатает 12 самых частых. */
#define PC_HIST_SLOTS 4096u
static __thread uint64_t pc_hist_pc[PC_HIST_SLOTS], pc_hist_n[PC_HIST_SLOTS], pc_hist_total;
static void pc_hist_note( uint64_t pc )
{
    static int enabled = -1;
    unsigned slot, k;
    if (enabled < 0) { const char *v = getenv( "MACRUNNER_HB_PC_HIST" ); enabled = v && *v && *v != '0'; }
    if (!enabled) return;
    slot = (unsigned)((pc * 0x9e3779b97f4a7c15ull) >> 52) & (PC_HIST_SLOTS - 1);
    if (pc_hist_pc[slot] != pc) { pc_hist_pc[slot] = pc; pc_hist_n[slot] = 0; }
    pc_hist_n[slot]++;
    if (++pc_hist_total & ((1u << 20) - 1)) return;
    for (k = 0; k < 12; k++)
    {
        unsigned best = 0, i;
        for (i = 1; i < PC_HIST_SLOTS; i++) if (pc_hist_n[i] > pc_hist_n[best]) best = i;
        if (!pc_hist_n[best]) break;
        fprintf( stderr, "hyperbridge-pc-hist: tid=%p rank=%u pc=%016llx n=%llu\n", (void *)pthread_self(), k,
                 (unsigned long long)pc_hist_pc[best], (unsigned long long)pc_hist_n[best] );
        pc_hist_n[best] = 0;
    }
    memset( pc_hist_n, 0, sizeof(pc_hist_n) );
    fflush( stderr );
}

static void fast_exec_stats( uint64_t blocks, uint64_t steps )
{
    static int enabled = -1;
    fast_stat_calls++;
    fast_stat_blocks += blocks;
    fast_stat_steps += steps;
    if (enabled < 0) enabled = getenv( "MACRUNNER_HB_FAST_STATS" ) != NULL;
    if (!enabled || fast_stat_blocks < fast_stat_next) return;
    fast_stat_next = fast_stat_blocks + (1u << 20);
    fprintf( stderr, "hyperbridge-fast-stats: tid=%p calls=%llu blocks=%llu steps=%llu lifts=%llu stub=%llu stub_empty=%llu\n",
             (void *)pthread_self(), (unsigned long long)fast_stat_calls,
             (unsigned long long)fast_stat_blocks, (unsigned long long)fast_stat_steps,
             (unsigned long long)fast_stat_lifts, (unsigned long long)fast_stat_stub,
             (unsigned long long)fast_stat_stub_empty );
    fflush( stderr );
}

static BOOL func_ends_in_control_transfer( const hb_ir_func_t *func )
{
    hb_ir_block_t *block;

    if (!func || !func->cfg || !func->cfg->entry) return FALSE;
    block = func->cfg->entry;
    if (!block->instr_count) return FALSE;
    switch (block->instrs[block->instr_count - 1].op)
    {
    case HB_IR_CALL:
    case HB_IR_RET:
    case HB_IR_JMP:
    case HB_IR_Jcc:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS ensure_process(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    pthread_mutex_lock( &process_mutex );
    if (!process_ready)
    {
        process_memory = hb_memory_create( 0 );
        if (!process_memory) status = STATUS_NO_MEMORY;
        else
        {
            hb_memory_set_special_handlers( process_memory, native_read, native_write, NULL );
            /* Бит 8: запись ядра в тождественные области — через native_write (прямо). */
            if (fast_exec_flags() & 8) hb_memory_set_identity_writes_special( process_memory, true );
            /* Бит 64: скалярные MOV — в родной код; интерпретатор (путь отказа) сохраняет запрос Wine. */
            {
                const char *sr = getenv( "MACRUNNER_HB_STORE_NATIVE_RANGE" );
                if (sr && *sr)
                {
                    char *end = NULL;
                    unsigned long long lo = strtoull( sr, &end, 16 ), hi = 0;
                    if (end && *end == '-') hi = strtoull( end + 1, NULL, 16 );
                    hb_codegen_set_store_native_range( lo, hi );
                    fprintf( stderr, "hyperbridge-store-native-range: %llx-%llx\n", lo, hi );
                }
            }
            /* Бит 8192 (опыт): запись помощника в исполняемую область через hb_memory_write. */
            if (fast_exec_flags() & 8192) hb_codegen_set_store_exec_via_memory_write( true );
            /* Бит 4096 (опыт): родной выпуск только MOV-загрузок. */
            if (fast_exec_flags() & 4096) hb_codegen_set_scalar_native_loads_only( true );
            /* Бит 2048 (опыт): без помощников-идиом. */
            if (fast_exec_flags() & 2048) hb_codegen_set_no_idioms( true );
            /* Бит 1024 (опыт): без сцепки x64. */
            if (fast_exec_flags() & 1024) hb_runtime_set_chain_x64_disabled( true );
            /* Бит 512: вход в код из записываемой памяти — только через диспетчер со сверкой SMC. */
            if (fast_exec_flags() & 512) hb_runtime_set_chain_skip_smc_tracked( true );
            /* Бит 128: кеш записываемых областей помощников по поколению карты памяти. */
            if (fast_exec_flags() & 128) hb_codegen_set_live_write_generation( &vm_map_generation );
            if (fast_exec_flags() & 64)
            {
                hb_memory_install_fault_handlers();
                /* MACRUNNER_HB_SCALAR_NATIVE_RANGE=lo-hi (hex): поиск ошибочного блока делением. */
                const char *range = getenv( "MACRUNNER_HB_SCALAR_NATIVE_RANGE" );
                hb_codegen_set_scalar_native( true );
                if (range && *range)
                {
                    char *end = NULL;
                    unsigned long long lo = strtoull( range, &end, 16 ), hi = UINT64_MAX;
                    if (end && *end == '-') hi = strtoull( end + 1, NULL, 16 );
                    hb_codegen_set_scalar_native_range( lo, hi );
                    fprintf( stderr, "hyperbridge-scalar-native-range: %llx-%llx\n", lo, hi );
                    fflush( stderr );
                }
            }
#if defined(__APPLE__) && defined(__aarch64__)
            if (__atomic_always_lock_free(16, 0))
                hb_memory_set_atomic_cmpxchg128_handler( process_memory, native_atomic_cmpxchg128, NULL );
#endif
            process_ready = TRUE;
        }
    }
    pthread_mutex_unlock( &process_mutex );
    return status;
}

static NTSTATUS ensure_thread(void)
{
    struct hb_thread_resources *resources;
    BOOL use_jit;
    NTSTATUS status;

    if ((status = ensure_process())) return status;
    /* Consult canonical ownership even if native TLS destructors re-enter.
     * Darwin's C TLS teardown order need not match our pthread-key order. */
    use_jit = xtajit64_use_jit_backend();
    resources = hb_thread_resources_get( process_memory, use_jit );
    if (!resources) return STATUS_NO_MEMORY;
    thread_ctx = resources->ctx;
    thread_jit = resources->jit;
    if (use_jit && !thread_jit && trace_xtajit64_enabled())
    {
        fprintf( stderr, "macrunner-xtajit64-unix: jit runtime create failed; using interpreter\n" );
        fflush( stderr );
    }
    return STATUS_SUCCESS;
}

static void import_context( hb_context_t *ctx, const struct xtajit64_amd64_context *src, uint64_t teb_fallback )
{
    unsigned int i;

    ctx->regs.x64.rax = src->rax;
    ctx->regs.x64.rbx = src->rbx;
    ctx->regs.x64.rcx = src->rcx;
    ctx->regs.x64.rdx = src->rdx;
    ctx->regs.x64.rsi = src->rsi;
    ctx->regs.x64.rdi = src->rdi;
    ctx->regs.x64.rsp = src->rsp;
    ctx->regs.x64.rbp = src->rbp;
    ctx->regs.x64.r8 = src->r8;
    ctx->regs.x64.r9 = src->r9;
    ctx->regs.x64.r10 = src->r10;
    ctx->regs.x64.r11 = src->r11;
    ctx->regs.x64.r12 = src->r12;
    ctx->regs.x64.r13 = src->r13;
    ctx->regs.x64.r14 = src->r14;
    ctx->regs.x64.r15 = src->r15;
    ctx->regs.x64.rip = src->rip;
    hb_packet_flags_import( ctx, src->rflags );
    ctx->pc = src->rip;
    ctx->fs_base = src->fs_base;
    ctx->gs_base = src->gs_base ? src->gs_base : teb_fallback;
    ctx->seg_cs = src->seg_cs;
    ctx->seg_ds = src->seg_ds;
    ctx->seg_es = src->seg_es;
    ctx->seg_fs = src->seg_fs;
    ctx->seg_gs = src->seg_gs;
    ctx->seg_ss = src->seg_ss;
    for (i = 0; i < 16; i++)
    {
        ctx->regs.x64.xmm[i][0] = src->xmm[i][0];
        ctx->regs.x64.xmm[i][1] = src->xmm[i][1];
    }
}

static NTSTATUS export_context( struct xtajit64_amd64_context *dst, hb_context_t *ctx )
{
    unsigned int i;
    uint64_t flags;
    hb_result_t result = hb_packet_flags_export( ctx, &flags );
    if (result != HB_OK) return status_from_hb( result );

    dst->rax = ctx->regs.x64.rax;
    dst->rbx = ctx->regs.x64.rbx;
    dst->rcx = ctx->regs.x64.rcx;
    dst->rdx = ctx->regs.x64.rdx;
    dst->rsi = ctx->regs.x64.rsi;
    dst->rdi = ctx->regs.x64.rdi;
    dst->rsp = ctx->regs.x64.rsp;
    dst->rbp = ctx->regs.x64.rbp;
    dst->r8 = ctx->regs.x64.r8;
    dst->r9 = ctx->regs.x64.r9;
    dst->r10 = ctx->regs.x64.r10;
    dst->r11 = ctx->regs.x64.r11;
    dst->r12 = ctx->regs.x64.r12;
    dst->r13 = ctx->regs.x64.r13;
    dst->r14 = ctx->regs.x64.r14;
    dst->r15 = ctx->regs.x64.r15;
    dst->rip = ctx->regs.x64.rip;
    dst->rflags = flags;
    dst->fs_base = ctx->fs_base;
    dst->gs_base = ctx->gs_base;
    dst->seg_cs = ctx->seg_cs;
    dst->seg_ds = ctx->seg_ds;
    dst->seg_es = ctx->seg_es;
    dst->seg_fs = ctx->seg_fs;
    dst->seg_gs = ctx->seg_gs;
    dst->seg_ss = ctx->seg_ss;
    for (i = 0; i < 16; i++)
    {
        dst->xmm[i][0] = ctx->regs.x64.xmm[i][0];
        dst->xmm[i][1] = ctx->regs.x64.xmm[i][1];
    }
    return STATUS_SUCCESS;
}

static NTSTATUS import_context_v2( hb_context_t *ctx, const struct xtajit64_simulate_params_v2 *src,
                                    uint64_t teb_fallback )
{
    if (!ctx || !src || !macrunner_hb_x64_packet_extension_valid( &src->extension, sizeof(*src) ))
        return STATUS_INVALID_PARAMETER;
    import_context( ctx, &src->v1.context, teb_fallback );
    ctx->mxcsr = src->extension.mxcsr;
    hb_host_fpcr_apply_mxcsr( ctx->mxcsr );
    return STATUS_SUCCESS;
}

static NTSTATUS export_context_v2( struct xtajit64_simulate_params_v2 *dst, hb_context_t *ctx )
{
    NTSTATUS status;
    if (!dst || !ctx || !macrunner_hb_x64_packet_extension_valid( &dst->extension, sizeof(*dst) ))
        return STATUS_INVALID_PARAMETER;
    if ((status = export_context( &dst->v1.context, ctx ))) return status;
    dst->extension.mxcsr = ctx->mxcsr;
    return STATUS_SUCCESS;
}

static size_t fetch_code( hb_memory_t *memory, uint64_t pc, uint8_t *code, size_t max_code_bytes )
{
    size_t len = 0;

    while (len < max_code_bytes)
    {
        size_t page_left = native_page_size() - (size_t)((pc + len) & (native_page_size() - 1));
        size_t chunk = max_code_bytes - len;
        size_t i;

        if (chunk > page_left) chunk = page_left;
        if (hb_memory_read( memory, pc + len, &code[len], chunk ) == HB_OK)
        {
            len += chunk;
            continue;
        }

        for (i = 0; i < chunk; i++)
        {
            if (hb_memory_read_u8( memory, pc + len, &code[len] ) != HB_OK) return len;
            len++;
        }
    }
    return len;
}

static NTSTATUS unix_process_init_impl( void *args )
{
    struct xtajit64_process_init_params *params = args;
    NTSTATUS status;

    if (params && !xtajit64_process_init_request_valid( params )) return STATUS_INVALID_PARAMETER;
#if defined(__APPLE__) && defined(__aarch64__)
    {
        const char *selftest = getenv( "MACRUNNER_HB_CAS128_SELFTEST" );
        if (selftest && !strcmp(selftest, "1") && !native_cas128_guard_selftest())
            return STATUS_UNSUCCESSFUL;
    }
#endif
    status = ensure_process();
    if (!status && params)
    {
        uint32_t cpuid_edx;
        xtajit64_reply_process_init( params );
        params->features |= XTAJIT64_FEATURE_SIMULATE_V3 | XTAJIT64_FEATURE_SIMULATE_V4 |
                            XTAJIT64_FEATURE_SIMULATE_V5;
        params->features |= XTAJIT64_FEATURE_SYSCALL_STUB | XTAJIT64_FEATURE_X87_TRANSFER;
        /* Query the actual core policy, including its explicit MMX opt-in. */
        hb_cpuid_query( NULL, 1, 0, NULL, NULL, NULL, &cpuid_edx );
        if (cpuid_edx & (1u << 23)) params->features |= XTAJIT64_FEATURE_CPUID_MMX;
        params->unix_funcs_count = unix_funcs_count_x87;
    }
    if (!status)
    {
        extern const unixlib_entry_t __wine_unix_call_funcs[];
        Dl_info image = {0};
        dladdr((const void *)__wine_unix_call_funcs, &image);
        fprintf(stderr, "hyperbridge-xtajit: backend=independent-hb transport=unix-v3 image=%s\n",
                image.dli_fname ? image.dli_fname : "unresolved");
        fflush(stderr);
    }
    return status;
}

static NTSTATUS unix_thread_init_impl( void *args )
{
    return ensure_thread();
}

static NTSTATUS unix_thread_term_impl( void *args )
{
    /* PRE notification on the caller, including foreign/invalid handles.
     * pthread exit, after any late guest callbacks, owns actual teardown. */
    return STATUS_SUCCESS;
}

static NTSTATUS unix_process_term_impl( void *args )
{
    /* NtTerminateProcess(NULL) returns before LdrShutdownProcess callbacks.
     * Keep the address space valid for every remaining thread until OS exit. */
    return STATUS_SUCCESS;
}

/* Opus 26.09.2026 — переполнение арены JIT есть внутреннее состояние движка, а не отказ гостя.
 * Ядро отдаёт его как фаллбэк ТОЛЬКО при нуле исполненных шагов (иначе — уступка на границе
 * блока), поэтому восстановление входа и интерпретация здесь ничего не переигрывают. Раньше
 * эта причина не узнавалась и уходила гостю как STATUS_ILLEGAL_INSTRUCTION (c000001d). */
static BOOL jit_cache_full_fallback( hb_result_t result, const hb_exec_result_t *exec )
{
    return result == HB_OK && exec && exec->faulted && exec->fault_reason &&
           !hb_exec_result_has_progress( exec ) &&
           !strcmp( exec->fault_reason, "JIT code cache full; interpreter fallback" );
}

static BOOL jit_should_fallback( hb_result_t result, const hb_exec_result_t *exec )
{
    if (result != HB_OK) return FALSE;
    if (!exec || !exec->faulted || !exec->fault_reason) return FALSE;
    return !strcmp( exec->fault_reason, "JIT codegen failed" ) ||
           !strcmp( exec->fault_reason, "JIT helper fault" ) ||
           jit_cache_full_fallback( result, exec );
}

static BOOL func_has_call_or_ret( const hb_ir_func_t *func )
{
    size_t b, i;

    if (!func || !func->cfg) return TRUE;
    for (b = 0; b < func->cfg->block_count; b++)
    {
        const hb_ir_block_t *block = func->cfg->blocks[b];
        if (!block) continue;
        for (i = 0; i < block->instr_count; i++)
        {
            hb_ir_op_t op = block->instrs[i].op;
            if (op == HB_IR_CALL || op == HB_IR_RET || op == HB_IR_HOST_CALL)
                return TRUE;
        }
    }
    return FALSE;
}

/* Прямой вызов кода хоста из переведённого кода (HB_IR_HOST_CALL) — наследие интеграции
 * внутри Wine. В адаптере переход в родной код обязан идти через границу ARM64EC и PE-сторону,
 * поэтому функции с ним по-прежнему исполняет интерпретатор даже при бите 2. */
static BOOL func_has_host_call( const hb_ir_func_t *func )
{
    size_t b, i;

    if (!func || !func->cfg) return TRUE;
    for (b = 0; b < func->cfg->block_count; b++)
    {
        const hb_ir_block_t *block = func->cfg->blocks[b];
        if (!block) continue;
        for (i = 0; i < block->instr_count; i++)
            if (block->instrs[i].op == HB_IR_HOST_CALL) return TRUE;
    }
    return FALSE;
}

static hb_result_t run_interpreter_slice( const hb_ir_func_t *func, hb_exec_result_t *out,
                                          BOOL *budget_yield )
{
    hb_result_t result = hb_runtime_run( thread_ctx, func, HB_BACKEND_INTERP, out );
    /* The pinned interpreter completes all IR belonging to one guest
     * instruction before publishing the next RIP at an instruction limit. */
    if (result == HB_OK && out->result == HB_ERR_STEP_LIMIT &&
        !out->faulted && (out->steps_executed ||
                         (thread_ctx->exec_access && out->blocks_executed == 1)))
    {
        out->result = HB_OK;
        *budget_yield = TRUE;
    }
    return result;
}

static BOOL cooperative_suspend_pending(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    return cpu && cpu->SuspendDoorbell &&
           __atomic_load_n( cpu->SuspendDoorbell, __ATOMIC_RELAXED );
}

/* Claude 25.09 (бит 256): пустая функция для входа, у которого уже есть перевод. Если JIT при ней
 * запросит откат в интерпретатор, исполнять нечего — возвращаемся без шагов, а следующий виток
 * цикла делает полный разбор (stub_force_lift). */
static __thread hb_ir_func_t *stub_func;
static __thread BOOL stub_force_lift;

static const hb_ir_func_t *get_stub_func( uint64_t pc )
{
    if (!stub_func) stub_func = hb_ir_func_create( pc, 0 );
    if (stub_func) stub_func->guest_addr = pc;
    return stub_func;
}

static BOOL no_ctx_snapshot_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_NO_CTX_SNAPSHOT" );
        cached = (v && v[0] && v[0] != '0') ? 1 : 0;
        fprintf( stderr, "macrunner-gate: MACRUNNER_HB_NO_CTX_SNAPSHOT=%d\n", cached );
    }
    return cached;
}

static hb_result_t run_translated_block( const hb_ir_func_t *func, hb_exec_result_t *out,
                                         BOOL *budget_yield )
{
    hb_exec_result_t jit_out;
    hb_context_t saved_ctx;
    BOOL snap;
    hb_result_t result;
    uint64_t scalar_entries_before, pair_entries_before;

    *budget_yield = FALSE;
    if (thread_ctx->exec_access)
    {
        uint64_t entries_before = thread_ctx->exec_access_jit_entries;
        /* The enabled core accepts only one validated architectural unit.
         * No old multi-block fallback may restore or replay committed state. */
        if (!thread_jit) return run_interpreter_slice( func, out, budget_yield );
        memset( out, 0, sizeof(*out) );
        scalar_entries_before = thread_ctx->scalar_access_jit_entries;
        pair_entries_before = thread_ctx->pair_access_jit_entries;
        result = hb_jit_runtime_run( thread_jit, func, out );
        /* Единица не исполнялась (переполнение арены) — её исполнит интерпретатор. */
        if (jit_cache_full_fallback( result, out ))
            return run_interpreter_slice( func, out, budget_yield );
        if ((result == HB_ERR_ACCESS_PENDING || out->result == HB_ERR_ACCESS_PENDING) &&
            getenv( "MACRUNNER_HB_TRACE_GUARD_PENDING" ))
        {
            const struct xtajit64_simulate_params_v5 *frame = thread_ctx->exec_access_user;
            /* Preserve the admitted data-helper diagnostics using their own
             * actual counters. EXEC/fetch pending is a distinct phase. */
            if (frame && frame->v4.pending &&
                frame->v4.request.phase == WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS)
                fprintf( stderr, "hyperbridge-guard-pair-pending: backend=jit helper_entries=%llu pc=%016llx width=%llu\n",
                         (unsigned long long)(thread_ctx->pair_access_jit_entries - pair_entries_before),
                         (unsigned long long)thread_ctx->pc,
                         (unsigned long long)frame->v4.request.span_length );
            else if (frame && frame->v4.pending &&
                     frame->v4.request.phase == WINE_EMULATOR_MEMORY_ACCESS_SCALAR_PREACCESS)
                fprintf( stderr, "hyperbridge-guard-pending: backend=jit helper_entries=%llu pc=%016llx\n",
                         (unsigned long long)(thread_ctx->scalar_access_jit_entries - scalar_entries_before),
                         (unsigned long long)thread_ctx->pc );
            fprintf( stderr, "hyperbridge-exec-unit: backend=jit helper_entries=%llu pc=%016llx phase=%u width=%llu result=%d faulted=%u\n",
                     (unsigned long long)(thread_ctx->exec_access_jit_entries - entries_before),
                     (unsigned long long)thread_ctx->pc,
                     frame && frame->v4.pending ? frame->v4.request.phase : 0,
                     (unsigned long long)(frame && frame->v4.pending ? frame->v4.request.span_length : 0),
                     out->result, (unsigned int)out->faulted );
            fflush( stderr );
        }
        /* A partial REP unit can yield after committed iterations. Preserve
         * its exact PC/count/pointers; observer errors are faulted and excluded. */
        if (result == HB_OK && out->result == HB_ERR_STEP_LIMIT &&
            !out->faulted && out->blocks_executed == 1)
        {
            out->result = HB_OK;
            *budget_yield = TRUE;
        }
        return result;
    }
    if (!thread_jit ||
        ((fast_exec_flags() & 2) ? func_has_host_call( func ) : func_has_call_or_ret( func )))
        return run_interpreter_slice( func, out, budget_yield );

    /* Opus 26.09.2026 — СНИМОК КОНТЕКСТА ТОЛЬКО ТАМ, ГДЕ ОН МОЖЕТ ПОНАДОБИТЬСЯ (гейт
     * MACRUNNER_HB_NO_CTX_SNAPSHOT, умолчание 0). Копия hb_context_t (~2,6 КБ) делалась на
     * КАЖДОМ входе и нужна только откату ниже; профиль HK 26.09 — 4 % рабочего потока в этом
     * memmove. В быстром режиме (scalar/pair) откат бывает только при НУЛЕ исполненных шагов:
     * провал кодогенерации ядро само доигрывает интерпретатором С ТЕКУЩЕГО блока
     * (hb_codegen_fail_to_interp), отказ помощника возвращается выше без отката, переполнение
     * арены отдаётся фаллбэком лишь до первого шага. Значит, контекст к откату не тронут. */
    snap = !(thread_ctx->scalar_access || thread_ctx->pair_access) || !no_ctx_snapshot_enabled();
    if (snap) saved_ctx = *thread_ctx;
    memset( &jit_out, 0, sizeof(jit_out) );
    scalar_entries_before = thread_ctx->scalar_access_jit_entries;
    pair_entries_before = thread_ctx->pair_access_jit_entries;
    result = hb_jit_runtime_run( thread_jit, func, &jit_out );
    if ((result == HB_ERR_ACCESS_PENDING || jit_out.result == HB_ERR_ACCESS_PENDING) &&
        getenv( "MACRUNNER_HB_TRACE_GUARD_PENDING" ))
    {
        const struct xtajit64_simulate_params_v4 *pair = thread_ctx->pair_access_user;
        if (pair && pair->pending == 1 &&
            pair->request.phase == WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS)
            fprintf( stderr, "hyperbridge-guard-pair-pending: backend=jit helper_entries=%llu pc=%016llx width=%llu\n",
                     (unsigned long long)(thread_ctx->pair_access_jit_entries - pair_entries_before),
                     (unsigned long long)thread_ctx->pc,
                     (unsigned long long)pair->request.span_length );
        else
            fprintf( stderr, "hyperbridge-guard-pending: backend=jit helper_entries=%llu pc=%016llx\n",
                     (unsigned long long)(thread_ctx->scalar_access_jit_entries - scalar_entries_before),
                     (unsigned long long)thread_ctx->pc );
        fflush( stderr );
    }
    /* Pending accesses and helper faults already have committed prefix state.
     * Never restore the block-entry registers and replay that prefix. */
    if (result == HB_ERR_ACCESS_PENDING || jit_out.result == HB_ERR_ACCESS_PENDING ||
        ((thread_ctx->scalar_access || thread_ctx->pair_access) && jit_out.faulted && jit_out.fault_reason &&
         !strcmp( jit_out.fault_reason, "JIT helper fault" )))
    {
        *out = jit_out;
        return result;
    }
    if (result == HB_OK && jit_out.result == HB_ERR_STEP_LIMIT &&
        !jit_out.faulted && hb_exec_result_has_progress( &jit_out ))
    {
        /* The JIT commits architectural state at this resumable slice boundary.
         * Keep the instruction budget; deliver the saved context to the PE
         * loop instead of converting an ordinary yield into a guest exception.
          * Faulted results are never normalized. */
        *out = jit_out;
        out->result = HB_OK;
        *budget_yield = TRUE;
        return HB_OK;
    }
    if (!jit_should_fallback( result, &jit_out ))
    {
        *out = jit_out;
        return result;
    }
    if (func == stub_func)
    {
        if (snap) *thread_ctx = saved_ctx;
        thread_ctx->memory = process_memory;
        memset( out, 0, sizeof(*out) );
        out->result = HB_OK;
        stub_force_lift = TRUE;
        return HB_OK;
    }

    if (trace_xtajit64_enabled() || getenv( "MACRUNNER_HB_TRACE_JIT_FALLBACKS" ))
    {
        fprintf( stderr, "macrunner-xtajit64-unix: jit-fallback pc=%016llx result=%s(%d) reason=%s "
                 "steps=%llu blocks=%llu\n",
                 (unsigned long long)thread_ctx->regs.x64.rip,
                 hb_result_string( jit_out.result ), jit_out.result,
                 jit_out.fault_reason ? jit_out.fault_reason : "",
                 (unsigned long long)jit_out.steps_executed,
                 (unsigned long long)jit_out.blocks_executed );
        fflush( stderr );
    }

    if ((!snap || jit_out.counters_are_dispatches) && hb_exec_result_has_progress( &jit_out ))
    {
        /* Без снимка откатывать нечем, а повтор исполненного недопустим — отдаём как есть.
         * Counter-free chains also forbid replay with a register snapshot:
         * preceding blocks may already have committed guest-memory stores. */
        static uint64_t no_snap_refused;
        uint64_t n = __atomic_add_fetch( &no_snap_refused, 1, __ATOMIC_RELAXED );
        if (n <= 8)
            fprintf( stderr, "hyperbridge-no-snapshot-fallback: n=%llu steps=%llu blocks=%llu reason=%s\n",
                     (unsigned long long)n, (unsigned long long)jit_out.steps_executed,
                     (unsigned long long)jit_out.blocks_executed,
                     jit_out.fault_reason ? jit_out.fault_reason : "" );
        *out = jit_out;
        return result;
    }
    if (snap) *thread_ctx = saved_ctx;
    thread_ctx->memory = process_memory;
    result = run_interpreter_slice( func, out, budget_yield );
    return result;
}

/* Non-consuming observation at an architectural scalar MOV boundary. The
 * Wine service will revalidate current authoritative protection before consume.
 * NtQueryVirtualMemory is not a permission grant or a mapping lifetime lease. */
static hb_result_t scalar_preaccess( void *user, uint64_t pc, hb_gva_t address,
                                     size_t size, uint32_t access )
{
    struct xtajit64_simulate_params_v4 *params = user;
    uint64_t end, cursor;
    const BOOL cache_guard = (fast_exec_flags() & 32) != 0;
    if (!params || !size || address > UINT64_MAX - (size - 1)) return HB_OK;
    end = address + size - 1;
    cursor = address;
    for (;;)
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returned = 0;
        NTSTATUS status;
        uint64_t generation = 0;
        if (cache_guard)
        {
            if (guard_free_cached( cursor & ~UINT64_C(4095) ))
            {
                if ((cursor >> 12) == (end >> 12)) break;
                cursor = (cursor | UINT64_C(4095)) + 1;
                continue;
            }
            generation = __atomic_load_n( &vm_map_generation, __ATOMIC_ACQUIRE );
        }
        status = NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)cursor,
                                       MemoryBasicInformation, &mbi, sizeof(mbi), &returned );
        if (status || returned < sizeof(mbi)) return HB_OK; /* Ordinary access owns AV. */
        /* Запоминаем только ВЫДЕЛЕННУЮ страницу без сторожа: невыделенная ведёт к обычному AV,
         * его точность не зависит от этого запроса, но кешировать её незачем. */
        if (cache_guard && mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD))
            guard_free_remember( cursor & ~UINT64_C(4095), generation );
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD))
        {
            WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 request = {0};
            if ((address >> 12) != (end >> 12)) return HB_ERR_UNSUPPORTED_FEATURE;
            if (params->pending || (access != 0 && access != 1)) return HB_ERR_INTERNAL;
            request.size = sizeof(request);
            request.version = WINE_EMULATOR_MEMORY_ACCESS_VERSION;
            request.owner_module = params->owner_module;
            request.selection_epoch = params->selection_epoch;
            request.current_teb = params->current_teb;
            request.invocation_serial = params->invocation_serial;
            request.guest_pc = pc;
            request.guest_address = address;
            request.span_length = size;
            request.access = access;
            request.phase = WINE_EMULATOR_MEMORY_ACCESS_SCALAR_PREACCESS;
            params->request = request;
            params->pending = 1;
            return HB_ERR_ACCESS_PENDING;
        }
        if ((cursor >> 12) == (end >> 12)) break;
        cursor = (cursor | UINT64_C(4095)) + 1;
    }
    return HB_OK;
}

static int pair_query_page( void *user, uint64_t address, struct hb_pair_page_view *view )
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returned = 0;
    hb_perm_t perm;
    (void)user;
    if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)address,
                              MemoryBasicInformation, &mbi, sizeof(mbi), &returned ) ||
        returned < sizeof(mbi)) return 0;
    perm = protect_to_perm( mbi.Protect );
    view->base = (uintptr_t)mbi.BaseAddress;
    view->size = mbi.RegionSize;
    view->committed = mbi.State == MEM_COMMIT;
    view->readable = !!(perm & HB_PERM_READ);
    view->writable = !!(perm & HB_PERM_WRITE);
    view->guard = !!(mbi.Protect & PAGE_GUARD);
    return 1;
}

/* Called only by the separately enabled pair instruction hook, before its
 * first read/CAS. Comparison mismatch has the same architectural write intent.
 * Querying VM metadata cannot consume PAGE_GUARD or deliver a native exception. */
static hb_result_t pair_preaccess( void *user, uint64_t pc, hb_gva_t address,
                                   size_t size, uint32_t access )
{
    struct xtajit64_simulate_params_v4 *params = user;
    WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 request = {0};
    enum hb_pair_preflight_result result;
    uint64_t fault_address = address;
    if (!params || !wine_emulator_memory_access_scope_valid_v1( params->capabilities,
            WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS, access, size ))
        return HB_ERR_UNSUPPORTED_FEATURE;
    if (!wine_emulator_memory_access_alignment_valid_v1(
            WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS, size, address )) return HB_ERR_INVALID_ARG;
    if (params->pending) return HB_ERR_INTERNAL;
    result = hb_pair_preflight( address, size, pair_query_page, NULL, &fault_address );
    if (result == HB_PAIR_PREFLIGHT_OK) return HB_OK;
    if (result == HB_PAIR_PREFLIGHT_WRITE_FAULT) return record_memory_fault( fault_address, 1 );
    if (result != HB_PAIR_PREFLIGHT_GUARD) return HB_ERR_UNSUPPORTED_FEATURE;
    request.size = sizeof(request);
    request.version = WINE_EMULATOR_MEMORY_ACCESS_VERSION;
    request.owner_module = params->owner_module;
    request.selection_epoch = params->selection_epoch;
    request.current_teb = params->current_teb;
    request.invocation_serial = params->invocation_serial;
    request.guest_pc = pc;
    request.guest_address = address;
    request.span_length = size;
    request.access = WINE_EMULATOR_MEMORY_ACCESS_WRITE;
    request.phase = WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS;
    params->request = request;
    params->pending = 1;
    return HB_ERR_ACCESS_PENDING;
}

/* Optional fresh, one-page metadata query. An older Wine or any malformed reply
 * retains the original BasicInformation behavior; no permission is cached. */
static BOOL exec_query_metadata( uint64_t address, MEMORY_BASIC_INFORMATION *info,
                                 BOOL *private_rx )
{
    WINE_EMULATOR_EXEC_PAGE_INFORMATION_V1 page = {0};
    MEMORY_BASIC_INFORMATION basic = {0};
    SIZE_T returned = 0;
    NTSTATUS status;
    ULONG protection;

    if (private_rx) *private_rx = FALSE;
    status = NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)address,
            (MEMORY_INFORMATION_CLASS)WINE_EMULATOR_EXEC_PAGE_INFORMATION_CLASS_V1,
            &page, sizeof(page), &returned );
    protection = page.protect & 0xff;
    if (!status && returned == sizeof(page) &&
        page.size == WINE_EMULATOR_EXEC_PAGE_INFORMATION_SIZE_V1 &&
        page.version == WINE_EMULATOR_EXEC_PAGE_INFORMATION_VERSION_V1 &&
        ((page.state == MEM_RESERVE && !page.protect) ||
         (page.state == MEM_COMMIT && protection && !(protection & (protection - 1)) &&
          !(page.protect & ~(0xffu | PAGE_GUARD | PAGE_NOCACHE)))))
    {
        basic.BaseAddress = (void *)(uintptr_t)(address &
                ~(uint64_t)(WINE_EMULATOR_EXEC_PAGE_SIZE_V1 - 1));
        basic.RegionSize = WINE_EMULATOR_EXEC_PAGE_SIZE_V1;
        basic.State = page.state;
        basic.Protect = page.protect;
        if (private_rx && page.state == MEM_COMMIT && page.protect == PAGE_EXECUTE_READ)
            *private_rx = TRUE;
    }
    else
    {
        returned = 0;
        if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)address,
                MemoryBasicInformation, &basic, sizeof(basic), &returned ) ||
            returned < sizeof(basic)) return FALSE;
    }
    *info = basic;
    return TRUE;
}

/* Non-consuming metadata check for one architecturally demanded extent. Guard
 * precedes NX; address is the earliest demanded byte in this Wine page. */
static hb_result_t exec_query_impl( void *user, uint64_t pc, uint64_t address, size_t size,
                                   BOOL *private_rx )
{
    struct xtajit64_simulate_params_v5 *params = user;
    struct xtajit64_simulate_params_v4 *guard;
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t end, base;
    if (private_rx) *private_rx = FALSE;
    if (!params || !wine_emulator_memory_access_scope_valid_v1( params->v4.capabilities,
            WINE_EMULATOR_MEMORY_ACCESS_EXEC_PREACCESS, 8, size ) ||
        !wine_emulator_memory_access_exec_span_valid_v1(
            WINE_EMULATOR_MEMORY_ACCESS_EXEC_PREACCESS, pc, address, size ) ||
        !size || address > UINT64_MAX - (size - 1)) return HB_ERR_INVALID_ARG;
    end = address + size - 1;
    if ((address >> 12) != (end >> 12)) return HB_ERR_INVALID_ARG;
    guard = &params->v4;
    if (guard->pending) return HB_ERR_INTERNAL;
    if (!exec_query_metadata( address, &mbi, private_rx ))
        return record_memory_fault( address, 8 );
    base = (uintptr_t)mbi.BaseAddress;
    if (mbi.State != MEM_COMMIT || address < base ||
        end - base >= mbi.RegionSize) return record_memory_fault( address, 8 );
    if (mbi.Protect & PAGE_GUARD)
    {
        WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 request = {0};
        request.size = sizeof(request);
        request.version = WINE_EMULATOR_MEMORY_ACCESS_VERSION;
        request.owner_module = guard->owner_module;
        request.selection_epoch = guard->selection_epoch;
        request.current_teb = guard->current_teb;
        request.invocation_serial = guard->invocation_serial;
        request.guest_pc = pc;
        request.guest_address = address;
        request.span_length = size;
        request.access = 8;
        request.phase = WINE_EMULATOR_MEMORY_ACCESS_EXEC_PREACCESS;
        guard->request = request;
        guard->pending = 1;
        return HB_ERR_ACCESS_PENDING;
    }
    if (!(protect_to_perm( mbi.Protect ) & HB_PERM_EXEC))
        return record_memory_fault( address, 8 );
    return HB_OK;
}

static hb_result_t exec_query( void *user, uint64_t pc, uint64_t address, size_t size )
{
    return exec_query_impl( user, pc, address, size, NULL );
}

/* Kernel copy only: it never invokes a guest first-chance handler. The demanded
 * read caller owns an EXEC fault; optional classification owns no fault at all. */
static BOOL exec_copy_bytes( uint64_t address, uint8_t *bytes, size_t size )
{
#ifdef __APPLE__
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)address,
                size, (mach_vm_address_t)(uintptr_t)bytes, &copied ) == KERN_SUCCESS && copied == size;
#else
    (void)address; (void)bytes; (void)size;
    return FALSE; /* No unguarded memcpy substitute on unsupported hosts. */
#endif
}

static hb_result_t exec_read_bytes( void *user, uint64_t address, uint8_t *bytes, size_t size )
{
    (void)user;
    return exec_copy_bytes( address, bytes, size ) ? HB_OK : record_memory_fault( address, 8 );
}

/* A single fetch owns this eligibility value. It never survives an instruction
 * or replaces the fresh final observer. Basic/synthetic metadata is ineligible. */
struct exec_fetch_scope
{
    struct xtajit64_simulate_params_v5 *params;
    uint64_t pc, address;
    size_t demanded;
    BOOL private_rx;
};

static hb_result_t exec_fetch_query( void *user, uint64_t pc, uint64_t address, size_t size )
{
    struct exec_fetch_scope *scope = user;
    BOOL private_rx = FALSE;
    hb_result_t result;
    if (!scope) return HB_ERR_INVALID_ARG;
    scope->private_rx = FALSE;
    result = exec_query_impl( scope->params, pc, address, size, &private_rx );
    if (result == HB_OK && private_rx)
    {
        scope->pc = pc;
        scope->address = address;
        scope->demanded = size;
        scope->private_rx = TRUE;
    }
    return result;
}

static hb_result_t exec_fetch_read_bytes( void *user, uint64_t address,
                                        uint8_t *bytes, size_t size )
{
    struct exec_fetch_scope *scope = user;
    if (!scope) return HB_ERR_INVALID_ARG;
    scope->private_rx = FALSE;
    return exec_read_bytes( scope->params, address, bytes, size );
}

/* Optional copying is fault-neutral. Its failure leaves the exact demanded
 * reader to report an architectural fault; the local bytes are not published. */
static hb_result_t exec_fetch_read_window( void *user, uint64_t pc, uint64_t address,
        size_t demanded, size_t capacity, uint8_t *bytes, size_t *copied )
{
    struct exec_fetch_scope *scope = user;
    BOOL eligible;
    if (copied) *copied = 0;
    if (!scope) return HB_ERR_INVALID_ARG;
    eligible = scope->private_rx;
    scope->private_rx = FALSE;
    if (!eligible || !bytes || !copied || scope->pc != pc || scope->address != address ||
        scope->demanded != demanded || !demanded || capacity <= demanded || capacity > 15 ||
        pc > UINT64_MAX - 14 || address < pc || address - pc > 14 ||
        capacity > 15 - (size_t)(address - pc) ||
        capacity > 4096u - (size_t)(address & 4095u)) return HB_ERR_INVALID_ARG;
    if (!exec_copy_bytes( address, bytes, capacity )) return HB_ERR_MEMORY_FAULT;
    *copied = capacity;
    return HB_OK;
}

static hb_result_t exec_observe_unit( void *user, uint64_t pc, size_t size )
{
    uint64_t address = pc;
    if (!size || size > 15 || pc > UINT64_MAX - (size - 1)) return HB_ERR_INVALID_ARG;
    while (size)
    {
        size_t chunk = 4096u - (size_t)(address & 4095u);
        hb_result_t result;
        if (chunk > size) chunk = size;
        result = exec_query( user, pc, address, chunk );
        if (result != HB_OK) return result;
        address += chunk;
        size -= chunk;
    }
    return HB_OK;
}

/* Optional format classification is distinct from architectural fetch. Limit
 * it to a stable-looking RX region; failed query/copy changes no fault/pending
 * state. Metadata is not a mapping lease or a concurrency guarantee. */
static BOOL exec_classify_syscall( struct xtajit64_simulate_params_v5 *params,
                                  uint64_t pc, const xtajit64_exec_fetch_result *fetched )
{
    struct xtajit64_syscall_snapshot snapshot = {0};
    MEMORY_BASIC_INFORMATION before, after;
    SIZE_T returned = 0;
    uint64_t base;
    if (!params || params->v4.pending || (pc & 15) || pc > UINT64_MAX - 23 ||
        (pc & 4095u) > 4096u - 24 || fetched->size != 3 ||
        fetched->bytes[0] != 0x4c || fetched->bytes[1] != 0x8b || fetched->bytes[2] != 0xd1)
        return FALSE;
    if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)pc,
            MemoryBasicInformation, &before, sizeof(before), &returned ) || returned < sizeof(before))
        return FALSE;
    base = (uintptr_t)before.BaseAddress;
    if (before.State != MEM_COMMIT || before.Protect != PAGE_EXECUTE_READ ||
        pc < base || pc + 23 - base >= before.RegionSize) return FALSE;
    if (!exec_copy_bytes( pc, snapshot.bytes, sizeof(snapshot.bytes) ) ||
        !hb_x64_syscall_stub_match( pc, snapshot.bytes, sizeof(snapshot.bytes), &snapshot.service ))
        return FALSE;
    if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)pc,
            MemoryBasicInformation, &after, sizeof(after), &returned ) || returned < sizeof(after) ||
        after.BaseAddress != before.BaseAddress || after.AllocationBase != before.AllocationBase ||
        after.RegionSize != before.RegionSize || after.State != before.State ||
        after.Protect != before.Protect || after.Type != before.Type) return FALSE;
    snapshot.valid = 1;
    snapshot.guest_pc = pc;
    params->syscall = snapshot;
    return TRUE;
}

static hb_result_t ir_reuse_create( void *user, const hb_decoded_t *decoded,
                                    hb_ir_func_t **out )
{
    (void)user;
    return hb_lift_unit_x64( decoded, out );
}

static void ir_reuse_destroy( void *user, hb_ir_func_t *func )
{
    (void)user;
    hb_ir_func_destroy( func );
}

static NTSTATUS unix_simulate_context( struct xtajit64_simulate_params *params,
                                        struct xtajit64_simulate_params_v2 *params_v2,
                                        BOOL allow_syscall_boundary,
                                        struct xtajit64_simulate_params_v4 *params_v4,
                                        struct xtajit64_simulate_params_v5 *params_v5 )
{
    uint8_t code[XTAJIT64_DEFAULT_MAX_CODE_BYTES];
    uint64_t total_steps = 0, total_blocks = 0, dispatched = 0, block_limit;
    BOOL ran_block = FALSE;
    BOOL syscall_boundary = FALSE;
    BOOL counter_free_yield = FALSE;
    hb_exec_result_t exec;
    hb_result_t result = HB_OK;
    NTSTATUS status;
    size_t max_code_bytes;
    /* This invocation owns immutable IR only; permissions and bytes are fresh. */
    struct hb_ir_reuse_table ir_reuse = {0};
    /* Быстрый режим (см. fast_exec_flags): EXEC-профиль исполняется пакетно. */
    const BOOL fast = params_v5 && (fast_exec_flags() & 1);
    struct xtajit64_simulate_params_v4 *data_guard =
        (fast && (fast_exec_flags() & 4)) ? NULL : params_v4;
    struct xtajit64_simulate_params_v5 *exec_observer = fast ? NULL : params_v5;

    if (!params) return STATUS_INVALID_PARAMETER;
    memset( &thread_fault, 0, sizeof(thread_fault) );
    if ((status = ensure_thread())) return status;
    reset_precise_fault( thread_ctx );
    if (__builtin_expect( __atomic_load_n( &nfp_state, __ATOMIC_RELAXED ) != 2, 0 )) nfp_discover();

    if (params_v2)
    {
        status = import_context_v2( thread_ctx, params_v2, (uint64_t)(uintptr_t)NtCurrentTeb() );
        if (status) return status;
    }
    else import_context( thread_ctx, &params->context, (uint64_t)(uintptr_t)NtCurrentTeb() );
    if (hb_context_set_scalar_access( thread_ctx, data_guard ? scalar_preaccess : NULL,
                                     data_guard, data_guard ? 4096 : 0 ) != HB_OK)
        return STATUS_INVALID_PARAMETER;
    {
        BOOL pair_enabled = data_guard &&
            (data_guard->capabilities & WINE_EMULATOR_MEMORY_ACCESS_CAP_PAIR_CMPXCHG);
        if (hb_context_set_pair_rmw_access( thread_ctx, pair_enabled ? pair_preaccess : NULL,
                                            pair_enabled ? data_guard : NULL,
                                            pair_enabled ? 4096 : 0 ) != HB_OK)
        {
            hb_context_set_scalar_access( thread_ctx, NULL, NULL, 0 );
            hb_context_set_pair_rmw_access( thread_ctx, NULL, NULL, 0 );
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (hb_context_set_exec_access( thread_ctx, exec_observer ? exec_observe_unit : NULL,
                                    exec_observer ) != HB_OK)
    {
        hb_context_set_scalar_access( thread_ctx, NULL, NULL, 0 );
        hb_context_set_pair_rmw_access( thread_ctx, NULL, NULL, 0 );
        return STATUS_INVALID_PARAMETER;
    }
    max_code_bytes = params->max_code_bytes ? params->max_code_bytes : XTAJIT64_DEFAULT_MAX_CODE_BYTES;
    if (fast) max_code_bytes = XTAJIT64_DEFAULT_MAX_CODE_BYTES;
    if (max_code_bytes > sizeof(code)) max_code_bytes = sizeof(code);
    block_limit = simulate_block_limit();
    /* EXEC always returns after a finite number of committed units, including
     * self loops and zero-IR instructions; a zero environment value is no escape. */
    if (params_v5 && !fast && (!block_limit || block_limit > 256)) block_limit = 256;
    /* Быстрый режим тоже конечен: возврат к PE-стороне не реже 1 Mi блоков. */
    if (fast && (!block_limit || block_limit > (1u << 20))) block_limit = 1u << 20;

    if (trace_xtajit64_enabled())
    {
        fprintf( stderr, "macrunner-xtajit64-unix: phase=enter rip=%016llx rsp=%016llx rcx=%016llx rdx=%016llx max=%zu\n",
                 (unsigned long long)thread_ctx->regs.x64.rip,
                 (unsigned long long)thread_ctx->regs.x64.rsp,
                 (unsigned long long)thread_ctx->regs.x64.rcx,
                 (unsigned long long)thread_ctx->regs.x64.rdx, max_code_bytes );
        fflush( stderr );
    }

    /* Бит 1024 (опыт): запуск JIT возвращается каждые 65536 шагов — звонок приостановки виден часто. */
    if (fast && (fast_exec_flags() & 1024)) thread_ctx->step_limit = 65536;

    while (!block_limit || dispatched < block_limit)
    {
        hb_decoder_t *dec = NULL;
        hb_ir_func_t *legacy_func = NULL;
        const hb_ir_func_t *func = NULL;
        hb_exec_result_t block_out;
        hb_result_t r;
        uint64_t pc = thread_ctx->regs.x64.rip;
        size_t len;
        BOOL chain, budget_yield;

        thread_ctx->pc = pc;
        if (fast) pc_hist_note( pc );
        if (is_ec_code_ptr( (ULONG_PTR)pc ))
        {
            if (trace_xtajit64_enabled()) fprintf( stderr, "macrunner-xtajit64-unix: boundary ec rip=%016llx after steps=%llu blocks=%llu\n",
                     (unsigned long long)pc, (unsigned long long)total_steps,
                     (unsigned long long)total_blocks );
            break;
        }
        if (pc >= XTAJIT64_HB_IMPORT_BASE && pc < XTAJIT64_HB_IMPORT_BASE + XTAJIT64_HB_IMPORT_SIZE)
        {
            if (trace_xtajit64_enabled()) fprintf( stderr, "macrunner-xtajit64-unix: boundary import rip=%016llx after steps=%llu blocks=%llu\n",
                     (unsigned long long)pc, (unsigned long long)total_steps,
                     (unsigned long long)total_blocks );
            break;
        }

        if (params_v5 && !fast)
        {
            xtajit64_exec_fetch_result fetched;
            struct exec_fetch_scope fetch_scope = { .params = params_v5 };
            r = xtajit64_exec_fetch_instruction_window( pc, exec_fetch_query,
                    exec_fetch_read_bytes, exec_fetch_read_window, &fetch_scope, &fetched );
            if (r != HB_OK)
            {
                if (r == HB_ERR_ACCESS_PENDING && getenv( "MACRUNNER_HB_TRACE_GUARD_PENDING" ))
                {
                    fprintf( stderr, "hyperbridge-exec-fetch-pending: pc=%016llx address=%016llx width=%llu\n",
                             (unsigned long long)pc,
                             (unsigned long long)params_v5->v4.request.guest_address,
                             (unsigned long long)params_v5->v4.request.span_length );
                    fflush( stderr );
                }
                memset( &exec, 0, sizeof(exec) );
                exec.result = r;
                exec.faulted = r != HB_ERR_ACCESS_PENDING;
                exec.fault_reason = "demanded instruction fetch stopped";
                exec.steps_executed = total_steps;
                exec.blocks_executed = total_blocks;
                result = r;
                goto done_with_exec;
            }
            if (allow_syscall_boundary && exec_classify_syscall( params_v5, pc, &fetched ))
            {
                syscall_boundary = TRUE;
                break;
            }
            r = hb_ir_reuse_acquire( &ir_reuse, pc, fetched.bytes, fetched.size,
                    &fetched.decoded, ir_reuse_create, ir_reuse_destroy, NULL, &func );
        }
        else if (fast && (fast_exec_flags() & 256) && thread_jit && !stub_force_lift &&
                 hb_jit_runtime_has_block( thread_jit, pc ) &&
                 !(allow_syscall_boundary && hb_memory_read( process_memory, pc, code, 3 ) == HB_OK &&
                   code[0] == 0x4c && code[1] == 0x8b && code[2] == 0xd1) &&
                 (func = get_stub_func( pc )))
        {
            r = HB_OK;   /* готовый перевод: разбирать нечего */
            fast_stat_stub++;
        }
        else
        {
            stub_force_lift = FALSE;
            if (fast) fast_stat_lifts++;
            len = fetch_code( process_memory, pc, code, max_code_bytes );
            if (!len)
            {
                if (ran_block) break;
                memset( &exec, 0, sizeof(exec) );
                exec.result = HB_ERR_MEMORY_FAULT;
                exec.faulted = TRUE;
                exec.fault_reason = "unable to fetch executable x64 code";
                record_memory_fault( pc, 8 );
                result = HB_ERR_MEMORY_FAULT;
                goto done_with_exec;
            }
            /* Быстрый режим отдаёт системный вызов по договору EXEC: снимок заглушки
             * нужен PE-стороне (hb_resolve_owned_syscall), поэтому классифицирует тот же
             * exec_classify_syscall, что и точный путь. */
            if (fast)
            {
                if (allow_syscall_boundary && len >= 3 && code[0] == 0x4c && code[1] == 0x8b && code[2] == 0xd1)
                {
                    xtajit64_exec_fetch_result stub = {0};
                    stub.size = 3;
                    memcpy( stub.bytes, code, 3 );
                    if (exec_classify_syscall( params_v5, pc, &stub ))
                    {
                        syscall_boundary = TRUE;
                        break;
                    }
                }
            }
            /* Legacy profiles 3/7 retain the admitted bulk classifier. */
            else if (allow_syscall_boundary && hb_x64_syscall_stub_match( pc, code, len, NULL ))
            {
                memset( &thread_fault, 0, sizeof(thread_fault) );
                syscall_boundary = TRUE;
                break;
            }
            dec = hb_decoder_create( HB_ARCH_X64, code, len, pc );
            if (!dec)
            {
                result = HB_ERR_OUT_OF_MEMORY;
                goto done;
            }
            r = hb_lift_func_x64( dec, &legacy_func );
            func = legacy_func;
            hb_decoder_destroy( dec );
        }
        if (r != HB_OK)
        {
            result = r;
            goto done;
        }

        chain = func_ends_in_control_transfer( func );
        memset( &block_out, 0, sizeof(block_out) );
        memset( &thread_fault, 0, sizeof(thread_fault) );
        reset_precise_fault( thread_ctx );
        r = run_translated_block( func, &block_out, &budget_yield );
        /* Бит 256: пустой запуск по заглушке — ни шага, ни блока — значит нужен полный разбор. */
        if (func == stub_func && !hb_exec_result_has_progress( &block_out ))
        {
            stub_force_lift = TRUE;
            fast_stat_stub_empty++;
        }
        if (params_v5 && !fast)
        {
            hb_result_t released = hb_ir_reuse_release( &ir_reuse, func );
            if (released != HB_OK) r = released;
        }
        else hb_ir_func_destroy( legacy_func );

        ran_block = TRUE;
        dispatched++;
        total_steps += block_out.steps_executed;
        total_blocks += block_out.blocks_executed;

        if (r != HB_OK || block_out.result != HB_OK || block_out.faulted)
        {
            if (!params_v5 && (r == HB_ERR_UNSUPPORTED_OPCODE || block_out.result == HB_ERR_UNSUPPORTED_OPCODE) &&
                getenv( "MACRUNNER_HB_TRACE_UNSUPPORTED_BYTES" ))
            {
                uint64_t block_pc = thread_ctx->regs.x64.rip;
                uint64_t fault_pc = thread_ctx->pc;
                uint8_t fault_bytes[64];
                size_t fault_len = fetch_code( process_memory, fault_pc, fault_bytes, sizeof(fault_bytes) );
                fprintf( stderr, "macrunner-xtajit64-unix: unsupported-bytes block=%016llx pc=%016llx len=%zu bytes=",
                         (unsigned long long)block_pc, (unsigned long long)fault_pc, fault_len );
                for (size_t i = 0; i < fault_len; i++) fprintf( stderr, "%02x", fault_bytes[i] );
                fprintf( stderr, "\n" );
            }
            exec = block_out;
            exec.steps_executed = total_steps;
            exec.blocks_executed = total_blocks;
            result = r;
            goto done_with_exec;
        }
        /* Only inspect the doorbell after a committed block/slice. The PE
         * side exports that complete state before Wine performs its handshake. */
        counter_free_yield = budget_yield && block_out.counters_are_dispatches;
        if (budget_yield || cooperative_suspend_pending() || (!params_v5 && !chain)) break;
    }

    memset( &exec, 0, sizeof(exec) );
    exec.result = HB_OK;
    exec.steps_executed = total_steps;
    exec.blocks_executed = total_blocks;

done_with_exec:
    if (fast) fast_exec_stats( total_blocks, total_steps );
    /* Includes pending, fault, budget, import/syscall boundary and normal exit. */
    hb_ir_reuse_clear( &ir_reuse, ir_reuse_destroy, NULL );
    /* The callback userdata belongs to this invocation, never to thread TLS. */
    hb_context_set_scalar_access( thread_ctx, NULL, NULL, 0 );
    hb_context_set_pair_rmw_access( thread_ctx, NULL, NULL, 0 );
    hb_context_set_exec_access( thread_ctx, NULL, NULL );
    /* Keep the V1 packet layout and success NTSTATUS. Older PE adapters still
     * resume; updated PE recognizes this reason without charging its ordinary
     * 65536-slice guard. Fault/pending/syscall paths retain their old results. */
    params->hb_result = counter_free_yield && result == HB_OK && exec.result == HB_OK && !exec.faulted
        ? HB_PE_COUNTER_FREE_YIELD : result;
    params->faulted = exec.faulted;
    params->steps = exec.steps_executed;
    params->blocks = exec.blocks_executed;
    if (params_v2)
    {
        status = export_context_v2( params_v2, thread_ctx );
        if (status) return status;
    }
    else if ((status = export_context( &params->context, thread_ctx ))) return status;
    if (result != HB_OK) params->status = status_from_hb( result );
    else if (exec.result != HB_OK) params->status = status_from_hb( exec.result );
    else if (syscall_boundary) params->status = XTAJIT64_STATUS_SYSCALL_STUB;
    else params->status = STATUS_SUCCESS;
    if (params_v4 && (result == HB_ERR_ACCESS_PENDING || exec.result == HB_ERR_ACCESS_PENDING))
    {
        if (params_v4->pending != 1 || params_v4->request.guest_pc != thread_ctx->pc)
            return STATUS_INVALID_PARAMETER;
        params->hb_result = HB_ERR_ACCESS_PENDING;
        params->faulted = 0;
        params->status = XTAJIT64_STATUS_ACCESS_PENDING;
        memset( &thread_fault, 0, sizeof(thread_fault) );
    }
    else publish_general_protection_fault( params, thread_ctx,
                                          result != HB_OK ? result : exec.result );

    if (trace_xtajit64_enabled())
    {
        fprintf( stderr, "macrunner-xtajit64-unix: simulate hb=%s(%d) exec=%s(%d) faulted=%u steps=%llu blocks=%llu rip=%016llx rsp=%016llx reason=%s\n",
                 hb_result_string( params->hb_result ), params->hb_result,
                 hb_result_string( exec.result ), exec.result, exec.faulted,
                 (unsigned long long)params->steps, (unsigned long long)params->blocks,
                 (unsigned long long)params->context.rip,
                 (unsigned long long)params->context.rsp,
                 exec.fault_reason ? exec.fault_reason : "" );
        fflush( stderr );
    }
    return params->status;

done:
    memset( &exec, 0, sizeof(exec) );
    goto done_with_exec;
}

static NTSTATUS unix_simulate_impl( void *args )
{
    return unix_simulate_context( args, NULL, FALSE, NULL, NULL );
}

static NTSTATUS unix_simulate_v2_impl( void *args )
{
    struct xtajit64_simulate_params_v2 *params = args;

    /* Validate before thread allocation, guest import or execution. */
    if (!params || !macrunner_hb_x64_packet_extension_valid( &params->extension, sizeof(*params) ))
        return STATUS_INVALID_PARAMETER;
    return unix_simulate_context( &params->v1, params, FALSE, NULL, NULL );
}

static NTSTATUS unix_simulate_v3_impl( void *args )
{
    struct xtajit64_simulate_params_v3 *params = args;
    NTSTATUS status;

    if (!params || !macrunner_hb_x64_packet_extension_valid( &params->v2.extension,
                                                           sizeof(params->v2) ))
        return STATUS_INVALID_PARAMETER;
    memset( &params->fault, 0, sizeof(params->fault) );
    status = unix_simulate_context( &params->v2.v1, &params->v2, TRUE, NULL, NULL );
    if (status == XTAJIT64_STATUS_SYSCALL_STUB) return STATUS_SUCCESS;
    if (status == STATUS_ACCESS_VIOLATION && thread_fault.valid && thread_ctx)
    {
        params->fault = thread_fault;
        params->fault.pc = thread_ctx->pc;
        /* The corrected core publishes the precise instruction on a fault. */
        params->v2.v1.context.rip = thread_ctx->pc;
        /* V3 delivered the complete guest fault successfully. Guest status
         * remains in v1.status; the Unix transport itself succeeded. */
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS unix_simulate_v4_impl( void *args )
{
    struct xtajit64_simulate_params_v4 *params = args;
    NTSTATUS status;
    if (!params || !macrunner_hb_x64_packet_extension_valid( &params->v3.v2.extension,
                                                            sizeof(params->v3.v2) ) ||
        !xtajit64_guard_identity_valid( params, params->owner_module, params->selection_epoch,
                                       (uint64_t)(uintptr_t)NtCurrentTeb(), params->invocation_serial ) ||
        (params->capabilities != 3 && params->capabilities != 7) ||
        params->pending || params->request.size) return STATUS_INVALID_PARAMETER;
    memset( &params->v3.fault, 0, sizeof(params->v3.fault) );
    memset( &params->request, 0, sizeof(params->request) );
    status = unix_simulate_context( &params->v3.v2.v1, &params->v3.v2, TRUE, params, NULL );
    if (status == XTAJIT64_STATUS_ACCESS_PENDING || status == XTAJIT64_STATUS_SYSCALL_STUB)
        return STATUS_SUCCESS;
    if (status == STATUS_ACCESS_VIOLATION && thread_fault.valid && thread_ctx)
    {
        params->v3.fault = thread_fault;
        params->v3.fault.pc = thread_ctx->pc;
        params->v3.v2.v1.context.rip = thread_ctx->pc;
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS unix_simulate_v5_impl( void *args )
{
    struct xtajit64_simulate_params_v5 *params = args;
    NTSTATUS status;
    if (!xtajit64_exec_request_valid( params, (uint64_t)(uintptr_t)NtCurrentTeb() ))
        return STATUS_INVALID_PARAMETER;
    memset( &params->v4.v3.fault, 0, sizeof(params->v4.v3.fault) );
    status = unix_simulate_context( &params->v4.v3.v2.v1, &params->v4.v3.v2, TRUE,
                                    &params->v4, params );
    if (status == XTAJIT64_STATUS_ACCESS_PENDING || status == XTAJIT64_STATUS_SYSCALL_STUB)
        return STATUS_SUCCESS;
    if (status == STATUS_ACCESS_VIOLATION && thread_fault.valid && thread_ctx)
    {
        params->v4.v3.fault = thread_fault;
        params->v4.v3.fault.pc = thread_ctx->pc;
        params->v4.v3.v2.v1.context.rip = thread_ctx->pc;
        return STATUS_SUCCESS;
    }
    return status;
}

static __thread hb_gva_t unmap_pending_base;
static __thread uint64_t unmap_pending_size;
static uint64_t unmap_by_query, unmap_by_region, unmap_full;

static BOOL unmap_precise_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "MACRUNNER_HB_UNMAP_PRECISE" );
        cached = (v && v[0] && v[0] != '0') ? 1 : 0;
        fprintf( stderr, "macrunner-gate: MACRUNNER_HB_UNMAP_PRECISE=%d\n", cached );
    }
    return cached;
}

/* Opus 26.09.2026 — ЧТО ОБЪЯВЛЯЕТСЯ К СБРОСУ (только учёт, поведение не меняется).
 * Перепись арены: 91 % смертей переводов — сброс по диапазону, 1 814 объявлений в среднем по
 * 7,4 МБ. Смена прав и выделение уже известной области БАЙТОВ НЕ МЕНЯЮТ; перевод остаётся верным,
 * если с области не снята исполняемость. Классификация — по нашей карте памяти ДО того, как
 * этот же вызов её обновит. Карта ведёт права по области целиком, поэтому счёт приблизительный. */
static uint64_t cls_total, cls_alloc_known, cls_alloc_fresh, cls_map_n;
static uint64_t cls_protect_same, cls_protect_x_off, cls_protect_x_on, cls_protect_w_only,
                cls_protect_unknown;
static uint64_t cls_bytes_alloc_known, cls_bytes_protect_same, cls_bytes_protect_w_only;

static void classify_notification( enum hb_cache_notification event,
                                   const struct xtajit64_memory_params *params )
{
    hb_region_t *region;
    hb_perm_t perm;
    uint64_t n, size;

    if (!params || !params->is_post || params->status || !params->size || !process_memory) return;
    size = page_span( (hb_gva_t)(uintptr_t)params->addr, params->size );
    region = hb_memory_find_region( process_memory, page_floor( (hb_gva_t)(uintptr_t)params->addr ) );
    perm = protect_to_perm( params->protect );
    if (event == HB_CACHE_ALLOC)
    {
        if (region)
        {
            __atomic_add_fetch( &cls_alloc_known, 1, __ATOMIC_RELAXED );
            __atomic_add_fetch( &cls_bytes_alloc_known, size, __ATOMIC_RELAXED );
        }
        else __atomic_add_fetch( &cls_alloc_fresh, 1, __ATOMIC_RELAXED );
    }
    else if (event == HB_CACHE_PROTECT)
    {
        if (!region) __atomic_add_fetch( &cls_protect_unknown, 1, __ATOMIC_RELAXED );
        else if (region->perm == perm)
        {
            __atomic_add_fetch( &cls_protect_same, 1, __ATOMIC_RELAXED );
            __atomic_add_fetch( &cls_bytes_protect_same, size, __ATOMIC_RELAXED );
        }
        else if ((region->perm & HB_PERM_EXEC) && !(perm & HB_PERM_EXEC))
            __atomic_add_fetch( &cls_protect_x_off, 1, __ATOMIC_RELAXED );
        else if (!(region->perm & HB_PERM_EXEC) && (perm & HB_PERM_EXEC))
            __atomic_add_fetch( &cls_protect_x_on, 1, __ATOMIC_RELAXED );
        else
        {
            __atomic_add_fetch( &cls_protect_w_only, 1, __ATOMIC_RELAXED );
            __atomic_add_fetch( &cls_bytes_protect_w_only, size, __ATOMIC_RELAXED );
        }
    }
    else if (event == HB_CACHE_MAP) __atomic_add_fetch( &cls_map_n, 1, __ATOMIC_RELAXED );
    n = __atomic_add_fetch( &cls_total, 1, __ATOMIC_RELAXED );
    if (n <= 4 || (n & 255) == 0)
        fprintf( stderr, "hyperbridge-notify-class: n=%llu alloc_known=%llu/%lluB alloc_fresh=%llu "
                 "map=%llu protect_same=%llu/%lluB protect_w_only=%llu/%lluB protect_x_on=%llu "
                 "protect_x_off=%llu protect_unknown=%llu\n",
                 (unsigned long long)n,
                 (unsigned long long)cls_alloc_known, (unsigned long long)cls_bytes_alloc_known,
                 (unsigned long long)cls_alloc_fresh, (unsigned long long)cls_map_n,
                 (unsigned long long)cls_protect_same, (unsigned long long)cls_bytes_protect_same,
                 (unsigned long long)cls_protect_w_only, (unsigned long long)cls_bytes_protect_w_only,
                 (unsigned long long)cls_protect_x_on, (unsigned long long)cls_protect_x_off,
                 (unsigned long long)cls_protect_unknown );
}

static NTSTATUS map_native_range( const struct xtajit64_memory_params *params,
                                  enum hb_cache_notification event, const char *reason )
{
    hb_gva_t base;
    size_t size;
    hb_perm_t perm;
    hb_region_t *region;
    hb_result_t result;

    if (!params) return STATUS_INVALID_PARAMETER;
    (void)reason;
    classify_notification( event, params );
    publish_cache_range(event, params->is_post, params->status,
                        page_floor( (hb_gva_t)(uintptr_t)params->addr ),
                        params->size ? page_span( (hb_gva_t)(uintptr_t)params->addr, params->size ) : 0);
    if (!params->is_post || params->status || !params->size) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;

    base = page_floor( (hb_gva_t)(uintptr_t)params->addr );
    size = page_span( (hb_gva_t)(uintptr_t)params->addr, params->size );
    if (!base || !size) return STATUS_SUCCESS;
    perm = protect_to_perm( params->protect );

    region = hb_memory_find_region( process_memory, base );
    if (region) result = hb_memory_protect( process_memory, region->base, region->size, perm );
    else result = hb_memory_map( process_memory, base, size, perm );
    return status_from_hb( result );
}

static NTSTATUS unix_notify_memory_alloc_impl( void *args )
{
    return map_native_range( args, HB_CACHE_ALLOC, "alloc" );
}

static NTSTATUS unix_notify_map_view_impl( void *args )
{
    return map_native_range( args, HB_CACHE_MAP, "map" );
}

static NTSTATUS unix_notify_memory_protect_impl( void *args )
{
    return map_native_range( args, HB_CACHE_PROTECT, "protect" );
}

__attribute__((visibility("default"))) void macrunner_xtajit64_notify_memory_alloc_unix( void *addr,
                                                                                         SIZE_T size,
                                                                                         ULONG type,
                                                                                         ULONG protect,
                                                                                         NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, protect, TRUE, status };
    NTSTATUS notify_status = map_native_range( &params, HB_CACHE_ALLOC, "alloc" );

    if (trace_xtajit64_enabled())
        fprintf( stderr, "macrunner-xtajit64-unix: notify-alloc addr=%p size=%#zx type=%#lx "
                 "protect=%#lx status=%08lx notify=%08lx\n",
                 addr, (size_t)size, (unsigned long)type, (unsigned long)protect,
                 (unsigned long)status, (unsigned long)notify_status );
}

__attribute__((visibility("default"))) void macrunner_xtajit64_notify_memory_protect_unix( void *addr,
                                                                                           SIZE_T size,
                                                                                           ULONG protect,
                                                                                           NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, 0, protect, TRUE, status };
    NTSTATUS notify_status = map_native_range( &params, HB_CACHE_PROTECT, "protect" );

    if (trace_xtajit64_enabled())
        fprintf( stderr, "macrunner-xtajit64-unix: notify-protect addr=%p size=%#zx "
                 "protect=%#lx status=%08lx notify=%08lx\n",
                 addr, (size_t)size, (unsigned long)protect,
                 (unsigned long)status, (unsigned long)notify_status );
}

static NTSTATUS unix_notify_memory_free_impl( void *args )
{
    const struct xtajit64_memory_params *params = args;
    hb_gva_t base;

    if (!params) return STATUS_INVALID_PARAMETER;
    publish_cache_range(HB_CACHE_FREE, params->is_post, params->status,
                        page_floor( (hb_gva_t)(uintptr_t)params->addr ),
                        params->size ? page_span( (hb_gva_t)(uintptr_t)params->addr, params->size ) : 0);
    if (!params->is_post || params->status || !params->size) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;
    base = page_floor( (hb_gva_t)(uintptr_t)params->addr );
    /* 26.09.2026 — ПО ДИАПАЗОНУ, а не по точной базе: освобождение части области, со смещённой
     * базой или MEM_DECOMMIT прежде оставляли её в карте HB читаемой (hb_memory_unmap_range). */
    {
        hb_result_t r = hb_memory_unmap_range( process_memory, base,
                                               page_span( (hb_gva_t)(uintptr_t)params->addr,
                                                          params->size ) );
        return r == HB_ERR_NOT_FOUND ? STATUS_SUCCESS : status_from_hb( r );
    }
}

__attribute__((visibility("default"))) void macrunner_xtajit64_notify_memory_free_unix( void *addr,
                                                                                        SIZE_T size,
                                                                                        ULONG type,
                                                                                        NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, 0, TRUE, status };
    NTSTATUS notify_status = unix_notify_memory_free_impl( &params );

    if (trace_xtajit64_enabled())
        fprintf( stderr, "macrunner-xtajit64-unix: notify-free addr=%p size=%#zx type=%#lx "
                 "status=%08lx notify=%08lx\n",
                 addr, (size_t)size, (unsigned long)type,
                 (unsigned long)status, (unsigned long)notify_status );
}

static NTSTATUS unix_notify_unmap_view_impl( void *args )
{
    const struct xtajit64_memory_params *params = args;
    hb_gva_t base;
    uint64_t gone_lo = 0, gone_hi = 0;   /* границы вида от Wine (пре-уведомление), если есть */

    if (!params) return STATUS_INVALID_PARAMETER;
    /* Размер вида здесь не приходит — сброс всего, как прежде.
     *
     * Opus 26.09.2026 — УРОВЕНЬ 4 ДЛЯ СБРОСА (гейт MACRUNNER_HB_UNMAP_PRECISE, умолчание 0 до замера).
     * Учёт по видам объявлений (HK, 507): у основного потока ВСЕ 190 681 выселение из 190 681 дали
     * ТРИ объявления unmap — каждое сбрасывало кеш целиком, и весь рабочий набор переводился заново.
     * Остальные 2 000+ объявлений (выделение 9 ГБ, права, освобождение, сброс кеша команд) не
     * выселили НИ ОДНОГО блока. Границы вида известны нашей карте памяти: область заведена при
     * отображении и снимается ниже, ПОСЛЕ объявления, так что здесь она ещё на месте. Объявляем
     * её — надмножество вида, пропуска нет. Области нет в карте — прежний сброс всего. */
    if (unmap_precise_enabled() && !params->is_post)
    {
        /* До снятия вид ещё отображён: его границы знает Wine. Складываем подряд идущие
         * области с тем же AllocationBase — это и есть вид. Пост-уведомление того же вызова
         * приходит следом на ЭТОМ ЖЕ потоке и берёт найденное отсюда. */
        hb_gva_t vbase = page_floor( (hb_gva_t)(uintptr_t)params->addr ), cursor = vbase;
        uint64_t vsize = 0;
        int guard = 0;
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T returned = 0;
        while (guard++ < 4096 &&
               !NtQueryVirtualMemory( NtCurrentProcess(), (void *)(uintptr_t)cursor,
                                      MemoryBasicInformation, &mbi, sizeof(mbi), &returned ) &&
               returned >= sizeof(mbi) && mbi.State != MEM_FREE &&
               (hb_gva_t)(uintptr_t)mbi.AllocationBase == vbase && mbi.RegionSize)
        {
            cursor += mbi.RegionSize;
            vsize = cursor - vbase;
        }
        unmap_pending_base = vbase;
        unmap_pending_size = vsize;
    }
    if (unmap_precise_enabled() && params->is_post && !params->status)
    {
        hb_gva_t vbase = page_floor( (hb_gva_t)(uintptr_t)params->addr );
        hb_region_t *view = process_memory ? hb_memory_find_region( process_memory, vbase ) : NULL;
        uint64_t pbase = unmap_pending_base, psize = unmap_pending_size;
        unmap_pending_base = 0;
        unmap_pending_size = 0;
        if (psize && pbase == vbase)
        {
            /* Границы от Wine; область нашей карты (если есть) добавляется — надмножество. */
            uint64_t lo = pbase, hi = pbase + psize;
            if (view && view->size)
            {
                if (view->base < lo) lo = view->base;
                if (view->base + view->size > hi) hi = view->base + view->size;
            }
            __atomic_add_fetch( &unmap_by_query, 1, __ATOMIC_RELAXED );
            publish_cache_range(HB_CACHE_UNMAP, params->is_post, params->status, lo, hi - lo);
            gone_lo = pbase;
            gone_hi = pbase + psize;
            goto unmapped_published;
        }
        if (view && view->size)
        {
            __atomic_add_fetch( &unmap_by_region, 1, __ATOMIC_RELAXED );
            publish_cache_range(HB_CACHE_UNMAP, params->is_post, params->status,
                                view->base, view->size);
            goto unmapped_published;
        }
        __atomic_add_fetch( &unmap_full, 1, __ATOMIC_RELAXED );
        fprintf( stderr, "hyperbridge-unmap-full: addr=%p by_query=%llu by_region=%llu full=%llu\n",
                 params->addr, (unsigned long long)unmap_by_query,
                 (unsigned long long)unmap_by_region, (unsigned long long)unmap_full );
    }
    publish_cache_range(HB_CACHE_UNMAP, params->is_post, params->status, 0, 0);
unmapped_published:
    if (!params->is_post || params->status) return STATUS_SUCCESS;
    if (ensure_process()) return STATUS_NO_MEMORY;
    base = page_floor( (hb_gva_t)(uintptr_t)params->addr );
    /* 26.09.2026 — вид образа после смены прав по секциям разрезан на несколько областей, и
     * снятие по точной базе убирало только первую. Границы вида известны — снимаем их целиком. */
    if (gone_hi > gone_lo)
    {
        hb_result_t r = hb_memory_unmap_range( process_memory, gone_lo, (size_t)(gone_hi - gone_lo) );
        return r == HB_ERR_NOT_FOUND ? STATUS_SUCCESS : status_from_hb( r );
    }
    if (!hb_memory_find_region( process_memory, base )) return STATUS_SUCCESS;
    return status_from_hb( hb_memory_unmap( process_memory, base ) );
}

static NTSTATUS unix_flush_instruction_cache_impl( void *args )
{
    /* The ABI permits NULL (whole flush). A range comes from the PE side since 25.09.2026. */
    const struct xtajit64_memory_params *params = args;
    if (params && params->addr && params->size)
        publish_cache_range(HB_CACHE_FLUSH, TRUE, STATUS_SUCCESS,
                            (uint64_t)(uintptr_t)params->addr, params->size);
    else
        publish_cache_range(HB_CACHE_FLUSH, TRUE, STATUS_SUCCESS, 0, 0);
    return STATUS_SUCCESS;
}

static NTSTATUS unix_x87_transfer_impl( void *args )
{
    struct hb_x87_wire *params = args;
    struct hb_x87_wire value;
    NTSTATUS status;
    hb_result_t result;
    if (!params) return STATUS_INVALID_PARAMETER;
    value = *params;
    if (!hb_x87_wire_valid(&value)) return STATUS_INVALID_PARAMETER;
    /* Public ingress may be the first use on this thread. Invalid packets are
     * rejected before context allocation or any architectural state change. */
    if ((status = ensure_thread())) return status;
    if (value.operation == HB_X87_WIRE_IMPORT)
        result = hb_x87_boundary_import(&thread_ctx->x87_64, &value);
    else
        result = hb_x87_boundary_export(&thread_ctx->x87_64, &value);
    if (result != HB_OK) return STATUS_INVALID_PARAMETER;
    if (value.operation == HB_X87_WIRE_EXPORT) *params = value;
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    unix_process_init_impl,
    unix_thread_init_impl,
    unix_thread_term_impl,
    unix_process_term_impl,
    unix_simulate_impl,
    unix_notify_memory_alloc_impl,
    unix_notify_memory_protect_impl,
    unix_notify_memory_free_impl,
    unix_notify_map_view_impl,
    unix_notify_unmap_view_impl,
    unix_flush_instruction_cache_impl,
    unix_simulate_v2_impl,
    unix_simulate_v3_impl,
    unix_simulate_v4_impl,
    unix_simulate_v5_impl,
    unix_x87_transfer_impl,
};

C_ASSERT( ARRAYSIZE(__wine_unix_call_funcs) == unix_funcs_count_x87 );
C_ASSERT( HB_ERR_ACCESS_PENDING == XTAJIT64_HB_ACCESS_PENDING );
