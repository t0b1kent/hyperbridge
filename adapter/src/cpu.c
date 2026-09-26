/*
 * x86-64 emulation on ARM64
 *
 * Copyright 2024 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/unixlib.h"
#include "wine/debug.h"

#include "xtajit64_exec.h"
#include "xtajit64_x87.h"
#include "hb_wine_unwind.h"
#include "hb_ec_boundary.h"
#include "hb_cpu_features.h"
#include "hb_syscall_stub.h"
#include "hb_flags_delivery.h"
#include "hb_pe_tls.h"
#include "hb_continuation_v1.h"

/* Independent entry state machine; Wine context conversion retains its LGPL notice. */
static void *hb_return_instruction;
/* COFF linker image base is available even before DLL_PROCESS_ATTACH. Wine
 * starts the selected emulator before ordinary module attach callbacks. */
extern const IMAGE_DOS_HEADER __ImageBase;
void DECLSPEC_NORETURN WINAPI hb_simulate(void);
static void DECLSPEC_NORETURN hb_simulate_inner(void);
static NTSTATUS xtajit64_unix_call( unsigned int func, void *params );
void DECLSPEC_NORETURN WINAPI hb_restore_ec(const ARM64_NT_CONTEXT *context);
/* Existing Wine ARM64EC export; this Wine snapshot omits its public prototype. */
extern void WINAPI ProcessPendingCrossProcessEmulatorWork(void);

C_ASSERT(offsetof(ARM64_NT_CONTEXT, X0) == 8);
C_ASSERT(offsetof(ARM64_NT_CONTEXT, Sp) == 0x100);
C_ASSERT(offsetof(ARM64_NT_CONTEXT, Pc) == 0x108);
C_ASSERT(offsetof(ARM64_NT_CONTEXT, V) == 0x110);
C_ASSERT(offsetof(ARM64_NT_CONTEXT, Fpcr) == 0x310);
C_ASSERT(sizeof(ARM64_NT_CONTEXT) <= 0x400);
C_ASSERT(offsetof(TEB, ChpeV2CpuAreaInfo) == 0x1788);
C_ASSERT(offsetof(CHPE_V2_CPU_AREA_INFO, EmulatorStackBase) == 8);

WINE_DEFAULT_DEBUG_CHANNEL(xtajit);

static BOOL simulate_v2_supported;
static BOOL simulate_v3_supported;
static BOOL simulate_v4_supported;
static BOOL simulate_v5_supported;
static BOOL x87_transfer_supported;
static WINE_EMULATOR_MEMORY_ACCESS_BOOTSTRAP_V1 *memory_access_bootstrap;
static NTSTATUS (WINAPI *memory_access_service)(const WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 *);
static LONG64 memory_access_serial;

static void hb_resolve_memory_access(void)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING( L"ntdll.dll" );
    ANSI_STRING call_name = RTL_CONSTANT_STRING( "__wine_arm64ec_memory_access_v1" );
    ANSI_STRING data_name = RTL_CONSTANT_STRING( "__wine_arm64ec_memory_access_bootstrap_v1" );
    HMODULE module;
    void *call = NULL, *data = NULL;
    if (LdrGetDllHandle( NULL, 0, &name, &module ) ||
        LdrGetProcedureAddress( module, &call_name, 0, &call ) ||
        LdrGetProcedureAddress( module, &data_name, 0, &data )) return;
    memory_access_service = call;
    memory_access_bootstrap = data;
}

static BOOL hb_memory_access_ready(uint64_t *owner, uint64_t *epoch, uint64_t *capabilities)
{
    WINE_EMULATOR_MEMORY_ACCESS_BOOTSTRAP_V1 value;
    if (!memory_access_service || !memory_access_bootstrap ||
        !wine_emulator_memory_access_caps_valid_v1(
            __atomic_load_n( &memory_access_bootstrap->capabilities, __ATOMIC_ACQUIRE ) ))
        return FALSE;
    value = *memory_access_bootstrap;
    if (value.size != sizeof(value) || value.version != WINE_EMULATOR_MEMORY_ACCESS_VERSION ||
        value.cookie != WINE_EMULATOR_MEMORY_ACCESS_ABI_COOKIE ||
        !wine_emulator_memory_access_caps_valid_v1( value.capabilities ) ||
        value.owner_module != (ULONG64)(ULONG_PTR)&__ImageBase || value.selection_epoch != 1 ||
        value.reserved[0] || value.reserved[1] || value.reserved[2]) return FALSE;
    if (value.capabilities == XTAJIT64_EXEC_PROFILE && !simulate_v5_supported)
        RtlRaiseStatus( STATUS_NOT_SUPPORTED );
    if (!simulate_v4_supported) return FALSE;
    *owner = value.owner_module;
    *epoch = value.selection_epoch;
    *capabilities = value.capabilities;
    return TRUE;
}
static BOOL trace_simulation;
static BOOL core_mmx_supported;
static BOOL syscall_stub_supported;
/* Separate owned TLS: EmulatorData already carries the suspension protocol.
 * Only the adapter's synchronous guest exception delivery may arm this state. */
static __declspec(thread) hb_flags_delivery exception_delivery;

static __attribute__((noinline)) hb_flags_delivery *hb_owned_delivery(void)
{
    void **slots = (void **)NtCurrentTeb()->ThreadLocalStoragePointer;
    DWORD index = _tls_index;
    /* Wine calls ThreadInit before allocating static TLS. Reset can also run
     * during that early phase. Never form a TLS address until the loader has
     * published both our index and this thread's backing allocation. */
    if (!slots || index == ~(DWORD)0 || !slots[index]) return NULL;
    return &exception_delivery;
}

static hb_flags_delivery_event hb_exception_event( const EXCEPTION_RECORD *rec,
                                                   const AMD64_CONTEXT *ctx )
{
    hb_flags_delivery_event event = {0};
    if (!rec || !ctx) return event;
    event.pc = ctx->Rip;
    event.sp = ctx->Rsp;
    event.address = (ULONG_PTR)rec->ExceptionAddress;
    event.code = rec->ExceptionCode;
    event.exception_flags = rec->ExceptionFlags;
    event.parameter_count = rec->NumberParameters;
    event.has_chained_record = rec->ExceptionRecord != NULL;
    if (event.parameter_count <= HB_FLAGS_DELIVERY_PARAMETERS)
        for (unsigned int i = 0; i < event.parameter_count; ++i)
            event.parameters[i] = rec->ExceptionInformation[i];
    return event;
}

/* Only Wine context ingress and explicit guest context delivery own these raw
 * fields. Ordinary EC calls use their overlapping native registers instead. */
static NTSTATUS hb_transfer_x87( AMD64_CONTEXT *ctx, uint32_t operation )
{
    struct hb_x87_wire value = {0};
    NTSTATUS status;
    unsigned int i;
    if (!ctx || (operation != HB_X87_WIRE_IMPORT && operation != HB_X87_WIRE_EXPORT))
        return STATUS_INVALID_PARAMETER;
    if ((ctx->ContextFlags & CONTEXT_AMD64_FLOATING_POINT) != CONTEXT_AMD64_FLOATING_POINT)
        return STATUS_SUCCESS;
    if (!x87_transfer_supported) return STATUS_NOT_SUPPORTED;
    value.struct_size = sizeof(value);
    value.version = HB_X87_WIRE_VERSION;
    value.operation = operation;
    if (operation == HB_X87_WIRE_IMPORT)
    {
        value.control_word = ctx->FltSave.ControlWord;
        value.status_word = ctx->FltSave.StatusWord;
        value.abridged_tag = ctx->FltSave.TagWord;
        for (i = 0; i < 8; ++i) memcpy(value.physical[i], &ctx->FltSave.FloatRegisters[i], 10);
    }
    status = xtajit64_unix_call(unix_x87_transfer, &value);
    if (status) return status;
    if (!hb_x87_wire_valid(&value) || value.operation != operation) return STATUS_INVALID_PARAMETER;
    if (operation == HB_X87_WIRE_EXPORT)
    {
        ctx->FltSave.ControlWord = value.control_word;
        ctx->FltSave.StatusWord = value.status_word;
        ctx->FltSave.TagWord = value.abridged_tag;
        for (i = 0; i < 8; ++i) memcpy(&ctx->FltSave.FloatRegisters[i], value.physical[i], 16);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS hb_raise_guest_exception( EXCEPTION_RECORD *record, AMD64_CONTEXT *ctx )
{
    ULONG_PTR owner = (ULONG_PTR)NtCurrentTeb();
    hb_flags_delivery *delivery = hb_owned_delivery();
    hb_flags_delivery_event event = hb_exception_event( record, ctx );
    uint64_t ticket;
    NTSTATUS status;

    if ((status = hb_transfer_x87(ctx, HB_X87_WIRE_EXPORT))) return status;
    if (delivery && !delivery->owner) hb_flags_delivery_init( delivery, owner );
    ticket = hb_flags_delivery_arm( delivery, owner, &event, ctx->EFlags );
    status = NtRaiseException( record, (CONTEXT *)ctx, TRUE );
    /* A resumed handler does not return here. Never let a failed raise leave
     * flags available for an unrelated later exception. */
    hb_flags_delivery_cancel( delivery, owner, ticket );
    return status;
}

/* Loader-populated ARM64EC checker slot from the linked Wine CRT. */
extern void *__os_arm64x_check_icall;

static __attribute__((noinline)) ULONG_PTR hb_resolve_wine_syscall_stub( ULONG_PTR stub )
{
    register ULONG_PTR target __asm__("x11") = stub;
    register ULONG_PTR fallback __asm__("x10") = 0;
    void *checker = __os_arm64x_check_icall;
    if (!checker) return 0;
    /* The checker preserves argument registers and returns its native target
     * in x11. A zero exit thunk makes unsupported targets fail closed. LR is
     * declared clobbered so the compiler emits stack/unwind metadata. */
    __asm__ volatile( "blr %2" : "+r"(target), "+r"(fallback) : "r"(checker)
                      : "x9", "x16", "x17", "x30", "cc", "memory" );
    return target;
}

static BOOL hb_target_is_ec( ULONG_PTR target );

/* The exact syscall branch is PC-independent: it extracts a service number
 * and returns Wine's native table entry. Resolve only our owned stable bytes;
 * the checker must never reread guest code in EXEC mode. */
static ULONG_PTR hb_resolve_owned_syscall( const struct xtajit64_syscall_snapshot *snapshot )
{
    uint8_t bytes[32] __attribute__((aligned(16))) = {0};
    ULONG_PTR address = (ULONG_PTR)bytes, target;
    uint32_t service;
    if (!snapshot || snapshot->valid != 1 ||
        !hb_x64_syscall_stub_match( snapshot->guest_pc, snapshot->bytes,
                                    sizeof(snapshot->bytes), &service ) ||
        service != snapshot->service) return 0;
    memcpy( bytes, snapshot->bytes, sizeof(snapshot->bytes) );
    if ((address & 15) || hb_target_is_ec( address )) return 0;
    target = hb_resolve_wine_syscall_stub( address );
    if (!hb_x64_syscall_target_valid( snapshot->guest_pc, target ) ||
        target == address || !hb_target_is_ec( target )) return 0;
    return target;
}


/* Claude 25.09: __wine_init_unix_call — это системный вызов NtQueryVirtualMemory(MemoryWineUnixFuncs),
 * а в Wine за ним стоит dlsym по библиотеке. Раньше он шёл на КАЖДЫЙ вызов симуляции: профиль HK
 * после загрузки сборок — ~30 % главного потока (pthread_sigmask, dyld hasExportedSymbol, strrchr).
 * Дескриптор после первого успеха не меняется, поэтому инициализируем один раз. */
static NTSTATUS xtajit64_unix_call( unsigned int func, void *params )
{
    if (!__wine_unixlib_handle)
    {
        NTSTATUS status = __wine_init_unix_call();
        if (status) return status;
    }
    return WINE_UNIX_CALL( func, params );
}

static void pack_amd64_context( struct xtajit64_amd64_context *dst, const AMD64_CONTEXT *src, ULONG64 teb )
{
    const M128A *xmm = &src->Xmm0;
    unsigned int i;

    dst->rax = src->Rax;
    dst->rbx = src->Rbx;
    dst->rcx = src->Rcx;
    dst->rdx = src->Rdx;
    dst->rsi = src->Rsi;
    dst->rdi = src->Rdi;
    dst->rsp = src->Rsp;
    dst->rbp = src->Rbp;
    dst->r8 = src->R8;
    dst->r9 = src->R9;
    dst->r10 = src->R10;
    dst->r11 = src->R11;
    dst->r12 = src->R12;
    dst->r13 = src->R13;
    dst->r14 = src->R14;
    dst->r15 = src->R15;
    dst->rip = src->Rip;
    dst->rflags = src->EFlags;
    dst->fs_base = 0;
    dst->gs_base = teb;
    dst->seg_cs = src->SegCs;
    dst->seg_ds = src->SegDs;
    dst->seg_es = src->SegEs;
    dst->seg_fs = src->SegFs;
    dst->seg_gs = src->SegGs;
    dst->seg_ss = src->SegSs;
    for (i = 0; i < 16; i++)
    {
        dst->xmm[i][0] = xmm[i].Low;
        dst->xmm[i][1] = (ULONG64)xmm[i].High;
    }
}

static void unpack_amd64_context( AMD64_CONTEXT *dst, const struct xtajit64_amd64_context *src )
{
    M128A *xmm = &dst->Xmm0;
    unsigned int i;

    dst->Rax = src->rax;
    dst->Rbx = src->rbx;
    dst->Rcx = src->rcx;
    dst->Rdx = src->rdx;
    dst->Rsi = src->rsi;
    dst->Rdi = src->rdi;
    dst->Rsp = src->rsp;
    dst->Rbp = src->rbp;
    dst->R8 = src->r8;
    dst->R9 = src->r9;
    dst->R10 = src->r10;
    dst->R11 = src->r11;
    dst->R12 = src->r12;
    dst->R13 = src->r13;
    dst->R14 = src->r14;
    dst->R15 = src->r15;
    dst->Rip = src->rip;
    dst->EFlags = (DWORD)src->rflags;
    dst->SegCs = src->seg_cs;
    dst->SegDs = src->seg_ds;
    dst->SegEs = src->seg_es;
    dst->SegFs = src->seg_fs;
    dst->SegGs = src->seg_gs;
    dst->SegSs = src->seg_ss;
    for (i = 0; i < 16; i++)
    {
        xmm[i].Low = src->xmm[i][0];
        xmm[i].High = (LONGLONG)src->xmm[i][1];
    }
}


static void pack_amd64_context_v2( struct xtajit64_simulate_params_v2 *dst,
                                   const AMD64_CONTEXT *src, ULONG64 teb )
{
    memset( dst, 0, sizeof(*dst) );
    pack_amd64_context( &dst->v1.context, src, teb );
    dst->extension.struct_size = sizeof(*dst);
    dst->extension.version = MACRUNNER_HB_X64_PACKET_VERSION;
    dst->extension.mxcsr = src->FltSave.MxCsr;
}

static NTSTATUS unpack_amd64_context_v2( AMD64_CONTEXT *dst,
                                         const struct xtajit64_simulate_params_v2 *src )
{
    if (!dst || !src || !macrunner_hb_x64_packet_extension_valid( &src->extension, sizeof(*src) ))
        return STATUS_INVALID_PARAMETER;
    unpack_amd64_context( dst, &src->v1.context );
    dst->MxCsr = dst->FltSave.MxCsr = src->extension.mxcsr;
    return STATUS_SUCCESS;
}

/* These exports are raw ARM64EC dispatch entries, not ordinary C calls.
 * GPR mapping follows Wine's ARM64EC_NT_CONTEXT definition. Never use
 * RtlCaptureContext here: its C argument and unwind would change entry state. */
#include "hb_ec_entry.inc"

void DECLSPEC_NORETURN WINAPI hb_ec_enter( const ARM64_NT_CONTEXT *snapshot )
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    AMD64_CONTEXT *ctx;
    DWORD old_flags;
    if (!cpu || !cpu->ContextAmd64) RtlRaiseStatus( STATUS_INVALID_PARAMETER );
    ctx = &cpu->ContextAmd64->AMD64_Context;
    old_flags = ctx->EFlags;
    context_arm_to_x64( (ARM64EC_NT_CONTEXT *)ctx, snapshot );
    /* Native NZCV does not represent PF/AF/DF. Keep that side state. */
    ctx->EFlags = (old_flags & ~0x9c1u) | (ctx->EFlags & 0x9c1u) | 0x202u;
    cpu->InSimulation = 1;
    hb_simulate_inner();
}

static BOOL hb_target_is_ec( ULONG_PTR target )
{
    const UINT64 *map = (const UINT64 *)NtCurrentTeb()->Peb->EcCodeBitMap;
    ULONG_PTR page = target >> 12; /* Windows bitmap pages are always 4 KiB. */
    return map && ((map[page >> 6] >> (page & 63)) & 1);
}

/* Optional NORMAL-only transport. The Wine dispatcher consumes its frame
 * before calling us. Validate its copied value against this live context,
 * without relying on TLS or changing any state on an invalid request. */
NTSTATUS WINAPI BTCpu64ApplyContinuationV1( AMD64_CONTEXT *ctx,
                                           const WINE_EMULATOR_CONTINUATION_V1 *value )
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    if (!cpu || !cpu->ContextAmd64 || !ctx || !value ||
        ctx != &cpu->ContextAmd64->AMD64_Context ||
        (ctx->ContextFlags & CONTEXT_AMD64_CONTROL) != CONTEXT_AMD64_CONTROL ||
        value->size != sizeof(*value) || value->version != WINE_EMULATOR_CONTINUATION_VERSION ||
        value->owner_module != (ULONG_PTR)&__ImageBase || value->owner_generation != 1 ||
        value->owner_teb != (ULONG_PTR)NtCurrentTeb() ||
        value->target_pc != ctx->Rip || value->target_sp != ctx->Rsp ||
        value->entry_kind != WINE_EMULATOR_CONTINUATION_RESUME || value->reserved ||
        (value->missing_eflags & ~WINE_EMULATOR_CONTINUATION_MISSING_FLAGS) ||
        hb_target_is_ec( ctx->Rip ))
        return STATUS_INVALID_PARAMETER;

    /* The legacy token belongs to an earlier suspension transfer. It must not
     * overwrite the final handler/requested flags when BeginSimulation runs. */
    cpu->EmulatorData[1] = 0;
    ctx->EFlags = (ctx->EFlags & ~WINE_EMULATOR_CONTINUATION_MISSING_FLAGS) |
                  value->missing_eflags;
    return STATUS_SUCCESS;
}

static BOOL hb_suspend_pending( CHPE_V2_CPU_AREA_INFO *cpu )
{
    return cpu->SuspendDoorbell &&
           __atomic_load_n( cpu->SuspendDoorbell, __ATOMIC_RELAXED );
}

static void hb_suspend_guest( CHPE_V2_CPU_AREA_INFO *cpu, AMD64_CONTEXT *ctx )
{
    NTSTATUS status;
    if (!hb_suspend_pending( cpu )) return;
    ctx->ContextFlags = CONTEXT_AMD64_FULL | CONTEXT_AMD64_SEGMENTS;
    if ((status = hb_transfer_x87(ctx, HB_X87_WIRE_EXPORT))) RtlRaiseStatus(status);
    /* Wine owns the pending signal, doorbell clear and server wait. Its
     * NtContinue handshake requires a committed context and InSimulation=0.
     * Standard emulation ingress reconstructs NZCV but loses PF/AF/DF, so
     * preserve those bits in emulator-owned storage across this one transfer. */
    cpu->EmulatorData[1] = (void *)(ULONG_PTR)(0x100000000ull | (ctx->EFlags & 0x414u));
    ctx->ContextFlags = CONTEXT_AMD64_FULL | CONTEXT_AMD64_SEGMENTS;
    status = NtContinue( (CONTEXT *)ctx, FALSE );
    cpu->EmulatorData[1] = 0;
    RtlRaiseStatus( status ? status : STATUS_UNSUCCESSFUL );
}

static void DECLSPEC_NORETURN hb_leave_to_native( AMD64_CONTEXT *ctx )
{
    ARM64_NT_CONTEXT arm;
    struct hb_ec_leave_plan plan;
    uint32_t metadata;
    uint64_t return_address = 0;
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    if (!hb_target_is_ec(ctx->Rip) || ctx->Rip < 4 || (ctx->Rip & 3))
        RtlRaiseStatus( STATUS_INVALID_PARAMETER );
    memcpy(&metadata, (const void *)(ULONG_PTR)(ctx->Rip - 4), sizeof metadata);
    if (metadata != HB_EC_EXIT_RETURN_INSN && (ctx->Rsp & 15) == 8)
        memcpy(&return_address, (const void *)(ULONG_PTR)ctx->Rsp, sizeof return_address);
    if (!hb_ec_plan_leave(ctx->Rip, ctx->Rsp, metadata, return_address,
                          (ULONG_PTR)hb_return_instruction, &plan))
        RtlRaiseStatus( STATUS_INVALID_PARAMETER );
    context_x64_to_arm(&arm, (const ARM64EC_NT_CONTEXT *)ctx);
    arm.Pc = plan.target;
    arm.Sp = plan.native_sp;
    arm.X9 = ctx->Rip;
    if (plan.kind != HB_EC_LEAVE_RETURN)
    {
        arm.X4 = plan.native_sp; /* Entry thunk's argument base after optional pop. */
        arm.Lr = plan.link_register;
    }
    /* Native code uses ordinary FPCR behavior, not translator AFP modes. */
    arm.Fpcr &= ~6u;
    cpu->InSimulation = 0;
    if (hb_suspend_pending( cpu ))
    {
        ARM64EC_NT_CONTEXT native_ctx;
        NTSTATUS status;
        /* The return/thunk plan has already adjusted SP, LR and X9. Suspend
         * with that native continuation rather than the pre-plan x64 target. */
        context_arm_to_x64( &native_ctx, &arm );
        status = NtContinue( (CONTEXT *)&native_ctx, FALSE );
        RtlRaiseStatus( status ? status : STATUS_UNSUCCESSFUL );
    }
    hb_restore_ec(&arm);
}

/**********************************************************************
 *           BeginSimulation  (xtajit64.@)
 */
void DECLSPEC_NORETURN WINAPI hb_simulate(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    AMD64_CONTEXT *ctx = cpu ? &cpu->ContextAmd64->AMD64_Context : NULL;
    NTSTATUS status = hb_transfer_x87(ctx, HB_X87_WIRE_IMPORT);
    if (status) RtlRaiseStatus(status);
    hb_simulate_inner();
}

/* EC callbacks and budget/guard retries retain the existing TLS x87 state. */
static void DECLSPEC_NORETURN hb_simulate_inner(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    AMD64_CONTEXT *ctx = cpu ? &cpu->ContextAmd64->AMD64_Context : NULL;
    struct xtajit64_simulate_params params;
    struct xtajit64_simulate_params_v2 params_v2;
    struct xtajit64_simulate_params_v3 params_v3;
    struct xtajit64_simulate_params_v4 params_v4;
    struct xtajit64_simulate_params_v5 params_v5;
    struct xtajit64_simulate_params_v4 *active_guard;
    uint64_t guard_owner = 0, guard_epoch = 0, guard_serial = 0, guard_capabilities = 0;
    BOOL used_v4, used_v5;
    ULONG guard_retries = 0;
    struct xtajit64_fault_record fault;
    NTSTATUS status;
    ULONG slices = 0;

    if (!cpu || !ctx)
    {
        MESSAGE( "macrunner-xtajit64: BeginSimulation REACHED but cpu/context is null cpu=%p ctx=%p\n", cpu, ctx );
        RtlRaiseStatus( STATUS_INVALID_PARAMETER );
    }
    if ((ULONG_PTR)cpu->EmulatorData[1] & 0x100000000ull)
    {
        ctx->EFlags = (ctx->EFlags & ~0x414u) | ((ULONG_PTR)cpu->EmulatorData[1] & 0x414u);
        cpu->EmulatorData[1] = 0;
    }

    if (trace_simulation || TRACE_ON(xtajit))
        MESSAGE( "macrunner-xtajit64: BeginSimulation REACHED rip=%p rsp=%p rax=%p rcx=%p rdx=%p insim=%lu\n",
                 (void *)ctx->Rip, (void *)ctx->Rsp, (void *)ctx->Rax,
                 (void *)ctx->Rcx, (void *)ctx->Rdx, (ULONG)cpu->InSimulation );

resume_guest:
    /* The captured guest context is complete and no translated code is active
     * here. Remote protect/free/flush notifications must reach our callbacks
     * before entering a cached block, including after an instruction-budget
     * yield. The callbacks publish invalidations; each JIT runtime applies them
     * at its own next entry. Keep Wine's simulation flag clear during the drain. */
    cpu->InSimulation = 0;
    if (!hb_target_is_ec(ctx->Rip)) hb_suspend_guest( cpu, ctx );
    ProcessPendingCrossProcessEmulatorWork();
    cpu->InSimulation = 1;
    RtlZeroMemory( &fault, sizeof(fault) );
    used_v4 = hb_memory_access_ready( &guard_owner, &guard_epoch, &guard_capabilities );
    used_v5 = used_v4 && guard_capabilities == XTAJIT64_EXEC_PROFILE;
    if (used_v5 && !simulate_v5_supported) RtlRaiseStatus( STATUS_NOT_SUPPORTED );
    active_guard = used_v5 ? &params_v5.v4 : &params_v4;
    if (used_v4)
    {
        NTSTATUS unpack_status;
        if (used_v5) RtlZeroMemory( &params_v5, sizeof(params_v5) );
        else RtlZeroMemory( &params_v4, sizeof(params_v4) );
        pack_amd64_context_v2( &active_guard->v3.v2, ctx, (ULONG64)(ULONG_PTR)NtCurrentTeb() );
        active_guard->v3.v2.v1.max_code_bytes = used_v5 ? 15 : 4096;
        guard_serial = (uint64_t)InterlockedIncrement64( &memory_access_serial );
        if (!guard_serial) RtlRaiseStatus( STATUS_INTEGER_OVERFLOW );
        active_guard->size = sizeof(*active_guard);
        active_guard->version = 1;
        active_guard->owner_module = guard_owner;
        active_guard->selection_epoch = guard_epoch;
        active_guard->current_teb = (ULONG64)(ULONG_PTR)NtCurrentTeb();
        active_guard->invocation_serial = guard_serial;
        active_guard->capabilities = guard_capabilities;
        if (used_v5)
        {
            params_v5.size = sizeof(params_v5);
            params_v5.version = 1;
            status = xtajit64_unix_call( unix_simulate_v5, &params_v5 );
        }
        else status = xtajit64_unix_call( unix_simulate_v4, &params_v4 );
        if (!status)
        {
            fault = active_guard->v3.fault;
            status = active_guard->v3.v2.v1.status;
        }
        unpack_status = unpack_amd64_context_v2( ctx, &active_guard->v3.v2 );
        if (unpack_status)
        {
            status = unpack_status;
            RtlZeroMemory( &fault, sizeof(fault) );
            active_guard->pending = 0;
            if (used_v5) params_v5.syscall = (struct xtajit64_syscall_snapshot){0};
        }
        params = active_guard->v3.v2.v1;
    }
    else if (simulate_v3_supported)
    {
        NTSTATUS unpack_status;
        RtlZeroMemory( &params_v3, sizeof(params_v3) );
        pack_amd64_context_v2( &params_v3.v2, ctx, (ULONG64)(ULONG_PTR)NtCurrentTeb() );
        params_v3.v2.v1.max_code_bytes = 4096;
        status = xtajit64_unix_call( unix_simulate_v3, &params_v3 );
        /* A transport error does not establish any fault-output contract. */
        if (!status)
        {
            fault = params_v3.fault;
            status = params_v3.v2.v1.status;
        }
        unpack_status = unpack_amd64_context_v2( ctx, &params_v3.v2 );
        if (unpack_status)
        {
            status = unpack_status;
            RtlZeroMemory( &fault, sizeof(fault) );
        }
        params = params_v3.v2.v1;
    }
    else if (simulate_v2_supported)
    {
        NTSTATUS unpack_status;
        pack_amd64_context_v2( &params_v2, ctx, (ULONG64)(ULONG_PTR)NtCurrentTeb() );
        params_v2.v1.max_code_bytes = 4096;
        status = xtajit64_unix_call( unix_simulate_v2, &params_v2 );
        if (!status) status = params_v2.v1.status;
        unpack_status = unpack_amd64_context_v2( ctx, &params_v2 );
        if (!status) status = unpack_status;
        params = params_v2.v1;
    }
    else
    {
        RtlZeroMemory( &params, sizeof(params) );
        pack_amd64_context( &params.context, ctx, (ULONG64)(ULONG_PTR)NtCurrentTeb() );
        params.max_code_bytes = 4096;
        status = xtajit64_unix_call( unix_simulate, &params );
        if (!status) status = params.status;
        unpack_amd64_context( ctx, &params.context );
    }
    cpu->InSimulation = 0;

    if (trace_simulation || TRACE_ON(xtajit))
        MESSAGE( "macrunner-xtajit64: BeginSimulation executed status=%08lx hb=%ld faulted=%lu steps=%llu blocks=%llu rip=%p rsp=%p\n",
                 status, params.hb_result, params.faulted,
                 (unsigned long long)params.steps, (unsigned long long)params.blocks,
                 (void *)ctx->Rip, (void *)ctx->Rsp );

    if (status == XTAJIT64_STATUS_ACCESS_PENDING)
    {
        WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 request;
        EXCEPTION_RECORD record;
        BOOL valid = used_v4 && (used_v5 ?
            xtajit64_exec_take_pending( &params_v5, guard_owner, guard_epoch,
                (ULONG64)(ULONG_PTR)NtCurrentTeb(), guard_serial, ctx->Rip, &request ) :
            xtajit64_guard_take_pending( active_guard, guard_owner, guard_epoch,
                (ULONG64)(ULONG_PTR)NtCurrentTeb(), guard_serial, ctx->Rip, &request ));
        if (!valid || active_guard->capabilities != guard_capabilities)
            RtlRaiseStatus( STATUS_INVALID_PARAMETER );
        /* Slot is spent, translated code has exited, and this frame owns value. */
        status = memory_access_service( &request );
        if (status == STATUS_GUARD_PAGE_VIOLATION)
        {
            xtajit64_guard_exception( &record, &request );
            ctx->ContextFlags = CONTEXT_AMD64_FULL | CONTEXT_AMD64_SEGMENTS;
            status = hb_raise_guest_exception( &record, ctx );
            RtlRaiseStatus( status ? status : STATUS_UNSUCCESSFUL );
        }
        if (status) RtlRaiseStatus( status );
        /* Mapping may have changed between observation and consumption. Retry
         * exact PC with fresh checks; never turn SUCCESS into a fabricated guard. */
        if (++guard_retries >= 32) RtlRaiseStatus( STATUS_RETRY );
        goto resume_guest;
    }
    guard_retries = 0;
    if (status == XTAJIT64_STATUS_SYSCALL_STUB)
    {
        ULONG_PTR target;
        struct xtajit64_syscall_snapshot snapshot;
        if (used_v5)
        {
            if (!xtajit64_exec_take_syscall( &params_v5, guard_owner, guard_epoch,
                     (ULONG64)(ULONG_PTR)NtCurrentTeb(), guard_serial, ctx->Rip, &snapshot ))
                RtlRaiseStatus( STATUS_INVALID_PARAMETER );
        }
        if (!syscall_stub_supported || params.faulted || params.hb_result || fault.valid)
            RtlRaiseStatus( STATUS_NOT_SUPPORTED );
        target = used_v5 ? hb_resolve_owned_syscall( &snapshot ) :
                          hb_resolve_wine_syscall_stub( ctx->Rip );
        if (!hb_x64_syscall_target_valid( ctx->Rip, target ) || !hb_target_is_ec( target ))
            RtlRaiseStatus( STATUS_NOT_SUPPORTED );
        ctx->Rip = target;
        hb_leave_to_native( ctx );
    }
    if (status)
    {
        EXCEPTION_RECORD record;
        if (xtajit64_prepare_memory_exception( &record, status, params.faulted, &fault ))
        {
            /* Raise at the guest instruction with its guest stack/registers.
             * Wine resumes the handler's context through NtContinue; success
             * does not return to this emulator-stack frame. */
            ctx->Rip = fault.pc;
            ctx->ContextFlags = CONTEXT_AMD64_FULL | CONTEXT_AMD64_SEGMENTS;
            status = hb_raise_guest_exception( &record, ctx );
            if (!status) status = STATUS_UNSUCCESSFUL;
        }
        RtlRaiseStatus( status );
    }
    if (hb_target_is_ec(ctx->Rip)) hb_leave_to_native(ctx);
    hb_suspend_guest( cpu, ctx );
    /* Resume the same captured x64 state directly. A Wine ARM64 context
     * roundtrip would discard PF/AF/DF, which NZCV cannot represent. */
    if (!params.steps && !params.blocks) RtlRaiseStatus( STATUS_ACCESS_VIOLATION );
    if (++slices >= 65536) RtlRaiseStatus( STATUS_TIMEOUT );
    goto resume_guest;
}


/**********************************************************************
 *           BTCpu64FlushInstructionCache  (xtajit64.@)
 */
/* Claude, 25.09.2026: диапазон передаётся unix-стороне — без него каждый сброс, запись в код и
 * даже каждый ReadFile стирали ВЕСЬ кеш переводов (HK: 600 сбросов / 301 799 блоков за 75 с).
 * Unix-сторона сужает сброс только под флагом 16 MACRUNNER_HB_FAST_EXEC; иначе — как прежде. */
static void hb_notify_range( void *addr, SIZE_T size )
{
    struct xtajit64_memory_params params = { addr, size, 0, 0, TRUE, STATUS_SUCCESS };
    (void)xtajit64_unix_call( unix_flush_instruction_cache, &params );
}

void WINAPI BTCpu64FlushInstructionCache( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
    hb_notify_range( addr, size );
}


/**********************************************************************
 *           BTCpu64IsProcessorFeaturePresent  (xtajit64.@)
 */
BOOLEAN WINAPI BTCpu64IsProcessorFeaturePresent( UINT feature )
{
    return hb_cpu_feature_present( feature, core_mmx_supported );
}


/**********************************************************************
 *           BTCpu64NotifyMemoryDirty  (xtajit64.@)
 */
void WINAPI BTCpu64NotifyMemoryDirty( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
    hb_notify_range( addr, size );
}


/**********************************************************************
 *           BTCpu64NotifyReadFile  (xtajit64.@)
 */
void WINAPI BTCpu64NotifyReadFile( HANDLE handle, void *addr, SIZE_T size, BOOL is_post, NTSTATUS status )
{
    TRACE( "%p %p %Ix\n", handle, addr, size );
    /* Even an unsuccessful read can have written a partial destination. */
    if (is_post) hb_notify_range( addr, size );
}


/**********************************************************************
 *           FlushInstructionCacheHeavy  (xtajit64.@)
 */
void WINAPI FlushInstructionCacheHeavy( void *addr, SIZE_T size )
{
    TRACE( "%p %Ix\n", addr, size );
    hb_notify_range( addr, size );
}


/**********************************************************************
 *           NotifyMapViewOfSection  (xtajit64.@)
 */
NTSTATUS WINAPI NotifyMapViewOfSection( void *unk1, void *addr, void *unk2, SIZE_T size,
                                        ULONG alloc_type, ULONG protect )
{
    struct xtajit64_memory_params params = { addr, size, alloc_type, protect, TRUE, STATUS_SUCCESS };

    TRACE( "%p %Ix %lx %lx\n", addr, size, alloc_type, protect );
    return xtajit64_unix_call( unix_notify_map_view, &params );
}


/**********************************************************************
 *           NotifyMemoryAlloc  (xtajit64.@)
 */
void WINAPI NotifyMemoryAlloc( void *addr, SIZE_T size, ULONG type, ULONG prot, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, prot, is_post, status };

    TRACE( "%p %Ix\n", addr, size );
    (void)xtajit64_unix_call( unix_notify_memory_alloc, &params );
}


/**********************************************************************
 *           NotifyMemoryFree  (xtajit64.@)
 */
void WINAPI NotifyMemoryFree( void *addr, SIZE_T size, ULONG type, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, type, 0, is_post, status };

    TRACE( "%p %Ix %lx\n", addr, size, type );
    (void)xtajit64_unix_call( unix_notify_memory_free, &params );
}


/**********************************************************************
 *           NotifyMemoryProtect  (xtajit64.@)
 */
void WINAPI NotifyMemoryProtect( void *addr, SIZE_T size, ULONG prot, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, size, 0, prot, is_post, status };

    TRACE( "%p %Ix %lx\n", addr, size, prot );
    (void)xtajit64_unix_call( unix_notify_memory_protect, &params );
}


/**********************************************************************
 *           NotifyUnmapViewOfSection  (xtajit64.@)
 */
void WINAPI NotifyUnmapViewOfSection( void *addr, BOOL is_post, NTSTATUS status )
{
    struct xtajit64_memory_params params = { addr, 0, 0, 0, is_post, status };

    TRACE( "%p\n", addr );
    (void)xtajit64_unix_call( unix_notify_unmap_view, &params );
}


/**********************************************************************
 *           ProcessInit  (xtajit64.@)
 */
NTSTATUS WINAPI ProcessInit(void)
{
    struct xtajit64_process_init_params params;
    UNICODE_STRING trace_name = RTL_CONSTANT_STRING( L"MACRUNNER_HB_TRACE_XTAJIT64" );
    WCHAR trace_buffer[16];
    UNICODE_STRING trace_value = { 0, sizeof(trace_buffer), trace_buffer };
    NTSTATUS status;

    trace_simulation = !RtlQueryEnvironmentVariable_U( NULL, &trace_name, &trace_value ) &&
                       trace_value.Length && trace_value.Buffer[0] != '0';
    if (!hb_return_instruction)
    {
        SIZE_T size = 4096;
        void *address = NULL, *protect_address;
        ULONG old_protect;
        status = NtAllocateVirtualMemory(GetCurrentProcess(), &address, 0, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (status) return status;
        *(unsigned char *)address = 0xc3; /* x64 RET, deliberately not an EC page. */
        protect_address = address;
        status = NtProtectVirtualMemory(GetCurrentProcess(), &protect_address, &size,
                                        PAGE_EXECUTE_READ, &old_protect);
        if (status) return status;
        hb_return_instruction = address;
    }
    xtajit64_prepare_process_init( &params );
    status = xtajit64_unix_call( unix_process_init, &params );
    simulate_v2_supported = !status && xtajit64_process_init_supports_v2( &params );
    simulate_v3_supported = !status && xtajit64_process_init_supports_v3( &params );
    simulate_v4_supported = !status && xtajit64_process_init_supports_v4( &params );
    simulate_v5_supported = !status && xtajit64_process_init_supports_v5( &params );
    x87_transfer_supported = !status && xtajit64_process_init_supports_x87( &params );
    /* This PE is built as the matching V5 provider. Reject an older/mismatched
     * companion before Wine can publish profile 15 after ProcessInit returns. */
    if (!status && (!simulate_v5_supported || !x87_transfer_supported)) status = STATUS_NOT_SUPPORTED;
    /* Loader publication happens after this callback; only resolve now. Even
     * an older native endpoint must not let a later profile-15 publication
     * silently select V3 or the old bulk-fetch route. Missing exports are optional. */
    if (!status) hb_resolve_memory_access();
    core_mmx_supported = simulate_v2_supported && (params.features & XTAJIT64_FEATURE_CPUID_MMX);
    syscall_stub_supported = simulate_v3_supported && (params.features & XTAJIT64_FEATURE_SYSCALL_STUB);
    MESSAGE( "macrunner-xtajit64: ProcessInit status=%08lx\n", status );
    return status;
}


/**********************************************************************
 *           ProcessTerm  (xtajit64.@)
 */
void WINAPI ProcessTerm( HANDLE handle, BOOL is_post, NTSTATUS status )
{
    TRACE( "%p\n", handle );
    (void)xtajit64_unix_call( unix_process_term, NULL );
}


/**********************************************************************
 *           ResetToConsistentState  (xtajit64.@)
 */
void WINAPI ResetToConsistentState( EXCEPTION_RECORD *rec, CONTEXT *context, ARM64_NT_CONTEXT *arm_ctx )
{
    hb_flags_delivery *delivery = hb_owned_delivery();
    AMD64_CONTEXT *ctx = (AMD64_CONTEXT *)context;
    if (!delivery) return;
    hb_flags_delivery_event event = hb_exception_event( rec, ctx );
    uint32_t flags = ctx ? ctx->EFlags : 0;

    /* Wine has converted through ARM NZCV before this callback. Restore only
     * PF/AF/DF for the exact owned event; retain every incoming represented bit,
     * including debugger edits. Consume before any guest handler can nest. */
    if (hb_flags_delivery_consume( delivery, (ULONG_PTR)NtCurrentTeb(), &event,
            arm_ctx ? arm_ctx->Pc : 0, arm_ctx ? arm_ctx->Sp : 0,
            ctx && (ctx->ContextFlags & CONTEXT_AMD64_CONTROL) == CONTEXT_AMD64_CONTROL,
            &flags ))
        ctx->EFlags = flags;
    TRACE( "%p %p %p\n", rec, context, arm_ctx );
}


/**********************************************************************
 *           ThreadInit  (xtajit64.@)
 */
NTSTATUS WINAPI ThreadInit(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu = NtCurrentTeb()->ChpeV2CpuAreaInfo;
    NTSTATUS status;
    if (!cpu || !cpu->ContextAmd64 || !cpu->EmulatorStackBase ||
        (ULONG_PTR)cpu->EmulatorStackBase < (ULONG_PTR)cpu->EmulatorStackLimit + 0x2000)
        return STATUS_INVALID_PARAMETER;
    cpu->EmulatorData[0] = 0; /* Stable per-thread storage owned by this emulator. */
    cpu->EmulatorData[1] = 0; /* One-shot PF/AF/DF continuation side state. */
    /* This callback precedes Wine's per-thread static TLS setup. The first
     * owned guest raise initializes its zero-filled delivery state lazily. */
    cpu->SuspendDoorbell = (ULONG *)&cpu->EmulatorData[0];
    status = xtajit64_unix_call( unix_thread_init, NULL );
    MESSAGE( "macrunner-xtajit64: ThreadInit status=%08lx\n", status );
    return status;
}


/**********************************************************************
 *           ThreadTerm  (xtajit64.@)
 */
static NTSTATUS hb_quiesce_thread_before_term( HANDLE handle )
{
    OBJECT_BASIC_INFORMATION access;
    THREAD_BASIC_INFORMATION info;
    CONTEXT context = {0};
    HANDLE target = NULL;
    NTSTATUS status;

    if (handle == NtCurrentThread()) return STATUS_SUCCESS;
    status = NtQueryObject( handle, ObjectBasicInformation, &access, sizeof(access), NULL );
    if (status) return status;
    if (!(access.GrantedAccess & THREAD_TERMINATE)) return STATUS_ACCESS_DENIED;
    status = NtDuplicateObject( NtCurrentProcess(), handle, NtCurrentProcess(), &target,
                                THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME |
                                THREAD_GET_CONTEXT, 0, 0 );
    if (status) return status;
    status = NtQueryInformationThread( target, ThreadBasicInformation, &info, sizeof(info), NULL );
    if (!status && info.ClientId.UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess &&
        info.ClientId.UniqueThread != NtCurrentTeb()->ClientId.UniqueThread)
    {
        /* A forced Unix thread exit may run pthread destructors. Wait for the
         * same committed guest boundary used by cooperative GetThreadContext,
         * so teardown cannot recursively acquire a lock held by the target.
         * Wine calls this notification before the terminating syscall. */
        status = NtSuspendThread( target, NULL );
        if (!status)
        {
            context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            status = NtGetContextThread( target, &context );
            if (status)
            {
                NTSTATUS resume_status = NtResumeThread( target, NULL );
                if (resume_status) WARN( "failed to undo termination suspension: %08lx\n", resume_status );
            }
            /* On success, the outer NtTerminateThread consumes this target.
             * Its validated server path has no further normal failure branch.
             * This PRE-only ABI cannot protect concurrent close/reuse of the
             * caller's original handle; callers must retain it through exit. */
        }
    }
    NtClose( target );
    return status;
}

void WINAPI ThreadTerm( HANDLE handle, LONG exit_code )
{
    NTSTATUS status;
    TRACE( "%p %lx\n", handle, exit_code );
    status = hb_quiesce_thread_before_term( handle );
    if (status) TRACE( "termination quiescence unavailable: %08lx\n", status );
    (void)xtajit64_unix_call( unix_thread_term, NULL );
}


/**********************************************************************
 *           UpdateProcessorInformation  (xtajit64.@)
 */
void WINAPI UpdateProcessorInformation( SYSTEM_CPU_INFORMATION *info )
{
    hb_cpu_feature_information_t profile = hb_cpu_feature_information( core_mmx_supported );
    info->ProcessorArchitecture = profile.architecture;
    info->ProcessorLevel = profile.level;
    info->ProcessorRevision = profile.revision;
    info->ProcessorFeatureBits = profile.feature_bits;
}


/**********************************************************************
 *           DllMain
 */
BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, void *reserved )
{
    if (reason == DLL_PROCESS_ATTACH) LdrDisableThreadCalloutsForDll( inst );
    return TRUE;
}
