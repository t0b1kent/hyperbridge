#ifndef __XTAJIT64_GUARD_H
#define __XTAJIT64_GUARD_H

#include "xtajit64_private.h"
#include "guard_access_v1.h"

/* Append only: V1/V2/V3 packets and ordinals retain their exact bytes. */
enum xtajit64_unix_funcs_v4
{
    unix_simulate_v4 = unix_funcs_count_v3,
    unix_funcs_count_v4
};

#define XTAJIT64_FEATURE_SIMULATE_V4 4u
#define XTAJIT64_STATUS_ACCESS_PENDING ((NTSTATUS)0x4000ff02u)
#define XTAJIT64_HB_ACCESS_PENDING (-20)

struct xtajit64_simulate_params_v4
{
    struct xtajit64_simulate_params_v3 v3;
    uint32_t size;
    uint32_t version;
    uint64_t owner_module;
    uint64_t selection_epoch;
    uint64_t current_teb;
    uint64_t invocation_serial;
    uint64_t capabilities;
    uint32_t pending;
    uint32_t reserved;
    WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 request;
};

static inline int xtajit64_process_init_supports_v4( const struct xtajit64_process_init_params *params )
{
    return xtajit64_process_init_supports_v3( params ) &&
           (params->features & XTAJIT64_FEATURE_SIMULATE_V4) &&
           params->unix_funcs_count > unix_simulate_v4;
}

static inline int xtajit64_guard_identity_valid( const struct xtajit64_simulate_params_v4 *params,
                                                uint64_t owner, uint64_t epoch, uint64_t teb,
                                                uint64_t serial )
{
    return params && params->size == sizeof(*params) && params->version == 1 &&
           owner && epoch == 1 && teb && serial &&
           params->owner_module == owner && params->selection_epoch == epoch &&
           params->current_teb == teb && params->invocation_serial == serial &&
           wine_emulator_memory_access_caps_valid_v1( params->capabilities ) && !params->reserved;
}

/* Retire this frame's slot before calling Wine or entering guest VEH. No TLS,
 * borrowed CONTEXT, exception-record pointer or output-copy after consumption.
 * A failed validation also retires the slot and leaves the caller output alone. */
static inline int xtajit64_guard_take_pending( struct xtajit64_simulate_params_v4 *params,
                                              uint64_t owner, uint64_t epoch, uint64_t teb,
                                              uint64_t serial, uint64_t exported_pc,
                                              WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 *out )
{
    WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 value;
    uint64_t end;
    uint32_t pending;
    if (!params || !out) return 0;
    pending = params->pending;
    value = params->request;
    params->pending = 0;
    params->request = (WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1){0};
    if (pending != 1 || !xtajit64_guard_identity_valid( params, owner, epoch, teb, serial ) ||
        params->v3.v2.v1.status != XTAJIT64_STATUS_ACCESS_PENDING ||
        params->v3.v2.v1.hb_result != XTAJIT64_HB_ACCESS_PENDING ||
        params->v3.v2.v1.faulted || params->v3.fault.valid ||
        value.size != sizeof(value) || value.version != WINE_EMULATOR_MEMORY_ACCESS_VERSION ||
        value.owner_module != owner || value.selection_epoch != epoch ||
        value.current_teb != teb || value.invocation_serial != serial ||
        value.guest_pc != exported_pc ||
        !wine_emulator_memory_access_scope_valid_v1( params->capabilities, value.phase,
                                                     value.access, value.span_length ) ||
        !wine_emulator_memory_access_alignment_valid_v1( value.phase, value.span_length,
                                                         value.guest_address ) ||
        !wine_emulator_memory_access_exec_span_valid_v1( value.phase, value.guest_pc,
                                                         value.guest_address, value.span_length ) ||
        value.reserved[0] || value.reserved[1] || value.reserved[2]) return 0;
    end = value.guest_address + value.span_length - 1;
    if (end < value.guest_address || (value.guest_address >> 12) != (end >> 12)) return 0;
    *out = value;
    return 1;
}

/* Call only for an actual service return of STATUS_GUARD_PAGE_VIOLATION. */
static inline void xtajit64_guard_exception( EXCEPTION_RECORD *record,
                                            const WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 *request )
{
    *record = (EXCEPTION_RECORD){0};
    record->ExceptionCode = 0x80000001u;
    record->ExceptionAddress = (void *)(ULONG_PTR)request->guest_pc;
    record->NumberParameters = 2;
    record->ExceptionInformation[0] = request->access;
    record->ExceptionInformation[1] = request->guest_address;
}

C_ASSERT( unix_simulate_v4 == 13 );
C_ASSERT( unix_funcs_count_v4 == 14 );

#endif
