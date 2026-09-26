#ifndef __XTAJIT64_EXEC_H
#define __XTAJIT64_EXEC_H

#include <string.h>
#include "xtajit64_guard.h"
#include "hb_syscall_stub.h"

/* Private append-only transport. Public Wine guard request/bootstrap and V4
 * bytes retain their original layout. Profile 15 may only use this endpoint. */
enum xtajit64_unix_funcs_v5
{
    unix_simulate_v5 = unix_funcs_count_v4,
    unix_funcs_count_v5
};
#define XTAJIT64_FEATURE_SIMULATE_V5 8u
#define XTAJIT64_EXEC_PROFILE 15u

struct xtajit64_syscall_snapshot
{
    uint32_t valid;
    uint32_t service;
    uint64_t guest_pc;
    uint8_t bytes[24];
};

struct xtajit64_simulate_params_v5
{
    struct xtajit64_simulate_params_v4 v4;
    uint32_t size;
    uint32_t version;
    struct xtajit64_syscall_snapshot syscall;
};

static inline int xtajit64_process_init_supports_v5( const struct xtajit64_process_init_params *params )
{
    return xtajit64_process_init_supports_v4( params ) &&
           (params->features & XTAJIT64_FEATURE_SIMULATE_V5) &&
           params->unix_funcs_count > unix_simulate_v5;
}

static inline int xtajit64_exec_identity_valid( const struct xtajit64_simulate_params_v5 *params,
                                               uint64_t owner, uint64_t epoch,
                                               uint64_t teb, uint64_t serial )
{
    return params && params->size == sizeof(*params) && params->version == 1 &&
           params->v4.capabilities == XTAJIT64_EXEC_PROFILE &&
           macrunner_hb_x64_packet_extension_valid( &params->v4.v3.v2.extension,
                                                    sizeof(params->v4.v3.v2) ) &&
           xtajit64_guard_identity_valid( &params->v4, owner, epoch, teb, serial );
}

static inline int xtajit64_exec_request_valid( const struct xtajit64_simulate_params_v5 *params,
                                              uint64_t current_teb )
{
    const struct xtajit64_syscall_snapshot empty_syscall = {0};
    const WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 empty_request = {0};
    return params && xtajit64_exec_identity_valid( params, params->v4.owner_module,
               params->v4.selection_epoch, current_teb, params->v4.invocation_serial ) &&
           params->v4.v3.v2.v1.max_code_bytes == 15 && !params->v4.pending &&
           !memcmp( &params->syscall, &empty_syscall, sizeof(empty_syscall) ) &&
           !memcmp( &params->v4.request, &empty_request, sizeof(empty_request) );
}

/* A local copy is retired before any validation, native checker or callback.
 * Malformed, duplicate and stale results cannot leave a reusable snapshot. */
static inline int xtajit64_exec_take_syscall( struct xtajit64_simulate_params_v5 *params,
                                            uint64_t owner, uint64_t epoch, uint64_t teb,
                                            uint64_t serial, uint64_t exported_pc,
                                            struct xtajit64_syscall_snapshot *out )
{
    struct xtajit64_syscall_snapshot value;
    WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 request;
    const WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 empty_request = {0};
    uint32_t service, pending;
    if (!params || !out) return 0;
    value = params->syscall;
    params->syscall = (struct xtajit64_syscall_snapshot){0};
    pending = params->v4.pending;
    request = params->v4.request;
    params->v4.pending = 0;
    params->v4.request = empty_request;
    if (value.valid != 1 ||
        !xtajit64_exec_identity_valid( params, owner, epoch, teb, serial ) ||
        params->v4.v3.v2.v1.status != XTAJIT64_STATUS_SYSCALL_STUB ||
        params->v4.v3.v2.v1.hb_result || params->v4.v3.v2.v1.faulted ||
        params->v4.v3.fault.valid || pending ||
        memcmp( &request, &empty_request, sizeof(empty_request) ) ||
        value.guest_pc != exported_pc ||
        params->v4.v3.v2.v1.context.rip != exported_pc ||
        !hb_x64_syscall_stub_match( value.guest_pc, value.bytes, sizeof(value.bytes), &service ) ||
        service != value.service) return 0;
    *out = value;
    return 1;
}

static inline int xtajit64_exec_take_pending( struct xtajit64_simulate_params_v5 *params,
                                            uint64_t owner, uint64_t epoch, uint64_t teb,
                                            uint64_t serial, uint64_t exported_pc,
                                            WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 *out )
{
    const struct xtajit64_syscall_snapshot empty = {0};
    struct xtajit64_syscall_snapshot snapshot;
    WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1 request;
    int valid;
    if (!params || !out) return 0;
    snapshot = params->syscall;
    params->syscall = empty;
    valid = xtajit64_guard_take_pending( &params->v4, owner, epoch, teb, serial,
                                        exported_pc, &request );
    if (!valid || !xtajit64_exec_identity_valid( params, owner, epoch, teb, serial ) ||
        memcmp( &snapshot, &empty, sizeof(empty) )) return 0;
    *out = request;
    return 1;
}

C_ASSERT( unix_simulate_v5 == 14 );
C_ASSERT( unix_funcs_count_v5 == 15 );
C_ASSERT( sizeof(struct xtajit64_syscall_snapshot) == 40 );
C_ASSERT( offsetof(struct xtajit64_simulate_params_v5, v4) == 0 );
C_ASSERT( offsetof(struct xtajit64_simulate_params_v5, size) == sizeof(struct xtajit64_simulate_params_v4) );
C_ASSERT( sizeof(struct xtajit64_simulate_params_v5) == sizeof(struct xtajit64_simulate_params_v4) + 48 );

#endif
