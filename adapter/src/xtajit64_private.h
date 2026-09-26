#ifndef __XTAJIT64_PRIVATE_H
#define __XTAJIT64_PRIVATE_H

#include <stdint.h>
#include "windef.h"
#include "winnt.h"
#include "wine/unixlib.h"
#include "wine/macrunner_hb_x64_packet.h"

/* Adapter-local extension: retain every V1/V2 ordinal and packet byte. */
enum xtajit64_unix_funcs_v3
{
    unix_simulate_v3 = unix_funcs_count,
    unix_funcs_count_v3
};

#define XTAJIT64_FEATURE_SIMULATE_V3 2u
/* Capability metadata only: no ordinal or packet layout changes. */
#define XTAJIT64_FEATURE_CPUID_MMX 0x100u
#define XTAJIT64_FEATURE_SYSCALL_STUB 0x200u
/* Private successful boundary notification, never a guest exception code. */
#define XTAJIT64_STATUS_SYSCALL_STUB ((NTSTATUS)0x4000ff01u)
#define XTAJIT64_EXCEPTION_ACCESS_VIOLATION 0xc0000005u

struct xtajit64_fault_record
{
    uint32_t valid;
    uint32_t exception_code;
    uint32_t access;
    uint32_t reserved;
    uint64_t pc;
    uint64_t address;
};

struct xtajit64_simulate_params_v3
{
    /* extension.struct_size describes this V2 member, not the outer packet. */
    struct xtajit64_simulate_params_v2 v2;
    struct xtajit64_fault_record fault;
};

static inline int xtajit64_process_init_supports_v3( const struct xtajit64_process_init_params *params )
{
    return xtajit64_process_init_supports_v2( params ) &&
           (params->features & XTAJIT64_FEATURE_SIMULATE_V3) &&
           params->unix_funcs_count > unix_simulate_v3;
}

/* Leave the output untouched unless a complete, matching guest fault arrived.
 * Zero is a valid fault address (and a valid instruction-fetch fault PC). */
static inline int xtajit64_prepare_memory_exception( EXCEPTION_RECORD *record, NTSTATUS status,
                                                    ULONG faulted, const struct xtajit64_fault_record *fault )
{
    if (!record || !fault || faulted != 1 || fault->valid != 1 || fault->reserved ||
        fault->exception_code != XTAJIT64_EXCEPTION_ACCESS_VIOLATION ||
        (uint32_t)status != fault->exception_code ||
        (fault->access != 0 && fault->access != 1 && fault->access != 8))
        return 0;
    *record = (EXCEPTION_RECORD){0};
    record->ExceptionCode = fault->exception_code;
    record->ExceptionAddress = (void *)(ULONG_PTR)fault->pc;
    record->NumberParameters = 2;
    record->ExceptionInformation[0] = fault->access;
    record->ExceptionInformation[1] = fault->address;
    return 1;
}

C_ASSERT( unix_simulate_v3 == 12 );
C_ASSERT( unix_funcs_count_v3 == 13 );
C_ASSERT( sizeof(struct xtajit64_fault_record) == 32 );

struct xtajit64_memory_params
{
    void *addr;
    SIZE_T size;
    ULONG type;
    ULONG protect;
    BOOL is_post;
    NTSTATUS status;
};

#endif
