/*
 * Shared MacRunner x64 PE/Unix packets. V1 layouts and ordinals are retained.
 * Declarations consolidated from xtajit64_private.h and ntdll/unixlib.h.
 * Original ntdll Unix interface: Copyright (C) 2020 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef __WINE_MACRUNNER_HB_X64_PACKET_H
#define __WINE_MACRUNNER_HB_X64_PACKET_H

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include "windef.h"
#include "winnt.h"
#include "winternl.h"

enum xtajit64_unix_funcs
{
    unix_process_init,
    unix_thread_init,
    unix_thread_term,
    unix_process_term,
    unix_simulate,
    unix_notify_memory_alloc,
    unix_notify_memory_protect,
    unix_notify_memory_free,
    unix_notify_map_view,
    unix_notify_unmap_view,
    unix_flush_instruction_cache,
    unix_simulate_v2,
    unix_funcs_count
};

#define MACRUNNER_HB_X64_REGISTER_FIELDS \
    ULONG64 rax, rbx, rcx, rdx; \
    ULONG64 rsi, rdi, rsp, rbp; \
    ULONG64 r8, r9, r10, r11; \
    ULONG64 r12, r13, r14, r15; \
    ULONG64 rip, rflags; \
    ULONG64 gs_base, fs_base; \
    WORD seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss; \
    ULONG64 xmm[16][2]

struct xtajit64_amd64_context
{
    MACRUNNER_HB_X64_REGISTER_FIELDS;
};

struct xtajit64_simulate_params
{
    struct xtajit64_amd64_context context;
    ULONG max_code_bytes;
    NTSTATUS status;
    LONG hb_result;
    ULONG faulted;
    ULONG64 steps;
    ULONG64 blocks;
};

struct macrunner_hb_x64_import_context_params
{
    MACRUNNER_HB_X64_REGISTER_FIELDS;
    ULONG handled;
    NTSTATUS status;
};
#undef MACRUNNER_HB_X64_REGISTER_FIELDS

/* V2 endpoints require a complete V2 allocation. The size word is a format
 * check, not proof that an arbitrary caller pointer has that much storage.
 * These full-state packets transport raw MXCSR, independently of ContextFlags.
 * Windows input authority is FltSave.MxCsr; output mirrors both MXCSR fields. */
#define MACRUNNER_HB_X64_PACKET_VERSION 2u
struct macrunner_hb_x64_packet_extension
{
    uint32_t struct_size;
    uint32_t version;
    uint32_t mxcsr;
    uint32_t flags;
};

struct xtajit64_simulate_params_v2
{
    struct xtajit64_simulate_params v1;
    struct macrunner_hb_x64_packet_extension extension;
};

struct macrunner_hb_x64_import_context_params_v2
{
    struct macrunner_hb_x64_import_context_params v1;
    struct macrunner_hb_x64_packet_extension extension;
};

static inline int macrunner_hb_x64_packet_extension_valid(
    const struct macrunner_hb_x64_packet_extension *extension, uint32_t size )
{
    return extension && extension->struct_size == size &&
           extension->version == MACRUNNER_HB_X64_PACKET_VERSION && !extension->flags;
}

/* Existing process_init ignored args in V1. Zero output fields make an old
 * implementation distinguishable without calling its nonexistent V2 ordinal. */
#define XTAJIT64_PROCESS_INIT_VERSION 1u
#define XTAJIT64_FEATURE_SIMULATE_V2 1u
struct xtajit64_process_init_params
{
    uint32_t struct_size;
    uint32_t version;
    uint32_t flags;
    uint32_t features;
    uint32_t unix_funcs_count;
};

static inline void xtajit64_prepare_process_init( struct xtajit64_process_init_params *params )
{
    *params = (struct xtajit64_process_init_params){ sizeof(*params), XTAJIT64_PROCESS_INIT_VERSION, 0, 0, 0 };
}

static inline int xtajit64_process_init_request_valid( const struct xtajit64_process_init_params *params )
{
    return params && params->struct_size == sizeof(*params) &&
           params->version == XTAJIT64_PROCESS_INIT_VERSION && !params->flags &&
           !params->features && !params->unix_funcs_count;
}

static inline void xtajit64_reply_process_init( struct xtajit64_process_init_params *params )
{
    params->features = XTAJIT64_FEATURE_SIMULATE_V2;
    params->unix_funcs_count = unix_funcs_count;
}

static inline int xtajit64_process_init_supports_v2( const struct xtajit64_process_init_params *params )
{
    return params && params->struct_size == sizeof(*params) &&
           params->version == XTAJIT64_PROCESS_INIT_VERSION && !params->flags &&
           (params->features & XTAJIT64_FEATURE_SIMULATE_V2) &&
           params->unix_funcs_count > unix_simulate_v2;
}

struct macrunner_hb_register_import_thunk_params
{
    void    *target;
    void    *pe_call12;
    void    *pe_callback12;
    ULONG64  module_id;
    ULONG64  target_module_id;
    ULONG64  guest_target;
    USHORT   target_machine;
    USHORT   target_module_machine;
    char     dll_name[96];
    char     import_name[96];
};

/* Discovery uses the EXISTING MacRunner V1 registration endpoint, which rejects
 * a NULL target before registration or string access. It does not support
 * arbitrary stock Wine tables lacking that endpoint. A normal registration
 * cannot have this NULL target. No padding or additional storage is read. */
#define MACRUNNER_HB_IMPORT_V2_PROBE_MAGIC UINT64_C(0x4842583634563201)
#define MACRUNNER_HB_IMPORT_V2_PROBE_REPLY UINT64_C(0x494d504f52545632)
#define MACRUNNER_HB_IMPORT_V2_PROBE_VERSION 1u

static inline void macrunner_hb_prepare_import_v2_probe( struct macrunner_hb_register_import_thunk_params *params )
{
    *params = (struct macrunner_hb_register_import_thunk_params){0};
    params->module_id = MACRUNNER_HB_IMPORT_V2_PROBE_MAGIC;
    params->target_module_id = ((ULONG64)MACRUNNER_HB_IMPORT_V2_PROBE_VERSION << 32) | sizeof(*params);
}

static inline int macrunner_hb_import_v2_probe_fields_valid( const struct macrunner_hb_register_import_thunk_params *params )
{
    return params && !params->target && !params->pe_call12 && !params->pe_callback12 &&
           params->module_id == MACRUNNER_HB_IMPORT_V2_PROBE_MAGIC &&
           params->target_module_id == (((ULONG64)MACRUNNER_HB_IMPORT_V2_PROBE_VERSION << 32) | sizeof(*params)) &&
           !params->target_machine && !params->target_module_machine &&
           !params->dll_name[0] && !params->import_name[0];
}

static inline int macrunner_hb_reply_import_v2_probe( struct macrunner_hb_register_import_thunk_params *params )
{
    if (!macrunner_hb_import_v2_probe_fields_valid( params ) || params->guest_target) return 0;
    params->guest_target = MACRUNNER_HB_IMPORT_V2_PROBE_REPLY;
    return 1;
}

static inline int macrunner_hb_import_v2_probe_supported( const struct macrunner_hb_register_import_thunk_params *params )
{
    return macrunner_hb_import_v2_probe_fields_valid( params ) &&
           params->guest_target == MACRUNNER_HB_IMPORT_V2_PROBE_REPLY;
}

#if defined(__aarch64__) || defined(__x86_64__)
_Static_assert(sizeof(struct xtajit64_amd64_context) == 432, "V1 register size");
_Static_assert(offsetof(struct xtajit64_amd64_context, xmm) == 176, "V1 XMM offset");
_Static_assert(sizeof(struct xtajit64_simulate_params) == 464, "V1 simulation size");
_Static_assert(offsetof(struct xtajit64_simulate_params, status) == 436, "V1 simulation status");
_Static_assert(offsetof(struct xtajit64_simulate_params, blocks) == 456, "V1 simulation blocks");
_Static_assert(sizeof(struct macrunner_hb_x64_import_context_params) == 440, "V1 import size");
_Static_assert(offsetof(struct macrunner_hb_x64_import_context_params, handled) == 432, "V1 import handled");
_Static_assert(offsetof(struct macrunner_hb_x64_import_context_params, status) == 436, "V1 import status");
_Static_assert(sizeof(struct xtajit64_simulate_params_v2) == 480, "V2 simulation size");
_Static_assert(sizeof(struct macrunner_hb_x64_import_context_params_v2) == 456, "V2 import size");
_Static_assert(unix_simulate == 4 && unix_flush_instruction_cache == 10 && unix_simulate_v2 == 11, "Stable V1 dispatch");
#endif

#endif
