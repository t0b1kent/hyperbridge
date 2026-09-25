#ifndef HB_WINEMETAL_COMPUTE_V1_H
#define HB_WINEMETAL_COMPUTE_V1_H

#include "hb_context.h"
#include "hb_result.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Independent marshalling for the observed winemetal unix operation 29.
 * Wire layout/provenance: reports/winemetal-entry-passport-20260921.md.
 * This API adapts the unix parameter packet, NOT the three-argument PE export.
 * These host-side structures are a fixed 64-bit ABI, not serialized pointers. */
#define HB_WINEMETAL_COMPUTE_OP_V1 29u
#define HB_WINEMETAL_COMPUTE_MAX_ARCHIVES_V1 255u

typedef struct {
    uint64_t compute_function;
    const uint64_t *binary_archives_for_lookup;
    uint64_t binary_archive_for_serialization;
    uint8_t num_binary_archives_for_lookup;
    uint8_t fail_on_binary_archive_miss;
    uint8_t support_indirect_command_buffers;
    uint8_t tgsize_is_multiple_of_sgwidth;
    uint32_t immutable_buffers;
} hb_winemetal_compute_info_v1_t;

typedef struct {
    uint64_t device;
    const hb_winemetal_compute_info_v1_t *info;
    uint64_t ret_error;
    uint64_t ret_pso;
} hb_winemetal_compute_params_v1_t;

/* Trusted host entry selected by the embedder, never a guest-supplied pointer.
 * Exact Darwin native prototype; return value is NTSTATUS, not the PSO. */
typedef int32_t (*hb_winemetal_compute_entry_v1_t)(void *params);

typedef struct {
    uint32_t native_invoked;
    int32_t native_status;
    uint64_t error_handle;
    uint64_t pipeline_handle;
} hb_winemetal_compute_report_v1_t;

/* Read the guest's 32-byte packet, snapshot its 32-byte info and optional
 * count*8 archive-handle array, call entry synchronously with host-owned data,
 * then write ONLY the two output handles at guest_packet+16. Handles are opaque:
 * no address translation, retain or release is performed on their values.
 *
 * Preconditions: x64/64-bit ctx with memory; trusted matching entry; packet/info
 * nonnull; report nonnull and not aliasing ctx or guest buffers. The caller owns
 * ctx/memory and keeps inputs/mappings stable during this synchronous operation.
 * entry must not retain the temporary packet/info/array pointers. Reentrant
 * calls require distinct contexts/memory; concurrent access to one context or
 * mutation of this call's guest inputs from a callback is outside the contract.
 * This snapshot contract is NOT automatically equivalent to Wine live memory
 * when inputs are changed during native execution.
 *
 * Output must be represented by writable guest-memory regions; special_write-
 * only endpoints cannot pass preflight. Unused arrays (count==0 or pointer==0)
 * are not read and the host array pointer is NULL. At most 255 handles are read.
 * All required reads and output preflight finish before entry is invoked.
 * report is cleared on entry when nonnull. Pre-invocation failure calls no
 * native target and writes neither guest memory nor guest registers.
 *
 * HB_OK means marshalling/invocation/writeback completed, even if native_status
 * is nonzero (the observed release PE wrapper ignores that status). The caller
 * owns delivery of NTSTATUS and guest return-slot handling. This function never
 * changes registers, PC or SP; PE err_out and PSO-return handling remain in PE.
 * After a native call, report preserves status/handles even on late writeback
 * failure. Native effects cannot be rolled back and a backend may have partially
 * written outputs. No transaction/rollback or module-lifetime guarantee is made.
 */
hb_result_t hb_winemetal_compute_dispatch_v1(
    const hb_context_t *ctx, uint64_t guest_packet,
    hb_winemetal_compute_entry_v1_t entry, hb_winemetal_compute_report_v1_t *report);

#ifdef __cplusplus
}
#endif
#endif
