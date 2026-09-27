#ifndef HB_CODE_WITNESS_RUNTIME_V1_H
#define HB_CODE_WITNESS_RUNTIME_V1_H

#include "hb_runtime.h"
#include "hb_code_witness_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Default-off MACRUNNER_HB_CODE_WITNESS_ENTRY controls native admission.
 * This header is the consumer fixture contract; implementation is staged
 * separately. It is not evidence that the engine supports the API yet. */
typedef enum hb_code_witness_reject_reason_v1 {
    HB_CODE_WITNESS_REJECT_NONE = 0,
    HB_CODE_WITNESS_REJECT_STATE = 1,
    HB_CODE_WITNESS_REJECT_BYTES = 2,
    HB_CODE_WITNESS_REJECT_VALIDATION_FAULT = 3,
    HB_CODE_WITNESS_REJECT_CONTRACT = 4
} hb_code_witness_reject_reason_v1_t;

typedef struct hb_code_witness_stats_v1 {
    uint32_t size;
    uint32_t version;
    uint64_t prepared;
    uint64_t published;
    uint64_t query_refused;
    uint64_t rejected_state;
    uint64_t rejected_bytes;
    uint64_t rejected_validation_fault;
    uint64_t fresh_fetch_returns;
    uint64_t last_reject_guest_pc;
    uint32_t last_reject_reason;
    uint32_t reserved;
} hb_code_witness_stats_v1_t;

/* Owner-thread, quiescent only. The callback and opaque object remain valid
 * until a successful replacement/disable or runtime destruction. An identical
 * tuple is a no-op. Replacing the tuple revokes all old native publishers before
 * releasing descriptors. NULL query disables admission. The final argument
 * attests no synchronous same-runtime reentry/reset/destruction/reclamation
 * from callbacks; deferred process-wide invalidation notifications are allowed.
 * EXEC callbacks remain unsupported. Invalid/reentrant calls change nothing. */
hb_result_t hb_jit_runtime_set_code_witness_v1(
    hb_jit_runtime_t *rt, hb_code_witness_query_cb query, void *opaque,
    bool no_synchronous_local_lifetime_mutation);

/* Caller supplies exact size/version. Returns 1 only for a valid quiescent
 * snapshot; returns 0 and preserves every output byte on any invalid request.
 * Counters are cold admission/rejection events, not hot native hit counters.
 * Rejection returns HB_OK with source work accounted but zero target work;
 * the stale target is evicted and ctx PC/RIP identify the fresh-fetch target. */
int hb_jit_runtime_get_code_witness_stats_v1(
    const hb_jit_runtime_t *rt, hb_code_witness_stats_v1_t *out);

#ifdef __cplusplus
}
#endif
#endif
