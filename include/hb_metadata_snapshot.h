#ifndef HB_METADATA_SNAPSHOT_H
#define HB_METADATA_SNAPSHOT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Owner-thread cumulative counters across that thread's memory objects.
 * Read only at a quiescent adapter boundary; this function does not scan,
 * allocate, log, reset counters, or change memory policy. Gate0 keeps zeros.
 * Diagnostic callers own their output/time cap. */
void hb_memory_metadata_snapshot_stats(uint64_t *hits, uint64_t *fills,
                                       uint64_t *misses, uint64_t *invalidations);
#ifdef __cplusplus
}
#endif
#endif
