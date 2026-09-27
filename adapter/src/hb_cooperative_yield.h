#ifndef HB_COOPERATIVE_YIELD_H
#define HB_COOPERATIVE_YIELD_H

#include <stdint.h>

/* The Unix adapter publishes this marker only for a committed counter-free
 * slice. Its wire value matches HB_ERR_STEP_LIMIT without a core dependency. */
#define HB_PE_COUNTER_FREE_YIELD (-10)
#define HB_PE_MAX_SLICES 65536u

static inline int hb_pe_is_counter_free_yield(uint32_t status, int32_t hb_result,
                                            uint32_t faulted, uint64_t steps,
                                            uint64_t blocks)
{
    return status == 0 && hb_result == HB_PE_COUNTER_FREE_YIELD &&
           !faulted && (steps != 0 || blocks != 0);
}

#endif
