#ifndef HB_CODE_WITNESS_V1_H
#define HB_CODE_WITNESS_V1_H

#include <stddef.h>
#include <stdint.h>

#define HB_CODE_WITNESS_VERSION 1u
#define HB_CODE_WITNESS_PAGE_SHIFT 12u
#define HB_CODE_WITNESS_MAX_SPAN 4096u
#define HB_CODE_WITNESS_MAX_PAGES 2u
#define HB_CODE_WITNESS_QUERY_SYMBOL "__wine_hb_code_witness_query_v1"

#define HB_CW_READY       (UINT64_C(1) << 0)
#define HB_CW_COMMITTED   (UINT64_C(1) << 1)
#define HB_CW_READ        (UINT64_C(1) << 2)
#define HB_CW_WRITE       (UINT64_C(1) << 3)
#define HB_CW_EXEC        (UINT64_C(1) << 4)
#define HB_CW_GUARD       (UINT64_C(1) << 5)
#define HB_CW_WRITEWATCH  (UINT64_C(1) << 6)
#define HB_CW_COW         (UINT64_C(1) << 7)
#define HB_CW_IDENTITY    (UINT64_C(1) << 8)
#define HB_CW_UNKNOWN     (UINT64_C(1) << 9)
#define HB_CW_KNOWN_FLAGS UINT64_C(0x03ff)
#define HB_CW_FLAG_MASK   UINT64_C(0xffff)
#define HB_CW_GENERATION_SHIFT 16u
#define HB_CW_GENERATION_MAX UINT64_C(0x0000ffffffffffff)
#define HB_CW_READ_REQUIRED \
    (HB_CW_READY | HB_CW_COMMITTED | HB_CW_READ | HB_CW_EXEC | HB_CW_IDENTITY)
#define HB_CW_READ_FORBIDDEN (HB_CW_GUARD | HB_CW_UNKNOWN)

/* state is accessed only with compiler atomics/generated ordered loads.
 * Other fields are initialized before publication and immutable afterwards. */
typedef struct hb_code_page_witness_v1 {
    uint32_t size;
    uint32_t version;
    uint64_t guest_page;
    uint64_t state;
    uint64_t reserved;
} hb_code_page_witness_v1;

typedef struct hb_code_span_witness_v1 {
    uint32_t size;
    uint32_t version;
    uint64_t guest_start;
    uint64_t guest_len;
    uint32_t page_count;
    uint32_t reserved;
    const hb_code_page_witness_v1 *pages[HB_CODE_WITNESS_MAX_PAGES];
    uint64_t expected[HB_CODE_WITNESS_MAX_PAGES];
} hb_code_span_witness_v1;

/* Caller initializes out.size/version; producer clears all other output on
 * failure. No guest or unstable shadow-region pointers may be returned. */
typedef int (*hb_code_witness_query_v1_fn)(uint64_t guest_start, uint64_t guest_len,
                                         hb_code_span_witness_v1 *out);
/* Generic core callback adds caller-owned opaque data without changing the
 * producer wire layout. Install/replace only while runtime is quiescent. */
typedef int (*hb_code_witness_query_cb)(void *opaque, uint64_t guest_start,
                                      uint64_t guest_len, hb_code_span_witness_v1 *out);

#if defined(__cplusplus)
static_assert(sizeof(void *) == 8, "V1 is a 64-bit process-local ABI");
static_assert(sizeof(hb_code_page_witness_v1) == 32, "page layout");
static_assert(offsetof(hb_code_page_witness_v1, state) == 16, "atomic state offset");
static_assert(sizeof(hb_code_span_witness_v1) == 64, "span layout");
#else
_Static_assert(sizeof(void *) == 8, "V1 is a 64-bit process-local ABI");
_Static_assert(sizeof(hb_code_page_witness_v1) == 32, "page layout");
_Static_assert(offsetof(hb_code_page_witness_v1, state) == 16, "atomic state offset");
_Static_assert(sizeof(hb_code_span_witness_v1) == 64, "span layout");
#endif

#endif
