#include "../adapter/src/hb_cooperative_yield.h"
#include "hb_result.h"
#include <stdio.h>

_Static_assert(HB_PE_COUNTER_FREE_YIELD == HB_ERR_STEP_LIMIT,
               "PE yield marker must match the core wire result");
_Static_assert(HB_PE_MAX_SLICES == 65536u, "ordinary PE slice cap changed");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "cooperative-yield failure at line %d: %s\n", \
                __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void)
{
    static const struct {
        uint32_t status;
        int32_t result;
        uint32_t faulted;
        uint64_t steps, blocks;
        int accepted;
    } cases[] = {
        {0, HB_PE_COUNTER_FREE_YIELD, 0, 1, 0, 1},
        {0, HB_PE_COUNTER_FREE_YIELD, 0, 0, 1, 1},
        {0, HB_PE_COUNTER_FREE_YIELD, 0, UINT64_MAX, UINT64_MAX, 1},
        {0, HB_PE_COUNTER_FREE_YIELD, 0, 0, 0, 0},
        {1, HB_PE_COUNTER_FREE_YIELD, 0, 1, 1, 0},
        {UINT32_C(0xc000000d), HB_PE_COUNTER_FREE_YIELD, 0, 1, 1, 0},
        {0, HB_PE_COUNTER_FREE_YIELD, 1, 1, 1, 0},
        {0, HB_PE_COUNTER_FREE_YIELD, UINT32_MAX, 1, 1, 0},
        {0, HB_OK, 0, 1, 1, 0},
        {0, HB_ERR_BLOCK_LIMIT, 0, 1, 1, 0},
        {0, HB_ERR_INVALID_ARG, 0, 1, 1, 0},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        CHECK(hb_pe_is_counter_free_yield(cases[i].status, cases[i].result,
              cases[i].faulted, cases[i].steps, cases[i].blocks) == cases[i].accepted);
    }

    /* Model the PE loop's conditional increment: more than 65536 marked
     * returns still permit ordinary work, without resetting its slice count. */
    uint32_t ordinary_slices = 0;
    uint64_t marked_returns = 0;
    for (uint32_t i = 0; i < 2 * HB_PE_MAX_SLICES + 1; ++i) {
        int32_t result = i % 8192 == 0 ? HB_OK : HB_PE_COUNTER_FREE_YIELD;
        int yielded = hb_pe_is_counter_free_yield(0, result, 0, 0, 1);
        if (!yielded) CHECK(++ordinary_slices < HB_PE_MAX_SLICES);
        else marked_returns++;
    }
    CHECK(marked_returns > HB_PE_MAX_SLICES);
    CHECK(ordinary_slices == 17);

    /* Ordinary returns retain the exact old boundary after the marked ones. */
    while (ordinary_slices + 1 < HB_PE_MAX_SLICES) {
        CHECK(!hb_pe_is_counter_free_yield(0, HB_OK, 0, 1, 1));
        CHECK(++ordinary_slices < HB_PE_MAX_SLICES);
    }
    CHECK(ordinary_slices == HB_PE_MAX_SLICES - 1);
    CHECK(!hb_pe_is_counter_free_yield(0, HB_OK, 0, 1, 1));
    CHECK(++ordinary_slices == HB_PE_MAX_SLICES);

    /* An ordinary-only run has the same timeout threshold. */
    ordinary_slices = 0;
    for (uint32_t i = 1; i <= HB_PE_MAX_SLICES; ++i) {
        int timed_out = !hb_pe_is_counter_free_yield(0, HB_OK, 0, 1, 0) &&
                        ++ordinary_slices >= HB_PE_MAX_SLICES;
        CHECK(timed_out == (i == HB_PE_MAX_SLICES));
    }
    puts("cooperative-yield: marker and mixed PE slice accounting PASS");
    return 0;
}
