/*
 * Differential test for hb_memory_protect's multi-region range path.
 *
 * The change under test replaces a full walk of mem->regions with an in-order
 * traversal of the base-keyed treap. The repo's unit suite cannot verify that:
 * its memory tests map raw stack addresses (&code, &wide at hb_test_runner.c:5301)
 * whose values move with ASLR, so 4 of its failures flip run to run. This test is
 * deterministic -- fixed guest addresses, no host pointers -- and prints a digest
 * of the resulting permission map so old and new can be compared byte for byte.
 */
#include <stdio.h>
#include <string.h>
#include "hb_memory.h"

static int failures = 0;

#define CHECK(cond, ...)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            printf("FAIL %s:%d: ", __func__, __LINE__);                   \
            printf(__VA_ARGS__);                                          \
            printf("\n");                                                 \
            failures++;                                                   \
        }                                                                 \
    } while (0)

#define PAGE 0x1000ULL
#define BASE 0x40000000ULL

/* Permission of every page in [BASE, BASE + n*PAGE), as one line. Comparing this
 * string across builds is the actual equivalence check. */
static void digest(hb_memory_t* mem, unsigned pages, const char* tag) {
    printf("%-22s ", tag);
    for (unsigned i = 0; i < pages; i++) {
        hb_region_t* r = hb_memory_find_region(mem, BASE + (hb_gva_t)i * PAGE);
        printf("%x", r ? (unsigned)r->perm : 0xf);
    }
    printf("\n");
}

/* N separate one-page regions, then protect a range covering the middle ones. */
static void test_many_single_page_regions(void) {
    const unsigned N = 64;
    hb_memory_t* mem = hb_memory_create(0);
    CHECK(mem != NULL, "create");
    if (!mem) return;

    for (unsigned i = 0; i < N; i++)
        CHECK(hb_memory_map(mem, BASE + (hb_gva_t)i * PAGE, PAGE,
                            HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map %u", i);

    /* Cover pages 10..39 inclusive. */
    hb_result_t res = hb_memory_protect(mem, BASE + 10 * PAGE, 30 * (size_t)PAGE,
                                        HB_PERM_READ);
    CHECK(res == HB_OK, "protect res=%d", (int)res);

    for (unsigned i = 0; i < N; i++) {
        hb_region_t* r = hb_memory_find_region(mem, BASE + (hb_gva_t)i * PAGE);
        CHECK(r != NULL, "page %u vanished", i);
        if (!r) continue;
        hb_perm_t want = (i >= 10 && i < 40) ? HB_PERM_READ
                                             : (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE);
        CHECK(r->perm == want, "page %u perm=%x want=%x", i, (unsigned)r->perm,
              (unsigned)want);
    }
    digest(mem, N, "many_single_page");
    hb_memory_destroy(mem);
}

/* A range that starts and ends mid-region: the two splits must run and only the
 * requested sub-range may change. */
static void test_split_boundaries(void) {
    hb_memory_t* mem = hb_memory_create(0);
    if (!mem) return;
    CHECK(hb_memory_map(mem, BASE, 16 * PAGE, HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map");

    hb_result_t res = hb_memory_protect(mem, BASE + 4 * PAGE, 5 * (size_t)PAGE, HB_PERM_READ);
    CHECK(res == HB_OK, "protect res=%d", (int)res);

    for (unsigned i = 0; i < 16; i++) {
        hb_region_t* r = hb_memory_find_region(mem, BASE + (hb_gva_t)i * PAGE);
        CHECK(r != NULL, "page %u", i);
        if (!r) continue;
        hb_perm_t want = (i >= 4 && i < 9) ? HB_PERM_READ
                                           : (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE);
        CHECK(r->perm == want, "page %u perm=%x want=%x", i, (unsigned)r->perm,
              (unsigned)want);
    }
    digest(mem, 16, "split_boundaries");
    hb_memory_destroy(mem);
}

/* Holes: protect across a gap. Regions inside change, the hole stays absent, and
 * regions beyond the end are untouched. */
static void test_holes(void) {
    hb_memory_t* mem = hb_memory_create(0);
    if (!mem) return;
    for (unsigned i = 0; i < 20; i++) {
        if (i >= 6 && i < 10) continue; /* hole */
        CHECK(hb_memory_map(mem, BASE + (hb_gva_t)i * PAGE, PAGE,
                            HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) == HB_OK, "map %u", i);
    }
    hb_result_t res = hb_memory_protect(mem, BASE + 3 * PAGE, 11 * (size_t)PAGE, HB_PERM_READ);
    CHECK(res == HB_OK, "protect res=%d", (int)res);
    for (unsigned i = 0; i < 20; i++) {
        hb_region_t* r = hb_memory_find_region(mem, BASE + (hb_gva_t)i * PAGE);
        if (i >= 6 && i < 10) { CHECK(r == NULL, "hole page %u present", i); continue; }
        CHECK(r != NULL, "page %u", i);
        if (!r) continue;
        hb_perm_t want = (i >= 3 && i < 14)
                             ? HB_PERM_READ
                             : (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC);
        CHECK(r->perm == want, "page %u perm=%x want=%x", i, (unsigned)r->perm,
              (unsigned)want);
    }
    digest(mem, 20, "holes");
    hb_memory_destroy(mem);
}

/* Nothing mapped in range -> HB_ERR_NOT_FOUND, and nothing else disturbed. */
static void test_not_found(void) {
    hb_memory_t* mem = hb_memory_create(0);
    if (!mem) return;
    CHECK(hb_memory_map(mem, BASE, PAGE, HB_PERM_READ) == HB_OK, "map");
    hb_result_t res = hb_memory_protect(mem, BASE + 100 * PAGE, PAGE, HB_PERM_WRITE);
    CHECK(res == HB_ERR_NOT_FOUND, "expected NOT_FOUND got %d", (int)res);
    hb_region_t* r = hb_memory_find_region(mem, BASE);
    CHECK(r && r->perm == HB_PERM_READ, "untouched region changed");
    printf("not_found              res=%d\n", (int)res);
    hb_memory_destroy(mem);
}

/* Insertion order must not matter: map descending, protect, compare digest with
 * the ascending case above. This is the property the old list walk had by
 * accident and the treap walk must keep. */
static void test_descending_insert(void) {
    const unsigned N = 64;
    hb_memory_t* mem = hb_memory_create(0);
    if (!mem) return;
    for (unsigned i = N; i-- > 0;)
        CHECK(hb_memory_map(mem, BASE + (hb_gva_t)i * PAGE, PAGE,
                            HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map %u", i);
    CHECK(hb_memory_protect(mem, BASE + 10 * PAGE, 30 * (size_t)PAGE, HB_PERM_READ) == HB_OK,
          "protect");
    digest(mem, N, "descending_insert");
    hb_memory_destroy(mem);
}

int main(void) {
    test_many_single_page_regions();
    test_split_boundaries();
    test_holes();
    test_not_found();
    test_descending_insert();
    printf("failures=%d\n", failures);
    return failures ? 1 : 0;
}
