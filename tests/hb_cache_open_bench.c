/* What does a WARM start actually pay to open the translation cache 77 times?
 *
 * MacRunner 2026-07-29, HK speed lane iter 7.
 *
 * hb_jit_runtime_create() opens the persistent cache once per guest thread. On a Hollow Knight
 * boot that is 77 opens, and `macrunner-hb-rtmeter` measured cacheopen at 99.9 % of all
 * runtime-creation cost, growing 4.4 ms -> 151 ms as the file filled (max 229 ms), 3.67 s total.
 *
 * A COLD run pays that against a file growing from empty. A WARM run opens a FULL file every
 * time, from the first runtime. That is the number this bench produces, and it needs no game
 * and no run slot -- point it at a real populated cache and it measures the mechanism directly.
 *
 * Usage:  hb_cache_open_bench <cache-root> [opens]        (default opens = 77, HK's count)
 *
 * Reports both regimes back to back on the same file, so the comparison controls for page cache
 * state: the UNSHARED arm runs first and warms the page cache, which biases the result AGAINST
 * the shared arm. If shared still wins, it is not a page-cache artefact.
 */
#include "hb_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

/* Open `n` times, keeping every handle live -- which is what the runtime does: 77 JIT runtimes
 * coexist, they are not opened and closed in sequence. Closing as we went would understate the
 * unshared arm's memory and let the allocator reuse blocks. */
static double run_arm(const char* root, int n, int shared, size_t* peak_entries) {
    hb_cache_t** h = calloc((size_t)n, sizeof(*h));
    double t0, t1;
    int i, opened = 0;
    if (!h) return -1;
    if (shared) setenv("MACRUNNER_HB_CACHE_SHARED", "1", 1);
    else unsetenv("MACRUNNER_HB_CACHE_SHARED");

    t0 = now_ms();
    for (i = 0; i < n; i++) {
        h[i] = hb_cache_open(root, NULL);
        if (h[i]) opened++;
    }
    t1 = now_ms();

    if (peak_entries) {
        hb_cache_stats_t s;
        *peak_entries = (h[0] && hb_cache_stats(h[0], &s) == HB_OK) ? (size_t)s.entries_current : 0;
    }
    for (i = 0; i < n; i++) if (h[i]) hb_cache_close(h[i]);
    free(h);
    if (opened != n) fprintf(stderr, "  WARN: only %d/%d opens succeeded\n", opened, n);
    return t1 - t0;
}

int main(int argc, char** argv) {
    const char* root = argc > 1 ? argv[1] : NULL;
    int n = argc > 2 ? atoi(argv[2]) : 77;
    double unshared, shared;
    size_t entries = 0, entries2 = 0;

    if (!root) {
        printf("usage: hb_cache_open_bench <cache-root> [opens]\n");
        return 2;
    }
    if (n < 1) n = 1;
    printf("hb cache-open bench: root=%s opens=%d\n", root, n);

    /* Unshared FIRST, so it -- not the shared arm -- gets the cold page cache penalty. */
    unshared = run_arm(root, n, 0, &entries);
    printf("  UNSHARED : %8.1f ms total   %7.2f ms/open   entries=%zu\n",
           unshared, unshared / n, entries);

    shared = run_arm(root, n, 1, &entries2);
    printf("  SHARED   : %8.1f ms total   %7.2f ms/open   entries=%zu\n",
           shared, shared / n, entries2);

    if (entries != entries2)
        printf("  ⚠ entry counts differ (%zu vs %zu) — the two arms did not read the same cache\n",
               entries, entries2);
    if (entries == 0)
        printf("  ⚠ EMPTY CACHE — this measures nothing. Point it at a populated root.\n");
    printf("  saved    : %8.1f ms  (%.1fx)\n", unshared - shared,
           shared > 0 ? unshared / shared : 0.0);
    return 0;
}
