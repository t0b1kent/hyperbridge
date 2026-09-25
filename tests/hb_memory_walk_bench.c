/*
 * hb_memory_walk_bench -- cost of hb_memory_protect's multi-region path as a
 * function of the region count, for both walk arms, WITHOUT the HK title slot.
 *
 * WHY.  Three lanes share one HK slot, so "run it and see" costs hours per
 * data point.  The claim under test -- that the full-list walk in
 * hb_memory_protect is the cold-start cost -- has two factors: how long the
 * list is, and how much a node costs to visit.  This measures the second one
 * exactly and off-slot, so the HK run only has to supply the first.
 *
 * The regions here are built with hb_memory_sync_live_range, which is what makes
 * them faithful: it produces allocated=false, is_guest32=false regions, i.e. the
 * Wine-owned live views that HK's hot protect traffic actually walks.  Building
 * them with hb_memory_map instead would make every visited region issue a real
 * mprotect(2) and the syscall would swamp the traversal being measured.
 *
 * Usage: hb_memory_walk_bench [iterations]
 *        MACRUNNER_HB_MEMPROTECT_WALK=list|tree selects the arm.
 */
#include "hb_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PAGE 0x1000ULL
#define BASE 0x100000000ULL

static unsigned long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

/* Two disjoint live regions per slot, so the map has `count` regions and a
 * protect spanning several of them takes the multi-region path. */
static hb_memory_t* build(size_t count) {
    hb_memory_t* mem = hb_memory_create(0);
    if (!mem) return NULL;
    for (size_t i = 0; i < count; i++) {
        hb_gva_t base = BASE + (hb_gva_t)i * PAGE * 2;
        if (hb_memory_sync_live_range(mem, base, (size_t)PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
            fprintf(stderr, "setup failed at i=%zu\n", i);
            hb_memory_destroy(mem);
            return NULL;
        }
    }
    return mem;
}

static void bench(size_t count, unsigned iters) {
    hb_memory_t* mem = build(count);
    unsigned long long t0, t1;
    unsigned ok = 0, err = 0;

    if (!mem) return;

    /* Span 4 regions and the holes between them: wholly-contained and
     * exact-fit ranges take the early-return paths and never reach the walk. */
    t0 = now_ns();
    for (unsigned it = 0; it < iters; it++) {
        size_t i = (size_t)((it * 7919u) % (count > 8 ? count - 8 : 1));
        hb_gva_t base = BASE + (hb_gva_t)i * PAGE * 2;
        hb_perm_t p = (it & 1) ? (HB_PERM_READ) : (HB_PERM_READ | HB_PERM_WRITE);
        if (hb_memory_protect(mem, base, (size_t)(PAGE * 8), p) == HB_OK) ok++;
        else err++;
    }
    t1 = now_ns();

    printf("regions=%-7zu iters=%-8u ok=%-8u err=%-8u ns_per_protect=%8.1f  total_ms=%8.2f\n",
           count, iters, ok, err,
           (double)(t1 - t0) / (double)iters, (double)(t1 - t0) / 1e6);
    fflush(stdout);
    hb_memory_destroy(mem);
}

/*
 * Does N actually grow without bound?
 *
 * Nothing in hb_memory.c ever merges two adjacent regions -- a whole-file search
 * for merge/coalesce/adjacent returns zero hits -- while split_region_at() callocs
 * a new region on every sub-range protect.  hb_memory_protect's own comment says
 * "Mono heap realloc traffic makes this the common case".  So the prediction is
 * that a stream of sub-range protects against ONE region turns it into thousands,
 * permanently, and every O(N) path in the file degrades with it.
 *
 * This models exactly that: one large live region, then single-page protects with
 * alternating permissions so no two consecutive ones can be absorbed.
 */
static void bench_growth(unsigned iters) {
    hb_memory_t* mem = hb_memory_create(0);
    size_t pages = 16384;
    unsigned long long t0, t1;
    unsigned step;

    if (!mem) return;
    if (hb_memory_sync_live_range(mem, BASE, (size_t)(PAGE * pages),
                                  HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        fprintf(stderr, "growth setup failed\n");
        hb_memory_destroy(mem);
        return;
    }

    printf("--- region growth from sub-range protects (start: 1 region of %zu pages) ---\n", pages);
    step = iters / 8 ? iters / 8 : 1;
    t0 = now_ns();
    for (unsigned it = 1; it <= iters; it++) {
        size_t i = (size_t)((it * 7919u) % pages);
        hb_gva_t base = BASE + (hb_gva_t)i * PAGE;
        hb_perm_t p = (it & 1) ? HB_PERM_READ : (HB_PERM_READ | HB_PERM_WRITE);
        hb_memory_protect(mem, base, (size_t)PAGE, p);
        if (it % step == 0) {
            size_t n = 0;
            for (hb_region_t* r = mem->regions; r; r = r->next) n++;
            t1 = now_ns();
            printf("  protects=%-8u regions=%-8zu ns_per_protect_so_far=%8.1f\n",
                   it, n, (double)(t1 - t0) / (double)it);
            fflush(stdout);
        }
    }
    hb_memory_destroy(mem);
}

/*
 * The composite, and the one that matters.
 *
 * bench_growth() above shows single-page protects shred one region into one
 * region PER PAGE.  It also shows both arms stay flat while that happens --
 * because a sub-range protect takes the split-then-re-enter path and lands on
 * the exact-fit return, never reaching the multi-region walk.
 *
 * But the shredding changes what EVERY LATER protect means.  Once the map is
 * per-page fragments, a protect covering k pages necessarily spans k regions, so
 * it can no longer take the exact-fit path -- it falls through to the walk, and
 * the walk is now O(N) over a list that the shredding made enormous.
 *
 * That is a self-reinforcing degradation, and it is the shape a throughput cliff
 * that never recovers has to have.  This measures the steady state it lands in.
 */
static void bench_shred_then_span(unsigned shred, unsigned iters) {
    hb_memory_t* mem = hb_memory_create(0);
    size_t pages = 16384;
    unsigned long long t0, t1;
    size_t n = 0;

    if (!mem) return;
    if (hb_memory_sync_live_range(mem, BASE, (size_t)(PAGE * pages),
                                  HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
        hb_memory_destroy(mem);
        return;
    }
    for (unsigned it = 1; it <= shred; it++) {
        size_t i = (size_t)((it * 7919u) % pages);
        hb_perm_t p = (it & 1) ? HB_PERM_READ : (HB_PERM_READ | HB_PERM_WRITE);
        hb_memory_protect(mem, BASE + (hb_gva_t)i * PAGE, (size_t)PAGE, p);
    }
    for (hb_region_t* r = mem->regions; r; r = r->next) n++;

    t0 = now_ns();
    for (unsigned it = 0; it < iters; it++) {
        size_t i = (size_t)((it * 7919u) % (pages - 16));
        hb_perm_t p = (it & 1) ? HB_PERM_READ : (HB_PERM_READ | HB_PERM_WRITE);
        hb_memory_protect(mem, BASE + (hb_gva_t)i * PAGE, (size_t)(PAGE * 8), p);
    }
    t1 = now_ns();
    printf("shred=%-7u regions_after=%-8zu span8_protects=%-7u ns_per_protect=%9.1f\n",
           shred, n, iters, (double)(t1 - t0) / (double)iters);
    fflush(stdout);
    hb_memory_destroy(mem);
}

int main(int argc, char** argv) {
    unsigned iters = (argc > 1) ? (unsigned)strtoul(argv[1], NULL, 0) : 2000;
    const char* arm = getenv("MACRUNNER_HB_MEMPROTECT_WALK");

    hb_memory_init_environment();
    printf("arm=%s iters=%u\n", arm ? arm : "(default=tree)", iters);
    bench(64, iters);
    bench(256, iters);
    bench(1024, iters);
    bench(4096, iters);
    bench(16384, iters);
    bench_growth(iters * 8);
    printf("--- shred, then span 8 pages (the predicted HK steady state) ---\n");
    bench_shred_then_span(0, iters);
    bench_shred_then_span(1000, iters);
    bench_shred_then_span(4000, iters);
    bench_shred_then_span(16000, iters);
    return 0;
}
