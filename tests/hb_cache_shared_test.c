/* Deterministic proof of the process-wide translation-cache handle.
 *
 * MacRunner 2026-07-29, HK speed lane iter 7.
 *
 * hb_jit_runtime_create() (hb_runtime.c:2391) runs once per GUEST THREAD, and every one of them
 * called hb_cache_open() -> load_entries(), a full read of the whole cache file into a PRIVATE
 * copy. Measured on a Hollow Knight boot, reproduced on both arms of an independent A/B:
 *
 *     77 opens per process; cacheopen = 99.9 % of all JIT-runtime creation time; per-open cost
 *     growing 34x as the file fills (4.4 ms -> 151 ms, max 229 ms); 77 x 42 MB of duplicate blobs.
 *
 * The 128 MB MAP_JIT arena everyone assumes is the expensive part costs 0.03 % of it.
 *
 * What this pins, none of which is visible by reading one function:
 *
 *   1. OFF (default): two opens of one root are two handles. This is the control — it says the
 *      test can tell the two regimes apart, so a passing ON case is not vacuous.
 *   2. ON: two opens of one root are ONE handle, and a store through the first is IMMEDIATELY
 *      visible through the second. Under the old code it was not, unless the second handle
 *      happened to be opened after the first had already appended — which is why cross-thread
 *      reuse depended on thread start order.
 *   3. ★ REFCOUNT: closing one holder leaves the other USABLE. This is the one that matters. A
 *      naive singleton frees the shared handle on the first close and every other holder is a
 *      use-after-free — silent, and it would corrupt a different thread's translation rather
 *      than crash where the bug is.
 *   4. A DIFFERENT root in the same process still gets its own handle, so sharing keys on the
 *      file and cannot alias two caches into one.
 *   5. The reuse counters report what actually happened, so a run can PROVE it took the shared
 *      path instead of assuming it from an env var it believes it set.
 *
 * Uses a temp dir under the process pid and no host pointers in what is asserted, so it does not
 * inherit the repo suite's ASLR flakiness.
 */
#include "hb_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int failures;

static void ok(const char* what, int cond) {
    printf("  %-58s %s\n", what, cond ? "ok" : "FAIL");
    if (!cond) failures++;
}

static void make_key(hb_cache_key_t* k, uint64_t addr) {
    memset(k, 0, sizeof(*k));
    k->version = 1;
    k->abi_version = 1;
    k->arch = 1;
    k->code_hash = 0xabcdef00ull ^ addr;
    k->guest_addr = addr;
    k->code_len = 16;
}

/* Store `blob` under `addr` through `w`, then read it back through `r`. Returns 1 if `r` saw it. */
static int visible_through(hb_cache_t* w, hb_cache_t* r, uint64_t addr, const char* blob) {
    hb_cache_key_t k;
    hb_cache_entry_t* got = NULL;
    int seen;
    make_key(&k, addr);
    if (hb_cache_store(w, &k, (const uint8_t*)blob, strlen(blob) + 1, NULL) != HB_OK) return -1;
    if (hb_cache_lookup(r, &k, &got) != HB_OK || !got) return 0;
    seen = got->native_code && strcmp((const char*)got->native_code, blob) == 0;
    hb_cache_entry_free(got);
    return seen;
}

int main(void) {
    char root[256], root2[256];
    hb_cache_t *a, *b, *c;
    unsigned long long opens = 0, reuses = 0;
    int vis;

    printf("hb cache-shared test\n");
    snprintf(root, sizeof(root), "/tmp/hb-cache-shared-%d", (int)getpid());
    snprintf(root2, sizeof(root2), "/tmp/hb-cache-shared-%d-b", (int)getpid());
    mkdir(root, 0755);
    mkdir(root2, 0755);

    /* ── 1. CONTROL: sharing off -> two independent handles ─────────────────────────────── */
    unsetenv("MACRUNNER_HB_CACHE_SHARED");
    a = hb_cache_open(root, NULL);
    b = hb_cache_open(root, NULL);
    ok("OFF: two opens give two distinct handles", a && b && a != b);
    /* b was opened BEFORE the store, so under the old regime it cannot see it. That is exactly
     * the cross-thread miss this change removes. */
    vis = visible_through(a, b, 0x1000, "unshared-payload");
    ok("OFF: a store through one handle is NOT visible in the other", vis == 0);
    hb_cache_close(a);
    hb_cache_close(b);

    /* ── 2. sharing on -> one handle, stores immediately visible ─────────────────────────── */
    setenv("MACRUNNER_HB_CACHE_SHARED", "1", 1);
    snprintf(root, sizeof(root), "/tmp/hb-cache-shared-%d-on", (int)getpid());
    mkdir(root, 0755);
    a = hb_cache_open(root, NULL);
    b = hb_cache_open(root, NULL);
    ok("ON: two opens give the SAME handle", a && b && a == b);
    vis = visible_through(a, b, 0x2000, "shared-payload");
    ok("ON: a store through one handle IS visible in the other", vis == 1);

    /* ── 3. ★ the refcount: closing one holder must not free the other's handle ──────────── */
    hb_cache_close(a);
    vis = visible_through(b, b, 0x3000, "after-one-close");
    ok("ON: the surviving handle still works after one close", vis == 1);
    {
        /* And a third open must still join the SAME handle: the refcount dropped to 1, it did
         * not unpublish. */
        c = hb_cache_open(root, NULL);
        ok("ON: a later open still joins the live handle", c == b);
        hb_cache_close(c);
        vis = visible_through(b, b, 0x3100, "after-third-close");
        ok("ON: still alive after the third holder closes", vis == 1);
    }

    /* ── 4. a different root is a different cache, never aliased ─────────────────────────── */
    c = hb_cache_open(root2, NULL);
    ok("ON: a different root gets its own handle", c && c != b);
    {
        hb_cache_key_t k;
        hb_cache_entry_t* got = NULL;
        make_key(&k, 0x2000);   /* stored into `root`, must NOT appear in `root2` */
        ok("ON: the other root does not see the first root's entry",
           hb_cache_lookup(c, &k, &got) != HB_OK || got == NULL);
        if (got) hb_cache_entry_free(got);
    }
    hb_cache_close(c);

    /* ── 5. the counters must report the reuse, so a run can prove it took this path ─────── */
    hb_cache_shared_stats(&opens, &reuses);
    printf("  shared_stats: opens=%llu reuses=%llu\n", opens, reuses);
    ok("ON: at least one open was satisfied by reuse", reuses >= 1);
    ok("ON: distinct handles loaded is at least 1", opens >= 1);

    hb_cache_close(b);

    printf("%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures,
           failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
