/* Proposal: runtime-private ownership; included after hb_block_cache_entry_t.
 * The budget covers allocated snapshot header+bytes, not malloc implementation
 * overhead or the cache entry's pointer. No snapshot is shared between entries. */
struct hb_smc_snapshot {
    size_t len;
    uint8_t bytes[];
};
#ifndef HB_SMC_EXACT_BUDGET_BYTES
#define HB_SMC_EXACT_BUDGET_BYTES (UINT64_C(64) * 1024u * 1024u)
#endif
static uint64_t g_smc_exact_reserved, g_smc_exact_peak;
static uint64_t g_smc_exact_budget_fallback, g_smc_exact_alloc_fallback;
static uint64_t g_smc_exact_attached, g_smc_exact_released;
static uint64_t g_smc_exact_equal, g_smc_exact_changed, g_smc_exact_unreadable;
static uint64_t g_smc_exact_lazy_attempts, g_smc_exact_lazy_admitted;
static uint64_t g_smc_exact_lazy_changed, g_smc_exact_lazy_unreadable;
static uint64_t g_smc_exact_lazy_wait_hashes, g_smc_exact_lazy_fallback_hashes;
static uint64_t g_smc_exact_destroy_reports;

static int smc_exact_cached_flag(int* cache, const char* name) {
    int value = __atomic_load_n(cache, __ATOMIC_RELAXED);
    if (value < 0) {
        int expected = -1;
        value = hb_env_flag(name, 0);
        if (!__atomic_compare_exchange_n(cache, &expected, value, false,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED)) value = expected;
    }
    return value;
}

static int smc_exact_enabled(void) {
    static int cache = -1;
    return smc_exact_cached_flag(&cache, "MACRUNNER_HB_SMC_EXACT_BYTES");
}

/* Independent selector: EXACT_BYTES=0 always retains the old path. */
static int smc_exact_lazy_enabled(void) {
    static int cache = -1;
    return smc_exact_cached_flag(&cache, "MACRUNNER_HB_SMC_EXACT_LAZY");
}

static int smc_exact_stats_enabled(void) {
    static int cache = -1;
    return smc_exact_cached_flag(&cache, "MACRUNNER_HB_SMC_EXACT_STATS");
}

static void smc_exact_count(uint64_t* counter) {
    if (smc_exact_stats_enabled()) __atomic_add_fetch(counter, 1, __ATOMIC_RELAXED);
}

static void smc_exact_report(void) {
    if (!smc_exact_stats_enabled()) return;
    fprintf(stderr, "macrunner-hb-smc-exact: reserved=%llu peak=%llu budget=%llu "
            "attached=%llu released=%llu equal=%llu changed=%llu unreadable=%llu "
            "budget_fallback=%llu alloc_fallback=%llu exact=%d lazy=%d "
            "lazy_attempts=%llu lazy_admitted=%llu lazy_changed=%llu lazy_unreadable=%llu "
            "lazy_wait_hashes=%llu lazy_fallback_hashes=%llu\n",
            (unsigned long long)__atomic_load_n(&g_smc_exact_reserved, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_peak, __ATOMIC_RELAXED),
            (unsigned long long)HB_SMC_EXACT_BUDGET_BYTES,
            (unsigned long long)__atomic_load_n(&g_smc_exact_attached, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_released, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_equal, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_changed, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_unreadable, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_budget_fallback, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_alloc_fallback, __ATOMIC_RELAXED),
            smc_exact_enabled(), smc_exact_lazy_enabled(),
            (unsigned long long)__atomic_load_n(&g_smc_exact_lazy_attempts, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_lazy_admitted, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_lazy_changed, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_lazy_unreadable, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_lazy_wait_hashes, __ATOMIC_RELAXED),
            (unsigned long long)__atomic_load_n(&g_smc_exact_lazy_fallback_hashes, __ATOMIC_RELAXED));
}

static void smc_exact_register_report(void) { (void)atexit(smc_exact_report); }
static pthread_once_t g_smc_exact_report_once = PTHREAD_ONCE_INIT;

static bool smc_exact_reserve(size_t bytes) {
    uint64_t current = __atomic_load_n(&g_smc_exact_reserved, __ATOMIC_RELAXED);
    if (smc_exact_stats_enabled()) pthread_once(&g_smc_exact_report_once, smc_exact_register_report);
    for (;;) {
        if (bytes > HB_SMC_EXACT_BUDGET_BYTES || current > HB_SMC_EXACT_BUDGET_BYTES - bytes) {
            smc_exact_count(&g_smc_exact_budget_fallback);
            return false;
        }
        if (__atomic_compare_exchange_n(&g_smc_exact_reserved, &current, current + bytes,
                                         false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) break;
    }
    if (smc_exact_stats_enabled()) {
        uint64_t peak = __atomic_load_n(&g_smc_exact_peak, __ATOMIC_RELAXED);
        while (peak < current + bytes &&
               !__atomic_compare_exchange_n(&g_smc_exact_peak, &peak, current + bytes,
                                             false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
    }
    return true;
}

static void smc_snapshot_release(hb_block_cache_entry_t* entry) {
    if (!entry || !entry->smc_snapshot) return;
    struct hb_smc_snapshot* snapshot = entry->smc_snapshot;
    size_t bytes = sizeof(*snapshot) + snapshot->len;
    entry->smc_snapshot = NULL;
    free(snapshot);
    __atomic_sub_fetch(&g_smc_exact_reserved, bytes, __ATOMIC_RELAXED);
    smc_exact_count(&g_smc_exact_released);
}

/* Existing destruction boundary; avoids relying only on atexit during Wine
 * shutdown. One record after this runtime's owners are released; process-wide
 * counts can still include other live runtimes. First eight and powers of two. */
static void smc_exact_report_destroy(void) {
    if (!smc_exact_stats_enabled()) return;
    uint64_t n = __atomic_add_fetch(&g_smc_exact_destroy_reports, 1, __ATOMIC_RELAXED);
    if (n <= 8 || (n & (n - 1)) == 0) {
        fprintf(stderr, "macrunner-hb-smc-exact-destroy: n=%llu\n", (unsigned long long)n);
        smc_exact_report();
        fflush(stderr);
    }
}
