/* V2: admission after three successful digest reverifications. Translation
 * retains the legacy digest. Admission compares that digest with the SAME byte
 * copy that will be retained; a different digest flows to normal eviction.
 * Before admission, digest collision semantics remain exactly the legacy ones.
 * A failed reservation/allocation is attempted once per cache-entry lifetime,
 * avoiding malloc/budget contention on every subsequent hot fallback. */
#define HB_SMC_EXACT_ADMIT_HITS 4u
#define HB_SMC_EXACT_ADMIT_FINISHED UINT8_MAX
static uint64_t smc_snapshot_reverify_hash(hb_jit_runtime_t* rt,
                                          hb_block_cache_entry_t* entry) {
    uint64_t now;
    size_t len = entry->smc_span_len;
    if (!smc_exact_enabled() || !smc_exact_lazy_enabled())
        return smc_hash_current(rt, entry->smc_span_start, len);
    if (entry->smc_exact_hits == HB_SMC_EXACT_ADMIT_FINISHED ||
        !len || len > 4096) {
        smc_exact_count(&g_smc_exact_lazy_fallback_hashes);
        return smc_hash_current(rt, entry->smc_span_start, len);
    }
    if (entry->smc_exact_hits < HB_SMC_EXACT_ADMIT_HITS - 1u) {
        now = smc_hash_current(rt, entry->smc_span_start, len);
        if (now && now == entry->smc_hash) ++entry->smc_exact_hits;
        smc_exact_count(&g_smc_exact_lazy_wait_hashes);
        return now;
    }

    entry->smc_exact_hits = HB_SMC_EXACT_ADMIT_FINISHED;
    smc_exact_count(&g_smc_exact_lazy_attempts);
    size_t bytes = sizeof(struct hb_smc_snapshot) + len;
    if (!smc_exact_reserve(bytes)) {
        smc_exact_count(&g_smc_exact_lazy_fallback_hashes);
        return smc_hash_current(rt, entry->smc_span_start, len);
    }
    struct hb_smc_snapshot* snapshot = malloc(bytes);
    if (!snapshot) {
        __atomic_sub_fetch(&g_smc_exact_reserved, bytes, __ATOMIC_RELAXED);
        smc_exact_count(&g_smc_exact_alloc_fallback);
        smc_exact_count(&g_smc_exact_lazy_fallback_hashes);
        return smc_hash_current(rt, entry->smc_span_start, len);
    }
    const uint8_t* current = smc_bytes_current(rt, entry->smc_span_start, len);
    if (!current) {
        free(snapshot);
        __atomic_sub_fetch(&g_smc_exact_reserved, bytes, __ATOMIC_RELAXED);
        smc_exact_count(&g_smc_exact_lazy_unreadable);
        return 0;
    }
    snapshot->len = len;
    memcpy(snapshot->bytes, current, len);
    now = smc_fnv1a(snapshot->bytes, len);
    if (now != entry->smc_hash) {
        free(snapshot);
        __atomic_sub_fetch(&g_smc_exact_reserved, bytes, __ATOMIC_RELAXED);
        smc_exact_count(&g_smc_exact_lazy_changed);
        return now; /* caller must evict; never attach changed bytes */
    }
    entry->smc_snapshot = snapshot;
    smc_exact_count(&g_smc_exact_attached);
    smc_exact_count(&g_smc_exact_lazy_admitted);
    return now;
}
