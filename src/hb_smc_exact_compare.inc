/* Uses precisely the existing readability/direct-pointer/nofault-read policy.
 * Capture happens at existing SMC tracking time, not before IR decoding; this
 * proposal deliberately does not claim to fix that pre-existing capture race. */
static uint64_t smc_snapshot_capture(hb_jit_runtime_t* rt, hb_block_cache_entry_t* entry,
                                     uint64_t start, size_t len) {
    if (!smc_exact_enabled() || smc_exact_lazy_enabled() || !entry || !len || len > 4096)
        return smc_hash_current(rt, start, len);
    size_t bytes = sizeof(struct hb_smc_snapshot) + len;
    if (!smc_exact_reserve(bytes)) return smc_hash_current(rt, start, len);
    struct hb_smc_snapshot* snapshot = malloc(bytes);
    if (!snapshot) {
        __atomic_sub_fetch(&g_smc_exact_reserved, bytes, __ATOMIC_RELAXED);
        smc_exact_count(&g_smc_exact_alloc_fallback);
        return smc_hash_current(rt, start, len);
    }
    const uint8_t* current = smc_bytes_current(rt, start, len);
    if (!current) {
        free(snapshot);
        __atomic_sub_fetch(&g_smc_exact_reserved, bytes, __ATOMIC_RELAXED);
        return 0;
    }
    snapshot->len = len;
    memcpy(snapshot->bytes, current, len);
    /* Both retained bytes and compatibility digest describe this SAME copy. */
    uint64_t hash = smc_fnv1a(snapshot->bytes, len);
    entry->smc_snapshot = snapshot;
    smc_exact_count(&g_smc_exact_attached);
    return hash;
}

/* 1 exact equality; 0 changed; -1 unreadable under the legacy policy.
 * On inequality the digest is DIAGNOSTIC ONLY: even a digest collision evicts. */
static int smc_snapshot_compare(hb_jit_runtime_t* rt, const hb_block_cache_entry_t* entry,
                                uint64_t* changed_hash) {
    if (!entry || !entry->smc_snapshot || !changed_hash ||
        entry->smc_snapshot->len != entry->smc_span_len) return -1;
    const uint8_t* current = smc_bytes_current(rt, entry->smc_span_start, entry->smc_span_len);
    if (!current) {
        smc_exact_count(&g_smc_exact_unreadable);
        return -1;
    }
    if (memcmp(entry->smc_snapshot->bytes, current, entry->smc_span_len) == 0) {
        smc_exact_count(&g_smc_exact_equal);
        return 1;
    }
    *changed_hash = smc_fnv1a(current, entry->smc_span_len);
    smc_exact_count(&g_smc_exact_changed);
    return 0;
}
