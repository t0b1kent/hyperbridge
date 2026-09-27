/* Cold admission/publication/rejection only; native acceptance is inline. */
#define HB_NATIVE_ENTRY_MAX_SPAN HB_CODE_WITNESS_MAX_SPAN
#define HB_NATIVE_ENTRY_BUDGET (UINT64_C(64) * 1024u * 1024u)
static uint64_t g_native_entry_reserved;
static uint64_t g_inval_seq;
static hb_result_t native_entry_reset_checked(hb_jit_runtime_t *rt, hb_context_t *ctx, int place);
static int native_entry_enabled(void) {
    static int cache = -1;
    return smc_exact_cached_flag(&cache, "MACRUNNER_HB_CODE_WITNESS_ENTRY");
}
static bool native_entry_context_eligible(hb_jit_runtime_t *rt) {
#if defined(__APPLE__) && defined(__aarch64__)
    hb_context_t *c = rt ? rt->ctx : NULL;
    return c && c->memory && c->arch == HB_ARCH_X64 && c->mode == HB_MODE_64BIT &&
           !c->exec_access && !hb_smc_protect_enabled() && rt->native_entry_query &&
           rt->native_entry_callback_contract && rt->native_entry_owner_thread == (uintptr_t)pthread_self();
#else
    (void)rt; return false;
#endif
}
static bool native_entry_reserve(size_t bytes) {
    uint64_t old = __atomic_load_n(&g_native_entry_reserved, __ATOMIC_RELAXED);
    do {
        if (bytes > HB_NATIVE_ENTRY_BUDGET || old > HB_NATIVE_ENTRY_BUDGET - bytes) return false;
    } while (!__atomic_compare_exchange_n(&g_native_entry_reserved, &old, old + bytes,
                                          true, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    return true;
}
static bool native_entry_source_covers_block(const hb_ir_block_t *b, uint64_t start, size_t len) {
    if (!b || (b->instr_count && !b->instrs)) return false;
    for (size_t n = 0; n < b->instr_count; ++n) {
        const hb_ir_instr_t *i = &b->instrs[n];
        if (!i->guest_len || i->guest_addr < start || i->guest_addr - start >= len ||
            i->guest_len > len - (size_t)(i->guest_addr - start)) return false;
    }
    return true;
}
/* Cold pointer validation has no guest-memory callback or fault-packet effects.
 * The producer still owns the future readable lifetime of the returned slot. */
static bool native_entry_copy_page(const hb_code_page_witness_v1 *p, hb_code_page_witness_v1 *out) {
#if defined(__APPLE__) && defined(__aarch64__)
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(uintptr_t)p,
        sizeof(*out), (mach_vm_address_t)(uintptr_t)out, &copied) == KERN_SUCCESS && copied == sizeof(*out);
#else
    (void)p; (void)out; return false;
#endif
}
static bool native_entry_span_valid(const hb_code_span_witness_v1 *s, uint64_t start, size_t len) {
    if (s->size != sizeof(*s) || s->version != HB_CODE_WITNESS_VERSION || s->reserved ||
        s->guest_start != start || s->guest_len != len || !len || len > HB_CODE_WITNESS_MAX_SPAN ||
        len > UINT64_MAX - start) return false;
    uint64_t first = start & ~UINT64_C(4095), last = (start + len - 1) & ~UINT64_C(4095);
    unsigned count = first == last ? 1u : 2u;
    if (s->page_count != count || (count == 1 && (s->pages[1] || s->expected[1]))) return false;
    for (unsigned n = 0; n < count; ++n) {
        hb_code_page_witness_v1 page;
        uintptr_t ptr = (uintptr_t)s->pages[n]; uint64_t expected = s->expected[n];
        if (!ptr || (ptr & 7u) || ptr > UINTPTR_MAX - sizeof(page) ||
            !(expected >> HB_CW_GENERATION_SHIFT) ||
            (expected & HB_CW_FLAG_MASK & ~HB_CW_KNOWN_FLAGS) ||
            (expected & HB_CW_READ_REQUIRED) != HB_CW_READ_REQUIRED ||
            (expected & HB_CW_READ_FORBIDDEN) || !native_entry_copy_page(s->pages[n], &page) ||
            page.size != sizeof(page) || page.version != HB_CODE_WITNESS_VERSION || page.reserved ||
            page.guest_page != first + n * UINT64_C(4096) || page.state != expected) return false;
    }
    return true;
}
static hb_native_entry_descriptor_t *native_entry_prepare(hb_jit_runtime_t *rt,
        const hb_ir_block_t *block, const hb_ir_func_t *func) {
    if (!native_entry_enabled()) return NULL;
    if (!native_entry_context_eligible(rt) || !block || !func || !func->decoded_source) goto refused;
    uint64_t start = func->guest_addr; size_t len = func->decoded_source_len;
    /* guest_len is NOT a cap: zero-IR instructions still consume source bytes. */
    if (!len || len > HB_NATIVE_ENTRY_MAX_SPAN || len > UINT64_MAX - start ||
        block->guest_addr < start || block->guest_addr >= start + len || block->guest_addr != rt->ctx->pc ||
        !native_entry_source_covers_block(block, start, len) || !func->cfg || !func->cfg->blocks ||
        func->cfg->block_count > func->cfg->block_cap) goto refused;
    for (size_t n = 0; n < func->cfg->block_count; ++n)
        if (!native_entry_source_covers_block(func->cfg->blocks[n], start, len)) goto refused;
    hb_code_span_witness_v1 span = {.size = sizeof(span), .version = HB_CODE_WITNESS_VERSION};
    if (rt->native_entry_query(rt->native_entry_query_opaque, start, len, &span) != 1 ||
        !native_entry_span_valid(&span, start, len)) goto refused;
    size_t bytes = sizeof(hb_native_entry_descriptor_t) + len;
    if (!native_entry_reserve(bytes)) { ++rt->native_entry_budget_fallback; goto refused; }
    hb_native_entry_descriptor_t *d = calloc(1, bytes);
    if (!d) {
        __atomic_sub_fetch(&g_native_entry_reserved, bytes, __ATOMIC_RELAXED);
        ++rt->native_entry_budget_fallback; goto refused;
    }
    memcpy(d->bytes, func->decoded_source, len);
    d->owner = rt; d->memory = rt->ctx->memory; d->guest_pc = block->guest_addr;
    d->span_start = start; d->span_len = len; d->allocation_size = bytes; d->page_count = span.page_count;
    memcpy(d->pages, span.pages, sizeof(d->pages)); memcpy(d->expected, span.expected, sizeof(d->expected));
    d->invalidation_current = &g_inval_seq; d->invalidation_seen = &rt->inval_seen; d->context_slot = &rt->ctx;
    d->next = rt->native_entry_descriptors; rt->native_entry_descriptors = d;
    ++rt->native_entry_prepared; return d;
refused:
    if (rt) ++rt->native_entry_ineligible;
    return NULL;
}
static void native_entry_revoke(hb_block_cache_entry_t *entry) {
    if (!entry || !entry->native_entry_desc) return;
    __atomic_store_n(&entry->native_entry_desc->live, 0, __ATOMIC_RELEASE);
    entry->native_entry_desc = NULL;
}
static bool native_entry_code_valid(const hb_codegen_buffer_t *code) {
    static const uint32_t frame[4] = {0xa9bd53f3u, 0xa9015bf5u, 0xa9027bf7u, 0xaa0003f3u};
    if (!code || !code->native_entry_desc) return true;
    const hb_native_entry_descriptor_t *d = code->native_entry_desc;
    size_t end = code->native_entry_guard_continue_off;
    if (!code->native_entry_guard_emitted || code->native_entry_guard_off != 16 || !code->code ||
        end < 20 || end > code->size || code->native_entry_guard_call_off + 44 != end ||
        !d->load_count || d->load_count > HB_NATIVE_ENTRY_MAX_LOAD_SITES ||
        memcmp(code->code, frame, sizeof(frame))) return false;
    uint64_t h = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < end; ++i) h = (h ^ code->code[i]) * UINT64_C(1099511628211);
    if (h != d->emitted_hash) return false;
    for (unsigned i = 0; i < d->load_count; ++i) {
        uint32_t word, width = d->load_widths[i]; size_t off = d->load_offsets[i];
        if ((off & 3u) || off < 16 || off + 4 > code->native_entry_guard_call_off) return false;
        memcpy(&word, code->code + off, 4);
        uint32_t expected = width == 16 ? 0x3dc00180u : width == 8 ? 0xf9400189u :
                            width == 4 ? 0xb9400189u : width == 2 ? 0x79400189u :
                            width == 1 ? 0x39400189u : 0;
        if (!expected || word != expected) return false;
    }
    return true;
}
static void native_entry_bind(hb_block_cache_entry_t *entry, const hb_codegen_buffer_t *code) {
    if (!entry || !code || !code->native_entry_desc || !native_entry_code_valid(code)) return;
    hb_native_entry_descriptor_t *d = (hb_native_entry_descriptor_t *)code->native_entry_desc;
    d->native_start = (uintptr_t)entry->native_code; d->native_size = entry->native_size;
    d->prefix_size = code->native_entry_guard_continue_off;
    entry->native_entry_desc = d; ++((hb_jit_runtime_t *)d->owner)->native_entry_published;
    __atomic_store_n(&d->live, 1, __ATOMIC_RELEASE);
}
static void native_entry_destroy(hb_jit_runtime_t *rt) {
    hb_native_entry_descriptor_t *d = rt->native_entry_descriptors;
    while (d) {
        hb_native_entry_descriptor_t *next = d->next; size_t bytes = d->allocation_size; free(d);
        __atomic_sub_fetch(&g_native_entry_reserved, bytes, __ATOMIC_RELAXED); d = next;
    }
    rt->native_entry_descriptors = NULL;
}
/* Cold reject defers eviction until native unwind. No reclamation or callback. */
int hb_native_entry_guard(hb_context_t *ctx, const hb_native_entry_descriptor_t *d, uint32_t reason) {
    hb_jit_runtime_t *rt = d ? d->owner : NULL;
    if (!rt || !ctx) return 1;
    ++rt->native_entry_rejects;
    if (reason == HB_CODE_WITNESS_REJECT_BYTES) ++rt->native_entry_changed;
    else if (reason == HB_CODE_WITNESS_REJECT_VALIDATION_FAULT) ++rt->native_entry_unreadable;
    else ++rt->native_entry_revoked;
    rt->native_entry_rejected = true; rt->native_entry_reject_pc = d->guest_pc;
    rt->native_entry_reject_reason = reason; ctx->pc = d->guest_pc; ctx->regs.x64.rip = d->guest_pc;
    return 1;
}
hb_result_t hb_jit_runtime_set_code_witness_v1(hb_jit_runtime_t *rt,
        hb_code_witness_query_cb query, void *opaque, bool contract) {
    if (!rt || rt->native_entry_run_depth ||
        (rt->native_entry_owner_thread && rt->native_entry_owner_thread != (uintptr_t)pthread_self()))
        return HB_ERR_INVALID_ARG;
    if (!query) { opaque = NULL; contract = false; }
    if (rt->native_entry_query == query && rt->native_entry_query_opaque == opaque &&
        rt->native_entry_callback_contract == contract) return HB_OK;
    hb_result_t reset = native_entry_reset_checked(rt, rt->ctx, HB_POVTOR_M_PROCHEE);
    if (reset != HB_OK) return reset;
    rt->native_entry_query = query; rt->native_entry_query_opaque = opaque;
    rt->native_entry_callback_contract = contract; rt->native_entry_owner_thread = (uintptr_t)pthread_self();
    return HB_OK;
}
int hb_jit_runtime_get_code_witness_stats_v1(const hb_jit_runtime_t *rt, hb_code_witness_stats_v1_t *out) {
    if (!rt || !out || out->size != sizeof(*out) || out->version != HB_CODE_WITNESS_VERSION ||
        rt->native_entry_run_depth ||
        (rt->native_entry_owner_thread && rt->native_entry_owner_thread != (uintptr_t)pthread_self())) return 0;
    hb_code_witness_stats_v1_t v = {.size = sizeof(v), .version = HB_CODE_WITNESS_VERSION};
    v.prepared = rt->native_entry_prepared; v.published = rt->native_entry_published;
    v.query_refused = rt->native_entry_ineligible; v.rejected_state = rt->native_entry_revoked;
    v.rejected_bytes = rt->native_entry_changed; v.rejected_validation_fault = rt->native_entry_unreadable;
    v.fresh_fetch_returns = rt->native_entry_fresh_fetch_returns;
    v.last_reject_guest_pc = rt->native_entry_reject_pc; v.last_reject_reason = rt->native_entry_reject_reason;
    *out = v; return 1;
}

/* Signal-safe metadata lookup. Owner-thread execution excludes descriptor
 * publication/reclamation while native code is running. No arbitrary host
 * address is read, and retired entries are retained until quiescent reset. */
static const hb_native_entry_descriptor_t *native_entry_prefix_at(
        const hb_jit_runtime_t *rt, uint64_t pc, unsigned *width) {
    if (width) *width = 0;
    for (const hb_native_entry_descriptor_t *d = rt->native_entry_descriptors; d; d = d->next) {
        if (!d->native_start || pc < d->native_start || pc - d->native_start >= d->prefix_size) continue;
        size_t off = (size_t)(pc - d->native_start);
        for (unsigned n = 0; n < d->load_count; ++n)
            if (off == d->load_offsets[n] && width) *width = d->load_widths[n];
        return d;
    }
    return NULL;
}
