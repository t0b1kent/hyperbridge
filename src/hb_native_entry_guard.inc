/* Experimental full-byte native entry guard. No imported implementation.
 * Metadata remains allocated until runtime destruction, even after revocation.
 * This deliberately trades bounded memory for a simple stale-entry lifetime. */
struct hb_native_entry_descriptor {
    struct hb_native_entry_descriptor* next;
    hb_jit_runtime_t* owner;
    hb_memory_t* memory;
    uint64_t guest_pc, span_start;
    size_t span_len, allocation_size;
    uint32_t live; /* sole mutable descriptor field; release/acquire revocation */
    uint8_t bytes[];
};

#define HB_NATIVE_ENTRY_MAX_SPAN 4096u
#ifndef HB_NATIVE_ENTRY_BUDGET
#define HB_NATIVE_ENTRY_BUDGET (UINT64_C(64) * 1024u * 1024u)
#endif
static uint64_t g_native_entry_reserved;
static bool native_entry_pending_invalidation(hb_jit_runtime_t* rt);

static int native_entry_enabled(void) {
    static int cache = -1;
    return smc_exact_cached_flag(&cache, "MACRUNNER_HB_NATIVE_ENTRY_GUARD");
}

static bool native_entry_context_eligible(hb_jit_runtime_t* rt) {
#if defined(__APPLE__) && defined(__aarch64__)
    hb_context_t* c = rt ? rt->ctx : NULL;
    hb_memory_t* m = c ? c->memory : NULL;
    if (!c || !m || c->arch != HB_ARCH_X64 || c->mode != HB_MODE_64BIT || c->exec_access)
        return false;
    if (hb_smc_protect_enabled()) return false; /* unsafe experimental lease is not used */
    if (!rt->native_entry_callback_contract &&
        (c->scalar_access || c->pair_access || m->special_read || m->special_write || m->special_grow))
        return false;
    return true;
#else
    (void)rt;
    return false; /* non-Apple nofault reader can invoke user callbacks */
#endif
}

hb_result_t hb_native_entry_set_callback_contract(hb_jit_runtime_t* rt, bool no_local_lifetime_mutation) {
    if (!rt || rt->native_entry_run_depth) return HB_ERR_INVALID_ARG;
    rt->native_entry_callback_contract = no_local_lifetime_mutation;
    return HB_OK;
}

static bool native_entry_reserve(size_t bytes) {
    uint64_t old = __atomic_load_n(&g_native_entry_reserved, __ATOMIC_RELAXED);
    do {
        if (bytes > HB_NATIVE_ENTRY_BUDGET || old > HB_NATIVE_ENTRY_BUDGET - bytes) return false;
    } while (!__atomic_compare_exchange_n(&g_native_entry_reserved, &old, old + bytes,
                                          true, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    return true;
}

static bool native_entry_source_covers_block(const hb_ir_block_t* block,
                                             uint64_t start, size_t len) {
    if (!block || (block->instr_count && !block->instrs)) return false;
    for (size_t n = 0; n < block->instr_count; ++n) {
        const hb_ir_instr_t* i = &block->instrs[n];
        if (!i->guest_len || i->guest_addr < start || i->guest_addr - start >= len ||
            i->guest_len > len - (size_t)(i->guest_addr - start)) return false;
    }
    return true;
}

static hb_native_entry_descriptor_t* native_entry_prepare(hb_jit_runtime_t* rt,
                                                         const hb_ir_block_t* block,
                                                         const hb_ir_func_t* func) {
    uint64_t start = 0;
    size_t len = 0, bytes;
    hb_native_entry_descriptor_t* d;
    if (!native_entry_enabled()) return NULL;
    if (!native_entry_context_eligible(rt) || !block || !func || !func->decoded_source) {
        if (rt) ++rt->native_entry_ineligible;
        return NULL;
    }
    /* The lifter froze its decoder input before decoding. Preserve that exact
     * consumed prefix, including zero-IR instructions and merged CFG blocks.
     * A fresh post-decode guest read would not be a valid witness for old IR. */
    start = func->guest_addr;
    len = func->decoded_source_len;
    if (!len || len > HB_NATIVE_ENTRY_MAX_SPAN || len > func->guest_len ||
        len > UINT64_MAX - start || block->guest_addr < start || block->guest_addr >= start + len ||
        block->guest_addr != rt->ctx->pc || !native_entry_source_covers_block(block, start, len)) {
        ++rt->native_entry_ineligible;
        return NULL;
    }
    /* Codegen may follow merged/fallthrough CFG dependencies. Unknown provenance
     * in any available CFG block prevents guarded admission; empty IR blocks are
     * covered by the lifter's consumed-byte prefix rather than a guessed length. */
    if (!func->cfg || !func->cfg->blocks || func->cfg->block_count > func->cfg->block_cap) {
        ++rt->native_entry_ineligible;
        return NULL;
    }
    for (size_t n = 0; n < func->cfg->block_count; ++n)
        if (!native_entry_source_covers_block(func->cfg->blocks[n], start, len)) {
            ++rt->native_entry_ineligible;
            return NULL;
        }
    bytes = sizeof(*d) + len;
    if (!native_entry_reserve(bytes)) {
        ++rt->native_entry_budget_fallback;
        return NULL;
    }
    d = malloc(bytes);
    if (!d) {
        __atomic_sub_fetch(&g_native_entry_reserved, bytes, __ATOMIC_RELAXED);
        ++rt->native_entry_budget_fallback;
        return NULL;
    }
    memcpy(d->bytes, func->decoded_source, len);
    d->owner = rt;
    d->memory = rt->ctx->memory;
    d->guest_pc = block->guest_addr;
    d->span_start = start;
    d->span_len = len;
    d->allocation_size = bytes;
    d->live = 0; /* no entry can execute before code and map publication */
    d->next = rt->native_entry_descriptors;
    rt->native_entry_descriptors = d;
    ++rt->native_entry_prepared;
    return d;
}

static void native_entry_revoke(hb_block_cache_entry_t* entry) {
    if (!entry || !entry->native_entry_desc) return;
    __atomic_store_n(&entry->native_entry_desc->live, 0, __ATOMIC_RELEASE);
    entry->native_entry_desc = NULL;
}

static bool native_entry_code_valid(const hb_codegen_buffer_t* code) {
    static const uint32_t frame[4] = {0xa9bd53f3u, 0xa9015bf5u, 0xa9027bf7u, 0xaa0003f3u};
    static const uint32_t lead[6] = {0xd53b4211u, 0xd53b440fu, 0xd53b442eu,
                                   0xa9be7bf1u, 0xa9013befu, 0xaa1303e0u};
    static const uint32_t tail[12] = {0xd63f0200u, 0xa9413befu, 0xa8c27bf1u,
        0xd51b440fu, 0xd51b442eu, 0xd51b4211u, 0x340000a0u, 0xa9427bf7u,
        0xa9415bf5u, 0xa8c353f3u, 0xd65f03c0u, 0xaa1303e0u};
    uint32_t pointers[8];
    uint64_t values[2];
    size_t call;
    if (!code || !code->native_entry_desc) return true;
    call = code->native_entry_guard_call_off;
    if (!code->native_entry_guard_emitted || code->native_entry_guard_off != 16 ||
        !code->code || call != 72 ||
        call > code->size || sizeof(tail) > code->size - call ||
        code->native_entry_guard_continue_off != call + sizeof(tail)) return false;
    values[0] = (uint64_t)(uintptr_t)code->native_entry_desc;
    values[1] = (uint64_t)(uintptr_t)hb_native_entry_guard;
    for (unsigned p = 0; p < 2; ++p)
        for (unsigned word = 0; word < 4; ++word)
            pointers[p * 4 + word] = (word ? 0xf2800000u | (word << 21) : 0xd2800000u) |
                ((uint32_t)((values[p] >> (word * 16)) & 0xffffu) << 5) | (p ? 16u : 1u);
    return memcmp(code->code, frame, sizeof(frame)) == 0 &&
           memcmp(code->code + 16, lead, sizeof(lead)) == 0 &&
           memcmp(code->code + 40, pointers, sizeof(pointers)) == 0 &&
           memcmp(code->code + call, tail, sizeof(tail)) == 0;
}

static void native_entry_bind(hb_block_cache_entry_t* entry, const hb_codegen_buffer_t* code) {
    if (!entry || !code || !code->native_entry_desc) return;
    hb_native_entry_descriptor_t* d = (hb_native_entry_descriptor_t*)code->native_entry_desc;
    /* Guard must be the first instruction at every +16 chained entry. */
    if (!native_entry_code_valid(code)) return;
    entry->native_entry_desc = d;
    __atomic_store_n(&d->live, 1, __ATOMIC_RELEASE);
}

static void native_entry_destroy(hb_jit_runtime_t* rt) {
    hb_native_entry_descriptor_t* d = rt->native_entry_descriptors;
    while (d) {
        hb_native_entry_descriptor_t* next = d->next;
        size_t bytes = d->allocation_size;
        free(d);
        __atomic_sub_fetch(&g_native_entry_reserved, bytes, __ATOMIC_RELAXED);
        d = next;
    }
    rt->native_entry_descriptors = NULL;
}

int hb_native_entry_guard(hb_context_t* ctx, const hb_native_entry_descriptor_t* d) {
    uint8_t current[HB_NATIVE_ENTRY_MAX_SPAN];
    hb_jit_runtime_t* rt;
    if (!d || !(rt = d->owner) || !ctx) return 1;
    if (!__atomic_load_n(&d->live, __ATOMIC_ACQUIRE)) {
        ++rt->native_entry_revoked;
        goto reject;
    }
    if (rt->ctx != ctx || ctx->memory != d->memory || !native_entry_context_eligible(rt)) {
        ++rt->native_entry_ineligible;
        goto reject;
    }
    if (native_entry_pending_invalidation(rt)) {
        ++rt->native_entry_revoked;
        goto reject;
    }
    /* Fixed-region-table contract is required: the existing API does not give a
     * reader borrow for concurrent split/unmap. Within that contract it checks
     * the full readable span and copies without callbacks or guest fault escape. */
    if (hb_memory_read_nofault(d->memory, d->span_start, current, d->span_len) != HB_OK) {
        ++rt->native_entry_unreadable;
        goto reject;
    }
    if (memcmp(current, d->bytes, d->span_len) != 0) {
        ++rt->native_entry_changed;
        goto reject;
    }
    if (!__atomic_load_n(&d->live, __ATOMIC_ACQUIRE) || native_entry_pending_invalidation(rt)) {
        ++rt->native_entry_revoked;
        goto reject;
    }
    ++rt->native_entry_accepted;
    return 0;
reject:
    ++rt->native_entry_rejects;
    rt->native_entry_rejected = true;
    rt->native_entry_reject_pc = d->guest_pc;
    ctx->pc = d->guest_pc;
    if (ctx->arch == HB_ARCH_X64) ctx->regs.x64.rip = d->guest_pc;
    else if (ctx->arch == HB_ARCH_X86) ctx->regs.x86.eip = (uint32_t)d->guest_pc;
    return 1;
}
