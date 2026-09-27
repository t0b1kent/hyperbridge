/* Private associated metadata, intentionally no hb_memory_t ABI change.
 * Retained state objects never move/recycle; bounded exhaustion disables new
 * admissions. Only copied region values escape the cold-copy lock. */
#define HB_MS_REGISTRY_SLOTS 1024u
#define HB_MS_MAX_STATES 4096u
#define HB_MS_CACHE_SLOTS 8u
typedef struct hb_ms_state {
    hb_memory_t *memory;
    pthread_mutex_t lock;
    uint64_t epoch;
    unsigned depth;
    int retired;
    int disabled;
} hb_ms_state;
typedef struct hb_ms_value {
    hb_ms_state *state;
    uint64_t epoch;
    hb_gva_t base;
    size_t size;
    uintptr_t backing;
    hb_perm_t perm;
} hb_ms_value;
typedef struct hb_ms_tls {
    hb_ms_state *state;
    hb_ms_value values[HB_MS_CACHE_SLOTS];
    uint64_t hits, fills, misses, invalidations;
    volatile unsigned busy;
} hb_ms_tls;
static hb_ms_state *hb_ms_registry[HB_MS_REGISTRY_SLOTS];
static uint64_t hb_ms_created;
static pthread_once_t hb_ms_once = PTHREAD_ONCE_INIT;
static int hb_ms_enabled;
static __thread hb_ms_tls hb_ms_local;
#ifndef HB_MS_TEST_VALIDATED
#define HB_MS_TEST_VALIDATED(state) ((void)(state))
#endif
static void hb_ms_init_gate(void) {
    __atomic_store_n(&hb_ms_enabled,
                    hb_env_flag("MACRUNNER_HB_METADATA_SNAPSHOT", 0),
                    __ATOMIC_RELEASE);
}
static size_t hb_ms_hash(const hb_memory_t *mem) {
    return ((uintptr_t)mem >> 6) & (HB_MS_REGISTRY_SLOTS - 1);
}
static hb_ms_state *hb_ms_find(hb_memory_t *mem) {
    if (!mem || !__atomic_load_n(&hb_ms_enabled, __ATOMIC_ACQUIRE)) return NULL;
    hb_ms_tls *tls = &hb_ms_local;
    hb_ms_state *cached = tls->state;
    if (cached && cached->memory == mem &&
        !__atomic_load_n(&cached->retired, __ATOMIC_ACQUIRE)) {
        HB_MS_TEST_VALIDATED(cached);
        return cached;
    }
    size_t start = hb_ms_hash(mem);
    /* Search all slots: retired entries can create holes in probe chains. */
    for (size_t i = 0; i < HB_MS_REGISTRY_SLOTS; ++i) {
        hb_ms_state *state = __atomic_load_n(
            &hb_ms_registry[(start + i) & (HB_MS_REGISTRY_SLOTS - 1)],
            __ATOMIC_ACQUIRE);
        if (state && state->memory == mem &&
            !__atomic_load_n(&state->retired, __ATOMIC_ACQUIRE)) {
            tls->state = state;
            HB_MS_TEST_VALIDATED(state);
            return state;
        }
    }
    return NULL;
}
static void hb_ms_create(hb_memory_t *mem) {
    pthread_once(&hb_ms_once, hb_ms_init_gate);
    if (!__atomic_load_n(&hb_ms_enabled, __ATOMIC_ACQUIRE)) return;
    uint64_t created = __atomic_load_n(&hb_ms_created, __ATOMIC_RELAXED);
    do {
        if (created >= HB_MS_MAX_STATES) return;
    } while (!__atomic_compare_exchange_n(&hb_ms_created, &created, created + 1,
                 false, __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    hb_ms_state *state = calloc(1, sizeof(*state));
    if (!state) return;
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr)) { free(state); return; }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) ||
        pthread_mutex_init(&state->lock, &attr)) {
        pthread_mutexattr_destroy(&attr); free(state); return;
    }
    pthread_mutexattr_destroy(&attr);
    state->memory = mem;
    state->epoch = 2;
    size_t start = hb_ms_hash(mem);
    for (size_t i = 0; i < HB_MS_REGISTRY_SLOTS; ++i) {
        hb_ms_state *empty = NULL;
        if (__atomic_compare_exchange_n(
                &hb_ms_registry[(start + i) & (HB_MS_REGISTRY_SLOTS - 1)],
                &empty, state, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
            return;
        }
    }
    pthread_mutex_destroy(&state->lock);
    free(state); /* Never published. */
}
static hb_ms_state *hb_ms_write_begin(hb_memory_t *mem) {
    hb_ms_state *state = hb_ms_find(mem);
    if (!state) return NULL;
    pthread_mutex_lock(&state->lock);
    if (!state->depth++) {
        ++hb_ms_local.invalidations;
        uint64_t epoch = __atomic_load_n(&state->epoch, __ATOMIC_RELAXED);
        if (epoch >= UINT64_MAX - 2) {
            __atomic_store_n(&state->disabled, 1, __ATOMIC_RELEASE);
            __atomic_store_n(&state->epoch, 0, __ATOMIC_SEQ_CST);
        } else {
            __atomic_store_n(&state->epoch, epoch + 1, __ATOMIC_SEQ_CST);
        }
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
    }
    return state;
}
static void hb_ms_write_end(hb_ms_state *state) {
    if (!state) return;
    if (!--state->depth && !__atomic_load_n(&state->disabled, __ATOMIC_RELAXED)) {
        uint64_t epoch = __atomic_load_n(&state->epoch, __ATOMIC_RELAXED);
        __atomic_store_n(&state->epoch, epoch + 1, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&state->lock);
}
static void hb_ms_retire(hb_ms_state *state) {
    if (!state) return;
    __atomic_store_n(&state->retired, 1, __ATOMIC_RELEASE);
    for (size_t i = 0; i < HB_MS_REGISTRY_SLOTS; ++i) {
        hb_ms_state *expected = state;
        if (__atomic_compare_exchange_n(&hb_ms_registry[i], &expected, NULL,
                false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) break;
    }
    /* Retain the private state/mutex, at most HB_MS_MAX_STATES process-wide.
     * Cached TLS state pointers can therefore be checked after memory reuse. */
}
/* Existing map() permits overlap and MRU-dependent selection. Do not cache
 * that ambiguous configuration. Called before insertion, under the write lock. */
static void hb_ms_check_insert(hb_memory_t *mem, hb_gva_t base, size_t size) {
    hb_ms_state *state = hb_ms_find(mem);
    if (!state || __atomic_load_n(&state->disabled, __ATOMIC_RELAXED)) return;
    for (hb_region_t *r = mem->region_tree; r;) {
        if (base + size <= r->base) r = r->tree_left;
        else if (base >= r->base + r->size) r = r->tree_right;
        else { __atomic_store_n(&state->disabled, 1, __ATOMIC_RELEASE); return; }
    }
}
static bool hb_ms_host_ptr(hb_memory_t *mem, hb_gva_t addr, size_t size,
                           hb_perm_t perm, void **out) {
    hb_ms_state *state = hb_ms_find(mem);
    if (!state || !size || size > UINT64_MAX - addr ||
        __atomic_load_n(&state->disabled, __ATOMIC_ACQUIRE)) return false;
    hb_ms_tls *tls = &hb_ms_local;
    if (tls->busy) return false;
    tls->busy = 1;
    hb_ms_value value;
    hb_ms_value *slot = &tls->values[(addr >> 12) & (HB_MS_CACHE_SLOTS - 1)];
    uint64_t epoch = __atomic_load_n(&state->epoch, __ATOMIC_ACQUIRE);
    if (epoch && !(epoch & 1) && slot->state == state && slot->epoch == epoch &&
        addr >= slot->base && addr - slot->base < slot->size) {
        value = *slot;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&state->epoch, __ATOMIC_ACQUIRE) != epoch ||
            __atomic_load_n(&state->retired, __ATOMIC_ACQUIRE)) {
            goto cold_copy;
        }
        ++tls->hits;
    } else {
cold_copy:
        ++tls->misses;
        pthread_mutex_lock(&state->lock);
        epoch = __atomic_load_n(&state->epoch, __ATOMIC_ACQUIRE);
        if (!epoch || (epoch & 1) || state->retired || state->disabled ||
            mem->guest32_base) {
            pthread_mutex_unlock(&state->lock); tls->busy = 0; return false;
        }
        hb_region_t *r = mem->region_tree;
        while (r) {
            if (addr < r->base) r = r->tree_left;
            else if (addr - r->base >= r->size) r = r->tree_right;
            else break;
        }
        if (!r) {
            *out = NULL;
            pthread_mutex_unlock(&state->lock); tls->busy = 0; return true;
        }
        if (r->is_guest32 || !r->size ||
            r->size > UINT64_MAX - r->base) {
            pthread_mutex_unlock(&state->lock); tls->busy = 0; return false;
        }
        value = (hb_ms_value){state, epoch, r->base, r->size,
                             (uintptr_t)r->host_base, r->perm};
        *slot = value;
        ++tls->fills;
        pthread_mutex_unlock(&state->lock);
    }
    /* Same policy as host_ptr_inner. No memory is touched and no host pointer
     * lifetime is extended. Every caller's existing checks/store remain. */
    if (size > value.size - (addr - value.base) ||
        (value.perm & perm) != perm ||
        (!value.backing && (perm & HB_PERM_WRITE) && (value.perm & HB_PERM_EXEC))) {
        *out = NULL; tls->busy = 0; return true;
    }
    *out = value.backing ? (void *)(value.backing + (addr - value.base))
                        : (void *)(uintptr_t)addr;
    tls->busy = 0; return true;
}
void hb_memory_metadata_snapshot_stats(uint64_t *hits, uint64_t *fills,
                                       uint64_t *misses, uint64_t *invalidations) {
    hb_ms_tls *tls = &hb_ms_local;
    if (hits) *hits = tls->hits;
    if (fills) *fills = tls->fills;
    if (misses) *misses = tls->misses;
    if (invalidations) *invalidations = tls->invalidations;
}
