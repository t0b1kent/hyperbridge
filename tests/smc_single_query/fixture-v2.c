/* Preserve the original 242-check source byte-for-byte; add controls here. */
#define main smc_v1_main
#include "fixture.c"
#undef main

static void host_inaccessible_control(void) {
    size_t size = (size_t)getpagesize();
    uint8_t *inaccessible = mmap(NULL, size, PROT_NONE, MAP_ANON|MAP_PRIVATE, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    if (inaccessible == MAP_FAILED) return;
    hb_memory_t *mem = hb_memory_create(0);
    CHECK(mem != NULL);
    if (!mem) { munmap(inaccessible, size); return; }
    uint64_t base = (uint64_t)(uintptr_t)inaccessible;
    CHECK(hb_memory_map(mem, base, size, HB_PERM_READ) == HB_OK);
    hb_memory_set_special_handlers(mem, special_read, NULL, NULL);
    hb_context_t ctx = {0}; ctx.memory = mem;
    hb_jit_runtime_t rt = {0}; rt.ctx = &ctx;

    /* Real host protection is PROT_NONE; the returned pointer is never read. */
    prime_fault(mem);
    struct fault before = fault();
    CHECK(hb_memory_probe_read_ptr(mem, base+16, 32) == inaccessible+16);
    CHECK(same_fault(before, fault()));
    for (direct_mode=0; direct_mode<=1; ++direct_mode) {
        prime_fault(mem); before = fault(); calls = (struct calls){0};
        const uint8_t *old = smc_bytes_current_original(&rt, base+16, 32);
        struct fault old_fault = fault(); struct calls old_calls = calls;
        prime_fault(mem); calls = (struct calls){0};
        const uint8_t *candidate = smc_bytes_current(&rt, base+16, 32);
        struct fault candidate_fault = fault(); struct calls candidate_calls = calls;
        CHECK(old == candidate);
        CHECK(same_fault(old_fault, candidate_fault));
        CHECK(same_fault(before, candidate_fault));
        if (direct_mode) {
            CHECK(candidate == inaccessible+16);
            CHECK(old_calls.span==1 && old_calls.ptr==1 && old_calls.read==0);
            CHECK(candidate_calls.probe==1 && candidate_calls.span==0 &&
                  candidate_calls.ptr==0 && candidate_calls.read==0);
        } else {
            CHECK(candidate == NULL);
            CHECK(old_calls.span==1 && old_calls.ptr==0 && old_calls.read==1);
            CHECK(candidate_calls.probe==0 && candidate_calls.span==1 &&
                  candidate_calls.ptr==0 && candidate_calls.read==1);
        }
    }
    CHECK(callback_reads == 0);
    hb_memory_destroy(mem);
    CHECK(munmap(inaccessible, size) == 0);
}

static void guest32_mirror_controls(void) {
    hb_memory_t *mem = hb_memory_create(0);
    CHECK(mem != NULL);
    if (!mem) return;
    const uint32_t low = 0x40000;
    const size_t extent = 16384;
    CHECK(hb_memory_guest32_reserve(mem) == HB_OK);
    uint8_t *mirror = hb_memory_guest32_base(mem);
    CHECK(mirror != NULL);
    if (!mirror) { hb_memory_destroy(mem); return; }
    hb_result_t first = hb_memory_guest32_map(mem, low, extent, HB_PERM_READ|HB_PERM_WRITE);
    hb_result_t second = hb_memory_guest32_map(mem, low+(uint32_t)extent, extent,
                                             HB_PERM_READ|HB_PERM_WRITE|HB_PERM_EXEC);
    hb_result_t top = hb_memory_guest32_map(mem, UINT32_MAX-(uint32_t)extent+1,
                                          extent, HB_PERM_READ|HB_PERM_WRITE);
    CHECK(first == HB_OK); CHECK(second == HB_OK); CHECK(top == HB_OK);
    if (first != HB_OK || second != HB_OK || top != HB_OK) {
        hb_memory_destroy(mem); return;
    }
    for (size_t i=0; i<2*extent; ++i) mirror[low+i] = (uint8_t)(i*23+11);
    mirror[UINT32_MAX] = 0xa7;
    hb_memory_set_special_handlers(mem, special_read, NULL, NULL);
    hb_context_t ctx = {0}; ctx.memory = mem;
    hb_jit_runtime_t rt = {0}; rt.ctx = &ctx;
    uint64_t host = (uint64_t)(uintptr_t)mirror;
    prime_fault(mem); struct fault before = fault();
    CHECK(hb_memory_probe_read_ptr(mem, low+16, 32) == mirror+low+16);
    CHECK(hb_memory_probe_read_ptr(mem, host+low+16, 32) == mirror+low+16);
    CHECK(hb_memory_probe_read_ptr(mem, host+UINT32_MAX, 1) == mirror+UINT32_MAX);
    CHECK(hb_memory_probe_read_ptr(mem, host+UINT32_MAX-7, 32) == NULL);
    CHECK(hb_memory_probe_read_ptr(mem, host+UINT64_C(0x100000000)+16, 32) == NULL);
    CHECK(same_fault(before, fault()));
    for (direct_mode=0; direct_mode<=1; ++direct_mode) {
        compare_case(&rt, low+16, 32, true, true);
        compare_case(&rt, host+low+16, 32, true, true);
        compare_case(&rt, host+low+extent-8, 32, true, false);
        compare_case(&rt, host+UINT32_MAX, 1, true, true);
        compare_case(&rt, host+UINT32_MAX-7, 32, false, false);
        compare_case(&rt, host+UINT64_C(0x100000000)+16, 32, false, false);
    }
    CHECK(callback_reads == 0);
    hb_memory_destroy(mem);
}

int main(void) {
    if (smc_v1_main()) return 1;
    host_inaccessible_control();
    guest32_mirror_controls();
    printf("SMC_SINGLE_QUERY_V2 checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
