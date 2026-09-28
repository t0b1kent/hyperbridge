/* Ordinary x64 MOV stores, using real identity addresses as Wine does.
 * Each arm runs in its own process because codegen gates may be cached.
 * Host backing deliberately stays RW when one guest 4 KiB subpage is RO:
 * this models the permission union on a 16 KiB host page and distinguishes
 * host-MMU precision loss from a valid permission-map optimization. */
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HOST_PAGE 16384u
#define DATA_BYTES (2u * HOST_PAGE)
#define VALUE UINT64_C(0x8796a5b4c3d2e1f0)

enum arm { ARM_OFF, ARM_HOSTMMU, ARM_HOSTMMU_STRICT, ARM_PERMMAP, ARM_NEGATIVE };
static enum arm selected;
static const char *arm_name;
static unsigned failures, cases, precision_losses;
static uint64_t writable_helpers, denied_helpers;
static char phase[160];

typedef struct {
    hb_context_t *ctx[2];
    hb_memory_t *mem[2];
    hb_jit_runtime_t *jit;
    hb_interpreter_t *interp;
    hb_ir_func_t *func;
    uint8_t *code, *data;
    size_t code_size;
} fixture_t;

static int check(int condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "FAIL x64-store %s: %s\n", phase, what);
        ++failures;
    }
    return condition;
}

static void configure(void) {
    static const char *const disabled[] = {
        "NO_ALIGN_CHECK", "FORCE_LAZY_STORE", "DIRECT_BYTE_STORE",
        "STORE_PERMMAP", "STORE_PERMMAP_NOALIGN", "TSO_RELAXED_STORES",
        "TSO_HELPER_RELAXED", "STORE_NOP_STR", "NATIVE_FASTPATH",
        "PROMOTE_FAMILIES", "BLOCK_CHAIN", "CHAIN_PATCH", "CHAIN_AFTER_RUN",
        "INDIRECT_IC", "L1_TABLE", "ZERO_TRANSIT", "FAST_EXEC"
    };
    for (size_t i = 0; i < sizeof(disabled) / sizeof(disabled[0]); ++i) {
        char name[100];
        snprintf(name, sizeof(name), "MACRUNNER_HB_%s", disabled[i]);
        setenv(name, "0", 1);
    }
    setenv("MACRUNNER_HB_JIT_DIRECT_MEM", "1", 1);
    setenv("MACRUNNER_HB_SMC_DIRECT_HASH", "1", 1);
    setenv("MACRUNNER_HB_SMC_REVERIFY", "1", 1);
    setenv("MACRUNNER_HB_SMC_TRACK_WRITABLE", "1", 1);
    setenv("MACRUNNER_HB_TEST_NO_SMC_REVERIFY", "0", 1);
    setenv("MACRUNNER_HB_SMC_PROTECT", "0", 1);
    setenv("MACRUNNER_HB_X64_STORE_UNALIGNED_HOSTMMU",
           selected == ARM_HOSTMMU || selected == ARM_HOSTMMU_STRICT ? "1" : "0", 1);
    setenv("MACRUNNER_HB_STORE_PERMMAP_NOALIGN",
           selected == ARM_PERMMAP || selected == ARM_NEGATIVE ? "1" : "0", 1);
    setenv("MACRUNNER_HB_TEST_X64_STORE_PERMMAP_BYPASS",
           selected == ARM_NEGATIVE ? "1" : "0", 1);
    hb_env_refresh();
}

static int fixture_create(fixture_t *f, unsigned bytes, unsigned denied_page) {
    memset(f, 0, sizeof(*f));
    f->code = mmap(NULL, HOST_PAGE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    f->data = mmap(NULL, DATA_BYTES, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (!check(f->code != MAP_FAILED && f->data != MAP_FAILED, "mmap")) return 0;
    if (bytes == 2) f->code[f->code_size++] = 0x66;
    if (bytes == 8) f->code[f->code_size++] = 0x48;
    f->code[f->code_size++] = 0x89;  /* mov [rcx], ax/eax/rax */
    f->code[f->code_size++] = 0x01;
    f->code[f->code_size++] = 0x90;
    hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, f->code,
                                               f->code_size, (uintptr_t)f->code);
    if (!check(decoder != NULL, "decoder")) return 0;
    hb_result_t lifted = hb_lift_func_x64(decoder, &f->func);
    hb_decoder_destroy(decoder);
    if (!check(lifted == HB_OK && f->func, "lift actual x64 MOV")) return 0;
    for (unsigned i = 0; i < 2; ++i) {
        f->ctx[i] = hb_context_create(HB_ARCH_X64,
                                      i ? HB_BACKEND_JIT : HB_BACKEND_INTERP);
        f->mem[i] = hb_memory_create(0);
        if (!check(f->ctx[i] && f->mem[i], "context and memory")) return 0;
        f->ctx[i]->memory = f->mem[i];
        f->ctx[i]->config.fallback_enabled = false;
        if (!check(hb_memory_sync_live_range(f->mem[i], (uintptr_t)f->code,
                       HOST_PAGE, HB_PERM_READ | HB_PERM_EXEC) == HB_OK &&
                   hb_memory_sync_live_range(f->mem[i], (uintptr_t)f->data,
                       DATA_BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
                   "identity memory metadata")) return 0;
        if (denied_page && !check(hb_memory_sync_live_range(f->mem[i],
                (uintptr_t)f->data + denied_page, 4096, HB_PERM_READ) == HB_OK,
                "guest RO metadata with host RW backing")) return 0;
    }
    f->interp = hb_interpreter_create(f->ctx[0]);
    f->jit = hb_jit_runtime_create(f->ctx[1]);
    return check(f->interp && f->jit, "runtimes");
}

static void fixture_destroy(fixture_t *f) {
    if (f->jit) hb_jit_runtime_destroy(f->jit);
    if (f->interp) hb_interpreter_destroy(f->interp);
    if (f->func) hb_ir_func_destroy(f->func);
    for (unsigned i = 0; i < 2; ++i) {
        if (f->ctx[i]) { f->ctx[i]->memory = NULL; hb_context_destroy(f->ctx[i]); }
        if (f->mem[i]) hb_memory_destroy(f->mem[i]);
    }
    if (f->code && f->code != MAP_FAILED) munmap(f->code, HOST_PAGE);
    if (f->data && f->data != MAP_FAILED) munmap(f->data, DATA_BYTES);
}

static void seed(fixture_t *f, unsigned backend, unsigned offset) {
    memset(f->data, 0x5a, DATA_BYTES);
    hb_context_t *ctx = f->ctx[backend];
    ctx->regs.x64.rax = VALUE;
    ctx->regs.x64.rcx = (uintptr_t)f->data + offset;
    ctx->regs.x64.rdx = UINT64_C(0x1122334455667788);
    ctx->regs.x64.rsp = (uintptr_t)f->data + DATA_BYTES - 128;
    ctx->regs.x64.rflags = 0x202;
    ctx->last_result = HB_OK;
    ctx->step_limit = ctx->block_limit = 0;
    hb_context_set_pc(ctx, (uintptr_t)f->code);
}

static int native_present(fixture_t *f) {
    hb_block_cache_t *cache = f->jit->block_cache;
    if (!cache) return 0;
    for (size_t i = 0; i < cache->size; ++i)
        if (cache->entries[i].valid &&
            cache->entries[i].guest_addr == (uintptr_t)f->code &&
            cache->entries[i].native_code && cache->entries[i].native_size) return 1;
    return 0;
}

static void run_case(unsigned bytes, unsigned offset, unsigned denied_page) {
    fixture_t f;
    uint8_t expected[DATA_BYTES], written[DATA_BYTES];
    hb_exec_result_t oracle = {0}, actual = {0};
    snprintf(phase, sizeof(phase), "arm=%s bytes=%u offset=%u denied_page=%u",
             arm_name, bytes, offset, denied_page);
    if (!fixture_create(&f, bytes, denied_page)) { fixture_destroy(&f); return; }
    seed(&f, 0, offset);
    hb_interpreter_run(f.interp, f.func, &oracle);
    memcpy(expected, f.data, sizeof(expected));
    seed(&f, 1, offset);
    uint64_t before = hb_codegen_fallback_store_count();
    hb_jit_runtime_run(f.jit, f.func, &actual);
    uint64_t helpers = hb_codegen_fallback_store_count() - before;
    ++cases;
    if (denied_page) denied_helpers += helpers; else writable_helpers += helpers;
    check(native_present(&f), "native block exists (no interpreter-only pass)");
    check(f.ctx[1]->regs.x64.rax == VALUE &&
          f.ctx[1]->regs.x64.rcx == (uintptr_t)f.data + offset &&
          f.ctx[1]->regs.x64.rdx == UINT64_C(0x1122334455667788),
          "source/base/unrelated GPRs preserved");
    if (denied_page) {
        memset(written, 0x5a, sizeof(written));
        check(oracle.result == HB_ERR_MEMORY_FAULT, "interpreter rejects guest RO page");
        check(!memcmp(expected, written, sizeof(expected)), "rejected store has no partial write");
        if (actual.result == HB_OK) ++precision_losses;
        if (selected == ARM_HOSTMMU) {
            uint64_t value = VALUE;
            memcpy(written + offset, &value, bytes);
            check(actual.result == HB_OK && !memcmp(f.data, written, sizeof(written)),
                  "host-MMU arm exhibits documented guest RO subpage precision loss");
            check(helpers == 0, "host-MMU unaligned store bypasses helper");
        } else {
            check(actual.result == oracle.result, "JIT matches interpreter RO rejection");
            check(!memcmp(f.data, expected, sizeof(expected)), "JIT denied store leaves all bytes intact");
            check(helpers == 1, "guest RO store goes to existing helper exactly once");
        }
    } else {
        uint64_t value = VALUE;
        memset(written, 0x5a, sizeof(written));
        memcpy(written + offset, &value, bytes);
        check(oracle.result == HB_OK && actual.result == HB_OK, "writable store succeeds");
        check(!memcmp(expected, written, sizeof(expected)), "interpreter matches exact-byte oracle");
        check(!memcmp(f.data, expected, sizeof(expected)), "JIT matches interpreter including guard bytes");
        uint64_t wanted = selected == ARM_OFF && (offset & (bytes - 1)) ? 1 : 0;
        check(helpers == wanted, "writable helper count matches selected arm and alignment");
    }
    fixture_destroy(&f);
}

static hb_ir_func_t *lift_target(uint8_t *code, size_t length) {
    hb_ir_func_t *func = NULL;
    hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, code, length, (uintptr_t)code);
    if (!check(decoder != NULL, "SMC target decoder")) return NULL;
    hb_result_t result = hb_lift_func_x64(decoder, &func);
    hb_decoder_destroy(decoder);
    if (!check(result == HB_OK && func, "SMC target lift")) return NULL;
    return func;
}

/* The embedding dispatcher may supply freshly lifted IR while the native cache
 * still holds the old translation. This checks the native-cache invalidation,
 * with page trapping explicitly disabled: the direct hash is the observer. */
static void run_smc(void) {
    fixture_t f;
    hb_ir_func_t *target_before = NULL, *target_after = NULL;
    hb_exec_result_t out = {0};
    const uint8_t original[] = {0xb8, 0x44, 0x33, 0x22, 0x11, 0x90};
    const uint32_t replacement = UINT32_C(0x55667788);
    uint64_t tracked0, tracked1, evicted0, evicted1;
    snprintf(phase, sizeof(phase), "arm=%s SMC direct-hash", arm_name);
    if (!fixture_create(&f, 4, 0)) { fixture_destroy(&f); return; }
    for (unsigned i = 0; i < 2; ++i)
        if (!check(hb_memory_sync_live_range(f.mem[i], (uintptr_t)f.data, DATA_BYTES,
                     HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) == HB_OK,
                   "SMC writable executable guest region")) goto done;
    memcpy(f.data, original, sizeof(original));
    target_before = lift_target(f.data, sizeof(original));
    if (!target_before) goto done;
    hb_jit_smc_reverify_stats(&tracked0, NULL, &evicted0, NULL);
    hb_context_set_pc(f.ctx[1], (uintptr_t)f.data);
    hb_jit_runtime_run(f.jit, target_before, &out);
    check(out.result == HB_OK && f.ctx[1]->regs.x64.rax == UINT32_C(0x11223344),
          "cached original target returns old immediate");
    hb_jit_smc_reverify_stats(&tracked1, NULL, NULL, NULL);
    check(tracked1 > tracked0, "writable target is SMC tracked");
    f.ctx[1]->regs.x64.rax = replacement;
    f.ctx[1]->regs.x64.rcx = (uintptr_t)f.data + 1;
    f.ctx[1]->last_result = HB_OK;
    hb_context_set_pc(f.ctx[1], (uintptr_t)f.code);
    uint64_t helpers_before = hb_codegen_fallback_store_count();
    hb_jit_runtime_run(f.jit, f.func, &out);
    uint64_t helpers = hb_codegen_fallback_store_count() - helpers_before;
    check(out.result == HB_OK && !memcmp(f.data + 1, &replacement, sizeof(replacement)),
          "ordinary unaligned guest store patches target bytes");
    check(helpers == (selected == ARM_OFF ? 1u : 0u), "SMC writer uses selected store arm");
    target_after = lift_target(f.data, sizeof(original));
    if (!target_after) goto done;
    f.ctx[0]->last_result = HB_OK;
    hb_context_set_pc(f.ctx[0], (uintptr_t)f.data);
    hb_interpreter_run(f.interp, target_after, &out);
    check(out.result == HB_OK && f.ctx[0]->regs.x64.rax == replacement,
          "interpreter sees patched immediate");
    f.ctx[1]->last_result = HB_OK;
    f.ctx[1]->regs.x64.rax = 0;
    hb_context_set_pc(f.ctx[1], (uintptr_t)f.data);
    hb_jit_runtime_run(f.jit, target_after, &out);
    /* SMC eviction deliberately returns at the current guest PC to request a
     * re-lift from the embedding dispatcher. Honor that one handoff; leaving
     * RAX zero prevents a zero-progress return from masquerading as execution. */
    if (out.result == HB_OK && !out.steps_executed &&
        f.ctx[1]->pc == (uintptr_t)f.data) {
        check(f.ctx[1]->regs.x64.rax == 0, "SMC handoff does not execute stale native code");
        hb_ir_func_destroy(target_after);
        target_after = lift_target(f.data, sizeof(original));
        if (!target_after) goto done;
        hb_jit_runtime_run(f.jit, target_after, &out);
    }
    check(out.result == HB_OK && f.ctx[1]->regs.x64.rax == f.ctx[0]->regs.x64.rax,
          "JIT target reentry agrees with interpreter after SMC");
    hb_jit_smc_reverify_stats(NULL, NULL, &evicted1, NULL);
    check(evicted1 > evicted0, "hash mismatch evicts old native target without write trapping");
    printf("X64_STORE_SMC arm=%s writer_helpers=%" PRIu64 " evicted=%" PRIu64 "\n",
           arm_name, helpers, evicted1 - evicted0);
done:
    if (target_before) hb_ir_func_destroy(target_before);
    if (target_after) hb_ir_func_destroy(target_after);
    fixture_destroy(&f);
}

int main(int argc, char **argv) {
    arm_name = argc == 2 ? argv[1] : "off";
    if (argc > 2) {
        fprintf(stderr, "usage: %s [off|hostmmu|hostmmu-strict]\n", argv[0]);
        return 2;
    }
    if (!strcmp(arm_name, "off")) selected = ARM_OFF;
    else if (!strcmp(arm_name, "hostmmu")) selected = ARM_HOSTMMU;
    else if (!strcmp(arm_name, "hostmmu-strict")) selected = ARM_HOSTMMU_STRICT;
    else if (!strcmp(arm_name, "permmap") || !strcmp(arm_name, "negative")) {
        fprintf(stderr, "x64-store: %s arm is not implemented yet\n", arm_name);
        return 2;
    } else { fprintf(stderr, "usage: %s [off|hostmmu|hostmmu-strict]\n", argv[0]); return 2; }
#if !defined(__aarch64__) && !defined(__arm64__)
    puts("SKIP x64-store: native JIT test requires ARM64");
    return 0;
#endif
    configure();
    static const unsigned offsets[] = {1, 4095, 8191, 16383, 20479, 128};
    for (unsigned bytes = 2; bytes <= 8; bytes *= 2) {
        for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i)
            run_case(bytes, offsets[i], 0);
        run_case(bytes, 4097, 4096);
        run_case(bytes, 4095, 4096);
        run_case(bytes, 16385, 16384);
        run_case(bytes, 16383, 16384);
    }
    run_smc();
    printf("X64_STORE arm=%s cases=%u writable_helpers=%" PRIu64
           " denied_helpers=%" PRIu64 " precision_losses=%u failures=%u host_page=%ld\n",
           arm_name, cases, writable_helpers, denied_helpers, precision_losses,
           failures, sysconf(_SC_PAGESIZE));
    return failures ? 1 : 0;
}
