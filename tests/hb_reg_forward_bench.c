/* A warmed single-block loop, with eight dependent GPR or packed SIMD adds.
 * Run tools/hb_reg_forward_measure.py for fresh-process AB/BA measurements.
 * No game/Wine is involved; compilation and warmup are outside the timed span. */
#define _DARWIN_C_SOURCE 1
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BASE UINT64_C(0x151200000)
#define ADD_RAX_RDX 0x48, 0x01, 0xd0
#define ADDPD_XMM0_XMM1 0x66, 0x0f, 0x58, 0xc1
#define PADDQ_XMM0_XMM1 0x66, 0x0f, 0xd4, 0xc1
static const uint8_t gpr_code[] = {
    ADD_RAX_RDX, ADD_RAX_RDX, ADD_RAX_RDX, ADD_RAX_RDX,
    ADD_RAX_RDX, ADD_RAX_RDX, ADD_RAX_RDX, ADD_RAX_RDX,
    0x48, 0x83, 0xe9, 0x01, /* sub rcx, 1 */
    0x75, 0xe2              /* jnz -30 */
};
static const uint8_t sse_code[] = {
    ADDPD_XMM0_XMM1, ADDPD_XMM0_XMM1, ADDPD_XMM0_XMM1, ADDPD_XMM0_XMM1,
    ADDPD_XMM0_XMM1, ADDPD_XMM0_XMM1, ADDPD_XMM0_XMM1, ADDPD_XMM0_XMM1,
    0x48, 0x83, 0xe9, 0x01, /* sub rcx, 1 */
    0x75, 0xda              /* jnz -38 */
};
static const uint8_t sse_int_code[] = {
    PADDQ_XMM0_XMM1, PADDQ_XMM0_XMM1, PADDQ_XMM0_XMM1, PADDQ_XMM0_XMM1,
    PADDQ_XMM0_XMM1, PADDQ_XMM0_XMM1, PADDQ_XMM0_XMM1, PADDQ_XMM0_XMM1,
    0x48, 0x83, 0xe9, 0x01, /* sub rcx, 1 */
    0x75, 0xda              /* jnz -38 */
};

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static void gate(const char* name, const char* value) {
    char full[96];
    snprintf(full, sizeof(full), "MACRUNNER_HB_%s", name);
    setenv(full, value, 1);
}

static void configure(const char* mode) {
    static const char* on[] = {
        "BLOCK_CHAIN", "CHAIN_PATCH", "CHAIN_WRITE", "NO_CTX_SNAPSHOT",
        "CHAIN_TWO_SLOTS", "CHAIN_AFTER_RUN", "SMC_DIRECT_HASH", "L1_TABLE",
        "L1_ANY_TERM", "NATIVE_FASTPATH", "NATIVE_FASTPATH_INLINE",
        "NATIVE_XMM_MOVES", "NATIVE_SIMD_INT", "NATIVE_SIMD_FP",
        "CHAIN_BODY_ENTRY", "CHAIN_NO_COUNTERS", "CHAIN_LAZY_PC", "CHAIN_SKIP_NOP"
    };
    for (size_t i = 0; i < sizeof(on) / sizeof(on[0]); ++i) gate(on[i], "1");
    gate("FAST_EXEC", "507");
    gate("JCC_FUSE_FULL", "2");
    gate("UNCHAIN_WALK", "0");
    gate("L1_TABLE_BITS", "14");
    gate("LEAN_FRAME", "0");
    gate("NO_DEADLINE_CHECKS", "0");
    gate("TEST_REG_FORWARD_FLIP", "0");
    gate("TEST_XMM_FORWARD_FLIP", "0");
    gate("REG_FORWARD", !strcmp(mode, "on") || !strcmp(mode, "gpr") ? "1" : "0");
    gate("XMM_FORWARD", !strcmp(mode, "on") || !strcmp(mode, "xmm") ? "1" : "0");
    hb_env_refresh();
}

static int run_loop(hb_jit_runtime_t* runtime, hb_context_t* ctx,
                    hb_ir_func_t* func, uint64_t count, size_t length, int sse,
                    uint64_t* elapsed) {
    const double initial[2] = {1.0, 2.0};
    const double increment[2] = {1.0, 2.0};
    ctx->pc = ctx->regs.x64.rip = BASE;
    ctx->regs.x64.rax = 0;
    ctx->regs.x64.rdx = 1;
    ctx->regs.x64.rcx = count;
    ctx->last_result = HB_OK;
    memcpy(ctx->regs.x64.xmm[0], initial, sizeof(initial));
    memcpy(ctx->regs.x64.xmm[1], increment, sizeof(increment));
    if (sse == 2) {
        ctx->regs.x64.xmm[0][0] = ctx->regs.x64.xmm[1][0] = 1;
        ctx->regs.x64.xmm[0][1] = ctx->regs.x64.xmm[1][1] = 2;
    }
    hb_exec_result_t result = {0};
    uint64_t start = now_ns();
    hb_result_t transport = hb_jit_runtime_run(runtime, func, &result);
    *elapsed = now_ns() - start;
    double value[2];
    memcpy(value, ctx->regs.x64.xmm[0], sizeof(value));
    if (transport != HB_OK || result.result != HB_OK || result.faulted ||
        ctx->regs.x64.rcx || ctx->pc != BASE + length ||
        ctx->regs.x64.rip != BASE + length ||
        (!sse && ctx->regs.x64.rax != 8 * count) ||
        (sse == 1 && (value[0] != 1.0 + 8.0 * (double)count ||
                      value[1] != 2.0 + 16.0 * (double)count)) ||
        (sse == 2 && (ctx->regs.x64.xmm[0][0] != 1 + 8 * count ||
                      ctx->regs.x64.xmm[0][1] != 2 + 16 * count))) {
        fprintf(stderr, "benchmark mismatch transport=%d result=%d fault=%d "
                "pc=%#" PRIx64 " rip=%#" PRIx64 " rax=%" PRIu64
                " rcx=%" PRIu64 " xmm0={%.17g,%.17g}\n", transport,
                result.result, result.faulted, ctx->pc, ctx->regs.x64.rip,
                ctx->regs.x64.rax, ctx->regs.x64.rcx, value[0], value[1]);
        return 0;
    }
    return 1;
}

static int dump_native(hb_jit_runtime_t* runtime, const char* path, size_t* size) {
    for (size_t i = 0; i < runtime->block_cache->size; ++i) {
        const hb_block_cache_entry_t* e = &runtime->block_cache->entries[i];
        if (!e->valid || e->guest_addr != BASE || !e->native_code) continue;
        *size = e->native_size;
        if (!path) return 1;
        FILE* f = fopen(path, "wb");
        if (!f) return 0;
        size_t written = fwrite(e->native_code, 1, e->native_size, f);
        int closed = fclose(f);
        return written == e->native_size && !closed;
    }
    return 0;
}

int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "off";
    const char* workload = argc > 2 ? argv[2] : "gpr";
    uint64_t iterations = argc > 3 ? strtoull(argv[3], NULL, 0) : 500000;
    if ((strcmp(mode, "off") && strcmp(mode, "on") && strcmp(mode, "gpr") &&
         strcmp(mode, "xmm")) || (strcmp(workload, "gpr") && strcmp(workload, "sse") &&
                                  strcmp(workload, "sse_int")) ||
        !iterations || iterations > UINT64_C(1000000000)) return 2;
    int sse = !strcmp(workload, "sse_int") ? 2 : !strcmp(workload, "sse");
    const uint8_t* code = sse == 2 ? sse_int_code : sse ? sse_code : gpr_code;
    size_t length = sse == 2 ? sizeof(sse_int_code) : sse ? sizeof(sse_code) : sizeof(gpr_code);
    configure(mode);
    hb_decoder_t* decoder = hb_decoder_create(HB_ARCH_X64, code, length, BASE);
    hb_ir_func_t* func = NULL;
    if (!decoder || hb_lift_func_x64(decoder, &func) != HB_OK || !func) {
        fprintf(stderr, "benchmark could not lift %s loop\n", workload);
        return 2;
    }
    hb_decoder_destroy(decoder);
    hb_context_t* ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    if (!ctx) { fprintf(stderr, "benchmark context allocation failed\n"); return 2; }
    if (!ctx->memory) ctx->memory = hb_memory_create(0);
    hb_result_t map_result = hb_memory_map_private(ctx->memory, BASE, length,
        HB_PERM_READ | HB_PERM_WRITE);
    hb_result_t write_result = map_result == HB_OK
        ? hb_memory_write(ctx->memory, BASE, code, length) : map_result;
    if (map_result != HB_OK || write_result != HB_OK) {
        fprintf(stderr, "benchmark guest memory setup failed: map=%d write=%d\n",
                map_result, write_result);
        return 2;
    }
    if (hb_memory_protect(ctx->memory, BASE, length, HB_PERM_READ | HB_PERM_EXEC) != HB_OK) {
        fprintf(stderr, "benchmark guest code protection failed\n");
        return 2;
    }
    ctx->step_limit = ctx->block_limit = 0;
    hb_jit_runtime_t* runtime = hb_jit_runtime_create(ctx);
    if (!runtime) { fprintf(stderr, "benchmark runtime allocation failed\n"); return 2; }
    uint64_t elapsed;
    for (unsigned warm = 0; warm < 3; ++warm)
        if (!run_loop(runtime, ctx, func, 128, length, sse, &elapsed)) return 1;
    size_t native_size = 0;
    if (!dump_native(runtime, argc > 4 ? argv[4] : NULL, &native_size)) {
        fprintf(stderr, "benchmark native block missing or dump failed\n");
        return 2;
    }
    if (!run_loop(runtime, ctx, func, iterations, length, sse, &elapsed)) return 1;
    printf("{\"mode\":\"%s\",\"workload\":\"%s\",\"iterations\":%" PRIu64
           ",\"guest_adds_per_iteration\":8,\"elapsed_ns\":%" PRIu64
           ",\"ns_per_iteration\":%.6f,\"native_bytes\":%zu}\n",
           mode, workload, iterations, elapsed, (double)elapsed / (double)iterations,
           native_size);
    hb_jit_runtime_destroy(runtime);
    hb_ir_func_destroy(func);
    hb_context_destroy(ctx);
    return 0;
}
