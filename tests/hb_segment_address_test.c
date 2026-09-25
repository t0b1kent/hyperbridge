/* x64 address-size 32 truncates the effective offset BEFORE adding FS/GS.
 * The expected offsets are explicit below, not computed by an engine resolver.
 * A mapped low-address decoy turns the original bug into incorrect successful
 * execution, exercising JIT atomic fast paths without fallback on a fault.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "hb_decoder.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

enum { PAGE_BYTES = 16384 };
enum { LOAD, STORE, ADD, XCHG, CMPXCHG_OK, CMPXCHG_FAIL, BIT_TEST, LEA, OP_COUNT };
static const uint64_t CODE = 0x4000000;
static const uint64_t OLD = UINT64_C(0x1122334455667701);
static const uint64_t VALUE = 0x25;
static unsigned passed, failed;

typedef struct {
    const char *name;
    uint8_t mod_rm; /* addressing bits without the register field */
    uint8_t tail[5];
    unsigned tail_len;
    uint64_t base, index;
    uint64_t offset32, offset64;
} address_case_t;

static void check(const address_case_t *a, unsigned op, unsigned segment,
                  int addr32, hb_backend_t backend) {
    static const char *names[] = {"load", "store", "add", "xchg", "cmpxchg-ok",
                                 "cmpxchg-fail", "bt", "lea"};
    uint8_t code[16], expected[PAGE_BYTES], actual[PAGE_BYTES], decoy[PAGE_BYTES];
    size_t n = 0;
    uint64_t seg_base = segment == 0x64 ? UINT64_C(0x100200000) : UINT64_C(0x200300000);
    uint64_t linear = seg_base + (addr32 ? a->offset32 : a->offset64);
    uint64_t page = linear & ~(uint64_t)(PAGE_BYTES - 1);
    uint64_t decoy_page = (uint32_t)linear & ~(uint64_t)(PAGE_BYTES - 1);
    size_t offset = (size_t)(linear - page);
    uint64_t expected_word = (op == STORE || op == XCHG || op == CMPXCHG_OK) ? VALUE : OLD;
    uint64_t expected_rdx = (op == LOAD || op == XCHG) ? OLD : VALUE;
    if (op == LEA) expected_rdx = addr32 ? a->offset32 : a->offset64;
    hb_context_t *ctx = NULL;
    hb_decoder_t *decoder = NULL;
    hb_ir_func_t *func = NULL;
    hb_interpreter_t *interp = NULL;
    hb_jit_runtime_t *jit = NULL;
    hb_exec_result_t out = {0};
    hb_result_t status = HB_ERR_INVALID_ARG;
    const char *reason = "setup";
    int ok = 0, native = 0;
    if (op == ADD) expected_word += VALUE;
    memset(expected, 0x5a, sizeof(expected));
    memcpy(expected + offset, &OLD, sizeof(OLD));
    memset(decoy, 0xa4, sizeof(decoy)); /* bit zero differs from OLD, too */
    code[n++] = (uint8_t)segment;
    if (addr32) code[n++] = 0x67;
    if (op == CMPXCHG_OK || op == CMPXCHG_FAIL) code[n++] = 0xf0;
    code[n++] = 0x48;
    if (op == CMPXCHG_OK || op == CMPXCHG_FAIL || op == BIT_TEST) code[n++] = 0x0f;
    code[n++] = op == LEA ? 0x8d : op == LOAD ? 0x8b : op == STORE ? 0x89 : op == ADD ? 0x01 :
                op == XCHG ? 0x87 : op == BIT_TEST ? 0xa3 : 0xb1;
    code[n++] = (uint8_t)(a->mod_rm | ((op == BIT_TEST ? 3u : 2u) << 3));
    memcpy(code + n, a->tail, a->tail_len);
    n += a->tail_len;

    ctx = hb_context_create(HB_ARCH_X64, backend);
    if (!ctx) goto done;
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory) goto done;
    reason = "map intended address";
    status = hb_memory_map_private(ctx->memory, page, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE);
    if (status != HB_OK) goto done;
    status = hb_memory_write(ctx->memory, page, expected, sizeof(expected));
    if (status != HB_OK) goto done;
    reason = "map low-address decoy";
    status = hb_memory_map_private(ctx->memory, decoy_page, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE);
    if (status != HB_OK) goto done;
    status = hb_memory_write(ctx->memory, decoy_page, decoy, sizeof(decoy));
    if (status != HB_OK) goto done;
    reason = "map code";
    status = hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE);
    if (status != HB_OK) goto done;
    status = hb_memory_write(ctx->memory, CODE, code, n);
    if (status != HB_OK) goto done;
    status = hb_memory_protect(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_EXEC);
    if (status != HB_OK) goto done;
    ctx->pc = ctx->regs.x64.rip = CODE;
    ctx->regs.x64.rsi = a->base | (addr32 ? UINT64_C(0xfeed123400000000) : 0);
    ctx->regs.x64.rcx = a->index | (addr32 ? UINT64_C(0xabcd123400000000) : 0);
    ctx->regs.x64.rdx = VALUE;
    ctx->regs.x64.rbx = 0;
    ctx->regs.x64.rax = op == CMPXCHG_FAIL ? OLD + 1 : OLD;
    ctx->flags.cf = op == LEA ? 1 : 0;
    ctx->flags.zf = (op == CMPXCHG_FAIL || op == LEA) ? 1 : 0;
    ctx->fs_base = segment == 0x64 ? seg_base : 0;
    ctx->gs_base = segment == 0x65 ? seg_base : 0;
    ctx->step_limit = 8;
    ctx->block_limit = 2;
    const uint64_t original_rsi = ctx->regs.x64.rsi, original_rcx = ctx->regs.x64.rcx;
    reason = "decode/lift";
    decoder = hb_decoder_create(HB_ARCH_X64, code, n, CODE);
    if (!decoder || hb_lift_func_x64(decoder, &func) != HB_OK || !func) goto done;
    reason = "execute";
    if (backend == HB_BACKEND_INTERP) {
        interp = hb_interpreter_create(ctx);
        if (!interp) goto done;
        status = hb_interpreter_run(interp, func, &out);
    } else {
        jit = hb_jit_runtime_create(ctx);
        if (!jit) goto done;
        status = hb_jit_runtime_run(jit, func, &out);
        if (jit->block_cache) {
            for (size_t i = 0; i < jit->block_cache->size; ++i) {
                const hb_block_cache_entry_t *e = &jit->block_cache->entries[i];
                if (e->valid && e->guest_addr == CODE && e->native_code && e->native_size) native = 1;
            }
        }
    }
    if (status != HB_OK || out.result != HB_OK || out.faulted || out.timed_out) goto done;
    reason = "intended memory";
    memcpy(expected + offset, &expected_word, sizeof(expected_word));
    status = hb_memory_read(ctx->memory, page, actual, sizeof(actual));
    if (status != HB_OK || memcmp(actual, expected, sizeof(actual))) goto done;
    reason = "decoy unchanged";
    status = hb_memory_read(ctx->memory, decoy_page, actual, sizeof(actual));
    if (status != HB_OK || memcmp(actual, decoy, sizeof(actual))) goto done;
    reason = "registers, flags or completion";
    if (hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_ZF | HB_FLAG_BIT_CF) != HB_OK) goto done;
    if (ctx->regs.x64.rdx != expected_rdx || ctx->regs.x64.rax != OLD ||
        ctx->regs.x64.rsi != original_rsi || ctx->regs.x64.rcx != original_rcx ||
        ctx->pc != CODE + n || !out.blocks_executed ||
        (backend == HB_BACKEND_JIT && !native)) goto done;
    if (op == BIT_TEST && ctx->flags.cf != 1) goto done;
    if (op == LEA && (ctx->flags.cf != 1 || ctx->flags.zf != 1)) goto done;
    if ((op == CMPXCHG_OK || op == CMPXCHG_FAIL) &&
        ctx->flags.zf != (op == CMPXCHG_OK)) goto done;
    reason = "atomic helper entered";
    if (backend == HB_BACKEND_JIT) {
        if (op == XCHG && !ctx->lock_census[HB_LKC_H_XCHG]) goto done;
        if ((op == CMPXCHG_OK || op == CMPXCHG_FAIL) &&
            !ctx->lock_census[HB_LKC_H_CMPXCHG]) goto done;
    }
    ok = 1;
done:
    if (ok) ++passed;
    else {
        ++failed;
        printf("FAIL backend=%s op=%s segment=%s addr=%d case=%s reason=%s "
               "status=%d result=%d linear=0x%" PRIx64 " pc=0x%" PRIx64 " native=%d\n",
               backend == HB_BACKEND_INTERP ? "interp" : "jit", names[op],
               segment == 0x64 ? "fs" : "gs", addr32 ? 32 : 64, a->name, reason,
               status, out.result, linear, ctx ? ctx->pc : 0, native);
    }
    if (jit) hb_jit_runtime_destroy(jit);
    if (interp) hb_interpreter_destroy(interp);
    if (decoder) hb_decoder_destroy(decoder);
    if (func) hb_ir_func_destroy(func);
    if (ctx) hb_context_destroy(ctx);
}

int main(void) {
    static const address_case_t cases[] = {
        {"base", 0x06, {0}, 0, 0x20, 0, 0x20, 0x20},
        {"negative-disp", 0x46, {0xe0}, 1, 0x48, 0, 0x28, 0x28},
        {"sib-carry", 0x44, {0x8e, 0x20}, 2, 0xffffffd8, 0x10, 0x38, UINT64_C(0x100000038)},
        {"offset-underflow", 0x46, {0xe0}, 1, 0x18, 0, 0xfffffff8, UINT64_C(0xfffffffffffffff8)},
        {"absolute", 0x04, {0x25, 0x20, 0x10, 0, 0}, 5, 0, 0, 0x1020, 0x1020},
        {"index-only-carry", 0x04, {0xcd, 0x60, 0, 0, 0}, 5, 0, 0x20000001, 0x68, UINT64_C(0x100000068)},
    };
    setvbuf(stdout, NULL, _IONBF, 0);
    for (size_t c = 0; c < sizeof(cases)/sizeof(cases[0]); ++c)
        for (unsigned op = 0; op < OP_COUNT; ++op)
            for (unsigned segment = 0x64; segment <= 0x65; ++segment)
                for (int addr32 = 0; addr32 <= 1; ++addr32) {
                    check(&cases[c], op, segment, addr32, HB_BACKEND_INTERP);
                    check(&cases[c], op, segment, addr32, HB_BACKEND_JIT);
                }
    printf("hb_segment_address_test: %u passed, %u failed\n", passed, failed);
    return failed ? 1 : 0;
}
