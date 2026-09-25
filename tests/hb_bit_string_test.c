/* Memory BT/BTS/BTR/BTC regression, decoded from actual x64 instruction bytes.
 * Expected byte/bit positions below are literal boundary cases, independent of
 * the interpreter's word-index calculation. No FEX or external runtime needed.
 * ISA reference: AMD64 Architecture Programmer's Manual, vol. 3, BT/BTC/BTR/BTS.
 * Both backends must satisfy the oracle; agreeing with each other is insufficient.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

/* A complete Apple Silicon host page, so the nominal-base guard really is
 * outside the allocation (private mappings round up to the host page size). */
enum { PAGE_BYTES = 16384 };
static const uint64_t DATA = 0x200000;
static const uint64_t CODE = 0x400000;
static unsigned passed, failed;

typedef struct {
    const char *name;
    uint64_t index;
    int base_offset;
    int expected_byte;
    unsigned expected_bit;
    unsigned segment;
    int immediate;
    int addr32;
} case_t;

static void check(unsigned width, unsigned op, const case_t *c,
                  unsigned old_bit, hb_backend_t backend) {
    static const unsigned opcodes[] = {0xa3, 0xab, 0xb3, 0xbb};
    static const char *names[] = {"bt", "bts", "btr", "btc"};
    uint8_t code[16], initial[PAGE_BYTES], expected[PAGE_BYTES], actual[PAGE_BYTES];
    size_t n = 0;
    hb_context_t *ctx = NULL;
    hb_decoder_t *decoder = NULL;
    hb_ir_func_t *func = NULL;
    hb_interpreter_t *interp = NULL;
    hb_jit_runtime_t *jit = NULL;
    hb_exec_result_t out = {0};
    hb_result_t status = HB_ERR_INVALID_ARG;
    const char *reason = "setup";
    int ok = 0, native = 0;
    uint64_t address = DATA + (uint64_t)c->base_offset;
    if (c->segment) code[n++] = (uint8_t)c->segment;
    if (c->addr32) code[n++] = 0x67;
    if (width == 16) code[n++] = 0x66;
    if (width == 64) code[n++] = 0x48;
    code[n++] = 0x0f;
    code[n++] = c->immediate ? 0xba : (uint8_t)opcodes[op];
    code[n++] = c->immediate ? (uint8_t)((4 + op) << 3) : 0x08;
    if (c->immediate) code[n++] = (uint8_t)c->index;
    memset(initial, 0x5a, sizeof(initial));
    initial[c->expected_byte] &= (uint8_t)~(1u << c->expected_bit);
    initial[c->expected_byte] |= (uint8_t)(old_bit << c->expected_bit);
    memcpy(expected, initial, sizeof(expected));
    if (op == 1) expected[c->expected_byte] |= (uint8_t)(1u << c->expected_bit);
    if (op == 2) expected[c->expected_byte] &= (uint8_t)~(1u << c->expected_bit);
    if (op == 3) expected[c->expected_byte] ^= (uint8_t)(1u << c->expected_bit);

    ctx = hb_context_create(HB_ARCH_X64, backend);
    if (!ctx) goto done;
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory) goto done;
    reason = "map data";
    status = hb_memory_map_private(ctx->memory, DATA, PAGE_BYTES, HB_PERM_READ | HB_PERM_WRITE);
    if (status != HB_OK) goto done;
    reason = "write data";
    status = hb_memory_write(ctx->memory, DATA, initial, sizeof(initial));
    if (status != HB_OK) goto done;
    reason = "map code";
    status = hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES,
                                   HB_PERM_READ | HB_PERM_WRITE);
    if (status != HB_OK) goto done;
    reason = "write code";
    status = hb_memory_write(ctx->memory, CODE, code, n);
    if (status != HB_OK) goto done;
    reason = "protect code";
    status = hb_memory_protect(ctx->memory, CODE, PAGE_BYTES, HB_PERM_READ | HB_PERM_EXEC);
    if (status != HB_OK) goto done;
    ctx->pc = ctx->regs.x64.rip = CODE;
    ctx->regs.x64.rax = address;
    ctx->regs.x64.rcx = c->index;
    ctx->flags.cf = (uint8_t)!old_bit;
    ctx->step_limit = 8;
    ctx->block_limit = 2;
    if (c->segment) {
        ctx->regs.x64.rax -= DATA;
        if (c->segment == 0x64) ctx->fs_base = DATA;
        else ctx->gs_base = DATA;
    }
    if (c->addr32) ctx->regs.x64.rax |= UINT64_C(0x1234567800000000);
    const uint64_t original_rax = ctx->regs.x64.rax;
    reason = "decode/lift";
    decoder = hb_decoder_create(HB_ARCH_X64, code, n, CODE);
    if (!decoder || hb_lift_func_x64(decoder, &func) != HB_OK || !func) goto done;
    reason = "execution";
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
                if (e->valid && e->guest_addr == CODE && e->native_code && e->native_size)
                    native = 1;
            }
        }
    }
    if (status != HB_OK || out.result != HB_OK || out.faulted || out.timed_out) goto done;
    reason = "CF, memory, registers, completion or compiled block";
    if (hb_memory_read(ctx->memory, DATA, actual, sizeof(actual)) != HB_OK) goto done;
    ok = ctx->flags.cf == old_bit && !memcmp(actual, expected, sizeof(actual)) &&
         ctx->regs.x64.rax == original_rax && ctx->regs.x64.rcx == c->index &&
         ctx->pc == CODE + n && out.blocks_executed > 0 &&
         (backend == HB_BACKEND_INTERP || native);
done:
    if (ok) ++passed;
    else {
        ++failed;
        printf("FAIL backend=%s op=%s width=%u case=%s old_bit=%u reason=%s "
               "status=%d result=%d cf=%u pc=0x%" PRIx64 " native=%d\n",
               backend == HB_BACKEND_INTERP ? "interp" : "jit", names[op], width,
               c->name, old_bit, reason, status, out.result, ctx ? ctx->flags.cf : 0,
               ctx ? ctx->pc : 0, native);
    }
    if (jit) hb_jit_runtime_destroy(jit);
    if (interp) hb_interpreter_destroy(interp);
    if (decoder) hb_decoder_destroy(decoder);
    if (func) hb_ir_func_destroy(func);
    if (ctx) hb_context_destroy(ctx);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (unsigned width = 16; width <= 64; width *= 2) {
        const unsigned bytes = width / 8;
        /* The byte containing bit -1 is always base-1, independent of width.
         * Cases crossing whole words distinguish floor from truncating division.
         * addr32+FS/GS and LOCK atomicity are outside this focused regression. */
        const case_t cases[] = {
            {"minus-one", UINT64_MAX, 128, 127, 7, 0, 0, 0},
            {"minus-word", (uint64_t)-(int64_t)width, 128, 128-(int)bytes, 0, 0, 0, 0},
            {"minus-word-one", (uint64_t)-(int64_t)(width+1), 128, 127-(int)bytes, 7, 0, 0, 0},
            {"plus-word", width, 128, 128+(int)bytes, 0, 0, 0, 0},
            {"zero", 0, 128, 128, 0, 0, 0, 0},
            {"immediate-255", 255, 128, 127+(int)bytes, 7, 0, 1, 0},
            {"unmapped-base-before", width, -(int)bytes, 0, 0, 0, 0, 0},
            {"unmapped-base-after", UINT64_MAX, PAGE_BYTES, PAGE_BYTES-1, 7, 0, 0, 0},
            {"fs-plus-word", width, 128, 128+(int)bytes, 0, 0x64, 0, 0},
            {"gs-minus-one", UINT64_MAX, 128, 127, 7, 0x65, 0, 0},
            {"addr32-minus-one", UINT64_MAX, 128, 127, 7, 0, 0, 1},
            {"addr32-plus-word", width, 128, 128+(int)bytes, 0, 0, 0, 1},
            {"addr32-wrap-plus-word", UINT64_C(0x800000000)+width,
                128, 128+(int)bytes, 0, 0, 0, 1},
            {"addr32-wrap-minus-one", UINT64_C(0xfffffff800000000)-1,
                128, 127, 7, 0, 0, 1},
        };
        for (unsigned op = 0; op < 4; ++op)
            for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
                for (unsigned bit = 0; bit < 2; ++bit) {
                    check(width, op, &cases[i], bit, HB_BACKEND_INTERP);
                    check(width, op, &cases[i], bit, HB_BACKEND_JIT);
                }
    }
    printf("hb_bit_string_test: %u passed, %u failed\n", passed, failed);
    return failed ? 1 : 0;
}
