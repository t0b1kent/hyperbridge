/* Deterministic proof of the relocation KIND classification the persistent cache depends on.
 *
 * MacRunner 2026-07-29, HK speed lane.
 *
 * The store path used to read `reg == 23` as "this value is a helper address". It is not: x23 is
 * also codegen's scratch register in emit_mask_x_reg_to_size(), at 22 of that function's 25 call
 * sites, and for a 32-bit operand it emits `mov x23, 0xffffffff` — the zero-extension every
 * 32-bit x86 operation needs. The relocation table records it, the store path looked up
 * 0xffffffff in the helper id table, found nothing, and declined THE WHOLE BLOCK.
 *
 * Measured on a Hollow Knight boot: 53 655 blocks, 90 % of every decline and 24.6 % of all
 * compiles that reached the cache. It is also why registering the 24 missing helpers (05f3f3f9)
 * moved retention by nothing: the old matcher only ever inspected the real `blr x23` target,
 * while the relocation table sees every x23 write including this constant.
 *
 * Codegen now states the kind at emission, so this test pins the two facts the store path relies
 * on, neither of which is visible by reading one file:
 *
 *   1. a 32-bit operand's mask produces an x23 relocation of kind VALUE, whose value is below the
 *      4 GB __PAGEZERO floor — so the store path classifies it as a literal and keeps the block;
 *   2. a helper call produces an x23 relocation of kind HELPER — so it is still named by helper
 *      id and restored against the next process's address.
 *
 * If 1 regresses, retention silently drops by a quarter with nothing failing. If 2 regresses, a
 * helper address is written into a cached blob raw and the next process calls a stale one — no
 * crash at store time, no crash at load time, wrong code far from the cause.
 *
 * No host pointers and no ASLR-dependent addresses in what is asserted, so it reproduces run to
 * run — unlike the repo suite, whose memory tests map raw stack addresses.
 *
 * Build:
 *   SDKROOT="$(xcrun --show-sdk-path)" clang -O1 -std=c11 -Wall -Wextra -I include \
 *     tests/hb_reloc_kind_test.c libhyperbridge.a -o tests/hb_reloc_kind_test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hb_codegen.h"
#include "hb_ir.h"
#include "hb_context.h"
#include "hb_runtime.h"

/* Mirrors HB_RELOC_HOST_PTR_FLOOR in hb_runtime.c: macOS maps __PAGEZERO over the low 4 GB, so a
 * value below this provably is not a host pointer and needs no relocation. */
#define HOST_PTR_FLOOR 0x100000000ull

static int failures;

#define CHECK(cond, ...)                                        \
    do {                                                        \
        if (!(cond)) {                                          \
            printf("  FAIL: "); printf(__VA_ARGS__);            \
            printf("   (%s:%d)\n", __FILE__, __LINE__);         \
            failures++;                                         \
        }                                                       \
    } while (0)

typedef struct {
    int x23_value;            /* reg 23, kind VALUE  — the 32-bit mask case */
    int x23_helper;           /* reg 23, kind HELPER — the emit_call_helper case */
    int other_helper;         /* kind HELPER on any other register — must never happen */
    uint64_t first_x23_value; /* so a failure says WHAT was recorded, not just that it was wrong */
} reloc_tally_t;

static reloc_tally_t tally(const hb_codegen_buffer_t* buf) {
    reloc_tally_t t;
    memset(&t, 0, sizeof(t));
    for (size_t i = 0; i < buf->reloc_count; i++) {
        const hb_codegen_reloc_t* r = &buf->relocs[i];
        if (r->kind == HB_RELOC_KIND_HELPER && r->reg != 23) t.other_helper++;
        if (r->reg != 23) continue;
        if (r->kind == HB_RELOC_KIND_HELPER) t.x23_helper++;
        else {
            if (!t.x23_value) t.first_x23_value = r->value;
            t.x23_value++;
        }
    }
    return t;
}

/* want_mask: expect an x23 kind=VALUE site holding 0xffffffff.
 * want_helper: expect at least one x23 kind=HELPER site. */
static void run_case(const char* name, hb_ir_op_t op, hb_size_t size,
                     int want_mask, int want_helper) {
    hb_ir_func_t* func;
    hb_ir_block_t* blk;
    hb_ir_builder_t* b;
    hb_ir_instr_t* ins;
    hb_context_t* ctx;
    hb_arm64_codegen_t* cg;
    hb_codegen_buffer_t* buf;
    reloc_tally_t t;

    func = hb_ir_func_create(0x7000, 0);
    blk = hb_ir_block_create(0, 0x7000);
    if (!func || !blk) { printf("  FAIL: %s: IR setup\n", name); failures++; return; }
    hb_ir_cfg_add_block(func->cfg, blk);
    func->cfg->entry = blk;
    b = hb_ir_builder_create(func);
    hb_ir_builder_set_block(b, blk);
    ins = hb_ir_emit_binop(b, op, hb_ir_reg(HB_REG_RAX, size),
                           hb_ir_reg(HB_REG_RAX, size), hb_ir_reg(HB_REG_RCX, size));
    if (ins) { ins->guest_addr = 0x7000; ins->guest_len = 3; }
    hb_ir_builder_destroy(b);

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    cg = hb_arm64_codegen_create(ctx);
    buf = hb_codegen_buffer_create(4096);
    if (!ctx || !cg || !buf) { printf("  FAIL: %s: codegen setup\n", name); failures++; return; }

    if (hb_arm64_codegen_block(cg, blk, buf) != HB_OK) {
        printf("  FAIL: %s: codegen_block did not return HB_OK\n", name);
        failures++;
    } else {
        t = tally(buf);
        printf("  %-30s relocs=%-2zu x23_value=%d x23_helper=%d first_x23=0x%llx\n",
               name, buf->reloc_count, t.x23_value, t.x23_helper,
               (unsigned long long)t.first_x23_value);

        if (want_mask) {
            CHECK(t.x23_value >= 1,
                  "%s: expected an x23 kind=VALUE relocation for the 32-bit mask, got none", name);
            if (t.x23_value) {
                CHECK(t.first_x23_value == 0xffffffffull,
                      "%s: x23 site recorded 0x%llx, expected the mask 0xffffffff",
                      name, (unsigned long long)t.first_x23_value);
                /* The whole point: below the floor, so the store path leaves it as a literal and
                 * KEEPS the block. Reading the register instead declined it. */
                CHECK(t.first_x23_value < HOST_PTR_FLOOR,
                      "%s: 0x%llx is not below the host-pointer floor — the store path would "
                      "decline this block", name, (unsigned long long)t.first_x23_value);
            }
        } else {
            CHECK(t.x23_value == 0,
                  "%s: unexpected x23 kind=VALUE relocation (%d)", name, t.x23_value);
        }

        if (want_helper)
            CHECK(t.x23_helper >= 1,
                  "%s: expected an x23 kind=HELPER relocation from emit_call_helper(), got none. "
                  "A helper address would be stored raw and restored stale.", name);

        /* A helper address must never be tagged on another register: the store path names those
         * by helper id, and anything else would put a raw host address in a cached blob. */
        CHECK(t.other_helper == 0, "%s: %d HELPER relocations outside x23", name, t.other_helper);
    }

    hb_codegen_buffer_destroy(buf);
    hb_arm64_codegen_destroy(cg);
    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
}

int main(void) {
    printf("hb reloc-kind test\n");

    /* THE case that cost the retention: a 32-bit operand zero-extends, so codegen emits
     * `mov x23, 0xffffffff` and nothing else. One relocation, on x23, and not a helper. */
    run_case("ADD 32-bit (mask -> x23)", HB_IR_ADD, HB_SIZE_32, 1, 0);
    run_case("XOR 32-bit (mask -> x23)", HB_IR_XOR, HB_SIZE_32, 1, 0);

    /* Control: 64 bits needs no mask, so x23 is never written. This is what says the case above
     * is caused by the operand SIZE and not by arithmetic in general. */
    run_case("ADD 64-bit (control)", HB_IR_ADD, HB_SIZE_64, 0, 0);

    /* The other kind must still be tagged: MUL lowers to a C helper. */
    run_case("MUL 32-bit (helper call)", HB_IR_MUL, HB_SIZE_32, 0, 1);
    run_case("DIV 32-bit (helper call)", HB_IR_DIV, HB_SIZE_32, 0, 1);

    printf("%s (%d failure%s)\n", failures ? "FAILED" : "PASSED", failures,
           failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
