/* MOVZX/MOVSX byte-register decode and execution, using literal register
 * contents/answers. Includes the cpu.exe printf argument instruction. */
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_flags.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static unsigned checks, failures, cases;
static const uint64_t CODE = UINT64_C(0x4000000), DATA = UINT64_C(0x8000000);
static const uint64_t values[16] = {
    UINT64_C(0x123456789abc8071), UINT64_C(0x223456789abc8172),
    UINT64_C(0x323456789abcfe73), UINT64_C(0xe4ba06ce8ae8006d),
    UINT64_C(0x4433221188771175), UINT64_C(0x5533221188772276),
    UINT64_C(0x6633221188773377), UINT64_C(0x77332211887744d1),
    UINT64_C(0x8833221188775588), UINT64_C(0x9933221188776689),
    UINT64_C(0xaa3322118877778a), UINT64_C(0xbb3322118877888b),
    UINT64_C(0xcc3322118877998c), UINT64_C(0xdd3322118877aa8d),
    UINT64_C(0xee3322118877bb8e), UINT64_C(0xff3322118877cc8f)
};
typedef struct { unsigned reg, offset, byte; int signed_byte; } source_t;
static const source_t legacy[8] = {
    {0,0,0x71,113}, {1,0,0x72,114}, {2,0,0x73,115}, {3,0,0x6d,109},
    {0,1,0x80,-128}, {1,1,0x81,-127}, {2,1,0xfe,-2}, {3,1,0,0}
};
static const source_t rex_low[8] = {
    {0,0,0x71,113}, {1,0,0x72,114}, {2,0,0x73,115}, {3,0,0x6d,109},
    {4,0,0x75,117}, {5,0,0x76,118}, {6,0,0x77,119}, {7,0,0xd1,-47}
};
static const source_t extended[8] = {
    {8,0,0x88,-120}, {9,0,0x89,-119}, {10,0,0x8a,-118}, {11,0,0x8b,-117},
    {12,0,0x8c,-116}, {13,0,0x8d,-115}, {14,0,0x8e,-114}, {15,0,0x8f,-113}
};

static int check(int ok, const char *what)
{
    ++checks;
    if (!ok) {
        ++failures;
        if (failures <= 80) fprintf(stderr, "FAIL case=%u %s\n", cases, what);
    }
    return ok;
}

static void run_case(hb_memory_t *memory, const uint8_t *code, size_t length,
                     unsigned dst, unsigned dst_size, int sign_extend,
                     const source_t *source, unsigned src_size, int memory_form)
{
    ++cases;
    hb_decoded_t d = {0};
    if (!check(hb_decode_x64(code, length, CODE, &d) == HB_OK, "decode")) return;
    check(d.len == length && d.opcode == (sign_extend ? HB_INS_MOVSX : HB_INS_MOVZX),
          "decoded length/opcode");
    check(d.op1.is_reg && d.op1.reg == (int)dst && d.op1.size == dst_size &&
          d.op1.reg_offset == 0, "wide destination must not become high-byte register");
    check(d.op2.size == src_size, "source width independent of destination");
    if (!memory_form)
        check(d.op2.is_reg && d.op2.reg == (int)source->reg &&
              d.op2.reg_offset == source->offset, "source register and byte offset");
    else
        check(d.op2.is_mem && d.op2.mem.base == HB_REG_RBX &&
              d.op2.mem.index == (memory_form == 2 ? HB_REG_RCX : -1) &&
              d.op2.mem.disp == (memory_form == 2 ? -16 : 0) &&
              (memory_form != 2 || d.op2.mem.scale == 4), "memory addressing unchanged");

    hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, code, length, CODE);
    hb_ir_func_t *func = NULL;
    if (!check(decoder && hb_lift_func_x64(decoder, &func) == HB_OK && func, "lift")) return;
    hb_decoder_destroy(decoder);
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    if (!check(ctx != NULL, "context")) { hb_ir_func_destroy(func); return; }
    ctx->memory = memory;
    for (unsigned i = 0; i < 16; ++i) hb_context_write_reg_value(ctx, i, values[i]);
    ctx->pc = ctx->regs.x64.rip = CODE;
    ctx->flags.cf = 1; ctx->flags.zf = 1; ctx->flags.of = 1;
    ctx->flags.sf = 0; ctx->flags.pf = 0; ctx->flags.af = 1;
    if (memory_form) {
        ctx->regs.x64.rbx = DATA + 64;
        if (memory_form == 2) ctx->regs.x64.rcx = 3;
        const uint8_t bytes[] = {0xff, 0x80};
        check(hb_memory_write(memory, DATA + (memory_form == 2 ? 60 : 64), bytes, src_size) == HB_OK,
              "memory setup");
    }
    uint64_t before[16];
    for (unsigned i = 0; i < 16; ++i) before[i] = hb_context_read_reg_value(ctx, i);
    uint64_t expected = sign_extend ? (uint64_t)(int64_t)source->signed_byte : source->byte;
    if (dst_size == 2) expected = (before[dst] & ~UINT64_C(0xffff)) | (expected & 0xffff);
    else if (dst_size == 4) expected &= UINT32_MAX;
    hb_exec_result_t out = {0};
    check(hb_runtime_run(ctx, func, HB_BACKEND_INTERP, &out) == HB_OK &&
          out.result == HB_OK && !out.faulted, "instruction executes");
    check(hb_context_read_reg_value(ctx, dst) == expected, "literal extended value and upper-bit rule");
    for (unsigned i = 0; i < 16; ++i)
        if (i != dst) check(hb_context_read_reg_value(ctx, i) == before[i], "other register retained");
    check(ctx->flags.cf && ctx->flags.zf && ctx->flags.of && !ctx->flags.sf &&
          !ctx->flags.pf && ctx->flags.af, "arithmetic flags retained");
    check(ctx->pc == CODE + length && ctx->regs.x64.rip == CODE + length, "instruction length advances RIP");
    ctx->memory = NULL;
    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
}

static void register_group(hb_memory_t *memory, uint8_t rex, int operand16,
                           unsigned dst_field, const source_t sources[8])
{
    for (unsigned sign = 0; sign < 2; ++sign) {
        for (unsigned rm = 0; rm < 8; ++rm) {
            uint8_t code[6]; size_t n = 0;
            if (operand16) code[n++] = 0x66;
            if (rex) code[n++] = rex;
            code[n++] = 0x0f;
            code[n++] = sign ? 0xbe : 0xb6;
            code[n++] = (uint8_t)(0xc0 | (dst_field << 3) | rm);
            unsigned dst = dst_field + ((rex & 4) ? 8 : 0);
            unsigned width = (rex & 8) ? 8 : operand16 ? 2 : 4;
            run_case(memory, code, n, dst, width, sign, &sources[rm], 1, 0);
        }
    }
}

int main(void)
{
    hb_memory_t *memory = hb_memory_create(0);
    if (!check(memory && hb_memory_map_private(memory, DATA, 16384,
                                              HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "memory")) return 2;
    /* First case is the exact cpu.exe formatting instruction: BH=00, DIL=d1. */
    const uint8_t actual[] = {0x0f,0xb6,0xf7};
    run_case(memory, actual, sizeof(actual), HB_REG_RSI, 4, 0, &legacy[7], 1, 0);
    register_group(memory, 0, 0, 6, legacy);
    register_group(memory, 0, 1, 6, legacy);
    register_group(memory, 0x40, 0, 6, rex_low);
    register_group(memory, 0x40, 1, 6, rex_low);
    register_group(memory, 0x48, 0, 6, rex_low);
    register_group(memory, 0x48, 1, 6, rex_low); /* REX.W overrides 66. */
    register_group(memory, 0x41, 0, 6, extended);
    register_group(memory, 0x49, 0, 6, extended);
    register_group(memory, 0, 0, 4, legacy);    /* ESP is a wide destination. */
    register_group(memory, 0, 1, 4, legacy);    /* SP preserves upper bits. */
    register_group(memory, 0x40, 0, 4, rex_low);
    register_group(memory, 0x44, 0, 4, rex_low); /* REX.R selects R12D. */
    register_group(memory, 0x4c, 0, 4, rex_low); /* R12 <- byte (REX.W+R). */
    for (unsigned sign = 0; sign < 2; ++sign) {
        for (unsigned width = 0; width < 3; ++width) {
            for (unsigned src_word = 0; src_word < 2; ++src_word) {
                source_t word_reg = {7,0,0x44d1,17617};
                if (src_word) {
                    uint8_t code[6]; size_t n = 0;
                    if (!width) code[n++] = 0x66;
                    if (width == 2) code[n++] = 0x48;
                    code[n++] = 0x0f; code[n++] = sign ? 0xbf : 0xb7; code[n++] = 0xf7;
                    run_case(memory, code, n, HB_REG_RSI, width == 2 ? 8 : width ? 4 : 2,
                             sign, &word_reg, 2, 0);
                }
                for (unsigned addressing = 1; addressing <= 2; ++addressing) {
                    source_t answer = {0,0,src_word ? 0x80ff : 0xff,src_word ? -32513 : -1};
                    uint8_t code[8]; size_t n = 0;
                    if (!width) code[n++] = 0x66;
                    if (width == 2) code[n++] = 0x48;
                    code[n++] = 0x0f;
                    code[n++] = (uint8_t)((sign ? 0xbe : 0xb6) + src_word);
                    code[n++] = addressing == 2 ? 0x74 : 0x33;
                    if (addressing == 2) { code[n++] = 0x8b; code[n++] = 0xf0; }
                    run_case(memory, code, n, HB_REG_RSI, width == 2 ? 8 : width ? 4 : 2,
                             sign, &answer, src_word ? 2 : 1, addressing);
                }
            }
        }
    }
    hb_memory_destroy(memory);
    printf("movx cases=%u checks=%u failures=%u\n", cases, checks, failures);
    return failures ? 1 : 0;
}
