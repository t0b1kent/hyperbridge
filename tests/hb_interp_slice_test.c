/* Instruction-budget continuation from real x64 bytes. The restart oracle is
 * fresh decoding at the exported guest PC, never an internal IR index. */
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned checks, failures, cases;
static const uint64_t CODE = UINT64_C(0x140001000);
static const uint64_t DATA = UINT64_C(0x2000000);
static const uint64_t SAVED_RBP = UINT64_C(0x6a7b8c9daebfc012);

static int check(int ok, const char *what)
{
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL %s\n", what); }
    return ok;
}

static hb_ir_func_t *lift(const uint8_t *bytes, size_t size, uint64_t pc)
{
    hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, bytes, size, pc);
    hb_ir_func_t *func = NULL;
    if (!decoder) return NULL;
    if (hb_lift_func_x64(decoder, &func) != HB_OK) func = NULL;
    hb_decoder_destroy(decoder);
    return func;
}

static hb_context_t *make_context(hb_memory_t *memory, uint64_t limit)
{
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    if (!check(ctx != NULL, "context allocation")) exit(2);
    ctx->memory = memory;
    ctx->pc = ctx->regs.x64.rip = CODE;
    ctx->step_limit = limit;
    ctx->regs.x64.rdi = DATA;
    ctx->regs.x64.rsi = DATA + 4;
    ctx->regs.x64.rbp = DATA + 0x100;
    ctx->regs.x64.rsp = DATA + 0x80;
    return ctx;
}

static uint32_t counter(hb_memory_t *memory, uint64_t addr)
{
    uint32_t value = 0;
    check(hb_memory_read(memory, addr, &value, sizeof(value)) == HB_OK, "read counter");
    return value;
}

static void initialize(hb_memory_t *memory)
{
    const uint64_t zero = 0;
    check(hb_memory_write(memory, DATA, &zero, 8) == HB_OK, "initialize counters");
    check(hb_memory_write(memory, DATA + 0x100, &SAVED_RBP, 8) == HB_OK,
          "initialize saved frame pointer");
}

static hb_exec_result_t execute(hb_interpreter_t *interp, hb_ir_func_t *func)
{
    hb_exec_result_t out = {0};
    check(hb_interpreter_run(interp, func, &out) == HB_OK, "interpreter report transport");
    check(!out.faulted && out.fault_reason == NULL, "budget is not a fault");
    check(out.result == HB_OK || out.result == HB_ERR_STEP_LIMIT, "controlled result");
    return out;
}

static void leave_case(hb_memory_t *memory, uint64_t limit)
{
    /* INC dword [RDI]; LEAVE; INC dword [RSI]; JMP CODE+0x100. LEAVE is
     * MOV RSP,RBP + POP RBP in IR; stopping between them is not resumable. */
    static const uint8_t bytes[] = {0xff,0x07, 0xc9, 0xff,0x06, 0xe9,0xf6,0,0,0};
    initialize(memory);
    hb_context_t *ctx = make_context(memory, limit);
    hb_interpreter_t *interp = hb_interpreter_create(ctx);
    if (!check(interp != NULL, "interpreter allocation")) exit(2);
    uint64_t total_steps = 0;
    unsigned slices = 0;
    while (ctx->pc != CODE + 0x100 && slices < 8) {
        if (!check(ctx->pc >= CODE && ctx->pc < CODE + sizeof(bytes), "restart PC in code")) break;
        size_t offset = (size_t)(ctx->pc - CODE);
        hb_ir_func_t *func = lift(bytes + offset, sizeof(bytes) - offset, ctx->pc);
        if (!check(func && func->cfg && func->cfg->entry, "fresh decode")) exit(2);
        if (!slices) {
            const hb_ir_block_t *block = func->cfg->entry;
            check(block->instr_count == 5, "four guest instructions become five IR operations");
            if (block->instr_count == 5)
                check(block->instrs[1].guest_addr == CODE + 2 && block->instrs[1].guest_len == 1 &&
                      block->instrs[2].guest_addr == CODE + 2 && block->instrs[2].guest_len == 1,
                      "LEAVE operations have one guest tag");
        }
        hb_exec_result_t out = execute(interp, func);
        total_steps += out.steps_executed;
        if (!slices) {
            check(out.result == HB_ERR_STEP_LIMIT, "first slice stops on budget");
            check(out.steps_executed == (limit == 1 ? 1 : 3), "finish whole LEAVE before yield");
            check(ctx->pc == CODE + (limit == 1 ? 2 : 3), "first restart names next whole instruction");
            check(counter(memory, DATA) == 1 && counter(memory, DATA + 4) == 0,
                  "first store once and second store pending");
            check(ctx->regs.x64.rbp == (limit == 1 ? DATA + 0x100 : SAVED_RBP) &&
                  ctx->regs.x64.rsp == (limit == 1 ? DATA + 0x80 : DATA + 0x108),
                  "yield frame is either before or after complete LEAVE");
        }
        check(ctx->pc == ctx->regs.x64.rip, "architectural RIP matches resume PC");
        check(out.steps_executed > 0, "slice makes progress");
        hb_ir_func_destroy(func);
        ++slices;
    }
    check(ctx->pc == CODE + 0x100 && slices < 8, "continuation reaches external JMP target");
    check(counter(memory, DATA) == 1 && counter(memory, DATA + 4) == 1, "both stores execute exactly once");
    check(ctx->regs.x64.rsp == DATA + 0x108 && ctx->regs.x64.rbp == SAVED_RBP,
          "final frame matches literal LEAVE semantics");
    check(total_steps == 5, "no repeated or skipped IR after fresh decode");
    printf("leave limit=%" PRIu64 " slices=%u steps=%" PRIu64 "\n", limit, slices, total_steps);
    ++cases;
    hb_interpreter_destroy(interp);
    ctx->memory = NULL;
    hb_context_destroy(ctx);
}

static void self_loop_case(hb_memory_t *memory)
{
    static const uint8_t bytes[] = {0xeb,0xfe}; /* JMP to itself. */
    hb_ir_func_t *func = lift(bytes, sizeof(bytes), CODE);
    hb_context_t *ctx = make_context(memory, 1);
    hb_interpreter_t *interp = hb_interpreter_create(ctx);
    if (!check(func && interp, "self-loop setup")) exit(2);
    for (unsigned i = 0; i < 3; ++i) {
        hb_exec_result_t out = execute(interp, func);
        check(out.result == HB_ERR_STEP_LIMIT && out.steps_executed == 1,
              "self-loop yields on each new block entry");
        check(ctx->pc == CODE && ctx->regs.x64.rip == CODE, "self-loop exact restart");
    }
    ++cases;
    hb_ir_func_destroy(func);
    hb_interpreter_destroy(interp);
    ctx->memory = NULL;
    hb_context_destroy(ctx);
}

static void branch_case(hb_memory_t *memory, uint64_t limit)
{
    /* INC [RDI]; DEC ECX; JNZ CODE; JMP CODE+0x100. */
    static const uint8_t bytes[] = {0xff,0x07, 0xff,0xc9, 0x75,0xfa, 0xe9,0xf5,0,0,0};
    initialize(memory);
    hb_context_t *ctx = make_context(memory, limit);
    ctx->regs.x64.rcx = 3;
    hb_interpreter_t *interp = hb_interpreter_create(ctx);
    if (!check(interp != NULL, "branch interpreter")) exit(2);
    unsigned slices = 0;
    uint64_t steps = 0;
    while (ctx->pc != CODE + 0x100 && slices < 24) {
        if (!check(ctx->pc >= CODE && ctx->pc < CODE + sizeof(bytes), "branch restart in code")) break;
        size_t offset = (size_t)(ctx->pc - CODE);
        hb_ir_func_t *func = lift(bytes + offset, sizeof(bytes) - offset, ctx->pc);
        if (!check(func != NULL, "branch fresh decode")) exit(2);
        hb_exec_result_t out = execute(interp, func);
        check(out.steps_executed > 0 && out.steps_executed <= limit, "single-IR branch budget");
        check(ctx->pc == ctx->regs.x64.rip, "branch architectural RIP");
        steps += out.steps_executed;
        ++slices;
        hb_ir_func_destroy(func);
    }
    check(ctx->pc == CODE + 0x100 && slices < 24, "conditional loop completes");
    check(counter(memory, DATA) == 3 && ctx->regs.x64.rcx == 0,
          "taken and untaken branch preserve loop count");
    check(steps == 10, "branch continuation neither repeats nor skips work");
    printf("branch limit=%" PRIu64 " slices=%u steps=%" PRIu64 "\n", limit, slices, steps);
    ++cases;
    hb_interpreter_destroy(interp);
    ctx->memory = NULL;
    hb_context_destroy(ctx);
}

static void untagged_case(hb_memory_t *memory)
{
    hb_ir_func_t *func = hb_ir_func_create(CODE, 0);
    hb_ir_block_t *block = hb_ir_block_create(0, CODE);
    if (!check(func && block, "synthetic allocation")) exit(2);
    hb_ir_cfg_add_block(func->cfg, block);
    func->cfg->entry = block;
    hb_ir_builder_t *builder = hb_ir_builder_create(func);
    if (!check(builder != NULL, "synthetic builder")) exit(2);
    check(hb_ir_emit_mov(builder, hb_ir_reg(HB_REG_RAX, HB_SIZE_64),
                         hb_ir_imm(17, HB_SIZE_64)) != NULL, "synthetic first MOV");
    check(hb_ir_emit_mov(builder, hb_ir_reg(HB_REG_RBX, HB_SIZE_64),
                         hb_ir_imm(29, HB_SIZE_64)) != NULL, "synthetic second MOV");
    hb_ir_builder_destroy(builder);
    check(block->instrs[0].guest_len == 0 && block->instrs[1].guest_len == 0,
          "synthetic IR has no precision tags");
    hb_context_t *ctx = make_context(memory, 1);
    ctx->regs.x64.rbx = 41;
    hb_interpreter_t *interp = hb_interpreter_create(ctx);
    if (!check(interp != NULL, "synthetic interpreter")) exit(2);
    hb_exec_result_t out = execute(interp, func);
    check(out.result == HB_ERR_STEP_LIMIT && out.steps_executed == 1, "legacy per-IR budget retained");
    check(ctx->regs.x64.rax == 17 && ctx->regs.x64.rbx == 41, "synthetic second MOV stays pending");
    check(ctx->pc == CODE && ctx->regs.x64.rip == CODE, "untagged IR does not invent a precise PC");
    ++cases;
    hb_interpreter_destroy(interp);
    hb_ir_func_destroy(func);
    ctx->memory = NULL;
    hb_context_destroy(ctx);
}

int main(void)
{
    hb_memory_t *memory = hb_memory_create(0);
    if (!check(memory && hb_memory_map_private(memory, DATA, 16384,
             HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "private guest memory")) return 2;
    for (uint64_t limit = 1; limit <= 3; ++limit) leave_case(memory, limit);
    self_loop_case(memory);
    for (uint64_t limit = 1; limit <= 3; ++limit) branch_case(memory, limit);
    untagged_case(memory);
    hb_memory_destroy(memory);
    printf("interp-slice cases=%u checks=%u failures=%u\n", cases, checks, failures);
    return failures ? 1 : 0;
}
