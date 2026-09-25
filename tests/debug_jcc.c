#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_codegen.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    /* Block A (0x1000): mov rax, 3; cmp rax, 3; jne 0x1020 */
    /* Block B (0x1010): mov rax, 99; ret */
    /* Block C (0x1020): mov rax, 1; ret */
    hb_ir_func_t* func = hb_ir_func_create(0x1000, 0);
    hb_ir_block_t* blkA = hb_ir_block_create(0, 0x1000);
    hb_ir_block_t* blkB = hb_ir_block_create(1, 0x1010);
    hb_ir_block_t* blkC = hb_ir_block_create(2, 0x1020);
    hb_ir_cfg_add_block(func->cfg, blkA);
    hb_ir_cfg_add_block(func->cfg, blkB);
    hb_ir_cfg_add_block(func->cfg, blkC);
    func->cfg->entry = blkA;

    hb_ir_builder_t* b = hb_ir_builder_create(func);
    hb_ir_builder_set_block(b, blkA);
    hb_ir_emit_mov(b, hb_ir_reg(HB_REG_RAX, HB_SIZE_64), hb_ir_imm(3, HB_SIZE_64));
    hb_ir_emit_cmp(b, hb_ir_reg(HB_REG_RAX, HB_SIZE_64), hb_ir_imm(3, HB_SIZE_64));
    hb_ir_emit_jcc(b, HB_CC_NE, 0x1020);
    hb_ir_builder_set_block(b, blkB);
    hb_ir_emit_mov(b, hb_ir_reg(HB_REG_RAX, HB_SIZE_64), hb_ir_imm(99, HB_SIZE_64));
    hb_ir_emit_ret(b);
    hb_ir_builder_set_block(b, blkC);
    hb_ir_emit_mov(b, hb_ir_reg(HB_REG_RAX, HB_SIZE_64), hb_ir_imm(1, HB_SIZE_64));
    hb_ir_emit_ret(b);
    hb_ir_builder_destroy(b);

    hb_context_t* ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    ctx->pc = 0x1000;

    hb_exec_result_t out;
    hb_result_t r = hb_runtime_run(ctx, func, HB_BACKEND_JIT, &out);
    printf("result=%d out.result=%d out.faulted=%d out.fault_reason=%s rax=%llu pc=0x%llx\n",
           r, out.result, out.faulted, out.fault_reason ? out.fault_reason : "(null)",
           (unsigned long long)ctx->regs.x64.rax,
           (unsigned long long)ctx->pc);

    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    return 0;
}
