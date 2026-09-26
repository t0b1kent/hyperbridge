/* Current target matcher copied verbatim, compiled twice (before/after).
 * Not a full runtime or AArch64 execution. Rejecting this pattern prevents a
 * semantic fast helper from bypassing per-instruction masked STORE fallback. */
#include "hb_ir.h"
#include <stdio.h>
#include <string.h>
/* EVEX.aaa == 0 is unmasked, independently of the contents of k0.
 * Call this only for vector IR; target also contains branch addresses elsewhere.
 * Upper-register zeroing is not a substitute for element writemasking. */
static bool jit_evex_write_masked(const hb_ir_instr_t* instr) {
    const uint32_t t = instr ? (uint32_t)instr->target : 0u;
    return (t & HB_EVEX_TARGET_PRESENT) != 0 &&
           ((t >> HB_EVEX_TARGET_MASK_SHIFT) & 7u) != 0;
}

static bool match_before(const hb_ir_block_t* block,
                                                  uint64_t* out_xmm_reg,
                                                  uint64_t* out_exit_pc) {
    if (!block || block->instr_count != 12) return false;
    uint64_t xmm_reg = HB_REG_COUNT;
    for (size_t i = 0; i < 8; i++) {
        const hb_ir_instr_t* instr = &block->instrs[i];
        if (instr->op != HB_IR_STORE) return false;
        if (instr->src1.type != HB_OP_MEM || instr->src1.size != HB_SIZE_128) return false;
        if (instr->src1.mem.base != HB_REG_RCX || instr->src1.mem.index != HB_REG_COUNT) return false;
        if (instr->src1.mem.scale != 1 || instr->src1.mem.disp != (int64_t)(i * 16)) return false;
        if (instr->src2.type != HB_OP_REG || instr->src2.size != HB_SIZE_128) return false;
        if (instr->src2.reg < HB_REG_XMM0 || instr->src2.reg > HB_REG_XMM15) return false;
        if (i == 0) xmm_reg = instr->src2.reg;
        else if (instr->src2.reg != xmm_reg) return false;
    }
    const hb_ir_instr_t* add = &block->instrs[8];
    const hb_ir_instr_t* sub = &block->instrs[9];
    const hb_ir_instr_t* cmp = &block->instrs[10];
    const hb_ir_instr_t* jcc = &block->instrs[11];
    if (add->op != HB_IR_ADD || add->dst.type != HB_OP_REG || add->dst.reg != HB_REG_RCX ||
        add->src1.type != HB_OP_REG || add->src1.reg != HB_REG_RCX ||
        add->src2.type != HB_OP_IMM || add->src2.imm != 0x80) return false;
    if (sub->op != HB_IR_SUB || sub->dst.type != HB_OP_REG || sub->dst.reg != HB_REG_R8 ||
        sub->src1.type != HB_OP_REG || sub->src1.reg != HB_REG_R8 ||
        sub->src2.type != HB_OP_IMM || sub->src2.imm != 0x80) return false;
    if (cmp->op != HB_IR_CMP || cmp->src1.type != HB_OP_REG || cmp->src1.reg != HB_REG_R8 ||
        cmp->src2.type != HB_OP_IMM || cmp->src2.imm != 0x80) return false;
    if (jcc->op != HB_IR_Jcc || jcc->cc != HB_CC_AE || jcc->target != block->guest_addr) return false;
    if (out_xmm_reg) *out_xmm_reg = xmm_reg;
    if (out_exit_pc) *out_exit_pc = jcc->guest_addr + jcc->guest_len;
    return true;
}
static bool match_after(const hb_ir_block_t* block,
                                                  uint64_t* out_xmm_reg,
                                                  uint64_t* out_exit_pc) {
    if (!block || block->instr_count != 12) return false;
    uint64_t xmm_reg = HB_REG_COUNT;
    for (size_t i = 0; i < 8; i++) {
        const hb_ir_instr_t* instr = &block->instrs[i];
        if (instr->op != HB_IR_STORE) return false;
        /* The 128-byte pattern shortcut has no per-lane writemask. */
        if (jit_evex_write_masked(instr)) return false;
        if (instr->src1.type != HB_OP_MEM || instr->src1.size != HB_SIZE_128) return false;
        if (instr->src1.mem.base != HB_REG_RCX || instr->src1.mem.index != HB_REG_COUNT) return false;
        if (instr->src1.mem.scale != 1 || instr->src1.mem.disp != (int64_t)(i * 16)) return false;
        if (instr->src2.type != HB_OP_REG || instr->src2.size != HB_SIZE_128) return false;
        if (instr->src2.reg < HB_REG_XMM0 || instr->src2.reg > HB_REG_XMM15) return false;
        if (i == 0) xmm_reg = instr->src2.reg;
        else if (instr->src2.reg != xmm_reg) return false;
    }
    const hb_ir_instr_t* add = &block->instrs[8];
    const hb_ir_instr_t* sub = &block->instrs[9];
    const hb_ir_instr_t* cmp = &block->instrs[10];
    const hb_ir_instr_t* jcc = &block->instrs[11];
    if (add->op != HB_IR_ADD || add->dst.type != HB_OP_REG || add->dst.reg != HB_REG_RCX ||
        add->src1.type != HB_OP_REG || add->src1.reg != HB_REG_RCX ||
        add->src2.type != HB_OP_IMM || add->src2.imm != 0x80) return false;
    if (sub->op != HB_IR_SUB || sub->dst.type != HB_OP_REG || sub->dst.reg != HB_REG_R8 ||
        sub->src1.type != HB_OP_REG || sub->src1.reg != HB_REG_R8 ||
        sub->src2.type != HB_OP_IMM || sub->src2.imm != 0x80) return false;
    if (cmp->op != HB_IR_CMP || cmp->src1.type != HB_OP_REG || cmp->src1.reg != HB_REG_R8 ||
        cmp->src2.type != HB_OP_IMM || cmp->src2.imm != 0x80) return false;
    if (jcc->op != HB_IR_Jcc || jcc->cc != HB_CC_AE || jcc->target != block->guest_addr) return false;
    if (out_xmm_reg) *out_xmm_reg = xmm_reg;
    if (out_exit_pc) *out_exit_pc = jcc->guest_addr + jcc->guest_len;
    return true;
}
int main(void){
 hb_ir_instr_t ir[12];memset(ir,0,sizeof(ir));hb_ir_block_t b;memset(&b,0,sizeof(b));b.instrs=ir;b.instr_count=12;b.guest_addr=0x1000;
 for(unsigned i=0;i<8;i++){ir[i].op=HB_IR_STORE;ir[i].src1.type=HB_OP_MEM;ir[i].src1.size=HB_SIZE_128;ir[i].src1.mem.base=HB_REG_RCX;ir[i].src1.mem.index=HB_REG_COUNT;ir[i].src1.mem.scale=1;ir[i].src1.mem.disp=i*16;ir[i].src2.type=HB_OP_REG;ir[i].src2.size=HB_SIZE_128;ir[i].src2.reg=HB_REG_XMM1;}
 ir[8].op=HB_IR_ADD;ir[8].dst.type=ir[8].src1.type=HB_OP_REG;ir[8].dst.reg=ir[8].src1.reg=HB_REG_RCX;ir[8].src2.type=HB_OP_IMM;ir[8].src2.imm=128;
 ir[9].op=HB_IR_SUB;ir[9].dst.type=ir[9].src1.type=HB_OP_REG;ir[9].dst.reg=ir[9].src1.reg=HB_REG_R8;ir[9].src2.type=HB_OP_IMM;ir[9].src2.imm=128;
 ir[10].op=HB_IR_CMP;ir[10].src1.type=HB_OP_REG;ir[10].src1.reg=HB_REG_R8;ir[10].src2.type=HB_OP_IMM;ir[10].src2.imm=128;
 ir[11].op=HB_IR_Jcc;ir[11].cc=HB_CC_AE;ir[11].target=b.guest_addr;
 unsigned n=0;if(!match_before(&b,0,0)||!match_after(&b,0,0))return 1;
 for(unsigned pos=0;pos<8;pos++)for(unsigned k=1;k<=7;k++){
  ir[pos].target=HB_EVEX_TARGET_PRESENT|((uint64_t)k<<HB_EVEX_TARGET_MASK_SHIFT)|4;
  if(!match_before(&b,0,0)||match_after(&b,0,0))return 2;
  ir[pos].target=0;n++;
 }
 for(unsigned i=0;i<8;i++)ir[i].target=HB_EVEX_TARGET_PRESENT|4;
 if(!match_after(&b,0,0))return 3;
 printf("{\"scope\":\"current matcher excerpt, not full runtime\",\"masked_patterns_wrongly_accepted_before\":%u,\"accepted_after\":0,\"unmasked_and_aaa0_controls\":true}\n",n);return 0;
}
