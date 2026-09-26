/* Composite and stack address consumers. The fixtures retain valid guest widths. */
static hb_ir_operand_t immop(uint64_t value,hb_size_t size) {
 hb_ir_operand_t o={0};o.type=HB_OP_IMM;o.imm=value;o.size=size;return o;
}
static hb_ir_instr_t make_op(hb_ir_op_t op,hb_ir_operand_t dst,hb_ir_operand_t lhs,hb_ir_operand_t rhs,uint64_t pc) {
 hb_ir_instr_t i={0};i.op=op;i.dst=dst;i.src1=lhs;i.src2=rhs;i.guest_addr=pc;i.guest_len=4;return i;
}
static int emit_extra(hb_codegen_buffer_t *b,const char *name,hb_ir_operand_t m,hb_size_t width,unsigned target,bool *ok) {
 hb_ir_instr_t v[6]={0},g[2]={0};hb_ir_operand_t none={0};hb_size_t native=gpr_native_size(b);
 hb_reg_t ptr=m.mem.base<HB_REG_XMM0?m.mem.base:m.mem.index;
 hb_ir_operand_t preg=regop(ptr,native),cnt=regop(HB_REG_RDX,native),val=regop(HB_REG_RAX,width);
 hb_ir_block_t body={0},guard={0};body.instrs=v;body.instr_count=body.instr_cap=5;body.guest_addr=0x90001000;
 guard.instrs=g;guard.instr_count=guard.instr_cap=2;guard.guest_addr=0x90001014;
 if(!strcmp(name,"bitsource")) {
  v[0].src1=m;*ok=emit_load_bit_scan_source_to_x20(b,v,width);return 1;
 }
 if(!strcmp(name,"setcc_store")) {
  m.size=HB_SIZE_8;emit_mov_imm_compact(b,20,target&1);*ok=emit_store_setcc_w20(b,&m);return 1;
 }
 if(!strcmp(name,"stack_push")||!strcmp(name,"stack_pop")||!strcmp(name,"push_mem")||!strcmp(name,"ret_stack")) {
  if(!strcmp(name,"stack_push")){if(b->arch!=HB_ARCH_X86){*ok=false;return 1;}emit_load_gpr_sized_to_x20(b,&(hb_ir_operand_t){.type=HB_OP_REG,.reg=HB_REG_RAX,.size=HB_SIZE_32});emit_native_stack_push_x20_x86(b);*ok=true;}
  if(!strcmp(name,"stack_pop")){if(b->arch!=HB_ARCH_X86){*ok=false;return 1;}emit_native_stack_pop_to_x20_x86(b);*ok=true;}
  if(!strcmp(name,"push_mem")){v[0].op=HB_IR_PUSH;v[0].src1=m;v[0].src1.size=native;*ok=emit_native_push(b,v);}
  if(!strcmp(name,"ret_stack")){v[0].op=HB_IR_RET;v[0].src1=immop(target,native);*ok=emit_native_ret(b,v);}
  return 1;
 }
 if(strcmp(name,"hot_scan")&&strcmp(name,"bounded_scan")&&strcmp(name,"copy_body")&&strcmp(name,"copy_count")&&strcmp(name,"store_count")&&strcmp(name,"zero_backedge"))return 0;
 if(b->arch==HB_ARCH_X86 && strcmp(name,"bounded_scan") && strcmp(name,"copy_count")){*ok=false;return 1;}
 if(!strcmp(name,"hot_scan")||!strcmp(name,"bounded_scan")) {
  body.instr_count=body.instr_cap=3;
  v[0]=make_op(HB_IR_ADD,preg,preg,immop(1,native),0x90001000);
  v[1]=make_op(HB_IR_CMP,none,m,immop(0,width),0x90001004);
  v[2]=make_op(HB_IR_Jcc,none,none,none,0x90001008);v[2].cc=HB_CC_NE;v[2].target=body.guest_addr;
  if(!strcmp(name,"hot_scan")){*ok=emit_hot_scalar_scan_loop(b,&body);return 1;}
  guard.guest_addr=0x90000ff8;
  g[0]=make_op(HB_IR_CMP,none,preg,cnt,guard.guest_addr);
  g[1]=make_op(HB_IR_Jcc,none,none,none,0x90000ffc);g[1].cc=HB_CC_E;g[1].target=0x9000100c;
  v[2].target=guard.guest_addr;
  *ok=emit_bounded_scan_loop_pochemu(b,&guard,&body).r==BS_OK;return 1;
 }
 if(!strcmp(name,"copy_body")||!strcmp(name,"copy_count")) {
  hb_ir_operand_t dest=m;dest.mem.disp+=64;
  v[0]=make_op(HB_IR_LOAD,val,m,none,0x90001000);
  v[1]=make_op(HB_IR_STORE,none,dest,val,0x90001004);
  v[2]=make_op(HB_IR_ADD,preg,preg,immop(1,native),0x90001008);
  v[3]=make_op(HB_IR_TEST,none,val,val,0x9000100c);
  v[4]=make_op(HB_IR_Jcc,none,none,none,0x90001010);v[4].cc=HB_CC_E;v[4].target=0x90002000;
  if(!strcmp(name,"copy_body")){*ok=emit_copy_scan_body_block(b,&body);return 1;}
  g[0]=make_op(HB_IR_SUB,cnt,cnt,immop(1,native),0x90001014);
  g[1]=make_op(HB_IR_Jcc,none,none,none,0x90001018);g[1].cc=HB_CC_NE;g[1].target=body.guest_addr;
  *ok=emit_copy_scan_counted_loop_pochemu(b,&body,&guard).r==CS_OK;return 1;
 }
 if(!strcmp(name,"store_count")) {
  v[0]=make_op(HB_IR_STORE,none,m,immop(0x5a,HB_SIZE_8),0x90001000);
  v[1]=make_op(HB_IR_ADD,cnt,cnt,immop(1,native),0x90001004);
  v[2]=make_op(HB_IR_ADD,preg,preg,immop(1,native),0x90001008);
  v[3]=make_op(HB_IR_CMP,none,cnt,immop(3,native),0x9000100c);
  v[4]=make_op(HB_IR_Jcc,none,none,none,0x90001010);v[4].cc=HB_CC_NE;v[4].target=body.guest_addr;
  *ok=emit_store_count_loop_block(b,&body);return 1;
 }
 if(!strcmp(name,"zero_backedge")) {
  hb_ir_operand_t bx=regop(HB_REG_RBX,HB_SIZE_64),cx=regop(HB_REG_RCX,HB_SIZE_64);body.instr_count=body.instr_cap=6;
  v[0]=make_op(HB_IR_XOR,val,val,val,0x90001000);
  v[1]=make_op(HB_IR_STORE,none,m,val,0x90001004);
  v[2]=make_op(HB_IR_ADD,bx,bx,immop(2,native),0x90001008);
  v[3]=make_op(HB_IR_ADD,cx,cx,immop(1,native),0x9000100c);
  v[4]=make_op(HB_IR_SUB,cnt,cnt,immop(1,native),0x90001010);
  v[5]=make_op(HB_IR_Jcc,none,none,none,0x90001014);v[5].cc=HB_CC_NE;v[5].target=body.guest_addr;
  *ok=emit_zero_store_update_backedge_block(b,&body);return 1;
 }
 return 0;
}
