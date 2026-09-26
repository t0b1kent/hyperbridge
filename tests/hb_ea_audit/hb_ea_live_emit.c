/* Compile the real production emitter.  This executable emits A64; it does not
 * call generated A64 or execute the runtime's x86 instruction helpers. */
#include <inttypes.h>
#include <errno.h>
#include HB_SOURCE
unsigned long long hb_alloc_calls, hb_free_calls;
uintptr_t hb_alloc_site_pc[HB_ALLOC_SITES];
unsigned long long hb_alloc_site_n[HB_ALLOC_SITES], hb_alloc_site_bytes[HB_ALLOC_SITES];
hb_result_t hb_codegen_buffer_append(hb_codegen_buffer_t *b,const uint8_t *p,size_t n) {
 if(!b || !p || b->size>b->capacity || n>b->capacity-b->size) abort();
 memcpy(b->code+b->size,p,n);b->size+=n;return HB_OK;
}
static hb_ir_operand_t regop(hb_reg_t r,hb_size_t s) {
 hb_ir_operand_t o={0};o.type=HB_OP_REG;o.reg=r;o.size=s;return o;
}
#include "hb_ea_extra_emit.h"
static int emit_one(int argc,char **argv) {
 if(argc!=10) {fprintf(stderr,"usage: emitter op shape disp arch lean pinned width scale target\n");return 2;}
 const char *op=argv[1];int shape=atoi(argv[2]),arch=atoi(argv[4]),lean=atoi(argv[5]),pinned=atoi(argv[6]);
 hb_size_t width=(hb_size_t)atoi(argv[7]);
 hb_codegen_buffer_t b={0};b.capacity=262144;b.code=calloc(1,b.capacity);b.arch=arch?HB_ARCH_X86:HB_ARCH_X64;b.pinned_g32_base=pinned;
 if(lean) lean_frame_arm(&b);
 hb_ir_operand_t m={0};m.type=HB_OP_MEM;m.size=width;m.mem.base=shape&2?HB_REG_COUNT:HB_REG_RBX;m.mem.index=shape&1?HB_REG_RCX:HB_REG_COUNT;m.mem.scale=atoi(argv[8]);m.mem.disp=strtoll(argv[3],NULL,0);
 hb_ir_instr_t i={0},j={0};i.target=strtoull(argv[9],NULL,0);i.guest_addr=0x401000;i.guest_len=4;
 i.dst=regop(HB_REG_XMM0,HB_SIZE_128);i.src1=i.dst;i.src2=m;
 bool ok=false;
 if(!strcmp(op,"xor")||!strcmp(op,"and")||!strcmp(op,"andn")||!strcmp(op,"or")||!strcmp(op,"regxor")||!strcmp(op,"vexxor")) {
  i.op=!strcmp(op,"and")?HB_IR_XMM_AND:!strcmp(op,"andn")?HB_IR_XMM_ANDN:!strcmp(op,"or")?HB_IR_XMM_OR:HB_IR_XORPS;
  i.src2.size=HB_SIZE_128;
  if(!strcmp(op,"regxor"))i.src2=regop(HB_REG_XMM1,HB_SIZE_128);
  if(!strcmp(op,"vexxor"))i.zero_ymm_upper=true;
  ok=emit_native_xmm_logic(&b,&i);
 } else if(!strcmp(op,"load")) {
  m.size=HB_SIZE_128;ok=emit_load_xmm_operand_to_pair(&b,&m,20,22);if(ok)emit_store_x20_x22_to_xmm(&b,HB_REG_XMM0);
 } else if(!strcmp(op,"unpackhi")||!strcmp(op,"unpacklo")||!strcmp(op,"regunpack")) {
  i.op=HB_IR_PUNPCK;i.target=!strcmp(op,"unpackhi")?0x108:8;i.src2.size=HB_SIZE_128;
  if(!strcmp(op,"regunpack")) {i.src2=regop(HB_REG_XMM1,HB_SIZE_128);i.target=strtoull(argv[9],NULL,0);}
  ok=emit_native_punpck_qdq(&b,&i);
 } else if(!strcmp(op,"insert")||!strcmp(op,"insert_mem")) {
  i.op=HB_IR_INSERTPS;i.src2=regop(HB_REG_XMM1,HB_SIZE_128);if(!strcmp(op,"insert_mem"))i.src2=m;
  ok=emit_native_insertps(&b,&i);
 } else if(!strcmp(op,"extract")||!strcmp(op,"extract_mem")) {
  i.op=HB_IR_EXTRACTPS;i.dst=regop(HB_REG_RAX,HB_SIZE_32);i.src1=regop(HB_REG_XMM0,HB_SIZE_128);
  if(!strcmp(op,"extract_mem"))i.dst=m;
  ok=emit_native_extractps(&b,&i);
 } else if(!strcmp(op,"movload")||!strcmp(op,"movstore")||!strcmp(op,"vexload")) {
  m.size=HB_SIZE_128;
  if(!strcmp(op,"movstore")){i.op=HB_IR_MOV;i.dst=m;i.src1=regop(HB_REG_XMM0,HB_SIZE_128);}
  else {i.op=HB_IR_MOV;i.src1=m;}
  if(!strcmp(op,"vexload"))i.zero_ymm_upper=true;
  ok=emit_native_xmm_mov(&b,&i);
 } else if(!strcmp(op,"scalar_rhs")||!strcmp(op,"scalar_lhs")) {
  hb_ir_operand_t r=regop(HB_REG_RAX,width);
  if(!strcmp(op,"scalar_rhs")){ok=emit_scalar_operand_to_x20(&b,&r,width)&&emit_scalar_operand_to_x21(&b,&m,width);}
  else {ok=emit_scalar_operand_to_x20(&b,&m,width)&&emit_scalar_operand_to_x21(&b,&r,width);}
  if(ok){emit_str_x(&b,20,19,xmm_reg_off(&b,HB_REG_XMM0));emit_str_x(&b,21,19,xmm_reg_off(&b,HB_REG_XMM0)+8);}
 } else if(!strcmp(op,"tso_load")||!strcmp(op,"tso_store")) {
  hb_ir_operand_t r=regop(HB_REG_RAX,width);
  if(!strcmp(op,"tso_load"))ok=emit_direct_mem_load_to_gpr_tso(&b,&m,&r);
  else {emit_load_gpr_sized_to_x20(&b,&r);ok=emit_direct_mem_store_from_x20_tso(&b,&m);}
 } else if(!strcmp(op,"extend_signed")||!strcmp(op,"extend_zero")) {
  i.op=!strcmp(op,"extend_signed")?HB_IR_SIGN_EXTEND:HB_IR_ZERO_EXTEND;
  i.dst=regop(HB_REG_RAX,arch?HB_SIZE_32:HB_SIZE_64);i.src1=m;
  ok=emit_native_extend(&b,&i);
 } else if(!strcmp(op,"branch_mem")) {
  m.size=arch?HB_SIZE_32:HB_SIZE_64;ok=emit_native_branch_target_to_x20(&b,&m);
 } else if(!strncmp(op,"cmp_",4)||!strncmp(op,"test_",5)) {
  i.op=!strncmp(op,"cmp_",4)?HB_IR_CMP:HB_IR_TEST;
  i.src1=!strcmp(op,"cmp_rhs")||!strcmp(op,"test_rhs")?regop(HB_REG_RAX,width):m;
  i.src2=i.src1.type==HB_OP_MEM?regop(HB_REG_RAX,width):m;
  j.op=HB_IR_Jcc;j.cc=(hb_cc_t)strtoul(argv[9],NULL,0);j.target=0x90001010;j.guest_addr=0x90001004;j.guest_len=6;
  if(strstr(op,"memreg"))ok=emit_mem_reg_flags_jcc_pair(&b,&i,&j);
  else if(strstr(op,"memimm")){i.src2.type=HB_OP_IMM;i.src2.imm=0x35;i.src2.size=width;ok=emit_mem_imm_flags_jcc_pair(&b,&i,&j);}
  else if(strstr(op,"simple"))ok=emit_scalar_flags_jcc_pair(&b,&i,&j);
  else ok=emit_cmp_sub_jcc_native(&b,&i,&j);
 } else if(!strncmp(op,"binary_",7)) {
  const char *p=op+7;i.op=!strcmp(p,"add")?HB_IR_ADD:!strcmp(p,"sub")?HB_IR_SUB:!strcmp(p,"and")?HB_IR_AND:!strcmp(p,"or")?HB_IR_OR:HB_IR_XOR;
  i.dst=regop(HB_REG_RAX,width);i.src1=i.dst;i.src2=regop(HB_REG_RDX,width);
  ok=emit_scalar_flags_result_to_x22(&b,&i);
 } else if(!strncmp(op,"rmw_",4)||!strncmp(op,"lock_",5)) {
  const char *p=op+(!strncmp(op,"rmw_",4)?4:5);
  i.op=!strcmp(p,"add")?HB_IR_ADD:!strcmp(p,"sub")?HB_IR_SUB:!strcmp(p,"xor")?HB_IR_XOR:!strcmp(p,"and")?HB_IR_AND:!strcmp(p,"or")?HB_IR_OR:!strcmp(p,"adc")?HB_IR_ADC:HB_IR_SBB;
  i.dst=m;i.src1=m;i.src2=regop(HB_REG_RAX,width);
  if(!strncmp(op,"lock_",5))ok=i.op==HB_IR_SUB?emit_locked_sub_atomic(&b,&i):emit_locked_rmw_lse(&b,&i);
  else ok=emit_direct_arith_rmw(&b,&i)||emit_direct_logic_rmw(&b,&i);
 } else if(!strcmp(op,"adj_load")||!strcmp(op,"adj_store")||!strcmp(op,"adj_alias")) {
  m.size=HB_SIZE_64;i.src1=m;j.src1=m;j.src1.mem.disp+=8;
  if(!strcmp(op,"adj_store")){i.op=j.op=HB_IR_STORE;i.src2=regop(HB_REG_RAX,HB_SIZE_64);j.src2=regop(HB_REG_RDX,HB_SIZE_64);}
  else{i.op=j.op=HB_IR_LOAD;i.dst=regop(!strcmp(op,"adj_alias")?HB_REG_RBX:HB_REG_RAX,HB_SIZE_64);j.dst=regop(HB_REG_RDX,HB_SIZE_64);}
  ok=emit_adjacent_mem64_pair(&b,&i,&j);
 } else if(!strcmp(op,"xmm_pair")||!strcmp(op,"scalar_pair")) {
  bool xmm=!strcmp(op,"xmm_pair");if(xmm)m.size=HB_SIZE_128;
  i.op=HB_IR_LOAD;i.dst=regop(xmm?HB_REG_XMM0:HB_REG_RAX,m.size);i.src1=m;
  j.op=HB_IR_STORE;j.src1=m;j.src1.mem.disp+=64;j.src2=i.dst;
  ok=xmm?emit_xmm_load_store_pair(&b,&i,&j):emit_scalar_load_store_pair(&b,&i,&j);
 } else if(!strncmp(op,"ir_",3)) {
  bool store=strstr(op,"store")!=NULL;
  bool narrow=strstr(op,"narrow")!=NULL;
  bool movd=strstr(op,"movd")!=NULL;
  if(!strcmp(op,"ir_scalar_mov_load")) {i.op=HB_IR_MOV;i.dst=regop(HB_REG_RAX,width);i.src1=m;}
  else if(movd) {i.op=HB_IR_MOVD;i.dst=store?m:regop(HB_REG_XMM0,HB_SIZE_128);i.src1=store?regop(HB_REG_XMM0,HB_SIZE_128):m;}
  else if(store) {i.op=HB_IR_STORE;if(!narrow)m.size=HB_SIZE_128;i.src1=m;i.src2=regop(HB_REG_XMM0,m.size);}
  else {i.op=HB_IR_LOAD;if(!narrow)m.size=HB_SIZE_128;i.dst=regop(HB_REG_XMM0,narrow?width:HB_SIZE_128);i.src1=m;i.zero_upper=narrow;}
  ok=codegen_instr(&b,&i)==HB_OK;
 } else if(!strcmp(op,"dispatch_cmpxchg")||!strcmp(op,"dispatch_cmpxchg8b")||!strcmp(op,"dispatch_cmpxchg16b")||!strcmp(op,"dispatch_x87_fld")||!strcmp(op,"dispatch_x87_fadd")||!strcmp(op,"dispatch_x87_fstp")||!strcmp(op,"dispatch_insert_mem")||!strcmp(op,"dispatch_extract_mem")||!strcmp(op,"dispatch_vexxor")||!strcmp(op,"dispatch_avxxor")) {
  if(!strncmp(op,"dispatch_cmpxchg",16)) {
   i.op=!strcmp(op,"dispatch_cmpxchg")?HB_IR_CMPXCHG:HB_IR_CMPXCHG8B;
   if(!strcmp(op,"dispatch_cmpxchg8b"))m.size=HB_SIZE_64;
   if(!strcmp(op,"dispatch_cmpxchg16b"))m.size=HB_SIZE_128;
   i.dst=m;i.src1=m;i.src2=regop(HB_REG_RDX,width);
  } else if(!strncmp(op,"dispatch_x87_",13)) {
   i.op=!strcmp(op,"dispatch_x87_fld")?HB_IR_X87_FLD:!strcmp(op,"dispatch_x87_fadd")?HB_IR_X87_FADD:HB_IR_X87_FSTP;
   memset(&i.dst,0,sizeof(i.dst));memset(&i.src2,0,sizeof(i.src2));i.src1=m;
   if(i.op==HB_IR_X87_FSTP)i.dst=m;
  } else if(!strcmp(op,"dispatch_insert_mem")) {i.op=HB_IR_INSERTPS;i.src2=m;}
  else if(!strcmp(op,"dispatch_extract_mem")){i.op=HB_IR_EXTRACTPS;i.dst=m;i.src1=regop(HB_REG_XMM0,HB_SIZE_128);}
  else {i.op=HB_IR_XORPS;i.zero_ymm_upper=true;i.dst.size=i.src1.size=i.src2.size=!strcmp(op,"dispatch_avxxor")?HB_SIZE_256:HB_SIZE_128;}
  ok=codegen_instr(&b,&i)==HB_OK;
 } else if(emit_extra(&b,op,m,width,(unsigned)strtoul(argv[9],NULL,0),&ok)) {
 } else {fprintf(stderr,"bad op: %s\n",op);return 2;}
 printf("{\"emitted\":%s,\"size\":%zu,\"ctx_size\":%zu,\"xmm_off\":%u,\"xmm1_off\":%u,\"rax_off\":%zu,\"rdx_off\":%zu,\"rbx_off\":%zu,\"rcx_off\":%zu,\"g32_off\":%zu,\"ctx_reg\":%d,\"emitted_call\":%u,\"code\":\"",ok?"true":"false",b.size,sizeof(hb_context_t),xmm_reg_off(&b,HB_REG_XMM0),xmm_reg_off(&b,HB_REG_XMM1),reg_off(&b,HB_REG_RAX),reg_off(&b,HB_REG_RDX),reg_off(&b,HB_REG_RBX),reg_off(&b,HB_REG_RCX),offsetof(hb_context_t,guest32_base),hb_rm(&b,19),b.emitted_call);
 for(size_t n=0;n<b.size;n++)printf("%02x",b.code[n]);
 printf("\",\"helpers\":{\"store_u128\":\"%p\",\"store\":\"%p\",\"load\":\"%p\",\"interp\":\"%p\",\"atomic\":\"%p\"},\"ir_ptr\":\"%p\",\"pc_off\":%zu,\"rmap\":[",(void*)hb_jit_helper_store_u128,(void*)hb_jit_helper_store_sized,(void*)hb_jit_helper_load_to_reg_sized,(void*)hb_jit_helper_exec_interp_ir,(void*)hb_jit_helper_exec_atomic_ir,(void*)&i,offsetof(hb_context_t,pc));
 for(int r=0;r<32;r++)printf("%s%d",r?",":"",hb_rm(&b,r));printf("],\"rsp_off\":%zu}\n",reg_off(&b,HB_REG_RSP));
 free(b.code);return 0;
}

int main(int argc,char **argv) {
 hb_env_refresh();
 if(argc==2 && !strcmp(argv[1],"--server")) {
  char line[1024];
  while(fgets(line,sizeof(line),stdin)) {
   char *av[12]={argv[0]},*save=NULL;int n=1;
   char *p=strtok_r(line," \t\r\n",&save);
   while(p && n<12){av[n++]=p;p=strtok_r(NULL," \t\r\n",&save);}
   if(n!=10 || emit_one(n,av))return 2;
   fflush(stdout);
  }
  return 0;
 }
 return emit_one(argc,argv);
}
