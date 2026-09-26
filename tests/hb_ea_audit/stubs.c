/* Filled only with fail-fast link stubs for runtime functions that the emitter
 * references in helper bodies but that this emit-only executable never runs. */
#include <stdio.h>
#include <stdlib.h>
void hb_flags_write_operand_value(void) {fputs("forbidden runtime call: hb_flags_write_operand_value\n",stderr);abort();}
void *hb_jit_last_arena_base(void) {return NULL;}
void hb_memory_find_region(void) {fputs("forbidden runtime call: hb_memory_find_region\n",stderr);abort();}
void hb_memory_host_ptr(void) {fputs("forbidden runtime call: hb_memory_host_ptr\n",stderr);abort();}
void hb_memory_read_u16(void) {fputs("forbidden runtime call: hb_memory_read_u16\n",stderr);abort();}
void hb_memory_read_u32(void) {fputs("forbidden runtime call: hb_memory_read_u32\n",stderr);abort();}
void hb_memory_read_u64(void) {fputs("forbidden runtime call: hb_memory_read_u64\n",stderr);abort();}
void hb_memory_read_u8(void) {fputs("forbidden runtime call: hb_memory_read_u8\n",stderr);abort();}
void hb_memory_write(void) {fputs("forbidden runtime call: hb_memory_write\n",stderr);abort();}
void hb_memory_write_u16(void) {fputs("forbidden runtime call: hb_memory_write_u16\n",stderr);abort();}
void hb_memory_write_u32(void) {fputs("forbidden runtime call: hb_memory_write_u32\n",stderr);abort();}
void hb_memory_write_u64(void) {fputs("forbidden runtime call: hb_memory_write_u64\n",stderr);abort();}
void hb_memory_write_u8(void) {fputs("forbidden runtime call: hb_memory_write_u8\n",stderr);abort();}
unsigned hb_runtime_helper_id_for_addr(unsigned long long x) {(void)x;return 0;}
void hb_context_read_reg_value(void){fputs("forbidden runtime call: hb_context_read_reg_value\n",stderr);abort();}
void hb_context_write_reg_value_sized(void){fputs("forbidden runtime call: hb_context_write_reg_value_sized\n",stderr);abort();}
void hb_flags_eval_cond(void){fputs("forbidden runtime call: hb_flags_eval_cond\n",stderr);abort();}
void hb_flags_exec_binop(void){fputs("forbidden runtime call: hb_flags_exec_binop\n",stderr);abort();}
void hb_flags_exec_binop_operand(void){fputs("forbidden runtime call: hb_flags_exec_binop_operand\n",stderr);abort();}
void hb_flags_exec_double_shift_operand(void){fputs("forbidden runtime call: hb_flags_exec_double_shift_operand\n",stderr);abort();}
void hb_flags_read_operand_value(void){fputs("forbidden runtime call: hb_flags_read_operand_value\n",stderr);abort();}
void hb_interpreter_exec_one_for_jit(void){fputs("forbidden runtime call: hb_interpreter_exec_one_for_jit\n",stderr);abort();}
void hb_ir_op_name_public(void){fputs("forbidden runtime call: hb_ir_op_name_public\n",stderr);abort();}
void hb_ir_reg(void){fputs("forbidden runtime call: hb_ir_reg\n",stderr);abort();}
void hb_lazy_flags_clear(void){fputs("forbidden runtime call: hb_lazy_flags_clear\n",stderr);abort();}
void hb_lazy_flags_materialize(void){fputs("forbidden runtime call: hb_lazy_flags_materialize\n",stderr);abort();}
void hb_lazy_flags_materialize_available(void){fputs("forbidden runtime call: hb_lazy_flags_materialize_available\n",stderr);abort();}
void hb_lazy_flags_note(void){fputs("forbidden runtime call: hb_lazy_flags_note\n",stderr);abort();}
void hb_lock_census_collect(void){fputs("forbidden runtime call: hb_lock_census_collect\n",stderr);abort();}
void hb_memory_atomic_cmpxchg128(void){fputs("forbidden runtime call: hb_memory_atomic_cmpxchg128\n",stderr);abort();}
void hb_memory_has_atomic_cmpxchg128_handler(void){fputs("forbidden runtime call: hb_memory_has_atomic_cmpxchg128_handler\n",stderr);abort();}
void hb_memory_read(void){fputs("forbidden runtime call: hb_memory_read\n",stderr);abort();}
__thread unsigned long long hb_memory_watch_guest_ecx;
__thread unsigned long long hb_memory_watch_guest_edi;
__thread unsigned long long hb_memory_watch_guest_edx;
__thread unsigned long long hb_memory_watch_guest_esp;
__thread unsigned long long hb_memory_watch_guest_pc;
