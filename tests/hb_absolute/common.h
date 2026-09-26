#ifndef HB_ABSOLUTE_COMMON_H
#define HB_ABSOLUTE_COMMON_H
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif
static inline void hb_need(FILE*f,void*p,size_t n){if(fread(p,1,n,f)!=n){fprintf(stderr,"truncated corpus\n");exit(2);}}
static inline uint64_t hb_le(FILE*f,unsigned n){uint8_t b[8];hb_need(f,b,n);uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)b[i]<<(i*8);return v;}
static inline unsigned hb_diff_words(const uint64_t*g,const uint64_t*e,const uint64_t*m,unsigned n){unsigned bad=0;for(unsigned i=0;i<n;i++)if((g[i]^e[i])&m[i])bad++;return bad;}
static inline int hb_comparator_selftest(void){
 uint64_t e[256]={0},g[256]={0},m[256];for(unsigned i=0;i<256;i++)m[i]=UINT64_MAX;
 for(unsigned i=0;i<256;i++)for(unsigned bit=0;bit<64;bit++){
  g[i]=UINT64_C(1)<<bit;if(hb_diff_words(g,e,m,256)!=1)return 1;g[i]=0;
 }
 g[0]=1;m[0]=0;if(hb_diff_words(g,e,m,256))return 1;m[0]=UINT64_MAX;
 if(hb_diff_words(g,e,m,256)!=1||hb_diff_words(g,e,m,256)!=1)return 1;
 uint64_t flags_good=0x45,flags_got=0x55,flags_mask=0x8c5;
 if(hb_diff_words(&flags_got,&flags_good,&flags_mask,1))return 1;
 flags_got^=1;if(hb_diff_words(&flags_got,&flags_good,&flags_mask,1)!=1)return 1;
 puts("{\"self_test\":\"pass\",\"single_bit_mutations\":16384,\"undefined_flags_ignored\":true,\"identical_wrong_backends_rejected\":true}");return 0;
}
#ifndef HB_ORACLE_COMPARATOR_ONLY
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_flags.h"
static inline void hb_set_vectors(hb_context_t*c,const uint8_t*p){for(unsigned r=0;r<16;r++){
 memcpy(c->regs.x64.xmm[r],p+r*64,16);memcpy(c->ymm_hi[r],p+r*64+16,16);memcpy(c->zmm_hi[r],p+r*64+32,32);
 memcpy(c->xmm_ext[r],p+(r+16)*64,16);memcpy(c->ymm_hi_ext[r],p+(r+16)*64+16,16);memcpy(c->zmm_hi_ext[r],p+(r+16)*64+32,32);
}}
static inline void hb_get_vectors(const hb_context_t*c,uint8_t*p){for(unsigned r=0;r<16;r++){
 memcpy(p+r*64,c->regs.x64.xmm[r],16);memcpy(p+r*64+16,c->ymm_hi[r],16);memcpy(p+r*64+32,c->zmm_hi[r],32);
 memcpy(p+(r+16)*64,c->xmm_ext[r],16);memcpy(p+(r+16)*64+16,c->ymm_hi_ext[r],16);memcpy(p+(r+16)*64+32,c->zmm_hi_ext[r],32);
}}
static inline hb_context_t*hb_new_context(int backend,void*code,size_t cs,void*stack,size_t ss,void*data,size_t ds){
 hb_context_t*c=hb_context_create(HB_ARCH_X64,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
 if(!c)return NULL;c->memory=hb_memory_create(0);c->config.fallback_enabled=false;
 if(!c->memory || hb_memory_sync_live_range(c->memory,(hb_gva_t)(uintptr_t)code,cs,HB_PERM_READ|HB_PERM_WRITE|HB_PERM_EXEC)!=HB_OK ||
 hb_memory_sync_live_range(c->memory,(hb_gva_t)(uintptr_t)stack,ss,HB_PERM_READ|HB_PERM_WRITE)!=HB_OK ||
 hb_memory_sync_live_range(c->memory,(hb_gva_t)(uintptr_t)data,ds,HB_PERM_READ|HB_PERM_WRITE)!=HB_OK){
  if(c->memory)hb_memory_destroy(c->memory);c->memory=NULL;hb_context_destroy(c);return NULL;
 }return c;
}
static inline void hb_free_context(hb_context_t*c){if(!c)return;hb_memory_t*m=c->memory;c->memory=NULL;hb_context_destroy(c);hb_memory_destroy(m);}
static inline hb_ir_func_t*hb_lift_at(uint8_t*at,size_t n){hb_decoder_t*d=hb_decoder_create(HB_ARCH_X64,at,n,(uint64_t)(uintptr_t)at);hb_ir_func_t*f=NULL;hb_result_t rc=d?hb_lift_func_x64(d,&f):HB_ERR_INTERNAL;if(d)hb_decoder_destroy(d);if(rc!=HB_OK||!f||f->has_unsupported){if(f)hb_ir_func_destroy(f);return NULL;}return f;}
/* Claude 26.09 (приёмка на Mac) — ТРИ ПЕРЕХОДНИКА К НАШЕЙ СРЕДЕ.
 * 1. Флаги живут в ctx->flags (+ отложенная запись), а не в regs.x64.rflags: вход задаём туда,
 *    выход собираем оттуда после материализации (доступного — неопределённое сверка всё равно маскирует).
 * 2. Лифтер HB поднимает ОДИН блок на функцию (до первого перехода), и исполнение функции кончается
 *    на границе блока. Настоящая среда поднимает следующий блок по новому pc — здесь то же, пока pc
 *    внутри программы. Без этого 500 из 500 случаев «граница переноса» были ошибкой исполнения у ОБОИХ
 *    исполнителей, а цикл восьми STORE проходил один оборот вместо всех. */
static inline void hb_set_rflags(hb_context_t*c,uint64_t f){
 c->regs.x64.rflags=f;memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
 c->flags.cf=(f>>0)&1;c->flags.pf=(f>>2)&1;c->flags.af=(f>>4)&1;c->flags.zf=(f>>6)&1;c->flags.sf=(f>>7)&1;c->flags.of=(f>>11)&1;
}
static inline uint64_t hb_get_rflags(hb_context_t*c,hb_result_t*fr){
 hb_result_t r=hb_lazy_flags_materialize_available(c,HB_FLAG_BIT_ALL);if(fr)*fr=r;
 uint64_t f=c->regs.x64.rflags&~(uint64_t)0x8d5;
 f|=(uint64_t)c->flags.cf|((uint64_t)c->flags.pf<<2)|((uint64_t)c->flags.af<<4)|((uint64_t)c->flags.zf<<6)|
    ((uint64_t)c->flags.sf<<7)|((uint64_t)c->flags.of<<11);
 return f;
}
static inline hb_result_t hb_run_program(hb_context_t*c,hb_ir_func_t*first,uint8_t*at,size_t len,int jit,hb_exec_result_t*total){
 const uint64_t base=(uint64_t)(uintptr_t)at,end=base+len;hb_ir_func_t*f=first;unsigned hops=0;hb_result_t rc=HB_OK;
 memset(total,0,sizeof(*total));
 for(;;){
  hb_exec_result_t out;memset(&out,0,sizeof(out));
  rc=hb_runtime_run(c,f,jit?HB_BACKEND_JIT:HB_BACKEND_INTERP,&out);
  if(f!=first)hb_ir_func_destroy(f);
  {uint64_t steps=total->steps_executed+out.steps_executed,blocks=total->blocks_executed+out.blocks_executed;
   *total=out;total->steps_executed=steps;total->blocks_executed=blocks;}
  if(rc!=HB_OK||out.result!=HB_OK||out.faulted||out.timed_out||!out.steps_executed)return rc;
  if(c->pc<base||c->pc>=end)return rc;
  if(++hops>200000){total->timed_out=true;return rc;}
  f=hb_lift_at((uint8_t*)(uintptr_t)c->pc,(size_t)(end-c->pc));
  if(!f){total->result=HB_ERR_UNSUPPORTED_OPCODE;return rc;}
 }
}
static inline void hb_seed_base(hb_context_t*c,void*at,void*stack,void*data){
 memset(&c->regs.x64,0,sizeof(c->regs.x64));memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
 c->pc=(uint64_t)(uintptr_t)at;c->regs.x64.rip=c->pc;c->regs.x64.rsp=(uint64_t)(uintptr_t)stack;
 c->regs.x64.rbx=(uint64_t)(uintptr_t)data;c->regs.x64.rdi=c->regs.x64.rbx+128;
 c->regs.x64.rax=UINT64_C(0x12345678fedcba98);c->regs.x64.rflags=2;c->mxcsr=0x1f80;c->last_result=HB_OK;
 hb_host_fpcr_apply_mxcsr(c->mxcsr);
}
#endif
#endif
