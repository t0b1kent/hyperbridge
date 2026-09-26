#define _GNU_SOURCE 1
#include "hb_context.h"
#include "hb_memory.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_flags.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stddef.h>
#include <xmmintrin.h>
unsigned long long hb_alloc_calls, hb_free_calls;
uintptr_t hb_alloc_site_pc[512];
unsigned long long hb_alloc_site_n[512], hb_alloc_site_bytes[512];
__thread int hb_trace_rsite;
static __thread unsigned memory_reads;
static __thread uint8_t *input_mem;
#define DATA_ADDRESS UINT64_C(0x70001000)
/* Exact byte store for one bounded ordinary RAM operand. No device callbacks,
   guest exception injection, code cache, or JIT memory translation is tested. */
hb_result_t hb_memory_read(hb_memory_t*m,hb_gva_t addr,void*out,size_t size){
 (void)m; if(addr<DATA_ADDRESS || size>32 || addr-DATA_ADDRESS>32-size){fprintf(stderr,"bad test read %llx + %zu\n",(unsigned long long)addr,size);abort();}
 memcpy(out,input_mem+(addr-DATA_ADDRESS),size);++memory_reads;return HB_OK;
}
hb_result_t hb_memory_write(hb_memory_t*m,hb_gva_t a,const void*b,size_t n){(void)m;(void)a;(void)b;(void)n;fputs("unexpected write in SSE read-only corpus\n",stderr);abort();}
#define RW(N,T) hb_result_t hb_memory_read_u##N(hb_memory_t*m,hb_gva_t a,T*out){return hb_memory_read(m,a,out,sizeof(*out));}\
 hb_result_t hb_memory_write_u##N(hb_memory_t*m,hb_gva_t a,T v){return hb_memory_write(m,a,&v,sizeof(v));}
RW(8,uint8_t) RW(16,uint16_t) RW(32,uint32_t) RW(64,uint64_t)
hb_region_t*hb_memory_find_region(hb_memory_t*m,hb_gva_t a){(void)m;static hb_region_t reg; if(a<DATA_ADDRESS||a>=DATA_ADDRESS+32)return NULL;reg.base=DATA_ADDRESS;reg.host_base=input_mem;reg.size=32;reg.perm=HB_PERM_READ;return &reg;}

typedef struct {uint8_t x[3][32],mem[32];uint64_t rax,flags;uint32_t mxcsr,pad;} sample_t;
typedef struct {uint8_t x[32];uint64_t rax,flags;uint32_t host_mxcsr,guest_mxcsr;int32_t status;uint32_t reads;} result_t;
_Static_assert(offsetof(sample_t,rax)==128,"input ABI");
_Static_assert(offsetof(sample_t,mxcsr)==144,"input ABI");
_Static_assert(offsetof(result_t,rax)==32,"output ABI");
_Static_assert(sizeof(result_t)==64,"output ABI");
extern void hb_native_execute(const sample_t*,void*,result_t*);
extern hb_result_t hb_interpreter_exec_one_for_jit(hb_context_t*,const hb_ir_instr_t*);
typedef struct {void *exec; hb_ir_func_t *func; unsigned ir_count;uint8_t code[16];unsigned len;} program_t;
static char err[256];
const char *oracle_error(void){return err;}
void *oracle_prepare(const uint8_t *code,unsigned len){
 if(!code||!len||len>15){snprintf(err,sizeof err,"invalid instruction length");return NULL;}
 hb_decoded_t d;memset(&d,0,sizeof d);int status=hb_decode_x64(code,len,0x140000000ULL,&d);
 if(status||d.len!=len){snprintf(err,sizeof err,"decode=%d length=%u expected=%u",status,d.len,len);return NULL;}
 hb_ir_func_t *f=NULL;status=hb_lift_unit_x64(&d,&f);
 if(status||!f||!f->cfg||!f->cfg->entry||!f->cfg->entry->instr_count){snprintf(err,sizeof err,"lift=%d empty=%d opcode=%d",status,!f,d.opcode);return NULL;}
 program_t*p=calloc(1,sizeof(*p));if(!p)abort();p->func=f;p->len=len;p->ir_count=f->cfg->entry->instr_count;memcpy(p->code,code,len);
 p->exec=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p->exec==MAP_FAILED)abort();memcpy(p->exec,code,len);((uint8_t*)p->exec)[len]=0xc3;
 if(mprotect(p->exec,4096,PROT_READ|PROT_EXEC))abort();return p;
}
unsigned oracle_ir_count(void*vp){return ((program_t*)vp)->ir_count;}
unsigned oracle_ir_opcode(void*vp){return ((program_t*)vp)->func->cfg->entry->instrs[0].op;}
void oracle_destroy(void*vp){program_t*p=vp;if(!p)return;munmap(p->exec,4096);hb_ir_func_destroy(p->func);free(p);}
void oracle_run(void*vp,const sample_t*s,unsigned mode,result_t*out){
 program_t*p=vp;memset(out,0,sizeof(*out));
 if(mode==0){hb_native_execute(s,p->exec,out);out->guest_mxcsr=out->host_mxcsr;return;}
 hb_context_t c;hb_memory_t m;memset(&c,0,sizeof c);memset(&m,0,sizeof m);
 c.arch=HB_ARCH_X64;c.memory=&m;c.pc=0x140000000ULL;c.mxcsr=s->mxcsr;c.regs.x64.rax=s->rax;c.regs.x64.rbx=DATA_ADDRESS;
 for(unsigned i=0;i<3;i++){memcpy(c.regs.x64.xmm[i],s->x[i],16);memcpy(c.ymm_hi[i],s->x[i]+16,16);}
 c.regs.x64.rflags=s->flags;c.flags.cf=(s->flags>>0)&1;c.flags.pf=(s->flags>>2)&1;c.flags.af=(s->flags>>4)&1;c.flags.zf=(s->flags>>6)&1;c.flags.sf=(s->flags>>7)&1;c.flags.of=(s->flags>>11)&1;
 memory_reads=0;input_mem=(uint8_t*)s->mem;
 unsigned saved=_mm_getcsr();_mm_setcsr(mode==1?s->mxcsr:0x1f80);
 /* Same public interpreter entry used by the generated helper call. */
 for(unsigned j=0;j<p->ir_count;j++){out->status=hb_interpreter_exec_one_for_jit(&c,&p->func->cfg->entry->instrs[j]);if(out->status)break;}
 out->host_mxcsr=_mm_getcsr();_mm_setcsr(saved);
 memcpy(out->x,c.regs.x64.xmm[0],16);memcpy(out->x+16,c.ymm_hi[0],16);out->rax=c.regs.x64.rax;
 out->flags=(s->flags&~UINT64_C(0x8d5))|((uint64_t)c.flags.cf)|((uint64_t)c.flags.pf<<2)|((uint64_t)c.flags.af<<4)|((uint64_t)c.flags.zf<<6)|((uint64_t)c.flags.sf<<7)|((uint64_t)c.flags.of<<11);
 out->guest_mxcsr=c.mxcsr;out->reads=memory_reads;
}
