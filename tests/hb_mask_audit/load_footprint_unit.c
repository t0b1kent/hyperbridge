/* Exact before/after LOAD excerpts, isolated with a bounded fake memory reader.
 * Not the full interpreter, not ARM64. Tests memory footprint and no writeback
 * on an active-lane read fault; hardware-page tests are in negative_controls.py. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
enum {HB_OK=0,HB_ERR_MEMORY_FAULT=-8};typedef int hb_result_t;
typedef struct {unsigned key;bool present;} hb_ir_instr_t;
typedef struct {size_t valid,calls,bytes;unsigned commits;} memory;
typedef struct {memory*memory;uint64_t k[8];} context;
static int evex_target_present(const hb_ir_instr_t*i){return i->present;}
static unsigned evex_target_mask(const hb_ir_instr_t*i){return i->key;}
static hb_result_t hb_memory_read(memory*m,uint64_t addr,void*p,size_t n){m->calls++;m->bytes+=n;if(addr>m->valid||n>m->valid-addr)return HB_ERR_MEMORY_FAULT;memset(p,0x5a,n);return HB_OK;}
static void trace_mem_watch_bytes(context*c,const char*a,uint64_t b,void*d,size_t n,void*x){(void)c;(void)a;(void)b;(void)d;(void)n;(void)x;}
static hb_result_t write_vec_reg_bytes_evex_masked(context*c,const hb_ir_instr_t*i,void*x,size_t b,unsigned l){(void)i;(void)x;(void)b;(void)l;c->memory->commits++;return HB_OK;}
static hb_result_t before(context*ctx,const hb_ir_instr_t*instr,size_t bytes,unsigned lane){
 uint8_t xmm[64]={0};uint64_t addr=0;hb_result_t r=HB_OK;
                r = hb_memory_read(ctx->memory, addr, xmm, bytes);
                if (r != HB_OK) return r;
                trace_mem_watch_bytes(ctx, "read", addr, xmm, bytes, NULL);
                return write_vec_reg_bytes_evex_masked(ctx, instr, xmm, bytes < 16 ? 16 : bytes, lane);
}
static hb_result_t after(context*ctx,const hb_ir_instr_t*instr,size_t bytes,unsigned lane){
 uint8_t xmm[64]={0};uint64_t addr=0;hb_result_t r=HB_OK;
                if (evex_target_present(instr) && evex_target_mask(instr) != 0) {
                    const uint64_t k = ctx->k[evex_target_mask(instr) & 7u];
                    /* Mask the memory footprint BEFORE reading, not just writeback.
                     * No read, translation or permission check for inactive lanes.
                     * Retire the vector only after every enabled lane succeeded. */
                    for (size_t off = 0; off < bytes; off += lane) {
                        if (!((k >> (off / lane)) & 1u)) continue;
                        const size_t n = bytes - off < lane ? bytes - off : lane;
                        r = hb_memory_read(ctx->memory, addr + off, xmm + off, n);
                        if (r != HB_OK) return r;
                        trace_mem_watch_bytes(ctx, "read", addr + off, xmm + off, n, NULL);
                    }
                } else {
                    r = hb_memory_read(ctx->memory, addr, xmm, bytes);
                    if (r != HB_OK) return r;
                    trace_mem_watch_bytes(ctx, "read", addr, xmm, bytes, NULL);
                }
                return write_vec_reg_bytes_evex_masked(ctx, instr, xmm, bytes < 16 ? 16 : bytes, lane);
}
int main(void){unsigned cases=0,old_faults=0;
 for(size_t bytes=16;bytes<=64;bytes*=2)for(unsigned lane=1;lane<=8;lane*=2)for(unsigned key=1;key<=7;key++){
  unsigned n=(unsigned)(bytes/lane);
  for(unsigned valid=0;valid<=n;valid++)for(unsigned pattern=0;pattern<4;pattern++){
   uint64_t full=n==64?UINT64_MAX:((UINT64_C(1)<<n)-1);
   uint64_t low=valid==64?UINT64_MAX:((UINT64_C(1)<<valid)-1);
   uint64_t k=pattern==0?0:pattern==1?full:pattern==2?low:(low^full);
   memory a={valid*lane,0,0,0},b=a;context ca={&a,{0}},cb={&b,{0}};ca.k[key]=cb.k[key]=k;hb_ir_instr_t ir={key,true};
   int ra=before(&ca,&ir,bytes,lane),rb=after(&cb,&ir,bytes,lane);bool fault=(k&~low&full)!=0;
   if((rb!=HB_OK)!=fault||b.commits!=(unsigned)!fault)return 1;
   if(!k&&(b.calls||b.bytes))return 2;
   if(ra!=HB_OK&&!fault)old_faults++;
   cases++;
  }
 }
 printf("{\"scope\":\"isolated exact read excerpts, not full interpreter\",\"cases\":%u,\"baseline_extra_faults\":%u,\"fixed_unexpected_faults\":0,\"masked_zero_reads\":0}\n",cases,old_faults);
 return old_faults?0:3;
}
