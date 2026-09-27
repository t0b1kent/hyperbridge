/* Independent synthetic baseline regression probe; not an engine change. */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "hb_codegen.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
static unsigned checks,failures;
#define CHECK(x) do {++checks;if(!(x)){++failures;fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);}}while(0)
#define MUST(x) do {int ok=!!(x);CHECK(ok);if(!ok)exit(2);}while(0)
extern void hb_codegen_set_scalar_native(bool);
extern void hb_codegen_set_no_idioms(bool);
struct callback_state { hb_context_t* ctx; unsigned calls; uint64_t addr,value,fp_value; size_t size; hb_result_t result; };
static hb_result_t reject_write(void* user,hb_gva_t addr,const void* input,size_t size) {
    struct callback_state* s=user;s->calls++;s->addr=addr;s->size=size;s->value=0;
    memcpy(&s->value,input,size<8?size:8);s->fp_value=s->ctx->regs.x64.xmm[0][0];return s->result;
}
static void run(uint8_t* code,uint8_t* data,size_t page,unsigned wide,unsigned unaligned,unsigned nan,unsigned kind,unsigned triple) {
    uint8_t bytes[]={0xf3,0x0f,0x59,0xc1,0xf3,0x0f,0x58,0xc1,0xf3,0x0f,0x11,0x02};
    if(wide)bytes[0]=bytes[4]=bytes[8]=0xf2;
    if(!triple)memmove(bytes+4,bytes+8,4);
    size_t code_size=triple?12:8;
    memcpy(code,bytes,code_size);
    hb_decoder_t* dec=hb_decoder_create(HB_ARCH_X64,code,code_size,(uintptr_t)code);MUST(dec);
    hb_ir_func_t* func=NULL;MUST(hb_lift_func_x64(dec,&func)==HB_OK);hb_decoder_destroy(dec);
    MUST(func && func->cfg && func->cfg->block_count==1 && func->cfg->blocks[0]->instr_count==(triple?3u:2u));
    hb_context_t* c[2]={hb_context_create(HB_ARCH_X64,HB_BACKEND_INTERP),hb_context_create(HB_ARCH_X64,HB_BACKEND_JIT)};
    struct callback_state cb[2]={{0},{0}};
    uint64_t target=(uintptr_t)data+(kind==1?32:page)-(unaligned?1:0);
    uint64_t initial=wide?0x3ff8000000000000ull:0x112233443fc00000ull;
    uint64_t expected=wide?0x4008000000000000ull:0x1122334440400000ull;
    if(triple)expected=wide?0x4014000000000000ull:0x1122334440a00000ull;
    if(nan)initial=expected=wide?0x7ff8000000012345ull:0x112233447fc12345ull;
    for(unsigned a=0;a<2;++a) {
        MUST(c[a]);c[a]->memory=hb_memory_create(0);MUST(c[a]->memory);
        MUST(hb_memory_sync_live_range(c[a]->memory,(uintptr_t)code,page,HB_PERM_READ|HB_PERM_EXEC)==HB_OK);
        MUST(hb_memory_sync_live_range(c[a]->memory,(uintptr_t)data,page,HB_PERM_READ|HB_PERM_WRITE)==HB_OK);
        c[a]->pc=c[a]->regs.x64.rip=(uintptr_t)code;c[a]->regs.x64.rdx=target;
        c[a]->mxcsr=0x1f80;c[a]->regs.x64.xmm[0][0]=initial;
        c[a]->regs.x64.xmm[0][1]=0x5566778899aabbccull;
        c[a]->regs.x64.xmm[1][0]=wide?0x4000000000000000ull:0x40000000u;
        cb[a].ctx=c[a];cb[a].result=kind==3?HB_ERR_ACCESS_PENDING:HB_ERR_MEMORY_FAULT;
        if(kind>=2)hb_memory_set_special_handlers(c[a]->memory,NULL,reject_write,&cb[a]);
    }
    hb_jit_runtime_t* rt=hb_jit_runtime_create(c[1]);MUST(rt);
    hb_exec_result_t out[2]={{0},{0}};
    memset(data,0x5a,page);
    hb_result_t ri=hb_runtime_run(c[0],func,HB_BACKEND_INTERP,&out[0]);
    uint8_t interp_bytes[8]={0};if(kind==1)memcpy(interp_bytes,(void*)(uintptr_t)target,wide?8:4);
    memset(data,0x5a,page);
    hb_result_t rj=hb_jit_runtime_run(rt,func,&out[1]);
    printf("store_pc wide=%u unaligned=%u nan=%u kind=%u triple=%u result=%d/%d faulted=%u/%u pc_delta=%lld/%lld rip_delta=%lld/%lld native_recover=%llu xmm0=%llx/%llx calls=%u/%u\n",
           wide,unaligned,nan,kind,triple,ri,rj,out[0].faulted,out[1].faulted,
           (long long)(c[0]->pc-(uintptr_t)code),(long long)(c[1]->pc-(uintptr_t)code),
           (long long)(c[0]->regs.x64.rip-(uintptr_t)code),(long long)(c[1]->regs.x64.rip-(uintptr_t)code),
           (unsigned long long)rt->guard_recover,(unsigned long long)c[0]->regs.x64.xmm[0][0],
           (unsigned long long)c[1]->regs.x64.xmm[0][0],cb[0].calls,cb[1].calls);
    CHECK(ri==rj && out[0].result==out[1].result);CHECK(out[0].faulted==out[1].faulted);
    CHECK(c[0]->pc==(uintptr_t)code+(kind==1?code_size:code_size-4));CHECK(c[1]->pc==c[0]->pc);
    CHECK(c[1]->regs.x64.rip==c[0]->regs.x64.rip);
    CHECK(memcmp(c[0]->regs.x64.xmm,c[1]->regs.x64.xmm,sizeof(c[0]->regs.x64.xmm))==0);
    CHECK(c[1]->regs.x64.xmm[0][0]==expected);
    if(unaligned || kind==1)CHECK(rt->guard_recover==0);
    if(kind==1){CHECK(out[1].result==HB_OK);CHECK(memcmp(interp_bytes,(void*)(uintptr_t)target,wide?8:4)==0);}
    else CHECK(out[1].result!=HB_OK);
    if(kind>=2){CHECK(cb[0].calls==cb[1].calls && cb[1].calls>0);CHECK(cb[0].size==cb[1].size);
        CHECK(cb[0].value==cb[1].value);CHECK(cb[1].fp_value==expected);CHECK(cb[0].addr==cb[1].addr);}
    CHECK(data[page-1]==0x5a);
    hb_jit_runtime_destroy(rt);hb_context_destroy(c[0]);hb_context_destroy(c[1]);hb_ir_func_destroy(func);
}
int main(void) {
    size_t page=(size_t)getpagesize();uint8_t* code=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    uint8_t* data=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    MUST(code!=MAP_FAILED && data!=MAP_FAILED);memset(data,0x5a,page);MUST(mprotect(data+page,page,PROT_NONE)==0);
    hb_memory_install_fault_handlers();hb_codegen_set_scalar_native(true);hb_codegen_set_no_idioms(true);
    for(unsigned wide=0;wide<2;++wide)for(unsigned unaligned=0;unaligned<2;++unaligned)
        for(unsigned nan=0;nan<2;++nan)for(unsigned kind=0;kind<4;++kind)
            for(unsigned triple=0;triple<2;++triple)run(code,data,page,wide,unaligned,nan,kind,triple);
    printf("store_pc_checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
