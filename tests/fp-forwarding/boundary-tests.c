/* Synthetic public-API tests; contains no proprietary guest code. */
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
#include "hb_env.h"
static unsigned checks, failures, tested;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); } } while(0)
#define REQUIRE(x) do { int ok_=!!(x); CHECK(ok_); if(!ok_) exit(2); } while(0)
extern void hb_codegen_set_scalar_native(bool);
extern void hb_codegen_set_no_idioms(bool);
static void gate(int n) { setenv("MACRUNNER_HB_SCALAR_FP_FORWARD",n?"1":"0",1); hb_env_refresh(); }
static hb_ir_func_t* lift(uint8_t* code,size_t n) {
    hb_decoder_t* d=hb_decoder_create(HB_ARCH_X64,code,n,(uintptr_t)code);
    hb_ir_func_t* f=NULL; REQUIRE(d); REQUIRE(hb_lift_func_x64(d,&f)==HB_OK);
    hb_decoder_destroy(d); REQUIRE(f && f->cfg && f->cfg->block_count); return f;
}
static hb_codegen_buffer_t* emit(hb_context_t* c,hb_ir_func_t* f,int on) {
    gate(on); hb_codegen_buffer_t* b=hb_codegen_buffer_create(65536);
    hb_arm64_codegen_t* cg=hb_arm64_codegen_create(c); REQUIRE(b && cg);
    REQUIRE(hb_arm64_codegen_block_with_cfg(cg,f->cfg->blocks[0],f->cfg,b)==HB_OK);
    hb_arm64_codegen_destroy(cg); return b;
}
static unsigned forwarded(const hb_codegen_buffer_t* b) {
    unsigned n=0;
    for(size_t i=0;i+4<=b->size;i+=4) {
        uint32_t w; memcpy(&w,b->code+i,4);
        uint32_t op=w & ~((31u<<16)|(31u<<5)|31u|(1u<<22));
        if ((op==0x1e202800 || op==0x1e203800 || op==0x1e200800 || op==0x1e201800) &&
            (w&31)==2 && ((w>>5)&31)==2) ++n;
    } return n;
}
static void admission(uint8_t* code) {
    /* MULSS xmm0,xmm1; ADDSS xmm0,xmm2. */
    const uint8_t normal[]={0xf3,0x0f,0x59,0xc1,0xf3,0x0f,0x58,0xc2};
    for(unsigned kind=0;kind<12;++kind) {
        memcpy(code,normal,sizeof(normal)); hb_ir_func_t* f=lift(code,sizeof(normal));
        hb_ir_block_t* block=f->cfg->blocks[0];
        if(block->instr_count!=2) { char* text=hb_ir_func_to_string(f);fprintf(stderr,"fixture IR: %s\n",text);free(text); }
        REQUIRE(block->instr_count==2);
        hb_ir_instr_t* a=&block->instrs[0]; hb_ir_instr_t* b=&block->instrs[1];
        hb_context_t* c=hb_context_create(HB_ARCH_X64,HB_BACKEND_JIT); REQUIRE(c);
        switch(kind) {
          case 1:b->src2.reg=b->dst.reg;break; /* alias must forward both inputs */
          case 2:b->zero_ymm_upper=true;break;
          case 3:b->dst.reg=b->src1.reg=HB_REG_XMM3;break;
          case 4:b->op=HB_IR_ADDSD;break;
          case 5:b->op=HB_IR_FMIN;break;
          case 6:b->is_locked=true;break;
          case 7:b->src2.type=HB_OP_MEM;b->src2.mem.base=HB_REG_RDX;
                 b->src2.mem.index=HB_REG_COUNT;b->src2.mem.scale=1;b->src2.size=HB_SIZE_32;break;
          case 8:b->guest_addr++;break;
          case 9: { /* Explicit other CFG block branch to midpoint. */
              hb_ir_block_t* extra=hb_ir_block_create(99,(uintptr_t)code+64);
              hb_ir_instr_t j={0};j.op=HB_IR_JMP;j.target=b->guest_addr;j.guest_addr=(uintptr_t)code+64;j.guest_len=2;
              hb_ir_builder_t* builder=hb_ir_builder_create(f);REQUIRE(builder);
              hb_ir_builder_set_block(builder,extra);*hb_ir_emit(builder,HB_IR_JMP)=j;
              hb_ir_builder_destroy(builder);hb_ir_cfg_add_block(f->cfg,extra);break; }
          case 10: { hb_ir_block_t* extra=hb_ir_block_create(100,b->guest_addr);
              hb_ir_cfg_add_block(f->cfg,extra);break; }
          case 11:a->target=b->guest_addr;break; /* conservative same-unit target */
        }
        hb_codegen_buffer_t* off=emit(c,f,0);hb_codegen_buffer_t* on=emit(c,f,1);
        CHECK(forwarded(off)==0); CHECK(forwarded(on)==(kind<2 || kind==7?1u:0u));
        if(kind<2 || kind==7) {
            CHECK(on->host_off_count==2);CHECK(!on->host_off_overflow);
            CHECK(on->host_instr[0]==0 && on->host_instr[1]==1);
            CHECK(on->host_off[1]>on->host_off[0]);
            unsigned second=on->host_off[1]; uint32_t w=0;memcpy(&w,on->code+second,4);
            if(kind==0) { /* Only source2 load remains at second instruction. */
                CHECK((w & 0xffc003ffu)==(0xbd400000u|(19u<<5)|1u));
            } else if(kind==1) CHECK(((w>>5)&31)==2 && (w&31)==2); /* begins with FP arithmetic */
        } else { CHECK(off->size==on->size);CHECK(memcmp(off->code,on->code,off->size)==0); }
        ++tested; hb_codegen_buffer_destroy(off);hb_codegen_buffer_destroy(on);
        hb_context_destroy(c);hb_ir_func_destroy(f);
    }
}
static void fault_case(uint8_t* code,uint8_t* data,size_t page,unsigned stage,unsigned unaligned,unsigned wide,int on) {
    /* MULSS xmm0,[rdx] or xmm1; ADDSS xmm0,xmm2; optional MOV eax,[rdx]. */
    uint8_t bytes[]={0xf3,0x0f,0x59,0xc1,0xf3,0x0f,0x58,0xc2,0x8b,0x02};
    if(stage==0)bytes[3]=0x02;
    if(stage>=2)bytes[7]=0x02;
    if(wide)bytes[0]=bytes[4]=0xf2;
    size_t n=stage==1?10:8;memcpy(code,bytes,n);hb_ir_func_t* f=lift(code,n);
    hb_context_t* c[2]={hb_context_create(HB_ARCH_X64,HB_BACKEND_INTERP),hb_context_create(HB_ARCH_X64,HB_BACKEND_JIT)};
    uint64_t bad=(uintptr_t)data+page-(unaligned?1:0);
    for(unsigned k=0;k<2;++k) {
        REQUIRE(c[k]);c[k]->memory=hb_memory_create(0);REQUIRE(c[k]->memory);
        REQUIRE(hb_memory_sync_live_range(c[k]->memory,(uintptr_t)code,page,HB_PERM_READ|HB_PERM_EXEC)==HB_OK);
        REQUIRE(hb_memory_sync_live_range(c[k]->memory,(uintptr_t)data,page,HB_PERM_READ|HB_PERM_WRITE)==HB_OK);
        c[k]->pc=c[k]->regs.x64.rip=(uintptr_t)code;c[k]->regs.x64.rdx=bad;
        c[k]->regs.x64.rax=0xdeadbeef;c[k]->mxcsr=0x1f80;
        c[k]->regs.x64.xmm[0][0]=wide?0x3ff8000000000000ull:0x112233443fc00000ull; /* 1.5 */
        if(stage==3)c[k]->regs.x64.xmm[0][0]=wide?0x7ff8000000012345ull:0x112233447fc12345ull;
        c[k]->regs.x64.xmm[0][1]=0x5566778899aabbccull;
        c[k]->regs.x64.xmm[1][0]=wide?0x4000000000000000ull:0x40000000; /* 2 */
        c[k]->regs.x64.xmm[2][0]=wide?0x4010000000000000ull:0x40800000; /* 4 */
    }
    gate(on);hb_jit_runtime_t* rt=hb_jit_runtime_create(c[1]);REQUIRE(rt);
    hb_exec_result_t out[2]={{0},{0}};
    hb_result_t a=hb_runtime_run(c[0],f,HB_BACKEND_INTERP,&out[0]);
    hb_result_t b=hb_jit_runtime_run(rt,f,&out[1]);
    CHECK(a==b);CHECK(out[0].result==out[1].result);CHECK(out[1].faulted);
    CHECK(out[1].result==HB_ERR_MEMORY_FAULT);
    CHECK(c[1]->pc==(uintptr_t)code+(stage>=2?4:stage?8:0));CHECK(c[1]->regs.x64.rip==c[1]->pc);
    CHECK(c[0]->pc==c[1]->pc);
    CHECK(memcmp(c[0]->regs.x64.xmm,c[1]->regs.x64.xmm,sizeof(c[0]->regs.x64.xmm))==0);
    uint64_t expected32[]={0x112233443fc00000ull,0x1122334440e00000ull,0x1122334440400000ull,0x112233447fc12345ull};
    uint64_t expected64[]={0x3ff8000000000000ull,0x401c000000000000ull,0x4008000000000000ull,0x7ff8000000012345ull};
    CHECK(c[1]->regs.x64.xmm[0][0]==(wide?expected64[stage]:expected32[stage]));
    CHECK(c[1]->regs.x64.xmm[0][1]==0x5566778899aabbccull);
    CHECK(c[1]->regs.x64.rax==0xdeadbeef);
    printf("fault stage=%u unaligned=%u wide=%u gate=%d native_recover=%llu pc_delta=%llu\n",stage,unaligned,wide,on,
           (unsigned long long)rt->guard_recover,(unsigned long long)(c[1]->pc-(uintptr_t)code));
    ++tested;hb_jit_runtime_destroy(rt);hb_context_destroy(c[0]);hb_context_destroy(c[1]);hb_ir_func_destroy(f);
}
int main(void) {
    size_t page=(size_t)getpagesize();uint8_t* code=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    uint8_t* data=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    REQUIRE(code!=MAP_FAILED && data!=MAP_FAILED);memset(data,0,page);
    REQUIRE(mprotect(data+page,page,PROT_NONE)==0);hb_memory_install_fault_handlers();
    hb_codegen_set_scalar_native(true);hb_codegen_set_no_idioms(true);
    admission(code);
    for(unsigned stage=0;stage<4;++stage)for(unsigned u=0;u<2;++u)for(unsigned wide=0;wide<2;++wide)for(int on=0;on<2;++on)
        fault_case(code,data,page,stage,u,wide,on);
    munmap(code,page);munmap(data,page*2);
    printf("boundary_checks=%u failures=%u cases=%u\n",checks,failures,tested);
    return failures?1:0;
}
