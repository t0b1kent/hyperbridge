/* Synthetic guest instructions; no proprietary image bytes. */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hb_codegen.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_env.h"
static unsigned checks,failures,cases;
#define CHECK(x) do { ++checks; if(!(x)){++failures;fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);} }while(0)
#define MUST(x) do { int ok_=!!(x); CHECK(ok_); if(!ok_)exit(2); }while(0)
extern void hb_codegen_set_scalar_native(bool);
extern void hb_codegen_set_no_idioms(bool);
static uint32_t word(const hb_codegen_buffer_t* b,size_t i){uint32_t w;memcpy(&w,b->code+i,4);return w;}
static void run(unsigned wide,unsigned triple,unsigned kind,unsigned fp,unsigned st) {
    uint8_t code[]={0xf3,0x0f,0x59,0xc1,0xf3,0x0f,0x58,0xc1,0xf3,0x0f,0x11,0x02};
    if(wide)code[0]=code[4]=code[8]=0xf2;
    if(!triple)memmove(code+4,code+8,4);
    hb_decoder_t* d=hb_decoder_create(HB_ARCH_X64,code,triple?12:8,0x100000);MUST(d);
    hb_ir_func_t* f=NULL;MUST(hb_lift_func_x64(d,&f)==HB_OK);hb_decoder_destroy(d);
    MUST(f && f->cfg && f->cfg->block_count==1);
    hb_ir_block_t* block=f->cfg->blocks[0];MUST(block->instr_count==(triple?3u:2u));
    hb_ir_instr_t* a=&block->instrs[triple?1:0];hb_ir_instr_t* s=&block->instrs[triple?2:1];
    switch(kind){
      case 1:s->src2.reg=HB_REG_XMM3;break;
      case 2:s->src1.size=wide?HB_SIZE_32:HB_SIZE_64;break;
      case 3:s->is_locked=true;break;
      case 4:s->zero_ymm_upper=true;break;
      case 5:s->guest_addr++;break;
      case 6:block->instrs[0].target=s->guest_addr;break;
      case 7:a->op=HB_IR_FMIN;break;
      case 8:a->src2.type=HB_OP_MEM;a->src2.mem.base=HB_REG_RCX;
             a->src2.mem.index=HB_REG_COUNT;a->src2.mem.scale=1;
             a->src2.size=wide?HB_SIZE_64:HB_SIZE_32;break;
      default:break;
    }
    setenv("MACRUNNER_HB_SCALAR_FP_FORWARD",fp?"1":"0",1);
    setenv("MACRUNNER_HB_SCALAR_FP_STORE_FORWARD",st?"1":"0",1);hb_env_refresh();
    hb_context_t* c=hb_context_create(HB_ARCH_X64,HB_BACKEND_JIT);MUST(c);
    hb_arm64_codegen_t* cg=hb_arm64_codegen_create(c);hb_codegen_buffer_t* b=hb_codegen_buffer_create(65536);MUST(cg && b);
    MUST(hb_arm64_codegen_block_with_cfg(cg,block,f->cfg,b)==HB_OK);
    uint32_t expect=(wide?0x9e660000u:0x1e260000u)|(2u<<5)|20u;
    unsigned carry=0;for(size_t p=0;p+4<=b->size;p+=4)if(word(b,p)==expect)carry++;
    unsigned admitted=st && (kind==0 || kind==8);
    CHECK(carry==admitted);
    if(admitted){
        size_t off=SIZE_MAX;
        for(size_t j=0;j<b->host_off_count;j++)if(b->host_instr[j]==(triple?2u:1u))off=b->host_off[j];
        MUST(off!=SIZE_MAX && off+4<=b->size);CHECK(word(b,off)==expect);
        /* Matching store starts with one register transfer, not the two old ctx loads. */
        CHECK((word(b,off)&0xffc003ffu)!=(0xf9400000u|(19u<<5)|20u));
    }
    ++cases;hb_codegen_buffer_destroy(b);hb_arm64_codegen_destroy(cg);hb_context_destroy(c);hb_ir_func_destroy(f);
}
int main(void){
    hb_codegen_set_scalar_native(true);hb_codegen_set_no_idioms(true);
    for(unsigned w=0;w<2;w++)for(unsigned t=0;t<2;t++)for(unsigned k=0;k<9;k++)
        for(unsigned f=0;f<2;f++)for(unsigned s=0;s<2;s++)run(w,t,k,f,s);
    printf("emission_checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;
}
