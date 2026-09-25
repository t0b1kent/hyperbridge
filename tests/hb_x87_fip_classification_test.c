/* M33: preserve x87 FIP across 14 real non-floating x86 instructions.
 * Leading NOP makes the instruction address CODE+1. Full x87 state is strict.
 * HOST_CALL is explicit internal IR only; no guest encoding/callback claim.
 * Positive FLD1/FISTTP/FI controls retain existing real x87 FIP updates.
 * Memory and arithmetic failures retain existing errors, not new #DE/#BR/#MF
 * delivery, GPR atomicity or x87 fault-time FIP guarantees. FNSTENV checks only
 * the existing 32-bit FIP transport. No native x86/Wine/FEX execution here. */
#pragma STDC FENV_ACCESS ON
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_BYTES=16384 };
enum { PUSHA,POPA,AAA,AAS,AAM,AAD,DAA,DAS,BOUND,ARPL,LDS,LES,LFS,LGS,FLD1,FISTTP,FIADD,ILLEGAL,HOST_CALL };
enum { ORDINARY,DENIED,ZERO_BASE,OUTSIDE_BOUNDS,POSITIVE,TYPED,INTERNAL,TRANSPORT };
enum { FPSTATE,RESULT,EXECUTION,HOST,DECODE,CATEGORIES };
static const uint64_t CODE=UINT64_C(0x6700000),DATA=UINT64_C(0x6710000),STACK=UINT64_C(0x6720000),ENV=UINT64_C(0x6730000);
static unsigned checks,failures,calls,ordinary_calls,failure_calls,positive_calls,typed_calls,internal_calls,transport_calls;
static unsigned category_failures[CATEGORIES];
static char phase[200]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,RESULT);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(8*i));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
static uint32_t get32(const uint8_t *p){uint32_t n=0;for(unsigned i=0;i<4;++i)n|=(uint32_t)p[i]<<(8*i);return n;}
typedef struct {const char *name;unsigned kind;uint8_t bytes[3];unsigned len;int decoded;hb_ir_op_t ir;} form_t;
#define F(N,K,A,B,C,L,D,I) {N,K,{A,B,C},L,D,I}
static const form_t forms[]={
    F("PUSHA",PUSHA,0x60,0,0,1,HB_INS_PUSHA,HB_IR_PUSHA),F("POPA",POPA,0x61,0,0,1,HB_INS_POPA,HB_IR_POPA),
    F("AAA",AAA,0x37,0,0,1,HB_INS_AAA,HB_IR_AAA),F("AAS",AAS,0x3f,0,0,1,HB_INS_AAS,HB_IR_AAS),
    F("AAM",AAM,0xd4,0x0a,0,2,HB_INS_AAM,HB_IR_AAM),F("AAD",AAD,0xd5,0x0a,0,2,HB_INS_AAD,HB_IR_AAD),
    F("DAA",DAA,0x27,0,0,1,HB_INS_DAA,HB_IR_DAA),F("DAS",DAS,0x2f,0,0,1,HB_INS_DAS,HB_IR_DAS),
    F("BOUND",BOUND,0x62,0x01,0,2,HB_INS_BOUND,HB_IR_BOUND),F("ARPL",ARPL,0x63,0xc8,0,2,HB_INS_ARPL,HB_IR_ARPL),
    F("LDS",LDS,0xc5,0x01,0,2,HB_INS_LDS,HB_IR_LDS),F("LES",LES,0xc4,0x01,0,2,HB_INS_LES,HB_IR_LES),
    F("LFS",LFS,0x0f,0xb4,0x01,3,HB_INS_LFS,HB_IR_LFS),F("LGS",LGS,0x0f,0xb5,0x01,3,HB_INS_LGS,HB_IR_LGS),
    F("FLD1",FLD1,0xd9,0xe8,0,2,HB_INS_X87_FLD,HB_IR_X87_FLD),
    F("FISTTP32",FISTTP,0xdb,0x09,0,2,HB_INS_X87_FISTTP,HB_IR_X87_FISTTP),
    F("FIADD32",FIADD,0xda,0x01,0,2,HB_INS_X87_FI,HB_IR_X87_FI),
    F("UD2",ILLEGAL,0x0f,0x0b,0,2,HB_INS_UD,HB_IR_FAULT),
    F("internal HOST_CALL",HOST_CALL,0x90,0,0,1,HB_INS_NOP,HB_IR_HOST_CALL)
};
#undef F
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;unsigned scenario,len;uint8_t code[16];} fixture_t;
static void install(hb_x87_state_t *x,unsigned p,uint16_t se,uint64_t sig,uint64_t preview)
{
    memcpy(&x->st[p],&preview,8);put64(x->st_ext[p],sig);put16(x->st_ext[p]+8,se);
    x->st_ext_valid|=(uint8_t)(1u<<p);x->tag_word=(uint16_t)(x->tag_word&~(3u<<(2*p)));
}
static int seed(fixture_t *f,unsigned top,unsigned profile)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));
    if(c->arch==HB_ARCH_X86){
        c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=2;c->regs.x86.eax=0x12340017;c->regs.x86.ecx=(uint32_t)DATA;
        c->regs.x86.edx=0x22334455;c->regs.x86.ebx=0x33445566;c->regs.x86.esp=(uint32_t)(STACK+128);
        c->regs.x86.ebp=0x55667788;c->regs.x86.esi=0x66778899;c->regs.x86.edi=0x778899aa;
        memset(&c->x87_64,0x49,sizeof(c->x87_64));
    }else{c->regs.x64.rip=CODE;c->regs.x64.rflags=2;c->regs.x64.rcx=DATA;c->regs.x64.rsp=STACK+128;}
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;
    x->control_word=0x037f;x->status_word=(uint16_t)((top<<11)|0x4524|((top&1)?0x40:0));
    x->last_x87_ip=profile?UINT32_C(0xfedcba98):UINT32_C(0x12345678);
    for(unsigned i=0;i<8;++i)install(x,(top+i)&7,0x4002,
        UINT64_C(0x8000000000000000)+(uint64_t)i*UINT64_C(0x1000000000000000),
        UINT64_C(0x4020000000000000)+(uint64_t)i*UINT64_C(0x2000000000000));
    x->st_ext_valid&=(uint8_t)~(1u<<((top+4)&7));x->tag_word|=(uint16_t)(3u<<(2*((top+6)&7)));
    if(f->form->kind==FLD1)x->tag_word|=(uint16_t)(3u<<(2*((top+7)&7)));
    if(f->form->kind==FISTTP)install(x,top,0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000));
    if(f->form->kind==FIADD)install(x,top,0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000));
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){0};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;
    c->fs_base=0x10000;c->gs_base=0x20000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr=0;c->last_fault_addr_valid=0;c->last_fault_pc=0;c->step_limit=16;c->block_limit=2;
    uint8_t data[32],stack[192],env[32];memset(data,0xa5,sizeof(data));memset(stack,0x6b,sizeof(stack));memset(env,0x79,sizeof(env));
    put32(data,3);put32(data+4,9);
    for(unsigned i=0;i<8;++i)put32(stack+128+4*i,UINT32_C(0x11110000)+i);
    switch(f->form->kind){
        case AAA:case AAS: c->regs.x86.eax=profile?0x1234020b:0x12340017;break;
        case AAM:c->regs.x86.eax=profile?0x12340063:0x12340017;break;
        case AAD:c->regs.x86.eax=profile?0x12340909:0x12340203;break;
        case DAA:c->regs.x86.eax=profile?0x1234009a:0x1234000a;break;
        case DAS:c->regs.x86.eax=profile?0x1234000b:0x12340010;c->flags.af=!profile;break;
        case BOUND:c->regs.x86.eax=f->scenario==OUTSIDE_BOUNDS?10:profile?9:3;break;
        case ARPL:c->regs.x86.eax=profile?0x12340013:0x12340010;c->regs.x86.ecx=profile?1:3;c->flags.zf=profile;break;
        case LDS:case LES:case LFS:case LGS:put32(data,UINT32_C(0x13572460)+profile);put16(data+4,(uint16_t)(profile?0x2b:0x23));break;
        default:break;
    }
    if(!check(hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_protect(c->memory,STACK,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned data permissions"))return 0;
    if(!check(hb_memory_write(c->memory,DATA,data,sizeof(data))==HB_OK&&hb_memory_write(c->memory,STACK,stack,sizeof(stack))==HB_OK&&hb_memory_write(c->memory,ENV,env,sizeof(env))==HB_OK,"seed operand and environment images"))return 0;
    if(f->scenario==DENIED){
        uint64_t addr=f->form->kind==PUSHA||f->form->kind==POPA?STACK:DATA;
        unsigned perms=f->form->kind==PUSHA?HB_PERM_READ:HB_PERM_WRITE;
        if(!check(hb_memory_protect(c->memory,addr,PAGE_BYTES,perms)==HB_OK,"isolate first memory access denial"))return 0;
    }
    return 1;
}
static void check_x87(fixture_t *f,const hb_context_t *before)
{
    hb_x87_state_t expected=*hb_context_x87((hb_context_t *)before),*actual=hb_context_x87(f->ctx);
    if(f->scenario==POSITIVE){
        expected.last_x87_ip=(uint32_t)(CODE+1);
        unsigned p=expected.top;
        if(f->form->kind==FLD1){
            p=(p+7)&7;expected.top=p;expected.status_word=(uint16_t)((expected.status_word&~0x3a00u)|(p<<11));
            /* Existing FLD1 constant path materializes exact ext80 +1.0. */
            install(&expected,p,0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000));
        }else if(f->form->kind==FISTTP){
            expected.tag_word|=(uint16_t)(3u<<(2*p));expected.top=(p+1)&7;
            expected.status_word=(uint16_t)((expected.status_word&~0x3a00u)|(expected.top<<11));
        }else{
            /* M48 exact FIADD32 result: 2+3=5; retain the FIP/status scope below. */
            install(&expected,p,0x4001,UINT64_C(0xa000000000000000),UINT64_C(0x4014000000000000));
        }
        /* Non-FIP condition-code details of positive arithmetic are not expanded. */
        expected.status_word=(uint16_t)((expected.status_word&~0x4700u)|(actual->status_word&0x4700u));
    }
    check_kind(!memcmp(actual,&expected,sizeof(expected)),"full physical x87 state and existing FIP classification",FPSTATE);
    if(f->ctx->arch==HB_ARCH_X86){
        check_kind(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 preserved",FPSTATE);
        check_kind(!memcmp(f->ctx->regs.x86.xmm,before->regs.x86.xmm,sizeof(before->regs.x86.xmm)),"XMM preserved",FPSTATE);
    }else check_kind(!memcmp(f->ctx->regs.x64.xmm,before->regs.x64.xmm,sizeof(before->regs.x64.xmm)),"XMM preserved",FPSTATE);
    check_kind(f->ctx->mxcsr==before->mxcsr&&!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"MXCSR and upper vectors preserved",FPSTATE);
}
static void check_visible(fixture_t *f,const hb_context_t *before,unsigned profile)
{
    hb_context_t *c=f->ctx;uint8_t data[32];
    if(f->scenario==DENIED||f->scenario==ZERO_BASE||f->scenario==OUTSIDE_BOUNDS||f->scenario==TYPED||f->scenario==INTERNAL)return;
    switch(f->form->kind){
        case PUSHA:{
            check(c->regs.x86.esp==before->regs.x86.esp-32,"PUSHA final ESP");
            if(check(hb_memory_read(c->memory,STACK+96,data,32)==HB_OK,"read actual PUSHA image")){
                uint32_t answer[8]={before->regs.x86.edi,before->regs.x86.esi,before->regs.x86.ebp,before->regs.x86.esp,before->regs.x86.ebx,before->regs.x86.edx,before->regs.x86.ecx,before->regs.x86.eax};
                for(unsigned i=0;i<8;++i)check(get32(data+4*i)==answer[i],"PUSHA independently ordered dword");
            }break;}
        case POPA:check(c->regs.x86.edi==0x11110000&&c->regs.x86.esi==0x11110001&&c->regs.x86.ebp==0x11110002&&c->regs.x86.ebx==0x11110004&&c->regs.x86.edx==0x11110005&&c->regs.x86.ecx==0x11110006&&c->regs.x86.eax==0x11110007&&c->regs.x86.esp==STACK+160,"POPA register order and skipped saved ESP");break;
        case AAA:check(c->regs.x86.eax==(profile?0x12340301u:0x12340007u)&&c->flags.af==(profile!=0)&&c->flags.cf==(profile!=0),"AAA defined adjustment");break;
        case AAS:check(c->regs.x86.eax==(profile?0x12340105u:0x12340007u)&&c->flags.af==(profile!=0)&&c->flags.cf==(profile!=0),"AAS defined adjustment");break;
        case AAM:check(c->regs.x86.eax==(profile?0x12340909u:0x12340203u),"AAM quotient and remainder");break;
        case AAD:check(c->regs.x86.eax==(profile?0x12340063u:0x12340017u),"AAD decimal combination");break;
        case DAA:check(c->regs.x86.eax==(profile?0x12340000u:0x12340010u)&&c->flags.af&&c->flags.cf==(profile!=0),"DAA defined packed-decimal correction");break;
        case DAS:check(c->regs.x86.eax==(profile?0x12340005u:0x1234000au)&&c->flags.af&&!c->flags.cf,"DAS defined packed-decimal correction");break;
        case BOUND:check(c->regs.x86.eax==(profile?9u:3u),"BOUND inclusive endpoints complete");break;
        case ARPL:check(c->regs.x86.eax==0x12340013u&&c->flags.zf==(profile==0),"ARPL adjustment and no-adjustment RPL cases");break;
        case LDS:case LES:case LFS:case LGS:{
            unsigned k=f->form->kind;uint16_t sel=k==LDS?c->seg_ds:k==LES?c->seg_es:k==LFS?c->seg_fs:c->seg_gs;
            check(c->regs.x86.eax==UINT32_C(0x13572460)+profile&&sel==(profile?0x2b:0x23),"far-pointer offset and selector");
            if(k==LFS)check(c->fs_base==0,"existing flat LFS base");if(k==LGS)check(c->gs_base==0,"existing flat LGS base");break;}
        case FISTTP:check(hb_memory_read(c->memory,DATA,data,4)==HB_OK&&get32(data)==7,"positive FISTTP actual integer store");break;
        default:break;
    }
    if(f->scenario==TRANSPORT)check(hb_memory_read(c->memory,ENV+12,data,4)==HB_OK&&get32(data)==hb_context_x87((hb_context_t *)before)->last_x87_ip,"guest FNSTENV transports retained 32-bit FIP");
}
static void run_case(fixture_t *f,unsigned top,unsigned profile)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    unsigned host=(top+profile)&3;
    snprintf(phase,sizeof(phase),"%s %s %s scenario=%u TOP=%u profile=%u",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,f->scenario,top,profile);
    if(!seed(f,top,profile))return;hb_context_t before;memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};
    hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++calls;
    switch(f->scenario){case ORDINARY:++ordinary_calls;break;case POSITIVE:++positive_calls;break;case TYPED:++typed_calls;break;case INTERNAL:++internal_calls;break;case TRANSPORT:++transport_calls;break;default:++failure_calls;break;}
    check_kind(actual_rc==modes[host]&&actual_flags==wanted,"host RC/status unchanged",HOST);
    hb_result_t expected=f->scenario==DENIED?HB_ERR_MEMORY_FAULT:f->scenario==ZERO_BASE||f->scenario==OUTSIDE_BOUNDS?HB_ERR_EXEC_FAULT:f->scenario==TYPED?HB_ERR_EXEC_FAULT:f->scenario==INTERNAL?HB_ERR_UNSUPPORTED_OPCODE:HB_OK;
    if(expected==HB_OK)check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+f->len,"actual guest operation completes",EXECUTION);
    else check_kind((result==HB_OK||result==expected)&&out.result==expected&&out.faulted&&!out.timed_out,"existing isolated error result",EXECUTION);
    if(f->scenario==TYPED)check_kind(f->ctx->last_fault_kind==HB_FAULT_KIND_ILLEGAL&&f->ctx->last_fault_addr_valid&&f->ctx->last_fault_addr==CODE+1&&f->ctx->last_fault_pc==CODE+1,"existing typed illegal metadata after NOP",EXECUTION);
    check_x87(f,&before);check_visible(f,&before,profile);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static int make_internal(fixture_t *f)
{
    f->func=hb_ir_func_create(CODE,2);if(!check(f->func!=NULL,"create explicit internal IR function"))return 0;
    hb_ir_block_t *b=hb_ir_block_create(0,CODE);if(!check(b!=NULL,"create internal IR block"))return 0;hb_ir_cfg_add_block(f->func->cfg,b);
    if(!check(f->func->cfg->block_count==1,"attach internal block")){hb_ir_block_destroy(b);return 0;}
    f->func->cfg->entry=b;
    hb_ir_builder_t *builder=hb_ir_builder_create(f->func);if(!check(builder!=NULL,"create internal builder"))return 0;
    hb_ir_instr_t *nop=hb_ir_emit(builder,HB_IR_NOP);int ok=check(nop!=NULL,"emit internal NOP");if(nop){nop->guest_addr=CODE;nop->guest_len=1;}
    hb_ir_instr_t *call=hb_ir_emit_host_call(builder,0);ok=check(call!=NULL,"emit unsupported internal placeholder")&&ok;if(call){call->guest_addr=CODE+1;call->guest_len=1;}
    hb_ir_builder_destroy(builder);return ok;
}
static void run_form(unsigned form_index,hb_arch_t arch,hb_backend_t backend,unsigned scenario)
{
    fixture_t f={0};f.form=&forms[form_index];f.scenario=scenario;f.code[0]=0x90;memcpy(f.code+1,f.form->bytes,f.form->len);f.len=1+f.form->len;
    if(scenario==ZERO_BASE)f.code[2]=0;
    if(scenario==TRANSPORT){f.code[f.len++]=0xd9;f.code[f.len++]=0x35;put32(f.code+f.len,(uint32_t)ENV);f.len+=4;}
    snprintf(phase,sizeof(phase),"%s %s setup %u",arch==HB_ARCH_X86?"x86":"x64",f.form->name,scenario);
    f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create context"))goto done;f.ctx->memory=hb_memory_create(0);if(!check(f.ctx->memory!=NULL,"create private memory"))goto done;
    uint64_t addresses[]={CODE,DATA,STACK,ENV};for(unsigned i=0;i<4;++i)if(!check(hb_memory_map_private(f.ctx->memory,addresses[i],PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned region"))goto done;
    if(!check(hb_memory_write(f.ctx->memory,CODE,f.code,f.len)==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"install bounded code"))goto done;
    if(scenario==INTERNAL){if(!make_internal(&f))goto done;}
    else{
        hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(f.code+1,f.form->len,CODE+1,&d):hb_decode_x64(f.code+1,f.form->len,CODE+1,&d);
        check_kind(r==HB_OK&&d.len==f.form->len&&(int)d.opcode==f.form->decoded,"actual guest encoding identity",DECODE);
        f.decoder=hb_decoder_create(arch,f.code,f.len,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
        r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift guest code",EXECUTION))goto done;
        unsigned matches=0;if(f.func->cfg)for(size_t b=0;b<f.func->cfg->block_count;++b)for(size_t i=0;i<f.func->cfg->blocks[b]->instr_count;++i){hb_ir_instr_t *ir=&f.func->cfg->blocks[b]->instrs[i];if(ir->op==f.form->ir&&ir->guest_addr==CODE+1)++matches;}
        check_kind(matches==1,"expected instruction IR at CODE+1",DECODE);
    }
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create runtime"))goto done;
    unsigned tops=scenario==ORDINARY?8:2;
    for(unsigned t=0;t<tops;++t)for(unsigned p=0;p<2;++p)run_case(&f,scenario==ORDINARY?t:t?5:0,p);
    if(f.jit)check_kind(native_present(&f),"native compiled entry present; helper lowering permitted",EXECUTION);
    uint8_t actual[16];check(hb_memory_read(f.ctx->memory,CODE,actual,f.len)==HB_OK&&!memcmp(actual,f.code,f.len),"code unchanged");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.ctx)hb_context_destroy(f.ctx);
}
static const struct{const char *name;enum hb_gate_id id;const char *value;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM,"0"},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR,"0"},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64,"0"},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS,"0"},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED,"0"},{"MACRUNNER_HB_UNCHAIN_STATS",HB_GATE_HB_UNCHAIN_STATS,"0"}};

int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *s=getenv(gates[i].name);if(s&&!check((saved[i]=strdup(s))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,gates[i].value,1)==0,"select private helper policy"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);if(!check(s&&!strcmp(s,gates[i].value),"effective gate"))goto done;}
    if(!check(fegetenv(&original)==0,"save caller fenv"))goto done;host_saved=1;fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host traps"))goto done;
    for(unsigned backend=0;backend<2;++backend){
        hb_backend_t b=backend?HB_BACKEND_JIT:HB_BACKEND_INTERP;
        for(unsigned form=0;form<14;++form)run_form(form,HB_ARCH_X86,b,ORDINARY);
        const unsigned denied[]={PUSHA,POPA,BOUND,LDS,LES,LFS,LGS};for(unsigned i=0;i<sizeof(denied)/sizeof(denied[0]);++i)run_form(denied[i],HB_ARCH_X86,b,DENIED);
        run_form(AAM,HB_ARCH_X86,b,ZERO_BASE);run_form(BOUND,HB_ARCH_X86,b,OUTSIDE_BOUNDS);
        run_form(AAA,HB_ARCH_X86,b,TRANSPORT);run_form(POPA,HB_ARCH_X86,b,TRANSPORT);
        for(unsigned arch=0;arch<2;++arch){
            hb_arch_t a=arch?HB_ARCH_X64:HB_ARCH_X86;
            for(unsigned form=FLD1;form<=FIADD;++form)run_form(form,a,b,POSITIVE);
            run_form(ILLEGAL,a,b,TYPED);run_form(HOST_CALL,a,b,INTERNAL);
        }
    }
    check(calls==616u&&ordinary_calls==448u&&failure_calls==72u&&positive_calls==48u&&typed_calls==16u&&internal_calls==16u&&transport_calls==16u,"planned calls, separate internal-control count");
done:
    if(host_saved)check(fesetenv(&original)==0,"restore caller fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_fip_classification_test: %u calls (%u ordinary, %u failure, %u positive x87, %u typed, %u transport; %u internal HOST_CALL), %u checks, %u failures\n",calls,ordinary_calls,failure_calls,positive_calls,typed_calls,transport_calls,internal_calls,checks,failures);
    printf("failure categories: fpstate=%u result=%u execution=%u host=%u decode=%u\n",category_failures[FPSTATE],category_failures[RESULT],category_failures[EXECUTION],category_failures[HOST],category_failures[DECODE]);return failures?1:0;
}
