/* Raw finite FCOM/FUCOM register relations with M37 family-specific C1.
 * Literal raw80/preview pairs were independently checked with exact arithmetic.
 * C0/C2/C3 reflect the raw relation; ordered C1 clears, unordered C1 preserves
 * the established engine policy. Integer/lazy flags, source/cache/preview and
 * neighbors stay unchanged; zero/one/two pops are independently modeled.
 * Cache-invalid operands use their stored double; pending controls stay legacy;
 * IM0 empties retain existing STi-first then ST0 errors. Synthetic two-pop
 * zero-REG/NONE and malformed IMM controls are separate from guest encodings.
 * No raw NaN/infinity/denormal, masked-empty, deferred delivery, full FIP,
 * enabled-host-trap, memory/FICOM or performance claim. No engine helper oracle.
 * Canonical finite values with zero/infinity previews are included. */
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
enum { LESS,EQUAL,GREATER };
enum { ADMITTED,UNCACHED,PENDING,EMPTY,LEGACY_ZERO,LEGACY_NONE,INVALID_TWO,INVALID_NEGATIVE };
enum { X87_STATUS,INTEGER_FLAGS,STATE,EXECUTION,HOST,DECODE,CATEGORIES };
static const uint64_t CODE=UINT64_C(0x6e00000);
static unsigned checks,failures,executions,raw_cases,uncached_cases,pending_cases,empty_cases,legacy_cases,invalid_cases;
static unsigned category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static int invalid_marker(unsigned kind){return kind==INVALID_TWO||kind==INVALID_NEGATIVE;}
static int legacy_marker(unsigned kind){return kind==LEGACY_ZERO||kind==LEGACY_NONE;}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint16_t se;uint64_t sig,preview;unsigned tag;} raw_t;
typedef struct {const char *name;raw_t a,b;unsigned relation,preview_relation;} sample_t;
static const sample_t samples[]={
    {"one_plus_lsb",{0x3fff,UINT64_C(0x8000000000000001),UINT64_C(0x3ff0000000000000),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},GREATER,EQUAL},
    {"one_minus_rhs_lsb",{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},{0x3fff,UINT64_C(0x8000000000000001),UINT64_C(0x3ff0000000000000),0},LESS,EQUAL},
    {"negative_one_plus_lsb",{0xbfff,UINT64_C(0x8000000000000001),UINT64_C(0xbff0000000000000),0},{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},LESS,EQUAL},
    {"negative_one_reverse",{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},{0xbfff,UINT64_C(0x8000000000000001),UINT64_C(0xbff0000000000000),0},GREATER,EQUAL},
    {"positive_tiny_zero",{0x3b4f,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},GREATER,EQUAL},
    {"positive_zero_tiny",{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},{0x3b4f,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},LESS,EQUAL},
    {"negative_tiny_zero",{0xbb4f,UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000000),0},{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},LESS,EQUAL},
    {"negative_zero_tiny",{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},{0xbb4f,UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000000),0},GREATER,EQUAL},
    {"huge_exponent_less",{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},{0x4400,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},LESS,EQUAL},
    {"huge_exponent_greater",{0x4400,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},GREATER,EQUAL},
    {"negative_huge_greater",{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0},{0xc400,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0},GREATER,EQUAL},
    {"negative_huge_less",{0xc400,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0},{0xc3ff,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0},LESS,EQUAL},
    {"signed_zero_pn",{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},EQUAL,EQUAL},
    {"signed_zero_np",{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},EQUAL,EQUAL},
    {"minimum_normal_zero",{0x0001,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},GREATER,EQUAL},
    {"negative_minimum_normal_zero",{0x8001,UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000000),0},{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},LESS,EQUAL},
    {"same_exponent_low_bits",{0x3fff,UINT64_C(0x8000000000000001),UINT64_C(0x3ff0000000000000),0},{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},LESS,EQUAL},
    {"negative_same_exponent_low_bits",{0xbfff,UINT64_C(0x8000000000000001),UINT64_C(0xbff0000000000000),0},{0xbfff,UINT64_C(0x8000000000000002),UINT64_C(0xbff0000000000000),0},GREATER,EQUAL},
    {"exponent_boundary",{0x3fff,UINT64_C(0xffffffffffffffff),UINT64_C(0x4000000000000000),0},{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},LESS,EQUAL},
    {"negative_exponent_boundary",{0xbfff,UINT64_C(0xffffffffffffffff),UINT64_C(0xc000000000000000),0},{0xc000,UINT64_C(0x8000000000000000),UINT64_C(0xc000000000000000),0},GREATER,EQUAL},
    {"opposite_tiny_less",{0xbb4f,UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000000),0},{0x3b4f,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},LESS,EQUAL},
    {"opposite_tiny_greater",{0x3b4f,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{0xbb4f,UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000000),0},GREATER,EQUAL},
    {"distinct_preview_control",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},GREATER,GREATER},
    {"exact_equal_seven",{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},EQUAL,EQUAL}
};
typedef struct {const char *name;uint8_t bytes[2];unsigned index,ordered,pops,two;int decoded;hb_ir_op_t ir;} form_t;
#define F(N,P,B,I,G,POP,D,IR) {N #I,{P,(B)+(I)},I,G,POP,0,HB_INS_X87_##D,HB_IR_X87_##IR}
#define EIGHT(N,P,B,G,POP,D,IR) F(N,P,B,0,G,POP,D,IR),F(N,P,B,1,G,POP,D,IR),F(N,P,B,2,G,POP,D,IR),F(N,P,B,3,G,POP,D,IR),F(N,P,B,4,G,POP,D,IR),F(N,P,B,5,G,POP,D,IR),F(N,P,B,6,G,POP,D,IR),F(N,P,B,7,G,POP,D,IR)
static const form_t forms[]={
    EIGHT("FCOM ST",0xd8,0xd0,1,0,FCOM,FCOM),
    EIGHT("FCOMP ST",0xd8,0xd8,1,1,FCOMP,FCOMP),
    EIGHT("FUCOM ST",0xdd,0xe0,0,0,FUCOM,FUCOM),
    EIGHT("FUCOMP ST",0xdd,0xe8,0,1,FUCOMP,FUCOMP),
    {"FCOMPP",{0xde,0xd9},1,1,2,1,HB_INS_X87_FCOMPP,HB_IR_X87_FCOMPP},
    {"FUCOMPP",{0xda,0xe9},1,0,2,1,HB_INS_X87_FCOMPP,HB_IR_X87_FCOMPP}
};
#undef EIGHT
#undef F
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;hb_ir_instr_t *comparison;} fixture_t;
static void install(hb_x87_state_t *x,unsigned p,const raw_t *v)
{memcpy(&x->st[p],&v->preview,8);put64(x->st_ext[p],v->sig);put16(x->st_ext[p]+8,v->se);x->st_ext_valid|=(uint8_t)(1u<<p);x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*p)))|(v->tag<<(2*p)));}
static void seed(fixture_t *f,const sample_t *s,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned empty,unsigned kind,unsigned cache)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));memset(&c->x87_64,0x56,sizeof(c->x87_64));
    hb_x87_state_t *x=hb_context_x87(c);memset(x,0,sizeof(*x));x->top=top;x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));
    x->status_word=(uint16_t)((top<<11)|0x0024|((cc&1)<<8)|((cc&2)<<8)|((cc&4)<<8)|((cc&8)<<11));
    if(top&1)x->status_word|=0x0040;x->last_x87_ip=0x12345678;
    for(unsigned p=0;p<8;++p){raw_t v={0x4002,UINT64_C(0x8000000000000000)+(uint64_t)p*UINT64_C(0x0800000000000000),UINT64_C(0x4020000000000000)+(uint64_t)p*UINT64_C(0x0001000000000000),0};install(x,p,&v);}
    unsigned other=(top+f->form->index)&7;install(x,other,&s->b);install(x,top,&s->a);
    unsigned neighbor=(top+6)&7;if(neighbor!=top&&neighbor!=other)x->tag_word|=(uint16_t)(3u<<(2*neighbor));
    if(empty){unsigned p=empty==1?top:other;x->tag_word|=(uint16_t)(3u<<(2*p));x->control_word&=(uint16_t)~1u;}
    if(kind==UNCACHED){if(cache&1)x->st_ext_valid&=(uint8_t)~(1u<<top);if(cache&2)x->st_ext_valid&=(uint8_t)~(1u<<other);}
    if(kind==PENDING){x->control_word&=(uint16_t)~1u;x->status_word|=0x8081u;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=(cc&1)!=0,.pf=(cc&2)!=0,.af=true,.zf=(cc&4)!=0,.sf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void check_state(fixture_t *f,const hb_context_t *before,unsigned relation,unsigned kind)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    if(kind==EMPTY)e->status_word=(uint16_t)((e->status_word|0x80c1u)&~0x0200u);
    else if(!invalid_marker(kind)){
        e->status_word=(uint16_t)((e->status_word&~0x4500u)|(relation==LESS?0x0100u:relation==EQUAL?0x4000u:0));
        if(f->form->ordered&&!legacy_marker(kind))e->status_word&=(uint16_t)~0x0200u;
        for(unsigned n=0;n<f->form->pops;++n){e->tag_word|=(uint16_t)(3u<<(2*e->top));e->top=(e->top+1)&7;e->status_word=(uint16_t)((e->status_word&~0x3800u)|(e->top<<11));}
    }
    check_kind(x->status_word==e->status_word,"x87 relation/C1, TOP and sticky status",X87_STATUS);
    check_kind(!memcmp(&f->ctx->flags,&expected.flags,sizeof(expected.flags))&&!memcmp(&f->ctx->lazy_flags,&expected.lazy_flags,sizeof(expected.lazy_flags)),"canonical integer flags and lazy state",INTEGER_FLAGS);
    e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"physical raw/cache/preview, tags, control and optional pop");
    if(f->ctx->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and nonarithmetic flag-image state preserved");
    if(f->ctx->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr,"MXCSR preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks preserved");
    check(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const sample_t *s,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned host,unsigned kind,unsigned side)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    snprintf(phase,sizeof(phase),"%s %s %s %s TOP=%u cc=%u PC=%u RC=%u host=%u kind=%u side=%u",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,s->name,top,cc,pc,rc,host,kind,side);
    seed(f,s,top,cc,pc,rc,kind==EMPTY?side:0,kind,side);hb_context_t before;memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;if(kind==EMPTY)++empty_cases;else if(kind==UNCACHED)++uncached_cases;else if(kind==PENDING)++pending_cases;else if(legacy_marker(kind))++legacy_cases;else if(invalid_marker(kind))++invalid_cases;else ++raw_cases;
    check_kind(actual_rc==modes[host]&&actual_flags==wanted,"host RC/status preserved",HOST);
    if(kind==EMPTY)check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"IM0 empty rejects before integer flags/pop",EXECUTION);
    else if(invalid_marker(kind))check_kind((result==HB_OK||result==HB_ERR_INTERNAL)&&out.result==HB_ERR_INTERNAL&&out.faulted&&!out.timed_out,"malformed internal marker rejects before comparison/pop",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+2,"actual comparison completes",EXECUTION);
    unsigned relation=kind==UNCACHED||kind==PENDING?s->preview_relation:s->relation;
    /* These literal rows keep exact ST0 when only STi loses its cache:
     * 1+2^-63 > 1, -1-2^-63 < -1, and 2^-1200 > 0. */
    if(kind==UNCACHED&&side==2&&(s==&samples[0]||s==&samples[2]||s==&samples[4]))relation=s->relation;
    check_state(f,&before,f->form->index?relation:EQUAL,kind);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void check_ir(fixture_t *f)
{
    unsigned count=0;if(!check_kind(f->func->cfg!=NULL,"IR container present",DECODE))return;
    for(size_t b=0;b<f->func->cfg->block_count;++b){hb_ir_block_t *block=f->func->cfg->blocks[b];
        for(size_t i=0;i<block->instr_count;++i){hb_ir_instr_t *ir=&block->instrs[i];if(ir->op!=f->form->ir)continue;++count;
            check_kind(ir->guest_addr==CODE&&ir->src1.type==HB_OP_IMM&&ir->src1.imm==(int64_t)f->form->index&&ir->dst.type==HB_OP_NONE,"comparison IR source/index and implicit destination",DECODE);
            f->comparison=ir;
            if(f->form->two)check_kind(ir->src2.type==HB_OP_IMM&&ir->src2.imm==(int64_t)f->form->ordered,"fresh two-pop family marker",DECODE);
        }
    }
    check_kind(count==1,"exactly one expected comparison IR",DECODE);
}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create reusable comparison context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,CODE,form->bytes,2)==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned code"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(form->bytes,2,CODE,&d):hb_decode_x64(form->bytes,2,CODE,&d);
    if(!check_kind(result==HB_OK&&d.len==2&&(int)d.opcode==form->decoded,"decode actual comparison opcode",DECODE))goto done;
    check_kind(d.op1.present&&d.op1.is_imm&&d.op1.imm==(int64_t)form->index,"decoded logical comparison operand",DECODE);
    if(form->two)check_kind(d.op2.present&&d.op2.is_imm&&d.op2.imm==(int64_t)form->ordered,"decoded two-pop family marker",DECODE);
    f.decoder=hb_decoder_create(arch,form->bytes,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift comparison",EXECUTION))goto done;
    check_ir(&f);
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pcs[]={0,2,3};
    for(unsigned si=0;si<sizeof(samples)/sizeof(samples[0]);++si)for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)run_case(&f,&samples[si],top,cc,pcs[top%3],cc>>2,cc&3,ADMITTED,0);
    if(form->index==0||form->index==3||form->index==7||form->two){
        static const unsigned cache_samples[]={0,2,4,22},pending_samples[]={4,6},empty_cc[]={0,2,13,15};
        for(unsigned si=0;si<4;++si)for(unsigned side=1;side<=3;++side)for(unsigned t=0;t<2;++t)for(unsigned cc=0;cc<16;++cc)run_case(&f,&samples[cache_samples[si]],t?7:0,cc,3,cc>>2,cc&3,UNCACHED,side);
        for(unsigned si=0;si<2;++si)for(unsigned t=0;t<2;++t)for(unsigned cc=0;cc<16;++cc)run_case(&f,&samples[pending_samples[si]],t?7:0,cc,3,cc>>2,cc&3,PENDING,0);
        for(unsigned side=1;side<=2;++side)for(unsigned t=0;t<3;++t)for(unsigned ci=0;ci<4;++ci)for(unsigned host=0;host<4;++host)run_case(&f,&samples[0],t==0?0:t==1?5:7,empty_cc[ci],3,3-host,host,EMPTY,side);
    }
    /* These descriptors are internal compatibility/error controls, not new
     * instruction bytes or an assertion of old persisted-cache execution. */
    if(form->two){
        if(f.jit)check_kind(native_present(&f),"two-pop guest form compiled entry before synthetic controls; helper lowering allowed",EXECUTION);
        if(!check(f.comparison!=NULL,"two-pop IR available for explicit synthetic controls"))goto done;
        hb_ir_operand_t original=f.comparison->src2;
        for(unsigned kind=LEGACY_ZERO;kind<=INVALID_NEGATIVE;++kind){
            if(f.jit){hb_jit_runtime_destroy(f.jit);f.jit=NULL;}
            if(kind==LEGACY_ZERO)memset(&f.comparison->src2,0,sizeof(f.comparison->src2));
            else if(kind==LEGACY_NONE)f.comparison->src2=hb_ir_none();
            else f.comparison->src2=hb_ir_imm(kind==INVALID_TWO?2:-1,HB_SIZE_8);
            if(backend==HB_BACKEND_JIT){f.jit=hb_jit_runtime_create(f.ctx);if(!check(f.jit!=NULL,"fresh runtime for changed internal marker"))goto done;}
            static const unsigned marker_samples[]={0,23};
            for(unsigned si=0;si<2;++si)for(unsigned t=0;t<2;++t)for(unsigned cc=0;cc<16;++cc)run_case(&f,&samples[marker_samples[si]],t?7:0,cc,3,cc>>2,cc&3,kind,0);
            if(f.jit)check_kind(native_present(&f),"synthetic policy compiled entry; helper lowering allowed",EXECUTION);
        }
        f.comparison->src2=original;
    }
    if(f.jit)check_kind(native_present(&f),"native compiled entry exists; helper lowering allowed",EXECUTION);
    uint8_t actual[2];check(hb_memory_read(f.ctx->memory,CODE,actual,2)==HB_OK&&!memcmp(actual,form->bytes,2),"code unchanged");
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
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned i=0;i<sizeof(forms)/sizeof(forms[0]);++i)run_form(&forms[i],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
    check(executions==450304u&&raw_cases==417792u&&uncached_cases==21504u&&pending_cases==3584u&&empty_cases==5376u&&legacy_cases==1024u&&invalid_cases==1024u,"planned actual call counts");
done:
    if(host_saved)check(fesetenv(&original)==0,"restore caller fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_raw_fcom_test: %u executions (%u raw finite/zero, %u uncached, %u pending compatibility, %u IM0 empty, %u legacy IR, %u invalid-marker IR), %u checks, %u failures\n",executions,raw_cases,uncached_cases,pending_cases,empty_cases,legacy_cases,invalid_cases,checks,failures);
    printf("failure categories: x87_status=%u integer_flags=%u state=%u execution=%u host=%u decode=%u\n",category_failures[X87_STATUS],category_failures[INTEGER_FLAGS],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[DECODE]);return failures?1:0;
}
