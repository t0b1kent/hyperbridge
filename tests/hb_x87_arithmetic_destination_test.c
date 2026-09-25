/* M32: D8/DC register arithmetic destination and operand-order regression.
 * All six dyadic pairs and their 36 ordinary/36 self answers are literal bits.
 * Every nonzero answer is exact at PC24/53/64 and all rounding modes.
 * M34 ADD/SUB and M47 MUL/DIV use exact raw80 destination representation
 * and require C1=0 for these eligible literal answers.
 * Alias subtraction zero sign, C0/C2/C3 and inherited FIP remain excluded;
 * The dedicated M34 fixture checks guest-RC cancellation signs independently.
 * No empty operands, exceptional arithmetic, memory operands or #MF claim. */
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
enum { NUMERIC,STATE,EXECUTION,HOST,DECODE,CATEGORIES };
static const uint64_t CODE=UINT64_C(0x6500000);
static unsigned checks,failures,executions,d8_cases,dc_cases,uncached_cases,alias_cases;
static unsigned category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint16_t se;uint64_t sig,preview;} raw_t;
/* Answer order: A+B, A*B, A-B, B-A, A/B, B/A; A=old ST0, B=old STi.
 * Self answers use B=A. Zero signs are excluded only for self subtraction. */
typedef struct {const char *name;raw_t a,b;uint64_t ordinary[6],self[6];} sample_t;
static const sample_t samples[]={
    {"positive",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000)},{0x4002,UINT64_C(0x8000000000000000),UINT64_C(0x4020000000000000)},{UINT64_C(0x4024000000000000),UINT64_C(0x4030000000000000),UINT64_C(0xc018000000000000),UINT64_C(0x4018000000000000),UINT64_C(0x3fd0000000000000),UINT64_C(0x4010000000000000)},{UINT64_C(0x4010000000000000),UINT64_C(0x4010000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff0000000000000)}},
    {"negative_source",{0xc000,UINT64_C(0x8000000000000000),UINT64_C(0xc000000000000000)},{0x4002,UINT64_C(0x8000000000000000),UINT64_C(0x4020000000000000)},{UINT64_C(0x4018000000000000),UINT64_C(0xc030000000000000),UINT64_C(0xc024000000000000),UINT64_C(0x4024000000000000),UINT64_C(0xbfd0000000000000),UINT64_C(0xc010000000000000)},{UINT64_C(0xc010000000000000),UINT64_C(0x4010000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff0000000000000)}},
    {"larger_source",{0x4002,UINT64_C(0x8000000000000000),UINT64_C(0x4020000000000000)},{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000)},{UINT64_C(0x4024000000000000),UINT64_C(0x4030000000000000),UINT64_C(0x4018000000000000),UINT64_C(0xc018000000000000),UINT64_C(0x4010000000000000),UINT64_C(0x3fd0000000000000)},{UINT64_C(0x4030000000000000),UINT64_C(0x4050000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff0000000000000)}},
    {"fraction",{0x3ffe,UINT64_C(0x8000000000000000),UINT64_C(0x3fe0000000000000)},{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000)},{UINT64_C(0x4004000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff8000000000000),UINT64_C(0x3ff8000000000000),UINT64_C(0x3fd0000000000000),UINT64_C(0x4010000000000000)},{UINT64_C(0x3ff0000000000000),UINT64_C(0x3fd0000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff0000000000000)}},
    {"negative_pair",{0xbffe,UINT64_C(0x8000000000000000),UINT64_C(0xbfe0000000000000)},{0xc000,UINT64_C(0x8000000000000000),UINT64_C(0xc000000000000000)},{UINT64_C(0xc004000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff8000000000000),UINT64_C(0xbff8000000000000),UINT64_C(0x3fd0000000000000),UINT64_C(0x4010000000000000)},{UINT64_C(0xbff0000000000000),UINT64_C(0x3fd0000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff0000000000000)}},
    {"negative_destination",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000)},{0xc002,UINT64_C(0x8000000000000000),UINT64_C(0xc020000000000000)},{UINT64_C(0xc018000000000000),UINT64_C(0xc030000000000000),UINT64_C(0x4024000000000000),UINT64_C(0xc024000000000000),UINT64_C(0xbfd0000000000000),UINT64_C(0xc010000000000000)},{UINT64_C(0x4010000000000000),UINT64_C(0x4010000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff0000000000000)}},
};
typedef struct {const char *name;uint8_t bytes[2];unsigned dc,index,answer;int decoded;hb_ir_op_t ir;} form_t;
#define F(N,P,B,I,D,A,OP) {N #I,{P,(B)+(I)},D,I,A,HB_INS_X87_##OP,HB_IR_X87_##OP}
#define EIGHT(N,P,B,D,A,OP) F(N,P,B,0,D,A,OP),F(N,P,B,1,D,A,OP),F(N,P,B,2,D,A,OP),F(N,P,B,3,D,A,OP),F(N,P,B,4,D,A,OP),F(N,P,B,5,D,A,OP),F(N,P,B,6,D,A,OP),F(N,P,B,7,D,A,OP)
static const form_t forms[]={
    EIGHT("D8 FADD ST0,ST",0xd8,0xc0,0,0,FADD),
    EIGHT("D8 FMUL ST0,ST",0xd8,0xc8,0,1,FMUL),
    EIGHT("D8 FSUB ST0,ST",0xd8,0xe0,0,2,FSUB),
    EIGHT("D8 FSUBR ST0,ST",0xd8,0xe8,0,3,FSUBR),
    EIGHT("D8 FDIV ST0,ST",0xd8,0xf0,0,4,FDIV),
    EIGHT("D8 FDIVR ST0,ST",0xd8,0xf8,0,5,FDIVR),
    EIGHT("DC FADD STi,ST0 i",0xdc,0xc0,1,0,FADD),
    EIGHT("DC FMUL STi,ST0 i",0xdc,0xc8,1,1,FMUL),
    EIGHT("DC FSUBR STi,ST0 i",0xdc,0xe0,1,2,FSUBR),
    EIGHT("DC FSUB STi,ST0 i",0xdc,0xe8,1,3,FSUB),
    EIGHT("DC FDIVR STi,ST0 i",0xdc,0xf0,1,4,FDIVR),
    EIGHT("DC FDIV STi,ST0 i",0xdc,0xf8,1,5,FDIV)
};
#undef EIGHT
#undef F
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;} fixture_t;
static void install(hb_x87_state_t *x,unsigned phys,const raw_t *r)
{
    memcpy(&x->st[phys],&r->preview,8);put64(x->st_ext[phys],r->sig);put16(x->st_ext[phys]+8,r->se);
    x->st_ext_valid|=(uint8_t)(1u<<phys);x->tag_word=(uint16_t)(x->tag_word&~(3u<<(2*phys)));
}
static void seed(fixture_t *f,const sample_t *s,unsigned top,unsigned pc,unsigned rc,int uncached)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));
    if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else{c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));
    x->status_word=(uint16_t)((top<<11)|0x4704|((top&1)?0x20:0)|((top&2)?0x40:0));x->last_x87_ip=0x12345678;
    for(unsigned i=0;i<8;++i){
        raw_t n={0x4002,UINT64_C(0x8000000000000000)+(uint64_t)i*UINT64_C(0x1000000000000000),
                 UINT64_C(0x4020000000000000)+(uint64_t)i*UINT64_C(0x2000000000000)};
        install(x,(top+i)&7,&n);
    }
    unsigned other=(top+f->form->index)&7;
    if(other!=top)install(x,other,&s->b);install(x,top,&s->a);
    if(uncached)x->st_ext_valid&=(uint8_t)~((1u<<top)|(1u<<other));
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void check_state(fixture_t *f,const hb_context_t *before,const sample_t *s)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));
    hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    unsigned dst=(e->top+(f->form->dc?f->form->index:0))&7;
    uint64_t wanted=(f->form->index?s->ordinary:s->self)[f->form->answer],actual;memcpy(&actual,&x->st[dst],8);
    int self_zero=!f->form->index&&(f->form->answer==2||f->form->answer==3);
    check_kind(self_zero?(actual&UINT64_C(0x7fffffffffffffff))==0:actual==wanted,"selected logical destination numerical result",NUMERIC);
    if(self_zero)wanted=actual&UINT64_C(0x8000000000000000);
    memcpy(&e->st[dst],&wanted,8);
    int exact=f->form->ir==HB_IR_X87_FADD||f->form->ir==HB_IR_X87_FSUB||f->form->ir==HB_IR_X87_FSUBR||f->form->ir==HB_IR_X87_FMUL||f->form->ir==HB_IR_X87_FDIV||f->form->ir==HB_IR_X87_FDIVR;
    if(exact){
        /* Every baked arithmetic answer is normal or zero and exact at all tested
         * PC values. Encode those literal binary64 bits into raw80 using only
         * format fields; no production conversion helper or host arithmetic.
         * M32's pre-existing self-zero sign exclusion applies to both views. */
        unsigned exp=(unsigned)((wanted>>52)&0x7ffu);
        uint64_t sig=exp?((wanted&UINT64_C(0x000fffffffffffff))|UINT64_C(0x0010000000000000))<<11:0;
        uint16_t se=(uint16_t)(((wanted>>63)<<15)|(exp?exp+15360u:0));
        put64(e->st_ext[dst],sig);put16(e->st_ext[dst]+8,se);
        e->st_ext_valid|=(uint8_t)(1u<<dst);e->status_word&=(uint16_t)~0x200u;
    }else e->st_ext_valid&=(uint8_t)~(1u<<dst);
    unsigned tag=(wanted&UINT64_C(0x7fffffffffffffff))?0:1;
    e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*dst)))|(tag<<(2*dst)));
    e->last_x87_ip=x->last_x87_ip;
    unsigned undefined_cc=exact?0x4500u:0x4700u;
    e->status_word=(uint16_t)((e->status_word&~undefined_cc)|(x->status_word&undefined_cc));
    check(!memcmp(x,e,sizeof(*x)),"TOP, selected exact or legacy setter/cache, sticky status, all other physical payload/cache unchanged");
    if(f->ctx->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and register state preserved");
    if(f->ctx->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr&&!memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR/integer flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks preserved");
    check(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const sample_t *s,unsigned top,unsigned pc,unsigned rc,unsigned host,int uncached)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    snprintf(phase,sizeof(phase),"%s %s %s %s TOP=%u PC=%u RC=%u host=%u uncached=%d",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,s->name,top,pc,rc,host,uncached);
    seed(f,s,top,pc,rc,uncached);hb_context_t before;memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};
    hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;
    if(f->form->dc)++dc_cases;else ++d8_cases;if(uncached)++uncached_cases;if(!f->form->index)++alias_cases;
    check_kind(actual_rc==modes[host]&&actual_flags==wanted,"host RC/status unchanged for exact dyadic inputs",HOST);
    check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+2,"non-pop arithmetic completes",EXECUTION);
    check_state(f,&before,s);
}
static void check_lift(fixture_t *f)
{
    unsigned count=0;const form_t *form=f->form;
    if(!check_kind(f->func->cfg!=NULL,"IR container present",DECODE))return;
    for(size_t b=0;b<f->func->cfg->block_count;++b){
        hb_ir_block_t *block=f->func->cfg->blocks[b];
        for(size_t i=0;i<block->instr_count;++i){
            hb_ir_instr_t *ir=&block->instrs[i];
            if(ir->op!=HB_IR_X87_FADD&&ir->op!=HB_IR_X87_FMUL&&ir->op!=HB_IR_X87_FSUB&&ir->op!=HB_IR_X87_FSUBR&&ir->op!=HB_IR_X87_FDIV&&ir->op!=HB_IR_X87_FDIVR)continue;
            ++count;check_kind(ir->op==form->ir&&ir->guest_addr==CODE,"IR identity and source address",DECODE);
            check_kind(ir->src1.type==HB_OP_IMM&&ir->src1.imm==(int64_t)form->index,"IR logical other operand",DECODE);
            check_kind(form->dc?(ir->dst.type==HB_OP_IMM&&ir->dst.imm==(int64_t)form->index):ir->dst.type==HB_OP_NONE,"IR DC destination marker versus D8 NONE",DECODE);
        }
    }
    check_kind(count==1,"exactly one arithmetic IR instruction",DECODE);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;snprintf(phase,sizeof(phase),"%s %s %s setup",arch==HB_ARCH_X86?"x86":"x64",backend==HB_BACKEND_JIT?"JIT":"interp",form->name);
    f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create reusable context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,CODE,form->bytes,2)==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned code"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(form->bytes,2,CODE,&d):hb_decode_x64(form->bytes,2,CODE,&d);
    /* Metadata failures deliberately do not skip old-library runtime cases. */
    check_kind(result==HB_OK&&d.len==2&&(int)d.opcode==form->decoded,"decode full two-byte instruction and operation identity",DECODE);
    check_kind(d.op1.present&&d.op1.is_imm&&d.op1.imm==(int64_t)form->index,"decoded ST index",DECODE);
    check_kind(form->dc?(d.op2.present&&d.op2.is_imm&&d.op2.imm==(int64_t)form->index&&d.op2.size==1):!d.op2.present,"decoded DC-only destination marker",DECODE);
    f.decoder=hb_decoder_create(arch,form->bytes,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);
    if(!check_kind(result==HB_OK&&f.func,"lift arithmetic",EXECUTION))goto done;check_lift(&f);
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pcs[]={0,2,3};
    for(unsigned s=0;s<sizeof(samples)/sizeof(samples[0]);++s)for(unsigned top=0;top<8;++top)for(unsigned p=0;p<3;++p)for(unsigned rc=0;rc<4;++rc){
        if(form->index==0||form->index==3)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s],top,pcs[p],rc,host,0);
        else run_case(&f,&samples[s],top,pcs[p],rc,rc^1u,0);
    }
    if(form->index==0||form->index==3||form->index==7)for(unsigned s=0;s<sizeof(samples)/sizeof(samples[0]);++s)for(unsigned t=0;t<2;++t)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s],t?5:0,3,3-host,host,1);
    if(f.jit)check_kind(native_present(&f),"native compiled entry exists; helper lowering permitted",EXECUTION);
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
    check(executions==393984u&&d8_cases==196992u&&dc_cases==196992u&&uncached_cases==6912u&&alias_cases==112896u,"planned actual calls and subset counts");
done:
    if(host_saved)check(fesetenv(&original)==0,"restore caller fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_arithmetic_destination_test: %u executions (%u D8, %u DC; subsets %u uncached, %u alias), %u checks, %u failures\n",executions,d8_cases,dc_cases,uncached_cases,alias_cases,checks,failures);
    printf("failure categories: numeric=%u state=%u execution=%u host=%u decode=%u\n",category_failures[NUMERIC],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[DECODE]);return failures?1:0;
}
