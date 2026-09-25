/* M28 preparation: actual FST/FSTP ST(i) and FXCH ST(i), all eight indices.
 * Occupied operands transfer exact raw80, including SNaN and true subnormals.
 * Unsupported/pseudo encodings are excluded. Masked FXCH substitutes indefinite
 * for originally empty operands before swapping; an occupied raw value survives.
 * FST/P ordinary C1 and all three instructions' C0/C2/C3 are not an oracle.
 * FXCH clears C1. FSTP copies using pre-pop TOP, then marks old ST0 empty.
 * Raw payload/cache after popping is not an architectural value assertion.
 * Nearest-even binary64 previews and fresh destination caches are engine policy.
 * No memory operands, pending #MF delivery, or inherited FIP/fault-PC claims.
 * JIT evidence is compiled entry; the existing interpreter helper is allowed.
 */
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
enum { STORE, POP_STORE, EXCHANGE };
enum { OCCUPIED, EMPTY_DEST, VALID_IM_DM0, EMPTY_ST0, EMPTY_STI, EMPTY_BOTH,
       EMPTY_ST0_IM0, EMPTY_STI_IM0, EMPTY_BOTH_IM0 };
enum { RAW, STATE, EXECUTION, HOST, CATEGORIES };
static const uint64_t CODE=UINT64_C(0x5700000);
static unsigned checks,failures,executions,ordinary_cases,empty_dest_cases,uncached_cases,unmasked_valid_cases,masked_empty_cases,unmasked_empty_cases;
static unsigned category_failures[CATEGORIES];
static char phase[240]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{ ++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok; }
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {const char *name;uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} raw_t;
/* Independent raw/preview literals; each runs with either sign. Raw classes
 * VALID=0, ZERO=1, SPECIAL=2 differ deliberately from huge/tiny previews. */
static const raw_t samples[]={
    {"zero",0,0,0,1},
    {"one-plus-low-bit",UINT64_C(0x8000000000000001),0x3fff,UINT64_C(0x3ff0000000000000),0},
    {"one-plus-low11",UINT64_C(0x80000000000007ff),0x3fff,UINT64_C(0x3ff0000000000001),0},
    {"2^53+1",UINT64_C(0x8000000000000400),0x4034,UINT64_C(0x4340000000000000),0},
    {"2^1024",UINT64_C(0x8000000000000000),0x43ff,UINT64_C(0x7ff0000000000000),0},
    {"above-half-min-double-subnormal",UINT64_C(0x8000000000000001),0x3bcc,1,0},
    {"min-normal",UINT64_C(0x8000000000000000),1,0,0},
    {"min-subnormal",1,0,0,2},
    {"max-subnormal",UINT64_C(0x7fffffffffffffff),0,0,2},
    {"infinity",UINT64_C(0x8000000000000000),0x7fff,UINT64_C(0x7ff0000000000000),2},
    {"qNaN-payload",UINT64_C(0xc000000000002001),0x7fff,UINT64_C(0x7ff8000000000004),2},
    {"sNaN-payload",UINT64_C(0x8000000000002001),0x7fff,UINT64_C(0x7ff8000000000004),2}
};
typedef struct {uint64_t input;raw_t raw;} uncached_t;
static const uncached_t uncached[]={
    {0,{"uncached-zero",0,0,0,1}},
    {UINT64_C(0x3ff8000000000000),{"uncached-1.5",UINT64_C(0xc000000000000000),0x3fff,UINT64_C(0x3ff8000000000000),0}},
    {1,{"uncached-min-subnormal",UINT64_C(0x8000000000000000),0x3bcd,1,0}},
    {UINT64_C(0x000fffffffffffff),{"uncached-max-subnormal",UINT64_C(0xfffffffffffff000),0x3c00,UINT64_C(0x000fffffffffffff),0}},
    {UINT64_C(0x7fefffffffffffff),{"uncached-max-normal",UINT64_C(0xfffffffffffff800),0x43fe,UINT64_C(0x7fefffffffffffff),0}},
    {UINT64_C(0x7ff0000000000000),{"uncached-inf",UINT64_C(0x8000000000000000),0x7fff,UINT64_C(0x7ff0000000000000),2}},
    {UINT64_C(0x7ff8000000000001),{"uncached-qNaN",UINT64_C(0xc000000000000800),0x7fff,UINT64_C(0x7ff8000000000001),2}},
    {UINT64_C(0x7ff0000000000001),{"uncached-sNaN",UINT64_C(0x8000000000000800),0x7fff,UINT64_C(0x7ff8000000000001),2}}
};
static const raw_t indefinite={"indefinite",UINT64_C(0xc000000000000000),0xffff,UINT64_C(0xfff8000000000000),2};
typedef struct {const char *name;uint8_t code[2];unsigned kind,index;} form_t;
#define FORM(n,k,a,b,i) {n " ST" #i,{a,b+i},k,i}
#define EIGHT(n,k,a,b) FORM(n,k,a,b,0),FORM(n,k,a,b,1),FORM(n,k,a,b,2),FORM(n,k,a,b,3),FORM(n,k,a,b,4),FORM(n,k,a,b,5),FORM(n,k,a,b,6),FORM(n,k,a,b,7)
static const form_t forms[]={EIGHT("FST",STORE,0xdd,0xd0),EIGHT("FSTP",POP_STORE,0xdd,0xd8),EIGHT("FXCH",EXCHANGE,0xd9,0xc8)};
#undef EIGHT
#undef FORM
typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;} fixture_t;
static int empty_case(unsigned state){return state>=EMPTY_ST0;}
static int aborts(unsigned state){return state>=EMPTY_ST0_IM0;}
static unsigned empty_sides(unsigned state){return (state-EMPTY_ST0)%3;}
static void install(hb_x87_state_t *x,unsigned phys,const raw_t *r,unsigned sign,unsigned occupied)
{
    uint64_t preview=r->preview|((uint64_t)sign<<63);memcpy(&x->st[phys],&preview,8);
    put64(x->st_ext[phys],r->sig);put16(x->st_ext[phys]+8,(uint16_t)(r->se|(sign<<15)));
    x->st_ext_valid|=(uint8_t)(1u<<phys);x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*phys)))|((occupied?r->tag:3u)<<(2*phys)));
}
static void seed(fixture_t *f,const raw_t *r,const raw_t *other,const uncached_t *u,unsigned sign,unsigned top,unsigned pc,unsigned rc,unsigned state)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));
    if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else{c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;
    /* Masked sticky ZE/SF/PE vary; fresh IE/DE remain clear. Stale C1=1 must
     * clear for occupied FXCH, but is intentionally unspecified for stores. */
    x->status_word=(uint16_t)((top<<11)|0x4704|((top&1)?0x20:0)|((top&2)?0x40:0));
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));if(state==VALID_IM_DM0)x->control_word&=(uint16_t)~3u;if(aborts(state))x->control_word&=(uint16_t)~1u;x->last_x87_ip=0x12345678;
    for(unsigned i=0;i<8;++i){raw_t n={"neighbor",UINT64_C(0x8000000000000000)+(uint64_t)i*UINT64_C(0x1000000000000000),0x4002,UINT64_C(0x4020000000000000)+(uint64_t)i*UINT64_C(0x2000000000000),0};install(x,(top+i)&7,&n,i&1,i!=6);}
    unsigned dst=(top+f->form->index)&7;
    if(dst!=top)install(x,dst,other,sign^1,state!=EMPTY_DEST);
    install(x,top,r,sign,1);
    if(u){uint64_t bits=u->input|((uint64_t)sign<<63);memcpy(&x->st[top],&bits,8);x->st_ext_valid&=(uint8_t)~(1u<<top);}
    if(empty_case(state)){unsigned sides=empty_sides(state);if(sides!=1)x->tag_word|=(uint16_t)(3u<<(2*top));if(sides!=0)x->tag_word|=(uint16_t)(3u<<(2*dst));}
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;
    c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void raw_result(hb_x87_state_t *actual,hb_x87_state_t *expected,unsigned phys,const raw_t *r,unsigned sign,int cache)
{
    uint64_t previous_preview;memcpy(&previous_preview,&expected->st[phys],8);
    install(expected,phys,r,sign,1);
    if(cache==1)check_kind((actual->st_ext_valid&(1u<<phys))&&!memcmp(actual->st_ext[phys],expected->st_ext[phys],10),"occupied destination retains all ten raw bytes and coherent cache",RAW);
    else{
        uint8_t raw[10];check_kind(hb_x87_save_st_ext80(actual,(phys-actual->top)&7,raw)==HB_OK&&!memcmp(raw,expected->st_ext[phys],10),"exported raw value is exact despite allowed cache representation",RAW);
        memcpy(expected->st_ext[phys],actual->st_ext[phys],10);expected->st_ext_valid=(uint8_t)((expected->st_ext_valid&~(1u<<phys))|(actual->st_ext_valid&(1u<<phys)));
    }
    if(cache==2){
        /* A self-copy may retain its original uncached binary64 preview or
         * materialize the same raw value; neither operation narrows raw80. */
        check_kind(!memcmp(&actual->st[phys],&expected->st[phys],8)||!memcmp(&actual->st[phys],&previous_preview,8),"self alias preserves or materializes equivalent preview",RAW);
        memcpy(&expected->st[phys],&actual->st[phys],8);
    }else check_kind(!memcmp(&actual->st[phys],&expected->st[phys],8),"nearest-even binary64 preview policy",RAW);
    check_kind(((actual->tag_word>>(2*phys))&3u)==r->tag,"occupied destination raw80 classification",RAW);
}
static void check_state(fixture_t *f,const hb_context_t *before,const raw_t *r,const raw_t *other,unsigned sign,unsigned state)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);unsigned source=e->top,dst=(source+f->form->index)&7;
    int source_empty=((e->tag_word>>(2*source))&3u)==3,other_empty=((e->tag_word>>(2*dst))&3u)==3;
    if(empty_case(state)){e->status_word=(uint16_t)((e->status_word|0x41u)&~0x200u);if(aborts(state))e->status_word|=0x8080u;}
    if(!aborts(state)&&f->form->kind==EXCHANGE){
        const raw_t *from_source=source_empty?&indefinite:r,*from_other=other_empty?&indefinite:(dst==source?r:other);
        raw_result(x,e,source,from_other,other_empty?0:(dst==source?sign:sign^1),other_empty?0:dst==source?2:1);
        if(dst!=source)raw_result(x,e,dst,from_source,source_empty?0:sign,!source_empty);
        e->status_word&=(uint16_t)~0x200u;
    }else if(!aborts(state)){
        if(f->form->kind==STORE||dst!=source)raw_result(x,e,dst,source_empty?&indefinite:r,source_empty?0:sign,source_empty?0:dst==source?2:1);
        if(f->form->kind==POP_STORE){
            e->tag_word|=(uint16_t)(3u<<(2*source));e->top=(source+1)&7;e->status_word=(uint16_t)((e->status_word&~0x3800u)|(e->top<<11));
            /* The popped physical payload is architecturally empty. Do not
             * prescribe whether an implementation retains/materializes its cache. */
            memcpy(&e->st[source],&x->st[source],8);memcpy(e->st_ext[source],x->st_ext[source],10);
            e->st_ext_valid=(uint8_t)((e->st_ext_valid&~(1u<<source))|(x->st_ext_valid&(1u<<source)));
        }
        if(!empty_case(state))e->status_word=(uint16_t)((e->status_word&~0x200u)|(x->status_word&0x200u));
    }
    e->status_word=(uint16_t)((e->status_word&~0x4500u)|(x->status_word&0x4500u));e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"status, TOP, pop ordering and all neighboring physical x87 state");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific registers preserved");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->c->mxcsr==before->mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const raw_t *r,const raw_t *other,const uncached_t *u,unsigned sign,unsigned top,unsigned pc,unsigned rc,unsigned host,unsigned state)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    snprintf(phase,sizeof(phase),"%s %s %s %s sign=%u TOP=%u PC=%u RC=%u host=%u state=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,r->name,sign,top,pc,rc,host,state);
    seed(f,r,other,u,sign,top,pc,rc,state);hb_context_t before;memcpy(&before,f->c,sizeof(before));
    if(!check(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host RC/status"))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;if(aborts(state))++unmasked_empty_cases;else if(empty_case(state))++masked_empty_cases;else if(u)++uncached_cases;else if(state==EMPTY_DEST)++empty_dest_cases;else if(state==VALID_IM_DM0)++unmasked_valid_cases;else ++ordinary_cases;
    check_kind(actual_rc==modes[host]&&actual_status==wanted,"register transfer preserves host RC and standard status",HOST);
    if(aborts(state))check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"unmasked stack underflow rejects without register/pop mutation",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->c->pc==CODE+2,"one raw register instruction completes",EXECUTION);
    check_state(f,&before,r,other,sign,state);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable register-transfer context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,form->code,2)==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned code"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(form->code,2,CODE,&d):hb_decode_x64(form->code,2,CODE,&d);int opcode=form->kind==STORE?HB_INS_X87_FST:form->kind==POP_STORE?HB_INS_X87_FSTP:HB_INS_X87_FXCH;
    if(!check_kind(result==HB_OK&&d.len==2&&(int)d.opcode==opcode,"decode actual register-transfer opcode",EXECUTION))goto done;
    check_kind(d.op1.present&&d.op1.is_imm&&d.op1.imm==(int64_t)form->index,"decode exact ST index",EXECUTION);
    f.decoder=hb_decoder_create(arch,form->code,2,CODE);if(!check(f.decoder!=NULL,"create raw decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift actual register transfer",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pcs[]={0,2,3};
    for(unsigned s=0;s<sizeof(samples)/sizeof(samples[0]);++s)for(unsigned sign=0;sign<2;++sign)for(unsigned top=0;top<8;++top){
        const raw_t *other=&samples[(s+5)%(sizeof(samples)/sizeof(samples[0]))];
        if(form->index==0||form->index==3){for(unsigned p=0;p<3;++p)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s],other,NULL,sign,top,pcs[p],rc,host,OCCUPIED);}
        else for(unsigned host=0;host<4;++host)run_case(&f,&samples[s],other,NULL,sign,top,3,3-host,host,OCCUPIED);
    }
    if(form->kind!=EXCHANGE&&form->index!=0)for(unsigned s=0;s<sizeof(samples)/sizeof(samples[0]);++s)for(unsigned sign=0;sign<2;++sign)for(unsigned t=0;t<2;++t)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s],&samples[(s+5)%12],NULL,sign,t?5:0,pcs[host%3],3-host,host,EMPTY_DEST);
    if(form->index==0||form->index==3||form->index==7)for(unsigned s=0;s<sizeof(uncached)/sizeof(uncached[0]);++s)for(unsigned sign=0;sign<2;++sign)for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)run_case(&f,&uncached[s].raw,&samples[(s+5)%12],&uncached[s],sign,top,pcs[host%3],3-host,host,OCCUPIED);
    for(unsigned s=0;s<2;++s)for(unsigned sign=0;sign<2;++sign)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s?11:7],&samples[s?7:11],NULL,sign,5,3,3-host,host,VALID_IM_DM0);
    if(form->index==0||form->index==3||form->index==7)for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)for(unsigned im=0;im<2;++im){
        unsigned sides_count=form->kind==EXCHANGE&&form->index!=0?3:1;
        for(unsigned sides=0;sides<sides_count;++sides)run_case(&f,&samples[3],&samples[4],NULL,host&1,top,pcs[host%3],3-host,host,EMPTY_ST0+sides+3*im);
    }
    if(f.jit)check_kind(native_present(&f),"native compiled entry exists; helper allowed",EXECUTION);
    uint8_t actual[2];check(hb_memory_read(f.c->memory,CODE,actual,2)==HB_OK&&!memcmp(actual,form->code,2),"raw instruction bytes preserved");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.c)hb_context_destroy(f.c);
}
static const struct{const char *name;enum hb_gate_id id;const char *value;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM,"0"},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR,"0"},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64,"0"},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS,"0"},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED,"0"},{"MACRUNNER_HB_UNCHAIN_STATS",HB_GATE_HB_UNCHAIN_STATS,"0"}
};
int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original_host;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *s=getenv(gates[i].name);if(s&&!check((saved[i]=strdup(s))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,gates[i].value,1)==0,"select private helper policy"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);if(!check(s&&!strcmp(s,gates[i].value),"effective gate"))goto done;}
    if(!check(fegetenv(&original_host)==0,"save original host fenv"))goto done;host_saved=1;fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host FP exceptions"))goto done;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned form=0;form<sizeof(forms)/sizeof(forms[0]);++form)run_form(&forms[form],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_register_transfer_test: %u executions (%u ordinary, %u empty destination, %u uncached, %u valid IM/DM0, %u masked empty, %u unmasked empty), %u checks, %u failures\n",executions,ordinary_cases,empty_dest_cases,uncached_cases,unmasked_valid_cases,masked_empty_cases,unmasked_empty_cases,checks,failures);
    printf("failure categories: raw=%u state=%u execution=%u host=%u\n",category_failures[RAW],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
