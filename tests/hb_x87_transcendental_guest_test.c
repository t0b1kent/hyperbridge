/* Consolidated nine-operation guest regression.
 * Fixed independent literals establish numerical expectations. Marked component
 * and legacy-libc references establish transport/commit expectations only.
 * No production admission predicate or guest operation is used as an oracle. */
#pragma STDC FENV_ACCESS ON
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include "transcendental_guest_test_reference.h"
#include "transcendental_guest_support.h"
#include "transcendental_guest_vectors.h"
#include "transcendental_guest_quadrants.h"
#include <math.h>
#include <stdlib.h>

#define MAP_BASE UINT64_C(0x7100000)
#define CODE (MAP_BASE+64u)
#define PAGE_BYTES 16384u
#define LENGTH(a) (sizeof(a)/sizeof((a)[0]))
enum {GT_NUMERIC,GT_BOUNDARY,GT_PENDING,GT_EMPTY,GT_OCCUPIED,GT_GROUPS};
enum {GT_COMPONENT,GT_LEGACY};
enum {RAW,STATUS,INTEGER_FLAGS,STATE,EXECUTION,HOST,DECODE,CATEGORIES};
typedef struct {const ct_vector *vector;unsigned cache;} gt_numeric_row;
typedef struct {
    const char *name;hb_x87_transcendental_op_t operation;ct_words a,b;
    unsigned cache,pending,empty,im,occupied,reference,category;
} gt_control_row;
#include "transcendental_guest_rows.h"
typedef struct {
    hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;
    hb_interpreter_t *interp;hb_jit_runtime_t *jit;unsigned operation;
} fixture_t;
static ct_stats stats;
static unsigned executions,group_calls[GT_GROUPS],category_failures[CATEGORIES];
static int check_kind(int ok,const char *what,unsigned kind)
{if(!ok)++category_failures[kind];return ct_check(&stats,ok,what);}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static const struct {const char *name;uint8_t bytes[2];unsigned opcode,ir;} forms[]={
    {"F2XM1",{0xd9,0xf0},HB_INS_X87_F2XM1,HB_IR_X87_F2XM1},
    {"FYL2X",{0xd9,0xf1},HB_INS_X87_FYL2X,HB_IR_X87_FYL2X},
    {"FYL2XP1",{0xd9,0xf9},HB_INS_X87_FYL2XP1,HB_IR_X87_FYL2XP1},
    {"FPATAN",{0xd9,0xf3},HB_INS_X87_FPATAN,HB_IR_X87_FPATAN},
    {"FSIN",{0xd9,0xfe},HB_INS_X87_FSIN,HB_IR_X87_FSIN},
    {"FCOS",{0xd9,0xff},HB_INS_X87_FCOS,HB_IR_X87_FCOS},
    {"FSINCOS",{0xd9,0xfb},HB_INS_X87_FSINCOS,HB_IR_X87_FSINCOS},
    {"FPTAN",{0xd9,0xf2},HB_INS_X87_FPTAN,HB_IR_X87_FPTAN},
    {"FSCALE",{0xd9,0xfd},HB_INS_X87_FSCALE,HB_IR_X87_FSCALE}};
_Static_assert(HB_X87_TRANS_F2XM1==0&&HB_X87_TRANS_FYL2X==1&&HB_X87_TRANS_FYL2XP1==2&&
               HB_X87_TRANS_FPATAN==3&&HB_X87_TRANS_FSIN==4&&HB_X87_TRANS_FCOS==5&&
               HB_X87_TRANS_FSINCOS==6&&HB_X87_TRANS_FPTAN==7&&HB_X87_TRANS_FSCALE==8,
               "Explicit opcode table follows the private enum");
static const struct{const char *name;enum hb_gate_id id;const char *value;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64,"0"},
    {"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS,"0"},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED,"0"},
    {"MACRUNNER_HB_UNCHAIN_STATS",HB_GATE_HB_UNCHAIN_STATS,"0"}};

static void install_words(hb_x87_state_t *x,unsigned physical,ct_words words)
{uint8_t raw[10];gt_raw(raw,words.sign_exp,words.significand);gt_store(x,physical,raw);}
static void seed(fixture_t *f,const gt_control_row *v,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned hf)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));memset(&c->x87_64,0x56,sizeof(c->x87_64));
    hb_x87_state_t *x=hb_context_x87(c);memset(x,0,sizeof(*x));x->top=(uint8_t)top;
    x->control_word=(uint16_t)(0x007eu|v->im|(pc<<8)|(rc<<10));
    x->status_word=(uint16_t)((top<<11)|0x0024u|((cc&7u)<<8)|((cc&8u)<<11)|(hf?0x80c0u:0));
    x->last_x87_ip=0x12345678;
    for(unsigned p=0;p<8;++p){ct_words word={0x4002,UINT64_C(0x8000000000000000)+p*UINT64_C(0x0800000000000000)};install_words(x,p,word);}
    install_words(x,top,v->a);if(gt_binary(v->operation))install_words(x,(top+1u)&7u,v->b);
    unsigned operands=gt_binary(v->operation)?2u:1u;
    for(unsigned i=0;i<operands;++i)if(!(v->cache&(1u<<i))){unsigned p=(top+i)&7u;
        x->st_ext_valid&=(uint8_t)~(1u<<p);
        gt_raw(x->st_ext[p],(uint16_t)(0xc321u+i),UINT64_C(0xdeadbeef12345678)+i);}
    gt_tag(x,(top+6u)&7u,3);
    if(gt_pushes(v->operation)&&!v->occupied)gt_tag(x,(top+7u)&7u,3);
    if(v->pending){x->control_word&=(uint16_t)~v->pending;x->status_word|=(uint16_t)(0x8080u|v->pending);}
    for(unsigned i=0;i<operands;++i)if(v->empty&(1u<<i))gt_tag(x,(top+i)&7u,3);
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags.cf=(top&1)!=0;c->flags.pf=(rc&1)!=0;c->flags.af=true;c->flags.zf=(rc&2)!=0;c->flags.sf=true;c->flags.of=true;memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static int seed_host(unsigned rc,unsigned hf,unsigned invalid)
{return check_kind(ct_seed_host(rc,hf)&&(!invalid||feraiseexcept(FE_INVALID)==0),"seed complete host environment and inherited masked-empty/push INVALID only",HOST);}
static unsigned preview_tag(uint64_t bits)
{if(!(bits&UINT64_C(0x7fffffffffffffff)))return 1;return ((bits>>52)&0x7ffu)==0x7ffu?2u:0u;}
static void legacy_store(hb_x87_state_t *x,unsigned slot,uint64_t bits)
{memcpy(&x->st[slot],&bits,8);x->st_ext_valid&=(uint8_t)~(1u<<slot);gt_tag(x,slot,preview_tag(bits));}
static int underflow(hb_x87_state_t *x)
{x->status_word=(uint16_t)((x->status_word|0x0041u)&~0x0200u);if(x->control_word&1u)return 0;x->status_word|=0x8080u;return 1;}
static int legacy_operand(hb_x87_state_t *x,unsigned relative,uint64_t *bits)
{
    unsigned p=(x->top+relative)&7u;
    if(((x->tag_word>>(2*p))&3u)==3u){if(underflow(x))return 1;*bits=UINT64_C(0xfff8000000000000);}
    else memcpy(bits,&x->st[p],8);return 0;
}
/* These are the inherited libc expressions, not a mathematical oracle. Inputs
 * arrive as runtime bits and the function is not inlined, preventing folding
 * a selected test constant into a different library operation. */
__attribute__((noinline)) static void legacy_math(hb_x87_transcendental_op_t op,uint64_t av,uint64_t bv,uint64_t out[2])
{
    double a,b,value=0,second=0;memcpy(&a,&av,8);memcpy(&b,&bv,8);
    switch(op){
    case HB_X87_TRANS_F2XM1:value=exp2(a)-1.0;break;
    case HB_X87_TRANS_FYL2X:value=b*log2(a);break;
    case HB_X87_TRANS_FYL2XP1:value=b*log2(a+1.0);break;
    case HB_X87_TRANS_FPATAN:value=atan2(b,a);break;
    case HB_X87_TRANS_FSIN:value=sin(a);break;
    case HB_X87_TRANS_FCOS:value=cos(a);break;
    case HB_X87_TRANS_FSINCOS:value=sin(a);second=cos(a);break;
    case HB_X87_TRANS_FPTAN:value=tan(a);second=1.0;break;
    case HB_X87_TRANS_FSCALE:value=scalbn(a,(int)trunc(b));break;
    }
    memcpy(&out[0],&value,8);memcpy(&out[1],&second,8);
}
static hb_result_t legacy_reference(hb_x87_state_t *x,hb_x87_transcendental_op_t op)
{
    uint64_t a=0,b=0,result[2]={0,0};unsigned old=x->top;
    if(legacy_operand(x,0,&a)||(gt_binary(op)&&legacy_operand(x,1,&b)))return HB_ERR_EXEC_FAULT;
    legacy_math(op,a,b,result);
    unsigned selected=gt_pops(op)?(old+1u)&7u:old;
    if(((x->tag_word>>(2*selected))&3u)==3u){if(underflow(x))return HB_ERR_EXEC_FAULT;result[0]=UINT64_C(0xfff8000000000000);}
    legacy_store(x,selected,result[0]);
    if(gt_pops(op)){if(((x->tag_word>>(2*old))&3u)==3u)return HB_ERR_EXEC_FAULT;gt_tag(x,old,3);gt_top(x,(old+1u)&7u);}
    if(gt_pushes(op)){unsigned dest=(old+7u)&7u;
        if(((x->tag_word>>(2*dest))&3u)!=3u){x->status_word|=0x0241u;
            if(!(x->control_word&1u)){x->status_word|=0x8080u;return HB_ERR_EXEC_FAULT;}
            result[1]=UINT64_C(0xfff8000000000000);}
        gt_top(x,dest);legacy_store(x,dest,result[1]);}
    return HB_OK;
}
static void check_state(fixture_t *f,const hb_context_t *before,hb_context_t *expected)
{
    hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(expected);
    check_kind(!memcmp(x->st_ext,e->st_ext,sizeof(x->st_ext)),"all eight raw payloads, including popped/unused cache poison",RAW);
    check_kind(x->st_ext_valid==e->st_ext_valid,"complete raw cache mask",RAW);
    check_kind(!memcmp(x->st,e->st,sizeof(x->st))&&x->tag_word==e->tag_word,"all strict preview bits and tags",RAW);
    check_kind(x->status_word==e->status_word&&x->top==e->top,"exact status and TOP including partial faults",STATUS);
    check_kind(!memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"integer and lazy flags unchanged",INTEGER_FLAGS);
    e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"complete x87 state including control and poisoned neighbors");
    if(f->ctx->arch==HB_ARCH_X86)expected->regs.x86.eip=f->ctx->regs.x86.eip;else expected->regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected->regs,sizeof(expected->regs)),"GPR/XMM and overlapping x86 x87 state");
    if(f->ctx->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state unchanged");
    check(f->ctx->mxcsr==before->mxcsr,"MXCSR unchanged");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks unchanged");
    check(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments unchanged");
}
static void run_case(fixture_t *f,const gt_control_row *row,const ct_vector *literal,unsigned top,unsigned cc,unsigned pc,unsigned rc,unsigned hf,unsigned host)
{
    snprintf(stats.phase,sizeof(stats.phase),"%s/%s %s %s TOP%u CC%u PC%u RC%u host%u flags%u cache%u empty%u IM%u",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",forms[f->operation].name,row->name,top,cc,pc,rc,host,hf,row->cache,row->empty,row->im);
    seed(f,row,top,cc,pc,rc,hf);hb_context_t before,expected;memcpy(&before,f->ctx,sizeof(before));memcpy(&expected,&before,sizeof(expected));
    hb_result_t expected_return=HB_OK;ct_host wanted;
    unsigned pre_invalid=row->im&&(row->empty||row->occupied);
    if(literal){hb_x87_transcendental_result_t answer;memset(&answer,0,sizeof(answer));answer.result_count=(uint8_t)literal->result_count;
        for(unsigned k=0;k<literal->result_count;++k)gt_raw(answer.raw[k],literal->expected[rc][k].sign_exp,literal->expected[rc][k].significand);
        answer.component_flags=(uint8_t)literal->flags_value;answer.status_set=(literal->flags_value&0x10u)?1u:0u;
        answer.status_clear=(row->operation==HB_X87_TRANS_FSIN||row->operation==HB_X87_TRANS_FCOS||gt_pushes(row->operation))?0x0400u:0;
        if(!check(gt_commit(hb_context_x87(&expected),row->operation,&answer,&expected_return),"fixed independent literal and commit contract"))return;
    }else if(row->reference==GT_COMPONENT){gt_reference reference;
        if(!check(gt_transport_reference(hb_context_x87(&before),hb_context_x87(&expected),row->operation,&reference),"marked component transport reference and independent state commit"))return;
        expected_return=reference.expected_return;
    }
    if(!seed_host(host,hf,pre_invalid))return;
    if(!literal&&row->reference==GT_LEGACY){expected_return=legacy_reference(hb_context_x87(&expected),row->operation);wanted=ct_capture_host();
        if(!seed_host(host,hf,pre_invalid))return;
    }else wanted=ct_capture_host();
    hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);ct_host actual=ct_capture_host();
    ++executions;++group_calls[row->category];
    check_kind(ct_same_host(&wanted,&actual),row->reference==GT_LEGACY&&!literal?"host state equals separately seeded inherited libc reference":"complete host fenv/FPCR/FPSR unchanged",HOST);
    if(expected_return==HB_ERR_EXEC_FAULT)check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"expected inherited partial stack fault",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+2,"single selected guest instruction completes",EXECUTION);
    check_state(f,&before,&expected);
}
static int native_present(fixture_t *f)
{
    if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;
    for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;
}
static void check_ir(fixture_t *f)
{
    unsigned count=0;if(!check_kind(f->func->cfg!=NULL,"IR container present",DECODE))return;
    for(size_t b=0;b<f->func->cfg->block_count;++b){hb_ir_block_t *block=f->func->cfg->blocks[b];for(size_t k=0;k<block->instr_count;++k){hb_ir_instr_t *ir=&block->instrs[k];
        if((unsigned)ir->op!=forms[f->operation].ir)continue;++count;check_kind(ir->guest_addr==CODE,"selected implicit x87 IR address",DECODE);}}
    check_kind(count==1,"exactly one selected implicit x87 IR",DECODE);
}
static void run_form(hb_arch_t arch,hb_backend_t backend,unsigned operation)
{
    fixture_t f={0};f.operation=operation;uint8_t guard[130];ct_pattern(guard,sizeof(guard),0x75);memcpy(guard+64,forms[operation].bytes,2);
    f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create reusable nine-op context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,MAP_BASE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,MAP_BASE,guard,sizeof(guard))==HB_OK&&hb_memory_protect(f.ctx->memory,MAP_BASE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned instruction with adjacent code canaries"))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(forms[operation].bytes,2,CODE,&d):hb_decode_x64(forms[operation].bytes,2,CODE,&d);
    if(!check_kind(r==HB_OK&&d.len==2&&(unsigned)d.opcode==forms[operation].opcode,"decode selected two-byte x87 opcode",DECODE))goto done;
    check_kind(!d.op1.present&&!d.op2.present,"selected x87 operands are implicit",DECODE);
    f.decoder=hb_decoder_create(arch,forms[operation].bytes,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift selected instruction",EXECUTION))goto done;
    check_ir(&f);if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create selected guest runtime"))goto done;
    static const unsigned patterns[]={0,5,10,15};
    for(size_t s=0;s<LENGTH(gt_numeric_rows);++s){const gt_numeric_row *n=&gt_numeric_rows[s];const ct_vector *v=n->vector;if((unsigned)v->operation!=operation)continue;
        gt_control_row row={v->name,v->operation,v->st0,v->st1,n->cache,0,0,1,0,GT_COMPONENT,GT_NUMERIC};
        for(unsigned top=0;top<8;++top)for(unsigned ci=0;ci<4;++ci)for(unsigned pc=0;pc<4;++pc)for(unsigned rc=0;rc<4;++rc)for(unsigned hf=0;hf<2;++hf)
            run_case(&f,&row,v,top,patterns[ci],pc,rc,hf,(rc+ci)&3u);
    }
    if(f.jit)check_kind(native_present(&f),"selected native entry exists before controls",EXECUTION);
    for(size_t s=0;s<LENGTH(gt_control_rows);++s){const gt_control_row *row=&gt_control_rows[s];if((unsigned)row->operation!=operation)continue;
        for(unsigned top=0;top<8;++top)for(unsigned cc=0;cc<16;++cc)for(unsigned hf=0;hf<2;++hf)
            run_case(&f,row,NULL,top,cc,cc>>2,cc&3u,hf,(cc+top)&3u);
    }
    uint8_t actual[sizeof(guard)];check(hb_memory_read(f.ctx->memory,MAP_BASE,actual,sizeof(actual))==HB_OK&&!memcmp(actual,guard,sizeof(guard)),"instruction and adjacent code canaries unchanged");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.ctx)hb_context_destroy(f.ctx);
}
int main(void)
{
    ct_host caller=ct_capture_host();char *saved[LENGTH(gates)]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original;
    for(size_t i=0;i<LENGTH(gates);++i){const char *s=getenv(gates[i].name);if(s&&!check((saved[i]=strdup(s))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,gates[i].value,1)==0,"select helper gate"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);if(!check(s&&!strcmp(s,gates[i].value),"effective helper gate"))goto done;}
    if(!check(fegetenv(&original)==0,"save caller fenv"))goto done;host_saved=1;fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host traps"))goto done;
    for(unsigned op=0;op<9;++op)for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)
        run_form(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP,op);
    check(executions==706560u&&group_calls[GT_NUMERIC]==372736u&&group_calls[GT_BOUNDARY]==204800u&&group_calls[GT_PENDING]==55296u&&group_calls[GT_EMPTY]==65536u&&group_calls[GT_OCCUPIED]==8192u,"complete static guest matrix");
done:
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();
        for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    if(host_saved&&!check_kind(ct_restore_host(&caller),"restore complete caller host environment",HOST))return 2;
    printf("hb_x87_transcendental_guest_test: %u executions (%u numerical, %u boundary, %u pending, %u empty, %u occupied), %u checks, %u failures\n",executions,group_calls[GT_NUMERIC],group_calls[GT_BOUNDARY],group_calls[GT_PENDING],group_calls[GT_EMPTY],group_calls[GT_OCCUPIED],stats.checks,stats.failures);
    printf("failure categories: raw=%u status=%u integer_flags=%u state=%u execution=%u host=%u decode=%u\n",category_failures[RAW],category_failures[STATUS],category_failures[INTEGER_FLAGS],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[DECODE]);
    if(host_saved&&!ct_restore_host(&caller))return 2;
    return stats.failures?1:0;
}
