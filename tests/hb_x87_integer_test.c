/* Raw FIST/FISTP/FISTTP regression. Independent ext80 bit patterns and integer
 * answers exercise guest rounding separately from host fenv. M9's existing
 * setter only seeds ST0; results come from decoded/lifted guest instructions.
 * This tests single-instruction completion and pending exception bits, not
 * subsequent #MF delivery. C0/C2/C3 and FIP bookkeeping are outside the oracle.
 */
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <fenv.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_BYTES=16384, TOP=5, FIST=0, FISTP=1, FISTTP=2 };
enum { MASKED, UNMASKED_INVALID, UNMASKED_PRECISION, READ_ONLY, UNMAPPED };
static const uint64_t CODE=UINT64_C(0x4400000), DATA=UINT64_C(0x5400000);
static unsigned checks, failures, executions, host_failures, result_failures, state_failures;
static char phase[200]="setup";

static int check(int ok,const char *what)
{
    ++checks;
    if(!ok) { ++failures; if(failures<=80) fprintf(stderr,"FAIL %s: %s\n",phase,what); }
    return ok;
}
static void put16(uint8_t *p,uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put64(uint8_t *p,uint64_t v) { for(unsigned i=0;i<8;++i) p[i]=(uint8_t)(v>>(8*i)); }

typedef struct {
    const char *name;
    uint64_t sig;
    uint16_t se;
    int64_t rounded[4]; /* nearest, down, up, zero: mathematical integer result */
    unsigned invalid64_rc, widths, fractional, special;
} sample_t;
#define V(n,s,e,a,b,c,d,w,f) {n,UINT64_C(s),e,{a,b,c,d},0,w,f,0}
#define BAD(n,s,e,w) {n,UINT64_C(s),e,{0,0,0,0},15,w,0,1}
static const sample_t samples[]={
    V("+zero",0,0,0,0,0,0,7,0),
    V("-zero",0,0x8000,0,0,0,0,7,0),
    V("+0.5",0x8000000000000000,0x3ffe,0,0,1,0,7,1),
    V("-0.5",0x8000000000000000,0xbffe,0,-1,0,0,7,1),
    V("+1.5",0xc000000000000000,0x3fff,2,1,2,1,7,1),
    V("-1.5",0xc000000000000000,0xbfff,-2,-2,-1,-1,7,1),
    V("+2.5",0xa000000000000000,0x4000,2,2,3,2,7,1),
    V("-2.5",0xa000000000000000,0xc000,-2,-3,-2,-2,7,1),
    V("+3.5",0xe000000000000000,0x4000,4,3,4,3,7,1),
    V("-3.5",0xe000000000000000,0xc000,-4,-4,-3,-3,7,1),
    V("below +2.5",0x9fffffffffffffff,0x4000,2,2,3,2,7,1),
    V("above +2.5",0xa000000000000001,0x4000,3,2,3,2,7,1),
    V("tiny extended normal",0x8000000000000000,1,0,0,1,0,7,1),
    V("negative tiny extended normal",0x8000000000000000,0x8001,0,-1,0,0,7,1),
    V("smallest ext80 denormal",1,0,0,0,1,0,7,1),
    V("pseudodenormal",0x8000000000000000,0,0,0,1,0,7,1),
    BAD("quiet NaN",0xc123456789abcdef,0x7fff,7),
    BAD("signaling NaN",0x8123456789abcdef,0x7fff,7),
    BAD("positive infinity",0x8000000000000000,0x7fff,7),
    BAD("negative infinity",0x8000000000000000,0xffff,7),
    BAD("unsupported unnormal",0x4000000000000000,0x3fff,7),
    V("i16 maximum",0xfffe000000000000,0x400d,32767,32767,32767,32767,1,0),
    V("i16 +limit",0x8000000000000000,0x400e,32768,32768,32768,32768,1,0),
    V("i16 minimum",0x8000000000000000,0xc00e,-32768,-32768,-32768,-32768,1,0),
    V("i16 maximum+half",0xffff000000000000,0x400d,32768,32767,32768,32767,1,1),
    V("i16 minimum+half",0xffff000000000000,0xc00d,-32768,-32768,-32767,-32767,1,1),
    V("i16 minimum-half",0x8000800000000000,0xc00e,-32768,-32769,-32768,-32768,1,1),
    V("i16 below minimum",0x8001000000000000,0xc00e,-32769,-32769,-32769,-32769,1,0),
    V("i32 maximum",0xfffffffe00000000,0x401d,INT64_C(2147483647),INT64_C(2147483647),INT64_C(2147483647),INT64_C(2147483647),2,0),
    V("i32 +limit",0x8000000000000000,0x401e,INT64_C(2147483648),INT64_C(2147483648),INT64_C(2147483648),INT64_C(2147483648),2,0),
    V("i32 minimum",0x8000000000000000,0xc01e,-INT64_C(2147483648),-INT64_C(2147483648),-INT64_C(2147483648),-INT64_C(2147483648),2,0),
    V("i32 maximum+half",0xffffffff00000000,0x401d,INT64_C(2147483648),INT64_C(2147483647),INT64_C(2147483648),INT64_C(2147483647),2,1),
    V("i32 minimum+half",0xffffffff00000000,0xc01d,-INT64_C(2147483648),-INT64_C(2147483648),-INT64_C(2147483647),-INT64_C(2147483647),2,1),
    V("i32 minimum-half",0x8000000080000000,0xc01e,-INT64_C(2147483648),-INT64_C(2147483649),-INT64_C(2147483648),-INT64_C(2147483648),2,1),
    V("i32 below minimum",0x8000000100000000,0xc01e,-INT64_C(2147483649),-INT64_C(2147483649),-INT64_C(2147483649),-INT64_C(2147483649),2,0),
    V("i64 maximum",0xfffffffffffffffe,0x403d,INT64_MAX,INT64_MAX,INT64_MAX,INT64_MAX,4,0),
    BAD("i64 +limit",0x8000000000000000,0x403e,4),
    V("i64 minimum",0x8000000000000000,0xc03e,INT64_MIN,INT64_MIN,INT64_MIN,INT64_MIN,4,0),
    {"i64 maximum+half",UINT64_C(0xffffffffffffffff),0x403d,{0,INT64_MAX,0,INT64_MAX},5,4,1,0},
    V("i64 minimum+half",0xffffffffffffffff,0xc03d,INT64_MIN,INT64_MIN,-INT64_MAX,-INT64_MAX,4,1),
    BAD("i64 below minimum",0x8000000000000001,0xc03e,4),
    V("i64 maximum-half",0xfffffffffffffffd,0x403d,INT64_MAX-1,INT64_MAX-1,INT64_MAX,INT64_MAX-1,4,1),
    V("exact 2^53+1",0x8000000000000400,0x4034,INT64_C(9007199254740993),INT64_C(9007199254740993),INT64_C(9007199254740993),INT64_C(9007199254740993),4,0),
    V("exact -(2^53+1)",0x8000000000000400,0xc034,-INT64_C(9007199254740993),-INT64_C(9007199254740993),-INT64_C(9007199254740993),-INT64_C(9007199254740993),4,0)
};
#undef V
#undef BAD

typedef struct {unsigned family,bits;uint8_t code[2];int opcode;} form_t;
static const form_t forms[]={
    {FIST,16,{0xdf,0x11},HB_INS_X87_FIST},{FIST,32,{0xdb,0x11},HB_INS_X87_FIST},
    {FISTP,16,{0xdf,0x19},HB_INS_X87_FISTP},{FISTP,32,{0xdb,0x19},HB_INS_X87_FISTP},
    {FISTP,64,{0xdf,0x39},HB_INS_X87_FISTP},
    {FISTTP,16,{0xdf,0x09},HB_INS_X87_FISTTP},{FISTTP,32,{0xdb,0x09},HB_INS_X87_FISTTP},
    {FISTTP,64,{0xdd,0x09},HB_INS_X87_FISTTP}
};
static const char *family_names[]={"FIST","FISTP","FISTTP"};
static const int host_rounds[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};

typedef struct {uint64_t bits;int invalid,precision,c1;} answer_t;
static uint64_t magnitude(int64_t v) {return v<0 ? UINT64_C(0)-(uint64_t)v:(uint64_t)v;}
static answer_t expected_answer(const sample_t *s,const form_t *f,unsigned rc,int empty)
{
    unsigned selected=f->family==FISTTP ? 3:rc;
    int64_t value=s->rounded[selected];
    int invalid=empty || s->special || ((s->invalid64_rc>>selected)&1u);
    if(f->bits==16 && (value<INT16_MIN || value>INT16_MAX)) invalid=1;
    if(f->bits==32 && (value<INT32_MIN || value>INT32_MAX)) invalid=1;
    answer_t a={.bits=invalid ? UINT64_C(1)<<(f->bits-1):(uint64_t)value,.invalid=invalid};
    a.precision=!invalid && s->fractional;
    a.c1=a.precision && f->family!=FISTTP && magnitude(value)>magnitude(s->rounded[3]);
    return a;
}

typedef struct {
    hb_context_t *ctx;
    hb_decoder_t *decoder;
    hb_ir_func_t *func;
    hb_interpreter_t *interp;
    hb_jit_runtime_t *jit;
    const form_t *form;
    hb_arch_t arch;
    hb_backend_t backend;
} fixture_t;

static int seed(fixture_t *f,const sample_t *s,unsigned rc,unsigned mode,int empty,uint16_t sticky)
{
    hb_context_t *ctx=f->ctx;
    memset(&ctx->regs,0x3c,sizeof(ctx->regs));
    uint64_t target=mode==UNMAPPED ? DATA+2*PAGE_BYTES:DATA+128;
    if(f->arch==HB_ARCH_X86) {
        ctx->regs.x86.ecx=(uint32_t)target;ctx->regs.x86.eip=(uint32_t)CODE;ctx->regs.x86.eflags=0xa57;
    } else {ctx->regs.x64.rcx=target;ctx->regs.x64.rip=CODE;ctx->regs.x64.rflags=0xa57;}
    memset(ctx->ymm_hi,0x7a,sizeof(ctx->ymm_hi));memset(ctx->zmm_hi,0x4b,sizeof(ctx->zmm_hi));
    memset(ctx->k,0x39,sizeof(ctx->k));memset(ctx->xmm_ext,0x51,sizeof(ctx->xmm_ext));
    memset(ctx->ymm_hi_ext,0x62,sizeof(ctx->ymm_hi_ext));memset(ctx->zmm_hi_ext,0x73,sizeof(ctx->zmm_hi_ext));
    if(f->arch==HB_ARCH_X86) memset(&ctx->x87_64,0x49,sizeof(ctx->x87_64));
    hb_x87_state_t *x=hb_context_x87(ctx);hb_x87_reset(x);
    x->top=TOP;x->status_word=(uint16_t)((TOP<<11)|0x0200|sticky);
    x->control_word=(uint16_t)(0x037f|(rc<<10));x->last_x87_ip=0x12345678;
    if(mode==UNMASKED_INVALID) x->control_word&=(uint16_t)~1u;
    if(mode==UNMASKED_PRECISION) x->control_word&=(uint16_t)~0x20u;
    uint8_t ext[10];put64(ext,UINT64_C(0x9000000000000000));put16(ext+8,0x4002);
    for(unsigned i=0;i<8;++i) if(!check(hb_x87_set_st_ext80(x,i,ext,true)==HB_OK,"seed independent neighboring register")) return 0;
    put64(ext,s->sig);put16(ext+8,s->se);
    if(!check(hb_x87_set_st_ext80(x,0,ext,!empty)==HB_OK,"seed exact raw ST0 and occupancy")) return 0;
    ctx->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};
    memset(&ctx->lazy_flags,0,sizeof(ctx->lazy_flags));
    ctx->mxcsr=0x5fa1;ctx->pc=CODE;ctx->last_result=HB_OK;
    ctx->last_fault_kind=HB_FAULT_KIND_NONE;ctx->last_fault_addr_valid=0;
    ctx->fs_base=0x11110000;ctx->gs_base=0x22220000;
    ctx->seg_cs=0x33;ctx->seg_ds=0x2b;ctx->seg_es=0x31;ctx->seg_fs=0x53;ctx->seg_gs=0x61;ctx->seg_ss=0x69;
    ctx->step_limit=8;ctx->block_limit=2;
    return 1;
}

static void check_state(const fixture_t *f,const hb_context_t *before,answer_t a,unsigned mode,int empty)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));
    hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    int memory_fault=mode==READ_ONLY || mode==UNMAPPED;
    int invalid_fault=a.invalid && mode==UNMASKED_INVALID;
    if(!memory_fault) {
        uint16_t status=(uint16_t)(e->status_word&~0x0200u);
        if(a.invalid) status|=(uint16_t)(1u|(empty?0x40u:0u));
        else if(a.precision) status|=0x20;
        if(a.c1) status|=0x0200;
        if(invalid_fault || (a.precision && mode==UNMASKED_PRECISION)) status|=0x8080;
        if(f->form->family!=FIST && !invalid_fault) {
            e->tag_word|=(uint16_t)(3u<<(2*TOP));e->top=(TOP+1)&7;
            status=(uint16_t)((status&~0x3800u)|(e->top<<11));
        }
        /* C0/C2/C3 are explicitly undefined for this instruction family. */
        e->status_word=(uint16_t)((status&~0x4500u)|(x->status_word&0x4500u));
    }
    /* The existing interpreter updates FIP before its staged conversion/write;
     * this suite makes no exception-delivery or FIP contract claim. */
    e->last_x87_ip=x->last_x87_ip;
    if(!check(!memcmp(x,e,sizeof(*x)),"x87 payload/cache/control/status/TOP/tag outcome")) ++state_failures;
    if(f->arch==HB_ARCH_X86) expected.regs.x86.eip=f->ctx->regs.x86.eip;
    else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    if(!check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register state")) ++state_failures;
    check(f->ctx->mxcsr==before->mxcsr && !memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags)) &&
          !memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi)) && !memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi)) &&
          !memcmp(f->ctx->k,before->k,sizeof(before->k)) && !memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext)) &&
          !memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext)) &&
          !memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"extended vector/opmask state preserved");
    if(f->arch==HB_ARCH_X86) check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->fs_base==before->fs_base && f->ctx->gs_base==before->gs_base && f->ctx->seg_cs==before->seg_cs &&
          f->ctx->seg_ds==before->seg_ds && f->ctx->seg_es==before->seg_es && f->ctx->seg_fs==before->seg_fs &&
          f->ctx->seg_gs==before->seg_gs && f->ctx->seg_ss==before->seg_ss,"segment state preserved");
}

static void run_one_source(fixture_t *f,const sample_t *s,unsigned rc,unsigned host,unsigned mode,int empty,
                           uint16_t sticky,const uint64_t *uncached_bits)
{
    uint8_t expected_memory[64],actual_memory[64];hb_context_t before;
    snprintf(phase,sizeof(phase),"%s %s %s%u %s guestRC=%u hostRC=%u mode=%u empty=%d uncached=%d",
             f->arch==HB_ARCH_X86?"x86":"x64",f->backend==HB_BACKEND_JIT?"JIT":"interp",
             family_names[f->form->family],f->form->bits,s->name,rc,host,mode,empty,uncached_bits!=NULL);
    memset(expected_memory,0xa5,sizeof(expected_memory));
    if(!check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f->ctx->memory,DATA+112,expected_memory,sizeof(expected_memory))==HB_OK,"seed owned destination guards")) return;
    if(!seed(f,s,rc,mode,empty,sticky)) return;
    if(uncached_bits) {
        hb_x87_state_t *x=hb_context_x87(f->ctx);
        memcpy(&x->st[TOP],uncached_bits,sizeof(*uncached_bits));
        x->st_ext_valid&=(uint8_t)~(1u<<TOP);
    }
    if(mode==READ_ONLY && !check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ)==HB_OK,"protect destination read-only")) return;
    answer_t a=expected_answer(s,f->form,rc,empty);
    int memory_fault=mode==READ_ONLY || mode==UNMAPPED;
    int invalid_fault=a.invalid && mode==UNMASKED_INVALID;
    if(!memory_fault && !invalid_fault) for(unsigned i=0;i<f->form->bits/8;++i) expected_memory[16+i]=(uint8_t)(a.bits>>(8*i));
    memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(host_rounds[host])==0 && feclearexcept(FE_ALL_EXCEPT)==0 && feraiseexcept(FE_DIVBYZERO)==0,
              "seed independent masked host fenv")) return;
    int host_status=fetestexcept(FE_ALL_EXCEPT);
    hb_exec_result_t out={0};
    hb_result_t result=f->jit ? hb_jit_runtime_run(f->jit,f->func,&out) : hb_interpreter_run(f->interp,f->func,&out);
    int actual_round=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);
    ++executions;
    if(!check(actual_round==host_rounds[host] && actual_status==host_status,"guest conversion preserves host FP environment")) {
        if(++host_failures<=4) fprintf(stderr,"HOST-FENV %s actual round=%d status=0x%x expected round=%d status=0x%x\n",
                                      phase,actual_round,actual_status,host_rounds[host],host_status);
    }
    if(memory_fault || invalid_fault) {
        hb_result_t expected_result=memory_fault?HB_ERR_MEMORY_FAULT:HB_ERR_EXEC_FAULT;
        if(!check((result==HB_OK || result==expected_result) && out.result==expected_result && out.faulted && !out.timed_out,
                  "expected memory or unmasked-invalid fault")) ++result_failures;
    } else if(!check(result==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out && out.steps_executed &&
                     out.blocks_executed && f->ctx->pc==CODE+2,"instruction completes store/pop, including unmasked precision")) ++result_failures;
    check_state(f,&before,a,mode,empty);
    /* Restore owned permissions on every path before subsequent inspection. */
    check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore destination permissions");
    if(!check(hb_memory_read(f->ctx->memory,DATA+112,actual_memory,sizeof(actual_memory))==HB_OK &&
              !memcmp(actual_memory,expected_memory,sizeof(actual_memory)),"exact integer bytes or no write, with adjacent guards")) ++result_failures;
}

static void run_one(fixture_t *f,const sample_t *s,unsigned rc,unsigned host,unsigned mode,int empty,uint16_t sticky)
{
    run_one_source(f,s,rc,host,mode,empty,sticky,NULL);
}

static const struct {uint64_t bits;sample_t value;} uncached[]={
    {UINT64_C(0x7ff0123456789abc),{"binary64 sNaN",UINT64_C(0x8123456789abcdef),0x7fff,{0,0,0,0},15,7,0,1}},
    {UINT64_C(0x7ff8123456789abc),{"binary64 qNaN",UINT64_C(0xc123456789abcdef),0x7fff,{0,0,0,0},15,7,0,1}},
    {UINT64_C(0x7ff0000000000000),{"binary64 +Inf",UINT64_C(0x8000000000000000),0x7fff,{0,0,0,0},15,7,0,1}},
    {UINT64_C(0xfff0000000000000),{"binary64 -Inf",UINT64_C(0x8000000000000000),0xffff,{0,0,0,0},15,7,0,1}},
    {UINT64_C(0x43e0000000000000),{"binary64 +2^63",UINT64_C(0x8000000000000000),0x403e,{0,0,0,0},15,7,0,0}},
    {UINT64_C(0xc3e0000000000000),{"binary64 -2^63",UINT64_C(0x8000000000000000),0xc03e,{INT64_MIN,INT64_MIN,INT64_MIN,INT64_MIN},0,7,0,0}},
    {UINT64_C(0x3ff8000000000000),{"binary64 1.5",UINT64_C(0xc000000000000000),0x3fff,{2,1,2,1},0,7,1,0}},
    {UINT64_C(1),{"binary64 smallest subnormal",UINT64_C(0x8000000000000000),0x3bcd,{0,0,1,0},0,7,1,0}}
};

static int native_present(const hb_jit_runtime_t *jit)
{
    if(!jit || !jit->block_cache) return 0;
    for(size_t i=0;i<jit->block_cache->size;++i) {const hb_block_cache_entry_t *e=&jit->block_cache->entries[i];
        if(e->valid && e->guest_addr==CODE && e->native_code && e->native_size) return 1;}
    return 0;
}

static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={.form=form,.arch=arch,.backend=backend};
    snprintf(phase,sizeof(phase),"%s %s%u setup",arch==HB_ARCH_X86?"x86":"x64",family_names[form->family],form->bits);
    f.ctx=hb_context_create(arch,backend);
    if(!check(f.ctx!=NULL,"create per-form reusable context")) goto done;
    f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory && hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f.ctx->memory,CODE,form->code,sizeof(form->code))==HB_OK &&
              hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK &&
              hb_memory_map_private(f.ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map private guest pages")) goto done;
    hb_decoded_t d={0};
    hb_result_t decoded=arch==HB_ARCH_X86?hb_decode_x86(form->code,2,CODE,&d):hb_decode_x64(form->code,2,CODE,&d);
    if(!check(decoded==HB_OK && d.len==2 && (int)d.opcode==form->opcode && d.op1.size==form->bits/8,
              "decode exact integer-store opcode and operand width")) goto done;
    f.decoder=hb_decoder_create(arch,form->code,2,CODE);
    if(!check(f.decoder!=NULL,"create decoder")) goto done;
    hb_result_t lifted=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);
    if(!check(lifted==HB_OK && f.func,"lift raw guest instruction")) goto done;
    if(backend==HB_BACKEND_JIT) f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);
    if(!check(f.jit || f.interp,"create reusable runtime")) goto done;
    unsigned width_mask=form->bits==16?1:form->bits==32?2:4;
    for(unsigned host=0;host<4;++host) for(unsigned rc=0;rc<4;++rc) {
        for(size_t i=0;i<sizeof(samples)/sizeof(samples[0]);++i) if(samples[i].widths&width_mask)
            run_one(&f,&samples[i],rc,host,MASKED,0,0x0004);
        /* A cached fractional payload must not override an empty tag or add PE. */
        run_one(&f,&samples[6],rc,host,MASKED,1,0x0004);
    }
    for(unsigned rc=0;rc<4;++rc) {
        for(size_t i=0;i<sizeof(samples)/sizeof(samples[0]);++i)
            if((samples[i].widths&width_mask) && expected_answer(&samples[i],form,rc,0).invalid)
                run_one(&f,&samples[i],rc,2,UNMASKED_INVALID,0,0x0004);
        run_one(&f,&samples[6],rc,2,UNMASKED_INVALID,1,0x0004);
        for(unsigned host=0;host<4;++host) {
            run_one(&f,&samples[6],rc,host,UNMASKED_PRECISION,0,0x0004);
            run_one(&f,&samples[7],rc,host,UNMASKED_PRECISION,0,0x0004);
        }
    }
    run_one(&f,&samples[16],0,2,MASKED,0,0x0044); /* SF is sticky through a later nonempty invalid. */
    run_one(&f,&samples[6],0,2,READ_ONLY,0,0x0004);
    run_one(&f,&samples[6],0,2,UNMAPPED,0,0x0004);
    /* One nondefault host mode keeps this fallback subset compact; the primary
     * raw80 matrix above crosses all four host and guest rounding modes. */
    for(unsigned rc=0;rc<4;++rc) for(size_t i=0;i<sizeof(uncached)/sizeof(uncached[0]);++i)
        run_one_source(&f,&uncached[i].value,rc,2,MASKED,0,0x0004,&uncached[i].bits);
    if(f.jit) check(native_present(f.jit),"JIT has an actual native guest entry block");
done:
    if(f.jit) hb_jit_runtime_destroy(f.jit);
    if(f.interp) hb_interpreter_destroy(f.interp);
    if(f.decoder) hb_decoder_destroy(f.decoder);
    if(f.func) hb_ir_func_destroy(f.func);
    if(f.ctx) hb_context_destroy(f.ctx);
}

static const struct {const char *name;enum hb_gate_id id;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM},
    {"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64},
    {"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED}
};

int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;
    int changed=0,host_saved=0;fenv_t original_host;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i) {const char *v=getenv(gates[i].name);
        if(v && !check((saved[i]=strdup(v))!=NULL,"save gate value")) goto done;++saved_count;}
    changed=1;
    for(size_t i=0;i<saved_count;++i) if(!check(setenv(gates[i].name,"0",1)==0,"select helper memory")) goto done;
    hb_env_refresh();
    for(size_t i=0;i<saved_count;++i) {const char *v=hb_gate(gates[i].id);if(!check(v && !strcmp(v,"0"),"effective helper gate")) goto done;}
    if(!check(feholdexcept(&original_host)==0,"save host fenv and mask host exceptions")) goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch) for(unsigned backend=0;backend<2;++backend)
        for(size_t i=0;i<sizeof(forms)/sizeof(forms[0]);++i)
            run_form(&forms[i],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    snprintf(phase,sizeof(phase),"cleanup");
    if(host_saved) check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed) {
        for(size_t i=0;i<saved_count;++i) check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate or absence");
        hb_env_refresh();
        for(size_t i=0;i<saved_count;++i) {const char *v=hb_gate(gates[i].id);check(saved[i]?v && !strcmp(v,saved[i]):!v,"effective original gate restored");}
    }
    for(size_t i=0;i<saved_count;++i) free(saved[i]);
    printf("hb_x87_integer_test: %u executions, %u checks, %u failures (host=%u result=%u state=%u)\n",
           executions,checks,failures,host_failures,result_failures,state_failures);
    return failures?1:0;
}
