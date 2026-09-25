/* Raw FRNDINT D9 FC through both decoders/lifters and interpreter/JIT.
 * Raw80 results below are independent fixed fixtures. No host FP arithmetic
 * creates an oracle, including values beyond binary64 precision/range.
 * Valid PC encodings 00/10/11 are tested; reserved PC01 is excluded. Single
 * instruction status/commit behavior is tested, not subsequent #MF delivery.
 * C0/C2/C3 and inherited FIP/fault-PC bookkeeping are outside the oracle.
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

enum {PAGE_BYTES=16384,JIT_BATCH=1024};
enum {NUMERIC,STATE,EXECUTION,HOST,CATEGORIES};
enum {EXACT,FRACTION,DENORMAL,SNAN,UNSUPPORTED,EMPTY};
enum {MASKED,UNMASKED_INVALID,UNMASKED_DENORMAL,UNMASKED_PRECISION};
enum {KEEP,ZP,ZN,P1,N1,P2,N2,P3,N3,P4,N4,P53,N53,P53_1,N53_1,P63,N63,P63_1,N63_1,INDEFINITE};
static const uint64_t CODE=UINT64_C(0x4a00000),DATA=UINT64_C(0x5a00000);
static const uint8_t code[]={0xd9,0xfc};
static unsigned checks,failures,executions,category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} value_t;
static const value_t values[]={
    {0,0,0,0}, /* KEEP uses the sample's full raw value. */
    {0,0,0,1},{0,0x8000,0x8000000000000000,1},
    {0x8000000000000000,0x3fff,0x3ff0000000000000,0},{0x8000000000000000,0xbfff,0xbff0000000000000,0},
    {0x8000000000000000,0x4000,0x4000000000000000,0},{0x8000000000000000,0xc000,0xc000000000000000,0},
    {0xc000000000000000,0x4000,0x4008000000000000,0},{0xc000000000000000,0xc000,0xc008000000000000,0},
    {0x8000000000000000,0x4001,0x4010000000000000,0},{0x8000000000000000,0xc001,0xc010000000000000,0},
    {0x8000000000000000,0x4034,0x4340000000000000,0},{0x8000000000000000,0xc034,0xc340000000000000,0},
    {0x8000000000000400,0x4034,0x4340000000000000,0},{0x8000000000000400,0xc034,0xc340000000000000,0},
    {0x8000000000000000,0x403e,0x43e0000000000000,0},{0x8000000000000000,0xc03e,0xc3e0000000000000,0},
    {0xfffffffffffffffe,0x403d,0x43e0000000000000,0},{0xfffffffffffffffe,0xc03d,0xc3e0000000000000,0},
    {0xc000000000000000,0xffff,0xfff8000000000000,2}
};
typedef struct {const char *name;value_t input;unsigned kind,result[4],c1_mask;} sample_t;
#define V(n,s,e,p,t,k,a,b,c,d,m) {n,{UINT64_C(s),e,UINT64_C(p),t},k,{a,b,c,d},m}
#define SAME(n,s,e,p,t) V(n,s,e,p,t,EXACT,KEEP,KEEP,KEEP,KEEP,0)
static const sample_t samples[]={
    SAME("+zero",0,0,0,1),SAME("-zero",0,0x8000,0x8000000000000000,1),
    V("+0.5",0x8000000000000000,0x3ffe,0x3fe0000000000000,0,FRACTION,ZP,ZP,P1,ZP,4),
    V("-0.5",0x8000000000000000,0xbffe,0xbfe0000000000000,0,FRACTION,ZN,N1,ZN,ZN,2),
    V("+1.5",0xc000000000000000,0x3fff,0x3ff8000000000000,0,FRACTION,P2,P1,P2,P1,5),
    V("-1.5",0xc000000000000000,0xbfff,0xbff8000000000000,0,FRACTION,N2,N2,N1,N1,3),
    V("+2.5",0xa000000000000000,0x4000,0x4004000000000000,0,FRACTION,P2,P2,P3,P2,4),
    V("-2.5",0xa000000000000000,0xc000,0xc004000000000000,0,FRACTION,N2,N3,N2,N2,2),
    V("+3.5",0xe000000000000000,0x4000,0x400c000000000000,0,FRACTION,P4,P3,P4,P3,5),
    V("-3.5",0xe000000000000000,0xc000,0xc00c000000000000,0,FRACTION,N4,N4,N3,N3,3),
    V("below+2.5",0x9fffffffffffffff,0x4000,0x4004000000000000,0,FRACTION,P2,P2,P3,P2,4),
    V("above+2.5",0xa000000000000001,0x4000,0x4004000000000000,0,FRACTION,P3,P2,P3,P2,5),
    V("tiny normal",0x8000000000000000,1,0,0,FRACTION,ZP,ZP,P1,ZP,4),
    V("negative tiny normal",0x8000000000000000,0x8001,0x8000000000000000,0,FRACTION,ZN,N1,ZN,ZN,2),
    V("smallest denormal",1,0,0,2,DENORMAL,ZP,ZP,P1,ZP,4),
    V("negative smallest denormal",1,0x8000,0x8000000000000000,2,DENORMAL,ZN,N1,ZN,ZN,2),
    V("largest denormal",0x7fffffffffffffff,0,0,2,DENORMAL,ZP,ZP,P1,ZP,4),
    V("pseudo-denormal",0x8000000000000000,0,0,2,DENORMAL,ZP,ZP,P1,ZP,4),
    V("negative pseudo-denormal",0x8000000000000000,0x8000,0x8000000000000000,2,DENORMAL,ZN,N1,ZN,ZN,2),
    SAME("exact2^53+1",0x8000000000000400,0x4034,0x4340000000000000,0),
    SAME("exact-(2^53+1)",0x8000000000000400,0xc034,0xc340000000000000,0),
    V("2^53+0.5",0x8000000000000200,0x4034,0x4340000000000000,0,FRACTION,P53,P53,P53_1,P53,4),
    V("-(2^53+0.5)",0x8000000000000200,0xc034,0xc340000000000000,0,FRACTION,N53,N53_1,N53,N53,2),
    V("2^63-0.5",0xffffffffffffffff,0x403d,0x43e0000000000000,0,FRACTION,P63,P63_1,P63,P63_1,5),
    V("-(2^63-0.5)",0xffffffffffffffff,0xc03d,0xc3e0000000000000,0,FRACTION,N63,N63,N63_1,N63_1,3),
    SAME("exact2^63+1",0x8000000000000001,0x403e,0x43e0000000000000,0),
    SAME("huge beyond binary64",0x8000000000000001,0x43ff,0x7ff0000000000000,0),
    SAME("negative huge beyond binary64",0x8000000000000001,0xc3ff,0xfff0000000000000,0),
    SAME("largest finite ext80",0xffffffffffffffff,0x7ffe,0x7ff0000000000000,0),
    SAME("+Inf",0x8000000000000000,0x7fff,0x7ff0000000000000,2),
    SAME("-Inf",0x8000000000000000,0xffff,0xfff0000000000000,2),
    SAME("qNaN low raw payload",0xc000000000000001,0x7fff,0x7ff8000000000000,2),
    SAME("negative qNaN",0xc000000000000800,0xffff,0xfff8000000000001,2),
    V("sNaN low raw payload",0x8000000000000001,0x7fff,0x7ff8000000000000,2,SNAN,KEEP,KEEP,KEEP,KEEP,0),
    V("negative sNaN payload",0x8000000000000800,0xffff,0xfff8000000000001,2,SNAN,KEEP,KEEP,KEEP,KEEP,0),
    V("unsupported unnormal",0x4000000000000000,0x3fff,0x7ff8000000000000,2,UNSUPPORTED,INDEFINITE,INDEFINITE,INDEFINITE,INDEFINITE,0),
    V("unsupported pseudo-infinity",0,0x7fff,0x7ff8000000000000,2,UNSUPPORTED,INDEFINITE,INDEFINITE,INDEFINITE,INDEFINITE,0),
    V("empty cached fraction",0xa000000000000000,0x4000,0x4004000000000000,3,EMPTY,INDEFINITE,INDEFINITE,INDEFINITE,INDEFINITE,0)
};
typedef struct {uint64_t bits;sample_t sample;} uncached_t;
static const uncached_t uncached[]={
    {0x8000000000000000,SAME("uncached -zero",0,0x8000,0x8000000000000000,1)},
    {0x3ff8000000000000,V("uncached 1.5",0xc000000000000000,0x3fff,0x3ff8000000000000,0,FRACTION,P2,P1,P2,P1,5)},
    {0xbff8000000000000,V("uncached -1.5",0xc000000000000000,0xbfff,0xbff8000000000000,0,FRACTION,N2,N2,N1,N1,3)},
    {1,V("uncached binary64 minsubnormal",0x8000000000000000,0x3bcd,1,0,FRACTION,ZP,ZP,P1,ZP,4)},
    {0x4340000000000001,SAME("uncached exact2^53+2",0x8000000000000800,0x4034,0x4340000000000001,0)},
    {0x7fefffffffffffff,SAME("uncached binary64 maximum",0xfffffffffffff800,0x43fe,0x7fefffffffffffff,0)},
    {0x7ff0000000000000,SAME("uncached Inf",0x8000000000000000,0x7fff,0x7ff0000000000000,2)},
    {0x7ff8000000000001,SAME("uncached qNaN",0xc000000000000800,0x7fff,0x7ff8000000000001,2)},
    {0x7ff0000000000001,V("uncached sNaN",0x8000000000000800,0x7fff,0x7ff8000000000001,2,SNAN,KEEP,KEEP,KEEP,KEEP,0)}
};
#undef SAME
#undef V

typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;unsigned use_jit,runs;} fixture_t;
static int native_present(const hb_jit_runtime_t *j)
{
    if(!j||!j->block_cache)return 0;for(size_t i=0;i<j->block_cache->size;++i){const hb_block_cache_entry_t *e=&j->block_cache->entries[i];if(e->valid&&e->guest_addr==CODE&&e->native_code&&e->native_size)return 1;}return 0;
}
static void close_jit(fixture_t *f)
{
    if(f->jit){check_kind(native_present(f->jit),"native JIT entry exists (helpers allowed)",EXECUTION);hb_jit_runtime_destroy(f->jit);f->jit=NULL;}f->runs=0;
}
static int seed(fixture_t *f,const sample_t *s,unsigned rc,unsigned pc,unsigned top,unsigned mode,unsigned sticky,const uint64_t *uncached_bits)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;x->status_word=(uint16_t)((top<<11)|0x4700|sticky);
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));x->last_x87_ip=0x12345678;
    if(mode==UNMASKED_INVALID)x->control_word&=(uint16_t)~1u;else if(mode==UNMASKED_DENORMAL)x->control_word&=(uint16_t)~2u;else if(mode==UNMASKED_PRECISION)x->control_word&=(uint16_t)~0x20u;
    uint8_t ext[10];for(unsigned i=0;i<8;++i){put64(ext,UINT64_C(0x9000000000000000)+(uint64_t)i*UINT64_C(0x0100000000000000));put16(ext+8,0x4002);
        if(!check(hb_x87_set_st_ext80(x,i,ext,(i&1)!=0)==HB_OK,"seed distinct occupied/empty neighboring raw slots"))return 0;}
    x->st_ext_valid&=(uint8_t)~(1u<<((top+3)&7)); /* Neighbor cache validity must remain unchanged. */
    put64(ext,s->input.sig);put16(ext+8,s->input.se);if(!check(hb_x87_set_st_ext80(x,0,ext,s->kind!=EMPTY)==HB_OK,"seed independent raw ST0"))return 0;
    if(uncached_bits){memcpy(&x->st[top],uncached_bits,8);x->st_ext_valid&=(uint8_t)~(1u<<top);}
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;c->step_limit=8;c->block_limit=2;return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,const sample_t *s,unsigned rc,unsigned mode,int fault)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);unsigned top=e->top;
    unsigned invalid=s->kind==SNAN||s->kind==UNSUPPORTED||s->kind==EMPTY,denormal=s->kind==DENORMAL;
    unsigned precision=(s->kind==FRACTION||denormal)&&!fault;
    uint16_t sw=(uint16_t)(e->status_word&~0x0200u);
    if(invalid)sw|=(uint16_t)(1u|(s->kind==EMPTY?0x40u:0));else if(denormal)sw|=2;
    if(precision)sw|=0x20;
    if(precision&&((s->c1_mask>>rc)&1u))sw|=0x0200;
    if(fault||(precision&&mode==UNMASKED_PRECISION))sw|=0x8080;
    e->status_word=(uint16_t)((sw&~0x4500u)|(x->status_word&0x4500u));
    if(!fault){value_t answer=s->result[rc]==KEEP?s->input:values[s->result[rc]];if(s->kind==SNAN){answer.sig|=UINT64_C(0x4000000000000000);answer.tag=2;}
        uint8_t raw[10],want[10];put64(want,answer.sig);put16(want+8,answer.se);uint64_t preview=0;memcpy(&preview,&x->st[top],8);
        check_kind(hb_x87_save_st_ext80(x,0,raw)==HB_OK&&!memcmp(raw,want,10),"independent full80 rounded result",NUMERIC);
        check_kind(preview==answer.preview,"binary64 preview consistent without controlling raw80 result",NUMERIC);
        if(e->st_ext_valid&(1u<<top))check_kind((x->st_ext_valid&(1u<<top))!=0,"authoritative raw input retains authoritative result cache",NUMERIC);
        if(x->st_ext_valid&(1u<<top))check_kind(!memcmp(x->st_ext[top],want,10),"valid result cache contains exact independent bytes",NUMERIC);
        e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*top)))|(answer.tag<<(2*top)));
        /* ST0 representation was checked independently; now normalize it so
         * the whole-state comparison isolates every unrelated physical slot. */
        memcpy(&e->st[top],&x->st[top],8);memcpy(e->st_ext[top],x->st_ext[top],10);
        e->st_ext_valid=(uint8_t)((e->st_ext_valid&~(1u<<top))|(x->st_ext_valid&(1u<<top)));
    }
    e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"x87 control/status/tags/TOP and other raw/cache/preview state");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register state");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->c->mxcsr==before->mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR/integer flags preserved");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"complete upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const sample_t *s,unsigned rc,unsigned host,unsigned pc,unsigned top,unsigned mode,unsigned sticky,const uint64_t *uncached_bits)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    snprintf(phase,sizeof(phase),"%s %s FRNDINT %s guestRC=%u hostRC=%u PC=%u TOP=%u mode=%u uncached=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->use_jit?"JIT":"interp",s->name,rc,host,pc,top,mode,uncached_bits!=NULL);
    if(!seed(f,s,rc,pc,top,mode,sticky,uncached_bits))return;
    if(f->use_jit){if(f->runs>=JIT_BATCH)close_jit(f);if(!f->jit){f->jit=hb_jit_runtime_create(f->c);if(!check(f->jit!=NULL,"create bounded JIT runtime"))return;}}
    hb_context_t before;memcpy(&before,f->c,sizeof(before));
    int invalid=s->kind==SNAN||s->kind==UNSUPPORTED||s->kind==EMPTY;
    int fault=(invalid&&mode==UNMASKED_INVALID)||(s->kind==DENORMAL&&mode==UNMASKED_DENORMAL);
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed independent masked host fenv"))return;
    int wanted_status=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;++f->runs;
    if(!check_kind(actual_rc==host_modes[host]&&actual_status==wanted_status,"host fenv preserved",HOST)&&category_failures[HOST]<=4)fprintf(stderr,"HOST %s actual rc=%d flags=%x expected rc=%d flags=%x\n",phase,actual_rc,actual_status,host_modes[host],wanted_status);
    if(fault)check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"unmasked invalid/denormal preserves operand and faults",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->c->pc==CODE+2,"complete FRNDINT including unmasked precision result",EXECUTION);
    check_state(f,&before,s,rc,mode,fault);
}
static void run_arch(hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.use_jit=backend==HB_BACKEND_JIT;snprintf(phase,sizeof(phase),"%s %s setup",arch==HB_ARCH_X86?"x86":"x64",f.use_jit?"JIT":"interp");
    f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable context"))goto done;f.c->memory=hb_memory_create(0);
    uint8_t canary[64],actual[64];memset(canary,0xa5,sizeof(canary));
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,code,sizeof(code))==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,DATA,canary,sizeof(canary))==HB_OK,"map owned private instruction and data canary"))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(code,2,CODE,&d):hb_decode_x64(code,2,CODE,&d);
    if(!check_kind(r==HB_OK&&d.len==2&&d.opcode==HB_INS_X87_FRNDINT,"decode exact FRNDINT D9 FC",EXECUTION))goto done;
    f.decoder=hb_decoder_create(arch,code,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift actual raw FRNDINT",EXECUTION))goto done;
    if(!f.use_jit){f.interp=hb_interpreter_create(f.c);if(!check(f.interp!=NULL,"create interpreter"))goto done;}
    static const unsigned precisions[]={0,2,3};
    for(unsigned top=0;top<8;++top)for(unsigned p=0;p<3;++p)for(unsigned host=0;host<4;++host)for(unsigned rc=0;rc<4;++rc)
        for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i)run_case(&f,&samples[i],rc,host,precisions[p],top,MASKED,4,NULL);
    for(unsigned rc=0;rc<4;++rc)for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i){const sample_t *s=&samples[i];
        if(s->kind==SNAN||s->kind==UNSUPPORTED||s->kind==EMPTY)run_case(&f,s,rc,2,3,5,UNMASKED_INVALID,4,NULL);
        if(s->kind==DENORMAL)run_case(&f,s,rc,2,3,5,UNMASKED_DENORMAL,4,NULL);
        if(s->kind==FRACTION||s->kind==DENORMAL)run_case(&f,s,rc,2,3,5,UNMASKED_PRECISION,4,NULL);}
    for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)for(unsigned i=0;i<sizeof(uncached)/sizeof(uncached[0]);++i)
        run_case(&f,&uncached[i].sample,rc,host,3,(rc+host)&7,MASKED,4,&uncached[i].bits);
    /* SF is sticky even through a later nonempty arithmetic invalid. */
    run_case(&f,&samples[33],0,2,3,5,MASKED,0x44,NULL);
    check(hb_memory_read(f.c->memory,DATA,actual,sizeof(actual))==HB_OK&&!memcmp(actual,canary,sizeof(canary)),"FRNDINT leaves unrelated guest data unchanged");
done:
    close_jit(&f);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.c)hb_context_destroy(f.c);
}
static const struct{const char *name;enum hb_gate_id id;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED}
};
int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original_host;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *v=getenv(gates[i].name);if(v&&!check((saved[i]=strdup(v))!=NULL,"save helper gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,"0",1)==0,"select private helper memory"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);if(!check(v&&!strcmp(v,"0"),"effective helper gate"))goto done;}
    if(!check(feholdexcept(&original_host)==0,"save and mask host fenv"))goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)run_arch(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v&&!strcmp(v,saved[i]):!v,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_frndint_test: %u executions, %u checks, %u failures\n",executions,checks,failures);
    printf("failure categories: numeric=%u state=%u execution=%u host=%u\n",category_failures[NUMERIC],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
