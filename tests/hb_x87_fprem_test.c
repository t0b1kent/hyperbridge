/* Raw FPREM D9 F8 / FPREM1 D9 F5. Finite output fixtures and quotient bits
 * are independent integer/raw80 oracles, never host fmod/remainder results.
 * HyperBridge's permitted partial-reduction choice is N=32; its intermediate
 * outputs are an engine policy, not a claim about every Intel processor.
 * Partial C0/C1/C3 and quotient bits on NaN/errors are undefined and excluded.
 * UM0 exact-tiny scaled commit is checked; ambiguous underflow C1 is excluded.
 * Pending #MF delivery and inherited FIP/fault-PC bookkeeping remain outside.
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

enum {PAGE_BYTES=16384};
enum {NUMERIC,STATE,EXECUTION,HOST,CATEGORIES};
enum {MASKED,IM0,DM0,UM0,PM0};
enum {SPECIAL=1,INVALID=2,DENORMAL=4,EMPTY_A=8,EMPTY_B=16,TINY=32};
static const uint64_t CODE=UINT64_C(0x4e00000);
static unsigned checks,failures,executions,partial_steps,completed_chains,category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} value_t;
enum {ZP,ZN,P_HALF,N_HALF,P1,N1,P2,N2,P3,P5,P7,N7,P9,P13,
      BIG53_1,BIG53_3,Q63_BELOW,Q63,Q63_ABOVE,NQ63_BELOW,NQ63,NQ63_ABOVE,
      Q63_HALF,NQ63_HALF,ABOVE7,ONE_PLUS_EPS,NEG_ONE_MINUS_EPS,
      MIN_NORMAL,MIN_NORMAL_PLUS,MIN_SUB,SUB3,PSEUDO,INF,NINF,
      QA,QB,SA,SB,QSA,QSB,UNNORMAL,INDEF,SCALED_SUB,Q64_BELOW,NQ64_BELOW,VALUE_COUNT};
#define X(s,e,p,t) {UINT64_C(s),e,UINT64_C(p),t}
static const value_t v[VALUE_COUNT]={
    X(0,0,0,1),X(0,0x8000,0x8000000000000000,1),
    X(0x8000000000000000,0x3ffe,0x3fe0000000000000,0),X(0x8000000000000000,0xbffe,0xbfe0000000000000,0),
    X(0x8000000000000000,0x3fff,0x3ff0000000000000,0),X(0x8000000000000000,0xbfff,0xbff0000000000000,0),
    X(0x8000000000000000,0x4000,0x4000000000000000,0),X(0x8000000000000000,0xc000,0xc000000000000000,0),
    X(0xc000000000000000,0x4000,0x4008000000000000,0),X(0xa000000000000000,0x4001,0x4014000000000000,0),
    X(0xe000000000000000,0x4001,0x401c000000000000,0),X(0xe000000000000000,0xc001,0xc01c000000000000,0),
    X(0x9000000000000000,0x4002,0x4022000000000000,0),X(0xd000000000000000,0x4002,0x402a000000000000,0),
    X(0x8000000000000400,0x4034,0x4340000000000000,0),X(0x8000000000000c00,0x4034,0x4340000000000002,0),
    X(0xfffffffffffffffe,0x403d,0x43e0000000000000,0),X(0x8000000000000000,0x403e,0x43e0000000000000,0),X(0x8000000000000001,0x403e,0x43e0000000000000,0),
    X(0xfffffffffffffffe,0xc03d,0xc3e0000000000000,0),X(0x8000000000000000,0xc03e,0xc3e0000000000000,0),X(0x8000000000000001,0xc03e,0xc3e0000000000000,0),
    X(0xffffffffffffffff,0x403d,0x43e0000000000000,0),X(0xffffffffffffffff,0xc03d,0xc3e0000000000000,0),
    X(0xe000000000000001,0x4001,0x401c000000000000,0),X(0x8000000000000004,0x3fff,0x3ff0000000000000,0),X(0xfffffffffffffff8,0xbffe,0xbff0000000000000,0),
    X(0x8000000000000000,1,0,0),X(0x8000000000000001,1,0,0),X(1,0,0,2),X(3,0,0,2),X(0x8000000000000000,0,0,2),
    X(0x8000000000000000,0x7fff,0x7ff0000000000000,2),X(0x8000000000000000,0xffff,0xfff0000000000000,2),
    X(0xc000000000000010,0x7fff,0x7ff8000000000000,2),X(0xc000000000000020,0xffff,0xfff8000000000000,2),
    X(0x8000000000000010,0x7fff,0x7ff8000000000000,2),X(0x8000000000000020,0xffff,0xfff8000000000000,2),
    X(0xc000000000000010,0x7fff,0x7ff8000000000000,2),X(0xc000000000000020,0xffff,0xfff8000000000000,2),
    X(0x4000000000000000,0x3fff,0x7ff8000000000000,2),X(0xc000000000000000,0xffff,0xfff8000000000000,2),
    X(0x8000000000000000,0x5fc2,0x7ff0000000000000,0),
    X(0xffffffffffffffff,0x403e,0x43f0000000000000,0),X(0xffffffffffffffff,0xc03e,0xc3f0000000000000,0)
};
#undef X
typedef struct {const char *name;unsigned a,b,result[2],q[2],flags,full;} sample_t;
static const sample_t samples[]={
    {"7/2",P7,P2,{P1,N1},{3,4},0,1},{"-7/2",N7,P2,{N1,P1},{3,4},0,1},
    {"7/-2",P7,N2,{P1,N1},{3,4},0,1},{"-7/-2",N7,N2,{N1,P1},{3,4},0,1},
    {"5/2 even tie",P5,P2,{P1,P1},{2,2},0,1},{"3/2 odd tie",P3,P2,{P1,N1},{1,2},0,1},
    {"9/2 even tie",P9,P2,{P1,P1},{4,4},0,1},{"13/2 quotient6",P13,P2,{P1,P1},{6,6},0,1},
    {"half/1 even tie",P_HALF,P1,{P_HALF,P_HALF},{0,0},0,1},
    {"2^53+1 /2",BIG53_1,P2,{P1,P1},{0,0},0,1},{"2^53+3 /2",BIG53_3,P2,{P1,N1},{1,2},0,1},
    {"(2^63-1)/1",Q63_BELOW,P1,{ZP,ZP},{7,7},0,1},{"2^63/1 D63",Q63,P1,{ZP,ZP},{0,0},0,1},
    {"(2^63+1)/1 D63",Q63_ABOVE,P1,{ZP,ZP},{1,1},0,1},
    {"-(2^63-1)/1",NQ63_BELOW,P1,{ZN,ZN},{7,7},0,1},{"-2^63/1 D63",NQ63,P1,{ZN,ZN},{0,0},0,1},
    {"-(2^63+1)/1 D63",NQ63_ABOVE,P1,{ZN,ZN},{1,1},0,1},
    {"(2^63-0.5)/1",Q63_HALF,P1,{P_HALF,N_HALF},{7,0},0,1},{"-(2^63-0.5)/1",NQ63_HALF,P1,{N_HALF,P_HALF},{7,0},0,1},
    {"above7/2 raw neighbor",ABOVE7,P2,{ONE_PLUS_EPS,NEG_ONE_MINUS_EPS},{3,4},0,1},
    {"+zero/2",ZP,P2,{ZP,ZP},{0,0},0,1},{"-zero/2",ZN,P2,{ZN,ZN},{0,0},0,1},
    {"finite/Inf",BIG53_1,INF,{BIG53_1,BIG53_1},{0,0},SPECIAL,1},
    {"Inf/finite",INF,P2,{INDEF,INDEF},{0,0},SPECIAL|INVALID,1},
    {"finite/zero",P7,ZP,{INDEF,INDEF},{0,0},SPECIAL|INVALID,1},
    {"zero/zero",ZP,ZP,{INDEF,INDEF},{0,0},SPECIAL|INVALID,0},
    {"QNaN/finite",QA,P2,{QA,QA},{0,0},SPECIAL,1},{"finite/QNaN",P7,QB,{QB,QB},{0,0},SPECIAL,1},
    {"SNaN/finite",SA,P2,{QSA,QSA},{0,0},SPECIAL|INVALID,1},{"finite/SNaN",P7,SB,{QSB,QSB},{0,0},SPECIAL|INVALID,1},
    {"two QNaNs larger raw payload",QA,QB,{QB,QB},{0,0},SPECIAL,0},
    {"two SNaNs larger raw payload",SA,SB,{QSB,QSB},{0,0},SPECIAL|INVALID,0},
    {"SNaN plus QNaN",SB,QA,{QA,QA},{0,0},SPECIAL|INVALID,0},
    {"QNaN before zero-divisor IA",QA,ZP,{QA,QA},{0,0},SPECIAL,0},
    {"QNaN before infinite-dividend IA",INF,QB,{QB,QB},{0,0},SPECIAL,0},
    {"unsupported before QNaN",UNNORMAL,QA,{INDEF,INDEF},{0,0},SPECIAL|INVALID,0},
    {"unsupported divisor",P7,UNNORMAL,{INDEF,INDEF},{0,0},SPECIAL|INVALID,1},
    {"empty ST0 cached dividend",P7,P2,{INDEF,INDEF},{0,0},SPECIAL|INVALID|EMPTY_A,1},
    {"empty ST1 cached divisor",P7,P2,{INDEF,INDEF},{0,0},SPECIAL|INVALID|EMPTY_B,1},
    {"both empty",P7,P2,{INDEF,INDEF},{0,0},SPECIAL|INVALID|EMPTY_A|EMPTY_B,0},
    {"input minsubnormal",MIN_SUB,P1,{MIN_SUB,MIN_SUB},{0,0},DENORMAL|TINY,1},
    {"pseudo-denormal canonical result",PSEUDO,P1,{MIN_NORMAL,MIN_NORMAL},{0,0},DENORMAL,1},
    {"denormal divisor exact quotient",MIN_NORMAL_PLUS,SUB3,{ZP,ZP},{3,3},DENORMAL,1},
    {"normal operands exact tiny remainder",MIN_NORMAL_PLUS,MIN_NORMAL,{MIN_SUB,MIN_SUB},{1,1},TINY,1},
    {"3/5 D-1 reflects nearest",P3,P5,{P3,N2},{0,1},0,1},
    {"1/3 D-1 below half",P1,P3,{P1,P1},{0,0},0,1},
    {"1/13 D below -1",P1,P13,{P1,P1},{0,0},0,1},
    {"(2^64-1)/1 largest complete quotient",Q64_BELOW,P1,{ZP,ZP},{7,7},0,1},
    {"-(2^64-1)/1 largest complete magnitude",NQ64_BELOW,P1,{ZN,ZN},{7,7},0,1},
    {"QNaN before denormal operand",QA,MIN_SUB,{QA,QA},{0,0},SPECIAL,0}
};

typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;unsigned nearest;} fixture_t;
static int native_present(fixture_t *f)
{
    if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;
    for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;
}
static int seed(fixture_t *f,const value_t *a,const value_t *b,unsigned flags,unsigned rc,unsigned pc,unsigned top,unsigned mode,unsigned sticky)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}else {c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;x->status_word=(uint16_t)((top<<11)|0x4700|sticky);x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));x->last_x87_ip=0x12345678;
    if(mode==IM0)x->control_word&=(uint16_t)~1u;else if(mode==DM0)x->control_word&=(uint16_t)~2u;else if(mode==UM0)x->control_word&=(uint16_t)~0x10u;else if(mode==PM0)x->control_word&=(uint16_t)~0x20u;
    uint8_t raw[10];for(unsigned i=0;i<8;++i){put64(raw,UINT64_C(0x9000000000000000)+(uint64_t)i*UINT64_C(0x0100000000000000));put16(raw+8,0x4002);if(!check(hb_x87_set_st_ext80(x,i,raw,(i&1)!=0)==HB_OK,"seed distinct neighboring physical slots"))return 0;}
    x->st_ext_valid&=(uint8_t)~(1u<<((top+3)&7));
    put64(raw,a->sig);put16(raw+8,a->se);if(!check(hb_x87_set_st_ext80(x,0,raw,!(flags&EMPTY_A))==HB_OK,"seed authoritative ST0"))return 0;
    put64(raw,b->sig);put16(raw+8,b->se);if(!check(hb_x87_set_st_ext80(x,1,raw,!(flags&EMPTY_B))==HB_OK,"seed authoritative ST1"))return 0;
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;return 1;
}
static uint16_t quotient_bits(unsigned q){return (uint16_t)(((q&4)?0x100:0)|((q&1)?0x200:0)|((q&2)?0x4000:0));}
static void check_state(fixture_t *f,const hb_context_t *before,const value_t *answer,unsigned q,unsigned flags,unsigned mode,int partial,int fault)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);unsigned top=e->top;
    uint16_t sw=e->status_word;unsigned empty=flags&(EMPTY_A|EMPTY_B),underflow=(flags&TINY)&&mode==UM0&&!fault;
    if(flags&INVALID)sw|=(uint16_t)(1u|(empty?0x40u:0));else if(flags&DENORMAL)sw|=2;
    if(underflow)sw|=0x10;if(fault||underflow)sw|=0x8080;
    if(fault){sw=(uint16_t)((sw&~0x4700u)|(x->status_word&0x4700u));if(empty)sw&=(uint16_t)~0x200u;}
    else if(partial)sw=(uint16_t)((sw&~0x4700u)|0x400u|(x->status_word&0x4300u));
    else if(flags&SPECIAL){sw=(uint16_t)((sw&~0x4700u)|(x->status_word&0x4300u));if(empty)sw&=(uint16_t)~0x200u;}
    else {sw=(uint16_t)((sw&~0x4700u)|quotient_bits(q));if(underflow)sw=(uint16_t)((sw&~0x200u)|(x->status_word&0x200u));}
    e->status_word=sw;
    if(!fault){uint8_t raw[10],want[10];put64(want,answer->sig);put16(want+8,answer->se);uint64_t preview=0;memcpy(&preview,&x->st[top],8);
        check_kind(hb_x87_save_st_ext80(x,0,raw)==HB_OK&&!memcmp(raw,want,10),"independent full80 remainder/partial result",NUMERIC);
        check_kind(preview==answer->preview,"consistent binary64 preview without narrowing authoritative result",NUMERIC);
        check_kind((x->st_ext_valid&(1u<<top))&& !memcmp(x->st_ext[top],want,10),"authoritative output cache stores exact raw80",NUMERIC);
        e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*top)))|(answer->tag<<(2*top)));
        memcpy(&e->st[top],&x->st[top],8);memcpy(e->st_ext[top],x->st_ext[top],10);e->st_ext_valid=(uint8_t)((e->st_ext_valid&~(1u<<top))|(x->st_ext_valid&(1u<<top)));}
    e->last_x87_ip=x->last_x87_ip;check(!memcmp(x,e,sizeof(*x)),"status/C2/defined quotient bits, TOP, ST1 and other raw/cache/preview state");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register state");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 preserved");
    check(f->c->mxcsr==before->mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR/integer flags preserved");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"complete upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segments preserved");
}
static void step(fixture_t *f,const value_t *answer,unsigned q,unsigned flags,unsigned mode,unsigned host,int partial)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};hb_context_t *c=f->c;
    c->pc=CODE;c->last_result=HB_OK;if(c->arch==HB_ARCH_X86)c->regs.x86.eip=(uint32_t)CODE;else c->regs.x64.rip=CODE;
    hb_context_t before;memcpy(&before,c,sizeof(before));int fault=((flags&INVALID)&&mode==IM0)||((flags&DENORMAL)&&!(flags&INVALID)&&mode==DM0);
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed independent masked host fenv"))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t r=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;if(partial)++partial_steps;
    if(!check_kind(actual_rc==host_modes[host]&&actual_flags==wanted,"host fenv preserved",HOST)&&category_failures[HOST]<=4)fprintf(stderr,"HOST %s actual rc=%d flags=%x expected rc=%d flags=%x\n",phase,actual_rc,actual_flags,host_modes[host],wanted);
    if(fault)check_kind((r==HB_OK||r==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"unmasked invalid/denormal abort before operand mutation",EXECUTION);
    else check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&c->pc==CODE+2,"complete one remainder step, including UM0 scaled commit",EXECUTION);
    check_state(f,&before,answer,q,flags,mode,partial,fault);
}
static void run_case(fixture_t *f,const sample_t *s,unsigned rc,unsigned host,unsigned pc,unsigned top,unsigned mode,unsigned sticky)
{
    snprintf(phase,sizeof(phase),"%s %s %s %s RC=%u host=%u PC=%u TOP=%u mode=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->nearest?"FPREM1":"FPREM",s->name,rc,host,pc,top,mode);
    if(!seed(f,&v[s->a],&v[s->b],s->flags,rc,pc,top,mode,sticky))return;
    const value_t *answer=(s->flags&TINY)&&mode==UM0?&v[SCALED_SUB]:&v[s->result[f->nearest]];
    step(f,answer,s->q[f->nearest],s->flags,mode,host,0);
}
static value_t power(unsigned exponent)
{
    value_t r={UINT64_C(0x8000000000000000),(uint16_t)(0x3fff+exponent),0,0};
    r.preview=exponent>1023?UINT64_C(0x7ff0000000000000):(uint64_t)(exponent+1023)<<52;return r;
}
static void power_three_chain(fixture_t *f,unsigned exponent,unsigned rc,unsigned host,unsigned top)
{
    /* For even e>=64, floor(2^33/3) leaves residue2, so the N32 partial
     * remainder is exactly 2^(e-32). Earlier quotient chunks are multiples
     * of2^32 and cannot change the final quotient's low three bits. */
    value_t a=power(exponent);if(!seed(f,&a,&v[P3],0,rc,3,top,MASKED,4))return;hb_context_x87(f->c)->status_word&=(uint16_t)~0x400u;
    unsigned count=0;while(exponent>=65&&count<1024){exponent-=32;value_t answer=power(exponent);
        snprintf(phase,sizeof(phase),"%s %s %s N32 power/3 step=%u exponent=%u RC=%u host=%u TOP=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->nearest?"FPREM1":"FPREM",count,exponent,rc,host,top);
        step(f,&answer,0,0,MASKED,host,1);++count;}
    check(count<1024,"bounded large-gap reduction makes progress");
    step(f,&v[P1],5,0,MASKED,host,0);++completed_chains;
}
static void fixed_chain(fixture_t *f,unsigned kind,unsigned rc,unsigned host,unsigned top)
{
    value_t a,b=v[P1];unsigned flags=0;
    if(kind==0)a=power(64);
    else if(kind==1){a=(value_t){UINT64_C(0x8000000000000001),0x4106,UINT64_C(0x5060000000000000),0};b=v[P3];}
    else {a=power(16383);b=v[MIN_SUB];flags=DENORMAL;}
    snprintf(phase,sizeof(phase),"%s %s %s fixed partial kind=%u RC=%u host=%u TOP=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->nearest?"FPREM1":"FPREM",kind,rc,host,top);
    if(!seed(f,&a,&b,flags,rc,3,top,MASKED,4))return;hb_context_x87(f->c)->status_word&=(uint16_t)~0x400u;
    if(kind==1){const value_t intermediate={UINT64_C(0x8000000100000000),0x40e6,UINT64_C(0x4e60000000200000),0};step(f,&intermediate,0,flags,MASKED,host,1);}
    step(f,&v[ZP],0,flags,MASKED,host,1);step(f,&v[ZP],0,flags,MASKED,host,0);++completed_chains;
}
static void run_arch(hb_arch_t arch,hb_backend_t backend,unsigned nearest)
{
    fixture_t f={0};f.nearest=nearest;const uint8_t raw[]={0xd9,nearest?0xf5:0xf8};
    snprintf(phase,sizeof(phase),"%s %s setup",arch==HB_ARCH_X86?"x86":"x64",nearest?"FPREM1":"FPREM");
    f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,raw,2)==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map private raw instruction"))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(raw,2,CODE,&d):hb_decode_x64(raw,2,CODE,&d);
    if(!check_kind(r==HB_OK&&d.len==2&&d.opcode==(nearest?HB_INS_X87_FPREM1:HB_INS_X87_FPREM),"decode exact remainder opcode",EXECUTION))goto done;
    f.decoder=hb_decoder_create(arch,raw,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift actual remainder instruction",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create long-lived runtime; M16 report fenv guard is required"))goto done;
    static const unsigned precisions[]={0,2,3};
    for(unsigned top=0;top<8;++top)for(unsigned p=0;p<3;++p)for(unsigned host=0;host<4;++host)for(unsigned rc=0;rc<4;++rc)
        for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i)if(samples[i].full)run_case(&f,&samples[i],rc,host,precisions[p],top,MASKED,4);
    for(unsigned rc=0;rc<4;++rc)for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i){const sample_t *s=&samples[i];
        if(!s->full)run_case(&f,s,rc,2,3,5,MASKED,4);
        if(s->flags&INVALID)run_case(&f,s,rc,2,3,5,IM0,4);
        if(s->flags&DENORMAL)run_case(&f,s,rc,2,3,5,DM0,4);
        if(s->flags&TINY)run_case(&f,s,rc,2,3,5,UM0,4);}
    for(unsigned host=0;host<4;++host)for(unsigned rc=0;rc<4;++rc){run_case(&f,&samples[0],rc,host,3,5,PM0,4);
        for(unsigned top=0;top<8;++top){power_three_chain(&f,200,rc,host,top);fixed_chain(&f,0,rc,host,top);fixed_chain(&f,1,rc,host,top);}}
    for(unsigned host=0;host<4;++host){power_three_chain(&f,16000,3-host,host,7);fixed_chain(&f,2,3-host,host,7);}
    run_case(&f,&samples[24],0,2,3,5,MASKED,0x44); /* sticky SF through a later non-stack invalid */
    if(f.jit)check_kind(native_present(&f),"native guest entry block exists (helpers allowed)",EXECUTION);
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
    if(!check(fegetenv(&original_host)==0,"save complete original host fenv"))goto done;host_saved=1;fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host exceptions"))goto done;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned nearest=0;nearest<2;++nearest)run_arch(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP,nearest);
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_fprem_test: %u executions, %u partial steps, %u completed chains, %u checks, %u failures\n",executions,partial_steps,completed_chains,checks,failures);
    printf("failure categories: numeric=%u state=%u execution=%u host=%u\n",category_failures[NUMERIC],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
