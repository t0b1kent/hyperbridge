/* M31 preparation: exact canonical-normal/zero DE FADDP/FSUBP/FSUBRP.
 * Literal raw/preview answers are independent dyadic-integer calculations.
 * FADDP writes old STi+ST0; FSUBP old STi-ST0; FSUBRP old ST0-STi, then pops.
 * Exact lane: occupied inputs, valid PC, normal/zero output, no new exceptions.
 * M50 admits the PM1 inexact-PC and normal tiny-ADD controls with PE/C1.
 * True tiny outputs, reserved PC, qNaN, pending IE and IM0 empties stay legacy.
 * No component includes, public bridge calls, memory forms or D8/DC admission.
 * C0/C2/C3, inherited FIP and popped payload/cache are excluded. */
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
enum { ADD, SUB, REVERSE_SUB };
enum { LEGACY_INEXACT,LEGACY_TINY,LEGACY_RESERVED,LEGACY_NAN,EMPTY_SOURCE,EMPTY_DESTINATION,LEGACY_PENDING };
enum { RAW,STATE,EXECUTION,HOST,CATEGORIES };
static const uint64_t CODE=UINT64_C(0x6300000);
static unsigned checks,failures,executions,exact_cases,uncached_cases,legacy_cases,empty_cases;
static unsigned category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint16_t se;uint64_t sig,preview;unsigned tag;} raw_t;
typedef struct {raw_t raw;unsigned cancellation;} answer_t;
typedef struct {const char *name;raw_t st0,sti;answer_t result[3];unsigned pc_mask,uncached_ok;} sample_t;
static const sample_t samples[]={
    {"zero_pp",{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},{{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},0},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1}},7,1},
    {"zero_nn",{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},{{{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},0},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1}},7,1},
    {"zero_pn",{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},{{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1},{{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},0},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},0}},7,1},
    {"zero_np",{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},{{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},0},{{0x8000,UINT64_C(0x0000000000000000),UINT64_C(0x8000000000000000),1},0}},7,1},
    {"integers",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},{{{0x4002,UINT64_C(0x9000000000000000),UINT64_C(0x4022000000000000),0},0},{{0x4001,UINT64_C(0xa000000000000000),UINT64_C(0x4014000000000000),0},0},{{0xc001,UINT64_C(0xa000000000000000),UINT64_C(0xc014000000000000),0},0}},7,1},
    {"fractions",{0x3ffe,UINT64_C(0x8000000000000000),UINT64_C(0x3fe0000000000000),0},{0x3fff,UINT64_C(0xc000000000000000),UINT64_C(0x3ff8000000000000),0},{{{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},0},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0}},7,1},
    {"wide_integer24",{0x4017,UINT64_C(0x8000000000000000),UINT64_C(0x4170000000000000),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},{{{0x4017,UINT64_C(0x8000008000000000),UINT64_C(0x4170000010000000),0},0},{{0xc016,UINT64_C(0xffffff0000000000),UINT64_C(0xc16fffffe0000000),0},0},{{0x4016,UINT64_C(0xffffff0000000000),UINT64_C(0x416fffffe0000000),0},0}},6,1},
    {"wide_integer53",{0x4034,UINT64_C(0x8000000000000000),UINT64_C(0x4340000000000000),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},{{{0x4034,UINT64_C(0x8000000000000400),UINT64_C(0x4340000000000000),0},0},{{0xc033,UINT64_C(0xfffffffffffff800),UINT64_C(0xc33fffffffffffff),0},0},{{0x4033,UINT64_C(0xfffffffffffff800),UINT64_C(0x433fffffffffffff),0},0}},4,1},
    {"raw_low64",{0x3fff,UINT64_C(0x8000000000000002),UINT64_C(0x3ff0000000000000),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},{{{0x4000,UINT64_C(0x8000000000000001),UINT64_C(0x4000000000000000),0},0},{{0xbfc1,UINT64_C(0x8000000000000000),UINT64_C(0xbc10000000000000),0},0},{{0x3fc1,UINT64_C(0x8000000000000000),UINT64_C(0x3c10000000000000),0},0}},4,0},
    {"huge_normal",{0x43ff,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},{0x43fe,UINT64_C(0x8000000000000000),UINT64_C(0x7fe0000000000000),0},{{{0x43ff,UINT64_C(0xc000000000000000),UINT64_C(0x7ff0000000000000),0},0},{{0xc3fe,UINT64_C(0x8000000000000000),UINT64_C(0xffe0000000000000),0},0},{{0x43fe,UINT64_C(0x8000000000000000),UINT64_C(0x7fe0000000000000),0},0}},7,0},
    {"tiny_normal",{0x3bcc,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{0x3bcb,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{{{0x3bcc,UINT64_C(0xc000000000000000),UINT64_C(0x0000000000000001),0},0},{{0xbbcb,UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000000),0},0},{{0x3bcb,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},0}},7,0},
    {"low24",{0x3fff,UINT64_C(0x8000020000000000),UINT64_C(0x3ff0000040000000),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},{{{0x4000,UINT64_C(0x8000010000000000),UINT64_C(0x4000000020000000),0},0},{{0xbfe9,UINT64_C(0x8000000000000000),UINT64_C(0xbe90000000000000),0},0},{{0x3fe9,UINT64_C(0x8000000000000000),UINT64_C(0x3e90000000000000),0},0}},7,1},
    {"low53",{0x3fff,UINT64_C(0x8000000000001000),UINT64_C(0x3ff0000000000002),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},{{{0x4000,UINT64_C(0x8000000000000800),UINT64_C(0x4000000000000001),0},0},{{0xbfcc,UINT64_C(0x8000000000000000),UINT64_C(0xbcc0000000000000),0},0},{{0x3fcc,UINT64_C(0x8000000000000000),UINT64_C(0x3cc0000000000000),0},0}},6,1},
    {"near_max_normal",{0x7ffd,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},{0x7ffc,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},{{{0x7ffd,UINT64_C(0xc000000000000000),UINT64_C(0x7ff0000000000000),0},0},{{0xfffc,UINT64_C(0x8000000000000000),UINT64_C(0xfff0000000000000),0},0},{{0x7ffc,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),0},0}},7,0},
    {"near_min_normal",{0x0003,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{0x0002,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{{{0x0003,UINT64_C(0xc000000000000000),UINT64_C(0x0000000000000000),0},0},{{0x8002,UINT64_C(0x8000000000000000),UINT64_C(0x8000000000000000),0},0},{{0x0002,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},0}},7,0},
};
typedef struct {const char *name;raw_t st0,sti;answer_t result[3];unsigned pc,kind;} legacy_t;
static const legacy_t legacy[]={
    {"inexact_PC24",{0x3fe6,UINT64_C(0x8000000000000000),UINT64_C(0x3e60000000000000),0},{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},{{{0x3fff,UINT64_C(0x8000004000000000),UINT64_C(0x3ff0000008000000),0},0},{{0x3ffe,UINT64_C(0xffffff8000000000),UINT64_C(0x3feffffff0000000),0},0},{{0xbffe,UINT64_C(0xffffff8000000000),UINT64_C(0xbfeffffff0000000),0},0}},0,LEGACY_INEXACT},
    {"subnormal_result",{0x0001,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},{0x0001,UINT64_C(0x8000000000000001),UINT64_C(0x0000000000000000),0},{{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},0},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1},{{0x0000,UINT64_C(0x0000000000000000),UINT64_C(0x0000000000000000),1},1}},3,LEGACY_TINY},
    {"reserved_PC",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},{{{0x4002,UINT64_C(0x9000000000000000),UINT64_C(0x4022000000000000),0},0},{{0x4001,UINT64_C(0xa000000000000000),UINT64_C(0x4014000000000000),0},0},{{0xc001,UINT64_C(0xa000000000000000),UINT64_C(0xc014000000000000),0},0}},1,LEGACY_RESERVED},
    {"quiet_NaN",{0x7fff,UINT64_C(0xc000000000000000),UINT64_C(0x7ff8000000000000),2},{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},{{{0x7fff,UINT64_C(0xc000000000000000),UINT64_C(0x7ff8000000000000),2},0},{{0x7fff,UINT64_C(0xc000000000000000),UINT64_C(0x7ff8000000000000),2},0},{{0x7fff,UINT64_C(0xc000000000000000),UINT64_C(0x7ff8000000000000),2},0}},3,LEGACY_NAN},
    {"empty_ST0",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},{{{0x4002,UINT64_C(0x9000000000000000),UINT64_C(0x4022000000000000),0},0},{{0x4001,UINT64_C(0xa000000000000000),UINT64_C(0x4014000000000000),0},0},{{0xc001,UINT64_C(0xa000000000000000),UINT64_C(0xc014000000000000),0},0}},3,EMPTY_SOURCE},
    {"empty_STi",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},{{{0x4002,UINT64_C(0x9000000000000000),UINT64_C(0x4022000000000000),0},0},{{0x4001,UINT64_C(0xa000000000000000),UINT64_C(0x4014000000000000),0},0},{{0xc001,UINT64_C(0xa000000000000000),UINT64_C(0xc014000000000000),0},0}},3,EMPTY_DESTINATION},
    {"pending_IE",{0x4000,UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000000),0},{0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0},{{{0x4002,UINT64_C(0x9000000000000000),UINT64_C(0x4022000000000000),0},0},{{0x4001,UINT64_C(0xa000000000000000),UINT64_C(0x4014000000000000),0},0},{{0xc001,UINT64_C(0xa000000000000000),UINT64_C(0xc014000000000000),0},0}},3,LEGACY_PENDING},
};
typedef struct {const char *name;uint8_t bytes[2];unsigned operation,index;} form_t;
#define F(n,op,byte,i) {n " ST" #i,{0xde,byte+i},op,i}
#define EIGHT(n,op,byte) F(n,op,byte,0),F(n,op,byte,1),F(n,op,byte,2),F(n,op,byte,3),F(n,op,byte,4),F(n,op,byte,5),F(n,op,byte,6),F(n,op,byte,7)
static const form_t forms[]={EIGHT("FADDP",ADD,0xc0),EIGHT("FSUBP",SUB,0xe8),EIGHT("FSUBRP",REVERSE_SUB,0xe0)};
#undef EIGHT
#undef F
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;} fixture_t;
static unsigned op_index(const form_t *f){return f->operation-ADD;}
static int is_empty_legacy(const legacy_t *l){return l&&(l->kind==EMPTY_SOURCE||l->kind==EMPTY_DESTINATION);}
static void install(hb_x87_state_t *x,unsigned phys,const raw_t *r,unsigned flip)
{
    uint64_t preview=r->preview^((uint64_t)flip<<63);
    memcpy(&x->st[phys],&preview,8);put64(x->st_ext[phys],r->sig);
    put16(x->st_ext[phys]+8,(uint16_t)(r->se^(flip<<15)));
    x->st_ext_valid|=(uint8_t)(1u<<phys);
    x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*phys)))|(r->tag<<(2*phys)));
}
static void seed(fixture_t *f,const raw_t *a,const raw_t *b,unsigned flip,unsigned top,unsigned pc,unsigned rc,int uncached,const legacy_t *l)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));
    if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else{c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));
    x->status_word=(uint16_t)((top<<11)|0x4704|((top&1)?0x20:0)|((top&2)?0x40:0));x->last_x87_ip=0x12345678;
    for(unsigned i=0;i<8;++i){raw_t n={0x4002,UINT64_C(0x8000000000000000)+(uint64_t)i*UINT64_C(0x1000000000000000),UINT64_C(0x4020000000000000)+(uint64_t)i*UINT64_C(0x2000000000000),0};install(x,(top+i)&7,&n,i&1);}
    x->tag_word|=(uint16_t)(3u<<(2*((top+6)&7)));
    unsigned dst=(top+f->form->index)&7;
    if(dst!=top)install(x,dst,b,flip);install(x,top,a,flip);
    if(uncached)x->st_ext_valid&=(uint8_t)~((1u<<top)|(1u<<dst));
    if(is_empty_legacy(l)){unsigned p=l->kind==EMPTY_SOURCE?top:dst;x->tag_word|=(uint16_t)(3u<<(2*p));x->control_word&=(uint16_t)~1u;}
    if(l&&l->kind==LEGACY_PENDING){x->control_word&=(uint16_t)~1u;x->status_word|=0x8081u;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static raw_t answer(const answer_t *a,unsigned flip,unsigned rc)
{
    raw_t r=a->raw;
    if(a->cancellation){r.se=(uint16_t)(rc==1?0x8000:0);r.preview=rc==1?UINT64_C(0x8000000000000000):0;}
    else{r.se^=(uint16_t)(flip<<15);r.preview^=(uint64_t)flip<<63;}
    return r;
}
/* M50: the historical legacy/exact counters retain their input-group meaning.
 * The explicitly selected old precision rows now require guest-PC/RC raw results,
 * sticky PE and C1 from discarded-bit magnitude increment. All loops/check counts
 * and unrelated-state, host-state and fault assertions remain unchanged.
 * These literals were derived with integer/Fraction arithmetic, without the bridge.
 */
typedef struct {raw_t raw;unsigned status_bits;} precision_answer_t;
static const precision_answer_t masked_precision[4][4]={
    {{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000010000000000),UINT64_C(0x3ff0000020000000),0},0x0220u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0020u}},
    {{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0220u},{{0x3ffe,UINT64_C(0xffffff0000000000),UINT64_C(0x3fefffffe0000000),0},0x0020u},{{0x3fff,UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),0},0x0220u},{{0x3ffe,UINT64_C(0xffffff0000000000),UINT64_C(0x3fefffffe0000000),0},0x0020u}},
    {{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0220u},{{0xbfff,UINT64_C(0x8000000000000000),UINT64_C(0xbff0000000000000),0},0x0220u},{{0xbffe,UINT64_C(0xffffff0000000000),UINT64_C(0xbfefffffe0000000),0},0x0020u},{{0xbffe,UINT64_C(0xffffff0000000000),UINT64_C(0xbfefffffe0000000),0},0x0020u}},
    {{{0x0002,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},0x0020u},{{0x0002,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},0x0020u},{{0x0002,UINT64_C(0x8000000000000001),UINT64_C(0x0000000000000000),0},0x0220u},{{0x0002,UINT64_C(0x8000000000000000),UINT64_C(0x0000000000000000),0},0x0020u}}
};
static precision_answer_t precision_answer(const legacy_t *l,unsigned operation,unsigned flip,unsigned rc)
{
    unsigned row=l->kind==LEGACY_TINY?3:operation;
    unsigned rounding=flip&&(rc==1||rc==2)?3-rc:rc;
    precision_answer_t answer=masked_precision[row][rounding];
    answer.raw.se^=(uint16_t)(flip<<15);answer.raw.preview^=(uint64_t)flip<<63;
    return answer;
}
static void check_state(fixture_t *f,const hb_context_t *before,const answer_t *expected_answer,unsigned flip,unsigned guest_rc,unsigned host_rc,const legacy_t *l)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    unsigned source=e->top,dst=(source+f->form->index)&7;
    int precision=l&&(l->kind==LEGACY_INEXACT||(l->kind==LEGACY_TINY&&op_index(f->form)==0));
    precision_answer_t pe={0};if(precision)pe=precision_answer(l,op_index(f->form),flip,guest_rc);
    if(is_empty_legacy(l))e->status_word=(uint16_t)((e->status_word|0x80c1u)&~0x200u);
    else{
        if(dst!=source){
            raw_t r=precision?pe.raw:answer(expected_answer,flip,l?host_rc:guest_rc);
            if(!l||precision){install(e,dst,&r,0);check_kind((x->st_ext_valid&(1u<<dst))&&!memcmp(x->st_ext[dst],e->st_ext[dst],10),"exact surviving destination ten-byte raw result/cache",RAW);}
            else{
                if(l->kind==LEGACY_NAN){uint64_t actual;memcpy(&actual,&x->st[dst],8);check_kind((actual&UINT64_C(0x7ff8000000000000))==UINT64_C(0x7ff8000000000000),"legacy quiet NaN result class only",RAW);r.preview=actual;r.tag=2;}
                memcpy(&e->st[dst],&r.preview,8);e->st_ext_valid&=(uint8_t)~(1u<<dst);e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*dst)))|(r.tag<<(2*dst)));
                check_kind(!(x->st_ext_valid&(1u<<dst)),"declined case retains legacy invalid-cache representation",RAW);
            }
            check_kind(!memcmp(&x->st[dst],&e->st[dst],8),"surviving destination preview",RAW);
            check_kind(((x->tag_word>>(2*dst))&3u)==((e->tag_word>>(2*dst))&3u),"surviving destination classification",RAW);
        }
        e->tag_word|=(uint16_t)(3u<<(2*source));e->top=(source+1)&7;e->status_word=(uint16_t)((e->status_word&~0x3800u)|(e->top<<11));
        if(!l||precision)e->status_word=(uint16_t)((e->status_word&~0x200u)|(precision?pe.status_bits:0));
        /* No surviving numerical value exists in the popped physical source. */
        memcpy(&e->st[source],&x->st[source],8);memcpy(e->st_ext[source],x->st_ext[source],10);e->st_ext_valid=(uint8_t)((e->st_ext_valid&~(1u<<source))|(x->st_ext_valid&(1u<<source)));
    }
    e->status_word=(uint16_t)((e->status_word&~0x4500u)|(x->status_word&0x4500u));e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"status, exact C1, pre-pop destination, TOP and all other physical x87 state");
    if(f->ctx->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and register state preserved");
    if(f->ctx->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr&&!memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR/integer flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks preserved");
    check(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const sample_t *s,const legacy_t *l,unsigned flip,unsigned top,unsigned pc,unsigned rc,unsigned host,int uncached)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    const raw_t *a=l?&l->st0:&s->st0,*b=l?&l->sti:&s->sti;const answer_t *expected=(l?l->result:s->result)+op_index(f->form);
    snprintf(phase,sizeof(phase),"%s %s %s %s flip=%u TOP=%u PC=%u RC=%u host=%u uncached=%d",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,l?l->name:s->name,flip,top,pc,rc,host,uncached);
    seed(f,a,b,flip,top,pc,rc,uncached,l);hb_context_t before;memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;if(is_empty_legacy(l))++empty_cases;else if(l)++legacy_cases;else if(uncached)++uncached_cases;else ++exact_cases;
    check_kind(actual_rc==modes[host]&&actual_flags==wanted,"host RC/status unchanged for selected literal case",HOST);
    if(is_empty_legacy(l))check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"legacy IM0 empty fault without store/pop",EXECUTION);
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==CODE+2,"DE instruction completes",EXECUTION);
    check_state(f,&before,expected,flip,rc,host,l);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create reusable DE context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,CODE,form->bytes,2)==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map owned code"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(form->bytes,2,CODE,&d):hb_decode_x64(form->bytes,2,CODE,&d);
    int opcode=form->operation==ADD?HB_INS_X87_FADDP:form->operation==SUB?HB_INS_X87_FSUBP:HB_INS_X87_FSUBRP;
    if(!check_kind(result==HB_OK&&d.len==2&&(int)d.opcode==opcode,"decode actual DE pop arithmetic",EXECUTION))goto done;
    check_kind(d.op1.present&&d.op1.is_imm&&d.op1.imm==(int64_t)form->index,"decoded logical ST destination",EXECUTION);
    f.decoder=hb_decoder_create(arch,form->bytes,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift DE arithmetic",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pcs[]={0,2,3};
    for(unsigned si=0;si<sizeof(samples)/sizeof(samples[0]);++si)for(unsigned flip=0;flip<2;++flip)for(unsigned top=0;top<8;++top)for(unsigned pi=0;pi<3;++pi)if(samples[si].pc_mask&(1u<<pi))for(unsigned rc=0;rc<4;++rc){
        if(form->index==0||form->index==3)for(unsigned host=0;host<4;++host)run_case(&f,&samples[si],NULL,flip,top,pcs[pi],rc,host,0);
        else run_case(&f,&samples[si],NULL,flip,top,pcs[pi],rc,rc^1u,0);
    }
    if(form->index==0||form->index==3||form->index==7)for(unsigned si=0;si<sizeof(samples)/sizeof(samples[0]);++si)if(samples[si].uncached_ok)for(unsigned flip=0;flip<2;++flip)for(unsigned t=0;t<2;++t)for(unsigned host=0;host<4;++host)run_case(&f,&samples[si],NULL,flip,t?5:0,3,3-host,host,1);
    for(unsigned li=0;li<sizeof(legacy)/sizeof(legacy[0]);++li)if(form->index==3||form->index==7||(form->index==0&&is_empty_legacy(&legacy[li])))for(unsigned t=0;t<3;++t)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)run_case(&f,NULL,&legacy[li],host&1,t==0?0:t==1?5:7,legacy[li].pc,rc,host,0);
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
    check(executions==434304u,"planned actual call count");
done:
    if(host_saved)check(fesetenv(&original)==0,"restore caller fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_exact_addsub_test: %u executions (%u exact, %u uncached, %u legacy completions, %u IM0 empty), %u checks, %u failures\n",executions,exact_cases,uncached_cases,legacy_cases,empty_cases,checks,failures);
    printf("failure categories: raw=%u state=%u execution=%u host=%u\n",category_failures[RAW],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
