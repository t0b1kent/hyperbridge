/* Raw FBSTP m80bcd (DF 31, [ECX/RCX]). Decimal output bytes and ext80
 * boundary fixtures are independent constants; no host FP conversion or HB
 * numeric helper supplies the oracle. The existing raw setter only seeds ST0.
 * C0/C2/C3, nonempty-invalid C1, inherited FIP/fault-PC bookkeeping and
 * subsequent #MF delivery are excluded. Fixed owned memory spans test engine prewrite failure ordering,
 * not rollback after arbitrary late host faults. Popped payload/cache retention
 * is checked as existing engine policy. All host FP exceptions remain masked.
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
enum {MASKED,IM0,PM0,DM0};
enum {NORMAL,LAST_EDGE,CROSS_RW,READ_ONLY,WRITE_ONLY,NO_ACCESS,CROSS_RO,CROSS_GAP,UNMAPPED,MEMORY_MODES};
enum {B_ZERO,B_ONE,B_TWO,B_THREE,B_FOUR,B_99,B_100,B_BIG53_1,B_DIGITS,B_MAX,B_MAX_PREV,B_INDEF};
static const uint64_t CODE=UINT64_C(0x4f00000),DATA=UINT64_C(0x5f00000);
static unsigned checks,failures,executions,memory_executions,uncached_executions,category_failures[CATEGORIES];
static char phase[240]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}

/* Pairs of decimal digits, least significant pair first. A normal result's
 * tenth byte is its source sign (including negative zero); its seven low bits
 * are architecturally unspecified and their zero value is engine policy. The indefinite
 * pattern is specified separately, independent of source sign or payload. */
static const uint8_t bcd[][10]={
    {0},{1},{2},{3},{4},{0x99},{0x00,0x01},
    {0x93,0x09,0x74,0x54,0x92,0x19,0x07,0x90,0x00,0},
    {0x78,0x56,0x34,0x12,0x90,0x78,0x56,0x34,0x12,0},
    {0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0},
    {0x98,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0},
    {0,0,0,0,0,0,0,0xc0,0xff,0xff}
};
typedef struct {
    const char *name;uint64_t sig;uint16_t se;
    unsigned out[4],fractional,c1_mask,empty,denormal;
} sample_t;
#define V(n,s,e,a,b,c,d,f,inc) {n,UINT64_C(s),e,{a,b,c,d},f,inc,0,0}
#define BAD(n,s,e) V(n,s,e,B_INDEF,B_INDEF,B_INDEF,B_INDEF,0,0)
static const sample_t samples[]={
    V("+zero",0,0,B_ZERO,B_ZERO,B_ZERO,B_ZERO,0,0),
    V("-zero",0,0x8000,B_ZERO,B_ZERO,B_ZERO,B_ZERO,0,0),
    V("+0.5",0x8000000000000000,0x3ffe,B_ZERO,B_ZERO,B_ONE,B_ZERO,1,4),
    V("-0.5",0x8000000000000000,0xbffe,B_ZERO,B_ONE,B_ZERO,B_ZERO,1,2),
    V("+1.5",0xc000000000000000,0x3fff,B_TWO,B_ONE,B_TWO,B_ONE,1,5),
    V("-1.5",0xc000000000000000,0xbfff,B_TWO,B_TWO,B_ONE,B_ONE,1,3),
    V("+2.5",0xa000000000000000,0x4000,B_TWO,B_TWO,B_THREE,B_TWO,1,4),
    V("-2.5",0xa000000000000000,0xc000,B_TWO,B_THREE,B_TWO,B_TWO,1,2),
    V("+3.5",0xe000000000000000,0x4000,B_FOUR,B_THREE,B_FOUR,B_THREE,1,5),
    V("-3.5",0xe000000000000000,0xc000,B_FOUR,B_FOUR,B_THREE,B_THREE,1,3),
    V("below +2.5",0x9fffffffffffffff,0x4000,B_TWO,B_TWO,B_THREE,B_TWO,1,4),
    V("above +2.5",0xa000000000000001,0x4000,B_THREE,B_TWO,B_THREE,B_TWO,1,5),
    V("+99.5 decimal carry",0xc700000000000000,0x4005,B_100,B_99,B_100,B_99,1,5),
    V("-99.5 decimal carry",0xc700000000000000,0xc005,B_100,B_100,B_99,B_99,1,3),
    V("exact 2^53+1",0x8000000000000400,0x4034,B_BIG53_1,B_BIG53_1,B_BIG53_1,B_BIG53_1,0,0),
    V("exact -(2^53+1)",0x8000000000000400,0xc034,B_BIG53_1,B_BIG53_1,B_BIG53_1,B_BIG53_1,0,0),
    V("exact 123456789012345678",0xdb4da5d31879a700,0x4037,B_DIGITS,B_DIGITS,B_DIGITS,B_DIGITS,0,0),
    V("exact -123456789012345678",0xdb4da5d31879a700,0xc037,B_DIGITS,B_DIGITS,B_DIGITS,B_DIGITS,0,0),
    V("positive maximum18",0xde0b6b3a763ffff0,0x403a,B_MAX,B_MAX,B_MAX,B_MAX,0,0),
    V("negative maximum18",0xde0b6b3a763ffff0,0xc03a,B_MAX,B_MAX,B_MAX,B_MAX,0,0),
    BAD("+10^18",0xde0b6b3a76400000,0x403a),BAD("-10^18",0xde0b6b3a76400000,0xc03a),
    V("+(10^18-0.5)",0xde0b6b3a763ffff8,0x403a,B_INDEF,B_MAX,B_INDEF,B_MAX,1,0),
    V("-(10^18-0.5)",0xde0b6b3a763ffff8,0xc03a,B_INDEF,B_INDEF,B_MAX,B_MAX,1,0),
    V("+(10^18-1.5)",0xde0b6b3a763fffe8,0x403a,B_MAX_PREV,B_MAX_PREV,B_MAX,B_MAX_PREV,1,4),
    V("-(10^18-1.5)",0xde0b6b3a763fffe8,0xc03a,B_MAX_PREV,B_MAX,B_MAX_PREV,B_MAX_PREV,1,2),
    V("one raw ulp below boundary half",0xde0b6b3a763ffff7,0x403a,B_MAX,B_MAX,B_INDEF,B_MAX,1,0),
    V("one raw ulp above boundary half",0xde0b6b3a763ffff9,0x403a,B_INDEF,B_MAX,B_INDEF,B_MAX,1,0),
    V("tiny normal",0x8000000000000000,1,B_ZERO,B_ZERO,B_ONE,B_ZERO,1,4),
    V("negative tiny normal",0x8000000000000000,0x8001,B_ZERO,B_ONE,B_ZERO,B_ZERO,1,2),
    {"positive minsubnormal",1,0,{B_ZERO,B_ZERO,B_ONE,B_ZERO},1,4,0,1},
    {"negative minsubnormal",1,0x8000,{B_ZERO,B_ONE,B_ZERO,B_ZERO},1,2,0,1},
    {"positive pseudo-denormal",UINT64_C(0x8000000000000000),0,{B_ZERO,B_ZERO,B_ONE,B_ZERO},1,4,0,1},
    {"negative pseudo-denormal",UINT64_C(0x8000000000000000),0x8000,{B_ZERO,B_ONE,B_ZERO,B_ZERO},1,2,0,1},
    BAD("quiet NaN",0xc123456789abcdef,0x7fff),BAD("signaling NaN",0x8123456789abcdef,0x7fff),
    BAD("positive infinity",0x8000000000000000,0x7fff),BAD("negative infinity",0x8000000000000000,0xffff),
    BAD("unsupported unnormal",0x4000000000000000,0x3fff),
    BAD("finite beyond binary64 range",0x8000000000000000,0x43ff),BAD("maximum finite raw80",0xffffffffffffffff,0x7ffe),
    {"empty ST0 with cached negative fraction",UINT64_C(0xa000000000000000),0xc000,{B_INDEF,B_INDEF,B_INDEF,B_INDEF},1,0,1,0}
};
#undef V
#undef BAD

typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;} fixture_t;
static int memory_fails(unsigned m){return m==READ_ONLY||m==NO_ACCESS||m==CROSS_RO||m==CROSS_GAP||m==UNMAPPED;}
static uint64_t target_for(unsigned m)
{
    if(m==LAST_EDGE)return DATA+2*PAGE_BYTES-10;
    if(m==CROSS_RW||m==CROSS_RO)return DATA+PAGE_BYTES-5;
    if(m==CROSS_GAP)return DATA+2*PAGE_BYTES-5;
    if(m==UNMAPPED)return DATA+3*PAGE_BYTES;
    return DATA+128;
}
static int restore_permissions(fixture_t *f)
{
    return check(hb_memory_protect(f->c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&
                 hb_memory_protect(f->c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned data permissions");
}
static int seed(fixture_t *f,const sample_t *s,unsigned rc,unsigned pc,unsigned top,unsigned mode,unsigned mem,unsigned sticky)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));uint64_t target=target_for(mem);
    if(c->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)target;c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rcx=target;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;x->status_word=(uint16_t)((top<<11)|0x4700|sticky);
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));x->last_x87_ip=0x12345678;
    if(mode==IM0)x->control_word&=(uint16_t)~1u;else if(mode==PM0)x->control_word&=(uint16_t)~0x20u;else if(mode==DM0)x->control_word&=(uint16_t)~2u;
    uint8_t raw[10];for(unsigned i=0;i<8;++i){put64(raw,UINT64_C(0x9000000000000000)+(uint64_t)i*UINT64_C(0x0100000000000000));put16(raw+8,0x4002);
        if(!check(hb_x87_set_st_ext80(x,i,raw,(i&1)!=0)==HB_OK,"seed distinct neighboring raw80 slots"))return 0;}
    x->st_ext_valid&=(uint8_t)~(1u<<((top+3)&7));put64(raw,s->sig);put16(raw+8,s->se);
    if(!check(hb_x87_set_st_ext80(x,0,raw,!s->empty)==HB_OK,"seed authoritative raw80 ST0"))return 0;
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,const sample_t *s,unsigned rc,unsigned mode,unsigned mem)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);
    unsigned invalid=s->out[rc]==B_INDEF,precision=s->fractional&&!invalid,invalid_fault=invalid&&mode==IM0;
    if(!memory_fails(mem)){
        uint16_t sw=(uint16_t)(e->status_word&~0x200u);
        if(invalid)sw|=(uint16_t)(1u|(s->empty?0x40u:0));else if(precision)sw|=0x20;
        if(!invalid&&(s->c1_mask&(1u<<rc)))sw|=0x200;
        if(invalid_fault||(precision&&mode==PM0))sw|=0x8080;
        if(!invalid_fault){e->tag_word|=(uint16_t)(3u<<(2*e->top));e->top=(e->top+1)&7;sw=(uint16_t)((sw&~0x3800u)|(e->top<<11));}
        if(invalid&&!s->empty)sw=(uint16_t)((sw&~0x200u)|(x->status_word&0x200u));
        /* The three other condition bits are architecturally undefined;
         * nonempty-invalid C1 is excluded from the fault-time oracle too. */
        e->status_word=(uint16_t)((sw&~0x4500u)|(x->status_word&0x4500u));
    }
    e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"x87 status/control/TOP/tags and physical payload/cache outcome");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register state preserved");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 preserved");
    check(f->c->mxcsr==before->mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"complete upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segment state preserved");
}
static void run_case(fixture_t *f,const sample_t *s,unsigned rc,unsigned host,unsigned pc,unsigned top,unsigned mode,unsigned mem,unsigned sticky,const uint64_t *uncached)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};uint8_t expected[64],actual[64];
    uint64_t target=target_for(mem),guard=DATA+112;size_t count=64;
    if(mem==LAST_EDGE||mem==CROSS_GAP){guard=DATA+2*PAGE_BYTES-32;count=32;}
    else if(mem==CROSS_RW||mem==CROSS_RO)guard=DATA+PAGE_BYTES-32;
    snprintf(phase,sizeof(phase),"%s %s FBSTP %s RC=%u host=%u PC=%u TOP=%u mode=%u mem=%u uncached=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",s->name,rc,host,pc,top,mode,mem,uncached!=NULL);
    if(!restore_permissions(f))return;for(unsigned i=0;i<sizeof(expected);++i)expected[i]=(uint8_t)(0xa5u^i*7u);
    if(!check(hb_memory_write(f->c->memory,guard,expected,count)==HB_OK,"seed exact destination and adjacent guard bytes"))return;
    if(!seed(f,s,rc,pc,top,mode,mem,sticky))return;
    if(uncached){hb_x87_state_t *x=hb_context_x87(f->c);memcpy(&x->st[top],uncached,8);x->st_ext_valid&=(uint8_t)~(1u<<top);}
    hb_perm_t perm=HB_PERM_READ|HB_PERM_WRITE;uint64_t protected_base=DATA;
    if(mem==READ_ONLY)perm=HB_PERM_READ;else if(mem==WRITE_ONLY)perm=HB_PERM_WRITE;else if(mem==NO_ACCESS)perm=(hb_perm_t)0;
    else if(mem==CROSS_RO){perm=HB_PERM_READ;protected_base+=PAGE_BYTES;}
    if(!check(hb_memory_protect(f->c->memory,protected_base,PAGE_BYTES,perm)==HB_OK,"select owned destination permissions"))goto restore;
    unsigned invalid=s->out[rc]==B_INDEF,invalid_fault=invalid&&mode==IM0,memory_fault=memory_fails(mem);
    if(!invalid_fault&&!memory_fault){uint8_t result[10];memcpy(result,bcd[s->out[rc]],10);if(!invalid)result[9]=(s->se&0x8000)?0x80:0;memcpy(expected+(size_t)(target-guard),result,10);}
    hb_context_t before;memcpy(&before,f->c,sizeof(before));
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed independent masked host fenv"))goto restore;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t r=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;if(mem!=NORMAL)++memory_executions;if(uncached)++uncached_executions;
    if(!check_kind(actual_rc==host_modes[host]&&actual_flags==wanted,"host RC/status preserved",HOST)&&category_failures[HOST]<=4)fprintf(stderr,"HOST %s actual rc=%d flags=%x expected rc=%d flags=%x\n",phase,actual_rc,actual_flags,host_modes[host],wanted);
    if(invalid_fault||memory_fault){hb_result_t want=memory_fault?HB_ERR_MEMORY_FAULT:HB_ERR_EXEC_FAULT;
        check_kind((r==HB_OK||r==want)&&out.result==want&&out.faulted&&!out.timed_out,"expected unmasked-invalid or memory fault",EXECUTION);}
    else check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->c->pc==CODE+2,"one instruction completes BCD store/pop, including PM0",EXECUTION);
    check_state(f,&before,s,rc,mode,mem);
restore:
    if(!restore_permissions(f))return;
    check_kind(hb_memory_read(f->c->memory,guard,actual,count)==HB_OK&&!memcmp(actual,expected,count),"independent ten BCD bytes and adjacent guards, or rejected-span no write",NUMERIC);
}
static int native_present(fixture_t *f)
{
    if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;
    for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;
}
static void run_arch(hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};const uint8_t raw[]={0xdf,0x31};snprintf(phase,sizeof(phase),"%s FBSTP setup",arch==HB_ARCH_X86?"x86":"x64");
    f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,raw,2)==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map private code and two separate adjacent data regions"))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(raw,2,CODE,&d):hb_decode_x64(raw,2,CODE,&d);
    if(!check_kind(r==HB_OK&&d.len==2&&d.opcode==HB_INS_X87_FBSTP,"decode exact FBSTP opcode",EXECUTION))goto done;
    check_kind(d.op1.size==10,"decode packed BCD operand width ten bytes",EXECUTION);
    f.decoder=hb_decoder_create(arch,raw,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift raw FBSTP",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create reusable runtime"))goto done;
    static const unsigned precisions[]={0,2,3};
    for(unsigned top=0;top<8;++top)for(unsigned p=0;p<3;++p)for(unsigned host=0;host<4;++host)for(unsigned rc=0;rc<4;++rc)
        for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i)run_case(&f,&samples[i],rc,host,precisions[p],top,MASKED,NORMAL,4,NULL);
    for(unsigned rc=0;rc<4;++rc)for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i){const sample_t *s=&samples[i];
        if(s->out[rc]==B_INDEF)run_case(&f,s,rc,2,3,5,IM0,NORMAL,4,NULL);
        if(s->fractional&&s->out[rc]!=B_INDEF)run_case(&f,s,rc,2,3,5,PM0,NORMAL,4,NULL);
        if(s->fractional&&s->out[rc]==B_INDEF&&!s->empty)run_case(&f,s,rc,2,3,5,PM0,NORMAL,4,NULL);
        if(s->denormal)run_case(&f,s,rc,2,3,5,DM0,NORMAL,4,NULL);}
    /* No mixed unmasked-invalid/memory-denial precedence claim. These fixed
     * spans reject before any guest byte or staged x87 state is committed. */
    for(unsigned m=LAST_EDGE;m<MEMORY_MODES;++m)for(unsigned rc=0;rc<4;++rc){
        run_case(&f,&samples[4],rc,2,3,7,MASKED,m,4,NULL);
        run_case(&f,&samples[7],rc,1,0,0,PM0,m,4,NULL);
        run_case(&f,&samples[41],rc,2,2,5,MASKED,m,4,NULL);}
    run_case(&f,&samples[34],0,2,3,5,MASKED,NORMAL,0x44,NULL); /* SF remains sticky through non-stack invalid. */
    run_case(&f,&samples[22],0,2,3,5,MASKED,NORMAL,0x64,NULL); /* Decimal overflow must preserve prior PE/SF. */
    /* Existing pending-state retention is engine policy here: delivery of an
     * earlier unmasked #P before this instruction is explicitly not tested. */
    run_case(&f,&samples[22],0,2,3,5,PM0,NORMAL,0x80a4,NULL);
    static const struct {uint64_t bits;unsigned sample;} uncached[]={
        {UINT64_C(0),0},{UINT64_C(0x8000000000000000),1},{UINT64_C(0x3ff8000000000000),4},
        {UINT64_C(0x7ff8123456789abc),34},{UINT64_C(0x7ff0123456789abc),35},{UINT64_C(0x7ff0000000000000),36},
        {UINT64_C(0x43abc16d674ec800),20},{UINT64_C(1),30}
    };
    for(unsigned rc=0;rc<4;++rc)for(unsigned i=0;i<sizeof(uncached)/sizeof(uncached[0]);++i)
        run_case(&f,&samples[uncached[i].sample],rc,2,3,5,MASKED,NORMAL,4,&uncached[i].bits);
    if(f.jit)check_kind(native_present(&f),"native guest entry block exists (helper execution allowed)",EXECUTION);
    uint8_t actual_code[2];check(hb_memory_read(f.c->memory,CODE,actual_code,2)==HB_OK&&!memcmp(actual_code,raw,2),"input raw instruction bytes preserved");
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
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)run_arch(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_bcd_test: %u executions, %u memory controls, %u uncached controls, %u checks, %u failures\n",executions,memory_executions,uncached_executions,checks,failures);
    printf("failure categories: numeric=%u state=%u execution=%u host=%u\n",category_failures[NUMERIC],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
