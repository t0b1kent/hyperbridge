/* M24 preparation: actual FLD m80 and FLD ST(i), without a new API oracle.
 * Firm raw inputs exclude unsupported encodings and pseudo-denormals. Intel
 * exempts these ext80 load forms from SNaN IA and denormal DE. The binary64
 * preview is an internal nearest-even policy, never the raw-value oracle.
 * C0/C2/C3, inherited FIP/fault-PC and pending #MF delivery are excluded.
 * Masked stack substitutes are checked numerically without prescribing their
 * cache representation. ST7 cannot have both occupied source and empty push
 * destination. JIT evidence is compiled entry; an interpreter helper is allowed.
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
enum { SPACE,FULL_MASKED,FULL_IM0,COLLISION_MASKED,COLLISION_IM0,EMPTY_SOURCE,EMPTY_SOURCE_IM0,SPACE_IM_DM0 };
enum { NORMAL,LAST_EDGE,READ_ONLY,WRITE_ONLY,NO_ACCESS,CROSS_RW,CROSS_DENIED,CROSS_GAP,UNMAPPED,MEMORY_MODES };
enum { RAW,STATE,EXECUTION,HOST,MEMORY,CATEGORIES };
static const uint64_t CODE=UINT64_C(0x5500000),DATA=UINT64_C(0x6500000);
static unsigned checks,failures,executions,ordinary_cases,uncached_cases,overflow_cases,underflow_cases,memory_cases,unmasked_valid_cases;
static unsigned category_failures[CATEGORIES];
static char phase[240]="setup";
static int check_kind(int ok,const char *what,unsigned kind)
{ ++checks;if(!ok){++failures;++category_failures[kind];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok; }
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {const char *name;uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} raw_t;
/* Independent literals: 16 positive magnitudes; each also runs with sign set.
 * Tags are physical x87 classes: VALID=0, ZERO=1, SPECIAL=2, EMPTY=3. */
static const raw_t samples[]={
    {"zero",0,0,0,1},
    {"one",UINT64_C(0x8000000000000000),0x3fff,UINT64_C(0x3ff0000000000000),0},
    {"one-plus-low-bit",UINT64_C(0x8000000000000001),0x3fff,UINT64_C(0x3ff0000000000000),0},
    {"one-plus-low11",UINT64_C(0x80000000000007ff),0x3fff,UINT64_C(0x3ff0000000000001),0},
    {"2^53+1",UINT64_C(0x8000000000000400),0x4034,UINT64_C(0x4340000000000000),0},
    {"2^63-0.5",UINT64_C(0xffffffffffffffff),0x403d,UINT64_C(0x43e0000000000000),0},
    {"2^1024",UINT64_C(0x8000000000000000),0x43ff,UINT64_C(0x7ff0000000000000),0},
    {"largest-normal",UINT64_C(0xffffffffffffffff),0x7ffe,UINT64_C(0x7ff0000000000000),0},
    {"half-min-double-subnormal",UINT64_C(0x8000000000000000),0x3bcc,0,0},
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
typedef struct {const char *name;uint8_t code[2];int index;} form_t;
static const form_t forms[]={
    {"FLD m80",{0xdb,0x29},-1},{"FLD ST0",{0xd9,0xc0},0},{"FLD ST1",{0xd9,0xc1},1},
    {"FLD ST2",{0xd9,0xc2},2},{"FLD ST3",{0xd9,0xc3},3},{"FLD ST4",{0xd9,0xc4},4},
    {"FLD ST5",{0xd9,0xc5},5},{"FLD ST6",{0xd9,0xc6},6},{"FLD ST7",{0xd9,0xc7},7}
};
typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;} fixture_t;
static int overflow(unsigned s){return s>=FULL_MASKED&&s<=COLLISION_IM0;}
static int underflow(unsigned s){return s==EMPTY_SOURCE||s==EMPTY_SOURCE_IM0;}
static int aborts(unsigned s){return s==FULL_IM0||s==COLLISION_IM0||s==EMPTY_SOURCE_IM0;}
static int memory_fails(unsigned m){return m==WRITE_ONLY||m==NO_ACCESS||m==CROSS_DENIED||m==CROSS_GAP||m==UNMAPPED;}
static uint64_t target_for(unsigned m)
{ if(m==LAST_EDGE)return DATA+2*PAGE_BYTES-10;if(m==CROSS_RW||m==CROSS_DENIED)return DATA+PAGE_BYTES-5;if(m==CROSS_GAP)return DATA+2*PAGE_BYTES-5;if(m==UNMAPPED)return DATA+3*PAGE_BYTES;return DATA+128; }
static void install(hb_x87_state_t *x,unsigned phys,const raw_t *r,unsigned sign,unsigned occupied)
{
    uint64_t preview=r->preview|((uint64_t)sign<<63);memcpy(&x->st[phys],&preview,8);
    put64(x->st_ext[phys],r->sig);put16(x->st_ext[phys]+8,(uint16_t)(r->se|(sign<<15)));
    x->st_ext_valid|=(uint8_t)(1u<<phys);x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*phys)))|((occupied?r->tag:3u)<<(2*phys)));
}
static int restore_permissions(fixture_t *f)
{return check(hb_memory_protect(f->c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_protect(f->c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned permissions");}
static void seed(fixture_t *f,const raw_t *r,const uncached_t *u,unsigned sign,unsigned top,unsigned pc,unsigned rc,unsigned stack,unsigned mem)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));uint64_t target=target_for(mem);
    if(c->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)target;c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else{c->regs.x64.rcx=target;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;
    /* Keep IE/DE clear and alternate PE clear/sticky, so exact transport cannot
     * conceal a newly raised exception behind every initial status word. */
    x->status_word=(uint16_t)((top<<11)|0x4504|((top&1)?0x20:0)|(overflow(stack)?0:0x200));
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));if(aborts(stack))x->control_word&=(uint16_t)~1u;if(stack==SPACE_IM_DM0)x->control_word&=(uint16_t)~3u;x->last_x87_ip=0x12345678;
    unsigned hole=f->form->index==3?2:3;
    for(unsigned i=0;i<8;++i){raw_t neighbor={"neighbor",UINT64_C(0x8000000000000000)+(uint64_t)i*UINT64_C(0x1000000000000000),0x4002,UINT64_C(0x4020000000000000)+(uint64_t)i*UINT64_C(0x2000000000000),0};
        unsigned occupied=overflow(stack)?1:i!=7;if((stack==COLLISION_MASKED||stack==COLLISION_IM0)&&i==hole)occupied=0;
        install(x,(top+i)&7,&neighbor,i&1,occupied);}
    if(f->form->index>=0){unsigned source=(top+(unsigned)f->form->index)&7;install(x,source,r,sign,!underflow(stack));
        if(u){uint64_t bits=u->input|((uint64_t)sign<<63);memcpy(&x->st[source],&bits,8);x->st_ext_valid&=(uint8_t)~(1u<<source);}}
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;
    c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void check_state(fixture_t *f,const hb_context_t *before,const raw_t *r,unsigned sign,unsigned stack,unsigned mem)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);unsigned dest=(e->top-1)&7;
    if(!memory_fails(mem)){uint16_t sw=(uint16_t)(e->status_word&~0x200u);if(overflow(stack)||underflow(stack))sw|=0x41;if(overflow(stack))sw|=0x200;if(aborts(stack))sw|=0x8080;
        if(!aborts(stack)){if(overflow(stack)||underflow(stack)){
                uint8_t want[10],actual[10];put64(want,indefinite.sig);put16(want+8,indefinite.se);uint64_t bits;memcpy(&bits,&x->st[dest],8);
                check_kind(hb_x87_save_st_ext80(x,0,actual)==HB_OK&&!memcmp(actual,want,10)&&bits==indefinite.preview,"masked stack substitute is floating indefinite",RAW);
                install(e,dest,&indefinite,0,1);memcpy(e->st_ext[dest],x->st_ext[dest],10);e->st_ext_valid=(uint8_t)((e->st_ext_valid&~(1u<<dest))|(x->st_ext_valid&(1u<<dest)));
            }else{
                install(e,dest,r,sign,1);check_kind((x->st_ext_valid&(1u<<dest))&&!memcmp(x->st_ext[dest],e->st_ext[dest],10),"authoritative ten raw bytes survive exact load",RAW);
                check_kind(!memcmp(&x->st[dest],&e->st[dest],8),"deterministic nearest-even preview policy",RAW);
                check_kind(((x->tag_word>>(2*dest))&3u)==r->tag,"tag comes from raw80, independently of preview",RAW);}
            e->top=dest;sw=(uint16_t)((sw&~0x3800u)|(dest<<11));}
        e->status_word=(uint16_t)((sw&~0x4500u)|(x->status_word&0x4500u));}
    e->last_x87_ip=x->last_x87_ip;check(!memcmp(x,e,sizeof(*x)),"status, TOP, source and all neighboring physical x87 state");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific registers preserved");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->c->mxcsr==before->mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,const raw_t *r,const uncached_t *u,unsigned sign,unsigned top,unsigned pc,unsigned rc,unsigned host,unsigned stack,unsigned mem)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};uint8_t expected[64],actual[64],input[10];uint64_t target=target_for(mem),guard=DATA+112;size_t count=64;
    if(mem==LAST_EDGE||mem==CROSS_GAP){guard=DATA+2*PAGE_BYTES-32;count=32;}else if(mem==CROSS_RW||mem==CROSS_DENIED)guard=DATA+PAGE_BYTES-32;
    snprintf(phase,sizeof(phase),"%s %s %s %s sign=%u TOP=%u PC=%u RC=%u host=%u stack=%u memory=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,r->name,sign,top,pc,rc,host,stack,mem);
    if(!restore_permissions(f))return;seed(f,r,u,sign,top,pc,rc,stack,mem);for(unsigned i=0;i<64;++i)expected[i]=(uint8_t)(0xa5u^i*7u);
    put64(input,r->sig);put16(input+8,(uint16_t)(r->se|(sign<<15)));
    if(f->form->index<0&&mem!=UNMAPPED){size_t available=count-(size_t)(target-guard),n=10;if(n>available)n=available;memcpy(expected+(size_t)(target-guard),input,n);}
    if(!check(hb_memory_write(f->c->memory,guard,expected,count)==HB_OK,"seed owned input and canaries"))return;
    hb_perm_t perm=HB_PERM_READ|HB_PERM_WRITE;uint64_t base=DATA;if(mem==READ_ONLY)perm=HB_PERM_READ;else if(mem==WRITE_ONLY)perm=HB_PERM_WRITE;else if(mem==NO_ACCESS)perm=(hb_perm_t)0;else if(mem==CROSS_DENIED){base+=PAGE_BYTES;perm=HB_PERM_WRITE;}
    if(!check(hb_memory_protect(f->c->memory,base,PAGE_BYTES,perm)==HB_OK,"select source access"))goto restore;
    hb_context_t before;memcpy(&before,f->c,sizeof(before));if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host RC/status"))goto restore;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;if(overflow(stack))++overflow_cases;else if(underflow(stack))++underflow_cases;else ++ordinary_cases;if(u)++uncached_cases;if(mem!=NORMAL)++memory_cases;if(stack==SPACE_IM_DM0)++unmasked_valid_cases;
    check_kind(actual_rc==host_modes[host]&&actual_status==wanted,"raw load preserves host RC and seeded standard status",HOST);
    if(memory_fails(mem)||aborts(stack)){hb_result_t want=memory_fails(mem)?HB_ERR_MEMORY_FAULT:HB_ERR_EXEC_FAULT;check_kind((result==HB_OK||result==want)&&out.result==want&&out.faulted&&!out.timed_out,"expected isolated memory or unmasked-stack fault",EXECUTION);}
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->c->pc==CODE+2,"one raw FLD completes",EXECUTION);
    check_state(f,&before,r,sign,stack,mem);
restore:
    if(!restore_permissions(f))return;check_kind(hb_memory_read(f->c->memory,guard,actual,count)==HB_OK&&!memcmp(actual,expected,count),"input and adjacent canaries preserved",MEMORY);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable raw-load context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,form->code,2)==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned code and input"))goto done;
    hb_decoded_t d={0};hb_result_t result=arch==HB_ARCH_X86?hb_decode_x86(form->code,2,CODE,&d):hb_decode_x64(form->code,2,CODE,&d);
    if(!check_kind(result==HB_OK&&d.len==2&&d.opcode==HB_INS_X87_FLD,"decode actual FLD opcode",EXECUTION))goto done;
    if(form->index<0)check_kind(d.op1.size==10,"decode exact ten-byte source",EXECUTION);
    f.decoder=hb_decoder_create(arch,form->code,2,CODE);if(!check(f.decoder!=NULL,"create raw decoder"))goto done;
    result=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift actual FLD",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pcs[]={0,2,3};
    if(form->index!=7)for(unsigned s=0;s<sizeof(samples)/sizeof(samples[0]);++s)for(unsigned sign=0;sign<2;++sign)for(unsigned top=0;top<8;++top){
        if(form->index<0||form->index==0||form->index==6){for(unsigned p=0;p<3;++p)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s],NULL,sign,top,pcs[p],rc,host,SPACE,NORMAL);}
        else for(unsigned host=0;host<4;++host)run_case(&f,&samples[s],NULL,sign,top,3,3-host,host,SPACE,NORMAL);}
    if(form->index==0||form->index==3||form->index==6)for(unsigned s=0;s<sizeof(uncached)/sizeof(uncached[0]);++s)for(unsigned sign=0;sign<2;++sign)for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)run_case(&f,&uncached[s].raw,&uncached[s],sign,top,pcs[host%3],3-host,host,SPACE,NORMAL);
    for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)for(unsigned stack=FULL_MASKED;stack<=COLLISION_IM0;++stack)run_case(&f,&samples[4],NULL,host&1,top,3,3-host,host,stack,NORMAL);
    if(form->index>=0)for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)for(unsigned stack=EMPTY_SOURCE;stack<=EMPTY_SOURCE_IM0;++stack)run_case(&f,&samples[4],NULL,host&1,top,3,3-host,host,stack,NORMAL);
    if(form->index<0)for(unsigned s=0;s<2;++s)for(unsigned mem=LAST_EDGE;mem<MEMORY_MODES;++mem)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s?15:8],NULL,host&1,5,3,3-host,host,SPACE,mem);
    if(form->index!=7)for(unsigned s=0;s<2;++s)for(unsigned sign=0;sign<2;++sign)for(unsigned host=0;host<4;++host)run_case(&f,&samples[s?15:11],NULL,sign,5,3,3-host,host,SPACE_IM_DM0,NORMAL);
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
    printf("hb_x87_raw_load_test: %u executions (%u ordinary, %u overflow, %u underflow; %u uncached, %u memory, %u valid IM/DM0), %u checks, %u failures\n",executions,ordinary_cases,overflow_cases,underflow_cases,uncached_cases,memory_cases,unmasked_valid_cases,checks,failures);
    printf("failure categories: raw=%u state=%u execution=%u host=%u memory=%u\n",category_failures[RAW],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[MEMORY]);return failures?1:0;
}
