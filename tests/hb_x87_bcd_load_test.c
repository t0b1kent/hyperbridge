/* Actual FBLD/FILD memory instructions. Independent packed decimal/integer
 * input bytes and raw80 answers verify exact loads, including values that a
 * binary64 preview cannot represent. Nearest-even preview bits, independent
 * of guest/host RC, are engine policy; authoritative ext80 results are exact.
 * Malformed BCD nibbles, subsequent #MF delivery, inherited FIP/fault-PC and
 * undefined C0/C2/C3 are outside the oracle. Owned-span read failure atomicity
 * and masked-overflow invalid-cache retention check existing engine behavior.
 * No native host FP traps are enabled; standard host RC/status are checked.
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
enum {SPACE,FULL_MASKED,FULL_IM0,COLLISION_MASKED,COLLISION_IM0};
enum {NORMAL,UNALIGNED,LAST_EDGE,CROSS_READABLE,READ_ONLY,WRITE_ONLY,NO_ACCESS,CROSS_WRITE_ONLY,CROSS_GAP,UNMAPPED,MEMORY_MODES};
static const uint64_t CODE=UINT64_C(0x5000000),DATA=UINT64_C(0x6000000);
static unsigned checks,failures,executions,bcd_executions,integer_executions,roundtrip_executions,memory_executions,overflow_executions,category_failures[CATEGORIES];
static char phase[240]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {const char *name;uint8_t input[10];uint64_t sig;uint16_t se;uint64_t preview;} sample_t;

/* BCD magnitudes are exercised with both signs, including signed zero.
 * All eighteen digit nibbles are valid decimal digits. The final three rows
 * bracket the binary64 halfway point below 10^18 (spacing128). */
static const sample_t bcd_samples[]={
    {"zero",{0},0,0,0},
    {"one",{1},UINT64_C(0x8000000000000000),0x3fff,UINT64_C(0x3ff0000000000000)},
    {"nine",{9},UINT64_C(0x9000000000000000),0x4002,UINT64_C(0x4022000000000000)},
    {"ten",{0x10},UINT64_C(0xa000000000000000),0x4002,UINT64_C(0x4024000000000000)},
    {"ninety-nine",{0x99},UINT64_C(0xc600000000000000),0x4005,UINT64_C(0x4058c00000000000)},
    {"one hundred",{0,1},UINT64_C(0xc800000000000000),0x4005,UINT64_C(0x4059000000000000)},
    {"123456789012345678",{0x78,0x56,0x34,0x12,0x90,0x78,0x56,0x34,0x12},UINT64_C(0xdb4da5d31879a700),0x4037,UINT64_C(0x437b69b4ba630f35)},
    {"2^53-1",{0x91,0x09,0x74,0x54,0x92,0x19,0x07,0x90,0},UINT64_C(0xfffffffffffff800),0x4033,UINT64_C(0x433fffffffffffff)},
    {"2^53",{0x92,0x09,0x74,0x54,0x92,0x19,0x07,0x90,0},UINT64_C(0x8000000000000000),0x4034,UINT64_C(0x4340000000000000)},
    {"2^53+1",{0x93,0x09,0x74,0x54,0x92,0x19,0x07,0x90,0},UINT64_C(0x8000000000000400),0x4034,UINT64_C(0x4340000000000000)},
    {"2^53+2",{0x94,0x09,0x74,0x54,0x92,0x19,0x07,0x90,0},UINT64_C(0x8000000000000800),0x4034,UINT64_C(0x4340000000000001)},
    {"2^53+3",{0x95,0x09,0x74,0x54,0x92,0x19,0x07,0x90,0},UINT64_C(0x8000000000000c00),0x4034,UINT64_C(0x4340000000000002)},
    {"maximum eighteen digits",{0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99},UINT64_C(0xde0b6b3a763ffff0),0x403a,UINT64_C(0x43abc16d674ec800)},
    {"maximum minus one",{0x98,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99},UINT64_C(0xde0b6b3a763fffe0),0x403a,UINT64_C(0x43abc16d674ec800)},
    {"999999999999999935",{0x35,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99},UINT64_C(0xde0b6b3a763ffbf0),0x403a,UINT64_C(0x43abc16d674ec7ff)},
    {"999999999999999936",{0x36,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99},UINT64_C(0xde0b6b3a763ffc00),0x403a,UINT64_C(0x43abc16d674ec800)},
    {"999999999999999937",{0x37,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99},UINT64_C(0xde0b6b3a763ffc10),0x403a,UINT64_C(0x43abc16d674ec800)}
};
/* Two's-complement input bytes are constants, not host signed FP casts. */
#define I(n,v,s,e,p) {n,{(uint8_t)UINT64_C(v),(uint8_t)(UINT64_C(v)>>8),(uint8_t)(UINT64_C(v)>>16),(uint8_t)(UINT64_C(v)>>24),(uint8_t)(UINT64_C(v)>>32),(uint8_t)(UINT64_C(v)>>40),(uint8_t)(UINT64_C(v)>>48),(uint8_t)(UINT64_C(v)>>56)},UINT64_C(s),e,UINT64_C(p)}
static const sample_t i16_samples[]={
    I("i16 zero",0,0,0,0),I("i16 +1",1,0x8000000000000000,0x3fff,0x3ff0000000000000),
    I("i16 -1",0xffff,0x8000000000000000,0xbfff,0xbff0000000000000),
    I("i16 maximum",0x7fff,0xfffe000000000000,0x400d,0x40dfffc000000000),
    I("i16 minimum",0x8000,0x8000000000000000,0xc00e,0xc0e0000000000000)
};
static const sample_t i32_samples[]={
    I("i32 zero",0,0,0,0),I("i32 +1",1,0x8000000000000000,0x3fff,0x3ff0000000000000),
    I("i32 -1",0xffffffff,0x8000000000000000,0xbfff,0xbff0000000000000),
    I("i32 maximum",0x7fffffff,0xfffffffe00000000,0x401d,0x41dfffffffc00000),
    I("i32 minimum",0x80000000,0x8000000000000000,0xc01e,0xc1e0000000000000)
};
static const sample_t i64_samples[]={
    I("i64 zero",0,0,0,0),I("i64 +1",1,0x8000000000000000,0x3fff,0x3ff0000000000000),
    I("i64 -1",0xffffffffffffffff,0x8000000000000000,0xbfff,0xbff0000000000000),
    I("i64 2^53+1",0x0020000000000001,0x8000000000000400,0x4034,0x4340000000000000),
    I("i64 -(2^53+1)",0xffdfffffffffffff,0x8000000000000400,0xc034,0xc340000000000000),
    I("i64 2^53+3",0x0020000000000003,0x8000000000000c00,0x4034,0x4340000000000002),
    I("i64 -(2^53+3)",0xffdffffffffffffd,0x8000000000000c00,0xc034,0xc340000000000002),
    I("i64 maximum",0x7fffffffffffffff,0xfffffffffffffffe,0x403d,0x43e0000000000000),
    I("i64 minimum",0x8000000000000000,0x8000000000000000,0xc03e,0xc3e0000000000000),
    I("i64 2^63-1024",0x7ffffffffffffc00,0xfffffffffffff800,0x403d,0x43dfffffffffffff)
};
#undef I
typedef struct {const char *name;uint8_t code[2];unsigned width;int opcode;const sample_t *samples;unsigned count,is_bcd;} form_t;
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
static const form_t forms[]={
    {"FBLD",{0xdf,0x21},10,HB_INS_X87_FBLD,bcd_samples,COUNT(bcd_samples),1},
    {"FILD16",{0xdf,0x01},2,HB_INS_X87_FILD,i16_samples,COUNT(i16_samples),0},
    {"FILD32",{0xdb,0x01},4,HB_INS_X87_FILD,i32_samples,COUNT(i32_samples),0},
    {"FILD64",{0xdf,0x29},8,HB_INS_X87_FILD,i64_samples,COUNT(i64_samples),0}
};
typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;} fixture_t;
static int memory_fails(unsigned m){return m==WRITE_ONLY||m==NO_ACCESS||m==CROSS_WRITE_ONLY||m==CROSS_GAP||m==UNMAPPED;}
static uint64_t target_for(unsigned m,unsigned width)
{
    if(m==UNALIGNED)return DATA+129;
    if(m==LAST_EDGE)return DATA+2*PAGE_BYTES-width;
    if(m==CROSS_READABLE||m==CROSS_WRITE_ONLY)return DATA+PAGE_BYTES-width/2;
    if(m==CROSS_GAP)return DATA+2*PAGE_BYTES-width/2;
    if(m==UNMAPPED)return DATA+3*PAGE_BYTES;
    return DATA+128;
}
static int restore_permissions(fixture_t *f)
{
    return check(hb_memory_protect(f->c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_protect(f->c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned source permissions");
}
static int seed(fixture_t *f,unsigned rc,unsigned pc,unsigned top,unsigned stack,unsigned mem,unsigned sticky)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));uint64_t target=target_for(mem,f->form->width);
    if(c->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)target;c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rcx=target;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;x->status_word=(uint16_t)((top<<11)|0x4500|(stack==SPACE?0x200:0)|sticky);
    x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));x->last_x87_ip=0x12345678;
    if(stack==FULL_IM0||stack==COLLISION_IM0)x->control_word&=(uint16_t)~1u;
    uint8_t raw[10];for(unsigned i=0;i<8;++i){put64(raw,UINT64_C(0x9000000000000000)+(uint64_t)i*UINT64_C(0x0100000000000000));put16(raw+8,0x4002);
        unsigned occupied=stack==SPACE?i!=7:1;if(stack>=COLLISION_MASKED&&i==3)occupied=0;
        if(!check(hb_x87_set_st_ext80(x,i,raw,occupied)==HB_OK,"seed physical payloads, occupancy and stale destination cache"))return 0;}
    x->st_ext_valid&=(uint8_t)~(1u<<((top+3)&7));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,const sample_t *s,unsigned negative,unsigned stack,unsigned mem)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);
    unsigned overflow=stack!=SPACE,abort=stack==FULL_IM0||stack==COLLISION_IM0,destination=(e->top-1u)&7u;
    if(!memory_fails(mem)){
        uint16_t sw=(uint16_t)(e->status_word&~0x200u);if(overflow)sw|=0x241;if(abort)sw|=0x8080;
        if(!abort){uint8_t raw[10];uint64_t preview;unsigned tag;
            if(overflow){put64(raw,UINT64_C(0xc000000000000000));put16(raw+8,0xffff);preview=UINT64_C(0xfff8000000000000);tag=2;
                e->st_ext_valid&=(uint8_t)~(1u<<destination); /* Existing masked-overflow cache policy. */}
            else {put64(raw,s->sig);put16(raw+8,(uint16_t)(s->se|(negative?0x8000:0)));preview=s->preview|(negative?UINT64_C(0x8000000000000000):0);tag=s->sig?0:1;
                memcpy(e->st_ext[destination],raw,10);e->st_ext_valid|=(uint8_t)(1u<<destination);}
            memcpy(&e->st[destination],&preview,8);e->top=destination;e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*destination)))|(tag<<(2*destination)));
            sw=(uint16_t)((sw&~0x3800u)|(destination<<11));
            uint8_t actual[10];check_kind(hb_x87_save_st_ext80(x,0,actual)==HB_OK&&!memcmp(actual,raw,10),"independent exact raw80 load or masked-overflow indefinite",NUMERIC);
            uint64_t actual_preview=0;memcpy(&actual_preview,&x->st[destination],8);check_kind(actual_preview==preview,"nearest-even binary64 preview is host/guest RC independent",NUMERIC);
        }
        e->status_word=(uint16_t)((sw&~0x4500u)|(x->status_word&0x4500u));
    }
    e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),"x87 control/status/TOP/tags, exact cache and all neighboring physical state");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register state preserved");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 preserved");
    check(f->c->mxcsr==before->mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"complete upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segment state preserved");
}
static void run_case(fixture_t *f,const sample_t *s,unsigned negative,unsigned sign_low,unsigned rc,unsigned host,unsigned pc,unsigned top,unsigned stack,unsigned mem,unsigned sticky)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};uint8_t expected[64],actual[64],input[10];
    uint64_t target=target_for(mem,f->form->width),guard=DATA+112;size_t count=64;
    if(mem==LAST_EDGE||mem==CROSS_GAP){guard=DATA+2*PAGE_BYTES-32;count=32;}else if(mem==CROSS_READABLE||mem==CROSS_WRITE_ONLY)guard=DATA+PAGE_BYTES-32;
    snprintf(phase,sizeof(phase),"%s %s %s %s sign=%u low=%u RC=%u host=%u PC=%u TOP=%u stack=%u mem=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,s->name,negative,sign_low,rc,host,pc,top,stack,mem);
    if(!restore_permissions(f))return;for(unsigned i=0;i<sizeof(expected);++i)expected[i]=(uint8_t)(0xa5u^i*7u);
    memcpy(input,s->input,sizeof(input));if(f->form->is_bcd)input[9]=(uint8_t)((negative?0x80:0)|sign_low);
    if(mem!=UNMAPPED){size_t available=count-(size_t)(target-guard),n=f->form->width;if(n>available)n=available;memcpy(expected+(size_t)(target-guard),input,n);}
    if(!check(hb_memory_write(f->c->memory,guard,expected,count)==HB_OK,"seed owned input bytes and adjacent canaries"))return;
    if(!seed(f,rc,pc,top,stack,mem,sticky))return;
    hb_perm_t perm=HB_PERM_READ|HB_PERM_WRITE;uint64_t protected_base=DATA;
    if(mem==READ_ONLY)perm=HB_PERM_READ;else if(mem==WRITE_ONLY)perm=HB_PERM_WRITE;else if(mem==NO_ACCESS)perm=(hb_perm_t)0;
    else if(mem==CROSS_READABLE){perm=HB_PERM_READ;protected_base+=PAGE_BYTES;}else if(mem==CROSS_WRITE_ONLY){perm=HB_PERM_WRITE;protected_base+=PAGE_BYTES;}
    if(!check(hb_memory_protect(f->c->memory,protected_base,PAGE_BYTES,perm)==HB_OK,"select owned source permissions"))goto restore;
    hb_context_t before;memcpy(&before,f->c,sizeof(before));
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed independent masked host fenv"))goto restore;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t r=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;if(f->form->is_bcd)++bcd_executions;else ++integer_executions;if(mem!=NORMAL)++memory_executions;if(stack!=SPACE)++overflow_executions;
    if(!check_kind(actual_rc==host_modes[host]&&actual_flags==wanted,"host RC/status preserved",HOST)&&category_failures[HOST]<=4)fprintf(stderr,"HOST %s actual rc=%d flags=%x expected rc=%d flags=%x\n",phase,actual_rc,actual_flags,host_modes[host],wanted);
    unsigned memfault=memory_fails(mem),stackfault=stack==FULL_IM0||stack==COLLISION_IM0;
    if(memfault||stackfault){hb_result_t want=memfault?HB_ERR_MEMORY_FAULT:HB_ERR_EXEC_FAULT;check_kind((r==HB_OK||r==want)&&out.result==want&&out.faulted&&!out.timed_out,"expected read or unmasked-stack fault",EXECUTION);}
    else check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->c->pc==CODE+2,"one exact load/push completes",EXECUTION);
    check_state(f,&before,s,negative,stack,mem);
restore:
    if(!restore_permissions(f))return;
    check_kind(hb_memory_read(f->c->memory,guard,actual,count)==HB_OK&&!memcmp(actual,expected,count),"complete input bytes and adjacent canaries unchanged",NUMERIC);
}
static int native_present(fixture_t *f)
{
    if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;
    for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;
}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;snprintf(phase,sizeof(phase),"%s %s setup",arch==HB_ARCH_X86?"x86":"x64",form->name);
    f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,form->code,2)==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map private raw code and adjacent source regions"))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(form->code,2,CODE,&d):hb_decode_x64(form->code,2,CODE,&d);
    if(!check_kind(r==HB_OK&&d.len==2&&(int)d.opcode==form->opcode,"decode exact load opcode",EXECUTION))goto done;
    check_kind(d.op1.size==form->width,"decode exact source byte width",EXECUTION);
    f.decoder=hb_decoder_create(arch,form->code,2,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift raw load instruction",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create reusable runtime"))goto done;
    static const unsigned precisions[]={0,2,3};unsigned signs=form->is_bcd?2:1,pc_count=form->is_bcd?3:1;
    for(unsigned top=0;top<8;++top)for(unsigned p=0;p<pc_count;++p)for(unsigned host=0;host<4;++host)for(unsigned rc=0;rc<4;++rc)
        for(unsigned i=0;i<form->count;++i)for(unsigned negative=0;negative<signs;++negative)
            run_case(&f,&form->samples[i],negative,0,rc,host,form->is_bcd?precisions[p]:3,top,SPACE,NORMAL,0x24);
    /* Full stack and a collision despite another empty physical slot both
     * test the destination tag. No memory-fault/stack-overflow priority claim. */
    for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)for(unsigned stack=FULL_MASKED;stack<=COLLISION_IM0;++stack)
        run_case(&f,&form->samples[form->count-1],form->is_bcd?(host&1):0,0,3-host,host,3,top,stack,NORMAL,0x24);
    for(unsigned mem=UNALIGNED;mem<MEMORY_MODES;++mem)for(unsigned host=0;host<4;++host){
        run_case(&f,&form->samples[form->count-1],form->is_bcd?(host&1):0,0,3-host,host,3,7,SPACE,mem,0x24);
        run_case(&f,&form->samples[0],form->is_bcd?1:0,0,host,host,0,0,SPACE,mem,0x24);}
    if(form->is_bcd){
        /* Every ignored low-seven-bit sign-byte pattern; sign itself remains
         * significant. Zero has a separate negative-zero ignored-bit probe. */
        for(unsigned low=0;low<128;++low)for(unsigned negative=0;negative<2;++negative)
            run_case(&f,&bcd_samples[12],negative,low,3,2,3,5,SPACE,NORMAL,0x24);
        for(unsigned negative=0;negative<2;++negative)run_case(&f,&bcd_samples[0],negative,0x7f,3,2,3,5,SPACE,NORMAL,0x64);
    }
    if(f.jit)check_kind(native_present(&f),"native guest entry block exists (helpers allowed)",EXECUTION);
    uint8_t actual_code[2];check(hb_memory_read(f.c->memory,CODE,actual_code,2)==HB_OK&&!memcmp(actual_code,form->code,2),"raw instruction input preserved");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.c)hb_context_destroy(f.c);
}
static void run_roundtrips(hb_arch_t arch,hb_backend_t backend)
{
    /* FBLD [ECX/RCX]; FBSTP [EDX/RDX]. Separate input/output guards mean the
     * standalone raw80 oracle is complemented by an actual composition test. */
    const uint8_t raw[]={0xdf,0x21,0xdf,0x32};fixture_t f={0};f.form=&forms[0];
    snprintf(phase,sizeof(phase),"%s FBLD/FBSTP pair setup",arch==HB_ARCH_X86?"x86":"x64");
    f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create roundtrip context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,raw,sizeof(raw))==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map actual load/store pair and owned memory"))goto done;
    for(unsigned i=0;i<2;++i){hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(raw+i*2,2,CODE+i*2,&d):hb_decode_x64(raw+i*2,2,CODE+i*2,&d);
        if(!check_kind(r==HB_OK&&d.len==2&&d.opcode==(i?HB_INS_X87_FBSTP:HB_INS_X87_FBLD),"decode both actual roundtrip instructions",EXECUTION))goto done;check_kind(d.op1.size==10,"both roundtrip operands have ten bytes",EXECUTION);}
    f.decoder=hb_decoder_create(arch,raw,sizeof(raw),CODE);if(!check(f.decoder!=NULL,"create pair decoder"))goto done;
    hb_result_t lifted=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(lifted==HB_OK&&f.func,"lift actual FBLD/FBSTP pair",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create pair runtime"))goto done;
    static const unsigned indexes[]={0,9,12},precisions[]={0,2,3};static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    for(unsigned i=0;i<COUNT(indexes);++i)for(unsigned negative=0;negative<2;++negative)for(unsigned host=0;host<4;++host)for(unsigned rc=0;rc<4;++rc){
        const sample_t *s=&bcd_samples[indexes[i]];unsigned top=(host+rc)&7,destination=(top-1)&7;uint8_t input[64],expected[64],actual[64];
        snprintf(phase,sizeof(phase),"%s %s FBLD/FBSTP %s sign=%u host=%u RC=%u",arch==HB_ARCH_X86?"x86":"x64",f.jit?"JIT":"interp",s->name,negative,host,rc);
        if(!seed(&f,rc,precisions[rc%3],top,SPACE,NORMAL,0x24))continue;
        if(arch==HB_ARCH_X86)f.c->regs.x86.edx=(uint32_t)(DATA+256);else f.c->regs.x64.rdx=DATA+256;
        memset(input,0xa5,sizeof(input));memset(expected,0x5a,sizeof(expected));memcpy(input+16,s->input,10);input[25]=(uint8_t)(negative?0x80:0);
        if(!check(hb_memory_write(f.c->memory,DATA+112,input,sizeof(input))==HB_OK&&hb_memory_write(f.c->memory,DATA+240,expected,sizeof(expected))==HB_OK,"seed separate roundtrip source/output canaries"))continue;
        memcpy(expected+16,input+16,10);hb_context_t before,want;memcpy(&before,f.c,sizeof(before));memcpy(&want,&before,sizeof(want));
        if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed roundtrip host fenv"))continue;
        int status=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t r=f.jit?hb_jit_runtime_run(f.jit,f.func,&out):hb_interpreter_run(f.interp,f.func,&out);
        int actual_rc=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;++roundtrip_executions;
        check_kind(actual_rc==host_modes[host]&&actual_status==status,"roundtrip host RC/status preserved",HOST);
        check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed>=2&&out.blocks_executed&&f.c->pc==CODE+sizeof(raw),"both raw load/store instructions complete",EXECUTION);
        check_kind(hb_memory_read(f.c->memory,DATA+240,actual,sizeof(actual))==HB_OK&&!memcmp(actual,expected,sizeof(actual)),"exact independent signed BCD bytes after actual roundtrip",NUMERIC);
        check(hb_memory_read(f.c->memory,DATA+112,actual,sizeof(actual))==HB_OK&&!memcmp(actual,input,sizeof(actual)),"roundtrip source and its guards unchanged");
        hb_x87_state_t *x=hb_context_x87(f.c),*e=hb_context_x87(&want);uint64_t preview=s->preview|(negative?UINT64_C(0x8000000000000000):0);
        memcpy(&e->st[destination],&preview,8);put64(e->st_ext[destination],s->sig);put16(e->st_ext[destination]+8,(uint16_t)(s->se|(negative?0x8000:0)));e->st_ext_valid|=(uint8_t)(1u<<destination);
        e->status_word=(uint16_t)((e->status_word&~0x4700u)|(x->status_word&0x4500u));e->last_x87_ip=x->last_x87_ip;
        check(!memcmp(x,e,sizeof(*x)),"roundtrip restores TOP/occupancy and retains exact loaded payload/cache");
        if(arch==HB_ARCH_X86)want.regs.x86.eip=f.c->regs.x86.eip;else want.regs.x64.rip=f.c->regs.x64.rip;
        check(!memcmp(&f.c->regs,&want.regs,sizeof(want.regs)),"roundtrip GPR/XMM state preserved");
        if(arch==HB_ARCH_X86)check(!memcmp(&f.c->x87_64,&before.x87_64,sizeof(before.x87_64)),"roundtrip inactive x64 x87 preserved");
        check(f.c->mxcsr==before.mxcsr&&!memcmp(&f.c->flags,&before.flags,sizeof(before.flags))&&!memcmp(&f.c->lazy_flags,&before.lazy_flags,sizeof(before.lazy_flags)),"roundtrip MXCSR/integer flags preserved");
        check(!memcmp(f.c->ymm_hi,before.ymm_hi,sizeof(before.ymm_hi))&&!memcmp(f.c->zmm_hi,before.zmm_hi,sizeof(before.zmm_hi))&&!memcmp(f.c->k,before.k,sizeof(before.k))&&!memcmp(f.c->xmm_ext,before.xmm_ext,sizeof(before.xmm_ext))&&!memcmp(f.c->ymm_hi_ext,before.ymm_hi_ext,sizeof(before.ymm_hi_ext))&&!memcmp(f.c->zmm_hi_ext,before.zmm_hi_ext,sizeof(before.zmm_hi_ext)),"roundtrip upper vector/opmask state preserved");
        check(f.c->fs_base==before.fs_base&&f.c->gs_base==before.gs_base&&f.c->seg_cs==before.seg_cs&&f.c->seg_ds==before.seg_ds&&f.c->seg_es==before.seg_es&&f.c->seg_fs==before.seg_fs&&f.c->seg_gs==before.seg_gs&&f.c->seg_ss==before.seg_ss,"roundtrip segment state preserved");
    }
    if(f.jit)check_kind(native_present(&f),"roundtrip has native guest entry block",EXECUTION);
    uint8_t actual_code[4];check(hb_memory_read(f.c->memory,CODE,actual_code,sizeof(actual_code))==HB_OK&&!memcmp(actual_code,raw,sizeof(raw)),"roundtrip raw instruction bytes preserved");
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
    char *saved[COUNT(gates)]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original_host;
    for(size_t i=0;i<COUNT(gates);++i){const char *s=getenv(gates[i].name);if(s&&!check((saved[i]=strdup(s))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,gates[i].value,1)==0,"select private helper policy"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);if(!check(s&&!strcmp(s,gates[i].value),"effective gate"))goto done;}
    if(!check(fegetenv(&original_host)==0,"save complete original host fenv"))goto done;host_saved=1;fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host exceptions"))goto done;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend){
        for(unsigned form=0;form<COUNT(forms);++form)run_form(&forms[form],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
        run_roundtrips(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);}
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_bcd_load_test: %u executions (%u BCD loads, %u integer loads, %u roundtrip pairs), %u memory controls, %u overflow controls, %u checks, %u failures\n",executions,bcd_executions,integer_executions,roundtrip_executions,memory_executions,overflow_executions,checks,failures);
    printf("failure categories: numeric=%u state=%u execution=%u host=%u\n",category_failures[NUMERIC],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
