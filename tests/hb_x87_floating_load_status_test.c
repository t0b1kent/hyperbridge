/* Prepared C1-only FLD tranche: actual memory32/64/80, ST0..7 and all seven
 * constants. Exact finite data avoids the separate precision/NaN/denormal
 * gaps. Irrational constants' numerical RC behavior is deliberately excluded.
 * Destination raw-cache representation is not prescribed; other physical
 * slots are preserved. C0/C2/C3, FIP/fault-PC and later #MF are excluded.
 * ST7 aliases the next push slot: it can only overflow or underflow, never
 * provide an ordinary occupied-source/empty-destination successful load.
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
enum {MEMORY_FORM,REGISTER_FORM,CONSTANT_FORM};
enum {SPACE,FULL_MASKED,FULL_IM0,COLLISION_MASKED,COLLISION_IM0,EMPTY_SOURCE,EMPTY_SOURCE_IM0};
enum {NORMAL,LAST_EDGE,READ_ONLY,WRITE_ONLY,NO_ACCESS,CROSS_RW,CROSS_DENIED,CROSS_GAP,UNMAPPED,MEMORY_MODES};
enum {STATE,EXECUTION,HOST,MEMORY,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x5300000),DATA=UINT64_C(0x6300000);
static unsigned checks,failures,executions,normal_cases,overflow_cases,underflow_cases,memory_cases,category_failures[CATEGORIES];
static char phase[200]="setup";
static int check_kind(int ok,const char *what,unsigned kind)
{
    ++checks;if(!ok){++failures;++category_failures[kind];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
typedef struct {uint64_t sig;uint16_t se;uint64_t preview;} raw_t;
static const raw_t integers[]={
    {UINT64_C(0x8000000000000000),0x3fff,UINT64_C(0x3ff0000000000000)},
    {UINT64_C(0x8000000000000000),0x4000,UINT64_C(0x4000000000000000)},
    {UINT64_C(0xc000000000000000),0x4000,UINT64_C(0x4008000000000000)},
    {UINT64_C(0x8000000000000000),0x4001,UINT64_C(0x4010000000000000)},
    {UINT64_C(0xa000000000000000),0x4001,UINT64_C(0x4014000000000000)},
    {UINT64_C(0xc000000000000000),0x4001,UINT64_C(0x4018000000000000)},
    {UINT64_C(0xe000000000000000),0x4001,UINT64_C(0x401c000000000000)},
    {UINT64_C(0x8000000000000000),0x4002,UINT64_C(0x4020000000000000)}
};
static const raw_t one_half={UINT64_C(0xc000000000000000),0x3fff,UINT64_C(0x3ff8000000000000)};
static const raw_t negative_zero={0,0x8000,UINT64_C(0x8000000000000000)},positive_zero={0,0,0};
static const raw_t indefinite={UINT64_C(0xc000000000000000),0xffff,UINT64_C(0xfff8000000000000)};
typedef struct {const char *name;uint8_t code[2];unsigned type,index,width;} form_t;
static const form_t forms[]={
    {"FLD m32",{0xd9,0x01},MEMORY_FORM,0,4},{"FLD m64",{0xdd,0x01},MEMORY_FORM,0,8},{"FLD m80",{0xdb,0x29},MEMORY_FORM,0,10},
    {"FLD ST0",{0xd9,0xc0},REGISTER_FORM,0,0},{"FLD ST1",{0xd9,0xc1},REGISTER_FORM,1,0},
    {"FLD ST2",{0xd9,0xc2},REGISTER_FORM,2,0},{"FLD ST3",{0xd9,0xc3},REGISTER_FORM,3,0},
    {"FLD ST4",{0xd9,0xc4},REGISTER_FORM,4,0},{"FLD ST5",{0xd9,0xc5},REGISTER_FORM,5,0},
    {"FLD ST6",{0xd9,0xc6},REGISTER_FORM,6,0},{"FLD ST7",{0xd9,0xc7},REGISTER_FORM,7,0},
    {"FLD1",{0xd9,0xe8},CONSTANT_FORM,0,0},{"FLDL2T",{0xd9,0xe9},CONSTANT_FORM,1,0},
    {"FLDL2E",{0xd9,0xea},CONSTANT_FORM,2,0},{"FLDPI",{0xd9,0xeb},CONSTANT_FORM,3,0},
    {"FLDLG2",{0xd9,0xec},CONSTANT_FORM,4,0},{"FLDLN2",{0xd9,0xed},CONSTANT_FORM,5,0},
    {"FLDZ",{0xd9,0xee},CONSTANT_FORM,6,0}
};
typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const form_t *form;} fixture_t;
static int overflow(unsigned stack){return stack>=FULL_MASKED&&stack<=COLLISION_IM0;}
static int aborts(unsigned stack){return stack==FULL_IM0||stack==COLLISION_IM0||stack==EMPTY_SOURCE_IM0;}
static int memory_fails(unsigned mode){return mode==WRITE_ONLY||mode==NO_ACCESS||mode==CROSS_DENIED||mode==CROSS_GAP||mode==UNMAPPED;}
static uint64_t target_for(unsigned mode,unsigned width)
{
    if(mode==LAST_EDGE)return DATA+2*PAGE_BYTES-width;
    if(mode==CROSS_RW||mode==CROSS_DENIED)return DATA+PAGE_BYTES-width/2;
    if(mode==CROSS_GAP)return DATA+2*PAGE_BYTES-width/2;
    if(mode==UNMAPPED)return DATA+3*PAGE_BYTES;
    return DATA+128;
}
static int restore_permissions(fixture_t *f)
{
    return check(hb_memory_protect(f->c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_protect(f->c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned memory permissions");
}
static int seed(fixture_t *f,unsigned top,unsigned pc,unsigned rc,unsigned stack,unsigned mem)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));uint64_t target=target_for(mem,f->form->width);
    if(c->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)target;c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rcx=target;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;x->status_word=(uint16_t)((top<<11)|0x4524|(overflow(stack)?0:0x200));x->control_word=(uint16_t)(0x007f|(pc<<8)|(rc<<10));x->last_x87_ip=0x12345678;
    if(aborts(stack))x->control_word&=(uint16_t)~1u;
    unsigned hole=f->form->type==REGISTER_FORM&&f->form->index==3?2:3;uint8_t raw[10];
    for(unsigned i=0;i<8;++i){unsigned occupied=overflow(stack)?1:i!=7;if((stack==COLLISION_MASKED||stack==COLLISION_IM0)&&i==hole)occupied=0;
        if(stack>=EMPTY_SOURCE&&f->form->type==REGISTER_FORM&&i==f->form->index)occupied=0;
        put64(raw,integers[i].sig);put16(raw+8,integers[i].se);if(!check(hb_x87_set_st_ext80(x,i,raw,occupied)==HB_OK,"seed exact physical source/destination state"))return 0;}
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;
    c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,unsigned stack,unsigned mem,unsigned negative)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);
    unsigned ov=overflow(stack),under=stack>=EMPTY_SOURCE,ab=aborts(stack),destination=(e->top-1)&7;
    if(!memory_fails(mem)){uint16_t sw=(uint16_t)(e->status_word&~0x200u);if(ov||under)sw|=0x41;if(ov)sw|=0x200;if(ab)sw|=0x8080;
        if(!ab){const raw_t *answer=NULL;unsigned tag=0;
            if(ov||under){answer=&indefinite;tag=2;}else if(f->form->type==MEMORY_FORM){answer=negative?&negative_zero:&one_half;tag=negative?1:0;}
            else if(f->form->type==REGISTER_FORM)answer=&integers[f->form->index];
            else if(f->form->index==0)answer=&integers[0];else if(f->form->index==6){answer=&positive_zero;tag=1;}
            if(answer){uint8_t raw[10],want[10];put64(want,answer->sig);put16(want+8,answer->se);uint64_t preview=0;memcpy(&preview,&x->st[destination],8);
                check(hb_x87_save_st_ext80(x,0,raw)==HB_OK&&!memcmp(raw,want,10)&&preview==answer->preview,"exact finite/zero/indefinite payload control");}
            /* The legitimate new slot may use either cached raw80 or the
             * existing exact preview path. Five irrational constants have no
             * numerical oracle in this status-only tranche. */
            memcpy(&e->st[destination],&x->st[destination],8);memcpy(e->st_ext[destination],x->st_ext[destination],10);
            e->st_ext_valid=(uint8_t)((e->st_ext_valid&~(1u<<destination))|(x->st_ext_valid&(1u<<destination)));
            e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*destination)))|(tag<<(2*destination)));e->top=destination;sw=(uint16_t)((sw&~0x3800u)|(destination<<11));}
        e->status_word=(uint16_t)((sw&~0x4500u)|(x->status_word&0x4500u));}
    e->last_x87_ip=x->last_x87_ip;check(!memcmp(x,e,sizeof(*x)),"C1/exception flags, TOP/occupancy and all other physical x87 state");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register state preserved");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 preserved");
    check(f->c->mxcsr==before->mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,unsigned top,unsigned pc,unsigned rc,unsigned host,unsigned stack,unsigned mem)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};uint8_t expected[64],actual[64],input[10]={0};unsigned negative=host&1;
    uint64_t target=target_for(mem,f->form->width),guard=DATA+112;size_t count=64;
    if(mem==LAST_EDGE||mem==CROSS_GAP){guard=DATA+2*PAGE_BYTES-32;count=32;}else if(mem==CROSS_RW||mem==CROSS_DENIED)guard=DATA+PAGE_BYTES-32;
    snprintf(phase,sizeof(phase),"%s %s %s TOP=%u PC=%u RC=%u host=%u stack=%u memory=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->form->name,top,pc,rc,host,stack,mem);
    if(!restore_permissions(f)||!seed(f,top,pc,rc,stack,mem))return;for(unsigned i=0;i<64;++i)expected[i]=(uint8_t)(0xa5u^i*7u);
    if(f->form->type==MEMORY_FORM){
        if(f->form->width==4){uint32_t bits=negative?UINT32_C(0x80000000):UINT32_C(0x3fc00000);for(unsigned i=0;i<4;++i)input[i]=(uint8_t)(bits>>(8*i));}
        else if(f->form->width==8)put64(input,negative?negative_zero.preview:one_half.preview);
        else {put64(input,negative?negative_zero.sig:one_half.sig);put16(input+8,negative?negative_zero.se:one_half.se);}
        if(mem!=UNMAPPED){size_t available=count-(size_t)(target-guard),n=f->form->width;if(n>available)n=available;memcpy(expected+(size_t)(target-guard),input,n);}}
    if(!check(hb_memory_write(f->c->memory,guard,expected,count)==HB_OK,"seed fixed owned input and canaries"))return;
    hb_perm_t perm=HB_PERM_READ|HB_PERM_WRITE;uint64_t base=DATA;
    if(mem==READ_ONLY)perm=HB_PERM_READ;else if(mem==WRITE_ONLY)perm=HB_PERM_WRITE;else if(mem==NO_ACCESS)perm=(hb_perm_t)0;else if(mem==CROSS_DENIED){base+=PAGE_BYTES;perm=HB_PERM_WRITE;}
    if(!check(hb_memory_protect(f->c->memory,base,PAGE_BYTES,perm)==HB_OK,"select source access policy"))goto restore;
    hb_context_t before;memcpy(&before,f->c,sizeof(before));
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host RC/status"))goto restore;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t r=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;if(overflow(stack))++overflow_cases;else if(stack>=EMPTY_SOURCE)++underflow_cases;else ++normal_cases;if(mem!=NORMAL)++memory_cases;
    check_kind(actual_rc==host_modes[host]&&actual_status==wanted,"exact-data load preserves host RC/status",HOST);
    if(memory_fails(mem)||aborts(stack)){hb_result_t want=memory_fails(mem)?HB_ERR_MEMORY_FAULT:HB_ERR_EXEC_FAULT;check_kind((r==HB_OK||r==want)&&out.result==want&&out.faulted&&!out.timed_out,"expected memory or unmasked-stack fault",EXECUTION);}
    else check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->c->pc==CODE+2,"one FLD commits its stack result",EXECUTION);
    check_state(f,&before,stack,mem,negative);
restore:
    if(!restore_permissions(f))return;check_kind(hb_memory_read(f->c->memory,guard,actual,count)==HB_OK&&!memcmp(actual,expected,count),"input memory and adjacent guards unchanged",MEMORY);
}
static int native_present(fixture_t *f)
{
    if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;
    for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;
}
static void run_form(const form_t *form,hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={0};f.form=form;f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable FLD context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,form->code,2)==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned code and input regions"))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(form->code,2,CODE,&d):hb_decode_x64(form->code,2,CODE,&d);
    if(!check_kind(r==HB_OK&&d.len==2&&d.opcode==HB_INS_X87_FLD,"decode actual FLD family opcode",EXECUTION))goto done;
    if(form->type==MEMORY_FORM)check_kind(d.op1.size==form->width,"decode exact floating memory width",EXECUTION);
    f.decoder=hb_decoder_create(arch,form->code,2,CODE);if(!check(f.decoder!=NULL,"create raw decoder"))goto done;
    r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift actual FLD instruction",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned pc[]={0,2,3};
    if(form->type!=REGISTER_FORM||form->index!=7)
        for(unsigned top=0;top<8;++top)for(unsigned p=0;p<3;++p)for(unsigned rc=0;rc<4;++rc)for(unsigned host=0;host<4;++host)run_case(&f,top,pc[p],rc,host,SPACE,NORMAL);
    for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)for(unsigned stack=FULL_MASKED;stack<=COLLISION_IM0;++stack)run_case(&f,top,3,3-host,host,stack,NORMAL);
    if(form->type==REGISTER_FORM&&form->index==7)
        for(unsigned top=0;top<8;++top)for(unsigned host=0;host<4;++host)for(unsigned stack=EMPTY_SOURCE;stack<=EMPTY_SOURCE_IM0;++stack)run_case(&f,top,3,3-host,host,stack,NORMAL);
    if(form->type==MEMORY_FORM)for(unsigned mem=LAST_EDGE;mem<MEMORY_MODES;++mem)for(unsigned host=0;host<4;++host)run_case(&f,5,3,3-host,host,SPACE,mem);
    if(f.jit)check_kind(native_present(&f),"native guest entry block exists; helper allowed",EXECUTION);
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
    printf("hb_x87_floating_load_status_test: %u executions (%u ordinary inputs, %u overflow, %u underflow; %u memory controls), %u checks, %u failures\n",executions,normal_cases,overflow_cases,underflow_cases,memory_cases,checks,failures);
    printf("failure categories: state=%u execution=%u host=%u memory=%u\n",category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[MEMORY]);return failures?1:0;
}
