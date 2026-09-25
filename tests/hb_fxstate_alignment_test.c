/* Prepared regression: NOP; FXSAVE/FXRSTOR [ECX/RCX]. AC is explicitly clear,
 * so each misaligned, otherwise accessible operand must raise #GP(0). Valid
 * MXCSR avoids combined state/alignment faults. Aligned memory failures are
 * separate: no implementation-independent #GP/#PF priority claim is made.
 * Known image fields and the 512-byte access boundary are checked. FIP/FDP/FOP,
 * reserved/software image bytes, XSAVE/XRSTOR, #AC-enabled behavior and later
 * exception delivery remain outside scope. JIT entry may call the IR helper.
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

enum {PAGE_BYTES=16384,IMAGE_BYTES=512,GUARD_BYTES=640};
enum {NORMAL,LAST_EDGE,CROSS_RW,DENIED,CROSS_DENIED,CROSS_GAP,UNMAPPED,MEMORY_MODES};
enum {STATE,MEMORY,EXECUTION,HOST,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x5200000),DATA=UINT64_C(0x6200000);
static unsigned checks,failures,executions,gp_cases,memory_fault_cases,success_cases,category_failures[CATEGORIES];
static char phase[200]="setup";
static int check_kind(int ok,const char *what,unsigned kind)
{
    ++checks;if(!ok){++failures;++category_failures[kind];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(i*8));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(i*8));}
typedef struct {uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} raw_t;
static const raw_t values[]={
    {UINT64_C(0xe000000000000000),0x4001,UINT64_C(0x401c000000000000),0},
    {0,0x8000,UINT64_C(0x8000000000000000),1},
    {UINT64_C(0xc000000000001234),0x7fff,UINT64_C(0x7ff8000000000002),2},
    {UINT64_C(0x8000000000000400),0x4034,UINT64_C(0x4340000000000000),0},
    {UINT64_C(0x8000000000000000),1,0,0},{1,0,0,2},
    {UINT64_C(0x8000000000000000),0x7fff,UINT64_C(0x7ff0000000000000),2},
    {UINT64_C(0xd000000000000000),0xc002,UINT64_C(0xc02a000000000000),0}
};
static uint64_t xmm_word(unsigned reg,unsigned half,unsigned restored)
{
    return (restored?UINT64_C(0xe130425364758697):UINT64_C(0x123456789abcdef0))^((uint64_t)reg<<36)^((uint64_t)half<<60);
}
typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;unsigned restore;} fixture_t;
static int memory_fails(unsigned mode){return mode==DENIED||mode==CROSS_DENIED||mode==CROSS_GAP||mode==UNMAPPED;}
static uint64_t target_for(unsigned mode,unsigned offset)
{
    if(mode==LAST_EDGE)return DATA+2*PAGE_BYTES-IMAGE_BYTES;
    if(mode==CROSS_RW||mode==CROSS_DENIED)return DATA+PAGE_BYTES-256;
    if(mode==CROSS_GAP)return DATA+2*PAGE_BYTES-256;
    if(mode==UNMAPPED)return DATA+3*PAGE_BYTES;
    return DATA+128+offset;
}
static int restore_permissions(fixture_t *f)
{
    return check(hb_memory_protect(f->c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_protect(f->c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned image permissions");
}
static int seed(fixture_t *f,uint64_t target,unsigned top,uint32_t mxcsr)
{
    hb_context_t *c=f->c;memset(&c->regs,0x3c,sizeof(c->regs));
    if(c->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)target;c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rcx=target;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    check(((c->arch==HB_ARCH_X86?c->regs.x86.eflags:c->regs.x64.rflags)&UINT64_C(0x40000))==0,"alignment-check flag explicitly disabled");
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;x->control_word=0x037f;x->status_word=(uint16_t)((top<<11)|0x4004);x->last_x87_ip=0x12345678;
    uint8_t raw[10];for(unsigned i=0;i<8;++i){put64(raw,values[i].sig);put16(raw+8,values[i].se);
        if(!check(hb_x87_set_st_ext80(x,i,raw,(0xa5u&(1u<<((top+i)&7)))!=0)==HB_OK,"seed independent occupied/empty raw80 state"))return 0;}
    for(unsigned i=0;i<(c->arch==HB_ARCH_X86?8u:16u);++i){uint64_t *v=c->arch==HB_ARCH_X86?c->regs.x86.xmm[i]:c->regs.x64.xmm[i];v[0]=xmm_word(i,0,0);v[1]=xmm_word(i,1,0);}
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=f->restore?(mxcsr^0x2000u):mxcsr;c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;
    c->last_fault_addr=UINT64_C(0x1122334455667788);c->last_fault_addr_valid=1;c->last_fault_pc=UINT64_C(0x8877665544332211);c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;return 1;
}
static void make_image(uint8_t image[IMAGE_BYTES],uint8_t known[IMAGE_BYTES],hb_arch_t arch,unsigned top,uint32_t mxcsr,unsigned restored)
{
    memset(image,0x69,IMAGE_BYTES);memset(known,0,IMAGE_BYTES);unsigned out_top=restored?(top+3)&7:top;
    put16(image,restored?0x0b7f:0x037f);put16(image+2,(uint16_t)((out_top<<11)|(restored?0x0104:0x4004)));image[4]=restored?0x5a:0xa5;memset(known,1,5);
    put32(image+0x18,mxcsr);put32(image+0x1c,HB_MXCSR_SUPPORTED_MASK);memset(known+0x18,1,8);
    for(unsigned i=0;i<8;++i){const raw_t *v=&values[(i+(restored?3:0))&7];put64(image+0x20+i*16,v->sig);put16(image+0x28+i*16,v->se);memset(known+0x20+i*16,1,10);}
    for(unsigned i=0;i<(arch==HB_ARCH_X86?8u:16u);++i){put64(image+0xa0+i*16,xmm_word(i,0,restored));put64(image+0xa8+i*16,xmm_word(i,1,restored));memset(known+0xa0+i*16,1,16);}
}
static void expected_restore(hb_context_t *expected,unsigned old_top,uint32_t mxcsr)
{
    hb_x87_state_t *x=hb_context_x87(expected);x->top=(old_top+3)&7;x->control_word=0x0b7f;x->status_word=(uint16_t)((x->top<<11)|0x0104);x->tag_word=0;x->st_ext_valid=0xff;
    for(unsigned i=0;i<8;++i){unsigned phys=(x->top+i)&7;const raw_t *v=&values[(i+3)&7];unsigned tag=(0x5a&(1u<<phys))?v->tag:3;
        x->tag_word|=(uint16_t)(tag<<(2*phys));put64(x->st_ext[phys],v->sig);put16(x->st_ext[phys]+8,v->se);memcpy(&x->st[phys],&v->preview,8);}
    expected->mxcsr=mxcsr;for(unsigned i=0;i<(expected->arch==HB_ARCH_X86?8u:16u);++i){uint64_t *v=expected->arch==HB_ARCH_X86?expected->regs.x86.xmm[i]:expected->regs.x64.xmm[i];v[0]=xmm_word(i,0,1);v[1]=xmm_word(i,1,1);}
}
static void check_context(fixture_t *f,const hb_context_t *before,unsigned top,uint32_t mxcsr,unsigned success)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));if(success&&f->restore){expected_restore(&expected,top,mxcsr);hb_context_x87(&expected)->last_x87_ip=hb_context_x87(f->c)->last_x87_ip;}
    check(!memcmp(hb_context_x87(f->c),hb_context_x87(&expected),sizeof(hb_x87_state_t)),"raw x87/cache/tag/TOP state or complete fault preservation including prior FIP");
    if(f->c->arch==HB_ARCH_X86)expected.regs.x86.eip=f->c->regs.x86.eip;else expected.regs.x64.rip=f->c->regs.x64.rip;
    check(!memcmp(&f->c->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register outcome");
    if(f->c->arch==HB_ARCH_X86)check(!memcmp(&f->c->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 preserved");
    check(f->c->mxcsr==expected.mxcsr&&!memcmp(&f->c->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->c->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags outcome");
    check(!memcmp(f->c->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->c->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->c->k,before->k,sizeof(before->k))&&!memcmp(f->c->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->c->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->c->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,unsigned offset,unsigned mode,unsigned top,uint32_t mxcsr,unsigned host)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};uint8_t image[IMAGE_BYTES],known[IMAGE_BYTES],original[GUARD_BYTES],actual[GUARD_BYTES];
    uint64_t target=target_for(mode,offset),guard=DATA+96;size_t count=GUARD_BYTES;
    if(mode==LAST_EDGE){guard=target-32;count=544;}else if(mode==CROSS_RW||mode==CROSS_DENIED){guard=target-32;count=576;}else if(mode==CROSS_GAP){guard=target-32;count=288;}
    snprintf(phase,sizeof(phase),"%s %s %s offset=%u memory=%u TOP=%u MXCSR=%x host=%u",f->c->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->restore?"FXRSTOR":"FXSAVE",offset,mode,top,mxcsr,host);
    if(!restore_permissions(f)||!seed(f,target,top,mxcsr))return;make_image(image,known,f->c->arch,top,mxcsr,f->restore);
    for(unsigned i=0;i<GUARD_BYTES;++i)original[i]=(uint8_t)(0xa5u^i*7u);
    if(f->restore&&mode!=UNMAPPED){size_t available=count-(size_t)(target-guard),n=IMAGE_BYTES;if(n>available)n=available;memcpy(original+(size_t)(target-guard),image,n);}
    if(!check(hb_memory_write(f->c->memory,guard,original,count)==HB_OK,"seed independent image and footprint guards"))return;
    hb_perm_t perm=f->restore?HB_PERM_WRITE:HB_PERM_READ;if(mode==DENIED||mode==CROSS_DENIED)
        if(!check(hb_memory_protect(f->c->memory,DATA+(mode==CROSS_DENIED?PAGE_BYTES:0),PAGE_BYTES,perm)==HB_OK,"deny only required image access"))goto restore;
    hb_context_t before;memcpy(&before,f->c,sizeof(before));unsigned gp=offset!=0,memfault=memory_fails(mode),success=!gp&&!memfault;
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed independent masked host fenv"))goto restore;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t r=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;if(gp)++gp_cases;else if(memfault)++memory_fault_cases;else ++success_cases;
    check_kind(actual_rc==host_modes[host]&&actual_flags==wanted,"host RC/status preserved",HOST);
    if(gp){check_kind((r==HB_OK||r==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"misaligned accessible image raises #GP",EXECUTION);
        check_kind(f->c->last_fault_kind==HB_FAULT_KIND_GENERAL_PROTECTION&&f->c->last_fault_addr==0&&!f->c->last_fault_addr_valid&&f->c->last_fault_pc==CODE+1,"#GP metadata identifies the FX instruction after NOP",EXECUTION);}
    else if(memfault){check_kind((r==HB_OK||r==HB_ERR_MEMORY_FAULT)&&out.result==HB_ERR_MEMORY_FAULT&&out.faulted&&!out.timed_out,"aligned inaccessible image raises memory fault",EXECUTION);
        check_kind(f->c->last_fault_kind!=HB_FAULT_KIND_GENERAL_PROTECTION,"aligned memory rejection is not reported as alignment #GP",EXECUTION);}
    else check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed>=2&&out.blocks_executed&&f->c->pc==CODE+4,"NOP and aligned state operation complete",EXECUTION);
    check_context(f,&before,top,mxcsr,success);
    if(!restore_permissions(f))return;
    if(check_kind(hb_memory_read(f->c->memory,guard,actual,count)==HB_OK,"read owned image and guards after permission restoration",MEMORY)){
        unsigned equal=1;for(size_t i=0;i<count;++i){uint64_t addr=guard+i;int inside=addr>=target&&addr-target<IMAGE_BYTES;
            if(success&&!f->restore&&inside){size_t at=(size_t)(addr-target);if(known[at]&&actual[i]!=image[at])equal=0;}
            else if(actual[i]!=original[i])equal=0;}
        check_kind(equal,success&&!f->restore?"defined save fields and outside-512-byte canaries":"complete source/destination preservation on restore or fault",MEMORY);}
    return;
restore:
    restore_permissions(f);
}
static int native_present(fixture_t *f)
{
    if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;
    for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;
}
static void run_form(hb_arch_t arch,hb_backend_t backend,unsigned restore)
{
    fixture_t f={0};f.restore=restore;const uint8_t code[]={0x90,0x0f,0xae,restore?0x09:0x01};
    f.c=hb_context_create(arch,backend);if(!check(f.c!=NULL,"create reusable FX context"))goto done;f.c->memory=hb_memory_create(0);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,code,sizeof(code))==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned raw code and two adjacent private regions"))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(code+1,3,CODE+1,&d):hb_decode_x64(code+1,3,CODE+1,&d);
    if(!check_kind(r==HB_OK&&d.len==3&&d.opcode==(restore?HB_INS_X87_FXRSTOR:HB_INS_X87_FXSAVE),"decode exact FX opcode following NOP",EXECUTION))goto done;
    f.decoder=hb_decoder_create(arch,code,sizeof(code),CODE);if(!check(f.decoder!=NULL,"create raw decoder"))goto done;
    r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(r==HB_OK&&f.func,"lift actual NOP and FX instruction",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create runtime"))goto done;
    static const unsigned tops[]={1,5};static const uint32_t mxcsr[]={0,0x7fa5};
    for(unsigned offset=0;offset<16;++offset)for(unsigned t=0;t<2;++t)for(unsigned m=0;m<2;++m)for(unsigned host=0;host<4;++host)
        run_case(&f,offset,NORMAL,tops[t],mxcsr[m],host);
    for(unsigned mode=LAST_EDGE;mode<MEMORY_MODES;++mode)for(unsigned host=0;host<4;++host)run_case(&f,0,mode,5,0x5fa1,host);
    if(f.jit)check_kind(native_present(&f),"native entry block exists; FX instruction helper allowed",EXECUTION);
    uint8_t actual[4];check(hb_memory_read(f.c->memory,CODE,actual,sizeof(actual))==HB_OK&&!memcmp(actual,code,sizeof(code)),"raw instruction bytes preserved");
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
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned restore=0;restore<2;++restore)run_form(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP,restore);
done:
    if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_fxstate_alignment_test: %u executions (%u GP, %u memory faults, %u success), %u checks, %u failures\n",executions,gp_cases,memory_fault_cases,success_cases,checks,failures);
    printf("failure categories: state=%u memory=%u execution=%u host=%u\n",category_failures[STATE],category_failures[MEMORY],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
