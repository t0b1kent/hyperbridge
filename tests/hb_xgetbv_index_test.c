/* XGETBV index validation, bounded x64 contract. CPUID.D.1:XG1 is clear,
 * so x64 ECX != 0 raises #GP(0) without committing destination registers.
 * High RCX bits are ignored. ECX0 returns existing XCR0=7 with zero-extended
 * EAX/EDX. NOP precedes XGETBV to distinguish the fault PC from block entry.
 * x86 ECX0=3 is an existing compatibility control only: advertised XSAVE /
 * OSXSAVE admission and x86 nonzero indices require a separate policy decision.
 * No CR4 model, prohibited-prefix #UD, XGETBV1/XINUSE, FEX/Wine or speed claim.
 * Planned 296 executions: 256 x64 faults, 32 x64 successes, 8 x86 controls.
 */
#include "hb_cpuid.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <fenv.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {PAGE_BYTES=16384,STATE=0,EXECUTION,HOST,MEMORY,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x7a00000),DATA=UINT64_C(0x7b00000);
static const uint8_t code[]={0x90,0x0f,0x01,0xd0};
static const uint32_t invalid_indices[]={1,2,3,0x100,0x10000,0x7fffffff,0x80000000u,0xffffffffu};
static const uint32_t high_halves[]={0,1,0xdeadbeefu,0xffffffffu};
static unsigned checks,failures,executions,x64_faults,x64_successes,x86_controls,category_failures[CATEGORIES];
static char phase[180]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;
    if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}
    return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
typedef struct {
    hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;
    hb_interpreter_t *interp;hb_jit_runtime_t *jit;
    hb_arch_t arch;hb_backend_t backend;
} fixture_t;
static int seed(fixture_t *f,uint64_t rcx,unsigned profile)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));
    if(f->arch==HB_ARCH_X64){
        c->regs.x64.rax=UINT64_C(0xaabbccdd11223344)^profile;
        c->regs.x64.rdx=UINT64_C(0xeeff001155667788)^((uint64_t)profile<<32);
        c->regs.x64.rcx=rcx;c->regs.x64.rip=CODE;c->regs.x64.rflags=profile&1u?0xa57:0x202;
    } else {
        c->regs.x86.eax=0x11223344u^profile;c->regs.x86.edx=0x55667788u^profile;
        c->regs.x86.ecx=(uint32_t)rcx;c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=profile&1u?0xa57:0x202;
        memset(&c->x87_64,0x49,sizeof(c->x87_64));
    }
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=(profile*2u+1)&7u;
    x->control_word=(uint16_t)(0x037fu|(profile<<10));x->status_word=(uint16_t)((x->top<<11)|0x4241);
    x->last_x87_ip=0x87654321u;
    for(unsigned i=0;i<8;++i){uint8_t raw[10]={0x23,1,0,0,0,0,0,0x80,0,0x40};raw[0]+=(uint8_t)i;
        if(!check(hb_x87_set_st_ext80(x,i,raw,(0xa5u&(1u<<i))!=0)==HB_OK,"seed exact occupied/empty x87 payloads"))return 0;}
    if(profile&1u)x->st_ext_valid&=0xedu;
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));
    memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));
    memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=(profile&1u)!=0,.pf=true,.af=true,.zf=(profile&2u)!=0,.of=true};
    memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=(profile&1u)?0:0x5fa1;
    c->fs_base=0x11110000;c->gs_base=0x22220000;
    c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;
    c->last_fault_addr=UINT64_C(0x1122334455667788);c->last_fault_addr_valid=1;
    c->last_fault_pc=UINT64_C(0x8877665544332211);c->step_limit=8;c->block_limit=2;
    return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,int fault)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));
    if(f->arch==HB_ARCH_X64){
        if(!fault){expected.regs.x64.rax=7;expected.regs.x64.rdx=0;}
        expected.regs.x64.rip=f->ctx->regs.x64.rip;
    } else {
        if(!fault){expected.regs.x86.eax=3;expected.regs.x86.edx=0;}
        expected.regs.x86.eip=f->ctx->regs.x86.eip;
    }
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),fault?
          "invalid index preserves all data registers and register flags":"ECX0 result zero-extends EAX/EDX and preserves every other register");
    check(!memcmp(hb_context_x87(f->ctx),hb_context_x87(&expected),sizeof(hb_x87_state_t)),
          "x87 control/status/tag/TOP/raw/cache/preview/FIP preserved");
    if(f->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr && !memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags)) &&
          !memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer/lazy flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi)) &&
          !memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi)) &&
          !memcmp(f->ctx->k,before->k,sizeof(before->k)) &&
          !memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext)) &&
          !memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext)) &&
          !memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors/opmasks preserved");
    check(f->ctx->fs_base==before->fs_base && f->ctx->gs_base==before->gs_base &&
          f->ctx->seg_cs==before->seg_cs && f->ctx->seg_ds==before->seg_ds && f->ctx->seg_es==before->seg_es &&
          f->ctx->seg_fs==before->seg_fs && f->ctx->seg_gs==before->seg_gs && f->ctx->seg_ss==before->seg_ss,
          "segment state preserved");
}
static void run_one(fixture_t *f,uint64_t rcx,unsigned profile)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    uint8_t memory[64],actual[64],actual_code[sizeof(code)];hb_context_t before;
    int fault=f->arch==HB_ARCH_X64 && (uint32_t)rcx!=0;
    snprintf(phase,sizeof(phase),"%s %s RCX=%016" PRIx64 " profile=%u",f->arch==HB_ARCH_X64?"x64":"x86",
             f->backend==HB_BACKEND_JIT?"JIT":"interp",rcx,profile);
    for(unsigned i=0;i<sizeof(memory);++i)memory[i]=(uint8_t)(0xa5u^i*7u^profile);
    if(!check(hb_memory_write(f->ctx->memory,DATA,memory,sizeof(memory))==HB_OK,"seed unrelated owned memory") ||
       !seed(f,rcx,profile))return;
    memcpy(&before,f->ctx,sizeof(before));
    if(!check_kind(fesetround(host_modes[profile])==0 && feclearexcept(FE_ALL_EXCEPT)==0 &&
                   feraiseexcept(FE_INVALID|FE_INEXACT)==0,"seed masked host fenv",HOST))return;
    int saved_flags=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};
    hb_result_t r=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_round=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;
    if(fault)++x64_faults;else if(f->arch==HB_ARCH_X64)++x64_successes;else ++x86_controls;
    check_kind(actual_round==host_modes[profile] && actual_flags==saved_flags,"host fenv preserved",HOST);
    if(fault){
        check_kind((r==HB_OK || r==HB_ERR_EXEC_FAULT) && out.result==HB_ERR_EXEC_FAULT && out.faulted && !out.timed_out,
                   "invalid x64 index faults before destination commit",EXECUTION);
        check_kind(f->ctx->last_fault_kind==HB_FAULT_KIND_GENERAL_PROTECTION && f->ctx->last_fault_addr==0 &&
                   !f->ctx->last_fault_addr_valid && f->ctx->last_fault_pc==CODE+1,
                   "#GP(0) metadata identifies XGETBV after NOP",EXECUTION);
    } else check_kind(r==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out &&
                     out.steps_executed>=2 && out.blocks_executed && f->ctx->pc==CODE+sizeof(code),
                     "NOP and ECX0 XGETBV complete",EXECUTION);
    check_state(f,&before,fault);
    check_kind(hb_memory_read(f->ctx->memory,DATA,actual,sizeof(actual))==HB_OK && !memcmp(actual,memory,sizeof(memory)),
               "unrelated mapped data preserved",MEMORY);
    check_kind(hb_memory_read(f->ctx->memory,CODE,actual_code,sizeof(actual_code))==HB_OK && !memcmp(actual_code,code,sizeof(code)),
               "instruction bytes preserved",MEMORY);
}
static int native_present(const hb_jit_runtime_t *jit)
{
    if(!jit || !jit->block_cache)return 0;
    for(size_t i=0;i<jit->block_cache->size;++i){const hb_block_cache_entry_t *e=&jit->block_cache->entries[i];
        if(e->valid && e->guest_addr==CODE && e->native_code && e->native_size)return 1;}
    return 0;
}
static void run_fixture(hb_arch_t arch,hb_backend_t backend)
{
    fixture_t f={.arch=arch,.backend=backend};uint32_t a,b,c,d;
    snprintf(phase,sizeof(phase),"%s %s setup",arch==HB_ARCH_X64?"x64":"x86",backend==HB_BACKEND_JIT?"JIT":"interp");
    f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create context"))goto done;
    hb_cpuid_query(f.ctx,13,1,&a,&b,&c,&d);
    check((a&4u)==0,"reference feature policy does not advertise XGETBV1");
    hb_cpuid_query(f.ctx,1,0,&a,&b,&c,&d);
    check(arch==HB_ARCH_X64?(c&0x0c000000u)==0x0c000000u:(c&0x0c000000u)==0,
          "x64 XSAVE/OSXSAVE policy; x86 controls deliberately preserve compatibility despite missing feature bits");
    f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory && hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f.ctx->memory,CODE,code,sizeof(code))==HB_OK &&
              hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK &&
              hb_memory_map_private(f.ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,
              "map isolated guest code and unrelated data"))goto done;
    hb_decoded_t decoded={0};hb_result_t decoded_result=arch==HB_ARCH_X86?
        hb_decode_x86(code+1,3,CODE+1,&decoded):hb_decode_x64(code+1,3,CODE+1,&decoded);
    if(!check_kind(decoded_result==HB_OK && decoded.len==3 && decoded.opcode==HB_INS_XGETBV &&
                   !memcmp(decoded.bytes,code+1,3),"decode exact unprefixed XGETBV bytes",EXECUTION))goto done;
    f.decoder=hb_decoder_create(arch,code,sizeof(code),CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    hb_result_t lifted=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);
    if(!check(lifted==HB_OK && f.func,"lift NOP plus XGETBV"))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);
    if(!check(f.jit || f.interp,"create runtime"))goto done;
    if(arch==HB_ARCH_X64){
        for(unsigned high=0;high<4;++high)for(unsigned profile=0;profile<4;++profile){
            run_one(&f,(uint64_t)high_halves[high]<<32,profile);
            for(unsigned index=0;index<sizeof(invalid_indices)/sizeof(invalid_indices[0]);++index)
                run_one(&f,((uint64_t)high_halves[high]<<32)|invalid_indices[index],profile);
        }
    } else for(unsigned profile=0;profile<4;++profile)run_one(&f,0,profile);
    if(f.jit)check_kind(native_present(f.jit),"JIT has native guest entry; shared helper execution allowed",EXECUTION);
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);
    if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.ctx)hb_context_destroy(f.ctx);
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
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *v=getenv(gates[i].name);
        if(v && !check((saved[i]=strdup(v))!=NULL,"save gate value"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,"0",1)==0,"select helper memory"))goto done;
    hb_env_refresh();
    for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);if(!check(v && !strcmp(v,"0"),"effective helper gate"))goto done;}
    if(!check_kind(feholdexcept(&original_host)==0,"save and mask original host fenv",HOST))goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)
        run_fixture(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
    check_kind(executions==296 && x64_faults==256 && x64_successes==32 && x86_controls==8,"complete index/high-RCX/mode/backend matrix",EXECUTION);
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check_kind(fesetenv(&original_host)==0,"restore original host fenv",HOST);
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value/absence");
        hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v && !strcmp(v,saved[i]):!v,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_xgetbv_index_test: %u executions (%u x64 faults, %u x64 success, %u x86 controls), %u checks, %u failures\n",
           executions,x64_faults,x64_successes,x86_controls,checks,failures);
    printf("failure categories: state=%u execution=%u host=%u memory=%u\n",category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[MEMORY]);
    return failures?1:0;
}
