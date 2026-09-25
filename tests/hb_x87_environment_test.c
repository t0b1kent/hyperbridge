/* Raw 28-byte FLDENV/FNSTENV. Incoming tags provide physical-register occupancy;
 * nonempty classification is rebuilt from existing physical raw80 data.
 * No 14-byte format, FIP/FDP/FOP completeness or pending #MF claim.
 * Failed-read atomicity is an engine contract: hardware can partially load an
 * environment on a page/limit fault. Only existing M9 APIs seed test state.
 */
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

enum {PAGE_BYTES=16384,ENV_BYTES=28,CACHED=0,TINY_NORMAL=1,UNCACHED=2,READABLE=0,NO_READ=1,TRUNCATED=2};
static const uint64_t CODE=UINT64_C(0x4400000),DATA=UINT64_C(0x5400000);
static const uint8_t code[]={0xd9,0x21}; /* fldenv (%ecx/%rcx), default 28-byte format */
static const uint8_t store_code[]={0xd9,0x31}; /* fnstenv (%ecx/%rcx), no FWAIT prefix */
static unsigned checks,failures,executions;
static char phase[180]="setup";

static int check(int ok,const char *what)
{
    ++checks;
    if(!ok) {++failures;if(failures<=80) fprintf(stderr,"FAIL %s: %s\n",phase,what);}
    return ok;
}
static void put16(uint8_t *p,uint16_t v) {p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void put64(uint8_t *p,uint64_t v) {for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(v>>(8*i));}
typedef struct {uint64_t sig;uint16_t se;} raw_t;
/* Explicit physical R0..R7 contents, not logical ST indices. Their tags are
 * valid,zero,special,special,special,special,special,valid = 0x2aa4. */
static const raw_t physical[]={
    {UINT64_C(0x8000000000000400),0x4034}, /* exact 2^53+1 */
    {0,0x8000},                         /* -zero */
    {UINT64_C(0xc123456789abcdef),0x7fff},/* qNaN */
    {UINT64_C(0x8123456789abcdef),0x7fff},/* sNaN */
    {1,0},                             /* ext80 denormal */
    {UINT64_C(0x4000000000000000),0x3fff},/* unsupported unnormal */
    {UINT64_C(0x8000000000000000),0x7fff},/* +infinity */
    {UINT64_C(0x8000000000000000),0x43ff} /* normal 2^1024, binary64 preview is infinity */
};
static const struct {uint16_t input,expected;const char *name;} tags[]={
    {0x5555,0x2aa4,"all occupied, deliberately wrong zero classifications"},
    {0x77dd,0x3bec,"physical R0/R2/R5/R7 occupied"},
    {0xffff,0xffff,"all empty"},
    {0x0000,0x2aa4,"all occupied with incoming valid classifications"},
    {0xaaaa,0x2aa4,"all occupied with incoming special classifications"}
};

typedef struct {
    hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;
    hb_interpreter_t *interp;hb_jit_runtime_t *jit;
    hb_arch_t arch;hb_backend_t backend;int store_env;
} fixture_t;

static int seed(fixture_t *f,unsigned old_top,unsigned profile,uint64_t address)
{
    hb_context_t *ctx=f->ctx;
    memset(&ctx->regs,0x3c,sizeof(ctx->regs));
    if(f->arch==HB_ARCH_X86) {
        ctx->regs.x86.ecx=(uint32_t)address;ctx->regs.x86.eip=(uint32_t)CODE;ctx->regs.x86.eflags=0xa57;
        memset(&ctx->x87_64,0x49,sizeof(ctx->x87_64));
    } else {ctx->regs.x64.rcx=address;ctx->regs.x64.rip=CODE;ctx->regs.x64.rflags=0xa57;}
    hb_x87_state_t *x=hb_context_x87(ctx);hb_x87_reset(x);
    x->top=old_top;x->control_word=0x037f;x->status_word=(uint16_t)((old_top<<11)|0x0201);
    x->last_x87_ip=0x12345678;
    for(unsigned phys=0;phys<8;++phys) {
        raw_t raw=physical[phys];
        if(profile==TINY_NORMAL && phys==0) raw=(raw_t){UINT64_C(0x8000000000000000),1};
        uint8_t bytes[10];put64(bytes,raw.sig);put16(bytes+8,raw.se);
        unsigned logical=(phys+8-old_top)&7;
        /* Initially R1/R3/R4/R6 are occupied; the opposite transitions and the
         * retained exact payload of empty R0 are exercised by incoming tags. */
        if(!check(hb_x87_set_st_ext80(x,logical,bytes,(0x5au&(1u<<phys))!=0)==HB_OK,"seed independent physical raw80 payload")) return 0;
        if(!check((x->st_ext_valid&(1u<<phys)) && !memcmp(x->st_ext[phys],bytes,10),"seed maps logical setter to intended physical slot")) return 0;
    }
    if(profile==UNCACHED) {
        static const struct {unsigned phys;uint64_t bits;} values[]={
            {0,UINT64_C(1)}, /* binary64 subnormal is normal in extended precision */
            {1,UINT64_C(0x8000000000000000)},
            {2,UINT64_C(0x7ff0123456789abc)},
            {3,UINT64_C(0x7ff0000000000000)},
            {7,UINT64_C(0x7fefffffffffffff)}
        };
        for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i) {
            memcpy(&x->st[values[i].phys],&values[i].bits,8);
            x->st_ext_valid&=(uint8_t)~(1u<<values[i].phys);
        }
        check(x->st_ext_valid==0x70,"uncached subset retains explicit cache-valid mask");
    }
    memset(ctx->ymm_hi,0x7a,sizeof(ctx->ymm_hi));memset(ctx->zmm_hi,0x4b,sizeof(ctx->zmm_hi));
    memset(ctx->k,0x39,sizeof(ctx->k));memset(ctx->xmm_ext,0x51,sizeof(ctx->xmm_ext));
    memset(ctx->ymm_hi_ext,0x62,sizeof(ctx->ymm_hi_ext));memset(ctx->zmm_hi_ext,0x73,sizeof(ctx->zmm_hi_ext));
    ctx->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};
    memset(&ctx->lazy_flags,0,sizeof(ctx->lazy_flags));
    ctx->mxcsr=0x5fa1;ctx->pc=CODE;ctx->last_result=HB_OK;
    ctx->last_fault_kind=HB_FAULT_KIND_NONE;ctx->last_fault_addr_valid=0;
    ctx->fs_base=0x11110000;ctx->gs_base=0x22220000;
    ctx->seg_cs=0x33;ctx->seg_ds=0x2b;ctx->seg_es=0x31;ctx->seg_fs=0x53;ctx->seg_gs=0x61;ctx->seg_ss=0x69;
    ctx->step_limit=8;ctx->block_limit=2;
    return 1;
}

static void check_state(fixture_t *f,const hb_context_t *before,unsigned new_top,unsigned tag,unsigned access)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));
    hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    if(f->store_env && access==READABLE) {
        e->control_word|=0x003f;
        /* FNSTENV leaves its condition codes undefined; stored SW is checked
         * separately against the pre-instruction value. */
        e->status_word=(uint16_t)((e->status_word&~0x4700u)|(x->status_word&0x4700u));
    } else if(!f->store_env && access==READABLE) {
        e->control_word=0x0b7f; /* all six exceptions masked, RC=up */
        e->status_word=(uint16_t)((new_top<<11)|0x4504); /* ZE masked, ES/B=0 */
        e->top=new_top;e->tag_word=tags[tag].expected;
    }
    /* Successful FLDENV metadata restoration is outside this tag-only oracle.
     * Dispatch excludes FLDENV/FNSTENV from FIP updates, so failed operations
     * and FNSTENV can compare the entire existing metadata field unchanged. */
    if(!f->store_env && access==READABLE)e->last_x87_ip=x->last_x87_ip;
    check(!memcmp(x,e,sizeof(*x)),f->store_env ?
          "FNSTENV masks only after success and preserves x87 payload/tags/TOP" : access==READABLE ?
          "CW/SW/TOP and reconstructed tags, with every physical preview/cache bit preserved" :
          "engine failed-read atomicity preserves complete x87 state");
    if(f->arch==HB_ARCH_X86) expected.regs.x86.eip=f->ctx->regs.x86.eip;
    else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register file preserved");
    if(f->arch==HB_ARCH_X86) check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr && !memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags)) &&
          !memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi)) && !memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi)) &&
          !memcmp(f->ctx->k,before->k,sizeof(before->k)) && !memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext)) &&
          !memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext)) &&
          !memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors and opmasks preserved");
    check(f->ctx->fs_base==before->fs_base && f->ctx->gs_base==before->gs_base && f->ctx->seg_cs==before->seg_cs &&
          f->ctx->seg_ds==before->seg_ds && f->ctx->seg_es==before->seg_es && f->ctx->seg_fs==before->seg_fs &&
          f->ctx->seg_gs==before->seg_gs && f->ctx->seg_ss==before->seg_ss,"segment state preserved");
}

static void run_one(fixture_t *f,unsigned old_top,unsigned new_top,unsigned tag,unsigned profile,unsigned access)
{
    uint8_t expected_memory[PAGE_BYTES],actual_memory[PAGE_BYTES],environment[ENV_BYTES];
    hb_context_t before;
    size_t offset=access==TRUNCATED ? PAGE_BYTES-16:128;
    snprintf(phase,sizeof(phase),"%s %s oldTOP=%u newTOP=%u tags=%04x profile=%u access=%u",
             f->arch==HB_ARCH_X86?"x86":"x64",f->backend==HB_BACKEND_JIT?"JIT":"interp",old_top,new_top,tags[tag].input,profile,access);
    memset(environment,0x6c,sizeof(environment));
    put16(environment,0x0b7f);put16(environment+4,(uint16_t)((new_top<<11)|0x4504));put16(environment+8,tags[tag].input);
    memset(expected_memory,0xa5,sizeof(expected_memory));
    memcpy(expected_memory+offset,environment,access==TRUNCATED?16:ENV_BYTES);
    if(!check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f->ctx->memory,DATA,expected_memory,sizeof(expected_memory))==HB_OK,"seed owned environment page")) return;
    if(!seed(f,old_top,profile,DATA+offset)) return;
    if(access==NO_READ && !check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_WRITE)==HB_OK,"deny environment reads")) return;
    memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(FE_UPWARD)==0 && feclearexcept(FE_ALL_EXCEPT)==0 && feraiseexcept(FE_DIVBYZERO)==0,
              "seed masked host rounding and exception flags")) goto restore_permissions;
    int host_status=fetestexcept(FE_ALL_EXCEPT);
    hb_exec_result_t out={0};
    hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_round=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);
    ++executions;
    check(actual_round==FE_UPWARD && actual_status==host_status,"FLDENV classification preserves host FP state, including sNaN previews");
    if(access==READABLE) check(result==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out &&
                             out.steps_executed && out.blocks_executed && f->ctx->pc==CODE+sizeof(code),"raw FLDENV completes at exact end PC");
    else check((result==HB_OK || result==HB_ERR_MEMORY_FAULT) && out.result==HB_ERR_MEMORY_FAULT && out.faulted && !out.timed_out,
               "unreadable or incomplete 28-byte environment reports memory fault");
    check_state(f,&before,new_top,tag,access);
restore_permissions:
    check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned page permissions");
    check(hb_memory_read(f->ctx->memory,DATA,actual_memory,sizeof(actual_memory))==HB_OK &&
          !memcmp(actual_memory,expected_memory,sizeof(actual_memory)),"entire source page and adjacent guards unchanged");
}

static int native_present(const hb_jit_runtime_t *jit)
{
    if(!jit || !jit->block_cache)return 0;
    for(size_t i=0;i<jit->block_cache->size;++i) {const hb_block_cache_entry_t *e=&jit->block_cache->entries[i];
        if(e->valid && e->guest_addr==CODE && e->native_code && e->native_size)return 1;}
    return 0;
}

static void run_store_one(fixture_t *f,unsigned masks,unsigned pattern,unsigned access)
{
    uint8_t expected_memory[PAGE_BYTES],actual_memory[PAGE_BYTES];hb_context_t before;
    uint64_t target=access==TRUNCATED?DATA+2*PAGE_BYTES:DATA+128; /* store mode2: wholly unmapped */
    unsigned top=pattern?2:5;
    snprintf(phase,sizeof(phase),"%s %s FNSTENV masks=%02x pattern=%u access=%u",
             f->arch==HB_ARCH_X86?"x86":"x64",f->backend==HB_BACKEND_JIT?"JIT":"interp",masks,pattern,access);
    memset(expected_memory,0xa5,sizeof(expected_memory));
    if(!check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f->ctx->memory,DATA,expected_memory,sizeof(expected_memory))==HB_OK,"seed FNSTENV output guards"))return;
    if(!seed(f,top,pattern?UNCACHED:CACHED,target))return;
    hb_x87_state_t *x=hb_context_x87(f->ctx);
    x->control_word=(uint16_t)((pattern?0x0a40:0x0740)|masks);
    x->status_word=(uint16_t)((top<<11)|0x4500|(pattern?0x0200:0)); /* no pending exceptions/ES/B */
    if(access==NO_READ && !check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ)==HB_OK,"deny FNSTENV destination writes"))return;
    memcpy(&before,f->ctx,sizeof(before));
    if(!check(fesetround(FE_DOWNWARD)==0 && feclearexcept(FE_ALL_EXCEPT)==0 && feraiseexcept(FE_DIVBYZERO)==0,
              "seed masked host fenv before FNSTENV"))goto restore_permissions;
    int host_status=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};
    hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_round=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;
    check(actual_round==FE_DOWNWARD && actual_status==host_status,"FNSTENV preserves host FP state");
    if(access==READABLE)check(result==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out && out.steps_executed &&
                            out.blocks_executed && f->ctx->pc==CODE+sizeof(store_code),"raw FNSTENV completes before mask side effect");
    else check((result==HB_OK || result==HB_ERR_MEMORY_FAULT) && out.result==HB_ERR_MEMORY_FAULT && out.faulted && !out.timed_out,
               "failed FNSTENV write reports memory fault");
    check_state(f,&before,0,0,access);
restore_permissions:
    check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore FNSTENV destination permissions");
    if(!check(hb_memory_read(f->ctx->memory,DATA,actual_memory,sizeof(actual_memory))==HB_OK,"read FNSTENV result page"))return;
    if(access==READABLE) {
        const hb_x87_state_t *old=hb_context_x87(&before);uint8_t word[2];
        put16(word,old->control_word);check(!memcmp(actual_memory+128,word,2),"stored CW contains original mask bits");
        put16(word,old->status_word);check(!memcmp(actual_memory+132,word,2),"stored SW is the pre-instruction status including TOP");
        put16(word,old->tag_word);check(!memcmp(actual_memory+136,word,2),"stored full tag word is unchanged");
        /* Reserved and address/opcode fields inside the 28-byte area are not
         * a completeness oracle; all surrounding bytes must be untouched. */
        check(!memcmp(actual_memory,expected_memory,128) &&
              !memcmp(actual_memory+128+ENV_BYTES,expected_memory+128+ENV_BYTES,PAGE_BYTES-128-ENV_BYTES),"FNSTENV writes only its 28-byte area");
    } else check(!memcmp(actual_memory,expected_memory,sizeof(actual_memory)),"failed FNSTENV write leaves owned memory unchanged");
}

static void run_fixture(hb_arch_t arch,hb_backend_t backend,int store_env)
{
    fixture_t f={.arch=arch,.backend=backend,.store_env=store_env};
    const uint8_t *guest_code=store_env?store_code:code;
    snprintf(phase,sizeof(phase),"%s %s setup",arch==HB_ARCH_X86?"x86":"x64",backend==HB_BACKEND_JIT?"JIT":"interp");
    f.ctx=hb_context_create(arch,backend);
    if(!check(f.ctx!=NULL,"create reusable context"))goto done;
    f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory && hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f.ctx->memory,CODE,guest_code,sizeof(code))==HB_OK &&
              hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK &&
              hb_memory_map_private(f.ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map isolated code and data pages"))goto done;
    hb_decoded_t d={0};hb_result_t decoded=arch==HB_ARCH_X86?hb_decode_x86(guest_code,sizeof(code),CODE,&d):hb_decode_x64(guest_code,sizeof(code),CODE,&d);
    if(!check(decoded==HB_OK && d.len==sizeof(code) && d.opcode==(store_env?HB_INS_X87_FNSTENV:HB_INS_X87_FLDENV) && d.op1.size==ENV_BYTES,
              "actual decoder recognizes environment opcode with 28-byte operand"))goto done;
    f.decoder=hb_decoder_create(arch,guest_code,sizeof(code),CODE);
    if(!check(f.decoder!=NULL,"create decoder"))goto done;
    hb_result_t lifted=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);
    if(!check(lifted==HB_OK && f.func,"lift actual guest environment instruction"))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);
    if(!check(f.jit || f.interp,"create reusable runtime"))goto done;
    if(store_env) {
        for(unsigned pattern=0;pattern<2;++pattern)for(unsigned masks=0;masks<64;++masks)run_store_one(&f,masks,pattern,READABLE);
        for(unsigned pattern=0;pattern<2;++pattern)for(unsigned access=NO_READ;access<=TRUNCATED;++access) {
            run_store_one(&f,0,pattern,access);run_store_one(&f,0x15,pattern,access);run_store_one(&f,0x3f,pattern,access);
        }
    } else {
        for(unsigned old_top=0;old_top<8;++old_top)for(unsigned new_top=0;new_top<8;++new_top)
            for(unsigned tag=0;tag<sizeof(tags)/sizeof(tags[0]);++tag)run_one(&f,old_top,new_top,tag,CACHED,READABLE);
        for(unsigned profile=TINY_NORMAL;profile<=UNCACHED;++profile)for(unsigned new_top=0;new_top<8;++new_top)
            for(unsigned tag=0;tag<sizeof(tags)/sizeof(tags[0]);++tag)run_one(&f,3,new_top,tag,profile,READABLE);
        for(unsigned old_top=0;old_top<8;old_top+=3)for(unsigned access=NO_READ;access<=TRUNCATED;++access)
            run_one(&f,old_top,(old_top+5)&7,0,UNCACHED,access);
    }
    if(f.jit)check(native_present(f.jit),"JIT has actual native guest entry block");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);
    if(f.interp)hb_interpreter_destroy(f.interp);
    if(f.decoder)hb_decoder_destroy(f.decoder);
    if(f.func)hb_ir_func_destroy(f.func);
    if(f.ctx)hb_context_destroy(f.ctx);
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
        if(v && !check((saved[i]=strdup(v))!=NULL,"save gate value"))goto done;++saved_count;}
    changed=1;
    for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,"0",1)==0,"select helper memory"))goto done;
    hb_env_refresh();
    for(size_t i=0;i<saved_count;++i) {const char *v=hb_gate(gates[i].id);if(!check(v && !strcmp(v,"0"),"effective helper gate"))goto done;}
    if(!check(feholdexcept(&original_host)==0,"save and mask original host fenv"))goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned store=0;store<2;++store)
        run_fixture(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP,(int)store);
done:
    snprintf(phase,sizeof(phase),"cleanup");
    if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed) {
        for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate or absence");
        hb_env_refresh();
        for(size_t i=0;i<saved_count;++i) {const char *v=hb_gate(gates[i].id);check(saved[i]?v && !strcmp(v,saved[i]):!v,"effective original gate restored");}
    }
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_environment_test: %u executions, %u checks, %u failures\n",executions,checks,failures);
    return failures?1:0;
}
