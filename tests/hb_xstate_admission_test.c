/* M29 preparation, x64 only: known unavailable xstate instructions become
 * typed #UD, including compiled JIT entry with a leading NOP. Full instruction
 * consumption is checked for simple, disp8 and SIB+disp32 memory forms.
 * Single prohibited prefixes only; no mixed prefix/index/alignment/fetch faults.
 * XSAVEOPT is unadvertised. F3 /4 PTWRITE and 66 /6 CLWB are decode-only controls,
 * never executed or presented as supported runtime parity. LOCK checks are
 * existing baseline behavior. Ordinary XSAVE/XRSTOR mask4 and XGETBV controls
 * preserve the M26/M27 behavior. REX.W controls do not claim x87 pointer fields.
 * Expected 368 executions: 248 #UD, 16 #GP, 104 completions; 8 decode-only forms.
 * No x86 admission, Wine/FEX, host traps, or performance claims.
 */
#include "hb_cpuid.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PAGE_BYTES=16384, IMAGE_BYTES=832, GUARD_BYTES=64, AREA_BYTES=960 };
enum { SAVE, RESTORE, SAVEOPT, GETBV, PTWRITE, CLWB };
enum { ILLEGAL, SAVE_OK, RESTORE_OK, GETBV_OK, GETBV_GP, DECODE_ONLY };
enum { STATE, EXECUTION, HOST, MEMORY, DECODE, CAPABILITY, CATEGORIES };
static const uint64_t CODE=UINT64_C(0x7900000),DATA=UINT64_C(0x7c00000),TARGET=UINT64_C(0x7c00100);
static unsigned checks,failures,executions,illegal_cases,gp_cases,completed_cases,decode_controls,category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t value){p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);}
static void put32(uint8_t *p,uint32_t value){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(value>>(8*i));}
static void put64(uint8_t *p,uint64_t value){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(value>>(8*i));}
typedef struct {const char *name;unsigned op;uint8_t prefix;unsigned rex,effect;uint32_t index;} spec_t;
static const spec_t specs[]={
    {"66 XSAVE",SAVE,0x66,0,ILLEGAL,0},{"F2 XSAVE",SAVE,0xf2,0,ILLEGAL,0},{"LOCK XSAVE",SAVE,0xf0,0,ILLEGAL,0},
    {"66 XRSTOR",RESTORE,0x66,0,ILLEGAL,0},{"F2 XRSTOR",RESTORE,0xf2,0,ILLEGAL,0},{"F3 XRSTOR",RESTORE,0xf3,0,ILLEGAL,0},{"LOCK XRSTOR",RESTORE,0xf0,0,ILLEGAL,0},
    {"XSAVEOPT",SAVEOPT,0,0,ILLEGAL,0},{"XSAVEOPT64",SAVEOPT,0,1,ILLEGAL,0},
    {"XSAVE",SAVE,0,0,SAVE_OK,0},{"XSAVE64",SAVE,0,1,SAVE_OK,0},{"XRSTOR",RESTORE,0,0,RESTORE_OK,0},{"XRSTOR64",RESTORE,0,1,RESTORE_OK,0},
    {"66 XGETBV",GETBV,0x66,0,ILLEGAL,0},{"F2 XGETBV",GETBV,0xf2,0,ILLEGAL,0},{"F3 XGETBV",GETBV,0xf3,0,ILLEGAL,0},{"LOCK XGETBV",GETBV,0xf0,0,ILLEGAL,0},
    {"XGETBV ECX0",GETBV,0,0,GETBV_OK,0},{"XGETBV ECX1",GETBV,0,0,GETBV_GP,1},{"XGETBV ECXmax",GETBV,0,0,GETBV_GP,UINT32_MAX}
};
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;const spec_t *spec;unsigned ea;uint8_t code[16];size_t length;} fixture_t;
static size_t encode(const spec_t *s,unsigned ea,uint8_t out[16])
{
    size_t n=0;out[n++]=0x90;if(s->prefix)out[n++]=s->prefix;if(s->rex)out[n++]=0x48;out[n++]=0x0f;
    if(s->op==GETBV){out[n++]=0x01;out[n++]=0xd0;return n;}
    out[n++]=0xae;unsigned ext=s->op==RESTORE?5:(s->op==SAVEOPT||s->op==CLWB)?6:4;
    if(ea==0)out[n++]=(uint8_t)((ext<<3)|1); /* [rcx] */
    else if(ea==1){out[n++]=(uint8_t)(0x40|(ext<<3)|1);out[n++]=0x40;} /* [rcx+64] */
    else if(ea==2){out[n++]=(uint8_t)(0x80|(ext<<3)|4);out[n++]=0xb3;put32(out+n,0x123456);n+=4;} /* [rbx+rsi*4+0x123456] */
    else out[n++]=(uint8_t)(0xc0|(ext<<3)|1); /* PTWRITE ecx/rcx decode only */
    return n;
}
static int expected_opcode(const spec_t *s)
{
    if(s->effect==ILLEGAL)return HB_INS_UNAVAILABLE_EXT;
    if(s->op==SAVE)return HB_INS_XSAVE;if(s->op==RESTORE)return HB_INS_XRSTOR;
    if(s->op==GETBV)return HB_INS_XGETBV;if(s->op==PTWRITE)return HB_INS_PTWRITE;return HB_INS_NOP;
}
static void seed(fixture_t *f,unsigned profile,uint8_t area[AREA_BYTES])
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));c->regs.x64.rip=CODE;c->regs.x64.rflags=profile&1?0xa57:0x202;
    c->regs.x64.rax=UINT64_C(0xdeadbeef00000000)|(f->spec->effect==SAVE_OK||f->spec->effect==RESTORE_OK?4u:7u);
    c->regs.x64.rdx=UINT64_C(0xfeedfacea5000000);c->regs.x64.rsi=5;c->regs.x64.rbx=TARGET-0x123456-20;
    c->regs.x64.rcx=f->spec->op==GETBV?((uint64_t)(profile?0xdeadbeefu:0)<<32)|f->spec->index:TARGET-(f->ea==1?64:0);
    hb_x87_state_t *x=&c->x87_64;memset(x,0,sizeof(*x));x->top=(profile*2+1)&7;x->control_word=(uint16_t)(0x037f|(profile<<10));x->status_word=(uint16_t)((x->top<<11)|0x4241);x->tag_word=0xd5a5;x->last_x87_ip=0x87654321;x->st_ext_valid=0xa5;
    for(unsigned i=0;i<8;++i){uint64_t bits=UINT64_C(0x4000000000000000)+((uint64_t)i<<48);memcpy(&x->st[i],&bits,8);put64(x->st_ext[i],UINT64_C(0x8000000000000023)+i);put16(x->st_ext[i]+8,0x4000);}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=(profile&1)!=0,.pf=true,.af=true,.zf=(profile&2)!=0,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x3f80;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr=UINT64_C(0x1122334455667788);c->last_fault_addr_valid=1;c->last_fault_pc=UINT64_C(0x8877665544332211);c->step_limit=8;c->block_limit=2;
    for(unsigned i=0;i<AREA_BYTES;++i)area[i]=(uint8_t)(0xa5u^i*7u^profile);uint8_t *image=area+GUARD_BYTES;
    put16(image,0x037f);put16(image+2,0);image[4]=0xff;static const uint32_t mxcsr[]={0,0x1f80,0x5fa5,0xffbf};put32(image+24,mxcsr[profile]);put32(image+28,HB_MXCSR_SUPPORTED_MASK);
    memset(image+512,0,64);put64(image+512,f->spec->effect==SAVE_OK?1:f->spec->effect==RESTORE_OK?(profile&1?0:4):7);
}
static void check_state(fixture_t *f,const hb_context_t *before,const uint8_t input[AREA_BYTES],unsigned profile)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));const uint8_t *image=input+GUARD_BYTES;
    if(f->spec->effect==GETBV_OK){expected.regs.x64.rax=7;expected.regs.x64.rdx=0;}
    if(f->spec->effect==RESTORE_OK){static const uint32_t mxcsr[]={0,0x1f80,0x5fa5,0xffbf};expected.mxcsr=mxcsr[profile];if(profile&1)memset(expected.ymm_hi,0,sizeof(expected.ymm_hi));else memcpy(expected.ymm_hi,image+576,sizeof(expected.ymm_hi));}
    expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"all register data preserved except declared XGETBV result");
    check(!memcmp(&f->ctx->x87_64,&expected.x87_64,sizeof(expected.x87_64)),"x87 raw/cache/preview/status/TOP/FIP preserved");
    check(f->ctx->mxcsr==expected.mxcsr&&!memcmp(&f->ctx->flags,&expected.flags,sizeof(expected.flags))&&!memcmp(&f->ctx->lazy_flags,&expected.lazy_flags,sizeof(expected.lazy_flags)),"MXCSR and integer/lazy flags match declared effect");
    check(!memcmp(f->ctx->ymm_hi,expected.ymm_hi,sizeof(expected.ymm_hi))&&!memcmp(f->ctx->zmm_hi,expected.zmm_hi,sizeof(expected.zmm_hi))&&!memcmp(f->ctx->k,expected.k,sizeof(expected.k))&&!memcmp(f->ctx->xmm_ext,expected.xmm_ext,sizeof(expected.xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,expected.ymm_hi_ext,sizeof(expected.ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,expected.zmm_hi_ext,sizeof(expected.zmm_hi_ext)),"requested YMM result and all unrelated upper vector state");
    check(f->ctx->fs_base==expected.fs_base&&f->ctx->gs_base==expected.gs_base&&f->ctx->seg_cs==expected.seg_cs&&f->ctx->seg_ds==expected.seg_ds&&f->ctx->seg_es==expected.seg_es&&f->ctx->seg_fs==expected.seg_fs&&f->ctx->seg_gs==expected.seg_gs&&f->ctx->seg_ss==expected.seg_ss,"segments preserved");
}
static int native_present(const fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;const hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_one(fixture_t *f,unsigned profile)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};uint8_t input[AREA_BYTES],expected[AREA_BYTES],actual[AREA_BYTES],code_after[16];hb_context_t before;
    snprintf(phase,sizeof(phase),"%s %s EA=%u profile=%u",f->jit?"JIT":"interp",f->spec->name,f->ea,profile);seed(f,profile,input);memcpy(expected,input,sizeof(expected));
    if(!check(hb_memory_write(f->ctx->memory,TARGET-GUARD_BYTES,input,sizeof(input))==HB_OK,"seed owned aligned image and guards"))return;memcpy(&before,f->ctx,sizeof(before));
    if(f->spec->effect==SAVE_OK){uint8_t *image=expected+GUARD_BYTES;put32(image+24,before.mxcsr);put32(image+28,HB_MXCSR_SUPPORTED_MASK);put64(image+512,5);memcpy(image+576,before.ymm_hi,sizeof(before.ymm_hi));}
    if(!check_kind(fesetround(modes[profile])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host RC/status",HOST))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_rc=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);++executions;check_kind(actual_rc==modes[profile]&&actual_flags==wanted,"host RC/status preserved",HOST);
    if(f->spec->effect==ILLEGAL||f->spec->effect==GETBV_GP){int illegal=f->spec->effect==ILLEGAL;if(illegal)++illegal_cases;else ++gp_cases;
        check_kind((result==HB_OK||result==HB_ERR_EXEC_FAULT)&&out.result==HB_ERR_EXEC_FAULT&&out.faulted&&!out.timed_out,"typed guest execution fault",EXECUTION);
        check_kind(f->ctx->last_fault_kind==(illegal?HB_FAULT_KIND_ILLEGAL:HB_FAULT_KIND_GENERAL_PROTECTION)&&f->ctx->last_fault_pc==CODE+1&&f->ctx->last_fault_addr==(illegal?CODE+1:0)&&f->ctx->last_fault_addr_valid==(illegal?1:0),"exact post-NOP fault PC and typed address metadata",EXECUTION);
    }else{++completed_cases;check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed>=2&&out.blocks_executed&&f->ctx->pc==CODE+f->length,"ordinary NOP and xstate control complete",EXECUTION);}
    check_state(f,&before,input,profile);
    check_kind(hb_memory_read(f->ctx->memory,TARGET-GUARD_BYTES,actual,sizeof(actual))==HB_OK&&!memcmp(actual,expected,sizeof(actual)),"typed faults preserve image; ordinary save modifies only mask4 fields",MEMORY);
    check_kind(hb_memory_read(f->ctx->memory,CODE,code_after,f->length)==HB_OK&&!memcmp(code_after,f->code,f->length),"raw instruction bytes preserved",MEMORY);
}
static void run_form(const spec_t *spec,unsigned ea,hb_backend_t backend)
{
    fixture_t f={0};f.spec=spec;f.ea=ea;f.length=encode(spec,ea,f.code);snprintf(phase,sizeof(phase),"setup %s EA=%u backend=%u",spec->name,ea,(unsigned)backend);
    f.ctx=hb_context_create(HB_ARCH_X64,backend);if(!check(f.ctx!=NULL,"create x64 context"))goto done;f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory&&hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.ctx->memory,CODE,f.code,f.length)==HB_OK&&hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned code and image"))goto done;
    uint32_t a,b,c,d;hb_cpuid_query(f.ctx,0xd,1,&a,&b,&c,&d);check_kind(!(a&1)&&hb_xcr0_value(f.ctx,0)==7,"XSAVEOPT remains unadvertised and XCR0 unchanged",CAPABILITY);hb_cpuid_query(f.ctx,1,0,&a,&b,&c,&d);check_kind((c&(7u<<26))==(7u<<26),"existing XSAVE/OSXSAVE/AVX advertisement retained",CAPABILITY);
    hb_decoded_t decoded={0};hb_result_t result=hb_decode_x64(f.code+1,f.length-1,CODE+1,&decoded);
    if(!check_kind(result==HB_OK,"decode fully fetched known instruction",DECODE))goto done;
    /* Keep executing the same old-library byte stream after classification
     * mismatch; otherwise unavailable admission could conceal alias behavior. */
    check_kind(decoded.len==f.length-1&&(int)decoded.opcode==expected_opcode(spec),"full instruction length and exact admission classification",DECODE);
    f.decoder=hb_decoder_create(HB_ARCH_X64,f.code,f.length,CODE);if(!check(f.decoder!=NULL,"create decoder including leading NOP"))goto done;
    result=hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift typed fault or ordinary instruction",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!check(f.jit||f.interp,"create runtime"))goto done;
    for(unsigned profile=0;profile<4;++profile)run_one(&f,profile);
    if(f.jit)check_kind(native_present(&f),"compiled native entry exists even for typed illegal instruction",EXECUTION);
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.ctx)hb_context_destroy(f.ctx);
}
static void alternate_decode_controls(void)
{
    for(unsigned op=0;op<2;++op)for(unsigned ea=0;ea<3;++ea){spec_t s={op?"CLWB":"PTWRITE",op?CLWB:PTWRITE,op?0x66:0xf3,0,DECODE_ONLY,0};uint8_t code[16];size_t n=encode(&s,ea,code);hb_decoded_t d={0};snprintf(phase,sizeof(phase),"decode-only %s EA=%u",s.name,ea);++decode_controls;
        check_kind(hb_decode_x64(code+1,n-1,CODE+1,&d)==HB_OK&&d.len==n-1&&(int)d.opcode==expected_opcode(&s)&&d.op1.present&&d.op1.is_mem&&d.op1.size==(op?1:4),"distinct prefixed memory instruction retains classification and width",DECODE);}
    for(unsigned rex=0;rex<2;++rex){spec_t s={"PTWRITE register",PTWRITE,0xf3,rex,DECODE_ONLY,0};uint8_t code[16];size_t n=encode(&s,3,code);hb_decoded_t d={0};snprintf(phase,sizeof(phase),"decode-only PTWRITE register REX.W=%u",rex);++decode_controls;
        check_kind(hb_decode_x64(code+1,n-1,CODE+1,&d)==HB_OK&&d.len==n-1&&d.opcode==HB_INS_PTWRITE&&d.op1.present&&d.op1.is_reg&&d.op1.size==(rex?8:4),"early PTWRITE register branch remains distinct",DECODE);}
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
    alternate_decode_controls();for(unsigned backend=0;backend<2;++backend)for(unsigned s=0;s<sizeof(specs)/sizeof(specs[0]);++s)for(unsigned ea=0;ea<(specs[s].op==GETBV?1u:3u);++ea)run_form(&specs[s],ea,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_xstate_admission_test: %u executions (%u expected illegal, %u expected GP, %u expected completions), %u decode-only controls, %u checks, %u failures\n",executions,illegal_cases,gp_cases,completed_cases,decode_controls,checks,failures);
    printf("failure categories: state=%u execution=%u host=%u memory=%u decode=%u capability=%u\n",category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[MEMORY],category_failures[DECODE],category_failures[CAPABILITY]);return failures?1:0;
}
