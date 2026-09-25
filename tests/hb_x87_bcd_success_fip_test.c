/* M38 preparation: completed FBLD/FBSTP record their own instruction address.
 * A leading NOP is separate, so the BCD instruction begins at code+1.
 * x64 high-code controls assert inherited uint32 FIP truncation, not full
 * architectural FIP width. Failed-operation FIP retention is engine policy;
 * no general fault-time, partial-write rollback or deferred #MF claim.
 * Numeric BCD breadth remains in M18/M19; these are compact independent values.
 * FNSTENV28 checks existing low32 FIP transport, not FDP/FOP/selector state. */
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
enum { NORMAL,TRANSPORT,LOAD_OVERFLOW_MASKED,STORE_INVALID_MASKED,STORE_EMPTY_MASKED,STORE_FRACTION,
       LOAD_DENIED,LOAD_TRUNCATED,LOAD_OVERFLOW_UNMASKED,STORE_DENIED,STORE_TRUNCATED,STORE_INVALID_UNMASKED,STORE_EMPTY_UNMASKED };
enum { FIP,X87_STATE,STATE,MEMORY,EXECUTION,HOST,DECODE,CATEGORIES };
static const uint64_t LOW_CODE=UINT64_C(0x6800000),HIGH_CODE=UINT64_C(0x106800000),DATA=UINT64_C(0x6810000),ENV=UINT64_C(0x6820000);
static unsigned checks,failures,executions,normal_cases,masked_cases,transport_cases,failure_cases,high_code_cases;
static unsigned category_failures[CATEGORIES];
static char phase[200]="setup";
static int ck(int ok,const char *what,unsigned kind)
{++checks;if(!ok){++failures;++category_failures[kind];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(i*8));}
static uint32_t get32(const uint8_t *p){uint32_t n=0;for(unsigned i=0;i<4;++i)n|=(uint32_t)p[i]<<(8*i);return n;}
static int failed(unsigned k){return k>=LOAD_DENIED;}
static int memfail(unsigned k){return k==LOAD_DENIED||k==LOAD_TRUNCATED||k==STORE_DENIED||k==STORE_TRUNCATED;}
static int truncated(unsigned k){return k==LOAD_TRUNCATED||k==STORE_TRUNCATED;}
static int invalid(unsigned k){return k==STORE_INVALID_MASKED||k==STORE_INVALID_UNMASKED;}
static int empty(unsigned k){return k==STORE_EMPTY_MASKED||k==STORE_EMPTY_UNMASKED;}
typedef struct {uint16_t se;uint64_t sig,preview;unsigned tag;uint8_t bcd[10];} sample_t;
static const sample_t samples[]={
    {0x4001,UINT64_C(0xe000000000000000),UINT64_C(0x401c000000000000),0,{7}},
    {0xc001,UINT64_C(0xe000000000000000),UINT64_C(0xc01c000000000000),0,{7,0,0,0,0,0,0,0,0,0x80}},
    {0,0,0,1,{0}},
    {0x8000,0,UINT64_C(0x8000000000000000),1,{0,0,0,0,0,0,0,0,0,0x80}}
};
static void install(hb_x87_state_t *x,unsigned p,const sample_t *v)
{memcpy(&x->st[p],&v->preview,8);put64(x->st_ext[p],v->sig);put16(x->st_ext[p]+8,v->se);x->st_ext_valid|=(uint8_t)(1u<<p);x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*p)))|(v->tag<<(2*p)));}
typedef struct {hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;uint64_t code;unsigned store,kind,len;uint8_t bytes[5];} fixture_t;
static int seed(fixture_t *f,unsigned top,unsigned profile,unsigned sentinel,uint64_t address,uint8_t before_mem[26])
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));memset(&c->x87_64,0x56,sizeof(c->x87_64));hb_x87_state_t *x=hb_context_x87(c);memset(x,0,sizeof(*x));
    x->top=top;x->control_word=(uint16_t)(0x037f|((top&3)<<10));x->status_word=(uint16_t)((top<<11)|0x4724|((top&1)?0x40:0));x->last_x87_ip=sentinel?0xfedcba98u:0x12345678u;
    for(unsigned p=0;p<8;++p){sample_t v={0x4002,UINT64_C(0x8000000000000000)+(uint64_t)p*UINT64_C(0x0800000000000000),UINT64_C(0x4020000000000000)+(uint64_t)p*UINT64_C(0x0001000000000000),0,{0}};install(x,p,&v);}
    if(!f->store&&f->kind!=LOAD_OVERFLOW_MASKED&&f->kind!=LOAD_OVERFLOW_UNMASKED)x->tag_word|=(uint16_t)(3u<<(2*((top+7)&7)));
    if(f->store){install(x,top,&samples[profile]);if(invalid(f->kind)){const sample_t q={0x7fff,UINT64_C(0xc000000000000000),UINT64_C(0x7ff8000000000000),2,{0}};install(x,top,&q);}if(empty(f->kind))x->tag_word|=(uint16_t)(3u<<(2*top));
        if(f->kind==STORE_FRACTION){const sample_t v={0x3fff,UINT64_C(0xc000000000000000),UINT64_C(0x3ff8000000000000),0,{0}};install(x,top,&v);}}
    if(f->kind==LOAD_OVERFLOW_UNMASKED||f->kind==STORE_INVALID_UNMASKED||f->kind==STORE_EMPTY_UNMASKED)x->control_word&=(uint16_t)~1u;
    if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)f->code;c->regs.x86.ecx=(uint32_t)address;c->regs.x86.edx=(uint32_t)ENV;}else{c->regs.x64.rip=f->code;c->regs.x64.rcx=address;c->regs.x64.rdx=ENV;}
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.sf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;c->pc=f->code;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr=0;c->last_fault_addr_valid=0;c->last_fault_pc=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
    if(!ck(hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned data permissions",MEMORY))return 0;
    memset(before_mem,0xa5,26);if(!f->store)memcpy(before_mem+8,samples[profile].bcd,truncated(f->kind)?5:10);
    if(!ck(hb_memory_write(c->memory,address-8,before_mem,truncated(f->kind)?13:26)==HB_OK,"seed input/output and guards",MEMORY))return 0;
    uint8_t env[32];memset(env,0x79,sizeof(env));if(!ck(hb_memory_write(c->memory,ENV,env,sizeof(env))==HB_OK,"seed environment guard",MEMORY))return 0;
    if(f->kind==LOAD_DENIED||f->kind==STORE_DENIED)if(!ck(hb_memory_protect(c->memory,DATA,PAGE_BYTES,f->store?HB_PERM_READ:HB_PERM_WRITE)==HB_OK,"deny isolated BCD access",MEMORY))return 0;
    return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,unsigned profile)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *e=hb_context_x87(&expected),*x=hb_context_x87(f->ctx);unsigned p=e->top;
    if(!failed(f->kind)){
        e->last_x87_ip=(uint32_t)(f->code+1);
        if(!f->store){p=(p+7)&7;e->top=p;e->status_word=(uint16_t)((e->status_word&~0x3800u)|(p<<11));
            if(f->kind==LOAD_OVERFLOW_MASKED){uint64_t bits=UINT64_C(0xfff8000000000000);memcpy(&e->st[p],&bits,8);e->st_ext_valid&=(uint8_t)~(1u<<p);e->tag_word=(uint16_t)((e->tag_word&~(3u<<(2*p)))|(2u<<(2*p)));e->status_word|=0x0241u;}
            else{e->status_word&=(uint16_t)~0x0200u;install(e,p,&samples[profile]);}
        }else{
            e->status_word&=(uint16_t)~0x0200u;if(invalid(f->kind)||empty(f->kind))e->status_word|=(uint16_t)(1u|(empty(f->kind)?0x40u:0));
            if(f->kind==STORE_FRACTION){e->status_word|=0x0020u;if((p&3)==0||(p&3)==2)e->status_word|=0x0200u;}
            e->tag_word|=(uint16_t)(3u<<(2*p));e->top=(p+1)&7;e->status_word=(uint16_t)((e->status_word&~0x3800u)|(e->top<<11));
        }
        if(f->kind==TRANSPORT)e->control_word|=0x003fu;
    }else if(f->kind==LOAD_OVERFLOW_UNMASKED)e->status_word|=0x82c1u;
    else if(f->kind==STORE_INVALID_UNMASKED||f->kind==STORE_EMPTY_UNMASKED)e->status_word=(uint16_t)((e->status_word&~0x0200u)|0x8081u|(empty(f->kind)?0x40u:0));
    ck(x->last_x87_ip==e->last_x87_ip,failed(f->kind)?"error FIP retention: compatibility policy":"completed BCD FIP including inherited uint32 truncation",FIP);
    ck(!memcmp(x,e,sizeof(*x)),"full x87 raw/cache/preview, status, tags, TOP and FIP",X87_STATE);
    if(f->ctx->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    ck(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"unrelated GPR/XMM and stored flags",STATE);
    if(f->ctx->arch==HB_ARCH_X86)ck(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state",STATE);
    ck(!memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags))&&!memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"integer and lazy flags",STATE);
    ck(f->ctx->mxcsr==before->mxcsr&&!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi))&&!memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(f->ctx->k,before->k,sizeof(before->k))&&!memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"MXCSR and upper vectors",STATE);
    ck(f->ctx->fs_base==before->fs_base&&f->ctx->gs_base==before->gs_base&&f->ctx->seg_cs==before->seg_cs&&f->ctx->seg_ds==before->seg_ds&&f->ctx->seg_es==before->seg_es&&f->ctx->seg_fs==before->seg_fs&&f->ctx->seg_gs==before->seg_gs&&f->ctx->seg_ss==before->seg_ss,"segments unchanged",STATE);
}
static void run_case(fixture_t *f,unsigned top,unsigned profile,unsigned host,unsigned sentinel)
{
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};uint64_t address=truncated(f->kind)?DATA+PAGE_BYTES-5:DATA+64;uint8_t expected_mem[26];
    snprintf(phase,sizeof(phase),"%s %s %s code=%llx kind=%u TOP=%u value=%u host=%u sentinel=%u",f->ctx->arch==HB_ARCH_X86?"x86":"x64",f->jit?"JIT":"interp",f->store?"FBSTP":"FBLD",(unsigned long long)f->code,f->kind,top,profile,host,sentinel);
    if(!seed(f,top,profile,sentinel,address,expected_mem))return;hb_context_t before;memcpy(&before,f->ctx,sizeof(before));
    if(!ck(fesetround(modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv",HOST))return;
    int wanted=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);int got_rc=fegetround(),got_flags=fetestexcept(FE_ALL_EXCEPT);++executions;
    if(f->code==HIGH_CODE)++high_code_cases;if(f->kind==NORMAL)++normal_cases;else if(f->kind==TRANSPORT)++transport_cases;else if(failed(f->kind))++failure_cases;else ++masked_cases;
    ck(got_rc==modes[host]&&got_flags==wanted,"host RC/status preserved",HOST);
    hb_result_t wanted_result=memfail(f->kind)?HB_ERR_MEMORY_FAULT:failed(f->kind)?HB_ERR_EXEC_FAULT:HB_OK;
    if(wanted_result==HB_OK)ck(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->ctx->pc==f->code+f->len,"actual completed guest operation",EXECUTION);
    else ck((result==HB_OK||result==wanted_result)&&out.result==wanted_result&&out.faulted&&!out.timed_out,"existing isolated operation error",EXECUTION);
    check_state(f,&before,profile);
    if(!ck(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore data for memory oracle",MEMORY))return;
    if(f->store&&!failed(f->kind)){
        if(invalid(f->kind)||empty(f->kind)){static const uint8_t indef[10]={0,0,0,0,0,0,0,0xc0,0xff,0xff};memcpy(expected_mem+8,indef,10);}
        else if(f->kind==STORE_FRACTION){memset(expected_mem+8,0,10);expected_mem[8]=(top&3)==0||(top&3)==2?2:1;}
        else memcpy(expected_mem+8,samples[profile].bcd,10);
    }
    uint8_t actual[26];size_t n=truncated(f->kind)?13:26;
    if(ck(hb_memory_read(f->ctx->memory,address-8,actual,n)==HB_OK,"read accessible operand window",MEMORY)){
        /* A late failing store may write its accessible prefix: no rollback claim. */
        ck(!memcmp(actual,expected_mem,f->kind==STORE_TRUNCATED?8:n),"operand bytes and canaries within completion/fault contract",MEMORY);
    }
    uint8_t env[32];if(ck(hb_memory_read(f->ctx->memory,ENV,env,sizeof(env))==HB_OK,"read environment output",MEMORY)){
        if(f->kind==TRANSPORT){ck(get32(env+12)==(uint32_t)(f->code+1),"FNSTENV transports completed BCD low32 FIP",FIP);ck(env[28]==0x79&&env[29]==0x79&&env[30]==0x79&&env[31]==0x79,"FNSTENV exact footprint guard",MEMORY);}
        else{uint8_t untouched[32];memset(untouched,0x79,sizeof(untouched));ck(!memcmp(env,untouched,sizeof(env)),"unused environment unchanged",MEMORY);}
    }
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==f->code&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_form(hb_arch_t arch,hb_backend_t backend,unsigned high,unsigned store,unsigned kind)
{
    fixture_t f={0};f.code=high?HIGH_CODE:LOW_CODE;f.store=store;f.kind=kind;f.bytes[0]=0x90;f.bytes[1]=0xdf;f.bytes[2]=store?0x31:0x21;f.len=3;if(kind==TRANSPORT){f.bytes[3]=0xd9;f.bytes[4]=0x32;f.len=5;}
    f.ctx=hb_context_create(arch,backend);if(!ck(f.ctx!=NULL,"create context",STATE))goto done;f.ctx->memory=hb_memory_create(0);if(!ck(f.ctx->memory!=NULL,"create private memory",STATE))goto done;
    uint64_t pages[]={f.code,DATA,ENV};for(unsigned i=0;i<3;++i)if(!ck(hb_memory_map_private(f.ctx->memory,pages[i],PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned page",MEMORY))goto done;
    if(!ck(hb_memory_write(f.ctx->memory,f.code,f.bytes,f.len)==HB_OK&&hb_memory_protect(f.ctx->memory,f.code,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"install bounded code",MEMORY))goto done;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(f.bytes+1,2,f.code+1,&d):hb_decode_x64(f.bytes+1,2,f.code+1,&d);
    ck(r==HB_OK&&d.len==2&&d.opcode==(store?HB_INS_X87_FBSTP:HB_INS_X87_FBLD)&&d.op1.present&&d.op1.is_mem&&d.op1.size==10,"exact BCD opcode/read-store width",DECODE);
    f.decoder=hb_decoder_create(arch,f.bytes,f.len,f.code);if(!ck(f.decoder!=NULL,"create decoder",STATE))goto done;r=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);if(!ck(r==HB_OK&&f.func,"lift bounded sequence",EXECUTION))goto done;
    unsigned count=0;if(f.func->cfg)for(size_t b=0;b<f.func->cfg->block_count;++b)for(size_t i=0;i<f.func->cfg->blocks[b]->instr_count;++i){hb_ir_instr_t *ir=&f.func->cfg->blocks[b]->instrs[i];if(ir->op==(store?HB_IR_X87_FBSTP:HB_IR_X87_FBLD)){++count;hb_ir_operand_t *op=store?&ir->dst:&ir->src1;ck(ir->guest_addr==f.code+1&&op->type==HB_OP_MEM&&op->size==HB_SIZE_80,"BCD IR address and 80-bit operand",DECODE);}}
    ck(count==1,"one BCD operation after NOP",DECODE);if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);if(!ck(f.jit||f.interp,"create runtime",STATE))goto done;
    if(kind==NORMAL)for(unsigned top=0;top<8;++top)for(unsigned profile=0;profile<4;++profile)for(unsigned host=0;host<4;++host)for(unsigned sentinel=0;sentinel<2;++sentinel)run_case(&f,top,profile,host,sentinel);
    else if(kind==TRANSPORT)for(unsigned t=0;t<2;++t)for(unsigned profile=0;profile<4;++profile)for(unsigned host=0;host<4;++host)run_case(&f,t?7:0,profile,host,1);
    else for(unsigned t=0;t<(failed(kind)?2u:8u);++t)for(unsigned host=0;host<4;++host)run_case(&f,failed(kind)?(t?7:0):t,0,host,1);
    if(f.jit)ck(native_present(&f),"native entry present; interpreter-helper lowering allowed",EXECUTION);{uint8_t actual[5];ck(hb_memory_read(f.ctx->memory,f.code,actual,f.len)==HB_OK&&!memcmp(actual,f.bytes,f.len),"code unchanged",MEMORY);}
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.ctx)hb_context_destroy(f.ctx);
}
static const struct {const char *name;enum hb_gate_id id;const char *value;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM,"0"},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR,"0"},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64,"0"},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS,"0"},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED,"0"},{"MACRUNNER_HB_UNCHAIN_STATS",HB_GATE_HB_UNCHAIN_STATS,"0"}};
int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t count=0;int changed=0,host_saved=0;fenv_t original;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *s=getenv(gates[i].name);if(s&&!ck((saved[i]=strdup(s))!=NULL,"save gate",STATE))goto done;++count;}
    changed=1;for(size_t i=0;i<count;++i)if(!ck(setenv(gates[i].name,gates[i].value,1)==0,"select private helper policy",STATE))goto done;
    hb_env_refresh();for(size_t i=0;i<count;++i){const char *s=hb_gate(gates[i].id);if(!ck(s&&!strcmp(s,gates[i].value),"effective gate",STATE))goto done;}
    if(!ck(fegetenv(&original)==0,"save caller fenv",HOST))goto done;host_saved=1;fenv_t ignored;if(!ck(feholdexcept(&ignored)==0,"mask host traps",HOST))goto done;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned high=0;high<(arch?2u:1u);++high){hb_arch_t a=arch?HB_ARCH_X64:HB_ARCH_X86;hb_backend_t b=backend?HB_BACKEND_JIT:HB_BACKEND_INTERP;
        for(unsigned store=0;store<2;++store){run_form(a,b,high,store,NORMAL);run_form(a,b,high,store,TRANSPORT);}
        run_form(a,b,high,0,LOAD_OVERFLOW_MASKED);run_form(a,b,high,1,STORE_INVALID_MASKED);run_form(a,b,high,1,STORE_EMPTY_MASKED);run_form(a,b,high,1,STORE_FRACTION);
        for(unsigned kind=LOAD_DENIED;kind<=STORE_EMPTY_UNMASKED;++kind)run_form(a,b,high,kind>=STORE_DENIED,kind);
    }
    ck(executions==4560u&&normal_cases==3072u&&masked_cases==768u&&transport_cases==384u&&failure_cases==336u&&high_code_cases==1520u,"planned bounded actual execution counts",EXECUTION);
done:
    if(host_saved)ck(fesetenv(&original)==0,"restore caller fenv",HOST);if(changed){for(size_t i=0;i<count;++i)ck((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate",STATE);hb_env_refresh();for(size_t i=0;i<count;++i){const char *s=hb_gate(gates[i].id);ck(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate",STATE);}}
    for(size_t i=0;i<count;++i)free(saved[i]);
    printf("hb_x87_bcd_success_fip_test: %u executions (%u normal, %u masked, %u transport, %u failure compatibility; %u high-code subset), %u checks, %u failures\n",executions,normal_cases,masked_cases,transport_cases,failure_cases,high_code_cases,checks,failures);
    printf("failure categories: fip=%u x87_state=%u state=%u memory=%u execution=%u host=%u decode=%u\n",category_failures[FIP],category_failures[X87_STATE],category_failures[STATE],category_failures[MEMORY],category_failures[EXECUTION],category_failures[HOST],category_failures[DECODE]);return failures?1:0;
}
