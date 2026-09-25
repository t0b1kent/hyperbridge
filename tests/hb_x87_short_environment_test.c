/* Legacy protected-layout x87 environment formats, ordinary operand-size 66.
 * FLDENV/FNSTENV: 14 versus 28 bytes; FRSTOR/FNSAVE: 94 versus 108 bytes.
 * 4 operations * 2 sizes * 2 architectures * 2 backends * 80 cases = 2560.
 * Each form has 64 interior, 8 exact page-edge, 4 denied and 4 truncated cases.
 * No guest-16-bit mode, REX.W, address-size override, real/v8086 format,
 * deferred #MF, or complete FIP/FDP/FOP transport assertion. The post-FNSAVE
 * reset oracle deliberately does not prescribe raw register-data retention.
 * Failed owned-span accesses must preserve x87 state. A truncated write may
 * have written a prefix; no rollback of bytes inside that span is asserted.
 * Decoder width failures remain nonfatal so an old library still runs all
 * cases. Raw80 payloads, previews and tag classes are independent constants.
 */
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <fenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {PAGE_BYTES=16384,INTERIOR=0,EDGE,DENIED,TRUNCATED};
enum {LOAD_ENV=0,STORE_ENV,SAVE_STATE,RESTORE_STATE};
enum {DECODE,X87,STATE,MEMORY,EXECUTION,HOST,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x6800000),DATA=UINT64_C(0x7800000);
static unsigned checks,failures,executions,interior_cases,edge_cases,denied_cases,truncated_cases;
static unsigned category_failures[CATEGORIES];
static char phase[180]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;
    if(!ok){++failures;++category_failures[category];
        if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}
    return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void put64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(v>>(8*i));}
typedef struct {uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} raw_t;
/* Physical R0..R7, including precision beyond f64, signed zero, NaNs, a
 * denormal and finite values outside the f64 exponent range. */
static const raw_t physical[]={
    {UINT64_C(0x8000000000000400),0x4034,UINT64_C(0x4340000000000000),0},
    {0,0x8000,UINT64_C(0x8000000000000000),1},
    {UINT64_C(0xc000000000000123),0x7fff,UINT64_C(0x7ff8000000000000),2},
    {UINT64_C(0x8000000000000123),0x7fff,UINT64_C(0x7ff8000000000000),2},
    {1,0,0,2},
    {UINT64_C(0x8000000000000000),1,0,0},
    {UINT64_C(0x8000000000000000),0x7fff,UINT64_C(0x7ff0000000000000),2},
    {UINT64_C(0x8000000000000000),0x43ff,UINT64_C(0x7ff0000000000000),0}
};
static const uint16_t input_tags[]={0x5555,0x77dd,0xffff,0xaaaa};
static const uint16_t masks[]={0,1,0x20,0x3f};
static const char *names[]={"FLDENV","FNSTENV","FNSAVE","FRSTOR"};
typedef struct {
    hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;
    hb_interpreter_t *interp;hb_jit_runtime_t *jit;
    hb_arch_t arch;hb_backend_t backend;unsigned op,short_form;
    size_t header_bytes,image_bytes,code_bytes;
} fixture_t;
static int is_store(const fixture_t *f){return f->op==STORE_ENV || f->op==SAVE_STATE;}
static void raw_bytes(uint8_t out[10],unsigned p)
{
    put64(out,physical[p].sig);put16(out+8,physical[p].se);
}
static uint16_t classified_tags(uint16_t incoming)
{
    uint16_t result=0;
    for(unsigned p=0;p<8;++p){unsigned tag=((incoming>>(2*p))&3u)==3u?3u:physical[p].tag;
        result|=(uint16_t)(tag<<(2*p));}
    return result;
}
/* Independent per-flag ES/B oracle; SF does not count as a seventh cause. */
static uint16_t loaded_status(uint16_t sw,uint16_t cw)
{
    unsigned pending=0;
    for(unsigned b=0;b<6;++b)if((sw&(1u<<b)) && !(cw&(1u<<b)))pending=1;
    return (uint16_t)((sw&0x7f7fu)|(pending?0x8080u:0));
}
static void image_header(const fixture_t *f,uint8_t *image,uint16_t cw,uint16_t sw,uint16_t tags)
{
    put16(image,cw);put16(image+(f->short_form?2:4),sw);put16(image+(f->short_form?4:8),tags);
}
static void defined_header_mask(const fixture_t *f,uint8_t *mask)
{
    unsigned sw=f->short_form?2:4,tw=f->short_form?4:8;
    mask[0]=mask[1]=mask[sw]=mask[sw+1]=mask[tw]=mask[tw+1]=1;
}
static int seed(fixture_t *f,unsigned top,unsigned profile,uint64_t address,uint16_t cw)
{
    hb_context_t *c=f->ctx;memset(&c->regs,0x3c,sizeof(c->regs));
    if(f->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)address;c->regs.x86.eip=(uint32_t)CODE;
        c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rcx=address;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);
    x->top=top;x->control_word=is_store(f)?cw:0x037f;
    /* Store controls have no pending unmasked exception on entry. */
    x->status_word=(uint16_t)((top<<11)|((profile&7u)<<8)|((profile&1u)<<14)|
                              ((profile&1u)?0x40u:0)|(x->control_word&0x21u));
    x->last_x87_ip=0x12345678;
    for(unsigned p=0;p<8;++p){unsigned source=f->op==RESTORE_STATE?(p+3)&7u:p;
        uint8_t raw[10];raw_bytes(raw,source);
        if(!check(hb_x87_set_st_ext80(x,(p+8-top)&7u,raw,
                  ((input_tags[profile&3u]>>(2*p))&3u)!=3u)==HB_OK,"seed physical raw80 state"))return 0;}
    /* Optional uncached zero/Inf fallbacks preserve the independent raw class
     * and payload; do not discard a precision-bearing raw80 cache entry. */
    if((profile&4u) && f->op!=RESTORE_STATE)x->st_ext_valid&=0xbdu;
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));
    memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));
    memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};
    memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;
    c->fs_base=0x11110000;c->gs_base=0x22220000;
    c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
    c->step_limit=8;c->block_limit=2;return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,uint16_t cw,uint16_t sw,
                        uint16_t tags,unsigned access)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));
    hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    if(access<DENIED){
        if(f->op==SAVE_STATE){
            /* The reset's data-register lifetime is a separate contract. */
            memcpy(e,x,sizeof(*e));e->control_word=0x037f;e->status_word=0;e->tag_word=0xffff;e->top=0;
        } else if(f->op==STORE_ENV)e->control_word|=0x003f;
        else {
            e->control_word=cw;e->status_word=loaded_status(sw,cw);e->top=(sw>>11)&7u;
            e->tag_word=classified_tags(tags);
            if(f->op==RESTORE_STATE){
                for(unsigned p=0;p<8;++p){uint8_t raw[10];raw_bytes(raw,p);
                    memcpy(e->st_ext[p],raw,10);memcpy(&e->st[p],&physical[p].preview,8);}
                e->st_ext_valid=0xff;
            }
            /* Full pointer/opcode loading remains outside this fixture. */
            e->last_x87_ip=x->last_x87_ip;
        }
    }
    check_kind(!memcmp(x,e,sizeof(*x)),access<DENIED?
               "CW/SW/tag/TOP and bounded payload/cache effects":"failed access preserves full x87 state",X87);
    if(f->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;
    else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and register state preserved");
    if(f->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr && !memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags)) &&
          !memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi)) &&
          !memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi)) &&
          !memcmp(f->ctx->k,before->k,sizeof(before->k)) &&
          !memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext)) &&
          !memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext)) &&
          !memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"upper vectors and opmasks preserved");
    check(f->ctx->fs_base==before->fs_base && f->ctx->gs_base==before->gs_base &&
          f->ctx->seg_cs==before->seg_cs && f->ctx->seg_ds==before->seg_ds && f->ctx->seg_es==before->seg_es &&
          f->ctx->seg_fs==before->seg_fs && f->ctx->seg_gs==before->seg_gs && f->ctx->seg_ss==before->seg_ss,
          "segment state preserved");
}
static void run_one(fixture_t *f,unsigned top,unsigned profile,unsigned access)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    uint8_t expected[160],actual[160],mask[160];hb_context_t before;
    uint16_t cw=(uint16_t)(0x0340u|((profile&3u)<<10)|masks[profile&3u]);
    unsigned conditions=(top+profile)&15u,esb=(profile>>1)&3u;
    uint16_t sw=(uint16_t)(((profile&1u)?0x3fu:0x20u)|((profile&4u)?0x40u:0)|
                         (top<<11)|((conditions&7u)<<8)|((conditions&8u)<<11)|
                         ((esb&1u)?0x80u:0)|((esb&2u)?0x8000u:0));
    uint16_t tags=input_tags[profile&3u];unsigned host=(top+profile)&3u;
    size_t available=f->image_bytes-(access==TRUNCATED?1:0);
    uint64_t address=(access==EDGE || access==TRUNCATED)?DATA+PAGE_BYTES-available:DATA+128;
    uint64_t guard=address-16;size_t count=(access==EDGE || access==TRUNCATED)?16+available:sizeof(expected);
    snprintf(phase,sizeof(phase),"%s %s %s%zu TOP=%u profile=%u access=%u",
             f->arch==HB_ARCH_X86?"x86":"x64",f->backend==HB_BACKEND_JIT?"JIT":"interp",
             names[f->op],f->image_bytes,top,profile,access);
    memset(expected,0xa5,sizeof(expected));memset(mask,1,sizeof(mask));
    if(!is_store(f)){
        uint8_t image[108];memset(image,0x6c,sizeof(image));image_header(f,image,cw,sw,tags);
        if(f->op==RESTORE_STATE)for(unsigned i=0;i<8;++i)raw_bytes(image+f->header_bytes+10*i,(top+i)&7u);
        memcpy(expected+16,image,available);
    }
    if(!check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f->ctx->memory,guard,expected,count)==HB_OK,"seed owned data and guards"))return;
    if(!seed(f,is_store(f)?top:(top+3)&7u,profile,address,cw))return;
    if(access==DENIED && !check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,
                   is_store(f)?HB_PERM_READ:HB_PERM_WRITE)==HB_OK,"deny required data permission"))return;
    memcpy(&before,f->ctx,sizeof(before));
    if(is_store(f) && access<DENIED){
        const hb_x87_state_t *x=hb_context_x87(&before);
        uint16_t saved_sw=(uint16_t)((x->status_word&~0x3800u)|(x->top<<11));
        image_header(f,expected+16,x->control_word,saved_sw,x->tag_word);
        memset(mask+16,0,f->header_bytes);defined_header_mask(f,mask+16);
        if(f->op==SAVE_STATE)for(unsigned i=0;i<8;++i)raw_bytes(expected+16+f->header_bytes+10*i,(top+i)&7u);
    } else if(is_store(f) && access==TRUNCATED)memset(mask+16,0,available);
    if(!check_kind(fesetround(host_modes[host])==0 && feclearexcept(FE_ALL_EXCEPT)==0 &&
                   feraiseexcept(FE_INVALID|FE_INEXACT)==0,"seed masked host fenv",HOST))goto restore;
    int host_flags=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};
    hb_result_t r=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_round=fegetround(),actual_flags=fetestexcept(FE_ALL_EXCEPT);
    ++executions;if(access==INTERIOR)++interior_cases;else if(access==EDGE)++edge_cases;
    else if(access==DENIED)++denied_cases;else ++truncated_cases;
    check_kind(actual_round==host_modes[host] && actual_flags==host_flags,"host rounding and flags preserved",HOST);
    if(access<DENIED)check_kind(r==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out &&
                               out.steps_executed && out.blocks_executed && f->ctx->pc==CODE+f->code_bytes,
                               "exact environment operation completes",EXECUTION);
    else check_kind((r==HB_OK || r==HB_ERR_MEMORY_FAULT) && out.result==HB_ERR_MEMORY_FAULT &&
                    out.faulted && !out.timed_out,"denied/truncated image reports memory fault",EXECUTION);
    check_state(f,&before,cw,sw,tags,access);
restore:
    check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned permissions");
    if(check_kind(hb_memory_read(f->ctx->memory,guard,actual,count)==HB_OK,"read owned image and guards",MEMORY)){
        int equal=1;for(size_t i=0;i<count;++i)if(mask[i] && actual[i]!=expected[i])equal=0;
        check_kind(equal,is_store(f) && access<DENIED?
                   "saved old CW/SW/TW, logical payload slots and exact-footprint canaries":
                   "input/denied-write bytes or truncated-write outside-span guards preserved",MEMORY);
    }
}
static int native_present(const hb_jit_runtime_t *jit)
{
    if(!jit || !jit->block_cache)return 0;
    for(size_t i=0;i<jit->block_cache->size;++i){const hb_block_cache_entry_t *e=&jit->block_cache->entries[i];
        if(e->valid && e->guest_addr==CODE && e->native_code && e->native_size)return 1;}
    return 0;
}
static void run_fixture(hb_arch_t arch,hb_backend_t backend,unsigned op,unsigned short_form)
{
    fixture_t f={.arch=arch,.backend=backend,.op=op,.short_form=short_form};
    uint8_t code[3];size_t n=0;if(short_form)code[n++]=0x66;
    code[n++]=(op==SAVE_STATE || op==RESTORE_STATE)?0xdd:0xd9;
    code[n++]=(op==STORE_ENV || op==SAVE_STATE)?0x31:0x21;
    f.code_bytes=n;f.header_bytes=short_form?14:28;
    f.image_bytes=f.header_bytes+((op==SAVE_STATE || op==RESTORE_STATE)?80:0);
    snprintf(phase,sizeof(phase),"%s %s %s%zu setup",arch==HB_ARCH_X86?"x86":"x64",
             backend==HB_BACKEND_JIT?"JIT":"interp",names[op],f.image_bytes);
    f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create context"))goto done;
    f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory && hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f.ctx->memory,CODE,code,n)==HB_OK &&
              hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK &&
              hb_memory_map_private(f.ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,
              "map isolated code and single data page"))goto done;
    hb_decoded_t d={0};hb_result_t decoded=arch==HB_ARCH_X86?
        hb_decode_x86(code,n,CODE,&d):hb_decode_x64(code,n,CODE,&d);
    if(!check_kind(decoded==HB_OK,"decode instruction",DECODE))goto done;
    check_kind(d.len==n,"decoded length includes ordinary 66 prefix",DECODE);
    check_kind(!memcmp(d.bytes,code,n),"decoded raw bytes match the exact fixture encoding",DECODE);
    check_kind(d.opcode==(op==LOAD_ENV?HB_INS_X87_FLDENV:op==STORE_ENV?HB_INS_X87_FNSTENV:
                         op==SAVE_STATE?HB_INS_X87_FNSAVE:HB_INS_X87_FRSTOR),"exact decoded operation",DECODE);
    check_kind(d.op1.size==f.image_bytes,"exact decoded image byte width",DECODE);
    f.decoder=hb_decoder_create(arch,code,n,CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    hb_result_t lifted=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);
    if(!check(lifted==HB_OK && f.func,"lift single environment operation"))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);
    if(!check(f.jit || f.interp,"create runtime"))goto done;
    for(unsigned top=0;top<8;++top)for(unsigned profile=0;profile<8;++profile)run_one(&f,top,profile,INTERIOR);
    for(unsigned top=0;top<8;++top)run_one(&f,top,top,EDGE);
    for(unsigned access=DENIED;access<=TRUNCATED;++access)for(unsigned profile=0;profile<4;++profile)
        run_one(&f,(profile+5)&7u,profile,access);
    if(f.jit)check_kind(native_present(f.jit),"JIT has native entry; helper execution allowed",EXECUTION);
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);
    if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);
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
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *v=getenv(gates[i].name);
        if(v && !check((saved[i]=strdup(v))!=NULL,"save gate value"))goto done;++saved_count;}
    changed=1;
    for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,"0",1)==0,"select helper memory"))goto done;
    hb_env_refresh();
    for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);if(!check(v && !strcmp(v,"0"),"effective helper gate"))goto done;}
    if(!check_kind(feholdexcept(&original_host)==0,"save and mask original host fenv",HOST))goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)
        for(unsigned op=0;op<4;++op)for(unsigned short_form=0;short_form<2;++short_form)
            run_fixture(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP,op,short_form);
    check_kind(executions==2560 && interior_cases==2048 && edge_cases==256 && denied_cases==128 && truncated_cases==128,
               "complete format/operation/mode/backend/access matrix",EXECUTION);
done:
    snprintf(phase,sizeof(phase),"cleanup");
    if(host_saved)check_kind(fesetenv(&original_host)==0,"restore original host fenv",HOST);
    if(changed){
        for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value/absence");
        hb_env_refresh();
        for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v && !strcmp(v,saved[i]):!v,"effective original gate restored");}
    }
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_short_environment_test: %u executions (%u interior, %u edge, %u denied, %u truncated), %u checks, %u failures\n",
           executions,interior_cases,edge_cases,denied_cases,truncated_cases,checks,failures);
    printf("failure categories: decode=%u x87=%u state=%u memory=%u execution=%u host=%u\n",
           category_failures[DECODE],category_failures[X87],category_failures[STATE],category_failures[MEMORY],
           category_failures[EXECUTION],category_failures[HOST]);
    return failures?1:0;
}
