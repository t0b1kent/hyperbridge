/* Raw FLDENV28 / FRSTOR108 loaded-status regression.
 * ES/B are derived from six loaded exception flags and CW masks. SF is not a
 * seventh exception. Main matrix: 64 flags * 64 masks * 4 incoming ES/B *
 * 2 instructions * 2 architectures * 2 backends = 131072 loads.
 * No pending-on-entry/deferred #MF, 14/94-byte formats, FXRSTOR normalization
 * or new FIP/FDP/FOP claim. Failed-read atomicity is the existing engine
 * guarantee for owned spans, not arbitrary architectural fault rollback.
 * Raw payload and preview constants are independent of production converters.
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

enum {PAGE_BYTES=16384,READABLE=0,NO_READ,TRUNCATED};
enum {STATUS,X87,STATE,MEMORY,EXECUTION,HOST,CATEGORIES};
enum {MAIN_CASE,SF_CASE,MEMORY_CASE};
static const uint64_t CODE=UINT64_C(0x5600000),DATA=UINT64_C(0x6600000);
static unsigned checks,failures,executions,main_loads,sf_controls,memory_controls;
static unsigned category_failures[CATEGORIES];
static char phase[200]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;
    if(!ok) {++failures;++category_failures[category];
        if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}
    return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void put64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(v>>(8*i));}
typedef struct {uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} raw_t;
/* Physical R0..R7. Exact ext80 data, nearest-even binary64 previews and full
 * tags are explicit fixture constants, including values outside f64 range. */
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
static const uint16_t incoming_tags[]={0x5555,0x77dd,0xffff,0xaaaa};
typedef struct {
    hb_context_t *ctx;hb_decoder_t *decoder;hb_ir_func_t *func;
    hb_interpreter_t *interp;hb_jit_runtime_t *jit;
    hb_arch_t arch;hb_backend_t backend;unsigned restore;
} fixture_t;

static void raw_bytes(uint8_t out[10],unsigned physical_index)
{
    put64(out,physical[physical_index].sig);put16(out+8,physical[physical_index].se);
}
static uint16_t classified_tags(uint16_t incoming)
{
    uint16_t result=0;
    for(unsigned p=0;p<8;++p) {
        unsigned tag=((incoming>>(2*p))&3u)==3u?3u:physical[p].tag;
        result|=(uint16_t)(tag<<(2*p));
    }
    return result;
}
/* Deliberately use a per-flag oracle instead of the production bit formula. */
static uint16_t expected_status(uint16_t sw,uint16_t cw)
{
    unsigned pending=0;
    for(unsigned bit=0;bit<6;++bit)
        if((sw&(1u<<bit)) && !(cw&(1u<<bit)))pending=1;
    return (uint16_t)((sw&0x7f7fu)|(pending?0x8080u:0));
}
static int seed(fixture_t *f,unsigned old_top,unsigned uncached,uint64_t address)
{
    hb_context_t *c=f->ctx;
    memset(&c->regs,0x3c,sizeof(c->regs));
    if(f->arch==HB_ARCH_X86) {
        c->regs.x86.ecx=(uint32_t)address;c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;
        memset(&c->x87_64,0x49,sizeof(c->x87_64));
    } else {c->regs.x64.rcx=address;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);
    x->top=old_top;x->control_word=0x037f;x->status_word=(uint16_t)((old_top<<11)|0x0241);
    x->last_x87_ip=0x12345678;
    for(unsigned p=0;p<8;++p) {
        /* Restore input differs from the old physical file. */
        unsigned source=f->restore?(p+3)&7:p;
        uint8_t raw[10];raw_bytes(raw,source);
        if(!check(hb_x87_set_st_ext80(x,(p+8-old_top)&7,raw,(0x5au&(1u<<p))!=0)==HB_OK,
                  "seed independent physical raw80 state"))return 0;
    }
    /* For FLDENV, zero/Inf fallback classification agrees with the independent
     * raw tags, but the precise old cache-valid pattern must remain unchanged. */
    if(uncached && !f->restore)x->st_ext_valid&=0xbdu;
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));
    memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));
    memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};
    memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x5fa1;c->pc=CODE;c->last_result=HB_OK;
    c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;
    c->fs_base=0x11110000;c->gs_base=0x22220000;
    c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
    c->step_limit=8;c->block_limit=2;
    return 1;
}
static void check_state(fixture_t *f,const hb_context_t *before,uint16_t cw,
                        uint16_t sw,uint16_t tags,unsigned access)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));
    hb_x87_state_t *x=hb_context_x87(f->ctx),*e=hb_context_x87(&expected);
    if(access==READABLE) {
        e->control_word=cw;e->status_word=expected_status(sw,cw);
        e->top=(sw>>11)&7u;e->tag_word=classified_tags(tags);
        if(f->restore) {
            for(unsigned p=0;p<8;++p) {
                uint8_t raw[10];raw_bytes(raw,p);
                memcpy(e->st_ext[p],raw,10);memcpy(&e->st[p],&physical[p].preview,8);
            }
            e->st_ext_valid=0xff;
        }
        /* Successful environment metadata restoration remains a separate task. */
        e->last_x87_ip=x->last_x87_ip;
    }
    check_kind(x->status_word==e->status_word,
               access==READABLE?"all loaded SW bits and normalized ES/B":"failed read preserves original SW",STATUS);
    /* The separate status assertion above owns that result; avoid duplicate
     * failures hiding raw/cache/tag or unrelated-state defects in the summary. */
    e->status_word=x->status_word;
    check_kind(!memcmp(x,e,sizeof(*x)),access==READABLE?
               "loaded CW/TOP/tags and exact raw/preview/cache state":"failed read preserves full remaining x87 state",X87);
    if(f->arch==HB_ARCH_X86)expected.regs.x86.eip=f->ctx->regs.x86.eip;
    else expected.regs.x64.rip=f->ctx->regs.x64.rip;
    check(!memcmp(&f->ctx->regs,&expected.regs,sizeof(expected.regs)),"GPR/XMM and mode-specific register file preserved");
    if(f->arch==HB_ARCH_X86)check(!memcmp(&f->ctx->x87_64,&before->x87_64,sizeof(before->x87_64)),"inactive x64 x87 state preserved");
    check(f->ctx->mxcsr==before->mxcsr && !memcmp(&f->ctx->flags,&before->flags,sizeof(before->flags)) &&
          !memcmp(&f->ctx->lazy_flags,&before->lazy_flags,sizeof(before->lazy_flags)),"MXCSR and integer flags preserved");
    check(!memcmp(f->ctx->ymm_hi,before->ymm_hi,sizeof(before->ymm_hi)) &&
          !memcmp(f->ctx->zmm_hi,before->zmm_hi,sizeof(before->zmm_hi)) &&
          !memcmp(f->ctx->k,before->k,sizeof(before->k)) &&
          !memcmp(f->ctx->xmm_ext,before->xmm_ext,sizeof(before->xmm_ext)) &&
          !memcmp(f->ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(before->ymm_hi_ext)) &&
          !memcmp(f->ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(before->zmm_hi_ext)),
          "upper vectors and opmasks preserved");
    check(f->ctx->fs_base==before->fs_base && f->ctx->gs_base==before->gs_base &&
          f->ctx->seg_cs==before->seg_cs && f->ctx->seg_ds==before->seg_ds &&
          f->ctx->seg_es==before->seg_es && f->ctx->seg_fs==before->seg_fs &&
          f->ctx->seg_gs==before->seg_gs && f->ctx->seg_ss==before->seg_ss,"segment state preserved");
}
static void run_one(fixture_t *f,unsigned flags,unsigned masks,unsigned esb,
                    unsigned sf,unsigned access,unsigned kind)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    uint8_t image[108],expected_memory[160],actual_memory[160];hb_context_t before;
    unsigned top=(flags^masks^esb)&7u,old_top=(top+3)&7u,host=(flags+masks+esb)&3u;
    unsigned condition=(flags^(masks>>2)^esb)&15u;
    uint16_t cw=(uint16_t)(0x0340u|(((flags+masks)&3u)<<10)|masks);
    uint16_t sw=(uint16_t)(flags|(sf?0x0040u:0)|(top<<11)|((condition&7u)<<8)|((condition&8u)<<11)|
                          ((esb&1u)?0x0080u:0)|((esb&2u)?0x8000u:0));
    uint16_t tags=incoming_tags[(flags+masks+esb)&3u];
    size_t image_size=f->restore?108:28;
    uint64_t guard=access==TRUNCATED?DATA+PAGE_BYTES-32:DATA+112;
    size_t count=access==TRUNCATED?32:sizeof(expected_memory);
    snprintf(phase,sizeof(phase),"%s %s %s flags=%02x masks=%02x ESB=%u SF=%u TOP=%u access=%u",
             f->arch==HB_ARCH_X86?"x86":"x64",f->backend==HB_BACKEND_JIT?"JIT":"interp",
             f->restore?"FRSTOR108":"FLDENV28",flags,masks,esb,sf,top,access);
    memset(image,0x6c,sizeof(image));put16(image,cw);put16(image+4,sw);put16(image+8,tags);
    if(f->restore)for(unsigned i=0;i<8;++i)raw_bytes(image+28+10*i,(top+i)&7u);
    memset(expected_memory,0xa5,sizeof(expected_memory));
    memcpy(expected_memory+16,image,access==TRUNCATED?16:image_size);
    if(!check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f->ctx->memory,guard,expected_memory,count)==HB_OK,"seed owned input and guards"))return;
    if(!seed(f,old_top,(flags^masks)&1u,guard+16))return;
    if(access==NO_READ && !check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_WRITE)==HB_OK,
                                "deny source reads"))return;
    memcpy(&before,f->ctx,sizeof(before));
    if(!check_kind(fesetround(host_modes[host])==0 && feclearexcept(FE_ALL_EXCEPT)==0 &&
                   feraiseexcept(FE_INVALID|FE_INEXACT)==0,"seed masked host fenv",HOST))goto restore;
    int host_status=fetestexcept(FE_ALL_EXCEPT);
    hb_exec_result_t out={0};
    hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int actual_round=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);
    ++executions;if(kind==MAIN_CASE)++main_loads;else if(kind==SF_CASE)++sf_controls;else ++memory_controls;
    check_kind(actual_round==host_modes[host] && actual_status==host_status,"host rounding and status preserved",HOST);
    if(access==READABLE)check_kind(result==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out &&
                                  out.steps_executed && out.blocks_executed && f->ctx->pc==CODE+2,
                                  "single legacy load completes; deferred delivery excluded",EXECUTION);
    else check_kind((result==HB_OK || result==HB_ERR_MEMORY_FAULT) && out.result==HB_ERR_MEMORY_FAULT &&
                    out.faulted && !out.timed_out,"denied/truncated input returns memory fault",EXECUTION);
    check_state(f,&before,cw,sw,tags,access);
restore:
    check(hb_memory_protect(f->ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned permissions");
    check_kind(hb_memory_read(f->ctx->memory,guard,actual_memory,count)==HB_OK &&
               !memcmp(actual_memory,expected_memory,count),"input bytes and both adjacent guards unchanged",MEMORY);
}
static int native_present(const hb_jit_runtime_t *jit)
{
    if(!jit || !jit->block_cache)return 0;
    for(size_t i=0;i<jit->block_cache->size;++i) {const hb_block_cache_entry_t *e=&jit->block_cache->entries[i];
        if(e->valid && e->guest_addr==CODE && e->native_code && e->native_size)return 1;}
    return 0;
}
static void run_fixture(hb_arch_t arch,hb_backend_t backend,unsigned restore)
{
    fixture_t f={.arch=arch,.backend=backend,.restore=restore};
    uint8_t code[]={restore?0xdd:0xd9,0x21}; /* /4, [ECX/RCX], no operand override */
    snprintf(phase,sizeof(phase),"%s %s setup",arch==HB_ARCH_X86?"x86":"x64",backend==HB_BACKEND_JIT?"JIT":"interp");
    f.ctx=hb_context_create(arch,backend);if(!check(f.ctx!=NULL,"create context"))goto done;
    f.ctx->memory=hb_memory_create(0);
    if(!check(f.ctx->memory &&
              hb_memory_map_private(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(f.ctx->memory,CODE,code,sizeof(code))==HB_OK &&
              hb_memory_protect(f.ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK &&
              hb_memory_map_private(f.ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,
              "map isolated code and data"))goto done;
    hb_decoded_t d={0};hb_result_t decoded=arch==HB_ARCH_X86?
        hb_decode_x86(code,sizeof(code),CODE,&d):hb_decode_x64(code,sizeof(code),CODE,&d);
    if(!check_kind(decoded==HB_OK && d.len==2 && d.opcode==(restore?HB_INS_X87_FRSTOR:HB_INS_X87_FLDENV) &&
                   d.op1.size==(restore?108:28),"decode exact opcode and existing image width",EXECUTION))goto done;
    f.decoder=hb_decoder_create(arch,code,sizeof(code),CODE);if(!check(f.decoder!=NULL,"create decoder"))goto done;
    hb_result_t lifted=arch==HB_ARCH_X86?hb_lift_func_x86(f.decoder,&f.func):hb_lift_func_x64(f.decoder,&f.func);
    if(!check(lifted==HB_OK && f.func,"lift exact legacy instruction"))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.ctx);else f.interp=hb_interpreter_create(f.ctx);
    if(!check(f.jit || f.interp,"create reusable runtime"))goto done;
    for(unsigned flags=0;flags<64;++flags)for(unsigned masks=0;masks<64;++masks)for(unsigned esb=0;esb<4;++esb)
        run_one(&f,flags,masks,esb,(flags^masks^esb)&1u,READABLE,MAIN_CASE);
    for(unsigned sf=0;sf<2;++sf)for(unsigned ie=0;ie<2;++ie)for(unsigned esb=0;esb<4;++esb)
        run_one(&f,ie,0,esb,sf,READABLE,SF_CASE);
    for(unsigned access=NO_READ;access<=TRUNCATED;++access)for(unsigned esb=0;esb<4;++esb)
        run_one(&f,0x3f,0,esb,1,access,MEMORY_CASE);
    if(f.jit)check_kind(native_present(f.jit),"JIT has native guest entry (helper execution allowed)",EXECUTION);
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
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(unsigned restore=0;restore<2;++restore)
        run_fixture(arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP,restore);
    check_kind(main_loads==131072 && sf_controls==128 && memory_controls==64 && executions==131264,
               "complete main/SF/memory matrix execution counts",EXECUTION);
done:
    snprintf(phase,sizeof(phase),"cleanup");
    if(host_saved)check_kind(fesetenv(&original_host)==0,"restore original host fenv",HOST);
    if(changed) {
        for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore original gate/absence");
        hb_env_refresh();
        for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v && !strcmp(v,saved[i]):!v,"effective original gate restored");}
    }
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_x87_loaded_status_test: %u executions, %u main loads, %u SF controls, %u memory controls, %u checks, %u failures\n",
           executions,main_loads,sf_controls,memory_controls,checks,failures);
    printf("failure categories: status=%u x87=%u state=%u memory=%u execution=%u host=%u\n",
           category_failures[STATUS],category_failures[X87],category_failures[STATE],
           category_failures[MEMORY],category_failures[EXECUTION],category_failures[HOST]);
    return failures?1:0;
}
