/* Actual VEX F16C instructions, independent integer-only numerical oracles.
 * All guest FP exceptions are masked; IE/DE/UE/OE/PE status and delivery remain
 * outside this regression. DAZ controls directly seed internal state and do
 * not claim admission by LDMXCSR/FXRSTOR: the mask remains 0xffbf. Narrowing FTZ
 * and widening DAZ/FTZ must not change results; narrowing DAZ=1 is not tested.
 * Full upper storage is checked without
 * claiming AVX-512 exposure or native SIMD lowering. Private memory uses the
 * seven helper gates below. Fresh JIT runtimes stay below the existing 4096
 * lookup diagnostic, whose floating-point formatting changes host FP status.
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

/* A guest run performs about two cache lookups; leave room below 4096. */
enum {PAGE_BYTES=16384,JIT_BATCH=1024};
enum {NUMERIC,UPPER,OTHER,MEMORY,EXECUTION,HOST,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x4800000),DATA=UINT64_C(0x5800000);
static unsigned checks,failures,executions,category_failures[CATEGORIES];
static char phase[200]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,OTHER);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(i*8));}

/* Binary32 input and four binary16 results: nearest-even, down, up, zero.
 * These are hand-written boundary fixtures, not values from the engine or a
 * reverse round-trip. In particular a NaN's discarded payload adds no new bit. */
typedef struct {const char *name;uint32_t input;uint16_t result[4];} narrow_t;
static const narrow_t narrow_samples[]={
    {"+zero",0x00000000,{0x0000,0x0000,0x0000,0x0000}},
    {"-zero",0x80000000,{0x8000,0x8000,0x8000,0x8000}},
    {"+one",0x3f800000,{0x3c00,0x3c00,0x3c00,0x3c00}},
    {"-one",0xbf800000,{0xbc00,0xbc00,0xbc00,0xbc00}},
    {"+even-tie",0x3f801000,{0x3c00,0x3c00,0x3c01,0x3c00}},
    {"-even-tie",0xbf801000,{0xbc00,0xbc01,0xbc00,0xbc00}},
    {"+odd-tie",0x3f803000,{0x3c02,0x3c01,0x3c02,0x3c01}},
    {"-odd-tie",0xbf803000,{0xbc02,0xbc02,0xbc01,0xbc01}},
    {"+below-tie",0x3f800fff,{0x3c00,0x3c00,0x3c01,0x3c00}},
    {"+above-tie",0x3f801001,{0x3c01,0x3c00,0x3c01,0x3c00}},
    {"-below-tie-magnitude",0xbf800fff,{0xbc00,0xbc01,0xbc00,0xbc00}},
    {"-above-tie-magnitude",0xbf801001,{0xbc01,0xbc01,0xbc00,0xbc00}},
    {"+subnormal-normal-carry",0x387fe000,{0x0400,0x03ff,0x0400,0x03ff}},
    {"-subnormal-normal-carry",0xb87fe000,{0x8400,0x8400,0x83ff,0x83ff}},
    {"+half-min-subnormal",0x33800000,{0x0001,0x0001,0x0001,0x0001}},
    {"-half-min-subnormal",0xb3800000,{0x8001,0x8001,0x8001,0x8001}},
    {"+zero-subnormal-tie",0x33000000,{0x0000,0x0000,0x0001,0x0000}},
    {"-zero-subnormal-tie",0xb3000000,{0x8000,0x8001,0x8000,0x8000}},
    {"+odd-subnormal-tie",0x33c00000,{0x0002,0x0001,0x0002,0x0001}},
    {"-odd-subnormal-tie",0xb3c00000,{0x8002,0x8002,0x8001,0x8001}},
    {"+above-zero-subnormal-tie",0x33000001,{0x0001,0x0000,0x0001,0x0000}},
    {"+below-zero-subnormal-tie",0x32ffffff,{0x0000,0x0000,0x0001,0x0000}},
    {"+float-min-subnormal",0x00000001,{0x0000,0x0000,0x0001,0x0000}},
    {"-float-min-subnormal",0x80000001,{0x8000,0x8001,0x8000,0x8000}},
    {"+float-max-subnormal",0x007fffff,{0x0000,0x0000,0x0001,0x0000}},
    {"-float-max-subnormal",0x807fffff,{0x8000,0x8001,0x8000,0x8000}},
    {"+half-max-subnormal",0x387fc000,{0x03ff,0x03ff,0x03ff,0x03ff}},
    {"+half-min-normal",0x38800000,{0x0400,0x0400,0x0400,0x0400}},
    {"+65504",0x477fe000,{0x7bff,0x7bff,0x7bff,0x7bff}},
    {"-65504",0xc77fe000,{0xfbff,0xfbff,0xfbff,0xfbff}},
    {"+65520-tie",0x477ff000,{0x7c00,0x7bff,0x7c00,0x7bff}},
    {"-65520-tie",0xc77ff000,{0xfc00,0xfc00,0xfbff,0xfbff}},
    {"+below-overflow-tie",0x477fefff,{0x7bff,0x7bff,0x7c00,0x7bff}},
    {"+above-overflow-tie",0x477ff001,{0x7c00,0x7bff,0x7c00,0x7bff}},
    {"+65536",0x47800000,{0x7c00,0x7bff,0x7c00,0x7bff}},
    {"-65536",0xc7800000,{0xfc00,0xfc00,0xfbff,0xfbff}},
    {"+float-max",0x7f7fffff,{0x7c00,0x7bff,0x7c00,0x7bff}},
    {"-float-max",0xff7fffff,{0xfc00,0xfc00,0xfbff,0xfbff}},
    {"+Inf",0x7f800000,{0x7c00,0x7c00,0x7c00,0x7c00}},
    {"-Inf",0xff800000,{0xfc00,0xfc00,0xfc00,0xfc00}},
    {"+qNaN-payload",0x7fc12345,{0x7e09,0x7e09,0x7e09,0x7e09}},
    {"-qNaN-payload",0xffc54321,{0xfe2a,0xfe2a,0xfe2a,0xfe2a}},
    {"+qNaN-low-payload",0x7fc00001,{0x7e00,0x7e00,0x7e00,0x7e00}},
    {"+sNaN-discarded-payload",0x7f800001,{0x7e00,0x7e00,0x7e00,0x7e00}},
    {"-sNaN-discarded-payload",0xff800001,{0xfe00,0xfe00,0xfe00,0xfe00}},
    {"+sNaN-first-retained-payload-bit",0x7f802000,{0x7e01,0x7e01,0x7e01,0x7e01}},
    {"+sNaN-retained-payload",0x7fa00000,{0x7f00,0x7f00,0x7f00,0x7f00}}
};
static const uint16_t wide_samples[]={0x0000,0x8000,0x0001,0x8001,0x03ff,0x83ff,0x0400,0x8400,
    0x3c00,0xbc00,0x3c01,0xbc01,0x7bff,0xfbff,0x7c00,0xfc00,0x7c01,0xfc01,0x7dff,0xfdff,0x7e00,0xfe00,0x7fff,0xffff};

/* Mathematical widening oracle: a half subnormal is fraction * 2^-24.
 * Find that integer's leading power, then place the remainder in binary32.
 * No rounding is needed for finite values. NaNs preserve payload and quiet. */
static uint32_t wide_oracle(uint16_t h)
{
    uint32_t sign=(uint32_t)(h&0x8000u)<<16,exponent=(h>>10)&31u,fraction=h&1023u;
    if(exponent==31)return sign|0x7f800000u|(fraction<<13)|(fraction?0x00400000u:0);
    if(exponent)return sign|((exponent+112u)<<23)|(fraction<<13);
    if(!fraction)return sign;
    unsigned k=9;while(!(fraction&(1u<<k)))--k;
    return sign|((k+103u)<<23)|((fraction-(1u<<k))<<(23-k));
}

typedef struct {const char *name;uint8_t code[5];unsigned narrow,width,dst,src,memory,compact;} form_t;
static const form_t forms[]={
    {"vcvtps2ph xmm0,xmm1",{0xc4,0xe3,0x79,0x1d,0xc8},1,16,0,1,0,0},
    {"vcvtps2ph xmm0,ymm1",{0xc4,0xe3,0x7d,0x1d,0xc8},1,32,0,1,0,0},
    {"vcvtph2ps xmm0,xmm1",{0xc4,0xe2,0x79,0x13,0xc1},0,16,0,1,0,0},
    {"vcvtph2ps ymm0,xmm1",{0xc4,0xe2,0x7d,0x13,0xc1},0,32,0,1,0,0},
    {"vcvtps2ph xmm0,xmm0 alias",{0xc4,0xe3,0x79,0x1d,0xc0},1,16,0,0,0,1},
    {"vcvtps2ph xmm0,ymm0 alias",{0xc4,0xe3,0x7d,0x1d,0xc0},1,32,0,0,0,1},
    {"vcvtph2ps xmm0,xmm0 alias",{0xc4,0xe2,0x79,0x13,0xc0},0,16,0,0,0,1},
    {"vcvtph2ps ymm0,xmm0 alias",{0xc4,0xe2,0x7d,0x13,0xc0},0,32,0,0,0,1},
    {"vcvtps2ph [rcx],xmm1",{0xc4,0xe3,0x79,0x1d,0x09},1,16,0,1,1,1},
    {"vcvtps2ph [rcx],ymm1",{0xc4,0xe3,0x7d,0x1d,0x09},1,32,0,1,1,1},
    {"vcvtph2ps xmm0,[rcx]",{0xc4,0xe2,0x79,0x13,0x01},0,16,0,0,1,1},
    {"vcvtph2ps ymm0,[rcx]",{0xc4,0xe2,0x7d,0x13,0x01},0,32,0,0,1,1}
};
static uint64_t *low(hb_context_t *c,unsigned r){return r>=16?c->xmm_ext[r-16]:c->arch==HB_ARCH_X86?c->regs.x86.xmm[r]:c->regs.x64.xmm[r];}
static uint64_t *mid(hb_context_t *c,unsigned r){return r<16?c->ymm_hi[r]:c->ymm_hi_ext[r-16];}
static uint64_t *high(hb_context_t *c,unsigned r){return r<16?c->zmm_hi[r]:c->zmm_hi_ext[r-16];}
static void vector(hb_context_t *c,unsigned r,uint8_t p[64]){memcpy(p,low(c,r),16);memcpy(p+16,mid(c,r),16);memcpy(p+32,high(c,r),32);}
static void seed(hb_context_t *c,uint64_t pc,uint64_t address,unsigned rc,unsigned control)
{
    memset(&c->regs,0x3c,sizeof(c->regs));if(c->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)address;c->regs.x86.eip=(uint32_t)pc;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rcx=address;c->regs.x64.rip=pc;c->regs.x64.rflags=0xa57;}hb_x87_reset(hb_context_x87(c));
    for(unsigned r=0;r<32;++r){uint8_t p[64];for(unsigned i=0;i<64;++i)p[i]=(uint8_t)(0x31+17*r+29*i);
        if(c->arch!=HB_ARCH_X86||r<8||r>=16)memcpy(low(c,r),p,16);memcpy(mid(c,r),p+16,16);memcpy(high(c,r),p+32,32);}
    for(unsigned i=0;i<sizeof(c->k)/sizeof(c->k[0]);++i)c->k[i]=UINT64_C(0x123456789abc0000)+i;
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x1f80|(rc<<13)|((control&1)?0x8000:0)|((control&2)?0x40:0);c->pc=pc;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;c->step_limit=8;c->block_limit=2;
}
static void check_state(hb_context_t *c,hb_context_t *e,const form_t *f)
{
    unsigned bytes=f->narrow?16:f->width;
    for(unsigned r=0;r<32;++r){if(c->arch==HB_ARCH_X86&&r>=8&&r<16){check(!memcmp(mid(c,r),mid(e,r),16)&&!memcmp(high(c,r),high(e,r),32),"inactive x86 upper storage");continue;}
        uint8_t a[64],b[64];vector(c,r,a);vector(e,r,b);
        if(r==f->dst&&!(f->narrow&&f->memory)){check_kind(!memcmp(a,b,bytes),"independent conversion bits and narrow XMM zero fill",NUMERIC);check_kind(!memcmp(a+bytes,b+bytes,64-bytes),"VEX upper state cleared or fault preserved",UPPER);}
        else check(!memcmp(a,b,64),"other complete vector register/source preserved");}
    hb_context_t n;memcpy(&n,c,sizeof(n));for(unsigned r=0;r<(c->arch==HB_ARCH_X86?8u:16u);++r)memcpy(low(&n,r),low(e,r),16);
    check(!memcmp(&n.regs,&e->regs,sizeof(n.regs))&&!memcmp(&c->x87_64,&e->x87_64,sizeof(c->x87_64)),"GPR/x87 state preserved");
    check(!memcmp(c->k,e->k,sizeof(c->k))&&((c->mxcsr^e->mxcsr)&~0x3fu)==0&&!memcmp(&c->flags,&e->flags,sizeof(c->flags))&&!memcmp(&c->lazy_flags,&e->lazy_flags,sizeof(c->lazy_flags)),"opmasks/MXCSR controls/integer flags preserved; FP status excluded");
    check(c->fs_base==e->fs_base&&c->gs_base==e->gs_base&&c->seg_cs==e->seg_cs&&c->seg_ds==e->seg_ds&&c->seg_es==e->seg_es&&c->seg_fs==e->seg_fs&&c->seg_gs==e->seg_gs&&c->seg_ss==e->seg_ss,"segments preserved");
}
static int valid_decode(const form_t *f,const hb_decoded_t *d)
{
    if(d->len!=(f->narrow?6u:5u)||d->opcode!=(f->narrow?HB_INS_VCVTPS2PH:HB_INS_VCVTPH2PS))return 0;
    if(f->narrow&&f->memory){if(!d->op1.is_mem||d->op1.size!=f->width/2)return 0;}
    else if(!d->op1.is_reg||d->op1.reg!=HB_REG_XMM0+(int)f->dst||d->op1.size!=(f->narrow?16:f->width))return 0;
    if(!f->narrow&&f->memory)return d->op2.is_mem&&d->op2.size==f->width/2;
    return d->op2.is_reg&&d->op2.reg==HB_REG_XMM0+(int)f->src&&d->op2.size==(f->narrow?f->width:f->width/2);
}
static int native_present(const hb_jit_runtime_t *j,uint64_t pc)
{
    if(!j||!j->block_cache)return 0;for(size_t i=0;i<j->block_cache->size;++i){const hb_block_cache_entry_t *e=&j->block_cache->entries[i];if(e->valid&&e->guest_addr==pc&&e->native_code&&e->native_size)return 1;}return 0;
}
typedef struct {hb_context_t *c;hb_interpreter_t *interp;hb_jit_runtime_t *jit;hb_ir_func_t *func;unsigned use_jit,runs;uint64_t pc;} run_t;
static void close_jit(run_t *s)
{
    if(s->jit){check_kind(native_present(s->jit,s->pc),"native JIT entry exists (helpers allowed)",EXECUTION);hb_jit_runtime_destroy(s->jit);s->jit=NULL;}s->runs=0;
}
static void run_case(run_t *s,const form_t *f,unsigned imm,unsigned guest,unsigned host,unsigned first,unsigned exhaustive,unsigned control,unsigned access)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    hb_context_t *c=s->c;unsigned lanes=f->width/4,mem_bytes=f->width/2,rc=(imm&4)?guest:imm&3;
    uint64_t address=DATA+PAGE_BYTES-mem_bytes;if(access==2)++address;else if(access==3)address=DATA+2*PAGE_BYTES;
    snprintf(phase,sizeof(phase),"%s %s %s imm=%u guest=%u host=%u first=%u exhaustive=%u control=%u access=%u",c->arch==HB_ARCH_X86?"x86":"x64",s->use_jit?"JIT":"interp",f->name,imm,guest,host,first,exhaustive,control,access);
    seed(c,s->pc,address,guest,control);uint8_t input[32]={0},output[32]={0},memory[64],actual_memory[64];memset(memory,0xa5,sizeof(memory));
    for(unsigned i=0;i<lanes;++i){if(f->narrow){const narrow_t *v=&narrow_samples[(first+i)%(sizeof(narrow_samples)/sizeof(narrow_samples[0]))];put32(input+4*i,v->input);put16(output+2*i,v->result[rc]);}
        else {uint16_t h=exhaustive?(uint16_t)(first+i):wide_samples[(first+i)%(sizeof(wide_samples)/sizeof(wide_samples[0]))];put16(input+2*i,h);put32(output+4*i,wide_oracle(h));}}
    if(f->narrow||!f->memory){unsigned source_bytes=f->narrow?f->width:f->width/2;memcpy(low(c,f->src),input,source_bytes<16?source_bytes:16);if(source_bytes==32)memcpy(mid(c,f->src),input+16,16);}
    if(f->memory){if(!f->narrow)memcpy(memory+sizeof(memory)-mem_bytes,input,mem_bytes);
        if(!check(hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(c->memory,DATA+PAGE_BYTES-sizeof(memory),memory,sizeof(memory))==HB_OK,"seed bounded memory and guards"))return;
        if(access==1&&!check(hb_memory_protect(c->memory,DATA,PAGE_BYTES,f->narrow?HB_PERM_READ:HB_PERM_WRITE)==HB_OK,"deny requested data access"))return;}
    hb_context_t expected;memcpy(&expected,c,sizeof(expected));
    if(!access){if(f->narrow&&f->memory)memcpy(memory+sizeof(memory)-mem_bytes,output,mem_bytes);
        else {memcpy(low(&expected,f->dst),output,16);if(!f->narrow&&f->width==32)memcpy(mid(&expected,f->dst),output+16,16);else memset(mid(&expected,f->dst),0,16);memset(high(&expected,f->dst),0,32);}
        expected.pc=s->pc+(f->narrow?6:5);if(c->arch==HB_ARCH_X86)expected.regs.x86.eip=(uint32_t)expected.pc;else expected.regs.x64.rip=expected.pc;}
    if(s->use_jit){if(s->runs>=JIT_BATCH)close_jit(s);if(!s->jit){s->jit=hb_jit_runtime_create(c);if(!check(s->jit!=NULL,"create bounded JIT runtime"))return;}}
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    int wanted_status=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=s->jit?hb_jit_runtime_run(s->jit,s->func,&out):hb_interpreter_run(s->interp,s->func,&out);
    int actual_rc=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;++s->runs;
    if(!check_kind(actual_rc==host_modes[host]&&actual_status==wanted_status,"host fenv preserved",HOST)&&category_failures[HOST]<=4)fprintf(stderr,"HOST %s: actual rc=%d flags=%x expected rc=%d flags=%x\n",phase,actual_rc,actual_status,host_modes[host],wanted_status);
    if(!access)check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&c->pc==expected.pc,"complete raw conversion at exact end PC",EXECUTION);
    else {check_kind((result==HB_OK||result==HB_ERR_MEMORY_FAULT)&&out.result==HB_ERR_MEMORY_FAULT&&out.faulted&&!out.timed_out,"denied/crossing/unmapped data faults",EXECUTION);
        if(c->arch==HB_ARCH_X86)expected.regs.x86.eip=c->regs.x86.eip;else expected.regs.x64.rip=c->regs.x64.rip;}
    check_state(c,&expected,f);
    if(f->memory){check(hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned data permissions");
        /* One owned region, no special callbacks: span/permission rejection
         * precedes writes. This does not assert rollback after late host faults. */
        check_kind(hb_memory_read(c->memory,DATA+PAGE_BYTES-sizeof(memory),actual_memory,sizeof(actual_memory))==HB_OK&&!memcmp(actual_memory,memory,sizeof(memory)),"memory result/input and guards; rejected span unchanged",MEMORY);}
}
static void run_form(const form_t *f,hb_arch_t arch,hb_backend_t backend)
{
    static const unsigned immediates[]={0,1,2,3,4,5,6,7,8,0x7f,0xf8,0xff};
    run_t s={0};hb_decoder_t *decoder=NULL;uint8_t code[PAGE_BYTES]={0};s.use_jit=backend==HB_BACKEND_JIT;
    snprintf(phase,sizeof(phase),"%s %s %s setup",arch==HB_ARCH_X86?"x86":"x64",s.use_jit?"JIT":"interp",f->name);
    for(unsigned i=0;i<sizeof(immediates)/sizeof(immediates[0]);++i){unsigned imm=immediates[i];memcpy(code+64*imm,f->code,5);code[64*imm+5]=(uint8_t)imm;}
    s.c=hb_context_create(arch,backend);if(!check(s.c!=NULL,"create context"))goto done;s.c->memory=hb_memory_create(0);
    if(!check(s.c->memory&&hb_memory_map_private(s.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(s.c->memory,CODE,code,sizeof(code))==HB_OK&&hb_memory_protect(s.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(s.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned private code/data"))goto done;
    if(!s.use_jit){s.interp=hb_interpreter_create(s.c);if(!check(s.interp!=NULL,"create interpreter"))goto done;}
    for(unsigned choice=0;choice<(f->narrow?sizeof(immediates)/sizeof(immediates[0]):1);++choice){unsigned imm=immediates[choice],n=f->narrow?6:5,lanes=f->width/4;s.pc=CODE+64*imm;
        if(f->compact&&f->narrow&&imm!=0&&imm!=4&&imm!=0xff)continue;
        hb_decoded_t d={0};const uint8_t *raw=code+64*imm;hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(raw,n,s.pc,&d):hb_decode_x64(raw,n,s.pc,&d);
        check_kind(r==HB_OK&&valid_decode(f,&d),"decode exact conversion, widths and register roles",EXECUTION);
        if(r!=HB_OK||d.opcode!=(f->narrow?HB_INS_VCVTPS2PH:HB_INS_VCVTPH2PS)||d.len!=n)continue;
        decoder=hb_decoder_create(arch,raw,n,s.pc);if(!check(decoder!=NULL,"create decoder"))goto done;
        r=arch==HB_ARCH_X86?hb_lift_func_x86(decoder,&s.func):hb_lift_func_x64(decoder,&s.func);if(!check_kind(r==HB_OK&&s.func,"lift actual raw F16C instruction",EXECUTION))goto done;
        if(f->memory){for(unsigned access=0;access<4;++access)run_case(&s,f,imm,2,1,f->narrow?12:0,0,0,access);}
        else if(f->narrow){
            if(!f->compact&&imm<8){for(unsigned host=0;host<4;++host)for(unsigned guest=0;guest<4;++guest)for(unsigned first=0;first<sizeof(narrow_samples)/sizeof(narrow_samples[0]);first+=lanes)run_case(&s,f,imm,guest,host,first,0,0,0);}
            else {for(unsigned guest=0;guest<4;++guest)for(unsigned first=0;first<sizeof(narrow_samples)/sizeof(narrow_samples[0]);first+=lanes)run_case(&s,f,imm,guest,2,first,0,0,0);}
            /* Narrowing FTZ=1 control only; DAZ stays zero pending its separate
             * primary-source contract. Widening DAZ is explicitly ignored. */
            if(!f->compact&&imm==4)for(unsigned control=1;control<2;++control)for(unsigned guest=0;guest<4;++guest)for(unsigned host=0;host<4;++host)
                for(unsigned first=12;first<24;first+=lanes)run_case(&s,f,imm,guest,host,first,0,control,0);
        } else {
            if(!f->compact)for(unsigned first=0;first<65536;first+=lanes)run_case(&s,f,0,(first/lanes/4)&3,(first/lanes)&3,first,1,0,0);
            for(unsigned control=0;control<4;++control)for(unsigned guest=0;guest<4;++guest)for(unsigned host=0;host<4;++host)
                for(unsigned first=0;first<sizeof(wide_samples)/sizeof(wide_samples[0]);first+=lanes)run_case(&s,f,0,guest,host,first,0,control,0);
        }
        close_jit(&s);hb_decoder_destroy(decoder);decoder=NULL;hb_ir_func_destroy(s.func);s.func=NULL;
    }
done:
    if(s.c&&s.c->memory)(void)hb_memory_protect(s.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE);
    close_jit(&s);if(s.interp)hb_interpreter_destroy(s.interp);if(decoder)hb_decoder_destroy(decoder);if(s.func)hb_ir_func_destroy(s.func);if(s.c)hb_context_destroy(s.c);
}
static const struct{const char *name;enum hb_gate_id id;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED}
};
int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original_host;
    check(HB_MXCSR_SUPPORTED_MASK==0xffbfu,"guest MXCSR mask unchanged; DAZ probes use internal state");
    /* Anchor the exhaustive mathematical oracle to independent known words. */
    check(wide_oracle(0x0001)==0x33800000&&wide_oracle(0x03ff)==0x387fc000&&wide_oracle(0x0400)==0x38800000&&wide_oracle(0x7c01)==0x7fc02000&&wide_oracle(0xfc01)==0xffc02000,"widening oracle anchors");
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *v=getenv(gates[i].name);if(v&&!check((saved[i]=strdup(v))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,"0",1)==0,"select private helper memory"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);if(!check(v&&!strcmp(v,"0"),"effective helper gate"))goto done;}
    if(!check(feholdexcept(&original_host)==0,"save and mask host fenv"))goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(size_t i=0;i<sizeof(forms)/sizeof(forms[0]);++i)run_form(&forms[i],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v&&!strcmp(v,saved[i]):!v,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_half_conversion_test: %u executions, %u checks, %u failures\n",executions,checks,failures);
    printf("failure categories: numeric=%u upper=%u other=%u memory=%u execution=%u host=%u\n",category_failures[NUMERIC],category_failures[UPPER],category_failures[OTHER],category_failures[MEMORY],category_failures[EXECUTION],category_failures[HOST]);return failures?1:0;
}
