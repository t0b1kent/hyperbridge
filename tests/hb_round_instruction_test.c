/* Numerical ROUNDPS/PD/SS/SD regression through actual decoding/lifting.
 * Integer bit-pattern oracles never use host floating-point arithmetic. All
 * guest exceptions are masked. Guest IE/PE delivery and imm8[3] status behavior
 * are deliberately outside this test: only MXCSR control bits are compared.
 * DAZ=1 probes directly seed internal context state; they do not claim DAZ is
 * admitted by guest LDMXCSR/FXRSTOR (the supported mask remains 0xffbf).
 * Private mappings use helper memory. A fresh JIT runtime per immediate keeps
 * each measured run below the periodic cache diagnostic's FP-formatting path.
 * Diagnostic host-fenv isolation is separate from this instruction test.
 * A native JIT
 * entry is required; native SIMD lowering and AVX-512 exposure are not claimed.
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

enum {PAGE_BYTES=16384,INSTRUCTION_BYTES=6};
enum {NUMERIC,UPPER,OTHER,MEMORY,EXECUTION,HOST,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x4600000),DATA=UINT64_C(0x5600000);
static unsigned checks,failures,executions,category_failures[CATEGORIES];
static char phase[200]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;if(!ok){++failures;++category_failures[category];
        if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}
    return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,OTHER);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(i*8));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(i*8));}

/* Each row is input, nearest-even, down, up, toward-zero, independently stated
 * for binary32 and binary64. Precision-boundary rows intentionally differ in
 * magnitude between formats. NaN results set only the quiet bit. */
typedef struct {const char *name;uint32_t f[5];uint64_t d[5];} sample_t;
static const sample_t samples[]={
    {"+zero",{0,0,0,0,0},{0,0,0,0,0}},
    {"-zero",{0x80000000,0x80000000,0x80000000,0x80000000,0x80000000},{0x8000000000000000,0x8000000000000000,0x8000000000000000,0x8000000000000000,0x8000000000000000}},
    {"+0.5",{0x3f000000,0,0,0x3f800000,0},{0x3fe0000000000000,0,0,0x3ff0000000000000,0}},
    {"-0.5",{0xbf000000,0x80000000,0xbf800000,0x80000000,0x80000000},{0xbfe0000000000000,0x8000000000000000,0xbff0000000000000,0x8000000000000000,0x8000000000000000}},
    {"+1.5",{0x3fc00000,0x40000000,0x3f800000,0x40000000,0x3f800000},{0x3ff8000000000000,0x4000000000000000,0x3ff0000000000000,0x4000000000000000,0x3ff0000000000000}},
    {"-1.5",{0xbfc00000,0xc0000000,0xc0000000,0xbf800000,0xbf800000},{0xbff8000000000000,0xc000000000000000,0xc000000000000000,0xbff0000000000000,0xbff0000000000000}},
    {"+2.5",{0x40200000,0x40000000,0x40000000,0x40400000,0x40000000},{0x4004000000000000,0x4000000000000000,0x4000000000000000,0x4008000000000000,0x4000000000000000}},
    {"-2.5",{0xc0200000,0xc0000000,0xc0400000,0xc0000000,0xc0000000},{0xc004000000000000,0xc000000000000000,0xc008000000000000,0xc000000000000000,0xc000000000000000}},
    {"+3.5",{0x40600000,0x40800000,0x40400000,0x40800000,0x40400000},{0x400c000000000000,0x4010000000000000,0x4008000000000000,0x4010000000000000,0x4008000000000000}},
    {"-3.5",{0xc0600000,0xc0800000,0xc0800000,0xc0400000,0xc0400000},{0xc00c000000000000,0xc010000000000000,0xc010000000000000,0xc008000000000000,0xc008000000000000}},
    {"below+2.5",{0x401fffff,0x40000000,0x40000000,0x40400000,0x40000000},{0x4003ffffffffffff,0x4000000000000000,0x4000000000000000,0x4008000000000000,0x4000000000000000}},
    {"above+2.5",{0x40200001,0x40400000,0x40000000,0x40400000,0x40000000},{0x4004000000000001,0x4008000000000000,0x4000000000000000,0x4008000000000000,0x4000000000000000}},
    {"small-magnitude-2.5",{0xc01fffff,0xc0000000,0xc0400000,0xc0000000,0xc0000000},{0xc003ffffffffffff,0xc000000000000000,0xc008000000000000,0xc000000000000000,0xc000000000000000}},
    {"large-magnitude-2.5",{0xc0200001,0xc0400000,0xc0400000,0xc0000000,0xc0000000},{0xc004000000000001,0xc008000000000000,0xc008000000000000,0xc000000000000000,0xc000000000000000}},
    {"+last-fraction",{0x4affffff,0x4b000000,0x4afffffe,0x4b000000,0x4afffffe},{0x432fffffffffffff,0x4330000000000000,0x432ffffffffffffe,0x4330000000000000,0x432ffffffffffffe}},
    {"-last-fraction",{0xcaffffff,0xcb000000,0xcb000000,0xcafffffe,0xcafffffe},{0xc32fffffffffffff,0xc330000000000000,0xc330000000000000,0xc32ffffffffffffe,0xc32ffffffffffffe}},
    {"+min-subnormal",{1,0,0,0x3f800000,0},{1,0,0,0x3ff0000000000000,0}},
    {"-min-subnormal",{0x80000001,0x80000000,0xbf800000,0x80000000,0x80000000},{0x8000000000000001,0x8000000000000000,0xbff0000000000000,0x8000000000000000,0x8000000000000000}},
    {"+max-subnormal",{0x007fffff,0,0,0x3f800000,0},{0x000fffffffffffff,0,0,0x3ff0000000000000,0}},
    {"-max-subnormal",{0x807fffff,0x80000000,0xbf800000,0x80000000,0x80000000},{0x800fffffffffffff,0x8000000000000000,0xbff0000000000000,0x8000000000000000,0x8000000000000000}},
    {"+integer-above-precision",{0x4b800001,0x4b800001,0x4b800001,0x4b800001,0x4b800001},{0x4340000000000001,0x4340000000000001,0x4340000000000001,0x4340000000000001,0x4340000000000001}},
    {"-integer-above-precision",{0xcb800001,0xcb800001,0xcb800001,0xcb800001,0xcb800001},{0xc340000000000001,0xc340000000000001,0xc340000000000001,0xc340000000000001,0xc340000000000001}},
    {"+Inf",{0x7f800000,0x7f800000,0x7f800000,0x7f800000,0x7f800000},{0x7ff0000000000000,0x7ff0000000000000,0x7ff0000000000000,0x7ff0000000000000,0x7ff0000000000000}},
    {"-Inf",{0xff800000,0xff800000,0xff800000,0xff800000,0xff800000},{0xfff0000000000000,0xfff0000000000000,0xfff0000000000000,0xfff0000000000000,0xfff0000000000000}},
    {"+qNaN",{0x7fc12345,0x7fc12345,0x7fc12345,0x7fc12345,0x7fc12345},{0x7ff8123456789abc,0x7ff8123456789abc,0x7ff8123456789abc,0x7ff8123456789abc,0x7ff8123456789abc}},
    {"-qNaN",{0xffc54321,0xffc54321,0xffc54321,0xffc54321,0xffc54321},{0xfff8abcdef012345,0xfff8abcdef012345,0xfff8abcdef012345,0xfff8abcdef012345,0xfff8abcdef012345}},
    {"+sNaN",{0x7f812345,0x7fc12345,0x7fc12345,0x7fc12345,0x7fc12345},{0x7ff0123456789abc,0x7ff8123456789abc,0x7ff8123456789abc,0x7ff8123456789abc,0x7ff8123456789abc}},
    {"-sNaN",{0xff854321,0xffc54321,0xffc54321,0xffc54321,0xffc54321},{0xfff0abcdef012345,0xfff8abcdef012345,0xfff8abcdef012345,0xfff8abcdef012345,0xfff8abcdef012345}}
};

typedef struct {const char *name;uint8_t code[5];unsigned lane,bytes,vex,scalar,dst,src,merge,memory,compact;} form_t;
static const form_t forms[]={
    {"roundps xmm0,xmm1",{0x66,0x0f,0x3a,0x08,0xc1},4,16,0,0,0,1,0,0,0},
    {"roundpd xmm0,xmm1",{0x66,0x0f,0x3a,0x09,0xc1},8,16,0,0,0,1,0,0,0},
    {"roundss xmm0,xmm1",{0x66,0x0f,0x3a,0x0a,0xc1},4,16,0,1,0,1,0,0,0},
    {"roundsd xmm0,xmm1",{0x66,0x0f,0x3a,0x0b,0xc1},8,16,0,1,0,1,0,0,0},
    {"vroundps xmm0,xmm1",{0xc4,0xe3,0x79,0x08,0xc1},4,16,1,0,0,1,0,0,0},
    {"vroundpd xmm0,xmm1",{0xc4,0xe3,0x79,0x09,0xc1},8,16,1,0,0,1,0,0,0},
    {"vroundss xmm0,xmm1,xmm2",{0xc4,0xe3,0x71,0x0a,0xc2},4,16,1,1,0,2,1,0,0},
    {"vroundsd xmm0,xmm1,xmm2",{0xc4,0xe3,0x71,0x0b,0xc2},8,16,1,1,0,2,1,0,0},
    {"vroundps ymm0,ymm1",{0xc4,0xe3,0x7d,0x08,0xc1},4,32,1,0,0,1,0,0,0},
    {"vroundpd ymm0,ymm1",{0xc4,0xe3,0x7d,0x09,0xc1},8,32,1,0,0,1,0,0,0},
    {"vroundss merge/dst alias",{0xc4,0xe3,0x71,0x0a,0xca},4,16,1,1,1,2,1,0,1},
    {"vroundsd input/dst alias",{0xc4,0xe3,0x71,0x0b,0xd2},8,16,1,1,2,2,1,0,1},
    {"vroundps ymm0,ymm0",{0xc4,0xe3,0x7d,0x08,0xc0},4,32,1,0,0,0,0,0,1},
    {"roundss xmm0,[rcx]",{0x66,0x0f,0x3a,0x0a,0x01},4,16,0,1,0,0,0,1,1},
    {"roundsd xmm0,[rcx]",{0x66,0x0f,0x3a,0x0b,0x01},8,16,0,1,0,0,0,1,1},
    {"vroundss xmm0,xmm1,[rcx]",{0xc4,0xe3,0x71,0x0a,0x01},4,16,1,1,0,0,1,1,1},
    {"vroundsd xmm0,xmm1,[rcx]",{0xc4,0xe3,0x71,0x0b,0x01},8,16,1,1,0,0,1,1,1},
    {"roundpd xmm0,[rcx]",{0x66,0x0f,0x3a,0x09,0x01},8,16,0,0,0,0,0,1,1}
};

static uint64_t *low(hb_context_t *c,unsigned r){return r>=16?c->xmm_ext[r-16]:c->arch==HB_ARCH_X86?c->regs.x86.xmm[r]:c->regs.x64.xmm[r];}
static uint64_t *mid(hb_context_t *c,unsigned r){return r<16?c->ymm_hi[r]:c->ymm_hi_ext[r-16];}
static uint64_t *high(hb_context_t *c,unsigned r){return r<16?c->zmm_hi[r]:c->zmm_hi_ext[r-16];}
static void vector(hb_context_t *c,unsigned r,uint8_t p[64]){memcpy(p,low(c,r),16);memcpy(p+16,mid(c,r),16);memcpy(p+32,high(c,r),32);}
static void seed(hb_context_t *c,uint64_t pc,uint64_t address,unsigned rc,unsigned daz)
{
    memset(&c->regs,0x3c,sizeof(c->regs));
    if(c->arch==HB_ARCH_X86){c->regs.x86.ecx=(uint32_t)address;c->regs.x86.eip=(uint32_t)pc;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rcx=address;c->regs.x64.rip=pc;c->regs.x64.rflags=0xa57;}
    hb_x87_reset(hb_context_x87(c));
    for(unsigned r=0;r<32;++r){uint8_t p[64];for(unsigned i=0;i<64;++i)p[i]=(uint8_t)(0x31+17*r+29*i);
        if(c->arch!=HB_ARCH_X86 || r<8 || r>=16)memcpy(low(c,r),p,16);memcpy(mid(c,r),p+16,16);memcpy(high(c,r),p+32,32);}
    for(unsigned i=0;i<sizeof(c->k)/sizeof(c->k[0]);++i)c->k[i]=UINT64_C(0x123456789abc0000)+i;
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->mxcsr=0x1f80|(rc<<13)|(daz?0x40:0);c->pc=pc;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
    c->step_limit=8;c->block_limit=2;
}
static void check_state(hb_context_t *c,hb_context_t *e,const form_t *f)
{
    for(unsigned r=0;r<32;++r){
        if(c->arch==HB_ARCH_X86 && r>=8 && r<16){check(!memcmp(mid(c,r),mid(e,r),16)&&!memcmp(high(c,r),high(e,r),32),"inactive x86 upper storage");continue;}
        uint8_t a[64],b[64];vector(c,r,a);vector(e,r,b);
        if(r==f->dst){check_kind(!memcmp(a,b,f->bytes),"independent result bits and scalar merge",NUMERIC);check_kind(!memcmp(a+f->bytes,b+f->bytes,64-f->bytes),"legacy/VEX upper-state rule",UPPER);}
        else check(!memcmp(a,b,64),"other complete vector register preserved");
    }
    hb_context_t n;memcpy(&n,c,sizeof(n));for(unsigned r=0;r<(c->arch==HB_ARCH_X86?8u:16u);++r)memcpy(low(&n,r),low(e,r),16);
    check(!memcmp(&n.regs,&e->regs,sizeof(n.regs))&&!memcmp(&c->x87_64,&e->x87_64,sizeof(c->x87_64)),"GPR/x87 state preserved");
    check(!memcmp(c->k,e->k,sizeof(c->k))&&((c->mxcsr^e->mxcsr)&~0x3fu)==0&&!memcmp(&c->flags,&e->flags,sizeof(c->flags))&&
          !memcmp(&c->lazy_flags,&e->lazy_flags,sizeof(c->lazy_flags)),"opmasks/MXCSR controls/integer flags preserved; FP status excluded");
    check(c->fs_base==e->fs_base&&c->gs_base==e->gs_base&&c->seg_cs==e->seg_cs&&c->seg_ds==e->seg_ds&&c->seg_es==e->seg_es&&
          c->seg_fs==e->seg_fs&&c->seg_gs==e->seg_gs&&c->seg_ss==e->seg_ss,"segments preserved");
}
static int valid_decode(const form_t *f,const hb_decoded_t *d,unsigned imm)
{
    int op=f->scalar?(f->lane==4?HB_INS_ROUNDSS:HB_INS_ROUNDSD):(f->lane==4?HB_INS_ROUNDPS:HB_INS_ROUNDPD);
    if(d->len!=INSTRUCTION_BYTES||(int)d->opcode!=op||!d->op1.is_reg||d->op1.reg!=HB_REG_XMM0+(int)f->dst||d->op1.size!=f->bytes)return 0;
    (void)imm; /* Raw immediate byte and output matrix prove selection independently. */
    if(f->vex&&f->scalar){
        if(!d->op2.is_reg||d->op2.reg!=HB_REG_XMM0+(int)f->merge||d->op2.size!=16)return 0;
        return f->memory?d->op3.is_mem&&d->op3.size==f->lane:d->op3.is_reg&&d->op3.reg==HB_REG_XMM0+(int)f->src&&d->op3.size==16;
    }
    return f->memory?d->op2.is_mem&&d->op2.size==(f->scalar?f->lane:f->bytes):
        d->op2.is_reg&&d->op2.reg==HB_REG_XMM0+(int)f->src&&d->op2.size==f->bytes;
}
static int native_present(const hb_jit_runtime_t *j,uint64_t pc)
{
    if(!j||!j->block_cache)return 0;for(size_t i=0;i<j->block_cache->size;++i){const hb_block_cache_entry_t *e=&j->block_cache->entries[i];
        if(e->valid&&e->guest_addr==pc&&e->native_code&&e->native_size)return 1;}return 0;
}
static void run_case(hb_context_t *c,hb_interpreter_t *interp,hb_jit_runtime_t *jit,hb_ir_func_t *func,const form_t *f,
                     unsigned imm,unsigned guest,unsigned host,unsigned first,unsigned daz,unsigned access)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    const unsigned count=sizeof(samples)/sizeof(samples[0]),lanes=f->scalar?1:f->bytes/f->lane;
    const unsigned read_bytes=f->scalar?f->lane:f->bytes,rc=(imm&4)?guest:imm&3;
    uint64_t pc=CODE+64*imm,address=DATA+PAGE_BYTES-read_bytes;
    if(access==2)address=DATA+PAGE_BYTES-read_bytes+1;else if(access==3)address=DATA+2*PAGE_BYTES;
    snprintf(phase,sizeof(phase),"%s %s %s imm=%u guest=%u host=%u %s DAZ=%u access=%u",c->arch==HB_ARCH_X86?"x86":"x64",jit?"JIT":"interp",f->name,imm,guest,host,samples[first%count].name,daz,access);
    seed(c,pc,address,guest,daz);
    uint8_t input[32]={0},rounded[32]={0},page_end[64],actual_end[64];memset(page_end,0xa5,sizeof(page_end));
    for(unsigned i=0;i<lanes;++i){const sample_t *s=&samples[(first+i)%count];
        if(f->lane==4){uint32_t v=s->f[0],answer=s->f[rc+1];if(daz&&(v&0x7f800000u)==0)answer=v&0x80000000u;put32(input+4*i,v);put32(rounded+4*i,answer);}
        else {uint64_t v=s->d[0],answer=s->d[rc+1];if(daz&&(v&UINT64_C(0x7ff0000000000000))==0)answer=v&UINT64_C(0x8000000000000000);put64(input+8*i,v);put64(rounded+8*i,answer);}
    }
    if(!f->memory){memcpy(low(c,f->src),input,read_bytes<16?read_bytes:16);if(read_bytes==32)memcpy(mid(c,f->src),input+16,16);}
    else {
        memcpy(page_end+sizeof(page_end)-read_bytes,input,read_bytes);
        if(!check(hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(c->memory,DATA+PAGE_BYTES-sizeof(page_end),page_end,sizeof(page_end))==HB_OK,"seed bounded source and guards"))return;
        if(access==1&&!check(hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_WRITE)==HB_OK,"deny source read"))return;
    }
    hb_context_t expected;memcpy(&expected,c,sizeof(expected));
    if(!access){
        if(f->scalar&&f->vex)memcpy(low(&expected,f->dst),low(c,f->merge),16);
        memcpy(low(&expected,f->dst),rounded,read_bytes<16?read_bytes:16);if(read_bytes==32)memcpy(mid(&expected,f->dst),rounded+16,16);
        if(f->vex){if(f->bytes==16)memset(mid(&expected,f->dst),0,16);memset(high(&expected,f->dst),0,32);}
        expected.pc=pc+INSTRUCTION_BYTES;if(c->arch==HB_ARCH_X86)expected.regs.x86.eip=(uint32_t)expected.pc;else expected.regs.x64.rip=expected.pc;
    }
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked host fenv"))return;
    int wanted_status=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};
    hb_result_t result=jit?hb_jit_runtime_run(jit,func,&out):hb_interpreter_run(interp,func,&out);
    int actual_rc=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;
    if(!check_kind(actual_rc==host_modes[host]&&actual_status==wanted_status,"host fenv preserved",HOST)&&category_failures[HOST]<=4)
        fprintf(stderr,"HOST %s: actual rc=%d flags=%x expected rc=%d flags=%x\n",phase,actual_rc,actual_status,host_modes[host],wanted_status);
    if(!access)check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&c->pc==expected.pc,"complete raw instruction at exact end PC",EXECUTION);
    else {check_kind((result==HB_OK||result==HB_ERR_MEMORY_FAULT)&&out.result==HB_ERR_MEMORY_FAULT&&out.faulted&&!out.timed_out,"operand read faults before destination mutation",EXECUTION);
        if(c->arch==HB_ARCH_X86)expected.regs.x86.eip=c->regs.x86.eip;else expected.regs.x64.rip=c->regs.x64.rip;}
    check_state(c,&expected,f);
    if(f->memory){check(hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore source permissions");
        check_kind(hb_memory_read(c->memory,DATA+PAGE_BYTES-sizeof(actual_end),actual_end,sizeof(actual_end))==HB_OK&&!memcmp(actual_end,page_end,sizeof(page_end)),"source bytes and adjacent guards unchanged",MEMORY);}
}

static void run_form(const form_t *f,hb_arch_t arch,hb_backend_t backend)
{
    hb_context_t *c=NULL;hb_interpreter_t *interp=NULL;hb_jit_runtime_t *jit=NULL;
    hb_decoder_t *decoder=NULL;hb_ir_func_t *func=NULL;uint8_t code[1024]={0};
    snprintf(phase,sizeof(phase),"%s %s %s setup",arch==HB_ARCH_X86?"x86":"x64",backend==HB_BACKEND_JIT?"JIT":"interp",f->name);
    for(unsigned imm=0;imm<16;++imm){memcpy(code+64*imm,f->code,5);code[64*imm+5]=(uint8_t)imm;}
    c=hb_context_create(arch,backend);if(!check(c!=NULL,"create context"))goto done;c->memory=hb_memory_create(0);
    if(!check(c->memory&&hb_memory_map_private(c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&
              hb_memory_write(c->memory,CODE,code,sizeof(code))==HB_OK&&hb_memory_protect(c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&
              hb_memory_map_private(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned private code/data"))goto done;
    if(backend!=HB_BACKEND_JIT){interp=hb_interpreter_create(c);if(!check(interp!=NULL,"create interpreter"))goto done;}
    for(unsigned choice=0;choice<10;++choice){unsigned imm=choice<8?choice:choice==8?8:12;
        if(f->compact&&imm!=0&&imm!=4&&imm!=8&&imm!=12)continue;
        const uint8_t *raw=code+64*imm;uint64_t pc=CODE+64*imm;hb_decoded_t d={0};
        hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(raw,INSTRUCTION_BYTES,pc,&d):hb_decode_x64(raw,INSTRUCTION_BYTES,pc,&d);
        check_kind(r==HB_OK&&valid_decode(f,&d,imm),"decode exact opcode, widths and register roles",EXECUTION);
        /* Keep old-library width defects observable during execution too. A
         * failed or unrelated decode is still a test failure and cannot run. */
        if(r!=HB_OK||d.len!=INSTRUCTION_BYTES||
           (d.opcode!=HB_INS_ROUNDPS&&d.opcode!=HB_INS_ROUNDPD&&d.opcode!=HB_INS_ROUNDSS&&d.opcode!=HB_INS_ROUNDSD))continue;
        decoder=hb_decoder_create(arch,raw,INSTRUCTION_BYTES,pc);if(!check(decoder!=NULL,"create decoder"))goto done;
        r=arch==HB_ARCH_X86?hb_lift_func_x86(decoder,&func):hb_lift_func_x64(decoder,&func);if(!check_kind(r==HB_OK&&func,"lift raw ROUND instruction",EXECUTION))goto done;
        if(backend==HB_BACKEND_JIT){jit=hb_jit_runtime_create(c);if(!check(jit!=NULL,"create JIT runtime for this immediate"))goto done;}
        if(f->memory){for(unsigned access=0;access<4;++access)run_case(c,interp,jit,func,f,imm,2,1,4,0,access);}
        else if(f->compact||imm>=8){for(unsigned guest=0;guest<4;++guest)for(unsigned first=2;first<8;first+=(f->scalar?1:f->bytes/f->lane))run_case(c,interp,jit,func,f,imm,guest,2,first,0,0);}
        else {for(unsigned host=0;host<4;++host)for(unsigned guest=0;guest<4;++guest)
            for(unsigned first=0;first<sizeof(samples)/sizeof(samples[0]);first+=(f->scalar?1:f->bytes/f->lane))run_case(c,interp,jit,func,f,imm,guest,host,first,0,0);}
        /* Internal-only DAZ=1 probes span both signs, subnormal endpoints and
         * every effective mode. DAZ=0 is used throughout the full matrix. */
        if(!f->memory&&!f->compact&&imm==4)for(unsigned guest=0;guest<4;++guest)
            for(unsigned first=16;first<20;first+=(f->scalar?1:f->bytes/f->lane))run_case(c,interp,jit,func,f,imm,guest,1,first,1,0);
        if(jit)check_kind(native_present(jit,pc),"native JIT entry exists for this immediate (helpers allowed)",EXECUTION);
        if(jit){hb_jit_runtime_destroy(jit);jit=NULL;}
        hb_decoder_destroy(decoder);decoder=NULL;hb_ir_func_destroy(func);func=NULL;
    }
done:
    if(c&&c->memory)(void)hb_memory_protect(c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE);
    if(jit)hb_jit_runtime_destroy(jit);if(interp)hb_interpreter_destroy(interp);if(decoder)hb_decoder_destroy(decoder);if(func)hb_ir_func_destroy(func);if(c)hb_context_destroy(c);
}

static const struct{const char *name;enum hb_gate_id id;} gates[]={
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
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original_host;
    check(HB_MXCSR_SUPPORTED_MASK==0xffbfu,"guest MXCSR admission mask unchanged; DAZ probes are internal only");
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *v=getenv(gates[i].name);if(v&&!check((saved[i]=strdup(v))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,"0",1)==0,"select private helper memory"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);if(!check(v&&!strcmp(v,"0"),"effective helper gate"))goto done;}
    if(!check(feholdexcept(&original_host)==0,"save and mask host fenv"))goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)for(size_t i=0;i<sizeof(forms)/sizeof(forms[0]);++i)
        run_form(&forms[i],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");
        hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v&&!strcmp(v,saved[i]):!v,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_round_instruction_test: %u executions, %u checks, %u failures\n",executions,checks,failures);
    printf("failure categories: numeric=%u upper=%u other=%u memory=%u execution=%u host=%u\n",category_failures[NUMERIC],category_failures[UPPER],category_failures[OTHER],category_failures[MEMORY],category_failures[EXECUTION],category_failures[HOST]);
    return failures?1:0;
}
