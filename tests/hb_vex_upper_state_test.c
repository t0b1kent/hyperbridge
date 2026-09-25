/* Raw decoded vector writes: legacy128 preserves higher storage, VEX128 clears
 * YMM/ZMM upper storage, VEX256 clears ZMM upper storage. These are internal
 * full-width state-consistency checks, not advertised AVX-512 parity: XCR0 stays
 * x86=3/x64=7. Unmasked EVEX256/512 controls cover both size maps; high-register
 * controls run x64 only. No masked EVEX, capability gating or native SIMD claim.
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

enum {PAGE_BYTES=16384};
enum {PS_DQ,PD_DQ,MOVE,XOR,STORE};
enum {LEGACY,VEX,EVEX};
enum {LOW_RESULT,UPPER_STATE,OTHER_STATE,MEMORY_RESULT,EXECUTION,HOST_FP,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x4400000),DATA=UINT64_C(0x5400000);
static unsigned checks,failures,executions,category_failures[CATEGORIES];
static char phase[160]="setup";

static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;
    if(!ok) {++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}
    return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,OTHER_STATE);}
static void put32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(v>>(8*i));}
static void put64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(v>>(8*i));}

typedef struct {
    const char *name;uint8_t code[8];unsigned n,kind,encoding,bytes,src_bytes,dst,src,left,memory,x64_only;
} form_t;
static const form_t forms[]={
    {"cvtps2dq xmm0,xmm1",{0x66,0x0f,0x5b,0xc1},4,PS_DQ,LEGACY,16,16,0,1,0,0,0},
    {"vcvtps2dq xmm0,xmm1",{0xc5,0xf9,0x5b,0xc1},4,PS_DQ,VEX,16,16,0,1,0,0,0},
    {"vcvtps2dq ymm0,ymm1",{0xc5,0xfd,0x5b,0xc1},4,PS_DQ,VEX,32,32,0,1,0,0,0},
    {"vcvtps2dq ymm0,ymm0 alias",{0xc5,0xfd,0x5b,0xc0},4,PS_DQ,VEX,32,32,0,0,0,0,0},
    {"vcvtps2dq ymm0,[rcx]",{0xc5,0xfd,0x5b,0x01},4,PS_DQ,VEX,32,32,0,0,0,1,0},
    {"cvtpd2dq xmm0,xmm1",{0xf2,0x0f,0xe6,0xc1},4,PD_DQ,LEGACY,16,16,0,1,0,0,0},
    {"vcvtpd2dq xmm0,xmm1",{0xc5,0xfb,0xe6,0xc1},4,PD_DQ,VEX,16,16,0,1,0,0,0},
    {"vcvtpd2dq xmm0,ymm1 narrowing",{0xc5,0xff,0xe6,0xc1},4,PD_DQ,VEX,16,32,0,1,0,0,0},
    {"vcvtpd2dq xmm1,ymm1 alias",{0xc5,0xff,0xe6,0xc9},4,PD_DQ,VEX,16,32,1,1,0,0,0},
    {"vcvtpd2dq xmm0,[rcx]",{0xc5,0xff,0xe6,0x01},4,PD_DQ,VEX,16,32,0,0,0,1,0},
    {"movups xmm0,xmm1",{0x0f,0x10,0xc1},3,MOVE,LEGACY,16,16,0,1,0,0,0},
    {"vmovups xmm0,xmm1",{0xc5,0xf8,0x10,0xc1},4,MOVE,VEX,16,16,0,1,0,0,0},
    {"vmovups ymm0,ymm1",{0xc5,0xfc,0x10,0xc1},4,MOVE,VEX,32,32,0,1,0,0,0},
    {"vmovups ymm1,ymm1 self-copy",{0xc5,0xfc,0x10,0xc9},4,MOVE,VEX,32,32,1,1,0,0,0},
    {"vmovups xmm0,[rcx]",{0xc5,0xf8,0x10,0x01},4,MOVE,VEX,16,16,0,0,0,1,0},
    {"vmovups ymm0,[rcx]",{0xc5,0xfc,0x10,0x01},4,MOVE,VEX,32,32,0,0,0,1,0},
    {"movups [rcx],xmm1",{0x0f,0x11,0x09},3,STORE,LEGACY,16,16,0,1,0,1,0},
    {"vmovups [rcx],xmm1",{0xc5,0xf8,0x11,0x09},4,STORE,VEX,16,16,0,1,0,1,0},
    {"vmovups [rcx],ymm1",{0xc5,0xfc,0x11,0x09},4,STORE,VEX,32,32,0,1,0,1,0},
    {"xorps xmm0,xmm2",{0x0f,0x57,0xc2},3,XOR,LEGACY,16,16,0,2,0,0,0},
    {"vxorps xmm0,xmm1,xmm2",{0xc5,0xf0,0x57,0xc2},4,XOR,VEX,16,16,0,2,1,0,0},
    {"vxorps ymm0,ymm1,ymm2",{0xc5,0xf4,0x57,0xc2},4,XOR,VEX,32,32,0,2,1,0,0},
    {"vxorps ymm1,ymm1,ymm2 alias-left",{0xc5,0xf4,0x57,0xca},4,XOR,VEX,32,32,1,2,1,0,0},
    {"vxorps ymm2,ymm1,ymm2 alias-right",{0xc5,0xf4,0x57,0xd2},4,XOR,VEX,32,32,2,2,1,0,0},
    {"vxorps ymm0,ymm0,ymm0 self-zero",{0xc5,0xfc,0x57,0xc0},4,XOR,VEX,32,32,0,0,0,0,0},
    {"vxorps ymm0,ymm1,[rcx]",{0xc5,0xf4,0x57,0x01},4,XOR,VEX,32,32,0,0,1,1,0},
    {"EVEX vmovups ymm0,ymm1",{0x62,0xf1,0x7c,0x28,0x10,0xc1},6,MOVE,EVEX,32,32,0,1,0,0,0},
    {"EVEX vmovups zmm0,zmm1",{0x62,0xf1,0x7c,0x48,0x10,0xc1},6,MOVE,EVEX,64,64,0,1,0,0,0},
    /* High-register encodings independently assembled by the parent; no x86
     * high-register forms exist. EVEX here exercises implemented state writers. */
    {"vmovups ymm8,ymm9",{0xc4,0x41,0x7c,0x10,0xc1},5,MOVE,VEX,32,32,8,9,0,0,1},
    {"vcvtps2dq ymm8,ymm9",{0xc4,0x41,0x7d,0x5b,0xc1},5,PS_DQ,VEX,32,32,8,9,0,0,1},
    {"EVEX vmovups ymm16,ymm17",{0x62,0xa1,0x7c,0x28,0x10,0xc1},6,MOVE,EVEX,32,32,16,17,0,0,1},
    {"EVEX vmovups zmm16,zmm17",{0x62,0xa1,0x7c,0x48,0x10,0xc1},6,MOVE,EVEX,64,64,16,17,0,0,1}
};

static uint64_t *low_reg(hb_context_t *ctx,unsigned reg)
{
    if(reg>=16)return ctx->xmm_ext[reg-16];
    return ctx->arch==HB_ARCH_X86?ctx->regs.x86.xmm[reg]:ctx->regs.x64.xmm[reg];
}
static uint64_t *mid_reg(hb_context_t *ctx,unsigned reg){return reg<16?ctx->ymm_hi[reg]:ctx->ymm_hi_ext[reg-16];}
static uint64_t *high_reg(hb_context_t *ctx,unsigned reg){return reg<16?ctx->zmm_hi[reg]:ctx->zmm_hi_ext[reg-16];}
static void get_vector(hb_context_t *ctx,unsigned reg,uint8_t out[64])
{
    memcpy(out,low_reg(ctx,reg),16);memcpy(out+16,mid_reg(ctx,reg),16);memcpy(out+32,high_reg(ctx,reg),32);
}
static void set_bytes(hb_context_t *ctx,unsigned reg,const uint8_t *input,unsigned bytes)
{
    memcpy(low_reg(ctx,reg),input,16);
    if(bytes>=32)memcpy(mid_reg(ctx,reg),input+16,16);
    if(bytes==64)memcpy(high_reg(ctx,reg),input+32,32);
}

static void seed(hb_context_t *ctx,uint64_t address)
{
    memset(&ctx->regs,0x3c,sizeof(ctx->regs));
    if(ctx->arch==HB_ARCH_X86) {
        ctx->regs.x86.ecx=(uint32_t)address;ctx->regs.x86.eip=(uint32_t)CODE;ctx->regs.x86.eflags=0xa57;
        memset(&ctx->x87_64,0x49,sizeof(ctx->x87_64));
    } else {ctx->regs.x64.rcx=address;ctx->regs.x64.rip=CODE;ctx->regs.x64.rflags=0xa57;}
    hb_x87_reset(hb_context_x87(ctx));
    for(unsigned reg=0;reg<32;++reg) {
        uint8_t bytes[64];for(unsigned i=0;i<64;++i)bytes[i]=(uint8_t)(0x31+17*reg+29*i);
        if(ctx->arch!=HB_ARCH_X86 || reg<8 || reg>=16)memcpy(low_reg(ctx,reg),bytes,16);
        memcpy(mid_reg(ctx,reg),bytes+16,16);memcpy(high_reg(ctx,reg),bytes+32,32);
    }
    for(unsigned i=0;i<sizeof(ctx->k)/sizeof(ctx->k[0]);++i)ctx->k[i]=UINT64_C(0x123456789abc0000)+i;
    ctx->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};
    memset(&ctx->lazy_flags,0,sizeof(ctx->lazy_flags));
    ctx->mxcsr=0x3f80;ctx->pc=CODE;ctx->last_result=HB_OK;
    ctx->last_fault_kind=HB_FAULT_KIND_NONE;ctx->last_fault_addr_valid=0;
    ctx->fs_base=0x11110000;ctx->gs_base=0x22220000;
    ctx->seg_cs=0x33;ctx->seg_ds=0x2b;ctx->seg_es=0x31;ctx->seg_fs=0x53;ctx->seg_gs=0x61;ctx->seg_ss=0x69;
    ctx->step_limit=8;ctx->block_limit=2;
}

static void inputs(hb_context_t *ctx,const form_t *f,uint8_t input[64],uint8_t output[64])
{
    static const uint32_t singles[]={0x3f800000,0xc0000000,0x40400000,0x40800000,0xc0a00000,0x40c00000,0x40e00000,0xc1000000};
    static const uint64_t doubles[]={UINT64_C(0x3ff0000000000000),UINT64_C(0xc000000000000000),UINT64_C(0x4008000000000000),UINT64_C(0x4010000000000000)};
    static const int32_t integers[]={1,-2,3,4,-5,6,7,-8};
    uint8_t left[64];memset(input,0,64);memset(output,0,64);
    if(f->kind==PS_DQ || f->kind==PD_DQ) {
        if(f->kind==PS_DQ)for(unsigned i=0;i<f->src_bytes/4;++i)put32(input+4*i,singles[i]);
        else for(unsigned i=0;i<f->src_bytes/8;++i)put64(input+8*i,doubles[i]);
        unsigned lanes=f->kind==PS_DQ?f->src_bytes/4:f->src_bytes/8;
        for(unsigned i=0;i<lanes;++i)put32(output+4*i,(uint32_t)integers[i]);
        if(!f->memory)set_bytes(ctx,f->src,input,f->src_bytes);
    } else {
        if(f->memory && f->kind!=STORE)for(unsigned i=0;i<64;++i)input[i]=(uint8_t)(0xe1+13*i);
        else get_vector(ctx,f->src,input);
        if(f->kind==XOR) {
            get_vector(ctx,f->left,left);
            for(unsigned i=0;i<f->bytes;++i)output[i]=left[i]^input[i];
        } else memcpy(output,input,f->bytes);
    }
}

static int opcode(const form_t *f)
{
    return f->kind==PS_DQ?HB_INS_CVTPS2DQ:f->kind==PD_DQ?HB_INS_CVTPD2DQ:f->kind==XOR?HB_INS_XORPS:HB_INS_SSE_MOV;
}
static int valid_decode(const form_t *f,const hb_decoded_t *d)
{
    if(d->len!=f->n || (int)d->opcode!=opcode(f) || d->op1.size!=f->bytes)return 0;
    if(f->kind==STORE) {
        if(!d->op1.is_mem)return 0;
    } else if(!d->op1.is_reg || d->op1.reg!=HB_REG_XMM0+(int)f->dst)return 0;
    if(f->encoding==EVEX && (!d->evex || d->evex_mask || d->evex_zero))return 0;
    if(f->kind==XOR && f->encoding!=LEGACY) {
        if(!d->op2.is_reg || d->op2.reg!=HB_REG_XMM0+(int)f->left || d->op2.size!=f->bytes || d->op3.size!=f->src_bytes)return 0;
        return f->memory?d->op3.is_mem:d->op3.is_reg && d->op3.reg==HB_REG_XMM0+(int)f->src;
    }
    if(d->op2.size!=f->src_bytes)return 0;
    return f->memory && f->kind!=STORE?d->op2.is_mem:d->op2.is_reg && d->op2.reg==HB_REG_XMM0+(int)f->src;
}

static void check_state(hb_context_t *ctx,hb_context_t *expected,const form_t *f)
{
    for(unsigned reg=0;reg<32;++reg) {
        if(ctx->arch==HB_ARCH_X86 && reg>=8 && reg<16) {
            check(!memcmp(mid_reg(ctx,reg),mid_reg(expected,reg),16) && !memcmp(high_reg(ctx,reg),high_reg(expected,reg),32),"inactive x86 upper-register storage preserved");
            continue;
        }
        uint8_t actual[64],want[64];get_vector(ctx,reg,actual);get_vector(expected,reg,want);
        if(f->kind!=STORE && reg==f->dst) {
            check_kind(!memcmp(actual,want,f->bytes),"independent low vector result/merge",LOW_RESULT);
            check_kind(!memcmp(actual+f->bytes,want+f->bytes,64-f->bytes),"destination upper state matches encoding width",UPPER_STATE);
        } else check(!memcmp(actual,want,64),"other complete vector register/source unchanged");
    }
    hb_context_t normalized;memcpy(&normalized,ctx,sizeof(normalized));
    for(unsigned i=0;i<(ctx->arch==HB_ARCH_X86?8u:16u);++i)memcpy(low_reg(&normalized,i),low_reg(expected,i),16);
    check(!memcmp(&normalized.regs,&expected->regs,sizeof(normalized.regs)),"GPR/x87 register state preserved");
    check(!memcmp(&ctx->x87_64,&expected->x87_64,sizeof(ctx->x87_64)),"x64 x87 state preserved");
    check(!memcmp(ctx->k,expected->k,sizeof(ctx->k)) && ctx->mxcsr==expected->mxcsr &&
          !memcmp(&ctx->flags,&expected->flags,sizeof(ctx->flags)) && !memcmp(&ctx->lazy_flags,&expected->lazy_flags,sizeof(ctx->lazy_flags)),"opmasks/MXCSR/integer flags preserved");
    check(ctx->fs_base==expected->fs_base && ctx->gs_base==expected->gs_base && ctx->seg_cs==expected->seg_cs &&
          ctx->seg_ds==expected->seg_ds && ctx->seg_es==expected->seg_es && ctx->seg_fs==expected->seg_fs &&
          ctx->seg_gs==expected->seg_gs && ctx->seg_ss==expected->seg_ss,"segment state preserved");
}

static int native_present(const hb_jit_runtime_t *jit)
{
    if(!jit || !jit->block_cache)return 0;
    for(size_t i=0;i<jit->block_cache->size;++i){const hb_block_cache_entry_t *e=&jit->block_cache->entries[i];
        if(e->valid && e->guest_addr==CODE && e->native_code && e->native_size)return 1;}
    return 0;
}

static void run_form(const form_t *f,hb_arch_t arch,hb_backend_t backend)
{
    hb_context_t *ctx=NULL,expected;hb_decoder_t *decoder=NULL;hb_ir_func_t *func=NULL;
    hb_interpreter_t *interp=NULL;hb_jit_runtime_t *jit=NULL;
    snprintf(phase,sizeof(phase),"%s %s %s setup",arch==HB_ARCH_X86?"x86":"x64",backend==HB_BACKEND_JIT?"JIT":"interp",f->name);
    ctx=hb_context_create(arch,backend);if(!check(ctx!=NULL,"create context"))goto done;
    ctx->memory=hb_memory_create(0);
    if(!check(ctx->memory && hb_memory_map_private(ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(ctx->memory,CODE,f->code,f->n)==HB_OK &&
              hb_memory_protect(ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK &&
              hb_memory_map_private(ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned private code/data"))goto done;
    hb_decoded_t d={0};hb_result_t decoded=arch==HB_ARCH_X86?hb_decode_x86(f->code,f->n,CODE,&d):hb_decode_x64(f->code,f->n,CODE,&d);
    if(!check_kind(decoded==HB_OK && valid_decode(f,&d),"decode declared opcode, destination/source widths and registers",EXECUTION))goto done;
    decoder=hb_decoder_create(arch,f->code,f->n,CODE);if(!check(decoder!=NULL,"create decoder"))goto done;
    hb_result_t lifted=arch==HB_ARCH_X86?hb_lift_func_x86(decoder,&func):hb_lift_func_x64(decoder,&func);
    if(!check_kind(lifted==HB_OK && func,"lift actual raw vector instruction",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)jit=hb_jit_runtime_create(ctx);else interp=hb_interpreter_create(ctx);
    if(!check(jit || interp,"create runtime"))goto done;
    unsigned access_count=f->memory && (f->kind!=STORE || f->bytes==32)?3:1;
    for(unsigned access=0;access<access_count;++access) {
        uint8_t input[64],output[64],memory[96],actual_memory[96];
        snprintf(phase,sizeof(phase),"%s %s %s access=%u",arch==HB_ARCH_X86?"x86":"x64",backend==HB_BACKEND_JIT?"JIT":"interp",f->name,access);
        seed(ctx,access==2?DATA+2*PAGE_BYTES:DATA+128);inputs(ctx,f,input,output);
        memset(memory,0xa5,sizeof(memory));
        if(f->kind!=STORE)memcpy(memory+16,input,64);
        if(!check(hb_memory_protect(ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
                  hb_memory_write(ctx->memory,DATA+112,memory,sizeof(memory))==HB_OK,"seed input/output guards"))goto done;
        if(access==1 && !check(hb_memory_protect(ctx->memory,DATA,PAGE_BYTES,f->kind==STORE?HB_PERM_READ:HB_PERM_WRITE)==HB_OK,"deny requested memory access"))goto done;
        memcpy(&expected,ctx,sizeof(expected));
        uint64_t xcr0=hb_xcr0_value(ctx,0);check(xcr0==(arch==HB_ARCH_X86?3u:7u),"existing XCR0 exposure unchanged; no AVX-512 capability claim");
        if(access==0) {
            if(f->kind==STORE)memcpy(memory+16,output,f->bytes);
            else {
                set_bytes(&expected,f->dst,output,f->bytes);
                if(f->encoding!=LEGACY) {
                    if(f->bytes==16)memset(mid_reg(&expected,f->dst),0,16);
                    if(f->bytes<=32)memset(high_reg(&expected,f->dst),0,32);
                }
            }
            expected.pc=CODE+f->n;
            if(arch==HB_ARCH_X86)expected.regs.x86.eip=(uint32_t)expected.pc;else expected.regs.x64.rip=expected.pc;
        }
        if(!check(fesetround(FE_UPWARD)==0 && feclearexcept(FE_ALL_EXCEPT)==0 && feraiseexcept(FE_DIVBYZERO)==0,"seed independent masked host fenv"))goto done;
        int host_status=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};
        hb_result_t result=jit?hb_jit_runtime_run(jit,func,&out):hb_interpreter_run(interp,func,&out);
        int actual_round=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);++executions;
        check_kind(actual_round==FE_UPWARD && actual_status==host_status,"exact-input guest operation preserves host fenv",HOST_FP);
        if(access==0)check_kind(result==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out && out.steps_executed &&
                               out.blocks_executed && ctx->pc==expected.pc,"complete guest instruction at exact end PC",EXECUTION);
        else {
            check_kind((result==HB_OK || result==HB_ERR_MEMORY_FAULT) && out.result==HB_ERR_MEMORY_FAULT && out.faulted && !out.timed_out,
                       "denied/unmapped operand reports memory fault",EXECUTION);
            /* Destination/data atomicity is tested; inherited fault-PC bookkeeping
             * is outside this instruction-family regression. */
            if(arch==HB_ARCH_X86)expected.regs.x86.eip=ctx->regs.x86.eip;else expected.regs.x64.rip=ctx->regs.x64.rip;
        }
        check_state(ctx,&expected,f);check(hb_xcr0_value(ctx,0)==xcr0,"guest operation leaves exposed XCR0 unchanged");
        check(hb_memory_protect(ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned page permissions");
        check_kind(hb_memory_read(ctx->memory,DATA+112,actual_memory,sizeof(actual_memory))==HB_OK &&
                   !memcmp(actual_memory,memory,sizeof(memory)),"independent memory result/input preservation and adjacent guards",MEMORY_RESULT);
    }
    if(jit)check_kind(native_present(jit),"JIT has native guest entry block (helper use allowed)",EXECUTION);
done:
    if(ctx && ctx->memory)(void)hb_memory_protect(ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE);
    if(jit)hb_jit_runtime_destroy(jit);if(interp)hb_interpreter_destroy(interp);
    if(decoder)hb_decoder_destroy(decoder);if(func)hb_ir_func_destroy(func);if(ctx)hb_context_destroy(ctx);
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
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *v=getenv(gates[i].name);if(v && !check((saved[i]=strdup(v))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,"0",1)==0,"select private helper memory"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);if(!check(v && !strcmp(v,"0"),"effective helper gate"))goto done;}
    if(!check(feholdexcept(&original_host)==0,"save and mask host fenv"))goto done;host_saved=1;
    for(unsigned arch=0;arch<2;++arch)for(unsigned backend=0;backend<2;++backend)
        for(size_t i=0;i<sizeof(forms)/sizeof(forms[0]);++i) {
            if(forms[i].x64_only && !arch)continue; /* Declared architectural register-file scope, not a decode skip. */
            run_form(&forms[i],arch?HB_ARCH_X64:HB_ARCH_X86,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
        }
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore original gate or absence");
        hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v && !strcmp(v,saved[i]):!v,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_vex_upper_state_test: %u executions, %u checks, %u failures\n",executions,checks,failures);
    printf("failure categories: low=%u upper=%u other=%u memory=%u execution=%u host=%u\n",category_failures[LOW_RESULT],
           category_failures[UPPER_STATE],category_failures[OTHER_STATE],category_failures[MEMORY_RESULT],category_failures[EXECUTION],category_failures[HOST_FP]);
    return failures?1:0;
}
