/* Independent FX x87 register-image oracles. FTW bits name physical R0..R7;
 * 16-byte register slots contain logical ST0..ST7. Only the ten defined ext80
 * bytes are compared, including payloads whose tag is empty. FIP/FDP/FOP and
 * reserved image bytes are outside this test. No Wine or native x86 execution.
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

enum { PAGE_BYTES=16384, IMAGE_BYTES=512, INPUT=0x100, OUTPUT=0x500, INTEGER=0x900, RESULT=0xa00 };
static const uint64_t CODE=UINT64_C(0x4400000), DATA=UINT64_C(0x5400000);
static unsigned checks, failures, executions;
static char phase[160]="setup";

static int check(int ok, const char *what)
{
    ++checks;
    if (!ok) { ++failures; if (failures <= 100) fprintf(stderr,"FAIL %s: %s\n",phase,what); }
    return ok;
}

static void put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v) { for(unsigned i=0;i<4;++i) p[i]=(uint8_t)(v>>(8*i)); }
static void put64(uint8_t *p, uint64_t v) { for(unsigned i=0;i<8;++i) p[i]=(uint8_t)(v>>(8*i)); }
typedef struct { uint64_t sig; uint16_t se; unsigned tag; } ext_t;
static const ext_t nine={UINT64_C(0x9000000000000000),0x4002,0};
static const ext_t exact_integer={UINT64_C(0x8000000000000400),0x4034,0}; /* 2^53+1 */
static const ext_t raw_values[] = {
    {UINT64_C(0x8000000000000001),0x3fff,0}, /* 1+2^-63 */
    {UINT64_C(0x8000000000000000),0x43ff,0}, /* normal 2^1024 */
    {UINT64_C(0x8000000000000000),0x0001,0}, /* smallest normal ext80 */
    {UINT64_C(0xc123456789abcdef),0x7fff,2}, /* quiet NaN payload */
    {UINT64_C(0x8123456789abcdef),0x7fff,2}, /* signaling NaN payload */
    {UINT64_C(0x0000000000000000),0x8000,1}, /* negative zero */
    {UINT64_C(0x0000000000000001),0x0000,2}, /* smallest ext80 subnormal */
    {UINT64_C(0x8000000000000000),0x3bcc,0}, /* 2^-1075: half smallest binary64 subnormal */
    {UINT64_C(0x8000000000000001),0x3bcc,0}  /* just above that half */
};
static void put_ext(uint8_t p[10], ext_t v) { put64(p,v.sig); put16(p+8,v.se); }

typedef struct {
    unsigned top;
    uint8_t ftw;
    uint16_t full_tag, cw, sw;
    ext_t logical[8];
} image_state_t;

static image_state_t uniform_nine(void)
{
    image_state_t s={.top=7,.ftw=0xff,.full_tag=0,.cw=0x037f,.sw=0x3900};
    for(unsigned i=0;i<8;++i) s.logical[i]=nine;
    return s;
}

static image_state_t diverse_state(unsigned profile)
{
    /* For TOP5: R5=normal, R7=zero, R1=special are the occupied sparse slots.
     * Explicit physical tag answers prevent two inverse mapping bugs cancelling. */
    image_state_t s={.top=5,.ftw=0xa2,.full_tag=0x73fb,.cw=0x027f,.sw=0x2900};
    s.logical[0]=nine;
    s.logical[1]=raw_values[0];
    s.logical[2]=(ext_t){0,0,1};
    s.logical[3]=raw_values[1];
    s.logical[4]=(ext_t){UINT64_C(0x8000000000000000),0xffff,2}; /* -infinity */
    s.logical[5]=raw_values[2];
    s.logical[6]=exact_integer;
    s.logical[7]=raw_values[3];
    if(profile==1) { s.ftw=0xff; s.full_tag=0x4208; }
    if(profile==2) { s.top=3; s.ftw=0; s.full_tag=0xffff; s.sw=0x1900; }
    return s;
}

static uint64_t xmm_bits(unsigned reg,unsigned half)
{
    return UINT64_C(0x9123456789abcdef) ^ ((uint64_t)reg<<36) ^ ((uint64_t)half<<61);
}

static void make_image(uint8_t image[IMAGE_BYTES],const image_state_t *s,uint32_t mxcsr)
{
    memset(image,0x6c,IMAGE_BYTES);
    put16(image,s->cw); put16(image+2,s->sw); image[4]=s->ftw;
    put32(image+0x18,mxcsr); put32(image+0x1c,0xffbf);
    for(unsigned i=0;i<8;++i) put_ext(image+0x20+16*i,s->logical[i]);
    for(unsigned i=0;i<16;++i) {
        put64(image+0xa0+16*i,xmm_bits(i,0)); put64(image+0xa8+16*i,xmm_bits(i,1));
    }
}

static void seed_context(hb_context_t *ctx)
{
    memset(&ctx->regs,0x3c,sizeof(ctx->regs));
    if(ctx->arch==HB_ARCH_X86) {
        ctx->regs.x86.eax=(uint32_t)(DATA+INPUT); ctx->regs.x86.ecx=(uint32_t)(DATA+INTEGER);
        ctx->regs.x86.edx=(uint32_t)(DATA+RESULT); ctx->regs.x86.edi=(uint32_t)(DATA+OUTPUT);
        ctx->regs.x86.eip=(uint32_t)CODE; ctx->regs.x86.eflags=0xa57;
    } else {
        ctx->regs.x64.rax=DATA+INPUT; ctx->regs.x64.rcx=DATA+INTEGER;
        ctx->regs.x64.rdx=DATA+RESULT; ctx->regs.x64.rdi=DATA+OUTPUT;
        ctx->regs.x64.rip=CODE; ctx->regs.x64.rflags=0xa57;
    }
    hb_x87_reset(hb_context_x87(ctx));
    memset(ctx->ymm_hi,0x7a,sizeof(ctx->ymm_hi)); memset(ctx->zmm_hi,0x4b,sizeof(ctx->zmm_hi));
    memset(ctx->k,0x39,sizeof(ctx->k)); memset(ctx->xmm_ext,0x51,sizeof(ctx->xmm_ext));
    memset(ctx->ymm_hi_ext,0x62,sizeof(ctx->ymm_hi_ext)); memset(ctx->zmm_hi_ext,0x73,sizeof(ctx->zmm_hi_ext));
    ctx->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};
    memset(&ctx->lazy_flags,0,sizeof(ctx->lazy_flags));
    ctx->mxcsr=0x3f82; ctx->pc=CODE;
    ctx->fs_base=0x11110000; ctx->gs_base=0x22220000;
    ctx->seg_cs=0x33; ctx->seg_ds=0x2b; ctx->seg_es=0x31;
    ctx->seg_fs=0x53; ctx->seg_gs=0x61; ctx->seg_ss=0x69;
    ctx->step_limit=32; ctx->block_limit=4;
}

static int native_present(const hb_jit_runtime_t *jit,uint64_t pc)
{
    if(!jit || !jit->block_cache) return 0;
    for(size_t i=0;i<jit->block_cache->size;++i) {
        const hb_block_cache_entry_t *e=&jit->block_cache->entries[i];
        if(e->valid && e->guest_addr==pc && e->native_code && e->native_size) return 1;
    }
    return 0;
}

static int execute(hb_context_t *ctx,hb_backend_t backend,const uint8_t *code,size_t n,
                   const int *opcodes,size_t count,uint64_t pc,int expect_fault,int check_host)
{
    hb_decoder_t *decoder=NULL; hb_ir_func_t *func=NULL;
    hb_interpreter_t *interp=NULL; hb_jit_runtime_t *jit=NULL;
    int completed=0;
    if(!check(hb_memory_protect(ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(ctx->memory,pc,code,n)==HB_OK &&
              hb_memory_protect(ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map actual guest bytes")) goto done;
    size_t offset=0;
    for(size_t i=0;i<count;++i) {
        hb_decoded_t d={0};
        hb_result_t r=ctx->arch==HB_ARCH_X86 ? hb_decode_x86(code+offset,n-offset,pc+offset,&d)
                                           : hb_decode_x64(code+offset,n-offset,pc+offset,&d);
        if(!check(r==HB_OK && d.len && d.len<=n-offset && (int)d.opcode==opcodes[i],"decode expected raw x87/FX instruction")) goto done;
        offset+=d.len;
    }
    if(!check(offset==n,"decode consumes complete sequence")) goto done;
    decoder=hb_decoder_create(ctx->arch,code,n,pc);
    if(!check(decoder!=NULL,"create decoder")) goto done;
    hb_result_t lifted=ctx->arch==HB_ARCH_X86 ? hb_lift_func_x86(decoder,&func) : hb_lift_func_x64(decoder,&func);
    if(!check(lifted==HB_OK && func,"lift actual guest sequence")) goto done;
    ctx->pc=pc;
    if(ctx->arch==HB_ARCH_X86) ctx->regs.x86.eip=(uint32_t)pc; else ctx->regs.x64.rip=pc;
    if(backend==HB_BACKEND_JIT) jit=hb_jit_runtime_create(ctx); else interp=hb_interpreter_create(ctx);
    if(!check(jit || interp,"create runtime")) goto done;
    if(check_host && !check(fesetround(FE_UPWARD)==0 && feclearexcept(FE_ALL_EXCEPT)==0 &&
                            feraiseexcept(FE_DIVBYZERO)==0,"seed masked host rounding/status")) goto done;
    int host_round=fegetround(),host_status=fetestexcept(FE_ALL_EXCEPT);
    hb_exec_result_t out={0};
    hb_result_t r=jit ? hb_jit_runtime_run(jit,func,&out) : hb_interpreter_run(interp,func,&out);
    int actual_round=fegetround(),actual_status=fetestexcept(FE_ALL_EXCEPT);
    ++executions;
    if(check_host) check(actual_round==host_round && actual_status==host_status,"FX sequence preserves host FP rounding and flags");
    if(jit) check(native_present(jit,pc),"JIT contains native guest entry block");
    if(expect_fault) completed=check((r!=HB_OK || out.result!=HB_OK) && out.faulted && !out.timed_out,
                                    "empty FISTP reports existing execution error");
    else completed=check(r==HB_OK && out.result==HB_OK && !out.faulted && !out.timed_out &&
                         out.steps_executed && out.blocks_executed && ctx->pc==pc+n,
                         "complete actual guest sequence at expected PC");
done:
    if(jit) hb_jit_runtime_destroy(jit);
    if(interp) hb_interpreter_destroy(interp);
    if(decoder) hb_decoder_destroy(decoder);
    if(func) hb_ir_func_destroy(func);
    return completed;
}

static void check_unrelated(const hb_context_t *ctx,const hb_context_t *before,int restored,int fault)
{
    hb_context_t expected; memcpy(&expected,before,sizeof(expected));
    if(ctx->arch==HB_ARCH_X86) {
        expected.regs.x86.eip=ctx->regs.x86.eip;
        /* Defined x87 fields are checked separately; FIP and fault-status details
         * are not smuggled into the unrelated-register comparison. */
        memcpy(&expected.regs.x86.x87,&ctx->regs.x86.x87,sizeof(ctx->regs.x86.x87));
    } else expected.regs.x64.rip=ctx->regs.x64.rip;
    if(restored) for(unsigned i=0;i<(ctx->arch==HB_ARCH_X86 ? 8u:16u);++i) {
        uint64_t *xmm=ctx->arch==HB_ARCH_X86 ? expected.regs.x86.xmm[i] : expected.regs.x64.xmm[i];
        xmm[0]=xmm_bits(i,0); xmm[1]=xmm_bits(i,1);
    }
    check(!memcmp(&ctx->regs,&expected.regs,sizeof(ctx->regs)),"GPRs and defined XMM restore/preservation");
    check(!memcmp(&ctx->flags,&before->flags,sizeof(ctx->flags)) &&
          !memcmp(&ctx->lazy_flags,&before->lazy_flags,sizeof(ctx->lazy_flags)),"guest integer flags preserved");
    check(!memcmp(ctx->ymm_hi,before->ymm_hi,sizeof(ctx->ymm_hi)) && !memcmp(ctx->zmm_hi,before->zmm_hi,sizeof(ctx->zmm_hi)) &&
          !memcmp(ctx->k,before->k,sizeof(ctx->k)) && !memcmp(ctx->xmm_ext,before->xmm_ext,sizeof(ctx->xmm_ext)) &&
          !memcmp(ctx->ymm_hi_ext,before->ymm_hi_ext,sizeof(ctx->ymm_hi_ext)) &&
          !memcmp(ctx->zmm_hi_ext,before->zmm_hi_ext,sizeof(ctx->zmm_hi_ext)),"extended vectors and opmasks preserved");
    check(ctx->fs_base==before->fs_base && ctx->gs_base==before->gs_base && ctx->seg_cs==before->seg_cs &&
          ctx->seg_ds==before->seg_ds && ctx->seg_es==before->seg_es && ctx->seg_fs==before->seg_fs &&
          ctx->seg_gs==before->seg_gs && ctx->seg_ss==before->seg_ss,"segment state preserved");
    check(ctx->mxcsr==(restored ? 0x5fa1u:before->mxcsr),"MXCSR is restored or preserved exactly");
    (void)fault;
}

static void check_restored(const hb_context_t *ctx,const image_state_t *s,int popped,int fault)
{
    const hb_x87_state_t *x=hb_context_x87((hb_context_t *)ctx);
    check(x->control_word==s->cw,"restored x87 control word");
    if(!fault) {
        unsigned top=popped ? (s->top+1)&7 : s->top;
        uint16_t tag=popped ? (uint16_t)(s->full_tag | (3u<<(2*s->top))) : s->full_tag;
        check(x->top==top && x->tag_word==tag,"physical tag reconstruction and logical TOP/pop");
        if(!popped) check(x->status_word==s->sw,"restored status word including nonzero TOP");
    }
    for(unsigned i=0;i<8;++i) {
        unsigned phys=(s->top+i)&7;
        uint8_t expected[10]; put_ext(expected,s->logical[i]);
        check((x->st_ext_valid&(1u<<phys)) && !memcmp(x->st_ext[phys],expected,10),
              "all physical ext80 cache payloads replaced, including empty tags");
    }
}

static void check_saved(const uint8_t image[IMAGE_BYTES],const image_state_t *s,uint32_t mxcsr,
                        const hb_context_t *source)
{
    uint8_t expected[IMAGE_BYTES]; make_image(expected,s,mxcsr);
    check(!memcmp(image,expected,4) && image[4]==s->ftw,"saved CW/SW and physical abridged FTW");
    check(!memcmp(image+0x18,expected+0x18,8),"saved MXCSR and supported mask");
    for(unsigned i=0;i<8;++i) check(!memcmp(image+0x20+16*i,expected+0x20+16*i,10),
                                   "saved exact logical ext80 slot including empty payload");
    for(unsigned i=0;i<(source->arch==HB_ARCH_X86 ? 8u:16u);++i) {
        const uint64_t *xmm=source->arch==HB_ARCH_X86 ? source->regs.x86.xmm[i] : source->regs.x64.xmm[i];
        check(!memcmp(image+0xa0+16*i,xmm,16),"saved mode-specific XMM bytes");
    }
}

enum { STALE_I64,CLEAN_I64,EXACT_I64,RESTORE_SAVE,DIRECT_SAVE,RESTORE_FSTP,EMPTY_FISTP,FILD_SAVE,
       FRSTOR_SAVE,FNSAVE_DIRECT,FRSTOR_I64,OVERFLOW_SAVE,EMPTY_FLDZ,OVERFLOW_FLDZ,UNCACHED_SUBNORMAL_SAVE };
static const char *kind_names[]={"cached7 restore9 fistp","clean restore9 fistp","restore exact2^53+1 fistp",
    "independent restore/save","independent physical save","restore/fstp80","empty restore/fistp error","fild exact2^53+1 then save",
    "legacy frstor/fxsave","legacy fnsave/reset","legacy frstor exact integer","masked full-stack fild/fxsave",
    "empty-stack fldz/fxsave","masked full-stack fldz/fxsave","uncached smallest binary64 subnormal save"};

static void run_case(unsigned kind,unsigned variant,hb_arch_t arch,hb_backend_t backend)
{
    uint8_t expected_memory[PAGE_BYTES],actual_memory[PAGE_BYTES];
    hb_context_t *ctx=NULL,before;
    image_state_t s=(kind==RESTORE_SAVE || kind==DIRECT_SAVE || kind==EMPTY_FISTP || kind==FRSTOR_SAVE || kind==FNSAVE_DIRECT)
                       ? diverse_state(variant) : uniform_nine();
    int restored=kind==STALE_I64 || kind==CLEAN_I64 || kind==EXACT_I64 || kind==RESTORE_SAVE || kind==RESTORE_FSTP || kind==EMPTY_FISTP;
    int legacy_restored=kind==FRSTOR_SAVE || kind==FRSTOR_I64;
    int saves=kind==RESTORE_SAVE || kind==DIRECT_SAVE || kind==FILD_SAVE || kind==FRSTOR_SAVE || kind==FNSAVE_DIRECT ||
              kind==OVERFLOW_SAVE || kind==EMPTY_FLDZ || kind==OVERFLOW_FLDZ || kind==UNCACHED_SUBNORMAL_SAVE;
    int popped=kind==STALE_I64 || kind==CLEAN_I64 || kind==EXACT_I64 || kind==RESTORE_FSTP || kind==FRSTOR_I64;
    int fault=kind==EMPTY_FISTP;
    if(kind==EXACT_I64 || kind==FRSTOR_I64) s.logical[0]=exact_integer;
    if(kind==RESTORE_FSTP) { s.logical[0]=raw_values[variant]; s.full_tag=(uint16_t)(raw_values[variant].tag<<14); }
    /* Unmask invalid-operation so empty FISTP must fault before conversion or
     * store. Masked empty FISTP's indefinite-integer behavior is a separate gap. */
    if(kind==EMPTY_FISTP) s.cw=(uint16_t)(s.cw & ~1u);
    /* Deliberately classify a normal payload as zero in the legacy input.
     * FRSTOR uses only empty/nonempty and must reconstruct its classification;
     * FNSAVE, independently, must serialize the current full tag word. */
    if(kind==FRSTOR_SAVE || kind==FNSAVE_DIRECT) s.full_tag=0x77fb;
    if(kind==OVERFLOW_SAVE || kind==OVERFLOW_FLDZ) { s.top=0; s.sw=0; }
    if(kind==UNCACHED_SUBNORMAL_SAVE) {
        s=(image_state_t){.top=7,.ftw=0x80,.full_tag=0x3fff,.cw=0x037f,.sw=0x3800};
        s.logical[0]=(ext_t){UINT64_C(0x8000000000000000),0x3bcd,0}; /* 16383-1074 */
    }
    snprintf(phase,sizeof(phase),"%s %s %s variant=%u",arch==HB_ARCH_X86?"x86":"x64",
             backend==HB_BACKEND_JIT?"JIT":"interp",kind_names[kind],variant);
    memset(expected_memory,0xa5,sizeof(expected_memory));
    make_image(expected_memory+INPUT,&s,0x5fa1);
    if(legacy_restored) {
        memset(expected_memory+INPUT,0x6c,108);
        put16(expected_memory+INPUT,s.cw); put16(expected_memory+INPUT+4,s.sw); put16(expected_memory+INPUT+8,s.full_tag);
        for(unsigned i=0;i<8;++i) put_ext(expected_memory+INPUT+28+10*i,s.logical[i]);
    }
    /* Keep 0x77fb in the input image; restored physical R5 is normal, not zero. */
    if(kind==FRSTOR_SAVE) s.full_tag=0x73fb;
    put64(expected_memory+INTEGER,kind==FILD_SAVE ? UINT64_C(9007199254740993):7);
    ctx=hb_context_create(arch,backend);
    if(!check(ctx!=NULL,"create context")) goto done;
    ctx->memory=hb_memory_create(0);
    if(!check(ctx->memory && hb_memory_map_private(ctx->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_map_private(ctx->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK &&
              hb_memory_write(ctx->memory,DATA,expected_memory,sizeof(expected_memory))==HB_OK,"map isolated private pages")) goto done;
    seed_context(ctx);
    if(kind==DIRECT_SAVE || kind==FNSAVE_DIRECT || kind==OVERFLOW_SAVE || kind==OVERFLOW_FLDZ) {
        hb_x87_state_t *x=hb_context_x87(ctx);
        x->top=s.top; x->tag_word=s.full_tag; x->control_word=s.cw; x->status_word=s.sw; x->st_ext_valid=0xff;
        for(unsigned i=0;i<8;++i) {
            unsigned phys=(s.top+i)&7;
            x->st[phys]=1000.0+(double)phys; /* Deliberately disagrees with exact cache. */
            put_ext(x->st_ext[phys],s.logical[i]);
        }
    }
    if(kind==UNCACHED_SUBNORMAL_SAVE) {
        hb_x87_state_t *x=hb_context_x87(ctx); uint64_t subnormal=1;
        x->top=7; x->tag_word=s.full_tag; x->control_word=s.cw; x->status_word=s.sw;
        memcpy(&x->st[7],&subnormal,sizeof(subnormal));
        check(x->st_ext_valid==0,"uncached save oracle exercises binary64-to-ext80 path");
    }
    if(kind==FILD_SAVE || kind==OVERFLOW_SAVE || kind==EMPTY_FLDZ || kind==OVERFLOW_FLDZ) {
        int fldz=kind==EMPTY_FLDZ || kind==OVERFLOW_FLDZ;
        const uint8_t seed_code[]={fldz?0xd9:0xdf,fldz?0xee:0x29};
        const int op[]={fldz?HB_INS_X87_FLD:HB_INS_X87_FILD};
        /* FILD's legacy binary64 preview cast is outside FX host-fenv scope. */
        if(!execute(ctx,backend,seed_code,sizeof(seed_code),op,1,CODE,0,fldz)) goto done;
        if(kind==FILD_SAVE) {
            check(hb_context_x87(ctx)->top==7 && (hb_context_x87(ctx)->st_ext_valid&0x80),"real FILD seeds exact physical R7 cache");
            s=(image_state_t){.top=7,.ftw=0x80,.full_tag=0x3fff,.cw=0x037f,.sw=0x3800};
            s.logical[0]=exact_integer;
        } else if(kind==EMPTY_FLDZ) {
            s=(image_state_t){.top=7,.ftw=0x80,.full_tag=0x7fff,.cw=0x037f,.sw=0x3800};
            hb_x87_state_t *x=hb_context_x87(ctx); uint8_t zero[10]={0};
            check(x->top==7 && x->tag_word==0x7fff && x->status_word==0x3800 &&
                  (x->st_ext_valid&0x80) && !memcmp(x->st_ext[7],zero,10),"normal FLDZ installs exact zero and zero tag");
        } else {
            s=uniform_nine(); s.sw=0x3a41; s.full_tag=0x8000;
            s.logical[0]=(ext_t){UINT64_C(0xc000000000000000),0xffff,2};
            hb_x87_state_t *x=hb_context_x87(ctx); uint8_t indefinite[10]; put_ext(indefinite,s.logical[0]);
            check(x->top==7 && x->tag_word==0x8000 && x->status_word==0x3a41,
                  "masked full-stack push installs special tag and IE/SF/C1 status");
            check(!(x->st_ext_valid&0x80) || !memcmp(x->st_ext[7],indefinite,10),
                  "masked overflow invalidates stale exact cache or installs indefinite");
        }
    }
    memcpy(&before,ctx,sizeof(before));
    uint8_t code[12]; int opcodes[4]; size_t n=0,count=0;
    if(kind==STALE_I64) { code[n++]=0xdf; code[n++]=0x29; opcodes[count++]=HB_INS_X87_FILD; }
    if(restored) { code[n++]=0x0f; code[n++]=0xae; code[n++]=0x08; opcodes[count++]=HB_INS_X87_FXRSTOR; }
    if(legacy_restored) { code[n++]=0xdd; code[n++]=0x20; opcodes[count++]=HB_INS_X87_FRSTOR; }
    if(kind==FNSAVE_DIRECT) { code[n++]=0xdd; code[n++]=0x37; opcodes[count++]=HB_INS_X87_FNSAVE; }
    else if(saves) { code[n++]=0x0f; code[n++]=0xae; code[n++]=0x07; opcodes[count++]=HB_INS_X87_FXSAVE; }
    else if(kind==RESTORE_FSTP) { code[n++]=0xdb; code[n++]=0x3a; opcodes[count++]=HB_INS_X87_FSTP; }
    else { code[n++]=0xdf; code[n++]=0x3a; opcodes[count++]=HB_INS_X87_FISTP; }
    if(!execute(ctx,backend,code,n,opcodes,count,CODE+0x100,fault,1)) goto done;
    check_unrelated(ctx,&before,restored,fault);
    if(restored || legacy_restored) check_restored(ctx,&s,popped,fault);
    else if(kind==FNSAVE_DIRECT) {
        hb_x87_state_t *x=hb_context_x87(ctx);
        check(x->control_word==0x037f && x->status_word==0 && x->tag_word==0xffff && x->top==0,
              "FNSAVE resets defined x87 control/status/tags/TOP after writing");
    }
    else check(!memcmp(hb_context_x87(ctx),hb_context_x87(&before),sizeof(hb_x87_state_t)),"FXSAVE leaves complete x87 source state unchanged");
    if(kind==RESTORE_FSTP && (variant<=2 || variant==5 || variant>=6)) {
        static const uint64_t preview[]={UINT64_C(0x3ff0000000000000),UINT64_C(0x7ff0000000000000),0,
            0,0,UINT64_C(0x8000000000000000),0,0,1};
        uint64_t actual; memcpy(&actual,&hb_context_x87(ctx)->st[7],sizeof(actual));
        check(actual==preview[variant],"integer-built binary64 preview handles normal range and subnormal ties");
    }
    if(kind==EMPTY_FISTP) {
        uint8_t ext[10];
        check(hb_x87_st_ext80(hb_context_x87(ctx),0,ext)!=HB_OK,"empty tag prevents exact-cache integer bypass");
    }
    if(!check(hb_memory_read(ctx->memory,DATA,actual_memory,sizeof(actual_memory))==HB_OK,"read result page")) goto done;
    if(saves) {
        size_t save_bytes=kind==FNSAVE_DIRECT ? 108 : IMAGE_BYTES;
        if(kind==FNSAVE_DIRECT) {
            uint8_t word[2];
            put16(word,s.cw); check(!memcmp(actual_memory+OUTPUT,word,2),"FNSAVE 108-byte image control word");
            put16(word,s.sw); check(!memcmp(actual_memory+OUTPUT+4,word,2),"FNSAVE 108-byte image status/TOP");
            put16(word,s.full_tag); check(!memcmp(actual_memory+OUTPUT+8,word,2),"FNSAVE preserves full physical tag word");
            for(unsigned i=0;i<8;++i) { uint8_t ext[10]; put_ext(ext,s.logical[i]);
                check(!memcmp(actual_memory+OUTPUT+28+10*i,ext,10),"FNSAVE exact logical ext80 slot including empty payload"); }
        } else check_saved(actual_memory+OUTPUT,&s,restored?0x5fa1:before.mxcsr,ctx);
        /* Reserved/metadata bytes inside the save area are deliberately outside
         * the oracle; every byte outside the entire area must be unchanged. */
        check(!memcmp(actual_memory,expected_memory,OUTPUT) &&
              !memcmp(actual_memory+OUTPUT+save_bytes,expected_memory+OUTPUT+save_bytes,PAGE_BYTES-OUTPUT-save_bytes),
              "save does not mutate source image or surrounding memory");
    } else {
        if(kind==RESTORE_FSTP) put_ext(expected_memory+RESULT,s.logical[0]);
        else if(!fault) put64(expected_memory+RESULT,(kind==EXACT_I64 || kind==FRSTOR_I64)?UINT64_C(9007199254740993):9);
        check(!memcmp(actual_memory,expected_memory,sizeof(actual_memory)),"exact consumer result, input image and guards unchanged");
    }
done:
    if(ctx) hb_context_destroy(ctx);
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
    char *saved[sizeof(gates)/sizeof(gates[0])]={0}; size_t saved_count=0;
    fenv_t original_host; int changed=0,host_saved=0;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i) {
        const char *v=getenv(gates[i].name);
        if(v && !check((saved[i]=strdup(v))!=NULL,"save gate")) goto done;
        ++saved_count;
    }
    changed=1;
    for(size_t i=0;i<saved_count;++i) if(!check(setenv(gates[i].name,"0",1)==0,"select helper memory")) goto done;
    hb_env_refresh();
    for(size_t i=0;i<saved_count;++i) { const char *v=hb_gate(gates[i].id); if(!check(v && !strcmp(v,"0"),"effective helper gate")) goto done; }
    if(!check(feholdexcept(&original_host)==0,"save and mask host fenv")) goto done;
    host_saved=1;
    for(unsigned a=0;a<2;++a) for(unsigned b=0;b<2;++b) {
        hb_arch_t arch=a?HB_ARCH_X64:HB_ARCH_X86; hb_backend_t backend=b?HB_BACKEND_JIT:HB_BACKEND_INTERP;
        run_case(STALE_I64,0,arch,backend); run_case(CLEAN_I64,0,arch,backend); run_case(EXACT_I64,0,arch,backend);
        for(unsigned profile=0;profile<3;++profile) { run_case(RESTORE_SAVE,profile,arch,backend); run_case(DIRECT_SAVE,profile,arch,backend); }
        for(unsigned value=0;value<sizeof(raw_values)/sizeof(raw_values[0]);++value) run_case(RESTORE_FSTP,value,arch,backend);
        run_case(EMPTY_FISTP,2,arch,backend); run_case(FILD_SAVE,0,arch,backend);
        run_case(FRSTOR_SAVE,0,arch,backend); run_case(FNSAVE_DIRECT,0,arch,backend);
        run_case(FRSTOR_I64,0,arch,backend); run_case(OVERFLOW_SAVE,0,arch,backend);
        run_case(EMPTY_FLDZ,0,arch,backend); run_case(OVERFLOW_FLDZ,0,arch,backend);
        run_case(UNCACHED_SUBNORMAL_SAVE,0,arch,backend);
    }
done:
    snprintf(phase,sizeof(phase),"cleanup");
    if(host_saved) check(fesetenv(&original_host)==0,"restore original host fenv");
    if(changed) {
        for(size_t i=0;i<saved_count;++i) check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore original gate or absence");
        hb_env_refresh();
        for(size_t i=0;i<saved_count;++i) {const char *v=hb_gate(gates[i].id);check(saved[i]?v && !strcmp(v,saved[i]):!v,"effective original gate restored");}
    }
    for(size_t i=0;i<saved_count;++i) free(saved[i]);
    printf("hb_fxstate_x87_test: %u executions, %u checks, %u failures\n",executions,checks,failures);
    return failures?1:0;
}
