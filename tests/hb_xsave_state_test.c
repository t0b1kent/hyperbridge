/* M26 preparation: x64 standard XSAVE/XRSTOR, actual 0F AE /4 and /5.
 * 410 configurations x 4 masked host RC x 2 backends = 3280 calls.
 * No XSAVEOPT, compacted/supervisor state, x86 admission changes or AVX512.
 * Defined x87 raw state is checked; FIP/FDP/FOP and padding are excluded.
 * Header/MXCSR rejection before state mutation is an explicit engine contract.
 * Late read faults may partially restore selected components; late XSAVE
 * faults may partially write the image. Neither rollback is asserted.
 * JIT means a compiled entry, with the ordinary interpreter helper allowed.
 */
#include "hb_cpuid.h"
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

enum { PAGE_BYTES=16384,IMAGE_BYTES=832,WINDOW_BYTES=960 };
enum { NORMAL,LAST_EDGE,CROSS_RW,DENIED,CROSS_DENIED,CROSS_GAP,UNMAPPED,HEADER_ONLY,MEMORY_MODES };
enum { IMAGE,STATE,EXECUTION,HOST,FAULT,CAPABILITY,CATEGORIES };
enum { GOOD,BAD_BV_LOW,BAD_BV_HIGH,BAD_XCOMP_LOW,BAD_XCOMP_HIGH,BAD_RESERVED_LOW,BAD_RESERVED_HIGH,BAD_MXCSR_DAZ,BAD_MXCSR16,BAD_MXCSR31 };
static const uint64_t CODE=UINT64_C(0x5600000),DATA=UINT64_C(0x6600000);
static unsigned checks,failures,executions,completions,gp_cases,memory_fault_cases;
static unsigned save_cases,restore_cases,alignment_cases,header_cases,mxcsr_cases,memory_cases,category_failures[CATEGORIES];
static char phase[220]="setup";
static int check_kind(int ok,const char *what,unsigned category)
{++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)fprintf(stderr,"FAIL %s: %s\n",phase,what);}return ok;}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(8*i));}
static void put64(uint8_t *p,uint64_t n){for(unsigned i=0;i<8;++i)p[i]=(uint8_t)(n>>(8*i));}
static uint64_t get64(const uint8_t *p){uint64_t n=0;for(unsigned i=0;i<8;++i)n|=(uint64_t)p[i]<<(8*i);return n;}
typedef struct {uint64_t sig;uint16_t se;uint64_t preview;unsigned tag;} raw_t;
static const raw_t values[]={
    {UINT64_C(0x8000000000000000),0x3fff,UINT64_C(0x3ff0000000000000),0},
    {0,0x8000,UINT64_C(0x8000000000000000),1},
    {UINT64_C(0x8000000000000400),0x4034,UINT64_C(0x4340000000000000),0},
    {UINT64_C(0x8000000000000000),0x43ff,UINT64_C(0x7ff0000000000000),0},
    {UINT64_C(0x8000000000000000),0x3bcc,0,0},
    {UINT64_C(0xc000000000001234),0x7fff,UINT64_C(0x7ff8000000000002),2},
    {UINT64_C(0x8000000000000000),0xffff,UINT64_C(0xfff0000000000000),2},
    {1,0,0,2}
};
typedef struct {hb_context_t *c;hb_decoder_t *decoder;hb_ir_func_t *func;hb_interpreter_t *interp;hb_jit_runtime_t *jit;unsigned restore;uint8_t code[3];} fixture_t;
static uint64_t target_for(unsigned mode,unsigned offset)
{if(mode==LAST_EDGE)return DATA+2*PAGE_BYTES-IMAGE_BYTES;if(mode==CROSS_RW||mode==CROSS_DENIED)return DATA+PAGE_BYTES-576;if(mode==CROSS_GAP)return DATA+2*PAGE_BYTES-576;if(mode==UNMAPPED)return DATA+3*PAGE_BYTES;if(mode==HEADER_ONLY)return DATA+PAGE_BYTES-512;return DATA+128+offset;}
static int memory_fails(unsigned mode,unsigned mask)
{if(mode==DENIED||mode==UNMAPPED)return 1;if(mode==CROSS_DENIED||mode==CROSS_GAP)return !!(mask&4);if(mode==HEADER_ONLY)return mask!=0;return 0;}
static int malformed_header(unsigned bad){return bad>=BAD_BV_LOW&&bad<=BAD_RESERVED_HIGH;}
static int malformed_mxcsr(unsigned bad){return bad>=BAD_MXCSR_DAZ;}
static int gp_expected(unsigned offset,unsigned bad,unsigned mask)
{return offset!=0||malformed_header(bad)||(malformed_mxcsr(bad)&&(mask&6));}
static int restore_permissions(fixture_t *f)
{return check(hb_memory_protect(f->c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_protect(f->c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"restore owned permissions");}
static void set_raw(hb_x87_state_t *x,unsigned phys,const raw_t *r,unsigned occupied)
{memcpy(&x->st[phys],&r->preview,8);put64(x->st_ext[phys],r->sig);put16(x->st_ext[phys]+8,r->se);x->st_ext_valid|=(uint8_t)(1u<<phys);x->tag_word=(uint16_t)((x->tag_word&~(3u<<(2*phys)))|((occupied?r->tag:3u)<<(2*phys)));}
static uint64_t input_vector(unsigned reg,unsigned lane,unsigned high)
{return UINT64_C(0x1928374655aa00ff)^((uint64_t)reg<<40)^((uint64_t)lane<<24)^((uint64_t)high<<60);}
static void seed(fixture_t *f,unsigned mask,uint64_t target,unsigned top,uint32_t input_mxcsr)
{
    hb_context_t *c=f->c;memset(&c->regs,0x4b,sizeof(c->regs));c->regs.x64.rax=UINT64_C(0xdeadbeef00000000)|mask;c->regs.x64.rdx=UINT64_C(0xcafebabea5a5a5a5);c->regs.x64.rcx=target;c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57; /* AC=0 */
    for(unsigned i=0;i<16;++i)for(unsigned lane=0;lane<2;++lane){c->regs.x64.xmm[i][lane]=~input_vector(i,lane,0);c->ymm_hi[i][lane]=~input_vector(i,lane,1);}
    memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    hb_x87_state_t *x=hb_context_x87(c);hb_x87_reset(x);x->top=top;x->control_word=0x0b7f;x->status_word=(uint16_t)((top<<11)|0x4524);x->last_x87_ip=0x12345678;
    for(unsigned i=0;i<8;++i){unsigned phys=(top+i)&7;set_raw(x,phys,&values[(i+4)&7],(0x6du>>phys)&1u);}
    c->mxcsr=input_mxcsr^0x6000u;c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->last_fault_pc=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void input_image(uint8_t image[IMAGE_BYTES],unsigned top,uint64_t bv,uint32_t mxcsr,unsigned bad,unsigned save)
{
    for(unsigned i=0;i<IMAGE_BYTES;++i)image[i]=(uint8_t)(0xa7u^(i*11u));
    put16(image,0x037f);put16(image+2,(uint16_t)((((top+3)&7)<<11)|0x4100));image[4]=0xa5;
    put32(image+24,mxcsr);put32(image+28,0); /* Informational image mask must not govern validation. */
    for(unsigned i=0;i<8;++i){put64(image+32+16*i,values[i].sig);put16(image+40+16*i,values[i].se);}
    for(unsigned i=0;i<16;++i)for(unsigned lane=0;lane<2;++lane){put64(image+160+16*i+8*lane,input_vector(i,lane,0));put64(image+576+16*i+8*lane,input_vector(i,lane,1));}
    memset(image+512,0,64);put64(image+512,bv);
    /* XSAVE must preserve the rest of its header, even an old image that would
     * be invalid for XRSTOR. XSAVE does not validate incoming XCOMP_BV. */
    if(save)memset(image+520,0x6b,56);
    if(bad==BAD_BV_LOW)put64(image+512,bv|8);else if(bad==BAD_BV_HIGH)put64(image+512,bv|(UINT64_C(1)<<63));
    else if(bad==BAD_XCOMP_LOW)put64(image+520,1);else if(bad==BAD_XCOMP_HIGH)put64(image+520,UINT64_C(1)<<63);
    else if(bad==BAD_RESERVED_LOW)image[528]=1;else if(bad==BAD_RESERVED_HIGH)image[535]=0x80;
    else if(bad==BAD_MXCSR_DAZ)put32(image+24,mxcsr|0x40);else if(bad==BAD_MXCSR16)put32(image+24,mxcsr|0x10000);else if(bad==BAD_MXCSR31)put32(image+24,mxcsr|0x80000000u);
}
static void expected_save(const hb_context_t *before,unsigned mask,uint8_t image[IMAGE_BYTES],uint8_t known[IMAGE_BYTES])
{
    const hb_x87_state_t *x=&before->x87_64;memset(known,1,IMAGE_BYTES);
    if(mask&1){memset(known,0,24);memset(known+32,0,128);put16(image,x->control_word);put16(image+2,(uint16_t)((x->status_word&~0x3800u)|(x->top<<11)));image[4]=0;
        for(unsigned phys=0;phys<8;++phys)if(((x->tag_word>>(2*phys))&3u)!=3)image[4]|=(uint8_t)(1u<<phys);
        memset(known,1,5);for(unsigned i=0;i<8;++i){memcpy(image+32+16*i,x->st_ext[(x->top+i)&7],10);memset(known+32+16*i,1,10);}}
    if(mask&2)memcpy(image+160,before->regs.x64.xmm,256);
    if(mask&4)memcpy(image+576,before->ymm_hi,256);
    if(mask&6){put32(image+24,before->mxcsr);put32(image+28,HB_MXCSR_SUPPORTED_MASK);}
    /* Every selected component has deliberately noninitial live state. */
    put64(image+512,get64(image+512)|mask);
}
static void check_x87_loaded(hb_x87_state_t *x,unsigned top,unsigned initialized)
{
    unsigned wanted_top=initialized?0:(top+3)&7;uint16_t tag=0xffffu;uint8_t raw[10],want[10];
    check_kind(x->top==wanted_top&&x->control_word==0x037f&&x->status_word==(initialized?0:(uint16_t)((wanted_top<<11)|0x4100)),"selected x87 control/status/TOP restored or initialized",STATE);
    for(unsigned i=0;i<8;++i){unsigned phys=(wanted_top+i)&7;if(initialized){memset(want,0,10);}else{put64(want,values[i].sig);put16(want+8,values[i].se);if((0xa5u>>phys)&1u)tag=(uint16_t)((tag&~(3u<<(2*phys)))|(values[i].tag<<(2*phys)));}
        uint64_t bits;memcpy(&bits,&x->st[phys],8);check_kind(hb_x87_save_st_ext80(x,i,raw)==HB_OK&&!memcmp(raw,want,10)&&bits==(initialized?0:values[i].preview),"selected x87 exact raw payload and preview; includes empty slots",STATE);}
    check_kind(x->tag_word==tag,"selected x87 physical occupancy and raw classification",STATE);
}
static void check_state(fixture_t *f,const hb_context_t *before,unsigned mask,uint64_t bv,unsigned top,uint32_t image_mxcsr,unsigned gp,unsigned memfault)
{
    hb_context_t expected;memcpy(&expected,before,sizeof(expected));hb_x87_state_t *x=hb_context_x87(f->c),*e=hb_context_x87(&expected);
    if(f->restore&&!gp){
        if(mask&1){if(!memfault)check_x87_loaded(x,top,!(bv&1));/* Late selected-component read faults may partially commit. */memcpy(e,x,sizeof(*e));}
        if(mask&2)for(unsigned i=0;i<16;++i)for(unsigned lane=0;lane<2;++lane)expected.regs.x64.xmm[i][lane]=memfault?f->c->regs.x64.xmm[i][lane]:(bv&2)?input_vector(i,lane,0):0;
        if(mask&4)for(unsigned i=0;i<16;++i)for(unsigned lane=0;lane<2;++lane)expected.ymm_hi[i][lane]=memfault?f->c->ymm_hi[i][lane]:(bv&4)?input_vector(i,lane,1):0;
        if(mask&6)expected.mxcsr=memfault?f->c->mxcsr:image_mxcsr;
    }
    /* FIP bookkeeping and legacy pointer/opcode completeness are separate. */
    e->last_x87_ip=x->last_x87_ip;check(!memcmp(x,e,sizeof(*x)),"unrequested x87 preservation / prevalidation engine state contract");
    expected.regs.x64.rip=f->c->regs.x64.rip;check(!memcmp(&expected.regs,&f->c->regs,sizeof(expected.regs)),"GPR/flags and requested versus unrequested XMM state");
    check(!memcmp(expected.ymm_hi,f->c->ymm_hi,sizeof(expected.ymm_hi)),"all16 requested versus unrequested YMM high halves");
    check(expected.mxcsr==f->c->mxcsr,"MXCSR follows request bits1 OR2, independently of XSTATE_BV");
    check(!memcmp(&before->flags,&f->c->flags,sizeof(before->flags))&&!memcmp(&before->lazy_flags,&f->c->lazy_flags,sizeof(before->lazy_flags)),"integer flag state preserved");
    check(!memcmp(before->zmm_hi,f->c->zmm_hi,sizeof(before->zmm_hi))&&!memcmp(before->k,f->c->k,sizeof(before->k))&&!memcmp(before->xmm_ext,f->c->xmm_ext,sizeof(before->xmm_ext))&&!memcmp(before->ymm_hi_ext,f->c->ymm_hi_ext,sizeof(before->ymm_hi_ext))&&!memcmp(before->zmm_hi_ext,f->c->zmm_hi_ext,sizeof(before->zmm_hi_ext)),"unadvertised upper vector/opmask state preserved");
    check(f->c->fs_base==before->fs_base&&f->c->gs_base==before->gs_base&&f->c->seg_cs==before->seg_cs&&f->c->seg_ds==before->seg_ds&&f->c->seg_es==before->seg_es&&f->c->seg_fs==before->seg_fs&&f->c->seg_gs==before->seg_gs&&f->c->seg_ss==before->seg_ss,"segments preserved");
}
static void run_case(fixture_t *f,unsigned mask,uint64_t bv,unsigned host,unsigned mode,unsigned offset,unsigned bad)
{
    static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};static const uint32_t mxcsrs[]={0,0x1f80,0x5fa5,0xffbf};
    unsigned top=(mask+(unsigned)bv)&7,gp=gp_expected(offset,bad,mask),memfault=memory_fails(mode,mask);uint32_t mxcsr=mxcsrs[host];
    uint64_t target=target_for(mode,offset),guard=mode==UNMAPPED?DATA+64:target-64;size_t count=WINDOW_BYTES;if(guard+count>DATA+2*PAGE_BYTES)count=(size_t)(DATA+2*PAGE_BYTES-guard);
    uint8_t initial[WINDOW_BYTES],want[WINDOW_BYTES],actual[WINDOW_BYTES],image[IMAGE_BYTES],known[IMAGE_BYTES];
    snprintf(phase,sizeof(phase),"%s %s mask=%u bv=%llx host=%u memory=%u offset=%u bad=%u",f->jit?"JIT":"interp",f->restore?"XRSTOR":"XSAVE",mask,(unsigned long long)bv,host,mode,offset,bad);
    if(!restore_permissions(f))return;seed(f,mask,target,top,mxcsr);input_image(image,top,bv,mxcsr,bad,!f->restore);
    for(size_t i=0;i<count;++i)initial[i]=(uint8_t)(0xd3u^(i*7u));size_t image_offset=64,available=mode==UNMAPPED?0:count-image_offset;if(available>IMAGE_BYTES)available=IMAGE_BYTES;
    if(available)memcpy(initial+image_offset,image,available);memcpy(want,initial,count);
    hb_context_t before;memcpy(&before,f->c,sizeof(before));memset(known,1,sizeof(known));if(!f->restore&&!gp&&!memfault){expected_save(&before,mask,image,known);if(available)memcpy(want+image_offset,image,available);}
    if(!check(hb_memory_write(f->c->memory,guard,initial,count)==HB_OK,"seed owned image and outer canaries"))return;
    hb_perm_t denied=f->restore?HB_PERM_WRITE:HB_PERM_READ;uint64_t denied_base=mode==CROSS_DENIED?DATA+PAGE_BYTES:DATA;
    if(mode==DENIED||mode==CROSS_DENIED||mode==HEADER_ONLY)if(!check(hb_memory_protect(f->c->memory,denied_base,PAGE_BYTES,denied)==HB_OK,"select component permissions"))goto restore;
    if(!check(fesetround(host_modes[host])==0&&feclearexcept(FE_ALL_EXCEPT)==0&&feraiseexcept(FE_DIVBYZERO)==0,"seed masked standard host fenv"))goto restore;
    int wanted_flags=fetestexcept(FE_ALL_EXCEPT);hb_exec_result_t out={0};hb_result_t result=f->jit?hb_jit_runtime_run(f->jit,f->func,&out):hb_interpreter_run(f->interp,f->func,&out);
    int got_rc=fegetround(),got_flags=fetestexcept(FE_ALL_EXCEPT);++executions;if(gp)++gp_cases;else if(memfault)++memory_fault_cases;else ++completions;
    if(offset)++alignment_cases;else if(malformed_header(bad))++header_cases;else if(malformed_mxcsr(bad))++mxcsr_cases;else if(mode!=NORMAL)++memory_cases;else if(f->restore)++restore_cases;else ++save_cases;
    check_kind(got_rc==host_modes[host]&&got_flags==wanted_flags,"state transport preserves host RC and standard status",HOST);
    if(gp||memfault){hb_result_t wanted=gp?HB_ERR_EXEC_FAULT:HB_ERR_MEMORY_FAULT;check_kind((result==HB_OK||result==wanted)&&out.result==wanted&&out.faulted&&!out.timed_out,"expected isolated alignment/header/MXCSR or memory fault",EXECUTION);}
    else check_kind(result==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed&&f->c->pc==CODE+3,"one standard state instruction completes",EXECUTION);
    if(gp)check_kind(f->c->last_fault_kind==HB_FAULT_KIND_GENERAL_PROTECTION&&!f->c->last_fault_addr_valid&&f->c->last_fault_addr==0&&f->c->last_fault_pc==CODE,"precise general-protection metadata",FAULT);
    check_state(f,&before,mask,bv,top,mxcsr,gp,memfault);
restore:
    if(!restore_permissions(f))return;if(!check(hb_memory_read(f->c->memory,guard,actual,count)==HB_OK,"read back owned image and canaries"))return;
    unsigned mismatch=0;for(size_t i=0;i<count;++i){int inside=available&&i>=image_offset&&i<image_offset+available;
        if(inside&&!f->restore&&memfault)continue; /* No late XSAVE rollback assertion. */
        if(inside&&!f->restore&&!gp&&!memfault&&!known[i-image_offset])continue;
        if(actual[i]!=want[i])++mismatch;}
    check_kind(mismatch==0,f->restore?"source image and outer canaries untouched":"selected defined fields, unselected bytes/header and outer canaries",IMAGE);
}
static int native_present(fixture_t *f)
{if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;}
static void run_form(unsigned restore,hb_backend_t backend)
{
    fixture_t f={0};f.restore=restore;f.code[0]=0x0f;f.code[1]=0xae;f.code[2]=restore?0x29:0x21;f.c=hb_context_create(HB_ARCH_X64,backend);if(!check(f.c!=NULL,"create x64 fixture"))goto done;f.c->memory=hb_memory_create(0);
    uint32_t a,b,c,d;hb_cpuid_query(f.c,1,0,&a,&b,&c,&d);check_kind((c&((1u<<26)|(1u<<27)|(1u<<28)))==((1u<<26)|(1u<<27)|(1u<<28)),"retain advertised XSAVE/OSXSAVE/AVX",CAPABILITY);
    hb_cpuid_query(f.c,13,0,&a,&b,&c,&d);check_kind(a==7&&b==832&&c==832&&d==0&&hb_xcr0_value(f.c,0)==7,"advertised standard832-byte mask7 contract",CAPABILITY);
    hb_cpuid_query(f.c,13,2,&a,&b,&c,&d);check_kind(a==256&&b==576&&c==0&&d==0,"advertised AVX high-half component",CAPABILITY);
    if(!check(f.c->memory&&hb_memory_map_private(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f.c->memory,CODE,f.code,3)==HB_OK&&hb_memory_protect(f.c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK&&hb_memory_map_private(f.c->memory,DATA,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_map_private(f.c->memory,DATA+PAGE_BYTES,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK,"map owned code and data pages"))goto done;
    hb_decoded_t decoded={0};hb_result_t result=hb_decode_x64(f.code,3,CODE,&decoded);if(!check_kind(result==HB_OK&&decoded.len==3,"decode actual XSAVE/XRSTOR bytes",EXECUTION))goto done;
    /* Record old alias failure but keep executing that same raw instruction in
     * the reference library: behavioral evidence must not be skipped. */
    check_kind(decoded.opcode!=HB_INS_X87_FXSAVE&&decoded.opcode!=HB_INS_X87_FXRSTOR,"extended instruction retains distinct decoded semantics",EXECUTION);
    f.decoder=hb_decoder_create(HB_ARCH_X64,f.code,3,CODE);if(!check(f.decoder!=NULL,"create raw decoder"))goto done;
    result=hb_lift_func_x64(f.decoder,&f.func);if(!check_kind(result==HB_OK&&f.func,"lift raw state instruction",EXECUTION))goto done;
    if(backend==HB_BACKEND_JIT)f.jit=hb_jit_runtime_create(f.c);else f.interp=hb_interpreter_create(f.c);if(!check(f.jit||f.interp,"create execution backend"))goto done;
    static const uint64_t old_bv[]={0,1,2,4,7,UINT64_C(0x1000000000000000)};
    for(unsigned mask=0;mask<8;++mask)for(unsigned bv=0;bv<(restore?8:6);++bv)for(unsigned host=0;host<4;++host)run_case(&f,mask,restore?bv:old_bv[bv],host,NORMAL,0,GOOD);
    for(unsigned offset=1;offset<64;++offset)for(unsigned host=0;host<4;++host)run_case(&f,7,7,host,NORMAL,offset,GOOD);
    if(restore){for(unsigned bad=BAD_BV_LOW;bad<=BAD_RESERVED_HIGH;++bad)for(unsigned m=0;m<2;++m)for(unsigned host=0;host<4;++host)run_case(&f,m?7:0,7,host,NORMAL,0,bad);
        for(unsigned bad=BAD_MXCSR_DAZ;bad<=BAD_MXCSR31;++bad)for(unsigned mask=0;mask<8;++mask)for(unsigned bv=0;bv<2;++bv)for(unsigned host=0;host<4;++host)run_case(&f,mask,bv?7:0,host,NORMAL,0,bad);}
    for(unsigned mode=LAST_EDGE;mode<MEMORY_MODES;++mode)for(unsigned mask=0;mask<8;++mask)for(unsigned host=0;host<4;++host)run_case(&f,mask,7,host,mode,0,GOOD);
    if(f.jit)check_kind(native_present(&f),"native compiled entry exists; helper allowed",EXECUTION);uint8_t actual[3];check(hb_memory_read(f.c->memory,CODE,actual,3)==HB_OK&&!memcmp(actual,f.code,3),"raw instruction bytes preserved");
done:
    if(f.jit)hb_jit_runtime_destroy(f.jit);if(f.interp)hb_interpreter_destroy(f.interp);if(f.decoder)hb_decoder_destroy(f.decoder);if(f.func)hb_ir_func_destroy(f.func);if(f.c)hb_context_destroy(f.c);
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
    for(unsigned backend=0;backend<2;++backend)for(unsigned restore=0;restore<2;++restore)run_form(restore,backend?HB_BACKEND_JIT:HB_BACKEND_INTERP);
done:
    if(host_saved)check(fesetenv(&original_host)==0,"restore original host fenv");if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *s=hb_gate(gates[i].id);check(saved[i]?s&&!strcmp(s,saved[i]):!s,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_xsave_state_test: %u executions (%u expected completions, %u expected GP, %u expected memory faults), %u checks, %u failures\n",executions,completions,gp_cases,memory_fault_cases,checks,failures);
    printf("inputs: save=%u restore=%u alignment=%u header=%u mxcsr=%u memory=%u\n",save_cases,restore_cases,alignment_cases,header_cases,mxcsr_cases,memory_cases);
    printf("failure categories: image=%u state=%u execution=%u host=%u fault=%u capability=%u\n",category_failures[IMAGE],category_failures[STATE],category_failures[EXECUTION],category_failures[HOST],category_failures[FAULT],category_failures[CAPABILITY]);return failures?1:0;
}
