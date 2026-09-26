/* Hardware-derived vector-state corpus for HyperBridge on ARM64.
 * Checks all 32 vector registers: low128, bits128..255, bits256..511,
 * and 256 bytes of RAM, against absolute x86 results, separately for each backend.
 * Build comparator alone with -DHB_UPPER_COMPARATOR_ONLY on any host.
 * This does not prove native emission; --require-pair checks the fusion host map.
 */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifndef HB_UPPER_COMPARATOR_ONLY
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#endif

typedef struct { unsigned low, upper, memory; } differences;
static differences compare(const uint8_t *got,const uint8_t *expected,const uint8_t *gm,const uint8_t *em) {
    differences d={0};
    for(unsigned r=0;r<32;r++) for(unsigned q=0;q<8;q++) {
        if(memcmp(got+r*64+q*8,expected+r*64+q*8,8)) {
            if(q<2)d.low++;else d.upper++;
        }
    }
    if(memcmp(gm,em,256))d.memory++;
    return d;
}
static int self_test(void) {
    uint8_t expected[2048]={0},got[2048]={0},mem[256]={0};unsigned checked=0;
    for(unsigned r=0;r<32;r++)for(unsigned q=0;q<8;q++) {
        memcpy(got,expected,sizeof(got));got[r*64+q*8]^=1;
        differences d=compare(got,expected,mem,mem);
        if((q<2?(d.low!=1||d.upper):(d.upper!=1||d.low))||d.memory)return 1;
        checked++;
    }
    /* Both executors returning the same wrong state must still fail independently. */
    memset(got,0,sizeof(got));got[63]=1;
    differences a=compare(got,expected,mem,mem),b=compare(got,expected,mem,mem);
    if(!a.upper||!b.upper)return 1;
    printf("{\"self_test\":\"pass\",\"single_qword_mutations\":%u,\"identical_wrong_backends_detected\":true}\n",checked);
    return 0;
}
#ifndef HB_UPPER_COMPARATOR_ONLY
static void need(FILE*f,void*p,size_t n){if(fread(p,1,n,f)!=n){fprintf(stderr,"truncated corpus\n");exit(2);}}
static uint64_t read_le(FILE*f,unsigned n){uint8_t b[8];need(f,b,n);uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)b[i]<<(8*i);return v;}
static void set_vectors(hb_context_t*c,const uint8_t*p){
    for(unsigned r=0;r<16;r++) {
        memcpy(c->regs.x64.xmm[r],p+r*64,16);memcpy(c->ymm_hi[r],p+r*64+16,16);memcpy(c->zmm_hi[r],p+r*64+32,32);
        memcpy(c->xmm_ext[r],p+(r+16)*64,16);memcpy(c->ymm_hi_ext[r],p+(r+16)*64+16,16);memcpy(c->zmm_hi_ext[r],p+(r+16)*64+32,32);
    }
}
static void get_vectors(const hb_context_t*c,uint8_t*p){
    for(unsigned r=0;r<16;r++) {
        memcpy(p+r*64,c->regs.x64.xmm[r],16);memcpy(p+r*64+16,c->ymm_hi[r],16);memcpy(p+r*64+32,c->zmm_hi[r],32);
        memcpy(p+(r+16)*64,c->xmm_ext[r],16);memcpy(p+(r+16)*64+16,c->ymm_hi_ext[r],16);memcpy(p+(r+16)*64+32,c->zmm_hi_ext[r],32);
    }
}
static int show_diffs(const char*name,uint64_t seed,int k,const uint8_t*got,const uint8_t*expected) {
    unsigned printed=0;
    for(unsigned r=0;r<32;r++)for(unsigned q=0;q<8;q++)if(memcmp(got+r*64+q*8,expected+r*64+q*8,8)) {
        uint64_t g,e;memcpy(&g,got+r*64+q*8,8);memcpy(&e,expected+r*64+q*8,8);
        fprintf(stderr,"%s seed=%"PRIx64" %s zmm%u.q%u expected=%016"PRIx64" got=%016"PRIx64"\n",name,seed,k?"JIT":"INTERP",r,q,e,g);
        if(++printed==4)return 0;
    }
    return 0;
}
static int pair_is_fused(hb_context_t*c,hb_ir_func_t*func){
    if(!func->cfg||func->cfg->block_count!=1)return 0;
    hb_ir_block_t*b=func->cfg->blocks[0];
    if(b->instr_count!=2||b->instrs[0].op!=HB_IR_LOAD||b->instrs[1].op!=HB_IR_STORE)return 0;
    hb_arm64_codegen_t*cg=hb_arm64_codegen_create(c);hb_codegen_buffer_t*out=hb_codegen_buffer_create(65536);
    if(!cg||!out){if(cg)hb_arm64_codegen_destroy(cg);if(out)hb_codegen_buffer_destroy(out);return 0;}
    hb_result_t rc=hb_arm64_codegen_block_with_cfg(cg,b,func->cfg,out);
    int first=0,second=0;
    for(unsigned j=0;j<out->host_off_count;j++){if(out->host_instr[j]==0)first=1;if(out->host_instr[j]==1)second=1;}
    int ok=rc==HB_OK&&out->size&&first&&!second;
    hb_codegen_buffer_destroy(out);hb_arm64_codegen_destroy(cg);return ok;
}
static int run(const char*path,const char*filter,int exclude_mask,int require_pair) {
    FILE*f=fopen(path,"rb");if(!f){perror(path);return 2;}
    char magic[8];need(f,magic,8);if(memcmp(magic,"HBUP0001",8)){fprintf(stderr,"bad magic\n");fclose(f);return 2;}
    uint64_t total=read_le(f,4);if(total==0||total>100000){fprintf(stderr,"invalid case count\n");fclose(f);return 2;}
    const size_t slot=16384,stacksize=65536;
    uint8_t*code=mmap(NULL,(size_t)total*slot,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    uint8_t*stack=mmap(NULL,stacksize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    uint8_t*data[2]={mmap(NULL,slot,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0),mmap(NULL,slot,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0)};
    if(code==MAP_FAILED||stack==MAP_FAILED||data[0]==MAP_FAILED||data[1]==MAP_FAILED){perror("mmap");return 2;}
    hb_context_t*c[2]={hb_context_create(HB_ARCH_X64,HB_BACKEND_INTERP),hb_context_create(HB_ARCH_X64,HB_BACKEND_JIT)};
    hb_memory_t*m[2]={hb_memory_create(0),hb_memory_create(0)};
    hb_ir_func_t**keep=calloc((size_t)total,sizeof(*keep));if(!keep||!c[0]||!c[1]||!m[0]||!m[1])return 2;
    for(int k=0;k<2;k++) {
        c[k]->memory=m[k];c[k]->config.fallback_enabled=false;
        if(hb_memory_sync_live_range(m[k],(hb_gva_t)(uintptr_t)code,(size_t)total*slot,HB_PERM_READ|HB_PERM_WRITE|HB_PERM_EXEC)!=HB_OK ||
           hb_memory_sync_live_range(m[k],(hb_gva_t)(uintptr_t)stack,stacksize,HB_PERM_READ|HB_PERM_WRITE)!=HB_OK ||
           hb_memory_sync_live_range(m[k],(hb_gva_t)(uintptr_t)data[k],slot,HB_PERM_READ|HB_PERM_WRITE)!=HB_OK)return 2;
    }
    uint64_t selected=0,unsupported=0,fusion_unproven=0,ran[2]={0},low[2]={0},upper[2]={0},mem_bad[2]={0},execution_bad[2]={0};
    for(uint64_t i=0;i<total;i++) {
        unsigned nl=(unsigned)read_le(f,2),cl=(unsigned)read_le(f,2),kind=(unsigned)read_le(f,4);
        uint64_t seed=read_le(f,8),mask=read_le(f,8);
        if(!nl||nl>255||!cl||cl>64){fprintf(stderr,"invalid record\n");return 2;}
        char name[256];uint8_t bytes[64],in[2048],im[256],expected[2048],em[256];
        need(f,name,nl);name[nl]=0;need(f,bytes,cl);need(f,in,2048);need(f,im,256);need(f,expected,2048);need(f,em,256);
        if((filter&&!strstr(name,filter))||(exclude_mask&&kind==2))continue;selected++;
        uint8_t*at=code+(size_t)i*slot;memcpy(at,bytes,cl);uint64_t base=(uint64_t)(uintptr_t)at;
        hb_decoder_t*dec=hb_decoder_create(HB_ARCH_X64,at,cl,base);hb_ir_func_t*func=NULL;
        hb_result_t lr=dec?hb_lift_func_x64(dec,&func):HB_ERR_INTERNAL;if(dec)hb_decoder_destroy(dec);
        if(lr!=HB_OK||!func||func->has_unsupported){unsupported++;if(func)hb_ir_func_destroy(func);fprintf(stderr,"UNSUPPORTED %s\n",name);continue;}
        keep[i]=func;
        if(require_pair&&kind==1&&!pair_is_fused(c[1],func)){fusion_unproven++;fprintf(stderr,"FUSION_NOT_PROVEN %s\n",name);}
        for(int k=0;k<2;k++) {
            hb_context_t*x=c[k];memcpy(data[k],im,256);memset(&x->regs.x64,0,sizeof(x->regs.x64));
            x->pc=base;x->regs.x64.rip=base;x->regs.x64.rsp=(uint64_t)(uintptr_t)(stack+0x8000);
            x->regs.x64.rbx=(uint64_t)(uintptr_t)data[k];x->regs.x64.rdi=(uint64_t)(uintptr_t)(data[k]+128);
            x->regs.x64.rax=UINT64_C(0x12345678fedcba98);x->regs.x64.rflags=2;x->mxcsr=0x1f80;x->last_result=HB_OK;
            memset(x->k,0,sizeof(x->k));x->k[1]=mask;memset(&x->lazy_flags,0,sizeof(x->lazy_flags));set_vectors(x,in);
            hb_host_fpcr_apply_mxcsr(x->mxcsr);
            hb_exec_result_t out={0};hb_result_t rc=hb_runtime_run(x,func,k?HB_BACKEND_JIT:HB_BACKEND_INTERP,&out);
            ran[k]++;if(rc!=HB_OK||out.result!=HB_OK||out.faulted||out.timed_out||!out.steps_executed||x->pc!=base+cl){execution_bad[k]++;fprintf(stderr,"EXECUTION %s backend=%d rc=%d out=%d steps=%"PRIu64" pc=%"PRIx64"\n",name,k,rc,out.result,out.steps_executed,x->pc);}
            uint8_t got[2048];get_vectors(x,got);differences d=compare(got,expected,data[k],em);
            if(d.low)low[k]++;if(d.upper)upper[k]++;if(d.memory)mem_bad[k]++;
            if((d.low||d.upper)&&low[k]+upper[k]<=20)show_diffs(name,seed,k,got,expected);
        }
    }
    if(fgetc(f)!=EOF){fprintf(stderr,"trailing corpus bytes\n");return 2;}fclose(f);
    printf("{\"selected\":%"PRIu64",\"decode_lift_unsupported\":%"PRIu64",\"fusion_unproven\":%"PRIu64",\"backends\":[",selected,unsupported,fusion_unproven);
    for(int k=0;k<2;k++)printf("%s{\"backend\":\"%s\",\"executed\":%"PRIu64",\"low128_mismatch\":%"PRIu64",\"upper_mismatch\":%"PRIu64",\"memory_mismatch\":%"PRIu64",\"execution_error\":%"PRIu64"}",k?",":"",k?"JIT":"INTERP",ran[k],low[k],upper[k],mem_bad[k],execution_bad[k]);puts("]}");
    for(int k=0;k<2;k++){c[k]->memory=NULL;hb_context_destroy(c[k]);hb_memory_destroy(m[k]);munmap(data[k],slot);}
    for(uint64_t i=0;i<total;i++)if(keep[i])hb_ir_func_destroy(keep[i]);free(keep);munmap(code,(size_t)total*slot);munmap(stack,stacksize);
    if(!selected||unsupported||fusion_unproven)return 2;
    return (low[0]+low[1]+upper[0]+upper[1]+mem_bad[0]+mem_bad[1]+execution_bad[0]+execution_bad[1])?1:0;
}
#endif
int main(int argc,char**argv){
    if(argc==2&&!strcmp(argv[1],"--self-test"))return self_test();
#ifdef HB_UPPER_COMPARATOR_ONLY
    fprintf(stderr,"comparator-only build: use --self-test\n");return 2;
#else
    const char*filter=NULL;int exclude=0,require=0;
    if(argc<2){fprintf(stderr,"usage: hb_upper_state_test corpus [--filter substring] [--exclude-mask] [--require-pair]\n");return 2;}
    for(int i=2;i<argc;i++) {
        if(!strcmp(argv[i],"--filter")&&i+1<argc)filter=argv[++i];
        else if(!strcmp(argv[i],"--exclude-mask"))exclude=1;
        else if(!strcmp(argv[i],"--require-pair"))require=1;
        else{fprintf(stderr,"bad argument: %s\n",argv[i]);return 2;}
    }
    return run(argv[1],filter,exclude,require);
#endif
}
