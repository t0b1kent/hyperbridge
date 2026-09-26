#ifndef HB_SSE_ORACLE_RUNNER_EXTENSION_H
#define HB_SSE_ORACLE_RUNNER_EXTENSION_H
/* Included by hb_diff_case_runner.c after snapshot and hex parser definitions.
 * Absolute hardware expectations are checked independently on BOTH engines.
 * MXCSR exception bits are diagnostic, never a numerical pass/fail criterion. */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>

typedef struct {
    unsigned touched, version, xm, ym, exm, eym;
    uint8_t xmm[16][16], ymm[16][16], expect_xmm[16][16], expect_ymm[16][16];
    uint8_t mem[32];
    unsigned has_mem, has_rbx_offset, has_mxcsr, has_rax, has_flags, has_exc;
    uint64_t id, rbx_offset, expect_rax, expect_flags, flag_mask;
    uint32_t mxcsr, expect_exc;
} hb_sse_case_t;
static hb_sse_case_t g_hb_sse;
static void hb_sse_reset(void) { memset(&g_hb_sse,0,sizeof(g_hb_sse));g_hb_sse.flag_mask=0x8d5; }
static int hb_sse_u64(const char*s,uint64_t*out) {
    if(!s||!*s||*s=='-'||*s=='+')return 0;
    char*end;errno=0;unsigned long long v=strtoull(s,&end,0);
    if(errno||*end)return 0;*out=(uint64_t)v;return 1;
}
static int hb_sse_hex16(const char*s,uint8_t*out) {
    size_t n=0;return strlen(s)==32&&parse_hex_bytes(s,out,16,&n)&&n==16;
}
/* 1: consumed; 0: not our field; -1: malformed/unknown oracle field. */
static int hb_sse_parse(const char*tok) {
    const char*eq=strchr(tok,'=');uint64_t v=0;hb_sse_case_t*c=&g_hb_sse;
    if(strncmp(tok,"sse-",4)&&strncmp(tok,"expect-",7))return 0;
    c->touched=1;if(!eq)return -1;
    struct vec_field {const char*prefix;uint8_t(*data)[16];unsigned*mask;} fs[]={
      {"sse-xmm",c->xmm,&c->xm},{"sse-ymmhi",c->ymm,&c->ym},
      {"expect-xmm",c->expect_xmm,&c->exm},{"expect-ymmhi",c->expect_ymm,&c->eym}};
    for(unsigned k=0;k<4;k++){
        size_t n=strlen(fs[k].prefix);
        if(!strncmp(tok,fs[k].prefix,n)){
            const char*p=tok+n;unsigned reg=0;if(p==eq)return -1;
            for(;p<eq;p++){if(*p<'0'||*p>'9'||reg>15)return -1;reg=reg*10+(*p-'0');}
            if(reg>15||(*fs[k].mask&(1u<<reg))||!hb_sse_hex16(eq+1,fs[k].data[reg]))return -1;
            *fs[k].mask|=1u<<reg;return 1;
        }
    }
    if(!strncmp(tok,"sse-mem=",8)){
        size_t n=0;if(c->has_mem||strlen(eq+1)!=64||!parse_hex_bytes(eq+1,c->mem,32,&n)||n!=32)return -1;c->has_mem=1;return 1;
    }
    if(!hb_sse_u64(eq+1,&v))return -1;
#define SSE_KEY(k) ((size_t)(eq-tok)==strlen(k)&&!strncmp(tok,k,strlen(k)))
    if(SSE_KEY("sse-version")){if(c->version||v!=1)return -1;c->version=1;}
    else if(SSE_KEY("sse-id"))c->id=v;
    else if(SSE_KEY("sse-rbx-data")){if(c->has_rbx_offset||v>HB_DIFF_DATA_SIZE-32)return -1;c->has_rbx_offset=1;c->rbx_offset=v;}
    else if(SSE_KEY("sse-mxcsr")){if(c->has_mxcsr||v>0xffff||(v&0x1f80)!=0x1f80||(v&63))return -1;c->has_mxcsr=1;c->mxcsr=(uint32_t)v;}
    else if(SSE_KEY("expect-rax")){if(c->has_rax)return -1;c->has_rax=1;c->expect_rax=v;}
    else if(SSE_KEY("expect-flags")){if(c->has_flags||v&~UINT64_C(0x8d5))return -1;c->has_flags=1;c->expect_flags=v;}
    else if(SSE_KEY("expect-flags-mask")){if(v&~UINT64_C(0x8d5))return -1;c->flag_mask=v;}
    else if(SSE_KEY("expect-mxcsr-exceptions")){if(c->has_exc||v>63)return -1;c->has_exc=1;c->expect_exc=(uint32_t)v;}
    else return -1;
#undef SSE_KEY
    return 1;
}
static int hb_sse_validate(void){
    const hb_sse_case_t*c=&g_hb_sse;
    return !c->touched||(c->version==1&&c->has_mxcsr&&(c->xm&1)&&(c->ym&1)&&
           (c->exm&1)&&(c->eym&1)&&c->has_rax&&c->has_flags&&c->has_exc&&
           (!c->has_mem||c->has_rbx_offset));
}
static hb_result_t hb_sse_apply(hb_context_t*ctx) {
    const hb_sse_case_t*c=&g_hb_sse;if(!c->touched)return HB_OK;
    unsigned n=ctx->mode==HB_MODE_32BIT?8:16;
    if((c->xm|c->ym|c->exm|c->eym)&~((1u<<n)-1))return HB_ERR_INVALID_ARG;
    for(unsigned j=0;j<n;j++){
        if(c->xm&(1u<<j))memcpy(ctx->mode==HB_MODE_32BIT?ctx->regs.x86.xmm[j]:ctx->regs.x64.xmm[j],c->xmm[j],16);
        if(c->ym&(1u<<j))memcpy(ctx->ymm_hi[j],c->ymm[j],16);
    }
    if(c->has_rbx_offset){uint64_t addr=HB_DIFF_DATA_BASE+c->rbx_offset;if(ctx->mode==HB_MODE_32BIT)ctx->regs.x86.ebx=(uint32_t)addr;else ctx->regs.x64.rbx=addr;}
    if(c->has_mem){hb_result_t r=hb_memory_write(ctx->memory,HB_DIFF_DATA_BASE+c->rbx_offset,c->mem,32);if(r!=HB_OK)return r;}
    if(c->has_mxcsr){ctx->mxcsr=c->mxcsr;hb_host_fpcr_apply_mxcsr(ctx->mxcsr);}
    return HB_OK;
}
typedef struct{uint64_t control,status;} hb_sse_host_state_t;
static hb_sse_host_state_t hb_sse_host_save(void){
    hb_sse_host_state_t s={0,0};
#if defined(__aarch64__)
    __asm__ volatile("mrs %0, fpcr":"=r"(s.control));__asm__ volatile("mrs %0, fpsr":"=r"(s.status));
#elif defined(__x86_64__)
    uint32_t csr;__asm__ volatile("stmxcsr %0":"=m"(csr));s.control=csr;s.status=csr&63;
#endif
    return s;
}
static void hb_sse_host_restore(hb_sse_host_state_t s){
#if defined(__aarch64__)
    __asm__ volatile("msr fpcr, %0\n\tisb"::"r"(s.control):"memory");__asm__ volatile("msr fpsr, %0"::"r"(s.status):"memory");
#elif defined(__x86_64__)
    uint32_t csr=(uint32_t)s.control;__asm__ volatile("ldmxcsr %0"::"m"(csr):"memory");
#else
    (void)s;
#endif
}
static int hb_sse_check_seed(const hb_diff_snapshot_t*s,char*why,size_t n){
    const hb_sse_case_t*c=&g_hb_sse;if(!c->touched)return 1;
    for(unsigned j=0;j<16;j++){
      if((c->xm&(1u<<j))&&memcmp(s->xmm[j],c->xmm[j],16)){snprintf(why,n,"sse-seed-xmm%u",j);return 0;}
      if((c->ym&(1u<<j))&&memcmp(s->ymm_hi[j],c->ymm[j],16)){snprintf(why,n,"sse-seed-ymmhi%u",j);return 0;}
    }
    if(c->has_mxcsr&&s->sse_mxcsr!=c->mxcsr){snprintf(why,n,"sse-seed-mxcsr");return 0;}
    if(c->has_rbx_offset&&s->gpr[1]!=HB_DIFF_DATA_BASE+c->rbx_offset){snprintf(why,n,"sse-seed-rbx");return 0;}
    if(c->has_mem&&memcmp(s->data+c->rbx_offset,c->mem,32)){snprintf(why,n,"sse-seed-memory");return 0;}
    return 1;
}
static int hb_sse_check_value(const hb_diff_snapshot_t*s,char*why,size_t n){
    const hb_sse_case_t*c=&g_hb_sse;if(!c->touched)return 1;
    if(s->api_result!=HB_OK||s->exec_result!=HB_OK){snprintf(why,n,"sse-execution-error");return 0;}
    for(unsigned j=0;j<16;j++){
        if(c->exm&(1u<<j)){
          uint8_t e[16];memcpy(e,c->expect_xmm[j],16);
          const char*bad=getenv("HB_DIFF_TEST_SSE_EXPECT_XOR");if(j==0&&bad&&!strcmp(bad,"1"))e[0]^=1;
          if(memcmp(s->xmm[j],e,16)){snprintf(why,n,"expect-xmm%u",j);return 0;}
        }
        if((c->eym&(1u<<j))&&memcmp(s->ymm_hi[j],c->expect_ymm[j],16)){snprintf(why,n,"expect-ymmhi%u",j);return 0;}
    }
    if(c->has_rax&&s->gpr[0]!=c->expect_rax){snprintf(why,n,"expect-rax");return 0;}
    if(c->has_flags&&((flags_to_bits(&s->flags)^c->expect_flags)&c->flag_mask)){snprintf(why,n,"expect-flags");return 0;}
    if(c->has_mxcsr&&((s->sse_mxcsr^c->mxcsr)&0xffc0)){snprintf(why,n,"expect-mxcsr-control");return 0;}
    return 1;
}
static void hb_sse_json(const hb_diff_snapshot_t*a,const hb_diff_snapshot_t*b,int si,int vi,int vj,int interp_only){
    if(!g_hb_sse.touched)return;
    printf("\"sse_oracle\":{\"id\":%" PRIu64 ",\"seed_ok\":%s,\"interp_values_ok\":%s,\"jit_values_ok\":",g_hb_sse.id,si?"true":"false",vi?"true":"false");
    if(interp_only)printf("null");else printf("%s",vj?"true":"false");
    printf(",\"mxcsr_expected_exc\":%u,\"interp_mxcsr_exc\":%u,\"jit_mxcsr_exc\":%u},",g_hb_sse.expect_exc,a->sse_mxcsr&63,b->sse_mxcsr&63);
}
#endif
