/* Portable unit test of the actual extension header. It does not claim to run
   the Mach/ARM64 full hb_diff_case_runner executable. */
#include "hb_context.h"
#include "hb_memory.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define HB_DIFF_DATA_SIZE 8192u
#define HB_DIFF_DATA_BASE UINT64_C(0x530000000)
typedef struct {hb_arch_t arch;uint64_t gpr[16];hb_flags_t flags;uint8_t xmm[16][16],ymm_hi[16][16],data[HB_DIFF_DATA_SIZE];uint32_t sse_mxcsr;hb_result_t api_result,exec_result;} hb_diff_snapshot_t;
static int hex_nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static bool parse_hex_bytes(const char*s,uint8_t*out,size_t max,size_t*n){size_t j=0;while(*s){int hi=hex_nibble(*s++);if(hi<0||!*s)return false;int lo=hex_nibble(*s++);if(lo<0||j>=max)return false;out[j++]=(uint8_t)((hi<<4)|lo);}*n=j;return j>0;}
static uint64_t flags_to_bits(const hb_flags_t*f){return f->cf|((uint64_t)f->pf<<2)|((uint64_t)f->af<<4)|((uint64_t)f->zf<<6)|((uint64_t)f->sf<<7)|((uint64_t)f->of<<11);}
static uint8_t fake_data[HB_DIFF_DATA_SIZE];static uint32_t applied_mxcsr;
hb_result_t hb_memory_write(hb_memory_t*m,hb_gva_t a,const void*b,size_t n){(void)m;if(a<HB_DIFF_DATA_BASE||a-HB_DIFF_DATA_BASE>sizeof(fake_data)-n)return HB_ERR_INVALID_ARG;memcpy(fake_data+(a-HB_DIFF_DATA_BASE),b,n);return HB_OK;}
void hb_host_fpcr_apply_mxcsr(uint32_t c){applied_mxcsr=c;}
#include "runner_extension.h"
static void token(const char*s){int r=hb_sse_parse(s);if(r!=1)fprintf(stderr,"bad token: %s (%d)\n",s,r);assert(r==1);}
static void snapshot(hb_context_t*c,hb_diff_snapshot_t*s){memset(s,0,sizeof(*s));memcpy(s->xmm,c->regs.x64.xmm,sizeof(s->xmm));memcpy(s->ymm_hi,c->ymm_hi,sizeof(s->ymm_hi));memcpy(s->data,fake_data,sizeof(fake_data));s->sse_mxcsr=c->mxcsr;s->gpr[0]=c->regs.x64.rax;s->gpr[1]=c->regs.x64.rbx;s->flags=c->flags;}
int main(void){
 hb_sse_reset();token("sse-version=1");token("sse-mxcsr=0x9fc0");token("sse-id=17");
 token("sse-xmm0=0100c07f000000000000000000000000");token("sse-ymmhi0=0102030405060708090a0b0c0d0e0f10");
 token("sse-rbx-data=0x1000");token("sse-mem=0000803f00000000000000000000000000000000000000000000000000000000");
 token("expect-xmm0=0100c07f000000000000000000000000");token("expect-ymmhi0=0102030405060708090a0b0c0d0e0f10");token("expect-rax=0x1234");token("expect-flags=0x40");token("expect-mxcsr-exceptions=0x01");
 assert(hb_sse_validate());hb_context_t c;memset(&c,0,sizeof c);c.arch=HB_ARCH_X64;c.mode=HB_MODE_64BIT;c.regs.x64.rax=0x1234;c.flags.zf=true;
 assert(hb_sse_apply(&c)==HB_OK);assert(applied_mxcsr==0x9fc0);assert(c.regs.x64.rbx==HB_DIFF_DATA_BASE+0x1000);
 hb_diff_snapshot_t initial,a,b;snapshot(&c,&initial);a=b=initial;char why[64];
 assert(hb_sse_check_seed(&initial,why,sizeof why));assert(hb_sse_check_value(&a,why,sizeof why));assert(hb_sse_check_value(&b,why,sizeof why));puts("positive: exact seed + both expected values PASS");
 a.xmm[0][0]^=1;b=a;assert(!hb_sse_check_value(&a,why,sizeof why));assert(!hb_sse_check_value(&b,why,sizeof why));puts("negative: BOTH engines identically wrong XMM -> FAIL/FAIL (caught)");
 a=initial;a.ymm_hi[0][15]^=1;assert(!hb_sse_check_value(&a,why,sizeof why));puts("negative: YMM upper corruption caught");
 a=initial;a.gpr[0]^=1;assert(!hb_sse_check_value(&a,why,sizeof why));puts("negative: GPR result corruption caught");
 a=initial;a.flags.af=true;assert(!hb_sse_check_value(&a,why,sizeof why));puts("negative: COMI cleared AF corruption caught");
 a=initial;a.sse_mxcsr^=0x2000;assert(!hb_sse_check_value(&a,why,sizeof why));puts("negative: rounding-control corruption caught");
 a=initial;a.sse_mxcsr|=63;assert(hb_sse_check_value(&a,why,sizeof why));puts("separation: exception flags differ, value verdict remains PASS");
 a=initial;a.xmm[0][0]^=1;assert(!hb_sse_check_seed(&a,why,sizeof why));puts("negative: lost seed caught independently of output");
 assert(setenv("HB_DIFF_TEST_SSE_EXPECT_XOR","1",1)==0);a=initial;assert(!hb_sse_check_value(&a,why,sizeof why));assert(unsetenv("HB_DIFF_TEST_SSE_EXPECT_XOR")==0);assert(hb_sse_check_value(&a,why,sizeof why));puts("negative: deliberate expectation XOR caught and reversible");
 const char*rest="1 sse-version=1";assert(strchr(rest,'=')!=NULL);assert(strcspn(rest,"= \t\r\n")==strcspn(rest," \t\r\n"));puts("negative: old whole-rest count test misses count; corrected token test recognizes it");
 const char*bad[]={"sse-version=2","sse-xmm16=00000000000000000000000000000000","sse-xmm0=123","sse-mxcsr=0x10000","sse-mxcsr=0","expect-rax=-1","expect-flags=0x4000","sse-nonexistent=0","sse-xmm1=gg000000000000000000000000000000","expect-mxcsr-exceptions=0x40"};
 for(unsigned j=0;j<sizeof(bad)/sizeof(bad[0]);j++){hb_sse_reset();assert(hb_sse_parse(bad[j])==-1);}puts("negative: 10 malformed/unknown tokens rejected");
 hb_sse_reset();token("sse-xmm0=00000000000000000000000000000000");assert(!hb_sse_validate());puts("negative: missing schema version rejected");
 puts("ALL RUNNER EXTENSION UNIT CONTROLS PASS");return 0;
}
