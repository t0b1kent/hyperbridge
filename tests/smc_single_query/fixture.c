#include "hb_runtime.h"
#include "hb_memory.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr,"FAIL line%d %s\n",__LINE__,#x); } } while(0)
struct calls { unsigned probe, span, ptr, read; };
static struct calls calls;
static int direct_mode, callback_reads;
static const void *count_probe(hb_memory_t*m,hb_gva_t a,size_t n) { ++calls.probe; return hb_memory_probe_read_ptr(m,a,n); }
static bool count_span(hb_memory_t*m,hb_gva_t a,size_t n) { ++calls.span; return hb_memory_can_read_span(m,a,n); }
static void *count_ptr(hb_memory_t*m,hb_gva_t a,size_t n,hb_perm_t p) { ++calls.ptr; return hb_memory_host_ptr(m,a,n,p); }
static hb_result_t count_read(hb_memory_t*m,hb_gva_t a,void*p,size_t n) { ++calls.read; return hb_memory_read_nofault(m,a,p,n); }
#define hb_memory_probe_read_ptr count_probe
#define hb_memory_can_read_span count_span
#define hb_memory_host_ptr count_ptr
#define hb_memory_read_nofault count_read
#define runtime_gate_flag(g,d) (direct_mode)
#include "smc-original.inc"
#include "smc-candidate.inc"
#undef runtime_gate_flag
#undef hb_memory_probe_read_ptr
#undef hb_memory_can_read_span
#undef hb_memory_host_ptr
#undef hb_memory_read_nofault

struct fault { uint64_t addr; size_t size; int write, valid; };
static struct fault fault(void) {
    struct fault f = {0}; hb_memory_last_fault(&f.addr,&f.size,&f.write,&f.valid); return f;
}
static bool same_fault(struct fault a, struct fault b) {
    return a.addr==b.addr && a.size==b.size && a.write==b.write && a.valid==b.valid;
}
static void prime_fault(hb_memory_t *mem) {
    CHECK(hb_memory_host_ptr(mem, 0x123, 8, HB_PERM_WRITE)==NULL);
}
static hb_result_t special_read(void *u,hb_gva_t a,void *p,size_t n) {
    (void)u;(void)a;(void)p;(void)n;++callback_reads;return HB_ERR_MEMORY_FAULT;
}
static void compare_case(hb_jit_runtime_t *rt,uint64_t addr,size_t size,bool expected,bool fast) {
    uint8_t old_bytes[4096],new_bytes[4096];
    prime_fault(rt->ctx->memory); calls=(struct calls){0};
    const uint8_t *a=smc_bytes_current_original(rt,addr,size);
    struct calls old_calls=calls; struct fault old_fault=fault();
    if(a && size<=4096)memcpy(old_bytes,a,size);
    prime_fault(rt->ctx->memory); calls=(struct calls){0};
    const uint8_t *b=smc_bytes_current(rt,addr,size);
    struct calls new_calls=calls; struct fault new_fault=fault();
    if(b && size<=4096)memcpy(new_bytes,b,size);
    CHECK((a!=NULL)==expected);CHECK((b!=NULL)==expected);
    CHECK(same_fault(old_fault,new_fault));
    if(expected)CHECK(memcmp(old_bytes,new_bytes,size)==0);
    if(direct_mode && fast) {
        CHECK(old_calls.span==1 && old_calls.ptr==1 && old_calls.read==0);
        CHECK(new_calls.probe==1 && new_calls.span==0 && new_calls.ptr==0 && new_calls.read==0);
    } else {
        CHECK(old_calls.span==new_calls.span);
        CHECK(old_calls.ptr==new_calls.ptr);
        CHECK(old_calls.read==new_calls.read);
    }
}

int main(void) {
    size_t native_size=(size_t)getpagesize();if(native_size<16384)native_size=16384;
    uint8_t *bytes=mmap(NULL,native_size,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);
    if(bytes==MAP_FAILED)return 2;
    for(size_t i=0;i<native_size;i++)bytes[i]=(uint8_t)(i*17+3);
    hb_memory_t *mem=hb_memory_create(0);if(!mem)return 2;
    uint64_t base=(uint64_t)(uintptr_t)bytes;
    CHECK(hb_memory_map(mem,base,4096,HB_PERM_READ|HB_PERM_WRITE)==HB_OK);
    CHECK(hb_memory_map(mem,base+4096,4096,HB_PERM_READ|HB_PERM_WRITE|HB_PERM_EXEC)==HB_OK);
    CHECK(hb_memory_map(mem,base+8192,4096,HB_PERM_WRITE)==HB_OK);
    hb_context_t ctx={0};ctx.memory=mem;hb_jit_runtime_t rt={0};rt.ctx=&ctx;
    hb_memory_set_special_handlers(mem,special_read,NULL,NULL);
    prime_fault(mem);struct fault before=fault();
    CHECK(hb_memory_probe_read_ptr(mem,base+16,32)==bytes+16);
    CHECK(hb_memory_probe_read_ptr(mem,base+4095,1)==bytes+4095);
    CHECK(hb_memory_probe_read_ptr(mem,base+4090,32)==NULL);
    CHECK(hb_memory_probe_read_ptr(mem,base+8192,16)==NULL);
    CHECK(hb_memory_probe_read_ptr(mem,base+12288,16)==NULL);
    CHECK(hb_memory_probe_read_ptr(mem,UINT64_MAX-8,16)==NULL);
    CHECK(hb_memory_probe_read_ptr(mem,base,0)==NULL);
    CHECK(hb_memory_probe_read_ptr(NULL,base,16)==NULL);
    CHECK(same_fault(before,fault()));CHECK(callback_reads==0);
    for(direct_mode=0;direct_mode<=1;direct_mode++) {
        compare_case(&rt,base+16,32,true,true);
        compare_case(&rt,base+4095,1,true,true);
        compare_case(&rt,base+4090,32,true,false);
        compare_case(&rt,base+4096,16,true,true);
        compare_case(&rt,base+8192,16,false,false);
        compare_case(&rt,base+12288,16,false,false);
        compare_case(&rt,base+8190,8,false,false);
        compare_case(&rt,base,0,false,false);
        compare_case(&rt,base,4097,false,false);
        uint8_t old=bytes[32];bytes[32]^=0x55;
        compare_case(&rt,base+24,32,true,true);
        CHECK(smc_bytes_current(&rt,base+24,32)[8]==(uint8_t)(old^0x55));
        CHECK(hb_memory_unmap(mem,base)==HB_OK);
        compare_case(&rt,base+24,32,false,false);
        bytes[32]^=0xa6;
        CHECK(hb_memory_map(mem,base,4096,HB_PERM_READ|HB_PERM_WRITE)==HB_OK);
        compare_case(&rt,base+24,32,true,true);
        CHECK(smc_bytes_current(&rt,base+24,32)[8]==bytes[32]);
        CHECK(hb_memory_protect(mem,base,4096,HB_PERM_WRITE)==HB_OK);
        compare_case(&rt,base+24,32,false,false);
        CHECK(hb_memory_protect(mem,base,4096,HB_PERM_READ|HB_PERM_WRITE)==HB_OK);
    }
    CHECK(callback_reads==0);
    hb_memory_destroy(mem);munmap(bytes,native_size);
    printf("SMC_SINGLE_QUERY checks=%u failures=%u\n",checks,failures);
    return failures?1:0;
}
