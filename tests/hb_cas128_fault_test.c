/* Native CASPAL host faults: exact HB replay, and HB-owned SMC retry/eviction.
 * No Wine. The protected-page provider models a denied guest write, recording
 * the architectural state at interpreter reentry before returning the fault. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

#define PAGE 16384u
extern int hb_smc_query_prot(uint64_t addr);
extern void hb_smc_protect_stats(uint64_t* armed, uint64_t* faults);
extern uint64_t hb_codegen_native_cas128_emitted(void);

static hb_ir_func_t* lift(uint8_t* code, size_t n) {
    hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, code, n, (uintptr_t)code);
    hb_ir_func_t* f = NULL;
    if (!dec) return NULL;
    if (hb_lift_func_x64(dec, &f) != HB_OK) f = NULL;
    hb_decoder_destroy(dec);
    return f;
}

static void* page(void) {
    return mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
}

static unsigned flag_bits(hb_context_t* ctx) {
    return ctx->flags.cf | ctx->flags.pf << 1 | ctx->flags.af << 2 |
           ctx->flags.zf << 3 | ctx->flags.sf << 4 | ctx->flags.of << 5;
}

typedef struct {
    hb_context_t* ctx;
    uint64_t pc, addr, rsp, expected[2], desired[2];
    unsigned calls, bad;
} deny_t;

static hb_result_t deny_write(void* user, hb_gva_t addr, const uint64_t expected[2],
                              const uint64_t desired[2], uint64_t observed[2], bool* exchanged) {
    deny_t* d = user;
    hb_context_t copy = *d->ctx;
    (void)observed; (void)exchanged;
    ++d->calls;
    if (addr != d->addr || d->ctx->pc != d->pc || d->ctx->regs.x64.rip != d->pc ||
        d->ctx->regs.x64.r8 != 0 || d->ctx->regs.x64.rsp != d->rsp - 8 ||
        memcmp(expected, d->expected, 16) || memcmp(desired, d->desired, 16) ||
        hb_lazy_flags_materialize(&copy, HB_FLAG_BIT_ALL) != HB_OK || flag_bits(&copy) != 15)
        ++d->bad;
    return HB_ERR_MEMORY_FAULT;
}

static int protected_case(unsigned guard, unsigned match, unsigned locked, int skew) {
    uint8_t* code = page();
    uint64_t* data = page();
    uint8_t* stack = page();
    hb_context_t* ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_memory_t* mem = hb_memory_create(0);
    if (code == MAP_FAILED || data == MAP_FAILED || stack == MAP_FAILED || !ctx || !mem) return 2;
    ctx->memory = mem;
    unsigned n = 0;
    const uint8_t prefix[] = {0x4d, 0x01, 0xc8, 0x56}; /* add r8,r9; push rsi */
    memcpy(code, prefix, sizeof(prefix)); n += sizeof(prefix);
    unsigned cas_off = n;
    if (locked) code[n++] = 0xf0;
    code[n++] = 0x48; code[n++] = 0x0f; code[n++] = 0xc7; code[n++] = 0x0f;
    const uint8_t after[] = {0x49, 0xff, 0xc3}; /* inc r11: must not execute */
    memcpy(code + n, after, sizeof(after)); n += sizeof(after);
    hb_ir_func_t* f = lift(code, n);
    if (!f ||
        hb_memory_sync_live_range(mem, (uintptr_t)code, PAGE, HB_PERM_READ | HB_PERM_EXEC) != HB_OK ||
        hb_memory_sync_live_range(mem, (uintptr_t)data, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK ||
        hb_memory_sync_live_range(mem, (uintptr_t)stack, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) return 2;
    data[0] = 0x1234; data[1] = 0x5678;
    deny_t d = {.ctx = ctx, .pc = (uintptr_t)code + cas_off, .addr = (uintptr_t)data,
                .rsp = (uintptr_t)stack + PAGE - 128,
                .expected = {match ? 0x1234 : 0x1235, 0x5678}, .desired = {0x9abc, 0xdef0}};
    ctx->pc = ctx->regs.x64.rip = (uintptr_t)code;
    ctx->regs.x64.rax = d.expected[0]; ctx->regs.x64.rdx = d.expected[1];
    ctx->regs.x64.rbx = d.desired[0]; ctx->regs.x64.rcx = d.desired[1];
    ctx->regs.x64.rdi = d.addr; ctx->regs.x64.rsp = d.rsp;
    ctx->regs.x64.r8 = UINT64_MAX; ctx->regs.x64.r9 = 1;
    ctx->regs.x64.rsi = UINT64_C(0x7273747576777879);
    ctx->regs.x64.r11 = 0x99;
    hb_memory_set_atomic_cmpxchg128_handler(mem, deny_write, &d);
    hb_jit_runtime_t* rt = hb_jit_runtime_create(ctx);
    if (!rt || mprotect(data, PAGE, guard ? PROT_NONE : PROT_READ)) return 2;
    uint64_t exact0, map0, block0, exact1, map1, block1;
    hb_jit_fault_pc_stats(&exact0, &map0, &block0);
    uint64_t emitted = hb_codegen_native_cas128_emitted();
    hb_exec_result_t out = {0};
    hb_result_t r = hb_jit_runtime_run(rt, f, &out);
    hb_jit_fault_pc_stats(&exact1, &map1, &block1);
    if (mprotect(data, PAGE, PROT_READ | PROT_WRITE)) return 2;
    int bad = r != HB_OK || out.result != HB_ERR_MEMORY_FAULT || !out.faulted ||
              d.calls != 1 || d.bad || exact1 != exact0 + 1 || map1 != map0 || block1 != block0 ||
              hb_codegen_native_cas128_emitted() <= emitted || ctx->pc != d.pc ||
              ctx->regs.x64.r8 != 0 || ctx->regs.x64.rsp != d.rsp - 8 ||
              ctx->regs.x64.rax != d.expected[0] || ctx->regs.x64.rdx != d.expected[1] ||
              ctx->regs.x64.rbx != d.desired[0] || ctx->regs.x64.rcx != d.desired[1] ||
              ctx->regs.x64.r11 != 0x99 || data[0] != 0x1234 || data[1] != 0x5678 ||
              *(uint64_t*)(uintptr_t)(d.rsp - 8) != ctx->regs.x64.rsi;
    printf("CAS128_FAULT guard=%u match=%u locked=%u exact=%llu provider=%u provider_bad=%u "
           "rsp_delta=%llu result=%d/%d faulted=%u bad=%d skew=%d\n", guard, match, locked,
           (unsigned long long)(exact1 - exact0), d.calls, d.bad,
           (unsigned long long)(d.rsp - ctx->regs.x64.rsp), r, out.result, out.faulted, bad, skew);
    int detected = bad && d.calls == 1 && d.bad == 1 &&
                   ctx->regs.x64.rsp == d.rsp - 16 && exact1 == exact0 + 1 &&
                   map1 == map0 && block1 == block0;
    hb_jit_runtime_destroy(rt); hb_ir_func_destroy(f);
    ctx->memory = NULL; hb_context_destroy(ctx); hb_memory_destroy(mem);
    munmap(code, PAGE); munmap(data, PAGE); munmap(stack, PAGE);
    return skew ? !detected : bad;
}

static int run_once(hb_jit_runtime_t* rt, hb_context_t* ctx, hb_ir_func_t* f, uint64_t base) {
    ctx->pc = ctx->regs.x64.rip = base;
    for (unsigned hop = 0; hop < 4; ++hop) {
        hb_exec_result_t out = {0};
        if (hb_jit_runtime_run(rt, f, &out) != HB_OK || out.result != HB_OK || out.faulted) return 0;
        if (ctx->pc < base || ctx->pc >= base + 0x40) return 1;
    }
    return 0;
}

static int smc_case(void) {
    uint8_t* target = page(); uint8_t* writer = page(); uint8_t* stack = page();
    hb_context_t* ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_memory_t* mem = hb_memory_create(0);
    if (target == MAP_FAILED || writer == MAP_FAILED || stack == MAP_FAILED || !ctx || !mem) return 2;
    ctx->memory = mem;
    uint32_t old = 0x11111111, changed = 0x22222222, rel = 0x100 - 10;
    memset(target, 0x90, 16);
    target[0] = 0xb8; memcpy(target + 1, &old, 4);
    target[5] = 0xe9; memcpy(target + 6, &rel, 4);
    const uint8_t patcher[] = {0x4d, 0x01, 0xc8, 0xf0, 0x48, 0x0f, 0xc7, 0x0f,
                             0xe9, 0xf3, 0x00, 0x00, 0x00}; /* add; lock cx16; jmp +0x100 */
    memcpy(writer, patcher, sizeof(patcher));
    if (hb_memory_sync_live_range(mem, (uintptr_t)target, PAGE, HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
        hb_memory_sync_live_range(mem, (uintptr_t)writer, PAGE, HB_PERM_READ | HB_PERM_EXEC) != HB_OK ||
        hb_memory_sync_live_range(mem, (uintptr_t)stack, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) return 2;
    ctx->regs.x64.rsp = (uintptr_t)stack + PAGE - 128;
    hb_jit_runtime_t* rt = hb_jit_runtime_create(ctx);
    hb_ir_func_t* first = lift(target, 10); hb_ir_func_t* write = lift(writer, sizeof(patcher));
    if (!rt || !first || !write || !run_once(rt, ctx, first, (uintptr_t)target)) return 2;
    int bad = ctx->regs.x64.rax != old || hb_smc_query_prot((uintptr_t)target) != 5;
    uint64_t expected[2], desired[2];
    memcpy(expected, target, 16); memcpy(desired, expected, 16); memcpy((uint8_t*)desired + 1, &changed, 4);
    ctx->regs.x64.rax = expected[0]; ctx->regs.x64.rdx = expected[1];
    ctx->regs.x64.rbx = desired[0]; ctx->regs.x64.rcx = desired[1];
    ctx->regs.x64.rdi = (uintptr_t)target; ctx->regs.x64.r8 = UINT64_MAX; ctx->regs.x64.r9 = 1;
    uint64_t faults0, faults1, exact0, exact1, ev0 = hb_jit_smc_evicted_total();
    uint64_t emitted = hb_codegen_native_cas128_emitted();
    hb_smc_protect_stats(NULL, &faults0); hb_jit_fault_pc_stats(&exact0, NULL, NULL);
    if (!run_once(rt, ctx, write, (uintptr_t)writer)) return 2;
    hb_smc_protect_stats(NULL, &faults1); hb_jit_fault_pc_stats(&exact1, NULL, NULL);
    bad |= faults1 != faults0 + 1 || exact1 != exact0 || memcmp(target, desired, 16) ||
           hb_codegen_native_cas128_emitted() <= emitted ||
           ctx->regs.x64.r8 != 0 || !ctx->flags.zf || ctx->regs.x64.rax != expected[0] ||
           ctx->regs.x64.rdx != expected[1];
    hb_ir_func_t* second = lift(target, 10);
    if (!second || !run_once(rt, ctx, second, (uintptr_t)target)) return 2;
    uint64_t ev1 = hb_jit_smc_evicted_total();
    bad |= ctx->regs.x64.rax != changed || ev1 <= ev0;
    printf("CAS128_SMC faults=%llu exact=%llu evictions=%llu eax=%llx bad=%d\n",
           (unsigned long long)(faults1 - faults0), (unsigned long long)(exact1 - exact0),
           (unsigned long long)(ev1 - ev0), (unsigned long long)ctx->regs.x64.rax, bad);
    hb_jit_runtime_destroy(rt); hb_ir_func_destroy(first); hb_ir_func_destroy(second); hb_ir_func_destroy(write);
    ctx->memory = NULL; hb_context_destroy(ctx); hb_memory_destroy(mem);
    munmap(target, PAGE); munmap(writer, PAGE); munmap(stack, PAGE);
    return bad;
}

int main(int argc, char** argv) {
    int skew = argc > 1 && !strcmp(argv[1], "skew");
    setenv("MACRUNNER_HB_NATIVE_CAS128", "1", 1);
    setenv("MACRUNNER_HB_JIT_DIRECT_MEM", "1", 1);
    setenv("MACRUNNER_HB_JIT_NATIVE_MEM_IR", "1", 1);
    setenv("MACRUNNER_HB_STATIC_REGS", "1", 1);
    setenv("MACRUNNER_HB_SMC_PROTECT", "1", 1);
    setenv("MACRUNNER_HB_TEST_RIPMAP_SKEW", skew ? "1" : "0", 1);
    hb_env_refresh(); hb_memory_install_fault_handlers();
    int bad = 0;
    for (unsigned guard = 0; guard < 2; ++guard)
        for (unsigned match = 0; match < 2; ++match)
            for (unsigned locked = 0; locked < 2; ++locked)
                bad += protected_case(guard, match, locked, skew);
    bad += smc_case();
    printf("CAS128_FAULT_TOTAL cases=9 skew=%d bad=%d\n", skew, bad);
    return bad ? 1 : 0;
}
