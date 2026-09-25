/* Interpreter LOCK correctness regression. Literal x86 encodings and answers;
 * no guest PE, Wine, or generated ARM64 code is executed by this test. */
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_flags.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

extern hb_result_t hb_interpreter_exec_one_for_jit(hb_context_t*, const hb_ir_instr_t*);
enum { THREADS = 8, ITERATIONS = 4000, PAGE_BYTES = 16384 };
static unsigned checks, failures;
static const uint64_t FIXTURE_PC = UINT64_C(0x1400016ea);
static const uint64_t COUNTER = UINT64_C(0x1400060a8);

static int check(int ok, const char *what)
{
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL %s\n", what); }
    return ok;
}

static hb_ir_func_t *lift(const uint8_t *bytes, size_t size, uint64_t pc)
{
    hb_decoder_t *decoder = hb_decoder_create(HB_ARCH_X64, bytes, size, pc);
    hb_ir_func_t *func = NULL;
    if (!decoder) return NULL;
    if (hb_lift_func_x64(decoder, &func) != HB_OK) func = NULL;
    hb_decoder_destroy(decoder);
    return func;
}

static const hb_ir_instr_t *locked_add(const hb_ir_func_t *func)
{
    if (!func || !func->cfg || !func->cfg->entry) return NULL;
    const hb_ir_block_t *block = func->cfg->entry;
    for (size_t i = 0; i < block->instr_count; ++i)
        if (block->instrs[i].op == HB_IR_ADD && block->instrs[i].is_locked)
            return &block->instrs[i];
    return NULL;
}

/* Same transport as the standalone adapter: no hb_memory mapping for the
 * native allocation, only Mach read/write callbacks. An aligned LOCK operation
 * must still use a true host atomic RMW rather than two callback calls. */
static hb_result_t native_read(void *user, hb_gva_t addr, void *out, size_t size)
{
    mach_vm_size_t copied = 0;
    (void)user;
    return mach_vm_read_overwrite(mach_task_self(), addr, size,
                                 (mach_vm_address_t)(uintptr_t)out, &copied) == KERN_SUCCESS &&
           copied == size ? HB_OK : HB_ERR_MEMORY_FAULT;
}

static hb_result_t native_write(void *user, hb_gva_t addr, const void *in, size_t size)
{
    (void)user;
    return mach_vm_write(mach_task_self(), addr, (vm_offset_t)(uintptr_t)in,
                         (mach_msg_type_number_t)size) == KERN_SUCCESS ? HB_OK : HB_ERR_MEMORY_FAULT;
}

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    unsigned ready;
    int go;
} start_gate_t;

typedef struct {
    hb_context_t *ctx;
    const hb_ir_instr_t *instr;
    uint32_t *host;
    start_gate_t *gate;
    int native_worker;
    hb_result_t result;
} worker_t;

static void *worker(void *opaque)
{
    worker_t *w = opaque;
    pthread_mutex_lock(&w->gate->mutex);
    ++w->gate->ready;
    pthread_cond_broadcast(&w->gate->cond);
    while (!w->gate->go) pthread_cond_wait(&w->gate->cond, &w->gate->mutex);
    pthread_mutex_unlock(&w->gate->mutex);
    for (unsigned i = 0; i < ITERATIONS; ++i) {
        if (w->native_worker) __atomic_fetch_add(w->host, 1u, __ATOMIC_SEQ_CST);
        else if ((w->result = hb_interpreter_exec_one_for_jit(w->ctx, w->instr)) != HB_OK) break;
    }
    return NULL;
}

static void concurrent_case(const char *name, hb_memory_t *memory,
                            const hb_ir_instr_t *instr, uint64_t guest,
                            uint32_t *host, int mixed)
{
    start_gate_t gate = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0, 0 };
    pthread_t threads[THREADS];
    worker_t work[THREADS] = {0};
    uint32_t zero = 0, value = 0;
    check(hb_memory_write(memory, guest, &zero, sizeof(zero)) == HB_OK, "initialize counter");
    unsigned created = 0;
    for (unsigned i = 0; i < THREADS; ++i) {
        work[i].ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
        if (!check(work[i].ctx != NULL, "create worker context")) break;
        work[i].ctx->memory = memory;
        work[i].ctx->pc = work[i].ctx->regs.x64.rip = instr->guest_addr;
        work[i].ctx->regs.x64.rax = guest;
        work[i].instr = instr;
        work[i].host = host;
        work[i].gate = &gate;
        work[i].native_worker = mixed && (i & 1);
        if (!check(pthread_create(&threads[i], NULL, worker, &work[i]) == 0, "create worker")) break;
        ++created;
    }
    pthread_mutex_lock(&gate.mutex);
    while (gate.ready != created) pthread_cond_wait(&gate.cond, &gate.mutex);
    gate.go = 1;
    pthread_cond_broadcast(&gate.cond);
    pthread_mutex_unlock(&gate.mutex);
    for (unsigned i = 0; i < created; ++i) {
        check(pthread_join(threads[i], NULL) == 0, "join worker");
        check(work[i].result == HB_OK, "worker instruction status");
    }
    check(hb_memory_read(memory, guest, &value, sizeof(value)) == HB_OK, "read final counter");
    printf("%s counter=%" PRIu32 " expected=32000\n", name, value);
    check(created == THREADS && value == 32000, name);
    for (unsigned i = 0; i < THREADS; ++i) {
        if (work[i].ctx) { work[i].ctx->memory = NULL; hb_context_destroy(work[i].ctx); }
    }
    pthread_cond_destroy(&gate.cond);
    pthread_mutex_destroy(&gate.mutex);
}

static void flag_cases(hb_memory_t *memory, const hb_ir_instr_t *instr)
{
    /* INC preserves carry, unlike ADD. Expected bits are literal x86 answers. */
    static const struct { uint32_t before, after; unsigned cf, of, sf, zf, af, pf; } cases[] = {
        {0x7fffffff, 0x80000000, 0, 1, 1, 0, 1, 1},
        {0x7fffffff, 0x80000000, 1, 1, 1, 0, 1, 1},
        {0xffffffff, 0x00000000, 1, 0, 0, 1, 1, 1},
        {0x00000000, 0x00000001, 0, 0, 0, 0, 0, 0}
    };
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    if (!check(ctx != NULL, "flag context")) return;
    ctx->memory = memory;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint32_t value = cases[i].before;
        hb_lazy_flags_clear(ctx);
        ctx->flags.cf = cases[i].cf;
        check(hb_memory_write(memory, COUNTER, &value, 4) == HB_OK, "flag setup write");
        check(hb_interpreter_exec_one_for_jit(ctx, instr) == HB_OK, "flag INC executes");
        check(hb_lazy_flags_materialize(ctx, HB_FLAG_BIT_ALL) == HB_OK, "materialize INC flags");
        check(hb_memory_read(memory, COUNTER, &value, 4) == HB_OK && value == cases[i].after,
              "literal INC result");
        check(ctx->flags.cf == cases[i].cf && ctx->flags.of == cases[i].of &&
              ctx->flags.sf == cases[i].sf && ctx->flags.zf == cases[i].zf &&
              ctx->flags.af == cases[i].af && ctx->flags.pf == cases[i].pf, "literal INC flags");
    }
    ctx->memory = NULL;
    hb_context_destroy(ctx);
}

static void fault_case(int exec_fault)
{
    /* Two successful MOVs precede either an invalid memory read or UD2. */
    static const uint8_t load[] = {0xb9,0x78,0x56,0x34,0x12, 0xba,0x21,0x43,0x65,0x07, 0x8b,0x18};
    static const uint8_t ud2[]  = {0xb9,0x78,0x56,0x34,0x12, 0xba,0x21,0x43,0x65,0x07, 0x0f,0x0b};
    hb_ir_func_t *func = lift(exec_fault ? ud2 : load, sizeof(load), 0x4000000);
    hb_context_t *ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    hb_memory_t *memory = hb_memory_create(0);
    if (!check(func && ctx && memory, "fault setup")) exit(2);
    ctx->memory = memory;
    ctx->pc = ctx->regs.x64.rip = 0x4000000;
    ctx->regs.x64.rax = 1;
    ctx->regs.x64.rbx = UINT64_C(0xfeed12345678);
    hb_interpreter_t *interp = hb_interpreter_create(ctx);
    hb_exec_result_t out = {0};
    check(interp && hb_interpreter_run(interp, func, &out) == HB_OK, "fault run returns report");
    check(out.faulted && out.result != HB_OK, "fault reported");
    check(ctx->pc == 0x400000a && ctx->regs.x64.rip == 0x400000a, "fault RIP names failing instruction");
    check(ctx->regs.x64.rcx == 0x12345678 && ctx->regs.x64.rdx == 0x07654321,
          "state from earlier instructions retained");
    check(ctx->regs.x64.rbx == UINT64_C(0xfeed12345678), "fault destination unchanged");
    hb_interpreter_destroy(interp);
    hb_ir_func_destroy(func);
    hb_memory_destroy(memory);
    ctx->memory = NULL;
    hb_context_destroy(ctx);
}

int main(void)
{
    static const uint8_t fixture[] = {0xf0,0xff,0x05,0xb7,0x49,0,0};
    static const uint8_t indirect[] = {0xf0,0xff,0x00};
    hb_ir_func_t *exact = lift(fixture, sizeof(fixture), FIXTURE_PC);
    hb_ir_func_t *via_rax = lift(indirect, sizeof(indirect), 0x5000000);
    const hb_ir_instr_t *inc = locked_add(exact), *ind = locked_add(via_rax);
    if (!check(inc && ind && inc->preserve_cf && ind->preserve_cf, "literal LOCK INC lifted")) return 2;
    hb_memory_t *mapped = hb_memory_create(0), *native = hb_memory_create(0);
    if (!check(mapped && native, "memory setup")) return 2;
    if (!check(hb_memory_map_private(mapped, 0x140004000, PAGE_BYTES,
                                     HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "mapped counter")) return 2;
    hb_memory_set_special_handlers(native, native_read, native_write, NULL);
    _Alignas(64) unsigned char storage[128] = {0};
    uint32_t *aligned = (uint32_t *)(void *)(storage + 64);
    flag_cases(mapped, inc);
    concurrent_case("fixture RIP-relative LOCK INC", mapped, inc, COUNTER, NULL, 0);
    concurrent_case("native callbacks LOCK INC", native, ind, (uintptr_t)aligned, aligned, 0);
    concurrent_case("interpreter plus native atomics", native, ind, (uintptr_t)aligned, aligned, 1);
    concurrent_case("unaligned cooperative fallback", native, ind, (uintptr_t)(storage + 1), NULL, 0);
    check(ind->is_locked && inc->is_locked, "fallback preserves shared IR LOCK marker");
    fault_case(0);
    fault_case(1);
    hb_ir_func_destroy(exact);
    hb_ir_func_destroy(via_rax);
    hb_memory_destroy(mapped);
    hb_memory_destroy(native);
    printf("checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
