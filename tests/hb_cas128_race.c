/* Four independent JIT environments share one 128-bit counter. The initial low
 * word crosses UINT64_MAX during the run, exercising the carry to the high word.
 * Run with NATIVE_CAS128=0 (provider) and =1 (CASPAL); both must be exact. */
#define _DARWIN_C_SOURCE 1
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

enum { THREADS = 4, ITER = 50000, PAGE = 16384 };
static uint8_t *code, *data;
static size_t code_len;
static pthread_mutex_t start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;
static unsigned ready;
static int start;
static unsigned long provider_calls[THREADS];

static hb_result_t provider(void* user, hb_gva_t addr, const uint64_t expected[2],
                            const uint64_t desired[2], uint64_t observed[2], bool* exchanged) {
    unsigned long* calls = user;
    unsigned __int128 e, d;
    ++*calls;
    memcpy(&e, expected, 16); memcpy(&d, desired, 16);
    *exchanged = __atomic_compare_exchange_n((unsigned __int128*)(uintptr_t)addr,
                                             &e, d, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    memcpy(observed, &e, 16);
    return HB_OK;
}
static void* worker(void* arg) {
    unsigned id = (unsigned)(uintptr_t)arg;
    hb_context_t* c = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_memory_t* m = hb_memory_create(0);
    uint8_t* stack = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (!c || !m || stack == MAP_FAILED) exit(2);
    c->memory = m; c->config.fallback_enabled = false;
    hb_memory_set_atomic_cmpxchg128_handler(m, provider, &provider_calls[id]);
    if (hb_memory_sync_live_range(m, (uintptr_t)code, PAGE, HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
        hb_memory_sync_live_range(m, (uintptr_t)data, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK ||
        hb_memory_sync_live_range(m, (uintptr_t)stack, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) exit(2);
    c->regs.x64.rdi = (uintptr_t)data;
    c->regs.x64.rsp = (uintptr_t)stack + PAGE - 256;
    c->pc = c->regs.x64.rip = (uintptr_t)code;
    c->mxcsr = 0x1f80;
    hb_context_set_step_limit(c, 100000000); hb_context_set_block_limit(c, 100000000);
    hb_jit_runtime_t* rt = hb_jit_runtime_create(c);
    if (!rt) exit(2);
    pthread_mutex_lock(&start_mutex);
    ++ready; pthread_cond_broadcast(&start_cond);
    while (!start) pthread_cond_wait(&start_cond, &start_mutex);
    pthread_mutex_unlock(&start_mutex);
    uint64_t end = (uintptr_t)code + code_len;
    for (unsigned hop = 0; hop < 100000 && c->pc != end; ++hop) {
        uint64_t off = c->pc - (uintptr_t)code;
        if (off >= code_len) { fprintf(stderr, "CAS128 race: bad pc\n"); exit(2); }
        hb_decoder_t* d = hb_decoder_create(HB_ARCH_X64, code + off, code_len - off, c->pc);
        hb_ir_func_t* f = NULL;
        if (!d || hb_lift_func_x64(d, &f) != HB_OK || !f) exit(2);
        hb_decoder_destroy(d);
        hb_exec_result_t r = {0};
        if (hb_jit_runtime_run(rt, f, &r) != HB_OK || r.faulted) { fprintf(stderr, "CAS128 race: execution fault\n"); exit(2); }
        hb_ir_func_destroy(f);
    }
    int finished = c->pc == end;
    hb_jit_runtime_destroy(rt);
    c->memory = NULL; hb_context_destroy(c); hb_memory_destroy(m); munmap(stack, PAGE);
    return (void*)(uintptr_t)!finished;
}
int main(void) {
    code = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    data = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED || data == MAP_FAILED) return 2;
    size_t n = 0;
    code[n++] = 0x41; code[n++] = 0xb8; /* mov r8d, ITER */
    memcpy(code + n, &(uint32_t){ITER}, 4); n += 4;
    size_t retry = n;
    const uint8_t body[] = {
        0x48,0x89,0xc3,                 /* mov rbx,rax */
        0x48,0x83,0xc3,0x01,            /* add rbx,1 */
        0x48,0x89,0xd1,                 /* mov rcx,rdx */
        0x48,0x83,0xd1,0x00,            /* adc rcx,0 */
        0xf0,0x48,0x0f,0xc7,0x0f        /* lock cmpxchg16b [rdi] */
    };
    memcpy(code + n, body, sizeof(body)); n += sizeof(body);
    code[n++] = 0x75; code[n] = (uint8_t)(retry - (n + 1)); ++n;
    const uint8_t success[] = {
        0x48,0x89,0xd8,                 /* mov rax,rbx */
        0x48,0x89,0xca,                 /* mov rdx,rcx */
        0x41,0xff,0xc8                  /* dec r8d */
    };
    memcpy(code + n, success, sizeof(success)); n += sizeof(success);
    code[n++] = 0x75; code[n] = (uint8_t)(retry - (n + 1)); ++n;
    code_len = n;
    const uint64_t initial[2] = {UINT64_MAX - (THREADS * ITER / 2), UINT64_C(0x3746aa82771fed09)};
    unsigned __int128 want, got;
    memcpy(data, initial, 16); memcpy(&want, initial, 16); want += THREADS * ITER;
    pthread_t threads[THREADS];
    for (unsigned i = 0; i < THREADS; ++i)
        if (pthread_create(&threads[i], NULL, worker, (void*)(uintptr_t)i)) return 2;
    pthread_mutex_lock(&start_mutex);
    while (ready < THREADS) pthread_cond_wait(&start_cond, &start_mutex);
    start = 1; pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&start_mutex);
    unsigned bad = 0; unsigned long calls = 0;
    for (unsigned i = 0; i < THREADS; ++i) {
        void* result;
        if (pthread_join(threads[i], &result)) return 2;
        bad += (unsigned)(uintptr_t)result; calls += provider_calls[i];
    }
    memcpy(&got, data, 16);
    const char* gate_value = getenv("MACRUNNER_HB_NATIVE_CAS128");
    int gate = gate_value && strcmp(gate_value, "0");
    if (gate ? calls != 0 : calls < THREADS * ITER) ++bad;
    if (got != want) ++bad;
    printf("CAS128_RACE gate=%d threads=%d iterations=%d increments=%d got=%016llx:%016llx want=%016llx:%016llx provider_calls=%lu bad=%u\n",
           gate, THREADS, ITER, THREADS * ITER, (unsigned long long)(got >> 64), (unsigned long long)got,
           (unsigned long long)(want >> 64), (unsigned long long)want, calls, bad);
    munmap(code, PAGE); munmap(data, PAGE);
    return bad ? 1 : 0;
}
