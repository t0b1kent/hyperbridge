/* Неделимость LOCK RMW в выпущенном коде (Claude 27.09.2026): THREADS потоков, у каждого своя среда JIT
 * (как у потоков игры), общая память. Каждый исполняет ITER раз `lock add dword [rdi], 1` (и отдельно
 * `lock add qword`), итог обязан быть ровно THREADS*ITER. Потерянные приращения = неатомарный выпуск.
 * Запуск: с MACRUNNER_HB_LSE_ATOMICS=1 (одна команда LSE) и =0 (помощник) — обе руки обязаны сойтись. */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

enum { THREADS = 4, ITER = 200000 };
static uint8_t* g_code;
static uint8_t* g_data;
static size_t g_page = 16384;
static size_t g_len;
static int g_wide;

static void* worker(void* arg) {
    (void)arg;
    hb_context_t* c = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    hb_memory_t* m = hb_memory_create(0);
    c->config.fallback_enabled = false; c->memory = m;
    hb_memory_sync_live_range(m, (hb_gva_t)(uintptr_t)g_code, g_page, HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC);
    hb_memory_sync_live_range(m, (hb_gva_t)(uintptr_t)g_data, g_page, HB_PERM_READ | HB_PERM_WRITE);
    uint8_t* stack = mmap(NULL, g_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    hb_memory_sync_live_range(m, (hb_gva_t)(uintptr_t)stack, g_page, HB_PERM_READ | HB_PERM_WRITE);
    memset(&c->regs, 0, sizeof c->regs);
    c->regs.x64.rdi = (uint64_t)(uintptr_t)g_data;
    c->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + g_page - 256);
    c->pc = c->regs.x64.rip = (uint64_t)(uintptr_t)g_code;
    c->mxcsr = 0x1f80;
    hb_context_set_step_limit(c, 100000000ull); hb_context_set_block_limit(c, 100000000ull);
    hb_jit_runtime_t* rt = hb_jit_runtime_create(c);
    uint64_t end = (uint64_t)(uintptr_t)g_code + g_len;
    for (int hop = 0; hop < 100000 && c->pc != end; hop++) {
        uint64_t off = c->pc - (uint64_t)(uintptr_t)g_code;
        hb_decoder_t* d = hb_decoder_create(HB_ARCH_X64, g_code + off, g_len - off, c->pc);
        hb_ir_func_t* f = NULL;
        if (!d || hb_lift_func_x64(d, &f) != HB_OK || !f) { fprintf(stderr, "lift failed\n"); exit(2); }
        hb_decoder_destroy(d);
        hb_exec_result_t r; memset(&r, 0, sizeof r);
        if (hb_jit_runtime_run(rt, f, &r) != HB_OK || r.faulted) { fprintf(stderr, "run failed\n"); exit(2); }
        hb_ir_func_destroy(f);
    }
    hb_jit_runtime_destroy(rt);
    c->memory = NULL; hb_context_destroy(c); hb_memory_destroy(m);
    munmap(stack, g_page);
    return NULL;
}

int main(void) {
    int rc = 0;
    g_code = mmap(NULL, g_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    g_data = mmap(NULL, g_page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    for (g_wide = 0; g_wide < 2; g_wide++) {
        size_t n = 0;
        /* mov ecx, ITER ; loop: lock add dword/qword [rdi], 1 ; dec ecx ; jnz loop */
        g_code[n++] = 0xb9; memcpy(g_code + n, &(uint32_t){ ITER }, 4); n += 4;
        size_t loop = n;
        if (!getenv("NOLOCK")) g_code[n++] = 0xf0;   /* NOLOCK=1 — отрицательный контроль: без LOCK приращения ОБЯЗАНЫ теряться */
        if (g_wide) g_code[n++] = 0x48; g_code[n++] = 0x83; g_code[n++] = 0x07; g_code[n++] = 0x01;
        g_code[n++] = 0xff; g_code[n++] = 0xc9;                                  /* dec ecx */
        g_code[n++] = 0x75; g_code[n] = (uint8_t)(loop - (n + 1)); n++;        /* jnz loop */
        g_len = n;
        memset(g_data, 0, 64);
        pthread_t t[THREADS];
        for (int i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, worker, NULL);
        for (int i = 0; i < THREADS; i++) pthread_join(t[i], NULL);
        uint64_t got = g_wide ? *(uint64_t*)g_data : *(uint32_t*)g_data;
        uint64_t want = (uint64_t)THREADS * ITER;
        printf("{\"width\":%d,\"threads\":%d,\"iter\":%d,\"got\":%llu,\"want\":%llu,\"lost\":%lld}\n", g_wide ? 64 : 32,
               THREADS, ITER, (unsigned long long)got, (unsigned long long)want, (long long)(want - got));
        if (got != want) rc = 1;
    }
    return rc;
}
