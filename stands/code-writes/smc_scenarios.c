/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 HyperBridge contributors */
/* smc_scenarios.c — small probes of a program that writes into its own code.
 *
 * Each case builds a few machine instructions in freshly allocated memory, runs them, changes them
 * and runs them again. The lines without a leading '#' contain no addresses and no timings, so the
 * output of real x86-64 Windows, of Wine on Rosetta and of an x86 translator can be compared
 * byte for byte. Lines starting with '#' carry timings and are informational.
 *
 * Cases:
 *   S1A  a function changes an operand in its caller, then returns into it
 *        mode 0: the caller is reached by a new thread through a direct jump another thread ran first
 *        mode 1: a new thread calls the caller directly            (control)
 *        mode 2: one thread does everything                        (control)
 *   S1B  one thread spins in a loop; another thread changes an operand inside that loop
 *   S2A  what VirtualQuery / VirtualProtect report for an executable+writable page after its code ran
 *   S2B  RX -> RWX -> write -> restore the reported old protection -> run
 *   S3   one thread keeps calling a function; another repeats: RWX, write operand, RX
 *   S4   writing into executed code with NtWriteVirtualMemory / NtReadVirtualMemory / WriteProcessMemory
 *   S5   one instruction writes into the page it is executed from: adc, sbb, pop, rep movsb
 *   S6   how long one store into an already executed page takes (timings only, '#' lines)
 *
 * Build: x86_64-w64-mingw32-clang -std=c11 -O1 -Wall -Wextra smc_scenarios.c -o smc-scenarios.exe
 * Run:   smc-scenarios.exe [--only S1A,S3]
 *
 * Prepared with the help of AI tools for diagnostics; not a test-suite patch.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t (*fn0)(void);
typedef int64_t (*fn0q)(void);
typedef LONG (NTAPI *nt_rw)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T *);

static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }
static uint32_t get32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint8_t *rwx(size_t n) { return (uint8_t *)VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); }
static void *rw(size_t n) { return VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }
static void flush(void *p, size_t n) { FlushInstructionCache(GetCurrentProcess(), p, n); }
static double now_ms(void)
{
    LARGE_INTEGER c, f;
    QueryPerformanceCounter(&c);
    QueryPerformanceFrequency(&f);
    return 1000.0 * (double)c.QuadPart / (double)f.QuadPart;
}
static uint32_t qprot(void *p)
{
    MEMORY_BASIC_INFORMATION m;
    if (!VirtualQuery(p, &m, sizeof m)) return 0xffffffffu;
    return m.Protect;
}
/* mov eax, imm32 ; ret  — the operand is at p+1 */
static void emit_ret_const(uint8_t *p, uint32_t v) { p[0] = 0xB8; put32(p + 1, v); p[5] = 0xC3; }

/* ---------- threads ---------- */
struct call { fn0 f; int times; uint32_t r; volatile LONG done; };
static DWORD WINAPI call_proc(void *a)
{
    struct call *c = (struct call *)a;
    for (int i = 0; i < c->times; i++) c->r = c->f();
    InterlockedExchange(&c->done, 1);
    return 0;
}
/* 1 = finished in time */
static int run_thread(fn0 f, int times, DWORD timeout_ms, uint32_t *r)
{
    struct call c;
    c.f = f; c.times = times; c.r = 0xdeadbeefu; c.done = 0;
    HANDLE h = CreateThread(NULL, 0, call_proc, &c, 0, NULL);
    if (!h) { *r = 0xdead0001u; return 0; }
    DWORD w = WaitForSingleObject(h, timeout_ms);
    if (w != WAIT_OBJECT_0) { TerminateThread(h, 1); WaitForSingleObject(h, 1000); CloseHandle(h); *r = 0xdead0002u; return 0; }
    CloseHandle(h);
    *r = c.r;
    return 1;
}

/* ---------- S1A ---------- */
static int s1a(int mode, int reps)
{
    int x86 = 0;
    for (int rep = 0; rep < reps; rep++) {
        uint8_t *b = rwx(0x30000);
        volatile uint32_t *flag = (volatile uint32_t *)rw(0x1000);
        if (!b || !flag) { printf("S1A mode=%d rep=%d alloc_failed\n", mode, rep); continue; }
        /* F lowest, T in the middle, X highest; 64 KiB apart so that no page grain puts them together */
        uint8_t *F = b, *T = b + 0x10000, *X = b + 0x20000, *p, *operand = T + 8;
        p = F;                                   /* F: if (*flag) *operand = 0x22222222; ret */
        *p++ = 0x48; *p++ = 0xB8; put64(p, (uint64_t)(uintptr_t)flag); p += 8;      /* mov rax, flag    */
        *p++ = 0x8B; *p++ = 0x00;                                                    /* mov eax, [rax]   */
        *p++ = 0x85; *p++ = 0xC0;                                                    /* test eax, eax    */
        *p++ = 0x74; *p++ = 0x10;                                                    /* jz +16           */
        *p++ = 0x48; *p++ = 0xB8; put64(p, (uint64_t)(uintptr_t)operand); p += 8;    /* mov rax, operand */
        *p++ = 0xC7; *p++ = 0x00; put32(p, 0x22222222u); p += 4;                     /* mov dword [rax], 0x22222222 */
        *p++ = 0xC3;                                                                 /* ret              */
        p = T;                                   /* T: call F; mov eax, 0x11111111; ret */
        *p++ = 0x90; *p++ = 0x90;                                                    /* nop nop (operand lands on a 4-byte boundary) */
        *p++ = 0xE8; put32(p, (uint32_t)(F - (p + 4))); p += 4;                      /* call F           */
        *p++ = 0xB8; put32(p, 0x11111111u); p += 4;                                  /* mov eax, 0x11111111 */
        *p++ = 0xC3;                                                                 /* ret              */
        p = X;                                   /* X: jmp T */
        *p++ = 0xE9; put32(p, (uint32_t)(T - (p + 4))); p += 4;
        flush(b, 0x30000);

        uint32_t warm = 0, r = 0;
        int fin = 1;
        *flag = 0;
        if (mode == 2) {
            warm = ((fn0)X)(); warm = ((fn0)X)(); warm = ((fn0)X)();
            *flag = 1;
            r = ((fn0)X)();
        } else {
            run_thread((fn0)X, 3, 5000, &warm);          /* thread 1: goes X -> T -> F -> T, nothing is written */
            *flag = 1;
            fin = run_thread(mode == 0 ? (fn0)X : (fn0)T, 1, 5000, &r);   /* thread 2: F rewrites T's operand, returns into T */
        }
        uint32_t mem = get32(operand);
        uint32_t again = ((fn0)T)();                      /* later call from the main thread */
        printf("S1A mode=%d rep=%d warm=%08x finished=%d returned=%08x operand_in_memory=%08x later_call=%08x\n",
               mode, rep, warm, fin, r, mem, again);
        if (fin && warm == 0x11111111u && r == 0x22222222u && mem == 0x22222222u && again == 0x22222222u) x86++;
        VirtualFree(b, 0, MEM_RELEASE);
        VirtualFree((void *)flag, 0, MEM_RELEASE);
    }
    printf("SUMMARY S1A mode=%d runs=%d as_x86=%d\n", mode, reps, x86);
    return x86 == reps;
}

/* ---------- S1B ---------- */
static int s1b(int reps)
{
    int x86 = 0;
    for (int rep = 0; rep < reps; rep++) {
        uint8_t *b = rwx(0x1000);
        volatile uint32_t *esc = (volatile uint32_t *)rw(0x1000);
        if (!b || !esc) { printf("S1B rep=%d alloc_failed\n", rep); continue; }
        uint8_t *p = b;
        /* L: nop nop nop; mov eax, 0; test eax, eax; jnz out; mov rcx, esc; mov ecx, [rcx]; test ecx, ecx; jz L; out: ret */
        *p++ = 0x90; *p++ = 0x90; *p++ = 0x90;
        *p++ = 0xB8; put32(p, 0); p += 4;                                           /* operand at b+4 */
        *p++ = 0x85; *p++ = 0xC0;
        *p++ = 0x75; *p++ = 0x10;
        *p++ = 0x48; *p++ = 0xB9; put64(p, (uint64_t)(uintptr_t)esc); p += 8;
        *p++ = 0x8B; *p++ = 0x09;
        *p++ = 0x85; *p++ = 0xC9;
        *p++ = 0x74; *p++ = 0xE4;
        *p++ = 0xC3;
        flush(b, 0x1000);
        *esc = 0;
        struct call c;
        c.f = (fn0)b; c.times = 1; c.r = 0xdeadbeefu; c.done = 0;
        HANDLE h = CreateThread(NULL, 0, call_proc, &c, 0, NULL);
        Sleep(30);                                                                   /* the thread is spinning in L */
        double t0 = now_ms();
        *(volatile uint32_t *)(b + 4) = 1;                                           /* one aligned 4-byte store */
        int by_code = 0, by_escape = 0;
        for (int i = 0; i < 1000 && !c.done; i++) Sleep(1);
        double t1 = now_ms();
        if (c.done) by_code = 1;
        else {
            *esc = 1;                                                                /* let it leave through data */
            for (int i = 0; i < 3000 && !c.done; i++) Sleep(1);
            if (c.done) by_escape = 1;
        }
        if (WaitForSingleObject(h, 2000) != WAIT_OBJECT_0) { TerminateThread(h, 1); WaitForSingleObject(h, 1000); }
        CloseHandle(h);
        printf("S1B rep=%d left_loop_after_code_change=%d left_only_after_data_flag=%d returned=%08x\n", rep, by_code, by_escape, c.r);
        printf("# S1B rep=%d ms_until_exit=%.1f\n", rep, t1 - t0);
        if (by_code && c.r == 1) x86++;
        VirtualFree(b, 0, MEM_RELEASE);
        VirtualFree((void *)esc, 0, MEM_RELEASE);
    }
    printf("SUMMARY S1B runs=%d as_x86=%d\n", reps, x86);
    return x86 == reps;
}

/* ---------- S2 ---------- */
static uint8_t *g_page;
static volatile LONG g_hits;
static volatile LONG g_info0;
static LONG CALLBACK veh(EXCEPTION_POINTERS *e)
{
    EXCEPTION_RECORD *r = e->ExceptionRecord;
    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && g_page && r->NumberParameters >= 2) {
        uint8_t *a = (uint8_t *)r->ExceptionInformation[1];
        if (a >= g_page && a < g_page + 0x1000) {
            DWORD o;
            InterlockedExchange(&g_info0, (LONG)r->ExceptionInformation[0]);
            InterlockedIncrement(&g_hits);
            VirtualProtect(g_page, 0x1000, PAGE_EXECUTE_READWRITE, &o);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void guarded_write32(uint8_t *page, uint8_t *where, uint32_t v, LONG *faults, LONG *kind)
{
    g_page = page; g_hits = 0; g_info0 = -1;
    *(volatile uint32_t *)where = v;
    *faults = g_hits; *kind = g_info0;
    g_page = NULL;
}
static void s2(void)
{
    LONG faults, kind;
    /* S2A: the program never asks for anything but RWX */
    uint8_t *p = rwx(0x1000);
    emit_ret_const(p, 1); flush(p, 0x1000);
    uint32_t r0 = ((fn0)p)();
    uint32_t q1 = qprot(p);
    DWORD old = 0xffff, prev = 0xffff;
    BOOL b1 = VirtualProtect(p, 0x1000, PAGE_EXECUTE_READWRITE, &old);
    uint32_t q2 = qprot(p);
    BOOL b2 = VirtualProtect(p, 0x1000, old, &prev);
    uint32_t q3 = qprot(p);
    guarded_write32(p, p + 1, 2, &faults, &kind);
    uint32_t r1 = ((fn0)p)();
    uint32_t q4 = qprot(p);
    printf("S2A first_call=%x query_after_call=%02x protect_rwx_ok=%d reported_old=%02x query=%02x restore_old_ok=%d reported_prev=%02x query=%02x "
           "write_faults=%ld fault_kind=%ld second_call=%x query_end=%02x\n",
           r0, q1, (int)b1, (unsigned)old, q2, (int)b2, (unsigned)prev, q3, faults, kind, r1, q4);

    /* S2B: RX -> RWX -> write -> restore -> run, then one write while the page is RX */
    p = rwx(0x1000);
    emit_ret_const(p, 1); flush(p, 0x1000);
    r0 = ((fn0)p)();
    DWORD o1 = 0xffff, o2 = 0xffff, o3 = 0xffff;
    b1 = VirtualProtect(p, 0x1000, PAGE_EXECUTE_READ, &o1);
    uint32_t ra = ((fn0)p)();
    q1 = qprot(p);
    b2 = VirtualProtect(p, 0x1000, PAGE_EXECUTE_READWRITE, &o2);
    q2 = qprot(p);
    guarded_write32(p, p + 1, 3, &faults, &kind);
    BOOL b3 = VirtualProtect(p, 0x1000, o2, &o3);
    q3 = qprot(p);
    uint32_t rb = ((fn0)p)();
    LONG faults2, kind2;
    guarded_write32(p, p + 1, 4, &faults2, &kind2);
    uint32_t rc = ((fn0)p)();
    q4 = qprot(p);
    printf("S2B first_call=%x to_rx_ok=%d old=%02x call=%x query=%02x to_rwx_ok=%d old=%02x query=%02x write_faults=%ld restore_ok=%d old=%02x query=%02x "
           "call_after_write=%x write_while_rx_faults=%ld fault_kind=%ld call_after_fault=%x query_end=%02x\n",
           r0, (int)b1, (unsigned)o1, ra, q1, (int)b2, (unsigned)o2, q2, faults, (int)b3, (unsigned)o3, q3, rb, faults2, kind2, rc, q4);
}

/* ---------- S3 ---------- */
struct s3ctx { fn0 f; volatile LONG seen; volatile LONG stop; volatile LONG calls; };
static DWORD WINAPI s3_proc(void *a)
{
    struct s3ctx *s = (struct s3ctx *)a;
    while (!s->stop) {
        uint32_t v = s->f();
        InterlockedExchange(&s->seen, (LONG)v);
        InterlockedIncrement(&s->calls);
    }
    return 0;
}
static int s3(int iterations)
{
    uint8_t *page = rwx(0x1000), *p = page;
    for (int i = 0; i < 200; i++) { *p++ = 0x48; *p++ = 0x8D; *p++ = 0x49; *p++ = 0x01; }   /* lea rcx, [rcx+1] x200 */
    *p++ = 0x90; *p++ = 0x90; *p++ = 0x90;
    *p++ = 0xB8; uint8_t *operand = p; put32(p, 0); p += 4;                                  /* operand at +804 */
    *p++ = 0xC3;
    flush(page, 0x1000);
    DWORD o;
    VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &o);
    struct s3ctx s;
    s.f = (fn0)page; s.seen = -1; s.stop = 0; s.calls = 0;
    HANDLE h = CreateThread(NULL, 0, s3_proc, &s, 0, NULL);
    for (int i = 0; i < 2000 && s.seen != 0; i++) Sleep(1);
    int stuck = 0, first_stuck = 0, done = 0, protect_failed = 0;
    double t0 = now_ms(), worst = 0;
    for (int k = 1; k <= iterations; k++) {
        if (!VirtualProtect(page, 0x1000, PAGE_EXECUTE_READWRITE, &o)) protect_failed++;
        *(volatile uint32_t *)operand = (uint32_t)k;
        if (!VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &o)) protect_failed++;
        double w0 = now_ms(), w = 0;
        while (s.seen != k && (w = now_ms() - w0) < 50.0) SwitchToThread();
        if (w > worst) worst = w;
        done = k;
        if (s.seen != k) { stuck++; if (!first_stuck) first_stuck = k; if (stuck >= 20) break; }
        if (now_ms() - t0 > 20000.0) break;
    }
    double t1 = now_ms();
    InterlockedExchange(&s.stop, 1);
    if (WaitForSingleObject(h, 5000) != WAIT_OBJECT_0) { TerminateThread(h, 1); WaitForSingleObject(h, 1000); }
    CloseHandle(h);
    printf("S3 new_value_not_seen_within_50ms=%d first_at=%d protect_failed=%d stopped_early=%d\n", stuck, first_stuck, protect_failed, done < iterations && stuck < 20);
    printf("# S3 iterations_done=%d of %d calls_by_runner=%ld total_ms=%.0f worst_wait_ms=%.1f\n", done, iterations, (long)s.calls, t1 - t0, worst);
    printf("SUMMARY S3 runs=1 as_x86=%d\n", stuck == 0 && protect_failed == 0);
    VirtualFree(page, 0, MEM_RELEASE);
    return stuck == 0;
}

/* ---------- S4 ---------- */
static void s4(void)
{
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    nt_rw wr = (nt_rw)(void *)GetProcAddress(nt, "NtWriteVirtualMemory");
    nt_rw rd = (nt_rw)(void *)GetProcAddress(nt, "NtReadVirtualMemory");
    HANDLE self = GetCurrentProcess();
    uint32_t v; SIZE_T n; LONG st; uint32_t r0, r1;

    uint8_t *p = rwx(0x1000); emit_ret_const(p, 1); flush(p, 0x1000);
    r0 = ((fn0)p)(); v = 5; n = 0;
    st = wr ? wr(self, p + 1, &v, 4, &n) : -1;
    r1 = ((fn0)p)();
    printf("S4A NtWriteVirtualMemory_into_operand first_call=%x status=%08lx written=%u operand_in_memory=%x second_call=%x\n", r0, (unsigned long)st, (unsigned)n, get32(p + 1), r1);

    p = rwx(0x1000); emit_ret_const(p, 1); flush(p, 0x1000);
    r0 = ((fn0)p)(); v = 6; n = 0;
    st = rd ? rd(self, &v, p + 1, 4, &n) : -1;
    r1 = ((fn0)p)();
    printf("S4B NtReadVirtualMemory_destination_is_operand first_call=%x status=%08lx read=%u operand_in_memory=%x second_call=%x\n", r0, (unsigned long)st, (unsigned)n, get32(p + 1), r1);

    p = rwx(0x1000); emit_ret_const(p, 1); flush(p, 0x1000);
    r0 = ((fn0)p)(); n = 0;
    uint8_t src[16];
    for (int i = 0; i < 16; i++) src[i] = (uint8_t)(0xA0 + i);
    st = rd ? rd(self, src, p + 0x800, 16, &n) : -1;
    int same = memcmp(src, p + 0x800, 16) == 0;
    r1 = ((fn0)p)();
    printf("S4C NtReadVirtualMemory_destination_on_code_page first_call=%x status=%08lx read=%u bytes_arrived=%d second_call=%x\n", r0, (unsigned long)st, (unsigned)n, same, r1);

    p = rwx(0x1000); emit_ret_const(p, 1); flush(p, 0x1000);
    r0 = ((fn0)p)(); v = 7; n = 0;
    BOOL ok = WriteProcessMemory(self, p + 1, &v, 4, &n);
    r1 = ((fn0)p)();
    printf("S4D WriteProcessMemory_into_operand first_call=%x ok=%d written=%u operand_in_memory=%x second_call=%x\n", r0, (int)ok, (unsigned)n, get32(p + 1), r1);
}

/* ---------- S5 ---------- */
static void s5(void)
{
    /* S5A: clc; adc dword [cell], -1 ; returns CF */
    uint8_t *page = rwx(0x1000), *p = page, *cell = page + 0x800;
    *p++ = 0x48; *p++ = 0xB8; put64(p, (uint64_t)(uintptr_t)cell); p += 8;
    *p++ = 0xF8;
    *p++ = 0x83; *p++ = 0x10; *p++ = 0xFF;
    *p++ = 0x0F; *p++ = 0x92; *p++ = 0xC0;
    *p++ = 0x0F; *p++ = 0xB6; *p++ = 0xC0;
    *p++ = 0xC3;
    flush(page, 0x1000);
    for (int i = 0; i < 3; i++) {
        *(volatile uint32_t *)cell = 1;
        uint32_t cf = ((fn0)page)();
        printf("S5A adc_into_own_page call=%d cell=%08x carry=%u\n", i, get32(cell), cf);
    }
    /* S5A2: stc; sbb dword [cell], 0 ; returns CF */
    page = rwx(0x1000); p = page; cell = page + 0x800;
    *p++ = 0x48; *p++ = 0xB8; put64(p, (uint64_t)(uintptr_t)cell); p += 8;
    *p++ = 0xF9;
    *p++ = 0x83; *p++ = 0x18; *p++ = 0x00;
    *p++ = 0x0F; *p++ = 0x92; *p++ = 0xC0;
    *p++ = 0x0F; *p++ = 0xB6; *p++ = 0xC0;
    *p++ = 0xC3;
    flush(page, 0x1000);
    for (int i = 0; i < 3; i++) {
        *(volatile uint32_t *)cell = 5;
        uint32_t cf = ((fn0)page)();
        printf("S5A2 sbb_into_own_page call=%d cell=%08x carry=%u\n", i, get32(cell), cf);
    }
    /* S5B: push 0x1234; pop qword [cell]; returns rsp_after - rsp_before */
    page = rwx(0x1000); p = page; cell = page + 0x800;
    *p++ = 0x48; *p++ = 0xB9; put64(p, (uint64_t)(uintptr_t)cell); p += 8;
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xE2;
    *p++ = 0x68; put32(p, 0x1234); p += 4;
    *p++ = 0x8F; *p++ = 0x01;
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xE0;
    *p++ = 0x48; *p++ = 0x29; *p++ = 0xD0;
    *p++ = 0xC3;
    flush(page, 0x1000);
    for (int i = 0; i < 3; i++) {
        uint64_t zero = 0;
        memcpy(cell, &zero, 8);
        int64_t d = ((fn0q)page)();
        uint64_t got; memcpy(&got, cell, 8);
        printf("S5B pop_into_own_page call=%d cell=%llx stack_pointer_change=%lld\n", i, (unsigned long long)got, (long long)d);
    }
    /* S5C: rep movsb, destination = source - 1, 64 bytes, all on the page of the code */
    page = rwx(0x1000); p = page;
    uint8_t *src = page + 0x900;
    *p++ = 0x56; *p++ = 0x57;
    *p++ = 0x48; *p++ = 0xBE; put64(p, (uint64_t)(uintptr_t)src); p += 8;
    *p++ = 0x48; *p++ = 0xBF; put64(p, (uint64_t)(uintptr_t)(src - 1)); p += 8;
    *p++ = 0xB9; put32(p, 64); p += 4;
    *p++ = 0xFC;
    *p++ = 0xF3; *p++ = 0xA4;
    *p++ = 0x5F; *p++ = 0x5E;
    *p++ = 0xC3;
    flush(page, 0x1000);
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j <= 64; j++) src[j - 1] = (uint8_t)j;                     /* src[-1]=0, src[k]=k+1 */
        ((fn0)page)();
        int bad = 0, first = -1;
        for (int j = 0; j < 64; j++) if (src[j - 1] != (uint8_t)(j + 1)) { bad++; if (first < 0) first = j; }
        printf("S5C rep_movsb_overlapping_in_own_page call=%d wrong_bytes=%d first_wrong=%d last_source_byte=%02x\n", i, bad, first, src[63]);
    }
}

/* ---------- S6 ---------- */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}
static void s6_report(const char *what, uint64_t *ns, uint64_t *tsc, int n)
{
    qsort(ns, (size_t)n, sizeof *ns, cmp_u64);
    qsort(tsc, (size_t)n, sizeof *tsc, cmp_u64);
    printf("# S6 %s stores=%d ns_min=%llu ns_median=%llu ns_p90=%llu ns_max=%llu tsc_min=%llu tsc_median=%llu tsc_p90=%llu tsc_max=%llu\n", what, n,
           (unsigned long long)ns[0], (unsigned long long)ns[n / 2], (unsigned long long)ns[n * 9 / 10], (unsigned long long)ns[n - 1],
           (unsigned long long)tsc[0], (unsigned long long)tsc[n / 2], (unsigned long long)tsc[n * 9 / 10], (unsigned long long)tsc[n - 1]);
}
static void s6(void)
{
    enum { N = 300 };
    static uint64_t ns[N], tsc[N];
    LARGE_INTEGER f, a, b;
    QueryPerformanceFrequency(&f);
    /* the function on the page is called before every store, so the page holds executed code each time */
    uint8_t *page = rwx(0x1000);
    emit_ret_const(page, 0); flush(page, 0x1000);
    int seen = 0;
    for (int i = 0; i < N; i++) {
        (void)((fn0)page)();
        QueryPerformanceCounter(&a);
        uint64_t t0 = __rdtsc();
        *(volatile uint32_t *)(page + 1) = (uint32_t)(i + 1);
        uint64_t t1 = __rdtsc();
        QueryPerformanceCounter(&b);
        ns[i] = (uint64_t)((b.QuadPart - a.QuadPart) * 1000000000LL / f.QuadPart);
        tsc[i] = t1 - t0;
        if (((fn0)page)() == (uint32_t)(i + 1)) seen++;
    }
    printf("S6 store_into_executed_page stores=%d new_value_returned=%d\n", N, seen);
    s6_report("store_into_executed_page", ns, tsc, N);
    /* control: the same store into a page of the same kind whose code was never executed */
    uint8_t *cold = rwx(0x1000);
    emit_ret_const(cold, 0);
    for (int i = 0; i < N; i++) {
        QueryPerformanceCounter(&a);
        uint64_t t0 = __rdtsc();
        *(volatile uint32_t *)(cold + 1) = (uint32_t)(i + 1);
        uint64_t t1 = __rdtsc();
        QueryPerformanceCounter(&b);
        ns[i] = (uint64_t)((b.QuadPart - a.QuadPart) * 1000000000LL / f.QuadPart);
        tsc[i] = t1 - t0;
    }
    s6_report("store_into_never_executed_page", ns, tsc, N);
    printf("# S6 qpc_frequency=%lld\n", (long long)f.QuadPart);
}

static int wanted(const char *only, const char *name)
{
    if (!only) return 1;
    size_t n = strlen(name);
    for (const char *q = only; (q = strstr(q, name)) != NULL; q += n) {
        if ((q == only || q[-1] == ',') && (q[n] == 0 || q[n] == ',')) return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *only = NULL;
    for (int i = 1; i + 1 < argc; i++) if (!strcmp(argv[i], "--only")) only = argv[i + 1];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("SMC-SCENARIOS v2\n");
    AddVectoredExceptionHandler(1, veh);
    if (wanted(only, "S2")) s2();
    if (wanted(only, "S4")) s4();
    if (wanted(only, "S5")) s5();
    if (wanted(only, "S1A")) { s1a(2, 10); s1a(1, 10); s1a(0, 20); }
    if (wanted(only, "S1B")) s1b(5);
    if (wanted(only, "S3")) s3(2000);
    if (wanted(only, "S6")) s6();
    printf("END\n");
    return 0;
}
