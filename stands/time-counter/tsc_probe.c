/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 HyperBridge contributors
 *
 * tsc_probe.c — small self-contained probe of how the time-stamp counter and the other clocks of a Windows x64
 * process behave. It reads only its own clocks; it has no knowledge of any other program.
 * Purpose: compare a real x86-64 Windows machine, Wine on Rosetta 2 (CrossOver) and our x86-64 -> ARM64 translator.
 * Output: "CELL <name> key=value ..." raw lines and "INV <name>=<0|1|n>" lines meant to be equal on every correct side.
 * Build: x86_64-w64-mingw32-clang -O2 -std=c11 -o tsc-probe.exe tsc_probe.c
 * Windows build in this stand: see run-windows.ps1 (installed clang-cl). */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>
#include <x86intrin.h>

#define KUSD 0x7ffe0000ULL
static uint64_t kusd_time(unsigned off) { /* KSYSTEM_TIME: LowPart, High1Time, High2Time */
    volatile uint32_t *p = (volatile uint32_t *)(KUSD + off); uint32_t lo, hi, hi2;
    do { hi = p[1]; lo = p[0]; hi2 = p[2]; } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}
static uint64_t qpc(void) { LARGE_INTEGER v; QueryPerformanceCounter(&v); return (uint64_t)v.QuadPart; }
static int cmp64(const void *a, const void *b) { uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return x < y ? -1 : x > y; }
static uint64_t gcd64(uint64_t a, uint64_t b) { while (b) { uint64_t t = a % b; a = b; b = t; } return a; }
static int inv_n = 0;
static void inv(const char *name, long long v) { printf("INV %s=%lld\n", name, v); inv_n++; }

static void cell_cpuid(void) {
    int r[4]; char vendor[13] = {0}, brand[49] = {0}, hv[13] = {0};
    __cpuid(r, 0); int maxleaf = r[0]; memcpy(vendor, &r[1], 4); memcpy(vendor + 4, &r[3], 4); memcpy(vendor + 8, &r[2], 4);
    __cpuid(r, 1); int tsc_bit = (r[3] >> 4) & 1, hvbit = (r[2] >> 31) & 1; unsigned fms = (unsigned)r[0];
    __cpuid(r, 0x80000000); unsigned maxext = (unsigned)r[0];
    int rdtscp = 0, invariant = 0;
    if (maxext >= 0x80000001) { __cpuid(r, 0x80000001); rdtscp = (r[3] >> 27) & 1; }
    if (maxext >= 0x80000007) { __cpuid(r, 0x80000007); invariant = (r[3] >> 8) & 1; }
    if (maxext >= 0x80000004) { __cpuid((int *)brand, 0x80000002); __cpuid((int *)(brand + 16), 0x80000003); __cpuid((int *)(brand + 32), 0x80000004); }
    unsigned l15[4] = {0}, l16[4] = {0};
    if (maxleaf >= 0x15) __cpuidex((int *)l15, 0x15, 0);
    if (maxleaf >= 0x16) __cpuidex((int *)l16, 0x16, 0);
    if (hvbit) { __cpuid(r, 0x40000000); memcpy(hv, &r[1], 4); memcpy(hv + 4, &r[2], 4); memcpy(hv + 8, &r[3], 4); }
    printf("CELL cpuid vendor=%s brand=\"%s\" fms=%08x maxleaf=%x maxext=%x tsc=%d rdtscp=%d invariant_tsc=%d hypervisor=%d hv=\"%s\" leaf15=%x/%x/%x leaf16_mhz=%u\n",
           vendor, brand, fms, maxleaf, maxext, tsc_bit, rdtscp, invariant, hvbit, hv, l15[0], l15[1], l15[2], l16[0]);
    inv("cpuid_tsc_bit", tsc_bit); inv("cpuid_invariant_tsc", invariant); inv("cpuid_rdtscp", rdtscp);
}

#define NP 2000000
static uint64_t *buf;
static void cell_pairs(void) {
    /* two reads with nothing in between */
    uint64_t zero = 0, neg = 0, mn = ~0ULL, mx = 0; 
    for (int i = 0; i < NP; i++) {
        uint64_t a = __rdtsc(), b = __rdtsc(); int64_t d = (int64_t)(b - a);
        if (d == 0) zero++; if (d < 0) neg++;
        buf[i] = (uint64_t)d; if ((uint64_t)d < mn) mn = (uint64_t)d; if ((uint64_t)d > mx) mx = (uint64_t)d;
    }
    qsort(buf, NP, 8, cmp64);
    printf("CELL pairs n=%d zero_delta=%llu negative=%llu min=%llu p01=%llu p50=%llu p99=%llu max=%llu\n", NP, (unsigned long long)zero, (unsigned long long)neg,
           (unsigned long long)mn, (unsigned long long)buf[NP / 100], (unsigned long long)buf[NP / 2], (unsigned long long)buf[NP - NP / 100], (unsigned long long)mx);
    inv("pair_zero_delta_present", zero != 0); inv("pair_negative_present", neg != 0);
    inv("pair_zero_delta_majority", zero * 2 > NP);
}
static void cell_lowbits(void) {
    /* one read per iteration with a small varying amount of work between reads */
    uint64_t orv = 0, andv = ~0ULL, g = 0, prev = 0; unsigned char seen6[64] = {0}, seen8[256] = {0}; volatile unsigned sink = 0;
    int minctz = 64; uint64_t same = 0;
    for (int i = 0; i < NP; i++) {
        for (unsigned k = 0; k < (unsigned)(i & 31); k++) sink += k;
        uint64_t t = __rdtsc(); orv |= t; andv &= t; seen6[t & 63] = 1; seen8[t & 255] = 1;
        if (t) { int z = __builtin_ctzll(t); if (z < minctz) minctz = z; }
        if (i) { if (t == prev) same++; else g = gcd64(g, t - prev); }
        prev = t;
    }
    int d6 = 0, d8 = 0; for (int i = 0; i < 64; i++) d6 += seen6[i]; for (int i = 0; i < 256; i++) d8 += seen8[i];
    printf("CELL lowbits n=%d or_low16=%04x and_low16=%04x distinct_low6=%d distinct_low8=%d min_trailing_zeros=%d gcd_of_steps=%llu equal_to_previous=%llu\n",
           NP, (unsigned)(orv & 0xffff), (unsigned)(andv & 0xffff), d6, d8, minctz, (unsigned long long)g, (unsigned long long)same);
    inv("low6_always_zero", (orv & 63) == 0); inv("low6_distinct_values", d6); inv("low8_distinct_values", d8);
    inv("gcd_of_steps_is_1", g == 1); inv("lowbits_equal_to_previous_present", same != 0);
}
static void cell_tight(void) {
    /* how many consecutive reads return the same value; how many distinct values in a tight loop */
    uint64_t prev = __rdtsc(), run = 1, maxrun = 1, distinct = 1, steps_sum = 0, minstep = ~0ULL;
    for (int i = 0; i < NP; i++) {
        uint64_t t = __rdtsc();
        if (t == prev) { run++; if (run > maxrun) maxrun = run; }
        else { distinct++; run = 1; if (t - prev < minstep) minstep = t - prev; steps_sum += t - prev; }
        prev = t;
    }
    printf("CELL tight n=%d distinct_values=%llu longest_run_of_equal=%llu min_step=%llu mean_step=%.1f\n", NP, (unsigned long long)distinct,
           (unsigned long long)maxrun, (unsigned long long)minstep, distinct > 1 ? (double)steps_sum / (double)(distinct - 1) : 0.0);
    inv("tight_every_read_distinct", distinct == (uint64_t)NP + 1); inv("tight_longest_run_gt_1", maxrun > 1);
}
static double tsc_hz_est;
static void cell_rate(void) {
    LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    double est[6], mn = 1e30, mx = 0;
    for (int i = 0; i < 6; i++) {
        uint64_t q0 = qpc(), t0 = __rdtsc(); Sleep(100); uint64_t q1 = qpc(), t1 = __rdtsc();
        est[i] = (double)(t1 - t0) * (double)f.QuadPart / (double)(q1 - q0);
        if (est[i] < mn) mn = est[i]; if (est[i] > mx) mx = est[i];
    }
    tsc_hz_est = (mn + mx) / 2;
    printf("CELL rate qpc_hz=%lld tsc_hz_min=%.0f tsc_hz_max=%.0f spread_ppm=%.0f\n", (long long)f.QuadPart, mn, mx, (mx - mn) / mn * 1e6);
    inv("qpc_frequency_is_10mhz", f.QuadPart == 10000000); inv("tsc_rate_ge_1ghz", tsc_hz_est >= 1e9);
    inv("tsc_vs_qpc_spread_lt_2000ppm", (mx - mn) / mn * 1e6 < 2000);
}
static void cell_qpc(void) {
    uint64_t zero = 0, mn = ~0ULL, g = 0;
    for (int i = 0; i < 200000; i++) { uint64_t a = qpc(), b = qpc(); if (b == a) zero++; else { if (b - a < mn) mn = b - a; g = gcd64(g, b - a); } }
    printf("CELL qpc pairs=200000 zero_delta=%llu min_nonzero=%llu gcd=%llu\n", (unsigned long long)zero, (unsigned long long)mn, (unsigned long long)g);
    inv("qpc_pair_zero_delta_present", zero != 0);
}
static void cell_clocks(void) {
    /* elapsed time of one ~1 s interval according to every clock */
    LARGE_INTEGER f; QueryPerformanceFrequency(&f); FILETIME ft0, ft1, fp0, fp1; LARGE_INTEGER n0, n1;
    uint64_t q0 = qpc(), t0 = __rdtsc(), tick0 = GetTickCount64(), it0 = kusd_time(0x08), st0 = kusd_time(0x14);
    GetSystemTimeAsFileTime(&ft0); GetSystemTimePreciseAsFileTime(&fp0); NtQuerySystemTime(&n0);
    Sleep(1000);
    uint64_t q1 = qpc(), t1 = __rdtsc(), tick1 = GetTickCount64(), it1 = kusd_time(0x08), st1 = kusd_time(0x14);
    GetSystemTimeAsFileTime(&ft1); GetSystemTimePreciseAsFileTime(&fp1); NtQuerySystemTime(&n1);
    double ms_q = (double)(q1 - q0) * 1000.0 / (double)f.QuadPart, ms_t = (double)(t1 - t0) * 1000.0 / tsc_hz_est;
    double ms_tick = (double)(tick1 - tick0), ms_it = (double)(it1 - it0) / 1e4, ms_st = (double)(st1 - st0) / 1e4;
    double ms_ft = (double)((((uint64_t)ft1.dwHighDateTime << 32) | ft1.dwLowDateTime) - (((uint64_t)ft0.dwHighDateTime << 32) | ft0.dwLowDateTime)) / 1e4;
    double ms_fp = (double)((((uint64_t)fp1.dwHighDateTime << 32) | fp1.dwLowDateTime) - (((uint64_t)fp0.dwHighDateTime << 32) | fp0.dwLowDateTime)) / 1e4;
    double ms_nt = (double)(n1.QuadPart - n0.QuadPart) / 1e4;
    printf("CELL clocks_ms qpc=%.2f tsc=%.2f tick64=%.0f kusd_interrupt=%.2f kusd_system=%.2f filetime=%.2f precise=%.2f ntsystemtime=%.2f\n", ms_q, ms_t, ms_tick, ms_it, ms_st, ms_ft, ms_fp, ms_nt);
    double v[] = {ms_t, ms_tick, ms_it, ms_st, ms_ft, ms_fp, ms_nt}; double worst = 0;
    for (int i = 0; i < 7; i++) { double d = v[i] - ms_q; if (d < 0) d = -d; if (d > worst) worst = d; }
    inv("clocks_agree_within_40ms", worst < 40.0); inv("kusd_interrupt_time_advances", it1 != it0); inv("kusd_system_time_advances", st1 != st0);
    uint64_t kq = *(volatile uint64_t *)(KUSD + 0x300), bias = *(volatile uint64_t *)(KUSD + 0x3b8), itb = *(volatile uint64_t *)(KUSD + 0x3b0);
    unsigned char bypass = *(volatile unsigned char *)(KUSD + 0x3c6), shift = *(volatile unsigned char *)(KUSD + 0x3c7);
    uint32_t mult = *(volatile uint32_t *)(KUSD + 0x04);
    printf("CELL kusd qpc_frequency=%llu qpc_bias=%llx interrupt_time_bias=%llx qpc_bypass=%02x qpc_shift=%u tick_multiplier=%08x\n",
           (unsigned long long)kq, (unsigned long long)bias, (unsigned long long)itb, bypass, shift, mult);
    inv("kusd_qpc_frequency_matches_api", kq == (uint64_t)f.QuadPart);
    /* does QueryPerformanceCounter follow the documented bypass formula (rdtsc + bias) >> shift ? */
    int formula = -1;
    if (bypass & 1) { uint64_t a = __rdtsc(), q = qpc(), b = __rdtsc(); uint64_t lo = (a + bias) >> shift, hi = (b + bias) >> shift; formula = (q >= lo && q <= hi); }
    printf("CELL qpc_formula bypass_enabled=%d qpc_equals_shifted_tsc=%d\n", bypass & 1, formula);
}
static volatile LONG lock_; static uint64_t last_; static volatile LONG64 regress_, equal_;
static DWORD WINAPI xthread(void *arg) {
    (void)arg;
    for (int i = 0; i < 300000; i++) {
        while (InterlockedExchange(&lock_, 1)) _mm_pause();
        uint64_t t = __rdtsc(); if (t < last_) InterlockedIncrement64(&regress_); else if (t == last_) InterlockedIncrement64(&equal_); last_ = t;
        InterlockedExchange(&lock_, 0);
    }
    return 0;
}
static void cell_threads(void) {
    HANDLE h[4]; for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, xthread, NULL, 0, NULL);
    WaitForMultipleObjects(4, h, TRUE, 60000); for (int i = 0; i < 4; i++) CloseHandle(h[i]);
    printf("CELL threads n=1200000 went_backwards=%lld equal_to_last=%lld\n", (long long)regress_, (long long)equal_);
    inv("threads_went_backwards_present", regress_ != 0); inv("threads_equal_present", equal_ != 0);
}
static void cell_rdtscp(void) {
    int r[4]; __cpuid(r, 0x80000000); if ((unsigned)r[0] < 0x80000001) { printf("CELL rdtscp supported=0\n"); return; }
    __cpuid(r, 0x80000001); if (!((r[3] >> 27) & 1)) { printf("CELL rdtscp supported=0\n"); return; }
    unsigned aux = 0, auxor = 0, auxand = ~0u; uint64_t zero = 0, back = 0;
    for (int i = 0; i < 200000; i++) { uint64_t a = __rdtsc(); uint64_t b = __rdtscp(&aux); if (b == a) zero++; if (b < a) back++; auxor |= aux; auxand &= aux; }
    printf("CELL rdtscp supported=1 n=200000 zero_delta_after_rdtsc=%llu went_backwards=%llu aux_or=%x aux_and=%x\n", (unsigned long long)zero, (unsigned long long)back, auxor, auxand);
    inv("rdtscp_zero_delta_present", zero != 0);
}
static void cell_cputime(void) {
    /* one thread spins for 400 ms: CPU time reported for the thread and the process against wall time */
    FILETIME c, e, k0, u0, k1, u1, pk0, pu0, pk1, pu1; LARGE_INTEGER f; QueryPerformanceFrequency(&f);
    GetThreadTimes(GetCurrentThread(), &c, &e, &k0, &u0); GetProcessTimes(GetCurrentProcess(), &c, &e, &pk0, &pu0);
    uint64_t q0 = qpc(), polls = 0, changes = 0, lastv = 0; volatile double x = 1.0;
    while ((double)(qpc() - q0) / (double)f.QuadPart < 0.4) {
        for (int i = 0; i < 20000; i++) x = x * 1.0000001 + 0.1;
        FILETIME kk, uu; GetProcessTimes(GetCurrentProcess(), &c, &e, &kk, &uu); uint64_t v = (((uint64_t)uu.dwHighDateTime << 32) | uu.dwLowDateTime) + (((uint64_t)kk.dwHighDateTime << 32) | kk.dwLowDateTime);
        polls++; if (v != lastv) { changes++; lastv = v; }
    }
    double wall = (double)(qpc() - q0) * 1000.0 / (double)f.QuadPart;
    GetThreadTimes(GetCurrentThread(), &c, &e, &k1, &u1); GetProcessTimes(GetCurrentProcess(), &c, &e, &pk1, &pu1);
#define FT(x) ((((uint64_t)(x).dwHighDateTime << 32) | (x).dwLowDateTime))
    double th = (double)((FT(k1) + FT(u1)) - (FT(k0) + FT(u0))) / 1e4, pr = (double)((FT(pk1) + FT(pu1)) - (FT(pk0) + FT(pu0))) / 1e4;
    printf("CELL cputime wall_ms=%.1f thread_cpu_ms=%.1f process_cpu_ms=%.1f polls=%llu process_time_changes=%llu\n", wall, th, pr, (unsigned long long)polls, (unsigned long long)changes);
    inv("thread_cpu_time_between_50_and_110_percent_of_wall", th >= wall * 0.5 && th <= wall * 1.1);
    inv("process_cpu_time_ge_thread_cpu_time", pr + 16.0 >= th); inv("process_cpu_time_le_3x_wall", pr <= wall * 3.0);
    inv("process_time_changes_ge_5", changes >= 5);
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    buf = (uint64_t *)malloc((size_t)NP * 8); if (!buf) return 3;
    SetThreadAffinityMask(GetCurrentThread(), 1);   /* single-thread cells stay on one processor */
    printf("# tsc_probe v1\n");
    cell_cpuid(); cell_pairs(); cell_lowbits(); cell_tight(); cell_rate(); cell_qpc(); cell_clocks(); cell_rdtscp(); cell_cputime();
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)-1);
    cell_threads();
    printf("# done inv=%d\n", inv_n);
    return 0;
}
