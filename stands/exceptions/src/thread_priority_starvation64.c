/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 HyperBridge contributors */
/* Thread-priority starvation probe (Windows x86-64, console, no game needed).
 *
 * Models what a game loader does: a few low-priority threads do a fixed amount of work while
 * higher-priority worker threads poll for the result (spin for a while, yield, sleep briefly).
 * Windows runs a low-priority thread on any core that is free, so the work finishes in about the
 * same wall time whatever its priority. A compatibility layer that maps Windows priorities onto
 * strict host priorities (or host background classes) can leave the low-priority threads with no
 * CPU at all: the work never finishes while the pollers spin.
 *
 *   thread_priority_starvation64.exe <cell> [limit_seconds]
 *     cell 0  control: work threads at THREAD_PRIORITY_NORMAL
 *     cell 1  work threads at THREAD_PRIORITY_BELOW_NORMAL
 *     cell 2  work threads at THREAD_PRIORITY_LOWEST
 *     cell 3  work threads at THREAD_PRIORITY_IDLE
 *     cell 4  work threads at THREAD_PRIORITY_IDLE, pollers at THREAD_PRIORITY_NORMAL
 *
 * Output: one line per work thread (wall ms, CPU ms) and a RESULT line. Exit code 0 = all work
 * finished within the limit, 3 = limit hit (starvation), 2 = usage.
 * The amount of work is fixed in iterations, so wall time depends on the machine; compare cells of
 * one run with each other (cell N wall / cell 0 wall), never raw numbers between machines.
 */
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum { WORK_THREADS = 5, MAX_POLLERS = 64 };

static volatile LONG done_count;
static volatile LONG stop_pollers;
static volatile LONG poll_generation;
static LARGE_INTEGER qpc_freq;
static uint64_t work_iterations = 60ull * 1000 * 1000;

typedef struct { int index; double wall_ms, cpu_ms; uint64_t sum; LONG finished; } WORK;
static WORK work[WORK_THREADS];

static double now_ms(void)
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart * 1000.0 / (double)qpc_freq.QuadPart;
}

static double thread_cpu_ms(HANDLE thread)
{
    FILETIME c, e, k, u;
    ULARGE_INTEGER a, b;
    if (!GetThreadTimes(thread, &c, &e, &k, &u)) return -1.0;
    a.LowPart = k.dwLowDateTime; a.HighPart = k.dwHighDateTime;
    b.LowPart = u.dwLowDateTime; b.HighPart = u.dwHighDateTime;
    return (double)(a.QuadPart + b.QuadPart) / 10000.0;
}

static DWORD WINAPI work_thread(void *arg)
{
    WORK *w = arg;
    double t0 = now_ms();
    uint64_t x = 0x9e3779b97f4a7c15ull + (uint64_t)w->index, sum = 0;
    for (uint64_t i = 0; i < work_iterations; i++)
    {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;   /* xorshift: integer work that cannot be skipped */
        sum += x;
    }
    w->sum = sum;
    w->wall_ms = now_ms() - t0;
    w->cpu_ms = thread_cpu_ms(GetCurrentThread());
    InterlockedExchange(&w->finished, 1);
    InterlockedIncrement(&done_count);
    return 0;
}

/* Poller: about 1 ms of spinning, a yield, then a wait of up to 1 ms. Roughly half a core each. */
static DWORD WINAPI poll_thread(void *arg)
{
    (void)arg;
    while (!stop_pollers)
    {
        double until = now_ms() + 1.0;
        LONG seen = poll_generation;
        while (!stop_pollers && now_ms() < until) YieldProcessor();
        SwitchToThread();
        WaitOnAddress((volatile void *)&poll_generation, &seen, sizeof(seen), 1);
    }
    return 0;
}

int main(int argc, char **argv)
{
    static const int work_priority[] = { THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_BELOW_NORMAL,
                                         THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_IDLE, THREAD_PRIORITY_IDLE };
    HANDLE workers[WORK_THREADS], pollers[MAX_POLLERS];
    SYSTEM_INFO si;
    int cell, limit_s = 60, npoll, poll_priority;
    double t0, wall;

    if (argc < 2 || argc > 3) { fprintf(stderr, "usage: thread_priority_starvation64.exe <cell 0..4> [limit_seconds]\n"); return 2; }
    cell = atoi(argv[1]);
    if (cell < 0 || cell > 4) return 2;
    if (argc == 3) limit_s = atoi(argv[2]);
    if (limit_s < 1 || limit_s > 600) return 2;

    QueryPerformanceFrequency(&qpc_freq);
    GetSystemInfo(&si);
    npoll = (int)si.dwNumberOfProcessors;          /* as many pollers as logical processors */
    if (npoll > MAX_POLLERS) npoll = MAX_POLLERS;
    poll_priority = cell == 4 ? THREAD_PRIORITY_NORMAL : THREAD_PRIORITY_ABOVE_NORMAL;

    printf("probe=thread_priority_starvation64 version=1 cell=%d processors=%lu pollers=%d poller_priority=%d "
           "work_threads=%d work_priority=%d iterations=%llu limit_s=%d\n",
           cell, (unsigned long)si.dwNumberOfProcessors, npoll, poll_priority, WORK_THREADS, work_priority[cell],
           (unsigned long long)work_iterations, limit_s);

    for (int i = 0; i < npoll; i++)
    {
        pollers[i] = CreateThread(NULL, 0, poll_thread, NULL, CREATE_SUSPENDED, NULL);
        if (!pollers[i]) { printf("RESULT cell=%d error=CreateThread(poller) gle=%lu\n", cell, GetLastError()); return 4; }
        SetThreadPriority(pollers[i], poll_priority);
        ResumeThread(pollers[i]);
    }
    Sleep(200);                                     /* let the pollers reach their steady pattern */

    t0 = now_ms();
    for (int i = 0; i < WORK_THREADS; i++)
    {
        work[i].index = i;
        workers[i] = CreateThread(NULL, 0, work_thread, &work[i], CREATE_SUSPENDED, NULL);
        if (!workers[i]) { printf("RESULT cell=%d error=CreateThread(work) gle=%lu\n", cell, GetLastError()); return 4; }
        SetThreadPriority(workers[i], work_priority[cell]);
        ResumeThread(workers[i]);
    }
    DWORD wr = WaitForMultipleObjects(WORK_THREADS, workers, TRUE, (DWORD)limit_s * 1000);
    wall = now_ms() - t0;

    for (int i = 0; i < WORK_THREADS; i++)
    {
        if (work[i].finished)
            printf("work[%d] finished=1 wall_ms=%.1f cpu_ms=%.1f\n", i, work[i].wall_ms, work[i].cpu_ms);
        else
            printf("work[%d] finished=0 cpu_ms_so_far=%.1f\n", i, thread_cpu_ms(workers[i]));
    }
    printf("RESULT cell=%d finished=%ld/%d wall_ms=%.1f limit_hit=%d\n",
           cell, (long)done_count, WORK_THREADS, wall, wr == WAIT_TIMEOUT);
    fflush(stdout);

    InterlockedExchange(&stop_pollers, 1);
    InterlockedIncrement(&poll_generation);
    WakeByAddressAll((void *)&poll_generation);
    if (wr == WAIT_TIMEOUT) ExitProcess(3);         /* work threads may still be starved: do not wait for them */
    WaitForMultipleObjects(npoll, pollers, TRUE, 5000);
    return 0;
}
