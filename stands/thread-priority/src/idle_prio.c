// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
/* idle_prio.c - a diagnostic probe, not Wine code.
 * How much work does a THREAD_PRIORITY_IDLE thread get done next to busy threads of a higher priority?
 * Each phase runs for a fixed time and prints the number of loop steps the worker thread completed.
 * Waiting threads come in three kinds: 0 spins in place, 1 yields with SwitchToThread, 2 yields with Sleep(0). */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static volatile LONG stop_flag;
static volatile LONGLONG worker_steps;

static DWORD WINAPI spinner(void *arg)
{
    int mode = (int)(INT_PTR)arg;
    while (!stop_flag) { if (mode == 1) SwitchToThread(); else if (mode == 2) Sleep(0); else YieldProcessor(); }
    return 0;
}
static DWORD WINAPI worker(void *arg) { (void)arg; while (!stop_flag) worker_steps++; return 0; }

static double cpu_ms(HANDLE thread)
{
    FILETIME c, e, k, u; ULARGE_INTEGER a, b;
    if (!GetThreadTimes(thread, &c, &e, &k, &u)) return -1.0;
    a.LowPart = k.dwLowDateTime; a.HighPart = k.dwHighDateTime; b.LowPart = u.dwLowDateTime; b.HighPart = u.dwHighDateTime;
    return (double)(a.QuadPart + b.QuadPart) / 10000.0;
}

static void phase(const char *name, int worker_prio, int spinners, int spin_prio, int mode, int secs)
{
    HANDLE *s = spinners ? calloc(spinners, sizeof(HANDLE)) : NULL, w;
    DWORD t0, wall; int i; double ms;
    stop_flag = 0; worker_steps = 0;
    for (i = 0; i < spinners; i++) { s[i] = CreateThread(NULL, 0, spinner, (void *)(INT_PTR)mode, CREATE_SUSPENDED, NULL); SetThreadPriority(s[i], spin_prio); }
    w = CreateThread(NULL, 0, worker, NULL, CREATE_SUSPENDED, NULL); SetThreadPriority(w, worker_prio);
    for (i = 0; i < spinners; i++) ResumeThread(s[i]);
    Sleep(200);                       /* the waiting threads already occupy the processors */
    t0 = GetTickCount(); ResumeThread(w);
    Sleep(secs * 1000);
    stop_flag = 1; wall = GetTickCount() - t0;
    WaitForSingleObject(w, 5000); ms = cpu_ms(w);
    for (i = 0; i < spinners; i++) { WaitForSingleObject(s[i], 5000); CloseHandle(s[i]); }
    printf("CELL %s worker_prio=%d spinners=%d spin_prio=%d spin_mode=%d wall_ms=%lu worker_cpu_ms=%.0f steps=%lld\n",
           name, worker_prio, spinners, spin_prio, mode, (unsigned long)wall, ms, (long long)worker_steps);
    fflush(stdout); CloseHandle(w); free(s);
}

int main(int argc, char **argv)
{
    SYSTEM_INFO si; int ncpu, n, secs = argc > 1 ? atoi(argv[1]) : 3;
    GetSystemInfo(&si); ncpu = (int)si.dwNumberOfProcessors; n = argc > 2 ? atoi(argv[2]) : ncpu - 1;
    if (n < 1) n = 1;
    printf("IDLEPRIO version=2 cpus=%d secs=%d\n", ncpu, secs);
    (void)n;
    phase("normal_alone", THREAD_PRIORITY_NORMAL, 0, 0, 0, secs);
    phase("idle_alone", THREAD_PRIORITY_IDLE, 0, 0, 0, secs);
    phase("idle_vs_busy_all_but_one", THREAD_PRIORITY_IDLE, ncpu - 1, THREAD_PRIORITY_ABOVE_NORMAL, 0, secs);
    phase("idle_vs_busy_all", THREAD_PRIORITY_IDLE, ncpu, THREAD_PRIORITY_ABOVE_NORMAL, 0, secs);
    phase("idle_vs_switchtothread_all", THREAD_PRIORITY_IDLE, ncpu, THREAD_PRIORITY_ABOVE_NORMAL, 1, secs);
    phase("normal_vs_switchtothread_all", THREAD_PRIORITY_NORMAL, ncpu, THREAD_PRIORITY_ABOVE_NORMAL, 1, secs);
    phase("idle_vs_sleep0_all", THREAD_PRIORITY_IDLE, ncpu, THREAD_PRIORITY_ABOVE_NORMAL, 2, secs);
    phase("lowest_vs_switchtothread_all", THREAD_PRIORITY_LOWEST, ncpu, THREAD_PRIORITY_ABOVE_NORMAL, 1, secs);
    return 0;
}
