/* SPDX-License-Identifier: MIT
 * Windows-only C11 priority/throughput diagnostic. No Wine implementation code.
 * Build x64 with: clang -std=c11 -O1 -Wall -Wextra -Werror priority_probe.c -o priority_probe.exe
 * See DESIGN.md and README_RU.md before running. No REALTIME process class.
 */
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
/* Clang with the Microsoft CRT: all string buffers below have fixed bounds. */
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS 1
#endif
#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wchar.h>

#define VERSION 1
#define MAX_CPUS 64
#define MAX_CHILDREN (MAX_CPUS + 1)
#define BLOCK_STEPS 4096
#define STARTUP_MS 15000
#define CLEANUP_MS 10000
#define HARD_RUN_MS 180000
#define SAMPLE_MS 100
#define SLOT_ALIGN 128

#if !defined(__x86_64__) && !defined(_M_X64)
#error "This probe requires an x86-64 target; ARM64 is not supported."
#endif
_Static_assert(sizeof(void *) == 8, "Build for Windows x64");

typedef struct {
    const char *name;
    DWORD value;
    int bases[7];
} Class;
typedef struct { const char *name; int value; } Level;
static const Class classes[5] = {
    {"IDLE", IDLE_PRIORITY_CLASS, {1,2,3,4,5,6,15}},
    {"BELOW_NORMAL", BELOW_NORMAL_PRIORITY_CLASS, {1,4,5,6,7,8,15}},
    {"NORMAL", NORMAL_PRIORITY_CLASS, {1,6,7,8,9,10,15}},
    {"ABOVE_NORMAL", ABOVE_NORMAL_PRIORITY_CLASS, {1,8,9,10,11,12,15}},
    {"HIGH", HIGH_PRIORITY_CLASS, {1,11,12,13,14,15,15}}
};
static const Level levels[7] = {
    {"IDLE", THREAD_PRIORITY_IDLE}, {"LOWEST", THREAD_PRIORITY_LOWEST},
    {"BELOW_NORMAL", THREAD_PRIORITY_BELOW_NORMAL}, {"NORMAL", THREAD_PRIORITY_NORMAL},
    {"ABOVE_NORMAL", THREAD_PRIORITY_ABOVE_NORMAL}, {"HIGHEST", THREAD_PRIORITY_HIGHEST},
    {"TIME_CRITICAL", THREAD_PRIORITY_TIME_CRITICAL}
};
/* Explicit canonical documented pairs, indexed by base - 1. */
static const int canonical[15][2] = {
    {2,0},{0,1},{0,2},{0,3},{0,4},{1,3},{2,2},{2,3},
    {2,4},{2,5},{3,4},{3,5},{4,3},{4,4},{4,5}
};

typedef struct {
    _Alignas(SLOT_ALIGN) volatile LONG ready;
    volatile LONG error;
    volatile LONG done;
    volatile LONG started;
    volatile LONG64 blocks;
    LONG64 first_work_qpc;
    LONG64 exit_qpc;
    uint64_t checksum;
    uint64_t cpu_begin_100ns;
    uint64_t cpu_end_100ns;
    LONG64 cpu_begin_qpc_before;
    LONG64 cpu_begin_qpc_after;
    LONG64 cpu_end_qpc_before;
    LONG64 cpu_end_qpc_after;
    DWORD final_class;
    int final_level;
    DWORD observed_class;
    int observed_level;
    WORD observed_group;
    DWORD_PTR observed_mask;
} Slot;
_Static_assert(sizeof(Slot) % SLOT_ALIGN == 0, "slots must not share cache lines");
typedef struct {
    LONG64 frequency;
    LONG64 start_qpc;
    LONG64 end_qpc;
    volatile LONG stop;
    Slot slots[MAX_CHILDREN];
} Shared;
typedef struct { PROCESS_INFORMATION pi; int cpu; int ci; int li; } Child;
typedef struct {
    int run;
    double window_seconds;
    double rate;
    LONG64 middle;
    uint64_t blocks;
    uint64_t cpu_100ns;
    int started;
} Result;
typedef struct {
    DWORD_PTR allowed;
    DWORD_PTR system;
    GROUP_AFFINITY original_thread;
    WORD group;
    int cpus[MAX_CPUS];
    int ncpus;
    int worker_cpu;
    int short_ms;
    int busy_ms;
    int warmup_ms;
    int all_pairs;
    int only_base;
    int expected_cpus;
} Config;
static LONG64 frequency;
static int next_run;
static volatile LONG cancel_requested;

static LONG64 qpc(void) { LARGE_INTEGER v; QueryPerformanceCounter(&v); return v.QuadPart; }
/* Windows x64 + Clang: aligned lock-free acquire loads, not shared-cache-line RMWs. */
static LONG64 atomic_read64(volatile LONG64 *v) { return __atomic_load_n(v, __ATOMIC_ACQUIRE); }
static LONG atomic_read(volatile LONG *v) { return __atomic_load_n(v, __ATOMIC_ACQUIRE); }
static LONG64 ticks_ms(int ms) { return (frequency * (LONG64)ms) / 1000; }
static double seconds(LONG64 ticks) { return (double)ticks / (double)frequency; }
static uint64_t ft_value(FILETIME f) { return ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime; }
static int cpu_time(HANDLE t, uint64_t *value)
{
    FILETIME c,e,k,u;
    if (!GetThreadTimes(t, &c,&e,&k,&u)) return 0;
    *value = ft_value(k) + ft_value(u); return 1;
}
static int error_record(const char *stage, DWORD code, int run)
{
    printf("{\"type\":\"error\",\"run\":%d,\"stage\":\"%s\",\"win32_error\":%lu}\n", run, stage, (unsigned long)code);
    fflush(stdout); return 0;
}
static BOOL WINAPI on_console(DWORD event)
{
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&cancel_requested, 1); return TRUE;
    }
    return FALSE;
}
static uint64_t burn(uint64_t x)
{
    for (unsigned i = 0; i < BLOCK_STEPS; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    }
    return x;
}
static int parse_u64(const char *s, uint64_t *v)
{
    char *end; unsigned long long n;
    if (!s[0] || s[0] == '-' || s[0] == '+') return 0;
    errno = 0; n = strtoull(s, &end, 10);
    if (errno || *end) return 0;
    *v = (uint64_t)n; return 1;
}
static int parse_int(const char *s, int lo, int hi, int *v)
{
    uint64_t n;
    if (!parse_u64(s, &n) || n < (uint64_t)lo || n > (uint64_t)hi) return 0;
    *v = (int)n; return 1;
}
static int child_main(int argc, char **argv)
{
    uint64_t mh, eh; int slot_index;
    HANDLE mapping, event; Shared *sh; Slot *s; GROUP_AFFINITY ga;
    uint64_t x = UINT64_C(0x9e3779b97f4a7c15), count = 0;
    LONG64 now, hard_end;
    if (argc != 5 || !parse_u64(argv[2], &mh) || !parse_u64(argv[3], &eh) ||
        !parse_int(argv[4], 0, MAX_CHILDREN - 1, &slot_index)) return 2;
    mapping = (HANDLE)(uintptr_t)mh; event = (HANDLE)(uintptr_t)eh;
    sh = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(*sh));
    if (!sh) return 4;
    s = &sh->slots[slot_index]; frequency = sh->frequency;
    hard_end = qpc() + ticks_ms(HARD_RUN_MS);
    s->observed_class = GetPriorityClass(GetCurrentProcess());
    s->observed_level = GetThreadPriority(GetCurrentThread());
    memset(&ga, 0, sizeof(ga));
    if (!s->observed_class || s->observed_level == THREAD_PRIORITY_ERROR_RETURN ||
        !GetThreadGroupAffinity(GetCurrentThread(), &ga)) {
        InterlockedExchange(&s->error, (LONG)GetLastError()); return 5;
    }
    s->observed_group = ga.Group; s->observed_mask = ga.Mask;
    InterlockedExchange(&s->ready, 1);
    if (WaitForSingleObject(event, STARTUP_MS) != WAIT_OBJECT_0) {
        InterlockedExchange(&s->error, ERROR_TIMEOUT); return 6;
    }
    CloseHandle(event); CloseHandle(mapping);
    if (sh->end_qpc <= sh->start_qpc || sh->end_qpc > hard_end) {
        InterlockedExchange(&s->error, ERROR_INVALID_DATA); return 7;
    }
    /* Warm up the identical loop until the common start. Never reset a counter
     * asynchronously from the observer, and never count warmup work. */
    while (qpc() < sh->start_qpc) {
        if (atomic_read(&sh->stop)) break;
        x = burn(x);
    }
    now = qpc();
    if (!atomic_read(&sh->stop) && now < sh->end_qpc) {
        s->first_work_qpc = now;
        s->cpu_begin_qpc_before = qpc();
        if (!cpu_time(GetCurrentThread(), &s->cpu_begin_100ns)) {
            InterlockedExchange(&s->error, (LONG)GetLastError()); return 8;
        }
        s->cpu_begin_qpc_after = qpc();
        InterlockedExchange(&s->started, 1);
        while (!atomic_read(&sh->stop) && qpc() < sh->end_qpc) {
            x = burn(x);
            now = qpc();
            if (now > sh->end_qpc) break; /* exclude a boundary-crossing block */
            ++count;
            InterlockedExchange64(&s->blocks, (LONG64)count);
        }
        s->cpu_end_qpc_before = qpc();
        if (!cpu_time(GetCurrentThread(), &s->cpu_end_100ns)) {
            InterlockedExchange(&s->error, (LONG)GetLastError()); return 9;
        }
        s->cpu_end_qpc_after = qpc();
    }
    /* A worker first scheduled after end legitimately has zero work/CPU delta. */
    s->checksum = x; s->exit_qpc = qpc();
    s->final_class = GetPriorityClass(GetCurrentProcess());
    s->final_level = GetThreadPriority(GetCurrentThread());
    if (!s->final_class || s->final_level == THREAD_PRIORITY_ERROR_RETURN) {
        InterlockedExchange(&s->error, (LONG)GetLastError()); return 10;
    }
    InterlockedExchange(&s->done, 1);
    UnmapViewOfFile(sh); return 0;
}

static void mapping_records(void)
{
    for (int c = 0; c < 5; ++c) {
        int present[16] = {0};
        for (int l = 0; l < 7; ++l) {
            int b = classes[c].bases[l]; present[b] = 1;
            printf("{\"type\":\"mapping\",\"class\":\"%s\",\"class_value\":%lu,\"level\":\"%s\",\"level_value\":%d,\"nominal_base\":%d,\"canonical\":%s}\n",
                classes[c].name, (unsigned long)classes[c].value, levels[l].name,
                levels[l].value, b, canonical[b-1][0] == c && canonical[b-1][1] == l ? "true" : "false");
        }
        printf("{\"type\":\"class_gaps\",\"class\":\"%s\",\"unreachable_bases\":[", classes[c].name);
        int comma = 0;
        for (int b = 1; b <= 15; ++b) if (!present[b]) { printf("%s%d", comma ? "," : "", b); comma = 1; }
        printf("]}\n");
    }
    printf("{\"type\":\"union_gaps\",\"unreachable_bases\":[],\"dynamic_priority_measured\":false}\n");
}
static int no_cpu_sets(HANDLE process, HANDLE thread, int run)
{
    ULONG n = 0; BOOL ok;
    ok = GetProcessDefaultCpuSets(process, NULL, 0, &n);
    if (!ok || n) return error_record(n ? "unsupported_process_cpu_sets" : "GetProcessDefaultCpuSets", n ? ERROR_NOT_SUPPORTED : GetLastError(), run);
    n = 0; ok = GetThreadSelectedCpuSets(thread, NULL, 0, &n);
    if (!ok || n) return error_record(n ? "unsupported_thread_cpu_sets" : "GetThreadSelectedCpuSets", n ? ERROR_NOT_SUPPORTED : GetLastError(), run);
    return 1;
}
static int setup_config(Config *cfg)
{
    USHORT groups[64], n = 64; DWORD_PTR original_allowed;
    if (!SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS) ||
        !SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL))
        return error_record("controller_priority", GetLastError(), 0);
    if (GetPriorityClass(GetCurrentProcess()) != NORMAL_PRIORITY_CLASS ||
        GetThreadPriority(GetCurrentThread()) != THREAD_PRIORITY_NORMAL)
        return error_record("controller_priority_readback", ERROR_INVALID_DATA, 0);
    if (!GetProcessAffinityMask(GetCurrentProcess(), &cfg->allowed, &cfg->system) ||
        !GetThreadGroupAffinity(GetCurrentThread(), &cfg->original_thread) ||
        !GetProcessGroupAffinity(GetCurrentProcess(), &n, groups))
        return error_record("detect_affinity", GetLastError(), 0);
    if (n != 1 || GetActiveProcessorGroupCount() != 1)
        return error_record("unsupported_multigroup_topology", ERROR_NOT_SUPPORTED, 0);
    cfg->group = groups[0];
    if (cfg->original_thread.Group != cfg->group)
        return error_record("inconsistent_thread_group", ERROR_INVALID_DATA, 0);
    if (!no_cpu_sets(GetCurrentProcess(), GetCurrentThread(), 0)) return 0;
    original_allowed = cfg->allowed;
    /* Respect a thread mask inherited from the launcher as well as process mask. */
    cfg->allowed &= cfg->original_thread.Mask;
    cfg->ncpus = 0;
    for (int i = 0; i < MAX_CPUS; ++i)
        if (cfg->allowed & ((DWORD_PTR)1 << i)) cfg->cpus[cfg->ncpus++] = i;
    if (cfg->ncpus != cfg->expected_cpus)
        return error_record("allowed_cpu_count_differs_from_expected", ERROR_NOT_SUPPORTED, 0);
    if (cfg->worker_cpu < 0) cfg->worker_cpu = cfg->cpus[0];
    if (!(cfg->allowed & ((DWORD_PTR)1 << cfg->worker_cpu)))
        return error_record("worker_cpu_not_allowed", ERROR_INVALID_PARAMETER, 0);
    DWORD_PTR observer = cfg->allowed & ~((DWORD_PTR)1 << cfg->worker_cpu);
    if (!SetThreadAffinityMask(GetCurrentThread(), observer))
        return error_record("controller_affinity", GetLastError(), 0);
    BOOL in_job = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), NULL, &in_job)) return error_record("IsProcessInJob", GetLastError(), 0);
    BOOL process_boost_disabled, thread_boost_disabled;
    if (!GetProcessPriorityBoost(GetCurrentProcess(), &process_boost_disabled) ||
        !GetThreadPriorityBoost(GetCurrentThread(), &thread_boost_disabled))
        return error_record("query_controller_boosts", GetLastError(), 0);
    printf("{\"type\":\"boost_state\",\"role\":\"controller\",\"process_boost_disabled\":%s,\"thread_boost_disabled\":%s}\n",
        process_boost_disabled ? "true":"false", thread_boost_disabled ? "true":"false");
    printf("{\"type\":\"metadata\",\"schema\":%d,\"probe\":\"windows_priority_throughput\",\"architecture\":\"x64\",\"qpc_frequency\":%lld,\"processor_group\":%u,\"active_groups\":%u,\"system_active_logical_cpus\":%lu,\"system_mask\":\"0x%llx\",\"original_process_mask\":\"0x%llx\",\"original_thread_mask\":\"0x%llx\",\"allowed_mask\":\"0x%llx\",\"observer_mask\":\"0x%llx\",\"worker_cpu\":%d,\"allowed_cpu_count\":%d,\"controller_in_existing_job\":%s,\"short_ms\":%d,\"busy_ms\":%d,\"warmup_ms\":%d,\"sample_ms\":%d,\"block_steps\":%d,\"all_pairs\":%s,\"only_base\":%d,\"priority_boosts\":\"unchanged\",\"dynamic_priority_measured\":false,\"cpu_sets\":\"none_selected\"}\n",
        VERSION, (long long)frequency, cfg->group, GetActiveProcessorGroupCount(),
        (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS),
        (unsigned long long)cfg->system, (unsigned long long)original_allowed,
        (unsigned long long)cfg->original_thread.Mask, (unsigned long long)cfg->allowed,
        (unsigned long long)observer, cfg->worker_cpu, cfg->ncpus, in_job ? "true" : "false",
        cfg->short_ms,cfg->busy_ms,cfg->warmup_ms,SAMPLE_MS,BLOCK_STEPS,
        cfg->all_pairs ? "true" : "false", cfg->only_base);
    return 1;
}

static int spawn_child(Child *ch, Shared *sh, HANDLE mapping, HANDLE event, HANDLE job,
                       int index, int cpu, int ci, int li, WORD group, int run)
{
    WCHAR exe[32768], command[512];
    STARTUPINFOEXW sx; SIZE_T bytes = 0; HANDLE inherit[2] = {mapping, event};
    GROUP_AFFINITY affinity; BOOL created;
    memset(ch, 0, sizeof(*ch)); memset(&sx, 0, sizeof(sx)); memset(&affinity, 0, sizeof(affinity));
    ch->cpu = cpu; ch->ci = ci; ch->li = li;
    DWORD n = GetModuleFileNameW(NULL, exe, 32768);
    if (!n || n >= 32768) return error_record("GetModuleFileNameW", GetLastError(), run);
    swprintf(command, sizeof(command)/sizeof(command[0]), L"priority_probe.exe --child %llu %llu %d",
        (unsigned long long)(uintptr_t)mapping, (unsigned long long)(uintptr_t)event, index);
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    sx.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!sx.lpAttributeList) return error_record("allocate_attribute_list", ERROR_NOT_ENOUGH_MEMORY, run);
    if (!InitializeProcThreadAttributeList(sx.lpAttributeList, 1, 0, &bytes)) {
        DWORD e = GetLastError(); HeapFree(GetProcessHeap(),0,sx.lpAttributeList); return error_record("InitializeProcThreadAttributeList",e,run);
    }
    if (!UpdateProcThreadAttribute(sx.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherit, sizeof(inherit), NULL, NULL)) {
        DWORD e = GetLastError(); DeleteProcThreadAttributeList(sx.lpAttributeList); HeapFree(GetProcessHeap(),0,sx.lpAttributeList);
        return error_record("UpdateProcThreadAttribute",e,run);
    }
    sx.StartupInfo.cb = sizeof(sx);
    created = CreateProcessW(exe, command, NULL, NULL, TRUE,
        CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, &sx.StartupInfo, &ch->pi);
    DWORD create_error = created ? 0 : GetLastError();
    DeleteProcThreadAttributeList(sx.lpAttributeList); HeapFree(GetProcessHeap(), 0, sx.lpAttributeList);
    if (!created) return error_record("CreateProcessW", create_error, run);
    printf("{\"type\":\"child_created\",\"run\":%d,\"index\":%d,\"pid\":%lu,\"tid\":%lu}\n",
        run,index,(unsigned long)ch->pi.dwProcessId,(unsigned long)ch->pi.dwThreadId);
    if (!AssignProcessToJobObject(job, ch->pi.hProcess)) {
        DWORD e = GetLastError();
        BOOL killed = TerminateProcess(ch->pi.hProcess, 10);
        DWORD kill_error = killed ? 0 : GetLastError();
        DWORD wr = WaitForSingleObject(ch->pi.hProcess,CLEANUP_MS);
        printf("{\"type\":\"unassigned_child_cleanup\",\"run\":%d,\"pid\":%lu,\"terminate_succeeded\":%s,\"terminate_error\":%lu,\"wait_result\":%lu,\"reaped\":%s}\n",
            run,(unsigned long)ch->pi.dwProcessId,killed ? "true":"false",(unsigned long)kill_error,
            (unsigned long)wr,wr == WAIT_OBJECT_0 ? "true":"false");
        return error_record("AssignProcessToJobObject",e,run);
    }
    /* Controller process affinity is never narrowed. Explicit thread group mask. */
    affinity.Group = group; affinity.Mask = (KAFFINITY)1 << cpu;
    if (!SetThreadGroupAffinity(ch->pi.hThread, &affinity, NULL) ||
        !SetPriorityClass(ch->pi.hProcess, classes[ci].value) ||
        !SetThreadPriority(ch->pi.hThread, levels[li].value))
        return error_record("configure_owned_child",GetLastError(),run);
    if (!no_cpu_sets(ch->pi.hProcess,ch->pi.hThread,run)) return 0;
    DWORD pc = GetPriorityClass(ch->pi.hProcess); int tp = GetThreadPriority(ch->pi.hThread);
    GROUP_AFFINITY actual;
    if (!GetThreadGroupAffinity(ch->pi.hThread,&actual)) return error_record("child_affinity_readback",GetLastError(),run);
    if (pc != classes[ci].value || tp != levels[li].value || actual.Group != group || actual.Mask != affinity.Mask)
        return error_record("child_configuration_mismatch",ERROR_INVALID_DATA,run);
    printf("{\"type\":\"child_config\",\"run\":%d,\"index\":%d,\"role\":\"%s\",\"pid\":%lu,\"tid\":%lu,\"class\":\"%s\",\"class_readback\":%lu,\"level\":\"%s\",\"level_readback\":%d,\"nominal_base\":%d,\"group\":%u,\"cpu\":%d,\"mask\":\"0x%llx\"}\n",
        run,index,index ? "competitor" : "worker",(unsigned long)ch->pi.dwProcessId,(unsigned long)ch->pi.dwThreadId,
        classes[ci].name,(unsigned long)pc,levels[li].name,tp,classes[ci].bases[li],group,cpu,(unsigned long long)actual.Mask);
    BOOL process_boost_disabled, thread_boost_disabled;
    if (!GetProcessPriorityBoost(ch->pi.hProcess, &process_boost_disabled) ||
        !GetThreadPriorityBoost(ch->pi.hThread, &thread_boost_disabled))
        return error_record("query_child_boosts", GetLastError(), run);
    printf("{\"type\":\"boost_state\",\"run\":%d,\"index\":%d,\"process_boost_disabled\":%s,\"thread_boost_disabled\":%s}\n",
        run,index,process_boost_disabled ? "true":"false", thread_boost_disabled ? "true":"false");
    (void)sh;
    if (ResumeThread(ch->pi.hThread) == (DWORD)-1) return error_record("ResumeThread",GetLastError(),run);
    return 1;
}

static int execute_condition(const Config *cfg, int ci, int li, int condition, const char *role, Result *result)
{
    int run = ++next_run, count = 1, okay = 0, terminated = 0;
    int duration_ms = condition == 2 ? cfg->busy_ms : cfg->short_ms;
    const char *condition_name = condition == 0 ? "alone" : condition == 1 ? "one_free" : "all_busy";
    SECURITY_ATTRIBUTES sa = {sizeof(sa),NULL,TRUE};
    HANDLE mapping = NULL, event = NULL, job = NULL; Shared *sh = NULL;
    Child children[MAX_CHILDREN]; memset(children,0,sizeof(children));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits; memset(&limits,0,sizeof(limits));
    memset(result,0,sizeof(*result)); result->run = run;
    job = CreateJobObjectW(NULL,NULL); /* deliberately NOT inheritable */
    if (!job) { error_record("CreateJobObjectW",GetLastError(),run); goto cleanup; }
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) {
        error_record("SetInformationJobObject",GetLastError(),run); goto cleanup;
    }
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE,&sa,PAGE_READWRITE,0,sizeof(Shared),NULL);
    event = CreateEventW(&sa,TRUE,FALSE,NULL);
    if (!mapping || !event) { error_record("create_shared_objects",GetLastError(),run); goto cleanup; }
    sh = MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(Shared));
    if (!sh) { error_record("MapViewOfFile",GetLastError(),run); goto cleanup; }
    memset(sh,0,sizeof(*sh)); sh->frequency = frequency;
    if (!spawn_child(&children[0],sh,mapping,event,job,0,cfg->worker_cpu,ci,li,cfg->group,run)) goto cleanup;
    if (condition) for (int i = 0; i < cfg->ncpus; ++i) {
        int cpu = cfg->cpus[i];
        if (condition == 1 && cpu == cfg->worker_cpu) continue;
        int index = count++;
        if (!spawn_child(&children[index],sh,mapping,event,job,index,cpu,2,3,cfg->group,run)) goto cleanup;
    }
    LONG64 startup_end = qpc() + ticks_ms(STARTUP_MS);
    for (;;) {
        int ready = 1;
        for (int i = 0; i < count; ++i) {
            if (atomic_read(&sh->slots[i].error)) { error_record("child_setup_error",(DWORD)atomic_read(&sh->slots[i].error),run); goto cleanup; }
            if (!atomic_read(&sh->slots[i].ready)) ready = 0;
            if (WaitForSingleObject(children[i].pi.hProcess,0) == WAIT_OBJECT_0) { error_record("child_exited_before_start",ERROR_PROCESS_ABORTED,run); goto cleanup; }
        }
        if (ready) break;
        if (qpc() > startup_end || atomic_read(&cancel_requested)) { error_record("startup_timeout_or_cancel",ERROR_TIMEOUT,run); goto cleanup; }
        Sleep(1);
    }
    for (int i = 0; i < count; ++i) {
        Slot *s = &sh->slots[i]; Child *ch = &children[i];
        if (s->observed_class != classes[ch->ci].value || s->observed_level != levels[ch->li].value ||
            s->observed_group != cfg->group || s->observed_mask != ((DWORD_PTR)1 << ch->cpu)) {
            error_record("child_self_readback_mismatch",ERROR_INVALID_DATA,run); goto cleanup;
        }
    }
    LONG64 release = qpc();
    sh->start_qpc = release + ticks_ms(cfg->warmup_ms);
    sh->end_qpc = sh->start_qpc + ticks_ms(duration_ms);
    MemoryBarrier();
    if (!SetEvent(event)) { error_record("SetEvent",GetLastError(),run); goto cleanup; }
    printf("{\"type\":\"run_start\",\"run\":%d,\"role\":\"%s\",\"condition\":\"%s\",\"class\":\"%s\",\"level\":\"%s\",\"nominal_base\":%d,\"competitors\":%d,\"release_qpc\":%lld,\"start_qpc\":%lld,\"end_qpc\":%lld,\"duration_ms\":%d}\n",
        run,role,condition_name,classes[ci].name,levels[li].name,classes[ci].bases[li],count-1,
        (long long)release,(long long)sh->start_qpc,(long long)sh->end_qpc,duration_ms);
    /* Capture actual samples, never fabricate the skipped nominal slots. */
    LONG64 sample_period = ticks_ms(SAMPLE_MS), due = sh->start_qpc;
    LONG64 previous_at = 0, previous_blocks = 0;
    uint64_t previous_cpu = 0; int sample_index = 0;
    for (;;) {
        LONG64 now = qpc();
        if (atomic_read(&cancel_requested)) { error_record("cancel_requested",ERROR_CANCELLED,run); goto cleanup; }
        if (now < due) {
            DWORD sleep_ms = (DWORD)((due-now)*1000/frequency);
            Sleep(sleep_ms > 0 ? sleep_ms : 1); continue;
        }
        LONG64 before = qpc(); uint64_t cpu;
        LONG64 blocks = atomic_read64(&sh->slots[0].blocks);
        if (!cpu_time(children[0].pi.hThread,&cpu)) { error_record("GetThreadTimes_sample",GetLastError(),run); goto cleanup; }
        LONG64 after = qpc();
        LONG64 late = before - due;
        int skipped = late > 0 ? (int)(late/sample_period) : 0;
        printf("{\"type\":\"sample\",\"run\":%d,\"sample\":%d,\"due_qpc\":%lld,\"read_before_qpc\":%lld,\"read_after_qpc\":%lld,\"lateness_ms\":%.6f,\"skipped_slots\":%d,\"blocks\":%lld,\"delta_blocks\":%lld,\"interval_seconds\":%.9f,\"cpu_total_100ns\":%llu,\"delta_cpu_100ns\":%llu,\"initial\":%s}\n",
            run,sample_index,(long long)due,(long long)before,(long long)after,seconds(late)*1000,skipped,
            (long long)blocks,(long long)(blocks-previous_blocks),sample_index ? seconds(before-previous_at) : 0.0,
            (unsigned long long)cpu,(unsigned long long)(sample_index ? cpu-previous_cpu : 0), sample_index ? "false":"true");
        previous_at = before; previous_blocks = blocks; previous_cpu = cpu; ++sample_index;
        if (before >= sh->end_qpc) break;
        due += (LONG64)(skipped+1) * sample_period;
        if (due > sh->end_qpc) due = sh->end_qpc;
    }
    /* One global cleanup deadline, not a separate timeout for each helper. */
    LONG64 join_end = qpc() + ticks_ms(CLEANUP_MS);
    for (int i = 0; i < count; ++i) {
        LONG64 remaining = join_end - qpc();
        DWORD ms = remaining > 0 ? (DWORD)((remaining*1000)/frequency) : 0;
        if (WaitForSingleObject(children[i].pi.hProcess,ms) != WAIT_OBJECT_0) {
            error_record("owned_child_deadline",ERROR_TIMEOUT,run); goto cleanup;
        }
        DWORD code;
        if (!GetExitCodeProcess(children[i].pi.hProcess,&code)) { error_record("GetExitCodeProcess",GetLastError(),run); goto cleanup; }
        Slot *s = &sh->slots[i];
        if (code || !atomic_read(&s->done) || atomic_read(&s->error)) {
            error_record("child_failed",code ? code : (DWORD)atomic_read(&s->error),run); goto cleanup;
        }
        DWORD pc = s->final_class;
        int tp = s->final_level;
        if (pc != classes[children[i].ci].value || tp != levels[children[i].li].value) {
            error_record("final_priority_readback_mismatch",ERROR_INVALID_DATA,run); goto cleanup;
        }
        uint64_t cpu_delta = s->cpu_end_100ns - s->cpu_begin_100ns;
        char cpu_json[32];
        if (atomic_read(&s->started)) snprintf(cpu_json,sizeof(cpu_json),"%llu",(unsigned long long)cpu_delta);
        else strcpy(cpu_json,"null");
        printf("{\"type\":\"child_result\",\"run\":%d,\"index\":%d,\"role\":\"%s\",\"pid\":%lu,\"cpu\":%d,\"configured_class\":%lu,\"configured_level\":%d,\"final_class\":%lu,\"final_level\":%d,\"started\":%s,\"blocks\":%lld,\"checksum\":\"0x%016llx\",\"first_work_qpc\":%lld,\"exit_qpc\":%lld,\"cpu_delta_100ns\":%s,\"cpu_begin_total_100ns\":%llu,\"cpu_end_total_100ns\":%llu,\"cpu_begin_before_qpc\":%lld,\"cpu_begin_after_qpc\":%lld,\"cpu_end_before_qpc\":%lld,\"cpu_end_after_qpc\":%lld,\"exit_code\":%lu}\n",
            run,i,i ? "competitor":"worker",(unsigned long)children[i].pi.dwProcessId,children[i].cpu,
            (unsigned long)classes[children[i].ci].value,levels[children[i].li].value,(unsigned long)pc,tp,
            atomic_read(&s->started) ? "true":"false",(long long)atomic_read64(&s->blocks),
            (unsigned long long)s->checksum,(long long)s->first_work_qpc,(long long)s->exit_qpc,
            cpu_json,(unsigned long long)s->cpu_begin_100ns,(unsigned long long)s->cpu_end_100ns,(long long)s->cpu_begin_qpc_before,(long long)s->cpu_begin_qpc_after,
            (long long)s->cpu_end_qpc_before,(long long)s->cpu_end_qpc_after,(unsigned long)code);
    }
    result->window_seconds = seconds(sh->end_qpc-sh->start_qpc);
    result->blocks = (uint64_t)atomic_read64(&sh->slots[0].blocks);
    result->rate = (double)result->blocks / result->window_seconds;
    result->middle = sh->start_qpc + (sh->end_qpc-sh->start_qpc)/2;
    result->cpu_100ns = sh->slots[0].cpu_end_100ns - sh->slots[0].cpu_begin_100ns;
    result->started = (int)atomic_read(&sh->slots[0].started);
    char cpu_json[32], utilization_json[48];
    if (result->started) {
        snprintf(cpu_json,sizeof(cpu_json),"%llu",(unsigned long long)result->cpu_100ns);
        snprintf(utilization_json,sizeof(utilization_json),"%.9f",100.0*(double)result->cpu_100ns/1e7/result->window_seconds);
    } else { strcpy(cpu_json,"null"); strcpy(utilization_json,"null"); }
    printf("{\"type\":\"run_result\",\"run\":%d,\"condition\":\"%s\",\"window_seconds\":%.9f,\"window_midpoint_qpc\":%lld,\"blocks\":%llu,\"blocks_per_second\":%.9f,\"cpu_delta_100ns\":%s,\"cpu_window_utilization_percent\":%s,\"cpu_time_scope\":\"approximate_marker_interval\",\"sample_count\":%d,\"valid\":true}\n",
        run,condition_name,result->window_seconds,(long long)result->middle,(unsigned long long)result->blocks,result->rate,
        cpu_json,utilization_json,sample_index);
    okay = 1;
cleanup:
    if (!okay && sh) InterlockedExchange(&sh->stop,1);
    if (!okay && job) {
        terminated = 1;
        if (!TerminateJobObject(job,11)) error_record("TerminateJobObject",GetLastError(),run);
    }
    if (job) { CloseHandle(job); job = NULL; }
    int reaped = 1;
    LONG64 cleanup_end = qpc() + ticks_ms(CLEANUP_MS);
    for (int i = 0; i < count; ++i) {
        if (children[i].pi.hProcess) {
            LONG64 remaining = cleanup_end-qpc();
            DWORD remaining_ms = remaining > 0 ? (DWORD)(remaining*1000/frequency) : 0;
            if (WaitForSingleObject(children[i].pi.hProcess,remaining_ms) != WAIT_OBJECT_0) reaped = 0;
            CloseHandle(children[i].pi.hProcess);
        }
        if (children[i].pi.hThread) CloseHandle(children[i].pi.hThread);
    }
    if (sh) UnmapViewOfFile(sh);
    if (mapping) CloseHandle(mapping);
    if (event) CloseHandle(event);
    printf("{\"type\":\"cleanup\",\"run\":%d,\"owned_children_reaped\":%s,\"job_terminated\":%s,\"valid\":%s}\n",
        run,reaped ? "true":"false",terminated ? "true":"false",okay && reaped ? "true":"false");
    if (fflush(stdout) != 0 || ferror(stdout)) okay = 0;
    return okay && reaped;
}
/* Each condition gets a fresh controller. The outer supervisor retains the
 * non-inherited kill-on-close job handle for that controller and descendants. */
typedef struct {
    Config cfg;
    int ci, li, condition, run;
    char role[24];
    LONG64 frequency;
    Result result;
    volatile LONG success;
} ConditionControl;

static int condition_child_main(int argc, char **argv)
{
    uint64_t handle_value;
    if (argc != 3 || !parse_u64(argv[2], &handle_value)) return 2;
    HANDLE mapping = (HANDLE)(uintptr_t)handle_value;
    ConditionControl *control = MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(*control));
    if (!control) return 3;
    frequency = control->frequency; next_run = control->run-1;
    setvbuf(stdout,NULL,_IOFBF,1024*1024);
    GROUP_AFFINITY ga; memset(&ga,0,sizeof(ga));
    ga.Group = control->cfg.group;
    ga.Mask = control->cfg.allowed & ~((DWORD_PTR)1 << control->cfg.worker_cpu);
    if (!SetPriorityClass(GetCurrentProcess(),NORMAL_PRIORITY_CLASS) ||
        !SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_NORMAL) ||
        !SetThreadGroupAffinity(GetCurrentThread(),&ga,NULL) ||
        !SetConsoleCtrlHandler(on_console,TRUE)) {
        error_record("condition_controller_setup",GetLastError(),control->run); return 4;
    }
    if (GetPriorityClass(GetCurrentProcess()) != NORMAL_PRIORITY_CLASS ||
        GetThreadPriority(GetCurrentThread()) != THREAD_PRIORITY_NORMAL) {
        error_record("condition_controller_readback",ERROR_INVALID_DATA,control->run); return 4;
    }
    if (!no_cpu_sets(GetCurrentProcess(),GetCurrentThread(),control->run)) return 4;
    printf("{\"type\":\"condition_controller\",\"run\":%d,\"pid\":%lu,\"class_readback\":%lu,\"level_readback\":%d,\"observer_mask\":\"0x%llx\"}\n",
        control->run,(unsigned long)GetCurrentProcessId(),(unsigned long)GetPriorityClass(GetCurrentProcess()),
        GetThreadPriority(GetCurrentThread()),(unsigned long long)ga.Mask);
    int ok = execute_condition(&control->cfg,control->ci,control->li,control->condition,control->role,&control->result);
    if (fflush(stdout) != 0 || ferror(stdout)) ok = 0;
    InterlockedExchange(&control->success,ok ? 1 : 0);
    UnmapViewOfFile(control); CloseHandle(mapping); return ok ? 0 : 5;
}
static int drain_pipe(HANDLE pipe)
{
    char buffer[8192]; DWORD available, read;
    for (;;) {
        if (!PeekNamedPipe(pipe,NULL,0,NULL,&available,NULL)) return GetLastError() == ERROR_BROKEN_PIPE;
        if (!available) return 1;
        DWORD requested = available < sizeof(buffer) ? available : (DWORD)sizeof(buffer);
        if (!ReadFile(pipe,buffer,requested,&read,NULL)) return GetLastError() == ERROR_BROKEN_PIPE;
        if (!read) return 1;
        if (fwrite(buffer,1,read,stdout) != read) return 0;
    }
}
static int run_condition(const Config *cfg, int ci, int li, int condition, const char *role, Result *result)
{
    int run = ++next_run, ok = 0, assigned = 0, reaped = 0;
    HANDLE job = NULL, mapping = NULL, read_pipe = NULL, write_pipe = NULL;
    ConditionControl *control = NULL;
    PROCESS_INFORMATION pi; memset(&pi,0,sizeof(pi));
    STARTUPINFOEXW sx; memset(&sx,0,sizeof(sx));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits; memset(&limits,0,sizeof(limits));
    SECURITY_ATTRIBUTES sa = {sizeof(sa),NULL,TRUE};
    WCHAR exe[32768], command[256]; SIZE_T bytes = 0;
    job = CreateJobObjectW(NULL,NULL);
    if (!job) { error_record("outer_CreateJobObject",GetLastError(),run); goto finish; }
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) {
        error_record("outer_SetInformationJobObject",GetLastError(),run); goto finish;
    }
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE,&sa,PAGE_READWRITE,0,sizeof(*control),NULL);
    if (!mapping || !CreatePipe(&read_pipe,&write_pipe,&sa,0) || !SetHandleInformation(read_pipe,HANDLE_FLAG_INHERIT,0)) {
        error_record("outer_shared_objects",GetLastError(),run); goto finish;
    }
    control = MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(*control));
    if (!control) { error_record("outer_MapViewOfFile",GetLastError(),run); goto finish; }
    memset(control,0,sizeof(*control)); control->cfg = *cfg;
    control->ci = ci; control->li = li; control->condition = condition; control->run = run;
    control->frequency = frequency; snprintf(control->role,sizeof(control->role),"%s",role);
    DWORD n = GetModuleFileNameW(NULL,exe,32768);
    if (!n || n >= 32768) { error_record("outer_GetModuleFileName",GetLastError(),run); goto finish; }
    swprintf(command,sizeof(command)/sizeof(command[0]),L"priority_probe.exe --condition %llu",(unsigned long long)(uintptr_t)mapping);
    InitializeProcThreadAttributeList(NULL,1,0,&bytes);
    sx.lpAttributeList = HeapAlloc(GetProcessHeap(),0,bytes);
    if (!sx.lpAttributeList) { error_record("outer_attribute_alloc",ERROR_NOT_ENOUGH_MEMORY,run); goto finish; }
    if (!InitializeProcThreadAttributeList(sx.lpAttributeList,1,0,&bytes)) {
        HeapFree(GetProcessHeap(),0,sx.lpAttributeList); sx.lpAttributeList = NULL;
        error_record("outer_InitializeAttributes",GetLastError(),run); goto finish;
    }
    HANDLE inherit[2] = {mapping,write_pipe};
    if (!UpdateProcThreadAttribute(sx.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherit,sizeof(inherit),NULL,NULL)) {
        error_record("outer_UpdateAttributes",GetLastError(),run); goto finish;
    }
    sx.StartupInfo.cb = sizeof(sx); sx.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    sx.StartupInfo.hStdOutput = write_pipe; sx.StartupInfo.hStdError = write_pipe; sx.StartupInfo.hStdInput = NULL;
    if (!CreateProcessW(exe,command,NULL,NULL,TRUE,CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS | EXTENDED_STARTUPINFO_PRESENT,
            NULL,NULL,&sx.StartupInfo,&pi)) {
        error_record("outer_CreateProcess",GetLastError(),run); goto finish;
    }
    printf("{\"type\":\"condition_created\",\"run\":%d,\"pid\":%lu,\"supervisor_pid\":%lu}\n",
        run,(unsigned long)pi.dwProcessId,(unsigned long)GetCurrentProcessId());
    fflush(stdout);
    if (!AssignProcessToJobObject(job,pi.hProcess)) { error_record("outer_AssignProcessToJobObject",GetLastError(),run); goto finish; }
    assigned = 1;
    GROUP_AFFINITY ga; memset(&ga,0,sizeof(ga)); ga.Group = cfg->group; ga.Mask = cfg->allowed;
    if (!SetThreadGroupAffinity(pi.hThread,&ga,NULL) || ResumeThread(pi.hThread) == (DWORD)-1) {
        error_record("outer_resume_controller",GetLastError(),run); goto finish;
    }
    CloseHandle(write_pipe); write_pipe = NULL;
    int duration = condition == 2 ? cfg->busy_ms : cfg->short_ms;
    LONG64 deadline = qpc() + ticks_ms(STARTUP_MS + cfg->warmup_ms + duration + 2*CLEANUP_MS + 5000);
    for (;;) {
        if (!drain_pipe(read_pipe)) { error_record("outer_read_output",GetLastError(),run); goto finish; }
        DWORD wr = WaitForSingleObject(pi.hProcess,50);
        if (wr == WAIT_OBJECT_0) { reaped = 1; break; }
        if (wr != WAIT_TIMEOUT || qpc() >= deadline || atomic_read(&cancel_requested)) {
            error_record("outer_condition_timeout_or_cancel",ERROR_TIMEOUT,run); goto finish;
        }
    }
    if (!drain_pipe(read_pipe)) { error_record("outer_final_read_output",GetLastError(),run); goto finish; }
    DWORD code;
    if (!GetExitCodeProcess(pi.hProcess,&code) || code || atomic_read(&control->success) != 1) {
        error_record("condition_controller_failed",ERROR_PROCESS_ABORTED,run); goto finish;
    }
    *result = control->result; ok = 1;
finish:
    if (sx.lpAttributeList) { DeleteProcThreadAttributeList(sx.lpAttributeList); HeapFree(GetProcessHeap(),0,sx.lpAttributeList); }
    if (write_pipe) { CloseHandle(write_pipe); write_pipe = NULL; }
    if (!ok && pi.hProcess) {
        BOOL killed = assigned ? TerminateJobObject(job,12) : TerminateProcess(pi.hProcess,12);
        printf("{\"type\":\"outer_termination\",\"run\":%d,\"pid\":%lu,\"assigned\":%s,\"termination_succeeded\":%s,\"win32_error\":%lu}\n",
            run,(unsigned long)pi.dwProcessId,assigned ? "true":"false",killed ? "true":"false",(unsigned long)(killed ? 0:GetLastError()));
    }
    LONG64 cleanup_deadline = qpc() + ticks_ms(CLEANUP_MS);
    if (pi.hProcess && !reaped) reaped = WaitForSingleObject(pi.hProcess,CLEANUP_MS) == WAIT_OBJECT_0;
    DWORD active = 0;
    if (job && assigned) {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        for (;;) {
            if (!QueryInformationJobObject(job,JobObjectBasicAccountingInformation,&accounting,sizeof(accounting),NULL)) {
                error_record("outer_QueryInformationJobObject",GetLastError(),run); ok = 0; active = 1; break;
            }
            active = accounting.ActiveProcesses;
            if (!active || qpc() >= cleanup_deadline) break;
            Sleep(10);
        }
        if (active) { error_record("outer_owned_descendants_unresolved",ERROR_TIMEOUT,run); ok = 0; }
    }
    if (read_pipe) { if (!drain_pipe(read_pipe)) ok = 0; CloseHandle(read_pipe); }
    if (job) CloseHandle(job);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (control) UnmapViewOfFile(control);
    if (mapping) CloseHandle(mapping);
    printf("{\"type\":\"outer_cleanup\",\"run\":%d,\"controller_reaped\":%s,\"active_owned_processes\":%lu,\"valid\":%s}\n",
        run,reaped ? "true":"false",(unsigned long)active,ok && reaped && !active ? "true":"false");
    if (fflush(stdout) != 0 || ferror(stdout)) ok = 0;
    return ok && reaped && !active;
}

static int run_pair(const Config *cfg, int ci, int li)
{
    Result before, after, r[3];
    if (!run_condition(cfg,2,3,0,"baseline_before",&before)) return 0;
    for (int condition = 0; condition < 3; ++condition)
        if (!run_condition(cfg,ci,li,condition,"measurement",&r[condition])) return 0;
    if (!run_condition(cfg,2,3,0,"baseline_after",&after)) return 0;
    if (before.rate <= 0 || after.rate <= 0 || after.middle <= before.middle)
        return error_record("invalid_normal_baseline",ERROR_INVALID_DATA,0);
    for (int condition = 0; condition < 3; ++condition) {
        double alpha = (double)(r[condition].middle-before.middle)/(double)(after.middle-before.middle);
        double reference = before.rate + alpha*(after.rate-before.rate);
        printf("{\"type\":\"comparison\",\"run\":%d,\"nominal_base\":%d,\"class\":\"%s\",\"level\":\"%s\",\"condition\":\"%s\",\"baseline_before_run\":%d,\"baseline_after_run\":%d,\"baseline_before_rate\":%.9f,\"baseline_after_rate\":%.9f,\"interpolation_alpha\":%.9f,\"reference_blocks_per_second\":%.9f,\"throughput_percent_of_normal_alone\":%.9f,\"baseline_drift_percent\":%.9f,\"literal_cpu_share\":false}\n",
            r[condition].run,classes[ci].bases[li],classes[ci].name,levels[li].name,
            condition == 0 ? "alone" : condition == 1 ? "one_free":"all_busy",before.run,after.run,
            before.rate,after.rate,alpha,reference,100.0*r[condition].rate/reference,100.0*(after.rate/before.rate-1));
    }
    return 1;
}
static void usage(void)
{
    fputs("priority_probe.exe [--base 1..15] [--all-pairs] [--short-ms 1000..30000] [--busy-ms 1000..120000] [--warmup-ms 100..5000] [--worker-cpu 0..63] [--expected-cpus 2..8]\nDefault: bases 1..15, 3000/3000/20000 ms, warmup 500 ms, samples 100 ms. Output is JSONL. Requires exactly 4 allowed logical CPUs by default, one system group. Explicit --expected-cpus permits 2..8.\n",stderr);
}
int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1],"--child") == 0) return child_main(argc,argv);
    if (argc > 1 && strcmp(argv[1],"--condition") == 0) return condition_child_main(argc,argv);
    Config cfg; memset(&cfg,0,sizeof(cfg));
    cfg.expected_cpus = 4; cfg.worker_cpu = -1; cfg.short_ms = 3000; cfg.busy_ms = 20000; cfg.warmup_ms = 500;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i],"--help")) { usage(); return 0; }
        if (!strcmp(argv[i],"--all-pairs")) { cfg.all_pairs = 1; continue; }
        if (i+1 >= argc) { usage(); return 2; }
        if (!strcmp(argv[i],"--base")) { if (!parse_int(argv[++i],1,15,&cfg.only_base)) return 2; }
        else if (!strcmp(argv[i],"--short-ms")) { if (!parse_int(argv[++i],1000,30000,&cfg.short_ms)) return 2; }
        else if (!strcmp(argv[i],"--busy-ms")) { if (!parse_int(argv[++i],1000,120000,&cfg.busy_ms)) return 2; }
        else if (!strcmp(argv[i],"--warmup-ms")) { if (!parse_int(argv[++i],100,5000,&cfg.warmup_ms)) return 2; }
        else if (!strcmp(argv[i],"--expected-cpus")) { if (!parse_int(argv[++i],2,8,&cfg.expected_cpus)) return 2; }
        else if (!strcmp(argv[i],"--worker-cpu")) { if (!parse_int(argv[++i],0,63,&cfg.worker_cpu)) return 2; }
        else { usage(); return 2; }
    }
    if (cfg.all_pairs && cfg.only_base) { usage(); return 2; }
    LARGE_INTEGER f;
    if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) return 3;
    frequency = f.QuadPart;
    setvbuf(stdout,NULL,_IOFBF,1024*1024);
    if (!SetConsoleCtrlHandler(on_console,TRUE)) return error_record("SetConsoleCtrlHandler",GetLastError(),0) ? 0 : 3;
    if (!setup_config(&cfg)) return 3;
    SYSTEMTIME utc; GetSystemTime(&utc);
    printf("{\"type\":\"run_identity\",\"parent_pid\":%lu,\"utc_started\":\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",\"os_build_source\":\"runner_host_json\"}\n",
        (unsigned long)GetCurrentProcessId(),utc.wYear,utc.wMonth,utc.wDay,utc.wHour,utc.wMinute,utc.wSecond,utc.wMilliseconds);
    mapping_records(); fflush(stdout);
    int okay = 1;
    if (cfg.all_pairs) {
        for (int c = 0; c < 5 && okay; ++c) for (int l = 0; l < 7 && okay; ++l) okay = run_pair(&cfg,c,l);
    } else {
        for (int b = 1; b <= 15 && okay; ++b) {
            if (cfg.only_base && cfg.only_base != b) continue;
            okay = run_pair(&cfg,canonical[b-1][0],canonical[b-1][1]);
        }
    }
    if (!SetThreadGroupAffinity(GetCurrentThread(),&cfg.original_thread,NULL)) {
        error_record("restore_controller_thread_affinity",GetLastError(),0); okay = 0;
    }
    if (fflush(stdout) != 0 || ferror(stdout)) okay = 0;
    printf("{\"type\":\"complete\",\"valid\":%s,\"runs\":%d,\"windows_execution\":true}\n",okay ? "true":"false",next_run);
    if (fflush(stdout) != 0 || ferror(stdout)) okay = 0;
    return okay ? 0 : 4;
}
