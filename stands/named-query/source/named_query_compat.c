/* Bounded, named Wine compatibility fixture.
 * Source contract: Wine a15ee2ccf20e2fc9f470badd916855801933d31f.
 * This program records status/length/change counts, never query data payloads.
 * It is not a class enumerator. The only query selectors are the list below.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define DATA_CAPACITY 8192u
#define LARGE_CAPACITY 4096u
#define CLASS_TIMEOUT_MS 15000u
#define WINE_PIN "a15ee2ccf20e2fc9f470badd916855801933d31f"

/* Public layouts absent from some SDKs; copied in shape from pinned winternl.h.
 * Names are private to avoid colliding with SDK declarations. */
typedef struct { VM_COUNTERS Base; SIZE_T PrivateUsage; } COMPAT_VM_COUNTERS_EX;
typedef struct { BOOLEAN Foreground; UCHAR PriorityClass; } COMPAT_PROCESS_PRIORITY_CLASS;
typedef struct { ULONGLONG AccumulatedCycles, CurrentCycleCount; } COMPAT_PROCESS_CYCLE_TIME;
typedef struct {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize, CommittedStackSize;
    ULONG SubSystemType;
    USHORT MinorSubsystemVersion, MajorSubsystemVersion;
    USHORT MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    USHORT ImageCharacteristics, DllCharacteristics, Machine;
    BOOLEAN ImageContainsCode;
    UCHAR ImageFlags;
    ULONG LoaderFlags, ImageFileSize, CheckSum;
} COMPAT_SECTION_IMAGE_INFORMATION;

_Static_assert(sizeof(ULONG) == 4, "ULONG layout");
_Static_assert(sizeof(LARGE_INTEGER) == 8, "LARGE_INTEGER layout");
_Static_assert(sizeof(KERNEL_USER_TIMES) == 32, "KERNEL_USER_TIMES layout");
_Static_assert(sizeof(COMPAT_PROCESS_PRIORITY_CLASS) == 2, "priority class layout");
_Static_assert(sizeof(COMPAT_PROCESS_CYCLE_TIME) == 16, "cycle time layout");
_Static_assert(sizeof(IO_COUNTERS) == 48, "IO_COUNTERS layout");
_Static_assert(sizeof(OBJECT_BASIC_INFORMATION) == 56, "object basic layout");
_Static_assert(sizeof(PROCESS_BASIC_INFORMATION) == (sizeof(void *) == 8 ? 48 : 24), "process basic layout");
_Static_assert(sizeof(VM_COUNTERS) == (sizeof(void *) == 8 ? 88 : 44), "VM_COUNTERS layout");
_Static_assert(sizeof(COMPAT_VM_COUNTERS_EX) == (sizeof(void *) == 8 ? 96 : 48), "VM_COUNTERS_EX layout");
_Static_assert(sizeof(QUOTA_LIMITS) == (sizeof(void *) == 8 ? 48 : 32), "quota layout");
_Static_assert(sizeof(COMPAT_SECTION_IMAGE_INFORMATION) == (sizeof(void *) == 8 ? 64 : 48), "image info layout");
_Static_assert(sizeof(OBJECT_TYPE_INFORMATION) == (sizeof(void *) == 8 ? 104 : 96), "object type header");

typedef NTSTATUS (NTAPI *query_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *version_fn)(PRTL_OSVERSIONINFOW);
enum api_kind { API_PROCESS, API_OBJECT, API_THREAD };
enum length_kind { LENGTH_FIXED, VM_DUAL, VARIABLE, PARTIAL_ZERO, SENTINEL, RESIDUAL };
enum handle_kind { OWN_PROCESS, INVALID_NULL, OWN_QUERY_LIMITED, OWN_SYNCHRONIZE,
                   OWN_EVENT, OWN_FILE, OWN_THREAD_RESTRICTED };
enum return_kind { RETURN_VALID, RETURN_NULL, RETURN_RESERVED };
struct query_desc {
    const char *name;
    enum api_kind api;
    ULONG info_class;
    enum length_kind kind;
    const char *layout;
    ULONG size;
    ULONG capacity;
};
#define P_FIXED(name, value, type) {name, API_PROCESS, value, LENGTH_FIXED, #type, sizeof(type), LARGE_CAPACITY}
#define P_VAR(name, value) {name, API_PROCESS, value, VARIABLE, "UNICODE_STRING_header", sizeof(UNICODE_STRING), LARGE_CAPACITY}
/* Every entry is named and justified in allowlist.json. No generated class range. */
static const struct query_desc queries[] = {
    P_FIXED("ProcessBasicInformation", 0, PROCESS_BASIC_INFORMATION),
    P_FIXED("ProcessQuotaLimits", 1, QUOTA_LIMITS),
    P_FIXED("ProcessIoCounters", 2, IO_COUNTERS),
    {"ProcessVmCounters", API_PROCESS, 3, VM_DUAL, "VM_COUNTERS", sizeof(VM_COUNTERS), LARGE_CAPACITY},
    P_FIXED("ProcessTimes", 4, KERNEL_USER_TIMES),
    P_FIXED("ProcessDebugPort", 7, ULONG_PTR),
    P_FIXED("ProcessDefaultHardErrorMode", 12, ULONG),
    P_FIXED("ProcessPriorityClass", 18, COMPAT_PROCESS_PRIORITY_CLASS),
    P_FIXED("ProcessHandleCount", 20, ULONG),
    P_FIXED("ProcessAffinityMask", 21, ULONG_PTR),
    P_FIXED("ProcessPriorityBoost", 22, ULONG),
    {"ProcessSessionInformation_partial_zero", API_PROCESS, 24, PARTIAL_ZERO, "unknown_no_N", 0, 0},
    P_FIXED("ProcessWow64Information", 26, ULONG_PTR),
    P_VAR("ProcessImageFileName", 27),
    P_FIXED("ProcessDebugFlags", 31, ULONG),
    P_FIXED("ProcessExecuteFlags", 34, ULONG),
    P_FIXED("ProcessCookie", 36, ULONG),
    P_FIXED("ProcessImageInformation", 37, COMPAT_SECTION_IMAGE_INFORMATION),
    P_FIXED("ProcessCycleTime", 38, COMPAT_PROCESS_CYCLE_TIME),
    P_VAR("ProcessImageFileNameWin32", 43),
    {"ObjectBasicInformation_event", API_OBJECT, 0, LENGTH_FIXED, "OBJECT_BASIC_INFORMATION", sizeof(OBJECT_BASIC_INFORMATION), LARGE_CAPACITY},
    {"ObjectNameInformation", API_OBJECT, 1, VARIABLE, "OBJECT_NAME_INFORMATION_header", sizeof(UNICODE_STRING), 1024},
    {"ObjectTypeInformation", API_OBJECT, 2, VARIABLE, "OBJECT_TYPE_INFORMATION_header", sizeof(OBJECT_TYPE_INFORMATION), 1024},
    {"ProcessSentinel_minus_one", API_PROCESS, 0xffffffffu, SENTINEL, "none", 0, 0},
    {"ProcessSentinel_int_max", API_PROCESS, 0x7fffffffu, SENTINEL, "none", 0, 0},
    {"ObjectSentinel_minus_one", API_OBJECT, 0xffffffffu, SENTINEL, "none", 0, 0},
    {"ObjectSentinel_int_max", API_OBJECT, 0x7fffffffu, SENTINEL, "none", 0, 0},
    /* Exactly four prior, explicitly requested residual cells. No new thread matrix. */
    {"ThreadPerformanceCount_reserved_R_len8", API_THREAD, 11, RESIDUAL, "LARGE_INTEGER", 8, 0},
    {"ThreadPerformanceCount_valid_R_len0", API_THREAD, 11, RESIDUAL, "LARGE_INTEGER", 0, 0},
    {"ThreadPerformanceCount_valid_R_len7", API_THREAD, 11, RESIDUAL, "LARGE_INTEGER", 7, 0},
    {"ThreadPerformanceCount_valid_R_len9", API_THREAD, 11, RESIDUAL, "LARGE_INTEGER", 9, 0}
};

struct case_spec {
    unsigned id;
    const char *layout;
    const char *length_label;
    ULONG reference_size;
    ULONG length;
    enum handle_kind handle;
    enum return_kind ret;
};
struct resources {
    HANDLE query_limited, synchronize, event, file, thread;
    DWORD query_error, sync_error, event_error, file_error, thread_error, reserved_error;
    void *reserved;
};
static HANDLE output_handle;
static const struct query_desc *active_query;
static struct case_spec active_case;
static BOOL case_active;
static unsigned group_index;
static char pattern;
static _Alignas(16) unsigned char data_buffer[DATA_CAPACITY];
static ULONG return_length;
static query_fn query_process, query_object, query_thread;

static const char *api_name(enum api_kind kind)
{
    return kind == API_PROCESS ? "NtQueryInformationProcess" :
           kind == API_OBJECT ? "NtQueryObject" : "NtQueryInformationThread";
}
static const char *handle_name(enum handle_kind kind)
{
    static const char *names[] = {"own_process_pseudo", "invalid_NULL", "own_process_QUERY_LIMITED_INFORMATION",
        "own_process_SYNCHRONIZE", "owned_named_event", "owned_temporary_file", "own_thread_QUERY_LIMITED_INFORMATION"};
    return names[kind];
}
static const char *return_name(enum return_kind kind)
{
    return kind == RETURN_VALID ? "valid_aligned" : kind == RETURN_NULL ? "NULL" : "reserved_uncommitted";
}
static const char *access_mask(enum handle_kind kind)
{
    switch (kind)
    {
    case OWN_QUERY_LIMITED: return "\"0x00001000\"";
    case OWN_SYNCHRONIZE: return "\"0x00100000\"";
    case OWN_THREAD_RESTRICTED: return "\"0x00000800\"";
    default: return "null";
    }
}
static void emit(const char *fmt, ...)
{
    char line[4096];
    DWORD written;
    int size;
    va_list args;
    va_start(args, fmt);
    size = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);
    if (size < 0 || (size_t)size >= sizeof(line) ||
        !WriteFile(output_handle, line, (DWORD)size, &written, NULL) || written != (DWORD)size)
        ExitProcess(11);
    if (!FlushFileBuffers(output_handle)) ExitProcess(12);
}
static unsigned char initial_byte(unsigned i)
{
    unsigned char value = (unsigned char)(0x29u + 37u * i);
    return pattern == 'A' ? value : (unsigned char)~value;
}
static ULONG initial_return_length(void)
{
    return pattern == 'A' ? 0xa1b2c3d4u : 0x5e4d3c2bu;
}
static void count_changes(unsigned *changed, unsigned *after_request, unsigned *ret_changed)
{
    unsigned i;
    ULONG before = initial_return_length();
    *changed = *after_request = *ret_changed = 0;
    for (i = 0; i < DATA_CAPACITY; ++i)
        if (data_buffer[i] != initial_byte(i))
        {
            ++*changed;
            if (i >= active_case.length) ++*after_request;
        }
    if (active_case.ret == RETURN_VALID)
        for (i = 0; i < sizeof(ULONG); ++i)
            if (((unsigned char *)&return_length)[i] != ((unsigned char *)&before)[i]) ++*ret_changed;
}
static void emit_case_begin(BOOL will_execute)
{
    emit("{\"record\":\"case_begin\",\"group\":%u,\"case\":%u,\"pattern\":\"%c\","
         "\"name\":\"%s\",\"api\":\"%s\",\"class\":%lu,\"length\":%lu,"
         "\"handle\":\"%s\",\"handle_access_mask\":%s,\"return_length_mode\":\"%s\",\"query_will_execute\":%s}\n",
         group_index, active_case.id, pattern, active_query->name, api_name(active_query->api),
         (unsigned long)active_query->info_class, (unsigned long)active_case.length,
         handle_name(active_case.handle), access_mask(active_case.handle), return_name(active_case.ret),
         will_execute ? "true" : "false");
}
static void emit_case(const char *outcome, BOOL has_status, DWORD status, DWORD exception, DWORD error)
{
    unsigned changed, after_request, ret_changed;
    char status_text[32], exception_text[32], ret_text[32], ret_change_text[32];
    count_changes(&changed, &after_request, &ret_changed);
    if (has_status) snprintf(status_text, sizeof(status_text), "\"0x%08lx\"", (unsigned long)status);
    else strcpy(status_text, "null");
    if (exception) snprintf(exception_text, sizeof(exception_text), "\"0x%08lx\"", (unsigned long)exception);
    else strcpy(exception_text, "null");
    if (active_case.ret == RETURN_VALID)
    {
        snprintf(ret_text, sizeof(ret_text), "%lu", (unsigned long)return_length);
        snprintf(ret_change_text, sizeof(ret_change_text), "%u", ret_changed);
    }
    else { strcpy(ret_text, "null"); strcpy(ret_change_text, "null"); }
    emit("{\"record\":\"case_result\",\"group\":%u,\"case\":%u,\"pattern\":\"%c\","
         "\"name\":\"%s\",\"api\":\"%s\",\"class\":%lu,\"layout\":\"%s\","
         "\"length_label\":\"%s\",\"reference_size\":%lu,\"length\":%lu,"
         "\"handle\":\"%s\",\"handle_access_mask\":%s,\"return_length_mode\":\"%s\",\"outcome\":\"%s\","
         "\"status\":%s,\"exception\":%s,\"setup_error\":%lu,\"return_length_value\":%s,"
         "\"return_length_changed_bytes\":%s,\"data_changed_bytes\":%u,"
         "\"data_changed_after_requested_length\":%u,\"data_capacity\":%u}\n",
         group_index, active_case.id, pattern, active_query->name, api_name(active_query->api),
         (unsigned long)active_query->info_class, active_case.layout, active_case.length_label,
         (unsigned long)active_case.reference_size, (unsigned long)active_case.length,
         handle_name(active_case.handle), access_mask(active_case.handle), return_name(active_case.ret), outcome,
         status_text, exception_text, (unsigned long)error, ret_text, ret_change_text,
         changed, after_request, DATA_CAPACITY);
}
static LONG CALLBACK exception_handler(EXCEPTION_POINTERS *exception)
{
    DWORD code = exception->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_IN_PAGE_ERROR &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_DATATYPE_MISALIGNMENT)
        return EXCEPTION_CONTINUE_SEARCH;
    if (case_active) emit_case("exception", FALSE, 0, code, 0);
    ExitProcess(code);
}
static void load_functions(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    query_process = (query_fn)(void *)GetProcAddress(ntdll, "NtQueryInformationProcess");
    query_object = (query_fn)(void *)GetProcAddress(ntdll, "NtQueryObject");
    query_thread = (query_fn)(void *)GetProcAddress(ntdll, "NtQueryInformationThread");
}
static void init_resources(struct resources *r, const struct query_desc *q)
{
    wchar_t event_name[100], directory[MAX_PATH], filename[MAX_PATH];
    memset(r, 0, sizeof(*r));
    if (q->api == API_PROCESS && q->kind != SENTINEL)
    {
        r->query_limited = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
        if (!r->query_limited) r->query_error = GetLastError();
        r->synchronize = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
        if (!r->synchronize) r->sync_error = GetLastError();
    }
    if (q->api == API_OBJECT)
    {
        swprintf(event_name, COUNT(event_name), L"Local\\NamedQueryCompat_%lu_%u", GetCurrentProcessId(), group_index);
        r->event = CreateEventW(NULL, FALSE, FALSE, event_name);
        if (!r->event) r->event_error = GetLastError();
        else if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            CloseHandle(r->event);
            r->event = NULL;
            r->event_error = ERROR_ALREADY_EXISTS;
        }
        if (q->kind == VARIABLE)
        {
            DWORD length = GetTempPathW(COUNT(directory), directory);
            if (!length || length >= COUNT(directory)) r->file_error = GetLastError();
            else if (!GetTempFileNameW(directory, L"nqc", 0, filename)) r->file_error = GetLastError();
            else
            {
                r->file = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE | DELETE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
                if (r->file == INVALID_HANDLE_VALUE)
                {
                    r->file_error = GetLastError();
                    r->file = NULL;
                    DeleteFileW(filename);
                }
            }
            if (!r->file && !r->file_error) r->file_error = ERROR_INSUFFICIENT_BUFFER;
        }
    }
    if (q->api == API_THREAD)
    {
        r->thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
        if (!r->thread) r->thread_error = GetLastError();
        if (q->size == 8)
        {
            r->reserved = VirtualAlloc(NULL, sizeof(ULONG), MEM_RESERVE, PAGE_NOACCESS);
            if (!r->reserved) r->reserved_error = GetLastError();
        }
    }
}
static void close_resources(struct resources *r)
{
    if (r->query_limited) CloseHandle(r->query_limited);
    if (r->synchronize) CloseHandle(r->synchronize);
    if (r->event) CloseHandle(r->event);
    if (r->file) CloseHandle(r->file);
    if (r->thread) CloseHandle(r->thread);
    if (r->reserved) VirtualFree(r->reserved, 0, MEM_RELEASE);
}
static HANDLE select_handle(struct resources *r, enum handle_kind kind, DWORD *error)
{
    *error = 0;
    switch (kind)
    {
    case OWN_PROCESS: return GetCurrentProcess();
    case INVALID_NULL: return NULL;
    case OWN_QUERY_LIMITED: *error = r->query_error; return r->query_limited;
    case OWN_SYNCHRONIZE: *error = r->sync_error; return r->synchronize;
    case OWN_EVENT: *error = r->event_error; return r->event;
    case OWN_FILE: *error = r->file_error; return r->file;
    case OWN_THREAD_RESTRICTED: *error = r->thread_error; return r->thread;
    }
    *error = ERROR_INVALID_PARAMETER;
    return NULL;
}
static unsigned make_cases(const struct query_desc *q, struct case_spec *cases)
{
    unsigned form, li, hi, ri, count = 0, forms = q->kind == VM_DUAL ? 2 : 1;
    enum handle_kind handles[4];
    unsigned nh, nr = 2, nl;
    ULONG lengths[5], size;
    const char *labels[5] = {"zero", "N_minus_1", "N", "N_plus_1", "large"};
    const char *layout;
    if (q->api == API_THREAD)
    {
        cases[0] = (struct case_spec){0, "LARGE_INTEGER", "requested_residual", sizeof(LARGE_INTEGER),
            q->size, OWN_THREAD_RESTRICTED, q->size == 8 ? RETURN_RESERVED : RETURN_VALID};
        return 1;
    }
    if (q->kind == SENTINEL)
    { handles[0] = q->api == API_PROCESS ? OWN_PROCESS : OWN_EVENT; nh = 1; }
    else if (q->api == API_PROCESS)
    { handles[0] = OWN_PROCESS; handles[1] = INVALID_NULL; handles[2] = OWN_QUERY_LIMITED; handles[3] = OWN_SYNCHRONIZE; nh = 4; }
    else if (q->kind == LENGTH_FIXED)
    { handles[0] = OWN_EVENT; handles[1] = INVALID_NULL; nh = 2; }
    else
    { handles[0] = OWN_EVENT; handles[1] = OWN_FILE; handles[2] = OWN_PROCESS; handles[3] = INVALID_NULL; nh = 4; }
    for (form = 0; form < forms; ++form)
    {
        size = form ? sizeof(COMPAT_VM_COUNTERS_EX) : q->size;
        layout = form ? "VM_COUNTERS_EX" : q->layout;
        if (q->kind == PARTIAL_ZERO || q->kind == SENTINEL)
        { lengths[0] = 0; nl = 1; }
        else
        {
            lengths[0] = 0; lengths[1] = size - 1; lengths[2] = size; lengths[3] = size + 1;
            lengths[4] = q->capacity;
            if (q->kind != VARIABLE && lengths[4] < 4 * size) lengths[4] = 4 * size;
            nl = 5;
        }
        for (li = 0; li < nl; ++li)
            for (hi = 0; hi < nh; ++hi)
                for (ri = 0; ri < nr; ++ri)
                {
                    const char *label = labels[li];
                    if (q->kind == VARIABLE)
                    {
                        static const char *variable_labels[] = {"zero", "header_minus_1", "header", "header_plus_1", "test_capacity"};
                        label = variable_labels[li];
                    }
                    cases[count] = (struct case_spec){count, layout, label, size, lengths[li], handles[hi], ri ? RETURN_NULL : RETURN_VALID};
                    ++count;
                }
    }
    return count;
}
static int child_main(unsigned index, char selected_pattern)
{
    struct case_spec cases[80];
    struct resources resources;
    unsigned count, i, j, setup_failures = 0;
    query_fn function;
    PVOID handler;
    output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    group_index = index;
    pattern = selected_pattern;
    active_query = &queries[index];
    count = make_cases(active_query, cases);
    load_functions();
    function = active_query->api == API_PROCESS ? query_process : active_query->api == API_OBJECT ? query_object : query_thread;
    if (!function)
    { emit("{\"record\":\"group_setup_failure\",\"group\":%u,\"reason\":\"missing_export\"}\n", index); return 3; }
    handler = AddVectoredExceptionHandler(1, exception_handler);
    if (!handler)
    { emit("{\"record\":\"group_setup_failure\",\"group\":%u,\"reason\":\"exception_handler_unavailable\"}\n", index); return 3; }
    init_resources(&resources, active_query);
    for (i = 0; i < count; ++i)
    {
        HANDLE handle;
        ULONG *ret;
        DWORD error;
        NTSTATUS status;
        active_case = cases[i];
        for (j = 0; j < DATA_CAPACITY; ++j) data_buffer[j] = initial_byte(j);
        return_length = initial_return_length();
        handle = select_handle(&resources, active_case.handle, &error);
        ret = active_case.ret == RETURN_VALID ? &return_length :
            active_case.ret == RETURN_RESERVED ? resources.reserved : NULL;
        if (active_case.ret == RETURN_RESERVED && !resources.reserved) error = resources.reserved_error;
        emit_case_begin(error == 0);
        if (error)
        { ++setup_failures; emit_case("setup_failure", FALSE, 0, 0, error); continue; }
        case_active = TRUE;
        status = function(handle, active_query->info_class, data_buffer, active_case.length, ret);
        emit_case("returned", TRUE, (DWORD)status, 0, 0);
        case_active = FALSE;
    }
    close_resources(&resources);
    RemoveVectoredExceptionHandler(handler);
    emit("{\"record\":\"group_complete\",\"group\":%u,\"case_records\":%u,"
         "\"case_setup_failures\":%u,\"query_calls\":%u}\n", index, count, setup_failures, count - setup_failures);
    return setup_failures ? 4 : 0;
}
static int parent_main(const wchar_t *filename, char selected_pattern)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    wchar_t executable[32768], command[33000], diagnostic_path[32768];
    unsigned i, total = 0, abnormal = 0, started = 0;
    BOOL unresolved = FALSE;
    HANDLE null_input, diagnostics;
    BOOL wow64 = FALSE;
    RTL_OSVERSIONINFOW version;
    version_fn get_version;
    SYSTEMTIME now;
    DWORD executable_length;
    output_handle = CreateFileW(filename, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_handle == INVALID_HANDLE_VALUE)
    { fwprintf(stderr, L"Cannot create new output file (error %lu). Existing files are never overwritten.\n", GetLastError()); return 2; }
    pattern = selected_pattern;
    if (wcslen(filename) + wcslen(L".stderr.txt") >= COUNT(diagnostic_path))
    { emit("{\"record\":\"run_setup_failure\",\"reason\":\"diagnostic_path_too_long\"}\n"); CloseHandle(output_handle); return 2; }
    swprintf(diagnostic_path, COUNT(diagnostic_path), L"%ls.stderr.txt", filename);
    diagnostics = CreateFileW(diagnostic_path, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (diagnostics == INVALID_HANDLE_VALUE)
    { emit("{\"record\":\"run_setup_failure\",\"reason\":\"diagnostic_file\"}\n"); CloseHandle(output_handle); return 2; }
    executable_length = GetModuleFileNameW(NULL, executable, COUNT(executable));
    if (!executable_length || executable_length >= COUNT(executable))
    { emit("{\"record\":\"run_setup_failure\",\"reason\":\"executable_path\"}\n"); CloseHandle(diagnostics); CloseHandle(output_handle); return 2; }
    null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    if (null_input == INVALID_HANDLE_VALUE)
    { emit("{\"record\":\"run_setup_failure\",\"reason\":\"null_input\"}\n"); CloseHandle(diagnostics); CloseHandle(output_handle); return 2; }
    memset(&version, 0, sizeof(version)); version.dwOSVersionInfoSize = sizeof(version);
    get_version = (version_fn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (get_version) get_version(&version);
    IsWow64Process(GetCurrentProcess(), &wow64);
    GetSystemTime(&now);
    emit("{\"record\":\"run_start\",\"schema\":1,\"wine_pin\":\"%s\",\"pattern\":\"%c\","
         "\"pointer_bits\":%u,\"wow64\":%s,\"os_major\":%lu,\"os_minor\":%lu,\"os_build\":%lu,"
         "\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02uZ\",\"groups\":%u,\"class_timeout_ms\":%u,"
         "\"boundary_sentinels\":\"omitted_pending_user_decision\",\"data_payload_emitted\":false}\n",
         WINE_PIN, pattern, (unsigned)(8 * sizeof(void *)), wow64 ? "true" : "false",
         (unsigned long)version.dwMajorVersion, (unsigned long)version.dwMinorVersion, (unsigned long)version.dwBuildNumber,
         now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, (unsigned)COUNT(queries), CLASS_TIMEOUT_MS);
    for (i = 0; i < COUNT(queries); ++i)
    {
        struct case_spec cases[80];
        total += make_cases(&queries[i], cases);
    }
    for (i = 0; i < COUNT(queries); ++i)
    {
        struct case_spec cases[80];
        unsigned count = make_cases(&queries[i], cases);
        STARTUPINFOW start;
        PROCESS_INFORMATION child;
        DWORD wait, exit_code = 0, termination_error = 0, cleanup_wait = WAIT_OBJECT_0;
        const char *outcome;
        ++started;
        emit("{\"record\":\"group_start\",\"group\":%u,\"name\":\"%s\",\"api\":\"%s\","
             "\"class\":%lu,\"planned_cases\":%u,\"reference_size\":%lu}\n",
             i, queries[i].name, api_name(queries[i].api), (unsigned long)queries[i].info_class, count, (unsigned long)queries[i].size);
        memset(&start, 0, sizeof(start)); start.cb = sizeof(start);
        start.dwFlags = STARTF_USESTDHANDLES;
        start.hStdInput = null_input; start.hStdOutput = output_handle; start.hStdError = diagnostics;
        memset(&child, 0, sizeof(child));
        swprintf(command, COUNT(command), L"\"%ls\" --child %u --pattern %c", executable, i, (wchar_t)pattern);
        if (!CreateProcessW(executable, command, NULL, NULL, TRUE, 0, NULL, NULL, &start, &child))
        {
            ++abnormal;
            emit("{\"record\":\"group_outcome\",\"group\":%u,\"outcome\":\"launch_failure\",\"error\":%lu}\n", i, GetLastError());
            continue;
        }
        wait = WaitForSingleObject(child.hProcess, CLASS_TIMEOUT_MS);
        if (wait == WAIT_TIMEOUT)
        {
            if (!TerminateProcess(child.hProcess, 124)) termination_error = GetLastError();
            cleanup_wait = WaitForSingleObject(child.hProcess, 5000);
            outcome = "timeout";
        }
        else if (wait != WAIT_OBJECT_0)
        {
            if (!TerminateProcess(child.hProcess, 125)) termination_error = GetLastError();
            cleanup_wait = WaitForSingleObject(child.hProcess, 5000);
            outcome = "wait_failure";
        }
        else outcome = "complete";
        if (cleanup_wait != WAIT_OBJECT_0)
        { outcome = "termination_unresolved"; unresolved = TRUE; }
        if (!GetExitCodeProcess(child.hProcess, &exit_code))
        { outcome = "exit_code_unavailable"; }
        else if (wait == WAIT_OBJECT_0 && exit_code != 0)
        { outcome = exit_code == 3 ? "setup_failure" : exit_code == 4 ? "partial_setup_failure" : "abnormal_exit"; }
        if (unresolved) outcome = "termination_unresolved";
        if (strcmp(outcome, "complete")) ++abnormal;
        emit("{\"record\":\"group_outcome\",\"group\":%u,\"outcome\":\"%s\",\"exit_code\":%lu,"
             "\"termination_error\":%lu,\"cleanup_wait\":%lu}\n", i, outcome, (unsigned long)exit_code,
             (unsigned long)termination_error, (unsigned long)cleanup_wait);
        CloseHandle(child.hThread); CloseHandle(child.hProcess);
        if (unresolved) break;
    }
    emit("{\"record\":\"run_complete\",\"planned_groups\":%u,\"planned_cases\":%u,\"started_groups\":%u,"
         "\"abnormal_groups\":%u,\"run_outcome\":\"%s\"}\n",
         (unsigned)COUNT(queries), total, started, abnormal,
         unresolved ? "aborted_unresolved_child" : abnormal ? "completed_with_failures" : "complete");
    CloseHandle(null_input); CloseHandle(diagnostics); CloseHandle(output_handle);
    return abnormal ? 1 : 0;
}
int wmain(int argc, wchar_t **argv)
{
    if (argc == 5 && !wcscmp(argv[1], L"--child") && !wcscmp(argv[3], L"--pattern"))
    {
        wchar_t *end;
        unsigned long index = wcstoul(argv[2], &end, 10);
        if (*end || index >= COUNT(queries) || wcslen(argv[4]) != 1 || (argv[4][0] != L'A' && argv[4][0] != L'B')) return 2;
        return child_main((unsigned)index, (char)argv[4][0]);
    }
    if (argc == 5 && !wcscmp(argv[1], L"--output") && !wcscmp(argv[3], L"--pattern") &&
        wcslen(argv[4]) == 1 && (argv[4][0] == L'A' || argv[4][0] == L'B'))
        return parent_main(argv[2], (char)argv[4][0]);
    fwprintf(stderr, L"Usage: named-query-compat.exe --output NEWFILE.jsonl --pattern A|B\nRun twice in independent invocations, once with A and once with B.\n");
    return 2;
}
