// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
/* AI-generated diagnostic preparation, not an upstream Wine contribution.
 * No Windows observations are encoded as expected results.
 * Expanded diagnostic schema 3. Run each case in a separate process with run-cases.ps1.
 * Additional schema 2/3 code is AI-generated local diagnostic preparation.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#ifndef PROBE_SOURCE_SHA256
#define PROBE_SOURCE_SHA256 "not-recorded"
#endif
#ifndef PROBE_BUILD_TARGET
#define PROBE_BUILD_TARGET "not-recorded"
#endif

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#endif

typedef LONG (WINAPI *query_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *version_fn)(OSVERSIONINFOW *);
typedef char assert_large_integer_is_8[(sizeof(LARGE_INTEGER) == 8) ? 1 : -1];
typedef char assert_ulong_is_4[(sizeof(ULONG) == 4) ? 1 : -1];

enum handle_mode { CURRENT, QUERY, LIMITED, ZERO_ACCESS, SYNC_ONLY,
                   NULL_HANDLE, INVALID_HANDLE, PROCESS_HANDLE, EVENT_HANDLE,
                   WORKER_IDLE, WORKER_BUSY, WORKER_SUSPENDED, WORKER_EXITED };
enum buffer_mode { WRITABLE, NULL_BUFFER, UNALIGNED_BUFFER, READONLY_BUFFER,
                   NOACCESS_BUFFER, CROSS_PAGE };
enum return_mode { RETURN_VALID, RETURN_NULL, RETURN_RESERVED, RETURN_UNALIGNED,
                   RETURN_READONLY, RETURN_ALIAS, RETURN_NOACCESS, RETURN_BOUNDARY };
enum phase_mode { NORMAL, AFTER_SLEEP, AFTER_BURN };
struct test_case {
    const char *name;
    ULONG length;
    enum handle_mode handle;
    enum buffer_mode buffer;
    enum return_mode ret;
    enum phase_mode phase;
    unsigned repeat;
    unsigned data_extra_offset;
    unsigned alias_offset;
    unsigned return_accessible_prefix;
};
#define C(n,l,h,b,r,p,k,d,a,f) { n,l,h,b,r,p,k,d,a,f }
static const struct test_case cases[] = {
    C("exact8_current",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_query_handle",8,QUERY,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_limited_handle",8,LIMITED,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_zero_access_handle",8,ZERO_ACCESS,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_sync_only_handle",8,SYNC_ONLY,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length0",0,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length1",1,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length4",4,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length7",7,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length9",9,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length16",16,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_no_return_length",8,CURRENT,WRITABLE,RETURN_NULL,NORMAL,1,0,0,0),
    C("exact8_null_buffer",8,CURRENT,NULL_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_unaligned_buffer",8,CURRENT,UNALIGNED_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_readonly_buffer",8,CURRENT,READONLY_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_noaccess_buffer",8,CURRENT,NOACCESS_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_cross_page_buffer",8,CURRENT,CROSS_PAGE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_reserved_return_length",8,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,0,0,0),
    C("exact8_unaligned_return_length",8,CURRENT,WRITABLE,RETURN_UNALIGNED,NORMAL,1,0,0,0),
    C("exact8_readonly_return_length",8,CURRENT,WRITABLE,RETURN_READONLY,NORMAL,1,0,0,0),
    C("exact8_alias_return_length",8,CURRENT,WRITABLE,RETURN_ALIAS,NORMAL,1,0,0,0),
    C("exact8_null_handle",8,NULL_HANDLE,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_invalid_handle",8,INVALID_HANDLE,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_process_handle",8,PROCESS_HANDLE,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_event_handle",8,EVENT_HANDLE,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length0_null_buffer",0,CURRENT,NULL_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("length7_null_buffer",7,CURRENT,NULL_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("length0_invalid_handle",0,INVALID_HANDLE,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length7_invalid_handle",7,INVALID_HANDLE,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("length7_reserved_return_length",7,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,0,0,0),
    C("exact8_invalid_handle_null_buffer",8,INVALID_HANDLE,NULL_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_invalid_handle_reserved_return_length",8,INVALID_HANDLE,WRITABLE,RETURN_RESERVED,NORMAL,1,0,0,0),
    C("exact8_null_buffer_reserved_return_length",8,CURRENT,NULL_BUFFER,RETURN_RESERVED,NORMAL,1,0,0,0),
    C("exact8_limited_handle_null_buffer",8,LIMITED,NULL_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("repeat8_current",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,5,0,0,0),
    C("repeat8_after_sleep",8,CURRENT,WRITABLE,RETURN_VALID,AFTER_SLEEP,5,0,0,0),
    C("repeat8_after_burn",8,CURRENT,WRITABLE,RETURN_VALID,AFTER_BURN,5,0,0,0),
    C("exact8_worker_idle",8,WORKER_IDLE,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_worker_busy",8,WORKER_BUSY,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_worker_suspended",8,WORKER_SUSPENDED,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("exact8_worker_exited",8,WORKER_EXITED,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("data_offset_0",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,0,0,0),
    C("data_offset_1",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,1,0,0),
    C("data_offset_2",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,2,0,0),
    C("data_offset_3",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,3,0,0),
    C("data_offset_4",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,4,0,0),
    C("data_offset_5",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,5,0,0),
    C("data_offset_6",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,6,0,0),
    C("data_offset_7",8,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,7,0,0),
    C("protected_readonly_handle_current_return_null",8,CURRENT,READONLY_BUFFER,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_readonly_handle_invalid_return_valid",8,INVALID_HANDLE,READONLY_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("protected_readonly_handle_invalid_return_null",8,INVALID_HANDLE,READONLY_BUFFER,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_readonly_handle_limited_return_valid",8,LIMITED,READONLY_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("protected_readonly_handle_limited_return_null",8,LIMITED,READONLY_BUFFER,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_noaccess_handle_current_return_null",8,CURRENT,NOACCESS_BUFFER,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_noaccess_handle_invalid_return_valid",8,INVALID_HANDLE,NOACCESS_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("protected_noaccess_handle_invalid_return_null",8,INVALID_HANDLE,NOACCESS_BUFFER,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_noaccess_handle_limited_return_valid",8,LIMITED,NOACCESS_BUFFER,RETURN_VALID,NORMAL,1,0,0,0),
    C("protected_noaccess_handle_limited_return_null",8,LIMITED,NOACCESS_BUFFER,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_cross_page_handle_current_return_null",8,CURRENT,CROSS_PAGE,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_cross_page_handle_invalid_return_valid",8,INVALID_HANDLE,CROSS_PAGE,RETURN_VALID,NORMAL,1,0,0,0),
    C("protected_cross_page_handle_invalid_return_null",8,INVALID_HANDLE,CROSS_PAGE,RETURN_NULL,NORMAL,1,0,0,0),
    C("protected_cross_page_handle_limited_return_valid",8,LIMITED,CROSS_PAGE,RETURN_VALID,NORMAL,1,0,0,0),
    C("protected_cross_page_handle_limited_return_null",8,LIMITED,CROSS_PAGE,RETURN_NULL,NORMAL,1,0,0,0),
    C("writable_handle_invalid_return_null",8,INVALID_HANDLE,WRITABLE,RETURN_NULL,NORMAL,1,0,0,0),
    C("writable_handle_limited_return_null",8,LIMITED,WRITABLE,RETURN_NULL,NORMAL,1,0,0,0),
    C("exact8_noaccess_return_length",8,CURRENT,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("exact8_boundary_return_prefix_1",8,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("exact8_boundary_return_prefix_2",8,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("exact8_boundary_return_prefix_3",8,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3),
    C("exact8_alias_return_plus_4",8,CURRENT,WRITABLE,RETURN_ALIAS,NORMAL,1,0,4,0),
    C("exact8_alias_return_plus_8",8,CURRENT,WRITABLE,RETURN_ALIAS,NORMAL,1,0,8,0),
    C("length0_reserved_return_length",0,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,0,0,0),
    C("length9_reserved_return_length",9,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,0,0,0),
    /* Schema 3: bounded precedence crosses; no expected statuses. */
    C("align1_length0_handle_current_return_valid",0,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,1,0,0),
    C("align1_length0_handle_current_return_reserved",0,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,1,0,0),
    C("align1_length0_handle_current_return_null",0,CURRENT,WRITABLE,RETURN_NULL,NORMAL,1,1,0,0),
    C("align1_length7_handle_current_return_valid",7,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,1,0,0),
    C("align1_length7_handle_current_return_reserved",7,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,1,0,0),
    C("align1_length7_handle_current_return_null",7,CURRENT,WRITABLE,RETURN_NULL,NORMAL,1,1,0,0),
    C("align1_length8_handle_current_return_reserved",8,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,1,0,0),
    C("align1_length8_handle_current_return_null",8,CURRENT,WRITABLE,RETURN_NULL,NORMAL,1,1,0,0),
    C("align1_length9_handle_current_return_valid",9,CURRENT,WRITABLE,RETURN_VALID,NORMAL,1,1,0,0),
    C("align1_length9_handle_current_return_reserved",9,CURRENT,WRITABLE,RETURN_RESERVED,NORMAL,1,1,0,0),
    C("align1_length9_handle_current_return_null",9,CURRENT,WRITABLE,RETURN_NULL,NORMAL,1,1,0,0),
    C("align1_length8_handle_invalid_return_valid",8,INVALID_HANDLE,WRITABLE,RETURN_VALID,NORMAL,1,1,0,0),
    C("align1_length8_handle_invalid_return_reserved",8,INVALID_HANDLE,WRITABLE,RETURN_RESERVED,NORMAL,1,1,0,0),
    C("align1_length8_handle_invalid_return_null",8,INVALID_HANDLE,WRITABLE,RETURN_NULL,NORMAL,1,1,0,0),
    C("align1_length8_handle_limited_return_valid",8,LIMITED,WRITABLE,RETURN_VALID,NORMAL,1,1,0,0),
    C("align1_length8_handle_limited_return_reserved",8,LIMITED,WRITABLE,RETURN_RESERVED,NORMAL,1,1,0,0),
    C("align1_length8_handle_limited_return_null",8,LIMITED,WRITABLE,RETURN_NULL,NORMAL,1,1,0,0),
    C("return_noaccess_length0_handle_current",0,CURRENT,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("return_noaccess_length0_handle_invalid",0,INVALID_HANDLE,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("return_noaccess_length7_handle_current",7,CURRENT,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("return_noaccess_length7_handle_invalid",7,INVALID_HANDLE,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("return_noaccess_length8_handle_invalid",8,INVALID_HANDLE,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("return_noaccess_length9_handle_current",9,CURRENT,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("return_noaccess_length9_handle_invalid",9,INVALID_HANDLE,WRITABLE,RETURN_NOACCESS,NORMAL,1,0,0,0),
    C("return_boundary1_length0_handle_current",0,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("return_boundary1_length0_handle_invalid",0,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("return_boundary1_length7_handle_current",7,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("return_boundary1_length7_handle_invalid",7,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("return_boundary1_length8_handle_invalid",8,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("return_boundary1_length9_handle_current",9,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("return_boundary1_length9_handle_invalid",9,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,1),
    C("return_boundary2_length0_handle_current",0,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("return_boundary2_length0_handle_invalid",0,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("return_boundary2_length7_handle_current",7,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("return_boundary2_length7_handle_invalid",7,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("return_boundary2_length8_handle_invalid",8,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("return_boundary2_length9_handle_current",9,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("return_boundary2_length9_handle_invalid",9,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,2),
    C("return_boundary3_length0_handle_current",0,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3),
    C("return_boundary3_length0_handle_invalid",0,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3),
    C("return_boundary3_length7_handle_current",7,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3),
    C("return_boundary3_length7_handle_invalid",7,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3),
    C("return_boundary3_length8_handle_invalid",8,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3),
    C("return_boundary3_length9_handle_current",9,CURRENT,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3),
    C("return_boundary3_length9_handle_invalid",9,INVALID_HANDLE,WRITABLE,RETURN_BOUNDARY,NORMAL,1,0,0,3)
};
#undef C

static HANDLE stop_event, ready_event;
static volatile LONG busy_worker;
static volatile unsigned long burn_sink;

static void burn(DWORD milliseconds)
{
    ULONGLONG end = GetTickCount64() + milliseconds;
    unsigned long x = 1;
    do { unsigned i; for (i = 0; i < 10000; ++i) x = x * 1664525u + 1013904223u; }
    while (GetTickCount64() < end);
    burn_sink = x;
}

static DWORD WINAPI worker(void *unused)
{
    (void)unused;
    SetEvent(ready_event);
    if (busy_worker) {
        while (WaitForSingleObject(stop_event, 0) == WAIT_TIMEOUT) burn(5);
    } else WaitForSingleObject(stop_event, INFINITE);
    return 0;
}

static void hex(const BYTE *p, size_t size)
{
    size_t i;
    for (i = 0; i < size; ++i) printf("%02x", (unsigned)p[i]);
}

static int setup_error(const char *stage)
{
    printf("{\"record\":\"setup_error\",\"stage\":\"%s\",\"win32_error\":%lu}\n",
           stage, GetLastError());
    return 2;
}

static int setup_wait_error(const char *stage, DWORD wait_result)
{
    DWORD error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
    printf("{\"record\":\"setup_error\",\"stage\":\"%s\",\"wait_result\":%lu,"
           "\"win32_error_valid\":%s,\"win32_error\":%lu}\n",
           stage, wait_result, wait_result == WAIT_FAILED ? "true" : "false", error);
    return 2;
}

static int run_case(const struct test_case *c)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    query_fn query;
    version_fn get_version;
    OSVERSIONINFOW version;
    SYSTEM_INFO si;
    HANDLE handle = GetCurrentThread(), owned_handle = NULL, thread = NULL;
    DWORD previous, wait_result, tid = 0;
    DECLSPEC_ALIGN(16) union { LARGE_INTEGER align; BYTE bytes[64]; } data_store, ret_store;
    BYTE *data_page = NULL, *ret_page = NULL, *data_snapshot = data_store.bytes;
    BYTE *ret_snapshot = ret_store.bytes;
    PVOID data;
    PULONG ret;
    ULONG sentinel = 0xdeadbeef, ret_value, class_value = 11;
    LONG status, version_status;
    BOOL wow64 = FALSE;
    BOOL wow64_ok;
    unsigned i;
    size_t data_offset = 16 + c->data_extra_offset, ret_offset = 16;

    if (!ntdll) return setup_error("GetModuleHandle_ntdll");
    query = (query_fn)GetProcAddress(ntdll, "NtQueryInformationThread");
    if (!query) return setup_error("resolve_NtQueryInformationThread");
    get_version = (version_fn)GetProcAddress(ntdll, "RtlGetVersion");
    if (!get_version) return setup_error("resolve_RtlGetVersion");
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    version_status = get_version(&version);
    GetNativeSystemInfo(&si);
    if (si.dwPageSize < 128 || c->data_extra_offset > 7 || c->alias_offset > 8 ||
        c->return_accessible_prefix > 3 ||
        (c->ret == RETURN_BOUNDARY && !c->return_accessible_prefix)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return setup_error("invalid_case_layout");
    }
    wow64_ok = IsWow64Process(GetCurrentProcess(), &wow64);
    printf("{\"record\":\"environment\",\"case\":\"%s\",\"pointer_bits\":%u,"
           "\"large_integer_size\":%u,\"ulong_size\":%u,\"os_major\":%lu,"
           "\"os_minor\":%lu,\"os_build\":%lu,\"version_status\":\"0x%08lx\","
           "\"native_processor_architecture\":%u,\"is_wow64_query_ok\":%s,"
           "\"is_wow64\":%s,\"wine_export_present\":%s,"
           "\"probe_schema\":3,\"page_size\":%lu,\"source_sha256\":\"%s\",\"build_target\":\"%s\"}\n",
           c->name, (unsigned)(8 * sizeof(void *)), (unsigned)sizeof(LARGE_INTEGER),
           (unsigned)sizeof(ULONG), version.dwMajorVersion, version.dwMinorVersion,
           version.dwBuildNumber, (ULONG)version_status, (unsigned)si.wProcessorArchitecture,
           wow64_ok ? "true" : "false", wow64 ? "true" : "false",
           GetProcAddress(ntdll, "wine_get_version") ? "true" : "false",
           si.dwPageSize, PROBE_SOURCE_SHA256, PROBE_BUILD_TARGET);

    if (c->handle >= QUERY && c->handle <= SYNC_ONLY) {
        DWORD access = c->handle == QUERY ? THREAD_QUERY_INFORMATION :
                       c->handle == LIMITED ? THREAD_QUERY_LIMITED_INFORMATION :
                       c->handle == SYNC_ONLY ? SYNCHRONIZE : 0;
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                             &owned_handle, access, FALSE, 0)) return setup_error("DuplicateHandle");
        handle = owned_handle;
    } else if (c->handle == NULL_HANDLE) handle = NULL;
    else if (c->handle == INVALID_HANDLE) handle = (HANDLE)(ULONG_PTR)0xdeadbeef;
    else if (c->handle == PROCESS_HANDLE) handle = GetCurrentProcess();
    else if (c->handle == EVENT_HANDLE) {
        owned_handle = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!owned_handle) return setup_error("CreateEvent_wrong_object");
        handle = owned_handle;
    } else if (c->handle >= WORKER_IDLE) {
        stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!stop_event) return setup_error("CreateEvent_worker_stop");
        ready_event = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!ready_event) return setup_error("CreateEvent_worker_ready");
        busy_worker = c->handle == WORKER_BUSY;
        thread = CreateThread(NULL, 0, worker, NULL,
                              c->handle == WORKER_SUSPENDED ? CREATE_SUSPENDED : 0, &tid);
        if (!thread) return setup_error("CreateThread");
        handle = thread;
        if (c->handle != WORKER_SUSPENDED) {
            wait_result = WaitForSingleObject(ready_event, 5000);
            if (wait_result != WAIT_OBJECT_0)
                return setup_wait_error("wait_worker_ready", wait_result);
        }
        if (c->handle == WORKER_BUSY) Sleep(50);
        if (c->handle == WORKER_EXITED) {
            if (!SetEvent(stop_event)) return setup_error("signal_worker_exit");
            wait_result = WaitForSingleObject(thread, 5000);
            if (wait_result != WAIT_OBJECT_0)
                return setup_wait_error("wait_worker_exit", wait_result);
        }
    }

    if (c->buffer >= READONLY_BUFFER) {
        data_page = (BYTE *)VirtualAlloc(NULL, 2 * si.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!data_page) return setup_error("VirtualAlloc_data");
        data_snapshot = c->buffer == CROSS_PAGE ? data_page + si.dwPageSize - 20 : data_page;
    }
    if (c->ret == RETURN_READONLY || c->ret == RETURN_NOACCESS || c->ret == RETURN_BOUNDARY) {
        ret_page = (BYTE *)VirtualAlloc(NULL, 2 * si.dwPageSize,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!ret_page) return setup_error("VirtualAlloc_return");
        ret_snapshot = c->ret == RETURN_BOUNDARY ?
            ret_page + si.dwPageSize - 16 - c->return_accessible_prefix : ret_page;
    } else if (c->ret == RETURN_RESERVED) {
        /* Owned address, deliberately not committed. Never read or write it
         * in this harness. Unlike schema 1 this is not the literal address 1. */
        ret_page = (BYTE *)VirtualAlloc(NULL, 2 * si.dwPageSize, MEM_RESERVE, PAGE_NOACCESS);
        if (!ret_page) return setup_error("VirtualAlloc_return_reserved");
    }
    if (c->buffer == UNALIGNED_BUFFER) data_offset++;
    if (c->ret == RETURN_UNALIGNED) ret_offset++;
    data = c->buffer == NULL_BUFFER ? NULL : data_snapshot + data_offset;
    ret = (PULONG)(ret_snapshot + ret_offset);
    if (c->ret == RETURN_NULL) ret = NULL;
    if (c->ret == RETURN_RESERVED) ret = (PULONG)(ret_page + 16);
    if (c->ret == RETURN_ALIAS) ret = (PULONG)((BYTE *)data + c->alias_offset);

    for (i = 0; i < c->repeat; ++i) {
        memset(data_snapshot, 0xa5, 64);
        memset(ret_snapshot, 0x5a, 64);
        memcpy(ret_snapshot + ret_offset, &sentinel, sizeof(sentinel));
        if (c->ret == RETURN_ALIAS) memcpy(ret, &sentinel, sizeof(sentinel));
        if (c->phase == AFTER_SLEEP) Sleep(50);
        if (c->phase == AFTER_BURN) burn(50);
        printf("{\"record\":\"call_begin\",\"case\":\"%s\",\"sample\":%u,"
               "\"class\":%lu,\"length\":%lu,\"handle_mode\":%u,\"buffer_mode\":%u,"
               "\"return_mode\":%u,\"phase\":%u,\"data_offset\":%u,\"return_offset\":%u,"
               "\"return_pointer_aliases_data\":%s,\"data_extra_offset\":%u,"
               "\"alias_offset\":%u,\"return_accessible_prefix\":%u,"
               "\"data_alignment_mod8\":%u,\"return_alignment_mod4\":%u,"
               "\"return_pointer_kind\":\"%s\",\"data_before\":\"", c->name, i, class_value, c->length,
               (unsigned)c->handle, (unsigned)c->buffer, (unsigned)c->ret,
               (unsigned)c->phase, (unsigned)data_offset, (unsigned)ret_offset,
               c->ret == RETURN_ALIAS ? "true" : "false", c->data_extra_offset,
               c->alias_offset, c->return_accessible_prefix,
               (unsigned)((ULONG_PTR)data % 8), (unsigned)((ULONG_PTR)ret % 4),
               c->ret == RETURN_RESERVED ? "owned_reserved_uncommitted" :
               c->ret == RETURN_NOACCESS ? "owned_committed_noaccess" :
               c->ret == RETURN_BOUNDARY ? "owned_page_boundary" :
               c->ret == RETURN_READONLY ? "owned_readonly" :
               c->ret == RETURN_NULL ? "null" :
               c->ret == RETURN_ALIAS ? "owned_data_offset" : "owned_writable");
        hex(data_snapshot, 64);
        printf("\",\"return_before\":\""); hex(ret_snapshot, 64); printf("\"}\n");
        if (data_page) {
            PVOID p = c->buffer == CROSS_PAGE ? data_page + si.dwPageSize : data_page;
            DWORD protect = c->buffer == READONLY_BUFFER ? PAGE_READONLY : PAGE_NOACCESS;
            if (!VirtualProtect(p, si.dwPageSize, protect, &previous)) return setup_error("protect_data");
        }
        if (ret_page && c->ret != RETURN_RESERVED) {
            PVOID p = c->ret == RETURN_BOUNDARY ? ret_page + si.dwPageSize : ret_page;
            DWORD protect = c->ret == RETURN_READONLY ? PAGE_READONLY : PAGE_NOACCESS;
            if (!VirtualProtect(p, si.dwPageSize, protect, &previous))
                return setup_error("protect_return");
        }
        fflush(stdout);
        /* No exception handler: run-cases.ps1 records an escaped exception as a process
         * exit, never as a returned NTSTATUS. No NtSetInformationThread is called. */
        status = query(handle, class_value, data, c->length, ret);
        printf("{\"record\":\"call_returned\",\"case\":\"%s\",\"sample\":%u,"
               "\"ntstatus\":\"0x%08lx\"}\n", c->name, i, (ULONG)status);
        fflush(stdout);
        if (data_page && !VirtualProtect(data_page, 2 * si.dwPageSize, PAGE_READWRITE, &previous))
            return setup_error("unprotect_data");
        if (ret_page && c->ret != RETURN_RESERVED &&
            !VirtualProtect(ret_page, 2 * si.dwPageSize, PAGE_READWRITE, &previous))
            return setup_error("unprotect_return");
        memcpy(&ret_value, ret_snapshot + ret_offset, sizeof(ret_value));
        printf("{\"record\":\"call_result\",\"case\":\"%s\",\"sample\":%u,"
               "\"ntstatus\":\"0x%08lx\",\"return_storage_value\":\"0x%08lx\","
               "\"return_pointer_value\":", c->name, i, (ULONG)status, ret_value);
        /* The separate storage is only a canary for NULL, invalid and alias
         * pointers. Report the actual destination too, without dereferencing
         * an invalid or NULL pointer or performing an unaligned C load. */
        if (c->ret == RETURN_NULL || c->ret == RETURN_RESERVED) printf("null");
        else {
            memcpy(&ret_value, ret, sizeof(ret_value));
            printf("\"0x%08lx\"", ret_value);
        }
        printf(",\"data_after\":\"");
        hex(data_snapshot, 64); printf("\",\"return_after\":\"");
        hex(ret_snapshot, 64); printf("\"}\n");
    }
    if (thread) {
        if (!SetEvent(stop_event)) return setup_error("cleanup_signal_worker");
        if (c->handle == WORKER_SUSPENDED && ResumeThread(thread) == (DWORD)-1)
            return setup_error("cleanup_resume_worker");
        wait_result = WaitForSingleObject(thread, 5000);
        if (wait_result != WAIT_OBJECT_0) return setup_wait_error("cleanup_worker", wait_result);
        CloseHandle(thread); CloseHandle(stop_event); CloseHandle(ready_event);
    }
    if (owned_handle) CloseHandle(owned_handle);
    if (data_page) VirtualFree(data_page, 0, MEM_RELEASE);
    if (ret_page) VirtualFree(ret_page, 0, MEM_RELEASE);
    return 0;
}

int main(int argc, char **argv)
{
    size_t i;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) puts(cases[i].name);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--case")) {
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
            if (!strcmp(argv[2], cases[i].name)) return run_case(&cases[i]);
    }
    fputs("Usage: thread-performance-count.exe --list | --case NAME\n", stderr);
    return 64;
}
