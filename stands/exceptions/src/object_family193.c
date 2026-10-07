/* SPDX-License-Identifier: MIT */
/* Synthetic Windows x64 object metadata contract. No game inputs. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef NTSTATUS (NTAPI *query_object_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct {
    ULONG Attributes, GrantedAccess, HandleCount, PointerCount;
    ULONG PagedPoolCharge, NonPagedPoolCharge, Reserved[3];
    ULONG NameInfoSize, TypeInfoSize, SecurityDescriptorSize;
    LARGE_INTEGER CreationTime;
} basic_info;
_Static_assert(sizeof(basic_info) == 56, "Windows x64 object basic ABI");
static query_object_fn query;
static unsigned failures, snapshots;

static void check(const char *type, unsigned named, const char *step, BOOL ok)
{
    DWORD error = GetLastError();
    printf("OBJECT193_OP type=%s named=%u step=%s ok=%u error=%08lx\n",
           type, named, step, !!ok, (unsigned long)error);
    if (!ok) ++failures;
}

static void snapshot(const char *type, unsigned named, const char *step, HANDLE handle)
{
    basic_info info;
    ULONG used = 0xa5a5a5a5u;
    DWORD flags = 0xa5a5a5a5u;
    memset(&info, 0xa5, sizeof(info));
    NTSTATUS status = query(handle, 0, &info, sizeof(info), &used);
    /* Query basic first: querying flags also consumes an object reference on
       Windows and must not silently alter the pointer-count input history. */
    SetLastError(0x51a7u);
    BOOL flags_ok = GetHandleInformation(handle, &flags);
    DWORD error = GetLastError();
    printf("OBJECT193_SNAP type=%s named=%u step=%s status=%08lx used=%lu flags_ok=%u flags=%08lx error=%08lx bytes=",
           type, named, step, (unsigned long)status, (unsigned long)used,
           !!flags_ok, (unsigned long)flags, (unsigned long)error);
    for (unsigned i = 0; i < sizeof(info); ++i) printf("%02x", ((unsigned char *)&info)[i]);
    putchar('\n');
    ++snapshots;
    if (handle != (HANDLE)(uintptr_t)0x0de42345 && status != 0) ++failures;
    if (handle == (HANDLE)(uintptr_t)0x0de42345 &&
        ((ULONG)status != 0xc0000008u || used != 0xa5a5a5a5u || flags_ok)) ++failures;
}

static HANDLE create_object(unsigned kind, const WCHAR *name)
{
    if (kind == 0) return CreateEventW(NULL, FALSE, FALSE, name);
    if (kind == 1) return CreateMutexW(NULL, FALSE, name);
    return CreateSemaphoreW(NULL, 0, 3, name);
}

static void family(unsigned kind, unsigned named)
{
    static const char *types[] = {"event", "mutex", "semaphore"};
    static const WCHAR *names[] = {L"MacRunner.OBJECT193.event", L"MacRunner.OBJECT193.mutex",
                                  L"MacRunner.OBJECT193.semaphore"};
    const char *type = types[kind];
    HANDLE handle, duplicate = NULL;
    SetLastError(0x51a7u);
    handle = create_object(kind, named ? names[kind] : NULL);
    DWORD error = GetLastError();
    check(type, named, "create", handle != NULL);
    if (!handle) return;
    if (named && error == ERROR_ALREADY_EXISTS)
    {
        ++failures;
        printf("OBJECT193_COLLISION type=%s named=%u\n", type, named);
        CloseHandle(handle);
        return;
    }
    snapshot(type, named, "created", handle);
    snapshot(type, named, "query-again", handle);
    check(type, named, "inherit-on", SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
    snapshot(type, named, "inherit", handle);
    check(type, named, "protect-on", SetHandleInformation(handle, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE));
    snapshot(type, named, "inherit-protect", handle);
    check(type, named, "duplicate", DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &duplicate,
          0, TRUE, DUPLICATE_SAME_ACCESS));
    if (duplicate)
    {
        snapshot(type, named, "two-original", handle);
        snapshot(type, named, "two-duplicate", duplicate);
        check(type, named, "duplicate-close", CloseHandle(duplicate));
        snapshot(type, named, "after-duplicate-close", handle);
    }
    check(type, named, "inherit-off", SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0));
    snapshot(type, named, "protect", handle);
    check(type, named, "protect-off", SetHandleInformation(handle, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0));
    snapshot(type, named, "flags-clear", handle);
    check(type, named, "close", CloseHandle(handle));
    snapshot("invalid", named, type, (HANDLE)(uintptr_t)0x0de42345);
}

int main(void)
{
    query = (query_object_fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (!query) return 2;
    printf("OBJECT193_BEGIN version=1 basic_bytes=%zu\n", sizeof(basic_info));
    fflush(stdout);
    Sleep(1000);
    for (unsigned kind = 0; kind < 3; ++kind)
        for (unsigned named = 0; named < 2; ++named) family(kind, named);
    if (snapshots != 60) ++failures;
    printf("OBJECT193_COMPLETE snapshots=%u failures=%u\n", snapshots, failures);
    return failures ? 1 : 0;
}
