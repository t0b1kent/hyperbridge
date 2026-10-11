/* Named own-object ABI compatibility fixture, source-only deliverable.
 * Exact Wine pin: a15ee2ccf20e2fc9f470badd916855801933d31f.
 * Explicit approved selectors only; no query payload is emitted.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define DATA_CAPACITY 8192u
#define CLASS_TIMEOUT_MS 15000u
#define WINE_PIN "a15ee2ccf20e2fc9f470badd916855801933d31f"
#define PENDING_STATUS ((NTSTATUS)0x00000103)

/* Private names preserve public layouts without colliding with SDK typedefs.
 * Exact pinned public header definitions and size evidence are in allowlist.json. */
typedef struct { PVOID BaseAddress; ULONG Attributes; LARGE_INTEGER Size; } COMPAT_SECTION_BASIC_INFORMATION;
typedef struct {
    PVOID TransferAddress; ULONG ZeroBits;
    SIZE_T MaximumStackSize, CommittedStackSize; ULONG SubSystemType;
    USHORT MinorSubsystemVersion, MajorSubsystemVersion;
    USHORT MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    USHORT ImageCharacteristics, DllCharacteristics, Machine;
    BOOLEAN ImageContainsCode; UCHAR ImageFlags;
    ULONG LoaderFlags, ImageFileSize, CheckSum;
} COMPAT_SECTION_IMAGE_INFORMATION;
typedef struct { ULONG EventType; LONG EventState; } COMPAT_EVENT_BASIC_INFORMATION;
typedef struct { LONG CurrentCount; BOOLEAN OwnedByCaller, AbandonedState; } COMPAT_MUTANT_BASIC_INFORMATION;
typedef struct { ULONG CurrentCount, MaximumCount; } COMPAT_SEMAPHORE_BASIC_INFORMATION;
typedef struct { ULONG Flags; } COMPAT_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION;
typedef struct { ULONGLONG VolumeSerialNumber; UCHAR FileId[16]; } COMPAT_FILE_ID_INFORMATION;
typedef struct {
    LARGE_INTEGER FileId, CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
    LARGE_INTEGER AllocationSize, EndOfFile;
    ULONG FileAttributes, ReparseTag, NumberOfLinks, EffectiveAccess;
} COMPAT_FILE_STAT_INFORMATION;
typedef struct {
    ULONGLONG ActualTotalAllocationUnits, ActualAvailableAllocationUnits, ActualPoolUnavailableAllocationUnits;
    ULONGLONG CallerTotalAllocationUnits, CallerAvailableAllocationUnits, CallerPoolUnavailableAllocationUnits;
    ULONGLONG UsedAllocationUnits, TotalReservedAllocationUnits, VolumeStorageReserveAllocationUnits;
    ULONGLONG AvailableCommittedAllocationUnits, PoolAvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit, BytesPerSector;
} COMPAT_FILE_FS_FULL_SIZE_INFORMATION_EX;
_Static_assert(sizeof(ULONG) == 4, "ULONG ABI");
_Static_assert(sizeof(SIZE_T) == sizeof(void *), "SIZE_T ABI");
_Static_assert(sizeof(IO_STATUS_BLOCK) == 2 * sizeof(void *), "IOSB ABI");
_Static_assert(offsetof(IO_STATUS_BLOCK, Information) == sizeof(void *), "IOSB Information offset");
_Static_assert(sizeof(TOKEN_USER) == (sizeof(void *) == 8 ? 16 : 8), "TOKEN_USER reference ABI");
_Static_assert(offsetof(TOKEN_GROUPS, Groups) == (sizeof(void *) == 8 ? 8 : 4), "TOKEN_GROUPS reference ABI");
_Static_assert(offsetof(TOKEN_PRIVILEGES, Privileges) == 4, "TOKEN_PRIVILEGES reference ABI");
_Static_assert(sizeof(TOKEN_OWNER) == (sizeof(void *) == 8 ? 8 : 4), "TOKEN_OWNER reference ABI");
_Static_assert(sizeof(TOKEN_PRIMARY_GROUP) == (sizeof(void *) == 8 ? 8 : 4), "TOKEN_PRIMARY_GROUP reference ABI");
_Static_assert(sizeof(TOKEN_DEFAULT_DACL) == (sizeof(void *) == 8 ? 8 : 4), "TOKEN_DEFAULT_DACL reference ABI");
_Static_assert(sizeof(TOKEN_TYPE) == 4, "TOKEN_TYPE reference ABI");
_Static_assert(sizeof(SECURITY_IMPERSONATION_LEVEL) == 4, "SECURITY_IMPERSONATION_LEVEL reference ABI");
_Static_assert(sizeof(TOKEN_STATISTICS) == 56, "TOKEN_STATISTICS reference ABI");
_Static_assert(sizeof(TOKEN_ELEVATION_TYPE) == 4, "TOKEN_ELEVATION_TYPE reference ABI");
_Static_assert(sizeof(TOKEN_ELEVATION) == 4, "TOKEN_ELEVATION reference ABI");
_Static_assert(sizeof(TOKEN_MANDATORY_LABEL) == (sizeof(void *) == 8 ? 16 : 8), "TOKEN_MANDATORY_LABEL reference ABI");
_Static_assert(sizeof(DWORD) == 4, "DWORD reference ABI");
_Static_assert(sizeof(COMPAT_SECTION_BASIC_INFORMATION) == (sizeof(void *) == 8 ? 24 : 16), "SECTION_BASIC_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_SECTION_IMAGE_INFORMATION) == (sizeof(void *) == 8 ? 64 : 48), "SECTION_IMAGE_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_EVENT_BASIC_INFORMATION) == 8, "EVENT_BASIC_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_MUTANT_BASIC_INFORMATION) == 8, "MUTANT_BASIC_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_SEMAPHORE_BASIC_INFORMATION) == 8, "SEMAPHORE_BASIC_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_BASIC_INFORMATION) == 40, "FILE_BASIC_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_STANDARD_INFORMATION) == 24, "FILE_STANDARD_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_INTERNAL_INFORMATION) == 8, "FILE_INTERNAL_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_ACCESS_INFORMATION) == 4, "FILE_ACCESS_INFORMATION reference ABI");
_Static_assert(offsetof(FILE_NAME_INFORMATION, FileName) == 4, "FILE_NAME_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_MODE_INFORMATION) == 4, "FILE_MODE_INFORMATION reference ABI");
_Static_assert(offsetof(FILE_ALL_INFORMATION, NameInformation.FileName) == 100, "FILE_ALL_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_ATTRIBUTE_TAG_INFORMATION) == 8, "FILE_ATTRIBUTE_TAG_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION) == 4, "FILE_IO_COMPLETION_NOTIFICATION_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_FILE_ID_INFORMATION) == 24, "FILE_ID_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_FILE_STAT_INFORMATION) == 72, "FILE_STAT_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_FS_SIZE_INFORMATION) == 24, "FILE_FS_SIZE_INFORMATION reference ABI");
_Static_assert(sizeof(FILE_FS_FULL_SIZE_INFORMATION) == 32, "FILE_FS_FULL_SIZE_INFORMATION reference ABI");
_Static_assert(sizeof(COMPAT_FILE_FS_FULL_SIZE_INFORMATION_EX) == 96, "FILE_FS_FULL_SIZE_INFORMATION_EX reference ABI");

_Static_assert(sizeof(FILE_NAME_INFORMATION) == 8, "FILE_NAME one-element layout");
_Static_assert(sizeof(FILE_ALL_INFORMATION) == 104, "FILE_ALL one-element layout");
typedef NTSTATUS (NTAPI *query32_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *section_fn)(HANDLE, ULONG, PVOID, SIZE_T, SIZE_T *);
typedef NTSTATUS (NTAPI *file_fn)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *version_fn)(PRTL_OSVERSIONINFOW);
enum api_kind { API_TOKEN, API_SECTION, API_EVENT, API_MUTANT, API_SEMAPHORE, API_FILE, API_VOLUME, API_COUNT };
enum length_kind { LENGTH_FIXED, VARIABLE, SENTINEL };
enum handle_kind { OWN_TOKEN, OWN_SECTION, SECTION_READ_ONLY, OWN_EVENT, OWN_MUTANT, OWN_SEMAPHORE,
                   OWN_FILE, FILE_WRITE_DELETE, FILE_WRITE_DELETE_SYNC, INVALID_DEADBEEF };
enum return_kind { RETURN_VALID, RETURN_NULL, RETURN_NONE };
struct variant { enum handle_kind handle; enum return_kind ret; };
struct query_desc {
    const char *name; enum api_kind api; ULONG info_class; enum length_kind kind;
    const char *layout; ULONG size, capacity; struct variant variants[4]; unsigned variant_count;
};
/* No numeric ranges or command-line class numbers: every allowed group is explicit. */
static const struct query_desc queries[] = {
    {"TokenUser", API_TOKEN, 0x00000001u, VARIABLE, "TOKEN_USER", sizeof(TOKEN_USER), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenGroups", API_TOKEN, 0x00000002u, VARIABLE, "TOKEN_GROUPS", offsetof(TOKEN_GROUPS, Groups), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenPrivileges", API_TOKEN, 0x00000003u, VARIABLE, "TOKEN_PRIVILEGES", offsetof(TOKEN_PRIVILEGES, Privileges), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenOwner", API_TOKEN, 0x00000004u, VARIABLE, "TOKEN_OWNER", sizeof(TOKEN_OWNER), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenPrimaryGroup", API_TOKEN, 0x00000005u, VARIABLE, "TOKEN_PRIMARY_GROUP", sizeof(TOKEN_PRIMARY_GROUP), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenDefaultDacl", API_TOKEN, 0x00000006u, VARIABLE, "TOKEN_DEFAULT_DACL", sizeof(TOKEN_DEFAULT_DACL), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenType", API_TOKEN, 0x00000008u, LENGTH_FIXED, "TOKEN_TYPE", sizeof(TOKEN_TYPE), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenImpersonationLevel", API_TOKEN, 0x00000009u, LENGTH_FIXED, "SECURITY_IMPERSONATION_LEVEL", sizeof(SECURITY_IMPERSONATION_LEVEL), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenStatistics", API_TOKEN, 0x0000000au, LENGTH_FIXED, "TOKEN_STATISTICS", sizeof(TOKEN_STATISTICS), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenElevationType", API_TOKEN, 0x00000012u, LENGTH_FIXED, "TOKEN_ELEVATION_TYPE", sizeof(TOKEN_ELEVATION_TYPE), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenElevation", API_TOKEN, 0x00000014u, LENGTH_FIXED, "TOKEN_ELEVATION", sizeof(TOKEN_ELEVATION), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenIntegrityLevel", API_TOKEN, 0x00000019u, VARIABLE, "TOKEN_MANDATORY_LABEL", sizeof(TOKEN_MANDATORY_LABEL), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenLogonSid", API_TOKEN, 0x0000001cu, VARIABLE, "TOKEN_GROUPS", offsetof(TOKEN_GROUPS, Groups), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenIsAppContainer", API_TOKEN, 0x0000001du, LENGTH_FIXED, "DWORD", sizeof(DWORD), 4096u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"SectionBasicInformation", API_SECTION, 0x00000000u, LENGTH_FIXED, "SECTION_BASIC_INFORMATION", sizeof(COMPAT_SECTION_BASIC_INFORMATION), 4096u, {{OWN_SECTION, RETURN_VALID}, {OWN_SECTION, RETURN_NULL}, {SECTION_READ_ONLY, RETURN_VALID}}, 3u},
    {"SectionImageInformation", API_SECTION, 0x00000001u, LENGTH_FIXED, "SECTION_IMAGE_INFORMATION", sizeof(COMPAT_SECTION_IMAGE_INFORMATION), 4096u, {{OWN_SECTION, RETURN_NULL}}, 1u},
    {"EventBasicInformation", API_EVENT, 0x00000000u, LENGTH_FIXED, "EVENT_BASIC_INFORMATION", sizeof(COMPAT_EVENT_BASIC_INFORMATION), 4096u, {{OWN_EVENT, RETURN_NULL}}, 1u},
    {"MutantBasicInformation", API_MUTANT, 0x00000000u, LENGTH_FIXED, "MUTANT_BASIC_INFORMATION", sizeof(COMPAT_MUTANT_BASIC_INFORMATION), 4096u, {{OWN_MUTANT, RETURN_VALID}, {OWN_MUTANT, RETURN_NULL}, {INVALID_DEADBEEF, RETURN_NULL}}, 3u},
    {"SemaphoreBasicInformation", API_SEMAPHORE, 0x00000000u, LENGTH_FIXED, "SEMAPHORE_BASIC_INFORMATION", sizeof(COMPAT_SEMAPHORE_BASIC_INFORMATION), 4096u, {{OWN_SEMAPHORE, RETURN_VALID}, {OWN_SEMAPHORE, RETURN_NULL}, {INVALID_DEADBEEF, RETURN_NULL}}, 3u},
    {"FileBasicInformation", API_FILE, 0x00000004u, LENGTH_FIXED, "FILE_BASIC_INFORMATION", sizeof(FILE_BASIC_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileStandardInformation", API_FILE, 0x00000005u, LENGTH_FIXED, "FILE_STANDARD_INFORMATION", sizeof(FILE_STANDARD_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}, {FILE_WRITE_DELETE, RETURN_NONE}}, 2u},
    {"FileInternalInformation", API_FILE, 0x00000006u, LENGTH_FIXED, "FILE_INTERNAL_INFORMATION", sizeof(FILE_INTERNAL_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileAccessInformation", API_FILE, 0x00000008u, LENGTH_FIXED, "FILE_ACCESS_INFORMATION", sizeof(FILE_ACCESS_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}, {INVALID_DEADBEEF, RETURN_NONE}, {FILE_WRITE_DELETE, RETURN_NONE}}, 3u},
    {"FileNameInformation", API_FILE, 0x00000009u, VARIABLE, "FILE_NAME_INFORMATION", offsetof(FILE_NAME_INFORMATION, FileName), 4096u, {{OWN_FILE, RETURN_NONE}, {FILE_WRITE_DELETE, RETURN_NONE}}, 2u},
    {"FileModeInformation", API_FILE, 0x00000010u, LENGTH_FIXED, "FILE_MODE_INFORMATION", sizeof(FILE_MODE_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}, {FILE_WRITE_DELETE_SYNC, RETURN_NONE}}, 2u},
    {"FileAllInformation", API_FILE, 0x00000012u, VARIABLE, "FILE_ALL_INFORMATION", offsetof(FILE_ALL_INFORMATION, NameInformation.FileName), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileAttributeTagInformation", API_FILE, 0x00000023u, LENGTH_FIXED, "FILE_ATTRIBUTE_TAG_INFORMATION", sizeof(FILE_ATTRIBUTE_TAG_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}, {INVALID_DEADBEEF, RETURN_NONE}}, 2u},
    {"FileIoCompletionNotificationInformation", API_FILE, 0x00000029u, LENGTH_FIXED, "FILE_IO_COMPLETION_NOTIFICATION_INFORMATION", sizeof(COMPAT_FILE_IO_COMPLETION_NOTIFICATION_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}, {FILE_WRITE_DELETE, RETURN_NONE}}, 2u},
    {"FileIdInformation", API_FILE, 0x0000003bu, LENGTH_FIXED, "FILE_ID_INFORMATION", sizeof(COMPAT_FILE_ID_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileStatInformation", API_FILE, 0x00000044u, LENGTH_FIXED, "FILE_STAT_INFORMATION", sizeof(COMPAT_FILE_STAT_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileFsSizeInformation", API_VOLUME, 0x00000003u, LENGTH_FIXED, "FILE_FS_SIZE_INFORMATION", sizeof(FILE_FS_SIZE_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileFsFullSizeInformation", API_VOLUME, 0x00000007u, LENGTH_FIXED, "FILE_FS_FULL_SIZE_INFORMATION", sizeof(FILE_FS_FULL_SIZE_INFORMATION), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileFsFullSizeInformationEx", API_VOLUME, 0x0000000eu, LENGTH_FIXED, "FILE_FS_FULL_SIZE_INFORMATION_EX", sizeof(COMPAT_FILE_FS_FULL_SIZE_INFORMATION_EX), 4096u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"TokenSentinel_minus_one", API_TOKEN, 0xffffffffu, SENTINEL, "none", 0, 0u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"TokenSentinel_int_max", API_TOKEN, 0x7fffffffu, SENTINEL, "none", 0, 0u, {{OWN_TOKEN, RETURN_VALID}}, 1u},
    {"SectionSentinel_minus_one", API_SECTION, 0xffffffffu, SENTINEL, "none", 0, 0u, {{OWN_SECTION, RETURN_VALID}, {OWN_SECTION, RETURN_NULL}}, 2u},
    {"SectionSentinel_int_max", API_SECTION, 0x7fffffffu, SENTINEL, "none", 0, 0u, {{OWN_SECTION, RETURN_VALID}, {OWN_SECTION, RETURN_NULL}}, 2u},
    {"EventSentinel_minus_one", API_EVENT, 0xffffffffu, SENTINEL, "none", 0, 0u, {{OWN_EVENT, RETURN_NULL}}, 1u},
    {"EventSentinel_int_max", API_EVENT, 0x7fffffffu, SENTINEL, "none", 0, 0u, {{OWN_EVENT, RETURN_NULL}}, 1u},
    {"MutantSentinel_minus_one", API_MUTANT, 0xffffffffu, SENTINEL, "none", 0, 0u, {{OWN_MUTANT, RETURN_VALID}, {OWN_MUTANT, RETURN_NULL}}, 2u},
    {"MutantSentinel_int_max", API_MUTANT, 0x7fffffffu, SENTINEL, "none", 0, 0u, {{OWN_MUTANT, RETURN_VALID}, {OWN_MUTANT, RETURN_NULL}}, 2u},
    {"SemaphoreSentinel_minus_one", API_SEMAPHORE, 0xffffffffu, SENTINEL, "none", 0, 0u, {{OWN_SEMAPHORE, RETURN_VALID}, {OWN_SEMAPHORE, RETURN_NULL}}, 2u},
    {"SemaphoreSentinel_int_max", API_SEMAPHORE, 0x7fffffffu, SENTINEL, "none", 0, 0u, {{OWN_SEMAPHORE, RETURN_VALID}, {OWN_SEMAPHORE, RETURN_NULL}}, 2u},
    {"FileSentinel_minus_one", API_FILE, 0xffffffffu, SENTINEL, "none", 0, 0u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"FileSentinel_int_max", API_FILE, 0x7fffffffu, SENTINEL, "none", 0, 0u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"VolumeSentinel_minus_one", API_VOLUME, 0xffffffffu, SENTINEL, "none", 0, 0u, {{OWN_FILE, RETURN_NONE}}, 1u},
    {"VolumeSentinel_int_max", API_VOLUME, 0x7fffffffu, SENTINEL, "none", 0, 0u, {{OWN_FILE, RETURN_NONE}}, 1u},
};

struct case_spec { unsigned id; const char *layout, *length_label; ULONG reference_size, length; enum handle_kind handle; enum return_kind ret; };
struct resources { HANDLE owned, limited; DWORD owned_error, limited_error; };
static HANDLE output_handle;
static const struct query_desc *active_query;
static struct case_spec active_case;
static BOOL case_active;
static unsigned group_index;
static char pattern;
static _Alignas(16) unsigned char data_buffer[DATA_CAPACITY];
static ULONG return_u32;
static SIZE_T return_size;
static _Alignas(16) IO_STATUS_BLOCK iosb;
static query32_fn query32[API_COUNT];
static section_fn query_section;
static file_fn query_file, query_volume;

static const char *api_name(enum api_kind kind)
{
    static const char *names[] = {"NtQueryInformationToken", "NtQuerySection", "NtQueryEvent", "NtQueryMutant",
        "NtQuerySemaphore", "NtQueryInformationFile", "NtQueryVolumeInformationFile"};
    return names[kind];
}
static BOOL is_io(enum api_kind kind) { return kind == API_FILE || kind == API_VOLUME; }
static const char *metadata_kind(enum api_kind kind)
{ return is_io(kind) ? "io_status_block" : kind == API_SECTION ? "size_t_return_length" : "ulong_return_length"; }
static unsigned return_width(enum api_kind kind)
{ return is_io(kind) ? 0 : kind == API_SECTION ? (unsigned)sizeof(SIZE_T) : (unsigned)sizeof(ULONG); }
static const char *handle_name(enum handle_kind kind)
{
    static const char *names[] = {"owned_process_token_QUERY", "owned_anonymous_pagefile_section_QUERY_MAP_READ",
        "owned_anonymous_pagefile_section_MAP_READ", "owned_event", "owned_mutant", "owned_semaphore",
        "owned_temporary_file", "owned_temporary_file_WRITE_DELETE", "owned_temporary_file_WRITE_DELETE_SYNCHRONIZE",
        "invalid_0xdeadbeef"};
    return names[kind];
}
static const char *access_mask(enum handle_kind kind)
{
    static const char *masks[] = {"\"0x00000008\"", "\"0x00000005\"", "\"0x00000004\"",
        "\"0x001f0003\"", "\"0x001f0001\"", "\"0x001f0003\"", "\"0xc0010000\"",
        "\"0x00130116\"", "\"0x00130116\"", "null"};
    return masks[kind];
}
static const char *return_name(enum return_kind kind)
{ return kind == RETURN_VALID ? "valid_aligned" : kind == RETURN_NULL ? "NULL" : "not_applicable"; }
static void emit(const char *fmt, ...)
{
    char line[4096]; DWORD written; int size; va_list args;
    va_start(args, fmt); size = vsnprintf(line, sizeof(line), fmt, args); va_end(args);
    if (size < 0 || (size_t)size >= sizeof(line) ||
        !WriteFile(output_handle, line, (DWORD)size, &written, NULL) || written != (DWORD)size) ExitProcess(11);
    if (!FlushFileBuffers(output_handle)) ExitProcess(12);
}
static unsigned char initial_byte(unsigned i)
{ unsigned char value = (unsigned char)(0x29u + 37u * i); return pattern == 'A' ? value : (unsigned char)~value; }
static ULONG initial_u32(ULONG value) { return pattern == 'A' ? value : ~value; }
static uint64_t initial_u64(uint64_t value) { return pattern == 'A' ? value : ~value; }
static ULONG initial_return_u32(void) { return initial_u32(0xa1b2c3d4u); }
static SIZE_T initial_return_size(void)
{ return sizeof(SIZE_T) == 8 ? (SIZE_T)initial_u64(UINT64_C(0xa1b2c3d4e5f60718)) : initial_return_u32(); }
static void initialize_iosb(IO_STATUS_BLOCK *io)
{
    memset(io, pattern == 'A' ? 0xa6 : 0x59, sizeof(*io));
    io->Status = (NTSTATUS)initial_u32(0xc1d2e3f4u);
    io->Information = sizeof(ULONG_PTR) == 8 ? (ULONG_PTR)initial_u64(UINT64_C(0x91a2b3c4d5e6f708)) : (ULONG_PTR)initial_u32(0xd5e6f708u);
}
static unsigned changed_bytes(const void *after, const void *before, size_t count)
{
    const unsigned char *a = after, *b = before; unsigned changed = 0; size_t i;
    for (i = 0; i < count; ++i) if (a[i] != b[i]) ++changed;
    return changed;
}
static void hex_text(char *target, size_t capacity, uint64_t value, unsigned bytes)
{ snprintf(target, capacity, "\"0x%0*llx\"", (int)(bytes * 2), (unsigned long long)value); }
static void count_text(char *target, size_t capacity, unsigned value)
{ snprintf(target, capacity, "%u", value); }
static void emit_case_begin(BOOL will_execute)
{
    emit("{\"record\":\"case_begin\",\"group\":%u,\"case\":%u,\"pattern\":\"%c\","
         "\"name\":\"%s\",\"api\":\"%s\",\"class\":%lu,\"length\":%lu,"
         "\"handle\":\"%s\",\"handle_access_mask\":%s,\"metadata_kind\":\"%s\","
         "\"return_length_mode\":\"%s\",\"query_will_execute\":%s}\n",
         group_index, active_case.id, pattern, active_query->name, api_name(active_query->api),
         (unsigned long)active_query->info_class, (unsigned long)active_case.length,
         handle_name(active_case.handle), access_mask(active_case.handle), metadata_kind(active_query->api),
         return_name(active_case.ret), will_execute ? "true" : "false");
}
static void emit_case(const char *outcome, BOOL has_status, DWORD status, DWORD exception, DWORD error, BOOL snapshot)
{
    char st[32] = "null", ex[32] = "null", rv[32] = "null", rc[32] = "null";
    char iv[32] = "null", ic[32] = "null", sv[32] = "null", sc[32] = "null", tc[32] = "null";
    char dc[32] = "null", ac[32] = "null";
    unsigned changed = 0, after = 0, i, rw = return_width(active_query->api);
    BOOL io = is_io(active_query->api);
    if (has_status) hex_text(st, sizeof(st), status, 4);
    if (exception) hex_text(ex, sizeof(ex), exception, 4);
    /* A pending kernel operation may still mutate buffers. No read occurs here. */
    if (snapshot)
    {
        for (i = 0; i < DATA_CAPACITY; ++i) if (data_buffer[i] != initial_byte(i))
        { ++changed; if (i >= active_case.length) ++after; }
        count_text(dc, sizeof(dc), changed); count_text(ac, sizeof(ac), after);
        if (active_case.ret == RETURN_VALID)
        {
            if (active_query->api == API_SECTION)
            {
                SIZE_T initial = initial_return_size();
                hex_text(rv, sizeof(rv), (uint64_t)return_size, rw);
                count_text(rc, sizeof(rc), changed_bytes(&return_size, &initial, sizeof(initial)));
            }
            else
            {
                ULONG initial = initial_return_u32();
                hex_text(rv, sizeof(rv), return_u32, rw);
                count_text(rc, sizeof(rc), changed_bytes(&return_u32, &initial, sizeof(initial)));
            }
        }
        if (io)
        {
            IO_STATUS_BLOCK initial; initialize_iosb(&initial);
            hex_text(sv, sizeof(sv), (ULONG)iosb.Status, 4);
            count_text(sc, sizeof(sc), changed_bytes(&iosb.Status, &initial.Status, sizeof(iosb.Status)));
            hex_text(iv, sizeof(iv), (uint64_t)iosb.Information, sizeof(iosb.Information));
            count_text(ic, sizeof(ic), changed_bytes(&iosb.Information, &initial.Information, sizeof(iosb.Information)));
            count_text(tc, sizeof(tc), changed_bytes(&iosb, &initial, sizeof(iosb)));
        }
    }
    emit("{\"record\":\"case_result\",\"group\":%u,\"case\":%u,\"pattern\":\"%c\","
         "\"name\":\"%s\",\"api\":\"%s\",\"class\":%lu,\"layout\":\"%s\","
         "\"length_label\":\"%s\",\"reference_size\":%lu,\"length\":%lu,\"handle\":\"%s\","
         "\"handle_access_mask\":%s,\"metadata_kind\":\"%s\",\"return_length_mode\":\"%s\","
         "\"outcome\":\"%s\",\"status\":%s,\"exception\":%s,\"setup_error\":%lu,\"snapshot_state\":\"%s\","
         "\"return_length_width\":%u,\"return_length_value\":%s,\"return_length_changed_bytes\":%s,"
         "\"iosb_size\":%u,\"iosb_status_value\":%s,\"iosb_status_changed_bytes\":%s,"
         "\"iosb_information_width\":%u,\"iosb_information_value\":%s,\"iosb_information_changed_bytes\":%s,"
         "\"iosb_changed_bytes\":%s,\"data_changed_bytes\":%s,\"data_changed_after_requested_length\":%s,\"data_capacity\":%u}\n",
         group_index, active_case.id, pattern, active_query->name, api_name(active_query->api),
         (unsigned long)active_query->info_class, active_case.layout, active_case.length_label,
         (unsigned long)active_case.reference_size, (unsigned long)active_case.length,
         handle_name(active_case.handle), access_mask(active_case.handle), metadata_kind(active_query->api), return_name(active_case.ret),
         outcome, st, ex, (unsigned long)error, snapshot ? "observed" : "unavailable_pending", rw, rv, rc,
         io ? (unsigned)sizeof(iosb) : 0, sv, sc, io ? (unsigned)sizeof(iosb.Information) : 0, iv, ic, tc, dc, ac, DATA_CAPACITY);
}
static LONG CALLBACK exception_handler(EXCEPTION_POINTERS *exception)
{
    DWORD code = exception->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_IN_PAGE_ERROR &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION && code != EXCEPTION_DATATYPE_MISALIGNMENT) return EXCEPTION_CONTINUE_SEARCH;
    if (case_active) emit_case("exception", FALSE, 0, code, 0, TRUE);
    ExitProcess(code);
}
static BOOL load_function(enum api_kind api)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC address = GetProcAddress(ntdll, api_name(api));
    if (api == API_SECTION) query_section = (section_fn)(void *)address;
    else if (api == API_FILE) query_file = (file_fn)(void *)address;
    else if (api == API_VOLUME) query_volume = (file_fn)(void *)address;
    else query32[api] = (query32_fn)(void *)address;
    return address != NULL;
}
static BOOL wants_limited(const struct query_desc *q, enum handle_kind *kind)
{
    unsigned i;
    for (i = 0; i < q->variant_count; ++i)
        if (q->variants[i].handle == SECTION_READ_ONLY || q->variants[i].handle == FILE_WRITE_DELETE || q->variants[i].handle == FILE_WRITE_DELETE_SYNC)
        { *kind = q->variants[i].handle; return TRUE; }
    return FALSE;
}
static void init_resources(struct resources *r, const struct query_desc *q)
{
    enum handle_kind limited_kind = SECTION_READ_ONLY;
    BOOL limited = wants_limited(q, &limited_kind);
    memset(r, 0, sizeof(*r));
    switch (q->api)
    {
    case API_TOKEN:
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &r->owned)) r->owned_error = GetLastError();
        break;
    case API_SECTION:
    {
        HANDLE original = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 16384, NULL);
        if (!original) r->owned_error = GetLastError();
        else
        {
            if (!DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &r->owned, 0x00000005, FALSE, 0)) r->owned_error = GetLastError();
            CloseHandle(original);
        }
        if (limited)
        {
            if (!r->owned) r->limited_error = r->owned_error;
            else if (!DuplicateHandle(GetCurrentProcess(), r->owned, GetCurrentProcess(), &r->limited, 0x00000004, FALSE, 0)) r->limited_error = GetLastError();
        }
        break;
    }
    case API_EVENT: r->owned = CreateEventW(NULL, TRUE, FALSE, NULL); if (!r->owned) r->owned_error = GetLastError(); break;
    case API_MUTANT: r->owned = CreateMutexW(NULL, TRUE, NULL); if (!r->owned) r->owned_error = GetLastError(); break;
    case API_SEMAPHORE: r->owned = CreateSemaphoreW(NULL, 1, 2, NULL); if (!r->owned) r->owned_error = GetLastError(); break;
    case API_FILE:
    case API_VOLUME:
    {
        wchar_t directory[MAX_PATH], filename[MAX_PATH], drive_root[4];
        DWORD length = GetTempPathW(COUNT(directory), directory);
        UINT drive_type = DRIVE_UNKNOWN;
        if (!length || length + 64 >= COUNT(directory)) r->owned_error = ERROR_INSUFFICIENT_BUFFER;
        else if (!((directory[0] >= L'A' && directory[0] <= L'Z') || (directory[0] >= L'a' && directory[0] <= L'z')) || directory[1] != L':' || directory[2] != L'\\')
            r->owned_error = ERROR_BAD_PATHNAME;
        else
        {
            drive_root[0] = directory[0]; drive_root[1] = L':'; drive_root[2] = L'\\'; drive_root[3] = 0;
            drive_type = GetDriveTypeW(drive_root);
            if (drive_type != DRIVE_FIXED && drive_type != DRIVE_RAMDISK) r->owned_error = ERROR_NOT_SUPPORTED;
            else if (swprintf(filename, COUNT(filename), L"%lsnob_%08lx_%02u_%08lx.tmp", directory,
                GetCurrentProcessId(), group_index, GetTickCount()) < 0) r->owned_error = ERROR_FILENAME_EXCED_RANGE;
            else
            {
                /* One atomic attempt: an existing name is never opened or deleted. */
                r->owned = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE | DELETE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
                if (r->owned == INVALID_HANDLE_VALUE) { r->owned_error = GetLastError(); r->owned = NULL; }
                else if (limited)
                {
                    /* Mapped GENERIC_WRITE|DELETE = 0x00130116; includes SYNCHRONIZE.
                     * Source test requested 0x40010000 or 0x40110000 before mapping. */
                    if (!DuplicateHandle(GetCurrentProcess(), r->owned, GetCurrentProcess(), &r->limited,
                        FILE_GENERIC_WRITE | DELETE, FALSE, 0)) r->limited_error = GetLastError();
                }
            }
        }
        if (limited && !r->owned) r->limited_error = r->owned_error;
        break;
    }
    case API_COUNT: r->owned_error = ERROR_INVALID_PARAMETER; break;
    }
    if (!r->owned && !r->owned_error) r->owned_error = ERROR_GEN_FAILURE;
    if (limited && !r->limited && !r->limited_error) r->limited_error = ERROR_GEN_FAILURE;
}
static void close_resources(struct resources *r)
{ if (r->limited) CloseHandle(r->limited); if (r->owned) CloseHandle(r->owned); }
static HANDLE select_handle(struct resources *r, enum handle_kind kind, DWORD *error)
{
    *error = 0;
    if (kind == INVALID_DEADBEEF) return (HANDLE)(ULONG_PTR)0xdeadbeefu;
    if (kind == SECTION_READ_ONLY || kind == FILE_WRITE_DELETE || kind == FILE_WRITE_DELETE_SYNC)
    { *error = r->limited_error; return r->limited; }
    *error = r->owned_error; return r->owned;
}
static unsigned make_cases(const struct query_desc *q, struct case_spec *cases)
{
    unsigned li, vi, count = 0, nl = q->kind == SENTINEL ? 1 : 5;
    ULONG lengths[5] = {0, q->size ? q->size - 1 : 0, q->size, q->size + 1, q->capacity};
    static const char *fixed_labels[] = {"zero", "N_minus_1", "N", "N_plus_1", "large"};
    static const char *variable_labels[] = {"zero", "header_minus_1", "header", "header_plus_1", "bounded_capacity"};
    const char **labels = q->kind == VARIABLE ? variable_labels : fixed_labels;
    for (li = 0; li < nl; ++li) for (vi = 0; vi < q->variant_count; ++vi)
    {
        cases[count] = (struct case_spec){count, q->layout, labels[li], q->size, lengths[li], q->variants[vi].handle, q->variants[vi].ret};
        ++count;
    }
    return count;
}
static NTSTATUS call_query(HANDLE handle)
{
    if (active_query->api == API_SECTION)
        return query_section(handle, active_query->info_class, data_buffer, (SIZE_T)active_case.length,
            active_case.ret == RETURN_VALID ? &return_size : NULL);
    if (is_io(active_query->api))
    {
        file_fn function = active_query->api == API_FILE ? query_file : query_volume;
        return function(handle, &iosb, data_buffer, active_case.length, active_query->info_class);
    }
    return query32[active_query->api](handle, active_query->info_class, data_buffer, active_case.length,
        active_case.ret == RETURN_VALID ? &return_u32 : NULL);
}
static int child_main(unsigned index, char selected_pattern)
{
    struct case_spec cases[20]; struct resources resources;
    unsigned count, i, j, setup_failures = 0; PVOID handler;
    output_handle = GetStdHandle(STD_OUTPUT_HANDLE); group_index = index; pattern = selected_pattern;
    active_query = &queries[index]; count = make_cases(active_query, cases);
    if (!load_function(active_query->api))
    { emit("{\"record\":\"group_setup_failure\",\"group\":%u,\"reason\":\"missing_export\"}\n", index); return 3; }
    handler = AddVectoredExceptionHandler(1, exception_handler);
    if (!handler)
    { emit("{\"record\":\"group_setup_failure\",\"group\":%u,\"reason\":\"exception_handler_unavailable\"}\n", index); return 3; }
    init_resources(&resources, active_query);
    for (i = 0; i < count; ++i)
    {
        HANDLE handle; DWORD error; NTSTATUS status;
        active_case = cases[i];
        for (j = 0; j < DATA_CAPACITY; ++j) data_buffer[j] = initial_byte(j);
        return_u32 = initial_return_u32(); return_size = initial_return_size(); initialize_iosb(&iosb);
        handle = select_handle(&resources, active_case.handle, &error); emit_case_begin(error == 0);
        if (error) { ++setup_failures; emit_case("setup_failure", FALSE, 0, 0, error, TRUE); continue; }
        case_active = TRUE; status = call_query(handle);
        if (status == PENDING_STATUS)
        {
            /* Never race-read D/IOSB or recycle them after a pending call. */
            case_active = FALSE;
            emit_case("pending_unresolved", TRUE, (DWORD)status, 0, 0, FALSE);
            ExitProcess(5); /* static buffers remain alive until this process exits */
        }
        emit_case("returned", TRUE, (DWORD)status, 0, 0, TRUE); case_active = FALSE;
    }
    close_resources(&resources); RemoveVectoredExceptionHandler(handler);
    emit("{\"record\":\"group_complete\",\"group\":%u,\"case_records\":%u,\"case_setup_failures\":%u,\"query_calls\":%u}\n",
         index, count, setup_failures, count - setup_failures);
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
    emit("{\"record\":\"run_start\",\"schema\":2,\"fixture\":\"named_owned_query_stage1b\",\"wine_pin\":\"%s\",\"pattern\":\"%c\","
         "\"pointer_bits\":%u,\"wow64\":%s,\"os_major\":%lu,\"os_minor\":%lu,\"os_build\":%lu,"
         "\"utc\":\"%04u-%02u-%02uT%02u:%02u:%02uZ\",\"groups\":%u,\"class_timeout_ms\":%u,"
         "\"fixed_sentinels_only\":true,\"data_payload_emitted\":false}\n",
         WINE_PIN, pattern, (unsigned)(8 * sizeof(void *)), wow64 ? "true" : "false",
         (unsigned long)version.dwMajorVersion, (unsigned long)version.dwMinorVersion, (unsigned long)version.dwBuildNumber,
         now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, (unsigned)COUNT(queries), CLASS_TIMEOUT_MS);
    for (i = 0; i < COUNT(queries); ++i)
    {
        struct case_spec cases[20];
        total += make_cases(&queries[i], cases);
    }
    for (i = 0; i < COUNT(queries); ++i)
    {
        struct case_spec cases[20];
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
        { outcome = exit_code == 3 ? "setup_failure" : exit_code == 4 ? "partial_setup_failure" : exit_code == 5 ? "pending_unresolved" : "abnormal_exit"; }
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
        if (end == argv[2] || *end || index >= COUNT(queries) || wcslen(argv[4]) != 1 || (argv[4][0] != L'A' && argv[4][0] != L'B')) return 2;
        return child_main((unsigned)index, (char)argv[4][0]);
    }
    if (argc == 5 && !wcscmp(argv[1], L"--output") && !wcscmp(argv[3], L"--pattern") &&
        wcslen(argv[4]) == 1 && (argv[4][0] == L'A' || argv[4][0] == L'B'))
        return parent_main(argv[2], (char)argv[4][0]);
    fwprintf(stderr, L"Usage: named-object-stage1b.exe --output NEWFILE.jsonl --pattern A|B\nRun twice in independent invocations, once with A and once with B.\n");
    return 2;
}
