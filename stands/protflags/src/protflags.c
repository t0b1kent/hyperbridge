/* SPDX-License-Identifier: MIT */
/* protflags: how Windows answers when a page-protection modifier (PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE) is combined
 * with each base protection, for every API that takes a protection value. One line per call; nothing is asserted.
 * Build: x86_64-w64-mingw32-gcc -O1 -o protflags.exe protflags.c */
#include <windows.h>
#include <stdio.h>

typedef LONG (NTAPI *nt_alloc_fn)(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
typedef LONG (NTAPI *nt_protect_fn)(HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);
typedef LONG (NTAPI *nt_map_fn)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, LARGE_INTEGER *, SIZE_T *, DWORD, ULONG, ULONG);
typedef LONG (NTAPI *nt_unmap_fn)(HANDLE, PVOID);

static const struct { DWORD v; const char *n; } base[] = {
    { PAGE_NOACCESS, "NOACCESS" }, { PAGE_READONLY, "READONLY" }, { PAGE_READWRITE, "READWRITE" }, { PAGE_WRITECOPY, "WRITECOPY" },
    { PAGE_EXECUTE, "EXECUTE" }, { PAGE_EXECUTE_READ, "EXECUTE_READ" }, { PAGE_EXECUTE_READWRITE, "EXECUTE_READWRITE" },
    { PAGE_EXECUTE_WRITECOPY, "EXECUTE_WRITECOPY" } };
static const struct { DWORD v; const char *n; } mod[] = {
    { 0, "none" }, { PAGE_GUARD, "GUARD" }, { PAGE_NOCACHE, "NOCACHE" }, { PAGE_WRITECOMBINE, "WRITECOMBINE" },
    { PAGE_GUARD | PAGE_NOCACHE, "GUARD|NOCACHE" }, { PAGE_GUARD | PAGE_WRITECOMBINE, "GUARD|WRITECOMBINE" },
    { PAGE_NOCACHE | PAGE_WRITECOMBINE, "NOCACHE|WRITECOMBINE" },
    { PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE, "GUARD|NOCACHE|WRITECOMBINE" } };

int main(void)
{
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    nt_alloc_fn pAlloc = (nt_alloc_fn)GetProcAddress(nt, "NtAllocateVirtualMemory");
    nt_protect_fn pProtect = (nt_protect_fn)GetProcAddress(nt, "NtProtectVirtualMemory");
    nt_map_fn pMap = (nt_map_fn)GetProcAddress(nt, "NtMapViewOfSection");
    nt_unmap_fn pUnmap = (nt_unmap_fn)GetProcAddress(nt, "NtUnmapViewOfSection");
    SYSTEM_INFO si;
    unsigned b, m;

    GetSystemInfo(&si);
    printf("PROTFLAGS version=2 page=%lu\n", (unsigned long)si.dwPageSize);
    for (b = 0; b < sizeof(base) / sizeof(base[0]); b++)
    for (m = 0; m < sizeof(mod) / sizeof(mod[0]); m++)
    {
        DWORD prot = base[b].v | mod[m].v, old, err;
        MEMORY_BASIC_INFORMATION info;
        void *p, *addr;
        SIZE_T size;
        ULONG nold;
        LONG st;
        BOOL ok;
        HANDLE map;

        /* 1. VirtualAlloc, reserve + commit in one call */
        SetLastError(0xdeadbeef);
        p = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, prot);
        err = GetLastError();
        memset(&info, 0, sizeof(info));
        if (p) VirtualQuery(p, &info, sizeof(info));
        printf("CELL %s+%s alloc_commit ok=%d err=%lu query_protect=%#lx alloc_protect=%#lx\n", base[b].n, mod[m].n, p != NULL,
               p ? 0ul : (unsigned long)err, (unsigned long)info.Protect, (unsigned long)info.AllocationProtect);
        if (p) VirtualFree(p, 0, MEM_RELEASE);

        /* 2. VirtualAlloc, reserve only */
        SetLastError(0xdeadbeef);
        p = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, prot);
        err = GetLastError();
        printf("CELL %s+%s alloc_reserve ok=%d err=%lu\n", base[b].n, mod[m].n, p != NULL, p ? 0ul : (unsigned long)err);
        if (p) VirtualFree(p, 0, MEM_RELEASE);

        /* 3. commit inside an existing reservation */
        p = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS);
        if (p)
        {
            void *q;
            SetLastError(0xdeadbeef);
            q = VirtualAlloc(p, 0x1000, MEM_COMMIT, prot);
            err = GetLastError();
            printf("CELL %s+%s commit_in_reserve ok=%d err=%lu\n", base[b].n, mod[m].n, q != NULL, q ? 0ul : (unsigned long)err);
            VirtualFree(p, 0, MEM_RELEASE);
        }

        /* 4. NtAllocateVirtualMemory */
        addr = NULL; size = 0x10000;
        st = pAlloc(GetCurrentProcess(), &addr, 0, &size, MEM_RESERVE | MEM_COMMIT, prot);
        printf("CELL %s+%s nt_alloc status=%08lx\n", base[b].n, mod[m].n, (unsigned long)st);
        if (st >= 0 && addr) VirtualFree(addr, 0, MEM_RELEASE);

        /* 5. VirtualProtect and NtProtectVirtualMemory on a committed read-write page */
        p = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p)
        {
            old = 0xdeadbeef;
            SetLastError(0xdeadbeef);
            ok = VirtualProtect(p, 0x1000, prot, &old);
            err = GetLastError();
            memset(&info, 0, sizeof(info));
            VirtualQuery(p, &info, sizeof(info));
            printf("CELL %s+%s protect ok=%d err=%lu old=%#lx query_protect=%#lx\n", base[b].n, mod[m].n, ok,
                   ok ? 0ul : (unsigned long)err, (unsigned long)old, (unsigned long)info.Protect);
            VirtualProtect(p, 0x1000, PAGE_READWRITE, &old);
            addr = p; size = 0x1000; nold = 0xdeadbeef;
            st = pProtect(GetCurrentProcess(), &addr, &size, prot, &nold);
            printf("CELL %s+%s nt_protect status=%08lx old=%#lx\n", base[b].n, mod[m].n, (unsigned long)st, (unsigned long)nold);
            VirtualFree(p, 0, MEM_RELEASE);
        }

        /* 6. NtMapViewOfSection of a pagefile-backed read-write section */
        map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x10000, NULL);
        if (map)
        {
            addr = NULL; size = 0;
            st = pMap(map, GetCurrentProcess(), &addr, 0, 0, NULL, &size, 1 /* ViewShare */, 0, prot);
            printf("CELL %s+%s nt_map_view status=%08lx\n", base[b].n, mod[m].n, (unsigned long)st);
            if (st >= 0 && addr) pUnmap(GetCurrentProcess(), addr);
            CloseHandle(map);
        }
    }
    printf("DONE\n");
    return 0;
}
