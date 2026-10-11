/* SPDX-License-Identifier: MIT */
/* getctx_tail: which CONTEXT fields beyond Dr0-Dr7 a debug-register request writes, and with which values.
 * The whole CONTEXT is pre-filled with 0xA5; every field of the tail (after VectorControl) is printed before and after
 * the call, for the current thread and for another suspended thread, through GetThreadContext and NtGetContextThread.
 * Build: x86_64-w64-mingw32-gcc -O1 -o getctx_tail.exe getctx_tail.c */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG (NTAPI *nt_get_fn)(HANDLE, PCONTEXT);

static DWORD WINAPI sleeper(void *arg) { Sleep(INFINITE); return (DWORD)(ULONG_PTR)arg; }

static void show(const char *tag, int ok, unsigned long err, const CONTEXT *c)
{
    printf("CELL %s ok=%d err=%#lx flags=%#lx dr0=%llx dr1=%llx dr2=%llx dr3=%llx dr6=%llx dr7=%llx "
           "DebugControl=%llx LastBranchToRip=%llx LastBranchFromRip=%llx LastExceptionToRip=%llx LastExceptionFromRip=%llx "
           "VectorControl=%llx\n", tag, ok, err, (unsigned long)c->ContextFlags,
           (unsigned long long)c->Dr0, (unsigned long long)c->Dr1, (unsigned long long)c->Dr2, (unsigned long long)c->Dr3,
           (unsigned long long)c->Dr6, (unsigned long long)c->Dr7,
           (unsigned long long)c->DebugControl, (unsigned long long)c->LastBranchToRip, (unsigned long long)c->LastBranchFromRip,
           (unsigned long long)c->LastExceptionToRip, (unsigned long long)c->LastExceptionFromRip,
           (unsigned long long)c->VectorControl);
}

int main(void)
{
    static const struct { DWORD f; const char *n; } fl[] = {
        { CONTEXT_DEBUG_REGISTERS, "debug" }, { CONTEXT_CONTROL, "control" }, { CONTEXT_INTEGER, "integer" },
        { CONTEXT_FLOATING_POINT, "fp" }, { CONTEXT_FULL, "full" }, { CONTEXT_ALL, "all" },
        { CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS, "control_debug" } };
    nt_get_fn pNtGet = (nt_get_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetContextThread");
    HANDLE other = CreateThread(NULL, 0, sleeper, NULL, 0, NULL);
    DECLSPEC_ALIGN(16) static CONTEXT c;
    char tag[64];
    unsigned i, who, api;

    Sleep(100);
    SuspendThread(other);
    printf("GETCTX_TAIL version=1 context_size=%u\n", (unsigned)sizeof(CONTEXT));
    for (i = 0; i < sizeof(fl) / sizeof(fl[0]); i++)
    for (who = 0; who < 2; who++)
    for (api = 0; api < 2; api++)
    {
        HANDLE h = who ? other : GetCurrentThread();
        unsigned long err;
        int ok;

        memset(&c, 0xA5, sizeof(c));
        c.ContextFlags = fl[i].f;
        if (api) { LONG st = pNtGet(h, &c); ok = st >= 0; err = (unsigned long)st; }
        else { SetLastError(0); ok = GetThreadContext(h, &c); err = GetLastError(); }
        snprintf(tag, sizeof(tag), "%s_%s_%s", fl[i].n, who ? "other" : "self", api ? "nt" : "w32");
        show(tag, ok, err, &c);
    }
    ResumeThread(other);
    printf("DONE\n");
    return 0;
}
