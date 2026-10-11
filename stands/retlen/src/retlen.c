// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
/*
 * retlen: when an Nt query function is given an information class that does not exist, does Windows
 * write the caller's ReturnLength?  Black-box probe: three ntdll query functions, a few class numbers
 * that are not defined, three buffer shapes.  The caller's ReturnLength and buffer are pre-filled with
 * a pattern, so "written" means "differs from the pattern after the call".  Nothing is asserted.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG PROBE_STATUS;

PROBE_STATUS NTAPI NtQuerySystemInformation(ULONG cls, PVOID info, ULONG len, PULONG ret);
PROBE_STATUS NTAPI NtQueryInformationProcess(HANDLE h, ULONG cls, PVOID info, ULONG len, PULONG ret);
PROBE_STATUS NTAPI NtQueryInformationThread(HANDLE h, ULONG cls, PVOID info, ULONG len, PULONG ret);

#define SENTINEL 0xFEDCBA98u
#define FILL     0xA5
#define BUFBYTES 64

static const ULONG classes[] = { 0xFFFFFFFFu, 0x7FFFFFFFu, 1000u, 300u, 255u };
static const char *const shapes[] = { "null,0", "buf,0", "buf,64" };

static PROBE_STATUS call(int fn, ULONG cls, PVOID info, ULONG len, PULONG ret)
{
    switch (fn)
    {
    case 0: return NtQuerySystemInformation(cls, info, len, ret);
    case 1: return NtQueryInformationProcess(GetCurrentProcess(), cls, info, len, ret);
    default: return NtQueryInformationThread(GetCurrentThread(), cls, info, len, ret);
    }
}

int main(void)
{
    static const char *const names[] = { "system", "process", "thread" };
    BOOL wow64 = FALSE;
    unsigned fn, c, s, i;

    IsWow64Process(GetCurrentProcess(), &wow64);
    printf("pointer_bits=%u wow64=%d\n", (unsigned)(sizeof(void *) * 8), (int)wow64);

    for (fn = 0; fn < 3; fn++)
        for (c = 0; c < sizeof(classes) / sizeof(classes[0]); c++)
            for (s = 0; s < 3; s++)
            {
                ULONGLONG storage[BUFBYTES / 8];
                unsigned char *buf = (unsigned char *)storage;
                ULONG ret = SENTINEL;
                PVOID info = s ? (PVOID)buf : NULL;
                ULONG len = s == 2 ? BUFBYTES : 0;
                unsigned changed = 0;
                PROBE_STATUS st;

                memset(buf, FILL, BUFBYTES);
                st = call((int)fn, classes[c], info, len, &ret);
                for (i = 0; i < BUFBYTES; i++) if (buf[i] != FILL) changed++;
                printf("fn=%s class=0x%08lx shape=%s status=0x%08lx retlen=0x%08lx retlen_written=%d buf_bytes_changed=%u\n",
                       names[fn], (unsigned long)classes[c], shapes[s], (unsigned long)st,
                       (unsigned long)ret, ret != SENTINEL, changed);
            }
    return 0;
}
