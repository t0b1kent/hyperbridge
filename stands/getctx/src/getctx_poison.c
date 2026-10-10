/* CLAUDE-EXC (11.10.2026), задача Е: «отравленный буфер» для GetThreadContext/NtGetContextThread СВОЕГО потока.
   Буфер CONTEXT (0x4d0 Б) и по 256 Б до и после заполнены 0xA5; после вызова печатается карта изменённых байт по полям.
   Клетки: 0-25 = 13 наборов флагов x {Win32, Nt}; 26-29 = буфер прижат к недоступной странице (DEBUG: пишутся только 0x48-0x77; CONTROL: до 0x100);
   30-31 = «нагрузка как у программы»: буфер заполнен RtlCaptureContext, запрос только DEBUG, сверка остальных полей.
   Использование: getctx_poison.exe cell N */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef LONG (NTAPI *nt_get_fn)(HANDLE, PCONTEXT);
static nt_get_fn pNtGet;
#define CTXSZ 0x4d0
typedef struct { const char* n; unsigned lo, hi; } fld;
static const fld F[] = {
 {"P1-6Home",0,0x30},{"ContextFlags",0x30,0x34},{"MxCsr",0x34,0x38},{"SegCs",0x38,0x3a},{"SegDs",0x3a,0x3c},{"SegEs",0x3c,0x3e},{"SegFs",0x3e,0x40},{"SegGs",0x40,0x42},{"SegSs",0x42,0x44},{"EFlags",0x44,0x48},
 {"Dr0",0x48,0x50},{"Dr1",0x50,0x58},{"Dr2",0x58,0x60},{"Dr3",0x60,0x68},{"Dr6",0x68,0x70},{"Dr7",0x70,0x78},
 {"Rax",0x78,0x80},{"Rcx",0x80,0x88},{"Rdx",0x88,0x90},{"Rbx",0x90,0x98},{"Rsp",0x98,0xa0},{"Rbp",0xa0,0xa8},{"Rsi",0xa8,0xb0},{"Rdi",0xb0,0xb8},
 {"R8",0xb8,0xc0},{"R9",0xc0,0xc8},{"R10",0xc8,0xd0},{"R11",0xd0,0xd8},{"R12",0xd8,0xe0},{"R13",0xe0,0xe8},{"R14",0xe8,0xf0},{"R15",0xf0,0xf8},{"Rip",0xf8,0x100},
 {"Flt.ctl",0x100,0x120},{"Flt.ST",0x120,0x1a0},{"Xmm0-5",0x1a0,0x200},{"Xmm6-15",0x200,0x2a0},{"Flt.rsv",0x2a0,0x300},{"VectorReg",0x300,0x4a0},{"VectorCtl",0x4a0,0x4a8},{"tail",0x4a8,0x4d0},
};
static void report(const char* tag, const unsigned char* ref, const unsigned char* got, unsigned n_ctx_len) {
    char line[1400]; int p = 0; p += sprintf(line + p, "%s changed=[", tag);
    int any = 0;
    for (unsigned i = 0; i < sizeof F / sizeof F[0]; i++) {
        unsigned lo = F[i].lo, hi = F[i].hi; if (lo >= n_ctx_len) break; if (hi > n_ctx_len) hi = n_ctx_len;
        unsigned ch = 0; for (unsigned k = lo; k < hi; k++) if (got[k] != ref[k]) ch++;
        if (ch) { p += sprintf(line + p, "%s%s(%u/%u)", any ? "," : "", F[i].n, ch, hi - lo); any = 1; }
    }
    p += sprintf(line + p, "]"); puts(line);
}
static DWORD fl[13] = { CONTEXT_CONTROL, CONTEXT_INTEGER, CONTEXT_SEGMENTS, CONTEXT_FLOATING_POINT, CONTEXT_DEBUG_REGISTERS, CONTEXT_XSTATE, CONTEXT_FULL, CONTEXT_ALL,
                        CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS, CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS, CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS, CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS, CONTEXT_ALL | CONTEXT_XSTATE };
static const char* fn[13] = { "control","integer","segments","fp","debug","xstate","full","all","control_debug","integer_debug","fp_debug","full_debug","all_xstate" };
static int call(int nt, CONTEXT* c, DWORD* err) {
    if (nt) { LONG s = pNtGet(GetCurrentThread(), c); *err = (DWORD)s; return s >= 0; }
    SetLastError(0); BOOL ok = GetThreadContext(GetCurrentThread(), c); *err = GetLastError(); return ok;
}
__attribute__((noinline)) static int guarded_call(int nt, CONTEXT* c, DWORD* err, DWORD* exc, ULONG_PTR* faddr) {
    *exc = 0; *faddr = 0; int r = 0;
    __try { r = call(nt, c, err); } __except (*exc = GetExceptionCode(), *faddr = (ULONG_PTR)(GetExceptionInformation()->ExceptionRecord->NumberParameters > 1 ? GetExceptionInformation()->ExceptionRecord->ExceptionInformation[1] : 0), EXCEPTION_EXECUTE_HANDLER) { r = -1; }
    return r;
}
int main(int argc, char** argv) {
    pNtGet = (nt_get_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtGetContextThread");
    int cell = argc > 2 ? atoi(argv[2]) : 0;
    static unsigned char mem[256 + CTXSZ + 256] __attribute__((aligned(64))), ref[256 + CTXSZ + 256] __attribute__((aligned(64)));
    char tag[160];
    if (cell < 26) {
        int nt = cell >= 13, k = cell % 13;
        memset(mem, 0xA5, sizeof mem); CONTEXT* c = (CONTEXT*)(mem + 256); c->ContextFlags = fl[k]; memcpy(ref, mem, sizeof mem);
        DWORD err, exc; ULONG_PTR fa; int r = guarded_call(nt, c, &err, &exc, &fa);
        sprintf(tag, "CELL %d %s_%s ret=%d err=%#lx exc=%#lx cfo=%#lx", cell, nt ? "nt" : "w32", fn[k], r, (unsigned long)err, (unsigned long)exc, (unsigned long)c->ContextFlags);
        report(tag, ref + 256, mem + 256, CTXSZ);
        unsigned gb = 0, ga = 0; for (int i = 0; i < 256; i++) { gb += mem[i] != 0xA5; ga += mem[256 + CTXSZ + i] != 0xA5; }
        printf("   guard_before_changed=%u guard_after_changed=%u\n", gb, ga);
        return 0;
    }
    if (cell < 30) {   /* короткий буфер: прижать к концу доступной страницы */
        int nt = cell & 1; int which = (cell - 26) / 2;   /* 0: DEBUG (до 0x78), 1: CONTROL (до 0x100) */
        unsigned end = which == 0 ? 0x78 : 0x100; DWORD fl2 = which == 0 ? CONTEXT_DEBUG_REGISTERS : CONTEXT_CONTROL;
        unsigned char* pg = (unsigned char*)VirtualAlloc(NULL, 0x20000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        DWORD o; VirtualProtect(pg + 0x10000, 0x10000, PAGE_NOACCESS, &o);
        unsigned char* buf = pg + 0x10000 - end; memset(buf, 0xA5, end); CONTEXT* c = (CONTEXT*)buf; c->ContextFlags = fl2;
        unsigned char save[0x100]; memcpy(save, buf, end);
        DWORD err, exc; ULONG_PTR fa; int r = guarded_call(nt, c, &err, &exc, &fa);
        unsigned ch = 0; for (unsigned i = 0; i < end; i++) ch += buf[i] != save[i];
        printf("CELL %d short_%s_%s буфер_до_смещения=%#x ret=%d err=%#lx exc=%#lx fault_addr_off=%s%#llx изменено_байт_в_доступной_части=%u cfo=%#lx\n", cell, nt ? "nt" : "w32", which ? "control" : "debug", end, r, (unsigned long)err, (unsigned long)exc,
               exc ? "+" : "", exc ? (unsigned long long)(fa - (ULONG_PTR)pg - 0x10000) : 0ULL, ch, exc ? 0UL : (unsigned long)c->ContextFlags);
        return 0;
    }
    /* 30-31: нагрузка как у программы */
    int nt = cell == 31;
    CONTEXT* c = (CONTEXT*)(mem + 256); memset(mem, 0xA5, sizeof mem);
    RtlCaptureContext(c); c->ContextFlags |= 0;   /* осмысленный контекст */
    DWORD cf0 = c->ContextFlags; memcpy(ref, mem, sizeof mem);
    c->ContextFlags = CONTEXT_DEBUG_REGISTERS; memcpy(ref + 256, c, 0); ((CONTEXT*)(ref + 256))->ContextFlags = CONTEXT_DEBUG_REGISTERS;
    DWORD err, exc; ULONG_PTR fa; int r = guarded_call(nt, c, &err, &exc, &fa);
    sprintf(tag, "CELL %d payload_%s_debug ret=%d err=%#lx cfo=%#lx (до захвата %#lx)", cell, nt ? "nt" : "w32", r, (unsigned long)err, (unsigned long)c->ContextFlags, (unsigned long)cf0);
    report(tag, ref + 256, mem + 256, CTXSZ);
    unsigned gb = 0, ga = 0; for (int i = 0; i < 256; i++) { gb += mem[i] != 0xA5; ga += mem[256 + CTXSZ + i] != 0xA5; }
    printf("   guard_before_changed=%u guard_after_changed=%u (изменённые поля, кроме Dr0-Dr7 и ContextFlags, — порча незапрошенных данных)\n", gb, ga);
    return 0;
}
