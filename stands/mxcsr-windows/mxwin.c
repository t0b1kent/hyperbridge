// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
// LAZY-FLAGS Windows probe: MXCSR status across OS boundaries (syscalls, exceptions, context get/set, threads, CRT).
// Build: x86_64-w64-mingw32-clang -O1 mxwin.c -o mxwin64.exe ; i686-w64-mingw32-clang -O1 -msse2 mxwin.c -o mxwin32.exe
// Every line: "<name> <hex>". Expected values (Windows x86 contract) are in EXPECTED.txt next to this file.
#include <windows.h>
#include <float.h>
#include <stdio.h>
#include <stdint.h>
static unsigned rd(void) { unsigned m; __asm__ volatile("stmxcsr %0" : "=m"(m)); return m; }
static void ld(unsigned m) { __asm__ volatile("ldmxcsr %0" : : "m"(m)); }
static void div0(void) { float a = 1.0f, b = 0.0f; __asm__ volatile("movss %0, %%xmm0\n\tdivss %1, %%xmm0" : : "m"(a), "m"(b) : "xmm0"); }
static void out(const char* n, unsigned v) { printf("%s %08x\n", n, v); fflush(stdout); }
static volatile LONG mode; static volatile unsigned seen_ctx, seen_fltsave, seen_handler;
static LONG CALLBACK veh(EXCEPTION_POINTERS* e) {
  if (e->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
  seen_handler = rd();
#ifdef _WIN64
  seen_ctx = e->ContextRecord->MxCsr; seen_fltsave = e->ContextRecord->FltSave.MxCsr;
  if (mode == 1) { e->ContextRecord->MxCsr &= ~0x3fu; e->ContextRecord->FltSave.MxCsr &= ~0x3fu; }
  if (mode == 2) { e->ContextRecord->MxCsr = 0x1fa0; e->ContextRecord->FltSave.MxCsr = 0x1fa0; }
  e->ContextRecord->Rip += 2;
#else
  XSAVE_FORMAT* x = (XSAVE_FORMAT*)e->ContextRecord->ExtendedRegisters;
  seen_ctx = x->MxCsr; seen_fltsave = x->MxCsr;
  if (mode == 1) x->MxCsr &= ~0x3fu;
  if (mode == 2) x->MxCsr = 0x1fa0;
  e->ContextRecord->Eip += 2;
#endif
  return EXCEPTION_CONTINUE_EXECUTION;
}
__attribute__((noinline)) static void fault(void) { void* p = 0; __asm__ volatile(".byte 0x89, 0x00" : : "a"(p) : "memory"); } // mov [rax|eax], eax: 2 bytes
static DWORD WINAPI thread_first(LPVOID p) { *(unsigned*)p = rd(); return 0; }
static HANDLE ev_go, ev_ready; static volatile unsigned worker_after;
static DWORD WINAPI worker(LPVOID p) { ld(0x1f80); div0(); SetEvent(ev_ready); WaitForSingleObject(ev_go, INFINITE); worker_after = rd(); return 0; }
int main(void) {
  out("start", rd());
  ld(0x1f80); div0(); out("same", rd());
  ld(0x1f80); div0(); SwitchToThread(); out("syscall.yield", rd());
  ld(0x1f80); div0(); Sleep(1); out("syscall.sleep", rd());
  ld(0x1f80); div0(); (void)GetTickCount64(); out("api.tick", rd());
  ld(0x1f80); div0(); { char b[64]; snprintf(b, sizeof b, "%f", 1.0 / 3.0); } out("crt.printf_fp", rd());
  AddVectoredExceptionHandler(1, veh);
  for (mode = 0; mode < 3; mode++) {
    ld(0x1f80); div0(); seen_ctx = seen_fltsave = seen_handler = 0xdead;
    fault();
    unsigned after = rd(); char n[64];
    snprintf(n, sizeof n, "exc%ld.ctx", (long)mode); out(n, seen_ctx);
    snprintf(n, sizeof n, "exc%ld.fltsave", (long)mode); out(n, seen_fltsave);
    snprintf(n, sizeof n, "exc%ld.inhandler", (long)mode); out(n, seen_handler);
    snprintf(n, sizeof n, "exc%ld.after", (long)mode); out(n, after);
  }
  { unsigned v = 0xdead; ld(0x1f80); div0(); HANDLE h = CreateThread(0, 0, thread_first, &v, 0, 0); WaitForSingleObject(h, INFINITE); CloseHandle(h);
    out("thread.first", v); out("thread.parent_after", rd()); }
  { ev_go = CreateEvent(0, TRUE, FALSE, 0); ev_ready = CreateEvent(0, TRUE, FALSE, 0);
    HANDLE h = CreateThread(0, 0, worker, 0, 0, 0); WaitForSingleObject(ev_ready, INFINITE); Sleep(20);
    SuspendThread(h);
    CONTEXT c; memset(&c, 0, sizeof c); c.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
#ifndef _WIN64
    c.ContextFlags |= CONTEXT_EXTENDED_REGISTERS;
#endif
    BOOL ok = GetThreadContext(h, &c);
#ifdef _WIN64
    out("getctx.worker", ok ? c.MxCsr : 0xbad); c.MxCsr &= ~0x3fu; c.FltSave.MxCsr &= ~0x3fu;
#else
    out("getctx.worker", ok ? ((XSAVE_FORMAT*)c.ExtendedRegisters)->MxCsr : 0xbad); ((XSAVE_FORMAT*)c.ExtendedRegisters)->MxCsr &= ~0x3fu;
#endif
    ok = SetThreadContext(h, &c); out("setctx.ok", ok);
    ResumeThread(h); SetEvent(ev_go); WaitForSingleObject(h, INFINITE); out("setctx.worker_after", worker_after); }
  ld(0x1f80); div0(); out("crt.statusfp", _statusfp()); _clearfp(); out("crt.after_clearfp", rd());
  ld(0x1f80); { volatile double x = 1.0; x /= 3.0; (void)x; } out("compiled.div", rd());
  ld(0x1f80); __asm__ volatile("fld1\n\tfldz\n\tfdivrp\n\tfstp %%st(0)" ::: "st"); out("x87.noeffect", rd());
  puts("MXWIN END"); puts("END"); fflush(stdout); return 0;
}
