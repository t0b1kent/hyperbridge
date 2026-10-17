// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
// X87CTX probe: x87 registers in the Windows CONTEXT while TOP != 0.
// Build: x86_64-w64-mingw32-clang -O1 x87ctx.c -o x87ctx64.exe ; i686-w64-mingw32-clang -O1 -msse2 -mfpmath=sse x87ctx.c -o x87ctx32.exe
// The x87 stack is set up inside one asm block (fninit; fldcw 0x027f; fld1, fldpi, fldl2t, fldl2e, fldlg2): TOP = 3, ST(0) = log10(2),
// ST(1) = log2(e), ST(2) = log2(10), ST(3) = pi, ST(4) = 1.0, physical R0..R2 empty. Each test ends in the same asm block with FNSAVE
// (env + ST(0..7) in stack order + full tag word), so no compiler code touches the x87 state in between.
//   exc<m>.*   : an access violation inside the block; the vectored handler prints what the CONTEXT carries, edits it per mode m,
//                continues at the next instruction; after.* is the FNSAVE image after the return.
//   get<m>.*   : a worker thread holds the same stack in a spin loop; the main thread suspends it, prints GetThreadContext,
//                edits per mode m and calls SetThreadContext, resumes; after.* is the worker's FNSAVE image.
// Variants: excb* = an indirect jump ends the translated block before the fault (exc* = same block; exs0/exp0 = other stack
// shapes in the same block, see exc_shape); getw* = the worker
// holds the stack across WaitForSingleObject (get* = spin loop in emulated code, x64 only).
// Modes: 0 = no edit; 1 = FXSAVE-format area (x64 FltSave / x86 ExtendedRegisters): ST(0) := 42.0, ControlWord := 0x037f;
//        2 (x86) = FNSAVE area FloatSave only: ST(0) := 43.0, ControlWord := 0x037f; 3 (x86) = both, conflicting (42 vs 43).
// Every line: "<name> <hex>"; 80-bit values are printed exponent first (20 hex digits).
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const uint16_t cw_start = 0x027f;
static const uint8_t f42[10] = {0, 0, 0, 0, 0, 0, 0, 0xa8, 0x04, 0x40}; // 42.0 = 1.3125 * 2^5
__attribute__((unused)) static const uint8_t f43[10] = {0, 0, 0, 0, 0, 0, 0, 0xac, 0x04, 0x40}; // 43.0

static void pr(const char* a, const char* b, unsigned v) { printf("%s.%s %08x\n", a, b, v); }
static void pr80(const char* a, const char* b, int i, const void* p) {
  const uint8_t* x = (const uint8_t*)p;
  printf("%s.%s%d ", a, b, i);
  for (int k = 9; k >= 0; --k) printf("%02x", x[k]);
  printf("\n");
}
// FNSAVE image (32-bit protected-mode layout, also used in 64-bit mode without REX.W): 28-byte environment + 8 x 10 bytes.
static void pr_fnsave(const char* a, const uint8_t* s) {
  uint16_t cw, sw, tw;
  memcpy(&cw, s + 0, 2); memcpy(&sw, s + 4, 2); memcpy(&tw, s + 8, 2);
  pr(a, "cw", cw); pr(a, "sw", sw); pr(a, "top", (sw >> 11) & 7); pr(a, "tw", tw);
  for (int i = 0; i < 8; ++i) pr80(a, "st", i, s + 28 + 10 * i);
}
#ifdef _WIN64
static void pr_ctx(const char* a, const CONTEXT* c) {
  pr(a, "flags", c->ContextFlags);
  pr(a, "fx.cw", c->FltSave.ControlWord); pr(a, "fx.sw", c->FltSave.StatusWord); pr(a, "fx.top", (c->FltSave.StatusWord >> 11) & 7);
  pr(a, "fx.tw", c->FltSave.TagWord);
  for (int i = 0; i < 8; ++i) pr80(a, "fx.st", i, &c->FltSave.FloatRegisters[i]);
}
#else
static void pr_ctx(const char* a, const CONTEXT* c) {
  const XSAVE_FORMAT* x = (const XSAVE_FORMAT*)c->ExtendedRegisters;
  pr(a, "flags", c->ContextFlags);
  pr(a, "fn.cw", c->FloatSave.ControlWord & 0xffff); pr(a, "fn.sw", c->FloatSave.StatusWord & 0xffff);
  pr(a, "fn.top", (c->FloatSave.StatusWord >> 11) & 7); pr(a, "fn.tw", c->FloatSave.TagWord & 0xffff);
  pr(a, "fn.cw32", c->FloatSave.ControlWord); pr(a, "fn.sw32", c->FloatSave.StatusWord); pr(a, "fn.tw32", c->FloatSave.TagWord);
  pr(a, "fn.cr0npx", c->FloatSave.Cr0NpxState);
  for (int i = 0; i < 8; ++i) pr80(a, "fn.st", i, &c->FloatSave.RegisterArea[10 * i]);
  pr(a, "fx.cw", x->ControlWord); pr(a, "fx.sw", x->StatusWord); pr(a, "fx.top", (x->StatusWord >> 11) & 7); pr(a, "fx.tw", x->TagWord);
  for (int i = 0; i < 8; ++i) pr80(a, "fx.st", i, &x->FloatRegisters[i]);
}
#endif

// Mode edits, applied to a CONTEXT (exception record context or GetThreadContext result).
static void edit(CONTEXT* c, int mode) {
#ifdef _WIN64
  if (mode == 1) { memcpy(&c->FltSave.FloatRegisters[0], f42, 10); c->FltSave.ControlWord = 0x037f; }
#else
  XSAVE_FORMAT* x = (XSAVE_FORMAT*)c->ExtendedRegisters;
  if (mode == 1 || mode == 3) { memcpy(&x->FloatRegisters[0], f42, 10); x->ControlWord = 0x037f; }
  if (mode == 2 || mode == 3) { memcpy(&c->FloatSave.RegisterArea[0], f43, 10); c->FloatSave.ControlWord = 0x037f; }
#endif
}

static volatile LONG exc_mode;
static CONTEXT exc_seen;
static volatile LONG exc_hits;
static LONG CALLBACK veh(EXCEPTION_POINTERS* e) {
  if (e->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
  exc_seen = *e->ContextRecord;
  exc_hits++;
  edit(e->ContextRecord, exc_mode);
#ifdef _WIN64
  e->ContextRecord->Rip += 2;
#else
  e->ContextRecord->Eip += 2;
#endif
  return EXCEPTION_CONTINUE_EXECUTION;
}

#define LOAD_STACK "fninit\n\t" "fldcw %[cw]\n\t" "fld1\n\t" "fldpi\n\t" "fldl2t\n\t" "fldl2e\n\t" "fldlg2\n\t"

#ifdef _WIN64
#define BOUNDARY "lea 9f(%%rip), %%rcx\n\t" "jmp *%%rcx\n\t" "9:\n\t"
#else
#define BOUNDARY "mov $9f, %%ecx\n\t" "jmp *%%ecx\n\t" "9:\n\t"
#endif
// sep = 0: the fault is in the same translated block as the loads; sep = 1: an indirect jump ends the block first.
static void exc_test(int mode, int sep) {
  uint8_t after[108];
  memset(after, 0xcc, sizeof after);
  exc_mode = mode;
  exc_hits = 0;
  void* null = 0;
  if (sep)
    __asm__ volatile(LOAD_STACK BOUNDARY
                     ".byte 0x89, 0x00\n\t"
                     "fnsave %[after]\n\t"
                     : [after] "=m"(after)
                     : [cw] "m"(cw_start), "a"(null)
                     : "memory", "ecx");
  else
    __asm__ volatile(LOAD_STACK
                     ".byte 0x89, 0x00\n\t"   /* mov [rax|eax], eax : access violation, the handler skips 2 bytes */
                     "fnsave %[after]\n\t"
                     : [after] "=m"(after)
                     : [cw] "m"(cw_start), "a"(null)
                     : "memory");
  char n[32];
  snprintf(n, sizeof n, "exc%s%d", sep ? "b" : "", mode);
  pr(n, "hits", exc_hits);
  pr_ctx(n, &exc_seen);
  snprintf(n, sizeof n, "exc%s%d.after", sep ? "b" : "", mode);
  pr_fnsave(n, after);
}

// P5 shapes of the pending stack at a fault inside one translated block (mode 0, no edit), checked by x86 semantics:
//   exs0: a new block starts with FLD ST(1) (the value is not in the block's own stack model: FEX's slow path, pending TOP);
//         expected TOP = 2, ST(0..5) = log2(e), log10(2), log2(e), log2(10), pi, 1.0.
//   exp0: the same block as the loads ends with FSTP ST(0) (a pop: pending empty tag); expected TOP = 4,
//         ST(0..3) = log2(e), log2(10), pi, 1.0.
static void exc_shape(int slow) {
  uint8_t after[108];
  memset(after, 0xcc, sizeof after);
  exc_mode = 0;
  exc_hits = 0;
  void* null = 0;
  if (slow)
    __asm__ volatile(LOAD_STACK BOUNDARY
                     "fld %%st(1)\n\t"
                     ".byte 0x89, 0x00\n\t"
                     "fnsave %[after]\n\t"
                     : [after] "=m"(after)
                     : [cw] "m"(cw_start), "a"(null)
                     : "memory", "ecx");
  else
    __asm__ volatile(LOAD_STACK
                     "fstp %%st(0)\n\t"
                     ".byte 0x89, 0x00\n\t"
                     "fnsave %[after]\n\t"
                     : [after] "=m"(after)
                     : [cw] "m"(cw_start), "a"(null)
                     : "memory");
  const char* n = slow ? "exs0" : "exp0";
  char m[32];
  pr(n, "hits", exc_hits);
  pr_ctx(n, &exc_seen);
  snprintf(m, sizeof m, "%s.after", n);
  pr_fnsave(m, after);
}

static volatile LONG w_ready, w_go;
static uint8_t w_after[108];
static HANDLE w_event;
static DWORD WINAPI worker_wait(LPVOID unused) {
  (void)unused;
  __asm__ volatile(LOAD_STACK "lock incl %[ready]\n\t" : [ready] "+m"(w_ready) : [cw] "m"(cw_start) : "memory");
  WaitForSingleObject(w_event, INFINITE);   /* no FP code in between: the compiler emits SSE only (-mfpmath=sse) */
  __asm__ volatile("fnsave %[after]\n\t" : [after] "=m"(w_after) : : "memory");
  return 0;
}
static DWORD WINAPI worker(LPVOID unused) {
  (void)unused;
  __asm__ volatile(LOAD_STACK
                   "lock incl %[ready]\n\t"
                   "1:\n\t"
                   "pause\n\t"
                   "cmpl $0, %[go]\n\t"
                   "je 1b\n\t"
                   "fnsave %[after]\n\t"
                   : [after] "=m"(w_after), [ready] "+m"(w_ready)
                   : [cw] "m"(cw_start), [go] "m"(w_go)
                   : "memory", "cc");
  return 0;
}

// wait = 0: the worker spins in emulated code holding the stack; wait = 1: it waits in WaitForSingleObject holding the stack.
static void get_test(int mode, int wait) {
  w_ready = 0; w_go = 0;
  memset(w_after, 0xcc, sizeof w_after);
  w_event = CreateEvent(0, TRUE, FALSE, 0);
  HANDLE h = CreateThread(0, 0, wait ? worker_wait : worker, 0, 0, 0);
  while (!w_ready) Sleep(1);
  Sleep(50);
  SuspendThread(h);
  CONTEXT c;
  memset(&c, 0, sizeof c);
  c.ContextFlags = CONTEXT_CONTROL | CONTEXT_FLOATING_POINT;
#ifndef _WIN64
  c.ContextFlags |= CONTEXT_EXTENDED_REGISTERS;
#endif
  BOOL ok = GetThreadContext(h, &c);
  char n[32];
  snprintf(n, sizeof n, "get%s%d", wait ? "w" : "", mode);
  pr(n, "ok", ok);
#ifdef _WIN64
  printf("%s.rip %016llx\n", n, (unsigned long long)c.Rip);   /* where the thread was stopped (diagnostic, not compared) */
#else
  printf("%s.rip %08lx\n", n, (unsigned long)c.Eip);
#endif
  pr_ctx(n, &c);
  if (mode) {
    edit(&c, mode);
#ifdef _WIN64
    c.ContextFlags = CONTEXT_FLOATING_POINT;
#else
    c.ContextFlags = mode == 1 ? CONTEXT_EXTENDED_REGISTERS : mode == 2 ? CONTEXT_FLOATING_POINT : (CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS);
#endif
    ok = SetThreadContext(h, &c);
    pr(n, "set_ok", ok);
  }
  ResumeThread(h);
  w_go = 1;
  SetEvent(w_event);
  WaitForSingleObject(h, INFINITE);
  CloseHandle(h);
  CloseHandle(w_event);
  snprintf(n, sizeof n, "get%s%d.after", wait ? "w" : "", mode);
  pr_fnsave(n, w_after);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN64
  const int modes = 2;
  puts("arch x64");
#else
  const int modes = 4;
  puts("arch x86");
#endif
  AddVectoredExceptionHandler(1, veh);
  for (int m = 0; m < modes; ++m) exc_test(m, 1);
  for (int m = 0; m < modes; ++m) exc_test(m, 0);
  exc_shape(1);
  exc_shape(0);
  for (int m = 0; m < modes; ++m) get_test(m, 1);
#ifdef _WIN64
  /* The spin variant is x64 only: suspending a WOW64 thread in a tight emulated loop is a known separate defect (hangs). */
  for (int m = 0; m < modes; ++m) get_test(m, 0);
#endif
  puts("X87CTX END");
  puts("END");
  return 0;
}
