// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
// CTXFLAGS probe: what the CONTEXT of an exception carries besides the x87/MXCSR part - ContextFlags, segment selectors,
// debug registers, and the XSTATE group (feature mask, CONTEXT_EX chunks, XSAVE header, AVX upper halves) - with live AVX
// state at the fault, and whether NtContinue gives the YMM upper halves back (unchanged, or as the handler edited them).
// Debug registers are only read, never written.
// Build: x86_64-w64-mingw32-clang -O1 ctxflags.c -o ctxflags64.exe ; i686-w64-mingw32-clang -O1 -msse2 -mfpmath=sse ctxflags.c -o ctxflags32.exe
// Every line: "<name> <hex>". 128-bit values: high qword first.
//   os.*        : GetEnabledXStateFeatures, InitializeContext lengths, CPUID AVX / OSXSAVE / XCR0.
//   exc<m>.*    : an access violation (mov [rax|eax], eax with rax|eax = 0) right after ymm0..ymm(N-1) were loaded with known
//                 values (low and high 128-bit halves differ per register); the vectored handler records the CONTEXT and,
//                 for m = 1, writes a new upper half of ymm0 through LocateXStateFeature (when the context has XSTATE);
//                 after.ymm<i>.hi is read back after the return in the same asm block.
//   getdr.*     : GetThreadContext(GetCurrentThread(), CONTEXT_DEBUG_REGISTERS | CONTEXT_SEGMENTS) of the thread itself.
//   getx.*      : GetThreadContext of another thread that holds the same ymm values (x64: spinning in guest code; x86: waiting
//                 in WaitForSingleObject), into a buffer from InitializeContext(CONTEXT_ALL | CONTEXT_XSTATE) with the AVX
//                 feature requested by SetXStateFeaturesMask when the OS has it.
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#ifdef _WIN64
#define NYMM 16
#else
#define NYMM 8
#ifndef CONTEXT_XSTATE
#define CONTEXT_XSTATE (CONTEXT_i386 | 0x40L) // Windows SDK value; the i686 MinGW headers lack it
#endif
#endif

typedef struct { LONG Offset; DWORD Length; } PROBE_CONTEXT_CHUNK;
typedef struct { PROBE_CONTEXT_CHUNK All, Legacy, XState; } PROBE_CONTEXT_EX; // the first three chunks of CONTEXT_EX

static void pr(const char* a, const char* b, unsigned long long v) { printf("%s.%s %llx\n", a, b, v); }
static void pr128(const char* a, const char* b, int i, const void* p) {
  uint64_t q[2];
  memcpy(q, p, 16);
  printf("%s.%s%d %016llx%016llx\n", a, b, i, (unsigned long long)q[1], (unsigned long long)q[0]);
}

static int avx_usable;
// ymm<i> = { lo: 0x3333333300000000+i, 0x4444444400000000+i ; hi: 0x1111111100000000+i, 0x2222222200000000+i }
static uint64_t ymm_in[NYMM][4];
static uint8_t ymm_hi_after[NYMM][16];
static const uint64_t ymm0_hi_edit[2] = {0x5555555555555555ULL, 0x6666666666666666ULL};

// The handler records into this buffer and prints after the return (the CONTEXT_EX and XSTATE area live past the CONTEXT).
static char seen[16384];
static size_t seen_len;
static volatile LONG exc_mode, exc_hits;
static void seen_add(const char* fmt, unsigned long long v, int idx, const char* a) {
  if (seen_len >= sizeof seen - 128) return;
  if (idx < 0) seen_len += snprintf(seen + seen_len, sizeof seen - seen_len, fmt, a, v);
  else seen_len += snprintf(seen + seen_len, sizeof seen - seen_len, fmt, a, idx, v);
}
static void seen_add128(const char* a, const char* b, int i, const void* p) {
  uint64_t q[2];
  memcpy(q, p, 16);
  if (seen_len >= sizeof seen - 128) return;
  seen_len += snprintf(seen + seen_len, sizeof seen - seen_len, "%s.%s%d %016llx%016llx\n", a, b, i, (unsigned long long)q[1],
                       (unsigned long long)q[0]);
}

static const char* exc_name;
static LONG CALLBACK veh(EXCEPTION_POINTERS* e) {
  if (e->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
  CONTEXT* c = e->ContextRecord;
  const char* n = exc_name;
  exc_hits++;
  seen_add("%s.flags %llx\n", c->ContextFlags, -1, n);
#ifdef _WIN64
  seen_add("%s.seg.cs %llx\n", c->SegCs, -1, n); seen_add("%s.seg.ds %llx\n", c->SegDs, -1, n);
  seen_add("%s.seg.es %llx\n", c->SegEs, -1, n); seen_add("%s.seg.fs %llx\n", c->SegFs, -1, n);
  seen_add("%s.seg.gs %llx\n", c->SegGs, -1, n); seen_add("%s.seg.ss %llx\n", c->SegSs, -1, n);
#else
  seen_add("%s.seg.cs %llx\n", c->SegCs, -1, n); seen_add("%s.seg.ds %llx\n", c->SegDs, -1, n);
  seen_add("%s.seg.es %llx\n", c->SegEs, -1, n); seen_add("%s.seg.fs %llx\n", c->SegFs, -1, n);
  seen_add("%s.seg.gs %llx\n", c->SegGs, -1, n); seen_add("%s.seg.ss %llx\n", c->SegSs, -1, n);
#endif
  seen_add("%s.eflags %llx\n", c->EFlags, -1, n);
  seen_add("%s.dr0 %llx\n", c->Dr0, -1, n); seen_add("%s.dr1 %llx\n", c->Dr1, -1, n);
  seen_add("%s.dr2 %llx\n", c->Dr2, -1, n); seen_add("%s.dr3 %llx\n", c->Dr3, -1, n);
  seen_add("%s.dr6 %llx\n", c->Dr6, -1, n); seen_add("%s.dr7 %llx\n", c->Dr7, -1, n);
  const int has_xstate = (c->ContextFlags & CONTEXT_XSTATE) == CONTEXT_XSTATE;
  seen_add("%s.xstate.present %llx\n", has_xstate, -1, n);
  if (has_xstate) {
    const PROBE_CONTEXT_EX* cx = (const PROBE_CONTEXT_EX*)(c + 1);
    seen_add("%s.cx.all.offset %llx\n", (unsigned long long)(long long)cx->All.Offset, -1, n);
    seen_add("%s.cx.all.length %llx\n", cx->All.Length, -1, n);
    seen_add("%s.cx.legacy.offset %llx\n", (unsigned long long)(long long)cx->Legacy.Offset, -1, n);
    seen_add("%s.cx.legacy.length %llx\n", cx->Legacy.Length, -1, n);
    seen_add("%s.cx.xstate.offset %llx\n", (unsigned long long)(long long)cx->XState.Offset, -1, n);
    seen_add("%s.cx.xstate.length %llx\n", cx->XState.Length, -1, n);
    if (cx->XState.Length >= 16) {
      const uint64_t* hdr = (const uint64_t*)((const uint8_t*)cx + cx->XState.Offset);
      seen_add("%s.xsave.mask %llx\n", hdr[0], -1, n);
      seen_add("%s.xsave.compaction %llx\n", hdr[1], -1, n);
    }
    DWORD64 mask = 0;
    const BOOL ok = GetXStateFeaturesMask(c, &mask);
    seen_add("%s.getmask.ok %llx\n", ok, -1, n);
    seen_add("%s.getmask %llx\n", mask, -1, n);
    DWORD len = 0;
    uint8_t* avx = (uint8_t*)LocateXStateFeature(c, XSTATE_AVX, &len);
    seen_add("%s.avx.length %llx\n", len, -1, n);
    seen_add("%s.avx.offset %llx\n", avx ? (unsigned long long)(avx - (uint8_t*)c) : 0xffffffffULL, -1, n);
    if (avx) {
      for (int i = 0; i < NYMM && (DWORD)(16 * (i + 1)) <= len; ++i) seen_add128(n, "ymm.hi", i, avx + 16 * i);
      if (exc_mode == 1) memcpy(avx, ymm0_hi_edit, 16);
    }
  }
#ifdef _WIN64
  for (int i = 0; i < 16; ++i) seen_add128(n, "xmm", i, &c->Xmm0 + i);
  c->Rip += 2;
#else
  const XSAVE_FORMAT* x = (const XSAVE_FORMAT*)c->ExtendedRegisters;
  for (int i = 0; i < 8; ++i) seen_add128(n, "xmm", i, &x->XmmRegisters[i]);
  c->Eip += 2;
#endif
  return EXCEPTION_CONTINUE_EXECUTION;
}

#ifdef _WIN64
#define LOADY(i) "vmovdqu " #i "*32(%[in]), %%ymm" #i "\n\t"
#define SAVEH(i) "vextractf128 $1, %%ymm" #i ", " #i "*16(%[out])\n\t"
#define FAULT "movl %%eax, (%%rax)\n\t" /* 89 00: two bytes, the handler skips them */
#else
#define LOADY(i) "vmovdqu " #i "*32(%[in]), %%ymm" #i "\n\t"
#define SAVEH(i) "vextractf128 $1, %%ymm" #i ", " #i "*16(%[out])\n\t"
#define FAULT "movl %%eax, (%%eax)\n\t"
#endif

__attribute__((target("avx"), noinline)) static void exc_avx(void) {
  void* null = 0;
  __asm__ volatile(LOADY(0) LOADY(1) LOADY(2) LOADY(3) LOADY(4) LOADY(5) LOADY(6) LOADY(7)
#ifdef _WIN64
                   LOADY(8) LOADY(9) LOADY(10) LOADY(11) LOADY(12) LOADY(13) LOADY(14) LOADY(15)
#endif
                   FAULT
                   SAVEH(0) SAVEH(1) SAVEH(2) SAVEH(3) SAVEH(4) SAVEH(5) SAVEH(6) SAVEH(7)
#ifdef _WIN64
                   SAVEH(8) SAVEH(9) SAVEH(10) SAVEH(11) SAVEH(12) SAVEH(13) SAVEH(14) SAVEH(15)
#endif
                   "vzeroupper\n\t"
                   :
                   : [in] "r"(ymm_in), [out] "r"(ymm_hi_after), "a"(null)
                   : "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"
#ifdef _WIN64
                   , "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
#endif
  );
}

static void exc_plain(void) {
  void* null = 0;
  __asm__ volatile(FAULT : : "a"(null) : "memory");
}

static void exc_test(int mode) {
  char n[16];
  snprintf(n, sizeof n, "exc%d", mode);
  exc_name = n;
  exc_mode = mode;
  exc_hits = 0;
  seen_len = 0;
  memset(ymm_hi_after, 0xcc, sizeof ymm_hi_after);
  if (avx_usable) exc_avx();
  else exc_plain();
  pr(n, "hits", exc_hits);
  fwrite(seen, 1, seen_len, stdout);
  if (avx_usable) {
    char m[24];
    snprintf(m, sizeof m, "%s.after", n);
    for (int i = 0; i < NYMM; ++i) pr128(m, "ymm.hi", i, ymm_hi_after[i]);
  }
}

static void os_info(void) {
  int r[4];
  __cpuid(r, 1);
  const int osxsave = (r[2] >> 27) & 1, avx = (r[2] >> 28) & 1;
  pr("os", "cpuid.avx", avx);
  pr("os", "cpuid.osxsave", osxsave);
  unsigned long long xcr0 = 0;
  if (osxsave) {
    unsigned lo, hi;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(lo), "=d"(hi) : "c"(0)); // xgetbv
    xcr0 = ((unsigned long long)hi << 32) | lo;
  }
  pr("os", "xcr0", xcr0);
  avx_usable = avx && osxsave && (xcr0 & 6) == 6;
  pr("os", "avx.usable", avx_usable);
  pr("os", "enabled.features", GetEnabledXStateFeatures());
  DWORD len = 0;
  InitializeContext(NULL, CONTEXT_ALL, NULL, &len);
  pr("os", "ctxlen.all", len);
  len = 0;
  InitializeContext(NULL, CONTEXT_ALL | CONTEXT_XSTATE, NULL, &len);
  pr("os", "ctxlen.all_xstate", len);
  pr("os", "sizeof.context", sizeof(CONTEXT));
}

static volatile LONG gx_ready, gx_go;
static HANDLE gx_event;
__attribute__((target("avx"), noinline)) static DWORD WINAPI gx_worker(LPVOID wait) {
  __asm__ volatile(LOADY(0) LOADY(1) LOADY(2) LOADY(3) LOADY(4) LOADY(5) LOADY(6) LOADY(7)
#ifdef _WIN64
                   LOADY(8) LOADY(9) LOADY(10) LOADY(11) LOADY(12) LOADY(13) LOADY(14) LOADY(15)
#endif
                   "lock incl %[ready]\n\t"
                   : [ready] "+m"(gx_ready)
                   : [in] "r"(ymm_in)
                   : "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"
#ifdef _WIN64
                   , "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
#endif
  );
  if (wait) WaitForSingleObject(gx_event, INFINITE); /* no FP code in between (-mfpmath=sse; x64 only takes the spin path) */
  else __asm__ volatile("1:\n\tpause\n\tcmpl $0, %[go]\n\tje 1b\n\t" : : [go] "m"(gx_go) : "memory", "cc");
  __asm__ volatile("vzeroupper" ::: "memory");
  return 0;
}
static void getx(void) {
  if (!avx_usable) { pr("getx", "skipped", 1); return; }
#ifdef _WIN64
  const int wait = 0;
#else
  const int wait = 1;
#endif
  gx_ready = 0; gx_go = 0;
  gx_event = CreateEvent(0, TRUE, FALSE, 0);
  HANDLE h = CreateThread(0, 0, gx_worker, (LPVOID)(INT_PTR)wait, 0, 0);
  while (!gx_ready) Sleep(1);
  Sleep(50);
  SuspendThread(h);
  static uint8_t buf[16384];
  DWORD len = sizeof buf;
  CONTEXT* c = NULL;
  const BOOL init = InitializeContext(buf, CONTEXT_ALL | CONTEXT_XSTATE, &c, &len);
  pr("getx", "init.ok", init);
  pr("getx", "init.len", len);
  if (init && c) {
    pr("getx", "setmask.ok", SetXStateFeaturesMask(c, XSTATE_MASK_AVX));
    const BOOL ok = GetThreadContext(h, c);
    pr("getx", "ok", ok);
    pr("getx", "flags", c->ContextFlags);
    DWORD64 mask = 0;
    pr("getx", "getmask.ok", GetXStateFeaturesMask(c, &mask));
    pr("getx", "getmask", mask);
    DWORD alen = 0;
    uint8_t* avx = (uint8_t*)LocateXStateFeature(c, XSTATE_AVX, &alen);
    pr("getx", "avx.length", alen);
    if (avx) for (int i = 0; i < NYMM && (DWORD)(16 * (i + 1)) <= alen; ++i) pr128("getx", "ymm.hi", i, avx + 16 * i);
  }
  ResumeThread(h);
  gx_go = 1;
  SetEvent(gx_event);
  WaitForSingleObject(h, INFINITE);
  CloseHandle(h);
  CloseHandle(gx_event);
}

static void getdr(void) {
  CONTEXT c;
  memset(&c, 0xcc, sizeof c);
  c.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_SEGMENTS;
  const BOOL ok = GetThreadContext(GetCurrentThread(), &c);
  pr("getdr", "ok", ok);
  pr("getdr", "flags", c.ContextFlags);
  pr("getdr", "dr0", c.Dr0); pr("getdr", "dr1", c.Dr1); pr("getdr", "dr2", c.Dr2); pr("getdr", "dr3", c.Dr3);
  pr("getdr", "dr6", c.Dr6); pr("getdr", "dr7", c.Dr7);
  pr("getdr", "seg.ds", c.SegDs); pr("getdr", "seg.es", c.SegEs); pr("getdr", "seg.fs", c.SegFs); pr("getdr", "seg.gs", c.SegGs);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN64
  puts("arch x64");
#else
  puts("arch x86");
#endif
  for (int i = 0; i < NYMM; ++i) {
    ymm_in[i][0] = 0x3333333300000000ULL + i; ymm_in[i][1] = 0x4444444400000000ULL + i;
    ymm_in[i][2] = 0x1111111100000000ULL + i; ymm_in[i][3] = 0x2222222200000000ULL + i;
  }
  os_info();
  AddVectoredExceptionHandler(1, veh);
  exc_test(0);
  exc_test(1);
  getdr();
  getx();
  puts("CTXFLAGS END");
  puts("END");
  return 0;
}
