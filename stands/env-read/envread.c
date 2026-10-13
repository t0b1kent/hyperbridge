/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 HyperBridge contributors
 *
 * envread.c - a small self-contained diagnostic probe for a Windows x64 process.
 *
 * It records what an ordinary program can observe about its environment WITHOUT asking the system:
 *   - registers, flags and FPU/SSE control state at the process entry point;
 *   - PEB, TEB, loader lists, process parameters and heap headers, read straight from memory;
 *   - the shared user data page at 0x7ffe0000 and how its clocks agree with the API clocks and RDTSC;
 *   - what is left in the volatile registers right after a fixed list of system calls return;
 *   - CPUID, segment selectors and a few unprivileged CPU instructions;
 *   - five ordinary API answers (system info, brand string, a query of the shared page) for cross-checking.
 * It reads only its own process, changes nothing and knows nothing about any other program.
 * Purpose: compare a real x86-64 Windows machine with compatibility layers and x86-64 -> ARM64 translators.
 * This is a diagnostic tool written with AI assistance; treat its output as observations, not as a specification.
 *
 * Output: one JSON object per line: {"c":"<cell>","v":"<normalised value>"[,"raw":"0x..."]}. All numbers are hex.
 * Addresses are reduced to classes (exe / mod:<name>:<x|w|r> / stack / heap / teb+off / peb+off / usd+off /
 * private / mapped / image) so that two machines can be compared; "raw" keeps the original value.
 *
 * The program does not use the C runtime and includes no headers, so that the loader state it prints does not
 * depend on the compiler or on an SDK:
 *   llvm-mingw:  x86_64-w64-mingw32-clang -O1 -ffreestanding -fno-builtin -fno-stack-protector -mno-stack-arg-probe
 *                -nostdlib -Wl,-e,envread_entry -Wl,--subsystem,console -o envread.exe envread.c -lkernel32
 *   clang-cl:    clang-cl /TC /O1 /GS- /Gs1048576 /Zl /clang:-ffreestanding /clang:-fno-builtin
 *                /clang:-mno-stack-arg-probe /clang:-masm=att -fuse-ld=lld /Feenvread.exe envread.c
 *                /link /NODEFAULTLIB /ENTRY:envread_entry /SUBSYSTEM:CONSOLE kernel32.lib   (see run-windows.ps1) */

typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32;
typedef unsigned long long u64; typedef long long i64;

#define IMP __declspec(dllimport)
IMP void *GetStdHandle(u32 n);
IMP int WriteFile(void *h, const void *p, u32 n, u32 *written, void *ov);
IMP void ExitProcess(u32 code);
IMP void *GetModuleHandleA(const char *name);
IMP void *GetProcAddress(void *mod, const char *name);

#define USD 0x7ffe0000ULL
#define FAULT_MARK 0xFA17FA17FA17FA17ULL
#define GLE_MARK 0xBADC0DE1u
#define LST_MARK 0xBADC0DE2u

/* ---- memory used by the assembly below (offsets are fixed, see the comments there) ---- */
u64 g_entry[64];    /* register state at the process entry point */
u64 g_in[48];       /* register state loaded before a call */
u64 g_out[48];      /* register state saved right after the call returns */

void envread_main(void);
extern void cap_call(void);
extern char cap_after[];
extern u32 gi_rd32(const void *p);
extern u64 gi_rdgs(u64 offset);
extern u64 gi_rdtsc(void);
extern u64 gi_cs(void), gi_ss(void), gi_ds(void), gi_es(void), gi_fs(void), gi_gs(void);
extern u64 gi_sidt(void *p), gi_sgdt(void *p), gi_sldt(void), gi_str(void), gi_smsw(void), gi_xgetbv(void);
extern u64 gi_lsl(u64 sel), gi_lar(u64 sel);
extern void gi_cpuid(u32 leaf, u32 subleaf, u32 *out4);
extern u64 gi_rdtscp(u32 *aux), gi_rdrand(u32 *carry);
extern char gi_rdtscp_r[], gi_rdrand_r[];
extern char gi_rd32_r[], gi_sidt_r[], gi_sgdt_r[], gi_sldt_r[], gi_str_r[], gi_smsw_r[], gi_xgetbv_r[], gi_lsl_r[], gi_lar_r[];

/* All assembly is file-level and starts with .att_syntax, so it does not depend on the compiler's default dialect
 * (clang-cl defaults to Intel syntax for inline assembly, the GNU-style driver to AT&T). */
__asm__(
"  .att_syntax prefix\n"
"  .text\n"
/* Process entry point: store every register before any compiler-generated code runs, then go to C. */
"  .globl envread_entry\n"
"  .def envread_entry; .scl 2; .type 32; .endef\n"
"envread_entry:\n"
"  movq %rax, g_entry+0x00(%rip)\n"
"  movq %rcx, g_entry+0x08(%rip)\n"
"  movq %rdx, g_entry+0x10(%rip)\n"
"  movq %rbx, g_entry+0x18(%rip)\n"
"  movq %rsp, g_entry+0x20(%rip)\n"
"  movq %rbp, g_entry+0x28(%rip)\n"
"  movq %rsi, g_entry+0x30(%rip)\n"
"  movq %rdi, g_entry+0x38(%rip)\n"
"  movq %r8,  g_entry+0x40(%rip)\n"
"  movq %r9,  g_entry+0x48(%rip)\n"
"  movq %r10, g_entry+0x50(%rip)\n"
"  movq %r11, g_entry+0x58(%rip)\n"
"  movq %r12, g_entry+0x60(%rip)\n"
"  movq %r13, g_entry+0x68(%rip)\n"
"  movq %r14, g_entry+0x70(%rip)\n"
"  movq %r15, g_entry+0x78(%rip)\n"
"  pushfq\n"
"  popq g_entry+0x80(%rip)\n"
"  stmxcsr g_entry+0x88(%rip)\n"
"  fnstcw g_entry+0x8c(%rip)\n"
"  fnstsw g_entry+0x8e(%rip)\n"
"  movw %cs, g_entry+0x90(%rip)\n"
"  movw %ss, g_entry+0x92(%rip)\n"
"  movw %ds, g_entry+0x94(%rip)\n"
"  movw %es, g_entry+0x96(%rip)\n"
"  movw %fs, g_entry+0x98(%rip)\n"
"  movw %gs, g_entry+0x9a(%rip)\n"
"  movq (%rsp), %rax\n"
"  movq %rax, g_entry+0xa0(%rip)\n"
"  movdqu %xmm0, g_entry+0x100(%rip)\n"
"  movdqu %xmm1, g_entry+0x110(%rip)\n"
"  movdqu %xmm2, g_entry+0x120(%rip)\n"
"  movdqu %xmm3, g_entry+0x130(%rip)\n"
"  movdqu %xmm4, g_entry+0x140(%rip)\n"
"  movdqu %xmm5, g_entry+0x150(%rip)\n"
"  jmp envread_main\n"
/* cap_call: load the registers from g_in, call g_in[0], and save the registers with the very first instruction
 * after the call. g_in: +0x00 target, +0x08 rax, +0x10 rcx, +0x18 rdx, +0x20 r8, +0x28 r9, +0x30 r10, +0x38 r11,
 * +0x40 flags, +0x48.. eight stack arguments, +0x88 rbp rsi rdi r12 r13 r14 r15, +0xc0 rsp at the call (written),
 * +0xc8 mxcsr to load, +0xcc x87 control word before (written), +0xd0 mxcsr found before (written), +0x100.. xmm0-xmm5.
 * g_out: +0x00 rax rcx rdx r8 r9 r10 r11, +0x38 flags, +0x40 rsp, +0x48 rbx rbp rsi rdi r12 r13 r14 r15,
 * +0x88 mxcsr, +0x8c x87 control word, +0x8e x87 status word, +0x90 x87 environment (28 bytes), +0x100.. xmm0-xmm5. */
"  .globl cap_call\n"
"  .def cap_call; .scl 2; .type 32; .endef\n"
"cap_call:\n"
"  pushq %rbx\n"
"  pushq %rbp\n"
"  pushq %rsi\n"
"  pushq %rdi\n"
"  pushq %r12\n"
"  pushq %r13\n"
"  pushq %r14\n"
"  pushq %r15\n"
"  subq $0x68, %rsp\n"
"  leaq g_in(%rip), %rbx\n"
"  movq 0x48(%rbx), %rax\n"
"  movq %rax, 0x20(%rsp)\n"
"  movq 0x50(%rbx), %rax\n"
"  movq %rax, 0x28(%rsp)\n"
"  movq 0x58(%rbx), %rax\n"
"  movq %rax, 0x30(%rsp)\n"
"  movq 0x60(%rbx), %rax\n"
"  movq %rax, 0x38(%rsp)\n"
"  movq 0x68(%rbx), %rax\n"
"  movq %rax, 0x40(%rsp)\n"
"  movq 0x70(%rbx), %rax\n"
"  movq %rax, 0x48(%rsp)\n"
"  movq 0x78(%rbx), %rax\n"
"  movq %rax, 0x50(%rsp)\n"
"  movq 0x80(%rbx), %rax\n"
"  movq %rax, 0x58(%rsp)\n"
"  stmxcsr 0xd0(%rbx)\n"
"  ldmxcsr 0xc8(%rbx)\n"
"  fnstcw 0xcc(%rbx)\n"
"  movdqu 0x100(%rbx), %xmm0\n"
"  movdqu 0x110(%rbx), %xmm1\n"
"  movdqu 0x120(%rbx), %xmm2\n"
"  movdqu 0x130(%rbx), %xmm3\n"
"  movdqu 0x140(%rbx), %xmm4\n"
"  movdqu 0x150(%rbx), %xmm5\n"
"  movq 0x88(%rbx), %rbp\n"
"  movq 0x90(%rbx), %rsi\n"
"  movq 0x98(%rbx), %rdi\n"
"  movq 0xa0(%rbx), %r12\n"
"  movq 0xa8(%rbx), %r13\n"
"  movq 0xb0(%rbx), %r14\n"
"  movq 0xb8(%rbx), %r15\n"
"  movq %rsp, 0xc0(%rbx)\n"
"  pushq 0x40(%rbx)\n"
"  popfq\n"
"  movq 0x38(%rbx), %r11\n"
"  movq 0x30(%rbx), %r10\n"
"  movq 0x28(%rbx), %r9\n"
"  movq 0x20(%rbx), %r8\n"
"  movq 0x18(%rbx), %rdx\n"
"  movq 0x10(%rbx), %rcx\n"
"  movq 0x08(%rbx), %rax\n"
"  callq *(%rbx)\n"
"  .globl cap_after\n"
"cap_after:\n"
"  movq %rax, g_out(%rip)\n"
"  leaq g_out(%rip), %rax\n"
"  movq %rcx, 0x08(%rax)\n"
"  movq %rdx, 0x10(%rax)\n"
"  movq %r8,  0x18(%rax)\n"
"  movq %r9,  0x20(%rax)\n"
"  movq %r10, 0x28(%rax)\n"
"  movq %r11, 0x30(%rax)\n"
"  pushfq\n"
"  popq 0x38(%rax)\n"
"  movq %rsp, 0x40(%rax)\n"
"  movq %rbx, 0x48(%rax)\n"
"  movq %rbp, 0x50(%rax)\n"
"  movq %rsi, 0x58(%rax)\n"
"  movq %rdi, 0x60(%rax)\n"
"  movq %r12, 0x68(%rax)\n"
"  movq %r13, 0x70(%rax)\n"
"  movq %r14, 0x78(%rax)\n"
"  movq %r15, 0x80(%rax)\n"
"  movdqu %xmm0, 0x100(%rax)\n"
"  movdqu %xmm1, 0x110(%rax)\n"
"  movdqu %xmm2, 0x120(%rax)\n"
"  movdqu %xmm3, 0x130(%rax)\n"
"  movdqu %xmm4, 0x140(%rax)\n"
"  movdqu %xmm5, 0x150(%rax)\n"
"  stmxcsr 0x88(%rax)\n"
"  fnstcw 0x8c(%rax)\n"
"  fnstsw 0x8e(%rax)\n"
"  fnstenv 0x90(%rax)\n"
"  fldenv 0x90(%rax)\n"
"  cld\n"
"  addq $0x68, %rsp\n"
"  popq %r15\n"
"  popq %r14\n"
"  popq %r13\n"
"  popq %r12\n"
"  popq %rdi\n"
"  popq %rsi\n"
"  popq %rbp\n"
"  popq %rbx\n"
"  retq\n"
/* Guarded one-instruction helpers. If the instruction between <name> and <name>_r raises an exception, the
 * vectored handler below resumes at <name>_r with rax = FAULT_MARK and remembers the exception code. */
"  .globl gi_rd32\n  .globl gi_rd32_r\n"
"gi_rd32:\n  movl (%rcx), %eax\ngi_rd32_r:\n  retq\n"
"  .globl gi_rdgs\n"
"gi_rdgs:\n  movq %gs:(%rcx), %rax\n  retq\n"
"  .globl gi_rdtsc\n"
"gi_rdtsc:\n  rdtsc\n  shlq $32, %rdx\n  orq %rdx, %rax\n  retq\n"
"  .globl gi_cs\n  .globl gi_ss\n  .globl gi_ds\n  .globl gi_es\n  .globl gi_fs\n  .globl gi_gs\n"
"gi_cs:\n  movl %cs, %eax\n  retq\n"
"gi_ss:\n  movl %ss, %eax\n  retq\n"
"gi_ds:\n  movl %ds, %eax\n  retq\n"
"gi_es:\n  movl %es, %eax\n  retq\n"
"gi_fs:\n  movl %fs, %eax\n  retq\n"
"gi_gs:\n  movl %gs, %eax\n  retq\n"
"  .globl gi_sidt\n  .globl gi_sidt_r\n"
"gi_sidt:\n  xorl %eax, %eax\n  sidt (%rcx)\ngi_sidt_r:\n  retq\n"
"  .globl gi_sgdt\n  .globl gi_sgdt_r\n"
"gi_sgdt:\n  xorl %eax, %eax\n  sgdt (%rcx)\ngi_sgdt_r:\n  retq\n"
"  .globl gi_sldt\n  .globl gi_sldt_r\n"
"gi_sldt:\n  xorl %eax, %eax\n  sldt %eax\ngi_sldt_r:\n  retq\n"
"  .globl gi_str\n  .globl gi_str_r\n"
"gi_str:\n  xorl %eax, %eax\n  str %eax\ngi_str_r:\n  retq\n"
"  .globl gi_smsw\n  .globl gi_smsw_r\n"
"gi_smsw:\n  xorl %eax, %eax\n  smsw %eax\ngi_smsw_r:\n  retq\n"
"  .globl gi_xgetbv\n  .globl gi_xgetbv_r\n"
"gi_xgetbv:\n  xorl %ecx, %ecx\n  xgetbv\n  shlq $32, %rdx\n  orq %rdx, %rax\ngi_xgetbv_r:\n  retq\n"
"  .globl gi_lsl\n  .globl gi_lsl_r\n"
"gi_lsl:\n  movl $0xEEEEEEEE, %eax\n  lsl %ecx, %eax\n  setz %dl\n  movzbl %dl, %edx\n  shlq $32, %rdx\n  orq %rdx, %rax\ngi_lsl_r:\n  retq\n"
"  .globl gi_lar\n  .globl gi_lar_r\n"
"gi_lar:\n  movl $0xEEEEEEEE, %eax\n  lar %ecx, %eax\n  setz %dl\n  movzbl %dl, %edx\n  shlq $32, %rdx\n  orq %rdx, %rax\ngi_lar_r:\n  retq\n"
"  .globl gi_cpuid\n"
"gi_cpuid:\n  pushq %rbx\n  movl %ecx, %eax\n  movl %edx, %ecx\n  cpuid\n  movl %eax, (%r8)\n  movl %ebx, 4(%r8)\n  movl %ecx, 8(%r8)\n  movl %edx, 12(%r8)\n  popq %rbx\n  retq\n"
/* rdtscp (0f 01 f9) and rdrand rax (48 0f c7 f0) are given as bytes so that any assembler accepts them */
"  .globl gi_rdtscp\n  .globl gi_rdtscp_r\n"
"gi_rdtscp:\n  movq %rcx, %r8\n  .byte 0x0f, 0x01, 0xf9\n  movl %ecx, (%r8)\n  shlq $32, %rdx\n  orq %rdx, %rax\ngi_rdtscp_r:\n  retq\n"
"  .globl gi_rdrand\n  .globl gi_rdrand_r\n"
"gi_rdrand:\n  movq %rcx, %r8\n  xorl %eax, %eax\n  .byte 0x48, 0x0f, 0xc7, 0xf0\n  setc %dl\n  movzbl %dl, %edx\n  movl %edx, (%r8)\ngi_rdrand_r:\n  retq\n"
);

/* ------------------------------------------------------------------ small runtime (no C library) */
void *memset(void *d, int c, u64 n) { volatile u8 *p = (volatile u8 *)d; while (n--) *p++ = (u8)c; return d; }
void *memcpy(void *d, const void *s, u64 n) { volatile u8 *p = (volatile u8 *)d; const volatile u8 *q = (const volatile u8 *)s; while (n--) *p++ = *q++; return d; }

static u64 rdn(const u8 *p, int n) { u64 v = 0; int i; for (i = n - 1; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static u64 rd64(const void *p) { return *(const volatile u64 *)p; }
static u32 rd32(const void *p) { return *(const volatile u32 *)p; }
static u16 rd16(const void *p) { return *(const volatile u16 *)p; }

static char obuf[1 << 16]; static u32 olen; static void *hout; static u32 ncell;
static void oflush(void) { u32 w = 0; if (olen) WriteFile(hout, obuf, olen, &w, 0); olen = 0; }
static void oc(char c) { if (olen >= sizeof(obuf) - 8) oflush(); obuf[olen++] = c; }
static void os(const char *s) { while (*s) oc(*s++); }
static char *hexd(char *o, u64 v) { int i, st = 0; for (i = 60; i >= 0; i -= 4) { u32 d = (u32)(v >> i) & 15; if (d || st || i == 0) { *o++ = (char)(d < 10 ? '0' + d : 'a' + d - 10); st = 1; } } return o; }
static void ojs(const char *s) {
    for (; *s; s++) { u8 c = (u8)*s; if (c == '"' || c == '\\') { oc('\\'); oc((char)c); } else if (c < 0x20 || c >= 0x7f) oc('?'); else oc((char)c); }
}
/* tiny formatter: %s string, %x hex with 0x, %X hex without prefix, %c char */
static void sfmt(char *o, const char *f, ...) {
    __builtin_va_list ap; __builtin_va_start(ap, f);
    for (; *f; f++) {
        if (*f != '%') { *o++ = *f; continue; }
        f++;
        if (*f == 's') { const char *s = __builtin_va_arg(ap, const char *); while (*s) *o++ = *s++; }
        else if (*f == 'x') { u64 v = __builtin_va_arg(ap, u64); *o++ = '0'; *o++ = 'x'; o = hexd(o, v); }
        else if (*f == 'X') { u64 v = __builtin_va_arg(ap, u64); o = hexd(o, v); }
        else if (*f == 'c') { *o++ = (char)__builtin_va_arg(ap, int); }
    }
    *o = 0; __builtin_va_end(ap);
}
static void cell(const char *name, const char *v, int has_raw, u64 raw) {
    char t[24];
    os("{\"c\":\""); ojs(name); os("\",\"v\":\""); ojs(v); oc('"');
    if (has_raw) { sfmt(t, "%x", raw); os(",\"raw\":\""); os(t); oc('"'); }
    os("}\n"); ncell++;
}
static void cell_s(const char *name, const char *v) { cell(name, v, 0, 0); }
static void cell_x(const char *name, u64 v) { char t[24]; sfmt(t, "%x", v); cell(name, t, 0, 0); }

/* ------------------------------------------------------------------ resolved functions */
static void *k32, *ntd;
static u64 (*pVirtualQuery)(const void *, void *, u64);
static void *(*pVirtualAlloc)(void *, u64, u32, u32);
static void *(*pAddVEH)(u32, void *);
static void (*pSleep)(u32);
static int (*pQPC)(u64 *), (*pQPF)(u64 *);
static u64 (*pGetTickCount64)(void);
static u32 (*pGetTickCount)(void);
static void (*pGSTAFT)(u64 *);
static int (*pQUIT)(u64 *);
static void *fK(const char *n) { return GetProcAddress(k32, n); }
static void *fN(const char *n) { return GetProcAddress(ntd, n); }

/* ------------------------------------------------------------------ address classes */
struct mbi { u64 BaseAddress, AllocationBase; u32 AllocationProtect, pad0; u64 RegionSize; u32 State, Protect, Type, pad1; };
struct mod { u64 base, size; char name[40], raw[40]; u32 flags; u16 loadcount, tls; };
static struct mod mods[64]; static int nmods;
static u64 heaps[16], heapalloc[16]; static int nheaps;
static u64 g_teb, g_peb, g_stack_lo, g_stack_hi, g_image;

static const char *seckind(u64 base, u64 rva) {
    const u8 *b = (const u8 *)base, *h, *s; u32 pe, i; u16 ns, so;
    if (b[0] != 'M' || b[1] != 'Z') return "?";
    pe = rd32(b + 0x3c); if (pe > 0x1000) return "?";
    h = b + pe; if (h[0] != 'P' || h[1] != 'E') return "?";
    ns = rd16(h + 6); so = rd16(h + 0x14); s = h + 0x18 + so;
    for (i = 0; i < ns && i < 96; i++, s += 40) {
        u32 vs = rd32(s + 8), va = rd32(s + 12), rs = rd32(s + 16), ch = rd32(s + 36), sz = vs ? vs : rs;
        if (rva >= va && rva < (u64)va + sz) return (ch & 0x20000000u) ? "x" : (ch & 0x80000000u) ? "w" : "r";
    }
    return rva < 0x1000 ? "hdr" : "gap";
}
/* returns 1 when v was recognised as an address (or zero), 0 when it is printed as a plain number */
static int classify(u64 v, char *o) {
    struct mbi m; int i;
    if (!v) { o[0] = '0'; o[1] = 0; return 1; }
    if (v >= USD && v < USD + 0x1000) { sfmt(o, "usd+%x", v - USD); return 1; }
    if (v >= g_teb && v < g_teb + 0x2000) { sfmt(o, "teb+%x", v - g_teb); return 1; }
    if (v >= g_peb && v < g_peb + 0x1000) { sfmt(o, "peb+%x", v - g_peb); return 1; }
    if (v >= g_stack_lo && v < g_stack_hi) { sfmt(o, "stack"); return 1; }
    for (i = 0; i < nmods; i++) if (v >= mods[i].base && v < mods[i].base + mods[i].size) {
        if (mods[i].base == g_image) sfmt(o, "exe:%s", seckind(mods[i].base, v - mods[i].base));
        else sfmt(o, "mod:%s:%s", mods[i].name, seckind(mods[i].base, v - mods[i].base));
        return 1;
    }
    if (v < 0x10000 || v >= 0x800000000000ULL) { sfmt(o, "%x", v); return 0; }
    memset(&m, 0, sizeof m);
    if (!pVirtualQuery((const void *)v, &m, sizeof m) || m.State == 0x10000) { sfmt(o, "%x", v); return 0; }
    for (i = 0; i < nheaps; i++) if (m.AllocationBase == heapalloc[i]) { sfmt(o, m.State == 0x2000 ? "heap-reserved" : "heap"); return 1; }
    sfmt(o, "%s%s", m.Type == 0x1000000 ? "image" : m.Type == 0x40000 ? "mapped" : m.Type == 0x20000 ? "private" : "region",
         m.State == 0x2000 ? "-reserved" : "");
    return 1;
}
static void cell_p(const char *name, u64 v) { char t[80]; classify(v, t); cell(name, t, 1, v); }

/* ------------------------------------------------------------------ exception handler */
struct guard { u64 start, resume; };
static struct guard guards[16]; static int nguards;
static volatile u32 g_fault_code, g_fault_n, veh_n, veh_code0;
static long veh(void **ep) {
    u32 code = rd32(ep[0]); u8 *ctx = (u8 *)ep[1]; u64 rip = rd64(ctx + 0xf8); int i;
    for (i = 0; i < nguards; i++) if (rip >= guards[i].start && rip < guards[i].resume) {
        g_fault_code = code; g_fault_n++;
        *(u64 *)(ctx + 0x78) = FAULT_MARK;        /* Rax */
        *(u64 *)(ctx + 0xf8) = guards[i].resume;  /* Rip */
        return -1;                                /* EXCEPTION_CONTINUE_EXECUTION */
    }
    if (!veh_n) veh_code0 = code;
    veh_n++;
    return 0;                                     /* EXCEPTION_CONTINUE_SEARCH */
}
static long dummy_veh(void **ep) { (void)ep; return 0; }
static void add_guard(void *start, void *resume) { guards[nguards].start = (u64)start; guards[nguards].resume = (u64)resume; nguards++; }
static u32 usd32(u32 off) { return gi_rd32((const void *)(USD + off)); }

/* ------------------------------------------------------------------ field tables */
struct fld { const char *name; u16 off; u8 size; char kind; };   /* kind: V value, P pointer class, I identifier, T KSYSTEM_TIME */
static const struct fld peb_f[] = {
    {"InheritedAddressSpace",0x000,1,'V'},{"ReadImageFileExecOptions",0x001,1,'V'},{"BeingDebugged",0x002,1,'V'},{"BitField",0x003,1,'V'},
    {"Mutant",0x008,8,'P'},{"ImageBaseAddress",0x010,8,'P'},{"Ldr",0x018,8,'P'},{"ProcessParameters",0x020,8,'P'},{"SubSystemData",0x028,8,'P'},
    {"ProcessHeap",0x030,8,'P'},{"FastPebLock",0x038,8,'P'},{"AtlThunkSListPtr",0x040,8,'P'},{"IFEOKey",0x048,8,'P'},{"CrossProcessFlags",0x050,4,'V'},
    {"KernelCallbackTable",0x058,8,'P'},{"SystemReserved",0x060,4,'V'},{"AtlThunkSListPtr32",0x064,4,'V'},{"ApiSetMap",0x068,8,'P'},
    {"TlsExpansionCounter",0x070,4,'V'},{"TlsBitmap",0x078,8,'P'},{"TlsBitmapBits",0x080,8,'V'},{"ReadOnlySharedMemoryBase",0x088,8,'P'},
    {"SharedData",0x090,8,'P'},{"ReadOnlyStaticServerData",0x098,8,'P'},{"AnsiCodePageData",0x0a0,8,'P'},{"OemCodePageData",0x0a8,8,'P'},
    {"UnicodeCaseTableData",0x0b0,8,'P'},{"NumberOfProcessors",0x0b8,4,'V'},{"NtGlobalFlag",0x0bc,4,'V'},{"CriticalSectionTimeout",0x0c0,8,'V'},
    {"HeapSegmentReserve",0x0c8,8,'V'},{"HeapSegmentCommit",0x0d0,8,'V'},{"HeapDeCommitTotalFreeThreshold",0x0d8,8,'V'},
    {"HeapDeCommitFreeBlockThreshold",0x0e0,8,'V'},{"NumberOfHeaps",0x0e8,4,'V'},{"MaximumNumberOfHeaps",0x0ec,4,'V'},{"ProcessHeaps",0x0f0,8,'P'},
    {"GdiSharedHandleTable",0x0f8,8,'P'},{"ProcessStarterHelper",0x100,8,'P'},{"GdiDCAttributeList",0x108,4,'V'},{"LoaderLock",0x110,8,'P'},
    {"OSMajorVersion",0x118,4,'V'},{"OSMinorVersion",0x11c,4,'V'},{"OSBuildNumber",0x120,2,'V'},{"OSCSDVersion",0x122,2,'V'},{"OSPlatformId",0x124,4,'V'},
    {"ImageSubsystem",0x128,4,'V'},{"ImageSubsystemMajorVersion",0x12c,4,'V'},{"ImageSubsystemMinorVersion",0x130,4,'V'},
    {"ActiveProcessAffinityMask",0x138,8,'V'},{"PostProcessInitRoutine",0x230,8,'P'},{"TlsExpansionBitmap",0x238,8,'P'},
    {"SessionId",0x2c0,4,'V'},{"AppCompatFlags",0x2c8,8,'V'},{"AppCompatFlagsUser",0x2d0,8,'V'},{"pShimData",0x2d8,8,'P'},{"AppCompatInfo",0x2e0,8,'P'},
    {"CSDVersion.Length",0x2e8,2,'V'},{"CSDVersion.MaximumLength",0x2ea,2,'V'},{"CSDVersion.Buffer",0x2f0,8,'P'},
    {"ActivationContextData",0x2f8,8,'P'},{"ProcessAssemblyStorageMap",0x300,8,'P'},{"SystemDefaultActivationContextData",0x308,8,'P'},
    {"SystemAssemblyStorageMap",0x310,8,'P'},{"MinimumStackCommit",0x318,8,'V'},{"SparePointers0",0x320,8,'P'},{"SparePointers1",0x328,8,'P'},
    {"PatchLoaderData",0x330,8,'P'},{"ChpeV2ProcessInfo",0x338,8,'P'},{"AppModelFeatureState",0x340,4,'V'},{"SpareUlongs",0x344,8,'V'},
    {"ActiveCodePage",0x34c,2,'V'},{"OemCodePage",0x34e,2,'V'},{"UseCaseMapping",0x350,2,'V'},{"UnusedNlsField",0x352,2,'V'},
    {"WerRegistrationData",0x358,8,'P'},{"WerShipAssertPtr",0x360,8,'P'},{"EcCodeBitMap",0x368,8,'P'},{"pImageHeaderHash",0x370,8,'P'},
    {"TracingFlags",0x378,4,'V'},{"CsrServerReadOnlySharedMemoryBase",0x380,8,'P'},{"TppWorkerpListLock",0x388,8,'V'},
    {"TppWorkerpList.Flink",0x390,8,'P'},{"TppWorkerpList.Blink",0x398,8,'P'},{"TelemetryCoverageHeader",0x7a0,8,'P'},
    {"CloudFileFlags",0x7a8,4,'V'},{"CloudFileDiagFlags",0x7ac,4,'V'},{"PlaceholderCompatibilityMode",0x7b0,1,'V'},
    {"LeapSecondData",0x7b8,8,'P'},{"LeapSecondFlags",0x7c0,4,'V'},{"NtGlobalFlag2",0x7c4,4,'V'},{"ExtendedFeatureDisableMask",0x7c8,8,'V'},
};
static const struct fld teb_f[] = {
    {"NtTib.ExceptionList",0x000,8,'P'},{"NtTib.StackBase",0x008,8,'P'},{"NtTib.StackLimit",0x010,8,'P'},{"NtTib.SubSystemTib",0x018,8,'P'},
    {"NtTib.FiberData",0x020,8,'P'},{"NtTib.ArbitraryUserPointer",0x028,8,'P'},{"NtTib.Self",0x030,8,'P'},{"EnvironmentPointer",0x038,8,'P'},
    {"ClientId.UniqueProcess",0x040,8,'I'},{"ClientId.UniqueThread",0x048,8,'I'},{"ActiveRpcHandle",0x050,8,'P'},
    {"ThreadLocalStoragePointer",0x058,8,'P'},{"ProcessEnvironmentBlock",0x060,8,'P'},{"LastErrorValue",0x068,4,'V'},
    {"CountOfOwnedCriticalSections",0x06c,4,'V'},{"CsrClientThread",0x070,8,'P'},{"Win32ThreadInfo",0x078,8,'P'},{"WOW32Reserved",0x100,8,'P'},
    {"CurrentLocale",0x108,4,'V'},{"FpSoftwareStatusRegister",0x10c,4,'V'},{"PlaceholderCompatibilityMode",0x280,1,'V'},
    {"ProxiedProcessId",0x28c,4,'V'},{"ActivationStack.ActiveFrame",0x290,8,'P'},{"ActivationStack.FrameListCache.Flink",0x298,8,'P'},
    {"ActivationStack.FrameListCache.Blink",0x2a0,8,'P'},{"ActivationStack.Flags",0x2a8,4,'V'},{"ActivationStack.NextCookieSequenceNumber",0x2ac,4,'V'},
    {"ActivationStack.StackId",0x2b0,4,'V'},{"ExceptionCode",0x2c0,4,'V'},{"ActivationContextStackPointer",0x2c8,8,'P'},
    {"InstrumentationCallbackSp",0x2d0,8,'P'},{"InstrumentationCallbackPreviousPc",0x2d8,8,'P'},{"InstrumentationCallbackPreviousSp",0x2e0,8,'P'},
    {"TxFsContext",0x2e8,4,'V'},{"InstrumentationCallbackDisabled",0x2ec,1,'V'},{"UnalignedLoadStoreExceptions",0x2ed,1,'V'},
    {"RealClientId.UniqueProcess",0x7d8,8,'I'},{"RealClientId.UniqueThread",0x7e0,8,'I'},{"GdiCachedProcessHandle",0x7e8,8,'P'},
    {"GdiClientPID",0x7f0,4,'V'},{"GdiClientTID",0x7f4,4,'V'},{"GdiThreadLocalInfo",0x7f8,8,'P'},{"LastStatusValue",0x1250,4,'V'},
    {"StaticUnicodeString.Length",0x1258,2,'V'},{"StaticUnicodeString.MaximumLength",0x125a,2,'V'},{"StaticUnicodeString.Buffer",0x1260,8,'P'},
    {"DeallocationStack",0x1478,8,'P'},{"TlsLinks.Flink",0x1680,8,'P'},{"TlsLinks.Blink",0x1688,8,'P'},{"Vdm",0x1690,8,'P'},
    {"ReservedForNtRpc",0x1698,8,'P'},{"HardErrorMode",0x16b0,4,'V'},{"SubProcessTag",0x1720,8,'P'},{"PerflibData",0x1728,8,'P'},
    {"EtwTraceData",0x1730,8,'P'},{"WinSockData",0x1738,8,'P'},{"GdiBatchCount",0x1740,4,'V'},{"IdealProcessorValue",0x1744,4,'V'},
    {"GuaranteedStackBytes",0x1748,4,'V'},{"ReservedForPerf",0x1750,8,'P'},{"ReservedForOle",0x1758,8,'P'},{"WaitingOnLoaderLock",0x1760,4,'V'},
    {"SavedPriorityState",0x1768,8,'P'},{"ReservedForCodeCoverage",0x1770,8,'V'},{"ThreadPoolData",0x1778,8,'P'},{"TlsExpansionSlots",0x1780,8,'P'},
    {"ChpeV2CpuAreaInfo",0x1788,8,'P'},{"Unused",0x1790,8,'P'},{"MuiGeneration",0x1798,4,'V'},{"IsImpersonating",0x179c,4,'V'},
    {"NlsCache",0x17a0,8,'P'},{"pShimData",0x17a8,8,'P'},{"HeapData",0x17b0,4,'V'},{"CurrentTransactionHandle",0x17b8,8,'P'},
    {"ActiveFrame",0x17c0,8,'P'},{"FlsData",0x17c8,8,'P'},{"PreferredLanguages",0x17d0,8,'P'},{"UserPrefLanguages",0x17d8,8,'P'},
    {"MergedPrefLanguages",0x17e0,8,'P'},{"MuiImpersonation",0x17e8,4,'V'},{"CrossTebFlags",0x17ec,2,'V'},{"SameTebFlags",0x17ee,2,'V'},
    {"TxnScopeEnterCallback",0x17f0,8,'P'},{"TxnScopeExitCallback",0x17f8,8,'P'},{"TxnScopeContext",0x1800,8,'P'},{"LockCount",0x1808,4,'V'},
    {"WowTebOffset",0x180c,4,'V'},{"ResourceRetValue",0x1810,8,'P'},{"ReservedForWdf",0x1818,8,'P'},{"ReservedForCrt",0x1820,8,'V'},
    {"LastSleepCounter",0x1838,8,'V'},{"SpinCallCount",0x1840,4,'V'},{"ExtendedFeatureDisableMask",0x1848,8,'V'},
};
static const struct fld usd_f[] = {
    {"TickCountLowDeprecated",0x000,4,'V'},{"TickCountMultiplier",0x004,4,'V'},{"InterruptTime",0x008,12,'T'},{"SystemTime",0x014,12,'T'},
    {"TimeZoneBias",0x020,12,'T'},{"ImageNumberLow",0x02c,2,'V'},{"ImageNumberHigh",0x02e,2,'V'},{"MaxStackTraceDepth",0x238,4,'V'},
    {"CryptoExponent",0x23c,4,'V'},{"TimeZoneId",0x240,4,'V'},{"LargePageMinimum",0x244,4,'V'},{"AitSamplingValue",0x248,4,'V'},
    {"AppCompatFlag",0x24c,4,'V'},{"RNGSeedVersion",0x250,8,'V'},{"GlobalValidationRunlevel",0x258,4,'V'},{"TimeZoneBiasStamp",0x25c,4,'V'},
    {"NtBuildNumber",0x260,4,'V'},{"NtProductType",0x264,4,'V'},{"ProductTypeIsValid",0x268,1,'V'},{"Reserved0",0x269,1,'V'},
    {"NativeProcessorArchitecture",0x26a,2,'V'},{"NtMajorVersion",0x26c,4,'V'},{"NtMinorVersion",0x270,4,'V'},{"Reserved1",0x2b4,4,'V'},
    {"Reserved3",0x2b8,4,'V'},{"TimeSlip",0x2bc,4,'V'},{"AlternativeArchitecture",0x2c0,4,'V'},{"BootId",0x2c4,4,'V'},
    {"SystemExpirationDate",0x2c8,8,'V'},{"SuiteMask",0x2d0,4,'V'},{"KdDebuggerEnabled",0x2d4,1,'V'},{"MitigationPolicies",0x2d5,1,'V'},
    {"CyclesPerYield",0x2d6,2,'V'},{"ActiveConsoleId",0x2d8,4,'V'},{"DismountCount",0x2dc,4,'V'},{"ComPlusPackage",0x2e0,4,'V'},
    {"LastSystemRITEventTickCount",0x2e4,4,'V'},{"NumberOfPhysicalPages",0x2e8,4,'V'},{"SafeBootMode",0x2ec,1,'V'},{"VirtualizationFlags",0x2ed,1,'V'},
    {"Reserved12",0x2ee,2,'V'},{"SharedDataFlags",0x2f0,4,'V'},{"DataFlagsPad",0x2f4,4,'V'},{"TestRetInstruction",0x2f8,8,'V'},
    {"QpcFrequency",0x300,8,'V'},{"SystemCall",0x308,4,'V'},{"Reserved2",0x30c,4,'V'},{"SystemCallPad0",0x310,8,'V'},{"SystemCallPad1",0x318,8,'V'},
    {"TickCount",0x320,12,'T'},{"TickCountPad",0x32c,4,'V'},{"Cookie",0x330,4,'V'},{"CookiePad",0x334,4,'V'},
    {"ConsoleSessionForegroundProcessId",0x338,8,'V'},{"TimeUpdateLock",0x340,8,'V'},{"BaselineSystemTimeQpc",0x348,8,'V'},
    {"BaselineInterruptTimeQpc",0x350,8,'V'},{"QpcSystemTimeIncrement",0x358,8,'V'},{"QpcInterruptTimeIncrement",0x360,8,'V'},
    {"QpcSystemTimeIncrementShift",0x368,1,'V'},{"QpcInterruptTimeIncrementShift",0x369,1,'V'},{"UnparkedProcessorCount",0x36a,2,'V'},
    {"TelemetryCoverageRound",0x37c,4,'V'},{"ImageFileExecutionOptions",0x3a0,4,'V'},{"LangGenerationCount",0x3a4,4,'V'},{"Reserved4",0x3a8,8,'V'},
    {"InterruptTimeBias",0x3b0,8,'V'},{"QpcBias",0x3b8,8,'V'},{"ActiveProcessorCount",0x3c0,4,'V'},{"ActiveGroupCount",0x3c4,1,'V'},
    {"Reserved9",0x3c5,1,'V'},{"QpcBypassEnabled",0x3c6,1,'V'},{"QpcShift",0x3c7,1,'V'},{"TimeZoneBiasEffectiveStart",0x3c8,8,'V'},
    {"TimeZoneBiasEffectiveEnd",0x3d0,8,'V'},{"XState.EnabledFeatures",0x3d8,8,'V'},{"XState.EnabledVolatileFeatures",0x3e0,8,'V'},
    {"XState.Size",0x3e8,4,'V'},{"XState.ControlFlags",0x3ec,4,'V'},
};
static const struct fld par_f[] = {
    {"MaximumLength",0x00,4,'V'},{"Length",0x04,4,'V'},{"Flags",0x08,4,'V'},{"DebugFlags",0x0c,4,'V'},{"ConsoleHandle",0x10,8,'H'},
    {"ConsoleFlags",0x18,4,'V'},{"StandardInput",0x20,8,'H'},{"StandardOutput",0x28,8,'H'},{"StandardError",0x30,8,'H'},
    {"StartingX",0x88,4,'V'},{"StartingY",0x8c,4,'V'},{"CountX",0x90,4,'V'},{"CountY",0x94,4,'V'},{"CountCharsX",0x98,4,'V'},
    {"CountCharsY",0x9c,4,'V'},{"FillAttribute",0xa0,4,'V'},{"WindowFlags",0xa4,4,'V'},{"ShowWindowFlags",0xa8,4,'V'},
    {"EnvironmentVersion",0x3f8,8,'V'},{"PackageDependencyData",0x400,8,'P'},{"ProcessGroupId",0x408,4,'I'},{"LoaderThreads",0x40c,4,'V'},
};
#define NF(a) ((int)(sizeof(a) / sizeof(a[0])))

static u8 teb_snap[0x1850], peb_snap[0x7d0], usd_snap[0x800], usd_snap2[0x800], par_snap[0x440];
static u8 cov[0x1850];

static void emit_fields(const char *sec, const struct fld *f, int n, const u8 *snap, u32 snaplen) {
    char nm[112], t[80]; int i; u32 k;
    memset(cov, 0, sizeof cov);
    for (i = 0; i < n; i++) {
        u64 v;
        if ((u32)f[i].off + f[i].size > snaplen) continue;
        for (k = 0; k < f[i].size; k++) cov[f[i].off + k] = 1;
        sfmt(nm, "%s.%s", sec, f[i].name);
        if (f[i].kind == 'T') { v = ((u64)rd32(snap + f[i].off + 4) << 32) | rd32(snap + f[i].off); cell_x(nm, v); continue; }
        v = rdn(snap + f[i].off, f[i].size);
        if (f[i].kind == 'P') cell_p(nm, v);
        else if (f[i].kind == 'I') { sfmt(t, "id:mod4=%x", v & 3); cell(nm, t, 1, v); }
        else if (f[i].kind == 'H') {
            if (!v) sfmt(t, "0"); else if ((i64)v < 0 && (i64)v >= -16) sfmt(t, "%x", v); else sfmt(t, "handle:low2=%x", v & 3);
            cell(nm, t, 1, v);
        }
        else cell_x(nm, v);
    }
}
/* every other non-zero word of the snapshot that the table above does not name */
static void emit_rest(const char *sec, const u8 *snap, u32 snaplen, int step, int ptrs) {
    char nm[64]; u32 o; int k, uncovered;
    for (o = 0; o + step <= snaplen; o += step) {
        u64 v = 0;
        uncovered = 0;
        for (k = step - 1; k >= 0; k--) { v <<= 8; if (!cov[o + k]) { uncovered = 1; v |= snap[o + k]; } }
        if (!uncovered || !v) continue;
        sfmt(nm, "%s.+%x", sec, (u64)o);
        if (ptrs) cell_p(nm, v); else cell_x(nm, v);
    }
}
static void wstr(const u8 *w, u32 nchars, char *o, u32 max, int lower) {
    u32 i; for (i = 0; i < nchars && i + 1 < max; i++) { u16 c = rd16(w + 2 * i); if (!c) break; if (lower && c >= 'A' && c <= 'Z') c += 32; o[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?'; }
    o[i] = 0;
}

/* ------------------------------------------------------------------ section: entry, PEB, TEB, loader, heaps */
static const char *gpr_name[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
static void xmm_text(const u64 *q, u64 pat, char *o) {
    char a[80], b[80];
    if (q[0] == pat && q[1] == pat) { sfmt(o, "kept"); return; }
    if (q[0] == pat) sfmt(a, "pat"); else classify(q[0], a);
    if (q[1] == pat) sfmt(b, "pat"); else classify(q[1], b);
    sfmt(o, "%s|%s", b, a);
}
static void sec_entry(void) {
    char nm[64], t[200]; int i;
    for (i = 0; i < 16; i++) { sfmt(nm, "entry.%s", gpr_name[i]); cell_p(nm, g_entry[i]); }
    cell_x("entry.rsp_low4", g_entry[4] & 15);
    cell_p("entry.return_address", g_entry[0x14]);
    cell_x("entry.eflags", g_entry[0x10]);
    cell_x("entry.mxcsr", (u32)g_entry[0x11]);
    cell_x("entry.x87_control", (u16)(g_entry[0x11] >> 32));
    cell_x("entry.x87_status", (u16)(g_entry[0x11] >> 48));
    cell_x("entry.cs", (u16)g_entry[0x12]); cell_x("entry.ss", (u16)(g_entry[0x12] >> 16));
    cell_x("entry.ds", (u16)(g_entry[0x12] >> 32)); cell_x("entry.es", (u16)(g_entry[0x12] >> 48));
    cell_x("entry.fs", (u16)g_entry[0x13]); cell_x("entry.gs", (u16)(g_entry[0x13] >> 16));
    for (i = 0; i < 6; i++) { sfmt(nm, "entry.xmm%X", (u64)i); xmm_text(&g_entry[0x20 + 2 * i], 0x1ULL << 63 | 0x7777, t); cell_s(nm, t); }
}
static void walk_list(const char *name, u64 head, u32 linkoff) {
    char t[900], one[48]; u32 n = 0, len = 0; u64 e = rd64((void *)head);
    t[0] = 0;
    while (e && e != head && n < 24) {
        u64 ent = e - linkoff; u16 l = rd16((void *)(ent + 0x58)); u64 b = rd64((void *)(ent + 0x60)); u32 k;
        one[0] = 0; if (b) wstr((const u8 *)b, l / 2u, one, sizeof one, 0);
        if (len > 820) break;
        if (n) t[len++] = ',';
        for (k = 0; one[k]; k++) t[len++] = one[k];
        t[len] = 0; n++; e = rd64((void *)e);
    }
    cell_s(name, t);
}
static void sec_process(void) {
    char nm[112], t[200]; u64 ldr, head, e, par, csd; int i; u32 nh; u64 ph;
    emit_fields("peb", peb_f, NF(peb_f), peb_snap, sizeof peb_snap);
    emit_rest("peb", peb_snap, sizeof peb_snap, 8, 1);
    csd = rdn(peb_snap + 0x2f0, 8);
    if (csd) { wstr((const u8 *)csd, rd16(peb_snap + 0x2e8) / 2u, t, sizeof t, 0); cell_s("peb.CSDVersion.text", t); }
    emit_fields("teb", teb_f, NF(teb_f), teb_snap, sizeof teb_snap);
    emit_rest("teb", teb_snap, sizeof teb_snap, 8, 1);
    oflush();
    /* loader data */
    ldr = rdn(peb_snap + 0x18, 8);
    cell_x("ldr.Length", rd32((void *)ldr)); cell_x("ldr.Initialized", *(u8 *)(ldr + 4)); cell_p("ldr.SsHandle", rd64((void *)(ldr + 8)));
    cell_p("ldr.EntryInProgress", rd64((void *)(ldr + 0x40))); cell_x("ldr.ShutdownInProgress", *(u8 *)(ldr + 0x48));
    cell_p("ldr.ShutdownThreadId", rd64((void *)(ldr + 0x50)));
    walk_list("ldr.order.load", ldr + 0x10, 0x00);
    walk_list("ldr.order.memory", ldr + 0x20, 0x10);
    walk_list("ldr.order.init", ldr + 0x30, 0x20);
    head = ldr + 0x10; e = rd64((void *)head); i = 0;
    while (e && e != head && i < nmods) {
        const char *mn = mods[i].base == g_image ? "exe" : mods[i].name;
        sfmt(nm, "ldr.mod.%s.Flags", mn); cell_x(nm, mods[i].flags);
        sfmt(nm, "ldr.mod.%s.LoadCount", mn); cell_x(nm, mods[i].loadcount);
        sfmt(nm, "ldr.mod.%s.TlsIndex", mn); cell_x(nm, mods[i].tls);
        sfmt(nm, "ldr.mod.%s.EntryPoint", mn); cell_p(nm, rd64((void *)(e + 0x38)));
        sfmt(nm, "ldr.mod.%s.BaseDllName", mn); cell_s(nm, mods[i].raw);
        i++; e = rd64((void *)e);
    }
    cell_x("ldr.count", (u64)nmods);
    /* heaps */
    nh = rd32(peb_snap + 0xe8); ph = rdn(peb_snap + 0xf0, 8);
    cell_x("heap.listed_in_peb", nh);
    for (i = 0; i < nheaps; i++) {
        u64 h = heaps[i];
        if (!h) continue;
        sfmt(nm, "heap.%X.is_process_heap", (u64)i); cell_x(nm, h == rdn(peb_snap + 0x30, 8));
        sfmt(nm, "heap.%X.Signature", (u64)i); cell_x(nm, rd32((void *)(h + 0x10)));
        sfmt(nm, "heap.%X.Flags", (u64)i); cell_x(nm, rd32((void *)(h + 0x70)));
        sfmt(nm, "heap.%X.ForceFlags", (u64)i); cell_x(nm, rd32((void *)(h + 0x74)));
    }
    (void)ph;
    /* process parameters */
    par = rdn(peb_snap + 0x20, 8);
    if (par) {
        memcpy(par_snap, (void *)par, sizeof par_snap);
        emit_fields("params", par_f, NF(par_f), par_snap, sizeof par_snap);
    }
    oflush();
}
static void build_maps(void) {
    u64 ldr = rdn(peb_snap + 0x18, 8), head = ldr + 0x10, e = rd64((void *)head), ph; u32 nh, i; struct mbi m;
    g_image = rdn(peb_snap + 0x10, 8);
    g_stack_hi = rdn(teb_snap + 0x08, 8);
    g_stack_lo = rdn(teb_snap + 0x1478, 8); if (!g_stack_lo) g_stack_lo = rdn(teb_snap + 0x10, 8);
    while (e && e != head && nmods < 64) {
        struct mod *md = &mods[nmods]; u16 l = rd16((void *)(e + 0x58)); u64 b = rd64((void *)(e + 0x60));
        md->base = rd64((void *)(e + 0x30)); md->size = rd32((void *)(e + 0x40));
        md->flags = rd32((void *)(e + 0x68)); md->loadcount = rd16((void *)(e + 0x6c)); md->tls = rd16((void *)(e + 0x6e));
        md->name[0] = md->raw[0] = 0;
        if (b) { wstr((const u8 *)b, l / 2u, md->name, sizeof md->name, 1); wstr((const u8 *)b, l / 2u, md->raw, sizeof md->raw, 0); }
        nmods++; e = rd64((void *)e);
    }
    nh = rd32(peb_snap + 0xe8); ph = rdn(peb_snap + 0xf0, 8);
    heaps[nheaps++] = rdn(peb_snap + 0x30, 8);
    for (i = 0; ph && i < nh && nheaps < 16; i++) {
        u64 h = rd64((void *)(ph + 8 * i));
        if (h && h != heaps[0]) heaps[nheaps++] = h;
    }
    for (i = 0; i < (u32)nheaps; i++) {
        memset(&m, 0, sizeof m);
        heapalloc[i] = pVirtualQuery((void *)heaps[i], &m, sizeof m) ? m.AllocationBase : heaps[i];
    }
}

/* ------------------------------------------------------------------ section: shared user data page */
static void usd_take(u8 *dst) { u32 o; for (o = 0; o < 0x800; o += 4) { u32 v = usd32(o); memcpy(dst + o, &v, 4); } }
static void sec_usd(void) {
    char nm[64], t[300]; u32 o, i; static const char hx[] = "0123456789abcdef";
    g_fault_n = 0; g_fault_code = 0;
    usd_take(usd_snap);
    cell_x("usd.read_faults", g_fault_n); cell_x("usd.read_fault_code", g_fault_code);
    for (o = 0; o < 0x800; o += 32) {
        for (i = 0; i < 32; i++) { t[2 * i] = hx[usd_snap[o + i] >> 4]; t[2 * i + 1] = hx[usd_snap[o + i] & 15]; }
        t[64] = 0; sfmt(nm, "usdraw.%x", (u64)o); cell_s(nm, t);
    }
    emit_fields("usd", usd_f, NF(usd_f), usd_snap, sizeof usd_snap);
    for (i = 0x30; i < 0x238; i++) cov[i] = 1;      /* NtSystemRoot */
    for (i = 0x274; i < 0x2b4; i++) cov[i] = 1;     /* ProcessorFeatures */
    emit_rest("usd", usd_snap, sizeof usd_snap, 4, 0);
    wstr(usd_snap + 0x30, 260, t, sizeof t, 0); cell_s("usd.NtSystemRoot", t);
    for (i = 0; i < 64; i++) t[i] = usd_snap[0x274 + i] == 0 ? '0' : usd_snap[0x274 + i] == 1 ? '1' : 'x';
    t[64] = 0; cell_s("usd.ProcessorFeatures", t);
    oflush();
}
static void sec_usd_changed(void) {
    char t[1200]; u32 o, len = 0, n = 0; char one[16]; u32 k;
    usd_take(usd_snap2);
    for (o = 0; o < 0x800; o += 4) if (rd32(usd_snap + o) != rd32(usd_snap2 + o) && n < 80) {
        sfmt(one, "%x", (u64)o); if (n) t[len++] = ','; for (k = 0; one[k]; k++) t[len++] = one[k]; n++;
    }
    t[len] = 0; cell_s("usd.words_changed_during_run", t);
    oflush();
}

/* ------------------------------------------------------------------ section: registers left after a call */
#define PAT_RAX 0x0A0A0A0A0A0A0A0AULL
#define PAT_RCX 0x0C0C0C0C0C0C0C0CULL
#define PAT_RDX 0x0D0D0D0D0D0D0D0DULL
#define PAT_R8  0x0808080808080808ULL
#define PAT_R9  0x0909090909090909ULL
#define PAT_R10 0x1010101010101010ULL
#define PAT_R11 0x1111111111111111ULL
#define PAT_NV  0x4E4E4E4E4E4E0000ULL
#define PAT_STK 0x5757575757570000ULL
#define FL_CLEAR 0x202ULL
#define FL_SET   0xAD7ULL    /* CF PF AF ZF SF OF all set */
struct rec {
    const char *name; u8 pass, missing, nargs, valret; u64 in[44], out[44]; u32 gle, lst, vehn, vehc;
    const u8 *buf; u32 buflen; u8 poison; u8 head[16]; u8 wr[160]; u32 retlen; u8 has_retlen, show_head;
    u64 extra[8]; u8 nextra; const char *extra_name[8];
};
static struct rec recs[120]; static int nrec;
static u8 ctx_buf[0x500] __attribute__((aligned(16)));
static u8 io_buf[64] __attribute__((aligned(16)));
static u8 mbi_buf[64] __attribute__((aligned(16)));
static volatile u32 g_retlen; static u64 g_zero_time, g_pv_base, g_pv_size; static u8 *g_page; static char g_probe_static;
static const char *passname[3] = {"A", "B", "C"};

static struct rec *docall(const char *name, void *fn, int nargs, const u64 *a, int pass, u8 *buf, u32 buflen, u32 ctxflags) {
    struct rec *r = &recs[nrec++]; int i; u32 k; u8 poison = pass == 1 ? 0x5a : 0xa5;
    static const u64 pat[7] = {PAT_RAX, PAT_RCX, PAT_RDX, PAT_R8, PAT_R9, PAT_R10, PAT_R11};
    memset(r, 0, sizeof *r); r->name = name; r->pass = (u8)pass; r->nargs = (u8)nargs; r->buf = buf; r->buflen = buflen; r->poison = poison;
    if (!fn) { r->missing = 1; return r; }
    memset(g_in, 0, sizeof g_in); memset(g_out, 0xee, sizeof g_out);
    g_in[0] = (u64)fn;
    for (i = 0; i < 7; i++) g_in[1 + i] = pat[i];
    for (i = 0; i < nargs && i < 4; i++) g_in[2 + i] = a[i];
    g_in[8] = pass == 1 ? FL_SET : FL_CLEAR;
    for (i = 0; i < 8; i++) g_in[9 + i] = (i + 4 < nargs) ? a[i + 4] : PAT_STK + (u64)i;
    for (i = 0; i < 7; i++) g_in[0x11 + i] = PAT_NV + (u64)i;
    for (i = 0; i < 6; i++) { g_in[0x20 + 2 * i] = g_in[0x21 + 2 * i] = 0xE0E0E0E0E0E0E0E0ULL + 0x0101010101010101ULL * (u64)i; }
    g_in[0x19] = 0x1f80;                           /* MXCSR loaded before the call: default, no sticky flags */
    if (buf) { memset(buf, poison, buflen); if (ctxflags) memcpy(buf + 0x30, &ctxflags, 4); }
    g_retlen = poison * 0x01010101u;
    *(volatile u32 *)(g_teb + 0x68) = GLE_MARK; *(volatile u32 *)(g_teb + 0x1250) = LST_MARK;
    veh_n = 0; veh_code0 = 0;
    cap_call();
    r->gle = *(volatile u32 *)(g_teb + 0x68); r->lst = *(volatile u32 *)(g_teb + 0x1250);
    r->vehn = veh_n; r->vehc = veh_code0; r->retlen = g_retlen;
    memcpy(r->in, g_in, sizeof r->in); memcpy(r->out, g_out, sizeof r->out);
    if (buf) {
        for (k = 0; k < 16 && k < buflen; k++) r->head[k] = buf[k];
        for (k = 0; k < buflen && k < 8 * sizeof r->wr; k++)
            if (buf[k] != poison && !(ctxflags && k >= 0x30 && k < 0x34)) r->wr[k >> 3] |= (u8)(1u << (k & 7));
    }
    return r;
}
static void addx(struct rec *r, const char *n, u64 v) { if (r->nextra < 8) { r->extra_name[r->nextra] = n; r->extra[r->nextra++] = v; } }
static void ctx_extra(struct rec *r) {
    addx(r, "ContextFlags", rd32(ctx_buf + 0x30)); addx(r, "Dr0", rd64(ctx_buf + 0x48)); addx(r, "Dr1", rd64(ctx_buf + 0x50));
    addx(r, "Dr2", rd64(ctx_buf + 0x58)); addx(r, "Dr3", rd64(ctx_buf + 0x60)); addx(r, "Dr6", rd64(ctx_buf + 0x68)); addx(r, "Dr7", rd64(ctx_buf + 0x70));
}
static void mbi_extra(struct rec *r) {
    addx(r, "mbi.AllocationProtect", rd32(mbi_buf + 0x10)); addx(r, "mbi.State", rd32(mbi_buf + 0x20));
    addx(r, "mbi.Protect", rd32(mbi_buf + 0x24)); addx(r, "mbi.Type", rd32(mbi_buf + 0x28));
}
static void do_pass(int p) {
    u64 a[8]; struct rec *r; u64 h;
#define A1(x0) (a[0] = (u64)(x0), a)
#define A2(x0, x1) (a[0] = (u64)(x0), a[1] = (u64)(x1), a)
#define A3(x0, x1, x2) (a[0] = (u64)(x0), a[1] = (u64)(x1), a[2] = (u64)(x2), a)
#define A4(x0, x1, x2, x3) (a[0] = (u64)(x0), a[1] = (u64)(x1), a[2] = (u64)(x2), a[3] = (u64)(x3), a)
#define A5(x0, x1, x2, x3, x4) (a[0] = (u64)(x0), a[1] = (u64)(x1), a[2] = (u64)(x2), a[3] = (u64)(x3), a[4] = (u64)(x4), a)
#define A6(x0, x1, x2, x3, x4, x5) (a[0] = (u64)(x0), a[1] = (u64)(x1), a[2] = (u64)(x2), a[3] = (u64)(x3), a[4] = (u64)(x4), a[5] = (u64)(x5), a)
#define ME ((u64)-1)
#define MYTHREAD ((u64)-2)
    docall("CloseHandle.invalid", fK("CloseHandle"), 1, A1(0x0DE42345), p, 0, 0, 0);
    docall("NtClose.invalid", fN("NtClose"), 1, A1(0x0DE42345), p, 0, 0, 0);
    r = docall("AddVectoredExceptionHandler", fK("AddVectoredExceptionHandler"), 2, A2(1, dummy_veh), p, 0, 0, 0);
    h = r->out[0];
    docall("RemoveVectoredExceptionHandler", fK("RemoveVectoredExceptionHandler"), 1, A1(h), p, 0, 0, 0);
    r = docall("NtQueryInformationProcess.7", fN("NtQueryInformationProcess"), 5, A5(ME, 7, io_buf, 8, &g_retlen), p, io_buf, 16, 0); r->has_retlen = r->show_head = 1;
    r = docall("NtQueryInformationProcess.30", fN("NtQueryInformationProcess"), 5, A5(ME, 30, io_buf, 8, &g_retlen), p, io_buf, 16, 0); r->has_retlen = r->show_head = 1;
    r = docall("NtQueryInformationProcess.31", fN("NtQueryInformationProcess"), 5, A5(ME, 31, io_buf, 4, &g_retlen), p, io_buf, 16, 0); r->has_retlen = r->show_head = 1;
    r = docall("GetThreadContext.debug", fK("GetThreadContext"), 2, A2(MYTHREAD, ctx_buf), p, ctx_buf, 0x4d0, 0x00100010); ctx_extra(r);
    docall("QueryPerformanceCounter", fK("QueryPerformanceCounter"), 1, A1(io_buf), p, io_buf, 16, 0);
    r = docall("GetTickCount", fK("GetTickCount"), 0, a, p, 0, 0, 0); r->valret = 1;
    r = docall("VirtualQuery", fK("VirtualQuery"), 3, A3(&g_probe_static, mbi_buf, 48), p, mbi_buf, 64, 0); mbi_extra(r);
    r = docall("VirtualProtect.same", fK("VirtualProtect"), 4, A4(g_page, 0x1000, 4, io_buf), p, io_buf, 16, 0); r->show_head = 1;
    docall("Sleep.0", fK("Sleep"), 1, A1(0), p, 0, 0, 0);
    docall("SwitchToThread", fK("SwitchToThread"), 0, a, p, 0, 0, 0);
    r = docall("NtQuerySystemInformation.5.small", fN("NtQuerySystemInformation"), 4, A4(5, io_buf, 8, &g_retlen), p, io_buf, 16, 0); r->has_retlen = 1;
    /* a few more of the same kind */
    docall("GetLastError", fK("GetLastError"), 0, a, p, 0, 0, 0);
    docall("IsDebuggerPresent", fK("IsDebuggerPresent"), 0, a, p, 0, 0, 0);
    r = docall("CheckRemoteDebuggerPresent", fK("CheckRemoteDebuggerPresent"), 2, A2(ME, io_buf), p, io_buf, 16, 0); r->show_head = 1;
    r = docall("NtQueryInformationThread.17", fN("NtQueryInformationThread"), 5, A5(MYTHREAD, 17, io_buf, 1, 0), p, io_buf, 16, 0); r->show_head = 1;
    r = docall("NtQuerySystemInformation.35", fN("NtQuerySystemInformation"), 4, A4(35, io_buf, 2, &g_retlen), p, io_buf, 16, 0); r->has_retlen = r->show_head = 1;
    docall("OutputDebugStringA", fK("OutputDebugStringA"), 1, A1("envread"), p, 0, 0, 0);
    docall("NtYieldExecution", fN("NtYieldExecution"), 0, a, p, 0, 0, 0);
    g_zero_time = 0;
    docall("NtDelayExecution.0", fN("NtDelayExecution"), 2, A2(0, &g_zero_time), p, 0, 0, 0);
    docall("NtQueryPerformanceCounter", fN("NtQueryPerformanceCounter"), 2, A2(io_buf, io_buf + 8), p, io_buf, 16, 0);
    r = docall("NtQueryVirtualMemory.0", fN("NtQueryVirtualMemory"), 6, A6(ME, &g_probe_static, 0, mbi_buf, 48, &g_retlen), p, mbi_buf, 64, 0); mbi_extra(r);
    g_pv_base = (u64)g_page; g_pv_size = 0x1000;
    r = docall("NtProtectVirtualMemory.same", fN("NtProtectVirtualMemory"), 5, A5(ME, &g_pv_base, &g_pv_size, 4, io_buf), p, io_buf, 16, 0); r->show_head = 1;
    r = docall("NtGetContextThread.debug", fN("NtGetContextThread"), 2, A2(MYTHREAD, ctx_buf), p, ctx_buf, 0x4d0, 0x00100010); ctx_extra(r);
    r = docall("GetTickCount64", fK("GetTickCount64"), 0, a, p, 0, 0, 0); r->valret = 1;
    docall("GetSystemTimeAsFileTime", fK("GetSystemTimeAsFileTime"), 1, A1(io_buf), p, io_buf, 16, 0);
    r = docall("GetCurrentThreadId", fK("GetCurrentThreadId"), 0, a, p, 0, 0, 0); r->valret = 1;
    r = docall("GetCurrentProcessId", fK("GetCurrentProcessId"), 0, a, p, 0, 0, 0); r->valret = 1;
    r = docall("QueryPerformanceFrequency", fK("QueryPerformanceFrequency"), 1, A1(io_buf), p, io_buf, 16, 0); r->show_head = 1;
}
static const char *vreg_name[7] = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"};
static const char *nv_name[7] = {"rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"};
static void regnorm(const struct rec *r, int idx, u64 v, char *o) {
    int j;
    if (!v) { sfmt(o, "0"); return; }
    if (v == r->in[1 + idx]) { sfmt(o, "kept"); return; }
    if (v == r->out[7]) { sfmt(o, "eq:eflags-after"); return; }
    if (v == r->in[8]) { sfmt(o, "eq:eflags-before"); return; }
    if (v >= 0x10000) {
        for (j = 0; j < 7; j++) if (j != idx && v == r->in[1 + j]) { sfmt(o, "in:%s", vreg_name[j]); return; }
        for (j = 0; j < 8; j++) if (v == r->in[9 + j]) { sfmt(o, "in:stack-arg%X", (u64)j); return; }
        for (j = 0; j < 7; j++) if (v == r->in[0x11 + j]) { sfmt(o, "in:%s", nv_name[j]); return; }
        if (v == r->in[0]) { sfmt(o, "target"); return; }
        if (v == (u64)cap_after) { sfmt(o, "return-address"); return; }
        if (v >= g_stack_lo && v < g_stack_hi) {   /* relative to rsp at the call: below = the callee's own dead frames */
            if (v < r->in[0x18]) sfmt(o, "stack-below");
            else if (v - r->in[0x18] < 0xa8) sfmt(o, "stack:call-frame+%x", v - r->in[0x18]);
            else sfmt(o, "stack-above");
            return;
        }
    }
    classify(v, o);
}
static void emit_recs(void) {
    char nm[128], t[200], base[96]; int i, j, percall = nrec / 3; u32 k;
    for (i = 0; i < nrec; i++) {
        const struct rec *r = &recs[i];
        sfmt(base, "ret.%s.%s", r->name, passname[r->pass]);
        if (r->missing) { sfmt(nm, "%s.missing", base); cell_x(nm, 1); continue; }
        for (j = 0; j < 7; j++) {
            sfmt(nm, "%s.%s", base, vreg_name[j]);
            if (j == 0 && r->valret) sfmt(t, "value"); else regnorm(r, j, r->out[j], t);
            cell(nm, t, 1, r->out[j]);
        }
        sfmt(nm, "%s.eflags", base); cell_x(nm, r->out[7]);
        for (j = 0; j < 6; j++) { sfmt(nm, "%s.xmm%X", base, (u64)j); xmm_text(&r->out[0x20 + 2 * j], r->in[0x20 + 2 * j], t); cell_s(nm, t); }
        sfmt(nm, "%s.mxcsr_after_1f80", base); cell_x(nm, (u32)r->out[0x11]);
        sfmt(nm, "%s.x87_control", base); cell_x(nm, (u16)(r->out[0x11] >> 32));
        sfmt(nm, "%s.x87_status", base); cell_x(nm, (u16)(r->out[0x11] >> 48));
        sfmt(nm, "%s.x87_tag", base); cell_x(nm, (u16)r->out[0x13]);
        sfmt(nm, "%s.x87_last_ip", base); cell((const char *)nm, (u32)(r->out[0x13] >> 32) ? "nonzero" : "0", 1, (u32)(r->out[0x13] >> 32));
        sfmt(nm, "%s.rsp_delta", base); cell_x(nm, r->out[8] - r->in[0x18]);
        t[0] = 0; k = 0;
        if (r->out[9] != (u64)g_in) { sfmt(t, "rbx"); k = 3; }
        for (j = 0; j < 7; j++) if (r->out[10 + j] != r->in[0x11 + j]) { sfmt(t + k, "%s%s", k ? "," : "", nv_name[j]); while (t[k]) k++; }
        sfmt(nm, "%s.nonvolatile_changed", base); cell_s(nm, k ? t : "none");
        sfmt(nm, "%s.last_error", base); if (r->gle == GLE_MARK) cell_s(nm, "kept"); else cell_x(nm, r->gle);
        sfmt(nm, "%s.last_status", base); if (r->lst == LST_MARK) cell_s(nm, "kept"); else cell_x(nm, r->lst);
        sfmt(nm, "%s.exceptions_seen", base); cell_x(nm, r->vehn);
        if (r->vehn) { sfmt(nm, "%s.first_exception_code", base); cell_x(nm, r->vehc); }
        if (r->has_retlen) { sfmt(nm, "%s.return_length", base); if (r->retlen == r->poison * 0x01010101u) cell_s(nm, "untouched"); else cell_x(nm, r->retlen); }
        if (r->buf) {
            if (r->pass == 2 && i >= 2 * percall) {   /* union over passes A, B, C: a byte equal to the fill byte cannot hide in all three */
                const struct rec *ra = &recs[i - 2 * percall], *rb = &recs[i - percall]; char *q = t; int open = 0, n = 0; u32 start = 0;
                *q = 0;
                for (k = 0; k <= r->buflen && k <= 8 * sizeof r->wr; k++) {
                    int w = k < r->buflen && k < 8 * sizeof r->wr && ((ra->wr[k >> 3] | rb->wr[k >> 3] | r->wr[k >> 3]) >> (k & 7) & 1);
                    if (w && !open) { start = k; open = 1; }
                    else if (!w && open) { if (n < 8) { sfmt(q, "%s%x-%x", n ? "," : "", (u64)start, (u64)k); while (*q) q++; } n++; open = 0; }
                }
                sfmt(nm, "%s.buffer_bytes_written_in_any_pass", base); cell_s(nm, n ? t : "none");
            }
            if (r->show_head) {
                static const char hx[] = "0123456789abcdef";
                for (k = 0; k < 16; k++) { u8 b = r->head[k]; if (b == r->poison) { t[2 * k] = '.'; t[2 * k + 1] = '.'; } else { t[2 * k] = hx[b >> 4]; t[2 * k + 1] = hx[b & 15]; } }
                t[32] = 0; sfmt(nm, "%s.buffer_head", base); cell_s(nm, t);
            }
        }
        for (j = 0; j < r->nextra; j++) { sfmt(nm, "%s.%s", base, r->extra_name[j]); cell_x(nm, r->extra[j]); }
        if ((i & 7) == 7) oflush();
    }
    oflush();
}

/* ------------------------------------------------------------------ section: clocks */
static u64 usd_time(u32 off) { u32 hi, lo, hi2; int n = 0; do { hi = usd32(off + 4); lo = usd32(off); hi2 = usd32(off + 8); } while (hi != hi2 && ++n < 1000); return ((u64)hi << 32) | lo; }
static u64 usd_tick_ms(void) { u64 t = usd_time(0x320); u64 m = usd32(4); return (((t & 0xffffffffULL) * m) >> 24) + (((t >> 32) * m) << 8); }
static u64 qpc(void) { u64 v = 0; pQPC(&v); return v; }
static u64 ftime(void) { u64 v = 0; pGSTAFT(&v); return v; }
struct samp { u64 qpc, tsc, gt64, gtc, ft, usys, uint_, utick, ulow, unb; };
static void take(struct samp *s) {
    s->qpc = qpc(); s->tsc = gi_rdtsc(); s->gt64 = pGetTickCount64 ? pGetTickCount64() : 0; s->gtc = pGetTickCount();
    s->ft = ftime(); s->usys = usd_time(0x14); s->uint_ = usd_time(0x08); s->utick = usd_tick_ms(); s->ulow = usd32(0);
    s->unb = 0; if (pQUIT) pQUIT(&s->unb);
}
static const char *bucket(u64 step100ns) {
    if (!step100ns) return "none";
    if (step100ns <= 10) return "<=1us"; if (step100ns <= 100) return "<=10us"; if (step100ns <= 1000) return "<=100us";
    if (step100ns <= 10000) return "<=1ms"; if (step100ns <= 20000) return "<=2ms"; if (step100ns <= 200000) return "<=20ms";
    return ">20ms";
}
struct trk { u64 prev, distinct, back, minstep, orv; int init; };
static void trk_add(struct trk *t, u64 v) {
    t->orv |= v;
    if (!t->init) { t->init = 1; t->prev = v; t->distinct = 1; t->minstep = ~0ULL; return; }
    if (v < t->prev) t->back++;
    else if (v > t->prev) { t->distinct++; if (v - t->prev < t->minstep) t->minstep = v - t->prev; }
    t->prev = v;
}
static void trk_emit(const char *name, struct trk *t, u64 unit100ns) {
    char nm[96]; u64 ms = t->minstep == ~0ULL ? 0 : t->minstep;
    sfmt(nm, "clk.noisy.%s.distinct_values", name); cell_x(nm, t->distinct);
    sfmt(nm, "clk.noisy.%s.min_step", name); cell_x(nm, ms);
    sfmt(nm, "clk.%s.went_backwards", name); cell_x(nm, t->back != 0);
    if (unit100ns) { sfmt(nm, "clk.%s.min_step_bucket", name); cell_s(nm, bucket(ms * unit100ns)); }
}
static u64 c_usys(void) { return usd_time(0x14); }
static u64 c_uint(void) { return usd_time(0x08); }
static u64 c_utick(void) { return usd_time(0x320); }
static u64 c_gt64(void) { return pGetTickCount64 ? pGetTickCount64() : 0; }
/* one clock read in a tight loop for a bounded time: number of distinct values, smallest step, any step backwards */
static void run_trk(const char *name, u64 (*fn)(void), u64 f, u32 ms, u64 unit100ns, struct trk *k) {
    char nm[96]; u64 t0 = qpc(), lim = f / 1000 * ms, n;
    memset(k, 0, sizeof *k);
    for (n = 0; n < 400000000ULL; n++) { trk_add(k, fn()); if ((n & 31) == 31 && qpc() - t0 > lim) break; }
    sfmt(nm, "clk.noisy.%s.reads", name); cell_x(nm, n);
    trk_emit(name, k, unit100ns);
}
static void sec_clocks(void) {
    struct samp s0, s1; u64 f = 0, dq, i, maxd = 0, d[6]; char nm[96];
    u64 behind = 0, inside = 0, ahead = 0, equal = 0, maxbehind = 0, maxahead = 0;
    u64 tb = 0, ti = 0, ta = 0, te = 0, ib = 0, ii = 0, ia = 0, bias; struct trk k;
    pQPF(&f);
    cell_x("clk.qpc_frequency", f);
    cell_x("clk.usd_qpc_frequency_equals_api", ((u64)usd32(0x304) << 32 | usd32(0x300)) == f);
    take(&s0); pSleep(1000); take(&s1);
    dq = (s1.qpc - s0.qpc) * 10000000ULL / (f ? f : 1);                  /* 100 ns units */
    d[0] = (s1.gt64 - s0.gt64) * 10000; d[1] = (u64)(u32)(s1.gtc - s0.gtc) * 10000; d[2] = s1.ft - s0.ft;
    d[3] = s1.usys - s0.usys; d[4] = s1.uint_ - s0.uint_; d[5] = (s1.utick - s0.utick) * 10000;
    cell_x("clk.noisy.sleep1000.qpc_100ns", dq);
    cell_x("clk.noisy.sleep1000.GetTickCount64_100ns", d[0]); cell_x("clk.noisy.sleep1000.GetTickCount_100ns", d[1]);
    cell_x("clk.noisy.sleep1000.GetSystemTimeAsFileTime_100ns", d[2]); cell_x("clk.noisy.sleep1000.usd_SystemTime_100ns", d[3]);
    cell_x("clk.noisy.sleep1000.usd_InterruptTime_100ns", d[4]); cell_x("clk.noisy.sleep1000.usd_TickCount_100ns", d[5]);
    cell_x("clk.noisy.sleep1000.unbiased_interrupt_100ns", s1.unb - s0.unb);
    cell_x("clk.noisy.sleep1000.rdtsc", s1.tsc - s0.tsc);
    cell_x("clk.noisy.rdtsc_per_second", dq ? (s1.tsc - s0.tsc) * 10000000ULL / dq : 0);
    for (i = 0; i < 6; i++) { u64 x = d[i] > dq ? d[i] - dq : dq - d[i]; if (x > maxd) maxd = x; }
    cell_x("clk.noisy.sleep1000.largest_disagreement_100ns", maxd);
    cell_x("clk.sleep1000.all_clocks_agree_within_50ms", maxd < 500000);
    cell_x("clk.sleep1000.qpc_between_900_and_1500_ms", dq > 9000000 && dq < 15000000);
    cell_x("clk.usd_SystemTime.advances", d[3] != 0); cell_x("clk.usd_InterruptTime.advances", d[4] != 0);
    cell_x("clk.usd_TickCount.advances", d[5] != 0); cell_x("clk.usd_TickCountLowDeprecated.advances", s1.ulow != s0.ulow);
    cell_x("clk.rdtsc.advances", s1.tsc > s0.tsc);
    /* the same instant seen through the page and through the API */
    bias = (u64)usd32(0x3b4) << 32 | usd32(0x3b0);
    for (i = 0; i < 2000; i++) {
        u64 a = ftime(), u = usd_time(0x14), b = ftime();
        if (u < a) { behind++; if (a - u > maxbehind) maxbehind = a - u; } else if (u > b) { ahead++; if (u - b > maxahead) maxahead = u - b; } else inside++;
        if (u == a || u == b) equal++;
        if (pGetTickCount64) { u64 g0 = pGetTickCount64(), ut = usd_tick_ms(), g1 = pGetTickCount64(); if (ut < g0) tb++; else if (ut > g1) ta++; else ti++; if (ut == g0 || ut == g1) te++; }
        if (pQUIT) { u64 q0 = 0, q1 = 0, ui; pQUIT(&q0); ui = usd_time(0x08) - bias; pQUIT(&q1); if (ui < q0) ib++; else if (ui > q1) ia++; else ii++; }
    }
    cell_x("clk.noisy.usd_SystemTime_vs_api.behind_count", behind); cell_x("clk.noisy.usd_SystemTime_vs_api.ahead_count", ahead);
    cell_x("clk.noisy.usd_SystemTime_vs_api.equal_count", equal);
    cell_x("clk.noisy.usd_SystemTime_vs_api.max_behind_100ns", maxbehind); cell_x("clk.noisy.usd_SystemTime_vs_api.max_ahead_100ns", maxahead);
    cell_x("clk.usd_SystemTime_vs_api.never_behind", behind == 0); cell_x("clk.usd_SystemTime_vs_api.never_ahead", ahead == 0);
    cell_x("clk.usd_SystemTime_vs_api.equal_in_most_reads", equal * 2 > 2000);
    cell_s("clk.usd_SystemTime_vs_api.max_behind_bucket", bucket(maxbehind));
    cell_x("clk.noisy.usd_TickCount_vs_api.behind_count", tb); cell_x("clk.noisy.usd_TickCount_vs_api.ahead_count", ta);
    cell_x("clk.noisy.usd_TickCount_vs_api.equal_count", te);
    cell_x("clk.usd_TickCount_vs_api.always_inside", pGetTickCount64 && tb == 0 && ta == 0);
    cell_x("clk.noisy.usd_InterruptTime_vs_api.behind_count", ib); cell_x("clk.noisy.usd_InterruptTime_vs_api.ahead_count", ia);
    cell_x("clk.usd_InterruptTime_vs_api.always_inside", pQUIT && ib == 0 && ia == 0); (void)ii; (void)ti; (void)inside;
    /* steps and monotonicity: every clock alone in a tight loop */
    run_trk("usd_SystemTime", c_usys, f, 100, 1, &k); run_trk("usd_InterruptTime", c_uint, f, 100, 1, &k);
    run_trk("usd_TickCount", c_utick, f, 100, 0, &k); run_trk("GetTickCount64", c_gt64, f, 100, 10000, &k);
    run_trk("GetSystemTimeAsFileTime", ftime, f, 20, 1, &k); run_trk("QueryPerformanceCounter", qpc, f, 20, f ? 10000000 / f : 0, &k);
    run_trk("rdtsc", gi_rdtsc, f, 20, 0, &k);
    sfmt(nm, "clk.rdtsc.low6_bits_seen_nonzero"); cell_x(nm, (s0.tsc | s1.tsc | k.orv) & 63 ? 1 : 0);
    oflush();
}

/* ------------------------------------------------------------------ section: CPU-level reads */
static void cpu_one(const char *name, u64 v) {
    char nm[64], t[40]; sfmt(nm, "cpu.%s", name);
    if (g_fault_n) { sfmt(t, "exception:%x", (u64)g_fault_code); cell_s(nm, t); } else cell_x(nm, v);
    oflush(); g_fault_n = 0; g_fault_code = 0;
}
static void sec_cpu(void) {
    static u8 dt[16]; static const u16 sels[] = {0x10, 0x18, 0x23, 0x2b, 0x33, 0x53}; char nm[48]; u32 i; u64 v;
    g_fault_n = 0; g_fault_code = 0;
    cell_s("cpu.begin", "1"); oflush();
    cpu_one("cs", gi_cs()); cpu_one("ss", gi_ss()); cpu_one("ds", gi_ds()); cpu_one("es", gi_es()); cpu_one("fs", gi_fs()); cpu_one("gs", gi_gs());
    v = gi_xgetbv(); cpu_one("xgetbv0", v);
    { u32 aux = 0xeeeeeeeeu; v = gi_rdtscp(&aux); if (!g_fault_n) { cell_x("cpu.noisy.rdtscp_aux", aux); v = 1; } cpu_one("rdtscp_executes", v); }
    { u32 cf = 0xee; v = gi_rdrand(&cf); if (!g_fault_n) v = 0x10 | cf; cpu_one("rdrand_executes_10_plus_carry", v); }
    for (i = 0; i < sizeof sels / sizeof sels[0]; i++) {
        v = gi_lsl(sels[i]); sfmt(nm, "lsl.%x", (u64)sels[i]); cpu_one(nm, v);
        v = gi_lar(sels[i]); sfmt(nm, "lar.%x", (u64)sels[i]); cpu_one(nm, v);
    }
    v = gi_smsw(); cpu_one("smsw", v);
    memset(dt, 0, sizeof dt); v = gi_sidt(dt); if (!g_fault_n) v = rd16(dt); cpu_one("sidt.limit", v);
    memset(dt, 0, sizeof dt); v = gi_sgdt(dt); if (!g_fault_n) v = rd16(dt); cpu_one("sgdt.limit", v);
    v = gi_sldt(); cpu_one("sldt", v);
    v = gi_str(); cpu_one("str", v);
    cell_s("cpu.end", "1"); oflush();
}

/* ------------------------------------------------------------------ section: CPUID and a few API answers */
static void sec_cpuid(void) {
    u32 r[4], maxleaf, maxext, i; char t[64], nm[48];
    gi_cpuid(0, 0, r); maxleaf = r[0];
    memcpy(t, &r[1], 4); memcpy(t + 4, &r[3], 4); memcpy(t + 8, &r[2], 4); t[12] = 0;
    cell_x("cpuid.0.eax", r[0]); cell_s("cpuid.vendor", t);
    gi_cpuid(1, 0, r);
    cell_x("cpuid.1.eax", r[0]); cell_x("cpuid.1.ebx_without_apic_id", r[1] & 0x00ffffffu); cell_x("cpuid.1.ecx", r[2]); cell_x("cpuid.1.edx", r[3]);
    cell_x("cpuid.1.hypervisor_bit", (r[2] >> 31) & 1);
    if ((r[2] >> 31) & 1) { gi_cpuid(0x40000000, 0, r); memcpy(t, &r[1], 12); t[12] = 0; cell_s("cpuid.hypervisor_vendor", t); }
    if (maxleaf >= 7) { gi_cpuid(7, 0, r); cell_x("cpuid.7.ebx", r[1]); cell_x("cpuid.7.ecx", r[2]); cell_x("cpuid.7.edx", r[3]); }
    if (maxleaf >= 0xd) { gi_cpuid(0xd, 0, r); cell_x("cpuid.d.0.eax", r[0]); cell_x("cpuid.d.0.ebx", r[1]); cell_x("cpuid.d.0.ecx", r[2]); }
    gi_cpuid(0x80000000u, 0, r); maxext = r[0]; cell_x("cpuid.80000000.eax", maxext);
    if (maxext >= 0x80000001u) { gi_cpuid(0x80000001u, 0, r); cell_x("cpuid.80000001.ecx", r[2]); cell_x("cpuid.80000001.edx", r[3]); }
    if (maxext >= 0x80000004u) {
        for (i = 0; i < 3; i++) gi_cpuid(0x80000002u + i, 0, (u32 *)(void *)(t + 16 * i));
        t[48] = 0; cell_s("cpuid.brand", t);
    }
    if (maxext >= 0x80000007u) { gi_cpuid(0x80000007u, 0, r); cell_x("cpuid.80000007.edx", r[3]); }
    if (maxext >= 0x80000008u) { gi_cpuid(0x80000008u, 0, r); cell_x("cpuid.80000008.eax", r[0]); }
    (void)nm;
    oflush();
}
static void sec_api(void) {
    static u8 si[64], b[80]; struct mbi m; u32 len = 0xa5a5a5a5u, st, i; char t[80];
    void (*gnsi)(void *) = (void (*)(void *))fK("GetNativeSystemInfo");
    void (*gsi)(void *) = (void (*)(void *))fK("GetSystemInfo");
    u32 (*qsi)(u32, void *, u32, u32 *) = (u32 (*)(u32, void *, u32, u32 *))fN("NtQuerySystemInformation");
    if (gsi) { memset(si, 0, sizeof si); gsi(si); cell_x("api.GetSystemInfo.architecture", rd16(si)); cell_x("api.GetSystemInfo.type", rd32(si + 0x24));
               cell_x("api.GetSystemInfo.level", rd16(si + 0x2c)); cell_x("api.GetSystemInfo.revision", rd16(si + 0x2e)); cell_x("api.GetSystemInfo.processors", rd32(si + 0x20)); }
    if (gnsi) { memset(si, 0, sizeof si); gnsi(si); cell_x("api.GetNativeSystemInfo.architecture", rd16(si)); cell_x("api.GetNativeSystemInfo.type", rd32(si + 0x24));
                cell_x("api.GetNativeSystemInfo.level", rd16(si + 0x2c)); cell_x("api.GetNativeSystemInfo.revision", rd16(si + 0x2e)); }
    if (qsi) {
        memset(b, 0xa5, sizeof b); st = qsi(105, b, 64, &len);
        cell_x("api.SystemProcessorBrandString.status", st);
        if (len == 0xa5a5a5a5u) cell_s("api.SystemProcessorBrandString.length", "untouched"); else cell_x("api.SystemProcessorBrandString.length", len);
        if (!st) { for (i = 0; i < 63 && b[i]; i++) t[i] = (b[i] >= 0x20 && b[i] < 0x7f) ? (char)b[i] : '?'; t[i] = 0; cell_s("api.SystemProcessorBrandString.text", t); }
    }
    {
        int (*ipfp)(u32) = (int (*)(u32))fK("IsProcessorFeaturePresent"); u32 mism = 0; char *q = t;
        if (ipfp) {
            for (i = 0; i < 64; i++) b[i] = ipfp(i) ? '1' : '0';
            b[64] = 0; cell_s("api.IsProcessorFeaturePresent", (const char *)b);
            *q = 0;
            for (i = 0; i < 64; i++) if ((b[i] == '1') != (usd_snap[0x274 + i] != 0)) { if (mism < 12) { sfmt(q, "%s%X", mism ? "," : "", (u64)i); while (*q) q++; } mism++; }
            cell_x("api.features_page_vs_api.mismatches", mism);
            cell_s("api.features_page_vs_api.numbers_hex", mism ? t : "none");
        }
    }
    memset(&m, 0, sizeof m);
    cell_x("api.VirtualQuery_usd.returned", pVirtualQuery((const void *)USD, &m, sizeof m));
    cell_x("api.VirtualQuery_usd.State", m.State); cell_x("api.VirtualQuery_usd.Protect", m.Protect); cell_x("api.VirtualQuery_usd.Type", m.Type);
    cell_x("api.VirtualQuery_usd.AllocationProtect", m.AllocationProtect); cell_x("api.VirtualQuery_usd.RegionSize_is_one_page", m.RegionSize == 0x1000);
    oflush();
}

/* ------------------------------------------------------------------ main */
void envread_main(void) {
    char t[40];
    g_teb = gi_rdgs(0x30); g_peb = gi_rdgs(0x60);
    memcpy(teb_snap, (void *)g_teb, sizeof teb_snap); memcpy(peb_snap, (void *)g_peb, sizeof peb_snap);
    hout = GetStdHandle((u32)-11);
    k32 = GetModuleHandleA("kernel32.dll"); ntd = GetModuleHandleA("ntdll.dll");
    pVirtualQuery = (u64 (*)(const void *, void *, u64))fK("VirtualQuery");
    pVirtualAlloc = (void *(*)(void *, u64, u32, u32))fK("VirtualAlloc");
    pAddVEH = (void *(*)(u32, void *))fK("AddVectoredExceptionHandler");
    pSleep = (void (*)(u32))fK("Sleep");
    pQPC = (int (*)(u64 *))fK("QueryPerformanceCounter"); pQPF = (int (*)(u64 *))fK("QueryPerformanceFrequency");
    pGetTickCount64 = (u64 (*)(void))fK("GetTickCount64"); pGetTickCount = (u32 (*)(void))fK("GetTickCount");
    pGSTAFT = (void (*)(u64 *))fK("GetSystemTimeAsFileTime"); pQUIT = (int (*)(u64 *))fK("QueryUnbiasedInterruptTime");
    build_maps();
    cell_s("meta.probe", "envread 1");
#ifdef _MSC_VER
    cell_s("meta.build", "msvc-target");
#else
    cell_s("meta.build", "mingw-target");
#endif
    sec_entry();
    sec_process();

    add_guard((void *)gi_rd32, gi_rd32_r); add_guard((void *)gi_sidt, gi_sidt_r); add_guard((void *)gi_sgdt, gi_sgdt_r);
    add_guard((void *)gi_sldt, gi_sldt_r); add_guard((void *)gi_str, gi_str_r); add_guard((void *)gi_smsw, gi_smsw_r);
    add_guard((void *)gi_xgetbv, gi_xgetbv_r); add_guard((void *)gi_lsl, gi_lsl_r); add_guard((void *)gi_lar, gi_lar_r);
    add_guard((void *)gi_rdtscp, gi_rdtscp_r); add_guard((void *)gi_rdrand, gi_rdrand_r);
    pAddVEH(1, (void *)veh);
    sec_usd();

    g_page = (u8 *)pVirtualAlloc(0, 0x1000, 0x3000, 4);
    do_pass(0); do_pass(1); do_pass(2);
    emit_recs();

    sec_clocks();
    sec_usd_changed();
    sec_cpuid();
    sec_api();
    sec_cpu();

    sfmt(t, "%x", (u64)ncell + 1); cell_s("meta.done", t);
    oflush();
    ExitProcess(0);
}
