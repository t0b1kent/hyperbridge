/* SPDX-License-Identifier: MIT */
/* excdump: what a vectored exception handler of an x86-64 program receives: the full EXCEPTION_RECORD and CONTEXT, one line per cell.
 * Win32 API only. Addresses are printed RELATIVE ("+off" = cell region base, "R+off" = the cell's separate 64 KB page-test region, "F+off" = the in-image test function, "I" = elsewhere in the image, "S+off" = stack at cell entry).
 * Every cell uses its own fresh memory region.
 *   excdump list             table of cells (id, name, bytes, instruction length, flags)
 *   excdump all              every cell in turn inside one process (LIST_ONLY cells are not executed)
 *   excdump cell N           a single cell
 *   excdump tsv              "name<TAB>args" list for running every cell in a separate process
 * Build: x86_64-w64-mingw32-gcc -O1 -g0 -static -fno-stack-protector -o excdump.exe excdump.c
 * Output: "CELL ..." lines (only they enter the checksum) and "SUMMARY cells=N run=R skipped=S checksum=...".
 * After the first exception (unless the cell is NOEDIT) the handler sets Rip to the ABSOLUTE address of the next instruction
 * (region base + offset + length), so continuation is identical on any implementation; differences show only in what the handler received.
 * The *_noedit cells leave Rip as given and show where execution naturally continued ("cont"). */
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define F_LIST_ONLY 1u   /* do not execute */
#define F_TF        2u   /* single-step cell */
#define F_EXECFAULT 4u   /* execute fault at a foreign address: return = Rip := [Rsp], Rsp += 8 */
#define F_NOEDIT    8u   /* leave Rip in the context untouched */
#define F_API       16u  /* exception comes from an API / no exception: address outside the region */
#define F_SPECIAL   32u  /* run by a dedicated branch of run_one */
#define F_GUARD     64u  /* guard page: repeat the same instruction */
#define F_UNPROT    1024u /* the handler makes the cell's separate region accessible and resumes without editing Rip */
#define F_PATCH_RET 256u /* the handler overwrites the byte at ExceptionAddress with C3 and resumes without editing Rip */
#define F_PATCH_NOP 512u /* same with 90 */
#define F_ISOLATED  128u /* run only by `cell N` in its own process: a hang or crash of this cell must not stop `all` */

typedef struct { uint64_t rax, rcx, rdx, r8; } Regs;
typedef struct {
    int id; const char *name; const char *desc;
    const uint8_t *code; int clen;   /* instruction bytes of the cell */
    int skip;                         /* instruction length: Rip := ia + skip */
    unsigned flags; int soff;         /* offset of the instruction in the region */
} Cell;

void call_cell(void *target, Regs *regs, uint64_t *entry_rsp);
__asm__(".text\n.globl call_cell\ncall_cell:\n.intel_syntax noprefix\n"
        "push rbx\npush rbp\npush rdi\npush rsi\npush r12\npush r13\npush r14\npush r15\nsub rsp, 40\n"
        "mov r10, rcx\nmov r11, rdx\nmov [r8], rsp\n"
        "mov rax, [r11]\nmov rcx, [r11+8]\nmov rdx, [r11+16]\nmov r8, [r11+24]\n"
        "movabs rbx, 0x2222222202020202\nmovabs rsi, 0x5555555505050505\nmovabs rdi, 0x6666666606060606\nmovabs rbp, 0x7777777707070707\n"
        "movabs r9, 0x9999999909090909\nmovabs r12, 0xcccccccc0c0c0c0c\nmovabs r13, 0xdddddddd0d0d0d0d\nmovabs r14, 0xeeeeeeee0e0e0e0e\nmovabs r15, 0xffffffff0f0f0f0f\n"
        "call r10\n"
        "pushfq\nand qword ptr [rsp], 0xfffffffffffffeff\npopfq\n"
        "add rsp, 40\npop r15\npop r14\npop r13\npop r12\npop rsi\npop rdi\npop rbp\npop rbx\nret\n.att_syntax\n");
/* cell 0: int3 in an ordinary code page of the image */
void cc_in_image(void);
__asm__(".text\n.globl cc_in_image\ncc_in_image:\n.intel_syntax noprefix\nint3\nnop\nnop\nret\n.att_syntax\n");

/* rescue of a cell that hangs: the watchdog thread redirects the main thread to rescue_entry, which jumps back into run_one */
int mini_setjmp(uint64_t *buf) __attribute__((returns_twice));
void mini_longjmp(uint64_t *buf);
__asm__(".text\n.globl mini_setjmp\nmini_setjmp:\n.intel_syntax noprefix\n"
        "mov [rcx], rbx\nmov [rcx+8], rbp\nmov [rcx+16], rdi\nmov [rcx+24], rsi\nmov [rcx+32], r12\nmov [rcx+40], r13\nmov [rcx+48], r14\nmov [rcx+56], r15\n"
        "lea rax, [rsp+8]\nmov [rcx+64], rax\nmov rax, [rsp]\nmov [rcx+72], rax\nxor eax, eax\nret\n"
        ".globl mini_longjmp\nmini_longjmp:\n"
        "mov rbx, [rcx]\nmov rbp, [rcx+8]\nmov rdi, [rcx+16]\nmov rsi, [rcx+24]\nmov r12, [rcx+32]\nmov r13, [rcx+40]\nmov r14, [rcx+48]\nmov r15, [rcx+56]\n"
        "mov rsp, [rcx+64]\nmov eax, 1\njmp qword ptr [rcx+72]\n.att_syntax\n");
static uint64_t g_rescue[10];
static volatile LONG g_hang;
static HANDLE g_main_thread;
static volatile ULONGLONG g_cell_tick;
static void rescue_entry(void) { mini_longjmp(g_rescue); }

/* ---- floating-point state through the handler (cells 77-86) ---- */
typedef struct {
    uint32_t mxcsr_in; uint16_t fcw_in; uint16_t pad;      /* 0, 4 */
    uint8_t xmm_in[16][16];                                 /* 8 */
    uint8_t st_in[3][16];                                   /* 264 */
    volatile uint8_t ready, go; uint8_t pad2[14];           /* 312, 313 */
    uint32_t mxcsr_out; uint16_t fcw_out; uint16_t pad3;    /* 328, 332 */
    uint8_t xmm_out[16][16];                                /* 336 */
    uint8_t st_out[3][16];                                  /* 592 */
    uint32_t scratch[4];                                    /* 640 */
    uint64_t fn_sleep;                                      /* 656 */
} FPS;
_Static_assert(offsetof(FPS, xmm_in) == 8 && offsetof(FPS, st_in) == 264 && offsetof(FPS, ready) == 312 && offsetof(FPS, mxcsr_out) == 328 &&
               offsetof(FPS, xmm_out) == 336 && offsetof(FPS, st_out) == 592, "FPS layout");
void fp_thread_asm(FPS *s);
__asm__(".text\n.globl fp_thread_asm\nfp_thread_asm:\n.intel_syntax noprefix\n"
        "push rbx\nmov rbx, rcx\n"
        "ldmxcsr [rbx]\nfldcw [rbx+4]\n"
        "fld tbyte ptr [rbx+264+32]\nfld tbyte ptr [rbx+264+16]\nfld tbyte ptr [rbx+264]\n"
        "movups xmm0,[rbx+8]\nmovups xmm1,[rbx+24]\nmovups xmm2,[rbx+40]\nmovups xmm3,[rbx+56]\nmovups xmm4,[rbx+72]\nmovups xmm5,[rbx+88]\nmovups xmm6,[rbx+104]\nmovups xmm7,[rbx+120]\n"
        "movups xmm8,[rbx+136]\nmovups xmm9,[rbx+152]\nmovups xmm10,[rbx+168]\nmovups xmm11,[rbx+184]\nmovups xmm12,[rbx+200]\nmovups xmm13,[rbx+216]\nmovups xmm14,[rbx+232]\nmovups xmm15,[rbx+248]\n"
        "mov byte ptr [rbx+312], 1\n"
        "1: sub rsp, 32\nmov ecx, 1\ncall qword ptr [rbx+656]\nadd rsp, 32\ncmp byte ptr [rbx+313], 0\nje 1b\n"
        "stmxcsr [rbx+328]\nfnstcw [rbx+332]\n"
        "movups [rbx+336],xmm0\nmovups [rbx+352],xmm1\nmovups [rbx+368],xmm2\nmovups [rbx+384],xmm3\nmovups [rbx+400],xmm4\nmovups [rbx+416],xmm5\nmovups [rbx+432],xmm6\nmovups [rbx+448],xmm7\n"
        "movups [rbx+464],xmm8\nmovups [rbx+480],xmm9\nmovups [rbx+496],xmm10\nmovups [rbx+512],xmm11\nmovups [rbx+528],xmm12\nmovups [rbx+544],xmm13\nmovups [rbx+560],xmm14\nmovups [rbx+576],xmm15\n"
        "fstp tbyte ptr [rbx+592]\nfstp tbyte ptr [rbx+608]\nfstp tbyte ptr [rbx+624]\n"
        "fninit\nmov dword ptr [rbx+640], 0x1f80\nldmxcsr [rbx+640]\npop rbx\nret\n.att_syntax\n");
void df_thread_asm(FPS *s);
__asm__(".text\n.globl df_thread_asm\ndf_thread_asm:\n.intel_syntax noprefix\n"
        "push rbx\nmov rbx, rcx\nstd\nmov byte ptr [rbx+312], 1\n"
        "1: cmp byte ptr [rbx+313], 0\nje 1b\n"
        "pushfq\npop rax\nmov [rbx+640], rax\ncld\npop rbx\nret\n.att_syntax\n");
static DWORD WINAPI df_thread_proc(LPVOID p) { df_thread_asm((FPS *)p); return 0; }
static FPS g_fps;                 /* sized 640 + 4 (scratch for the default MXCSR) */
static DWORD WINAPI fp_thread_proc(LPVOID p) { fp_thread_asm((FPS *)p); return 0; }

static uint8_t *g_base; static size_t g_size = 0x40000;
static uint8_t *g_spec;   /* separate 64 KB region of the cell for page-protection tests */
static uint8_t *g_img;
static uint64_t g_entry_rsp, g_ia;
static volatile int g_active;
static unsigned g_calls, g_land_calls, g_armed;
static uint64_t g_cont; static int g_cont_set;
static const Cell *g_cell;
static uint64_t g_land_lo;
static uint64_t g_probe_val;
typedef struct { uint64_t rip, rsp, efl, code; } Step;
static Step g_steps[16]; static unsigned g_nsteps;
static EXCEPTION_RECORD g_er; static CONTEXT g_cx;
static uint64_t g_extra_a, g_extra_b;
static unsigned g_maxsteps = 8;
static int g_ia_adj;                        /* offset of the tested instruction inside the stub */
static volatile uint32_t g_st[4];           /* x87/SSE control words: [0] fcw in/out (u16 at +0/+2), [1] mxcsr in, [2] mxcsr out */
static unsigned g_phase_calls[4]; static int g_phase;

static const uint8_t LAND[4] = {0xCC, 0xCC, 0x90, 0xC3};
#define BYTES(...) (const uint8_t[]){__VA_ARGS__}
#define CELL(id, name, desc, flags, skip, ...) {id, name, desc, BYTES(__VA_ARGS__), (int)sizeof(BYTES(__VA_ARGS__)), skip, flags, 0x100}
#define SP(id, name, desc, flags, skip, soff) {id, name, desc, NULL, 0, skip, (flags) | F_SPECIAL, soff}
#define TFPRE 0x9C, 0x48, 0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00, 0x9D   /* pushfq; or qword [rsp],0x100; popfq */

static const Cell cells[] = {
    /* a) CC */
    SP(0, "cc_image_text", "0xCC in an ordinary code page of the image (int3; nop; nop; ret)", 0, 1, 0),
    CELL(1, "cc_rwx_fresh", "0xCC in an RWX page written right before execution", 0, 1, 0xCC),
    SP(2, "cc_ret_then_cc", "same page: first C3 (executed), then CC (executed)", 0, 1, 0x100),
    SP(3, "cc_cc_then_ret", "same page: first CC (executed), then C3 (executed)", 0, 1, 0x100),
    SP(4, "cc_after_neighbor_write", "C3 executed; a neighbouring byte of the same page written; then CC in place of C3 and executed", 0, 1, 0x100),
    SP(5, "cc_at_4k_edge", "CC in the last byte of a 4 KB page (landing continues on the next page)", 0, 1, 0xFFF),
    SP(6, "cc_at_16k_edge", "CC in the last byte of a 16 KB page (landing continues on the next page)", 0, 1, 0x3FFF),
    /* b) instructions with special exceptions */
    CELL(7, "cd03", "int 3 as the two-byte form CD 03", 0, 2, 0xCD, 0x03),
    CELL(8, "f1_icebp", "F1 (int1/icebp)", 0, 1, 0xF1),
    CELL(9, "cd2d", "int 2d (Rip left as given; continuation decided by the landing)", F_NOEDIT, 0, 0xCD, 0x2D),
    CELL(10, "cd29_fastfail", "int 29 terminates the process at once: list only", F_LIST_ONLY, 2, 0xCD, 0x29),
    CELL(11, "ud2", "0F 0B", 0, 2, 0x0F, 0x0B),
    CELL(12, "hlt", "F4", 0, 1, 0xF4),
    CELL(13, "cli", "FA", 0, 1, 0xFA),
    CELL(14, "in_al_imm8", "E4 60", 0, 2, 0xE4, 0x60),
    CELL(15, "rdmsr", "0F 32 (ecx=0x1b)", 0, 2, 0x0F, 0x32),
    CELL(16, "mov_rax_cr0", "0F 20 C0", 0, 3, 0x0F, 0x20, 0xC0),
    CELL(17, "mov_rax_dr7", "0F 21 F8", 0, 3, 0x0F, 0x21, 0xF8),
    /* c) single stepping */
    SP(18, "tf_nop", "TF via popfq, nop under step", F_TF | F_NOEDIT, 0, 0x100),
    SP(19, "tf_cpuid", "TF via popfq, cpuid under step", F_TF | F_NOEDIT, 0, 0x100),
    SP(20, "tf_rdtsc", "TF via popfq, rdtsc under step", F_TF | F_NOEDIT, 0, 0x100),
    SP(21, "tf_pushfq", "TF via popfq, pushfq under step (extra = flags image that landed on the stack)", F_TF | F_NOEDIT, 0, 0x100),
    SP(22, "tf_mov_ss", "TF via popfq, mov ss,eax and the next instruction", F_TF | F_NOEDIT, 0, 0x100),
    SP(23, "tf_rep_movsb3", "TF via popfq, rep movsb of 3 bytes (extra = copied bytes)", F_TF | F_NOEDIT, 0, 0x100),
    /* d) guard page and access violations */
    SP(24, "guard_read", "read of a 64 KB guard region (own allocation)", F_GUARD | F_NOEDIT, 0, 0x100),
    SP(25, "guard_write", "write to a 64 KB guard region (own allocation)", F_GUARD | F_NOEDIT, 0, 0x100),
    SP(26, "guard_exec", "execution inside a 64 KB guard region (call)", F_GUARD | F_NOEDIT | F_ISOLATED, 0, 0x100),
    SP(27, "av_read_unmapped", "read of a reserved-only (uncommitted) 64 KB region", 0, 2, 0x100),
    SP(28, "av_write_unmapped", "write to a reserved-only (uncommitted) 64 KB region", 0, 2, 0x100),
    SP(29, "av_exec_unmapped", "execute in a reserved-only 64 KB region (call)", F_EXECFAULT, 0, 0x100),
    SP(30, "av_write_readonly", "write to a 64 KB read-only region", 0, 2, 0x100),
    SP(31, "av_exec_noexec", "execute in a 64 KB region without execute right (call)", F_EXECFAULT, 0, 0x100),
    SP(32, "av_read_noncanon_bit63", "read at non-canonical 0x8000000000000000", 0, 2, 0x100),
    SP(33, "av_write_noncanon_bit63", "write at non-canonical 0x8000000000000000", 0, 2, 0x100),
    SP(34, "av_read_noncanon_bit48", "read at non-canonical 0x0001000000000000", 0, 2, 0x100),
    SP(35, "av_read_topff", "read at 0xFFFFFFFFFFFFFFFF", 0, 2, 0x100),
    /* e) arithmetic, alignment, RaiseException */
    CELL(36, "div0", "div ecx with ecx=0", 0, 2, 0xF7, 0xF1),
    CELL(37, "idiv_overflow", "idiv ecx: edx:eax=-2^31 / -1", 0, 2, 0xF7, 0xF9),
    SP(38, "movaps_load_misaligned", "movaps xmm0,[rcx] at address +8", 0, 3, 0x100),
    SP(39, "movaps_store_misaligned", "movaps [rcx],xmm0 at address +8", 0, 3, 0x100),
    SP(40, "raise_custom_3params", "RaiseException(0xE0C0FFEE, 0, 3, {...})", F_API, 0, 0),
    /* f) contexts */
    SP(41, "get_thread_context_suspended", "GetThreadContext(CONTEXT_ALL) of another own thread stopped by SuspendThread", F_API, 0, 0),
    SP(42, "rtl_capture_context", "RtlCaptureContext in own thread", F_API, 0, 0),
    /* neighbours */
    CELL(43, "cd01", "CD 01", 0, 2, 0xCD, 0x01),
    CELL(44, "cd2c", "CD 2C", 0, 2, 0xCD, 0x2C),
    CELL(45, "ud0", "0F FF C0", 0, 3, 0x0F, 0xFF, 0xC0),
    CELL(46, "ud1", "0F B9 C0", 0, 3, 0x0F, 0xB9, 0xC0),
    CELL(47, "sti", "FB", 0, 1, 0xFB),
    CELL(48, "out_dx_al", "EE", 0, 1, 0xEE),
    CELL(49, "mov_cr0_rax", "0F 22 C0", 0, 3, 0x0F, 0x22, 0xC0),
    CELL(50, "in_eax_dx", "ED", 0, 1, 0xED),
    CELL(51, "wrmsr", "0F 30 (ecx=0x1b)", 0, 2, 0x0F, 0x30),
    CELL(52, "int_cd80", "CD 80", 0, 2, 0xCD, 0x80),
    /* where execution naturally continues (Rip left untouched) */
    CELL(53, "cc_noedit", "0xCC, Rip left as given", F_NOEDIT, 1, 0xCC),
    CELL(54, "cd03_noedit", "CD 03, Rip left as given", F_NOEDIT, 2, 0xCD, 0x03),
    CELL(55, "f1_noedit", "F1, Rip left as given", F_NOEDIT, 1, 0xF1),
    SP(56, "cc_neighbor_first", "neighbouring byte written, then CC at once and executed", 0, 1, 0x100),
    CELL(57, "div_overflow", "div ecx: edx:eax=2^32 / 1 (quotient does not fit)", 0, 2, 0xF7, 0xF1),
    CELL(58, "ud2_noedit", "0F 0B, Rip left as given", F_NOEDIT, 2, 0x0F, 0x0B),
    CELL(59, "hlt_noedit", "F4, Rip left as given", F_NOEDIT, 1, 0xF4),
    /* 4 KB pages inside a 64 KB block (shows host page size effects) */
    /* state kept across the handler: arithmetic flags, x87 control word, MXCSR */
    SP(68, "flags_keep_int3_all", "CF PF AF ZF SF DF OF set before int3; handler skips; flags read after (extra = after,before)", 0, 1, 0x100),
    SP(69, "flags_keep_int3_alt", "CF AF SF OF set (PF ZF DF clear) before int3; flags read after the handler", 0, 1, 0x100),
    SP(70, "flags_keep_ud2_all", "all arithmetic flags set before ud2 (fault); flags read after the handler", 0, 2, 0x100),
    SP(71, "flags_keep_ud2_alt", "CF AF SF OF set before ud2; flags read after the handler", 0, 2, 0x100),
    SP(72, "flags_keep_div0_all", "all arithmetic flags set before div by zero; flags read after the handler", 0, 2, 0x100),
    SP(73, "flags_keep_av_alt", "CF AF SF OF set before a read access violation; flags read after the handler", 0, 2, 0x100),
    SP(74, "flags_keep_noexc_alt", "control: CF AF SF OF set, nop, no exception; flags read after", 0, 1, 0x100),
    SP(75, "fcw_keep_int3", "FCW set to 037f before int3 (default 027f); FCW read after the handler (extra = after,before)", 0, 1, 0x100),
    SP(76, "mxcsr_keep_int3", "MXCSR set to 00003f80 before int3; MXCSR read after the handler (extra = after,before)", 0, 1, 0x100),
    SP(77, "fp_keep_int3_A", "MXCSR 9fc0 (DAZ|FTZ, masks), FCW 027f, XMM0-15 and ST0-2 known; int3; handler continues; state compared in CONTEXT and after the return", 0, 1, 0x100),
    SP(78, "fp_keep_int3_B", "MXCSR 1f80, FCW 0c7f; int3; same comparison", 0, 1, 0x100),
    SP(79, "fp_keep_avwrite_A", "MXCSR 9fc0, FCW 027f; write to a read-only region; same comparison", 0, 2, 0x100),
    SP(80, "fp_keep_avwrite_B", "MXCSR 1f80, FCW 0c7f; write to a read-only region; same comparison", 0, 2, 0x100),
    SP(81, "fp_keep_raise_A", "MXCSR 9fc0, FCW 027f; RaiseException (only the callee-saved state XMM6-15, FCW, MXCSR control bits are comparable)", F_API, 0, 0x100),
    SP(82, "fp_keep_raise_B", "MXCSR 1f80, FCW 0c7f; RaiseException", F_API, 0, 0x100),
    SP(83, "fp_thread_suspend_resume_A", "own thread holds MXCSR 9fc0, FCW 027f, XMM6-15 known and waits in Sleep(1); main thread SuspendThread, GetThreadContext, ResumeThread; callee-saved state compared after", F_API, 0, 0),
    SP(84, "fp_thread_suspend_resume_B", "same with MXCSR 1f80, FCW 0c7f", F_API, 0, 0),
    SP(85, "fp_thread_get_set_ctx_A", "as 83, plus SetThreadContext with the unchanged context before ResumeThread", F_API, 0, 0),
    SP(86, "fp_thread_get_set_ctx_B", "as 85 with MXCSR 1f80, FCW 0c7f", F_API, 0, 0),
    SP(87, "df_keep_int3", "STD; int3; handler continues; PUSHFQ after: DF must stay 1 (extra = DF after,1)", 0, 1, 0x100),
    SP(88, "df_keep_avwrite", "STD; write to a read-only region; handler continues; DF after", 0, 2, 0x100),
    SP(89, "df_thread_suspend_resume", "own thread runs STD and spins; SuspendThread, GetThreadContext (EFlags shows DF), ResumeThread; DF read back after", F_API, 0, 0),
    SP(90, "df_thread_get_set_ctx", "as 89 with SetThreadContext of the unchanged context before ResumeThread", F_API, 0, 0),
    SP(91, "df_rep_movsb_backward_fault", "STD; REP MOVSB copies 8 bytes backward and faults in the 5th iteration on a no-access region; handler makes it accessible and resumes in place; copy and DF checked (extra = DF after,copy ok)", F_UNPROT, 0, 0x100),
    CELL(64, "ud0_after_nop", "90 0F FF C0 (ud0 not at the block entry)", 0, 4, 0x90, 0x0F, 0xFF, 0xC0),
    CELL(65, "ud1_after_nop", "90 0F B9 C0 (ud1 not at the block entry)", 0, 4, 0x90, 0x0F, 0xB9, 0xC0),
    CELL(66, "cc_patch_ret_in_handler", "handler overwrites the CC at ExceptionAddress with C3 and resumes without editing Rip", F_PATCH_RET, 1, 0xCC),
    CELL(67, "cc_patch_nop_in_handler", "handler overwrites the CC at ExceptionAddress with 90 and resumes without editing Rip", F_PATCH_NOP, 1, 0xCC),
    SP(60, "av_write_ro_subpage", "write to a 4 KB read-only page inside a read-write 64 KB block", 0, 2, 0x100),
    SP(61, "av_read_decommit_subpage", "read of a 4 KB decommitted page inside a committed 64 KB block", 0, 2, 0x100),
    SP(62, "guard_read_subpage", "read of a 4 KB guard page inside a read-write 64 KB block", F_GUARD | F_NOEDIT, 0, 0x100),
    SP(63, "av_exec_noexec_subpage", "execute in a 4 KB non-executable page inside an RWX 64 KB block (call)", F_EXECFAULT, 0, 0x100),
};
#define NCELLS ((int)(sizeof(cells) / sizeof(cells[0])))

static const char *rel(uint64_t a, char *buf) {
    if (g_base && a >= (uint64_t)g_base && a < (uint64_t)g_base + g_size) sprintf(buf, "+%llx", (unsigned long long)(a - (uint64_t)g_base));
    else if (g_spec && a >= (uint64_t)g_spec && a < (uint64_t)g_spec + 0x10000) sprintf(buf, "R+%llx", (unsigned long long)(a - (uint64_t)g_spec));
    else if (a >= (uint64_t)cc_in_image && a < (uint64_t)cc_in_image + 16) sprintf(buf, "F+%llx", (unsigned long long)(a - (uint64_t)cc_in_image));
    else if (g_img && a >= (uint64_t)g_img && a < (uint64_t)g_img + 0x400000) sprintf(buf, "I");
    else if (g_entry_rsp && a + 0x10000 >= g_entry_rsp && a <= g_entry_rsp + 0x10000) sprintf(buf, "S%+lld", (long long)(a - g_entry_rsp));
    else if (a == 0 || a >= 0x0000800000000000ULL || a < 0x10000) sprintf(buf, "%llx", (unsigned long long)a);
    else sprintf(buf, "A");
    return buf;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    if (!g_active) return EXCEPTION_CONTINUE_SEARCH;
    PEXCEPTION_RECORD er = ep->ExceptionRecord; PCONTEXT cx = ep->ContextRecord;
    const Cell *c = g_cell;
    uint64_t rip = cx->Rip;
    /* landing: a CC in the tail of the cell after the first exception was handled */
    if (g_armed && er->ExceptionCode == 0x80000003 && g_land_lo && rip >= g_land_lo && rip <= g_land_lo + 2) {
        if (!g_cont_set) { g_cont = rip; g_cont_set = 1; }
        g_land_calls++;
        cx->Rip = g_land_lo + 3;
        cx->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (g_calls == 0) { g_er = *er; g_cx = *cx; }
    if (g_nsteps < 16) { g_steps[g_nsteps].rip = rip; g_steps[g_nsteps].rsp = cx->Rsp; g_steps[g_nsteps].efl = cx->EFlags; g_steps[g_nsteps].code = er->ExceptionCode; g_nsteps++; }
    g_phase_calls[g_phase & 3]++;
    g_calls++;
    if (c->flags & F_TF) {
        g_armed = 1;
        if (er->ExceptionCode == 0x80000004 && g_calls < g_maxsteps && !(g_land_lo && rip >= g_land_lo)) cx->EFlags |= 0x100u;
        else cx->EFlags &= ~0x100u;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (g_calls > 4) { cx->Rip = g_land_lo ? g_land_lo + 3 : rip; cx->EFlags &= ~0x100u; return EXCEPTION_CONTINUE_EXECUTION; }  /* guard against endless repeat */
    g_armed = 1;
    if (c->flags & F_UNPROT) {
        DWORD o; VirtualProtect(g_spec, 0x20000, PAGE_READWRITE, &o);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c->flags & (F_PATCH_RET | F_PATCH_NOP)) {
        uint8_t *pa = (uint8_t *)er->ExceptionAddress;
        *pa = (c->flags & F_PATCH_RET) ? 0xC3 : 0x90;
        FlushInstructionCache(GetCurrentProcess(), pa, 1);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (c->flags & (F_API | F_GUARD | F_NOEDIT)) return EXCEPTION_CONTINUE_EXECUTION;
    if (c->flags & F_EXECFAULT) { cx->Rip = *(uint64_t *)cx->Rsp; cx->Rsp += 8; return EXCEPTION_CONTINUE_EXECUTION; }
    cx->Rip = g_ia + c->skip;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static uint64_t g_checksum = 0xcbf29ce484222325ULL;
static unsigned g_run, g_skipped;
static void emit(const char *line) {
    for (const unsigned char *p = (const unsigned char *)line; *p; p++) { g_checksum ^= *p; g_checksum *= 0x100000001b3ULL; }
    g_checksum ^= '\n'; g_checksum *= 0x100000001b3ULL;
    fputs(line, stdout); fputc('\n', stdout); fflush(stdout);
}

static void print_cell(const Cell *c) {
    char line[3800], b1[40], b2[40], b3[40]; int n = 0;
    const EXCEPTION_RECORD *e = &g_er; const CONTEXT *x = &g_cx;
    int ctxonly = (c->id == 41 || c->id == 42);
    n += sprintf(line + n, "CELL id=%02d name=%s calls=%u%s", c->id, c->name, g_calls, g_hang ? " HANG=1" : "");
    if (c->id >= 2 && c->id <= 4) n += sprintf(line + n, " p1=%u p2=%u", g_phase_calls[1], g_phase_calls[2]);
    if (!g_calls) { n += sprintf(line + n, " exception=none land=%u cont=%s extra=%llx,%llx", g_land_calls, g_cont_set ? rel(g_cont, b1) : "-", (unsigned long long)g_extra_a, (unsigned long long)g_extra_b); emit(line); return; }
    n += sprintf(line + n, " code=%08lx flags=%08lx addr=%s np=%lu info=[", e->ExceptionCode, e->ExceptionFlags,
                 (c->flags & F_API) ? "API" : rel((uint64_t)e->ExceptionAddress, b1), e->NumberParameters);
    int isav = (e->ExceptionCode == 0xC0000005 || e->ExceptionCode == 0x80000001 || e->ExceptionCode == 0xC0000006);
    int last = (int)e->NumberParameters - 1; if (last > 14) last = 14;
    for (int i = 0; i <= last; i++) {
        if (isav && i == 1) n += sprintf(line + n, "%s%s", i ? "," : "", rel((uint64_t)e->ExceptionInformation[i], b2));
        else n += sprintf(line + n, "%s%llx", i ? "," : "", (unsigned long long)e->ExceptionInformation[i]);
    }
    n += sprintf(line + n, "] rec=%s", e->ExceptionRecord ? "nested" : "0");
    n += sprintf(line + n, " | cf=%08lx rip=%s efl=%08lx cs=%04x ds=%04x es=%04x fs=%04x gs=%04x ss=%04x", x->ContextFlags, (c->flags & F_API) ? "API" : rel(x->Rip, b3), x->EFlags,
                 x->SegCs, x->SegDs, x->SegEs, x->SegFs, x->SegGs, x->SegSs);
    { char d0[40], d1[40], d2[40], d3[40];
      n += sprintf(line + n, " dr0=%s dr1=%s dr2=%s dr3=%s dr6=%llx dr7=%llx", rel(x->Dr0, d0), rel(x->Dr1, d1), rel(x->Dr2, d2), rel(x->Dr3, d3),
                   (unsigned long long)x->Dr6, (unsigned long long)x->Dr7); }
    n += sprintf(line + n, " mxcsr=%08lx fcw=%04x fsw=%04x ftw=%02x fmx=%08lx fmask=%08lx", x->MxCsr, x->FltSave.ControlWord, x->FltSave.StatusWord, x->FltSave.TagWord,
                 x->FltSave.MxCsr, x->FltSave.MxCsr_Mask);
    if (ctxonly || (c->flags & F_API)) n += sprintf(line + n, " rsp=%s", rel(x->Rsp, b2));
    else n += sprintf(line + n, " rsp=%+lld", (long long)(x->Rsp - g_entry_rsp));
    if (!ctxonly && c->id != 19 && c->id != 20) { char ra[40], rc[40], rd[40];
        n += sprintf(line + n, " rax=%s rcx=%s rdx=%s", rel(x->Rax, ra), rel(x->Rcx, rc), rel(x->Rdx, rd)); }
    if (g_nsteps > 1 || (g_nsteps && (c->flags & F_TF))) {
        n += sprintf(line + n, " list=[");
        for (unsigned i = 0; i < g_nsteps; i++) n += sprintf(line + n, "%s%s/%llx/%lx", i ? ";" : "", rel(g_steps[i].rip, b1), (unsigned long long)g_steps[i].efl, (unsigned long)g_steps[i].code);
        n += sprintf(line + n, "]");
    }
    if (c->id >= 77 && c->id <= 86) {
        const FPS *f = &g_fps; unsigned xo = 0, xc = 0, so = 0, sc = 0, i;
        unsigned volmask = (c->id == 81 || c->id == 82 || c->id >= 83) ? 0x003fu : 0;     /* RaiseException: XMM0-5 and the x87 stack are volatile */
        int rs = (c->id == 81 || c->id == 82 || c->id >= 83);
        for (i = 0; i < 16; i++) { if ((volmask >> i) & 1) continue; if (memcmp(f->xmm_out[i], f->xmm_in[i], 16)) xo |= 1u << i; if (memcmp(&x->FltSave.XmmRegisters[i], f->xmm_in[i], 16)) xc |= 1u << i; }
        for (i = 0; i < 3; i++) { if (!rs && memcmp(f->st_out[i], f->st_in[i], 10)) so |= 1u << i; if (!rs && memcmp(&x->FltSave.FloatRegisters[i], f->st_in[i], 10)) sc |= 1u << i; }
        n += sprintf(line + n, " fpin=%08x,%04x fpctx=mxcsr:%08lx,fmx:%08lx,fcw:%04x,xmmdiff:%04x,stdiff:%x fpout=mxcsr:%08x,fcw:%04x,xmmdiff:%04x,stdiff:%x",
                     f->mxcsr_in, f->fcw_in, x->MxCsr, x->FltSave.MxCsr, x->FltSave.ControlWord, xc, sc, f->mxcsr_out, f->fcw_out, xo, so);
    }
    n += sprintf(line + n, " | land=%u cont=%s extra=%llx,%llx", g_land_calls, g_cont_set ? rel(g_cont, b2) : "-", (unsigned long long)g_extra_a, (unsigned long long)g_extra_b);
    emit(line);
}

static void reset_cell(const Cell *c) {
    g_calls = g_land_calls = g_armed = 0; g_cont_set = 0; g_cont = 0; g_nsteps = 0; g_extra_a = g_extra_b = 0; g_probe_val = 0;
    memset(&g_er, 0, sizeof g_er); memset(&g_cx, 0, sizeof g_cx); memset(g_phase_calls, 0, sizeof g_phase_calls); g_phase = 0;
    g_cell = c;
}
static void place(uint32_t off, const uint8_t *code, int n, int with_land) {
    memcpy(g_base + off, code, n);
    if (with_land) { memcpy(g_base + off + n, LAND, 4); g_land_lo = (uint64_t)g_base + off + n; }
}
static void run_stub(uint32_t off, Regs *r) {
    g_armed = 0; g_ia = (uint64_t)g_base + off + g_ia_adj; g_ia_adj = 0;
    FlushInstructionCache(GetCurrentProcess(), g_base, 0x10000);
    call_cell(g_base + off, r, &g_entry_rsp);
}
static DWORD WINAPI spin_thread(LPVOID p) { (void)p; for (;;) Sleep(1); }

static void run_one(const Cell *c) {
    char info[96]; DWORD old;
    fprintf(stderr, "CELLSTART %d %s\n", c->id, c->name); fflush(stderr);
    reset_cell(c);
    g_base = VirtualAlloc(NULL, g_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!g_base) { sprintf(info, "CELL id=%02d name=%s ALLOC_FAILED", c->id, c->name); emit(info); return; }
    g_land_lo = 0; g_entry_rsp = 0;
    Regs r = {0x1111111101010101ULL, 0x3333333303030303ULL, 0x4444444404040404ULL, 0x8888888808080808ULL};
    g_hang = 0; g_cell_tick = GetTickCount64();
    g_active = 1;
    if (mini_setjmp(g_rescue) == 0)
    switch (c->id) {
    case 0: g_armed = 0; g_ia = (uint64_t)cc_in_image; call_cell((void *)cc_in_image, &r, &g_entry_rsp); break;
    case 2: { uint8_t ret = 0xC3, cc = 0xCC; g_phase = 1; place(0x100, &ret, 1, 1); run_stub(0x100, &r);
              g_phase = 2; place(0x100, &cc, 1, 1); run_stub(0x100, &r); } break;
    case 3: { uint8_t ret = 0xC3, cc = 0xCC; g_phase = 1; place(0x100, &cc, 1, 1); run_stub(0x100, &r);
              g_phase = 2; place(0x100, &ret, 1, 1); run_stub(0x100, &r); } break;
    case 4: { uint8_t ret = 0xC3, cc = 0xCC; g_phase = 1; place(0x100, &ret, 1, 1); run_stub(0x100, &r);
              g_base[0x180] = 0x5a;                      /* write to a neighbouring byte of the same page */
              g_phase = 2; place(0x100, &cc, 1, 1); run_stub(0x100, &r); } break;
    case 56: { uint8_t cc = 0xCC; g_base[0x108] = 0x5a; g_base[0x180] = 0xa5; place(0x100, &cc, 1, 1); run_stub(0x100, &r); } break;
    case 5: case 6: { uint8_t cc = 0xCC; place(c->soff, &cc, 1, 1); run_stub(c->soff, &r); } break;
    case 18: case 19: case 20: case 21: case 22: case 23: {
        uint8_t buf[96]; int n = 0;
        if (c->id == 22) { buf[n++] = 0x8C; buf[n++] = 0xD0; }                       /* mov eax,ss */
        if (c->id == 23) { buf[n++] = 0x48; buf[n++] = 0xBE; uint64_t s = (uint64_t)g_base + 0x2000; memcpy(buf + n, &s, 8); n += 8;   /* movabs rsi */
                           buf[n++] = 0x48; buf[n++] = 0xBF; uint64_t d = (uint64_t)g_base + 0x2100; memcpy(buf + n, &d, 8); n += 8;   /* movabs rdi */
                           buf[n++] = 0xB9; buf[n++] = 3; buf[n++] = 0; buf[n++] = 0; buf[n++] = 0; }                                 /* mov ecx,3 */
        const uint8_t pre[] = {TFPRE}; memcpy(buf + n, pre, sizeof pre); n += sizeof pre;
        if (c->id == 18) buf[n++] = 0x90;
        if (c->id == 19) { buf[n++] = 0x0F; buf[n++] = 0xA2; r.rax = 0; r.rcx = 0; }
        if (c->id == 20) { buf[n++] = 0x0F; buf[n++] = 0x31; }
        if (c->id == 21) { buf[n++] = 0x9C; buf[n++] = 0x58; buf[n++] = 0x48; buf[n++] = 0xA3; uint64_t a = (uint64_t)&g_probe_val; memcpy(buf + n, &a, 8); n += 8; }
        if (c->id == 22) { buf[n++] = 0x8E; buf[n++] = 0xD0; buf[n++] = 0x31; buf[n++] = 0xC9; }                                     /* mov ss,eax; xor ecx,ecx */
        if (c->id == 23) { buf[n++] = 0xF3; buf[n++] = 0xA4; }
        buf[n++] = 0x90; buf[n++] = 0x90;
        memset(g_base + 0x2000, 0xab, 16);
        place(0x100, buf, n, 1);
        run_stub(0x100, &r);
        g_extra_a = g_probe_val; g_extra_b = (c->id == 23) ? *(uint32_t *)(g_base + 0x2100) : 0; } break;
    case 24: case 25: case 26: case 62: {
        int sub = (c->id == 62); uint8_t *pg; size_t len = sub ? 0x1000 : 0x10000;
        if (sub) pg = g_base + 0x10000; else { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); pg = g_spec; }
        if (!pg) break;
        if (c->id == 26) { *pg = 0xC3; VirtualProtect(pg, len, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old);
                           const uint8_t code[] = {0xFF, 0xD1}; place(0x100, code, 2, 1); r.rcx = (uint64_t)pg; run_stub(0x100, &r); }
        else { VirtualProtect(pg, len, PAGE_READWRITE | PAGE_GUARD, &old);
               const uint8_t rd[] = {0x8A, 0x01}, wr[] = {0x88, 0x01}; place(0x100, c->id == 25 ? wr : rd, 2, 1); r.rcx = (uint64_t)pg; run_stub(0x100, &r); } } break;
    case 27: case 28: case 30: case 60: case 61: case 32: case 33: case 34: case 35: {
        uint64_t target;
        if (c->id == 27 || c->id == 28) { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS); target = (uint64_t)g_spec; }
        else if (c->id == 30) { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); if (g_spec) VirtualProtect(g_spec, 0x10000, PAGE_READONLY, &old); target = (uint64_t)g_spec; }
        else if (c->id == 60) { VirtualProtect(g_base + 0x11000, 0x1000, PAGE_READONLY, &old); target = (uint64_t)(g_base + 0x11000); }
        else if (c->id == 61) { VirtualFree(g_base + 0x20000, 0x1000, MEM_DECOMMIT); target = (uint64_t)(g_base + 0x20000); }
        else target = (c->id == 32 || c->id == 33) ? 0x8000000000000000ULL : c->id == 34 ? 0x0001000000000000ULL : 0xFFFFFFFFFFFFFFFFULL;
        const uint8_t rd[] = {0x8A, 0x01}, wr[] = {0x88, 0x01};
        int w = (c->id == 28 || c->id == 33 || c->id == 30 || c->id == 60);
        place(0x100, w ? wr : rd, 2, 1);
        r.rcx = target;
        run_stub(0x100, &r); } break;
    case 29: case 31: case 63: {
        uint64_t target;
        if (c->id == 29) { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS); target = (uint64_t)g_spec; }
        else if (c->id == 31) { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); if (g_spec) *g_spec = 0xC3; target = (uint64_t)g_spec; }
        else { uint8_t *nx = g_base + 0x12000; *nx = 0xC3; VirtualProtect(nx, 0x1000, PAGE_READWRITE, &old); target = (uint64_t)nx; }
        const uint8_t code[] = {0xFF, 0xD1}; place(0x100, code, 2, 1);
        r.rcx = target; run_stub(0x100, &r); } break;
    case 38: case 39: {
        const uint8_t ld[] = {0x0F, 0x28, 0x01}, st[] = {0x0F, 0x29, 0x01};
        place(0x100, c->id == 38 ? ld : st, 3, 1); memset(g_base + 0x2000, 0x11, 64); r.rcx = (uint64_t)g_base + 0x2008; run_stub(0x100, &r); } break;
    case 40: { ULONG_PTR prm[3] = {0x1111222233334444ULL, 0x5555666677778888ULL, 0x9999aaaabbbbccccULL}; g_armed = 0; RaiseException(0xE0C0FFEE, 0, 3, prm); } break;
    case 68: case 69: case 70: case 71: case 72: case 73: case 74: case 75: case 76: {
        uint8_t buf[96]; int n = 0, id = c->id;
        uint32_t pat = (id == 68 || id == 70 || id == 72) ? 0xCD5u : 0x891u;
        uint64_t pv = (uint64_t)(uintptr_t)&g_probe_val, ps = (uint64_t)(uintptr_t)g_st;
        if (id <= 74) {
            uint32_t v = pat | 0x202u;
            buf[n++] = 0x41; buf[n++] = 0xBB; memcpy(buf + n, &v, 4); n += 4;      /* mov r11d, imm32 */
            buf[n++] = 0x41; buf[n++] = 0x53; buf[n++] = 0x9D;                      /* push r11; popfq */
        } else {
            buf[n++] = 0x49; buf[n++] = 0xBA; memcpy(buf + n, &ps, 8); n += 8;      /* mov r10, &g_st */
            if (id == 75) { g_st[0] = 0x037f; buf[n++] = 0x41; buf[n++] = 0xD9; buf[n++] = 0x2A; }                      /* fldcw [r10] */
            else          { g_st[1] = 0x00003f80; buf[n++] = 0x41; buf[n++] = 0x0F; buf[n++] = 0xAE; buf[n++] = 0x52; buf[n++] = 0x04; }  /* ldmxcsr [r10+4] */
        }
        g_ia_adj = n;
        if (id == 68 || id == 69 || id == 75 || id == 76) buf[n++] = 0xCC;
        else if (id == 70 || id == 71) { buf[n++] = 0x0F; buf[n++] = 0x0B; }
        else if (id == 72) { buf[n++] = 0xF7; buf[n++] = 0xF1; r.rax = 1; r.rdx = 0; r.rcx = 0; }
        else if (id == 73) { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS); r.rcx = (uint64_t)(uintptr_t)g_spec; buf[n++] = 0x8A; buf[n++] = 0x01; }
        else buf[n++] = 0x90;
        if (id <= 74) { buf[n++] = 0x9C; buf[n++] = 0x58; buf[n++] = 0x48; buf[n++] = 0xA3; memcpy(buf + n, &pv, 8); n += 8; }   /* pushfq; pop rax; mov [g_probe_val], rax */
        else if (id == 75) { buf[n++] = 0x41; buf[n++] = 0xD9; buf[n++] = 0x7A; buf[n++] = 0x02; }                              /* fnstcw [r10+2] */
        else { buf[n++] = 0x41; buf[n++] = 0x0F; buf[n++] = 0xAE; buf[n++] = 0x5A; buf[n++] = 0x08; }                           /* stmxcsr [r10+8] */
        place(0x100, buf, n, 1);
        run_stub(0x100, &r);
        if (id <= 74) { g_extra_a = g_probe_val & 0xCD5u; g_extra_b = pat; }
        else if (id == 75) { g_extra_a = (uint16_t)(g_st[0] >> 16); g_extra_b = (uint16_t)g_st[0]; }
        else { g_extra_a = g_st[2]; g_extra_b = g_st[1]; } } break;
    case 77: case 78: case 79: case 80: case 81: case 82: case 83: case 84: case 85: case 86: {
        int id = c->id, variantB = (id % 2 == 0), thr = id >= 83, raise = (id == 81 || id == 82), av = (id == 79 || id == 80);
        FPS *f = &g_fps; unsigned i;
        memset(f, 0, sizeof *f); f->fn_sleep = (uint64_t)(uintptr_t)Sleep;
        f->mxcsr_in = variantB ? 0x1f80u : 0x9fc0u; f->fcw_in = variantB ? 0x0c7f : 0x027f;
        for (i = 0; i < 16; i++) for (unsigned j = 0; j < 16; j++) f->xmm_in[i][j] = (uint8_t)(0x11 * (i + 1) + j * 3 + 0x40);
        { static const uint8_t st[3][10] = {{0,0,0,0,0,0,0,0x80,0xff,0x3f}, {0x35,0xc2,0x68,0x21,0xa2,0xda,0x0f,0xc9,0x00,0x40}, {0,0,0,0,0,0,0,0xa0,0x04,0x40}};
          for (i = 0; i < 3; i++) memcpy(f->st_in[i], st[i], 10); }
        if (thr) {
            CONTEXT cx; HANDLE th = CreateThread(NULL, 0, fp_thread_proc, f, 0, NULL); int w = 0;
            memset(&cx, 0, sizeof cx);
            while (!f->ready && w++ < 4000) Sleep(1);
            SuspendThread(th); cx.ContextFlags = 0x10001F; GetThreadContext(th, &cx);
            g_calls = 1; g_cx = cx;
            if (id >= 85) { cx.ContextFlags = 0x10001F; SetThreadContext(th, &cx); }
            ResumeThread(th); f->go = 1; WaitForSingleObject(th, 5000); CloseHandle(th);
            break;
        }
        uint8_t buf[640]; int n = 0; uint64_t pf = (uint64_t)(uintptr_t)f, pv = (uint64_t)(uintptr_t)&g_probe_val;
        buf[n++] = 0x49; buf[n++] = 0xBA; memcpy(buf + n, &pf, 8); n += 8;                                  /* mov r10, &f */
        buf[n++] = 0x41; buf[n++] = 0x0F; buf[n++] = 0xAE; buf[n++] = 0x12;                                    /* ldmxcsr [r10] */
        buf[n++] = 0x41; buf[n++] = 0xD9; buf[n++] = 0x6A; buf[n++] = 0x04;                                    /* fldcw [r10+4] */
        for (i = 3; i-- > 0; ) { buf[n++] = 0x41; buf[n++] = 0xDB; buf[n++] = 0xAA; uint32_t d = 264 + 16 * i; memcpy(buf + n, &d, 4); n += 4; } /* fld tbyte [r10+264+16*i] */
        for (i = 0; i < 16; i++) { buf[n++] = (i < 8) ? 0x41 : 0x45; buf[n++] = 0x0F; buf[n++] = 0x10; buf[n++] = 0x82 | ((i & 7) << 3); uint32_t d = 8 + 16 * i; memcpy(buf + n, &d, 4); n += 4; } /* movups xmmN, [r10+d32] */
        { uint32_t v = 0x891u | 0x202u; buf[n++] = 0x41; buf[n++] = 0xBB; memcpy(buf + n, &v, 4); n += 4; buf[n++] = 0x41; buf[n++] = 0x53; buf[n++] = 0x9D; }  /* flags pattern */
        g_ia_adj = n;
        if (id <= 78) buf[n++] = 0xCC;
        else if (av) { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); if (g_spec) { DWORD o; VirtualProtect(g_spec, 0x10000, PAGE_READONLY, &o); }
                       uint64_t pg = (uint64_t)(uintptr_t)g_spec; buf[n++] = 0x48; buf[n++] = 0xB9; memcpy(buf + n, &pg, 8); n += 8; g_ia_adj = n; buf[n++] = 0x88; buf[n++] = 0x01; }
        else { uint64_t rx = (uint64_t)(uintptr_t)RaiseException; g_ia_adj = n;
               buf[n++] = 0x48; buf[n++] = 0x83; buf[n++] = 0xEC; buf[n++] = 0x28;                                   /* sub rsp,40 */
               buf[n++] = 0xB9; { uint32_t code = 0xE0C0FFEEu; memcpy(buf + n, &code, 4); n += 4; }                  /* mov ecx, code */
               buf[n++] = 0x31; buf[n++] = 0xD2; buf[n++] = 0x45; buf[n++] = 0x31; buf[n++] = 0xC0; buf[n++] = 0x45; buf[n++] = 0x31; buf[n++] = 0xC9;   /* xor edx,edx; xor r8d,r8d; xor r9d,r9d */
               buf[n++] = 0x48; buf[n++] = 0xB8; memcpy(buf + n, &rx, 8); n += 8; buf[n++] = 0xFF; buf[n++] = 0xD0;  /* mov rax,&RaiseException; call rax */
               buf[n++] = 0x48; buf[n++] = 0x83; buf[n++] = 0xC4; buf[n++] = 0x28; }                                 /* add rsp,40 */
        buf[n++] = 0x9C; buf[n++] = 0x58; buf[n++] = 0x48; buf[n++] = 0xA3; memcpy(buf + n, &pv, 8); n += 8;       /* pushfq; pop rax; mov [g_probe_val],rax */
        buf[n++] = 0x49; buf[n++] = 0xBA; memcpy(buf + n, &pf, 8); n += 8;                                      /* mov r10, &f */
        buf[n++] = 0x41; buf[n++] = 0x0F; buf[n++] = 0xAE; buf[n++] = 0x9A; { uint32_t d = 328; memcpy(buf + n, &d, 4); n += 4; }   /* stmxcsr [r10+328] */
        buf[n++] = 0x41; buf[n++] = 0xD9; buf[n++] = 0xBA; { uint32_t d = 332; memcpy(buf + n, &d, 4); n += 4; }                    /* fnstcw [r10+332] */
        for (i = 0; i < 16; i++) { buf[n++] = (i < 8) ? 0x41 : 0x45; buf[n++] = 0x0F; buf[n++] = 0x11; buf[n++] = 0x82 | ((i & 7) << 3); uint32_t d = 336 + 16 * i; memcpy(buf + n, &d, 4); n += 4; }   /* movups [r10+d32], xmmN */
        for (i = 0; i < 3; i++) { buf[n++] = 0x41; buf[n++] = 0xDB; buf[n++] = 0xBA; uint32_t d = 592 + 16 * i; memcpy(buf + n, &d, 4); n += 4; }  /* fstp tbyte [r10+592+16*i] */
        buf[n++] = 0xDB; buf[n++] = 0xE3;                                                                          /* fninit */
        place(0x100, buf, n, 1);
        r.rax = 0; run_stub(0x100, &r);
        { static volatile uint32_t dm = 0x1f80; __asm__ volatile("ldmxcsr %0" : : "m"(dm)); }
        g_extra_a = g_probe_val & 0xCD5u; g_extra_b = 0x891; } break;
    case 87: case 88: {
        uint8_t buf[96]; int n = 0; uint64_t pv = (uint64_t)(uintptr_t)&g_probe_val;
        buf[n++] = 0xFD;                                                              /* std */
        if (c->id == 87) { g_ia_adj = n; buf[n++] = 0xCC; }
        else { g_spec = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); if (g_spec) { DWORD o; VirtualProtect(g_spec, 0x10000, PAGE_READONLY, &o); }
               uint64_t pg = (uint64_t)(uintptr_t)g_spec; buf[n++] = 0x48; buf[n++] = 0xB9; memcpy(buf + n, &pg, 8); n += 8; g_ia_adj = n; buf[n++] = 0x88; buf[n++] = 0x01; }
        buf[n++] = 0x9C; buf[n++] = 0x58; buf[n++] = 0x48; buf[n++] = 0xA3; memcpy(buf + n, &pv, 8); n += 8; buf[n++] = 0xFC;   /* pushfq; pop rax; mov [probe],rax; cld */
        place(0x100, buf, n, 1); run_stub(0x100, &r);
        g_extra_a = (g_probe_val >> 10) & 1; g_extra_b = 1; } break;
    case 89: case 90: {
        FPS *f = &g_fps; CONTEXT cx; HANDLE th; int w = 0;
        memset(f, 0, sizeof *f); memset(&cx, 0, sizeof cx);
        th = CreateThread(NULL, 0, df_thread_proc, f, 0, NULL);
        while (!f->ready && w++ < 4000) Sleep(1);
        SuspendThread(th); cx.ContextFlags = 0x10001F; GetThreadContext(th, &cx);
        g_calls = 1; g_cx = cx;
        if (c->id == 90) { cx.ContextFlags = 0x10001F; SetThreadContext(th, &cx); }
        ResumeThread(th); f->go = 1; WaitForSingleObject(th, 5000); CloseHandle(th);
        { uint64_t fl; memcpy(&fl, f->scratch, 8); g_extra_a = (fl >> 10) & 1; g_extra_b = 1; } } break;
    case 91: {
        uint8_t buf[96]; int n = 0; uint64_t pv = (uint64_t)(uintptr_t)&g_probe_val; DWORD o; unsigned k; int ok = 1;
        g_spec = VirtualAlloc(NULL, 0x20000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!g_spec) break;
        VirtualProtect(g_spec, 0x10000, PAGE_NOACCESS, &o);
        for (k = 0; k < 8; k++) g_base[0x2000 + k] = (uint8_t)(0x31 + k);
        { uint64_t ps = (uint64_t)(uintptr_t)(g_base + 0x2000 + 7), pd = (uint64_t)(uintptr_t)(g_spec + 0x10000 + 3);
          buf[n++] = 0x48; buf[n++] = 0xBE; memcpy(buf + n, &ps, 8); n += 8; buf[n++] = 0x48; buf[n++] = 0xBF; memcpy(buf + n, &pd, 8); n += 8; }   /* movabs rsi,rdi */
        buf[n++] = 0xFD; g_ia_adj = n; buf[n++] = 0xF3; buf[n++] = 0xA4;               /* std; rep movsb */
        buf[n++] = 0x9C; buf[n++] = 0x58; buf[n++] = 0x48; buf[n++] = 0xA3; memcpy(buf + n, &pv, 8); n += 8; buf[n++] = 0xFC;
        place(0x100, buf, n, 1);
        r.rcx = 8;
        run_stub(0x100, &r);
        for (k = 0; k < 8; k++) if (g_spec[0x10000 + 3 - 7 + k] != (uint8_t)(0x31 + k)) ok = 0;
        g_extra_a = (g_probe_val >> 10) & 1; g_extra_b = ok; } break;
    case 41: { HANDLE th = CreateThread(NULL, 0, spin_thread, NULL, 0, NULL); Sleep(50); SuspendThread(th);
        CONTEXT cx; memset(&cx, 0, sizeof cx); cx.ContextFlags = 0x10001F; BOOL ok = GetThreadContext(th, &cx);
        g_calls = 1; g_cx = cx; g_extra_a = ok; ResumeThread(th); TerminateThread(th, 0); CloseHandle(th); } break;
    case 42: { CONTEXT cx; memset(&cx, 0xAA, sizeof cx); RtlCaptureContext(&cx); g_calls = 1; g_cx = cx; } break;
    default: {
        place(c->soff, c->code, c->clen, 1);
        if (c->id == 15 || c->id == 51) r.rcx = 0x1b;
        if (c->id == 36) { r.rax = 1; r.rdx = 0; r.rcx = 0; }
        if (c->id == 37) { r.rax = 0x80000000ULL; r.rdx = 0xFFFFFFFFULL; r.rcx = 0xFFFFFFFFULL; }
        if (c->id == 57) { r.rax = 0; r.rdx = 1; r.rcx = 1; }
        run_stub(c->soff, &r); } break;
    }
    g_active = 0;
    g_run++;
    print_cell(c);
    g_hang = 0;
    if (g_spec) { VirtualFree(g_spec, 0, MEM_RELEASE); g_spec = NULL; }
    VirtualFree(g_base, 0, MEM_RELEASE); g_base = NULL;
}

static void list(void) {
    for (int i = 0; i < NCELLS; i++) {
        const Cell *c = &cells[i]; char hex[64] = "";
        for (int k = 0; k < c->clen && c->code; k++) sprintf(hex + strlen(hex), "%02x", c->code[k]);
        printf("LIST id=%02d name=%s bytes=%s skip=%d flags=%u desc=%s\n", c->id, c->name, hex, c->skip, c->flags, c->desc);
    }
    printf("LIST cells=%d\n", NCELLS);
}
static DWORD WINAPI watchdog(LPVOID p) {
    (void)p; ULONGLONG t0 = GetTickCount64();
    for (;;) {
        Sleep(50);
        ULONGLONG now = GetTickCount64();
        if (now - t0 > 45000) { fprintf(stderr, "WATCHDOG timeout cell=%s\n", g_cell ? g_cell->name : "?"); fflush(stderr); ExitProcess(3); }
        if (g_active && !g_hang && now - g_cell_tick > 3000) {
            CONTEXT cx; memset(&cx, 0, sizeof cx); cx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            SuspendThread(g_main_thread);
            if (GetThreadContext(g_main_thread, &cx)) {
                cx.Rip = (DWORD64)(uintptr_t)rescue_entry; cx.Rsp = ((cx.Rsp - 0x400) & ~0xFULL) - 8; cx.EFlags &= ~0x100u;
                g_hang = 1; fprintf(stderr, "HANG cell=%s\n", g_cell ? g_cell->name : "?"); fflush(stderr);
                SetThreadContext(g_main_thread, &cx);
            }
            ResumeThread(g_main_thread);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "all";
    setvbuf(stdout, NULL, _IONBF, 0);
    g_img = (uint8_t *)GetModuleHandleA(NULL);
    if (!strcmp(mode, "list")) { list(); return 0; }
    if (!strcmp(mode, "tsv")) { for (int i = 0; i < NCELLS; i++) printf("c%02d-%s\tcell %d\n", cells[i].id, cells[i].name, cells[i].id); return 0; }
    AddVectoredExceptionHandler(1, veh);
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &g_main_thread, 0, FALSE, DUPLICATE_SAME_ACCESS);
    CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    printf("EXCDUMP version=1 cells=%d context_size=%u record_size=%u\n", NCELLS, (unsigned)sizeof(CONTEXT), (unsigned)sizeof(EXCEPTION_RECORD));
    if (!strcmp(mode, "cell")) {
        int n = argc > 2 ? atoi(argv[2]) : -1;
        for (int i = 0; i < NCELLS; i++) if (cells[i].id == n) {
            if (cells[i].flags & F_LIST_ONLY) { g_skipped++; printf("CELL id=%02d name=%s SKIPPED_LIST_ONLY\n", n, cells[i].name); } else run_one(&cells[i]);
        }
    } else {
        for (int i = 0; i < NCELLS; i++) {
            if (cells[i].flags & F_LIST_ONLY) { g_skipped++; printf("CELL id=%02d name=%s SKIPPED_LIST_ONLY\n", cells[i].id, cells[i].name); continue; }
            if (cells[i].flags & F_ISOLATED) { g_skipped++; printf("CELL id=%02d name=%s SKIPPED_ISOLATED\n", cells[i].id, cells[i].name); continue; }
            run_one(&cells[i]);
        }
    }
    printf("SUMMARY cells=%d run=%u skipped=%u checksum=%016llx\n", NCELLS, g_run, g_skipped, (unsigned long long)g_checksum);
    return 0;
}
