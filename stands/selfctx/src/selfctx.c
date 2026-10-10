/* SPDX-License-Identifier: MIT */
/* selfctx: Get/SetThreadContext, NtGetContextThread/NtSetContextThread and NtContinue applied to the CALLING thread.
 * What the program sees when it reads its own context, and whether writing a context back leaves the rest of the thread state exactly as it was.
 *
 *   selfctx list            cell names (tsv: "name<TAB>cell N")
 *   selfctx cell N          one cell in a fresh process
 *   selfctx all             every cell in turn in one process
 *   selfctx info            machine/OS line (not part of the comparison)
 *
 * The thread state is set to KNOWN values by an assembly stub, the API is called from the stub (callee-saved registers, XMM, x87 and MXCSR are therefore
 * observable at the moment of the call), and the state is captured again when control comes back (after a Set that includes CONTEXT_CONTROL control resumes at
 * a label inside the stub, because Rip/Rsp of the context are patched to it).
 * Known state: rbx rbp rsi rdi r12..r15 = patterns, XMM0..15 = patterns, ST0..ST2 = 1.5 2.5 3.25, FCW 0x0c7f, MXCSR 0x9fc0, (AVX: YMM upper halves = patterns).
 * Flags before a call cannot be observed (the ntdll stub itself clobbers them); after a Set with CONTROL the flags equal EFlags of the context (checked).
 *
 * One line per cell:  CELL <id> <name> ok=0|1 <key=value ...>
 *   ok=1 means: every field that the ideal contract covers equals the known state:
 *     Get: callee-saved GPR, XMM0..15, ST0..2, FCW, MXCSR in the returned context (only for the groups requested), AND the live thread state after the call is unchanged;
 *     Set/Continue: the live thread state after the call equals the context that was given (callee-saved GPR, XMM, ST, FCW, MXCSR, flags when CONTROL), and unrelated state is untouched;
 *     debug-register variants: Dr0..Dr3/Dr7 read back as written (Dr7 bit 10 and reserved bits excluded) and all other state untouched.
 *   Windows reference values for informational fields (cfo=, seg=, efl=, dr=, vol=) are compared by the caller; ok= is only the contract.
 * Build: x86_64-w64-mingw32-gcc -O1 -g0 -fms-extensions -fno-stack-protector -o selfctx.exe selfctx.c
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <intrin.h>

/* ---------------------------------------------------------------- state records */
typedef struct {
    uint64_t gpr[16];       /* rax rcx rdx rbx rsp rbp rsi rdi r8..r15 */   /* 0 */
    uint64_t flags;         /* 128 */
    uint32_t mxcsr;         /* 136 */
    uint16_t fcw;           /* 140 */
    uint16_t fsw;           /* 142 */
    uint8_t xmm[16][16];    /* 144 */
    uint8_t st[3][16];      /* 400 */
    uint8_t ymmhi[16][16];  /* 448 (AVX upper halves, stub fills when g_avx) */
} SS;                       /* 704 */
_Static_assert(sizeof(SS) == 704, "SS");
_Static_assert(__builtin_offsetof(SS, xmm) == 144 && __builtin_offsetof(SS, st) == 400 && __builtin_offsetof(SS, ymmhi) == 448, "SS offsets");
_Static_assert(__builtin_offsetof(CONTEXT, Rip) == 0xF8 && __builtin_offsetof(CONTEXT, Rsp) == 0x98 && sizeof(CONTEXT) == 0x4D0, "CONTEXT offsets");

volatile int g_avx;
void *g_out_p;                 /* referenced from the stub */
uint64_t g_t_rax, g_t_flags;
uint32_t g_phase, g_mode;
void *g_fn2, *g_a1;
__attribute__((used)) const uint32_t d1f80 = 0x1f80;

uint64_t selfctx_stub(void *fn, void *a1, void *a2, const SS *in, SS *out, CONTEXT *patch);
extern char selfctx_resume[];

__asm__(".text\n.globl selfctx_stub\nselfctx_stub:\n.intel_syntax noprefix\n"
        "push rbx\npush rbp\npush rdi\npush rsi\npush r12\npush r13\npush r14\npush r15\nsub rsp, 0x28\n"
        "mov rax, [rsp+0x90]\nmov [rip+g_out_p], rax\n"
        "mov dword ptr [rip+g_phase], 0\n"
        "mov rax, [rsp+0x98]\ntest rax, rax\njz 1f\n"
        "lea r10, [rip+selfctx_resume]\nmov [rax+0xF8], r10\nmov [rax+0x98], rsp\n"
        "1:\n"
        "mov [rip+g_a1], rdx\n"
        "mov r10, rcx\nmov r11, r9\nmov rcx, rdx\nmov rdx, r8\n"
        "fninit\nfldcw [r11+140]\nfld tbyte ptr [r11+432]\nfld tbyte ptr [r11+416]\nfld tbyte ptr [r11+400]\nldmxcsr [r11+136]\n"
        "cmp dword ptr [rip+g_avx], 0\njne 2f\n"
        "movups xmm0,[r11+144]\nmovups xmm1,[r11+160]\nmovups xmm2,[r11+176]\nmovups xmm3,[r11+192]\nmovups xmm4,[r11+208]\nmovups xmm5,[r11+224]\nmovups xmm6,[r11+240]\nmovups xmm7,[r11+256]\n"
        "movups xmm8,[r11+272]\nmovups xmm9,[r11+288]\nmovups xmm10,[r11+304]\nmovups xmm11,[r11+320]\nmovups xmm12,[r11+336]\nmovups xmm13,[r11+352]\nmovups xmm14,[r11+368]\nmovups xmm15,[r11+384]\n"
        "jmp 3f\n"
        "2:\n"
        "vmovups xmm0,[r11+144]\nvinsertf128 ymm0, ymm0, xmmword ptr [r11+448], 1\nvmovups xmm1,[r11+160]\nvinsertf128 ymm1, ymm1, xmmword ptr [r11+464], 1\nvmovups xmm2,[r11+176]\nvinsertf128 ymm2, ymm2, xmmword ptr [r11+480], 1\nvmovups xmm3,[r11+192]\nvinsertf128 ymm3, ymm3, xmmword ptr [r11+496], 1\n"
        "vmovups xmm4,[r11+208]\nvinsertf128 ymm4, ymm4, xmmword ptr [r11+512], 1\nvmovups xmm5,[r11+224]\nvinsertf128 ymm5, ymm5, xmmword ptr [r11+528], 1\nvmovups xmm6,[r11+240]\nvinsertf128 ymm6, ymm6, xmmword ptr [r11+544], 1\nvmovups xmm7,[r11+256]\nvinsertf128 ymm7, ymm7, xmmword ptr [r11+560], 1\n"
        "vmovups xmm8,[r11+272]\nvinsertf128 ymm8, ymm8, xmmword ptr [r11+576], 1\nvmovups xmm9,[r11+288]\nvinsertf128 ymm9, ymm9, xmmword ptr [r11+592], 1\nvmovups xmm10,[r11+304]\nvinsertf128 ymm10, ymm10, xmmword ptr [r11+608], 1\nvmovups xmm11,[r11+320]\nvinsertf128 ymm11, ymm11, xmmword ptr [r11+624], 1\n"
        "vmovups xmm12,[r11+336]\nvinsertf128 ymm12, ymm12, xmmword ptr [r11+640], 1\nvmovups xmm13,[r11+352]\nvinsertf128 ymm13, ymm13, xmmword ptr [r11+656], 1\nvmovups xmm14,[r11+368]\nvinsertf128 ymm14, ymm14, xmmword ptr [r11+672], 1\nvmovups xmm15,[r11+384]\nvinsertf128 ymm15, ymm15, xmmword ptr [r11+688], 1\n"
        "3:\n"
        "mov rbx,[r11+24]\nmov rbp,[r11+40]\nmov rsi,[r11+48]\nmov rdi,[r11+56]\nmov r12,[r11+96]\nmov r13,[r11+104]\nmov r14,[r11+112]\nmov r15,[r11+120]\n"
        "cld\ncall r10\n"
        "cmp dword ptr [rip+g_mode], 1\njne 4f\n"
        "cmp dword ptr [rip+g_phase], 0\njne 4f\n"
        "mov dword ptr [rip+g_phase], 1\nmov rcx, [rip+g_a1]\nxor edx, edx\nmov r10, [rip+g_fn2]\ncall r10\n"
        "4:\njmp 5f\n"
        ".globl selfctx_resume\nselfctx_resume:\n"
        "5:\n"
        "pushfq\npop qword ptr [rip+g_t_flags]\n"
        "mov [rip+g_t_rax], rax\n"
        "mov rax, [rip+g_out_p]\n"
        "mov [rax+8], rcx\nmov [rax+16], rdx\nmov [rax+24], rbx\nmov [rax+32], rsp\nmov [rax+40], rbp\nmov [rax+48], rsi\nmov [rax+56], rdi\n"
        "mov [rax+64], r8\nmov [rax+72], r9\nmov [rax+80], r10\nmov [rax+88], r11\nmov [rax+96], r12\nmov [rax+104], r13\nmov [rax+112], r14\nmov [rax+120], r15\n"
        "mov rcx, [rip+g_t_rax]\nmov [rax+0], rcx\nmov rcx, [rip+g_t_flags]\nmov [rax+128], rcx\n"
        "stmxcsr [rax+136]\nfnstcw [rax+140]\nfnstsw [rax+142]\n"
        "movups [rax+144],xmm0\nmovups [rax+160],xmm1\nmovups [rax+176],xmm2\nmovups [rax+192],xmm3\nmovups [rax+208],xmm4\nmovups [rax+224],xmm5\nmovups [rax+240],xmm6\nmovups [rax+256],xmm7\n"
        "movups [rax+272],xmm8\nmovups [rax+288],xmm9\nmovups [rax+304],xmm10\nmovups [rax+320],xmm11\nmovups [rax+336],xmm12\nmovups [rax+352],xmm13\nmovups [rax+368],xmm14\nmovups [rax+384],xmm15\n"
        "cmp dword ptr [rip+g_avx], 0\nje 6f\n"
        "vextractf128 xmmword ptr [rax+448], ymm0, 1\nvextractf128 xmmword ptr [rax+464], ymm1, 1\nvextractf128 xmmword ptr [rax+480], ymm2, 1\nvextractf128 xmmword ptr [rax+496], ymm3, 1\nvextractf128 xmmword ptr [rax+512], ymm4, 1\nvextractf128 xmmword ptr [rax+528], ymm5, 1\n"
        "vextractf128 xmmword ptr [rax+544], ymm6, 1\nvextractf128 xmmword ptr [rax+560], ymm7, 1\nvextractf128 xmmword ptr [rax+576], ymm8, 1\nvextractf128 xmmword ptr [rax+592], ymm9, 1\nvextractf128 xmmword ptr [rax+608], ymm10, 1\nvextractf128 xmmword ptr [rax+624], ymm11, 1\n"
        "vextractf128 xmmword ptr [rax+640], ymm12, 1\nvextractf128 xmmword ptr [rax+656], ymm13, 1\nvextractf128 xmmword ptr [rax+672], ymm14, 1\nvextractf128 xmmword ptr [rax+688], ymm15, 1\nvzeroupper\n"
        "6:\n"
        "fstp tbyte ptr [rax+400]\nfstp tbyte ptr [rax+416]\nfstp tbyte ptr [rax+432]\n"
        "fninit\nldmxcsr [rip+d1f80]\ncld\n"
        "mov rax, [rip+g_t_rax]\n"
        "add rsp, 0x28\npop r15\npop r14\npop r13\npop r12\npop rsi\npop rdi\npop rbp\npop rbx\nret\n.att_syntax\n");

/* ---------------------------------------------------------------- ntdll */
typedef LONG (NTAPI *nt_ctx_fn)(HANDLE, PCONTEXT);
typedef LONG (NTAPI *nt_cont_fn)(PCONTEXT, BOOLEAN);
static nt_ctx_fn pNtGet, pNtSet; static nt_cont_fn pNtCont;
static void (WINAPI *pCapture)(PCONTEXT);
static BOOL (WINAPI *pInitCtx)(PVOID, DWORD, PCONTEXT *, PDWORD);
static PVOID (WINAPI *pLocate)(PCONTEXT, DWORD, PDWORD);
static BOOL (WINAPI *pSetMask)(PCONTEXT, DWORD64);
#define HSELF ((HANDLE)(LONG_PTR)-2)

static SS known;
static void init_known(void) {
    memset(&known, 0, sizeof known);
    uint64_t g[16] = {0, 0, 0, 0x1111111101010101ULL, 0, 0x2222222202020202ULL, 0x3333333303030303ULL, 0x4444444404040404ULL,
                      0x5555555505050505ULL, 0x6666666606060606ULL, 0x7777777707070707ULL, 0x8888888808080808ULL,
                      0x9999999909090909ULL, 0xAAAAAAAA0A0A0A0AULL, 0xBBBBBBBB0B0B0B0BULL, 0xCCCCCCCC0C0C0C0CULL};
    memcpy(known.gpr, g, sizeof g);
    known.mxcsr = 0x9fc0; known.fcw = 0x0c7f;
    for (int i = 0; i < 16; i++) for (int j = 0; j < 16; j++) { known.xmm[i][j] = (uint8_t)(0x10 * (i + 1) + j); known.ymmhi[i][j] = (uint8_t)(0xE0 - 0x10 * i + j); }
    /* ST0=1.5 ST1=2.5 ST2=3.25 as 80-bit extended */
    static const long double v[3] = {1.5L, 2.5L, 3.25L};
    for (int i = 0; i < 3; i++) { memset(known.st[i], 0, 16); memcpy(known.st[i], &v[i], 10); }
}

/* the named differences between a state and the known state. Contract = what the x64 ABI keeps across a call: rbx rbp rsi rdi r12..r15, XMM6..15,
 * MXCSR control bits, FCW. strict (resume after Set/Continue: every register comes from the context) also checks XMM0..5 and ST0..2. */
static unsigned g_vol_xmm;   /* mask of volatile XMM0..5 that differ (informational) */
static int cmp_regs(const SS *s, const SS *k, int gpr, int fp, int strict, char *why, size_t n) {
    static const char *nm[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    int bad = 0; why[0] = 0; g_vol_xmm = 0;
    if (gpr) for (int i = 3; i < 16; i++) { if (i == 4 || (i >= 8 && i <= 11)) continue; if (s->gpr[i] != k->gpr[i]) { bad++; snprintf(why + strlen(why), n - strlen(why), "%s,", nm[i]); } }
    if (fp) {
        if ((s->mxcsr & 0xFFC0u) != (k->mxcsr & 0xFFC0u)) { bad++; snprintf(why + strlen(why), n - strlen(why), "mxcsr=%x,", s->mxcsr); }
        if (s->fcw != k->fcw) { bad++; snprintf(why + strlen(why), n - strlen(why), "fcw=%x,", s->fcw); }
        unsigned xm = 0; for (int i = 0; i < 16; i++) if (memcmp(s->xmm[i], k->xmm[i], 16)) xm |= 1u << i;
        g_vol_xmm = xm & 0x3Fu;
        if (strict ? xm : (xm & ~0x3Fu)) { bad++; snprintf(why + strlen(why), n - strlen(why), "xmm=%04x,", strict ? xm : (xm & ~0x3Fu)); }
        unsigned sm = 0; for (int i = 0; i < 3; i++) if (memcmp(s->st[i], k->st[i], 10)) sm |= 1u << i;
        if (sm) { bad++; snprintf(why + strlen(why), n - strlen(why), "st=%x,", sm); }
    }
    return bad;
}

/* ---------------------------------------------------------------- cells */
enum { OP_GET, OP_SET_SAME, OP_SET_DR, OP_CONT };
typedef struct { const char *name; int op; DWORD flags; int api; int efl; } Cell;   /* api: 0 Win32 wrapper, 1 Nt* direct */
#define M_CTRL 1u
#define M_INT 2u
#define M_SEG 4u
#define M_FP 8u
#define M_DR 0x10u
#define M_XS 0x40u
#define F_CTRL 0x100001u
#define F_INT  0x100002u
#define F_SEG  0x100004u
#define F_FP   0x100008u
#define F_DR   0x100010u
#define F_XS   0x100040u
#define F_FULL 0x10000Bu
#define F_ALL  0x10001Fu
static const struct { const char *n; DWORD f; } FL[] = {
    {"control", F_CTRL}, {"integer", F_INT}, {"segments", F_SEG}, {"fp", F_FP}, {"debug", F_DR}, {"xstate", F_XS | 0x100000u}, {"full", F_FULL}, {"all", F_ALL},
    {"control_debug", F_CTRL | F_DR}, {"integer_debug", F_INT | F_DR}, {"fp_debug", F_FP | F_DR}, {"full_debug", F_FULL | F_DR}, {"all_xstate", F_ALL | F_XS},
};
#define NFL ((int)(sizeof FL / sizeof FL[0]))
static Cell cells[200]; static int ncells; static char names[200][48];
static void add(const char *n, int op, DWORD f, int api) { snprintf(names[ncells], 48, "%s", n); cells[ncells] = (Cell){names[ncells], op, f, api, 0}; ncells++; }
static void addefl(const char *n, int op, DWORD f, int api, int efl) { add(n, op, f, api); cells[ncells - 1].efl = efl; }
static void build_cells(void) {
    char b[48];
    for (int api = 0; api < 2; api++) for (int i = 0; i < NFL; i++) { snprintf(b, 48, "get_%s_%s", api ? "nt" : "w32", FL[i].n); add(b, OP_GET, FL[i].f, api); }
    for (int api = 0; api < 2; api++) for (int i = 0; i < NFL; i++) { snprintf(b, 48, "set_same_%s_%s", api ? "nt" : "w32", FL[i].n); add(b, OP_SET_SAME, FL[i].f, api); }
    for (int api = 0; api < 2; api++) for (int i = 0; i < NFL; i++) if (FL[i].f & M_DR) { snprintf(b, 48, "set_dr_%s_%s", api ? "nt" : "w32", FL[i].n); add(b, OP_SET_DR, FL[i].f, api); }
    addefl("set_ctrl_efl_snapshot", OP_SET_SAME, F_CTRL, 1, 0);
    addefl("set_ctrl_efl_202", OP_SET_SAME, F_CTRL, 1, 1);
    addefl("set_ctrl_efl_602_df", OP_SET_SAME, F_CTRL, 1, 2);
    addefl("set_ctrl_efl_ed7_all", OP_SET_SAME, F_CTRL, 1, 3);
    add("continue_capture", OP_CONT, F_ALL, 1);
    add("continue_capture_xstate", OP_CONT, F_ALL | F_XS, 1);
    add("load_debug", 100, F_DR, 0);          /* ids >= 100 are load cells (special) */
    add("load_all_but_control", 101, F_INT | F_SEG | F_FP | F_DR, 0);
    add("load_nt_debug", 102, F_DR, 1);
}

typedef struct { CONTEXT *c; void *raw; } Ctx;
static Ctx new_ctx(DWORD flags) {
    Ctx x; x.raw = NULL;
    if (flags & M_XS) {
        DWORD len = 0; PCONTEXT pc = NULL;
        if (pInitCtx) {
            pInitCtx(NULL, flags | 0x100000u, NULL, &len);
            x.raw = _aligned_malloc(len + 64, 64); memset(x.raw, 0, len + 64);
            if (pInitCtx(x.raw, flags | 0x100000u, &pc, &len)) { if (pSetMask) pSetMask(pc, 0x7); x.c = pc; return x; }
        }
    }
    x.raw = _aligned_malloc(sizeof(CONTEXT) + 64, 64); memset(x.raw, 0, sizeof(CONTEXT) + 64);
    x.c = (CONTEXT *)x.raw; x.c->ContextFlags = flags | 0x100000u;
    return x;
}
static void free_ctx(Ctx x) { if (x.raw) _aligned_free(x.raw); }

static void *api_fn(int op, int api) {
    if (op == OP_GET) return api ? (void *)pNtGet : (void *)GetThreadContext;
    return api ? (void *)pNtSet : (void *)SetThreadContext;
}

static int has_ymm(CONTEXT *c, uint8_t out[16][16]) {   /* XSTATE: upper halves from the context */
    DWORD len = 0; if (!pLocate) return 0;
    uint8_t *p = (uint8_t *)pLocate(c, 2 /* XSTATE_AVX */, &len);
    if (!p || len < 256) return 0;
    for (int i = 0; i < 16; i++) memcpy(out[i], p + 16 * i, 16);
    return 1;
}

static void put_ctx_xmm(CONTEXT *c, const SS *s) { memcpy(&c->FltSave.XmmRegisters[0], s->xmm, 256); }

static int run_cell(int id) {
    const Cell *c = &cells[id]; SS out; char why[512], extra[512]; extra[0] = 0; why[0] = 0;
    int ok = 1; LONG st = 0;
    memset(&out, 0, sizeof out);
    if (c->op >= 100) {
        /* load cells: checksum of arithmetic/double/x87/rep work, with and without Get/Set of the own thread in between */
        extern uint64_t checksum_work(int, DWORD, int);
        uint64_t a = checksum_work(0, 0, 0);
        uint64_t b = checksum_work(100000, c->flags, c->api);
        uint64_t a2 = checksum_work(0, 0, 0);
        int good = (a == b) && (a == a2);
        printf("CELL %d %s ok=%d plain=%016llx withctx=%016llx plain2=%016llx\n", id, c->name, good, (unsigned long long)a, (unsigned long long)b, (unsigned long long)a2);
        return !good;
    }
    int ctrl = (c->flags & M_CTRL) != 0, dr = (c->flags & M_DR) != 0;
    Ctx x = new_ctx(c->flags); CONTEXT *ctx = x.c;
    SS in = known; SS pre; int bad;
    if (c->op == OP_GET) {
        ctx->ContextFlags = c->flags | 0x100000u;
        g_mode = 0;
        st = (LONG)selfctx_stub(api_fn(OP_GET, c->api), HSELF, ctx, &in, &out, NULL);
        /* returned context vs known */
        char w1[256]; w1[0] = 0; SS cs; memset(&cs, 0, sizeof cs);
        cs.gpr[3] = ctx->Rbx; cs.gpr[5] = ctx->Rbp; cs.gpr[6] = ctx->Rsi; cs.gpr[7] = ctx->Rdi; cs.gpr[12] = ctx->R12; cs.gpr[13] = ctx->R13; cs.gpr[14] = ctx->R14; cs.gpr[15] = ctx->R15;
        cs.mxcsr = ctx->MxCsr; cs.fcw = ctx->FltSave.ControlWord;
        memcpy(cs.xmm, &ctx->FltSave.XmmRegisters[0], 256);
        for (int i = 0; i < 3; i++) memcpy(cs.st[i], &ctx->FltSave.FloatRegisters[i], 10);
        bad = cmp_regs(&cs, &known, (c->flags & M_INT) != 0, (c->flags & M_FP) != 0, 0, w1, sizeof w1); unsigned vx = g_vol_xmm;
        if (bad) ok = 0;
        int lv = cmp_regs(&out, &known, 1, 1, 0, why, sizeof why);      /* live state after the call */
        if (lv) ok = 0;
        uint8_t yh[16][16]; const char *ym = "na";
        if (c->flags & M_XS) { if (has_ymm(ctx, yh)) { ym = memcmp(yh, known.ymmhi, 256) ? "diff" : "ok"; if (g_avx && ym[0] == 'd') ok = 0; } else ym = "none"; }
        snprintf(extra, sizeof extra, "cfo=%lx st=%lx ctx_diff=[%s] ctx_xmm_vol=%x live_diff=[%s] mx=%x fmx=%x fcw=%x fsw=%x ftw=%x seg=%x:%x:%x:%x:%x:%x efl=%lx rsp_ok=%d vol=%d ymm=%s dr=%llx,%llx,%llx,%llx,%llx,%llx",
                 (unsigned long)ctx->ContextFlags, (unsigned long)st, w1, vx, why, ctx->MxCsr, ctx->FltSave.MxCsr, ctx->FltSave.ControlWord, ctx->FltSave.StatusWord, ctx->FltSave.TagWord,
                 ctx->SegCs, ctx->SegDs, ctx->SegEs, ctx->SegFs, ctx->SegGs, ctx->SegSs, (unsigned long)ctx->EFlags, ctx->Rsp != 0, (ctx->Rax != 0) + (ctx->Rcx != 0) + (ctx->Rdx != 0),
                 ym, dr ? (unsigned long long)ctx->Dr0 : 0ULL, dr ? (unsigned long long)ctx->Dr1 : 0ULL, dr ? (unsigned long long)ctx->Dr2 : 0ULL, dr ? (unsigned long long)ctx->Dr3 : 0ULL,
                 dr ? (unsigned long long)ctx->Dr6 : 0ULL, dr ? (unsigned long long)ctx->Dr7 : 0ULL);
    } else if (c->op == OP_SET_SAME || c->op == OP_SET_DR) {
        /* 1. snapshot through the stub in the known state: the context then describes the known state */
        ctx->ContextFlags = c->flags | 0x100000u;
        g_mode = 0; selfctx_stub(api_fn(OP_GET, c->api), HSELF, ctx, &in, &pre, NULL);
        DWORD64 d0 = 0, d1 = 0, d2 = 0, d3 = 0, d7 = 0;
        if (c->op == OP_SET_DR) {
            ctx->Dr0 = 0x00007ff600001000ULL; ctx->Dr1 = 0x00007ff600002000ULL; ctx->Dr2 = 0x00007ff600003000ULL; ctx->Dr3 = 0x00007ff600004000ULL; ctx->Dr7 = 0;
            d0 = ctx->Dr0; d1 = ctx->Dr1; d2 = ctx->Dr2; d3 = ctx->Dr3; d7 = ctx->Dr7;
        }
        DWORD flags_in = ctx->ContextFlags;
        if (ctrl && c->efl) { static const DWORD ev[4] = {0, 0x202u, 0x602u, 0xED7u}; ctx->EFlags = ev[c->efl]; }
        /* 2. Set from the known state (patch Rip/Rsp inside the stub when CONTROL is part of the flags) */
        ctx->ContextFlags = flags_in;
        g_mode = 0; st = (LONG)selfctx_stub(api_fn(OP_SET_SAME, c->api), HSELF, ctx, &in, &out, ctrl ? ctx : NULL);
        bad = cmp_regs(&out, &known, 1, 1, ctrl, why, sizeof why);
        /* after Set without INTEGER/FP in the flags, those groups must stay as they were (= known); with them they were taken from the snapshot (= known) */
        if (bad) ok = 0;
        if (ctrl) { uint64_t want = ctx->EFlags; uint64_t got = out.flags & 0xCD5u; if (got != (want & 0xCD5u)) { ok = 0; snprintf(why + strlen(why), sizeof why - strlen(why), "flags=%llx,", (unsigned long long)out.flags); } }
        /* debug registers read back */
        char drs[200]; drs[0] = 0;
        if (dr) {
            CONTEXT back; memset(&back, 0, sizeof back); back.ContextFlags = F_DR | 0x100000u;
            GetThreadContext(GetCurrentThread(), &back);
            snprintf(drs, sizeof drs, "dr_back=%llx,%llx,%llx,%llx,%llx", (unsigned long long)back.Dr0, (unsigned long long)back.Dr1, (unsigned long long)back.Dr2, (unsigned long long)back.Dr3, (unsigned long long)back.Dr7);
            if (c->op == OP_SET_DR && (back.Dr0 != d0 || back.Dr1 != d1 || back.Dr2 != d2 || back.Dr3 != d3 || (back.Dr7 & ~0x400ULL) != (d7 & ~0x400ULL))) { ok = 0; strcat(why, "dr_readback,"); }
            if (c->op == OP_SET_DR) { CONTEXT z; memset(&z, 0, sizeof z); z.ContextFlags = F_DR | 0x100000u; SetThreadContext(GetCurrentThread(), &z); }   /* clear again */
        }
        snprintf(extra, sizeof extra, "st=%lx cfo=%lx live_diff=[%s] flags_after=%llx %s", (unsigned long)st, (unsigned long)ctx->ContextFlags, why, (unsigned long long)out.flags, drs);
    } else {   /* OP_CONT: RtlCaptureContext inside the stub, then NtContinue(that context) -> control comes back after the capture call */
        ctx->ContextFlags = c->flags | 0x100000u; pre = in;
        g_mode = 1; g_fn2 = (void *)pNtCont;
        st = (LONG)selfctx_stub((void *)pCapture, ctx, NULL, &in, &out, NULL); g_mode = 0;
        bad = cmp_regs(&out, &known, 1, 1, 1, why, sizeof why);
        if (bad) ok = 0;
        snprintf(extra, sizeof extra, "phase=%u cfo=%lx live_diff=[%s] flags_after=%llx efl_ctx=%lx", g_phase, (unsigned long)ctx->ContextFlags, why, (unsigned long long)out.flags, (unsigned long)ctx->EFlags);
        if (g_phase != 1) ok = 0;
    }
    printf("CELL %d %s ok=%d %s\n", id, c->name, ok, extra);
    free_ctx(x);
    return !ok;
}

/* ---------------------------------------------------------------- load cells */
static volatile uint64_t g_sink;
uint64_t checksum_work(int pairs, DWORD flags, int api) {
    uint32_t saved; __asm__ volatile("stmxcsr %0" : "=m"(saved)); unsigned short fcw0; __asm__ volatile("fnstcw %0" : "=m"(fcw0));
    uint32_t mx = 0x9fc0; __asm__ volatile("ldmxcsr %0" : : "m"(mx));
    unsigned short fc = 0x0c7f; __asm__ volatile("fldcw %0" : : "m"(fc));
    uint64_t cks = 0x9E3779B97F4A7C15ULL, acc = 1; double d0 = 1.0, d1 = 0.0, d2 = 0.5;
    long double ld = 1.0L; unsigned char buf[96], dst[96];
    CONTEXT *c = (CONTEXT *)_aligned_malloc(sizeof(CONTEXT) + 64, 64);
    for (int it = 0; it < 100000; it++) {
        /* arithmetic with flags: add/adc chain */
        unsigned long long lo = (unsigned long long)it * 0x100000001B3ULL, hi = 0; unsigned char cf = 0;
        cf = _addcarry_u64(cf, lo, cks, &hi); cf = _addcarry_u64(cf, acc, hi, &lo); acc = lo ^ (acc << 7) ^ cf;
        /* double sum with denormals (DAZ makes them zero) */
        double tiny = 4.9406564584124654e-324 * (double)(it & 7);   /* denormals */
        d0 += tiny; d1 += d0 * 1e-3; d2 = d2 * 1.0000001 + tiny;
        ld = ld * 1.0000001L + (long double)(it & 3) * 0.25L;           /* x87, rounding per FCW 0x0c7f */
        for (int k = 0; k < 96; k++) buf[k] = (unsigned char)(acc >> ((k & 7) * 8)) ^ (unsigned char)k;
        /* backward copy: std; rep movsb */
        { unsigned char *s = buf + 63, *t = dst + 70; size_t n = 64;
          __asm__ volatile("std\n rep movsb\n cld" : "+S"(s), "+D"(t), "+c"(n) : : "memory"); }
        uint64_t m = 0; for (int k = 0; k < 96; k++) m = m * 131 + dst[k];
        union { double d; uint64_t u; } u1 = {d1}, u0 = {d0}; union { long double l; uint64_t q[2]; } ul = {0}; ul.l = ld;
        cks = (cks ^ acc ^ m ^ u1.u ^ u0.u ^ ul.q[0]) * 0x100000001B3ULL + (uint64_t)it;
        if (it < pairs) {
            memset(c, 0, sizeof *c);
            if (flags & M_DR) { c->ContextFlags = flags | 0x100000u; if (api) { pNtGet(HSELF, c); if (flags == F_DR) { c->Dr0 = 0; c->Dr7 = 0; } pNtSet(HSELF, c); } else { GetThreadContext(GetCurrentThread(), c); SetThreadContext(GetCurrentThread(), c); } }
        }
    }
    _aligned_free(c);
    cks ^= (uint64_t)(d2 * 1e6) ^ (uint64_t)(ld * 1000.0L);
    __asm__ volatile("ldmxcsr %0" : : "m"(saved)); __asm__ volatile("fldcw %0" : : "m"(fcw0));
    g_sink = cks; return cks;
}

/* ---------------------------------------------------------------- main */
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *mode = argc > 1 ? argv[1] : "all";
    HMODULE nt = GetModuleHandleA("ntdll.dll"), k32 = GetModuleHandleA("kernel32.dll");
    pNtGet = (nt_ctx_fn)GetProcAddress(nt, "NtGetContextThread"); pNtSet = (nt_ctx_fn)GetProcAddress(nt, "NtSetContextThread"); pNtCont = (nt_cont_fn)GetProcAddress(nt, "NtContinue");
    pCapture = (void *)GetProcAddress(nt, "RtlCaptureContext");
    pInitCtx = (void *)GetProcAddress(k32, "InitializeContext"); pLocate = (void *)GetProcAddress(k32, "LocateXStateFeature"); pSetMask = (void *)GetProcAddress(k32, "SetXStateFeaturesMask");
    init_known(); build_cells();
    { int r[4]; __cpuid(r, 1); unsigned c = (unsigned)r[2]; int avx = (c >> 28) & 1, osx = (c >> 27) & 1; if (avx && osx) { unsigned lo, hi; __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0)); g_avx = (lo & 6) == 6; } }
    if (!strcmp(mode, "list")) { for (int i = 0; i < ncells; i++) printf("c%02d-%s\tcell %d\n", i, cells[i].name, i); return 0; }
    if (!strcmp(mode, "info")) { printf("INFO avx=%d ntget=%p ntset=%p ntcont=%p initctx=%p locate=%p\n", g_avx, (void *)pNtGet, (void *)pNtSet, (void *)pNtCont, (void *)pInitCtx, (void *)pLocate); return 0; }
    printf("SELFCTX version=1 cells=%d avx=%d\n", ncells, g_avx);
    int bad = 0, n = 0;
    if (!strcmp(mode, "cell")) { int id = argc > 2 ? atoi(argv[2]) : -1; if (id >= 0 && id < ncells) { bad += run_cell(id); n++; } }
    else for (int i = 0; i < ncells; i++) { bad += run_cell(i); n++; }
    printf("TOTAL cells=%d failed=%d\n", n, bad);
    return bad ? 1 : 0;
}
