/* Standalone test of verbatim functions extracted from our copied Wine source.
 * The extractor supplies the original thread-entry type and conversion closure.
 * Real Wine/HB headers provide layouts; no Wine services or runtime are linked. */
#include <stdarg.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winternl.h>
#include "hb_context.h"
#include <fenv.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hb_wine_x64_context_extract.inc"

static unsigned checks, failures;
static const char *phase;
static DWORD current_flags;
static uint32_t current_mxcsr;

static void check(int ok, const char *what)
{
    ++checks;
    if (!ok) {
        ++failures;
        fprintf(stderr, "FAIL [%s flags=%08x mxcsr=%08x]: %s\n", phase,
                (unsigned)current_flags, current_mxcsr, what);
    }
}

/* Contract mapping, expressed as offsets so the oracle does not call any
 * production converter. RSP is included in the existing INTEGER contract. */
static const struct { size_t hb, wine; } integer_fields[] = {
#define FIELD(h, w) {offsetof(hb_regs_x64_t, h), offsetof(AMD64_CONTEXT, w)}
    FIELD(rax, Rax), FIELD(rbx, Rbx), FIELD(rcx, Rcx), FIELD(rdx, Rdx),
    FIELD(rsp, Rsp), FIELD(rbp, Rbp), FIELD(rsi, Rsi), FIELD(rdi, Rdi),
    FIELD(r8, R8), FIELD(r9, R9), FIELD(r10, R10), FIELD(r11, R11),
    FIELD(r12, R12), FIELD(r13, R13), FIELD(r14, R14), FIELD(r15, R15)
#undef FIELD
};

static void init_hb(hb_context_t *ctx, uint32_t mxcsr, uint64_t salt)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->arch = HB_ARCH_X64;
    ctx->mode = HB_MODE_64BIT;
    for (size_t i = 0; i < sizeof(integer_fields) / sizeof(integer_fields[0]); ++i) {
        uint64_t bits = UINT64_C(0x1020304050607000) + salt + 0x101 * i;
        memcpy((uint8_t *)&ctx->regs.x64 + integer_fields[i].hb, &bits, 8);
    }
    ctx->regs.x64.rip = UINT64_C(0x140000123) + salt;
    ctx->regs.x64.rflags = 0x245;
    ctx->pc = UINT64_C(0x140007890) + salt;
    for (unsigned i = 0; i < 16; ++i) {
        ctx->regs.x64.xmm[i][0] = UINT64_C(0x7ff8000000100000) + salt + i;
        ctx->regs.x64.xmm[i][1] = UINT64_C(0x8000000000200000) + salt + 0x101 * i;
    }
    /* Distinct raw payloads include negative zero and quiet NaNs. */
    ctx->regs.x64.xmm[0][0] = UINT64_C(0x8000000000000000);
    ctx->regs.x64.xmm[15][1] = UINT64_C(0x7fc5432180000000);
    memset(ctx->ymm_hi, 0x6d, sizeof(ctx->ymm_hi));
    memset(&ctx->x87_64, 0x39, sizeof(ctx->x87_64));
    ctx->fs_base = UINT64_C(0x100123450);
    ctx->gs_base = UINT64_C(0x200765430);
    ctx->flags.cf = true;
    ctx->flags.zf = true;
    ctx->step_limit = 987;
    ctx->block_limit = 654;
    ctx->mxcsr = mxcsr;
}

static void init_wine(AMD64_CONTEXT *context, uint32_t mxcsr, uint64_t salt)
{
    memset(context, 0xb6, sizeof(*context));
    context->ContextFlags = CONTEXT_AMD64_ALL;
    for (size_t i = 0; i < sizeof(integer_fields) / sizeof(integer_fields[0]); ++i) {
        uint64_t bits = UINT64_C(0x8877665544332000) + salt + 0x101 * i;
        memcpy((uint8_t *)context + integer_fields[i].wine, &bits, 8);
    }
    context->Rip = UINT64_C(0x180005678) + salt;
    context->EFlags = 0x204; /* Required bit 1 is supplied by import. */
    context->MxCsr = mxcsr ^ 0x2000u; /* Deliberately not the import authority. */
    context->FltSave.MxCsr = mxcsr;
    for (unsigned i = 0; i < 16; ++i) {
        context->FltSave.XmmRegisters[i].Low = UINT64_C(0x7ff8000000500000) + salt + i;
        context->FltSave.XmmRegisters[i].High = (LONGLONG)(UINT64_C(0xfedcba0000600000) + salt + 0x101 * i);
    }
    context->FltSave.XmmRegisters[0].Low = UINT64_C(0x8000000000000000);
    context->FltSave.XmmRegisters[15].High = (LONGLONG)UINT64_C(0x7fc5432180000000);
}

/* The low four flag bits are independent literal selectors from AMD64_CONTEXT:
 * CONTROL=1, INTEGER=2, SEGMENTS=4, FLOATING_POINT=8. Decorations select no state. */
static void expected_capture(AMD64_CONTEXT *dst, const hb_context_t *src, DWORD flags)
{
    dst->ContextFlags = flags | CONTEXT_AMD64;
    if (flags & 1) {
        dst->SegCs = 0x33;
        dst->SegSs = 0x2b;
        dst->EFlags = (DWORD)(src->regs.x64.rflags ? src->regs.x64.rflags : 0x202) | 2;
        dst->Rsp = src->regs.x64.rsp;
        dst->Rip = src->regs.x64.rip;
    }
    if (flags & 2)
        for (size_t i = 0; i < sizeof(integer_fields) / sizeof(integer_fields[0]); ++i)
            memcpy((uint8_t *)dst + integer_fields[i].wine,
                   (const uint8_t *)&src->regs.x64 + integer_fields[i].hb, 8);
    if (flags & 4) {
        dst->SegDs = dst->SegEs = dst->SegGs = 0x2b;
        dst->SegFs = 0x53;
    }
    if (flags & 8) {
        dst->MxCsr = dst->FltSave.MxCsr = src->mxcsr;
        dst->FltSave.ControlWord = 0x37f;
        dst->FltSave.MxCsr_Mask = 0x2ffff;
        memcpy(dst->FltSave.XmmRegisters, src->regs.x64.xmm, 16 * 16);
    }
}

static void expected_apply(hb_context_t *dst, const AMD64_CONTEXT *src, DWORD flags)
{
    if (flags & 2)
        for (size_t i = 0; i < sizeof(integer_fields) / sizeof(integer_fields[0]); ++i)
            memcpy((uint8_t *)&dst->regs.x64 + integer_fields[i].hb,
                   (const uint8_t *)src + integer_fields[i].wine, 8);
    if (flags & 1) {
        dst->regs.x64.rsp = src->Rsp;
        dst->regs.x64.rip = dst->pc = src->Rip;
        dst->regs.x64.rflags = src->EFlags | 2;
    }
    if (flags & 8) {
        memcpy(dst->regs.x64.xmm, src->FltSave.XmmRegisters, 16 * 16);
        dst->mxcsr = src->FltSave.MxCsr;
    }
}

static void expected_copy(AMD64_CONTEXT *dst, const AMD64_CONTEXT *src, DWORD flags)
{
    dst->ContextFlags = flags | CONTEXT_AMD64;
    if (flags & 1) {
        dst->SegCs = src->SegCs;
        dst->SegSs = src->SegSs;
        dst->EFlags = src->EFlags;
        dst->Rsp = src->Rsp;
        dst->Rip = src->Rip;
    }
    if (flags & 2)
        for (size_t i = 0; i < sizeof(integer_fields) / sizeof(integer_fields[0]); ++i)
            memcpy((uint8_t *)dst + integer_fields[i].wine,
                   (const uint8_t *)src + integer_fields[i].wine, 8);
    if (flags & 4) {
        dst->SegDs = src->SegDs;
        dst->SegEs = src->SegEs;
        dst->SegFs = src->SegFs;
        dst->SegGs = src->SegGs;
    }
    if (flags & 8) {
        dst->MxCsr = src->MxCsr;
        memcpy(&dst->FltSave, &src->FltSave, sizeof(dst->FltSave));
    }
}

static void conversions(void)
{
    static const uint32_t values[] = {0x1f80, 0x1fa1, 0x3fa1, 0x5fa1, 0x7fa1, 0xffe1};
    static const DWORD groups[] = {
        CONTEXT_AMD64, CONTEXT_AMD64_CONTROL, CONTEXT_AMD64_INTEGER,
        CONTEXT_AMD64_SEGMENTS, CONTEXT_AMD64_FLOATING_POINT,
        CONTEXT_AMD64_INTEGER | CONTEXT_AMD64_FLOATING_POINT,
        CONTEXT_AMD64_CONTROL | CONTEXT_AMD64_FLOATING_POINT, CONTEXT_AMD64_ALL,
        CONTEXT_AMD64 | CONTEXT_EXCEPTION_ACTIVE | CONTEXT_SERVICE_ACTIVE |
            CONTEXT_EXCEPTION_REQUEST | CONTEXT_EXCEPTION_REPORTING,
        CONTEXT_AMD64_FLOATING_POINT | CONTEXT_EXCEPTION_ACTIVE |
            CONTEXT_SERVICE_ACTIVE | CONTEXT_EXCEPTION_REQUEST | CONTEXT_EXCEPTION_REPORTING
    };
    for (size_t v = 0; v < sizeof(values) / sizeof(values[0]); ++v)
        for (size_t g = 0; g < sizeof(groups) / sizeof(groups[0]); ++g) {
            hb_context_t source, before, target, expected;
            AMD64_CONTEXT wine, wine_before, got, want;
            current_mxcsr = values[v];
            current_flags = groups[g];
            int rounding = fegetround(), exceptions = fetestexcept(FE_ALL_EXCEPT);

            phase = "capture";
            init_hb(&source, values[v], 0x100);
            memcpy(&before, &source, sizeof(before));
            memset(&got, 0xc7, sizeof(got));
            memcpy(&want, &got, sizeof(want));
            expected_capture(&want, &source, groups[g]);
            macrunner_hb_fill_amd64_context_from_regs(&got, &source.regs.x64,
                                                     source.mxcsr, groups[g]);
            check(!memcmp(&got, &want, sizeof(got)), "exact selected capture fields and preserved output bytes");
            check(!memcmp(&source, &before, sizeof(source)), "capture preserves complete HB source");
            if (groups[g] & 8)
                check(got.MxCsr == values[v] && got.FltSave.MxCsr == values[v],
                      "capture preserves both nondefault MXCSR fields");

            phase = "apply";
            init_wine(&wine, values[v], 0x200);
            memcpy(&wine_before, &wine, sizeof(wine));
            init_hb(&target, values[v] ^ 0x4000u, 0x300);
            memcpy(&expected, &target, sizeof(expected));
            expected_apply(&expected, &wine, groups[g]);
            uint64_t entry = macrunner_hb_apply_amd64_context_to_ctx(&target, &wine, groups[g]);
            check(entry == ((groups[g] & 1) ? wine.Rip : 0), "only CONTROL supplies entry override");
            check(!memcmp(&target, &expected, sizeof(target)), "apply preserves all unselected HB state");
            check(!memcmp(&wine, &wine_before, sizeof(wine)), "apply preserves entire Wine input");
            if (groups[g] & 8)
                check(target.mxcsr == wine.FltSave.MxCsr && target.mxcsr != wine.MxCsr,
                      "FltSave MXCSR is the import authority");

            phase = "copy";
            memset(&got, 0xd8, sizeof(got));
            memcpy(&want, &got, sizeof(want));
            expected_copy(&want, &wine, groups[g]);
            macrunner_hb_copy_amd64_context_fields(&got, &wine, groups[g]);
            check(!memcmp(&got, &want, sizeof(got)), "copy changes only selected fields, including FP gating");
            check(!memcmp(&wine, &wine_before, sizeof(wine)), "copy preserves entire source");
            check(fegetround() == rounding && fetestexcept(FE_ALL_EXCEPT) == exceptions,
                  "raw conversions preserve host rounding and exception state");
        }
}

static void snapshot_and_seed(void)
{
    hb_context_t source, source_before, target, expected;
    struct macrunner_hb_x64_thread_context_entry entry, expected_entry;
    AMD64_CONTEXT seed, partial, snapshot;
    current_mxcsr = 0x5fa1;
    current_flags = CONTEXT_AMD64_FLOATING_POINT;

    phase = "partial pending seed";
    init_wine(&seed, current_mxcsr, 0x100);
    init_wine(&partial, 0xffe1, 0x900);
    memset(&entry, 0, sizeof(entry));
    entry.tid = 123;
    entry.pending_seed = TRUE;
    macrunner_hb_copy_amd64_context_fields(&entry.snapshot, &seed, CONTEXT_AMD64_FLOATING_POINT);
    entry.seed_flags = CONTEXT_AMD64_FLOATING_POINT;
    macrunner_hb_copy_amd64_context_fields(&entry.snapshot, &partial, CONTEXT_AMD64_INTEGER);
    entry.seed_flags |= CONTEXT_AMD64_INTEGER;
    memset(&snapshot, 0, sizeof(snapshot));
    expected_copy(&snapshot, &seed, CONTEXT_AMD64_FLOATING_POINT);
    expected_copy(&snapshot, &partial, CONTEXT_AMD64_INTEGER);
    check(!memcmp(&entry.snapshot, &snapshot, sizeof(snapshot)),
          "INTEGER partial set preserves earlier FP seed including both MXCSR fields");
    init_hb(&target, 0x1f80, 0x300);
    memcpy(&expected, &target, sizeof(expected));
    expected_apply(&expected, &snapshot, CONTEXT_AMD64_INTEGER | CONTEXT_AMD64_FLOATING_POINT);
    memcpy(&expected_entry, &entry, sizeof(entry));
    check(macrunner_hb_adopt_seed_into_ctx_locked(&entry, &target) == 0,
          "pending FP/INTEGER seed does not redirect entry");
    check(!memcmp(&target, &expected, sizeof(target)), "actual adoption imports accumulated groups");
    check(!memcmp(&entry, &expected_entry, sizeof(entry)), "clean adoption preserves seed bookkeeping");

    phase = "control pending seed";
    macrunner_hb_copy_amd64_context_fields(&entry.snapshot, &partial, CONTEXT_AMD64_CONTROL);
    entry.seed_flags |= CONTEXT_AMD64_CONTROL;
    expected_copy(&snapshot, &partial, CONTEXT_AMD64_CONTROL);
    init_hb(&target, 0x1f80, 0x300);
    memcpy(&expected, &target, sizeof(expected));
    expected_apply(&expected, &snapshot, CONTEXT_AMD64_FULL);
    check(macrunner_hb_adopt_seed_into_ctx_locked(&entry, &target) == partial.Rip,
          "CONTROL seed supplies actual entry override");
    check(!memcmp(&target, &expected, sizeof(target)), "control accumulation retains earlier FP state");

    for (unsigned pc_present = 0; pc_present < 2; ++pc_present) {
        phase = pc_present ? "dirty snapshot with PC" : "dirty snapshot with RIP fallback";
        init_hb(&source, current_mxcsr, 0x500);
        if (!pc_present) source.pc = 0;
        memcpy(&source_before, &source, sizeof(source));
        memset(&entry, 0x4a, sizeof(entry));
        entry.ctx = &source;
        entry.snapshot_dirty = TRUE;
        entry.pending_seed = TRUE;
        entry.seed_flags = CONTEXT_AMD64_FLOATING_POINT;
        memcpy(&expected_entry, &entry, sizeof(entry));
        memset(&expected_entry.snapshot, 0, sizeof(expected_entry.snapshot));
        expected_capture(&expected_entry.snapshot, &source, CONTEXT_AMD64_ALL);
        expected_entry.snapshot.Rip = pc_present ? source.pc : source.regs.x64.rip;
        expected_entry.snapshot_dirty = FALSE;
        init_hb(&target, 0x1f80, 0x700);
        memcpy(&expected, &target, sizeof(expected));
        expected_apply(&expected, &expected_entry.snapshot, CONTEXT_AMD64_FLOATING_POINT);
        check(macrunner_hb_adopt_seed_into_ctx_locked(&entry, &target) == 0,
              "dirty FP adoption does not redirect entry");
        check(!memcmp(&entry, &expected_entry, sizeof(entry)),
              "actual sync/update captures complete expected snapshot and clears dirty marker");
        check(!memcmp(&target, &expected, sizeof(target)), "dirty adoption imports live MXCSR and XMM");
        check(!memcmp(&source, &source_before, sizeof(source)), "snapshot refresh preserves live source");
    }
}

static void general_protection_records(void)
{
    static const uint64_t instruction_pcs[] = {
        0, UINT64_C(0x140012345), UINT64_C(0x7ffffffeabcd)
    };
    struct record_frame {
        uint64_t before;
        EXCEPTION_RECORD record;
        uint64_t after;
    } actual, expected;

    phase = "general protection record";
    current_flags = 0;
    current_mxcsr = 0;
    for (unsigned int i = 0; i < sizeof(instruction_pcs) / sizeof(instruction_pcs[0]); ++i) {
        memset(&actual, 0xa7, sizeof(actual));
        memcpy(&expected, &actual, sizeof(expected));
        memset(&expected.record, 0, sizeof(expected.record));
        expected.record.ExceptionCode = (DWORD)0xc0000005;
        expected.record.ExceptionAddress = (void *)(uintptr_t)instruction_pcs[i];
        expected.record.NumberParameters = 2;
        expected.record.ExceptionInformation[0] = 0;
        expected.record.ExceptionInformation[1] = (ULONG_PTR)UINT64_MAX;

        macrunner_hb_build_guest_general_protection_record(&actual.record, instruction_pcs[i]);
        check(!memcmp(&actual, &expected, sizeof(actual)),
              "actual #GP builder produces exact Wine record and preserves adjacent canaries");
        check((uint64_t)(uintptr_t)actual.record.ExceptionAddress == instruction_pcs[i],
              "#GP instruction address is preserved, including zero");
        check(actual.record.ExceptionInformation[0] == 0 &&
              actual.record.ExceptionInformation[1] == (ULONG_PTR)UINT64_MAX,
              "#GP without a data address uses Wine read/-1 parameters");
    }
}

int main(void)
{
    phase = "real layouts";
    check(sizeof(AMD64_CONTEXT) == 0x4d0 && offsetof(AMD64_CONTEXT, MxCsr) == 0x34 &&
          offsetof(AMD64_CONTEXT, FltSave) == 0x100 && sizeof(M128A) == 16,
          "compile against actual Wine AMD64 context layout");
    conversions();
    snapshot_and_seed();
    general_protection_records();
    printf("hb_wine_x64_context_test: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
