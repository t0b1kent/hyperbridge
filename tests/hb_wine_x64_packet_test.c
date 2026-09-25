/* Actual copied Wine packet helpers, compiled without Wine service execution.
 * V2 endpoints require complete V2 objects; bad sizes below are format tests,
 * not a claim that arbitrary short caller allocations can be validated. */
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "wine/macrunner_hb_x64_packet.h"
#include "hb_context.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hb_wine_x64_packet_extract.inc"

static unsigned checks, failures;
static const char *phase = "layout";
static const uint64_t TEB_SENTINEL = UINT64_C(0x12345678000);

static void check(int ok, const char *message)
{
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL [%s]: %s\n", phase, message); }
}

static const struct { size_t packet, wine, hb; } gpr_fields[] = {
#define FIELD(p, w) {offsetof(struct xtajit64_amd64_context, p), offsetof(AMD64_CONTEXT, w), offsetof(hb_regs_x64_t, p)}
    FIELD(rax, Rax), FIELD(rbx, Rbx), FIELD(rcx, Rcx), FIELD(rdx, Rdx),
    FIELD(rsi, Rsi), FIELD(rdi, Rdi), FIELD(rsp, Rsp), FIELD(rbp, Rbp),
    FIELD(r8, R8), FIELD(r9, R9), FIELD(r10, R10), FIELD(r11, R11),
    FIELD(r12, R12), FIELD(r13, R13), FIELD(r14, R14), FIELD(r15, R15)
#undef FIELD
};

static void init_wine(AMD64_CONTEXT *context, uint32_t mxcsr)
{
    memset(context, 0xb6, sizeof(*context));
    /* Packet transport is full state even when this metadata lacks FP. */
    context->ContextFlags = CONTEXT_AMD64_INTEGER;
    context->MxCsr = mxcsr ^ 0x2000u;
    context->FltSave.MxCsr = mxcsr;
    context->EFlags = 0x247;
    context->Rip = UINT64_C(0x140005678);
    for (size_t i = 0; i < sizeof(gpr_fields) / sizeof(gpr_fields[0]); ++i) {
        uint64_t bits = UINT64_C(0x1234567000000000) + i * 0x101;
        memcpy((uint8_t *)context + gpr_fields[i].wine, &bits, 8);
    }
    context->SegCs = 0x33; context->SegDs = 0x2b; context->SegEs = 0x31;
    context->SegFs = 0x53; context->SegGs = 0x61; context->SegSs = 0x69;
    for (unsigned i = 0; i < 16; ++i) {
        context->FltSave.XmmRegisters[i].Low = UINT64_C(0x7ff8000000100000) + i;
        context->FltSave.XmmRegisters[i].High = (LONGLONG)(UINT64_C(0xfedcba0000200000) + i * 0x101);
    }
    context->FltSave.XmmRegisters[0].Low = UINT64_C(0x8000000000000000);
    context->FltSave.XmmRegisters[15].High = (LONGLONG)UINT64_C(0x7fc5432180000000);
}

static void init_hb(hb_context_t *ctx, uint32_t mxcsr)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->arch = HB_ARCH_X64; ctx->mode = HB_MODE_64BIT;
    memset(&ctx->regs.x64, 0xc7, sizeof(ctx->regs.x64));
    memset(ctx->ymm_hi, 0x6d, sizeof(ctx->ymm_hi));
    memset(&ctx->x87_64, 0x39, sizeof(ctx->x87_64));
    ctx->mxcsr = mxcsr;
    ctx->pc = UINT64_C(0x18000aaaa);
    ctx->regs.x64.rip = UINT64_C(0x18000bbbb);
    ctx->fs_base = UINT64_C(0x111100000);
    ctx->gs_base = UINT64_C(0x222200000);
    ctx->flags.cf = true; ctx->flags.zf = true;
    ctx->step_limit = 765; ctx->block_limit = 432;
}

static void expected_pack(struct xtajit64_amd64_context *dst, const AMD64_CONTEXT *src)
{
    for (size_t i = 0; i < sizeof(gpr_fields) / sizeof(gpr_fields[0]); ++i)
        memcpy((uint8_t *)dst + gpr_fields[i].packet, (const uint8_t *)src + gpr_fields[i].wine, 8);
    dst->rip = src->Rip; dst->rflags = src->EFlags;
    dst->fs_base = 0; dst->gs_base = TEB_SENTINEL;
    dst->seg_cs = src->SegCs; dst->seg_ds = src->SegDs; dst->seg_es = src->SegEs;
    dst->seg_fs = src->SegFs; dst->seg_gs = src->SegGs; dst->seg_ss = src->SegSs;
    memcpy(dst->xmm, src->FltSave.XmmRegisters, sizeof(dst->xmm));
}

static void expected_unpack(AMD64_CONTEXT *dst, const struct xtajit64_amd64_context *src,
                            const uint32_t *mxcsr)
{
    for (size_t i = 0; i < sizeof(gpr_fields) / sizeof(gpr_fields[0]); ++i)
        memcpy((uint8_t *)dst + gpr_fields[i].wine, (const uint8_t *)src + gpr_fields[i].packet, 8);
    dst->Rip = src->rip; dst->EFlags = (DWORD)src->rflags;
    dst->SegCs = src->seg_cs; dst->SegDs = src->seg_ds; dst->SegEs = src->seg_es;
    dst->SegFs = src->seg_fs; dst->SegGs = src->seg_gs; dst->SegSs = src->seg_ss;
    memcpy(dst->FltSave.XmmRegisters, src->xmm, sizeof(src->xmm));
    if (mxcsr) dst->MxCsr = dst->FltSave.MxCsr = *mxcsr;
}

static void expected_import(hb_context_t *dst, const struct xtajit64_amd64_context *src,
                            const uint32_t *mxcsr, int simulate)
{
    for (size_t i = 0; i < sizeof(gpr_fields) / sizeof(gpr_fields[0]); ++i)
        memcpy((uint8_t *)&dst->regs.x64 + gpr_fields[i].hb,
               (const uint8_t *)src + gpr_fields[i].packet, 8);
    dst->regs.x64.rip = dst->pc = src->rip; dst->regs.x64.rflags = src->rflags;
    dst->fs_base = src->fs_base;
    dst->gs_base = simulate && !src->gs_base ? TEB_SENTINEL : src->gs_base;
    dst->seg_cs = src->seg_cs; dst->seg_ds = src->seg_ds; dst->seg_es = src->seg_es;
    dst->seg_fs = src->seg_fs; dst->seg_gs = src->seg_gs; dst->seg_ss = src->seg_ss;
    memcpy(dst->regs.x64.xmm, src->xmm, sizeof(src->xmm));
    if (mxcsr) dst->mxcsr = *mxcsr;
}

static void expected_export(struct xtajit64_amd64_context *dst, const hb_context_t *src,
                            int simulate)
{
    for (size_t i = 0; i < sizeof(gpr_fields) / sizeof(gpr_fields[0]); ++i)
        memcpy((uint8_t *)dst + gpr_fields[i].packet,
               (const uint8_t *)&src->regs.x64 + gpr_fields[i].hb, 8);
    dst->rip = simulate ? src->regs.x64.rip : src->pc; dst->rflags = src->regs.x64.rflags;
    dst->fs_base = src->fs_base; dst->gs_base = src->gs_base;
    dst->seg_cs = src->seg_cs; dst->seg_ds = src->seg_ds; dst->seg_es = src->seg_es;
    dst->seg_fs = src->seg_fs; dst->seg_gs = src->seg_gs; dst->seg_ss = src->seg_ss;
    memcpy(dst->xmm, src->regs.x64.xmm, sizeof(dst->xmm));
}

static void layouts_and_discovery(void)
{
    struct xtajit64_process_init_params init, expected_init, before_init;
    struct macrunner_hb_register_import_thunk_params probe, expected_probe, before_probe;
    check(sizeof(struct xtajit64_amd64_context) == 432 &&
          offsetof(struct xtajit64_amd64_context, xmm) == 176 &&
          offsetof(struct xtajit64_amd64_context, seg_ss) == 170, "legacy register bytes and padding remain fixed");
    check(sizeof(struct xtajit64_simulate_params) == 464 &&
          sizeof(struct macrunner_hb_x64_import_context_params) == 440,
          "legacy simulation/import sizes remain fixed");
    check(sizeof(struct xtajit64_simulate_params_v2) == 480 &&
          offsetof(struct xtajit64_simulate_params_v2, extension) == 464 &&
          sizeof(struct macrunner_hb_x64_import_context_params_v2) == 456 &&
          offsetof(struct macrunner_hb_x64_import_context_params_v2, extension) == 440,
          "version extension follows complete legacy packet");
    const unsigned ordinals[] = {unix_process_init, unix_thread_init, unix_thread_term,
        unix_process_term, unix_simulate, unix_notify_memory_alloc, unix_notify_memory_protect,
        unix_notify_memory_free, unix_notify_map_view, unix_notify_unmap_view,
        unix_flush_instruction_cache, unix_simulate_v2, unix_funcs_count};
    for (unsigned i = 0; i < sizeof(ordinals) / sizeof(ordinals[0]); ++i)
        check(ordinals[i] == i, "all legacy dispatch ordinals preserved, V2 appended");

    phase = "simulation capability discovery";
    memset(&init, 0xa5, sizeof(init));
    xtajit64_prepare_process_init(&init);
    expected_init = (struct xtajit64_process_init_params){20, 1, 0, 0, 0};
    check(!memcmp(&init, &expected_init, sizeof(init)), "exact bounded process-init request");
    check(xtajit64_process_init_request_valid(&init), "new process-init request valid");
    check(!xtajit64_process_init_supports_v2(&init), "old peer ignoring request cannot advertise V2");
    xtajit64_reply_process_init(&init);
    expected_init.features = 1; expected_init.unix_funcs_count = 12;
    check(!memcmp(&init, &expected_init, sizeof(init)), "reply changes only feature/count outputs");
    check(xtajit64_process_init_supports_v2(&init), "new peer confirms appended ordinal");
    for (unsigned bad = 0; bad < 7; ++bad) {
        xtajit64_prepare_process_init(&init);
        switch (bad) {
            case 0: init.struct_size = 0; break;
            case 1: init.struct_size = 24; break;
            case 2: init.version = 2; break;
            case 3: init.flags = 1; break;
            case 4: init.features = 1; break;
            case 5: init.unix_funcs_count = 12; break;
            case 6: init.version = 0; break;
        }
        memcpy(&before_init, &init, sizeof(init));
        check(!xtajit64_process_init_request_valid(&init), "malformed discovery request rejected");
        check(!memcmp(&init, &before_init, sizeof(init)), "request validation leaves bytes unchanged");
    }
    init = expected_init; init.features = 0;
    check(!xtajit64_process_init_supports_v2(&init), "missing feature rejects new ordinal");
    init = expected_init; init.unix_funcs_count = 11;
    check(!xtajit64_process_init_supports_v2(&init), "table must include V2 ordinal");
    check(!xtajit64_process_init_request_valid(NULL) && !xtajit64_process_init_supports_v2(NULL),
          "null discovery request/reply rejected");

    phase = "import capability discovery";
    memset(&probe, 0xa5, sizeof(probe));
    macrunner_hb_prepare_import_v2_probe(&probe);
    memset(&expected_probe, 0, sizeof(expected_probe));
    expected_probe.module_id = UINT64_C(0x4842583634563201);
    expected_probe.target_module_id = UINT64_C(0x100000000) | sizeof(expected_probe);
    check(!memcmp(&probe, &expected_probe,
                  offsetof(struct macrunner_hb_register_import_thunk_params, import_name) + sizeof(probe.import_name)),
          "probe initializes every declared field of fully sized legacy registration");
    /* C aggregate assignment need not define trailing padding bytes. Preserve
     * the observed padding for the stricter reply/no-mutation comparisons. */
    memcpy(&expected_probe, &probe, sizeof(probe));
    check(!macrunner_hb_import_v2_probe_supported(&probe), "unanswered old-peer probe cannot advertise support");
    check(macrunner_hb_reply_import_v2_probe(&probe), "new import peer answers valid probe");
    expected_probe.guest_target = UINT64_C(0x494d504f52545632);
    check(!memcmp(&probe, &expected_probe, sizeof(probe)), "reply changes only declared output token");
    check(macrunner_hb_import_v2_probe_supported(&probe), "new import peer token recognized");
    for (unsigned bad = 0; bad < 11; ++bad) {
        macrunner_hb_prepare_import_v2_probe(&probe);
        switch (bad) {
            case 0: probe.target = &probe; break;
            case 1: probe.pe_call12 = &probe; break;
            case 2: probe.pe_callback12 = &probe; break;
            case 3: probe.module_id ^= 1; break;
            case 4: probe.target_module_id ^= 1; break;
            case 5: probe.target_module_id ^= UINT64_C(0x100000000); break;
            case 6: probe.target_machine = 1; break;
            case 7: probe.target_module_machine = 1; break;
            case 8: probe.dll_name[0] = 'x'; break;
            case 9: probe.import_name[0] = 'x'; break;
            case 10: probe.guest_target = 1; break;
        }
        memcpy(&before_probe, &probe, sizeof(probe));
        check(!macrunner_hb_reply_import_v2_probe(&probe), "invalid probe receives no reply");
        check(!macrunner_hb_import_v2_probe_supported(&probe), "invalid probe grants no support");
        check(!memcmp(&probe, &before_probe, sizeof(probe)), "probe rejection preserves complete registration record");
    }
    check(!macrunner_hb_reply_import_v2_probe(NULL) && !macrunner_hb_import_v2_probe_supported(NULL),
          "null import discovery rejected");
}

typedef void (*sim_pack_fn)(struct xtajit64_simulate_params_v2 *, const AMD64_CONTEXT *, ULONG64);
typedef NTSTATUS (*sim_unpack_fn)(AMD64_CONTEXT *, const struct xtajit64_simulate_params_v2 *);
static const sim_pack_fn sim_packers[] = {pack_amd64_context_v2, macrunner_hb_xtajit64_pack_context_v2};
static const sim_unpack_fn sim_unpackers[] = {unpack_amd64_context_v2, macrunner_hb_xtajit64_unpack_context_v2};

static void initialized_context(void)
{
    AMD64_CONTEXT context, expected_context;
    struct xtajit64_simulate_params_v2 packet, expected_packet;
    struct macrunner_hb_x64_import_context_params_v2 import_packet, expected_import_packet;
    struct xtajit64_amd64_context registers;
    phase = "fresh loader context defaults";
    memset(&context, 0xa5, sizeof(context));
    memset(&expected_context, 0, sizeof(expected_context));
    expected_context.ContextFlags = CONTEXT_AMD64_FULL;
    expected_context.MxCsr = expected_context.FltSave.MxCsr = 0x1f80;
    expected_context.SegCs = 0x33;
    expected_context.SegSs = 0x2b;
    expected_context.EFlags = 0x202;
    macrunner_hb_xtajit64_initialize_context(&context);
    check(!memcmp(&context, &expected_context, sizeof(context)),
          "actual initializer sets both MXCSR defaults and otherwise exact context bytes");
    memset(&expected_packet, 0, sizeof(expected_packet));
    expected_pack(&expected_packet.v1.context, &expected_context);
    expected_packet.extension = (struct macrunner_hb_x64_packet_extension){480, 2, 0x1f80, 0};
    for (unsigned producer = 0; producer < 2; ++producer) {
        memset(&packet, 0xb6, sizeof(packet));
        sim_packers[producer](&packet, &context, TEB_SENTINEL);
        check(!memcmp(&packet, &expected_packet, sizeof(packet)),
              "both simulation producers transport initialized FltSave default instead of zero");
        check(!memcmp(&context, &expected_context, sizeof(context)),
              "packing initialized context preserves all source bytes");
    }
    memset(&expected_import_packet, 0, sizeof(expected_import_packet));
    memset(&registers, 0, sizeof(registers));
    expected_pack(&registers, &expected_context);
    memcpy(&expected_import_packet.v1, &registers, sizeof(registers));
    expected_import_packet.extension = (struct macrunner_hb_x64_packet_extension){456, 2, 0x1f80, 0};
    macrunner_hb_xtajit64_pack_import_context_v2(&import_packet, &context, TEB_SENTINEL);
    check(!memcmp(&import_packet, &expected_import_packet, sizeof(import_packet)),
          "import producer also transports initialized MXCSR default");
}

static void simulation_roundtrip(uint32_t mxcsr)
{
    const uint32_t output_mxcsr = mxcsr ^ 0x6000u;
    AMD64_CONTEXT source, before_source, returned, expected_return;
    hb_context_t ctx, expected_ctx, before_ctx;
    struct { uint64_t pre[2]; struct xtajit64_simulate_params_v2 packet; uint64_t post[2]; } got, want;
    init_wine(&source, mxcsr);
    memcpy(&before_source, &source, sizeof(source));
    for (unsigned producer = 0; producer < 2; ++producer) {
        phase = producer ? "loader simulation V2" : "CPU simulation V2";
        memset(&got, 0xa5, sizeof(got));
        memcpy(&want, &got, sizeof(got));
        memset(&want.packet, 0, sizeof(want.packet));
        expected_pack(&want.packet.v1.context, &source);
        want.packet.extension = (struct macrunner_hb_x64_packet_extension){480, 2, mxcsr, 0};
        sim_packers[producer](&got.packet, &source, TEB_SENTINEL);
        check(!memcmp(&got, &want, sizeof(got)), "exact full-state pack, header, padding and guard bytes");
        check(!memcmp(&source, &before_source, sizeof(source)), "pack preserves all Windows source state");
        check(got.packet.extension.mxcsr == source.FltSave.MxCsr &&
              got.packet.extension.mxcsr != source.MxCsr, "pack uses FltSave MXCSR even without FP ContextFlags");

        /* Nonzero GS passes through; zero uses the explicit simulation fallback. */
        if (mxcsr & 1) got.packet.v1.context.gs_base = want.packet.v1.context.gs_base = 0;
        init_hb(&ctx, mxcsr ^ 0x4000u);
        memcpy(&expected_ctx, &ctx, sizeof(ctx));
        expected_import(&expected_ctx, &want.packet.v1.context, &mxcsr, 1);
        check(import_context_v2(&ctx, &got.packet, TEB_SENTINEL) == STATUS_SUCCESS,
              "actual Unix V2 import succeeds");
        check(!memcmp(&ctx, &expected_ctx, sizeof(ctx)), "Unix import changes only declared full-state fields");
        check(!memcmp(&got, &want, sizeof(got)), "import preserves complete input packet and guards");

        /* Standalone conversion of independently seeded guest output; no guest code runs. */
        init_hb(&ctx, output_mxcsr);
        memcpy(ctx.regs.x64.xmm, source.FltSave.XmmRegisters, sizeof(ctx.regs.x64.xmm));
        ctx.regs.x64.xmm[7][1] ^= UINT64_C(0x0055000055000055);
        memcpy(&before_ctx, &ctx, sizeof(ctx));
        expected_export(&want.packet.v1.context, &ctx, 1);
        want.packet.extension.mxcsr = output_mxcsr;
        check(export_context_v2(&got.packet, &ctx) == STATUS_SUCCESS, "actual Unix V2 export succeeds");
        check(!memcmp(&got, &want, sizeof(got)), "export preserves metadata/header and uses register RIP");
        check(!memcmp(&ctx, &before_ctx, sizeof(ctx)), "export preserves entire HB source state");
        for (unsigned consumer = 0; consumer < 2; ++consumer) {
            memset(&returned, 0xd8, sizeof(returned));
            memcpy(&expected_return, &returned, sizeof(returned));
            expected_unpack(&expected_return, &want.packet.v1.context, &output_mxcsr);
            check(sim_unpackers[consumer](&returned, &got.packet) == STATUS_SUCCESS,
                  "both PE consumers accept either producer's V2 packet");
            check(!memcmp(&returned, &expected_return, sizeof(returned)),
                  "PE unpack restores all XMM lanes/both MXCSR fields and preserves unrelated state");
            check(!memcmp(&got, &want, sizeof(got)), "unpack preserves source packet and guards");
        }
    }
}

static void import_roundtrip(uint32_t mxcsr)
{
    const uint32_t output_mxcsr = mxcsr ^ 0x6000u;
    AMD64_CONTEXT source, before_source, returned, expected_return;
    hb_context_t ctx, expected_ctx, before_ctx;
    struct xtajit64_amd64_context registers;
    struct { uint64_t pre[2]; struct macrunner_hb_x64_import_context_params_v2 packet; uint64_t post[2]; } got, want;
    phase = "native import handoff V2 converters";
    init_wine(&source, mxcsr);
    memcpy(&before_source, &source, sizeof(source));
    memset(&got, 0xa5, sizeof(got));
    memcpy(&want, &got, sizeof(got));
    memset(&want.packet, 0, sizeof(want.packet));
    memset(&registers, 0, sizeof(registers));
    expected_pack(&registers, &source);
    memcpy(&want.packet.v1, &registers, sizeof(registers));
    want.packet.extension = (struct macrunner_hb_x64_packet_extension){456, 2, mxcsr, 0};
    macrunner_hb_xtajit64_pack_import_context_v2(&got.packet, &source, TEB_SENTINEL);
    check(!memcmp(&got, &want, sizeof(got)), "exact import pack preserves legacy prefix and guards");
    check(!memcmp(&source, &before_source, sizeof(source)), "import producer preserves Windows source");
    if (mxcsr & 1) got.packet.v1.gs_base = want.packet.v1.gs_base = 0;
    memcpy(&registers, &want.packet.v1, sizeof(registers));
    init_hb(&ctx, mxcsr ^ 0x4000u);
    memcpy(&expected_ctx, &ctx, sizeof(ctx));
    expected_import(&expected_ctx, &registers, &mxcsr, 0);
    macrunner_hb_import_context_to_ctx(&ctx, &got.packet.v1, &got.packet.extension.mxcsr);
    check(!memcmp(&ctx, &expected_ctx, sizeof(ctx)), "actual ntdll import preserves raw zero GS and unrelated HB state");
    check(!memcmp(&got, &want, sizeof(got)), "ntdll import preserves input packet");
    init_hb(&ctx, output_mxcsr);
    memcpy(ctx.regs.x64.xmm, source.FltSave.XmmRegisters, sizeof(ctx.regs.x64.xmm));
    memcpy(&before_ctx, &ctx, sizeof(ctx));
    expected_export(&registers, &ctx, 0);
    memcpy(&want.packet.v1, &registers, sizeof(registers));
    want.packet.extension.mxcsr = output_mxcsr;
    macrunner_hb_export_context_from_ctx(&got.packet.v1, &ctx, &got.packet.extension.mxcsr);
    check(!memcmp(&got, &want, sizeof(got)), "ntdll export uses context PC and preserves handled/status/header");
    check(!memcmp(&ctx, &before_ctx, sizeof(ctx)), "ntdll export preserves entire HB source");
    memset(&returned, 0xd8, sizeof(returned));
    memcpy(&expected_return, &returned, sizeof(returned));
    expected_unpack(&expected_return, &registers, &output_mxcsr);
    check(macrunner_hb_xtajit64_unpack_import_context_v2(&returned, &got.packet) == STATUS_SUCCESS,
          "actual import PE consumer succeeds");
    check(!memcmp(&returned, &expected_return, sizeof(returned)), "import consumer restores all XMM/both MXCSR fields");
    check(!memcmp(&got, &want, sizeof(got)), "import consumer preserves complete source packet");
}

static void corrupt_extension(struct macrunner_hb_x64_packet_extension *extension, unsigned which)
{
    switch (which) {
        case 0: extension->struct_size = 0; break;
        case 1: --extension->struct_size; break;
        case 2: extension->struct_size += 8; break;
        case 3: extension->struct_size -= 16; break; /* V1 byte count. */
        case 4: extension->struct_size = UINT32_MAX; break;
        case 5: extension->version = 0; break;
        case 6: extension->version = 1; break;
        case 7: extension->version = 3; break;
        case 8: extension->version = UINT32_MAX; break;
        case 9: extension->flags = 1; break;
        case 10: extension->flags = UINT32_MAX; break;
    }
}

static void rejection(void)
{
    AMD64_CONTEXT source, target, before_target;
    hb_context_t ctx, before_ctx;
    struct xtajit64_simulate_params_v2 sim, before_sim;
    struct macrunner_hb_x64_import_context_params_v2 import, before_import;
    phase = "V2 validation before mutation";
    init_wine(&source, 0x3fa1);
    for (unsigned bad = 0; bad < 11; ++bad) {
        pack_amd64_context_v2(&sim, &source, TEB_SENTINEL);
        macrunner_hb_xtajit64_pack_import_context_v2(&import, &source, TEB_SENTINEL);
        corrupt_extension(&sim.extension, bad);
        corrupt_extension(&import.extension, bad);
        memcpy(&before_sim, &sim, sizeof(sim));
        memcpy(&before_import, &import, sizeof(import));
        memset(&target, 0xd8, sizeof(target));
        memcpy(&before_target, &target, sizeof(target));
        init_hb(&ctx, 0x5fa1);
        memcpy(&before_ctx, &ctx, sizeof(ctx));
        check(!macrunner_hb_x64_packet_extension_valid(&sim.extension, 480) &&
              !macrunner_hb_x64_packet_extension_valid(&import.extension, 456),
              "shared format validator rejects malformed complete packet");
        for (unsigned consumer = 0; consumer < 2; ++consumer) {
            check(sim_unpackers[consumer](&target, &sim) == STATUS_INVALID_PARAMETER,
                  "PE simulation consumer returns exact invalid-parameter error");
            check(!memcmp(&target, &before_target, sizeof(target)), "rejected PE unpack preserves entire target");
        }
        check(import_context_v2(&ctx, &sim, TEB_SENTINEL) == STATUS_INVALID_PARAMETER,
              "Unix simulation import rejects malformed packet");
        check(!memcmp(&ctx, &before_ctx, sizeof(ctx)), "rejected Unix import preserves entire HB state");
        check(export_context_v2(&sim, &ctx) == STATUS_INVALID_PARAMETER,
              "Unix simulation export rejects malformed destination header");
        check(!memcmp(&ctx, &before_ctx, sizeof(ctx)), "rejected export preserves entire HB source");
        check(macrunner_hb_xtajit64_unpack_import_context_v2(&target, &import) == STATUS_INVALID_PARAMETER,
              "PE import consumer rejects malformed packet");
        check(!memcmp(&target, &before_target, sizeof(target)), "rejected import unpack preserves entire target");
        check(!memcmp(&sim, &before_sim, sizeof(sim)) && !memcmp(&import, &before_import, sizeof(import)),
              "all rejection paths preserve complete packet bytes, including results");
    }
    pack_amd64_context_v2(&sim, &source, TEB_SENTINEL);
    macrunner_hb_xtajit64_pack_import_context_v2(&import, &source, TEB_SENTINEL);
    memcpy(&before_sim, &sim, sizeof(sim));
    memcpy(&before_import, &import, sizeof(import));
    for (unsigned consumer = 0; consumer < 2; ++consumer) {
        check(sim_unpackers[consumer](NULL, &sim) == STATUS_INVALID_PARAMETER &&
              sim_unpackers[consumer](&target, NULL) == STATUS_INVALID_PARAMETER, "null simulation unpack pointers rejected");
    }
    check(import_context_v2(NULL, &sim, TEB_SENTINEL) == STATUS_INVALID_PARAMETER &&
          import_context_v2(&ctx, NULL, TEB_SENTINEL) == STATUS_INVALID_PARAMETER &&
          export_context_v2(NULL, &ctx) == STATUS_INVALID_PARAMETER &&
          export_context_v2(&sim, NULL) == STATUS_INVALID_PARAMETER, "null Unix conversion pointers rejected");
    check(macrunner_hb_xtajit64_unpack_import_context_v2(NULL, &import) == STATUS_INVALID_PARAMETER &&
          macrunner_hb_xtajit64_unpack_import_context_v2(&target, NULL) == STATUS_INVALID_PARAMETER,
          "null import unpack pointers rejected");
    check(!macrunner_hb_x64_packet_extension_valid(NULL, 480), "null extension rejected");
    check(!memcmp(&ctx, &before_ctx, sizeof(ctx)) && !memcmp(&target, &before_target, sizeof(target)) &&
          !memcmp(&sim, &before_sim, sizeof(sim)) && !memcmp(&import, &before_import, sizeof(import)),
          "null-input failures preserve every remaining valid object");
}

static void legacy_preservation(void)
{
    AMD64_CONTEXT source, target, expected_target;
    hb_context_t ctx, expected_ctx;
    struct { uint64_t pre[2]; struct xtajit64_amd64_context packet; uint64_t post[2]; } got, want;
    struct { uint64_t pre[2]; struct macrunner_hb_x64_import_context_params packet; uint64_t post[2]; } old_import, expected_import_packet;
    phase = "unchanged V1 conversion contracts";
    init_wine(&source, 0x7fa1);
    for (unsigned producer = 0; producer < 2; ++producer) {
        memset(&got, 0xa5, sizeof(got)); memcpy(&want, &got, sizeof(got));
        expected_pack(&want.packet, &source);
        if (producer) macrunner_hb_xtajit64_pack_context(&got.packet, &source, TEB_SENTINEL);
        else pack_amd64_context(&got.packet, &source, TEB_SENTINEL);
        check(!memcmp(&got, &want, sizeof(got)), "V1 pack preserves padding and writes no MXCSR extension");
        memset(&target, 0xd8, sizeof(target)); memcpy(&expected_target, &target, sizeof(target));
        expected_unpack(&expected_target, &want.packet, NULL);
        if (producer) macrunner_hb_xtajit64_unpack_context(&target, &got.packet);
        else unpack_amd64_context(&target, &got.packet);
        check(!memcmp(&target, &expected_target, sizeof(target)), "V1 unpack preserves both existing Windows MXCSR fields");
    }
    got.packet.gs_base = want.packet.gs_base = 0;
    init_hb(&ctx, 0x5fa1); memcpy(&expected_ctx, &ctx, sizeof(ctx));
    expected_import(&expected_ctx, &want.packet, NULL, 1);
    import_context(&ctx, &got.packet, TEB_SENTINEL);
    check(!memcmp(&ctx, &expected_ctx, sizeof(ctx)), "V1 simulation import retains MXCSR and zero-GS fallback");
    init_hb(&ctx, 0x3fa1);
    expected_export(&want.packet, &ctx, 1);
    export_context(&got.packet, &ctx);
    check(!memcmp(&got, &want, sizeof(got)), "V1 simulation export uses register RIP and preserves guards");

    memset(&old_import, 0xa5, sizeof(old_import));
    memcpy(&expected_import_packet, &old_import, sizeof(old_import));
    memset(&expected_import_packet.packet, 0, sizeof(expected_import_packet.packet));
    memset(&want.packet, 0, sizeof(want.packet)); expected_pack(&want.packet, &source);
    memcpy(&expected_import_packet.packet, &want.packet, sizeof(want.packet));
    macrunner_hb_xtajit64_pack_import_context(&old_import.packet, &source, TEB_SENTINEL);
    check(!memcmp(&old_import, &expected_import_packet, sizeof(old_import)), "legacy import pack retains exact 440-byte object and guards");
    memset(&target, 0xd8, sizeof(target)); memcpy(&expected_target, &target, sizeof(target));
    expected_unpack(&expected_target, &want.packet, NULL);
    macrunner_hb_xtajit64_unpack_import_context(&target, &old_import.packet);
    check(!memcmp(&target, &expected_target, sizeof(target)), "legacy import unpack retains existing MXCSR fields");
    old_import.packet.gs_base = expected_import_packet.packet.gs_base = want.packet.gs_base = 0;
    init_hb(&ctx, 0x5fa1); memcpy(&expected_ctx, &ctx, sizeof(ctx));
    expected_import(&expected_ctx, &want.packet, NULL, 0);
    macrunner_hb_import_context_to_ctx(&ctx, &old_import.packet, NULL);
    check(!memcmp(&ctx, &expected_ctx, sizeof(ctx)), "V1 ntdll import retains raw zero GS and HB MXCSR");
    init_hb(&ctx, 0x3fa1);
    expected_export(&want.packet, &ctx, 0);
    memcpy(&expected_import_packet.packet, &want.packet, sizeof(want.packet));
    macrunner_hb_export_context_from_ctx(&old_import.packet, &ctx, NULL);
    check(!memcmp(&old_import, &expected_import_packet, sizeof(old_import)), "V1 ntdll export retains context PC convention and guard bytes");
}

int main(void)
{
    static const uint32_t mxcsr_values[] = {0, 0x6000, 0x1f80, 0x1fa1, 0x3fa1, 0x5fa1, 0x7fa1, 0xffe1};
    layouts_and_discovery();
    initialized_context();
    for (size_t i = 0; i < sizeof(mxcsr_values) / sizeof(mxcsr_values[0]); ++i) {
        simulation_roundtrip(mxcsr_values[i]);
        import_roundtrip(mxcsr_values[i]);
    }
    rejection();
    legacy_preservation();
    printf("hb_wine_x64_packet_test: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
