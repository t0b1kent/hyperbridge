#include "hb_winemetal_compute_v1.h"
#include "hb_memory.h"
#include <stddef.h>
#include <string.h>

_Static_assert(sizeof(void *) == 8, "winemetal native ABI requires 64-bit pointers");
_Static_assert(sizeof(hb_winemetal_compute_params_v1_t) == 32, "native packet size");
_Static_assert(offsetof(hb_winemetal_compute_params_v1_t, info) == 8, "packet info");
_Static_assert(offsetof(hb_winemetal_compute_params_v1_t, ret_error) == 16, "packet error");
_Static_assert(offsetof(hb_winemetal_compute_params_v1_t, ret_pso) == 24, "packet PSO");
_Static_assert(sizeof(hb_winemetal_compute_info_v1_t) == 32, "native info size");
_Static_assert(offsetof(hb_winemetal_compute_info_v1_t, binary_archives_for_lookup) == 8, "info array");
_Static_assert(offsetof(hb_winemetal_compute_info_v1_t, binary_archive_for_serialization) == 16, "info archive");
_Static_assert(offsetof(hb_winemetal_compute_info_v1_t, num_binary_archives_for_lookup) == 24, "info count");
_Static_assert(offsetof(hb_winemetal_compute_info_v1_t, fail_on_binary_archive_miss) == 25, "info fail flag");
_Static_assert(offsetof(hb_winemetal_compute_info_v1_t, support_indirect_command_buffers) == 26, "info indirect flag");
_Static_assert(offsetof(hb_winemetal_compute_info_v1_t, tgsize_is_multiple_of_sgwidth) == 27, "info group flag");
_Static_assert(offsetof(hb_winemetal_compute_info_v1_t, immutable_buffers) == 28, "info mask");

static int valid_span(uint64_t address, size_t size)
{
    return address != 0 && size != 0 && address <= UINT64_MAX - (size - 1);
}

static uint64_t load_le(const uint8_t *source, unsigned size)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < size; ++i) value |= (uint64_t)source[i] << (8 * i);
    return value;
}

static void store_le64(uint8_t *dest, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) dest[i] = (uint8_t)(value >> (8 * i));
}

hb_result_t hb_winemetal_compute_dispatch_v1(
    const hb_context_t *ctx, uint64_t guest_packet,
    hb_winemetal_compute_entry_v1_t entry, hb_winemetal_compute_report_v1_t *report)
{
    if (report) memset(report, 0, sizeof *report);
    if (!ctx || !ctx->memory || ctx->arch != HB_ARCH_X64 || ctx->mode != HB_MODE_64BIT ||
        !entry || !report || !valid_span(guest_packet, 32)) return HB_ERR_INVALID_ARG;

    uint8_t packet_bytes[32], info_bytes[32];
    hb_result_t result = hb_memory_read(ctx->memory, guest_packet, packet_bytes, sizeof packet_bytes);
    if (result != HB_OK) return result;
    /* Preflight is not a pin/transaction; the caller must keep mappings stable. */
    if (!hb_memory_can_write_span(ctx->memory, guest_packet + 16, 16)) return HB_ERR_MEMORY_FAULT;
    uint64_t info_address = load_le(packet_bytes + 8, 8);
    if (!valid_span(info_address, sizeof info_bytes)) return HB_ERR_INVALID_ARG;
    result = hb_memory_read(ctx->memory, info_address, info_bytes, sizeof info_bytes);
    if (result != HB_OK) return result;

    hb_winemetal_compute_info_v1_t info = {0};
    uint64_t archives[HB_WINEMETAL_COMPUTE_MAX_ARCHIVES_V1];
    uint64_t archive_address = load_le(info_bytes + 8, 8);
    info.compute_function = load_le(info_bytes, 8);
    info.binary_archive_for_serialization = load_le(info_bytes + 16, 8);
    info.num_binary_archives_for_lookup = info_bytes[24];
    info.fail_on_binary_archive_miss = info_bytes[25];
    info.support_indirect_command_buffers = info_bytes[26];
    info.tgsize_is_multiple_of_sgwidth = info_bytes[27];
    info.immutable_buffers = (uint32_t)load_le(info_bytes + 28, 4);
    if (info.num_binary_archives_for_lookup && archive_address) {
        size_t bytes = (size_t)info.num_binary_archives_for_lookup * 8;
        if (!valid_span(archive_address, bytes)) return HB_ERR_INVALID_ARG;
        uint8_t archive_bytes[HB_WINEMETAL_COMPUTE_MAX_ARCHIVES_V1 * 8];
        result = hb_memory_read(ctx->memory, archive_address, archive_bytes, bytes);
        if (result != HB_OK) return result;
        for (unsigned i = 0; i < info.num_binary_archives_for_lookup; ++i)
            archives[i] = load_le(archive_bytes + i * 8, 8);
        info.binary_archives_for_lookup = archives;
    }
    hb_winemetal_compute_params_v1_t params = {
        load_le(packet_bytes, 8), &info,
        load_le(packet_bytes + 16, 8), load_le(packet_bytes + 24, 8)
    };
    report->native_status = entry(&params);
    report->native_invoked = 1;
    report->error_handle = params.ret_error;
    report->pipeline_handle = params.ret_pso;
    uint8_t outputs[16];
    store_le64(outputs, params.ret_error);
    store_le64(outputs + 8, params.ret_pso);
    return hb_memory_write(ctx->memory, guest_packet + 16, outputs, sizeof outputs);
}
