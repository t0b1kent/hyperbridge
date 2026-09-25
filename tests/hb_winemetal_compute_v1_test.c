#include "hb_winemetal_compute_v1.h"
#include "hb_memory.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BYTES = 16384, SMALL_PAGE = 4096 };
static const uint64_t PRIVATE_BASE = UINT64_C(0x660000);
static unsigned checks, failures;
static const char *phase = "setup";

static int check(int ok, const char *what)
{
    ++checks;
    if (!ok) { ++failures; fprintf(stderr, "FAIL [%s]: %s\n", phase, what); }
    return ok;
}

static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

typedef struct fixture {
    hb_context_t *ctx;
    uint64_t base, packet, info, array;
    uint64_t device, function, serialization, initial_error, initial_pso, error, pso;
    unsigned count, calls, seed;
    int null_array, write_outputs, fail_late;
    int32_t status;
    struct fixture *child;
} fixture_t;

static fixture_t *active;

static uint64_t archive_value(const fixture_t *f, unsigned i)
{
    return UINT64_C(0xf123456700000000) + ((uint64_t)f->seed << 16) + 257 * i;
}

static int make_fixture(fixture_t *f, int identity, int split, unsigned count, unsigned seed)
{
    memset(f, 0, sizeof *f);
    f->ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP);
    if (!check(f->ctx != NULL, "create owned context")) return 0;
    f->ctx->memory = hb_memory_create(0);
    if (!check(f->ctx->memory != NULL, "create owned memory")) return 0;
    if (identity) {
        if (!check(hb_memory_map(f->ctx->memory, 0, BYTES, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
                   "map identity storage")) return 0;
        f->base = f->ctx->memory->regions->base;
    } else {
        f->base = PRIVATE_BASE;
        if (split) {
            for (unsigned i = 0; i < BYTES / SMALL_PAGE; ++i)
                if (!check(hb_memory_map_private(f->ctx->memory, f->base + i * SMALL_PAGE,
                           SMALL_PAGE, HB_PERM_READ | HB_PERM_WRITE) == HB_OK,
                           "map independent adjacent guest regions")) return 0;
        } else if (!check(hb_memory_map_private(f->ctx->memory, f->base, BYTES,
                                 HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map private storage")) return 0;
    }
    void *host = hb_memory_host_ptr(f->ctx->memory, f->base, 8, HB_PERM_READ);
    check(host != NULL && (((uint64_t)(uintptr_t)host == f->base) == identity),
          "test mapping is really private or identity");
    uint8_t initial[BYTES]; memset(initial, 0xa5, sizeof initial);
    if (!check(hb_memory_write(f->ctx->memory, f->base, initial, sizeof initial) == HB_OK,
               "initialize all guest bytes")) return 0;
    memset(&f->ctx->regs, 0x3c, sizeof f->ctx->regs);
    f->ctx->regs.x64.rip = f->ctx->pc = UINT64_C(0x720000);
    f->ctx->regs.x64.rsp = f->base + BYTES - 128;
    f->ctx->mxcsr = 0x3fa1;
    f->packet = f->base + (split ? SMALL_PAGE - 24 : 0x103);
    f->info = f->base + 0x303;
    f->array = f->base + (split ? 2 * SMALL_PAGE - 8 : 0x803);
    f->count = count; f->seed = seed; f->write_outputs = 1;
    f->device = UINT64_C(0xfeed000000000001) + seed;
    f->function = UINT64_C(0xf00d000000000002) + seed;
    f->serialization = UINT64_C(0xabcd000000000003) + seed;
    f->initial_error = UINT64_C(0x1111222233334444);
    f->initial_pso = UINT64_C(0x5555666677778888);
    f->error = UINT64_C(0xe123456789abcdef) + seed;
    f->pso = UINT64_C(0xc123456789abcdef) + seed;
    return 1;
}

static int write_inputs(fixture_t *f)
{
    /* Literal byte layouts from compiled entry evidence, not native structs. */
    uint8_t packet[32] = {0}, info[32] = {0}, handles[255 * 8];
    put64(packet, f->device); put64(packet + 8, f->info);
    put64(packet + 16, f->initial_error); put64(packet + 24, f->initial_pso);
    put64(info, f->function); put64(info + 8, f->null_array ? 0 : f->array);
    put64(info + 16, f->serialization);
    info[24] = (uint8_t)f->count; info[25] = 1; info[26] = 0; info[27] = 1;
    info[28] = 0x01; info[29] = 0x00; info[30] = 0x20; info[31] = 0x80;
    if (!check(hb_memory_write(f->ctx->memory, f->packet, packet, sizeof packet) == HB_OK,
               "write literal guest packet") ||
        !check(hb_memory_write(f->ctx->memory, f->info, info, sizeof info) == HB_OK,
               "write literal guest info")) return 0;
    if (f->count && !f->null_array) {
        for (unsigned i = 0; i < f->count; ++i) put64(handles + i * 8, archive_value(f, i));
        if (!check(hb_memory_write(f->ctx->memory, f->array, handles, f->count * 8) == HB_OK,
                   "write literal opaque handle array")) return 0;
    }
    return 1;
}

static hb_result_t dispatch(fixture_t *f, hb_winemetal_compute_report_v1_t *report);

static int32_t native_consumer(void *arg)
{
    fixture_t *f = active;
    if (!f) { check(0, "native target fixture bound"); return -1; }
    ++f->calls;
    /* The oracle uses byte offsets read from the real binary. It deliberately
     * does not access the adapter's public native structs. */
    uint8_t packet[32], info[32];
    memcpy(packet, arg, sizeof packet);
    const void *host_info = NULL, *host_array = NULL;
    memcpy(&host_info, packet + 8, 8);
    check((uintptr_t)arg != f->packet && (uintptr_t)host_info != f->info,
          "native packet and info are host-owned staging buffers");
    check(get64(packet) == f->device, "opaque device bits are not translated");
    check(get64(packet + 16) == f->initial_error && get64(packet + 24) == f->initial_pso,
          "native entry sees incoming inout fields unchanged");
    if (!check(host_info != NULL, "native info is addressable")) return -1;
    memcpy(info, host_info, sizeof info);
    memcpy(&host_array, info + 8, 8);
    check(get64(info) == f->function && get64(info + 16) == f->serialization,
          "opaque function/archive handles preserved");
    check(info[24] == f->count && info[25] == 1 && info[26] == 0 && info[27] == 1 &&
          info[28] == 1 && info[29] == 0 && info[30] == 0x20 && info[31] == 0x80,
          "literal count flags and mask occupy correct native offsets");
    if (f->count && !f->null_array) {
        check(host_array != NULL && (uintptr_t)host_array != f->array,
              "archive array is independently addressable host storage");
        if (host_array)
            for (unsigned i = 0; i < f->count; ++i) {
                uint64_t value;
                memcpy(&value, (const uint8_t *)host_array + i * 8, 8);
                check(value == archive_value(f, i), "each archive handle retains its literal position");
            }
    } else check(host_array == NULL, "unused array is not dereferenced or forwarded");

    if (f->child) {
        uint8_t saved_array[255 * 8];
        if (host_array) memcpy(saved_array, host_array, f->count * 8);
        hb_winemetal_compute_report_v1_t child_report;
        const char *saved_phase = phase;
        phase = "nested child packet";
        check(dispatch(f->child, &child_report) == HB_OK && child_report.native_invoked == 1 &&
              child_report.pipeline_handle == f->child->pso, "nested child dispatch succeeds");
        phase = saved_phase;
        check(active == f, "test native entry restores parent fixture");
        check(!memcmp(packet, arg, sizeof packet) && !memcmp(info, host_info, sizeof info),
              "nested call preserves outer native packet and info snapshots");
        if (host_array) check(!memcmp(saved_array, host_array, f->count * 8),
                              "nested call preserves outer archive snapshot");
    }
    if (f->write_outputs) {
        uint8_t outputs[16]; put64(outputs, f->error); put64(outputs + 8, f->pso);
        memcpy((uint8_t *)arg + 16, outputs, sizeof outputs);
    }
    if (f->fail_late)
        check(hb_memory_protect(f->ctx->memory, f->base, BYTES, HB_PERM_READ) == HB_OK,
              "inject output permission loss after native effects");
    return f->status;
}

static hb_result_t dispatch(fixture_t *f, hb_winemetal_compute_report_v1_t *report)
{
    fixture_t *saved = active;
    active = f;
    hb_result_t result = hb_winemetal_compute_dispatch_v1(f->ctx, f->packet, native_consumer, report);
    active = saved;
    return result;
}

static void verify_result(fixture_t *f, int late_failure)
{
    uint8_t before_packet[32], after_packet[32];
    unsigned char registers[sizeof f->ctx->regs];
    memcpy(registers, &f->ctx->regs, sizeof registers);
    uint64_t pc = f->ctx->pc;
    uint32_t mxcsr = f->ctx->mxcsr;
    check(hb_memory_read(f->ctx->memory, f->packet, before_packet, sizeof before_packet) == HB_OK,
          "snapshot guest packet before native call");
    hb_winemetal_compute_report_v1_t report;
    memset(&report, 0x5a, sizeof report);
    hb_result_t result = dispatch(f, &report);
    check(result == (late_failure ? HB_ERR_MEMORY_FAULT : HB_OK), "transport result matches expected writeback");
    check(report.native_invoked == 1 && f->calls == 1 && report.native_status == f->status,
          "native status is reported separately from transport success");
    uint64_t error = f->write_outputs ? f->error : f->initial_error;
    uint64_t pso = f->write_outputs ? f->pso : f->initial_pso;
    check(report.error_handle == error && report.pipeline_handle == pso,
          "native output handles remain available even after late failure");
    check(hb_memory_read(f->ctx->memory, f->packet, after_packet, sizeof after_packet) == HB_OK,
          "read guest packet after native call");
    check(!memcmp(before_packet, after_packet, 16),
          "copyback preserves device and guest pointer; no host scratch pointer leaks");
    if (!late_failure)
        check(get64(after_packet + 16) == error && get64(after_packet + 24) == pso,
              "only result handles are copied back at literal offsets");
    else check(!memcmp(before_packet, after_packet, 32),
               "this permission-loss injection leaves packet untouched (not a general rollback claim)");
    check(!memcmp(registers, &f->ctx->regs, sizeof registers) && f->ctx->pc == pc && f->ctx->mxcsr == mxcsr,
          "packet adapter leaves context registers and return ownership unchanged");
    uint64_t guard = 0;
    check(hb_memory_read_u64(f->ctx->memory, f->packet - 8, &guard) == HB_OK &&
          guard == UINT64_C(0xa5a5a5a5a5a5a5a5), "packet lower guard");
    check(hb_memory_read_u64(f->ctx->memory, f->packet + 32, &guard) == HB_OK &&
          guard == UINT64_C(0xa5a5a5a5a5a5a5a5), "packet upper guard");
}

static void positive_cases(void)
{
    for (unsigned identity = 0; identity < 2; ++identity)
        for (unsigned which = 0; which < 7; ++which) {
            char label[96]; snprintf(label, sizeof label, "packet %s case=%u", identity ? "identity" : "private", which);
            phase = label; unsigned before = failures;
            fixture_t f;
            unsigned count = which == 1 ? 255 : which == 2 ? 0 : 3;
            if (!make_fixture(&f, identity, 0, count, which + identity * 10)) { hb_context_destroy(f.ctx); continue; }
            if (which == 2) f.array = UINT64_MAX; /* Unused even though invalid. */
            if (which == 3) f.null_array = 1;    /* Nonzero count, null array. */
            if (which == 4 || which == 5) f.status = (int32_t)UINT32_C(0xc0000001);
            if (which == 5) f.write_outputs = 0;
            if (which == 6) f.fail_late = 1;
            if (write_inputs(&f)) verify_result(&f, f.fail_late);
            printf("packet-case: mapping=%s case=%u calls=%u failures=%u\n",
                   identity ? "identity" : "private", which, f.calls, failures - before);
            hb_context_destroy(f.ctx);
        }
    phase = "split packet and archive regions";
    fixture_t f;
    if (make_fixture(&f, 0, 1, 3, 77) && write_inputs(&f)) verify_result(&f, 0);
    hb_context_destroy(f.ctx);
    phase = "separate-context nested packet";
    fixture_t parent, child;
    memset(&child, 0, sizeof child);
    if (make_fixture(&parent, 0, 0, 3, 101) && make_fixture(&child, 0, 0, 5, 202) &&
        write_inputs(&parent) && write_inputs(&child)) {
        parent.child = &child;
        verify_result(&parent, 0);
        check(child.calls == 1, "one nested native invocation");
        uint64_t child_pso = 0;
        check(hb_memory_read_u64(child.ctx->memory, child.packet + 24, &child_pso) == HB_OK &&
              child_pso == child.pso, "child output goes to its own mapping at the same guest address");
    }
    hb_context_destroy(parent.ctx); hb_context_destroy(child.ctx);
}

static void rejected_cases(void)
{
    for (unsigned which = 0; which < 14; ++which) {
        char label[80]; snprintf(label, sizeof label, "pre-native rejection case=%u", which);
        phase = label; unsigned before = failures;
        fixture_t f;
        if (!make_fixture(&f, 0, 0, 3, 33) || !write_inputs(&f)) { hb_context_destroy(f.ctx); continue; }
        uint64_t packet = f.packet, info = f.info;
        hb_context_t *ctx = f.ctx;
        hb_memory_t *memory = ctx->memory;
        hb_winemetal_compute_entry_v1_t entry = native_consumer;
        hb_result_t wanted = HB_ERR_INVALID_ARG;
        switch (which) {
        case 0: ctx = NULL; break;
        case 1: entry = NULL; break;
        case 2: f.ctx->memory = NULL; break;
        case 3: f.ctx->arch = HB_ARCH_X86; break;
        case 4: f.ctx->mode = HB_MODE_32BIT; break;
        case 5: packet = 0; break;
        case 6: packet = UINT64_MAX - 15; break;
        case 7: packet = f.base + BYTES + 128; wanted = HB_ERR_MEMORY_FAULT; break;
        case 8: info = 0; break;
        case 9: info = UINT64_MAX - 15; break;
        case 10: info = f.base + BYTES + 128; wanted = HB_ERR_MEMORY_FAULT; break;
        case 11:
            check(hb_memory_write_u64(memory, f.info + 8, UINT64_MAX - 7) == HB_OK, "inject overflowing array span");
            break;
        case 12:
            check(hb_memory_write_u64(memory, f.info + 8, f.base + BYTES - 8) == HB_OK,
                  "inject partially readable array span");
            wanted = HB_ERR_MEMORY_FAULT; break;
        case 13:
            check(hb_memory_protect(memory, f.base, BYTES, HB_PERM_READ) == HB_OK, "inject unwritable outputs");
            wanted = HB_ERR_MEMORY_FAULT; break;
        }
        if (which >= 8 && which <= 10)
            check(hb_memory_write_u64(memory, f.packet + 8, info) == HB_OK, "inject invalid info pointer");
        uint8_t snapshot[32], after[32];
        check(hb_memory_read(memory, f.packet, snapshot, sizeof snapshot) == HB_OK, "snapshot rejected packet");
        unsigned char regs[sizeof f.ctx->regs]; memcpy(regs, &f.ctx->regs, sizeof regs);
        uint64_t pc = f.ctx->pc;
        hb_winemetal_compute_report_v1_t report, zero = {0}; memset(&report, 0x5a, sizeof report);
        active = &f;
        hb_result_t result = hb_winemetal_compute_dispatch_v1(ctx, packet, entry, &report);
        active = NULL;
        check(result == wanted && f.calls == 0, "invalid input rejects before native side effects");
        check(!memcmp(&report, &zero, sizeof report), "pre-native rejection clears invocation report");
        check(!memcmp(regs, &f.ctx->regs, sizeof regs) && f.ctx->pc == pc, "rejection preserves guest registers and PC");
        check(hb_memory_read(memory, f.packet, after, sizeof after) == HB_OK && !memcmp(snapshot, after, sizeof snapshot),
              "rejection preserves guest packet bytes");
        f.ctx->memory = memory;
        printf("packet-reject: case=%u result=%d calls=%u failures=%u\n", which, result, f.calls, failures - before);
        hb_context_destroy(f.ctx);
    }
    phase = "null report";
    fixture_t f;
    if (make_fixture(&f, 0, 0, 0, 1) && write_inputs(&f)) {
        active = &f;
        check(hb_winemetal_compute_dispatch_v1(f.ctx, f.packet, native_consumer, NULL) == HB_ERR_INVALID_ARG &&
              f.calls == 0, "report is required before any native invocation");
        active = NULL;
    }
    hb_context_destroy(f.ctx);
}

int main(void)
{
    positive_cases(); rejected_cases();
    printf("hb_winemetal_compute_v1_test: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
