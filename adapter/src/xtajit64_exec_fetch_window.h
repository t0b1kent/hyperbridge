#ifndef XTAJIT64_EXEC_FETCH_WINDOW_H
#define XTAJIT64_EXEC_FETCH_WINDOW_H

#include "xtajit64_exec_fetch.h"

/* Optional, invocation-local same-page snapshot. The provider must authorize a
 * window only from the immediately preceding fresh query's authoritative full
 * 4 KiB private-class reply with exact RX protection. This is not a permission
 * lease. Basic fallback/unknown/special mappings keep the demanded exact path.
 *
 * The callback must not alter guest fault/pending metadata, execute guest code,
 * or retain pointers. It consumes its eligibility before attempting the copy.
 * Any refusal/failure/malformed copied length is ignored and the exact demanded
 * read is then performed. Only the demanded read owns an architectural fault.
 */
typedef hb_result_t (*xtajit64_exec_read_window_fn)(
    void *user, uint64_t guest_pc, uint64_t address, size_t demanded,
    size_t capacity, uint8_t *bytes, size_t *copied);

/* Explicit new contract: same-page unused bytes may enter the local snapshot,
 * but no second page is touched until the decoder needs it. No snapshot or
 * query eligibility survives this invocation. The caller must still perform
 * the unchanged fresh complete-instruction observer before executing any IR.
 * Old exact-demand helper and output semantics remain available unchanged.
 */
static inline hb_result_t xtajit64_exec_fetch_instruction_window(
    uint64_t pc, xtajit64_exec_query_fn query, xtajit64_exec_read_fn read_bytes,
    xtajit64_exec_read_window_fn read_window, void *user,
    xtajit64_exec_fetch_result *out)
{
    xtajit64_exec_fetch_result local = {0};
    size_t available = 0;

    if (!read_window)
        return xtajit64_exec_fetch_instruction(pc, query, read_bytes, user, out);
    if (!out || !query || !read_bytes || pc > UINT64_MAX - 14)
        return HB_ERR_INVALID_ARG;

    for (;;)
    {
        hb_decode_probe_t probe;
        hb_result_t result = hb_decode_x64_probe(local.bytes, available, pc,
                                                 &local.decoded, &probe);
        if (result != HB_OK) return result;
        if (probe.state == HB_DECODE_COMPLETE)
        {
            if (!local.decoded.len || local.decoded.len > available)
                return HB_ERR_DECODE_FAILED;
            local.size = local.decoded.len;
            /* Publish only this instruction, even if an optional attempt
             * copied unused bytes or partially modified the scratch tail. */
            memset(local.bytes + local.size, 0, sizeof(local.bytes) - local.size);
            *out = local;
            return HB_OK;
        }
        if (probe.state == HB_DECODE_TERMINAL)
            return probe.decode_result == HB_OK ? HB_ERR_UNSUPPORTED_OPCODE :
                                                  probe.decode_result;
        if (probe.state != HB_DECODE_NEED_MORE ||
            probe.required_size <= available || probe.required_size > sizeof(local.bytes))
            return HB_ERR_DECODE_FAILED;

        while (available < probe.required_size)
        {
            uint64_t address = pc + available;
            size_t demanded = probe.required_size - available;
            size_t page_left = 4096u - (size_t)(address & 4095u);
            size_t capacity = sizeof(local.bytes) - available;
            size_t copied = 0;
            if (demanded > page_left) demanded = page_left;
            if (capacity > page_left) capacity = page_left;
            result = query(user, pc, address, demanded);
            if (result != HB_OK) return result;
            if (capacity > demanded &&
                read_window(user, pc, address, demanded, capacity,
                            local.bytes + available, &copied) == HB_OK &&
                copied >= demanded && copied <= capacity)
            {
                available += copied;
                continue;
            }
            result = read_bytes(user, address, local.bytes + available, demanded);
            if (result != HB_OK) return result;
            available += demanded;
        }
    }
}

#endif
