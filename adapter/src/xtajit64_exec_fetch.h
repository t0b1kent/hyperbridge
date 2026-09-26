#ifndef XTAJIT64_EXEC_FETCH_H
#define XTAJIT64_EXEC_FETCH_H

#include <stdint.h>
#include <string.h>
#include "hb_decoder.h"

/* Invocation-local, decoder-demanded fetch. Query before each read; neither
 * callback grants a mapping lease. Callbacks must not execute guest code or
 * retain borrowed pointers. The caller owns pending/fault metadata and must
 * preserve architectural state. This helper does not execute an instruction.
 * Decoder terminal ordering is not a claim about hardware exception priority.
 * The 15-byte address envelope and 4 KiB split match the private EXEC protocol. */
typedef hb_result_t (*xtajit64_exec_query_fn)(void *user, uint64_t guest_pc,
                                            uint64_t address, size_t size);
typedef hb_result_t (*xtajit64_exec_read_fn)(void *user, uint64_t address,
                                           uint8_t *bytes, size_t size);

typedef struct xtajit64_exec_fetch_result
{
    hb_decoded_t decoded;
    uint8_t bytes[15];
    size_t size;
} xtajit64_exec_fetch_result;

/* HB_OK publishes one complete supported instruction. All other results leave
 * out unchanged, including ACCESS_PENDING. A terminal legacy HB_OK/unavailable
 * encoding is normalized to UNSUPPORTED_OPCODE. No speculative tail is read. */
static inline hb_result_t xtajit64_exec_fetch_instruction(
    uint64_t pc, xtajit64_exec_query_fn query, xtajit64_exec_read_fn read_bytes,
    void *user, xtajit64_exec_fetch_result *out)
{
    xtajit64_exec_fetch_result local = {0};
    size_t available = 0;

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
            size_t size = probe.required_size - available;
            size_t page_left = 4096u - (size_t)(address & 4095u);
            if (size > page_left) size = page_left;
            result = query(user, pc, address, size);
            if (result != HB_OK) return result;
            result = read_bytes(user, address, local.bytes + available, size);
            if (result != HB_OK) return result;
            available += size;
        }
    }
}

#endif
