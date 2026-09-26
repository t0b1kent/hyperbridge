#ifndef HB_SYSCALL_STUB_H
#define HB_SYSCALL_STUB_H

#include <stddef.h>
#include <stdint.h>

/* Recognize only the complete Windows-form x64 syscall entry consumed by
 * Wine's ARM64EC call checker. The caller supplies safely fetched bytes.
 * The checker, not this format gate, owns its actual service-table bound. */
static inline int hb_x64_syscall_stub_match(uint64_t pc, const void *bytes,
                                          size_t len, uint32_t *service_out)
{
    static const uint8_t prefix[4] = {0x4c, 0x8b, 0xd1, 0xb8};
    static const uint8_t suffix[16] = {
        0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,
        0x75, 0x03, 0x0f, 0x05, 0xc3, 0xcd, 0x2e, 0xc3
    };
    const uint8_t *p = (const uint8_t *)bytes;
    uint32_t service;
    size_t i;

    if (!p || len < 24 || (pc & 15) || pc > UINT64_MAX - 23) return 0;
    for (i = 0; i < sizeof(prefix); ++i)
        if (p[i] != prefix[i]) return 0;
    for (i = 0; i < sizeof(suffix); ++i)
        if (p[i + 8] != suffix[i]) return 0;
    service = (uint32_t)p[4] | ((uint32_t)p[5] << 8) |
              ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
    /* Wine extracts twelve bits: reject high-bit aliases before its resolver. */
    if (service >= 0x1000) return 0;
    if (service_out) *service_out = service;
    return 1;
}

/* Structural rejection only. The caller must additionally verify the returned
 * address against Wine's ARM64EC bitmap before transferring guest state. */
static inline int hb_x64_syscall_target_valid(uint64_t stub, uint64_t target)
{
    return target != 0 && target != stub && !(target & 3);
}

#endif
