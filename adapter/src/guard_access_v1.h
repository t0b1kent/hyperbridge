/* Optional private scalar/pair-CMPXCHG memory-access transport. */
#ifndef WINE_EMULATOR_GUARD_ACCESS_V1_H
#define WINE_EMULATOR_GUARD_ACCESS_V1_H

#include <stddef.h>
#include <stdint.h>

#define WINE_EMULATOR_MEMORY_ACCESS_VERSION 1u
#define WINE_EMULATOR_MEMORY_ACCESS_ABI_COOKIE UINT64_C(0x4842475541524431)
#define WINE_EMULATOR_MEMORY_ACCESS_CAP_READ UINT64_C(1)
#define WINE_EMULATOR_MEMORY_ACCESS_CAP_WRITE UINT64_C(2)
#define WINE_EMULATOR_MEMORY_ACCESS_CAP_PAIR_CMPXCHG UINT64_C(4)
#define WINE_EMULATOR_MEMORY_ACCESS_CAP_EXEC UINT64_C(8)
#define WINE_EMULATOR_MEMORY_ACCESS_SCALAR_PREACCESS 1u
#define WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS 2u
#define WINE_EMULATOR_MEMORY_ACCESS_EXEC_PREACCESS 3u
#define WINE_EMULATOR_MEMORY_ACCESS_READ 0u
#define WINE_EMULATOR_MEMORY_ACCESS_WRITE 1u
#define WINE_EMULATOR_MEMORY_ACCESS_EXEC 8u
#define WINE_EMULATOR_MEMORY_ACCESS_OP_BIND 1u
#define WINE_EMULATOR_MEMORY_ACCESS_OP_ACCESS 2u

/* Exact matched profiles: scalar MOV (3), plus pair CMPXCHG (7), plus
 * demanded x64 instruction fetch (15). Older endpoints reject profile 15.
 * No unknown bit or existing callback implicitly enables instruction fetch. */
static inline int wine_emulator_memory_access_caps_valid_v1( uint64_t caps )
{
    const uint64_t scalar = WINE_EMULATOR_MEMORY_ACCESS_CAP_READ |
                            WINE_EMULATOR_MEMORY_ACCESS_CAP_WRITE;
    return caps == scalar || caps == (scalar | WINE_EMULATOR_MEMORY_ACCESS_CAP_PAIR_CMPXCHG) ||
           caps == (scalar | WINE_EMULATOR_MEMORY_ACCESS_CAP_PAIR_CMPXCHG |
                    WINE_EMULATOR_MEMORY_ACCESS_CAP_EXEC);
}

static inline int wine_emulator_memory_access_scope_valid_v1( uint64_t caps,
                                                             uint32_t phase,
                                                             uint32_t access,
                                                             uint64_t span )
{
    if (!wine_emulator_memory_access_caps_valid_v1( caps )) return 0;
    if (phase == WINE_EMULATOR_MEMORY_ACCESS_SCALAR_PREACCESS)
        return (access == WINE_EMULATOR_MEMORY_ACCESS_READ ||
                access == WINE_EMULATOR_MEMORY_ACCESS_WRITE) &&
               (span == 1 || span == 2 || span == 4 || span == 8);
    if (phase == WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS)
        return (caps & WINE_EMULATOR_MEMORY_ACCESS_CAP_PAIR_CMPXCHG) &&
               access == WINE_EMULATOR_MEMORY_ACCESS_WRITE && (span == 8 || span == 16);
    if (phase == WINE_EMULATOR_MEMORY_ACCESS_EXEC_PREACCESS)
        return (caps & WINE_EMULATOR_MEMORY_ACCESS_CAP_EXEC) &&
               access == WINE_EMULATOR_MEMORY_ACCESS_EXEC && span >= 1 && span <= 15;
    return 0;
}

/* Structural demand envelope, not proof that the decoder needs these bytes.
 * Require the entire architectural 15-byte envelope to be representable.
 * Page containment is checked separately by both packet consumers. */
static inline int wine_emulator_memory_access_exec_span_valid_v1( uint32_t phase,
                                                                  uint64_t pc,
                                                                  uint64_t address,
                                                                  uint64_t span )
{
    if (phase != WINE_EMULATOR_MEMORY_ACCESS_EXEC_PREACCESS) return 1;
    return span >= 1 && span <= 15 && pc <= UINT64_MAX - 14 && address >= pc &&
           address - pc <= 14 && span <= 15 - (address - pc);
}

/* CMPXCHG16B's #GP must precede any guard consumption. Its producer checks
 * alignment architecturally; endpoints also reject malformed wire requests.
 * No new alignment restriction applies to scalar MOV or CMPXCHG8B. */
static inline int wine_emulator_memory_access_alignment_valid_v1( uint32_t phase,
                                                                 uint64_t span,
                                                                 uint64_t address )
{
    return phase != WINE_EMULATOR_MEMORY_ACCESS_PAIR_PREACCESS || span != 16 || !(address & 15);
}

/* Unix snapshots this value before VM mutation. Phase 1 remains scalar MOV;
 * phase 2 means paired CMPXCHG8B/16B WRITE-before-READ, including mismatch.
 * Phase 3 carries only demanded fetch bytes within the instruction envelope.
 * Every request is limited to one Windows page. The adapter owns invocation lifetime
 * and serial. Zero guest addresses/PCs remain structurally representable. */
typedef struct wine_emulator_memory_access_request_v1
{
    uint32_t size;
    uint32_t version;
    uint64_t owner_module;
    uint64_t selection_epoch;
    uint64_t current_teb;
    uint64_t invocation_serial;
    uint64_t guest_pc;
    uint64_t guest_address;
    uint64_t span_length;
    uint32_t access;
    uint32_t phase;
    uint64_t reserved[3];
} WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1;

/* On disk, only size/version are initialized. Unix loader readiness publishes
 * the cookie; successful PE processor startup BIND establishes an immutable
 * native owner/capability shadow before release-publication of capabilities.
 * Repeating BIND must match every byte, including capabilities. No reselection,
 * opportunistic ACCESS binding, or hostile in-process security claim. */
typedef struct wine_emulator_memory_access_bootstrap_v1
{
    uint32_t size;
    uint32_t version;
    uint64_t cookie;
    uint64_t capabilities;
    uint64_t owner_module;
    uint64_t selection_epoch;
    uint64_t reserved[3];
} WINE_EMULATOR_MEMORY_ACCESS_BOOTSTRAP_V1;

_Static_assert(sizeof(WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1) == 96, "guard request size");
_Static_assert(offsetof(WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1, access) == 64, "guard access offset");
_Static_assert(offsetof(WINE_EMULATOR_MEMORY_ACCESS_REQUEST_V1, reserved) == 72, "guard reserved offset");
_Static_assert(sizeof(WINE_EMULATOR_MEMORY_ACCESS_BOOTSTRAP_V1) == 64, "guard bootstrap size");
_Static_assert(offsetof(WINE_EMULATOR_MEMORY_ACCESS_BOOTSTRAP_V1, cookie) == 8, "guard readiness offset");
_Static_assert(offsetof(WINE_EMULATOR_MEMORY_ACCESS_BOOTSTRAP_V1, owner_module) == 24, "guard owner offset");

#endif
