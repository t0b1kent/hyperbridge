/* Private, optional Wine PE/Unix continuation transport. No public CONTEXT ABI changes. */
#ifndef WINE_EMULATOR_CONTINUATION_V1_H
#define WINE_EMULATOR_CONTINUATION_V1_H

#include <stdint.h>
#include <stddef.h>
#include "winnt.h"

#define WINE_EMULATOR_CONTINUATION_VERSION 1u
#define WINE_EMULATOR_CONTINUATION_SIZE 64u
#define WINE_EMULATOR_CONTINUATION_ABI_COOKIE UINT64_C(0x4842434f4e543031)
#define WINE_EMULATOR_CONTINUATION_CAP_NORMAL UINT64_C(1)
#define WINE_EMULATOR_CONTINUATION_CAP_APC UINT64_C(2) /* Reserved; not advertised by this increment. */
#define WINE_EMULATOR_CONTINUATION_MISSING_FLAGS 0x414u
#define WINE_EMULATOR_CONTINUATION_RESUME 1u
#define WINE_EMULATOR_CONTINUATION_APC 2u
#define WINE_EMULATOR_CONTINUATION_AMD64_CONTROL 0x00100001u

typedef struct wine_emulator_continuation_v1
{
    uint32_t size;
    uint32_t version;
    uint64_t owner_module;
    uint64_t owner_generation;
    uint64_t owner_teb;
    uint64_t target_pc;
    uint64_t target_sp;
    uint32_t missing_eflags;
    uint32_t entry_kind;
    uint64_t reserved;
} WINE_EMULATOR_CONTINUATION_V1;

/* The PE image initializes size/version/abi_cookie. A matching Unix loader
 * publishes capabilities then unix_cookie with release ordering only after
 * finding and redirecting the optional normal dispatcher. PE publishes the
 * selected pinned owner_module then owner_generation=1 with release ordering.
 * No live provider replacement is allowed in V1; no thread pending state. */
typedef struct wine_emulator_continuation_bootstrap_v1
{
    uint32_t size;
    uint32_t version;
    uint64_t abi_cookie;
    uint64_t unix_cookie;
    uint64_t capabilities;
    uint64_t owner_module;
    uint64_t owner_generation;
    uint64_t reserved[2];
} WINE_EMULATOR_CONTINUATION_BOOTSTRAP_V1;

/* SP points at context, so the normal dispatcher can retain .seh_context.
 * Payload is frame-owned by value, consumed and invalidated before callbacks. */
struct wine_continuation_frame_v1
{
    ARM64_NT_CONTEXT context;
    WINE_EMULATOR_CONTINUATION_V1 value;
};

/* Layout reservation only. Keep the old APC prefix/context/redzone intact;
 * APC capability stays off until its complete transaction is implemented. */
struct wine_continuation_apc_frame_v1
{
    uint64_t func;
    uint64_t args[3];
    uint64_t alertable;
    uint64_t align;
    ARM64_NT_CONTEXT context;
    uint64_t redzone[2];
    WINE_EMULATOR_CONTINUATION_V1 value;
};

_Static_assert(sizeof(WINE_EMULATOR_CONTINUATION_V1) == 64, "continuation value size");
_Static_assert(sizeof(WINE_EMULATOR_CONTINUATION_BOOTSTRAP_V1) == 64, "bootstrap size");
_Static_assert(offsetof(struct wine_continuation_frame_v1, value) == 0x390, "normal value offset");
_Static_assert(sizeof(struct wine_continuation_frame_v1) == 0x3d0, "normal frame size");
_Static_assert(offsetof(struct wine_continuation_apc_frame_v1, context) == 0x30, "APC context offset");
_Static_assert(offsetof(struct wine_continuation_apc_frame_v1, value) == 0x3d0, "APC value offset");
_Static_assert(sizeof(struct wine_continuation_apc_frame_v1) == 0x410, "APC frame size");

#endif
