#ifndef HB_ABI_X64_V1_H
#define HB_ABI_X64_V1_H

#include "hb_context.h"
#include "hb_result.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HB_ABI_X64_V1      1u
#define HB_ABI_X64_NONE_V1 0u
#define HB_ABI_X64_GPR_V1  1u
#define HB_ABI_X64_F32_V1  2u
#define HB_ABI_X64_F64_V1  3u

/* Raw guest scalar bits, without numeric conversion or implicit promotion.
 * GPR widths: 1/2/4/8 bytes. F32: 4. F64: 8. Bits above width are ignored.
 * NONE/0/0 is required for unused positions; active arguments cannot be NONE. */
typedef struct {
    uint32_t kind;
    uint32_t width_bytes;
    uint64_t bits;
} hb_abi_x64_value_v1_t;

/* In-process C interface, not a serialized packet. Use this exact header and
 * sizeof(hb_abi_x64_call_v1_t). No varargs, vectors or aggregate classification.
 * argument_count includes the first four positions; stack_args holds the tail.
 * Each position selects RCX/RDX/R8/R9 OR XMM0/1/2/3 according to its kind. */
typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t argument_count;
    uint64_t return_pc;
    hb_abi_x64_value_v1_t slots[4];
    const hb_abi_x64_value_v1_t *stack_args;
} hb_abi_x64_call_v1_t;

/* Prepare a suspended x64/64-bit context; never execute guest instructions.
 * Execution must use a backend configuration compatible with the guest memory
 * mapping. Preparation does not configure JIT direct-address memory paths.
 * RSP must be 16-byte aligned. The complete frame is 40 + 8*N bytes, plus
 * 8 bytes of padding when N (the tail count) is odd; entry RSP is 8 mod 16.
 * Homes and padding are zeroed. return_pc and target are raw guest addresses.
 * No legacy headroom adjustment is inserted.
 * GPR arguments are zero-extended; F32/F64 replace only the low 32/64 bits of
 * their positional XMM register. Other registers, x87/YMM and MXCSR are kept.
 * The caller supplies valid C objects; descriptor/tail may alias the future
 * guest frame, because all input values are captured before its first write.
 * Concurrent context, mapping or argument mutation is unsupported.
 * Unknown version/active scalar kind returns UNSUPPORTED_FEATURE. Invalid widths, size,
 * alignment or frame arithmetic return INVALID_ARG. A rejected writable-span
 * probe or a failed frame write returns MEMORY_FAULT; allocation failure is
 * OUT_OF_MEMORY. Error precedence for multiply-invalid inputs is unspecified.
 * Validation, allocation and preflight failures leave frame/registers intact.
 * Registers commit only after a successful write; a late write failure may
 * leave partial stack contents. This API does not provide memory rollback. */
hb_result_t hb_abi_x64_prepare_v1(hb_context_t *ctx, uint64_t target,
                                 const hb_abi_x64_call_v1_t *call);

/* Collect raw RAX or low XMM0 bits after the caller independently establishes
 * normal guest return. This function cannot establish execution completion.
 * NONE/0 returns zero; other kind/width rules match scalar arguments. Only an
 * x64/64-bit context is required (memory may be NULL). out_bits is mandatory,
 * must be separate from ctx, and is unchanged on error. Guest MXCSR is kept. */
hb_result_t hb_abi_x64_read_return_v1(const hb_context_t *ctx, uint32_t kind,
                                     uint32_t width_bytes, uint64_t *out_bits);

#ifdef __cplusplus
}
#endif
#endif
