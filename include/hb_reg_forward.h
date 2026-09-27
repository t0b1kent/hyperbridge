#ifndef HB_REG_FORWARD_H
#define HB_REG_FORWARD_H
#include <stddef.h>
#include <stdint.h>

/* Fixed-size, store-through forwarding over a completed ARM64 code buffer.
 * Unknown instructions and control-flow joins are barriers. Returns replaced
 * loads, never changes offsets (relocations and fault maps remain valid). */
size_t hb_reg_forward(uint8_t *code, size_t size, int gpr, int xmm, int test_flip);
#endif
