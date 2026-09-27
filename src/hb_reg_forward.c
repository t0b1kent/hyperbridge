#include "hb_reg_forward.h"
#include "hb_context.h"
#include <stdlib.h>
#include <string.h>

/* No allocation of host registers, no deferred guest stores. The knowledge is
 * an equality with a memory slot, not ownership of a register. Each host write
 * kills that equality. Each overlapping ctx store kills all older equalities;
 * a full store then establishes a new one. Unclassified stores may alias ctx.
 * Unclassified opcode groups end forwarding; admitted data-processing groups
 * have only an explicit Rd destination. This targets the emitted M1 ISA.
 *
 * x19 is the ordinary frame's ctx base. The caller excludes SRA and lean
 * frames. A write to x19 kills ALL knowledge, including vector knowledge.
 * The pass starts empty at every unit; transit never carries cached state.
 * Only Q accesses establish XMM knowledge: S/D writes, integer lane stores,
 * MMX/x87 helpers and YMM/ZMM paths cannot manufacture a full XMM value.
 */
typedef struct { unsigned off, bytes; } value_t;
typedef struct { value_t x[32], v[32]; } values_t;

static uint32_t word(const uint8_t *p) {
    uint32_t w; memcpy(&w, p, sizeof(w)); return w;
}
static int64_t signed_imm(uint32_t n, unsigned bits) {
    return (int64_t)(n & ((1u << bits) - 1u)) -
           ((n & (1u << (bits - 1))) ? (1ll << bits) : 0);
}
static int direct_branch(uint32_t w, int64_t *delta) {
    if ((w & 0x7c000000u) == 0x14000000u) {
        *delta = signed_imm(w, 26); return 1;
    }
    if ((w & 0xff000010u) == 0x54000000u ||
        (w & 0x7e000000u) == 0x34000000u) {
        *delta = signed_imm(w >> 5, 19); return 1;
    }
    if ((w & 0x7e000000u) == 0x36000000u) {
        *delta = signed_imm(w >> 5, 14); return 1;
    }
    return 0;
}
static void kill_x(values_t *s, unsigned rd) {
    if (rd == 19) memset(s, 0, sizeof(*s));
    else s->x[rd].bytes = 0;
}
static void store_range(values_t *s, unsigned off, unsigned bytes) {
    for (unsigned k = 0; k < 32; ++k) {
        value_t *a = &s->x[k], *b = &s->v[k];
        if (a->bytes && off < a->off + a->bytes && a->off < off + bytes) a->bytes = 0;
        if (b->bytes && off < b->off + b->bytes && b->off < off + bytes) b->bytes = 0;
    }
}
static int find_value(value_t *a, unsigned off, unsigned bytes, unsigned rt) {
    /* Prefer the destination itself: a NOP needs no register move. */
    if (a[rt].off == off && a[rt].bytes >= bytes) return (int)rt;
    for (unsigned k = 0; k < 32; ++k)
        if (a[k].off == off && a[k].bytes >= bytes) return (int)k;
    return -1;
}
static int gpr_slot(unsigned off, unsigned bytes) {
    return (bytes == 4 || bytes == 8) && off >= offsetof(hb_context_t, regs) &&
           off < offsetof(hb_context_t, regs) + 16 * 8 &&
           (off - offsetof(hb_context_t, regs)) % 8 == 0;
}
static int xmm_slot(unsigned off, unsigned bytes) {
    return bytes == 16 && off >= offsetof(hb_context_t, regs.x64.xmm) &&
           off < offsetof(hb_context_t, regs.x64.xmm) + 16 * 16 &&
           (off - offsetof(hb_context_t, regs.x64.xmm)) % 16 == 0;
}

static int pair_word(uint32_t w) { return (w & 0x3a000000u) == 0x28000000u; }
static int pair_writeback(uint32_t w) { return ((w >> 23) & 1u) != 0; }

/* The base pointer is a separate CFG fact. Early guard-failure epilogues
 * restore x19 and return; their clobber must not reach the guard's success
 * target. Bit 1 = canonical, bit 2 = possibly clobbered, zero = unreachable.
 * Two incoming states per word bound the worklist to 2*N entries. */
static int writes_ctx_base(uint32_t w) {
    unsigned rt = w & 31u, rn = (w >> 5) & 31u;
    if ((w & 0x3b000000u) == 0x39000000u)
        return !(w & 0x04000000u) && ((w >> 22) & 3u) != 0 && rt == 19;
    if (pair_word(w))
        return (pair_writeback(w) && rn == 19) ||
               (!(w & 0x04000000u) && (w & 0x00400000u) &&
                (rt == 19 || ((w >> 10) & 31u) == 19));
    if ((w & 0x0a000000u) == 0x08000000u) {
        /* Unclassified memory: include exclusive Rt2 and CASP's implicit
         * second result. A false clobber costs only coverage. */
        unsigned rs = (w >> 16) & 31u;
        return rt == 19 || rn == 19 || ((w >> 10) & 31u) == 19 || rs == 19 || rs == 18;
    }
    return rt == 19;
}
static void ctx_edge(uint8_t *state, size_t *queue, size_t *tail,
                     size_t n, int64_t dest, unsigned bits) {
    if (dest < 0 || (uint64_t)dest >= n || (state[dest] | bits) == state[dest]) return;
    state[dest] |= bits;
    queue[(*tail)++] = (size_t)dest;
}
static uint8_t *ctx_states(const uint8_t *code, size_t n) {
    uint8_t *state = calloc(n, 1);
    size_t *queue = malloc((2 * n + 2) * sizeof(*queue));
    if (!state || !queue) { free(state); free(queue); return NULL; }
    size_t head = 0, tail = 0;
    ctx_edge(state, queue, &tail, n, 0, 1);
    ctx_edge(state, queue, &tail, n, 4, 1); /* independent canonical body entry */
    while (head < tail) {
        size_t i = queue[head++];
        uint32_t w = word(code + 4 * i);
        unsigned out = state[i];
        int64_t d;
        if (direct_branch(w, &d)) {
            if ((w & 0xfc000000u) == 0x94000000u) { /* ABI-preserving BL */
                ctx_edge(state, queue, &tail, n, (int64_t)i + 1, out);
            } else {
                ctx_edge(state, queue, &tail, n, (int64_t)i + d, out);
                if ((w & 0xfc000000u) != 0x14000000u)
                    ctx_edge(state, queue, &tail, n, (int64_t)i + 1, out);
            }
            continue;
        }
        if ((w & 0xfe000000u) == 0xd6000000u) {
            if ((w & 0xfffffc1fu) == 0xd63f0000u) /* ABI-preserving BLR */
                ctx_edge(state, queue, &tail, n, (int64_t)i + 1, out);
            continue; /* BR/RET have no linear successor. */
        }
        if (i == 3 && w == 0xaa0003f3u && word(code) == 0xa9bd53f3u &&
            word(code + 4) == 0xa9015bf5u && word(code + 8) == 0xa9027bf7u)
            out = 1; /* ordinary entry's MOV X19,X0 */
        else if (writes_ctx_base(w)) out = 2;
        ctx_edge(state, queue, &tail, n, (int64_t)i + 1, out);
    }
    free(queue);
    return state;
}

size_t hb_reg_forward(uint8_t *code, size_t size, int gpr, int xmm, int test_flip) {
    if ((!gpr && !xmm) || !code || !size || size % 4 || size > 1024 * 1024) return 0;
    size_t n = size / 4, changed = 0;
    uint8_t *join = calloc(n, 1);
    if (!join) return 0; /* A missed optimisation is harmless. */
    /* Backward targets must be known BEFORE rewriting their first load. */
    for (size_t i = 0; i < n; ++i) {
        int64_t d;
        uint32_t w = word(code + i * 4);
        if (direct_branch(w, &d)) {
            int64_t t = (int64_t)i + d;
            if (t >= 0 && (uint64_t)t < n) join[t] = 1;
        }
        /* This emitter uses MOVZ/MOVK, never literal pools. Refuse unfamiliar
         * literal-load buffers entirely so that data cannot be rewritten. */
        if ((w & 0x3b000000u) == 0x18000000u) { free(join); return 0; }
    }
    uint8_t *ctx_state = ctx_states(code, n);
    if (!ctx_state) { free(join); return 0; }
    values_t s = {0};
    for (size_t i = 0; i < n; ++i) {
        uint32_t w = word(code + i * 4), replacement = w;
        unsigned rt = w & 31u, rn = (w >> 5) & 31u;
        int64_t d;
        if (join[i] || i == 4) memset(&s, 0, sizeof(s)); /* canonical body entry +16 */
        if (direct_branch(w, &d) || (w & 0xfe000000u) == 0xd6000000u) {
            memset(&s, 0, sizeof(s)); /* B/BL/BR/BLR/RET, both paths */
        } else if ((w & 0x3b000000u) == 0x39000000u) {
            /* Unsigned immediate LDR/STR, integer B/H/W/X and SIMD B/H/S/D/Q.
             * Sign-extending loads/prefetch (integer opc > 1) are barriers. */
            unsigned opc = (w >> 22) & 3u, simd = (w >> 26) & 1u;
            unsigned scale = (w >> 30) & 3u;
            if ((!simd && opc > 1) || (simd && opc > 1 && scale)) {
                memset(&s, 0, sizeof(s)); continue;
            }
            unsigned bytes = 1u << (simd && opc > 1 ? 4 : scale);
            unsigned off = ((w >> 10) & 4095u) * bytes;
            int load = opc & 1u;
            int eligible = ctx_state[i] == 1 && rn == 19 && (simd ? xmm && xmm_slot(off, bytes) :
                                      gpr && rt != 31 && rt != 19 && gpr_slot(off, bytes));
            if (load) {
                int src = eligible ? find_value(simd ? s.v : s.x, off, bytes, rt) : -1;
                if (src >= 0) {
                    /* LDR W must still zero the top half, including self moves. */
                    if ((unsigned)src == rt && (simd || bytes == 8)) replacement = 0xd503201fu;
                    else if (simd) replacement = 0x4ea01c00u | ((unsigned)src << 16) | ((unsigned)src << 5) | rt;
                    else replacement = (bytes == 8 ? 0xaa0003e0u : 0x2a0003e0u) | ((unsigned)src << 16) | rt;
                    memcpy(code + i * 4, &replacement, 4); ++changed;
                }
                if (simd) s.v[rt].bytes = 0;
                else kill_x(&s, rt);
                if (eligible) (simd ? s.v : s.x)[rt] = (value_t){off, bytes};
            } else if (rn == 19) {
                /* Test-only stale-state control: retain the old full GPR
                 * equality across an AL/AH/AX store. Never enabled normally. */
                if (!(test_flip && bytes < 4 && off >= offsetof(hb_context_t, regs) &&
                      off < offsetof(hb_context_t, regs) + 16 * 8))
                    store_range(&s, off, bytes);
                if (eligible) (simd ? s.v : s.x)[rt] = (value_t){off, bytes};
            } else {
                memset(&s, 0, sizeof(s)); /* Includes ctx aliases, guest stores. */
            }
        } else if (pair_word(w) && !pair_writeback(w)) {
            unsigned opc = w >> 30, simd = (w >> 26) & 1u;
            unsigned rt2 = (w >> 10) & 31u;
            if (opc == 3 || (!simd && opc == 1)) {
                memset(&s, 0, sizeof(s)); continue;
            }
            unsigned bytes = simd ? 4u << opc : (opc == 2 ? 8u : 4u);
            int64_t off = signed_imm(w >> 15, 7) * bytes;
            if (w & 0x00400000u) {
                if (simd) s.v[rt].bytes = s.v[rt2].bytes = 0;
                else { kill_x(&s, rt); kill_x(&s, rt2); }
            } else if (rn == 19 && ctx_state[i] == 1 && off >= 0) {
                store_range(&s, (unsigned)off, bytes * 2);
                unsigned regs[2] = {rt, rt2};
                for (unsigned k = 0; k < 2; ++k) {
                    unsigned at = (unsigned)off + k * bytes, r = regs[k];
                    if (simd ? xmm && xmm_slot(at, bytes) :
                        gpr && r != 19 && r != 31 && gpr_slot(at, bytes))
                        (simd ? s.v : s.x)[r] = (value_t){at, bytes};
                }
            } else memset(&s, 0, sizeof(s));
        } else if ((w & 0x1c000000u) == 0x10000000u ||
                   (w & 0x0e000000u) == 0x0a000000u) {
            /* Data-processing immediate / register: one GPR destination.
             * Includes ADR(P), MOVK, bitfields, W ops, CSEL, multiply/divide.
             * The negative control deliberately retains a stale equality. */
            if (!test_flip || rt == 19) kill_x(&s, rt);
        } else if ((w & 0x9e000000u) == 0x0e000000u || /* Advanced SIMD vector */
                   (w & 0x7e000000u) == 0x1e000000u || /* scalar FP, GPR transfers */
                   (w & 0xdf000000u) == 0x5e000000u || /* Advanced SIMD scalar */
                   (w & 0xdf000000u) == 0x5f000000u) {
            /* SIMD/FP includes conversions to GPR and scalar partial writes.
             * Killing BOTH possible destination banks is conservative. */
            kill_x(&s, rt); s.v[rt].bytes = 0;
        } else if (w == 0xd503201fu || (w & 0xfffff09fu) == 0xd503309fu) {
            /* NOP and DMB/DSB/ISB do not alter registers or guest ctx slots. */
        } else {
            memset(&s, 0, sizeof(s)); /* pairs, exclusives, atomics, system ... */
        }
    }
    free(join);
    free(ctx_state);
    return changed;
}
