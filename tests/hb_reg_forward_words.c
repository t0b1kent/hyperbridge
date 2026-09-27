#include "hb_reg_forward.h"
#include "hb_context.h"
#include <stdio.h>
#include <string.h>

/* Machine words independently checked with clang's AArch64 assembler.
 * Every test has a four-word prologue prefix: +16 is a separate entry ABI.
 * Comparing every word verifies that stores, branches and fault offsets stay
 * unchanged, rather than just counting the pass's claimed optimisations. */
#define NOP 0xd503201fu
#define LX(r,o) (0xf9400000u | (((o)/8u)<<10) | (19u<<5) | (r))
#define LW(r,o) (0xb9400000u | (((o)/4u)<<10) | (19u<<5) | (r))
#define SX(r,o) (0xf9000000u | (((o)/8u)<<10) | (19u<<5) | (r))
#define SW(r,o) (0xb9000000u | (((o)/4u)<<10) | (19u<<5) | (r))
#define SH(r,o) (0x79000000u | (((o)/2u)<<10) | (19u<<5) | (r))
#define SB(r,o) (0x39000000u | ((o)<<10) | (19u<<5) | (r))
#define LQ(r,o) (0x3dc00000u | (((o)/16u)<<10) | (19u<<5) | (r))
#define SQ(r,o) (0x3d800000u | (((o)/16u)<<10) | (19u<<5) | (r))
#define LD(r,o) (0xfd400000u | (((o)/8u)<<10) | (19u<<5) | (r))
#define SD(r,o) (0xfd000000u | (((o)/8u)<<10) | (19u<<5) | (r))
#define LS(r,o) (0xbd400000u | (((o)/4u)<<10) | (19u<<5) | (r))
#define SS(r,o) (0xbd000000u | (((o)/4u)<<10) | (19u<<5) | (r))
#define MX(d,s) (0xaa0003e0u | ((s)<<16) | (d))
#define MW(d,s) (0x2a0003e0u | ((s)<<16) | (d))
#define MQ(d,s) (0x4ea01c00u | ((s)<<16) | ((s)<<5) | (d))
#define B(d) (0x14000000u | ((unsigned)(d)&0x3ffffffu))
#define BC(d) (0x54000000u | (((unsigned)(d)&0x7ffffu)<<5))
#define CB(d) (0xb4000000u | (((unsigned)(d)&0x7ffffu)<<5))
#define TB(d) (0x36000000u | (((unsigned)(d)&0x3fffu)<<5))
#define G ((unsigned)offsetof(hb_context_t, regs.x64.rax))
#define V ((unsigned)offsetof(hb_context_t, regs.x64.xmm))

static unsigned checks, failures;
static void run(const char *name, const uint32_t *body, const uint32_t *wanted,
                size_t count, size_t changes, int gpr, int xmm, int flip) {
    uint32_t code[64] = {0xa9bd53f3u, 0xa9015bf5u, 0xa9027bf7u, MX(19,0)};
    uint32_t expected[64];
    if (count > 60) { ++failures; return; }
    memcpy(code + 4, body, count * 4);
    memcpy(expected, code, (count + 4) * 4);
    memcpy(expected + 4, wanted, count * 4);
    size_t got = hb_reg_forward((uint8_t *)code, (count + 4) * 4, gpr, xmm, flip);
    ++checks;
    if (got != changes) {
        fprintf(stderr, "%s: changed=%zu wanted=%zu\n", name, got, changes);
        ++failures;
    }
    for (size_t i = 0; i < count + 4; ++i) {
        ++checks;
        if (code[i] != expected[i]) {
            fprintf(stderr, "%s: word=%zu got=%08x wanted=%08x\n", name, i, code[i], expected[i]);
            ++failures;
        }
    }
}
#define CASE(name,changes,...) do { \
    const uint32_t body[] = {__VA_ARGS__}; \
    uint32_t want[sizeof(body)/sizeof(body[0])]; memcpy(want,body,sizeof(body)); \
    PATCH; run(name,body,want,sizeof(body)/4,changes,1,1,0); \
} while (0)
#define PATCH ((void)0)

int main(void) {
    /* Establishing, killing and retaining independent host equalities. */
#undef PATCH
#define PATCH want[1]=NOP
    CASE("gpr-self",1,LX(0,G),LX(0,G));
    CASE("xmm-self",1,LQ(0,V),LQ(0,V));
#undef PATCH
#define PATCH want[1]=MX(1,0)
    CASE("gpr-other-host",1,LX(0,G),LX(1,G));
#undef PATCH
#define PATCH want[1]=MW(0,0)
    CASE("word-self-must-zero",1,LX(0,G),LW(0,G));
    CASE("word-self",1,LW(0,G),LW(0,G));
#undef PATCH
#define PATCH want[1]=MW(1,0)
    CASE("wide-to-word",1,LX(0,G),LW(1,G));
#undef PATCH
#define PATCH ((void)0)
    CASE("word-not-wide",0,LW(0,G),LX(0,G));
    CASE("host-write",0,LX(0,G),0x91000400u,LX(1,G)); /* add x0,x0,#1 */
    CASE("word-host-write",0,LX(0,G),0x11000400u,LX(1,G));
    CASE("ctx-write",0,LX(0,G),MX(19,20),LX(1,G));
    CASE("ctx-base-no-longer-canonical",0,MX(19,20),LX(0,G),LX(1,G));
    CASE("unknown",0,LX(0,G),0xffffffffu,LX(1,G));
    CASE("trap-boundary",0,LX(0,G),0xd4200000u,LX(1,G));
    CASE("unknown-mrs-x19",0,0xd53b4213u,LX(0,G),LX(1,G));
    CASE("unknown-load-pair-x19",0,0xa9404c20u,LX(0,G),LX(1,G));
    CASE("unknown-writeback-x19",0,0xf8008674u,LX(0,G),LX(1,G));
    CASE("exclusive-pair-writes-ctx",0,0xc87fcc20u,LX(0,G),LX(1,G)); /* LDAXP X0,X19,[X1] */
    CASE("casp-implicit-second-ctx",0,0x48327c34u,LX(0,G),LX(1,G)); /* CASP X18,X19,... */
    CASE("pair-load-clobbers-host",0,LX(0,G),0xa9420660u,LX(2,G));
    CASE("ctx-mixed-canonical-clobbered-join",0,BC(3),MX(19,20),B(2),NOP,LX(0,G),LX(1,G));
    CASE("ctx-backedge-clobber",0,LX(0,G),LX(1,G),MX(19,20),B(-3));
#undef PATCH
#define PATCH want[5]=MX(1,0)
    CASE("guard-return-does-not-clobber-success",1,BC(3),0xa8c353f3u,0xd65f03c0u,LX(0,G),0xa91b0e62u,LX(1,G));
#undef PATCH
#define PATCH want[3]=MX(1,0)
    CASE("ctx-unreachable-clobber",1,B(2),MX(19,20),LX(0,G),LX(1,G));
    CASE("ctx-all-canonical-join",1,BC(2),NOP,LX(0,G),LX(1,G));
#undef PATCH
#define PATCH want[2]=MX(1,0)
    CASE("nonoverlapping-flag-pair-store",1,LX(0,G),0xa91b0e62u,LX(1,G));
#undef PATCH
#define PATCH want[1]=MX(0,2);want[2]=MX(1,3)
    CASE("pair-store-establishes-both-gprs",2,0xa9020e62u,LX(0,G),LX(1,G+8));
#undef PATCH
#define PATCH want[1]=MQ(0,2);want[2]=MQ(1,3)
    CASE("pair-store-establishes-both-xmms",2,0xad058e62u,LQ(0,V),LQ(1,V+16));
#undef PATCH
#define PATCH want[1]=MX(1,0);want[3]=MX(2,1)
    CASE("second-host-survives",2,LX(0,G),LX(1,G),0x91000400u,LX(2,G));
#undef PATCH
#define PATCH want[1]=MX(3,2)
    CASE("store-establishes",1,SX(2,G),LX(3,G));
#undef PATCH
#define PATCH want[1]=MW(3,2)
    CASE("word-store-establishes-word",1,SW(2,G),LW(3,G));
#undef PATCH
#define PATCH ((void)0)
    CASE("word-store-not-wide",0,SW(2,G),LX(3,G));
    CASE("partial-low-byte",0,LX(0,G),SB(2,G),LX(3,G));
    CASE("partial-high-byte",0,LX(0,G),SB(2,G+1),LX(3,G));
    CASE("partial-halfword",0,LX(0,G),SH(2,G),LX(3,G));
    CASE("partial-word",0,LX(0,G),SW(2,G),LX(3,G));
    CASE("zero-register-store",0,LX(0,G),SX(31,G),LX(3,G));
    CASE("zero-register-load",0,LX(31,G),LX(3,G));
    CASE("q-store-overlaps-two-gprs",0,LX(0,G),LX(1,G+8),SQ(2,G),LX(3,G),LX(4,G+8));
    CASE("aliased-ctx-store",0,LX(0,G),MX(1,19),0xf9001022u,LX(3,G));
    CASE("unknown-stur",0,LX(0,G),0xf8008262u,LX(3,G));
#undef PATCH
#define PATCH want[2]=MX(3,0)
    CASE("unrelated-store",1,LX(0,G),SX(2,G+8),LX(3,G));
    CASE("ctx-flags-store",1,LX(0,G),SX(2,0x1b0),LX(3,G));
    CASE("dmb-preserves",1,LX(0,G),0xd5033bbfu,LX(3,G));
    CASE("dsb-preserves",1,LX(0,G),0xd5033b9fu,LX(3,G));
    CASE("isb-preserves",1,LX(0,G),0xd5033fdfu,LX(3,G));
#undef PATCH
#define PATCH want[1]=MQ(1,0)
    CASE("xmm-other-host",1,LQ(0,V),LQ(1,V));
    CASE("xmm-store-establishes",1,SQ(0,V),LQ(1,V));
#undef PATCH
#define PATCH want[1]=MQ(0,31)
    CASE("vector31-is-not-zero",1,LQ(31,V),LQ(0,V));
#undef PATCH
#define PATCH ((void)0)
    CASE("xmm-scalar-load-clobber",0,LQ(0,V),LD(0,V+16),LQ(1,V));
    CASE("xmm-fadd-clobber",0,LQ(0,V),0x1e612800u,LQ(1,V));
    CASE("xmm-ins-clobber",0,LQ(0,V),0x4e081c40u,LQ(1,V));
    CASE("xmm-double-store",0,LQ(0,V),SD(2,V),LQ(1,V));
    CASE("xmm-single-store",0,LQ(0,V),SS(2,V),LQ(1,V));
    CASE("xmm-integer-upper-store",0,LQ(0,V),SX(2,V+8),LQ(1,V));
    CASE("xmm-integer-low-store",0,LQ(0,V),SW(2,V),LQ(1,V));
    CASE("xmm-upper-byte-store",0,LQ(0,V),SB(2,V+15),LQ(1,V));
    CASE("scalar-store-not-q",0,SD(2,V),LQ(1,V));
    CASE("scalar-load-not-q",0,LD(2,V),LQ(1,V));
    CASE("q-to-s-load-not-full-move",0,LQ(2,V),LS(1,V));
    CASE("q-to-d-load-not-full-move",0,LQ(2,V),LD(1,V));
    CASE("fmov-cross-bank",0,LX(0,G),0x9e660040u,LX(1,G)); /* fmov x0,d2 */
    CASE("umov-cross-bank",0,LX(0,G),0x4e083c40u,LX(1,G)); /* umov x0,v2.d[0] */
    CASE("fmov-to-fp-clobber",0,LQ(0,V),0x9e670040u,LQ(1,V));
    CASE("ymm-upper-outside-xmm",0,LQ(0,V+16*16),LQ(1,V+16*16));
    CASE("helper-boundary",0,LX(0,G),0xd63f02e0u,LX(1,G));
    CASE("vector-helper-boundary",0,LQ(0,V),0xd63f02e0u,LQ(1,V));
    CASE("indirect-branch",0,LX(0,G),0xd61f02e0u,LX(1,G));
    CASE("branch-fallthrough",0,LX(0,G),BC(2),LX(1,G),NOP);
    CASE("forward-join",0,BC(2),LX(0,G),LX(1,G));
    CASE("backward-join",0,LX(0,G),LX(1,G),BC(-1));
    CASE("unconditional-join",0,LX(0,G),LX(1,G),B(-1));
    CASE("compare-branch-join",0,LX(0,G),LX(1,G),CB(-1));
    CASE("test-branch-join",0,LX(0,G),LX(1,G),TB(-1));
    CASE("vector-backward-join",0,LQ(0,V),LQ(1,V),BC(-1));
    CASE("literal-veto-even-after-opportunity",0,LX(0,G),LX(1,G),0x58000020u);
    CASE("simd-literal-veto",0,LQ(0,V),LQ(1,V),0x9c000020u);

    /* Gates are independent; the injected stale-value bug must change a word
     * that the ordinary pass leaves as a reload. End-to-end tests execute it. */
    {
        uint32_t body[]={LX(0,G),LX(1,G),LQ(0,V),LQ(1,V)}, want[4];
        memcpy(want,body,sizeof(body));
        run("all-gates-off",body,want,4,0,0,0,0);
        want[1]=MX(1,0); run("gpr-only",body,want,4,1,1,0,0);
        memcpy(want,body,sizeof(body));want[3]=MQ(1,0);
        run("xmm-only",body,want,4,1,0,1,0);
    }
    {
        uint32_t body[]={LX(0,G),0x91000400u,LX(1,G)};
        uint32_t want[]={LX(0,G),0x91000400u,MX(1,0)};
        run("negative-control-stale-host",body,want,3,1,1,0,1);
    }
    {
        uint32_t code[]={LX(0,G),NOP,NOP,NOP,LX(1,G)}, before[5];
        memcpy(before,code,sizeof(code));++checks;
        if (hb_reg_forward((uint8_t *)code,sizeof(code),1,1,0) || memcmp(code,before,sizeof(code))) ++failures;
        ++checks;if(hb_reg_forward(NULL,0,1,1,0))++failures;
        ++checks;if(hb_reg_forward((uint8_t *)code,sizeof(code)-1,1,1,0))++failures;
    }
    printf("hb_reg_forward_words: %u checks, %u failures\n",checks,failures);
    return failures ? 1 : 0;
}
