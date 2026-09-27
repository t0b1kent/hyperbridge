/* Native CMPXCHG16B: differential registers/memory/all flags, pending producers,
 * every alignment remainder, emission/provider controls and CASPAL write intent. */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_flags.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

extern uint64_t hb_codegen_native_cas128_emitted(void);
enum { PAGE = 16384, FORMS = 14, ALIGNED_CASES = 2048, UNALIGNED_CASES = 240 };
static uint64_t rng = UINT64_C(0xf37116bca552896d);
static uint64_t random64(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}
static hb_result_t provider(void* user, hb_gva_t addr, const uint64_t expected[2],
                            const uint64_t desired[2], uint64_t observed[2], bool* exchanged) {
    unsigned long* calls = user;
    unsigned __int128 e, d;
    ++*calls;
    memcpy(&e, expected, 16); memcpy(&d, desired, 16);
    *exchanged = __atomic_compare_exchange_n((unsigned __int128*)(uintptr_t)addr,
                                             &e, d, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    memcpy(observed, &e, 16);
    return HB_OK;
}
static unsigned flags(hb_context_t* c) {
    (void)hb_lazy_flags_materialize_available(c, HB_FLAG_BIT_ALL);
    return c->flags.cf | c->flags.pf << 1 | c->flags.af << 2 |
           c->flags.zf << 3 | c->flags.sf << 4 | c->flags.of << 5;
}
static void init_flags(hb_context_t* c, unsigned bits, unsigned mode, uint64_t a, uint64_t b) {
    memset(&c->flags, 0, sizeof(c->flags));
    c->flags.cf = bits & 1; c->flags.pf = (bits >> 1) & 1;
    c->flags.af = (bits >> 2) & 1; c->flags.zf = (bits >> 3) & 1;
    c->flags.sf = (bits >> 4) & 1; c->flags.of = (bits >> 5) & 1;
    memset(&c->lazy_flags, 0, sizeof(c->lazy_flags));
    if (!mode) return;
    hb_lazy_flags_note(c, HB_LAZY_FLAGS_SUB, (hb_size_t)(1u << ((mode - 1u) & 3u)), a, b, a - b, 0);
    if (mode == 5) c->lazy_flags.materialized_mask = HB_FLAG_BIT_ALL;
    if (mode == 6) {
        c->lazy_flags.unsupported_mask = HB_FLAG_BIT_ZF | HB_FLAG_BIT_AF;
        c->lazy_flags.valid_mask &= ~c->lazy_flags.unsupported_mask;
    }
    if (mode == 7) {
        c->lazy_flags.materialized_mask = HB_FLAG_BIT_ZF | HB_FLAG_BIT_CF | HB_FLAG_BIT_PF;
        c->lazy_flags.unsupported_mask = HB_FLAG_BIT_ZF | HB_FLAG_BIT_OF;
        c->lazy_flags.valid_mask &= ~c->lazy_flags.unsupported_mask;
    }
}

/* Assembled by the system clang, not a hand-written opcode. Probe before HB
 * installs handlers. A mismatching CASPAL still requires write permission. */
static sigjmp_buf probe_jump;
static volatile sig_atomic_t probe_signal;
static void probe_handler(int sig) { probe_signal = sig; siglongjmp(probe_jump, 1); }
__attribute__((noinline)) static void caspal_probe(uint64_t* p, uint64_t expected) {
    register uint64_t a __asm__("x0") = expected;
    register uint64_t b __asm__("x1") = 2;
    register uint64_t d __asm__("x2") = 3;
    register uint64_t e __asm__("x3") = 4;
    __asm__ volatile(".arch armv8.1-a\n\tcaspal x0, x1, x2, x3, [%[p]]"
                     : "+r"(a), "+r"(b) : "r"(d), "r"(e), [p] "r"(p) : "memory");
}
static int readonly_probe(void) {
    uint64_t* p = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) return 1;
    p[0] = 1; p[1] = 2;
    struct sigaction sa, old_bus, old_segv;
    memset(&sa, 0, sizeof(sa)); sa.sa_handler = probe_handler; sigemptyset(&sa.sa_mask);
    if (sigaction(SIGBUS, &sa, &old_bus) || sigaction(SIGSEGV, &sa, &old_segv) ||
        mprotect(p, PAGE, PROT_READ)) return 1;
    int bad = 0;
    for (int match = 0; match < 2; ++match) {
        probe_signal = 0;
        if (!sigsetjmp(probe_jump, 1)) caspal_probe(p, match ? 1 : 0);
        if ((probe_signal != SIGBUS && probe_signal != SIGSEGV) || p[0] != 1 || p[1] != 2) ++bad;
        printf("CASPAL_READONLY match=%d signal=%d unchanged=%d\n", match, (int)probe_signal, p[0] == 1 && p[1] == 2);
    }
    sigaction(SIGBUS, &old_bus, NULL); sigaction(SIGSEGV, &old_segv, NULL);
    munmap(p, PAGE);
    return bad;
}

int main(void) {
    const char* gate_value = getenv("MACRUNNER_HB_NATIVE_CAS128");
    const char* flip_value = getenv("MACRUNNER_HB_TEST_MEM_NATIVE_FLIP");
    int gate = gate_value && strcmp(gate_value, "0");
    int flip = flip_value && strcmp(flip_value, "0");
    unsigned long cases = 0, bad = 0, detected = 0, controls_bad = readonly_probe();
    unsigned long calls[2] = {0, 0};
    hb_context_t* cs[2] = {hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP), hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT)};
    hb_memory_t* ms[2] = {hb_memory_create(0), hb_memory_create(0)};
    uint8_t* code = mmap(NULL, PAGE * FORMS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* data = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* stack = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (!cs[0] || !cs[1] || !ms[0] || !ms[1] || code == MAP_FAILED || data == MAP_FAILED || stack == MAP_FAILED) return 2;
    for (int k = 0; k < 2; ++k) {
        cs[k]->memory = ms[k]; cs[k]->config.fallback_enabled = false;
        hb_memory_set_atomic_cmpxchg128_handler(ms[k], provider, &calls[k]);
        if (hb_memory_sync_live_range(ms[k], (uintptr_t)code, PAGE * FORMS, HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
            hb_memory_sync_live_range(ms[k], (uintptr_t)data, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK ||
            hb_memory_sync_live_range(ms[k], (uintptr_t)stack, PAGE, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) return 2;
    }
    hb_jit_runtime_t* rt = hb_jit_runtime_create(cs[1]);
    if (!rt) return 2;
    hb_ir_func_t* funcs[FORMS] = {0};
    uint64_t emitted_before = hb_codegen_native_cas128_emitted();
    for (unsigned form = 0; form < FORMS; ++form) {
        uint8_t* at = code + PAGE * form;
        unsigned prefix = form < 6 ? form / 2 : 0, n = 0;
        unsigned addressing = form < 6 ? 0 : 1 + (form - 6) / 2;
        /* Real predecessor in the SAME block: cmp r8,r9 / add r8,r9. */
        if (prefix) { at[n++] = 0x4d; at[n++] = prefix == 1 ? 0x39 : 0x01; at[n++] = 0xc8; }
        unsigned cas_offset = n;
        if (!(form & 1u)) at[n++] = 0xf0;
        at[n++] = 0x48; at[n++] = 0x0f; at[n++] = 0xc7;
        switch (addressing) {
            case 0: at[n++] = 0x0f; break;                      /* [rdi] */
            case 1:                                           /* [rdi+rsi*8+127] */
                at[n++] = 0x4c; at[n++] = 0xf7; at[n++] = 0x7f; break;
            case 2:                                           /* [rdi+rsi*4-128] */
                at[n++] = 0x4c; at[n++] = 0xb7; at[n++] = 0x80; break;
            case 3:                                           /* [rax+rcx*2+0x12345678] */
                at[n++] = 0x8c; at[n++] = 0x48;
                memcpy(at + n, &(int32_t){0x12345678}, 4); n += 4; break;
            case 4:                                           /* [rbx+rdx*4-0x12345678] */
                at[n++] = 0x8c; at[n++] = 0x93;
                memcpy(at + n, &(int32_t){-0x12345678}, 4); n += 4; break;
        }
        /* Consume the new ZF before flags are materialized at the test boundary. */
        at[n++] = 0x41; at[n++] = 0x0f; at[n++] = 0x94; at[n++] = 0xc2; /* sete r10b */
        at[n++] = 0x41; at[n++] = 0x0f; at[n++] = 0x95; at[n++] = 0xc3; /* setne r11b */
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, at, n, (uintptr_t)at);
        if (!dec || hb_lift_func_x64(dec, &funcs[form]) != HB_OK || !funcs[form]) return 2;
        hb_decoder_destroy(dec);
        unsigned long form_bad = 0, form_detected = 0;
        for (unsigned item = 0; item < ALIGNED_CASES + UNALIGNED_CASES; ++item) {
            unsigned unaligned = item >= ALIGNED_CASES;
            unsigned offset = unaligned ? 1 + (item - ALIGNED_CASES) % 15 : 0;
            unsigned outcome = (item >> 6) & 3u, mode = (item >> 8) & 7u;
            uint64_t initial[8], observed[2][8];
            for (unsigned i = 0; i < 8; ++i) initial[i] = random64();
            uint64_t expected[2], desired[2] = {random64(), random64()};
            memcpy(expected, (uint8_t*)initial + offset, 16);
            if (outcome & 1) expected[0] ^= UINT64_C(0x8100000000000001);
            if (outcome & 2) expected[1] ^= UINT64_C(0x4280000000000001);
            uint64_t target = (uintptr_t)data + offset;
            uint64_t index = random64(), base = target;
            if (addressing == 1) base = target - index * 8 - 127;
            if (addressing == 2) base = target - index * 4 + 128;
            if (addressing == 3) {
                /* RAX supplies both the expected low word and the EA base;
                 * RCX supplies both the desired high word and the EA index.
                 * Retain the requested match/mismatch independently of EA. */
                expected[0] = target - desired[1] * 2 - UINT64_C(0x12345678);
                uint64_t memory_low = expected[0] ^ ((outcome & 1) ? UINT64_C(0x8100000000000001) : 0);
                memcpy((uint8_t*)initial + offset, &memory_low, 8);
            }
            if (addressing == 4) {
                /* RBX is desired low and EA base; RDX is expected high and
                 * EA index. A mismatch must update RDX only after the access. */
                desired[0] = target - expected[1] * 4 + UINT64_C(0x12345678);
            }
            uint64_t a = random64(), b = random64();
            hb_exec_result_t o[2]; hb_result_t r[2], flag_result[2]; unsigned f[2];
            unsigned long before_calls[2] = {calls[0], calls[1]};
            for (int k = 0; k < 2; ++k) {
                hb_context_t* c = cs[k];
                hb_context_reset(c);
                memset(&c->regs, 0, sizeof(c->regs));
                c->regs.x64.rax = expected[0]; c->regs.x64.rdx = expected[1];
                c->regs.x64.rbx = desired[0]; c->regs.x64.rcx = desired[1];
                c->regs.x64.rdi = base;
                c->regs.x64.rsi = index;
                c->regs.x64.rsp = (uintptr_t)stack + PAGE - 256;
                c->regs.x64.r8 = a; c->regs.x64.r9 = b;
                c->pc = c->regs.x64.rip = (uintptr_t)at;
                init_flags(c, item & 63u, mode, a, b);
                memcpy(data, initial, sizeof(initial));
                memset(&o[k], 0, sizeof(o[k]));
                r[k] = k ? hb_jit_runtime_run(rt, funcs[form], &o[k]) : hb_runtime_run(c, funcs[form], HB_BACKEND_INTERP, &o[k]);
                flag_result[k] = unaligned ? HB_OK : hb_lazy_flags_materialize(c, HB_FLAG_BIT_ZF);
                f[k] = flags(c);
                memcpy(observed[k], data, sizeof(initial));
            }
            int diff = r[0] != r[1] || flag_result[0] != flag_result[1] ||
                       o[0].result != o[1].result || o[0].faulted != o[1].faulted ||
                       cs[0]->pc != cs[1]->pc || memcmp(&cs[0]->regs, &cs[1]->regs, sizeof(cs[0]->regs)) ||
                       memcmp(observed[0], observed[1], sizeof(observed[0])) || f[0] != f[1] ||
                       cs[0]->last_fault_kind != cs[1]->last_fault_kind;
            if (!unaligned) {
                if (r[0] != HB_OK || flag_result[0] != HB_OK || flag_result[1] != HB_OK ||
                    o[0].faulted || cs[0]->pc != (uintptr_t)at + n ||
                    ((f[0] >> 3) & 1u) != (outcome == 0) || calls[0] != before_calls[0] + 1 ||
                    calls[1] != before_calls[1] + (gate ? 0 : 1)) ++controls_bad;
            } else if (cs[0]->last_fault_kind != HB_FAULT_KIND_GENERAL_PROTECTION ||
                       cs[0]->pc != (uintptr_t)at + cas_offset ||
                       memcmp(observed[0], initial, sizeof(initial)) ||
                       calls[0] != before_calls[0] || calls[1] != before_calls[1]) ++controls_bad;
            ++cases;
            if (flip && gate && !unaligned) {
                if (diff) { ++detected; ++form_detected; }
                else { ++bad; ++form_bad; }
            } else if (diff) { ++bad; ++form_bad; }
            if (diff && !(flip && gate && !unaligned) && bad <= 10)
                printf("CAS128_DIFF form=%u item=%u off=%u outcome=%u mode=%u r=%d/%d flags=%02x/%02x fault=%u/%u pc=%llx/%llx\n",
                       form, item, offset, outcome, mode, r[0], r[1], f[0], f[1], cs[0]->last_fault_kind, cs[1]->last_fault_kind,
                       (unsigned long long)cs[0]->pc, (unsigned long long)cs[1]->pc);
        }
        printf("CAS128_FORM form=%u locked=%u predecessor=%u addressing=%u cases=%u bad=%lu flip_detected=%lu\n",
               form, !(form & 1u), prefix, addressing, ALIGNED_CASES + UNALIGNED_CASES, form_bad, form_detected);
    }
    uint64_t emitted = hb_codegen_native_cas128_emitted() - emitted_before;
    if (gate ? emitted < FORMS : emitted != 0) ++controls_bad;
    printf("CAS128_TOTAL gate=%d flip=%d cases=%lu bad=%lu control_bad=%lu flip_detected=%lu emitted=%llu provider_interp=%lu provider_jit=%lu\n",
           gate, flip, cases, bad, controls_bad, detected, (unsigned long long)emitted, calls[0], calls[1]);
    hb_jit_runtime_destroy(rt);
    for (unsigned i = 0; i < FORMS; ++i) hb_ir_func_destroy(funcs[i]);
    for (unsigned k = 0; k < 2; ++k) { cs[k]->memory = NULL; hb_context_destroy(cs[k]); hb_memory_destroy(ms[k]); }
    munmap(code, PAGE * FORMS); munmap(data, PAGE); munmap(stack, PAGE);
    return bad || controls_bad ? 1 : 0;
}
