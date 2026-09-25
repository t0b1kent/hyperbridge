/* Standalone private-evaluator conformance. Reference construction never calls
 * this evaluator or its bundled arithmetic. Root owns compilation/execution. */
#pragma STDC FENV_ACCESS ON
#include "hb_x87_transcendental.h"
#include "test_support.h"
#include "reference_vectors.h"
#include <limits.h>
#include <stdbool.h>

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
typedef struct { uint8_t before[32]; ct_raw80 raw; uint8_t after[32]; } ct_input;
typedef struct { uint8_t before[32]; hb_x87_transcendental_result_t result; uint8_t after[32]; } ct_output;
static ct_stats stats;
static unsigned numerical_calls, structural_calls, error_calls, operation_coverage;

static bool binary_operation(hb_x87_transcendental_op_t op)
{
    return op == HB_X87_TRANS_FYL2X || op == HB_X87_TRANS_FYL2XP1 ||
           op == HB_X87_TRANS_FPATAN || op == HB_X87_TRANS_FSCALE;
}
static unsigned expected_count(hb_x87_transcendental_op_t op)
{
    return op == HB_X87_TRANS_FSINCOS || op == HB_X87_TRANS_FPTAN ? 2u : 1u;
}
static unsigned expected_clear(hb_x87_transcendental_op_t op)
{
    return op == HB_X87_TRANS_FSIN || op == HB_X87_TRANS_FCOS ||
           op == HB_X87_TRANS_FSINCOS || op == HB_X87_TRANS_FPTAN ? 0x0400u : 0u;
}
static int same_result(const hb_x87_transcendental_result_t *a,
                       const hb_x87_transcendental_result_t *b)
{
    return a->result_count == b->result_count && a->result_count <= 2 &&
           a->component_flags == b->component_flags && a->status_set == b->status_set &&
           a->status_clear == b->status_clear &&
           memcmp(a->raw, b->raw, 10u * a->result_count) == 0;
}

static int successful_call(const ct_vector *vector, const char *name,
                            hb_x87_transcendental_op_t op, ct_words a, ct_words b,
                            unsigned pc, unsigned rc, unsigned host_rc, unsigned sticky,
                            unsigned alias, hb_x87_transcendental_result_t *observed)
{
    ct_input input0, input1;
    ct_output output;
    ct_pattern(&input0, sizeof(input0), 0xa6);
    ct_pattern(&input1, sizeof(input1), 0x39);
    ct_pattern(&output, sizeof(output), 0xd2);
    input0.raw = ct_raw(a.sign_exp, a.significand);
    input1.raw = ct_raw(b.sign_exp, b.significand);
    const uint8_t *st0 = input0.raw.bytes;
    const uint8_t *st1 = binary_operation(op) ? input1.raw.bytes : NULL;
    if (alias == 1 || alias == 3 || alias == 5) {
        memcpy(output.result.raw[0], st0, 10);
        st0 = output.result.raw[0];
    }
    if (alias == 2 && binary_operation(op)) {
        memcpy(output.result.raw[0], input1.raw.bytes, 10);
        st1 = output.result.raw[0];
    } else if (alias == 3 && binary_operation(op)) {
        memcpy(output.result.raw[1], input1.raw.bytes, 10);
        st1 = output.result.raw[1];
    } else if (!binary_operation(op) && alias >= 2) {
        /* Optional unary ST1 is ignored, including overlap with the output. */
        st1 = alias == 2 ? input1.raw.bytes : output.result.raw[1];
    }
    if (alias >= 4 && binary_operation(op)) st1 = st0;
    ct_input old0, old1;
    ct_output old_output;
    memcpy(&old0, &input0, sizeof(old0));
    memcpy(&old1, &input1, sizeof(old1));
    memcpy(&old_output, &output, sizeof(old_output));
    snprintf(stats.phase, sizeof(stats.phase), "%s op=%u PC=%u RC=%u host=%u sticky=%u alias=%u",
             name, (unsigned)op, pc, rc, host_rc, sticky, alias);
    if (!ct_check(&stats, ct_seed_host(host_rc, sticky), "host seed"))
        return 0;
    ct_host before = ct_capture_host();
    bool ok = hb_x87_transcendental(op, st0, st1,
                                   (uint16_t)(0x007fu | (pc << 8) | (rc << 10)), &output.result);
    ct_host after = ct_capture_host();
    if (vector) ++numerical_calls; else ++structural_calls;
    operation_coverage |= 1u << (unsigned)op;
    ct_check(&stats, ok, "all declared operations accept nonnull raw encodings");
    ct_check(&stats, ct_same_host(&before, &after), "full host FPCR/FPSR/fenv preserved");
    ct_check(&stats, memcmp(&input0, &old0, sizeof(input0)) == 0 &&
                    memcmp(&input1, &old1, sizeof(input1)) == 0,
             "disjoint input payloads and canaries unchanged");
    ct_check(&stats, memcmp(output.before, old_output.before, sizeof(output.before)) == 0 &&
                    memcmp(output.after, old_output.after, sizeof(output.after)) == 0,
             "output canaries unchanged across all alias arrangements");
    ct_check(&stats, output.result.result_count == expected_count(op), "scalar/paired result count");
    ct_check(&stats, !(output.result.component_flags & ~0x1fu) &&
                    output.result.status_set == ((output.result.component_flags & 0x10u) ? 1u : 0u) &&
                    output.result.status_clear == expected_clear(op),
             "outer flags and selected invalid/C2 policy");
    if (vector) {
        ct_check(&stats, output.result.result_count == vector->result_count,
                 "independent vector result count");
        for (unsigned result = 0; result < vector->result_count; ++result) {
            ct_words word = vector->expected[rc][result];
            ct_raw80 expected = ct_raw(word.sign_exp, word.significand);
            ct_check(&stats, memcmp(output.result.raw[result], expected.bytes, 10) == 0,
                     result ? "independent secondary raw result/order" : "independent primary raw result");
        }
        ct_check(&stats, (output.result.component_flags & vector->flags_mask) == vector->flags_value,
                 "independent vector outer-flag constraint");
    }
    if (observed)
        memcpy(observed, &output.result, sizeof(*observed));
    return 1;
}

static void numerical_matrix(void)
{
    for (size_t i = 0; i < COUNT(ct_vectors); ++i) {
        const ct_vector *v = &ct_vectors[i];
        unsigned aliases = binary_operation(v->operation) && v->st0.sign_exp == v->st1.sign_exp &&
                           v->st0.significand == v->st1.significand ? 6u : 4u;
        for (unsigned pc = 0; pc < 4; ++pc)
            for (unsigned rc = 0; rc < 4; ++rc)
                for (unsigned host = 0; host < 4; ++host)
                    for (unsigned sticky = 0; sticky < 2; ++sticky)
                        for (unsigned alias = 0; alias < aliases; ++alias)
                            successful_call(v, v->name, v->operation, v->st0, v->st1,
                                            pc, rc, host, sticky, alias, NULL);
    }
}

static void boundary_structure_matrix(void)
{
    static const ct_words encodings[] = {
        {0x0000, UINT64_C(0x0000000000000001)}, /* Minimum ext80 subnormal. */
        {0x0000, UINT64_C(0x8000000000000000)}, /* Pseudo-denormal. */
        {0x3fff, UINT64_C(0x4000000000000000)}, /* Unnormal. */
        {0x3fff, UINT64_C(0x0000000000000000)}, /* Noncanonical zero significand. */
        {0x7fff, UINT64_C(0xc000000000000001)}, /* Quiet NaN payload. */
        {0xffff, UINT64_C(0x8000000000000001)}, /* Signaling NaN payload. */
        {0x7ffe, UINT64_C(0xffffffffffffffff)}, /* Largest canonical finite. */
        {0xffff, UINT64_C(0x8000000000000000)}  /* Negative infinity. */
    };
    const ct_words one = {0x3fff, UINT64_C(0x8000000000000000)};
    for (unsigned operation = 0; operation <= HB_X87_TRANS_FSCALE; ++operation) {
        hb_x87_transcendental_op_t op = (hb_x87_transcendental_op_t)operation;
        for (unsigned operand = 0; operand < (binary_operation(op) ? 2u : 1u); ++operand)
            for (size_t i = 0; i < COUNT(encodings); ++i)
                for (unsigned rc = 0; rc < 4; ++rc) {
                    hb_x87_transcendental_result_t reference;
                    bool have_reference = false;
                    for (unsigned pc = 0; pc < 4; ++pc)
                        for (unsigned sticky = 0; sticky < 2; ++sticky)
                            for (unsigned alias = 0; alias < 4; ++alias) {
                                hb_x87_transcendental_result_t observed;
                                if (!successful_call(NULL, "boundary encoding: protocol only", op,
                                                operand ? one : encodings[i], operand ? encodings[i] : one,
                                                pc, rc, (rc + 1u) & 3u, sticky, alias, &observed)) continue;
                                if (!have_reference) {
                                    memcpy(&reference, &observed, sizeof(reference));
                                    have_reference = true;
                                } else {
                                    ct_check(&stats, same_result(&reference, &observed),
                                             "full80 PC and storage invariance; no invented numerical oracle");
                                }
                            }
                }
    }
}

static void invalid_call(int operation, unsigned null_case, unsigned pc, unsigned rc,
                         unsigned host, unsigned sticky, unsigned alias)
{
    ct_input input0, input1;
    ct_output output;
    ct_pattern(&input0, sizeof(input0), 0x71);
    ct_pattern(&input1, sizeof(input1), 0x1d);
    ct_pattern(&output, sizeof(output), 0xb3);
    input0.raw = ct_raw(0x3fff, UINT64_C(0x8000000000000000));
    input1.raw = ct_raw(0x3ffe, UINT64_C(0x8000000000000000));
    const uint8_t *st0 = input0.raw.bytes, *st1 = input1.raw.bytes;
    if (alias) { memcpy(output.result.raw[0], st0, 10); st0 = output.result.raw[0]; }
    hb_x87_transcendental_result_t *destination = &output.result;
    if (null_case == 1 || null_case == 3) st0 = NULL;
    if (null_case == 2 || null_case == 3) destination = NULL;
    if (null_case == 4) st1 = NULL;
    ct_input old0, old1;
    ct_output old_output;
    memcpy(&old0, &input0, sizeof(old0)); memcpy(&old1, &input1, sizeof(old1));
    memcpy(&old_output, &output, sizeof(old_output));
    snprintf(stats.phase, sizeof(stats.phase), "error op=%d null=%u PC=%u RC=%u host=%u sticky=%u alias=%u",
             operation, null_case, pc, rc, host, sticky, alias);
    if (!ct_check(&stats, ct_seed_host(host, sticky), "host seed for error")) return;
    ct_host before = ct_capture_host();
    bool ok = hb_x87_transcendental((hb_x87_transcendental_op_t)operation, st0, st1,
                                   (uint16_t)(0x007fu | (pc << 8) | (rc << 10)), destination);
    ct_host after = ct_capture_host();
    ++error_calls;
    ct_check(&stats, !ok, "invalid API arguments return false");
    ct_check(&stats, ct_same_host(&before, &after), "error path preserves full host environment");
    ct_check(&stats, memcmp(&output, &old_output, sizeof(output)) == 0 &&
                    memcmp(&input0, &old0, sizeof(input0)) == 0 &&
                    memcmp(&input1, &old1, sizeof(input1)) == 0,
             "false return leaves complete output/input/canary bytes unchanged");
}

static void invalid_matrix(void)
{
    static const int invalid_operations[] = {-1, HB_X87_TRANS_FSCALE + 1, INT_MAX};
    for (unsigned pc = 0; pc < 4; ++pc)
        for (unsigned rc = 0; rc < 4; ++rc)
            for (unsigned host = 0; host < 4; ++host)
                for (unsigned sticky = 0; sticky < 2; ++sticky)
                    for (unsigned alias = 0; alias < 2; ++alias) {
                        for (unsigned op = 0; op <= HB_X87_TRANS_FSCALE; ++op) {
                            for (unsigned null_case = 1; null_case <= 3; ++null_case)
                                invalid_call((int)op, null_case, pc, rc, host, sticky, alias);
                            if (binary_operation((hb_x87_transcendental_op_t)op))
                                invalid_call((int)op, 4, pc, rc, host, sticky, alias);
                        }
                        for (size_t i = 0; i < COUNT(invalid_operations); ++i)
                            invalid_call(invalid_operations[i], 0, pc, rc, host, sticky, alias);
                    }
}

int main(void)
{
    ct_host caller = ct_capture_host();
    fenv_t held;
    if (!caller.env_ok || feholdexcept(&held)) return 2;
    numerical_matrix();
    boundary_structure_matrix();
    invalid_matrix();
    ct_check(&stats, operation_coverage == 0x1ffu, "all nine operations exercised");
    int restored = ct_restore_host(&caller);
    ct_check(&stats, restored, "complete caller environment restored");
    printf("transcendental_component_test: %zu reference vectors, %u numerical calls, %u structural calls, %u error calls, %u checks, %u failures, restored=%d\n",
           COUNT(ct_vectors), numerical_calls, structural_calls, error_calls, stats.checks, stats.failures, restored);
    if (!ct_restore_host(&caller)) return 2;
    return stats.failures ? 1 : 0;
}
