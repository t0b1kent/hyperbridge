/* Independent ARM64EC boundary planning. No executable donor code is used.
 * Inputs are already captured values; this helper performs no memory access. */
#ifndef HB_EC_BOUNDARY_H
#define HB_EC_BOUNDARY_H
#include <stdint.h>
#define HB_EC_EXIT_RETURN_INSN UINT32_C(0xd63f0200)
enum hb_ec_leave_kind { HB_EC_LEAVE_RETURN, HB_EC_LEAVE_CALL, HB_EC_LEAVE_CALL_SHIM };
struct hb_ec_leave_plan {
    uint64_t target, native_sp, link_register;
    enum hb_ec_leave_kind kind;
};
static inline int hb_ec_plan_leave(uint64_t pc, uint64_t sp, uint32_t metadata,
                                  uint64_t return_address, uint64_t ret_shim,
                                  struct hb_ec_leave_plan *out)
{
    struct hb_ec_leave_plan plan;
    int64_t delta;
    if (!out || pc < 4 || (pc & 3) || !sp || (sp & 7)) return 0;
    plan.target = pc;
    plan.native_sp = sp;
    plan.link_register = 0;
    if (metadata == HB_EC_EXIT_RETURN_INSN) {
        if (sp & 15) return 0;
        plan.kind = HB_EC_LEAVE_RETURN;
    } else {
        delta = (int32_t)(metadata & ~UINT32_C(3));
        if (delta < 0) {
            if (pc < (uint64_t)-delta) return 0;
            plan.target = pc - (uint64_t)-delta;
        } else {
            if (pc > UINT64_MAX - (uint64_t)delta) return 0;
            plan.target = pc + (uint64_t)delta;
        }
        if (!plan.target) return 0;
        if (sp & 15) {
            if (sp > UINT64_MAX - 8) return 0;
            plan.native_sp = sp + 8;
            plan.link_register = return_address;
            plan.kind = HB_EC_LEAVE_CALL;
        } else {
            if (!ret_shim) return 0;
            plan.link_register = ret_shim;
            plan.kind = HB_EC_LEAVE_CALL_SHIM;
        }
    }
    *out = plan;
    return 1;
}
#endif
