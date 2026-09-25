/* Test-only incoming ARM64 boundary. The compiler places the arguments; this
 * stub only captures them. All three spilled arguments are 64-bit, the common
 * scalar Darwin/Windows ARM64 subset. This is not a Wine/ARM64EC trampoline. */
_Static_assert(sizeof(hb_abi_native_image_v1_t) == 304, "capture image size");
_Static_assert(offsetof(hb_abi_native_image_v1_t, x) == 0, "capture x offset");
_Static_assert(offsetof(hb_abi_native_image_v1_t, d_bits) == 64, "capture d offset");
_Static_assert(offsetof(hb_abi_native_image_v1_t, stack) == 128, "capture stack offset");
_Static_assert(offsetof(hb_abi_native_image_v1_t, stack_count) == 288, "capture counts offset");
_Static_assert(offsetof(hb_abi_native_image_v1_t, x_count) == 292, "capture x count");
_Static_assert(offsetof(hb_abi_native_image_v1_t, d_count) == 296, "capture d count");
_Static_assert(offsetof(hb_abi_native_image_v1_t, reserved) == 300, "capture reserved");

#define HB_CAPTURE_PARAMETERS \
    uint64_t, double, uint64_t, float, uint32_t, double, uint16_t, float, \
    uint8_t, double, uint64_t, float, uint32_t, double, uint64_t, float, \
    uint64_t, double, uint64_t
extern uint64_t hb_test_callback_gpr(HB_CAPTURE_PARAMETERS);
extern double hb_test_callback_f64(HB_CAPTURE_PARAMETERS);
extern float hb_test_callback_f32(HB_CAPTURE_PARAMETERS);
#undef HB_CAPTURE_PARAMETERS

/* image[304], return registers[16], saved FP/LR[16]. Incoming SP is SP+336.
 * x9/x10 are scratch; x18 and all other callee-saved registers are untouched.
 * Counts come from the fixed prototype, not from architectural registers. */
__asm__(
    ".text\n.p2align 2\n"
    ".globl _hb_test_callback_gpr\n"
    ".globl _hb_test_callback_f64\n"
    ".globl _hb_test_callback_f32\n"
    "_hb_test_callback_gpr:\n_hb_test_callback_f64:\n_hb_test_callback_f32:\n"
    "sub sp, sp, #336\n"
    "stp x0, x1, [sp, #0]\n"
    "stp x2, x3, [sp, #16]\n"
    "stp x4, x5, [sp, #32]\n"
    "stp x6, x7, [sp, #48]\n"
    "stp d0, d1, [sp, #64]\n"
    "stp d2, d3, [sp, #80]\n"
    "stp d4, d5, [sp, #96]\n"
    "stp d6, d7, [sp, #112]\n"
    "ldp x9, x10, [sp, #336]\n"
    "stp x9, x10, [sp, #128]\n"
    "ldr x9, [sp, #352]\n"
    "str x9, [sp, #144]\n"
    "mov w9, #3\nmov w10, #8\n"
    "str w9, [sp, #288]\nstr w10, [sp, #292]\n"
    "str w10, [sp, #296]\nstr wzr, [sp, #300]\n"
    "stp x29, x30, [sp, #320]\n"
    "add x29, sp, #320\n"
    "mov x0, sp\nadd x1, sp, #304\nadd x2, sp, #336\n"
    "bl _hb_test_captured_callback_body\n"
    "ldr x0, [sp, #304]\nldr d0, [sp, #312]\n"
    "ldp x29, x30, [sp, #320]\nadd sp, sp, #336\nret\n"
);

typedef struct {
    hb_context_t *ctx;
    hb_abi_native_sig_v1_t sig;
    const uint64_t *expected;
    uint64_t stack;
    int direct, swap, completed;
} host_callback_fixture_t;

/* The binary runs these fixtures serially. No recursive or concurrent callback
 * support is implied by this test-only fixture. */
static host_callback_fixture_t host_callback_fixture;

void hb_test_captured_callback_body(const hb_abi_native_image_v1_t *captured,
                                    uint64_t result[2], uintptr_t incoming_sp)
{
    host_callback_fixture_t *f = &host_callback_fixture;
    const uint64_t *e = f->expected;
    unsigned failures_before = failures;
    result[0] = result[1] = SENTINEL;
    check((incoming_sp & 15) == 0, "real host entry stack is 16-byte aligned");
    check(captured->x[0] == f->stack + 0x100, "compiler passes guest output pointer intact");
    /* Independent positional oracle, with unspecified upper bits excluded. */
    const uint64_t expected_x[7] = {e[1],e[3],e[5],e[7],e[9],e[11],e[13]};
    const unsigned widths_x[7] = {8,4,2,1,8,4,8};
    for (unsigned i = 0; i < 7; ++i)
        check(low_bits(captured->x[i + 1], widths_x[i]) == expected_x[i],
              "real host GPR matches independent positional bits");
    for (unsigned i = 0; i < 8; ++i)
        check(low_bits(captured->d_bits[i], i % 2 ? 4 : 8) == e[2 * i],
              "real host FP register matches independent positional bits");
    for (unsigned i = 0; i < 3; ++i)
        check(captured->stack[i] == e[15 + i], "real host spill matches literal argument order");
    check(captured->stack_count == 3 && captured->x_count == 8 &&
          captured->d_count == 8 && captured->reserved == 0, "fixed prototype capture metadata");
    if (failures != failures_before) return;

    /* Copy only initialized fields: unused capture stack slots are unspecified. */
    hb_abi_native_image_v1_t image = {0};
    memcpy(image.x, captured->x, sizeof image.x);
    memcpy(image.d_bits, captured->d_bits, sizeof image.d_bits);
    memcpy(image.stack, captured->stack, 3 * sizeof(uint64_t));
    image.x_count = image.d_count = 8;
    image.stack_count = 3;
    if (f->swap) {
        uint64_t temp = image.stack[0];
        image.stack[0] = image.stack[2];
        image.stack[2] = temp;
    }
    hb_abi_x64_call_v1_t call;
    hb_abi_x64_value_v1_t tail[15];
    if (!check(hb_abi_native_raise_v1(&image, &f->sig, RETURN_PC, &call, tail, 15) == HB_OK,
               "raise genuinely captured host arguments") ||
        !check(hb_abi_x64_prepare_v1(f->ctx, CODE, &call) == HB_OK,
               "prepare guest from captured host arguments")) return;
    uint64_t entry_rsp = f->ctx->regs.x64.rsp;
    check(entry_rsp == f->stack + PAGE_BYTES - 168, "captured callback guest frame extent");
    uint32_t kind = f->sig.ret.kind, width = f->sig.ret.width_bytes;
    uint64_t expected_return = kind == HB_ABI_X64_F64_V1 ? e[16] :
                               kind == HB_ABI_X64_F32_V1 ? e[14] : e[f->swap ? 15 : 17];
    uint8_t code[512];
    size_t length = callback_code(code, kind);
    execute_return(f->ctx, code, length, kind, width, expected_return, 0,
                   f->stack, 1, f->direct);
    /* execute_return reports failures but returns void, including on early exit. */
    if (failures != failures_before ||
        !check(f->ctx->pc == RETURN_PC && f->ctx->regs.x64.rsp == entry_rsp + 8,
               "host callback collects only after actual guest RET")) return;
    unsigned mismatches = 0;
    for (unsigned i = 0; i < 18; ++i) {
        uint64_t observed = SENTINEL;
        check(hb_memory_read_u64(f->ctx->memory, f->stack + 0x100 + 8 * i, &observed) == HB_OK,
              "read host-call guest output");
        int differs = observed != e[i];
        mismatches += differs;
        check(differs == (f->swap && (i == 15 || i == 17)),
              "host-call guest observes literal positions, including swap control");
    }
    check(mismatches == (f->swap ? 2u : 0u), "swap control detects exactly two displaced arguments");
    uint64_t bits = SENTINEL;
    if (failures != failures_before ||
        !check(hb_abi_x64_read_return_v1(f->ctx, kind, width, &bits) == HB_OK,
               "collect guest result for real host caller")) return;
    result[kind == HB_ABI_X64_GPR_V1 ? 0 : 1] = bits;
    f->completed = 1;
}

static double host_callback_double(uint64_t bits)
{
    double value;
    memcpy(&value, &bits, sizeof value);
    return value;
}

static float host_callback_float(uint64_t bits)
{
    uint32_t low = (uint32_t)bits;
    float value;
    memcpy(&value, &low, sizeof value);
    return value;
}

static uint64_t host_captured_callback_case(int direct, unsigned backend,
                                           unsigned row, unsigned which)
{
    static const uint64_t rows[2][18] = {
        {UINT64_C(0x7ff8000000001234),UINT64_C(0x0123456789abcdef),
         UINT64_C(0x80000000),UINT64_C(0x89abcdef),
         UINT64_C(0x8000000000000000),UINT64_C(0x80fe),
         UINT64_C(0x7fc54321),UINT64_C(0x81),
         UINT64_C(0x7ff0000000000000),UINT64_C(0xfedcba9876543210),
         UINT64_C(0x7f800000),UINT64_C(0x80000001),
         UINT64_C(0x3ff8000000000000),UINT64_C(0x1000000020000000),
         UINT64_C(0xffc01234),UINT64_C(0x8877665544332211),
         UINT64_C(0xfff8000000005678),UINT64_C(0x13579bdf2468ace0)},
        {UINT64_C(0xfff8000000004321),UINT64_C(0xf123456789abcdef),
         UINT64_C(0x7fc01234),UINT64_C(0x76543210),
         UINT64_C(0x3ff4000000000000),UINT64_C(0xfedc),
         UINT64_C(0x80000000),UINT64_C(0xfe),
         UINT64_C(0xfff0000000000000),UINT64_C(0x123456789abcdef0),
         UINT64_C(0xff800000),UINT64_C(0xfffffffe),
         UINT64_C(0x7ff800000000abcd),UINT64_C(0xaabbccdd11223344),
         UINT64_C(0x80000000),UINT64_C(0x1122334455667788),
         UINT64_C(0x8000000000000000),UINT64_C(0xeca86420fdb97531)}
    };
    static const hb_abi_native_arg_v1_t arguments[19] = {
        {HB_ABI_X64_GPR_V1,8},{HB_ABI_X64_F64_V1,8},{HB_ABI_X64_GPR_V1,8},
        {HB_ABI_X64_F32_V1,4},{HB_ABI_X64_GPR_V1,4},{HB_ABI_X64_F64_V1,8},
        {HB_ABI_X64_GPR_V1,2},{HB_ABI_X64_F32_V1,4},{HB_ABI_X64_GPR_V1,1},
        {HB_ABI_X64_F64_V1,8},{HB_ABI_X64_GPR_V1,8},{HB_ABI_X64_F32_V1,4},
        {HB_ABI_X64_GPR_V1,4},{HB_ABI_X64_F64_V1,8},{HB_ABI_X64_GPR_V1,8},
        {HB_ABI_X64_F32_V1,4},{HB_ABI_X64_GPR_V1,8},{HB_ABI_X64_F64_V1,8},
        {HB_ABI_X64_GPR_V1,8}
    };
    {
                char label[112];
                snprintf(label, sizeof label, "real host callback %s %s row=%u case=%u",
                         backend ? "JIT" : "interpreter", direct ? "direct" : "helper", row, which);
                phase = label;
                unsigned before = failures;
                host_callback_fixture_t *f = &host_callback_fixture;
                memset(f, 0, sizeof *f);
                f->ctx = new_context_mapped(backend ? HB_BACKEND_JIT : HB_BACKEND_INTERP,
                                            direct, &f->stack);
                if (!f->ctx) return SENTINEL;
                f->ctx->step_limit = 256;
                f->expected = rows[row]; f->direct = direct; f->swap = which == 3;
                uint32_t kind = which == 1 ? HB_ABI_X64_F64_V1 :
                                which == 2 ? HB_ABI_X64_F32_V1 : HB_ABI_X64_GPR_V1;
                f->sig.abi_version = HB_ABI_NATIVE_V1;
                f->sig.struct_size = sizeof f->sig;
                f->sig.target_abi = HB_ABI_NATIVE_TARGET_AAPCS64_WIN_V1;
                f->sig.argument_count = 19;
                f->sig.ret = (hb_abi_native_arg_v1_t){kind, kind == HB_ABI_X64_F32_V1 ? 4 : 8};
                memcpy(f->sig.args, arguments, sizeof arguments);
                const uint64_t *e = rows[row];
                uint64_t observed = SENTINEL;
                /* Opaque assembly callees: the compiler must implement these
                 * exact prototypes. No generated native image drives this call. */
#define HB_CAPTURE_ARGUMENTS \
    f->stack + 0x100, host_callback_double(e[0]), e[1], host_callback_float(e[2]), \
    (uint32_t)e[3], host_callback_double(e[4]), (uint16_t)e[5], host_callback_float(e[6]), \
    (uint8_t)e[7], host_callback_double(e[8]), e[9], host_callback_float(e[10]), \
    (uint32_t)e[11], host_callback_double(e[12]), e[13], host_callback_float(e[14]), \
    e[15], host_callback_double(e[16]), e[17]
                if (kind == HB_ABI_X64_GPR_V1) observed = hb_test_callback_gpr(HB_CAPTURE_ARGUMENTS);
                else if (kind == HB_ABI_X64_F64_V1) {
                    double result = hb_test_callback_f64(HB_CAPTURE_ARGUMENTS);
                    memcpy(&observed, &result, sizeof result);
                } else {
                    float result = hb_test_callback_f32(HB_CAPTURE_ARGUMENTS);
                    uint32_t low;
                    memcpy(&low, &result, sizeof low);
                    observed = low;
                }
#undef HB_CAPTURE_ARGUMENTS
                uint64_t wanted = kind == HB_ABI_X64_F64_V1 ? e[16] :
                                  kind == HB_ABI_X64_F32_V1 ? e[14] : e[f->swap ? 15 : 17];
                check(f->completed, "real host callback completed guest execution and collection");
                check(observed == wanted, "real C caller receives exact scalar return bits");
                uint64_t guard = 0;
                check(hb_memory_read_u64(f->ctx->memory, f->stack + 0xf8, &guard) == HB_OK &&
                      guard == UINT64_C(0xa5a5a5a5a5a5a5a5), "host-call output lower guard");
                check(hb_memory_read_u64(f->ctx->memory, f->stack + 0x190, &guard) == HB_OK &&
                      guard == UINT64_C(0xa5a5a5a5a5a5a5a5), "host-call output upper guard");
                printf("host-callback: backend=%s mapping=%s row=%u return=%u swap=%d completed=%d failures=%u\n",
                       backend ? "JIT" : "interpreter", direct ? "direct" : "helper", row,
                       kind, f->swap, f->completed, failures - before);
                hb_context_destroy(f->ctx);
                f->ctx = NULL;
                phase = "real host callback cleanup";
                return observed;
    }
}

static void host_captured_callbacks(int direct)
{
    for (unsigned backend = 0; backend < 2; ++backend)
        for (unsigned row = 0; row < 2; ++row)
            for (unsigned which = 0; which < 4; ++which)
                (void)host_captured_callback_case(direct, backend, row, which);
}
