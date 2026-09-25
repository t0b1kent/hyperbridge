/* Model the missing external dispatcher with existing public engine APIs.
 * The outer executor is suspended at an external CALL, not recursively running
 * the same context or entering a still-active JIT block. The native target
 * invokes the real typed capture fixture with a separate context/executor. */
typedef struct {
    hb_context_t *outer;
    int direct;
    unsigned inner_backend, inner_return, calls;
    uint64_t observed[5], inner_bits;
} nested_boundary_fixture_t;

static nested_boundary_fixture_t *nested_boundary_active;

static uint32_t nested_boundary_target(uint64_t a, uint64_t b, uint32_t c,
                                       uint64_t d, uint64_t e)
{
    nested_boundary_fixture_t *f = nested_boundary_active;
    if (!f) { check(0, "native reentry target has an active fixture"); return 0; }
    ++f->calls;
    f->observed[0] = a; f->observed[1] = b; f->observed[2] = c;
    f->observed[3] = d; f->observed[4] = e;
    const char *outer_phase = phase;
    unsigned char saved_regs[sizeof f->outer->regs.x64];
    unsigned char saved_frame[96], after_frame[96];
    memcpy(saved_regs, &f->outer->regs.x64, sizeof saved_regs);
    uint64_t saved_pc = f->outer->pc;
    uint32_t saved_mxcsr = f->outer->mxcsr;
    if (!check(hb_memory_read(f->outer->memory, f->outer->regs.x64.rsp,
                              saved_frame, sizeof saved_frame) == HB_OK,
               "snapshot suspended outer stack")) return 0;
    f->inner_bits = host_captured_callback_case(f->direct, f->inner_backend, 1, f->inner_return);
    phase = outer_phase;
    check(!memcmp(saved_regs, &f->outer->regs.x64, sizeof saved_regs),
          "inner callback preserves all suspended outer GPR/XMM state");
    check(f->outer->pc == saved_pc && f->outer->mxcsr == saved_mxcsr,
          "inner callback preserves suspended outer PC/MXCSR");
    check(hb_memory_read(f->outer->memory, f->outer->regs.x64.rsp,
                          after_frame, sizeof after_frame) == HB_OK &&
          !memcmp(saved_frame, after_frame, sizeof saved_frame),
          "separate inner memory preserves suspended outer call frame");
    /* Return depends on the actual inner C caller result, not fixture expectations. */
    return (uint32_t)f->inner_bits ^ UINT32_C(0x13579bdf);
}

static void nested_callback_boundaries(int direct)
{
    static const uint64_t arguments[5] = {
        UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
        UINT64_C(0x89abcdfe), UINT64_C(0x13579bdf2468ace0),
        UINT64_C(0x8877665544332211)
    };
    static const uint64_t inner_returns[3] = {
        UINT64_C(0xeca86420fdb97531), UINT64_C(0x8000000000000000), UINT64_C(0x80000000)
    };
    static const uint64_t thunk_returns[3] = {
        UINT64_C(0xeeeeeeee), UINT64_C(0x13579bdf), UINT64_C(0x93579bdf)
    };
    static const uint64_t final_returns[3] = {
        UINT64_C(0xeeeeef25), UINT64_C(0x13579c16), UINT64_C(0x93579c16)
    };
    const uint64_t external = UINT64_C(0x720000);
    const uint64_t module = UINT64_C(0x48424e4553540001);
    for (unsigned outer_backend = 0; outer_backend < 2; ++outer_backend)
        for (unsigned inner_backend = 0; inner_backend < 2; ++inner_backend)
            for (unsigned which = 0; which < 3; ++which) {
                char label[128];
                snprintf(label, sizeof label, "nested boundary outer=%s inner=%s %s return=%u",
                         outer_backend ? "JIT" : "interpreter", inner_backend ? "JIT" : "interpreter",
                         direct ? "direct" : "helper", which);
                phase = label;
                unsigned before = failures;
                uint64_t stack = 0;
                hb_context_t *ctx = new_context_mapped(
                    outer_backend ? HB_BACKEND_JIT : HB_BACKEND_INTERP, direct, &stack);
                if (!ctx) return;
                ctx->step_limit = 128;
                ctx->regs.x64.rbx = stack + 0x200;
                ctx->regs.x64.rbp = UINT64_C(0x1122334455667701);
                ctx->regs.x64.rsi = UINT64_C(0x2233445566778802);
                ctx->regs.x64.rdi = UINT64_C(0x3344556677889903);
                ctx->regs.x64.r12 = UINT64_C(0x445566778899aa04);
                ctx->regs.x64.r13 = UINT64_C(0x5566778899aabb05);
                ctx->regs.x64.r14 = UINT64_C(0x66778899aabbcc06);
                ctx->regs.x64.r15 = UINT64_C(0x778899aabbccdd07);
                nested_boundary_fixture_t fixture = {0};
                fixture.outer = ctx; fixture.direct = direct;
                fixture.inner_backend = inner_backend; fixture.inner_return = which;
                hb_ir_func_t *func = NULL;
                hb_ir_builder_t *builder = NULL;
                hb_ir_block_t *continuation = NULL;
                hb_interpreter_t *interp = NULL;
                hb_jit_runtime_t *jit = NULL;
                hb_generated_thunk_t thunk = {0};
                int registered = 0, complete = 0;
                hb_exec_result_t out = {0};
                hb_result_t result;
                /* Entry counter proves resume never replays block1. A fifth
                 * outgoing arg is copied from the outer incoming stack frame.
                 * sub40 preserves Win64 alignment and reserves32 shadow bytes. */
                uint8_t code[] = {
                    0x48,0xff,0x03,                         /* INC qword [RBX] */
                    0x48,0x83,0xec,0x28,                    /* SUB RSP,40 */
                    0x48,0x8b,0x44,0x24,0x50,               /* MOV RAX,[RSP+80] */
                    0x48,0x89,0x44,0x24,0x20,               /* MOV [RSP+32],RAX */
                    0xe8,0,0,0,0,                          /* CALL external */
                    0x48,0x89,0x43,0x08,                    /* MOV [RBX+8],RAX */
                    0x48,0x83,0xc4,0x28,                    /* ADD RSP,40 */
                    0x48,0x83,0xc0,0x37,                    /* ADD RAX,55 */
                    0xc3                                   /* RET */
                };
                enum { CONTINUATION = 22 };
                uint32_t relative = (uint32_t)(external - (CODE + CONTINUATION));
                for (unsigned i = 0; i < 4; ++i) code[18 + i] = (uint8_t)(relative >> (8 * i));
                if (!check(hb_memory_write_u64(ctx->memory, stack + 0x200, 0) == HB_OK,
                           "initialize observable outer entry counter") ||
                    !check(hb_memory_map_private(ctx->memory, CODE, PAGE_BYTES,
                              HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "map outer guest code") ||
                    !check(hb_memory_write(ctx->memory, CODE, code, sizeof code) == HB_OK,
                           "write outer guest code") ||
                    !check(hb_memory_protect(ctx->memory, CODE, PAGE_BYTES,
                              HB_PERM_READ | HB_PERM_EXEC) == HB_OK, "protect outer guest code")) goto nested_done;
                func = hb_ir_func_create(CODE, sizeof code);
                if (!check(func != NULL, "create outer two-block function")) goto nested_done;
                hb_ir_block_t *entry = hb_ir_block_create(0, CODE);
                if (!check(entry != NULL, "create outer CALL block")) goto nested_done;
                hb_ir_cfg_add_block(func->cfg, entry);
                func->cfg->entry = entry;
                continuation = hb_ir_block_create(1, CODE + CONTINUATION);
                if (!check(continuation != NULL, "create outer continuation block")) goto nested_done;
                hb_ir_cfg_add_block(func->cfg, continuation);
                builder = hb_ir_builder_create(func);
                if (!check(builder != NULL, "create outer shared builder")) goto nested_done;
                hb_ir_builder_set_block(builder, entry);
                for (size_t at = 0; at < sizeof code;) {
                    hb_decoded_t decoded = {0};
                    if (at == CONTINUATION) hb_ir_builder_set_block(builder, continuation);
                    if (!check(hb_decode_x64(code + at, sizeof code - at, CODE + at, &decoded) == HB_OK &&
                               decoded.len && decoded.len <= sizeof code - at,
                               "decode each outer instruction") ||
                        !check(hb_lift_x64(&decoded, builder) == HB_OK,
                               "lift each outer instruction")) goto nested_done;
                    at += decoded.len;
                }
                hb_ir_builder_destroy(builder); builder = NULL;
                if (!check(!func->truncated && func->cfg->block_count == 2 &&
                           entry->instr_count && continuation->instr_count,
                           "complete outer CFG has populated entry and continuation")) goto nested_done;
                hb_abi_x64_call_v1_t call = call_with_count(5);
                for (unsigned i = 0; i < 4; ++i)
                    call.slots[i] = value(HB_ABI_X64_GPR_V1, i == 2 ? 4 : 8, arguments[i]);
                hb_abi_x64_value_v1_t tail = value(HB_ABI_X64_GPR_V1, 8, arguments[4]);
                call.stack_args = &tail;
                if (!check(hb_abi_x64_prepare_v1(ctx, CODE, &call) == HB_OK,
                           "prepare outer five-argument call")) goto nested_done;
                uint64_t entry_rsp = ctx->regs.x64.rsp;
                check(entry_rsp == stack + PAGE_BYTES - 56, "outer frame has literal five-argument extent");
                uint64_t nonvolatile[8] = {ctx->regs.x64.rbx,ctx->regs.x64.rbp,ctx->regs.x64.rsi,
                    ctx->regs.x64.rdi,ctx->regs.x64.r12,ctx->regs.x64.r13,ctx->regs.x64.r14,ctx->regs.x64.r15};
                uint64_t xmm[10][2]; memcpy(xmm, &ctx->regs.x64.xmm[6], sizeof xmm);
                uint32_t mxcsr = ctx->mxcsr;
                if (outer_backend) jit = hb_jit_runtime_create(ctx);
                else interp = hb_interpreter_create(ctx);
                if (!check(outer_backend ? jit != NULL : interp != NULL, "create persistent outer executor")) goto nested_done;
                result = outer_backend ? hb_jit_runtime_run(jit, func, &out) :
                                         hb_interpreter_run(interp, func, &out);
                if (!check(result == HB_OK && out.result == HB_OK && !out.faulted && !out.timed_out,
                           "external CALL is a successful boundary, not a completed callback") ||
                    !check(ctx->pc == external && ctx->regs.x64.rip == external,
                           "outer CALL exits at the exact external token") ||
                    !check(ctx->regs.x64.rsp == entry_rsp - 48 && (ctx->regs.x64.rsp & 15) == 8,
                           "CALL reserves shadow space and pushes a real return slot")) goto nested_done;
                uint64_t ret = 0, count = 0;
                if (!check(hb_memory_read_u64(ctx->memory, ctx->regs.x64.rsp, &ret) == HB_OK &&
                           ret == CODE + CONTINUATION, "CALL records exact continuation") ||
                    !check(hb_memory_read_u64(ctx->memory, stack + 0x200, &count) == HB_OK && count == 1,
                           "outer entry executes once before native dispatch")) goto nested_done;
                if (jit) check(has_native_block(jit), "outer entry executes compiled ARM64 code");
                if (!check(hb_thunk_get(ctx, module, HB_THUNK_SIG_BOOL_HANDLE_PTR_U32_PTR_PTR,
                              (void *)nested_boundary_target, &thunk) == HB_OK,
                           "register exact native five-argument prototype")) goto nested_done;
                registered = 1;
                uint64_t suspended_rsp = ctx->regs.x64.rsp;
                nested_boundary_active = &fixture;
                result = hb_thunk_call_generated(ctx, &thunk);
                nested_boundary_active = NULL;
                phase = label;
                if (!check(result == HB_OK && fixture.calls == 1,
                           "registered thunk invokes native reentry target exactly once") ||
                    !check(!memcmp(arguments, fixture.observed, sizeof arguments),
                           "native target observes four registers and fifth stack argument") ||
                    !check(fixture.inner_bits == inner_returns[which], "inner callback returns literal scalar bits") ||
                    !check(ctx->regs.x64.rax == thunk_returns[which], "thunk zero-extends native uint32 result") ||
                    !check(ctx->pc == external && ctx->regs.x64.rsp == suspended_rsp,
                           "thunk leaves guest return-slot ownership to external dispatcher")) goto nested_done;
                /* Test-only external dispatcher: emulate callee RET after native
                 * return. No second prepare/reset, no replay of the outer entry. */
                if (!check(hb_memory_read_u64(ctx->memory, suspended_rsp, &ret) == HB_OK &&
                           ret == CODE + CONTINUATION, "native call preserves guest continuation slot")) goto nested_done;
                ctx->regs.x64.rsp += 8;
                if (!check(hb_context_set_pc(ctx, ret) == HB_OK, "dispatch back to saved guest continuation")) goto nested_done;
                result = outer_backend ? hb_jit_runtime_run(jit, func, &out) :
                                         hb_interpreter_run_from(interp, func, continuation, &out);
                if (!check(result == HB_OK && out.result == HB_OK && !out.faulted && !out.timed_out,
                           "same outer executor resumes successfully") ||
                    !check(ctx->pc == RETURN_PC && ctx->regs.x64.rsp == entry_rsp + 8,
                           "outer RET reaches original caller with restored stack") ||
                    !check(ctx->regs.x64.rax == final_returns[which],
                           "outer continuation consumes native result before returning")) goto nested_done;
                uint64_t stored = 0;
                check(hb_memory_read_u64(ctx->memory, stack + 0x200, &count) == HB_OK && count == 1,
                      "outer continuation never replays entry side effect");
                check(hb_memory_read_u64(ctx->memory, stack + 0x208, &stored) == HB_OK && stored == thunk_returns[which],
                      "outer guest stores actual nested native result");
                uint64_t after_nv[8] = {ctx->regs.x64.rbx,ctx->regs.x64.rbp,ctx->regs.x64.rsi,
                    ctx->regs.x64.rdi,ctx->regs.x64.r12,ctx->regs.x64.r13,ctx->regs.x64.r14,ctx->regs.x64.r15};
                check(!memcmp(nonvolatile, after_nv, sizeof nonvolatile) &&
                      !memcmp(xmm, &ctx->regs.x64.xmm[6], sizeof xmm) && ctx->mxcsr == mxcsr,
                      "outer nonvolatile state survives full guest-native-guest cycle");
                uint64_t guard = 0;
                check(hb_memory_read_u64(ctx->memory, stack + 0x1f8, &guard) == HB_OK &&
                      guard == UINT64_C(0xa5a5a5a5a5a5a5a5), "outer data lower guard");
                check(hb_memory_read_u64(ctx->memory, stack + 0x210, &guard) == HB_OK &&
                      guard == UINT64_C(0xa5a5a5a5a5a5a5a5), "outer data upper guard");
                complete = failures == before;
nested_done:
                nested_boundary_active = NULL;
                phase = label;
                if (registered) check(hb_thunk_release(module) == HB_OK, "release isolated native thunk registration");
                printf("nested-boundary: outer=%s inner=%s mapping=%s return=%u calls=%u complete=%d failures=%u\n",
                       outer_backend ? "JIT" : "interpreter", inner_backend ? "JIT" : "interpreter",
                       direct ? "direct" : "helper", which, fixture.calls, complete, failures - before);
                if (jit) hb_jit_runtime_destroy(jit);
                if (interp) hb_interpreter_destroy(interp);
                if (builder) hb_ir_builder_destroy(builder);
                if (func) hb_ir_func_destroy(func);
                hb_context_destroy(ctx);
            }
    phase = "nested callback boundary cleanup";
}
