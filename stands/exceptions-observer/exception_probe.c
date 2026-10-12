/* Native Windows x64, own-process reference collector. See DESIGN.md.
 * No debugger attachment, executable-memory generation, scanning, or Wine code.
 * Compile with llvm-mingw clang -std=c11 -fms-extensions -O0 -g -municode.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <fcntl.h>
#include <inttypes.h>
#include <io.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#if !defined(_WIN64) || !defined(__x86_64__) || !defined(__clang__)
#error This source requires llvm-mingw clang targeting Windows x86-64.
#endif

#include "asm_fragment.h"

#define NVAR 18u
#define REPEATS 20u
#define GROUP_TIMEOUT_MS 30000u
#define SNAP_CAP 5u
#define JSON_CAP 49152u
#define ARITH_FLAGS UINT64_C(0x8d5)

/* site/sled/escape are link-time labels in this program, never discovered by scanning. */
typedef struct {
    const char *name;
    unsigned family;
    void (*fn)(void);
    const unsigned char *site, *sled, *sled_end, *escape, *end;
    unsigned length;
    int api;
} Variant;
#define V(n, f, a, l, api_)                                                                        \
    {n,                                                                                            \
     f,                                                                                            \
     probe_##a,                                                                                    \
     probe_##a##_site,                                                                             \
     probe_##a##_sled_start,                                                                       \
     probe_##a##_sled_end,                                                                         \
     probe_##a##_escape,                                                                           \
     probe_##a##_end,                                                                              \
     l,                                                                                            \
     api_}
static const Variant variants[NVAR] = {V("int3_cc", 1, int3, 1, 0),
                                       V("int3_cd03", 2, int3_long, 2, 0),
                                       V("int2d_0", 3, int2d_0, 2, 0),
                                       V("int2d_1", 3, int2d_1, 2, 0),
                                       V("int2d_2", 3, int2d_2, 2, 0),
                                       V("int2d_3", 3, int2d_3, 2, 0),
                                       V("int2d_4", 3, int2d_4, 2, 0),
                                       V("int2d_5", 3, int2d_5, 2, 0),
                                       V("int2d_10", 3, int2d_10, 2, 0),
                                       V("icebp", 4, icebp, 1, 0),
                                       V("debugbreak", 5, debugbreak, 0, 1),
                                       V("raise0", 6, raise0, 0, 1),
                                       V("raise1", 7, raise1, 0, 1),
                                       V("single_step", 8, tf_nop, 1, 0),
                                       V("ud2", 9, ud2, 2, 0),
                                       V("int2c", 10, int2c, 2, 0),
                                       V("hlt", 11, hlt, 1, 0),
                                       V("int1_cd01", 12, int1, 2, 0)};
#undef V
static const char *observer_names[] = {"veh", "seh", "uef"};
static const char *seed_names[] = {"clear", "set"};
static const char *policy_names[] = {"advance", "keep_then_advance"};
static const char *gpr_names[] = {"Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
                                  "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15"};

typedef struct {
    EXCEPTION_RECORD er;
    CONTEXT ctx;
    uint64_t proposed, actual;
    int has_proposed, has_actual, tf_cleared;
    const char *action, *reason;
} Snapshot;
static Snapshot snapshots[SNAP_CAP];
static unsigned vi, oi, si, pi, rep, nsnap;
static volatile LONG active, in_handler;
static int unsupported, guard_escape, fatal_current;
static FILE *raw;
static const Variant *cur;
static volatile unsigned char depth_sink;
static FILE *create_new_file(const wchar_t *path) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    int fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(h);
        return NULL;
    }
    FILE *f = _fdopen(fd, "wb");
    if (!f)
        _close(fd);
    return f;
}

/* A bounded writer: no heap allocations and no partial line is intentionally emitted. */
static char jb[JSON_CAP];
static size_t jn;
static int jbad;
static void ja(const char *s) {
    size_t n = strlen(s);
    if (n >= sizeof jb - jn) {
        jbad = 1;
        return;
    }
    memcpy(jb + jn, s, n);
    jn += n;
    jb[jn] = 0;
}
static void js(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    ja("\"");
    while (*p) {
        char b[8];
        unsigned c = *p++;
        if (c == '"')
            ja("\\\"");
        else if (c == '\\')
            ja("\\\\");
        else if (c < 32) {
            snprintf(b, sizeof b, "\\u%04x", c);
            ja(b);
        } else {
            b[0] = (char)c;
            b[1] = 0;
            ja(b);
        }
    }
    ja("\"");
}
static void hx(uint64_t v) {
    char b[32];
    snprintf(b, sizeof b, "\"0x%" PRIx64 "\"", v);
    ja(b);
}
static void off(uint64_t p, uint64_t base) {
    char b[40];
    if (p >= base)
        snprintf(b, sizeof b, "\"0x%" PRIx64 "\"", p - base);
    else
        snprintf(b, sizeof b, "\"-0x%" PRIx64 "\"", base - p);
    ja(b);
}
static void key_name(const char *s) {
    js(s);
    ja(":");
}
static void fieldhex(const char *s, uint64_t v) {
    ja(",");
    key_name(s);
    hx(v);
}
static void fieldstr(const char *s, const char *v) {
    ja(",");
    key_name(s);
    js(v);
}
static void fieldbool(const char *s, int v) {
    ja(",");
    key_name(s);
    ja(v ? "true" : "false");
}
static void bytes(const void *p, size_t n) {
    static const char h[] = "0123456789abcdef";
    const unsigned char *b = p;
    ja("\"0x");
    for (size_t k = 0; k < n; k++) {
        char q[3] = {h[b[k] >> 4], h[b[k] & 15], 0};
        ja(q);
    }
    ja("\"");
}
static void begin(const char *type) {
    jn = 0;
    jbad = 0;
    ja("{\"type\":");
    js(type);
}
static void end_record(void) {
    ja("}\n");
    if (jbad || fwrite(jb, 1, jn, raw) != jn || fflush(raw)) {
        /* Only this owned collector process exits; no outside process is targeted. */
        TerminateProcess(GetCurrentProcess(), 0xe001u);
    }
}
static void emit_key(void) {
    ja(",\"key\":{\"variant\":");
    js(variants[vi].name);
    fieldstr("observer", observer_names[oi]);
    fieldstr("flag_seed", seed_names[si]);
    fieldstr("policy", policy_names[pi]);
    fieldhex("repeat", rep);
    ja("}");
}
static uint64_t getgpr(const CONTEXT *c, unsigned i) {
    switch (i) {
#define G(n, m)                                                                                    \
    case n:                                                                                        \
        return c->m
        G(0, Rax);
        G(1, Rcx);
        G(2, Rdx);
        G(3, Rbx);
        G(4, Rsp);
        G(5, Rbp);
        G(6, Rsi);
        G(7, Rdi);
        G(8, R8);
        G(9, R9);
        G(10, R10);
        G(11, R11);
        G(12, R12);
        G(13, R13);
        G(14, R14);
        G(15, R15);
#undef G
    default:
        return 0;
    }
}
static void emit_context(const CONTEXT *c) {
    ja("{\"ContextFlags\":");
    hx(c->ContextFlags);
#define C(m) fieldhex(#m, c->m)
    C(Rip);
    ja(",\"RipOffset\":");
    off(c->Rip, (uintptr_t)cur->site);
    C(EFlags);
    C(Rsp);
    fieldhex("RspMod16", c->Rsp & 15u);
    C(Dr0);
    C(Dr1);
    C(Dr2);
    C(Dr3);
    C(Dr6);
    C(Dr7);
    C(SegCs);
    C(SegDs);
    C(SegEs);
    C(SegFs);
    C(SegGs);
    C(SegSs);
    C(MxCsr);
    C(P1Home);
    C(P2Home);
    C(P3Home);
    C(P4Home);
    C(P5Home);
    C(P6Home);
    C(DebugControl);
    C(LastBranchToRip);
    C(LastBranchFromRip);
    C(LastExceptionToRip);
    C(LastExceptionFromRip);
#undef C
    ja(",\"gpr\":{");
    for (unsigned k = 0; k < 16; k++) {
        if (k)
            ja(",");
        key_name(gpr_names[k]);
        hx(getgpr(c, k));
    }
    ja("}");
    ja(",\"xmm\":{");
    const M128A *x = c->FltSave.XmmRegisters;
    for (unsigned k = 0; k < 16; k++) {
        char name[16];
        snprintf(name, sizeof name, "Xmm%u", k);
        if (k)
            ja(",");
        key_name(name);
        bytes(&x[k], 16);
    }
    ja("}}");
}
static void emit_observations(void) {
    for (unsigned k = 0; k < nsnap; k++) {
        const Snapshot *s = &snapshots[k];
        begin("observation");
        emit_key();
        fieldhex("delivery_index", k + 1u);
        ja(",\"exception\":{\"ExceptionCode\":");
        hx(s->er.ExceptionCode);
        fieldhex("ExceptionFlags", s->er.ExceptionFlags);
        fieldhex("ExceptionAddress", (uintptr_t)s->er.ExceptionAddress);
        ja(",\"ExceptionAddressOffset\":");
        off((uintptr_t)s->er.ExceptionAddress, (uintptr_t)cur->site);
        fieldhex("NumberParameters", s->er.NumberParameters);
        ja(",\"ExceptionInformation\":[");
        for (unsigned z = 0; z < 4; z++) {
            if (z)
                ja(",");
            hx(s->er.ExceptionInformation[z]);
        }
        ja("]}");
        ja(",\"context\":");
        emit_context(&s->ctx);
        ja(",\"context_bytes_hex\":");
        bytes(&s->ctx, sizeof s->ctx);
        fieldhex("context_size", sizeof s->ctx);
        fieldstr("context_field_semantics", "raw_bytes_validity_depends_on_returned_ContextFlags");
        fieldhex("exception_information_valid_slots",
                 s->er.NumberParameters < 4u ? s->er.NumberParameters : 4u);
        ja(",\"gpr_expected\":{");
        for (unsigned z = 0; z < 16; z++) {
            if (z)
                ja(",");
            key_name(gpr_names[z]);
            hx(probe_seed_gpr[z]);
        }
        ja("}");
        ja(",\"gpr_differences\":[");
        int comma = 0;
        for (unsigned z = 0; z < 16; z++)
            if (getgpr(&s->ctx, z) != probe_seed_gpr[z]) {
                if (comma++)
                    ja(",");
                js(gpr_names[z]);
            }
        ja("]");
        ja(",\"xmm_differences\":[");
        comma = 0;
        const M128A *x = s->ctx.FltSave.XmmRegisters;
        for (unsigned z = 0; z < 16; z++)
            if (memcmp(&x[z], probe_xmm_seed[z], 16)) {
                char name[16];
                snprintf(name, sizeof name, "Xmm%u", z);
                if (comma++)
                    ja(",");
                js(name);
            }
        ja("]");
        fieldstr("register_interpretation",
                 cur->api ? "api_pre_call_differences_not_preservation_failures"
                          : "instruction_entry_seed_comparison");
        ja(",\"xstate\":{\"present\":");
        ja((s->ctx.ContextFlags & 0x40u) ? "true" : "false");
        ja(",\"total_length\":null,\"length_status\":\"unavailable_documented_size_for_borrowed_"
           "context\"}");
        ja(",\"continuation\":{\"requested_policy\":");
        js(policy_names[pi]);
        fieldstr("action", s->action);
        ja(",\"proposed_rip\":");
        if (s->has_proposed)
            hx(s->proposed);
        else
            ja("null");
        ja(",\"actual_rip\":");
        if (s->has_actual)
            hx(s->actual);
        else
            ja("null");
        fieldbool("tf_cleared", s->tf_cleared);
        fieldstr("reason", s->reason);
        ja("}");
        fieldhex("instruction_site", (uintptr_t)cur->site);
        fieldhex("sled_start", (uintptr_t)cur->sled);
        ja(",\"instruction_length\":");
        if (cur->api)
            ja("null");
        else
            hx(cur->length);
        fieldstr("offset_reference", cur->api ? "owned_api_call_site" : "owned_instruction_start");
        end_record();
    }
}
static void emit_result(const char *status, const char *reason, int known_delivery, int completed) {
    begin("run_result");
    emit_key();
    fieldstr("status", status);
    ja(",\"exception_delivered\":");
    if (known_delivery)
        ja(nsnap ? "true" : "false");
    else
        ja("null");
    fieldhex("observation_count", nsnap);
    fieldhex("stack_depth", rep);
    ja(",\"continuation_entry_offset\":");
    if (completed && !probe_escape_taken && probe_sled_entry <= 8u)
        hx(probe_sled_entry);
    else
        ja("null");
    ja(",\"continuation_site_offset\":");
    if (completed && !probe_escape_taken && probe_sled_entry <= 8u)
        hx((uintptr_t)cur->sled - (uintptr_t)cur->site + probe_sled_entry);
    else
        ja("null");
    ja(",\"post_rax\":");
    if (completed)
        hx(probe_post_gpr[0]);
    else
        ja("null");
    fieldbool("probe_returned", completed);
    fieldbool("safety_escape", guard_escape || (completed && probe_escape_taken));
    fieldstr("reason", reason);
    if (completed) {
        fieldhex("post_rflags", probe_post_rflags);
        fieldhex("post_rsp", probe_post_gpr[4]);
        fieldhex("pre_rsp", probe_pre_rsp);
    }
    end_record();
}
static void fatal_from_handler(const char *reason) {
    fatal_current = 1;
    active = 0;
    emit_observations();
    emit_result("runtime_aborted", reason, 1, 0);
    TerminateProcess(GetCurrentProcess(), 0xe002u);
    for (;;) {
    } /* TerminateProcess on this process should not return successfully. */
}
static int owned_destination(uint64_t p) {
    if (p == (uintptr_t)cur->site)
        return 1;
    return p >= (uintptr_t)cur->sled && p <= (uintptr_t)cur->sled_end;
}
static LONG observe(EXCEPTION_POINTERS *ep) {
    if (!active)
        return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedExchange(&in_handler, 1)) {
        /* Do not recurse into formatting or touch the borrowed context again. */
        TerminateProcess(GetCurrentProcess(), 0xe003u);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (nsnap >= SNAP_CAP) {
        TerminateProcess(GetCurrentProcess(), 0xe004u);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    Snapshot *s = &snapshots[nsnap++];
    memcpy(&s->er, ep->ExceptionRecord, sizeof s->er);
    memcpy(&s->ctx, ep->ContextRecord, sizeof s->ctx);
    s->action = "keep";
    s->reason = "requested_policy";
    s->has_proposed = 1;
    s->has_actual = 1;
    s->proposed = s->actual = s->ctx.Rip;
    s->tf_cleared = (s->ctx.EFlags & 0x100u) != 0;
    /* Sampling precedes the TF safety mutation; never trace handler/cleanup. */
    ep->ContextRecord->EFlags &= ~0x100u;
    if (s->er.ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
        s->action = "terminate";
        s->reason = "noncontinuable_exception";
        s->has_actual = 0;
        fatal_from_handler(s->reason);
    }
    if (cur->api) {
        if (nsnap >= 4u) {
            s->action = "terminate";
            s->reason = "api_repeat_guard_no_documented_instruction_length";
            s->has_proposed = 0;
            s->has_actual = 0;
            fatal_from_handler(s->reason);
        }
        if (pi == 0u) {
            unsupported = 1;
            s->action = "keep_fallback";
            s->reason = "api_instruction_length_unavailable";
            s->has_proposed = 0;
        }
        InterlockedExchange(&in_handler, 0);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (pi == 0u || nsnap >= 4u) {
        s->proposed = s->ctx.Rip + cur->length;
        s->action = "advance";
    }
    if (nsnap >= 5u) {
        guard_escape = 1;
        s->action = "escape";
        s->reason = "total_delivery_guard";
    } else if (!owned_destination(s->proposed)) {
        unsupported = 1;
        guard_escape = 1;
        s->action = "escape";
        s->reason = "requested_destination_not_owned_instruction_boundary";
    }
    if (s->action[0] == 'e') {
        /* Only a live owned assembly frame may use its own cleanup label. */
        if (s->ctx.Rbp != probe_pre_rbp || s->ctx.Rip < (uintptr_t)cur->site ||
            s->ctx.Rip >= (uintptr_t)cur->end) {
            s->action = "terminate";
            s->reason = "owned_cleanup_frame_not_verified";
            s->has_actual = 0;
            fatal_from_handler(s->reason);
        }
        s->actual = (uintptr_t)cur->escape;
    } else
        s->actual = s->proposed;
    ep->ContextRecord->Rip = s->actual;
    InterlockedExchange(&in_handler, 0);
    return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep) {
    return observe(ep);
}
static LONG CALLBACK uef_handler(EXCEPTION_POINTERS *ep) {
    return observe(ep);
}
static LONG seh_filter(EXCEPTION_POINTERS *ep) {
    return observe(ep);
}

/* __try is deliberately in a DIFFERENT frame from every faulting instruction. */
__declspec(noinline) static void invoke(void) {
    if (oi == 1u) {
        __try {
            cur->fn();
        } __except (seh_filter(GetExceptionInformation())) {
            guard_escape = 1;
        }
    } else
        cur->fn();
}
__declspec(noinline) static void at_depth(unsigned depth) {
    volatile unsigned char owned[256];
    for (unsigned z = 0; z < sizeof owned; z++)
        owned[z] = (unsigned char)(0xa5u ^ (z & 0xffu));
    if (depth)
        at_depth(depth - 1u);
    else
        invoke();
    depth_sink ^= owned[depth % sizeof owned]; /* no tail-call elimination */
}
static int child(const wchar_t *path) {
    raw = create_new_file(path);
    if (!raw)
        return 3;
    setvbuf(raw, NULL, _IONBF, 0);
    cur = &variants[vi];
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    PVOID veh = NULL;
    if (oi == 0u) {
        veh = AddVectoredExceptionHandler(1, veh_handler);
        if (!veh) {
            fclose(raw);
            return 4;
        }
    } else if (oi == 2u)
        SetUnhandledExceptionFilter(uef_handler);
    for (rep = 0; rep < REPEATS; rep++) {
        nsnap = 0;
        unsupported = guard_escape = fatal_current = 0;
        in_handler = 0;
        memset(snapshots, 0xa5, sizeof snapshots);
        requested_flags = si ? ARITH_FLAGS : 0;
        begin("run_start");
        emit_key();
        fieldhex("stack_depth", rep);
        fieldhex("process_id", GetCurrentProcessId());
        fieldhex("arithmetic_flags_mask", ARITH_FLAGS);
        fieldhex("requested_arithmetic_flags", requested_flags);
        fieldhex("instruction_site", (uintptr_t)cur->site);
        fieldhex("sled_start", (uintptr_t)cur->sled);
        fieldhex("family", cur->family);
        fieldstr("stack_pattern", "primed_owned_window_120_bytes_0xa5_plus_8_byte_flags_scratch");
        end_record();
        active = 1;
        at_depth(rep);
        active = 0;
        emit_observations();
        if (!probe_completed)
            emit_result("runtime_aborted", "owned_probe_did_not_complete", 1, 0);
        else if (unsupported)
            emit_result("requested_policy_unsupported", "safety_action_is_separately_logged", 1, 1);
        else if (guard_escape)
            emit_result("guard_escape", "total_delivery_guard", 1, 1);
        else
            emit_result("completed", "", 1, 1);
    }
    if (veh)
        RemoveVectoredExceptionHandler(veh);
    if (oi == 2u)
        SetUnhandledExceptionFilter(NULL);
    fclose(raw);
    raw = NULL;
    return 0;
}

/* The only target is the thread handle returned by this program's CreateThread. */
static volatile LONG thread_ready, thread_stop;
static DWORD WINAPI context_thread(LPVOID unused) {
    (void)unused;
    InterlockedExchange(&thread_ready, 1);
    while (!InterlockedCompareExchange(&thread_stop, 0, 0))
        Sleep(1);
    return 0;
}
static void emit_thread_context(const char *target, const char *request, const char *phase,
                                const char *operation, const CONTEXT *c, DWORD requested, BOOL ok,
                                DWORD error, const char *validity, const char *status) {
    begin("thread_context");
    fieldstr("target", target);
    fieldstr("request", request);
    fieldstr("phase", phase);
    fieldstr("operation", operation);
    fieldstr("status", status);
    fieldbool("success", ok);
    fieldhex("last_error", error);
    fieldhex("requested_flags", requested);
    fieldstr("validity", validity);
    fieldstr("debug_alias_status", "Dr4_Dr5_not_present_in_CONTEXT");
    ja(",\"context\":{\"ContextFlags\":");
    hx(c->ContextFlags);
#define D(m) fieldhex(#m, c->m)
    D(Dr0);
    D(Dr1);
    D(Dr2);
    D(Dr3);
    ja(",\"Dr4\":null,\"Dr5\":null");
    D(Dr6);
    D(Dr7);
#undef D
    ja("}");
    ja(",\"context_bytes_hex\":");
    bytes(c, sizeof *c);
    fieldhex("buffer_pattern_byte", 0xa5);
    end_record();
}
static BOOL read_thread(HANDLE h, const char *target, const char *request, const char *phase,
                        DWORD flags, int available, DWORD blocker, CONTEXT *out) {
    CONTEXT c;
    memset(&c, 0xa5, sizeof c);
    c.ContextFlags = flags;
    BOOL ok = FALSE;
    DWORD err = blocker;
    if (available) {
        SetLastError(ERROR_SUCCESS);
        ok = GetThreadContext(h, &c);
        err = GetLastError();
    }
    emit_thread_context(target, request, phase, "get", &c, flags, ok, err,
                        !strcmp(target, "current")
                            ? "invalid_current_thread_context"
                            : (ok ? "requested_fields_only" : "call_failed_no_valid_context"),
                        available ? "observed" : "skipped");
    if (out)
        memcpy(out, &c, sizeof c);
    return ok;
}
static int thread_block(void) {
    read_thread(GetCurrentThread(), "current", "debug", "before", CONTEXT_DEBUG_REGISTERS, 1, 0,
                NULL);
    read_thread(GetCurrentThread(), "current", "all", "before", CONTEXT_ALL, 1, 0, NULL);
    thread_ready = thread_stop = 0;
    HANDLE t = CreateThread(NULL, 0, context_thread, NULL, 0, NULL);
    DWORD createerr = t ? 0 : GetLastError(), blocker = createerr;
    int suspended = 0, ready = 0;
    DWORD suspenderr = 0, resumeerr = 0, wait = WAIT_FAILED;
    if (t) {
        ULONGLONG until = GetTickCount64() + 5000u;
        while (!InterlockedCompareExchange(&thread_ready, 0, 0) && GetTickCount64() < until)
            Sleep(1);
        ready = InterlockedCompareExchange(&thread_ready, 0, 0) != 0;
        if (ready) {
            DWORD n = SuspendThread(t);
            if (n == (DWORD)-1)
                blocker = suspenderr = GetLastError();
            else
                suspended = 1;
        } else
            blocker = WAIT_TIMEOUT;
    }
    CONTEXT before;
    BOOL got = read_thread(t, "suspended", "debug", "before", CONTEXT_DEBUG_REGISTERS, suspended,
                           blocker, &before);
    got = got && ((before.ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS);
    read_thread(t, "suspended", "all", "before", CONTEXT_ALL, suspended, blocker, NULL);
    CONTEXT setctx;
    memcpy(&setctx, &before, sizeof setctx);
    setctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    setctx.Dr7 = 0;
    BOOL setok = FALSE;
    DWORD seterr = blocker;
    if (suspended && got) {
        SetLastError(ERROR_SUCCESS);
        setok = SetThreadContext(t, &setctx);
        seterr = GetLastError();
    } else if (suspended)
        seterr = ERROR_INVALID_DATA;
    emit_thread_context("suspended", "debug", "set_dr7_zero", "set", &setctx,
                        CONTEXT_DEBUG_REGISTERS, setok, seterr,
                        got ? "input_debug_snapshot_with_only_Dr7_zeroed"
                            : "not_attempted_no_valid_debug_snapshot",
                        suspended && got ? "observed" : "skipped");
    read_thread(t, "suspended", "debug", "after_set", CONTEXT_DEBUG_REGISTERS, suspended, blocker,
                NULL);
    read_thread(t, "suspended", "all", "after_set", CONTEXT_ALL, suspended, blocker, NULL);
    int resumed = !suspended;
    if (t) {
        InterlockedExchange(&thread_stop, 1);
        if (suspended) {
            DWORD r = ResumeThread(t);
            if (r == (DWORD)-1)
                resumeerr = GetLastError();
            else
                resumed = 1;
        }
        if (resumed)
            wait = WaitForSingleObject(t, 5000u);
    }
    begin("thread_cleanup");
    fieldbool("created", t != NULL);
    fieldbool("ready", ready);
    fieldbool("suspended", suspended);
    fieldbool("resume_success", resumed);
    fieldbool("thread_signaled", wait == WAIT_OBJECT_0);
    fieldhex("create_error", createerr);
    fieldhex("suspend_error", suspenderr);
    fieldhex("resume_error", resumeerr);
    fieldhex("wait_status", wait);
    end_record();
    if (t)
        CloseHandle(t);
    /* Returning from this isolated process also ends an unreaped worker safely. */
    return (t && ready && suspended && resumed && wait == WAIT_OBJECT_0) ? 0 : 2;
}

static void manifest(void) {
    begin("manifest");
    fieldhex("schema_version", 1);
    fieldhex("planned_runs", 4320);
    fieldhex("families", 12);
    fieldhex("variants", NVAR);
    fieldhex("observers", 3);
    fieldhex("flag_seeds", 2);
    fieldhex("policies", 2);
    fieldhex("repeats", REPEATS);
    fieldhex("groups", 216);
    fieldhex("group_timeout_ms", GROUP_TIMEOUT_MS);
    fieldhex("context_size", sizeof(CONTEXT));
    fieldstr("architecture", "x86_64");
    fieldstr("compiler", __clang_version__);
    fieldstr("runtime_claim", "observations_only_no_expected_Windows_values");
    fieldstr("raw_numbers", "hexadecimal_strings");
    fieldstr("xstate_total_length", "unavailable_for_borrowed_handler_context");
    SYSTEM_INFO inf;
    GetNativeSystemInfo(&inf);
    fieldhex("native_processor_architecture", inf.wProcessorArchitecture);
    end_record();
}
static unsigned merge_child(const wchar_t *path, int *dropped, unsigned *pending_observations) {
    FILE *in = _wfopen(path, L"rb");
    if (!in)
        return 0;
    static char line[JSON_CAP];
    unsigned results = 0;
    while (fgets(line, sizeof line, in)) {
        size_t n = strlen(line);
        if (!n || line[n - 1] != '\n') {
            *dropped = 1;
            while (n && line[n - 1] != '\n' && fgets(line, sizeof line, in))
                n = strlen(line);
            continue;
        }
        if (!strncmp(line, "{\"type\":\"run_result\"", 20)) {
            results++;
            if (pending_observations)
                *pending_observations = 0;
        } else if (pending_observations && !strncmp(line, "{\"type\":\"observation\"", 21))
            (*pending_observations)++;
        if (fwrite(line, 1, n, raw) != n) {
            fclose(in);
            return results;
        }
    }
    fclose(in);
    fflush(raw);
    return results;
}
typedef struct {
    int created, assigned, resumed, reaped, timeout;
    DWORD create_error, assign_error, resume_error, wait_status, wait_error, cleanup_wait_status,
        cleanup_wait_error, terminate_error, child_exit_code, exit_query_error, child_process_id,
        child_thread_id;
} Outcome;
static Outcome run_owned_child(const wchar_t *self, wchar_t *command, HANDLE job) {
    Outcome o;
    memset(&o, 0, sizeof o);
    o.wait_status = WAIT_FAILED;
    o.cleanup_wait_status = WAIT_FAILED;
    o.child_exit_code = 0xffffffffu;
    STARTUPINFOW start;
    PROCESS_INFORMATION proc;
    memset(&start, 0, sizeof start);
    memset(&proc, 0, sizeof proc);
    start.cb = sizeof start;
    o.created = CreateProcessW(self, command, NULL, NULL, FALSE,
                               CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL, &start, &proc) != 0;
    if (!o.created) {
        o.create_error = GetLastError();
        return o;
    }
    o.child_process_id = proc.dwProcessId;
    o.child_thread_id = proc.dwThreadId;
    o.assigned = AssignProcessToJobObject(job, proc.hProcess) != 0;
    if (!o.assigned)
        o.assign_error = GetLastError();
    if (o.assigned) {
        DWORD r = ResumeThread(proc.hThread);
        if (r == (DWORD)-1)
            o.resume_error = GetLastError();
        else
            o.resumed = 1;
    }
    if (o.resumed) {
        o.wait_status = WaitForSingleObject(proc.hProcess, GROUP_TIMEOUT_MS);
        if (o.wait_status == WAIT_FAILED)
            o.wait_error = GetLastError();
        o.timeout = o.wait_status == WAIT_TIMEOUT;
    }
    if (o.wait_status != WAIT_OBJECT_0) {
        if (!TerminateProcess(proc.hProcess, 0xe005u))
            o.terminate_error = GetLastError();
        o.cleanup_wait_status = WaitForSingleObject(proc.hProcess, 5000u);
        if (o.cleanup_wait_status == WAIT_FAILED)
            o.cleanup_wait_error = GetLastError();
    }
    o.reaped = o.wait_status == WAIT_OBJECT_0 || o.cleanup_wait_status == WAIT_OBJECT_0;
    if (!GetExitCodeProcess(proc.hProcess, &o.child_exit_code))
        o.exit_query_error = GetLastError();
    CloseHandle(proc.hThread);
    CloseHandle(proc.hProcess);
    return o;
}
static void outcome_fields(const Outcome *o) {
    fieldbool("created", o->created);
    fieldbool("assigned", o->assigned);
    fieldbool("resumed", o->resumed);
    fieldbool("reaped", o->reaped);
    fieldbool("timeout", o->timeout);
#define O(m) fieldhex(#m, o->m)
    O(create_error);
    O(assign_error);
    O(resume_error);
    O(wait_status);
    O(wait_error);
    O(cleanup_wait_status);
    O(cleanup_wait_error);
    O(terminate_error);
    O(child_exit_code);
    O(exit_query_error);
    O(child_process_id);
    O(child_thread_id);
#undef O
}
static int parent(const wchar_t *dir) {
    wchar_t output[32768], self[32768], childpath[32768], command[65536];
    DWORD selflen = GetModuleFileNameW(NULL, self, 32768);
    if (!selflen || selflen >= 32768)
        return 10;
    if (swprintf(output, 32768, L"%ls\\raw.jsonl", dir) < 0)
        return 11;
    if (!CreateDirectoryW(dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        return 13;
    raw = create_new_file(output);
    if (!raw) {
        fwprintf(stderr, L"Cannot create fresh %ls\n", output);
        return 14;
    }
    manifest();
    HANDLE job = CreateJobObjectW(NULL, NULL);
    DWORD joberr = job ? 0 : GetLastError();
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof limits);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job &&
        !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof limits)) {
        joberr = GetLastError();
        CloseHandle(job);
        job = NULL;
    }
    int failures = 0;
    const char *stop_reason = job ? NULL : "owned_kill_on_close_job_unavailable";
    Outcome tc;
    memset(&tc, 0, sizeof tc);
    tc.create_error = joberr;
    tc.child_exit_code = 0xffffffffu;
    tc.wait_status = WAIT_FAILED;
    tc.cleanup_wait_status = WAIT_FAILED;
    if (swprintf(childpath, 32768, L"%ls\\thread-context.jsonl", dir) < 0) {
        if (job)
            CloseHandle(job);
        fclose(raw);
        return 15;
    }
    if (job && GetFileAttributesW(childpath) == INVALID_FILE_ATTRIBUTES) {
        if (swprintf(command, 65536, L"\"%ls\" --thread-block \"%ls\"", self, childpath) < 0) {
            CloseHandle(job);
            fclose(raw);
            return 16;
        }
        tc = run_owned_child(self, command, job);
    } else if (job)
        stop_reason = "preexisting_context_output_not_overwritten";
    int dropped = 0;
    if (tc.created && tc.resumed && tc.reaped && tc.child_exit_code != 3u)
        merge_child(childpath, &dropped, NULL);
    begin("thread_block_result");
    outcome_fields(&tc);
    fieldbool("partial_record_dropped", dropped);
    end_record();
    if (!tc.created || !tc.assigned || !tc.resumed || !tc.reaped || tc.child_exit_code || dropped)
        failures = 1;
    if (!tc.created && !stop_reason)
        stop_reason = "owned_child_creation_failed_sweep_stopped";
    if (tc.child_exit_code == 3u)
        stop_reason = "owned_context_output_creation_failed_sweep_stopped";
    if (tc.created && !tc.reaped)
        stop_reason = "owned_child_not_reaped_sweep_stopped";
    if (tc.created && (!tc.assigned || !tc.resumed))
        stop_reason = "owned_child_setup_failed_sweep_stopped";
    if (stop_reason && job) {
        CloseHandle(job);
        job = NULL;
    }
    unsigned group = 0;
    for (vi = 0; vi < NVAR; vi++)
        for (oi = 0; oi < 3; oi++)
            for (si = 0; si < 2; si++)
                for (pi = 0; pi < 2; pi++, group++) {
                    cur = &variants[vi];
                    Outcome o;
                    memset(&o, 0, sizeof o);
                    o.wait_status = WAIT_FAILED;
                    o.cleanup_wait_status = WAIT_FAILED;
                    o.child_exit_code = 0xffffffffu;
                    if (swprintf(childpath, 32768, L"%ls\\group-%03u.jsonl", dir, group) < 0) {
                        if (job)
                            CloseHandle(job);
                        fclose(raw);
                        return 15;
                    }
                    if (!stop_reason && GetFileAttributesW(childpath) != INVALID_FILE_ATTRIBUTES)
                        stop_reason = "preexisting_group_output_not_overwritten";
                    if (!stop_reason) {
                        if (swprintf(command, 65536, L"\"%ls\" --child %u %u %u %u \"%ls\"", self,
                                     vi, oi, si, pi, childpath) < 0) {
                            CloseHandle(job);
                            fclose(raw);
                            return 16;
                        }
                        o = run_owned_child(self, command, job);
                    }
                    dropped = 0;
                    unsigned pending_observations = 0;
                    unsigned count = (o.created && o.resumed && o.reaped && o.child_exit_code != 3u)
                                         ? merge_child(childpath, &dropped, &pending_observations)
                                         : 0;
                    if (count > REPEATS)
                        count = REPEATS;
                    for (rep = count; rep < REPEATS; rep++) {
                        nsnap = rep == count ? pending_observations : 0;
                        guard_escape = 0;
                        emit_result("runtime_aborted",
                                    stop_reason
                                        ? stop_reason
                                        : (o.created
                                               ? (o.timeout ? "own_child_timeout"
                                                            : "own_child_exited_before_repeat")
                                               : "CreateProcess_failed"),
                                    nsnap != 0, 0);
                    }
                    begin("group_result");
                    ja(",\"group\":{\"variant\":");
                    js(cur->name);
                    fieldstr("observer", observer_names[oi]);
                    fieldstr("flag_seed", seed_names[si]);
                    fieldstr("policy", policy_names[pi]);
                    ja("}");
                    fieldhex("group_index", group);
                    outcome_fields(&o);
                    fieldbool("partial_record_dropped", dropped);
                    fieldhex("child_terminal_records", count);
                    end_record();
                    if (!o.created || !o.assigned || !o.resumed || !o.reaped || o.child_exit_code ||
                        count != REPEATS || dropped)
                        failures = 1;
                    if (!o.created && !stop_reason)
                        stop_reason = "owned_child_creation_failed_sweep_stopped";
                    if (o.child_exit_code == 3u)
                        stop_reason = "owned_group_output_creation_failed_sweep_stopped";
                    if (o.created && !o.reaped)
                        stop_reason = "owned_child_not_reaped_sweep_stopped";
                    if (o.created && (!o.assigned || !o.resumed))
                        stop_reason = "owned_child_setup_failed_sweep_stopped";
                    if (stop_reason && job) {
                        CloseHandle(job);
                        job = NULL;
                    }
                }
    if (job)
        CloseHandle(job);
    fclose(raw);
    raw = NULL;
    return failures ? 2 : 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && !wcscmp(argv[1], L"--thread-block")) {
        raw = create_new_file(argv[2]);
        if (!raw)
            return 3;
        setvbuf(raw, NULL, _IONBF, 0);
        int result = thread_block();
        fclose(raw);
        raw = NULL;
        return result;
    }
    if (argc == 7 && !wcscmp(argv[1], L"--child")) {
        vi = (unsigned)wcstoul(argv[2], NULL, 10);
        oi = (unsigned)wcstoul(argv[3], NULL, 10);
        si = (unsigned)wcstoul(argv[4], NULL, 10);
        pi = (unsigned)wcstoul(argv[5], NULL, 10);
        if (vi >= NVAR || oi >= 3 || si >= 2 || pi >= 2)
            return 20;
        return child(argv[6]);
    }
    if (argc == 3 && !wcscmp(argv[1], L"--output"))
        return parent(argv[2]);
    fwprintf(stderr, L"Usage: exception_probe.exe --output NEW_RESULTS_DIRECTORY\n");
    return 21;
}
