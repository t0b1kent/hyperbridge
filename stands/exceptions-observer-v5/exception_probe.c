/* Native Windows x64, own-process reference collector. See DESIGN.md.
 * No debugger attachment, executable-memory generation, scanning, or Wine code.
 * Compile with llvm-mingw clang -std=c11 -fms-extensions -O1 -g -municode.
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

_Static_assert(sizeof(CONTEXT) == 1232u,
               "Expected public Windows AMD64 CONTEXT layout");
_Static_assert(sizeof(EXCEPTION_RECORD) == 152u,
               "Expected public Windows AMD64 EXCEPTION_RECORD layout");
_Static_assert(EXCEPTION_MAXIMUM_PARAMETERS == 15u,
               "Expected 15 exception parameter slots");
#include "asm_fragment.h"

#define NVAR 20u
#define REPEATS 20u
#define GROUP_TIMEOUT_MS 30000u
#define SNAP_CAP 32u
#define JSON_CAP 49152u
#define ARITH_FLAGS UINT64_C(0x8d5)

/* site/sled/escape are link-time labels in this program, never discovered by
 * scanning. */
typedef struct {
  const char *name;
  unsigned family;
  void (*fn)(void);
  const unsigned char *site, *sled, *sled_end, *escape, *end;
  unsigned length;
  int api;
} Variant;
#define V(n, f, a, l, api_)                                                    \
  {n,                                                                          \
   f,                                                                          \
   probe_##a,                                                                  \
   probe_##a##_site,                                                           \
   probe_##a##_sled_start,                                                     \
   probe_##a##_sled_end,                                                       \
   probe_##a##_escape,                                                         \
   probe_##a##_end,                                                            \
   l,                                                                          \
   api_}
static const Variant variants[NVAR] = {
    V("int2d_stack", 1, int2d, 2, 0),
    V("int2d_heap", 1, int2d, 2, 0),
    V("int2d_function", 1, int2d, 2, 0),
    V("int2d_static", 1, int2d, 2, 0),
    V("int2d_6", 1, int2d, 2, 0),
    V("int2d_7", 1, int2d, 2, 0),
    V("int2d_8", 1, int2d, 2, 0),
    V("int2d_f", 1, int2d, 2, 0),
    V("int2d_11", 1, int2d, 2, 0),
    V("int2d_100", 1, int2d, 2, 0),
    V("int2d_ffffffff", 1, int2d, 2, 0),
    V("int2d_8000000000000000", 1, int2d, 2, 0),
    V("ctx_int2d_0", 2, int2d, 2, 0),
    V("ctx_int2d_stack", 2, int2d, 2, 0),
    V("ctx_int3_cc", 2, int3, 1, 0),
    V("debugbreak", 3, debugbreak, 0, 1),
    V("output_a", 3, output_a, 0, 1),
    V("output_w", 3, output_w, 0, 1),
    V("is_debugger_present", 3, is_debugger_present, 0, 1),
    V("check_remote_debugger_present", 3, check_remote_debugger_present, 0, 1)};
#undef V
static const char *observer_names[] = {"veh", "seh", "uef", "veh_seh"};
static const char *seed_names[] = {"clear", "set"};
static const char *policy_names[] = {
    "advance",   "keep_then_advance", "rip_plus_length", "alternate",
    "enable_tf", "veh_search_seh",    "vch_order",       "api_keep"};
static int applicable(unsigned v, unsigned o, unsigned p) {
  if (v < 12u)
    return o < 3u && p < 2u;
  if (v < 15u)
    return (o < 3u && (p == 2u || p == 3u || p == 4u || p == 6u)) ||
           (o == 3u && p == 5u);
  return o == 0u && p == 7u;
}
const char own_debug_a[] = "exception-observer-v5: own ANSI test";
const wchar_t own_debug_w[] = L"exception-observer-v5: own Unicode test \u03a9";
volatile long own_remote_present;
static volatile uint64_t own_static_value = UINT64_C(0x51314f574e535441);
static uint64_t own_stack_address, own_heap_address;
static DWORD api_last_error;
static int api_error_valid;
static unsigned deliveries, vch_count, second_traps;
static int synthesized_by_parent;
static unsigned parent_observation_count;
static int chain_pending, action_applied, tf_armed, alternate_taken;
static const char *gpr_names[] = {"Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp",
                                  "Rsi", "Rdi", "R8",  "R9",  "R10", "R11",
                                  "R12", "R13", "R14", "R15"};

typedef struct {
  EXCEPTION_RECORD er;
  CONTEXT ctx;
  uint64_t proposed, actual;
  int has_proposed, has_actual, tf_cleared;
  const char *action, *reason, *observer, *stage;
  unsigned delivery;
  int tf_set;
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

/* A bounded writer: no heap allocations and no partial line is intentionally
 * emitted. */
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
  if (jbad || ferror(raw) || fwrite(jb, 1, jn, raw) != jn || fflush(raw) ||
      ferror(raw)) {
    /* Only this owned collector process exits; no outside process is targeted.
     */
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
#define G(n, m)                                                                \
  case n:                                                                      \
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
static int in_range(uint64_t p, const void *base, size_t size) {
  return p >= (uintptr_t)base && p - (uintptr_t)base < size;
}
static const char *location(uint64_t p) {
  if (p >= (uintptr_t)cur->fn && p < (uintptr_t)cur->end)
    return "owned_probe";
  if (p >= (uintptr_t)probe_alternate && p < (uintptr_t)probe_alternate_end)
    return "owned_alternate";
  HMODULE m = NULL;
  if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         (LPCWSTR)(uintptr_t)p, &m) &&
      (m == GetModuleHandleW(L"ntdll.dll") ||
       m == GetModuleHandleW(L"kernelbase.dll") ||
       m == GetModuleHandleW(L"kernel32.dll")))
    return "inside_system_library";
  return "unclassified_address";
}
static void relative_address(uint64_t p) {
  const char *kind = location(p);
  if (!strcmp(kind, "owned_probe"))
    off(p, (uintptr_t)cur->site);
  else if (!strcmp(kind, "owned_alternate"))
    off(p, (uintptr_t)probe_alternate_sled_start);
  else
    ja("null");
}
static void parameter_reference(uint64_t p) {
  const char *symbol = NULL;
  uint64_t base = 0;
  if (in_range(p, own_debug_a, sizeof own_debug_a)) {
    symbol = "own_debug_a";
    base = (uintptr_t)own_debug_a;
  } else if (in_range(p, own_debug_w, sizeof own_debug_w)) {
    symbol = "own_debug_w";
    base = (uintptr_t)own_debug_w;
  } else if (p == own_stack_address) {
    symbol = "own_stack_variable";
    base = p;
  } else if (p == own_heap_address) {
    symbol = "own_heap_block";
    base = p;
  } else if (p == (uintptr_t)&own_static_value) {
    symbol = "own_static_variable";
    base = p;
  } else if (p == (uintptr_t)probe_int2d) {
    symbol = "probe_int2d";
    base = p;
  }
  ja("{\"symbol\":");
  if (symbol)
    js(symbol);
  else
    ja("null");
  ja(",\"offset\":");
  if (symbol)
    off(p, base);
  else
    ja("null");
  ja(",\"dereferenced\":false}");
}
static void emit_context(const CONTEXT *c) {
  ja("{\"ContextFlags\":");
  hx(c->ContextFlags);
#define C(m) fieldhex(#m, c->m)
  C(Rip);
  ja(",\"RipOffset\":");
  relative_address(c->Rip);
  fieldstr("RipLocation", location(c->Rip));
  fieldstr("RipOffsetReference",
           !strcmp(location(c->Rip), "owned_alternate")
               ? "alternate_sled_start"
               : (!strcmp(location(c->Rip), "owned_probe") ? "instruction_site"
                                                           : "none"));
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
    fieldhex("callback_ordinal", k + 1u);
    fieldhex("delivery_index", s->delivery);
    fieldstr("observer", s->observer);
    fieldstr("stage", s->stage);
    ja(",\"exception\":{\"ExceptionCode\":");
    hx(s->er.ExceptionCode);
    fieldhex("ExceptionFlags", s->er.ExceptionFlags);
    fieldhex("ExceptionAddress", (uintptr_t)s->er.ExceptionAddress);
    ja(",\"ExceptionAddressOffset\":");
    relative_address((uintptr_t)s->er.ExceptionAddress);
    fieldstr("ExceptionAddressLocation",
             location((uintptr_t)s->er.ExceptionAddress));
    const char *al = location((uintptr_t)s->er.ExceptionAddress);
    fieldstr("ExceptionAddressOffsetReference",
             !strcmp(al, "owned_alternate")
                 ? "alternate_sled_start"
                 : (!strcmp(al, "owned_probe") ? "instruction_site" : "none"));
    fieldhex("NumberParameters", s->er.NumberParameters);
    ja(",\"ExceptionInformation\":[");
    for (unsigned z = 0; z < EXCEPTION_MAXIMUM_PARAMETERS; z++) {
      if (z)
        ja(",");
      hx(s->er.ExceptionInformation[z]);
    }
    ja("],\"parameter_references\":[");
    for (unsigned z = 0; z < EXCEPTION_MAXIMUM_PARAMETERS; z++) {
      if (z)
        ja(",");
      parameter_reference(s->er.ExceptionInformation[z]);
    }
    ja("]}");
    ja(",\"context\":");
    emit_context(&s->ctx);
    ja(",\"context_bytes_hex\":");
    bytes(&s->ctx, sizeof s->ctx);
    fieldhex("context_size", sizeof s->ctx);
    fieldstr("context_field_semantics",
             "raw_bytes_validity_depends_on_returned_ContextFlags");
    fieldhex("exception_information_valid_slots",
             s->er.NumberParameters < EXCEPTION_MAXIMUM_PARAMETERS
                 ? s->er.NumberParameters
                 : EXCEPTION_MAXIMUM_PARAMETERS);
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
    ja(",\"total_length\":null,\"length_status\":\"unavailable_documented_size_"
       "for_borrowed_"
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
    fieldbool("tf_set", s->tf_set);
    fieldstr("reason", s->reason);
    ja("}");
    fieldhex("instruction_site", (uintptr_t)cur->site);
    fieldhex("sled_start", (uintptr_t)cur->sled);
    fieldhex("sled_end", (uintptr_t)cur->sled_end);
    fieldhex("probe_fn", (uintptr_t)cur->fn);
    fieldhex("probe_end", (uintptr_t)cur->end);
    fieldhex("alternate_fn", (uintptr_t)probe_alternate);
    fieldhex("alternate_sled_start", (uintptr_t)probe_alternate_sled_start);
    fieldhex("alternate_end", (uintptr_t)probe_alternate_end);
    ja(",\"instruction_length\":");
    if (cur->api)
      ja("null");
    else
      hx(cur->length);
    fieldstr("offset_reference", "per_field_location_reference");
    end_record();
  }
}
static void emit_result(const char *status, const char *reason,
                        int known_delivery, int completed) {
  int valid = completed && !probe_escape_taken && probe_sled_entry <= 8u &&
              (probe_capture_path == 1u || probe_capture_path == 2u);
  begin("run_result");
  emit_key();
  fieldstr("status", status);
  ja(",\"exception_delivered\":");
  if (known_delivery)
    ja(deliveries ? "true" : "false");
  else
    ja("null");
  fieldbool("synthesized_by_parent", synthesized_by_parent);
  fieldhex("observation_count",
           synthesized_by_parent ? parent_observation_count : nsnap);
  ja(",\"delivery_count\":");
  if (synthesized_by_parent)
    ja("null");
  else
    hx(deliveries);
  ja(",\"vch_count\":");
  if (synthesized_by_parent)
    ja("null");
  else
    hx(vch_count);
  ja(",\"second_trap_count\":");
  if (synthesized_by_parent)
    ja("null");
  else
    hx(second_traps);
  fieldhex("stack_depth", rep);
  ja(",\"action_applied\":");
  if (synthesized_by_parent)
    ja("null");
  else
    ja(action_applied ? "true" : "false");
  fieldstr("action_reachability",
           synthesized_by_parent
               ? "unknown_child_aborted"
               : (action_applied
                      ? "applied"
                      : (deliveries ? "unsupported_or_aborted"
                                    : "initial_exception_not_observed")));
  ja(",\"callback_order\":");
  if (synthesized_by_parent)
    ja("null");
  else {
    ja("[");
    for (unsigned z = 0; z < nsnap; z++) {
      if (z)
        ja(",");
      js(snapshots[z].observer);
    }
    ja("]");
  }
  ja(",\"continuation_entry_offset\":");
  if (valid)
    hx(probe_sled_entry);
  else
    ja("null");
  ja(",\"continuation_site_offset\":");
  if (valid && probe_capture_path == 1u)
    hx((uintptr_t)cur->sled - (uintptr_t)cur->site + probe_sled_entry);
  else
    ja("null");
  fieldstr("continuation_target",
           !valid ? "unavailable"
                  : (probe_capture_path == 2u ? "owned_alternate_landing"
                                              : "owned_probe_sled"));
  ja(",\"capture_marker\":");
  if (valid)
    hx(probe_capture_path);
  else
    ja("null");
  ja(",\"requested_alternate\":");
  if (synthesized_by_parent)
    ja("null");
  else
    ja(alternate_taken ? "true" : "false");
  fieldstr("capture_path",
           !valid ? "unavailable"
                  : (probe_capture_path == 2u ? "alternate" : "normal"));
  fieldstr(
      "capture_method",
      "nine_one_byte_PUSHFQ_then_MOV_GPR_first_image_at_entry_rsp_minus_8");
  ja(",\"post_rax\":");
  if (valid)
    hx(probe_post_gpr[0]);
  else
    ja("null");
  fieldbool("probe_returned", completed);
  fieldbool("post_snapshot_valid", valid);
  fieldbool("safety_escape", guard_escape || (completed && probe_escape_taken));
  fieldstr("reason", reason);
  ja(",\"post_gpr\":");
  if (valid) {
    ja("{");
    for (unsigned z = 0; z < 16; z++) {
      if (z)
        ja(",");
      key_name(gpr_names[z]);
      hx(z == 4u ? probe_post_gpr[4] + (9u - probe_sled_entry) * 8u
                 : probe_post_gpr[z]);
    }
    ja("}");
  } else
    ja("null");
  ja(",\"post_rflags\":");
  if (valid)
    hx(probe_post_rflags);
  else
    ja("null");
  ja(",\"last_pushfq_rflags\":");
  if (valid)
    hx(probe_last_rflags);
  else
    ja("null");
  ja(",\"post_rsp_raw\":");
  if (valid)
    hx(probe_post_gpr[4]);
  else
    ja("null");
  ja(",\"pre_rsp\":");
  if (completed)
    hx(probe_pre_rsp);
  else
    ja("null");
  fieldstr("post_rsp_semantics",
           "post_gpr.Rsp_reconstructed_from_exact_owned_push_count");
  fieldstr("post_flags_semantics",
           "first_executed_PUSHFQ_image_RF_VM_not_preserved_by_PUSHFQ");
  ja(",\"api_result\":");
  if (cur->api) {
    ja("{\"return_kind\":");
    js(vi >= 18u ? "BOOL" : "void");
    ja(",\"return_value\":");
    if (valid && vi >= 18u)
      hx((uint32_t)probe_post_gpr[0]);
    else
      ja("null");
    ja(",\"remote_present\":");
    if (valid && vi == 19u && (uint32_t)probe_post_gpr[0])
      hx((uint32_t)own_remote_present);
    else
      ja("null");
    ja(",\"last_error\":");
    if (api_error_valid)
      hx(api_last_error);
    else
      ja("null");
    ja("}");
  } else
    ja("null");
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
  return p >= (uintptr_t)cur->sled && p < (uintptr_t)cur->sled_end;
}
static int original_frame(const CONTEXT *c) {
  return c->Rbp == probe_pre_rbp && c->Rsp == probe_pre_rsp &&
         c->Rip >= (uintptr_t)cur->site && c->Rip < (uintptr_t)cur->end;
}
static LONG observe(EXCEPTION_POINTERS *ep, const char *who) {
  if (!active)
    return EXCEPTION_CONTINUE_SEARCH;
  if (InterlockedExchange(&in_handler, 1)) {
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
  s->observer = who;
  s->tf_set = 0;
  s->tf_cleared = 0;
  if (!strcmp(who, "vch")) {
    vch_count++;
    s->delivery = deliveries;
    s->stage = "continue_callback";
    s->action = "observe_only";
    s->reason = "read_only_vectored_continue_handler";
    s->has_proposed = s->has_actual = 1;
    s->proposed = s->actual = s->ctx.Rip;
    InterlockedExchange(&in_handler, 0);
    return EXCEPTION_CONTINUE_SEARCH;
  }
  if (!strcmp(who, "seh") && chain_pending)
    chain_pending = 0;
  else
    deliveries++;
  s->delivery = deliveries;
  s->stage = tf_armed && s->er.ExceptionCode == EXCEPTION_SINGLE_STEP
                 ? "second_trap"
                 : (deliveries == 1u ? "initial" : "other");
  if (!strcmp(s->stage, "second_trap"))
    second_traps++;
  s->action = "keep";
  s->reason = "requested_policy";
  s->has_proposed = s->has_actual = 1;
  s->proposed = s->actual = s->ctx.Rip;
  if (pi == 5u && !strcmp(who, "veh")) {
    chain_pending = 1;
    s->action = "search";
    s->reason = "pass_to_frame_SEH_without_mutation";
    InterlockedExchange(&in_handler, 0);
    return EXCEPTION_CONTINUE_SEARCH;
  }
  if (s->er.ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
    s->action = "terminate";
    s->reason = "noncontinuable_exception";
    s->has_actual = 0;
    fatal_from_handler(s->reason);
  }
  if (cur->api) {
    if (deliveries >= 4u ||
        strcmp(location(s->ctx.Rip), "inside_system_library")) {
      s->action = "terminate";
      s->reason = deliveries >= 4u
                      ? "api_repeat_guard_no_documented_instruction_length"
                      : "api_exception_not_in_verified_system_library";
      s->has_actual = 0;
      fatal_from_handler(s->reason);
    }
    s->tf_cleared = (s->ctx.EFlags & 0x100u) != 0;
    ep->ContextRecord->EFlags &= ~0x100u;
    action_applied = 1;
    InterlockedExchange(&in_handler, 0);
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  if (tf_armed && s->er.ExceptionCode == EXCEPTION_SINGLE_STEP) {
    tf_armed = 0;
    s->tf_cleared = (s->ctx.EFlags & 0x100u) != 0;
    ep->ContextRecord->EFlags &= ~0x100u;
    s->action = "clear_tf_keep";
    /* A completed PUSHFQ moved RSP by one or more known eight-byte slots. */
    uint64_t d = probe_pre_rsp - s->ctx.Rsp;
    if (s->ctx.Rbp != probe_pre_rbp || d < 8u || d > 72u || (d & 7u) ||
        s->ctx.Rip < (uintptr_t)cur->sled + 1u ||
        s->ctx.Rip > (uintptr_t)cur->sled_end ||
        d / 8u != s->ctx.Rip - (uintptr_t)cur->sled) {
      s->action = "terminate";
      s->reason = "second_trap_owned_frame_or_boundary_not_verified";
      s->has_actual = 0;
      fatal_from_handler(s->reason);
    }
    InterlockedExchange(&in_handler, 0);
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  s->tf_cleared = (s->ctx.EFlags & 0x100u) != 0;
  ep->ContextRecord->EFlags &= ~0x100u;
  if (!original_frame(&s->ctx)) {
    s->action = "terminate";
    s->reason = "owned_original_frame_not_verified";
    s->has_actual = 0;
    fatal_from_handler(s->reason);
  }
  if (pi == 3u) {
    s->proposed = (uintptr_t)probe_alternate_sled_start;
    s->action = "alternate";
    alternate_taken = 1;
  } else if (pi == 4u && deliveries == 1u) {
    s->proposed = (uintptr_t)cur->sled;
    s->action = "set_tf_owned_sled";
    s->tf_set = 1;
    s->tf_cleared = 0;
    ep->ContextRecord->EFlags |= 0x100u;
    tf_armed = 1;
  } else if (pi == 0u || pi == 2u || pi == 5u || pi == 6u ||
             (pi == 1u && deliveries >= 4u)) {
    s->proposed = s->ctx.Rip + cur->length;
    s->action = "advance";
  }
  if (deliveries >= 5u) {
    guard_escape = 1;
    s->action = "escape";
    s->reason = "total_delivery_guard";
  } else if (pi != 3u && !owned_destination(s->proposed)) {
    unsupported = guard_escape = 1;
    s->action = "escape";
    s->reason = "requested_destination_not_owned_instruction_boundary";
  }
  if (!strcmp(s->action, "escape")) {
    s->actual = (uintptr_t)cur->escape;
    ep->ContextRecord->EFlags &= ~0x100u;
    tf_armed = 0;
  } else {
    s->actual = s->proposed;
    action_applied = 1;
  }
  ep->ContextRecord->Rip = s->actual;
  InterlockedExchange(&in_handler, 0);
  return EXCEPTION_CONTINUE_EXECUTION;
}
static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep) {
  return observe(ep, "veh");
}
static LONG CALLBACK uef_handler(EXCEPTION_POINTERS *ep) {
  return observe(ep, "uef");
}
static LONG CALLBACK vch_handler(EXCEPTION_POINTERS *ep) {
  return observe(ep, "vch");
}
static LONG seh_filter(EXCEPTION_POINTERS *ep) { return observe(ep, "seh"); }

/* __try is deliberately in a DIFFERENT frame from every faulting instruction.
 */
__declspec(noinline) static void invoke(void) {
  if (oi == 1u || oi == 3u) {
    __try {
      cur->fn();
    } __except (seh_filter(GetExceptionInformation())) {
      guard_escape = 1;
    }
  } else {
    cur->fn();
    if (vi == 19u && (uint32_t)probe_post_gpr[0] == 0u && probe_completed &&
        !probe_escape_taken && probe_sled_entry <= 8u &&
        (probe_capture_path == 1u || probe_capture_path == 2u)) {
      api_last_error = GetLastError();
      api_error_valid = 1;
    }
  }
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
  volatile uint64_t own_stack_value = UINT64_C(0x4f574e535441434b);
  own_stack_address = (uintptr_t)&own_stack_value;
  void *heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32u);
  if (!heap) {
    own_stack_address = 0;
    fclose(raw);
    return 5;
  }
  own_heap_address = (uintptr_t)heap;
  PVOID veh = NULL, vch = NULL;
  if (oi == 0u || oi == 3u) {
    veh = AddVectoredExceptionHandler(1, veh_handler);
    if (!veh) {
      HeapFree(GetProcessHeap(), 0, heap);
      own_stack_address = own_heap_address = 0;
      fclose(raw);
      return 4;
    }
  } else if (oi == 2u)
    SetUnhandledExceptionFilter(uef_handler);
  if (pi == 6u) {
    vch = AddVectoredContinueHandler(1, vch_handler);
    if (!vch) {
      if (veh)
        RemoveVectoredExceptionHandler(veh);
      HeapFree(GetProcessHeap(), 0, heap);
      own_stack_address = own_heap_address = 0;
      if (oi == 2u)
        SetUnhandledExceptionFilter(NULL);
      fclose(raw);
      return 6;
    }
  }
  for (rep = 0; rep < REPEATS; rep++) {
    nsnap = deliveries = vch_count = second_traps = 0;
    chain_pending = action_applied = tf_armed = alternate_taken =
        api_error_valid = 0;
    own_remote_present = -1;
    const uint64_t values[12] = {own_stack_address,
                                 own_heap_address,
                                 (uintptr_t)probe_int2d,
                                 (uintptr_t)&own_static_value,
                                 6u,
                                 7u,
                                 8u,
                                 0xfu,
                                 0x11u,
                                 0x100u,
                                 UINT64_C(0xffffffff),
                                 UINT64_C(0x8000000000000000)};
    requested_rax = vi < 12u
                        ? values[vi]
                        : (vi == 12u ? 0u
                                     : (vi == 13u ? own_stack_address
                                                  : probe_base_seed_gpr[0]));
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
    fieldhex("sled_end", (uintptr_t)cur->sled_end);
    fieldhex("probe_fn", (uintptr_t)cur->fn);
    fieldhex("probe_end", (uintptr_t)cur->end);
    fieldhex("alternate_fn", (uintptr_t)probe_alternate);
    fieldhex("alternate_sled_start", (uintptr_t)probe_alternate_sled_start);
    fieldhex("alternate_end", (uintptr_t)probe_alternate_end);
    fieldhex("family", cur->family);
    fieldhex("requested_rax", requested_rax);
    ja(",\"rax_reference\":");
    parameter_reference(requested_rax);
    fieldstr("own_debug_string_a", own_debug_a);
    fieldstr("own_debug_string_w",
             "exception-observer-v5: own Unicode test U+03A9");
    fieldstr("stack_pattern",
             "primed_owned_window_120_bytes_0xa5_plus_8_byte_flags_scratch");
    end_record();
    SetLastError(0);
    active = 1;
    at_depth(rep);
    active = 0;
    emit_observations();
    if (!probe_completed)
      emit_result("runtime_aborted", "owned_probe_did_not_complete", 1, 0);
    else if (unsupported)
      emit_result("requested_policy_unsupported",
                  "safety_action_is_separately_logged", 1, 1);
    else if (guard_escape)
      emit_result("guard_escape", "total_delivery_guard", 1, 1);
    else if (probe_sled_entry > 8u ||
             (probe_capture_path != 1u && probe_capture_path != 2u))
      emit_result("runtime_aborted", "post_snapshot_owned_stack_delta_invalid",
                  1, 1);
    else
      emit_result("completed", "", 1, 1);
  }
  if (vch)
    RemoveVectoredContinueHandler(vch);
  if (veh)
    RemoveVectoredExceptionHandler(veh);
  if (oi == 2u)
    SetUnhandledExceptionFilter(NULL);
  HeapFree(GetProcessHeap(), 0, heap);
  own_stack_address = own_heap_address = 0;
  fclose(raw);
  raw = NULL;
  return 0;
}

static void manifest(void) {
  begin("manifest");
  fieldhex("schema_version", 5);
  fieldhex("planned_runs", 4640);
  fieldhex("families", 3);
  fieldhex("variants", NVAR);
  fieldhex("observers", 4);
  fieldhex("flag_seeds", 2);
  fieldhex("policies", 8);
  fieldhex("repeats", REPEATS);
  fieldhex("groups", 232);
  fieldhex("group_timeout_ms", GROUP_TIMEOUT_MS);
  fieldhex("context_size", sizeof(CONTEXT));
  fieldstr("architecture", "x86_64");
  fieldstr("compiler", __clang_version__);
  fieldstr("runtime_claim", "observations_only_no_expected_Windows_values");
  fieldstr("raw_numbers", "hexadecimal_strings");
  fieldstr("routing_base_continuation",
           "literal_incoming_Rip_plus_declared_instruction_length_guarded");
  fieldstr("xstate_total_length", "unavailable_for_borrowed_handler_context");
  SYSTEM_INFO inf;
  GetNativeSystemInfo(&inf);
  fieldhex("native_processor_architecture", inf.wProcessorArchitecture);
  end_record();
}
static unsigned merge_child(const wchar_t *path, int *dropped,
                            unsigned *pending_observations) {
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
    } else if (pending_observations &&
               !strncmp(line, "{\"type\":\"observation\"", 21))
      (*pending_observations)++;
    if (ferror(raw) || fwrite(line, 1, n, raw) != n) {
      fclose(in);
      TerminateProcess(GetCurrentProcess(), 0xe006u);
      return results;
    }
  }
  if (ferror(in))
    *dropped = 1;
  fclose(in);
  if (fflush(raw) || ferror(raw))
    TerminateProcess(GetCurrentProcess(), 0xe006u);
  return results;
}
typedef struct {
  int created, assigned, resumed, reaped, timeout;
  DWORD create_error, assign_error, resume_error, wait_status, wait_error,
      cleanup_wait_status, cleanup_wait_error, terminate_error, child_exit_code,
      exit_query_error, child_process_id, child_thread_id;
} Outcome;
static Outcome run_owned_child(const wchar_t *self, wchar_t *command,
                               HANDLE job) {
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
                             CREATE_NO_WINDOW | CREATE_SUSPENDED, NULL, NULL,
                             &start, &proc) != 0;
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
  o.reaped =
      o.wait_status == WAIT_OBJECT_0 || o.cleanup_wait_status == WAIT_OBJECT_0;
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
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  memset(&limits, 0, sizeof limits);
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job && !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                      &limits, sizeof limits)) {
    CloseHandle(job);
    job = NULL;
  }
  int failures = 0;
  const char *stop_reason = job ? NULL : "owned_kill_on_close_job_unavailable";
  int dropped = 0;
  unsigned group = 0;
  for (vi = 0; vi < NVAR; vi++)
    for (oi = 0; oi < 4; oi++)
      for (si = 0; si < 2; si++)
        for (pi = 0; pi < 8; pi++) {
          if (!applicable(vi, oi, pi))
            continue;
          cur = &variants[vi];
          Outcome o;
          memset(&o, 0, sizeof o);
          o.wait_status = WAIT_FAILED;
          o.cleanup_wait_status = WAIT_FAILED;
          o.child_exit_code = 0xffffffffu;
          if (swprintf(childpath, 32768, L"%ls\\group-%03u.jsonl", dir, group) <
              0) {
            if (job)
              CloseHandle(job);
            fclose(raw);
            return 15;
          }
          if (!stop_reason &&
              GetFileAttributesW(childpath) != INVALID_FILE_ATTRIBUTES)
            stop_reason = "preexisting_group_output_not_overwritten";
          if (!stop_reason) {
            if (swprintf(command, 65536, L"\"%ls\" --child %u %u %u %u \"%ls\"",
                         self, vi, oi, si, pi, childpath) < 0) {
              CloseHandle(job);
              fclose(raw);
              return 16;
            }
            o = run_owned_child(self, command, job);
          }
          dropped = 0;
          unsigned pending_observations = 0;
          unsigned count =
              (o.created && o.resumed && o.reaped && o.child_exit_code != 3u)
                  ? merge_child(childpath, &dropped, &pending_observations)
                  : 0;
          if (count > REPEATS)
            count = REPEATS;
          for (rep = count; rep < REPEATS; rep++) {
            synthesized_by_parent = 1;
            parent_observation_count = rep == count ? pending_observations : 0;
            nsnap = 0;
            deliveries = vch_count = second_traps = 0;
            action_applied = alternate_taken = api_error_valid = 0;
            guard_escape = 0;
            emit_result(
                "runtime_aborted",
                stop_reason
                    ? stop_reason
                    : (o.created
                           ? (o.timeout ? "own_child_timeout"
                                        : "own_child_exited_before_repeat")
                           : "CreateProcess_failed"),
                0, 0);
          }
          synthesized_by_parent = 0;
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
          group++;
          if (!o.created || !o.assigned || !o.resumed || !o.reaped ||
              o.child_exit_code || count != REPEATS || dropped)
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
  if (argc == 7 && !wcscmp(argv[1], L"--child")) {
    vi = (unsigned)wcstoul(argv[2], NULL, 10);
    oi = (unsigned)wcstoul(argv[3], NULL, 10);
    si = (unsigned)wcstoul(argv[4], NULL, 10);
    pi = (unsigned)wcstoul(argv[5], NULL, 10);
    if (vi >= NVAR || oi >= 4 || si >= 2 || pi >= 8 || !applicable(vi, oi, pi))
      return 20;
    return child(argv[6]);
  }
  if (argc == 3 && !wcscmp(argv[1], L"--output"))
    return parent(argv[2]);
  fwprintf(stderr,
           L"Usage: exception_probe.exe --output NEW_RESULTS_DIRECTORY\n");
  return 21;
}
