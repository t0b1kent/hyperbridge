#!/usr/bin/env python3
"""Validate and summarize exception-observer-probe JSONL using only the stdlib.

This is a schema/coverage checker, not an oracle for Windows exception values.
It deliberately does not assume a particular exception code, RIP adjustment,
flags preservation, delivery count, or successful API result. A completed run
with no exception delivered is a legitimate measured outcome.

Exit status: 0 means the file is structurally valid and all matrix keys have an
acceptable terminal result. Explicit requested_policy_unsupported results count
as accounted coverage, not as completed measurements. Missing/skipped keys make
the default check fail; --allow-incomplete relaxes only those coverage checks.
Malformed input, runtime_aborted, and guard_escape always fail. Summary output is
written even when validation fails. No raw or summary JSON number is permitted;
all numerical values use hexadecimal strings. Booleans remain JSON booleans.
"""

import argparse
import collections
import hashlib
import itertools
import json
import pathlib
import re
import sys

VARIANTS = (
    "int3_cc", "int3_cd03", "int2d_0", "int2d_1", "int2d_2", "int2d_3",
    "int2d_4", "int2d_5", "int2d_10", "icebp", "debugbreak", "raise0",
    "raise1", "single_step", "ud2", "int2c", "hlt", "int1_cd01",
)
OBSERVERS = ("veh", "seh", "uef")
FLAG_SEEDS = ("clear", "set")
POLICIES = ("advance", "keep_then_advance")
API_VARIANTS = ("debugbreak", "raise0", "raise1")
REPEATS = 20
KEY_FIELDS = ("variant", "observer", "flag_seed", "policy", "repeat")
STATUSES = ("completed", "requested_policy_unsupported", "guard_escape",
            "runtime_aborted", "skipped")
RECORD_TYPES = ("manifest", "run_start", "observation", "run_result",
                "group_result", "thread_context", "thread_cleanup", "thread_block_result")
GPRS = ("Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi", "R8", "R9",
        "R10", "R11", "R12", "R13", "R14", "R15")
CONTEXT_BITS = {
    "ContextFlags": 32, "Rip": 64, "RipOffset": 64, "EFlags": 32,
    "Dr0": 64, "Dr1": 64, "Dr2": 64, "Dr3": 64, "Dr6": 64, "Dr7": 64,
    "SegCs": 16, "SegDs": 16, "SegEs": 16, "SegFs": 16, "SegGs": 16,
    "SegSs": 16, "MxCsr": 32, "Rsp": 64, "RspMod16": 4,
    "P1Home": 64, "P2Home": 64, "P3Home": 64, "P4Home": 64,
    "P5Home": 64, "P6Home": 64, "DebugControl": 64,
    "LastBranchToRip": 64, "LastBranchFromRip": 64,
    "LastExceptionToRip": 64, "LastExceptionFromRip": 64,
}
EXCEPTION_BITS = {
    "ExceptionCode": 32, "ExceptionFlags": 32, "ExceptionAddress": 64,
    "ExceptionAddressOffset": 64, "NumberParameters": 32,
}
HEX = re.compile(r"0x[0-9a-fA-F]+\Z")
SIGNED_HEX = re.compile(r"-?0x[0-9a-fA-F]+\Z")
SIGNED_FIELDS = {"RipOffset", "ExceptionAddressOffset"}
NUMERIC_NAMES = {
    "repeat", "delivery_index", "observation_count", "continuation_entry_offset",
    "continuation_site_offset", "post_rax", "stack_depth", "proposed_rip",
    "actual_rip", "total_length", "exit_code", "child_exit", "child_exit_code",
    "last_error", "LastError", "pid", "tid", "process_id", "thread_id",
    "instruction_length", "instruction_address", "site_address", "timeout_ms",
    "duration_ms", "requested_flags", "returned_flags", "ContextFlags",
    "Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7", "Dr7_requested",
    "wait_status", "create_error",
    "schema_version", "planned_runs", "families", "variants", "observers", "flag_seeds",
    "policies", "repeats", "groups", "group_timeout_ms", "context_size",
    "native_processor_architecture", "kernel32_base", "kernelbase_base", "ntdll_base",
    "buffer_pattern_byte", "exception_information_valid_slots", "instruction_site", "sled_start",
    "group_index", "child_terminal_records", "post_rflags", "post_rsp", "pre_rsp",
    "arithmetic_flags_mask", "requested_arithmetic_flags", "family", "assign_error",
    "resume_error", "terminate_error", "suspend_error",
    "exit_query_error",
    "child_process_id", "child_thread_id", "wait_error", "cleanup_wait_status", "cleanup_wait_error",
} | set(CONTEXT_BITS) | set(EXCEPTION_BITS) | set(GPRS)
PROCESS_BOOLEANS = ("created", "assigned", "resumed", "reaped", "timeout", "partial_record_dropped")
PROCESS_NUMERIC = ("create_error", "assign_error", "resume_error", "wait_status", "terminate_error",
                   "child_exit_code", "exit_query_error", "child_process_id", "child_thread_id",
                   "wait_error", "cleanup_wait_status", "cleanup_wait_error")
THREAD_KEYS = tuple(("get", target, request, phase)
                    for target, phase in (("current", "before"), ("suspended", "before"),
                                          ("suspended", "after_set"))
                    for request in ("debug", "all")) + (
                        ("set", "suspended", "debug", "set_dr7_zero"),)
VARIABILITY_NOTES = [
    "Variability is descriptive; no Windows exception values are assumed.",
    "Absolute addresses can vary with ASLR, allocations, and process layout.",
    "Stack pointers and home slots can vary legitimately with call depth and ABI activity.",
    "Site-relative addresses are retained verbatim; changing offsets are not normalized away.",
    "Across-depth and within-depth comparisons are separate; a single sample cannot establish stability.",
    "Only exception, context, xstate, and gpr_differences participate in field variability.",
]


def key_object(key):
    return dict(zip(KEY_FIELDS, key[:4] + (hex(key[4]),)))


def expected_keys():
    return tuple(itertools.product(VARIANTS, OBSERVERS, FLAG_SEEDS, POLICIES,
                                   range(REPEATS)))


def json_hex_numbers(value, member=None):
    """Ensure generated JSON itself satisfies the no-JSON-number contract."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, float):
        # This can occur only when retaining malformed auxiliary input records.
        return {"invalid_json_number": repr(value)}
    if isinstance(value, dict):
        return {str(k): json_hex_numbers(v, str(k)) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_hex_numbers(v, member) for v in value]
    if isinstance(value, str) and member in NUMERIC_NAMES:
        expression = SIGNED_HEX if member in SIGNED_FIELDS else HEX
        if expression.fullmatch(value) is None:
            return {"invalid_numeric_text": value}
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def flatten(value, prefix=""):
    if isinstance(value, dict):
        if not value:
            yield prefix, value
        for name in sorted(value):
            yield from flatten(value[name], prefix + "." + name if prefix else name)
    else:
        # Array order and all four ExceptionInformation slots remain observable.
        yield prefix, value


def duplicate_safe_object(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise ValueError("duplicate JSON object member: " + name)
        obj[name] = value
    return obj


def reject_constant(value):
    raise ValueError("nonstandard JSON numeric constant: " + value)


def hex_value(value, signed=False):
    expression = SIGNED_HEX if signed else HEX
    return int(value, 16) if isinstance(value, str) and expression.fullmatch(value) else None


class Checker:
    def __init__(self, source="<stream>", allow_incomplete=False):
        self.source = str(source)
        self.allow_incomplete = allow_incomplete
        self.errors = []
        self.warnings = []
        self.starts = collections.defaultdict(list)
        self.results = collections.defaultdict(list)
        self.observations = collections.defaultdict(list)
        self.valid_observations = collections.defaultdict(list)
        self.record_counts = collections.Counter()
        self.manifests = []
        self.groups = []
        self.thread_contexts = []
        self.thread_cleanup = []
        self.thread_blocks = []
        self.line_count = 0
        self.sha256 = hashlib.sha256()
        self.current_key = None
        self.current_line = 0

    def error(self, message, category="schema"):
        item = {"line": hex(self.current_line), "category": category,
                "message": message}
        if self.current_key is not None:
            item["key"] = key_object(self.current_key)
        self.errors.append(item)

    def mapping(self, value, path):
        if not isinstance(value, dict):
            self.error(path + " must be an object")
            return {}
        return value

    def required(self, obj, names, path):
        for name in names:
            if name not in obj:
                self.error(path + "." + name + " is required")

    def uint(self, value, path, bits=64, nullable=False):
        if value is None and nullable:
            return None
        if not isinstance(value, str) or HEX.fullmatch(value) is None:
            self.error(path + " must be an unsigned 0x-prefixed hexadecimal string")
            return None
        number = int(value, 16)
        if number >= 1 << bits:
            self.error(path + " is outside uint" + str(bits) + " range")
            return None
        return number

    def address_offset(self, value, path):
        if not isinstance(value, str) or SIGNED_HEX.fullmatch(value) is None:
            self.error(path + " must be a signed or unsigned 0x-prefixed hexadecimal offset")
            return None
        number = int(value, 16)
        if abs(number) >= 1 << 64:
            self.error(path + " magnitude is outside uint64 address-difference range")
            return None
        return number

    def boolean(self, value, path):
        if not isinstance(value, bool):
            self.error(path + " must be a JSON boolean")
            return None
        return value

    def string(self, value, path, nonempty=True):
        if not isinstance(value, str) or (nonempty and not value):
            self.error(path + " must be " + ("a nonempty" if nonempty else "a") + " string")
            return None
        return value

    def global_numbers(self, value, path="record", member=None):
        if isinstance(value, bool):
            if member in NUMERIC_NAMES:
                self.error(path + " is a numeric field, not a boolean", "numeric")
            return
        if value is None:
            return
        if isinstance(value, (int, float)):
            self.error(path + " contains a JSON number; encode it as a hex string", "numeric")
        elif isinstance(value, dict):
            for name, child in value.items():
                self.global_numbers(child, path + "." + name, name)
        elif isinstance(value, list):
            for i, child in enumerate(value):
                self.global_numbers(child, path + "[" + str(i) + "]", member)
        elif isinstance(value, str) and member in NUMERIC_NAMES:
            expression = SIGNED_HEX if member in SIGNED_FIELDS else HEX
            if expression.fullmatch(value) is None:
                self.error(path + " is a numeric field and must be a hex string", "numeric")

    def parse_key(self, record):
        obj = self.mapping(record.get("key"), "key")
        self.required(obj, KEY_FIELDS, "key")
        if set(obj) - set(KEY_FIELDS):
            self.error("key contains unknown fields", "key")
        choices = (VARIANTS, OBSERVERS, FLAG_SEEDS, POLICIES)
        valid = True
        values = []
        for name, allowed in zip(KEY_FIELDS[:4], choices):
            value = obj.get(name)
            if value not in allowed:
                self.error("key." + name + " is outside the fixed matrix", "key")
                valid = False
            values.append(value)
        repeat = self.uint(obj.get("repeat"), "key.repeat", 32)
        if repeat is None or repeat >= REPEATS:
            self.error("key.repeat is outside 0x0..0x13", "key")
            valid = False
        if set(obj) != set(KEY_FIELDS):
            valid = False
        if not valid:
            return None
        return tuple(values) + (repeat,)

    def check_register_map(self, obj, path, required_names, bits=64):
        obj = self.mapping(obj, path)
        self.required(obj, required_names, path)
        for name, value in obj.items():
            if name not in required_names:
                self.error(path + " contains unknown register " + name)
            self.uint(value, path + "." + name, bits)
            if bits == 128 and isinstance(value, str) and HEX.fullmatch(value) and len(value) != 34:
                self.error(path + "." + name + " must contain exactly 0x10 bytes (32 hexadecimal digits)")
        return obj

    def check_observation(self, record, key):
        before = len(self.errors)
        self.required(record, ("delivery_index", "exception", "context", "gpr_expected",
                               "gpr_differences", "xstate", "continuation", "instruction_site",
                               "sled_start", "instruction_length", "offset_reference"), "observation")
        self.uint(record.get("instruction_site"), "observation.instruction_site")
        self.uint(record.get("sled_start"), "observation.sled_start")
        expected_reference = "owned_api_call_site" if key[0] in API_VARIANTS else "owned_instruction_start"
        if record.get("offset_reference") != expected_reference:
            self.error("observation.offset_reference disagrees with the variant")
        if key[0] in API_VARIANTS:
            if record.get("instruction_length") is not None:
                self.error("API instruction_length must be null; no library instruction length is inferred")
        else:
            length = self.uint(record.get("instruction_length"), "observation.instruction_length", 32)
            if length is not None and length not in (1, 2):
                self.error("instruction_length must be 0x1 or 0x2 for the closed instruction set")
        index = self.uint(record.get("delivery_index"), "delivery_index", 32)
        if index is not None and not 1 <= index <= 5:
            self.error("delivery_index must be in 0x1..0x5; the last slot is the hard guard")
        exception = self.mapping(record.get("exception"), "exception")
        self.required(exception, tuple(EXCEPTION_BITS) + ("ExceptionInformation",), "exception")
        for name, bits in EXCEPTION_BITS.items():
            number = (self.address_offset(exception.get(name), "exception." + name) if name in SIGNED_FIELDS
                      else self.uint(exception.get(name), "exception." + name, bits))
            if name == "NumberParameters" and number is not None and number > 15:
                self.error("exception.NumberParameters exceeds EXCEPTION_MAXIMUM_PARAMETERS")
        info = exception.get("ExceptionInformation")
        if not isinstance(info, list) or len(info) != 4:
            self.error("exception.ExceptionInformation must contain exactly four slots")
        else:
            for i, value in enumerate(info):
                self.uint(value, "exception.ExceptionInformation[" + str(i) + "]")
        context = self.mapping(record.get("context"), "context")
        self.required(context, tuple(CONTEXT_BITS) + ("gpr", "xmm"), "context")
        for name, bits in CONTEXT_BITS.items():
            if name in SIGNED_FIELDS:
                self.address_offset(context.get(name), "context." + name)
            else:
                self.uint(context.get(name), "context." + name, bits)
        rsp, rsp_mod = hex_value(context.get("Rsp")), hex_value(context.get("RspMod16"))
        if rsp is not None and rsp_mod is not None and rsp % 16 != rsp_mod:
            self.error("context.RspMod16 disagrees with context.Rsp")
        site = hex_value(record.get("instruction_site"))
        if site is not None:
            for obj, address, offset, prefix in ((context, "Rip", "RipOffset", "context"),
                                               (exception, "ExceptionAddress", "ExceptionAddressOffset", "exception")):
                absolute, relative = hex_value(obj.get(address)), hex_value(obj.get(offset), signed=True)
                if absolute is not None and relative is not None and absolute - site != relative:
                    self.error(prefix + "." + offset + " disagrees with absolute address and instruction_site")
        actual = self.check_register_map(context.get("gpr"), "context.gpr", GPRS)
        rsp, gpr_rsp = context.get("Rsp"), actual.get("Rsp")
        if isinstance(rsp, str) and HEX.fullmatch(rsp) and isinstance(gpr_rsp, str) and HEX.fullmatch(gpr_rsp):
            if int(rsp, 16) != int(gpr_rsp, 16):
                self.error("context.Rsp disagrees with context.gpr.Rsp")
        self.check_register_map(context.get("xmm"), "context.xmm",
                                tuple("Xmm" + str(i) for i in range(16)), 128)
        wanted = self.check_register_map(record.get("gpr_expected"), "gpr_expected", GPRS)
        differences = record.get("gpr_differences")
        if not isinstance(differences, list) or any(not isinstance(n, str) for n in differences):
            self.error("gpr_differences must be an array of register names")
        elif len(set(differences)) != len(differences) or any(n not in GPRS for n in differences):
            self.error("gpr_differences contains duplicates or unknown register names")
        elif all(isinstance(actual.get(n), str) and HEX.fullmatch(actual[n]) and
                 isinstance(wanted.get(n), str) and HEX.fullmatch(wanted[n]) for n in GPRS):
            expected_differences = {n for n in GPRS if int(actual[n], 16) != int(wanted[n], 16)}
            if set(differences) != expected_differences:
                self.error("gpr_differences does not match context.gpr versus gpr_expected")
        xstate = self.mapping(record.get("xstate"), "xstate")
        self.required(xstate, ("present", "total_length", "length_status"), "xstate")
        present = self.boolean(xstate.get("present"), "xstate.present")
        self.uint(xstate.get("total_length"), "xstate.total_length", 32, nullable=True)
        self.string(xstate.get("length_status"), "xstate.length_status")
        flags = context.get("ContextFlags")
        if isinstance(flags, str) and HEX.fullmatch(flags) and present is not None:
            if present != bool(int(flags, 16) & 0x40):
                self.error("xstate.present must report the 0x40 ContextFlags bit")
        continuation = self.mapping(record.get("continuation"), "continuation")
        self.required(continuation, ("requested_policy", "action", "proposed_rip", "actual_rip",
                                     "tf_cleared", "reason"), "continuation")
        if continuation.get("requested_policy") != key[3]:
            self.error("continuation.requested_policy disagrees with the run key")
        self.string(continuation.get("action"), "continuation.action")
        self.uint(continuation.get("proposed_rip"), "continuation.proposed_rip", nullable=True)
        self.uint(continuation.get("actual_rip"), "continuation.actual_rip", nullable=True)
        self.boolean(continuation.get("tf_cleared"), "continuation.tf_cleared")
        self.string(continuation.get("reason"), "continuation.reason", nonempty=False)
        action = continuation.get("action")
        if action not in ("keep", "keep_fallback", "advance", "escape", "terminate"):
            self.error("continuation.action is not a supported collector action")
        rip = hex_value(context.get("Rip"))
        proposed = hex_value(continuation.get("proposed_rip"))
        actual_rip = hex_value(continuation.get("actual_rip"))
        if action in ("keep", "keep_fallback") and rip is not None and actual_rip != rip:
            self.error("keep continuation must leave actual_rip equal to the sampled Rip")
        if action == "keep" and rip is not None and proposed != rip:
            self.error("keep continuation must leave proposed_rip equal to the sampled Rip")
        if action == "keep_fallback" and continuation.get("proposed_rip") is not None:
            self.error("API keep_fallback must leave proposed_rip null")
        if action == "terminate" and continuation.get("actual_rip") is not None:
            self.error("terminate continuation must have null actual_rip")
        if action != "terminate" and actual_rip is None:
            self.error("non-terminating continuation requires actual_rip")
        if action == "advance":
            if proposed is None or actual_rip != proposed:
                self.error("advance continuation actual_rip must equal proposed_rip")
            length = hex_value(record.get("instruction_length"))
            if length is not None and rip is not None and proposed != (rip + length) & ((1 << 64) - 1):
                self.error("advance proposed_rip disagrees with Rip plus instruction_length")
        if key[0] not in API_VARIANTS and action in ("keep", "advance"):
            sled = hex_value(record.get("sled_start"))
            if site is not None and sled is not None and actual_rip is not None:
                if actual_rip != site and not sled <= actual_rip <= sled + 8:
                    self.error("continuation destination lies outside the owned instruction and bounded sled")
        eflags = hex_value(context.get("EFlags"))
        if eflags is not None and isinstance(continuation.get("tf_cleared"), bool):
            if continuation["tf_cleared"] != bool(eflags & 0x100):
                self.error("continuation.tf_cleared disagrees with the sampled TF bit")
        if len(self.errors) == before:
            self.valid_observations[key].append(record)

    def check_run_result(self, record):
        names = ("status", "exception_delivered", "observation_count",
                 "continuation_entry_offset", "continuation_site_offset", "post_rax",
                 "stack_depth", "reason", "probe_returned", "safety_escape")
        self.required(record, names, "run_result")
        status = record.get("status")
        if status not in STATUSES:
            self.error("run_result.status is unknown")
        if record.get("exception_delivered") is not None or status not in ("runtime_aborted", "skipped"):
            self.boolean(record.get("exception_delivered"), "run_result.exception_delivered")
        self.uint(record.get("observation_count"), "run_result.observation_count", 32)
        for name in ("continuation_entry_offset", "continuation_site_offset", "post_rax"):
            self.uint(record.get(name), "run_result." + name, nullable=True)
        self.uint(record.get("stack_depth"), "run_result.stack_depth", 32)
        self.string(record.get("reason"), "run_result.reason", nonempty=status != "completed")
        returned = self.boolean(record.get("probe_returned"), "run_result.probe_returned")
        escaped = self.boolean(record.get("safety_escape"), "run_result.safety_escape")
        if status == "completed" and (returned is not True or escaped is not False):
            self.error("completed run requires probe_returned=true and safety_escape=false")
        if status in ("runtime_aborted", "skipped"):
            if returned is not False:
                self.error("aborted/skipped runs must not claim the probe returned")
            if any(record.get(n) is not None for n in ("post_rax", "continuation_entry_offset", "continuation_site_offset")):
                self.error("aborted/skipped runs must not invent post-state or continuation offsets")
        if returned is True:
            self.required(record, ("post_rflags", "post_rsp", "pre_rsp"), "run_result")
            for name in ("post_rax", "post_rflags", "post_rsp", "pre_rsp"):
                self.uint(record.get(name), "run_result." + name)
            if escaped is True:
                if any(record.get(n) is not None for n in ("continuation_entry_offset", "continuation_site_offset")):
                    self.error("safety escape is not a measured sled entry; continuation offsets must be null")
            elif escaped is False:
                entry = hex_value(record.get("continuation_entry_offset"))
                before, after = hex_value(record.get("pre_rsp")), hex_value(record.get("post_rsp"))
                if before is not None and after is not None:
                    delta = before - after
                    if delta < 0 or delta > 64 or delta % 8 or entry != 8 - delta // 8:
                        self.error("continuation entry disagrees with the bounded eight-PUSH stack-delta measurement")

    def check_thread_context(self, record):
        names = ("operation", "target", "request", "phase", "status", "success",
                 "last_error", "requested_flags", "context")
        self.required(record, names, "thread_context")
        identity = tuple(record.get(n) for n in names[:4])
        if identity not in THREAD_KEYS:
            self.error("thread_context operation/target/request/phase is outside the fixed block")
        if record.get("status") not in ("observed", "skipped"):
            self.error("thread_context.status must be observed or skipped")
        self.boolean(record.get("success"), "thread_context.success")
        self.uint(record.get("last_error"), "thread_context.last_error", 32)
        self.uint(record.get("requested_flags"), "thread_context.requested_flags", 32)
        context = self.mapping(record.get("context"), "thread_context.context")
        self.required(context, ("ContextFlags", "Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7"),
                      "thread_context.context")
        for name in ("ContextFlags", "Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7"):
            self.uint(context.get(name), "thread_context.context." + name, 32 if name == "ContextFlags" else 64)
        for name in ("Dr4", "Dr5"):
            if name in context and context[name] is not None:
                self.error("thread_context.context." + name + " must be null: no such CONTEXT member")
        for name in ("suspended", "suspension_success"):
            if name in record:
                self.boolean(record[name], "thread_context." + name)
        if record.get("target") == "current" and record.get("validity") != "invalid_current_thread_context":
            self.error("current-thread GetThreadContext must mark validity=invalid_current_thread_context")
        self.thread_contexts.append(record)

    def check_group(self, record):
        group = self.mapping(record.get("group"), "group_result.group")
        self.required(group, KEY_FIELDS[:4], "group_result.group")
        if set(group) != set(KEY_FIELDS[:4]):
            self.error("group_result.group must have exactly the four non-repeat key fields")
        for name, allowed in zip(KEY_FIELDS[:4], (VARIANTS, OBSERVERS, FLAG_SEEDS, POLICIES)):
            if group.get(name) not in allowed:
                self.error("group_result.group." + name + " is outside the fixed matrix")
        self.required(record, PROCESS_BOOLEANS + PROCESS_NUMERIC + ("group_index", "child_terminal_records"), "group_result")
        self.check_process_fields(record, "group_result")
        index = self.uint(record.get("group_index"), "group_result.group_index", 32)
        count = self.uint(record.get("child_terminal_records"), "group_result.child_terminal_records", 32)
        groups = tuple(itertools.product(VARIANTS, OBSERVERS, FLAG_SEEDS, POLICIES))
        identity = tuple(group.get(n) for n in KEY_FIELDS[:4])
        if identity in groups and index is not None and groups.index(identity) != index:
            self.error("group_result.group_index disagrees with fixed matrix order")
        if count is not None and count > REPEATS:
            self.error("group_result.child_terminal_records exceeds 0x14")
        self.groups.append(record)

    def check_process_fields(self, record, kind):
        for name in PROCESS_BOOLEANS:
            self.boolean(record.get(name), kind + "." + name)
        for name in PROCESS_NUMERIC:
            self.uint(record.get(name), kind + "." + name, 32)
        if record.get("created") is False and any(record.get(n) is True for n in ("assigned", "resumed", "reaped")):
            self.error(kind + " cannot assign, resume, or reap a child that was not created")
        if record.get("resumed") is True and record.get("assigned") is not True:
            self.error(kind + " resumed a child without the owned cleanup job")
        if record.get("created") is True:
            for name in ("child_process_id", "child_thread_id"):
                if hex_value(record.get(name)) == 0:
                    self.error(kind + "." + name + " must be nonzero for a created child")
        wait = record.get("wait_status")
        cleanup_wait = hex_value(record.get("cleanup_wait_status"))
        if isinstance(wait, str) and HEX.fullmatch(wait) and cleanup_wait is not None and isinstance(record.get("reaped"), bool):
            if record["reaped"] != (int(wait, 16) == 0 or cleanup_wait == 0):
                self.error(kind + ".reaped disagrees with initial and cleanup wait statuses")

    def check_thread_auxiliary(self, record, kind):
        if kind == "thread_cleanup":
            booleans = ("created", "ready", "suspended", "resume_success", "thread_signaled")
            numeric = ("create_error", "suspend_error", "resume_error", "wait_status")
            destination = self.thread_cleanup
        else:
            booleans = PROCESS_BOOLEANS
            numeric = PROCESS_NUMERIC
            destination = self.thread_blocks
        self.required(record, booleans + numeric, kind)
        for name in booleans:
            self.boolean(record.get(name), kind + "." + name)
        for name in numeric:
            self.uint(record.get(name), kind + "." + name, 32)
        if kind == "thread_block_result":
            self.check_process_fields(record, kind)
        destination.append(record)

    def check_context_blob(self, record):
        if "context_bytes_hex" not in record:
            return
        blob = record["context_bytes_hex"]
        if not isinstance(blob, str) or HEX.fullmatch(blob) is None or (len(blob) - 2) % 2:
            self.error("context_bytes_hex must be a 0x-prefixed whole-byte hex blob")
            return
        size = record.get("context_size")
        if size is None and self.manifests:
            size = self.manifests[0].get("context_size")
        if size is not None:
            expected_size = self.uint(size, "context_size", 32)
            if expected_size is not None and (len(blob) - 2) // 2 != expected_size:
                self.error("context_bytes_hex byte length disagrees with context_size")

    def check_manifest(self, record):
        expected = {"schema_version": 1, "planned_runs": 4320, "families": 12,
                    "variants": 18, "observers": 3, "flag_seeds": 2, "policies": 2,
                    "repeats": 20, "groups": 216}
        self.required(record, tuple(expected) + ("architecture", "context_size", "group_timeout_ms"), "manifest")
        for name, wanted in expected.items():
            actual = self.uint(record.get(name), "manifest." + name, 32)
            if actual is not None and actual != wanted:
                self.error("manifest." + name + " disagrees with the fixed capture contract")
        if record.get("architecture") != "x86_64":
            self.error("manifest.architecture must be x86_64")
        for name in ("context_size", "group_timeout_ms"):
            value = self.uint(record.get(name), "manifest." + name, 32)
            if value == 0:
                self.error("manifest." + name + " must be nonzero")
        self.manifests.append(record)

    def add_record(self, record):
        self.current_key = None
        if not isinstance(record, dict):
            self.error("each JSONL record must be an object")
            return
        self.global_numbers(record)
        self.check_context_blob(record)
        kind = record.get("type")
        if not isinstance(kind, str) or kind not in RECORD_TYPES:
            self.error("unknown or missing record type")
            return
        self.record_counts[kind] += 1
        if kind == "manifest":
            self.check_manifest(record)
            return
        if kind == "group_result":
            self.check_group(record)
            return
        if kind == "thread_context":
            self.check_thread_context(record)
            return
        if kind in ("thread_cleanup", "thread_block_result"):
            self.check_thread_auxiliary(record, kind)
            return
        key = self.parse_key(record)
        if key is None:
            return
        self.current_key = key
        if kind == "run_start":
            self.required(record, ("stack_depth", "process_id", "arithmetic_flags_mask", "requested_arithmetic_flags",
                                   "instruction_site", "sled_start"), "run_start")
            for name in ("arithmetic_flags_mask", "requested_arithmetic_flags", "instruction_site", "sled_start"):
                self.uint(record.get(name), "run_start." + name)
            process_id = self.uint(record.get("process_id"), "run_start.process_id", 32)
            if process_id == 0:
                self.error("run_start.process_id must be nonzero")
            if self.starts[key]:
                self.error("duplicate run_start", "cardinality")
            if self.results[key] or self.observations[key]:
                self.error("run_start occurs after observations or terminal result", "sequence")
            if "stack_depth" in record:
                depth = self.uint(record["stack_depth"], "run_start.stack_depth", 32)
                if depth is not None and depth != key[4]:
                    self.error("run_start.stack_depth must equal the repeat's owned recursion depth")
            if "arithmetic_flags_mask" in record and hex_value(record["arithmetic_flags_mask"]) != 0x8d5:
                self.error("run_start.arithmetic_flags_mask must report the collector's 0x8d5 mask")
            if "requested_arithmetic_flags" in record:
                wanted = 0x8d5 if key[2] == "set" else 0
                if hex_value(record["requested_arithmetic_flags"]) != wanted:
                    self.error("requested arithmetic flags disagree with flag_seed")
            self.starts[key].append(record)
        elif kind == "observation":
            if not self.starts[key]:
                self.error("observation occurs before run_start", "sequence")
            if self.results[key]:
                self.error("observation occurs after terminal result", "sequence")
            self.observations[key].append(record)
            index = record.get("delivery_index")
            if isinstance(index, str) and HEX.fullmatch(index):
                if int(index, 16) != len(self.observations[key]):
                    self.error("delivery_index is not the next contiguous index", "sequence")
            self.check_observation(record, key)
        elif kind == "run_result":
            if self.results[key]:
                self.error("duplicate terminal run_result", "cardinality")
            if not self.starts[key] and record.get("status") not in ("runtime_aborted", "skipped"):
                self.error("terminal run_result has no preceding run_start", "cardinality")
            self.check_run_result(record)
            self.results[key].append(record)

    def read(self, stream):
        for number, line in enumerate(stream, 1):
            self.current_line = number
            self.line_count = number
            self.current_key = None
            if isinstance(line, bytes):
                self.sha256.update(line)
                try:
                    line = line.decode("utf-8-sig" if number == 1 else "utf-8")
                except UnicodeDecodeError as exc:
                    self.error("invalid UTF-8: " + str(exc), "parse")
                    continue
            else:
                self.sha256.update(line.encode("utf-8"))
                if number == 1:
                    line = line.lstrip("\ufeff")
            if not line.strip():
                self.error("blank lines are not JSONL records", "parse")
                continue
            try:
                record = json.loads(line, object_pairs_hook=duplicate_safe_object,
                                    parse_constant=reject_constant)
            except (ValueError, RecursionError) as exc:
                self.error("invalid JSON: " + str(exc), "parse")
                continue
            try:
                self.add_record(record)
            except RecursionError:
                self.error("record nesting is too deep", "schema")
        return self

    @staticmethod
    def variability_samples(samples):
        fields = collections.defaultdict(lambda: collections.defaultdict(list))
        for key, record in samples:
            payload = {name: record[name] for name in
                       ("exception", "context", "xstate", "gpr_differences")}
            for name, value in flatten(payload):
                fields[name][canonical(value)].append(hex(key[4]))
        unstable = []
        for name in sorted(fields):
            values = fields[name]
            if len(values) > 1:
                unstable.append({"field": name, "distinct_count": len(values), "values": [
                    {"value": json.loads(value), "repeats": repeats}
                    for value, repeats in sorted(values.items())]})
        return {"sample_count": len(samples),
                "repeats": [hex(k[4]) for k, _ in samples],
                "comparison_possible": len(samples) > 1,
                "unstable_fields": unstable}

    def build_variability(self):
        buckets = collections.defaultdict(list)
        for key in expected_keys():
            for record in self.valid_observations[key]:
                buckets[key[:4] + (int(record["delivery_index"], 16),)].append((key, record))
        result = []
        for group, samples in buckets.items():
            depths = collections.defaultdict(list)
            for key, record in samples:
                terminal = self.results[key][0] if self.results[key] else {}
                depth = terminal.get("stack_depth")
                if not isinstance(depth, str) or HEX.fullmatch(depth) is None:
                    start = self.starts[key][0] if self.starts[key] else {}
                    depth = start.get("stack_depth")
                if not isinstance(depth, str) or HEX.fullmatch(depth) is None:
                    depth = None
                else:
                    depth = hex(int(depth, 16))
                depths[depth].append((key, record))
            result.append({
                "group": dict(zip(KEY_FIELDS[:4], group[:4])),
                "delivery_index": hex(group[4]),
                "expected_repeats": REPEATS,
                "repeats_without_this_delivery": [hex(i) for i in range(REPEATS)
                                                  if i not in {k[4] for k, _ in samples}],
                "across_depths": self.variability_samples(samples),
                "within_depths": [dict({"stack_depth": depth}, **self.variability_samples(entries))
                                  for depth, entries in sorted(depths.items(), key=lambda item:
                                      -1 if item[0] is None else int(item[0], 16))],
            })
        return result

    def summary(self):
        self.current_key = None
        self.current_line = 0
        if not self.manifests:
            self.error("no manifest record was found", "manifest")
        elif len(self.manifests) != 1:
            self.error("exactly one global manifest is required", "manifest")
        expected = expected_keys()
        missing = []
        missing_starts = []
        status_lists = {name: [] for name in STATUSES}
        duplicate_terminals = []
        duplicate_starts = []
        no_exception = []
        started_without_result = []
        explicitly_not_started = []
        for key in expected:
            self.current_key = key
            results = self.results[key]
            starts = self.starts[key]
            observations = self.observations[key]
            if not results:
                missing.append(key_object(key))
                if starts:
                    started_without_result.append(key_object(key))
            if not starts:
                if results and results[0].get("status") in ("runtime_aborted", "skipped"):
                    explicitly_not_started.append(key_object(key))
                else:
                    missing_starts.append(key_object(key))
            if len(results) > 1:
                duplicate_terminals.append(key_object(key))
            if len(starts) > 1:
                duplicate_starts.append(key_object(key))
            if not results:
                continue
            terminal = results[0]
            depth = hex_value(terminal.get("stack_depth"))
            if depth is not None and depth != key[4]:
                self.error("run_result.stack_depth must equal the repeat's owned recursion depth")
            status = terminal.get("status")
            if isinstance(status, str) and status in status_lists:
                status_lists[status].append({"key": key_object(key), "reason": terminal.get("reason", "")})
            count = terminal.get("observation_count")
            if isinstance(count, str) and HEX.fullmatch(count):
                if int(count, 16) != len(observations):
                    self.error("run_result.observation_count disagrees with observation records", "cardinality")
            delivered = terminal.get("exception_delivered")
            if isinstance(delivered, bool) and delivered != bool(observations):
                self.error("exception_delivered disagrees with observation records", "cardinality")
            if status == "completed" and delivered is False:
                no_exception.append(key_object(key))
            if starts and "stack_depth" in starts[0] and "stack_depth" in terminal:
                first, last = starts[0]["stack_depth"], terminal["stack_depth"]
                if isinstance(first, str) and HEX.fullmatch(first) and isinstance(last, str) and HEX.fullmatch(last):
                    if int(first, 16) != int(last, 16):
                        self.error("stack_depth disagrees between run_start and run_result", "consistency")
            if starts and terminal.get("safety_escape") is False:
                site, sled = hex_value(starts[0].get("instruction_site")), hex_value(starts[0].get("sled_start"))
                entry, offset = hex_value(terminal.get("continuation_entry_offset")), hex_value(terminal.get("continuation_site_offset"))
                if all(n is not None for n in (site, sled, entry, offset)) and offset != sled - site + entry:
                    self.error("continuation_site_offset disagrees with sled/site addresses and measured entry")
        self.current_key = None
        thread_counts = collections.Counter()
        skipped_threads = []
        for record in self.thread_contexts:
            identity = tuple(record.get(n) for n in ("operation", "target", "request", "phase"))
            if all(isinstance(n, str) for n in identity) and identity in THREAD_KEYS:
                thread_counts[identity] += 1
                if record.get("status") == "skipped":
                    skipped_threads.append(dict(zip(("operation", "target", "request", "phase"), identity)))
        missing_threads = [dict(zip(("operation", "target", "request", "phase"), identity))
                           for identity in THREAD_KEYS if not thread_counts[identity]]
        for identity, count in thread_counts.items():
            if count > 1:
                self.error("duplicate thread_context identity: " + "/".join(identity), "cardinality")
        if not self.groups:
            self.warnings.append("No group_result records: child exit and timeout accounting is unavailable.")
        group_counts = collections.Counter()
        for record in self.groups:
            group = record.get("group")
            if isinstance(group, dict) and all(isinstance(group.get(n), str) for n in KEY_FIELDS[:4]):
                identity = tuple(group[n] for n in KEY_FIELDS[:4])
                group_counts[identity] += 1
                child_pid = hex_value(record.get("child_process_id"))
                for repeat in range(REPEATS):
                    for start in self.starts.get(identity + (repeat,), []):
                        if child_pid is not None and hex_value(start.get("process_id")) != child_pid:
                            self.error("run_start.process_id disagrees with its group_result.child_process_id", "consistency")
        if any(count > 1 for count in group_counts.values()):
            self.error("duplicate group_result identity", "cardinality")
        expected_groups = tuple(itertools.product(VARIANTS, OBSERVERS, FLAG_SEEDS, POLICIES))
        missing_groups = [dict(zip(KEY_FIELDS[:4], identity)) for identity in expected_groups
                          if not group_counts[identity]]
        for name, records in (("thread_cleanup", self.thread_cleanup),
                              ("thread_block_result", self.thread_blocks)):
            if len(records) > 1:
                self.error("duplicate " + name + " record", "cardinality")
        missing_auxiliary = []
        if not self.thread_blocks:
            missing_auxiliary.append("thread_block_result")
        if not self.thread_cleanup:
            missing_auxiliary.append("thread_cleanup")
        runtime_failures = []
        for record in self.thread_blocks + self.groups:
            causes = []
            if record.get("created") is False:
                causes.append("child_process_not_created")
            if record.get("reaped") is False:
                causes.append("child_process_not_reaped")
            if record.get("assigned") is False:
                causes.append("child_process_not_assigned_to_cleanup_job")
            if record.get("resumed") is False:
                causes.append("child_process_not_resumed")
            if record.get("timeout") is True:
                causes.append("child_timeout")
            if record.get("partial_record_dropped") is True:
                causes.append("partial_record_dropped")
            code = record.get("child_exit_code")
            if isinstance(code, str) and HEX.fullmatch(code) and int(code, 16) != 0:
                causes.append("child_exit_nonzero")
            query_error = record.get("exit_query_error")
            if isinstance(query_error, str) and HEX.fullmatch(query_error) and int(query_error, 16) != 0:
                causes.append("child_exit_query_failed")
            if causes:
                runtime_failures.append({"record_type": record["type"],
                                         "group": record.get("group"), "causes": causes})
        for record in self.thread_cleanup:
            incomplete = [name for name in ("created", "ready", "suspended", "resume_success", "thread_signaled")
                          if record.get(name) is False]
            if incomplete:
                runtime_failures.append({"record_type": "thread_cleanup", "group": None,
                                         "causes": ["owned_thread_cleanup_or_setup_failed"], "failed_fields": incomplete})
        aborted = status_lists["runtime_aborted"] + status_lists["guard_escape"]
        accounted = len(expected) - len(missing)
        coverage_complete = not missing and not missing_starts and not duplicate_terminals and not duplicate_starts
        successful_measurements = len(status_lists["completed"])
        valid = not self.errors
        accepted = valid and not aborted and not runtime_failures and (self.allow_incomplete or
                    (coverage_complete and not status_lists["skipped"] and not missing_threads
                     and not skipped_threads and not missing_auxiliary and not missing_groups))
        provenance = "synthetic_test_fixture" if any(m.get("synthetic") is True for m in self.manifests) else "input_file"
        summary = {
            "schema": "exception-observer-summary-v1",
            "data_provenance": provenance,
            "manifest": self.manifests[0] if self.manifests else None,
            "input": {"path": self.source, "sha256": self.sha256.hexdigest(),
                      "line_count": self.line_count, "record_counts": dict(self.record_counts)},
            "validation": {"passed": accepted, "structurally_valid": valid,
                           "allow_incomplete": self.allow_incomplete,
                           "error_count": len(self.errors), "errors": self.errors,
                           "runtime_failures": runtime_failures,
                           "warnings": self.warnings},
            "coverage": {
                "expected_run_count": len(expected), "accounted_run_count": accounted,
                "coverage_complete": coverage_complete,
                "all_runs_measured": successful_measurements == len(expected) and valid,
                "completed_count": successful_measurements,
                "unsupported_count": len(status_lists["requested_policy_unsupported"]),
                "skipped_count": len(status_lists["skipped"]), "aborted_count": len(aborted),
                "missing_count": len(missing), "missing": missing,
                "missing_starts": missing_starts,
                "explicitly_not_started": explicitly_not_started,
                "started_without_result": started_without_result,
                "duplicate_terminal_keys": duplicate_terminals,
                "duplicate_start_keys": duplicate_starts,
                "unsupported": status_lists["requested_policy_unsupported"],
                "skipped": status_lists["skipped"], "aborted": aborted,
                "completed_without_exception": no_exception,
            },
            "semantics": {
                "expected_unsupported_counts_as_accounted_coverage": True,
                "expected_unsupported_counts_as_completed_measurement": False,
                "no_exception_delivered_is_valid": True,
                "allow_incomplete_does_not_ignore_malformed_data_or_runtime_failures": True,
                "context_blob_validation": "hex_syntax_and_byte_count_only; structured fields are not decoded from redundant CONTEXT bytes",
            },
            "thread_context": {"expected_record_count": len(THREAD_KEYS),
                               "record_count": len(self.thread_contexts),
                               "coverage_complete": not missing_threads and len(thread_counts) == len(THREAD_KEYS),
                               "missing": missing_threads, "skipped": skipped_threads,
                               "missing_auxiliary_records": missing_auxiliary,
                               "records": self.thread_contexts,
                               "cleanup": self.thread_cleanup,
                               "block_results": self.thread_blocks},
            "group_results": self.groups,
            "group_coverage": {"expected_count": len(expected_groups), "record_count": len(self.groups),
                               "missing": missing_groups, "coverage_complete": not missing_groups
                               and not any(count > 1 for count in group_counts.values())},
            "variability": {"notes": VARIABILITY_NOTES, "groups": self.build_variability()},
        }
        # Never echo malformed numeric values from auxiliary raw records into a
        # summary. This conversion preserves evidence while keeping output legal.
        return json_hex_numbers(summary)


def check_file(path, allow_incomplete=False):
    checker = Checker(path, allow_incomplete)
    with pathlib.Path(path).open("rb") as source:
        checker.read(source)
    return checker.summary()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("raw", type=pathlib.Path, help="raw JSONL capture")
    parser.add_argument("--summary", type=pathlib.Path, default=pathlib.Path("summary.json"))
    parser.add_argument("--allow-incomplete", action="store_true",
                        help="permit missing/skipped matrix keys, but never malformed data or runtime failures")
    args = parser.parse_args(argv)
    if args.raw.resolve() == args.summary.resolve():
        parser.error("--summary must not overwrite the raw input")
    try:
        summary = check_file(args.raw, args.allow_incomplete)
        args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        print("check_results: " + str(exc), file=sys.stderr)
        return 2
    coverage = summary["coverage"]
    print("coverage " + coverage["accounted_run_count"] + "/" + coverage["expected_run_count"] +
          "; completed " + coverage["completed_count"] + "; unsupported " + coverage["unsupported_count"] +
          "; missing " + coverage["missing_count"] + "; errors " + summary["validation"]["error_count"])
    return 0 if summary["validation"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
