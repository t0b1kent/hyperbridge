#!/usr/bin/env python3
"""Validate v5 own-process Windows probe JSONL using Python's standard library.

This validates raw schema, internal consistency, and the fixed capture matrix.
It is not a Windows behavioral oracle. No expected exception code, delivery,
callback order, TF outcome, API result, or successful continuation is assumed.
Synthetic tests do not establish native Windows correctness.

Exit 0: structurally valid, no runtime failure, coverage accounted (unsupported
policies are separate from measurements). --allow-incomplete permits missing or
skipped coverage only. Exit 1: validation/coverage/runtime failure. Exit 2: I/O
or invocation error. Every numerical raw/summary value is a hexadecimal string.
"""

import argparse
import collections
import hashlib
import itertools
import json
import pathlib
import re
import sys

POINTER_VARIANTS = ("int2d_stack", "int2d_heap", "int2d_function", "int2d_static")
PART1_VARIANTS = POINTER_VARIANTS + ("int2d_6", "int2d_7", "int2d_8", "int2d_f",
    "int2d_11", "int2d_100", "int2d_ffffffff", "int2d_8000000000000000")
PART2_VARIANTS = ("ctx_int2d_0", "ctx_int2d_stack", "ctx_int3_cc")
API_VARIANTS = ("debugbreak", "output_a", "output_w", "is_debugger_present",
                "check_remote_debugger_present")
VARIANTS = PART1_VARIANTS + PART2_VARIANTS + API_VARIANTS
OBSERVERS = ("veh", "seh", "uef", "veh_seh")
FLAG_SEEDS = ("clear", "set")
POLICIES = ("advance", "keep_then_advance", "rip_plus_length", "alternate", "enable_tf",
            "veh_search_seh", "vch_order", "api_keep")
REPEATS = 20
KEY_FIELDS = ("variant", "observer", "flag_seed", "policy", "repeat")
STATUSES = ("completed", "requested_policy_unsupported", "guard_escape", "runtime_aborted", "skipped")
RECORD_TYPES = ("manifest", "run_start", "observation", "run_result", "group_result")
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

NUMERIC_NAMES = set(CONTEXT_BITS) | set(EXCEPTION_BITS) | set(GPRS) | {
    "repeat", "delivery_index", "callback_ordinal", "observation_count", "delivery_count", "vch_count",
    "continuation_entry_offset", "continuation_site_offset", "post_rax", "post_rflags", "post_rsp",
    "pre_rsp", "stack_depth", "proposed_rip", "actual_rip", "total_length", "process_id",
    "instruction_length", "instruction_site", "sled_start", "group_index", "child_terminal_records",
    "schema_version", "planned_runs", "variants", "observers", "flag_seeds", "policies", "repeats",
    "groups", "group_timeout_ms", "context_size", "native_processor_architecture",
    "exception_information_valid_slots", "arithmetic_flags_mask", "requested_arithmetic_flags",
    "family", "part", "rax_input", "exception_count", "initial_delivery_count", "second_trap_count",
    "api_return_value", "api_last_error", "post_eflags", "mutated_eflags", "actual_eflags",
    "alternate_site", "probe_end", "sled_end", "post_site", "api_function_address",
}
PROCESS_BOOLEANS = ("created", "assigned", "resumed", "reaped", "timeout", "partial_record_dropped")
PROCESS_NUMERIC = ("create_error", "assign_error", "resume_error", "wait_status", "terminate_error",
    "child_exit_code", "exit_query_error", "child_process_id", "child_thread_id", "wait_error",
    "cleanup_wait_status", "cleanup_wait_error")
NUMERIC_NAMES.update(PROCESS_NUMERIC)
NUMERIC_NAMES.update({'capture_marker', 'requested_rax', 'post_rsp_raw', 'last_pushfq_rflags', 'probe_fn', 'alternate_fn', 'alternate_end', 'return_value', 'remote_present', 'last_error', 'families'})


def applicable(variant, observer, policy):
    if variant in PART1_VARIANTS:
        return observer in OBSERVERS[:3] and policy in POLICIES[:2]
    if variant in PART2_VARIANTS:
        return ((observer in OBSERVERS[:3] and policy in ("rip_plus_length", "alternate", "enable_tf", "vch_order"))
                or (observer == "veh_seh" and policy == "veh_search_seh"))
    return variant in API_VARIANTS and observer == "veh" and policy == "api_keep"


def expected_groups():
    return tuple((v, o, s, p) for v, o, s, p in itertools.product(VARIANTS, OBSERVERS, FLAG_SEEDS, POLICIES)
                 if applicable(v, o, p))


def expected_keys():
    return tuple(group + (repeat,) for group in expected_groups() for repeat in range(REPEATS))


def key_object(key):
    return dict(zip(KEY_FIELDS, key[:4] + (hex(key[4]),)))


def part_for(variant):
    return 1 if variant in PART1_VARIANTS else 2 if variant in PART2_VARIANTS else 3


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
        self.line_count = 0
        self.sha256 = hashlib.sha256()
        self.current_key = None
        self.current_line = 0
        self._summary = None
        self.finished_groups = set()

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

    def parse_key(self, record, group=False):
        name = 'group' if group else 'key'
        fields = KEY_FIELDS[:4] if group else KEY_FIELDS
        obj = self.mapping(record.get(name), name)
        self.required(obj, fields, name)
        valid = set(obj) == set(fields)
        if not valid:
            self.error(name + ' must contain exactly ' + ', '.join(fields), 'key')
        values = []
        for field, choices in zip(KEY_FIELDS[:4], (VARIANTS, OBSERVERS, FLAG_SEEDS, POLICIES)):
            value = obj.get(field)
            if not isinstance(value, str) or value not in choices:
                self.error(name + '.' + field + ' is outside the fixed matrix', 'key')
                valid = False
            values.append(value)
        if valid and not applicable(values[0], values[1], values[3]):
            self.error(name + ' variant/observer/policy combination is outside the fixed matrix', 'key')
            valid = False
        if not group:
            repeat = self.uint(obj.get('repeat'), name + '.repeat', 32)
            if repeat is None or repeat >= REPEATS:
                self.error(name + '.repeat is outside 0x0..0x13', 'key')
                valid = False
            values.append(repeat)
        return tuple(values) if valid else None

    def check_register_map(self, obj, path, required_names, bits=64):
        obj = self.mapping(obj, path)
        self.required(obj, required_names, path)
        for name, value in obj.items():
            if name not in required_names:
                self.error(path + ' contains unknown register ' + name)
            self.uint(value, path + '.' + name, bits)
            if bits == 128 and isinstance(value, str) and HEX.fullmatch(value) and len(value) != 34:
                self.error(path + '.' + name + ' must contain exactly 0x10 bytes (32 hexadecimal digits)')
        return obj

    def check_name_list(self, value, names, path):
        if not isinstance(value, list) or any(not isinstance(n, str) for n in value):
            self.error(path + ' must be an array of names')
            return None
        if len(set(value)) != len(value) or any(n not in names for n in value):
            self.error(path + ' contains duplicates or unknown names')
            return None
        return value

    def check_context_blob(self, record):
        self.required(record, ('context_bytes_hex', 'context_size'), 'observation')
        blob = record.get('context_bytes_hex')
        size = self.uint(record.get('context_size'), 'context_size', 32)
        if not isinstance(blob, str) or HEX.fullmatch(blob) is None or (len(blob) - 2) % 2:
            self.error('context_bytes_hex must be a 0x-prefixed whole-byte hex blob')
            return
        if size is not None and (len(blob) - 2) // 2 != size:
            self.error('context_bytes_hex byte length disagrees with context_size')
        if self.manifests and size != hex_value(self.manifests[0].get('context_size')):
            self.error('observation.context_size disagrees with manifest.context_size')

    def check_manifest(self, record):
        expected = {'schema_version': 5, 'planned_runs': 4640, 'variants': 20,
                    'flag_seeds': 2, 'repeats': 20, 'groups': 232, 'families': 3, 'observers': 4, 'policies': 8}
        self.required(record, tuple(expected) + ('architecture', 'context_size', 'group_timeout_ms'), 'manifest')
        for name, wanted in expected.items():
            actual = self.uint(record.get(name), 'manifest.' + name, 32)
            if actual is not None and actual != wanted:
                self.error('manifest.' + name + ' disagrees with the fixed capture contract')
        if record.get('architecture') != 'x86_64':
            self.error('manifest.architecture must be x86_64')
        for name in ('context_size', 'group_timeout_ms'):
            value = self.uint(record.get(name), 'manifest.' + name, 32)
            if value == 0:
                self.error('manifest.' + name + ' must be nonzero')
        if 'synthetic' in record:
            self.boolean(record['synthetic'], 'manifest.synthetic')
        if self.record_counts['manifest'] != 1 or sum(self.record_counts.values()) != 1:
            self.error('exactly one manifest is required as the first record', 'sequence')
        self.manifests.append(record)

    def check_process_fields(self, record):
        kind = 'group_result'
        self.required(record, PROCESS_BOOLEANS + PROCESS_NUMERIC, kind)
        for name in PROCESS_BOOLEANS:
            self.boolean(record.get(name), kind + '.' + name)
        for name in PROCESS_NUMERIC:
            self.uint(record.get(name), kind + '.' + name, 32)
        if record.get('created') is False and any(record.get(n) is True for n in ('assigned', 'resumed', 'reaped')):
            self.error(kind + ' cannot assign, resume, or reap a child that was not created')
        if record.get('resumed') is True and record.get('assigned') is not True:
            self.error(kind + ' resumed a child without the owned cleanup job')
        if record.get('created') is True:
            for name in ('child_process_id', 'child_thread_id'):
                if hex_value(record.get(name)) == 0:
                    self.error(kind + '.' + name + ' must be nonzero for a created child')
        wait = hex_value(record.get('wait_status'))
        cleanup = hex_value(record.get('cleanup_wait_status'))
        if wait is not None and cleanup is not None and isinstance(record.get('reaped'), bool):
            if record['reaped'] != (wait == 0 or cleanup == 0):
                self.error(kind + '.reaped disagrees with initial and cleanup wait statuses')
        if wait is not None and isinstance(record.get('timeout'), bool):
            if record['timeout'] != (wait == 0x102):
                self.error(kind + '.timeout disagrees with initial wait_status')

    def check_group(self, record):
        identity = self.parse_key(record, group=True)
        self.required(record, ('group_index', 'child_terminal_records'), 'group_result')
        self.check_process_fields(record)
        index = self.uint(record.get('group_index'), 'group_result.group_index', 32)
        count = self.uint(record.get('child_terminal_records'), 'group_result.child_terminal_records', 32)
        if identity is not None and index is not None and expected_groups().index(identity) != index:
            self.error('group_result.group_index disagrees with fixed matrix order')
        if count is not None and count > REPEATS:
            self.error('group_result.child_terminal_records exceeds 0x14')
        self.groups.append(record)
        if identity is not None:
            self.finished_groups.add(identity)

    def check_start(self, record, key):
        names = ('stack_depth', 'process_id', 'arithmetic_flags_mask', 'requested_arithmetic_flags',
                 'instruction_site', 'sled_start')
        self.required(record, names, 'run_start')
        for name in ('arithmetic_flags_mask', 'requested_arithmetic_flags', 'instruction_site', 'sled_start'):
            self.uint(record.get(name), 'run_start.' + name)
        pid = self.uint(record.get('process_id'), 'run_start.process_id', 32)
        if pid == 0:
            self.error('run_start.process_id must be nonzero')
        depth = self.uint(record.get('stack_depth'), 'run_start.stack_depth', 32)
        if depth is not None and depth != key[4]:
            self.error('run_start.stack_depth must equal repeat')
        if hex_value(record.get('arithmetic_flags_mask')) != 0x8d5:
            self.error('arithmetic_flags_mask must report the collector 0x8d5 mask')
        if hex_value(record.get('requested_arithmetic_flags')) != (0x8d5 if key[2] == 'set' else 0):
            self.error('requested_arithmetic_flags disagrees with flag_seed')
    def read(self, stream):
        for number, line in enumerate(stream, 1):
            self.current_line = self.line_count = number
            self.current_key = None
            if isinstance(line, bytes):
                self.sha256.update(line)
                try:
                    line = line.decode('utf-8-sig' if number == 1 else 'utf-8')
                except UnicodeDecodeError as exc:
                    self.error('invalid UTF-8: ' + str(exc), 'parse')
                    continue
            else:
                self.sha256.update(line.encode('utf-8'))
                if number == 1:
                    line = line.lstrip('\ufeff')
            if not line.strip():
                self.error('blank lines are not JSONL records', 'parse')
                continue
            try:
                record = json.loads(line, object_pairs_hook=duplicate_safe_object, parse_constant=reject_constant)
            except (ValueError, RecursionError) as exc:
                self.error('invalid JSON: ' + str(exc), 'parse')
                continue
            try:
                self.add_record(record)
            except RecursionError:
                self.error('record nesting is too deep', 'schema')
        return self

    @staticmethod
    def variability_samples(samples):
        fields = collections.defaultdict(lambda: collections.defaultdict(list))
        for key, payload in samples:
            for name, value in flatten(payload):
                fields[name][canonical(value)].append(hex(key[4]))
        changed = []
        for name in sorted(fields):
            values = fields[name]
            if len(values) > 1:
                changed.append({'field': name, 'distinct_count': len(values), 'values': [
                    {'value': json.loads(value), 'repeats': repeats} for value, repeats in sorted(values.items())]})
        return {'sample_count': len(samples), 'repeats': [hex(k[4]) for k, _ in samples],
                'comparison_possible': len(samples) > 1, 'unstable_fields': changed}

    def build_variability(self):
        buckets = collections.defaultdict(list)
        post_buckets = collections.defaultdict(list)
        for key in expected_keys():
            for record in self.valid_observations[key]:
                identity = (record.get('callback_ordinal'), record.get('delivery_index'), record.get('observer'), record.get('stage'))
                payload = {n: record.get(n) for n in ('exception', 'context', 'xstate', 'gpr_differences', 'continuation')}
                buckets[key[:4] + identity].append((key, payload))
            for record in self.results[key][:1]:
                if record.get('probe_returned') is True:
                    payload = {n: record.get(n) for n in ('post_gpr', 'post_rflags', 'last_pushfq_rflags', 'post_rsp_raw', 'pre_rsp',
                               'continuation_entry_offset', 'continuation_site_offset', 'callback_order', 'api_result')}
                    post_buckets[key[:4]].append((key, payload))
        def grouped(group, samples):
            return {'group': dict(zip(KEY_FIELDS[:4], group[:4])),
                    'across_depths': self.variability_samples(samples),
                    'within_depths': [dict({'stack_depth': hex(key[4])}, **self.variability_samples([(key, payload)]))
                                      for key, payload in samples],
                    'repeats_without_sample': [hex(i) for i in range(REPEATS) if i not in {key[4] for key, _ in samples}]}
        observations = []
        for group, samples in buckets.items():
            entry = grouped(group, samples)
            entry.update(dict(zip(('callback_ordinal', 'delivery_index', 'observer', 'stage'), group[4:])))
            observations.append(entry)
        return {'notes': ['Descriptive variability only; no Windows behavior is assumed.',
                          'Absolute addresses, stack contents, and ABI state may vary legitimately.',
                          'Each repeat has a distinct owned recursion depth; within-depth single samples cannot establish stability.',
                          'Callback identity is separate from logical delivery identity; VCH does not become another delivery.',
                          'Offsets and TF state are retained verbatim; differences are not normalized away.'],
                'observations': observations, 'post_state': [grouped(g, s) for g, s in post_buckets.items()]}

    def summary(self):
        if self._summary is not None:
            return self._summary
        self.current_key = None
        self.current_line = 0
        if len(self.manifests) != 1:
            self.error('exactly one manifest is required; found ' + str(len(self.manifests)), 'manifest')
        missing, missing_starts, not_started, unfinished = [], [], [], []
        duplicate_starts, duplicate_results, no_exception = [], [], []
        statuses = {name: [] for name in STATUSES}
        for key in expected_keys():
            self.current_key = key
            starts, results, observations = self.starts[key], self.results[key], self.observations[key]
            if not results:
                missing.append(key_object(key))
                if starts:
                    unfinished.append(key_object(key))
            if not starts:
                if results and results[0].get('status') in ('runtime_aborted', 'skipped'):
                    not_started.append(key_object(key))
                else:
                    missing_starts.append(key_object(key))
            if len(starts) > 1:
                duplicate_starts.append(key_object(key))
            if len(results) > 1:
                duplicate_results.append(key_object(key))
            if not results:
                continue
            record = results[0]
            status = record.get('status')
            if isinstance(status, str) and status in statuses:
                statuses[status].append({'key': key_object(key), 'reason': record.get('reason')})
            if status == 'completed' and record.get('exception_delivered') is False:
                no_exception.append(key_object(key))
            self.check_run_consistency(key, starts, observations, record)
        self.current_key = None
        group_counts = collections.Counter()
        runtime_failures = []
        for record in self.groups:
            group = record.get('group')
            identity = tuple(group.get(n) for n in KEY_FIELDS[:4]) if isinstance(group, dict) else None
            if identity is not None and all(isinstance(n, str) for n in identity) and identity in expected_groups():
                group_counts[identity] += 1
                actual_child_results = 0
                for repeat in range(REPEATS):
                    key = identity + (repeat,)
                    for start in self.starts[key]:
                        if hex_value(start.get('process_id')) != hex_value(record.get('child_process_id')):
                            self.error('run_start.process_id disagrees with group_result.child_process_id', 'consistency')
                    actual_child_results += sum(1 for result in self.results[key] if result.get('synthesized_by_parent') is False)
                count = hex_value(record.get('child_terminal_records'))
                if count is not None and count != actual_child_results:
                    self.error('group_result.child_terminal_records disagrees with non-parent terminal records', 'cardinality')
            causes = []
            for name in ('created', 'assigned', 'resumed', 'reaped'):
                if record.get(name) is False:
                    causes.append('child_' + name + '_false')
            for name in ('timeout', 'partial_record_dropped'):
                if record.get(name) is True:
                    causes.append(name)
            for name in ('child_exit_code', 'exit_query_error'):
                number = hex_value(record.get(name))
                if number is not None and number != 0:
                    causes.append(name + '_nonzero')
            if causes:
                runtime_failures.append({'group': group, 'causes': causes})
        duplicates = [dict(zip(KEY_FIELDS[:4], g)) for g, count in group_counts.items() if count > 1]
        if duplicates:
            self.error('duplicate group_result identity', 'cardinality')
        missing_groups = [dict(zip(KEY_FIELDS[:4], g)) for g in expected_groups() if not group_counts[g]]
        coverage_complete = not (missing or missing_starts or duplicate_starts or duplicate_results)
        aborted = statuses['runtime_aborted'] + statuses['guard_escape']
        structural = not self.errors
        accepted = structural and not aborted and not runtime_failures and (self.allow_incomplete or
                    (coverage_complete and not statuses['skipped'] and not missing_groups))
        completed = len(statuses['completed'])
        attempted = sum(bool(self.starts[k]) for k in expected_keys())
        parts = []
        for part in (1, 2, 3):
            keys = [k for k in expected_keys() if part_for(k[0]) == part]
            parts.append({'part': part, 'planned_count': len(keys),
                'attempted_count': sum(bool(self.starts[k]) for k in keys),
                'accounted_count': sum(bool(self.results[k]) for k in keys),
                'completed_count': sum(bool(self.results[k]) and self.results[k][0].get('status') == 'completed' for k in keys)})
        result = {'schema': 'exception-observer-summary-v5',
            'data_provenance': 'synthetic_test_fixture' if any(m.get('synthetic') is True for m in self.manifests) else 'input_file_not_authenticated',
            'manifest': self.manifests[0] if self.manifests else None,
            'input': {'path': self.source, 'sha256': self.sha256.hexdigest(), 'line_count': self.line_count,
                      'record_counts': dict(self.record_counts)},
            'validation': {'passed': accepted, 'structurally_valid': structural, 'allow_incomplete': self.allow_incomplete,
                           'error_count': len(self.errors), 'errors': self.errors, 'warnings': self.warnings,
                           'runtime_failures': runtime_failures},
            'coverage': {'expected_run_count': len(expected_keys()), 'planned_run_count': len(expected_keys()),
                'attempted_run_count': attempted, 'accounted_run_count': len(expected_keys()) - len(missing),
                'coverage_complete': coverage_complete, 'all_runs_measured': completed == len(expected_keys()) and structural and not runtime_failures,
                'completed_count': completed, 'unsupported_count': len(statuses['requested_policy_unsupported']),
                'skipped_count': len(statuses['skipped']), 'aborted_count': len(aborted),
                'missing_count': len(missing), 'missing': missing, 'missing_starts': missing_starts,
                'explicitly_not_started': not_started, 'started_without_result': unfinished,
                'duplicate_start_keys': duplicate_starts, 'duplicate_terminal_keys': duplicate_results,
                'unsupported': statuses['requested_policy_unsupported'], 'skipped': statuses['skipped'], 'aborted': aborted,
                'completed_without_exception': no_exception, 'parts': parts},
            'group_coverage': {'expected_count': len(expected_groups()), 'record_count': len(self.groups), 'missing': missing_groups,
                               'duplicates': duplicates, 'coverage_complete': not missing_groups and not duplicates},
            'group_results': self.groups,
            'semantics': {'native_windows_behavior_verified': False,
                'checker_is_behavioral_oracle': False, 'no_exception_delivered_is_valid': True,
                'validation_does_not_authenticate_machine_or_OS_provenance': True,
                'unsupported_is_accounted_not_measured': True,
                'allow_incomplete_does_not_ignore_malformed_data_or_runtime_failures': True,
                'context_blob_validation': 'hex_syntax_and_byte_count_only; structured fields are not decoded from redundant CONTEXT bytes'},
            'variability': self.build_variability()}
        self._summary = json_hex_numbers(result)
        return self._summary
    def check_location(self, obj, address_name, offset_name, location_name, record, path):
        location = obj.get(location_name)
        choices = ('owned_probe', 'owned_alternate', 'inside_system_library', 'unclassified_address')
        if location not in choices:
            self.error(path + '.' + location_name + ' must identify an owned, system, or unclassified address')
        reference = obj.get(offset_name + 'Reference')
        expected_reference = 'instruction_site' if location == 'owned_probe' else ('alternate_sled_start' if location == 'owned_alternate' else 'none')
        if reference != expected_reference:
            self.error(path + '.' + offset_name + 'Reference disagrees with location')
        absolute = hex_value(obj.get(address_name))
        fn, end = hex_value(record.get('probe_fn')), hex_value(record.get('probe_end'))
        afn, aend = hex_value(record.get('alternate_fn')), hex_value(record.get('alternate_end'))
        if all(v is not None for v in (absolute, fn, end, afn, aend)):
            owned = 'owned_probe' if fn <= absolute < end else ('owned_alternate' if afn <= absolute < aend else None)
            if owned is not None and location != owned:
                self.error(path + '.' + location_name + ' disagrees with recorded owned bounds')
            if owned is None and location in choices[:2]:
                self.error(path + '.' + location_name + ' falsely claims an owned range')
        offset = obj.get(offset_name)
        if location in choices[:2]:
            relative = self.address_offset(offset, path + '.' + offset_name)
            base = hex_value(record.get('instruction_site' if location == 'owned_probe' else 'alternate_sled_start'))
            absolute = hex_value(obj.get(address_name))
            if base is not None and absolute is not None and relative is not None and absolute - base != relative:
                self.error(path + '.' + offset_name + ' disagrees with its declared owned origin')
        elif offset is not None:
            self.error(path + '.' + offset_name + ' must be null outside owned code; no system-code offsets')

    def check_reference(self, value, path):
        obj = self.mapping(value, path)
        self.required(obj, ('symbol', 'offset', 'dereferenced'), path)
        if obj.get('dereferenced') is not False:
            self.error(path + '.dereferenced must be false')
        if obj.get('symbol') is None:
            if obj.get('offset') is not None:
                self.error(path + '.offset must be null for an unclassified value')
        else:
            symbols = ('own_debug_a', 'own_debug_w', 'own_stack_variable', 'own_heap_block',
                       'own_static_variable', 'probe_int2d')
            if obj.get('symbol') not in symbols:
                self.error(path + '.symbol is outside the fixed owned symbols')
            self.address_offset(obj.get('offset'), path + '.offset')
        return obj

    def check_observation(self, record, key):
        names = ('callback_ordinal', 'delivery_index', 'observer', 'stage', 'exception', 'context',
                 'gpr_expected', 'gpr_differences', 'xmm_differences', 'xstate', 'continuation',
                 'instruction_site', 'sled_start', 'instruction_length', 'offset_reference',
                 'context_field_semantics', 'exception_information_valid_slots', 'register_interpretation')
        self.required(record, names, 'observation')
        self.check_context_blob(record)
        ordinal = self.uint(record.get('callback_ordinal'), 'callback_ordinal', 32)
        if ordinal is not None and not 1 <= ordinal <= 32:
            self.error('callback_ordinal is outside the fixed 0x20-slot capture buffer')
        self.uint(record.get('delivery_index'), 'delivery_index', 32)
        who = record.get('observer')
        permitted = ('veh', 'seh') if key[1] == 'veh_seh' else (key[1],)
        if key[3] == 'vch_order':
            permitted += ('vch',)
        if who not in permitted:
            self.error('observation.observer was not registered for this key')
        stage = record.get('stage')
        if stage not in ('initial', 'second_trap', 'other', 'continue_callback'):
            self.error('observation.stage is unknown')
        if (who == 'vch') != (stage == 'continue_callback'):
            self.error('continue_callback stage must identify only a VCH observation')
        for name in ('instruction_site', 'sled_start'):
            self.uint(record.get(name), 'observation.' + name)
        for name in ('alternate_sled_start', 'probe_fn', 'probe_end'):
            if name in record:
                self.uint(record[name], 'observation.' + name)
        api = key[0] in API_VARIANTS
        if record.get('offset_reference') != 'per_field_location_reference':
            self.error('offset_reference disagrees with variant')
        if api:
            if record.get('instruction_length') is not None:
                self.error('API instruction_length must be null; no library opcode is decoded')
        else:
            wanted = 1 if key[0] == 'ctx_int3_cc' else 2
            if self.uint(record.get('instruction_length'), 'instruction_length', 32) != wanted:
                self.error('instruction_length disagrees with the fixed owned instruction')
        if record.get('context_field_semantics') != 'raw_bytes_validity_depends_on_returned_ContextFlags':
            self.error('context_field_semantics must preserve raw-field validity qualification')
        if record.get('register_interpretation') != ('api_pre_call_differences_not_preservation_failures' if api else 'instruction_entry_seed_comparison'):
            self.error('register_interpretation disagrees with variant')
        exception = self.mapping(record.get('exception'), 'exception')
        self.required(exception, tuple(EXCEPTION_BITS) + ('ExceptionInformation', 'ExceptionAddressLocation', 'ExceptionAddressOffsetReference', 'parameter_references'), 'exception')
        for name, bits in EXCEPTION_BITS.items():
            if name not in SIGNED_FIELDS:
                self.uint(exception.get(name), 'exception.' + name, bits)
        count = hex_value(exception.get('NumberParameters'))
        if count is not None and count > 15:
            self.warnings.append({'key': key_object(key), 'field': 'exception.NumberParameters',
                'value': exception.get('NumberParameters'), 'message': 'Reported parameter count exceeds the physical fifteen-slot record; preserved as a runtime diagnostic, not a schema error.'})
        info = exception.get('ExceptionInformation')
        if not isinstance(info, list) or len(info) != 15:
            self.error('exception.ExceptionInformation must contain exactly fifteen raw slots')
        else:
            for i, value in enumerate(info):
                self.uint(value, 'exception.ExceptionInformation[' + str(i) + ']')
        references = exception.get('parameter_references')
        if not isinstance(references, list) or len(references) != 15:
            self.error('exception.parameter_references must contain exactly fifteen entries')
        else:
            for i, reference in enumerate(references):
                self.check_reference(reference, 'exception.parameter_references[' + str(i) + ']')
        valid_slots = self.uint(record.get('exception_information_valid_slots'), 'exception_information_valid_slots', 32)
        if count is not None and valid_slots is not None and valid_slots != min(count, 15):
            self.error('exception_information_valid_slots disagrees with NumberParameters')
        self.check_location(exception, 'ExceptionAddress', 'ExceptionAddressOffset', 'ExceptionAddressLocation', record, 'exception')
        context = self.mapping(record.get('context'), 'context')
        self.required(context, tuple(CONTEXT_BITS) + ('gpr', 'xmm', 'RipLocation', 'RipOffsetReference'), 'context')
        for name, bits in CONTEXT_BITS.items():
            if name not in SIGNED_FIELDS:
                self.uint(context.get(name), 'context.' + name, bits)
        self.check_location(context, 'Rip', 'RipOffset', 'RipLocation', record, 'context')
        actual = self.check_register_map(context.get('gpr'), 'context.gpr', GPRS)
        xmm = self.check_register_map(context.get('xmm'), 'context.xmm', tuple('Xmm' + str(i) for i in range(16)), 128)
        expected = self.check_register_map(record.get('gpr_expected'), 'gpr_expected', GPRS)
        rsp, mod, gpr_rsp = hex_value(context.get('Rsp')), hex_value(context.get('RspMod16')), hex_value(actual.get('Rsp'))
        if rsp is not None and mod is not None and rsp % 16 != mod:
            self.error('context.RspMod16 disagrees with context.Rsp')
        if rsp is not None and gpr_rsp is not None and rsp != gpr_rsp:
            self.error('context.Rsp disagrees with context.gpr.Rsp')
        differences = self.check_name_list(record.get('gpr_differences'), GPRS, 'gpr_differences')
        if differences is not None and all(hex_value(actual.get(n)) is not None and hex_value(expected.get(n)) is not None for n in GPRS):
            if set(differences) != {n for n in GPRS if hex_value(actual[n]) != hex_value(expected[n])}:
                self.error('gpr_differences does not match context.gpr versus gpr_expected')
        xmm_differences = self.check_name_list(record.get('xmm_differences'), tuple('Xmm' + str(i) for i in range(16)), 'xmm_differences')
        if xmm_differences is not None and all(isinstance(xmm.get('Xmm' + str(i)), str) and HEX.fullmatch(xmm['Xmm' + str(i)]) and len(xmm['Xmm' + str(i)]) == 34 for i in range(16)):
            wanted = set()
            for i in range(16):
                seed = (0x5a00000000000000 + i).to_bytes(8, 'little') + (0xa500000000000000 + i).to_bytes(8, 'little')
                if bytes.fromhex(xmm['Xmm' + str(i)][2:]) != seed:
                    wanted.add('Xmm' + str(i))
            if set(xmm_differences) != wanted:
                self.error('xmm_differences does not match the fixed owned XMM seeds')
        xstate = self.mapping(record.get('xstate'), 'xstate')
        self.required(xstate, ('present', 'total_length', 'length_status'), 'xstate')
        present = self.boolean(xstate.get('present'), 'xstate.present')
        flags = hex_value(context.get('ContextFlags'))
        if present is not None and flags is not None and present != bool(flags & 0x40):
            self.error('xstate.present disagrees with the raw 0x40 ContextFlags bit')
        if xstate.get('total_length') is not None:
            self.error('xstate.total_length must be null; borrowed extended size is unknown')
        if xstate.get('length_status') != 'unavailable_documented_size_for_borrowed_context':
            self.error('xstate.length_status must explicitly preserve unavailable size')
        self.check_continuation(record, key)

    def check_continuation(self, record, key):
        continuation = self.mapping(record.get('continuation'), 'continuation')
        self.required(continuation, ('requested_policy', 'action', 'proposed_rip', 'actual_rip', 'tf_cleared', 'tf_set', 'reason'), 'continuation')
        if continuation.get('requested_policy') != key[3]:
            self.error('continuation.requested_policy disagrees with key')
        action = continuation.get('action')
        if action not in ('keep', 'advance', 'alternate', 'set_tf_owned_sled', 'clear_tf_keep', 'search', 'observe_only', 'escape', 'terminate'):
            self.error('continuation.action is unknown')
        proposed = self.uint(continuation.get('proposed_rip'), 'continuation.proposed_rip', nullable=True)
        actual = self.uint(continuation.get('actual_rip'), 'continuation.actual_rip', nullable=True)
        cleared = self.boolean(continuation.get('tf_cleared'), 'continuation.tf_cleared')
        tf_set = self.boolean(continuation.get('tf_set'), 'continuation.tf_set')
        self.string(continuation.get('reason'), 'continuation.reason', nonempty=False)
        context = record.get('context') if isinstance(record.get('context'), dict) else {}
        rip = hex_value(context.get('Rip'))
        flags = hex_value(context.get('EFlags'))
        if cleared is True and flags is not None and not flags & 0x100:
            self.error('tf_cleared cannot claim an incoming TF bit that was absent')
        if cleared is True and tf_set is True:
            self.error('tf_cleared and tf_set cannot both be true')
        if action in ('keep', 'clear_tf_keep', 'search', 'observe_only') and rip is not None:
            if actual != rip or proposed != rip:
                self.error(action + ' must preserve both recorded RIP targets')
        if action in ('observe_only', 'search') and (cleared is not False or tf_set is not False):
            self.error(action + ' callback must not mutate TF')
        if (record.get('observer') == 'vch') != (action == 'observe_only'):
            self.error('VCH must be read-only observe_only, and other handlers cannot claim that action')
        if action == 'search' and not (key[3] == 'veh_search_seh' and record.get('observer') == 'veh'):
            self.error('search action is only the registered VEH-to-SEH chain')
        if action == 'escape':
            fn, end = hex_value(record.get('probe_fn')), hex_value(record.get('probe_end'))
            if all(n is not None for n in (fn, end, actual)) and not fn <= actual < end:
                self.error('escape actual_rip must remain in owned probe cleanup code')
        if action == 'terminate':
            if actual is not None:
                self.error('terminate must have null actual_rip')
        elif actual is None:
            self.error('non-terminating continuation requires actual_rip')
        if action in ('advance', 'alternate', 'set_tf_owned_sled') and (proposed is None or actual != proposed):
            self.error(action + ' actual_rip must equal proposed_rip')
        if action == 'advance':
            length = hex_value(record.get('instruction_length'))
            if length is None:
                self.error('advance cannot infer a system API instruction length')
            elif rip is not None and proposed != (rip + length) & ((1 << 64) - 1):
                self.error('advance proposed_rip disagrees with sampled Rip plus instruction_length')
        if action == 'alternate':
            if key[3] != 'alternate':
                self.error('alternate action requires alternate policy')
            target = hex_value(record.get('alternate_sled_start'))
            if target is not None and proposed != target:
                self.error('alternate target disagrees with owned alternate landing')
        if action == 'set_tf_owned_sled':
            if key[3] != 'enable_tf' or tf_set is not True or cleared is not False:
                self.error('set_tf_owned_sled requires enable_tf, tf_set=true, tf_cleared=false')
            if proposed != hex_value(record.get('sled_start')):
                self.error('set_tf_owned_sled must target the owned sled start')
        elif tf_set is not False:
            self.error('tf_set is only valid for set_tf_owned_sled')
        if action == 'keep' and key[0] in API_VARIANTS:
            if context.get('RipLocation') != 'inside_system_library':
                self.error('API keep requires verified inside_system_library location')
            delivery = hex_value(record.get('delivery_index'))
            if delivery is not None and delivery >= 4:
                self.error('API keep cannot bypass the fixed four-delivery safety guard')
        if action == 'clear_tf_keep' and record.get('stage') != 'second_trap':
            self.error('clear_tf_keep must be tagged second_trap')
        expected = record.get('gpr_expected') if isinstance(record.get('gpr_expected'), dict) else {}
        expected_rsp, expected_rbp = hex_value(expected.get('Rsp')), hex_value(expected.get('Rbp'))
        rsp = hex_value(context.get('Rsp'))
        gpr = context.get('gpr') if isinstance(context.get('gpr'), dict) else {}
        rbp = hex_value(gpr.get('Rbp'))
        sled, site, end = hex_value(record.get('sled_start')), hex_value(record.get('instruction_site')), hex_value(record.get('probe_end'))
        delivery = hex_value(record.get('delivery_index'))
        if action == 'clear_tf_keep' and all(n is not None for n in (expected_rsp, expected_rbp, rsp, rbp, rip, sled)):
            delta = expected_rsp - rsp
            if rbp != expected_rbp or not 8 <= delta <= 72 or delta % 8 or delta // 8 != rip - sled:
                self.error('clear_tf_keep violates the verified owned TF stack/RIP geometry')
        if action in ('keep', 'advance', 'alternate', 'set_tf_owned_sled') and key[0] not in API_VARIANTS:
            if all(n is not None for n in (expected_rsp, expected_rbp, rsp, rbp, rip, site, end)):
                if rsp != expected_rsp or rbp != expected_rbp or not site <= rip < end:
                    self.error('continuation action requires the verified original owned frame')
            if action == 'advance' and not (key[3] in ('advance', 'rip_plus_length', 'veh_search_seh', 'vch_order') or
                                           (key[3] == 'keep_then_advance' and delivery is not None and delivery >= 4)):
                self.error('advance action disagrees with requested policy/delivery index')
            if action == 'keep' and not ((key[3] == 'keep_then_advance' and delivery is not None and delivery < 4) or
                                        (key[3] == 'enable_tf' and delivery is not None and delivery != 1)):
                self.error('keep action disagrees with requested policy/delivery index')
            if action == 'set_tf_owned_sled' and delivery != 1:
                self.error('set_tf_owned_sled is only the first logical delivery')

        if action in ('keep', 'advance', 'set_tf_owned_sled') and key[0] not in API_VARIANTS:
            site, sled = hex_value(record.get('instruction_site')), hex_value(record.get('sled_start'))
            if site is not None and sled is not None and actual is not None and actual != site and not sled <= actual < sled + 9:
                self.error('continuation leaves owned instruction/PUSHFQ boundaries')
    def check_bounds(self, record, key, path):
        names = ('instruction_site', 'sled_start', 'sled_end', 'probe_fn', 'probe_end',
                 'alternate_fn', 'alternate_sled_start', 'alternate_end')
        self.required(record, names, path)
        values = {n: self.uint(record.get(n), path + '.' + n) for n in names}
        if all(value is not None for value in values.values()):
            v = values
            if not v['probe_fn'] <= v['instruction_site'] <= v['sled_start'] < v['sled_end'] <= v['probe_end']:
                self.error(path + ' owned probe bounds are inconsistent')
            if v['sled_end'] - v['sled_start'] != 9:
                self.error(path + ' owned PUSHFQ sled must have exactly nine one-byte entries')
            if not v['alternate_fn'] <= v['alternate_sled_start'] < v['alternate_sled_start'] + 9 <= v['alternate_end']:
                self.error(path + ' owned alternate bounds are inconsistent')
            if not (v['probe_end'] <= v['alternate_fn'] or v['alternate_end'] <= v['probe_fn']):
                self.error(path + ' owned probe and alternate ranges overlap')
            if key[0] not in API_VARIANTS:
                length = 1 if key[0] == 'ctx_int3_cc' else 2
                if v['sled_start'] != v['instruction_site'] + length:
                    self.error(path + ' owned instruction length disagrees with sled start')

    def check_run_result(self, record, key):
        names = ('status', 'exception_delivered', 'synthesized_by_parent', 'observation_count', 'delivery_count',
                 'vch_count', 'second_trap_count', 'stack_depth', 'action_applied', 'action_reachability',
                 'callback_order', 'continuation_entry_offset', 'continuation_site_offset', 'continuation_target',
                 'capture_path', 'capture_marker', 'requested_alternate', 'capture_method', 'post_rax', 'probe_returned', 'post_snapshot_valid',
                 'safety_escape', 'reason', 'post_gpr', 'post_rflags', 'last_pushfq_rflags', 'post_rsp_raw',
                 'pre_rsp', 'post_rsp_semantics', 'post_flags_semantics', 'api_result')
        self.required(record, names, 'run_result')
        status = record.get('status')
        if status not in STATUSES:
            self.error('run_result.status is unknown')
        parent = self.boolean(record.get('synthesized_by_parent'), 'run_result.synthesized_by_parent')
        returned = self.boolean(record.get('probe_returned'), 'run_result.probe_returned')
        valid = self.boolean(record.get('post_snapshot_valid'), 'run_result.post_snapshot_valid')
        escaped = self.boolean(record.get('safety_escape'), 'run_result.safety_escape')
        self.string(record.get('reason'), 'run_result.reason', nonempty=status != 'completed')
        depth = self.uint(record.get('stack_depth'), 'run_result.stack_depth', 32)
        if depth is not None and depth != key[4]:
            self.error('run_result.stack_depth must equal repeat')
        count = self.uint(record.get('observation_count'), 'run_result.observation_count', 32)
        if count is not None and count > 32:
            self.error('observation_count exceeds fixed capture buffer')
        if parent is True:
            if status not in ('runtime_aborted', 'skipped'):
                self.error('parent-synthesized result must be explicitly aborted or skipped')
            for name in ('exception_delivered', 'delivery_count', 'vch_count', 'second_trap_count', 'callback_order', 'action_applied', 'requested_alternate'):
                if record.get(name) is not None:
                    self.error('parent-synthesized ' + name + ' must be null, not an invented outcome')
            if record.get('action_reachability') != 'unknown_child_aborted':
                self.error('parent-synthesized action_reachability must be unknown_child_aborted')
            if returned is not False or valid is not False or escaped is not False:
                self.error('parent-synthesized result must not invent a returned/valid/escape path')
        elif parent is False:
            self.boolean(record.get('exception_delivered'), 'run_result.exception_delivered')
            for name in ('delivery_count', 'vch_count', 'second_trap_count'):
                self.uint(record.get(name), 'run_result.' + name, 32)
            applied = self.boolean(record.get('action_applied'), 'run_result.action_applied')
            self.boolean(record.get('requested_alternate'), 'run_result.requested_alternate')
            deliveries = hex_value(record.get('delivery_count'))
            reach = 'applied' if applied else ('unsupported_or_aborted' if deliveries else 'initial_exception_not_observed')
            if record.get('action_reachability') != reach:
                self.error('action_reachability disagrees with recorded delivery/action state')
            order = record.get('callback_order')
            if not isinstance(order, list) or any(who not in ('veh', 'seh', 'uef', 'vch') for who in order):
                self.error('callback_order must list actual callback observer names')
        if status == 'completed' and (returned is not True or valid is not True or escaped is not False):
            self.error('completed requires returned=true, post_snapshot_valid=true, safety_escape=false')
        if valid is True and (returned is not True or escaped is not False):
            self.error('valid post snapshot requires returned=true and safety_escape=false')
        target = record.get('continuation_target')
        if (valid is True and target not in ('owned_probe_sled', 'owned_alternate_landing')) or (valid is False and target != 'unavailable'):
            self.error('continuation_target must name the measured owned landing, or unavailable without a valid snapshot')
        marker = self.uint(record.get('capture_marker'), 'capture_marker', 32, nullable=True)
        if valid is True:
            if marker not in (1, 2):
                self.error('valid capture_marker must be 0x1 normal or 0x2 alternate')
            elif target != ('owned_probe_sled' if marker == 1 else 'owned_alternate_landing'):
                self.error('capture_marker disagrees with observed continuation target')
        elif record.get('capture_marker') is not None:
            self.error('unavailable capture_marker must be null')
        path = record.get('capture_path')
        wanted_path = 'unavailable' if not valid else ('alternate' if target == 'owned_alternate_landing' else 'normal')
        if path != wanted_path:
            self.error('capture_path disagrees with valid snapshot and continuation target')
        for name, expected in (
            ('capture_method', 'nine_one_byte_PUSHFQ_then_MOV_GPR_first_image_at_entry_rsp_minus_8'),
            ('post_rsp_semantics', 'post_gpr.Rsp_reconstructed_from_exact_owned_push_count'),
            ('post_flags_semantics', 'first_executed_PUSHFQ_image_RF_VM_not_preserved_by_PUSHFQ')):
            if record.get(name) != expected:
                self.error(name + ' must identify the actual owned capture method')
        measured = ('continuation_entry_offset', 'continuation_site_offset', 'post_rax', 'post_gpr',
                    'post_rflags', 'last_pushfq_rflags', 'post_rsp_raw')
        if valid is False:
            for name in measured:
                if record.get(name) is not None:
                    self.error('unavailable post snapshot must leave ' + name + ' null')
        elif valid is True:
            post = self.check_register_map(record.get('post_gpr'), 'post_gpr', GPRS)
            for name in ('post_rax', 'post_rflags', 'last_pushfq_rflags', 'post_rsp_raw', 'pre_rsp'):
                self.uint(record.get(name), name)
            entry = self.uint(record.get('continuation_entry_offset'), 'continuation_entry_offset', 32)
            if entry is not None and entry > 8:
                self.error('continuation_entry_offset must be 0x0..0x8 with at least one PUSHFQ')
            if target == 'owned_alternate_landing':
                if record.get('continuation_site_offset') is not None:
                    self.error('alternate landing must not invent a primary-site continuation offset')
            else:
                self.uint(record.get('continuation_site_offset'), 'continuation_site_offset')
            rax, post_rax = hex_value(record.get('post_rax')), hex_value(post.get('Rax'))
            if rax is not None and post_rax is not None and rax != post_rax:
                self.error('post_rax disagrees with post_gpr.Rax')
            before, after, reconstructed = hex_value(record.get('pre_rsp')), hex_value(record.get('post_rsp_raw')), hex_value(post.get('Rsp'))
            if all(n is not None for n in (entry, before, after, reconstructed)):
                pushes = 9 - entry
                if not 1 <= pushes <= 9 or before - after != pushes * 8 or reconstructed != after + pushes * 8:
                    self.error('post RSP/entry disagree with nine-PUSHFQ exact owned stack delta')
            for name in ('post_rflags', 'last_pushfq_rflags'):
                flags = hex_value(record.get(name))
                if flags is not None and flags & 0x30000:
                    self.warnings.append({'key': key_object(key), 'field': name, 'value': record.get(name),
                        'message': 'Raw PUSHFQ image contains RF/VM bits; retained as an architecture/translator diagnostic, not a schema error.'})
        if returned is True:
            self.uint(record.get('pre_rsp'), 'pre_rsp')
        elif returned is False and record.get('pre_rsp') is not None:
            self.error('non-returned probe must not invent pre_rsp terminal metadata')
        self.check_api_result(record, key)

    def check_api_result(self, record, key):
        value = record.get('api_result')
        if key[0] not in API_VARIANTS:
            if value is not None:
                self.error('non-API run must have null api_result')
            return
        obj = self.mapping(value, 'api_result')
        self.required(obj, ('return_kind', 'return_value', 'remote_present', 'last_error'), 'api_result')
        boolean_api = key[0] in ('is_debugger_present', 'check_remote_debugger_present')
        if obj.get('return_kind') != ('BOOL' if boolean_api else 'void'):
            self.error('api_result.return_kind disagrees with documented API signature')
        valid = record.get('post_snapshot_valid') is True
        if valid and boolean_api:
            result = self.uint(obj.get('return_value'), 'api_result.return_value', 32)
            rax = hex_value(record.get('post_rax'))
            if result is not None and rax is not None and result != rax & 0xffffffff:
                self.error('API return_value disagrees with low DWORD of captured RAX')
        else:
            result = None
            if obj.get('return_value') is not None:
                self.error('void or uncaptured API return_value must be null')
        remote = valid and key[0] == 'check_remote_debugger_present'
        if remote and result is not None and result != 0:
            self.uint(obj.get('remote_present'), 'api_result.remote_present', 32)
            if obj.get('last_error') is not None:
                self.error('successful CheckRemoteDebuggerPresent last_error must be null')
        else:
            if obj.get('remote_present') is not None:
                self.error('remote_present is valid only after successful CheckRemoteDebuggerPresent')
            if remote and result == 0:
                self.uint(obj.get('last_error'), 'api_result.last_error', 32)
            elif obj.get('last_error') is not None:
                self.error('last_error is failure-only CheckRemoteDebuggerPresent metadata')

    def check_run_consistency(self, key, starts, observations, terminal):
        if hex_value(terminal.get('observation_count')) != len(observations):
            self.error('observation_count disagrees with raw callback records', 'cardinality')
        start = starts[0] if starts else {}
        if start:
            for obs in observations:
                for name in ('instruction_site', 'sled_start', 'sled_end', 'probe_fn', 'probe_end', 'alternate_fn', 'alternate_sled_start', 'alternate_end'):
                    if hex_value(obs.get(name)) != hex_value(start.get(name)):
                        self.error('observation.' + name + ' disagrees with run_start', 'consistency')
                wanted = obs.get('gpr_expected')
                if isinstance(wanted, dict):
                    if hex_value(wanted.get('Rax')) != hex_value(start.get('requested_rax')):
                        self.error('gpr_expected.Rax disagrees with run_start.requested_rax', 'consistency')
            if terminal.get('post_snapshot_valid') is True and terminal.get('continuation_target') == 'owned_probe_sled':
                site, sled = hex_value(start.get('instruction_site')), hex_value(start.get('sled_start'))
                entry, relative = hex_value(terminal.get('continuation_entry_offset')), hex_value(terminal.get('continuation_site_offset'))
                if all(n is not None for n in (site, sled, entry, relative)) and relative != sled - site + entry:
                    self.error('continuation_site_offset disagrees with owned sled/site and measured entry', 'consistency')
        delivery, vch, second, chain_pending, armed = 0, 0, 0, False, False
        for ordinal, record in enumerate(observations, 1):
            if hex_value(record.get('callback_ordinal')) != ordinal:
                self.error('callback_ordinal is not the next contiguous callback index', 'sequence')
            who, stage = record.get('observer'), record.get('stage')
            cont = record.get('continuation') if isinstance(record.get('continuation'), dict) else {}
            exception = record.get('exception') if isinstance(record.get('exception'), dict) else {}
            if who == 'vch':
                vch += 1
            else:
                if who == 'seh' and chain_pending:
                    chain_pending = False
                else:
                    delivery += 1
                trap = armed and hex_value(exception.get('ExceptionCode')) == 0x80000004
                wanted_stage = 'second_trap' if trap else ('initial' if delivery == 1 else 'other')
                if stage != wanted_stage:
                    self.error('stage disagrees with collector TF-armed/delivery bookkeeping', 'sequence')
                if stage == 'second_trap':
                    second += 1
                if cont.get('action') == 'search':
                    chain_pending = True
                elif trap and cont.get('reason') != 'noncontinuable_exception':
                    armed = False
                if cont.get('action') == 'set_tf_owned_sled':
                    armed = True
                if cont.get('action') == 'escape':
                    armed = False
            if hex_value(record.get('delivery_index')) != delivery:
                self.error('delivery_index disagrees with callback versus logical-delivery bookkeeping', 'sequence')
        if terminal.get('synthesized_by_parent') is False:
            for name, number in (('delivery_count', delivery), ('vch_count', vch), ('second_trap_count', second)):
                if hex_value(terminal.get(name)) != number:
                    self.error(name + ' disagrees with callback records', 'cardinality')
            if terminal.get('exception_delivered') != bool(delivery):
                self.error('exception_delivered disagrees with logical deliveries', 'cardinality')
            if terminal.get('callback_order') != [r.get('observer') for r in observations]:
                self.error('callback_order disagrees with raw ordered callbacks', 'sequence')
            applied = any((r.get('continuation') or {}).get('action') in ('keep', 'advance', 'alternate', 'set_tf_owned_sled')
                          for r in observations if isinstance(r.get('continuation'), dict))
            if terminal.get('action_applied') != applied:
                self.error('action_applied disagrees with recorded continuation actions', 'consistency')
            requested_alternate = any((r.get('continuation') or {}).get('action') == 'alternate'
                                      for r in observations if isinstance(r.get('continuation'), dict))
            if terminal.get('requested_alternate') != requested_alternate:
                self.error('requested_alternate disagrees with recorded context edit; independent of measured capture path', 'consistency')
    def add_record(self, record):
        if self._summary is not None:
            raise ValueError('cannot append records after summary was finalized')
        self.current_key = None
        before = len(self.errors)
        if not isinstance(record, dict):
            self.error('each JSONL record must be an object')
            return
        self.global_numbers(record)
        kind = record.get('type')
        if not isinstance(kind, str) or kind not in RECORD_TYPES:
            self.error('unknown or missing record type')
            return
        self.record_counts[kind] += 1
        if kind == 'manifest':
            self.check_manifest(record)
            return
        if not self.manifests:
            self.error('record occurs before manifest', 'sequence')
        if kind == 'group_result':
            self.check_group(record)
            return
        key = self.parse_key(record)
        if key is None:
            return
        self.current_key = key
        if key[:4] in self.finished_groups:
            self.error('run record occurs after its group_result', 'sequence')
        if kind == 'run_start':
            if self.starts[key]:
                self.error('duplicate run_start', 'cardinality')
            if self.observations[key] or self.results[key]:
                self.error('run_start occurs after observations or terminal', 'sequence')
            self.check_start(record, key)
            self.check_bounds(record, key, 'run_start')
            self.required(record, ('family', 'requested_rax', 'rax_reference'), 'run_start')
            family = self.uint(record.get('family'), 'run_start.family', 32)
            if family != part_for(key[0]):
                self.error('run_start.family disagrees with closed matrix part')
            rax = self.uint(record.get('requested_rax'), 'run_start.requested_rax')
            ref = self.check_reference(record.get('rax_reference'), 'run_start.rax_reference')
            pointers = {'int2d_stack': 'own_stack_variable', 'int2d_heap': 'own_heap_block',
                        'int2d_function': 'probe_int2d', 'int2d_static': 'own_static_variable',
                        'ctx_int2d_stack': 'own_stack_variable'}
            if key[0] in pointers:
                if rax == 0 or ref.get('symbol') != pointers[key[0]] or hex_value(ref.get('offset'), signed=True) != 0:
                    self.error('requested_rax reference disagrees with fixed own-pointer case')
                if key[0] == 'int2d_function' and rax != hex_value(record.get('probe_fn')):
                    self.error('own-function requested_rax must equal the recorded own probe function')
            else:
                wanted = int(key[0][6:], 16) if key[0] in PART1_VARIANTS else (0 if key[0] == 'ctx_int2d_0' else 0x1100000000000001)
                if rax != wanted:
                    self.error('requested_rax disagrees with fixed integer input')
            self.starts[key].append(record)
        elif kind == 'observation':
            if not self.starts[key]:
                self.error('observation occurs before run_start', 'sequence')
            if self.results[key]:
                self.error('observation occurs after terminal result', 'sequence')
            self.observations[key].append(record)
            self.check_bounds(record, key, 'observation')
            self.check_observation(record, key)
            if len(self.errors) == before:
                self.valid_observations[key].append(record)
        elif kind == 'run_result':
            if self.results[key]:
                self.error('duplicate terminal run_result', 'cardinality')
            if not self.starts[key] and record.get('status') not in ('runtime_aborted', 'skipped'):
                self.error('terminal run_result has no preceding run_start', 'cardinality')
            self.check_run_result(record, key)
            self.results[key].append(record)


def check_file(path, allow_incomplete=False):
    checker = Checker(path, allow_incomplete)
    with pathlib.Path(path).open('rb') as stream:
        checker.read(stream)
    return checker.summary()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('raw', type=pathlib.Path, help='raw JSONL capture')
    parser.add_argument('--summary', type=pathlib.Path, default=pathlib.Path('summary.json'))
    parser.add_argument('--allow-incomplete', action='store_true', help='permit missing/skipped coverage only')
    args = parser.parse_args(argv)
    same = args.raw.resolve() == args.summary.resolve()
    if args.raw.exists() and args.summary.exists():
        same = same or args.raw.samefile(args.summary)
    if same:
        parser.error('--summary must not overwrite the raw input')
    input_missing = False
    try:
        try:
            result = check_file(args.raw, args.allow_incomplete)
        except FileNotFoundError:
            # A failed collector startup still owes an explicit matrix ledger.
            # No empty-file digest or measured-zero outcome is substituted.
            input_missing = True
            missing = Checker(args.raw, args.allow_incomplete)
            missing.error('raw input file was not created or cannot be found', 'io')
            result = missing.summary()
            result['data_provenance'] = 'missing_input'
            result['input']['sha256'] = None
            result['input']['read_status'] = 'missing_input'
        args.summary.write_text(json.dumps(result, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    except (OSError, ValueError) as exc:
        print('check_results: ' + str(exc), file=sys.stderr)
        return 2
    coverage = result['coverage']
    print('schema/coverage check: accounted ' + coverage['accounted_run_count'] + '/' + coverage['expected_run_count'] +
          '; attempted ' + coverage['attempted_run_count'] + '; measured ' + coverage['completed_count'] +
          '; unsupported ' + coverage['unsupported_count'] + '; missing ' + coverage['missing_count'] +
          '; errors ' + result['validation']['error_count'] + '; not a native Windows behavioral verdict')
    return 2 if input_missing else (0 if result['validation']['passed'] else 1)


if __name__ == '__main__':
    sys.exit(main())
