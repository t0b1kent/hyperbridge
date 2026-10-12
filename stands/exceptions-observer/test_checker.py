#!/usr/bin/env python3
"""Synthetic-only checker tests. No Windows/Wine execution or reference data.

Run: python -m unittest -v test_checker
All fixtures are generated in memory or a temporary directory, visibly labelled
synthetic. They test parsing, schema, coverage, and summary mechanics only.
"""

import copy
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import check_results as checker


MANIFEST = {"type": "manifest", "schema": "exception-observer-probe-v1",
            "synthetic": True,
            "schema_version": "0x1", "planned_runs": "0x10e0", "families": "0xc", "variants": "0x12",
            "observers": "0x3", "flag_seeds": "0x2", "policies": "0x2", "repeats": "0x14", "groups": "0xd8",
            "architecture": "x86_64", "context_size": "0x4d0", "group_timeout_ms": "0x1388",
            "description": "Synthetic checker fixture; not Windows reference measurements."}
FIRST_KEY = checker.expected_keys()[0]


def start(key=FIRST_KEY):
    return {"type": "run_start", "key": checker.key_object(key), "stack_depth": hex(key[4]), "process_id": "0x200",
            "arithmetic_flags_mask": "0x8d5", "requested_arithmetic_flags": "0x8d5" if key[2] == "set" else "0x0",
            "instruction_site": "0x1000", "sled_start": "0x1001"}


def terminal(key=FIRST_KEY, count=0, status="completed"):
    returned = status not in ("runtime_aborted", "skipped")
    record = {"type": "run_result", "key": checker.key_object(key), "status": status,
            "exception_delivered": count > 0, "observation_count": hex(count),
            "continuation_entry_offset": "0x2" if returned else None,
            "continuation_site_offset": "0x3" if returned else None,
            "post_rax": "0x1234" if returned else None, "stack_depth": hex(key[4]),
            "probe_returned": returned, "safety_escape": False,
            "reason": "" if status == "completed" else "Synthetic explicit outcome"}
    if returned:
        record.update({"pre_rsp": "0x100000", "post_rsp": "0xfffd0", "post_rflags": "0x202"})
    return record


def observation(key=FIRST_KEY, delivery=1):
    context = {name: "0x0" for name in checker.CONTEXT_BITS}
    context.update({"ContextFlags": "0x10001f", "Rip": "0x1001", "RipOffset": "0x1",
                    "Rsp": hex(0x100000 - 0x100 * (key[4] % 4)), "RspMod16": "0x0",
                    "P1Home": hex(key[4] % 4),
                    "gpr": {name: hex(0x100 + i) for i, name in enumerate(checker.GPRS)},
                    "xmm": {"Xmm" + str(i): "0x" + format(i, "032x") for i in range(16)}})
    context["gpr"]["Rsp"] = context["Rsp"]
    api = key[0] in checker.API_VARIANTS
    return {"type": "observation", "key": checker.key_object(key), "delivery_index": hex(delivery),
            "instruction_site": "0x1000", "sled_start": "0x1001", "instruction_length": None if api else "0x1",
            "offset_reference": "owned_api_call_site" if api else "owned_instruction_start",
            "exception": {"ExceptionCode": "0x80000003", "ExceptionFlags": "0x0",
                          "ExceptionAddress": "0x1000", "ExceptionAddressOffset": "0x0",
                          "NumberParameters": "0x0", "ExceptionInformation": ["0x0"] * 4},
            "context": context, "gpr_expected": copy.deepcopy(context["gpr"]), "gpr_differences": [],
            "xstate": {"present": False, "total_length": None, "length_status": "not_present"},
            "continuation": {"requested_policy": key[3], "action": "keep_fallback" if api else "advance",
                             "proposed_rip": None if api else "0x1002", "actual_rip": "0x1001" if api else "0x1002",
                             "tf_cleared": False, "reason": "Synthetic continuation only"}}


def thread_records():
    for operation, target, request, phase in checker.THREAD_KEYS:
        flags = "0x100010" if request == "debug" else "0x10001f"
        yield {"type": "thread_context", "operation": operation, "target": target,
               "request": request, "phase": phase, "status": "observed", "success": True,
               "last_error": "0x0", "requested_flags": flags,
               "validity": "invalid_current_thread_context" if target == "current" else "suspended_thread",
               "context": {"ContextFlags": flags, "Dr0": "0x0", "Dr1": "0x0", "Dr2": "0x0",
                           "Dr3": "0x0", "Dr4": None, "Dr5": None, "Dr6": "0x0", "Dr7": "0x0"},
               "debug_alias_status": "not_present_in_CONTEXT"}


def auxiliary_records():
    return [{"type": "thread_cleanup", "created": True, "ready": True,
             "suspended": True, "resume_success": True, "thread_signaled": True,
             "create_error": "0x0", "suspend_error": "0x0", "resume_error": "0x0", "wait_status": "0x0"},
            {"type": "thread_block_result", "created": True, "assigned": True,
             "resumed": True, "reaped": True, "timeout": False, "partial_record_dropped": False,
             "create_error": "0x0", "assign_error": "0x0", "resume_error": "0x0",
             "wait_status": "0x0", "terminate_error": "0x0", "child_exit_code": "0x0", "exit_query_error": "0x0",
             "child_process_id": "0x200", "child_thread_id": "0x204", "wait_error": "0x0",
             "cleanup_wait_status": "0xffffffff", "cleanup_wait_error": "0x0"}]


def group_record(key=FIRST_KEY):
    record = dict(auxiliary_records()[1])
    record.update({"type": "group_result", "group": dict(zip(checker.KEY_FIELDS[:4], key[:4])),
                   "group_index": hex(checker.expected_keys().index(key[:4] + (0,)) // 20),
                   "child_terminal_records": "0x14"})
    return record


def complete_records(observed=False):
    yield copy.deepcopy(MANIFEST)
    for key in checker.expected_keys():
        yield start(key)
        # A legitimate no-delivery path is included even in observed fixtures.
        delivered = observed and key[0] != "int2d_0"
        if delivered:
            yield observation(key)
        yield terminal(key, int(delivered))
        if key[4] == 19:
            yield group_record(key)
    yield from auxiliary_records()
    yield from thread_records()


def small_records(observed=True):
    records = [copy.deepcopy(MANIFEST), start()]
    if observed:
        records.append(observation())
    records.append(terminal(count=int(observed)))
    records.extend(auxiliary_records())
    records.extend(thread_records())
    return records


def run_records(records, allow_incomplete=True):
    stream = (json.dumps(record, ensure_ascii=True) + "\n" for record in records)
    return checker.Checker("synthetic://unit-tests", allow_incomplete).read(stream).summary()


def error_text(summary):
    return "\n".join(e["message"] for e in summary["validation"]["errors"])


def assert_no_json_numbers(test, value):
    if isinstance(value, bool) or value is None:
        return
    test.assertNotIsInstance(value, (int, float))
    if isinstance(value, dict):
        for child in value.values():
            assert_no_json_numbers(test, child)
    elif isinstance(value, list):
        for child in value:
            assert_no_json_numbers(test, child)


class CoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.complete = run_records(complete_records(), allow_incomplete=False)

    def test_fixed_matrix_exactly_4320_unique_keys(self):
        keys = checker.expected_keys()
        self.assertEqual(len(keys), 4320)
        self.assertEqual(len(set(keys)), 4320)
        self.assertEqual(len(checker.VARIANTS), 18)

    def test_complete_empty_exception_paths_are_valid_measurements(self):
        summary = self.complete
        self.assertTrue(summary["validation"]["passed"], error_text(summary))
        self.assertTrue(summary["coverage"]["coverage_complete"])
        self.assertTrue(summary["coverage"]["all_runs_measured"])
        self.assertEqual(summary["coverage"]["expected_run_count"], "0x10e0")
        self.assertEqual(len(summary["coverage"]["completed_without_exception"]), 4320)
        self.assertEqual(summary["data_provenance"], "synthetic_test_fixture")
        assert_no_json_numbers(self, summary)

    def test_complete_observed_fixture_is_structurally_valid(self):
        summary = run_records(complete_records(observed=True), allow_incomplete=False)
        self.assertTrue(summary["validation"]["passed"], error_text(summary))
        self.assertEqual(len(summary["coverage"]["completed_without_exception"]), 240)
        self.assertEqual(len(summary["variability"]["groups"]), 204)
        assert_no_json_numbers(self, summary)

    def test_every_missing_key_is_listed_without_truncation(self):
        summary = run_records([MANIFEST], allow_incomplete=False)
        self.assertFalse(summary["validation"]["passed"])
        self.assertEqual(len(summary["coverage"]["missing"]), 4320)
        self.assertEqual(summary["coverage"]["missing"][-1]["repeat"], "0x13")
        self.assertEqual(summary["coverage"]["missing"][-1]["variant"], "int1_cd01")
        self.assertEqual(len(summary["thread_context"]["missing"]), 7)

    def test_allow_incomplete_only_relaxes_coverage(self):
        summary = run_records([MANIFEST], allow_incomplete=True)
        self.assertTrue(summary["validation"]["passed"])
        self.assertFalse(summary["coverage"]["coverage_complete"])
        bad = run_records([MANIFEST, {"type": "nonsense"}], allow_incomplete=True)
        self.assertFalse(bad["validation"]["passed"])

    def test_missing_one_terminal_and_started_without_result(self):
        records = list(complete_records())
        del records[2]
        summary = run_records(records, allow_incomplete=False)
        self.assertFalse(summary["validation"]["passed"])
        self.assertEqual(summary["coverage"]["missing"], [checker.key_object(FIRST_KEY)])
        self.assertEqual(summary["coverage"]["started_without_result"], [checker.key_object(FIRST_KEY)])

    def test_unsupported_is_accounted_but_not_a_completed_measurement(self):
        records = list(complete_records())
        records[2] = terminal(status="requested_policy_unsupported")
        summary = run_records(records, allow_incomplete=False)
        self.assertTrue(summary["validation"]["passed"], error_text(summary))
        self.assertTrue(summary["coverage"]["coverage_complete"])
        self.assertFalse(summary["coverage"]["all_runs_measured"])
        self.assertEqual(summary["coverage"]["unsupported_count"], "0x1")
        self.assertEqual(summary["coverage"]["completed_count"], "0x10df")
        self.assertEqual(summary["coverage"]["unsupported"][0]["key"], checker.key_object(FIRST_KEY))

    def test_skipped_without_start_is_explicit_not_missing(self):
        records = list(complete_records())
        records[2] = terminal(status="skipped")
        records[2]["exception_delivered"] = None
        del records[1]
        strict = run_records(records, allow_incomplete=False)
        permissive = run_records(records, allow_incomplete=True)
        self.assertFalse(strict["validation"]["passed"])
        self.assertTrue(permissive["validation"]["passed"], error_text(permissive))
        self.assertEqual(strict["coverage"]["missing"], [])
        self.assertEqual(strict["coverage"]["explicitly_not_started"], [checker.key_object(FIRST_KEY)])

    def test_runtime_abort_without_start_is_accounted_but_fails_even_permissive(self):
        records = list(complete_records())
        records[2] = terminal(status="runtime_aborted")
        records[2]["exception_delivered"] = None
        del records[1]
        summary = run_records(records, allow_incomplete=True)
        self.assertTrue(summary["validation"]["structurally_valid"], error_text(summary))
        self.assertFalse(summary["validation"]["passed"])
        self.assertTrue(summary["coverage"]["coverage_complete"])
        self.assertEqual(summary["coverage"]["aborted_count"], "0x1")

    def test_guard_escape_fails_even_permissive(self):
        records = small_records(False)
        records[2] = terminal(status="guard_escape")
        self.assertFalse(run_records(records)["validation"]["passed"])


class SchemaTests(unittest.TestCase):
    def assert_bad(self, records, substring=None):
        summary = run_records(records)
        self.assertFalse(summary["validation"]["passed"])
        if substring:
            self.assertIn(substring, error_text(summary))
        assert_no_json_numbers(self, summary)
        return summary

    def test_duplicate_terminal(self):
        records = small_records(False)
        records.insert(3, terminal())
        result = self.assert_bad(records, "duplicate terminal")
        self.assertEqual(result["coverage"]["duplicate_terminal_keys"], [checker.key_object(FIRST_KEY)])

    def test_duplicate_start(self):
        records = small_records(False)
        records.insert(2, start())
        self.assert_bad(records, "duplicate run_start")

    def test_terminal_without_start(self):
        records = small_records(False)
        del records[1]
        self.assert_bad(records, "no preceding run_start")

    def test_bad_observation_sequence_and_counts(self):
        cases = []
        records = small_records()
        records[1], records[2] = records[2], records[1]
        cases.append((records, "before run_start"))
        records = small_records()
        records[2]["delivery_index"] = "0x2"
        cases.append((records, "contiguous"))
        records = small_records()
        records[2]["delivery_index"] = "0x6"
        cases.append((records, "hard guard"))
        records = small_records()
        records[3]["observation_count"] = "0x0"
        cases.append((records, "observation_count disagrees"))
        records = small_records()
        records[3]["exception_delivered"] = False
        cases.append((records, "exception_delivered disagrees"))
        records = small_records()
        records[2], records[3] = records[3], records[2]
        cases.append((records, "after terminal"))
        for records, message in cases:
            with self.subTest(message=message):
                self.assert_bad(records, message)

    def test_missing_context_field(self):
        records = small_records()
        del records[2]["context"]["LastExceptionFromRip"]
        self.assert_bad(records, "LastExceptionFromRip is required")

    def test_numeric_json_values_rejected_everywhere(self):
        for value in (1, 1.5, -1):
            for location in ("manifest", "auxiliary", "context"):
                with self.subTest(value=value, location=location):
                    records = small_records()
                    if location == "manifest":
                        records[0]["arbitrary"] = {"deep": [value]}
                    elif location == "auxiliary":
                        records[-1]["arbitrary"] = value
                    else:
                        records[2]["context"]["EFlags"] = value
                    self.assert_bad(records, "JSON number")

    def test_known_numeric_strings_must_be_hex(self):
        for field, value in (("EFlags", "514"), ("EFlags", "0X202"), ("Rip", "-0x1"),
                             ("Rsp", "0x"), ("ContextFlags", True)):
            records = small_records()
            records[2]["context"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_bad(records, "hexadecimal string")

    def test_ranges_are_validated(self):
        for field, bits in (("EFlags", 32), ("Rip", 64), ("SegCs", 16), ("RspMod16", 4)):
            records = small_records()
            records[2]["context"][field] = hex(1 << bits)
            with self.subTest(field=field):
                self.assert_bad(records, "outside uint")
        records = small_records()
        records[2]["context"]["xmm"]["Xmm0"] = hex(1 << 128)
        self.assert_bad(records, "outside uint128")
        records = small_records()
        records[2]["exception"]["NumberParameters"] = "0x10"
        self.assert_bad(records, "EXCEPTION_MAXIMUM_PARAMETERS")

    def test_exception_information_has_exactly_four_hex_slots(self):
        for value in (None, [], ["0x0"] * 3, ["0x0"] * 5, ["0x0", "0", "0x0", "0x0"]):
            records = small_records()
            records[2]["exception"]["ExceptionInformation"] = value
            with self.subTest(value=value):
                self.assert_bad(records, "ExceptionInformation")

    def test_gpr_comparison_is_consistent_without_assuming_constants(self):
        records = small_records()
        records[2]["context"]["gpr"]["Rax"] = "0xdeadbeef"
        self.assert_bad(records, "gpr_differences does not match")
        records[2]["gpr_differences"] = ["Rax"]
        self.assertTrue(run_records(records)["validation"]["passed"])
        records[2]["gpr_differences"] = ["Rax", "Rax"]
        self.assert_bad(records, "duplicates")

    def test_xstate_bit_is_reported_consistently(self):
        records = small_records()
        records[2]["xstate"]["present"] = True
        self.assert_bad(records, "0x40")
        records[2]["context"]["ContextFlags"] = "0x10005f"
        records[2]["xstate"]["total_length"] = "0x1000"
        self.assertTrue(run_records(records)["validation"]["passed"])

    def test_extra_variant_and_bad_keys_rejected(self):
        for field, value in (("variant", "int2d_11"), ("observer", "debugger"),
                             ("flag_seed", "random"), ("policy", "ignore"),
                             ("repeat", "0x14"), ("repeat", "0"), ("variant", [])):
            records = small_records(False)
            records[1]["key"][field] = value
            with self.subTest(field=field, value=value):
                self.assert_bad(records, "key.")
        records = small_records(False)
        records[1]["key"]["extra"] = "extra"
        self.assert_bad(records, "unknown fields")

    def test_malformed_shapes_do_not_crash(self):
        for top_value in (None, [], "record", 7, True):
            with self.subTest(top_value=top_value):
                self.assert_bad([MANIFEST, top_value], "must be an object")
        for field in ("exception", "context", "xstate", "continuation", "gpr_expected"):
            for value in (None, [], "bad", True):
                records = small_records()
                records[2][field] = value
                with self.subTest(field=field, value=value):
                    self.assert_bad(records)
        for value in (None, [], {}, True):
            records = small_records(False)
            records[2]["status"] = value
            with self.subTest(status=value):
                self.assert_bad(records)

    def test_continuation_policy_matches_key(self):
        records = small_records()
        records[2]["continuation"]["requested_policy"] = "keep_then_advance"
        self.assert_bad(records, "disagrees with the run key")

    def test_null_proposed_rip_is_permitted_for_api_cases(self):
        records = small_records()
        for record in records:
            if "key" in record:
                record["key"]["variant"] = "debugbreak"
        records[2]["continuation"]["proposed_rip"] = None
        records[2]["instruction_length"] = None
        records[2]["offset_reference"] = "owned_api_call_site"
        records[2]["continuation"]["action"] = "keep_fallback"
        records[2]["continuation"]["actual_rip"] = records[2]["context"]["Rip"]
        self.assertTrue(run_records(records)["validation"]["passed"])

    def test_null_delivery_is_only_for_skipped_or_aborted(self):
        records = small_records(False)
        records[2]["exception_delivered"] = None
        self.assert_bad(records, "JSON boolean")

    def test_manifest_required_and_unique(self):
        self.assert_bad(small_records()[1:], "no manifest")
        self.assert_bad([MANIFEST] + small_records(), "exactly one")

    def test_unknown_record_type_is_an_error(self):
        self.assert_bad([MANIFEST, {"type": "extra"}], "unknown or missing")

    def test_thread_block_required_identities_duplicates_and_fields(self):
        records = small_records(False)
        records.append(copy.deepcopy(records[-1]))
        self.assert_bad(records, "duplicate thread_context")
        records = small_records(False)
        records[-1]["phase"] = "unknown"
        self.assert_bad(records, "outside the fixed block")
        records = small_records(False)
        del records[-1]["context"]["Dr7"]
        self.assert_bad(records, "Dr7 is required")
        records = small_records(False)
        records[-1]["context"]["Dr4"] = "0x0"
        self.assert_bad(records, "must be null")
        records = small_records(False)
        next(r for r in records if r["type"] == "thread_context" and r["target"] == "current")["validity"] = "valid"
        self.assert_bad(records, "invalid_current_thread_context")

    def test_group_shape_numeric_fields_and_duplicates(self):
        record = group_record()
        self.assertTrue(run_records(small_records() + [record])["validation"]["passed"])
        self.assert_bad(small_records() + [record, record], "duplicate group_result")
        record["child_exit_code"] = "0"
        self.assert_bad(small_records() + [record], "hexadecimal")


class ParserTests(unittest.TestCase):
    def parse_text(self, text):
        return checker.Checker("synthetic://parse-tests", True).read(io.StringIO(text)).summary()

    def test_json_corruption_is_reported_and_following_records_are_read(self):
        text = '{broken json\n' + json.dumps(MANIFEST) + '\n'
        result = self.parse_text(text)
        self.assertFalse(result["validation"]["passed"])
        self.assertIn("invalid JSON", error_text(result))
        self.assertEqual(result["input"]["record_counts"]["manifest"], "0x1")

    def test_duplicate_json_members_nan_infinity_and_blank_lines(self):
        for line in ('{"type":"manifest","type":"manifest"}',
                     '{"type":"manifest","value":NaN}',
                     '{"type":"manifest","value":Infinity}', ''):
            with self.subTest(line=line):
                result = self.parse_text(json.dumps(MANIFEST) + '\n' + line + '\n')
                self.assertFalse(result["validation"]["passed"])
                self.assertEqual(result["validation"]["errors"][0]["category"], "parse")

    def test_utf8_bom_and_invalid_utf8(self):
        valid = b'\xef\xbb\xbf' + json.dumps(MANIFEST).encode() + b'\n'
        summary = checker.Checker("synthetic", True).read(io.BytesIO(valid)).summary()
        self.assertTrue(summary["validation"]["passed"])
        bad = checker.Checker("synthetic", True).read(io.BytesIO(valid + b'\xff\n')).summary()
        self.assertFalse(bad["validation"]["passed"])
        self.assertIn("invalid UTF-8", error_text(bad))


class VariabilityTests(unittest.TestCase):
    def test_depth_separated_variability_and_no_identity_noise(self):
        records = [MANIFEST]
        for repeat in range(20):
            key = FIRST_KEY[:4] + (repeat,)
            records.extend([start(key), observation(key), terminal(key, 1)])
        summary = run_records(records)
        group = summary["variability"]["groups"][0]
        self.assertEqual(group["across_depths"]["sample_count"], "0x14")
        self.assertEqual(group["repeats_without_this_delivery"], [])
        changed = {field["field"] for field in group["across_depths"]["unstable_fields"]}
        self.assertEqual(changed, {"context.Rsp", "context.gpr.Rsp", "context.P1Home"})
        self.assertEqual(len(group["within_depths"]), 20)
        self.assertTrue(all(not depth["unstable_fields"] for depth in group["within_depths"]))
        self.assertTrue(all(depth["sample_count"] == "0x1" for depth in group["within_depths"]))
        self.assertTrue(all(not depth["comparison_possible"] for depth in group["within_depths"]))

    def test_rip_offsets_and_flags_are_not_normalized_away(self):
        records = [MANIFEST]
        for repeat in range(2):
            key = FIRST_KEY[:4] + (repeat,)
            obs = observation(key)
            obs["context"]["RipOffset"] = hex(repeat)
            obs["context"]["Rip"] = hex(0x1000 + repeat)
            obs["continuation"]["actual_rip"] = obs["continuation"]["proposed_rip"] = hex(0x1001 + repeat)
            obs["context"]["EFlags"] = hex(0x202 + repeat)
            obs["exception"]["ExceptionAddressOffset"] = hex(repeat)
            obs["exception"]["ExceptionAddress"] = hex(0x1000 + repeat)
            records.extend([start(key), obs, terminal(key, 1)])
        summary = run_records(records)
        changed = {f["field"] for f in summary["variability"]["groups"][0]["across_depths"]["unstable_fields"]}
        self.assertTrue({"context.RipOffset", "context.EFlags", "exception.ExceptionAddressOffset"} <= changed)

    def test_deliveries_are_not_mixed(self):
        key = FIRST_KEY[:3] + ("keep_then_advance", 0)
        records = [MANIFEST, start(key)]
        for index in range(1, 6):
            obs = observation(key, index)
            obs["context"]["RipOffset"] = hex(index)
            obs["context"]["Rip"] = hex(0x1000 + index)
            obs["continuation"]["actual_rip"] = obs["continuation"]["proposed_rip"] = hex(0x1001 + index)
            records.append(obs)
        records.append(terminal(key, 5, "guard_escape"))
        summary = run_records(records)
        groups = summary["variability"]["groups"]
        self.assertEqual(len(groups), 5)
        self.assertTrue(all(not g["across_depths"]["comparison_possible"] for g in groups))
        self.assertTrue(all(not g["across_depths"]["unstable_fields"] for g in groups))


class ProducerContractTests(unittest.TestCase):
    def test_producer_shaped_api_record_and_context_blobs(self):
        key = ("debugbreak", "veh", "clear", "advance", 0)
        obs = observation(key)
        # The API body lies below our call site in this synthetic address layout.
        obs["context"]["Rip"] = "0x800"
        obs["context"]["RipOffset"] = "-0x800"
        obs["exception"]["ExceptionAddress"] = "0x700"
        obs["exception"]["ExceptionAddressOffset"] = "-0x900"
        obs["continuation"]["actual_rip"] = "0x800"
        obs["context_bytes_hex"] = "0x" + "a5" * 0x4d0
        obs["context_size"] = "0x4d0"
        obs["context_field_semantics"] = "raw_bytes_validity_depends_on_returned_ContextFlags"
        obs["exception_information_valid_slots"] = "0x0"
        obs["xmm_differences"] = []
        obs["register_interpretation"] = "api_pre_call_differences_not_preservation_failures"
        result = terminal(key, 1, "requested_policy_unsupported")
        records = [MANIFEST, start(key), obs, result] + auxiliary_records()
        for record in thread_records():
            record["context_bytes_hex"] = "0x" + "a5" * 0x4d0
            record["buffer_pattern_byte"] = "0xa5"
            record["debug_alias_status"] = "Dr4_Dr5_not_present_in_CONTEXT"
            records.append(record)
        records.append(group_record(key))
        summary = run_records(records)
        self.assertTrue(summary["validation"]["passed"], error_text(summary))
        self.assertEqual(summary["coverage"]["unsupported_count"], "0x1")
        self.assertIn("not decoded", summary["semantics"]["context_blob_validation"])

    def test_signed_offset_bounds_and_unsigned_fields_remain_distinct(self):
        records = small_records()
        records[2]["context"]["RipOffset"] = "-0x10000000000000000"
        self.assertIn("magnitude", error_text(run_records(records)))
        records[2]["context"]["RipOffset"] = "-1"
        self.assertIn("hexadecimal offset", error_text(run_records(records)))
        records[2]["context"]["Rip"] = "-0x1"
        self.assertIn("unsigned", error_text(run_records(records)))

    def test_source_metadata_cannot_be_omitted_to_disable_checks(self):
        fields = ((1, "instruction_site"), (1, "sled_start"), (1, "arithmetic_flags_mask"),
                  (1, "requested_arithmetic_flags"), (1, "process_id"),
                  (2, "instruction_site"), (2, "sled_start"), (2, "instruction_length"), (2, "offset_reference"))
        for index, name in fields:
            records = small_records()
            del records[index][name]
            with self.subTest(name=name, index=index):
                summary = run_records(records)
                self.assertFalse(summary["validation"]["passed"])
                self.assertIn(name + " is required", error_text(summary))

    def test_manifest_dimensions_and_architecture_are_checked(self):
        for field, value in (("planned_runs", "0x1"), ("variants", "0x13"),
                             ("architecture", "arm64"), ("schema_version", "0x2"),
                             ("context_size", "0x0"), ("families", True)):
            records = small_records()
            records[0][field] = value
            with self.subTest(field=field):
                self.assertFalse(run_records(records)["validation"]["passed"])

    def test_context_blob_syntax_and_byte_count(self):
        for blob in ("0x0", "a5", "0xzz", "0x" + "a5" * 12):
            records = small_records()
            records[2]["context_bytes_hex"] = blob
            with self.subTest(blob=blob[:20]):
                self.assertFalse(run_records(records)["validation"]["passed"])

    def test_internal_arithmetic_mutations_fail(self):
        mutations = (
            (1, ("stack_depth",), "0x1"),
            (1, ("requested_arithmetic_flags",), "0x8d5"),
            (2, ("context", "RspMod16"), "0x1"),
            (2, ("context", "RipOffset"), "0x7"),
            (2, ("exception", "ExceptionAddressOffset"), "-0x1"),
            (2, ("continuation", "actual_rip"), "0x9999"),
            (2, ("continuation", "tf_cleared"), True),
            (3, ("continuation_entry_offset",), "0x4"),
            (3, ("continuation_site_offset",), "0x9"),
            (3, ("probe_returned",), False),
        )
        for index, path, value in mutations:
            records = small_records()
            target = records[index]
            for name in path[:-1]:
                target = target[name]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertFalse(run_records(records)["validation"]["passed"])

    def test_timeout_cleanly_reaped_still_fails(self):
        records = small_records()
        block = next(r for r in records if r["type"] == "thread_block_result")
        block.update({"timeout": True, "wait_status": "0x102", "cleanup_wait_status": "0x0", "reaped": True})
        summary = run_records(records)
        self.assertTrue(summary["validation"]["structurally_valid"], error_text(summary))
        self.assertFalse(summary["validation"]["passed"])
        self.assertIn("child_timeout", summary["validation"]["runtime_failures"][0]["causes"])

    def test_nonzero_exit_unreaped_and_cleanup_failures_are_never_ignored(self):
        for field, value in (("child_exit_code", "0x2"), ("reaped", False),
                             ("partial_record_dropped", True), ("exit_query_error", "0x5")):
            records = small_records()
            block = next(r for r in records if r["type"] == "thread_block_result")
            block[field] = value
            with self.subTest(field=field):
                self.assertFalse(run_records(records, allow_incomplete=True)["validation"]["passed"])
        records = small_records()
        next(r for r in records if r["type"] == "thread_cleanup")["thread_signaled"] = False
        self.assertFalse(run_records(records, allow_incomplete=True)["validation"]["passed"])

    def test_group_process_identity_and_missing_group_coverage(self):
        records = small_records() + [group_record()]
        records[1]["process_id"] = "0x300"
        self.assertIn("group_result.child_process_id", error_text(run_records(records)))
        records = list(complete_records())
        records = [r for r in records if r["type"] != "group_result" or r["group_index"] != "0x0"]
        summary = run_records(records, allow_incomplete=False)
        self.assertFalse(summary["validation"]["passed"])
        self.assertEqual(len(summary["group_coverage"]["missing"]), 1)

    def test_duplicate_or_missing_thread_block_accounting(self):
        records = small_records()
        records.append(copy.deepcopy(next(r for r in records if r["type"] == "thread_block_result")))
        self.assertIn("duplicate thread_block_result", error_text(run_records(records)))
        records = [r for r in complete_records() if r["type"] not in ("thread_context", "thread_cleanup")]
        block = next(r for r in records if r["type"] == "thread_block_result")
        block["child_exit_code"] = "0xe005"
        summary = run_records(records)
        self.assertEqual(len(summary["thread_context"]["missing"]), 7)
        self.assertIn("thread_cleanup", summary["thread_context"]["missing_auxiliary_records"])
        self.assertFalse(summary["validation"]["passed"])


class CommandLineTests(unittest.TestCase):
    def invoke(self, path, summary, *extra):
        return subprocess.run([sys.executable, str(pathlib.Path(checker.__file__).resolve()),
                               str(path), "--summary", str(summary), *extra],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

    def test_cli_writes_summary_for_corrupt_input_and_fails(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-checker-") as directory:
            raw = pathlib.Path(directory) / "synthetic_raw.jsonl"
            out = pathlib.Path(directory) / "synthetic_summary.json"
            raw.write_text(json.dumps(MANIFEST) + '\n{broken}\n', encoding="utf-8")
            result = self.invoke(raw, out, "--allow-incomplete")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue(out.exists())
            self.assertFalse(json.loads(out.read_text())["validation"]["passed"])

    def test_cli_partial_exit_codes_and_no_input_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-checker-") as directory:
            raw = pathlib.Path(directory) / "synthetic_raw.jsonl"
            out = pathlib.Path(directory) / "synthetic_summary.json"
            original = json.dumps(MANIFEST) + '\n'
            raw.write_text(original, encoding="utf-8")
            self.assertEqual(self.invoke(raw, out).returncode, 1)
            self.assertEqual(self.invoke(raw, out, "--allow-incomplete").returncode, 0)
            self.assertEqual(self.invoke(raw, raw, "--allow-incomplete").returncode, 2)
            self.assertEqual(raw.read_text(), original)

    def test_cli_missing_file_is_io_error(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-checker-") as directory:
            directory = pathlib.Path(directory)
            result = self.invoke(directory / "missing.jsonl", directory / "summary.json")
            self.assertEqual(result.returncode, 2)
            self.assertIn("check_results:", result.stderr)


if __name__ == "__main__":
    unittest.main()
