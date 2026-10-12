#!/usr/bin/env python3
"""Synthetic checker tests only. No Windows, Wine, FEX, or PE execution.

Fixtures are invented in memory to exercise parsing and consistency. They are
not predictions or reference measurements of Windows behavior. Run normally and
with python -O -m unittest -v test_checker; validation never relies on assert.
"""
import copy
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

import check_results as checker

MANIFEST = {'type': 'manifest', 'synthetic': True, 'schema_version': '0x5',
    'planned_runs': '0x1220', 'families': '0x3', 'variants': '0x14', 'observers': '0x4',
    'flag_seeds': '0x2', 'policies': '0x8', 'repeats': '0x14', 'groups': '0xe8',
    'context_size': '0x4d0', 'group_timeout_ms': '0x7530', 'architecture': 'x86_64',
    'description': 'SYNTHETIC CHECKER FIXTURE; NOT WINDOWS MEASUREMENTS',
    'compiler': 'synthetic checker fixture only', 'runtime_claim': 'observations_only_no_expected_Windows_values',
    'raw_numbers': 'hexadecimal_strings', 'xstate_total_length': 'unavailable_for_borrowed_handler_context',
    'native_processor_architecture': '0x9',
    'routing_base_continuation': 'literal_incoming_Rip_plus_instruction_length_guarded_by_owned_boundaries'}
FIRST = checker.expected_keys()[0]
POINTERS = {'int2d_stack': 'own_stack_variable', 'int2d_heap': 'own_heap_block',
            'int2d_function': 'probe_int2d', 'int2d_static': 'own_static_variable',
            'ctx_int2d_stack': 'own_stack_variable'}


def reference(symbol=None):
    return {'symbol': symbol, 'offset': '0x0' if symbol else None, 'dereferenced': False}


def bounds(key):
    length = 1 if key[0] == 'ctx_int3_cc' else (6 if key[0] in checker.API_VARIANTS else 2)
    return {'instruction_site': '0x1000', 'sled_start': hex(0x1000 + length),
            'sled_end': hex(0x1000 + length + 9), 'probe_fn': '0xf00', 'probe_end': '0x1200',
            'alternate_fn': '0x2000', 'alternate_sled_start': '0x2100', 'alternate_end': '0x2300'}


def start(key=FIRST):
    rax = (0xf00 if key[0] == 'int2d_function' else 0x100000) if key[0] in POINTERS else (int(key[0][6:], 16) if key[0] in checker.PART1_VARIANTS else 0 if key[0] == 'ctx_int2d_0' else 0x1100000000000001)
    return dict({'type': 'run_start', 'key': checker.key_object(key), 'stack_depth': hex(key[4]),
        'process_id': '0x200', 'arithmetic_flags_mask': '0x8d5',
        'requested_arithmetic_flags': '0x8d5' if key[2] == 'set' else '0x0',
        'family': hex(checker.part_for(key[0])), 'requested_rax': hex(rax),
        'rax_reference': reference(POINTERS.get(key[0])),
        'own_debug_string_a': 'exception-observer-v5: own ANSI test',
        'own_debug_string_w': 'exception-observer-v5: own Unicode test U+03A9',
        'stack_pattern': 'primed_owned_window_120_bytes_0xa5_plus_8_byte_flags_scratch'}, **bounds(key))


def gprs(key):
    values = {name: hex(0x100 + i) for i, name in enumerate(checker.GPRS)}
    values['Rsp'] = '0x100000'
    values['Rbp'] = '0x100000'
    values['Rax'] = start(key)['requested_rax']
    return values


def set_location(record, address, location='owned_probe'):
    if location == 'owned_probe':
        base = int(record['instruction_site'], 16)
        origin = 'instruction_site'
    elif location == 'owned_alternate':
        base = int(record['alternate_sled_start'], 16)
        origin = 'alternate_sled_start'
    else:
        base, origin = None, 'none'
    for obj, aname, oname, lname in ((record['context'], 'Rip', 'RipOffset', 'RipLocation'),
                                    (record['exception'], 'ExceptionAddress', 'ExceptionAddressOffset', 'ExceptionAddressLocation')):
        obj[aname] = hex(address)
        obj[oname] = hex(address - base) if base is not None else None
        obj[lname] = location
        obj[oname + 'Reference'] = origin


def observation(key=FIRST, ordinal=1, delivery=1, who=None, action=None, stage=None):
    who = who or ('veh' if key[1] == 'veh_seh' else key[1])
    context = {name: '0x0' for name in checker.CONTEXT_BITS}
    context.update({'ContextFlags': '0x10001f', 'Rip': '0x1000', 'RipOffset': '0x0',
        'RipLocation': 'owned_probe', 'RipOffsetReference': 'instruction_site',
        'Rsp': '0x100000', 'RspMod16': '0x0', 'EFlags': '0x202', 'gpr': gprs(key),
        'xmm': {'Xmm' + str(i): '0x' + ((0x5a00000000000000+i).to_bytes(8, 'little') +
                (0xa500000000000000+i).to_bytes(8, 'little')).hex() for i in range(16)}})
    api = key[0] in checker.API_VARIANTS
    length = None if api else (1 if key[0] == 'ctx_int3_cc' else 2)
    if action is None:
        action = ('observe_only' if who == 'vch' else 'search' if key[3] == 'veh_search_seh' and who == 'veh'
                  else 'keep' if api or key[3] == 'keep_then_advance' else 'alternate' if key[3] == 'alternate'
                  else 'set_tf_owned_sled' if key[3] == 'enable_tf' else 'advance')
    record = dict({'type': 'observation', 'key': checker.key_object(key), 'callback_ordinal': hex(ordinal),
        'delivery_index': hex(delivery), 'observer': who,
        'stage': stage or ('continue_callback' if who == 'vch' else 'initial' if delivery == 1 else 'other'),
        'context': context, 'exception': {'ExceptionCode': '0x80000003', 'ExceptionFlags': '0x0',
            'ExceptionAddress': '0x1000', 'ExceptionAddressOffset': '0x0', 'ExceptionAddressLocation': 'owned_probe',
            'ExceptionAddressOffsetReference': 'instruction_site', 'NumberParameters': '0x0',
            'ExceptionInformation': ['0xa5'] * 15, 'parameter_references': [reference() for _ in range(15)]},
        'context_bytes_hex': '0x' + 'a5' * 0x4d0, 'context_size': '0x4d0',
        'context_field_semantics': 'raw_bytes_validity_depends_on_returned_ContextFlags',
        'exception_information_valid_slots': '0x0', 'gpr_expected': gprs(key),
        'gpr_differences': [], 'xmm_differences': [],
        'register_interpretation': 'api_pre_call_differences_not_preservation_failures' if api else 'instruction_entry_seed_comparison',
        'xstate': {'present': False, 'total_length': None, 'length_status': 'unavailable_documented_size_for_borrowed_context'},
        'instruction_length': None if length is None else hex(length), 'offset_reference': 'per_field_location_reference',
        'continuation': {'requested_policy': key[3], 'action': action, 'proposed_rip': '0x1000', 'actual_rip': '0x1000',
            'tf_cleared': False, 'tf_set': action == 'set_tf_owned_sled', 'reason': 'synthetic_capture_only'}}, **bounds(key))
    if api:
        set_location(record, 0x70000000, 'inside_system_library')
    rip = int(record['context']['Rip'], 16)
    target = rip
    if action == 'advance': target = rip + length
    if action == 'alternate': target = int(record['alternate_sled_start'], 16)
    if action == 'set_tf_owned_sled': target = int(record['sled_start'], 16)
    record['continuation']['proposed_rip'] = hex(target)
    record['continuation']['actual_rip'] = None if action == 'terminate' else hex(target)
    return record


def terminal(key=FIRST, observations=(), status='completed', parent=False):
    valid = status == 'completed'
    returned = status in ('completed', 'requested_policy_unsupported', 'guard_escape')
    alternate = any(o['continuation']['action'] == 'alternate' for o in observations)
    delivery = max([int(o['delivery_index'], 16) for o in observations] or [0])
    applied = any(o['continuation']['action'] in ('keep', 'advance', 'alternate', 'set_tf_owned_sled') for o in observations)
    post = gprs(key)
    if key[0] in ('is_debugger_present', 'check_remote_debugger_present'):
        post['Rax'] = '0x1'
    b = bounds(key)
    record = {'type': 'run_result', 'key': checker.key_object(key), 'status': status,
        'exception_delivered': None if parent else bool(delivery), 'synthesized_by_parent': parent,
        'observation_count': hex(len(observations)), 'delivery_count': None if parent else hex(delivery),
        'vch_count': None if parent else hex(sum(o['observer'] == 'vch' for o in observations)),
        'second_trap_count': None if parent else hex(sum(o['stage'] == 'second_trap' and o['continuation']['action'] != 'search' for o in observations)),
        'stack_depth': hex(key[4]), 'action_applied': None if parent else applied,
        'action_reachability': 'unknown_child_aborted' if parent else 'applied' if applied else 'unsupported_or_aborted' if delivery else 'initial_exception_not_observed',
        'callback_order': None if parent else [o['observer'] for o in observations],
        'continuation_entry_offset': '0x0' if valid else None,
        'continuation_site_offset': hex(int(b['sled_start'], 16) - 0x1000) if valid and not alternate else None,
        'continuation_target': ('owned_alternate_landing' if alternate else 'owned_probe_sled') if valid else 'unavailable',
        'capture_path': 'unavailable' if not valid else 'alternate' if alternate else 'normal',
        'capture_marker': ('0x2' if alternate else '0x1') if valid else None,
        'requested_alternate': None if parent else alternate,
        'capture_method': 'nine_one_byte_PUSHFQ_then_MOV_GPR_first_image_at_entry_rsp_minus_8',
        'post_rax': post['Rax'] if valid else None, 'probe_returned': returned, 'post_snapshot_valid': valid,
        'safety_escape': status in ('requested_policy_unsupported', 'guard_escape'),
        'reason': '' if status == 'completed' else 'synthetic_explicit_outcome', 'post_gpr': post if valid else None,
        'post_rflags': '0x202' if valid else None, 'last_pushfq_rflags': '0x202' if valid else None,
        'post_rsp_raw': '0xfffb8' if valid else None, 'pre_rsp': '0x100000' if returned else None,
        'post_rsp_semantics': 'post_gpr.Rsp_reconstructed_from_exact_owned_push_count',
        'post_flags_semantics': 'first_executed_PUSHFQ_image_RF_VM_not_preserved_by_PUSHFQ', 'api_result': None}
    if key[0] in checker.API_VARIANTS:
        is_bool = key[0] in ('is_debugger_present', 'check_remote_debugger_present')
        record['api_result'] = {'return_kind': 'BOOL' if is_bool else 'void',
            'return_value': '0x1' if valid and is_bool else None,
            'remote_present': '0x0' if valid and key[0] == 'check_remote_debugger_present' else None, 'last_error': None}
    return record


def group(key=FIRST, count=20):
    record = {'type': 'group_result', 'group': dict(zip(checker.KEY_FIELDS[:4], key[:4])),
        'group_index': hex(checker.expected_groups().index(key[:4])), 'child_terminal_records': hex(count),
        'created': True, 'assigned': True, 'resumed': True, 'reaped': True, 'timeout': False,
        'partial_record_dropped': False, 'child_process_id': '0x200', 'child_thread_id': '0x204'}
    record.update({name: '0x0' for name in checker.PROCESS_NUMERIC if name not in record})
    record['cleanup_wait_status'] = '0xffffffff'
    return record


def small(key=FIRST, observed=True):
    obs = [observation(key)] if observed else []
    return [copy.deepcopy(MANIFEST), start(key)] + obs + [terminal(key, obs)]


def complete(observed=False):
    yield copy.deepcopy(MANIFEST)
    for key in checker.expected_keys():
        obs = []
        if observed:
            obs = [observation(key)]
            if key[1] == 'veh_seh':
                obs.append(observation(key, 2, 1, 'seh', 'advance'))
        yield start(key)
        yield from obs
        yield terminal(key, obs)
        if key[4] == 19:
            yield group(key)


def run(records, incomplete=True):
    stream = (json.dumps(record, ensure_ascii=True) + '\n' for record in records)
    return checker.Checker('synthetic://unit-tests', incomplete).read(stream).summary()


def errors(summary):
    return '\n'.join(e['message'] for e in summary['validation']['errors'])


def no_numbers(test, value):
    if isinstance(value, bool) or value is None: return
    test.assertNotIsInstance(value, (int, float))
    if isinstance(value, dict):
        for child in value.values(): no_numbers(test, child)
    elif isinstance(value, list):
        for child in value: no_numbers(test, child)


class ContractTests(unittest.TestCase):
    def bad(self, records, message=None):
        result = run(records)
        self.assertFalse(result['validation']['passed'], 'malformed synthetic record was accepted')
        if message: self.assertIn(message, errors(result))
        no_numbers(self, result)
        return result

    def good(self, records):
        result = run(records)
        self.assertTrue(result['validation']['passed'], errors(result))
        return result

    def test_exact_fixed_matrix_4640_runs_232_groups(self):
        keys = checker.expected_keys()
        self.assertEqual(len(keys), 4640)
        self.assertEqual(len(set(keys)), 4640)
        self.assertEqual(len(checker.expected_groups()), 232)
        self.assertEqual([sum(checker.part_for(k[0]) == p for k in keys) for p in (1, 2, 3)], [2880, 1560, 200])

    def test_complete_no_exception_capture_has_no_behavior_oracle(self):
        result = run(complete(), False)
        self.assertTrue(result['validation']['passed'], errors(result))
        self.assertTrue(result['coverage']['all_runs_measured'])
        self.assertEqual(result['coverage']['attempted_run_count'], '0x1220')
        self.assertEqual(len(result['coverage']['completed_without_exception']), 4640)
        self.assertFalse(result['semantics']['native_windows_behavior_verified'])
        self.assertEqual(result['data_provenance'], 'synthetic_test_fixture')
        no_numbers(self, result)

    def test_complete_observed_capture_is_only_structurally_valid(self):
        result = run(complete(True), False)
        self.assertTrue(result['validation']['passed'], errors(result))
        self.assertTrue(result['coverage']['coverage_complete'])
        self.assertFalse(result['semantics']['checker_is_behavioral_oracle'])

    def test_every_missing_cell_is_explicit_without_truncation(self):
        result = run([MANIFEST], False)
        self.assertFalse(result['validation']['passed'])
        self.assertEqual(result['coverage']['missing'], [checker.key_object(k) for k in checker.expected_keys()])
        self.assertEqual(len(result['group_coverage']['missing']), 232)

    def test_allow_incomplete_relaxes_only_coverage(self):
        self.good([MANIFEST])
        self.bad([MANIFEST, {'type': 'invalid'}], 'unknown')

    def test_unsupported_accounted_separately_from_measurements(self):
        records = small()
        records[2]['continuation'].update(action='escape', proposed_rip='0x1001', actual_rip='0x1100')
        records[3] = terminal(FIRST, [records[2]], 'requested_policy_unsupported')
        result = self.good(records)
        self.assertEqual(result['coverage']['unsupported_count'], '0x1')
        self.assertEqual(result['coverage']['completed_count'], '0x0')
        self.assertEqual(result['coverage']['attempted_run_count'], '0x1')

    def test_parent_aborted_unknown_metadata_is_not_zeroed(self):
        record = terminal(status='runtime_aborted', parent=True)
        result = run([MANIFEST, record])
        self.assertTrue(result['validation']['structurally_valid'], errors(result))
        self.assertFalse(result['validation']['passed'])
        self.assertEqual(result['coverage']['attempted_run_count'], '0x0')
        self.assertEqual(result['coverage']['explicitly_not_started'], [checker.key_object(FIRST)])
        record['delivery_count'] = '0x0'
        self.bad([MANIFEST, record], 'must be null')

    def test_parent_abort_preserves_partial_callback_count(self):
        records = small()
        records[3] = terminal(FIRST, [records[2]], 'runtime_aborted', True)
        result = run(records)
        self.assertTrue(result['validation']['structurally_valid'], errors(result))
        self.assertFalse(result['validation']['passed'])
        records[3]['observation_count'] = '0x0'
        self.bad(records, 'observation_count disagrees')

    def test_explicit_skip_is_accounted_but_not_measured(self):
        result = self.good([MANIFEST, terminal(status='skipped', parent=True)])
        self.assertEqual(result['coverage']['skipped_count'], '0x1')
        self.assertEqual(result['coverage']['completed_count'], '0x0')

    def test_guard_escape_is_never_accepted(self):
        records = small()
        records[2]['continuation'].update(action='escape', actual_rip='0x1100')
        records[3] = terminal(FIRST, [records[2]], 'guard_escape')
        self.assertFalse(run(records)['validation']['passed'])

    def test_started_without_result_and_missing_group(self):
        records = [MANIFEST, start()]
        result = run(records, False)
        self.assertEqual(result['coverage']['started_without_result'], [checker.key_object(FIRST)])
        self.assertFalse(result['validation']['passed'])

    def test_duplicate_start_and_terminal(self):
        records = small()
        records.insert(2, start())
        self.bad(records, 'duplicate run_start')
        records = small()
        records.append(copy.deepcopy(records[-1]))
        self.bad(records, 'duplicate terminal')

    def test_terminal_requires_start(self):
        self.bad([MANIFEST, terminal()], 'no preceding run_start')

    def test_observations_before_start_or_after_terminal_fail(self):
        records = small()
        records[1], records[2] = records[2], records[1]
        self.bad(records, 'before run_start')
        records = small()
        records[2], records[3] = records[3], records[2]
        self.bad(records, 'after terminal')

    def test_fixed_matrix_rejects_extra_and_inapplicable_cases(self):
        for field, value in (('variant', 'int2d_2'), ('observer', 'debugger'), ('flag_seed', 'random'),
                             ('policy', 'arbitrary'), ('repeat', '0x14'), ('variant', [])):
            records = small()
            records[1]['key'][field] = value
            with self.subTest(field=field, value=value): self.bad(records, 'key')
        records = small()
        records[1]['key']['observer'] = 'veh_seh'
        self.bad(records, 'combination')
        records = small()
        records[1]['key']['extra'] = 'no'
        self.bad(records, 'exactly')

    def test_all_snapshot_fields_required(self):
        for name in checker.CONTEXT_BITS:
            records = small()
            del records[2]['context'][name]
            with self.subTest(name=name): self.bad(records, name + ' is required')

    def test_raw_context_blob_is_mandatory_and_size_checked(self):
        for value in (None, '0x0', 'zz', '0xzz', '0x' + 'a5'*12):
            records = small()
            records[2]['context_bytes_hex'] = value
            with self.subTest(value=str(value)[:20]): self.bad(records, 'context_bytes_hex')
        records = small()
        records[2]['context_size'] = '0x10'
        self.bad(records, 'context_size')

    def test_fixed_width_registers_and_xmm(self):
        for field, bits in (('ContextFlags',32), ('EFlags',32), ('Rip',64), ('SegCs',16), ('RspMod16',4)):
            records=small(); records[2]['context'][field]=hex(1 << bits)
            with self.subTest(field=field): self.bad(records, 'outside uint')
        for value in ('0x0', hex(1 << 128), '-0x1', None):
            records=small(); records[2]['context']['xmm']['Xmm0']=value
            with self.subTest(value=value): self.bad(records)

    def test_all_fifteen_parameter_slots_and_valid_count(self):
        for count in (0, 1, 4, 15):
            records=small(); records[2]['exception']['NumberParameters']=hex(count)
            records[2]['exception_information_valid_slots']=hex(count)
            with self.subTest(count=count): self.good(records)
        for value in (None, [], ['0x0']*4, ['0x0']*16):
            records=small(); records[2]['exception']['ExceptionInformation']=value
            self.bad(records, 'fifteen')
        records=small(); records[2]['exception']['NumberParameters']='0x10'
        records[2]['exception_information_valid_slots']='0xf'
        result=self.good(records); self.assertTrue(result['validation']['warnings'])
        records=small(); records[2]['exception_information_valid_slots']='0x1'
        self.bad(records, 'valid_slots disagrees')

    def test_references_do_not_dereference_unknown_values(self):
        records=small(); records[2]['exception']['parameter_references'][0]['dereferenced']=True
        self.bad(records, 'dereferenced')
        records=small(); records[2]['exception']['parameter_references'][0]['offset']='0x1'
        self.bad(records, 'unclassified')

    def test_full_gpr_and_xmm_difference_lists_are_internal_checks(self):
        records=small(); records[2]['context']['gpr']['Rcx']='0xdeadbeef'
        self.bad(records, 'gpr_differences does not match')
        records[2]['gpr_differences']=['Rcx']; self.good(records)
        records[2]['gpr_differences']=['Rcx','Rcx']; self.bad(records, 'duplicates')
        records=small(); records[2]['context']['xmm']['Xmm0']='0x'+'11'*16
        self.bad(records, 'xmm_differences does not match')
        records[2]['xmm_differences']=['Xmm0']; self.good(records)

    def test_rsp_duplicates_and_modulo_are_consistent(self):
        records=small(); records[2]['context']['RspMod16']='0x1'; self.bad(records, 'RspMod16')
        records=small(); records[2]['context']['gpr']['Rsp']='0x2'; self.bad(records, 'context.Rsp disagrees')

    def test_xstate_size_is_unknown_even_if_flag_present(self):
        records=small(); records[2]['context']['ContextFlags']='0x10005f'; records[2]['xstate']['present']=True
        self.good(records)
        records[2]['xstate']['total_length']='0x400'; self.bad(records, 'must be null')
        records=small(); records[2]['xstate']['present']=True; self.bad(records, '0x40')

    def test_owned_offsets_and_no_offsets_in_system_code(self):
        records=small(); records[2]['context']['RipOffset']='0x1'; self.bad(records, 'declared owned origin')
        key=('debugbreak','veh','clear','api_keep',0)
        records=small(key); self.good(records)
        records[2]['context']['RipOffset']='0x6ffff000'; self.bad(records, 'no system-code offsets')
        records=small(); records[2]['context']['RipLocation']='inside_system_library'
        records[2]['context']['RipOffset']=None; records[2]['context']['RipOffsetReference']='none'
        self.bad(records, 'owned bounds')

    def test_post_gprs_and_first_last_flags_are_preserved_separately(self):
        records=small(); records[3]['post_rflags']='0x302'; records[3]['last_pushfq_rflags']='0x202'
        self.good(records)
        records[3]['post_rflags']='0x10202'; result=self.good(records)
        self.assertIn('RF/VM',result['validation']['warnings'][0]['message'])

    def test_nine_pushfq_stack_delta_all_entry_offsets(self):
        for entry in range(9):
            records=small(); r=records[3]
            r['continuation_entry_offset']=hex(entry); r['continuation_site_offset']=hex(2+entry)
            r['post_rsp_raw']=hex(0x100000-(9-entry)*8)
            with self.subTest(entry=entry): self.good(records)
        records=small(); records[3]['post_rsp_raw']='0xfffb0'; self.bad(records, 'nine-PUSHFQ')
        records=small(); records[3]['post_gpr']['Rsp']='0xfffb8'; self.bad(records, 'nine-PUSHFQ')
        records=small(); records[3]['continuation_entry_offset']='0x9'; self.bad(records, 'at least one')

    def test_unavailable_post_state_cannot_claim_stale_flags(self):
        records=small(); records[2]['continuation'].update(action='escape',actual_rip='0x1100')
        records[3]=terminal(FIRST,[records[2]],'requested_policy_unsupported')
        for field,value in (('post_rflags','0xa5'),('post_gpr',gprs(FIRST)),('continuation_entry_offset','0x0')):
            mutation=copy.deepcopy(records); mutation[3][field]=value
            with self.subTest(field=field): self.bad(mutation, 'null')

    def test_alternate_has_separate_origin(self):
        key=('ctx_int2d_0','veh','clear','alternate',0)
        records=small(key); self.good(records)
        records[3]['continuation_site_offset']='0x1100'; self.bad(records,'alternate landing')
        records=small(key); records[2]['continuation']['actual_rip']='0x2101'; self.bad(records,'actual_rip')

    def test_arbitrary_exception_code_not_a_windows_oracle(self):
        records=small(); records[2]['exception']['ExceptionCode']='0xc0000005'
        records[2]['context']['Dr6']='0x1234'; self.good(records)

    def test_tf_second_stage_incoming_flag_may_be_set_or_clear(self):
        key=('ctx_int2d_0','veh','clear','enable_tf',0)
        for incoming in (0x202,0x302):
            first=observation(key)
            second=observation(key,2,2,action='clear_tf_keep',stage='second_trap')
            set_location(second, int(second['sled_start'],16)+1)
            second['exception']['ExceptionCode']='0x80000004'; second['context']['EFlags']=hex(incoming)
            second['context']['Dr6']='0xffff0ff0'; second['context']['Rsp']='0xffff8'; second['context']['RspMod16']='0x8'
            second['context']['gpr']['Rsp']='0xffff8'; second['gpr_differences']=['Rsp']
            second['continuation'].update(proposed_rip=second['context']['Rip'],actual_rip=second['context']['Rip'],tf_cleared=bool(incoming&0x100))
            obs=[first,second]
            records=[MANIFEST,start(key)]+obs+[terminal(key,obs)]
            with self.subTest(incoming=incoming): self.good(records)

    def test_tf_action_not_reached_is_a_valid_no_delivery_measurement(self):
        key=('ctx_int2d_stack','uef','set','enable_tf',0)
        result=self.good(small(key,False))
        self.assertEqual(result['coverage']['completed_count'],'0x1')

    def test_tf_cleared_requires_sampled_tf_but_not_os_clear(self):
        records=small(); records[2]['continuation']['tf_cleared']=True; self.bad(records,'incoming TF')

    def test_veh_search_seh_is_one_delivery_two_callbacks(self):
        key=('ctx_int3_cc','veh_seh','clear','veh_search_seh',0)
        obs=[observation(key),observation(key,2,1,'seh','advance')]
        records=[MANIFEST,start(key)]+obs+[terminal(key,obs)]
        self.good(records)
        records[-1]['delivery_count']='0x2'; self.bad(records,'delivery_count disagrees')

    def test_vch_is_read_only_and_not_a_delivery_or_guard_increment(self):
        key=('ctx_int2d_0','veh','clear','vch_order',0)
        obs=[observation(key),observation(key,2,1,'vch')]
        records=[MANIFEST,start(key)]+obs+[terminal(key,obs)]
        self.good(records)
        records[3]['continuation']['tf_cleared']=True; self.bad(records,'must not mutate TF')

    def test_vch_order_is_recorded_not_hardcoded(self):
        key=('ctx_int2d_0','veh','clear','vch_order',0)
        obs=[observation(key,1,0,'vch'),observation(key,2,1)]
        self.good([MANIFEST,start(key)]+obs+[terminal(key,obs)])

    def test_callback_indices_order_counts_and_registration(self):
        for field,value in (('callback_ordinal','0x2'),('delivery_index','0x2'),('observer','seh')):
            records=small(); records[2][field]=value
            with self.subTest(field=field): self.bad(records)
        records=small(); records[-1]['callback_order']=[]; self.bad(records,'callback_order disagrees')
        records=small(); records[-1]['vch_count']='0x1'; self.bad(records,'vch_count disagrees')

    def test_void_api_has_no_invented_return(self):
        for name in ('debugbreak','output_a','output_w'):
            key=(name,'veh','clear','api_keep',0); records=small(key); self.good(records)
            records[-1]['api_result']['return_value']='0x0'
            with self.subTest(name=name): self.bad(records,'void')

    def test_check_remote_success_out_bool_and_failure_error_are_distinct(self):
        key=('check_remote_debugger_present','veh','clear','api_keep',0)
        records=small(key); self.good(records)
        r=records[-1]; r['post_rax']=r['post_gpr']['Rax']='0x0'
        r['api_result'].update(return_value='0x0',remote_present=None,last_error='0x5'); self.good(records)
        r['api_result']['remote_present']='0x0'; self.bad(records,'only after successful')
        r['api_result'].update(remote_present=None,last_error=None); self.bad(records,'last_error')

    def test_is_debugger_present_bool_is_not_assumed(self):
        key=('is_debugger_present','veh','clear','api_keep',0)
        for value in (0,1,2,0xffffffff):
            records=small(key); r=records[-1]; r['post_rax']=r['post_gpr']['Rax']=hex(value)
            r['api_result']['return_value']=hex(value)
            with self.subTest(value=value): self.good(records)

    def test_returned_status_and_post_validity_are_consistent(self):
        for field,value in (('probe_returned',False),('post_snapshot_valid',False),('safety_escape',True),('capture_path','alternate')):
            records=small(); records[-1][field]=value
            with self.subTest(field=field): self.bad(records)

    def test_manifest_counts_architecture_and_order(self):
        for field,value in (('schema_version','0x4'),('planned_runs','0x10e0'),('families','0xc'),('architecture','arm64'),('context_size','0x0')):
            records=small(); records[0][field]=value
            with self.subTest(field=field): self.bad(records)
        self.bad([MANIFEST]+small(),'exactly one')
        self.bad(small()[1:],'before manifest')

    def test_group_process_identity_and_index(self):
        records=small()+[group(count=1)]; self.good(records)
        records[-1]['child_process_id']='0x999'; self.bad(records,'process_id disagrees')
        records=small()+[group(count=1)]; records[-1]['group_index']='0x1'; self.bad(records,'group_index')
        records=small()+[group(count=1),group(count=1)]; self.bad(records,'duplicate group_result')

    def test_timeout_even_if_reaped_is_a_runtime_failure(self):
        records=small()+[group(count=1)]
        records[-1].update(timeout=True,wait_status='0x102',cleanup_wait_status='0x0')
        result=run(records); self.assertTrue(result['validation']['structurally_valid'],errors(result))
        self.assertFalse(result['validation']['passed'])

    def test_group_failures_not_ignored_by_allow_incomplete(self):
        for field,value in (('child_exit_code','0x2'),('partial_record_dropped',True),('exit_query_error','0x5')):
            records=small()+[group(count=1)]; records[-1][field]=value
            with self.subTest(field=field): self.assertFalse(run(records)['validation']['passed'])

    def test_impossible_child_lifecycle_is_rejected(self):
        records=small()+[group(count=1)]; records[-1]['created']=False; self.bad(records,'was not created')
        records=small()+[group(count=1)]; records[-1]['assigned']=False; self.bad(records,'cleanup job')
        records=small()+[group(count=1)]; records[-1]['reaped']=False; self.bad(records,'wait statuses')

    def test_known_numeric_strings_and_unsigned_ranges(self):
        for value in ('514','0X202','-0x1','0x',True,None):
            records=small(); records[2]['context']['EFlags']=value
            with self.subTest(value=value): self.bad(records,'hexadecimal')

    def test_json_numbers_are_rejected_in_arbitrary_nested_metadata(self):
        for value in (1,1.5,-1):
            records=small(); records[0]['extra']={'arbitrary':[value]}
            with self.subTest(value=value): self.bad(records,'JSON number')

    def test_malformed_shapes_do_not_crash(self):
        for value in (None,[],'record',7,True):
            with self.subTest(value=value): self.bad([MANIFEST,value],'must be an object')
        for field in ('context','exception','continuation','xstate','gpr_expected'):
            for value in (None,[],'bad',True):
                records=small(); records[2][field]=value
                with self.subTest(field=field,value=value): self.bad(records)
        for value in (None,[],{},True):
            records=small(); records[-1]['status']=value
            with self.subTest(value=value): self.bad(records)

    def test_parser_duplicate_members_nan_infinity_and_blank_lines(self):
        for line in ('{"type":"manifest","type":"manifest"}','{"x":NaN}','{"x":Infinity}',''):
            result=checker.Checker('synthetic',True).read(io.StringIO(json.dumps(MANIFEST)+'\n'+line+'\n')).summary()
            with self.subTest(line=line): self.assertFalse(result['validation']['passed'])

    def test_invalid_json_utf8_bom_and_recovery(self):
        data=b'\xef\xbb\xbf'+json.dumps(MANIFEST).encode()+b'\n'
        result=checker.Checker('synthetic',True).read(io.BytesIO(data)).summary(); self.assertTrue(result['validation']['passed'])
        result=checker.Checker('synthetic',True).read(io.BytesIO(data+b'\xff\n{broken}\n')).summary()
        self.assertFalse(result['validation']['passed']); self.assertIn('invalid UTF-8',errors(result)); self.assertIn('invalid JSON',errors(result))

    def test_summary_is_idempotent_and_no_numeric_json(self):
        obj=checker.Checker('synthetic',True).read([json.dumps(MANIFEST)+'\n'])
        first=obj.summary(); second=obj.summary(); self.assertEqual(first,second); no_numbers(self,first)

    def test_variability_retains_raw_fields_and_separates_callbacks(self):
        records=[MANIFEST]
        for repeat in (0,1):
            key=FIRST[:4]+(repeat,); obs=observation(key)
            obs['context']['Dr6']=hex(repeat)
            records += [start(key),obs,terminal(key,[obs])]
        result=self.good(records)
        fields={x['field'] for x in result['variability']['observations'][0]['across_depths']['unstable_fields']}
        self.assertIn('context.Dr6',fields)
        self.assertTrue(all(not x['comparison_possible'] for x in result['variability']['observations'][0]['within_depths']))

    def test_group_terminal_count_is_exact_not_only_a_lower_bound(self):
        records=small()+[group(count=2)]
        self.bad(records,'child_terminal_records disagrees')

    def test_group_closure_precedes_no_further_run_records(self):
        records=[MANIFEST,group(count=1)]+small()[1:]
        self.bad(records,'after its group_result')

    def test_noncontinuable_tf_stage_counts_the_observed_trap(self):
        key=('ctx_int2d_0','veh','clear','enable_tf',0)
        first=observation(key)
        second=observation(key,2,2,action='terminate',stage='second_trap')
        second['exception'].update(ExceptionCode='0x80000004',ExceptionFlags='0x1')
        second['continuation']['reason']='noncontinuable_exception'
        obs=[first,second]; result=terminal(key,obs,'runtime_aborted')
        result['second_trap_count']='0x1'
        summary=run([MANIFEST,start(key)]+obs+[result])
        self.assertTrue(summary['validation']['structurally_valid'],errors(summary))
        self.assertFalse(summary['validation']['passed'])

    def test_escape_cannot_target_unowned_code(self):
        records=small(); records[2]['continuation'].update(action='escape',actual_rip='0x90000000')
        records[-1]=terminal(FIRST,[records[2]],'requested_policy_unsupported')
        self.bad(records,'owned probe cleanup')

    def test_own_function_input_is_bound_to_recorded_function_address(self):
        key=('int2d_function','veh','clear','advance',0)
        records=small(key); self.good(records)
        records[1]['requested_rax']='0x1234'; self.bad(records,'own-function')

    def test_api_keep_cannot_continue_at_unverified_addresses(self):
        key=('debugbreak','veh','clear','api_keep',0)
        records=small(key); set_location(records[2],0x70000000,'unclassified_address')
        self.bad(records,'API keep requires')

    def test_actual_capture_may_differ_from_requested_alternate(self):
        key=('ctx_int2d_0','veh','clear','alternate',0)
        records=small(key); r=records[-1]
        r.update(capture_marker='0x1',capture_path='normal',continuation_target='owned_probe_sled',continuation_site_offset='0x2')
        self.good(records)
        r['capture_marker']='0x2'; self.bad(records,'capture_marker disagrees')
        r['capture_marker']='0x1'; r['requested_alternate']=False
        self.bad(records,'requested_alternate disagrees')

    def test_policy_actions_are_collector_bookkeeping_not_os_predictions(self):
        records=small(); records[2]['continuation'].update(action='keep',proposed_rip='0x1000',actual_rip='0x1000')
        self.bad(records,'keep action disagrees')
        key=FIRST[:3]+('keep_then_advance',0); records=small(key)
        records[2]['continuation'].update(action='advance',proposed_rip='0x1002',actual_rip='0x1002')
        self.bad(records,'advance action disagrees')

    def test_clear_tf_keep_requires_owned_rip_stack_geometry(self):
        key=('ctx_int2d_0','veh','clear','enable_tf',0)
        first=observation(key)
        second=observation(key,2,2,action='clear_tf_keep',stage='second_trap')
        second['exception']['ExceptionCode']='0x80000004'
        obs=[first,second]
        self.bad([MANIFEST,start(key)]+obs+[terminal(key,obs)],'owned TF stack/RIP geometry')


class StaticEmitterContractTests(unittest.TestCase):
    """Static extraction of real producer fields, not execution of that producer."""
    @classmethod
    def setUpClass(cls):
        cls.source=pathlib.Path(checker.__file__).with_name('exception_probe.c').read_text(encoding='utf-8')

    def function(self,name):
        found=re.search(r'^static\s+[^\n]*\b'+re.escape(name)+r'\s*\([^;]*?\)\s*\{',self.source,re.M)
        self.assertIsNotNone(found,'actual C emitter function is absent: '+name)
        rest=self.source[found.start():]
        end=re.search(r'^static\s',rest[1:],re.M)
        return rest[:end.start()+1] if end else rest

    @staticmethod
    def fields(source):
        names=set(re.findall(r'\b(?:fieldhex|fieldstr|fieldbool|key_name)\(\s*"([A-Za-z][A-Za-z0-9_]*)"',source))
        for literal in re.findall(r'"(?:\\.|[^"\\])*"',source):
            try: decoded=json.loads(literal)
            except ValueError: continue
            names.update(re.findall(r'"([A-Za-z][A-Za-z0-9_]*)"\s*:',decoded))
        names.update(re.findall(r'\bC\(([A-Za-z][A-Za-z0-9_]*)\)\s*;',source))
        return names

    @staticmethod
    def all_fields(value):
        result=set()
        if isinstance(value,dict):
            result.update(value)
            for child in value.values(): result.update(StaticEmitterContractTests.all_fields(child))
        elif isinstance(value,list):
            for child in value: result.update(StaticEmitterContractTests.all_fields(child))
        return result

    def test_actual_c_emitted_member_names_exist_in_synthetic_fixtures(self):
        key=('check_remote_debugger_present','veh','clear','api_keep',0)
        obs=observation(key)
        cases=[('manifest',MANIFEST),('emit_observations',obs),('emit_context',obs['context']),
               ('emit_result',terminal(key,[obs])),('parameter_reference',reference())]
        for function,fixture in cases:
            with self.subTest(function=function):
                emitted=self.fields(self.function(function))
                self.assertTrue(emitted,'static emitter extraction unexpectedly empty')
                self.assertEqual(emitted-self.all_fields(fixture),set(),'fixture misses fields from actual C emitter')
        child=self.function('child')
        segment=child[child.index('begin("run_start")'):]
        segment=segment[:segment.index('end_record()')]
        self.assertEqual(self.fields(segment)-self.all_fields(start()),set())

    def test_actual_c_case_observer_policy_enums_equal_checker(self):
        found=tuple(re.findall(r'\bV\("([^"]+)"',self.source))
        self.assertEqual(found,checker.VARIANTS)
        for variable,expected in (('observer_names',checker.OBSERVERS),('policy_names',checker.POLICIES),('seed_names',checker.FLAG_SEEDS)):
            match=re.search(variable+r'\[\]\s*=\s*\{(.*?)\};',self.source,re.S)
            self.assertIsNotNone(match)
            self.assertEqual(tuple(re.findall(r'"([^"]+)"',match.group(1))),expected)

    def test_actual_c_dimensions_slot_limits_and_post_method(self):
        for name,wanted in (('NVAR',20),('REPEATS',20),('SNAP_CAP',32)):
            match=re.search(r'#define\s+'+name+r'\s+(\d+)u',self.source)
            self.assertIsNotNone(match); self.assertEqual(int(match.group(1)),wanted)
        manifest=self.function('manifest')
        for name,wanted in (('schema_version',5),('planned_runs',4640),('families',3),('observers',4),('flag_seeds',2),('policies',8),('groups',232)):
            match=re.search(r'fieldhex\("'+name+r'",\s*(\d+)\)',manifest)
            self.assertIsNotNone(match,name); self.assertEqual(int(match.group(1)),wanted)
        self.assertGreaterEqual(len(re.findall(r'z\s*<\s*EXCEPTION_MAXIMUM_PARAMETERS',self.function('emit_observations'))),2)
        self.assertIn('nine_one_byte_PUSHFQ_then_MOV_GPR_first_image_at_entry_rsp_minus_8',self.function('emit_result'))
        self.assertNotIn('assert ',pathlib.Path(checker.__file__).read_text())


class CommandLineTests(unittest.TestCase):
    def invoke(self,raw,out,*extra):
        return subprocess.run([sys.executable,str(pathlib.Path(checker.__file__).resolve()),str(raw),'--summary',str(out),*extra],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)

    def test_cli_incomplete_malformed_and_summary_protection(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-v5-checker-') as directory:
            raw=pathlib.Path(directory)/'raw.jsonl'; out=pathlib.Path(directory)/'summary.json'
            original=json.dumps(MANIFEST)+'\n'; raw.write_text(original)
            self.assertEqual(self.invoke(raw,out).returncode,1)
            self.assertEqual(self.invoke(raw,out,'--allow-incomplete').returncode,0)
            self.assertEqual(self.invoke(raw,raw,'--allow-incomplete').returncode,2)
            self.assertEqual(raw.read_text(),original)
            raw.write_text(original+'{broken}\n')
            self.assertEqual(self.invoke(raw,out,'--allow-incomplete').returncode,1)
            self.assertFalse(json.loads(out.read_text())['validation']['passed'])

    def test_cli_missing_file_io_error(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-v5-checker-') as directory:
            path=pathlib.Path(directory)
            self.assertEqual(self.invoke(path/'missing',path/'summary').returncode,2)
            result=json.loads((path/'summary').read_text())
            self.assertEqual(result['data_provenance'],'missing_input')
            self.assertIsNone(result['input']['sha256'])
            self.assertEqual(result['input']['read_status'],'missing_input')
            self.assertEqual(len(result['coverage']['missing']),4640)
            self.assertEqual(len(result['group_coverage']['missing']),232)
            self.assertFalse(result['validation']['passed'])

    def test_optimized_python_rejects_impossible_log(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-v5-checker-') as directory:
            raw=pathlib.Path(directory)/'raw.jsonl'; out=pathlib.Path(directory)/'summary.json'
            records=small(); records[-1]['post_rsp_raw']='0x1'
            raw.write_text(''.join(json.dumps(r)+'\n' for r in records))
            result=subprocess.run([sys.executable,'-O',str(pathlib.Path(checker.__file__).resolve()),str(raw),
                '--summary',str(out),'--allow-incomplete'],capture_output=True,text=True,check=False)
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertIn('nine-PUSHFQ',errors(json.loads(out.read_text())))


if __name__=='__main__':
    unittest.main()
