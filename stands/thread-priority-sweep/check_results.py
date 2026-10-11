#!/usr/bin/env python3
"""Strict offline JSONL validation. Never executes a Windows program."""
import argparse
import json
import math
from pathlib import Path

MATRIX = {
    'IDLE': [1, 2, 3, 4, 5, 6, 15],
    'BELOW_NORMAL': [1, 4, 5, 6, 7, 8, 15],
    'NORMAL': [1, 6, 7, 8, 9, 10, 15],
    'ABOVE_NORMAL': [1, 8, 9, 10, 11, 12, 15],
    'HIGH': [1, 11, 12, 13, 14, 15, 15],
}
LEVELS = ['IDLE', 'LOWEST', 'BELOW_NORMAL', 'NORMAL', 'ABOVE_NORMAL', 'HIGHEST', 'TIME_CRITICAL']
LEVEL_VALUES = [-15, -2, -1, 0, 1, 2, 15]
CLASS_VALUES = {'IDLE': 64, 'BELOW_NORMAL': 16384, 'NORMAL': 32, 'ABOVE_NORMAL': 32768, 'HIGH': 128}
CANONICAL = [('NORMAL', 'IDLE'), ('IDLE', 'LOWEST'), ('IDLE', 'BELOW_NORMAL'),
             ('IDLE', 'NORMAL'), ('IDLE', 'ABOVE_NORMAL'), ('BELOW_NORMAL', 'NORMAL'),
             ('NORMAL', 'BELOW_NORMAL'), ('NORMAL', 'NORMAL'), ('NORMAL', 'ABOVE_NORMAL'),
             ('NORMAL', 'HIGHEST'), ('ABOVE_NORMAL', 'ABOVE_NORMAL'), ('ABOVE_NORMAL', 'HIGHEST'),
             ('HIGH', 'NORMAL'), ('HIGH', 'ABOVE_NORMAL'), ('HIGH', 'HIGHEST')]
TYPES = {'metadata', 'run_identity', 'boost_state', 'mapping', 'class_gaps', 'union_gaps',
         'condition_created', 'condition_controller', 'child_created', 'child_config',
         'run_start', 'sample', 'child_result', 'run_result', 'cleanup', 'outer_cleanup',
         'comparison', 'complete', 'error', 'unassigned_child_cleanup', 'outer_termination'}


def no_duplicate_keys(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def no_constant(value):
    raise ValueError(f'nonfinite JSON value: {value}')


def load_jsonl(text):
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line, object_pairs_hook=no_duplicate_keys, parse_constant=no_constant)
        if not isinstance(row, dict):
            raise ValueError(f'line {number}: expected object')
        rows.append(row)
    if not rows:
        raise ValueError('empty JSONL')
    return rows


def validate(records):
    errors, warnings, summaries = [], [], []
    def need(ok, message):
        if not ok:
            errors.append(message)
    def same_number(actual, expected, message, tolerance=1e-7):
        need(isinstance(actual, (int, float)) and not isinstance(actual, bool)
             and math.isfinite(actual) and math.isclose(actual, expected, rel_tol=1e-9, abs_tol=tolerance), message)
    def one(kind, rows):
        found = [r for r in rows if r.get('type') == kind]
        need(len(found) == 1, f'{kind}: expected one record, found {len(found)}')
        return found[0] if found else {}
    def base_of(cls, level):
        return MATRIX[cls][LEVELS.index(level)] if cls in MATRIX and level in LEVELS else None
    def check_priority(row, cls, level, context):
        need(row.get('class') == cls and row.get('level') == level, context + ': class/level')
        need(row.get('nominal_base') == base_of(cls, level), context + ': nominal base')
    def finite(value):
        if isinstance(value, float):
            return math.isfinite(value)
        if isinstance(value, dict):
            return all(finite(v) for v in value.values())
        if isinstance(value, list):
            return all(finite(v) for v in value)
        return True
    need(bool(records), 'empty record list')
    if not records:
        return dict(valid=False, errors=errors, warnings=warnings, comparisons=summaries)
    need(all(r.get('type') in TYPES for r in records), 'unknown record type')
    need(all(finite(r) for r in records), 'nonfinite number')
    if not all(finite(r) for r in records):
        return dict(valid=False,errors=errors,warnings=warnings,comparisons=summaries)
    top_types = {'metadata','run_identity','boost_state','mapping','class_gaps','union_gaps','complete'}
    need(all('run' in r or r.get('type') in top_types for r in records), 'scoped record missing run ID')
    need(not any(r.get('type') in {'error', 'outer_termination', 'unassigned_child_cleanup'} for r in records), 'probe reported error/abnormal cleanup')
    def positive_id(value):
        return isinstance(value,int) and not isinstance(value,bool) and 0 < value <= 0xffffffff
    for row in records:
        kind=row.get('type')
        id_fields = ['parent_pid'] if kind=='run_identity' else ['pid','supervisor_pid'] if kind=='condition_created' else ['pid'] if kind in {'condition_controller','child_result'} else ['pid','tid'] if kind in {'child_created','child_config'} else []
        need(all(positive_id(row.get(field)) for field in id_fields), f'{kind}: missing/invalid PID/TID')
        if kind=='boost_state':
            need(isinstance(row.get('process_boost_disabled'),bool) and isinstance(row.get('thread_boost_disabled'),bool), 'invalid boost-state booleans')
    metadata, identity, complete = one('metadata', records), one('run_identity', records), one('complete', records)
    need(metadata.get('schema') == 1 and metadata.get('architecture') == 'x64', 'unsupported schema/architecture')
    need(complete.get('valid') is True and complete.get('windows_execution') is True, 'missing successful completion')
    need(records[-1].get('type') == 'complete', 'last record is not complete')
    frequency = metadata.get('qpc_frequency', 0)
    need(isinstance(frequency, int) and frequency > 0, 'invalid QPC frequency')
    if not frequency:
        return dict(valid=False, errors=errors, warnings=warnings, comparisons=summaries)
    need(metadata.get('active_groups') == 1 and metadata.get('processor_group') == 0, 'unsupported group topology')
    allowed = int(metadata.get('allowed_mask', '0'), 16)
    observer = int(metadata.get('observer_mask', '0'), 16)
    original_process = int(metadata.get('original_process_mask', '0'), 16)
    original_thread = int(metadata.get('original_thread_mask', '0'), 16)
    system_mask = int(metadata.get('system_mask', '0'), 16)
    cpus = {i for i in range(64) if allowed & (1 << i)}
    worker_cpu = metadata.get('worker_cpu', -1)
    need(2 <= len(cpus) <= 8 and metadata.get('allowed_cpu_count') == len(cpus), 'allowed CPU count')
    need(allowed == (original_process & original_thread) and (allowed & system_mask) == allowed, 'allowed affinity derivation')
    need(worker_cpu in cpus and observer == sum(1 << c for c in cpus if c != worker_cpu), 'observer/worker affinity')
    need(metadata.get('cpu_sets') == 'none_selected' and metadata.get('dynamic_priority_measured') is False, 'scope metadata')
    sample_ms = metadata.get('sample_ms', 0)
    need(sample_ms == 100 and metadata.get('block_steps') == 4096, 'unexpected sample/block configuration')
    period = frequency * sample_ms // 1000
    need(period > 0, 'invalid sample period')
    short_ms, busy_ms, warmup_ms = [metadata.get(k, 0) for k in ('short_ms', 'busy_ms', 'warmup_ms')]
    need(1000 <= short_ms <= 30000 and 1000 <= busy_ms <= 120000 and 100 <= warmup_ms <= 5000, 'duration options out of range')
    mapping_rows = [r for r in records if r.get('type') == 'mapping']
    pairs = {(r.get('class'), r.get('level')): r for r in mapping_rows}
    need(len(mapping_rows) == 35 and len(pairs) == 35, 'expected 35 unique mapping records')
    for cls, bases in MATRIX.items():
        for index, (level, base) in enumerate(zip(LEVELS, bases)):
            r = pairs.get((cls, level), {})
            need(r.get('nominal_base') == base and r.get('class_value') == CLASS_VALUES[cls]
                 and r.get('level_value') == LEVEL_VALUES[index], f'mapping mismatch {cls}/{level}')
            need(r.get('canonical') == ((cls, level) == CANONICAL[base-1]), f'canonical mismatch {cls}/{level}')
        gaps = [r for r in records if r.get('type') == 'class_gaps' and r.get('class') == cls]
        need(len(gaps) == 1 and gaps[0].get('unreachable_bases') == sorted(set(range(1,16))-set(bases)), f'class gaps {cls}')
    need(len([r for r in records if r.get('type') == 'class_gaps']) == 5, 'duplicate/extra class gaps')
    union = one('union_gaps', records)
    need(union.get('unreachable_bases') == [] and union.get('dynamic_priority_measured') is False, 'union mapping scope')
    only_base = metadata.get('only_base', 0)
    need(isinstance(only_base, int) and 0 <= only_base <= 15, 'invalid only_base')
    all_pairs = metadata.get('all_pairs')
    need(isinstance(all_pairs, bool) and not (all_pairs and only_base), 'invalid pair selection')
    selected = [(c, l) for c in MATRIX for l in LEVELS] if all_pairs else [p for b, p in enumerate(CANONICAL, 1) if not only_base or b == only_base]
    run_ids = sorted({r['run'] for r in records if r.get('type') == 'run_start'})
    expected_ids = list(range(1, len(selected)*5+1))
    need(run_ids == expected_ids and complete.get('runs') == len(expected_ids), 'run coverage/count')
    need([r.get('run') for r in records if r.get('type')=='run_start'] == expected_ids, 'run record order')
    need(all('run' not in r or r['run'] in expected_ids for r in records), 'unexpected run ID')
    top_boosts = [r for r in records if r.get('type') == 'boost_state' and 'run' not in r]
    need(len(top_boosts) == 1 and top_boosts[0].get('role') == 'controller', 'controller boost record')
    results, starts, samples_by_run = {}, {}, {}
    positions = {id(r): i for i, r in enumerate(records)}
    for run in run_ids:
        rows = [r for r in records if r.get('run') == run]
        start, result = one('run_start', rows), one('run_result', rows)
        cleanup, outer = one('cleanup', rows), one('outer_cleanup', rows)
        created, controller = one('condition_created', rows), one('condition_controller', rows)
        starts[run], results[run] = start, result
        offset = (run-1) % 5
        pair = selected[(run-1)//5]
        role = 'baseline_before' if offset == 0 else 'baseline_after' if offset == 4 else 'measurement'
        condition = ['alone', 'alone', 'one_free', 'all_busy', 'alone'][offset]
        cls, level = ('NORMAL', 'NORMAL') if offset in (0,4) else pair
        need(start.get('role') == role and start.get('condition') == condition, f'run {run}: role/condition order')
        check_priority(start, cls, level, f'run {run}: start priority')
        need(controller.get('class_readback') == 32 and controller.get('level_readback') == 0, f'run {run}: observer priority')
        need(int(controller.get('observer_mask', '0'), 16) == observer, f'run {run}: observer affinity')
        need(created.get('pid') == controller.get('pid') and created.get('supervisor_pid') == identity.get('parent_pid'), f'run {run}: controller identity')
        need(result.get('valid') is True and cleanup.get('valid') is True and outer.get('valid') is True, f'run {run}: invalid result/cleanup')
        need(cleanup.get('owned_children_reaped') is True and cleanup.get('job_terminated') is False, f'run {run}: abnormal helper cleanup')
        need(outer.get('controller_reaped') is True and outer.get('active_owned_processes') == 0, f'run {run}: outer cleanup')
        competitor_cpus = set() if condition == 'alone' else cpus - {worker_cpu} if condition == 'one_free' else cpus
        n = len(competitor_cpus)
        need(start.get('competitors') == n, f'run {run}: competitor count')
        configs = [r for r in rows if r.get('type') == 'child_config']
        children = [r for r in rows if r.get('type') == 'child_result']
        child_creates = [r for r in rows if r.get('type') == 'child_created']
        boosts = [r for r in rows if r.get('type') == 'boost_state']
        for name, items in [('config',configs), ('result',children), ('created',child_creates), ('boost',boosts)]:
            need(len(items) == n+1 and sorted(r.get('index',-1) for r in items) == list(range(n+1)), f'run {run}: child {name} coverage')
        need(len({r.get('pid') for r in configs}) == n+1 and controller.get('pid') not in {r.get('pid') for r in configs}, f'run {run}: separate processes')
        need({r.get('cpu') for r in configs if r.get('index') != 0} == competitor_cpus, f'run {run}: exact competitor CPU set')
        a, b = start.get('start_qpc',0), start.get('end_qpc',0)
        duration_ms = busy_ms if condition == 'all_busy' else short_ms
        need(start.get('duration_ms') == duration_ms and b-a == frequency*duration_ms//1000, f'run {run}: duration mismatch')
        need(a-start.get('release_qpc',0) == frequency*warmup_ms//1000, f'run {run}: warmup mismatch')
        wall = (b-a)/frequency
        need(wall > 0, f'run {run}: invalid window')
        same_number(result.get('window_seconds'),wall,f'run {run}: wall mismatch')
        need(result.get('window_midpoint_qpc') == a+(b-a)//2, f'run {run}: midpoint mismatch')
        need(result.get('condition') == condition, f'run {run}: result condition')
        worker = {}
        for c in configs:
            index = c.get('index'); child_role = 'worker' if index == 0 else 'competitor'
            cc, ll = (cls,level) if index == 0 else ('NORMAL','NORMAL')
            check_priority(c,cc,ll,f'run {run}: {child_role} priority')
            need(c.get('class_readback') == CLASS_VALUES[cc] and c.get('level_readback') == LEVEL_VALUES[LEVELS.index(ll)], f'run {run}: priority API readbacks')
            cpu = c.get('cpu',-1)
            need(cpu in cpus and c.get('group') == 0 and int(c.get('mask','0'),16) == 1 << cpu, f'run {run}: helper affinity')
            if index == 0:
                need(cpu == worker_cpu, f'run {run}: worker CPU')
            matching = [x for x in children if x.get('index') == index]
            cm = [x for x in child_creates if x.get('index') == index]
            need(len(matching) == 1 and len(cm) == 1, f'run {run}: helper records')
            if not matching or not cm:
                continue
            x, cr = matching[0], cm[0]
            need(c.get('role') == x.get('role') == child_role and c.get('pid') == x.get('pid') == cr.get('pid') and c.get('tid') == cr.get('tid'), f'run {run}: helper identity')
            need(x.get('cpu') == cpu and x.get('exit_code') == 0, f'run {run}: helper exit/CPU')
            need(x.get('configured_class') == x.get('final_class') == c.get('class_readback') and x.get('configured_level') == x.get('final_level') == c.get('level_readback'), f'run {run}: final priority changed')
            need(x.get('blocks',-1) >= 0 and x.get('exit_qpc',0) >= b, f'run {run}: helper final values')
            if x.get('started') is True:
                need(a <= x.get('first_work_qpc',0) < b, f'run {run}: first work time')
                marker = [x.get(k,0) for k in ('first_work_qpc','cpu_begin_before_qpc','cpu_begin_after_qpc','cpu_end_before_qpc','cpu_end_after_qpc','exit_qpc')]
                need(marker == sorted(marker), f'run {run}: CPU marker time order')
                cb, ce = x.get('cpu_begin_total_100ns',-1), x.get('cpu_end_total_100ns',-1)
                need(0 <= cb <= ce and x.get('cpu_delta_100ns') == ce-cb, f'run {run}: CPU marker delta')
            else:
                need(x.get('started') is False and x.get('blocks') == 0 and x.get('cpu_delta_100ns') is None, f'run {run}: unstarted CPU must be unavailable')
            if index == 0:
                worker = x
            need(positions.get(id(cr),-1) < positions.get(id(c),-1) < positions.get(id(start),-1), f'run {run}: setup record order')
        need(worker.get('blocks') == result.get('blocks') and worker.get('cpu_delta_100ns') == result.get('cpu_delta_100ns'), f'run {run}: worker/result totals')
        need(result.get('cpu_time_scope') == 'approximate_marker_interval', f'run {run}: CPU scope')
        if worker.get('cpu_delta_100ns') is None:
            need(result.get('cpu_window_utilization_percent') is None, f'run {run}: unavailable CPU percentage')
        elif wall > 0:
            same_number(result.get('cpu_window_utilization_percent'),100*worker['cpu_delta_100ns']/1e7/wall,f'run {run}: CPU percentage')
        blocks = result.get('blocks',0)
        if wall > 0:
            same_number(result.get('blocks_per_second'),blocks/wall,f'run {run}: throughput rate')
        ss = [r for r in rows if r.get('type') == 'sample']; samples_by_run[run] = ss
        need(len(ss) == result.get('sample_count') and len(ss) >= 1, f'run {run}: missing samples')
        if len(ss) == 1:
            warnings.append(f'run {run}: only one endpoint observation; temporal gaps/bursts unavailable')
        need([s.get('sample') for s in ss] == list(range(len(ss))), f'run {run}: sample sequence')
        previous, due = None, a
        for sample_index,s in enumerate(ss):
            before, after = s.get('read_before_qpc',0), s.get('read_after_qpc',0)
            need(s.get('due_qpc') == due and after >= before >= due, f'run {run}: sample due/timing')
            late = before-due
            same_number(s.get('lateness_ms'),late*1000/frequency,f'run {run}: sample lateness',tolerance=5.1e-7)
            skipped = late//period if period else 0
            need(s.get('skipped_slots') == skipped, f'run {run}: skipped-slot count')
            need(s.get('initial') is (sample_index == 0), f'run {run}: initial sample flag')
            need(0 <= s.get('blocks',-1) <= blocks, f'run {run}: sampled blocks')
            expected_delta = s.get('blocks',0) - (previous.get('blocks',0) if previous else 0)
            need(expected_delta >= 0 and s.get('delta_blocks') == expected_delta, f'run {run}: sample block delta')
            interval = (before-previous['read_before_qpc'])/frequency if previous else 0
            same_number(s.get('interval_seconds'),interval,f'run {run}: actual sample interval')
            cpu_delta = s.get('cpu_total_100ns',0) - previous.get('cpu_total_100ns',0) if previous else 0
            need(cpu_delta >= 0 and s.get('delta_cpu_100ns') == cpu_delta, f'run {run}: external CPU sample delta')
            if previous:
                need(before > previous['read_before_qpc'], f'run {run}: sample time regression')
            need(positions[id(start)] < positions[id(s)] < positions[id(result)], f'run {run}: sample record order')
            if before >= b:
                need(sample_index == len(ss)-1, f'run {run}: samples after endpoint')
            due = min(b,due+(skipped+1)*period); previous = s
        if ss:
            need(ss[-1]['read_before_qpc'] >= b, f'run {run}: missing endpoint')
        sequence = [created,controller,start,result,cleanup,outer]
        need(all(sequence) and [positions[id(r)] for r in sequence] == sorted(positions[id(r)] for r in sequence), f'run {run}: lifecycle order')
        missed = sum(s.get('skipped_slots',0) for s in ss)
        if missed:
            warnings.append(f'run {run}: {missed} missed nominal slots, actual observations retained')
    comparisons = [r for r in records if r.get('type') == 'comparison']
    expected_comparison_runs = [r for r in expected_ids if (r-1)%5 in (1,2,3)]
    need(sorted(c.get('run',-1) for c in comparisons) == expected_comparison_runs, 'comparison run coverage')
    for c in comparisons:
        run = c.get('run'); result, start = results.get(run,{}), starts.get(run,{})
        check_priority(c,start.get('class'),start.get('level'),f'run {run}: comparison priority')
        need(c.get('condition') == start.get('condition') and c.get('literal_cpu_share') is False, f'run {run}: comparison scope')
        before_id = run-((run-1)%5); after_id = before_id+4
        need(c.get('baseline_before_run') == before_id and c.get('baseline_after_run') == after_id, f'run {run}: baseline IDs')
        before, after = results.get(before_id,{}), results.get(after_id,{})
        need(positions.get(id(after),-1) < positions[id(c)], f'run {run}: comparison precedes closing baseline')
        br, ar = before.get('blocks_per_second',0), after.get('blocks_per_second',0)
        mid,bm,am = result.get('window_midpoint_qpc',0),before.get('window_midpoint_qpc',0),after.get('window_midpoint_qpc',0)
        need(br > 0 and ar > 0 and bm < mid < am, f'run {run}: baseline time/rates')
        if br <= 0 or ar <= 0 or am <= bm:
            continue
        alpha = (mid-bm)/(am-bm); reference = br+alpha*(ar-br)
        ratio = 100*result.get('blocks_per_second',0)/reference; drift = 100*(ar/br-1)
        for field,value in [('baseline_before_rate',br),('baseline_after_rate',ar),('interpolation_alpha',alpha),
                            ('reference_blocks_per_second',reference),('throughput_percent_of_normal_alone',ratio),('baseline_drift_percent',drift)]:
            same_number(c.get(field),value,f'run {run}: {field}')
        if abs(drift) > 10:
            warnings.append(f'run {run}: NORMAL-alone baseline drift {drift:.1f}%')
        longest = current = 0.0; zeros = bursts = 0; previous_zero = False
        for sample in samples_by_run.get(run,[])[1:]:
            zero = sample.get('delta_blocks') == 0
            if zero:
                current += sample.get('interval_seconds',0); zeros += 1; longest = max(longest,current)
            else:
                bursts += int(previous_zero); current = 0.0
            previous_zero = zero
        summaries.append(dict(run=run,nominal_base=c.get('nominal_base'),**{'class':c.get('class')},
            level=c.get('level'),condition=c.get('condition'),throughput_percent_of_normal_alone=ratio,
            cpu_window_utilization_percent=result.get('cpu_window_utilization_percent'),baseline_drift_percent=drift,
            temporal_resolution_available=len(samples_by_run.get(run,[]))>=2,
            zero_progress_observed_intervals=zeros if len(samples_by_run.get(run,[]))>=2 else None,
            longest_observed_zero_progress_seconds=longest if len(samples_by_run.get(run,[]))>=2 else None,
            observed_zero_to_positive_transitions=bursts if len(samples_by_run.get(run,[]))>=2 else None,
            missed_nominal_sample_slots=sum(s.get('skipped_slots',0) for s in samples_by_run.get(run,[]))))
    return dict(valid=not errors, errors=errors, warnings=warnings,
        interpretation='Throughput ratio is not CPU share. CPU time is approximate and separate. Zero-progress gaps/bursts are sampled observations, not scheduler events.', comparisons=summaries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('jsonl',type=Path); parser.add_argument('--out',type=Path)
    args = parser.parse_args()
    try:
        result = validate(load_jsonl(args.jsonl.read_text(encoding='utf-8-sig')))
    except (OSError,ValueError,KeyError,TypeError,ZeroDivisionError,IndexError,OverflowError) as exc:
        result = dict(valid=False,errors=[str(exc)],warnings=[],comparisons=[])
    text = json.dumps(result,indent=2,ensure_ascii=False,allow_nan=False)+'\n'
    if args.out:
        args.out.write_text(text,encoding='utf-8')
    print(text,end='')
    return 0 if result['valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
