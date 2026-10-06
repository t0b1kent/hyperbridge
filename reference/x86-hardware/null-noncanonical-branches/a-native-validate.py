#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 OpenAI
# Validate recorded observations; never replace or infer missing result rows.
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
forms = ('call-reg', 'call-mem', 'jmp-reg', 'jmp-mem', 'ret')
targets = {64: (0, 0x10, 0xfff, 0x1000000000, 0x800000000000, 0x8000000000000000),
           32: (0, 0x10, 0xfff, 0x60000000)}

def parse(line):
    d = dict(word.split('=', 1) for word in line.strip().split()[1:])
    return {k: (v if k == 'form' else int(v, 10 if k == 'bits' else 16)) for k, v in d.items()}

def context(path):
    lines = path.read_text().splitlines()
    return {k: int(v, 16) for k, v in (line.split('=', 1) for line in lines[2:])}

raw = (here / 'a-native.tsv').read_bytes()
repeat = (here / 'a-native-repeat.tsv').read_bytes()
assert raw == repeat, 'normalized repeats differ'
rows = [parse(line) for line in raw.decode().splitlines()]
assert len(rows) == 50
assert len({(r['bits'], r['form'], r['target']) for r in rows}) == 50
summary = {'rows': len(rows), 'repeat_byte_identical': True,
           'table_sha256': hashlib.sha256(raw).hexdigest(), 'runs': []}
noncanon = []
for run in (1, 2):
    base = here / f'raw/a/run{run}'
    assert (base / 'exit.txt').read_text() == 'exit=0\n'
    assert (base / 'stderr.txt').read_text() == ''
    assert (base / 'table.tsv').read_bytes() == raw
    count_pf = count_gp = count_alt = count_maps = 0
    for r in rows:
        bits, form, target = r['bits'], r['form'], r['target']
        assert form in forms and target in targets[bits]
        stem = f'{bits}-{form}-{target:016x}'
        c = context(base / (stem + '.context'))
        assert c['on_altstack'] == c['top_readable'] == 1
        assert c['cs'] == (0x33 if bits == 64 else 0x23)
        assert c['ss'] == 0x2b
        count_alt += 1
        text = (base / (stem + '.maps')).read_text()
        lines = text.splitlines()
        assert lines[-1] == f'PROOF target={target:016x} mapped=0 source=/proc/self/maps sampled=immediately-before-branch'
        for line in lines[:-1]:
            lo, hi = (int(x, 16) for x in line.split()[0].split('-'))
            assert not lo <= target < hi
        count_maps += 1
        assert c['signo'] == r['signo'] == 0xb
        assert c['addr'] == r['si_addr']
        assert c['ip'] == r['ip']
        assert c['trap'] == r['trapno']
        mask = (1 << bits) - 1
        assert (c['sp'] - c['entry_sp']) & mask == r['sp']
        assert (c['top'] - c['form_address']) & mask == r['top']
        assert (c['expected'] - c['form_address']) & mask == r['expected_top']
        if r['trapno'] == 0xe:
            count_pf += 1
            assert r['err'] == 0x14 and r['si_code'] == 1
            assert r['si_addr'] == r['ip'] == target
            assert c['cr2'] == target
            assert c['top_eq_expected'] == c['ip_eq_target'] == 1
            assert c['ip_eq_branch'] == 0
            delta = -48 if bits == 64 and form.startswith('call') else -4 if bits == 32 and form.startswith('call') else 0
            assert r['sp'] == delta & mask
        elif r['trapno'] == 0xd:
            count_gp += 1
            assert bits == 64 and target in targets[64][-2:]
            assert r['err'] == 0 and r['si_code'] == 0x80 and r['si_addr'] == 0
            assert c['ip_eq_branch'] == 1 and c['ip_eq_target'] == 0
            delta = -40 if form.startswith('call') else -8 if form == 'ret' else 0
            assert r['sp'] == delta & mask
            assert c['top_eq_expected'] == int(form.startswith('jmp'))
        else:
            raise AssertionError(f'unexpected trap: {r}')
        if run == 1 and bits == 64 and target in targets[64][-2:]:
            # Additional explicit lines requested by TASK; values copied from execution.
            noncanon.append(f"A_NONCANON bits=64 form={form} target={target:016x} trap={'#GP' if r['trapno'] == 0xd else '#PF'} trapno={r['trapno']:02x} si_addr={r['si_addr']:016x} ip={r['ip']:016x}")
    summary['runs'].append({'run': run, 'page_faults': count_pf, 'general_protection_faults': count_gp,
                            'confirmed_altstack': count_alt, 'confirmed_unmapped_in_child_maps': count_maps,
                            'captured_64bit_cs33': 30, 'captured_32bit_cs23': 20})
(here / 'a-native-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
(here / 'a-native-noncanonical.tsv').write_text('\n'.join(noncanon) + '\n')
print(json.dumps(summary, indent=2))
