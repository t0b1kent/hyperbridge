#!/usr/bin/env python3
"""Static census by saved entry, retaining full-span and first-BB counts."""
import collections
import functools
import json
import pathlib
import sys
import time

OWN = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(OWN.parent / 'stand-diff-stage5-20261001'))
import fast_replay


def family(name):
    name = name.removeprefix('v')
    if name.startswith(('cvt', 'cvtt')):
        return 'conversion'
    if name.startswith(('add', 'sub', 'mul', 'div', 'sqrt', 'min', 'max')) and name.endswith(('ss', 'sd', 'ps', 'pd')):
        return 'sqrt' if name.startswith('sqrt') else 'arithmetic'
    if name.startswith(('comiss', 'comisd', 'ucomiss', 'ucomisd', 'cmpss', 'cmpsd', 'cmpps', 'cmppd')) or (name.startswith('cmp') and name.endswith(('ss', 'sd', 'ps', 'pd'))):
        return 'comparison'
    if name.startswith(('round', 'dpp', 'hadd', 'hsub', 'addsub')):
        return 'round' if name.startswith('round') else 'horizontal'
    if name.startswith(('rcp', 'rsqrt')):
        return 'approximation_no_status'
    return None


def main():
    replay = fast_replay.replay
    dataset = json.loads((OWN.parent / 'stand-diff-stage5-20261001/dataset.json').read_text())
    results = []
    for game in dataset['games']:
        start = time.monotonic()
        codes, _ = replay.selective_code_index(game['capture'], replay.entry_rips(game['states']))
        @functools.lru_cache(maxsize=200000)
        def decode(rip):
            full = set(); first = set(); boundary = False
            for ins in replay.sd.DIS.disasm(codes[rip][1], rip):
                kind = family(ins.mnemonic)
                if kind and kind != 'approximation_no_status':
                    full.add(ins.mnemonic)
                    if not boundary:
                        first.add(ins.mnemonic)
                if ins.group(replay.sd.cs.CS_GRP_JUMP) or ins.group(replay.sd.cs.CS_GRP_CALL) or ins.group(replay.sd.cs.CS_GRP_RET):
                    boundary = True
            return full, first
        counts = collections.Counter(); full = collections.Counter(); first = collections.Counter()
        for state in replay.states(game['states']):
            counts['states'] += 1
            if state['rip'] not in codes:
                counts['missing_code'] += 1
                continue
            a, b = decode(state['rip'])
            if a: counts['contains_status_instruction'] += 1
            if b: counts['first_bb_status_instruction'] += 1
            full.update(a); first.update(b)
        row = dict(game=game['game'], counts=dict(counts), full_span_states=dict(full.most_common()),
                   first_bb_states=dict(first.most_common()), seconds=time.monotonic()-start)
        results.append(row)
        print(json.dumps(row), flush=True)
    path = OWN / 'CENSUS-STATIC.json'
    path.write_text(json.dumps(dict(games=results), indent=2)+'\n')


if __name__ == '__main__':
    main()
