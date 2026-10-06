#!/usr/bin/env python3
"""MIT. Validate raw measured rows, then derive repeatability statistics."""
import csv, math, re, statistics, sys
from pathlib import Path
base=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parent
first=list(base.glob('RESULTS-*.tsv'))
first=[p for p in first if not p.stem.endswith('-run2')]
assert len(first)==1,first
p1=first[0]; p2=p1.with_name(p1.stem+'-run2.tsv')
sets=[]
for result in (p1,p2):
    rows=list(csv.DictReader(result.open(),delimiter='\t'))
    raw=list(csv.DictReader(result.with_name(result.name.replace('RESULTS-','RAW-')).open(),delimiter='\t'))
    run_log=result.with_name(result.name.replace('RESULTS-','RUN-')).with_suffix('.txt').read_text()
    chosen_cpu=re.search(r'affinity_cpu=(\d+)',run_log)[1]
    assert len(rows)==26, (result,len(rows))
    assert len(raw)==130, (result,len(raw))
    for row in rows:
        samples=[r for r in raw if r['loop']==row['loop']]
        assert len(samples)==5
        assert [int(r['sample']) for r in samples]==[1,2,3,4,5]
        assert all(r['iters']==row['iters'] for r in samples)
        assert all(r['cpu_before']==r['cpu_after']==chosen_cpu for r in samples)
        ns=[float(r['delta_ns'])/int(r['iters']) for r in samples]
        ticks=[int(r['delta_tsc_ticks'])/int(r['iters']) for r in samples]
        for key, expected in [('ns_median',statistics.median(ns)),('ns_min',min(ns)),('ns_max',max(ns)),('tsc_ticks_median',statistics.median(ticks)),('tsc_ticks_min',min(ticks))]:
            assert abs(float(row[key])-expected)<1e-8,(result,row['loop'],key)
        if row['core_cycles_method']=='unavailable':
            assert row['core_cycles_median']==row['core_cycles_min']=='NA'
        else:
            measured_cycles=[float(r['core_cycles_per_iter']) for r in samples]
            assert abs(float(row['core_cycles_median'])-statistics.median(measured_cycles))<1e-8
            assert abs(float(row['core_cycles_min'])-min(measured_cycles))<1e-8
        for r in samples:
            assert abs(float(r['ns_per_iter'])-float(r['delta_ns'])/int(r['iters']))<1e-8
            assert abs(float(r['tsc_ticks_per_iter'])-int(r['delta_tsc_ticks'])/int(r['iters']))<1e-8
    sets.append({r['loop']:r for r in rows})
    ratios=[float(r['thread_cpu_ns'])/float(r['delta_ns']) for r in raw]
    print(f'{result.name}: PASS 26 loops, 130 samples, exact counts, affinity, medians/minima, core-cycle availability')
    print(f'  thread_cpu_ns / wall_ns min={min(ratios):.6f} median={statistics.median(ratios):.6f} max={max(ratios):.6f}')
    print(f'  voluntary_switches={sum(int(r["voluntary_context_switches"]) for r in raw)} involuntary_switches={sum(int(r["involuntary_context_switches"]) for r in raw)} tsc_aux={sorted(set(r["tsc_aux"] for r in raw))}')
with (base/'REPEATABILITY.tsv').open('w') as out:
    out.write('loop\tns_median_run1\tns_median_run2\tmedian_change_pct\tns_min_run1\tns_min_run2\tmin_change_pct\n')
    differences=[]
    for name,a in sets[0].items():
        b=sets[1][name]
        delta=100*(float(b['ns_median'])/float(a['ns_median'])-1)
        md=100*(float(b['ns_min'])/float(a['ns_min'])-1)
        differences.append(abs(delta))
        out.write(f"{name}\t{a['ns_median']}\t{b['ns_median']}\t{delta:.6f}\t{a['ns_min']}\t{b['ns_min']}\t{md:.6f}\n")
    print(f'absolute median change: median={statistics.median(differences):.6f}% max={max(differences):.6f}%')
    print(f'loops with absolute median change >5%: {sum(x>5 for x in differences)} of 26')
disasm=(base/('DISASM-'+p1.stem.removeprefix('RESULTS-')+'.txt')).read_text()
source=(Path(__file__).resolve().parent/'xbench-linux.c').read_text()
names=re.findall(r'static void (b_\w+)\(uint64_t n\)',source)
assert len(names)==26
with (base/'DISASM-BENCHMARK-BODIES.txt').open('w') as out:
    for name in names:
        match=re.search(r'^([0-9a-f]+ <'+re.escape(name)+r'>:\n.*?)(?=\n\n|\Z)',disasm,re.M|re.S)
        assert match,name
        out.write(match[1]+'\n\n')
print('PASS: all 26 distinct b_* symbols present in archived executable disassembly')
