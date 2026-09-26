#!/usr/bin/env python3
"""Export stored NATIVE x86 expectations to hb_diff_case_runner oracle fields.
No interpreter result is used as an expectation. No ARM instruction executes.
"""
from pathlib import Path
import argparse, gzip, json, hashlib, csv, collections
from corpus import SEED

def case_line(row, op):
    fields=[hex(SEED),op['bytes'],str(op['ir_count']),
            'sse-version=1','sse-id='+str(row['id']),
            'sse-mxcsr='+hex(row['mxcsr']),
            'рег-rax=0x'+row['rax'],'флаги=0x'+row['flags'],
            'sse-rbx-data=0x1000','sse-mem='+row['mem']]
    for j,x in enumerate(row['x']):
        fields += [f'sse-xmm{j}='+x[:32],f'sse-ymmhi{j}='+x[32:]]
    hw=row['hw']
    fields += ['expect-xmm0='+hw[0][:32],'expect-ymmhi0='+hw[0][32:],
               'expect-rax=0x'+hw[1],'expect-flags=0x'+hw[2],
               'expect-flags-mask=0x8d5',
               'expect-mxcsr-exceptions='+hex(int(hw[3],16)&63)]
    return ' '.join(fields)+'\n'

def main():
    a=argparse.ArgumentParser();a.add_argument('--results',required=True,type=Path)
    a.add_argument('--out',required=True,type=Path);args=a.parse_args()
    out=args.out;out.mkdir(parents=True,exist_ok=True)
    ops={x['id']:x for x in json.loads((args.results/'opcodes.json').read_text())}
    report=json.loads((args.results/'summary.json').read_text())
    ws=json.loads((args.results/'witnesses.json').read_text())
    witness_ids={x['case']['id'] for x in ws}
    smoke_ids=set();first=set();count=0;maxlen=0;digest=hashlib.sha256()
    matched_count=0;by_op=collections.Counter();by_mode=collections.Counter()
    smoke=out/'smoke.cases';regress=out/'regressions.cases'
    with gzip.open(args.results/'measurements.jsonl.gz','rt') as src, \
         gzip.open(out/'full.cases.gz','wt',compresslevel=6) as dst, \
         smoke.open('w') as ss, regress.open('w') as rs, \
         gzip.open(out/'matched-failures.csv.gz','wt') as fc:
        writer=csv.writer(fc);writer.writerow(['id','operation','form','bytes','mxcsr','category','xmm0_input_le','xmm1_input_le','xmm2_input_le','memory_le','hardware_xmm0_ymmhi0_le','hb_xmm0_ymmhi0_le','hardware_rax','hb_rax','hardware_status_flags','hb_status_flags','hardware_mxcsr','hb_guest_mxcsr','hb_host_mxcsr'])
        for text in src:
            r=json.loads(text);op=ops[r['op']];line=case_line(r,op)
            assert r['id']==count,(r['id'],count)
            dst.write(line);digest.update(line.encode());maxlen=max(maxlen,len(line.encode()))
            key=(r['op'],r['mxcsr'])
            if key not in first or r['id'] in witness_ids:
                ss.write(line);smoke_ids.add(r['id']);first.add(key)
            if r['id'] in witness_ids:rs.write(line)
            bad=[x.split(':',1)[1] for x in r['bad'] if x.startswith('matched:')]
            if bad:
                matched_count+=1
                writer.writerow([r['id'],op['name'],op['form'],op['bytes'],hex(r['mxcsr']),','.join(bad),r['x'][0][:32],r['x'][1][:32],r['x'][2][:32],r['mem'],r['hw'][0],r['matched'][0],r['hw'][1],r['matched'][1],r['hw'][2],r['matched'][2],r['hw'][3],r['matched'][4],r['matched'][3]])
            by_op[op['name']]+=1;by_mode[hex(r['mxcsr'])]+=1;count+=1
            if count%500000==0:print('exported',count,flush=True)
    assert count==report['cases']
    manifest={'schema':1,'source_commit':report['source_commit'],'seed':hex(SEED),
              'full_cases':count,'smoke_cases':len(smoke_ids),'regression_cases':len(witness_ids),
              'matched_failure_rows':matched_count,'longest_line_utf8_bytes':maxlen,
              'full_uncompressed_sha256':digest.hexdigest(),
              'expectation_source':'native x86 hardware only: measurements.hw',
              'by_operation':dict(by_op),'by_mxcsr':dict(by_mode),
              'record_vector_encoding':'hexadecimal bytes in increasing-address little-endian order',
              'command_count':'actual lifted IR instr_count; each case contains one architectural x86 instruction',
              'memory_address':'RBX=HB_DIFF_DATA_BASE+0x1000; same 32 bytes seeded in both engines',
              'mxcsr_exceptions':'separate diagnostic, NEVER counted as numerical mismatch'}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
