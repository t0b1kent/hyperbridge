#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare measured AMD and Intel CSVs without modifying either oracle.
Usage: python3 compare_cpu.py amd/raw.csv.gz intel/raw.csv.gz > cpu-diff.csv
First input must be AMD and second Intel; verify hardware.txt yourself.
"""
import csv,gzip,sys
KEY=['group','op','cw','case','a_name','a_ext80','b_name','b_ext80']
VALUE=['st0','st1','st2','st3','st4','st5','st6','st7','memory_bits']
STATE=['pre_sw','post_sw','post_ftw','memory_sw']
def read(path):
    f=gzip.open(path,'rt') if path.endswith('.gz') else open(path)
    with f:
        out={}
        for r in csv.DictReader(f):
            key=tuple(r[k] for k in KEY)
            if key in out:raise ValueError('duplicate semantic key: '+repr(key))
            out[key]=r
        return out
if len(sys.argv)!=3:raise SystemExit(__doc__)
a,b=map(read,sys.argv[1:]);w=csv.writer(sys.stdout);w.writerow(KEY+['amd_row','intel_row']+['amd_'+k for k in VALUE+STATE]+['intel_'+k for k in VALUE+STATE]+['value_bits_diff','raw_state_diff','intel_amd_diff'])
for key in sorted(a.keys()|b.keys()):
    x,y=a.get(key),b.get(key)
    if x is None or y is None:v=s=d='NOT_MEASURED'
    else:
        v=int(any(x[k]!=y[k] for k in VALUE));s=int(any(x[k]!=y[k] for k in STATE));d=int(bool(v or s))
    w.writerow(list(key)+[x['row'] if x else 'NOT_MEASURED',y['row'] if y else 'NOT_MEASURED']+[x[k] if x else 'NOT_MEASURED' for k in VALUE+STATE]+[y[k] if y else 'NOT_MEASURED' for k in VALUE+STATE]+[v,s,d])
