#!/usr/bin/env python3
"""MIT. Verify all original b_* function definitions are preserved verbatim."""
import hashlib, re
from pathlib import Path
base=Path(__file__).resolve().parent
original=(base/'../input/xbench.c').read_text()
ported=(base/'xbench-linux.c').read_text()
pat=r'static void (b_\w+)\(uint64_t n\)\s*\{.*?^\}'
# b_empty is intentionally one line in the supplied source.
functions=re.findall(pat,original,re.M|re.S)
# Extract using balanced braces so both one-line and multiline functions work.
def extract(text):
    result={}
    for m in re.finditer(r'static void (b_\w+)\(uint64_t n\)\s*\{',text):
        depth=1; p=m.end()
        while depth:
            depth += (text[p]=='{')-(text[p]=='}'); p+=1
        result[m[1]]=text[m.start():p]
    return result
src,dst=extract(original),extract(ported)
assert len(src)==21, len(src)
print('original_function\tsha256_of_verbatim_function\tstatus')
for name, body in src.items():
    assert dst.get(name)==body, name
    print(name+'\t'+hashlib.sha256(body.encode()).hexdigest()+'\tUNCHANGED')
assert len(dst)==26, len(dst)
print('# PASS: 21 original function definitions unchanged; exactly 5 additional b_* functions')
