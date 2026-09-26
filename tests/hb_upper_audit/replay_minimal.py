#!/usr/bin/env python3
"""Replay SAVED emitted A64, not a fresh emission and not ARM hardware.
Only successful ordinary RAM store_u128 is modeled; fault/MMIO paths are outside scope.
U02 is an artificial IR contract, with no claim of a current guest-byte trigger.
"""
import argparse,json,re,struct
from pathlib import Path
from a64_eval import CPU,Memory

def machine_code(path):
    return b''.join(struct.pack('<I',int(m.group(1),16)) for m in re.finditer(r'^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s',path.read_text(),re.M))

def execute(code,inp,mem,layout):
    CTX=0x100000000;SRC=0x200000000;DST=SRC+128
    ctx=bytearray(layout['size'])
    fields=['regs.x64.xmm','ymm_hi','zmm_hi','xmm_ext','ymm_hi_ext','zmm_hi_ext']
    for r in range(32):
        f=fields[:3] if r<16 else fields[3:];i=r%16
        for key,q,n in zip(f,(0,16,32),(16,16,32)):
            off=layout[key]+i*n;ctx[off:off+n]=inp[r*64+q:r*64+q+n]
    struct.pack_into('<Q',ctx,layout['regs.x64.rbx'],SRC);struct.pack_into('<Q',ctx,layout['regs.x64.rdi'],DST)
    memory=Memory();memory.map(CTX,ctx);memory.map(SRC,mem)
    regs=[0]*32;regs[19]=CTX;calls=[]
    def helper(cpu,addr):
        # This saved stream only contains this one ordinary-RAM helper.
        if addr!=0x452660 or cpu.r[0]!=CTX or cpu.r[1]!=DST:raise RuntimeError('unexpected helper boundary')
        memory.write(DST,struct.pack('<QQ',cpu.r[2],cpu.r[3]));calls.append(hex(addr))
    cpu=CPU(regs,memory,helper);cpu.run(code)
    actual=bytearray(inp)
    for r in range(32):
        f=fields[:3] if r<16 else fields[3:];i=r%16
        for key,q,n in zip(f,(0,16,32),(16,16,32)):
            actual[r*64+q:r*64+q+n]=memory.read(CTX+layout[key]+i*n,n)
    return bytes(actual),memory.read(SRC,256),calls

def changed(a,b):
    return [f'zmm{r}.q{q}' for r in range(32) for q in range(8) if a[r*64+q*8:r*64+q*8+8]!=b[r*64+q*8:r*64+q*8+8]]
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2]);a=ap.parse_args();root=a.root
    layout=json.loads((root/'evidence/current/layout.json').read_text())
    records={}
    for l in (root/'evidence/current/native-measurements.jsonl').open():
        j=json.loads(l)
        if j['seed']=='0x1' and j['name'] in ('U01-pair-vex-vex-xmm0','U01-evex128-pair','M01-evex-zero-xmm0-k5'):
            records[j['name']]=j
    report=[]
    j=records['U01-pair-vex-vex-xmm0'];inp=bytes.fromhex(j['input_zmm']);mem=bytes.fromhex(j['input_mem']);gold=bytes.fromhex(j['hardware_zmm']);gm=bytes.fromhex(j['hardware_mem'])
    for version in ('before','after'):
        code=machine_code(root/f'evidence/minimal/U01-vex-{version}.txt');out,om,calls=execute(code,inp,mem,layout)
        row=dict(case='U01',version=version,guest_bytes=j['bytes'],mismatch_qwords=changed(out,gold),memory_matches=om==gm,modeled_helper_calls=calls,expected_xmm0=gold[:16].hex(),actual_xmm0=out[:16].hex(),expected_upper=gold[16:64].hex(),actual_upper=out[16:64].hex())
        assert (len(row['mismatch_qwords'])==6 if version=='before' else not row['mismatch_qwords']) and row['memory_matches'];report.append(row)
    # Exact IR specification: LOAD32 zero_upper=1, zero_ymm_upper=1.
    contract=bytearray(inp);contract[:64]=mem[:4]+bytes(60)
    for version in ('before','after'):
        code=machine_code(root/f'evidence/minimal/U02-ir-{version}.txt');out,om,calls=execute(code,inp,mem,layout)
        row=dict(case='U02',version=version,guest_bytes=None,ir='HB_IR_LOAD XMM0 <- [RBX]:32; zero_upper=1; zero_ymm_upper=1',mismatch_qwords=changed(out,contract),memory_matches=om==mem,expected_xmm0=contract[:16].hex(),actual_xmm0=out[:16].hex(),expected_upper=contract[16:64].hex(),actual_upper=out[16:64].hex())
        assert (len(row['mismatch_qwords'])==6 if version=='before' else not row['mismatch_qwords']) and row['memory_matches'];report.append(row)
    j=records['M01-evex-zero-xmm0-k5'];inp=bytes.fromhex(j['input_zmm']);mem=bytes.fromhex(j['input_mem']);gold=bytes.fromhex(j['hardware_zmm'])
    code=machine_code(root/'evidence/minimal/M01-mask-before.txt');out,om,calls=execute(code,inp,mem,layout)
    mismatches=changed(out,gold)
    assert mismatches and all(int(v.split('.q')[1])<2 for v in mismatches)
    report.append(dict(case='M01',guest_bytes=j['bytes'],mask=5,mismatch_qwords=mismatches,expected_xmm0=gold[:16].hex(),actual_xmm0=out[:16].hex(),upper_matches=gold[16:64]==out[16:64],status='separate low128 mask bug, not fixed by upper patch'))
    # Ensure dropping only the final upper clear remains observable, and legacy must retain upper.
    code=machine_code(root/'evidence/minimal/U01-vex-after.txt')
    words=list(struct.unpack('<'+'I'*(len(code)//4),code));assert words.count(0xf901ce7f)==1
    words.remove(0xf901ce7f);inp=bytes.fromhex(records['U01-pair-vex-vex-xmm0']['input_zmm']);mem=bytes.fromhex(records['U01-pair-vex-vex-xmm0']['input_mem']);gold=bytes.fromhex(records['U01-pair-vex-vex-xmm0']['hardware_zmm'])
    out,_,_=execute(struct.pack('<'+'I'*len(words),*words),inp,mem,layout)
    assert changed(out,gold)==['zmm0.q7'];report.append(dict(case='negative-delete-final-clear',mismatch_qwords=changed(out,gold)))
    dest=root/'evidence/current/minimal-replay.json';dest.write_text(json.dumps(dict(scope=__doc__,results=report),indent=2)+'\n');print(dest)
    for r in report:print(r['case'],r.get('version',''),r['mismatch_qwords'])
if __name__=='__main__':main()
