# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
#!/usr/bin/env python3
"""Measured Zen4 SIMD inputs against FEX. Product env, all supplied result bits."""
from __future__ import annotations
import argparse
import collections
import concurrent.futures
import dataclasses
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent / 'data'
TABLE = HERE / 'amd-simd'
CACHE = ROOT / 'build/hardware/cache/simd-code.json.gz'
active_timeout = subprocess
CODE = 0x7ffc0000000
DATA = 0x80000000000
END = DATA + 0x4000
BASE = DATA + 0x100
ARITH = 0x8d5


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def little(value):
    return b'' if value in ('-','UNKNOWN','') else bytes.fromhex(value)[::-1]


@dataclasses.dataclass
class Row:
    file: str
    line: int
    name: str
    width: int
    x1: str
    x2: str
    x3: str
    result: str
    extra: dict
    family: str
    form: str
    meta: dict
    raw: str

    @property
    def key(self):
        return f'{self.file}:{self.line}'

    @property
    def expected_trap(self):
        if 'TRAP(sig=' in self.raw:
            return 13
        return int(self.extra.get('TRAP','0'))

    @property
    def group(self):
        m = self.meta
        scenario=self.name.rsplit('.p',1)[0].split('.')[-1] if self.family in ('movement','gather') else ''
        return '|'.join(str(x) for x in (self.family,
            m.get('op',m.get('name',m.get('mnemonic'))),
            m.get('enc',m.get('encoding','')),m.get('width',m.get('destination_bits',self.width)),
            m.get('loc',m.get('memory','')),m.get('mode',''),scenario,
            'trap'+str(self.expected_trap) if self.expected_trap else 'success'))


def catalog():
    with gzip.open(CACHE,'rt') as f:
        return json.load(f)


def rows(table, forms, files=None):
    lookups = {}
    for key, m in forms.items():
        family = key.split(':')[0]
        if family == 'core':
            continue
        if family == 'movement':
            lookup = (family,m['name'],m['encoding'],m['imm'])
        elif family == 'gather':
            lookup = (family,m['name'],m['encoding_width']*8,m['scale'])
        elif family in ('crypto','strings'):
            lookup = (family,m['mnemonic'],m['destination_bits'],m['memory'],m['imm'])
        else:
            lookup = (family,m['mnemonic'])
        if lookup in lookups:
            raise ValueError('ambiguous instruction metadata: '+str(lookup))
        lookups[lookup] = key
    for path in sorted(table.glob('out-*.txt.gz')):
        if files and path.stem.removesuffix('.txt') not in files and path.name not in files:
            continue
        kind = path.name[4:].split('.')[0]
        family = 'core' if kind in ('arithmetic','logic','pack','permutation','shifts') else kind
        current = None
        with gzip.open(path,'rt') as f:
            for line, raw in enumerate(f,1):
                if raw.startswith('#'):
                    if raw.startswith('# form='):
                        current = f"core:{raw.split('form=')[1].split()[0]}"
                    continue
                if not raw.strip():
                    continue
                parts = raw.split()
                if len(parts)<7 or parts[5]!='->':
                    raise ValueError(f'{path.name}:{line}: malformed canonical prefix')
                name, width, x1, x2, x3, _, result = parts[:7]
                width = int(width)
                extra = dict(token.split('=',1) for token in parts[7:] if '=' in token and not token.startswith('TRAP('))
                immediate = re.search(r'\[([0-9a-fA-F]+)\]',name)
                imm = int(immediate[1],10 if family=='movement' else 16) if immediate else -1
                root = re.sub(r'\[[^]]+\]','',name)
                if family=='core':
                    key = current
                elif family=='movement':
                    split = re.split(r'\.(SSE|VEX128|VEX256)\.',root)
                    key = lookups[(family,split[0],split[1],imm)]
                elif family=='gather':
                    key = lookups[(family,root.split('.')[0],int(re.search(r'VEX(128|256)',root)[1]),int(immediate[1]))]
                    extra['MASK_AFTER'] = parts[7]
                elif family in ('strings','crypto'):
                    key = lookups[(family,root,width,int(extra.get('MEM','0')),imm)]
                else:
                    key = lookups[(family,root)]
                if key is None or key not in forms:
                    raise ValueError('missing exact target instruction: '+name)
                yield Row(path.name,line,name,width,x1,x2,x3,result,extra,family,key,forms[key],raw.rstrip())


def prepared(row):
    """Actual oracle source slots, without calculating any instruction result."""
    m,e = row.meta,row.extra
    vectors = {i:bytes(32) for i in range(16)}
    regs = {name:0 for name in ('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',*[f'r{i}' for i in range(8,16)])}
    regs['rsp'] = DATA + 0x1003000
    patches, watches = {}, []
    flags = 0x202
    primary = None
    expected_vectors, expected_regs = {}, {}
    expected_mem = {}
    def vec(index,value):
        data = little(value)
        if data:
            if len(data)!=32:
                raise ValueError(row.key+': vector input must contain all 256 bits')
            vectors[index] = data
    def patch(address,data):
        if not data:
            return
        if not DATA <= address <= END-len(data):
            raise ValueError(row.key+': patch outside owned arena')
        for off,b in enumerate(data):
            if address+off in patches and patches[address+off]!=b:
                raise ValueError(row.key+': inconsistent overlapping source bytes')
            patches[address+off]=b
    if row.family=='core':
        flags=0xad7
        pointer=BASE+int(m['loc']=='mem-unaligned')
        regs['rdx']=pointer
        if m['mode']=='flags':
            flags=int(row.x1,16)
            vec(4,row.x2);vec(1,row.x3)
            source=row.x3
            primary=('flags',None)
        else:
            vec(4,row.x1)
            if m['enc']=='SSE' and m['mode']=='shiftcount':
                vec(2,row.x2);source=row.x2
            else:
                vec(1,row.x2);vec(2,row.x3)
                source=row.x3 if m['memslot']==2 else row.x2
            primary=('vector',4)
            expected_vectors[4]=little(row.result)
        if m['loc']!='reg':
            patch(pointer,little(source)[:m['memsize']])
        if 'mask' in e:vec(0,e['mask'])
    elif row.family=='movement':
        vec(0,e['YMM0_BEFORE']);vec(1,e['SOURCE_YMM1']);vec(2,e['INPUT_YMM2'])
        regs['rax']=int(e['GPR_BEFORE_FULL64'],16)
        accessible=int(e['ACCESSIBLE_BYTES'])
        case=row.name.rsplit('.p',1)[0].split('.')[-1]
        guarded='guard' in case or case=='alloff_guard'
        pointer=END-accessible if guarded else BASE+int(case=='unaligned')
        regs['rsi']=regs['rdi']=pointer
        patch(pointer,little(e['MEM_BEFORE']))
        if accessible:
            watches.append((pointer,accessible));expected_mem[pointer]=little(e['MEM_AFTER'])
        expected_vectors.update({0:little(e['YMM0_AFTER']),1:vectors[1],2:little(e['MASK_AFTER'])})
        expected_regs['rax']=int(e['GPR_AFTER_FULL64'],16)
        primary=({'YMM':'vector','GPR':'register','MEM':'memory'}[e['DEST_KIND']],0 if e['DEST_KIND']=='YMM' else 'rax' if e['DEST_KIND']=='GPR' else pointer)
    elif row.family=='gather':
        vec(0,row.x1);vec(1,row.x2);vec(2,row.x3)
        scenario=row.name.rsplit('.p',1)[0].split('.')[-1]
        base=END-2048+int(scenario=='unaligned')
        regs['rsi']=base
        indexes=little(row.x2);data=little(e['MEM_INPUT']);valid=int(e['VALID_LANES'],16)
        for i in range(m['lanes']):
            address=base+int.from_bytes(indexes[i*m['index_bytes']:(i+1)*m['index_bytes']],'little',signed=True)*m['scale']
            if valid>>i&1:
                patch(address,data[i*m['element_bytes']:(i+1)*m['element_bytes']])
        expected_vectors.update({0:little(row.result),1:vectors[1],2:little(e['MASK_AFTER'])})
        primary=('vector',0)
    elif row.family=='strings':
        vec(0,e['YMM0_BEFORE'] if row.width==32 else row.x1)
        vec(1,row.x2)
        if e['MEM']=='0':vec(2,row.x3)
        regs.update(rax=int(e['LA'])&0xffffffff,rdx=int(e['LB'])&0xffffffff,rcx=int(e['ECX0'],16))
        pointer=BASE+int(e['MEM']=='2');regs['r9']=pointer
        if e['MEM']!='0':patch(pointer,little(row.x3)[:16])
        expected_vectors.update({0:little(e['YMM0_AFTER'] if row.width==32 else row.result),1:vectors[1],2:vectors[2]})
        if row.width==32:
            expected_regs['rcx']=int(row.result,16);primary=('register','rcx')
        else:
            primary=('vector',0)
    elif row.family=='crypto':
        pointer=BASE+int(e.get('MEM','0')=='2');regs['r9']=pointer
        if m['kind']<14:
            vec(1,row.x1);vec(2,e['SOURCE_YMM2_BEFORE']);vec(0,e['YMM0_BEFORE'])
            if e.get('MEM','0')!='0':
                memory_source=row.x3 if m['kind'] not in (4,5) and m['mnemonic'].startswith('v') else row.x2
                patch(pointer,little(memory_source)[:m['operand_bits']//8])
            expected_vectors.update({1:little(row.result),0:little(e['YMM0_AFTER']),2:little(e['SOURCE_YMM2_AFTER'])})
            primary=('vector',1)
        else:
            regs['rax']=int(e['GPR64_BEFORE'],16)
            if m['kind']==14:
                regs['rdx']=int(row.x2,16)
                if e.get('MEM','0')!='0':patch(pointer,little(row.x2))
                primary=('register','rax')
            elif m['destination']=='memory':
                patch(pointer,little(row.x1));primary=('memory',pointer)
            else:
                patch(pointer,little(row.x2));primary=('register','rax')
            expected_regs['rax']=int(e['GPR64_AFTER'],16)
            if e.get('MEM_AFTER','-')!='-':
                memory=little(e['MEM_AFTER']);watches.append((pointer,len(memory)));expected_mem[pointer]=memory
    else:
        index=int(e['reg'].removeprefix('ymm'))
        vec(index,row.x1);expected_vectors[index]=little(row.result);primary=('vector',index)
    if row.family=='core' and m['mode']=='flags':
        expected_flags=int(row.result,16)
    elif row.family=='strings':expected_flags=int(e['FLAGS'],16)
    else:expected_flags=None
    # Preserve every supplied source/implicit register as observed by hardware.
    for index in range(16):
        expected_vectors.setdefault(index,vectors[index])
    for name,value in regs.items():expected_regs.setdefault(name,value)
    runs=[]
    for address in sorted(patches):
        if not runs or address!=runs[-1][0]+len(runs[-1][1]) or len(runs[-1][1])==64:
            runs.append((address,bytearray()))
        runs[-1][1].append(patches[address])
    if len(runs)>8:
        raise ValueError(row.key+': patches exceed stand cap')
    return dict(vectors=vectors,regs=regs,flags=flags,patches=runs,watches=watches,
        expected_vectors=expected_vectors,expected_regs=expected_regs,expected_mem=expected_mem,
        expected_flags=expected_flags,primary=primary)


def case(row,identity):
    p=prepared(row)
    items=dict(id=identity,seed=0,code=row.meta['code'],rip=hex(CODE),rflags=hex(p['flags']),mxcsr='0x1f80')
    items.update({k:hex(v) for k,v in p['regs'].items()})
    for index,value in p['vectors'].items():
        items['x'+str(index)]=value[:16].hex();items['y'+str(index)]=value[16:].hex()
    return ' '.join(f'{k}={v}' for k,v in items.items())+''.join(f' mem={hex(a)}:{b.hex()}' for a,b in p['patches'])+''.join(f' watch={hex(a)}:{n}' for a,n in p['watches'])+'\n'


def compare(row,state):
    p=prepared(row)
    bad=set();got={};deltas={}
    status=state.get('status','NO_OUTPUT')
    sfd=state.get('sfd',{})
    trap=sfd.get('trap',0) if sfd.get('gen') else 0
    host=state.get('host',{})
    if status=='jit_fault' and host.get('where')==0:
        address=int(host.get('addr','0'),16)
        guest_rip=int(host.get('guest_rip','0'),16)
        if (END<=address<END+0x4000 or DATA-0x4000<=address<DATA) and guest_rip==CODE:
            trap=14
    got['trap']=trap
    if trap!=row.expected_trap:bad.add('fault')
    if not row.expected_trap and status not in ('exit','EXIT_SPAN'):
        bad.add('execution')
    if row.expected_trap and not trap:
        bad.add('execution')
    if status not in ('exit','EXIT_SPAN','jit_fault','guest_sigill','guest_sigtrap') or not state.get('state_valid'):
        bad.add('execution')
    if state.get('state_valid'):
        expected_rip=CODE if row.expected_trap else CODE+len(row.meta['code'])//2
        actual_rip=int(state['rip'],16)
        if actual_rip!=expected_rip:
            bad.add('rip');got['rip']=actual_rip;deltas['rip']=actual_rip^expected_rip
        upper=state.get('ymm_hi',state.get('ymmh',[]))
        if len(state.get('xmm',[]))!=16 or len(upper)!=16:
            raise ValueError('runner omitted YMM state')
        for index,expected in p['expected_vectors'].items():
            actual=bytes.fromhex(state['xmm'][index]+upper[index])
            if actual[:16]!=expected[:16]:bad.add('result')
            if actual[16:]!=expected[16:]:bad.add('upper')
            if actual!=expected:
                key='ymm'+str(index);got[key]=actual.hex()
                deltas[key]=(int.from_bytes(actual,'little')^int.from_bytes(expected,'little'))
        for name,expected in p['expected_regs'].items():
            actual=int(state['regs'][name],16)
            if actual!=expected:
                bad.add('result');got[name]=actual;deltas[name]=actual^expected
        memories={int(a,16):bytes.fromhex(b) for a,b in state.get('written_memory',[])}
        for address,expected in p['expected_mem'].items():
            if memories.get(address)!=expected:
                key='mem'+hex(address);actual=memories.get(address,b'')
                bad.add('result');got[key]=actual.hex()
                if len(actual)==len(expected):deltas[key]=int.from_bytes(actual,'little')^int.from_bytes(expected,'little')
        if p['expected_flags'] is not None:
            actual=int(state['rflags'],16)&0xffff
            if actual!=p['expected_flags']:
                bad.add('flags');got['flags']=actual;deltas['flags']=actual^p['expected_flags']
    if 'execution' in bad:
        got['status']=status
    return dict(classes=sorted(bad),got=got,deltas=deltas,primary_unavailable=row.result=='UNKNOWN')


def classify(current,previous):
    if not current['classes']:
        return 'FIXED' if previous else 'AUXILIARY_EQUAL' if current['primary_unavailable'] else 'EQUAL'
    if previous and current==previous:
        return 'KNOWN'
    if previous and set(current['classes'])<=set(previous['classes']):
        # A partial repair may remove only bits that were manually accepted.
        # Fault/status or missing-memory changes require their own triage.
        remaining=current.get('deltas',{})
        old=previous.get('deltas',{})
        if all(key in old and not (value&~old[key]) for key,value in remaining.items()):
            if all(key in remaining or previous['got'].get(key)==value
                or (key=='trap' and 'fault' not in current['classes'])
                for key,value in current['got'].items()):
                return 'PARTIAL_FIXED'
    return 'NEW'


def batches(runner,selected,env,raw,native):
    remaining=list(selected)
    while remaining:
        payload=''.join(case(row,i) for i,row in enumerate(remaining))
        try:
            proc=active_timeout.run(['nice','-n','20',str(runner)],input=payload,text=True,capture_output=True,env=env,timeout=55)
        except subprocess.TimeoutExpired as error:
            raw.write(error.stdout.decode('utf-8') if isinstance(error.stdout, bytes) else (error.stdout or ''))
            native.write(error.stderr.decode('utf-8') if isinstance(error.stderr, bytes) else (error.stderr or ''))
            raise
        raw.write(proc.stdout);native.write(proc.stderr)
        output=[json.loads(line) for line in proc.stdout.splitlines() if line.startswith('{')]
        if not output:
            raise RuntimeError(f'native batch returned no measured state, rc={proc.returncode}')
        if len(output)>len(remaining):raise ValueError('duplicate native state')
        for index,state in enumerate(output):
            if state.get('id')!=index:raise ValueError('native identity mismatch')
            yield remaining[index],state
        remaining=remaining[len(output):]


def known(registry,table):
    if not registry.exists():raise ValueError('missing manually accepted registry')
    spec=json.loads(registry.read_text())
    if spec.get('state')!='MANUALLY_ACCEPTED':
        raise ValueError('SIMD registry requires manual acceptance, not a proposal')
    if spec['instruction_map_sha256'] != hashlib.sha256(json.dumps({k:v['code'] for k,v in catalog().items()}, sort_keys=True, separators=(',',':')).encode()).hexdigest():
        raise ValueError('manually accepted SIMD instruction bytes drift')
    if spec['table_sha256']!={p.name:sha(p) for p in table.glob('out-*.txt.gz')}:
        raise ValueError('manually accepted SIMD table drift')
    baseline=HERE/spec['baseline']
    if sha(baseline)!=spec['baseline_sha256']:raise ValueError('manual SIMD baseline drift')
    with gzip.open(baseline,'rt') as f:
        return {r['key']:r['comparison'] for r in map(json.loads,f)}


def summary(result,out):
    c=result['counts']
    print(json.dumps(dict(gate='HB_HWSIMD',status=result['status'],mode=result['mode'],
        checked=c.get('checked',0),result_bad=c.get('result',0),upper_bad=c.get('upper',0),
        fault_bad=c.get('fault',0),flags_bad=c.get('flags',0),known=c.get('KNOWN',0),
        rip_bad=c.get('rip',0),
        fixed=c.get('FIXED',0),new=c.get('NEW',0),primary_unavailable=c.get('primary_unavailable',0),
        equal=c.get('EQUAL',0),auxiliary_equal=c.get('AUXILIARY_EQUAL',0),partial_fixed=c.get('PARTIAL_FIXED',0),
        seconds=result['seconds'],canonical_sha256=result['canonical_sha256'],report=str(out.resolve()))))
