#!/usr/bin/env python3
"""Native x86-64 flags oracle. Inputs/opcodes/absolute outputs, not a CPU model.
Architecturally undefined flags and their dependent consumer outputs are recorded
but excluded from correctness claims. HBFL0001 contains every raw observation.
"""
import argparse, ctypes as C, gzip, hashlib, json, mmap, os, platform, random, struct, subprocess
from pathlib import Path
H=Path(__file__).resolve().parent
M=(1<<64)-1
CF,PF,AF,ZF,SF,OF=1,4,16,64,128,2048
STATUS=CF|PF|AF|ZF|SF|OF
CC=['o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g']
NEEDS=[OF,OF,CF,CF,ZF,ZF,CF|ZF,CF|ZF,SF,SF,PF,PF,SF|OF,SF|OF,SF|OF|ZF,SF|OF|ZF]
RN={8:'al',16:'ax',32:'eax',64:'rax'};RS={8:'dl',16:'dx',32:'edx',64:'rdx'}

def producers():
    fs=[]
    def add(op,w,asm,chain=''):
        fs.append(dict(op=op,w=w,asm=asm,chain=chain,name=f'{op}-{w}'+('-'+chain if chain else '')))
    for w in (8,16,32,64):
        for op in ('add','sub','cmp','and','or','xor','test','adc','sbb'):
            add(op,w,f'{op} {RN[w]},{RS[w]}')
        for op in ('inc','dec','neg'):
            add(op,w,f'{op} {RN[w]}')
        for op in ('shl','shr','sar','rol','ror','rcl','rcr'):
            add(op,w,f'{op} {RN[w]},cl')
        for op in ('mul','imul'):add(op,w,f'{op} {RS[w]}')
        if w>=16:
            add('imul2',w,f'imul {RN[w]},{RS[w]}')
            for imm in (-128,-1,0,1,127):
                add('imul3_'+str(imm),w,f'imul {RN[w]},{RS[w]},{imm}')
            for op in ('bt','bts','btr','btc'):add(op,w,f'{op} {RN[w]},{RS[w]}')
            for op in ('bsf','bsr','tzcnt','lzcnt','popcnt'):add(op,w,f'{op} {RN[w]},{RS[w]}')
        if w>=32:
            add('andn',w,f'andn {RN[w]},{RN[w]},{RS[w]}')
            for op in ('blsi','blsmsk','blsr'):add(op,w,f'{op} {RN[w]},{RS[w]}')
            add('bzhi',w,f'bzhi {RN[w]},{RN[w]},{RS[w]}')
    # All flags producers followed by INC/DEC; consume carry in both polarities.
    base=list(fs)
    for f in base:
        for chain in ('inc','dec'):
            add(f['op'],f['w'],f['asm']+f'\n{chain} {RN[f["w"]]}',chain)
    return fs

def consumer_forms(f):
    # Reference also captures the standalone producer, important for flags that consumers do not use.
    out=[dict(kind='none',cc=-1,cw=0,asm='')]
    ccs=(2,3) if f['chain'] else range(16)
    for i in ccs:
        cc=CC[i]
        out.append(dict(kind='jcc',cc=i,cw=32,asm=f'mov r8d,0\nj{cc} 1f\njmp 2f\n1: mov r8d,1\n2:'))
        out.append(dict(kind='setcc',cc=i,cw=8,asm=f'set{cc} r8b'))
        for w,r,src,sz in [(16,'r8w','r9w','word'),(32,'r8d','r9d','dword'),(64,'r8','r9','qword')]:
            out.append(dict(kind='cmov-rr',cc=i,cw=w,asm=f'cmov{cc} {r},{src}'))
            out.append(dict(kind='cmov-rm',cc=i,cw=w,asm=f'cmov{cc} {r},{sz} ptr [rdi]'))
    return out

def vals(w):
    m=(1<<w)-1;s=1<<(w-1)
    return list(dict.fromkeys([0,1,2,3,m,m-1,s,s-1,s+1,(0x5555555555555555&m),(0xaaaaaaaaaaaaaaaa&m)]))

def inputs(f,rng):
    w=f['w'];vs=vals(w);op=f['op'];out=[]
    shift=op in ('shl','shr','sar','rol','ror','rcl','rcr')
    if shift:
        counts=list(dict.fromkeys([0,1,2,w-1,w,w+1,31,32,33,63,64,65,127,255]))
        out=[(x,0x1122334455667788,c,fl) for x in vs for c in counts for fl in (0,STATUS)]
    elif op in ('bt','bts','btr','btc','bzhi'):
        counts=list(dict.fromkeys([0,1,w-1,w,w+1,255,256,M]))
        out=[(x,c,3,fl) for x in vs for c in counts for fl in (0,STATUS)]
    else:
        # Full boundary pair product: both positions, not just zipped boundaries.
        out=[(x,y,3,fl) for x in vs for y in vs for fl in (0,STATUS)]
    for _ in range(16):out.append((rng.getrandbits(64),rng.getrandbits(64),rng.randrange(256),rng.getrandbits(16)&STATUS))
    # Upper halves nonzero for narrow writes. Values up to w=64 unchanged.
    result=[]
    wm=(1<<w)-1
    for x,y,c,fl in out:
        a=(x&wm)|((0xdadabeefdead0000&~wm) if w<64 else 0)
        b=(y&wm)|((0xcafebabefeed0000&~wm) if w<64 else 0)
        # BT register indices only use low width; BZHI only low8, preserved above.
        result.append([a,b,c,0xcafe123498765432,0x12345678abcdef09,0x6789abcd00112233,fl|2])
    return result

def defined(f,ini):
    op=f['op'];w=f['w'];c=ini[2]&(63 if w==64 else 31)
    mask=STATUS
    if op in ('and','or','xor','test'):mask=STATUS&~AF
    elif op in ('shl','shr','sar'):
        if c:mask=(SF|ZF|PF)|(CF if c<w or op=='sar' else 0)|(OF if c==1 else 0)
    elif op in ('rol','ror'):
        if c:mask=(STATUS&~OF)|(OF if c==1 else 0)
    elif op in ('rcl','rcr'):
        # Conservative across vendors when masked count is nonzero, even if
        # modulo-(width+1) makes the rotation itself a no-op.
        if c:mask=(STATUS&~OF)|(OF if c==1 else 0)
    elif op in ('bt','bts','btr','btc'):mask=CF
    elif op in ('bsf','bsr'):mask=ZF
    elif op in ('tzcnt','lzcnt'):mask=CF|ZF
    elif op=='mul' or op.startswith('imul'):mask=CF|OF
    elif op in ('andn','blsi','blsmsk','blsr','bzhi'):mask=CF|SF|ZF|OF
    if f['chain']:mask=(STATUS&~CF)|(mask&CF)
    return mask

def masks(f,consumer,ini):
    fm=defined(f,ini);rm=[M]*6
    # BSF/BSR destination undefined on zero input, including a following INC/DEC.
    if f['op'] in ('bsf','bsr') and not(ini[1]&((1<<f['w'])-1)):
        rm[0]=0
        if f['chain']:fm&=CF
    if consumer['cc']>=0 and (NEEDS[consumer['cc']]&fm)!=NEEDS[consumer['cc']]:rm[3]=0
    return fm,rm

def cc_eval(cc,fl):
    c=bool(fl&CF);p=bool(fl&PF);z=bool(fl&ZF);s=bool(fl&SF);o=bool(fl&OF)
    return [o,not o,c,not c,z,not z,c or z,not(c or z),s,not s,p,not p,s!=o,s==o,z or s!=o,not z and s==o][cc]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True,type=Path);ap.add_argument('--quick',action='store_true');a=ap.parse_args()
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise SystemExit('native Linux x86-64 required')
    cpu=Path('/proc/cpuinfo').read_text();
    for feature in ('bmi1','bmi2','popcnt','abm'):
        if feature not in cpu:raise SystemExit('CPU missing '+feature)
    o=a.out;o.mkdir(parents=True,exist_ok=True);b=o/'build';b.mkdir(exist_ok=True)
    subprocess.run(['clang','-shared','-fPIC',str(H/'native.S'),'-o',str(b/'oracle.so')],check=True)
    lib=C.CDLL(str(b/'oracle.so'));lib.hb_flags_native.argtypes=[C.c_void_p]*4;lib.hb_flags_native.restype=None
    fs=producers();fs=fs[:2] if a.quick else fs
    variants=[];s=['.intel_syntax noprefix','.text']
    for fi,f in enumerate(fs):
        for con in consumer_forms(f):
            i=len(variants);variants.append(dict(producer=fi,**con))
            s += [f'.global f_{i}',f'f_{i}:',f['asm'],con['asm'],'ret']
    (b/'forms.S').write_text('\n'.join(s)+'\n');subprocess.run(['clang','-c',str(b/'forms.S'),'-o',str(b/'forms.o')],check=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(b/'forms.o'),str(b/'forms.bin')],check=True)
    syms=subprocess.check_output(['nm','-n',str(b/'forms.o')],text=True)
    offs={int(l.split()[-1][2:]):int(l.split()[0],16) for l in syms.splitlines() if ' f_' in l}
    codes=(b/'forms.bin').read_bytes();cm=mmap.mmap(-1,len(codes),prot=3);cm.write(codes);ca=C.addressof(C.c_char.from_buffer(cm))
    libc=C.CDLL(None,use_errno=True);libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int]
    if libc.mprotect(ca,len(codes),5):raise OSError(C.get_errno())
    (o/'x86-disassembly.txt').write_text(subprocess.check_output(['objdump','-d','-Mintel',str(b/'forms.o')],text=True))
    mem=struct.pack('<Q',0x0badc0ffeebbaadd)+bytes(range(8,64));mb=C.create_string_buffer(mem)
    seed=0xfc6a28ef1a65;rng=random.Random(seed);allinputs=[inputs(f,rng) for f in fs]
    corpus=o/'corpus';corpus.mkdir(exist_ok=True);rec=[];shard=0;cnt=0;normconsumer=0;undefinedconsumer=0;dig=hashlib.sha256();errors=[];byproducer={};examples={}
    def flush():
        nonlocal rec,shard
        if not rec:return
        with gzip.GzipFile(filename=str(corpus/f'flags-{shard:04}.hbfl.gz'),mode='wb',mtime=0) as g:g.write(b'HBFL0001'+struct.pack('<I',len(rec))+b''.join(rec))
        rec=[];shard+=1
    # Binary has full input and observations. JSONL only concise (no duplicate assembly).
    with gzip.open(o/'measurements.jsonl.gz','wt') as j:
      for i,v in enumerate(variants):
        f=fs[v['producer']];end=offs.get(i+1,len(codes));bc=codes[offs[i]:end-1];v['bytes']=bc.hex();v['id']=i
        for vi,ini in enumerate(allinputs[v['producer']]):
            ib=(C.c_uint64*7)(*ini);ob=(C.c_uint64*7)();lib.hb_flags_native(ib,ob,ca+offs[i],mb);out=list(ob)
            fm,rm=masks(f,v,ini)
            # Structural consumer check uses raw observed flags, including undefined values;
            # independent of the portable normative mask.
            if v['cc']>=0:
                truth=cc_eval(v['cc'],out[6]);old=ini[3];w=v['cw'];lo=(1<<w)-1
                if v['kind']=='jcc':expected=int(truth)
                elif v['kind']=='setcc':expected=(old&~255)|int(truth)
                else:
                    src=ini[4] if v['kind']=='cmov-rr' else struct.unpack('<Q',mem[:8])[0]
                    expected=((src if truth else old)&lo)|((old&~lo) if w==16 else 0)
                if out[3]!=expected:errors.append(dict(form=i,input=vi,expected=hex(expected),got=hex(out[3])))
                if rm[3]:normconsumer+=1
                else:undefinedconsumer+=1
            byproducer[f['name']]=byproducer.get(f['name'],0)+1
            name=f'{f["name"]}-{v["kind"]}-{v["cc"]}-{v["cw"]}-i{vi}'.encode()
            header=struct.pack('<HHQ7Q7Q7Q',len(name),len(bc),seed,*ini,*out,*rm,fm)
            rec.append(header+name+bc+mem)
            dig.update(struct.pack('<7Q',*out));cnt+=1
            j.write(json.dumps(dict(id=cnt-1,form=i,input=vi,in_regs=list(map(hex,ini)),out_regs=list(map(hex,out)),flags_mask=hex(fm),reg_masks=list(map(hex,rm))),separators=(',',':'))+'\n')
            ek=(f['op'],f['w'],f['chain'],v['kind'])
            if vi<2 and (v['cc'] in (-1,2,3)):
                examples[name.decode()]=dict(bytes=bc.hex(),input=list(map(hex,ini)),hardware=list(map(hex,out)),flags_mask=hex(fm),reg_masks=list(map(hex,rm)))
            if len(rec)>=4096:flush()
      flush()
    (o/'forms.json').write_text(json.dumps(dict(producers=fs,variants=variants),indent=2));(o/'examples.json').write_text(json.dumps(examples,indent=2))
    summary=dict(executor='native AMD x86-64 under KVM',seed=hex(seed),producer_forms=len(fs),programs=len(variants),executions=cnt,normative_consumer_cases=normconsumer,undefined_consumer_cases=undefinedconsumer,consumer_structure_errors=errors[:30],error_count=len(errors),shards=shard,result_sha256=dig.hexdigest(),by_producer=byproducer,cpu=subprocess.check_output(['lscpu'],text=True))
    (o/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps({k:v for k,v in summary.items() if k not in ('cpu','by_producer')},indent=2));return bool(errors)
if __name__=='__main__':raise SystemExit(main())
