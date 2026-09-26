#!/usr/bin/env python3
"""Actual x86 AVX-512 oracle; HBUP0002 uses all eight opmask seeds.
No HyperBridge/ARM execution is claimed by this generator.
"""
import argparse, ctypes as C, gzip, hashlib, json, mmap, os, platform, struct, subprocess
from pathlib import Path
H=Path(__file__).resolve().parent
MASK64=(1<<64)-1

def seed_vec(seed):
    out=bytearray(2048)
    for r in range(32):
        for q in range(16):
            # Finite, different lanes/sources; upper state deliberately nonzero.
            v=0x3f000000+((r*0x1357+q*0x107+seed)&0x007fffff)
            struct.pack_into('<I',out,r*64+q*4,v)
    mem=bytes((i*37+seed*11)&255 for i in range(256))
    return bytes(out),mem

def forms():
    out=[]
    def add(name,asm,vl,lane,k,z,kind='normal',mode=0,valid=0):
        out.append(dict(name=name,asm=asm,vl=vl,lane=lane,k=k,z=z,kind=kind,mode=mode,valid=valid))
    moves=[('vmovups',4),('vmovupd',8),('vmovdqu8',1),('vmovdqu16',2),('vmovdqu32',4),('vmovdqu64',8)]
    # k0 encoded as aaa=0 is a distinct no-mask control, not an all-zero mask.
    for op,lane in moves:
        for vl,reg in [(128,'xmm'),(256,'ymm'),(512,'zmm')]:
            for k in range(1,8):
                for z in (False,True):
                    suf=f'{{k{k}}}'+('{z}' if z else '')
                    for form,rhs in [('rr',reg+'1'),('rm','[rbx]')]:
                        add(f'M01-{op}-{vl}-{form}-k{k}-z{int(z)}',f'{op} {reg}0{suf},{rhs}',vl,lane,k,z)
                add(f'M01-{op}-{vl}-mr-k{k}',f'{op} [rdi]{{k{k}}},{reg}1',vl,lane,k,False)
            add(f'CTRL-{op}-{vl}-rm-aaa0',f'{{evex}} {op} {reg}0,[rbx]',vl,lane,0,False)
    # Every existing native arithmetic/shuffle/unpack family with a legal EVEX form.
    ops=[(op,lane) for lane,tail in [(4,'ps'),(8,'pd')] for op in [f'v{x}{tail}' for x in ('add','sub','mul','div','min','max','and','andn','or','xor','unpckl','unpckh')]]
    ops += [(op,lane) for op,lane in [('vpaddb',1),('vpaddw',2),('vpaddd',4),('vpaddq',8),('vpsubb',1),('vpsubw',2),('vpsubd',4),('vpsubq',8),('vpxord',4),('vpxorq',8),('vpunpcklbw',1),('vpunpckhbw',1),('vpunpcklwd',2),('vpunpckhwd',2),('vpunpckldq',4),('vpunpckhdq',4),('vpunpcklqdq',8),('vpunpckhqdq',8)]]
    for op,lane in ops:
        for vl,reg in [(128,'xmm'),(256,'ymm'),(512,'zmm')]:
            for k in range(1,8):
                for z in (False,True):
                    suf=f'{{k{k}}}'+('{z}' if z else '')
                    for form,rhs in [('rr',reg+'2'),('rm','[rbx]')]:
                        add(f'VEC-{op}-{vl}-{form}-k{k}-z{int(z)}',f'{op} {reg}0{suf},{reg}1,{rhs}',vl,lane,k,z)
    for op,lane in [('vaddss',4),('vsubss',4),('vmulss',4),('vdivss',4),('vminss',4),('vmaxss',4),('vaddsd',8),('vsubsd',8),('vmulsd',8),('vdivsd',8),('vminsd',8),('vmaxsd',8)]:
        for k in range(1,8):
            for z in (False,True):
                for form,rhs in [('rr','xmm2'),('rm','[rbx]')]:
                    suf=f'{{k{k}}}'+('{z}' if z else '')
                    add(f'SCALAR-{op}-{form}-k{k}-z{int(z)}',f'{op} xmm0{suf},xmm1,{rhs}',128,lane,k,z)
    # Additional native SSE conversion/shuffle families; legal EVEX masking only.
    # There is no EVEX opmask encoding for (V)INSERTPS, (V)EXTRACTPS or MOVD/Q.
    for vl,reg in [(128,'xmm'),(256,'ymm'),(512,'zmm')]:
        for k in range(1,8):
            for z in (False,True):
                suf=f'{{k{k}}}'+('{z}' if z else '')
                for op,lane in [('vsqrtps',4),('vsqrtpd',8),('vcvtdq2ps',4),('vcvttps2dq',4),('vcvtps2dq',4)]:
                    for form,rhs in [('rr',reg+'1'),('rm','[rbx]')]:
                        add(f'EXTRA-{op}-{vl}-{form}-k{k}-z{int(z)}',f'{op} {reg}0{suf},{rhs}',vl,lane,k,z)
                for op,lane in [('vshufps',4),('vshufpd',8)]:
                    for imm in (0,0x1b,0xe4,0xff):
                        for form,rhs in [('rr',reg+'2'),('rm','[rbx]')]:
                            add(f'EXTRA-{op}-{vl}-{form}-k{k}-z{int(z)}-imm{imm}',f'{op} {reg}0{suf},{reg}1,{rhs},{imm}',vl,lane,k,z)
                for op,lane in [('vpshufd',4),('vpshufhw',2),('vpshuflw',2)]:
                    for form,rhs in [('rr',reg+'1'),('rm','[rbx]')]:
                        add(f'EXTRA-{op}-{vl}-{form}-k{k}-z{int(z)}',f'{op} {reg}0{suf},{rhs},0x1b',vl,lane,k,z)
        # Widen/narrow conversions: mask granularity refers to output elements.
        for op,lane,dstreg,srcreg,nvl in [('vcvtps2pd',8,reg,'xmm' if vl<=256 else 'ymm',vl),('vcvtdq2pd',8,reg,'xmm' if vl<=256 else 'ymm',vl),('vcvtpd2ps',4,'xmm' if vl<=256 else 'ymm',reg,vl//2)]:
            for k in range(1,8):
                for z in (False,True):
                    suf=f'{{k{k}}}'+('{z}' if z else '')
                    memsz=({128:'xmmword',256:'ymmword',512:'zmmword'}[vl] if op=='vcvtpd2ps' else {128:'qword',256:'xmmword',512:'ymmword'}[vl])
                    for form,rhs in [('rr',srcreg+'1'),('rm',memsz+' ptr [rbx]')]:
                        add(f'EXTRA-{op}-srcvl{vl}-{form}-k{k}-z{int(z)}',f'{op} {dstreg}0{suf},{rhs}',nvl,lane,k,z)
    for op,lane in [('vsqrtss',4),('vsqrtsd',8),('vcvtss2sd',8),('vcvtsd2ss',4)]:
        for k in range(1,8):
            for z in (False,True):
                suf=f'{{k{k}}}'+('{z}' if z else '')
                for form,rhs in [('rr','xmm2'),('rm','[rbx]')]:
                    add(f'SCALAR-{op}-{form}-k{k}-z{int(z)}',f'{op} xmm0{suf},xmm1,{rhs}',128,lane,k,z)
    # Pair masks independent: encoded k1/k2, both zero/merge paths.
    for lk,sk in [(1,0),(0,2),(1,2)]:
        for z in (False,True):
            if not lk and z: continue
            ls=f'{{k{lk}}}'+('{z}' if z else '') if lk else ''
            ss=f'{{k{sk}}}' if sk else ''
            add(f'PAIR-loadk{lk}-storek{sk}-z{int(z)}',f'{{evex}} vmovups xmm0{ls},[rbx]\n{{evex}} vmovups [rdi]{ss},xmm0',128,4,lk or sk,z,'pair')
    # Guard-page corpus covers loads AND stores. End of mapped page is after valid bytes.
    for op,lane in moves:
        for vl,reg in [(128,'xmm'),(256,'ymm'),(512,'zmm')]:
            for k in range(1,8):
                for valid in (0,lane,vl//16):
                    for direction,mode in [('load',1),('store',2)]:
                        for z in ((False,True) if mode==1 else (False,)):
                            suf=f'{{k{k}}}'+('{z}' if z else '')
                            asm=f'{op} {reg}0{suf},[rbx]' if mode==1 else f'{op} [rdi]{suf},{reg}1'
                            add(f'FAULT-{op}-{vl}-{direction}-k{k}-z{int(z)}-valid{valid}',asm,vl,lane,k,z,'guard',mode,valid)
    return out

def patterns(f):
    n=1 if f['name'].startswith('SCALAR-') else f['vl']//(8*f['lane'])
    full=(1<<n)-1
    if f['mode']:
        active=(1<<(f['valid']//f['lane']))-1
        return list(dict.fromkeys([0,active,active|(1<<(f['valid']//f['lane'])),full]))
    return list(dict.fromkeys([0,full,MASK64,full&0x5555555555555555,full&0xaaaaaaaaaaaaaaaa,*[1<<i for i in range(n)]]))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);ap.add_argument('--quick',action='store_true');a=ap.parse_args()
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise SystemExit('requires Linux x86-64')
    o=a.out;o.mkdir(parents=True,exist_ok=True);w=o/'build';w.mkdir(exist_ok=True)
    subprocess.run(['clang','-O2','-shared','-fPIC',str(H/'native_oracle.c'),str(H/'native_seed.S'),'-o',str(w/'oracle.so')],check=True)
    lib=C.CDLL(str(w/'oracle.so'));lib.hb_mask_native.argtypes=[C.c_void_p]*7
    if not lib.hb_mask_available():raise SystemExit('AVX512F/DQ/BW/VL unavailable')
    fs=forms();fs=fs[:24] if a.quick else fs
    s=['.intel_syntax noprefix','.text']
    for i,f in enumerate(fs):s += [f'.global mask_{i}',f'mask_{i}:',f['asm'],'ret']
    (w/'forms.S').write_text('\n'.join(s)+'\n')
    subprocess.run(['clang','-c',str(w/'forms.S'),'-o',str(w/'forms.o')],check=True)
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(w/'forms.o'),str(w/'forms.bin')],check=True)
    syms=subprocess.check_output(['nm','-n',str(w/'forms.o')],text=True)
    offs={int(l.split()[-1].split('_')[1]):int(l.split()[0],16) for l in syms.splitlines() if ' mask_' in l}
    code=(w/'forms.bin').read_bytes();cm=mmap.mmap(-1,len(code),prot=3);cm.write(code);ca=C.addressof(C.c_char.from_buffer(cm))
    libc=C.CDLL(None,use_errno=True);libc.mprotect.argtypes=[C.c_void_p,C.c_size_t,C.c_int]
    if libc.mprotect(ca,len(code),5):raise OSError(C.get_errno())
    page=os.sysconf('SC_PAGESIZE');mem=mmap.mmap(-1,page*2,prot=3);ma=C.addressof(C.c_char.from_buffer(mem));data=ma+page-256
    if libc.mprotect(ma+page,page,0):raise OSError(C.get_errno())
    (o/'x86-disassembly.txt').write_text(subprocess.check_output(['objdump','-d','-Mintel',str(w/'forms.o')],text=True))
    corpus=o/'corpus';corpus.mkdir(exist_ok=True);rec=[];count=0;shard=0;faults=0;nonfaults=0;unexpected=[];dig=hashlib.sha256();seed=0xfc6a28e
    def flush():
        nonlocal rec,shard
        if not rec:return
        with gzip.GzipFile(filename=str(corpus/f'mask-{shard:04}.hbup.gz'),mode='wb',mtime=0) as g:g.write(b'HBUP0002'+struct.pack('<I',len(rec))+b''.join(rec))
        rec=[];shard+=1
    with gzip.open(o/'measurements.jsonl.gz','wt') as j:
      for i,f in enumerate(fs):
        end=offs.get(i+1,len(code));bc=code[offs[i]:end-1];f['bytes']=bc.hex();f['form_id']=i
        for pi,p in enumerate(patterns(f)):
            ks=[(0x9e3779b97f4a7c15*(k+1)^seed)&MASK64 for k in range(8)]
            if f['k']:ks[f['k']]=p
            if f['kind']=='pair':
                if 'loadk1' in f['name']:ks[1]=p
                if 'storek2' in f['name']:ks[2]=(p^0x5)&15
            inp,im=seed_vec(seed);ib=C.create_string_buffer(inp);ob=C.create_string_buffer(2048);ka=(C.c_uint64*8)(*ks)
            C.memmove(data,im,256);rd=ma+page-f['valid'] if f['mode']==1 else data;wr=ma+page-f['valid'] if f['mode']==2 else data+128
            fa=C.c_size_t();sig=lib.hb_mask_native(ib,ob,rd,ca+offs[i],wr,ka,C.byref(fa));out=ob.raw;om=C.string_at(data,256)
            n=f['vl']//(8*f['lane']);accessible=f['valid']//f['lane'];should_fault=bool(f['mode'] and p&(((1<<n)-1)^((1<<accessible)-1)))
            if (sig!=0)!=should_fault or sig not in (0,11,7):unexpected.append(dict(name=f['name'],p=hex(p),signal=sig,expected_fault=should_fault))
            count+=1;faults+=bool(sig);nonfaults+=not bool(sig);dig.update(out+om+struct.pack('<i',sig))
            name=(f['name']+f'-p{p:x}').encode();header=struct.pack('<HHIQ8QiiI',len(name),len(bc),2,seed,*ks,f['mode'],f['valid'],int(bool(sig)))
            rec.append(header+name+bc+inp+im+out+om)
            j.write(json.dumps(dict(id=count-1,name=name.decode(),form_id=i,bytes=bc.hex(),k=list(map(hex,ks)),signal=sig,expected_fault=should_fault,fault_delta=int(fa.value-(ma+page)) if sig else None,mode=f['mode'],valid=f['valid'],input_zmm=inp.hex(),input_mem=im.hex(),hardware_zmm=None if sig else out.hex(),hardware_mem=om.hex()),separators=(',',':'))+'\n')
            if len(rec)>=2048:flush()
      flush()
    (o/'forms.json').write_text(json.dumps(fs,indent=2))
    summary=dict(executor='native AMD x86-64 under KVM; no ARM execution',cpu=subprocess.check_output(['lscpu'],text=True),forms=len(fs),executions=count,no_fault=nonfaults,fault=faults,unexpected=unexpected,shards=shard,result_sha256=dig.hexdigest(),memory_guard='second host page PROT_NONE; equivalent inaccessible-page suppression, not claimed as an unmapped mapping')
    (o/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps({k:v for k,v in summary.items() if k!='cpu'},indent=2))
    return bool(unexpected)
if __name__=='__main__':raise SystemExit(main())
