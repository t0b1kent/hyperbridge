#!/usr/bin/env python3
"""Replay HBSTATE1 with a frozen HBMEM001 image; no game or Wine required."""
import argparse
import bisect
import collections
import hashlib
import json
import mmap
import os
import pathlib
import subprocess
import sys
import struct
import time
import unicorn as uc
from unicorn import x86_const as ux
STAGE3 = pathlib.Path(__file__).resolve().parents[1] / 'stand-diff-20260930'
sys.path.insert(0, str(STAGE3))
import span_diff as sd
import known_findings
from evidence_io import open_binary, mapped, write_text, exists
from flag_semantics import scalar_logic_mask
from capture_index import code_index as selective_code_index, entry_rips

OWN = pathlib.Path(__file__).resolve().parent
STAGE5 = OWN.parent / 'stand-diff-stage5-20261001'
sys.path.insert(0, str(STAGE5))
import intel_vex
from defects import Registry
STATUS_ORACLE = None  # Stage6 adapter opts in; historical stage5 CLI remains unchanged.

def code_index(capture, entry_rips):
    """Use byte-exact suffixes of authentic translated spans for internal entries."""
    entries = sorted(set(entry_rips)); codes = {}; capture_rips = set()
    for index, fields, code, why in sd.records(capture, 10**9):
        if why: continue
        start = fields[1]; capture_rips.add(start)
        a = bisect.bisect_left(entries, start)
        b = bisect.bisect_left(entries, start + len(code))
        for rip in entries[a:b]:
            suffix = code[rip-start:]
            if rip not in codes or len(suffix) < len(codes[rip][1]):
                codes[rip] = (index, suffix)
    return codes, capture_rips

def sha(p):
    h = hashlib.sha256()
    with open_binary(p) as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()

class Image:
    def __init__(self, path):
        self._mapping = mapped(path); self.data = self._mapping.__enter__()
        if self.data[:8] != b'HBMEM001': raise ValueError('image magic')
        self.regions = []; self.statuses = collections.Counter(); off = 40; self.footer = None
        while off < len(self.data):
            if off+48 > len(self.data): raise ValueError('truncated image region')
            tag,status,addr,size,prot,kind,n,err,_ = struct.unpack('<IIQQIIQII', self.data[off:off+48]); off += 48
            if tag == 0x45: self.footer = status; break
            if tag != 0x52 or off+n > len(self.data): raise ValueError('invalid image region')
            self.statuses[status] += 1
            if status == 1 and n == size: self.regions.append((addr,addr+size,off))
            off += n
        self.regions.sort(); self.starts = [r[0] for r in self.regions]
        if self.footer is None: raise ValueError('missing image footer')
    def read(self, addr, size):
        out = bytearray()
        while size:
            i = bisect.bisect_right(self.starts, addr)-1
            if i < 0: return None
            a,b,o = self.regions[i]
            if not a <= addr < b: return None
            n = min(size,b-addr); out += self.data[o+addr-a:o+addr-a+n]; addr += n; size -= n
        return bytes(out)
    def page(self, addr):
        # Padding allows 4KiB guest regions on a 16KiB host; accesses into
        # padding are rejected by the reference, never credited as coverage.
        return b''.join(self.read(addr+i,4096) or bytes(4096) for i in range(0,16384,4096))

def states(path, sequences=None, sequence=None, shard_index=0, shard_count=1):
    with open_binary(path) as f:
        if f.read(8) != b'HBSTATE1': raise ValueError('state magic')
        version,size,length,_ = struct.unpack('<4I',f.read(16))
        if version != 1 or size > 4096 or length > 8192: raise ValueError('state header')
        meta = json.loads(f.read(length)); count = 0
        while True:
            raw = f.read(size)
            if not raw: break
            if len(raw) != size: raise ValueError('truncated state')
            ordinal=count;count+=1
            if ordinal % shard_count != shard_index:continue
            entry,seq = struct.unpack_from('<2Q',raw)
            if sequence is not None and seq != sequence:continue
            if sequences is not None and seq not in sequences:continue
            rip,seq,thread,fpcr,fpsr,rflags,mxcsr = struct.unpack_from('<5Q2I',raw)
            go,xo,yo,fo,mo = [meta[k] for k in ['gpr_offset','xmm_offset','ymm_offset','fsw_offset','mm_offset']]
            fsw,fcw,ftw,reduced = struct.unpack_from('<IHBB',raw,fo)
            regs = dict(zip(sd.NAMES,struct.unpack_from('<16Q',raw,go)))
            yield dict(seed=0,sequence=seq,thread=thread,rip=rip,regs=regs,rflags=rflags,mxcsr=mxcsr,
                       fpcr=fpcr,fpsr=fpsr,xmm=[raw[xo+i*16:xo+(i+1)*16].hex() for i in range(16)],
                       ymm=[raw[yo+i*16:yo+(i+1)*16].hex() for i in range(16)],
                       fsw=fsw,fcw=fcw,ftw=ftw,reduced=reduced,mm=raw[mo:mo+128].hex(),
                       fsbase=struct.unpack_from('<Q',raw,meta['fs_base_offset'])[0],
                       gsbase=struct.unpack_from('<Q',raw,meta['gs_base_offset'])[0])

def oracle(code, state, image):
    rip = state['rip']; em = uc.Uc(uc.UC_ARCH_X86,uc.UC_MODE_64)
    pages = {}; writes = []; trace = []; status = {'status':'exit','undefined':0,'dynamic_undefined':0,'x87_undefined':0}
    flag_tracker = STATUS_ORACLE.Tracker(state) if STATUS_ORACLE else None
    def load(addr,n):
        for base in range(addr&~16383,(addr+n+16383)&~16383,16384):
            if base not in pages:
                pages[base]=image.page(base); em.mem_map(base,16384); em.mem_write(base,pages[base])
    load(rip,len(code)+1); em.mem_write(rip,code); em.mem_write(rip+len(code),b'\xf4')
    for k,r in zip(sd.NAMES,sd.REGS): em.reg_write(r,state['regs'][k])
    for name,value in [('EFLAGS',state['rflags']),('MXCSR',state['mxcsr']),('FS_BASE',state['fsbase']),('GS_BASE',state['gsbase']),('FPCW',state['fcw']),('FPSW',state['fsw'])]:
        em.reg_write(getattr(ux,'UC_X86_REG_'+name),value)
    tag=0; raw=bytes.fromhex(state['mm'])
    for i in range(8):
        tag |= (0 if state['ftw']&(1<<i) else 3) << (2*i)
        em.reg_write(getattr(ux,f'UC_X86_REG_FP{i}'),struct.unpack_from('<QH',raw,i*16))
    em.reg_write(ux.UC_X86_REG_FPTAG,tag)
    for i,x in enumerate(state['xmm']):
        lower=int.from_bytes(bytes.fromhex(x),'little')
        upper=int.from_bytes(bytes.fromhex(state['ymm'][i]),'little')
        em.reg_write(getattr(ux,f'UC_X86_REG_YMM{i}'),lower | (upper<<128))
    def invalid(em,access,addr,n,value,user):
        if access in [uc.UC_MEM_FETCH_UNMAPPED,uc.UC_MEM_FETCH_PROT] and not rip<=em.reg_read(ux.UC_X86_REG_RIP)<rip+len(code):
            status.update(status='exit',transfer_exit=True,exit_reason='EXIT_SPAN');return False
        if image.read(addr,n) is None:status.update(status='image_memory_NOT_PRESENT',bad_address=hex(addr));return False
        if len(pages)>1024:status['status']='page_cap_DROPPED';return False
        load(addr,n);return True
    def memory(em,access,addr,n,value,user):
        if image.read(addr,n) is None and not (rip<=addr and addr+n<=rip+len(code)):
            status.update(status='image_memory_NOT_PRESENT',bad_address=hex(addr));em.emu_stop();return
        if access==uc.UC_MEM_WRITE:writes.append((addr,n))
    def vex_read(addr, n):
        if image.read(addr,n) is None and not (rip<=addr and addr+n<=rip+len(code)):
            status.update(status='image_memory_NOT_PRESENT',bad_address=hex(addr))
            raise intel_vex.Unavailable('missing memory')
        load(addr,n)
        return bytes(em.mem_read(addr,n))
    def vex_write(addr, data):
        vex_read(addr,len(data))
        writes.append((addr,len(data)))
        em.mem_write(addr,data)
    def step(em,addr,n,user):
        if not rip<=addr<rip+len(code):
            status.update(status='exit',transfer_exit=True,exit_reason='EXIT_SPAN');em.emu_stop();return
        if addr+n > rip+len(code):
            status.update(status='capture_instruction_TRUNCATED',bad_address=hex(addr));em.emu_stop();return
        ins=next(sd.DIS.disasm(bytes(em.mem_read(addr,n)),addr),None)
        if ins is None:status['status']='unicorn_decode_gap';em.emu_stop();return
        if len(trace)>=512:status['status']='step_limit';em.emu_stop();return
        if ins.mnemonic in ['rdtsc','rdtscp','rdrand','rdseed','cpuid','syscall','sysenter']:
            status['status']='nondeterministic_or_environment';em.emu_stop();return
        trace.append([addr,n,ins.mnemonic,ins.op_str])
        if flag_tracker:
            try:
                flag_tracker.before(ins,em,ux,sd.xc,vex_read)
            except (STATUS_ORACLE.Unavailable, intel_vex.Unavailable) as exc:
                if status['status']=='exit':
                    status.update(status='flags_reference_unavailable',unavailable_instruction=str(exc))
                em.emu_stop()
                return
        if intel_vex.is_vex(ins):
            status['vex_instructions'] = status.get('vex_instructions',0) + 1
            try:
                intel_vex.execute(ins,em,ux,sd.xc,vex_read,vex_write)
            except intel_vex.Unavailable as exc:
                if status['status']=='exit':
                    status.update(status='reference_unavailable',unavailable_instruction=str(exc))
                em.emu_stop()
            return
        if ins.mnemonic in ['bsf','bsr']:
            operand=ins.operands[1]
            if operand.type == sd.xc.X86_OP_REG:
                source=em.reg_read(getattr(ux,'UC_X86_REG_'+ins.reg_name(operand.reg).upper()))
            elif operand.type == sd.xc.X86_OP_MEM:
                m=operand.mem
                value=lambda reg: em.reg_read(getattr(ux,'UC_X86_REG_'+ins.reg_name(reg).upper())) if reg else 0
                base=addr+n if m.base==sd.xc.X86_REG_RIP else value(m.base)
                address=(base+value(m.index)*m.scale+m.disp)&((1<<64)-1)
                if m.segment:address+=em.reg_read(getattr(ux,'UC_X86_REG_'+ins.reg_name(m.segment).upper()+'_BASE'))
                if image.read(address,operand.size) is None:
                    status.update(status='image_memory_NOT_PRESENT',bad_address=hex(address));em.emu_stop();return
                load(address,operand.size)
                source=int.from_bytes(em.mem_read(address,operand.size),'little')
            else:source=None
            if source == 0:
                status['status']='undefined_bsf_bsr_destination';em.emu_stop();return
        previous_undefined = status['undefined']
        for name,bit in sd.FLAG_BITS.items():
            if ins.eflags & getattr(sd.xc,'X86_EFLAGS_UNDEFINED_'+name,0):status['undefined'] |= 1<<bit
            elif any(ins.eflags & getattr(sd.xc,'X86_EFLAGS_'+kind+'_'+name,0) for kind in ['MODIFY','RESET','SET']):status['undefined'] &= ~(1<<bit)
        if ins.mnemonic in ['mul', 'imul']:
            status['undefined'] |= 0xd4
        status['undefined'] = scalar_logic_mask(ins.mnemonic, status['undefined'])
        if ins.mnemonic in ['shl','shr','sal','sar','rol','ror','rcl','rcr','shld','shrd']:
            op = ins.operands[-1]
            count = op.imm if op.type == sd.xc.X86_OP_IMM else em.reg_read(getattr(ux, 'UC_X86_REG_'+ins.reg_name(op.reg).upper())) if op.type == sd.xc.X86_OP_REG else 1
            width = ins.operands[0].size * 8
            count &= 63 if width == 64 else 31
            if ins.mnemonic in ['rol', 'ror']: count %= width
            if ins.mnemonic in ['rcl', 'rcr'] and width < 32: count %= width+1
            if count == 0: status['undefined'] = previous_undefined
            elif ins.mnemonic in ['shl','sal','shr','sar','shld','shrd']:
                status['undefined'] |= 1 << 4
                if count != 1: status['undefined'] |= 1 << 11
                if ins.mnemonic in ['shl','sal','shr'] and count >= width: status['undefined'] |= 1
                if ins.mnemonic in ['shld','shrd'] and count > width: status['undefined'] |= 0x8d5
            elif count != 1: status['undefined'] |= 1 << 11
        if ins.mnemonic.startswith('f'):
            status['status']='real_flag_family_NOT_ENABLED';em.emu_stop()
    interrupts=[]
    def interrupt(em,n,user):interrupts.append(n);status['status']='guest_exception';em.emu_stop()
    em.hook_add(uc.UC_HOOK_CODE,step);em.hook_add(uc.UC_HOOK_MEM_INVALID,invalid)
    em.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,memory);em.hook_add(uc.UC_HOOK_INTR,interrupt)
    try:em.emu_start(rip,0,count=513)
    except uc.UcError as exc:
        if status['status']=='exit' and not status.get('transfer_exit'):status['status']='unicorn_decode_gap' if exc.errno==uc.UC_ERR_INSN_INVALID else 'unicorn_error'
        status['error']=str(exc)
    ranges=[]
    for a,n in sorted(set(writes)):
        if image.read(a,n) is None:continue
        if ranges and a<=ranges[-1][1]:ranges[-1][1]=max(ranges[-1][1],a+n)
        else:ranges.append([a,a+n])
    written=[[hex(a),bytes(em.mem_read(a,b-a)).hex()] for a,b in ranges]
    out={**status,'rip':em.reg_read(ux.UC_X86_REG_RIP),'regs':dict(zip(sd.NAMES,[em.reg_read(r) for r in sd.REGS])),
         'rflags':em.reg_read(ux.UC_X86_REG_EFLAGS),'mxcsr':em.reg_read(ux.UC_X86_REG_MXCSR),
         'xmm':[em.reg_read(getattr(ux,f'UC_X86_REG_XMM{i}')).to_bytes(16,'little').hex() for i in range(16)],
         'ymm_hi':[(em.reg_read(getattr(ux,f'UC_X86_REG_YMM{i}')) >> 128).to_bytes(16,'little').hex() for i in range(16)],
         'written_memory':written,'trace':trace,'interrupts':interrupts,
         'memory_page_sha256':[[hex(a),hashlib.sha256(bytes(em.mem_read(a,16384))).hexdigest()] for a in sorted(pages)],
         'x87_fcw':em.reg_read(ux.UC_X86_REG_FPCW),'x87_fsw':em.reg_read(ux.UC_X86_REG_FPSW),
         'x87_tag':em.reg_read(ux.UC_X86_REG_FPTAG),
         'x87_fp':[em.reg_read(getattr(ux,f'UC_X86_REG_FP{i}')) for i in range(8)]}
    if flag_tracker:
        out['unicorn_mxcsr'] = out['mxcsr']
        out['mxcsr_flags'] = flag_tracker.result()
        out['mxcsr'] = (out['mxcsr'] & ~0x3f) | flag_tracker.flags
    return out,pages

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--states',required=True);ap.add_argument('--image',required=True)
    ap.add_argument('--capture',required=True);ap.add_argument('--runner',default=str(STAGE3/'stand_runner_real_ec_union_20261001'))
    ap.add_argument('--limit',type=int,default=1000);ap.add_argument('--inject',action='store_true')
    ap.add_argument('--fp-gate',choices=['0','1']);ap.add_argument('--fp-kind',choices=['mxcsr','addsub'],default='mxcsr')
    ap.add_argument('--sequence',type=int)
    ap.add_argument('--sequences', type=pathlib.Path, help='JSON array of exact selected sequences')
    ap.add_argument('--batch-size',type=int,default=256,help='Reuse existing runner case protocol; fresh guest thread and pages each case')
    ap.add_argument('--shard-index',type=int,default=0)
    ap.add_argument('--shard-count',type=int,default=1)
    ap.add_argument('--scan-all',action='store_true',help='Preserve all independent failures; never turn failures into PASS')
    ap.add_argument('--fp-target-only',action='store_true',help='Only captured blocks containing the selected FP trigger family')
    ap.add_argument('--known-mxcsr-code',action='append',default=[],help='Curator-classified exact code bytes: continue only a sole MXCSR mismatch')
    ap.add_argument('--known-mxcsr-1f80-1fa0',action='store_true',help='Stage3 user classification: sole MXCSR 1f80/1fa0 mismatch is KNOWN')
    ap.add_argument('--out-prefix',type=pathlib.Path)
    ap.add_argument('--known-findings',type=pathlib.Path,default=STAGE3/'known-findings-empty.json')
    ap.add_argument('--game',default='unknown')
    ap.add_argument('--known-defects',type=pathlib.Path,default=STAGE5/'known-defects.json')
    ap.add_argument('--cpu-budget-ms',type=int,default=2000)
    ap.add_argument('--legacy-known-patterns',action='store_true',help='Historical diagnostic mode only; stage5 gates use exact manual entries')
    ap.add_argument('--detach',action='store_true',help='Run standalone replay in an owned non-PTY session')
    args=ap.parse_args()
    if not 0 <= args.shard_index < args.shard_count:ap.error('invalid shard index/count')
    if args.detach:
        base=args.out_prefix or OWN/'out'/('real-inputs-stage3-'+str(time.time_ns()))
        driver=base.with_suffix('.driver.log')
        if driver.exists():raise FileExistsError('preserve existing driver log')
        command=[sys.executable,str(pathlib.Path(__file__).resolve()),*[s for s in sys.argv[1:] if s!='--detach']]
        if args.out_prefix is None:command+=['--out-prefix',str(base)]
        with driver.open('w') as stream:
            child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stream,stderr=stream,start_new_session=True)
        print('REPLAY_PID',child.pid,'OUTPUT',base,'DRIVER',driver)
        return 0
    if args.fp_gate is not None:
        for k in ['MACRUNNER_FEX_MXCSR_FLAGS','MACRUNNER_FEX_ADDSUB_NAN']:os.environ[k]='0'
        os.environ['MACRUNNER_FEX_MXCSR_FLAGS' if args.fp_kind=='mxcsr' else 'MACRUNNER_FEX_ADDSUB_NAN']=args.fp_gate
        for k in ['MACRUNNER_FEX_ADDSUB_NAN_PRIORITY','MACRUNNER_FEX_ADDSUB_INDEFINITE']:os.environ[k]='0'
    image=Image(args.image)
    registry=Registry(args.known_defects)
    known_patterns,known_findings_sha=known_findings.load(args.known_findings)
    if image.footer != 0 or image.statuses[3]:
        raise ValueError(f'incomplete memory image: footer={image.footer}, FAILED={image.statuses[3]}; replay NOT_ENABLED')
    selected = set(json.loads(args.sequences.read_text())) if args.sequences else None
    codes,capture_rips = selective_code_index(args.capture, entry_rips(args.states,selected,args.sequence))
    started=time.monotonic();stamp=str(time.time_ns());base=args.out_prefix or OWN/'out'/('real-inputs-stage3-'+stamp);counts=collections.Counter();classes=collections.Counter()
    base.parent.mkdir(parents=True,exist_ok=True)
    if any(exists(base.with_suffix(suffix)) for suffix in ['.json','.jsonl','.log']):
        raise FileExistsError('preserve existing stage3 output')
    input_rips=set();checked_rips=set();known_classes=collections.Counter();new_classes=collections.Counter()
    inputs={str(p):sha(p) for p in [args.states,args.image,args.capture,args.runner,
        args.known_defects,STAGE5/'intel_vex.py',STAGE5/'defects.py',
        pathlib.Path(__file__),OWN/'flag_semantics.py',OWN/'capture_index.py',STAGE3/'evidence_io.py',pathlib.Path(sd.__file__),pathlib.Path(known_findings.__file__),args.known_findings]}
    with open_binary(args.capture) as f:
        f.read(8);n,=struct.unpack('<I',f.read(4));env=dict(l.split('=',1) for l in f.read(n).decode().splitlines() if '=' in l)
        env={k:v for k,v in env.items() if k.startswith('FEX_') and v}
    if not 1<=args.batch_size<=4096:raise ValueError('batch size outside 1..4096')
    # Reserve all legitimate guest addresses before FEX allocates host/JIT state.
    ranges=[(a&~16383,(b+16383)&~16383) for a,b,_ in image.regions]
    ranges += [(rip&~16383,(rip&~16383)+0x14000) for rip in codes]
    merged=[]
    for a,b in sorted(ranges):
        if merged and a<=merged[-1][1]:merged[-1][1]=max(b,merged[-1][1])
        else:merged.append([a,b])
    reserve=base.with_suffix('.ranges')
    reserve.write_text(''.join(f'{a:x} {b:x}\n' for a,b in merged))
    env['ORACLE_RESERVE_RANGES']=str(reserve)
    injected=False;native=None;batch_used=0
    retries=collections.Counter();fixed_classes=collections.Counter();phase=collections.Counter()
    import atexit, signal
    def close_owned_native():
        nonlocal native
        if native is not None:
            current=native;native=None
            if current.p.poll() is None:current.p.terminate()
            current.close()
    def terminated(signum,frame):
        close_owned_native()
        raise SystemExit(124)
    atexit.register(close_owned_native)
    signal.signal(signal.SIGTERM,terminated)
    with write_text(base.with_suffix('.jsonl')) as out,base.with_suffix('.log').open('w') as log:
        for state in states(args.states,selected,args.sequence,args.shard_index,args.shard_count):
            if counts['checked']>=args.limit:break
            counts['states']+=1
            input_rips.add(state['rip'])
            if args.sequence is not None and state['sequence']!=args.sequence:continue
            if selected is not None and state['sequence'] not in selected: continue
            if state['rip'] not in codes:
                counts['missing_code_NOT_PRESENT']+=1
                out.write(json.dumps(dict(state=state,status='missing_code_NOT_PRESENT'))+'\n');continue
            index,code=codes[state['rip']]
            if args.fp_target_only:
                targets = {'ldmxcsr','stmxcsr','fxrstor','fxrstor64'} if args.fp_kind=='mxcsr' else {'addsubps','addsubpd'}
                if not any(ins.mnemonic in targets for ins in sd.DIS.disasm(code,state['rip'])):
                    counts['not_selected_FP_family']+=1;continue
            if image.read(state['rip'],len(code)) != code:
                counts['capture_code_overlay']+=1
            if state['reduced']:
                counts['x87_reduced_input_NOT_ENABLED']+=1
                out.write(json.dumps(dict(state=state,record=index,code=code.hex(),status='x87_reduced_input_NOT_ENABLED'))+'\n');continue
            tick=time.monotonic()
            ref,pages=oracle(code,state,image)
            phase['reference_seconds']+=time.monotonic()-tick
            if ref.get('mxcsr_flags',{}).get('families'):
                counts['mxcsr_flags_states_executed']+=1
                for name in ref['mxcsr_flags']['families']:
                    counts['mxcsr_flags_family_states_'+name]+=1
                for name in ref['mxcsr_flags']['instructions']:
                    counts['mxcsr_flags_instruction_states_'+name]+=1
            if ref.get('vex_instructions'):counts['vex_states_executed']+=1
            if ref['status']!='exit':
                counts[ref['status']]+=1
                out.write(json.dumps(dict(state=state,record=index,code=code.hex(),status=ref['status'],reference=ref))+'\n');continue
            pp=base.with_suffix('.pages')
            with pp.open('wb') as f:
                f.write(b'HBPAGES1'+struct.pack('<Q',len(pages)))
                for a,b in sorted(pages.items()):f.write(struct.pack('<Q',a)+b)
            if native is None or batch_used>=args.batch_size:
                if native is not None:native.close()
                native=sd.Native(log,runner=pathlib.Path(args.runner),captured_env={**env,'FEX_X87REDUCEDPRECISION':'0'},timeout_ms=args.cpu_budget_ms)
                batch_used=0
            try:
                items={'id':state['sequence'],'seed':0,'code':code.hex(),'rip':hex(state['rip']),
                       'rflags':hex(state['rflags']),'mxcsr':hex(state['mxcsr']),'pages':str(pp),
                       'fsbase':hex(state['fsbase']),'gsbase':hex(state['gsbase']),
                       'fcw':hex(state['fcw']),'fsw':hex(state['fsw']),'ftw':hex(state['ftw']),'mm':state['mm'],
                       **{k:hex(v) for k,v in state['regs'].items()},**{f'x{i}':x for i,x in enumerate(state['xmm'])},
                       **{f'y{i}':x for i,x in enumerate(state['ymm'])}}
                line=' '.join(f'{k}={v}' for k,v in items.items())+''.join(f' watch={a}:{len(bytes.fromhex(h))}' for a,h in ref['written_memory'])
                attempts=[]
                tick=time.monotonic()
                for attempt in range(2):
                    native.p.stdin.write(line+'\n');native.p.stdin.flush()
                    while not native.sel.select(1):
                        if native.p.poll() is not None:raise RuntimeError('owned native process gone before response')
                    raw_answer=native.p.stdout.readline()
                    if not raw_answer:raise RuntimeError('owned native empty response')
                    answer=json.loads(raw_answer)
                    attempts.append(answer)
                    if answer.get('state_valid') or answer.get('status') not in ['timeout','host_code_collision','guest_image_mapping_FAILED'] or attempt:
                        break
                    retries[answer['status']]+=1
                    native.close()
                    native=sd.Native(log,runner=pathlib.Path(args.runner),captured_env={**env,'FEX_X87REDUCEDPRECISION':'0'},timeout_ms=args.cpu_budget_ms)
                    batch_used=0
                phase['native_seconds']+=time.monotonic()-tick
            finally:batch_used+=1
            diff=[]
            if not answer.get('state_valid'):counts[answer['status']]+=1
            else:
                counts['checked']+=1
                checked_rips.add(state['rip'])
                if args.inject and not injected:
                    answer['regs']['rax']=hex(int(answer['regs']['rax'],0)^1);injected=True;counts['injected']+=1
                for k in ['rip','mxcsr']:
                    if ref[k]!=int(answer[k],0):diff.append(k)
                if any(ref['regs'][k]!=int(answer['regs'][k],0) for k in sd.NAMES):diff.append('gpr')
                if (ref['rflags']^int(answer['rflags'],0))&(0x3f7fd7 & ~ref['undefined']):diff.append('rflags')
                if ref['xmm']!=answer['xmm']:diff.append('xmm')
                if ref['ymm_hi']!=answer['ymm_hi']:diff.append('ymm_hi')
                if ref['written_memory']!=answer['written_memory']:diff.append('written_memory')
                if 'memory_page_sha256' in answer:
                    if ref['memory_page_sha256']!=answer['memory_page_sha256']:diff.append('memory_page_sha256')
                    if any(answer[k+'_hash'] != answer['init_'+k+'_hash'] for k in ['data','stack']):diff.append('extra_native_arena_write')
                if ref['x87_fcw']!=int(answer['fcw'],0) or ref['x87_fsw']!=answer['x87_fsw']:diff.append('x87_status')
                ftw=sum(1<<i for i in range(8) if (ref['x87_tag']>>(2*i))&3 != 3)
                if ftw!=answer['x87_abridged_ftw']:diff.append('x87_tags')
                mm=bytes.fromhex(answer['x87_raw'])
                if any(ftw&(1<<i) and mm[i*16:i*16+10]!=struct.pack('<QH',*ref['x87_fp'][i]) for i in range(8)):diff.append('x87_value')
                counts['mismatch' if diff else 'matched']+=1;classes.update(diff)
            known=args.legacy_known_patterns and diff == ['mxcsr'] and (code.hex() in args.known_mxcsr_code or
                (args.known_mxcsr_1f80_1fa0 and {ref['mxcsr'],int(answer['mxcsr'],0)}=={0x1f80,0x1fa0}))
            known_name='mxcsr' if known else None
            known_provenance=None
            approved,adjudication=registry.classify(args.game,state,code,diff,ref,answer)
            if adjudication and adjudication.get('flags_verdict'):
                counts['mxcsr_flags_'+adjudication['flags_verdict'].lower()]+=1
                if adjudication['flags_verdict']=='FIXED' and approved!='FIXED_MXCSR_STATUS_NOT_TRACKED':
                    fixed_classes['MXCSR_STATUS_NOT_TRACKED']+=1
            if adjudication and adjudication.get('exact_fixed_class'):
                fixed_classes[adjudication['exact_fixed_class']]+=1
            if adjudication and adjudication.get('flags_partial_fixed'):
                counts['mxcsr_flags_partial_fixed']+=1
            if approved and approved.startswith('KNOWN_'):
                known_name=approved.removeprefix('KNOWN_');known=True;known_provenance=adjudication
            elif approved and approved.startswith('FIXED_'):
                fixed_classes[approved.removeprefix('FIXED_')]+=1
            if diff and not known and args.legacy_known_patterns:
                known_name,known_provenance=known_findings.classify(known_patterns,code.hex(),diff,ref,answer)
                known=bool(known_name)
            classification='KNOWN_'+known_name if known else ('NEW' if diff else 'EQUAL' if answer.get('state_valid') else answer['status'])
            unsafe_fault = not answer.get('state_valid') and answer['status'] not in [
                'host_code_collision','guest_image_mapping_FAILED','watch_mapping_FAILED']
            if unsafe_fault:new_classes['native_'+answer['status']]+=1
            if known:known_classes[known_name]+=1
            elif diff:new_classes.update(diff)
            out.write(json.dumps(dict(state=state,record=index,code=code.hex(),reference=ref,native=answer,classes=diff,classification=classification,known_provenance=known_provenance,adjudication=approved,retry_attempts=attempts if len(attempts)>1 else [],pages_sha256=sha(pp)))+'\n')
            pp.unlink()
            if not answer.get('state_valid'):
                native.close();native=None
            if unsafe_fault and not args.scan_all:
                counts['STOP_fault_requires_classification']+=1;break
            if known:
                counts['KNOWN_'+known_name]+=1
            elif diff and args.fp_gate!='0' and not args.inject and not args.scan_all:
                counts['STOP_mismatch_requires_classification']+=1;break
        if native is not None:native.close();native=None
    result=dict(label='DIAGNOSTIC_ONLY_NOT_GOLDEN',status='CHECKED' if counts['checked'] else 'UNVERIFIED',counts=dict(counts),classes=dict(classes),inputs_sha256=inputs,runner_batch_size=args.batch_size,
                effective_config=env,fp_gate=args.fp_gate,fp_kind=args.fp_kind,fp_target_only=args.fp_target_only,
                 known_mxcsr_codes=args.known_mxcsr_code,
                  known_mxcsr_1f80_1fa0=args.known_mxcsr_1f80_1fa0,known_classes=dict(known_classes),new_classes=dict(new_classes),
                  known_findings_sha256=known_findings_sha,
                  fixed_classes=dict(fixed_classes),retry_counts=dict(retries),phase_seconds=dict(phase),cpu_budget_ms=args.cpu_budget_ms,
                 elapsed_seconds=time.monotonic()-started,
                 coverage=dict(input_unique_rips=len(input_rips),checked_unique_rips=len(checked_rips),capture_unique_rips=len(capture_rips),
                               checked_capture_start_rips=len(checked_rips & capture_rips),
                               percent=100*len(checked_rips & capture_rips)/len(capture_rips) if capture_rips else None),
                image_footer=image.footer,image_statuses=dict(image.statuses),raw=str(base.with_suffix('.jsonl')),
                boundaries=['Entry register times differ from end memory snapshot identically on both engines.',
                            'All supplied sparse pages compared by SHA256 when runner exposes memory_page_sha256; unmapped accesses fault. Other native mappings NOT_VERIFIED.',
                            'x87 execution NOT_ENABLED; x87 input preserved. Shift flags and YMM upper halves compared.',
                            'Captured code overrides later image code identically on both engines; snapshot skew remains.',
                            'No EC-native boundary acceptance. GPU private-region exclusion NOT_VERIFIED.'])
    base.with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    return 2 if not counts['checked'] else int(bool(new_classes or counts['STOP_fault_requires_classification']))

if __name__=='__main__':raise SystemExit(main())
