#!/usr/bin/env python3
"""HBCAP -> same-address native FEX/Unicorn block differential prototype.

Native backend is deliberately labelled NOT_PRODUCT_ARM64EC. Captures are read-only.
No claim of full coverage: x87 state comparison is currently NOT_ENABLED.
"""
import argparse, collections, ctypes, functools, hashlib, json, mmap, os, pathlib, selectors, struct, subprocess, sys, time
import capstone as cs
from capstone import x86_const as xc
import unicorn as uc
from unicorn import x86_const as ux
from evidence_io import open_binary, mapped, write_text

OWN = pathlib.Path(__file__).resolve().parent
ROOT = OWN.parents[1]
ARENA = 0x80000000000
STACK = ARENA + 0x1000000
SIZE = 0x4000
MASK64 = (1 << 64)-1
NAMES = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',*[f'r{i}' for i in range(8,16)]]
REGS = [getattr(ux, 'UC_X86_REG_'+x.upper()) for x in NAMES]
FLAG_BITS = {'CF':0,'PF':2,'AF':4,'ZF':6,'SF':7,'TF':8,'IF':9,'DF':10,'OF':11,'NT':14,'RF':16}
DIS = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
DIS.detail = True
HASH = None
if (OWN/'hash.dylib').exists():
    HASH = ctypes.CDLL(str(OWN/'hash.dylib')).stand_fnv
    HASH.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    HASH.restype = ctypes.c_uint64

def random_bytes(seed, length):
    result = bytearray()
    for _ in range((length+7)//8):
        seed = (seed+0x9e3779b97f4a7c15)&MASK64
        z = seed
        z = ((z^(z>>30))*0xbf58476d1ce4e5b9)&MASK64
        z = ((z^(z>>27))*0x94d049bb133111eb)&MASK64
        result.extend(struct.pack('<Q', z^(z>>31)))
    return bytes(result[:length]), seed

def fnv(data):
    if HASH is not None: return HASH(data,len(data))
    h = 0xcbf29ce484222325
    for b in data:
        h = ((h^b)*0x100000001b3)&MASK64
    return h

def records(path, limit):
    with mapped(path) as data:
        magic = data[:8]
        if magic not in [b'HBCAP001', b'HBCAP002']: raise ValueError('bad capture magic')
        textlen, = struct.unpack_from('<I', data, 8)
        offset = 12+textlen
        if offset > len(data): raise ValueError('truncated header')
        pages = {}
        index = 0
        while offset < len(data) and index < limit:
            if offset+4 > len(data): raise ValueError(f'truncated tag at {offset}')
            tag, = struct.unpack_from('<I', data, offset)
            if tag == 0x50:
                if offset+4108 > len(data): raise ValueError(f'truncated page at {offset}')
                h, = struct.unpack_from('<Q', data, offset+4)
                pages[h] = offset+12
                offset += 4108
            elif tag == 0x43:
                if offset+132 > len(data): raise ValueError(f'truncated record at {offset}')
                fields = struct.unpack_from('<16Q', data, offset+4)
                np, nq = fields[14:16]
                end = offset+132+np*16+nq*32
                if end > len(data): raise ValueError(f'truncated record at {offset}')
                pairs = dict(struct.unpack_from('<QQ', data, offset+132+i*16) for i in range(np))
                rip, start, length = fields[1], fields[5], fields[6]
                why, code = None, bytearray()
                if fields[3] & 8: why = 'capture_raced'
                elif fields[3] & 16: why = 'capture_no_ir'
                elif start != rip: why = 'noncontiguous_span'
                elif not 0 < length <= 65536: why = 'invalid_span'
                else:
                    address = rip
                    while address < rip+length:
                        page = address & ~4095
                        h = pairs.get(page, 0)
                        if not h or h not in pages:
                            why = 'missing_code_page'; break
                        n = min(4096-(address-page), rip+length-address)
                        po = pages[h]+address-page
                        code.extend(data[po:po+n]); address += n
                yield index, fields, bytes(code), why
                index += 1; offset = end
            elif magic == b'HBCAP002' and tag in [0x4b,0x49,0x51,0x52,0x47,0x58,0x42,0x46,0x4d,0x56,0x54,0x4a]:
                if offset+8 > len(data): raise ValueError(f'truncated event header at {offset}')
                words, = struct.unpack_from('<I',data,offset+4)
                end = offset+8+words*8
                if words > 1000000 or end > len(data): raise ValueError(f'truncated event at {offset}')
                offset = end
            else: raise ValueError(f'bad tag {tag:#x} at {offset}')

def instruction_block(code, rip):
    # HBCAP spans may contain multiple basic blocks and embedded data.
    # Decode only the actual dynamic path in Unicorn, never linear-scan gaps.
    first=next(DIS.disasm(code,rip,count=1),None)
    return (code,[first],None) if first else (b'',[],'decode_unsupported')

@functools.lru_cache(maxsize=32)
def initial(seed):
    regs = {name:ARENA+0x800+i*0x80+seed*16 for i,name in enumerate(NAMES)}
    regs['rsp'] = STACK+0x2000
    regs['rbp'] = STACK+0x2100
    # Mix integer and pointer-friendly seeds. Every value is recorded for reproduction.
    if seed % 2:
        regs.update(rax=seed+3, rcx=seed+1, rdx=0)
    a, state = random_bytes(seed, SIZE)
    b, state = random_bytes(state, SIZE)
    x, _ = random_bytes(state, 256)
    return {'seed':seed, 'regs':regs, 'rflags':0x202, 'mxcsr':0x1f80,
            'xmm':[x[i*16:i*16+16].hex() for i in range(16)]}, a, b

def reference(code, rip, init, data, stack):
    em = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
    base = rip & ~0x3fff
    end = (rip+len(code)+1+0x3fff)&~0x3fff
    em.mem_map(base,end-base,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    em.mem_write(rip,code)
    # Unicorn translates ahead before firing CODE hooks. A non-executed HLT
    # immediately outside the declared span terminates that translation scan.
    # Otherwise a prefix near a page end can fail its speculative fetch before
    # executing even its first instruction, falsely looking like a block exit.
    em.mem_write(rip+len(code),b'\xf4')
    for addr, blob in [(ARENA,data),(STACK,stack)]:
        em.mem_map(addr,SIZE,uc.UC_PROT_READ|uc.UC_PROT_WRITE);em.mem_write(addr,blob)
    for name, reg in zip(NAMES,REGS): em.reg_write(reg,init['regs'][name])
    em.reg_write(ux.UC_X86_REG_EFLAGS,init['rflags'])
    em.reg_write(ux.UC_X86_REG_MXCSR,init['mxcsr'])
    em.reg_write(ux.UC_X86_REG_FPCW,0x37f)
    em.reg_write(ux.UC_X86_REG_FPTAG,0xffff)
    for i,x in enumerate(init['xmm']): em.reg_write(getattr(ux,f'UC_X86_REG_XMM{i}'),int.from_bytes(bytes.fromhex(x),'little'))
    trace, writes = [], []
    state = {'status':'exit','undefined':0,'dynamic_undefined':0,'x87_undefined':0}
    def arena(addr,n): return ARENA <= addr and addr+n <= ARENA+SIZE or STACK <= addr and addr+n <= STACK+SIZE
    def on_memory(em, access, addr, size, value, user):
        if not arena(addr,size) and not (access == uc.UC_MEM_READ and rip <= addr and addr+size <= rip+len(code)):
            state['status']='memory_outside_arena';state['bad_address']=hex(addr);em.emu_stop()
        if access == uc.UC_MEM_WRITE: writes.append([hex(addr),size])
    def invalid(em, access, addr, size, value, user):
        if access in [uc.UC_MEM_FETCH_UNMAPPED,uc.UC_MEM_FETCH_PROT] and not rip <= addr < rip+len(code):
            if not rip <= em.reg_read(ux.UC_X86_REG_RIP) < rip+len(code):
                state.update(status='exit',transfer_exit=True)
            else:state.update(status='unicorn_prefetch_gap')
            em.emu_stop();return False
        state.update(status='memory_outside_arena',bad_address=hex(addr));return False
    def step(em, address, size, user):
        if not rip <= address < rip+len(code): em.emu_stop();return
        if len(trace) >= 512: state['status']='step_limit';em.emu_stop();return
        ins = next(DIS.disasm(bytes(em.mem_read(address,size)),address),None)
        if ins is None: state['status']='unicorn_decode_gap';em.emu_stop();return
        if ins.mnemonic in ['rdtsc','rdtscp','rdrand','rdseed','cpuid','syscall','sysenter']:
            state['status']='nondeterministic_or_environment';em.emu_stop();return
        trace.append((ins.address,ins.size,ins.mnemonic,ins.op_str))
        previous_undefined=state['undefined']
        if ins.mnemonic.startswith('f'):
            for name,bit in {'C0':8,'C1':9,'C2':10,'C3':14}.items():
                if ins.fpu_flags & getattr(xc,'X86_FPU_FLAGS_UNDEFINED_'+name,0):state['x87_undefined'] |= 1<<bit
                elif any(ins.fpu_flags & getattr(xc,'X86_FPU_FLAGS_'+kind+'_'+name,0) for kind in ['MODIFY','RESET','SET']):state['x87_undefined'] &= ~(1<<bit)
        for name,bit in (FLAG_BITS.items() if not ins.mnemonic.startswith('f') or ins.mnemonic in ['fcomi','fcomip','fucomi','fucomip'] else []):
            if ins.eflags & getattr(xc,'X86_EFLAGS_UNDEFINED_'+name,0): state['undefined'] |= 1<<bit
            elif any(ins.eflags & getattr(xc,'X86_EFLAGS_'+kind+'_'+name,0) for kind in ['MODIFY','RESET','SET']): state['undefined'] &= ~(1<<bit)
        if ins.mnemonic in ['mul','imul']:
            # SDM MUL/IMUL: only CF/OF defined. Capstone 5.0.7 misses SF.
            state['undefined'] |= 0xd4
            state.setdefault('capstone_flag_corrections',[]).append([hex(address),ins.mnemonic,'SF/PF/AF/ZF undefined'])
        if ins.mnemonic in ['shl','shr','sal','sar','rol','ror','rcl','rcr','shld','shrd']:
            op=ins.operands[-1]
            if op.type==xc.X86_OP_IMM:count=op.imm
            elif op.type==xc.X86_OP_REG:
                count=em.reg_read(getattr(ux,'UC_X86_REG_'+ins.reg_name(op.reg).upper()))
            else:count=1
            width=ins.operands[0].size*8
            count &= 63 if width==64 else 31
            if count==0:state['undefined']=previous_undefined
            elif ins.mnemonic in ['shl','sal','shr','sar','shld','shrd']:
                state['undefined'] |= 1<<4 # AF
                if count!=1:state['undefined'] |= 1<<11
                if ins.mnemonic in ['shl','sal','shr'] and count>=width:state['undefined'] |= 1
                if ins.mnemonic in ['shld','shrd'] and count>width:state['undefined'] |= 0x8d5
            elif count!=1:state['undefined'] |= 1<<11
            state.setdefault('dynamic_flag_rules',[]).append([hex(address),ins.mnemonic,count,width])
    em.hook_add(uc.UC_HOOK_CODE,step)
    em.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,on_memory)
    em.hook_add(uc.UC_HOOK_MEM_INVALID,invalid)
    interrupts=[]
    def interrupt(em,number,user): interrupts.append(number);state['status']='guest_exception';em.emu_stop()
    em.hook_add(uc.UC_HOOK_INTR,interrupt)
    try: em.emu_start(rip,0,count=513)
    except uc.UcError as exc:
        if state['status']=='exit' and not state.get('transfer_exit'): state['status']='unicorn_unsupported' if exc.errno == uc.UC_ERR_INSN_INVALID else 'unicorn_error'
        state['error']=str(exc)
    ranges=[]
    for address,size in sorted(set((int(a,0),n) for a,n in writes if arena(int(a,0),n))):
        if ranges and address <= ranges[-1][1]:ranges[-1][1]=max(ranges[-1][1],address+size)
        else:ranges.append([address,address+size])
    written_memory=[[hex(a),bytes(em.mem_read(a,b-a)).hex()] for a,b in ranges]
    out = {**state,'rip':em.reg_read(ux.UC_X86_REG_RIP), 'regs':dict(zip(NAMES,[em.reg_read(r) for r in REGS])),
           'rflags':em.reg_read(ux.UC_X86_REG_EFLAGS),'mxcsr':em.reg_read(ux.UC_X86_REG_MXCSR),
           'xmm':[em.reg_read(getattr(ux,f'UC_X86_REG_XMM{i}')).to_bytes(16,'little').hex() for i in range(16)],
           'data_hash':fnv(bytes(em.mem_read(ARENA,SIZE))),'stack_hash':fnv(bytes(em.mem_read(STACK,SIZE))),
           'init_data_hash':fnv(data),'init_stack_hash':fnv(stack),'trace':trace,'writes':writes,'written_memory':written_memory,'interrupts':interrupts,
           'x87_fcw':em.reg_read(ux.UC_X86_REG_FPCW),'x87_fsw':em.reg_read(ux.UC_X86_REG_FPSW),
           'x87_tag':em.reg_read(ux.UC_X86_REG_FPTAG),
           'x87_fp':[list(em.reg_read(getattr(ux,f'UC_X86_REG_FP{i}'))) for i in range(8)],'x87_status':'PRESENT'}
    return out

class Native:
    def __init__(self, log, gate=None, captured_env=None, runner=None, timeout_ms=100):
        env=os.environ.copy()
        if captured_env:env.update(captured_env)
        env.update(ORACLE_TIMEOUT_MS=str(timeout_ms),ORACLE_DATA_BASE=hex(ARENA),MACRUNNER_FEX_NULL_HOST='1')
        if gate is not None: env['MACRUNNER_FEX_DIV_OVERFLOW_DE']=str(gate)
        self.p=subprocess.Popen([str(runner or OWN/'stand_runner')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,
                                text=True,bufsize=1,env=env,start_new_session=True)
        self.sel=selectors.DefaultSelector();self.sel.register(self.p.stdout,selectors.EVENT_READ)
    def run(self, code, rip, init, identity=0, dump=False, ref=None):
        items={'id':identity,'seed':init['seed'],'code':code.hex(),'rip':hex(rip),'rflags':hex(init['rflags']),
               'mxcsr':hex(init['mxcsr']),**{k:hex(v) for k,v in init['regs'].items()},
               **{f'x{i}':x for i,x in enumerate(init['xmm'])},'dump':int(dump)}
        line=' '.join(f'{k}={v}' for k,v in items.items())
        if ref:
            line+=' '+f"expect_data={hex(ref['data_hash'])} expect_stack={hex(ref['stack_hash'])}"
            line+=''.join(f' watch={a}:{len(bytes.fromhex(h))}' for a,h in ref['written_memory'])
        self.p.stdin.write(line+'\n');self.p.stdin.flush()
        if not self.sel.select(5): raise RuntimeError('native response timeout')
        line=self.p.stdout.readline()
        if not line: raise RuntimeError(f'native exited {self.p.poll()}')
        return json.loads(line)
    def close(self):
        if self.p.poll() is None:
            self.p.stdin.close()
            try:self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Popen identity remains owned; never kill by process name.
                self.p.kill();self.p.wait()
        self.sel.close()

def differences(ref, native):
    if not native.get('state_valid'):return ['native_'+native['status']]
    classes=[]
    if any(ref[key] != int(native[key],0) for key in ['init_data_hash','init_stack_hash']):return ['stand_initial_memory_mismatch']
    if ref['status']=='guest_exception':
        if native.get('sfd',{}).get('trap') != ref['interrupts'][0]:classes.append('exception')
        return classes
    if native.get('sfd',{}).get('gen') and native['sfd'].get('trap') not in [0,14]:return ['exception']
    for field in ['rip','mxcsr','data_hash','stack_hash','init_data_hash','init_stack_hash']:
        if ref[field] != int(native[field],0):classes.append('memory' if 'hash' in field else field)
    if any(ref['regs'][k] != int(native['regs'][k],0) for k in NAMES):classes.append('gpr')
    mask=0x3f7fd7 & ~(ref['undefined']|ref['dynamic_undefined'])
    if (ref['rflags']^int(native['rflags'],0))&mask:classes.append('rflags')
    if ref['xmm'] != native['xmm']:classes.append('xmm')
    if 'written_memory' in native and ref['written_memory'] != native['written_memory']:classes.append('written_memory')
    if 'x87_fsw' in native:
        if ((ref['x87_fsw']^native['x87_fsw']) & ~ref['x87_undefined']) or ref['x87_fcw'] != int(native['fcw'],0):classes.append('x87_status')
        ftw=sum(1<<i for i in range(8) if ((ref['x87_tag']>>(2*i))&3) != 3)
        if ftw != native['x87_abridged_ftw']:classes.append('x87_tags')
        mm=bytes.fromhex(native['x87_raw'])
        for i in range(8):
            if not (ftw&native['x87_abridged_ftw']&(1<<i)):continue
            if native['x87_reduced']:
                mant,exponent=ref['x87_fp'][i]
                sign=-1.0 if exponent&0x8000 else 1.0
                try:value=sign*(mant/(1<<63))*2.0**((exponent&0x7fff)-16383)
                except OverflowError:value=sign*float('inf')
                expected=struct.pack('<d',value)
                if mm[i*16:i*16+8] != expected:classes.append('x87_reduced_precision')
            elif mm[i*16:i*16+10] != struct.pack('<QH',*ref['x87_fp'][i]):classes.append('x87_value')
    return sorted(set(classes))

def run_capture(args):
    if not pathlib.Path(args.runner).exists():raise RuntimeError('selected runner missing')
    counts=collections.Counter();classes=collections.Counter();skips=collections.Counter();start=time.monotonic()
    outpath=OWN/'out'/f'{pathlib.Path(args.capture).name}.{time.time_ns()}'
    with open_binary(args.capture) as capture:
        capture.read(8);n,=struct.unpack('<I',capture.read(4))
        captured_env=dict(line.split('=',1) for line in capture.read(n).decode().splitlines() if '=' in line)
        captured_env={k:v for k,v in captured_env.items() if k.startswith('FEX_') and v}
    log=open(str(outpath)+'.native.log','w');native=Native(log,captured_env=captured_env,runner=args.runner)
    try:
        with write_text(str(outpath)+'.jsonl') as raw:
            for index, fields, code, why in records(args.capture,args.limit):
                if index%args.jobs != args.worker:continue
                counts['records']+=1
                if why:skips[why]+=1;continue
                code,insns,why=instruction_block(code,fields[1])
                if why:skips[why]+=1;continue
                success=True;any_diff=False;observed=False
                for seed in range(args.seeds):
                    init,data,stack=initial(seed);ref=reference(code,fields[1],init,data,stack)
                    if ref['status'] not in ['exit','guest_exception']:
                        skips[ref['status']]+=1;success=False;break
                    answer=native.run(code,fields[1],init,index,ref=ref)
                    if not answer.get('state_valid'):
                        reason='native_'+answer['status']
                        if ref['status']=='guest_exception' and ref['interrupts']==[13] and (answer.get('host') or {}).get('esr')=='0x92000021':
                            reason='native_guest_GP_frontend_NOT_ENABLED'
                        skips[reason]+=1;success=False
                        raw.write(json.dumps({'record':index,'code':code.hex(),'initial':init,'reference':ref,'native':answer,'classification':'UNCLASSIFIED_native_fault'})+'\n');raw.flush()
                        native.close();native=Native(log,captured_env=captured_env,runner=args.runner);break
                    diff=differences(ref,answer)
                    injected=False
                    if args.inject and not counts['injected'] and ref['status']=='exit':
                        injected=True
                        answer['regs']['rax']=hex(int(answer['regs']['rax'],0)^1);counts['injected']+=1;diff=differences(ref,answer)
                    counts['cases']+=1
                    observed=True
                    if diff:
                        any_diff=True;classes.update(diff)
                        event={'record':index,'fields':fields,'rip':hex(fields[1]),'code':code.hex(),'initial':init,
                               'reference':ref,'native':answer,'classes':diff,'injected':injected,
                               'first_prefix':None}
                        # Scan every prefix in order: no monotonicity assumption for a binary search.
                        endmax=fields[1]
                        previous_prefix=None
                        for n,trace_ins in enumerate(ref['trace'],1):
                            endmax=max(endmax,trace_ins[0]+trace_ins[1])
                            prefix=code[:endmax-fields[1]]
                            if prefix==previous_prefix:continue
                            previous_prefix=prefix
                            rr=reference(prefix,fields[1],init,data,stack)
                            if rr['status'] not in ['exit','guest_exception']:continue
                            nn=native.run(prefix,fields[1],init,index,ref=rr)
                            if not nn.get('state_valid'):
                                event['prefix_fault']={'instructions':n,'native':nn}
                                native.close();native=Native(log,captured_env=captured_env,runner=args.runner);break
                            dd=differences(rr,nn)
                            if dd:event['first_prefix']={'instructions':n,'code':prefix.hex(),'reference':rr,'native':nn,'classes':dd,'instruction_address':hex(trace_ins[0])};break
                        if any(t[0]<ref['trace'][j-1][0] for j,t in enumerate(ref['trace']) if j):event['prefix_limits']='Backedges: prefix address-envelope may include later dynamic instructions; first dynamic instruction NOT_PROVEN'
                        raw.write(json.dumps(event)+'\n');raw.flush()
                    elif args.save_all:
                        raw.write(json.dumps({'record':index,'fields':fields,'rip':hex(fields[1]),
                            'code':code.hex(),'initial':init,'reference':ref,'native':answer,
                            'classes':[],'injected':False})+'\n')
                # A mismatch from an earlier seed must survive a later arena skip.
                if any_diff:counts['mismatch_blocks']+=1
                if success:
                    counts['checked_blocks']+=1
                    counts['fully_mismatched_blocks' if any_diff else 'matched_blocks']+=1
                elif observed:counts['partial_checked_blocks']+=1
                if index and index%1000==0:print(json.dumps({'progress':index,'elapsed_s':time.monotonic()-start}),file=sys.stderr)
    finally:native.close();log.close()
    summary={'capture':str(pathlib.Path(args.capture).resolve()),'backend':args.backend,'runner':str(pathlib.Path(args.runner).resolve()),
             'counts':dict(counts),'mismatch_classes':dict(classes),'skips':dict(skips),
             'elapsed_s':time.monotonic()-start,'raw':str(outpath)+'.jsonl',
            'effective_config':captured_env,
             'worker':args.worker,'saved_all_states':args.save_all,
            'coverage':{'x87':'PRESENT_initial_empty; reduced_precision_separate','dynamic_shift_flags':'COUNT_RULES_plus_Capstone','seeds':args.seeds,'jobs':args.jobs,
                         'original_multiblock_shape':'ORIGINAL_CAPTURE_SPAN_at_original_RIP; exact_native_codegen_shape_NOT_VERIFIED'}}
    pathlib.Path(str(outpath)+'.summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary));return 1 if counts['mismatch_blocks'] or any(n for k,n in skips.items() if k.startswith('native_')) else 0

def main():
    p=argparse.ArgumentParser();p.add_argument('capture');p.add_argument('--limit',type=int,default=2**63-1)
    p.add_argument('--runner',default=str(OWN/'stand_runner'));p.add_argument('--backend',default='native_arm64_NOT_PRODUCT_ARM64EC')
    p.add_argument('--seeds',type=int,default=3);p.add_argument('--inject',action='store_true')
    p.add_argument('--save-all',action='store_true',help='Preserve every executed final state for paired native/EC comparison')
    p.add_argument('-j','--jobs',type=int,default=2);p.add_argument('--worker',type=int,default=-1);args=p.parse_args()
    if not 1 <= args.seeds <= 32:p.error('seeds must be 1..32')
    if args.jobs not in [1,2]:p.error('jobs must be 1 or 2')
    if args.worker < 0:
        workers=[]
        for worker in range(args.jobs):
            cmd=[sys.executable,str(OWN/'span_diff.py'),args.capture,'--limit',str(args.limit),'--seeds',str(args.seeds),'-j',str(args.jobs),'--worker',str(worker),'--runner',args.runner,'--backend',args.backend]
            if args.inject and worker==0:cmd+=['--inject']
            if args.save_all:cmd+=['--save-all']
            workers.append(subprocess.Popen(['nice','-n','20',*cmd],stdout=subprocess.PIPE,text=True))
        summaries=[];exitcode=0
        for worker in workers:
            output,_=worker.communicate();exitcode=max(exitcode,worker.returncode)
            if worker.returncode not in [0,1]:raise RuntimeError('worker failed; partial receipts preserved')
            summaries.append(json.loads(output))
        counts=collections.Counter();classes=collections.Counter();skips=collections.Counter()
        for s in summaries:counts.update(s['counts']);classes.update(s['mismatch_classes']);skips.update(s['skips'])
        result={'capture':summaries[0]['capture'],'counts':dict(counts),'mismatch_classes':dict(classes),
                'skips':dict(skips),'elapsed_s':max(s['elapsed_s'] for s in summaries),'workers':summaries,
                'status':'DIAGNOSTIC_ONLY_INCOMPLETE_COVERAGE'}
        path=OWN/'out'/f'aggregate.{pathlib.Path(args.capture).name}.{time.time_ns()}.json'
        path.write_text(json.dumps(result,indent=2)+'\n');result['report']=str(path)
        print(json.dumps(result));return exitcode
    return run_capture(args)

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print('STAND_FAILED:',str(exc),file=sys.stderr);sys.exit(2)
