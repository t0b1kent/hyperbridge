#!/usr/bin/env python3
"""Wine-free FEX32 / Unicorn32 replay. No missing input is counted as equal."""
import argparse, collections, copy, datetime, gzip, hashlib, json, os, pathlib, shutil, struct, subprocess, time
import capstone as cs
from capstone import x86_const as C
import unicorn as uc
from unicorn import x86_const as X
import memory_store
import evidence_io
from x87_instructions import is_x87,memory_operand_size
from adjudicate import classify as adjudicate_case

OWN=pathlib.Path(__file__).resolve().parent
ROOT=OWN.parents[1]
GPRS=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi')
SEGMENTS=('cs','ss','ds','es','fs','gs')
FLAG_BITS={'CF':0,'PF':2,'AF':4,'ZF':6,'SF':7,'TF':8,'IF':9,'DF':10,'OF':11,'NT':14,'RF':16,'AC':18}
MASK=0x003f7fd7
DIS=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);DIS.detail=True

def number(x): return int(x,0) if isinstance(x,str) else int(x)
def sha(path): return evidence_io.sha(path)
def random_memory(seed):
    out=bytearray();mask=(1<<64)-1
    for _ in range(0x8000//8):
        seed=(seed+0x9e3779b97f4a7c15)&mask;z=seed
        z=((z^(z>>30))*0xbf58476d1ce4e5b9)&mask;z=((z^(z>>27))*0x94d049bb133111eb)&mask
        out+=(z^(z>>31)).to_bytes(8,'little')
    return out

def full_ftw(raw,abridged):
    """Intel extended tag classification; raw is the eight physical 16-byte slots."""
    tag=0
    for i in range(8):
        mant,exp=struct.unpack_from('<QH',raw,i*16);exp &= 0x7fff
        t=3 if not abridged&(1<<i) else 1 if exp==0 and mant==0 else 0 if 0<exp<0x7fff and mant>>63 else 2
        tag |= t<<(2*i)
    return tag

def default_state():
    return dict(rip=0x10000000,rflags=0x202,mxcsr=0x1f80,fcw=0x37f,fsw=0,ftw=0,
                mm='00'*128,xmm=['00'*16]*8,selectors=[8,16,16,16,24,32],bases=[0]*6,
                regs=dict(zip(GPRS,[0x87654321,4,0x12345678,0x20000100,0x21001000,0x21001100,0x20000200,0x20000300])))

def descriptor(base,code=False,dpl=0):
    limit=0xfffff
    return struct.pack('<HHBBBB',limit&0xffff,base&0xffff,(base>>16)&255,(0x9b if code else 0x93)|((dpl&3)<<5),0xc0|(limit>>16),(base>>24)&255)

def effective_descriptors(state):
    if state.get('segment_model')=='WINE_WOW64_FLAT':
        # WOW64/Module.cpp fills base and CS.D in FEX's internal table, but
        # leaves hardware P/S/type/DPL fields absent. Both replay backends
        # receive the same explicit flat Windows protected-mode descriptors.
        if state['selectors'] != [0x23,0x2b,0x2b,0x2b,0x53,0x2b] or any(state['bases'][i] for i in [0,1,2,3,5]):
            raise ValueError('unknown WOW64 segment layout; cannot reconstruct')
        return b''.join(descriptor(base,i==0,selector&3) for i,(base,selector) in enumerate(zip(state['bases'],state['selectors'])))
    return bytes.fromhex(state['descriptors']) if state.get('descriptors') else b''.join(descriptor(b,i==0) for i,b in enumerate(state['bases']))

def page_image(case):
    pages={}
    if case.get('pages'):
        pages=dict(memory_store.read_pages(case['pages']))
    else:
        raw=random_memory(case.get('seed',1));pages={0x20000000:bytes(raw[:16384]),0x21000000:bytes(raw[16384:])}
    for a,hx in case.get('patches',[]):
        a=number(a);base=a&~16383;b=bytearray(pages[base]);v=bytes.fromhex(hx)
        if a+len(v)>base+16384:raise ValueError('patch crosses input page')
        b[a-base:a-base+len(v)]=v;pages[base]=bytes(b)
    return pages

def oracle(case, *, omit_x87_sites=(), sparse=False):
    # Offline counterfactual only: suppress selected x87 instructions at their
    # original PCs without modifying captured code/data or normal replay.
    omit_x87_sites=frozenset(omit_x87_sites)
    state=case['state'];code=bytes.fromhex(case['code']);rip=state['rip']
    em=uc.Uc(uc.UC_ARCH_X86,uc.UC_MODE_32);mapped=set()
    image_index=memory_store.index_path(case['pages']) if sparse and case.get('pages') else None
    image_hashes=dict(memory_store.read_index(case['pages'])['pages']) if image_index and memory_store.has_index(case['pages']) else None
    pages={} if image_hashes is not None else page_image(case)
    def lazy_page(a):
        if a in mapped:return True
        if image_hashes is None or a not in image_hashes:return False
        data=memory_store.read_object(image_hashes[a]);pages[a]=data
        em.mem_map(a,16384);em.mem_write(a,data);mapped.add(a)
        return True
    regions=[]
    for a,b in sorted(pages.items()):
        if regions and regions[-1][0]+16384*len(regions[-1][1])==a:regions[-1][1].append(b)
        else:regions.append((a,[b]))
        mapped.add(a)
    for a,parts in regions:
        em.mem_map(a,16384*len(parts));em.mem_write(a,b''.join(parts))
    for a in range(rip&~16383,(rip+len(code)+16384)&~16383,16384):
        if a not in mapped and not lazy_page(a):em.mem_map(a,16384);mapped.add(a)
    em.mem_write(rip,code+b'\xf4')
    # Segment bases in 32-bit Unicorn must be installed through descriptors.
    gdt=0x30000000
    while any(a in (image_hashes if image_hashes is not None else mapped) for a in range(gdt,gdt+0x20000,16384)):gdt+=0x20000
    em.mem_map(gdt,0x10000);em.mem_map(gdt+0x10000,0x10000)
    em.reg_write(X.UC_X86_REG_GDTR,(0,gdt,0xffff,0))
    if any(s&4 for s in state['selectors']):raise ValueError('Unicorn LDT input not yet implemented')
    descriptors=effective_descriptors(state)
    for i,(name,selector) in enumerate(zip(SEGMENTS,state['selectors'])):
        em.mem_write(gdt+(selector>>3)*8,descriptors[i*8:i*8+8])
    if state.get('segment_model')=='WINE_WOW64_FLAT':
        # Unicorn's CS register write does not update its hidden CPL. Enter
        # ring3 architecturally through a private IRETD before restoring GPRs.
        em.mem_write(gdt+8,descriptor(0,True));em.mem_write(gdt+16,descriptor(0))
        em.reg_write(X.UC_X86_REG_CS,8);em.reg_write(X.UC_X86_REG_SS,16)
        boot=gdt+0x10000;stack=gdt+0x18000
        em.mem_write(boot,b'\xcf')
        em.mem_write(stack,struct.pack('<5I',rip,state['selectors'][0],state['rflags'],state['regs']['rsp'],state['selectors'][1]))
        em.reg_write(X.UC_X86_REG_ESP,stack);em.reg_write(X.UC_X86_REG_EFLAGS,2)
        # Do not set `until=rip`: Unicorn may retain an exit TB at that address
        # across the next emu_start and return without executing the guest.
        em.emu_start(boot,0,count=1)
        if em.reg_read(X.UC_X86_REG_CS)!=state['selectors'][0] or em.reg_read(X.UC_X86_REG_SS)!=state['selectors'][1]:
            raise ValueError('Unicorn ring3 bootstrap failed')
        segment_inputs=list(zip(SEGMENTS,state['selectors']))[2:]
    else:segment_inputs=list(zip(SEGMENTS,state['selectors']))
    for name,selector in segment_inputs:em.reg_write(getattr(X,'UC_X86_REG_'+name.upper()),selector)
    for name,value in state['regs'].items():em.reg_write(getattr(X,'UC_X86_REG_E'+name[1:].upper()),value&0xffffffff)
    em.reg_write(X.UC_X86_REG_EFLAGS,state['rflags']);em.reg_write(X.UC_X86_REG_MXCSR,state['mxcsr'])
    em.reg_write(X.UC_X86_REG_FPCW,state['fcw']);em.reg_write(X.UC_X86_REG_FPSW,state['fsw'])
    raw=bytes.fromhex(state['mm'])
    for i in range(8):em.reg_write(getattr(X,f'UC_X86_REG_FP{i}'),struct.unpack_from('<QH',raw,i*16))
    em.reg_write(X.UC_X86_REG_FPTAG,full_ftw(raw,state['ftw']))
    for i,v in enumerate(state['xmm'][:8]):em.reg_write(getattr(X,f'UC_X86_REG_XMM{i}'),int.from_bytes(bytes.fromhex(v),'little'))
    result=dict(status='exit',undefined_flags=0,trace=[],writes=[],interrupts=[],x87_events=[],hook_steps=0,
                segment_model=state.get('segment_model','EXPLICIT'),effective_descriptors=descriptors.hex())
    valid4k=set(case['valid_pages4k']) if case.get('valid_pages4k') is not None else None
    writable4k=set(case['writable_pages4k']) if case.get('writable_pages4k') is not None else None
    if 'valid_ranges4k' in case:valid4k={a for lo,hi in case['valid_ranges4k'] for a in range(lo,hi,4096)}
    if 'writable_ranges4k' in case:writable4k={a for lo,hi in case['writable_ranges4k'] for a in range(lo,hi,4096)}
    def present(addr,size):
        return valid4k is None or (addr+size<=1<<32 and all(a in valid4k for a in range(addr&~4095,((addr+size-1)&~4095)+4096,4096)))
    def finish_x87(em):
        if not result['x87_events'] or 'after' in result['x87_events'][-1]:return
        ev=result['x87_events'][-1]
        after=dict(fsw=em.reg_read(X.UC_X86_REG_FPSW),ftw=em.reg_read(X.UC_X86_REG_FPTAG),fcw=em.reg_read(X.UC_X86_REG_FPCW),
            rflags=em.reg_read(X.UC_X86_REG_EFLAGS),regs={k:em.reg_read(getattr(X,'UC_X86_REG_E'+k[1:].upper())) for k in GPRS},
            fp80=[struct.pack('<QH',*em.reg_read(getattr(X,f'UC_X86_REG_FP{i}'))).hex() for i in range(8)],memory=[])
        for entry in ev['memory']:
            item={k:entry[k] for k in ['address','size']}
            try:item['bytes']=bytes(em.mem_read(item['address'],item['size'])).hex()
            except uc.UcError:item['status']='NOT_PRESENT'
            after['memory'].append(item)
        ev['after']=after
    def step(em,addr,size,_):
        result['hook_steps']+=1
        finish_x87(em)
        if not rip<=addr<rip+len(code):em.emu_stop();return
        if result['hook_steps']>1000000:result['status']='STEP_LIMIT';em.emu_stop();return
        if not present(addr,size):result.update(status='MEMORY_NOT_PRESENT',bad_address=hex(addr),access='fetch');em.emu_stop();return
        ins=next(DIS.disasm(bytes(em.mem_read(addr,size)),addr),None)
        if ins is None:result['status']='REFERENCE_DECODE_GAP';em.emu_stop();return
        if ins.mnemonic in ['rdtsc','rdtscp','rdrand','rdseed','cpuid','syscall','sysenter','int']:
            result['status']='ENVIRONMENT_NOT_REPLAYABLE';em.emu_stop();return
        if ins.mnemonic.startswith(('rep ','repe ','repne ')) and result['trace'] and result['trace'][-1][0]==addr:return
        if len(result['trace'])<4096:result['trace'].append([addr,size,ins.mnemonic,ins.op_str])
        else:result['trace_dropped']=result.get('trace_dropped',0)+1
        # Keep explicit visibility witnesses even beyond the bounded trace.
        if ins.mnemonic in ['fnsave','fsave','fxsave','fxsave64'] or C.X86_GRP_MMX in ins.groups:
            result['raw80_observer_count']=result.get('raw80_observer_count',0)+1
            observers=result.setdefault('raw80_observers',[])
            if len(observers)<64:observers.append([addr,ins.mnemonic])
            else:result['raw80_observers_dropped']=result.get('raw80_observers_dropped',0)+1
        if addr in omit_x87_sites:
            if not is_x87(ins):raise ValueError('omission PC is not x87')
            omitted=result.setdefault('omitted_x87',{})
            omitted[hex(addr)]=omitted.get(hex(addr),0)+1
            em.reg_write(X.UC_X86_REG_EIP,(addr+size)&0xffffffff)
            return
        if is_x87(ins) and len(result['x87_events'])>=16384:
            result['x87_events_dropped']=result.get('x87_events_dropped',0)+1
        elif is_x87(ins):
            event=dict(address=addr,code=bytes(ins.bytes).hex(),mnemonic=ins.mnemonic,operands=ins.op_str,
                fcw=em.reg_read(X.UC_X86_REG_FPCW),fsw=em.reg_read(X.UC_X86_REG_FPSW),ftw=em.reg_read(X.UC_X86_REG_FPTAG),
                rflags=em.reg_read(X.UC_X86_REG_EFLAGS),regs={k:em.reg_read(getattr(X,'UC_X86_REG_E'+k[1:].upper())) for k in GPRS},
                fpcr=state.get('fpcr'),fp80=[struct.pack('<QH',*em.reg_read(getattr(X,f'UC_X86_REG_FP{i}'))).hex() for i in range(8)],memory=[])
            for op in ins.operands:
                if op.type!=C.X86_OP_MEM:continue
                def rv(reg):return em.reg_read(getattr(X,'UC_X86_REG_'+ins.reg_name(reg).upper())) if reg else 0
                segment=ins.reg_name(op.mem.segment) if op.mem.segment else ('ss' if ins.reg_name(op.mem.base) in ['ebp','esp'] else 'ds')
                base=state['bases'][SEGMENTS.index(segment)]
                ea=base+((rv(op.mem.base)+rv(op.mem.index)*op.mem.scale+op.mem.disp)&0xffffffff)
                memory_size=memory_operand_size(ins,op.size)
                entry=dict(address=ea,size=memory_size)
                try:
                    if not present(ea,memory_size):raise ValueError('memory not present')
                    if image_hashes is not None:
                        for page in range(ea&~16383,((ea+memory_size-1)&~16383)+16384,16384):lazy_page(page)
                    entry['bytes']=bytes(em.mem_read(ea,memory_size)).hex()
                except (ValueError,uc.UcError):entry['status']='NOT_PRESENT'
                event['memory'].append(entry)
            result['x87_events'].append(event)
        prev=result['undefined_flags']
        # Capstone shares eflags/fpu_flags storage; x87 condition-code bits must not mask EFLAGS.
        if not ins.mnemonic.startswith('f') or ins.mnemonic in ['fcomi','fcomip','fucomi','fucomip']:
            for name,bit in FLAG_BITS.items():
                if ins.eflags&getattr(C,'X86_EFLAGS_UNDEFINED_'+name,0):result['undefined_flags'] |= 1<<bit
                elif any(ins.eflags&getattr(C,'X86_EFLAGS_'+kind+'_'+name,0) for kind in ['MODIFY','SET','RESET']):result['undefined_flags'] &= ~(1<<bit)
        # Capstone 5.0.7 omits ALL EFLAGS metadata for TEST r/m8,r8 and
        # TEST r/m16/32,r16/32 with a memory destination (84/85). Apply the
        # architectural TEST-family rule to every form: AF undefined, while
        # CF/PF/ZF/SF/OF are defined. Do not hide defined-bit differences.
        if ins.mnemonic == 'test':
            result['undefined_flags'] = (result['undefined_flags'] & ~0x8c5) | 0x10
        if ins.mnemonic in ['mul','imul']:result['undefined_flags'] |= 0xd4
        if ins.mnemonic in ['shl','shr','sal','sar','rol','ror','rcl','rcr','shld','shrd']:
            op=ins.operands[-1];n=op.imm if op.type==C.X86_OP_IMM else em.reg_read(getattr(X,'UC_X86_REG_'+ins.reg_name(op.reg).upper())) if op.type==C.X86_OP_REG else 1
            width=ins.operands[0].size*8;n &= 31
            if ins.mnemonic in ['rol','ror']:n%=width
            if ins.mnemonic in ['rcl','rcr'] and width<32:n%=width+1
            if n==0:result['undefined_flags']=prev
            elif ins.mnemonic in ['shl','sal','shr','sar','shld','shrd']:
                result['undefined_flags'] |= 16
                if n!=1:result['undefined_flags'] |= 1<<11
                if ins.mnemonic in ['shl','sal','shr'] and n>=width:result['undefined_flags'] |= 1
                if ins.mnemonic in ['shld','shrd'] and n>width:result['undefined_flags'] |= 0x8d5
            elif n!=1:result['undefined_flags'] |= 1<<11
    def invalid(em,access,addr,size,value,_):
        if sparse and access in (uc.UC_MEM_READ_UNMAPPED,uc.UC_MEM_WRITE_UNMAPPED,uc.UC_MEM_FETCH_UNMAPPED) and present(addr,size):
            if all(lazy_page(a) for a in range(addr&~16383,((addr+size-1)&~16383)+16384,16384)):return True
        result.update(status='MEMORY_NOT_PRESENT',bad_address=hex(addr),access=access);return False
    def access_check(em,access,addr,size,value,_):
        if not present(addr,size):result.update(status='MEMORY_NOT_PRESENT',bad_address=hex(addr),access=access);em.emu_stop()
    def write(em,access,addr,size,value,_):
        access_check(em,access,addr,size,value,_)
        if writable4k is not None and any(a not in writable4k for a in range(addr&~4095,((addr+size-1)&~4095)+4096,4096)):
            result.update(status='MEMORY_PROTECTION',bad_address=hex(addr),access=access);em.emu_stop()
        if len(result['writes'])<4096:result['writes'].append([addr,size])
        else:result['write_trace_dropped']=result.get('write_trace_dropped',0)+1
    def interrupt(em,n,_):result['interrupts'].append(n);result['status']='GUEST_EXCEPTION';em.emu_stop()
    em.hook_add(uc.UC_HOOK_CODE,step);em.hook_add(uc.UC_HOOK_MEM_INVALID,invalid)
    em.hook_add(uc.UC_HOOK_MEM_WRITE,write);em.hook_add(uc.UC_HOOK_INTR,interrupt)
    if valid4k is not None:em.hook_add(uc.UC_HOOK_MEM_READ,access_check)
    # IRETD may translate the target before guest trace hooks are installed.
    # Discard that TB so tracing/boundary hooks are present on real execution.
    if state.get('segment_model')=='WINE_WOW64_FLAT':em.ctl_flush_tb()
    try:em.emu_start(rip,0,count=1000001)
    except uc.UcError as exc:
        if result['status']=='exit':result['status']='REFERENCE_INSN_GAP' if exc.errno==uc.UC_ERR_INSN_INVALID else 'REFERENCE_ERROR'
        result['error']=str(exc)
    if result['status']=='exit' and not result['trace']:result['status']='REFERENCE_EXECUTION_EMPTY'
    if result['status']=='exit' and rip<=em.reg_read(X.UC_X86_REG_EIP)<rip+len(code):
        result['status']='REFERENCE_BUDGET_EXHAUSTED'
    if result['status']=='exit':finish_x87(em)
    selectors=[em.reg_read(getattr(X,'UC_X86_REG_'+name.upper())) for name in SEGMENTS]
    bases=[]
    for selector in selectors:
        if selector&4:raise ValueError('after-state LDT selector unsupported')
        d=bytes(em.mem_read(gdt+(selector>>3)*8,8));bases.append(d[2]|(d[3]<<8)|(d[4]<<16)|(d[7]<<24))
    result.update(segments={'selectors':selectors,'bases':bases},rip=em.reg_read(X.UC_X86_REG_EIP),regs={k:em.reg_read(getattr(X,'UC_X86_REG_E'+k[1:].upper())) for k in GPRS},
        rflags=em.reg_read(X.UC_X86_REG_EFLAGS),mxcsr=em.reg_read(X.UC_X86_REG_MXCSR),fcw=em.reg_read(X.UC_X86_REG_FPCW),
        fsw=em.reg_read(X.UC_X86_REG_FPSW),ftw=em.reg_read(X.UC_X86_REG_FPTAG),
        fp80=[struct.pack('<QH',*em.reg_read(getattr(X,f'UC_X86_REG_FP{i}'))).hex() for i in range(8)],
        xmm=[em.reg_read(getattr(X,f'UC_X86_REG_XMM{i}')).to_bytes(16,'little').hex() for i in range(8)],
        memory={hex(a):bytes(em.mem_read(a,16384)).hex() for a in pages} if not case.get('pages') else {},
        memory_sha256={hex(a):hashlib.sha256(bytes(em.mem_read(a,16384))).hexdigest() for a in pages})
    if image_hashes is not None:
        result['sparse_input_pages']=[[a,image_hashes[a]] for a in sorted(pages)]
        result['image_pages_total']=len(image_hashes)
    result['execution_limit']={'kind':'guest_instruction_count','maximum':1000000}
    return result

def native_line(case,pages_override=None):
    s=case['state'];parts=[f'id={case["id"]}',f'seed={case.get("seed",1)}',f'code={case["code"]}f4',f'xlen={len(bytes.fromhex(case["code"]))}','dump=0' if case.get('pages') else 'dump=1']
    for k in ['rip','rflags','mxcsr','fcw','fsw','ftw']:parts.append(f'{k}={s[k]:#x}')
    parts += [f'{k}={v:#x}' for k,v in s['regs'].items()]
    parts += [f'{k}={v:#x}' for k,v in zip(SEGMENTS,s['selectors'])]
    parts += [f'{k}base={v:#x}' for k,v in zip(SEGMENTS,s['bases'])]
    parts += [f'x{i}={v}' for i,v in enumerate(s['xmm'][:8])]+['mm='+s['mm']]
    if s.get('descriptors') or s.get('segment_model'):parts+=['segdesc='+effective_descriptors(s).hex()]
    if case.get('pages'):parts+=['pages='+str(pages_override or case['pages'])]
    parts += [f'mem={number(a):#x}:{b}' for a,b in case.get('patches',[])]
    return ' '.join(parts)+'\n'

def compare(ref,got,rc):
    diff={}
    if rc or got.get('status') not in ['exit','EXIT_SPAN'] or not got.get('state_valid'):return {'execution':dict(rc=rc,status=got.get('status'))}
    if got.get('segments')!=ref.get('segments'):diff['segments']=[ref.get('segments'),got.get('segments')]
    for k in GPRS:
        a=number(got['regs'][k])&0xffffffff
        if a!=ref['regs'][k]:diff[k]=[ref['regs'][k],a]
    for k in ['rip','mxcsr','fcw']:
        a=number(got[k])
        if a!=ref[k]:diff[k]=[ref[k],a]
    mask=MASK&~ref['undefined_flags']
    if (number(got['rflags'])^ref['rflags'])&mask:diff['rflags']=[ref['rflags'],number(got['rflags']),mask]
    raw=bytes.fromhex(got['x87_raw'])
    ftw=full_ftw(raw,got['x87_abridged_ftw'])
    for k,a in [('fsw',got['x87_fsw']),('ftw',ftw)]:
        if a!=ref[k]:diff[k]=[ref[k],a]
    if got['x87_reduced']:diff['x87_reduced']=[False,True]
    # Compare physical registers even when empty; keep those differences explicit.
    for i in range(8):
        a=raw[i*16:i*16+10].hex()
        if a!=ref['fp80'][i]:diff[f'fp80_{i}']=[ref['fp80'][i],a]
        if got['xmm'][i]!=ref['xmm'][i]:diff[f'xmm{i}']=[ref['xmm'][i],got['xmm'][i]]
    for addr,k in [(0x20000000,'data'),(0x21000000,'stack')]:
        expected=ref['memory'].get(hex(addr))
        if expected is not None and got.get(k)!=expected:diff[k]=dict(expected_sha256=hashlib.sha256(bytes.fromhex(expected)).hexdigest(),actual_sha256=hashlib.sha256(bytes.fromhex(got.get(k,''))).hexdigest())
    for a,digest in got.get('memory_page_sha256',[]):
        expected=ref['memory'].get(hex(number(a)))
        expected_hash=ref.get('memory_sha256',{}).get(hex(number(a)))
        if expected_hash is None and expected is not None:expected_hash=hashlib.sha256(bytes.fromhex(expected)).hexdigest()
        if expected_hash is None:diff['unexpected_page_'+a]=digest
        elif expected_hash!=digest:diff['memory_page_'+a]={'expected':expected_hash,'actual':digest}
    if got.get('memory_page_sha256'):
        emitted={hex(number(a)) for a,_ in got['memory_page_sha256']}
        for a in ref.get('memory_sha256',{}):
            if a not in emitted:diff['missing_page_'+a]=ref['memory_sha256'][a]
    return diff

def native_classification(diff, got, rc, stderr):
    if got.get('status') in {'host_address_unavailable', 'host_code_collision', 'host_fixture_collision', 'guest_image_mapping_FAILED'}:
        return 'HOST_MAPPING_FAILED'
    if not got and rc == 2 and stderr.startswith('fex-oracle: mmap '):
        return 'HOST_MAPPING_FAILED'
    return 'NEW' if diff else 'EQUAL'

def directed():
    specs=[('mov_imm','b878563412'),('load32','8b03'),('movsx8','0fbe03'),('store32','8903'),('add_mem','0103'),
           ('x87_fld1','d9e8'),('x87_fadd','d9e8d9e8dec1'),('x87_fxch','d9e8d9eed9c9'),('x87_round','d9fc'),
           ('x87_store','db3b'),('fs_load','648b0300'),('push_pop','5059')]
    out=[]
    for i,(name,hx) in enumerate(specs,1):
        state=default_state()
        if name=='fs_load':hx='648b03';state['bases'][4]=0x20000000;state['regs']['rbx']=0x100
        if name in ['x87_round','x87_store']:
            mm=bytearray(128);mm[:10]=struct.pack('<QH',0xc000000000000000,0x3fff)
            state.update(mm=mm.hex(),ftw=1,fcw=0x77f)
        out.append(dict(id=i,name=name,code=hx,state=state,origin='SYNTHETIC',seed=i))
    return out

def run(args):
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    cases=evidence_io.read_json(args.cases) if args.cases else directed()
    if isinstance(cases,dict):cases=cases['cases'] if 'cases' in cases else [cases]
    if args.case_id is not None:cases=[c for c in cases if str(c['id'])==args.case_id]
    results=[];start=time.monotonic()
    for case in cases:
        if time.monotonic()-start>args.budget:break
        prefix=out/f'{case["id"]:06d}'
        evidence_io.write_json(prefix.with_suffix('.case.json'),case,indent=2)
        try:ref=oracle(case)
        except Exception as e:ref=dict(status='REFERENCE_SETUP_FAILED',error=repr(e))
        evidence_io.write_json(prefix.with_suffix('.reference.json'),ref)
        if ref['status']!='exit':
            row=dict(id=case['id'],name=case['name'],classification=ref['status'],proof='reference execution trace',diff={})
            classification,family,verdict,witness=adjudicate_case(case,ref,{},row)
            row.update(raw_classification=ref['status'],classification=classification,family=family,verdict=verdict,witness=witness)
            results.append(row);continue
        if args.oracle_only:
            results.append(dict(id=case['id'],name=case['name'],origin=case['origin'],classification='REFERENCE_EXIT',diff={},
                                proof='Unicorn32 base0 only; no native base0 execution claimed'));continue
        # The permanent corpus stays compressed; only one process-local input is expanded.
        expanded=None
        if case.get('pages','').endswith('.gz'):
            expanded=prefix.with_suffix('.temporary.pages')
            memory_store.expand(case['pages'],expanded)
        line=native_line(case,expanded);prefix.with_suffix('.input').write_text(line)
        env=dict(os.environ,STAND32_GUEST_BASE=args.base,STAND32_MUTATION=args.mutation,FEX_MULTIBLOCK='0',FEX_TSOENABLED='0',FEX_MAXINST='256',FEX_X87REDUCEDPRECISION='0',ORACLE_TIMEOUT_MS='2000',ORACLE_NO_FENCE='1')
        try:
            with prefix.with_suffix('.stdout').open('wb') as stdout,prefix.with_suffix('.stderr').open('wb') as stderr:
                p=subprocess.run(['perl','-e','alarm 8; exec @ARGV',str(args.runner.resolve())],input=line.encode(),env=env,stdout=stdout,stderr=stderr)
        finally:
            if expanded:expanded.unlink(missing_ok=True)
        raw=prefix.with_suffix('.stdout').read_text();rows=[json.loads(x) for x in raw.splitlines() if x.startswith('{')];got=rows[-1] if rows else {}
        if prefix.with_suffix('.stdout').stat().st_size>=32768:
            evidence_io.pack_existing(prefix.with_suffix('.stdout'))
        diff=compare(ref,got,p.returncode)
        # The standalone runner rejects an unavailable host mapping before
        # entering FEX. Preserve the raw error; do not call this an opcode bug.
        classification=native_classification(diff,got,p.returncode,prefix.with_suffix('.stderr').read_text())
        result=dict(id=case['id'],name=case['name'],origin=case['origin'],classification=classification,diff=diff,
            reproduction=f'python3 {OWN}/stand32.py --runner {args.runner.resolve()} --cases {prefix.with_suffix(".case-list.json")} --base {args.base} --out {OWN}/out/repro-{case["id"]}-{time.time_ns()}')
        classified,family,verdict,witness=adjudicate_case(case,ref,got,result)
        result.update(raw_classification=classification,classification=classified,family=family,verdict=verdict,witness=witness)
        evidence_io.write_json(prefix.with_suffix('.case-list.json'),[case]);results.append(result)
    result=dict(status='DIAGNOSTIC_ONLY_NOT_GOLDEN',base=args.base,execution_backend='Unicorn32_reference_only' if args.oracle_only else ('FEXCore32_base0_vs_Unicorn32' if args.base=='0' else 'FEXCore32_shifted_vs_Unicorn32'),runner=str(args.runner.resolve()),runner_sha256=sha(args.runner),
                versions=dict(unicorn=uc.__version__,capstone=cs.__version__),seconds=time.monotonic()-start,planned=len(cases),executed=len(results),
                counts=dict(collections.Counter(r['classification'] for r in results)),results=results)
    (out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ['results','runner']}))
    return 0 if len(results)==len(cases) and all(r['classification']==('REFERENCE_EXIT' if args.oracle_only else 'EQUAL') for r in results) else 1

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runner',type=pathlib.Path,required=True)
    p.add_argument('--oracle-only',action='store_true',help='Base0 Unicorn32 anchor; never claims native execution/equality')
    p.add_argument('--base',choices=['0','0x80000000000'],default='0x80000000000')
    p.add_argument('--cases',type=pathlib.Path);p.add_argument('--case-id');p.add_argument('--out',type=pathlib.Path,required=True)
    p.add_argument('--budget',type=float,default=150)
    p.add_argument('--mutation',choices=['','base','sign','carry4g','x87_rounding','x87_stack_order'],default='')
    return run(p.parse_args())
if __name__=='__main__':raise SystemExit(main())
