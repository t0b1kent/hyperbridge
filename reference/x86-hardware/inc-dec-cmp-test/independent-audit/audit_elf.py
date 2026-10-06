#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent stdlib ELF parser: verify all literal immediate stubs and dispatch tables."""
import hashlib,json,pathlib,struct,sys
p=pathlib.Path(sys.argv[1]);data=p.read_bytes();assert data[:6]==b'\x7fELF\x02\x01'
h=struct.unpack_from('<HHIQQQIHHHHHH',data,16)
assert h[1]==62,('not EM_X86_64',h[1])
shoff=h[5];shentsize=h[10];shnum=h[11]
sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*shentsize) for i in range(shnum)]
def section_bytes(s):return data[s[4]:s[4]+s[5]]
symsec=next(s for s in sections if s[1]==2);names=section_bytes(sections[symsec[6]])
symbols={}
for offset in range(symsec[4],symsec[4]+symsec[5],symsec[9]):
    n,info,other,idx,addr,size=struct.unpack_from('<IBBHQQ',data,offset)
    name=names[n:names.index(b'\0',n)].decode()
    symbols[name]=(addr,size,idx)
def body(name):
    addr,size,idx=symbols[name];s=sections[idx];off=s[4]+addr-s[3]
    return data[off:off+size]
def jmp_target(raw,addr):
    if raw[0]==0xe9 and len(raw)==5:return addr+5+struct.unpack('<i',raw[1:])[0]
    if raw[0]==0xeb and len(raw)==2:return addr+2+struct.unpack('<b',raw[1:])[0]
    raise AssertionError(('unexpected jump',raw.hex()))
variants=[('cmp_m8_i8',256,bytes.fromhex('803f'),1),('test_m8_i8',256,bytes.fromhex('f607'),1),('cmp_m16_i8',256,bytes.fromhex('66833f'),1),('cmp_m16_i16',65536,bytes.fromhex('66813f'),2),('cmp_m32_i8',256,bytes.fromhex('833f'),1)]
report={'binary_sha256':hashlib.sha256(data).hexdigest(),'elf':'ELF64 little-endian EM_X86_64','memory_stubs':{},'register_forms':{}}
for name,count,prefix,nbytes in variants:
    table=body('table_'+name);assert len(table)==8*count
    for imm in range(count):
        stub=f'{name}_{imm:04x}';addr=symbols[stub][0];raw=body(stub)
        op=prefix+imm.to_bytes(nbytes,'little');expected=op+b'\x9c\x58'
        assert raw.startswith(expected),(stub,raw.hex(),expected.hex())
        assert jmp_target(raw[len(expected):],addr+len(expected))==symbols['memory_return'][0],stub
        assert struct.unpack_from('<Q',table,8*imm)[0]==addr,(stub,'wrong dispatch pointer')
    report['memory_stubs'][name]=count
prefix=bytes.fromhex('9c41584d89c14981e12af7ffff4881e6d50800004909f141519d')
# After the common POPFQ, opcode and PUSHFQ must be adjacent.
for op,middle in [('inc','c7'),('dec','cf'),('add','c7'),('sub','ef')]:
    for width in [8,16,32,64]:
        if op in ['inc','dec']:
            insn={8:'40fe'+middle,16:'66ff'+middle,32:'ff'+middle,64:'48ff'+middle}[width]
        else:
            insn={8:'4080'+middle+'01',16:'6683'+middle+'01',32:'83'+middle+'01',64:'4883'+middle+'01'}[width]
        name=f'probe_{op}{width}';raw=body(name)
        assert raw.startswith(prefix+bytes.fromhex(insn)+b'\x9c\x58'),name
        report['register_forms'][name]=insn
for name,insn in [('probe_inc_ah','fec4'),('probe_dec_ch','fecd')]:
    raw=body(name);ix=raw.index(prefix);assert raw[ix:].startswith(prefix+bytes.fromhex(insn)+b'\x9c\x41\x5a'),name
    report['register_forms'][name]=insn
assert body('probe_memory')==prefix+bytes.fromhex('ffe2'),'memory dispatcher changes flags'
assert body('memory_return')==bytes.fromhex('4825d508000041509dc3'),'unexpected flag return path'
report.update(status='PASS',total_memory_stubs=sum(report['memory_stubs'].values()),memory_dispatch='POPFQ; JMP RDX; memory-immediate opcode; PUSHFQ',flags_mask='0x8d5')
print(json.dumps(report,indent=2))
