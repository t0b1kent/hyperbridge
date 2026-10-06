# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
#!/usr/bin/env python3
"""Build stand frontend and assemble exact oracle target instructions, never execute x86."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time
import zlib

SOURCE = Path(__file__).resolve().parent
HERE = SOURCE.parents[1] / 'build/hardware/cache'


def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def descriptions():
    envelope = json.loads((SOURCE/'data/SIMD-ENCODING-MAP.json').read_text())
    payload = zlib.decompress(base64.b64decode(envelope['payload_base64']))
    if len(payload) != envelope['payload_bytes'] or hashlib.sha256(payload).hexdigest() != envelope['payload_sha256']:
        raise ValueError('encoding description payload drift')
    spec = json.loads(payload)
    forms = {}
    for family, groups in spec['groups'].items():
        for ordinal, group in enumerate(groups):
            ids = group.get('manifest_ids', dict(start=ordinal, count=1, step=0))
            imm = group.get('immediates', dict(start=-1, count=1, step=0))
            for index in range(ids['count']):
                number = ids['start'] + index * ids['step']
                entry = dict(group)
                entry['imm'] = imm['start'] + index * imm['step']
                entry['asm'] = group['target_asm'].format(imm=entry['imm'])
                key = f'{family}:{number}'
                if key in forms:
                    raise ValueError('duplicate form: ' + key)
                forms[key] = entry
    return spec, forms


def elf_sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected little-endian ELF64')
    shoff = struct.unpack_from('<Q',data,40)[0]
    entsize, count, names = struct.unpack_from('<HHH',data,58)
    raw = [struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*entsize) for i in range(count)]
    shstr = data[raw[names][4]:raw[names][4]+raw[names][5]]
    result = {}
    for index, row in enumerate(raw):
        name = shstr[row[0]:].split(b'\0',1)[0].decode()
        result[name] = dict(index=index, row=row, bytes=data[row[4]:row[4]+row[5]])
    return result, raw


def assemble():
    spec, forms = descriptions()
    HERE.mkdir(parents=True, exist_ok=True)
    asm = ['.text']
    keys = list(forms)
    for index, key in enumerate(keys):
        entry = forms[key]
        asm += ['.intel_syntax noprefix' if entry['syntax']=='Intel' else '.att_syntax prefix',
                f'.globl start_{index}', f'start_{index}:', entry['asm'],
                f'.globl end_{index}', f'end_{index}:']
    source = HERE/'simd-targets.S'
    source.write_text('\n'.join(asm)+'\n')
    command = ['nice','-n','20','/usr/bin/clang','-target','x86_64-linux-gnu','-c',str(source),'-o',str(HERE/'simd-targets.o')]
    proc = subprocess.run(command, text=True, capture_output=True)
    (HERE/'simd-assembler.log').write_text(proc.stdout+proc.stderr)
    if proc.returncode:
        raise RuntimeError('cross-assembly failed; simd-assembler.log')
    sections, raw = elf_sections((HERE/'simd-targets.o').read_bytes())
    sym = sections['.symtab']['row']
    strings = raw[sym[6]]
    strings = (HERE/'simd-targets.o').read_bytes()[strings[4]:strings[4]+strings[5]]
    symbols = {}
    for offset in range(0,sym[5],sym[9]):
        name, info, other, section, value, size = struct.unpack_from('<IBBHQQ',sections['.symtab']['bytes'],offset)
        symbols[strings[name:].split(b'\0',1)[0].decode()] = value
    text = sections['.text']['bytes']
    import capstone
    decoder = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    for index, key in enumerate(keys):
        code = text[symbols[f'start_{index}']:symbols[f'end_{index}']]
        decoded = list(decoder.disasm(code,0))
        if len(decoded)!=1 or decoded[0].size!=len(code):
            raise ValueError('instruction boundary not verified: '+key)
        forms[key]['code'] = code.hex()
        forms[key]['decoded'] = decoded[0].mnemonic+' '+decoded[0].op_str
    with gzip.open(HERE/'simd-code.json.gz','wt',compresslevel=6) as f:
        json.dump(forms,f,sort_keys=True)
    return len(forms)



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=HERE)
    args = parser.parse_args()
    HERE = args.out.resolve()
    print('ASSEMBLED_FORMS=' + str(assemble()))
