#!/usr/bin/env python3
"""Static-only audit of the OWN compiled PE. Does not execute a PE or read DLL code."""
import argparse
import json
import re
import subprocess
from pathlib import Path

NAMES = ['int2d', 'int3', 'debugbreak', 'output_a', 'output_w', 'is_debugger_present', 'check_remote_debugger_present', 'alternate']
def require(condition, message):
    if not condition:
        raise ValueError(message)

def audit(pe, tool_dir):
    def tool(name, *args):
        suffix = '.exe' if (tool_dir / (name + '.exe')).exists() else ''
        return subprocess.run([str(tool_dir / (name + suffix)), *args, str(pe)], check=True, capture_output=True, text=True).stdout
    dis = tool('llvm-objdump', '-d')
    unw = tool('llvm-readobj', '--unwind')
    imp = tool('llvm-readobj', '--coff-imports')
    symbols = tool('llvm-nm', '-n')
    addresses = {}
    for line in symbols.splitlines():
        m = re.match(r'([0-9a-fA-F]+)\s+\w\s+(\S+)$', line)
        if m:
            addresses[m[2]] = int(m[1], 16)
    instructions = {}
    for line in dis.splitlines():
        m = re.match(r'\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2} )+)\s*(.*)', line)
        if m:
            instructions[int(m[1], 16)] = (bytes.fromhex(m[2]), m[3].strip())
    blocks = {}
    for m in re.finditer(r'StartAddress: (?:\w+ )?\(0x([0-9a-fA-F]+)\).*?UnwindCodes \[([^]]+)\]', unw, re.S):
        blocks[int(m[1], 16)] = m[2].strip()
    for name in NAMES:
        n = 'probe_' + name
        require(addresses[n] in blocks, n + ': missing unwind entry')
        require(blocks[addresses[n]] == blocks[addresses['probe_int2d']], n + ': inherited frame unwind differs')
        start, sled, end = addresses[n], addresses[n + '_sled_start'], addresses[n + '_sled_end']
        require(end - sled == 9, n + ': sled not nine bytes')
        for off in range(9):
            require(instructions[sled + off][0] == b'\x9c', n + ': not one-byte PUSHFQ at safe entry')
        if name == 'int2d': require(instructions[addresses[n + '_site']][0] == b'\xcd\x2d', 'INT2D bytes differ')
        if name == 'int3': require(instructions[addresses[n + '_site']][0] == b'\xcc', 'INT3 bytes differ')
        after = [instructions[a] for a in sorted(instructions) if end <= a < addresses[n + '_escape']]
        require(len(after) >= 16 and all(t.startswith('movq') for _, t in after[:16]), n + ': GPR capture is not first 16 MOVs')
        require('probe_capture_path' in after[16][1], n + ': missing observed capture marker after GPR snapshot')
        require(('$0x2' if name == 'alternate' else '$0x1') in after[16][1], n + ': wrong capture marker')
        body = '\n'.join(t for _, t in after)
        require('(%rax), %rax' in body and ('-0x8(%rax)' in body or '-8(%rax)' in body), n + ': missing first PUSHFQ image load')
        prologue = b''.join(instructions[a][0] for a in sorted(instructions) if start <= a < start + 125)
        require(len(prologue) == 125, n + ': prologue extent differs')
        if name == 'int2d': reference_prologue = prologue
        else: require(prologue == reference_prologue, n + ': prologue bytes differ')
        escape = addresses[n + '_escape']
        escape_body = '\n'.join(t for a, (_, t) in instructions.items() if escape <= a < addresses[n + '_cleanup'])
        require('probe_post_gpr' not in escape_body and 'probe_post_rflags' not in escape_body, n + ': escape creates misleading snapshot')
    invoke_unwind = re.search(r'StartAddress: invoke .*?(?=\n  RuntimeFunction \{|\Z)', unw, re.S)
    require(invoke_unwind is not None and 'Handler: __C_specific_handler ' in invoke_unwind[0], 'invoke frame SEH unwind missing')
    invoke_section = dis.split('<invoke>:', 1)[1].split('\n\n', 1)[0]
    require('callq' in invoke_section, 'faulting frame separation missing')
    depth_section = dis.split('<at_depth>:', 1)[1].split('\n\n', 1)[0]
    require('<at_depth>' in depth_section and 'callq' in depth_section, 'recursive depth control optimized away')
    for forbidden in ['OpenProcess', 'DebugActiveProcess', 'WriteProcessMemory', 'VirtualAlloc', 'SetThreadContext', 'CreateRemoteThread']:
        require('Symbol: ' + forbidden + ' ' not in imp, 'unexpected import: ' + forbidden)
    return {'status': 'passed_static_only', 'functions': len(NAMES), 'safe_pushfq_entries_per_function': 9,
            'matching_inherited_prologues_and_unwind': True, 'real_frame_SEH': True,
            'PE_executed': False, 'foreign_code_disassembled': False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('pe', type=Path)
    p.add_argument('--tool-dir', required=True, type=Path)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    result = audit(a.pe, a.tool_dir)
    text = json.dumps(result, indent=2) + '\n'
    if a.output: a.output.write_text(text, encoding='utf-8')
    print(text, end='')
if __name__ == '__main__': main()
