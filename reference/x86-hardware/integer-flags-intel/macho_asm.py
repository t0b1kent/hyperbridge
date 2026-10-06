#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mach-O spelling only; fail closed unless every opcode/body is preserved."""
import hashlib
import json
import pathlib
import re
import sys


def adapt(source):
    lines = source.splitlines()
    converted = []
    removed = {'type': 0, 'size': 0, 'stack': 0}
    symbols = []
    for line in lines:
        if re.fullmatch(r'\.type core_\d+,@function', line):
            removed['type'] += 1
        elif re.fullmatch(r'\.size core_\d+,\.-core_\d+', line):
            removed['size'] += 1
        elif line == '.section .note.GNU-stack,"",@progbits':
            removed['stack'] += 1
        elif re.fullmatch(r'\.globl core_\d+', line):
            name = line.split()[1]
            symbols.append(name)
            converted.append('.globl _' + name)
        elif re.fullmatch(r'core_\d+:', line):
            converted.append('_' + line)
        else:
            # This also preserves .byte for undefined BSWAP16, without mnemonic rewriting.
            converted.append(line)
    if not symbols or removed != {'type': len(symbols), 'size': len(symbols), 'stack': 1}:
        raise ValueError('Unexpected ELF directive inventory')
    if symbols != [f'core_{n}' for n in range(len(symbols))]:
        raise ValueError('Non-sequential or duplicated assembly symbols')
    original_body = [s for s in lines if s and not s.startswith('.') and not s.endswith(':')]
    new_body = [s for s in converted if s and not s.startswith('.') and not s.endswith(':')]
    # Include all .byte instructions in the independent body check.
    original_body += [s for s in lines if s.startswith('.byte ')]
    new_body += [s for s in converted if s.startswith('.byte ')]
    if original_body != new_body:
        raise ValueError('Instruction body changed')
    result = '\n'.join(converted) + '\n'
    return result, {'symbols': len(symbols), 'removed_elf_directives': removed,
                    'instruction_lines_identical': True,
                    'instruction_lines_sha256': hashlib.sha256(('\n'.join(original_body) + '\n').encode()).hexdigest()}


def main():
    source, destination, report = map(pathlib.Path, sys.argv[1:])
    result, audit = adapt(source.read_text())
    destination.write_text(result)
    audit['elf_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
    audit['macho_source_sha256'] = hashlib.sha256(destination.read_bytes()).hexdigest()
    report.write_text(json.dumps(audit, indent=2) + '\n')


if __name__ == '__main__':
    main()
