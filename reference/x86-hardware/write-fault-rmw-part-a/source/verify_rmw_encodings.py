# SPDX-License-Identifier: MIT
"""Independently validate rmw.py against GNU as; does not execute instructions."""
import collections
import pathlib
import subprocess
import tempfile

import rmw


def main():
    rows = rmw.forms()
    source = ['.intel_syntax noprefix', '.text']
    for n, row in enumerate(rows):
        assembly = row['asm'] if row['legal'] else row['asm'].removeprefix('lock ')
        source += [f'.global case_{n}', f'case_{n}:', assembly]
    source += ['.global case_end', 'case_end:']
    with tempfile.TemporaryDirectory(prefix='new0035-rmw-encoding-') as directory:
        path = pathlib.Path(directory)
        (path / 'cases.s').write_text('\n'.join(source) + '\n')
        subprocess.run(['as', '--64', '-o', str(path / 'cases.o'), str(path / 'cases.s')], check=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text',
                        str(path / 'cases.o'), str(path / 'cases.bin')], check=True)
        binary = (path / 'cases.bin').read_bytes()
        nm = subprocess.check_output(['nm', '-n', str(path / 'cases.o')], text=True)
        positions = {name: int(address, 16) for address, kind, name in
                     (line.split() for line in nm.splitlines())}
        mismatches = []
        for n, row in enumerate(rows):
            end = f'case_{n + 1}' if n + 1 < len(rows) else 'case_end'
            actual = binary[positions[f'case_{n}']:positions[end]]
            if not row['legal']:
                # GNU as rejects illegal LOCK forms, so independently
                # assemble their unlocked opcode and insert only LOCK.
                actual = (actual[:1] + b'\xf0' + actual[1:]) if actual[:1] == b'\x66' else b'\xf0' + actual
            if actual.hex() != row['code']:
                mismatches.append((row['name'], row['code'], actual.hex()))
        assert not mismatches, mismatches
        print(f"Verified {len(rows)} definitions: {sum(row['legal'] for row in rows)} legal, "
              f"{sum(not row['legal'] for row in rows)} intentional illegal LOCK forms")
        print('Widths (bytes):', dict(sorted(collections.Counter(row['width'] for row in rows).items())))
        print('No GNU as byte mismatches; intentional illegal forms checked by prefix insertion')


if __name__ == '__main__':
    main()
