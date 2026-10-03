#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Synthetic native FEX JIT versus an externally installed Unicorn."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

import unicorn
from unicorn import x86_const as x86
from generate import CODE, DATA, STACK, SIZE, GPRS, SplitMix64, cases, line


def fnv(data):
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & ((1 << 64) - 1)
    return f'0x{value:016x}'


def oracle(case):
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    for address in (CODE, DATA, STACK):
        uc.mem_map(address, SIZE)
    stream = SplitMix64(case['seed'])
    data, stack = stream.bytes(SIZE), stream.bytes(SIZE)
    uc.mem_write(DATA, data)
    uc.mem_write(STACK, stack)
    code = bytes.fromhex(case['code']) + b'\xf4'
    uc.mem_write(CODE, code)
    for name, value in case['regs'].items():
        uc.reg_write(getattr(x86, 'UC_X86_REG_' + name.upper()), value)
    uc.reg_write(x86.UC_X86_REG_EFLAGS, case['rflags'])
    uc.reg_write(x86.UC_X86_REG_MXCSR, case['mxcsr'])
    for index in range(16):
        combined = int.from_bytes(case['xmm'][index] + case['upper'][index], 'little')
        uc.reg_write(getattr(x86, 'UC_X86_REG_YMM' + str(index)), combined)
    # EnableExitOnHLT leaves FEX RIP on the harness sentinel. Stop Unicorn at
    # that same boundary; the appended HLT is not part of the tested fragment.
    uc.emu_start(CODE, CODE + len(code) - 1, count=64)
    return dict(
        regs={name: f'0x{uc.reg_read(getattr(x86, "UC_X86_REG_" + name.upper())):016x}' for name in GPRS},
        rip=f'0x{uc.reg_read(x86.UC_X86_REG_RIP):016x}',
        rflags=uc.reg_read(x86.UC_X86_REG_EFLAGS), mxcsr=uc.reg_read(x86.UC_X86_REG_MXCSR),
        xmm=[uc.reg_read(getattr(x86, 'UC_X86_REG_XMM' + str(index))).to_bytes(16, 'little').hex() for index in range(16)],
        ymm_hi=[(uc.reg_read(getattr(x86, 'UC_X86_REG_YMM' + str(index))) >> 128).to_bytes(16, 'little').hex() for index in range(16)],
        init_data_hash=fnv(data), init_stack_hash=fnv(stack),
        data_hash=fnv(uc.mem_read(DATA, SIZE)), stack_hash=fnv(uc.mem_read(STACK, SIZE)))


def differences(case, actual, expected):
    errors = []
    if actual.get('id') != case['id']:
        errors.append('case-identity')
    if actual.get('status') != 'exit' or not actual.get('state_valid'):
        errors.append('native:' + str(actual.get('status', 'missing')))
    for field in ('regs', 'rip', 'xmm', 'ymm_hi', 'init_data_hash', 'init_stack_hash', 'data_hash', 'stack_hash'):
        if actual.get(field) != expected[field]:
            errors.append(field)
    if (int(actual.get('rflags', '0'), 0) ^ expected['rflags']) & case['flag_mask']:
        errors.append('defined-rflags')
    if int(actual.get('mxcsr', '0'), 0) != expected['mxcsr']:
        errors.append('mxcsr')
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--quick', action='store_true')
    mode.add_argument('--full', action='store_true')
    ap.add_argument('--runner', required=True)
    ap.add_argument('--report', required=True)
    ap.add_argument('--mutate-runner', action='store_true')
    args = ap.parse_args()
    selected = list(cases(args.full))
    # The public configuration is explicit: inherited private FEX gates cannot
    # silently alter a CI result. This synthetic stand has no product manifest.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('FEX_', 'MACRUNNER_', 'ORACLE_', 'STAND_MUTATE_'))}
    env.update(FEX_MULTIBLOCK='0', ORACLE_TIMEOUT_MS='2000')
    if args.mutate_runner:
        env['STAND_MUTATE_GPR'] = '1'
    runner = pathlib.Path(args.runner)
    process = subprocess.Popen([str(runner.resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, env=env)
    try:
        raw, log = process.communicate('\n'.join(line(case) for case in selected) + '\n', timeout=180)
    except subprocess.TimeoutExpired:
        # Popen owns this still-live process; never signal a process by name.
        process.kill()
        raw, log = process.communicate()
    destination = pathlib.Path(args.report)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.with_suffix('.native.log').write_text(log)
    answers = [json.loads(item) for item in raw.splitlines() if item.strip()]
    rows = []
    for index, case in enumerate(selected):
        expected = oracle(case)
        actual = answers[index] if index < len(answers) else {}
        errors = differences(case, actual, expected)
        # Only semantic fields go into the deterministic report; host fault
        # PCs, clock readings, tool output and absolute paths are log evidence.
        rows.append(dict(id=case['id'], family=case['name'], seed=case['seed'],
                         code=case['code'], verdict='FAIL' if errors else 'EQUAL', errors=errors,
                         expected=expected,
                         actual={key: actual.get(key) for key in expected}))
    failed = sum(row['verdict'] == 'FAIL' for row in rows)
    result = dict(schema=1, mode='full' if args.full else 'quick',
                  generator='splitmix64-v1', oracle='Unicorn ' + unicorn.__version__,
                  runner_sha256=hashlib.sha256(runner.read_bytes()).hexdigest(),
                  environment={'FEX_MULTIBLOCK': '0', 'ORACLE_TIMEOUT_MS': '2000'},
                  mutation=args.mutate_runner, states=len(rows), equal=len(rows) - failed,
                  new=failed, native_rc=process.returncode, native_rows=len(answers), rows=rows)
    destination.write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    success = failed == 0 and process.returncode == 0 and len(answers) == len(selected)
    print(f'STAND {"PASS" if success else "FAIL"} states={len(rows)} equal={len(rows)-failed} new={failed}')
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
