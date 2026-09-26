#!/usr/bin/env python3
"""Сверка сжатого смещения EVEX (disp8*N) декодера HB против capstone — по ВСЕМ формам.

Перебор: карты 1/2/3/5/6 × pp × W × L'L × b × все 256 кодов × [rcx+disp8] и [rsp+disp8] (SIB),
disp8 = 1. Из них берутся формы, которые декодер HB принимает как исполнимые EVEX (не UD/VEC/
UNKNOWN/UNSUPPORTED). Для каждой смещение HB сравнивается со смещением capstone.

  sweep.py <hb_disp_probe> [--arch 64|32] [--table out.h]

Выход 0 — все сравнимые формы сошлись; 1 — есть расхождения. --table пишет C-таблицу
ожидаемых смещений для tests/hb_evex_disp8_test.c (тест в `make test` без capstone).
Нужен пакет capstone (pip install capstone); проверено с 5.0.7.
Замер 26.09.2026 до правки: x64 956 из 962 форм с неверным адресом.
"""
import argparse, collections, json, subprocess, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_MEM

PLACEHOLDERS = (629, 631, 634, 635)   # HB_INS_UD, HB_INS_VEC, HB_INS_UNKNOWN, HB_INS_UNSUPPORTED

ap = argparse.ArgumentParser()
ap.add_argument('probe'); ap.add_argument('--arch', default='64', choices=('64', '32'))
ap.add_argument('--table'); ap.add_argument('--json')
a = ap.parse_args()
md = Cs(CS_ARCH_X86, CS_MODE_64 if a.arch == '64' else CS_MODE_32); md.detail = True

cases = []
for mmm in (1, 2, 3, 5, 6):
    for pp in range(4):
        for W in (0, 1):
            for LL in (0, 1, 2):
                for bb in (0, 1):
                    for op in range(256):
                        for modrm in (0x49, 0x4c):
                            p0 = 0xF0 | mmm; p1 = (W << 7) | (0xF << 3) | 4 | pp; p2 = (LL << 5) | (bb << 4) | 8
                            body = bytes([0x62, p0, p1, p2, op, modrm]) + (b'\x24' if modrm == 0x4c else b'') + b'\x01\x00'
                            cases.append(body)
inp = '\n'.join(c.hex() for c in cases) + '\n'
out = subprocess.run([a.probe] + (['32'] if a.arch == '32' else []), input=inp, capture_output=True, text=True).stdout.splitlines()
assert len(out) == len(cases), (len(out), len(cases))

stats = collections.Counter(); bad = []; table = []; rejected = []
for body, line in zip(cases, out):
    f = line.split()
    if f[0] != 'ok' or f[3] != '1' or int(f[2]) in PLACEHOLDERS:
        continue
    stats['hb_executes'] += 1
    ins = list(md.disasm(body, 0x10000, 1))
    if not ins:
        stats['capstone_rejects'] += 1; rejected.append(body.hex()); continue
    i = ins[0]; csd = None
    for o in i.operands:
        if o.type == X86_OP_MEM: csd = o.mem.disp
    hbd = None if f[4] == 'none' else int(f[4])
    if int(f[1]) != i.size:
        stats['length_mismatch'] += 1; bad.append((body.hex(), line, i.mnemonic, 'len')); continue
    if csd is None and hbd is None:
        stats['no_memory'] += 1; continue
    if csd != hbd:
        stats['disp_mismatch'] += 1; bad.append((body.hex(), line, i.mnemonic + ' ' + i.op_str, csd))
    else:
        stats['disp_ok'] += 1; table.append((body, i.size, csd, i.mnemonic))
print(json.dumps(dict(stats, arch=a.arch)))
for b in bad[:40]: print('BAD', *b)
if a.json:
    json.dump(dict(bad=bad, capstone_rejects=rejected), open(a.json, 'w'))
if a.table:
    with open(a.table, 'w') as t:
        t.write('/* ПОРОЖДЁННЫЙ ФАЙЛ: tests/hb_evex_disp8/sweep.py --arch %s --table (эталон — capstone). */\n' % a.arch)
        t.write('/* %d форм EVEX, которые исполняет декодер HB; смещение disp8=1 × N. */\n' % len(table))
        for body, size, disp, mn in table:
            t.write('{%s, %d, {%s}, %d}, /* %s */\n' % (a.arch, len(body), ','.join('0x%02x' % x for x in body), disp, mn))
sys.exit(1 if bad else 0)
