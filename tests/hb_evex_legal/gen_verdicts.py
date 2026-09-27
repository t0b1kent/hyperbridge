#!/usr/bin/env python3
"""Аппаратные вердикты законности EVEX -> C-таблица для tests/hb_evex_legal_test.c.

  gen_verdicts.py EVEX_RESULTS.json [--details details.json] [--controls controls.json] > verdicts.inc

EVEX_RESULTS.json — [{bytes, arch, ud}], 264 кодировки, которые декодер HB принимал, а
capstone отвергал (tests/hb_evex_disp8/sweep.py --json). Все исполнены на x86 (пакет
HB_EDGE_ORACLE: AMD EPYC 9V74; x64 в CS=0x33, i386 в режиме совместимости CS=0x23;
одиночный шаг на первой команде): ud=true — SIGILL с trap 6 на её начале, ud=false —
trap 1 после неё. details.json (evidence/legality/) даёт замеренную длину исполнившихся;
controls.json — законные контрольные формы того же прогона (берутся только EVEX).

Длину команды, давшей #UD, процессор не называет — она считается разбором EVEX:
62 P0 P1 P2 код ModRM [SIB] [смещение] [imm8]. Формула сверяется с замером у каждой
записи, где замер есть; расхождение, незнакомый код или лишние байты сверх одного
завершающего — отказ порождения, а не таблица.
"""
import argparse, hashlib, json, sys

# Коды, которые встречаются в замере; imm8 из них несёт только VCMP (карта 1, C2).
KNOWN = {(1, 0xc2)} | {(2, op) for op in (0x08, 0x09, 0x0a, 0x18, 0x19, 0x1a, 0x1b,
                                          0x58, 0x59, 0x78, 0x79, 0xcf)}
IMM8 = {(1, 0xc2)}


def fields(b):
    return dict(map=b[1] & 7, pp=b[2] & 3, W=b[2] >> 7, LL=(b[3] >> 5) & 3,
                b=(b[3] >> 4) & 1, op=b[4], mod=b[5] >> 6)


def evex_len(b):
    if b[0] != 0x62 or len(b) < 6:
        raise SystemExit('not an EVEX encoding: ' + b.hex())
    f = fields(b)
    if (f['map'], f['op']) not in KNOWN:
        raise SystemExit('opcode outside the known set, imm8 unknown: ' + b.hex())
    modrm = b[5]
    mod, rm = modrm >> 6, modrm & 7
    n = 6
    if mod != 3 and rm == 4:
        n += 1
        if mod == 0 and (b[6] & 7) == 5:
            n += 4
    if mod == 1:
        n += 1
    elif mod == 2 or (mod == 0 and rm == 5):
        n += 4
    if (f['map'], f['op']) in IMM8:
        n += 1
    return n


ap = argparse.ArgumentParser()
ap.add_argument('results')
ap.add_argument('--details')
ap.add_argument('--controls')
a = ap.parse_args()

raw = open(a.results, 'rb').read()
results = json.loads(raw)
measured = {}
if a.details:
    for r in json.load(open(a.details)):
        measured[(r['arch'], r['bytes'])] = r
    if set(measured) != {(r['arch'], r['bytes']) for r in results}:
        raise SystemExit('details.json does not describe the same records')

rows = []
for r in results:
    b = bytes.fromhex(r['bytes'])
    if r['arch'] not in ('x64', 'i386') or not isinstance(r['ud'], bool):
        raise SystemExit('bad record: %r' % (r,))
    n = evex_len(b)
    if len(b) - n not in (0, 1):
        raise SystemExit('record longer than one instruction plus one byte: ' + r['bytes'])
    m = measured.get((r['arch'], r['bytes']))
    if m is not None:
        if m['ud'] != r['ud']:
            raise SystemExit('details.json disagrees on ud: ' + r['bytes'])
        if m['instruction_length'] is not None and m['instruction_length'] != n:
            raise SystemExit('length formula %d != measured %d: %s' % (n, m['instruction_length'], r['bytes']))
    rows.append((r['arch'], b, r['ud'], n, 0, m is not None and m['instruction_length'] is not None))

if a.controls:
    for r in json.load(open(a.controls)):
        if not r['bytes'].startswith('62'):
            continue
        b = bytes.fromhex(r['bytes'])
        n = evex_len(b)
        if r['ud'] or r['instruction_length'] != n:
            raise SystemExit('unexpected control: %r' % (r,))
        rows.append((r['arch'], b, False, n, 1, True))

cnt = {}
for arch, b, ud, n, ctl, meas in rows:
    k = (arch, 'ctl' if ctl else ('ud' if ud else 'ok'))
    cnt[k] = cnt.get(k, 0) + 1

w = sys.stdout.write
w('/* ПОРОЖДЁННЫЙ ФАЙЛ: tests/hb_evex_legal/gen_verdicts.py (эталон — процессор x86, не capstone).\n')
w(' * Источник: EVEX_RESULTS.json пакета HB_EDGE_ORACLE, sha256 %s.\n' % hashlib.sha256(raw).hexdigest())
w(' * x64: #UD %d, исполнилось %d, законных контрольных %d; i386: #UD %d, исполнилось %d, контрольных %d.\n' % (
    cnt.get(('x64', 'ud'), 0), cnt.get(('x64', 'ok'), 0), cnt.get(('x64', 'ctl'), 0),
    cnt.get(('i386', 'ud'), 0), cnt.get(('i386', 'ok'), 0), cnt.get(('i386', 'ctl'), 0)))
w(' * Поля: {разрядность, байтов, {байты}, #UD, длина команды, контрольная}.\n')
w(' * Длина посчитана разбором EVEX; %d из них сверены с длиной, замеренной процессором\n'
  ' * (trap 1 после команды), у #UD-записей замера длины нет. */\n' % sum(1 for x in rows if x[5]))
for arch, b, ud, n, ctl, meas in rows:
    f = fields(b)
    w('{%d, %d, {%s}, %d, %d, %d}, /* %s map%d pp%d W%d L\'L%d b%d %02x %s%s */\n' % (
        64 if arch == 'x64' else 32, len(b), ','.join('0x%02x' % x for x in b), int(ud), n, ctl,
        arch, f['map'], f['pp'], f['W'], f['LL'], f['b'], f['op'],
        '#UD' if ud else ('legal control' if ctl else 'executed'),
        ', length measured' if meas else ''))
