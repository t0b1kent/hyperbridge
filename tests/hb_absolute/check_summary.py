#!/usr/bin/env python3
"""Сводка раннера HBUP0002/HBFL0001 (последняя строка stdout) -> код выхода для `make test`.

Раннер отвечает 2, если в корпусе есть формы, которых HB не исполняет, — и это правильно для
приёмки. Для регрессии нужно другое: ни одного расхождения ни у одного исполнителя, и число
неподдержанных не РОСЛО. --max-unsupported — потолок, известный на момент записи.
"""
import argparse, json, sys

ap = argparse.ArgumentParser()
ap.add_argument('--max-unsupported', type=int, default=0)
ap.add_argument('--expect-selected', type=int)
a = ap.parse_args()
lines = [l for l in sys.stdin.read().splitlines() if l.startswith('{')]
if not lines:
    print('check_summary: no JSON summary from the runner'); sys.exit(1)
s = json.loads(lines[-1]); bad = []
if a.expect_selected is not None and s.get('selected') != a.expect_selected:
    bad.append(f"selected={s.get('selected')} expected {a.expect_selected}")
if s.get('unsupported', 0) > a.max_unsupported:
    bad.append(f"unsupported={s.get('unsupported')} > {a.max_unsupported}")
for b in s.get('backends', []):
    for k, v in b.items():
        if k not in ('backend', 'executed') and v:
            bad.append(f"{b['backend']} {k}={v}")
    if not b.get('executed'):
        bad.append(f"{b['backend']} executed nothing")
print(('FAIL ' + '; '.join(bad)) if bad else
      f"ok selected={s.get('selected')} unsupported={s.get('unsupported', 0)} " +
      ' '.join(f"{b['backend']}={b['executed']}" for b in s.get('backends', [])))
sys.exit(1 if bad else 0)
