#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the instrument; do not decide the disputed diagonal by assumption."""
import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path


def qualify(run):
    raw = run / 'raw'
    cases = list(csv.DictReader((run / 'cases.csv').open(encoding='utf-8-sig')))
    assert len(cases) == 6
    device = json.loads((raw / 'device.json').read_text())
    assert device['backend'] == 'WARP, not hardware' and device['software'] is True
    results = [json.loads(line) for line in (raw / 'results.jsonl').read_text().splitlines()]
    assert len(results) == 12
    indexed = {(r['name'], r['pass']): r for r in results}
    assert len(indexed) == 12
    images, rows = {}, []
    for c in cases:
        name = c['name']
        params = struct.pack('<8I', *(int(c[k], 0) for k in
            ['outer0', 'outer1', 'outer2', 'outer3', 'inner0', 'inner1', 'tag']), 65536)
        assert (raw / name / 'params.bin').read_bytes() == params
        last = 0
        for p, pixel_name, recorder_name in [
            (0, 'own.pixels.bin', 'recorder-uncull.bin'),
            (1, 'front.pixels.bin', 'recorder.bin')]:
            r = indexed[name, p]
            image = (raw / name / pixel_name).read_bytes()
            assert len(image) == 128 * 128 * 4
            covered = sum(v != 0 for v in image[3::4])
            assert covered == r['covered'] and (p or covered == 112 * 112)
            assert r['winding'] == c['winding'] and r['guards_tags'] is True
            data = (raw / name / recorder_name).read_bytes()
            assert len(data) == 16 + 65536 * 16 + 256
            count, overflow, reserved0, reserved1 = struct.unpack_from('<4I', data)
            assert 0 < count <= 65536 and count >= last
            assert overflow == r['overflow'] == reserved0 == reserved1 == 0
            assert count == r['invocations_cumulative']
            last = count
            points = set()
            for u, v, z, tag in struct.iter_unpack('<4I', data[16:16+count*16]):
                assert z == 0 and tag == int(c['tag'])
                uf, vf = struct.unpack('<2f', struct.pack('<2I', u, v))
                assert 0 <= uf <= 1 and 0 <= vf <= 1
                points.add((u, v))
            assert data[16+count*16:] == b'\xa5' * (len(data)-16-count*16)
            images[name, p] = image
            rows.append(dict(name=name, pass_index=p, covered=covered, unique_uv=len(points),
                             rgba_sha256=hashlib.sha256(image).hexdigest()))
    # These controls qualify orientation/culling and both shader configurations.
    for cw, ccw in [('c0000','c0099'), ('c0002','c0101'), ('c0097','c0196')]:
        assert images[cw, 0] == images[ccw, 0], ('winding changed uncull', cw)
        visible = []
        for name in (cw, ccw):
            if any(images[name, 1]):
                assert images[name, 1] == images[name, 0]
                visible.append(name)
        assert len(visible) == 1, ('back-cull qualification', cw, visible)
    assert images['c0000', 0] != images['c0002', 0], 'odd1/odd3 must differ'
    return dict(status='PRESENT', backend='WARP, not hardware', cases=6, draws=12,
                diagonal_verdict='NOT_EVALUATED: compare raw output to both saved candidates', rows=rows)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--run', type=Path, required=True)
    args = ap.parse_args()
    result = qualify(args.run)
    (args.run / 'QUALIFICATION.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'rows'}))
