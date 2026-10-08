#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify the instrument; do not decide the disputed diagonal by assumption."""
import argparse
import csv
import hashlib
import json
import math
import struct
from pathlib import Path


def qualify(run, float_target=False, observed=False):
    raw = run / (('raw-float' if float_target else 'raw') + ('-observed' if observed else ''))
    cases = list(csv.DictReader((run / 'cases.csv').open(encoding='utf-8-sig')))
    assert len(cases) == 6
    device = json.loads((raw / 'device.json').read_text())
    assert device['backend'] == 'WARP, not hardware' and device['software'] is True
    assert device['format'] == ('RGBA32_FLOAT' if float_target else 'RGBA8_UNORM')
    assert device['observer'] is observed
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
            assert len(image) == 128 * 128 * (16 if float_target else 4)
            if float_target:
                values = struct.unpack('<65536f', image)
                assert all(math.isfinite(v) and 0 <= v <= 1 for v in values), 'float range'
                assert all(v in (0., 1.) for v in values[3::4]), 'float alpha'
                covered = sum(v != 0 for v in values[3::4])
            else:
                covered = sum(v != 0 for v in image[3::4])
            assert covered == r['covered'] and (p or covered == 112 * 112)
            fragments = (raw / name / ('fragment.bin' if p else 'fragment-uncull.bin')).read_bytes()
            fragment_count = qualify_fragment(image, fragments, float_target, observed)
            assert fragment_count == (covered if observed else 0)
            assert r['winding'] == c['winding'] and r['guards_tags'] is True
            data = (raw / name / recorder_name).read_bytes()
            assert len(data) == 16 + 65536 * 48 + 256 and r['record_words'] == 12
            count, overflow, reserved0, reserved1 = struct.unpack_from('<4I', data)
            assert 0 < count <= 65536 and count >= last
            assert overflow == r['overflow'] == reserved0 == reserved1 == 0
            assert count == r['invocations_cumulative']
            last = count
            points = set()
            produced = {}
            for record in struct.iter_unpack('<12I', data[16:16+count*48]):
                u, v, z, tag = record[:4]
                assert z == 0 and tag == int(c['tag'])
                uf, vf = struct.unpack('<2f', struct.pack('<2I', u, v))
                assert 0 <= uf <= 1 and 0 <= vf <= 1
                pos, color = record[4:8], record[8:12]
                values = struct.unpack('<8f', struct.pack('<8I', *pos, *color))
                assert all(math.isfinite(x) for x in values), 'DS output finite'
                assert -1 <= values[0] <= 1 and -1 <= values[1] <= 1, 'DS position range'
                assert values[2:4] == (0., 1.), 'DS position z/w'
                assert all(0 <= x <= 1 for x in values[4:]) and values[6:] == (.25, 1.), 'DS color range'
                assert (u, v) not in produced or produced[u, v] == (pos, color), 'DS duplicate UV output differs'
                produced[u, v] = (pos, color)
                points.add((u, v))
            assert data[16+count*48:] == b'\xa5' * (len(data)-16-count*48)
            images[name, p] = image
            rows.append(dict(name=name, pass_index=p, covered=covered, unique_uv=len(points),
                             record_words=12, producer_values='PRESENT_NOT_COMPARED',
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
                format=device['format'], observer=observed,
                diagonal_verdict='NOT_EVALUATED: compare raw output to both saved candidates', rows=rows)


def qualify_fragment(image, data, float_target, observed=True):
    assert len(data) == 16 + 16384*64 + 256, 'fragment size'
    assert data[:16] == bytes(16), 'fragment overflow/header'
    assert data[-256:] == b'\xa5'*256, 'fragment guard'
    stride = 16 if float_target else 4
    assert len(image) == 16384*stride, 'fragment target size'
    active = 0
    for i in range(16384):
        record = data[16+64*i:16+64*(i+1)]
        count = struct.unpack_from('<I', record)[0]
        assert count <= 1, 'fragment overlap'
        assert record[4:16] == b'\xa5'*12, 'fragment reserved'
        pixel = image[stride*i:stride*(i+1)]
        covered = pixel[12:16] == struct.pack('<f', 1.) if float_target else pixel[3] == 255
        assert bool(count) == (covered and observed), 'fragment coverage'
        if not count:
            assert record[16:] == b'\xa5'*48, 'fragment empty record'
            continue
        active += 1
        incoming, outgoing = record[16:32], record[32:48]
        assert incoming == outgoing, 'fragment input/output'
        assert record[48:56] == struct.pack('<2f', (i % 128)+.5, (i//128)+.5), 'fragment position'
        values = struct.unpack('<4f', outgoing)
        assert all(math.isfinite(v) for v in values), 'fragment output finite'
        # Float targets retain the exact recorded words, including interpolation
        # excursions. UNORM conversion saturates; it does not alter float evidence.
        converted = outgoing if float_target else bytes(round(min(1., max(0., v))*255) for v in values)
        assert pixel == converted, 'fragment target/output'
    return active


def qualify_pair(run):
    arms = [qualify(run), qualify(run, True), qualify(run, False, True), qualify(run, True, True)]
    # Both targets must rasterize the same coverage; color equality is a measurement.
    assert [(r['name'], r['pass_index'], r['covered'], r['unique_uv']) for r in arms[0]['rows']] == [
        (r['name'], r['pass_index'], r['covered'], r['unique_uv']) for r in arms[1]['rows']]
    equal = 0
    for is_float in [False, True]:
        baseline = run / ('raw-float' if is_float else 'raw')
        observed = run / (baseline.name + '-observed')
        for row in arms[int(is_float)]['rows']:
            pixel_name = 'front.pixels.bin' if row['pass_index'] else 'own.pixels.bin'
            assert (baseline/row['name']/pixel_name).read_bytes() == (observed/row['name']/pixel_name).read_bytes(), 'observer target drift'
            equal += 1
    return dict(status='PRESENT', backend='WARP, not hardware', cases=6, draws=48,
                observer_targets_equal=equal, arms=arms)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--run', type=Path, required=True)
    args = ap.parse_args()
    result = qualify_pair(args.run)
    (args.run / 'QUALIFICATION.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'arms'}))
