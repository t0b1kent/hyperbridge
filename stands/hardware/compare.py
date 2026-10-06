#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
"""Compare already collected local/cloud semantic files; executes no guest code."""
import argparse
import gzip
import hashlib
import json

import common


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--component', choices=['hwflags', 'hwsimd'], required=True)
    p.add_argument('--local', required=True)
    p.add_argument('--cloud', required=True)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    hashes = [hashlib.sha256(), hashlib.sha256()]
    counts = [0, 0]
    def rows(path, index):
        previous = None
        with gzip.open(path, 'rt') as stream:
            for line in stream:
                record = json.loads(line)
                key = common.semantic_key(record)
                if previous is not None and key <= previous:
                    raise ValueError('input is not in serial order; merge local shards first')
                previous = key
                encoded = common.semantic_bytes(a.component, record)
                hashes[index].update(encoded)
                counts[index] += 1
                yield key, record, encoded
    left, right = rows(a.local, 0), rows(a.cloud, 1)
    x, y = next(left, None), next(right, None)
    different, missing_local, missing_cloud, examples = 0, 0, 0, []
    while x is not None or y is not None:
        if y is None or (x is not None and x[0] < y[0]):
            missing_cloud += 1
            x = next(left, None)
        elif x is None or y[0] < x[0]:
            missing_local += 1
            y = next(right, None)
        else:
            if x[2] != y[2]:
                different += 1
                if len(examples) < 20:
                    examples.append({'key': x[1]['key'], 'local': x[1], 'cloud': y[1]})
            x, y = next(left, None), next(right, None)
    result = {'equal': not (different or missing_local or missing_cloud),
              'different_rows': different, 'missing_local': missing_local, 'missing_cloud': missing_cloud,
              'rows_local': counts[0], 'rows_cloud': counts[1], 'examples': examples,
              'canonical_local': hashes[0].hexdigest(), 'canonical_cloud': hashes[1].hexdigest(),
              'cause': 'NONE' if not (different or missing_local or missing_cloud) else 'UNRESOLVED: inspect examples and BUILD.json host/compiler/environment; do not infer processor causality from one run'}
    common.write_json(a.out, result)
    print(f"HB_HW_COMPARE {'PASS' if result['equal'] else 'FAIL'} different_rows={different} missing_local={missing_local} missing_cloud={missing_cloud}")
    return int(not result['equal'])


if __name__ == '__main__':
    raise SystemExit(main())
