#!/usr/bin/env python3
"""Apply the sealed c34r (MacRunner 1.1.4) 32-bit translator source delta after the c33r profile.

The c33r profile is the exact preimage: its whole-tree inventory must match before any file is
replaced, and the c34r inventory must match afterwards. Only fex32 changes in 1.1.4.
"""
import json
from pathlib import Path

import candidate_source as source
import release111_source

HERE = Path(__file__).resolve().parent


def read_config(pin, here=HERE):
    config = pin.get('release114')
    if config is None:
        return None
    source.require(config.get('schema') == 1 and set(config['profiles']) == {'fex32'},
                   'c34r profile selection differs')
    source.require(pin.get('release111') is not None, 'c34r requires the c33r profile')
    profile(config, 'fex32', here)
    return config


def profile(config, variant, here=HERE):
    source.require(variant == 'fex32', 'Unknown c34r source profile')
    row = config['profiles'][variant]
    product = source.pinned_json(source.owned(here, row['path']), row['sha256'])
    source.require(product['schema'] == 1 and product['variant'] == variant and
                   len(product['product_source_postimages']) == row['files'] and
                   len(product['changes']) == row['changes'], 'c34r source profile count differs')
    before = source.pinned_json(source.owned(here, product['base_product_manifest']),
                                product['base_product_manifest_sha256'])['product_source_postimages']
    after = product['product_source_postimages']
    expected = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    source.require([change['path'] for change in product['changes']] == expected,
                   'c34r source change set differs')
    for change in product['changes']:
        name = source.relative(change['path'])
        source.require(change['before_sha256'] == before.get(name) and change['after_sha256'] == after.get(name),
                       'c34r source preimage/postimage differs')
        if name in after:
            path = source.owned(here, change['store'])
            source.require(path.stat().st_size == change['bytes'] and source.sha(path) == after[name],
                           'c34r source postimage content differs: ' + name)
    return product


def apply(config, variant, root, here=HERE):
    product = profile(config, variant, here)
    before = source.pinned_json(source.owned(here, product['base_product_manifest']),
                                product['base_product_manifest_sha256'])
    preimage = source.verify_product(root, before, len(before['product_source_postimages']))
    for row in product['changes']:
        path = Path(root) / row['path']
        if row['after_sha256'] is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            store = source.owned(here, row['store'])
            source.require(source.sha(store) == row['after_sha256'], 'c34r postimage changed during application')
            path.write_bytes(store.read_bytes())
    verified = source.verify_product(root, product, len(product['product_source_postimages']))
    return dict(status='C34R_EXACT_SOURCE_PROFILE_APPLIED', variant=variant, preimage=preimage,
                postimage=verified, profile_sha256=config['profiles'][variant]['sha256'])
