#!/usr/bin/env python3
"""Apply sealed c33r postimages after the exact, separately pinned legacy source profiles."""
import json
from pathlib import Path
import re

import candidate_source as source

HERE = Path(__file__).resolve().parent


def read_config(pin, here=HERE):
    config = pin.get('release111')
    if config is None:
        return None
    source.require(config.get('schema') == 1 and set(config['profiles']) == {'fex32', 'fex64'},
                   'c33r profile selection differs')
    compiler = config['compiler']
    source.require(compiler['version'] == '20260908' and compiler['clang'] == '23.1.1' and
                   compiler['size'] == 124244100 and compiler['sha256'] ==
                   'd1dc5d1ecf3a3ced5ed5544c72f1acd0c8e84eb3024d520ecc6b143eec62a149',
                   'c33r LLVM23 compiler pin differs')
    engine = source.pinned_json(source.owned(here, config['engine']), config['engine_sha256'])
    source.require(type(engine['environment']) is dict, 'c33r ENGINE environment differs')
    for variant in config['profiles']:
        profile(config, variant, here)
    return config


def profile(config, variant, here=HERE):
    source.require(variant in ('fex32', 'fex64'), 'Unknown c33r source profile')
    row = config['profiles'][variant]
    product = source.pinned_json(source.owned(here, row['path']), row['sha256'])
    source.require(product['schema'] == 1 and product['variant'] == variant and
                   len(product['product_source_postimages']) == row['files'] and
                   len(product['changes']) == row['changes'], 'c33r source profile count differs')
    before = source.pinned_json(source.owned(here, product['base_product_manifest']),
                                product['base_product_manifest_sha256'])['product_source_postimages']
    after = product['product_source_postimages']
    expected = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
    source.require([change['path'] for change in product['changes']] == expected,
                   'c33r source change set differs')
    for change in product['changes']:
        name = source.relative(change['path'])
        source.require(change['before_sha256'] == before.get(name) and change['after_sha256'] == after.get(name),
                       'c33r source preimage/postimage differs')
        if name in after:
            path = source.owned(here, change['store'])
            source.require(path.stat().st_size == change['bytes'] and source.sha(path) == after[name],
                           'c33r source postimage content differs: ' + name)
    return product


def apply(config, variant, root, here=HERE):
    product = profile(config, variant, here)
    before = source.pinned_json(source.owned(here, product['base_product_manifest']),
                                product['base_product_manifest_sha256'])
    # Whole-tree verification, including rejection of unexpected files and
    # symlinks, happens before any postimage can replace a source file.
    preimage = source.verify_product(root, before, len(before['product_source_postimages']))
    for row in product['changes']:
        path = Path(root) / row['path']
        if row['after_sha256'] is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            data = source.owned(here, row['store']).read_bytes()
            source.require(source.sha(source.owned(here, row['store'])) == row['after_sha256'],
                           'c33r postimage changed during application')
            path.write_bytes(data)
    verified = source.verify_product(root, product, len(product['product_source_postimages']))
    return dict(status='C33R_EXACT_SOURCE_PROFILE_APPLIED', variant=variant, preimage=preimage,
                postimage=verified, profile_sha256=config['profiles'][variant]['sha256'])


def build_fields(config, variant, here=HERE):
    product = profile(config, variant, here)
    compiler = config['compiler']
    fields = {key: value for key, value in config['native_platform'].items() if key != 'jobs'}
    fields.update(llvm_mingw_version=compiler['version'], llvm_mingw_url=compiler['url'],
                  llvm_mingw_sha256=compiler['sha256'], llvm_mingw_size=compiler['size'],
                  pe_link_timestamp=product['pe_link_timestamp'], build_jobs=config['native_platform']['jobs'])
    return fields


def engine(config, here=HERE):
    return source.pinned_json(source.owned(here, config['engine']), config['engine_sha256'])
