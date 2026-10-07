#!/usr/bin/env python3
"""Reuse the source FEX builder on the explicitly pinned GitHub ARM64 profile."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'support'))
import build_fex64 as fex
import native_stand
import candidate_source as source
import release_bytes


def inputs():
    pin = json.loads((HERE / 'recipe.lock.json').read_bytes())
    source.require(pin.get('schema') == 1 and pin['repository'] ==
                   'https://github.com/t0b1kent/hyperbridge.git', 'Recipe identity differs')
    for key in ['base_revision', 'candidate_revision']:
        source.require(type(pin[key]) is str and len(pin[key]) == 40 and
                       all(c in '0123456789abcdef' for c in pin[key]), 'Revision must be full SHA')
    source.relative(pin['candidate_directory'])
    source.relative(pin['candidate_order_file'])
    base = HERE / 'base'
    manifest = source.pinned_json(base / 'MANIFEST.json', pin['base_manifest_sha256'])
    source.require(manifest.get('reference_binaries') == {} and
                   type(manifest.get('files')) is dict, 'Source-only base manifest required')
    # All 61 patches already exist byte-for-byte in the pinned public repository.
    # Their mailbox headers need not be copied into a new publication packet.
    for name in ['repro109/fex64.lock.json', 'repro109/fex32.lock.json',
                 'repro109/tools.lock.json', 'repro109/check-build-srcdir.sh',
                 'repro109/check-arm64ec-dist.py']:
        row = manifest['files'][name]
        p = source.owned(base, name)
        source.require(type(row) is str and source.sha(p) == row,
                       'Base source file differs: ' + name)
    product = source.pinned_json(HERE / 'c9/PRODUCT-MANIFEST.json', pin['product_manifest_sha256'])
    engine = source.pinned_json(HERE / 'c9/ENGINE.json', pin['engine_sha256'])
    source.require(engine['environment'] == product['environment'] and len(engine['environment']) == 60,
                   'ENGINE environment differs from INTEGRATE product')
    source.supplement(HERE, pin)
    locks = {n: json.loads((base / 'repro109' / (n + '.lock.json')).read_bytes())
             for n in ['fex64', 'fex32']}
    mapping = json.loads((HERE / 'public-patches.json').read_bytes())
    wanted = {r['path'] for lock in locks.values() for r in lock['patches']}
    source.require(type(mapping) is dict and set(mapping) == wanted and len(mapping) == 61,
                   'Public patch mapping incomplete')
    for name in mapping.values():
        source.relative(name)
        source.require(name.startswith(('fex/patches/', 'fex/wow64/patches/')),
                       'Public patch mapping leaves the source series')
    for lock in locks.values():
        lock['public_patch_paths'] = mapping
    source.require([len(locks[n]['patches']) for n in ['fex64', 'fex32']] == [55, 61],
                   'r5 architecture patch counts differ')
    tools = json.loads((base / 'repro109/tools.lock.json').read_bytes())
    native_pin = json.loads((HERE / 'support/native-stand.lock.json').read_bytes())
    source.require(native_pin['revision'] == pin['base_revision'], 'Native builder pin differs')
    return pin, product, engine, locks, tools


def archive(out, variants):
    members = {}
    for variant in variants:
        for prefix in ['engine', 'licenses', 'native-stand']:
            directory = out / variant / prefix
            if not directory.exists():
                continue
            for path in directory.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    if prefix == 'native-stand' and path.name not in ('stand_runner', 'LICENSE', 'RESULT.json'):
                        continue
                    members[path.relative_to(out).as_posix()] = path
        for name in ['outputs.json', 'license-inputs.json', 'license-source-inputs.json',
                     'product-postimages.json', 'source-verification.json', 'PATCH-ORDER.json',
                     'pe-path-canonicalization.json', 'outputs.before-pe-paths.json']:
            path = out / variant / name
            if path.is_file():
                members[path.relative_to(out).as_posix()] = path
        for path in (out / variant / 'pe-path-preimages').glob('*.before'):
            source.require(path.is_file() and not path.is_symlink(), 'Foreign PE preimage')
            members[path.relative_to(out).as_posix()] = path
    source.require(any(n.endswith('.dll') for n in members), 'No component DLL outputs')
    members['ENGINE-environment.json'] = out / 'ENGINE-environment.json'
    target = out / 'fex-c9-unsigned.tar'
    with tarfile.open(target, 'x') as stream:
        for name, path in sorted(members.items()):
            source.require(path.stat().st_size <= 256 * 1024**2, 'Component archive member exceeds cap')
            stream.add(path, arcname=name, recursive=False)
    return dict(path=target.name, bytes=target.stat().st_size, sha256=source.sha(target), files=len(members))


def build(out, variants, stage='full', from_outputs=None):
    source.require(stage in ['full', 'inventory', 'patches', 'configure', 'compile', 'native-stand', 'admission'],
                   'Unknown source recipe stage')
    source.require(stage == 'full' or variants == ['fex64'], 'Stage matrix requires exactly FEX64')
    source.require((from_outputs is not None) == (stage == 'admission'),
                   'Admission requires compiled outputs; other stages must not receive them')
    fex.cloud_only()
    pin, product, engine, sealed, tools = inputs()
    source.require(not out.exists(), 'Preserve previous component result')
    out.mkdir(parents=True)
    result = dict(schema=1, status='STARTED', first_failure=None, variants={},
                  classification='SOURCE_BUILD_NOT_ACCEPTED_NOT_GOLDEN', install='skipped',
                  signing='NOT_PERFORMED', comparison='NOT_ENABLED', stands='NOT_RUN',
                  base_revision=pin['base_revision'], candidate_revision=pin['candidate_revision'],
                  product_manifest_sha256=pin['product_manifest_sha256'],
                  platform=pin['platform'], selected_variants=variants, selected_stage=stage)
    fex.HERE = HERE / 'base/repro109'
    fex.DEADLINE = time.monotonic() + pin['platform']['minutes'] * 60
    (out / 'ENGINE-environment.json').write_text(json.dumps(engine, indent=2) + '\n')
    try:
        for variant in variants:
            target = out / variant
            target.mkdir()
            if stage == 'inventory':
                result['variants'][variant] = dict(status='INVENTORY_ONLY_NOT_ACCEPTED',
                    postimages=len(product['product_source_postimages']), actual_source='NOT_ENABLED',
                    patches=len(sealed[variant]['patches']), compiler='NOT_ENABLED')
                continue
            if stage == 'admission':
                admitted = fex.admit_outputs(Path(from_outputs) / variant, target, variant)
                result['variants'][variant] = admitted
                continue
            lock = copy.deepcopy(sealed[variant])
            lock['repo_source_revision'] = pin['base_revision']
            for field in ['xcode', 'xcode_build', 'sdk', 'deployment_target', 'apple_clang_build', 'linker_lc']:
                lock[field] = pin['platform'][field]
            # The existing runner uses this job limit while retaining exact platform checks.
            lock['build_jobs'] = pin['platform']['jobs']
            lock['build_native_stand'] = variant == 'fex64'
            def overlay(stage, src, actual_lock, output, env):
                if stage == 'prepared':
                    checkout = src.parent / 'public-candidate'
                    fex.run(['git', 'init', '-q', str(checkout)], src.parent, output, 'candidate-init', env)
                    fex.run(['git', 'fetch', '-q', '--depth', '1', pin['repository'],
                             pin['candidate_revision']], checkout, output, 'candidate-fetch', env)
                    fex.run(['git', 'checkout', '-q', '--detach', 'FETCH_HEAD'], checkout, output,
                            'candidate-checkout', env)
                    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, text=True).strip()
                    source.require(head == pin['candidate_revision'], 'Loaded candidate revision differs')
                    def run(argv, name):
                        return fex.run(argv, src, output, name, env)
                    applied = source.apply(src, checkout / pin['candidate_directory'], pin,
                                           product, HERE, output, run)
                    actual_lock['patches'].extend(applied['order'])
                    return applied
                source.require(stage == 'submodules', 'Unknown source overlay stage')
                verified = source.verify_product(src, product)
                (output / 'product-postimages.json').write_text(json.dumps(verified, indent=2) + '\n')
                return verified
            stage_result = fex.build(target, lock, tools,
                source_overlay=overlay if variant == 'fex64' else None, stage=stage)
            if stage != 'full':
                result['variants'][variant] = stage_result
                continue
            canonical = release_bytes.canonicalize_outputs(target, variant)
            outputs = json.loads((target / 'outputs.json').read_bytes())
            source.require(outputs['ec_modules'] == (2 if variant == 'fex64' else 0) and
                           outputs['unique_ec_binaries'] == (1 if variant == 'fex64' else 0),
                           'ARM64EC output count differs')
            result['variants'][variant] = dict(status='BUILT_SOURCE_ONLY', files=len(outputs['files']),
                                                ec_modules=outputs['ec_modules'],
                                                unique_ec_binaries=outputs['unique_ec_binaries'],
                                                release_dll_sha256=canonical['expected_sha256'],
                                                release_bytes=canonical['status'])
        if stage == 'full':
            result['archive'] = archive(out, variants)
            result['status'] = 'BUILT_SOURCE_ONLY_NOT_ACCEPTED'
        else:
            result['status'] = 'STAGE_ONLY_NOT_ACCEPTED'
    except Exception as error:
        result.update(status='FAILED', first_failure=str(error)[:700])
        raise
    finally:
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-inputs', action='store_true')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--only', choices=['fex64', 'fex32'])
    parser.add_argument('--stage', default='full',
                        choices=['full', 'inventory', 'patches', 'configure', 'compile', 'native-stand', 'admission'])
    parser.add_argument('--from-outputs', type=Path)
    args = parser.parse_args()
    if args.check_inputs:
        pin, product, engine, locks, _ = inputs()
        print(json.dumps(dict(status='PLAN_ONLY', base=pin['base_revision'], candidate=pin['candidate_revision'],
                              patches64=len(locks['fex64']['patches']), patches32=len(locks['fex32']['patches']),
                              postimages=len(product['product_source_postimages']), environment=len(engine['environment']),
                              builds=0, downloads=0, install='skipped')))
        return 0
    if args.out is None:
        parser.error('--out is required for a cloud build')
    try:
        build(args.out.resolve(), [args.only] if args.only else ['fex64', 'fex32'],
              stage=args.stage, from_outputs=args.from_outputs)
        return 0
    except Exception as error:
        print('FEX source build failed: ' + str(error)[:700], file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
