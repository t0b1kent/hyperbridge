"""Preserve source notices from FEX, including bundled non-submodule code."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


BUNDLED = ('FEXCore', 'External/tiny-json', 'External/cephes')
SOFTFLOAT = 'External/SoftFloat-3e'
NOTICE_TOKENS = (b'Redistribution and use', b'Redistributions in binary form',
                 b'THIS SOFTWARE IS PROVIDED')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_path(root, relative):
    path = PurePosixPath(relative)
    if (not isinstance(relative, str) or path.is_absolute() or
            str(path) != relative or any(part in ('.', '..') for part in path.parts)):
        raise ValueError('invalid source notice path')
    selected = root / relative
    for node in (selected, *selected.parents):
        if node.is_symlink():
            raise ValueError('source notice symlink: ' + relative)
        if node == root:
            break
    if not selected.resolve().is_relative_to(root.resolve()):
        raise ValueError('source notice escape: ' + relative)
    return selected


def collect_source_notices(src, out, lock):
    """Keep the existing license-inputs map, with a separate source byte map.

    All copies are exact bytes. SoftFloat has no standalone LICENSE: retain
    every distinct leading C comment, together with every C/H source hash.
    This inventories source notices; it does not establish final link coverage.
    """
    src, out = Path(src), Path(out)
    components = [('FEX', '')]
    components.extend((row['path'], row['path']) for row in lock['submodules'])
    components.extend((name, name) for name in BUNDLED)
    names = [name for name, _ in components] + [SOFTFLOAT]
    if len(set(names)) != len(names):
        raise ValueError('duplicate source notice component')
    receipt, inputs = {}, []

    def preserve(component, name, body):
        relative = 'licenses/' + component + '/' + name
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        if target.read_bytes() != body:
            raise ValueError('source notice copy differs')
        return relative, digest(body)

    for component, relative in components:
        source = source_path(src, relative) if relative else src
        if source.is_symlink() or not source.is_dir():
            raise ValueError('missing source notice component: ' + component)
        records = {}
        for candidate in sorted(source.iterdir()):
            if not candidate.name.lower().startswith(('license', 'copying')):
                continue
            path = candidate.relative_to(src).as_posix()
            candidate = source_path(src, path)
            if not candidate.is_file():
                continue
            body = candidate.read_bytes()
            if not body:
                raise ValueError('empty source notice: ' + path)
            copied, sha = preserve(component, candidate.name, body)
            records[candidate.name] = sha
            inputs.append({'component': component, 'path': path,
                           'source_sha256': sha, 'notice': copied, 'notice_sha256': sha})
        if not records:
            raise ValueError('license input missing: ' + component)
        receipt[component] = records

    source = source_path(src, SOFTFLOAT)
    candidates = sorted(path for path in source.rglob('*') if path.suffix in ('.c', '.h'))
    if not candidates or len(candidates) > 512:
        raise ValueError('SoftFloat source notice census outside bounds')
    records = {}
    for candidate in candidates:
        path = candidate.relative_to(src).as_posix()
        candidate = source_path(src, path)
        if not candidate.is_file() or candidate.stat().st_size > 512 * 1024:
            raise ValueError('SoftFloat source notice input invalid: ' + path)
        body = candidate.read_bytes()
        match = re.match(rb'\s*(/\*.*?\*/)', body, re.S)
        if not match or any(token not in match[1] for token in NOTICE_TOKENS):
            raise ValueError('SoftFloat leading notice incomplete: ' + path)
        notice = match[1]
        sha = digest(notice)
        name = 'NOTICE-' + sha + '.txt'
        copied, copied_sha = preserve(SOFTFLOAT, name, notice)
        records[name] = copied_sha
        inputs.append({'component': SOFTFLOAT, 'path': path,
                       'source_sha256': digest(body), 'notice': copied,
                       'notice_sha256': copied_sha})
    receipt[SOFTFLOAT] = records
    (out / 'license-inputs.json').write_text(json.dumps(receipt, indent=2) + '\n')
    (out / 'license-source-inputs.json').write_text(json.dumps({
        'schema': 1, 'coverage': 'SOURCE_NOTICES_NOT_LINK_OR_LEGAL_AUDIT',
        'components': len(receipt), 'inputs': inputs,
    }, indent=2) + '\n')
    return receipt
