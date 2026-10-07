"""Pinned public tail plus the two product source tests; no vendor execution."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def relative(value):
    require(type(value) is str and bool(value) and '\\' not in value,
            'Expected a portable relative path')
    p = PurePosixPath(value)
    require(not p.is_absolute() and all(x not in ('', '.', '..') for x in value.split('/'))
            and not any(x in value for x in ':*?"<>|'), 'Unsafe relative path')
    return value


def owned(root, name):
    root = Path(root).resolve()
    p = root / relative(name)
    require(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root),
            'Missing or foreign input: ' + name)
    return p


def pinned_json(path, digest):
    require(re.fullmatch('[a-f0-9]{64}', digest or '') is not None and
            Path(path).stat().st_size <= 2 * 1024**2 and sha(path) == digest,
            'Input JSON pin differs')
    value = json.loads(Path(path).read_bytes())
    require(type(value) is dict, 'Input JSON must be an object')
    return value


def candidate(root, pin, product):
    order = owned(root, pin['candidate_order_file'])
    value = pinned_json(order, pin['candidate_manifest_sha256'])
    require(value.get('schema') == 1 and
            value.get('base_series_sha256') == product['public_base_series_sha256'],
            'Candidate base series differs')
    rows = value.get('patches')
    require(type(rows) is list and len(rows) == pin['candidate_patch_count'],
            'Candidate patch count differs')
    names = set()
    for row in rows:
        require(type(row) is dict and set(row) == {'file', 'sha256'},
                'Candidate patch row differs')
        name = relative(row['file'])
        require('/' not in name and name.endswith('.patch') and name not in names,
                'Duplicate or nonlocal candidate patch')
        require(re.fullmatch('[a-f0-9]{64}', row['sha256'] or '') is not None and
                sha(owned(root, name)) == row['sha256'], 'Candidate patch SHA differs')
        names.add(name)
    return rows


def supplement(root, pin):
    source = owned(root, pin['supplement_source'])
    require(sha(source) == pin['supplement_source_sha256'], 'Supplement source pin differs')
    raw = source.read_bytes()
    chunks = re.split(rb'(?=^diff --git )', raw, flags=re.M)
    selected = []
    for name in pin['supplement_files']:
        name = relative(name)
        prefix = ('diff --git a/' + name + ' b/' + name + '\n').encode()
        found = [c for c in chunks if c.startswith(prefix)]
        require(len(found) == 1 and b'new file mode 100644\n' in found[0] and
                b'--- /dev/null\n' in found[0], 'Supplement must add each source test exactly once')
        selected.append(found[0])
    require(len(set(pin['supplement_files'])) == len(selected) == 2,
            'Exactly two distinct product source tests required')
    return b''.join(selected)


def inventory(root):
    root = Path(root).resolve()
    files = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '.git')
        require(not any((Path(directory) / d).is_symlink() for d in dirs),
                'Foreign source directory symlink')
        for name in sorted(names):
            if name == '.DS_Store' or name == '.git':
                continue
            p = Path(directory) / name
            require(p.is_file() and not p.is_symlink(), 'Foreign source file')
            files[p.relative_to(root).as_posix()] = sha(p)
    return files


def verify_product(source, product):
    expected = product['product_source_postimages']
    require(type(expected) is dict and len(expected) == 6928, 'Product postimages incomplete')
    actual = inventory(source)
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = sorted(n for n in set(actual) & set(expected) if actual[n] != expected[n])
    require(not missing and not extra and not changed,
            'Product postimages differ: missing=' + repr(missing[:8]) +
            '; extra=' + repr(extra[:8]) + '; changed=' + repr(changed[:8]))
    raw = ''.join(n + '\t' + actual[n] + '\n' for n in sorted(actual)).encode()
    return dict(status='PASS_EXACT_PRODUCT_SOURCE', files=len(actual),
                digest=hashlib.sha256(raw).hexdigest(), missing=0, extra=0, changed=0)


def apply(source, tail_root, pin, product, recipe_root, out, run):
    """The source is an owned copy. run(argv, label) saves full bounded git output."""
    out = Path(out)
    rows = candidate(tail_root, pin, product)
    for number, row in enumerate(rows, 1):
        patch = owned(tail_root, row['file'])
        run(['git', 'apply', '--check', '--index', str(patch)], f'c9-check-{number:02d}')
        run(['git', 'apply', '--index', '--whitespace=nowarn', str(patch)], f'c9-apply-{number:02d}')
    raw = supplement(recipe_root, pin)
    path = out / 'c9-source-tests.patch'
    with path.open('xb') as stream:
        stream.write(raw)
    run(['git', 'apply', '--check', '--index', str(path)], 'c9-tests-check')
    run(['git', 'apply', '--index', str(path)], 'c9-tests-apply')
    order = [dict(path='candidate/' + r['file'], sha256=r['sha256']) for r in rows]
    order.append(dict(path='candidate/c9-source-tests.patch', sha256=sha(path)))
    result = dict(schema=1, status='APPLIED_AWAITING_SUBMODULE_POSTIMAGES',
                  revision=pin['candidate_revision'], directory=pin['candidate_directory'],
                  order_file=pin['candidate_order_file'], manifest_sha256=pin['candidate_manifest_sha256'],
                  public_patch_count=len(rows), supplement_files=pin['supplement_files'],
                  supplement_source_sha256=pin['supplement_source_sha256'],
                  supplement_sha256=sha(path), order=order)
    (out / 'c9-source-apply.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
