"""Named post-link canonicalization of the pinned llvm-mingw libc++abi paths.

Only six equal-length strings in the read-only PE .rdata section may change.
The complete resulting DLL must match the release hash before any file write.
No signed PE, code, headers, load commands, or installed runtime is modified.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct

REFERENCE_HASHES = {
    'fex64': 'ed14b28a89675c4544e84da2a4c271b3cd7c6ac61becbe804aa68cb96553147d',
    'fex32': 'aef436aacd966ce9e55ccc1e68706f4af2d2192da923cf0ae17b682580742025',
}
SOURCE = b'Users/runner'
CANONICAL = b'build/xxxxxx'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def positions(raw, needle):
    start, result = 0, []
    while True:
        at = raw.find(needle, start)
        if at < 0:
            return result
        result.append(at)
        require(len(result) <= 6, 'Expected six pinned libc++abi source paths')
        start = at + len(needle)


def normalize(raw, expected_sha256):
    require(type(raw) is bytes and len(raw) >= 64, 'Invalid PE input size')
    require(len(SOURCE) == len(CANONICAL) == 12, 'Path replacement must preserve length')
    require(raw[:2] == b'MZ', 'Expected PE DLL')
    nt = struct.unpack_from('<I', raw, 0x3c)[0]
    require(64 <= nt <= len(raw) - 24 and raw[nt:nt + 4] == b'PE\0\0', 'Invalid PE header')
    count, optional_size = struct.unpack_from('<H', raw, nt + 6)[0], struct.unpack_from('<H', raw, nt + 20)[0]
    optional = nt + 24
    require(count >= 1 and optional_size >= 152 and
            optional + optional_size + count * 40 <= len(raw), 'Invalid PE section table')
    require(struct.unpack_from('<H', raw, optional)[0] == 0x20b, 'Expected PE32+ translator DLL')
    certificate = struct.unpack_from('<II', raw, optional + 112 + 4 * 8)
    require(certificate == (0, 0), 'Refuse signed PE input')
    selected, other_ranges = [], []
    for number in range(count):
        offset = optional + optional_size + number * 40
        name = raw[offset:offset + 8].rstrip(b'\0')
        size, start = struct.unpack_from('<II', raw, offset + 16)
        flags = struct.unpack_from('<I', raw, offset + 36)[0]
        require(start <= len(raw) and size <= len(raw) - start, 'Section exceeds PE file')
        if name == b'.rdata':
            require(flags & 0x40000000 and not flags & (0x80000000 | 0x20000000),
                    'Path data must be read-only and non-executable')
            selected.append((start, start + size))
        elif size:
            other_ranges.append((start, start + size))
    require(len(selected) == 1, 'Expected one .rdata section')
    lo, hi = selected[0]
    require(all(hi <= start or end <= lo for start, end in other_ranges),
            '.rdata overlaps another material section')
    offsets = positions(raw, SOURCE)
    input_sha256 = sha(raw)
    already = input_sha256 == expected_sha256
    require(already or len(offsets) == 6, 'Expected six pinned libc++abi source paths')
    require(all(lo <= offset and offset + len(SOURCE) <= hi for offset in offsets),
            'Path occurrence outside .rdata')
    normalized = raw if already else raw.replace(SOURCE, CANONICAL)
    output_sha256 = input_sha256 if already else sha(normalized)
    require(output_sha256 == expected_sha256, 'Release DLL SHA256 differs after path canonicalization')
    changed = [] if already else [offset + i for offset in offsets for i, (before, after)
                                in enumerate(zip(SOURCE, CANONICAL)) if before != after]
    return normalized, dict(
        step='llvm-mingw-libcxxabi-path-canonicalization',
        status='ALREADY_RELEASE_BYTES' if already else 'CANONICALIZED_RELEASE_BYTES',
        input_sha256=input_sha256, output_sha256=output_sha256, expected_sha256=expected_sha256,
        bytes=len(raw), source_occurrences=len(offsets), changed_bytes=len(changed),
        changed_offsets=changed, section='.rdata', source_hex=SOURCE.hex(),
        canonical_hex=CANONICAL.hex(), header_and_code_unchanged=True)


def owned_file(root, relative):
    require(type(relative) is str, 'Invalid output path type')
    name = PurePosixPath(relative)
    require(not name.is_absolute() and '..' not in name.parts and
            name.as_posix() == relative and name.parts[0] in ('fex', 'wine'), 'Foreign output path')
    path = root / 'engine' / relative
    require(path.is_file() and not path.is_symlink() and
            path.resolve().is_relative_to((root / 'engine').resolve()), 'Missing or foreign DLL output')
    return path


def canonicalize_outputs(target, variant):
    require(variant in REFERENCE_HASHES, 'Unknown translator variant')
    target = Path(target).resolve()
    manifest_path = target / 'outputs.json'
    manifest_raw = manifest_path.read_bytes()
    outputs = json.loads(manifest_raw)
    require(type(outputs) is dict and type(outputs.get('files')) is dict, 'Invalid output manifest')
    primary = 'fex/aarch64-windows/' + ('xtajit64.dll' if variant == 'fex64' else 'xtajit.dll')
    require(primary in outputs['files'], 'Primary translator DLL missing')
    dlls = sorted(name for name in outputs['files'] if name.endswith('.dll'))
    require(1 <= len(dlls) <= 2, 'Unexpected DLL output scope')
    primary_raw = owned_file(target, primary).read_bytes()
    normalized, record = normalize(primary_raw, REFERENCE_HASHES[variant])
    primary_sha = record['input_sha256']
    plans = []
    for name in dlls:
        path = owned_file(target, name)
        raw = path.read_bytes()
        row = outputs['files'][name]
        require(type(row) is dict and raw == primary_raw and
                row.get('bytes') == len(raw) and row.get('sha256') == primary_sha,
                'DLL peer or manifest bytes differ before canonicalization')
        plans.append((name, path, raw, normalized, record))
    backups = target / 'pe-path-preimages'
    require(not backups.exists(), 'Preserve previous path-canonicalization evidence')
    backups.mkdir()
    for name, path, raw, normalized, record in plans:
        require(path.read_bytes() == raw, 'Output drift before path canonicalization')
        if normalized != raw:
            backup = backups / (name.replace('/', '__') + '.before')
            with backup.open('xb') as stream:
                stream.write(raw)
            require(backup.read_bytes() == raw, 'Preimage drift')
            with path.open('wb') as stream:
                stream.write(normalized)
        require(sha(path.read_bytes()) == record['expected_sha256'], 'Written DLL hash differs')
        outputs['files'][name]['sha256'] = record['output_sha256']
    with (target / 'outputs.before-pe-paths.json').open('xb') as stream:
        stream.write(manifest_raw)
    receipt = dict(schema=1, variant=variant, status='PASS_RELEASE_DLL_BYTES',
                   expected_sha256=REFERENCE_HASHES[variant],
                   files=[dict(path=name, **record) for name, _, _, _, record in plans],
                   install='skipped', signatures='NOT_MODIFIED')
    with (target / 'pe-path-canonicalization.json').open('x') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
    outputs['release_path_canonicalization'] = receipt
    manifest_path.write_text(json.dumps(outputs, indent=2) + '\n')
    return receipt


def verify(out, variants):
    for variant in variants:
        root = Path(out) / variant
        receipt = json.loads((root / 'pe-path-canonicalization.json').read_bytes())
        require(receipt.get('status') == 'PASS_RELEASE_DLL_BYTES' and
                receipt.get('expected_sha256') == REFERENCE_HASHES[variant],
                'Missing successful release path canonicalization')
        require(type(receipt.get('files')) is list and receipt['files'], 'Missing checked DLLs')
        for row in receipt['files']:
            require(sha(owned_file(root, row['path']).read_bytes()) == REFERENCE_HASHES[variant],
                    'Release DLL changed after canonicalization')
    return 0


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify', type=Path, required=True)
    parser.add_argument('--only', choices=['', 'fex64', 'fex32'], default='')
    args = parser.parse_args()
    try:
        return verify(args.verify, [args.only] if args.only else ['fex64', 'fex32'])
    except Exception as error:
        print('Release DLL byte check failed: ' + str(error)[:700], file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
