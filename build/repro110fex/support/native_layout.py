"""Bind the accepted symbolic audit to exact known Unix bytes, with a pinned ld."""
import hashlib
import json
from pathlib import Path
import re
import struct

HERE = Path(__file__).resolve().parent


def reject(note, expected, actual):
    raise ValueError(note+'; expected='+repr(expected)[:600]+'; actual='+repr(actual)[:600])


def policy():
    return json.loads((HERE / 'native-layout.lock.json').read_text())


def build_version(data):
    if data[:4] != b'\xcf\xfa\xed\xfe' or len(data) < 32:
        reject('expected thin ARM64 Mach-O64', 'cffaedfe header and >=32 bytes', (data[:4].hex(), len(data)))
    if struct.unpack_from('<I', data, 4)[0] != 0x0100000c:
        reject('foreign Mach-O CPU', 0x0100000c, struct.unpack_from('<I', data, 4)[0])
    count, total = struct.unpack_from('<II', data, 16)
    limit = 32 + total
    if count > 1024 or limit > len(data):
        reject('invalid Mach-O load commands', 'count<=1024 and limit<=file bytes', (count, limit, len(data)))
    offset, found = 32, []
    for _ in range(count):
        if offset + 8 > limit:
            reject('truncated load command header', 'offset+8<=limit', (offset, limit))
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or size % 8 or offset + size > limit:
            reject('invalid load command size', 'size>=8, aligned8, offset+size<=limit', (size, offset, limit))
        if command == 0x32:
            if size < 24:
                reject('short LC_BUILD_VERSION', 'size>=24', size)
            platform, minimum, sdk, count_tools = struct.unpack_from('<IIII', data, offset+8)
            if size != 24 + 8 * count_tools:
                reject('invalid LC_BUILD_VERSION tools', 24+8*count_tools, size)
            version = lambda v: '.'.join(map(str, (v >> 16, (v >> 8) & 255, v & 255)))
            tools = [struct.unpack_from('<II', data, offset+24+i*8) for i in range(count_tools)]
            found.append(dict(platform=platform, minimum=version(minimum), sdk=version(sdk),
                              tools=[dict(tool=t, version=version(v)) for t, v in tools],
                              offset=offset, raw_hex=data[offset:offset+size].hex()))
        offset += size
    if offset != limit or len(found) != 1:
        reject('expected exactly one LC_BUILD_VERSION', (limit, 1), (offset, len(found)))
    return found[0]


def verify_linker(raw, expected_lc=None):
    # ld -v uses the project number, while LC_BUILD_VERSION stores a version triplet.
    # The real fex5 log prints PROJECT:ld-1267, not the previously assumed ld-1267.0.
    expected_lc = expected_lc or policy()['ld']
    expected = expected_lc.split('.')[0]
    tokens = re.findall(r'(?<![\w.-])ld-(\d+)(?:\.(\d+))?(?:\.(\d+))?(?![\w.-])', raw)
    wanted = expected_lc.split('.')
    # Missing trailing zero components are normal in Apple's PROJECT banner.
    # Preserve lexical checks too: 1267.01 is not silently normalized to 1267.1.
    actual = [part or '0' for part in tokens[0]] if len(tokens) == 1 else []
    if len(wanted) != 3 or actual != wanted:
        reject('Apple linker differs', {'project': expected, 'LC_BUILD_VERSION': expected_lc}, raw)
    return {'project': expected, 'raw_components': list(tokens[0]),
            'expected_lc_build_version_ld': expected_lc,
            'raw_sha256': hashlib.sha256(raw.encode()).hexdigest()}


def verify_rows(variant, rows, target, reference):
    lock = policy()
    known = {row['path']: row for row in lock['native'] if row['variant'] == variant}
    expected_pe = {'fex64': 2, 'fex32': 1}
    if variant not in expected_pe or len(known) != 3 or len(rows) != 3+expected_pe[variant]:
        reject('native/PE coverage differs', 'known variant, 3 native and 2/1 PE', (variant, len(known), len(rows)))
    paths = [row['path'] for row in rows]
    if len(set(paths)) != len(paths):
        reject('duplicate comparison output', len(paths), len(set(paths)))
    accepted = []
    for row in rows:
        name = row['path']
        if name.endswith('.dll'):
            if row['reference_sha256'] != row['built_sha256']:
                reject('candidate PE differs: '+name, row['reference_sha256'], row['built_sha256'])
            continue
        item = known.pop(name, None)
        if item is None:
            reject('unknown native layout: '+name, sorted(known), name)
        for key in ['reference_sha256', 'built_sha256']:
            if row[key] != item[key]:
                reject('known byte audit differs: '+name+' '+key, item[key], row[key])
        versions = {}
        for key, path in [('built', target/'engine'/name), ('reference', reference/name)]:
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != item['built_sha256' if key == 'built' else 'reference_sha256']:
                reject('actual bytes differ from audit: '+name, item['built_sha256' if key == 'built' else 'reference_sha256'], hashlib.sha256(data).hexdigest())
            value = build_version(data)
            expected = dict(platform=1, minimum=lock['deployment_target'],
                            sdk=lock['sdk' if key == 'built' else 'reference_sdk'],
                            tools=[dict(tool=3, version=lock['ld' if key == 'built' else 'reference_ld'])])
            if any(value[k] != v for k, v in expected.items()):
                reject('LC_BUILD_VERSION differs: '+name+' '+key, expected, value)
            versions[key] = value
        accepted.append(dict(path=name, acceptance='EXACT_KNOWN_LAYOUT',
                             symbolic_targets=item['symbolic_targets'], other_words=item['other_words'],
                             changed_functions=item['changed_functions'], functions=item['functions'],
                             versions=versions))
    if known:
        reject('missing native outputs', [], sorted(known))
    return dict(classification=lock['classification'], native=accepted,
                pe_byte_exact=expected_pe[variant], audit_raw_sha256=lock['native_audit_raw_sha256'],
                policy_sha256=hashlib.sha256((HERE/'native-layout.lock.json').read_bytes()).hexdigest(),
                limits=lock['limits'])


def record_source_changed_rows(variant, rows, target, reference, cloud=None):
    """0161 changes source: enforce PE truth, preserve native audit without accepting new bytes."""
    lock = policy()
    native = {row['path']: row for row in lock['native'] if row['variant'] == variant}
    pe = {'fex64': {'fex/aarch64-windows/xtajit64.dll', 'wine/lib/wine/aarch64-windows/libarm64ecfex.dll'},
          'fex32': {'fex/aarch64-windows/xtajit.dll'}}
    paths = [row['path'] for row in rows]
    if variant not in pe or len(native) != 3 or len(paths) != len(set(paths)) or set(paths) != set(native) | pe[variant]:
        reject('0161 native/PE coverage differs', 'three native and explicit 2/1 PE views', (variant, paths))
    recorded = []
    known_bytes = True
    for row in rows:
        name = row['path']
        actual = {}
        for key, path in [('built', target / 'engine' / name), ('reference', reference / name)]:
            data = path.read_bytes()
            actual[key] = hashlib.sha256(data).hexdigest()
            if actual[key] != row[key + '_sha256']:
                reject('0161 actual comparison bytes differ: ' + name, row[key + '_sha256'], actual[key])
        if name in pe[variant]:
            if actual['built'] != actual['reference']:
                reject('candidate PE differs: ' + name, actual['reference'], actual['built'])
        else:
            known_bytes &= all(actual[key] == native[name][key + '_sha256'] for key in ['built', 'reference'])
            recorded.append(dict(path=name, reference_sha256=actual['reference'], built_sha256=actual['built'],
                                 acceptance='NOT_ACCEPTED_SOURCE_CHANGED',
                                 versions={'built': build_version((target / 'engine' / name).read_bytes()),
                                           'reference': build_version((reference / name).read_bytes())}))
    if cloud is not None:
        exact = 0
        for item in recorded:
            versions = item['versions']['built']
            expected = dict(platform=1, minimum=cloud['deployment_target'] + '.0',
                            sdk=cloud['sdk'] + '.0', tools=[dict(tool=3, version=cloud['ld'])])
            if any(versions[key] != value for key, value in expected.items()):
                reject('Xcode Cloud LC_BUILD_VERSION differs: ' + item['path'], expected, versions)
            same = item['built_sha256'] == item['reference_sha256']
            item['acceptance'] = 'BYTE_EXACT_R2' if same else 'NOT_ACCEPTED_SOURCE_AND_PLATFORM_CHANGED'
            exact += int(same)
        return dict(classification='PE_BYTE_EXACT_XCODE_NATIVE_COMPARISON_NOT_GOLDEN',
                    native=recorded, pe_byte_exact=len(pe[variant]), native_accepted=exact,
                    native_byte_exact=exact, native_different=len(recorded) - exact,
                    comparison='PRESENT_RAW_FUNCTION_SECTION_COMPARISON',
                    runtime='NOT_ENABLED', stands='NOT_ENABLED', causal_claim='NOT_ENABLED',
                    profile_sha256=hashlib.sha256((HERE / 'xcode-cloud.lock.json').read_bytes()).hexdigest())
    if known_bytes:
        return verify_rows(variant, rows, target, reference)
    return dict(classification='PE_BYTE_EXACT_NATIVE_SOURCE_CHANGED_AUDIT_PENDING_NOT_GOLDEN',
                native=recorded, pe_byte_exact=len(pe[variant]), native_accepted=0,
                comparison='PRESENT_RAW_FUNCTION_SECTION_COMPARISON',
                policy_sha256=hashlib.sha256((HERE / 'native-layout.lock.json').read_bytes()).hexdigest(),
                runtime='NOT_ENABLED', stands='NOT_ENABLED')
