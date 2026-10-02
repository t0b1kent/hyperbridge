"""Conservative recognition of classes already recorded in stage1 FINDINGS."""
import hashlib
import json
import pathlib

def load(path):
    path = pathlib.Path(path)
    document = json.loads(path.read_text())
    requested = {}
    for event in document['events']:
        kind = event['classification']
        if kind.startswith(('LIKELY_FEX: MXCSR', 'LIKELY_FEX: canonical NaN', 'ISA_UNDEFINED_DEST:')):
            requested.setdefault(event['source'], {})[event['line']] = event
    patterns = {}
    for source, lines in requested.items():
        digest = hashlib.sha256()
        with open(source, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b''): digest.update(chunk)
        if digest.hexdigest() != document['raw_sha256'][source]:
            raise ValueError('FINDINGS raw source changed: '+source)
        with open(source) as stream:
            for number, line in enumerate(stream, 1):
                if number in lines:
                    raw = json.loads(line)
                    patterns.setdefault(raw['code'], []).append((lines[number], raw))
    return patterns, hashlib.sha256(path.read_bytes()).hexdigest()

def nan_sign_only(left, right):
    a, b = bytes.fromhex(left), bytes.fromhex(right)
    if len(a) != len(b): return False
    if a == b: return True
    for width, pair in [(4, {0x7fc00000, 0xffc00000}),
                        (8, {0x7ff8000000000000, 0xfff8000000000000})]:
        if len(a) % width: continue
        if all(a[i:i+width] == b[i:i+width] or
               {int.from_bytes(a[i:i+width], 'little'), int.from_bytes(b[i:i+width], 'little')} == pair
               for i in range(0, len(a), width)):
            return True
    return False

def classify(patterns, code, classes, reference, native):
    for event, raw in patterns.get(code, []):
        kind = event['classification']
        original_ref, original_native = raw['reference'], raw['native']
        if kind.startswith('LIKELY_FEX: MXCSR') and classes == ['mxcsr']:
            if (reference['mxcsr'], int(native['mxcsr'], 0)) == (original_ref['mxcsr'], int(original_native['mxcsr'], 0)):
                return 'mxcsr', event
        if kind.startswith('LIKELY_FEX: canonical NaN') and classes and set(classes) <= {'xmm', 'written_memory'}:
            xmm = all(nan_sign_only(a, b) for a, b in zip(reference['xmm'], native['xmm']))
            rm, nm = reference['written_memory'], native['written_memory']
            memory = len(rm) == len(nm) and all(a[0] == b[0] and nan_sign_only(a[1], b[1]) for a, b in zip(rm, nm))
            if xmm and memory: return 'canonical_nan_sign', event
        if kind.startswith('ISA_UNDEFINED_DEST:') and classes == ['gpr']:
            changes = {k: (v, int(native['regs'][k], 0)) for k, v in reference['regs'].items() if v != int(native['regs'][k], 0)}
            original = {k: (v, int(original_native['regs'][k], 0)) for k, v in original_ref['regs'].items() if v != int(original_native['regs'][k], 0)}
            if changes == original: return 'bsf_bsr_undefined_dest', event
    return None, None
