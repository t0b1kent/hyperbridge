"""Only manually adjudicated entries may become KNOWN. Exact deltas required."""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / 'stand-diff-20260930'))
from evidence_io import open_binary


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def signature(classes, reference, native):
    result = {'classes': sorted(classes)}
    for name in classes:
        if name in ('xmm', 'ymm_hi', 'written_memory', 'memory_page_sha256'):
            a, b = reference[name], native[name]
            if name in ('xmm', 'ymm_hi'):
                result[name] = [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x != y]
            else:
                expected, actual = dict(a), dict(b)
                result[name] = [(address, expected.get(address), actual.get(address))
                                for address in sorted(set(expected) | set(actual))
                                if expected.get(address) != actual.get(address)]
        elif name in ('mxcsr', 'rip', 'rflags'):
            result[name] = [reference[name], int(native[name], 0)]
        elif name == 'gpr':
            result[name] = [(k, v, int(native['regs'][k], 0)) for k, v in reference['regs'].items()
                            if v != int(native['regs'][k], 0)]
        else:
            result[name] = [reference, native]
    return digest(result)


class Registry:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.sha256 = hashlib.sha256(self.path.read_bytes()).hexdigest()
        document = json.loads(self.path.read_text())
        if document['admission'] != 'MANUAL_OWNER_ADJUDICATION_ONLY':
            raise ValueError('manual owner adjudication required')
        self.entries = {}
        evidence = {}
        for entry in document['entries']:
            entry = {**document['provenance'], **entry}
            path = pathlib.Path(entry['baseline_evidence'])
            if path not in evidence:
                with open_binary(path) as stream:
                    raw = stream.read()
                if hashlib.sha256(raw).hexdigest() != entry['baseline_sha256']:
                    raise ValueError('adjudicated evidence drift')
                evidence[path] = {r['state']['sequence']: r for r in map(json.loads, raw.splitlines())}
            row = evidence[path][entry['sequence']]
            key = entry['game'], entry['sequence']
            if key in self.entries:
                raise ValueError('duplicate manual entry')
            self.entries[key] = dict(entry, state_sha256=digest(row['state']),
                                     code_sha256=hashlib.sha256(bytes.fromhex(row['code'])).hexdigest(),
                                     difference_sha256=signature(row['classes'], row['reference'], row['native']))

    def classify(self, game, state, code, classes, reference, native):
        entry = self.entries.get((game, state['sequence']))
        if not entry:
            return None, None
        if entry['state_sha256'] != digest(state) or entry['code_sha256'] != hashlib.sha256(code).hexdigest():
            return None, None
        if not classes and native.get('state_valid'):
            return 'FIXED_' + entry['class'], entry
        if signature(classes, reference, native) == entry['difference_sha256']:
            return 'KNOWN_' + entry['class'], entry
        return None, entry
