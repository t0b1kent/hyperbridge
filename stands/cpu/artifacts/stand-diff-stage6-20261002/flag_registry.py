"""One manually authorized missing-status class, plus exact stage5 adjudications."""
import copy
import json
import os
import pathlib
import re
from defects import Registry as ExactRegistry, digest

OWN = pathlib.Path(__file__).resolve().parent
CLASS = 'MXCSR_STATUS_NOT_TRACKED'


class Registry(ExactRegistry):
    def __init__(self, path):
        super().__init__(path)
        document = json.loads((OWN/'known-classes.json').read_text())
        if document['admission'] != 'MANUAL_OWNER_ADJUDICATION_ONLY' or len(document['classes']) != 1:
            raise ValueError('manual class adjudication required')
        self.status_entry = document['classes'][0]
        if self.status_entry['class'] != CLASS:
            raise ValueError('unexpected status class')

    def classify(self, game, state, code, classes, reference, native):
        if 'mxcsr_flags' not in reference or not native.get('state_valid'):
            return super().classify(game, state, code, classes, reference, native)
        expected = reference['mxcsr']
        legacy = reference['unicorn_mxcsr']
        actual = int(native['mxcsr'], 0)
        expected_status, legacy_status, actual_status = expected & 0x3f, legacy & 0x3f, actual & 0x3f
        missing = expected_status & ~actual_status
        protected = 0
        # FP-CORRECT's adjudicated scope is scalar FP -> signed GPR.
        # An enabled repaired producer may not regress behind the known class.
        if os.environ.get('MACRUNNER_FEX_MXCSR_FLAGS')=='1' and os.environ.get('MACRUNNER_FEX_MXCSR_CVT_FLAGS')=='1':
            oracle = reference['mxcsr_flags']
            for event in oracle.get('events',[])[oracle.get('last_reset_event',0):]:
                if re.fullmatch(r'v?cvtt?(ss|sd)2si',event['instruction']):
                    protected |= event['raised']
        generated_difference = (expected ^ legacy) & 0x3f
        generated_only = generated_difference and not ((legacy & 0x3f) & ~(expected & 0x3f)) and not (generated_difference & ~reference['mxcsr_flags']['produced'])
        flags_verdict = None
        if generated_only and not ((actual ^ expected) & ~0x3f):
            if missing and not (actual_status & ~expected_status) and not (legacy_status & ~actual_status) and not (missing & protected):
                flags_verdict = 'KNOWN'
            elif actual_status == expected_status:
                flags_verdict = 'FIXED'
        meta = dict(self.status_entry, flags_verdict=flags_verdict)
        if flags_verdict=='KNOWN' and actual_status != legacy_status:
            meta['flags_partial_fixed'] = True
        old_ref = dict(reference, mxcsr=legacy)
        old_native = dict(native)
        # Compare stage5 adjudications with their original exception-bit source.
        # This only normalizes a proven flags match or the authorized missing class.
        if flags_verdict or actual & 0x3f == expected & 0x3f:
            old_native['mxcsr'] = hex((actual & ~0x3f) | (legacy & 0x3f))
        residual = [k for k in classes if k != 'mxcsr']
        if legacy != int(old_native['mxcsr'], 0): residual.append('mxcsr')
        approved, adjudication = super().classify(game, state, code, residual, old_ref, old_native)
        if adjudication: meta['exact_adjudication'] = adjudication
        status_bad = bool((actual ^ expected) & 0x3f)
        if status_bad and not flags_verdict:
            # Exact old LDMXCSR status-transport defect is still manually known.
            if approved and approved.startswith('KNOWN_') and 'mxcsr' in residual:
                return approved, meta
            return None, meta
        if approved:
            if approved.startswith('FIXED_') and flags_verdict == 'KNOWN':
                meta['exact_fixed_class'] = approved.removeprefix('FIXED_')
                return 'KNOWN_'+CLASS, meta
            return approved, meta
        if residual:
            return None, meta
        if flags_verdict:
            return flags_verdict+'_'+CLASS, meta
        return None, meta
