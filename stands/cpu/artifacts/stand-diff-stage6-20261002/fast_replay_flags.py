#!/usr/bin/env python3
"""Stage6 adapter: fast stage5 replay with independent SSE MXCSR status."""
import json
import os
import pathlib
import sys

OWN = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(OWN.parent/'stand-diff-stage5-20261001'))
import fast_replay
import mxcsr_flags
import flag_registry


def enable():
    fast_replay.replay.STATUS_ORACLE = mxcsr_flags
    fast_replay.replay.Registry = flag_registry.Registry


def main():
    enable()
    rc = fast_replay.main()
    prefix = pathlib.Path(sys.argv[sys.argv.index('--out-prefix')+1])
    path = prefix.with_suffix('.json')
    result = json.loads(path.read_text())
    result['parent_engine_env'] = {k:v for k,v in os.environ.items() if k.startswith(('FEX_', 'MACRUNNER_FEX_', 'STAND_DIFF_'))}
    result['effective_config'].update({k:v for k,v in os.environ.items() if k.startswith(('MACRUNNER_FEX_', 'STAND_DIFF_'))})
    for source in [pathlib.Path(__file__), OWN/'mxcsr_flags.py', OWN/'flag_registry.py', OWN/'known-classes.json', OWN/'census.py']:
        result['inputs_sha256'][str(source.resolve())] = fast_replay.replay.sha(source)
    result['boundaries'].append('MXCSR status from exact Intel operand oracle; unmasked #XM, unsupported producers and divergent status-memory transport are explicitly unavailable.')
    path.write_text(json.dumps(result, indent=2)+'\n')
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
