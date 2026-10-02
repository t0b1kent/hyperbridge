#!/usr/bin/env python3
"""Reuse reference engine, resetting hooks/mappings; cache instruction decode.

All guest registers supplied by the existing adapter are reset on every case.
Each previous mapping is unmapped before accepting a new case, which also
invalidates translated code. No output or state is taken from the native runner.
"""
import functools
import json
import pathlib
import sys

OWN=pathlib.Path(__file__).resolve().parent
STAGE4=OWN.parent/'stand-diff-stage4-20261001'
sys.path.insert(0,str(STAGE4))
import real_inputs_batch as replay


class DecodeCache:
    def __init__(self, original):
        self.original=original
        self.decode=functools.lru_cache(maxsize=131072)(lambda data,address:
                     tuple(original.disasm(data,address)))
    def disasm(self,data,address,count=0):
        result=self.decode(bytes(data),address)
        return iter(result if not count else result[:count])
    def __getattr__(self,name):return getattr(self.original,name)


class EnginePool:
    def __init__(self, constructor):
        self.constructor=constructor;self.engine=None;self.hooks=[];self.regions=[];self.pristine=None
    def __call__(self, architecture, mode, *args, **kwargs):
        if architecture!=replay.uc.UC_ARCH_X86 or mode!=replay.uc.UC_MODE_64 or args or kwargs:
            return self.constructor(architecture,mode,*args,**kwargs)
        if self.engine is None:
            self.engine=self.constructor(architecture,mode)
            self.pristine=self.engine.context_save()
        for hook in self.hooks:self.engine.hook_del(hook)
        self.hooks.clear()
        for address,size in self.regions:self.engine.mem_unmap(address,size)
        self.regions.clear()
        self.engine.context_restore(self.pristine)
        return self
    def hook_add(self,*args,**kwargs):
        hook=self.engine.hook_add(*args,**kwargs);self.hooks.append(hook);return hook
    def mem_map(self,address,size,*args,**kwargs):
        self.engine.mem_map(address,size,*args,**kwargs);self.regions.append((address,size))
    def __getattr__(self,name):return getattr(self.engine,name)


def enable():
    replay.sd.DIS=DecodeCache(replay.sd.DIS)
    replay.uc.Uc=EnginePool(replay.uc.Uc)


def main():
    enable()
    rc=replay.main()
    prefix=pathlib.Path(sys.argv[sys.argv.index('--out-prefix')+1])
    path=prefix.with_suffix('.json');result=json.loads(path.read_text())
    result['inputs_sha256'][str(pathlib.Path(__file__).resolve())]=replay.sha(__file__)
    result['reference_reuse']='Fresh supplied registers, previous guest pages unmapped and hooks removed; decode cache keyed by exact bytes/address.'
    path.write_text(json.dumps(result,indent=2)+'\n')
    return rc


if __name__=='__main__':raise SystemExit(main())
