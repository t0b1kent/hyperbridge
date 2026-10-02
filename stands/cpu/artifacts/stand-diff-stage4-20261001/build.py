#!/usr/bin/env python3
"""Private frontend/recorder build. Existing FEX objects stay read-only."""
import argparse
import hashlib
import json
import pathlib
import shlex
import subprocess
import concurrent.futures
import shutil
import datetime
import os

OWN = pathlib.Path(__file__).resolve().parent
ROOT = OWN.parents[1]

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('kind',choices=['runner','recorder'])
    ap.add_argument('--fex-build',type=pathlib.Path,required=True)
    ap.add_argument('--output',type=pathlib.Path)
    ap.add_argument('--frontend',type=pathlib.Path,help='Runner only: own standalone frontend source')
    ap.add_argument('--jit-source',type=pathlib.Path,help='Own experimental JIT TU; linked before read-only FEX archives')
    ap.add_argument('--frozen-source',type=pathlib.Path,help='Recorder: rebuild every linked TU against one immutable source snapshot')
    daytime = 700 <= int(datetime.datetime.now().strftime('%H%M')) < 2330
    inherited=os.getpriority(os.PRIO_PROCESS,0)
    priority = ['nice','-n',str(5-inherited)] if daytime and inherited<5 else []
    ap.add_argument('-j',type=int,choices=range(1,7),default=4 if daytime else 6)
    a=ap.parse_args()
    if daytime and a.j > 4: ap.error('daytime limit is four workers')
    if (ROOT/'scripts/wine-slot.sh').exists() and subprocess.run([str(ROOT/'scripts/wine-slot.sh'),'builds-ok']).returncode:
        print('WAIT builds; install skipped');return 75
    free=shutil.disk_usage(OWN).free
    if free<40*1024**3:print('WAIT export volume <40GiB; install skipped');return 75
    recorder=a.kind=='recorder'
    if recorder and a.frontend:raise ValueError('--frontend is runner-only')
    build=a.fex_build.resolve()
    target=(a.output or OWN/('xtajit64-firstk.dll' if recorder else 'stand_runner_ec')).resolve()
    if target.exists():raise RuntimeError('Existing binary: preserve it with cp -p or choose a new output')
    src=a.frontend.resolve() if a.frontend else OWN/('recorder/JIT.cpp' if recorder else '../stand-diff-stage5-20261001/stand_runner_fixed.cpp')
    for directory in [OWN/'logs', OWN/'out', target.parent]:directory.mkdir(parents=True,exist_ok=True)
    if recorder and not src.exists():raise RuntimeError('Integrate the own recorder header into your external FEX JIT source first')
    name='xtajit64.dll' if recorder else 'hb_replay'
    suffix='/JIT/JIT.cpp' if recorder else '/hb_replay.cpp'
    rec=next(r for r in json.loads((build/'compile_commands.json').read_text()) if r['file'].endswith(suffix))
    obj=target.with_suffix('.obj' if recorder else '.o')
    cmd=shlex.split(rec['command']);cmd[cmd.index('-o')+1]=str(obj);cmd[-1]=str(src)
    compiler=next(i for i,x in enumerate(cmd) if pathlib.Path(x).name.endswith('clang++'))
    cmd.insert(compiler+1,'-I'+str(src.parent))
    if not recorder:cmd.insert(compiler+1,'-I'+str(OWN/'fexmac'))
    if recorder and pathlib.Path(cmd[0]).name!='ccache':cmd.insert(0,'ccache')
    source_base=pathlib.Path(rec['file']).parents[5] if recorder else None
    if a.frozen_source:
        if not recorder:raise ValueError('--frozen-source requires recorder')
        frozen=a.frozen_source.resolve()
        for p in (frozen/'Data').rglob('*.json'):
            other=source_base/p.relative_to(frozen)
            if not other.exists() or sha(p)!=sha(other):raise ValueError('Generated IR/config input drift: '+str(p))
        cmd=[x.replace(str(source_base),str(frozen)) for x in cmd]
    lines=(build/'build.ninja').read_text().splitlines()
    i=next(i for i,l in enumerate(lines) if l.startswith('build Bin/'+name) and ': ' in l)
    objects=shlex.split(lines[i].split(':',1)[1].split('|',1)[0])[1:]
    old='/JIT/JIT.cpp.obj' if recorder else '/hb_replay.cpp.o'
    objects=[str(obj) if x.endswith(old) else str(build/x) for x in objects]
    frozen_commands=[]
    frozen_archives=[]
    frozen_generated=[]
    if a.frozen_source:
        private=OWN/('frozen-deps-'+target.stem)
        for sub in ['include','generated']:
            shutil.copytree(build/sub,private/sub,dirs_exist_ok=True)
        generated_ir=private/'include/FEXCore/IR'
        subprocess.run([*priority,'python3',str(frozen/'FEXCore/Scripts/json_ir_generator.py'),
                        str(frozen/'FEXCore/Source/Interface/IR/IR.json'),
                        str(generated_ir/'IRDefines.inc'),str(generated_ir/'IRDefines_Dispatch.inc')],check=True)
        frozen_generated=[p for sub in ['include','generated'] for p in (private/sub).rglob('*') if p.is_file()]
        def rewrite(cc):
            return [x.replace(str(source_base),str(frozen)).replace(str(build),str(private)) for x in cc]
        cmd=rewrite(cmd)
        compile_records=json.loads((build/'compile_commands.json').read_text())
        def rebuild_object(old_object):
            matched=None
            for rr in compile_records:
                cc=shlex.split(rr['command'])
                if '-o' not in cc:continue
                out_path=pathlib.Path(cc[cc.index('-o')+1])
                out_path=out_path if out_path.is_absolute() else pathlib.Path(rr['directory'])/out_path
                if out_path.resolve()==pathlib.Path(old_object).resolve():matched=(rr,cc);break
            if matched is None:raise ValueError('No compile recipe for linked object: '+old_object)
            rr,cc=matched
            rebuilt=OWN/('frozen-objects-'+target.stem)/pathlib.Path(old_object).relative_to(build)
            rebuilt.parent.mkdir(parents=True,exist_ok=True)
            cc[cc.index('-o')+1]=str(rebuilt)
            cc=rewrite(cc)
            if pathlib.Path(cc[0]).name!='ccache':cc.insert(0,'ccache')
            frozen_commands.append(([*priority,*cc],rr['directory'],rebuilt))
            return str(rebuilt)
        for oi,old_object in enumerate(objects):
            if old_object!=str(obj):objects[oi]=rebuild_object(old_object)
    settings=dict(l.strip().split(' = ',1) for l in lines[i+1:i+13] if ' = ' in l)
    libs=[x if x.startswith('-') or pathlib.Path(x).is_absolute() else str(build/x)
          for x in shlex.split(settings['LINK_LIBRARIES']) if x!='-ldl']
    if a.frozen_source:
        rules={}
        for line in lines:
            if line.startswith('build ') and ': ' in line:
                outputs,rhs=line[6:].split(': ',1)
                for output in shlex.split(outputs.split('|')[0]):
                    rules[output]=(rhs.split()[0],shlex.split(rhs.split('|')[0])[1:])
        archive_map={}
        ar=str(pathlib.Path(next(x for x in cmd if x.endswith('clang++'))).parent/'llvm-ar')
        for li,lib in enumerate(libs):
            lp=pathlib.Path(lib)
            if lp.is_absolute() and lp.is_relative_to(build):
                relative=str(lp.relative_to(build));rule,inputs=rules[relative]
                if not inputs:
                    # Import-only ntdll_ex archive has no executable code. Its definition
                    # belongs to the pinned snapshot; rebuild via the original dlltool rule.
                    ri=next(j for j,l in enumerate(lines) if l.startswith('build '+relative+' ')
                            or l.startswith('build '+relative+':'))
                    command=next(l.strip()[10:] for l in lines[ri+1:ri+8] if l.strip().startswith('COMMAND = '))
                    args=shlex.split(command.split(' && ')[-1])
                    args=rewrite(args);(private/lp.relative_to(build)).parent.mkdir(parents=True,exist_ok=True)
                    subprocess.run([*priority,*args],cwd=(private/lp.relative_to(build)).parent,check=True)
                    libs[li]=str(private/lp.relative_to(build));continue
                if lib not in archive_map:
                    archive=private/lp.relative_to(build);archive.parent.mkdir(parents=True,exist_ok=True)
                    archived=[rebuild_object(str(build/x)) for x in inputs]
                    frozen_archives.append([*priority,ar,'rcs',str(archive),*archived])
                    archive_map[lib]=str(archive)
                libs[li]=archive_map[lib]
    if recorder:
        flags=[('-Wl,-Map,'+str(target.with_suffix('.map'))) if x.startswith('-Wl,-Map,') else x
               for x in shlex.split(settings['LINK_FLAGS'])]
        cc=next(x for x in cmd if x.endswith('clang++'))
        link=[cc,*shlex.split(settings['LANGUAGE_COMPILE_FLAGS']),*flags,'-o',str(target),
              '-Wl,--out-implib,'+str(target.with_suffix('.dll.a')),
              '-Wl,--major-image-version,0,--minor-image-version,0',*objects,*libs]
    else:
        link=['/usr/bin/clang++','-O3','-arch','arm64','-Wl,-dead_strip','-fPIE','-Xlinker','-pie',*objects,*libs,'-o',str(target)]
    logpath=OWN/'logs'/('build-'+target.name+'.log')
    commands=[[*priority,*cmd]]
    if a.jit_source:
        if recorder:raise ValueError('--jit-source is only for native runner')
        jr=next(r for r in json.loads((build/'compile_commands.json').read_text()) if r['file'].endswith('/JIT/JIT.cpp'))
        jc=shlex.split(jr['command']);jo=target.with_suffix('.jit.o')
        jc[jc.index('-o')+1]=str(jo);jc[-1]=str(a.jit_source.resolve())
        commands.append([*priority,*jc])
        link.insert(link.index(objects[0]),str(jo))
    commands.append([*priority,*link])
    if frozen_commands:
        def compile_frozen(item):
            command,directory,rebuilt=item
            lp=rebuilt.with_suffix('.log')
            with lp.open('w') as f:
                f.write(shlex.join(command)+'\n');f.flush()
                rc=subprocess.run(command,cwd=directory,stdout=f,stderr=f).returncode
            return rc,str(lp)
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.j) as pool:
            results=list(pool.map(compile_frozen,frozen_commands))
        failed=[r for r in results if r[0]]
        if failed:print('FROZEN_BUILD_FAILED',failed[:4],'; install skipped');return 1
    commands=frozen_archives+commands
    with logpath.open('x') as log:
        for command in commands:
            log.write(shlex.join(command)+'\n');log.flush()
            rc=subprocess.run(command,cwd=rec['directory'],stdout=log,stderr=log).returncode
            if rc:print('BUILD_FAILED',rc,logpath,'; install skipped');return rc
    if recorder:
        source_base=a.frozen_source.resolve() if a.frozen_source else pathlib.Path(rec['file']).parents[5]
        marker=(source_base/'Source/Windows/wine_builtin.bin').read_bytes()[:32]
        with target.open('r+b') as f:f.seek(64);f.write(marker)
    header_dir=src.parent if recorder else OWN/'fexmac'
    inputs=[src,src.with_name('StandStateCapture.h')] if recorder else [src,header_dir/'OracleRanges.h',header_dir/'MacHostFeatures.h']
    inputs += [target,build/'compile_commands.json',build/'build.ninja']
    if not recorder:inputs += [build/'FEXCore/Source/libFEXCore.a',build/'FEXCore/Source/libFEXCore_Base.a']
    if a.jit_source:inputs.append(a.jit_source.resolve())
    if frozen_commands:inputs += [p for _,_,p in frozen_commands]
    if a.frozen_source:
        inputs += frozen_generated+[pathlib.Path(x) for x in libs if not x.startswith('-')]
        inputs += [frozen/'FEXCore/Source/Interface/IR/IR.json',frozen/'FEXCore/Scripts/json_ir_generator.py']
    (OWN/'out'/('build-'+target.name+'.json')).write_text(json.dumps(dict(
        label='PRIVATE_DIAGNOSTIC_ONLY_NOT_GOLDEN',fex_build=str(build),commands=commands,
        sha256={str(p):sha(p) for p in inputs},install='skipped',parallel_compilers=a.j if frozen_commands else 1,
        frozen_source=str(a.frozen_source) if a.frozen_source else None,
        frozen_commands=[c for c,_,_ in frozen_commands]),indent=2)+'\n')
    print('BUILD_OK',target,'; install skipped');return 0

if __name__=='__main__':raise SystemExit(main())
