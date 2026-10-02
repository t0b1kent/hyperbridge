#!/usr/bin/env python3
"""Build private STAND32 frontend using an existing native FEX CMake build."""
import argparse, datetime, hashlib, json, os, pathlib, shlex, shutil, subprocess
OWN=pathlib.Path(__file__).resolve().parent
ROOT=OWN.parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fex-build',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path,default=OWN/'stand_runner32')
    p.add_argument('--engine-native-base',action='store_true',help='Use supplied engine unchanged; no GUEST32 prototype overlays')
    p.add_argument('--x87-mutants',action='store_true',help='Own deliberate X87.cpp lifter mutations; requires native base')
    a=p.parse_args(); build=a.fex_build.resolve(); target=a.output.resolve()
    target_nice=5 if 7 <= datetime.datetime.now().hour < 23 or (datetime.datetime.now().hour == 23 and datetime.datetime.now().minute < 30) else 0
    inherited_nice=os.getpriority(os.PRIO_PROCESS,0)
    priority=['nice','-n',str(max(0,target_nice-inherited_nice))] if inherited_nice < target_nice else []
    (OWN/'tmp').mkdir(exist_ok=True);os.environ['TMPDIR']=str(OWN/'tmp')
    if shutil.disk_usage(OWN).free<40*1024**3: print('WAIT export volume <40GiB; install skipped'); return 75
    if (ROOT/'scripts/wine-slot.sh').exists() and subprocess.run([str(ROOT/'scripts/wine-slot.sh'),'builds-ok']).returncode: print('WAIT build slot; install skipped'); return 75
    if not a.engine_native_base:raise ValueError('Export contains own frontend only; use --engine-native-base with a compatible external FEX build')
    if a.x87_mutants:raise ValueError('Integrate the own mutation insertion into your external X87 source; upstream X87.cpp is not distributed here')
    for directory in [OWN/'logs',OWN/'out',target.parent]:directory.mkdir(parents=True,exist_ok=True)
    records=json.loads((build/'compile_commands.json').read_text())
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    logpath=OWN/'logs'/('build-'+stamp+'.log'); outputs=[]; commands=[]; sources=[]
    selection=[('hb_replay.cpp','fexmac/stand_runner.cpp')]
    if a.x87_mutants:
        if not a.engine_native_base:raise ValueError('x87 mutants require native engine')
        selection += [('X87.cpp','mutants/X87.cpp')]
    if not a.engine_native_base: selection += [('Frontend.cpp','src/Frontend.cpp'),('MemoryOps.cpp','src/MemoryOps.cpp')]
    with logpath.open('x') as log:
        for original,local in selection:
            rec=next(x for x in records if x['file'].endswith('/'+original))
            cmd=shlex.split(rec['command']); source=OWN/local; obj=OWN/'out'/(original+'-'+stamp+'.o')
            cmd[cmd.index('-o')+1]=str(obj);cmd[-1]=str(source)
            if a.engine_native_base and original=='hb_replay.cpp':cmd.insert(1,'-DSTAND32_ADDRESS_SPACE32=1')
            if a.x87_mutants and original=='hb_replay.cpp':cmd.insert(1,'-DSTAND32_X87_MUTANTS=1')
            if pathlib.Path(cmd[0]).name!='ccache': cmd.insert(0,'ccache')
            cmd=[*priority,*cmd];commands.append(cmd);sources.append(source)
            log.write(shlex.join(cmd)+'\n');log.flush()
            rc=subprocess.run(cmd,cwd=rec['directory'],stdout=log,stderr=log).returncode
            if rc: print('BUILD_FAILED',original,rc,logpath,'; install skipped');return 1
            outputs.append(str(obj))
        lines=(build/'build.ninja').read_text().splitlines()
        link_target = 'guest32_memory_runner' if a.engine_native_base and any(
            l.startswith('build Bin/guest32_memory_runner:') for l in lines) else 'hb_replay'
        i=next(i for i,l in enumerate(lines) if l.startswith('build Bin/'+link_target+':'))
        objects=shlex.split(lines[i].split(':',1)[1].split('|',1)[0])[1:]
        objects=[str(build/x) for x in objects if not x.endswith('/'+link_target+'.cpp.o')]
        # A branch may have built guest32_memory_runner but not hb_replay.
        # Compile missing frontend support objects privately from the exact
        # hb_replay recipe; never build or write into the supplied engine tree.
        for index, original_obj in enumerate(objects):
            if pathlib.Path(original_obj).exists():
                continue
            rec = next((r for r in records if str(pathlib.Path(r['directory']) /
                shlex.split(r['command'])[shlex.split(r['command']).index('-o')+1]) == original_obj), None)
            if rec is None:
                print('MISSING_OBJECT_RECIPE', original_obj, '; install skipped'); return 1
            cmd=shlex.split(rec['command']); source=pathlib.Path(rec['file'])
            obj=OWN/'out'/('support-'+str(index)+'-'+stamp+'.o')
            cmd[cmd.index('-o')+1]=str(obj)
            if pathlib.Path(cmd[0]).name!='ccache': cmd.insert(0,'ccache')
            cmd=[*priority,*cmd]; commands.append(cmd); sources.append(source)
            log.write(shlex.join(cmd)+'\n'); log.flush()
            rc=subprocess.run(cmd,cwd=rec['directory'],stdout=log,stderr=log).returncode
            if rc: print('BUILD_FAILED_SUPPORT',source,rc,logpath,'; install skipped'); return 1
            objects[index]=str(obj)
        settings=dict(l.strip().split(' = ',1) for l in lines[i+1:i+13] if ' = ' in l)
        libs=[x if x.startswith('-') or pathlib.Path(x).is_absolute() else str(build/x) for x in shlex.split(settings['LINK_LIBRARIES']) if x!='-ldl']
        if target.exists(): subprocess.run(['cp','-p',str(target),str(target)+'.БЫЛО-'+stamp],check=True)
        cmd=[*priority,'/usr/bin/clang++','-O3','-arch','arm64','-Wl,-dead_strip','-fPIE','-Xlinker','-pie',*outputs,*objects,*libs,'-o',str(target)]
        commands.append(cmd);log.write(shlex.join(cmd)+'\n');log.flush()
        rc=subprocess.run(cmd,cwd=build,stdout=log,stderr=log).returncode
        if rc:print('LINK_FAILED',rc,logpath,'; install skipped');return 1
    inputs=sources+[pathlib.Path(x) for x in objects]+[pathlib.Path(x) for x in libs if not x.startswith('-')]+[target,build/'compile_commands.json',build/'build.ninja']
    receipt=dict(label='PRIVATE_DIAGNOSTIC_ONLY_NOT_GOLDEN',fex_build=str(build),commands=commands,
                 engine_native_base=a.engine_native_base,parallel_compilers=1,install='skipped',
                 requested_nice=target_nice,inherited_nice=inherited_nice,
                 sha256={str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in inputs})
    (OWN/'out'/('build-'+stamp+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
    print('BUILD_OK',target,'; install skipped');return 0
if __name__=='__main__':raise SystemExit(main())
