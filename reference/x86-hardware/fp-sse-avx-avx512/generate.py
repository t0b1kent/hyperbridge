#!/usr/bin/env python3
# Original code, MIT License. Generates fixed native assembly, never reference results.
import importlib, json, pathlib, sys
root=pathlib.Path(__file__).resolve().parent
mods=['forms_core','forms_conversion','forms_round_horizontal','forms_evex']
all_forms=[]
for mod in mods:
    if (root/(mod+'.py')).exists():
        all_forms.extend(importlib.import_module(mod).forms())
if len(sys.argv)>1:
    all_forms=[f for f in all_forms if f['cls'] in sys.argv[1:]]
build=root/'build';build.mkdir(exist_ok=True)
types={'f32':0,'f64':1,'i32':2,'i64':3,'f16':4,'u32':2,'u64':3}
ss=['.text']; hh=[]; rows=[]
for i,f in enumerate(all_forms):
    ident='kernel_'+str(i);f['id']=i
    f.setdefault('imm',-1);f.setdefault('out_bytes',f['width']//8);f.setdefault('cases',0)
    f.setdefault('types',['f32' if f['lane']==4 else 'f64']*3)
    f.setdefault('sizes',[f['width']//8]*3)
    f.setdefault('mask',(1<<(1 if f['scalar'] else f['width']//(8*f['lane'])))-1)
    f.setdefault('zero',False);f.setdefault('er','-');f.setdefault('flags',False)
    evex=f['enc']=='EVEX'; load='vmovdqu64' if evex else 'vmovdqu';reg='zmm' if evex else 'ymm'
    ss += [f'.globl {ident}',f'.type {ident},@function',f'{ident}:']
    ss += [f'  {load} {64*j}(%rdi), %{reg}{j}' for j in range(3)]
    if evex:ss += [f'  movabs ${f["mask"]}, %r11','  kmovq %r11, %k1']
    if f.get('pre'): ss += ['  '+f['pre']]
    if f['flags']:ss += ['  pushq $0xad7','  popfq']
    ss += ['  ldmxcsr 192(%rdi)',f'.globl {ident}_fault',f'{ident}_fault:', '  '+f['asm'],f'.globl {ident}_resume',f'{ident}_resume:', '  stmxcsr 64(%rsi)',f'  {load} %{reg}0, 0(%rsi)','  pushfq','  popq %r11','  movq %r11, 72(%rsi)']
    if f.get('post'): ss += ['  '+f['post']]
    ss += ['  ldmxcsr clean_mxcsr(%rip)','  vzeroupper','  ret',f'.size {ident},.-{ident}']
    hh += [f'extern void {ident}(const struct input *, struct output *);',f'extern char {ident}_resume, {ident}_fault;']
    ax=sum(1<<x for x in f['axes']);fmt=lambda s:json.dumps(s)
    rows += ['{'+','.join([fmt(f['cls']),fmt(f['name']),fmt(f['enc']),fmt(f['er']),fmt(f.get('feature','avx')),str(f['width']),str(f['lane']),str(int(f['scalar'])),str(f['nops']),str(ax),str(f['imm']),str(f['out_bytes']),str(f['cases']),str(int(f['flags'])),str(f['mask']),str(int(f['zero'])),'{'+','.join(str(types[t]) for t in f['types'])+'}','{'+','.join(map(str,f['sizes']))+'}',ident,'&'+ident+'_resume','&'+ident+'_fault'])+'},']
ss += ['.section .rodata','.align 4','clean_mxcsr: .long 0x1f80','.section .note.GNU-stack,"",@progbits']
(build/'kernels.S').write_text('\n'.join(ss)+'\n')
(build/'forms.h').write_text('\n'.join(hh)+'\nstatic const struct form FORMS[] = {\n'+'\n'.join(rows)+'\n};\n')
(build/'forms.json').write_text(json.dumps(all_forms,indent=2)+'\n')
print('generated',len(all_forms),'native instruction forms',file=sys.stderr)
