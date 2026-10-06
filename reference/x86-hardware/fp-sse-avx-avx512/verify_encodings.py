#!/usr/bin/env python3
# Original MIT-licensed native-encoding audit; no target instructions executed.
import collections,importlib,json,pathlib,re,subprocess,tempfile
root=pathlib.Path(__file__).resolve().parent
forms=[]
for module in ('forms_core','forms_conversion','forms_round_horizontal','forms_evex'):
    forms.extend(importlib.import_module(module).forms())
(root/'build').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='encoding-',dir=root/'build') as t:
    t=pathlib.Path(t);lines=['.text']
    for i,f in enumerate(forms):lines += [f'.globl audit_{i}',f'audit_{i}:',f['asm']]
    lines += ['.section .note.GNU-stack,"",@progbits']
    (t/'targets.S').write_text('\n'.join(lines)+'\n')
    subprocess.run(['gcc','-c',str(t/'targets.S'),'-o',str(t/'targets.o')],check=True)
    output=subprocess.check_output(['objdump','-d','-w',str(t/'targets.o')],text=True)
    target=None;seen=set();counts=collections.Counter()
    for line in output.splitlines():
        label=re.search(r'<audit_(\d+)>:',line)
        if label:target=int(label[1]);continue
        match=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)\s*(\S+)\s*(.*)',line)
        if not match or target is None:continue
        f=forms[target];prefix=int(match[1].split()[0],16);actual=match[2];operands=match[3];expected=f['name']
        if actual=='{evex}':
            actual,operands=operands.split(None,1)
        encoding='EVEX' if prefix==0x62 else 'VEX' if prefix in (0xc4,0xc5) else 'SSE'
        assert encoding==f['enc'],(target,expected,'encoding',encoding,f['enc'])
        name_ok=actual==expected or actual in (expected+'l',expected+'q')
        if expected.startswith(('cmp','vcmp')):
            name_ok=actual.startswith('vcmp' if expected.startswith('v') else 'cmp') and actual.endswith(expected[-2:])
        assert name_ok,(target,expected,actual)
        if f.get('gpr_bits'):
            reg='%eax' if f['gpr_bits']==32 else '%rax'
            assert reg in operands,(target,expected,reg,operands)
        seen.add(target);counts[encoding]+=1;target=None
    assert len(seen)==len(forms),(len(seen),len(forms))
report={'forms':len(forms),'encodings':dict(counts),'instruction_encoding_errors':0,'mnemonic_errors':0,'GPR_width_errors':0,'target_instructions_executed':False}
(root/'encoding-validation.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
