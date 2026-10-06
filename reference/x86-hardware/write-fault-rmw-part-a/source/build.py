# SPDX-License-Identifier: MIT
import json,subprocess,pathlib
import scalar,rmw,vector
root=pathlib.Path(__file__).resolve().parent
fs=[]
regnames='rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rflags'.split()
regvals=[0x1122334455667788,0xa1b2c3d4e5f60718,3,0x99aabbccddeeff00,0,0,0x778899aabbccddee,0,0x0808080808080808,0x0909090909090909,0x1010101010101010,0x1212121212121212,0x1313131313131313,0x1414141414141414,0x1515151515151515,0x1616161616161616,0x203]
features={'sse2':1,'sse4_1':2,'avx':4,'cx8':8,'cx16':16}
def arr(b):return '{'+','.join(str(x) for x in b)+'}'
lines=['static const Form allforms[] = {']
for group,module in [('scalar',scalar),('rmw',rmw),('vector',vector)]:
 for f in module.forms():
  f['group']=group;fs.append(f);code=bytes.fromhex(f['code']); regs=regvals.copy()
  for k,v in f.get('regs',{}).items():regs[regnames.index(k)]=v
  regs[-1]=f.get('flags',regs[-1]);ini=bytes.fromhex(f.get('initial',''));mask=bytes.fromhex(f.get('mask','ff'*16))
  vals=[json.dumps(f['name']),json.dumps(group),str(f['width']),arr(code),str(len(code)),str(int(f['legal'])),str(f.get('alignment',0)),str(features.get(f.get('feature'),0)),str(f.get('count',1)),str(int(f.get('string',False))),str(f.get('df',0)),str(int(f.get('stack',False))),str(int(f.get('call',False))),'{'+','.join(f'0x{x:x}ULL' for x in regs)+'}',arr(ini),str(len(ini)),arr(mask)]
  lines.append('{'+','.join(vals)+'},')
lines.append('};')
(root/'forms.h').write_text('\n'.join(lines)+'\n');(root/'forms.json').write_text(json.dumps(fs,indent=2)+'\n')
subprocess.run(['g++','-O2','-std=c++17','-Wall','-Wextra','-fno-pie','-no-pie','harness.cpp','run.S','-o','probe35'],cwd=root,check=True)
print(f'Built {len(fs)} instruction forms')
