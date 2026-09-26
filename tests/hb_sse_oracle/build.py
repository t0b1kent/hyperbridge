#!/usr/bin/env python3
"""Build the real interpreter/decoder/lifter, never the ARM64 code generator.
Only unavailable, out-of-scope paths have fail-fast link shims.
"""
from pathlib import Path
import argparse, subprocess, re, json, hashlib, os, platform
if platform.system()!='Linux' or platform.machine()!='x86_64':raise SystemExit('The native oracle builder requires Linux x86-64; use the exported corpus on Mac.')
p=argparse.ArgumentParser();p.add_argument('--cc',default='clang');p.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--build-dir',type=Path);a=p.parse_args()
r=a.repo.resolve();t=Path(__file__).resolve().parent;o=a.build_dir.resolve() if a.build_dir else t/'out';o.mkdir(parents=True,exist_ok=True)
common=[a.cc,'-O2','-g','-std=gnu11','-D_GNU_SOURCE','-fPIC','-fno-fast-math','-ffp-contract=off','-frounding-math','-ffunction-sections','-fdata-sections','-I'+str(r/'include'),'-I'+str(r/'src'),'-I'+str(o),'-I'+str(t)]
# Test-only architecture port: these timer instructions are never in this corpus.
s=(r/'src/hb_interpreter.c').read_text()
s,n=re.subn(r'__asm__ volatile\("dsb sy\\n\\tisb\\n\\tmrs %0, cntvct_el0"\s*: "=r"\(cnt\) : : "memory"\);', 'abort(); cnt = 0; /* test-only: RDTSC is out of scope */',s);assert n==1,n
s,n=re.subn(r'__asm__ volatile\("mrs %0, cntvct_el0" : "=r"\(cnt\)\);','abort(); cnt = 0; /* test-only: RDTSC is out of scope */',s);assert n==1,n
(o/'hb_interpreter.c').write_text(s)
# Primary source includes are preferred. The archived source bundle omitted .inc
# files; the explicit fail-fast fallbacks below are for that bundle ONLY.
# None of the tested opcode paths may invoke them.
fallbacks={
'hb_decode_vsib_obshchee.inc':'''static bool hb_sbor_vex(hb_dec_t*d,uint8_t c,bool w,bool l,uint8_t s,unsigned v,bool r,bool x,bool b,hb_decoded_t*out,hb_result_t*i){if(c<0x90||c>0x93)return false;abort();}\n''',
'hb_decode_tsx_obshchee.inc':'''static bool hb_tsx_gruppa11(hb_dec_t*d,uint8_t c,bool rel,hb_decoded_t*out,hb_result_t*i){if(!(c==0xc6||c==0xc7)||!can_read(d,1)||d->code[d->pos]!=0xf8)return false;abort();}\nstatic bool hb_tsx_0f01(uint8_t m,hb_decoded_t*out){if(m!=0xd5&&m!=0xd6)return false;abort();}\n''',
'hb_lift_vec_opory.inc':'''static bool has_vex_src(const hb_decoded_t*d){return d->op3.present&&!d->op3.is_imm;}
static uint8_t dec_imm8(const hb_decoded_t*d){if(d->has_imm8)return d->imm8;if(d->op3.present&&d->op3.is_imm)return (uint8_t)d->op3.imm;return 0;}
static hb_ir_operand_t vector_src1_from_dec(const hb_decoded_t*d,hb_ir_operand_t dst){return has_vex_src(d)?operand_from_dec(d,2):dst;}
static hb_ir_operand_t vector_src2_from_dec(const hb_decoded_t*d){return has_vex_src(d)?operand_from_dec(d,3):operand_from_dec(d,2);}
static uint64_t vec_target(hb_ir_vec_op_t op,uint64_t arg){return ((uint64_t)op<<32)|arg;}
static uint32_t fma_target_from_ins(int op){abort();}\n''',
'hb_lift_vec_obshchee.inc':'''static bool hb_evex_cmp_mask(const hb_decoded_t*d,hb_ir_builder_t*b,hb_result_t*i){abort();}
static hb_result_t hb_vek_obshchij(const hb_decoded_t*d,hb_ir_builder_t*b){abort();}
static bool hb_vek_osobye(const hb_decoded_t*d,hb_ir_builder_t*b,hb_result_t*i){abort();}\n''',
'hb_lift_sist_obshchee.inc':'''static bool hb_sist_obshchee(const hb_decoded_t*d,hb_ir_builder_t*b,hb_result_t*i){abort();}\n''',
}
used=[]
for name,text in fallbacks.items():
 if not (r/'src'/name).exists():(o/name).write_text(text);used.append(name)
 elif (o/name).exists():(o/name).unlink()  # never let an archived fallback shadow a real source include
# Copy decode/lift into output so quoted include search can find the fallbacks;
# source bytes themselves remain identical.
objects=[]
for name in ['hb_interpreter','hb_flags','hb_decode_x64','hb_lift_x64','hb_ir','hb_probe','hb_env','hb_gates_tbl']:
 src=o/(name+'.c')
 if name!='hb_interpreter':src.write_bytes((r/'src'/(name+'.c')).read_bytes())
 obj=o/(name+'.o');subprocess.run(common+['-c',str(src),'-o',str(obj)],check=True);objects.append(obj)
for name in ['adapter']:
 src=t/(name+'.c')
 if not src.exists():continue
 obj=o/(name+'.o');subprocess.run(common+['-c',str(src),'-o',str(obj)],check=True);objects.append(obj)
if (t/'native.S').exists():
 obj=o/'native.o';subprocess.run([a.cc,'-fPIC','-c',str(t/'native.S'),'-o',str(obj)],check=True);objects.append(obj)
# Resolving only non-test APIs; missing implementations abort, never return fake values.
undef=set();defined=set()
for obj in objects:
 for line in subprocess.check_output(['nm',str(obj)],text=True).splitlines():
  x=line.split()
  if len(x)==2 and x[0]=='U':undef.add(x[1])
  elif len(x)>=3 and x[-2].upper() in ['T','D','B','R','W']:defined.add(x[-1])
missing=sorted(x for x in undef-defined if x.startswith('hb_'))
text='#include <stdio.h>\n#include <stdlib.h>\n'
for sym in missing:text+='void '+sym+'(void){fprintf(stderr,"OUT-OF-SCOPE LINK SHIM: '+sym+'\\n");abort();}\n'
(o/'fail_fast.c').write_text(text);obj=o/'fail_fast.o';subprocess.run(common+['-c',str(o/'fail_fast.c'),'-o',str(obj)],check=True);objects.append(obj)
subprocess.run([a.cc,'-shared','-Wl,--no-undefined','-Wl,--gc-sections',*[str(x) for x in objects],'-lm','-lpthread','-ldl','-o',str(o/'libhb_sse_oracle.so')],check=True)
report={'cc':subprocess.check_output([a.cc,'--version'],text=True),'test_cflags':common,'source_bundle_fallbacks':used,'fail_fast_link_symbols':missing,'inputs':{n:hashlib.sha256((r/'src'/n).read_bytes()).hexdigest() for n in ['hb_interpreter.c','hb_flags.c','hb_decode_x64.c','hb_lift_x64.c','hb_ir.c']},'codegenerator_built':False}
(o/'build.json').write_text(json.dumps(report,indent=2));print(json.dumps({'built':str(o/'libhb_sse_oracle.so'),'fail_fast_count':len(missing),'fallbacks':used}))
