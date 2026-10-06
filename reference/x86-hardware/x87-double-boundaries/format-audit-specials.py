#!/usr/bin/env python3
# SPDX-License-Identifier: MIT. Original literal special-value audit.
import hashlib, pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parent
source = (root / 'format-candidates.c').read_text()
marker = 'int main(int argc,char**argv)'
assert source.count(marker) == 1
prefix = source.split(marker)[0].replace('#include "auxiliary.c"', '#include "' + str(root / 'auxiliary.c') + '"')
TEST_MAIN = '\nint main(void){\n const int pcs[]={24,53,64};\n const uint64_t v64[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8000000000011),UINT64_C(0xfff8000000000022),UINT64_C(0x7ff0000000000033),UINT64_C(0xfff0000000000044)};\n const uint32_t v32[]={0,0x80000000,0x7f800000,0xff800000,0x7fc00011,0xffc00022,0x7f800033,0xff800044};\n unsigned count=0,bad=0;\n for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++)for(int op=0;op<2;op++)for(int t=0;t<8;t++){\n  Input in={0};in.x=v64[t];in.xf=v32[t];Result r={0};int code=op?RND:XTRACT;\n  x87_eval(code,pcs[p],rc,&in,&r);if(op)full_round(pcs[p],rc,&in,&r);else full_extract(pcs[p],rc,&in,&r);\n  ext a={0,(uint16_t)((t&1)?0x8000:0)},b={0,0};unsigned flags=0;\n  if(t>=2){a.se|=0x7fff;a.sig=UINT64_C(0x8000000000000000);}\n  if(t>=4){unsigned payload=(unsigned)(t-3)*0x11;a.sig|=UINT64_C(0x4000000000000000)|((uint64_t)payload<<(pcs[p]==24?40:11));}\n  if(t>=6)flags=1;\n  if(!op){if(t<2){b.sig=UINT64_C(0x8000000000000000);b.se=0xffff;flags=4;}else if(t<4){b.sig=UINT64_C(0x8000000000000000);b.se=0x7fff;}else b=a;}\n  if(!same(r.a,a)||!same(r.b,a)||(!op&&(!same(r.a2,b)||!same(r.b2,b)))||(r.post&63)!=flags||(r.mx&63)!=flags){if(bad<8)printf("FAIL %s pc%d rc%d special%d x=%04x%016"PRIx64" b=%04x%016"PRIx64" flags%02x/%02x expected%02x\\n",op?"FRNDINT":"FXTRACT",pcs[p],rc,t,r.a.se,r.a.sig,r.b.se,r.b.sig,r.post&63,r.mx&63,flags);bad++;}count++;\n }\n __asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));printf("Format-candidate literal special audit: %u cases, %u failures\\n",count,bad);return bad!=0;\n}\n'
with tempfile.TemporaryDirectory(prefix='x87-format-audit-') as temp:
    temp = pathlib.Path(temp); path = temp / 'audit.c'; binary = temp / 'audit'
    path.write_text(prefix + TEST_MAIN)
    subprocess.run(['gcc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Wno-unused-variable', '-Wno-unused-function', '-fno-strict-aliasing', '-fno-fast-math', '-ffp-contract=off', str(path), '-o', str(binary)], check=True)
    print('format-candidates.c SHA-256:', hashlib.sha256(source.encode()).hexdigest(), flush=True)
    subprocess.run([str(binary)], check=True)
