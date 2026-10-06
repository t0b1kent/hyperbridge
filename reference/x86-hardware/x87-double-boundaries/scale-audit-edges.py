#!/usr/bin/env python3
# SPDX-License-Identifier: MIT. Original small FSCALE helper edge audit.
# Reuses the current implementation helpers, replacing only its program entry.
import hashlib, pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parent
source = (root / 'scale.c').read_text()
marker = 'int main(int argc,char**argv)'
assert source.count(marker) == 1, 'Update audit entry marker after implementation refactor'
prefix = source.split(marker)[0].replace('#include "core.c"', '#include "' + str(root / 'core.c') + '"')
TEST_MAIN = 'int main(void){\n const uint64_t a32[]={0,1,0x00800000,0x7f7fffff,0x3f800000},a64[]={0,1,UINT64_C(0x0010000000000000),UINT64_C(0x7fefffffffffffff),UINT64_C(0x3ff0000000000000)};\n unsigned n=0,bad=0;\n for(int p=0;p<3;p++)for(int rc=0;rc<4;rc++)for(unsigned aidx=0;aidx<5;aidx++)for(int sx=0;sx<2;sx++)for(unsigned bi=0;bi<sizeof(scale_edges)/sizeof(scale_edges[0]);bi++){\n  int fmt=pcs[p]==24?32:64;uint16_t cw=(pcs[p]==24?0x7f:pcs[p]==53?0x27f:0x37f)|(rc<<10);uint32_t mx=0x1f80|(rc<<13);\n  __asm__ volatile("fninit; fldcw %0"::"m"(cw):"memory");\n  uint64_t a=(fmt==32?a32[aidx]:a64[aidx])|(sx?(UINT64_C(1)<<(fmt-1)):0),b=integer_input(scale_edges[bi],fmt);result r={0};int req;unsigned steps;\n  scale_execute(fmt,a,b,mx,&r,&req,&steps);\n  if(r.memory_bits!=r.sbits){if(bad<10)printf("FAIL pc%d rc%d a%u sign%d scale%d xmem=%016"PRIx64" sse=%016"PRIx64"\\n",pcs[p],rc,aidx,sx,scale_edges[bi],r.memory_bits,r.sbits);bad++;}n++;\n }\n __asm__ volatile("fninit");uint32_t mx=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(mx));printf("FSCALE target-store edge audit: %u cases, %u failures\\n",n,bad);return bad!=0;\n}\n'
with tempfile.TemporaryDirectory(prefix='x87-scale-audit-') as temp:
    temp = pathlib.Path(temp)
    path = temp / 'audit.c'
    binary = temp / 'audit'
    path.write_text(prefix + TEST_MAIN)
    subprocess.run(['gcc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Wno-unused-variable', '-fno-strict-aliasing', '-fno-fast-math', '-ffp-contract=off', str(path), '-o', str(binary)], check=True)
    print('scale.c SHA-256:', hashlib.sha256(source.encode()).hexdigest(), flush=True)
    subprocess.run([str(binary)], check=True)
