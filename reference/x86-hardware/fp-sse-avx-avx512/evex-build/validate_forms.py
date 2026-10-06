# SPDX-License-Identifier: MIT
from pathlib import Path
import sys
p=Path(__file__).resolve().parent
sys.path.insert(0,str(p.parent))
from forms_evex import forms
fs=forms()
s=['.text']
for n,f in enumerate(fs):
 s.extend(['.globl probe_'+str(n),'.type probe_'+str(n)+',@function','probe_'+str(n)+':',
           'vmovups 0(%rdi), %zmm0','vmovups 64(%rdi), %zmm1','vmovups 128(%rdi), %zmm2',
           'movabs $'+str(f['mask'])+', %rax','kmovq %rax, %k1',f.get('pre',''),
           'ldmxcsr probe_mxcsr(%rip)',f['asm'],'vmovups %zmm0, 0(%rsi)',f.get('post',''),
           'vzeroupper','ret'])
s += ['.section .rodata','.p2align 2','probe_mxcsr:','.long 0x1f80','.section .note.GNU-stack,"",@progbits']
(p/'validate-forms.s').write_text('\n'.join(s)+'\n')
c=['#include <stdio.h>','#include <stdint.h>','#include <signal.h>','#include <setjmp.h>',
   'static sigjmp_buf jump; static volatile sig_atomic_t fault;',
   'static void handler(int s) { fault=s; siglongjmp(jump,1); }',
   'typedef void (*Fn)(void*,void*);']
c += ['extern void probe_'+str(n)+'(void*,void*);' for n in range(len(fs))]
c += ['static Fn funcs[] = {' + ','.join('probe_'+str(n) for n in range(len(fs))) + '};',
      'int main(void) { uint64_t in[24] __attribute__((aligned(64)))={0};',
      'uint64_t out[8] __attribute__((aligned(64)))={0}; unsigned i, failures=0;',
      'signal(SIGILL,handler); signal(SIGSEGV,handler); signal(SIGFPE,handler);',
      'for(i=0;i<24;i++) in[i]=0x3ff000003f800000ULL;',
      'for(i=0;i<sizeof(funcs)/sizeof(funcs[0]);i++) { fault=0; if(sigsetjmp(jump,1)==0) funcs[i](in,out);',
      'if(fault) { printf("FORM %u SIGNAL %d\\n",i,fault); failures++; } }',
      'printf("Executed %u forms; faults %u\\n",i,failures); return failures!=0; }']
(p/'validate-forms.c').write_text('\n'.join(c)+'\n')
