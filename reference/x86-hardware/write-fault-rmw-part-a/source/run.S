/* SPDX-License-Identifier: MIT */
.text
.globl probe_run
.type probe_run,@function
probe_run:
 pushfq
 push %rbx
 push %rbp
 push %r12
 push %r13
 push %r14
 push %r15
 mov %rsp,host_rsp(%rip)
 cmpl $0,xsave_mask(%rip)
 je 2f
 mov xsave_mask(%rip),%eax
 xor %edx,%edx
 xrstor64 xinit(%rip)
 jmp 3f
2:
 fxrstor64 xinit(%rip)
3:
 movdqu vec0(%rip),%xmm0
 movdqu mask0(%rip),%xmm1
 cmpl $0,avx_enabled(%rip)
 je 1f
 vmovdqu vec0(%rip),%ymm0
1:
 pushq inp+128(%rip)
 popfq
 mov inp+8(%rip),%rbx
 mov inp+16(%rip),%rcx
 mov inp+24(%rip),%rdx
 mov inp+32(%rip),%rsi
 mov inp+40(%rip),%rdi
 mov inp+48(%rip),%rbp
 mov inp+56(%rip),%rsp
 mov inp+64(%rip),%r8
 mov inp+72(%rip),%r9
 mov inp+80(%rip),%r10
 mov inp+88(%rip),%r11
 mov inp+96(%rip),%r12
 mov inp+104(%rip),%r13
 mov inp+112(%rip),%r14
 mov inp+120(%rip),%r15
 mov inp(%rip),%rax
 jmp *code_addr(%rip)
.globl probe_done
probe_done:
 sfence
 mov %rax,outp(%rip)
 mov %rbx,outp+8(%rip)
 mov %rcx,outp+16(%rip)
 mov %rdx,outp+24(%rip)
 mov %rsi,outp+32(%rip)
 mov %rdi,outp+40(%rip)
 mov %rbp,outp+48(%rip)
 mov %rsp,outp+56(%rip)
 mov %r8,outp+64(%rip)
 mov %r9,outp+72(%rip)
 mov %r10,outp+80(%rip)
 mov %r11,outp+88(%rip)
 mov %r12,outp+96(%rip)
 mov %r13,outp+104(%rip)
 mov %r14,outp+112(%rip)
 mov %r15,outp+120(%rip)
 mov host_rsp(%rip),%rsp
 pushfq
 popq outp+128(%rip)
 cld
 pop %r15
 pop %r14
 pop %r13
 pop %r12
 pop %rbp
 pop %rbx
 popfq
 ret
.size probe_run,.-probe_run
.section .note.GNU-stack,"",@progbits
