/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 OpenAI
 * Handwritten native x86 instruction-form probe. No privileged instructions.
 */
.text
.code64
.globl a_enter64
.type a_enter64,@function
a_enter64:
    movq %rdx,%rsp
    call *%rsi
    ud2
.size a_enter64,.-a_enter64

.macro entry64 name
.globl \name
.type \name,@function
\name:
    movq %rsp,a_entry_sp(%rip)
.endm
entry64 a64_call_reg
    movq %rdi,%rax
    leaq 1f(%rip),%rdx
    movq %rdx,a_expected_top(%rip)
    subq $40,%rsp
.globl a64_call_reg_branch
a64_call_reg_branch:
    call *%rax
1:  addq $40,%rsp
    ret
.size a64_call_reg,.-a64_call_reg
entry64 a64_call_mem
    leaq 1f(%rip),%rdx
    movq %rdx,a_expected_top(%rip)
    subq $40,%rsp
    movq %rdi,(%rsp)
.globl a64_call_mem_branch
a64_call_mem_branch:
    call *(%rsp)
1:  addq $40,%rsp
    ret
.size a64_call_mem,.-a64_call_mem
entry64 a64_jmp_reg
    movq (%rsp),%rax
    movq %rax,a_expected_top(%rip)
.globl a64_jmp_reg_branch
a64_jmp_reg_branch:
    jmp *%rdi
.size a64_jmp_reg,.-a64_jmp_reg
entry64 a64_jmp_mem
    movq (%rsp),%rax
    movq %rax,a_expected_top(%rip)
    movq %rdi,8(%rsp)
.globl a64_jmp_mem_branch
a64_jmp_mem_branch:
    jmp *8(%rsp)
.size a64_jmp_mem,.-a64_jmp_mem
entry64 a64_ret
    movq (%rsp),%rax
    movq %rax,a_expected_top(%rip)
    pushq %rdi
.globl a64_ret_branch
a64_ret_branch:
    ret
.size a64_ret,.-a64_ret

.globl a_enter32
.type a_enter32,@function
a_enter32:
    movl %edi,%eax
    movl %esi,%ebx
    movq %rdx,%rsp
    pushq $0x23
    pushq $a_compat_entry
    lretq
.code32
a_compat_entry:
    movw $0x2b,%cx
    movw %cx,%ds
    movw %cx,%es
    pushl %eax
    call *%ebx
    ud2
.size a_enter32,.-a_enter32
.macro entry32 name
.globl \name
.type \name,@function
\name:
    movl %esp,a_entry_sp
.endm
entry32 a32_call_reg
    movl 4(%esp),%eax
    movl $1f,%edx
    movl %edx,a_expected_top
.globl a32_call_reg_branch
a32_call_reg_branch:
    call *%eax
1:  ret
.size a32_call_reg,.-a32_call_reg
entry32 a32_call_mem
    movl $1f,%edx
    movl %edx,a_expected_top
.globl a32_call_mem_branch
a32_call_mem_branch:
    call *4(%esp)
1:  ret
.size a32_call_mem,.-a32_call_mem
entry32 a32_jmp_reg
    movl (%esp),%eax
    movl %eax,a_expected_top
    movl 4(%esp),%eax
.globl a32_jmp_reg_branch
a32_jmp_reg_branch:
    jmp *%eax
.size a32_jmp_reg,.-a32_jmp_reg
entry32 a32_jmp_mem
    movl (%esp),%eax
    movl %eax,a_expected_top
.globl a32_jmp_mem_branch
a32_jmp_mem_branch:
    jmp *4(%esp)
.size a32_jmp_mem,.-a32_jmp_mem
entry32 a32_ret
    movl (%esp),%eax
    movl %eax,a_expected_top
    pushl 4(%esp)
.globl a32_ret_branch
a32_ret_branch:
    ret
.size a32_ret,.-a32_ret
.code64
.section .note.GNU-stack,"",@progbits
