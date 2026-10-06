/* SPDX-License-Identifier: MIT
 * Independent full-width GPR/flags snapshot around the bridge.
 */
.text
.globl check_bridge_preservation
.type check_bridge_preservation,@function
check_bridge_preservation:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq $0x1122334455667788,%rax
    movq $0x2233445566778899,%rcx
    movq $0x33445566778899aa,%rbx
    movq $0x445566778899aabb,%rbp
    movq $0x5566778899aabbcc,%r8
    movq $0x66778899aabbccdd,%r9
    movq $0x778899aabbccddee,%r10
    movq $0x8899aabbccddeeff,%r11
    movq $0x99aabbccddeeff00,%r12
    movq $0xaabbccddeeff0011,%r13
    movq $0xbbccddeeff001122,%r14
    movq $0xccddeeff00112233,%r15
    movq $0x20000000,%rdi
    movq $preservation32,%rsi
    movq $0x2000fff0,%rdx
    pushq $0xad7
    popfq
    movq %rax,expected_regs+0(%rip)
    movq %rcx,expected_regs+8(%rip)
    movq %rdx,expected_regs+16(%rip)
    movq %rbx,expected_regs+24(%rip)
    movq %rsp,expected_regs+32(%rip)
    movq %rbp,expected_regs+40(%rip)
    movq %rsi,expected_regs+48(%rip)
    movq %rdi,expected_regs+56(%rip)
    movq %r8,expected_regs+64(%rip)
    movq %r9,expected_regs+72(%rip)
    movq %r10,expected_regs+80(%rip)
    movq %r11,expected_regs+88(%rip)
    movq %r12,expected_regs+96(%rip)
    movq %r13,expected_regs+104(%rip)
    movq %r14,expected_regs+112(%rip)
    movq %r15,expected_regs+120(%rip)
    pushfq
    popq expected_regs+128(%rip)
    call bridge
    movq %rax,observed_regs+0(%rip)
    movq %rcx,observed_regs+8(%rip)
    movq %rdx,observed_regs+16(%rip)
    movq %rbx,observed_regs+24(%rip)
    movq %rsp,observed_regs+32(%rip)
    movq %rbp,observed_regs+40(%rip)
    movq %rsi,observed_regs+48(%rip)
    movq %rdi,observed_regs+56(%rip)
    movq %r8,observed_regs+64(%rip)
    movq %r9,observed_regs+72(%rip)
    movq %r10,observed_regs+80(%rip)
    movq %r11,observed_regs+88(%rip)
    movq %r12,observed_regs+96(%rip)
    movq %r13,observed_regs+104(%rip)
    movq %r14,observed_regs+112(%rip)
    movq %r15,observed_regs+120(%rip)
    pushfq
    popq observed_regs+128(%rip)
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.code32
preservation32:
    movl $0xdead0001,%eax
    movl $0xdead0002,%ecx
    movl $0xdead0003,%edx
    movl $0xdead0004,%ebx
    movl $0xdead0005,%ebp
    movl $0xdead0006,%esi
    movl $0xdead0007,%edi
    addl $1,%eax
    jmp leave32
.bss
.align 8
.globl expected_regs,observed_regs
expected_regs: .zero 136
observed_regs: .zero 136
.section .note.GNU-stack,"",@progbits
