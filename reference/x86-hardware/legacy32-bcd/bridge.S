/* SPDX-License-Identifier: MIT
 * Native CPL3 compatibility-mode bridge. No syscall occurs in compatibility mode.
 * The existing Linux user code/data selectors have been checked by probe.c.
 */
.text
.globl bridge
.type bridge,@function
bridge:
    pushfq
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movw %ds, saved_ds(%rip)
    movw %es, saved_es(%rip)
    movq %rsp, saved_sp(%rip)
    movq %rdi, %rbp
    movq %rsi, %rdi
    movq %rdx, %rsp
    pushq $0x23
    pushq $entry32
    lretq
.code32
entry32:
    movw $0x2b, %ax
    movw %ax, %ds
    movw %ax, %es
    jmp *%edi
.globl probe32
probe32:
    movl $0x12345678, 0(%ebp)
    movl %esp, 4(%ebp)
    jmp leave32
.globl leave32
leave32:
    .byte 0xea
    .long leave64
    .word 0x33
.code64
leave64:
    /* Only explicit POP FS/GS tests need TLS-base restoration. */
    cmpl $0, 0x2000006c
    je tls_done
    testl $1, 0x2000006c
    jz restore_gs
    movq saved_fsbase(%rip), %rsi
    movl $0x1002, %edi
    movl $158, %eax
    syscall
    testq %rax, %rax
    js tls_restore_failed
restore_gs:
    testl $2, 0x2000006c
    jz tls_done
    movq saved_gsbase(%rip), %rsi
    movl $0x1001, %edi
    movl $158, %eax
    syscall
    testq %rax, %rax
    js tls_restore_failed
tls_done:
    movq saved_sp(%rip), %rsp
    movw saved_ds(%rip), %ax
    movw %ax, %ds
    movw saved_es(%rip), %ax
    movw %ax, %es
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rax
    popfq
    ret
tls_restore_failed:
    /* Do not retry a denied syscall or invoke libc with a wrong TLS base.
     * Exit status 77 is the explicit unavailable outcome. */
    movl $1, %eax
    movl $2, %edi
    leaq tls_error(%rip), %rsi
    movl $tls_error_end-tls_error, %edx
    syscall
    movl $231, %eax
    movl $77, %edi
    syscall
    ud2
.section .rodata
tls_error: .ascii "UNAVAILABLE: restoration of the original per-thread TLS base failed; no retry.\n"
tls_error_end:
.bss
.align 8
saved_sp: .quad 0
.globl saved_fsbase,saved_gsbase
saved_fsbase: .quad 0
saved_gsbase: .quad 0
saved_ds: .word 0
saved_es: .word 0
.section .note.GNU-stack,"",@progbits
