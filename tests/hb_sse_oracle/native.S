.text
.globl hb_native_execute
.type hb_native_execute,@function
hb_native_execute:
    pushq %rbx
    pushq %r12
    pushq %r13
    subq $16,%rsp
    movq %rdi,%r12
    movq %rdx,%r13
    movq %rsi,%r11
    stmxcsr 0(%rsp)
    pushfq
    popq %r10
    movq %r10,8(%rsp)
    vmovdqu 0(%r12),%ymm0
    vmovdqu 32(%r12),%ymm1
    vmovdqu 64(%r12),%ymm2
    leaq 96(%r12),%rbx
    movq 128(%r12),%rax
    ldmxcsr 144(%r12)
    movq 136(%r12),%r10
    pushq %r10
    popfq
    call *%r11
    pushfq
    popq %r10
    movq %r10,40(%r13)
    movq %rax,32(%r13)
    vmovdqu %ymm0,0(%r13)
    stmxcsr 48(%r13)
    vzeroupper
    ldmxcsr 0(%rsp)
    movq 8(%rsp),%r10
    pushq %r10
    popfq
    leaq 16(%rsp),%rsp
    popq %r13
    popq %r12
    popq %rbx
    ret
.size hb_native_execute,.-hb_native_execute
.section .note.GNU-stack,"",@progbits
