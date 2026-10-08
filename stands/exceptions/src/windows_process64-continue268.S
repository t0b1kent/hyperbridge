/* Extension of pinned209; all NV registers have ABI unwind metadata.
 * after is captured before the probe restores its own caller's registers. */
.text
.globl ExcCtxPinnedCall209
.def ExcCtxPinnedCall209; .scl 2; .type 32; .endef
.seh_proc ExcCtxPinnedCall209
ExcCtxPinnedCall209:
    pushq %rbx
    .seh_pushreg %rbx
    pushq %rbp
    .seh_pushreg %rbp
    pushq %rsi
    .seh_pushreg %rsi
    pushq %rdi
    .seh_pushreg %rdi
    pushq %r12
    .seh_pushreg %r12
    pushq %r13
    .seh_pushreg %r13
    pushq %r14
    .seh_pushreg %r14
    pushq %r15
    .seh_pushreg %r15
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_endprologue
    movq %r9, 32(%rsp)
    movq %rcx, %rax
    movq %rdx, %rcx
    movq %r8, %rdx
    movabsq $0x1122334455667788, %rbx
    movabsq $0x2233445566778899, %rbp
    movabsq $0x33445566778899aa, %rsi
    movabsq $0x445566778899aabb, %rdi
    movabsq $0x5566778899aabbcc, %r12
    movabsq $0x66778899aabbccdd, %r13
    movabsq $0x778899aabbccddee, %r14
    movabsq $0x8899aabbccddeeff, %r15
    movabsq $0x9911223344556677, %r11
    movdqu .Lxmm_seed268(%rip), %xmm1
    pushq $0x202
    popfq
    movq %rbx, 0(%rdx)
    movq %rbp, 8(%rdx)
    movq %rsi, 16(%rdx)
    movq %rdi, 24(%rdx)
    movq %r12, 32(%rdx)
    movq %r13, 40(%rdx)
    movq %r14, 48(%rdx)
    movq %r15, 56(%rdx)
    movq %r11, 64(%rdx)
    pushfq
    popq %r10
    movq %r10, 72(%rdx)
    movq %rcx, 80(%rdx)
    movq %rsp, 88(%rdx)
    leaq .Lreturn268(%rip), %r10
    movq %r10, 96(%rdx)
    movdqu %xmm1, 104(%rdx)
    callq *%rax
.Lreturn268:
    movq 32(%rsp), %rdx
    movq %rbx, 0(%rdx)
    movq %rbp, 8(%rdx)
    movq %rsi, 16(%rdx)
    movq %rdi, 24(%rdx)
    movq %r12, 32(%rdx)
    movq %r13, 40(%rdx)
    movq %r14, 48(%rdx)
    movq %r15, 56(%rdx)
    movq %r11, 64(%rdx)
    pushfq
    popq %r10
    movq %r10, 72(%rdx)
    movq %rax, 80(%rdx)
    movq %rsp, 88(%rdx)
    addq $40, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    retq
.seh_endproc
.section .rdata,"dr"
.p2align 4
.Lxmm_seed268:
    .byte 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    .byte 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
