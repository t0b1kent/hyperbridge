/* Windows x64 ABI; independent of the translator and kernel API internals. */
.text
.globl ExcCtxPinnedCall209
.def ExcCtxPinnedCall209; .scl 2; .type 32; .endef
.seh_proc ExcCtxPinnedCall209
ExcCtxPinnedCall209:
    pushq %rbx
    .seh_pushreg %rbx
    pushq %r14
    .seh_pushreg %r14
    pushq %r15
    .seh_pushreg %r15
    subq $32, %rsp
    .seh_stackalloc 32
    .seh_endprologue
    movq %rcx, %rax
    movq %rdx, %rcx
    movq %r8, %rdx
    movabsq $0x1122334455667788, %rbx
    movabsq $0x2233445566778899, %r11
    movabsq $0x33445566778899aa, %r14
    movabsq $0x445566778899aabb, %r15
    movdqu .Lxmm_seed209(%rip), %xmm1
    pushq $0x202
    popfq
    movq %rbx, 0(%rdx)
    movq %r11, 8(%rdx)
    movq %r14, 16(%rdx)
    movq %r15, 24(%rdx)
    pushfq
    popq %r10
    movq %r10, 32(%rdx)
    movq %rcx, 40(%rdx)
    movq %rsp, 48(%rdx)
    leaq .Lreturn209(%rip), %r10
    movq %r10, 56(%rdx)
    movdqu %xmm1, 64(%rdx)
    callq *%rax
.Lreturn209:
    addq $32, %rsp
    popq %r15
    popq %r14
    popq %rbx
    retq
.seh_endproc
.section .rdata,"dr"
.p2align 4
.Lxmm_seed209:
    .byte 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    .byte 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
