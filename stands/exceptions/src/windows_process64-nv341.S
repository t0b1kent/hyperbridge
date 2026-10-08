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
    subq $216, %rsp
    .seh_stackalloc 216
    movdqu %xmm6, 48(%rsp)
    .seh_savexmm %xmm6, 48
    movdqu %xmm7, 64(%rsp)
    .seh_savexmm %xmm7, 64
    movdqu %xmm8, 80(%rsp)
    .seh_savexmm %xmm8, 80
    movdqu %xmm9, 96(%rsp)
    .seh_savexmm %xmm9, 96
    movdqu %xmm10, 112(%rsp)
    .seh_savexmm %xmm10, 112
    movdqu %xmm11, 128(%rsp)
    .seh_savexmm %xmm11, 128
    movdqu %xmm12, 144(%rsp)
    .seh_savexmm %xmm12, 144
    movdqu %xmm13, 160(%rsp)
    .seh_savexmm %xmm13, 160
    movdqu %xmm14, 176(%rsp)
    .seh_savexmm %xmm14, 176
    movdqu %xmm15, 192(%rsp)
    .seh_savexmm %xmm15, 192
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
    movdqu .Lnv_seed334+0(%rip), %xmm6
    movdqu .Lnv_seed334+16(%rip), %xmm7
    movdqu .Lnv_seed334+32(%rip), %xmm8
    movdqu .Lnv_seed334+48(%rip), %xmm9
    movdqu .Lnv_seed334+64(%rip), %xmm10
    movdqu .Lnv_seed334+80(%rip), %xmm11
    movdqu .Lnv_seed334+96(%rip), %xmm12
    movdqu .Lnv_seed334+112(%rip), %xmm13
    movdqu .Lnv_seed334+128(%rip), %xmm14
    movdqu .Lnv_seed334+144(%rip), %xmm15
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
    movdqu %xmm6, 96(%rdx)
    movdqu %xmm7, 112(%rdx)
    movdqu %xmm8, 128(%rdx)
    movdqu %xmm9, 144(%rdx)
    movdqu %xmm10, 160(%rdx)
    movdqu %xmm11, 176(%rdx)
    movdqu %xmm12, 192(%rdx)
    movdqu %xmm13, 208(%rdx)
    movdqu %xmm14, 224(%rdx)
    movdqu %xmm15, 240(%rdx)
    movdqu 48(%rsp), %xmm6
    movdqu 64(%rsp), %xmm7
    movdqu 80(%rsp), %xmm8
    movdqu 96(%rsp), %xmm9
    movdqu 112(%rsp), %xmm10
    movdqu 128(%rsp), %xmm11
    movdqu 144(%rsp), %xmm12
    movdqu 160(%rsp), %xmm13
    movdqu 176(%rsp), %xmm14
    movdqu 192(%rsp), %xmm15
    addq $216, %rsp
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

.p2align 4
.Lnv_seed334:
    .quad 0x1100000000000006, 0x2200000000000006
    .quad 0x1100000000000007, 0x2200000000000007
    .quad 0x1100000000000008, 0x2200000000000008
    .quad 0x1100000000000009, 0x2200000000000009
    .quad 0x110000000000000a, 0x220000000000000a
    .quad 0x110000000000000b, 0x220000000000000b
    .quad 0x110000000000000c, 0x220000000000000c
    .quad 0x110000000000000d, 0x220000000000000d
    .quad 0x110000000000000e, 0x220000000000000e
    .quad 0x110000000000000f, 0x220000000000000f
