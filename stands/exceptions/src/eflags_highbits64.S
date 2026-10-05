/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 HyperBridge contributors */
.text
.macro SETUP_FLAGS
    mov %rcx,%rbx
    shl $8,%rbx
    mov %rdx,%r11
    bt $11,%ecx
    jnc 1f
    mov $0x7f,%al
    add $1,%al
    jmp 2f
1:  xor %eax,%eax
2:  mov %ebx,%eax
    sahf
.endm
.macro PROLOGUE name
.globl \name
.def \name; .scl 2; .type 32; .endef
.seh_proc \name
\name:
    push %rbx
    .seh_pushreg %rbx
    pushfq
    .seh_stackalloc 8
    sub $40,%rsp
    .seh_stackalloc 40
    .seh_endprologue
.endm
.macro EPILOGUE
    lea 40(%rsp),%rsp
    popfq
    pop %rbx
    ret
    .seh_endproc
.endm
PROLOGUE flags_plain
    SETUP_FLAGS
    pushfq
    pop %rax
    mov %rax,(%r11)
    EPILOGUE
PROLOGUE flags_fault
    SETUP_FLAGS
    pushfq
    pop %rax
    mov %rax,(%r11)
.globl flags_fault_rip
flags_fault_rip:
    ud2
.globl flags_resume_rip
flags_resume_rip:
    pushfq
    pop %rax
    mov %rax,8(%r11)
    EPILOGUE
