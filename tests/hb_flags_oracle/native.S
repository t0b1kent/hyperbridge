.intel_syntax noprefix
.text
.global hb_flags_native
.type hb_flags_native,@function
# in={rax,rdx,rcx,r8,r9,rbx,status}, out same order with raw RFLAGS last.
# Only status flags from the corpus may be loaded. The C/Python caller sanitizes them.
hb_flags_native:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r10,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov rax,[r10]
    mov rdx,[r10+8]
    mov rcx,[r10+16]
    mov r8,[r10+24]
    mov r9,[r10+32]
    mov rbx,[r10+40]
    mov rdi,r14
    push qword ptr [r10+48]
    popfq
    call r13
    mov [r12],rax
    mov [r12+8],rdx
    mov [r12+16],rcx
    mov [r12+24],r8
    mov [r12+32],r9
    mov [r12+40],rbx
    pushfq
    pop rax
    mov [r12+48],rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.size hb_flags_native,.-hb_flags_native
.section .note.GNU-stack,"",@progbits
