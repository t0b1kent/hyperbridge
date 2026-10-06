.intel_syntax noprefix
.text
.globl stack_call
.def stack_call; .scl 2; .type 32; .endef
.seh_proc stack_call
stack_call:
    push rbp
    .seh_pushreg rbp
    sub rsp, 0x40
    .seh_stackalloc 0x40
    lea rbp, [rsp+0x40]
    .seh_setframe rbp, 0x40
    mov [rbp-8], rbx
    .seh_savereg rbx, 0x38
    .seh_endprologue
    mov eax, ecx
    shl rax, 4
    sub rsp, rax
    mov [rip+stack_call_rsp], rsp
    mov [rip+stack_call_rbx], r8
    mov rbx, r8
    mov rax, [rip+stack_target]
    /* RtlRaiseException accepts the record; RaiseException four arguments. */
    mov rcx, rdx
    cmp dword ptr [rip+stack_path], 1
    je .Lrtl
    cmp dword ptr [rip+stack_path], 2
    je .Lclose
    mov ecx, 0xe042ec16
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    jmp .Lrtl
.Lclose:
    mov ecx, 0x1337
.Lrtl:
    movdqa xmm0, [rip+stack_xmm_seed]
    movdqa xmm1, [rip+stack_xmm_seed]
    movdqa xmm2, [rip+stack_xmm_seed]
    movdqa xmm3, [rip+stack_xmm_seed]
    movdqa xmm4, [rip+stack_xmm_seed]
    movdqa xmm5, [rip+stack_xmm_seed]
    push 0x202
    popfq
    call rax
    pushfq
    pop qword ptr [rip+stack_after_flags]
    mov [rip+stack_after_rax], rax
    mov [rip+stack_after_rdx], rdx
    movdqu [rip+stack_after_xmm+0], xmm0
    movdqu [rip+stack_after_xmm+16], xmm1
    movdqu [rip+stack_after_xmm+32], xmm2
    movdqu [rip+stack_after_xmm+48], xmm3
    movdqu [rip+stack_after_xmm+64], xmm4
    movdqu [rip+stack_after_xmm+80], xmm5
    mov rbx, [rbp-8]
    lea rsp, [rbp]
    pop rbp
    ret
.seh_endproc
