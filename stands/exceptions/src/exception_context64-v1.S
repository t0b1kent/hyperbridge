/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 HyperBridge contributors */
.intel_syntax noprefix
.text
.extern g_pre,g_post,g_stack_pre,g_capture,g_xmm_markers,g_ymm_markers
.extern g_use_avx,g_flag_mode,g_fault_kind,g_mxcsr,g_fcw,g_fault_entry,g_resume_entry,g_handler_entry_rsp
.extern g_explicit_flags,g_api_result,g_raise_parameters,g_readonly,g_noexec,g_guard,g_misaligned
.extern veh_impl,seh_filter_impl,__imp_RtlCaptureContext,__imp_RaiseException,__imp_CloseHandle
.macro SNAP sym,stack=0
    mov qword ptr [rip+\sym+0],rax
    mov qword ptr [rip+\sym+8],rbx
    mov qword ptr [rip+\sym+16],rcx
    mov qword ptr [rip+\sym+24],rdx
    mov qword ptr [rip+\sym+32],rsi
    mov qword ptr [rip+\sym+40],rdi
    mov qword ptr [rip+\sym+48],rbp
    mov qword ptr [rip+\sym+56],rsp
    mov qword ptr [rip+\sym+64],r8
    mov qword ptr [rip+\sym+72],r9
    mov qword ptr [rip+\sym+80],r10
    mov qword ptr [rip+\sym+88],r11
    mov qword ptr [rip+\sym+96],r12
    mov qword ptr [rip+\sym+104],r13
    mov qword ptr [rip+\sym+112],r14
    mov qword ptr [rip+\sym+120],r15
    pushfq
    pop qword ptr [rip+\sym+128]
    fxsave64 [rip+\sym+144]
    cmp dword ptr [rip+g_use_avx],0
    je .Lno_avx\@
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        vextractf128 xmmword ptr [rip+\sym+656+16*\n],ymm\n,1
    .endr
.Lno_avx\@:
    .if \stack
        mov rsi,rsp
        lea rdi,[rip+g_stack_pre]
        mov ecx,32
        cld
        rep movsq
        mov rsi,qword ptr [rip+\sym+32]
        mov rdi,qword ptr [rip+\sym+40]
        mov rcx,qword ptr [rip+\sym+16]
    .endif
    push qword ptr [rip+\sym+128]
    popfq
.endm

.globl veh_entry
veh_entry:
    mov qword ptr [rip+g_handler_entry_rsp],rsp
    cld
    jmp veh_impl
.globl seh_filter_entry
seh_filter_entry:
    mov qword ptr [rip+g_handler_entry_rsp],rsp
    cld
    jmp seh_filter_impl

.globl run_case_asm
.seh_proc run_case_asm
run_case_asm:
    push rbp
    .seh_pushreg rbp
    push rbx
    .seh_pushreg rbx
    push rsi
    .seh_pushreg rsi
    push rdi
    .seh_pushreg rdi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp,744
    .seh_stackalloc 744
    .irp n,6,7,8,9,10,11,12,13,14,15
        movaps xmmword ptr [rsp+32+16*(\n-6)],xmm\n
        .seh_savexmm xmm\n,32+16*(\n-6)
    .endr
    fxsave64 [rsp+192]
    .seh_endprologue
    fninit
    fldcw word ptr [rip+g_fcw]
    fld1
    fld1
    fdiv qword ptr [rip+double_three]
    ldmxcsr dword ptr [rip+g_mxcsr]
    movss xmm0,dword ptr [rip+float_one]
    divss xmm0,dword ptr [rip+float_three]
    cmp dword ptr [rip+g_use_avx],0
    je .Lload_xmm
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        vmovdqu ymm\n,ymmword ptr [rip+g_ymm_markers+32*\n]
    .endr
    jmp .Lflags
.Lload_xmm:
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        movdqu xmm\n,xmmword ptr [rip+g_xmm_markers+16*\n]
    .endr
.Lflags:
    push 0x202
    popfq
    mov eax,dword ptr [rip+g_flag_mode]
    cmp eax,8
    jae .Lexplicit_flags
    push 0x202
    popfq
    lea rdx,[rip+flag_targets]
    jmp qword ptr [rdx+rax*8]
.Lmul:
    mov eax,0xffffffff
    mov ecx,2
    mul ecx
    jmp .Lmarkers
.Lshl1:
    mov eax,0x80000001
    shl eax,1
    jmp .Lmarkers
.Lshr1:
    mov eax,0x80000001
    shr eax,1
    jmp .Lmarkers
.Lshlcl:
    mov eax,0x80000001
    mov ecx,17
    shl eax,cl
    jmp .Lmarkers
.Lshrcl:
    mov eax,0x80000001
    mov ecx,17
    shr eax,cl
    jmp .Lmarkers
.Lbsf:
    mov eax,0x11223344
    mov ecx,0
    bsf eax,ecx
    jmp .Lmarkers
.Lbsr:
    mov eax,0x11223344
    mov ecx,0
    bsr eax,ecx
    jmp .Lmarkers
.Ldiv:
    mov eax,13
    mov edx,0
    div dword ptr [rip+integer_three]
    jmp .Lmarkers
.Lexplicit_flags:
    push qword ptr [rip+g_explicit_flags]
    popfq
.Lmarkers:
    mov rax,0x1111111101010101
    mov rbx,0x2222222202020202
    mov rcx,0x3333333303030303
    mov rdx,0x4444444404040404
    mov rsi,0x5555555505050505
    mov rdi,0x6666666606060606
    mov rbp,0x7777777707070707
    mov r8,0x8888888808080808
    mov r9,0x9999999909090909
    mov r10,0xaaaaaaaa0a0a0a0a
    mov r11,0xbbbbbbbb0b0b0b0b
    mov r12,0xcccccccc0c0c0c0c
    mov r13,0xdddddddd0d0d0d0d
    mov r14,0xeeeeeeee0e0e0e0e
    mov r15,0xffffffff0f0f0f0f
    SNAP g_pre,1
    jmp qword ptr [rip+g_fault_entry]

.globl fault_read,fault_write,fault_execute,fault_breakpoint,fault_divide,fault_ud2,fault_capture
fault_read:
    .byte 0x48,0xa1
    .quad 0
    jmp resume_fault
fault_write:
    .byte 0x48,0xa3
    .quad 0
    jmp resume_fault
fault_execute:
    call qword ptr [rip+bad_target]
    jmp resume_execute
fault_breakpoint:
    int3
    jmp resume_fault
fault_divide:
    div qword ptr [rip+integer_zero]
    jmp resume_fault
fault_ud2:
    ud2
    jmp resume_fault
fault_capture:
    lea rcx,[rip+g_capture]
    SNAP g_pre,1
    call qword ptr [rip+__imp_RtlCaptureContext]
    jmp resume_capture
.globl fault_read_unmapped,fault_write_unmapped,fault_readonly,fault_noexec
.globl fault_int3_long,fault_int2d,fault_icebp,fault_idiv_overflow
.globl fault_in,fault_out,fault_hlt,fault_cli,fault_sti,fault_rdmsr,fault_cr0_read,fault_cr0_write
.globl fault_movaps,fault_tf,fault_guard,fault_raise,fault_closehandle,tf_instruction
fault_read_unmapped:
    mov r11,qword ptr [rip+bad_target]
    SNAP g_pre,1
    mov rax,qword ptr [r11]
    jmp resume_fault
fault_write_unmapped:
    mov r11,qword ptr [rip+bad_target]
    SNAP g_pre,1
    mov qword ptr [r11],rax
    jmp resume_fault
fault_readonly:
    mov r11,qword ptr [rip+g_readonly]
    SNAP g_pre,1
    mov qword ptr [r11],rax
    jmp resume_fault
fault_noexec:
    call qword ptr [rip+g_noexec]
    jmp resume_execute
fault_int3_long:
    .byte 0xcd,0x03
    jmp resume_fault
fault_int2d:
    .byte 0xcd,0x2d
    jmp resume_fault
fault_icebp:
    .byte 0xf1
    jmp resume_fault
fault_idiv_overflow:
    mov rax,0x8000000000000000
    mov rdx,-1
    SNAP g_pre,1
    idiv qword ptr [rip+integer_minus_one]
    jmp resume_fault
fault_in:
    in al,dx
    jmp resume_fault
fault_out:
    out dx,al
    jmp resume_fault
fault_hlt:
    hlt
    jmp resume_fault
fault_cli:
    cli
    jmp resume_fault
fault_sti:
    sti
    jmp resume_fault
fault_rdmsr:
    rdmsr
    jmp resume_fault
fault_cr0_read:
    mov rax,cr0
    jmp resume_fault
fault_cr0_write:
    mov cr0,rax
    jmp resume_fault
fault_movaps:
    mov r11,qword ptr [rip+g_misaligned]
    SNAP g_pre,1
    movaps xmm0,xmmword ptr [r11]
    jmp resume_fault
fault_tf:
    or qword ptr [rip+g_pre+128],0x100
    push qword ptr [rip+g_pre+128]
    popfq
tf_instruction:
    nop
    jmp resume_fault
fault_guard:
    mov r11,qword ptr [rip+g_guard]
    SNAP g_pre,1
    mov rax,qword ptr [r11]
    jmp resume_fault
fault_raise:
    mov ecx,0xe0424242
    mov edx,0
    mov r8d,3
    lea r9,[rip+g_raise_parameters]
    SNAP g_pre,1
    cld
    call qword ptr [rip+__imp_RaiseException]
    mov qword ptr [rip+g_api_result],rax
    jmp resume_fault
fault_closehandle:
    mov ecx,0x1337
    SNAP g_pre,1
    cld
    call qword ptr [rip+__imp_CloseHandle]
    mov qword ptr [rip+g_api_result],rax
    jmp resume_fault
.globl resume_fault,resume_execute,resume_capture
resume_execute:
    SNAP g_post,0
    lea rsp,[rsp+8]
    jmp .Lreturn
resume_fault:
resume_capture:
    SNAP g_post,0
.Lreturn:
    cld
    fxrstor64 [rsp+192]
    add rsp,744
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
.seh_endproc

.section .rdata,"dr"
.balign 8
double_three: .quad 0x4008000000000000
integer_zero: .quad 0
integer_minus_one: .quad -1
bad_target: .quad 0x133700000
integer_three: .long 3
float_one: .long 0x3f800000
float_three: .long 0x40400000
.balign 8
flag_targets: .quad .Lmul,.Lshl1,.Lshr1,.Lshlcl,.Lshrcl,.Lbsf,.Lbsr,.Ldiv
