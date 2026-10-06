/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 OpenAI
 * Original kernels, no third-party source incorporated.
 * System V AMD64 ABI: RDI = positive iteration count, RSI = 10-byte result.
 */
.intel_syntax noprefix
.text
.macro begin name
.p2align 6
.globl bench_\name
.type bench_\name,@function
bench_\name:
.endm
.macro finish name
ret
.size bench_\name,.-bench_\name
.endm
begin empty
.p2align 6
1: dec rdi
jnz 1b
fld1
fstp TBYTE PTR [rsi]
finish empty
begin fadd
fld QWORD PTR [rip+addend]
fld1
.p2align 6
1: fadd st(0),st(1)
dec rdi
jnz 1b
fstp TBYTE PTR [rsi]
fstp st(0)
finish fadd
begin fld_fstp
sub rsp,16
mov rax,QWORD PTR [rip+memory_value]
mov QWORD PTR [rsp],rax
.p2align 6
1: fld QWORD PTR [rsp]
fstp QWORD PTR [rsp]
dec rdi
jnz 1b
fld QWORD PTR [rsp]
fstp TBYTE PTR [rsi]
add rsp,16
finish fld_fstp
begin fild_fistp
sub rsp,16
mov DWORD PTR [rsp],123456789
.p2align 6
1: fild DWORD PTR [rsp]
fistp DWORD PTR [rsp]
dec rdi
jnz 1b
fild DWORD PTR [rsp]
fstp TBYTE PTR [rsi]
add rsp,16
finish fild_fistp
begin fmul
fld QWORD PTR [rip+factor]
fld1
.p2align 6
1: fmul st(0),st(1)
dec rdi
jnz 1b
fstp TBYTE PTR [rsi]
fstp st(0)
finish fmul
begin fdiv
fld QWORD PTR [rip+factor]
fld1
.p2align 6
1: fdiv st(0),st(1)
dec rdi
jnz 1b
fstp TBYTE PTR [rsi]
fstp st(0)
finish fdiv
begin fsqrt
fld QWORD PTR [rip+two]
.p2align 6
1: fsqrt
dec rdi
jnz 1b
fstp TBYTE PTR [rsi]
finish fsqrt
begin fcom_branch
fld QWORD PTR [rip+two]
fld1
.p2align 6
1: fcom st(1)
fnstsw ax
sahf
jb 2f
nop
2: dec rdi
jnz 1b
fstp TBYTE PTR [rsi]
fstp st(0)
finish fcom_branch
begin mixed5
fld QWORD PTR [rip+factor]
fld QWORD PTR [rip+addend]
fld1
.p2align 6
1: fadd st(0),st(1)
fmul st(0),st(2)
fsub st(0),st(1)
fdiv st(0),st(2)
fabs
dec rdi
jnz 1b
fstp TBYTE PTR [rsi]
fstp st(0)
fstp st(0)
finish mixed5
.section .rodata
.p2align 3
addend: .double 0.125
factor: .double 1.00000011920928955078125 /* exactly 1 + 2^-23 */
two: .double 2.0
memory_value: .double 1.23456789012345
.section .note.GNU-stack,"",@progbits
