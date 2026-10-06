/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026.
 * Minimal 32-bit static execution probe. No libc and no dynamic loader.
 * An exit status of zero would establish native i386 execution support;
 * the current environment rejects this ELF32 binary before _start.
 */
.globl _start
.section .text
_start:
    movl $1, %eax       /* i386 __NR_exit */
    xorl %ebx, %ebx
    int $0x80
.section .note.GNU-stack,"",@progbits
