# SPDX-License-Identifier: MIT
# Copyright (c) 2026 OpenAI
# Encoding crosscheck source only; this is not a separate probe harness.
.intel_syntax noprefix
.text
.globl vector35_encoding_check
vector35_encoding_check:
movups_store: movups XMMWORD PTR [rdi], xmm0
movdqu_store: movdqu XMMWORD PTR [rdi], xmm0
movaps_store: movaps XMMWORD PTR [rdi], xmm0
movdqa_store: movdqa XMMWORD PTR [rdi], xmm0
movss_store: movss DWORD PTR [rdi], xmm0
movsd_store: movsd QWORD PTR [rdi], xmm0
movq_store: movq QWORD PTR [rdi], xmm0
movd_store: movd DWORD PTR [rdi], xmm0
movlps_store: movlps QWORD PTR [rdi], xmm0
movhps_store: movhps QWORD PTR [rdi], xmm0
pextrb_first: pextrb BYTE PTR [rdi], xmm0, 0
pextrb_last: pextrb BYTE PTR [rdi], xmm0, 15
pextrw_first: pextrw WORD PTR [rdi], xmm0, 0
pextrw_last: pextrw WORD PTR [rdi], xmm0, 7
pextrd_first: pextrd DWORD PTR [rdi], xmm0, 0
pextrd_last: pextrd DWORD PTR [rdi], xmm0, 3
pextrq_first: pextrq QWORD PTR [rdi], xmm0, 0
pextrq_last: pextrq QWORD PTR [rdi], xmm0, 1
movntps_store: movntps XMMWORD PTR [rdi], xmm0
movntdq_store: movntdq XMMWORD PTR [rdi], xmm0
maskmovdqu_store: maskmovdqu xmm0, xmm1
vmovdqu_store: vmovdqu YMMWORD PTR [rdi], ymm0
.section .note.GNU-stack,"",@progbits
