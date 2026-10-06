# Class 1: data movement and widening

| Instruction | Encodings | Operand forms | Assembled immediate forms | Rows | Checked | Faults |
|---|---|---:|---:|---:|---:|---:|
| movd | SSE | 4 | 4 | 54 | 54 | 0 |
| movq | SSE | 6 | 6 | 72 | 72 | 0 |
| movdqa | SSE | 3 | 3 | 45 | 45 | 18 |
| movdqu | SSE | 3 | 3 | 45 | 45 | 0 |
| movaps | SSE | 3 | 3 | 45 | 45 | 18 |
| movups | SSE | 3 | 3 | 45 | 45 | 0 |
| movapd | SSE | 3 | 3 | 45 | 45 | 18 |
| movupd | SSE | 3 | 3 | 45 | 45 | 0 |
| movss | SSE | 4 | 4 | 54 | 54 | 0 |
| movsd | SSE | 4 | 4 | 54 | 54 | 0 |
| movlps | SSE | 2 | 2 | 36 | 36 | 0 |
| movhps | SSE | 2 | 2 | 36 | 36 | 0 |
| movlpd | SSE | 2 | 2 | 36 | 36 | 0 |
| movhpd | SSE | 2 | 2 | 36 | 36 | 0 |
| movlhps | SSE | 1 | 1 | 9 | 9 | 0 |
| movhlps | SSE | 1 | 1 | 9 | 9 | 0 |
| movddup | SSE | 2 | 2 | 27 | 27 | 0 |
| movsldup | SSE | 2 | 2 | 27 | 27 | 9 |
| movshdup | SSE | 2 | 2 | 27 | 27 | 9 |
| pmovzxbw | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovzxbd | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovzxbq | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovzxwd | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovzxwq | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovzxdq | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovsxbw | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovsxbd | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovsxbq | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovsxwd | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovsxwq | SSE | 2 | 2 | 27 | 27 | 0 |
| pmovsxdq | SSE | 2 | 2 | 27 | 27 | 0 |
| movmskps | SSE | 1 | 1 | 9 | 9 | 0 |
| movmskpd | SSE | 1 | 1 | 9 | 9 | 0 |
| pmovmskb | SSE | 1 | 1 | 9 | 9 | 0 |
| maskmovdqu | SSE | 1 | 1 | 63 | 63 | 27 |
| pextrb | SSE | 2 | 512 | 6912 | 6912 | 0 |
| pextrw | SSE | 3 | 768 | 9216 | 9216 | 0 |
| pextrd | SSE | 2 | 512 | 6912 | 6912 | 0 |
| pextrq | SSE | 2 | 512 | 6912 | 6912 | 0 |
| pinsrb | SSE | 2 | 512 | 6912 | 6912 | 0 |
| pinsrw | SSE | 2 | 512 | 6912 | 6912 | 0 |
| pinsrd | SSE | 2 | 512 | 6912 | 6912 | 0 |
| pinsrq | SSE | 2 | 512 | 6912 | 6912 | 0 |
| extractps | SSE | 2 | 512 | 6912 | 6912 | 0 |
| insertps | SSE | 2 | 512 | 6912 | 6912 | 0 |
| vmovd | VEX128 | 4 | 4 | 54 | 54 | 0 |
| vmovq | VEX128 | 6 | 6 | 72 | 72 | 0 |
| vmovdqa | VEX128, VEX256 | 6 | 6 | 90 | 90 | 36 |
| vmovdqu | VEX128, VEX256 | 6 | 6 | 90 | 90 | 0 |
| vmovaps | VEX128, VEX256 | 6 | 6 | 90 | 90 | 36 |
| vmovups | VEX128, VEX256 | 6 | 6 | 90 | 90 | 0 |
| vmovapd | VEX128, VEX256 | 6 | 6 | 90 | 90 | 36 |
| vmovupd | VEX128, VEX256 | 6 | 6 | 90 | 90 | 0 |
| vmovss | VEX128 | 4 | 4 | 54 | 54 | 0 |
| vmovsd | VEX128 | 4 | 4 | 54 | 54 | 0 |
| vmovlps | VEX128 | 2 | 2 | 36 | 36 | 0 |
| vmovhps | VEX128 | 2 | 2 | 36 | 36 | 0 |
| vmovlpd | VEX128 | 2 | 2 | 36 | 36 | 0 |
| vmovhpd | VEX128 | 2 | 2 | 36 | 36 | 0 |
| vmovlhps | VEX128 | 1 | 1 | 9 | 9 | 0 |
| vmovhlps | VEX128 | 1 | 1 | 9 | 9 | 0 |
| vmovddup | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vmovsldup | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vmovshdup | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovzxbw | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovzxbd | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovzxbq | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovzxwd | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovzxwq | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovzxdq | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovsxbw | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovsxbd | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovsxbq | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovsxwd | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovsxwq | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpmovsxdq | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vmovmskps | VEX128, VEX256 | 2 | 2 | 18 | 18 | 0 |
| vmovmskpd | VEX128, VEX256 | 2 | 2 | 18 | 18 | 0 |
| vpmovmskb | VEX128, VEX256 | 2 | 2 | 18 | 18 | 0 |
| vmaskmovdqu | VEX128 | 1 | 1 | 63 | 63 | 27 |
| vpextrb | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vpextrw | VEX128 | 3 | 768 | 9216 | 9216 | 0 |
| vpextrd | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vpextrq | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vpinsrb | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vpinsrw | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vpinsrd | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vpinsrq | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vextractps | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vinsertps | VEX128 | 2 | 512 | 6912 | 6912 | 0 |
| vbroadcastss | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vbroadcastsd | VEX256 | 2 | 2 | 27 | 27 | 0 |
| vbroadcastf128 | VEX256 | 1 | 1 | 18 | 18 | 0 |
| vbroadcasti128 | VEX256 | 1 | 1 | 18 | 18 | 0 |
| vpbroadcastb | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpbroadcastw | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpbroadcastd | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vpbroadcastq | VEX128, VEX256 | 4 | 4 | 54 | 54 | 0 |
| vextractf128 | VEX256 | 2 | 512 | 6912 | 6912 | 0 |
| vinsertf128 | VEX256 | 2 | 512 | 6912 | 6912 | 0 |
| vextracti128 | VEX256 | 2 | 512 | 6912 | 6912 | 0 |
| vinserti128 | VEX256 | 2 | 512 | 6912 | 6912 | 0 |
| vmaskmovps | VEX128, VEX256 | 4 | 4 | 252 | 252 | 36 |
| vmaskmovpd | VEX128, VEX256 | 4 | 4 | 252 | 252 | 36 |
| vpmaskmovd | VEX128, VEX256 | 4 | 4 | 252 | 252 | 36 |
| vpmaskmovq | VEX128, VEX256 | 4 | 4 | 252 | 252 | 36 |

Total: 13051 separately assembled forms; 174861 predicted and observed rows. 174483 complete scalar-result comparisons, 378 fault-path scalar/state invariants. No instruction results are generated by the model.

All PEXTR/PINSR, EXTRACTPS/INSERTPS and 128-bit insert/extract controls cover every immediate byte 0–255. For PEXTRW both SSE2 register-only and SSE4.1 register/memory opcodes are included, also their VEX counterparts. MOVQ and scalar MOVSS/MOVSD both load- and store-opcode register aliases are included.

Register forms use 9 fixed input patterns. Every memory form uses aligned and one-byte-misaligned pointers. Masked forms additionally use boundary-crossing protected-page lanes disabled/enabled, all-disabled protected-page addresses, all-enabled and alternating masks. Aligned-only instructions are deliberately run unaligned and their fault/context is recorded. Prefix/writes are observed using actual full YMM0 and YMM2 snapshots.

Reduction rule: 128-bit move chunks use two 64-bit pattern units (or the numbered-byte pattern), avoiding out-of-range scalar shifts. 9 deterministic source patterns; destination and extra source use different fixed nonzero patterns, rather than a full Cartesian product. Element patterns include zero, one, all ones, signed extrema, AA/55 and mixed edge lanes. Every legal requested SSE/VEX128/VEX256 operand form is retained. MOVLPD/MOVHPD and VBROADCASTI128 are included as useful adjacent forms.

Primary fields follow the task: X1 is the actual vector/GPR/memory destination before, and the first result is that destination after. Width is destination width. GPR values use 8 hex digits for 32-bit destinations and 16 for 64-bit destinations. X2/X3 are the actual sources (including GPR/memory inputs); absent sources are -. Full YMM/GPR/memory observations remain in named extras. UNKNOWN marks a memory value whose full span is inaccessible; MEM_BEFORE/MEM_AFTER show only the actual readable prefix with ACCESSIBLE_BYTES, never fabricated inaccessible bytes.

Scope/omissions: MMX, EVEX/AVX-512, privileged instructions, segment/address-size variants, redundant REX/prefix/register-number choices, and unrelated non-temporal moves are outside the requested SSE/AVX/AVX2 scope. VZEROUPPER/VZEROALL are supplied by class 10. Faulting operations have architectural invariants checked, not a fabricated successful value. The exact signal, trap and error code and actual fault-time YMM context are retained. No external or kernel memory is accessed.
