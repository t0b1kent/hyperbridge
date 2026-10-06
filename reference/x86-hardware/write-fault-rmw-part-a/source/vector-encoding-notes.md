# Vector-store encoding cases

Original code, SPDX-License-Identifier: MIT. This module is case data for the parent's native Linux probe, not a separate harness.

## Coverage

`vector.py:forms()` returns 28 independent dictionaries representing 22 distinct instruction encodings:

- MOVUPS, MOVDQU, MOVAPS, MOVDQA
- MOVSS, MOVSD, MOVQ, MOVD, MOVLPS, MOVHPS
- PEXTRB/W/D/Q, each with immediate lane 0 and the final lane (15/7/3/1 respectively)
- MOVNTPS, MOVNTDQ
- MASKMOVDQU with seven masks: all selected, none selected, low eight, high eight, alternating even, alternating odd, and endpoints
- VMOVDQU YMM

Counts by destination span: 1 byte: 2; 2 bytes: 2; 4 bytes: 4; 8 bytes: 6; 16 bytes: 13; 32 bytes: 1.

All stores target `[rdi]`, explicitly or implicitly. XMM0/YMM0 is the source. MASKMOVDQU uses XMM0 as data and XMM1 as mask. The mask hex string is ordered by increasing memory byte offset / increasing XMM byte index. A selected sparse-mask byte is `80`, while an unselected byte is `00`; only the high bit is significant. The full mask uses `ff` throughout. The destination `width` remains 16 for every mask, including the zero mask, so all address placements can be exercised without prejudging fault suppression.

No general register or flags overrides are needed. SSE2 is used as the common x86-64 baseline feature label (some individual opcodes need only SSE). Memory PEXTRW uses the SSE4.1 encoding, not the older register-only PEXTRW encoding. PEXTRB/D/Q also use feature `sse4_1`. VMOVDQU uses feature `avx`; the harness must check CPU AVX/OSXSAVE and XCR0 XMM+YMM enablement before executing it or initializing YMM state.

## Layout exclusions and ordering

MOVAPS, MOVDQA, MOVNTPS and MOVNTDQ each set `alignment=16`. Legal aligned 16-byte accesses cannot cross a 4096-byte page boundary: an aligned start is a multiple of 16 and so is the boundary. A start 1 through 15 bytes before that boundary is necessarily misaligned. Mark those cross-page cells **N/A: aligned vector cross-page placement impossible with 4 KiB pages**; do not count them as measured page-fault cases. Writable-page and wholly-read-only-page controls still apply.

The two one-byte PEXTRB cases have no cross-page offset. For the remaining applicable forms, the sum of all legal cross-page offsets is 222; at five cross-page layouts this is 1110 cells, plus 56 whole-page writable/read-only controls for 1166 basic form/layout/offset cells before continuation modes and repeated runs.

Non-temporal instructions can use weakly ordered write-combining behavior. The harness should document how SFENCE/draining is handled when sampling memory after successful execution and at the fault-handler snapshot. Do not mistake an unfenced visibility issue for a partial architectural store. The zero and sparse MASKMOVDQU cases must be measured, not used to assume that inaccessible unselected bytes suppress all exceptions.

## GNU assembler verification

The included `vector-encodings.S` is an encoding crosscheck source only. It was assembled with GNU as and disassembled with GNU objdump:

```
as --64 -o /tmp/vector35-encodings.o vector-encodings.S
objdump -d -Mintel /tmp/vector35-encodings.o
```

`vector-encodings.objdump.txt` records the output. A Python check loaded all 28 cases, verified unique names and 16-byte masks, parsed the 22 instructions in objdump output, and required exact equality of the distinct encoded-byte sets. It passed. No hardware-fault result is claimed by this encoding-only validation.
