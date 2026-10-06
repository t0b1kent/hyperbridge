# Classes 2–6: native forms and rows

A form is one mnemonic × legal encoding/width × register/aligned-memory/+1-memory operand variant × immediate byte (when present). All immediate groups contain exactly 256 forms. Each memory form has its own labelled native instruction. Full YMM destination is printed even for 128-bit operations.

| Class | Mnemonic | Encodings/width | Forms | Rows |
|---|---|---|---:|---:|
| arithmetic | mpsadbw | SSE128, VEX128, VEX256 | 2304 | 9216 |
| arithmetic | pabsb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pabsd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pabsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddq | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddsb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddusb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddusw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | paddw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pavgb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pavgw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | phaddd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | phaddsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | phaddw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | phminposuw | SSE128, VEX128 | 6 | 144 |
| arithmetic | phsubd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | phsubsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | phsubw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaddubsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaddwd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaxsb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaxsd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaxsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaxub | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaxud | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmaxuw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pminsb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pminsd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pminsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pminub | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pminud | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pminuw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmuldq | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmulhrsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmulhuw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmulhw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmulld | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmullw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | pmuludq | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psadbw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psignb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psignd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psignw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubd | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubq | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubsb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubsw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubusb | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubusw | SSE128, VEX128, VEX256 | 9 | 216 |
| arithmetic | psubw | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | andnpd | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | andnps | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | andpd | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | andps | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | orpd | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | orps | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pand | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pandn | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpeqb | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpeqd | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpeqq | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpeqw | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpgtb | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpgtd | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpgtq | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pcmpgtw | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | por | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | ptest | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | pxor | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | testpd | VEX128, VEX256 | 6 | 144 |
| logic | testps | VEX128, VEX256 | 6 | 144 |
| logic | xorpd | SSE128, VEX128, VEX256 | 9 | 216 |
| logic | xorps | SSE128, VEX128, VEX256 | 9 | 216 |
| pack | packssdw | SSE128, VEX128, VEX256 | 9 | 216 |
| pack | packsswb | SSE128, VEX128, VEX256 | 9 | 216 |
| pack | packusdw | SSE128, VEX128, VEX256 | 9 | 216 |
| pack | packuswb | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | blendpd | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | blendps | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | blendvpd | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | blendvps | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | palignr | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | pblendd | VEX128, VEX256 | 1536 | 6144 |
| permutation | pblendvb | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | pblendw | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | perm2f128 | VEX256 | 768 | 3072 |
| permutation | perm2i128 | VEX256 | 768 | 3072 |
| permutation | permd | VEX256 | 3 | 72 |
| permutation | permilpd | VEX128, VEX256 | 1542 | 6288 |
| permutation | permilps | VEX128, VEX256 | 1542 | 6288 |
| permutation | permpd | VEX256 | 768 | 3072 |
| permutation | permps | VEX256 | 3 | 72 |
| permutation | permq | VEX256 | 768 | 3072 |
| permutation | pshufb | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | pshufd | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | pshufhw | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | pshuflw | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | punpckhbw | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | punpckhdq | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | punpckhqdq | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | punpckhwd | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | punpcklbw | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | punpckldq | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | punpcklqdq | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | punpcklwd | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | shufpd | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | shufps | SSE128, VEX128, VEX256 | 2304 | 9216 |
| permutation | unpckhpd | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | unpckhps | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | unpcklpd | SSE128, VEX128, VEX256 | 9 | 216 |
| permutation | unpcklps | SSE128, VEX128, VEX256 | 9 | 216 |
| shifts | pslld | SSE128, VEX128, VEX256 | 777 | 6486 |
| shifts | pslldq | SSE128, VEX128, VEX256 | 768 | 6144 |
| shifts | psllq | SSE128, VEX128, VEX256 | 777 | 6774 |
| shifts | psllvd | VEX128, VEX256 | 6 | 144 |
| shifts | psllvq | VEX128, VEX256 | 6 | 144 |
| shifts | psllw | SSE128, VEX128, VEX256 | 777 | 6342 |
| shifts | psrad | SSE128, VEX128, VEX256 | 777 | 6486 |
| shifts | psravd | VEX128, VEX256 | 6 | 144 |
| shifts | psraw | SSE128, VEX128, VEX256 | 777 | 6342 |
| shifts | psrld | SSE128, VEX128, VEX256 | 777 | 6486 |
| shifts | psrldq | SSE128, VEX128, VEX256 | 768 | 6144 |
| shifts | psrlq | SSE128, VEX128, VEX256 | 777 | 6774 |
| shifts | psrlvd | VEX128, VEX256 | 6 | 144 |
| shifts | psrlvq | VEX128, VEX256 | 6 | 144 |
| shifts | psrlw | SSE128, VEX128, VEX256 | 777 | 6342 |

## Input reduction and omissions

All immediate values are retained. Immediate permutations/arithmetic use 4 deterministic input cases; immediate shifts use 8. Non-immediate forms use 24 cases, except scalar-count shifts use element-width-in-bits + 6 (0 through width+1 plus four very large counts). Lane values mix zero, one, all ones, sign boundaries, saturation boundaries, alternating bits, fixed byte tags and out-of-range/high-bit controls. This is a documented input sample, not an exhaustive Cartesian product.

All requested SSE/VEX128/VEX256 forms for these classes are included where ISA encodings exist. Memory operands use aligned and +1-unaligned addresses. Legacy alignment faults are captured as actual fault-time states. Immediate packed shifts have register destinations/sources only; no nonexistent memory form is invented. No MMX, EVEX or AVX-512-only instructions (such as VPSRAVQ) are in the requested SSE/AVX/AVX2 scope. Class 10 additionally snapshots all sixteen YMM registers for VZEROUPPER/VZEROALL.

C models cover every successfully executed row in these classes; fault rows verify actual destination preservation instead. core-verify.py checks each linked instruction mnemonic, VEX/SSE prefix, width, memory/register choice, all immediate bytes, row counts, raw SHA-256 and selected semantic rules.
