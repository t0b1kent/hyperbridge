# Class 9: native BMI/BMI2/ADX reference

Original MIT source: `bmi.c`, immediate-form source `bmi_rorx.inc`, reproducible runner `bmi_run.sh`, and independent output audit `bmi_verify.py`. All result rows are captured from instructions executed by the x86-64 CPU. Neither the C expected-value calculation nor the Python audit generates or modifies result rows.

## Status and reproduction

- CPUID leaf 7 subleaf 0 EBX: `f1bf07ab`; BMI1 bit 3, BMI2 bit 8 and ADX bit 19 all present. All 15 requested mnemonics executed in both permitted operand widths, 32 and 64 bits. These instructions have no 8/16-bit forms.
- `./bmi_run.sh` compiles with `gcc -O2 -Wall -Wextra -mno-red-zone`, executes twice, compares raw output and diagnostic statistics, and independently compresses both streams with `gzip -n -9`; both raw and compressed results are byte-identical.
- `python3 bmi_verify.py` audits `out-09-bmi.txt.gz`, all field widths, expected row counts, input flag states and the empirical full-flags rules below. Audit report: `bmi_RULE_CHECKS.txt`.
- Output: `out-09-bmi.txt.gz`; raw uncompressed `.txt` checksum: `out-09-bmi.sha256`; defined-semantics counters: `bmi_CHECKS.txt`.
- Data rows: **286,616**, plus one CPUID comment. Compressed size: **874,072 bytes** on this capture.
- No packages installed, downloads, emulators or network access used.

## Capture and operand conventions

The inline-assembly block first installs `RFLAGS=0202` or `0ad7`, takes `PUSHFQ/POP` immediately before the tested instruction, executes it, and takes `PUSHFQ/POP` immediately after it. POP, register moves and PUSHFQ do not modify arithmetic flags. Before/after fields are the captured low 16 bits, not requested values. `-mno-red-zone` protects compiler storage from the PUSH/POP capture sequence. R1 is read from the actual destination and R2 from the actual MULX high-result register. Every numeric operand/result/count is padded to the operand width.

Register forms use destination RAX/EAX and source RBX/EBX. For three-operand forms the first data source aliases the destination, so A faithfully represents its initial value. ANDN computes `~A & B`. PDEP/PEXT use A as data and B as mask. BEXTR, BZHI and SARX/SHLX/SHRX store their second, control/count operand in C and print `-` in B. RORX similarly records its immediate in C. MULX begins with both RAX and implicit RDX equal to A; B is its explicit multiplier; R1 is the low product, R2 the high product. ADCX/ADOX have A as the destination and B as their added source.

For each width, there are 22 pattern positions, retaining duplicates deliberately: 0, 1, 2, 3, signed maximum, signed minimum, all ones, alternating 55/AA bits, the low/high/middle one-bit values, then these ten fixed 64-bit constants truncated to the width:

`0123456789abcdef fedcba9876543210 9e3779b97f4a7c15 d1b54a32d192ed03 94d049bb133111eb 2545f4914f6cdd1d deadbeefcafebabe 8000000000000001 0000000100000080 7fffffff00000000`

Every binary register form uses all 22×22 pairs and two initial flag states, for 968 rows per width. Unary BLS* forms use 22×2=44 rows per width. RORX covers all 256 encodable immediates for all 22 data positions and both flags: 11,264 per width. In addition to 22×22 pattern pairs, BEXTR covers every start and length in `0..width+1`, a Cartesian product, for every data position and both flags. Its row counts are `968+34²×22×2=51,832` for 32 bits and `968+66²×22×2=192,632` for 64 bits.

## Coverage and C defined-semantics validation

“Forms” counts encoded width/forms: two register forms per mnemonic, except RORX, which has 256 immediates×2 widths=512 forms. BEXTR control sweeps remain register forms. Memory-source forms, alternative register allocations and upper-half zero-extension above the reported operand width were not separately measured. Non-arithmetic low-16 flags are checked unchanged on every row. There were no execution traps in this class.

| Instruction | Forms | Manual-undefined arithmetic flags | Rows | C defined matches | C defined mismatches |
|---|---:|---|---:|---:|---:|
| ANDN | 2 | AF, PF | 1,936 | 1,936 | 0 |
| BEXTR | 2 | AF, PF, SF | 244,464 | 244,464 | 0 |
| BLSI | 2 | AF, PF | 88 | 88 | 0 |
| BLSMSK | 2 | AF, PF | 88 | 88 | 0 |
| BLSR | 2 | AF, PF | 88 | 88 | 0 |
| BZHI | 2 | AF, PF | 1,936 | 1,936 | 0 |
| MULX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| PDEP | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| PEXT | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| RORX | 512 | None; arithmetic flags unchanged | 22,528 | 22,528 | 0 |
| SARX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| SHLX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| SHRX | 2 | None; arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| ADCX | 2 | None; CF updated, other arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| ADOX | 2 | None; OF updated, other arithmetic flags unchanged | 1,936 | 1,936 | 0 |
| **Total** | **540** | | **286,616** | **286,616** | **0** |

C checks use unsigned modulo-width arithmetic, unsigned 128-bit products/sums, independent bit-by-bit PDEP/PEXT reference loops, extraction truncation and the architecturally specified shift-count masks. The defined-flags mask excludes every manual-undefined flag. Empirical rules are checked separately and do not affect the defined-semantics result.

## Measured rules, with support and contradiction counts

These are observations for this reported CPU/virtual CPU only, not promises for every x86 implementation. Let `R` be the captured result, `p(R)` the even parity of its low byte, `s(R)` its sign bit, `z(R)=(R==0)`, and `mask=2^width-1`. “Preserved” compares with the captured initial flags. The complete arithmetic-flags rule is independently checked against every listed row; the C validator also checks the listed defined result and non-arithmetic low-16 flags.

| Instruction | Observed result / arithmetic-flags rule | Supporting rows | Contradicting rows |
|---|---|---:|---:|
| ANDN | R=`(~A&B)&mask`; AF=0, PF=p(R), CF=OF=0, SF=s(R), ZF=z(R) | 1,936 | 0 |
| BEXTR | Extract C low-byte start and next-byte length, truncating at width; AF=1, PF=p(R), SF=0, CF=OF=0, ZF=z(R) | 244,464 | 0 |
| BLSI | R=`A&(-A)`; AF=0, PF=p(R), CF=(A!=0), OF=0, SF=s(R), ZF=z(R) | 88 | 0 |
| BLSMSK | R=`(A^(A-1))&mask`; AF=0, PF=p(R), CF=(A==0), OF=0, SF=s(R), ZF=0 | 88 | 0 |
| BLSR | R=`A&(A-1)`; AF=0, PF=p(R), CF=(A==0), OF=0, SF=s(R), ZF=z(R) | 88 | 0 |
| BZHI | For n=C&255, R=A if n>=width else A with bits >=n cleared; AF=0, PF=p(R), CF=(n>=width), OF=0, SF=s(R), ZF=z(R) | 1,936 | 0 |
| MULX | R1=low(A×B), R2=high(A×B); all arithmetic flags preserved | 1,936 | 0 |
| PDEP | Deposit low A bits into set positions of B; all arithmetic flags preserved | 1,936 | 0 |
| PEXT | Pack A bits selected by B into low bits; all arithmetic flags preserved | 1,936 | 0 |
| RORX | R=rotate-right(A,C&(width-1)); all arithmetic flags preserved | 22,528 | 0 |
| SARX | R=arithmetic-right(A,C&(width-1)); all arithmetic flags preserved | 1,936 | 0 |
| SHLX | R=(A<<(C&(width-1)))&mask; all arithmetic flags preserved | 1,936 | 0 |
| SHRX | R=A>>(C&(width-1)); all arithmetic flags preserved | 1,936 | 0 |
| ADCX | R=(A+B+CF_before)&mask; CF=carry-out; PF, AF, ZF, SF, OF preserved | 1,936 | 0 |
| ADOX | R=(A+B+OF_before)&mask; OF=unsigned carry-out; CF, PF, AF, ZF, SF preserved | 1,936 | 0 |

In particular, a rule “all undefined BMI flags are zero” is false here. BEXTR sets AF on every tested row, and all six BMI1/BZHI instructions above compute parity rather than preserving PF or uniformly clearing it.
