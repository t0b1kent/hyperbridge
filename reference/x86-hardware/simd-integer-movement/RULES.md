# Empirical rules on the recorded CPU

Detailed support counts are in core-RULES.md, movement-RULES.md, gather-RULES.md, strings-RULES.md and crypto-RULES.md. Statements below are observations on this sample, not exhaustive input proofs or guarantees for undefined behavior on other CPUs.

| Observation | Evidence | Counterexamples |
|---|---:|---:|
| Legacy XMM-writing forms preserve the upper YMM half; VEX128 writes clear it | Full destination checked across every class; per-family counts in reports | 0 |
| Packed oversized logical shifts zero; arithmetic right shifts sign-fill | 43,665 rows / 299,388 elements | 0 |
| PSHUFB high control bit zeroes its selected byte | 180 rows / 2,910 bytes | 0 |
| Successful gathers retain disabled destination lanes and clear the entire final mask, including initially disabled nonzero mask elements | 4,032 full scalar result/mask comparisons | 0 |
| All-off or partly-off gather masks suppress inaccessible addresses | 576 all-off + 576 partly-off protected-address rows | 0 |
| Faulting gathers retain pending destination/mask values, clear completed/disabled mask elements, and reflect actual partial loads | 2,304 fault-context/state comparisons | 0 |
| String bit-mask results have observed zero in XMM0 bits127:16 | 122,880 mask-result rows, including equal-ordered | 0 |
| String immediate bit7 is ignored | 245,760 paired comparisons of result, ECX and flags | 0 |
| PCLMUL ignores selector bits other than0/4 | 16,128 pairs | 0 |
| SHA1RNDS4 ignores bits7:2 | 6,048 pairs | 0 |
| VZEROUPPER preserves every low half / clears every high half; VZEROALL clears all YMM registers | 256 YMM observations | 0 |

## Important qualifications

- The VEX upper-zero shorthand applies to instructions that actually write XMM. Memory stores, GPR-result operations, PTEST/VTEST and string index operations do not write an imaginary vector destination. Their full vectors are preserved. VEXTRACT128 clears its XMM destination high half despite a 256-bit source encoding
- Successful gathers zero bits outside the form's output lanes. On this host, faulting gathers instead retain those destination and mask bits, including poisoned YMM high halves. These are captured from signal XSAVE context, not post-longjmp registers
- VMASKMOVPS/PD and VPMASKMOVD/Q suppress disabled protected lanes. **MASKMOVDQU/VMASKMOVDQU are counterexamples to a blanket “all masked vector stores suppress all inaccessible addresses” rule**: 18 guard-off and 18 all-off protected-address rows fault on this machine, while the corresponding categories have 144 successes each from the other masked families
- Legacy aligned-only memory operations and legacy AES/PCLMUL misaligned operands produce real faults. They are retained, with actual register/fault state, rather than omitted or replaced with hypothetical success values
- Word string masks nominally use eight result bits, byte masks sixteen. The common unused-zero empirical check conservatively asserts bits127:16 in both modes; complete scalar checks verify all low128 bits in every aggregation mode. No unstable output bit was seen in repeated executions. Every equal-ordered string and SHA row independently matches the original scalar model
