# Class 8 observations on this CPU

These are measured observations, not guarantees for unspecified behavior on other CPUs.

| Rule | Supporting rows / pairs | Counterexamples |
|---|---:|---:|
| Full source YMM1/YMM2 remain unchanged, and YMM0 upper-half behavior matches the destination type | 491,520 rows | 0 |
| Legacy mask instructions preserve YMM0[255:128] | 122,880 rows | 0 |
| VEX.128 mask instructions clear YMM0[255:128] | 122,880 rows | 0 |
| Index instructions preserve YMM0, including VEX encodings (their destination is ECX, not a vector register) | 245,760 rows | 0 |
| Bit-mask output has zero in XMM0 bits 127:16, including hardware-observed equal-ordered cases | 122,880 rows | 0 |
| Changing immediate bit 7 leaves YMM0, ECX and flags unchanged | 245,760 paired comparisons | 0 |
| Aligned or +1-unaligned m128 string operands execute without a fault | 327,680 rows | 0 |
| Independently modeled equal-any/ranges/equal-each/equal-ordered outputs, lengths and flags agree | 491,520 rows | 0 |

The nominal byte-mode bit mask uses 16 result bits; word mode uses 8. The generic unused-zero check deliberately asserts only bits 127:16 for all modes; the scalar comparisons additionally check every low-128 output bit on all rows. There are no observed arbitrary/unstable bits in two repeated native executions. The independent equal-ordered model now also checks every result bit and all flags. There are no remaining numerical-model gaps.
