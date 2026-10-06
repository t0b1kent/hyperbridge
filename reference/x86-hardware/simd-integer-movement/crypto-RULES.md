# Class 9 observations on this CPU

| Observation | Supporting rows / pairs | Counterexamples |
|---|---:|---:|
| Vector upper-half semantics plus implicit YMM0 preservation match the encoding | 33,208 successful vector rows | 0 |
| Legacy vector instructions preserve destination upper 128 bits | 14,560 successful rows | 0 |
| VEX.128 vector instructions zero destination upper 128 bits | 12,408 rows | 0 |
| VEX.256 AES/PCLMUL compute both independent 128-bit lanes, scalar-model checked | 6,240 rows | 0 |
| PCLMUL ignores immediate bits other than 0 and 4 | 16,128 paired comparisons | 0 |
| SHA1RNDS4 ignores immediate bits 7:2 | 6,048 paired comparisons | 0 |
| Legacy AES rounds/AESIMC/AESKEYGENASSIST/PCLMUL +1-unaligned m128 operands raise SIGSEGV | 4,136 rows | 0 |
| Corresponding VEX memory operands, including unaligned, execute and match scalar C | see per-family coverage | 0 |
| Actual fault-time destination/source/implicit registers and memory remain unchanged; SIGSEGV/#GP(0) matches the expected alignment fault | 4,136 snapshots | 0 |
| All successful SHA results match independent scalar rounds/message schedules | 6,288 rows | 0 |
| CRC32 outputs have the expected zero-extended 32-bit CRC32C, for every legal destination/source width tested | 120 rows | 0 |
| MOVBE 16-bit loads preserve upper destination bits; 32-bit loads zero-extend; stores update only the operand width | 96 combined load/store rows | 0 |

The unaligned legacy faults are retained as result rows, rather than omitted or replaced. SHA unaligned memory operands succeed in all **2,096** corresponding rows (256 immediate SHA1RNDS4 forms × 8 cases = 2,048, plus six other SHA mnemonics × 8 = 48).

The full two-run raw and deterministic-gzip comparisons pass. These results describe the AMD EPYC 9V74 recorded in `crypto-machine.txt`; a hypervisor is advertised by CPUID, but the programs execute native x86-64 instructions directly and use no emulator.
