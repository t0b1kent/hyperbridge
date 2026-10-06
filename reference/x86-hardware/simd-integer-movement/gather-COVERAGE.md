# Class 7: indexed gathers

| Instruction | VEX L width | Scale forms | Rows | Full scalar checks | Fault state checks |
|---|---:|---:|---:|---:|---:|
| vgatherdps | 128 | 4 | 396 | 252 | 144 |
| vgatherdps | 256 | 4 | 396 | 252 | 144 |
| vgatherqps | 128 | 4 | 396 | 252 | 144 |
| vgatherqps | 256 | 4 | 396 | 252 | 144 |
| vgatherdpd | 128 | 4 | 396 | 252 | 144 |
| vgatherdpd | 256 | 4 | 396 | 252 | 144 |
| vgatherqpd | 128 | 4 | 396 | 252 | 144 |
| vgatherqpd | 256 | 4 | 396 | 252 | 144 |
| vpgatherdd | 128 | 4 | 396 | 252 | 144 |
| vpgatherdd | 256 | 4 | 396 | 252 | 144 |
| vpgatherqd | 128 | 4 | 396 | 252 | 144 |
| vpgatherqd | 256 | 4 | 396 | 252 | 144 |
| vpgatherdq | 128 | 4 | 396 | 252 | 144 |
| vpgatherdq | 256 | 4 | 396 | 252 | 144 |
| vpgatherqq | 128 | 4 | 396 | 252 | 144 |
| vpgatherqq | 256 | 4 | 396 | 252 | 144 |

Total: 64 forms, 6336 predicted and observed rows, 4032 complete scalar result/mask comparisons, 2304 scalar fault-state comparisons. Each mnemonic × VEX128/VEX256 × scale 1/2/4/8 has 9 deterministic data patterns × 11 access/mask scenarios (99 rows).

Scenarios: aligned; one-byte-misaligned base; alternating mask; all mask signs clear with every address protected; protected addresses only in disabled lanes; last-lane fault; first-lane fault; sign-only/noncanonical masks; duplicate indices; fault with noncanonical pending mask bits; fault with both initially disabled and enabled lanes. Negative signed indices occur at every scale. All addresses are within this process’s own guarded mapping or its deliberately inaccessible guard pages.

The .VEX128/.VEX256 name suffix is the encoded form width; the primary width column is the actual destination register width: QPS/QD use XMM destinations even in their L=1 forms. DPD/DQ L=1 use XMM indices and YMM destinations. Full 256-bit index, initial/final destination and mask are retained.

Exact omissions: EVEX/AVX-512 gather/scatter, 32-bit address-size and alternate register-allocation/segment-prefix aliases are outside the requested AVX2 forms. There are no omitted requested mnemonic/scale/L combinations. Signal handlers record actual fault-time destination/mask including XSAVE YMM upper halves; no partial result is synthesized.

Run movement-gather-run.sh from submission. It rebuilds, runs each binary with a 900-second timeout, compares two deterministic gzip -n outputs, and hashes the uncompressed canonical out-gather.txt stream. The scalar C model is compiled with tree/SLP vectorization disabled. gather-manifest.tsv inventories each form; gather-opcode-audit.tsv verifies disassembled mnemonic and VEX L/W bits.
