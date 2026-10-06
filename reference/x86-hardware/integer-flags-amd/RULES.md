# Measured integer rules on this machine

These are empirical observations on the CPU named in MACHINE.txt, not architectural guarantees. Every supporting/contradicting count below is computed from the unmodified native rows by analyze_core.py. Counts include both initial flag patterns and duplicate labeled input positions. A zero contradiction count applies only to the stated sample.

Notation: n is COUNT masked with 31 (8/16/32-bit operands) or 63 (64-bit operands); MSB/LSB refer to the operand width. `preserved` compares the same flag before and after. Defined semantics are independently checked by the C model in core.c; exact check counts are in each class validation file.

## Per-command coverage and rules

### SHL
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit cl, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit imm, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 264; contradicting 0.
- 8-bit cl, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 264; contradicting 0.
- 8-bit imm, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 440; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 440; contradicting 0.
- 8-bit cl, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 440; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 440; contradicting 0.
- 16-bit imm, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit cl, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit imm, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 616; contradicting 0.
- 16-bit cl, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 616; contradicting 0.
- 16-bit imm, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 704; contradicting 0.
- 16-bit cl, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 704; contradicting 0.
- 32-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit imm, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 64-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit imm, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.

### SAL
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit cl, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit imm, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 264; contradicting 0.
- 8-bit cl, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 264; contradicting 0.
- 8-bit imm, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 440; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 440; contradicting 0.
- 8-bit cl, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 440; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 440; contradicting 0.
- 16-bit imm, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit cl, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit imm, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 616; contradicting 0.
- 16-bit cl, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 616; contradicting 0.
- 16-bit imm, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 704; contradicting 0.
- 16-bit cl, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = CF_after; also matches MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 704; contradicting 0.
- 32-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit imm, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 64-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit imm, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.

### SHR
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit cl, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit imm, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 264; contradicting 0.
- 8-bit cl, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 264; contradicting 0.
- 8-bit imm, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 440; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 440; contradicting 0.
- 8-bit cl, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 440; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 440; contradicting 0.
- 16-bit imm, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit cl, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit imm, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 616; contradicting 0.
- 16-bit cl, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 616; contradicting 0.
- 16-bit imm, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 704; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 704; contradicting 0.
- 16-bit cl, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 704; contradicting 0.
  - CF = last shifted bit of zero-extended input (0 beyond width). Supporting 704; contradicting 0.
- 32-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit imm, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 64-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit imm, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = 0; also matches top two bits of R1 XOR. Supporting 5456; contradicting 0.

### SAR
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit cl, masked count = 1 (44 rows):
  - AF = 1. Supporting 44; contradicting 0.
- 8-bit imm, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 264; contradicting 0.
- 8-bit cl, masked count > 1, less than width (264 rows):
  - AF = 1. Supporting 264; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 264; contradicting 0.
- 8-bit imm, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 440; contradicting 0.
- 8-bit cl, masked count >= width (440 rows):
  - AF = 1. Supporting 440; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 440; contradicting 0.
- 16-bit imm, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit cl, masked count = 1 (88 rows):
  - AF = 1. Supporting 88; contradicting 0.
- 16-bit imm, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 616; contradicting 0.
- 16-bit cl, masked count > 1, less than width (616 rows):
  - AF = 1. Supporting 616; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 616; contradicting 0.
- 16-bit imm, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 704; contradicting 0.
- 16-bit cl, masked count >= width (704 rows):
  - AF = 1. Supporting 704; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 704; contradicting 0.
- 32-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 32-bit imm, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1, less than width (2640 rows):
  - AF = 1. Supporting 2640; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 64-bit imm, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit cl, masked count = 1 (132 rows):
  - AF = 1. Supporting 132; contradicting 0.
- 64-bit imm, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1, less than width (5456 rows):
  - AF = 1. Supporting 5456; contradicting 0.
  - OF = 0; also matches MSB(A) XOR MSB(R1); also matches top two bits of R1 XOR. Supporting 5456; contradicting 0.

### ROL
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count > 1 (704 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
- 8-bit cl, masked count > 1 (704 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
- 16-bit imm, masked count > 1 (1320 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 1320; contradicting 0.
- 16-bit cl, masked count > 1 (1320 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 1320; contradicting 0.
- 32-bit imm, masked count > 1 (2640 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1 (2640 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 64-bit imm, masked count > 1 (5456 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1 (5456 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.

### ROR
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count > 1 (704 rows):
  - OF = top two bits of R1 XOR. Supporting 704; contradicting 0.
- 8-bit cl, masked count > 1 (704 rows):
  - OF = top two bits of R1 XOR. Supporting 704; contradicting 0.
- 16-bit imm, masked count > 1 (1320 rows):
  - OF = top two bits of R1 XOR. Supporting 1320; contradicting 0.
- 16-bit cl, masked count > 1 (1320 rows):
  - OF = top two bits of R1 XOR. Supporting 1320; contradicting 0.
- 32-bit imm, masked count > 1 (2640 rows):
  - OF = top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1 (2640 rows):
  - OF = top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 64-bit imm, masked count > 1 (5456 rows):
  - OF = top two bits of R1 XOR. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1 (5456 rows):
  - OF = top two bits of R1 XOR. Supporting 5456; contradicting 0.

### RCL
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count > 1 (704 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
- 8-bit cl, masked count > 1 (704 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 704; contradicting 0.
- 16-bit imm, masked count > 1 (1320 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 1320; contradicting 0.
- 16-bit cl, masked count > 1 (1320 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 1320; contradicting 0.
- 32-bit imm, masked count > 1 (2640 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1 (2640 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 2640; contradicting 0.
- 64-bit imm, masked count > 1 (5456 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1 (5456 rows):
  - OF = MSB(R1) XOR CF_after. Supporting 5456; contradicting 0.

### RCR
21,824 measured rows; 496 width/form/immediate configurations.

- 8-bit imm, masked count > 1 (704 rows):
  - OF = top two bits of R1 XOR. Supporting 704; contradicting 0.
- 8-bit cl, masked count > 1 (704 rows):
  - OF = top two bits of R1 XOR. Supporting 704; contradicting 0.
- 16-bit imm, masked count > 1 (1320 rows):
  - OF = top two bits of R1 XOR. Supporting 1320; contradicting 0.
- 16-bit cl, masked count > 1 (1320 rows):
  - OF = top two bits of R1 XOR. Supporting 1320; contradicting 0.
- 32-bit imm, masked count > 1 (2640 rows):
  - OF = top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 32-bit cl, masked count > 1 (2640 rows):
  - OF = top two bits of R1 XOR. Supporting 2640; contradicting 0.
- 64-bit imm, masked count > 1 (5456 rows):
  - OF = top two bits of R1 XOR. Supporting 5456; contradicting 0.
- 64-bit cl, masked count > 1 (5456 rows):
  - OF = top two bits of R1 XOR. Supporting 5456; contradicting 0.

### SHLD
371,712 measured rows; 384 width/form/immediate configurations.

- 16-bit imm: REJECTED candidate: result equals high16(ROL32((A << 16) | B, n)). Supporting 5824; contradicting 23216.
- 16-bit imm: for masked count 17..31, undefined result equals ROL16(B, n - 16) (independent of A). Supporting 29040; contradicting 0.
- 16-bit cl: REJECTED candidate: result equals high16(ROL32((A << 16) | B, n)). Supporting 5824; contradicting 23216.
- 16-bit cl: for masked count 17..31, undefined result equals ROL16(B, n - 16) (independent of A). Supporting 29040; contradicting 0.
- 16-bit imm, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 16-bit cl, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 16-bit imm, 1 < masked count < width (27104 rows):
  - AF = 1. Supporting 27104; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 27104; contradicting 0.
- 16-bit cl, 1 < masked count < width (27104 rows):
  - AF = 1. Supporting 27104; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 27104; contradicting 0.
- 16-bit imm, masked count = width (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
  - OF = CF_after. Supporting 1936; contradicting 0.
- 16-bit cl, masked count = width (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
  - OF = CF_after. Supporting 1936; contradicting 0.
- 16-bit imm, masked count > width (29040 rows):
  - CF = 0. Supporting 29040; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 29040; contradicting 0.
  - AF = 1. Supporting 29040; contradicting 0.
  - ZF = R1 == 0. Supporting 29040; contradicting 0.
  - SF = MSB(R1). Supporting 29040; contradicting 0.
  - OF = 0; also matches CF_after. Supporting 29040; contradicting 0.
- 16-bit cl, masked count > width (29040 rows):
  - CF = 0. Supporting 29040; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 29040; contradicting 0.
  - AF = 1. Supporting 29040; contradicting 0.
  - ZF = R1 == 0. Supporting 29040; contradicting 0.
  - SF = MSB(R1). Supporting 29040; contradicting 0.
  - OF = 0; also matches CF_after. Supporting 29040; contradicting 0.
- 32-bit imm, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 32-bit cl, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 32-bit imm, 1 < masked count < width (58080 rows):
  - AF = 1. Supporting 58080; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 58080; contradicting 0.
- 32-bit cl, 1 < masked count < width (58080 rows):
  - AF = 1. Supporting 58080; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 58080; contradicting 0.
- 64-bit imm, masked count = 1 (968 rows):
  - AF = 1. Supporting 968; contradicting 0.
- 64-bit cl, masked count = 1 (968 rows):
  - AF = 1. Supporting 968; contradicting 0.
- 64-bit imm, 1 < masked count < width (60016 rows):
  - AF = 1. Supporting 60016; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 60016; contradicting 0.
- 64-bit cl, 1 < masked count < width (60016 rows):
  - AF = 1. Supporting 60016; contradicting 0.
  - OF = MSB(R1) XOR CF_after. Supporting 60016; contradicting 0.

### SHRD
371,712 measured rows; 384 width/form/immediate configurations.

- 16-bit imm: REJECTED candidate: result equals low16(ROR32((B << 16) | A, n)). Supporting 4320; contradicting 24720.
- 16-bit imm: for masked count 17..31, undefined result equals ROR16(B, n - 16) (independent of A). Supporting 29040; contradicting 0.
- 16-bit cl: REJECTED candidate: result equals low16(ROR32((B << 16) | A, n)). Supporting 4320; contradicting 24720.
- 16-bit cl: for masked count 17..31, undefined result equals ROR16(B, n - 16) (independent of A). Supporting 29040; contradicting 0.
- 16-bit imm, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 16-bit cl, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 16-bit imm, 1 < masked count < width (27104 rows):
  - AF = 1. Supporting 27104; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 27104; contradicting 0.
- 16-bit cl, 1 < masked count < width (27104 rows):
  - AF = 1. Supporting 27104; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 27104; contradicting 0.
- 16-bit imm, masked count = width (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 1936; contradicting 0.
- 16-bit cl, masked count = width (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 1936; contradicting 0.
- 16-bit imm, masked count > width (29040 rows):
  - CF = 0. Supporting 29040; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 29040; contradicting 0.
  - AF = 1. Supporting 29040; contradicting 0.
  - ZF = R1 == 0. Supporting 29040; contradicting 0.
  - SF = MSB(R1). Supporting 29040; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 29040; contradicting 0.
- 16-bit cl, masked count > width (29040 rows):
  - CF = 0. Supporting 29040; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 29040; contradicting 0.
  - AF = 1. Supporting 29040; contradicting 0.
  - ZF = R1 == 0. Supporting 29040; contradicting 0.
  - SF = MSB(R1). Supporting 29040; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 29040; contradicting 0.
- 32-bit imm, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 32-bit cl, masked count = 1 (1936 rows):
  - AF = 1. Supporting 1936; contradicting 0.
- 32-bit imm, 1 < masked count < width (58080 rows):
  - AF = 1. Supporting 58080; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 58080; contradicting 0.
- 32-bit cl, 1 < masked count < width (58080 rows):
  - AF = 1. Supporting 58080; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 58080; contradicting 0.
- 64-bit imm, masked count = 1 (968 rows):
  - AF = 1. Supporting 968; contradicting 0.
- 64-bit cl, masked count = 1 (968 rows):
  - AF = 1. Supporting 968; contradicting 0.
- 64-bit imm, 1 < masked count < width (60016 rows):
  - AF = 1. Supporting 60016; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 60016; contradicting 0.
- 64-bit cl, 1 < masked count < width (60016 rows):
  - AF = 1. Supporting 60016; contradicting 0.
  - OF = top two bits of R1 XOR. Supporting 60016; contradicting 0.

### MUL
3,872 measured rows; 4 width/form/immediate configurations.

- 8-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 16-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.

### IMUL1
3,872 measured rows; 4 width/form/immediate configurations.

- 8-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 16-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.

### IMUL2
2,904 measured rows; 3 width/form/immediate configurations.

- 16-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.

### IMUL3
38,720 measured rows; 40 width/form/immediate configurations.

- 16-bit imm, all executions (11616 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 11616; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 11616; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 11616; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 11616; contradicting 0.
- 32-bit imm, all executions (13552 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.
- 64-bit imm, all executions (13552 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 13552; contradicting 0.

### DIV
87,128 measured rows; 4 width/form/immediate configurations.

- 8-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 11710; contradicting 0.
- 8-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 10066.
- 16-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 11528; contradicting 0.
- 16-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 10248.
- 32-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 11540; contradicting 0.
- 32-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 10236.
- 64-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 11410; contradicting 0.
- 64-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 10390.
- 8-bit reg, trap context (11710 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 11710; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 11710; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 11710; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 11710; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 11710; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 11710; contradicting 0.
- 8-bit reg, successful division (10066 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 10066; contradicting 0.
  - PF = 0. Supporting 10066; contradicting 0.
  - AF = 1. Supporting 10066; contradicting 0.
  - ZF = 0. Supporting 10066; contradicting 0.
  - SF = 0. Supporting 10066; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 10066; contradicting 0.
- 16-bit reg, trap context (11528 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 11528; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 11528; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 11528; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 11528; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 11528; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 11528; contradicting 0.
- 16-bit reg, successful division (10248 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 10248; contradicting 0.
  - PF = 0. Supporting 10248; contradicting 0.
  - AF = 1. Supporting 10248; contradicting 0.
  - ZF = 0. Supporting 10248; contradicting 0.
  - SF = 0. Supporting 10248; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 10248; contradicting 0.
- 32-bit reg, trap context (11540 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 11540; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 11540; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 11540; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 11540; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 11540; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 11540; contradicting 0.
- 32-bit reg, successful division (10236 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 10236; contradicting 0.
  - PF = 0. Supporting 10236; contradicting 0.
  - AF = 1. Supporting 10236; contradicting 0.
  - ZF = 0. Supporting 10236; contradicting 0.
  - SF = 0. Supporting 10236; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 10236; contradicting 0.
- 64-bit reg, trap context (11410 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 11410; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 11410; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 11410; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 11410; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 11410; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 11410; contradicting 0.
- 64-bit reg, successful division (10390 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 10390; contradicting 0.
  - PF = 0. Supporting 10390; contradicting 0.
  - AF = 1. Supporting 10390; contradicting 0.
  - ZF = 0. Supporting 10390; contradicting 0.
  - SF = 0. Supporting 10390; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 10390; contradicting 0.

### IDIV
87,128 measured rows; 4 width/form/immediate configurations.

- 8-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 13698; contradicting 0.
- 8-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 8078.
- 16-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 13520; contradicting 0.
- 16-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 8256.
- 32-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 13858; contradicting 0.
- 32-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 7918.
- 64-bit reg: trap context: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 13592; contradicting 0.
- 64-bit reg: successful division: REJECTED candidate: arithmetic flags preserved: (after & 0x8d5) = (before & 0x8d5). Supporting 0; contradicting 8208.
- 8-bit reg, trap context (13698 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 13698; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 13698; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 13698; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 13698; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 13698; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 13698; contradicting 0.
- 8-bit reg, successful division (8078 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 8078; contradicting 0.
  - PF = 0. Supporting 8078; contradicting 0.
  - AF = 1. Supporting 8078; contradicting 0.
  - ZF = 0. Supporting 8078; contradicting 0.
  - SF = 0. Supporting 8078; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 8078; contradicting 0.
- 16-bit reg, trap context (13520 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 13520; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 13520; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 13520; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 13520; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 13520; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 13520; contradicting 0.
- 16-bit reg, successful division (8256 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 8256; contradicting 0.
  - PF = 0. Supporting 8256; contradicting 0.
  - AF = 1. Supporting 8256; contradicting 0.
  - ZF = 0. Supporting 8256; contradicting 0.
  - SF = 0. Supporting 8256; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 8256; contradicting 0.
- 32-bit reg, trap context (13858 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 13858; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 13858; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 13858; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 13858; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 13858; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 13858; contradicting 0.
- 32-bit reg, successful division (7918 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 7918; contradicting 0.
  - PF = 0. Supporting 7918; contradicting 0.
  - AF = 1. Supporting 7918; contradicting 0.
  - ZF = 0. Supporting 7918; contradicting 0.
  - SF = 0. Supporting 7918; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 7918; contradicting 0.
- 64-bit reg, trap context (13592 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 13592; contradicting 0.
  - PF = preserved (same bit in FLAGS_before). Supporting 13592; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 13592; contradicting 0.
  - ZF = preserved (same bit in FLAGS_before). Supporting 13592; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 13592; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 13592; contradicting 0.
- 64-bit reg, successful division (8208 rows):
  - CF = preserved (same bit in FLAGS_before). Supporting 8208; contradicting 0.
  - PF = 0. Supporting 8208; contradicting 0.
  - AF = 1. Supporting 8208; contradicting 0.
  - ZF = 0. Supporting 8208; contradicting 0.
  - SF = 0. Supporting 8208; contradicting 0.
  - OF = preserved (same bit in FLAGS_before); also matches CF_after. Supporting 8208; contradicting 0.

### BSF
2,904 measured rows; 3 width/form/immediate configurations.

- 16-bit reg: zero source leaves destination unchanged: R1 = A. Supporting 88; contradicting 0.
- 32-bit reg: zero source leaves destination unchanged: R1 = A. Supporting 88; contradicting 0.
- 64-bit reg: zero source leaves destination unchanged: R1 = A. Supporting 44; contradicting 0.
- 16-bit reg, source = 0 (88 rows):
  - CF = 0. Supporting 88; contradicting 0.
  - PF = 1. Supporting 88; contradicting 0.
  - AF = 0. Supporting 88; contradicting 0.
  - SF = 0. Supporting 88; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(A) XOR MSB(R1). Supporting 88; contradicting 0.
- 16-bit reg, source != 0 (880 rows):
  - CF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 880; contradicting 0.
  - AF = 0. Supporting 880; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 880; contradicting 0.
- 32-bit reg, source = 0 (88 rows):
  - CF = 0. Supporting 88; contradicting 0.
  - PF = 1. Supporting 88; contradicting 0.
  - AF = 0. Supporting 88; contradicting 0.
  - SF = 0. Supporting 88; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(A) XOR MSB(R1). Supporting 88; contradicting 0.
- 32-bit reg, source != 0 (880 rows):
  - CF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 880; contradicting 0.
  - AF = 0. Supporting 880; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 880; contradicting 0.
- 64-bit reg, source = 0 (44 rows):
  - CF = 0. Supporting 44; contradicting 0.
  - PF = 1. Supporting 44; contradicting 0.
  - AF = 0. Supporting 44; contradicting 0.
  - SF = 0. Supporting 44; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(A) XOR MSB(R1). Supporting 44; contradicting 0.
- 64-bit reg, source != 0 (924 rows):
  - CF = 0; also matches MSB(R1). Supporting 924; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 924; contradicting 0.
  - AF = 0. Supporting 924; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 924; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 924; contradicting 0.

### BSR
2,904 measured rows; 3 width/form/immediate configurations.

- 16-bit reg: zero source leaves destination unchanged: R1 = A. Supporting 88; contradicting 0.
- 32-bit reg: zero source leaves destination unchanged: R1 = A. Supporting 88; contradicting 0.
- 64-bit reg: zero source leaves destination unchanged: R1 = A. Supporting 44; contradicting 0.
- 16-bit reg, source = 0 (88 rows):
  - CF = 0. Supporting 88; contradicting 0.
  - PF = 1. Supporting 88; contradicting 0.
  - AF = 0. Supporting 88; contradicting 0.
  - SF = 0. Supporting 88; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(A) XOR MSB(R1). Supporting 88; contradicting 0.
- 16-bit reg, source != 0 (880 rows):
  - CF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 880; contradicting 0.
  - AF = 0. Supporting 880; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 880; contradicting 0.
- 32-bit reg, source = 0 (88 rows):
  - CF = 0. Supporting 88; contradicting 0.
  - PF = 1. Supporting 88; contradicting 0.
  - AF = 0. Supporting 88; contradicting 0.
  - SF = 0. Supporting 88; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(A) XOR MSB(R1). Supporting 88; contradicting 0.
- 32-bit reg, source != 0 (880 rows):
  - CF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 880; contradicting 0.
  - AF = 0. Supporting 880; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 880; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 880; contradicting 0.
- 64-bit reg, source = 0 (44 rows):
  - CF = 0. Supporting 44; contradicting 0.
  - PF = 1. Supporting 44; contradicting 0.
  - AF = 0. Supporting 44; contradicting 0.
  - SF = 0. Supporting 44; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(A) XOR MSB(R1). Supporting 44; contradicting 0.
- 64-bit reg, source != 0 (924 rows):
  - CF = 0; also matches MSB(R1). Supporting 924; contradicting 0.
  - PF = even parity of R1 low byte. Supporting 924; contradicting 0.
  - AF = 0. Supporting 924; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 924; contradicting 0.
  - OF = 0; also matches CF_after; also matches MSB(R1) XOR CF_after; also matches top two bits of R1 XOR. Supporting 924; contradicting 0.

### TZCNT
2,904 measured rows; 3 width/form/immediate configurations.

- 16-bit reg, all executions (968 rows):
  - PF = 0. Supporting 968; contradicting 0.
  - AF = 0. Supporting 968; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 968; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - PF = 0. Supporting 968; contradicting 0.
  - AF = 0. Supporting 968; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 968; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - PF = 0. Supporting 968; contradicting 0.
  - AF = 0. Supporting 968; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 968; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.

### LZCNT
2,904 measured rows; 3 width/form/immediate configurations.

- 16-bit reg, all executions (968 rows):
  - PF = 0. Supporting 968; contradicting 0.
  - AF = 0. Supporting 968; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 968; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - PF = 0. Supporting 968; contradicting 0.
  - AF = 0. Supporting 968; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 968; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - PF = 0. Supporting 968; contradicting 0.
  - AF = 0. Supporting 968; contradicting 0.
  - SF = 0; also matches MSB(R1). Supporting 968; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 968; contradicting 0.

### POPCNT
2,904 measured rows; 3 width/form/immediate configurations.

- 16-bit reg: ZF = (B == 0); CF=PF=AF=SF=OF=0. Supporting 968; contradicting 0.
- 32-bit reg: ZF = (B == 0); CF=PF=AF=SF=OF=0. Supporting 968; contradicting 0.
- 64-bit reg: ZF = (B == 0); CF=PF=AF=SF=OF=0. Supporting 968; contradicting 0.

### BT
8,712 measured rows; 48 width/form/immediate configurations.

- 16-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 16-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 16-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 16-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 32-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 32-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 64-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 64-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.

### BTS
8,712 measured rows; 48 width/form/immediate configurations.

- 16-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 16-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 16-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 16-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 32-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 32-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 64-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 64-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.

### BTR
8,712 measured rows; 48 width/form/immediate configurations.

- 16-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 16-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 16-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 16-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 32-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 32-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 64-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 64-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.

### BTC
8,712 measured rows; 48 width/form/immediate configurations.

- 16-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 16-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 16-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 16-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 32-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 32-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 32-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit reg-reg, all executions (1628 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 1628; contradicting 0.
- 64-bit mem-reg, all executions (660 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 660; contradicting 0.
- 64-bit reg-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
- 64-bit mem-imm, all executions (308 rows):
  - PF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - AF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - SF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.
  - OF = preserved (same bit in FLAGS_before). Supporting 308; contradicting 0.

### AND
3,872 measured rows; 4 width/form/immediate configurations.

- 8-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 16-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.

### OR
3,872 measured rows; 4 width/form/immediate configurations.

- 8-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 16-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.

### XOR
3,872 measured rows; 4 width/form/immediate configurations.

- 8-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 16-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.

### TEST
3,872 measured rows; 4 width/form/immediate configurations.

- 8-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 16-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 32-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.
- 64-bit reg, all executions (968 rows):
  - AF = 0. Supporting 968; contradicting 0.

### CMPXCHG
85,184 measured rows; 4 width/form/immediate configurations.

- 8-bit reg: CF/PF/AF/ZF/SF/OF equal subtraction flags of C - A (accumulator - old destination). Supporting 21296; contradicting 0.
- 16-bit reg: CF/PF/AF/ZF/SF/OF equal subtraction flags of C - A (accumulator - old destination). Supporting 21296; contradicting 0.
- 32-bit reg: CF/PF/AF/ZF/SF/OF equal subtraction flags of C - A (accumulator - old destination). Supporting 21296; contradicting 0.
- 64-bit reg: CF/PF/AF/ZF/SF/OF equal subtraction flags of C - A (accumulator - old destination). Supporting 21296; contradicting 0.

### XADD
3,872 measured rows; 4 width/form/immediate configurations.

- 8-bit reg: CF/PF/AF/ZF/SF/OF equal addition flags of A + B. Supporting 968; contradicting 0.
- 16-bit reg: CF/PF/AF/ZF/SF/OF equal addition flags of A + B. Supporting 968; contradicting 0.
- 32-bit reg: CF/PF/AF/ZF/SF/OF equal addition flags of A + B. Supporting 968; contradicting 0.
- 64-bit reg: CF/PF/AF/ZF/SF/OF equal addition flags of A + B. Supporting 968; contradicting 0.

### BSWAP16
44 measured rows; 1 width/form/immediate configurations.

- 16-bit reg: undefined 16-bit result is zero: R1 = 0. Supporting 44; contradicting 0.
- 16-bit reg: arithmetic flags preserved. Supporting 44; contradicting 0.

### CMPXCHG8B
21,296 measured rows; 1 width/form/immediate configurations.

- 64-bit mem: ZF = (A == B); CF/PF/AF/SF/OF preserved. Supporting 21296; contradicting 0.

### CMPXCHG16B
21,296 measured rows; 1 width/form/immediate configurations.

- 128-bit mem: ZF = (A == B); CF/PF/AF/SF/OF preserved. Supporting 21296; contradicting 0.

## Class 9 and class 11

See bmi_REPORT.md for class 9 measured rules and legacy_REPORT.md for the native i386 execution blocker. No class 11 result or CPU rule is fabricated.

## Class 9 measured rules (included here)



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

