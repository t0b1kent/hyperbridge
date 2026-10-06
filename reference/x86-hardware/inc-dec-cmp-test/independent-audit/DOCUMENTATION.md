# Architectural documentation used by the independent audit

Checked 2026-10-05. These are publisher-authored primary sources, not an emulator's implementation.

## Intel

[Intel SDM Volume 2, order 325383-085US, October 2024](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf) was downloaded directly from Intel and parsed locally.

- ADD, pp. 3-32–33; SUB, pp. 4-681–682: arithmetic result updates CF, PF, AF, ZF, SF, OF
- INC, pp. 3-514–515; DEC, pp. 3-328–329: CF survives; the other five status flags reflect the increment/decrement result
- CMP, pp. 3-179–180: comparison is subtraction without writing the result; a shorter immediate is sign-extended to operand width; all six status flags are defined
- TEST, pp. 4-713–714: AND temporary is discarded; CF and OF become zero; SF/ZF/PF reflect the temporary; AF is undefined
- Memory-immediate encodings: CMP 80 /7 ib, 83 /7 ib, 81 /7 iw; TEST F6 /0 ib; 66 prefix selects word operands in 64-bit mode
- AH/CH require legacy high-byte encoding without REX; FE /0 and FE /1 are the relevant INC/DEC forms

The [current Intel index](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) advertises revision 093. The audit cites the directly retrieved revision above, not an uninspected newer revision.

## AMD

[AMD APM Volume 3, publication 24594 revision 3.37, July 2025](https://docs.amd.com/api/khub/documents/j44LvPXzuuXgM0WyHKQfeQ/content), CMP p. 162, was available through the public search index. Its CMP description and opcode table corroborate subtraction flag semantics, unchanged destination, and signed imm8 extension for word/dword forms. Direct fetching returned 404; a current-download claim would be incorrect.

[AMD APM Volume 1, publication 24592 revision 3.24, August 2025](https://docs.amd.com/api/khub/documents/sfvvekC9mDflu6vd3R0NXA/content), section 3.3.9 p. 59, independently specifies that CMP updates all six arithmetic flags without storing its subtraction result, and that TEST changes flags while preserving operands.

[AMD APM combined volumes, general-purpose programming p. 54](https://docs.amd.com/api/khub/documents/68GKiN0gMEd6bMddsmhPwg/content), available through the public index, states that INC/DEC correspond to ADD/SUB with immediate one except that CF is preserved.

No AMD hardware result is a proof of behavior on every Intel implementation. Undefined TEST AF is recorded as an observation and excluded from defined-flag conformance checks.
