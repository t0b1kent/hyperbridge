# Measured rules on this exposed AMD EPYC 9V74

These are empirical choices for this CPU, not portable architectural guarantees. Counts are recomputed from native result files. Undefined flags are never substituted into the raw output. CF/PF/AF/ZF/SF/OF mask: 0x08d5.

## BCD undefined flags and fault behavior

- **DAA.undefined_OF:** OF equals 8-bit ADD overflow for old AL + d, where d = (low-nibble > 9 or input AF ? 6 : 0) + (old AL > 0x99 or input CF ? 0x60 : 0). Supporting rows: **2048**; contradicting rows: **0**; applicable rows: 2048.
- **DAS.undefined_OF:** OF equals 8-bit SUB overflow for old AL - d, with the same d condition as DAA. Supporting rows: **2048**; contradicting rows: **0**; applicable rows: 2048.
- **AAA.undefined_OSZP:** OF, SF, ZF and PF equal flags of 16-bit AX + d BEFORE AL is masked to four bits; d = 0x106 when adjustment is selected, otherwise zero. Supporting rows: **262144**; contradicting rows: **0**; applicable rows: 262144.
- **AAS.undefined_OSZP:** OF, SF, ZF and PF equal flags of 16-bit AX - d BEFORE AL is masked to four bits; d = 0x106 when adjustment is selected, otherwise zero. Supporting rows: **262144**; contradicting rows: **0**; applicable rows: 262144.
- **AAM.undefined_OAC:** On successful AAM, OF = AF = CF = 0. Supporting rows: **11688**; contradicting rows: **0**; applicable rows: 11688.
- **AAD.undefined_OAC:** OF, AF and CF equal flags of an 8-bit ADD of old AL and ((old AH * immediate) & 0xff). Supporting rows: **142292**; contradicting rows: **0**; applicable rows: 142292.
- **AAM.zero_trap:** AAM immediate zero traps and preserves input AX and all six arithmetic flags in the saved fault context. Supporting rows: **44**; contradicting rows: **0**; applicable rows: 44.

## Extra legacy instructions and mode-control flags

- **SALC.observed:** SALC gives AL = input CF ? 0xff : 0, preserving all six arithmetic flags. Supporting rows: **512**; contradicting rows: **0**; applicable rows: 512.
- **PUSHSEG32.upper:** 32-bit segment PUSH zeroes the upper 16 bits of its four-byte stack slot, overwriting the initial 0xa5a5 high half. Supporting rows: **264**; contradicting rows: **0**; applicable rows: 264.
- **STACK.flags:** PUSHA/PUSHAD/POPA/POPAD preserve all six arithmetic flags. Supporting rows: **176**; contradicting rows: **0**; applicable rows: 176.
- **SEGMENT.flags:** PUSH/POP of measured segment registers preserve all six arithmetic flags. Supporting rows: **968**; contradicting rows: **0**; applicable rows: 968.
- **INCDEC.CF:** All measured INC/DEC register forms preserve CF. Supporting rows: **1264**; contradicting rows: **0**; applicable rows: 1264.
- **BOUND.flags:** BOUND preserves all six arithmetic flags, including saved out-of-range fault contexts. Supporting rows: **352**; contradicting rows: **0**; applicable rows: 352.
- **INTO.flags:** INTO preserves all six arithmetic flags, including saved overflow trap contexts. Supporting rows: **44**; contradicting rows: **0**; applicable rows: 44.
- **ARPL.preserved:** ARPL preserves CF, PF, AF, SF and OF (ZF alone is the architecturally modified arithmetic flag). Supporting rows: **968**; contradicting rows: **0**; applicable rows: 968.
- **LAHF.flags:** LAHF preserves all six arithmetic flags. Supporting rows: **44**; contradicting rows: **0**; applicable rows: 44.
- **SAHF.OF:** SAHF preserves OF. Supporting rows: **512**; contradicting rows: **0**; applicable rows: 512.
- **SHL.undefined_AF:** SHL in compatibility mode: count zero preserves AF; every nonzero masked count sets AF. Supporting rows: **2904**; contradicting rows: **0**; applicable rows: 2904.
- **SHL.undefined_OF:** SHL in compatibility mode, masked count > 1: OF equals sign(final result) XOR output CF. Supporting rows: **2640**; contradicting rows: **0**; applicable rows: 2640.

## Formula conventions

For an n-bit addition r = (a + b) mod 2^n: OF = ((~(a XOR b) AND (a XOR r)) >> (n-1)) AND 1; AF = ((a XOR b XOR r) >> 4) AND 1; CF = (a + b) >= 2^n. For subtraction, OF = (((a XOR b) AND (a XOR r)) >> (n-1)) AND 1. SF is bit n-1, ZF means the entire n-bit intermediate is zero, PF is even parity of its low byte. These are formulas used for counting observations, not a claim that the CPU internally executes those exact micro-operations.

AAA/AAS adjustment is selected by (old AL & 15) > 9 OR input AF. Thus their measured undefined ZF/SF refer to the full 16-bit intermediate, not the final four-bit AL. AAM rules exclude immediate-zero fault rows. AAD includes immediate zero.

PUSH/POP segment measurements use valid existing user selectors only: ES/SS/DS=0x2b, CS=0x23, FS/GS=0. POP CS has no valid legacy encoding and is intentionally absent. Segment loads are normal per-process instructions; FS/GS bases are restored before returning to libc.

See bcd-CHECKS.txt, extra-CHECKS.txt and control-CHECKS.txt for separately executed C checks of defined result/flag semantics. The SALC equation is observational, because SALC is undocumented.
