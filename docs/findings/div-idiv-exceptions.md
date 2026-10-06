# DIV/IDIV need a quotient-overflow exception

## Measured

September 28–29, 2026, original division oracle plus Windows/Prism controls. The overflow oracle covered 26/26 selected cases; the later Windows-facing matrix covered 88/88 cells across operand widths and x64/WOW64. The tested Windows mapping was 0xC0000095 for quotient overflow, distinct from 0xC0000094 for division by zero. The retained summary reports matrix coverage, not independent repeated runs. Native integer divide input/output rows are also included in the [AMD corpus](../../reference/x86-hardware/integer-flags-amd/README.md).

## Conclusion

Checking only a zero divisor misses x86 #DE for an out-of-range quotient. The overflow check must preserve single-read memory semantics and distinguish the Windows-facing cause.

## Limits

Oracle cells and Windows exception mapping are separate layers. Hardware #DE does not by itself identify which Windows status to return. Fast paths are valid only when the high half is proven zero/sign-extension as appropriate.

## What would refute it

A legal in-range divide incorrectly faulting, an overflow completing, a repeated volatile/MMIO divisor read, or incorrect preserved fault-state fields.

## Where it is fixed in our series

Released **0014** adds quotient-overflow #DE with the divisor read once; **0017** supplies the proven-high-half fast path; **0018** maps quotient overflow to STATUS_INTEGER_OVERFLOW. These numbered patches are in fex/patches. The hardware corpus tests observed semantics independently of the translator.
