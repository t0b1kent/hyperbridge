# Noncanonical branches: processor behavior differs from Prism

## Measured

October 3, 2026. Original Linux probe on AMD EPYC 9V74: 50 normalized cells repeated twice, byte-identical; ten noncanonical target cells raised #GP at the branch instruction before completion. Forty canonical unmapped targets raised #PF at the target; CALL had pushed its return address. [Native sources and tables](../../reference/x86-hardware/null-noncanonical-branches/README.md) are included.

Prism on Windows 11 Arm 26200.9457 in a Parallels VM: 12 recorded noncanonical cells, each with one access violation, execute parameter 8, target in the fault-address field, ExceptionAddress/RIP at the target, and CALL's return already pushed. Our unguarded dispatcher produced thousands of records rather than one exception. Candidate control passed 20/20 cells with one target-side exception and left 45 ordinary pairs unchanged.

## Conclusion

Prism's target-side access violation is not native x86's instruction-side #GP. A translator must name the reference it follows; a fault storm matches neither.

## Limits

The Linux processor/kernel result does not itself determine Windows exception parameters. This note describes the October 3 branch matrix. The later native Windows data-address test is a different test and must not silently replace the branch result.

## What would refute it

A repeat with the same native branch form completing the branch to a noncanonical target, or a Prism cell faulting at the branch instruction, would refute that recorded distinction.

## Where it is fixed in our series

Candidate **0051**, `MACRUNNER_FEX_NONCANONICAL_GUARD`, prevents the dispatcher storm and follows the measured Prism variant. It is outside the released 1.0.8 common series; a hardware-faithful variant remains distinct.
