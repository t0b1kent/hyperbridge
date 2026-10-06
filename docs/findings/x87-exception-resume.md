# Continuing an exception can erase guest x87 state

## Measured

October 6, 2026, original 64-bit exception-context probe: 54 cells (27 kinds × VEH/SEH), Windows 11 Arm 26200.9457 / Prism and MacRunner 1.0.8 r5. After continuing tested hardware exceptions, r5 changed FCW 0x027f → 0, FSW 0x3000 → 0, FTW 0xc0 → 0 and the seeded ST0 to zero. Prism retained the seeded state. A candidate module with X87_KEEP enabled passed ten selected continuation cells; r5 passed zero of those ten. One retained comparison and one ten-cell candidate check are reported.

## Conclusion

The ARM64EC context conversion path can replace x87 state with zeros from a representation that does not carry it. The audited path is Wine `context_arm_to_x64` followed by FEX `LoadStateFromECContext`. A continuing handler must preserve or explicitly restore valid guest x87 state.

## Limits

The candidate is not general validation of SetThreadContext or all explicit handler edits. The snapshot does not prove any particular application failure was caused by this defect. Native Windows context data provide a further reference, not permission to infer untested cells.

## What would refute it

A same seeded-state r5 continuation retaining all x87 fields, or a candidate failing preservation or discarding a valid explicit x87 edit.

## Where it is fixed in our series

Candidate `MACRUNNER_FEX_X87_KEEP` was tested outside released 1.0.8. The retained receipt identifies the candidate module but does not assign an accepted numbered patch; no patch number is invented here. It is not part of the released common series.
