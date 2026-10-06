# Native Windows x64, Prism and our exception contexts

## Measured

October 6, 2026, original [exception probes](../../stands/exceptions/README.md). One workflow capture per machine: Intel Xeon 6973P-C / Windows Server 2022 20348.5622 and AMD EPYC 9V74 / Server 2025 26100.33438. Per machine, v1 had 61 launches, v3 132, v4 six. [Text outputs and machine descriptions](../../reference/windows-x64/2026-10-06/README.md) are public.

On both processors, `int 2d` raised 0x80000003 with one parameter, ExceptionAddress = instruction + 3 and Rip = instruction + 2; the next byte executed on continuation. Our measured delivery matched these offsets. Prism on Windows 11 Arm 26200.9457 used ExceptionAddress + 2. Handler ContextFlags were 0x0010005f on native Windows, 0x0010005b on Prism and 0x0010000b in our 1.0.8 context probe. The latter comparison used 54 cells (27 fault kinds × VEH/SEH); it is not a completed comparison of every v3 cell.

## Conclusion

For int 2d offsets, our delivery matched native Windows. A disagreement with Prism alone did not prove our behavior wrong. The missing context groups are a separate measured difference.

## Limits

Two exposed x86 cloud processors and specified Windows builds. Handler flags do not prove every advertised register group is valid; each field needs checking. No inference about protected application code is made.

## What would refute it

An independent same-form native Windows capture with different offsets, or a complete field comparison showing our context groups already match the hardware reference.

## Where it is fixed in our series

Int 2d offset delivery needs no change based on this reference. ContextFlags and context-group coverage had no accepted released fix at this snapshot. See the separate [x87 continuation defect](x87-exception-resume.md).
