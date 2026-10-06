# Intel | AMD flags, cell by cell

Run `vendor-flags.yml` manually after curator review. It uses `windows-2022` and
`windows-2025` with the same SHA-pinned llvm-mingw dependency as the published
Windows exception stand. CPU vendor/model/family/stepping are measured by CPUID;
the runner label is never treated as evidence of a manufacturer.

The four files under `probes/` are the unchanged authored native integer probes
used for the accepted hardware reference (MIT; source hashes are in each receipt).
The Windows adapter changes only the calling convention, ELF directives and fault
capture. Each assembly wrapper saves Windows nonvolatile RDI/RSI, moves the Ctx
argument from RCX to RDI and uses the same instruction sequence. The VEH saves the
actual fault-time RAX/RDX/RBX/RCX/EFLAGS, then resumes at a dedicated wrapper return
epilogue; it does not invent a result or unwind through assembly. Each artifact
contains the exact generated adapter diff. BMI capture needs no adapter.

Each host executes every class twice. Native defined-output validators must pass,
all required CPUID features must be present, all 1,624,804 rows must be collected,
and the two uncompressed byte streams must have identical SHA256. Binaries stay on
the hosted runner; artifacts retain compressed raw output, logs and source hashes.

If both successful first captures have the same CPUID vendor, the workflow repeats
the two-host allocation once. The maximum is four hosted machines. Continued lack
of either manufacturer is `NOT_COVERED`/FAIL, never inferred from the OS label.
A failed build or probe is retained as failure and does not masquerade as vendor
coverage. This bound prevents indefinite hosted allocation.

`vendor-flags-RESULT` contains `RESULT.json` and `intel-amd-cells.jsonl.gz`.
Each cell includes its instruction/input, Intel and AMD trap/result/flags, exact
equality, result equality, trap equality, and the agreement mask over CF/PF/AF/ZF/SF/OF.
`by_form` counts equal/different cells and agreeing bits for ENGINE-108 selection.
The inputs must align exactly; both machines must use identical probe sources.
Observed agreement on two CPU models is not a universal ISA rule or game evidence.

To run on an owned native Windows x64 host, use
`python stands/vendor-flags/capture.py --compiler COMPILER --work FRESH_WORK --out FRESH_REPORT`.
The script also accepts native Linux x86-64 with GCC and retains the original POSIX
capture there. That path passed on AMD Ryzen 9 9900X/GCC 13.3: all 1,624,804 cells,
ten identical raw A/A pairs, no missing CPUID forms or defined-output failures.
This is not a Windows or FEX result. Windows adapter correctness, a measured Intel
pair and cloud qualification still require the first hosted run.
