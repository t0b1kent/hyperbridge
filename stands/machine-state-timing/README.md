# machine-state-timing

The timing mode of the `machine-state` probe with one correction: the probe's own software exception is accepted by its
vectored handler when Windows sets `EXCEPTION_SOFTWARE_ORIGINATE` in `ExceptionFlags` (the earlier build stopped with
its own code `0xE0860001` on current Windows builds). Nothing else differs from `stands/machine-state/src/windows_probe.c`.

`run-windows-timing.ps1` builds the single source file with a given llvm-mingw toolchain and runs the timing mode twice;
each run writes a JSON file plus stdout, stderr and the exit code. The numbers describe the hosted runner they were
taken on and are a reference for the shape of the results, not a performance claim.
