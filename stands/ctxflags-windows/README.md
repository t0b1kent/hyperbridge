# Exception CONTEXT beyond x87: flags, segments, debug registers, XSTATE

`ctxflags.c` loads known values into all YMM registers, raises an access violation and records in a vectored exception
handler what the CONTEXT carries besides the x87/MXCSR part: ContextFlags, segment selectors, EFlags, Dr0-Dr7 (read only,
never written), and the XSTATE group (feature mask, CONTEXT_EX chunks, XSAVE header, AVX upper halves). One mode edits the
upper half of ymm0 in the handler and checks that the edit takes effect after the thread continues. It also reports the OS
view of AVX (CPUID, XCR0, GetEnabledXStateFeatures, InitializeContext lengths) and reads the context of another thread with
XSTATE requested. Every line is `<name> <hex>`. The workflow builds the probe with a pinned llvm-mingw as 64-bit and 32-bit
and runs it on GitHub's Windows runners; the output is the reference for a translator's exception context handling.
