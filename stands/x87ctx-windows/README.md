# x87 state in the Windows CONTEXT

`x87ctx.c` loads five values onto the x87 stack (TOP = 3) and then reads the Windows CONTEXT in three ways: inside a vectored
exception handler (fault in the same translated region and after an indirect jump), and through GetThreadContext on a suspended
worker that either waits in WaitForSingleObject or spins in guest code. Some modes edit ST(0) and the control word and check that
the edit takes effect after the thread continues. Every line is `<name> <hex>`. The workflow builds the probe with a pinned
llvm-mingw as 64-bit and 32-bit and runs it on GitHub's Windows runners; the output is the reference for a translator's x87
context handling (HyperBridge `MACRUNNER_FEX_X87_CONTEXT`).
