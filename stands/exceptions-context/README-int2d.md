# Native AMD64 INT 2D service matrix

This source-only extension is independent of the 320-case context package.
Run `pwsh -NoProfile -File .\run-int2d-windows.ps1` on native AMD64 Windows
2022 and 2025 with installed Visual Studio and Clang. Build/results stay in a
fresh temporary directory. No downloads, network, input or other applications.

The matrix uses RAX 0, 1, 2, 3, 4, 5 and 0x10, 20 repetitions per value in one
process after patterned/deep stack history. Its three observers are VEH, an
SEH filter and the process unhandled-exception filter (UEF): 420 cases. UEF is
an added observer; it is not an attached debugger. Preserve observer identity
when comparing this matrix to a separate debugger-based reference.

The delivered CONTEXT is not edited for these cases. The guest byte sequence
is INT 2D followed by one-byte PUSH RAX (CD 2D 50). The common tail stores the
full 64-bit RAX and RSP, then restores the fixture's original RSP before return.
PUSH changes neither RAX nor flags. `INT2D_MATRIX` prints input RAX, full RAX
after the command, handler count, reached marker and before/after RSP.
RSP-8 proves execution of the byte at I+2; unchanged RSP proves it was skipped
and execution reached I+3. Any other RSP is FAILED_UNEXPECTED_RSP and fails
the functional check. This data-effect observation also covers no-handler
cases. It infers the continuation boundary; it is not a debugger PC snapshot.
FaultInstruction identifies the INT 2D bytes. ExceptionAddress, delivered Rip
and final ResumeRip are printed separately. Preserve the synthetic PUSH tail
when comparing references; the older NOP matrix has no continuation evidence.

Functional failures check return, the reached marker, duplicate handler calls
and the previously measured RAX=1 no-handler requirement. Other values have no
embedded Windows expectations yet. A zero exit is not a field-equality verdict.
Keep raw stdout/stderr, identity, hashes and result.json even on nonzero exit.
The process timeout is 150 seconds; the runner terminates only its owned PID.
