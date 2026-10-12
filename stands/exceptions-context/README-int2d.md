# INT 2D observer matrix, including a pointer-shaped RAX

Source-only revision of the INT 2D matrix. No prebuilt executable or recorded
runtime data is included.

Eight RAX inputs: 0, 1, 2, 3, 4, 5, 0x10, and 0x6249071e4f40.
The last value is used solely as a register bit pattern; the probe does not
dereference it. Three observers (VEH, SEH, UEF), 20 repeats: 480 cases.

Run the included PowerShell script on native Windows x86-64 with a local
Visual Studio/Clang installation. It builds int2d-matrix.c and int2d-matrix.S
and runs the executable with argument int2d-matrix. The script performs no
downloads and preserves stdout, stderr, exit code, source and executable SHA.

The raw records contain the observed EXCEPTION_RECORD/CONTEXT, full RAX,
whether the byte at I+2 was executed, and flags before and after resumption.
The I+2 byte is PUSH RAX; the stack depth is restored by both continuation
paths. RIP is measured separately from ExceptionAddress.

The seven original values have a native Windows reference. Behavior of the
pointer-shaped eighth value must be measured; ORACLE_REQUIRED_POINTER marks
its assertions as a hypothesis. The result and raw fields, including a
nonzero exit code, must be preserved rather than treated as oracle facts.

This fixture also retains its original smoke and pattern20 modes, but the
included script selects only int2d-matrix. It does not modify system exception
handlers or other processes. Each observer and process error mode is restored
before termination.
