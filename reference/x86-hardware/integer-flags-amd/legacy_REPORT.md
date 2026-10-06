# Class 11: native 32-bit execution unavailable

## Verified blocker

`legacy32.S` is original MIT assembly containing only a libc-free `_start` and the i386 `exit(0)` system call. The requested compilation route works:

```
gcc -m32 -nostdlib -static -no-pie legacy32.S -o build/legacy32
```

`file` and `readelf -h` verify an ELF32, little-endian, statically linked Intel 80386 executable, with entry point `0x8049000`; it needs neither 32-bit libc nor a dynamic loader. But the environment rejects executing this file before `_start`:

```
Native i386 execution unavailable: errno=8 (Exec format error)
```

`./legacy_probe.sh` reproduces the compilation, ELF inspection and execution attempt, returning 77 when the operating environment cannot execute the probe. Full evidence is preserved in `legacy_CHECKS.txt`. This is an observed environment limit; we do not infer a particular kernel configuration from it. No packages, emulator, compatibility loader, or other workaround was installed or used.

## Coverage

| Instruction | Intended sweep | Executed forms | Captured rows | Why not covered |
|---|---|---:|---:|---|
| DAA | All 256 AL values × four AF/CF combinations | 0 | 0 | Native i386 ELF execution rejected |
| DAS | All 256 AL values × four AF/CF combinations | 0 | 0 | Native i386 ELF execution rejected |
| AAA | All 65,536 AX values × both AF states | 0 | 0 | Native i386 ELF execution rejected |
| AAS | All 65,536 AX values × both AF states | 0 | 0 | Native i386 ELF execution rejected |
| AAM | All 256 immediates for pattern inputs; exhaustive constant 10; AAM 0 trap context | 0 | 0 | Native i386 ELF execution rejected |
| AAD | Default constant 10 with pattern/exhaustive inputs | 0 | 0 | Native i386 ELF execution rejected |

Manual-undefined flags: DAA/DAS OF; AAA/AAS OF, SF, ZF, PF; AAM/AAD OF, AF, CF. No hardware rules can be claimed: supporting rows=0 and contradicting rows=0 for every legacy instruction. Defined-result checks and duplicate-run determinism do not apply because there are no instruction rows. The task explicitly permits this limitation when the 32-bit program cannot be built or run; none of the absent results were synthesized. There is deliberately no purported legacy hardware data archive.
