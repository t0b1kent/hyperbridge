# Coverage for this macOS Intel capture

The original generators, instruction/input matrix, output row format and raw SHA-256 convention are retained.
Darwin signal-context access, Mach-O symbol/directive spelling, runners and Python reporting have explicit adapters.
See PLATFORM-ADAPTER.patch and ASSEMBLY-ADAPTER.json. No unsupported instruction is emulated.

Total measured rows: 1624804. Full original 64-bit set expected: 1,624,804.
Complete original 64-bit coverage: True.

| Class | Rows | Traps | CPUID omissions |
|---|---:|---:|---|
| shifts | 87296 | 0 | none |
| rotates | 87296 | 0 | none |
| double | 743424 | 0 | none |
| multiply | 49368 | 0 | none |
| divide | 174256 | 100856 | none |
| bitscan | 14520 | 0 | none |
| bittest | 34848 | 0 | none |
| logic | 15488 | 0 | none |
| misc | 131692 | 0 | none |
| 09-bmi | 286616 | 0 | none |

Each omission above comes from unchanged native CPUID logic and retains its original raw SKIP comment.
Any omission makes the overall package INCOMPLETE_CPUID_FEATURES, even if all available rows validate.
Feature absence is never interpreted as a zero measurement or a match with AMD.

DIV/IDIV fault rows retain the original low16 RFLAGS and register capture, now read from Darwin SIGFPE ucontext.
Fault observations are OS-mediated: any Linux/macOS trap-context differences must be separated from CPU differences in the final AMD–Intel report.
Fault capture and all defined-result/non-arithmetic flag checks remain active; failures are not patched out or rewritten.

Original detailed input/form coverage is in original-0002/COVERAGE.md; AMD measurements there are historical.
Current form counts/hashes are in validation-summary.json; defined C checks are in out-*.validation.txt and bmi_CHECKS.txt.

Legacy ELF/i386 compatibility probe: NOT_ATTEMPTED_MACOS_NO_ELF32_ABI. Class 11 remains unimplemented and has zero rows.
No sanitizer run is claimed. No AMD–Intel diff is claimed until these artifacts are reviewed against AMD data.
