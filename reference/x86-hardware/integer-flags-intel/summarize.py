#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture-specific Darwin coverage; never reuse historical AMD observations."""
import json
import pathlib

P = pathlib.Path(__file__).resolve().parent
summary = json.loads((P / 'validation-summary.json').read_text())
legacy = (P / 'build/legacy.current.txt').read_text()
if 'NOT_ATTEMPTED_MACOS_NO_ELF32_ABI' not in legacy:
    raise ValueError('Missing explicit Darwin legacy-gap evidence')
(P / 'legacy_CHECKS.txt').write_text(legacy + 'probe_script_exit=77\n')
(P / 'legacy_REPORT.md').write_text('# Legacy compatibility gap on macOS\n\n'
    'Status: NOT_ATTEMPTED_MACOS_NO_ELF32_ABI. This is a declared platform gap, not a failed native execution.\n\n'
    'The Linux ELF/i386 syscall probe is preserved in original-0002 but not built or executed on macOS. '
    'Original class 11 DAA/DAS/AAA/AAS/AAM/AAD had no full generator and zero measurement rows; this remains unchanged.\n')
lines = ['# Coverage for this macOS Intel capture', '',
         'The original generators, instruction/input matrix, output row format and raw SHA-256 convention are retained.',
         'Darwin signal-context access, Mach-O symbol/directive spelling, runners and Python reporting have explicit adapters.',
         'See PLATFORM-ADAPTER.patch and ASSEMBLY-ADAPTER.json. No unsupported instruction is emulated.', '',
         f'Total measured rows: {summary["total_rows"]}. Full original 64-bit set expected: 1,624,804.',
         f'Complete original 64-bit coverage: {summary["complete_0002_64bit_coverage"]}.', '',
         '| Class | Rows | Traps | CPUID omissions |', '|---|---:|---:|---|']
for cls, record in summary.items():
    if isinstance(record, dict):
        lines.append(f'| {cls} | {record["rows"]} | {record.get("traps", 0)} | {", ".join(record["skipped"]) or "none"} |')
lines += ['', 'Each omission above comes from unchanged native CPUID logic and retains its original raw SKIP comment.',
          'Any omission makes the overall package INCOMPLETE_CPUID_FEATURES, even if all available rows validate.',
          'Feature absence is never interpreted as a zero measurement or a match with AMD.', '',
          'DIV/IDIV fault rows retain the original low16 RFLAGS and register capture, now read from Darwin SIGFPE ucontext.',
          'Fault observations are OS-mediated: any Linux/macOS trap-context differences must be separated from CPU differences in the final AMD–Intel report.',
          'Fault capture and all defined-result/non-arithmetic flag checks remain active; failures are not patched out or rewritten.', '',
          'Original detailed input/form coverage is in original-0002/COVERAGE.md; AMD measurements there are historical.',
          'Current form counts/hashes are in validation-summary.json; defined C checks are in out-*.validation.txt and bmi_CHECKS.txt.', '',
          'Legacy ELF/i386 compatibility probe: NOT_ATTEMPTED_MACOS_NO_ELF32_ABI. Class 11 remains unimplemented and has zero rows.',
          'No sanitizer run is claimed. No AMD–Intel diff is claimed until these artifacts are reviewed against AMD data.']
(P / 'COVERAGE.md').write_text('\n'.join(lines) + '\n')
print('Darwin capture-specific COVERAGE.md and explicit legacy-gap reports generated')
