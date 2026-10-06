# Coverage and architecture-defined checks

Native CPL3 compatibility mode is available through the existing selector 0x23. `PROBE.txt` records `LAR_valid=1`, present=1, DPL=3, long=0, default32=1, limit=ffffffff. `ROUNDTRIP.txt` verifies real execution and full-width host state restoration. There is **no unavailable instruction family** in this task on the measured route; modify_ldt was unnecessary.

## Required BCD matrix

| Instruction | Forms/configurations | Exact inputs and flag multiplicity | Rows | Manual-undefined arithmetic flags |
|---|---:|---|---:|---|
| DAA | 1 | 256 AL × four AF/CF × two remaining-flag states | 2,048 | OF |
| DAS | 1 | 256 AL × four AF/CF × two remaining-flag states | 2,048 | OF |
| AAA | 1 | 65,536 AX × two AF × two remaining-flag states | 262,144 | OF,SF,ZF,PF |
| AAS | 1 | 65,536 AX × two AF × two remaining-flag states | 262,144 | OF,SF,ZF,PF |
| AAM | 256 immediate configurations | imm10: 256 AL × two flag states; each other immediate: 22 AL sample positions × two flag states | 11,732 | OF,AF,CF on success; imm0 captures #DE |
| AAD | 256 immediate configurations | imm10: 65,536 AX × two flag states; each other immediate, including zero: 22 AX sample positions × two flag states | 142,292 | OF,AF,CF |
| Total | 516 | Exact input/flag multiset independently checked | **682,408** | |

AAM immediate zero gives 44 actual #DE contexts, signal 8 (SIGFPE), vector 0. Other AAM immediates 1..255 succeed. AAD immediate zero is a normal instruction and is measured.

## Additional compatibility instructions

| Instruction | Forms | Rows | Inputs and checked output |
|---|---:|---:|---|
| PUSHA, PUSHAD, POPA, POPAD | 4 | 176 | 22 AX/EAX positions × two flag states each; all eight register/frame slots and original/skipped SP/ESP checked |
| BOUND | 16/32-bit | 352 | Four signed bound pairs × 22 index positions × two flag states × two widths; 208 actual #BR contexts (SIGSEGV, vector 5) |
| INTO | 1 | 44 | 22 accumulator inputs × OF-clear/all-clear and OF-set/all-set; 22 actual #OF contexts (SIGSEGV, vector 4) |
| SALC (D6) | 1 | 512 | All 256 AL × two CF/flag states; documented status is undefined/undocumented, so checks are empirical |
| One-byte INC/DEC 40–4F | 32 | 1,264 | Eight registers × two operations × 16/32-bit; seven registers have 22 patterns × flags, SP/ESP use four bounded stack values × flags |
| PUSH ES/CS/SS/DS/FS/GS | 12 | 528 | 16/32-bit slots; 22 labeled accumulator inputs × two flag states; initial stack bytes a5; actual full slot and SP/ESP recorded |
| POP ES/SS/DS/FS/GS | 10 | 440 | 16/32-bit forms with valid existing selector values; high half dead in 32-bit stack inputs; loaded selector and SP/ESP checked |
| LAHF | 1 | 44 | 22 AX patterns × two flag states; AH bits and unchanged flags |
| SAHF | 1 | 512 | Every AH value × two OF/flag states, AL=5a |
| ARPL AX,BX | 1 | 968 | 22×22 full 16-bit samples × two flag states; destination RPL and ZF, other flags preserved |
| Total | 65 | **4,840** | All six arithmetic flags recorded for every successful/trapping execution |

The segment PUSH high-half behavior is measured, not assumed in the architecture-defined C checks. This CPU writes a zero high half in all 264 32-bit PUSH-segment rows, despite initial a5a5 data. Both operand sizes of every valid segment PUSH/POP opcode are covered; POP CS has no valid encoding.

## Native mode controls

ADD and SUB each have 22×22×2 = 968 compatibility rows; SHL has 22×66×2 = 2,904 compatibility rows. Each is followed by the same 32-bit operands/flags on the corresponding instruction in 64-bit mode. Total: **4,840 matched pairs**, **9,680 rows**. C separately validates all defined results/flags, including masked-zero SHL counts.

## Checks and limitations

- All 696,928 canonical rows have exact field/hex-width checks, raw SHA verification and independent per-form expected counts
- All BCD operand/AF/CF/rest-flag combinations and labeled sample duplicates are independently verified from the raw streams
- Every compatibility fragment is executed twice immediately from a reset state: **692,088 identical pairs**. Separate whole-process reruns also yield byte-identical raw files, check logs and deterministic gzip archives
- **274** actual trap rows have complete captured fault comments; no fault is synthesized from expected semantics
- Architecture-defined C checks: **691,576 flag-check rows**, **691,302 successful result-check rows**, plus the 274 captured fault-state checks. Counts exclude 512 explicitly empirical SALC rows
- All 696,928 canonical rows also match a UBSan-compiled native run with zero sanitizer errors
- RULES.md has actual supporting and contradicting counts for every empirical claim; no rule is asserted from a guessed output

This dataset is not an exhaustive census of arbitrary segment descriptors or every operand combination for the extra instruction families. SP/ESP INC/DEC is deliberately restricted to safe mapped stack values. The memory form of ARPL, unrelated invalid opcodes and privileged forms are not included. LDT fallback measurement is not needed on this machine and is not claimed tested; the standalone probe's fallback merely reports capability if the existing selector is unavailable elsewhere.
