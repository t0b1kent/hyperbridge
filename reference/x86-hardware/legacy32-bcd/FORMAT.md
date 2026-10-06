# Native legacy32 BCD and compatibility-mode instruction reference

Task 0005 is fully measured on the exposed AMD EPYC 9V74. The previous ELF32 exec failure does not prevent running normal ring-3 compatibility instructions inside an ELF64 process: the read-only LAR/LSL probe found the existing code selector **0x23**, and a native round trip succeeded. No LDT descriptor was needed or created. All result rows come from native instructions, not an emulator or a computed replacement.

## Reproduce

From this directory:

```
bash run.sh
```

Requires the already installed Linux x86-64 GCC/binutils, Python 3 and gzip. No network or packages. The script builds original MIT sources, probes the descriptor, verifies the bridge, generates 584 static compatibility stubs, runs each class twice, compares raw output/check logs/deterministic gzip byte-for-byte, checks exact counts and operand/flag matrices, regenerates empirical rules, and runs an undefined-behavior-sanitized native executable. Build products and uncompressed intermediates stay under `build/` and are excluded from delivery.

A normal complete run is comfortably below the protocol's 15-minute limit. If the existing selector is absent or the non-replacing scratch mapping fails, execution stops rather than changing system configuration or using an emulator. The standalone probe has the task's normal per-process `modify_ldt` capability fallback, but that fallback was **not invoked here**. A descriptor installed in the probe process does not configure another process; if only that fallback succeeds on a different machine, this script explicitly exits 77 rather than mislabeling it as instruction coverage. This deliverable's tested bridge is the existing-selector route.

## Delivered results

| Stream | Instruction rows | Captured traps |
|---|---:|---:|
| `out-bcd.txt.gz` | 682,408 | 44 AAM-immediate-zero #DE |
| `out-extra.txt.gz` | 4,840 | 208 BOUND #BR; 22 INTO #OF |
| `out-control.txt.gz` | 9,680 | 0 |
| Total | **696,928** | **274** |

Each `.sha256` sidecar hashes the **decompressed raw text** and names `decompressed.txt`. `FILE-SHA256.txt` separately hashes every delivered file except itself. `validation-summary.json` also records compressed and raw sizes/hashes. `REPRODUCTION-CHECKS.txt` additionally verifies that a complete rebuild reproduces all 17 result/evidence files byte-for-byte. `RULES.md` and `rule-counts.json` count every empirical claim from measured rows, including the undefined BCD flags and segment-PUSH upper bits.

## Bridge and validation

- `probe.c`: LAR/LSL validates the existing user code descriptor without accessing privileged tables; exact selector/access/limit evidence is in `PROBE.txt`
- `bridge.S`: saves all 15 non-stack 64-bit GPRs, RFLAGS, DS and ES, and remembers RSP; enters CS32 with a far return and leaves it with a direct far jump to CS64, then restores the original 64-bit state. This is an equivalent native far-transfer implementation of the task's suggested call/return wrapper. No syscall runs in compatibility mode
- `bridge_check.S`, `roundtrip.c`, `ROUNDTRIP.txt`: independent full-width sentinel snapshots verify all 16 GPRs including RSP, RFLAGS, DS/ES/FS/GS, and FS/GS bases. Both the ordinary path and the path restoring original TLS bases pass. The minimal marker/low-stack round trip also passes
- `generate.py`, `inventory.json`: original static `.code32` instruction generator and complete per-form inventory; immediates are actual encoded bytes, including all 256 AAM and AAD constants
- `oracle.c`: native result capture, alternate-stack POSIX fault handlers, independent C defined-result/flag checks, and immediate repeat of every compatibility fragment with a reset input/stack state
- `analyze.py`, `audit.py`: read-only analysis of native result streams; they never repair or synthesize result rows
- `*-CHECKS.txt`: actual C result, defined-flag, trap, duplicate and mode-control counts, broken down by form
- `SANITIZER-CHECKS.txt`, `run-ubsan.sh`: all 696,928 canonical instruction rows also match the separately compiled UBSan native executable. Fault IP comment addresses naturally change with executable layout, so this cross-build check compares canonical rows; complete normal-run raw streams, including fault comments, match byte-for-byte

One normal run verifies **692,088 immediate duplicate pairs**, **4,840 cross-mode pairs**, and **274 genuine signal contexts**. C reports 692,088 arithmetic-flag checks and 691,814 successful result checks, including 512 explicitly empirical SALC cases. Excluding undocumented SALC, the architectural totals are **691,576 flag-check rows** and **691,302 successful result-check rows**. All counts have zero errors. The additional 4,840 long-mode rows are exact result/flags comparisons with their compatibility-mode partners.

Successful paths restore all GPRs through the bridge. Fault paths return through a 64-bit signal handler and `siglongjmp`, preserving the host C calling convention while recording the fault-time 32-bit register image. Actual Linux trap vector, signal, `si_code`, CS, error code, EIP, all eight 32-bit GPRs and full saved EFLAGS are printed in raw comments. No fault row is inferred or generated from the C expected model.

## Inputs

Every non-BCD-special case uses both arithmetic masks 0 and 0x08d5; the observed complete low-16 FLAGS are normally 0x0202 and 0x0ad7. DAA/DAS explicitly cross all four AF/CF combinations with both states of PF/ZF/SF/OF. AAA/AAS cross both AF values with both states of the remaining five flags. The exact input/flag matrix is independently audited from output.

The 22-position sample, recomputed at each width, is: 0, 1, 2, 3, largest signed positive, smallest signed negative, all ones, repeating 0x55, repeating 0xaa, low bit, high bit, middle bit, and ten fixed constants truncated to the operand width:

```
89abcdef 76543210 7f4a7c15 d192ed03 133111eb
4f6cdd1d cafebabe 00000001 00000080 00000000
```

Duplicate labeled positions are retained to keep count formulas exact. AAM uses an 8-bit AL sample with AH initially 0xa5. AAD uses a 16-bit AX sample. INC/DEC use 16- and 32-bit samples on each register except SP/ESP, which use four valid bounded stack values (`0x2000e000 + {0,4,8,12}`) so capturing flags remains safe. Other fixed 32-bit input registers are ECX=13579bdf, EDX=2468ace0, EBX=76543210, ESP=2000e000, EBP=11223344, ESI=55667788, EDI=99aabbcc; opcode-specific source/count registers replace these as documented. EAX begins a5a50000 before its relevant low bits are replaced. Upper-width preservation is included in the C checks.

BOUND uses signed bounds [0,3], [-3,2], [signed minimum,signed maximum], and the intentionally inverted [10,5], at both widths. Every bound pair crosses all 22 index positions and both flag patterns. Control ADD/SUB use all 22×22 operand pairs; SHL uses 22 inputs and every raw CL count 0..65, covering count masking.

## Field conventions

Every instruction line has the exact task shape:

```
OP.form width FLAGS_before A B C -> [TRAP] R1 R2 FLAGS_after
```

Flags are actual low-16 values, not reduced to the six arithmetic bits. Values are operand-width hexadecimal; absent fields are `-`. Comments begin `#` and contain additional raw state.

- DAA/DAS: width 8; A/R1 are AL; R2 is the observed unchanged AH (initially zero). C checks full EAX preservation outside AL
- AAA/AAS: width 16; A/R1 are AX
- AAM/AAD: width 16 so both AL and AH are visible; C is the encoded immediate. AAM-zero TRAP R1 is saved AX and R2 is saved DX; the comment contains complete EAX/EDX and other saved registers
- PUSHA/PUSHAD: A is initial AX/EAX; R1 is final SP/ESP, R2 is the original SP/ESP captured in the stack frame. The raw `# stack-frame` lists eight values from low to high addresses; `# registers` gives full before/after registers
- POPA/POPAD: R1 is resulting AX/EAX, R2 final SP/ESP. Every output register and the skipped stack-pointer slot are checked. Stack slots start `12341111,12342222,...,12348888`, truncated for 16-bit POPA
- BOUND: A=index, B=lower, C=upper; R1 is index after execution/fault. TRAP R2 gives saved DX/EDX
- INTO: A/R1 are a harmless accumulator pattern; OF comes from FLAGS_before; fault details are captured at the actual overflow trap
- SALC: A/R1 are AL. Its CF-dependent result and preservation of all six flags are empirical checks, not a claim of documented architectural status
- INC/DEC: the suffix identifies the exact register and width; A/R1 are that register. Raw bytes 40..4f are used, with 66 for 16-bit operands
- PUSH segment: suffix identifies the segment; B is the initial stack-slot fill (a5a5/a5a5a5a5), R1 is the actual pushed slot and R2 final SP/ESP. A is a harmless initial accumulator input
- POP segment: B contains the prepared stack value (valid low selector; 32-bit form has high half dead), R1 is the actual loaded selector and R2 final SP/ESP. Valid existing ES/DS/SS=2b and FS/GS=0 are used. Only FS/GS POP paths restore original thread bases with ordinary `arch_prctl` before returning to libc; they do not establish new access
- LAHF/SAHF: A/R1 are AX. SAHF covers every possible AH with AL=5a
- ARPL: A/R1 are AX; B is BX
- ADD/SUB control: A=EAX, B=EDX, R1=EAX; SHL control: A=EAX, C=raw CL. `.compat` and `.long` partners are otherwise identical and are independently compared

All addresses printed in fault/stack evidence are this executable's stable code or fixed scratch addresses, not machine or network identifiers. No process IDs, hostnames, environment variables, credentials, keys or network addresses are captured.

## Limits

These are results for one exposed CPU implementation and normal flat user segments. No privilege elevation, kernel change, sandbox bypass, security-setting change, packages or emulator was used. POP CS has no valid legacy encoding; no invalid-selector or privileged descriptor tests are attempted. Alternate segment bases/limits, SS stack-address-size 16, arbitrary segment values, memory ARPL, LOCK prefixes and exhaustive combinations for the extra instructions are outside the requested measured set. The task's BCD exhaustive domains and all listed extra instruction families are covered. The code is single-threaded; its fixed process scratch mapping and saved bridge state are deliberately not reentrant.
