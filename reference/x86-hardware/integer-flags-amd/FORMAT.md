# Native integer undefined-flags oracle

Original MIT source and real x86-64 execution results for TASK 0002. The CPU presents as AMD EPYC 9V74 (AuthenticAMD family 25, model 17, stepping 1). It is a cloud virtual machine exposing a hypervisor flag; no instruction emulator was used. See MACHINE.txt.

## Reproduce with one command

```
bash run.sh
```

Requires Linux x86-64, GCC/binutils, Python 3 and gzip already installed. No packages or external source downloads are used. All generated assembly/binaries/uncompressed intermediate files stay in `build/` and are excluded from delivery. The command generates native stubs, assembles, runs every class twice, compares raw streams and deterministic gzip streams byte-for-byte, performs C defined-semantics checks, regenerates measured rules and audits hashes/counts/field widths. The i386 no-libc build/execute probe is included; exit 77 is the recorded, allowed unavailable result on this environment. If i386 becomes available later, the probe reports that a full class-11 measurement is still needed rather than pretending that the probe itself covers the instructions.

Individual core classes can be rerun with `bash run-core.sh shifts rotates double multiply divide bitscan bittest logic misc` (choose any subset). Class 9: `bash bmi_run.sh && python3 bmi_verify.py`. Recompute core empirical rules: `python3 analyze_core.py`. Regenerate documentation/count audit: `python3 summarize.py`.

## Files and validation

- `core.c`, `generate_core.py`: original harness, signal handler, independent C expected-result/defined-flag calculations, static native instruction generator
- `core-inventory.json`: exact generated native stubs with mnemonic, width, immediate/count and assembly symbol
- `out-<class>.txt.gz`: unmodified output from executed instructions, with deterministic `gzip -n -9`
- `out-<class>.sha256`: SHA-256 hashes of the uncompressed raw `.txt` stream for every class, following TASK 0001. `verify_data.py` validates them by decompression without retaining a raw file; the manifest and validation summary additionally record compressed-file hashes
- `out-<class>.validation.txt`: expected/measured row counts, actual C result and flag check counts, trap count, before/non-arithmetic flag checks, deterministic-repeat outcome
- `bmi_CHECKS.txt`, `bmi_RULE_CHECKS.txt`, `bmi_REPORT.md`: class-9 detailed independent checks and measured rules
- `RULES.md`, `core-rule-counts.json`: counted empirical rules, including falsified candidate equations and all alternative candidate counts
- `COVERAGE.md`: per-instruction undefined flags, precise forms/rows, count formulas and omissions
- `legacy_REPORT.md`, `legacy_CHECKS.txt`, `legacy32.S`, `legacy_probe.sh`: real native i386 build/execute evidence

Results are written only by the native executable. Analysis and validation scripts read them and write separate reports; they never repair, synthesize or alter any result row. The C reference checks only architecturally specified bits/results. A separately compiled undefined-behavior-sanitized native run also produces exactly the same core result bytes; SANITIZER-CHECKS.txt records this additional audit. Undefined values are preserved exactly in the table and analyzed independently afterward. Every trap row contains the Linux SIGFPE handler's saved machine RAX/RDX (AX halves for 8-bit DIV) and low-16 EFLAGS, not handler-time arithmetic flags. The signal handler uses the actual ucontext register image and siglongjmp; no synthetic trap result is printed.

## Input policy and sampling

For every execution the two requested arithmetic-flag patterns are installed and actual FLAGS_before is captured immediately before the instruction: `0202` and `0ad7` (CF,PF,AF,ZF,SF,OF all clear/all set). Arithmetic mask is `08d5`. Only low 16 RFLAGS bits are reported. DF is clear and IF reflects user-mode execution. Full non-arithmetic low-16 preservation is separately checked.

Each width has 22 labeled operand positions. Duplicates are retained deliberately to make the formulas exact: 0,1,2,3,signed maximum,signed minimum,all ones,55... bits,AA... bits,low bit,high bit,middle bit, and ten deterministic constants truncated to width:

```
0123456789abcdef fedcba9876543210 9e3779b97f4a7c15 d1b54a32d192ed03
94d049bb133111eb 2545f4914f6cdd1d deadbeefcafebabe 8000000000000001
0000000100000080 7fffffff00000000
```

Binary data operands use all 22×22 positions. Unary operations use 22. DIV/IDIV sweep all 22³ low/divisor/high triples and explicitly constructed quotient-overflow boundary triples. CMPXCHG sweeps all 22³ destination/new-source/accumulator triples. CMPXCHG8B/16B sweep all 22³ expected/memory/replacement triples. The 128-bit set has the same twelve canonical whole-value boundary/bit patterns (including zero, signed extrema and all ones); its ten additional positions concatenate low64=fixed[j] and high64=fixed[(j+3)%10]. It is a 22-position 128-bit sample, not all Cartesian low/high limbs.

No reduction was needed for the 60 MB compressed-result budget. Instruction counters are never sampled away: SHL/SAL/SHR/SAR/ROL/ROR/RCL/RCR cover every raw count 0..(2×width+1), immediate and CL; SHLD/SHRD cover every raw count 0..63, immediate and CL, including 16-bit undefined results. The CL stubs are duplicated by raw count intentionally for manifest simplicity; encoded register/count forms should be distinguished from generated form/count configurations.

Bit-test register indices include all 22 pattern indices plus 15 explicit offsets. Memory indices use those 15 bounded offsets, with all 22 data patterns: -2w-1,-2w,-w-1,-w,-1,0,1,w/2,w-1,w,w+1,2w-1,2w,2w+1,255. Arbitrary 64-bit offsets from the full pattern set would address inaccessible memory and are not used for bit-string memory forms. This restriction is documented rather than generating artificial rows or unrequested memory faults. Immediate indices are 0,1,w/2,w-1,w,w+1,255. Raw instruction imm8 is encoded directly: high immediate bits are masked by the CPU, not rewritten by the assembler into an extra displacement.

IMUL3 uses every A×B pair for each chosen immediate, retaining initial A even though the three-operand instruction overwrites it independently. For 16 bits: -128,-2,-1,0,1,2,3,127,-32768,32767,128,255. For 32/64 bits add the signed 32-bit minimum and maximum. The assembler selects imm8 versus full imm16/32 as required by value. All signed immediates print as operand-width two's-complement hex.

## Field conventions

Every data line has exactly the requested shape `OP.form width FLAGS_before A B C -> [TRAP] R1 R2 FLAGS_after`. Mnemonic suffixes identify immediate/CL and register/memory forms. Numeric operand/result fields have operand-width hex digits; flags have four. A `-` means no applicable operand/result. Unused scalar B slots in the core harness print a harmless zero and are documented here. Class 9 uses `-` for absent B. C records a count/immediate; it additionally records an essential implicit input where the fixed three-input schema otherwise cannot hold it:

- shifts/rotates/double shifts: A=destination, B=source (zero for single-input forms), C=unmasked original count, R1=destination
- MUL/IMUL1: A=implicit low accumulator, B=multiplier, R1=low product, R2=high product (AL/AH for width 8)
- IMUL2: A=destination, B=source; IMUL3: A=old destination, B=source, C=immediate; R1=low product
- DIV/IDIV: A=low dividend, B=divisor, C=high dividend; R1=quotient and R2=remainder, or the same two architectural register parts from trap context; for 8 bits C is AH and A is AL
- scans: A=old destination, B=source; R1=actual destination including zero-source undefined cases
- bit-test register forms: A=data, B=register bit index (zero for immediate), C=immediate when applicable, R1=data after
- bit-test memory forms: a 256-byte aligned buffer is initialized with repeated A-width words; the logical base is its center. For register-index forms R1 is the actual selected word and R2 the nominal base word after execution, so out-of-range writes are visible. B is a signed width-bit index. C holds an immediate for immediate forms; these select within the base word
- logic: A=destination, B=source, R1=destination (unchanged A for TEST)
- CMPXCHG: A=destination, B=replacement source, C=accumulator comparison input; R1=destination afterward, R2=accumulator afterward
- CMPXCHG8B/16B: A=expected accumulator pair, B=initial memory pair, C=replacement pair; R1=accumulator pair afterward, R2=memory pair afterward; width 64/128 captures the full pair
- XADD: R1=sum, R2=old destination; BSWAP16: R1=actual AX after raw 66 0f c8 encoding

No addresses, instruction pointers, stack pointers, process IDs, environment values, credentials or host/network names enter result rows. RAX/RDX and other named registers refer to the operand-width values unless an explicit paired form above widens the operand.

## Limits

These are measurements for one exposed CPU implementation, not portable promises for every x86 CPU. Register encodings dominate the data; memory forms are intentionally exercised for bit strings and CMPXCHG8B/16B. Alternate register allocations, LOCK prefixes, arbitrary memory alignments and upper-register preservation/zero-extension above the displayed operand width are not independently enumerated. No fault classes except the requested DIV/IDIV #DE are induced. Class 11 is unavailable because native ELF32 execution is rejected (errno 8), despite successful static no-libc compilation. No guessed legacy rows are supplied.
