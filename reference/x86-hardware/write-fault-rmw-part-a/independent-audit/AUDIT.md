# Independent audit: 0035 native write-fault capture

## Result

The original 0035 capture passes independent source, encoding, raw-data, instruction-model, repeatability, and CSV checks. This sign-off concerns the original fault/restart matrix; the October 5 split-lock contention addendum is a separate, unfinished deliverable and is not marked complete here.

- 593 forms: scalar/string 99, RMW 466, vector 28
- 12,811 measured form/layout/offset cells; 38,433 continuation rows in each full run
- 300 explicit aligned-vector cross-page N/A cells, giving 13,111 delivered CSV rows
- 39,419 captured fault records across all continuation rows in run 1
- 32,466 successful rows independently modeled for destination bytes and all GPRs
- Every ISA-defined arithmetic flag independently modeled for the 18,609 successful RMW rows; undefined bits remain observations
- All 21,644 continuation-1/3 clean-reference comparisons match full mapped memory, 16 GPRs, and complete RFLAGS
- No validator errors

## Checks performed

1. Read TASK.md and the actual C++/assembly/generator source, rather than relying on summary counts. POPF precedes flag-neutral test-register loads. The return path saves all GPRs before changing RSP and saves RFLAGS before CLD. SA_ONSTACK isolates signal-frame construction from PUSH/CALL's synthetic, possibly unmapped destination RSP. CALL writes the real deterministic return address code+5.
2. Recomputed the entire expected form/layout/offset/continuation grid from the form catalog, checked uniqueness and process completion, and separately verified required families and legal long-mode widths against the task. REP covers every offset of its complete count×width footprint for counts 1–4 and both directions; single-element forms are separate.
3. Independently assembled all 99 scalar forms with GNU as. 83 match byte-for-byte; 16 REP word forms differ only in the interchangeable F3/66 legacy-prefix order. The executed bytes have not been rewritten to make the audit match. Re-ran the 466-form RMW assembler audit; legal instructions match, and illegal LOCK forms match their independently assembled base opcode plus the deliberate LOCK prefix. The vector encoding assembly/catalog crosscheck covers all 28 vector cases, with mask variants sharing instruction bytes.
4. Reconstructed every mapped-page snapshot losslessly, checked ordered/in-bounds patches, and checked all bytes outside the destination footprint. Unmapped page two is never read or inferred. At every fault, reconstructed memory contains exactly the completed REP elements and no bytes from a partially completed current element; all other faulting forms preserve the pre-attempt image.
5. Checked every fault's 23 gregs, exact instruction-start RIP, alternate-stack metadata, 2436-byte FP/XSAVE image, and initialized XMM0/XMM1/YMM0 data. Checked all pre-fault GPRs and RFLAGS against expected input and REP progress, excluding only architectural RF from this input comparison. Checked page-fault error bits, CR2/si_addr, and distinct #UD/#GP classifications.
6. Independently modeled all successful scalar/string, vector, and RMW outcomes. This includes handler-written 0x3c inputs, XADD/XCHG returned values, CMPXCHG accumulator/results, both DF directions, full REP restart, and the documented address/count re-arming before a deliberate second execution. The RMW predictor compares defined flags and deliberately avoids inventing values for undefined flags.
7. Recomputed clean-reference equality instead of trusting the recorded Boolean. Verified every CSV's memory, register, and fault-context fields against its raw JSONL cell, plus exact CSV/gzip equivalence and all 300 N/A rows.
8. Recomputed uncompressed SHA256 for both primary runs and independently ran the complete vector group a third time. Its 3498 rows are byte-identical to both primary captures.

## Repeat evidence

- Scalar: b049d2af26c8d296e4a778b0da393c71836940e51a9c2613ca61dc93b18f59a1
- RMW: 0fa750b812861c8a28841c94a7c9bdd3729ccbfc0c2cf6491db706d944496e49
- Vector, including independent run 3: 7a52a7960bce55435e505cf9555b0dcbc1ec5fedc69e28c508ccc9bba088598f

These are uncompressed JSONL digests. The third vector raw capture, stderr log, and exit status accompany this audit.

## RULES review and limits

RULES.md's measured denominators, examples, partial-REP counts, restart equality, illegal-LOCK classification, CMPXCHG16B alignment distinction, and undefined-flag caveat agree with the evidence. Absence of #AC is correctly stated as an observation, not a claim about host policy. The single-thread fault matrix does not establish inter-core atomic visibility.

Independent CPUID leaf 0x40000000 reports KVMKVMKVM. These are native x86 instructions in a KVM-exposed Linux environment, not a bare-metal claim. HYPERVISOR.txt records the raw leaf and its decoded vendor.

The documentation claims were checked against indexed primary AMD/Intel manuals. Direct AMD PDF/API/landing fetches returned 404 in the audit tool, while official indexed excerpts remained available; Intel PDFs were located but exceeded the extraction tool's full-document size limit. This is a retrieval limitation, not a contradiction in the documented semantics. The report should retain this distinction and avoid implying a successful full-document download.

Primary references supporting the reviewed semantics:

- AMD APM Vol. 2 §§8.1.2–8.1.3, precise fault restart and saved RIP: https://docs.amd.com/api/khub/documents/sD1_QL~h4Afq2_tvzxqqSQ/content
- AMD APM Vol. 3 §1.2.5, legal LOCK forms and #UD: https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24594.pdf
- Intel SDM, CMPXCHG8B/CMPXCHG16B alignment: https://cdrdv2-public.intel.com/868140/253666-089-sdm-vol-2a.pdf
- Intel SDM, REP restart state: https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf
- Intel SDM, MASKMOVDQU zero-mask exception behavior and non-temporal ordering: https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf

## Reproduce this audit

From this directory, adjacent to the original probe35 and results directories:

```
python3 verify_scalar_bytes.py
python3 validate_capture.py
python3 model_rmw.py
python3 validate_csv.py
python3 validate_split_A.py
```

The split-A validator covers the addendum's first slice, not the unfinished two-thread part B. Machine-readable reports are CAPTURE-VALIDATION.json, SCALAR-BYTE-VALIDATION.json, RMW-MODEL-VALIDATION.json, CSV-VALIDATION.json, and SPLIT-A-VALIDATION.json.
