# Measured findings

Prepared October 6, 2026. These are observations from original probes and measured translator behavior, with conclusions, limits and explicit falsification criteria. Each note names a released patch, a candidate patch, or the absence of a completed fix. Candidate numbers do not imply inclusion in MacRunner 1.0.8.

- [Apple compatibility mode: PF and AF](apple-compat-pfaf.md)
- [Apple compatibility mode: scalar FP lane merging](apple-compat-scalar-fp.md)
- [Wide loads under hardware TSO on M1](m1-hardware-tso-wide-loads.md)
- [macOS discard and MAP_JIT protection](macos-memory-discard-map-jit.md)
- [4 KiB guest permissions on 16 KiB host pages](guest-subpage-permissions.md)
- [Noncanonical branch targets: hardware and Prism](noncanonical-branches.md)
- [Windows x64 exception delivery and Prism](windows-exception-delivery.md)
- [x87 state after continuing an exception](x87-exception-resume.md)
- [DIV/IDIV quotient overflow and #DE](div-idiv-exceptions.md)
- [CALL/RET suspension polling cost](suspension-polling-cost.md)
- [Low 4 GiB address space and signing on macOS](macos-low-4gb.md)
- [wineboot self-name lookup latency](wineboot-self-name-lookup.md)
- [Nine wow64win message cases lost dispatch](wow64win-message-dispatch.md)
- [Split unaligned atomics and lost updates](split-unaligned-atomics.md)

Original probe sources and selected numeric captures are under [evidence](evidence/README.md). Native x86 corpora are under [reference/x86-hardware](../../reference/x86-hardware/README.md); native Windows outputs are under [reference/windows-x64](../../reference/windows-x64/2026-10-06/README.md). Proprietary implementations, disassemblies and binaries are not included. These notes and original probes are MIT licensed. Third-party code is not reproduced.
