# c33r frozen translator source profiles

The existing public chain remains pinned: upstream FEX, the common MacRunner
series, c9, c12/c32, and the separately retained WOW64 source delta. Only after
the exact legacy variant passes its whole-tree postimage check does
`release111_source.py` apply the separately sealed c33r profile. Every replacement
and deletion has a preimage hash, every new/replaced source has a postimage hash,
and the final whole-tree inventory is checked again. An unexpected file or
symlink refuses the operation before replacement. The two variants must never
be interchanged: the 32-bit profile contains the accepted x87/native32 work.

The selected inventories contain 6,953 FEX32 and 6,941 FEX64 files. Eight and
39 inactive private backup files are excluded explicitly in the profile
receipts; their contents are not published. The three missing range-v3 editor
settings are explicit deletions. No compiler input is silently omitted or
rewritten. All selected source content is byte-exact to the retained producers.

The compiler pin is llvm-mingw 20260908 / LLVM23.1.1. Native compilation uses
Xcode27.0 build27A266a, SDK27.0, Apple clang21.0.0 (clang-2100.3.34.2), linker
27037.1, target macOS26.0, and two workers. The application minimum remains26.5.
The existing source-only cloud restriction stays active; this export does not
authorize local full CPU builds or dispatch a cloud job. Effective source,
compiler and platform pins are recorded in each build receipt. Native source
equivalence was separately checked by rebuilding all six retained producer
objects; this does not replace whole-component cloud binary comparison.

`reference_pe_sha256` in each c33r profile identifies the unmodified producer PE
before packaging, while the legacy references remain pinned for reconstruction
of the legacy preimages. The final archive uses the c33r ENGINE environment.
The older c12/c32 manifests and compiler fields are retained as historical
preimage inputs. The public ENGINE metadata omits only `report.c15.layer1_gates`,
a local proof path. Its file hash is separate from the frozen candidate ENGINE
hash; runtime configuration and environment are unchanged. Legacy records are
preimage inputs; the c33r build overrides the effective compiler/platform fields.
Release byte comparison, assembly stripping/relocation/signing, correctness,
upgrades and game gates remain required. Source qualification is not release
acceptance, and no public push or signing is performed by these recipes.
