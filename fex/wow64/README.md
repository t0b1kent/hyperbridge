# WOW64 additions shipped in MacRunner 1.0.8

These six patches are the 32-bit frontend chain from the published
[MacRunner 1.0.8 source archive](https://github.com/t0b1kent/macrunner-app/releases/tag/v1.0.8).
They retain their original bytes. All six were found in the archive's
`stage2-received-patches`; `0052-port-Darwin-host-interrupt-page.patch` is the exported
`0052-Darwin-host-interrupt-page-PRODUCT-PREREQUISITE.patch`, renamed only.
None is missing. These are downstream MIT modifications, like the common FEX series.

Use a separate FEX tree at upstream `fd141ed6d721d03062619e4702bca1a0c93b6dd9`.
First apply common 0001–0049, 0055, 0056, 0065 and 0075 from `../patches/` in filename
order (53 patches). Then apply this directory's [`ORDER.txt`](ORDER.txt), **in its
listed order, not lexical order**. Finally apply common 0160 and 0161. This is the
release source order: 53 common patches, six WOW64 additions, two common final fixes.
Do not put these additions into `fex/patches/`, which CI applies lexically.

| Order | Patch | Change |
|---|---|---|
| 1 | 0070 | Release the registry lock while waiting for a target to suspend; protect target lifetime |
| 2 | 0071 | Use the implemented local suspend contract and synchronize native control context before teardown |
| 3 | 0052-port | Put the Darwin host interrupt on an isolated host protection page |
| 4 | 0050 | Cooperative suspend checkpoints at translated backedges |
| 5 | 0053 | Product backedge continuations for the WOW64 suspend protocol |
| 6 | 0087 | Preserve the existing owner on current-thread Get/Set context reentry |

MacRunner 1.0.8's `ENGINE.json` sets `MACRUNNER_FEX_SUSPEND_BACKEDGE=1`.
0087's source defaults owner reentry on and diagnostics off; its control is
`MACRUNNER_FEX_CONTEXT_OWNER_REENTRY=0`. This source default is not a separately
listed setting in the shipped `ENGINE.json`.

On October 5, 2026 a local `git archive` of the pinned bare upstream was initialized
as an isolated Git tree. Each of the 53 common patches, these six additions, and
0160/0161 passed `git apply --check <absolute-patch-path>` and then
`git apply <absolute-patch-path>` with exit code 0. Submodules were absent from that
archive; none of these patches touches them. This checks applicability, not builds,
runtime suspension, Wine ABI compatibility or gameplay. No translator build or
runtime was launched for the check.

The release archive's `WOW64-REBUILD-0087.md` describes the source base, target
`wow64fex`, `aarch64-w64-mingw32` toolchain and Wine-side dependency. It is an
intermediate recipe; the final release also includes 0160/0161. The later clean
Xcode Cloud reconstruction matched the shipped `xtajit.dll` byte for byte; the
signed unix companion did not reproduce byte for byte. See
[`../MANIFEST.json`](../MANIFEST.json) for final hashes and the measured scope.
