# Native macOS LLVM22 compiler for Wine

The prerequisite diagnostic run 37772884815 on revision 865d87f390f2b487967c908810c0efb89fdfab2a passed all 44 LEVEL4 RUN lines and synthetic assembly checks. This recipe builds the compiler on an ARM64 macOS host and retains the accepted official llvm-mingw sysroots.

The workflow first runs three independent preflight cells with fail-fast disabled: the official LLVM source and patch, the pinned official sysroot/wrapper/runtime archive, and source-built CMake/Ninja. A push to repro109/llvm22-wine-macos-20261008 runs only these cells. After their actual results pass, the curator pushes the identical reviewed commit to repro109/llvm22-wine-macos-full-20261008. That narrow branch push repeats preflight and, only if it passes, starts the full compiler job. This route works without assuming a new branch-only workflow is dispatchable from the default branch. workflow_dispatch with full=true is an optional route after default-branch registration is independently proved.

Host: GitHub macos-26 (hosted ARM64), Xcode 26.6 build 17F113 selected through /Applications/Xcode_26.6.app/Contents/Developer, macOS SDK 26.5, Python 3.13.7. The official image document (SHA256 688dc6f11befc470dd78896f4b69f5956dd9cc3986287919a6b912d748b97f21, image 20260907.0351.1) lists this exact Xcode/SDK pair. The label document lists macos-26 as ARM64 with 3 M1 CPUs and 7 GB RAM; parallel compilation is bounded at two tasks and linking at one. Both document URLs and image identity are in macos.lock.json. The job checks the actual Xcode build, SDK, CPU architecture, physical memory and free disk before downloads; a changed image fails with evidence. This compiler emits native ARM64 Mach-O tools with deployment target 14.0; it does not change the application's minimum macOS version.

Official source pins, tool versions, accepted helper hashes, sizes and deadlines are in macos.lock.json. LLVM 22.1.5 is patched with the previously accepted Q-restores patch, default=false. The same primary RUN10 stdout adjustment is applied only to the test input; the compiler patch is unchanged. CMake 4.3.2 and Ninja 1.13.2 are built from their official archives. LLVM builds clang, lld, llc, FileCheck, llvm-readobj, llvm-ar, llvm-nm, llvm-objcopy and llvm-objdump, with AArch64 and X86 backends and a single link worker.

The output is macrunner-llvm22-22.1.5-macos-arm64-ucrt.tar.xz with its own root and SHA256. Nine tools come from this LLVM source build. The official llvm-mingw-20260505 archive supplies the four sysroots, runtime libraries, resource headers, shell wrappers and remaining auxiliary files. These retained files are pinned bootstrap inputs, not a claim that all compiler-package files were rebuilt from source. COMPILER.json lists every regular file's bytes, hash and origin, and every symlink. The wrapper itself retains its license; the LLVM license is included separately.

Before export the producer requires:
- native ARM64 Mach-O for every rebuilt tool;
- all ten Wine compiler interfaces inside this package;
- 44 real LEVEL4 commands and default/off/on synthetic assembly checks;
- C and C++ compilation and linking for aarch64, arm64ec, x86_64 and i686, checking COFF/PE machine types and preserving llvm-readobj load-config output.

Windows binaries are not executed. No Wine, games, product stands, signing or notarization run here. Passing the compiler boundary is not product acceptance.

From a clean owned checkout, in the pinned cloud host:
1. python3 -I -B build/repro109llvm22/macos.py --phase llvm-source --out "$RUNNER_TEMP/llvm-source-results"
2. python3 -I -B build/repro109llvm22/macos.py --phase sysroots --out "$RUNNER_TEMP/sysroot-results"
3. python3 -I -B build/repro109llvm22/macos.py --phase build-tools --out "$RUNNER_TEMP/build-tools-results"
4. After all three pass: python3 -I -B build/repro109llvm22/macos.py --phase full --out "$RUNNER_TEMP/full-results"

Each command requires a fresh output and work root. Deadlines and command log caps use the accepted LLVM runner. The job always preserves RESULT.json, driver output and complete bounded logs; source hashes are recorded before extraction, and LLVM preimages/postimages and CMake source ownership are checked.

Wine's existing official-compiler hash and archive-root checks are unchanged. After the new artifact is accepted, a separate pinned Wine consumer must bind its exact producer revision/run, compiler archive SHA/root and COMPILER.json hash. Q-restores is enabled only in the intended ARM64EC A/B compiler selection; the compiler default stays false. The EC module census remains mandatory after Wine install, followed by the existing function/section comparison and product stands.
