# Decoder source witness and exact dependency span

Isolated `core-source03`, derived from verified `core-perf02`. The original application and Opus lane are unchanged. Provider SHA256: `21e2c62d418e6144bbf024625588180a160118535f69426051389efa2094ca99`.

`MACRUNNER_HB_DECODED_SOURCE` defaults to zero. When enabled, both ordinary x64/i386 lifters freeze a bounded decoder input window before reading instructions, then retain only its consumed prefix. The prefix includes merged fallthrough and instructions that generate no IR; later optimization cannot erase its provenance. `func->guest_len` keeps its existing window semantics. EXEC units, nonzero initial positions, over-4096-byte inputs and allocation failures receive no witness and retain legacy SMC spans. Destruction frees the witness. A failed shrink preserves the valid original allocation.

The SMC expansion uses this decoded prefix instead of the whole decoder window when provenance exists. This eliminates repeated comparison of unrelated trailing bytes. It does not enable mutable direct chains, page protection, static register allocation, or remove the inherited write-after-check race. It does not by itself change the inherited cold SMC snapshot timing; the separate native-entry proposal consumes the original bytes to address that provenance gap.

This is a tail extension of the IR function object. The retained Wine adapter allocates through the core and uses only existing fields; its object uses no gate enumeration. All core objects were rebuilt because the added gate changes internal enum numbering. Read-only peer review is in `proposals/native-entry-guard/SOURCE03-REVIEW.md`.

Validation: general native suite 516/0 with source gate off and on. Source provenance fixture:45/55 checks with gate off and merge off/on;94/118 with gate on, all passed. It includes mutation after freeze before decode, caller-buffer mutation after lift, window/consumed-prefix distinction, merged branches, x64/i386, custom-start and over-limit fallback. CTRL2 supported full corpus:520/520 x64 and520/520 i386, with valid and intentionally wrong expectation controls. Wine:8/8 (SMC detail/process, exceptions and threads, source gate off/on), backend confirmed and owned prefixes removed after drain.

Matched menu measurements remain pending. These correctness results do not imply120FPS or full-game parity.
