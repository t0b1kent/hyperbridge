# Scalar FP forwarding checkpoint

This checkpoint preserves an isolated experiment, not a release or a claim of FEX performance parity. Both new optimization gates default to0.

Consecutive scalar FP instructions can reuse the previous ARM64 result when their exact instruction boundaries, source/destination XMM register and width agree. Canonical guest state is still written, fault boundaries remain intact, and cold NaN-helper paths reload the value. A following scalar store can reuse that result without two context loads. It still uses the existing address, alignment, permission, ordering and invalidation paths.

The checkpoint also includes a correctness repair: when a scalar store fails in the helper path, publish the exact store PC before leaving the block. The ordinary successful path does not gain this work.

Experimental controls:

- `MACRUNNER_HB_SCALAR_FP_FORWARD=1`: scalar FP result forwarding.
- `MACRUNNER_HB_SCALAR_FP_STORE_FORWARD=1`: forwarding to scalar stores.

Run `python3 -E tests/fp-forwarding/run.py` on Apple Silicon macOS. It builds the archive, checks pair boundaries, runs the8 FP/store/helper combinations, and checks emitted instructions. Generic fixture sources are included; game code, game saves and proprietary runtime files are not.

Local retained validation before this checkpoint:516 core checks for each of the4 gate combinations;16 Wine regression runs passed; store/helper checks1562/0 and emission checks1200/0. Independent generated arithmetic comparisons covered43520 cases and1074945 checks per arm with identical output streams; a deliberately incorrect NaN path differed. Those larger local receipts are not a portable reproduction claim for files absent here.

One saved-scene gameplay pair with the same provider and graphics files measured18.31494FPS enabled and17.91837FPS disabled (+2.21%). This is one ordered pair, with no significance claim. It is far below the user's120FPS FEX observation. Source policy and faults must remain correct even if a future timing result is neutral or negative. The user's latest instruction is to complete the larger combined optimization package before one further game run; no additional game baseline run is planned for this checkpoint.
