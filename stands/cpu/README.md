# CPU differential stand

The own gate and replay code from STAND-DIFF stages 4–6 compares translated x64 block execution with Unicorn from the same registers and mapped memory. Independent rational VEX rules correct known reference gaps; the MXCSR oracle computes masked exception-status bits from operand bits. It reports EQUAL, KNOWN, NEW and unavailable input/reference states separately.

The October 2 private qualification run checked 500,595 of 540,861 states. Stage 6 reported 651 known states and zero new ones; 650 belong to missing MXCSR status flags. Its independent status oracle matched 7,168 hardware-reference pairs / 14,336 executions. Six deliberate ARM64 code-generation errors and two status-state mutations were detected. These numbers describe the retained private inputs, which are not distributed.

## Dependencies

Python 3.10+, external Unicorn 2.1.4 and Capstone 5.0.x (preparation checked with 5.0.7). Native replay additionally requires Apple Silicon macOS, Xcode Command Line Tools, ccache and a separately prepared compatible MacRunner FEX build with `compile_commands.json`, Ninja link recipes and `hb_replay` support objects. FEX and its third-party libraries are not included. zstd is needed only for compressed private inputs. [License](LICENSE).

## Run

From this directory, with the Python dependencies already installed:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 examples/check_synthetic.py
```

This runs the own assembly example in the reference and checks independent value/status rules; native FEX is NOT_ENABLED.

For native replay, prepare the external FEX build separately, then build only the own frontend into a new output:

```sh
python3 artifacts/stand-diff-stage4-20261001/build.py runner --fex-build "$FEX_BUILD" --output "$NEW_RUNNER"
python3 artifacts/stand-diff-stage6-20261002/fast_replay_flags.py --runner "$NEW_RUNNER" --states "$OWN_STATES" --image "$OWN_IMAGE" --capture "$OWN_CODE" --game own --scan-all --out-prefix "$NEW_RESULT"
```

The build helper does not install or replace a runtime. Its imported link recipe must match the selected engine. The default standalone frontend is not proof of product ARM64EC integration.

`sh scripts/hb-stand-diff.sh --quick|--full "$RUNNER" --dataset "$DATASET"` retains the original qualification gate. It requires a complete five-title dataset and coverage metadata. No such dataset is shipped. A small own-code corpus belongs in the individual comparator, not a fabricated qualification manifest.

## Record your own corpus

Use only software and data you may distribute. [DATA_FORMAT.md](DATA_FORMAT.md) describes the streams. The own recorder header and entry insertion are included; integrate them into your external diagnostic FEX source after the normal entrypoint, preserving full guest state. Set `MACRUNNER_FEX_STAND_STATE` to a new output stem; first-K sampling is bounded. Collect matching code and readable memory with the guest stopped at each selected state. A later memory snapshot cannot prove entry-state coherence. Seal hashes and counts, preserve failures, and record unmatched pages as missing.

The six emitter insertions are in [mutations](mutations/README.md); full upstream JIT source is excluded.

## Limits

Separate-block checks do not cover SMC, aliases, cache lifetime, EC/native ABI, scheduling, game startup, GPU or FPS. x87, unmasked #XM and flag writes to memory are outside the status oracle. The historical corpus had zero nonzero upper YMM halves, 19 missing references and 602 mapping failures. Empty exact-case registries contain no private adjudications; unknown deltas must remain NEW.
