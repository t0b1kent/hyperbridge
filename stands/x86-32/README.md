# 32-bit differential stand

The own STAND32 code compares 32-bit native FEX execution and Unicorn32 at base zero and a shifted 8 TiB address space. Independent integer x87 rules check stack tags, empty slots, environment serialization and sticky exception witnesses without using either engine's arithmetic as truth.

Stage 1, October 1, used 616 states from four titles and 296/296 equal PE probes at each base. Five mutation controls and six guard controls were detected. It found 22 pop-tag, four sticky-invalid and 32 serialized-tag cases; 56 empty-slot-byte cases remained disputed. These private game and PE inputs are excluded.

## Dependencies

Python 3.10+, external Unicorn 2.1.4 and Capstone 5.0.x (preparation checked with 5.0.7). Native execution requires Apple Silicon macOS, Xcode tools, ccache and an external compatible MacRunner FEX build with the 32-bit guest-address-space API, `compile_commands.json` and Ninja support objects. Compressed memory storage uses external zstd. FEX, Unicorn and their source/binaries are not bundled. [License](LICENSE).

Base-zero execution on macOS needs the operator's own permitted loader/entitlement setup; this package contains no profiles, signing receipts or signing helpers. It does not create or substitute those rights.

## Run

From this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 examples/check_synthetic.py
```

This checks own MOV/FLD1 encodings and integer tag rules; native FEX is NOT_ENABLED.

With a separately prepared compatible engine:

```sh
python3 artifacts/stand32-20261001/build.py --engine-native-base --fex-build "$FEX_BUILD" --output "$NEW_RUNNER"
python3 artifacts/stand32-20261001/stand32.py --runner "$NEW_RUNNER" --cases examples/cases.json --base 0x80000000000 --out "$NEW_RESULT"
```

The helper builds the own frontend privately and reports `install skipped`. It does not build, install or replace the engine. Use a new output; an existing frontend is backed up before overwrite. Native base zero is a separate explicitly selected test.

`sh scripts/hb-stand32.sh --quick|--full --runner "$RUNNER" --dataset "$DATASET"` retains the original qualification gate. Its private four-title cases, extracted PE cases, complete directed fixtures and mutant binaries are not shipped. Missing inputs/controls fail, rather than granting qualification to the synthetic examples. The first-stage gate also fails on known defects.

## Record your own corpus

Use your own 32-bit program and data. Integrate the own recorder headers into an external diagnostic FEX tree. Set `MACRUNNER_FEX_STAND_STATE` to a new stem; bound `MACRUNNER_STAND32_CAP` and restrict RIP ranges as appropriate. For memory coherence use `MACRUNNER_STAND32_SYNC_MEMORY=1`: the collector must snapshot the stopped guest state, preserve the sequence-linked image/delta and acknowledge exactly that sequence through the weight header. Preserve timeout/failure records; never substitute a later memory image.

The included capture/parser/storage modules document the handshake and streams. [DATA_FORMAT.md](DATA_FORMAT.md) describes the JSON input and binary formats. The own x87 mutation insertions are provided without upstream `X87.cpp`; the frontend includes the address/sign/carry control hooks.

## Limits

The first-stage corpus covered only 105–194 blocks per title. Offline equality does not establish Wine startup, ABI, gameplay, GPU, FPS, general x87 correctness or product integration. A recorded wall-clock timeout remains evidence, not an opcode defect. Missing memory, unresolved reference behavior and disputed empty-slot bytes must remain distinct. The exported exact-case registry is empty; no private approvals are transferable.
