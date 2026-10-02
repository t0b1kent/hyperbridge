# CPU input formats

These are format descriptions, not captured inputs. Parsers and the own recorder header are the executable definitions.

- **HBSTATE1:** eight-byte magic, then four little-endian uint32 values: version, record size, JSON metadata length, reserved zero. Version 1 uses the packed `Record` in `recorder/StandStateCapture.h`. Read offsets from metadata; do not assume C struct layout from another build. Records include RIP, sequence/thread, FPCR/FPSR, EFLAGS/MXCSR, 16 GPRs, XMM/YMM data, x87 state and FS/GS bases. YMM upper-half handling must be tested with nonzero own inputs.
- **HBMEM001:** frozen readable regions and page contents, parsed by `real_inputs.py`'s image reader. Region records include address, size, protection, allocation type, payload length and read status. Keep failed/unreadable regions explicit and bound allocation sizes before loading a corpus.
- **HBCAP001:** metadata and translated-block code records, parsed by `span_diff.records` and `capture_index.py`. Record each code site's original guest RIP and static bytes; the stream does not establish dynamic execution coverage.
- **Dataset:** the original gate's JSON has `games` entries with `game`, `states`, `image`, `capture`, quick-selection information and pinned hashes/counts. Inspect `parallel_replay.tasks_for` for the exact accepted keys. The historical gate requires its five title labels and coverage rules. Do not relabel synthetic examples as captured game inputs.

All records and memory must refer to the same owned process, execution point and selected engine. Hash the raw streams, maintain sequence/clock provenance and preserve reference failures. Replay only the declared span and memory; absent bytes are missing evidence.

`examples/synthetic.asm` and `synthetic.json` give an own MOV/ADD encoding and expected result. `check_synthetic.py` constructs deterministic own memory in RAM, without saving pages, and exercises the existing reference parser. It does not generate a private qualification corpus.
