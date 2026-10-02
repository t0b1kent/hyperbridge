# 32-bit input formats

No recorded state or memory is distributed. The tiny own examples in `examples/cases.json` correspond to `synthetic.asm` and deterministic generated memory.

| Format | Definition |
| --- | --- |
| Case JSON | List of objects with `id`, `name`, `origin`, `code` hex, `seed` and `state`. `state` includes RIP/EFLAGS/MXCSR, GPRs, FCW/FSW/abridged FTW, raw x87 storage, XMM data, segment selectors and bases. `pages`/`patches` are optional for own memory inputs. See `stand32.default_state`, `page_image` and `oracle`. |
| HBSTATE1 version 2 | Magic plus four uint32 header fields and metadata offsets, followed by fixed-size records. Adds segment selectors/bases/descriptors, guest bitness, synchronous-memory flag, monotonic clock and execution count to version 1. Read exact offsets from metadata. |
| HBWGHT32 | Versioned shared weight header and bounded slots; includes an acknowledged sequence for the synchronous-memory handshake. The record-producing guest waits for exactly that sequence or reports failure. |
| HBM32D01 | Sequence-linked memory delta stream. `capture32.py` validates version, predecessor and monotonically advancing sequence before applying it. |
| HBPAGES1 | Eight-byte magic, uint64 page count, then uint64 guest address and 16,384 bytes per page. Optional SHA-256-addressed zstd storage is defined by `memory_store.py`; hashes, counts and absent pages are validated. |
| HBCAP001 | Versioned translated-code capture; metadata must prove 32-bit mode before `capture32.py` accepts it. |

Save the exact record/memory relationship and raw hashes. Synthetic cases are `SYNTHETIC`; only actual captured inputs can be `GAME_CAPTURE`. No label alone establishes valid memory provenance.

For another own program, encode its instruction sequence, set an explicit register/segment/x87 state and provide only the memory it can reach. Record failures and missing memory. The individual `stand32.py --cases` comparator accepts small own corpora; the historical qualification gate has additional private dataset requirements.
