# Binary formats (little-endian), independent gzip shards

All lengths/counts checked. Instructions are actual assembled x86 bytes without the
oracle's trailing RET. No external pointer is serialized. Memory locations are
relocated by the Mac runner: RBX=read pointer, RDI=write pointer for masks, RDI=data
for CMOV memory. RSP is a mapped scratch stack. Other documented input registers
are seeded exactly. Every byte string below is raw binary, not hex text.

## HBUP0002

File: ASCII magic `HBUP0002` (8), u32 record count.

Record fixed header, Python `struct` format `<HHIQ8QiiI`:
- u16 name byte length, u16 guest-code byte length, u32 kind=2;
- u64 seed, eight u64 k0…k7;
- i32 mode (0 ordinary; 1 guard load; 2 guard store), i32 accessible prefix bytes;
- u32 expected memory fault (0/1).

Then name UTF-8, guest code, input vectors2048, input mapped-memory window256,
expected vectors2048, expected mapped-memory window256. Vector layout:
register0…31, 64 bytes each, low128 then ymm_hi128 then zmm_hi256. Normal RBX
is the window start; RDI is window+128. Window is the final256 bytes before a
protected page. In guard mode the relevant pointer is boundary-prefix_bytes.

For expected-fault records, output vectors/partially written memory are retained
as measurements where available but **not checked as architectural expectations**.
An unsupported instruction is not an expected memory fault.

## HBFL0001

File: ASCII magic `HBFL0001` (8), u32 record count.

Record fixed header, Python struct `<HHQ7Q7Q7Q`:
- u16 name length, u16 guest-code length, u64 seed;
- seven u64 input fields; seven u64 hardware output fields;
- seven u64 comparison masks.

Then UTF-8 name, guest-code bytes, initial memory64 bytes.
Seven-field order: RAX,RDX,RCX,R8,R9,RBX,RFLAGS. The last compare mask contains only
normatively defined status bits. Other registers may have zero masks when ISA
says their result is undefined. Hardware values of those bits remain recorded.
R8 records the chosen branch/CMOV/SET result, captured before flags materialization.

## Tools

`tests/hb_absolute/corpus.py` is the reference strict reader. `replay_shards.py`
feeds decompressed shards to the corresponding binary, saves stdout/stderr, checks
nonempty/exact record counts for an unfiltered run, and preserves nonzero statuses.
Archives containing different shard ranges can be extracted into one directory.
Do not concatenate gzip streams and pretend they are one corpus with one header.
