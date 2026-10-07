# Code-store stand: what a real x86 processor does when a store modifies code that is about to run

A small native Linux x86-64 probe. It writes 1, 2, 4 or 8 bytes (aligned and unaligned) into code at several
distances from the storing instruction — the rest of the storing instruction itself, the next instruction, +16 bytes,
+64 bytes (another cache line), the next page — and then reaches the modified bytes by falling through, by `jmp`, or
by `call`/`ret`, with and without a serializing instruction in between. The code is mapped either as one RWX region
or as an RX view plus a separate writable view of the same pages. One more cell stores 4 bytes across a page boundary
whose second page is read-only and records which bytes were written when the fault arrived.

Each executable cell is repeated 1000 times; `summary.tsv` has one row per cell (old marker / new marker / faults).

## Results so far

| Processor | Environment | Result |
|---|---|---|
| AMD EPYC 9V74 (Zen 4) | Linux 6.18, KVM guest | 352 cells measured, two full runs identical |
| AMD Ryzen 9 9900X (Zen 5) | Linux 6.8, bare metal | byte-identical `summary.tsv` and `layout.tsv` to the EPYC run |

In all 266,000 executions of a *future* instruction the new bytes ran, serialized or not. In all 84,000 stores into
the tail of the *current* instruction the instruction completed with its original decoding. In all 2,000 stores
split 2+2 across a page boundary with a read-only second page the processor faulted and none of the four bytes had
been written.

An x86 → ARM64 translator has to reproduce exactly this, including on hosts whose page is larger than the guest's.

## Running

```sh
sh run.sh out      # needs cc, gzip, sha256sum, timeout; no privileges, no network
```

The workflow `stand-code-store-linux-x86.yml` runs the probe on GitHub's Linux runners and uploads the tables together
with the processor identification, so results from Intel processors can be added when a runner has one.

The probe is MIT-licensed original code (see the SPDX header in `probe.c`).
