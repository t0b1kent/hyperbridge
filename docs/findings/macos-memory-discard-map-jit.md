# macOS memory discard and MAP_JIT protection

## Measured

October 5, 2026, M1 Pro host with 16,384-byte pages; one retained standalone native probe capture. On a 1,048,576-byte private anonymous mapping filled with 0xA5, MADV_DONTNEED returned success and retained all 1,048,576 bytes; MADV_FREE did likewise. MAP_FIXED anonymous remapping at the same address cleared all bytes. On the last MAP_JIT page, mprotect to PROT_NONE and PROT_READ both failed with errno 13; the same PROT_NONE operation on an ordinary anonymous mapping succeeded. [Probe and exact text output](evidence/README.md) are included.

## Conclusion

A successful discard advisory is not evidence of synchronous zeroing on this measured macOS. A guard computed in bytes is not evidence of an installed protection on MAP_JIT memory. Both return values and observed bytes matter.

## Limits

One system/capture and these exact mapping/protection flags. This does not show that every MAP_JIT protection change is impossible, or that released Wine cache reset has the native runner's problem. The suspected stale-cache crash mechanism was not proven by this memory probe.

## What would refute it

A same-system repetition reliably zeroing the tested mapping, or successfully installing the tested last-page protection, would refute the corresponding observation.

## Where it is fixed in our series

No released patch fixes the native runner's discard/protection semantics. **0161** sizes the guard using the host page; it does not make rejected mprotect calls succeed. Native cache zeroing and guard installation still require separate validation.
