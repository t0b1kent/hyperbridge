# Low 4 GiB mappings depend on process signing on macOS Arm

## Measured

September 8, 2026, original native constructor probe inside a loader process on Apple Silicon. One documented signed/unsigned pair: the properly entitled signed loader process mapped address 0x400000 and wrote/read it; the unsigned control failed with errno 12. The effective capability involved `com.apple.developer.cross-architecture-support` and the provisioning profile. No third-party loader bytes or disassembly are included.

## Conclusion

The unsigned failure did not demonstrate an unconditional kernel ban on all low-address mappings. Process admission/signing state is part of the measurement and of native 32-bit support.

## Limits

This is one documented pair, not a public entitlement availability guarantee or validation of every low address, loader or OS version. The capability's issuance policy and future availability were not measured. No certificate, team or profile identifiers are published.

## What would refute it

A correctly admitted same-process test unable to map/read/write the address, or an unsigned control succeeding under otherwise identical page-zero and mapping conditions.

## Where it is fixed in our series

This boundary is handled by the loader's signing/provisioning configuration, not a numbered translator opcode patch. There is no released translator patch that makes an unadmitted process acquire the entitlement. **0070/0071** in the WOW64 chain concern the translator path and are not substitutes for this admission check.
