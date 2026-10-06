# Notes

- No packages were installed and no external source code was used. Supplied tasks, run-pending.sh and PROTOCOL.md were not edited
- The CPU advertises a hypervisor. Results come from native x86 instructions executed in the Linux VM, not from a software instruction emulator
- The updated TASK requirement for payloads distinguishable after quieting is implemented for binary16/32/64. Early partial snapshots are superseded by corrected results
- All advertised implemented features were available. The preflight refuses unsupported native CPU/OS configurations; its EVEX register-capture implementation also requires AVX512BW
- Independent result review checked checksum/count/format, preserved native trap destinations and MXCSR, scalar high lanes, NaN identity after quieting, SAE suppression, zero-mask suppression, and instruction encoding classes. The included validation tools provide reproducible checksum/count/size and assembler/disassembler checks
