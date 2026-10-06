# Execution notes

The existing native code selector worked immediately. No `modify_ldt` call, ELF32 loader, emulator, package installation, external source, privilege escalation or security-setting change was used. The previous task 0002 ELF32 exec rejection (errno 8) is separate from this successfully measured ring-3 compatibility path.

All temporary executables, generated assembly, early test logs and raw/intermediate streams are in the excluded `build/` directory. The delivered `out-*.txt.gz` files are the unedited stdout of the native measurement executable.

The reference models for defined bits and the counted empirical models are deliberately distinct. In particular: DAA/DAS OF, AAA/AAS OF/SF/ZF/PF, AAM/AAD OF/AF/CF, SHL AF/multi-count OF and upper bits written by segment PUSH are preserved as hardware observations rather than overwritten by a portable assumption. SALC is undocumented and its equation is explicitly empirical.

The bridge was strengthened during development from ordinary ABI preservation to full general-register/RFLAGS/DS/ES restoration and then remeasured. Its separate sentinel check covers both its ordinary exit and the original-TLS-base restoration path. Fixed-address scratch uses MAP_FIXED_NOREPLACE, so an existing mapping is never overwritten. Existing FS/GS bases are queried only to restore the same thread state after the requested segment POP instructions; their values are never written to result files.

The initial candidate guesses that SHL clears AF or uses the original top-two-bit XOR for all counts were falsified by real rows. The final counted rules instead report AF=1 for nonzero masked counts and OF=sign(final result) XOR CF for counts greater than one, agreeing with this CPU's previously measured 0002 behavior. No result row was edited to fit a rule.
