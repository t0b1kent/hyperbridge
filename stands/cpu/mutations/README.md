# Own code-generation mutation insertions

`codegen-setup.inc` is inserted before the IR-node loop; `codegen-body.inc` goes inside that loop before ordinary opcode dispatch. They are our additions from the stage-4 mutation source; the upstream FEX file and its surrounding code are excluded. Integrate against the compatible external engine after reviewing its APIs.

`STAND_CODEGEN_MUTATION` selects `flags`, `sign_extend`, `operand_width`, `store_omitted`, `register_write_omitted` or `sse_rounding`. Each changes emitted ARM64 instructions and logs activation. Run an unchanged baseline first and require an EQUAL result for the same input, activation evidence, then failure through the unchanged comparison/gate. Zero activation is NOT_ENABLED, not a successful negative control.

The original `mutation_controls.py`/`quick_mutations.py` select triggers from private inputs and require an explicitly prepared mutant runner. Their private evidence is omitted. The own insertion can instead be exercised by your own programs with the six corresponding instruction patterns.

Stage 6 also includes the own status-mutant frontend and `negative_controls.py` for extra ZE / lost input PE. Those are post-execution state mutations, a different scope from JIT mutation. Its input-selection script needs your corresponding frozen input and baseline; no such recording is distributed.
