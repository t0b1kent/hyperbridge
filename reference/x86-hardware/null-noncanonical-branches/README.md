# Null and noncanonical branch targets

Measured October 3, 2026 on AMD EPYC 9V74 in a native Linux x86-64 cloud VM. Section A was accepted independently of the unavailable Wine section B. Two captures of 50 normalized cells match byte-for-byte. Forty canonical unmapped targets raised #PF (error 0x14) at the target; CALL had already pushed its return address. Ten noncanonical targets raised #GP at the branch instruction; the branch had not completed.

`a-native.tsv` and `a-native-repeat.tsv` are normalized text records, with operand width, branch form, target, signal, trap number/error, instruction/stack location and return-stack evidence. They have no header. `a-native-noncanonical.tsv` is the ten-cell slice. ASLR-dependent raw addresses were normalized by the original probe; the tables are copied without further edits. Sources and result hashes are listed in MANIFEST.json.

Reproduce on native Linux x86-64 with GCC, Python 3 and binutils: `bash commands-a.sh`, then `python3 a-native-validate.py`. The script builds its own temporary ELF and collects two new captures before validating them. It also produces local mappings/context diagnostics; these diagnostics and the original compiled probe are excluded from this publication.

The VM exposes a hypervisor. This establishes observed processor/kernel behavior; it does not independently establish Windows exception parameters. Compare the separate [native Windows reference](../../windows-x64/2026-10-06/README.md) for Windows delivery. The unsuccessful Wine runs and all unfinished section B material are excluded. Original probe and notes are MIT licensed; see a-native-LICENSE.
