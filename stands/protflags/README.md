<!-- SPDX-License-Identifier: MIT -->
# protflags

A small Windows probe: which combinations of a base page protection with `PAGE_GUARD`, `PAGE_NOCACHE` and `PAGE_WRITECOMBINE`
are accepted by `VirtualAlloc` (reserve+commit, reserve only, commit inside a reservation), `NtAllocateVirtualMemory`,
`VirtualProtect`, `NtProtectVirtualMemory` and `NtMapViewOfSection`. One line per call with the result and the error or status;
nothing is asserted. The workflow builds it with a pinned toolchain on `windows-2022` and `windows-2025` and uploads the output.
