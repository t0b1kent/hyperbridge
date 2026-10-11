<!-- SPDX-License-Identifier: MIT -->
# retlen

A small Windows probe: when `NtQuerySystemInformation`, `NtQueryInformationProcess` or `NtQueryInformationThread` is called
with an information class that does not exist, is the caller's `ReturnLength` written? The probe pre-fills `ReturnLength` and
the buffer with a pattern, makes the call with a few undefined class numbers and three buffer shapes, and prints one line per
call: the status, the value left in `ReturnLength`, and how many buffer bytes changed. Nothing is asserted. The workflow builds
it with a pinned toolchain as a 64-bit and a 32-bit program on `windows-2022` and `windows-2025` and uploads the output.
