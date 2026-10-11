<!-- SPDX-License-Identifier: MIT -->
# thread-perfcount

A small Windows probe for one question: what does `NtQueryInformationThread` do for information class 11
(`ThreadPerformanceCount`)? It calls the function with different buffer lengths, buffers, return-length pointers and thread
handles, each case in its own process, and prints what came back: the status, the bytes left in the buffer and the value
left in the return length. Nothing is asserted and no expected values are encoded. The workflow builds it with a pinned
toolchain as a 64-bit and a 32-bit program on `windows-2022` and `windows-2025` and uploads the output.

The probe source was prepared with AI assistance as a diagnostic; one enum constant was renamed so that it does not collide
with a macro from the Windows headers.
