probes stand: new_probes.c (0090 new probes, 122 cells), source byte for byte from the submission, SHA-256 83d2307fae0083fd6c5143b5b023d98a42990bf3ff4c173bb505b0979ead5f3d.
Allowed arguments only: list | cell N | range A B | all. The working directory of every run is the output directory: the program creates and removes its own one-time
subdirectories `0090-owned-<pid>-<tick>-<n>\probe.bin` there (16 cells). No network, no registry, no other processes, no direct system calls (see SOURCE-REVIEW).
Build is the command from the submission README: x86_64-w64-mingw32-gcc -std=c11 -O1 -Wall -Wextra new_probes.c -o new_probes.exe (llvm-mingw 20260505, pinned by SHA-256 in the workflow).
