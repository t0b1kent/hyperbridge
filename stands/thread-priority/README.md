# Idle-priority threads next to busy threads: what Windows does

A small reference stand. The probe starts one worker thread and a number of waiting threads of a higher priority, lets them
run for a fixed time and prints how many loop steps the worker completed. Phases: the worker alone at normal and at idle
priority; an idle worker next to busy threads on all but one processor and on all processors; an idle worker next to threads
that yield with `SwitchToThread` or `Sleep(0)`.

The numbers are compared as a share of the "normal, alone" phase on the same machine. The workflow builds the probe with a
pinned llvm-mingw on `windows-2022` and `windows-2025` and keeps the output and the built program as the job artifact. The
probe was prepared with AI assistance as a diagnostic; it is not Wine code.
