# Thread priority sweep: how much work a thread gets done at each Windows base priority 1-15

A reference stand. For each nominal base priority 1-15 (one documented process class / thread level pair per base) the probe
measures how many fixed work blocks a pinned worker completes in three conditions: alone; with busy normal-priority processes
on every other processor; with busy normal-priority processes on every processor including its own. The result is reported as
a share of a normal-priority worker running alone on the same machine, together with the worker's own CPU time.

The workflow builds the probe with a pinned llvm-mingw on `windows-2022` and `windows-2025`, runs the default sweep (about nine
minutes) and keeps the raw JSONL, the checker summary and the built program as the job artifact. The REALTIME priority class
is never used; every helper process is the probe's own and is confined to a kill-on-close job object.

`DESIGN.md` describes the method and `MAPPING.md` the documented priority table. The probe was prepared with AI assistance as
a diagnostic; it is not Wine code.
