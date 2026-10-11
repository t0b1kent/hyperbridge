# Windows priority throughput probe: review contract

Source-only C11 experiment, Windows x64. No Wine changes, no Windows execution here, no disassembly.

## Nominal priorities

Microsoft's Scheduling Priorities table establishes the following nominal base priority matrix (columns: IDLE, LOWEST, BELOW_NORMAL, NORMAL, ABOVE_NORMAL, HIGHEST, TIME_CRITICAL):

- IDLE: 1, 2, 3, 4, 5, 6, 15
- BELOW_NORMAL: 1, 4, 5, 6, 7, 8, 15
- NORMAL: 1, 6, 7, 8, 9, 10, 15
- ABOVE_NORMAL: 1, 8, 9, 10, 11, 12, 15
- HIGH: 1, 11, 12, 13, 14, 15, 15

All 1–15 are reachable in the union. The probe will enumerate all 35 mappings and explicitly identify gaps within individual classes. Default: one canonical pair per nominal base 1–15. Optional --all-pairs: all 35. The label is nominal/documented base, not measured instantaneous dynamic effective priority. GetPriorityClass and GetThreadPriority verify the configured class and relative level only.

## Process isolation and placement

NORMAL-class/NORMAL-thread outer supervisor, one fresh NORMAL controller process per condition; one separate worker process; zero, N−1, or N separate NORMAL-class/NORMAL-thread competitor processes. No changing priorities of unrelated processes. All children start suspended, are assigned to a new kill-on-close Job object, then resumed. Only each owner holds its Job handle: the outer supervisor owns a containing Job for the condition controller and all descendants; the condition controller owns a nested Job for its worker/helpers. Neither Job handle is inherited. The outer supervisor applies a per-condition wall deadline and checks the containing Job has zero active processes at cleanup. Configuration failure or timeout fails the run and tears down only owned children.

Detect process and thread group/affinity, system active processor groups, and allowed process mask. Refuse every multi-group system and explicit CPU Set selections. Require exactly four allowed CPUs by default; an explicit --expected-cpus setting accepts 2–8. Select one worker CPU in the verified allowed mask (default least significant bit). Pin each competitor to one allowed CPU. The controller's main sampling thread is pinned to the other allowed CPUs. Therefore “all CPUs” means all N allowed logical CPUs within the selected group; machine-wide coverage is never inferred. Log masks, group counts and selected processor indices. Read both process default and thread selected CPU Sets; fail rather than clear a selected restriction.

Conditions: alone; one_free (one competitor on every allowed CPU except the pinned worker CPU); all_busy (one competitor on every allowed CPU, including the worker CPU). No monitor-only reserved CPU in all_busy; the monitor shares NORMAL competitors' CPUs and its overhead is disclosed. Busy logical siblings can affect physical-core throughput even when worker CPU is free.

## Timing and observations

Identical checksum-dependent, compiler-resistant fixed work blocks for worker and competitors. Shared slots occupy separate cache lines. Atomic shared progress after each completed block; QPC checked every bounded block. Each helper self-terminates at a shared wall-clock deadline; controller also applies a timeout and closes/terminates its owned Job on failure. No REALTIME process class, privilege adjustment, global scheduler/timer/power settings, priority-boost changes, foreign processes, or forceful system cleanup.

Startup readiness barrier and common QPC warmup/start/end timestamps. Default warmup 500 ms. Low-priority starvation during warmup is possible and recorded, not hidden. Default duration: 3 s alone, 3 s one_free, 20 s all_busy. Samples are nominally every 100 ms in every condition. Actual QPC collection times, lateness, total/delta block count and actual interval duration are logged; delayed wakeups are not fabricated as on-time samples. Do not interpolate samples into scheduler events or claim exact quantum length. Record all-busy zero-progress intervals, coarse 0→positive bursts and maximum observed gaps as sampling observations only.

GetThreadTimes separately measures worker CPU seconds. Counter throughput / interpolated adjacent NORMAL-alone baselines is a throughput ratio, not literal CPU share. CPU marker delta / common window seconds is a separate approximate utilization estimate. Marker intervals can start late/end after the window; their QPC brackets are retained. Missing markers yield null CPU delta/utilization, including a never-started worker, because a warmup block may have crossed the boundary. Resolution/rounding limits are explicit. Interleaved reference baselines before and after each tested priority enable drift inspection. Absolute counts, wall times and QPC frequency remain in raw JSONL so alternate analyses are possible.

Readbacks for worker and every competitor are checked before release and captured afterward. Job teardown is verified. Delayed/skipped nominal sample deadlines are observations, not automatically errors. Any setting failure, missing readiness, child failure, invalid baseline, impossible timing, output failure, corrupt/lost records or timeout is visible in structured records and a nonzero exit, rather than a nominal successful result.

## Primary references

- https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadtimes
- https://learn.microsoft.com/en-us/windows/win32/procthread/processor-groups
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
