# Documented nominal base mapping

The table is a transcription of numeric API behavior, not runtime observations. Level names below are the suffixes of `THREAD_PRIORITY_*`; row names are the prefixes of `*_PRIORITY_CLASS`.

| Process class | IDLE (-15) | LOWEST (-2) | BELOW_NORMAL (-1) | NORMAL (0) | ABOVE_NORMAL (+1) | HIGHEST (+2) | TIME_CRITICAL (+15) |
|---|---:|---:|---:|---:|---:|---:|---:|
| IDLE | 1 | 2 | 3 | 4 | 5 | 6 | 15 |
| BELOW_NORMAL | 1 | 4 | 5 | 6 | 7 | 8 | 15 |
| NORMAL | 1 | 6 | 7 | 8 | 9 | 10 | 15 |
| ABOVE_NORMAL | 1 | 8 | 9 | 10 | 11 | 12 | 15 |
| HIGH | 1 | 11 | 12 | 13 | 14 | 15 | 15 |

Union: every integer 1–15. No union gaps. Per-class gaps:

- IDLE: 7, 8, 9, 10, 11, 12, 13, 14
- BELOW_NORMAL: 2, 3, 9, 10, 11, 12, 13, 14
- NORMAL: 2, 3, 4, 5, 11, 12, 13, 14
- ABOVE_NORMAL: 2, 3, 4, 5, 6, 7, 13, 14
- HIGH: 2, 3, 4, 5, 6, 7, 8, 9, 10

Default canonical sweep:

| Nominal base | Process class | Thread level |
|---:|---|---|
| 1 | NORMAL | IDLE |
| 2 | IDLE | LOWEST |
| 3 | IDLE | BELOW_NORMAL |
| 4 | IDLE | NORMAL |
| 5 | IDLE | ABOVE_NORMAL |
| 6 | BELOW_NORMAL | NORMAL |
| 7 | NORMAL | BELOW_NORMAL |
| 8 | NORMAL | NORMAL |
| 9 | NORMAL | ABOVE_NORMAL |
| 10 | NORMAL | HIGHEST |
| 11 | ABOVE_NORMAL | ABOVE_NORMAL |
| 12 | ABOVE_NORMAL | HIGHEST |
| 13 | HIGH | NORMAL |
| 14 | HIGH | ABOVE_NORMAL |
| 15 | HIGH | HIGHEST |

TIME_CRITICAL appears in the complete matrix and optional all-pairs sweep, but is not needed to reach base15. REALTIME_PRIORITY_CLASS is never used. Different pairs with the same base need not have identical non-CPU behavior; the default does not claim to have measured every pair. Dynamic priority, quantum duration, priority boosts and unrelated scheduler policies are not inferred from this table.

Primary documentation, checked 2026-10-11:

- [Scheduling priorities and full base table](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities)
- [GetThreadPriority: relative priority value](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriority)
- [GetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass)
- [Priority boosts](https://learn.microsoft.com/en-us/windows/win32/procthread/priority-boosts)
- [GetThreadTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadtimes)
- [Processor groups](https://learn.microsoft.com/en-us/windows/win32/procthread/processor-groups)
- [GetProcessDefaultCpuSets](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessdefaultcpusets)
- [Job kill-on-close limit](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
