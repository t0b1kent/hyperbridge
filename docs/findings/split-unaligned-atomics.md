# Split unaligned atomics can lose updates

## Measured

October 5, 2026, original synthetic RMW probes. Thirty fault/restart cases with a handler replacing the operand produced nine memory and twelve state mismatches; repeating without replacement was clean in 30/30. A native hardware [part-A reference](../../reference/x86-hardware/write-fault-rmw-part-a/README.md) supplies 264 measured page-cross cells, repeated identically, with no partial write and the resumed operation using the handler's replacement value.

In a two-thread Wine probe, `lock add word [m],1` at offset 15 across a 16-byte boundary, 1,000 increments per thread, r5 returned 1,996–2,000 instead of 2,000. Ten runs per arm: lost updates in 5/10 on r5, 8/10 on the candidate with its key off and 0/10 with its key on. A separate direct-helper matrix reported 22/72 passing before and 72/72 after the candidate.

## Conclusion

Splitting the operation can retain stale Expected/Desired state across a lower-half fault or intervening update. The audited DoCAS path could return early after an upper-half success instead of recomputing and completing one architectural operation.

## Limits

The hardware submission's separate two-thread part B was unfinished and is excluded. Ten translated runs do not prove all concurrency schedules, widths or address boundaries. No conclusion about a protected application's failure follows from these synthetic measurements.

## What would refute it

A correct control repeatedly yielding exactly 2N with the same split geometry, or any wrong result/state/restart/conservation behavior with the candidate enabled.

## Where it is fixed in our series

Candidate **0200–0203**, `MACRUNNER_FEX_SPLIT_ATOMIC_EXACT`, passed the recorded controls; the wider family work was numbered **0200–0209**. These are outside released 1.0.8 and default off. Full family concurrency and exception validation remain separate requirements.
