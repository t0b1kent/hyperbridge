# Cost of suspension polls around CALL/RET

## Measured

October 5, 2026, native ARM64 microloop on the project Mac, using original generated instruction bytes, not a running translator. 41 fixtures; 82/82 functional checks and 369 state/count/SP samples passed. Timing used 20 million iterations, warmup, A/A control and three alternating 0/2 pairs. With compatibility mode enabled: two LDR/CBZ polls 2.259606 ns; both removed 1.604048 ns; both replaced by STR XZR to a separately mapped 16 KiB doorbell page 1.603094 ns. A/A variation for the store variant was 2.036%. These are CPU nanoseconds, not core cycles.

## Conclusion

For this fixed matched-return loop, replacing polling loads/branches by writes predicts about 29% less time, and the store cost was within the measured noise of no polls.

## Limits

DIAGNOSTIC_ONLY / NOT_GOLDEN. The doorbell page remained writable: actual fault handling, Windows suspend/SEH and lost-wakeup behavior were NOT_ENABLED. The return stack was prefilled; fallback behavior was not exercised. This is a microloop forecast, not an application result.

## What would refute it

A repeat with store cost above twice A/A noise, a missing safe point, wrong precise state, a lost resume or a false fault accepted as suspension.

## Where it is fixed in our series

Candidate `MACRUNNER_FEX_EC_FAULT_DOORBELL` was proposed; no accepted numbered released fix at the snapshot. **0052-port** supplies the earlier page/address layout in the separate WOW64 chain. Normal-path timing alone does not qualify a suspension implementation.
