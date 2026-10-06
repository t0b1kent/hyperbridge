# Wide loads cost more under hardware TSO on M1

## Measured

October 4, 2026, M1 Pro. Original ARM64EC loops executed natively inside a compatibility-mode Wine thread; each instruction-loop form sampled five times. The mode controls were recorded as HW_TSO=2 and HW_TSO=0. Four-Q `ld1` measured 0.42 → 13.2 ns; the save/restore-style sequence 3.3 → 58 ns; `stp q` + `ldp q` 1.6 → 6.6 ns. A second probe separated forms: `ldp q`/`ldnp q` cost about 4.4 ns per pair; `ld1` ×2/×3/×4 about 4.4/8.8/13.1 ns. Single `ldr q`, one-register `ld1`, stores and tested GPR pairs did not show that penalty. Copying 4 KiB with Q pairs cost about 846 ns; two single-Q loads plus a paired store cost 53.8 ns.

An M2 Pro cloud-VM control, with compatibility-mode memory ordering separately checked, did not show the M1 penalty: reported ratios were about 1.00×, CRT copy 55.7 ns. The retained summary does not specify that control's repetition count. [Original native loops](evidence/README.md) are included.

## Conclusion

On the measured M1, replacing wide loads with single-Q loads avoids a large mode-dependent cost. The M2 control prevents generalizing it to all Apple Silicon.

## Limits

These are nanoseconds in specific microloops, not core cycles or application FPS. Store-forwarding overlap is another measured source of cost. M3/M4 were not tested; the original numeric mode labels alone are not a direct ACTLR read.

## What would refute it

Matched, physically admitted mode controls on the same chip showing no wide-load penalty, or a correctness/speed failure of the single-Q replacement.

## Where it is fixed in our series

Released **0160** changes the relevant hardware-TSO load paths, including LD4 lowering. **0055** enables the mode. **0161** separately repairs code-buffer guard sizing; it is not the cause of the load penalty.
