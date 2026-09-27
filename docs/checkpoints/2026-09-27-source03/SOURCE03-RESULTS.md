# First matched decoder-source measurement

2026-09-27, M1 Pro, Hollow Knight1.5.12620, 1280×720. Provider:
`21e2c62d418e6144bbf024625588180a160118535f69426051389efa2094ca99`.
Same provider, input pins, graphics pins, saved-English prefix template and
runner in both arms. Only requested environment difference:
`MACRUNNER_HB_DECODED_SOURCE=0` versus`1`. FAST1019, exact1/lazy1/prune1,
stats0 stayed fixed. All agents were CPU-quiet during both observations.

| Arm | Run | Last-window frames | Seconds | FPS |
|---|---|---:|---:|---:|
| Legacy decoder-window span | hk-m5mqwtjx | 2270 | 59.541 | 38.124990 |
| Frozen consumed-source prefix | hk-g5keb7eb | 2786 | 59.408 | 46.896041 |

Relative difference:+23.006%. FPS is cumulative presented-frame delta divided
by elapsed HUD time, not an average of instantaneous FPS. Each run lasted180s,
stopped at the intended observation timeout, verified the HB backend and
unchanged inputs, drained its processes and removed its owned Wine prefix.
Logs/registries/results remain in the run directories.

Limitations: one matched pair; the menu scene is inferred from the saved English
prefix and Player.log and was not visually reconfirmed. This is preliminary
performance evidence, not statistical significance, full-game parity or120FPS.
The separate FEX menu reference remains117.6157FPS. This candidate retains the
conservative ban on unguarded mutable chains; the old unsafe FAST507 performance
is not its comparison baseline.

Correctness before measurement:516 native cases in each gate state, all focused
provenance cases, CTRL2 supported520/520 for each architecture and Wine8/8.
Detailed scope is in SOURCE03-REVIEW.md. The native-entry guard is a different,
unpromoted prototype and was not present in this provider.

Next: diagnostic byte/budget counters to verify the eliminated work; complete
actual native route/descriptor tests; repeat matched performance after the next
eligible integration. Keep the default source gate off until workload and
remaining adversarial checks finish.
