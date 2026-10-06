# wineboot self-name lookup can delay startup

## Measured

October 4, 2026, macOS 26 M2 Pro cloud VM. Instrumented `create_computer_name_keys` followed gethostname with getaddrinfo of the local name, AI_CANONNAME. One diagnostic capture placed 35.009 seconds in that call, with mDNS A/AAAA requests and network-privacy denial indications. Native name lookup took 6–10 ms and Wine's A-only ping took 0.19 s.

Four cold-start observations before the wineboot-only replacement were 36.04/35.81/35.82/35.75 s; four with patch 0092 were 0.78/0.87/0.91/0.89 s. Prefix creation changed from 40.2–40.9 s to 6.23 s. On the local host the lookup was about 3 ms, so the delay was not universal.

## Conclusion

Network canonical-name lookup was an avoidable startup dependency in the measured environment. Deriving local computer/domain names from gethostname removed that wait in the recorded control.

## Limits

One cloud machine class and its privacy/network state. The privacy-log correlation does not measure every user permission state or establish a universal 35-second delay. No host names or network/environment dumps are published.

## What would refute it

The same machine/configuration remaining slow after only this replacement, or a trace locating the delay outside the call.

## Where it is fixed in our series

Wine patch **0092** removes this lookup while retaining the intended name formatting. It is a MacRunner Wine change shipped with 1.0.8, not a patch in the common FEX chain.
