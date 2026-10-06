# Guest 4 KiB permissions on a 16 KiB host

## Measured

October 3, 2026, STAND-DIFF synthetic page/access probes on the 16 KiB-page macOS host. A write into a guest read-only 4 KiB page completed without a fault; ReadProcessMemory read 32 bytes through guest NOACCESS. The cross-host-page CAS matrix had three SEH-delivery failures in 105 cells. This is one retained matrix result; the summary does not report additional repetitions. A source audit found `get_host_page_vprot` combining the four guest permissions with a union.

## Conclusion

The union can give a guest subpage permissions it does not have. Correct host-page protection alone cannot reproduce four distinct guest protections; translation and Wine memory APIs need a consistent guest permission check.

## Limits

These are synthetic access/exception observations, not proof of a particular application's failure. Uniform host pages and mixed-permission pages have different requirements. No performance result establishes the proposed complete implementation.

## What would refute it

The same mixed-permission cells delivering exact guest faults and enforcing NOACCESS without bypassing the guest checks would refute the observed gap.

## Where it is fixed in our series

No complete released fix. **0072–0074** are candidate continuation/ownership interfaces, not proof of end-to-end protection. Released **0005/0007/0161** accommodate host-page granularity in other mechanisms; they do not close this permission gap.
