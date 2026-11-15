// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// One process policy shared by both unix halves. 0=software, 1=both, 2=hardware.
// The first call decides before JIT creation. Later failed admissions terminate.
uint32_t macrunner_hwtso_admit(void);
// Same admission policy, with one bounded identity/entry receipt per native
// guest thread. No syscall repetition, stdio, TLV or loader initialization.
uint32_t macrunner_hwtso_admit_entry(uint32_t kind, uint32_t windows_pid, uint32_t windows_tid);
// 1 only when MACRUNNER_FEX_APPLE_AFP=1 was requested, hardware TSO admission
// succeeded and Apple AFPCR (s3_6_c15_c2_5) was read on that admitted thread
// under a temporary SIGILL guard. Every later guest thread must pass the same
// admission or the process terminates, so the decision holds for shared JIT code.
uint32_t macrunner_hwtso_apple_afp(void);
#ifdef __cplusplus
}
#endif
