// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
#include <mach/mach_time.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>


#define HB_CLOCK_IMPL() mach_absolute_time()
#define HB_FREQ_IMPL() 24000000ULL
#define HB_SOURCE "replay"
#define HB_PID_SPACE "unix"
#define HB_PID() ((uint64_t)getpid())
static void* hb_replay_alloc(size_t n) {
  void* p = mmap(nullptr, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  return p == MAP_FAILED ? nullptr : p;
}
#define HB_ALLOC(n) hb_replay_alloc(n)
#define HB_SINK(s) fputs(s, stderr)
#include "Interface/Core/hb_native_impl.h"
extern "C" void hb_native_start_watcher(void) {}
