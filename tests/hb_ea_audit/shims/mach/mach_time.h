#ifndef TEST_MACH_TIME_H
#define TEST_MACH_TIME_H
#include <stdint.h>
#include <time.h>
static inline uint64_t mach_absolute_time(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec; }
#endif
