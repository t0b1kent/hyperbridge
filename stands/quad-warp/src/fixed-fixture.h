// SPDX-License-Identifier: MIT
// Exact public quad-cross outputs at UV (0,1),(0,0),(1,0),(1,1).
#ifdef __METAL_VERSION__
#define FIXED_WORDS constant uint
#elif defined(__cplusplus)
#include <cstdint>
#define FIXED_WORDS constexpr uint32_t
#else
#define FIXED_WORDS static const uint
#endif
FIXED_WORDS FixedPositions[4][4] = {
    {0xbf600000,0x3f600000,0,0x3f800000},
    {0xbf600000,0xbf600000,0,0x3f800000},
    {0x3f600000,0xbf600000,0,0x3f800000},
    {0x3f600000,0x3f600000,0,0x3f800000}
};
FIXED_WORDS FixedColors[4][4] = {
    {0,0,0x3e800000,0x3f800000},
    {0,0,0x3e800000,0x3f800000},
    {0,0x3f800000,0x3e800000,0x3f800000},
    {0x3f800000,0x3f800000,0x3e800000,0x3f800000}
};
FIXED_WORDS FixedIndices[6] = {1,2,0,0,2,3};
#undef FIXED_WORDS
