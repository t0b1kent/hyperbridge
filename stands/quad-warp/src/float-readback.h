// SPDX-License-Identifier: MIT
#pragma once
#include <cmath>
// Clear alpha is zero. This synthetic corpus produces nonzero alpha on every
// covered sample; the observer independently checks this inference. Never
// change target bytes or require the interpolator to preserve alpha exactly.
inline bool readback_alpha_valid(float alpha) { return std::isfinite(alpha); }
inline bool readback_alpha_covered(float alpha) { return alpha != 0.f; }
