#pragma once
#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

// Owned mappings may be adjacent. A watch must be covered by their union,
// including every byte; a gap or arithmetic overflow is never admitted.
template<typename Ranges>
bool oracle_range_covered(uint64_t start, uint64_t length, const Ranges& ranges) {
  if (length > UINT64_MAX - start) return false;
  const uint64_t end = start + length;
  while (start < end) {
    uint64_t covered = start;
    for (const auto& [base, size] : ranges) {
      if (size <= UINT64_MAX - base && base <= start && start < base + size)
        covered = std::max(covered, std::min(end, base + size));
    }
    if (covered == start) return false;
    start = covered;
  }
  return true;
}
