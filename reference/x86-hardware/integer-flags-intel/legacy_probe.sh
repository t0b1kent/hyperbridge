#!/bin/sh
# SPDX-License-Identifier: MIT
# Explicit platform gap, NOT a native compatibility test or measurement.
set -eu
printf '%s\n' 'Native i386 execution unavailable: NOT_ATTEMPTED_MACOS_NO_ELF32_ABI' \
 'The original legacy32.S uses Linux ELF/i386 syscalls and is not run on macOS.' \
 'Class 11 DAA/DAS/AAA/AAS/AAM/AAD had no measurement generator in 0002 and still has zero rows.'
exit 77
