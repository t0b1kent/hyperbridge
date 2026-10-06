# SPDX-License-Identifier: MIT
# Copyright (c) 2026 OpenAI
"""Original x86-64 vector-store cases for the native write-fault probe.

Instruction bytes were independently assembled with GNU as --64 and checked
with objdump -d -Mintel.  Every memory destination is [rdi], including the
implicit destination of MASKMOVDQU.  Byte strings use instruction byte order;
mask strings give XMM1 bytes from the least-significant byte upward.

The harness must initialize XMM0/YMM0 and apply the optional XMM1 mask. AVX
execution additionally requires CPU AVX, OSXSAVE and XCR0 XMM+YMM enablement.
"""


def forms():
    """Return fresh case dictionaries; width is the full destination span."""
    cases = [
        dict(name="movups_m128_xmm0", width=16, code="0f1107", legal=True, feature="sse2"),
        dict(name="movdqu_m128_xmm0", width=16, code="f30f7f07", legal=True, feature="sse2"),
        dict(name="movaps_m128_xmm0", width=16, code="0f2907", legal=True, feature="sse2", alignment=16),
        dict(name="movdqa_m128_xmm0", width=16, code="660f7f07", legal=True, feature="sse2", alignment=16),
        dict(name="movss_m32_xmm0", width=4, code="f30f1107", legal=True, feature="sse2"),
        dict(name="movsd_m64_xmm0", width=8, code="f20f1107", legal=True, feature="sse2"),
        dict(name="movq_m64_xmm0", width=8, code="660fd607", legal=True, feature="sse2"),
        dict(name="movd_m32_xmm0", width=4, code="660f7e07", legal=True, feature="sse2"),
        dict(name="movlps_m64_xmm0", width=8, code="0f1307", legal=True, feature="sse2"),
        dict(name="movhps_m64_xmm0", width=8, code="0f1707", legal=True, feature="sse2"),
        dict(name="pextrb_m8_xmm0_0", width=1, code="660f3a140700", legal=True, feature="sse4_1"),
        dict(name="pextrb_m8_xmm0_15", width=1, code="660f3a14070f", legal=True, feature="sse4_1"),
        dict(name="pextrw_m16_xmm0_0", width=2, code="660f3a150700", legal=True, feature="sse4_1"),
        dict(name="pextrw_m16_xmm0_7", width=2, code="660f3a150707", legal=True, feature="sse4_1"),
        dict(name="pextrd_m32_xmm0_0", width=4, code="660f3a160700", legal=True, feature="sse4_1"),
        dict(name="pextrd_m32_xmm0_3", width=4, code="660f3a160703", legal=True, feature="sse4_1"),
        dict(name="pextrq_m64_xmm0_0", width=8, code="66480f3a160700", legal=True, feature="sse4_1"),
        dict(name="pextrq_m64_xmm0_1", width=8, code="66480f3a160701", legal=True, feature="sse4_1"),
        dict(name="movntps_m128_xmm0", width=16, code="0f2b07", legal=True, feature="sse2", alignment=16),
        dict(name="movntdq_m128_xmm0", width=16, code="660fe707", legal=True, feature="sse2", alignment=16),
    ]
    masks = [
        ("full", bytes([0xff] * 16)),
        ("zero", bytes(16)),
        ("low_half", bytes([0x80] * 8 + [0] * 8)),
        ("high_half", bytes([0] * 8 + [0x80] * 8)),
        ("even_bytes", bytes([0x80, 0] * 8)),
        ("odd_bytes", bytes([0, 0x80] * 8)),
        ("endpoints", bytes([0x80] + [0] * 14 + [0x80])),
    ]
    for name, mask in masks:
        cases.append(dict(name="maskmovdqu_xmm0_xmm1_" + name,
                          width=16, code="660ff7c1", legal=True,
                          feature="sse2", mask=mask.hex()))
    cases.append(dict(name="vmovdqu_m256_ymm0", width=32, code="c5fe7f07",
                      legal=True, feature="avx"))
    return cases
