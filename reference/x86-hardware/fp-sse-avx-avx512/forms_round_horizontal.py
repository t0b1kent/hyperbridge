# SPDX-License-Identifier: MIT
# Copyright (c) 2026 x86 floating-point reference contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Stage 1 ROUND, horizontal arithmetic, alternating arithmetic and dot forms.

This module defines instructions only; it neither probes nor executes the CPU.
The calling harness owns register setup, feature checks, MXCSR and SIGFPE.
Operands A, B, C occupy registers 0, 1, 2, with A the old destination.
``axes`` lists input slots varied arithmetically by the shared corpus builder.
All assembly strings use GNU/AT&T syntax, with literal immediate operands.
"""


def _form(cls, mnemonic, encoding, width, lane, scalar, immediate=None):
    """Return one fresh form descriptor in the shared harness's schema."""
    vex = encoding == "VEX"
    rounding = cls == "rounding"
    # Packed ROUND is unary even with VEX.  Scalar VEX ROUND has a separate
    # upper-lane merge source B and the rounded low-element source C.
    if rounding:
        nops = 3 if vex and scalar else 2
        axes = [1, 2] if vex and scalar else [1]
    else:
        nops = 3 if vex else 2
        axes = [1, 2] if vex else [0, 1]

    register = "ymm" if width == 256 else "xmm"
    name = ("v" if vex else "") + mnemonic
    inputs = ["%%%s%d" % (register, slot) for slot in range(nops - 1, -1, -1)]
    if immediate is not None:
        inputs.insert(0, "$%d" % immediate)

    if vex:
        feature = "avx"
    elif rounding or mnemonic.startswith("dp"):
        feature = "sse4.1"
    else:
        feature = "sse3"

    form = {
        "cls": cls,
        "name": name,
        "enc": encoding,
        "width": width,
        "lane": lane,
        "scalar": scalar,
        "nops": nops,
        "axes": axes,
        "feature": feature,
        "asm": name + " " + ", ".join(inputs),
    }
    if immediate is not None:
        form["imm"] = immediate
    return form


def forms():
    """Return all 1,458 legal requested forms, in deterministic order.

    Counts are 160 rounding forms and 1,298 horizontal/dot forms.  Every call
    returns fresh dictionaries and fresh axis lists; callers can annotate them.
    """
    result = []

    for suffix, lane, scalar in (("ps", 4, False), ("pd", 8, False),
                                 ("ss", 4, True), ("sd", 8, True)):
        encodings = (("SSE", 128), ("VEX", 128))
        if not scalar:
            encodings += (("VEX", 256),)
        for encoding, width in encodings:
            for immediate in range(16):
                result.append(_form("rounding", "round" + suffix, encoding,
                                    width, lane, scalar, immediate))

    for operation in ("hadd", "hsub", "addsub"):
        for suffix, lane in (("ps", 4), ("pd", 8)):
            for encoding, width in (("SSE", 128), ("VEX", 128), ("VEX", 256)):
                result.append(_form("horizontal", operation + suffix,
                                    encoding, width, lane, False))

    for mnemonic, lane in (("dpps", 4), ("dppd", 8)):
        encodings = (("SSE", 128), ("VEX", 128))
        if mnemonic == "dpps":
            encodings += (("VEX", 256),)
        for encoding, width in encodings:
            for immediate in range(256):
                result.append(_form("horizontal", mnemonic, encoding,
                                    width, lane, False, immediate))

    return result
