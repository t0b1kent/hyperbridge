# SPDX-License-Identifier: MIT
# Native synthetic x86 instruction-form inventory for this project.
"""Stage 1 SSE/VEX conversion kernels consumed by the shared generator.

The width is the vector encoding width except for an MMX destination, whose
reported width is 64.  sizes describes the complete architectural registers
printed in slots A/B/C, not just the source bits consumed by an instruction.
Thus an XMM source is still printed as 16 bytes when only its low half is used.

The caller initializes SIMD registers 0/1/2 from slots A/B/C.  pre runs before
LDMXCSR, post after the tested instruction and STMXCSR.  On a synchronous
exception the caller must resume immediately after the tested instruction,
with the saved native register context restored, so post also records the
unchanged GPR or MMX destination.  post runs after any default SIMD store.
"""


def _form(name, enc, width, lane, types, sizes, asm, *, scalar=False,
          nops=2, axes=None, out_bytes=None, feature=None, **extra):
    """Build fresh metadata, keeping register and element widths independent."""
    result = {
        "cls": "conversion",
        "name": name,
        "enc": enc,
        "width": width,
        "lane": lane,
        "scalar": scalar,
        "nops": nops,
        "axes": [1] if axes is None else list(axes),
        "types": list(types),
        "sizes": list(sizes),
        "out_bytes": sizes[0] if out_bytes is None else out_bytes,
        "asm": asm,
        "feature": feature or ("avx" if enc == "VEX" else "sse2"),
    }
    result.update(extra)
    return result


def forms():
    """Return all 92 register-source Stage 1 conversion/control forms.

    There are 28 legacy forms (including six SSE/MMX forms), 30 AVX forms,
    and 34 F16C forms.  GPR operand size is specified by sizes and gpr_bits;
    the mnemonic itself deliberately remains the architectural mnemonic.
    """
    result = []

    # Scalar float <-> double: legacy preserves high A; VEX copies high B.
    for mnemonic, src, dst, lane in (
        ("cvtss2sd", "f32", "f64", 4),
        ("cvtsd2ss", "f64", "f32", 8),
    ):
        result.append(_form(
            mnemonic, "SSE", 128, lane, [dst, src, src], [16, 16, 16],
            f"{mnemonic} %xmm1, %xmm0", scalar=True, axes=[0, 1]))
        result.append(_form(
            "v" + mnemonic, "VEX", 128, lane,
            [dst, dst, src], [16, 16, 16],
            f"v{mnemonic} %xmm2, %xmm1, %xmm0",
            scalar=True, nops=3, axes=[1, 2]))

    # Packed float <-> double.  Widening always reads an XMM source;
    # narrowing always writes an XMM destination, even for VEX.256.
    for mnemonic, src, dst, lane, widening in (
        ("cvtps2pd", "f32", "f64", 4, True),
        ("cvtpd2ps", "f64", "f32", 8, False),
    ):
        for enc, width in (("SSE", 128), ("VEX", 128), ("VEX", 256)):
            name = ("v" if enc == "VEX" else "") + mnemonic
            vector = "ymm" if width == 256 else "xmm"
            dest_reg = vector if widening else "xmm"
            src_reg = "xmm" if widening else vector
            dest_bytes = width // 8 if widening else 16
            src_bytes = 16 if widening else width // 8
            result.append(_form(
                name, enc, width, lane, [dst, src, src],
                [dest_bytes, src_bytes, width // 8],
                f"{name} %{src_reg}1, %{dest_reg}0"))

    # Scalar signed integer -> float/double, in both GPR operand sizes.
    # The converted integer is B in legacy encoding and C in VEX encoding.
    for suffix, dst, lane in (("ss", "f32", 4), ("sd", "f64", 8)):
        for bits in (32, 64):
            integer = "i" + str(bits)
            integer_bytes = bits // 8
            reg = "eax" if bits == 32 else "rax"
            move = "movl" if bits == 32 else "movq"
            mnemonic = "cvtsi2" + suffix
            result.append(_form(
                mnemonic, "SSE", 128, lane,
                [dst, integer, dst], [16, integer_bytes, 16],
                f"{mnemonic} %{reg}, %xmm0", scalar=True, axes=[0, 1],
                pre=f"{move} 64(%rdi), %{reg}", gpr_bits=bits,
                feature="sse" if suffix == "ss" else "sse2"))
            result.append(_form(
                "v" + mnemonic, "VEX", 128, lane,
                [dst, dst, integer], [16, 16, integer_bytes],
                f"v{mnemonic} %{reg}, %xmm1, %xmm0",
                scalar=True, nops=3, axes=[1, 2],
                pre=f"{move} 128(%rdi), %{reg}", gpr_bits=bits))

    # Scalar float/double -> signed integer: CVT honors MXCSR.RC, CVTT
    # truncates.  A is a real native GPR initialized before every execution.
    for suffix, src, lane in (("ss", "f32", 4), ("sd", "f64", 8)):
        for truncating in (False, True):
            mnemonic = ("cvtt" if truncating else "cvt") + suffix + "2si"
            for bits in (32, 64):
                integer = "i" + str(bits)
                integer_bytes = bits // 8
                reg = "eax" if bits == 32 else "rax"
                move = "movl" if bits == 32 else "movq"
                for enc in ("SSE", "VEX"):
                    name = ("v" if enc == "VEX" else "") + mnemonic
                    result.append(_form(
                        name, enc, 128, lane,
                        [integer, src, src], [integer_bytes, 16, 16],
                        f"{name} %xmm1, %{reg}", scalar=True,
                        pre=f"{move} 0(%rdi), %{reg}",
                        post=f"{move} %{reg}, 0(%rsi)",
                        gpr_bits=bits, result_reg=reg,
                        feature=("avx" if enc == "VEX" else
                                 ("sse" if suffix == "ss" else "sse2"))))

    # Packed signed dwords -> float/double.  There is no SSE/VEX packed
    # qword conversion: those are deferred EVEX forms, not missing variants.
    for suffix, dst, lane in (("ps", "f32", 4), ("pd", "f64", 8)):
        mnemonic = "cvtdq2" + suffix
        for enc, width in (("SSE", 128), ("VEX", 128), ("VEX", 256)):
            name = ("v" if enc == "VEX" else "") + mnemonic
            dest_reg = "ymm" if width == 256 else "xmm"
            src_reg = "xmm" if suffix == "pd" else dest_reg
            src_bytes = 16 if suffix == "pd" else width // 8
            result.append(_form(
                name, enc, width, lane, [dst, "i32", dst],
                [width // 8, src_bytes, width // 8],
                f"{name} %{src_reg}1, %{dest_reg}0"))

    # Packed float/double -> signed dwords.  The double conversion writes
    # XMM; with a 128-bit source it also clears the unused high 64 result bits.
    for suffix, src, lane in (("ps", "f32", 4), ("pd", "f64", 8)):
        for truncating in (False, True):
            mnemonic = ("cvtt" if truncating else "cvt") + suffix + "2dq"
            for enc, width in (("SSE", 128), ("VEX", 128), ("VEX", 256)):
                name = ("v" if enc == "VEX" else "") + mnemonic
                src_reg = "ymm" if width == 256 else "xmm"
                dest_reg = "xmm" if suffix == "pd" else src_reg
                dest_bytes = 16 if suffix == "pd" else width // 8
                result.append(_form(
                    name, enc, width, lane, ["i32", src, src],
                    [dest_bytes, width // 8, width // 8],
                    f"{name} %{src_reg}1, %{dest_reg}0"))

    # Original SSE/SSE2 conversions using packed dwords in MMX registers.
    # EMMS is after STMXCSR/result collection and also runs after a trap.
    for suffix, dst, lane in (("ps", "f32", 4), ("pd", "f64", 8)):
        name = "cvtpi2" + suffix
        result.append(_form(
            name, "SSE", 128, lane, [dst, "i32", dst], [16, 8, 16],
            f"{name} %mm1, %xmm0", pre="movq 64(%rdi), %mm1",
            post="emms", feature="mmx"))
    for suffix, src, lane in (("ps", "f32", 4), ("pd", "f64", 8)):
        for truncating in (False, True):
            name = ("cvtt" if truncating else "cvt") + suffix + "2pi"
            result.append(_form(
                name, "SSE", 64, lane, ["i32", src, src], [8, 16, 16],
                f"{name} %xmm1, %mm0", pre="movq 0(%rdi), %mm0",
                post="movq %mm0, 0(%rsi); emms", result_reg="mm0",
                feature="mmx"))

    # F16C: VEX-only binary16 conversions.  Source/destination registers
    # have asymmetric widths.  Control bit 2 selects MXCSR.RC; bit 3 is
    # ignored (unlike ROUND's precision-suppression bit).  Test both values.
    for width in (128, 256):
        vector = "ymm" if width == 256 else "xmm"
        result.append(_form(
            "vcvtph2ps", "VEX", width, 4,
            ["f32", "f16", "f32"], [width // 8, 16, width // 8],
            f"vcvtph2ps %xmm1, %{vector}0", feature="f16c"))
        for imm in range(16):
            result.append(_form(
                "vcvtps2ph", "VEX", width, 4,
                ["f16", "f32", "f32"], [16, width // 8, width // 8],
                f"vcvtps2ph ${imm}, %{vector}1, %xmm0",
                imm=imm, feature="f16c"))

    assert len(result) == 92
    return result
