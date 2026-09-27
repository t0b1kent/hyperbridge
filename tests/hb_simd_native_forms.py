#!/usr/bin/env python3
"""Form table of tests/hb_simd_native_diff.c, produced by the SYSTEM x86 assembler (Claude 27.09.2026).

    python3 tests/hb_simd_native_forms.py > table.txt   # then paste between FORMS[] = { ... };

Each entry: family (0 moves, 1 int, 2 fp), expect (1 native via the new families, 0 must stay with the
helper, 2 native via a pre-existing emitter), value type (I/S/D), count source of a register shift
(-1 none, 0..15 xmm index, 99 memory), encoded length, bytes, Intel text. Encodings are taken from
`clang -target x86_64-apple-macos` + `objdump -d`, never typed by hand."""
import subprocess, sys, re, os, tempfile

F = []
def f(fam, exp, vt, asm, cnt=-1):
    F.append((fam, exp, vt, cnt, asm))

# ---------- family 0: moves ----------
for a in ["movsd xmm1, xmm1", "movsd xmm1, xmm0", "movsd xmm0, xmm0", "movsd xmm3, xmm1",
          "movss xmm1, xmm2", "movss xmm3, xmm3", "movsd xmm9, xmm12", "movss xmm15, xmm0",
          "vmovaps xmm1, xmm2", "vmovaps xmm5, xmm5", "vmovdqa xmm4, xmm13", "vmovaps ymm1, ymm2",
          "vmovups ymm3, ymm3", "vmovapd ymm8, ymm15",
          "movlhps xmm3, xmm3", "movhlps xmm4, xmm0", "movlhps xmm5, xmm0", "movlhps xmm7, xmm2",
          "movhlps xmm9, xmm9", "movhps xmm0, qword ptr [rdx]", "movhpd xmm1, qword ptr [rdx+8]",
          "movhps qword ptr [rdx], xmm2", "movhpd qword ptr [rdx+16], xmm3",
          "vmovhlps xmm0, xmm1, xmm2", "vmovlhps xmm0, xmm1, xmm2", "vmovlhps xmm6, xmm6, xmm6",
          "vmovhps xmm1, xmm2, qword ptr [rdx]", "vmovlps xmm1, xmm2, qword ptr [rdx+8]",
          "vmovhps qword ptr [rdx+8], xmm1",
          "vmovss xmm0, xmm1, xmm2", "vmovsd xmm3, xmm4, xmm5", "vmovss xmm0, dword ptr [rdx]",
          "vmovsd xmm1, qword ptr [rdx+8]", "vmovss xmm8, xmm9, xmm10", "vmovsd xmm2, xmm2, xmm2",
          "vzeroupper", "vzeroall",
          "vinsertf128 ymm0, ymm0, xmm0, 1", "vinsertf128 ymm1, ymm2, xmm3, 0",
          "vinsertf128 ymm1, ymm2, xmmword ptr [rdx], 1", "vinserti128 ymm4, ymm5, xmm6, 1",
          "vinserti128 ymm7, ymm7, xmmword ptr [rdx+16], 0",
          "vextractf128 xmm0, ymm1, 1", "vextractf128 xmm2, ymm3, 0", "vextractf128 xmm4, ymm4, 1",
          "vextractf128 xmmword ptr [rdx], ymm1, 1", "vextracti128 xmm5, ymm6, 1",
          "vextracti128 xmmword ptr [rdx+16], ymm2, 0",
          "vperm2f128 ymm0, ymm1, ymm2, 0x21", "vperm2f128 ymm0, ymm1, ymmword ptr [rdx], 0x38",
          "vperm2i128 ymm3, ymm4, ymm5, 0x93", "vperm2f128 ymm6, ymm6, ymm7, 0x02"]:
    f(0, 1, 'I', a)
# lane duplication and broadcasts
for a in ["movddup xmm0, xmm1", "movddup xmm2, qword ptr [rdx]", "movsldup xmm3, xmm4",
          "movshdup xmm5, xmmword ptr [rdx]", "movshdup xmm6, xmm6", "vmovddup xmm0, xmm1",
          "vmovddup ymm2, ymm3", "vmovddup xmm4, qword ptr [rdx]", "vmovsldup ymm5, ymmword ptr [rdx]",
          "vmovshdup xmm6, xmm7", "vbroadcastss ymm0, dword ptr [rdx]", "vbroadcastss xmm1, xmm2",
          "vbroadcastsd ymm3, xmm4", "vbroadcastsd ymm5, qword ptr [rdx]", "vpbroadcastb xmm0, xmm1",
          "vpbroadcastb ymm2, byte ptr [rdx]", "vpbroadcastw ymm3, word ptr [rdx]", "vpbroadcastw xmm8, xmm9",
          "vpbroadcastd xmm4, xmm5", "vpbroadcastq ymm6, qword ptr [rdx]", "vbroadcasti128 ymm7, xmmword ptr [rdx]",
          "vbroadcastf128 ymm8, xmmword ptr [rdx]"]:
    f(0, 1, 'I', a)
f(0, 0, 'S', "vbroadcastss xmm0 {k1}, xmm1")
# EVEX / masked moves must stay with the helper
f(0, 0, 'I', "vmovaps xmm0 {k1}, xmm1")
f(0, 0, 'I', "vmovaps zmm0, zmm1")

# ---------- family 1: integer ----------
I = []
def i(a, cnt=-1, exp=1):
    f(1, exp, 'I', a, cnt)
for a in ["paddd xmm0, xmm3", "paddd xmm4, xmm2", "paddw xmm6, xmm1", "paddb xmm0, xmmword ptr [rdx]",
          "paddq xmm1, xmmword ptr [rdx]", "vpaddd xmm0, xmm1, xmm2", "vpaddd ymm0, ymm1, ymm2",
          "vpaddq ymm3, ymm4, ymmword ptr [rdx]", "vpaddw xmm9, xmm10, xmm11",
          "psubw xmm3, xmm2", "psubb xmm1, xmm7", "psubd xmm2, xmmword ptr [rdx]", "psubq xmm5, xmm6",
          "vpsubw ymm1, ymm2, ymm3", "vpsubb xmm0, xmm0, xmmword ptr [rdx]",
          "paddsb xmm0, xmm1", "paddsw xmm2, xmmword ptr [rdx]", "paddusb xmm3, xmm4", "paddusw xmm5, xmm6",
          "psubsb xmm0, xmm1", "psubsw xmm2, xmm3", "psubusb xmm4, xmmword ptr [rdx]", "psubusw xmm6, xmm7",
          "vpaddsw ymm0, ymm1, ymm2", "vpsubusb ymm3, ymm4, ymm5",
          "pavgb xmm0, xmm1", "pavgw xmm2, xmmword ptr [rdx]", "vpavgb ymm0, ymm1, ymm2",
          "psadbw xmm0, xmm1", "psadbw xmm2, xmmword ptr [rdx]", "vpsadbw ymm3, ymm4, ymm5",
          "pmullw xmm3, xmm0", "pmullw xmm1, xmmword ptr [rdx]", "vpmullw ymm0, ymm1, ymm2",
          "pmulhw xmm0, xmm1", "pmulhuw xmm2, xmm3", "pmaddwd xmm4, xmm5", "vpmaddwd ymm0, ymm1, ymm2",
          "vpmulhw xmm6, xmm7, xmmword ptr [rdx]",
          "pmulld xmm0, xmm1", "pmuludq xmm2, xmm3", "pmuldq xmm4, xmmword ptr [rdx]", "vpmuludq ymm0, ymm1, ymm2",
          "pminub xmm0, xmm1", "pmaxub xmm2, xmm3", "pminsw xmm4, xmm5", "pmaxsw xmm6, xmmword ptr [rdx]",
          "pminsb xmm0, xmm1", "pmaxsb xmm2, xmm3", "pminsd xmm4, xmm5", "pmaxsd xmm6, xmm7",
          "pminuw xmm0, xmm1", "pmaxuw xmm2, xmm3", "pminud xmm4, xmm5", "pmaxud xmm6, xmm7",
          "vpmaxub ymm0, ymm1, ymm2", "vpminsd ymm3, ymm4, ymmword ptr [rdx]",
          "pabsb xmm0, xmm1", "pabsw xmm2, xmmword ptr [rdx]", "pabsd xmm3, xmm3", "vpabsd ymm4, ymm5",
          "pcmpeqb xmm0, xmm1", "pcmpeqw xmm2, xmm3", "pcmpeqd xmm4, xmmword ptr [rdx]", "pcmpeqb xmm5, xmm5",
          "pcmpgtb xmm0, xmm1", "pcmpgtw xmm2, xmm3", "pcmpgtd xmm4, xmm5", "pcmpeqq xmm6, xmm7",
          "pcmpgtq xmm0, xmm1", "vpcmpeqb ymm0, ymm1, ymm2", "vpcmpgtd xmm3, xmm4, xmm5",
          "vpcmpeqd xmm0, xmm0, xmm0",
          "vandps xmm0, xmm1, xmm2", "vandps ymm0, ymm1, ymmword ptr [rdx]", "vxorps xmm0, xmm0, xmm0",
          "vxorps ymm3, ymm3, ymm3", "vpxor xmm1, xmm2, xmm3", "vandnps xmm4, xmm5, xmm6",
          "vandnpd ymm7, ymm8, ymm9", "vorps ymm1, ymm2, ymm3", "vpand xmm10, xmm11, xmmword ptr [rdx]",
          "vpor ymm12, ymm13, ymm14", "vpandn xmm15, xmm0, xmm1",
          "packsswb xmm0, xmm1", "packuswb xmm3, xmm6", "packssdw xmm2, xmmword ptr [rdx]",
          "packusdw xmm4, xmm5", "vpackuswb ymm0, ymm1, ymm2", "vpacksswb xmm3, xmm4, xmm5",
          "vpackusdw ymm6, ymm7, ymm8",
          "punpcklbw xmm0, xmmword ptr [rdx]", "punpckhwd xmm1, xmm2", "punpckldq xmm3, xmmword ptr [rdx]",
          "punpckhqdq xmm4, xmmword ptr [rdx]", "unpcklps xmm5, xmmword ptr [rdx]", "unpckhpd xmm6, xmmword ptr [rdx]",
          "vpunpcklbw xmm0, xmm1, xmm2", "vpunpckhdq ymm3, ymm4, ymm5", "vunpcklps ymm6, ymm7, ymmword ptr [rdx]",
          "vunpckhpd xmm8, xmm9, xmm10", "vpunpcklqdq ymm0, ymm1, ymm2",
          "pmovmskb eax, xmm1", "pmovmskb ecx, xmm9", "vpmovmskb eax, ymm1", "vpmovmskb edx, xmm3",
          "movmskps eax, xmm7", "movmskpd ecx, xmm0", "vmovmskps eax, ymm1", "vmovmskpd esi, ymm2",
          "movmskps r9d, xmm15",
          "psrad xmm7, 31", "psraw xmm6, 8", "pslld xmm0, 16", "psrlw xmm1, 0", "psrlw xmm2, 15",
          "psrlw xmm3, 16", "psraw xmm4, 200", "pslld xmm5, 33", "psrld xmm6, 1", "psllw xmm7, 7",
          "psrlq xmm2, 5", "psllq xmm3, 64", "psrlq xmm4, 63", "psllq xmm5, 0",
          "psrldq xmm0, 8", "psrldq xmm1, 3", "psrldq xmm2, 16", "psrldq xmm3, 20", "pslldq xmm4, 4",
          "pslldq xmm5, 15", "pslldq xmm6, 0",
          "vpsrld xmm0, xmm1, 3", "vpsrad ymm2, ymm3, 31", "vpsllw ymm4, ymm5, 17", "vpsrldq ymm0, ymm1, 5",
          "vpslldq xmm6, xmm7, 9", "vpsrlq ymm8, ymm9, 40"]:
    i(a)
for a, c in [("psrld xmm2, xmm3", 3), ("psraw xmm1, xmm2", 2), ("psllq xmm0, xmm1", 1),
             ("psrlw xmm0, xmmword ptr [rdx]", 99), ("psrlq xmm5, xmm6", 6), ("pslld xmm7, xmm8", 8),
             ("psrad xmm3, xmmword ptr [rdx]", 99), ("vpsllw ymm0, ymm1, xmm2", 2),
             ("vpsrad ymm3, ymm4, xmm5", 5), ("vpsrlq xmm6, xmm7, xmmword ptr [rdx]", 99)]:
    i(a, c)
# pre-existing native path (emit_native_punpck_qdq): value checked, family counter not expected
for a in ["punpckhwd xmm1, xmm2", "punpckhqdq xmm4, xmmword ptr [rdx]", "unpckhpd xmm6, xmmword ptr [rdx]"]:
    for k, e in enumerate(F):
        if e[4] == a:
            F[k] = (e[0], 2, e[2], e[3], e[4])
# MMX forms of the same IR ops must stay with the helper (the families take XMM0..15 only)
for a in ["paddd mm0, mm1", "psubw mm2, qword ptr [rdx]", "pmovmskb eax, mm1", "psrlq mm0, 3",
          "psllw mm1, mm2", "punpcklbw mm0, mm1", "pxor mm2, mm3", "pcmpeqb mm0, mm1",
          "packuswb mm4, mm5", "pmullw mm6, mm7"]:
    i(a, exp=0)
# EVEX forms with a mask must stay with the helper
i("vpaddd xmm0 {k1}, xmm1, xmm2", exp=0)
i("vpaddd zmm0, zmm1, zmm2", exp=0)

# ---------- family 2: floating point ----------
def fp(a, vt, exp=1):
    f(2, exp, vt, a)
for a in ["vmulps xmm0, xmm1, xmm2", "vmulps ymm0, ymm1, ymm2", "vaddps xmm3, xmm4, xmmword ptr [rdx]",
          "vdivps ymm5, ymm6, ymmword ptr [rdx]", "vsubps xmm7, xmm7, xmm8",
          "vsubss xmm0, xmm1, xmm2", "vaddss xmm3, xmm4, dword ptr [rdx]", "vmulss xmm5, xmm5, xmm5",
          "vdivss xmm6, xmm7, xmm8", "vminps xmm0, xmm1, xmm2", "vmaxps ymm3, ymm4, ymm5",
          "vminss xmm6, xmm7, dword ptr [rdx]", "vmaxss xmm8, xmm9, xmm10",
          "sqrtps xmm0, xmm1", "sqrtss xmm0, xmm1", "sqrtss xmm2, dword ptr [rdx]", "vsqrtps ymm0, ymm1",
          "vsqrtss xmm0, xmm1, xmm2", "vsqrtps xmm3, xmmword ptr [rdx]",
          "rsqrtps xmm0, xmm1", "rsqrtss xmm2, xmm3", "rcpps xmm4, xmmword ptr [rdx]", "rcpss xmm5, xmm6",
          "vrsqrtps ymm0, ymm1", "vrcpss xmm0, xmm1, xmm2", "vrcpps ymm3, ymm4",
          "roundps xmm0, xmm1, 0", "roundps xmm0, xmm1, 1", "roundps xmm0, xmm1, 2", "roundps xmm0, xmm1, 3",
          "roundps xmm0, xmm1, 4", "roundps xmm2, xmmword ptr [rdx], 9", "roundss xmm0, xmm1, 4",
          "roundss xmm3, dword ptr [rdx], 10", "vroundps ymm0, ymm1, 1", "vroundps xmm4, xmm5, 12",
          "vroundss xmm6, xmm7, xmm8, 3",
          "cmpltps xmm6, xmm14", "cmpltps xmm7, xmm10", "cmpeqps xmm0, xmm1", "cmpleps xmm0, xmm1",
          "cmpunordps xmm0, xmm1", "cmpneqps xmm0, xmm1", "cmpnltps xmm0, xmm1", "cmpnleps xmm0, xmm1",
          "cmpordps xmm0, xmmword ptr [rdx]", "cmpltss xmm2, xmm3", "cmpeqss xmm4, dword ptr [rdx]",
          "cmpnless xmm5, xmm5", "vcmpltps ymm0, ymm1, ymm2", "vcmpgeps xmm3, xmm4, xmm5",
          "vcmpeq_uqps xmm0, xmm1, xmm2", "vcmpngeps xmm0, xmm1, xmm2", "vcmpngtps xmm0, xmm1, xmm2",
          "vcmpfalseps xmm0, xmm1, xmm2", "vcmpneq_oqps xmm0, xmm1, xmm2", "vcmpgtps ymm0, ymm1, ymmword ptr [rdx]",
          "vcmptrueps xmm0, xmm1, xmm2", "vcmpeq_osps xmm0, xmm1, xmm2", "vcmplt_oqps xmm0, xmm1, xmm2",
          "vcmpunord_sps xmm0, xmm1, xmm2", "vcmpneq_usps ymm0, ymm1, ymm2", "vcmpnlt_uqps xmm0, xmm1, xmm2",
          "vcmpord_sps xmm0, xmm1, xmm2", "vcmpeq_usps xmm0, xmm1, xmm2", "vcmpnge_uqps xmm0, xmm1, xmm2",
          "vcmpngt_uqps xmm0, xmm1, xmm2", "vcmpfalse_osps xmm0, xmm1, xmm2", "vcmpneq_osps xmm0, xmm1, xmm2",
          "vcmpge_oqps xmm0, xmm1, xmm2", "vcmpgt_oqps xmm0, xmm1, xmm2", "vcmptrue_usps xmm0, xmm1, xmm2",
          "vcmpless xmm6, xmm7, xmm8",
          "cvttps2dq xmm0, xmm1", "cvtps2dq xmm2, xmm3", "cvttps2dq xmm4, xmmword ptr [rdx]",
          "vcvttps2dq ymm0, ymm1", "vcvtps2dq ymm2, ymmword ptr [rdx]", "vcvtdq2ps ymm3, ymm4",
          "vcvtdq2ps xmm5, xmm6", "vcvtss2sd xmm0, xmm1, xmm2"]:
    fp(a, 'S')
for a in ["vmulpd xmm0, xmm1, xmm2", "vaddpd ymm0, ymm1, ymm2", "vsubsd xmm3, xmm4, qword ptr [rdx]",
          "vmulsd xmm5, xmm6, xmm7", "vdivsd xmm8, xmm8, xmm9", "vdivpd ymm10, ymm11, ymmword ptr [rdx]",
          "vminpd ymm0, ymm1, ymm2", "vmaxsd xmm3, xmm4, xmm5",
          "sqrtpd xmm0, xmm1", "sqrtsd xmm2, qword ptr [rdx]", "vsqrtpd ymm3, ymm4", "vsqrtsd xmm5, xmm6, xmm7",
          "roundpd xmm1, xmm1, 1", "roundpd xmm0, xmm2, 0", "roundpd xmm0, xmmword ptr [rdx], 6",
          "roundsd xmm0, qword ptr [rdx], 2", "roundsd xmm3, xmm4, 12", "vroundpd ymm0, ymm1, 3",
          "vroundsd xmm0, xmm1, xmm2, 14",
          "cmpltpd xmm0, xmm1", "cmpnlepd xmm2, xmmword ptr [rdx]", "cmpunordsd xmm3, xmm4",
          "vcmppd ymm0, ymm1, ymm2, 29", "vcmpsd xmm3, xmm4, qword ptr [rdx], 18", "vcmppd xmm5, xmm6, xmm7, 8",
          "cvttpd2dq xmm0, xmm1", "cvtpd2dq xmm2, xmm3", "cvttpd2dq xmm4, xmmword ptr [rdx]",
          "vcvttpd2dq xmm0, ymm1", "vcvtpd2dq xmm2, ymm3", "vcvtpd2dq xmm4, xmm5",
          "vcvtpd2ps xmm0, ymm1", "vcvtpd2ps xmm2, xmm3", "vcvtsd2ss xmm0, xmm1, xmm2",
          "vcvtsd2ss xmm3, xmm4, qword ptr [rdx]"]:
    fp(a, 'D')
for a in ["vcvtps2pd ymm0, xmm1", "vcvtps2pd xmm2, xmm3", "vcvtps2pd ymm4, xmmword ptr [rdx]",
          "vcvtss2sd xmm5, xmm6, dword ptr [rdx]"]:
    fp(a, 'S')
for a in ["cvtss2si eax, xmm1", "cvtss2si rax, xmm1", "cvtss2si ecx, dword ptr [rdx]", "vcvtss2si eax, xmm2",
          "cvtss2si r9, xmm15"]:
    fp(a, 'S')
for a in ["cvtsd2si eax, xmm1", "cvtsd2si rax, xmm2", "cvtsd2si r9d, qword ptr [rdx]", "vcvtsd2si rax, xmm3",
          "cvtsd2si esi, xmm4"]:
    fp(a, 'D')
for a in ["vcvtdq2pd ymm0, xmm1", "vcvtdq2pd xmm2, qword ptr [rdx]", "vcvtsi2ss xmm0, xmm1, eax",
          "vcvtsi2sd xmm2, xmm3, rax", "vcvtsi2sd xmm4, xmm5, dword ptr [rdx]", "vcvtsi2ss xmm6, xmm7, qword ptr [rdx]"]:
    fp(a, 'I')
# address shapes of emit_direct_mem_addr: index register (rcx is seeded 0/4/8/12), displacement past
# the add-immediate range (X22 carries it), RIP-relative (absolute after lifting) — loads and stores
f(0, 1, 'I', "vinsertf128 ymm3, ymm3, xmmword ptr [rdx + rcx*1], 1")
f(0, 1, 'I', "movhps xmm4, qword ptr [rdx + rcx*4 + 4]")
f(0, 1, 'I', "movhps qword ptr [rdx + rcx*4], xmm5")
f(0, 1, 'I', "vextractf128 xmmword ptr [rdx + rcx*2 + 16], ymm6, 1")
f(0, 1, 'I', "vmovss xmm8, dword ptr [rdx + 4100]")
f(1, 1, 'I', "paddd xmm0, xmmword ptr [rdx + rcx*4]")
f(1, 1, 'I', "psrlw xmm1, xmmword ptr [rdx + rcx*4]", 99)
f(1, 1, 'I', "vpand ymm2, ymm3, ymmword ptr [rdx + 4096]")
f(1, 2, 'I', "pxor xmm12, xmmword ptr [rip + 512]")     # legacy logic with memory: emit_native_xmm_logic
f(1, 1, 'S', "vandps xmm10, xmm11, xmmword ptr [rip + 512]")
fp("vmulps ymm1, ymm2, ymmword ptr [rdx + rcx*2 + 8]", 'S')
fp("cvttps2dq xmm7, xmmword ptr [rdx + 4096]", 'S')
fp("cvtss2si eax, dword ptr [rdx + rcx*4]", 'S')
fp("sqrtsd xmm9, qword ptr [rip + 256]", 'D')
# EVEX with a mask or zmm must stay with the helper
fp("vaddps xmm0 {k1}, xmm1, xmm2", 'S', exp=0)
fp("vaddps zmm0, zmm1, zmm2", 'S', exp=0)
fp("vsqrtps xmm0 {k1}, xmm1", 'S', exp=0)

src = ".intel_syntax noprefix\n" + "".join(a + "\n" for (_, _, _, _, a) in F)
wd = tempfile.mkdtemp(prefix="hb_simd_forms_")
open(os.path.join(wd, "forms.s"), "w").write(src)
subprocess.check_call(["clang", "-c", "-target", "x86_64-apple-macos", "-mavx512f", "-mavx512vl",
                       os.path.join(wd, "forms.s"), "-o", os.path.join(wd, "forms.o")])
dump = subprocess.check_output(["objdump", "-d", os.path.join(wd, "forms.o")]).decode()
enc = []
for line in dump.splitlines():
    m = re.match(r"\s*[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)\s*(.*)$", line)
    if m:
        enc.append([int(b, 16) for b in m.group(1).split()])
if len(enc) != len(F):
    sys.exit("count mismatch %d vs %d" % (len(enc), len(F)))
out = []
for (fam, exp, vt, cnt, a), b in zip(F, enc):
    bs = ",".join("0x%02x" % x for x in b)
    out.append('    {%d, %d, \'%s\', %d, %d, {%s}, "%s"},' % (fam, exp, vt, cnt, len(b), bs, a))
print("\n".join(out))
print("/* %d forms */" % len(F), file=sys.stderr)
