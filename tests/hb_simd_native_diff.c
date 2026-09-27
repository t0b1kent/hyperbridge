/*
 * hb_simd_native_diff.c — разностный тест SIMD без помощника: выпущенный код против интерпретатора.
 *
 * Claude 27.09.2026. Три семьи под гейтами MACRUNNER_HB_NATIVE_XMM_MOVES, _SIMD_INT, _SIMD_FP
 * (src/hb_arm64_simd.inc). Эталон — интерпретатор этого же ядра; образец — tests/hb_alumem_diff.c.
 *
 * Формы (390) собраны системным ассемблером x86 (clang -target x86_64 + objdump), а не руками —
 * таблицу порождает tests/hb_simd_native_forms.py: устаревшие SSE, VEX.128, VEX.256, операнды-
 * регистры и память [rdx], [rdx+disp8], [rdx+rcx*k], [rdx+4096], [rip+disp] (обе дальние цели засеяны) по выровненному и
 * невыровненному адресу, счётчики сдвига из XMM и памяти, контрольные формы EVEX с маской и zmm и
 * MMX-формы тех же операций IR (обязаны остаться у помощника). У каждой формы проверяется и значение, и сам факт выпуска: счётчик
 * hb_codegen_native_simd_emitted(семья) обязан вырасти (или НЕ вырасти у контрольных).
 *
 * Входы: все 16 XMM, ymm_hi, zmm_hi, k0..k7, mm0..mm7 — случайные значения вперемешку с особыми (±0,
 * денормали, ±inf, QNaN/SNaN с полезной нагрузкой, границы int, все единицы, x.5); MXCSR у форм FP —
 * RN/RD/RU/RZ и DAZ/FTZ; окно памяти теми же значениями. Сверяются: 16 XMM, ymm_hi, zmm_hi, k,
 * MXCSR, mm и x87, все GPR (rdx — смещением от своего окна или значением), флаги и запись ленивых
 * флагов, pc, итог, окно памяти.
 *
 * Выход 0 — всё совпало и ожидания выпуска выполнены; 1 — расхождение; 2 — отказ оснастки.
 * ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: MACRUNNER_HB_TEST_SIMD_FLIP=1 портит результат выпуска. Тогда выход 0
 * означает «расхождение увидено на КАЖДОЙ форме, которая выпускается нативно», 1 — не на каждой.
 * HB_SIMD_CASES — случаев на форму (по умолчанию 300).
 */
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

/* Слабый символ: тест собирается и против ядра без семей (тогда нативных выпусков ноль). */
extern uint64_t hb_codegen_native_simd_emitted(unsigned fam) __attribute__((weak));
static uint64_t native_count(unsigned fam) {
    return hb_codegen_native_simd_emitted ? hb_codegen_native_simd_emitted(fam) : 0;
}

/* expect: 1 — выпуск семьи обязан состояться, 0 — обязан уйти помощнику, 2 — прежний нативный путь. */
struct form { int fam, expect; char vt; int cnt; int len; uint8_t b[15]; const char* name; };
static const struct form FORMS[] = {
    {0, 1, 'I', -1, 4, {0xf2,0x0f,0x10,0xc9}, "movsd xmm1, xmm1"},
    {0, 1, 'I', -1, 4, {0xf2,0x0f,0x10,0xc8}, "movsd xmm1, xmm0"},
    {0, 1, 'I', -1, 4, {0xf2,0x0f,0x10,0xc0}, "movsd xmm0, xmm0"},
    {0, 1, 'I', -1, 4, {0xf2,0x0f,0x10,0xd9}, "movsd xmm3, xmm1"},
    {0, 1, 'I', -1, 4, {0xf3,0x0f,0x10,0xca}, "movss xmm1, xmm2"},
    {0, 1, 'I', -1, 4, {0xf3,0x0f,0x10,0xdb}, "movss xmm3, xmm3"},
    {0, 1, 'I', -1, 5, {0xf2,0x45,0x0f,0x10,0xcc}, "movsd xmm9, xmm12"},
    {0, 1, 'I', -1, 5, {0xf3,0x44,0x0f,0x10,0xf8}, "movss xmm15, xmm0"},
    {0, 1, 'I', -1, 4, {0xc5,0xf8,0x28,0xca}, "vmovaps xmm1, xmm2"},
    {0, 1, 'I', -1, 4, {0xc5,0xf8,0x28,0xed}, "vmovaps xmm5, xmm5"},
    {0, 1, 'I', -1, 4, {0xc5,0x79,0x7f,0xec}, "vmovdqa xmm4, xmm13"},
    {0, 1, 'I', -1, 4, {0xc5,0xfc,0x28,0xca}, "vmovaps ymm1, ymm2"},
    {0, 1, 'I', -1, 4, {0xc5,0xfc,0x10,0xdb}, "vmovups ymm3, ymm3"},
    {0, 1, 'I', -1, 5, {0xc4,0x41,0x7d,0x28,0xc7}, "vmovapd ymm8, ymm15"},
    {0, 1, 'I', -1, 3, {0x0f,0x16,0xdb}, "movlhps xmm3, xmm3"},
    {0, 1, 'I', -1, 3, {0x0f,0x12,0xe0}, "movhlps xmm4, xmm0"},
    {0, 1, 'I', -1, 3, {0x0f,0x16,0xe8}, "movlhps xmm5, xmm0"},
    {0, 1, 'I', -1, 3, {0x0f,0x16,0xfa}, "movlhps xmm7, xmm2"},
    {0, 1, 'I', -1, 4, {0x45,0x0f,0x12,0xc9}, "movhlps xmm9, xmm9"},
    {0, 1, 'I', -1, 3, {0x0f,0x16,0x02}, "movhps xmm0, qword ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0x66,0x0f,0x16,0x4a,0x08}, "movhpd xmm1, qword ptr [rdx+8]"},
    {0, 1, 'I', -1, 3, {0x0f,0x17,0x12}, "movhps qword ptr [rdx], xmm2"},
    {0, 1, 'I', -1, 5, {0x66,0x0f,0x17,0x5a,0x10}, "movhpd qword ptr [rdx+16], xmm3"},
    {0, 1, 'I', -1, 4, {0xc5,0xf0,0x12,0xc2}, "vmovhlps xmm0, xmm1, xmm2"},
    {0, 1, 'I', -1, 4, {0xc5,0xf0,0x16,0xc2}, "vmovlhps xmm0, xmm1, xmm2"},
    {0, 1, 'I', -1, 4, {0xc5,0xc8,0x16,0xf6}, "vmovlhps xmm6, xmm6, xmm6"},
    {0, 1, 'I', -1, 4, {0xc5,0xe8,0x16,0x0a}, "vmovhps xmm1, xmm2, qword ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc5,0xe8,0x12,0x4a,0x08}, "vmovlps xmm1, xmm2, qword ptr [rdx+8]"},
    {0, 1, 'I', -1, 5, {0xc5,0xf8,0x17,0x4a,0x08}, "vmovhps qword ptr [rdx+8], xmm1"},
    {0, 1, 'I', -1, 4, {0xc5,0xf2,0x10,0xc2}, "vmovss xmm0, xmm1, xmm2"},
    {0, 1, 'I', -1, 4, {0xc5,0xdb,0x10,0xdd}, "vmovsd xmm3, xmm4, xmm5"},
    {0, 1, 'I', -1, 4, {0xc5,0xfa,0x10,0x02}, "vmovss xmm0, dword ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc5,0xfb,0x10,0x4a,0x08}, "vmovsd xmm1, qword ptr [rdx+8]"},
    {0, 1, 'I', -1, 5, {0xc4,0x41,0x32,0x10,0xc2}, "vmovss xmm8, xmm9, xmm10"},
    {0, 1, 'I', -1, 4, {0xc5,0xeb,0x10,0xd2}, "vmovsd xmm2, xmm2, xmm2"},
    {0, 1, 'I', -1, 3, {0xc5,0xf8,0x77}, "vzeroupper"},
    {0, 1, 'I', -1, 3, {0xc5,0xfc,0x77}, "vzeroall"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x7d,0x18,0xc0,0x01}, "vinsertf128 ymm0, ymm0, xmm0, 1"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x6d,0x18,0xcb,0x00}, "vinsertf128 ymm1, ymm2, xmm3, 0"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x6d,0x18,0x0a,0x01}, "vinsertf128 ymm1, ymm2, xmmword ptr [rdx], 1"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x55,0x38,0xe6,0x01}, "vinserti128 ymm4, ymm5, xmm6, 1"},
    {0, 1, 'I', -1, 7, {0xc4,0xe3,0x45,0x38,0x7a,0x10,0x00}, "vinserti128 ymm7, ymm7, xmmword ptr [rdx+16], 0"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x7d,0x19,0xc8,0x01}, "vextractf128 xmm0, ymm1, 1"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x7d,0x19,0xda,0x00}, "vextractf128 xmm2, ymm3, 0"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x7d,0x19,0xe4,0x01}, "vextractf128 xmm4, ymm4, 1"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x7d,0x19,0x0a,0x01}, "vextractf128 xmmword ptr [rdx], ymm1, 1"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x7d,0x39,0xf5,0x01}, "vextracti128 xmm5, ymm6, 1"},
    {0, 1, 'I', -1, 7, {0xc4,0xe3,0x7d,0x39,0x52,0x10,0x00}, "vextracti128 xmmword ptr [rdx+16], ymm2, 0"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x75,0x06,0xc2,0x21}, "vperm2f128 ymm0, ymm1, ymm2, 0x21"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x75,0x06,0x02,0x38}, "vperm2f128 ymm0, ymm1, ymmword ptr [rdx], 0x38"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x5d,0x46,0xdd,0x93}, "vperm2i128 ymm3, ymm4, ymm5, 0x93"},
    {0, 1, 'I', -1, 6, {0xc4,0xe3,0x4d,0x06,0xf7,0x02}, "vperm2f128 ymm6, ymm6, ymm7, 0x02"},
    {0, 1, 'I', -1, 4, {0xf2,0x0f,0x12,0xc1}, "movddup xmm0, xmm1"},
    {0, 1, 'I', -1, 4, {0xf2,0x0f,0x12,0x12}, "movddup xmm2, qword ptr [rdx]"},
    {0, 1, 'I', -1, 4, {0xf3,0x0f,0x12,0xdc}, "movsldup xmm3, xmm4"},
    {0, 1, 'I', -1, 4, {0xf3,0x0f,0x16,0x2a}, "movshdup xmm5, xmmword ptr [rdx]"},
    {0, 1, 'I', -1, 4, {0xf3,0x0f,0x16,0xf6}, "movshdup xmm6, xmm6"},
    {0, 1, 'I', -1, 4, {0xc5,0xfb,0x12,0xc1}, "vmovddup xmm0, xmm1"},
    {0, 1, 'I', -1, 4, {0xc5,0xff,0x12,0xd3}, "vmovddup ymm2, ymm3"},
    {0, 1, 'I', -1, 4, {0xc5,0xfb,0x12,0x22}, "vmovddup xmm4, qword ptr [rdx]"},
    {0, 1, 'I', -1, 4, {0xc5,0xfe,0x12,0x2a}, "vmovsldup ymm5, ymmword ptr [rdx]"},
    {0, 1, 'I', -1, 4, {0xc5,0xfa,0x16,0xf7}, "vmovshdup xmm6, xmm7"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x18,0x02}, "vbroadcastss ymm0, dword ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x79,0x18,0xca}, "vbroadcastss xmm1, xmm2"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x19,0xdc}, "vbroadcastsd ymm3, xmm4"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x19,0x2a}, "vbroadcastsd ymm5, qword ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x79,0x78,0xc1}, "vpbroadcastb xmm0, xmm1"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x78,0x12}, "vpbroadcastb ymm2, byte ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x79,0x1a}, "vpbroadcastw ymm3, word ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc4,0x42,0x79,0x79,0xc1}, "vpbroadcastw xmm8, xmm9"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x79,0x58,0xe5}, "vpbroadcastd xmm4, xmm5"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x59,0x32}, "vpbroadcastq ymm6, qword ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x5a,0x3a}, "vbroadcasti128 ymm7, xmmword ptr [rdx]"},
    {0, 1, 'I', -1, 5, {0xc4,0x62,0x7d,0x1a,0x02}, "vbroadcastf128 ymm8, xmmword ptr [rdx]"},
    {0, 0, 'S', -1, 6, {0x62,0xf2,0x7d,0x09,0x18,0xc1}, "vbroadcastss xmm0 {k1}, xmm1"},
    {0, 0, 'I', -1, 6, {0x62,0xf1,0x7c,0x09,0x28,0xc1}, "vmovaps xmm0 {k1}, xmm1"},
    {0, 0, 'I', -1, 6, {0x62,0xf1,0x7c,0x48,0x28,0xc1}, "vmovaps zmm0, zmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xfe,0xc3}, "paddd xmm0, xmm3"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xfe,0xe2}, "paddd xmm4, xmm2"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xfd,0xf1}, "paddw xmm6, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xfc,0x02}, "paddb xmm0, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xd4,0x0a}, "paddq xmm1, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0xc5,0xf1,0xfe,0xc2}, "vpaddd xmm0, xmm1, xmm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0xfe,0xc2}, "vpaddd ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xdd,0xd4,0x1a}, "vpaddq ymm3, ymm4, ymmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0xc4,0x41,0x29,0xfd,0xcb}, "vpaddw xmm9, xmm10, xmm11"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xf9,0xda}, "psubw xmm3, xmm2"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xf8,0xcf}, "psubb xmm1, xmm7"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xfa,0x12}, "psubd xmm2, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xfb,0xee}, "psubq xmm5, xmm6"},
    {1, 1, 'I', -1, 4, {0xc5,0xed,0xf9,0xcb}, "vpsubw ymm1, ymm2, ymm3"},
    {1, 1, 'I', -1, 4, {0xc5,0xf9,0xf8,0x02}, "vpsubb xmm0, xmm0, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xec,0xc1}, "paddsb xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xed,0x12}, "paddsw xmm2, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xdc,0xdc}, "paddusb xmm3, xmm4"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xdd,0xee}, "paddusw xmm5, xmm6"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xe8,0xc1}, "psubsb xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xe9,0xd3}, "psubsw xmm2, xmm3"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xd8,0x22}, "psubusb xmm4, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xd9,0xf7}, "psubusw xmm6, xmm7"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0xed,0xc2}, "vpaddsw ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xdd,0xd8,0xdd}, "vpsubusb ymm3, ymm4, ymm5"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xe0,0xc1}, "pavgb xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xe3,0x12}, "pavgw xmm2, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0xe0,0xc2}, "vpavgb ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xf6,0xc1}, "psadbw xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xf6,0x12}, "psadbw xmm2, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0xc5,0xdd,0xf6,0xdd}, "vpsadbw ymm3, ymm4, ymm5"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xd5,0xd8}, "pmullw xmm3, xmm0"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xd5,0x0a}, "pmullw xmm1, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0xd5,0xc2}, "vpmullw ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xe5,0xc1}, "pmulhw xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xe4,0xd3}, "pmulhuw xmm2, xmm3"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xf5,0xe5}, "pmaddwd xmm4, xmm5"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0xf5,0xc2}, "vpmaddwd ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xc1,0xe5,0x32}, "vpmulhw xmm6, xmm7, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x40,0xc1}, "pmulld xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xf4,0xd3}, "pmuludq xmm2, xmm3"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x28,0x22}, "pmuldq xmm4, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0xf4,0xc2}, "vpmuludq ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xda,0xc1}, "pminub xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xde,0xd3}, "pmaxub xmm2, xmm3"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xea,0xe5}, "pminsw xmm4, xmm5"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xee,0x32}, "pmaxsw xmm6, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x38,0xc1}, "pminsb xmm0, xmm1"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x3c,0xd3}, "pmaxsb xmm2, xmm3"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x39,0xe5}, "pminsd xmm4, xmm5"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x3d,0xf7}, "pmaxsd xmm6, xmm7"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x3a,0xc1}, "pminuw xmm0, xmm1"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x3e,0xd3}, "pmaxuw xmm2, xmm3"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x3b,0xe5}, "pminud xmm4, xmm5"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x3f,0xf7}, "pmaxud xmm6, xmm7"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0xde,0xc2}, "vpmaxub ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 5, {0xc4,0xe2,0x5d,0x39,0x1a}, "vpminsd ymm3, ymm4, ymmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x1c,0xc1}, "pabsb xmm0, xmm1"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x1d,0x12}, "pabsw xmm2, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x1e,0xdb}, "pabsd xmm3, xmm3"},
    {1, 1, 'I', -1, 5, {0xc4,0xe2,0x7d,0x1e,0xe5}, "vpabsd ymm4, ymm5"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x74,0xc1}, "pcmpeqb xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x75,0xd3}, "pcmpeqw xmm2, xmm3"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x76,0x22}, "pcmpeqd xmm4, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x74,0xed}, "pcmpeqb xmm5, xmm5"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x64,0xc1}, "pcmpgtb xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x65,0xd3}, "pcmpgtw xmm2, xmm3"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x66,0xe5}, "pcmpgtd xmm4, xmm5"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x29,0xf7}, "pcmpeqq xmm6, xmm7"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x37,0xc1}, "pcmpgtq xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0x74,0xc2}, "vpcmpeqb ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xd9,0x66,0xdd}, "vpcmpgtd xmm3, xmm4, xmm5"},
    {1, 1, 'I', -1, 4, {0xc5,0xf9,0x76,0xc0}, "vpcmpeqd xmm0, xmm0, xmm0"},
    {1, 1, 'I', -1, 4, {0xc5,0xf0,0x54,0xc2}, "vandps xmm0, xmm1, xmm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xf4,0x54,0x02}, "vandps ymm0, ymm1, ymmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0xc5,0xf8,0x57,0xc0}, "vxorps xmm0, xmm0, xmm0"},
    {1, 1, 'I', -1, 4, {0xc5,0xe4,0x57,0xdb}, "vxorps ymm3, ymm3, ymm3"},
    {1, 1, 'I', -1, 4, {0xc5,0xe9,0xef,0xcb}, "vpxor xmm1, xmm2, xmm3"},
    {1, 1, 'I', -1, 4, {0xc5,0xd0,0x55,0xe6}, "vandnps xmm4, xmm5, xmm6"},
    {1, 1, 'I', -1, 5, {0xc4,0xc1,0x3d,0x55,0xf9}, "vandnpd ymm7, ymm8, ymm9"},
    {1, 1, 'I', -1, 4, {0xc5,0xec,0x56,0xcb}, "vorps ymm1, ymm2, ymm3"},
    {1, 1, 'I', -1, 4, {0xc5,0x21,0xdb,0x12}, "vpand xmm10, xmm11, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0xc4,0x41,0x15,0xeb,0xe6}, "vpor ymm12, ymm13, ymm14"},
    {1, 1, 'I', -1, 4, {0xc5,0x79,0xdf,0xf9}, "vpandn xmm15, xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x63,0xc1}, "packsswb xmm0, xmm1"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x67,0xde}, "packuswb xmm3, xmm6"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x6b,0x12}, "packssdw xmm2, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x38,0x2b,0xe5}, "packusdw xmm4, xmm5"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0x67,0xc2}, "vpackuswb ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xd9,0x63,0xdd}, "vpacksswb xmm3, xmm4, xmm5"},
    {1, 1, 'I', -1, 5, {0xc4,0xc2,0x45,0x2b,0xf0}, "vpackusdw ymm6, ymm7, ymm8"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x60,0x02}, "punpcklbw xmm0, xmmword ptr [rdx]"},
    {1, 2, 'I', -1, 4, {0x66,0x0f,0x69,0xca}, "punpckhwd xmm1, xmm2"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x62,0x1a}, "punpckldq xmm3, xmmword ptr [rdx]"},
    {1, 2, 'I', -1, 4, {0x66,0x0f,0x6d,0x22}, "punpckhqdq xmm4, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 3, {0x0f,0x14,0x2a}, "unpcklps xmm5, xmmword ptr [rdx]"},
    {1, 2, 'I', -1, 4, {0x66,0x0f,0x15,0x32}, "unpckhpd xmm6, xmmword ptr [rdx]"},
    {1, 1, 'I', -1, 4, {0xc5,0xf1,0x60,0xc2}, "vpunpcklbw xmm0, xmm1, xmm2"},
    {1, 1, 'I', -1, 4, {0xc5,0xdd,0x6a,0xdd}, "vpunpckhdq ymm3, ymm4, ymm5"},
    {1, 1, 'I', -1, 4, {0xc5,0xc4,0x14,0x32}, "vunpcklps ymm6, ymm7, ymmword ptr [rdx]"},
    {1, 1, 'I', -1, 5, {0xc4,0x41,0x31,0x15,0xc2}, "vunpckhpd xmm8, xmm9, xmm10"},
    {1, 1, 'I', -1, 4, {0xc5,0xf5,0x6c,0xc2}, "vpunpcklqdq ymm0, ymm1, ymm2"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0xd7,0xc1}, "pmovmskb eax, xmm1"},
    {1, 1, 'I', -1, 5, {0x66,0x41,0x0f,0xd7,0xc9}, "pmovmskb ecx, xmm9"},
    {1, 1, 'I', -1, 4, {0xc5,0xfd,0xd7,0xc1}, "vpmovmskb eax, ymm1"},
    {1, 1, 'I', -1, 4, {0xc5,0xf9,0xd7,0xd3}, "vpmovmskb edx, xmm3"},
    {1, 1, 'I', -1, 3, {0x0f,0x50,0xc7}, "movmskps eax, xmm7"},
    {1, 1, 'I', -1, 4, {0x66,0x0f,0x50,0xc8}, "movmskpd ecx, xmm0"},
    {1, 1, 'I', -1, 4, {0xc5,0xfc,0x50,0xc1}, "vmovmskps eax, ymm1"},
    {1, 1, 'I', -1, 4, {0xc5,0xfd,0x50,0xf2}, "vmovmskpd esi, ymm2"},
    {1, 1, 'I', -1, 4, {0x45,0x0f,0x50,0xcf}, "movmskps r9d, xmm15"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x72,0xe7,0x1f}, "psrad xmm7, 31"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x71,0xe6,0x08}, "psraw xmm6, 8"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x72,0xf0,0x10}, "pslld xmm0, 16"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x71,0xd1,0x00}, "psrlw xmm1, 0"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x71,0xd2,0x0f}, "psrlw xmm2, 15"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x71,0xd3,0x10}, "psrlw xmm3, 16"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x71,0xe4,0xc8}, "psraw xmm4, 200"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x72,0xf5,0x21}, "pslld xmm5, 33"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x72,0xd6,0x01}, "psrld xmm6, 1"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x71,0xf7,0x07}, "psllw xmm7, 7"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xd2,0x05}, "psrlq xmm2, 5"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xf3,0x40}, "psllq xmm3, 64"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xd4,0x3f}, "psrlq xmm4, 63"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xf5,0x00}, "psllq xmm5, 0"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xd8,0x08}, "psrldq xmm0, 8"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xd9,0x03}, "psrldq xmm1, 3"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xda,0x10}, "psrldq xmm2, 16"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xdb,0x14}, "psrldq xmm3, 20"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xfc,0x04}, "pslldq xmm4, 4"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xfd,0x0f}, "pslldq xmm5, 15"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0x73,0xfe,0x00}, "pslldq xmm6, 0"},
    {1, 1, 'I', -1, 5, {0xc5,0xf9,0x72,0xd1,0x03}, "vpsrld xmm0, xmm1, 3"},
    {1, 1, 'I', -1, 5, {0xc5,0xed,0x72,0xe3,0x1f}, "vpsrad ymm2, ymm3, 31"},
    {1, 1, 'I', -1, 5, {0xc5,0xdd,0x71,0xf5,0x11}, "vpsllw ymm4, ymm5, 17"},
    {1, 1, 'I', -1, 5, {0xc5,0xfd,0x73,0xd9,0x05}, "vpsrldq ymm0, ymm1, 5"},
    {1, 1, 'I', -1, 5, {0xc5,0xc9,0x73,0xff,0x09}, "vpslldq xmm6, xmm7, 9"},
    {1, 1, 'I', -1, 6, {0xc4,0xc1,0x3d,0x73,0xd1,0x28}, "vpsrlq ymm8, ymm9, 40"},
    {1, 1, 'I', 3, 4, {0x66,0x0f,0xd2,0xd3}, "psrld xmm2, xmm3"},
    {1, 1, 'I', 2, 4, {0x66,0x0f,0xe1,0xca}, "psraw xmm1, xmm2"},
    {1, 1, 'I', 1, 4, {0x66,0x0f,0xf3,0xc1}, "psllq xmm0, xmm1"},
    {1, 1, 'I', 99, 4, {0x66,0x0f,0xd1,0x02}, "psrlw xmm0, xmmword ptr [rdx]"},
    {1, 1, 'I', 6, 4, {0x66,0x0f,0xd3,0xee}, "psrlq xmm5, xmm6"},
    {1, 1, 'I', 8, 5, {0x66,0x41,0x0f,0xf2,0xf8}, "pslld xmm7, xmm8"},
    {1, 1, 'I', 99, 4, {0x66,0x0f,0xe2,0x1a}, "psrad xmm3, xmmword ptr [rdx]"},
    {1, 1, 'I', 2, 4, {0xc5,0xf5,0xf1,0xc2}, "vpsllw ymm0, ymm1, xmm2"},
    {1, 1, 'I', 5, 4, {0xc5,0xdd,0xe2,0xdd}, "vpsrad ymm3, ymm4, xmm5"},
    {1, 1, 'I', 99, 4, {0xc5,0xc1,0xd3,0x32}, "vpsrlq xmm6, xmm7, xmmword ptr [rdx]"},
    {1, 0, 'I', -1, 3, {0x0f,0xfe,0xc1}, "paddd mm0, mm1"},
    {1, 0, 'I', -1, 3, {0x0f,0xf9,0x12}, "psubw mm2, qword ptr [rdx]"},
    {1, 0, 'I', -1, 3, {0x0f,0xd7,0xc1}, "pmovmskb eax, mm1"},
    {1, 0, 'I', -1, 4, {0x0f,0x73,0xd0,0x03}, "psrlq mm0, 3"},
    {1, 0, 'I', -1, 3, {0x0f,0xf1,0xca}, "psllw mm1, mm2"},
    {1, 0, 'I', -1, 3, {0x0f,0x60,0xc1}, "punpcklbw mm0, mm1"},
    {1, 0, 'I', -1, 3, {0x0f,0xef,0xd3}, "pxor mm2, mm3"},
    {1, 0, 'I', -1, 3, {0x0f,0x74,0xc1}, "pcmpeqb mm0, mm1"},
    {1, 0, 'I', -1, 3, {0x0f,0x67,0xe5}, "packuswb mm4, mm5"},
    {1, 0, 'I', -1, 3, {0x0f,0xd5,0xf7}, "pmullw mm6, mm7"},
    {1, 0, 'I', -1, 6, {0x62,0xf1,0x75,0x09,0xfe,0xc2}, "vpaddd xmm0 {k1}, xmm1, xmm2"},
    {1, 0, 'I', -1, 6, {0x62,0xf1,0x75,0x48,0xfe,0xc2}, "vpaddd zmm0, zmm1, zmm2"},
    {2, 1, 'S', -1, 4, {0xc5,0xf0,0x59,0xc2}, "vmulps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 4, {0xc5,0xf4,0x59,0xc2}, "vmulps ymm0, ymm1, ymm2"},
    {2, 1, 'S', -1, 4, {0xc5,0xd8,0x58,0x1a}, "vaddps xmm3, xmm4, xmmword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xcc,0x5e,0x2a}, "vdivps ymm5, ymm6, ymmword ptr [rdx]"},
    {2, 1, 'S', -1, 5, {0xc4,0xc1,0x40,0x5c,0xf8}, "vsubps xmm7, xmm7, xmm8"},
    {2, 1, 'S', -1, 4, {0xc5,0xf2,0x5c,0xc2}, "vsubss xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 4, {0xc5,0xda,0x58,0x1a}, "vaddss xmm3, xmm4, dword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xd2,0x59,0xed}, "vmulss xmm5, xmm5, xmm5"},
    {2, 1, 'S', -1, 5, {0xc4,0xc1,0x42,0x5e,0xf0}, "vdivss xmm6, xmm7, xmm8"},
    {2, 1, 'S', -1, 4, {0xc5,0xf0,0x5d,0xc2}, "vminps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 4, {0xc5,0xdc,0x5f,0xdd}, "vmaxps ymm3, ymm4, ymm5"},
    {2, 1, 'S', -1, 4, {0xc5,0xc2,0x5d,0x32}, "vminss xmm6, xmm7, dword ptr [rdx]"},
    {2, 1, 'S', -1, 5, {0xc4,0x41,0x32,0x5f,0xc2}, "vmaxss xmm8, xmm9, xmm10"},
    {2, 1, 'S', -1, 3, {0x0f,0x51,0xc1}, "sqrtps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x51,0xc1}, "sqrtss xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x51,0x12}, "sqrtss xmm2, dword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xfc,0x51,0xc1}, "vsqrtps ymm0, ymm1"},
    {2, 1, 'S', -1, 4, {0xc5,0xf2,0x51,0xc2}, "vsqrtss xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 4, {0xc5,0xf8,0x51,0x1a}, "vsqrtps xmm3, xmmword ptr [rdx]"},
    {2, 1, 'S', -1, 3, {0x0f,0x52,0xc1}, "rsqrtps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x52,0xd3}, "rsqrtss xmm2, xmm3"},
    {2, 1, 'S', -1, 3, {0x0f,0x53,0x22}, "rcpps xmm4, xmmword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x53,0xee}, "rcpss xmm5, xmm6"},
    {2, 1, 'S', -1, 4, {0xc5,0xfc,0x52,0xc1}, "vrsqrtps ymm0, ymm1"},
    {2, 1, 'S', -1, 4, {0xc5,0xf2,0x53,0xc2}, "vrcpss xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 4, {0xc5,0xfc,0x53,0xdc}, "vrcpps ymm3, ymm4"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x08,0xc1,0x00}, "roundps xmm0, xmm1, 0"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x08,0xc1,0x01}, "roundps xmm0, xmm1, 1"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x08,0xc1,0x02}, "roundps xmm0, xmm1, 2"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x08,0xc1,0x03}, "roundps xmm0, xmm1, 3"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x08,0xc1,0x04}, "roundps xmm0, xmm1, 4"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x08,0x12,0x09}, "roundps xmm2, xmmword ptr [rdx], 9"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x0a,0xc1,0x04}, "roundss xmm0, xmm1, 4"},
    {2, 1, 'S', -1, 6, {0x66,0x0f,0x3a,0x0a,0x1a,0x0a}, "roundss xmm3, dword ptr [rdx], 10"},
    {2, 1, 'S', -1, 6, {0xc4,0xe3,0x7d,0x08,0xc1,0x01}, "vroundps ymm0, ymm1, 1"},
    {2, 1, 'S', -1, 6, {0xc4,0xe3,0x79,0x08,0xe5,0x0c}, "vroundps xmm4, xmm5, 12"},
    {2, 1, 'S', -1, 6, {0xc4,0xc3,0x41,0x0a,0xf0,0x03}, "vroundss xmm6, xmm7, xmm8, 3"},
    {2, 1, 'S', -1, 5, {0x41,0x0f,0xc2,0xf6,0x01}, "cmpltps xmm6, xmm14"},
    {2, 1, 'S', -1, 5, {0x41,0x0f,0xc2,0xfa,0x01}, "cmpltps xmm7, xmm10"},
    {2, 1, 'S', -1, 4, {0x0f,0xc2,0xc1,0x00}, "cmpeqps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0x0f,0xc2,0xc1,0x02}, "cmpleps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0x0f,0xc2,0xc1,0x03}, "cmpunordps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0x0f,0xc2,0xc1,0x04}, "cmpneqps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0x0f,0xc2,0xc1,0x05}, "cmpnltps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0x0f,0xc2,0xc1,0x06}, "cmpnleps xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0x0f,0xc2,0x02,0x07}, "cmpordps xmm0, xmmword ptr [rdx]"},
    {2, 1, 'S', -1, 5, {0xf3,0x0f,0xc2,0xd3,0x01}, "cmpltss xmm2, xmm3"},
    {2, 1, 'S', -1, 5, {0xf3,0x0f,0xc2,0x22,0x00}, "cmpeqss xmm4, dword ptr [rdx]"},
    {2, 1, 'S', -1, 5, {0xf3,0x0f,0xc2,0xed,0x06}, "cmpnless xmm5, xmm5"},
    {2, 1, 'S', -1, 5, {0xc5,0xf4,0xc2,0xc2,0x01}, "vcmpltps ymm0, ymm1, ymm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xd8,0xc2,0xdd,0x0d}, "vcmpgeps xmm3, xmm4, xmm5"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x08}, "vcmpeq_uqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x09}, "vcmpngeps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x0a}, "vcmpngtps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x0b}, "vcmpfalseps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x0c}, "vcmpneq_oqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf4,0xc2,0x02,0x0e}, "vcmpgtps ymm0, ymm1, ymmword ptr [rdx]"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x0f}, "vcmptrueps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x10}, "vcmpeq_osps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x11}, "vcmplt_oqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x13}, "vcmpunord_sps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf4,0xc2,0xc2,0x14}, "vcmpneq_usps ymm0, ymm1, ymm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x15}, "vcmpnlt_uqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x17}, "vcmpord_sps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x18}, "vcmpeq_usps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x19}, "vcmpnge_uqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x1a}, "vcmpngt_uqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x1b}, "vcmpfalse_osps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x1c}, "vcmpneq_osps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x1d}, "vcmpge_oqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x1e}, "vcmpgt_oqps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 5, {0xc5,0xf0,0xc2,0xc2,0x1f}, "vcmptrue_usps xmm0, xmm1, xmm2"},
    {2, 1, 'S', -1, 6, {0xc4,0xc1,0x42,0xc2,0xf0,0x02}, "vcmpless xmm6, xmm7, xmm8"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x5b,0xc1}, "cvttps2dq xmm0, xmm1"},
    {2, 1, 'S', -1, 4, {0x66,0x0f,0x5b,0xd3}, "cvtps2dq xmm2, xmm3"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x5b,0x22}, "cvttps2dq xmm4, xmmword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xfe,0x5b,0xc1}, "vcvttps2dq ymm0, ymm1"},
    {2, 1, 'S', -1, 4, {0xc5,0xfd,0x5b,0x12}, "vcvtps2dq ymm2, ymmword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xfc,0x5b,0xdc}, "vcvtdq2ps ymm3, ymm4"},
    {2, 1, 'S', -1, 4, {0xc5,0xf8,0x5b,0xee}, "vcvtdq2ps xmm5, xmm6"},
    {2, 1, 'S', -1, 4, {0xc5,0xf2,0x5a,0xc2}, "vcvtss2sd xmm0, xmm1, xmm2"},
    {2, 1, 'D', -1, 4, {0xc5,0xf1,0x59,0xc2}, "vmulpd xmm0, xmm1, xmm2"},
    {2, 1, 'D', -1, 4, {0xc5,0xf5,0x58,0xc2}, "vaddpd ymm0, ymm1, ymm2"},
    {2, 1, 'D', -1, 4, {0xc5,0xdb,0x5c,0x1a}, "vsubsd xmm3, xmm4, qword ptr [rdx]"},
    {2, 1, 'D', -1, 4, {0xc5,0xcb,0x59,0xef}, "vmulsd xmm5, xmm6, xmm7"},
    {2, 1, 'D', -1, 5, {0xc4,0x41,0x3b,0x5e,0xc1}, "vdivsd xmm8, xmm8, xmm9"},
    {2, 1, 'D', -1, 4, {0xc5,0x25,0x5e,0x12}, "vdivpd ymm10, ymm11, ymmword ptr [rdx]"},
    {2, 1, 'D', -1, 4, {0xc5,0xf5,0x5d,0xc2}, "vminpd ymm0, ymm1, ymm2"},
    {2, 1, 'D', -1, 4, {0xc5,0xdb,0x5f,0xdd}, "vmaxsd xmm3, xmm4, xmm5"},
    {2, 1, 'D', -1, 4, {0x66,0x0f,0x51,0xc1}, "sqrtpd xmm0, xmm1"},
    {2, 1, 'D', -1, 4, {0xf2,0x0f,0x51,0x12}, "sqrtsd xmm2, qword ptr [rdx]"},
    {2, 1, 'D', -1, 4, {0xc5,0xfd,0x51,0xdc}, "vsqrtpd ymm3, ymm4"},
    {2, 1, 'D', -1, 4, {0xc5,0xcb,0x51,0xef}, "vsqrtsd xmm5, xmm6, xmm7"},
    {2, 1, 'D', -1, 6, {0x66,0x0f,0x3a,0x09,0xc9,0x01}, "roundpd xmm1, xmm1, 1"},
    {2, 1, 'D', -1, 6, {0x66,0x0f,0x3a,0x09,0xc2,0x00}, "roundpd xmm0, xmm2, 0"},
    {2, 1, 'D', -1, 6, {0x66,0x0f,0x3a,0x09,0x02,0x06}, "roundpd xmm0, xmmword ptr [rdx], 6"},
    {2, 1, 'D', -1, 6, {0x66,0x0f,0x3a,0x0b,0x02,0x02}, "roundsd xmm0, qword ptr [rdx], 2"},
    {2, 1, 'D', -1, 6, {0x66,0x0f,0x3a,0x0b,0xdc,0x0c}, "roundsd xmm3, xmm4, 12"},
    {2, 1, 'D', -1, 6, {0xc4,0xe3,0x7d,0x09,0xc1,0x03}, "vroundpd ymm0, ymm1, 3"},
    {2, 1, 'D', -1, 6, {0xc4,0xe3,0x71,0x0b,0xc2,0x0e}, "vroundsd xmm0, xmm1, xmm2, 14"},
    {2, 1, 'D', -1, 5, {0x66,0x0f,0xc2,0xc1,0x01}, "cmpltpd xmm0, xmm1"},
    {2, 1, 'D', -1, 5, {0x66,0x0f,0xc2,0x12,0x06}, "cmpnlepd xmm2, xmmword ptr [rdx]"},
    {2, 1, 'D', -1, 5, {0xf2,0x0f,0xc2,0xdc,0x03}, "cmpunordsd xmm3, xmm4"},
    {2, 1, 'D', -1, 5, {0xc5,0xf5,0xc2,0xc2,0x1d}, "vcmppd ymm0, ymm1, ymm2, 29"},
    {2, 1, 'D', -1, 5, {0xc5,0xdb,0xc2,0x1a,0x12}, "vcmpsd xmm3, xmm4, qword ptr [rdx], 18"},
    {2, 1, 'D', -1, 5, {0xc5,0xc9,0xc2,0xef,0x08}, "vcmppd xmm5, xmm6, xmm7, 8"},
    {2, 1, 'D', -1, 4, {0x66,0x0f,0xe6,0xc1}, "cvttpd2dq xmm0, xmm1"},
    {2, 1, 'D', -1, 4, {0xf2,0x0f,0xe6,0xd3}, "cvtpd2dq xmm2, xmm3"},
    {2, 1, 'D', -1, 4, {0x66,0x0f,0xe6,0x22}, "cvttpd2dq xmm4, xmmword ptr [rdx]"},
    {2, 1, 'D', -1, 4, {0xc5,0xfd,0xe6,0xc1}, "vcvttpd2dq xmm0, ymm1"},
    {2, 1, 'D', -1, 4, {0xc5,0xff,0xe6,0xd3}, "vcvtpd2dq xmm2, ymm3"},
    {2, 1, 'D', -1, 4, {0xc5,0xfb,0xe6,0xe5}, "vcvtpd2dq xmm4, xmm5"},
    {2, 1, 'D', -1, 4, {0xc5,0xfd,0x5a,0xc1}, "vcvtpd2ps xmm0, ymm1"},
    {2, 1, 'D', -1, 4, {0xc5,0xf9,0x5a,0xd3}, "vcvtpd2ps xmm2, xmm3"},
    {2, 1, 'D', -1, 4, {0xc5,0xf3,0x5a,0xc2}, "vcvtsd2ss xmm0, xmm1, xmm2"},
    {2, 1, 'D', -1, 4, {0xc5,0xdb,0x5a,0x1a}, "vcvtsd2ss xmm3, xmm4, qword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xfc,0x5a,0xc1}, "vcvtps2pd ymm0, xmm1"},
    {2, 1, 'S', -1, 4, {0xc5,0xf8,0x5a,0xd3}, "vcvtps2pd xmm2, xmm3"},
    {2, 1, 'S', -1, 4, {0xc5,0xfc,0x5a,0x22}, "vcvtps2pd ymm4, xmmword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xca,0x5a,0x2a}, "vcvtss2sd xmm5, xmm6, dword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x2d,0xc1}, "cvtss2si eax, xmm1"},
    {2, 1, 'S', -1, 5, {0xf3,0x48,0x0f,0x2d,0xc1}, "cvtss2si rax, xmm1"},
    {2, 1, 'S', -1, 4, {0xf3,0x0f,0x2d,0x0a}, "cvtss2si ecx, dword ptr [rdx]"},
    {2, 1, 'S', -1, 4, {0xc5,0xfa,0x2d,0xc2}, "vcvtss2si eax, xmm2"},
    {2, 1, 'S', -1, 5, {0xf3,0x4d,0x0f,0x2d,0xcf}, "cvtss2si r9, xmm15"},
    {2, 1, 'D', -1, 4, {0xf2,0x0f,0x2d,0xc1}, "cvtsd2si eax, xmm1"},
    {2, 1, 'D', -1, 5, {0xf2,0x48,0x0f,0x2d,0xc2}, "cvtsd2si rax, xmm2"},
    {2, 1, 'D', -1, 5, {0xf2,0x44,0x0f,0x2d,0x0a}, "cvtsd2si r9d, qword ptr [rdx]"},
    {2, 1, 'D', -1, 5, {0xc4,0xe1,0xfb,0x2d,0xc3}, "vcvtsd2si rax, xmm3"},
    {2, 1, 'D', -1, 4, {0xf2,0x0f,0x2d,0xf4}, "cvtsd2si esi, xmm4"},
    {2, 1, 'I', -1, 4, {0xc5,0xfe,0xe6,0xc1}, "vcvtdq2pd ymm0, xmm1"},
    {2, 1, 'I', -1, 4, {0xc5,0xfa,0xe6,0x12}, "vcvtdq2pd xmm2, qword ptr [rdx]"},
    {2, 1, 'I', -1, 4, {0xc5,0xf2,0x2a,0xc0}, "vcvtsi2ss xmm0, xmm1, eax"},
    {2, 1, 'I', -1, 5, {0xc4,0xe1,0xe3,0x2a,0xd0}, "vcvtsi2sd xmm2, xmm3, rax"},
    {2, 1, 'I', -1, 4, {0xc5,0xd3,0x2a,0x22}, "vcvtsi2sd xmm4, xmm5, dword ptr [rdx]"},
    {2, 1, 'I', -1, 5, {0xc4,0xe1,0xc2,0x2a,0x32}, "vcvtsi2ss xmm6, xmm7, qword ptr [rdx]"},
    {0, 1, 'I', -1, 7, {0xc4,0xe3,0x65,0x18,0x1c,0x0a,0x01}, "vinsertf128 ymm3, ymm3, xmmword ptr [rdx + rcx*1], 1"},
    {0, 1, 'I', -1, 5, {0x0f,0x16,0x64,0x8a,0x04}, "movhps xmm4, qword ptr [rdx + rcx*4 + 4]"},
    {0, 1, 'I', -1, 4, {0x0f,0x17,0x2c,0x8a}, "movhps qword ptr [rdx + rcx*4], xmm5"},
    {0, 1, 'I', -1, 8, {0xc4,0xe3,0x7d,0x19,0x74,0x4a,0x10,0x01}, "vextractf128 xmmword ptr [rdx + rcx*2 + 16], ymm6, 1"},
    {0, 1, 'I', -1, 8, {0xc5,0x7a,0x10,0x82,0x04,0x10,0x00,0x00}, "vmovss xmm8, dword ptr [rdx + 4100]"},
    {1, 1, 'I', -1, 5, {0x66,0x0f,0xfe,0x04,0x8a}, "paddd xmm0, xmmword ptr [rdx + rcx*4]"},
    {1, 1, 'I', 99, 5, {0x66,0x0f,0xd1,0x0c,0x8a}, "psrlw xmm1, xmmword ptr [rdx + rcx*4]"},
    {1, 1, 'I', -1, 8, {0xc5,0xe5,0xdb,0x92,0x00,0x10,0x00,0x00}, "vpand ymm2, ymm3, ymmword ptr [rdx + 4096]"},
    {1, 2, 'I', -1, 9, {0x66,0x44,0x0f,0xef,0x25,0x00,0x02,0x00,0x00}, "pxor xmm12, xmmword ptr [rip + 512]"},
    {1, 1, 'S', -1, 8, {0xc5,0x20,0x54,0x15,0x00,0x02,0x00,0x00}, "vandps xmm10, xmm11, xmmword ptr [rip + 512]"},
    {2, 1, 'S', -1, 6, {0xc5,0xec,0x59,0x4c,0x4a,0x08}, "vmulps ymm1, ymm2, ymmword ptr [rdx + rcx*2 + 8]"},
    {2, 1, 'S', -1, 8, {0xf3,0x0f,0x5b,0xba,0x00,0x10,0x00,0x00}, "cvttps2dq xmm7, xmmword ptr [rdx + 4096]"},
    {2, 1, 'S', -1, 5, {0xf3,0x0f,0x2d,0x04,0x8a}, "cvtss2si eax, dword ptr [rdx + rcx*4]"},
    {2, 1, 'D', -1, 9, {0xf2,0x44,0x0f,0x51,0x0d,0x00,0x01,0x00,0x00}, "sqrtsd xmm9, qword ptr [rip + 256]"},
    {2, 0, 'S', -1, 6, {0x62,0xf1,0x74,0x09,0x58,0xc2}, "vaddps xmm0 {k1}, xmm1, xmm2"},
    {2, 0, 'S', -1, 6, {0x62,0xf1,0x74,0x48,0x58,0xc2}, "vaddps zmm0, zmm1, zmm2"},
    {2, 0, 'S', -1, 6, {0x62,0xf1,0x7c,0x09,0x51,0xc1}, "vsqrtps xmm0 {k1}, xmm1"},
};
#define NFORMS (sizeof(FORMS) / sizeof(FORMS[0]))
static const char* const FAM_NAME[3] = { "moves", "int", "fp" };

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static const uint32_t F32[] = {
    0x00000000u, 0x80000000u, 0x00000001u, 0x80000001u, 0x007fffffu, 0x807fffffu, 0x00800000u,
    0x80800000u, 0x3f800000u, 0xbf800000u, 0x3fc00000u, 0xbfc00000u, 0x3f000000u, 0xbf000000u,
    0x40200000u, 0xc0200000u, 0x3f400000u, 0x7f7fffffu, 0xff7fffffu, 0x7f800000u, 0xff800000u,
    0x7fc00000u, 0xffc00000u, 0x7fc12345u, 0xffd54321u, 0x7f800001u, 0x7fa00000u, 0xff800123u,
    0x4f000000u, 0xcf000000u, 0x4effffffu, 0xcf000001u, 0x4f800000u, 0x5f000000u, 0xdf000000u,
    0x4b000000u, 0x4b7fffffu, 0x40490fdbu, 0xbeaaaaabu, 0x3eaaaaabu,
};
static const uint64_t F64[] = {
    0x0000000000000000ull, 0x8000000000000000ull, 0x0000000000000001ull, 0x800fffffffffffffull,
    0x0010000000000000ull, 0x3ff0000000000000ull, 0xbff0000000000000ull, 0x3ff8000000000000ull,
    0xbff8000000000000ull, 0x3fe0000000000000ull, 0xbfe0000000000000ull, 0x4004000000000000ull,
    0xc004000000000000ull, 0x7fefffffffffffffull, 0xffefffffffffffffull, 0x7ff0000000000000ull,
    0xfff0000000000000ull, 0x7ff8000000000000ull, 0xfff8000000000000ull, 0x7ff8000000012345ull,
    0xfffc000000054321ull, 0x7ff0000000000001ull, 0x7ff4000000000000ull, 0xfff0000000000123ull,
    0x41dfffffffc00000ull, 0x41dfffffffe00000ull, 0x41dffffffff00000ull, 0xc1e0000000000000ull,
    0x41e0000000000000ull, 0xc1e0000000100000ull, 0xc1e0000000200000ull, 0x41f0000000000000ull,
    0x43e0000000000000ull, 0xc3e0000000000000ull, 0x4330000000000000ull, 0x400921fb54442d18ull,
};
#define NF32 (sizeof(F32) / sizeof(F32[0]))
#define NF64 (sizeof(F64) / sizeof(F64[0]))

static uint32_t f32_val(void) {
    uint64_t r = rnd();
    switch (r % 5) {
        case 0: case 1: return F32[(r >> 8) % NF32];
        case 2: return (uint32_t)(r >> 16);
        default: {                                     /* «хорошие» числа: целые, половинки, дроби */
            float v = (float)((int)((r >> 20) % 2001) - 1000) / (float)(1 + (r >> 40) % 8);
            uint32_t b; memcpy(&b, &v, 4); return b;
        }
    }
}
static uint64_t f64_val(void) {
    uint64_t r = rnd();
    switch (r % 5) {
        case 0: case 1: return F64[(r >> 8) % NF64];
        case 2: return rnd();
        default: {
            double v = (double)((int64_t)((r >> 20) % 4000001) - 2000000) / (double)(1 + (r >> 44) % 8);
            uint64_t b; memcpy(&b, &v, 8); return b;
        }
    }
}
static uint64_t int_lane(unsigned bytes) {           /* особые значения ширины дорожки */
    static const uint64_t e[] = { 0, 1, ~0ull, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff,
                                  0x80000000u, 0xffffffffu, 0x7fffffffffffffffull, 0x8000000000000000ull,
                                  0xfe, 0x100, 0xff00, 0x10000 };
    uint64_t r = rnd();
    uint64_t v = (r & 3) ? rnd() : e[(r >> 8) % (sizeof e / sizeof e[0])];
    if (bytes < 8) {
        uint64_t m = (1ull << (bytes * 8)) - 1;
        if (!(r & 3)) {                              /* INT_MIN/MAX именно этой ширины */
            unsigned k = (unsigned)((r >> 16) % 3);
            v = k == 0 ? (m >> 1) : k == 1 ? ((m >> 1) + 1) : v;
        }
        v &= m;
    }
    return v;
}
static void fill16(uint8_t* p, char vt) {
    unsigned i;
    if (vt == 'S') {
        for (i = 0; i < 4; i++) { uint32_t v = f32_val(); memcpy(p + 4 * i, &v, 4); }
    } else if (vt == 'D') {
        for (i = 0; i < 2; i++) { uint64_t v = f64_val(); memcpy(p + 8 * i, &v, 8); }
    } else {
        unsigned lane = 1u << (rnd() % 4), n;
        for (n = 0; n < 16; n += lane) { uint64_t v = int_lane(lane); memcpy(p + n, &v, lane); }
    }
}

/* Окно данных у rdx и ДАЛЬНЕЕ окно: [rdx+4096] и [rdx+4100] попадают в data+FAR_OFF..+DATA_LEN,
 * засеваются каждый случай так же, как ближнее, и сверяются так же — нули там не отличили бы
 * неверный адрес от верного. */
enum { DATA_WIN = 64, DATA_LEN = 320, FAR_OFF = 4096 };
/* Цель [rip+disp] (256 и 512 байт за командой) лежит в странице кода формы: она заполняется ОДИН раз
 * на форму, до разбора, конечными положительными значениями типа формы — корень из отрицательного
 * ушёл бы в медленный путь, и контроль не увидел бы выпуска; нули не отличили бы неверный адрес. */
static void fill_rip_window(uint8_t* p, size_t len, char vt) {
    size_t i;
    for (i = 0; i + 8 <= len; i += 8) {
        if (vt == 'D') {
            double v = (double)(rnd() % 1000000u + 1u) / 7.0;
            memcpy(p + i, &v, 8);
        } else if (vt == 'S') {
            float v[2] = { (float)(rnd() % 100000u + 1u) / 3.0f, (float)(rnd() % 100000u + 1u) / 3.0f };
            memcpy(p + i, v, 8);
        } else {
            uint64_t v = rnd();
            memcpy(p + i, &v, 8);
        }
    }
}

static const uint32_t MXCSR_SET[] = { 0x1f80, 0x3f80, 0x5f80, 0x7f80, 0x1fc0, 0x9f80, 0x9fc0 };

struct seed { uint8_t xmm[16][16], yhi[16][16], zhi[16][32]; uint64_t k[8], gpr[16], mm[8]; uint8_t mem[DATA_LEN];
              uint8_t far[DATA_LEN]; uint32_t mxcsr; unsigned off; bool fl[6]; };

static void make_seed(struct seed* s, const struct form* f) {
    unsigned i;
    for (i = 0; i < 16; i++) { fill16(s->xmm[i], f->vt); fill16(s->yhi[i], f->vt); }
    for (i = 0; i < 16; i++) for (unsigned j = 0; j < 32; j += 8) { uint64_t v = rnd(); memcpy(s->zhi[i] + j, &v, 8); }
    for (i = 0; i < 8; i++) { s->k[i] = rnd(); s->mm[i] = int_lane(8); }
    for (i = 0; i < 16; i++) s->gpr[i] = (i == 0 || i == 1) ? int_lane(8) : rnd();
    s->gpr[2] = (rnd() % 4) * 4;                     /* rcx — индекс в формах [rdx + rcx*k]: окно не покидаем */
    for (i = 0; i < DATA_LEN; i += 16) { fill16(s->mem + i, f->vt); fill16(s->far + i, f->vt); }
    s->mxcsr = f->fam == 2 ? MXCSR_SET[rnd() % (sizeof MXCSR_SET / sizeof MXCSR_SET[0])] : 0x1f80;
    s->off = (rnd() & 1) ? (unsigned)(rnd() % 3) * 16u : 1u + (unsigned)(rnd() % 15);
    for (i = 0; i < 6; i++) s->fl[i] = (rnd() & 1) != 0;
    if (strstr(f->name, "sqrt")) {                  /* корень из отрицательного — NaN и медленный путь: */
        uint8_t* regs[4] = { &s->xmm[0][0], &s->yhi[0][0], s->mem, s->far }; /* 7/8 дорожек неотрицательны, */
        size_t lens[4] = { sizeof s->xmm, sizeof s->yhi, DATA_LEN, DATA_LEN }; /* иначе у ymm быстрый путь */
        for (unsigned r = 0; r < 4; r++)                                /* почти не исполняется        */
            for (size_t b = 0; b + 4 <= lens[r]; b += 4)
                if (rnd() % 8) regs[r][b + 3] &= 0x7f;
    }
    if (f->cnt >= 0) {                              /* счётчик сдвига: чаще малый, чтобы сдвиг был виден */
        uint64_t c = (rnd() % 5) ? (rnd() % 72) : rnd();
        if (f->cnt == 99) memcpy(s->mem + DATA_WIN + s->off, &c, 8);
        else memcpy(s->xmm[f->cnt], &c, 8);
    }
}

static void apply_seed(hb_context_t* c, const struct seed* s, uint64_t base, uint8_t* stack, uint8_t* data) {
    uint64_t* g = &c->regs.x64.rax;
    unsigned i;
    memset(&c->regs, 0, sizeof c->regs);
    for (i = 0; i < 16; i++) g[i] = s->gpr[i];      /* rax rbx rcx rdx rsi rdi rsp rbp r8..r15 */
    c->regs.x64.rdx = (uint64_t)(uintptr_t)(data + DATA_WIN + s->off);
    c->regs.x64.rsp = (uint64_t)(uintptr_t)(stack + 0x8000);
    memcpy(c->regs.x64.xmm, s->xmm, sizeof s->xmm);
    memcpy(c->ymm_hi, s->yhi, sizeof s->yhi);
    memcpy(c->zmm_hi, s->zhi, sizeof s->zhi);
    memcpy(c->k, s->k, sizeof s->k);
    memcpy(c->mm, s->mm, sizeof s->mm);
    memset(&c->x87_64, 0, sizeof c->x87_64);
    c->x87_64.control_word = 0x037f;
    memset(c->xmm_ext, 0, sizeof c->xmm_ext);
    memset(c->ymm_hi_ext, 0, sizeof c->ymm_hi_ext);
    memset(c->zmm_hi_ext, 0, sizeof c->zmm_hi_ext);
    memcpy(data, s->mem, DATA_LEN);
    memcpy(data + FAR_OFF, s->far, DATA_LEN);
    c->mxcsr = s->mxcsr;
    c->pc = base; c->regs.x64.rip = base;
    c->regs.x64.rflags = 0x202;
    c->flags.zf = s->fl[0]; c->flags.sf = s->fl[1]; c->flags.cf = s->fl[2];
    c->flags.of = s->fl[3]; c->flags.pf = s->fl[4]; c->flags.af = s->fl[5];
    memset(&c->lazy_flags, 0, sizeof c->lazy_flags);
    c->lazy_flags.pending = true; c->lazy_flags.kind = HB_LAZY_FLAGS_SUB; c->lazy_flags.width = 8;
    c->lazy_flags.lhs = s->gpr[3]; c->lazy_flags.rhs = s->gpr[5]; c->lazy_flags.result = s->gpr[3] - s->gpr[5];
    c->lazy_flags.valid_mask = 0x3f;
}

/* Первое расхождение по имени поля; NULL — совпало всё. */
static const char* diff_of(hb_context_t* a, hb_context_t* b, const uint8_t* da, const uint8_t* db,
                           int* idx) {
    uint64_t* ga = &a->regs.x64.rax; uint64_t* gb = &b->regs.x64.rax;
    unsigned i;
    *idx = -1;
    for (i = 0; i < 16; i++) {
        if (i == 3) {                                /* rdx: порядок полей rax rbx rcx rdx ... */
            if (ga[3] != gb[3] &&                   /* указатель в своё окно ИЛИ записанное значение */
                ga[3] - (uint64_t)(uintptr_t)da != gb[3] - (uint64_t)(uintptr_t)db) { *idx = 3; return "gpr"; }
        } else if (ga[i] != gb[i]) { *idx = (int)i; return "gpr"; }
    }
    for (i = 0; i < 16; i++) if (memcmp(a->regs.x64.xmm[i], b->regs.x64.xmm[i], 16)) { *idx = (int)i; return "xmm"; }
    for (i = 0; i < 16; i++) if (memcmp(a->ymm_hi[i], b->ymm_hi[i], 16)) { *idx = (int)i; return "ymm_hi"; }
    for (i = 0; i < 16; i++) if (memcmp(a->zmm_hi[i], b->zmm_hi[i], 32)) { *idx = (int)i; return "zmm_hi"; }
    if (memcmp(a->k, b->k, sizeof a->k)) return "k";
    if (memcmp(a->mm, b->mm, sizeof a->mm)) return "mm";
    if (memcmp(&a->x87_64, &b->x87_64, sizeof a->x87_64)) return "x87";
    if (a->mxcsr != b->mxcsr) return "mxcsr";
    if (memcmp(&a->flags, &b->flags, sizeof a->flags)) return "flags";
    if (memcmp(&a->lazy_flags, &b->lazy_flags, sizeof a->lazy_flags)) return "lazy_flags";
    if (a->regs.x64.rflags != b->regs.x64.rflags) return "rflags";
    if (memcmp(da, db, DATA_LEN)) return "memory";
    if (memcmp(da + FAR_OFF, db + FAR_OFF, DATA_LEN)) return "memory_far";
    return NULL;
}

int main(void) {
    const int flip = getenv("MACRUNNER_HB_TEST_SIMD_FLIP") != NULL && getenv("MACRUNNER_HB_TEST_SIMD_FLIP")[0] &&
                     getenv("MACRUNNER_HB_TEST_SIMD_FLIP")[0] != '0';
    const char* cs = getenv("HB_SIMD_CASES");
    const unsigned ncases = (cs && atoi(cs) > 0) ? (unsigned)atoi(cs) : 300u;
    unsigned long cases[3] = {0}, bad[3] = {0}, runfail[3] = {0}, forms_n[3] = {0}, native_ok[3] = {0},
                  native_want[3] = {0}, helper_ok[3] = {0}, helper_want[3] = {0}, flip_seen[3] = {0};
    unsigned long printed = 0, expect_fail = 0;
    hb_context_t* cx[2] = { hb_context_create(HB_ARCH_X64, HB_BACKEND_INTERP),
                            hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT) };
    hb_memory_t* mx[2] = { hb_memory_create(0), hb_memory_create(0) };
    if (!cx[0] || !cx[1] || !mx[0] || !mx[1]) { printf("ОТКАЗ ОСНАСТКИ: контекст\n"); return 2; }
    uint8_t* code = mmap(NULL, 16384 * NFORMS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint8_t* data[2] = { mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
                         mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) };
    if (code == MAP_FAILED || stack == MAP_FAILED || data[0] == MAP_FAILED || data[1] == MAP_FAILED) {
        printf("ОТКАЗ ОСНАСТКИ: mmap\n"); return 2;
    }
    for (int k = 0; k < 2; k++) {
        cx[k]->memory = mx[k];
        cx[k]->config.fallback_enabled = false;
        if (hb_memory_sync_live_range(mx[k], (hb_gva_t)(uintptr_t)code, 16384 * NFORMS,
                                      HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC) != HB_OK ||
            hb_memory_sync_live_range(mx[k], (hb_gva_t)(uintptr_t)stack, 65536, HB_PERM_READ | HB_PERM_WRITE) != HB_OK ||
            hb_memory_sync_live_range(mx[k], (hb_gva_t)(uintptr_t)data[k], 16384, HB_PERM_READ | HB_PERM_WRITE) != HB_OK) {
            printf("ОТКАЗ ОСНАСТКИ: учёт памяти\n"); return 2;
        }
    }
    /* Одна среда JIT на весь тест, у каждой формы своя страница — выпуск переиспользуется. */
    hb_jit_runtime_t* rt = hb_jit_runtime_create(cx[1]);
    if (!rt) { printf("ОТКАЗ ОСНАСТКИ: среда JIT\n"); return 2; }
    for (unsigned fi = 0; fi < NFORMS; fi++) {
        const struct form* f = &FORMS[fi];
        uint8_t* at = code + 16384 * fi;
        uint64_t base = (uint64_t)(uintptr_t)at;
        uint64_t before[3], delta = 0, delta_fam = 0;
        unsigned long form_bad = 0;
        memcpy(at, f->b, (size_t)f->len);
        fill_rip_window(at + 64, 1024, f->vt);   /* цель [rip+256] и [rip+512] */
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X64, at, (size_t)f->len, base);
        hb_ir_func_t* func = NULL;
        if (!dec || hb_lift_func_x64(dec, &func) != HB_OK || !func || func->has_unsupported) {
            printf("ОТКАЗ ОСНАСТКИ: лифт %s\n", f->name); return 2;
        }
        hb_decoder_destroy(dec);
        forms_n[f->fam]++;
        for (unsigned u = 0; u < 3; u++) before[u] = native_count(u);
        for (unsigned it = 0; it < ncases; it++) {
            struct seed s;
            hb_exec_result_t o[2];
            hb_result_t r[2];
            const char* d;
            int idx;
            make_seed(&s, f);
            for (int k = 0; k < 2; k++) {
                apply_seed(cx[k], &s, base, stack, data[k]);
                memset(&o[k], 0, sizeof o[k]);
                r[k] = k ? hb_jit_runtime_run(rt, func, &o[k]) : hb_runtime_run(cx[0], func, HB_BACKEND_INTERP, &o[k]);
            }
            if (it == 0) {
                for (unsigned u = 0; u < 3; u++) delta += native_count(u) - before[u];
                delta_fam = native_count((unsigned)f->fam) - before[f->fam];
            }
            cases[f->fam]++;
            if (r[0] != HB_OK || o[0].result != HB_OK || o[0].faulted || cx[0]->pc != base + (uint64_t)f->len) {
                runfail[f->fam]++;
                if (printed++ < 16) printf("ОТКАЗ ИСПОЛНЕНИЯ %-44s interp r=%d res=%d faulted=%d | jit r=%d res=%d\n",
                                           f->name, (int)r[0], (int)o[0].result, (int)o[0].faulted, (int)r[1], (int)o[1].result);
                continue;
            }
            d = (r[0] != r[1] || o[0].result != o[1].result || o[0].faulted != o[1].faulted ||
                 cx[0]->pc != cx[1]->pc) ? "result/pc" : diff_of(cx[0], cx[1], data[0], data[1], &idx);
            if (d) {
                bad[f->fam]++;
                form_bad++;
                if (!flip && printed++ < 40) {
                    printf("РАСХОЖДЕНИЕ %-44s поле=%s[%d] mxcsr=%04x off=%u", f->name, d, idx, s.mxcsr, s.off);
                    if (!strcmp(d, "xmm") && idx >= 0)
                        printf(" interp=%016" PRIx64 ":%016" PRIx64 " jit=%016" PRIx64 ":%016" PRIx64 " seed=%016" PRIx64 ":%016" PRIx64,
                               cx[0]->regs.x64.xmm[idx][1], cx[0]->regs.x64.xmm[idx][0],
                               cx[1]->regs.x64.xmm[idx][1], cx[1]->regs.x64.xmm[idx][0],
                               ((uint64_t*)s.xmm[idx])[1], ((uint64_t*)s.xmm[idx])[0]);
                    else if (!strcmp(d, "ymm_hi") && idx >= 0)
                        printf(" interp=%016" PRIx64 ":%016" PRIx64 " jit=%016" PRIx64 ":%016" PRIx64,
                               cx[0]->ymm_hi[idx][1], cx[0]->ymm_hi[idx][0], cx[1]->ymm_hi[idx][1], cx[1]->ymm_hi[idx][0]);
                    else if (!strcmp(d, "gpr") && idx >= 0)
                        printf(" interp=%016" PRIx64 " jit=%016" PRIx64, (&cx[0]->regs.x64.rax)[idx], (&cx[1]->regs.x64.rax)[idx]);
                    printf("\n");
                }
            }
        }
        if (getenv("HB_SIMD_VERBOSE"))
            printf("ФОРМА %-46s случаев=%u расхождений=%lu выпуск_семьи=%llu\n", f->name, ncases, form_bad,
                   (unsigned long long)delta_fam);
        if (f->expect == 2) {
            /* форму выпускает ПРЕЖНИЙ нативный путь (emit_native_punpck_qdq и др.) — счётчик семей
             * не растёт, порча FLIP её не касается; значение сверено выше, как у всех. */
        } else if (f->expect) {
            native_want[f->fam]++;
            if (delta_fam > 0) native_ok[f->fam]++;
            else { expect_fail++; printf("НЕ НАТИВНО: %s\n", f->name); }
            if (flip) {
                if (form_bad) flip_seen[f->fam]++;
                else printf("КОНТРОЛЬ НЕ УВИДЕЛ: %s — порча выпуска не дала ни одного расхождения\n", f->name);
            }
        } else {
            helper_want[f->fam]++;
            if (delta == 0) helper_ok[f->fam]++;
            else { expect_fail++; printf("ВЫПУЩЕНО, А ДОЛЖНО УЙТИ ПОМОЩНИКУ: %s\n", f->name); }
        }
        /* func не освобождается: среда JIT держит выпуск по адресу гостя до конца теста. */
    }
    hb_jit_runtime_destroy(rt);
    unsigned long tc = 0, tb = 0, tr = 0, tf = 0, tw = 0;
    for (unsigned u = 0; u < 3; u++) {
        printf("SECTION %-5s forms=%lu cases=%lu mismatch=%lu run_fail=%lu native=%lu/%lu helper_as_expected=%lu/%lu%s",
               FAM_NAME[u], forms_n[u], cases[u], bad[u], runfail[u], native_ok[u], native_want[u],
               helper_ok[u], helper_want[u], flip ? "" : "\n");
        if (flip) printf(" control_detected=%lu/%lu\n", flip_seen[u], native_want[u]);
        tc += cases[u]; tb += bad[u]; tr += runfail[u]; tf += flip_seen[u]; tw += native_want[u];
    }
    printf("{\"cases\":%lu,\"mismatch\":%lu,\"run_fail\":%lu,\"expect_fail\":%lu,\"control\":%d}\n",
           tc, tb, tr, expect_fail, flip);
    if (flip) return (tr || expect_fail || tf != tw) ? 1 : 0;
    return (tb || tr || expect_fail) ? 1 : 0;
}
