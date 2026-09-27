/* EVEX-преобразования FP в декодере x64 (27.09.2026): vcvtdq2ps, vcvtps2dq, vcvttps2dq,
 * vcvtps2pd, vcvtpd2ps, vcvtdq2pd, vcvtss2sd, vcvtsd2ss.
 *
 * Таблица — разбор HB избранных кодировок: регистры 16..31 (EVEX.R'/X/V'), маски и {z},
 * [r13+disp8*N], SIB, [rip+disp32], рассылка {1toN}, EVEX.b на регистре при всех четырёх L'L
 * ({er}: RC+1 в evex_rounding; {sae}: длина 512). У строк без #UD операнды и длина сверены с
 * capstone 5.0.7; случайный перебор тех же полей (72 000 кодировок) дал 43 272 исполнимых,
 * все совпали с capstone. Строки #UD — правила, проверенные на Bochs: обнуление без маски,
 * L'L = 11 (и у скалярных), vvvv/V' у одноместных, рассылка у скалярных (capstone из них
 * принимает только первые два); и регистровая форма vcvtdq2pd с EVEX.b — у неё нет ни {er},
 * ни {sae} (так у capstone и в SDM; Bochs её исполняет, железом не проверено).
 * Формат строки: длина, опкод, операнды (r,номер,ширина | m,база,индекс,масштаб,смещение,
 * ширина), затем маска, {z}, рассылка, округление, ширина дорожки маски, длина вектора. */
#include <stdio.h>
#include <string.h>
#include "hb_decoder.h"
#include "hb_ir.h"

typedef struct { unsigned len; unsigned char b[15]; const char* expect; bool ud; } row_t;
static const row_t rows[] = {
    {6, {0x62,0x01,0x7c,0xcb,0x5b,0xee}, "6 CVTDQ2PS 1:r,29,64 2:r,30,64 3:- | 3 1 0 0 4 64", false},  /* vcvtdq2ps high regs: vcvtdq2ps zmm29 {k3} {z}, zmm30 */
    {6, {0x62,0xf1,0x7c,0x0f,0x5b,0xd7}, "6 CVTDQ2PS 1:r,2,16 2:r,7,16 3:- | 7 0 0 0 4 16", false},  /* vcvtdq2ps vl128 k7: vcvtdq2ps xmm2 {k7}, xmm7 */
    {6, {0x62,0xf1,0x7c,0x28,0x5b,0xf1}, "6 CVTDQ2PS 1:r,6,32 2:r,1,32 3:- | 0 0 0 0 4 32", false},  /* vcvtdq2ps vl256: vcvtdq2ps ymm6, ymm1 */
    {7, {0x62,0xd1,0x7c,0x49,0x5b,0x5d,0x02}, "7 CVTDQ2PS 1:r,3,64 2:m,13,-1,1,128,64 3:- | 1 0 0 0 4 64", false},  /* vcvtdq2ps [r13+d8]: vcvtdq2ps zmm3 {k1}, zmmword ptr [r13 + 0x80] */
    {8, {0x62,0x91,0x7c,0x28,0x5b,0x4c,0xcc,0xff}, "8 CVTDQ2PS 1:r,1,32 2:m,12,9,8,-32,32 3:- | 0 0 0 0 4 32", false},  /* vcvtdq2ps SIB: vcvtdq2ps ymm1, ymmword ptr [r12 + r9*8 - 0x20] */
    {10, {0x62,0xf1,0x7c,0x08,0x5b,0x25,0x00,0x01,0x00,0x00}, "10 CVTDQ2PS 1:r,4,16 2:m,16,-1,1,256,16 3:- | 0 0 0 0 4 16", false},  /* vcvtdq2ps rip: vcvtdq2ps xmm4, xmmword ptr [rip + 0x100] */
    {7, {0x62,0xf1,0x7c,0x5a,0x5b,0x43,0x03}, "7 CVTDQ2PS 1:r,0,64 2:m,3,-1,1,12,4 3:- | 2 0 1 0 4 64", false},  /* vcvtdq2ps bcst vl512: vcvtdq2ps zmm0 {k2}, dword ptr [rbx + 0xc]{1to16} */
    {7, {0x62,0xf1,0x7c,0x18,0x5b,0x7e,0x7f}, "7 CVTDQ2PS 1:r,7,16 2:m,6,-1,1,508,4 3:- | 0 0 1 0 4 16", false},  /* vcvtdq2ps bcst vl128: vcvtdq2ps xmm7, dword ptr [rsi + 0x1fc]{1to4} */
    {6, {0x62,0xf1,0x7c,0x1c,0x5b,0xca}, "6 CVTDQ2PS 1:r,1,64 2:r,2,64 3:- | 4 0 0 1 4 64", false},  /* vcvtdq2ps b-reg LL0: vcvtdq2ps zmm1 {k4}, zmm2, {rn-sae} */
    {6, {0x62,0xf1,0x7c,0x3c,0x5b,0xca}, "6 CVTDQ2PS 1:r,1,64 2:r,2,64 3:- | 4 0 0 2 4 64", false},  /* vcvtdq2ps b-reg LL1: vcvtdq2ps zmm1 {k4}, zmm2, {rd-sae} */
    {6, {0x62,0xf1,0x7c,0x5c,0x5b,0xca}, "6 CVTDQ2PS 1:r,1,64 2:r,2,64 3:- | 4 0 0 3 4 64", false},  /* vcvtdq2ps b-reg LL2: vcvtdq2ps zmm1 {k4}, zmm2, {ru-sae} */
    {6, {0x62,0xf1,0x7c,0x7c,0x5b,0xca}, "6 CVTDQ2PS 1:r,1,64 2:r,2,64 3:- | 4 0 0 4 4 64", false},  /* vcvtdq2ps b-reg LL3: vcvtdq2ps zmm1 {k4}, zmm2, {rz-sae} */
    {6, {0x62,0xf1,0x7c,0xc8,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 1 0 0 4 64", true},  /* vcvtdq2ps UD z without mask */
    {6, {0x62,0xf1,0x7c,0x68,0x5b,0xc1}, "6 UD 1:r,0,16 2:r,1,16 3:- | 0 0 0 0 4 16", true},  /* vcvtdq2ps UD LL=11 */
    {6, {0x62,0xf1,0x7c,0x68,0x5b,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,16 3:- | 0 0 0 0 4 16", true},  /* vcvtdq2ps UD LL=11 mem */
    {6, {0x62,0xf1,0x64,0x48,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvtdq2ps UD vvvv */
    {6, {0x62,0xf1,0x7c,0x40,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvtdq2ps UD V' */
    {6, {0x62,0xf1,0x7c,0x78,0x5b,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,4 3:- | 0 0 1 0 4 16", true},  /* vcvtdq2ps UD bcst LL=11 */
    {6, {0x62,0x01,0x7d,0xcb,0x5b,0xee}, "6 CVTPS2DQ 1:r,29,64 2:r,30,64 3:- | 3 1 0 0 4 64", false},  /* vcvtps2dq high regs: vcvtps2dq zmm29 {k3} {z}, zmm30 */
    {6, {0x62,0xf1,0x7d,0x0f,0x5b,0xd7}, "6 CVTPS2DQ 1:r,2,16 2:r,7,16 3:- | 7 0 0 0 4 16", false},  /* vcvtps2dq vl128 k7: vcvtps2dq xmm2 {k7}, xmm7 */
    {6, {0x62,0xf1,0x7d,0x28,0x5b,0xf1}, "6 CVTPS2DQ 1:r,6,32 2:r,1,32 3:- | 0 0 0 0 4 32", false},  /* vcvtps2dq vl256: vcvtps2dq ymm6, ymm1 */
    {7, {0x62,0xd1,0x7d,0x49,0x5b,0x5d,0x02}, "7 CVTPS2DQ 1:r,3,64 2:m,13,-1,1,128,64 3:- | 1 0 0 0 4 64", false},  /* vcvtps2dq [r13+d8]: vcvtps2dq zmm3 {k1}, zmmword ptr [r13 + 0x80] */
    {8, {0x62,0x91,0x7d,0x28,0x5b,0x4c,0xcc,0xff}, "8 CVTPS2DQ 1:r,1,32 2:m,12,9,8,-32,32 3:- | 0 0 0 0 4 32", false},  /* vcvtps2dq SIB: vcvtps2dq ymm1, ymmword ptr [r12 + r9*8 - 0x20] */
    {10, {0x62,0xf1,0x7d,0x08,0x5b,0x25,0x00,0x01,0x00,0x00}, "10 CVTPS2DQ 1:r,4,16 2:m,16,-1,1,256,16 3:- | 0 0 0 0 4 16", false},  /* vcvtps2dq rip: vcvtps2dq xmm4, xmmword ptr [rip + 0x100] */
    {7, {0x62,0xf1,0x7d,0x5a,0x5b,0x43,0x03}, "7 CVTPS2DQ 1:r,0,64 2:m,3,-1,1,12,4 3:- | 2 0 1 0 4 64", false},  /* vcvtps2dq bcst vl512: vcvtps2dq zmm0 {k2}, dword ptr [rbx + 0xc]{1to16} */
    {7, {0x62,0xf1,0x7d,0x18,0x5b,0x7e,0x7f}, "7 CVTPS2DQ 1:r,7,16 2:m,6,-1,1,508,4 3:- | 0 0 1 0 4 16", false},  /* vcvtps2dq bcst vl128: vcvtps2dq xmm7, dword ptr [rsi + 0x1fc]{1to4} */
    {6, {0x62,0xf1,0x7d,0x1c,0x5b,0xca}, "6 CVTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 1 4 64", false},  /* vcvtps2dq b-reg LL0: vcvtps2dq zmm1 {k4}, zmm2, {rn-sae} */
    {6, {0x62,0xf1,0x7d,0x3c,0x5b,0xca}, "6 CVTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 2 4 64", false},  /* vcvtps2dq b-reg LL1: vcvtps2dq zmm1 {k4}, zmm2, {rd-sae} */
    {6, {0x62,0xf1,0x7d,0x5c,0x5b,0xca}, "6 CVTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 3 4 64", false},  /* vcvtps2dq b-reg LL2: vcvtps2dq zmm1 {k4}, zmm2, {ru-sae} */
    {6, {0x62,0xf1,0x7d,0x7c,0x5b,0xca}, "6 CVTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 4 4 64", false},  /* vcvtps2dq b-reg LL3: vcvtps2dq zmm1 {k4}, zmm2, {rz-sae} */
    {6, {0x62,0xf1,0x7d,0xc8,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 1 0 0 4 64", true},  /* vcvtps2dq UD z without mask */
    {6, {0x62,0xf1,0x7d,0x68,0x5b,0xc1}, "6 UD 1:r,0,16 2:r,1,16 3:- | 0 0 0 0 4 16", true},  /* vcvtps2dq UD LL=11 */
    {6, {0x62,0xf1,0x7d,0x68,0x5b,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,16 3:- | 0 0 0 0 4 16", true},  /* vcvtps2dq UD LL=11 mem */
    {6, {0x62,0xf1,0x65,0x48,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvtps2dq UD vvvv */
    {6, {0x62,0xf1,0x7d,0x40,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvtps2dq UD V' */
    {6, {0x62,0xf1,0x7d,0x78,0x5b,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,4 3:- | 0 0 1 0 4 16", true},  /* vcvtps2dq UD bcst LL=11 */
    {6, {0x62,0x01,0x7e,0xcb,0x5b,0xee}, "6 CVTTPS2DQ 1:r,29,64 2:r,30,64 3:- | 3 1 0 0 4 64", false},  /* vcvttps2dq high regs: vcvttps2dq zmm29 {k3} {z}, zmm30 */
    {6, {0x62,0xf1,0x7e,0x0f,0x5b,0xd7}, "6 CVTTPS2DQ 1:r,2,16 2:r,7,16 3:- | 7 0 0 0 4 16", false},  /* vcvttps2dq vl128 k7: vcvttps2dq xmm2 {k7}, xmm7 */
    {6, {0x62,0xf1,0x7e,0x28,0x5b,0xf1}, "6 CVTTPS2DQ 1:r,6,32 2:r,1,32 3:- | 0 0 0 0 4 32", false},  /* vcvttps2dq vl256: vcvttps2dq ymm6, ymm1 */
    {7, {0x62,0xd1,0x7e,0x49,0x5b,0x5d,0x02}, "7 CVTTPS2DQ 1:r,3,64 2:m,13,-1,1,128,64 3:- | 1 0 0 0 4 64", false},  /* vcvttps2dq [r13+d8]: vcvttps2dq zmm3 {k1}, zmmword ptr [r13 + 0x80] */
    {8, {0x62,0x91,0x7e,0x28,0x5b,0x4c,0xcc,0xff}, "8 CVTTPS2DQ 1:r,1,32 2:m,12,9,8,-32,32 3:- | 0 0 0 0 4 32", false},  /* vcvttps2dq SIB: vcvttps2dq ymm1, ymmword ptr [r12 + r9*8 - 0x20] */
    {10, {0x62,0xf1,0x7e,0x08,0x5b,0x25,0x00,0x01,0x00,0x00}, "10 CVTTPS2DQ 1:r,4,16 2:m,16,-1,1,256,16 3:- | 0 0 0 0 4 16", false},  /* vcvttps2dq rip: vcvttps2dq xmm4, xmmword ptr [rip + 0x100] */
    {7, {0x62,0xf1,0x7e,0x5a,0x5b,0x43,0x03}, "7 CVTTPS2DQ 1:r,0,64 2:m,3,-1,1,12,4 3:- | 2 0 1 0 4 64", false},  /* vcvttps2dq bcst vl512: vcvttps2dq zmm0 {k2}, dword ptr [rbx + 0xc]{1to16} */
    {7, {0x62,0xf1,0x7e,0x18,0x5b,0x7e,0x7f}, "7 CVTTPS2DQ 1:r,7,16 2:m,6,-1,1,508,4 3:- | 0 0 1 0 4 16", false},  /* vcvttps2dq bcst vl128: vcvttps2dq xmm7, dword ptr [rsi + 0x1fc]{1to4} */
    {6, {0x62,0xf1,0x7e,0x1c,0x5b,0xca}, "6 CVTTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 0 4 64", false},  /* vcvttps2dq b-reg LL0: vcvttps2dq zmm1 {k4}, zmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0x3c,0x5b,0xca}, "6 CVTTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 0 4 64", false},  /* vcvttps2dq b-reg LL1: vcvttps2dq zmm1 {k4}, zmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0x5c,0x5b,0xca}, "6 CVTTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 0 4 64", false},  /* vcvttps2dq b-reg LL2: vcvttps2dq zmm1 {k4}, zmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0x7c,0x5b,0xca}, "6 CVTTPS2DQ 1:r,1,64 2:r,2,64 3:- | 4 0 0 0 4 64", false},  /* vcvttps2dq b-reg LL3: vcvttps2dq zmm1 {k4}, zmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0xc8,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 1 0 0 4 64", true},  /* vcvttps2dq UD z without mask */
    {6, {0x62,0xf1,0x7e,0x68,0x5b,0xc1}, "6 UD 1:r,0,16 2:r,1,16 3:- | 0 0 0 0 4 16", true},  /* vcvttps2dq UD LL=11 */
    {6, {0x62,0xf1,0x7e,0x68,0x5b,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,16 3:- | 0 0 0 0 4 16", true},  /* vcvttps2dq UD LL=11 mem */
    {6, {0x62,0xf1,0x66,0x48,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvttps2dq UD vvvv */
    {6, {0x62,0xf1,0x7e,0x40,0x5b,0xc1}, "6 UD 1:r,0,64 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvttps2dq UD V' */
    {6, {0x62,0xf1,0x7e,0x78,0x5b,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,4 3:- | 0 0 1 0 4 16", true},  /* vcvttps2dq UD bcst LL=11 */
    {6, {0x62,0x01,0x7c,0xcb,0x5a,0xee}, "6 CVTPS2PD 1:r,29,64 2:r,30,32 3:- | 3 1 0 0 8 64", false},  /* vcvtps2pd high regs: vcvtps2pd zmm29 {k3} {z}, ymm30 */
    {6, {0x62,0xf1,0x7c,0x0f,0x5a,0xd7}, "6 CVTPS2PD 1:r,2,16 2:r,7,16 3:- | 7 0 0 0 8 16", false},  /* vcvtps2pd vl128 k7: vcvtps2pd xmm2 {k7}, xmm7 */
    {6, {0x62,0xf1,0x7c,0x28,0x5a,0xf1}, "6 CVTPS2PD 1:r,6,32 2:r,1,16 3:- | 0 0 0 0 8 32", false},  /* vcvtps2pd vl256: vcvtps2pd ymm6, xmm1 */
    {7, {0x62,0xd1,0x7c,0x49,0x5a,0x5d,0x02}, "7 CVTPS2PD 1:r,3,64 2:m,13,-1,1,64,32 3:- | 1 0 0 0 8 64", false},  /* vcvtps2pd [r13+d8]: vcvtps2pd zmm3 {k1}, ymmword ptr [r13 + 0x40] */
    {8, {0x62,0x91,0x7c,0x28,0x5a,0x4c,0xcc,0xff}, "8 CVTPS2PD 1:r,1,32 2:m,12,9,8,-16,16 3:- | 0 0 0 0 8 32", false},  /* vcvtps2pd SIB: vcvtps2pd ymm1, xmmword ptr [r12 + r9*8 - 0x10] */
    {10, {0x62,0xf1,0x7c,0x08,0x5a,0x25,0x00,0x01,0x00,0x00}, "10 CVTPS2PD 1:r,4,16 2:m,16,-1,1,256,8 3:- | 0 0 0 0 8 16", false},  /* vcvtps2pd rip: vcvtps2pd xmm4, qword ptr [rip + 0x100] */
    {7, {0x62,0xf1,0x7c,0x5a,0x5a,0x43,0x03}, "7 CVTPS2PD 1:r,0,64 2:m,3,-1,1,12,4 3:- | 2 0 1 0 8 64", false},  /* vcvtps2pd bcst vl512: vcvtps2pd zmm0 {k2}, dword ptr [rbx + 0xc]{1to8} */
    {7, {0x62,0xf1,0x7c,0x18,0x5a,0x7e,0x7f}, "7 CVTPS2PD 1:r,7,16 2:m,6,-1,1,508,4 3:- | 0 0 1 0 8 16", false},  /* vcvtps2pd bcst vl128: vcvtps2pd xmm7, dword ptr [rsi + 0x1fc]{1to2} */
    {6, {0x62,0xf1,0x7c,0x1c,0x5a,0xca}, "6 CVTPS2PD 1:r,1,64 2:r,2,32 3:- | 4 0 0 0 8 64", false},  /* vcvtps2pd b-reg LL0: vcvtps2pd zmm1 {k4}, ymm2, {sae} */
    {6, {0x62,0xf1,0x7c,0x3c,0x5a,0xca}, "6 CVTPS2PD 1:r,1,64 2:r,2,32 3:- | 4 0 0 0 8 64", false},  /* vcvtps2pd b-reg LL1: vcvtps2pd zmm1 {k4}, ymm2, {sae} */
    {6, {0x62,0xf1,0x7c,0x5c,0x5a,0xca}, "6 CVTPS2PD 1:r,1,64 2:r,2,32 3:- | 4 0 0 0 8 64", false},  /* vcvtps2pd b-reg LL2: vcvtps2pd zmm1 {k4}, ymm2, {sae} */
    {6, {0x62,0xf1,0x7c,0x7c,0x5a,0xca}, "6 CVTPS2PD 1:r,1,64 2:r,2,32 3:- | 4 0 0 0 8 64", false},  /* vcvtps2pd b-reg LL3: vcvtps2pd zmm1 {k4}, ymm2, {sae} */
    {6, {0x62,0xf1,0x7c,0xc8,0x5a,0xc1}, "6 UD 1:r,0,64 2:r,1,32 3:- | 0 1 0 0 8 64", true},  /* vcvtps2pd UD z without mask */
    {6, {0x62,0xf1,0x7c,0x68,0x5a,0xc1}, "6 UD 1:r,0,16 2:r,1,16 3:- | 0 0 0 0 8 16", true},  /* vcvtps2pd UD LL=11 */
    {6, {0x62,0xf1,0x7c,0x68,0x5a,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,8 3:- | 0 0 0 0 8 16", true},  /* vcvtps2pd UD LL=11 mem */
    {6, {0x62,0xf1,0x64,0x48,0x5a,0xc1}, "6 UD 1:r,0,64 2:r,1,32 3:- | 0 0 0 0 8 64", true},  /* vcvtps2pd UD vvvv */
    {6, {0x62,0xf1,0x7c,0x40,0x5a,0xc1}, "6 UD 1:r,0,64 2:r,1,32 3:- | 0 0 0 0 8 64", true},  /* vcvtps2pd UD V' */
    {6, {0x62,0xf1,0x7c,0x78,0x5a,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,4 3:- | 0 0 1 0 8 16", true},  /* vcvtps2pd UD bcst LL=11 */
    {6, {0x62,0x01,0xfd,0xcb,0x5a,0xee}, "6 CVTPD2PS 1:r,29,32 2:r,30,64 3:- | 3 1 0 0 4 64", false},  /* vcvtpd2ps high regs: vcvtpd2ps ymm29 {k3} {z}, zmm30 */
    {6, {0x62,0xf1,0xfd,0x0f,0x5a,0xd7}, "6 CVTPD2PS 1:r,2,16 2:r,7,16 3:- | 7 0 0 0 4 16", false},  /* vcvtpd2ps vl128 k7: vcvtpd2ps xmm2 {k7}, xmm7 */
    {6, {0x62,0xf1,0xfd,0x28,0x5a,0xf1}, "6 CVTPD2PS 1:r,6,16 2:r,1,32 3:- | 0 0 0 0 4 32", false},  /* vcvtpd2ps vl256: vcvtpd2ps xmm6, ymm1 */
    {7, {0x62,0xd1,0xfd,0x49,0x5a,0x5d,0x02}, "7 CVTPD2PS 1:r,3,32 2:m,13,-1,1,128,64 3:- | 1 0 0 0 4 64", false},  /* vcvtpd2ps [r13+d8]: vcvtpd2ps ymm3 {k1}, zmmword ptr [r13 + 0x80] */
    {8, {0x62,0x91,0xfd,0x28,0x5a,0x4c,0xcc,0xff}, "8 CVTPD2PS 1:r,1,16 2:m,12,9,8,-32,32 3:- | 0 0 0 0 4 32", false},  /* vcvtpd2ps SIB: vcvtpd2ps xmm1, ymmword ptr [r12 + r9*8 - 0x20] */
    {10, {0x62,0xf1,0xfd,0x08,0x5a,0x25,0x00,0x01,0x00,0x00}, "10 CVTPD2PS 1:r,4,16 2:m,16,-1,1,256,16 3:- | 0 0 0 0 4 16", false},  /* vcvtpd2ps rip: vcvtpd2ps xmm4, xmmword ptr [rip + 0x100] */
    {7, {0x62,0xf1,0xfd,0x5a,0x5a,0x43,0x03}, "7 CVTPD2PS 1:r,0,32 2:m,3,-1,1,24,8 3:- | 2 0 1 0 4 64", false},  /* vcvtpd2ps bcst vl512: vcvtpd2ps ymm0 {k2}, qword ptr [rbx + 0x18]{1to8} */
    {7, {0x62,0xf1,0xfd,0x18,0x5a,0x7e,0x7f}, "7 CVTPD2PS 1:r,7,16 2:m,6,-1,1,1016,8 3:- | 0 0 1 0 4 16", false},  /* vcvtpd2ps bcst vl128: vcvtpd2ps xmm7, qword ptr [rsi + 0x3f8]{1to2} */
    {6, {0x62,0xf1,0xfd,0x1c,0x5a,0xca}, "6 CVTPD2PS 1:r,1,32 2:r,2,64 3:- | 4 0 0 1 4 64", false},  /* vcvtpd2ps b-reg LL0: vcvtpd2ps ymm1 {k4}, zmm2, {rn-sae} */
    {6, {0x62,0xf1,0xfd,0x3c,0x5a,0xca}, "6 CVTPD2PS 1:r,1,32 2:r,2,64 3:- | 4 0 0 2 4 64", false},  /* vcvtpd2ps b-reg LL1: vcvtpd2ps ymm1 {k4}, zmm2, {rd-sae} */
    {6, {0x62,0xf1,0xfd,0x5c,0x5a,0xca}, "6 CVTPD2PS 1:r,1,32 2:r,2,64 3:- | 4 0 0 3 4 64", false},  /* vcvtpd2ps b-reg LL2: vcvtpd2ps ymm1 {k4}, zmm2, {ru-sae} */
    {6, {0x62,0xf1,0xfd,0x7c,0x5a,0xca}, "6 CVTPD2PS 1:r,1,32 2:r,2,64 3:- | 4 0 0 4 4 64", false},  /* vcvtpd2ps b-reg LL3: vcvtpd2ps ymm1 {k4}, zmm2, {rz-sae} */
    {6, {0x62,0xf1,0xfd,0xc8,0x5a,0xc1}, "6 UD 1:r,0,32 2:r,1,64 3:- | 0 1 0 0 4 64", true},  /* vcvtpd2ps UD z without mask */
    {6, {0x62,0xf1,0xfd,0x68,0x5a,0xc1}, "6 UD 1:r,0,16 2:r,1,16 3:- | 0 0 0 0 4 16", true},  /* vcvtpd2ps UD LL=11 */
    {6, {0x62,0xf1,0xfd,0x68,0x5a,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,16 3:- | 0 0 0 0 4 16", true},  /* vcvtpd2ps UD LL=11 mem */
    {6, {0x62,0xf1,0xe5,0x48,0x5a,0xc1}, "6 UD 1:r,0,32 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvtpd2ps UD vvvv */
    {6, {0x62,0xf1,0xfd,0x40,0x5a,0xc1}, "6 UD 1:r,0,32 2:r,1,64 3:- | 0 0 0 0 4 64", true},  /* vcvtpd2ps UD V' */
    {6, {0x62,0xf1,0xfd,0x78,0x5a,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,8 3:- | 0 0 1 0 4 16", true},  /* vcvtpd2ps UD bcst LL=11 */
    {6, {0x62,0x01,0x7e,0xcb,0xe6,0xee}, "6 CVTDQ2PD 1:r,29,64 2:r,30,32 3:- | 3 1 0 0 8 64", false},  /* vcvtdq2pd high regs: vcvtdq2pd zmm29 {k3} {z}, ymm30 */
    {6, {0x62,0xf1,0x7e,0x0f,0xe6,0xd7}, "6 CVTDQ2PD 1:r,2,16 2:r,7,16 3:- | 7 0 0 0 8 16", false},  /* vcvtdq2pd vl128 k7: vcvtdq2pd xmm2 {k7}, xmm7 */
    {6, {0x62,0xf1,0x7e,0x28,0xe6,0xf1}, "6 CVTDQ2PD 1:r,6,32 2:r,1,16 3:- | 0 0 0 0 8 32", false},  /* vcvtdq2pd vl256: vcvtdq2pd ymm6, xmm1 */
    {7, {0x62,0xd1,0x7e,0x49,0xe6,0x5d,0x02}, "7 CVTDQ2PD 1:r,3,64 2:m,13,-1,1,64,32 3:- | 1 0 0 0 8 64", false},  /* vcvtdq2pd [r13+d8]: vcvtdq2pd zmm3 {k1}, ymmword ptr [r13 + 0x40] */
    {8, {0x62,0x91,0x7e,0x28,0xe6,0x4c,0xcc,0xff}, "8 CVTDQ2PD 1:r,1,32 2:m,12,9,8,-16,16 3:- | 0 0 0 0 8 32", false},  /* vcvtdq2pd SIB: vcvtdq2pd ymm1, xmmword ptr [r12 + r9*8 - 0x10] */
    {10, {0x62,0xf1,0x7e,0x08,0xe6,0x25,0x00,0x01,0x00,0x00}, "10 CVTDQ2PD 1:r,4,16 2:m,16,-1,1,256,8 3:- | 0 0 0 0 8 16", false},  /* vcvtdq2pd rip: vcvtdq2pd xmm4, qword ptr [rip + 0x100] */
    {7, {0x62,0xf1,0x7e,0x5a,0xe6,0x43,0x03}, "7 CVTDQ2PD 1:r,0,64 2:m,3,-1,1,12,4 3:- | 2 0 1 0 8 64", false},  /* vcvtdq2pd bcst vl512: vcvtdq2pd zmm0 {k2}, dword ptr [rbx + 0xc]{1to8} */
    {7, {0x62,0xf1,0x7e,0x18,0xe6,0x7e,0x7f}, "7 CVTDQ2PD 1:r,7,16 2:m,6,-1,1,508,4 3:- | 0 0 1 0 8 16", false},  /* vcvtdq2pd bcst vl128: vcvtdq2pd xmm7, dword ptr [rsi + 0x1fc]{1to2} */
    {6, {0x62,0xf1,0x7e,0xc8,0xe6,0xc1}, "6 UD 1:r,0,64 2:r,1,32 3:- | 0 1 0 0 8 64", true},  /* vcvtdq2pd UD z without mask */
    {6, {0x62,0xf1,0x7e,0x68,0xe6,0xc1}, "6 UD 1:r,0,16 2:r,1,16 3:- | 0 0 0 0 8 16", true},  /* vcvtdq2pd UD LL=11 */
    {6, {0x62,0xf1,0x7e,0x68,0xe6,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,8 3:- | 0 0 0 0 8 16", true},  /* vcvtdq2pd UD LL=11 mem */
    {6, {0x62,0xf1,0x66,0x48,0xe6,0xc1}, "6 UD 1:r,0,64 2:r,1,32 3:- | 0 0 0 0 8 64", true},  /* vcvtdq2pd UD vvvv */
    {6, {0x62,0xf1,0x7e,0x40,0xe6,0xc1}, "6 UD 1:r,0,64 2:r,1,32 3:- | 0 0 0 0 8 64", true},  /* vcvtdq2pd UD V' */
    {6, {0x62,0xf1,0x7e,0x78,0xe6,0x03}, "6 UD 1:r,0,16 2:m,3,-1,1,0,4 3:- | 0 0 1 0 8 16", true},  /* vcvtdq2pd UD bcst LL=11 */
    {6, {0x62,0xf1,0x7e,0x58,0xe6,0xc1}, "6 UD 1:r,0,64 2:r,1,32 3:- | 0 0 0 0 8 64", true},  /* vcvtdq2pd UD b-reg */
    {6, {0x62,0x01,0x36,0x83,0x5a,0xee}, "6 CVTSS2SD 1:r,29,16 2:r,25,16 3:r,30,16 | 3 1 0 0 8 16", false},  /* vcvtss2sd high regs: vcvtss2sd xmm29 {k3} {z}, xmm25, xmm30 */
    {6, {0x62,0xf1,0x7e,0x0f,0x5a,0xd7}, "6 CVTSS2SD 1:r,2,16 2:r,0,16 3:r,7,16 | 7 0 0 0 8 16", false},  /* vcvtss2sd vl128 k7: vcvtss2sd xmm2 {k7}, xmm0, xmm7 */
    {6, {0x62,0xf1,0x7e,0x28,0x5a,0xf1}, "6 CVTSS2SD 1:r,6,16 2:r,0,16 3:r,1,16 | 0 0 0 0 8 32", false},  /* vcvtss2sd vl256: vcvtss2sd xmm6, xmm0, xmm1 */
    {7, {0x62,0xd1,0x7e,0x49,0x5a,0x5d,0x02}, "7 CVTSS2SD 1:r,3,16 2:r,0,16 3:m,13,-1,1,8,4 | 1 0 0 0 8 64", false},  /* vcvtss2sd [r13+d8]: vcvtss2sd xmm3 {k1}, xmm0, dword ptr [r13 + 8] */
    {8, {0x62,0x91,0x7e,0x28,0x5a,0x4c,0xcc,0xff}, "8 CVTSS2SD 1:r,1,16 2:r,0,16 3:m,12,9,8,-4,4 | 0 0 0 0 8 32", false},  /* vcvtss2sd SIB: vcvtss2sd xmm1, xmm0, dword ptr [r12 + r9*8 - 4] */
    {10, {0x62,0xf1,0x7e,0x08,0x5a,0x25,0x00,0x01,0x00,0x00}, "10 CVTSS2SD 1:r,4,16 2:r,0,16 3:m,16,-1,1,256,4 | 0 0 0 0 8 16", false},  /* vcvtss2sd rip: vcvtss2sd xmm4, xmm0, dword ptr [rip + 0x100] */
    {6, {0x62,0xf1,0x7e,0x1c,0x5a,0xca}, "6 CVTSS2SD 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 0 8 64", false},  /* vcvtss2sd b-reg LL0: vcvtss2sd xmm1 {k4}, xmm0, xmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0x3c,0x5a,0xca}, "6 CVTSS2SD 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 0 8 64", false},  /* vcvtss2sd b-reg LL1: vcvtss2sd xmm1 {k4}, xmm0, xmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0x5c,0x5a,0xca}, "6 CVTSS2SD 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 0 8 64", false},  /* vcvtss2sd b-reg LL2: vcvtss2sd xmm1 {k4}, xmm0, xmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0x7c,0x5a,0xca}, "6 CVTSS2SD 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 0 8 64", false},  /* vcvtss2sd b-reg LL3: vcvtss2sd xmm1 {k4}, xmm0, xmm2, {sae} */
    {6, {0x62,0xf1,0x7e,0xc8,0x5a,0xc1}, "6 UD 1:r,0,16 2:r,0,16 3:r,1,16 | 0 1 0 0 8 64", true},  /* vcvtss2sd UD z without mask */
    {6, {0x62,0xf1,0x7e,0x68,0x5a,0xc1}, "6 UD 1:r,0,16 2:r,0,16 3:r,1,16 | 0 0 0 0 8 16", true},  /* vcvtss2sd UD LL=11 */
    {6, {0x62,0xf1,0x7e,0x68,0x5a,0x03}, "6 UD 1:r,0,16 2:r,0,16 3:m,3,-1,1,0,4 | 0 0 0 0 8 16", true},  /* vcvtss2sd UD LL=11 mem */
    {6, {0x62,0xf1,0x7e,0x58,0x5a,0x03}, "6 UD 1:r,0,16 2:r,0,16 3:m,3,-1,1,0,4 | 0 0 0 0 8 64", true},  /* vcvtss2sd UD bcst scalar */
    {6, {0x62,0x01,0xb7,0x83,0x5a,0xee}, "6 CVTSD2SS 1:r,29,16 2:r,25,16 3:r,30,16 | 3 1 0 0 4 16", false},  /* vcvtsd2ss high regs: vcvtsd2ss xmm29 {k3} {z}, xmm25, xmm30 */
    {6, {0x62,0xf1,0xff,0x0f,0x5a,0xd7}, "6 CVTSD2SS 1:r,2,16 2:r,0,16 3:r,7,16 | 7 0 0 0 4 16", false},  /* vcvtsd2ss vl128 k7: vcvtsd2ss xmm2 {k7}, xmm0, xmm7 */
    {6, {0x62,0xf1,0xff,0x28,0x5a,0xf1}, "6 CVTSD2SS 1:r,6,16 2:r,0,16 3:r,1,16 | 0 0 0 0 4 32", false},  /* vcvtsd2ss vl256: vcvtsd2ss xmm6, xmm0, xmm1 */
    {7, {0x62,0xd1,0xff,0x49,0x5a,0x5d,0x02}, "7 CVTSD2SS 1:r,3,16 2:r,0,16 3:m,13,-1,1,16,8 | 1 0 0 0 4 64", false},  /* vcvtsd2ss [r13+d8]: vcvtsd2ss xmm3 {k1}, xmm0, qword ptr [r13 + 0x10] */
    {8, {0x62,0x91,0xff,0x28,0x5a,0x4c,0xcc,0xff}, "8 CVTSD2SS 1:r,1,16 2:r,0,16 3:m,12,9,8,-8,8 | 0 0 0 0 4 32", false},  /* vcvtsd2ss SIB: vcvtsd2ss xmm1, xmm0, qword ptr [r12 + r9*8 - 8] */
    {10, {0x62,0xf1,0xff,0x08,0x5a,0x25,0x00,0x01,0x00,0x00}, "10 CVTSD2SS 1:r,4,16 2:r,0,16 3:m,16,-1,1,256,8 | 0 0 0 0 4 16", false},  /* vcvtsd2ss rip: vcvtsd2ss xmm4, xmm0, qword ptr [rip + 0x100] */
    {6, {0x62,0xf1,0xff,0x1c,0x5a,0xca}, "6 CVTSD2SS 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 1 4 64", false},  /* vcvtsd2ss b-reg LL0: vcvtsd2ss xmm1 {k4}, xmm0, xmm2, {rn-sae} */
    {6, {0x62,0xf1,0xff,0x3c,0x5a,0xca}, "6 CVTSD2SS 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 2 4 64", false},  /* vcvtsd2ss b-reg LL1: vcvtsd2ss xmm1 {k4}, xmm0, xmm2, {rd-sae} */
    {6, {0x62,0xf1,0xff,0x5c,0x5a,0xca}, "6 CVTSD2SS 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 3 4 64", false},  /* vcvtsd2ss b-reg LL2: vcvtsd2ss xmm1 {k4}, xmm0, xmm2, {ru-sae} */
    {6, {0x62,0xf1,0xff,0x7c,0x5a,0xca}, "6 CVTSD2SS 1:r,1,16 2:r,0,16 3:r,2,16 | 4 0 0 4 4 64", false},  /* vcvtsd2ss b-reg LL3: vcvtsd2ss xmm1 {k4}, xmm0, xmm2, {rz-sae} */
    {6, {0x62,0xf1,0xff,0xc8,0x5a,0xc1}, "6 UD 1:r,0,16 2:r,0,16 3:r,1,16 | 0 1 0 0 4 64", true},  /* vcvtsd2ss UD z without mask */
    {6, {0x62,0xf1,0xff,0x68,0x5a,0xc1}, "6 UD 1:r,0,16 2:r,0,16 3:r,1,16 | 0 0 0 0 4 16", true},  /* vcvtsd2ss UD LL=11 */
    {6, {0x62,0xf1,0xff,0x68,0x5a,0x03}, "6 UD 1:r,0,16 2:r,0,16 3:m,3,-1,1,0,8 | 0 0 0 0 4 16", true},  /* vcvtsd2ss UD LL=11 mem */
    {6, {0x62,0xf1,0xff,0x58,0x5a,0x03}, "6 UD 1:r,0,16 2:r,0,16 3:m,3,-1,1,0,8 | 0 0 0 0 4 64", true},  /* vcvtsd2ss UD bcst scalar */
};

static void describe_op(char* out, size_t cap, const char* slot, bool present, bool is_reg, bool is_mem,
                        int reg, int size, int base, int index, int scale, long long disp) {
    size_t n = strlen(out);
    if (!present) snprintf(out + n, cap - n, " %s:-", slot);
    else if (is_reg) snprintf(out + n, cap - n, " %s:r,%d,%d", slot, reg >= HB_REG_XMM0 ? reg - HB_REG_XMM0 : reg, size);
    else if (is_mem) snprintf(out + n, cap - n, " %s:m,%d,%d,%d,%lld,%d", slot, base, index, scale, disp, size);
    else snprintf(out + n, cap - n, " %s:i", slot);
}

int main(void) {
    unsigned bad = 0, n = 0;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        hb_decoded_t o;
        char got[256];
        hb_decoder_t* d = hb_decoder_create(HB_ARCH_X64, rows[i].b, rows[i].len, 0x10000);
        memset(&o, 0, sizeof(o));
        hb_result_t r = d ? hb_decode_next(d, &o) : HB_ERR_INTERNAL;
        if (d) hb_decoder_destroy(d);
        n++;
        if (r != HB_OK) {
            snprintf(got, sizeof(got), "rc=%d", r);
        } else {
            snprintf(got, sizeof(got), "%u %s", o.len, hb_opcode_name((int)o.opcode));
            describe_op(got, sizeof(got), "1", o.op1.present, o.op1.is_reg, o.op1.is_mem, o.op1.reg, o.op1.size,
                        o.op1.mem.base, o.op1.mem.index, o.op1.mem.scale, (long long)o.op1.mem.disp);
            describe_op(got, sizeof(got), "2", o.op2.present, o.op2.is_reg, o.op2.is_mem, o.op2.reg, o.op2.size,
                        o.op2.mem.base, o.op2.mem.index, o.op2.mem.scale, (long long)o.op2.mem.disp);
            describe_op(got, sizeof(got), "3", o.op3.present, o.op3.is_reg, o.op3.is_mem, o.op3.reg, o.op3.size,
                        o.op3.mem.base, o.op3.mem.index, o.op3.mem.scale, (long long)o.op3.mem.disp);
            size_t k = strlen(got);
            snprintf(got + k, sizeof(got) - k, " | %d %d %d %d %d %d", o.evex_mask, o.evex_zero,
                     o.evex_broadcast, o.evex_rounding, o.evex_mask_lane, o.evex_vl);
        }
        if (strcmp(got, rows[i].expect) != 0 || (r == HB_OK && (o.opcode == HB_INS_UD) != rows[i].ud)) {
            if (++bad <= 20) {
                printf("BAD ");
                for (unsigned j = 0; j < rows[i].len; j++) printf("%02x", rows[i].b[j]);
                printf("\n  got      %s\n  expected %s\n", got, rows[i].expect);
            }
        }
    }
    printf("EVEX FP conversions decode: %u encodings, %u bad\n", n, bad);
    return bad ? 1 : 0;
}
