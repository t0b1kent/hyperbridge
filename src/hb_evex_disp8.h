#ifndef HB_EVEX_DISP8_H
#define HB_EVEX_DISP8_H
#include <stdint.h>
#include "hb_decoder.h"
/* СЖАТОЕ СМЕЩЕНИЕ EVEX (disp8*N) — один текст на обе ветви декодера.
 *
 * У EVEX однобайтовое смещение (mod=01) хранится ДЕЛЁННЫМ на N и при разборе
 * умножается обратно. N по таблицам кортежей Intel (FV, HV, FVM, T1S, T2, T4,
 * T8, HVM, QVM, OVM, M128, DUP) во всех случаях равно размеру одного обращения к
 * памяти: всему операнду без рассылки, одному элементу при рассылке, элементу
 * при VSIB. Размер операнда декодер уже знает, поэтому поправка одна и на
 * выходе, а не в каждой ветви EVEX.
 *
 * Замер 26.09.2026 до правки: `62 f1 7c 08 11 49 01` (`vmovups [rcx+0x10],xmm1`)
 * разбирался как [rcx+1]. Сверка против capstone по всем EVEX-формам, которые
 * исполняет x64-ветвь, с mod=01 и disp8=1: 956 из 962 форм с неверным адресом
 * (верными были только формы с N=1). Нашёл аппаратный оракул Астры
 * (HBUP0002, store-loop): восемь записей по 16 байт ложились с шагом в байт. */
static inline void hb_evex_scale_disp8(hb_decoded_t* out) {
    if (!out->evex || !out->has_modrm || out->mod != 1) return;
#define HB_EVEX_SCALE_ONE(op) \
    if ((op).is_mem) { \
        unsigned n = (op).mem.vsib ? (op).mem.vsib_elem_size : (op).size; \
        if (n == 1 || n == 2 || n == 4 || n == 8 || n == 16 || n == 32 || n == 64) \
            (op).mem.disp *= (int64_t)n; \
        return; \
    }
    HB_EVEX_SCALE_ONE(out->op1)
    HB_EVEX_SCALE_ONE(out->op2)
    HB_EVEX_SCALE_ONE(out->op3)
#undef HB_EVEX_SCALE_ONE
}
#endif
