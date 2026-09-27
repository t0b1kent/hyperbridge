#ifndef HB_EVEX_LEGAL_H
#define HB_EVEX_LEGAL_H
#include <stdbool.h>
#include <string.h>
#include "hb_decoder.h"
/* ЗАКОННОСТЬ КОДИРОВОК EVEX — один текст на обе ветви декодера.
 *
 * Оба декодера принимали и исполняли кодировки EVEX, на которые процессор
 * отвечает #UD. Сверка с capstone (tests/hb_evex_disp8/sweep.py --json) нашла
 * 188 таких форм на x64 и 76 на i386, но судьёй capstone здесь быть не может:
 * у скалярных форм длина вектора не проверяется (LIG), и там он отвергает
 * законное. Ответ дал процессор: все 264 исполнены на x86 (AMD EPYC 9V74; x64
 * в CS=0x33, i386 в настоящем режиме совместимости CS=0x23; одиночный шаг,
 * #UD — trap 6 на самой команде). 248 дали #UD, 16 исполнились — это
 * vcmpss/vcmpsd с b=0 при L'L=1/2. Вердикты: tests/hb_evex_legal/verdicts.inc,
 * проверка: tests/hb_evex_legal_test.c.
 *
 * Семь правил ниже воспроизводят список ТОЧНО: 248 из 248, ни одной из 16
 * исполнившихся и ни одной из 24 законных соседних форм того же прогона;
 * лишних правил нет — каждое оказывается единственной причиной отказа хотя бы
 * для шести записей. Таблица не понадобилась. Число в скобках — сколько
 * записей прогона задевает правило; все они #UD.
 *
 * Правило — свойство КОМАНДЫ, поэтому W, допустимая длина вектора и
 * отсутствие формы EVEX проверяются при любой адресации. Регистровых форм
 * процессор не исполнял; в переборе с ModRM=C1 правила задевают 52 формы на
 * x64 и 64 на i386, capstone отвергает все. Правило о бите b — только для
 * ПАМЯТИ: там b=1 означает рассылку, а у регистра — округление или SAE, это
 * другое свойство, и замеров по нему нет.
 *
 * Отказ — `HB_INS_UD` с честной длиной, как у UD2 и у недопустимого LOCK
 * (hb_zamok_pravilo.h): блок трансляции цел, гость получает #UD (c000001d)
 * ровно на этой команде. Отказ РАЗБОРА дал бы «неподдержанную команду» —
 * пробел движка, а не ответ процессора. В #UD переводится только то, что
 * декодер иначе ИСПОЛНИЛ бы; прежние отказы разбора и заглушка VEC остаются.
 *
 * Не замерено и потому не тронуто: L'L=3, префиксы 66/F2/F3/REX перед EVEX,
 * b=1 у регистровых форм без округления. */

/* true — процессор отвечает на кодировку #UD. mod — поле ModRM (3 — регистр). */
static inline bool hb_evex_hw_ud(unsigned map, unsigned pp, unsigned w, unsigned ll,
                                 unsigned b, unsigned op, unsigned mod) {
    bool bcast_mem = b && mod != 3;   /* b=1 при памяти — рассылка элемента */
    if (map == 1 && op == 0xc2) {
        /* VCMPPS/PD/SS/SD: W — часть кода операции, W0 у ps (NP) и ss (F3),
         * W1 у pd (66) и sd (F2); иначе #UD при любых L'L и b (x64 48, i386 24). */
        if (w != (pp & 1u)) return true;
        /* У скаляра рассылки нет (x64 24). L'L скаляр не проверяет: L'L=1/2
         * при b=0 исполнились, все 16. */
        return (pp == 2 || pp == 3) && bcast_mem;
    }
    if (map == 2 && pp == 1) {
        switch (op) {
            case 0x08: case 0x09: case 0x0a:
                /* VPSIGNB/W/D — только VEX, формы EVEX нет (x64 18, i386 18). */
                return true;
            case 0x18: case 0x19: case 0x1a: case 0x1b:  /* VBROADCASTSS/SD/F32X2/F32X4/F64X2/F32X8/F64X4 */
            case 0x58: case 0x59: case 0x78: case 0x79:  /* VPBROADCASTD/Q/B/W, VBROADCASTI32X2 */
                /* Источник и есть элемент: встроенной рассылки нет (x64 76). */
                if (bcast_mem) return true;
                /* VBROADCASTSD/F32X2 (19) и F32X4/F64X2 (1A) — только 256 и 512
                 * бит (x64 16, i386 8). */
                if ((op == 0x19 || op == 0x1a) && ll == 0) return true;
                /* VPBROADCASTB/W — только W0 (x64 24, i386 12). */
                return (op == 0x78 || op == 0x79) && w;
            case 0xcf:
                /* VGF2P8MULB — только W0 (x64 6, i386 6). */
                return w != 0;
            default:
                break;
        }
    }
    return false;
}

/* Разобранную команду — в #UD: код тот же, что у UD2; длина, адрес и байты
 * остаются. Операнды снимаются: у недопустимой команды их нет, а лифтер по ним
 * ставил бы побочные действия (например, обнуление верха приёмника в emit). */
static inline void hb_evex_mark_ud(hb_decoded_t* out) {
    out->opcode = HB_INS_UD;
    out->writes_flags = false;
    out->reads_flags = false;
    memset(&out->op1, 0, sizeof(out->op1));
    memset(&out->op2, 0, sizeof(out->op2));
    memset(&out->op3, 0, sizeof(out->op3));
    out->has_imm8 = false;
    out->imm8 = 0;
    out->evex_broadcast = false;
    out->evex_rounding = 0;
    out->evex_mask_lane = 0;
}
#endif
