/* Приёмка кодировщика логического непосредственного ARM64.
 *
 * ★ ПОЧЕМУ ЭТО НЕ «СОГЛАСИЕ КОДА С САМИМ СОБОЙ». Оракул здесь — ОБРАТНЫЙ ход,
 * написанный по букве ISA (ROR(Ones(imms+1), immr), повторить по элементу), а не
 * тот же алгоритм задом наперёд. Перебираются ВСЕ 8192 сочетания (N,immr,imms):
 * для каждого допустимого декодер даёт значение, и кодировщик обязан вернуть
 * ровно эти поля обратно.
 *
 * ★ ПРИБОР УМЕЕТ КРАСНЕТЬ. Отрицательные контроли ниже проверяют именно это:
 *   • 0 и ~0 обязаны быть отвергнуты (в кодировке непредставимы);
 *   • непредставимые маски (0x1234…, 0x101 и т.п.) обязаны быть отвергнуты;
 *   • намеренно испорченное поле (immr+1) обязано дать ДРУГОЕ значение —
 *     то есть декодер различает соседние кодировки, а не соглашается со всем;
 *   • 32-битная форма обязана отвергнуть значение с ненулевым верхом и любое,
 *     которому нужен N=1.
 *
 * Приёмка — строка "N passed, 0 failed" и код возврата, как у соседних тестов. */

#include "hb_arm64_logical_imm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed, failed;

static void ok(int cond, const char* what) {
    if (cond) { passed++; return; }
    failed++;
    fprintf(stderr, "hb_logical_imm_test: ОТКАЗ — %s\n", what);
}

/* Независимый декодер: буквальный ARM DecodeBitMasks для логических immediate. */
static int decode_bitmask(unsigned n, unsigned immr, unsigned imms, uint64_t* out) {
    unsigned len, esize, s, r, i;
    uint64_t welem, element;

    /* len = позиция старшего единичного бита в (N : NOT(imms)), 7 бит. */
    {
        unsigned combined = (n << 6) | ((~imms) & 0x3fu);
        int hi = -1;
        for (i = 0; i < 7; i++) if (combined & (1u << i)) hi = (int)i;
        if (hi < 0) return 0;              /* N:NOT(imms) == 0 — не определено */
        len = (unsigned)hi;
    }
    esize = 1u << len;
    s = imms & (esize - 1);
    r = immr & (esize - 1);
    if (s == esize - 1) return 0;          /* полоса во весь элемент — не определено */

    welem = (s == 63) ? ~(uint64_t)0 : (((uint64_t)1 << (s + 1)) - 1);
    /* ROR внутри элемента шириной esize. */
    if (r == 0) element = welem;
    else element = ((welem >> r) | (welem << (esize - r)));
    if (esize < 64) element &= (((uint64_t)1 << esize) - 1);

    *out = 0;
    for (i = 0; i < 64; i += esize) *out |= element << i;
    return 1;
}

int main(void) {
    unsigned n, immr, imms;
    unsigned covered = 0, distinct_ok = 0;
    uint64_t value;
    uint32_t enc;

    /* 1. Полный перебор кодировок: каждое допустимое (N,immr,imms) обязано
     *    вернуться из кодировщика ровно тем же значением полей. */
    for (n = 0; n < 2; n++)
    for (immr = 0; immr < 64; immr++)
    for (imms = 0; imms < 64; imms++) {
        if (!decode_bitmask(n, immr, imms, &value)) continue;
        covered++;
        if (!hb_arm64_logical_imm(value, true, &enc)) {
            failed++;
            fprintf(stderr, "hb_logical_imm_test: ОТКАЗ — значение 0x%016llx (N=%u immr=%u "
                            "imms=%u) объявлено некодируемым\n",
                    (unsigned long long)value, n, immr, imms);
            continue;
        }
        /* Кодировщик волен выбрать ДРУГУЮ, но эквивалентную запись (immr для
         * полосы во весь элемент неоднозначен), поэтому сверяем по ЗНАЧЕНИЮ:
         * декодируем то, что он выдал, и требуем совпадения значений. */
        {
            uint64_t back = 0;
            unsigned bn = (enc >> 12) & 1u, br = (enc >> 6) & 0x3fu, bs = enc & 0x3fu;
            if (!decode_bitmask(bn, br, bs, &back) || back != value) {
                failed++;
                fprintf(stderr, "hb_logical_imm_test: ОТКАЗ — 0x%016llx закодировано как "
                                "N=%u immr=%u imms=%u, что декодируется в 0x%016llx\n",
                        (unsigned long long)value, bn, br, bs, (unsigned long long)back);
            } else {
                distinct_ok++;
            }
        }
    }
    ok(covered > 4000, "перебор покрыл меньше 4000 допустимых кодировок — прибор слеп");
    ok(distinct_ok == covered, "не все допустимые кодировки сошлись по значению");

    /* 2. Отрицательный контроль: непредставимые значения обязаны быть отвергнуты. */
    ok(!hb_arm64_logical_imm(0, true, &enc), "ноль обязан быть отвергнут");
    ok(!hb_arm64_logical_imm(~(uint64_t)0, true, &enc), "все единицы обязаны быть отвергнуты");
    ok(!hb_arm64_logical_imm(0x123456789abcdef0ull, true, &enc), "0x1234… обязано быть отвергнуто");
    ok(!hb_arm64_logical_imm(0x0000000000000101ull, true, &enc), "0x101 обязано быть отвергнуто");
    ok(!hb_arm64_logical_imm(0x00000000000000b0ull, true, &enc), "0xb0 обязано быть отвергнуто");

    /* 3. Положительный контроль на значениях, ради которых кодировщик и заведён. */
    ok(hb_arm64_logical_imm(1, true, &enc), "маска выравнивания 1 обязана кодироваться");
    ok(hb_arm64_logical_imm(3, true, &enc), "маска выравнивания 3 обязана кодироваться");
    ok(hb_arm64_logical_imm(7, true, &enc), "маска выравнивания 7 обязана кодироваться");
    ok(hb_arm64_logical_imm(15, true, &enc), "маска выравнивания 15 обязана кодироваться");
    ok(hb_arm64_logical_imm(0xff00ff00ff00ff00ull, true, &enc), "0xff00… обязано кодироваться");
    ok(hb_arm64_logical_imm(0xfffffffffffffff0ull, true, &enc), "-16 обязано кодироваться");
    ok(hb_arm64_logical_imm(0x00000000ffffffffull, true, &enc), "0xffffffff обязано кодироваться");

    /* 4. Соседняя кодировка обязана давать ДРУГОЕ значение — иначе оракул слеп. */
    {
        uint64_t a = 0, b = 0;
        ok(decode_bitmask(1, 0, 2, &a) && decode_bitmask(1, 1, 2, &b) && a != b,
           "соседние immr обязаны давать разные значения");
        ok(decode_bitmask(1, 0, 2, &a) && decode_bitmask(1, 0, 3, &b) && a != b,
           "соседние imms обязаны давать разные значения");
        ok(decode_bitmask(1, 0, 2, &a) && a == 7,
           "N=1 immr=0 imms=2 обязано декодироваться в 7");
    }

    /* 5. 32-битная форма: верх обязан быть пуст, N=1 недопустим. */
    ok(!hb_arm64_logical_imm(0x1ffffffffull, false, &enc), "32-битная форма обязана отвергнуть верх");
    ok(hb_arm64_logical_imm(0xf, false, &enc) && ((enc >> 12) & 1u) == 0,
       "32-битная форма обязана дать N=0");
    ok(!hb_arm64_logical_imm(0x00000000ffffffffull, false, &enc),
       "32-битная форма обязана отвергнуть значение, которому нужен N=1");

    /* 6. Раскладка полей по местам в слове команды. */
    ok(hb_arm64_logical_fields((1u << 12) | (5u << 6) | 9u) ==
       ((1u << 22) | (5u << 16) | (9u << 10)), "поля N/immr/imms обязаны лечь по своим битам");

    printf("hb_logical_imm_test: перебрано допустимых кодировок %u\n", covered);
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
