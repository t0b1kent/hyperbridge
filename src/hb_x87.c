#include "hb_x87.h"
#include "hb_x87_exact.h"
#include "hb_x87_transcendental.h"
#include "hb_env.h"
#include "hb_gates.h"
#include <limits.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

#define HB_X87_DEFAULT_CW 0x037f
#define HB_X87_EMPTY_TAG  0x3
#define HB_X87_STATUS_EXCEPTION_MASK 0x00ffu
#define HB_X87_STATUS_BUSY_MASK      0x8000u
#define HB_X87_CONTROL_INVALID_MASK  0x0001u
#define HB_X87_STATUS_INVALID        0x0001u
#define HB_X87_STATUS_STACK_FAULT    0x0040u
#define HB_X87_STATUS_C1             0x0200u
#define HB_X87_CONTROL_PRECISION_MASK 0x0020u
#define HB_X87_STATUS_PRECISION       0x0020u
#define HB_X87_STATUS_ERROR_SUMMARY   0x0080u
#define HB_X87_CONTROL_DENORMAL_MASK  0x0002u
#define HB_X87_STATUS_DENORMAL        0x0002u
#define HB_X87_CONTROL_UNDERFLOW_MASK 0x0010u
#define HB_X87_STATUS_UNDERFLOW       0x0010u

/* ★ ЗОНД ПЕРЕПОЛНЕНИЯ СТЕКА x87 — гейт MACRUNNER_HB_X87_PROBE=1, умолчание 0.
 *
 * Установщик Diablo умирает на FILD, потому что стек x87 ПОЛОН. Починка 29.08 сделала
 * переполнение маскированным, но Delphi ставит управляющее слово $1332, где маска
 * недействительной операции СНЯТА, — и маскированный путь до него не доходит.
 * Приборов x87 в движке не было ни одного: неизвестно ни реальное CW, ни баланс
 * PUSH/POP. Зонд печатает и то и другое, первые 8 переполнений, только под гейтом. */
static unsigned long long hb_x87_push_n, hb_x87_pop_n, hb_x87_ovf_n;
static int hb_x87_probe_on(void) {
    static int cached = -1;
    if (cached < 0) cached = hb_gate_flag( HB_GATE_HB_X87_PROBE, 0);
    return cached;
}

static unsigned phys_st(const hb_x87_state_t* x87, unsigned index) {
    return (x87->top + index) & 7u;
}

static void set_top(hb_x87_state_t* x87, unsigned top) {
    x87->top = top & 7u;
    x87->status_word = (uint16_t)((x87->status_word & ~(7u << 11)) | (x87->top << 11));
}

static bool tag_is_empty(const hb_x87_state_t* x87, unsigned phys) {
    return ((x87->tag_word >> (phys * 2u)) & 0x3u) == HB_X87_EMPTY_TAG;
}

static void set_tag(hb_x87_state_t* x87, unsigned phys, uint16_t tag) {
    uint16_t shift = (uint16_t)(phys * 2u);
    x87->tag_word = (uint16_t)((x87->tag_word & ~(0x3u << shift)) | ((tag & 0x3u) << shift));
}

static void set_condition_bits(hb_x87_state_t* x87, unsigned c0, unsigned c1,
                               unsigned c2, unsigned c3) {
    const uint16_t mask = (uint16_t)~((1u << 8) | (1u << 9) | (1u << 10) | (1u << 14));
    x87->status_word = (uint16_t)((x87->status_word & mask)
                                  | ((c0 & 1u) << 8) | ((c1 & 1u) << 9)
                                  | ((c2 & 1u) << 10) | ((c3 & 1u) << 14));
}

/*
 * x87 tag word encoding (per Intel SDM, Vol. 1, §8.1.5):
 *   00 = Valid (normal finite nonzero)
 *   01 = Zero (true +/-0.0)
 *   10 = Special (NaN, +/-inf, denormal, unsupported)
 *   11 = Empty
 *
 * fpclassify is the canonical way to determine the class of a double — keeps
 * the rule centralized rather than re-deriving it at every store site.
 */
static uint16_t tag_from_f64(double value) {
    switch (fpclassify(value)) {
        case FP_ZERO:      return 0x1u;  /* 01 = zero */
        case FP_NAN:       /* fallthrough */
        case FP_INFINITE:  /* fallthrough */
        case FP_SUBNORMAL: return 0x2u;  /* 10 = special */
        case FP_NORMAL:    /* fallthrough */
        default:           return 0x0u;  /* 00 = valid */
    }
}

void hb_x87_reset(hb_x87_state_t* x87) {
    if (!x87) return;
    memset(x87, 0, sizeof(*x87));
    x87->control_word = HB_X87_DEFAULT_CW;
    x87->tag_word = 0xffff;
    set_top(x87, 0);
}

hb_result_t hb_x87_fnclex(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    x87->status_word = (uint16_t)(x87->status_word &
        ~(HB_X87_STATUS_EXCEPTION_MASK | HB_X87_STATUS_BUSY_MASK));
    return HB_OK;
}

hb_result_t hb_x87_fninit(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    hb_x87_reset(x87);
    return HB_OK;
}

/* FINCSTP / FDECSTP — rotate TOP by +/-1, no value changes. The 8 physical
 * slots stay where they are; only the "ST(0)" pointer moves. Per Intel SDM,
 * this does NOT push or pop — it just changes which slot is ST(0). */
/* ★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — FFREE ST(i).
 *
 * Delphi заканчивает большой `FillChar` идиомой `FFREE ST(0); FINCSTP` (в установщике
 * Diablo это `40328e: dd c0` и `403290: d9 f7`). `FFREE` помечает слот свободным, а
 * `FINCSTP` двигает вершину — вместе это «снять значение, ничего не записывая».
 *
 * У нас `FFREE` поднимался в NOP (`hb_lift_x86.c`, комментарий «We model as NOP»),
 * поэтому тег слота оставался занятым, а вершина уходила дальше. Каждый вызов
 * `FillChar` терял один слот; на восьмом стек оказывался полон, и следующий `FILD`
 * в `System.Move` давал переполнение -> c0000092 -> InnoSetup отменял распаковку.
 * Замер: `x87-overflow: top=0 tag=0x7fff pushes=320 pops=318`, а трасса показала
 * `pc=0x40328e op=X87_FINCSTP top=7->0 tag=7fff->7fff` — тег не изменился.
 *
 * По руководству Intel FFREE меняет ТОЛЬКО тег; значение, вершина и флаги не трогаются. */
hb_result_t hb_x87_ffree(hb_x87_state_t* x87, unsigned index) {
    unsigned phys;

    if (!x87 || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    set_tag(x87, phys, HB_X87_EMPTY_TAG);
    x87->st_ext_valid &= (uint8_t)~(1u << phys);
    return HB_OK;
}

hb_result_t hb_x87_fincstp(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    set_top(x87, (x87->top + 1u) & 7u);
    return HB_OK;
}

hb_result_t hb_x87_fdecstp(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    set_top(x87, (x87->top - 1u) & 7u);
    return HB_OK;
}

/* FXAM — examine ST(0). Intel encodes the class in C3:C2:C0 and the
 * operand sign in C1:
 *   000 unsupported, 001 NaN, 010 normal, 011 infinity,
 *   100 zero, 101 empty, 110 denormal.
 */
hb_result_t hb_x87_fxam(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;

    unsigned phys = x87->top;
    double value = x87->st[phys];
    bool empty = tag_is_empty(x87, phys);

    /* An occupied cached normal may have a zero or infinite binary64 preview.
     * Classify its represented raw value; preserve the existing path for empty,
     * uncached, excluded encodings and pending unmasked exceptions. */
    if (!empty && !(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t raw[10];
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            uint64_t significand;
            uint16_t sign_exp;
            memcpy(&significand, raw, sizeof(significand));
            memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
            unsigned exponent = sign_exp & 0x7fffu;
            if (exponent != 0 && exponent != 0x7fffu &&
                (significand & UINT64_C(0x8000000000000000))) {
                set_condition_bits(x87, 0, sign_exp >> 15, 1, 0);
                return HB_OK;
            }
        }
    }
    unsigned c0, c2, c3;
    unsigned c1 = (!empty && signbit(value)) ? 1u : 0u;

    if (empty) {
        c3 = 1u; c2 = 0u; c0 = 1u;
    } else {
        switch (fpclassify(value)) {
            case FP_NAN:       c3 = 0u; c2 = 0u; c0 = 1u; break;
            case FP_INFINITE:  c3 = 0u; c2 = 1u; c0 = 1u; break;
            case FP_ZERO:      c3 = 1u; c2 = 0u; c0 = 0u; break;
            case FP_SUBNORMAL: c3 = 1u; c2 = 1u; c0 = 0u; break;
            case FP_NORMAL:    c3 = 0u; c2 = 1u; c0 = 0u; break;
            default:           c3 = 0u; c2 = 0u; c0 = 0u; break;
        }
    }

    set_condition_bits(x87, c0, c1, c2, c3);
    return HB_OK;
}

/* QNaN indefinite для x87: знак 1, экспонента все единицы, старший бит мантиссы 1.
 * Собираем через объединение, а не литералом: NAN из math.h не гарантирует знак. */
static double hb_x87_indefinite_f64(void) {
    union { uint64_t u; double d; } v;
    v.u = 0xFFF8000000000000ull;
    return v.d;
}

hb_result_t hb_x87_push_f64(hb_x87_state_t* x87, double value) {
    unsigned top;

    if (!x87) return HB_ERR_INVALID_ARG;
    ++hb_x87_push_n;
    top = (x87->top - 1u) & 7u;

    /* ★★★★★★ MacRunner 2026-08-29 — ПЕРЕПОЛНЕНИЕ СТЕКА x87 НЕ ОБРЫВАЕТ ИСПОЛНЕНИЕ.
     *
     * Здесь стоял безусловный `return HB_ERR_EXEC_FAULT`, и любой лишний PUSH убивал
     * прогон. На настоящем x86 это не так: переполнение стека — «недействительная
     * операция» со ЗНАКОМ СТЕКА, и исключение #IA по умолчанию ЗАМАСКИРОВАНО (бит IM
     * управляющего слова, начальное значение 0x037F — все маски взведены). Маскированное
     * поведение по руководству Intel (том 1, 8.5.1): установить IE и SF в статусном слове,
     * C1 = 1 (переполнение, а не потеря значимости), записать в приёмник QNaN indefinite
     * и ПРОДОЛЖИТЬ. Прерывать работу процессор обязан только при снятой маске.
     *
     * Чего это стоило: установщик Diablo (Delphi/InnoSetup) считает на x87 длины и
     * смещения строк. Обрыв на PUSH давал неверные вычисления, и имя DLL приходило с
     * испорченным ПЕРВЫМ БАЙТОМ КАЖДОГО ФРАГМЕНТА склейки:
     *   C:\windows\system32\shell32.dll  ->  D:\windows\systdm32\thell320dll
     *      ^          ^       ^         ^      (позиции 0, 15, 20, 27 — начала фрагментов)
     * Эталон (CrossOver) на том же файле грузит `shell32.dll` тринадцать раз без единого
     * искажения — то есть дефект был наш.
     *
     * Признак в журнале: `interp-unsupported: r=-9 op=X87_FILD`, где -9 это EXEC_FAULT,
     * а вовсе не «не поддержано»: FILD реализован, падал именно PUSH. */
    if (!tag_is_empty(x87, top)) {
        const uint16_t IE = 0x0001u, SF = 0x0040u, C1 = 0x0200u, ES = 0x0080u, B = 0x8000u;
        if (hb_x87_probe_on() && ++hb_x87_ovf_n <= 8)
            fprintf(stderr, "macrunner-hb-x87-overflow: n=%llu top=%u tag=0x%04x cw=0x%04x sw=0x%04x im=%u pushes=%llu pops=%llu\n",
                    hb_x87_ovf_n, x87->top, (unsigned)x87->tag_word, (unsigned)x87->control_word,
                    (unsigned)x87->status_word, (unsigned)(x87->control_word & 1u),
                    hb_x87_push_n, hb_x87_pop_n);
        const uint16_t IM = 0x0001u;                 /* маска недействительной операции */
        x87->status_word |= (uint16_t)(IE | SF | C1);
        if (!(x87->control_word & IM)) {
            /* Маска снята — исключение доходит до гостя, как на железе. */
            x87->status_word |= (uint16_t)(ES | B);
            return HB_ERR_EXEC_FAULT;
        }
        /* Маскированный путь: приёмник получает QNaN indefinite, работа продолжается. */
        set_top(x87, top);
        x87->st[top] = hb_x87_indefinite_f64();
        x87->st_ext_valid &= (uint8_t)~(1u << top);
        set_tag(x87, top, tag_from_f64(x87->st[top]));   /* NaN -> метка «особое» */
        return HB_OK;
    }
    set_top(x87, top);
    x87->st[top] = value;
    x87->st_ext_valid &= (uint8_t)~(1u << top);   /* итерация 516: тень гасим */
    set_tag(x87, top, tag_from_f64(value));
    return HB_OK;
}

hb_result_t hb_x87_push_f64_ext(hb_x87_state_t* x87, double value, const uint8_t ext[10]) {
    /* A masked stack overflow also returns HB_OK, but installs indefinite
     * instead of value. Do not attach the caller's raw bytes to that result. */
    bool destination_empty = x87 && tag_is_empty(x87, (x87->top - 1u) & 7u);
    hb_result_t r = hb_x87_push_f64(x87, value);
    if (r != HB_OK || !ext || !destination_empty) return r;
    memcpy(x87->st_ext[x87->top], ext, 10);
    x87->st_ext_valid |= (uint8_t)(1u << x87->top);
    return HB_OK;
}

/* ★★★★★★ MacRunner 2026-08-30, лейн УСТАНОВЩИКИ — FILD m64 / FISTP m64 БЕЗ ПОТЕРИ БИТ.
 *
 * Delphi копирует память ЧЕРЕЗ x87: `System.Move` в цикле делает
 * `fildll (%ecx,%eax)` / `fistpll (%ecx,%edx)` — по 8 байт как 64-битное целое
 * (в установщике Diablo это адреса 0x403030/0x403033).
 *
 * У настоящего x87 регистр 80-битный: мантисса 64 бита, и такой перенос ТОЧЕН.
 * У нас `x87->st[]` объявлен `double` — мантисса 53 бита. Значение, которому нужно
 * больше 53 бит, ОКРУГЛЯЕТСЯ, и копия отличается от оригинала.
 *
 * Замер (не гипотеза): все ЧЕТЫРЕ наблюдённые порчи имени DLL воспроизводятся
 * точным вычислением `(int64)(double)v` над теми же 8 байтами UTF-16:
 *
 *   "C:\w" 0077005c003a0043 -> ...0044   C -> D   (нужно 55 бит, теряем 2)
 *   "em32" 00320033006d0065 -> ...0064   e -> d   (54 бита, теряем 1)
 *   "shel" 006c006500680073 -> ...0074   s -> t   (55 бит, теряем 2)
 *   ".dll" 006c006c0064002e -> ...0030   . -> 0   (55 бит, теряем 2)
 *
 * Отсюда и формула порчи `(v+2)&~3`, замеченная раньше: это округление к
 * ближайшему при потере двух младших бит. Портится ВСЕГДА младшее 16-битное
 * слово фрагмента — то есть первый символ каждого копируемого куска.
 *
 * ВАЖНО: соседний комментарий выше (переполнение стека, 29.08) приписывает эту же
 * порчу обрыву на PUSH. Это неверно: обрыв убран, порча осталась — в прогоне 30.08
 * `x87ctx-bad 0`, `interp-unsupported 0`, а порча те же 6 строк.
 *
 * Лечение — не менять тип `st[]` (на macOS ARM64 `long double` это тот же двойной
 * формат, шире не станет), а положить ТОЧНОЕ значение в уже готовую тень 80 бит
 * (механизм итерации 516) и брать его обратно при FISTP, пока регистр не тронут
 * арифметикой: любая запись в регистр тень гасит (строки 300, 313).
 *
 * Гейт `MACRUNNER_HB_X87_EXACT_I64`, умолчание 1; 0 даёт прежнее поведение
 * для парного замера на ОДНОМ двоичном. */
static void hb_x87_ext80_from_i64(int64_t v, uint8_t out[10]) {
    uint64_t u;
    unsigned sign = 0;
    int p;
    uint16_t se;

    memset(out, 0, 10);
    if (v == 0) return;                       /* +0.0: экспонента и мантисса нули */
    if (v < 0) { sign = 1; u = (uint64_t)(-(v + 1)) + 1u; } else u = (uint64_t)v;
    p = 63;
    while (!((u >> p) & 1u)) --p;             /* старший установленный бит */
    u <<= (unsigned)(63 - p);                 /* явная единица в бит 63 */
    se = (uint16_t)(((uint16_t)sign << 15) | (uint16_t)(16383 + p));
    memcpy(out, &u, 8);
    memcpy(out + 8, &se, 2);
}

/* State transport must not change host FP status or depend on host rounding.
 * Keep the exact ext80 payload separately from this nearest-even preview. */
static uint64_t hb_x87_round_shift_u64(uint64_t value, unsigned shift) {
    if (shift == 0) return value;
    if (shift > 64) return 0;
    if (shift == 64)
        return value > UINT64_C(0x8000000000000000) ? 1u : 0u;
    uint64_t integer = value >> shift;
    uint64_t remainder = value & ((UINT64_C(1) << shift) - 1u);
    uint64_t half = UINT64_C(1) << (shift - 1u);
    return integer + (remainder > half || (remainder == half && (integer & 1u)));
}

static uint64_t hb_x87_ext80_preview_bits(uint64_t significand, uint16_t sign_exp) {
    uint64_t sign = (uint64_t)(sign_exp & 0x8000u) << 48;
    unsigned exponent = sign_exp & 0x7fffu;

    /* Every ext80 subnormal and pseudo-denormal is below half the smallest
     * binary64 subnormal. Unsupported encodings get a quiet-NaN preview. */
    if (exponent == 0) return sign;
    if (exponent == 0x7fffu || !(significand & UINT64_C(0x8000000000000000))) {
        if (exponent == 0x7fffu && significand == UINT64_C(0x8000000000000000))
            return sign | UINT64_C(0x7ff0000000000000);
        return sign | UINT64_C(0x7ff8000000000000) |
               ((significand >> 11) & UINT64_C(0x000fffffffffffff));
    }

    int unbiased = (int)exponent - 16383;
    if (unbiased > 1023) return sign | UINT64_C(0x7ff0000000000000);
    if (unbiased < -1022) {
        unsigned shift = (unsigned)(-unbiased - 1011);
        /* Rounding can produce the smallest normal binary64 bit pattern. */
        return sign | hb_x87_round_shift_u64(significand, shift);
    }

    uint64_t rounded = hb_x87_round_shift_u64(significand, 11);
    if (rounded == UINT64_C(0x0020000000000000)) {
        rounded >>= 1;
        if (++unbiased > 1023) return sign | UINT64_C(0x7ff0000000000000);
    }
    return sign | ((uint64_t)(unbiased + 1023) << 52) |
           (rounded & UINT64_C(0x000fffffffffffff));
}

hb_result_t hb_x87_push_i64_exact(hb_x87_state_t* x87, int64_t value) {
    uint8_t ext[10];
    uint64_t significand, preview_bits;
    uint16_t sign_exp;
    double preview;
    if (!x87) return HB_ERR_INVALID_ARG;
    bool empty = tag_is_empty(x87, (x87->top - 1u) & 7u);

    hb_x87_ext80_from_i64(value, ext);
    memcpy(&significand, ext, sizeof(significand));
    memcpy(&sign_exp, ext + 8, sizeof(sign_exp));
    /* Keep the exact integer in raw80; the internal binary64 view is a
     * nearest-even preview and must not depend on or change host FP state. */
    preview_bits = hb_x87_ext80_preview_bits(significand, sign_exp);
    memcpy(&preview, &preview_bits, sizeof(preview));
    hb_result_t r = hb_x87_push_f64_ext(x87, preview, ext);
    if (r == HB_OK && empty) x87->status_word &= (uint16_t)~HB_X87_STATUS_C1;
    return r;
}

static void hb_x87_f64_bits_to_ext80(uint64_t bits, uint8_t out[10]) {
    uint16_t sign_exp = (uint16_t)((bits >> 48) & 0x8000u);
    unsigned exponent = (unsigned)((bits >> 52) & 0x7ffu);
    uint64_t fraction = bits & UINT64_C(0x000fffffffffffff);
    uint64_t significand = 0;

    if (exponent == 0) {
        if (fraction != 0) {
            unsigned leading_bit = 0;
            for (uint64_t scan = fraction; scan > 1; scan >>= 1) leading_bit++;
            significand = fraction << (63u - leading_bit);
            sign_exp |= (uint16_t)(16383 - 1074 + leading_bit);
        }
    } else {
        significand = UINT64_C(0x8000000000000000) | (fraction << 11);
        sign_exp |= exponent == 0x7ffu ? 0x7fffu : (uint16_t)(exponent + 15360u);
    }
    memcpy(out, &significand, sizeof(significand));
    memcpy(out + 8, &sign_exp, sizeof(sign_exp));
}

static uint16_t hb_x87_tag_from_ext80(uint64_t significand, uint16_t sign_exp) {
    unsigned exponent = sign_exp & 0x7fffu;
    if (exponent == 0 && significand == 0) return 0x1u;
    if (exponent != 0 && exponent != 0x7fffu &&
        (significand & UINT64_C(0x8000000000000000))) return 0x0u;
    return 0x2u;
}

hb_result_t hb_x87_set_st_ext80(hb_x87_state_t* x87, unsigned index,
                              const uint8_t ext[10], bool occupied) {
    if (!x87 || !ext || index >= 8) return HB_ERR_INVALID_ARG;
    uint8_t raw[10];
    uint64_t significand;
    uint16_t sign_exp;
    memcpy(raw, ext, sizeof(raw));
    memcpy(&significand, raw, sizeof(significand));
    memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
    uint16_t tag = occupied ? hb_x87_tag_from_ext80(significand, sign_exp) : HB_X87_EMPTY_TAG;
    unsigned phys = phys_st(x87, index);
    uint64_t preview = hb_x87_ext80_preview_bits(significand, sign_exp);
    memcpy(&x87->st[phys], &preview, sizeof(preview));
    memcpy(x87->st_ext[phys], raw, sizeof(raw));
    x87->st_ext_valid |= (uint8_t)(1u << phys);
    set_tag(x87, phys, tag);
    return HB_OK;
}

hb_result_t hb_x87_push_raw_ext80(hb_x87_state_t* x87, const uint8_t ext[10]) {
    if (!x87 || !ext) return HB_ERR_INVALID_ARG;
    uint8_t raw[10];
    memcpy(raw, ext, sizeof(raw));
    bool empty = tag_is_empty(x87, (x87->top - 1u) & 7u);
    hb_result_t r = hb_x87_push_f64(x87, 0.0);
    if (r != HB_OK || !empty) return r;
    /* The raw setter derives both the tag and integer-only binary64 preview;
     * a huge/tiny normal must not be classified from its narrowed preview. */
    r = hb_x87_set_st_ext80(x87, 0, raw, true);
    if (r == HB_OK) x87->status_word &= (uint16_t)~HB_X87_STATUS_C1;
    return r;
}

hb_result_t hb_x87_save_st_ext80(const hb_x87_state_t* x87, unsigned index,
                               uint8_t out[10]) {
    if (!x87 || !out || index >= 8) return HB_ERR_INVALID_ARG;
    unsigned phys = phys_st(x87, index);
    if (x87->st_ext_valid & (1u << phys)) {
        memmove(out, x87->st_ext[phys], 10);
    } else {
        uint64_t bits;
        memcpy(&bits, &x87->st[phys], sizeof(bits));
        hb_x87_f64_bits_to_ext80(bits, out);
    }
    return HB_OK;
}

hb_result_t hb_x87_st_ext80(const hb_x87_state_t* x87, unsigned index, uint8_t out[10]) {
    unsigned phys;
    if (!x87 || !out || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    if (tag_is_empty(x87, phys)) return HB_ERR_EXEC_FAULT;
    if (!(x87->st_ext_valid & (1u << phys))) return HB_ERR_UNSUPPORTED_FEATURE;
    memcpy(out, x87->st_ext[phys], 10);
    return HB_OK;
}

hb_result_t hb_x87_reclassify_tags(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    uint16_t incoming = x87->tag_word;
    uint16_t tags = 0xffffu;
    for (unsigned i = 0; i < 8; i++) {
        unsigned phys = phys_st(x87, i);
        if (((incoming >> (phys * 2u)) & 3u) == HB_X87_EMPTY_TAG) continue;
        uint8_t raw[10];
        uint64_t significand;
        uint16_t sign_exp;
        hb_result_t r = hb_x87_save_st_ext80(x87, i, raw);
        if (r != HB_OK) return r;
        memcpy(&significand, raw, sizeof(significand));
        memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
        uint16_t tag = hb_x87_tag_from_ext80(significand, sign_exp);
        tags = (uint16_t)((tags & ~(3u << (phys * 2u))) | (tag << (phys * 2u)));
    }
    /* FLDENV changes classifications, not register data or cache validity. */
    x87->tag_word = tags;
    return HB_OK;
}

hb_result_t hb_x87_pop(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    ++hb_x87_pop_n;
    if (tag_is_empty(x87, x87->top)) return HB_ERR_EXEC_FAULT;
    set_tag(x87, x87->top, HB_X87_EMPTY_TAG);
    set_top(x87, (x87->top + 1u) & 7u);
    return HB_OK;
}

/* Once FSTP has completed its destination store, the architectural pop occurs
 * even when the masked source underflow left the old TOP slot empty. */
hb_result_t hb_x87_fstp_pop(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    ++hb_x87_pop_n;
    set_tag(x87, x87->top, HB_X87_EMPTY_TAG);
    set_top(x87, (x87->top + 1u) & 7u);
    return HB_OK;
}

/* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 891 — ЧТЕНИЕ ПУСТОГО РЕГИСТРА СТЕКА.
 *
 * Здесь стоял безусловный `HB_ERR_EXEC_FAULT`, то есть команда СВАЛИВАЛАСЬ. Это неверно:
 * после `FNINIT` управляющее слово маскирует недопустимую операцию, и переполнение стека вниз
 * обязано поставить IE и SF, снять C1 и дать «неопределённость» QNaN — исполнение при этом
 * продолжается. Отказ правилен только при СНЯТОЙ маске.
 *
 * Ровно это делает `hb_x87_stack_underflow()`, написанный в дереве заранее и НЕ ВЫЗЫВАВШИЙСЯ
 * ниоткуда (0 вызовов на момент правки) — его же комментарий обещает «materialize the masked
 * invalid response for an empty x87 source».
 *
 * Правка одноточечная намеренно: `hb_x87_st_f64` — единственная дверь чтения ИСТОЧНИКА, через
 * неё идут все 39 мест (25 в этом файле, 14 в интерпретаторе). Патчить их по одному значило бы
 * развести расхождение. `FXAM` пустоту смотрит отдельно (`tag_is_empty`) и не затронут.
 *
 * Замер до правки: `fadd st(4)` при пустом ST(4) -> result=-9, при занятом -> 0; эталон
 * исполняет и не падает. По стенду это 86 отказов из 92. */
hb_result_t hb_x87_st_f64(hb_x87_state_t* x87, unsigned index, double* out) {
    unsigned phys;

    if (!x87 || !out || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    if (tag_is_empty(x87, phys)) return hb_x87_stack_underflow(x87, out);
    *out = x87->st[phys];
    return HB_OK;
}

hb_result_t hb_x87_set_st_f64(hb_x87_state_t* x87, unsigned index, double value) {
    unsigned phys;

    if (!x87 || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    /* Итерация 891, вторая половина: ПУСТОЙ ПРИЁМНИК арифметики. Формы с выталкиванием
     * (`faddp st(i), st(0)` и родня) пишут результат в ST(i); если тот пуст, это то же
     * маскированное переполнение стека, а не повод свалить команду: ответ — «неопределённость»
     * в приёмник, затем штатное выталкивание. Отказ остаётся только при СНЯТОЙ маске, и об этом
     * судит сам `hb_x87_stack_underflow`.
     * Замер до правки: 18 отказов, все формы с `p` (faddp, fsubp, fdivp, fmulp, fsubrp, fdivrp). */
    if (tag_is_empty(x87, phys)) {
        double indefinite;
        hb_result_t ru = hb_x87_stack_underflow(x87, &indefinite);
        if (ru != HB_OK) return ru;          /* маска снята — отказ правилен */
        value = indefinite;
    }
    x87->st[phys] = value;
    x87->st_ext_valid &= (uint8_t)~(1u << phys);   /* итерация 516 */
    set_tag(x87, phys, tag_from_f64(value));
    return HB_OK;
}

/* FST/FSTP may write an empty destination register.  This differs from
 * arithmetic result replacement, where an empty ST(i) is itself underflow. */
hb_result_t hb_x87_store_st_f64(hb_x87_state_t* x87, unsigned index, double value) {
    unsigned phys;

    if (!x87 || index >= 8) return HB_ERR_INVALID_ARG;
    phys = phys_st(x87, index);
    x87->st[phys] = value;
    x87->st_ext_valid &= (uint8_t)~(1u << phys);   /* итерация 516 */
    set_tag(x87, phys, tag_from_f64(value));
    return HB_OK;
}

/* Materialize the masked-invalid response for an empty x87 source.  The
 * instruction owns any subsequent destination write/pop so memory faults
 * still suppress the pop.  With IM clear, preserve the synchronous fault. */
hb_result_t hb_x87_stack_underflow(hb_x87_state_t* x87, double* indefinite) {
    const uint64_t indefinite_bits = UINT64_C(0xfff8000000000000);

    if (!x87 || !indefinite) return HB_ERR_INVALID_ARG;
    x87->status_word = (uint16_t)((x87->status_word |
        HB_X87_STATUS_INVALID | HB_X87_STATUS_STACK_FAULT) & ~HB_X87_STATUS_C1);
    if (!(x87->control_word & HB_X87_CONTROL_INVALID_MASK)) {
        x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
        return HB_ERR_EXEC_FAULT;
    }
    memcpy(indefinite, &indefinite_bits, sizeof(*indefinite));
    return HB_OK;
}

hb_result_t hb_x87_fcom(hb_x87_state_t* x87, double rhs) {
    double lhs;
    uint16_t sw;

    if (!x87) return HB_ERR_INVALID_ARG;
    if (hb_x87_st_f64(x87, 0, &lhs) != HB_OK) return HB_ERR_EXEC_FAULT;

    sw = (uint16_t)(x87->status_word & ~(uint16_t)((1u << 8) | (1u << 10) | (1u << 14)));
    if (isnan(lhs) || isnan(rhs)) {
        sw |= (uint16_t)((1u << 8) | (1u << 10) | (1u << 14));
    } else if (lhs < rhs) {
        sw |= (uint16_t)(1u << 8);
    } else if (lhs == rhs) {
        sw |= (uint16_t)(1u << 14);
    }
    x87->status_word = sw;
    return HB_OK;
}

hb_result_t hb_x87_fldcw(hb_x87_state_t* x87, uint16_t control_word) {
    if (!x87) return HB_ERR_INVALID_ARG;
    x87->control_word = control_word;
    return HB_OK;
}

hb_result_t hb_x87_fnstcw(const hb_x87_state_t* x87, uint16_t* out) {
    if (!x87 || !out) return HB_ERR_INVALID_ARG;
    *out = x87->control_word;
    return HB_OK;
}

hb_result_t hb_x87_frndint(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    const uint64_t integer_bit = UINT64_C(0x8000000000000000);
    const uint64_t quiet_bit = UINT64_C(0x4000000000000000);
    uint8_t raw[10];
    uint64_t significand = 0;
    uint16_t sign_exp = 0;
    bool empty = tag_is_empty(x87, phys_st(x87, 0));
    if (!empty) {
        hb_result_t r = hb_x87_save_st_ext80(x87, 0, raw);
        if (r != HB_OK) return r;
        memcpy(&significand, raw, sizeof(significand));
        memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
    }
    unsigned exponent = sign_exp & 0x7fffu;
    bool unsupported = exponent != 0 && !(significand & integer_bit);
    bool snan = exponent == 0x7fffu && (significand & ~integer_bit) != 0 &&
                !(significand & quiet_bit);
    /* C0/C2/C3 are undefined for FRNDINT; retain their stored values. All
     * exception flags, including a preexisting SF, remain sticky. */
    x87->status_word &= (uint16_t)~HB_X87_STATUS_C1;
    if (empty || unsupported || snan) {
        x87->status_word |= HB_X87_STATUS_INVALID;
        if (empty) x87->status_word |= HB_X87_STATUS_STACK_FAULT;
        if (!(x87->control_word & HB_X87_CONTROL_INVALID_MASK)) {
            x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
            return HB_ERR_EXEC_FAULT;
        }
        if (empty || unsupported) {
            significand = integer_bit | quiet_bit;
            sign_exp = 0xffffu;
        } else {
            significand |= quiet_bit;
        }
    } else if (exponent != 0x7fffu && significand != 0) {
        /* FRNDINT raises #D for true and pseudo-denormals. Both use the
         * minimum normal exponent; an unmasked #D suppresses the result. */
        if (exponent == 0) {
            x87->status_word |= HB_X87_STATUS_DENORMAL;
            if (!(x87->control_word & HB_X87_CONTROL_DENORMAL_MASK)) {
                x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
                return HB_ERR_EXEC_FAULT;
            }
        }
        int unbiased = (int)(exponent ? exponent : 1u) - 16383;
        /* Every supported ext80 value with exponent >=63 is integral. Keep
         * its complete significand, even outside binary64 or int64 range.
         * FRNDINT uses CW.RC and is independent of precision control. */
        if (unbiased < 63) {
            unsigned shift = (unsigned)(63 - unbiased);
            uint64_t magnitude = shift >= 64 ? 0 : significand >> shift;
            bool inexact = shift >= 64 ? significand != 0 :
                           (significand & ((UINT64_C(1) << shift) - 1u)) != 0;
            unsigned rc = (x87->control_word >> 10) & 3u;
            bool negative = (sign_exp & 0x8000u) != 0;
            uint64_t rounded = magnitude;
            if (rc == 0) rounded = hb_x87_round_shift_u64(significand, shift);
            else if (inexact && ((rc == 1 && negative) || (rc == 2 && !negative))) rounded++;
            if (inexact) {
                x87->status_word |= HB_X87_STATUS_PRECISION;
                if (rounded > magnitude) x87->status_word |= HB_X87_STATUS_C1;
                if (!(x87->control_word & HB_X87_CONTROL_PRECISION_MASK))
                    x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
            }
            sign_exp &= 0x8000u;
            significand = 0;
            if (rounded != 0) {
                unsigned leading = 0;
                for (uint64_t scan = rounded; scan > 1; scan >>= 1) leading++;
                significand = rounded << (63u - leading);
                sign_exp |= (uint16_t)(16383u + leading);
            }
        }
    }
    /* Raw transport refreshes the preview/tag without host FP arithmetic.
     * Unmasked precision completes the result; subsequent #MF delivery and
     * checks for exceptions pending on entry belong to the runtime. */
    memcpy(raw, &significand, sizeof(significand));
    memcpy(raw + 8, &sign_exp, sizeof(sign_exp));
    return hb_x87_set_st_ext80(x87, 0, raw, true);
}

static hb_result_t hb_x87_integer_invalid(hb_x87_state_t* x87, unsigned width,
                                          bool empty, int64_t* out) {
    x87->status_word = (uint16_t)((x87->status_word & ~HB_X87_STATUS_C1) |
                                 HB_X87_STATUS_INVALID);
    if (empty) x87->status_word |= HB_X87_STATUS_STACK_FAULT;
    /* SF and all previous exception flags are sticky, including when this
     * invalid operation is unrelated to a stack fault. */
    if (!(x87->control_word & HB_X87_CONTROL_INVALID_MASK)) {
        x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
        return HB_ERR_EXEC_FAULT;
    }
    *out = width == 64 ? INT64_MIN : -(INT64_C(1) << (width - 1u));
    return HB_OK;
}

hb_result_t hb_x87_integer_from_st0(hb_x87_state_t* x87, unsigned width,
                                   bool truncate, int64_t* out) {
    if (!x87 || !out || (width != 16 && width != 32 && width != 64))
        return HB_ERR_INVALID_ARG;
    if (tag_is_empty(x87, x87->top))
        return hb_x87_integer_invalid(x87, width, true, out);

    uint8_t raw[10];
    uint64_t significand;
    uint16_t sign_exp;
    hb_result_t r = hb_x87_save_st_ext80(x87, 0, raw);
    if (r != HB_OK) return r;
    memcpy(&significand, raw, sizeof(significand));
    memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
    unsigned exponent = sign_exp & 0x7fffu;
    bool negative = (sign_exp & 0x8000u) != 0;
    if (exponent == 0x7fffu ||
        (exponent != 0 && !(significand & UINT64_C(0x8000000000000000))))
        return hb_x87_integer_invalid(x87, width, false, out);

    /* Denormals and pseudo-denormals use the minimum normal exponent.
     * These integer-store instructions do not signal denormal-operand #D. */
    int unbiased = (int)(exponent ? exponent : 1u) - 16383;
    if (unbiased > 63)
        return hb_x87_integer_invalid(x87, width, false, out);

    uint64_t magnitude;
    bool inexact = false, increment = false;
    if (unbiased == 63) {
        magnitude = significand;
    } else {
        unsigned shift = (unsigned)(63 - unbiased);
        if (shift >= 64) {
            magnitude = 0;
            inexact = significand != 0;
        } else {
            magnitude = significand >> shift;
            inexact = (significand & ((UINT64_C(1) << shift) - 1u)) != 0;
        }
        unsigned rc = truncate ? 3u : (unsigned)((x87->control_word >> 10) & 3u);
        if (rc == 0) {
            uint64_t rounded = hb_x87_round_shift_u64(significand, shift);
            increment = rounded > magnitude;
            magnitude = rounded;
        } else if (inexact && ((rc == 1 && negative) || (rc == 2 && !negative))) {
            magnitude++;
            increment = true;
        }
    }

    uint64_t limit = UINT64_C(1) << (width - 1u);
    if (!negative) limit--;
    if (magnitude > limit)
        return hb_x87_integer_invalid(x87, width, false, out);

    x87->status_word &= (uint16_t)~HB_X87_STATUS_C1;
    if (inexact) {
        x87->status_word |= HB_X87_STATUS_PRECISION;
        if (increment && !truncate) x87->status_word |= HB_X87_STATUS_C1;
        /* Unmasked precision completes the store/pop like masked precision.
         * ES/B records the pending exception; later #MF delivery is separate. */
        if (!(x87->control_word & HB_X87_CONTROL_PRECISION_MASK))
            x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
    }
    if (magnitude == UINT64_C(0x8000000000000000)) *out = INT64_MIN;
    else *out = negative ? -(int64_t)magnitude : (int64_t)magnitude;
    return HB_OK;
}

hb_result_t hb_x87_fistp_i16(hb_x87_state_t* x87, int16_t* out) {
    int64_t value;
    if (!out) return HB_ERR_INVALID_ARG;
    hb_result_t r = hb_x87_integer_from_st0(x87, 16, false, &value);
    if (r != HB_OK) return r;
    *out = (int16_t)value;
    return hb_x87_fstp_pop(x87);
}

hb_result_t hb_x87_fistp_i32(hb_x87_state_t* x87, int32_t* out) {
    int64_t value;
    if (!out) return HB_ERR_INVALID_ARG;
    hb_result_t r = hb_x87_integer_from_st0(x87, 32, false, &value);
    if (r != HB_OK) return r;
    *out = (int32_t)value;
    return hb_x87_fstp_pop(x87);
}

hb_result_t hb_x87_fistp_i64(hb_x87_state_t* x87, int64_t* out) {
    if (!out) return HB_ERR_INVALID_ARG;
    hb_result_t r = hb_x87_integer_from_st0(x87, 64, false, out);
    if (r != HB_OK) return r;
    return hb_x87_fstp_pop(x87);
}

hb_result_t hb_x87_fist_i16(hb_x87_state_t* x87, int16_t* out) {
    int64_t value;
    if (!out) return HB_ERR_INVALID_ARG;
    hb_result_t r = hb_x87_integer_from_st0(x87, 16, false, &value);
    if (r != HB_OK) return r;
    *out = (int16_t)value;
    return HB_OK;
}

hb_result_t hb_x87_fist_i32(hb_x87_state_t* x87, int32_t* out) {
    int64_t value;
    if (!out) return HB_ERR_INVALID_ARG;
    hb_result_t r = hb_x87_integer_from_st0(x87, 32, false, &value);
    if (r != HB_OK) return r;
    *out = (int32_t)value;
    return HB_OK;
}

/* ============================================================
 * D9 F0-FF transcendentals (libm-backed).
 *
 * Each function reads ST(0) (and ST(1) for binary ops), replaces the result
 * in the documented slot, and pops or pushes per Intel SDM. We do not yet
 * raise exception flags for edge cases (denormal, invalid, partial-remainder
 * C0..C3 bits); that is gap matrix #3 (status word exception bits). The
 * fuzzer accepts this.
 *
 * Note: real x87 uses 80-bit extended precision internally; we use double
 * (53-bit mantissa). The fuzz harness runs at random doubles, so single-ulp
 * mismatches from libm vs x87 are accepted. fyl2x/fyl2xp1/cordic-precision
 * transcendentals typically agree to < 1ulp on well-conditioned inputs.
 * ============================================================ */

hb_result_t hb_x87_fsqrt(hb_x87_state_t* x87) {
    /* Keep host sqrt effects observable and retain its existing
     * indefinite-result repair under ordinary optimization. */
#pragma STDC FENV_ACCESS ON
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    /* Keep the original preview read/error above. Only occupied inputs with
     * no pending unmasked exception may use the private finite sqrt bridge. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t raw[10];
        hb_x87_finite_result_t finite;
        hb_result_t raw_read = hb_x87_st_ext80(x87, 0, raw);
        /* A missing cache uses authoritative binary64 bits; an empty slot
         * must not consume stale saved payload through the permissive getter. */
        if (raw_read == HB_ERR_UNSUPPORTED_FEATURE)
            raw_read = hb_x87_save_st_ext80(x87, 0, raw);
        if (raw_read == HB_OK && hb_x87_finite_sqrt(raw, x87->control_word, &finite)) {
            r = hb_x87_set_st_ext80(x87, 0, finite.raw, true);
            if (r != HB_OK) return r;
            x87->status_word = (uint16_t)((x87->status_word & (uint16_t)~HB_X87_STATUS_C1) |
                                         finite.status_bits);
            return HB_OK;
        }
    }
    result = sqrt(value);
    /* MacRunner 2026-08-15, лейн ЛЕСТНИЦА, итерация 904 — знак QNaN indefinite.
     * Хозяин ARM64 на sqrt(отрицательное) даёт 7ff8…, x86 требует fff8… (знак взведён) —
     * ту же константу этот файл уже использует при опустошении стека. Вход-NaN не трогаем:
     * его x86 распространяет, а не заменяет на indefinite. */
    {
        uint64_t src_bits, res_bits;
        memcpy(&src_bits, &value, sizeof(src_bits));
        memcpy(&res_bits, &result, sizeof(res_bits));
        if ((res_bits & UINT64_C(0x7ff0000000000000)) == UINT64_C(0x7ff0000000000000) &&
            (res_bits & UINT64_C(0x000fffffffffffff)) != 0 &&
            !((src_bits & UINT64_C(0x7ff0000000000000)) == UINT64_C(0x7ff0000000000000) &&
              (src_bits & UINT64_C(0x000fffffffffffff)) != 0)) {
            const uint64_t indefinite_bits = UINT64_C(0xfff8000000000000);
            memcpy(&result, &indefinite_bits, sizeof(result));
        }
    }
    return hb_x87_set_st_f64(x87, 0, result);
}

/* Shared numerical fallback. Existing verified raw paths run before this
 * helper; empty/pending and explicitly excluded domains keep their old tails. */
static bool hb_x87_read_transcendental_raw(const hb_x87_state_t* x87,
                                         unsigned index, uint8_t raw[10]) {
    hb_result_t r = hb_x87_st_ext80(x87, index, raw);
    if (r == HB_ERR_UNSUPPORTED_FEATURE)
        r = hb_x87_save_st_ext80(x87, index, raw);
    return r == HB_OK;
}

static bool hb_x87_prepare_transcendental(hb_x87_state_t* x87,
                                         hb_x87_transcendental_op_t operation,
                                         hb_x87_transcendental_result_t* output) {
    if (x87->status_word & (uint16_t)~x87->control_word & 0x003fu)
        return false;
    bool binary = operation == HB_X87_TRANS_FYL2X ||
                  operation == HB_X87_TRANS_FYL2XP1 ||
                  operation == HB_X87_TRANS_FPATAN ||
                  operation == HB_X87_TRANS_FSCALE;
    uint8_t raw0[10], raw1[10] = {0};
    if (!hb_x87_read_transcendental_raw(x87, 0, raw0) ||
        (binary && !hb_x87_read_transcendental_raw(x87, 1, raw1)))
        return false;
    uint64_t sig0, sig1 = 0;
    uint16_t se0, se1 = 0;
    memcpy(&sig0, raw0, sizeof(sig0));
    memcpy(&se0, raw0 + 8, sizeof(se0));
    if (binary) {
        memcpy(&sig1, raw1, sizeof(sig1));
        memcpy(&se1, raw1 + 8, sizeof(se1));
    }
    unsigned e0 = se0 & 0x7fffu, e1 = se1 & 0x7fffu;
    const uint64_t integer_bit = UINT64_C(0x8000000000000000);
    /* Zero and exceptional encodings retain inherited guest semantics. */
    if (e0 == 0 || e0 == 0x7fffu || !(sig0 & integer_bit) ||
        (binary && (e1 == 0 || e1 == 0x7fffu || !(sig1 & integer_bit))))
        return false;
    if (operation == HB_X87_TRANS_F2XM1 &&
        (e0 > 0x3fffu || (e0 == 0x3fffu && sig0 != integer_bit)))
        return false;
    if (operation == HB_X87_TRANS_FYL2X && (se0 & 0x8000u))
        return false;
    if (operation == HB_X87_TRANS_FYL2XP1 &&
        (se0 & 0x8000u) && e0 >= 0x3fffu)
        return false;
    bool trigonometric = operation == HB_X87_TRANS_FSIN ||
                         operation == HB_X87_TRANS_FCOS ||
                         operation == HB_X87_TRANS_FSINCOS ||
                         operation == HB_X87_TRANS_FPTAN;
    /* Selected Cephes returns zero above its 2^55 total-loss threshold. */
    if (trigonometric &&
        (e0 > 0x4036u || (e0 == 0x4036u && sig0 != integer_bit)))
        return false;
    /* Avoid the selected ldexpl denormal-subtraction defect. */
    if ((operation == HB_X87_TRANS_FCOS ||
         operation == HB_X87_TRANS_FSINCOS) && e0 < 0x2001u)
        return false;
    if (operation == HB_X87_TRANS_FSCALE) {
        int exponent = (int)e1 - 16383;
        if (exponent >= 15) return false;
        int scale = exponent < 0 ? 0 : (int)(sig1 >> (63 - exponent));
        if (se1 & 0x8000u) scale = -scale;
        if (scale < -16382 || scale > 16383) return false;
    }
    return hb_x87_transcendental(operation, raw0, binary ? raw1 : NULL,
                               x87->control_word, output);
}

static void hb_x87_apply_transcendental_status(
    hb_x87_state_t* x87, const hb_x87_transcendental_result_t* result) {
    x87->status_word = (uint16_t)((x87->status_word &
                                 (uint16_t)~result->status_clear) |
                                result->status_set);
}

static hb_result_t hb_x87_push_transcendental(
    hb_x87_state_t* x87, const uint8_t raw[10]) {
    bool was_empty = tag_is_empty(x87, (x87->top - 1u) & 7u);
    hb_result_t r = hb_x87_push_f64(x87, 0.0);
    if (r != HB_OK || !was_empty) return r;
    return hb_x87_set_st_ext80(x87, 0, raw, true);
}

hb_result_t hb_x87_f2xm1(hb_x87_state_t* x87) {
    /* ST(0) = 2^ST(0) - 1. No pop. */
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_F2XM1, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        return hb_x87_set_st_ext80(x87, 0, numerical.raw[0], true);
    }
    result = exp2(value) - 1.0;
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fyl2x(hb_x87_state_t* x87) {
    /* ST(1) = ST(1) * log2(ST(0)); pop 1. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);   /* log2 arg */
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);   /* multiplier */
    if (r != HB_OK) return r;
    /* The selected full80 donor gives log2(+2)=+1 and log2(+0.5)=-1.
     * Multiplication preserves every canonical normal raw multiplier bit
     * except its sign for +0.5. Keep the inherited pop and condition bits. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t argument_raw[10], multiplier_raw[10];
        if (hb_x87_st_ext80(x87, 0, argument_raw) == HB_OK &&
            hb_x87_st_ext80(x87, 1, multiplier_raw) == HB_OK) {
            uint64_t argument_significand, multiplier_significand;
            uint16_t argument_sign_exp, multiplier_sign_exp;
            memcpy(&argument_significand, argument_raw, sizeof(argument_significand));
            memcpy(&argument_sign_exp, argument_raw + 8, sizeof(argument_sign_exp));
            memcpy(&multiplier_significand, multiplier_raw, sizeof(multiplier_significand));
            memcpy(&multiplier_sign_exp, multiplier_raw + 8, sizeof(multiplier_sign_exp));
            unsigned exponent = multiplier_sign_exp & 0x7fffu;
            if (argument_significand == UINT64_C(0x8000000000000000) &&
                (argument_sign_exp == 0x4000u || argument_sign_exp == 0x3ffeu) &&
                exponent != 0u && exponent != 0x7fffu &&
                (multiplier_significand & UINT64_C(0x8000000000000000))) {
                if (argument_sign_exp == 0x3ffeu) {
                    multiplier_sign_exp ^= 0x8000u;
                    memcpy(multiplier_raw + 8, &multiplier_sign_exp, sizeof(multiplier_sign_exp));
                }
                r = hb_x87_set_st_ext80(x87, 1, multiplier_raw, true);
                if (r != HB_OK) return r;
                return hb_x87_pop(x87);
            }
        }
    }
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FYL2X, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        r = hb_x87_set_st_ext80(x87, 1, numerical.raw[0], true);
        if (r != HB_OK) return r;
        return hb_x87_pop(x87);
    }
    result = b * log2(a);
    r = hb_x87_set_st_f64(x87, 1, result);
    if (r != HB_OK) return r;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fptan(hb_x87_state_t* x87) {
    /* ST(0) = tan(ST(0)); push 1.0. */
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    /* The selected full80 donor returns this raw input as tangent and
     * pushes +1 for canonical nonzero normals below 2^-64. Its tiny
     * identity branch also covers the lowest normals; occupied slots stay legacy. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu) &&
        tag_is_empty(x87, (x87->top - 1u) & 7u)) {
        uint8_t raw[10];
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            uint64_t significand;
            uint16_t sign_exp;
            memcpy(&significand, raw, sizeof(significand));
            memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
            unsigned exponent = sign_exp & 0x7fffu;
            if (exponent != 0u && exponent < 0x3fbfu &&
                (significand & UINT64_C(0x8000000000000000))) {
                const uint8_t one[10] = {0,0,0,0,0,0,0,0x80,0xff,0x3f};
                r = hb_x87_set_st_ext80(x87, 0, raw, true);
                if (r != HB_OK) return r;
                r = hb_x87_push_f64(x87, 1.0);
                if (r != HB_OK) return r;
                r = hb_x87_set_st_ext80(x87, 0, one, true);
                if (r == HB_OK) x87->status_word &= (uint16_t)~0x0400u;
                return r;
            }
        }
    }
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FPTAN, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        r = hb_x87_set_st_ext80(x87, 0, numerical.raw[0], true);
        if (r != HB_OK) return r;
        return hb_x87_push_transcendental(x87, numerical.raw[1]);
    }
    result = tan(value);
    r = hb_x87_set_st_f64(x87, 0, result);
    if (r != HB_OK) return r;
    return hb_x87_push_f64(x87, 1.0);
}

hb_result_t hb_x87_fpatan(hb_x87_state_t* x87) {
    /* ST(1) = atan2(ST(1), ST(0)); pop 1.
     * Note: Intel's FPATAN computes arctan(ST(1)/ST(0)) — that's atan2 with
     * ST(1) as Y and ST(0) as X, which keeps the correct quadrant when X<0. */
    double y, x, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &x);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &y);
    if (r != HB_OK) return r;
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FPATAN, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        r = hb_x87_set_st_ext80(x87, 1, numerical.raw[0], true);
        if (r != HB_OK) return r;
        return hb_x87_pop(x87);
    }
    result = atan2(y, x);
    r = hb_x87_set_st_f64(x87, 1, result);
    if (r != HB_OK) return r;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fxtract(hb_x87_state_t* x87) {
    /* ★ 05.09.2026 — ПОЛОВИНКИ КЛАЛИСЬ НАОБОРОТ.
     *
     * Спецификация (Intel SDM, том 2, FXTRACT): «stores the exponent in ST(0),
     * and pushes the significand onto the register stack» — то есть ПОСЛЕ
     * команды ST(0) = МАНТИССА (её только что положили сверху), ST(1) =
     * ПОРЯДОК. Здесь стояло обратное: ST(0) := мантисса, а затем на стек
     * клался порядок, — и он оказывался наверху. Комментарий описывал ту же
     * перестановку, поэтому расхождения кода и записи не было видно.
     *
     * Замер (оракул Bochs, вход ST(0) = log2(e) = 1,4426950408889634,
     * хвост `FSTP qword [rdi]`): процессор кладёт в память 1,4426950408889634
     * (мантисса, порядок 0), мы клали 0 (порядок). Ошибка ровно в порядке
     * двух присваиваний; сами величины считались верно.
     *
     * Файл общий для обеих ветвей, поэтому дефект был и на i386, и на x64 —
     * но виден стал только когда x64 научился ЗВАТЬ FXTRACT: до 05.09 декодер
     * x64 сваливал весь диапазон D9 E0..FF в заглушку-NOP. */
    /* ST(0) = exponent, затем PUSH significand -> ST(0) = мантисса, ST(1) = порядок.
     * Мантисса — |x|, нормированная в [1, 2), со знаком x. Снятия нет. */
    double value, sign, mag, exponent, significand;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;

    /* Exact extraction needs no rounding. Keep the legacy overflow path and
     * successful status policy by admitting only a free next stack slot. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu) &&
        tag_is_empty(x87, (x87->top - 1u) & 7u)) {
        uint8_t raw[10], exponent_raw[10];
        uint64_t raw_significand;
        uint16_t raw_sign_exp;
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            memcpy(&raw_significand, raw, sizeof(raw_significand));
            memcpy(&raw_sign_exp, raw + 8, sizeof(raw_sign_exp));
            unsigned raw_exponent = raw_sign_exp & 0x7fffu;
            if (raw_exponent != 0 && raw_exponent != 0x7fffu &&
                (raw_significand & UINT64_C(0x8000000000000000))) {
                hb_x87_ext80_from_i64((int64_t)raw_exponent - 16383, exponent_raw);
                raw_sign_exp = (uint16_t)((raw_sign_exp & 0x8000u) | 0x3fffu);
                memcpy(raw + 8, &raw_sign_exp, sizeof(raw_sign_exp));
                r = hb_x87_set_st_ext80(x87, 0, exponent_raw, true);
                if (r != HB_OK) return r;
                r = hb_x87_push_f64(x87, 0.0);
                if (r != HB_OK) return r;
                return hb_x87_set_st_ext80(x87, 0, raw, true);
            }
        }
    }

    sign = (signbit(value) != 0) ? -1.0 : 1.0;
    mag = fabs(value);
    if (mag == 0.0) {
        /* x87 returns -inf for exponent and +0/-0 for significand. */
        exponent = -INFINITY;
        significand = (sign < 0.0) ? -0.0 : 0.0;
    } else if (isinf(mag)) {
        exponent = INFINITY;
        significand = sign * INFINITY;
    } else if (isnan(mag)) {
        exponent = nan("");
        significand = nan("");
    } else {
        /* ST(0) = sign * mag / 2^ilogb — gives value in [1, 2).
         * We avoid the ilogb() macro (it expands to a function pointer on
         * some platforms) by using log2/frexp directly. */
        double l2 = log2(mag);
        int ilogb_v = (int)floor(l2);
        /* Edge case: if mag is a power of 2, log2 is exact integer; l2 may
         * be 1 ulp below due to rounding, so ilogb_v can be off by 1.
         * Snap by re-checking via scalbn reconstruction. */
        if (scalbn(1.0, ilogb_v) > mag) ilogb_v -= 1;
        else if (scalbn(1.0, ilogb_v + 1) <= mag) ilogb_v += 1;
        significand = sign * scalbn(mag, -ilogb_v);
        exponent = (double)ilogb_v;
    }
    r = hb_x87_set_st_f64(x87, 0, exponent);
    if (r != HB_OK) return r;
    return hb_x87_push_f64(x87, significand);
}

static hb_result_t hb_x87_fprem_store(hb_x87_state_t* x87, uint64_t significand,
                                       uint16_t sign_exp) {
    uint8_t raw[10];
    memcpy(raw, &significand, sizeof(significand));
    memcpy(raw + 8, &sign_exp, sizeof(sign_exp));
    return hb_x87_set_st_ext80(x87, 0, raw, true);
}

static void hb_x87_fprem_normalize(uint64_t* significand, int* exponent) {
    while (*significand != 0 && !(*significand & UINT64_C(0x8000000000000000))) {
        *significand <<= 1;
        --*exponent;
    }
}

static hb_result_t hb_x87_fprem_finite(hb_x87_state_t* x87, uint64_t significand,
                                      int exponent, uint16_t sign) {
    hb_x87_fprem_normalize(&significand, &exponent);
    if (significand == 0) {
        exponent = 0;
    } else if (exponent <= 0) {
        if (!(x87->control_word & HB_X87_CONTROL_UNDERFLOW_MASK)) {
            /* An unmasked tiny register result is committed after scaling
             * by 2^24576, even when exact. Deferred #MF is a runtime concern. */
            x87->status_word |= HB_X87_STATUS_UNDERFLOW |
                               HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
            /* Follow the generic exact-underflow C1=0 policy. Its interaction
             * with FPREM quotient-bit reporting remains a separate oracle check. */
            x87->status_word &= (uint16_t)~HB_X87_STATUS_C1;
            exponent += 24576;
        } else {
            /* Remainders are exact multiples of the inputs' common binary
             * quantum. A representable tiny result loses no bits here and
             * therefore does not raise masked underflow or precision. */
            unsigned shift = (unsigned)(1 - exponent);
            significand = shift < 64 ? significand >> shift : 0;
            exponent = 0;
        }
    }
    return hb_x87_fprem_store(x87, significand, (uint16_t)(sign | (unsigned)exponent));
}

static hb_result_t hb_x87_fprem_impl(hb_x87_state_t* x87, bool nearest) {
    if (!x87) return HB_ERR_INVALID_ARG;
    const uint64_t integer_bit = UINT64_C(0x8000000000000000);
    const uint64_t quiet_bit = UINT64_C(0x4000000000000000);
    uint64_t sig[2] = {0, 0};
    uint16_t se[2] = {0, 0};
    unsigned exp[2] = {0, 0};
    bool empty = false, unsupported = false;
    bool nan_value[2] = {false, false}, snan[2] = {false, false};
    for (unsigned i = 0; i < 2; ++i) {
        if (tag_is_empty(x87, phys_st(x87, i))) {
            empty = true;
            continue;
        }
        uint8_t raw[10];
        hb_result_t r = hb_x87_save_st_ext80(x87, i, raw);
        if (r != HB_OK) return r;
        memcpy(&sig[i], raw, sizeof(sig[i]));
        memcpy(&se[i], raw + 8, sizeof(se[i]));
        exp[i] = se[i] & 0x7fffu;
        unsupported |= exp[i] != 0 && !(sig[i] & integer_bit);
        nan_value[i] = exp[i] == 0x7fffu && (sig[i] & ~integer_bit) != 0;
        snan[i] = nan_value[i] && !(sig[i] & quiet_bit);
    }

    /* Operand priority: empty, unsupported, SNaN, QNaN, the remaining
     * invalid operations, denormal operand, then result underflow. */
    bool have_nan = nan_value[0] || nan_value[1];
    bool invalid = empty || unsupported || snan[0] || snan[1] ||
                   (!have_nan && (exp[0] == 0x7fffu || sig[1] == 0));
    if (invalid) {
        x87->status_word = (uint16_t)((x87->status_word | HB_X87_STATUS_INVALID) &
                                     ~HB_X87_STATUS_C1);
        if (empty) x87->status_word |= HB_X87_STATUS_STACK_FAULT;
        if (!(x87->control_word & HB_X87_CONTROL_INVALID_MASK)) {
            x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
            return HB_ERR_EXEC_FAULT;
        }
        if (empty || unsupported || !have_nan) {
            x87->status_word &= (uint16_t)~(1u << 10);
            return hb_x87_fprem_store(x87, integer_bit | quiet_bit, 0xffffu);
        }
    }
    if (have_nan) {
        unsigned selected;
        if (!nan_value[0]) selected = 1;
        else if (!nan_value[1]) selected = 0;
        else if (snan[0] != snan[1]) selected = snan[0] ? 1u : 0u;
        else if (sig[0] != sig[1]) selected = sig[0] > sig[1] ? 0u : 1u;
        else {
            /* Intel's larger-significand rule leaves an equal-payload sign
             * tie unspecified. Prefer positive as an explicit engine policy. */
            selected = (se[0] & 0x8000u) && !(se[1] & 0x8000u) ? 1u : 0u;
        }
        x87->status_word &= (uint16_t)~((1u << 10) | HB_X87_STATUS_C1);
        return hb_x87_fprem_store(x87, sig[selected] | quiet_bit, se[selected]);
    }
    if ((exp[0] == 0 && sig[0] != 0) || (exp[1] == 0 && sig[1] != 0)) {
        x87->status_word |= HB_X87_STATUS_DENORMAL;
        if (!(x87->control_word & HB_X87_CONTROL_DENORMAL_MASK)) {
            x87->status_word |= HB_X87_STATUS_ERROR_SUMMARY | HB_X87_STATUS_BUSY_MASK;
            return HB_ERR_EXEC_FAULT;
        }
    }

    uint16_t sign = se[0] & 0x8000u;
    int ea = (int)(exp[0] ? exp[0] : 1u);
    int eb = (int)(exp[1] ? exp[1] : 1u);
    hb_x87_fprem_normalize(&sig[0], &ea);
    hb_x87_fprem_normalize(&sig[1], &eb);
    uint64_t remainder_sig = sig[0];
    int remainder_exp = ea;
    unsigned low = 0;
    bool partial = false;
    if (sig[0] != 0 && exp[1] != 0x7fffu) {
        int difference = ea - eb;
        if (difference >= 64) {
            /* Intel permits an implementation-dependent N in [32,63].
             * Choose N=32 for both instructions; partial quotient truncates
             * regardless of FPREM1 or CW.RC. Its discarded low bits are zero. */
            __uint128_t numerator = (__uint128_t)sig[0] << 32;
            remainder_sig = (uint64_t)(numerator % sig[1]);
            remainder_exp = ea - 32;
            partial = true;
        } else if (difference >= 0) {
            /* The shift is at most 63 and the divisor is normalized, so the
             * quotient fits uint64_t. Only its magnitude modulo eight is used;
             * there is no floating-to-signed cast or signed negation. */
            __uint128_t numerator = (__uint128_t)sig[0] << (unsigned)difference;
            uint64_t quotient = (uint64_t)(numerator / sig[1]);
            remainder_sig = (uint64_t)(numerator % sig[1]);
            remainder_exp = eb;
            low = (unsigned)(quotient & 7u);
            __uint128_t twice = (__uint128_t)remainder_sig << 1;
            if (nearest && (twice > sig[1] || (twice == sig[1] && (low & 1u)))) {
                remainder_sig = sig[1] - remainder_sig;
                sign ^= 0x8000u;
                low = (low + 1u) & 7u;
            }
        } else if (nearest && difference == -1 && sig[0] > sig[1]) {
            /* Here 1/2 < |a/b| < 1. At exactly 1/2, the even quotient is zero. */
            remainder_sig = (uint64_t)(((__uint128_t)sig[1] << 1) - sig[0]);
            sign ^= 0x8000u;
            low = 1;
        }
    }
    if (partial) {
        /* C0/C1/C3 are undefined until completion; retain their stored values.
         * Even a zero partial remainder completes only on a subsequent call. */
        x87->status_word |= (uint16_t)(1u << 10);
    } else {
        set_condition_bits(x87, (low >> 2) & 1u, low & 1u, 0, (low >> 1) & 1u);
    }
    return hb_x87_fprem_finite(x87, remainder_sig, remainder_exp, sign);
}

hb_result_t hb_x87_fprem1(hb_x87_state_t* x87) {
    return hb_x87_fprem_impl(x87, true);
}

hb_result_t hb_x87_fprem(hb_x87_state_t* x87) {
    return hb_x87_fprem_impl(x87, false);
}

hb_result_t hb_x87_fyl2xp1(hb_x87_state_t* x87) {
    /* ST(1) = ST(1) * log2(ST(0) + 1); pop 1. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);
    if (r != HB_OK) return r;
    /* The selected full80 donor first adds exact +1 at forced precision80.
     * For raw +1 or -0.5, log2 of that sum is exact +1 or -1.
     * Preserve the raw normal multiplier, inherited condition bits and pop. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t argument_raw[10], multiplier_raw[10];
        if (hb_x87_st_ext80(x87, 0, argument_raw) == HB_OK &&
            hb_x87_st_ext80(x87, 1, multiplier_raw) == HB_OK) {
            uint64_t argument_significand, multiplier_significand;
            uint16_t argument_sign_exp, multiplier_sign_exp;
            memcpy(&argument_significand, argument_raw, sizeof(argument_significand));
            memcpy(&argument_sign_exp, argument_raw + 8, sizeof(argument_sign_exp));
            memcpy(&multiplier_significand, multiplier_raw, sizeof(multiplier_significand));
            memcpy(&multiplier_sign_exp, multiplier_raw + 8, sizeof(multiplier_sign_exp));
            unsigned exponent = multiplier_sign_exp & 0x7fffu;
            if (argument_significand == UINT64_C(0x8000000000000000) &&
                (argument_sign_exp == 0x3fffu || argument_sign_exp == 0xbffeu) &&
                exponent != 0u && exponent != 0x7fffu &&
                (multiplier_significand & UINT64_C(0x8000000000000000))) {
                if (argument_sign_exp == 0xbffeu) {
                    multiplier_sign_exp ^= 0x8000u;
                    memcpy(multiplier_raw + 8, &multiplier_sign_exp, sizeof(multiplier_sign_exp));
                }
                r = hb_x87_set_st_ext80(x87, 1, multiplier_raw, true);
                if (r != HB_OK) return r;
                return hb_x87_pop(x87);
            }
        }
    }
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FYL2XP1, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        r = hb_x87_set_st_ext80(x87, 1, numerical.raw[0], true);
        if (r != HB_OK) return r;
        return hb_x87_pop(x87);
    }
    result = b * log2(a + 1.0);
    r = hb_x87_set_st_f64(x87, 1, result);
    if (r != HB_OK) return r;
    return hb_x87_pop(x87);
}

hb_result_t hb_x87_fsincos(hb_x87_state_t* x87) {
    /* ST(0) = sin(ST(0)); push cos(ST(0)). No pop. */
    double value, s, c;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    /* The selected full80 donor rounds sine to this raw input and cosine
     * to +1 in this interval. Keep zz and zz/2 normal to avoid its retained
     * ldexpl denormal-subtraction defect; occupied push slots stay legacy. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu) &&
        tag_is_empty(x87, (x87->top - 1u) & 7u)) {
        uint8_t raw[10];
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            uint64_t significand;
            uint16_t sign_exp;
            memcpy(&significand, raw, sizeof(significand));
            memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
            unsigned exponent = sign_exp & 0x7fffu;
            if (exponent >= 0x2001u && exponent < 0x3fbfu &&
                (significand & UINT64_C(0x8000000000000000))) {
                const uint8_t one[10] = {0,0,0,0,0,0,0,0x80,0xff,0x3f};
                r = hb_x87_set_st_ext80(x87, 0, raw, true);
                if (r != HB_OK) return r;
                r = hb_x87_push_f64(x87, 1.0);
                if (r != HB_OK) return r;
                r = hb_x87_set_st_ext80(x87, 0, one, true);
                if (r == HB_OK) x87->status_word &= (uint16_t)~0x0400u;
                return r;
            }
        }
    }
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FSINCOS, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        r = hb_x87_set_st_ext80(x87, 0, numerical.raw[0], true);
        if (r != HB_OK) return r;
        return hb_x87_push_transcendental(x87, numerical.raw[1]);
    }
    s = sin(value);
    c = cos(value);
    r = hb_x87_set_st_f64(x87, 0, s);
    if (r != HB_OK) return r;
    return hb_x87_push_f64(x87, c);
}

hb_result_t hb_x87_fscale(hb_x87_state_t* x87) {
    /* ST(0) = ST(0) * 2^trunc(ST(1)). No pop. */
    double a, b, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &a);
    if (r != HB_OK) return r;
    r = hb_x87_st_f64(x87, 1, &b);
    if (r != HB_OK) return r;
    /* Preserve full80 exact scaling only inside the selected donor's normal
     * exp2 intermediate range. Other classes and boundaries retain the legacy
     * path below, including its existing successful status policy. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t raw_a[10], raw_b[10];
        if (hb_x87_st_ext80(x87, 0, raw_a) == HB_OK &&
            hb_x87_st_ext80(x87, 1, raw_b) == HB_OK) {
            uint64_t sig_a, sig_b;
            uint16_t se_a, se_b;
            memcpy(&sig_a, raw_a, sizeof(sig_a));
            memcpy(&sig_b, raw_b, sizeof(sig_b));
            memcpy(&se_a, raw_a + 8, sizeof(se_a));
            memcpy(&se_b, raw_b + 8, sizeof(se_b));
            unsigned exp_a = se_a & 0x7fffu, exp_b = se_b & 0x7fffu;
            bool zero_a = exp_a == 0 && sig_a == 0;
            bool zero_b = exp_b == 0 && sig_b == 0;
            const uint64_t integer_bit = UINT64_C(0x8000000000000000);
            bool normal_a = exp_a > 0 && exp_a < 0x7fffu && (sig_a & integer_bit);
            bool normal_b = exp_b > 0 && exp_b < 0x7fffu && (sig_b & integer_bit);
            if ((zero_a || normal_a) && (zero_b || normal_b) && exp_b < 0x400eu) {
                /* |ST1| < 32768 makes this shift and signed conversion bounded.
                 * Truncate the raw magnitude toward zero, independent of PC/RC. */
                int scale = 0;
                if (exp_b >= 0x3fffu) {
                    scale = (int)(sig_b >> (63u - (exp_b - 0x3fffu)));
                    if (se_b & 0x8000u) scale = -scale;
                }
                int result_exp = (int)exp_a + scale;
                if (scale >= -16382 && scale <= 16383 &&
                    (zero_a || (result_exp > 0 && result_exp < 0x7fff))) {
                    if (!zero_a) {
                        se_a = (uint16_t)((se_a & 0x8000u) | (unsigned)result_exp);
                        memcpy(raw_a + 8, &se_a, sizeof(se_a));
                    }
                    return hb_x87_set_st_ext80(x87, 0, raw_a, true);
                }
            }
        }
    }
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FSCALE, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        return hb_x87_set_st_ext80(x87, 0, numerical.raw[0], true);
    }
    result = scalbn(a, (int)trunc(b));
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fsin(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    /* The selected full80 donor's nearest binary128 sine polynomial rounds
     * back to its nonzero input throughout |x| < 2^-64. Keep that raw value;
     * this is donor parity, not an exact-real sine or precision-flag claim. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t raw[10];
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            uint64_t significand;
            uint16_t sign_exp;
            memcpy(&significand, raw, sizeof(significand));
            memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
            unsigned exponent = sign_exp & 0x7fffu;
            if (exponent > 0 && exponent < 0x3fbfu &&
                (significand & UINT64_C(0x8000000000000000))) {
                r = hb_x87_set_st_ext80(x87, 0, raw, true);
                if (r == HB_OK) x87->status_word &= (uint16_t)~0x0400u;
                return r;
            }
        }
    }
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FSIN, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        return hb_x87_set_st_ext80(x87, 0, numerical.raw[0], true);
    }
    result = sin(value);
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fcos(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;
    /* The selected full80 donor rounds cosine to exact +1 on this
       bounded interval. Keep zz and zz/2 normal to exclude its retained
       denormal-scaling defect; other domains keep the original fallback. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t raw[10];
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            uint64_t significand;
            uint16_t sign_exponent;
            memcpy(&significand, raw, sizeof(significand));
            memcpy(&sign_exponent, raw + 8, sizeof(sign_exponent));
            uint16_t exponent = sign_exponent & 0x7fffu;
            if (exponent >= 0x2001u && exponent < 0x3fbfu &&
                (significand & UINT64_C(0x8000000000000000))) {
                static const uint8_t one[10] = {0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f};
                r = hb_x87_set_st_ext80(x87, 0, one, true);
                if (r == HB_OK) x87->status_word &= (uint16_t)~0x0400u;
                return r;
            }
        }
    }
    hb_x87_transcendental_result_t numerical;
    if (hb_x87_prepare_transcendental(x87, HB_X87_TRANS_FCOS, &numerical)) {
        hb_x87_apply_transcendental_status(x87, &numerical);
        return hb_x87_set_st_ext80(x87, 0, numerical.raw[0], true);
    }
    result = cos(value);
    return hb_x87_set_st_f64(x87, 0, result);
}

/* D9 D0/E0/E1/E4 — stack-top sign / abs / test. These operate on ST(0) only.
 * Per Intel SDM: FCHS inverts sign, FABS clears sign, FTST compares ST(0)
 * to +0.0 and sets C0/C2/C3 in the FPU status word, FNOP is a true no-op
 * (no register reads, no flag changes). */

hb_result_t hb_x87_fnop(hb_x87_state_t* x87) {
    /* FNOP does nothing. We accept a NULL pointer for symmetry with the
     * call sites, but there is no state to mutate. */
    (void)x87;
    return HB_OK;
}

hb_result_t hb_x87_fchs(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;

    /* Change only the raw sign; retain the current successful status policy. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t raw[10];
        uint64_t raw_significand;
        uint16_t raw_sign_exp;
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            memcpy(&raw_significand, raw, sizeof(raw_significand));
            memcpy(&raw_sign_exp, raw + 8, sizeof(raw_sign_exp));
            unsigned raw_exponent = raw_sign_exp & 0x7fffu;
            if ((raw_exponent != 0 && raw_exponent != 0x7fffu &&
                 (raw_significand & UINT64_C(0x8000000000000000))) ||
                (raw_exponent == 0 && raw_significand == 0)) {
                raw[9] ^= 0x80u;
                return hb_x87_set_st_ext80(x87, 0, raw, true);
            }
        }
    }
    result = -value;
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_fabs(hb_x87_state_t* x87) {
    double value, result;
    hb_result_t r;

    if (!x87) return HB_ERR_INVALID_ARG;
    r = hb_x87_st_f64(x87, 0, &value);
    if (r != HB_OK) return r;

    /* Change only the raw sign; retain the current successful status policy. */
    if (!(x87->status_word & (uint16_t)~x87->control_word & 0x003fu)) {
        uint8_t raw[10];
        uint64_t raw_significand;
        uint16_t raw_sign_exp;
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            memcpy(&raw_significand, raw, sizeof(raw_significand));
            memcpy(&raw_sign_exp, raw + 8, sizeof(raw_sign_exp));
            unsigned raw_exponent = raw_sign_exp & 0x7fffu;
            if ((raw_exponent != 0 && raw_exponent != 0x7fffu &&
                 (raw_significand & UINT64_C(0x8000000000000000))) ||
                (raw_exponent == 0 && raw_significand == 0)) {
                raw[9] &= 0x7fu;
                return hb_x87_set_st_ext80(x87, 0, raw, true);
            }
        }
    }
    result = fabs(value);
    return hb_x87_set_st_f64(x87, 0, result);
}

hb_result_t hb_x87_ftst(hb_x87_state_t* x87) {
    double value;
    uint16_t sw;

    if (!x87) return HB_ERR_INVALID_ARG;
    if (hb_x87_st_f64(x87, 0, &value) != HB_OK) return HB_ERR_EXEC_FAULT;

    /* FTST compares ST(0) to +0.0, clears C1, and writes C0/C2/C3.
     * Preserve the existing comparison and source-read error ordering. */
    sw = (uint16_t)(x87->status_word & ~(uint16_t)((1u << 8) | (1u << 9) | (1u << 10) | (1u << 14)));
    /* A canonical finite ext80 value can have a zero binary64 preview.
     * Use its occupied raw cache without widening the legacy fallback scope. */
    if ((x87->status_word & (uint16_t)~x87->control_word & 0x003fu) == 0) {
        uint8_t raw[10];
        if (hb_x87_st_ext80(x87, 0, raw) == HB_OK) {
            uint64_t significand;
            uint16_t sign_exp;
            memcpy(&significand, raw, sizeof(significand));
            memcpy(&sign_exp, raw + 8, sizeof(sign_exp));
            unsigned exponent = sign_exp & 0x7fffu;
            if ((exponent == 0 && significand == 0) ||
                (exponent != 0 && exponent != 0x7fffu &&
                 (significand & UINT64_C(0x8000000000000000)))) {
                if (significand == 0) sw |= (uint16_t)(1u << 14);
                else if (sign_exp & 0x8000u) sw |= (uint16_t)(1u << 8);
                x87->status_word = sw;
                return HB_OK;
            }
        }
    }
    if (isnan(value)) {
        sw |= (uint16_t)((1u << 8) | (1u << 10) | (1u << 14));
    } else if (value < 0.0) {
        sw |= (uint16_t)(1u << 8);
    } else if (value == 0.0) {
        sw |= (uint16_t)(1u << 14);
    }
    x87->status_word = sw;
    return HB_OK;
}

/* MacRunner 2026-08-12, лейн ЛЕСТНИЦА, итерация 519 — НАЛОЖЕНИЕ MMX НА СТЕК x87.
 *
 * Архитектурно `MM(i)` — это мантисса `ST(i)`, а запись в MMX помечает ВСЕ восемь регистров
 * занятыми и ставит экспоненту в `0xFFFF`. Правило не взято по памяти, а ИЗМЕРЕНО у эталона
 * побайтным восстановлением образа `fnstenv`:
 *
 *   fninit                            тег-слово 0xffff  (всё пусто)
 *   fninit + movd mm0,eax             тег-слово 0x5556  ← ST0=особое, ST1..7=ноль
 *   fninit + movd mm0,eax + emms      тег-слово 0xffff
 *
 * `0x5556` читается однозначно: запись в MMX сняла «пусто» со ВСЕХ регистров, а `fnstenv`
 * пересчитал тег по содержимому — у ST0 экспонента `0xFFFF` (особое), у остальных ноль. */
static uint16_t tag_by_content(const hb_x87_state_t* x87, unsigned phys) {
    if (x87->st_ext_valid & (1u << phys)) {
        uint16_t e = (uint16_t)(x87->st_ext[phys][8] | ((uint16_t)x87->st_ext[phys][9] << 8));
        if ((e & 0x7fffu) == 0x7fffu) return 2u;   /* особое: бесконечность/NaN/MMX */
    }
    if (x87->st[phys] == 0.0) return 1u;           /* ноль */
    if (isnan(x87->st[phys]) || isinf(x87->st[phys])) return 2u;
    return 0u;                                     /* занято */
}

hb_result_t hb_x87_mmx_write(hb_x87_state_t* x87, unsigned idx, uint64_t value) {
    unsigned i;
    if (!x87 || idx >= 8) return HB_ERR_INVALID_ARG;
    memcpy(x87->st_ext[idx], &value, 8);
    x87->st_ext[idx][8] = 0xff;
    x87->st_ext[idx][9] = 0xff;
    x87->st_ext_valid |= (uint8_t)(1u << idx);
    x87->st[idx] = NAN;
    x87->tag_word = 0;
    for (i = 0; i < 8; i++)
        x87->tag_word = (uint16_t)(x87->tag_word | (uint16_t)(tag_by_content(x87, i) << (2u * i)));
    return HB_OK;
}

hb_result_t hb_x87_emms(hb_x87_state_t* x87) {
    if (!x87) return HB_ERR_INVALID_ARG;
    x87->tag_word = 0xffff;      /* все пусты — измерено у эталона */
    x87->st_ext_valid = 0;
    return HB_OK;
}
