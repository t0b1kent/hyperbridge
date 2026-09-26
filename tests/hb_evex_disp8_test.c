/* Сжатое смещение EVEX (disp8*N): декодер против таблицы, порождённой сверкой с capstone
 * (tests/hb_evex_disp8/sweep.py --table). В таблице каждая EVEX-форма, которую исполняет
 * декодер HB, с [rcx+disp8] и [rsp+disp8], disp8 = 1: ожидаемое смещение равно N.
 *
 * Замер 26.09.2026 до правки (hb_evex_disp8.h): x64 — 956 из 962 форм с неверным адресом,
 * `vmovups [rcx+0x10],xmm1` разбирался как [rcx+1]. Нашёл аппаратный оракул Астры (HBUP0002,
 * store-loop): восемь записей по 16 байт ложились с шагом в байт.
 *
 * Вторая половина — формы, которые декодер обязан ОТКЛОНИТЬ: их рассылку не исполняет никто
 * (лифтер PSHUFD и весь лифтер i386 признака рассылки не несут), и прежде они исполнялись
 * молча неверно, с чтением всего вектора вместо одного элемента. */
#include <stdio.h>
#include <string.h>
#include "hb_decoder.h"

typedef struct { int arch; unsigned len; unsigned char b[16]; long long disp; } row_t;
static const row_t rows[] = {
#include "hb_evex_disp8/table64.inc"
#include "hb_evex_disp8/table32.inc"
};

typedef struct { int arch; unsigned len; unsigned char b[16]; const char* what; } refuse_t;
static const refuse_t refuse[] = {
    {64, 8, {0x62, 0xf1, 0x7d, 0x18, 0x70, 0x49, 0x01, 0x00}, "vpshufd xmm1, [rcx+4]{1to4}, 0"},
    {64, 7, {0x62, 0xf1, 0x7e, 0x18, 0x78, 0x49, 0x01}, "vcvttss2usi eax, [rcx+4] with b=1 (#UD)"},
    {32, 7, {0x62, 0xf1, 0xfd, 0x18, 0x58, 0x49, 0x01}, "i386 vaddpd xmm1, xmm0, [ecx+8]{1to2}"},
};

static hb_result_t decode(int arch, const unsigned char* b, unsigned len, hb_decoded_t* o) {
    hb_decoder_t* d = hb_decoder_create(arch == 32 ? HB_ARCH_X86 : HB_ARCH_X64, b, len, 0x10000);
    if (!d) return HB_ERR_INTERNAL;
    memset(o, 0, sizeof(*o));
    hb_result_t r = hb_decode_next(d, o);
    hb_decoder_destroy(d);
    return r;
}

static int mem_disp(const hb_decoded_t* o, long long* disp) {
    if (o->op1.is_mem) { *disp = o->op1.mem.disp; return 1; }
    if (o->op2.is_mem) { *disp = o->op2.mem.disp; return 1; }
    if (o->op3.is_mem) { *disp = o->op3.mem.disp; return 1; }
    return 0;
}

int main(void) {
    unsigned n = 0, bad = 0;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        hb_decoded_t o;
        long long got = 0;
        hb_result_t r = decode(rows[i].arch, rows[i].b, rows[i].len, &o);
        n++;
        if (r != HB_OK || !o.evex || !mem_disp(&o, &got) || got != rows[i].disp) {
            if (++bad <= 20) {
                printf("BAD x%d rc=%d disp=%lld expected=%lld bytes=", rows[i].arch, r, got, rows[i].disp);
                for (unsigned k = 0; k < rows[i].len; k++) printf("%02x", rows[i].b[k]);
                printf("\n");
            }
        }
    }
    for (size_t i = 0; i < sizeof(refuse) / sizeof(refuse[0]); i++) {
        hb_decoded_t o;
        hb_result_t r = decode(refuse[i].arch, refuse[i].b, refuse[i].len, &o);
        n++;
        if (r == HB_OK) {
            bad++;
            printf("BAD accepted: %s\n", refuse[i].what);
        }
    }
    printf("EVEX disp8*N: %u forms, %u bad\n", n, bad);
    return bad ? 1 : 0;
}
