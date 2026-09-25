/* MacRunner 2026-08-18, лейн РЕГИСТРЫ, итерация 1 — ОБСЛЕДОВАНИЕ ЗАНЯТЫХ РЕГИСТРОВ ХОЗЯИНА.
 *
 * Зачем. Карту закрепления нельзя выбирать по грепу: греп по `emit_*(buf, 24` нашёл два места,
 * где выпуск пишет x24, и НЕ нашёл бы их, будь номер в переменной. Правило проекта прямо
 * запрещает самодельные переборы по исходникам как основание вывода
 * (`lesson_source_sweeps_overreport_print_lines_first`).
 *
 * Поэтому обследуем ФАКТ: гоним корпус случаев через настоящий лифтер и настоящий выпуск,
 * печатаем выпущенные слова как `.word`, а разбирает их НАСТОЯЩИЙ дизассемблер (clang+otool).
 * Так «регистр свободен» становится наблюдением, а не предположением.
 *
 * Ввод: строки `seed hex [что-угодно]` — тот же формат, что у hb_diff_case_runner, чтобы
 * корпуса были общими. Вывод: ассемблерный текст на stdout, годный для clang -c.
 */
#include "hb_codegen.h"
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ★ БАЗА ЗАГРУЗКИ ВЛИЯЕТ НА ЗАМЕР, И ЭТО ИЗМЕРЕНО (лейн РЕГИСТРЫ, 19.08).
 *
 * Прежняя база 0x100000 (1 МБ) не бывает у настоящего кода: x64-PE грузится по
 * 0x140000000 (5,4 ГБ). Разница не косметическая — гостевые адреса переходов
 * укладываются как КОНСТАНТЫ, и порог короткой укладки (`MACRUNNER_HB_IMM_COMPACT`)
 * проходит по 4 ГБ. При базе 1 МБ адреса ниже порога и сжимаются; при настоящей — выше
 * и не сжимаются.
 *
 * Замер: короткая укладка давала 7,18 % при базе 1 МБ и 4,83 % при 0x140000000 —
 * завышение в 1,49 раза на ровном месте.
 *
 * Поэтому по умолчанию берётся настоящая база. Переопределяется HB_SURVEY_BASE. */
#define SURVEY_CODE_BASE_DEFAULT 0x140000000ULL
static unsigned long long survey_code_base(void) {
    const char* e = getenv("HB_SURVEY_BASE");
    return (e && *e) ? strtoull(e, NULL, 0) : SURVEY_CODE_BASE_DEFAULT;
}
#define SURVEY_CODE_BASE survey_code_base()
/* ★ ПРЕДЕЛ ПОДНЯТ 32 -> 128 БАЙТ (лейн РЕГИСТРЫ, итерация 126).
 *
 * Зачем. Итерация 125 измерила: в корпусе закрепляется 2,0 % блоков, а в настоящем кеше
 * прогонов — 13,9 %. Это не про величину выигрыша (её берут по кешу), это про ПОЛНОТУ
 * ПРОВЕРКИ: сличение с интерпретатором гоняло путь закрепления на 71 блоке из 3510.
 *
 * Причина структурная: случай корпуса ограничен 32 байтами гостя, поэтому постоянная обвязка
 * блока весит в нём больше, а гостевое тело меньше — обращений к файлу регистров 2,20 на блок
 * против 3,14 у настоящих. Порог отбора (`n > cost`) нелинеен, и эти 1,43 раза плотности
 * дают 7 раз разницы в доле закрепляемых блоков.
 *
 * ★ ОБРЕЗКА БЫЛА МОЛЧАЛИВОЙ: разбор останавливался на пределе, а третье поле случая
 * (ожидаемое число команд) оставалось прежним — то есть длинный случай превращался в чужой,
 * и поймать это мог только входной сторож. Предел поднят вместе с буфером строки. */
#define SURVEY_MAX_CODE  128U

static int parse_hex(const char* s, uint8_t* out, size_t* out_len) {
    size_t n = 0;
    while (*s && n < SURVEY_MAX_CODE) {
        while (*s == ' ' || *s == '\t') s++;
        if (!isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1])) break;
        char b[3] = { s[0], s[1], 0 };
        out[n++] = (uint8_t)strtoul(b, NULL, 16);
        s += 2;
    }
    *out_len = n;
    return n > 0;
}

int main(void) {
    char line[1024];   /* 128 байт гостя = 256 знаков + зерно и счёт */
    unsigned long cases = 0, lifted = 0, emitted = 0, words = 0;
    unsigned long reloc_ok = 0, reloc_bad = 0;

    printf(".text\n");
    while (fgets(line, sizeof(line), stdin)) {
        char* p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;
        /* поле 1: seed — пропускаем */
        while (*p && !isspace((unsigned char)*p)) p++;
        while (*p && isspace((unsigned char)*p)) p++;
        char* code_s = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        *p = 0;

        uint8_t code[SURVEY_MAX_CODE];
        size_t code_len = 0;
        if (!parse_hex(code_s, code, &code_len)) continue;
        cases++;

        const char* arch_env = getenv("HB_SURVEY_ARCH");
        hb_arch_t arch = (arch_env && strcmp(arch_env, "x86") == 0) ? HB_ARCH_X86 : HB_ARCH_X64;

        hb_decoder_t* dec = hb_decoder_create(arch, code, code_len, SURVEY_CODE_BASE);
        if (!dec) continue;
        hb_ir_func_t* func = NULL;
        hb_result_t r = (arch == HB_ARCH_X86) ? hb_lift_func_x86(dec, &func)
                                              : hb_lift_func_x64(dec, &func);
        hb_decoder_destroy(dec);
        if (r != HB_OK || !func) { if (func) hb_ir_func_destroy(func); continue; }
        lifted++;

        hb_context_t* ctx = hb_context_create(arch, HB_BACKEND_JIT);
        hb_arm64_codegen_t* cg = ctx ? hb_arm64_codegen_create(ctx) : NULL;
        hb_codegen_buffer_t* buf = hb_codegen_buffer_create(65536);
        if (cg && buf && func->cfg && func->cfg->entry) {
            buf->arch = arch;
            if (hb_arm64_codegen_block(cg, func->cfg->entry, buf) == HB_OK && buf->size >= 4) {
                /* ★ СВЕРКА ТАБЛИЦЫ РЕЛОКАЦИЙ (лейн РЕГИСТРЫ, итерация 25).
                 *
                 * Таблица хранит смещения четырёхкомандных последовательностей MOVZ/MOVK и
                 * регистр-приёмник; по ней постоянный кеш делает код переносимым между
                 * процессами. Закрепление ВЫПУСКАЕТ БЛОК ЗАНОВО, и если счётчик релокаций
                 * сброшен неверно, записи первого прохода будут указывать в код второго — на
                 * смещения, где никакого MOVZ уже нет. Кеш восстановил бы по ним мусор, и
                 * узнали бы мы об этом не здесь, а на живом прогоне.
                 *
                 * Поэтому каждая запись сверяется с кодом: по её смещению обязана лежать
                 * MOVZ, а следом MOVK, и обе — в записанный регистр. */
                for (size_t k = 0; k < buf->reloc_count; k++) {
                    uint32_t w0, w1;
                    size_t off = buf->relocs[k].off;
                    unsigned rd = buf->relocs[k].reg;
                    if (off + 8 > buf->size) { reloc_bad++; continue; }
                    memcpy(&w0, buf->code + off, 4);
                    memcpy(&w1, buf->code + off + 4, 4);
                    if ((w0 & 0x7F800000u) != 0x52800000u || (w0 & 0x1Fu) != rd ||
                        (w1 & 0x7F800000u) != 0x72800000u || (w1 & 0x1Fu) != rd)
                        reloc_bad++;
                    else reloc_ok++;
                }
                emitted++;
                printf("// case %s\n", code_s);
                for (size_t i = 0; i + 4 <= buf->size; i += 4) {
                    uint32_t w;
                    memcpy(&w, buf->code + i, 4);
                    printf(".word 0x%08x\n", w);
                    words++;
                }
            }
        }
        if (buf) hb_codegen_buffer_destroy(buf);
        if (cg) hb_arm64_codegen_destroy(cg);
        if (ctx) hb_context_destroy(ctx);
        hb_ir_func_destroy(func);
    }
    fprintf(stderr, "случаев=%lu лифт=%lu выпуск=%lu слов=%lu\n", cases, lifted, emitted, words);
    fprintf(stderr, "релокации: сверено=%lu БИТЫХ=%lu\n", reloc_ok, reloc_bad);
    return 0;
}
