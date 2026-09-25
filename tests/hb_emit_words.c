/* СЧЁТ ВЫПУЩЕННЫХ СЛОВ — прибор лейна ВЫПУСК, 07.09.2026.
 *
 * ЗАЧЕМ. Правки кодогенератора мерить временем нельзя: рабочий поток — 2,48 % времени
 * процесса, и эффект в словах там утонет. Меряем то, что правка меняет НАПРЯМУЮ: число
 * выпущенных 4-байтных команд ARM64 на ОДНОМ И ТОМ ЖЕ корпусе.
 *
 * ЧТО СЧИТАЕТ. Ровно `out->size / 4` после `hb_arm64_codegen_block_with_cfg` по каждому
 * случаю корпуса, плюс число случаев, где выпуск ОТКАЗАЛ. Отказы считаются отдельно и в
 * сумму слов не входят: иначе «стало меньше слов» могло бы означать «стало больше отказов»,
 * то есть прибор врал бы в ту же сторону, ради которой заведён.
 *
 * ЧЕГО НЕ СЧИТАЕТ. Ни времени, ни числа ИСПОЛНЕНИЙ этих команд. Статическое слово и
 * исполненная команда — разные величины: блок несёт запасные ветви и несколько выходов.
 *
 * Формат корпуса тот же, что у hb_diff_case_runner: `<зерно> <байты-hex> [ожидание]`,
 * строки с `#` — примечания.
 *
 * Приёмка прибора (отрицательный контроль): `HB_EMIT_WORDS_NADBAVKA=<n>` дописывает n
 * лишних слов к каждому блоку. Прогон с надбавкой ОБЯЗАН показать больше слов — иначе
 * прибор ничего не считает. */

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include "hb_codegen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_CODE 512

/* Счётчики свёртки смещения из кодогенератора (hb_arm64_codegen.c). Разряды описаны там. */
extern unsigned long long macrunner_hb_kraya_off[5];

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char* s, uint8_t* out, size_t* out_n) {
    size_t n = 0;
    while (s[0] && s[1]) {
        int hi = hexval(s[0]), lo = hexval(s[1]);
        if (hi < 0 || lo < 0) return 0;
        if (n >= MAX_CODE) return 0;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    if (s[0]) return 0;
    *out_n = n;
    return n > 0;
}

int main(void) {
    const char* arch_s = getenv("HB_DIFF_ARCH");
    int is86 = arch_s && strcmp(arch_s, "x86") == 0;
    hb_arch_t arch = is86 ? HB_ARCH_X86 : HB_ARCH_X64;
    uint64_t base = is86 ? 0x100000ULL : 0x140000000ULL;
    const char* nad_s = getenv("HB_EMIT_WORDS_NADBAVKA");
    unsigned nadbavka = nad_s ? (unsigned)strtoul(nad_s, NULL, 0) : 0;

    unsigned long long words = 0, cases = 0, otkazov = 0, lift_otkazov = 0;
    char line[8192];

    while (fgets(line, sizeof(line), stdin)) {
        char* p = line;
        char* seed_s;
        char* code_s;
        uint8_t bytes[MAX_CODE];
        size_t n = 0;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        seed_s = strtok(p, " \t\r\n");
        code_s = strtok(NULL, " \t\r\n");
        if (!seed_s || !code_s) continue;
        if (!parse_hex(code_s, bytes, &n)) continue;

        cases++;
        {
            hb_decoder_t* dec = hb_decoder_create(arch, bytes, n, base);
            hb_ir_func_t* func = NULL;
            hb_result_t r;
            if (!dec) { lift_otkazov++; continue; }
            r = is86 ? hb_lift_func_x86(dec, &func) : hb_lift_func_x64(dec, &func);
            hb_decoder_destroy(dec);
            if (r != HB_OK || !func) { lift_otkazov++; if (func) hb_ir_func_destroy(func); continue; }

            {
                hb_context_t* ctx = hb_context_create(arch, HB_BACKEND_JIT);
                hb_arm64_codegen_t* cg = ctx ? hb_arm64_codegen_create(ctx) : NULL;
                hb_codegen_buffer_t* out = hb_codegen_buffer_create(64 * 1024);
                if (cg && out && func->cfg && func->cfg->entry) {
                    r = hb_arm64_codegen_block_with_cfg(cg, func->cfg->entry, func->cfg, out);
                    if (r == HB_OK) words += (unsigned long long)(out->size / 4) + nadbavka;
                    else otkazov++;
                    /* ПОСЛУЧАЙНАЯ ПЕЧАТЬ (HB_EMIT_WORDS_POSLUCHAJNO=1): «слов<TAB>байты».
                     * Заведена лейном ФЛАГИ-ЖИВОСТЬ 07.09, когда две редакции анализа
                     * живости разошлись на 136 слов из 69 712 и по итогам корпуса нельзя
                     * было понять, ГДЕ. Сумма отвечает «сколько», а не «на чём». */
                    if (getenv("HB_EMIT_WORDS_POSLUCHAJNO")) {
                        printf("%zu\t%s\n", r == HB_OK ? out->size / 4 : (size_t)0, code_s);
                    }
                } else {
                    otkazov++;
                }
                if (out) hb_codegen_buffer_destroy(out);
                if (ctx) hb_context_destroy(ctx);
            }
            hb_ir_func_destroy(func);
        }
    }

    /* ★ ПЕРЕПИСЬ ПОДГОТОВИТЕЛЬНЫХ `ADD` (лейн КРАЯ-АДРЕСОВ, п.7). Счётчики живут в
     * кодогенераторе и БЕЗУСЛОВНЫ; печатает их этот офлайн-прибор, а не движок —
     * `atexit` из кодогенератора убивает живой прогон (замер 06.09, Diablo 205 -> 23 с).
     * Печать по гейту, чтобы прежние замеры слов сравнивались строка в строку. */
    {
        const char* e = getenv("HB_EMIT_WORDS_OFF_PEREPIS");
        if (e && *e && *e != '0')
            printf("СВЁРТКА-СМЕЩЕНИЯ без-смещения=%llu свёрнуто=%llu "
                   "ADD-ISA=%llu ADD-наше=%llu ADD-не-влезло=%llu\n",
                   macrunner_hb_kraya_off[0], macrunner_hb_kraya_off[1],
                   macrunner_hb_kraya_off[2], macrunner_hb_kraya_off[3],
                   macrunner_hb_kraya_off[4]);
    }
    printf("СЛОВ %llu СЛУЧАЕВ %llu ОТКАЗОВ-ВЫПУСКА %llu ОТКАЗОВ-ЛИФТА %llu\n",
           words, cases, otkazov, lift_otkazov);
    return 0;
}
