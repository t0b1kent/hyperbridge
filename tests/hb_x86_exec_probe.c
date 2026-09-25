/* Проба ИСПОЛНЕНИЯ одной 32-битной команды.
 *
 * `hb_x86_probe` отвечает только на вопрос «разобралось и поднялось ли» — он не
 * исполняет ничего. Оттого закрытая «дыра покрытия» может при работе падать:
 * декодер знает команду, лифтер её принял, а обработчик в интерпретаторе ждёт
 * XMM и получает MMX. Ровно это случилось с MMX-формами PINSRW/PEXTRW/PMOVMSKB
 * 28.08.2026 — проба разбора показывала ✅ при неисправленной семантике.
 *
 * Ввод (stdin, по строке на случай):  <hex-байты> [ключ=значение ...]
 *   mm<N>=<hex64>    начальное значение регистра MMX
 *   xmm<N>=<hex64>:<hex64>  начальное значение XMM (младшая:старшая)
 *   e<имя>=<hex32>   начальное значение обычного регистра (eax, ecx, ...)
 * Вывод: JSON со всеми регистрами после исполнения и признаком отказа.
 */
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

/* Порядок ПОЛЕЙ СТРУКТУРЫ (hb_context.h), а не порядок кодирования x86:
 * eax, ebx, ecx, edx, esi, edi, esp, ebp. Перепутать легко — совпадает только eax. */
static const char* ИМЕНА32[8] = {"eax","ebx","ecx","edx","esi","edi","esp","ebp"};

static int из_hex(const char* s, unsigned char* буфер, int предел) {
    int n = 0;
    while (*s && n < предел) {
        while (*s == ' ') s++;
        if (!s[0] || !s[1]) break;
        char пара[3] = { s[0], s[1], 0 };
        char* конец = NULL;
        long v = strtol(пара, &конец, 16);
        if (конец != пара + 2) break;
        буфер[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

int main(void) {
    char строка[1024];
    while (fgets(строка, sizeof(строка), stdin)) {
        char* пробел = strchr(строка, ' ');
        char* хвост = NULL;
        if (пробел) { *пробел = 0; хвост = пробел + 1; }
        char* nl = strchr(строка, '\n'); if (nl) *nl = 0;
        if (!строка[0]) continue;

        unsigned char код[64];
        int длина = из_hex(строка, код, (int)sizeof(код) - 16);
        if (длина <= 0) { printf("{\"ошибка\":\"пустой ввод\"}\n"); fflush(stdout); continue; }
        /* Хвост из NOP: команда может оказаться короче, чем подано. */
        memset(код + длина, 0x90, 8);
        длина += 8;

        /* ★ 32-битный режим требует ОКНА guest32 (`hb_memory_guest32_map`), а не
         * обычного `hb_memory_map`: последний даёт тождественное отображение, и
         * любая запись по 32-битному `esp` уходила в MEMORY_FAULT — ловилось на
         * обычном PUSH. Образец взят из приёмки (`hb_test_runner.c`, тесты
         * дальнего возврата). Код тоже кладём в окно и по гостевому адресу. */
        const hb_gva_t КОД_БАЗА = 0x00100000u;
        const hb_gva_t СТЕК_ВЕРХ = 0x00210000u;
        uint64_t база = КОД_БАЗА;
        hb_decoder_t* dec = hb_decoder_create(HB_ARCH_X86, (void*)код, (size_t)длина, база);
        hb_ir_func_t* func = NULL;
        if (!dec || hb_lift_func_x86(dec, &func) != HB_OK) {
            printf("{\"этап\":\"подъём\",\"ок\":0}\n"); fflush(stdout);
            if (dec) hb_decoder_destroy(dec);
            continue;
        }
        hb_decoder_destroy(dec);

        hb_context_t* ctx = hb_context_create(HB_ARCH_X86, HB_BACKEND_INTERP);
        if (!ctx) { printf("{\"этап\":\"контекст\",\"ок\":0}\n"); fflush(stdout); continue; }
        ctx->memory = hb_memory_create(0);
        hb_memory_guest32_map(ctx->memory, КОД_БАЗА, 4096,
                              HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC);
        hb_memory_guest32_map(ctx->memory, СТЕК_ВЕРХ - 65536, 65536,
                              HB_PERM_READ | HB_PERM_WRITE);
        hb_memory_write(ctx->memory, КОД_БАЗА, код, (size_t)длина);
        ctx->pc = база;
        ctx->regs.x86.eip = (uint32_t)база;
        ctx->regs.x86.esp = (uint32_t)(СТЕК_ВЕРХ - 0x1000u);
        ctx->regs.x86.ebp = ctx->regs.x86.esp;

        uint64_t* mm = ctx->mm;
        for (int i = 0; i < 8; i++) {
            if (mm) mm[i] = 0xeeeeeeeeeeeeeeeeULL;
            ctx->regs.x86.xmm[i][0] = 0xeeeeeeeeeeeeeeeeULL;
            ctx->regs.x86.xmm[i][1] = 0xeeeeeeeeeeeeeeeeULL;
        }

        /* Начальные значения из хвоста строки. */
        if (хвост) {
            char* лексема = strtok(хвост, " \t\n");
            while (лексема) {
                char* eq = strchr(лексема, '=');
                if (eq) {
                    *eq = 0;
                    const char* имя = лексема; const char* знач = eq + 1;
                    if (!strncmp(имя, "mm", 2) && имя[2] >= '0' && имя[2] <= '7') {
                        if (mm) mm[имя[2] - '0'] = strtoull(знач, NULL, 16);
                    } else if (!strncmp(имя, "xmm", 3) && имя[3] >= '0' && имя[3] <= '7') {
                        char* двоеточие = strchr(знач, ':');
                        int n = имя[3] - '0';
                        ctx->regs.x86.xmm[n][0] = strtoull(знач, NULL, 16);
                        if (двоеточие) ctx->regs.x86.xmm[n][1] = strtoull(двоеточие + 1, NULL, 16);
                    } else {
                        for (int i = 0; i < 8; i++)
                            if (!strcmp(имя, ИМЕНА32[i]))
                                *(&ctx->regs.x86.eax + i) = (uint32_t)strtoul(знач, NULL, 16);
                    }
                }
                лексема = strtok(NULL, " \t\n");
            }
        }

        hb_exec_result_t out;
        memset(&out, 0, sizeof(out));
        int r = hb_runtime_run(ctx, func, HB_BACKEND_INTERP, &out);

        printf("{\"ок\":%d,\"r\":%d,\"res\":%d", (r == HB_OK && out.result == HB_OK), r, out.result);
        printf(",\"регистры\":{");
        for (int i = 0; i < 8; i++)
            printf("%s\"%s\":\"%08x\"", i ? "," : "", ИМЕНА32[i], *(&ctx->regs.x86.eax + i));
        printf("},\"mm\":[");
        for (int i = 0; i < 8; i++)
            printf("%s\"%016llx\"", i ? "," : "", (unsigned long long)(mm ? mm[i] : 0));
        printf("],\"xmm\":[");
        for (int i = 0; i < 8; i++)
            printf("%s\"%016llx:%016llx\"", i ? "," : "",
                   (unsigned long long)ctx->regs.x86.xmm[i][0],
                   (unsigned long long)ctx->regs.x86.xmm[i][1]);
        printf("],\"pc\":\"%08llx\",\"cs\":\"%04x\",\"eip\":\"%08x\"}\n",
               (unsigned long long)ctx->pc, ctx->regs.x86.seg[1], ctx->regs.x86.eip);
        fflush(stdout);

        /* Намеренно НЕ освобождаем: разрушение контекста между случаями обрывало
         * цикл после первой строки. Проба короткоживущая — десятки случаев за
         * запуск, — и течь здесь дешевле, чем неверный ответ. */
    }
    return 0;
}
