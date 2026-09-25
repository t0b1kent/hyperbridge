/* ПЕРЕПИСЬ РЕШЕНИЙ ПРЯМОГО ПУТИ К ПАМЯТИ — офлайн, по настоящим двоичным.
 *
 * ВОССТАНОВЛЕН 06.09.2026 лейном ПАМЯТЬ-i386. Цель `perepis-directmem` в Makefile
 * (строка 202) осталась сиротой: сам `tests/dm_perepis.c` исчез вместе со снесённой
 * копией лейна, в гите его нет ни в одной ветви (`git log --all -- <путь>` пуст).
 * Это ровно тот класс потерь, про который в CLAUDE.md записано «копию лейна не сносить,
 * пока не сверен её дист» — только здесь потерян ИСХОДНИК инструмента, а не дист.
 *
 * ЗАЧЕМ. Перепись форм операндов не требует ни wine, ни игры: корпус настоящих PE даёт
 * тот же набор форм, что и прогон. Секунды вместо прогонов по 10-15 минут.
 *
 * КАК. Каркас взят у `hb_regsurvey.c` (корпус -> настоящий лифтер -> настоящий выпуск),
 * вход заменён с шестнадцатеричных случаев на PE-файлы: hb_pe_load, затем линейный обход
 * исполняемых секций декодером.
 *
 * ГРАНИЦА ЛИНЕЙНОГО ОБХОДА, названная вслух: в .text вперемешку с кодом лежат таблицы
 * переходов и выравнивание, поэтому часть разобранного — не команды. Для ПЕРЕПИСИ ФОРМ
 * это допустимо (нас интересует распределение форм операндов, а не исполнение), но
 * доля 64-битных чтений отсюда — оценка по статике, а не по исполнению. Динамику даёт
 * тот же прибор на живом прогоне: счётчики в кодогенераторе одни и те же.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hb_context.h"
#include "hb_codegen.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_ir.h"
#include "hb_pe.h"

#define PE_SECTION_EXECUTE 0x20000000u
#define PE_SECTION_CODE    0x00000020u

/* Сколько байт секции разбирать максимум — защита от гигантских модулей. */
#define MAX_SECTION_BYTES (4u * 1024u * 1024u)

static unsigned long g_files, g_sections, g_decoded, g_lifted, g_blocks;

static void projti_sekciyu(hb_arch_t arch, const uint8_t* code, size_t len, uint64_t base)
{
    size_t off = 0;

    while (off < len) {
        hb_decoded_t d;
        hb_result_t r = (arch == HB_ARCH_X86)
                            ? hb_decode_x86(code + off, len - off, base + off, &d)
                            : hb_decode_x64(code + off, len - off, base + off, &d);
        size_t step;

        if (r != HB_OK || d.len == 0) { off += 1; continue; }
        step = d.len;
        g_decoded++;

        /* Блок из ОДНОЙ команды: нас интересует решение выпуска на команду, а не
         * качество разбиения на блоки. Лифтер функции пошёл бы по потоку управления
         * и на мусоре в .text давал бы неповторимый обход. */
        {
            hb_decoder_t* dec = hb_decoder_create(arch, code + off, step, base + off);
            hb_ir_func_t* func = NULL;
            hb_result_t lr;

            if (!dec) { off += step; continue; }
            lr = (arch == HB_ARCH_X86) ? hb_lift_func_x86(dec, &func)
                                       : hb_lift_func_x64(dec, &func);
            hb_decoder_destroy(dec);
            if (lr != HB_OK || !func) { if (func) hb_ir_func_destroy(func); off += step; continue; }
            g_lifted++;

            {
                hb_context_t* ctx = hb_context_create(arch, HB_BACKEND_JIT);
                hb_arm64_codegen_t* cg = ctx ? hb_arm64_codegen_create(ctx) : NULL;
                hb_codegen_buffer_t* buf = hb_codegen_buffer_create(65536);

                if (cg && buf && func->cfg && func->cfg->entry) {
                    buf->arch = arch;
                    if (hb_arm64_codegen_block(cg, func->cfg->entry, buf) == HB_OK)
                        g_blocks++;
                }
                if (buf) hb_codegen_buffer_destroy(buf);
                if (cg) hb_arm64_codegen_destroy(cg);
                if (ctx) hb_context_destroy(ctx);
            }
            hb_ir_func_destroy(func);
        }
        off += step;
    }
}

static void projti_fajl(const char* put)
{
    FILE* f = fopen(put, "rb");
    uint8_t* data;
    long size;
    hb_pe_image_t* pe;
    hb_arch_t arch;
    uint16_t i;

    if (!f) { fprintf(stderr, "перепись: не открыть %s\n", put); return; }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) { fclose(f); return; }
    data = (uint8_t*)malloc((size_t)size);
    if (!data) { fclose(f); return; }
    if (fread(data, 1, (size_t)size, f) != (size_t)size) { free(data); fclose(f); return; }
    fclose(f);

    pe = hb_pe_load(data, (size_t)size);
    if (!pe) { free(data); return; }

    /* 0x14c = i386, 0x8664 = amd64. Прочие мишени пропускаем молча — в корпусе их нет. */
    if (pe->machine == 0x014c) arch = HB_ARCH_X86;
    else if (pe->machine == 0x8664) arch = HB_ARCH_X64;
    else { hb_pe_unload(pe); free(data); return; }

    g_files++;
    for (i = 0; i < pe->section_count; i++) {
        hb_pe_section_t* s = &pe->sections[i];
        size_t len;
        if (!(s->characteristics & (PE_SECTION_EXECUTE | PE_SECTION_CODE))) continue;
        if (s->pointer_to_raw_data >= (uint32_t)size) continue;
        len = s->size_of_raw_data;
        if (s->pointer_to_raw_data + len > (uint32_t)size)
            len = (size_t)size - s->pointer_to_raw_data;
        if (len > MAX_SECTION_BYTES) len = MAX_SECTION_BYTES;
        if (!len) continue;
        g_sections++;
        projti_sekciyu(arch, data + s->pointer_to_raw_data, len,
                       pe->image_base + s->virtual_address);
    }

    hb_pe_unload(pe);
    free(data);
}

int main(int argc, char** argv)
{
    int i;
    for (i = 1; i < argc; i++) projti_fajl(argv[i]);
    fprintf(stderr, "перепись: файлов=%lu секций=%lu команд=%lu лифт=%lu блоков=%lu\n",
            g_files, g_sections, g_decoded, g_lifted, g_blocks);
    fflush(stderr);
    /* Сводки прибора печатаются на выходе через atexit — см. dm_svodka_na_vyhode
     * и perepis_shirin_na_vyhode в hb_arm64_codegen.c. */
    return 0;
}
