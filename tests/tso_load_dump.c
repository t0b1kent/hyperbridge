/* MacRunner 2026-08-31 — ЧТО ИМЕННО ВЫПУСКАЕТСЯ НА ГОСТЕВОЕ ЧТЕНИЕ.
 *
 * Вопрос стоял так: соблюдается ли модель памяти x86 на настоящем пути чтения?
 * Счётчики TSO дают ноль ВЕЗДЕ, включая полноценный блокнот, — но они стоят лишь
 * в двух эмиттерах, и неизвестно, тот ли это путь. Спорить об этом бессмысленно:
 * берём чтение, гоним через кодогенератор и СМОТРИМ БАЙТЫ.
 *
 * ldar/ldapr в выпуске -> порядок соблюдён, дыры нет.
 * голый ldr            -> порядок НЕ соблюдён, это дефект правильности.
 */
#include "hb_codegen.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    hb_ir_func_t* func = hb_ir_func_create(0x1000, 0);
    hb_ir_block_t* blk = hb_ir_block_create(0, 0x1000);
    hb_ir_builder_t* b;
    hb_arm64_codegen_t* cg;
    hb_codegen_buffer_t* out;
    size_t i;

    hb_ir_cfg_add_block(func->cfg, blk);
    func->cfg->entry = blk;
    b = hb_ir_builder_create(func);
    hb_ir_builder_set_block(b, blk);

    /* mov eax, [ebx]  — простейшее гостевое чтение из памяти */
    hb_ir_emit_load(b, hb_ir_reg(HB_REG_RAX, HB_SIZE_32),
                       hb_ir_mem(HB_REG_RBX, HB_REG_RBX, 0, 0, HB_SIZE_32));
    hb_ir_emit_ret(b);
    hb_ir_builder_destroy(b);

    { hb_context_t* ctx = hb_context_create(HB_ARCH_X86, HB_BACKEND_JIT); cg = hb_arm64_codegen_create(ctx); }
    out = hb_codegen_buffer_create(4096);   /* буфер СОЗДАЁТСЯ, а не обнуляется на стеке:
                                             * у него внутри списки релокаций, и нулевой
                                             * стековый экземпляр вешал прогон */
    if (hb_arm64_codegen_func(cg, func, out) != HB_OK) {
        printf("tso-dump: кодогенератор отказал\n");
        return 1;
    }
    printf("tso-dump: выпущено байт=%zu\n", out->size);
    for (i = 0; i + 4 <= out->size; i += 4) {
        uint32_t w;
        memcpy(&w, (const uint8_t*)out->code + i, 4);
        const char* note = "";
        /* LDAR/LDARB/LDARH: 0x08dffc00 / 0x48dffc00 / 0x88dffc00 / 0xc8dffc00 */
        if ((w & 0x3ffffc00u) == 0x08dffc00u) note = "  <-- LDAR (захват)";
        /* LDAPR: 0x38bfc000 / 0x78bfc000 / 0xb8bfc000 / 0xf8bfc000 */
        else if ((w & 0x3ffffc00u) == 0x38bfc000u) note = "  <-- LDAPR (захват RCpc)";
        /* DMB: 0xd50330bf | CRm<<8 */
        else if ((w & 0xfffff0ffu) == 0xd50330bfu) note = "  <-- DMB (барьер)";
        /* LDR immediate unsigned offset: 0xb9400000 / 0xf9400000 */
        else if ((w & 0xffc00000u) == 0xb9400000u || (w & 0xffc00000u) == 0xf9400000u)
            note = "  <-- ГОЛЫЙ LDR (без захвата)";
        printf("  %04zu: %08x%s\n", i, w, note);
    }
    hb_arm64_codegen_destroy(cg);
    hb_ir_func_destroy(func);
    return 0;
}
