/* hb_lock_window_probe — ПРИБОР: выпустить строчный путь блокирующей операции и
 * НАЗВАТЬ КОМАНДЫ ОКНА ГОНКИ.
 *
 * Отчёт 05.09 доказал ЧИСЛОМ, что строчный путь теряет приращения (4 416 из 400 000
 * на i386). Число говорит ЧТО, но не ГДЕ. Здесь берутся настоящие гостевые байты
 * `lock addl $1, [disp32]`, прогоняются через настоящий декодер, лифтер и
 * кодогенератор движка, а выпущенные слова ARM64 выводятся сырыми — чтобы окно между
 * загрузкой и записью можно было увидеть, а не вывести рассуждением.
 *
 * Сборка:
 *   clang -O1 -std=c11 -Wall -I include tests/hb_lock_window_probe.c libhyperbridge.a \
 *     -o tests/hb_lock_window_probe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "hb_codegen.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_ir.h"
#include "hb_context.h"

static void vypustit(const char* imya, hb_arch_t arch,
                     const uint8_t* bajty, size_t n, uint64_t baza) {
    hb_decoder_t* dec;
    hb_decoded_t d;
    hb_ir_func_t* func;
    hb_ir_block_t* blk;
    hb_ir_builder_t* b;
    hb_context_t* ctx;
    hb_arm64_codegen_t* cg;
    hb_codegen_buffer_t* buf;
    size_t i;

    dec = hb_decoder_create(arch, bajty, n, baza);
    if (!dec) { printf("%s: DEKODER NE SOZDAN\n", imya); return; }
    memset(&d, 0, sizeof(d));
    if (hb_decode_next(dec, &d) != HB_OK) { printf("%s: NE DEKODIROVANO\n", imya); return; }

    func = hb_ir_func_create(baza, 0);
    blk  = hb_ir_block_create(0, baza);
    hb_ir_cfg_add_block(func->cfg, blk);
    func->cfg->entry = blk;
    b = hb_ir_builder_create(func);
    hb_ir_builder_set_block(b, blk);
    if ((arch == HB_ARCH_X86 ? hb_lift_x86(&d, b) : hb_lift_x64(&d, b)) != HB_OK) {
        printf("%s: LIFTER OTKAZAL\n", imya); return;
    }
    hb_ir_builder_destroy(b);

    /* Ровно то, что делает настоящий блочный цикл лифтера (hb_lift_x86.c:2322,
     * hb_lift_x64.c:2084): пометка живёт в НЁМ, а не в hb_lift_x86 одной команды. */
    if (d.lock_prefix)
        for (i = 0; i < blk->instr_count; i++) blk->instrs[i].is_locked = true;

    printf("=== %s  (arch=%s, guest-bytes=%zu)\n", imya,
           arch == HB_ARCH_X86 ? "i386" : "x64", (size_t)d.len);
    printf("    IR-instr=%zu\n", (size_t)blk->instr_count);
    for (i = 0; i < blk->instr_count; i++) {
        const hb_ir_instr_t* ins = &blk->instrs[i];
        printf("    IR[%zu] op=%d is_locked=%d dst.type=%d dst.size=%d src2.type=%d\n",
               i, (int)ins->op, (int)ins->is_locked,
               (int)ins->dst.type, (int)ins->dst.size, (int)ins->src2.type);
    }

    ctx = hb_context_create(arch, HB_BACKEND_JIT);
    cg  = hb_arm64_codegen_create(ctx);
    buf = hb_codegen_buffer_create(16384);
    buf->arch = arch;
    if (hb_arm64_codegen_block(cg, blk, buf) != HB_OK) {
        printf("    KODOGENERATOR OTKAZAL\n");
    } else {
        printf("    emitted-bytes=%zu\n", buf->size);
        for (i = 0; i < buf->reloc_count; i++) {
            const hb_codegen_reloc_t* r = &buf->relocs[i];
            if (r->kind != HB_RELOC_KIND_HELPER) continue;
            Dl_info di;
            if (dladdr((void*)(uintptr_t)r->value, &di) && di.dli_sname)
                printf("    HELPER off=%zu reg=x%u -> %s\n", r->off, (unsigned)r->reg, di.dli_sname);
            else
                printf("    HELPER off=%zu reg=x%u -> 0x%llx (bez imeni)\n",
                       r->off, (unsigned)r->reg, (unsigned long long)r->value);
        }
        printf("    RAW-WORDS:\n");
        for (i = 0; i + 4 <= buf->size; i += 4) {
            uint32_t w;
            memcpy(&w, buf->code + i, 4);
            printf("    %04zu: %08x\n", i, w);
        }
    }
    hb_codegen_buffer_destroy(buf);
    hb_arm64_codegen_destroy(cg);
    hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    hb_decoder_destroy(dec);
    printf("\n");
}

#define D32 0x00, 0x40, 0x40, 0x00

int main(void) {
    /* lock addl $1, ds:0x00404000   =  F0 83 05 <disp32> 01  (mod=00 rm=101 -> disp32) */
    static const uint8_t lock_add_i386[] = { 0xF0, 0x83, 0x05, D32, 0x01 };
    /* lock addl $1, [rip+0] dlya x64 */
    static const uint8_t lock_add_x64[]  = { 0xF0, 0x83, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01 };
    /* kontrol: NEblokiruyushchij add */
    static const uint8_t add_i386[]      = { 0x83, 0x05, D32, 0x01 };

    /* Vsya semya blokiruyushchih RMW nad pamyatyu, forma [disp32], operand EAX. */
    static const uint8_t f_add[]  = { 0xF0, 0x01, 0x05, D32 };
    static const uint8_t f_sub[]  = { 0xF0, 0x29, 0x05, D32 };
    static const uint8_t f_and[]  = { 0xF0, 0x21, 0x05, D32 };
    static const uint8_t f_or[]   = { 0xF0, 0x09, 0x05, D32 };
    static const uint8_t f_xor[]  = { 0xF0, 0x31, 0x05, D32 };
    static const uint8_t f_adc[]  = { 0xF0, 0x11, 0x05, D32 };
    static const uint8_t f_sbb[]  = { 0xF0, 0x19, 0x05, D32 };
    static const uint8_t f_inc[]  = { 0xF0, 0xFF, 0x05, D32 };
    static const uint8_t f_dec[]  = { 0xF0, 0xFF, 0x0D, D32 };
    static const uint8_t f_neg[]  = { 0xF0, 0xF7, 0x1D, D32 };
    static const uint8_t f_not[]  = { 0xF0, 0xF7, 0x15, D32 };
    static const uint8_t f_bts[]  = { 0xF0, 0x0F, 0xAB, 0x05, D32 };
    static const uint8_t f_btr[]  = { 0xF0, 0x0F, 0xB3, 0x05, D32 };
    static const uint8_t f_btc[]  = { 0xF0, 0x0F, 0xBB, 0x05, D32 };
    static const uint8_t f_xadd[] = { 0xF0, 0x0F, 0xC1, 0x05, D32 };
    static const uint8_t f_cmpx[] = { 0xF0, 0x0F, 0xB1, 0x05, D32 };
    static const uint8_t f_add8[] = { 0xF0, 0x00, 0x05, D32 };
    static const uint8_t f_add16[]= { 0xF0, 0x66, 0x01, 0x05, D32 };

#define P(imya, bajty) vypustit(imya, HB_ARCH_X86, bajty, sizeof(bajty), 0x401000)
    vypustit("lock addl $1,[0x404000]  i386", HB_ARCH_X86, lock_add_i386, sizeof(lock_add_i386), 0x401000);
    vypustit("addl $1,[0x404000]  i386 (kontrol)", HB_ARCH_X86, add_i386, sizeof(add_i386), 0x401000);
    vypustit("lock addl $1,[rip]  x64", HB_ARCH_X64, lock_add_x64, sizeof(lock_add_x64), 0x140001000ull);
    P("lock add  [m],eax", f_add);   P("lock sub  [m],eax", f_sub);
    P("lock and  [m],eax", f_and);   P("lock or   [m],eax", f_or);
    P("lock xor  [m],eax", f_xor);   P("lock adc  [m],eax", f_adc);
    P("lock sbb  [m],eax", f_sbb);   P("lock inc  dword[m]", f_inc);
    P("lock dec  dword[m]", f_dec);  P("lock neg  dword[m]", f_neg);
    P("lock not  dword[m]", f_not);  P("lock bts  [m],eax", f_bts);
    P("lock btr  [m],eax", f_btr);   P("lock btc  [m],eax", f_btc);
    P("lock xadd [m],eax", f_xadd);  P("lock cmpxchg [m],eax", f_cmpx);
    P("lock add  byte[m],al", f_add8); P("lock add  word[m],ax", f_add16);
#undef P
    return 0;
}
