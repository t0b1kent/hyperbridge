/* MacRunner 2026-08-16, лейн ДИСПЕТЧ, итерация 7 — КАРТА ВОЗВРАТА НА НАСТОЯЩЕМ x86.
 *
 * Зачем. Самопроверка карты (`MACRUNNER_HB_RIPMAP_SELFTEST`, итерации 5-6) прошла 93 184
 * смещения без единого расхождения, но счётчик блоков со слиянием так и остался НУЛЁМ. То
 * есть про свою главную опасность — «номер записи карты отстаёт от номера команды после
 * слияния» — она не сказала ничего. Четыре попытки построить слияние прямо в представлении
 * промахнулись, и каждый промах имел свою причину (см. итерацию 6).
 *
 * Здесь слияние не синтезируется, а берётся оттуда, откуда оно берётся в жизни: НАСТОЯЩИЕ
 * байты x86 прогоняются через декодер и лифтер дерева, и кодогенерация сливает то, что
 * сливает сама. Ни одного допущения о том, какой образец сработает.
 *
 * Байты подобраны по условиям слияний из `hb_arm64_codegen.c`:
 *   cmp + sete        — `emit_scalar_flags_setcc_sequence` (две команды)
 *   add [mem],reg + test + jcc — `emit_arith_rmw_dead_flags_test_jcc` (три)
 *   mov [mem],imm + mov + lea  — `emit_store_imm_mov_lea_same_base` (три)
 * Если не сработает ни один, счётчик останется нулём — и это будет честный ответ «окно не
 * открылось», а не тишина.
 *
 * Сборка:
 *   /usr/bin/clang -O2 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/dispatch_ripmap_real.c libhyperbridge.a -o tests/dispatch_ripmap_real
 * Запуск:
 *   MACRUNNER_HB_RIPMAP=1 MACRUNNER_HB_RIPMAP_SELFTEST=1 ./tests/dispatch_ripmap_real
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_codegen.h"
#include "hb_memory.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUEST_BASE 0x140000000ull

static const uint8_t CODE[] = {
    /* cmp eax, 1 ; sete al        — пара для scalar_flags_setcc */
    0x83, 0xF8, 0x01,
    0x0F, 0x94, 0xC0,
    /* cmp ecx, 2 ; sete cl */
    0x83, 0xF9, 0x02,
    0x0F, 0x94, 0xC1,
    /* mov rdx, 0x200000 ; add [rdx], eax ; test eax, eax ; jne +2  — тройка для arith_rmw */
    0x48, 0xC7, 0xC2, 0x00, 0x00, 0x20, 0x00,
    0x01, 0x02,
    0x85, 0xC0,
    0x75, 0x02,
    /* mov dword [rdx], 7 ; mov eax, ecx ; lea rsi, [rdx+8]  — тройка для store_imm_mov_lea */
    0xC7, 0x02, 0x07, 0x00, 0x00, 0x00,
    0x89, 0xC8,
    0x48, 0x8D, 0x72, 0x08,
    /* mov eax, 5 ; ret */
    0xB8, 0x05, 0x00, 0x00, 0x00,
    0xC3
};

int main(int argc, char** argv)
{
    size_t reps = (argc > 1) ? (size_t)strtoull( argv[1], NULL, 0 ) : 256;
    size_t n, lifted = 0, ran = 0, failed = 0;
    hb_decoder_t* dec;
    hb_ir_func_t* func = NULL;
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    hb_exec_result_t out;
    hb_result_t r;

    printf( "# ДИСПЕТЧ: карта возврата на настоящем x86, байт кода=%zu\n", sizeof(CODE) );
    printf( "# карта=%s самопроверка=%s\n",
            getenv( "MACRUNNER_HB_RIPMAP" ) ? getenv( "MACRUNNER_HB_RIPMAP" ) : "(выкл)",
            getenv( "MACRUNNER_HB_RIPMAP_SELFTEST" ) ? getenv( "MACRUNNER_HB_RIPMAP_SELFTEST" ) : "(выкл)" );

    ctx = hb_context_create( HB_ARCH_X64, HB_BACKEND_JIT );
    if (!ctx) { printf( "ОТКАЗ ОСНАСТКИ: нет контекста\n" ); return 2; }
    if (!ctx->memory) ctx->memory = hb_memory_create( 0 );
    if (ctx->memory) {
        hb_memory_setup_stack( ctx->memory, 0x300000, 0x10000 );
        hb_memory_setup_heap( ctx->memory, 0x200000, 0x10000 );
        ctx->regs.x64.rsp = 0x2f8000;
    }
    rt = hb_jit_runtime_create( ctx );
    if (!rt) { printf( "ОТКАЗ ОСНАСТКИ: нет среды JIT\n" ); return 2; }

    /* ОДИН И ТОТ ЖЕ код по РАЗНЫМ гостевым базам: каждая база даёт свой блок, поэтому
     * самопроверка карты набирает вес, а не судит по одному блоку. Кода тут 43 байта, базы
     * разнесены на страницу — пересечений нет. */
    for (n = 0; n < reps; n++) {
        uint64_t base = GUEST_BASE + (uint64_t)n * 0x1000ull;

        dec = hb_decoder_create( HB_ARCH_X64, CODE, sizeof(CODE), base );
        if (!dec) { printf( "ОТКАЗ ОСНАСТКИ: декодер не создан на %zu\n", n ); return 2; }
        func = NULL;
        r = hb_lift_func_x64( dec, &func );
        if (r != HB_OK || !func) {
            printf( "ОТКАЗ ОСНАСТКИ: лифтер вернул %d на %zu\n", (int)r, n );
            return 2;
        }
        lifted++;
        ctx->pc = base;
        memset( &out, 0, sizeof(out) );
        r = hb_jit_runtime_run( rt, func, &out );
        if (r == HB_OK && out.result == HB_OK) ran++; else failed++;
        hb_ir_func_destroy( func );
        hb_decoder_destroy( dec );
    }
    func = NULL; dec = NULL;
    printf( "переведено функций=%zu  исполнено=%zu  отказов исполнения=%zu\n",
            lifted, ran, failed );
    if (!lifted) printf( "ВЕРДИКТА НЕТ: не переведено ни одной функции\n" );
    /* ★ Даже если исполнение отказало, ПЕРЕВОД состоялся, а самопроверка карты работает на
     * переводе. Поэтому отказ исполнения здесь не обесценивает результат — но и не прячется. */

    hb_jit_runtime_destroy( rt );
    hb_context_destroy( ctx );
    return 0;
}
