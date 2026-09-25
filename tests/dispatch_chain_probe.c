/* MacRunner 2026-08-16, лейн ДИСПЕТЧ, итерация 9 — ПОВОЗКА СО СВЯЗЫВАНИЕМ.
 *
 * Зачем. Итерация 8 нашла статически: связывание входит в цель по жёсткой константе
 * `native_code + 12`, верной только для четырёхкомандного пролога, тогда как при бережливом
 * кадре (`MACRUNNER_HB_LEAN_FRAME`) пролог сжимается до ОДНОЙ команды. Правка (гейт
 * `MACRUNNER_HB_CHAIN_ENTRY_EXACT`) ищет вход по единственной кодировке `MOV X19, X0`.
 * Проверить её было НЕЧЕМ: обе прежние повозки строят ОДНООБЛОЧНЫЕ функции, рёбер между
 * блоками нет, переходники не создаются вовсе, счётчик молчит.
 *
 * Здесь функции МНОГООБЛОЧНЫЕ: короткие переходы вперёд разрезают код на блоки, между ними
 * появляются рёбра, и связыванию становится что связывать. Переходы только ВПЕРЁД — у
 * связывания есть гейт `MACRUNNER_HB_CHAIN_FORWARD_ONLY`, и обратное ребро он может отвергнуть.
 *
 * Что проверяется двумя руками:
 *   обычный кадр      вход обязан найтись на 12-м байте  (счётчик «на 12»)
 *   бережливый кадр   вход обязан найтись НЕ на 12-м     (счётчик «не на 12» + печать)
 * Если обе руки молчат — окно опять не открылось, и это будет сказано, а не скрыто.
 *
 * Сборка:
 *   /usr/bin/clang -O2 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/dispatch_chain_probe.c libhyperbridge.a -o tests/dispatch_chain_probe
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

#define GUEST_BASE 0x150000000ull

/* Первая редакция брала `EB 00` (jmp на следующую команду) — лифтер такой переход СВОРАЧИВАЕТ,
 * и вся функция осталась ОДНИМ блоком: `блоков в представлении=1`, `блоков исполнено=512` при
 * 512 запусках. Сторож повозки это и сказал.
 *
 * Здесь ветвь перепрыгивает ЧЕРЕЗ команду, поэтому у неё два разных преемника, и блок
 * действительно разрезается: вход (cmp+jne), сквозной путь и цель ветви. */
static const uint8_t CODE[] = {
    0x83, 0xF8, 0x00,               /* cmp eax, 0 */
    0x75, 0x05,                     /* jne +5  -> перепрыгивает mov ниже */
    0xB8, 0x01, 0x00, 0x00, 0x00,   /* mov eax, 1   (сквозной путь) */
    0xB8, 0x02, 0x00, 0x00, 0x00,   /* mov eax, 2   (цель ветви) */
    0x83, 0xF9, 0x00,               /* cmp ecx, 0 */
    0x74, 0x05,                     /* je +5 */
    0xB8, 0x03, 0x00, 0x00, 0x00,   /* mov eax, 3 */
    0xB8, 0x04, 0x00, 0x00, 0x00,   /* mov eax, 4 */
    0xC3                            /* ret */
};

/* Лифтер `hb_lift_func_x64` строит ОДИН блок на функцию — проверено двумя формами кода:
 * `jmp +0` он сворачивает, ветвь через команду тоже оставляет один блок (`блоков в
 * представлении=1`, `блоков исполнено=512` при 512 запусках в обоих случаях). Значит
 * многооблочный граф надо собирать руками — образец есть в `tests/debug_jcc.c`.
 *
 * Три блока: вход с условной ветвью, сквозной путь и цель ветви. Рёбра между ними — то, ради
 * чего повозка и написана: связыванию нужно ребро блок→блок, иначе переходник не строится. */
static hb_ir_func_t* make_multi(uint64_t addr)
{
    hb_ir_func_t* func = hb_ir_func_create( addr, 0 );
    hb_ir_block_t *a, *b, *c;
    hb_ir_builder_t* bld;

    if (!func) return NULL;
    a = hb_ir_block_create( 0, addr );
    b = hb_ir_block_create( 1, addr + 10 );   /* ровно сквозной путь блока A */
    c = hb_ir_block_create( 2, addr + 32 );
    if (!a || !b || !c) return NULL;
    hb_ir_cfg_add_block( func->cfg, a );
    hb_ir_cfg_add_block( func->cfg, b );
    hb_ir_cfg_add_block( func->cfg, c );
    hb_ir_cfg_add_edge( func->cfg, a, b );
    hb_ir_cfg_add_edge( func->cfg, a, c );
    hb_ir_cfg_add_edge( func->cfg, b, c );
    func->cfg->entry = a;

    bld = hb_ir_builder_create( func );
    /* ★ ГОСТЕВЫЕ АДРЕСА И ДЛИНЫ ОБЯЗАТЕЛЬНЫ. Без них сквозной путь условной ветви вычисляется
     * как `guest_addr + guest_len` последней команды, то есть в НОЛЬ: замер показал `pc=0x0`
     * после первого же блока, цикл диспетчеризации обрывался, и рёбер не возникало.
     * Адреса подобраны так, чтобы сквозной путь блока A попадал РОВНО на блок B. */
#define AT(i, a, l) do { hb_ir_instr_t* _i = (i); if (_i) { _i->guest_addr = (a); _i->guest_len = (l); } } while (0)
    hb_ir_builder_set_block( bld, a );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 1, HB_SIZE_64 ) ), addr, 5 );
    AT( hb_ir_emit_cmp( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 1, HB_SIZE_64 ) ), addr + 5, 3 );
    AT( hb_ir_emit_jcc( bld, HB_CC_NE, addr + 32 ), addr + 8, 2 );   /* сквозной путь -> addr+10 */
    hb_ir_builder_set_block( bld, b );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 2, HB_SIZE_64 ) ), addr + 10, 5 );
    AT( hb_ir_emit_jmp( bld, addr + 32 ), addr + 15, 5 );
    hb_ir_builder_set_block( bld, c );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 3, HB_SIZE_64 ) ), addr + 32, 5 );
    AT( hb_ir_emit_jmp( bld, addr + 64 ), addr + 37, 5 );
#undef AT
    hb_ir_builder_destroy( bld );
    return func;
}

int main(int argc, char** argv)
{
    size_t reps = (argc > 1) ? (size_t)strtoull( argv[1], NULL, 0 ) : 64;
    size_t rounds = (argc > 2) ? (size_t)strtoull( argv[2], NULL, 0 ) : 8;
    size_t n, r2, lifted = 0, ran = 0, failed = 0;
    uint64_t blocks_total = 0;
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    hb_ir_func_t** funcs;
    hb_result_t r;
    (void)CODE;

    printf( "# ДИСПЕТЧ: повозка со связыванием, функций=%zu обходов=%zu, байт кода=%zu\n",
            reps, rounds, sizeof(CODE) );
    printf( "# кадр=%s связывание=%s патч=%s запись=%s вход-точно=%s\n",
            getenv( "MACRUNNER_HB_LEAN_FRAME" ) ? "БЕРЕЖЛИВЫЙ" : "обычный",
            getenv( "MACRUNNER_HB_BLOCK_CHAIN" ) ? getenv( "MACRUNNER_HB_BLOCK_CHAIN" ) : "(выкл)",
            getenv( "MACRUNNER_HB_CHAIN_PATCH" ) ? getenv( "MACRUNNER_HB_CHAIN_PATCH" ) : "(выкл)",
            getenv( "MACRUNNER_HB_CHAIN_WRITE" ) ? getenv( "MACRUNNER_HB_CHAIN_WRITE" ) : "(выкл)",
            getenv( "MACRUNNER_HB_CHAIN_ENTRY_EXACT" ) ? getenv( "MACRUNNER_HB_CHAIN_ENTRY_EXACT" )
                                                       : "(умолчание=1)" );

    ctx = hb_context_create( HB_ARCH_X64, HB_BACKEND_JIT );
    if (!ctx) { printf( "ОТКАЗ ОСНАСТКИ: нет контекста\n" ); return 2; }
    if (!ctx->memory) ctx->memory = hb_memory_create( 0 );
    if (ctx->memory) {
        hb_memory_setup_stack( ctx->memory, 0x300000, 0x10000 );
        ctx->regs.x64.rsp = 0x2f8000;
    }
    /* ★ ПРЕДЕЛЫ ШАГОВ И БЛОКОВ ГАСЯТ СВЯЗЫВАНИЕ ЦЕЛИКОМ. Измерено счётчиками отказов
     * (`macrunner-hb-chaindecline`): единственная причина отказа была `site_patch_off=1024`,
     * то есть `chain_patch_enabled` ложно. А считается он так:
     *     chain_patch_enabled = chain_accounting && ctx->step_limit == 0 && ctx->block_limit == 0
     * Пределов повозка не задавала — их выставил `hb_context_create`. Печатаем их значения и
     * снимаем: иначе связывание не включается НИКАКИМИ гейтами. */
    printf( "# пределы контекста до снятия: шагов=%llu блоков=%llu\n",
            (unsigned long long)ctx->step_limit, (unsigned long long)ctx->block_limit );
    ctx->step_limit = 0;
    ctx->block_limit = 0;

    rt = hb_jit_runtime_create( ctx );
    if (!rt) { printf( "ОТКАЗ ОСНАСТКИ: нет среды JIT\n" ); return 2; }

    funcs = calloc( reps, sizeof(*funcs) );
    if (!funcs) { printf( "ОТКАЗ ОСНАСТКИ: нет памяти\n" ); return 2; }

    for (n = 0; n < reps; n++) {
        uint64_t base = GUEST_BASE + (uint64_t)n * 0x1000ull;
        funcs[n] = make_multi( base );
        if (!funcs[n]) { printf( "ОТКАЗ ОСНАСТКИ: граф не построен на %zu\n", n ); return 2; }
        if (!n)
            printf( "# блоков в представлении одной функции=%zu\n",
                    funcs[n]->cfg ? (size_t)funcs[n]->cfg->block_count : (size_t)0 );
        lifted++;
    }

    /* Повторные обходы нужны потому, что связывание ставит ребро НЕ на первом проходе: пока
     * цель не переведена и не попала в кеш, связывать не с чем. */
    for (r2 = 0; r2 < rounds; r2++) {
        for (n = 0; n < reps; n++) {
            /* ЦИКЛ ДИСПЕТЧЕРИЗАЦИИ. `hb_jit_runtime_run` исполняет ОДИН блок и возвращается —
             * проверено: при графе из трёх блоков `блоков исполнено` равнялось числу запусков.
             * Переходы блок→блок, ради которых связывание и существует, возникают только когда
             * вызывающий гонит диспетчер по `ctx->pc`, как это делает настоящая среда. */
            uint64_t base = GUEST_BASE + (uint64_t)n * 0x1000ull;
            int hops;

            ctx->pc = base;
            for (hops = 0; hops < 8; hops++) {
                hb_exec_result_t out;
                memset( &out, 0, sizeof(out) );
                r = hb_jit_runtime_run( rt, funcs[n], &out );
                (void)0;
                blocks_total += out.blocks_executed;
                if (r == HB_OK && out.result == HB_OK) ran++; else { failed++; break; }
                if (!n && !r2 && hops < 3)
                    printf( "# после блока %d: pc=0x%llx (база=0x%llx, блоков за запуск=%llu)\n",
                            hops, (unsigned long long)ctx->pc, (unsigned long long)base,
                            (unsigned long long)out.blocks_executed );
                if (ctx->pc < base || ctx->pc >= base + 64) break;
            }
        }
    }

    printf( "переведено=%zu  исполнено=%zu  отказов=%zu  блоков исполнено всего=%llu\n",
            lifted, ran, failed, (unsigned long long)blocks_total );
    if (blocks_total <= ran)
        printf( "ВНИМАНИЕ: блоков исполнено не больше, чем запусков — рёбер между блоками "
                "могло не быть, и связыванию нечего было связывать\n" );

    hb_jit_runtime_destroy( rt );
    hb_context_destroy( ctx );
    for (n = 0; n < reps; n++) hb_ir_func_destroy( funcs[n] );
    free( funcs );
    return 0;
}
