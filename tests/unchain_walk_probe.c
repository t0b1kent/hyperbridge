/* MacRunner 06.09.2026, лейн СЦЕПЛЕНИЕ — ПОСЕЩЕНО ПРОТИВ ИЗМЕНЕНО.
 *
 * ЗАЧЕМ. Разбор Астры (пункт 1 её порядка) называет `block_cache_unchain_references`
 * повторной работой: строкой выше входной трамплин уже перенаправлен на bailout ОДНОЙ
 * атомарной записью, а обход всё равно проходит все занятые слоты. Прямо там же стоит
 * её запрет: «нельзя просто удалить вызов по одному комментарию».
 *
 * Поэтому здесь не рассуждение, а два числа с одной повозки:
 *     ПОСЕЩЕНО   сколько записей кеша обход посмотрел
 *     ИЗМЕНЕНО   сколько рёбер он при этом действительно снял
 * Если второе ноль при первом большом — обход есть чистая трата. Если не ноль —
 * удалять нечего, и это будет сказано.
 *
 * ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ (обязателен, MACRUNNER_HB_TEST_NO_TRAMP_REVOKE=1). Вывод
 * «отзыв делает трамплин, а не обход» проверяется тем, что отзыв ОТКЛЮЧАЕТСЯ: тогда
 * входящее ребро обязано привести в СТАРОЕ тело, и повозка это увидит по значению
 * RAX. Не увидела — значит отзыв делает не литерал, и вывод неверен.
 *
 * Устройство одной функции (тот же приём, что в tests/dispatch_chain_probe.c: лифтер
 * строит ОДИН блок на функцию, поэтому граф собирается руками):
 *     A  addr+0    rax=1; cmp rax,1; jne addr+32     -> сквозной путь в B
 *     B  addr+10   rax=2; jmp addr+32                -> РЕБРО B->C, его и сшивают
 *     C  addr+32   rax=<метка версии>; jmp addr+64   -> выход из окна
 *
 * Сборка:
 *   /usr/bin/clang -O2 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/unchain_walk_probe.c libhyperbridge.a -o tests/unchain_walk_probe
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include "hb_probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUEST_BASE   0x150000000ull
#define GUEST_STRIDE 0x1000ull
#define METKA_V1     3ull        /* значение, которое ставит СТАРОЕ тело блока C */
#define METKA_V2     0x2222ull   /* значение, которое ставит НОВОЕ тело блока C */

static hb_ir_func_t* make_multi(uint64_t addr, uint64_t metka_c)
{
    hb_ir_func_t* func = hb_ir_func_create( addr, 0 );
    hb_ir_block_t *a, *b, *c;
    hb_ir_builder_t* bld;

    if (!func) return NULL;
    a = hb_ir_block_create( 0, addr );
    b = hb_ir_block_create( 1, addr + 10 );
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
    /* Гостевые адреса и длины обязательны: без них сквозной путь условной ветви
     * вычисляется в ноль и рёбер не возникает вовсе (проверено повозкой ДИСПЕТЧ). */
#define AT(i, ga, l) do { hb_ir_instr_t* _i = (i); if (_i) { _i->guest_addr = (ga); _i->guest_len = (l); } } while (0)
    hb_ir_builder_set_block( bld, a );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 1, HB_SIZE_64 ) ), addr, 5 );
    AT( hb_ir_emit_cmp( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 1, HB_SIZE_64 ) ), addr + 5, 3 );
    AT( hb_ir_emit_jcc( bld, HB_CC_NE, addr + 32 ), addr + 8, 2 );
    hb_ir_builder_set_block( bld, b );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 2, HB_SIZE_64 ) ), addr + 10, 5 );
    AT( hb_ir_emit_jmp( bld, addr + 32 ), addr + 15, 5 );
    hb_ir_builder_set_block( bld, c );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ),
                        hb_ir_imm( (int64_t)metka_c, HB_SIZE_64 ) ), addr + 32, 5 );
    AT( hb_ir_emit_jmp( bld, addr + 64 ), addr + 37, 5 );
#undef AT
    hb_ir_builder_destroy( bld );
    return func;
}

/* Гонит диспетчер по ctx->pc внутри окна одной функции — ровно так, как это делает
 * настоящая среда: hb_jit_runtime_run исполняет ОДИН блок и возвращается, а переходы
 * блок->блок (то, ради чего существует сцепление) возникают только у вызывающего. */
static int progon(hb_jit_runtime_t* rt, hb_context_t* ctx, hb_ir_func_t* func,
                  uint64_t base, uint64_t* blocks_out)
{
    int hops;
    for (hops = 0; hops < 8; hops++) {
        hb_exec_result_t out;
        hb_result_t r;
        memset( &out, 0, sizeof(out) );
        r = hb_jit_runtime_run( rt, func, &out );
        if (blocks_out) *blocks_out += out.blocks_executed;
        if (r != HB_OK || out.result != HB_OK) return 0;
        if (ctx->pc < base || ctx->pc >= base + 64) break;
    }
    return 1;
}

int main(int argc, char** argv)
{
    size_t reps   = (argc > 1) ? (size_t)strtoull( argv[1], NULL, 0 ) : 512;
    size_t rounds = (argc > 2) ? (size_t)strtoull( argv[2], NULL, 0 ) : 6;
    size_t n, r2, otkazov = 0;
    uint64_t blocks_total = 0, evicted_total = 0;
    uint64_t calls = 0, visited = 0, matched = 0, skipped = 0, overflow = 0, ns = 0;
    uint64_t staryh = 0, novyh = 0, inyh = 0;
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    hb_ir_func_t** v1;
    hb_ir_func_t** v2;
    const char* control = getenv( "MACRUNNER_HB_TEST_NO_TRAMP_REVOKE" );
    int control_on = control && *control && *control != '0';

    printf( "# СЦЕПЛЕНИЕ: посещено против изменено. функций=%zu обходов=%zu\n", reps, rounds );
    printf( "# отзыв трамплина=%s  обход=%s  прибор=%s\n",
            control_on ? "ОТКЛЮЧЁН (отрицательный контроль)" : "включён",
            getenv( "MACRUNNER_HB_UNCHAIN_WALK" ) ? getenv( "MACRUNNER_HB_UNCHAIN_WALK" )
                                                  : "(умолчание=1)",
            getenv( "MACRUNNER_HB_UNCHAIN_STATS" ) ? getenv( "MACRUNNER_HB_UNCHAIN_STATS" )
                                                   : "(умолчание=0 — чисел не будет)" );

    ctx = hb_context_create( HB_ARCH_X64, HB_BACKEND_JIT );
    if (!ctx) { printf( "ОТКАЗ ОСНАСТКИ: нет контекста\n" ); return 2; }
    if (!ctx->memory) ctx->memory = hb_memory_create( 0 );
    if (ctx->memory) {
        hb_memory_setup_stack( ctx->memory, 0x300000, 0x10000 );
        ctx->regs.x64.rsp = 0x2f8000;
    }
    /* Пределы шагов и блоков гасят сцепление ЦЕЛИКОМ (chain_patch_enabled требует обоих
     * нулей). Их выставляет hb_context_create, повозка обязана снять. */
    ctx->step_limit = 0;
    ctx->block_limit = 0;

    rt = hb_jit_runtime_create( ctx );
    if (!rt) { printf( "ОТКАЗ ОСНАСТКИ: нет среды JIT\n" ); return 2; }

    v1 = calloc( reps, sizeof(*v1) );
    v2 = calloc( reps, sizeof(*v2) );
    if (!v1 || !v2) { printf( "ОТКАЗ ОСНАСТКИ: нет памяти\n" ); return 2; }
    for (n = 0; n < reps; n++) {
        uint64_t base = GUEST_BASE + (uint64_t)n * GUEST_STRIDE;
        v1[n] = make_multi( base, METKA_V1 );
        v2[n] = make_multi( base, METKA_V2 );
        if (!v1[n] || !v2[n]) { printf( "ОТКАЗ ОСНАСТКИ: граф не построен на %zu\n", n ); return 2; }
    }

    /* ── ЭТАП 1: набить кеш и поставить рёбра ─────────────────────────────────── */
    for (r2 = 0; r2 < rounds; r2++)
        for (n = 0; n < reps; n++) {
            uint64_t base = GUEST_BASE + (uint64_t)n * GUEST_STRIDE;
            ctx->pc = base;
            if (!progon( rt, ctx, v1[n], base, &blocks_total )) otkazov++;
        }
    printf( "этап 1: блоков исполнено=%llu отказов=%zu\n",
            (unsigned long long)blocks_total, otkazov );
    if (blocks_total <= reps * rounds)
        printf( "ВНИМАНИЕ: блоков не больше, чем запусков — рёбер могло не быть\n" );

    hb_unchain_stats( &calls, &visited, &matched, &skipped, &overflow, &ns );
    printf( "этап 1: обход вызовов=%llu посещено=%llu изменено=%llu\n",
            (unsigned long long)calls, (unsigned long long)visited,
            (unsigned long long)matched );

    /* ── ЭТАП 2: выселить блок C у каждой функции ─────────────────────────────── */
    for (n = 0; n < reps; n++) {
        uint64_t base = GUEST_BASE + (uint64_t)n * GUEST_STRIDE;
        evicted_total += hb_jit_invalidate_guest_range( rt, base + 32, 8 );
    }
    hb_unchain_stats( &calls, &visited, &matched, &skipped, &overflow, &ns );
    printf( "этап 2: выселено записей=%llu\n", (unsigned long long)evicted_total );
    printf( "ЧИСЛА ОБХОДА: вызовов=%llu снято_гейтом=%llu посещено=%llu изменено=%llu "
            "полный_обход=%llu нс=%llu\n",
            (unsigned long long)calls, (unsigned long long)skipped,
            (unsigned long long)visited, (unsigned long long)matched,
            (unsigned long long)overflow, (unsigned long long)ns );
    if (calls)
        printf( "ЧИСЛА ОБХОДА: посещено_на_вызов=%.1f нс_на_вызов=%.1f\n",
                (double)visited / (double)calls, (double)ns / (double)calls );

    /* ── ЭТАП 3: исполнить сшитое ребро ПОСЛЕ подмены тела ────────────────────── */
    /* Блок C переведут заново — теперь из v2, то есть с ДРУГОЙ меткой. Предшественник B
     * при этом не выселялся: его заплата по-прежнему ведёт в СТАРЫЙ трамплин блока C.
     *   отзыв включён  -> литерал ведёт в bailout -> диспетчер -> новое тело -> METKA_V2
     *   отзыв отключён -> литерал ведёт в старое тело -> METKA_V1  (исполнение мёртвого) */
    for (n = 0; n < reps; n++) {
        uint64_t base = GUEST_BASE + (uint64_t)n * GUEST_STRIDE;
        ctx->pc = base;
        ctx->regs.x64.rax = 0;
        if (!progon( rt, ctx, v2[n], base, &blocks_total )) { otkazov++; continue; }
        if (ctx->regs.x64.rax == METKA_V2)      novyh++;
        else if (ctx->regs.x64.rax == METKA_V1) staryh++;
        else                                    inyh++;
    }
    printf( "этап 3: новых тел=%llu СТАРЫХ тел=%llu иных=%llu из %zu\n",
            (unsigned long long)novyh, (unsigned long long)staryh,
            (unsigned long long)inyh, reps );

    /* ── ЭТАП 4: МОЖЕТ ЛИ ПРЕДШЕСТВЕННИК ПЕРЕСШИТЬСЯ ─────────────────────────── */
    /* Второй вопрос, отдельный от стоимости. Обход был не только «лишним»: снимая
     * заплату предшественника, он ОСВОБОЖДАЛ его щель под новую цель. Если он этого
     * не делает, у предшественника в `meta->target_code` навсегда остаётся адрес
     * МЁРТВОГО трамплина, и `patch_block_tail` отвергает его как «уже сшит» при
     * каждом проходе. Число видно в переписи отказов сцепления
     * (macrunner-hb-chaindecline, гейт MACRUNNER_HB_TRACE_DISPATCH_STATS=1):
     * растущий `already` при неизменном числе заплат и означает эту потерю. */
    for (r2 = 0; r2 < rounds; r2++)
        for (n = 0; n < reps; n++) {
            uint64_t base = GUEST_BASE + (uint64_t)n * GUEST_STRIDE;
            ctx->pc = base;
            if (!progon( rt, ctx, v2[n], base, &blocks_total )) otkazov++;
        }
    printf( "этап 4: ещё %zu обходов после подмены цели — перепись отказов сцепления "
            "ниже (нужен MACRUNNER_HB_TRACE_DISPATCH_STATS=1)\n", rounds );

    hb_probe_census( stderr );

    /* ── ВЕРДИКТ ──────────────────────────────────────────────────────────────── */
    {
        int verdikt = 0;
        if (control_on) {
            /* Контроль обязан ОБНАРУЖИТЬ исполнение старой версии. Ноль здесь означает,
             * что повозка неспособна отличить отозванное ребро от неотозванного, и
             * тогда ЛЮБОЙ её положительный ответ ничего не стоит. */
            if (staryh == 0) {
                printf( "КОНТРОЛЬ ПРОВАЛЕН: отзыв отключён, а старых тел не исполнено ни "
                        "разу — повозка не различает отозванное ребро и неотозванное\n" );
                verdikt = 1;
            } else {
                printf( "КОНТРОЛЬ СРАБОТАЛ: отзыв отключён -> старое тело исполнено %llu раз\n",
                        (unsigned long long)staryh );
            }
        } else {
            if (staryh != 0) {
                printf( "ОТКАЗ: при включённом отзыве старое тело исполнено %llu раз\n",
                        (unsigned long long)staryh );
                verdikt = 1;
            }
        }
        if (otkazov) printf( "ВНИМАНИЕ: отказов исполнения=%zu\n", otkazov );
        hb_jit_runtime_destroy( rt );
        hb_context_destroy( ctx );
        for (n = 0; n < reps; n++) { hb_ir_func_destroy( v1[n] ); hb_ir_func_destroy( v2[n] ); }
        free( v1 ); free( v2 );
        return verdikt;
    }
}
