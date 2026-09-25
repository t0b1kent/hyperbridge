/* MacRunner 14.09.2026, независимая линия HyperBridge — МАТРИЦА ВРЕМЕНИ ЖИЗНИ КЕША БЛОКОВ
 * (пункт 6 карты паритета FEX -> HyperBridge: SMC / cache lifetime).
 *
 * ДОНОРСКИЙ КОНТРАКТ (FEX, Source/Windows/Common/InvalidationTracker.cpp +
 * FEXCore/Source/Interface/Core/Core.cpp, LookupCache.h):
 *     инвалидация гостевого диапазона — ПРОЦЕСС-ШИРОКАЯ: под одним замком
 *     (CodeInvalidationMutex) стираются записи ВСЕХ буферов кода
 *     (InvalidateCodeBuffersCodeRange) и кеши ВСЕХ потоков
 *     (InvalidateThreadCachedCodeRange для каждого Thread); при стирании записи
 *     снимаются все ВХОДЯЩИЕ связи на неё (LookupCache::Erase -> delinker).
 *
 * НАШ МЕХАНИЗМ: hb_jit_invalidate_guest_range(rt, start, len) выселяет из кеша ОДНОЙ
 * среды JIT; кеш блоков — на среду (hb_jit_runtime_create: rt->block_cache =
 * block_cache_create()), среда — на поток. Клей Wine (macrunner_hb.c:33933, перехват
 * VirtualProtect) зовёт её с macrunner_hb_tls_jit_rt — средой ВЫЗЫВАЮЩЕГО потока.
 *
 * ВОПРОС, на который отвечает прибор числом, а не рассуждением: исполняет ли ДРУГАЯ
 * среда старый перевод после того, как первая объявила диапазон недействительным.
 *
 * СТРОКИ МАТРИЦЫ (каждая — по reps функций, итог — счёт):
 *   К   контроль оснастки: без инвалидации кеш обязан отдать СТАРОЕ тело (METKA_V1).
 *       Иначе повозка не отличает «выселено» от «и не было в кеше» — отказ оснастки, код 2.
 *   Р1  своя среда: rt1 выселяет, rt1 исполняет -> обязано быть НОВОЕ тело (METKA_V2).
 *   К2  чужая среда через СТАРЫЙ вход (как звал клей Wine до 14.09): rt1 и rt2 оба перевели
 *       v1; rt1 выселяет у себя; rt2 исполняет. Вход на одну среду остаётся на одну среду,
 *       поэтому здесь ОБЯЗАНО быть METKA_V1 — это отрицательный контроль, доказывающий, что
 *       повозка видит чужую среду. До починки эта строка была ПРОБЕЛОМ (256 из 256,
 *       outputs/cache-lifetime-01); клей Wine должен звать _all (требование к Wine, отдельно).
 *   Р4  (появляется вместе с починкой) процесс-широкая инвалидация: rt1 зовёт
 *       hb_jit_invalidate_guest_range_all; rt2 исполняет -> METKA_V2.
 *   Р6  (с починкой) переполнение кольца: объявлений больше ёмкости, пока rt2 не входит в
 *       диспетчер -> ровно одна полная чистка своего кеша у rt2 и METKA_V2 (лишнее выселение,
 *       не пропуск).
 *   Р5  (с починкой) в полёте: поток 2 крутит rt2 по v1, пока поток 1 объявляет диапазон
 *       недействительным много раз; потом поток 2 исполняет v2 -> METKA_V2, без падения.
 *
 * ГРАНИЦА, названная вслух: записи здесь НЕ отслежены хешем (гостевых байт нет —
 * ровно случай страницы R|X, «аккуратный порождатель RW->RX»). Отслеженный хешем случай
 * (W-область) ловится сверкой на входе в диспетчер, но НЕ через сцепленное ребро; он не
 * измеряется этой повозкой.
 *
 * Устройство функции — как в tests/unchain_walk_probe.c (лифтер строит ОДИН блок на
 * функцию, поэтому граф собирается руками):
 *     A  addr+0    rax=1; cmp rax,1; jne addr+32
 *     B  addr+10   rax=2; jmp addr+32
 *     C  addr+32   rax=<метка версии>; jmp addr+64     -> выход из окна
 *
 * Сборка: make -C engine/hyperbridge tests/zhizn_kesha_matrix && ./tests/zhizn_kesha_matrix
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUEST_BASE   0x160000000ull
#define GUEST_STRIDE 0x1000ull
#define METKA_V1     3ull
#define METKA_V2     0x2222ull

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

/* Гонит диспетчер по ctx->pc внутри окна одной функции: hb_jit_runtime_run исполняет ОДИН
 * блок и возвращается, переходы блок->блок возникают у вызывающего (или по сцеплению). */
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

typedef struct {
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
} sreda_t;

static int sreda_create(sreda_t* s, hb_memory_t* shared_mem)
{
    s->ctx = hb_context_create( HB_ARCH_X64, HB_BACKEND_JIT );
    if (!s->ctx) return 0;
    if (shared_mem) {
        if (s->ctx->memory) hb_memory_destroy( s->ctx->memory );
        s->ctx->memory = shared_mem;
    } else if (!s->ctx->memory) {
        s->ctx->memory = hb_memory_create( 0 );
        if (!s->ctx->memory) return 0;
        hb_memory_setup_stack( s->ctx->memory, 0x300000, 0x10000 );
    }
    s->ctx->regs.x64.rsp = 0x2f8000;
    /* Пределы шагов и блоков гасят сцепление целиком; повозка их снимает. */
    s->ctx->step_limit = 0;
    s->ctx->block_limit = 0;
    s->rt = hb_jit_runtime_create( s->ctx );
    return s->rt != NULL;
}

static void sreda_destroy(sreda_t* s, int owns_mem)
{
    if (s->rt) hb_jit_runtime_destroy( s->rt );
    if (s->ctx) {
        if (!owns_mem) s->ctx->memory = NULL;
        hb_context_destroy( s->ctx );
    }
}

/* Прогрев: rounds обходов по всем функциям v1 — набить кеш и поставить рёбра. */
static size_t progrev(sreda_t* s, hb_ir_func_t** v1, size_t reps, size_t rounds, uint64_t base0,
                      uint64_t* blocks)
{
    size_t r, n, otkazov = 0;
    for (r = 0; r < rounds; r++)
        for (n = 0; n < reps; n++) {
            uint64_t base = base0 + (uint64_t)n * GUEST_STRIDE;
            s->ctx->pc = base;
            if (!progon( s->rt, s->ctx, v1[n], base, blocks )) otkazov++;
        }
    return otkazov;
}

/* Исполнить v2 по всем функциям и посчитать, чьё тело сработало. */
static void ispolnit_v2(sreda_t* s, hb_ir_func_t** v2, size_t reps, uint64_t base0,
                        uint64_t* novyh, uint64_t* staryh, uint64_t* inyh, size_t* otkazov)
{
    size_t n;
    *novyh = *staryh = *inyh = 0;
    for (n = 0; n < reps; n++) {
        uint64_t base = base0 + (uint64_t)n * GUEST_STRIDE;
        s->ctx->pc = base;
        s->ctx->regs.x64.rax = 0;
        if (!progon( s->rt, s->ctx, v2[n], base, NULL )) { (*otkazov)++; continue; }
        if (s->ctx->regs.x64.rax == METKA_V2)      (*novyh)++;
        else if (s->ctx->regs.x64.rax == METKA_V1) (*staryh)++;
        else                                       (*inyh)++;
    }
}

static int make_all(hb_ir_func_t** v1, hb_ir_func_t** v2, size_t reps, uint64_t base0)
{
    size_t n;
    for (n = 0; n < reps; n++) {
        uint64_t base = base0 + (uint64_t)n * GUEST_STRIDE;
        v1[n] = make_multi( base, METKA_V1 );
        v2[n] = make_multi( base, METKA_V2 );
        if (!v1[n] || !v2[n]) return 0;
    }
    return 1;
}

static void free_all(hb_ir_func_t** v1, hb_ir_func_t** v2, size_t reps)
{
    size_t n;
    for (n = 0; n < reps; n++) { hb_ir_func_destroy( v1[n] ); hb_ir_func_destroy( v2[n] ); }
}

/* Р5: поток, который крутит среду 2, пока главный поток объявляет инвалидации. */
#define POSLE_KRUGOV 16u
typedef struct {
    sreda_t* s;
    hb_ir_func_t** v1;
    hb_ir_func_t** v2;
    size_t reps;
    uint64_t base0;
    pthread_mutex_t zamok;      /* «подъём+исполнение» против «переписали+объявили» */
    int rewritten;              /* байты стали v2 (ставится под замком, читается acquire) */
    uint64_t otkazov;
    uint64_t do_krugov, posle_krugov;
    uint64_t posle_staryh, posle_novyh, posle_inyh;
} polyot_t;

static void* polyot_thread(void* arg)
{
    polyot_t* p = (polyot_t*)arg;
    size_t n;
    for (;;) {
        int rw_krug = 0;
        for (n = 0; n < p->reps; n++) {
            uint64_t base = p->base0 + (uint64_t)n * GUEST_STRIDE;
            int rw;
            pthread_mutex_lock( &p->zamok );
            rw = __atomic_load_n( &p->rewritten, __ATOMIC_ACQUIRE );
            p->s->ctx->pc = base;
            p->s->ctx->regs.x64.rax = 0;
            if (!progon( p->s->rt, p->s->ctx, rw ? p->v2[n] : p->v1[n], base, NULL )) p->otkazov++;
            else if (rw) {
                if (p->s->ctx->regs.x64.rax == METKA_V2)      p->posle_novyh++;
                else if (p->s->ctx->regs.x64.rax == METKA_V1) p->posle_staryh++;
                else                                          p->posle_inyh++;
            }
            pthread_mutex_unlock( &p->zamok );
            if (rw) rw_krug = 1;
        }
        if (rw_krug) { if (++p->posle_krugov >= POSLE_KRUGOV) break; }
        else p->do_krugov++;
    }
    return NULL;
}

int main(int argc, char** argv)
{
    size_t reps   = (argc > 1) ? (size_t)strtoull( argv[1], NULL, 0 ) : 256;
    size_t rounds = (argc > 2) ? (size_t)strtoull( argv[2], NULL, 0 ) : 4;
    size_t otkazov = 0, n;
    uint64_t blocks = 0, novyh, staryh, inyh, evicted;
    hb_ir_func_t **v1, **v2;
    sreda_t s1, s2;
    hb_memory_t* mem;
    int verdikt = 0;
    /* Три отдельных полосы адресов, чтобы строки матрицы не делили кеш друг с другом. */
    const uint64_t POLOSA_K  = GUEST_BASE;
    const uint64_t POLOSA_R2 = GUEST_BASE + 0x01000000ull;
    const uint64_t POLOSA_R4 = GUEST_BASE + 0x02000000ull;
    const uint64_t POLOSA_R5 = GUEST_BASE + 0x03000000ull;
    const uint64_t POLOSA_R6 = GUEST_BASE + 0x04000000ull;

    printf( "# ЖИЗНЬ КЕША: функций=%zu прогревов=%zu\n", reps, rounds );

    memset( &s1, 0, sizeof s1 ); memset( &s2, 0, sizeof s2 );
    if (!sreda_create( &s1, NULL )) { printf( "ОТКАЗ ОСНАСТКИ: нет среды 1\n" ); return 2; }
    mem = s1.ctx->memory;
    if (!sreda_create( &s2, mem )) { printf( "ОТКАЗ ОСНАСТКИ: нет среды 2\n" ); return 2; }

    v1 = calloc( reps, sizeof(*v1) );
    v2 = calloc( reps, sizeof(*v2) );
    if (!v1 || !v2) { printf( "ОТКАЗ ОСНАСТКИ: нет памяти\n" ); return 2; }

    /* ── К: контроль оснастки — без инвалидации кеш обязан отдать СТАРОЕ тело ─────── */
    if (!make_all( v1, v2, reps, POLOSA_K )) { printf( "ОТКАЗ ОСНАСТКИ: граф\n" ); return 2; }
    otkazov += progrev( &s1, v1, reps, rounds, POLOSA_K, &blocks );
    ispolnit_v2( &s1, v2, reps, POLOSA_K, &novyh, &staryh, &inyh, &otkazov );
    printf( "К   контроль (без инвалидации, своя среда): старых=%llu новых=%llu иных=%llu из %zu; "
            "блоков за прогрев=%llu%s\n",
            (unsigned long long)staryh, (unsigned long long)novyh, (unsigned long long)inyh, reps,
            (unsigned long long)blocks,
            blocks <= reps * rounds ? " (ВНИМАНИЕ: рёбер могло не быть)" : "" );
    if (staryh != reps) {
        printf( "ОТКАЗ ОСНАСТКИ: кеш не отдал старое тело %zu раз — повозка не различает "
                "«выселено» и «не было в кеше»\n", reps );
        return 2;
    }

    /* ── Р1: своя среда — выселение и исполнение в одной среде ───────────────────── */
    /* Сейчас в кеше s1 лежат тела v1 (контроль их не выселял). */
    evicted = 0;
    for (n = 0; n < reps; n++)
        evicted += hb_jit_invalidate_guest_range( s1.rt, POLOSA_K + (uint64_t)n * GUEST_STRIDE, 64 );
    ispolnit_v2( &s1, v2, reps, POLOSA_K, &novyh, &staryh, &inyh, &otkazov );
    printf( "Р1  своя среда: выселено=%llu старых=%llu новых=%llu иных=%llu из %zu\n",
            (unsigned long long)evicted, (unsigned long long)staryh, (unsigned long long)novyh,
            (unsigned long long)inyh, reps );
    if (staryh) { printf( "ОТКАЗ Р1: своя среда исполнила старое тело %llu раз\n", (unsigned long long)staryh ); verdikt = 1; }
    free_all( v1, v2, reps );

    /* ── Р2: чужая среда — как зовёт клей Wine (только своя среда) ───────────────── */
    if (!make_all( v1, v2, reps, POLOSA_R2 )) { printf( "ОТКАЗ ОСНАСТКИ: граф\n" ); return 2; }
    otkazov += progrev( &s1, v1, reps, rounds, POLOSA_R2, NULL );
    otkazov += progrev( &s2, v1, reps, rounds, POLOSA_R2, NULL );
    evicted = 0;
    for (n = 0; n < reps; n++)
        evicted += hb_jit_invalidate_guest_range( s1.rt, POLOSA_R2 + (uint64_t)n * GUEST_STRIDE, 64 );
    ispolnit_v2( &s2, v2, reps, POLOSA_R2, &novyh, &staryh, &inyh, &otkazov );
    printf( "К2  контроль: чужая среда при инвалидации ОДНОЙ среды (вход как у клея Wine): выселено_в_rt1=%llu "
            "старых=%llu новых=%llu иных=%llu из %zu\n",
            (unsigned long long)evicted, (unsigned long long)staryh, (unsigned long long)novyh,
            (unsigned long long)inyh, reps );
    /* До починки 14.09 это была строка ПРОБЕЛА (outputs/cache-lifetime-01: 256 из 256). Теперь
     * это ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: вход на одну среду по-прежнему на одну среду, и другая
     * среда ОБЯЗАНА показать устаревший перевод — иначе повозка не видит чужую среду, и
     * зелёная Р4 ничего не стоит. */
    if (staryh != reps) {
        printf( "ОТКАЗ ОСНАСТКИ (контроль К2): инвалидация одной среды должна оставить старые "
                "тела у другой (%zu), увидено %llu — повозка не различает среды\n",
                reps, (unsigned long long)staryh );
        return 2;
    }
    free_all( v1, v2, reps );

    /* ── Р4: процесс-широкая инвалидация (починка 14.09) ─────────────────────────── */
    {
        uint64_t calls0, applied0, over0, calls1, applied1, over1;
        if (!make_all( v1, v2, reps, POLOSA_R4 )) { printf( "ОТКАЗ ОСНАСТКИ: граф\n" ); return 2; }
        otkazov += progrev( &s1, v1, reps, rounds, POLOSA_R4, NULL );
        otkazov += progrev( &s2, v1, reps, rounds, POLOSA_R4, NULL );
        hb_jit_inval_all_stats( &calls0, &applied0, &over0 );
        evicted = 0;
        for (n = 0; n < reps; n++)
            evicted += hb_jit_invalidate_guest_range_all( s1.rt, POLOSA_R4 + (uint64_t)n * GUEST_STRIDE, 64 );
        ispolnit_v2( &s2, v2, reps, POLOSA_R4, &novyh, &staryh, &inyh, &otkazov );
        hb_jit_inval_all_stats( &calls1, &applied1, &over1 );
        printf( "Р4  процесс-широкая (rt1 объявляет, rt2 применяет у себя): выселено_в_rt1=%llu "
                "старых=%llu новых=%llu иных=%llu из %zu; объявлений=%llu применено_чужими=%llu "
                "полных_чисток=%llu\n",
                (unsigned long long)evicted, (unsigned long long)staryh, (unsigned long long)novyh,
                (unsigned long long)inyh, reps, (unsigned long long)(calls1 - calls0),
                (unsigned long long)(applied1 - applied0), (unsigned long long)(over1 - over0) );
        if (staryh) { printf( "ОТКАЗ Р4: старое тело исполнено %llu раз\n", (unsigned long long)staryh ); verdikt = 1; }
        if (applied1 - applied0 == 0 && over1 - over0 == 0) {
            printf( "ОТКАЗ Р4: механизм не сработал ни разу (применено=0, чисток=0) — зелёный "
                    "результат ничем не подтверждён\n" );
            verdikt = 1;
        }
        /* Переполнение кольца: reps=%zu объявлений подряд БЕЗ входа rt2 в диспетчер должно дать
         * полную чистку у rt2, а не пропуск. При reps <= HB_INVAL_RING (256) чисток нет — тогда
         * это применение по одному; печатаем, что именно было, и не судим. */
        free_all( v1, v2, reps );
    }

    /* ── Р6: переполнение кольца — отставшая среда чистит ВСЁ, а не пропускает ─────── */
    {
        uint64_t calls0, applied0, over0, calls1, applied1, over1;
        size_t objavleno = 0;
        if (!make_all( v1, v2, reps, POLOSA_R6 )) { printf( "ОТКАЗ ОСНАСТКИ: граф\n" ); return 2; }
        otkazov += progrev( &s1, v1, reps, 1, POLOSA_R6, NULL );
        otkazov += progrev( &s2, v1, reps, 1, POLOSA_R6, NULL );
        hb_jit_inval_all_stats( &calls0, &applied0, &over0 );
        /* Больше объявлений, чем ёмкость кольца (256), пока rt2 в диспетчер не входит: половина
         * из них — по чужим адресам, чтобы кольцо переполнилось ЗАВЕДОМО, а не впритык. */
        for (n = 0; n < reps; n++, objavleno++)
            (void)hb_jit_invalidate_guest_range_all( s1.rt, POLOSA_R6 + (uint64_t)n * GUEST_STRIDE, 64 );
        for (n = 0; n < reps; n++, objavleno++)
            (void)hb_jit_invalidate_guest_range_all( s1.rt, POLOSA_R6 + 0x00800000ull + (uint64_t)n * GUEST_STRIDE, 64 );
        ispolnit_v2( &s2, v2, reps, POLOSA_R6, &novyh, &staryh, &inyh, &otkazov );
        hb_jit_inval_all_stats( &calls1, &applied1, &over1 );
        printf( "Р6  переполнение кольца (%zu объявлений без входа rt2): старых=%llu новых=%llu иных=%llu "
                "из %zu; применено_по_одному=%llu полных_чисток=%llu\n",
                objavleno, (unsigned long long)staryh, (unsigned long long)novyh,
                (unsigned long long)inyh, reps, (unsigned long long)(applied1 - applied0),
                (unsigned long long)(over1 - over0) );
        if (staryh) { printf( "ОТКАЗ Р6: после переполнения старое тело исполнено %llu раз\n", (unsigned long long)staryh ); verdikt = 1; }
        if (over1 - over0 != 1) {
            printf( "ОТКАЗ Р6: ожидалась ровно одна полная чистка, увидено %llu\n", (unsigned long long)(over1 - over0) );
            verdikt = 1;
        }
        free_all( v1, v2, reps );
    }

    /* ── Р5: в полёте — поток 2 крутит rt2, поток 1 объявляет ────────────────────── */
    /* Две фазы. ШУМ: поток 2 крутит v1 без замка, поток 1 объявляет диапазоны — проверяется,
     * что применение у себя на входе в диспетчер не роняет полёт (отказов_в_полёте=0) и
     * действительно происходит (применено>0 или чистка>0). ПЕРЕПИСЬ: под замком поток 1
     * ставит rewritten=1 и объявляет все диапазоны; поток 2 берёт тот же замок на КАЖДЫЙ
     * подъём+исполнение — так «байты читаются при подъёме ПОСЛЕ выселения на входе», как в
     * настоящей памяти; без замка повозка сама создавала бы окно «прочитал старые байты, потом
     * применил объявление, потом перевёл старое» — окно, которого у настоящего лифтера нет
     * (он читает байты после входа в диспетчер). После переписи поток 2 обязан исполнять
     * только v2 (>= POSLE_KRUGOV кругов), и каждый исход обязан быть METKA_V2. */
    {
        polyot_t pl;
        pthread_t th;
        uint64_t applied0, applied1, over0, over1, calls0, calls1;
        size_t m;
        if (!make_all( v1, v2, reps, POLOSA_R5 )) { printf( "ОТКАЗ ОСНАСТКИ: граф\n" ); return 2; }
        otkazov += progrev( &s1, v1, reps, 1, POLOSA_R5, NULL );
        memset( &pl, 0, sizeof pl );
        pl.s = &s2; pl.v1 = v1; pl.v2 = v2; pl.reps = reps; pl.base0 = POLOSA_R5;
        pthread_mutex_init( &pl.zamok, NULL );
        hb_jit_inval_all_stats( &calls0, &applied0, &over0 );
        if (pthread_create( &th, NULL, polyot_thread, &pl ) != 0) { printf( "ОТКАЗ ОСНАСТКИ: поток\n" ); return 2; }
        /* ШУМ: объявляем, пока поток 2 летит без замка. */
        for (m = 0; m < 8; m++) {
            for (n = 0; n < reps; n++)
                (void)hb_jit_invalidate_guest_range_all( s1.rt, POLOSA_R5 + (uint64_t)n * GUEST_STRIDE, 64 );
            sched_yield();
        }
        /* ПЕРЕПИСЬ: байты стали v2, объявляем — под тем же замком, что и подъём в потоке 2. */
        pthread_mutex_lock( &pl.zamok );
        __atomic_store_n( &pl.rewritten, 1, __ATOMIC_RELEASE );
        for (n = 0; n < reps; n++)
            (void)hb_jit_invalidate_guest_range_all( s1.rt, POLOSA_R5 + (uint64_t)n * GUEST_STRIDE, 64 );
        pthread_mutex_unlock( &pl.zamok );
        pthread_join( th, NULL );
        pthread_mutex_destroy( &pl.zamok );
        otkazov += pl.otkazov;
        hb_jit_inval_all_stats( &calls1, &applied1, &over1 );
        printf( "Р5  в полёте (до переписи %llu кругов v1, после %llu кругов v2; объявлено %llu): "
                "после переписи старых=%llu новых=%llu иных=%llu; применено_чужими=%llu "
                "полных_чисток=%llu отказов_в_полёте=%llu\n",
                (unsigned long long)pl.do_krugov, (unsigned long long)pl.posle_krugov,
                (unsigned long long)(calls1 - calls0),
                (unsigned long long)pl.posle_staryh, (unsigned long long)pl.posle_novyh,
                (unsigned long long)pl.posle_inyh,
                (unsigned long long)(applied1 - applied0), (unsigned long long)(over1 - over0),
                (unsigned long long)pl.otkazov );
        if (pl.posle_staryh) { printf( "ОТКАЗ Р5: после переписи старое тело исполнено %llu раз\n", (unsigned long long)pl.posle_staryh ); verdikt = 1; }
        if (pl.posle_inyh)   { printf( "ОТКАЗ Р5: после переписи иных исходов %llu\n", (unsigned long long)pl.posle_inyh ); verdikt = 1; }
        if (pl.otkazov)      { printf( "ОТКАЗ Р5: отказов исполнения в полёте=%llu\n", (unsigned long long)pl.otkazov ); verdikt = 1; }
        if (pl.do_krugov == 0) { printf( "ОТКАЗ ОСНАСТКИ Р5: поток 2 не сделал ни круга до переписи — полёта не было\n" ); return 2; }
        if (applied1 - applied0 == 0 && over1 - over0 == 0) {
            printf( "ОТКАЗ Р5: механизм не сработал ни разу в чужой среде\n" ); verdikt = 1;
        }
        free_all( v1, v2, reps );
    }

    if (otkazov) printf( "ВНИМАНИЕ: отказов исполнения=%zu\n", otkazov );
    printf( "итог: %s\n", verdikt ? "КРАСНЫЙ" : "ЗЕЛЁНЫЙ" );

    sreda_destroy( &s2, 0 );
    sreda_destroy( &s1, 1 );
    free( v1 ); free( v2 );
    return verdikt;
}
