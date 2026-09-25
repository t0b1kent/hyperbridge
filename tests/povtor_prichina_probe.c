/* MacRunner 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ПЕРЕПИСИ ПРИЧИН.
 *
 * ЗАЧЕМ. Прибор `hb-povtor-prichina` раскладывает каждое занесение блока в кеш по
 * четырём корзинам (первый / сброс / выселение / чужой кеш). Число, вышедшее из такого
 * прибора, стоит ровно столько, сколько стоит доказательство, что прибор УМЕЕТ показать
 * ноль там, где явления нет. За 04–06.09 проект поймал шестнадцать приборов, у которых
 * этого доказательства не было; все они врали одинаково — нулём, означавшим «не смотрел».
 *
 * ЧТО ЗДЕСЬ. Четыре руки, каждая создаёт РОВНО ОДНУ причину. Приёмка руки двойная:
 *     своя корзина  выросла ровно на ожидаемое число
 *     ТРИ ЧУЖИЕ     не выросли ВОВСЕ
 * Второе важнее первого: корзина, растущая заодно с соседней, делает всю раскладку
 * бессмысленной, а по одной лишь своей корзине это не видно.
 *
 * У каждой руки СВОЙ диапазон гостевых адресов: перепись глобальная и живёт весь
 * процесс, поэтому пересечение диапазонов сделало бы «первый» одной руки «повтором»
 * следующей — и приёмка ловила бы собственную оснастку, а не прибор.
 *
 * РУКИ:
 *   1 ПЕРВЫЙ     N различных адресов, один кеш, без сбросов и выселений
 *   2 СБРОС      адрес -> hb_jit_runtime_reset -> тот же адрес
 *   3 ВЫСЕЛЕНИЕ  адрес -> hb_jit_invalidate_guest_range по нему -> тот же адрес
 *   4 ЧУЖОЙ      адрес в кеше A -> тот же адрес в кеше B (вторая среда)
 *
 * ГРАНИЦА ЭТОЙ ПОВОЗКИ, названная вслух: она доказывает, что РАЗЛИЧЕНИЕ работает, и
 * НЕ доказывает, что на мишени встречаются все четыре причины. Доли на мишени — дело
 * прогона, а не стенда.
 *
 * Сборка: make povtor-probe
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Диапазоны рук разнесены на 1 ГБ — с запасом от любого шага внутри руки. */
#define BASE_PERVYJ    0x150000000ull
#define BASE_SBROS     0x190000000ull
#define BASE_VYSELENIE 0x1d0000000ull
#define BASE_CHUZHOJ   0x210000000ull
#define STRIDE         0x1000ull

static const char* const imena[HB_POVTOR_K_N] = {
#define HB_POVTOR_NAME_ITEM(imya, podpis) podpis,
    HB_POVTOR_KORZINY(HB_POVTOR_NAME_ITEM)
#undef HB_POVTOR_NAME_ITEM
};

/* Один блок на функцию: повозке нужен факт ЗАНЕСЕНИЯ в кеш, а не форма графа. */
static hb_ir_func_t* make_one(uint64_t addr)
{
    hb_ir_func_t* func = hb_ir_func_create( addr, 0 );
    hb_ir_block_t* a;
    hb_ir_builder_t* bld;

    if (!func) return NULL;
    a = hb_ir_block_create( 0, addr );
    if (!a) return NULL;
    hb_ir_cfg_add_block( func->cfg, a );
    func->cfg->entry = a;

    bld = hb_ir_builder_create( func );
#define AT(i, ga, l) do { hb_ir_instr_t* _i = (i); if (_i) { _i->guest_addr = (ga); _i->guest_len = (l); } } while (0)
    hb_ir_builder_set_block( bld, a );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( 7, HB_SIZE_64 ) ), addr, 5 );
    AT( hb_ir_emit_jmp( bld, addr + 64 ), addr + 5, 5 );
#undef AT
    hb_ir_builder_destroy( bld );
    return func;
}

static int progon(hb_jit_runtime_t* rt, hb_context_t* ctx, hb_ir_func_t* func, uint64_t base)
{
    hb_exec_result_t out;
    hb_result_t r;
    memset( &out, 0, sizeof(out) );
    ctx->pc = base;
    r = hb_jit_runtime_run( rt, func, &out );
    return (r == HB_OK && out.result == HB_OK);
}

static void snimok(uint64_t* v)
{
    int k;
    for (k = 0; k < HB_POVTOR_K_N; k++) v[k] = hb_povtor_korzina( k );
}

/* Приёмка одной руки. Возвращает 0 при успехе. Печатает ВСЕ четыре дельты всегда —
 * нулевая чужая корзина есть часть результата, а не её отсутствие. */
static int sudit(const char* ruka, const uint64_t* do_, const uint64_t* posle,
                 int svoya, uint64_t zhdem)
{
    uint64_t d[HB_POVTOR_K_N];
    int k, ploho = 0;

    for (k = 0; k < HB_POVTOR_K_N; k++) d[k] = posle[k] - do_[k];
    printf( "рука %-10s: ", ruka );
    for (k = 0; k < HB_POVTOR_K_N; k++)
        printf( "%s%s=%llu", k ? " " : "", imena[k], (unsigned long long)d[k] );
    printf( "  (ожидали %s=%llu, прочие=0)\n", imena[svoya], (unsigned long long)zhdem );

    if (d[svoya] != zhdem) {
        printf( "  ОТКАЗ: своя корзина %s дала %llu вместо %llu\n",
                imena[svoya], (unsigned long long)d[svoya], (unsigned long long)zhdem );
        ploho = 1;
    }
    for (k = 0; k < HB_POVTOR_K_N; k++) {
        if (k == svoya || !d[k]) continue;
        printf( "  ОТКАЗ: чужая корзина %s выросла на %llu — корзины НЕ различаются\n",
                imena[k], (unsigned long long)d[k] );
        ploho = 1;
    }
    return ploho;
}

static hb_context_t* sdelat_ctx(void)
{
    hb_context_t* ctx = hb_context_create( HB_ARCH_X64, HB_BACKEND_JIT );
    if (!ctx) return NULL;
    if (!ctx->memory) ctx->memory = hb_memory_create( 0 );
    if (ctx->memory) {
        hb_memory_setup_stack( ctx->memory, 0x300000, 0x10000 );
        ctx->regs.x64.rsp = 0x2f8000;
    }
    ctx->step_limit = 0;
    ctx->block_limit = 0;
    return ctx;
}

int main(int argc, char** argv)
{
    size_t reps = (argc > 1) ? (size_t)strtoull( argv[1], NULL, 0 ) : 64;
    size_t n;
    int plohih = 0;
    uint64_t a[HB_POVTOR_K_N], b[HB_POVTOR_K_N];
    hb_context_t *ctx, *ctx2;
    hb_jit_runtime_t *rt, *rt2;
    const char* gejt = getenv( "MACRUNNER_HB_POVTOR_STATS" );

    printf( "# ПОВТОРНЫЙ-ВЫПУСК: отрицательный контроль переписи причин. функций=%zu\n", reps );
    printf( "# гейт MACRUNNER_HB_POVTOR_STATS=%s\n", (gejt && *gejt) ? gejt : "(не задан)" );
    if (!gejt || !*gejt || *gejt == '0') {
        printf( "ОТКАЗ ОСНАСТКИ: без MACRUNNER_HB_POVTOR_STATS=1 перепись не ведётся,\n"
                "и все корзины дадут ноль — что неотличимо от исправного прибора.\n" );
        return 2;
    }

    ctx = sdelat_ctx();
    if (!ctx) { printf( "ОТКАЗ ОСНАСТКИ: нет контекста\n" ); return 2; }
    rt = hb_jit_runtime_create( ctx );
    if (!rt) { printf( "ОТКАЗ ОСНАСТКИ: нет среды JIT\n" ); return 2; }

    /* ── РУКА 1: ПЕРВЫЙ ───────────────────────────────────────────────────────── */
    snimok( a );
    for (n = 0; n < reps; n++) {
        uint64_t base = BASE_PERVYJ + (uint64_t)n * STRIDE;
        hb_ir_func_t* f = make_one( base );
        if (!f || !progon( rt, ctx, f, base )) { printf( "ОТКАЗ ОСНАСТКИ: рука 1 на %zu\n", n ); return 2; }
    }
    snimok( b );
    plohih += sudit( "ПЕРВЫЙ", a, b, HB_POVTOR_K_PERVYJ, (uint64_t)reps );

    /* ── РУКА 2: СБРОС ────────────────────────────────────────────────────────── */
    /* Прогреть адреса, затем сбросить среду и прогнать их снова. Первый проход даёт
     * «первый» и в счёт руки не идёт — снимок берётся ПОСЛЕ него. */
    for (n = 0; n < reps; n++) {
        uint64_t base = BASE_SBROS + (uint64_t)n * STRIDE;
        hb_ir_func_t* f = make_one( base );
        if (!f || !progon( rt, ctx, f, base )) { printf( "ОТКАЗ ОСНАСТКИ: рука 2 прогрев %zu\n", n ); return 2; }
    }
    snimok( a );
    hb_jit_runtime_reset( rt, ctx );
    for (n = 0; n < reps; n++) {
        uint64_t base = BASE_SBROS + (uint64_t)n * STRIDE;
        hb_ir_func_t* f = make_one( base );
        if (!f || !progon( rt, ctx, f, base )) { printf( "ОТКАЗ ОСНАСТКИ: рука 2 повтор %zu\n", n ); return 2; }
    }
    snimok( b );
    plohih += sudit( "СБРОС", a, b, HB_POVTOR_K_SBROS, (uint64_t)reps );

    /* ── РУКА 3: ВЫСЕЛЕНИЕ ────────────────────────────────────────────────────── */
    for (n = 0; n < reps; n++) {
        uint64_t base = BASE_VYSELENIE + (uint64_t)n * STRIDE;
        hb_ir_func_t* f = make_one( base );
        if (!f || !progon( rt, ctx, f, base )) { printf( "ОТКАЗ ОСНАСТКИ: рука 3 прогрев %zu\n", n ); return 2; }
    }
    snimok( a );
    for (n = 0; n < reps; n++) {
        uint64_t base = BASE_VYSELENIE + (uint64_t)n * STRIDE;
        hb_ir_func_t* f;
        if (!hb_jit_invalidate_guest_range( rt, base, 16 )) {
            printf( "ОТКАЗ ОСНАСТКИ: рука 3 — выселение не сняло записи на %zu\n", n );
            return 2;
        }
        f = make_one( base );
        if (!f || !progon( rt, ctx, f, base )) { printf( "ОТКАЗ ОСНАСТКИ: рука 3 повтор %zu\n", n ); return 2; }
    }
    snimok( b );
    plohih += sudit( "ВЫСЕЛЕНИЕ", a, b, HB_POVTOR_K_VYSELENIE, (uint64_t)reps );

    /* ── РУКА 4: ЧУЖОЙ КЕШ ────────────────────────────────────────────────────── */
    for (n = 0; n < reps; n++) {
        uint64_t base = BASE_CHUZHOJ + (uint64_t)n * STRIDE;
        hb_ir_func_t* f = make_one( base );
        if (!f || !progon( rt, ctx, f, base )) { printf( "ОТКАЗ ОСНАСТКИ: рука 4 прогрев %zu\n", n ); return 2; }
    }
    ctx2 = sdelat_ctx();
    if (!ctx2) { printf( "ОТКАЗ ОСНАСТКИ: нет второго контекста\n" ); return 2; }
    rt2 = hb_jit_runtime_create( ctx2 );
    if (!rt2) { printf( "ОТКАЗ ОСНАСТКИ: нет второй среды JIT\n" ); return 2; }
    snimok( a );
    for (n = 0; n < reps; n++) {
        uint64_t base = BASE_CHUZHOJ + (uint64_t)n * STRIDE;
        hb_ir_func_t* f = make_one( base );
        if (!f || !progon( rt2, ctx2, f, base )) { printf( "ОТКАЗ ОСНАСТКИ: рука 4 второй кеш %zu\n", n ); return 2; }
    }
    snimok( b );
    plohih += sudit( "ЧУЖОЙ", a, b, HB_POVTOR_K_CHUZHOJ, (uint64_t)reps );

    printf( "сбросов=%llu снесено_записей=%llu\n",
            (unsigned long long)hb_povtor_sbrosov(),
            (unsigned long long)hb_povtor_sneseno() );
    hb_povtor_itog_print( "povozka" );

    printf( "ВЕРДИКТ: %s (провалившихся рук=%d из 4)\n",
            plohih ? "ПРИБОР НЕ РАЗЛИЧАЕТ ПРИЧИНЫ" : "ВЕРНО — четыре причины различаются",
            plohih );
    return plohih ? 1 : 0;
}
