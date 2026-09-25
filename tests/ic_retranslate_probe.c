/* MacRunner 07.09.2026, лейн ПОВТОРНЫЙ-ВЫПУСК — КЕШ КОСВЕННЫХ ПОСЛЕ ПОВТОРНОГО ПЕРЕВОДА.
 *
 * ЗАЧЕМ. Из трёх путей, снимающих запись кеша блоков, кеш косвенных переходов чистили ДВА:
 *     hb_jit_invalidate_guest_range -> hb_ic_slots_clear_all() при dropped
 *     smc_evict_entry               -> hb_ic_slots_clear_all() безусловно
 * а третий, повторный перевод того же гостевого адреса в block_cache_put, — НЕТ. Дефект
 * назван лейном СЦЕПЛЕНИЕ 06.09 и им же оставлен нетронутым. В слоте лежит СЫРОЙ нативный
 * адрес, арена только растёт и старое тело остаётся отображённым — значит косвенный переход
 * уходил бы в ПРЕЖНЮЮ версию блока. Это исполнение старого кода, а не потеря скорости.
 *
 * ДВЕ РУКИ, И ВТОРАЯ ОБЯЗАТЕЛЬНА.
 *     A  правка включена (умолчание)     -> после повторного перевода слот НЕ держит
 *                                           старый нативный адрес
 *     B  MACRUNNER_HB_TEST_NO_IC_CLEAR_ON_RETRANSLATE=1 (поведение ДО правки)
 *                                        -> слот старый адрес ДЕРЖИТ
 * Без руки B «слот чист» неотличимо от «слот и так не заполнялся», и правка не была бы
 * доказана ничем. Повозка сама отказывается судить, если до повторного перевода занятых
 * слотов НОЛЬ: тогда наблюдать нечего, и это отказ ОСНАСТКИ, а не зелёный результат.
 *
 * УСТРОЙСТВО. Блок кончается КОСВЕННЫМ переходом (`HB_IR_JMP` с регистровым операндом) —
 * только на таком завершителе кодогенератор ставит зонд кеша (emit_native_indirect_jmp,
 * hb_arm64_codegen.c). Повторный перевод создаётся вторым занесением ТОГО ЖЕ гостевого
 * адреса: block_cache_put уходит в ветвь «Update existing entry», ту самую.
 *
 * ГРАНИЦА, названная вслух: повозка доказывает, что СЛОТ ПЕРЕСТАЛ ДЕРЖАТЬ старый адрес.
 * Она НЕ доказывает отсутствие гонки «поток уже прочитал адрес до чистки» — эта гонка
 * описана в hb_codegen.h у hb_ic_slot_t, признана там же и правкой не закрывается.
 *
 * ПОЧЕМУ ПОВТОРНЫЙ ПЕРЕВОД СОЗДАЁТСЯ ВХОДОМ ПРИЁМКИ, А НЕ ПРОГОНОМ. Из диспетчера эта
 * ветвь недостижима по построению: занесение случается только после промаха поиска, а
 * промах означает, что живой записи с этим адресом нет. Достигают её другие занесения —
 * свёртки и помощники. Это не догадка: прибор hb-povtornyj-perevod даёт looked>0, hits=0
 * и у повозки лейна СЦЕПЛЕНИЕ (1024/0), и у повозки причин (448/0). Поэтому повозка зовёт
 * hb_test_povtornyj_perevod — ТУ ЖЕ block_cache_put с тем же адресом; синтетичен только
 * вызывающий, исполняемый код ветви настоящий.
 *
 * Сборка: make ic-retranslate-probe
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_codegen.h"
#include "hb_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GUEST_BASE 0x260000000ull
#define STRIDE     0x1000ull

/* ДВА блока. Слот кеша косвенных заполняется только когда промах попал в ЖИВУЮ,
 * сцепляемую запись кеша (update_indirect_ic, hb_runtime.c: проверяет valid,
 * native_code, block_terminal_is_chainable и наличие щели сцепления). Значит одного
 * блока с косвенным переходом мало — цель обязана быть переведена и лежать в кеше.
 *
 *   A  addr        mov rax,<addr+0x40>; jmp rax        <- КОСВЕННЫЙ, тут зонд кеша
 *   B  addr+0x40   mov rax,<metka>;     jmp addr+0x80  <- прямой выход из окна
 */
static hb_ir_func_t* make_indirect(uint64_t addr, uint64_t metka)
{
    hb_ir_func_t* func = hb_ir_func_create( addr, 0 );
    hb_ir_block_t *a, *b;
    hb_ir_builder_t* bld;
    hb_ir_instr_t* jmp;

    if (!func) return NULL;
    a = hb_ir_block_create( 0, addr );
    b = hb_ir_block_create( 1, addr + 0x40 );
    if (!a || !b) return NULL;
    hb_ir_cfg_add_block( func->cfg, a );
    hb_ir_cfg_add_block( func->cfg, b );
    hb_ir_cfg_add_edge( func->cfg, a, b );
    func->cfg->entry = a;

    bld = hb_ir_builder_create( func );
#define AT(i, ga, l) do { hb_ir_instr_t* _i = (i); if (_i) { _i->guest_addr = (ga); _i->guest_len = (l); } } while (0)
    hb_ir_builder_set_block( bld, a );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ),
                        hb_ir_imm( (int64_t)(addr + 0x40), HB_SIZE_64 ) ), addr, 10 );
    jmp = hb_ir_emit( bld, HB_IR_JMP );
    if (jmp) {
        jmp->src1 = hb_ir_reg( HB_REG_RAX, HB_SIZE_64 );   /* регистровый операнд = КОСВЕННЫЙ */
        jmp->guest_addr = addr + 10;
        jmp->guest_len = 2;
    }
    hb_ir_builder_set_block( bld, b );
    AT( hb_ir_emit_mov( bld, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ),
                        hb_ir_imm( (int64_t)metka, HB_SIZE_64 ) ), addr + 0x40, 10 );
    AT( hb_ir_emit_jmp( bld, addr + 0x80 ), addr + 0x4a, 5 );
#undef AT
    hb_ir_builder_destroy( bld );
    return func;
}

/* Гонит диспетчер по ctx->pc внутри окна одной функции: hb_jit_runtime_run исполняет
 * ОДИН блок и возвращается, а переход A->B возникает только у вызывающего. */
static int progon(hb_jit_runtime_t* rt, hb_context_t* ctx, hb_ir_func_t* func, uint64_t base)
{
    int hops;
    ctx->pc = base;
    for (hops = 0; hops < 8; hops++) {
        hb_exec_result_t out;
        hb_result_t r;
        memset( &out, 0, sizeof(out) );
        r = hb_jit_runtime_run( rt, func, &out );
        if (r != HB_OK || out.result != HB_OK) return 0;
        if (ctx->pc < base || ctx->pc >= base + 0x80) break;
    }
    return 1;
}

int main(int argc, char** argv)
{
    size_t reps = (argc > 1) ? (size_t)strtoull( argv[1], NULL, 0 ) : 32;
    size_t n;
    uint64_t zanyato_do, zanyato_posle;
    uint64_t vseh = 0, derzhat_staroe = 0;
    /* Тело-подстановка для повторного занесения: важно лишь что оно ДРУГОЕ. */
    static uint8_t telo[16];
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    const char* ic = getenv( "MACRUNNER_HB_INDIRECT_IC" );
    const char* control = getenv( "MACRUNNER_HB_TEST_NO_IC_CLEAR_ON_RETRANSLATE" );
    int control_on = control && *control && *control != '0';
    int ploho = 0;

    printf( "# ПОВТОРНЫЙ-ВЫПУСК: кеш косвенных после повторного перевода. функций=%zu\n", reps );
    printf( "# рука: %s\n", control_on
            ? "B — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ, гашение подавлено (поведение ДО правки)"
            : "A — правка включена (умолчание)" );
    if (!ic || !*ic || *ic == '0') {
        printf( "ОТКАЗ ОСНАСТКИ: нужен MACRUNNER_HB_INDIRECT_IC=1 — без него зонд кеша\n"
                "не выпускается вовсе, слоты пусты, и обе руки дали бы одинаковый ноль.\n" );
        return 2;
    }

    {
        const char* g = getenv( "MACRUNNER_HB_POVTOR_STATS" );
        if (!g || !*g || *g == '0') {
            printf( "ОТКАЗ ОСНАСТКИ: нужен MACRUNNER_HB_POVTOR_STATS=1 — вход приёмки\n"
                    "hb_test_povtornyj_perevod живёт только при нём.\n" );
            return 2;
        }
    }

    ctx = hb_context_create( HB_ARCH_X64, HB_BACKEND_JIT );
    if (!ctx) { printf( "ОТКАЗ ОСНАСТКИ: нет контекста\n" ); return 2; }
    if (!ctx->memory) ctx->memory = hb_memory_create( 0 );
    if (ctx->memory) {
        hb_memory_setup_stack( ctx->memory, 0x300000, 0x10000 );
        ctx->regs.x64.rsp = 0x2f8000;
    }
    ctx->step_limit = 0;
    ctx->block_limit = 0;
    rt = hb_jit_runtime_create( ctx );
    if (!rt) { printf( "ОТКАЗ ОСНАСТКИ: нет среды JIT\n" ); return 2; }

    /* ЭТАП 1: перевести и ИСПОЛНИТЬ — исполнение заполняет слот на промахе. */
    for (n = 0; n < reps; n++) {
        uint64_t base = GUEST_BASE + (uint64_t)n * STRIDE;
        hb_ir_func_t* f = make_indirect( base, 0x1111 );
        if (!f) { printf( "ОТКАЗ ОСНАСТКИ: граф не построен на %zu\n", n ); return 2; }
        /* ДВАЖДЫ: на первом проходе цель только заводится в кеше, слот пишется на
         * ВТОРОМ, когда промах уже находит живую запись. */
        progon( rt, ctx, f, base );
        progon( rt, ctx, f, base );
    }
    zanyato_do = hb_ic_slotov_zanyato();
    printf( "этап 1: занятых слотов=%llu\n", (unsigned long long)zanyato_do );
    if (!zanyato_do) {
        printf( "ОТКАЗ ОСНАСТКИ: до повторного перевода занятых слотов НОЛЬ — наблюдать\n"
                "нечего, и «чисто» после этого не значило бы ничего. Повозка не судит.\n" );
        return 2;
    }

    /* ЭТАП 2: ПОВТОРНЫЙ ПЕРЕВОД тех же адресов через вход приёмки. Прежний нативный
     * адрес возвращается — по нему и спрашиваем кеш косвенных. Тело подставляем своё:
     * его никто не исполняет, важно лишь что оно ДРУГОЕ. */
    for (n = 0; n < reps; n++) {
        /* Переводим заново ЦЕЛЬ перехода (блок B), а не блок A: слот кеша косвенных
         * держит нативный адрес ЦЕЛИ. Первая редакция повозки переводила заново A и
         * получила ноль в ОБЕИХ руках — ноль был правдой про блок, которого в слоте
         * нет. Ровно тот класс ошибки, ради которого рука B и существует: без неё
         * ноль руки A был бы принят за доказательство правки. */
        uint64_t base = GUEST_BASE + (uint64_t)n * STRIDE + 0x40;
        uint8_t* staroe = hb_test_povtornyj_perevod( rt, base, telo, sizeof(telo) );
        if (!staroe) continue;
        vseh++;
        /* +16: в слоте лежит НЕ начало тела, а точка ПОСЛЕ пролога — так его пишет
         * update_indirect_ic (`target->native_code + 16`). Спрашивать про голое начало
         * значило бы получать честный ноль про адрес, которого в слоте не бывает. */
        if (hb_ic_slot_derzhit_native( (uint64_t)(uintptr_t)staroe + 16 )) derzhat_staroe++;
    }
    zanyato_posle = hb_ic_slotov_zanyato();
    printf( "этап 2: повторно переведено=%llu, слотов держат СТАРОЕ тело=%llu, занято=%llu\n",
            (unsigned long long)vseh, (unsigned long long)derzhat_staroe,
            (unsigned long long)zanyato_posle );

    if (!vseh) {
        printf( "ОТКАЗ ОСНАСТКИ: повторный перевод не состоялся НИ РАЗУ — судить нечего.\n"
                "(нужен MACRUNNER_HB_POVTOR_STATS=1: вход приёмки живёт только при нём)\n" );
        return 2;
    }

    /* Суд по САМОМУ ПРЕДМЕТУ: держит ли кеш сырой указатель на прежнее тело.
     *   A (правка)  -> обязан быть НОЛЬ
     *   B (контроль)-> обязан быть НЕ ноль, иначе повозка не умеет увидеть дефект и
     *                  ноль руки A ничего не стоит. */
    if (control_on) {
        if (!derzhat_staroe) {
            printf( "ОТКАЗ: рука B (гашение подавлено) не нашла НИ ОДНОГО слота со старым\n"
                    "телом. Значит повозка дефект увидеть не может, и ноль руки A пуст.\n" );
            ploho = 1;
        } else {
            printf( "рука B: %llu из %llu слотов держат СТАРОЕ тело — дефект воспроизведён,\n"
                    "прибор способен его увидеть\n",
                    (unsigned long long)derzhat_staroe, (unsigned long long)vseh );
        }
    } else {
        if (derzhat_staroe) {
            printf( "ОТКАЗ: рука A оставила %llu слотов со старым телом из %llu повторных\n"
                    "переводов — гашение на этом пути НЕ работает\n",
                    (unsigned long long)derzhat_staroe, (unsigned long long)vseh );
            ploho = 1;
        } else {
            printf( "рука A: ноль слотов со старым телом при %llu повторных переводах —\n"
                    "гашение работает\n", (unsigned long long)vseh );
        }
    }

    printf( "ВЕРДИКТ: %s\n", ploho ? "ОТКАЗ" : "ВЕРНО" );
    return ploho ? 1 : 0;
}
