/* MacRunner 2026-08-16, лейн ДИСПЕТЧ, итерация 3 — ПОВОЗКА ДЛЯ ПЕРВОГО УРОВНЯ.
 *
 * Зачем понадобилась. Правку первого уровня поиска (гейт `MACRUNNER_HB_L1_CACHE`) сначала
 * проверял штатным набором `hb_test_runner`. Он для этого НЕ ГОДИТСЯ, и это измерено:
 * набор заводит сотни крошечных сред по ОДНОМУ-ДВУМ обращениям к кешу каждая, попаданий в
 * первый уровень не возникает вовсе, и сверка не срабатывает ни разу. Проба, в которой
 * искомое событие не происходило, вердикта не даёт — ни за, ни против.
 *
 * Здесь повозка делает ровно то, чего не хватало: K различных блоков, N обращений по кругу.
 * Меняя K, получаем долю попаданий как ФУНКЦИЮ рабочего множества — а порог окупаемости
 * первого уровня уже посчитан (45.2 %, итерация 2: 1786 пс против 3947 пс), и по этой
 * таблице сразу видно, при каком рабочем множестве правка перестаёт окупаться.
 *
 * Что НЕ измеряется: настоящее распределение обращений живой игры. Здесь круговой обход,
 * то есть худший случай для прямого кеша — никакой временно́й близости, кроме периода. Число
 * из этой повозки — НИЖНЯЯ оценка доли попаданий, и так его и надо читать.
 *
 * Сборка:
 *   cd engine/hyperbridge
 *   /usr/bin/clang -O2 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/dispatch_l1_stress.c libhyperbridge.a -o tests/dispatch_l1_stress
 *   ./tests/dispatch_l1_stress [блоков] [обращений]
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_codegen.h"
#include "hb_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Один блок на гостевом адресе addr: mov rax, imm; ret. Тело намеренно тривиально — мерится
 * ПОИСК блока, а не исполнение; чем короче тело, тем большую долю занимает измеряемое. */
/* ВТОРОЙ ВИД БЛОКА — со СЛИЯНИЕМ. Нужен потому, что самопроверка карты возврата (итерация 5)
 * прошла 77 824 смещения без расхождений, но счётчик блоков со слиянием остался НУЛЁМ, то есть
 * про свою главную опасность она не сказала ничего.
 *
 * Образец взят не наугад, а из кода: `emit_xfg_dispatch_call_pair` (hb_arm64_codegen.c:13570)
 * сливает ДВЕ команды и требует ровно этого:
 *     MOV r10 (64 бита, imm)   и следом   CALL с непустым src1,
 *     причём guest_addr+guest_len первой обязан совпасть с guest_addr второй.
 * После слияния номер записи карты отстаёт от номера команды — это и есть проверяемое место. */
static hb_ir_func_t* make_fused_block(uint64_t addr, uint64_t value)
{
    hb_ir_func_t* func = hb_ir_func_create( addr, 0 );
    hb_ir_block_t* blk = hb_ir_block_create( 0, addr );
    hb_ir_builder_t* b;
    hb_ir_instr_t *m, *c, *j;

    if (!func || !blk) return NULL;
    hb_ir_cfg_add_block( func->cfg, blk );
    func->cfg->entry = blk;

    b = hb_ir_builder_create( func );
    hb_ir_builder_set_block( b, blk );
    m = hb_ir_emit_mov( b, hb_ir_reg( HB_REG_R10, HB_SIZE_64 ), hb_ir_imm( value, HB_SIZE_64 ) );
    if (m) { m->guest_addr = addr; m->guest_len = 4; }
    c = hb_ir_emit_call( b, addr + 48 );
    if (c) {
        c->guest_addr = addr + 4; c->guest_len = 5;
        /* `hb_ir_emit_call` ставит `src1 = none`, а слияние требует НЕПУСТОЙ (условие
         * `call->src1.type == HB_OP_NONE` отвергает пару). Из-за этого окно не открывалось,
         * сколько бы блоков повозка ни строила. */
        c->src1 = hb_ir_imm( addr + 48, HB_SIZE_64 );
    }
    /* Команда ПОСЛЕ слитой пары — без неё расхождение номеров не проявится: слияние съедает
     * команду, и все последующие записи карты получают номер на единицу больше своего
     * порядкового. Если после пары ничего нет, сдвигаться нечему. */
    hb_ir_emit_mov( b, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( value, HB_SIZE_64 ) );
    j = hb_ir_emit_jmp( b, addr + 32 );
    if (j) { j->guest_addr = addr + 9; j->guest_len = 2; }
    hb_ir_builder_destroy( b );
    return func;
}

static hb_ir_func_t* make_block(uint64_t addr, uint64_t value, char kind)
{
    hb_ir_func_t* func = hb_ir_func_create( addr, 0 );
    hb_ir_block_t* blk = hb_ir_block_create( 0, addr );
    hb_ir_builder_t* b;

    if (!func || !blk) return NULL;
    hb_ir_cfg_add_block( func->cfg, blk );
    func->cfg->entry = blk;

    b = hb_ir_builder_create( func );
    hb_ir_builder_set_block( b, blk );
    hb_ir_emit_mov( b, hb_ir_reg( HB_REG_RAX, HB_SIZE_64 ), hb_ir_imm( value, HB_SIZE_64 ) );
    /* Пара CMP+Jcc здесь СНЯТА. Она добавлялась в итерации 6 ради слияния (оно всё равно не
     * сработало), а классификатору завершителей мешала насмерть: `Jcc` — передача управления
     * НЕ последней командой, поэтому `term_slot_of` относил блок к `xfer_mid`, и все три вида
     * завершителя давали одну и ту же строку (замер: 40 959 обращений, 97.19 %, одинаково для
     * прямого перехода, возврата и непрямого). Теперь завершитель в блоке единственный. */
    /* Завершитель выбирается видом блока — наряд, пункт 4: доля попаданий нужна ОТДЕЛЬНО
     * для возвратов и непрямых переходов, а не общая. */
    switch (kind) {
    case 'r':  hb_ir_emit_ret( b ); break;                       /* возврат */
    case 'i': {                                                   /* непрямой переход */
        hb_ir_instr_t* j = hb_ir_emit_jmp( b, addr + 32 );
        if (j) j->src1 = hb_ir_reg( HB_REG_RAX, HB_SIZE_64 );     /* src1 непуст => jmp_ind */
        break;
    }
    default:   hb_ir_emit_jmp( b, addr + 32 ); break;             /* прямой переход */
    }
    hb_ir_builder_destroy( b );
    return func;
}

int main(int argc, char** argv)
{
    size_t blocks = (argc > 1) ? (size_t)strtoull( argv[1], NULL, 0 ) : 1024;
    size_t rounds = (argc > 2) ? (size_t)strtoull( argv[2], NULL, 0 ) : 200;
    int fused = (argc > 3 && argv[3][0] == 'f');   /* третий довод "f" — блоки со слиянием */
    char kind = (argc > 3) ? argv[3][0] : 'j';     /* 'j' прямой переход, 'r' возврат, 'i' непрямой */
    hb_ir_func_t** funcs;
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    size_t i, r, ok = 0, bad = 0;
    uint64_t t0, dt;

    printf( "# ДИСПЕТЧ, нагрузка на первый уровень: блоков=%zu обходов=%zu (обращений=%zu)\n",
            blocks, rounds, blocks * rounds );
    printf( "# вид блока: %s\n", fused ? "СО СЛИЯНИЕМ (MOV r10 + CALL)" : "простой" );
    printf( "# гейт MACRUNNER_HB_L1_CACHE=%s  сверка MACRUNNER_HB_L1_VERIFY=%s\n",
            getenv( "MACRUNNER_HB_L1_CACHE" ) ? getenv( "MACRUNNER_HB_L1_CACHE" ) : "(умолчание=1)",
            getenv( "MACRUNNER_HB_L1_VERIFY" ) ? getenv( "MACRUNNER_HB_L1_VERIFY" ) : "(умолчание=0)" );

    funcs = calloc( blocks, sizeof(*funcs) );
    if (!funcs) { printf( "ОТКАЗ ОСНАСТКИ: нет памяти под %zu блоков\n", blocks ); return 2; }

    /* Адреса разносим на 64 байта: медиана гостевого блока 16 байт (замер корпуса, итерация 2),
     * а хеш первого уровня сдвигает адрес на 4 — при шаге 16 слоты шли бы подряд, и раскладка
     * вышла бы искусственно идеальной. */
    for (i = 0; i < blocks; i++) {
        funcs[i] = fused ? make_fused_block( 0x100000 + i * 64, i )
                         : make_block( 0x100000 + i * 64, i, kind );
        if (!funcs[i]) { printf( "ОТКАЗ ОСНАСТКИ: не построен блок %zu\n", i ); return 2; }
    }

    ctx = hb_context_create( HB_ARCH_X64, HB_BACKEND_JIT );
    if (!ctx) { printf( "ОТКАЗ ОСНАСТКИ: нет контекста\n" ); return 2; }
    /* Стек обязателен: блок кончается `ret`, а без стека каждый блок отказывает по чтению,
     * и повозка мерила бы путь отказа вместо поиска в кеше (поймано первым прогоном:
     * `helper-fault-addr ... last_result=-8` на каждом блоке). */
    /* `hb_context_create` память НЕ заводит — проверено, `ctx->memory` пуст, и каждый блок
     * отказывал с `JIT helper fault`. Заводим сами: это вызов публичного API лейна ПАМЯТЬ,
     * их файлы не трогаются. */
    if (!ctx->memory) ctx->memory = hb_memory_create( 0 );
    printf( "# память контекста: %s\n", ctx->memory ? "есть" : "НЕТ" );
    if (ctx->memory) {
        printf( "# setup_stack вернул %d\n",
                (int)hb_memory_setup_stack( ctx->memory, 0x200000, 0x10000 ) );
        ctx->regs.x64.rsp = 0x1f8000;   /* СЕРЕДИНА области, а не её нижняя граница */
    }

    /* ОДНА среда на весь прогон. `hb_runtime_run` заводит СВОЮ среду на каждый вызов, и первая
     * редакция повозки из-за этого печатала «обращений=2» на каждом блоке: кеш умирал раньше,
     * чем в нём успевало что-то накопиться. Именно эта ошибка делала штатный набор негодным
     * для проверки первого уровня — повозка повторила её в точности. */
    rt = hb_jit_runtime_create( ctx );
    if (!rt) { printf( "ОТКАЗ ОСНАСТКИ: нет среды JIT\n" ); return 2; }

    t0 = now_ns();
    for (r = 0; r < rounds; r++) {
        for (i = 0; i < blocks; i++) {
            hb_exec_result_t out;
            memset( &out, 0, sizeof(out) );
            ctx->pc = 0x100000 + i * 64;
            hb_result_t rr = hb_jit_runtime_run( rt, funcs[i], &out );
            if (rr == HB_OK && out.result == HB_OK) ok++;
            else {
                if (!bad)
                    printf( "ПЕРВЫЙ ОТКАЗ: rr=%d out.result=%d faulted=%d причина=%s pc=0x%llx\n",
                            (int)rr, (int)out.result, (int)out.faulted,
                            out.fault_reason ? out.fault_reason : "(нет)",
                            (unsigned long long)ctx->pc );
                bad++;
            }
        }
    }
    dt = now_ns() - t0;

    printf( "исполнено успешно  %zu\n", ok );
    printf( "отказов исполнения %zu\n", bad );
    if (ok + bad)
        printf( "время на обращение %llu пс\n",
                (unsigned long long)( dt * 1000ull / (uint64_t)(ok + bad) ) );
    /* ★ Строка ниже — не украшение. Повозка, в которой ничего не исполнилось, напечатала бы
     * красивые нули по доле попаданий, и их можно было бы принять за измерение. */
    if (!ok) printf( "ВЕРДИКТА НЕТ: не исполнилось НИ ОДНОГО блока, доля попаданий недействительна\n" );

    hb_jit_runtime_destroy( rt );
    hb_context_destroy( ctx );
    for (i = 0; i < blocks; i++) hb_ir_func_destroy( funcs[i] );
    free( funcs );
    return bad ? 1 : 0;
}
