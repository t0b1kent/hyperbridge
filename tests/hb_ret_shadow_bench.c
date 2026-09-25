/* ═══ СТЕНД ТЕНЕВОГО СТЕКА ВОЗВРАТОВ ═══════════════════════════════════════════
 *
 * ЧТО МЕРЯЕТ И ПОЧЕМУ ИМЕННО ЭТО. Возврат гостя без теневого стека заканчивает ВЕСЬ
 * вызов `hb_jit_runtime_run`: диспетчер видит завершитель RET, считает
 * `t_runexit[RUNEXIT_RET]` и уходит наружу. В движке снаружи стоит цикл wow64, и один
 * такой выход стоит порядка 65 нс (обнуление кадра, снимок контекста, sigsetjmp).
 * Здесь снаружи стоит пустой цикл, поэтому ВРЕМЯ тут занижает выигрыш — и потому
 * главная мера стенда не время, а ЧИСЛО ВЫХОДОВ из диспетчера: величина структурная,
 * от цены обвязки не зависящая и переносимая на живой прогон умножением на цену выхода.
 *
 * Гостевая программа — цикл из вызова и возврата, три блока в ОДНОЙ функции:
 *     L: call F        (адрес возврата R)
 *     R: sub ecx,1 ; jnz L
 *     F: ret
 * Прогон кончается, когда ecx дошёл до нуля и провал `jnz` уводит на адрес без блока.
 *
 * ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ВСТРОЕН: та же программа гоняется дважды, с гейтом и без, в
 * одном процессе. Совпадение обеих контрольных величин (число итераций и конечный ecx)
 * доказывает, что руки считали одно и то же; расхождение делает числа недействительными.
 *
 * ПОТОЛОК ИТЕРАЦИЙ — 2 500 000, И ЭТО НЕ ПРИДИРКА КОНТРОЛЯ, А НАСТОЯЩЕЕ РАЗЛИЧИЕ.
 * Один оборот цикла — четыре шага гостя, а умолчание предела шагов для x86 —
 * 10 000 000. БЕЗ приёма каждый возврат заканчивает `hb_jit_runtime_run`, и местный
 * счётчик шагов начинается заново, поэтому предел не срабатывает НИКОГДА. С приёмом
 * прогон остаётся внутри диспетчера, и предел наконец действует — ровно так же, как
 * это случилось со сцеплением блоков. Для движка это не отказ, а ритм (предел выражен
 * сроком в шкале ctx->step_count, внешний цикл спокойно входит снова), но для стенда
 * это разные объёмы работы, и контроль обязан такие числа отвергать. Отсюда
 * умолчание 2 000 000: 8 млн шагов, запас до предела.
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

/* Внутренние счётчики выходов доступны наружу этой дверью (hb_runtime.c). */
void hb_runtime_runexit_snapshot(unsigned long long* ret_exits, unsigned long long* total);

#define BAZA      0x00400000u
#define STACK_PG  0x0140f000u
#define STACK_TOP 0x0140fb68u

static hb_ir_func_t* postroit(void) {
    hb_ir_func_t* f = hb_ir_func_create(BAZA + 0x1000, 0);
    hb_ir_block_t *l, *r, *fn;
    hb_ir_builder_t* b;
    hb_ir_instr_t* in;
    if (!f) return NULL;

    l  = hb_ir_block_create(0, BAZA + 0x1000);
    r  = hb_ir_block_create(0, BAZA + 0x1005);
    fn = hb_ir_block_create(0, BAZA + 0x2000);
    if (!l || !r || !fn) return NULL;
    hb_ir_cfg_add_block(f->cfg, l);
    hb_ir_cfg_add_block(f->cfg, r);
    hb_ir_cfg_add_block(f->cfg, fn);
    f->cfg->entry = l;

    b = hb_ir_builder_create(f);
    hb_ir_builder_set_block(b, l);
    in = hb_ir_emit_call(b, BAZA + 0x2000);
    in->guest_addr = BAZA + 0x1000; in->guest_len = 5;
    hb_ir_builder_destroy(b);

    b = hb_ir_builder_create(f);
    hb_ir_builder_set_block(b, r);
    in = hb_ir_emit_binop(b, HB_IR_SUB, hb_ir_reg(HB_REG_RCX, HB_SIZE_32),
                          hb_ir_reg(HB_REG_RCX, HB_SIZE_32), hb_ir_imm(1, HB_SIZE_32));
    in->guest_addr = BAZA + 0x1005; in->guest_len = 3;
    in = hb_ir_emit_jcc(b, HB_CC_NE, BAZA + 0x1000);
    in->guest_addr = BAZA + 0x1008; in->guest_len = 2;
    hb_ir_builder_destroy(b);

    b = hb_ir_builder_create(f);
    hb_ir_builder_set_block(b, fn);
    in = hb_ir_emit_ret(b);
    in->guest_addr = BAZA + 0x2000; in->guest_len = 1;
    hb_ir_builder_destroy(b);
    return f;
}

struct itog {
    double sec;
    unsigned long long vhodov;      /* вызовов hb_jit_runtime_run — они же выходы наружу */
    unsigned long long ret_exits;   /* из них по завершителю RET */
    unsigned long long hit, miss, reset;
    unsigned int ecx_konec;
    int armed;
};

static struct itog progon(unsigned int n) {
    struct itog r;
    hb_ir_func_t* f = postroit();
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    hb_exec_result_t out;
    unsigned long long re0 = 0, tot0 = 0, re1 = 0, tot1 = 0;
    double t0;

    memset(&r, 0, sizeof(r));
    if (!f) { fprintf(stderr, "ne postroilos\n"); exit(2); }

    ctx = hb_context_create(HB_ARCH_X86, HB_BACKEND_JIT);
    ctx->memory = hb_memory_create(0);
    hb_memory_guest32_map(ctx->memory, STACK_PG, 4096, HB_PERM_READ | HB_PERM_WRITE);
    r.armed = ctx->ret_shadow_armed ? 1 : 0;
    rt = hb_jit_runtime_create(ctx);

    ctx->pc = BAZA + 0x1000;
    ctx->regs.x86.esp = STACK_TOP;
    ctx->regs.x86.ecx = n;

    hb_runtime_runexit_snapshot(&re0, &tot0);
    t0 = now_s();
    while (ctx->pc != BAZA + 0x100a) {
        if (hb_jit_runtime_run(rt, f, &out) != HB_OK) break;
        r.vhodov++;
        if (out.result != HB_OK) break;
        if (r.vhodov > 200000000ull) break;      /* сторож от зависания стенда */
    }
    r.sec = now_s() - t0;
    hb_runtime_runexit_snapshot(&re1, &tot1);
    r.ret_exits = re1 - re0;
    r.hit = ctx->ret_shadow_hit;
    r.miss = ctx->ret_shadow_miss;
    r.reset = ctx->ret_shadow_reset;
    r.ecx_konec = ctx->regs.x86.ecx;

    hb_jit_runtime_destroy(rt);
    hb_context_destroy(ctx);
    hb_ir_func_destroy(f);
    return r;
}

int main(int argc, char** argv) {
    unsigned int n = (argc > 1) ? (unsigned)atoi(argv[1]) : 2000000u;
    struct itog vykl, vkl;

    /* ПОРЯДОК РУК — ПЕРЕКЛЮЧАЕМЫЙ. Вторая рука в одном процессе идёт по прогретым
     * страницам и прогретой таблице гейтов, то есть порядок сам по себе даёт сдвиг.
     * Второй аргумент `obratno` меняет руки местами: совпадение выводов при обоих
     * порядках и есть проверка, что мерили механизм, а не разогрев. */
    if (argc > 2 && strcmp(argv[2], "obratno") == 0) {
        setenv("MACRUNNER_HB_RET_SHADOW", "1", 1);
        hb_arm64_codegen_gate_cache_reset();
        vkl = progon(n);
        setenv("MACRUNNER_HB_RET_SHADOW", "0", 1);
        hb_arm64_codegen_gate_cache_reset();
        vykl = progon(n);
    } else {
        setenv("MACRUNNER_HB_RET_SHADOW", "0", 1);
        hb_arm64_codegen_gate_cache_reset();
        vykl = progon(n);
        setenv("MACRUNNER_HB_RET_SHADOW", "1", 1);
        hb_arm64_codegen_gate_cache_reset();
        vkl = progon(n);
    }

    printf("STAND-RETSHADOW itog=%u\n", n);
    printf("%-10s %10s %12s %12s %10s %10s %10s %6s\n",
           "ruka", "sek", "vhodov", "ret_exits", "hit", "miss", "reset", "armed");
    printf("%-10s %10.4f %12llu %12llu %10llu %10llu %10llu %6d\n", "VYKL",
           vykl.sec, vykl.vhodov, vykl.ret_exits, vykl.hit, vykl.miss, vykl.reset, vykl.armed);
    printf("%-10s %10.4f %12llu %12llu %10llu %10llu %10llu %6d\n", "VKL",
           vkl.sec, vkl.vhodov, vkl.ret_exits, vkl.hit, vkl.miss, vkl.reset, vkl.armed);

    /* КОНТРОЛЬ: обе руки обязаны выполнить ОДНУ И ТУ ЖЕ работу. */
    if (vykl.ecx_konec != vkl.ecx_konec || vykl.ecx_konec != 0) {
        printf("KONTROL VERDIKT=NEGODEN ecx vykl=%u vkl=%u "
               "(veroyatno predel shagov: 4 shaga na oborot protiv step_limit)\n",
               vykl.ecx_konec, vkl.ecx_konec);
        return 1;
    }
    if (!vkl.armed || vykl.armed) {
        printf("KONTROL VERDIKT=NEGODEN gejt ne dejstvuet vykl.armed=%d vkl.armed=%d\n",
               vykl.armed, vkl.armed);
        return 1;
    }
    printf("KONTROL VERDIKT=VERNO ecx=0 v obeih rukah\n");
    if (vykl.ret_exits)
        printf("ret_exits: %.2f %% ot ishodnogo (sdvig %+.2f %%)\n",
               100.0 * (double)vkl.ret_exits / (double)vykl.ret_exits,
               100.0 * ((double)vkl.ret_exits - (double)vykl.ret_exits) / (double)vykl.ret_exits);
    if (vykl.sec > 0.0)
        printf("vremya: sdvig %+.2f %%\n", 100.0 * (vkl.sec - vykl.sec) / vykl.sec);
    return 0;
}
