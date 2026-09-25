/* ═══ ПРИБОР: СКОЛЬКО МЕСТ ВЫХОДА ПОМЕЧАЕТ ЗАПИСЬ ═══════════════════════════════
 *
 * ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. Прибор записи (hb_record.c) до сих пор проверялся
 * ТОЛЬКО живым прогоном Hollow Knight: приёмка `тест-записи-и-повтора.sh`
 * собирает запись САМА, в обход прибора, а мутации трогают лишь сличение окон.
 * То есть пометка мест выхода не была покрыта ничем, и её дыра — 52,6 % входов
 * без выхода на настоящей записи HK — прожила четыре захода лейна.
 *
 * ЧТО ДОКАЗЫВАЕТСЯ ЗДЕСЬ, БЕЗ ИГРЫ И БЕЗ WINE.
 *   ИНВАРИАНТ: один вызов `hb_jit_runtime_run` = один вход = один выход.
 *   Значит в исправной записи ВХОДОВ столько же, сколько ВЫХОДОВ, и ни один
 *   вход не идёт следом за входом. Число входов известно точно — стенд сам их
 *   считает, — поэтому «столько же» здесь есть проверяемое равенство, а не
 *   впечатление.
 *
 * ГОСТЕВАЯ ПРОГРАММА выбрана так, чтобы диспетчер выходил через место, которое
 * прибор НЕ метил: `call` + `ret` в одной функции — тот же узор, что у
 * hb_ret_shadow_bench, и на нём диспетчер считает `t_runexit[RUNEXIT_RET]`.
 * Проваливание `jnz` в конце уводит на адрес без блока — это RUNEXIT_NO_BLOCK,
 * то есть в одном прогоне присутствуют ОБА класса: помеченный прежде и нет.
 *
 * ОТРИЦАТЕЛЬНЫЕ КОНТРОЛИ — гейтом MACRUNNER_HB_RECORD_EXIT_SITES:
 *   7 метить всё; 3 вернуть прежнее поведение (два места из пяти);
 *   5 снять ext_xfer; 6 снять no_block. Каждый обязан менять числа предсказуемо.
 *
 * Кириллица только в строках и комментариях.
 */
#include "hb_context.h"
#include "hb_ir.h"
#include "hb_runtime.h"
#include "hb_memory.h"
#include "hb_record.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* ★ АДРЕСА ГОСТЯ ЗДЕСЬ ОБЯЗАНЫ БЫТЬ НАСТОЯЩИМИ АДРЕСАМИ ПРОЦЕССА.
 *
 * Прибор записи снимает окна наблюдения ЧТЕНИЕМ ПАМЯТИ ПРОЦЕССА по гостевому
 * адресу (`hb_rec_read_guest`) — в движке гостевой адрес и есть хостовой, там
 * это тождество. Стенд, где память гостя живёт только внутри `hb_memory`,
 * прибор роняет: проверено, SIGSEGV на первом же выходе, и роняет он его
 * ОДИНАКОВО при маске 0 и при маске 7, то есть это устройство прибора, а не
 * новая правка.
 *
 * Отсюда два следствия: стек отображается настоящим `mmap` MAP_FIXED, и база
 * лежит ВЫШЕ 4 ГБ — ниже на macOS растянут __PAGEZERO, и MAP_FIXED туда не
 * ложится (память проекта: macos_arm64_requires_4gb_pagezero). */
#define BAZA      0x0000000140000000ull
#define STACK_PG  0x000000014000f000ull
#define STACK_TOP 0x000000014000fb68ull

static hb_ir_func_t* postroit(void)
{
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

/* ─── разбор получившейся записи ─── */

typedef struct {
    uint64_t enter, exit_n, sites[4], bez_vyhoda, chuzhih;
    int celo;                       /* seq сплошной и хвост пуст */
} svod_t;

/* Шаг по потоку событий ТЕМ ЖЕ правилом, что и читатель: по total_len. Сторож
 * целостности обязателен — питоновский скан прошлого захода шагал не тем
 * выравниванием и дал 412 ложных попаданий. */
static int razobrat(const char* put, svod_t* s)
{
    FILE* f = fopen(put, "rb");
    hb_record_header_t hdr;
    uint8_t* buf;
    struct stat st;
    size_t len, off = 0;
    uint64_t seq_zhdyom = 0;
    int prev_enter = 0;

    memset(s, 0, sizeof(*s));
    if (!f) return 0;
    if (stat(put, &st) != 0) { fclose(f); return 0; }
    if (fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { fclose(f); return 0; }
    if (memcmp(hdr.magic, HB_RECORD_MAGIC, 8) != 0) { fclose(f); return 0; }

    len = (size_t)st.st_size - (size_t)hdr.events_off;
    buf = (uint8_t*)malloc(len ? len : 1);
    if (!buf) { fclose(f); return 0; }
    fseek(f, (long)hdr.events_off, SEEK_SET);
    if (fread(buf, 1, len, f) != len) { free(buf); fclose(f); return 0; }
    fclose(f);

    s->celo = 1;
    while (off + sizeof(hb_record_event_t) <= len) {
        hb_record_event_t ev;
        memcpy(&ev, buf + off, sizeof(ev));
        if (ev.total_len < sizeof(ev) || off + ev.total_len > len) { s->celo = 0; break; }
        if (ev.seq != seq_zhdyom) { s->celo = 0; break; }
        seq_zhdyom++;
        if (ev.kind == HB_REC_ENTER) {
            s->enter++;
            if (prev_enter) s->bez_vyhoda++;
            prev_enter = 1;
        } else if (ev.kind == HB_REC_EXIT) {
            s->exit_n++;
            if (ev.site < 4) s->sites[ev.site]++; else s->chuzhih++;
            prev_enter = 0;
        } else {
            prev_enter = 0;
        }
        off += ev.total_len;
    }
    if (off != len) s->celo = 0;
    free(buf);
    return 1;
}

int main(int argc, char** argv)
{
    const char* dir = (argc > 1) ? argv[1] : NULL;
    unsigned n = (argc > 2) ? (unsigned)strtoul(argv[2], NULL, 0) : 400u;
    hb_ir_func_t* f;
    hb_context_t* ctx;
    hb_jit_runtime_t* rt;
    hb_exec_result_t out;
    unsigned long long zahodov = 0;
    uint64_t stack_pg = 0, stack_top = 0;
    const char* prichina = "pc==konec";
    unsigned ctx_rcx = 0, rep = 0;
    int stop = 0;
    char put[1024];
    svod_t s;

    if (!dir) { fprintf(stderr, "nuzhen katalog zapisi\n"); return 2; }

    f = postroit();
    if (!f) { fprintf(stderr, "ne postroilos\n"); return 2; }

    /* Стек гостя — настоящая страница процесса, и АДРЕС ЕЁ ВЫБИРАЕТ ЯДРО.
     * Заданный вручную адрес не ложится (проверено на 0x14000f000: занят), а
     * подбирать его перебором значило бы вписать в стенд предположение о карте
     * процесса. Адреса кода при этом остаются условными: код гость не читает,
     * IR построен заранее. */
    {
        void* p = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED) {
            fprintf(stderr, "povtor7-vyhody: OTKAZ ne lyog stek gostya\n");
            return 2;
        }
        stack_pg = (uint64_t)(uintptr_t)p;
        stack_top = stack_pg + 0xb68ull;
    }

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    if (!ctx) return 2;
    ctx->memory = hb_memory_create(0);
    hb_memory_map(ctx->memory, (hb_gva_t)stack_pg, 65536,
                  (hb_perm_t)(HB_PERM_READ | HB_PERM_WRITE));
    rt = hb_jit_runtime_create(ctx);

    /* ★ ПРОГРАММА ГОНЯЕТСЯ n РАЗ ЗАНОВО, а не крутится одним длинным циклом.
     * Замер: 400 оборотов внутреннего цикла дают ВСЕГО ТРИ захода в диспетчер —
     * `call` и `ret` ведут в блоки той же функции, диспетчер находит их сам и
     * наружу не выходит. Стенд, меряющий пометку ВЫХОДОВ, на трёх выходах
     * доказывал бы мало; перезапуск программы даёт по три выхода на повтор. */
    ctx->regs.x64.rcx = 4;

    /* ЦИКЛ ВЫЗЫВАЮЩЕГО — тот же порядок, что в macrunner_hb_run_x64: вход
     * пишется ВНУТРИ hb_jit_runtime_run, выход помечается СРАЗУ за возвратом. */
    for (rep = 0; rep < n && !stop; rep++) {
        ctx->pc = BAZA + 0x1000;
        ctx->regs.x64.rsp = stack_top;
        ctx->regs.x64.rcx = 4;
        while (ctx->pc != BAZA + 0x100a) {
            if (hb_jit_runtime_run(rt, f, &out) != HB_OK) { prichina = "run!=HB_OK"; stop = 1; break; }
            zahodov++;
            hb_record_left(ctx, ctx->pc, out.faulted ? 1 : 0, (int)out.result);
            if (out.result != HB_OK) { prichina = "out.result!=HB_OK"; stop = 1; break; }
            if (zahodov > 2000000ull) { prichina = "storozh"; stop = 1; break; }
        }
    }

    ctx_rcx = ctx->regs.x64.rcx;
    hb_jit_runtime_destroy(rt);
    hb_context_destroy(ctx);

    snprintf(put, sizeof(put), "%s/zapis.bin", dir);
    if (!razobrat(put, &s)) {
        fprintf(stderr, "povtor7-vyhody: OTKAZ ne prochital %s\n", put);
        return 3;
    }

    printf("povtor7-vyhody: zahodov=%llu ENTER=%llu EXIT=%llu "
           "mesto0=%llu mesto1=%llu mesto2=%llu mesto3=%llu chuzhih=%llu "
           "vhodov_bez_vyhoda=%llu celo=%d konec=%s rcx=%u\n",
           zahodov, (unsigned long long)s.enter, (unsigned long long)s.exit_n,
           (unsigned long long)s.sites[0], (unsigned long long)s.sites[1],
           (unsigned long long)s.sites[2], (unsigned long long)s.sites[3],
           (unsigned long long)s.chuzhih, (unsigned long long)s.bez_vyhoda,
           s.celo, prichina, ctx_rcx);
    return 0;
}
