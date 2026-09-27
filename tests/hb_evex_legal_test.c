/* Законность EVEX: декодер против ПРОЦЕССОРА, а не против capstone.
 *
 * Каждая запись tests/hb_evex_legal/verdicts.inc — кодировка, исполненная на x86 (пакет
 * HB_EDGE_ORACLE: AMD EPYC 9V74, x64 в CS=0x33, i386 в CS=0x23, одиночный шаг). Таблицу
 * порождает tests/hb_evex_legal/gen_verdicts.py из EVEX_RESULTS.json того же пакета.
 *
 *   #UD на железе   — декодер обязан вернуть HB_OK, HB_INS_UD и полную длину команды;
 *                     затем команда поднимается и исполняется интерпретатором и JIT: отказ
 *                     обязан быть вида ILLEGAL (гостю c000001d) и ровно по её адресу.
 *   исполнилась     — декодер обязан разобрать настоящую EVEX-команду той длины, что
 *                     замерена (trap 1 после неё). Сюда же 24 законные контрольные формы.
 *
 * Замер 27.09.2026 до правки (hb_evex_legal.h): из 248 кодировок с #UD отвергнута 0 —
 * декодер исполнял все. Числа записей сверяются с ожидаемыми: усечённая таблица не может
 * пройти молча. */
#include <stdio.h>
#include <string.h>
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"

typedef struct {
    int arch;               /* 64 или 32 */
    unsigned n;             /* байтов в записи (у части карты 2 — команда и ещё один байт) */
    unsigned char b[16];
    int ud;                 /* 1 — процессор дал #UD */
    unsigned len;           /* длина команды */
    int control;            /* 1 — законная контрольная форма того же прогона */
} verdict_t;

static const verdict_t rows[] = {
#include "hb_evex_legal/verdicts.inc"
};
#define NROWS (sizeof(rows) / sizeof(rows[0]))

/* [0] x64, [1] i386 × {#UD, исполнилась, контрольная} — числа пакета HB_EDGE_ORACLE. */
static const unsigned expected[2][3] = { {180, 8, 12}, {68, 8, 12} };

static int placeholder(int op) {
    return op == HB_INS_UD || op == HB_INS_VEC || op == HB_INS_UNKNOWN ||
           op == HB_INS_UNSUPPORTED || op == HB_INS_UNAVAILABLE_EXT;
}

/* Код x64 исполняется по своему адресу в памяти хоста, код i386 — в гостевой памяти ниже
 * 4 ГБ. У каждой записи свой адрес: отказ обязан назвать именно его. */
static unsigned char code64[NROWS][16];
#define BASE32 0x00401000u

static hb_context_t* make_ctx(int a, hb_backend_t be) {
    hb_context_t* ctx = hb_context_create(a ? HB_ARCH_X86 : HB_ARCH_X64, be);
    if (!ctx) return NULL;
    ctx->memory = hb_memory_create(0);
    if (!ctx->memory) { hb_context_destroy(ctx); return NULL; }
    hb_result_t r = a ? hb_memory_guest32_map(ctx->memory, BASE32, (NROWS * 16 + 4095) & ~(size_t)4095,
                                              HB_PERM_READ | HB_PERM_WRITE | HB_PERM_EXEC)
                      : hb_memory_map(ctx->memory, (hb_gva_t)(uintptr_t)code64, sizeof(code64),
                                      HB_PERM_READ | HB_PERM_EXEC);
    if (r != HB_OK) { hb_context_destroy(ctx); return NULL; }
    for (size_t i = 0; a && i < NROWS; i++)
        if (hb_memory_write(ctx->memory, BASE32 + i * 16, rows[i].b, rows[i].len) != HB_OK) {
            hb_context_destroy(ctx);
            return NULL;
        }
    return ctx;
}

/* Поднять одну команду и исполнить: 1 — отказ ILLEGAL ровно по её адресу. */
static int runs_to_ud(hb_context_t* ctx, int a, hb_backend_t be, size_t i) {
    uint64_t addr = a ? BASE32 + i * 16 : (uint64_t)(uintptr_t)code64[i];
    hb_decoder_t* dec = hb_decoder_create(a ? HB_ARCH_X86 : HB_ARCH_X64,
                                          a ? rows[i].b : code64[i], rows[i].len, addr);
    hb_ir_func_t* f = NULL;
    int ok = 0;
    if (dec && (a ? hb_lift_func_x86(dec, &f) : hb_lift_func_x64(dec, &f)) == HB_OK &&
        f && !f->has_unsupported) {
        hb_exec_result_t out;
        ctx->pc = addr;
        if (a) ctx->regs.x86.eip = (uint32_t)addr;
        else ctx->regs.x64.rip = addr;
        ctx->last_fault_kind = HB_FAULT_KIND_NONE;
        ctx->last_fault_pc = 0;
        ok = hb_runtime_run(ctx, f, be, &out) == HB_OK && out.result == HB_ERR_EXEC_FAULT &&
             ctx->last_fault_kind == HB_FAULT_KIND_ILLEGAL && ctx->last_fault_pc == addr;
    }
    if (f) hb_ir_func_destroy(f);
    if (dec) hb_decoder_destroy(dec);
    return ok;
}

int main(void) {
    unsigned total[2][3] = {{0}}, agree[2][3] = {{0}}, ran[2][2] = {{0}}, bad = 0;
    for (size_t i = 0; i < NROWS; i++) memcpy(code64[i], rows[i].b, rows[i].len);
    for (size_t i = 0; i < NROWS; i++) {
        const verdict_t* v = &rows[i];
        int a = v->arch == 32, k = v->control ? 2 : (v->ud ? 0 : 1), ok;
        hb_decoded_t o;
        memset(&o, 0, sizeof(o));
        hb_decoder_t* d = hb_decoder_create(a ? HB_ARCH_X86 : HB_ARCH_X64, v->b, v->n, 0x10000);
        hb_result_t r = d ? hb_decode_next(d, &o) : HB_ERR_INTERNAL;
        if (d) hb_decoder_destroy(d);
        if (v->ud) ok = r == HB_OK && o.opcode == HB_INS_UD && o.len == v->len;
        else ok = r == HB_OK && o.evex && !placeholder(o.opcode) && o.len == v->len;
        total[a][k]++;
        if (ok) {
            agree[a][k]++;
        } else if (++bad <= 20) {
            printf("BAD %s %s rc=%d opcode=%s len=%u expected len=%u bytes=",
                   a ? "i386" : "x64", v->ud ? "hardware #UD" : "hardware executed",
                   r, hb_opcode_name(o.opcode), o.len, v->len);
            for (unsigned j = 0; j < v->n; j++) printf("%02x", v->b[j]);
            printf("\n");
        }
    }
    for (int a = 0; a < 2; a++) {
        for (int be = 0; be < 2; be++) {
            hb_backend_t backend = be ? HB_BACKEND_JIT : HB_BACKEND_INTERP;
            hb_context_t* ctx = make_ctx(a, backend);
            if (!ctx) { printf("BAD cannot create a %s context\n", a ? "i386" : "x64"); bad++; continue; }
            for (size_t i = 0; i < NROWS; i++) {
                if ((rows[i].arch == 32) != a || !rows[i].ud) continue;
                if (runs_to_ud(ctx, a, backend, i)) {
                    ran[a][be]++;
                } else if (++bad <= 40) {
                    printf("BAD %s %s: no ILLEGAL fault at the instruction, bytes=",
                           a ? "i386" : "x64", be ? "JIT" : "INTERP");
                    for (unsigned j = 0; j < rows[i].len; j++) printf("%02x", rows[i].b[j]);
                    printf("\n");
                }
            }
            hb_context_destroy(ctx);
        }
    }
    for (int a = 0; a < 2; a++) {
        printf("EVEX legality %s: #UD refused %u/%u (ILLEGAL at the instruction: INTERP %u, JIT %u), "
               "executed accepted %u/%u, legal controls accepted %u/%u\n",
               a ? "i386" : "x64", agree[a][0], total[a][0], ran[a][0], ran[a][1],
               agree[a][1], total[a][1], agree[a][2], total[a][2]);
        for (int k = 0; k < 3; k++) {
            if (total[a][k] != expected[a][k]) {
                printf("BAD table: %s kind %d has %u records, expected %u\n",
                       a ? "i386" : "x64", k, total[a][k], expected[a][k]);
                bad++;
            }
        }
    }
    return bad ? 1 : 0;
}
