/* ГРАФ АНАЛИЗА — АДРЕСНЫЙ ВЫВОД. Прибор лейна CFG, 07.09.2026.
 *
 * ЗАЧЕМ. Наряд требует «прогнать гостевые байты контрольного ромба через
 * ПРОИЗВОДСТВЕННЫЕ лифтер и построитель, получить адресные дуги и маски, затем
 * намеренно удалить дугу». Значит прибор обязан звать РОВНО те же
 * `hb_lift_func_x64`/`hb_lift_func_x86`, что и движок, и печатать то, что построил
 * ПРОИЗВОДСТВЕННЫЙ `hb_cfg_build`, а не собственную копию правил.
 *
 * ЧТО ПЕЧАТАЕТ. По каждому случаю корпуса: перепись гостевых команд (включая те, что
 * не породили IR), узлы диапазонами, ТИПИЗОВАННЫЕ дуги с адресами и причинами, точки
 * наблюдения, вердикт независимой проверки `hb_cfg_validate`. В конце — итог с
 * разбивкой выходов по состоянию цели и признаком полноты вывода.
 *
 * ЧЕГО НЕ ДЕЛАЕТ. Не судит о КОРРЕКТНОСТИ исполнения: это статическая структура.
 * Ноль дуг у линейной единицы законен — обязательна ПОЛНОТА ожидаемых дуг, а не
 * `edges>0` (у контрольного ромба переходы заданы конструкцией, поэтому там ноль
 * означал бы отказ).
 *
 * ★ ПОЛНОТА ВЫВОДА. Потолка печати нет; последняя строка `ИТОГ` содержит число
 * случаев и completion-признак. Оборванный вывод виден по её отсутствию. */

#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include "hb_codegen.h"
#include "hb_probe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_CODE 512

static const char* kind_name(unsigned k) {
    switch (k) {
        case HB_CFG_E_FALL:     return "FALL";
        case HB_CFG_E_TAKEN:    return "TAKEN";
        case HB_CFG_E_JUMP:     return "JUMP";
        case HB_CFG_E_TRANSFER: return "TRANSFER";
        case HB_CFG_E_END:      return "END";
    }
    return "?";
}

static const char* state_name(unsigned s) {
    switch (s) {
        case HB_CFG_T_KNOWN_LOCAL:        return "KNOWN_LOCAL";
        case HB_CFG_T_UNKNOWN_NOT_LIFTED: return "UNKNOWN_NOT_LIFTED";
        case HB_CFG_T_UNKNOWN_OUTSIDE:    return "UNKNOWN_OUTSIDE";
        case HB_CFG_T_UNKNOWN_TRANSFER:   return "UNKNOWN_TRANSFER";
        case HB_CFG_T_UNKNOWN_INCOMPLETE: return "UNKNOWN_INCOMPLETE";
    }
    return "?";
}

static const char* obs_name(unsigned r) {
    switch (r) {
        case HB_CFG_OBS_MEM:    return "MEM";
        case HB_CFG_OBS_HELPER: return "HELPER";
        case HB_CFG_OBS_TRAP:   return "TRAP";
    }
    return "?";
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char* s, uint8_t* out, size_t* out_n) {
    size_t n = 0;
    while (s[0] && s[1]) {
        int hi = hexval(s[0]), lo = hexval(s[1]);
        if (hi < 0 || lo < 0) return 0;
        if (n >= MAX_CODE) return 0;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    if (s[0]) return 0;
    *out_n = n;
    return n > 0;
}

/* Отступы входов из HB_CFG_VHODY="0,4,15". Пусто -> один вход, отступ 0.
 * ★ Это НЕ «читать произвольные байты соседа»: каждый вход поднимается ОТДЕЛЬНОЙ
 * производственной трансляцией со своим базовым адресом, ровно как это делает движок,
 * когда управление приходит на середину прежде разобранного окна. */
#define MAX_VHOD 32
static size_t parse_vhody(unsigned* out) {
    const char* s = getenv("HB_CFG_VHODY");
    size_t k = 0;
    if (!s || !*s) { out[0] = 0; return 1; }
    while (*s && k < MAX_VHOD) {
        char* end;
        unsigned long v = strtoul(s, &end, 0);
        if (end == s) break;
        out[k++] = (unsigned)v;
        s = end;
        while (*s == ',' || *s == ' ') s++;
    }
    return k ? k : 1;
}

int main(void) {
    const char* arch_s = getenv("HB_DIFF_ARCH");
    int is86 = arch_s && strcmp(arch_s, "x86") == 0;
    hb_arch_t arch = is86 ? HB_ARCH_X86 : HB_ARCH_X64;
    uint64_t base0 = is86 ? 0x100000ULL : 0x140000000ULL;
    int tiho = getenv("HB_CFG_TIHO") != NULL;     /* только итог, без поштучной печати */
    char line[8192];
    unsigned vhody[MAX_VHOD];
    size_t n_vhod = parse_vhody(vhody), vi;

    unsigned long long cases = 0, s_nodes = 0, s_edges = 0, s_obs = 0, s_guest = 0;
    unsigned long long s_known = 0, s_notlifted = 0, s_outside = 0, s_transfer = 0, s_incompl = 0;
    unsigned long long valid_ok = 0, valid_bad = 0, no_graph = 0, lift_bad = 0;
    unsigned long long s_words = 0, s_emit_bad = 0;
    unsigned long long s_maski_val = 0, s_maski_pub = 0, s_passes = 0;
    unsigned long long s_legacy_succ = 0, s_legacy_pred = 0;

    while (fgets(line, sizeof(line), stdin)) {
        char* p = line;
        char* seed_s;
        char* code_s;
        uint8_t bytes[MAX_CODE];
        size_t n = 0;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        seed_s = strtok(p, " \t\r\n");
        code_s = strtok(NULL, " \t\r\n");
        if (!seed_s || !code_s) continue;
        if (!parse_hex(code_s, bytes, &n)) continue;

        for (vi = 0; vi < n_vhod; vi++) {
        hb_decoder_t* dec;
        hb_ir_func_t* func = NULL;
        hb_result_t r;
        unsigned off = vhody[vi];
        uint64_t base;

        if (off >= n) continue;
        base = base0 + off;
        cases++;

        dec = hb_decoder_create(arch, bytes + off, n - off, base);
        if (!dec) { lift_bad++; continue; }
        r = is86 ? hb_lift_func_x86(dec, &func) : hb_lift_func_x64(dec, &func);
        hb_decoder_destroy(dec);
        if (r != HB_OK || !func) { lift_bad++; if (func) hb_ir_func_destroy(func); continue; }

        /* ★ ВЫПУСК ПО ЗАПРОСУ. Приборы живости стоят В КОДОГЕНЕРАТОРЕ: без прохода
         * выпуска их `looked` останется нулём, и перепись прочиталась бы как «явления
         * нет» вместо «наблюдение не начиналось». Поэтому HB_CFG_VYPUSK=1 гонит тот же
         * `hb_arm64_codegen_block_with_cfg`, что и прибор слов. */
        if (getenv("HB_CFG_VYPUSK")) {
            hb_context_t* ctx = hb_context_create(arch, HB_BACKEND_JIT);
            hb_arm64_codegen_t* cg = ctx ? hb_arm64_codegen_create(ctx) : NULL;
            hb_codegen_buffer_t* outb = hb_codegen_buffer_create(64 * 1024);
            if (cg && outb && func->cfg && func->cfg->entry) {
                if (hb_arm64_codegen_block_with_cfg(cg, func->cfg->entry, func->cfg, outb) == HB_OK)
                    s_words += outb->size / 4;
                else s_emit_bad++;
            } else s_emit_bad++;
            if (outb) hb_codegen_buffer_destroy(outb);
            if (ctx) hb_context_destroy(ctx);
        }
        /* ★ «БЫЛО 0» — ЭТО НЕ ССЫЛКА НА ОТЧЁТ, А ЗАМЕР. Считаем succ/pred СТАРОГО
         * контейнера выпуска по КАЖДОЙ единице: именно на них поставили бы анализ, если
         * бы не завели отдельный граф, и именно они пусты всегда (производственных
         * вызовов hb_ir_cfg_add_edge нет). Печатается безусловно, гейтом не гасится. */
        if (func->cfg) {
            size_t bi;
            for (bi = 0; bi < func->cfg->block_count; bi++) {
                s_legacy_succ += func->cfg->blocks[bi]->succ_count;
                s_legacy_pred += func->cfg->blocks[bi]->pred_count;
            }
        }

        if (!func->acfg) {
            no_graph++;
            if (!tiho) printf("СЛУЧАЙ %s вход+%u  ГРАФА НЕТ (гейт закрыт либо перепись пуста)\n",
                              code_s, off);
            hb_ir_func_destroy(func);
            continue;
        }
        {
            const hb_cfg_analysis_t* a = func->acfg;
            const hb_ir_block_t* blk = func->cfg ? func->cfg->entry : NULL;
            const char* why = NULL;
            int ok = hb_cfg_validate(a, blk, &why);
            size_t i;

            s_guest += a->guest_n; s_nodes += a->node_n; s_edges += a->edge_n; s_obs += a->obs_n;
            s_known += a->n_known_local; s_notlifted += a->n_unknown_not_lifted;
            s_outside += a->n_unknown_outside; s_transfer += a->n_unknown_transfer;
            s_incompl += a->n_unknown_incomplete;
            if (ok) valid_ok++; else valid_bad++;

            if (!tiho) {
                printf("СЛУЧАЙ %s вход+%u  guest=0x%llx окно=%zu  перепись=%zu узлов=%zu дуг=%zu набл=%zu  полон=%d  проверка=%s%s%s\n",
                       code_s, off, (unsigned long long)func->guest_addr, func->guest_len,
                       a->guest_n, a->node_n, a->edge_n, a->obs_n, a->complete,
                       ok ? "ВЕРНО" : "ОТКАЗ", ok ? "" : " — ", ok ? "" : (why ? why : "?"));
                for (i = 0; i < a->guest_n; i++) {
                    const hb_cfg_guest_t* g = &a->guest[i];
                    printf("  перепись[%zu] 0x%llx len=%u ir=[%u..%u) %s%s%s%s tgt=0x%llx\n",
                           i, (unsigned long long)g->addr, (unsigned)g->len,
                           g->ir_first, g->ir_first + g->ir_count,
                           g->is_branch ? (g->is_cond ? "Jcc " : "JMP ") : "",
                           g->is_call ? "CALL " : "", g->is_ret ? "RET " : "",
                           g->ir_count ? "" : "БЕЗ-IR ",
                           (unsigned long long)g->target);
                }
                for (i = 0; i < a->node_n; i++) {
                    const hb_cfg_node_t* nd = &a->nodes[i];
                    printf("  узел[%zu] ir=[%u..%u) guest=0x%llx..0x%llx входов=%u\n",
                           i, nd->ir_first, nd->ir_end,
                           (unsigned long long)nd->guest_first, (unsigned long long)nd->guest_end,
                           (a->pred_n > i) ? a->pred_count[i] : 0u);
                }
                for (i = 0; i < a->edge_n; i++) {
                    const hb_cfg_edge_t* e = &a->edges[i];
                    printf("  ДУГА узел%u -> %s%d  вид=%-8s состояние=%-18s сайт=0x%llx цель=0x%llx\n",
                           e->from, e->to >= 0 ? "узел" : "", e->to,
                           kind_name(e->kind), state_name(e->state),
                           (unsigned long long)e->site_guest,
                           (unsigned long long)e->target_guest);
                }
                for (i = 0; i < a->obs_n; i++)
                    printf("  НАБЛЮДАТЕЛЬ узел%u ir=%u guest=0x%llx причина=%s\n",
                           a->obs[i].node, a->obs[i].ir,
                           (unsigned long long)a->obs[i].guest, obs_name(a->obs[i].reason));
            }
            /* ★ СТАТИЧЕСКАЯ ПРИЁМКА МАСОК — на ПОЛНОМ массиве, без проекции на предел
             * выпуска. Отдельно от сквозной: см. разбор у hb_cfg_masks_probe. */
            if (getenv("HB_CFG_MASKI") && blk) {
                uint32_t mv[256], mp[256], jv[256], jp[256];
                size_t passes = 0;
                size_t got = hb_cfg_masks_probe(blk, func->cfg, mv, mp, jv, jp, 256, &passes);
                if (!got) printf("  МАСКИ: граф недоступен\n");
                else {
                    printf("  МАСКИ (проходов=%zu):\n", passes);
                    for (i = 0; i < got; i++) {
                        s_maski_val += mv[i]; s_maski_pub += mp[i];
                        printf("    [%zu] guest=0x%llx op=%d NeedValue=0x%02x NeedPublished=0x%02x"
                               " ПослеJcc: val=0x%02x pub=0x%02x\n",
                               i, (unsigned long long)blk->instrs[i].guest_addr,
                               (int)blk->instrs[i].op, mv[i], mp[i], jv[i], jp[i]);
                    }
                    s_passes += passes;
                }
            }
        }
        hb_ir_func_destroy(func);
        }   /* vhody */
    }

    if (getenv("HB_CFG_VYPUSK"))
        printf("ИТОГ слов=%llu отказов_выпуска=%llu\n", s_words, s_emit_bad);
    if (getenv("HB_CFG_MASKI"))
        printf("ИТОГ маски: сумма_NeedValue=%llu сумма_NeedPublished=%llu проходов_всего=%llu\n",
               s_maski_val, s_maski_pub, s_passes);
    if (getenv("HB_CFG_PEREPIS")) hb_probe_census(stdout);
    printf("ИТОГ СТАРЫЙ контейнер выпуска: succ=%llu pred=%llu (ноль = анализ на нём был бы прибором на пустой структуре)\n",
           s_legacy_succ, s_legacy_pred);
    printf("ИТОГ случаев=%llu переписей=%llu узлов=%llu дуг=%llu наблюдателей=%llu "
           "проверка_верно=%llu проверка_отказ=%llu без_графа=%llu отказ_лифтера=%llu\n",
           cases, s_guest, s_nodes, s_edges, s_obs, valid_ok, valid_bad, no_graph, lift_bad);
    printf("ИТОГ выходы: KNOWN_LOCAL=%llu NOT_LIFTED=%llu OUTSIDE=%llu TRANSFER=%llu INCOMPLETE=%llu\n",
           s_known, s_notlifted, s_outside, s_transfer, s_incompl);
    return 0;
}
