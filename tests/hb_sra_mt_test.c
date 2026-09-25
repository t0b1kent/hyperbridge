/* ОДНОВРЕМЕННЫЙ ВЫПУСК: тот же блок из нескольких потоков обязан дать тот же код.
 *
 * MacRunner 2026-08-18, лейн РЕГИСТРЫ, итерация 26.
 *
 * Зачем. Выпуск идёт из потока гостя, и потоков много. Флаг подавления перехвата
 * (`g_sra_bypass`) был файловой переменной — то есть общей на все потоки. Гонка давала бы не
 * падение, а МОЛЧАЛИВОЕ РАСХОЖДЕНИЕ: чужой флаг заставляет пропустить перехват, и блок
 * выпускает обращение к памяти для регистра, живущего в регистре хозяина.
 *
 * Ни сличение с интерпретатором, ни сторожа полноты этого не поймают: они однопоточные.
 * Поэтому проверка отдельная — один и тот же корпус выпускается сначала в одном потоке, потом
 * в N потоках сразу, и коды сверяются побайтно.
 *
 * Адресные значения (MOVZ/MOVK помощников) гасятся: они одинаковы внутри процесса, но пусть
 * сверка не зависит от этого.
 */
#include "hb_codegen.h"
#include "hb_context.h"
#include "hb_decoder.h"
#include "hb_ir.h"
#include "hb_lifter.h"
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MT_CODE_BASE 0x100000ULL
#define MT_MAX_CODE  32U
#define MT_MAX_CASES 4096
#define MT_THREADS   4

static uint8_t  g_code[MT_MAX_CASES][MT_MAX_CODE];
static size_t   g_len[MT_MAX_CASES];
static size_t   g_cases;
static uint64_t g_ref[MT_MAX_CASES];      /* эталон: свёртка кода из одного потока */
static uint64_t g_got[MT_THREADS][MT_MAX_CASES];

static uint64_t emit_hash(size_t idx) {
    hb_decoder_t* dec;
    hb_ir_func_t* func = NULL;
    hb_context_t* ctx;
    hb_arm64_codegen_t* cg;
    hb_codegen_buffer_t* buf;
    uint64_t h = 1469598103934665603ULL;
    size_t i;

    dec = hb_decoder_create(HB_ARCH_X64, g_code[idx], g_len[idx], MT_CODE_BASE);
    if (!dec) return 0;
    if (hb_lift_func_x64(dec, &func) != HB_OK || !func) { hb_decoder_destroy(dec); return 0; }
    hb_decoder_destroy(dec);

    ctx = hb_context_create(HB_ARCH_X64, HB_BACKEND_JIT);
    cg  = ctx ? hb_arm64_codegen_create(ctx) : NULL;
    buf = hb_codegen_buffer_create(65536);
    if (cg && buf && func->cfg && func->cfg->entry) {
        buf->arch = HB_ARCH_X64;
        if (hb_arm64_codegen_block(cg, func->cfg->entry, buf) == HB_OK) {
            for (i = 0; i + 4 <= buf->size; i += 4) {
                uint32_t w;
                memcpy(&w, buf->code + i, 4);
                /* гасим непосредственные значения MOVZ/MOVK — оставляем опкод и приёмник */
                if ((w & 0x7F800000u) == 0x52800000u || (w & 0x7F800000u) == 0x72800000u)
                    w = (w & 0xFF80001Fu);
                h ^= w; h *= 1099511628211ULL;
            }
        }
    }
    if (buf) hb_codegen_buffer_destroy(buf);
    if (cg)  hb_arm64_codegen_destroy(cg);
    if (ctx) hb_context_destroy(ctx);
    hb_ir_func_destroy(func);
    return h;
}

static void* worker(void* arg) {
    size_t t = (size_t)arg, round, i;
    for (round = 0; round < 3; round++)          /* несколько кругов — больше шансов на гонку */
        for (i = 0; i < g_cases; i++)
            g_got[t][i] = emit_hash(i);
    return NULL;
}

int main(void) {
    char line[256];
    pthread_t th[MT_THREADS];
    size_t i, t;
    unsigned long bad = 0;

    while (g_cases < MT_MAX_CASES && fgets(line, sizeof(line), stdin)) {
        char* p = line;
        size_t n = 0;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') continue;
        while (*p && !isspace((unsigned char)*p)) p++;      /* зерно — мимо */
        while (*p && isspace((unsigned char)*p)) p++;
        while (n < MT_MAX_CODE && isxdigit((unsigned char)p[0]) && isxdigit((unsigned char)p[1])) {
            char b[3] = { p[0], p[1], 0 };
            g_code[g_cases][n++] = (uint8_t)strtoul(b, NULL, 16);
            p += 2;
        }
        if (!n) continue;
        g_len[g_cases] = n;
        g_cases++;
    }
    if (!g_cases) { fprintf(stderr, "нет случаев\n"); return 2; }

    for (i = 0; i < g_cases; i++) g_ref[i] = emit_hash(i);   /* эталон в одном потоке */

    for (t = 0; t < MT_THREADS; t++) pthread_create(&th[t], NULL, worker, (void*)t);
    for (t = 0; t < MT_THREADS; t++) pthread_join(th[t], NULL);

    for (t = 0; t < MT_THREADS; t++)
        for (i = 0; i < g_cases; i++)
            if (g_got[t][i] != g_ref[i]) {
                bad++;
                if (bad <= 3) {
                    size_t k;
                    fprintf(stderr, "  расхождение: поток=%zu случай=%zu байты=", t, i);
                    for (k = 0; k < g_len[i]; k++) fprintf(stderr, "%02x", g_code[i][k]);
                    fprintf(stderr, "  эталон=%llx поток=%llx\n",
                            (unsigned long long)g_ref[i], (unsigned long long)g_got[t][i]);
                }
            }

    printf("случаев=%zu потоков=%d кругов=3 РАСХОЖДЕНИЙ=%lu\n", g_cases, MT_THREADS, bad);
    return bad ? 1 : 0;
}
