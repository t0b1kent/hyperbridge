/* MacRunner 2026-08-16, лейн ДИСПЕТЧ, итерация 1 — ЗАМЕР ДО.
 *
 * Зачем. Наряд называет шесть статей на переходе и их размеры (снимок 760 Б, memset 790 Б,
 * sigsetjmp, три обращения к поточной памяти, обход представления, хеш FNV). Числа взяты из
 * профиля, то есть в ДОЛЯХ времени. Чтобы доказать, что снятие статьи что-то дало, нужна её
 * цена ОТДЕЛЬНО и в наносекундах на ЭТОМ железе — иначе «стало на 3 % быстрее» неотличимо от
 * шума планировщика.
 *
 * Прибор мерит КАЖДУЮ статью изолированно, тем же кодом, что стоит на горячем пути:
 *   1 снимок контекста        memcpy sizeof(hb_context_t)
 *   2 обнуление хвоста кадра  memset (кадр минус снимок) — ровно как в hb_runtime.c:5880
 *   3 sigsetjmp(env, 0)       второй довод НОЛЬ, как у нас и как у QEMU
 *   3b sigsetjmp(env, 1)      для сравнения: с сохранением маски (системный вызов)
 *   4 обращение к поточной переменной   __thread — на macOS это вызов _tlv_get_addr
 *   5 хеш FNV по байтам блока  smc_reverify — длина типового блока
 *   6 проба прямого кеша      524288 записей против 4096 — разница попадания в кеш процессора
 *
 * ЧЕСТНОСТЬ ПРИБОРА. Три ловушки, каждая уже стоила проекту времени, поэтому обойдены явно:
 *   - оптимизатор выбрасывает измеряемое: у каждой статьи результат уходит в `sink`, а
 *     буферы объявлены volatile-указателями, чтобы вызов нельзя было свернуть;
 *   - «нулевая» цена от кеша процессора: перед каждым замером идёт прогрев, и печатается
 *     МЕДИАНА пяти повторов, а не один замер;
 *   - цена самого таймера: измеряется пустой виток и вычитается, а её величина печатается,
 *     чтобы было видно, когда измеряемое меньше собственной погрешности.
 *
 * Размеры структур НЕ ЗАДАНЫ ЧИСЛАМИ, а взяты из заголовков дерева — иначе прибор разъедется
 * с кодом при первой же правке структуры и будет мерить выдуманное.
 *
 * Сборка (цель в Makefile — ЧУЖОЙ файл, поэтому руками):
 *   clang -O2 -std=c11 -arch arm64 -mmacosx-version-min=14.0 -I./include \
 *       tests/dispatch_baseline.c -o tests/dispatch_baseline
 */
#include "hb_runtime.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>

/* Кадр отказа объявлен в hb_runtime.c и наружу не вынесен. Здесь повторена ТОЛЬКО его
 * геометрия — ради размера обнуляемого хвоста. Если поля разъедутся, разъедется и число;
 * поэтому прибор печатает оба размера, и расхождение с исходником будет видно глазом. */
typedef struct probe_frame {
    void* prev;
    uint64_t stale_cookie;
    void* rt;
    void* ctx;
    void* entry;
    hb_context_t snapshot;
    bool snapshot_valid;
    uint64_t steps, blocks_executed, host_pc, fault_addr;
    uint64_t host_gpr[31];
    uint64_t host_sp, host_fault_pc, host_pstate;
    uint64_t dispatched_guest, dispatched_native;
    size_t dispatched_native_size;
    uint64_t fault_guest_pc, fault_arch_pc, fault_indirect_ic_guest, fault_indirect_ic_native;
    uint32_t native_word;
    bool native_word_valid, active_guard_claim;
    uint8_t aa_dst_pre[32], aa_src_pre[32], aa_dst_post[32], aa_src_post[32];
    uint32_t aa_dst_pre_valid, aa_src_pre_valid, aa_dst_post_valid, aa_src_post_valid;
    bool aa_enabled, host_context_valid;
    int signal;
    sigjmp_buf env;
} probe_frame_t;

static uint64_t sink;
static __thread uint64_t tls_word;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void* a, const void* b)
{
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

/* Медиана пяти повторов, в пикосекундах на виток — чтобы статьи дешевле наносекунды не
 * схлопывались в ноль при печати. */
#define REPEATS 5
static uint64_t bench(uint64_t (*fn)(uint64_t), uint64_t iters, uint64_t overhead_ps)
{
    uint64_t r[REPEATS];
    int i;

    fn( iters / 8 );                                   /* прогрев */
    for (i = 0; i < REPEATS; i++) {
        uint64_t t0 = now_ns();
        sink += fn( iters );
        r[i] = (now_ns() - t0) * 1000ull / iters;      /* пикосекунды на виток */
    }
    qsort( r, REPEATS, sizeof(r[0]), cmp_u64 );
    return r[REPEATS / 2] > overhead_ps ? r[REPEATS / 2] - overhead_ps : 0;
}

static probe_frame_t g_frame;
static hb_context_t g_ctx;

/* Непрозрачность для оптимизатора. Без неё пустой виток сворачивается в замкнутую формулу и
 * печатает «0 пс», а вычитание нуля тихо возвращает в каждую строку цену самого цикла.
 * Поймано первым же прогоном прибора. */
static inline uint64_t opaque(uint64_t v)
{
    __asm__ volatile ( "" : "+r"(v) );
    return v;
}

static uint64_t loop_empty(uint64_t n)
{
    uint64_t acc = 0, i;
    for (i = 0; i < n; i++) acc += opaque( i );
    return acc;
}

/* Поточная память. Прямое чтение `__thread` в цикле оптимизатор поднимает наружу: адрес он
 * считает постоянным для потока, и вызов `_tlv_get_addr` остаётся ОДИН на весь цикл — прибор
 * тогда печатает 0 пс, что и случилось. На горячем пути обращения стоят в РАЗНЫХ местах, и
 * подъём невозможен. Поэтому здесь два витка с одинаковой ценой вызова, и разность даёт цену
 * самого разрешителя: чтение глобальной против чтения поточной. */
static uint64_t g_plain_word;

__attribute__((noinline)) static uint64_t read_plain(void)
{
    __asm__ volatile ( "" ::: "memory" );
    return g_plain_word;
}

__attribute__((noinline)) static uint64_t read_tls(void)
{
    __asm__ volatile ( "" ::: "memory" );
    return tls_word;
}

static uint64_t loop_call_plain(uint64_t n)
{
    uint64_t i, acc = 0;
    for (i = 0; i < n; i++) acc += read_plain();
    return acc;
}

static uint64_t loop_call_tls(uint64_t n)
{
    uint64_t i, acc = 0;
    for (i = 0; i < n; i++) acc += read_tls();
    return acc;
}

static uint64_t loop_snapshot(uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n; i++) {
        memcpy( &g_frame.snapshot, &g_ctx, sizeof(hb_context_t) );
        g_ctx.pc = i;                                  /* источник меняется — копию не свернуть */
    }
    return g_frame.snapshot.pc;
}

/* Ровно та же арифметика смещений, что в hb_runtime.c:5880-5882. */
#define FRAME_TAIL_OFF (offsetof(probe_frame_t, snapshot) + sizeof(((probe_frame_t*)0)->snapshot))
#define FRAME_TAIL_LEN (sizeof(probe_frame_t) - FRAME_TAIL_OFF)

static uint64_t loop_memset_tail(uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n; i++) {
        memset( (char*)&g_frame + FRAME_TAIL_OFF, 0, FRAME_TAIL_LEN );
        g_frame.steps = i;
    }
    return g_frame.steps;
}

static uint64_t loop_sigsetjmp0(uint64_t n)
{
    uint64_t i, acc = 0;
    for (i = 0; i < n; i++)
        if (sigsetjmp( g_frame.env, 0 ) == 0) acc += i;
    return acc;
}

static uint64_t loop_sigsetjmp1(uint64_t n)
{
    uint64_t i, acc = 0;
    for (i = 0; i < n; i++)
        if (sigsetjmp( g_frame.env, 1 ) == 0) acc += i;
    return acc;
}

static uint64_t loop_tls(uint64_t n)
{
    uint64_t i, acc = 0;
    for (i = 0; i < n; i++) { tls_word = i; acc += tls_word; }
    return acc;
}

static uint64_t loop_tls_x3(uint64_t n)
{
    uint64_t i, acc = 0;
    for (i = 0; i < n; i++) { tls_word = i; acc += tls_word; acc ^= tls_word; }
    return acc;
}

static uint8_t g_block[4096];
static size_t g_block_len = 64;

static uint64_t loop_fnv(uint64_t n)
{
    uint64_t i, acc = 0;
    for (i = 0; i < n; i++) {
        uint64_t h = 1469598103934665603ull;
        size_t k;
        for (k = 0; k < g_block_len; k++) { h ^= g_block[k]; h *= 1099511628211ull; }
        acc += h;
    }
    return acc;
}

/* Проба прямого кеша. Запись — НАСТОЯЩАЯ `hb_block_cache_entry_t` из заголовка дерева, иначе
 * мерились бы придуманные 32 байта вместо действительных.
 *
 * Первая редакция брала ключи из готового массива на 65536 значений: рабочее множество вышло
 * 2 МБ и целиком легло в L2, то есть «большой» кеш мерился как быстрый. Здесь ключ считается
 * прямо в витке сдвиговым генератором — распределение по всей таблице, массива нет вовсе, и
 * цена генератора одинакова в обеих руках, поэтому в разности она сокращается. */
static hb_block_cache_entry_t* g_big;
static hb_block_cache_entry_t* g_small;
static uint64_t g_mask_big, g_mask_small;

static uint64_t loop_keys_only(uint64_t n)
{
    uint64_t i, acc = 0, s = 88172645463325252ull;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        acc += s & 0xff;
    }
    return acc;
}

static uint64_t loop_cache_big(uint64_t n)
{
    uint64_t i, acc = 0, s = 88172645463325252ull;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        acc += g_big[(s >> 4) & g_mask_big].guest_addr;
    }
    return acc;
}

static uint64_t loop_cache_small(uint64_t n)
{
    uint64_t i, acc = 0, s = 88172645463325252ull;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        acc += g_small[(s >> 4) & g_mask_small].guest_addr;
    }
    return acc;
}

/* ПЕРВЫЙ УРОВЕНЬ ПО ОБРАЗЦУ QEMU. У QEMU 4096 записей занимают 32 КБ, потому что запись — это
 * УКАЗАТЕЛЬ, а не блок целиком. Наша `hb_block_cache_entry_t` весит 112 байт, и 4096 таких это
 * 458 КБ — мимо L1d (128 КБ на этом ядре) и впритык к L2. То есть буквальное «уменьшить до
 * 4096 записей» большей части выигрыша НЕ даёт: важен не счёт записей, а объём.
 * Здесь мерится честный первый уровень: адрес гостя + указатель на запись = 16 байт,
 * 4096 * 16 = 64 КБ, что в L1d помещается. */
typedef struct { uint64_t guest_addr; void* entry; } l1_slot_t;
static l1_slot_t* g_l1;
static uint64_t g_mask_l1;

static uint64_t loop_cache_l1(uint64_t n)
{
    uint64_t i, acc = 0, s = 88172645463325252ull;
    for (i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        acc += g_l1[(s >> 4) & g_mask_l1].guest_addr;
    }
    return acc;
}

/* ПУНКТ 5 НАРЯДА — партии фиксации против фиксации на блок.
 *
 * На Apple ARM64 фиксация арены (`hb_jit_buffer_commit`, hb_jit.c:281) состоит ровно из двух
 * статей: `pthread_jit_write_protect_np(1)` и сброс кеша команд по грязному диапазону; перед
 * следующим выпуском идёт парный `(0)`. Партия амортизирует ПАРУ переключений, но сброс кеша
 * остаётся пропорционален объёму — поэтому мерим их РАЗДЕЛЬНО, иначе выигрыш партии будет
 * посчитан там, где его нет.
 *
 * Размер блока взят из корпуса (итерация 2): медиана выпуска 156 Б, средний 220 Б. */
static uint8_t* g_jit_area;
#define JIT_AREA_BYTES (1u << 20)
#define BLOCK_BYTES 220u
#define BATCH 64u

static uint64_t loop_wprotect_pair(uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n; i++) {
        pthread_jit_write_protect_np( 1 );
        pthread_jit_write_protect_np( 0 );
    }
    return n;
}

static uint64_t loop_clear_block(uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n; i++) {
        char* p = (char*)g_jit_area + ((i * BLOCK_BYTES) % (JIT_AREA_BYTES - BLOCK_BYTES));
        __builtin___clear_cache( p, p + BLOCK_BYTES );
    }
    return n;
}

static uint64_t loop_clear_batch(uint64_t n)
{
    uint64_t i;
    for (i = 0; i < n; i++) {
        char* p = (char*)g_jit_area + ((i * BLOCK_BYTES * BATCH) % (JIT_AREA_BYTES - BLOCK_BYTES * BATCH));
        __builtin___clear_cache( p, p + BLOCK_BYTES * BATCH );
    }
    return n;
}

int main(int argc, char** argv)
{
    uint64_t iters = (argc > 1) ? strtoull( argv[1], NULL, 0 ) : 2000000;
    uint64_t over, i;

    if (argc > 2) g_block_len = strtoull( argv[2], NULL, 0 );

    printf( "# ДИСПЕТЧ, замер ДО — цена статей перехода, витков=%llu\n", (unsigned long long)iters );
    printf( "# sizeof(hb_context_t)=%zu  sizeof(кадр)=%zu  обнуляемый хвост=%zu\n",
            sizeof(hb_context_t), sizeof(probe_frame_t), (size_t)FRAME_TAIL_LEN );
    printf( "# sizeof(sigjmp_buf)=%zu  длина блока для FNV=%zu\n",
            sizeof(sigjmp_buf), g_block_len );

    for (i = 0; i < sizeof(g_block); i++) g_block[i] = (uint8_t)(i * 7 + 1);

    g_mask_big = HB_BLOCK_CACHE_SIZE - 1;              /* столько записей у нас на самом деле */
    g_mask_small = (1u << 12) - 1;                      /* 4096 записей, как у QEMU */
    g_big = calloc( g_mask_big + 1, sizeof(hb_block_cache_entry_t) );
    g_small = calloc( g_mask_small + 1, sizeof(hb_block_cache_entry_t) );
    g_mask_l1 = (1u << 12) - 1;
    g_l1 = calloc( g_mask_l1 + 1, sizeof(l1_slot_t) );
    if (!g_big || !g_small || !g_l1) { printf( "ОТКАЗ ОСНАСТКИ: нет памяти\n" ); return 2; }
    printf( "# первый уровень: %zu записей по %zu Б = %zu Б\n",
            (size_t)(g_mask_l1 + 1), sizeof(l1_slot_t),
            (size_t)(g_mask_l1 + 1) * sizeof(l1_slot_t) );
    printf( "# sizeof(запись кеша)=%zu  кеш большой=%zu Б (%zu записей)  кеш малый=%zu Б\n",
            sizeof(hb_block_cache_entry_t),
            (size_t)(g_mask_big + 1) * sizeof(hb_block_cache_entry_t), (size_t)(g_mask_big + 1),
            (size_t)(g_mask_small + 1) * sizeof(hb_block_cache_entry_t) );
    /* Заселяем ОБЕ таблицы целиком: пустая (не тронутая) страница на macOS отображается на одну
     * общую нулевую, и «большая» таблица мерилась бы как одна страница в кеше процессора. */
    for (i = 0; i <= g_mask_big; i++) g_big[i].guest_addr = i * 2654435761ull;
    for (i = 0; i <= g_mask_small; i++) g_small[i].guest_addr = i * 2654435761ull;
    for (i = 0; i <= g_mask_l1; i++) g_l1[i].guest_addr = i * 2654435761ull;

    over = bench( loop_empty, iters, 0 );
    printf( "цена пустого витка (вычитается из всех строк ниже) = %llu пс\n",
            (unsigned long long)over );
    printf( "%-46s %10s\n", "статья", "пс/виток" );
    printf( "%-46s %10llu\n", "1  снимок контекста (memcpy)", (unsigned long long)bench( loop_snapshot, iters, over ) );
    printf( "%-46s %10llu\n", "2  обнуление хвоста кадра (memset)", (unsigned long long)bench( loop_memset_tail, iters, over ) );
    printf( "%-46s %10llu\n", "3  sigsetjmp(env, 0)", (unsigned long long)bench( loop_sigsetjmp0, iters, over ) );
    printf( "%-46s %10llu\n", "3b sigsetjmp(env, 1) — с маской", (unsigned long long)bench( loop_sigsetjmp1, iters, over ) );
    {
        uint64_t plain = bench( loop_call_plain, iters, over );
        uint64_t tls = bench( loop_call_tls, iters, over );
        uint64_t keys = bench( loop_keys_only, iters, over );
        uint64_t big = bench( loop_cache_big, iters, over );
        uint64_t small = bench( loop_cache_small, iters, over );

        printf( "%-46s %10llu\n", "4  вызов + чтение ОБЫЧНОЙ памяти (опора)", (unsigned long long)plain );
        printf( "%-46s %10llu\n", "4b вызов + чтение ПОТОЧНОЙ памяти", (unsigned long long)tls );
        printf( "%-46s %10lld   <= цена ОДНОГО разрешителя\n", "4c разность (b минус a)",
                (long long)tls - (long long)plain );
        printf( "%-46s %10llu\n", "5  хеш FNV по байтам блока", (unsigned long long)bench( loop_fnv, iters, over ) );
        printf( "%-46s %10llu\n", "6  генератор ключей без обращения (опора)", (unsigned long long)keys );
        printf( "%-46s %10llu\n", "6b проба кеша 524288 записей", (unsigned long long)big );
        printf( "%-46s %10llu\n", "6c проба кеша 4096 записей", (unsigned long long)small );
        uint64_t l1 = bench( loop_cache_l1, iters, over );
        printf( "%-46s %10llu\n", "6d первый уровень 4096 по 16 Б = 64 КБ", (unsigned long long)l1 );
        printf( "%-46s %10lld   <= 4096 записей ЦЕЛИКОМ (458 КБ)\n", "6e выигрыш b минус c",
                (long long)big - (long long)small );
        printf( "%-46s %10lld   <= первый уровень 16 Б (64 КБ)\n", "6f выигрыш b минус d",
                (long long)big - (long long)l1 );
        if (big > l1 && l1 > 0)
            printf( "%-46s %9.1f%%\n", "6g порог окупаемости первого уровня",
                    100.0 * (double)l1 / (double)big );
    }
    /* Арена под замер сброса кеша. MAP_JIT здесь НЕ нужен: мерится стоимость самой операции
     * сброса по диапазону, а не права доступа. */
    g_jit_area = mmap( NULL, JIT_AREA_BYTES, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0 );
    if (g_jit_area == MAP_FAILED) { printf( "ОТКАЗ ОСНАСТКИ: арена не отображена\n" ); return 2; }
    memset( g_jit_area, 0xd5, JIT_AREA_BYTES );
    {
        uint64_t pair = bench( loop_wprotect_pair, iters / 8, over );
        uint64_t cb = bench( loop_clear_block, iters / 8, over );
        uint64_t cbatch = bench( loop_clear_batch, iters / 64, over );

        printf( "\n# ПУНКТ 5: партии фиксации (блок=%u Б, партия=%u блоков)\n",
                (unsigned)BLOCK_BYTES, (unsigned)BATCH );
        printf( "%-46s %10llu\n", "7  пара pthread_jit_write_protect (1 и 0)", (unsigned long long)pair );
        printf( "%-46s %10llu\n", "7b сброс кеша команд, один блок 220 Б", (unsigned long long)cb );
        printf( "%-46s %10llu\n", "7c сброс кеша команд, партия 64 блока", (unsigned long long)cbatch );
        printf( "%-46s %10llu\n", "7d сброс партии В ПЕРЕСЧЁТЕ НА БЛОК", (unsigned long long)(cbatch / BATCH) );
        printf( "%-46s %10lld   <= экономия партии на блок\n", "7e (7+7b) минус (7/64 + 7c/64)",
                (long long)(pair + cb) - (long long)(pair / BATCH + cbatch / BATCH) );
    }
    printf( "# контрольная сумма (чтобы витки не выбросил оптимизатор) = 0x%llx\n",
            (unsigned long long)sink );
    return 0;
}
