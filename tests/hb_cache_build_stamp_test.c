/* ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ОТПЕЧАТКА СБОРКИ В ФАЙЛЕ ПОСТОЯННОГО КЕША.
 *
 * MacRunner 2026-09-06, лейн КЕШ.
 *
 * ЗАЧЕМ. До 06.09 заголовок `translation-cache.bin` нёс magic + версию формата + константу
 * `HB_AOT_ABI`. Все три — величины ВРЕМЕНИ КОМПИЛЯЦИИ, одинаковые у любых двух сборок
 * движка. Файл, записанный ДРУГОЙ сборкой, проходил проверку заголовка, и его записи
 * попадали в поиск. Разделение по сборкам держалось на дисциплине вызывающего
 * (`scripts/laneA-run-hk.sh:9-12` делает корень по SHA ntdll.so), а лейны A/B задают корень
 * СВОИМ именем — такой корень переживает пересборку движка молча.
 *
 * ЧТО ПРОВЕРЯЕТСЯ. Три случая, и третий — тот самый отрицательный контроль, без которого
 * первые два ничего не значат:
 *
 *   1. СВОЙ файл читается: записал -> закрыл -> открыл -> запись на месте.
 *      Это положительный контроль: он говорит, что стенд вообще умеет видеть попадание,
 *      и потому ноль в случае 3 — свойство отказа, а не немощь стенда.
 *   2. Поле `reserved` заголовка ненулевое и одинаково у двух записей одной сборки.
 *      Ноль означал бы, что отпечаток не пишется вовсе (ровно прежнее поведение), а
 *      разные значения — что он не детерминирован.
 *   3. ЧУЖАЯ СБОРКА ОТВЕРГАЕТСЯ: тот же файл с подделанным `reserved` даёт НОЛЬ записей.
 *      Подделка — четыре байта по смещению 12, то есть проверяется именно поле сборки,
 *      а не «испортили файл вообще»: magic, версия формата и ABI остаются верными.
 *
 * ГРАНИЦА. Стенд проверяет ЗАГОЛОВОК файла. Второй рубеж — номер в ключе КАЖДОЙ записи
 * (`persistent_cache_version()` в hb_runtime.c, туда отпечаток внесён тем же заходом) —
 * здесь не проверяется: он наблюдается отдельно через `tests/hb_cache_key_version_test`.
 */
#include "hb_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int failures;

static void ok(const char* what, int cond) {
    printf("  %-58s %s\n", what, cond ? "ok" : "PROVAL");
    if (!cond) failures++;
}

static void make_key(hb_cache_key_t* k, uint64_t addr) {
    memset(k, 0, sizeof(*k));
    k->version = 1;
    k->abi_version = 1;
    k->arch = 1;
    k->code_hash = 0xfeedfaceull ^ addr;
    k->guest_addr = addr;
    k->code_len = 16;
}

/* Смещение поля `reserved` в hb_aot_header_t: magic[4] + version[4] + abi_version[4]. */
#define HDR_RESERVED_OFF 12

static int read_reserved(const char* path, unsigned* out) {
    FILE* f = fopen(path, "rb");
    unsigned v = 0;
    if (!f) return 0;
    if (fseek(f, HDR_RESERVED_OFF, SEEK_SET) != 0) { fclose(f); return 0; }
    if (fread(&v, sizeof(v), 1, f) != 1) { fclose(f); return 0; }
    fclose(f);
    *out = v;
    return 1;
}

static int poke_reserved(const char* path, unsigned v) {
    FILE* f = fopen(path, "r+b");
    if (!f) return 0;
    if (fseek(f, HDR_RESERVED_OFF, SEEK_SET) != 0) { fclose(f); return 0; }
    if (fwrite(&v, sizeof(v), 1, f) != 1) { fclose(f); return 0; }
    fclose(f);
    return 1;
}

/* Открыть корень и сказать, видна ли запись по адресу `addr`. */
static int entry_visible(const char* root, uint64_t addr) {
    hb_cache_t* c = hb_cache_open(root, NULL);
    hb_cache_key_t k;
    hb_cache_entry_t* got = NULL;
    int seen;
    if (!c) return -1;
    make_key(&k, addr);
    seen = (hb_cache_get(c, &k, &got) == HB_OK && got != NULL);
    if (got) hb_cache_entry_free(got);
    hb_cache_close(c);
    return seen;
}

int main(void) {
    char root[256], path[320];
    const uint8_t blob[8] = { 0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6 };
    unsigned mine = 0, mine2 = 0;
    hb_cache_t* c;
    hb_cache_key_t k;

    snprintf(root, sizeof(root), "/tmp/hb-cache-stamp-test-%ld", (long)getpid());
    snprintf(path, sizeof(path), "%s/translation-cache.bin", root);
    mkdir(root, 0755);

    printf("Otpechatok sborki v zagolovke kesha\n");

    /* --- 1. записать и закрыть --------------------------------------------------------- */
    c = hb_cache_open(root, NULL);
    ok("kesh otkryt", c != NULL);
    if (!c) return 1;
    make_key(&k, 0x140001000ull);
    ok("zapis' polozhena", hb_cache_store(c, &k, blob, sizeof(blob), NULL) == HB_OK);
    hb_cache_close(c);

    /* --- 2. отпечаток в файле есть и он устойчив ---------------------------------------- */
    ok("reserved prochitan", read_reserved(path, &mine));
    ok("reserved NE nol' (otpechatok pishetsya)", mine != 0);

    /* --- 1'. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: своя сборка запись видит ---------------------------- */
    ok("svoya sborka: zapis' vidna", entry_visible(root, 0x140001000ull) == 1);

    /* Повторное открытие/запись не меняет отпечаток. */
    c = hb_cache_open(root, NULL);
    if (c) {
        make_key(&k, 0x140002000ull);
        hb_cache_store(c, &k, blob, sizeof(blob), NULL);
        hb_cache_close(c);
    }
    ok("reserved prochitan povtorno", read_reserved(path, &mine2));
    ok("otpechatok ustojchiv mezhdu otkrytiyami", mine == mine2);

    /* --- 3. ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: чужая сборка отвергается ---------------------------- */
    ok("reserved podmenen na chuzhoj", poke_reserved(path, mine ^ 0xa5a5a5a5u));
    ok("chuzhaya sborka: zapis' NE vidna", entry_visible(root, 0x140001000ull) == 0);

    /* --- 4. возврат своего отпечатка снова даёт попадание --------------------------------
     * Без этого шага «не видна» могло бы означать «файл разрушен подделкой». Он не разрушен:
     * вернули четыре байта — запись снова на месте. Значит отвергает ИМЕННО поле сборки.
     * ★ Порядок важен: hb_cache_open с чужим отпечатком ПЕРЕЗАПИСЫВАЕТ файл пустым
     * заголовком (ensure_file), поэтому проверять надо на копии. */
    {
        char copy[320], copy_root[256];
        FILE* in; FILE* out; int ch;
        snprintf(copy_root, sizeof(copy_root), "%s-copy", root);
        snprintf(copy, sizeof(copy), "%s/translation-cache.bin", copy_root);
        mkdir(copy_root, 0755);
        /* заново наполнить исходный корень (его затёрло открытие с чужим отпечатком) */
        c = hb_cache_open(root, NULL);
        if (c) { make_key(&k, 0x140003000ull); hb_cache_store(c, &k, blob, sizeof(blob), NULL); hb_cache_close(c); }
        in = fopen(path, "rb"); out = fopen(copy, "wb");
        if (in && out) { while ((ch = fgetc(in)) != EOF) fputc(ch, out); }
        if (in) fclose(in);
        if (out) fclose(out);
        ok("kopiya so SVOIM otpechatkom: zapis' vidna", entry_visible(copy_root, 0x140003000ull) == 1);
        ok("ta zhe kopiya s CHUZHIM otpechatkom: ne vidna",
           poke_reserved(copy, mine ^ 0x5a5a5a5au) && entry_visible(copy_root, 0x140003000ull) == 0);
        unlink(copy); rmdir(copy_root);
    }

    unlink(path);
    rmdir(root);

    printf("\n%d proverok ne proshlo\n", failures);
    return failures ? 1 : 0;
}
