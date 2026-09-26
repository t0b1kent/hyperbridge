/* hb_memory_unmap_range и hb_memory_read_nofault (26.09.2026).
 *
 * Снятие по диапазону: середина области, повтор (нечего снимать), смещённая база.
 * Чтение для нужд транслятора: по странице, которую карта HB ещё считает читаемой, а хозяин
 * уже снял, — ошибка, а не сигнал. Контроль в дочернем процессе: то же чтение обычным
 * hb_memory_read убивает процесс (так обрывался HK на 42-й секунде: _platform_memmove <-
 * hb_memory_read_inner, 206 байт по освобождённой области). */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "hb_memory.h"

static int passed, failed;
#define CHECK(c, msg) do { if (c) passed++; else { failed++; printf("FAIL %s\n", msg); } } while (0)

int main(void) {
    const size_t P = 16384, N = 8 * P;
    uint8_t* host = mmap(NULL, N, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    hb_memory_t* m = hb_memory_create(0);
    hb_gva_t A = (hb_gva_t)(uintptr_t)host;
    uint8_t buf[256];

    if (host == MAP_FAILED || !m) { printf("setup failed\n"); return 2; }
    memset(host, 0x5a, N);
    CHECK(hb_memory_sync_live_range(m, A, N, HB_PERM_READ | HB_PERM_WRITE) == HB_OK, "sync");

    CHECK(hb_memory_unmap_range(m, A + 2 * P, 2 * P) == HB_OK, "unmap middle");
    CHECK(hb_memory_find_region(m, A) != NULL, "left part kept");
    CHECK(hb_memory_find_region(m, A + 2 * P) == NULL, "middle gone at its start");
    CHECK(hb_memory_find_region(m, A + 4 * P - 1) == NULL, "middle gone at its end");
    CHECK(hb_memory_find_region(m, A + 4 * P) != NULL, "right part kept");
    CHECK(hb_memory_unmap_range(m, A + 2 * P, 2 * P) == HB_ERR_NOT_FOUND, "nothing left to unmap");
    CHECK(hb_memory_unmap_range(m, A + 5 * P + 100, P - 100) == HB_OK, "unmap with an unaligned base");
    CHECK(hb_memory_find_region(m, A + 5 * P) == NULL, "unaligned base covers its page");
    CHECK(hb_memory_find_region(m, A + 6 * P) != NULL, "page after the range kept");

    CHECK(hb_memory_read_nofault(m, A + 100, buf, 200) == HB_OK && buf[0] == 0x5a, "live read");
    CHECK(hb_memory_read_nofault(m, A + 2 * P, buf, 16) == HB_ERR_MEMORY_FAULT, "read of an unmapped range");
    munmap(host + 7 * P, P);                      /* the map of HB still says [A+6P, A+8P) is readable */
    CHECK(hb_memory_read_nofault(m, A + 7 * P, buf, 206) == HB_ERR_MEMORY_FAULT, "host page gone -> error");
    CHECK(hb_memory_read_nofault(m, A + 7 * P - 50, buf, 100) == HB_ERR_MEMORY_FAULT, "span into the gone page -> error");

#ifdef __APPLE__
    {
        pid_t pid = fork();
        int st = 0;
        if (pid == 0) {
            (void)hb_memory_read(m, A + 7 * P, buf, 206);
            _exit(0);
        }
        waitpid(pid, &st, 0);
        CHECK(WIFSIGNALED(st), "control: plain hb_memory_read of the same page dies by a signal");
    }
#endif
    printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
