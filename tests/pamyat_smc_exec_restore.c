/* MacRunner 2026-08-16, лейн ПАМЯТЬ — ВОЗВРАТ ПРАВА ИСПОЛНЕНИЯ ПОСЛЕ ЗАПИСИ (вторая половина
 * самоизменения).
 *
 * Зачем. В итоге ступени 7 записано: «восстановление права исполнения после отпускания страницы
 * живёт в hb_runtime.c и ТРЕБУЕТ ПРОГОНА». Входящее (пункт 8) велит проверить, точно ли требует.
 * Проверяю — и оказывается, что вопрос ХОСТОВЫЙ: умеет ли macOS вернуть право исполнения странице,
 * с которой оно было снято ради записи. Ответ виден без wine, без гостя и без игры.
 *
 * Что меряется — четыре дороги, все на обычной анонимной памяти:
 *   A  R|X  ->  R|W  (снять исполнение ради записи)  ->  R|X  (вернуть)   — путь SMC
 *   B  R|X  ->  R|W|X                                                     — прямой возврат
 *   C  то же, но страница выделена с MAP_JIT
 *   D  контроль: исполняем код ДО и ПОСЛЕ, чтобы «право вернулось» значило исполнение,
 *      а не только успешный код возврата mprotect
 *
 * Правило 3 входящего: окно должно открыться. Поэтому дорога D исполняет настоящую команду
 * `ret` и печатает, что она отработала: без этого «mprotect вернул 0» не доказывает НИЧЕГО.
 *
 * Сборка:  make -C engine/hyperbridge tests/pamyat_smc_exec_restore && ./tests/pamyat_smc_exec_restore
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#endif

typedef void (*fn_t)(void);

/* `ret` для ARM64 — одна команда. Кладём её в страницу и зовём: только исполнение доказывает,
 * что право ИСПОЛНЕНИЯ действительно вернулось. */
static const uint32_t RET_INSN = 0xd65f03c0u;

static const char *ok(int rc) { return rc == 0 ? "ok" : "ОТКАЗ"; }

static int попытка(void *p, size_t n, int prot, const char *имя)
{
    int rc = mprotect(p, n, prot);
    printf("    mprotect(%-9s) = %-5s%s\n", имя, ok(rc),
           rc ? (errno == EACCES ? "  (EACCES — W^X)"
                                 : (errno == EINVAL ? "  (EINVAL)" : "")) : "");
    return rc;
}

static int исполнить(void *p, const char *где)
{
    fn_t f = (fn_t)p;

    /* Если исполнение запрещено — упадём; это и есть проверка. Ловить сигнал здесь не буду:
     * дорога вызывается ТОЛЬКО когда mprotect вернул 0, то есть право по учёту хоста есть.
     * Падение в этом месте само по себе было бы результатом и его видно по коду выхода. */
    f();
    printf("    исполнение %-12s ПРОШЛО\n", где);
    return 1;
}

int main(void)
{
    size_t n = (size_t)getpagesize();
    int итог = 0;

    printf("проба возврата права исполнения; хостовая страница %zu Б\n", n);

    /* --- A: R|X -> R|W -> R|X, с исполнением на обоих концах ------------------------------ */
    {
        void *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

        printf("  A. R|W -> код -> R|X -> исполнить -> R|W -> переписать -> R|X -> исполнить\n");
        if (p == MAP_FAILED) { printf("    ПРОПУСК: mmap отказал (%d)\n", errno); }
        else {
            memcpy(p, &RET_INSN, sizeof(RET_INSN));
#if defined(__APPLE__)
            sys_icache_invalidate(p, sizeof(RET_INSN));
#endif
            if (попытка(p, n, PROT_READ | PROT_EXEC, "R|X") == 0) {
                исполнить(p, "первое");
                if (попытка(p, n, PROT_READ | PROT_WRITE, "R|W") == 0) {
                    memcpy(p, &RET_INSN, sizeof(RET_INSN));   /* «гость переписал код» */
                    if (попытка(p, n, PROT_READ | PROT_EXEC, "R|X снова") == 0) {
#if defined(__APPLE__)
                        sys_icache_invalidate(p, sizeof(RET_INSN));
#endif
                        исполнить(p, "после записи");
                        итог |= 1;
                    }
                }
            }
            munmap(p, n);
        }
    }

    /* --- B: прямой R|W|X на обычной странице ---------------------------------------------- */
    {
        void *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

        printf("  B. прямой R|W|X (без MAP_JIT)\n");
        if (p == MAP_FAILED) printf("    ПРОПУСК: mmap отказал (%d)\n", errno);
        else { (void)попытка(p, n, PROT_READ | PROT_WRITE | PROT_EXEC, "R|W|X"); munmap(p, n); }
    }

    /* --- C: то же с MAP_JIT ---------------------------------------------------------------- */
    {
#if defined(MAP_JIT)
        void *p = mmap(NULL, n, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);

        printf("  C. MAP_JIT: R|W|X сразу при отображении\n");
        if (p == MAP_FAILED) printf("    ПРОПУСК: mmap(MAP_JIT) отказал (%d)\n", errno);
        else {
            printf("    mmap(MAP_JIT, R|W|X) = ok\n");
            /* Запись в такую страницу требует переключения защиты потока. */
            pthread_jit_write_protect_np(0);
            memcpy(p, &RET_INSN, sizeof(RET_INSN));
            pthread_jit_write_protect_np(1);
#if defined(__APPLE__)
            sys_icache_invalidate(p, sizeof(RET_INSN));
#endif
            исполнить(p, "MAP_JIT");
            итог |= 2;
            munmap(p, n);
        }
#else
        printf("  C. ПРОПУСК: MAP_JIT не объявлен\n");
#endif
    }

    printf("итог: путь SMC (A) %s, путь MAP_JIT (C) %s\n",
           (итог & 1) ? "РАБОТАЕТ" : "не подтверждён",
           (итог & 2) ? "РАБОТАЕТ" : "не подтверждён");
    return 0;
}
