// Curator probe 05.10.2026: does Darwin madvise(MADV_DONTNEED) zero private anonymous memory (as Linux does),
// and can the last page of a MAP_JIT region be made PROT_NONE with mprotect?
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

static size_t count_a5(const unsigned char *c, size_t n) {
  size_t same = 0;
  for (size_t i = 0; i < n; i++) if (c[i] == 0xA5) same++;
  return same;
}

static void check_advice(const char *name, void *p, size_t n, int advice) {
  memset(p, 0xA5, n);
  errno = 0;
  int rc = madvise(p, n, advice);
  int e = errno;
  printf("%-28s rc=%d errno=%d bytes_still_A5=%zu of %zu\n", name, rc, rc ? e : 0, count_a5(p, n), n);
}

int main(void) {
  size_t pg = (size_t)sysconf(_SC_PAGESIZE);
  size_t n = pg * 64;
  printf("host page size %zu\n", pg);
  void *p = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (p == MAP_FAILED) { printf("mmap failed errno=%d\n", errno); return 1; }
  check_advice("anon MADV_DONTNEED", p, n, MADV_DONTNEED);
  check_advice("anon MADV_FREE", p, n, MADV_FREE);
  memset(p, 0xA5, n);
  void *q = mmap(p, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
  printf("%-28s same_addr=%d bytes_still_A5=%zu of %zu\n", "anon MAP_FIXED remap", q == p, count_a5(p, n), n);

  void *j = mmap(0, n, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
  if (j == MAP_FAILED) {
    printf("MAP_JIT mmap failed errno=%d\n", errno);
  } else {
    errno = 0;
    int rc = mprotect((char *)j + n - pg, pg, PROT_NONE);
    printf("%-28s rc=%d errno=%d\n", "MAP_JIT last page PROT_NONE", rc, rc ? errno : 0);
    errno = 0;
    rc = mprotect((char *)j + n - pg, pg, PROT_READ);
    printf("%-28s rc=%d errno=%d\n", "MAP_JIT last page PROT_READ", rc, rc ? errno : 0);
    errno = 0;
    rc = madvise(j, n, MADV_DONTNEED);
    printf("%-28s rc=%d errno=%d\n", "MAP_JIT MADV_DONTNEED", rc, rc ? errno : 0);
  }
  errno = 0;
  int rc = mprotect((char *)p + n - pg, pg, PROT_NONE);
  printf("%-28s rc=%d errno=%d\n", "plain anon last page NONE", rc, rc ? errno : 0);
  return 0;
}
