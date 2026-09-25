#include "hb_contract_telemetry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
        return; \
    } \
} while (0)

static int contains(const char* text, const char* needle) {
    return text && needle && strstr(text, needle) != NULL;
}

static void test_disabled_default_behavior(void) {
    hb_contract_telemetry_counts_t counts;
    FILE* f;

    unsetenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE");
    hb_contract_telemetry_reset_for_test();
    hb_contract_telemetry_record_open(true);
    hb_contract_telemetry_record_cache_hit(16);
    hb_contract_telemetry_record_compile();
    hb_contract_telemetry_record_translation(true);
    hb_contract_telemetry_record_dispatch(1, 2, 3);
    hb_contract_telemetry_snapshot(&counts);
    CHECK(counts.open_ok == 0);
    CHECK(counts.hits == 0);
    CHECK(counts.compile_count == 0);
    CHECK(counts.translation_count == 0);
    CHECK(counts.dispatches == 0);

    f = tmpfile();
    CHECK(f != NULL);
    CHECK(hb_contract_telemetry_emit_summary(f) == 0);
    CHECK(ftell(f) == 0);
    fclose(f);

    setenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE", "0", 1);
    hb_contract_telemetry_reset_for_test();
    hb_contract_telemetry_record_open(false);
    hb_contract_telemetry_snapshot(&counts);
    CHECK(counts.open_fail == 0);
    unsetenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE");
}

static void test_counter_accounting_and_format(void) {
    hb_contract_telemetry_counts_t counts;
    char line[512];

    setenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE", "1", 1);
    hb_contract_telemetry_reset_for_test();
    hb_contract_telemetry_record_open(true);
    hb_contract_telemetry_record_open(false);
    hb_contract_telemetry_record_cache_hit(32);
    hb_contract_telemetry_record_cache_miss();
    hb_contract_telemetry_record_cache_store(64);
    hb_contract_telemetry_record_cache_store_skip();
    hb_contract_telemetry_record_compile();
    hb_contract_telemetry_record_compile();
    hb_contract_telemetry_record_translation(true);
    hb_contract_telemetry_record_translation(false);
    hb_contract_telemetry_record_dispatch(3, 4, 5);
    hb_contract_telemetry_record_dispatch(7, 11, 13);

    hb_contract_telemetry_snapshot(&counts);
    CHECK(counts.open_ok == 1);
    CHECK(counts.open_fail == 1);
    CHECK(counts.hits == 1);
    CHECK(counts.misses == 1);
    CHECK(counts.stores == 1);
    CHECK(counts.store_skips == 1);
    CHECK(counts.bytes_loaded == 32);
    CHECK(counts.bytes_stored == 64);
    CHECK(counts.compile_count == 2);
    CHECK(counts.translation_count == 2);
    CHECK(counts.distinct_translation_count == 1);
    CHECK(counts.dispatches == 10);
    CHECK(counts.blocks == 15);
    CHECK(counts.steps == 18);

    CHECK(hb_contract_telemetry_format_summary(line, sizeof(line), &counts) > 0);
    CHECK(contains(line, "open_ok=1 open_fail=1"));
    CHECK(contains(line, "compile_count=2 translation_count=2 distinct_translation_count=1"));
    CHECK(contains(line, "dispatches=10 blocks=15 steps=18"));
    unsetenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE");
}

static void test_one_summary(void) {
    char buf[1024];
    FILE* f;
    size_t n;

    setenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE", "1", 1);
    hb_contract_telemetry_reset_for_test();
    hb_contract_telemetry_record_open(true);
    hb_contract_telemetry_record_cache_miss();
    f = tmpfile();
    CHECK(f != NULL);
    CHECK(hb_contract_telemetry_emit_summary(f) == 1);
    CHECK(hb_contract_telemetry_emit_summary(f) == 0);
    rewind(f);
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    CHECK(contains(buf, "macrunner-hb-translation-cache-summary:"));
    CHECK(strstr(buf, "\n") == strrchr(buf, '\n'));
    CHECK(contains(buf, "open_ok=1"));
    CHECK(contains(buf, "misses=1"));
    unsetenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE");
}

static void test_atexit_final_flush(void) {
    int fds[2];
    pid_t pid;
    char buf[1024];
    ssize_t n;
    int status = 0;

    CHECK(pipe(fds) == 0);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        setenv("MACRUNNER_HB_TRACE_TRANSLATION_CACHE", "1", 1);
        hb_contract_telemetry_reset_for_test();
        hb_contract_telemetry_record_open(true);
        hb_contract_telemetry_record_compile();
        hb_contract_telemetry_record_translation(true);
        hb_contract_telemetry_register_atexit();
        exit(0);
    }

    close(fds[1]);
    n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(n > 0);
    buf[n] = 0;
    CHECK(contains(buf, "macrunner-hb-translation-cache-summary:"));
    CHECK(contains(buf, "open_ok=1"));
    CHECK(contains(buf, "compile_count=1 translation_count=1 distinct_translation_count=1"));
}

int main(void) {
    test_disabled_default_behavior();
    test_counter_accounting_and_format();
    test_one_summary();
    test_atexit_final_flush();
    if (failures) {
        fprintf(stderr, "%d failed\n", failures);
        return 1;
    }
    printf("hb_contract_telemetry_test: 4 passed\n");
    return 0;
}
