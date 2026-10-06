/* xbench.c — x86-64 microbenchmark for comparing x86 emulators (Prism, FEX under our Wine, FEX in CrossOver).
 * Each test is a tight inline-asm loop of one idiom; the result is nanoseconds per iteration (loop overhead included,
 * see "empty"). Every test runs 5 times after a calibration pass; the median and the minimum are printed.
 * Tests that need a CPUID feature (SSE4.2 crc32) are skipped when the feature is not advertised.
 * Output lines start with "bench:". Build: x86_64-w64-mingw32-clang -O2 -static. */
/* Linux timing/measurement wrapper and five additional x87 loops: MIT.
 * Original benchmark function bodies below are unchanged from input/xbench.c. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <cpuid.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*bench_fn)(uint64_t n);

static volatile uint64_t g_sink;
static uint32_t g_mem[16] __attribute__((aligned(64)));
static uint8_t g_src[4096] __attribute__((aligned(64)));
static uint8_t g_dst[4096] __attribute__((aligned(64)));
static const float g_f = 123.625f;
static const double g_d = 12345.625;

static void b_empty(uint64_t n) { __asm__ volatile("1: dec %0\n\tjnz 1b" : "+r"(n) :: "cc"); }

static void b_add(uint64_t n)
{
    uint64_t a = 0;
    __asm__ volatile("1: add $3, %0\n\tdec %1\n\tjnz 1b" : "+r"(a), "+r"(n) :: "cc");
    g_sink = a;
}

static void b_imul(uint64_t n)
{
    uint64_t a = 1, m = 3;
    __asm__ volatile("1: imul %2, %0\n\tdec %1\n\tjnz 1b" : "+r"(a), "+r"(n) : "r"(m) : "cc");
    g_sink = a;
}

static void b_cvttss2si(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("movss %2, %%xmm0\n\t"
                     "1: cvttss2si %%xmm0, %%eax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) : "m"(g_f) : "rax", "xmm0", "cc");
    g_sink = acc;
}

static void b_cvtss2si(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("movss %2, %%xmm0\n\t"
                     "1: cvtss2si %%xmm0, %%eax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) : "m"(g_f) : "rax", "xmm0", "cc");
    g_sink = acc;
}

static void b_cvttsd2si64(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("movsd %2, %%xmm0\n\t"
                     "1: cvttsd2si %%xmm0, %%rax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) : "m"(g_d) : "rax", "xmm0", "cc");
    g_sink = acc;
}

static void b_cvttps2dq(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm0\n\tshufps $0, %%xmm0, %%xmm0\n\tpxor %%xmm2, %%xmm2\n\t"
                     "1: cvttps2dq %%xmm0, %%xmm1\n\tpaddd %%xmm1, %%xmm2\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm2, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "xmm2", "cc", "memory");
}

static void b_cvtdq2ps(uint64_t n)
{
    __asm__ volatile("pcmpeqd %%xmm0, %%xmm0\n\txorps %%xmm2, %%xmm2\n\t"
                     "1: cvtdq2ps %%xmm0, %%xmm1\n\taddps %%xmm1, %%xmm2\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm2, %%eax\n\tmov %%eax, %1"
                     : "+r"(n) : "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "xmm2", "cc", "memory");
}

static void b_addsubps(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm1\n\tshufps $0, %%xmm1, %%xmm1\n\txorps %%xmm0, %%xmm0\n\t"
                     "1: addsubps %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_addss(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm1\n\txorps %%xmm0, %%xmm0\n\t"
                     "1: addss %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_mulps(uint64_t n)
{
    __asm__ volatile("movss %1, %%xmm1\n\tshufps $0, %%xmm1, %%xmm1\n\tmovaps %%xmm1, %%xmm0\n\t"
                     "1: mulps %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %2"
                     : "+r"(n) : "m"(g_f), "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_pshufb(uint64_t n)
{
    __asm__ volatile("pcmpeqd %%xmm1, %%xmm1\n\tpsrlw $12, %%xmm1\n\tpxor %%xmm0, %%xmm0\n\t"
                     "1: pshufb %%xmm1, %%xmm0\n\tdec %0\n\tjnz 1b\n\t"
                     "movd %%xmm0, %%eax\n\tmov %%eax, %1"
                     : "+r"(n) : "m"(g_mem[0]) : "rax", "xmm0", "xmm1", "cc", "memory");
}

static void b_div32(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("mov $7, %%ecx\n\t"
                     "1: xor %%edx, %%edx\n\tmov %k1, %%eax\n\tdiv %%ecx\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) :: "rax", "rcx", "rdx", "cc");
    g_sink = acc;
}

static void b_idiv64(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("mov $-7, %%rcx\n\t"
                     "1: mov %1, %%rax\n\tcqo\n\tidiv %%rcx\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b"
                     : "+r"(acc), "+r"(n) :: "rax", "rcx", "rdx", "cc");
    g_sink = acc;
}

static void b_crc32(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("1: crc32l %k1, %k0\n\tdec %1\n\tjnz 1b" : "+r"(acc), "+r"(n) :: "cc");
    g_sink = acc;
}

static void b_popcnt(uint64_t n)
{
    uint64_t acc = 0;
    __asm__ volatile("1: popcnt %1, %%rax\n\tadd %%rax, %0\n\tdec %1\n\tjnz 1b" : "+r"(acc), "+r"(n) :: "rax", "cc");
    g_sink = acc;
}

static void b_lock_xadd(uint64_t n)
{
    __asm__ volatile("mov $1, %%eax\n\t"
                     "1: lock xaddl %%eax, %1\n\tmov $1, %%eax\n\tdec %0\n\tjnz 1b"
                     : "+r"(n), "+m"(g_mem[0]) :: "rax", "cc", "memory");
}

static void b_call_ret(uint64_t n)
{
    __asm__ volatile("jmp 2f\n\t"
                     "3: ret\n\t"
                     "2: call 3b\n\tdec %0\n\tjnz 2b"
                     : "+r"(n) :: "cc", "memory");
}

static void b_icall(uint64_t n)
{
    __asm__ volatile("lea 3f(%%rip), %%r11\n\tjmp 2f\n\t"
                     "3: ret\n\t"
                     "2: call *%%r11\n\tdec %0\n\tjnz 2b"
                     : "+r"(n) :: "r11", "cc", "memory");
}

static void b_rep_movsb_4k(uint64_t n)
{
    __asm__ volatile("1: lea %1, %%rsi\n\tlea %2, %%rdi\n\tmov $4096, %%ecx\n\trep movsb\n\tdec %0\n\tjnz 1b"
                     : "+r"(n) : "m"(g_src), "m"(g_dst) : "rsi", "rdi", "rcx", "cc", "memory");
}

static void b_x87_fadd(uint64_t n)
{
    __asm__ volatile("fld1\n\tfld1\n\t"
                     "1: fadd %%st(1), %%st\n\tdec %0\n\tjnz 1b\n\t"
                     "fstpl %1\n\tfstp %%st(0)"
                     : "+r"(n), "=m"(g_mem[2]) :: "cc", "memory");
}

static int has_sse42(void)
{
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    return (c >> 20) & 1;
}

static double now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t)) { perror("clock_gettime"); exit(1); }
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int cmp_d(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

/* All code below is Linux measurement harness or additional x87 tests. */
static const double g_x87_two = 2.0;
static const double g_x87_input = 1.25;
static double g_x87_output;

static void b_x87_fmul(uint64_t n)
{
    __asm__ volatile("fld1\n\tfld1\n\t"
                     "1: fmul %%st(1), %%st\n\tdec %0\n\tjnz 1b\n\t"
                     "fstpl %1\n\tfstp %%st(0)"
                     : "+r"(n), "=m"(g_x87_output) :: "cc", "memory");
}
static void b_x87_fdiv(uint64_t n)
{
    __asm__ volatile("fld1\n\tfld1\n\t"
                     "1: fdiv %%st(1), %%st\n\tdec %0\n\tjnz 1b\n\t"
                     "fstpl %1\n\tfstp %%st(0)"
                     : "+r"(n), "=m"(g_x87_output) :: "cc", "memory");
}
static void b_x87_fsqrt(uint64_t n)
{
    __asm__ volatile("fld1\n\t"
                     "1: fsqrt\n\tdec %0\n\tjnz 1b\n\t"
                     "fstpl %1"
                     : "+r"(n), "=m"(g_x87_output) :: "cc", "memory");
}
static void b_x87_fld_fstp_m64(uint64_t n)
{
    __asm__ volatile("1: fldl %1\n\tfstpl %2\n\tdec %0\n\tjnz 1b"
                     : "+r"(n) : "m"(g_x87_input), "m"(g_x87_output) : "cc", "memory");
}
static void b_x87_fyl2x(uint64_t n)
{
    __asm__ volatile("fld1\n\t"
                     "1: fldl %1\n\tfyl2x\n\tdec %0\n\tjnz 1b\n\t"
                     "fstpl %2"
                     : "+r"(n) : "m"(g_x87_two), "m"(g_x87_output) : "cc", "memory");
}

static int perf_fd = -1;
static FILE *result_file, *raw_file;
static int chosen_cpu;
static unsigned full_run;

static uint64_t tsc_start(void)
{
    unsigned lo, hi;
    __asm__ volatile("lfence; rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}
static uint64_t tsc_stop(unsigned *aux)
{
    unsigned lo, hi, c;
    __asm__ volatile("rdtscp; lfence" : "=a"(lo), "=d"(hi), "=c"(c) :: "memory");
    *aux = c;
    return ((uint64_t)hi << 32) | lo;
}
static void fp_reset(void)
{
    const unsigned mxcsr = 0x1f80;
    __asm__ volatile("fninit; ldmxcsr %0" :: "m"(mxcsr) : "memory");
}
static void perf_init(void)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    perf_fd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (perf_fd < 0) printf("meta: core_cycles=unavailable perf_event_open_errno=%d message=%s\n", errno, strerror(errno));
    else printf("meta: core_cycles=perf_event_open event=PERF_COUNT_HW_CPU_CYCLES scope=this_thread exclude_kernel=1 exclude_hv=1\n");
}
static void print_cpu_metadata(void)
{
    unsigned a,b,c,d,maxext = __get_cpuid_max(0x80000000, NULL);
    char brand[49] = {0};
    if (maxext >= 0x80000004) {
        for (unsigned i=0; i<3; i++) {
            __cpuid(0x80000002+i,a,b,c,d);
            memcpy(brand+16*i,&a,4); memcpy(brand+16*i+4,&b,4);
            memcpy(brand+16*i+8,&c,4); memcpy(brand+16*i+12,&d,4);
        }
    }
    __cpuid(1,a,b,c,d);
    printf("meta: brand=%s signature=0x%08x hypervisor=%u sse42=%u popcnt=%u\n", brand,a,c>>31,(c>>20)&1,(c>>23)&1);
    if (!(c & (1u<<23)) || !(c & (1u<<9)) || !(c & 1u)) {
        fprintf(stderr,"Required original-loop CPU features (POPCNT/SSSE3/SSE3) absent\n"); exit(1);
    }
    unsigned rdtscp=0, invariant=0;
    if (maxext >= 0x80000001) { __cpuid(0x80000001,a,b,c,d); rdtscp=(d>>27)&1; }
    if (maxext >= 0x80000007) { __cpuid(0x80000007,a,b,c,d); invariant=(d>>8)&1; }
    printf("meta: rdtscp=%u invariant_tsc=%u tsc_is_core_cycles=NO\n",rdtscp,invariant);
    if (!rdtscp) { fprintf(stderr,"RDTSCP absent; cannot use selected TSC timing wrapper\n"); exit(1); }
    unsigned maxbasic=__get_cpuid_max(0,NULL);
    if (maxbasic>=0x15) { __cpuid_count(0x15,0,a,b,c,d); printf("meta: cpuid_15_denominator=%u numerator=%u crystal_hz=%u\n",a,b,c); }
    if (maxbasic>=0x16) { __cpuid_count(0x16,0,a,b,c,d); printf("meta: cpuid_16_base_mhz=%u max_mhz=%u bus_mhz=%u not_actual_frequency=1\n",a,b,c); }
    FILE *f=fopen("/proc/cpuinfo","r");
    if (f) {
        char line[512]; int cpu=-1;
        while(fgets(line,sizeof(line),f)) {
            if(sscanf(line,"processor : %d",&cpu)==1) continue;
            if(cpu==chosen_cpu && !strncmp(line,"cpu MHz",7)) printf("meta: proc_cpuinfo_reported_%s",line);
        }
        fclose(f);
    }
    printf("meta: compiler=%s affinity_cpu=%d full_run=%u clock=CLOCK_MONOTONIC_RAW frequency_control=unavailable actual_core_frequency=unavailable\n",__VERSION__, chosen_cpu,full_run);
}
static void calibrate_tsc(void)
{
    double rate[5];
    for(int i=0;i<5;i++) {
        unsigned aux;
        struct timespec req={0,100000000};
        double n0=now_ns(); uint64_t c0=tsc_start();
        while(nanosleep(&req,&req) && errno==EINTR) {}
        uint64_t c1=tsc_stop(&aux); double n1=now_ns();
        rate[i]=(double)(c1-c0)/(n1-n0);
        printf("tsc_calibration: sample=%d delta_ns=%.0f delta_ticks=%" PRIu64 " ticks_per_ns=%.9f aux=%u\n",i+1,n1-n0,c1-c0,rate[i],aux);
    }
    qsort(rate,5,sizeof(rate[0]),cmp_d);
    printf("meta: measured_tsc_ghz_median=%.9f min=%.9f max=%.9f rate_is_not_actual_core_frequency=1\n",rate[2],rate[0],rate[4]);
}
static void run(const char *name, bench_fn fn)
{
    /* Original calibration policy: >=20 ms, target ~150 ms, then 5 samples. */
    uint64_t n=100000;
    double t;
    for(;;) {
        fp_reset();
        double t0=now_ns(); fn(n); t=now_ns()-t0;
        if(t>=20e6 || n>=(1ull<<34)) break;
        n*=4;
    }
    n=(uint64_t)((double)n*(150e6/t));
    if(n<1000) n=1000;
    double r[5], ticks[5], cycles[5];
    int core_ok=perf_fd>=0;
    for(int i=0;i<5;i++) {
        fp_reset();
        int cpu_before=sched_getcpu();
        struct rusage ru0,ru1; getrusage(RUSAGE_THREAD,&ru0);
        struct timespec ct0,ct1; clock_gettime(CLOCK_THREAD_CPUTIME_ID,&ct0);
        if(perf_fd>=0) {
            if(ioctl(perf_fd,PERF_EVENT_IOC_RESET,0) || ioctl(perf_fd,PERF_EVENT_IOC_ENABLE,0)) { perror("perf ioctl begin"); exit(1); }
        }
        double t0=now_ns(); uint64_t c0=tsc_start();
        fn(n);
        unsigned aux; uint64_t c1=tsc_stop(&aux); double t1=now_ns();
        struct { uint64_t value, enabled, running; } counts={0};
        if(perf_fd>=0) {
            if(ioctl(perf_fd,PERF_EVENT_IOC_DISABLE,0)) { perror("perf ioctl end"); exit(1); }
            if(read(perf_fd,&counts,sizeof(counts))!=sizeof(counts)) { perror("perf read"); exit(1); }
            if(!counts.running) core_ok=0;
        }
        clock_gettime(CLOCK_THREAD_CPUTIME_ID,&ct1); getrusage(RUSAGE_THREAD,&ru1);
        int cpu_after=sched_getcpu();
        if(cpu_before!=chosen_cpu || cpu_after!=chosen_cpu) { fprintf(stderr,"Affinity verification failed\n"); exit(1); }
        double thread_ns=(double)(ct1.tv_sec-ct0.tv_sec)*1e9+(ct1.tv_nsec-ct0.tv_nsec);
        r[i]=(t1-t0)/(double)n;
        ticks[i]=(double)(c1-c0)/(double)n;
        cycles[i]=counts.running ? (double)counts.value*(double)counts.enabled/(double)counts.running/(double)n : -1;
        fprintf(raw_file,"%u\t%s\t%d\t%" PRIu64 "\t%.0f\t%" PRIu64 "\t%.9f\t%.9f\t",full_run,name,i+1,n,t1-t0,c1-c0,r[i],ticks[i]);
        if(cycles[i]>=0) fprintf(raw_file,"%.9f",cycles[i]); else fprintf(raw_file,"NA");
        fprintf(raw_file,"\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%.0f\t%d\t%d\t%u\t%ld\t%ld\n",counts.value,counts.enabled,counts.running,thread_ns,cpu_before,cpu_after,aux,ru1.ru_nvcsw-ru0.ru_nvcsw,ru1.ru_nivcsw-ru0.ru_nivcsw);
    }
    qsort(r,5,sizeof(r[0]),cmp_d); qsort(ticks,5,sizeof(ticks[0]),cmp_d); qsort(cycles,5,sizeof(cycles[0]),cmp_d);
    fprintf(result_file,"%s\t%.9f\t%.9f\t",name,r[2],r[0]);
    if(core_ok) fprintf(result_file,"%.9f\t%.9f\tperf_event_open_cpu_cycles",cycles[2],cycles[0]);
    else fprintf(result_file,"NA\tNA\tunavailable");
    fprintf(result_file,"\t%.9f\t%.9f\t%.9f\t%" PRIu64 "\t5\n",ticks[2],ticks[0],r[4],n);
    printf("bench: name=%-18s iters=%-12" PRIu64 " ns_median=%10.6f ns_min=%10.6f ns_max=%10.6f tsc_ticks_median=%10.6f core_cycles=%s\n",name,n,r[2],r[0],r[4],ticks[2],core_ok?"see_tsv":"NA");
    fflush(result_file); fflush(raw_file); fflush(stdout);
}
int main(int argc,char **argv)
{
    if(argc!=4) { fprintf(stderr,"Usage: %s RESULT.tsv RAW.tsv FULL_RUN_NUMBER\n",argv[0]); return 2; }
    full_run=(unsigned)strtoul(argv[3],NULL,10);
    cpu_set_t allowed, selected, verified;
    CPU_ZERO(&allowed); CPU_ZERO(&selected);
    if(sched_getaffinity(0,sizeof(allowed),&allowed)) { perror("sched_getaffinity"); return 1; }
    chosen_cpu=-1;
    printf("meta: allowed_cpus=");
    for(int i=0;i<CPU_SETSIZE;i++) if(CPU_ISSET(i,&allowed)) { if(chosen_cpu<0) chosen_cpu=i; printf("%d,",i); }
    printf("\n");
    if(chosen_cpu<0) return 1;
    CPU_SET(chosen_cpu,&selected);
    if(sched_setaffinity(0,sizeof(selected),&selected)) { perror("sched_setaffinity"); return 1; }
    if(sched_getaffinity(0,sizeof(verified),&verified) || CPU_COUNT(&verified)!=1 || !CPU_ISSET(chosen_cpu,&verified)) return 1;
    result_file=fopen(argv[1],"wx"); raw_file=fopen(argv[2],"wx");
    if(!result_file || !raw_file) { perror("open output (must not exist)"); return 1; }
    setvbuf(stdout,NULL,_IONBF,0);
    fprintf(result_file,"loop\tns_median\tns_min\tcore_cycles_median\tcore_cycles_min\tcore_cycles_method\ttsc_ticks_median\ttsc_ticks_min\tns_max\titers\tsamples\n");
    fprintf(raw_file,"full_run\tloop\tsample\titers\tdelta_ns\tdelta_tsc_ticks\tns_per_iter\ttsc_ticks_per_iter\tcore_cycles_per_iter\tperf_raw_cycles\tperf_time_enabled_ns\tperf_time_running_ns\tthread_cpu_ns\tcpu_before\tcpu_after\ttsc_aux\tvoluntary_context_switches\tinvoluntary_context_switches\n");
    print_cpu_metadata(); perf_init(); calibrate_tsc();
    memset(g_src,0x5a,sizeof(g_src));
    run("empty", b_empty);
    run("add", b_add);
    run("imul", b_imul);
    run("cvttss2si", b_cvttss2si);
    run("cvtss2si", b_cvtss2si);
    run("cvttsd2si64", b_cvttsd2si64);
    run("cvttps2dq", b_cvttps2dq);
    run("cvtdq2ps", b_cvtdq2ps);
    run("addsubps", b_addsubps);
    run("addss", b_addss);
    run("mulps", b_mulps);
    run("pshufb", b_pshufb);
    run("div32", b_div32);
    run("idiv64", b_idiv64);
    if (has_sse42()) run("crc32", b_crc32); else printf("bench: name=crc32 skipped=no-sse42\n");
    run("popcnt", b_popcnt);
    run("lock_xadd", b_lock_xadd);
    run("call_ret", b_call_ret);
    run("icall", b_icall);
    run("rep_movsb_4k", b_rep_movsb_4k);
    run("x87_fadd", b_x87_fadd);
    run("x87_fmul",b_x87_fmul);
    run("x87_fdiv",b_x87_fdiv);
    run("x87_fsqrt",b_x87_fsqrt);
    run("x87_fld_fstp_m64",b_x87_fld_fstp_m64);
    run("x87_fyl2x",b_x87_fyl2x);
    printf("bench: end full_run=%u\n",full_run);
    if(perf_fd>=0) close(perf_fd);
    if(fclose(result_file) || fclose(raw_file)) { perror("close output"); return 1; }
    return 0;
}
