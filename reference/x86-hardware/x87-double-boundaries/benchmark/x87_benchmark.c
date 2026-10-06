/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 OpenAI
 * Original native x86-64 driver, no third-party source incorporated.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(__x86_64__) || !defined(__linux__)
#error This benchmark requires native Linux x86-64.
#endif
typedef void (*kernel)(uint64_t, unsigned char *);
#define DECLARE(n) extern void bench_##n(uint64_t, unsigned char *);
DECLARE(empty) DECLARE(fadd) DECLARE(fld_fstp) DECLARE(fild_fistp)
DECLARE(fmul) DECLARE(fdiv) DECLARE(fsqrt) DECLARE(fcom_branch) DECLARE(mixed5)
struct test { const char *name; kernel fn; };
static const struct test tests[] = {
 {"empty",bench_empty}, {"fadd",bench_fadd}, {"fld_fstp",bench_fld_fstp},
 {"fild_fistp",bench_fild_fistp}, {"fmul",bench_fmul}, {"fdiv",bench_fdiv},
 {"fsqrt",bench_fsqrt}, {"fcom_branch",bench_fcom_branch}, {"mixed5",bench_mixed5}
};
static uint64_t ns(clockid_t id) {
 struct timespec t;
 if(clock_gettime(id,&t)) { perror("clock_gettime"); exit(1); }
 return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static uint64_t tsc_begin(void) {
 unsigned a,d;
 __asm__ volatile("lfence; rdtsc" : "=a"(a),"=d"(d) :: "memory");
 return ((uint64_t)d<<32)|a;
}
static uint64_t tsc_end(void) {
 unsigned a,d,c;
 __asm__ volatile("rdtscp; lfence" : "=a"(a),"=d"(d),"=c"(c) :: "memory");
 return ((uint64_t)d<<32)|a;
}
static double observed_mhz(int wanted) {
 FILE *f=fopen("/proc/cpuinfo","r"); if(!f) return -1;
 char line[512]; int cpu=-1; double mhz=-1;
 while(fgets(line,sizeof(line),f)) {
  int v; if(sscanf(line,"processor : %d",&v)==1) cpu=v;
  if(cpu==wanted && sscanf(line,"cpu MHz : %lf",&mhz)==1) break;
 }
 fclose(f); return mhz;
}
static void init_x87(unsigned short cw) {
 __asm__ volatile("fninit; fldcw %0" :: "m"(cw) : "memory");
}
static void cpu_metadata(FILE *f,int cpu) {
 unsigned a,b,c,d; __cpuid(0,a,b,c,d); unsigned max=a;
 char vendor[13]; memcpy(vendor,&b,4); memcpy(vendor+4,&d,4); memcpy(vendor+8,&c,4); vendor[12]=0;
 __cpuid(1,a,b,c,d);
 fprintf(f,"vendor=%s\ncpuid_signature=0x%08x\nhypervisor_present=%u\n",vendor,a,(c>>31)&1);
 __cpuid(0x80000000,a,b,c,d); unsigned ext=a;
 if(ext>=0x80000004) {
  char brand[49]; unsigned values[4];
  for(unsigned i=0;i<3;i++) { __cpuid(0x80000002+i,a,b,c,d); values[0]=a; values[1]=b; values[2]=c; values[3]=d; memcpy(brand+16*i,values,16); }
  brand[48]=0; fprintf(f,"cpu_brand=%s\n",brand);
 }
 if(ext>=0x80000007) { __cpuid(0x80000007,a,b,c,d); fprintf(f,"invariant_tsc=%u\n",(d>>8)&1); }
 if(max>=0x15) { __cpuid_count(0x15,0,a,b,c,d); fprintf(f,"cpuid_15_eax=%u\ncpuid_15_ebx=%u\ncpuid_15_ecx=%u\n",a,b,c); }
 if(max>=0x16) { __cpuid_count(0x16,0,a,b,c,d); fprintf(f,"cpuid_16_base_mhz=%u\ncpuid_16_max_mhz=%u\n",a,b); }
 fprintf(f,"pinned_logical_cpu=%d\nproc_cpuinfo_mhz_before=%.3f\ncompiler=%s\n",cpu,observed_mhz(cpu),__VERSION__);
}
static uint64_t number(const char *s,const char *what) {
 char *end=NULL; errno=0; unsigned long long v=strtoull(s,&end,10);
 if(errno || !*s || *end || v==0) { fprintf(stderr,"Invalid %s\n",what); exit(2); }
 return v;
}
int main(int argc,char **argv) {
 if(argc!=5) { fprintf(stderr,"Usage: %s iterations repetitions raw.csv metadata.txt\n",argv[0]); return 2; }
 uint64_t iterations=number(argv[1],"iterations"),repetitions=number(argv[2],"repetitions");
 if(iterations>100000000ULL || repetitions>1000) { fputs("Refusing excessive run\n",stderr); return 2; }
 unsigned a,b,c,d; __cpuid(0x80000001,a,b,c,d);
 if(!(d&(1U<<27))) { fputs("RDTSCP required\n",stderr); return 2; }
 cpu_set_t allowed,set;
 if(sched_getaffinity(0,sizeof(allowed),&allowed)) { perror("sched_getaffinity"); return 1; }
 int cpu=-1; for(int i=0;i<CPU_SETSIZE;i++) if(CPU_ISSET(i,&allowed)) cpu=i;
 if(cpu<0) return 1;
 CPU_ZERO(&set); CPU_SET(cpu,&set);
 if(sched_setaffinity(0,sizeof(set),&set)) { perror("sched_setaffinity"); return 1; }
 FILE *raw=fopen(argv[3],"w"),*meta=fopen(argv[4],"w");
 if(!raw || !meta) { perror("output file"); return 1; }
 cpu_metadata(meta,cpu);
 fprintf(meta,"iterations=%" PRIu64 "\nrepetitions=%" PRIu64 "\nwarmup_iterations=1000000\nrounding=nearest_even\nexceptions=masked\n",iterations,repetitions);
 /* This calibration measures TSC rate, not the actual core clock. */
 for(int k=0;k<5;k++) {
  struct timespec delay={0,150000000};
  uint64_t w0=ns(CLOCK_MONOTONIC_RAW),t0=tsc_begin();
  while(nanosleep(&delay,&delay) && errno==EINTR) {}
  uint64_t t1=tsc_end(),w1=ns(CLOCK_MONOTONIC_RAW);
  fprintf(meta,"tsc_calibration_%d_ns=%" PRIu64 "\ntsc_calibration_%d_ticks=%" PRIu64 "\ntsc_calibration_%d_mhz=%.6f\n",k,w1-w0,k,t1-t0,k,(double)(t1-t0)*1000.0/(double)(w1-w0));
 }
 fflush(meta);
 fputs("pc_bits,cw,round,order,test,iterations,wall_ns,thread_cpu_ns,tsc_ticks,ns_per_iteration,tsc_ticks_per_iteration,cpu_before,cpu_after,result80_le\n",raw);
 const unsigned short cws[]={0x027f,0x007f,0x037f}; const unsigned bits[]={53,24,64};
 unsigned short saved_cw; __asm__ volatile("fnstcw %0" : "=m"(saved_cw));
 for(unsigned p=0;p<3;p++) {
  unsigned char result[10]={0};
  for(unsigned j=0;j<9;j++) { init_x87(cws[p]); tests[j].fn(1000000,result); }
  for(uint64_t rep=0;rep<repetitions;rep++) {
   /* Rotating order distributes drift without a random input dependency. */
   for(unsigned order=0;order<9;order++) {
    unsigned j=(order+rep)%9; init_x87(cws[p]); int before=sched_getcpu();
    uint64_t c0=ns(CLOCK_THREAD_CPUTIME_ID),w0=ns(CLOCK_MONOTONIC_RAW),t0=tsc_begin();
    tests[j].fn(iterations,result);
    uint64_t t1=tsc_end(),w1=ns(CLOCK_MONOTONIC_RAW),c1=ns(CLOCK_THREAD_CPUTIME_ID);
    int after=sched_getcpu();
    fprintf(raw,"%u,0x%04x,%" PRIu64 ",%u,%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.9f,%.9f,%d,%d,",bits[p],cws[p],rep,order,tests[j].name,iterations,w1-w0,c1-c0,t1-t0,(double)(w1-w0)/iterations,(double)(t1-t0)/iterations,before,after);
    for(unsigned k=0;k<10;k++) { fprintf(raw,"%02x",result[k]); }
    fputc('\n',raw);
   }
   fflush(raw);
  }
 }
 __asm__ volatile("fninit; fldcw %0" :: "m"(saved_cw) : "memory");
 fprintf(meta,"proc_cpuinfo_mhz_after=%.3f\n",observed_mhz(cpu));
 fclose(raw); fclose(meta);
 printf("BENCHMARK_OK iterations=%" PRIu64 " repetitions=%" PRIu64 " precision_modes=3 timed_rows=%" PRIu64 "\n",iterations,repetitions,repetitions*27);
 return 0;
}
