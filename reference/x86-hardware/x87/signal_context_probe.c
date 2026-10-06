/* Original audit probe, MIT License. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>
static void benign(int sig){(void)sig;}
int main(void) {
 _Alignas(16) uint8_t seed[32]={0},a[32]={0},b[32]={0};
 uint16_t cw=0x037f,tw=0xffff,op=0x321;uint32_t ip=0x12345678,dp=0x23456789;
 memcpy(seed,&cw,2);memcpy(seed+8,&tw,2);memcpy(seed+12,&ip,4);memcpy(seed+18,&op,2);memcpy(seed+20,&dp,4);
 struct rusage r0,r1;
 signal(SIGUSR1,benign);
 for(int i=0;i<9;i++){
  getrusage(RUSAGE_THREAD,&r0);
  __asm__ volatile("fninit; fldenv %1; fnstenv %0":"=m"(a):"m"(seed):"memory");
  if(i>=6)raise(SIGUSR1);else if(i>=3)(void)syscall(SYS_getpid);
  __asm__ volatile("fnstenv %0; fninit":"=m"(b)::"memory");
  getrusage(RUSAGE_THREAD,&r1);
  uint16_t aop,bop;uint32_t ai,bi,ad,bd;memcpy(&aop,a+18,2);memcpy(&bop,b+18,2);memcpy(&ai,a+12,4);memcpy(&bi,b+12,4);memcpy(&ad,a+20,4);memcpy(&bd,b+20,4);
  printf("trial=%d voluntary_switches=%ld involuntary_switches=%ld before_FOP=%03x FIP=%08x FDP=%08x after_FOP=%03x FIP=%08x FDP=%08x\n",i,r1.ru_nvcsw-r0.ru_nvcsw,r1.ru_nivcsw-r0.ru_nivcsw,aop&0x7ff,ai,ad,bop&0x7ff,bi,bd);
 }
}
