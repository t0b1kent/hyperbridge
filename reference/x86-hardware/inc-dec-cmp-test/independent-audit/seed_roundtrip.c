/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>
__attribute__((noinline)) static uint64_t roundtrip(uint64_t six) {
    uint64_t saved, actual, requested;
    __asm__ volatile("pushfq; popq %0" : "=r"(saved) : : "memory");
    requested=(saved&~UINT64_C(0x8d5))|six;
    __asm__ volatile("pushq %1; popfq; pushfq; popq %0; pushq %2; popfq"
                     : "=&r"(actual) : "r"(requested),"r"(saved) : "cc","memory");
    return actual&UINT64_C(0x8d5);
}
int main(void) { uint64_t states[]={0,0x8d5,1,0x8d4};
    for (unsigned i=0;i<4;i++) {uint64_t got=roundtrip(states[i]);
      printf("flags_in=0x%03llx captured=0x%03llx %s\n",(unsigned long long)states[i],(unsigned long long)got,states[i]==got?"PASS":"FAIL");
      if(got!=states[i])return 1;
    }
    return 0;
}
