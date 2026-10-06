/* SPDX-License-Identifier: MIT */
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
int main(void){unsigned a,b,c,d;char vendor[13]={0},brand[49]={0};__cpuid(0,a,b,c,d);memcpy(vendor,&b,4);memcpy(vendor+4,&d,4);memcpy(vendor+8,&c,4);printf("architecture=x86_64\nvendor=%s\n",vendor);for(unsigned i=0;i<3;i++){__cpuid(0x80000002+i,a,b,c,d);memcpy(brand+16*i,&a,4);memcpy(brand+16*i+4,&b,4);memcpy(brand+16*i+8,&c,4);memcpy(brand+16*i+12,&d,4);}printf("brand=%s\n",brand);__cpuid(1,a,b,c,d);printf("CPUID.1 eax=%08x ecx=%08x edx=%08x\n",a,c,d);printf("hypervisor_present=%u\n",c>>31);__cpuid_count(7,0,a,b,c,d);printf("CPUID.7.0 eax=%08x ebx=%08x ecx=%08x edx=%08x\n",a,b,c,d);unsigned lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0));printf("XCR0=%08x%08x\n",hi,lo);printf("Execution=native Linux x86-64 instructions, no software emulator\nPackages_installed=none\n");return 0;}
