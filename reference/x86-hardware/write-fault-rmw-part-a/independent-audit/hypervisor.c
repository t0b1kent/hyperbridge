/* SPDX-License-Identifier: MIT */
#include <cpuid.h>
#include <stdio.h>
#include <string.h>
int main(void) { unsigned a,b,c,d;char s[13];__cpuid_count(0x40000000,0,a,b,c,d);memcpy(s,&b,4);memcpy(s+4,&c,4);memcpy(s+8,&d,4);s[12]=0;printf("CPUID 40000000:0 %08x %08x %08x %08x\nhypervisor_vendor=%s\n",a,b,c,d,s); }
