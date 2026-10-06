// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  unsigned a,b,c,d, family,model,stepping,hypervisor;
  char vendor[13]={0}, brand[49]={0};
  __cpuid(0,a,b,c,d);
  memcpy(vendor,&b,4); memcpy(vendor+4,&d,4); memcpy(vendor+8,&c,4);
  __cpuid(1,a,b,c,d);
  family=(a>>8)&15; model=(a>>4)&15; stepping=a&15; hypervisor=(c>>31)&1;
  if(family==6 || family==15) model|=((a>>16)&15)<<4;
  if(family==15) family+=(a>>20)&255;
  if(__get_cpuid_max(0x80000000,0)>=0x80000004)
    for(unsigned leaf=0;leaf<3;leaf++) {
      __cpuid(0x80000002+leaf,a,b,c,d);
      memcpy(brand+16*leaf,&a,4); memcpy(brand+16*leaf+4,&b,4);
      memcpy(brand+16*leaf+8,&c,4); memcpy(brand+16*leaf+12,&d,4);
    }
  for(unsigned i=0;i<48;i++) if(brand[i]=='"' || brand[i]=='\\' || (brand[i] && (unsigned char)brand[i]<32)) brand[i]='?';
  printf("{\"vendor\":\"%s\",\"model_name\":\"%s\",\"family\":%u,\"model\":%u,\"stepping\":%u,\"hypervisor\":%u}\n",
         vendor,brand,family,model,stepping,hypervisor);
  return 0;
}
