// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
static unsigned fault_code,fault_cw,fault_mxcsr;
static int capture(EXCEPTION_POINTERS *p) {fault_code=p->ExceptionRecord->ExceptionCode;fault_cw=p->ContextRecord->FltSave.ControlWord;fault_mxcsr=p->ContextRecord->MxCsr;return EXCEPTION_EXECUTE_HANDLER;}
static void emit(const char *format,...) {char buffer[512];va_list args;va_start(args,format);int n=vsnprintf(buffer,sizeof(buffer),format,args);va_end(args);DWORD written;if(n<0||n>=(int)sizeof(buffer)||!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),buffer,n,&written,NULL)||written!=(DWORD)n)ExitProcess(3);}
static __attribute__((noinline)) void execute(unsigned op,unsigned request,uint32_t *value,unsigned char *image) {
    if(op==0)__asm__ volatile("ldmxcsr %0"::"m"(*value):"memory");
    else if(op==1)__asm__ volatile("fxrstor64 %0"::"m"(*(unsigned char (*)[1024])image):"memory");
    else __asm__ volatile("xrstor64 %0"::"m"(*(unsigned char (*)[1024])image),"a"(request),"d"(0u):"memory");
}
static void run(unsigned op,unsigned request,unsigned bv,uint32_t value,unsigned repeat,unsigned family) {
    unsigned char image[1024] __attribute__((aligned(64))),after[512] __attribute__((aligned(16)));
    uint32_t initial=0x1f80;memset(image,0,sizeof(image));
    __asm__ volatile("fninit;ldmxcsr %0;fxsave64 %1"::"m"(initial),"m"(image):"memory");
    *(uint16_t*)image=0x27f;*(uint32_t*)(image+24)=value;*(uint64_t*)(image+512)=bv;
    fault_code=fault_cw=fault_mxcsr=0;
    __try {execute(op,request,&value,image);}
    __except(capture(GetExceptionInformation())) {}
    __asm__ volatile("fxsave64 %0":"=m"(after));
    emit("MXCSR_RESTORE family=%u repeat=%u op=%u request=%u bv=%u value=%08x code=%08x fault_cw=%04x fault_mxcsr=%08x after_cw=%04x after_mxcsr=%08x mask=%08x\n",family,repeat,op,request,bv,value,fault_code,fault_cw,fault_mxcsr,*(uint16_t*)after,*(uint32_t*)(after+24),*(uint32_t*)(after+28));
}
int main(int argc,char **argv) {
    unsigned family=0,count=0;
    if(argc==2&&!strcmp(argv[1],"reserved"))family=123;
    else if(argc==2&&!strcmp(argv[1],"request-bv"))family=124;
    else if(argc!=1)return 2;
    uint32_t values[]={0x1f80,0x21f80,0x11f80,0x41f80,0x80001f80};unsigned requests[]={0,1,2,4,6,7};
    if(!family||family==123){for(unsigned repeat=0;repeat<2;repeat++)for(unsigned op=0;op<3;op++)for(unsigned i=0;i<5;i++)run(op,3,3,values[i],repeat,123);count+=30;}
    if(!family||family==124){for(unsigned repeat=0;repeat<2;repeat++)for(unsigned request=0;request<6;request++)for(unsigned bv=0;bv<2;bv++)for(unsigned i=0;i<3;i++)run(2,requests[request],bv?3:0,values[i],repeat,124);count+=72;}
    uint32_t initial=0x1f80;__asm__ volatile("fninit;ldmxcsr %0"::"m"(initial):"memory");emit("MXCSR_RESTORE COMPLETE observations=%u\n",count);return 0;
}
