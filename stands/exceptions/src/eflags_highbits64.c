/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 HyperBridge contributors */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void flags_plain(uint32_t flags,uint64_t* result);
extern void flags_fault(uint32_t flags,uint64_t* result);
extern char flags_fault_rip[],flags_resume_rip[];
static volatile LONG active;
static DWORD own_thread,context_flags,context_mask;
static CONTEXT fault_context;
static EXCEPTION_RECORD fault_record;
static LONG CALLBACK handler(PEXCEPTION_POINTERS p) {
    if(!active || GetCurrentThreadId()!=own_thread || p->ExceptionRecord->ExceptionCode!=EXCEPTION_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
    memcpy(&fault_context,p->ContextRecord,sizeof(fault_context));
    memcpy(&fault_record,p->ExceptionRecord,sizeof(fault_record));
    context_flags=p->ContextRecord->EFlags;context_mask=p->ContextRecord->ContextFlags;
    p->ContextRecord->Rip=(DWORD64)(uintptr_t)flags_resume_rip;
    active=0;return EXCEPTION_CONTINUE_EXECUTION;
}
static void raw(const char* name,const void* ptr,size_t size,unsigned row) {
    const unsigned char* b=(const unsigned char*)ptr;
    printf("EFLAGS_RAW row=%02u field=%s bytes=%04u hex=",row,name,(unsigned)size);
    for(size_t i=0;i<size;i++)printf("%02x",b[i]);putchar('\n');
}
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);own_thread=GetCurrentThreadId();
    PVOID h=AddVectoredExceptionHandler(1,handler);if(!h)return 2;
    printf("CONTEXT_PROBE phase=identity-hold fixture=EFLAGS16 pid=%lu fault_rip=%016llx resume_rip=%016llx\n",(unsigned long)GetCurrentProcessId(),(unsigned long long)(uintptr_t)flags_fault_rip,(unsigned long long)(uintptr_t)flags_resume_rip);Sleep(3000);
    unsigned failures=0;
    for(unsigned k=0;k<16;k++) {
        uint32_t f=0x202|((k&1)<<7)|(((k>>1)&1)<<6)|((k>>2)&1)|(((k>>3)&1)<<11);
        uint64_t plain[2]={0},fault[2]={0};context_flags=0;memset(&fault_context,0,sizeof(fault_context));
        flags_plain(f,plain);active=1;flags_fault(f,fault);
        printf("EFLAGS_ROW row=%02u SF=%u ZF=%u CF=%u OF=%u input=%08x pushfq=%016llx before_fault=%016llx context=%08lx context_mask=%08lx after=%016llx context_Rip=%016llx exception=%08lx\n",k,k&1,(k>>1)&1,(k>>2)&1,(k>>3)&1,f,(unsigned long long)plain[0],(unsigned long long)fault[0],(unsigned long)context_flags,(unsigned long)context_mask,(unsigned long long)fault[1],(unsigned long long)fault_context.Rip,(unsigned long)fault_record.ExceptionCode);
        raw("CONTEXT",&fault_context,sizeof(fault_context),k);raw("EXCEPTION_RECORD",&fault_record,sizeof(fault_record),k);
        if(active || (plain[0]&~0x3fffffull) || (fault[0]&~0x3fffffull) || (fault[1]&~0x3fffffull) || (context_flags&~0x3fffffu))failures++;
    }
    RemoveVectoredExceptionHandler(h);printf("EFLAGS_PROBE COMPLETE cases=16 highbit_or_dispatch_failures=%u\n",failures);return failures?1:0;
}
