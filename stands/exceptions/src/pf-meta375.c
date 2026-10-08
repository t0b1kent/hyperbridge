/* Same-process metadata before the unchanged, flag-seeded PF354 assembly.
 * No handlers, tracing, disassembly, writes or process enumeration. */
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <cpuid.h>
typedef ULONG64 (WINAPI *features_fn)(ULONG64);
typedef LONG (WINAPI *length_fn)(ULONG, ULONG *);
typedef LONG (WINAPI *length2_fn)(ULONG, ULONG *, ULONG64);
__attribute__((noinline)) void ExcCtxPFMetadata375(void)
{
    unsigned a=0,b=0,c=0,d=0;
    uint64_t xcr0=0;
    HMODULE nt=GetModuleHandleA("ntdll.dll");
    features_fn features=(features_fn)GetProcAddress(nt,"RtlGetEnabledExtendedFeatures");
    length_fn length=(length_fn)GetProcAddress(nt,"RtlGetExtendedContextLength");
    length2_fn length2=(length2_fn)GetProcAddress(nt,"RtlGetExtendedContextLength2");
    ULONG64 enabled=features ? features(~(ULONG64)0) : 0;
    const char *names[]={"ntdll.dll","kernelbase.dll","kernel32.dll"};
    __get_cpuid(1,&a,&b,&c,&d);
    if(c & (1u<<27)) {
        unsigned lo,hi;
        __asm__ volatile("xgetbv" : "=a"(lo),"=d"(hi) : "c"(0));
        xcr0=(uint64_t)lo | ((uint64_t)hi<<32);
    }
    printf("PF375_CPU leaf1_ecx=%08x leaf1_edx=%08x xcr0_state=%s xcr0=%016llx\n",
           c,d,(c&(1u<<27)) ? "PRESENT":"NOT_ENABLED",(unsigned long long)xcr0);
    a=b=c=d=0;
    __get_cpuid_count(7,0,&a,&b,&c,&d);
    printf("PF375_CPU leaf7_ebx=%08x leaf7_ecx=%08x leaf7_edx=%08x\n",b,c,d);
    a=b=c=d=0;
    __get_cpuid_count(13,0,&a,&b,&c,&d);
    printf("PF375_CPU leafd_eax=%08x leafd_ebx=%08x leafd_ecx=%08x leafd_edx=%08x\n",a,b,c,d);
    printf("PF375_XSTATE state=%s enabled=%016llx\n",features ? "PRESENT":"NOT_ENABLED",
           (unsigned long long)enabled);
    for(unsigned i=0;i<3;i++) {
        HMODULE module=GetModuleHandleA(names[i]);
        char path[512];
        DWORD n=module ? GetModuleFileNameA(module,path,sizeof(path)) : 0;
        printf("PF375_MODULE name=%s state=%s path_hex=",names[i],
               !module || !n ? "FAILED" : n>=sizeof(path) ? "DROPPED":"PRESENT");
        if(module && n && n<sizeof(path))
            for(DWORD j=0;j<n;j++) printf("%02x",(unsigned char)path[j]);
        printf("\n");
    }
    for(unsigned i=0;i<2;i++) {
        ULONG flags=i ? 0x0010004f : 0x0010000f, bytes=0;
        LONG status=length ? length(flags,&bytes) : (LONG)0xc0000002;
        printf("PF375_LENGTH api=RtlGetExtendedContextLength state=%s flags=%08lx status=%08lx bytes=%lu\n",
               length ? "PRESENT":"NOT_ENABLED",flags,(ULONG)status,bytes);
        ULONG64 masks[]={3,7,enabled};
        for(unsigned j=0;j<3;j++) {
            bytes=0;
            status=length2 ? length2(flags,&bytes,masks[j]) : (LONG)0xc0000002;
            printf("PF375_LENGTH api=RtlGetExtendedContextLength2 state=%s flags=%08lx mask=%016llx status=%08lx bytes=%lu\n",
                   length2 ? "PRESENT":"NOT_ENABLED",flags,(unsigned long long)masks[j],(ULONG)status,bytes);
        }
    }
    printf("PF375_METADATA_COMPLETE modules=3 length_rows=8\n");
}
