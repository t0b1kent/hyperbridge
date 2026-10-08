#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef VOID (WINAPI *rtl_raise_t)(PEXCEPTION_RECORD);
void *stack_target;
uint64_t stack_call_rsp;
uint64_t stack_call_rbx;
unsigned stack_path, stack_count;
ULONG_PTR stack_arguments[3]={0x1111222233334444ULL,0x5555666677778888ULL,0x9999aaaabbbbccccULL};
volatile uint64_t stack_after_flags, stack_after_rax, stack_after_rdx;
__attribute__((aligned(16))) uint64_t stack_after_xmm[12];
__attribute__((aligned(16))) const uint64_t stack_xmm_seed[2] = {
    UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)};
static unsigned return_rows;
static unsigned stack_mode, stack_depth;
static unsigned rows, failures, entered;
static EXCEPTION_RECORD stack_record;
extern void stack_call(unsigned depth, EXCEPTION_RECORD *record, uint64_t rbx);

static LONG record_exception(PEXCEPTION_POINTERS info)
{
    CONTEXT *c = info->ContextRecord;
    unsigned low = (unsigned)((stack_call_rsp - 8) & 255);
    if (info->ExceptionRecord->ExceptionCode != 0xe0424242 &&
        !(stack_path == 2 && info->ExceptionRecord->ExceptionCode == 0xc0000008)) return EXCEPTION_CONTINUE_SEARCH;
    ++entered; ++rows;
    printf("STACK_CONTEXT path=%s handler=%s depth=%u count=%u rsp_low=%02x eflags=%08lx "
           "caller_rsp=%016llx context_rsp=%016llx flags=%08lx p3home=%016llx "
           "caller_rbx=%016llx context_rbx=%016llx\n",
           stack_path ? "RtlRaiseException" : "RaiseException", stack_mode ? "SEH" : "VEH",
           stack_depth, stack_count, low, c->EFlags, (unsigned long long)stack_call_rsp,
           (unsigned long long)c->Rsp, c->ContextFlags, (unsigned long long)c->P3Home,
           (unsigned long long)stack_call_rbx, (unsigned long long)c->Rbx);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS info)
{
    return stack_mode ? EXCEPTION_CONTINUE_SEARCH : record_exception(info);
}

__declspec(noinline) static void run_depth(unsigned depth, uint64_t rbx)
{
    /* The assembly helper uses a frame pointer, 32-byte shadow space and
       depth*16 bytes of dynamic stack, with an aligned call site. */
    entered = 0;
    __try { stack_call(depth, &stack_record, rbx); }
    __except(record_exception(GetExceptionInformation())) { ++failures; }
    if (entered != (stack_path == 2 ? 0 : 1)) ++failures;
    ++return_rows;
    printf("STACK_RETURN path=%s handler=%s depth=%u count=%u entry_rsp=%016llx flags=%08llx rax=%016llx rdx=%016llx last_error=%lu",
        stack_path == 2 ? "CloseHandle" : stack_path ? "RtlRaiseException" : "RaiseException",
        stack_mode ? "SEH" : "VEH", stack_depth, stack_count, (unsigned long long)(stack_call_rsp - 8),
        (unsigned long long)stack_after_flags, (unsigned long long)stack_after_rax,
        (unsigned long long)stack_after_rdx, GetLastError());
    for (unsigned i = 0; i < 6; ++i)
        printf(" xmm%u=%016llx%016llx", i, (unsigned long long)stack_after_xmm[2*i+1],
               (unsigned long long)stack_after_xmm[2*i]);
    printf("\n");
}

void ExcCtxPFMetadata375(void);
int main(void)
{
    ExcCtxPFMetadata375();
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    rtl_raise_t rtl_raise = (rtl_raise_t)GetProcAddress(module, "RtlRaiseException");
    PVOID handler;
    if (!rtl_raise) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&stack_record, 0, sizeof(stack_record));
    stack_record.ExceptionCode = 0xe0424242;
    handler = AddVectoredExceptionHandler(1, veh);
    if (!handler) return 3;
    printf("STACK_CONTEXT_BEGIN version=354 paths=3 mechanisms=2 depths=16 raise_counts=0,3 "
           "rsp_low_basis=callee_entry aligned_call=16\n");
    for (stack_path = 0; stack_path != 3; ++stack_path)
    {
        stack_target = stack_path == 2 ? (void *)CloseHandle : stack_path ? (void *)rtl_raise : (void *)RaiseException;
        for (stack_count=0; stack_count<=(stack_path==0 ? 3u : 0u); stack_count+=3)
            for (stack_mode = 0; stack_mode != 2; ++stack_mode)
                for (stack_depth = 0; stack_depth != 16; ++stack_depth)
                    run_depth(stack_depth, UINT64_C(0x3141592653589793));
    }
    RemoveVectoredExceptionHandler(handler);
    printf("PF354_CONTEXT_COMPLETE rows=%u failures=%u\n", rows, failures);
    printf("PF354_RETURN_COMPLETE rows=%u failures=%u\n", return_rows, failures);
    return failures || rows != 96 || return_rows != 128;
}
