#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef VOID (WINAPI *rtl_raise_t)(PEXCEPTION_RECORD);
void *stack_target;
uint64_t stack_call_rsp;
uint64_t stack_call_rbx;
unsigned stack_path;
static unsigned stack_mode, stack_depth;
static unsigned rows, failures, entered;
static EXCEPTION_RECORD stack_record;
extern void stack_call(unsigned depth, EXCEPTION_RECORD *record, uint64_t rbx);

static LONG record_exception(PEXCEPTION_POINTERS info)
{
    CONTEXT *c = info->ContextRecord;
    unsigned low = (unsigned)((stack_call_rsp - 8) & 255);
    if (info->ExceptionRecord->ExceptionCode != 0xe042ec16) return EXCEPTION_CONTINUE_SEARCH;
    ++entered; ++rows;
    printf("STACK_CONTEXT path=%s handler=%s depth=%u rsp_low=%02x eflags=%08lx "
           "caller_rsp=%016llx context_rsp=%016llx flags=%08lx p3home=%016llx "
           "caller_rbx=%016llx context_rbx=%016llx\n",
           stack_path ? "RtlRaiseException" : "RaiseException", stack_mode ? "SEH" : "VEH",
           stack_depth, low, c->EFlags, (unsigned long long)stack_call_rsp,
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
    if (entered != 1) ++failures;
}

int main(void)
{
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    rtl_raise_t rtl_raise = (rtl_raise_t)GetProcAddress(module, "RtlRaiseException");
    PVOID handler;
    if (!rtl_raise) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&stack_record, 0, sizeof(stack_record));
    stack_record.ExceptionCode = 0xe042ec16;
    handler = AddVectoredExceptionHandler(1, veh);
    if (!handler) return 3;
    printf("STACK_CONTEXT_BEGIN version=1 paths=2 mechanisms=2 depths=16 "
           "rsp_low_basis=callee_entry aligned_call=16\n");
    for (stack_path = 0; stack_path != 2; ++stack_path)
    {
        stack_target = stack_path ? (void *)rtl_raise : (void *)RaiseException;
        for (stack_mode = 0; stack_mode != 2; ++stack_mode)
            for (stack_depth = 0; stack_depth != 16; ++stack_depth)
                run_depth(stack_depth, UINT64_C(0x3141592653589793));
    }
    RemoveVectoredExceptionHandler(handler);
    printf("STACK_CONTEXT_COMPLETE rows=%u failures=%u\n", rows, failures);
    return failures || rows != 64;
}
