/* v5c: same finite families1--7, complete 32/64-bit clock API siblings.
 * One cell per process. No debugger manipulation on a debugged process, no
 * critical-process enable, no code injection, no external process handles.
 * Public SDK: winnt.h mitigation enum through SEHOP (19 policies).
 * NT selectors/layouts: Wine winternl.h, llvm-mingw ntddk.h; see v5-COVERAGE.md.
 */
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

typedef NTSTATUS (NTAPI *NT_QPROC)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *NT_SPROC)(HANDLE,ULONG,PVOID,ULONG);
typedef NTSTATUS (NTAPI *NT_QTHREAD)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *NT_STHREAD)(HANDLE,ULONG,PVOID,ULONG);
typedef NTSTATUS (NTAPI *NT_QSYSTEM)(ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *NT_QOBJECT)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *NT_CLOSE)(HANDLE);
typedef BOOL (WINAPI *GET_MITIGATION)(HANDLE,PROCESS_MITIGATION_POLICY,PVOID,SIZE_T);
typedef BOOL (WINAPI *SET_MITIGATION)(PROCESS_MITIGATION_POLICY,PVOID,SIZE_T);

enum { P_DEBUG_PORT=7, P_BREAK=29, P_DEBUG_OBJECT=30, P_DEBUG_FLAGS=31,
       P_HANDLE_TRACING=32, P_INSTRUMENT=40, P_MITIGATION=52,
       T_HIDE=17, S_KERNEL_DEBUGGER=35, O_BASIC=0, O_HANDLE_FLAGS=4 };
enum { LAST_ERROR_SEED=0xc0dec0deu, STATUS_NOT_AVAILABLE=0xe0010001u };
typedef struct { ULONG Flags; } HANDLE_TRACE_ENABLE;
typedef struct { HANDLE Handle; ULONG TotalTraces; ULONG Pad; } HANDLE_TRACE_HEADER;
typedef struct { HANDLE Handle; CLIENT_ID ClientId; ULONG Type; PVOID Stacks[16]; } HANDLE_TRACE_ENTRY;
typedef struct { HANDLE Handle; ULONG TotalTraces; HANDLE_TRACE_ENTRY Entries[1]; } HANDLE_TRACE_QUERY;
typedef struct { ULONG Version, Reserved; PVOID Callback; } INSTRUMENT_CALLBACK;
/* Native mitigation query/set: 32-bit selector + 32-bit policy flags.
 * OptionsMask/DEP are separately exposed through the documented Win32 API;
 * NT form remains a measured request, never treated as success without status.
 */
typedef struct { ULONG Policy, Flags; } NT_MITIGATION_REQUEST;
typedef struct { BOOLEAN Enabled, NotPresent; } KERNEL_DEBUGGER_INFO;
typedef struct { BOOLEAN Inherit, ProtectFromClose; } OBJECT_HANDLE_FLAGS;
_Static_assert(sizeof(CONTEXT)==1232,"x64 CONTEXT");
_Static_assert(sizeof(EXCEPTION_RECORD)==152,"x64 EXCEPTION_RECORD");
_Static_assert(sizeof(INSTRUMENT_CALLBACK)==16,"instrumentation ABI");
_Static_assert(sizeof(NT_MITIGATION_REQUEST)==8,"native mitigation request ABI");
_Static_assert(offsetof(HANDLE_TRACE_QUERY,Entries)==16,"trace query ABI");
_Static_assert(sizeof(HANDLE_TRACE_ENTRY)==160,"trace entry ABI");

static NT_QPROC qproc; static NT_SPROC sproc;
static NT_QTHREAD qthread; static NT_STHREAD sthread;
static NT_QSYSTEM qsystem; static NT_QOBJECT qobject; static NT_CLOSE nclose;
static GET_MITIGATION getmit; static SET_MITIGATION setmit;
static volatile LONG active, veh_count, seh_count;
static EXCEPTION_RECORD veh_record, seh_record;
static CONTEXT veh_context, seh_context;
static EXCEPTION_RECORD top_record;
static CONTEXT top_context;
static volatile LONG top_count, top_continue, dr_active, worker_mode, worker_result;
static volatile LONG debug_cells[4];
static char output_buffer[65536];
static unsigned cell;
/* One bounded copy of v5c: capture the exact pre-call inputs, never format in
 * VEH/SEH. The assembly callee has Windows unwind metadata and restores all
 * seeded nonvolatile registers during normal return and exception unwind. */
typedef struct {
    uint64_t Rbx, Rbp, Rsi, Rdi, R12, R13, R14, R15, R11, EFlags, Rcx, Rsp, ReturnRip;
    unsigned char Xmm1[16];
} API_ENTRY209;
typedef struct { uint64_t Rbx,Rbp,Rsi,Rdi,R12,R13,R14,R15,R11,EFlags,Rax,Rsp; unsigned char XmmNV[10][16]; } API_AFTER268;
_Static_assert(sizeof(API_ENTRY209)==120,"assembly entry layout");
_Static_assert(offsetof(API_ENTRY209,Xmm1)==104,"assembly XMM offset");
_Static_assert(sizeof(API_AFTER268)==256,"assembly after layout");
extern uintptr_t ExcCtxPinnedCall209(uintptr_t function,uintptr_t argument,API_ENTRY209 *entry,API_AFTER268 *after);
static API_ENTRY209 api_entry209;
static API_AFTER268 api_after268;
static unsigned continue_mode;
static volatile LONG continue_level,continue_faults,nested_faults,nested_returned;
static CONTEXT nested_context;
static CONTEXT nested_requested385;
static EXCEPTION_RECORD nested_record;
static void exact_copy(void *d,const void *s,size_t n) {
    volatile unsigned char *to=(volatile unsigned char*)d;
    const volatile unsigned char *from=(const volatile unsigned char*)s;
    for(size_t i=0;i<n;i++) to[i]=from[i];
}
/* No formatting, allocation, loader calls or first-use initialization here. */
static LONG CALLBACK observer(PEXCEPTION_POINTERS p) {
    if(active && veh_count==0) {
        exact_copy(&veh_record,p->ExceptionRecord,sizeof(veh_record));
        exact_copy(&veh_context,p->ContextRecord,sizeof(veh_context));
        veh_count=1;
    }
    if(active && p->ExceptionRecord->ExceptionCode==0xc0000008u && continue_mode) {
        continue_faults++;
        if(continue_faults>4) return EXCEPTION_CONTINUE_SEARCH;
        if(continue_level) {
            exact_copy(&nested_record,p->ExceptionRecord,sizeof(nested_record));
            exact_copy(&nested_context,p->ContextRecord,sizeof(nested_context));
            nested_faults++;
            if(continue_mode>=17) {
                p->ContextRecord->R12=0xdeaddeaddead0012ULL;
                p->ContextRecord->R13=0xdeaddeaddead0013ULL;
                p->ContextRecord->ContextFlags &= ~2u;
                exact_copy(&nested_requested385,p->ContextRecord,sizeof(nested_requested385));
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if(continue_mode==3 || continue_mode==10 || continue_mode>=16) {
            continue_level=1;
            (void)CloseHandle((HANDLE)(uintptr_t)0x0de42346u);
            nested_returned=1;
            continue_level=0;
        }
        if(continue_mode==2) {p->ContextRecord->R14=0xabcde01401401401ULL;p->ContextRecord->R15=0xabcde01501501501ULL;}
        if(continue_mode==4) {p->ContextRecord->R12=0xabcde01201201201ULL;p->ContextRecord->R13=0xabcde01301301301ULL;}
        if(continue_mode==5) {p->ContextRecord->Rsi=0xabcde00600600601ULL;p->ContextRecord->Rdi=0xabcde00700700701ULL;}
        if(continue_mode==6) p->ContextRecord->Rbp=0xabcde00500500501ULL;
        if(continue_mode==7) p->ContextRecord->Rbx=0xabcde00300300301ULL;
        if(continue_mode>=8) {
            for(unsigned i=6;i<16;i++) {
                if((continue_mode==14 && i!=6) || (continue_mode==15 && i!=15)) continue;
                p->ContextRecord->FltSave.XmmRegisters[i].Low = continue_mode==11 ? 0 : (0xa100000000000000ULL|i);
                p->ContextRecord->FltSave.XmmRegisters[i].High = continue_mode==11 ? 0 : (0xa200000000000000ULL|i);
            }
            if(continue_mode>=9 && continue_mode<=13) p->ContextRecord->Rbp=continue_mode==11?0:0xabcde00500500501ULL;
            if(continue_mode==12) p->ContextRecord->ContextFlags &= ~8u; /* unselected FLOAT */
            if(continue_mode==13) p->ContextRecord->ContextFlags &= ~2u; /* unselected INTEGER */
            if(continue_mode>=16) {
                p->ContextRecord->R12=0xabcde01201201201ULL;
                p->ContextRecord->R13=0xabcde01301301301ULL;
                p->ContextRecord->Rbp=0xabcde00500500501ULL;
                if(continue_mode!=17) p->ContextRecord->ContextFlags &= ~2u;
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG filter(PEXCEPTION_POINTERS p) {
    if(active && seh_count==0) {
        exact_copy(&seh_record,p->ExceptionRecord,sizeof(seh_record));
        exact_copy(&seh_context,p->ContextRecord,sizeof(seh_context));
        seh_count=1;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}
static LONG WINAPI top_filter(PEXCEPTION_POINTERS p) {
    if(top_count==0) {exact_copy(&top_record,p->ExceptionRecord,sizeof(top_record));exact_copy(&top_context,p->ContextRecord,sizeof(top_context));top_count=1;}
    return top_continue?EXCEPTION_CONTINUE_EXECUTION:EXCEPTION_EXECUTE_HANDLER;
}
static LONG CALLBACK debug_observer(PEXCEPTION_POINTERS p) {
    if(!dr_active || p->ExceptionRecord->ExceptionCode!=EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    if(veh_count==0) {exact_copy(&veh_record,p->ExceptionRecord,sizeof(veh_record));exact_copy(&veh_context,p->ContextRecord,sizeof(veh_context));}
    veh_count++;
    /* Owned synthetic one-shot breakpoint; no WinAPI/allocator/loader in handler. */
    p->ContextRecord->Dr7=0;p->ContextRecord->EFlags&=~0x100u;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static void blob(const char *field,const void *p,size_t n) {
    const unsigned char *b=(const unsigned char*)p;
    printf("WINENV cell=%03u field=%s bytes=%zu hex=",cell,field,n);
    for(size_t i=0;i<n;i++) printf("%02x",b[i]);
    putchar('\n');
}
static void value(const char *field,uint64_t v) {
    printf("WINENV cell=%03u field=%s value=%016llx\n",cell,field,(unsigned long long)v);
}
static void result(const char *op,NTSTATUS s,ULONG length,ULONG error) {
    printf("WINENV cell=%03u op=%s status=%08lx return_length=%08lx last_error=%08lx\n",
           cell,op,(unsigned long)(ULONG)s,(unsigned long)length,(unsigned long)error);
}
static void available(const char *name,int yes) {
    printf("WINENV cell=%03u availability=%s state=%s\n",cell,name,yes?"PRESENT":"NOT_ENABLED_EXPORT_MISSING");
}
static void query_process(ULONG cls,void *data,ULONG bytes,const char *name) {
    ULONG len=0xc0dec0deu;
    SetLastError(LAST_ERROR_SEED);
    NTSTATUS st=qproc?qproc(GetCurrentProcess(),cls,data,bytes,&len):(NTSTATUS)STATUS_NOT_AVAILABLE;
    ULONG err=GetLastError(); result(name,st,len,err); value("Query.Class",cls);value("Query.RequestBytes",bytes);
    blob(name,data,bytes>192?192:bytes);
}
static void set_process(ULONG cls,void *data,ULONG bytes,const char *name) {
    SetLastError(LAST_ERROR_SEED);
    NTSTATUS st=sproc?sproc(GetCurrentProcess(),cls,data,bytes):(NTSTATUS)STATUS_NOT_AVAILABLE;
    result(name,st,0,GetLastError());value("Set.Class",cls);value("Set.RequestBytes",bytes);
    if(data&&bytes) blob(name,data,bytes>32?32:bytes);
}
static void tracing_query(void) {
    HANDLE_TRACE_QUERY x; memset(&x,0xa5,sizeof(x)); x.Handle=(HANDLE)(uintptr_t)0x0de42345;
    query_process(P_HANDLE_TRACING,&x,sizeof(x),"NtQuery.HandleTracing");
    value("HandleTracing.TotalTraces",x.TotalTraces);
}
static void enable_trace(void) {
    HANDLE_TRACE_ENABLE x={0};set_process(P_HANDLE_TRACING,&x,sizeof(x),"NtSet.HandleTracing.Enable");
    tracing_query();
}
static SIZE_T mitigation_size(unsigned policy) {
    if(policy==ProcessDEPPolicy) return sizeof(PROCESS_MITIGATION_DEP_POLICY);
    if(policy==ProcessMitigationOptionsMask) return 2*sizeof(ULONGLONG);
    return sizeof(DWORD);
}
static void query_mitigation(unsigned policy) {
    NT_MITIGATION_REQUEST nt={policy,0xa5a5a5a5u};
    query_process(P_MITIGATION,&nt,sizeof(nt),"NtQuery.Mitigation");
    value("Mitigation.Policy",policy); value("Mitigation.NTFlags",nt.Flags);
    unsigned char data[16];memset(data,0xa5,sizeof(data));SIZE_T n=mitigation_size(policy);
    SetLastError(LAST_ERROR_SEED);
    BOOL ok=getmit?getmit(GetCurrentProcess(),(PROCESS_MITIGATION_POLICY)policy,data,n):FALSE;
    ULONG err=GetLastError();value("GetProcessMitigationPolicy.Return",ok);value("GetProcessMitigationPolicy.LastError",err);
    blob("GetProcessMitigationPolicy",data,n);
}
static void strict_policy(ULONG flags) {
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY x;memset(&x,0,sizeof(x));x.Flags=flags;
    SetLastError(LAST_ERROR_SEED);
    BOOL ok=setmit?setmit(ProcessStrictHandleCheckPolicy,&x,sizeof(x)):FALSE;
    ULONG err=GetLastError();value("SetStrict.Flags",flags);value("SetStrict.Return",ok);value("SetStrict.LastError",err);
    query_mitigation(ProcessStrictHandleCheckPolicy);
}
static void exception_dump(void) {
    value("Exception.VEHCount",veh_count);value("Exception.SEHCount",seh_count);
    if(veh_count) {blob("VEH.EXCEPTION_RECORD",&veh_record,sizeof(veh_record));blob("VEH.CONTEXT",&veh_context,sizeof(veh_context));}
    if(seh_count) {blob("SEH.EXCEPTION_RECORD",&seh_record,sizeof(seh_record));blob("SEH.CONTEXT",&seh_context,sizeof(seh_context));}
}
static const char *const names[]={
 "CloseHandle.invalid.default","NtClose.invalid.default",
 "CloseHandle.invalid.tracing","NtClose.invalid.tracing",
 "CloseHandle.invalid.strict","NtClose.invalid.strict",
 "CloseHandle.invalid.strict_permanent","NtClose.invalid.strict_permanent",
 "CloseHandle.protected","NtClose.protected",
 "CloseHandle.pseudo_process","NtClose.pseudo_process",
 "CloseHandle.pseudo_thread","NtClose.pseudo_thread",
 "CloseHandle.valid_event","NtClose.valid_event",
 "Query.DebugPort","Query.DebugObjectHandle","Query.DebugFlags","Query.HandleTracing",
 "Query.InstrumentationCallback","Query.BreakOnTermination",
 "Query.Mitigation.DEP","Query.Mitigation.ASLR","Query.Mitigation.DynamicCode","Query.Mitigation.StrictHandle",
 "Query.Mitigation.SystemCallDisable","Query.Mitigation.OptionsMask","Query.Mitigation.ExtensionPoint",
 "Query.Mitigation.CFG","Query.Mitigation.Signature","Query.Mitigation.Font","Query.Mitigation.ImageLoad",
 "Query.Mitigation.SystemCallFilter","Query.Mitigation.Payload","Query.Mitigation.ChildProcess",
 "Query.Mitigation.SideChannel","Query.Mitigation.UserShadowStack","Query.Mitigation.RedirectionTrust",
 "Query.Mitigation.UserPointerAuth","Query.Mitigation.SEHOP",
 "Set.DebugPort.null","Set.DebugObjectHandle.null","Set.DebugFlags.one","Set.HandleTracing.enable",
 "Set.HandleTracing.disable","Set.InstrumentationCallback.null","Set.BreakOnTermination.zero",
 "Set.Mitigation.DEP.zero","Set.Mitigation.ASLR.zero","Set.Mitigation.DynamicCode.zero",
 "Set.Mitigation.StrictHandle.zero","Set.Mitigation.SystemCallDisable.zero","Set.Mitigation.OptionsMask.readonly",
 "Set.Mitigation.ExtensionPoint.zero","Set.Mitigation.CFG.zero","Set.Mitigation.Signature.zero",
 "Set.Mitigation.Font.zero","Set.Mitigation.ImageLoad.zero","Set.Mitigation.SystemCallFilter.zero",
 "Set.Mitigation.Payload.zero","Set.Mitigation.ChildProcess.zero","Set.Mitigation.SideChannel.zero",
 "Set.Mitigation.UserShadowStack.zero","Set.Mitigation.RedirectionTrust.zero","Set.Mitigation.UserPointerAuth.zero",
 "Set.Mitigation.SEHOP.zero",
 "Thread.Hide.query_set_query","System.KernelDebuggerInformation",
 "Object.invalid.basic","Object.protected.basic","Object.valid.basic",
 "Object.invalid.flags","Object.protected.flags","Object.pseudo_process.basic"
 ,"Environment.PEB_TEB_Heap","Environment.DebuggerReports","Exception.UnhandledFilter.direct",
 "Exception.UnhandledFilter.real","Clock.Monotonic","Context.DebugRegisters.roundtrip",
 "Context.OwnExecuteBreakpoint","Context.OwnSingleStep"
};
enum { CELL_COUNT=sizeof(names)/sizeof(names[0]) };
_Static_assert(CELL_COUNT==83,"finite cell inventory");
_Static_assert(MaxProcessMitigationPolicy==19,"audit new SDK mitigation siblings before building");
static void exercise_close(void) {
    unsigned mode=cell/2;BOOL nt=cell&1;HANDLE h=(HANDLE)(uintptr_t)0x0de42345;
    if(mode==1) enable_trace();
    if(mode==2) strict_policy(1);
    if(mode==3) {strict_policy(1);strict_policy(3);}
    if(mode==4||mode==7) {
        h=CreateEventW(NULL,FALSE,FALSE,NULL);value("Event.Created",h!=NULL);
        if(!h) {value("Event.LastError",GetLastError());return;}
        if(mode==4) {SetLastError(LAST_ERROR_SEED);BOOL ok=SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,HANDLE_FLAG_PROTECT_FROM_CLOSE);ULONG err=GetLastError();value("Protect.Return",ok);value("Protect.LastError",err);}
    }
    if(mode==5) h=GetCurrentProcess();
    if(mode==6) h=GetCurrentThread();
    value("Close.Handle",(uintptr_t)h);
    volatile ULONG returned=0,code=0xa5a5a5a5u,err=LAST_ERROR_SEED;
    fflush(stdout);active=1;
    __try {
        SetLastError(LAST_ERROR_SEED);
        if(nt) code=nclose?(ULONG)ExcCtxPinnedCall209((uintptr_t)nclose,(uintptr_t)h,&api_entry209,&api_after268):STATUS_NOT_AVAILABLE;
        else code=(ULONG)ExcCtxPinnedCall209((uintptr_t)&CloseHandle,(uintptr_t)h,&api_entry209,&api_after268);
        err=GetLastError();returned=1;
    } __except(filter(GetExceptionInformation())) { err=GetLastError(); }
    active=0;
    value("Close.Returned",returned);value(nt?"NtClose.Status":"CloseHandle.Return",code);value("Close.LastError",err);
    value("Continue.Mode",continue_mode);value("Continue.Faults",continue_faults);
    value("Continue.NestedFaults",nested_faults);value("Continue.NestedReturned",nested_returned);
    blob("API.ENTRY268",&api_entry209,sizeof(api_entry209));
    blob("API.AFTER341",&api_after268,sizeof(api_after268));
    if(nested_faults) {blob("NESTED.CONTEXT",&nested_context,sizeof(nested_context));blob("NESTED.EXCEPTION_RECORD",&nested_record,sizeof(nested_record));}
    if(continue_mode>=17 && nested_faults) blob("NESTED.REQUESTED385",&nested_requested385,sizeof(nested_requested385));
    exception_dump();
    if(mode==4) {SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,0);CloseHandle(h);}
}
static void query_scalar(unsigned cls,unsigned size,const char *name) {
    union { uint64_t align; unsigned char bytes[192]; } data;memset(&data,0xa5,sizeof(data));
    query_process(cls,data.bytes,size,name);
}
static void query_class(unsigned c) {
    switch(c) {
    case 16: query_scalar(P_DEBUG_PORT,sizeof(ULONG_PTR),"NtQuery.DebugPort");break;
    case 17: { HANDLE h=(HANDLE)(uintptr_t)0xa5a5a5a5a5a5a5a5ULL;ULONG len=LAST_ERROR_SEED;
        SetLastError(LAST_ERROR_SEED);NTSTATUS st=qproc?qproc(GetCurrentProcess(),P_DEBUG_OBJECT,&h,sizeof(h),&len):(NTSTATUS)STATUS_NOT_AVAILABLE;
        result("NtQuery.DebugObjectHandle",st,len,GetLastError());value("DebugObjectHandle",(uintptr_t)h);
        if(st>=0 && h && h!=(HANDLE)(intptr_t)-1 && nclose) nclose(h);break; }
    case 18: query_scalar(P_DEBUG_FLAGS,sizeof(ULONG),"NtQuery.DebugFlags");break;
    case 19: tracing_query();break;
    case 20: query_scalar(P_INSTRUMENT,sizeof(INSTRUMENT_CALLBACK),"NtQuery.InstrumentationCallback");break;
    case 21: query_scalar(P_BREAK,sizeof(ULONG),"NtQuery.BreakOnTermination");break;
    default: query_mitigation(c-22);break;
    }
}
static void set_class(unsigned c) {
    if(c>=48) {
        unsigned pol=c-48;query_mitigation(pol);
        if(pol==ProcessMitigationOptionsMask) {printf("WINENV cell=%03u set_state=NOT_APPLICABLE_READONLY_OPTIONS_MASK\n",cell);return;}
        NT_MITIGATION_REQUEST nt={pol,0};set_process(P_MITIGATION,&nt,sizeof(nt),"NtSet.Mitigation.Zero");
        /* Measure NT setter effect before a second API can change the state. */
        query_mitigation(pol);
        unsigned char zero[16]={0};SIZE_T n=mitigation_size(pol);SetLastError(LAST_ERROR_SEED);
        BOOL ok=setmit?setmit((PROCESS_MITIGATION_POLICY)pol,zero,n):FALSE;
        ULONG err=GetLastError();value("SetProcessMitigationPolicy.Return",ok);value("SetProcessMitigationPolicy.LastError",err);
        query_mitigation(pol);return;
    }
    ULONG zero=0,one=1;HANDLE null_handle=NULL;INSTRUMENT_CALLBACK inst={0,0,NULL};
    switch(c) {
    case 41:set_process(P_DEBUG_PORT,&null_handle,sizeof(null_handle),"NtSet.DebugPort.Null");query_scalar(P_DEBUG_PORT,sizeof(null_handle),"NtQuery.DebugPort.After");break;
    case 42:set_process(P_DEBUG_OBJECT,&null_handle,sizeof(null_handle),"NtSet.DebugObjectHandle.Null");query_scalar(P_DEBUG_OBJECT,sizeof(null_handle),"NtQuery.DebugObjectHandle.After");break;
    case 43:query_scalar(P_DEBUG_FLAGS,sizeof(one),"NtQuery.DebugFlags.Before");set_process(P_DEBUG_FLAGS,&one,sizeof(one),"NtSet.DebugFlags.One");query_scalar(P_DEBUG_FLAGS,sizeof(one),"NtQuery.DebugFlags.After");break;
    case 44:enable_trace();break;
    case 45:enable_trace();set_process(P_HANDLE_TRACING,NULL,0,"NtSet.HandleTracing.Disable");tracing_query();break;
    case 46:set_process(P_INSTRUMENT,&inst,sizeof(inst),"NtSet.InstrumentationCallback.Null");query_scalar(P_INSTRUMENT,sizeof(inst),"NtQuery.InstrumentationCallback.After");break;
    case 47:query_scalar(P_BREAK,sizeof(zero),"NtQuery.BreakOnTermination.Before");set_process(P_BREAK,&zero,sizeof(zero),"NtSet.BreakOnTermination.Zero");query_scalar(P_BREAK,sizeof(zero),"NtQuery.BreakOnTermination.After");break;
    }
}
static void other_class(unsigned c) {
    ULONG len=LAST_ERROR_SEED;NTSTATUS st;
    if(c==67) {
        BOOLEAN hidden=0xa5;SetLastError(LAST_ERROR_SEED);
        st=qthread?qthread(GetCurrentThread(),T_HIDE,&hidden,sizeof(hidden),&len):(NTSTATUS)STATUS_NOT_AVAILABLE;
        result("NtQuery.ThreadHide.Before",st,len,GetLastError());value("ThreadHide.Before",hidden);
        /* Only the owned un-debugged synthetic process, never hide a debugger. */
        if(IsDebuggerPresent()) {printf("WINENV cell=%03u set_state=NOT_ENABLED_DEBUGGED_PROCESS\n",cell);return;}
        SetLastError(LAST_ERROR_SEED);st=sthread?sthread(GetCurrentThread(),T_HIDE,NULL,0):(NTSTATUS)STATUS_NOT_AVAILABLE;
        result("NtSet.ThreadHide",st,0,GetLastError());hidden=0xa5;len=LAST_ERROR_SEED;SetLastError(LAST_ERROR_SEED);
        st=qthread?qthread(GetCurrentThread(),T_HIDE,&hidden,sizeof(hidden),&len):(NTSTATUS)STATUS_NOT_AVAILABLE;
        result("NtQuery.ThreadHide.After",st,len,GetLastError());value("ThreadHide.After",hidden);return;
    }
    if(c==68) {
        KERNEL_DEBUGGER_INFO x={0xa5,0xa5};SetLastError(LAST_ERROR_SEED);
        st=qsystem?qsystem(S_KERNEL_DEBUGGER,&x,sizeof(x),&len):(NTSTATUS)STATUS_NOT_AVAILABLE;
        result("NtQuery.SystemKernelDebuggerInformation",st,len,GetLastError());blob("KernelDebugger",&x,sizeof(x));return;
    }
    BOOL invalid=c==69||c==72,protected_handle=c==70||c==73;
    HANDLE h=invalid?(HANDLE)(uintptr_t)0x0de42345:c==74?GetCurrentProcess():CreateEventW(NULL,FALSE,FALSE,NULL);
    if(!h) {value("Event.Created",0);value("Event.LastError",GetLastError());return;}
    if(protected_handle) {BOOL ok=SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,HANDLE_FLAG_PROTECT_FROM_CLOSE);value("Protect.Return",ok);}
    unsigned cls=c==72||c==73?O_HANDLE_FLAGS:O_BASIC;
    union { uint64_t alignment; unsigned char bytes[56]; } b;memset(&b,0xa5,sizeof(b));ULONG n=cls==O_HANDLE_FLAGS?sizeof(OBJECT_HANDLE_FLAGS):sizeof(OBJECT_BASIC_INFORMATION);
    _Static_assert(sizeof(OBJECT_BASIC_INFORMATION)==56,"object basic ABI");
    SetLastError(LAST_ERROR_SEED);st=qobject?qobject(h,cls,&b,n,&len):(NTSTATUS)STATUS_NOT_AVAILABLE;
    result("NtQuery.Object",st,len,GetLastError());value("Object.Class",cls);blob("Object.Info",&b,n);
    if(!invalid&&c!=74) {if(protected_handle) SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,0);CloseHandle(h);}
}
static void load_exports(void) {
    HMODULE n=GetModuleHandleW(L"ntdll.dll"),k=GetModuleHandleW(L"kernel32.dll");
#define LOAD_N(var,type,name) var=(type)GetProcAddress(n,name);available(name,var!=NULL)
    LOAD_N(qproc,NT_QPROC,"NtQueryInformationProcess");LOAD_N(sproc,NT_SPROC,"NtSetInformationProcess");
    LOAD_N(qthread,NT_QTHREAD,"NtQueryInformationThread");LOAD_N(sthread,NT_STHREAD,"NtSetInformationThread");
    LOAD_N(qsystem,NT_QSYSTEM,"NtQuerySystemInformation");LOAD_N(qobject,NT_QOBJECT,"NtQueryObject");LOAD_N(nclose,NT_CLOSE,"NtClose");
    getmit=(GET_MITIGATION)GetProcAddress(k,"GetProcessMitigationPolicy");available("GetProcessMitigationPolicy",getmit!=NULL);
    setmit=(SET_MITIGATION)GetProcAddress(k,"SetProcessMitigationPolicy");available("SetProcessMitigationPolicy",setmit!=NULL);
#undef LOAD_N
}
static uintptr_t own_teb(void) {
    uintptr_t p;__asm__ volatile("movq %%gs:0x30,%0":"=r"(p));return p;
}
static void environment_fields(void) {
    unsigned char *teb=(unsigned char*)own_teb();unsigned char *peb=*(unsigned char**)(teb+0x60);
    value("TEB.Self",(uintptr_t)teb);value("PEB.Address",(uintptr_t)peb);
    value("PEB.BeingDebugged",peb[2]);value("PEB.NtGlobalFlag",*(ULONG*)(peb+0xbc));
    void *heap=*(void**)(peb+0x30);value("PEB.ProcessHeap",(uintptr_t)heap);value("GetProcessHeap",(uintptr_t)GetProcessHeap());
    SetLastError(LAST_ERROR_SEED);ULONG api_error=GetLastError(),teb_error=*(ULONG*)(teb+0x68);
    value("TEB.LastErrorValue",teb_error);value("GetLastError.Value",api_error);value("TEB.LastErrorMatches",api_error==teb_error);
    ULONG signature=*(ULONG*)((unsigned char*)heap+0x10);value("Heap.Signature",signature);
    if(signature==0xffeeffeeu) {
        value("Heap.Flags",*(ULONG*)((unsigned char*)heap+0x70));value("Heap.ForceFlags",*(ULONG*)((unsigned char*)heap+0x74));
        printf("WINENV cell=%03u heap_layout=NT_HEAP_WINDOWS10_COMPATIBLE\n",cell);
    } else printf("WINENV cell=%03u heap_flags_state=NOT_ENABLED_UNKNOWN_OR_SEGMENT_HEAP_LAYOUT\n",cell);
}
static void debugger_reports(void) {
    SetLastError(LAST_ERROR_SEED);BOOL local=IsDebuggerPresent();ULONG err=GetLastError();
    value("IsDebuggerPresent.Return",local);value("IsDebuggerPresent.LastError",err);
    BOOL remote=0x7f;SetLastError(LAST_ERROR_SEED);BOOL ok=CheckRemoteDebuggerPresent(GetCurrentProcess(),&remote);err=GetLastError();
    value("CheckRemoteDebuggerPresent.Return",ok);value("CheckRemoteDebuggerPresent.Value",remote);value("CheckRemoteDebuggerPresent.LastError",err);
    SetLastError(LAST_ERROR_SEED);OutputDebugStringA("WINENV v5b owned benign API conformity cell\n");err=GetLastError();value("OutputDebugStringA.LastError",err);
    SetLastError(LAST_ERROR_SEED);OutputDebugStringW(L"WINENV v5b owned benign API conformity cell\n");err=GetLastError();value("OutputDebugStringW.LastError",err);
}
static void unhandled_filter(BOOL actual_path) {
    SetErrorMode(SEM_NOGPFAULTERRORBOX|SEM_FAILCRITICALERRORS);
    LPTOP_LEVEL_EXCEPTION_FILTER old=SetUnhandledExceptionFilter(top_filter);top_continue=actual_path;
    if(actual_path) {
        ULONG_PTR parameters[2]={0x1122334455667788ULL,0x8877665544332211ULL};
        printf("WINENV cell=%03u phase=unhandled_raise code=e0424242\n",cell);fflush(stdout);
        RaiseException(0xe0424242u,0,2,parameters);
        value("Unhandled.RaiseReturned",1);
    } else {
        EXCEPTION_RECORD record;CONTEXT context;memset(&record,0,sizeof(record));memset(&context,0,sizeof(context));
        (void)ExcCtxPinnedCall209((uintptr_t)&RtlCaptureContext,(uintptr_t)&context,&api_entry209,&api_after268);
        value("Continue.Mode",continue_mode);value("Continue.Faults",continue_faults);
    value("Continue.NestedFaults",nested_faults);value("Continue.NestedReturned",nested_returned);
    blob("API.ENTRY268",&api_entry209,sizeof(api_entry209));
    blob("API.AFTER341",&api_after268,sizeof(api_after268));
    if(nested_faults) {blob("NESTED.CONTEXT",&nested_context,sizeof(nested_context));blob("NESTED.EXCEPTION_RECORD",&nested_record,sizeof(nested_record));}
        blob("UEF.INPUT_CONTEXT209",&context,sizeof(context));
        record.ExceptionCode=0xe0424242u;record.ExceptionAddress=(void*)(uintptr_t)context.Rip;
        EXCEPTION_POINTERS pair={&record,&context};SetLastError(LAST_ERROR_SEED);
        LONG result_code=UnhandledExceptionFilter(&pair);ULONG err=GetLastError();value("UnhandledExceptionFilter.Return",(ULONG)result_code);value("UnhandledExceptionFilter.LastError",err);
    }
    value("Unhandled.TopCount",top_count);
    if(top_count) {blob("UEF.EXCEPTION_RECORD",&top_record,sizeof(top_record));blob("UEF.CONTEXT",&top_context,sizeof(top_context));}
    SetUnhandledExceptionFilter(old);
}
static void clocks(void) {
    LARGE_INTEGER frequency={0},before={0},after={0};BOOL freq_ok=QueryPerformanceFrequency(&frequency);
    BOOL before_ok=QueryPerformanceCounter(&before);ULONGLONG tick_before=GetTickCount64(),tsc_before=__rdtsc();
    DWORD tick32_before=GetTickCount(),prev_tick32=tick32_before;
    ULONGLONG prev_tsc=tsc_before,prev_tick=tick_before;LONGLONG prev_qpc=before.QuadPart;
    unsigned tsc_back=0,qpc_back=0,tick_back=0,tick32_back=0,qpc_failed=!before_ok;
    for(unsigned i=0;i<32;i++) {
        Sleep(1);ULONGLONG tsc=__rdtsc(),tick=GetTickCount64();DWORD tick32=GetTickCount();LARGE_INTEGER q;
        if(!QueryPerformanceCounter(&q)) {qpc_failed++;q.QuadPart=prev_qpc;}
        tsc_back+=tsc<prev_tsc;tick_back+=tick<prev_tick;qpc_back+=q.QuadPart<prev_qpc;
        /* Modular subtraction admits a real 49.7-day DWORD wrap, not regress. */
        tick32_back+=(DWORD)(tick32-prev_tick32)>0x80000000u;
        prev_tsc=tsc;prev_tick=tick;prev_tick32=tick32;prev_qpc=q.QuadPart;
    }
    if(!QueryPerformanceCounter(&after)) qpc_failed++;ULONGLONG tick_after=GetTickCount64(),tsc_after=__rdtsc();
    DWORD tick32_after=GetTickCount();
    value("Clock.FrequencySuccess",freq_ok);value("Clock.QPCFailures",qpc_failed);value("Clock.TSCBackwards",tsc_back);
    value("Clock.QPCBackwards",qpc_back);value("Clock.TickBackwards",tick_back);value("Clock.Samples",32);
    value("Clock.Tick32Backwards",tick32_back);value("Clock.Tick32Delta",(DWORD)(tick32_after-tick32_before));
    value("Clock.Frequency",frequency.QuadPart);value("Clock.QPCDelta",after.QuadPart-before.QuadPart);
    value("Clock.TickDelta",tick_after-tick_before);value("Clock.TSCDelta",tsc_after-tsc_before);
    ULONGLONG qpc_ms=(freq_ok&&frequency.QuadPart>0&&after.QuadPart>=before.QuadPart)?
        (ULONGLONG)(after.QuadPart-before.QuadPart)*1000/(ULONGLONG)frequency.QuadPart:0;
    ULONGLONG tick_ms=tick_after-tick_before;
    BOOL progress=freq_ok&&frequency.QuadPart>0&&!qpc_failed&&after.QuadPart>before.QuadPart&&tsc_after>tsc_before&&tick_ms>0&&(DWORD)(tick32_after-tick32_before)>0;
    value("Clock.AllCountersProgress",progress);
    value("Clock.QPCTickUnitsAgree",progress&&qpc_ms<=tick_ms*4+32&&qpc_ms*4+32>=tick_ms);
    value("Clock.Tick32Tick64UnitsAgree",(DWORD)(tick32_after-tick32_before)<=tick_ms+32&&(DWORD)(tick32_after-tick32_before)+32>=tick_ms);
    printf("WINENV cell=%03u timing_scope=MONOTONICITY_AND_UNITS_NOT_EXACT_PERFORMANCE\n",cell);
}
__attribute__((noinline)) static void debug_target(void) {debug_cells[0]++;}
__attribute__((naked,noinline)) static void step_target(void) {
    __asm__ volatile("pushfq\n orq $0x100,(%rsp)\n popfq\n .globl winenv_tf_nop\nwinenv_tf_nop:\n nop\n .globl winenv_tf_after\nwinenv_tf_after:\n ret\n");
}
extern unsigned char winenv_tf_nop,winenv_tf_after;
static DWORD WINAPI debug_worker(void *unused) {
    (void)unused;if(worker_mode==82) step_target();else debug_target();worker_result=1;return 0;
}
static void debug_registers(unsigned mode) {
    worker_mode=mode;HANDLE thread=CreateThread(NULL,0,debug_worker,NULL,CREATE_SUSPENDED,NULL);
    value("DebugThread.Created",thread!=NULL);if(!thread) return;
    CONTEXT before,requested,after;memset(&before,0,sizeof(before));before.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    printf("CONTEXT_PROBE phase=Get winenv=debug_before\n");fflush(stdout);SetLastError(LAST_ERROR_SEED);
    BOOL got=GetThreadContext(thread,&before);ULONG err=GetLastError();
    value("GetThreadContext.BeforeReturn",got);value("GetThreadContext.BeforeLastError",err);blob("Debug.Before",&before,sizeof(before));
    memcpy(&requested,&before,sizeof(requested));requested.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    if(mode==80) {requested.Dr0=(uintptr_t)&debug_cells[0];requested.Dr1=(uintptr_t)&debug_cells[1];requested.Dr2=(uintptr_t)&debug_cells[2];requested.Dr3=(uintptr_t)&debug_cells[3];requested.Dr6=0;requested.Dr7=0;}
    if(mode==81) {requested.Dr0=(uintptr_t)&debug_target;requested.Dr1=requested.Dr2=requested.Dr3=0;requested.Dr6=0;requested.Dr7=1;}
    blob("Debug.Requested",&requested,sizeof(requested));BOOL set=FALSE;
    if(got && mode!=82) {SetLastError(LAST_ERROR_SEED);set=SetThreadContext(thread,&requested);err=GetLastError();value("SetThreadContext.Return",set);value("SetThreadContext.LastError",err);}
    memset(&after,0,sizeof(after));after.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    printf("CONTEXT_PROBE phase=Get winenv=debug_after\n");fflush(stdout);SetLastError(LAST_ERROR_SEED);
    BOOL after_ok=GetThreadContext(thread,&after);err=GetLastError();value("GetThreadContext.AfterReturn",after_ok);value("GetThreadContext.AfterLastError",err);blob("Debug.After",&after,sizeof(after));
    value("Debug.Target",(uintptr_t)&debug_target);value("Debug.TFNop",(uintptr_t)&winenv_tf_nop);value("Debug.TFAfter",(uintptr_t)&winenv_tf_after);
    for(unsigned i=0;i<4;i++) {char name[32];snprintf(name,sizeof(name),"Debug.OwnData%u",i);value(name,(uintptr_t)&debug_cells[i]);}
    PVOID handler=AddVectoredExceptionHandler(1,debug_observer);value("Debug.HandlerInstalled",handler!=NULL);
    if(!handler) {
        if(got) SetThreadContext(thread,&before);
        ResumeThread(thread);WaitForSingleObject(thread,2000);CloseHandle(thread);
        printf("WINENV cell=%03u debug_state=NOT_ENABLED_HANDLER_INSTALL_FAILED\n",cell);return;
    }
    dr_active=(mode==82)||(mode==81&&set);
    DWORD resume=ResumeThread(thread);value("Debug.ResumeReturn",resume);DWORD wait=WaitForSingleObject(thread,2000);
    value("Debug.WaitReturn",wait);value("Debug.WorkerCompleted",worker_result);value("Debug.FaultCount",veh_count);
    if(wait!=WAIT_OBJECT_0) {
        /* Publish the first fault once before owned process termination. Do not
         * leave a faulty resume cycling or remove a handler under a live worker. */
        exception_dump();printf("WINENV_PROBE INCOMPLETE cell=%03u reason=OWNED_DEBUG_THREAD_WAIT exit=124\n",cell);
        fflush(stdout);ExitProcess(124);
    }
    dr_active=0;
    if(handler) RemoveVectoredExceptionHandler(handler);CloseHandle(thread);
    printf("CONTEXT_PROBE phase=debug_complete\n");fflush(stdout);
}
static void extended_class(unsigned c) {
    if(c==75) environment_fields();else if(c==76) debugger_reports();else if(c==77) unhandled_filter(FALSE);
    else if(c==79) clocks();else if(c>=80) debug_registers(c);
}
int main(int argc,char **argv) {
    setvbuf(stdout,output_buffer,_IOFBF,sizeof(output_buffer));
    if(argc==2 && !strcmp(argv[1],"--list")) {
        for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) printf("WINENV_CELL %03u %s\n",i,names[i]);return 0;
    }
    if((argc!=3&&argc!=4)||strcmp(argv[1],"cell")) {fprintf(stderr,"usage: windows_process64-v5c.exe --list | cell <0..82>\n");return 2;}
    char *end=NULL;unsigned long n=strtoul(argv[2],&end,10);if(!end||*end||n>=CELL_COUNT) return 2;cell=(unsigned)n;continue_mode=argc==4?(unsigned)strtoul(argv[3],NULL,10):0;if(continue_mode>18||(cell!=2&&cell!=3))return 2;
    printf("WINENV_PROBE version=continue268 base=pinned209 cell=%03u name=%s context_bytes=%zu exception_bytes=%zu\n",cell,names[cell],sizeof(CONTEXT),sizeof(EXCEPTION_RECORD));
    value("Image.Base",(uintptr_t)GetModuleHandleW(NULL));value("Cell.Entry",(uintptr_t)&main);value("Process.Debugged",IsDebuggerPresent());
    load_exports();PVOID veh=AddVectoredExceptionHandler(1,observer);if(!veh) {printf("WINENV_PROBE FAILED_VEH_INSTALL\n");fflush(stdout);return 2;}
    printf("WINENV_PROBE phase=identity-hold\n");fflush(stdout);Sleep(1000);
    if(IsDebuggerPresent() && ((cell>=41&&cell<=43)||cell==67)) {
        printf("WINENV cell=%03u state=NOT_ENABLED_DEBUGGED_PROCESS\n",cell);
    } else if(cell<16) exercise_close();
    else if(cell==78) {active=1;unhandled_filter(TRUE);active=0;exception_dump();}
    else {
        /* Retain and terminate the one cell on an unexpected API exception. */
        active=1;
        __try {if(cell<=40) query_class(cell);else if(cell<=66) set_class(cell);else if(cell<=74) other_class(cell);else extended_class(cell);}
        __except(filter(GetExceptionInformation())) {printf("WINENV cell=%03u unexpected_api_exception=1\n",cell);}
        active=0;exception_dump();
    }
    RemoveVectoredExceptionHandler(veh);
    printf("WINENV_PROBE COMPLETE cell=%03u recorded=1 verdict=OBSERVATION_REFERENCE_REQUIRED\n",cell);fflush(stdout);return 0;
}
