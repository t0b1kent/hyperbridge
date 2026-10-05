/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2026 HyperBridge contributors */
#define _WIN32_WINNT 0x0a00
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

typedef struct __declspec(align(64)) { uint64_t gpr[16],flags,reserved; unsigned char fx[512],ymmhi[256]; } SNAPSHOT;
_Static_assert(offsetof(SNAPSHOT,fx)==144,"assembly layout fx");
_Static_assert(offsetof(SNAPSHOT,ymmhi)==656,"assembly layout ymm");
SNAPSHOT g_pre,g_post;
__declspec(align(64)) unsigned char g_stack_pre[256],g_xmm_markers[256],g_ymm_markers[512];
__declspec(align(16)) CONTEXT g_capture;
uint32_t g_use_avx,g_flag_mode,g_fault_kind,g_mxcsr=0x3f80;
uint64_t g_explicit_flags=0x202,g_api_result;
ULONG_PTR g_raise_parameters[3]={0x1111222233334444ULL,0x5555666677778888ULL,0x9999aaaabbbbccccULL};
void *g_readonly,*g_noexec,*g_guard,*g_misaligned;
void *g_noncanon,*g_bad_data_address;
__declspec(align(8)) uint32_t g_debug_cell;
uint16_t g_after_fcw,g_after_fsw,g_seg_before[6],g_seg_after[6];
unsigned char g_after_fenv[28],g_after_st0[10],g_after_st1[10],g_roundtrip_st0[10];
uint32_t g_x87_reads;
static char g_stdout_buffer[65536];
uint16_t g_fcw=0x027f;
void *g_fault_entry,*g_resume_entry;
uint64_t g_handler_entry_rsp;
extern void run_case_asm(void);
extern LONG CALLBACK veh_entry(PEXCEPTION_POINTERS);
extern LONG seh_filter_entry(PEXCEPTION_POINTERS);
extern unsigned char fault_read,fault_write,fault_execute,fault_breakpoint,fault_divide,fault_ud2,fault_capture;
extern unsigned char resume_fault,resume_execute,resume_capture;
extern unsigned char fault_read_unmapped,fault_write_unmapped,fault_readonly,fault_noexec;
extern unsigned char fault_int3_long,fault_int2d,fault_icebp,fault_idiv_overflow;
extern unsigned char fault_int2d_next_nop,fault_int2d_next_xchg,int2d_nop_instruction,int2d_xchg_instruction;
extern unsigned char fault_int2d_rax1,int2d_rax1_instruction;
extern unsigned char fault_in,fault_out,fault_hlt,fault_cli,fault_sti,fault_rdmsr,fault_cr0_read,fault_cr0_write;
extern unsigned char fault_movaps,fault_tf,fault_guard,fault_raise,fault_closehandle,tf_instruction;
extern unsigned char fault_noncanon_read,fault_noncanon_write,fault_movaps_store;
extern unsigned char fault_movapd_load,fault_movapd_store,fault_movdqa_load,fault_movdqa_store,fault_movntps,fault_movntdq,fault_addps;
extern unsigned char fault_vmovaps_load,fault_vmovaps_store,fault_vmovapd_load,fault_vmovapd_store,fault_vmovdqa_load,fault_vmovdqa_store,fault_vaddps;
extern unsigned char fault_cd01,fault_cd2c,fault_cd29,fault_ud0,fault_ud1;
extern unsigned char control_execute,control_write,control_tf,control_exec_instruction;
extern unsigned char nested_ud2_instruction,nested_resume;
extern void nested_ud2_asm(void),handler_tf_asm(void);
static unsigned g_case, g_handler_mode, g_fault_thread_id;
static volatile LONG g_caught,g_resumed,g_race,g_race_ready,g_race_done;
static volatile LONG g_in_handler;
static volatile LONG g_nested_allowed;
static HANDLE g_fault_thread;
static CRITICAL_SECTION g_print_lock;
static DWORD64 (WINAPI *p_enabled_xstate)(void);
static PVOID (WINAPI *p_locate_xstate)(PCONTEXT,DWORD,PDWORD);
static const char* names[16]={"Rax","Rbx","Rcx","Rdx","Rsi","Rdi","Rbp","Rsp","R8","R9","R10","R11","R12","R13","R14","R15"};
static const char* flags[16]={"mul","shl1","shr1","shl_cl17","shr_cl17","bsf_zero","bsr_zero","div13_by3",
    "PF0_AF0_DF0","PF1_AF0_DF0","PF0_AF1_DF0","PF1_AF1_DF0","PF0_AF0_DF1","PF1_AF0_DF1","PF0_AF1_DF1","PF1_AF1_DF1"};
static const char* faults[]={"read0","write0","execute_unmapped","int3_CC","divide0","ud2","RtlCaptureContext",
    "read_unmapped","write_unmapped","write_readonly","execute_noexec","int3_CD03","int2d","icebp_F1","idiv_overflow",
    "in_al_dx","out_dx_al","hlt","cli","sti","rdmsr","mov_rax_cr0","mov_cr0_rax","movaps_misaligned","TF_step",
    "guard_read","RaiseException","CloseHandle_invalid",
    "read_topFF","write_topFF","read_bit48","write_bit48","read_bit63","write_bit63",
    "movaps_store_misaligned","movapd_load_misaligned","movapd_store_misaligned","movdqa_load_misaligned","movdqa_store_misaligned",
    "movntps_misaligned","movntdq_misaligned","addps_misaligned","vmovaps_load_misaligned","vmovaps_store_misaligned",
    "vmovapd_load_misaligned","vmovapd_store_misaligned","vmovdqa_load_misaligned","vmovdqa_store_misaligned","vaddps_misaligned",
    "context_Dr_exec","context_Dr_write","context_TF","context_FCW","context_MXCSR","context_segments",
    "CD01","CD2C","CD29_fastfail","ud0","ud1","TF_inside_handler","nested_ud2_handler",
    "int2d_next_nop","int2d_next_xchg","int2d_rax1"};
#define FAULT_COUNT ((unsigned)(sizeof(faults)/sizeof(faults[0])))
static void bytes(const char* label,const void* vp,size_t n) {
    const unsigned char* p=(const unsigned char*)vp;
    for(size_t off=0;off<n;off+=16) {
        printf("CTX case=%08x %s offset=%04llx data=",g_case,label,(unsigned long long)off);
        for(size_t i=off;i<n&&i<off+16;i++) printf("%02x",p[i]);
        putchar('\n');
    }
}
static void field(const char* label,const char* key,uint64_t v,unsigned width) {
    printf("CTX case=%08x %s %s=%0*llx\n",g_case,label,key,(int)width,(unsigned long long)v);
}
static void snapshot(const char* label,const SNAPSHOT* s) {
    for(unsigned i=0;i<16;i++) field(label,names[i],s->gpr[i],16);
    field(label,"EFlags",s->flags,16);
    bytes(label,s->fx,sizeof(s->fx));
    if(g_use_avx) bytes("SNAP_YMM_HI",s->ymmhi,sizeof(s->ymmhi));
    else printf("CTX case=%08x %s YMM_HI=NOT_ENABLED_CPU_OR_OS\n",g_case,label);
}
static int readable(const void* p,size_t n) {
    MEMORY_BASIC_INFORMATION m;
    if(!VirtualQuery(p,&m,sizeof(m))) return 0;
    return m.State==MEM_COMMIT && !(m.Protect&(PAGE_NOACCESS|PAGE_GUARD)) &&
        (uintptr_t)p+n >= (uintptr_t)p && (uintptr_t)p+n <= (uintptr_t)m.BaseAddress+m.RegionSize;
}
static void context(const char* label,const CONTEXT* c) {
    #define F(x,w) field(label,#x,(uint64_t)c->x,w)
    F(ContextFlags,8);F(MxCsr,8);F(SegCs,4);F(SegDs,4);F(SegEs,4);F(SegFs,4);F(SegGs,4);F(SegSs,4);F(EFlags,8);
    F(Dr0,16);F(Dr1,16);F(Dr2,16);F(Dr3,16);F(Dr6,16);F(Dr7,16);
    F(Rax,16);F(Rbx,16);F(Rcx,16);F(Rdx,16);F(Rsi,16);F(Rdi,16);F(Rbp,16);F(Rsp,16);
    F(R8,16);F(R9,16);F(R10,16);F(R11,16);F(R12,16);F(R13,16);F(R14,16);F(R15,16);F(Rip,16);
    F(FltSave.ControlWord,4);F(FltSave.StatusWord,4);F(FltSave.TagWord,2);F(FltSave.ErrorOpcode,4);
    F(FltSave.ErrorOffset,8);F(FltSave.ErrorSelector,4);F(FltSave.DataOffset,8);F(FltSave.DataSelector,4);
    F(FltSave.MxCsr,8);F(FltSave.MxCsr_Mask,8);
    F(VectorControl,16);F(DebugControl,16);F(LastBranchToRip,16);F(LastBranchFromRip,16);F(LastExceptionToRip,16);F(LastExceptionFromRip,16);
    #undef F
    bytes("CONTEXT_RAW",c,sizeof(*c));
    bytes("FLT_SAVE_RAW",&c->FltSave,sizeof(c->FltSave));
    bytes("VECTOR_REGISTERS_RAW",c->VectorRegister,sizeof(c->VectorRegister));
    if((c->ContextFlags&CONTEXT_XSTATE)==CONTEXT_XSTATE && p_locate_xstate) {
        DWORD n=0;void* p=p_locate_xstate((PCONTEXT)c,2,&n);
        printf("CTX case=%08x %s XSTATE_AVX length=%08lx state=%s\n",g_case,label,(unsigned long)n,p&&n>=256&&readable(p,256)?"PRESENT":"NOT_AVAILABLE");
        if(p&&n>=256&&readable(p,256)) bytes("CONTEXT_YMM_HI",p,256);
    } else printf("CTX case=%08x %s XSTATE_AVX=NOT_ENABLED_CONTEXT_OR_API\n",g_case,label);
}
static void record(const EXCEPTION_RECORD* e,const char* label) {
    field(label,"ExceptionCode",e->ExceptionCode,8);
    field(label,"ExceptionFlags",e->ExceptionFlags,8);
    field(label,"ExceptionRecord",(uintptr_t)e->ExceptionRecord,16);
    field(label,"ExceptionAddress",(uintptr_t)e->ExceptionAddress,16);
    field(label,"NumberParameters",e->NumberParameters,8);
    for(unsigned i=0;i<EXCEPTION_MAXIMUM_PARAMETERS;i++) {
        char key[32];snprintf(key,sizeof(key),"ExceptionInformation%02u",i);field(label,key,e->ExceptionInformation[i],16);
    }
    bytes("EXCEPTION_RAW",e,sizeof(*e));
}
static LONG caught(PEXCEPTION_POINTERS ep,const char* mechanism) {
    if(GetCurrentThreadId()!=g_fault_thread_id) return EXCEPTION_CONTINUE_SEARCH;
    /* Include incorrect Windows classifications: the reference comparison must see them.
       Scope still requires the active fault thread and a currently invoked fixture. */
    if(g_resumed || !g_pre.gpr[7]) return EXCEPTION_CONTINUE_SEARCH;
    LONG depth=InterlockedIncrement(&g_in_handler);
    if(depth>1 && (!g_nested_allowed || depth>2)) {InterlockedDecrement(&g_in_handler);return EXCEPTION_CONTINUE_SEARCH;}
    EnterCriticalSection(&g_print_lock);
    printf("CONTEXT_PROBE case=%08x phase=handler depth=%ld mechanism=%s kind=%s\n",g_case,(long)depth,mechanism,faults[g_fault_kind]);
    record(ep->ExceptionRecord,depth==1?"EXCEPTION":"NESTED_EXCEPTION");context(depth==1?"HANDLER_CONTEXT":"NESTED_CONTEXT",ep->ContextRecord);
    field("HANDLER","EntryRsp",g_handler_entry_rsp,16);
    field("HANDLER","EntryRspMinusFaultRsp",g_handler_entry_rsp-ep->ContextRecord->Rsp,16);
    field("HANDLER","FaultRspMinusBeforeRsp",ep->ContextRecord->Rsp-g_pre.gpr[7],16);
    if(readable((void*)(uintptr_t)ep->ContextRecord->Rsp,256)) {
        bytes("FAULT_STACK256",(void*)(uintptr_t)ep->ContextRecord->Rsp,256);
        if(ep->ContextRecord->Rsp==g_pre.gpr[7]) field("HANDLER","Stack256Changed",memcmp(g_stack_pre,(void*)(uintptr_t)ep->ContextRecord->Rsp,256)!=0,8);
        else printf("CTX case=%08x HANDLER Stack256Changed=NOT_COMPARABLE_RSP_SHIFT\n",g_case);
    } else printf("CTX case=%08x HANDLER FaultStack256=FAILED_UNREADABLE\n",g_case);
    if(g_fault_kind!=26 && g_fault_kind!=27 && g_fault_kind<62) ep->ContextRecord->Rip=(DWORD64)(uintptr_t)g_resume_entry;
    else printf("CTX case=%08x HANDLER ResumeRipPolicy=%s\n",g_case,g_fault_kind>=62?"INT2D_ORIGINAL_NO_CONTEXT_EDITS":"API_ORIGINAL");
    if(g_fault_kind==24 || (g_fault_kind>=49 && g_fault_kind<=51 && g_caught)) {
        /* Disable TF before continuing into the instrumentation. Original is printed above. */
        ep->ContextRecord->EFlags &= ~0x100u;
        field("HANDLER","ExplicitResumeFlagsMask",0x100,8);
    }
    if(g_fault_kind>=49 && g_fault_kind<=54 && depth==1 && !g_caught) {
        switch(g_fault_kind) {
        case 49:ep->ContextRecord->Dr0=(uintptr_t)&control_exec_instruction;ep->ContextRecord->Dr7=1;ep->ContextRecord->Rip=(uintptr_t)&control_execute;break;
        case 50:ep->ContextRecord->Dr0=(uintptr_t)&g_debug_cell;ep->ContextRecord->Dr7=0xd0001;ep->ContextRecord->Rip=(uintptr_t)&control_write;break;
        case 51:ep->ContextRecord->EFlags|=0x100;ep->ContextRecord->Rip=(uintptr_t)&control_tf;break;
        case 52:ep->ContextRecord->FltSave.ControlWord=0x037f;break;
        case 53:ep->ContextRecord->MxCsr=0x5f80;ep->ContextRecord->FltSave.MxCsr=0x5f80;break;
        case 54:ep->ContextRecord->SegDs=0x53;ep->ContextRecord->SegEs=0x53;ep->ContextRecord->SegFs=0x2b;ep->ContextRecord->SegGs=0x53;break;
        }
        context("REQUESTED_CONTEXT",ep->ContextRecord);
    } else if(g_fault_kind>=49 && g_fault_kind<=51) {
        ep->ContextRecord->Dr7=0;ep->ContextRecord->EFlags&=~0x100u;
    }
    if(depth==2) {
        ep->ContextRecord->Rip=(uintptr_t)&nested_resume;
        ep->ContextRecord->EFlags&=~0x100u;ep->ContextRecord->Dr7=0;
    }
    field("HANDLER","ResumeRip",ep->ContextRecord->Rip,16);
    InterlockedIncrement(&g_caught);
    LeaveCriticalSection(&g_print_lock);
    fflush(stdout);
    if(depth==1 && (g_fault_kind==60 || g_fault_kind==61)) {
        InterlockedExchange(&g_nested_allowed,1);fflush(stdout);
        if(g_fault_kind==60) handler_tf_asm();else nested_ud2_asm();
        InterlockedExchange(&g_nested_allowed,0);
        printf("CONTEXT_PROBE case=%08x phase=nested_returned calls=%08lx\n",g_case,(unsigned long)g_caught);fflush(stdout);
    }
    if(g_race) {
        InterlockedExchange(&g_race_ready,1);DWORD start=GetTickCount();
        while(!g_race_done && GetTickCount()-start<3000) Sleep(0);
    }
    InterlockedDecrement(&g_in_handler);
    return EXCEPTION_CONTINUE_EXECUTION;
}
LONG CALLBACK veh_impl(PEXCEPTION_POINTERS ep) {
    return g_handler_mode==0?caught(ep,"VEH"):EXCEPTION_CONTINUE_SEARCH;
}
LONG seh_filter_impl(PEXCEPTION_POINTERS ep) { return caught(ep,"SEH_FILTER"); }
static void prepare(unsigned handler,unsigned kind,unsigned producer,unsigned mx,unsigned cw) {
    g_handler_mode=handler;g_fault_kind=kind;g_flag_mode=producer;g_mxcsr=mx?0x3f80:0x1f80;g_fcw=cw?0x037f:0x027f;
    g_explicit_flags=0x202;
    if(producer>=8 && producer<16) g_explicit_flags|=((producer-8)&1?4:0)|((producer-8)&2?16:0)|((producer-8)&4?1024:0);
    if(producer>=16) g_explicit_flags|=((producer-16)&1?1:0)|((producer-16)&2?0x40:0)|((producer-16)&4?0x80:0)|((producer-16)&8?0x800:0);
    void* entries[]={&fault_read,&fault_write,&fault_execute,&fault_breakpoint,&fault_divide,&fault_ud2,&fault_capture,
        &fault_read_unmapped,&fault_write_unmapped,&fault_readonly,&fault_noexec,&fault_int3_long,&fault_int2d,&fault_icebp,&fault_idiv_overflow,
        &fault_in,&fault_out,&fault_hlt,&fault_cli,&fault_sti,&fault_rdmsr,&fault_cr0_read,&fault_cr0_write,&fault_movaps,&fault_tf,
        &fault_guard,&fault_raise,&fault_closehandle,
        &fault_noncanon_read,&fault_noncanon_write,&fault_noncanon_read,&fault_noncanon_write,&fault_noncanon_read,&fault_noncanon_write,
        &fault_movaps_store,&fault_movapd_load,&fault_movapd_store,&fault_movdqa_load,&fault_movdqa_store,&fault_movntps,&fault_movntdq,&fault_addps,
        &fault_vmovaps_load,&fault_vmovaps_store,&fault_vmovapd_load,&fault_vmovapd_store,&fault_vmovdqa_load,&fault_vmovdqa_store,&fault_vaddps,
        &fault_read,&fault_read,&fault_read,&fault_read,&fault_read,&fault_read,
        &fault_cd01,&fault_cd2c,&fault_cd29,&fault_ud0,&fault_ud1,&fault_read,&fault_read,
        &fault_int2d_next_nop,&fault_int2d_next_xchg,&fault_int2d_rax1};
    _Static_assert(sizeof(entries)/sizeof(entries[0])==FAULT_COUNT,"fault table");
    g_fault_entry=entries[kind];g_resume_entry=(kind==2||kind==10)?&resume_execute:kind==6?&resume_capture:&resume_fault;
    if(kind==25) {DWORD old; if(!VirtualProtect(g_guard,4096,PAGE_READWRITE|PAGE_GUARD,&old)) ExitProcess(3);}
    if(kind>=28 && kind<=33) {
        uintptr_t tag=kind<30?0xff00000000000000ULL:kind<32?0x0001000000000000ULL:0x8000000000000000ULL;
        g_bad_data_address=(void*)(kind>=32?tag:(uintptr_t)g_noncanon|tag);
        field("LABEL","NoncanonicalDataAddress",(uintptr_t)g_bad_data_address,16);
    }
    memset(&g_pre,0,sizeof(g_pre));memset(&g_post,0,sizeof(g_post));memset(&g_capture,0xa5,sizeof(g_capture));
    g_caught=0;g_resumed=0;g_in_handler=0;g_nested_allowed=0;g_api_result=0;g_debug_cell=0;g_x87_reads=0;SetLastError(0);
    printf("CONTEXT_PROBE case=%08x phase=before handler=%u kind=%s flags=%s explicit_flags=%08llx mxcsr=%08x fcw=%04x\n",g_case,handler,faults[kind],producer<16?flags[producer]:"SF_ZF_CF_OF_16",(unsigned long long)g_explicit_flags,g_mxcsr,g_fcw);
    field("LABEL","ImageBase",(uintptr_t)GetModuleHandleW(NULL),16);
    field("LABEL","FaultInstruction",(uintptr_t)(kind==62?&int2d_nop_instruction:kind==63?&int2d_xchg_instruction:kind==64?&int2d_rax1_instruction:g_fault_entry),16);field("LABEL","ResumeInstruction",(uintptr_t)g_resume_entry,16);
    if(kind==24) field("LABEL","TFInstruction",(uintptr_t)&tf_instruction,16);
    if(kind==26||kind==27) printf("CTX case=%08x LABEL BeforeToHandlerFlags=API_ABI_NOT_EXACT_FAULT_STATE\n",g_case);
    fflush(stdout);
}
static void invoke(void) {
    g_fault_thread_id=GetCurrentThreadId();
    fflush(stdout); /* No output/calls between this flush and the assembly's final setup/fault. */
    if(g_handler_mode==0||g_fault_kind==6) run_case_asm();
    else {
        __try { run_case_asm(); }
        __except(seh_filter_entry(GetExceptionInformation())) { printf("CONTEXT_PROBE case=%08x phase=unexpected_except_body\n",g_case); }
    }
    DWORD api_error=GetLastError();g_resumed=1;
    printf("CONTEXT_PROBE case=%08x phase=after caught=%08lx resumed=%08lx\n",g_case,(unsigned long)g_caught,(unsigned long)g_resumed);
    snapshot("BEFORE_SNAPSHOT",&g_pre);bytes("BEFORE_STACK256",g_stack_pre,256);snapshot("AFTER_SNAPSHOT",&g_post);
    field("AFTER_X87","FNSTCW",g_after_fcw,4);field("AFTER_X87","FNSTSW",g_after_fsw,4);
    bytes("AFTER_FNSTENV",g_after_fenv,sizeof(g_after_fenv));
    printf("CTX case=%08x AFTER_X87 StackRead=%s\n",g_case,g_x87_reads?"PRESENT":"NOT_ENABLED_EMPTY_STACK");
    if(g_x87_reads) {bytes("AFTER_ST0_80",g_after_st0,10);bytes("AFTER_ST1_80",g_after_st1,10);bytes("FLD_ROUNDTRIP_ST0_80",g_roundtrip_st0,10);}
    field("CONTROL","WriteWatchCell",g_debug_cell,8);bytes("SEG_BEFORE",g_seg_before,sizeof(g_seg_before));bytes("SEG_AFTER",g_seg_after,sizeof(g_seg_after));
    if(g_fault_kind==6) context("RTL_CAPTURE_CONTEXT",&g_capture);
    if(g_fault_kind==26 || g_fault_kind==27) {
        field("API","Result",g_api_result,16);field("API","LastError",api_error,8);
        printf("CTX case=%08x API Exception=%s\n",g_case,g_caught?"PRESENT":"EMPTY_NOT_RAISED");
    }
    if(g_fault_kind>=62) {
        unsigned exchanged=g_post.gpr[0]==g_pre.gpr[2] && g_post.gpr[2]==g_pre.gpr[0];
        printf("INT2D_NEXT case=%08x kind=%s before_rax=%016llx before_rcx=%016llx after_rax=%016llx after_rcx=%016llx byte=%s observed=%s reference=PRISM_PENDING\n",
            g_case,faults[g_fault_kind],(unsigned long long)g_pre.gpr[0],(unsigned long long)g_pre.gpr[2],
            (unsigned long long)g_post.gpr[0],(unsigned long long)g_post.gpr[2],g_fault_kind==62?"90":"91",
            g_fault_kind==62?"NOP_HAS_NO_DATA_EFFECT_USE_HANDLER_RIP":exchanged?"EXECUTED":"NOT_EXCHANGED");
    }
    fflush(stdout);
}
static unsigned x87_return_delta(void) {
    unsigned delta=0;
    if(memcmp(g_pre.fx,g_post.fx,2)) delta|=1;
    if(memcmp(g_pre.fx+2,g_post.fx+2,2)) delta|=2;
    if(g_pre.fx[4]!=g_post.fx[4]) delta|=4;
    if(memcmp(g_pre.fx+32,g_post.fx+32,10)) delta|=8;
    if(memcmp(g_pre.fx+48,g_post.fx+48,10)) delta|=16;
    printf("X87_RETURN case=%08x kind=%s delta=%08x verdict=%s fields=FCW,FSW,FTW,ST0_80,ST1_80\n",g_case,faults[g_fault_kind],delta,delta?"FAIL":"PASS");fflush(stdout);
    return delta;
}
static DWORD WINAPI fault_worker(void* p) { (void)p;invoke();return 0; }
static DWORD WINAPI remote_worker(void* p) {
    (void)p;DWORD start=GetTickCount();while(!g_race_ready&&GetTickCount()-start<4000) Sleep(0);
    if(!g_race_ready) {printf("CONTEXT_PROBE phase=remote_ready state=FAILED_TIMEOUT\n");return 1;}
    CONTEXT c;memset(&c,0,sizeof(c));c.ContextFlags=CONTEXT_ALL;
    printf("CONTEXT_PROBE phase=RemoteSuspend\n");DWORD prev=SuspendThread(g_fault_thread);DWORD se=GetLastError();
    printf("CONTEXT_PROBE phase=RemoteGet suspend=%08lx error=%08lx\n",(unsigned long)prev,(unsigned long)se);
    BOOL ok=prev!=(DWORD)-1&&GetThreadContext(g_fault_thread,&c);DWORD ge=GetLastError();
    DWORD rr=prev!=(DWORD)-1?ResumeThread(g_fault_thread):(DWORD)-1;
    EnterCriticalSection(&g_print_lock);
    printf("CONTEXT_PROBE phase=RemoteResult get=%08x error=%08lx resume=%08lx\n",ok,(unsigned long)ge,(unsigned long)rr);
    if(ok) context("REMOTE_CONTEXT",&c);
    LeaveCriticalSection(&g_print_lock);InterlockedExchange(&g_race_done,1);return ok?0:1;
}
int main(int argc,char** argv) {
    setvbuf(stdout,g_stdout_buffer,_IOFBF,sizeof(g_stdout_buffer));InitializeCriticalSection(&g_print_lock);
    uint32_t ca=1,cb,cc=0,cd;__asm__ volatile("cpuid":"+a"(ca),"=b"(cb),"+c"(cc),"=d"(cd));
    int cp[4]={(int)ca,(int)cb,(int)cc,(int)cd};uint64_t xcr0=0;
    if(cp[2]&(1<<27)) {uint32_t lo,hi;__asm__ volatile(".byte 0x0f,0x01,0xd0":"=a"(lo),"=d"(hi):"c"(0));xcr0=((uint64_t)hi<<32)|lo;}
    g_use_avx=(cp[2]&(1<<28)) && (xcr0&6)==6;
    HMODULE k=GetModuleHandleW(L"kernel32.dll");p_enabled_xstate=(void*)GetProcAddress(k,"GetEnabledXStateFeatures");p_locate_xstate=(void*)GetProcAddress(k,"LocateXStateFeature");
    MEMORY_BASIC_INFORMATION warm;VirtualQuery(&g_pre,&warm,sizeof(warm));
    MEMORY_BASIC_INFORMATION bad;SIZE_T bad_query=VirtualQuery((void*)(uintptr_t)0x133700000,&bad,sizeof(bad));
    printf("CONTEXT_PROBE execute_target=0000000133700000 query=%08llx state=%08lx\n",(unsigned long long)bad_query,(unsigned long)bad.State);
    if(!bad_query||bad.State!=MEM_FREE) {printf("CONTEXT_PROBE FAILED_EXECUTE_TARGET_NOT_UNMAPPED\n");return 3;}
    g_readonly=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    g_noexec=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    g_guard=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    g_noncanon=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    unsigned char* aligned=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!g_readonly||!g_noexec||!g_guard||!g_noncanon||!aligned) return 3;
    memset(g_readonly,0x55,4096);memset(g_noexec,0xc3,4096);memset(g_guard,0x77,4096);memset(aligned,0x66,4096);
    g_misaligned=aligned+1;DWORD previous;if(!VirtualProtect(g_readonly,4096,PAGE_READONLY,&previous)) return 3;
    for(unsigned n=0;n<16;n++) for(unsigned j=0;j<32;j++) {g_ymm_markers[n*32+j]=(unsigned char)(j<16?0x10+n+j:0x80+n+j);if(j<16)g_xmm_markers[n*16+j]=g_ymm_markers[n*32+j];}
    printf("CONTEXT_PROBE version=00000003 buffer_bytes=00010000 fault_kinds=%08x context_size=%08llx exception_size=%08llx snapshot_size=%08llx cpuid_ecx=%08x xcr0=%016llx avx=%08x xstate_features=%016llx\n",FAULT_COUNT,(unsigned long long)sizeof(CONTEXT),(unsigned long long)sizeof(EXCEPTION_RECORD),(unsigned long long)sizeof(SNAPSHOT),cp[2],(unsigned long long)xcr0,g_use_avx,(unsigned long long)(p_enabled_xstate?p_enabled_xstate():0));
    printf("CONTEXT_PROBE int2d_revision=00000002 added_cells=62,63,64 resume_policy=ORIGINAL_NO_CONTEXT_EDITS rax1_expected_calls=0 reference=Wine_signal_x86_64_Prism_pending\n");
    PVOID vh=AddVectoredExceptionHandler(1,veh_entry);if(!vh) return 2;
    printf("CONTEXT_PROBE phase=identity-hold milliseconds=3000\n");fflush(stdout);Sleep(3000);
    int failures=0;const char* mode=argc>1?argv[1]:"smoke";
    if(!strcmp(mode,"race")) {
        g_case=0xf0000000;prepare(0,0,0,1,0);g_race=1;
        g_fault_thread=CreateThread(NULL,0,fault_worker,NULL,0,NULL);HANDLE other=CreateThread(NULL,0,remote_worker,NULL,0,NULL);
        HANDLE hs[2]={g_fault_thread,other};DWORD wr=WaitForMultipleObjects(2,hs,TRUE,10000);
        printf("CONTEXT_PROBE phase=RaceComplete wait=%08lx ready=%08lx done=%08lx caught=%08lx resumed=%08lx\n",(unsigned long)wr,(unsigned long)g_race_ready,(unsigned long)g_race_done,(unsigned long)g_caught,(unsigned long)g_resumed);
        if(wr!=WAIT_OBJECT_0) ExitProcess(124);
        DWORD status=0;GetExitCodeThread(other,&status);failures=(int)status;CloseHandle(other);CloseHandle(g_fault_thread);
    } else if(!strcmp(mode,"capture")) {
        for(unsigned mx=0;mx<2;mx++)for(unsigned cw=0;cw<2;cw++) {g_case++;prepare(0,6,0,mx,cw);invoke();}
    } else if(!strcmp(mode,"flagbits")) {
        for(unsigned f=8;f<32;f++) {g_case++;prepare(0,3,f,1,0);invoke();if(g_caught!=1||!g_resumed) failures++;}
    } else if(!strcmp(mode,"x87")) {
        const unsigned kinds[]={0,3,7,24,25};
        for(unsigned h=0;h<2;h++)for(unsigned i=0;i<5;i++) {
            g_case++;prepare(h,kinds[i],15,1,0);invoke();
            if(g_caught!=1||!g_resumed||x87_return_delta()) failures++;
        }
    } else if(!strcmp(mode,"exceptions")||!strcmp(mode,"exceptions-seh")||!strcmp(mode,"extended")||!strcmp(mode,"extended-seh")) {
        unsigned h=strstr(mode,"-seh")!=NULL;
        for(unsigned knd=strstr(mode,"extended")?28:0;knd<FAULT_COUNT;knd++) {
            if(knd==6||knd==57) continue; /* Fast fail belongs in its own process. */
            if(knd>=42 && knd<=48 && !g_use_avx) {printf("CONTEXT_PROBE kind=%s state=NOT_ENABLED_CPU_OR_OS\n",faults[knd]);continue;}
            g_case++;prepare(h,knd,15,1,0);invoke();
            unsigned expected=knd==48||knd==64?0:(knd>=49&&knd<=51)||knd==60||knd==61?2:1;
            if(!g_resumed||(knd!=27&&g_caught!=expected)) failures++;
        }
    } else if(!strcmp(mode,"fastfail")) {
        g_case=1;prepare(0,57,15,1,0);printf("CONTEXT_PROBE phase=EXPECTED_PROCESS_TERMINATION code=c0000409\n");fflush(stdout);invoke();printf("CONTEXT_PROBE FAILED_FASTFAIL_RETURNED\n");failures++;
    } else if(!strcmp(mode,"cell")) {
        if(argc<4) return 2;
        unsigned kind=(unsigned)strtoul(argv[2],NULL,10),producer=(unsigned)strtoul(argv[3],NULL,10),h=argc>4?(unsigned)strtoul(argv[4],NULL,10):0;
        if(kind>=FAULT_COUNT||producer>=32||h>1) return 2;
        if(kind>=42&&kind<=48&&!g_use_avx) {printf("CONTEXT_PROBE kind=%s state=NOT_ENABLED_CPU_OR_OS\n",faults[kind]);fflush(stdout);return 77;}
        if(kind==57) {printf("CONTEXT_PROBE FASTFAIL_REQUIRES_SEPARATE_MODE\n");fflush(stdout);return 2;}
        g_case=1;prepare(h,kind,producer,1,0);invoke();unsigned expected=kind==48||kind==64?0:(kind>=49&&kind<=51)||kind==60||kind==61?2:1;if(!g_resumed||(kind!=6&&kind!=27&&g_caught!=expected)) failures++;
        if(kind==0||kind==3||kind==7||kind==24||kind==25) {if(x87_return_delta()) failures++;}
    } else {
        unsigned handlers=!strcmp(mode,"matrix")?2:1,producers=!strcmp(mode,"matrix")?16:1,modes=!strcmp(mode,"matrix")?2:1;
        for(unsigned h=0;h<handlers;h++)for(unsigned knd=0;knd<6;knd++)for(unsigned f=0;f<producers;f++)for(unsigned mx=0;mx<modes;mx++)for(unsigned cw=0;cw<modes;cw++) {
            g_case++;prepare(h,knd,f,mx,cw);invoke();if(g_caught!=1||!g_resumed) failures++;
        }
    }
    RemoveVectoredExceptionHandler(vh);DeleteCriticalSection(&g_print_lock);
    VirtualFree(g_readonly,0,MEM_RELEASE);VirtualFree(g_noexec,0,MEM_RELEASE);VirtualFree(g_guard,0,MEM_RELEASE);VirtualFree(g_noncanon,0,MEM_RELEASE);VirtualFree(aligned,0,MEM_RELEASE);
    printf("CONTEXT_PROBE COMPLETE mode=%s cases=%08x functional_failures=%08x reference=PRISM_PENDING\n",mode,g_case,failures);fflush(stdout);return failures?1:0;
}
