/* BEGIN harness_head.c */
/* 0090 NEW probes. Synthetic OWN process/memory/threads/files only.
 * Portable host build: cc -std=c11 -O2 -Wall -Wextra -Werror new_probes.c -o new_probes_list
 * The portable executable supports list ONLY; it never executes x86 test bytes.
 * Windows x64 candidate builds (NOT validated by host list build):
 *   x86_64-w64-mingw32-gcc -std=c11 -O1 -Wall -Wextra new_probes.c -o new_probes.exe
 *   cl /nologo /W4 /O1 /TC new_probes.c
 * all | cell N | range A B | list. Preserve stdout, stderr, exit code, build warnings.
 * Generated assembly consists solely of this program's synthetic instructions.
 * No syscall-number discovery, direct syscall, foreign process, or security changes.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <limits.h>
typedef struct {const char *family; unsigned count;} ProbeGroup;
static const ProbeGroup probe_groups[]={
 {"fp.roundtrip",48},{"flags.roundtrip",32},{"fault.precise",3},
 {"memory.neighbor_code",5},{"memory.os_write",6},{"file.small_mapping",12},
 {"nt.semantic_pair",10},{"sync.lifecycle",6}
};
static unsigned probe_total(void){unsigned i,n=0;for(i=0;i<sizeof(probe_groups)/sizeof(*probe_groups);++i)n+=probe_groups[i].count;return n;}
static uint64_t probe_checksum=UINT64_C(14695981039346656037);
static unsigned probe_emitted;
static int probe_emit(unsigned id,const char *family,unsigned axis,const char *json){
 char *line; size_t n=strlen(json)+strlen(family)+128,i;
 if(json[0]!='{'||strlen(json)<2||json[strlen(json)-1]!='}')return 0;
 line=(char*)malloc(n);if(!line)return 0;
 snprintf(line,n,"CELL %u %s => {\"axes\":{\"axis\":%u},%s",id,family,axis,json+1);
 if(puts(line)<0){free(line);return 0;}
 for(i=0;line[i];++i){probe_checksum^=(unsigned char)line[i];probe_checksum*=UINT64_C(1099511628211);}
 probe_checksum^='\n';probe_checksum*=UINT64_C(1099511628211);
 free(line);probe_emitted++;return fflush(stdout)==0;
}
static int probe_number(const char *s,unsigned *out){
 char *end;unsigned long n; if(!s||!*s||*s=='-'||*s=='+')return 0;
 errno=0;n=strtoul(s,&end,10);if(errno||*end||!n||n>probe_total())return 0;*out=(unsigned)n;return 1;
}
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <io.h>
#include <fcntl.h>
#if !defined(_M_X64) && !defined(__x86_64__)
#error 0090 runtime is for Windows x86-64 guest builds only, including translated execution.
#endif
static HANDLE probe_watchdog_event;
static DWORD WINAPI probe_watchdog(LPVOID unused){
 DWORD rc;(void)unused;rc=WaitForSingleObject(probe_watchdog_event,900000);
 if(rc!=WAIT_OBJECT_0){fputs("0090 watchdog: no DONE; run timed out or watchdog wait failed\n",stderr);fflush(stderr);TerminateProcess(GetCurrentProcess(),124);}
 return 0;
}

/* END harness_head.c */
/* BEGIN fp_flags.inc */
/* 0090 FP, flags and non-continuable-by-retry fault probes.
 * Generated code uses only documented x64 instructions and own allocations.
 * No handler changes CONTEXT or patches code. Eight dispatches cap a persistent
 * fault via ExitThread: this is explicit abort, NOT successful continuation.
 * axis FP: ((mxcsr_index*3+cw_index)*4+path); flags: pattern*4+path.
 * paths: CC, own read-only write, RaiseException, suspended own thread.
 * Compiles as C with GCC/clang/MSVC x64; generated code is compiler-independent.
 */
#include <stdarg.h>
#define FP_AXIS_COUNT 48u
#define FLAGS_AXIS_COUNT 32u
#define FAULTS_AXIS_COUNT 3u
#define FP_CAP 8u
#define FP_FLAG_MASK 0xCD5u /* CF PF AF ZF SF DF OF */
typedef BOOL (WINAPI *fp_initialize_context_fn)(PVOID,DWORD,PCONTEXT*,PDWORD);
typedef BOOL (WINAPI *fp_set_xstate_mask_fn)(PCONTEXT,DWORD64);
typedef BOOL (WINAPI *fp_get_xstate_mask_fn)(PCONTEXT,PDWORD64);
typedef PVOID (WINAPI *fp_locate_xstate_fn)(PCONTEXT,DWORD,PDWORD);
typedef struct fp_case {
    unsigned char *allocation, *code, *page;
    unsigned char *saved, *seed, *before, *after, *yb, *ya, *ys;
    size_t used, fault_offset, continuation_offset;
    unsigned char prologue_end, xmm_spill_end[10];
    volatile LONG ready, gate, completed, count, aborted;
    DWORD thread_id, error, protect_error;
    unsigned path, fault, avx, flags_case, pattern;
    uint64_t before_flags, after_flags;
    DWORD direct_mxcsr_before,direct_mxcsr_after;
    WORD direct_cw_before,direct_cw_after;
    CONTEXT captured[FP_CAP];
    DWORD codes[FP_CAP],exception_flags[FP_CAP];
    ULONG_PTR addresses[FP_CAP];
    ULONG_PTR info0[FP_CAP], info1[FP_CAP];
    DWORD parameter_counts[FP_CAP];
    DWORD suspend_result, resume_result;
    BOOL got_context, set_context, context_same;
    CONTEXT thread_context;
    fp_initialize_context_fn initialize_context;
    fp_set_xstate_mask_fn set_xstate_mask;
    fp_get_xstate_mask_fn get_xstate_mask;
    fp_locate_xstate_fn locate_xstate;
    unsigned char handler_y[FP_CAP][256], thread_y[256];
    DWORD64 handler_xmask[FP_CAP], thread_xmask;
    BOOL handler_y_valid[FP_CAP], thread_y_valid, xstate_requested;
    DWORD xstate_error, hardware_mxcsr_mask;
    BOOL unsupported_mxcsr;
    PVOID context_buffer;
    DWORD context_buffer_size;
    volatile LONG handler_context_changed;
    BOOL remove_handler_ok, function_table_added;
    RUNTIME_FUNCTION runtime_function;

} fp_case;
static fp_case *fp_active;
static const DWORD fp_mxcsr_values[4]={0x1f80,0x9fc0,0x3f80,0x5f80};
static const WORD fp_cw_values[3]={0x027f,0x037f,0x0c7f};
/* Eight intentionally distinct patterns, with DF both clear and set. */
static const DWORD fp_flag_values[8]={0,0x001,0x044,0x090,0x800,0x400,0x455,0xcd5};
static void fp_byte(fp_case *p,unsigned b){p->code[p->used++]=(unsigned char)b;}
static void fp_u32(fp_case *p,uint32_t v){memcpy(p->code+p->used,&v,4);p->used+=4;}
static void fp_u64(fp_case *p,uint64_t v){memcpy(p->code+p->used,&v,8);p->used+=8;}
static void fp_rax(fp_case *p,const void *v){fp_byte(p,0x48);fp_byte(p,0xb8);fp_u64(p,(uint64_t)(uintptr_t)v);}
static void fp_fx(fp_case *p,void *v,int restore){fp_rax(p,v);fp_byte(p,0x48);fp_byte(p,0x0f);fp_byte(p,0xae);fp_byte(p,restore?8:0);}
static void fp_direct_reads(fp_case *p,DWORD *mx,WORD *cw){fp_rax(p,mx);fp_byte(p,0x0f);fp_byte(p,0xae);fp_byte(p,0x18);fp_rax(p,cw);fp_byte(p,0xd9);fp_byte(p,0x38);}
static void fp_mov32(fp_case *p,volatile LONG *v,uint32_t x){fp_rax(p,(const void*)v);fp_byte(p,0xc7);fp_byte(p,0);fp_u32(p,x);}
static void fp_flags_save(fp_case *p,uint64_t *v){fp_byte(p,0x9c);fp_byte(p,0x58);fp_byte(p,0x48);fp_byte(p,0xa3);fp_u64(p,(uint64_t)(uintptr_t)v);}
static void fp_ymm(fp_case *p,void *v,int store){unsigned i;fp_rax(p,v);for(i=0;i<16;i++){
    fp_byte(p,0xc4);fp_byte(p,i<8?0xe1:0x61);fp_byte(p,0x7e);fp_byte(p,store?0x7f:0x6f);
    fp_byte(p,0x80|((i&7)<<3));fp_u32(p,i*32);
}}
static BOOL fp_read_y(fp_case *p,PCONTEXT ctx,unsigned char *dst,DWORD64 *mask){
    DWORD length=0;PVOID area;
    *mask=0;
    if(!(ctx->ContextFlags&0x40)||!p->get_xstate_mask||!p->locate_xstate)return FALSE;
    if(!p->get_xstate_mask(ctx,mask))return FALSE;
    /* A valid XSTATE context with an absent AVX bit denotes architectural
     * INIT state (zero YMM uppers), not uninitialized buffer contents. */
    if(!(*mask&4)){memset(dst,0,256);return p->avx?TRUE:FALSE;}
    area=p->locate_xstate(ctx,2,&length);
    if(!area||length<256)return FALSE;
    memcpy(dst,area,256);return TRUE;
}
static LONG CALLBACK fp_handler(EXCEPTION_POINTERS *ep){
    fp_case *p=fp_active; unsigned i; DWORD old;
    if(!p || GetCurrentThreadId()!=p->thread_id)return EXCEPTION_CONTINUE_SEARCH;
    if(!((ULONG_PTR)ep->ExceptionRecord->ExceptionAddress>=(ULONG_PTR)p->code && (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress<(ULONG_PTR)p->code+2048) && !(p->path==2 && ep->ExceptionRecord->ExceptionCode==0xe0090001u))return EXCEPTION_CONTINUE_SEARCH;
    i=(unsigned)p->count;
    if(i<FP_CAP){p->captured[i]=*ep->ContextRecord;p->handler_y_valid[i]=fp_read_y(p,ep->ContextRecord,p->handler_y[i],&p->handler_xmask[i]);p->codes[i]=ep->ExceptionRecord->ExceptionCode;
        p->exception_flags[i]=ep->ExceptionRecord->ExceptionFlags;
        p->addresses[i]=(ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;
        p->parameter_counts[i]=ep->ExceptionRecord->NumberParameters;
        if(p->parameter_counts[i]>0)p->info0[i]=ep->ExceptionRecord->ExceptionInformation[0];
        if(p->parameter_counts[i]>1)p->info1[i]=ep->ExceptionRecord->ExceptionInformation[1];
        p->count=(LONG)(i+1);
    }
    if(p->path==1 && p->fault==0 && ep->ExceptionRecord->ExceptionCode==EXCEPTION_ACCESS_VIOLATION){
        if(!VirtualProtect(p->page,4096,PAGE_READWRITE,&old))p->protect_error=GetLastError();
    }
    if(i<FP_CAP && memcmp(&p->captured[i],ep->ContextRecord,sizeof(CONTEXT)))p->handler_context_changed=1;
    if((unsigned)p->count>=FP_CAP){p->aborted=1;ExitThread(0xe0090008u);}
    return EXCEPTION_CONTINUE_EXECUTION;
}
static DWORD WINAPI fp_worker(void *arg){fp_case *p=(fp_case*)arg;
    p->thread_id=GetCurrentThreadId();((void(*)(void))(void*)p->code)();return 0;
}
static unsigned fp_xmm_diff(const unsigned char *a,const unsigned char *b){unsigned i,m=0;for(i=0;i<16;i++)if(memcmp(a+160+i*16,b+160+i*16,16))m|=1u<<i;return m;}
static unsigned fp_st_diff(const unsigned char *a,const unsigned char *b){unsigned i,m=0;for(i=0;i<3;i++)if(memcmp(a+32+i*16,b+32+i*16,10))m|=1u<<i;return m;}
static unsigned fp_y_diff(const unsigned char *a,const unsigned char *b){unsigned i,m=0;for(i=0;i<16;i++)if(memcmp(a+i*32+16,b+i*32+16,16))m|=1u<<i;return m;}
static unsigned fp_word(const unsigned char *p){unsigned short v;memcpy(&v,p,2);return v;}
static unsigned fp_dword(const unsigned char *p){unsigned v;memcpy(&v,p,4);return v;}
static int fp_prepare(fp_case *p,unsigned mx,unsigned cw){
    unsigned i,j; DWORD old; HMODULE kernel;
    p->allocation=(unsigned char*)VirtualAlloc(NULL,16384,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    p->code=(unsigned char*)VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    p->page=(unsigned char*)VirtualAlloc(NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!p->allocation||!p->code||!p->page){p->error=GetLastError();return 0;}
    p->saved=p->allocation;p->seed=p->allocation+512;p->before=p->allocation+1024;p->after=p->allocation+1536;
    p->ys=p->allocation+2048;p->yb=p->allocation+2560;p->ya=p->allocation+3072;
    memcpy(p->seed,&fp_cw_values[cw],2);p->seed[4]=7;
    memcpy(p->seed+24,&fp_mxcsr_values[mx],4);
    /* 80-bit encodings of ST0=1, ST1=2, ST2=3; TOP=0, abridged FTW=7. */
    for(i=0;i<3;i++){p->seed[32+i*16+7]=(unsigned char)(i==2?0xc0:0x80);p->seed[32+i*16+8]=(unsigned char)(i?0:0xff);p->seed[32+i*16+9]=(unsigned char)(i?0x40:0x3f);}
    for(i=0;i<16;i++)for(j=0;j<32;j++)p->ys[i*32+j]=(unsigned char)(0x31+i*11+j*3);
    for(i=0;i<16;i++)memcpy(p->seed+160+i*16,p->ys+i*32,16);
    /* PF_AVX_INSTRUCTIONS_AVAILABLE includes CPU and enabled OS support. */
    p->avx=(unsigned)IsProcessorFeaturePresent(39);
    kernel=GetModuleHandleA("kernel32.dll");
    p->initialize_context=(fp_initialize_context_fn)(uintptr_t)GetProcAddress(kernel,"InitializeContext");
    p->set_xstate_mask=(fp_set_xstate_mask_fn)(uintptr_t)GetProcAddress(kernel,"SetXStateFeaturesMask");
    p->get_xstate_mask=(fp_get_xstate_mask_fn)(uintptr_t)GetProcAddress(kernel,"GetXStateFeaturesMask");
    p->locate_xstate=(fp_locate_xstate_fn)(uintptr_t)GetProcAddress(kernel,"LocateXStateFeature");
    if(p->path==1 && !p->fault && !VirtualProtect(p->page,4096,PAGE_READONLY,&old)){p->error=GetLastError();return 0;}
    /* Stack: 32-byte shadow + 160-byte XMM6-15 unwind spills + 8 pad.
     * Entry RSP=8 mod16, subtract200 gives aligned call stack. */
    fp_byte(p,0x48);fp_byte(p,0x81);fp_byte(p,0xec);fp_u32(p,200);
    for(i=6;i<16;i++){
        fp_byte(p,0xf3);if(i>=8)fp_byte(p,0x44);fp_byte(p,0x0f);fp_byte(p,0x7f);
        fp_byte(p,0x84|((i&7)<<3));fp_byte(p,0x24);fp_u32(p,32+(i-6)*16);
        p->xmm_spill_end[i-6]=(unsigned char)p->used;
    }
    p->prologue_end=(unsigned char)p->used;
    fp_fx(p,p->saved,0);fp_fx(p,p->seed,1);
    if(p->avx)fp_ymm(p,p->ys,0);
    fp_rax(p,(void*)(uintptr_t)(0x202u|fp_flag_values[p->pattern]));fp_byte(p,0x50);fp_byte(p,0x9d);
    fp_flags_save(p,&p->before_flags);fp_fx(p,p->before,0);if(p->avx)fp_ymm(p,p->yb,1);
    fp_direct_reads(p,&p->direct_mxcsr_before,&p->direct_cw_before);
    p->fault_offset=p->used;
    if(p->fault==1){
        /* CD03 can report RIP at its second byte. Both possible entries are
         * register-only: +1 ADD EAX,EAX; JMP +0; +2 SHR BL,0. The latter
         * leaves BL and flags unchanged. Seed EAX distinguishes flag traces. */
        fp_byte(p,0xb8);fp_u32(p,0x40000000);p->fault_offset=p->used;
        fp_byte(p,0xcd);fp_byte(p,3);fp_byte(p,0xc0);fp_byte(p,0xeb);fp_byte(p,0);
    }
    else if(p->fault==2){fp_rax(p,p->page+1);p->fault_offset=p->used;fp_byte(p,0x0f);fp_byte(p,0x29);fp_byte(p,0);}
    else if(p->fault==3){fp_rax(p,(void*)(uintptr_t)UINT64_C(0x0100000000000000));p->fault_offset=p->used;fp_byte(p,0xc6);fp_byte(p,0);fp_byte(p,0x42);}
    else if(p->path==0){fp_byte(p,0xcc);}
    else if(p->path==1){fp_rax(p,p->page);p->fault_offset=p->used;fp_byte(p,0xc6);fp_byte(p,0);fp_byte(p,0x42);}
    else if(p->path==2){
        /* API call boundary may clobber volatile FP and arithmetic flags.
         * DF is cleared per Win64 ABI BEFORE entering C/Windows API. Raw
         * handler results must not be interpreted as direct DF retention. */
        fp_byte(p,0xfc);
        fp_byte(p,0xb9);fp_u32(p,0xe0090001u);fp_byte(p,0xba);fp_u32(p,0);
        fp_byte(p,0x41);fp_byte(p,0xb8);fp_u32(p,0);fp_byte(p,0x41);fp_byte(p,0xb9);fp_u32(p,0);
        fp_rax(p,(const void*)(uintptr_t)RaiseException);fp_byte(p,0xff);fp_byte(p,0xd0);
    }else{
        fp_mov32(p,&p->ready,1);
        /* MOV + JRCXZ do not change ANY requested flags (including DF). */
        fp_rax(p,(const void*)&p->gate);fp_byte(p,0x8b);fp_byte(p,0x08);fp_byte(p,0xe3);fp_byte(p,0xfc);
    }
    p->continuation_offset=p->used;
    fp_flags_save(p,&p->after_flags);fp_byte(p,0xfc);fp_fx(p,p->after,0);if(p->avx)fp_ymm(p,p->ya,1);
    fp_direct_reads(p,&p->direct_mxcsr_after,&p->direct_cw_after);
    fp_fx(p,p->saved,1);fp_mov32(p,&p->completed,1);
    fp_byte(p,0x48);fp_byte(p,0x81);fp_byte(p,0xc4);fp_u32(p,200);fp_byte(p,0xc3);
    p->runtime_function.BeginAddress=0;p->runtime_function.EndAddress=(DWORD)p->used;p->runtime_function.UnwindData=3072;
    /* UNWIND_INFO v1: descending SAVE_XMM128 entries (each two slots),
     * then ALLOC_LARGE(200/8), two slots. Even22 slots need no padding. */
    p->code[3072]=1;p->code[3073]=p->prologue_end;p->code[3074]=22;p->code[3075]=0;
    j=3076;
    for(i=16;i>6;){--i;p->code[j++]=p->xmm_spill_end[i-6];p->code[j++]=(unsigned char)((i<<4)|8);p->code[j++]=(unsigned char)(2+i-6);p->code[j++]=0;}
    p->code[j++]=7;p->code[j++]=1;p->code[j++]=25;p->code[j++]=0;
    /* VEH entry trampoline clears DF before compiler-generated C executes. */
    p->used=2048;fp_byte(p,0xfc);fp_rax(p,(const void*)(uintptr_t)fp_handler);fp_byte(p,0xff);fp_byte(p,0xe0);
    /* Leaf helper: FXSAVE64 [RCX]; RET. It changes no architectural FP state. */
    p->code[2064]=0x48;p->code[2065]=0x0f;p->code[2066]=0xae;p->code[2067]=0x01;p->code[2068]=0xc3;
    if(!VirtualProtect(p->code,4096,PAGE_EXECUTE_READ,&old)){p->error=GetLastError();return 0;}
    if(!FlushInstructionCache(GetCurrentProcess(),p->code,4096)){p->error=GetLastError();return 0;}
    ((void(*)(void*))(void*)(p->code+2064))(p->saved);
    p->hardware_mxcsr_mask=fp_dword(p->saved+28);
    if(!p->hardware_mxcsr_mask)p->hardware_mxcsr_mask=0xffbf; /* architectural fallback */
    if(fp_mxcsr_values[mx]&~p->hardware_mxcsr_mask){p->unsupported_mxcsr=TRUE;p->error=ERROR_NOT_SUPPORTED;return 0;}
    if(!RtlAddFunctionTable(&p->runtime_function,1,(DWORD64)(uintptr_t)p->code)){p->error=ERROR_NOT_SUPPORTED;return 0;}p->function_table_added=TRUE;
    return 1;
}
static void fp_cleanup(fp_case *p){if(p->function_table_added&&!RtlDeleteFunctionTable(&p->runtime_function)){fputs("0090 FP unwind-table cleanup failed; own process exits.\n",stderr);fflush(stderr);ExitProcess(125);}if(p->context_buffer)HeapFree(GetProcessHeap(),0,p->context_buffer);if(p->code)VirtualFree(p->code,0,MEM_RELEASE);if(p->page)VirtualFree(p->page,0,MEM_RELEASE);if(p->allocation)VirtualFree(p->allocation,0,MEM_RELEASE);}

/* Checked appender: never publish a silently truncated JSON object. */
typedef struct fp_writer {char *s;size_t cap,used;int failed;} fp_writer;
#if defined(__GNUC__) || defined(__clang__)
static void fp_add(fp_writer *w,const char *fmt,...) __attribute__((format(printf,2,3)));
#endif
static void fp_add(fp_writer *w,const char *fmt,...){int r;va_list ap;if(w->failed)return;va_start(ap,fmt);r=vsnprintf(w->s+w->used,w->cap-w->used,fmt,ap);va_end(ap);if(r<0||(size_t)r>=w->cap-w->used){w->failed=1;return;}w->used+=(size_t)r;}
static void fp_hex(fp_writer *w,const unsigned char *p,size_t count){size_t i;fp_add(w,"\"");for(i=0;i<count;i++)fp_add(w,"%02x",p[i]);fp_add(w,"\"");}
static const char *fp_bool(int b){return b?"true":"false";}
static unsigned fp_context_y_diff(const unsigned char *seed,const unsigned char *actual){unsigned i,m=0;for(i=0;i<16;i++)if(memcmp(seed+i*32+16,actual+i*16,16))m|=1u<<i;return m;}
static long long fp_relative(fp_case *p,ULONG_PTR address){ULONG_PTR base=(ULONG_PTR)p->code;return address>=base&&address<base+4096?(long long)(address-base):-1;}
static const char *fp_address_class(fp_case *p,unsigned i){ULONG_PTR a=p->info1[i];if(p->parameter_counts[i]<2)return "not_reported";if(a==(ULONG_PTR)-1)return "minus_one";if(!a)return "zero";if(a>=(ULONG_PTR)p->page&&a<(ULONG_PTR)p->page+4096)return "own_page";if(a==UINT64_C(0x0100000000000000))return "noncanonical_target";return "other";}
static void fp_context_roundtrip(fp_case *p,HANDLE h){
    PCONTEXT c=&p->thread_context;PVOID original=NULL;DWORD length=0;
    memset(c,0,sizeof(*c));c->ContextFlags=CONTEXT_ALL;
    if(p->avx&&p->initialize_context&&p->set_xstate_mask&&p->get_xstate_mask&&p->locate_xstate){
        PCONTEXT xc=NULL;
        p->initialize_context(NULL,CONTEXT_ALL|0x40,&xc,&length);
        if(length>=sizeof(CONTEXT)&&length<=1024*1024){
            p->context_buffer=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,length);
            p->context_buffer_size=length;
            if(p->context_buffer&&p->initialize_context(p->context_buffer,CONTEXT_ALL|0x40,&xc,&length)&&p->set_xstate_mask(xc,4)){c=xc;p->xstate_requested=TRUE;}
            else p->xstate_error=GetLastError();
        }else p->xstate_error=GetLastError();
    }
    p->got_context=GetThreadContext(h,c);
    if(!p->got_context){p->error=GetLastError();return;}
    p->thread_context=*c;
    p->thread_y_valid=fp_read_y(p,c,p->thread_y,&p->thread_xmask);
    /* Copy and compare the ENTIRE initialized XSTATE buffer where present. */
    length=p->xstate_requested?p->context_buffer_size:(DWORD)sizeof(*c);
    original=HeapAlloc(GetProcessHeap(),0,length);
    if(!original){p->error=ERROR_NOT_ENOUGH_MEMORY;return;}
    memcpy(original,p->xstate_requested?p->context_buffer:(PVOID)c,length);
    p->set_context=SetThreadContext(h,c);
    if(!p->set_context)p->error=GetLastError();
    p->context_same=memcmp(original,p->xstate_requested?p->context_buffer:(PVOID)c,length)==0;
    HeapFree(GetProcessHeap(),0,original);
}
static void fp_run(unsigned axis,unsigned kind,char *out,size_t n){
    fp_case p;HANDLE h=NULL;PVOID veh=NULL;unsigned mx=0,cw=0,i;DWORD wait,exit_code=0;const unsigned char *ctx;int context_valid;
    fp_writer w;memset(&p,0,sizeof(p));w.s=out;w.cap=n;w.used=0;w.failed=n==0;
    if((kind==0&&axis>=FP_AXIS_COUNT)||(kind==1&&axis>=FLAGS_AXIS_COUNT)||(kind==2&&axis>=FAULTS_AXIS_COUNT)){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"axis_out_of_range\",\"raw\":{},\"norm\":{}}");return;}
    p.path=axis%4;p.flags_case=kind==1;
    if(kind==0){mx=axis/12;cw=(axis/4)%3;}else if(kind==1)p.pattern=axis/4;else{p.fault=axis+1;p.path=0;}
    if(!fp_prepare(&p,mx,cw))goto failed;
    fp_active=&p;veh=AddVectoredExceptionHandler(1,(PVECTORED_EXCEPTION_HANDLER)(void*)(p.code+2048));
    if(!veh){p.error=GetLastError();goto failed;}
    h=CreateThread(NULL,0,fp_worker,&p,0,NULL);if(!h){p.error=GetLastError();goto failed;}
    if(p.path==3){
        ULONGLONG deadline=GetTickCount64()+5000;
        while(!p.ready&&GetTickCount64()<deadline&&WaitForSingleObject(h,0)==WAIT_TIMEOUT)Sleep(1);
        if(!p.ready){p.error=WAIT_TIMEOUT;p.gate=1;}
        else{
            p.suspend_result=SuspendThread(h);
            if(p.suspend_result==(DWORD)-1){p.error=GetLastError();p.gate=1;}
            else{
                fp_context_roundtrip(&p,h);
                p.gate=1;p.resume_result=ResumeThread(h);if(p.resume_result==(DWORD)-1)p.error=GetLastError();
            }
        }
    }
    wait=WaitForSingleObject(h,10000);
    if(wait!=WAIT_OBJECT_0){
        /* Stack-backed state cannot outlive this call. Exit the OWN process,
         * not a foreign target; no unsafe TerminateThread or freeing live code.
         * Deliberately no CELL/DONE: harness parser must reject this run. */
        fprintf(stderr,"0090 FP worker did not stop (wait=%lu); no result or DONE; own process exits.\n",(unsigned long)wait);fflush(stderr);ExitProcess(124);
    }
    if(!GetExitCodeThread(h,&exit_code))p.error=GetLastError();
    p.remove_handler_ok=RemoveVectoredExceptionHandler(veh)!=0;veh=NULL;
    if(!p.remove_handler_ok){fputs("0090 FP could not unregister handler; own process exits without DONE.\n",stderr);fflush(stderr);ExitProcess(125);}
    fp_active=NULL;
    ctx=p.path==3?(const unsigned char*)&p.thread_context.FltSave:(const unsigned char*)&p.captured[0].FltSave;
    context_valid=p.path==3?p.got_context:p.count>0;
    fp_add(&w,"{\"status\":\"OBSERVED\",\"reason\":\"\",\"raw\":{\"path\":%u,\"fault\":%u,\"error\":%lu,\"mxcsr_requested\":%lu,\"cw_requested\":%u,\"flags_requested\":%lu,\"flags_before\":%llu,\"flags_after\":%llu,\"api_df_cleared\":%s,\"avx\":%s,\"before_valid\":%s,\"after_valid\":%s,\"code_base\":\"0x%llx\",\"page_base\":\"0x%llx\",\"fault_offset\":%llu,\"continuation_offset\":%llu,\"seed_fxsave\":",
        p.path,p.fault,(unsigned long)p.error,(unsigned long)fp_mxcsr_values[mx],(unsigned)fp_cw_values[cw],(unsigned long)fp_flag_values[p.pattern],(unsigned long long)p.before_flags,(unsigned long long)p.after_flags,fp_bool(p.path==2),fp_bool(p.avx),fp_bool(p.before_flags!=0),fp_bool(p.completed),(unsigned long long)(uintptr_t)p.code,(unsigned long long)(uintptr_t)p.page,(unsigned long long)p.fault_offset,(unsigned long long)p.continuation_offset);
    fp_hex(&w,p.seed,512);fp_add(&w,",\"direct_mxcsr_before\":%lu,\"direct_cw_before\":%u,\"direct_mxcsr_after\":",(unsigned long)p.direct_mxcsr_before,(unsigned)p.direct_cw_before);if(p.completed)fp_add(&w,"%lu",(unsigned long)p.direct_mxcsr_after);else fp_add(&w,"null");fp_add(&w,",\"direct_cw_after\":");if(p.completed)fp_add(&w,"%u",(unsigned)p.direct_cw_after);else fp_add(&w,"null");fp_add(&w,",\"hardware_mxcsr_mask\":%lu",(unsigned long)p.hardware_mxcsr_mask);fp_add(&w,",\"before_fxsave\":");fp_hex(&w,p.before,512);fp_add(&w,",\"after_fxsave\":");if(p.completed)fp_hex(&w,p.after,512);else fp_add(&w,"null");
    fp_add(&w,",\"seed_ymm\":");fp_hex(&w,p.ys,512);fp_add(&w,",\"before_ymm\":");if(p.avx)fp_hex(&w,p.yb,512);else fp_add(&w,"null");fp_add(&w,",\"after_ymm\":");if(p.avx&&p.completed)fp_hex(&w,p.ya,512);else fp_add(&w,"null");
    fp_add(&w,",\"thread_context_valid\":%s,\"thread_context_flags\":%lu,\"thread_eflags\":%lu,\"thread_rip\":\"0x%llx\",\"thread_fxsave\":",fp_bool(p.got_context),(unsigned long)p.thread_context.ContextFlags,(unsigned long)p.thread_context.EFlags,(unsigned long long)p.thread_context.Rip);if(p.got_context)fp_hex(&w,(const unsigned char*)&p.thread_context.FltSave,512);else fp_add(&w,"null");
    fp_add(&w,",\"thread_xstate_mask\":%llu,\"thread_ymm_upper\":",(unsigned long long)p.thread_xmask);if(p.thread_y_valid)fp_hex(&w,p.thread_y,256);else fp_add(&w,"null");
    fp_add(&w,",\"suspend_result\":%lu,\"resume_result\":%lu,\"exit_code\":%lu,\"xstate_error\":%lu,\"protect_error\":%lu,\"events\":[",(unsigned long)p.suspend_result,(unsigned long)p.resume_result,(unsigned long)exit_code,(unsigned long)p.xstate_error,(unsigned long)p.protect_error);
    for(i=0;i<(unsigned)p.count&&i<FP_CAP;i++){
        fp_add(&w,"%s{\"code\":%lu,\"exception_flags\":%lu,\"rip\":\"0x%llx\",\"exception_address\":\"0x%llx\",\"flags\":%lu,\"mxcsr\":%lu,\"cw\":%u,\"context_flags\":%lu,\"parameters\":%lu,\"info0\":\"0x%llx\",\"info1\":\"0x%llx\",\"fxsave\":",i?",":"",(unsigned long)p.codes[i],(unsigned long)p.exception_flags[i],(unsigned long long)p.captured[i].Rip,(unsigned long long)p.addresses[i],(unsigned long)p.captured[i].EFlags,(unsigned long)p.captured[i].MxCsr,(unsigned)p.captured[i].FltSave.ControlWord,(unsigned long)p.captured[i].ContextFlags,(unsigned long)p.parameter_counts[i],(unsigned long long)p.info0[i],(unsigned long long)p.info1[i]);
        fp_hex(&w,(const unsigned char*)&p.captured[i].FltSave,512);fp_add(&w,",\"xstate_mask\":%llu,\"ymm_upper\":",(unsigned long long)p.handler_xmask[i]);if(p.handler_y_valid[i])fp_hex(&w,p.handler_y[i],256);else fp_add(&w,"null");fp_add(&w,"}");
    }
    fp_add(&w,"]},\"norm\":{\"invariants\":{\"execution_api_ok\":%s,\"seed_xmm_exact\":%s,\"seed_st_exact\":%s,\"seed_flags_exact\":%s,\"seed_mxcsr_exact\":%s,\"seed_cw_exact\":%s,\"handler_context_unchanged\":%s,\"thread_set_buffer_unchanged\":%s,\"bounded_dispatch\":%s",
        fp_bool(!p.error&&!p.protect_error),fp_bool(p.before_flags&&fp_xmm_diff(p.seed,p.before)==0),fp_bool(p.before_flags&&fp_st_diff(p.seed,p.before)==0),fp_bool(p.before_flags&&(p.before_flags&FP_FLAG_MASK)==fp_flag_values[p.pattern]),fp_bool(p.before_flags&&fp_dword(p.before+24)==fp_mxcsr_values[mx]),fp_bool(p.before_flags&&fp_word(p.before)==fp_cw_values[cw]),fp_bool(!p.handler_context_changed),fp_bool(p.path!=3||(p.set_context&&p.context_same)),fp_bool(p.count>=0&&(unsigned)p.count<=FP_CAP));
    fp_add(&w,",\"seed_ymm_upper_exact\":%s",fp_bool(!p.avx||(p.before_flags&&fp_y_diff(p.ys,p.yb)==0)));
    fp_add(&w,",\"direct_before_reads_match_snapshot\":%s",fp_bool(p.before_flags&&p.direct_mxcsr_before==fp_dword(p.before+24)&&p.direct_cw_before==fp_word(p.before)));
    if(kind!=2){
        fp_add(&w,",\"direct_after_reads_match_snapshot\":%s",fp_bool(p.completed&&p.direct_mxcsr_after==fp_dword(p.after+24)&&p.direct_cw_after==fp_word(p.after)));
        /* API paths guarantee only ABI-nonvolatile components at RETURN.
         * An exception inside an API need not expose caller nonvolatile values
         * at that intermediate PC; do not mistake that for failed restoration. */
        fp_add(&w,",\"roundtrip_completed\":%s,\"roundtrip_cw_restored\":%s",fp_bool(p.completed),fp_bool(p.completed&&fp_word(p.before)==fp_word(p.after)));
        if(p.path==2){
            fp_add(&w,",\"roundtrip_mxcsr_controls_restored\":%s,\"roundtrip_xmm_nonvolatile_restored\":%s",fp_bool(p.completed&&((fp_dword(p.before+24)^fp_dword(p.after+24))&0xffc0)==0),fp_bool(p.completed&&(fp_xmm_diff(p.before,p.after)&0xffc0)==0));
        }else{
            fp_add(&w,",\"roundtrip_flags_restored\":%s,\"roundtrip_mxcsr_restored\":%s,\"roundtrip_xmm_restored\":%s,\"roundtrip_st_restored\":%s",fp_bool(p.completed&&((p.before_flags^p.after_flags)&FP_FLAG_MASK)==0),fp_bool(p.completed&&fp_dword(p.before+24)==fp_dword(p.after+24)),fp_bool(p.completed&&fp_xmm_diff(p.before,p.after)==0),fp_bool(p.completed&&fp_st_diff(p.before,p.after)==0));
            if(p.avx)fp_add(&w,",\"roundtrip_ymm_upper_restored\":%s",fp_bool(p.completed&&fp_y_diff(p.yb,p.ya)==0));
        }
    }
    fp_add(&w,"},\"path\":%u,\"fault\":%u,\"avx\":%s,\"before_valid\":%s,\"after_valid\":%s,\"context_valid\":%s,\"api_df_cleared\":%s,\"dispatch_count\":%ld,\"abort_intervention\":%s,\"ro_protection_intervention\":%s,\"flags_mask\":%u,\"flags_requested\":%u,\"flags_before_masked\":%u,\"flags_after_masked\":",
        p.path,p.fault,fp_bool(p.avx),fp_bool(p.before_flags!=0),fp_bool(p.completed),fp_bool(context_valid),fp_bool(p.path==2),(long)p.count,fp_bool(p.aborted),fp_bool(p.path==1&&p.count>0),FP_FLAG_MASK,(unsigned)fp_flag_values[p.pattern],(unsigned)(p.before_flags&FP_FLAG_MASK));
    if(p.completed)fp_add(&w,"%u",(unsigned)(p.after_flags&FP_FLAG_MASK));else fp_add(&w,"null");
    fp_add(&w,",\"mxcsr_before\":%u,\"cw_before\":%u,\"mxcsr_after\":",fp_dword(p.before+24),fp_word(p.before));if(p.completed)fp_add(&w,"%u",fp_dword(p.after+24));else fp_add(&w,"null");fp_add(&w,",\"cw_after\":");if(p.completed)fp_add(&w,"%u",fp_word(p.after));else fp_add(&w,"null");
    fp_add(&w,",\"xmm_after_mismatch\":");if(p.completed)fp_add(&w,"%u",fp_xmm_diff(p.seed,p.after));else fp_add(&w,"null");fp_add(&w,",\"st_after_mismatch\":");if(p.completed)fp_add(&w,"%u",fp_st_diff(p.seed,p.after));else fp_add(&w,"null");
    fp_add(&w,",\"ymm_upper_before_mismatch\":");if(p.avx)fp_add(&w,"%u",fp_y_diff(p.ys,p.yb));else fp_add(&w,"null");fp_add(&w,",\"ymm_upper_after_mismatch\":");if(p.avx&&p.completed)fp_add(&w,"%u",fp_y_diff(p.ys,p.ya));else fp_add(&w,"null");
    fp_add(&w,",\"context_xmm_mismatch\":");if(context_valid)fp_add(&w,"%u",fp_xmm_diff(p.seed,ctx));else fp_add(&w,"null");fp_add(&w,",\"context_st_mismatch\":");if(context_valid)fp_add(&w,"%u",fp_st_diff(p.seed,ctx));else fp_add(&w,"null");
    fp_add(&w,",\"context_ymm_upper_mismatch\":");if(p.path==3?p.thread_y_valid:p.handler_y_valid[0])fp_add(&w,"%u",fp_context_y_diff(p.ys,p.path==3?p.thread_y:p.handler_y[0]));else fp_add(&w,"null");
    fp_add(&w,",\"context_flags_masked\":");if(context_valid)fp_add(&w,"%u",(unsigned)((p.path==3?p.thread_context.EFlags:p.captured[0].EFlags)&FP_FLAG_MASK));else fp_add(&w,"null");
    fp_add(&w,",\"context_mxcsr\":");if(context_valid)fp_add(&w,"%u",fp_dword(ctx+24));else fp_add(&w,"null");fp_add(&w,",\"context_cw\":");if(context_valid)fp_add(&w,"%u",fp_word(ctx));else fp_add(&w,"null");
    fp_add(&w,",\"postreturn_captured\":%s,\"handler_context_captured\":%s,\"thread_context_captured\":%s,\"ymm_supported\":%s,\"ymm_context_captured\":%s,\"xstate_requested\":%s,\"thread_ymm_context_valid\":%s,\"get_context\":%s,\"set_context\":%s,\"events\":[",fp_bool(p.completed),fp_bool(p.count>0),fp_bool(p.got_context),fp_bool(p.avx),fp_bool(p.path==3?p.thread_y_valid:p.handler_y_valid[0]),fp_bool(p.xstate_requested),fp_bool(p.thread_y_valid),fp_bool(p.got_context),fp_bool(p.set_context));
    for(i=0;i<(unsigned)p.count&&i<FP_CAP;i++){fp_add(&w,"%s{\"code\":%lu,\"exception_flags\":%lu,\"rip_offset\":%lld,\"exception_offset\":%lld,\"flags_masked\":%u,\"mxcsr\":%lu,\"cw\":%u,\"parameters\":%lu,\"address_class\":\"%s\",\"ymm_context_valid\":%s,\"access_kind\":",i?",":"",(unsigned long)p.codes[i],(unsigned long)p.exception_flags[i],fp_relative(&p,(ULONG_PTR)p.captured[i].Rip),fp_relative(&p,p.addresses[i]),(unsigned)(p.captured[i].EFlags&FP_FLAG_MASK),(unsigned long)p.captured[i].MxCsr,(unsigned)p.captured[i].FltSave.ControlWord,(unsigned long)p.parameter_counts[i],fp_address_class(&p,i),fp_bool(p.handler_y_valid[i]));if(p.parameter_counts[i]>0)fp_add(&w,"%llu",(unsigned long long)p.info0[i]);else fp_add(&w,"null");fp_add(&w,"}");}
    fp_add(&w,"]}}");
    if(w.failed)snprintf(out,n,"{\"status\":\"OBSERVED\",\"reason\":\"output_buffer_too_small\",\"raw\":{},\"norm\":{\"invariants\":{\"output_complete\":false}}}");
    goto done;
failed:snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"%s\",\"raw\":{\"win32_error\":%lu,\"hardware_mxcsr_mask\":%lu},\"norm\":{}}",p.unsupported_mxcsr?"unsupported_mxcsr_bits":"probe_setup_failed",(unsigned long)p.error,(unsigned long)p.hardware_mxcsr_mask);
done:if(h)CloseHandle(h);if(veh&&!RemoveVectoredExceptionHandler(veh)){fputs("0090 FP handler cleanup failed; own process exits.\n",stderr);fflush(stderr);ExitProcess(125);}fp_active=NULL;fp_cleanup(&p);
}
void probe_fp(unsigned axis,char *out,size_t n){fp_run(axis,0,out,n);}
void probe_flags(unsigned axis,char *out,size_t n){fp_run(axis,1,out,n);}
void probe_faults(unsigned axis,char *out,size_t n){fp_run(axis,2,out,n);}

/* END fp_flags.inc */
/* BEGIN memory.inc */
/* 0090: self-owned memory/file observations. Windows x64; scoped VEH with C setjmp recovery.
 * No external process or pre-existing file is modified. No timing pass/fail.
 * Sources (reviewed 2026-10-10):
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-getwritewatch
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
 * https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setendoffile
 * Deliberate live-map resize is a negative diagnostic, not supported application usage.
 */
#if defined(_WIN64)
#include <setjmp.h>
#ifndef MEM_WRITE_WATCH
#define MEM_WRITE_WATCH 0x00200000
#endif

typedef struct mem_exception {
    DWORD code, flags, parameter_count;
    ULONG_PTR instruction, access, address, inpage_status;
} mem_exception;
/* Scoped VEH recovery: only this thread, active owned address range, one fault.
 * No instruction here changes DF. longjmp unwinds to a live setjmp caller;
 * no locks/resources are acquired between the two inside our helpers.
 * Limitation: recovering a user-mode fault thrown inside ReadFile/RPM bypasses
 * API-internal unwinding. Their internal cleanup is not guaranteed by this probe.
 * cleanup_complete covers ONLY our explicit handles, files, views, and VEH. */
static jmp_buf mem_jump;
static int mem_handler_cleanup_ok=1;
static DWORD mem_thread;
static volatile LONG mem_active;
static ULONG_PTR mem_low,mem_high;
static mem_exception *mem_record;
static LONG CALLBACK mem_veh(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *e=ep->ExceptionRecord; mem_exception *r=mem_record;
    ULONG_PTR target=e->NumberParameters>1?e->ExceptionInformation[1]:(ULONG_PTR)e->ExceptionAddress;
    if(!mem_active || GetCurrentThreadId()!=mem_thread || target<mem_low || target>=mem_high)
        return EXCEPTION_CONTINUE_SEARCH;
    if(e->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION && e->ExceptionCode!=EXCEPTION_GUARD_PAGE &&
       e->ExceptionCode!=EXCEPTION_IN_PAGE_ERROR && e->ExceptionCode!=EXCEPTION_ILLEGAL_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;
    r->code=e->ExceptionCode;r->flags=e->ExceptionFlags;r->parameter_count=e->NumberParameters;
    r->instruction=(ULONG_PTR)e->ExceptionAddress;
    if(e->NumberParameters>0)r->access=e->ExceptionInformation[0];
    if(e->NumberParameters>1)r->address=e->ExceptionInformation[1];
    if(e->NumberParameters>2)r->inpage_status=e->ExceptionInformation[2];
    mem_active=0;longjmp(mem_jump,1);
    return EXCEPTION_CONTINUE_SEARCH;
}
static PVOID mem_begin(const void *p,SIZE_T size,mem_exception *ex) {
    PVOID h;mem_low=(ULONG_PTR)p;mem_high=mem_low+size;mem_record=ex;
    mem_thread=GetCurrentThreadId();mem_active=0;
    h=AddVectoredExceptionHandler(1,mem_veh);return h;
}
static void mem_end(PVOID h) {mem_active=0;if(h && !RemoveVectoredExceptionHandler(h))mem_handler_cleanup_ok=0;mem_record=NULL;}
static void mem_exjson(char *s,size_t n,const mem_exception *r) {
    snprintf(s,n,"{\"code\":%lu,\"flags\":%lu,\"parameters\":%lu,\"instruction\":\"0x%llx\",\"access\":%llu,\"address\":\"0x%llx\",\"inpage_status\":%llu}",
      (unsigned long)r->code,(unsigned long)r->flags,(unsigned long)r->parameter_count,
      (unsigned long long)r->instruction,(unsigned long long)r->access,
      (unsigned long long)r->address,(unsigned long long)r->inpage_status);
}
typedef struct mem_file {
    HANDLE h; char dir[MAX_PATH],path[MAX_PATH]; int made_dir,made_file;
    DWORD error; int close_ok,delete_ok,rmdir_ok;
} mem_file;
static LONG mem_sequence;
static int mem_file_open(mem_file *f,DWORD length) {
    unsigned char data[4096]; DWORD wrote,chunk,left=length; unsigned attempt;
    memset(f,0,sizeof(*f)); f->h=INVALID_HANDLE_VALUE;
    memset(data,0x31,sizeof(data));
    for(attempt=0;attempt<32;attempt++) {
        snprintf(f->dir,sizeof(f->dir),".\\0090-owned-%lu-%llu-%ld",(unsigned long)GetCurrentProcessId(),
          (unsigned long long)GetTickCount64(),(long)InterlockedIncrement(&mem_sequence));
        if(CreateDirectoryA(f->dir,NULL)) {f->made_dir=1;break;}
        f->error=GetLastError(); if(f->error!=ERROR_ALREADY_EXISTS)return 0;
    }
    if(!f->made_dir)return 0;
    snprintf(f->path,sizeof(f->path),"%s\\probe.bin",f->dir);
    f->h=CreateFileA(f->path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    NULL,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY,NULL);
    if(f->h==INVALID_HANDLE_VALUE){f->error=GetLastError();return 0;}
    f->made_file=1;
    while(left) {
        chunk=left>sizeof(data)?(DWORD)sizeof(data):left; wrote=0;
        if(!WriteFile(f->h,data,chunk,&wrote,NULL)){f->error=GetLastError();return 0;}
        if(wrote!=chunk){f->error=ERROR_WRITE_FAULT;return 0;}
        left-=wrote;
    }
    if(SetFilePointer(f->h,0,NULL,FILE_BEGIN)==INVALID_SET_FILE_POINTER){f->error=GetLastError();return 0;}
    f->error=0;return 1;
}
static void mem_file_close(mem_file *f) {
    f->close_ok=f->h==INVALID_HANDLE_VALUE?1:CloseHandle(f->h);
    f->h=INVALID_HANDLE_VALUE;
    f->delete_ok=!f->made_file?1:DeleteFileA(f->path);
    f->rmdir_ok=!f->made_dir?1:RemoveDirectoryA(f->dir);
}
static int mem_read_byte(volatile unsigned char *p,int *value,mem_exception *ex) {
    PVOID h=mem_begin((const void*)p,1,ex);int ok=0;if(!h)return -1;
    if(setjmp(mem_jump)==0){mem_active=1;*value=*p;mem_active=0;ok=1;}
    mem_end(h);return ok;
}
static int mem_write_byte(volatile unsigned char *p,unsigned char value,mem_exception *ex) {
    PVOID h=mem_begin((const void*)p,1,ex);int ok=0;if(!h)return -1;
    if(setjmp(mem_jump)==0){mem_active=1;*p=value;mem_active=0;ok=1;}
    mem_end(h);return ok;
}
static void mem_query_json(char *s,size_t n,const void *p) {
    MEMORY_BASIC_INFORMATION q; SIZE_T z; DWORD error;
    memset(&q,0,sizeof(q)); SetLastError(0xdeadbeef);z=VirtualQuery(p,&q,sizeof(q));error=GetLastError();
    snprintf(s,n,"{\"query_bytes\":%llu,\"last_error_raw\":%lu,\"address\":\"%p\",\"base\":\"%p\",\"allocation_base\":\"%p\",\"region_size\":%llu,\"state\":%lu,\"protect\":%lu,\"allocation_protect\":%lu,\"type\":%lu}",
      (unsigned long long)z,(unsigned long)error,p,q.BaseAddress,q.AllocationBase,(unsigned long long)q.RegionSize,
      (unsigned long)q.State,(unsigned long)q.Protect,(unsigned long)q.AllocationProtect,(unsigned long)q.Type);
}
static int mem_call_code(unsigned char *p,int *result,mem_exception *ex) {
    int (__cdecl *fn)(void)=(int (__cdecl *)(void))(void*)p;
    PVOID h=mem_begin(p,4096,ex);int ok=0;if(!h)return -1;
    if(setjmp(mem_jump)==0){mem_active=1;*result=fn();mem_active=0;ok=1;}
    mem_end(h);return ok;
}
void probe_smc(unsigned axis,char *out,size_t n) {
    char raw[12288],norm[4096]; int cleanup; mem_handler_cleanup_ok=1;
    static const char *names[]={"ordinary-neighbor-write","memcpy-data-boundary","ReadFile-data-buffer","code-patch-with-flush","code-patch-without-flush-diagnostic"};
    SYSTEM_INFO si; unsigned char *p=NULL,source[32],initial[6]={0xb8,0x44,0x33,0x22,0x11,0xc3};
    DWORD old=0,error=0,got=0,io_error=0; BOOL io=0,initial_flush=0,patch_flush=0;
    int before=-1,after=-1,called_before=0,called_after=0,operation=0,free_ok=1;
    mem_exception e1={0},e2={0}; char j1[320],j2[320]; mem_file f;
    const char *status="OBSERVED",*stage="complete"; int file_used=0,data_first=-1,data_last=-1;
    memset(&f,0,sizeof(f)); f.h=INVALID_HANDLE_VALUE;
    if(axis>=5){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"invalid-axis\",\"raw\":{},\"norm\":{}}");return;}
    GetSystemInfo(&si);if(si.dwPageSize!=4096){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"requires-4KB-pages\",\"raw\":{},\"norm\":{}}");return;}
    p=(unsigned char*)VirtualAlloc(NULL,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!p){error=GetLastError();status="ERROR";stage="VirtualAlloc";goto done;}
    memcpy(p,initial,sizeof(initial));memset(source,0x72,sizeof(source));
    if(!VirtualProtect(p,4096,PAGE_EXECUTE_READ,&old)){error=GetLastError();status="UNSUPPORTED";stage="executable-protection";goto done;}
    initial_flush=FlushInstructionCache(GetCurrentProcess(),p,6);
    if(!initial_flush){error=GetLastError();status="ERROR";stage="initial-flush";goto done;}
    called_before=mem_call_code(p,&before,&e1);
    if(called_before<0){error=GetLastError();status="UNSUPPORTED";stage="VEH-registration";goto done;}
    if(called_before!=1){status="ERROR";stage="initial-execute";goto done;}
    if(axis==0){p[4096]=0x72;operation=1;data_first=p[4096];data_last=p[4096];}
    if(axis==1){memcpy(p+8192-16,source,32);operation=1;data_first=p[8176];data_last=p[8207];}
    if(axis==2){
        file_used=1;if(!mem_file_open(&f,32)){error=f.error;status="ERROR";stage="owned-file";goto done;}
        SetLastError(0xdeadbeef);io=ReadFile(f.h,p+4096,32,&got,NULL);io_error=GetLastError();operation=io;
        data_first=p[4096];data_last=p[4127];
    }
    if(axis>=3){
        if(!VirtualProtect(p,4096,PAGE_READWRITE,&old)){error=GetLastError();status="ERROR";stage="patch-protect";goto done;}
        p[1]=0x88;p[2]=0x77;p[3]=0x66;p[4]=0x55;operation=1;
        if(!VirtualProtect(p,4096,PAGE_EXECUTE_READ,&old)){error=GetLastError();status="ERROR";stage="patch-executable";goto done;}
        if(axis==3){patch_flush=FlushInstructionCache(GetCurrentProcess(),p,6);if(!patch_flush){error=GetLastError();status="ERROR";stage="patch-flush";goto done;}}
    }
    called_after=mem_call_code(p,&after,&e2);
    if(called_after<0){error=GetLastError();status="UNSUPPORTED";stage="VEH-registration";goto done;}
    if(called_after!=1){status="ERROR";stage="post-execute";}
 done:
    if(p)free_ok=VirtualFree(p,0,MEM_RELEASE);
    if(file_used)mem_file_close(&f);
    mem_exjson(j1,sizeof(j1),&e1);mem_exjson(j2,sizeof(j2),&e2);
    snprintf(raw,sizeof(raw),"{\"status\":\"%s\",\"axis\":\"%s\",\"stage\":\"%s\",\"error\":%lu,\"allocation_bytes\":16384,\"code_offset\":0,\"data_offset\":4096,\"cross_boundary_offset\":8192,\"before_called\":%d,\"before_return\":%d,\"after_called\":%d,\"after_return\":%d,\"operation_ok\":%d,\"initial_flush\":%d,\"patch_flush_called\":%d,\"patch_flush\":%d,\"diagnostic_only\":%s,\"ReadFile_ok\":%d,\"ReadFile_bytes\":%lu,\"ReadFile_last_error_raw\":%lu,\"data_first\":%d,\"data_last\":%d,\"before_exception\":%s,\"after_exception\":%s,\"cleanup\":{\"allocation\":%d,\"file_used\":%d,\"close\":%d,\"delete\":%d,\"directory\":%d}}",
      status,names[axis],stage,(unsigned long)error,called_before,before,called_after,after,operation,initial_flush,axis==3,patch_flush,axis==4?"true":"false",io,(unsigned long)got,(unsigned long)io_error,data_first,data_last,j1,j2,free_ok,file_used,f.close_ok,f.delete_ok,f.rmdir_ok);
    cleanup=free_ok && mem_handler_cleanup_ok && (!file_used || (f.close_ok && f.delete_ok && f.rmdir_ok));
    snprintf(norm,sizeof(norm),"{\"invariants\":{\"initial_code_return_correct\":%s,\"post_operation_code_return_correct\":%s,\"cleanup_complete\":%s},\"before_return\":%d,\"after_return\":%d,\"diagnostic_only\":%s,\"call_before\":%d,\"call_after\":%d,\"operation_ok\":%d,\"exception_before\":%lu,\"exception_after\":%lu}",
      called_before==1 && before==0x11223344?"true":"false",
      axis==4 || (called_after==1 && after==(axis==3?0x55667788:0x11223344))?"true":"false",
      cleanup?"true":"false",before,axis==4?0:after,axis==4?"true":"false",called_before,axis==4?0:called_after,operation,(unsigned long)e1.code,axis==4?0ul:(unsigned long)e2.code);
    snprintf(out,n,"{\"status\":\"%s\",\"reason\":\"%s\",\"raw\":%s,\"norm\":%s}",
      strcmp(stage,"complete")==0 || strcmp(stage,"post-execute")==0 || strcmp(stage,"initial-execute")==0?"OBSERVED":"UNSUPPORTED",
      strcmp(stage,"complete")==0 || strcmp(stage,"post-execute")==0 || strcmp(stage,"initial-execute")==0?"":stage,raw,norm);
}
static int mem_os_call(unsigned kind,HANDLE file,void *dst,const void *src,SIZE_T *bytes,BOOL *ret,DWORD *err,mem_exception *ex) {
    PVOID h=mem_begin(dst,32,ex);DWORD got=0;int completed=0;if(!h)return -1;
    if(setjmp(mem_jump)==0) {
        mem_active=1;SetLastError(0xdeadbeef);
        if(kind==0){*ret=ReadFile(file,dst,32,&got,NULL);*err=GetLastError();*bytes=got;}
        else {*ret=ReadProcessMemory(GetCurrentProcess(),src,dst,32,bytes);*err=GetLastError();}
        mem_active=0;completed=1;
    }
    mem_end(h);return completed;
}
void probe_oswrite(unsigned axis,char *out,size_t n) {
    char raw[12288],norm[4096]; int cleanup; mem_handler_cleanup_ok=1;
    static const char *names[]={"ReadFile-RO","ReadFile-GUARD","ReadFile-WRITE_WATCH","RPM-self-RO","RPM-self-GUARD","RPM-self-WRITE_WATCH"};
    unsigned char *p=NULL,src[32];unsigned kind=axis/3,mode=axis%3,i;DWORD old,error=0,err=0,gran=0;
    ULONG_PTR count=4;PVOID pages[4]={0};UINT ww=~0u,reset=~0u;SIZE_T bytes=0;BOOL ret=0;
    int completed=0,first=-1,last=-1,changed=0,protect_ok=0,restore_ok=0,free_ok=1,file_used=0;
    MEMORY_BASIC_INFORMATION state_after;DWORD protect_after=0;
    char exjson[320],query[512]="null",offsets[128]="[]",content[65]="";const char *status="OBSERVED",*stage="complete";
    mem_exception ex={0};mem_file f;SYSTEM_INFO si;
    memset(&f,0,sizeof(f));f.h=INVALID_HANDLE_VALUE;memset(src,0x31,sizeof(src));
    if(axis>=6){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"invalid-axis\",\"raw\":{},\"norm\":{}}");return;}
    GetSystemInfo(&si);p=(unsigned char*)VirtualAlloc(NULL,si.dwPageSize,MEM_RESERVE|MEM_COMMIT|MEM_WRITE_WATCH,PAGE_READWRITE);
    if(!p){error=GetLastError();status="UNSUPPORTED";stage="write-watch-allocation";goto done;}
    memset(p,0xa5,si.dwPageSize);reset=ResetWriteWatch(p,si.dwPageSize);
    if(reset){status="UNSUPPORTED";stage="ResetWriteWatch";goto done;}
    protect_ok=VirtualProtect(p,si.dwPageSize,mode==0?PAGE_READONLY:mode==1?(PAGE_READWRITE|PAGE_GUARD):PAGE_READWRITE,&old);
    if(!protect_ok){error=GetLastError();status="ERROR";stage="VirtualProtect";goto done;}
    if(!kind){file_used=1;if(!mem_file_open(&f,32)){error=f.error;status="ERROR";stage="owned-file";goto done;}}
    completed=mem_os_call(kind,f.h,p,src,&bytes,&ret,&err,&ex);
    if(completed<0){error=GetLastError();status="UNSUPPORTED";stage="VEH-registration";goto done;}
    /* Query guard state and write-watch BEFORE inspection can affect either. */
    mem_query_json(query,sizeof(query),p);
    memset(&state_after,0,sizeof(state_after));if(VirtualQuery(p,&state_after,sizeof(state_after)))protect_after=state_after.Protect;
    ww=GetWriteWatch(0,p,si.dwPageSize,pages,&count,&gran);
    if(!ww && count<=4){size_t used=0;used+=(size_t)snprintf(offsets+used,sizeof(offsets)-used,"[");
        for(i=0;i<count;i++)used+=(size_t)snprintf(offsets+used,sizeof(offsets)-used,"%s%llu",i?",":"",(unsigned long long)((ULONG_PTR)pages[i]-(ULONG_PTR)p));
        snprintf(offsets+used,sizeof(offsets)-used,"]");}
    restore_ok=VirtualProtect(p,si.dwPageSize,PAGE_READWRITE,&old);
    if(restore_ok){first=p[0];last=p[31];for(i=0;i<32;i++){if(p[i]!=0xa5)changed++;snprintf(content+2*i,3,"%02x",p[i]);}}
    else {error=GetLastError();status="ERROR";stage="inspection-protect";}
 done:
    if(p)free_ok=VirtualFree(p,0,MEM_RELEASE);if(file_used)mem_file_close(&f);mem_exjson(exjson,sizeof(exjson),&ex);
    snprintf(raw,sizeof(raw),"{\"status\":\"%s\",\"axis\":\"%s\",\"stage\":\"%s\",\"error\":%lu,\"allocation_has_write_watch\":true,\"reset_result\":%u,\"protect_ok\":%d,\"call_completed\":%d,\"return\":%d,\"last_error_raw\":%lu,\"bytes\":%llu,\"source_process\":\"self-only\",\"buffer_before\":165,\"buffer_first\":%d,\"buffer_last\":%d,\"changed_bytes\":%d,\"buffer_hex\":\"%s\",\"query_before_inspection\":%s,\"write_watch_result\":%u,\"write_watch_count\":%llu,\"write_watch_granularity\":%lu,\"write_watch_offsets\":%s,\"restore_ok\":%d,\"exception\":%s,\"cleanup\":{\"allocation\":%d,\"file_used\":%d,\"close\":%d,\"delete\":%d,\"directory\":%d}}",
      status,names[axis],stage,(unsigned long)error,reset,protect_ok,completed,ret,(unsigned long)err,(unsigned long long)bytes,first,last,changed,content,query,ww,(unsigned long long)count,(unsigned long)gran,offsets,restore_ok,exjson,free_ok,file_used,f.close_ok,f.delete_ok,f.rmdir_ok);
    cleanup=free_ok && mem_handler_cleanup_ok && (!file_used || (f.close_ok && f.delete_ok && f.rmdir_ok));
    snprintf(norm,sizeof(norm),"{\"invariants\":{\"cleanup_complete\":%s},\"call_completed\":%d,\"return\":%d,\"bytes\":%llu,\"changed_bytes\":%d,\"buffer_hex\":\"%s\",\"exception_code\":%lu,\"write_watch_result\":%u,\"write_watch_count\":%llu,\"write_watch_offsets\":%s,\"last_error\":%lu,\"protect_after_call\":%lu}",
      cleanup?"true":"false",completed,ret,(unsigned long long)bytes,changed,content,(unsigned long)ex.code,ww,(unsigned long long)count,offsets,ret?0ul:(unsigned long)err,(unsigned long)protect_after);
    snprintf(out,n,"{\"status\":\"%s\",\"reason\":\"%s\",\"raw\":%s,\"norm\":%s}",strcmp(stage,"complete")==0?"OBSERVED":"UNSUPPORTED",strcmp(stage,"complete")==0?"":stage,raw,norm);
}
/* Dynamically resolved to retain builds with older Windows SDK headers.
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3
 * https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
 * Constants are documented MEM_RESERVE_PLACEHOLDER / MEM_REPLACE_PLACEHOLDER /
 * MEM_PRESERVE_PLACEHOLDER. This is an INTERVENTION, not natural mapping behavior. */
typedef PVOID (WINAPI *mem_va2_fn)(HANDLE,PVOID,SIZE_T,ULONG,ULONG,PVOID,ULONG);
typedef PVOID (WINAPI *mem_map3_fn)(HANDLE,HANDLE,PVOID,ULONG64,SIZE_T,ULONG,ULONG,PVOID,ULONG);
static int mem_placeholder_beyond(HANDLE mapping,DWORD rounded,unsigned mode,int *rd,int *wr,int *value,
                                 mem_exception *read_ex,mem_exception *write_ex,DWORD *error,int *clean,char *query,size_t qn) {
    HMODULE k=GetModuleHandleA("kernelbase.dll");mem_va2_fn va;mem_map3_fn mv;
    MEMORY_BASIC_INFORMATION before,view_info,next_info;
    unsigned char *base=NULL,*view=NULL;int split=0,observed=0;DWORD protect=mode==0?PAGE_READONLY:mode==1?PAGE_READWRITE:PAGE_WRITECOPY;
    if(!k)k=GetModuleHandleA("kernel32.dll");
    va=k?(mem_va2_fn)(void*)GetProcAddress(k,"VirtualAlloc2"):NULL;
    mv=k?(mem_map3_fn)(void*)GetProcAddress(k,"MapViewOfFile3"):NULL;
    if(!va || !mv){*error=ERROR_PROC_NOT_FOUND;return 0;}
    base=(unsigned char*)va(GetCurrentProcess(),NULL,(SIZE_T)rounded+4096,MEM_RESERVE|0x00040000,PAGE_NOACCESS,NULL,0);
    if(!base){*error=GetLastError();return 0;}
    memset(&before,0,sizeof(before));
    if(!VirtualQuery(base,&before,sizeof(before)) || before.BaseAddress!=base || before.State!=MEM_RESERVE || before.RegionSize<(SIZE_T)rounded+4096){*error=ERROR_INVALID_ADDRESS;goto done;}
    if(!VirtualFree(base,rounded,MEM_RELEASE|0x00000002)){*error=GetLastError();goto done;}
    split=1;
    view=(unsigned char*)mv(mapping,GetCurrentProcess(),base,0,rounded,0x00004000,protect,NULL,0);
    if(!view){*error=GetLastError();goto done;}
    if(view!=base){*error=ERROR_INVALID_ADDRESS;goto done;}
    memset(&view_info,0,sizeof(view_info));memset(&next_info,0,sizeof(next_info));
    if(!VirtualQuery(view,&view_info,sizeof(view_info)) || view_info.AllocationBase!=view || view_info.State!=MEM_COMMIT || view_info.Type!=MEM_MAPPED || view_info.RegionSize<rounded ||
       !VirtualQuery(base+rounded,&next_info,sizeof(next_info)) || next_info.BaseAddress!=base+rounded || next_info.State!=MEM_RESERVE || next_info.RegionSize<4096){*error=ERROR_INVALID_ADDRESS;goto done;}
    mem_query_json(query,qn,base+rounded);
    *rd=mem_read_byte(base+rounded,value,read_ex);
    *wr=mem_write_byte(base+rounded,0x63,write_ex);
    if(*rd<0 || *wr<0){*error=ERROR_NOT_ENOUGH_MEMORY;goto done;}
    observed=1;*error=0;
 done:
    if(view){if(!UnmapViewOfFile(view))*clean=0;if(view!=base && !VirtualFree(base,0,MEM_RELEASE))*clean=0;}
    else if(!VirtualFree(base,0,MEM_RELEASE))*clean=0;
    if(split && !VirtualFree(base+rounded,0,MEM_RELEASE))*clean=0;
    return observed;
}
void probe_mapping(unsigned axis,char *out,size_t n) {
    char raw[12288],norm[4096]; int cleanup; mem_handler_cleanup_ok=1;
    static const DWORD lengths[]={1,4095,4097,16385};static const char *modes[]={"READ","WRITE","COPY"};
    DWORD length=lengths[(axis/3)%4],mode=axis%3,access=mode==0?FILE_MAP_READ:mode==1?FILE_MAP_WRITE:FILE_MAP_COPY;
    SYSTEM_INFO si;mem_file f;HANDLE mapping=NULL;unsigned char *p=NULL,*peer=NULL;
    DWORD rounded,error=0,flush_error=0,file_flush_error=0,resize_error=0,got=0,sentinel_error=0;
    BOOL flushed=0,file_flushed=0,resize=0;LARGE_INTEGER position,size_after;
    int eof_read=-2,tail_read=-2,eof_write=-2,tail_write=-2,beyond_read=-2,beyond_write=-2;
    int eof_value=-1,tail_value=-1,beyond_value=-1,first_write=-2,own_first=-1,peer_first=-1,file_first=-1;
    int unmap_ok=1,peer_unmap_ok=1,map_close_ok=1,sentinel_free_ok=1,owned_sentinel=0;
    mem_exception ex[9];char ej[9][320],queries[4096]="[]",q[512],bq[512]="null",sentinel_query[512]="null";
    int last_valid_read=-2,last_valid_value=-1,last_valid_write=-2;
    const char *status="OBSERVED",*stage="complete",*beyond_status="UNSUPPORTED";unsigned i;size_t used=0;
    memset(ex,0,sizeof(ex));memset(&f,0,sizeof(f));f.h=INVALID_HANDLE_VALUE;size_after.QuadPart=-1;
    if(axis>=12){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"invalid-axis\",\"raw\":{},\"norm\":{}}");return;}
    GetSystemInfo(&si);if(si.dwPageSize!=4096){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"requires-4KB-pages\",\"raw\":{},\"norm\":{}}");return;}
    rounded=(length+4095)&~4095u;
    if(!mem_file_open(&f,length)){error=f.error;status="ERROR";stage="owned-file";goto done;}
    mapping=CreateFileMappingA(f.h,NULL,PAGE_READWRITE,0,0,NULL);
    if(!mapping){error=GetLastError();status="UNSUPPORTED";stage="CreateFileMapping";goto done;}
    p=(unsigned char*)MapViewOfFile(mapping,access,0,0,length);
    if(!p){error=GetLastError();status="UNSUPPORTED";stage="MapViewOfFile";goto done;}
    peer=(unsigned char*)MapViewOfFile(mapping,FILE_MAP_READ,0,0,length);
    if(!peer){error=GetLastError();status="UNSUPPORTED";stage="peer-view";goto done;}
    used+=(size_t)snprintf(queries+used,sizeof(queries)-used,"[");
    for(i=0;i<rounded;i+=4096){mem_query_json(q,sizeof(q),p+i);used+=(size_t)snprintf(queries+used,sizeof(queries)-used,"%s%s",i?",":"",q);}
    snprintf(queries+used,sizeof(queries)-used,"]");
    /* EOF and final byte within rounded last page. These are owned view pages.
     * File sizes deliberately have a nonempty tail; never access unowned next page. */
    last_valid_read=mem_read_byte(p+length-1,&last_valid_value,&ex[7]);
    last_valid_write=mem_write_byte(p+length-1,0x4c,&ex[8]);
    eof_read=mem_read_byte(p+length,&eof_value,&ex[0]);
    tail_read=mem_read_byte(p+rounded-1,&tail_value,&ex[1]);
    eof_write=mem_write_byte(p+length,0x6d,&ex[2]);
    tail_write=mem_write_byte(p+rounded-1,0x7e,&ex[3]);
    first_write=mem_write_byte(p,0x59,&ex[4]);
    if(last_valid_read<0 || last_valid_write<0 || eof_read<0 || tail_read<0 || eof_write<0 || tail_write<0 || first_write<0){status="UNSUPPORTED";stage="VEH-registration";goto done;}
    {mem_exception inspect={0};mem_read_byte(p,&own_first,&inspect);mem_read_byte(peer,&peer_first,&inspect);}
    mem_query_json(bq,sizeof(bq),p+rounded);
    /* Separate controlled view: preserve ordinary MapViewOfFile measurements.
     * The next address belongs to an explicitly reserved placeholder, never a stranger. */
    owned_sentinel=mem_placeholder_beyond(mapping,rounded,mode,&beyond_read,&beyond_write,&beyond_value,
      &ex[5],&ex[6],&sentinel_error,&sentinel_free_ok,sentinel_query,sizeof(sentinel_query));
    if(owned_sentinel)beyond_status="OBSERVED-OWN-RESERVED-SENTINEL";
    SetLastError(0xdeadbeef);flushed=FlushViewOfFile(p,length);flush_error=GetLastError();
    SetLastError(0xdeadbeef);file_flushed=FlushFileBuffers(f.h);file_flush_error=GetLastError();
    position.QuadPart=0;
    if(SetFilePointerEx(f.h,position,NULL,FILE_BEGIN)) {unsigned char b=0; if(ReadFile(f.h,&b,1,&got,NULL)&&got==1)file_first=b;}
    /* Negative diagnostic: API contract requires views/object closed before resize. */
    position.QuadPart=(LONGLONG)length+4096;
    if(SetFilePointerEx(f.h,position,NULL,FILE_BEGIN)){
        SetLastError(0xdeadbeef);resize=SetEndOfFile(f.h);resize_error=GetLastError();
    }else resize_error=GetLastError();
    GetFileSizeEx(f.h,&size_after);
 done:
    if(peer)peer_unmap_ok=UnmapViewOfFile(peer);if(p)unmap_ok=UnmapViewOfFile(p);if(mapping)map_close_ok=CloseHandle(mapping);
    mem_file_close(&f);for(i=0;i<9;i++)mem_exjson(ej[i],sizeof(ej[i]),&ex[i]);
    snprintf(raw,sizeof(raw),"{\"status\":\"%s\",\"file_bytes\":%lu,\"mode\":\"%s\",\"stage\":\"%s\",\"error\":%lu,\"rounded_bytes\":%lu,\"page_queries\":%s,\"eof_read\":%d,\"eof_value\":%d,\"tail_read\":%d,\"tail_value\":%d,\"eof_write\":%d,\"tail_write\":%d,\"first_write\":%d,\"own_first\":%d,\"peer_first\":%d,\"file_first\":%d,\"beyond\":{\"status\":\"%s\",\"natural_boundary_access\":\"UNSUPPORTED\",\"query_before_reservation\":%s,\"placeholder_query\":%s,\"exact_reservation_owned\":%d,\"reservation_last_error_raw\":%lu,\"read\":%d,\"write\":%d,\"value\":%d,\"intervention\":\"VirtualAlloc2-split-MapViewOfFile3-own-reserved-sentinel\"},\"flush\":%d,\"flush_last_error_raw\":%lu,\"file_flush\":%d,\"file_flush_last_error_raw\":%lu,\"live_resize\":%d,\"resize_last_error_raw\":%lu,\"size_after\":%lld,\"last_valid_read\":%d,\"last_valid_value\":%d,\"last_valid_write\":%d,\"exceptions\":[%s,%s,%s,%s,%s,%s,%s,%s,%s],\"cleanup\":{\"sentinel\":%d,\"view\":%d,\"peer\":%d,\"mapping\":%d,\"file\":%d,\"delete\":%d,\"directory\":%d}}",
      status,(unsigned long)length,modes[mode],stage,(unsigned long)error,(unsigned long)rounded,queries,eof_read,eof_value,tail_read,tail_value,eof_write,tail_write,first_write,own_first,peer_first,file_first,beyond_status,bq,sentinel_query,owned_sentinel,(unsigned long)sentinel_error,beyond_read,beyond_write,beyond_value,flushed,(unsigned long)flush_error,file_flushed,(unsigned long)file_flush_error,resize,(unsigned long)resize_error,(long long)size_after.QuadPart,last_valid_read,last_valid_value,last_valid_write,ej[0],ej[1],ej[2],ej[3],ej[4],ej[5],ej[6],ej[7],ej[8],sentinel_free_ok,unmap_ok,peer_unmap_ok,map_close_ok,f.close_ok,f.delete_ok,f.rmdir_ok);
    cleanup=mem_handler_cleanup_ok && sentinel_free_ok && unmap_ok && peer_unmap_ok && map_close_ok && f.close_ok && f.delete_ok && f.rmdir_ok;
    snprintf(norm,sizeof(norm),"{\"invariants\":{\"cleanup_complete\":%s,\"copy_write_is_private\":%s},\"eof_read\":%d,\"eof_value\":%d,\"tail_read\":%d,\"tail_value\":%d,\"eof_write\":%d,\"tail_write\":%d,\"first_write\":%d,\"own_first\":%d,\"peer_first\":%d,\"file_first\":%d,\"eof_read_exception\":%lu,\"tail_read_exception\":%lu,\"eof_write_exception\":%lu,\"tail_write_exception\":%lu,\"first_write_exception\":%lu,\"flush\":%d,\"flush_error\":%lu,\"file_flush\":%d,\"file_flush_error\":%lu,\"live_resize\":%d,\"resize_error\":%lu,\"size_after\":%lld,\"natural_beyond_status\":\"UNSUPPORTED\",\"last_valid_read\":%d,\"last_valid_value\":%d,\"last_valid_write\":%d,\"last_valid_read_exception\":%lu,\"last_valid_write_exception\":%lu,\"controlled_beyond_supported\":%d,\"controlled_beyond_read\":%d,\"controlled_beyond_write\":%d,\"controlled_beyond_read_exception\":%lu,\"controlled_beyond_write_exception\":%lu}",
      cleanup?"true":"false",mode!=2 || (first_write==1 && own_first==0x59 && peer_first==0x31 && file_first==0x31)?"true":"false",
      eof_read,eof_value,tail_read,tail_value,eof_write,tail_write,first_write,own_first,peer_first,file_first,
      (unsigned long)ex[0].code,(unsigned long)ex[1].code,(unsigned long)ex[2].code,(unsigned long)ex[3].code,(unsigned long)ex[4].code,
      flushed,flushed?0ul:(unsigned long)flush_error,file_flushed,file_flushed?0ul:(unsigned long)file_flush_error,resize,resize?0ul:(unsigned long)resize_error,(long long)size_after.QuadPart,last_valid_read,last_valid_value,last_valid_write,(unsigned long)ex[7].code,(unsigned long)ex[8].code,owned_sentinel,beyond_read,beyond_write,(unsigned long)ex[5].code,(unsigned long)ex[6].code);
    snprintf(out,n,"{\"status\":\"%s\",\"reason\":\"%s\",\"raw\":%s,\"norm\":%s}",strcmp(stage,"complete")==0?"OBSERVED":"UNSUPPORTED",strcmp(stage,"complete")==0?"":stage,raw,norm);
}
#else
void probe_smc(unsigned axis,char*out,size_t n){(void)axis;snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"requires-Windows-x64\",\"raw\":{},\"norm\":{}}");}
void probe_oswrite(unsigned axis,char*out,size_t n){(void)axis;snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"requires-Windows-x64\",\"raw\":{},\"norm\":{}}");}
void probe_mapping(unsigned axis,char*out,size_t n){(void)axis;snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"requires-Windows-x64\",\"raw\":{},\"norm\":{}}");}
#endif

/* END memory.inc */
/* BEGIN nt_sync.inc */
/* Self-process NT export and synchronization probes. See nt_sync_sources.md.
 * No DLL stub inspection and no direct system-call instruction is used.
 * Axes: NT 0..9; synchronization kind=axis/2, threads=(axis%2?4:1).
 */
#if defined(__x86_64__) && defined(__GNUC__) && defined(_WIN32)
#define NT_ABI_AVAILABLE 1
/* Assembly boundary calls the actual export, not an intervening C callback.
 * Seven integer/pointer slots cover every selected signature. All original
 * nonvolatile registers are restored; Windows unwind metadata is emitted. */
extern unsigned nt_abi_invoke(FARPROC target, const uintptr_t *args, LONG *status);
__asm__(
".text\n"
".p2align 4\n"
".globl nt_abi_invoke\n"
".def nt_abi_invoke; .scl 2; .type 32; .endef\n"
".seh_proc nt_abi_invoke\n"
"nt_abi_invoke:\n"
"pushq %rbx\n"
".seh_pushreg %rbx\n"
"pushq %rbp\n"
".seh_pushreg %rbp\n"
"pushq %rsi\n"
".seh_pushreg %rsi\n"
"pushq %rdi\n"
".seh_pushreg %rdi\n"
"pushq %r12\n"
".seh_pushreg %r12\n"
"pushq %r13\n"
".seh_pushreg %r13\n"
"pushq %r14\n"
".seh_pushreg %r14\n"
"pushq %r15\n"
".seh_pushreg %r15\n"
"subq $248, %rsp\n"
".seh_stackalloc 248\n"
"movdqu %xmm6, 80(%rsp)\n"
".seh_savexmm %xmm6, 80\n"
"movdqu %xmm7, 96(%rsp)\n"
".seh_savexmm %xmm7, 96\n"
"movdqu %xmm8, 112(%rsp)\n"
".seh_savexmm %xmm8, 112\n"
"movdqu %xmm9, 128(%rsp)\n"
".seh_savexmm %xmm9, 128\n"
"movdqu %xmm10, 144(%rsp)\n"
".seh_savexmm %xmm10, 144\n"
"movdqu %xmm11, 160(%rsp)\n"
".seh_savexmm %xmm11, 160\n"
"movdqu %xmm12, 176(%rsp)\n"
".seh_savexmm %xmm12, 176\n"
"movdqu %xmm13, 192(%rsp)\n"
".seh_savexmm %xmm13, 192\n"
"movdqu %xmm14, 208(%rsp)\n"
".seh_savexmm %xmm14, 208\n"
"movdqu %xmm15, 224(%rsp)\n"
".seh_savexmm %xmm15, 224\n"
".seh_endprologue\n"
"movq %rcx, 56(%rsp)\n"
"movq %rdx, 64(%rsp)\n"
"movq %r8, 72(%rsp)\n"
"movl $0x11223340, %ebx\n"
"movl $0x11223341, %ebp\n"
"movl $0x11223342, %esi\n"
"movl $0x11223343, %edi\n"
"movl $0x11223344, %r12d\n"
"movl $0x11223345, %r13d\n"
"movl $0x11223346, %r14d\n"
"movl $0x11223347, %r15d\n"
"movl $0x55667706, %edx\n"
"movd %edx, %xmm6\n"
"pshufd $0, %xmm6, %xmm6\n"
"movl $0x55667707, %edx\n"
"movd %edx, %xmm7\n"
"pshufd $0, %xmm7, %xmm7\n"
"movl $0x55667708, %edx\n"
"movd %edx, %xmm8\n"
"pshufd $0, %xmm8, %xmm8\n"
"movl $0x55667709, %edx\n"
"movd %edx, %xmm9\n"
"pshufd $0, %xmm9, %xmm9\n"
"movl $0x5566770a, %edx\n"
"movd %edx, %xmm10\n"
"pshufd $0, %xmm10, %xmm10\n"
"movl $0x5566770b, %edx\n"
"movd %edx, %xmm11\n"
"pshufd $0, %xmm11, %xmm11\n"
"movl $0x5566770c, %edx\n"
"movd %edx, %xmm12\n"
"pshufd $0, %xmm12, %xmm12\n"
"movl $0x5566770d, %edx\n"
"movd %edx, %xmm13\n"
"pshufd $0, %xmm13, %xmm13\n"
"movl $0x5566770e, %edx\n"
"movd %edx, %xmm14\n"
"pshufd $0, %xmm14, %xmm14\n"
"movl $0x5566770f, %edx\n"
"movd %edx, %xmm15\n"
"pshufd $0, %xmm15, %xmm15\n"
"movq 64(%rsp), %r10\n"
"movq 32(%r10), %rax\n"
"movq %rax, 32(%rsp)\n"
"movq 40(%r10), %rax\n"
"movq %rax, 40(%rsp)\n"
"movq 48(%r10), %rax\n"
"movq %rax, 48(%rsp)\n"
"movq 0(%r10), %rcx\n"
"movq 8(%r10), %rdx\n"
"movq 16(%r10), %r8\n"
"movq 24(%r10), %r9\n"
"call *56(%rsp)\n"
"movq 72(%rsp), %rcx\n"
"movl %eax, (%rcx)\n"
"xorl %eax, %eax\n"
"cmpq $0x11223340, %rbx\n"
"je nt_abi_gpr_0\n"
"orl $1, %eax\n"
"nt_abi_gpr_0:\n"
"cmpq $0x11223341, %rbp\n"
"je nt_abi_gpr_1\n"
"orl $2, %eax\n"
"nt_abi_gpr_1:\n"
"cmpq $0x11223342, %rsi\n"
"je nt_abi_gpr_2\n"
"orl $4, %eax\n"
"nt_abi_gpr_2:\n"
"cmpq $0x11223343, %rdi\n"
"je nt_abi_gpr_3\n"
"orl $8, %eax\n"
"nt_abi_gpr_3:\n"
"cmpq $0x11223344, %r12\n"
"je nt_abi_gpr_4\n"
"orl $16, %eax\n"
"nt_abi_gpr_4:\n"
"cmpq $0x11223345, %r13\n"
"je nt_abi_gpr_5\n"
"orl $32, %eax\n"
"nt_abi_gpr_5:\n"
"cmpq $0x11223346, %r14\n"
"je nt_abi_gpr_6\n"
"orl $64, %eax\n"
"nt_abi_gpr_6:\n"
"cmpq $0x11223347, %r15\n"
"je nt_abi_gpr_7\n"
"orl $128, %eax\n"
"nt_abi_gpr_7:\n"
"movl $0x55667706, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm6, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_6\n"
"orl $256, %eax\n"
"nt_abi_xmm_6:\n"
"movl $0x55667707, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm7, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_7\n"
"orl $512, %eax\n"
"nt_abi_xmm_7:\n"
"movl $0x55667708, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm8, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_8\n"
"orl $1024, %eax\n"
"nt_abi_xmm_8:\n"
"movl $0x55667709, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm9, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_9\n"
"orl $2048, %eax\n"
"nt_abi_xmm_9:\n"
"movl $0x5566770a, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm10, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_10\n"
"orl $4096, %eax\n"
"nt_abi_xmm_10:\n"
"movl $0x5566770b, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm11, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_11\n"
"orl $8192, %eax\n"
"nt_abi_xmm_11:\n"
"movl $0x5566770c, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm12, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_12\n"
"orl $16384, %eax\n"
"nt_abi_xmm_12:\n"
"movl $0x5566770d, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm13, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_13\n"
"orl $32768, %eax\n"
"nt_abi_xmm_13:\n"
"movl $0x5566770e, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm14, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_14\n"
"orl $65536, %eax\n"
"nt_abi_xmm_14:\n"
"movl $0x5566770f, %edx\n"
"movd %edx, %xmm1\n"
"pshufd $0, %xmm1, %xmm1\n"
"movdqa %xmm15, %xmm0\n"
"pcmpeqb %xmm1, %xmm0\n"
"pmovmskb %xmm0, %edx\n"
"cmpl $65535, %edx\n"
"je nt_abi_xmm_15\n"
"orl $131072, %eax\n"
"nt_abi_xmm_15:\n"
"movdqu 80(%rsp), %xmm6\n"
"movdqu 96(%rsp), %xmm7\n"
"movdqu 112(%rsp), %xmm8\n"
"movdqu 128(%rsp), %xmm9\n"
"movdqu 144(%rsp), %xmm10\n"
"movdqu 160(%rsp), %xmm11\n"
"movdqu 176(%rsp), %xmm12\n"
"movdqu 192(%rsp), %xmm13\n"
"movdqu 208(%rsp), %xmm14\n"
"movdqu 224(%rsp), %xmm15\n"
"addq $248, %rsp\n"
"popq %r15\n"
"popq %r14\n"
"popq %r13\n"
"popq %r12\n"
"popq %rdi\n"
"popq %rsi\n"
"popq %rbp\n"
"popq %rbx\n"
"ret\n"
".seh_endproc\n"
);
#else
#define NT_ABI_AVAILABLE 0
#endif
static LONG nt_dispatch(unsigned axis, FARPROC fn, uintptr_t a[7], unsigned *mask) {
#if NT_ABI_AVAILABLE
    LONG status; unsigned before_mxcsr,after_mxcsr; unsigned short before_cw,after_cw;
    (void)axis;
    __asm__ volatile("stmxcsr %0; fnstcw %1" : "=m"(before_mxcsr), "=m"(before_cw));
    *mask = nt_abi_invoke(fn, a, &status);
    __asm__ volatile("stmxcsr %0; fnstcw %1" : "=m"(after_mxcsr), "=m"(after_cw));
    if((before_mxcsr^after_mxcsr)&0xffc0u)*mask|=1u<<18;
    if(before_cw!=after_cw)*mask|=1u<<19;
    __asm__ volatile("ldmxcsr %0; fldcw %1" : : "m"(before_mxcsr), "m"(before_cw));
    return status;
#else
    /* Typed fallback performs semantics only; it does not claim ABI testing. */
    *mask = 0;
    switch (axis) {
    case 0: return ((LONG (NTAPI *)(HANDLE,PVOID,ULONG,PVOID,SIZE_T,PSIZE_T))fn)((HANDLE)a[0],(PVOID)a[1],(ULONG)a[2],(PVOID)a[3],(SIZE_T)a[4],(PSIZE_T)a[5]);
    case 1: return ((LONG (NTAPI *)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG))fn)((HANDLE)a[0],(PVOID*)a[1],(PSIZE_T)a[2],(ULONG)a[3],(PULONG)a[4]);
    case 2: return ((LONG (NTAPI *)(HANDLE))fn)((HANDLE)a[0]);
    case 3: return ((LONG (NTAPI *)(BOOLEAN,PLARGE_INTEGER))fn)((BOOLEAN)a[0],(PLARGE_INTEGER)a[1]);
    case 4: return ((LONG (NTAPI *)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG))fn)((HANDLE)a[0],(PROCESSINFOCLASS)a[1],(PVOID)a[2],(ULONG)a[3],(PULONG)a[4]);
    case 5: return ((LONG (NTAPI *)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG))fn)((HANDLE)a[0],(PVOID*)a[1],(ULONG_PTR)a[2],(PSIZE_T)a[3],(ULONG)a[4],(ULONG)a[5]);
    case 6: return ((LONG (NTAPI *)(HANDLE,PVOID*,PSIZE_T,ULONG))fn)((HANDLE)a[0],(PVOID*)a[1],(PSIZE_T)a[2],(ULONG)a[3]);
    case 7: return ((LONG (NTAPI *)(HANDLE,BOOLEAN,PLARGE_INTEGER))fn)((HANDLE)a[0],(BOOLEAN)a[1],(PLARGE_INTEGER)a[2]);
    case 8: return ((LONG (NTAPI *)(PLARGE_INTEGER))fn)((PLARGE_INTEGER)a[0]);
    case 9: return ((LONG (NTAPI *)(HANDLE,HANDLE,HANDLE,PHANDLE,ACCESS_MASK,ULONG,ULONG))fn)((HANDLE)a[0],(HANDLE)a[1],(HANDLE)a[2],(PHANDLE)a[3],(ACCESS_MASK)a[4],(ULONG)a[5],(ULONG)a[6]);
    }
    return (LONG)0xc000000d;
#endif
}
static void probe_nt(unsigned axis, char *out, size_t n) {
    static const char *nt_names[10] = {"NtQueryVirtualMemory","NtProtectVirtualMemory","NtClose","NtDelayExecution","NtQueryInformationProcess","NtAllocateVirtualMemory","NtFreeVirtualMemory","NtWaitForSingleObject","NtQuerySystemTime","NtDuplicateObject"};
    static const char *nt_win32[10] = {"VirtualQuery","VirtualProtect","CloseHandle","Sleep","GetCurrentProcessId","VirtualAlloc","VirtualFree","WaitForSingleObject","GetSystemTimeAsFileTime","DuplicateHandle"};
    static const char *nt_docs[10] = {"DDI_only","empirical_export_ABI","documented_user_mode_deprecated","empirical_export_ABI","documented_user_mode_internal","DDI_only","DDI_only","documented_user_mode_deprecated","documented_user_mode_internal","DDI_only"};
    uintptr_t a[7] = {0}; unsigned abi_mask=0, cleanup_mask=0;
    LONG status=(LONG)0xc0000001, cleanup_status=0;
    HMODULE module; FARPROC fn, alloc_fn, free_fn;
    HANDLE h1=NULL,h2=NULL,source=NULL;
    PVOID p1=NULL,p2=NULL,original=NULL; SIZE_T size=4096,returned=0;
    MEMORY_BASIC_INFORMATION m1,m2; PROCESS_BASIC_INFORMATION pbi;
    ULONG old1=0,returned32=0; DWORD old2=0,winerr=0; BOOL winok=FALSE;
    LARGE_INTEGER interval,t0,t1,freq,nt_time; FILETIME ft0,ft1;
    uint64_t value1=0,value2=0,value3=0,value4=0; int match=0,clean=1,nt_owned=0;
    const char *meaning="none", *reason=NULL;
    if (axis>=10 || sizeof(void*)!=8) { snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"NT axes require 0..9 and x64\",\"raw\":{},\"norm\":{}}"); return; }
    module=GetModuleHandleW(L"ntdll.dll"); fn=module?GetProcAddress(module,nt_names[axis]):NULL;
    if (!fn) { snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"export unavailable\",\"raw\":{\"export\":\"%s\"},\"norm\":{}}",nt_names[axis]); return; }
    alloc_fn=GetProcAddress(module,"NtAllocateVirtualMemory"); free_fn=GetProcAddress(module,"NtFreeVirtualMemory");
    memset(&m1,0,sizeof(m1)); memset(&m2,0,sizeof(m2)); memset(&pbi,0,sizeof(pbi));
    if (axis==0 || axis==1) {
        p1=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        if (axis==1) p2=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        if (!p1 || (axis==1&&!p2)) { reason="private allocation failed"; goto nt_cleanup; }
    }
    if (axis==2 || axis==7 || axis==9) {
        h1=CreateEventW(NULL,TRUE,TRUE,NULL); h2=CreateEventW(NULL,TRUE,TRUE,NULL);
        if (!h1 || !h2) { reason="private event creation failed"; goto nt_cleanup; }
    }
    if (axis==5 || axis==6) {
        if (!alloc_fn || !free_fn) { reason="allocation cleanup exports unavailable"; goto nt_cleanup; }
        p2=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        if (!p2) { reason="Win32 allocation failed"; goto nt_cleanup; }
        if (axis==6) {
            uintptr_t setup[7]={(uintptr_t)GetCurrentProcess(),(uintptr_t)&p1,0,(uintptr_t)&size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE,0};
            if (nt_dispatch(5,alloc_fn,setup,&cleanup_mask)!=0 || !p1) { reason="NT allocation precondition failed"; goto nt_cleanup; }
            nt_owned=1;
        }
    }
    switch (axis) {
    case 0:
        a[0]=(uintptr_t)GetCurrentProcess(); a[1]=(uintptr_t)p1; a[2]=0;
        a[3]=(uintptr_t)&m1; a[4]=sizeof(m1); a[5]=(uintptr_t)&returned;
        status=nt_dispatch(axis,fn,a,&abi_mask);
        winok=VirtualQuery(p1,&m2,sizeof(m2))==sizeof(m2); if(!winok)winerr=GetLastError();
        value1=m1.State; value2=m2.State; value3=m1.Protect; value4=m2.Protect;
        meaning="native_state,win32_state,native_protect,win32_protect";
        match=status==0&&winok&&returned==sizeof(m1)&&m1.BaseAddress==m2.BaseAddress&&m1.RegionSize==m2.RegionSize&&m1.State==m2.State&&m1.Protect==m2.Protect&&m1.Type==m2.Type;
        break;
    case 1:
        a[0]=(uintptr_t)GetCurrentProcess();a[1]=(uintptr_t)&p1;a[2]=(uintptr_t)&size;a[3]=PAGE_READONLY;a[4]=(uintptr_t)&old1;
        status=nt_dispatch(axis,fn,a,&abi_mask);
        winok=VirtualProtect(p2,4096,PAGE_READONLY,&old2);if(!winok)winerr=GetLastError();
        if(VirtualQuery(p1,&m1,sizeof(m1))!=sizeof(m1)||VirtualQuery(p2,&m2,sizeof(m2))!=sizeof(m2))winok=FALSE;
        value1=old1;value2=old2;value3=m1.Protect;value4=m2.Protect;
        meaning="native_old_protect,win32_old_protect,native_new_protect,win32_new_protect";
        match=status==0&&winok&&old1==PAGE_READWRITE&&old2==PAGE_READWRITE&&m1.Protect==PAGE_READONLY&&m2.Protect==PAGE_READONLY;
        break;
    case 2:
        a[0]=(uintptr_t)h1;status=nt_dispatch(axis,fn,a,&abi_mask);if(status==0)h1=NULL;
        winok=CloseHandle(h2);if(winok)h2=NULL;else winerr=GetLastError();
        match=status==0&&winok;value1=(uint32_t)status;value2=winok;meaning="native_status,win32_close_success,unused,unused";break;
    case 3:
        interval.QuadPart=-10000;freq.QuadPart=t0.QuadPart=t1.QuadPart=0;
        if(!QueryPerformanceFrequency(&freq)||!QueryPerformanceCounter(&t0)){reason="performance counter unavailable";break;}
        a[0]=FALSE;a[1]=(uintptr_t)&interval;status=nt_dispatch(axis,fn,a,&abi_mask);
        if(!QueryPerformanceCounter(&t1)){reason="performance counter read failed";break;}
        value1=(uint64_t)(t1.QuadPart-t0.QuadPart);
        QueryPerformanceCounter(&t0);Sleep(1);winok=QueryPerformanceCounter(&t1);value2=(uint64_t)(t1.QuadPart-t0.QuadPart);value3=(uint64_t)freq.QuadPart;
        meaning="native_elapsed_qpc,win32_elapsed_qpc,qpc_frequency,unused";match=status==0&&winok;break;
    case 4:
        a[0]=(uintptr_t)GetCurrentProcess();a[1]=0;a[2]=(uintptr_t)&pbi;a[3]=sizeof(pbi);a[4]=(uintptr_t)&returned32;
        status=nt_dispatch(axis,fn,a,&abi_mask);value1=(uint64_t)pbi.UniqueProcessId;value2=GetCurrentProcessId();winok=value2!=0;
        value3=returned32;meaning="native_pid,win32_pid,returned_bytes,unused";match=status==0&&winok&&value1==value2;break;
    case 5:
        a[0]=(uintptr_t)GetCurrentProcess();a[1]=(uintptr_t)&p1;a[2]=0;a[3]=(uintptr_t)&size;a[4]=MEM_RESERVE|MEM_COMMIT;a[5]=PAGE_READWRITE;
        status=nt_dispatch(axis,fn,a,&abi_mask);nt_owned=p1!=NULL;
        winok=p1&&VirtualQuery(p1,&m1,sizeof(m1))==sizeof(m1)&&VirtualQuery(p2,&m2,sizeof(m2))==sizeof(m2);
        value1=m1.State;value2=m2.State;value3=m1.Protect;value4=m2.Protect;
        meaning="native_state,win32_state,native_protect,win32_protect";
        match=status==0&&winok&&m1.State==MEM_COMMIT&&m2.State==MEM_COMMIT&&m1.Protect==PAGE_READWRITE&&m2.Protect==PAGE_READWRITE;break;
    case 6:
        original=p1;size=0;a[0]=(uintptr_t)GetCurrentProcess();a[1]=(uintptr_t)&p1;a[2]=(uintptr_t)&size;a[3]=MEM_RELEASE;
        status=nt_dispatch(axis,fn,a,&abi_mask);if(status==0){p1=NULL;nt_owned=0;}
        winok=VirtualFree(p2,0,MEM_RELEASE);if(winok)p2=NULL;else winerr=GetLastError();
        value1=(uint32_t)status;value2=winok;meaning="native_status,win32_free_success,unused,unused";match=status==0&&winok;(void)original;break;
    case 7:
        interval.QuadPart=0;a[0]=(uintptr_t)h1;a[1]=FALSE;a[2]=(uintptr_t)&interval;
        status=nt_dispatch(axis,fn,a,&abi_mask);value2=WaitForSingleObject(h2,0);winok=value2==WAIT_OBJECT_0;
        value1=(uint32_t)status;meaning="native_wait_status,win32_wait_status,unused,unused";match=status==0&&winok;break;
    case 8:
        nt_time.QuadPart=0;GetSystemTimeAsFileTime(&ft0);a[0]=(uintptr_t)&nt_time;status=nt_dispatch(axis,fn,a,&abi_mask);GetSystemTimeAsFileTime(&ft1);
        value1=(uint64_t)nt_time.QuadPart;value2=((uint64_t)ft0.dwHighDateTime<<32)|ft0.dwLowDateTime;value3=((uint64_t)ft1.dwHighDateTime<<32)|ft1.dwLowDateTime;
        meaning="native_filetime,win32_before_filetime,win32_after_filetime,unused";winok=TRUE;
        /* Clock adjustment can invalidate the bracket; report observation only. */
        match=status==0&&value1>=value2&&value1<=value3;break;
    case 9:
        source=h1;h1=NULL;if(!CloseHandle(h2)){clean=0;reason="spare event cleanup failed";break;}h2=NULL;
        a[0]=(uintptr_t)GetCurrentProcess();a[1]=(uintptr_t)source;a[2]=(uintptr_t)GetCurrentProcess();a[3]=(uintptr_t)&h1;a[4]=0;a[5]=0;a[6]=DUPLICATE_SAME_ACCESS;
        status=nt_dispatch(axis,fn,a,&abi_mask);
        winok=DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),&h2,0,FALSE,DUPLICATE_SAME_ACCESS);if(!winok)winerr=GetLastError();
        value1=h1?WaitForSingleObject(h1,0):WAIT_FAILED;value2=h2?WaitForSingleObject(h2,0):WAIT_FAILED;
        meaning="native_duplicate_wait,win32_duplicate_wait,unused,unused";match=status==0&&winok&&value1==WAIT_OBJECT_0&&value2==WAIT_OBJECT_0;break;
    }
nt_cleanup:
    if(h1&&!CloseHandle(h1))clean=0;
    if(h2&&!CloseHandle(h2))clean=0;
    if(source&&!CloseHandle(source))clean=0;
    if(p1) {
        if(nt_owned&&free_fn){uintptr_t ca[7]={(uintptr_t)GetCurrentProcess(),(uintptr_t)&p1,(uintptr_t)&size,MEM_RELEASE,0,0,0};size=0;cleanup_status=nt_dispatch(6,free_fn,ca,&cleanup_mask);if(cleanup_status!=0)clean=0;}
        else if(!VirtualFree(p1,0,MEM_RELEASE))clean=0;
    }
    if(p2&&!VirtualFree(p2,0,MEM_RELEASE))clean=0;
    if(reason){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"%s\",\"raw\":{\"cleanup_ok\":%s},\"norm\":{}}",reason,clean?"true":"false");return;}
    snprintf(out,n,"{\"status\":\"%s\",\"reason\":\"%s\",\"raw\":{\"export\":\"%s\",\"win32\":\"%s\",\"documentation\":\"%s\",\"ntstatus\":%" PRIu32 ",\"win32_success\":%s,\"win32_error\":%lu,\"value_meaning\":\"%s\",\"values\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],\"native_base\":%" PRIuPTR ",\"win32_base\":%" PRIuPTR ",\"native_region_size\":%" PRIu64 ",\"win32_region_size\":%" PRIu64 ",\"native_returned_bytes\":%" PRIu64 ",\"abi_status\":\"%s\",\"abi_changed_mask\":%u},\"norm\":{\"semantic_match\":%s,\"invariants\":{%s\"resource_cleanup_ok\":%s}}}",NT_ABI_AVAILABLE?"OBSERVED":"UNSUPPORTED",NT_ABI_AVAILABLE?"":"GNU x64 ABI wrapper unavailable; semantic fallback observed only",nt_names[axis],nt_win32[axis],nt_docs[axis],(uint32_t)status,winok?"true":"false",(unsigned long)winerr,meaning,value1,value2,value3,value4,(uintptr_t)m1.BaseAddress,(uintptr_t)m2.BaseAddress,(uint64_t)m1.RegionSize,(uint64_t)m2.RegionSize,(uint64_t)(axis==4?returned32:returned),NT_ABI_AVAILABLE?"OBSERVED":"UNSUPPORTED",abi_mask,match?"true":"false",NT_ABI_AVAILABLE?(abi_mask?"\"abi_preserved\":false,":"\"abi_preserved\":true,"):"",clean?"true":"false");
}

/* Synchronization probes: 100000 cycles per worker; 100000/400000 total.
 * Heap-owned state has one coordinator ref plus one ref per started worker.
 * Timeout never frees state still in use and never forcibly kills a thread. */
#define SYNC_CYCLES_PER_WORKER 100000u
#define SYNC_JOIN_TIMEOUT_MS 120000u
#define SYNC_CANCEL_GRACE_MS 5000u
typedef struct sync_group sync_group;
typedef struct sync_worker_state {
    sync_group *group;
    unsigned completed, waits_ok, waits_bad, create_failures, close_failures;
    DWORD first_error;
    uintptr_t min_handle, max_handle, previous_handle;
    unsigned adjacent_reuse;
} sync_worker_state;
struct sync_group {
    volatile LONG references, stop;
    unsigned kind;
    HANDLE start;
    sync_worker_state workers[4];
};
static volatile LONG sync_active_groups=0;
static int sync_release_group(sync_group *g) {
    if (InterlockedDecrement(&g->references)==0) {
        int clean=CloseHandle(g->start)!=0;
        if(!HeapFree(GetProcessHeap(),0,g))clean=0;
        InterlockedDecrement(&sync_active_groups);
        return clean;
    }
    return 1;
}
static void sync_record_wait(sync_worker_state *w, HANDLE h, DWORD expected) {
    DWORD actual=WaitForSingleObject(h,0);
    if(actual==expected) ++w->waits_ok;
    else { ++w->waits_bad; if(!w->first_error)w->first_error=actual==WAIT_FAILED?GetLastError():ERROR_INVALID_DATA; }
}
static DWORD WINAPI sync_worker(LPVOID argument) {
    sync_worker_state *w=(sync_worker_state*)argument; sync_group *g=w->group;
    unsigned i; DWORD startup=WaitForSingleObject(g->start,SYNC_JOIN_TIMEOUT_MS);
    w->min_handle=UINTPTR_MAX;
    if(startup!=WAIT_OBJECT_0) { w->first_error=startup==WAIT_FAILED?GetLastError():ERROR_TIMEOUT; sync_release_group(g);return 1; }
    for(i=0;i<SYNC_CYCLES_PER_WORKER&&!InterlockedCompareExchange(&g->stop,0,0);++i) {
        HANDLE h=NULL;uintptr_t value;BOOL use_ok=TRUE;
        if(g->kind==0)h=CreateEventW(NULL,FALSE,FALSE,NULL);
        else if(g->kind==1)h=CreateSemaphoreW(NULL,0,1,NULL);
        else h=CreateMutexW(NULL,FALSE,NULL);
        if(!h){++w->create_failures;w->first_error=GetLastError();break;}
        value=(uintptr_t)h;
        if(value<w->min_handle)w->min_handle=value;
        if(value>w->max_handle)w->max_handle=value;
        if(i&&value==w->previous_handle)++w->adjacent_reuse;
        w->previous_handle=value;
        if(g->kind<2) {
            sync_record_wait(w,h,WAIT_TIMEOUT);
            use_ok=g->kind==0?SetEvent(h):ReleaseSemaphore(h,1,NULL);
            if(!use_ok&&!w->first_error)w->first_error=GetLastError();
            sync_record_wait(w,h,WAIT_OBJECT_0);
            sync_record_wait(w,h,WAIT_TIMEOUT);
        } else {
            DWORD acquired=WaitForSingleObject(h,0);
            if(acquired==WAIT_OBJECT_0)++w->waits_ok;else{++w->waits_bad;w->first_error=acquired==WAIT_FAILED?GetLastError():ERROR_INVALID_DATA;}
            if(acquired==WAIT_OBJECT_0||acquired==WAIT_ABANDONED) {
                use_ok=ReleaseMutex(h);if(!use_ok&&!w->first_error)w->first_error=GetLastError();
                /* Verify release and immediate re-acquisition, then release. */
                acquired=WaitForSingleObject(h,0);
                if(acquired==WAIT_OBJECT_0)++w->waits_ok;else{++w->waits_bad;if(!w->first_error)w->first_error=acquired==WAIT_FAILED?GetLastError():ERROR_INVALID_DATA;}
                if(acquired==WAIT_OBJECT_0||acquired==WAIT_ABANDONED) {
                    if(!ReleaseMutex(h)){use_ok=FALSE;if(!w->first_error)w->first_error=GetLastError();}
                }
            }
        }
        if(!CloseHandle(h)){++w->close_failures;if(!w->first_error)w->first_error=GetLastError();}
        ++w->completed;
        if(!use_ok||w->waits_bad||w->close_failures)break;
    }
    sync_release_group(g); return 0;
}
static void probe_sync(unsigned axis,char *out,size_t n) {
    static const char *names[3]={"event","semaphore","mutex"};
    sync_group *g;HANDLE threads[4]={NULL,NULL,NULL,NULL};
    unsigned desired=axis%2?4:1,started=0,i,total=0,waits_ok=0,waits_bad=0,create_bad=0,close_bad=0,reuse=0;
    uintptr_t minimum=UINTPTR_MAX,maximum=0;DWORD before=0,after=0,first_error=0,joined=WAIT_FAILED;
    BOOL before_ok,after_ok=FALSE,start_ok;int all_joined=0,timed_out=0,handles_clean=1;
    if(axis>=6){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"sync axis must be 0..5\",\"raw\":{},\"norm\":{}}");return;}
    if(InterlockedCompareExchange(&sync_active_groups,0,0)){
        snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"previous timed-out sync workers still finishing\",\"raw\":{},\"norm\":{}}");return;
    }
    before_ok=GetProcessHandleCount(GetCurrentProcess(),&before);
    g=(sync_group*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*g));
    if(!g){snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"worker-state allocation failed\",\"raw\":{},\"norm\":{}}");return;}
    g->references=1;g->kind=axis/2;g->start=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!g->start){HeapFree(GetProcessHeap(),0,g);snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"worker start event unavailable\",\"raw\":{},\"norm\":{}}");return;}
    InterlockedIncrement(&sync_active_groups);
    for(i=0;i<desired;++i) {
        g->workers[i].group=g;InterlockedIncrement(&g->references);
        threads[i]=CreateThread(NULL,0,sync_worker,&g->workers[i],0,NULL);
        if(!threads[i]){first_error=GetLastError();sync_release_group(g);InterlockedExchange(&g->stop,1);break;}
        ++started;
    }
    start_ok=SetEvent(g->start);
    if(!start_ok){first_error=GetLastError();InterlockedExchange(&g->stop,1);}
    if(started) {
        joined=WaitForMultipleObjects(started,threads,TRUE,SYNC_JOIN_TIMEOUT_MS);
        if(joined!=WAIT_OBJECT_0) {
            timed_out=joined==WAIT_TIMEOUT;if(!first_error)first_error=joined==WAIT_FAILED?GetLastError():ERROR_TIMEOUT;
            InterlockedExchange(&g->stop,1);
            joined=WaitForMultipleObjects(started,threads,TRUE,SYNC_CANCEL_GRACE_MS);
        }
        all_joined=joined==WAIT_OBJECT_0;
    }else all_joined=1;
    if(all_joined) {
        for(i=0;i<started;++i) {
            sync_worker_state *w=&g->workers[i];
            total+=w->completed;waits_ok+=w->waits_ok;waits_bad+=w->waits_bad;
            create_bad+=w->create_failures;close_bad+=w->close_failures;reuse+=w->adjacent_reuse;
            if(w->min_handle<minimum)minimum=w->min_handle;
            if(w->max_handle>maximum)maximum=w->max_handle;
            if(!first_error&&w->first_error)first_error=w->first_error;
        }
    }
    for(i=0;i<started;++i)if(!CloseHandle(threads[i]))handles_clean=0;
    /* Coordinator drops its ref; unfinished workers retain the whole group. */
    if(!sync_release_group(g))handles_clean=0;
    if(all_joined)after_ok=GetProcessHandleCount(GetCurrentProcess(),&after);
    if(minimum==UINTPTR_MAX)minimum=0;
    snprintf(out,n,"{\"status\":\"OBSERVED\",\"reason\":\"\",\"raw\":{\"kind\":\"%s\",\"threads_requested\":%u,\"threads_started\":%u,\"cycles_per_worker\":%u,\"cycles_requested_total\":%u,\"completed\":%u,\"stats_valid\":%s,\"zero_waits_ok\":%u,\"zero_waits_bad\":%u,\"create_failures\":%u,\"close_failures\":%u,\"first_error\":%lu,\"timed_out\":%s,\"workers_joined\":%s,\"handle_counts_valid\":%s,\"handles_before\":%lu,\"handles_after\":%lu,\"minimum_handle\":%" PRIuPTR ",\"maximum_handle\":%" PRIuPTR ",\"adjacent_reuse_within_worker\":%u,\"join_timeout_ms\":%u,\"cancel_grace_ms\":%u},\"norm\":{\"invariants\":{\"cycles_complete\":%s,\"zero_time_waits_expected\":%s,\"resource_cleanup_ok\":%s,\"operations_succeeded\":%s,\"handle_count_restored\":%s}}}",names[axis/2],desired,started,SYNC_CYCLES_PER_WORKER,desired*SYNC_CYCLES_PER_WORKER,total,all_joined?"true":"false",waits_ok,waits_bad,create_bad,close_bad,(unsigned long)first_error,timed_out?"true":"false",all_joined?"true":"false",before_ok&&after_ok?"true":"false",(unsigned long)before,(unsigned long)after,minimum,maximum,reuse,SYNC_JOIN_TIMEOUT_MS,SYNC_CANCEL_GRACE_MS,all_joined&&started==desired&&total==desired*SYNC_CYCLES_PER_WORKER?"true":"false",all_joined&&!waits_bad&&waits_ok==desired*SYNC_CYCLES_PER_WORKER*(axis/2==2?2u:3u)?"true":"false",all_joined&&handles_clean&&!close_bad?"true":"false",all_joined&&!first_error&&!create_bad&&!close_bad&&start_ok?"true":"false",before_ok&&after_ok&&before==after?"true":"false");
}

/* END nt_sync.inc */
/* BEGIN harness_tail.c */
static void probe_dispatch(unsigned group,unsigned axis,char *out,size_t n){
 switch(group){
 case 0:probe_fp(axis,out,n);break;case 1:probe_flags(axis,out,n);break;
 case 2:probe_faults(axis,out,n);break;case 3:probe_smc(axis,out,n);break;
 case 4:probe_oswrite(axis,out,n);break;case 5:probe_mapping(axis,out,n);break;
 case 6:probe_nt(axis,out,n);break;case 7:probe_sync(axis,out,n);break;
 default:snprintf(out,n,"{\"status\":\"UNSUPPORTED\",\"reason\":\"invalid_group\",\"raw\":{},\"norm\":{}}");break;
 }
}
#endif
int main(int argc,char **argv){
 unsigned first=1,last=probe_total(),id=0,g,x;int listing=0;const char *mode=NULL;
#ifdef _WIN32
 HANDLE watchdog=NULL;LARGE_INTEGER freq={0};
#endif
 if(argc==2&&!strcmp(argv[1],"list")){listing=1;mode="list";}
 else if(argc==2&&!strcmp(argv[1],"all"))mode="all";
 else if(argc==3&&!strcmp(argv[1],"cell")&&probe_number(argv[2],&first)){last=first;mode="cell";}
 else if(argc==4&&!strcmp(argv[1],"range")&&probe_number(argv[2],&first)&&probe_number(argv[3],&last)&&first<=last)mode="range";
 if(!mode){fprintf(stderr,"usage: %s all | cell N | range A B | list (IDs 1..%u)\n",argv[0],probe_total());return 2;}
#ifndef _WIN32
 if(!listing){fputs("This portable build supports list only. Windows execution NOT_RUN.\n",stderr);return 2;}
#else
 if(_setmode(_fileno(stdout),_O_BINARY)==-1)return 3;
 if(!listing){
  probe_watchdog_event=CreateEventW(NULL,TRUE,FALSE,NULL);
  if(!probe_watchdog_event){fputs("watchdog setup failed\n",stderr);return 3;}
  watchdog=CreateThread(NULL,0,probe_watchdog,NULL,0,NULL);
  if(!watchdog){CloseHandle(probe_watchdog_event);return 3;}
  QueryPerformanceFrequency(&freq);
 }
#endif
 printf("META {\"schema\":1,\"source_schema\":\"0090-new-v1\",\"mode\":\"%s\",\"first\":%u,\"last\":%u,\"total_cells\":%u,\"expected_count\":%u",mode,first,last,probe_total(),last-first+1);
#ifdef _WIN32
 if(!listing)printf(",\"platform\":\"windows-x64\",\"pointer_bits\":%u,\"pid\":%lu,\"watchdog_ms\":900000",(unsigned)(8*sizeof(void*)),(unsigned long)GetCurrentProcessId());
#endif
 puts("}");fflush(stdout);
 for(g=0;g<sizeof(probe_groups)/sizeof(*probe_groups);g++)for(x=0;x<probe_groups[g].count;x++){
  id++;if(id<first||id>last)continue;
  if(listing){if(!probe_emit(id,probe_groups[g].family,x,"{\"listed\":true}"))return 3;}
#ifdef _WIN32
  else{
   char *result=(char*)calloc(1,131072);LARGE_INTEGER a={0},b={0};BOOL qa,qb;
   if(!result)return 3;
   qa=QueryPerformanceCounter(&a);probe_dispatch(g,x,result,131072);qb=QueryPerformanceCounter(&b);
   if(!probe_emit(id,probe_groups[g].family,x,result)){free(result);fputs("invalid/truncated probe payload\n",stderr);return 3;}
   free(result);
   printf("TIMING {\"cell\":%u,\"kind\":\"whole_cell_qpc\",\"valid\":%s,\"delta\":%" PRId64 ",\"frequency\":%" PRId64 "}\n",id,(qa&&qb&&freq.QuadPart>0&&b.QuadPart>=a.QuadPart)?"true":"false",(int64_t)(b.QuadPart-a.QuadPart),(int64_t)freq.QuadPart);fflush(stdout);
  }
#endif
 }
#ifdef _WIN32
 if(watchdog){SetEvent(probe_watchdog_event);if(WaitForSingleObject(watchdog,5000)!=WAIT_OBJECT_0)return 3;CloseHandle(watchdog);CloseHandle(probe_watchdog_event);}
#endif
 printf("DONE count=%u checksum=%016" PRIx64 "\n",probe_emitted,probe_checksum);
 return ferror(stdout)?3:0;
}

/* END harness_tail.c */