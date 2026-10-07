/* SPDX-License-Identifier: MIT
 * Original bounded Windows API observation probe, task 0064, revision 1.
 * Sources only: native Windows results must be produced by the curator.
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#include <x86intrin.h>
#endif
#if !defined(_WIN64) || !(defined(_M_X64) || defined(__x86_64__))
#error This revision is for Windows x64 on Intel/AMD, not ARM64EC or x86.
#endif
#define ARRAY_COUNT(x) (sizeof(x)/sizeof((x)[0]))
#define IPC_MS 5000
#define PAGES 4
#define STAGES 2
#define THREADS 2
#define SAMPLES 16
#define USD_BASE ((uintptr_t)0x7ffe0000u)

typedef LONG (NTAPI *nt_query_fn)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef LONG (NTAPI *rtl_version_fn)(OSVERSIONINFOW *);
typedef BOOL (WINAPI *unbiased_fn)(PULONGLONG);
typedef VOID (WINAPI *interrupt_fn)(PULONGLONG);
static int infrastructure_errors;
static unsigned dependent_checks_skipped;
static unsigned tsc_available;

static int resolve(HMODULE module,const char *name,void *out,size_t bytes)
{
    FARPROC address = module ? GetProcAddress(module,name) : NULL;
    if (bytes != sizeof(address)) return 0;
    memcpy(out,&address,bytes);
    return address != NULL;
}
static void error_row(const char *where,DWORD error)
{
    printf("{\"kind\":\"infrastructure_error\",\"where\":\"%s\",\"win32\":%lu}\n",where,(unsigned long)error);
    infrastructure_errors++;
}
static void wait_failure(const char *where,DWORD result,DWORD error)
{
    printf("{\"kind\":\"wait_failure\",\"where\":\"%s\",\"wait_result\":\"0x%08lx\",\"win32\":%lu}\n",where,(unsigned long)result,(unsigned long)error);
    infrastructure_errors++;
}
static DWORD wait_status_error(DWORD result)
{ return result==WAIT_FAILED?GetLastError():result==WAIT_TIMEOUT?ERROR_TIMEOUT:ERROR_INVALID_DATA; }
static int parent_wait(HANDLE handle,const char *where,DWORD milliseconds)
{
    DWORD result=WaitForSingleObject(handle,milliseconds);
    if(result==WAIT_OBJECT_0)return 1;
    wait_failure(where,result,wait_status_error(result));return 0;
}
static void cpuid_leaf(int out[4],unsigned leaf,unsigned subleaf)
{
#if defined(_MSC_VER)
    __cpuidex(out,(int)leaf,(int)subleaf);
#else
    unsigned a,b,c,d;
    __cpuid_count(leaf,subleaf,a,b,c,d);
    out[0]=(int)a;out[1]=(int)b;out[2]=(int)c;out[3]=(int)d;
#endif
}
static uint64_t tsc_read(void)
{
    uint64_t value;
    _mm_lfence();
    value=__rdtsc();
    _mm_lfence();
    return value;
}
static void emit_meta(void)
{
    OSVERSIONINFOW version;
    rtl_version_fn getversion=NULL;
    int cpu[4];char vendor[13];SYSTEM_INFO si;LONG status=(LONG)0xc0000002;
    memset(&version,0,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
    if(resolve(GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion",&getversion,sizeof(getversion)))status=getversion(&version);
    cpuid_leaf(cpu,0,0);memcpy(vendor,&cpu[1],4);memcpy(vendor+4,&cpu[3],4);memcpy(vendor+8,&cpu[2],4);vendor[12]=0;
    cpuid_leaf(cpu,1,0);tsc_available=((unsigned)cpu[3]>>4)&1u;GetSystemInfo(&si);
    /* Vendor is deliberately whitelisted; no host/account/path identifiers. */
    printf("{\"kind\":\"meta\",\"schema\":1,\"probe\":\"0064-ordinary-api-v1\",\"architecture\":\"x64\",\"os_status\":\"0x%08lx\",\"os_major\":%lu,\"os_minor\":%lu,\"os_build\":%lu,\"cpu_vendor\":\"%s\",\"cpuid_signature\":\"0x%08lx\",\"hypervisor_bit\":%u,\"debugger_present\":%u,\"page_size\":%lu,\"allocation_granularity\":%lu}\n",
      (unsigned long)(ULONG)status,(unsigned long)version.dwMajorVersion,(unsigned long)version.dwMinorVersion,(unsigned long)version.dwBuildNumber,
      !strcmp(vendor,"GenuineIntel")?"GenuineIntel":!strcmp(vendor,"AuthenticAMD")?"AuthenticAMD":"other",
      (unsigned long)(ULONG)cpu[0],((unsigned)cpu[2]>>31)&1u,IsDebuggerPresent()?1u:0u,(unsigned long)si.dwPageSize,(unsigned long)si.dwAllocationGranularity);
}
static void process_queries(void)
{
    static const ULONG classes[]={29,32};
    static const ULONG lengths[]={0,1,3,4,8,16,32,64,256,4096};
    nt_query_fn query=NULL;size_t c,n;
    if(!resolve(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess",&query,sizeof(query))) {error_row("resolve_NtQueryInformationProcess",ERROR_PROC_NOT_FOUND);return;}
    for(c=0;c<ARRAY_COUNT(classes);c++) for(n=0;n<ARRAY_COUNT(lengths);n++) {
        union { uint64_t alignment;unsigned char bytes[4096+32]; } block;
        unsigned char before[sizeof(block.bytes)];unsigned char *buffer=block.bytes+16;
        ULONG returned=0xccccccccu;LONG status;size_t i,changed=0,outside=0;unsigned guards=1;
        ULONG scalar=0;unsigned scalar_valid;
        memset(block.bytes,0xa5,sizeof(block.bytes));
        /* Zero the ProcessHandleTracing input header, including its Handle.
         * Never pass a sentinel as an input handle. */
        if(classes[c]==32)memset(buffer,0,32);
        memcpy(before,block.bytes,sizeof(before));
        status=query(GetCurrentProcess(),classes[c],buffer,lengths[n],&returned);
        for(i=0;i<4096;i++)if(buffer[i]!=before[i+16]){if(i<lengths[n])changed++;else outside++;}
        for(i=0;i<16;i++)if(block.bytes[i]!=before[i]||block.bytes[16+4096+i]!=before[16+4096+i])guards=0;
        scalar_valid=classes[c]==29 && status>=0 && lengths[n]>=4 && returned>=4 && returned<=lengths[n];
        if(scalar_valid)memcpy(&scalar,buffer,4);
        printf("{\"kind\":\"process_query\",\"row\":\"P08\",\"class\":%lu,\"length\":%lu,\"status\":\"0x%08lx\",\"return_length\":%lu,\"return_length_written\":%u,\"changed_inside\":%zu,\"changed_outside_declared\":%zu,\"guards_unchanged\":%u,\"scalar_valid\":%u,\"scalar\":\"0x%08lx\",\"initialized_prefix_after_hex\":\"",
          (unsigned long)classes[c],(unsigned long)lengths[n],(unsigned long)(ULONG)status,(unsigned long)returned,returned!=0xccccccccu,changed,outside,guards,scalar_valid,(unsigned long)scalar);
        /* Raw initialized bytes, not a claim that a failure returned a value. */
        for(i=0;i<lengths[n] && i<64;i++)printf("%02x",buffer[i]);
        printf("\"}\n");
    }
}

typedef struct {
    uint64_t returned,region_size;int64_t base_offset;
    DWORD error,state,protect,allocation_protect,type;
    unsigned allocation_base_matches;
} page_observation;
typedef struct {
    volatile LONG stage,commit_ok,data_ready;
    DWORD child_error,child_stage,child_wait_result,child_wait_observed;
    page_observation before[PAGES],after[STAGES][PAGES];
    ULONG data_read[STAGES],data_written[STAGES];
    unsigned data_valid[STAGES];
} shared_control;

static page_observation observe_page(unsigned char *base,SIZE_T page,unsigned index)
{
    page_observation out;MEMORY_BASIC_INFORMATION mbi;SIZE_T n;
    memset(&out,0,sizeof(out));memset(&mbi,0,sizeof(mbi));SetLastError(0);
    n=VirtualQuery(base+page*index,&mbi,sizeof(mbi));out.returned=(uint64_t)n;
    if(!n){out.error=GetLastError();return out;}
    out.region_size=(uint64_t)mbi.RegionSize;
    out.base_offset=(int64_t)((intptr_t)mbi.BaseAddress-(intptr_t)base);
    out.allocation_base_matches=mbi.AllocationBase==base;
    out.state=mbi.State;out.protect=mbi.Protect;out.allocation_protect=mbi.AllocationProtect;out.type=mbi.Type;
    return out;
}
static void snapshot(unsigned char *base,SIZE_T page,page_observation out[PAGES])
{ unsigned i;for(i=0;i<PAGES;i++)out[i]=observe_page(base,page,i); }
static void emit_pages(const char *role,const char *phase,unsigned stage,const page_observation rows[PAGES])
{
    unsigned i;
    for(i=0;i<PAGES;i++){
        const page_observation *o=&rows[i];
        if(!o->returned)dependent_checks_skipped++;
        printf("{\"kind\":\"memory_page\",\"row\":\"M08\",\"role\":\"%s\",\"phase\":\"%s\",\"stage\":%u,\"page\":%u,\"query_bytes\":%" PRIu64 ",\"error\":%lu,\"base_offset\":%" PRId64 ",\"region_size\":%" PRIu64 ",\"allocation_base_matches\":%u,\"state\":\"0x%08lx\",\"protect\":\"0x%08lx\",\"allocation_protect\":\"0x%08lx\",\"type\":\"0x%08lx\"}\n",
          role,phase,stage,i,o->returned,(unsigned long)o->error,o->base_offset,o->region_size,o->allocation_base_matches,(unsigned long)o->state,(unsigned long)o->protect,(unsigned long)o->allocation_protect,(unsigned long)o->type);
    }
}
static void object_name(wchar_t out[128],const wchar_t *prefix,const wchar_t *suffix)
{ swprintf(out,128,L"%ls_%ls",prefix,suffix); }
static HANDLE open_named_event(const wchar_t *prefix,const wchar_t *suffix,DWORD access)
{ wchar_t name[128];object_name(name,prefix,suffix);return OpenEventW(access,FALSE,name); }
static int memory_child(const wchar_t *prefix)
{
    HANDLE data=NULL,control=NULL,ready=NULL,go=NULL,done=NULL;
    unsigned char *view=NULL;shared_control *ctl=NULL;SYSTEM_INFO si;wchar_t name[128];unsigned stage;int rc=2;
    if(wcslen(prefix)>80 || wcsncmp(prefix,L"Local\\dot0064_",14))return 2;
    GetSystemInfo(&si);
    object_name(name,prefix,L"control");control=OpenFileMappingW(FILE_MAP_WRITE,FALSE,name);if(!control)goto cleanup;
    ctl=(shared_control*)MapViewOfFile(control,FILE_MAP_WRITE,0,0,sizeof(*ctl));if(!ctl)goto cleanup;
    ready=open_named_event(prefix,L"ready",EVENT_MODIFY_STATE);
    if(!ready){ctl->child_error=GetLastError();goto cleanup;}
    go=open_named_event(prefix,L"go",SYNCHRONIZE);
    if(!go){ctl->child_error=GetLastError();goto notify;}
    done=open_named_event(prefix,L"done",EVENT_MODIFY_STATE);
    if(!done){ctl->child_error=GetLastError();goto notify;}
    object_name(name,prefix,L"data");data=OpenFileMappingW(FILE_MAP_WRITE,FALSE,name);
    if(!data){ctl->child_error=GetLastError();goto notify;}
    view=(unsigned char*)MapViewOfFile(data,FILE_MAP_WRITE,0,0,PAGES*(SIZE_T)si.dwPageSize);
    if(!view){ctl->child_error=GetLastError();goto notify;}
    snapshot(view,si.dwPageSize,ctl->before);
notify:
    if(ready && !SetEvent(ready)){ctl->child_error=GetLastError();goto cleanup;}
    if(!view)goto cleanup;
    for(stage=0;stage<STAGES;stage++){
        unsigned index=stage==0?1u:PAGES-1u;page_observation check;ULONG value;
        ctl->child_wait_result=WaitForSingleObject(go,IPC_MS);ctl->child_wait_observed=1;
        if(ctl->child_wait_result!=WAIT_OBJECT_0){ctl->child_error=wait_status_error(ctl->child_wait_result);goto cleanup;}
        if(ctl->stage!=(LONG)stage){ctl->child_error=ERROR_INVALID_DATA;SetEvent(done);goto cleanup;}
        snapshot(view,si.dwPageSize,ctl->after[stage]);check=ctl->after[stage][index];
        if(ctl->data_ready && check.returned && check.state==MEM_COMMIT && !(check.protect&PAGE_GUARD) && (check.protect&0xffu)==PAGE_READWRITE){
            /* Only a committed ordinary data word is accessed. */
            memcpy(&value,view+(SIZE_T)index*si.dwPageSize,sizeof(value));ctl->data_read[stage]=value;
            value=0x34560000u+stage;memcpy(view+(SIZE_T)index*si.dwPageSize,&value,sizeof(value));
            ctl->data_written[stage]=value;ctl->data_valid[stage]=1;
        }
        ctl->child_stage=stage+1;
        if(!SetEvent(done)){ctl->child_error=GetLastError();goto cleanup;}
    }
    rc=0;
cleanup:
    if(view)UnmapViewOfFile(view);
    if(ctl)UnmapViewOfFile(ctl);
    if(data)CloseHandle(data);
    if(control)CloseHandle(control);
    if(ready)CloseHandle(ready);
    if(go)CloseHandle(go);
    if(done)CloseHandle(done);
    return rc;
}
static HANDLE new_mapping(const wchar_t *name,DWORD protect,DWORD bytes)
{
    HANDLE h;SetLastError(0);h=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,protect,0,bytes,name);
    if(h && GetLastError()==ERROR_ALREADY_EXISTS){CloseHandle(h);SetLastError(ERROR_ALREADY_EXISTS);return NULL;}
    return h;
}
static HANDLE new_event(const wchar_t *prefix,const wchar_t *suffix)
{
    wchar_t name[128];HANDLE h;object_name(name,prefix,suffix);SetLastError(0);
    h=CreateEventW(NULL,FALSE,FALSE,name);
    if(h && GetLastError()==ERROR_ALREADY_EXISTS){CloseHandle(h);SetLastError(ERROR_ALREADY_EXISTS);return NULL;}
    return h;
}
static void memory_probe(void)
{
    SYSTEM_INFO si;HANDLE data=NULL,control=NULL,ready=NULL,go=NULL,done=NULL;
    unsigned char *a=NULL,*b=NULL;shared_control *ctl=NULL;PROCESS_INFORMATION pi;STARTUPINFOW startup;
    static wchar_t exe[32768],cmd[33000];wchar_t prefix[96],name[128];page_observation local[PAGES];unsigned stage;DWORD count;int child_started=0,child_joined=0;
    memset(&pi,0,sizeof(pi));memset(&startup,0,sizeof(startup));startup.cb=sizeof(startup);GetSystemInfo(&si);
    swprintf(prefix,ARRAY_COUNT(prefix),L"Local\\dot0064_%08lx_%016llx",(unsigned long)GetCurrentProcessId(),(unsigned long long)GetTickCount64());
    object_name(name,prefix,L"data");data=new_mapping(name,PAGE_READWRITE|SEC_RESERVE,PAGES*si.dwPageSize);
    if(!data){error_row("create_reserved_data_mapping",GetLastError());goto cleanup;}
    object_name(name,prefix,L"control");control=new_mapping(name,PAGE_READWRITE,(DWORD)sizeof(shared_control));
    if(!control){error_row("create_control_mapping",GetLastError());goto cleanup;}
    ctl=(shared_control*)MapViewOfFile(control,FILE_MAP_WRITE,0,0,sizeof(*ctl));
    if(!ctl){error_row("map_control",GetLastError());goto cleanup;}memset(ctl,0,sizeof(*ctl));
    a=(unsigned char*)MapViewOfFile(data,FILE_MAP_WRITE,0,0,PAGES*(SIZE_T)si.dwPageSize);
    if(!a){error_row("map_data_a",GetLastError());goto cleanup;}
    b=(unsigned char*)MapViewOfFile(data,FILE_MAP_WRITE,0,0,PAGES*(SIZE_T)si.dwPageSize);
    if(!b){error_row("map_data_b",GetLastError());goto cleanup;}
    ready=new_event(prefix,L"ready");if(!ready){error_row("create_ready_event",GetLastError());goto cleanup;}
    go=new_event(prefix,L"go");if(!go){error_row("create_go_event",GetLastError());goto cleanup;}
    done=new_event(prefix,L"done");if(!done){error_row("create_done_event",GetLastError());goto cleanup;}
    count=GetModuleFileNameW(NULL,exe,(DWORD)ARRAY_COUNT(exe));
    if(!count || count>=ARRAY_COUNT(exe)){error_row("module_path",ERROR_INSUFFICIENT_BUFFER);goto cleanup;}
    swprintf(cmd,ARRAY_COUNT(cmd),L"\"%ls\" --memory-child %ls",exe,prefix);
    if(!CreateProcessW(exe,cmd,NULL,NULL,FALSE,0,NULL,NULL,&startup,&pi)){error_row("create_cooperative_child",GetLastError());goto cleanup;}
    child_started=1;CloseHandle(pi.hThread);pi.hThread=NULL;
    if(!parent_wait(ready,"wait_child_ready",IPC_MS))goto cleanup;
    if(ctl->child_error){error_row("child_initialization",ctl->child_error);goto cleanup;}
    printf("{\"kind\":\"memory_setup\",\"row\":\"M08\",\"pages\":%u,\"page_bytes\":%lu,\"distinct_parent_views\":%u}\n",PAGES,(unsigned long)si.dwPageSize,a!=b);
    snapshot(a,si.dwPageSize,local);emit_pages("parent_a","before",0,local);
    snapshot(b,si.dwPageSize,local);emit_pages("parent_b","before",0,local);emit_pages("child","before",0,ctl->before);
    for(stage=0;stage<STAGES;stage++){
        unsigned index=stage==0?1u:PAGES-1u;void *p;DWORD commit_error=0;
        DWORD requested_protect=stage==0?PAGE_READONLY:PAGE_READWRITE;
        ULONG pattern=0x12340000u+stage,seen=0;unsigned read_valid=0;page_observation check_b;
        SetLastError(0);p=VirtualAlloc(a+(SIZE_T)index*si.dwPageSize,si.dwPageSize,MEM_COMMIT,requested_protect);
        if(!p)commit_error=GetLastError();
        ctl->commit_ok=p==a+(SIZE_T)index*si.dwPageSize;ctl->data_ready=0;
        printf("{\"kind\":\"memory_commit\",\"stage\":%u,\"page\":%u,\"requested_protect\":\"0x%08lx\",\"returned_requested_address\":%u,\"commit_error\":%lu}\n",stage,index,(unsigned long)requested_protect,ctl->commit_ok?1u:0u,(unsigned long)commit_error);
        snapshot(a,si.dwPageSize,local);emit_pages("parent_a","after_commit",stage,local);
        snapshot(b,si.dwPageSize,local);emit_pages("parent_b","after_commit",stage,local);check_b=local[index];
        /* Commit protection applies to A; only B is used for the data write. */
        if(ctl->commit_ok && check_b.returned && check_b.state==MEM_COMMIT && !(check_b.protect&PAGE_GUARD) && (check_b.protect&0xffu)==PAGE_READWRITE){
            memcpy(b+(SIZE_T)index*si.dwPageSize,&pattern,sizeof(pattern));ctl->data_ready=1;
        }
        else dependent_checks_skipped++;
        ctl->stage=(LONG)stage;if(!SetEvent(go)){error_row("signal_child_stage",GetLastError());goto cleanup;}
        if(!parent_wait(done,"wait_child_stage",IPC_MS))goto cleanup;
        if(ctl->child_error || ctl->child_stage!=stage+1){error_row("child_stage",ctl->child_error?ctl->child_error:ERROR_INVALID_DATA);goto cleanup;}
        emit_pages("child","after_commit",stage,ctl->after[stage]);
        local[index]=observe_page(b,si.dwPageSize,index);
        if(ctl->data_valid[stage] && local[index].returned && local[index].state==MEM_COMMIT && !(local[index].protect&PAGE_GUARD) && (local[index].protect&0xffu)==PAGE_READWRITE){memcpy(&seen,b+(SIZE_T)index*si.dwPageSize,sizeof(seen));read_valid=1;}
        if(!ctl->data_valid[stage] || !read_valid)dependent_checks_skipped++;
        printf("{\"kind\":\"memory_data\",\"stage\":%u,\"parent_write_valid\":%u,\"parent_written\":\"0x%08lx\",\"child_data_valid\":%u,\"child_read\":\"0x%08lx\",\"child_written\":\"0x%08lx\",\"parent_read_valid\":%u,\"parent_read\":\"0x%08lx\"}\n",stage,ctl->data_ready?1u:0u,(unsigned long)pattern,ctl->data_valid[stage],(unsigned long)ctl->data_read[stage],(unsigned long)ctl->data_written[stage],read_valid,(unsigned long)seen);
    }
cleanup:
    /* Child waits are finite. No thread suspension/context changes/forced kill. */
    if(child_started){
        DWORD result=WaitForSingleObject(pi.hProcess,IPC_MS+1000),code=0;unsigned exit_valid=0;
        if(result!=WAIT_OBJECT_0)wait_failure("join_child",result,wait_status_error(result));
        child_joined=result==WAIT_OBJECT_0;
        if(child_joined){exit_valid=GetExitCodeProcess(pi.hProcess,&code)?1u:0u;if(!exit_valid)error_row("child_exit_code",GetLastError());}
        printf("{\"kind\":\"memory_child_exit\",\"joined\":%u,\"wait_result\":\"0x%08lx\",\"exit_code_valid\":%u,\"exit_code\":%lu,\"child_status_valid\":%u,\"child_error\":%lu,\"child_stage\":%lu,\"child_wait_observed\":%lu,\"child_wait_result\":\"0x%08lx\"}\n",child_joined?1u:0u,(unsigned long)result,exit_valid,(unsigned long)code,child_joined&&ctl?1u:0u,(unsigned long)(child_joined&&ctl?ctl->child_error:0),(unsigned long)(child_joined&&ctl?ctl->child_stage:0),(unsigned long)(child_joined&&ctl?ctl->child_wait_observed:0),(unsigned long)(child_joined&&ctl?ctl->child_wait_result:0));
        if(exit_valid && code)infrastructure_errors++;
        CloseHandle(pi.hProcess);
    }
    /* Separate mappings remain valid in the child until it closes them. */
    if(a)UnmapViewOfFile(a);
    if(b)UnmapViewOfFile(b);
    if(ctl)UnmapViewOfFile(ctl);
    if(data)CloseHandle(data);
    if(control)CloseHandle(control);
    if(ready)CloseHandle(ready);
    if(go)CloseHandle(go);
    if(done)CloseHandle(done);
}

typedef struct {
    uint64_t qpc0,qpc1,tsc0,tsc1,tick0,tick1,usd_tick,usd_interrupt,usd_system;
    uint64_t interrupt_time,interrupt0,unbiased_time,unbiased0,usd_interrupt_bias,usd_qpc_frequency,usd_qpc_bias;
    unsigned cpu0,cpu1,group0,group1,usd_stable,flags,shift;DWORD qpc0_ok,qpc1_ok,unbiased_ok,unbiased0_ok;
} clock_sample;
typedef struct { unsigned id;HANDLE start;DWORD wait_result,wait_error;clock_sample samples[SAMPLES]; } clock_worker;
static clock_worker workers[THREADS];
static interrupt_fn query_interrupt=NULL;
static unbiased_fn query_unbiased=NULL;
static int usd_readable;
static ULONG read_usd32(size_t offset){return *(volatile const ULONG*)(USD_BASE+offset);}
static uint64_t read_usd64(size_t offset){return *(volatile const uint64_t*)(USD_BASE+offset);}
static unsigned read_ksystem(size_t offset,uint64_t *value)
{
    unsigned n;ULONG h1,h2,lo;
    for(n=0;n<64;n++){h1=read_usd32(offset+4);lo=read_usd32(offset);h2=read_usd32(offset+8);if(h1==h2){*value=((uint64_t)h1<<32)|lo;return 1;}}
    *value=0;return 0;
}
static DWORD WINAPI clock_thread(void *arg)
{
    clock_worker *w=(clock_worker*)arg;unsigned i;LARGE_INTEGER q;PROCESSOR_NUMBER cpu;
    w->wait_result=WaitForSingleObject(w->start,IPC_MS);
    w->wait_error=w->wait_result==WAIT_OBJECT_0?0:wait_status_error(w->wait_result);
    if(w->wait_result!=WAIT_OBJECT_0)return 2;
    for(i=0;i<SAMPLES;i++){
        clock_sample *s=&w->samples[i];GetCurrentProcessorNumberEx(&cpu);s->cpu0=cpu.Number;s->group0=cpu.Group;s->tsc0=tsc_available?tsc_read():0;
        q.QuadPart=0;s->qpc0_ok=QueryPerformanceCounter(&q);s->qpc0=(uint64_t)q.QuadPart;s->tick0=GetTickCount64();
        if(query_interrupt)query_interrupt(&s->interrupt0);
        if(query_unbiased)s->unbiased0_ok=query_unbiased(&s->unbiased0);
        if(usd_readable){uint64_t raw_tick=0;unsigned ok0,ok1,ok2;
            ok0=read_ksystem(0x320,&raw_tick);ok1=read_ksystem(0x008,&s->usd_interrupt);ok2=read_ksystem(0x014,&s->usd_system);
            /* Preserve raw TickCount plus multiplier separately in metadata. */
            s->usd_tick=raw_tick;s->usd_stable=ok0|(ok1<<1)|(ok2<<2);
            s->usd_interrupt_bias=read_usd64(0x3b0);s->usd_qpc_frequency=read_usd64(0x300);s->usd_qpc_bias=read_usd64(0x3b8);
            s->flags=*(volatile const BYTE*)(USD_BASE+0x3c6);s->shift=*(volatile const BYTE*)(USD_BASE+0x3c7);
        }
        if(query_interrupt)query_interrupt(&s->interrupt_time);
        if(query_unbiased)s->unbiased_ok=query_unbiased(&s->unbiased_time);
        s->tick1=GetTickCount64();q.QuadPart=0;s->qpc1_ok=QueryPerformanceCounter(&q);s->qpc1=(uint64_t)q.QuadPart;
        s->tsc1=tsc_available?tsc_read():0;GetCurrentProcessorNumberEx(&cpu);s->cpu1=cpu.Number;s->group1=cpu.Group;Sleep(1);
    }
    return 0;
}
static void clock_probe(void)
{
    HANDLE threads[THREADS]={0},start=NULL;MEMORY_BASIC_INFORMATION mbi;LARGE_INTEGER frequency;unsigned i,j;DWORD joined;BOOL freq_ok;
    memset(&mbi,0,sizeof(mbi));usd_readable=VirtualQuery((const void*)USD_BASE,&mbi,sizeof(mbi))!=0 && mbi.State==MEM_COMMIT && !(mbi.Protect&(PAGE_NOACCESS|PAGE_GUARD)) && (uintptr_t)mbi.BaseAddress<=USD_BASE && mbi.RegionSize>=USD_BASE-(uintptr_t)mbi.BaseAddress+0x3c8;
    resolve(GetModuleHandleW(L"kernel32.dll"),"QueryInterruptTime",&query_interrupt,sizeof(query_interrupt));
    resolve(GetModuleHandleW(L"kernel32.dll"),"QueryUnbiasedInterruptTime",&query_unbiased,sizeof(query_unbiased));
    frequency.QuadPart=0;freq_ok=QueryPerformanceFrequency(&frequency);
    printf("{\"kind\":\"clock_setup\",\"rows\":\"T03/T04-partial\",\"threads\":%u,\"samples_per_thread\":%u,\"qpf_ok\":%u,\"qpf\":\"0x%016" PRIx64 "\",\"usd_readable\":%u,\"tick_multiplier\":%lu,\"interrupt_api\":%u,\"unbiased_api\":%u,\"tsc_advertised\":%u,\"tsc_sequence\":\"LFENCE_RDTSC_LFENCE\",\"affinity_changed\":false}\n",THREADS,SAMPLES,freq_ok?1u:0u,(uint64_t)frequency.QuadPart,usd_readable?1u:0u,(unsigned long)(usd_readable?read_usd32(4):0),query_interrupt?1u:0u,query_unbiased?1u:0u,tsc_available);
    if(!usd_readable || !query_interrupt || !query_unbiased || !tsc_available || !freq_ok)dependent_checks_skipped++;
    start=CreateEventW(NULL,TRUE,FALSE,NULL);if(!start){error_row("clock_start_event",GetLastError());return;}
    for(i=0;i<THREADS;i++){
        workers[i].id=i;workers[i].start=start;
        threads[i]=CreateThread(NULL,0,clock_thread,&workers[i],0,NULL);
        if(!threads[i]){error_row("clock_CreateThread",GetLastError());SetEvent(start);goto join_partial;}
    }
    if(!SetEvent(start)){error_row("clock_SetEvent",GetLastError());goto join_partial;}
    joined=WaitForMultipleObjects(THREADS,threads,TRUE,IPC_MS+1000);
    if(joined!=WAIT_OBJECT_0){wait_failure("clock_join",joined,wait_status_error(joined));goto no_read;}
    for(i=0;i<THREADS;i++){
        DWORD exit_code=0;if(!GetExitCodeThread(threads[i],&exit_code)){error_row("clock_exit_code",GetLastError());continue;}
        if(workers[i].wait_result!=WAIT_OBJECT_0)wait_failure("clock_worker_start",workers[i].wait_result,workers[i].wait_error);
        if(exit_code || workers[i].wait_result!=WAIT_OBJECT_0){
            printf("{\"kind\":\"clock_worker_exit\",\"thread\":%u,\"exit_code\":%lu}\n",i,(unsigned long)exit_code);
            if(workers[i].wait_result==WAIT_OBJECT_0)infrastructure_errors++;
            continue;
        }
        for(j=0;j<SAMPLES;j++){
            clock_sample *s=&workers[i].samples[j];
            if(!s->qpc0_ok || !s->qpc1_ok || (usd_readable && s->usd_stable!=7) || (query_unbiased && (!s->unbiased_ok || !s->unbiased0_ok)))dependent_checks_skipped++;
            printf("{\"kind\":\"clock_sample\",\"thread\":%u,\"index\":%u,\"cpu_before\":%u,\"cpu_after\":%u,\"group_before\":%u,\"group_after\":%u,\"qpc0_ok\":%lu,\"qpc1_ok\":%lu,\"qpc0\":\"0x%016" PRIx64 "\",\"qpc1\":\"0x%016" PRIx64 "\",\"tsc0\":\"0x%016" PRIx64 "\",\"tsc1\":\"0x%016" PRIx64 "\",\"tick0\":\"0x%016" PRIx64 "\",\"tick1\":\"0x%016" PRIx64 "\",\"usd_tick_raw\":\"0x%016" PRIx64 "\",\"usd_interrupt\":\"0x%016" PRIx64 "\",\"usd_system\":\"0x%016" PRIx64 "\",\"usd_stable_mask\":%u,\"interrupt0\":\"0x%016" PRIx64 "\",\"interrupt\":\"0x%016" PRIx64 "\",\"unbiased0_ok\":%lu,\"unbiased0\":\"0x%016" PRIx64 "\",\"usd_interrupt_bias\":\"0x%016" PRIx64 "\",\"unbiased_ok\":%lu,\"unbiased\":\"0x%016" PRIx64 "\",\"usd_qpc_frequency\":\"0x%016" PRIx64 "\",\"usd_qpc_bias\":\"0x%016" PRIx64 "\",\"usd_qpc_flags\":%u,\"usd_qpc_shift\":%u}\n",
              i,j,s->cpu0,s->cpu1,s->group0,s->group1,(unsigned long)s->qpc0_ok,(unsigned long)s->qpc1_ok,s->qpc0,s->qpc1,s->tsc0,s->tsc1,s->tick0,s->tick1,s->usd_tick,s->usd_interrupt,s->usd_system,s->usd_stable,s->interrupt0,(uint64_t)s->interrupt_time,(unsigned long)s->unbiased0_ok,s->unbiased0,s->usd_interrupt_bias,(unsigned long)s->unbiased_ok,s->unbiased_time,s->usd_qpc_frequency,s->usd_qpc_bias,s->flags,s->shift);
        }
    }
    goto no_read;
join_partial:
    /* Static worker storage remains live; never read an unjoined worker. */
    for(i=0;i<THREADS;i++)if(threads[i])WaitForSingleObject(threads[i],IPC_MS+1000);
no_read:
    for(i=0;i<THREADS;i++)if(threads[i])CloseHandle(threads[i]);
    /* If a worker timed out, keep its event alive until process exit. */
    if(infrastructure_errors==0)CloseHandle(start);
}
int wmain(int argc,wchar_t **argv)
{
    if(argc==3 && !wcscmp(argv[1],L"--memory-child"))return memory_child(argv[2]);
    if(argc!=1){fprintf(stderr,"usage: probe.exe (internal child mode is launcher-owned)\n");return 2;}
    if(setvbuf(stdout,NULL,_IONBF,0)){fputs("stdout buffering setup failed\n",stderr);return 2;}
    emit_meta();process_queries();memory_probe();clock_probe();
    printf("{\"kind\":\"end\",\"completed\":true,\"coverage_complete\":%s,\"infrastructure_errors\":%d,\"dependent_checks_skipped\":%u,\"observed_api_values_are_not_pass_fail\":true}\n",!infrastructure_errors && !dependent_checks_skipped?"true":"false",infrastructure_errors,dependent_checks_skipped);
    return infrastructure_errors || dependent_checks_skipped?2:0;
}
