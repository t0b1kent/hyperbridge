/* Windows x64 visible-memory probe. C11; no non-Win32 runtime dependencies.
   Host build supports list only. Runtime uses real compiler SEH, not VEH/longjmp. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#if !defined(_M_X64) && !defined(__x86_64__)
#error This probe requires the x64 Windows ABI.
#endif
#if !defined(_MSC_VER) && !defined(__clang__)
#error Use MSVC or llvm-mingw (Clang). Traditional GCC MinGW driver is not llvm-mingw.
#endif
#endif
#define PAGE_BYTES 4096u
#define REGION_BYTES 196608u
#define TARGET_BLOCK 65536u
#define TOTAL_CELLS 19008u
static const char *alloc_names[]={"alloc","partial","watch","section","copy"};
static const unsigned protections[]={1,2,4,16,32,64,8,128};
static const char *access_names[]={"read","write1","write2","write4","write8","cross_write","execute","none"};
static const char *action_names[]={"protect_all","protect_page","protect_cross4","protect_cross16","protect_cross64","protect_unaligned","decommit","recommit","reset","query"};
typedef struct { unsigned id,family,allocation,initial,guard,position,neighbors,action,access; } Cell;
static uint64_t checksum=UINT64_C(14695981039346656037);
static unsigned emitted;
static int hashing;
static void out(const char *fmt,...) {
    char b[8192]; int n; va_list ap; va_start(ap,fmt); n=vsnprintf(b,sizeof b,fmt,ap); va_end(ap);
    if(n<0 || (size_t)n>=sizeof b) { fputs("format overflow\n",stderr); exit(3); }
    if(hashing) { int i; for(i=0;i<n;i++) {checksum^=(unsigned char)b[i];checksum*=UINT64_C(1099511628211);} }
    if(fwrite(b,1,(size_t)n,stdout)!=(size_t)n) exit(3);
}
static void axes(const Cell *c) {
    out("{\"family\":\"%s\",\"allocation\":\"%s\",\"initial\":%u,\"guard\":%u,\"position\":%u,\"neighbors\":%u,\"action\":\"%s\",\"access\":\"%s\"}",c->family?"action":"access",alloc_names[c->allocation],c->initial,c->guard,c->position,c->neighbors,action_names[c->action],access_names[c->access]);
}
static int parse_uint(const char *s,unsigned *v) { char *e; unsigned long n; if(!*s || *s=='-')return 0; errno=0;n=strtoul(s,&e,10); if(errno||*e||n>UINT32_MAX)return 0;*v=(unsigned)n;return 1; }
#ifdef _WIN32
typedef struct { DWORD code; uintptr_t address,pc; ULONG_PTR access,information,parameters[15]; unsigned count; } Fault;
static LONG record_fault(EXCEPTION_POINTERS *e,Fault *f) {
    EXCEPTION_RECORD *r=e->ExceptionRecord; f->count++;f->code=r->ExceptionCode;
    f->address=r->NumberParameters>1?(uintptr_t)r->ExceptionInformation[1]:0;
    f->access=r->NumberParameters>0?r->ExceptionInformation[0]:0;
    {unsigned i;f->pc=(uintptr_t)r->ExceptionAddress;f->information=r->NumberParameters;for(i=0;i<r->NumberParameters && i<15;i++)f->parameters[i]=r->ExceptionInformation[i];}return EXCEPTION_EXECUTE_HANDLER;
}
/* noinline avoids compilers moving faulting operations outside the SEH region. */
#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif
#pragma pack(push,1)
typedef struct { uint64_t value; } Unaligned64;
#pragma pack(pop)
static NOINLINE void access_leaf(unsigned char *p,unsigned access) {
    volatile unsigned char sink=0;
    switch(access) {
        case 0:sink=*(volatile unsigned char *)p;break;
        case 1:*(volatile uint8_t *)p=UINT8_C(0x6b);break;
        case 2:*(volatile uint16_t *)p=UINT16_C(0x6b5a);break;
        case 3:*(volatile uint32_t *)p=UINT32_C(0x6b5a4938);break;
        case 4:*(volatile uint64_t *)p=UINT64_C(0x6b5a4938271605f4);break;
        case 5:((volatile Unaligned64 *)(void *)p)->value=UINT64_C(0x6b5a4938271605f4);break;
        case 6:((void (*)(void))(uintptr_t)p)();break;
        default:break;
    }
    (void)sink;
}
static NOINLINE void access_once(unsigned char *p,unsigned access,Fault *f) {
    __try { access_leaf(p,access); }
    __except(record_fault(GetExceptionInformation(),f)) { }
}
static NOINLINE void snapshot_leaf(unsigned char *to,const unsigned char *from,unsigned n) {unsigned i;for(i=0;i<n;i++)to[i]=*(const volatile unsigned char *)(from+i);}
static NOINLINE int snapshot(unsigned char *to,const unsigned char *from,unsigned n,Fault *f) {
    __try { snapshot_leaf(to,from,n); }
    __except(record_fault(GetExceptionInformation(),f)) { return 0; }
    return 1;
}
static int64_t rel(uintptr_t p,const unsigned char *base) { return (int64_t)(p-(uintptr_t)base); }
static void queries(unsigned char *base,unsigned lo,unsigned hi) {
    unsigned o;int first=1;out("[");
    for(o=lo;o<hi;o+=PAGE_BYTES) {
        MEMORY_BASIC_INFORMATION m;SIZE_T n;DWORD qe;memset(&m,0,sizeof m);SetLastError(0xcccccccc);n=VirtualQuery(base+o,&m,sizeof m);qe=GetLastError();
        if(!first)out(",");first=0;
        out("{\"offset\":%u,\"return_size\":%llu,\"base\":%lld,\"allocation_base\":%lld,\"allocation_protect\":%lu,\"region_size\":%llu,\"state\":%lu,\"protect\":%lu,\"type\":%lu,\"defined\":[",o,(unsigned long long)n,(long long)rel((uintptr_t)m.BaseAddress,base),(long long)rel((uintptr_t)m.AllocationBase,base),(unsigned long)m.AllocationProtect,(unsigned long long)m.RegionSize,(unsigned long)m.State,(unsigned long)m.Protect,(unsigned long)m.Type);
        if(n==sizeof m) {out("\"base\",\"region_size\",\"state\"");if(m.State!=MEM_FREE)out(",\"allocation_base\",\"allocation_protect\",\"type\"");if(m.State==MEM_COMMIT)out(",\"protect\"");}
        out("],\"last_error\":%lu,\"last_error_defined\":%s}",(unsigned long)qe,n?"false":"true");
    }out("]");
}
static void watch(unsigned char *base,unsigned allocation) {
    PVOID pages[48];ULONG_PTR count=48;ULONG gran=0;UINT r;DWORD we;unsigned i;
    if(allocation!=2){out("null");return;}
    memset(pages,0,sizeof pages);SetLastError(0xcccccccc);r=GetWriteWatch(0,base,REGION_BYTES,pages,&count,&gran);we=GetLastError();
    /* Sort normalized offsets: API ordering is not part of the comparison. */
    if(!r && count<=48) { ULONG_PTR a,b;for(a=1;a<count;a++)for(b=a;b && (uintptr_t)pages[b-1]>(uintptr_t)pages[b];b--){PVOID t=pages[b];pages[b]=pages[b-1];pages[b-1]=t;} }
    out("{\"return_code\":%u,\"count\":%llu,\"granularity\":%lu,\"pages\":[",r,(unsigned long long)count,(unsigned long)gran);
    if(!r && count<=48)for(i=0;i<(unsigned)count;i++)out("%s%lld",i?",":"",(long long)rel((uintptr_t)pages[i],base));
    out("],\"last_error\":%lu,\"last_error_defined\":false}",(unsigned long)we);
}
static void byte_array(const unsigned char *p,unsigned n) {unsigned i;out("[");for(i=0;i<n;i++)out("%s%u",i?",":"",(unsigned)p[i]);out("]");}
static void execute_cell(const Cell *c) {
    unsigned char *base=NULL,*peer=NULL;HANDLE section=NULL;
    unsigned target=TARGET_BLOCK+c->position*PAGE_BYTES,at=target,lo=TARGET_BLOCK,hi=TARGET_BLOCK+65536;
    unsigned char before[16],after[16],peer_before[16],peer_after[16];
    unsigned capture=16,attempt=0;DWORD setup_error=0,tmp=0,old=0xcccccccc,err=0;const char *setup_stage="ready";int64_t setup_result=1;int setup_ok=1,ok=1,old_defined=0,error_defined=0,after_ok=0,peer_after_ok=0;
    Fault fault={0},inspection={0};int64_t return_value=1;const char *return_kind="bool32";unsigned neighbor_page,neighbor_bit=0;
    DWORD initial=c->initial|(c->guard?PAGE_GUARD:0);SIZE_T size=PAGE_BYTES;unsigned start=target;
    static const uintptr_t candidates[]={UINT64_C(0x0000011000000000),UINT64_C(0x0000022000000000),UINT64_C(0x0000033000000000),UINT64_C(0x0000044000000000),UINT64_C(0x0000055000000000),UINT64_C(0x0000066000000000),UINT64_C(0x0000077000000000),UINT64_C(0x0000088000000000)};
        if(c->family) switch(c->action) {
            case 0:start=0;size=REGION_BYTES;lo=0;hi=REGION_BYTES;break;
            case 2:start=target+PAGE_BYTES-1;size=2;break;
            case 3:start=TARGET_BLOCK+16383;size=2;break;
            case 4:start=TARGET_BLOCK-1;size=2;lo=0;break;
            case 5:start=target+1;size=PAGE_BYTES;break;
            default:break;
        }
    if(c->family && c->action>=2 && c->action<=5)at=start;
    memset(before,0,sizeof before);memset(after,0,sizeof after);memset(peer_before,0,sizeof peer_before);memset(peer_after,0,sizeof peer_after);
    if(c->allocation>=3) {section=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_EXECUTE_READWRITE,0,REGION_BYTES,NULL);if(!section){setup_ok=0;setup_error=GetLastError();setup_stage="create_section";setup_result=0;}}
    for(attempt=0;setup_ok && attempt<sizeof candidates/sizeof candidates[0];attempt++) {
        if(c->allocation>=3) {
            /* Reserve/release verifies the same explicit VA path as private allocation. */
            PVOID reservation=VirtualAlloc((void *)candidates[attempt],REGION_BYTES,MEM_RESERVE,PAGE_NOACCESS);
            if(reservation){VirtualFree(reservation,0,MEM_RELEASE);base=(unsigned char *)MapViewOfFileEx(section,(c->allocation==4?FILE_MAP_COPY:FILE_MAP_ALL_ACCESS)|FILE_MAP_EXECUTE,0,0,REGION_BYTES,(void *)candidates[attempt]);}
        } else base=(unsigned char *)VirtualAlloc((void *)candidates[attempt],REGION_BYTES,MEM_RESERVE|(c->allocation==1?0:MEM_COMMIT)|(c->allocation==2?MEM_WRITE_WATCH:0),PAGE_EXECUTE_READWRITE);
        if(base){setup_error=0;break;}
        setup_error=GetLastError();
        out("ALLOC {\"cell\":%u,\"candidate\":%u,\"base\":\"0x%llx\",\"ok\":false,\"last_error\":%lu}\n",c->id,attempt,(unsigned long long)candidates[attempt],(unsigned long)setup_error);
    }
    if(!base && setup_ok){setup_ok=0;setup_stage=c->allocation>=3?"map_primary":"allocate";setup_result=0;}
    if(setup_ok && c->allocation==1 && !VirtualAlloc(base+TARGET_BLOCK-PAGE_BYTES,65536+2*PAGE_BYTES,MEM_COMMIT,PAGE_EXECUTE_READWRITE)){setup_ok=0;setup_error=GetLastError();setup_stage="commit_partial";setup_result=0;}
    if(setup_ok && c->allocation>=3){peer=(unsigned char *)MapViewOfFile(section,FILE_MAP_ALL_ACCESS|FILE_MAP_EXECUTE,0,0,REGION_BYTES);if(!peer){setup_ok=0;setup_error=GetLastError();setup_stage="map_peer";setup_result=0;}}
    if(setup_ok) {
        unsigned char *init=peer?peer:base;unsigned initlo=c->allocation==1?TARGET_BLOCK-PAGE_BYTES:0,initlen=c->allocation==1?65536+2*PAGE_BYTES:REGION_BYTES;
        memset(init+initlo,0x31,initlen);init[target]=0xc3;
        if(!FlushInstructionCache(GetCurrentProcess(),base+target,1)){setup_ok=0;setup_error=GetLastError();setup_stage="flush_instruction_cache";setup_result=0;}
        if(c->access==5)at=target+PAGE_BYTES-4;
        memcpy(before,init+at,capture);if(peer)memcpy(peer_before,peer+at,capture);
        for(neighbor_page=0;setup_ok && neighbor_page<4;neighbor_page++)if(neighbor_page!=c->position){
            DWORD np=(c->neighbors&(1u<<neighbor_bit))?PAGE_EXECUTE_READWRITE:PAGE_NOACCESS;neighbor_bit++;
            if(!VirtualProtect(base+TARGET_BLOCK+neighbor_page*PAGE_BYTES,PAGE_BYTES,np,&tmp)){setup_ok=0;setup_error=GetLastError();setup_stage="neighbor_protect";setup_result=0;}
        }
        if(setup_ok && !VirtualProtect(base+target,PAGE_BYTES,initial,&tmp)){setup_ok=0;setup_error=GetLastError();setup_stage="initial_protect";setup_result=0;}
        if(setup_ok && c->allocation==2) {UINT r=ResetWriteWatch(base,REGION_BYTES);if(r){setup_ok=0;setup_error=r;setup_stage="reset_baseline";setup_result=r;}else if(c->family && c->action==8){base[target]=0x42;memcpy(before,base+at,capture);}}
    }
    out("ALLOC {\"cell\":%u,\"candidate\":%u,\"base\":\"0x%llx\",\"peer\":\"0x%llx\",\"ok\":%s}\n",c->id,attempt,(unsigned long long)(uintptr_t)base,(unsigned long long)(uintptr_t)peer,setup_ok?"true":"false");
    hashing=1;out("CELL %u ",c->id);axes(c);out(" => {");
    out("\"setup\":{\"ok\":%s,\"error\":%lu,\"stage\":\"%s\",\"return_value\":%lld}",setup_ok?"true":"false",(unsigned long)setup_error,setup_stage,(long long)setup_result);
    if(setup_ok) {
        out(",\"range\":{\"offset\":%u,\"size\":%llu},\"query_before\":",start,(unsigned long long)size);queries(base,lo,hi);out(",\"watch_before\":");watch(base,c->allocation);
        SetLastError(0xcccccccc);
        if(c->family && c->action<6) {return_value=VirtualProtect(base+start,size,PAGE_READONLY,&old);ok=return_value!=0;err=GetLastError();old_defined=ok;error_defined=!ok;}
        else if(c->family && c->action==6){return_value=VirtualFree(base+target,PAGE_BYTES,MEM_DECOMMIT);ok=return_value!=0;err=GetLastError();error_defined=!ok;}
        else if(c->family && c->action==7) {BOOL d=VirtualFree(base+target,PAGE_BYTES,MEM_DECOMMIT);DWORD de=GetLastError();PVOID r;SetLastError(0xcccccccc);r=VirtualAlloc(base+target,PAGE_BYTES,MEM_COMMIT,PAGE_READWRITE);ok=r!=NULL;return_value=r?rel((uintptr_t)r,base):0;return_kind="relative_pointer";err=GetLastError();error_defined=!ok;out(",\"recommit_prepare\":{\"ok\":%s,\"last_error\":%lu,\"last_error_defined\":%s}",d?"true":"false",(unsigned long)de,d?"false":"true");}
        else if(c->family && c->action==8){UINT r=ResetWriteWatch(base,REGION_BYTES);ok=r==0;return_value=r;return_kind="status";err=GetLastError();out(",\"reset_return\":%u",r);}
        else { MEMORY_BASIC_INFORMATION m;return_value=(int64_t)VirtualQuery(base+target,&m,sizeof m);return_kind="size";ok=return_value!=0;err=GetLastError();error_defined=!ok; }
        out(",\"result\":{\"return_value\":%lld,\"return_kind\":\"%s\",\"ok\":%s,\"last_error\":%lu,\"last_error_defined\":%s,\"old_protect\":%lu,\"old_protect_defined\":%s}",(long long)return_value,return_kind,ok?"true":"false",(unsigned long)err,error_defined?"true":"false",(unsigned long)old,old_defined?"true":"false");
        out(",\"query_action\":");queries(base,lo,hi);out(",\"watch_action\":");watch(base,c->allocation);
        access_once(base+at,c->access,&fault);
        out(",\"exception\":{\"code\":%lu,\"address\":",(unsigned long)fault.code);
        if(fault.information>1){if(fault.address>=(uintptr_t)base && fault.address<(uintptr_t)base+REGION_BYTES)out("%lld",(long long)rel(fault.address,base));else out("%llu",(unsigned long long)fault.address);}else out("null");
        out(",\"address_region\":\"%s\"",(fault.address>=(uintptr_t)base && fault.address<(uintptr_t)base+REGION_BYTES)?"primary":"external");
        out(",\"access\":%llu,\"information\":%llu,\"count\":%u,\"instruction_site\":\"%s\",\"parameters\":[",(unsigned long long)fault.access,(unsigned long long)fault.information,fault.count,(fault.pc>=(uintptr_t)base && fault.pc<(uintptr_t)base+REGION_BYTES)?"target_code":"access_leaf");
        {unsigned fi;for(fi=0;fi<fault.information && fi<15;fi++){if(fi)out(",");if(fi==1 && fault.parameters[fi]>=(uintptr_t)base && fault.parameters[fi]<(uintptr_t)base+REGION_BYTES)out("%lld",(long long)rel((uintptr_t)fault.parameters[fi],base));else out("%llu",(unsigned long long)fault.parameters[fi]);}}out("]}");
        out(",\"query\":");queries(base,lo,hi);out(",\"watch\":");watch(base,c->allocation);
        /* Intrusive inspection ONLY after query/watch: record whether readable restoration succeeded. */
        {BOOL restored;DWORD re;SetLastError(0xcccccccc);restored=VirtualProtect(base+(at&~(PAGE_BYTES-1)),((at&(PAGE_BYTES-1))+capture+PAGE_BYTES-1)&~(PAGE_BYTES-1),c->allocation==4?PAGE_WRITECOPY:PAGE_READWRITE,&tmp);re=GetLastError();
        out(",\"inspection_restore\":{\"return_value\":%ld,\"last_error\":%lu,\"last_error_defined\":%s}",(long)restored,(unsigned long)re,restored?"false":"true");
        if(restored)after_ok=snapshot(after,base+at,capture,&inspection);}
        if(peer){peer_after_ok=snapshot(peer_after,peer+at,capture,&inspection);}
        out(",\"bytes\":{\"offset\":%u,\"before\":",at);byte_array(before,capture);out(",\"after\":");if(after_ok)byte_array(after,capture);else out("null");out(",\"peer_before\":");if(peer)byte_array(peer_before,capture);else out("null");out(",\"peer_after\":");if(peer_after_ok)byte_array(peer_after,capture);else out("null");out("}");
    }
    out(",\"inspection_exceptions\":%u}\n",inspection.count);hashing=0;emitted++;
    if(fault.count){unsigned fi;out("ALLOC {\"cell\":%u,\"exception_pc\":\"0x%llx\",\"exception_pc_module_offset\":%lld,\"parameters_raw\":[",c->id,(unsigned long long)fault.pc,(long long)(fault.pc-(uintptr_t)GetModuleHandleW(NULL)));for(fi=0;fi<fault.information && fi<15;fi++)out("%s%llu",fi?",":"",(unsigned long long)fault.parameters[fi]);out("]}\n");}
    if(peer)UnmapViewOfFile(peer);if(base){if(c->allocation>=3)UnmapViewOfFile(base);else VirtualFree(base,0,MEM_RELEASE);}if(section)CloseHandle(section);
}
#endif
static void emit(const Cell *c,int list) {
    if(list){hashing=1;out("CELL %u ",c->id);axes(c);out(" => {\"listed\":true}\n");hashing=0;emitted++;}
#ifdef _WIN32
    else execute_cell(c);
#else
    else {fputs("Runtime requires Windows x64. Host builds support list only.\n",stderr);exit(2);}
#endif
}
int main(int argc,char **argv) {
    unsigned first=0,last=TOTAL_CELLS-1,id=0,a,p,g,s,n,x,act;int list=0;Cell c;
    if(argc==2 && !strcmp(argv[1],"list"))list=1;
    else if(argc==2 && !strcmp(argv[1],"all")){}
    else if(argc==3 && !strcmp(argv[1],"cell") && parse_uint(argv[2],&first))last=first;
    else if(argc==4 && !strcmp(argv[1],"range") && parse_uint(argv[2],&first)&&parse_uint(argv[3],&last)){}
    else {fputs("Usage: memory_probe all | list | cell N | range FIRST LAST (inclusive, zero based)\n",stderr);return 2;}
    if(first>last||last>=TOTAL_CELLS){fputs("Invalid cell range\n",stderr);return 2;}
    setvbuf(stdout,NULL,_IOFBF,1024*1024);
#ifdef _WIN32
    {SYSTEM_INFO si;DWORD v=GetVersion();GetSystemInfo(&si);out("HEADER {\"schema\":1,\"mode\":\"%s\",\"total_cells\":%u,\"first\":%u,\"last\":%u,\"expected_count\":%u,\"pointer_bits\":%u,\"version\":%lu,\"page_size\":%lu,\"allocation_granularity\":%lu}\n",argv[1],TOTAL_CELLS,first,last,last-first+1,(unsigned)(sizeof(void *)*8),(unsigned long)v,(unsigned long)si.dwPageSize,(unsigned long)si.dwAllocationGranularity);if(!list && (si.dwPageSize!=PAGE_BYTES||si.dwAllocationGranularity!=65536)){fputs("Unsupported Windows page or allocation granularity\n",stderr);return 2;}}
#else
    out("HEADER {\"schema\":1,\"mode\":\"%s\",\"total_cells\":%u,\"first\":%u,\"last\":%u,\"expected_count\":%u,\"pointer_bits\":%u,\"runtime\":\"host-list-only\"}\n",argv[1],TOTAL_CELLS,first,last,last-first+1,(unsigned)(sizeof(void *)*8));
#endif
    memset(&c,0,sizeof c);c.action=9;
    for(a=0;a<5;a++)for(p=0;p<(a<3?6u:8u);p++)for(g=0;g<2;g++)for(s=0;s<4;s++)for(n=0;n<8;n++)for(x=0;x<8;x++) {
        c.id=id++;c.allocation=a;c.initial=protections[p];c.guard=g;c.position=s;c.neighbors=n;c.access=x;
        if(c.id>=first&&c.id<=last)emit(&c,list);
    }
    c.family=1;c.initial=4;c.guard=0;c.access=1;
    for(a=0;a<5;a++)for(act=0;act<10;act++)for(s=0;s<4;s++)for(n=0;n<8;n++) {
        c.id=id++;c.allocation=a;c.action=act;c.position=s;c.neighbors=n;
        if(c.id>=first&&c.id<=last)emit(&c,list);
    }
    if(id!=TOTAL_CELLS){fputs("Internal enumeration mismatch\n",stderr);return 3;}
    out("FOOTER count=%u fnv1a64=%016" PRIx64 "\n",emitted,checksum);
    return fflush(stdout)==0?0:3;
}
