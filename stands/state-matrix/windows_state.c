/* 0087 self-process state observer. Host build executes list only.
 * llvm-mingw: x86_64-w64-mingw32-gcc -O1 -fms-extensions windows_state.c -o windows_state.exe -lpsapi
 * MSVC x64: cl /nologo /W4 /O1 /TC windows_state.c /link psapi.lib
 * all | cell N | range A B | list. No child processes or file writes.
 * CELL checksum: FNV1a64 over actual CELL lines with one LF (binary stdout).
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
#define MOD_CAP 256
#define NT_CAP (4U*1024U*1024U)
#define HEADER_CAP (1024U*1024U)
#define EXPORT_CAP 65536U
#define SAMPLE_N 101

typedef enum {
 K_SYSINFO,K_FEATURE,K_TOPO,K_VERSION,K_WOW,K_MEMORY,K_SYSMAP,K_SYSDOC,
 K_PROCMAP,K_PROCDOC,K_PEB,K_DEBUG,K_MITIGATION,K_AFFINITY,K_WS,K_PROCTIME,
 K_THREADMAP,K_THREADS,K_THREADDOC,K_HIDE,K_CONTEXT,K_TEB,K_SUSPEND,K_PRIORITY,
 K_MODULES,K_HEADERS,K_SECTIONS,K_ADDRESS,K_EXPORTS,K_CLOSE,K_DUP,K_HFLAGS,K_OBJECT,
 K_QPF,K_CLOCK,K_STEP,K_WAIT,K_SHARED
} Kind;
typedef struct { Kind k; const char *family; unsigned count; } Group;
static const Group groups[] = {
 {K_SYSINFO,"system.info",2},{K_FEATURE,"system.processor_feature",64},
 {K_TOPO,"system.topology",9},{K_VERSION,"system.version",3},
 {K_WOW,"system.wow64",1},{K_MEMORY,"system.memory",1},
 {K_SYSMAP,"system.nt_class_map",256},{K_SYSDOC,"system.nt_documented",16},
 {K_PROCMAP,"process.nt_class_map",256},{K_PROCDOC,"process.nt_documented",7},
 {K_PEB,"process.peb",4},{K_DEBUG,"process.debugger",2},
 {K_MITIGATION,"process.mitigation",20},{K_AFFINITY,"process.affinity",1},
 {K_WS,"process.working_set",6},{K_PROCTIME,"process.times",1},
 {K_THREADMAP,"thread.nt_class_map",256},{K_THREADS,"thread.inventory",3},
 {K_THREADDOC,"thread.nt_documented",3},{K_HIDE,"thread.hide_from_debugger",1},
 {K_CONTEXT,"thread.context_roundtrip",6},{K_TEB,"thread.teb",4},
 {K_SUSPEND,"thread.suspend_resume",1},{K_PRIORITY,"thread.priority_roundtrip",7},
 {K_MODULES,"module.inventory",1},{K_HEADERS,"module.image_headers",1},
 {K_SECTIONS,"module.sections",1},{K_ADDRESS,"module.address_lookup",3},
 {K_EXPORTS,"module.exports",3},{K_CLOSE,"handle.close",6},
 {K_DUP,"handle.duplicate_pseudo",2},{K_HFLAGS,"handle.flags",4},
 {K_OBJECT,"handle.object",10},{K_QPF,"time.frequency",1},
 {K_CLOCK,"time.sleep100",7},{K_STEP,"time.minimum_step",7},
 {K_WAIT,"time.wait_distribution",6},{K_SHARED,"time.shared_data",2}
};
static const char *sysdocs[]={"Basic","CodeIntegrity","ExceptionOpaque","InterruptOpaque","KernelVaShadow","LeapSecond","LookasideOpaque","PerformanceOpaque","PolicyOpaque","ProcessExcluded","ProcessorPerformance","QueryPerformanceCounter","RegistryQuota","SpeculationControl","TimeOfDayOpaque","BasicProcessExcluded"};
#ifdef _WIN32
static const unsigned sysclasses[]={0,103,33,23,196,206,45,2,134,5,8,124,37,201,3,252};
#endif
static const char *procdocs[]={"Basic","DebugPort","Wow64","ImageFileName","BreakOnTermination","TelemetryId","Subsystem"};
#ifdef _WIN32
static const unsigned procclasses[]={0,7,26,27,29,64,75};
#endif
static const char *mitnames[]={"DEP","ASLR","DynamicCode","StrictHandleCheck","SystemCallDisable","OptionsMask","ExtensionPointDisable","ControlFlowGuard","Signature","FontDisable","ImageLoad","SystemCallFilter","PayloadRestriction","ChildProcess","SideChannelIsolation","UserShadowStack","RedirectionTrust","UserPointerAuth","SEHOP","ActivationContextTrust"};
static const char *clocknames[]={"QueryPerformanceCounter","GetTickCount64","GetSystemTimeAsFileTime","GetSystemTimePreciseAsFileTime","QueryUnbiasedInterruptTime","timeGetTime","NtQuerySystemTime"};
static const char *contextnames[]={"CONTROL","INTEGER","SEGMENTS","FLOATING_POINT","DEBUG_REGISTERS","ALL"};
static const char *objectnames[]={"event","mutex","semaphore","process","thread"};
static const char *waitnames[]={"Sleep0","Sleep1","SwitchToThread","Wait1","Wait15","Wait16"};
static const char *wsnames[]={"private_untouched","private_touched","private_readonly","private_noaccess","pagefile_mapping","own_image"};
static unsigned total_cells(void){unsigned i,n=0;for(i=0;i<sizeof(groups)/sizeof(groups[0]);i++)n+=groups[i].count;return n;}
static void axes(char *b,size_t n,Kind k,unsigned x){
 const char *name=NULL;
 switch(k){
 case K_SYSINFO:name=x?"GetNativeSystemInfo":"GetSystemInfo";break;
 case K_VERSION:name=x==0?"RtlGetVersion":x==1?"GetVersionExW":"VerifyVersionInfoW";break;
 case K_SYSDOC:name=sysdocs[x];break;case K_PROCDOC:name=procdocs[x];break;
 case K_MITIGATION:name=mitnames[x];break;case K_CONTEXT:name=contextnames[x];break;
 case K_WS:name=wsnames[x];break;case K_CLOCK:case K_STEP:name=clocknames[x];break;
 case K_WAIT:name=waitnames[x];break;
 case K_EXPORTS:name=x==0?"kernel32.dll":x==1?"ntdll.dll":"user32.dll";break;
 case K_OBJECT:snprintf(b,n,"\"axis\":%u,\"type\":\"%s\",\"class\":%u",x,objectnames[x/2],x%2?2:0);return;
 case K_CLOSE:snprintf(b,n,"\"axis\":%u,\"api\":\"%s\",\"handle\":\"%s\"",x,x/3?"NtClose":"CloseHandle",x%3==0?"valid":x%3==1?"invalid":"protected");return;
 default:break;
 }
 if(name)snprintf(b,n,"\"axis\":%u,\"name\":\"%s\"",x,name);else snprintf(b,n,"\"axis\":%u",x);
}
static uint64_t hash=UINT64_C(14695981039346656037);
static unsigned emitted=0;
static void hash_line(const char *s){while(*s){hash^=(unsigned char)*s++;hash*=UINT64_C(1099511628211);}hash^='\n';hash*=UINT64_C(1099511628211);}
static void emit(unsigned id,const char *family,const char *payload){
 size_t n=strlen(payload)+strlen(family)+64;char *s=(char*)malloc(n);
 if(!s){fputs("allocation failure\n",stderr);exit(3);}snprintf(s,n,"CELL %u %s => %s",id,family,payload);
 puts(s);hash_line(s);free(s);emitted++;
}
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 2
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <io.h>
#include <fcntl.h>
#ifdef _MSC_VER
#pragma comment(lib,"psapi.lib")
#endif
#if !defined(_M_X64) && !defined(__x86_64__)
#error This observer targets Windows x64 including x64 emulation on ARM64.
#endif
typedef struct {char *s;size_t len,cap;} Buf;
static void add(Buf *b,const char *fmt,...){
 va_list ap;int n;size_t need;
 if(!b->s){b->cap=1024;b->s=(char*)malloc(b->cap);b->len=0;if(!b->s)exit(3);b->s[0]=0;}
 for(;;){va_start(ap,fmt);n=vsnprintf(b->s+b->len,b->cap-b->len,fmt,ap);va_end(ap);
  if(n>=0&&(size_t)n<b->cap-b->len){b->len+=(size_t)n;return;}
  need=n<0?b->cap*2:b->len+(size_t)n+1;if(need>32U*1024U*1024U){fputs("cell too large\n",stderr);exit(3);}
  b->cap=need*2;b->s=(char*)realloc(b->s,b->cap);if(!b->s)exit(3);
 }
}
static void quote(Buf *b,const char *s){const unsigned char *p=(const unsigned char*)s;add(b,"\"");while(*p){if(*p=='"'||*p=='\\')add(b,"\\%c",*p);else if(*p<32)add(b,"\\u%04x",*p);else add(b,"%c",*p);p++;}add(b,"\"");}
static void wquote(Buf *b,const WCHAR *w,unsigned count){unsigned i;add(b,"\"");for(i=0;i<count&&w[i];i++){unsigned c=w[i];if(c=='"'||c=='\\')add(b,"\\%c",c);else if(c>=32&&c<127)add(b,"%c",c);else add(b,"\\u%04x",c);}add(b,"\"");}
static void reset(Buf *b){b->len=0;if(b->s)b->s[0]=0;}
static const char *jb(int v){return v?"true":"false";}
static Buf raw,norm,comparison,out;
static const char *reason=NULL;static int unsupported=0;
static void unsup(const char *why){unsupported=1;reason=why;}
static void failed(DWORD e){add(&raw,"\"error\":%lu",(unsigned long)e);add(&norm,"\"call_succeeded\":false");}
static void finish_cell(unsigned id,const char *family,Kind kind,unsigned axis){
 char ax[256];axes(ax,sizeof(ax),kind,axis);
 reset(&out);add(&out,"{\"axes\":{%s},\"raw\":{%s},\"norm\":{\"invariants\":{%s}%s%s},\"status\":\"%s\",\"reason\":",ax,raw.s?raw.s:"",norm.s?norm.s:"",comparison.len?",":"",comparison.s?comparison.s:"",unsupported?"UNSUPPORTED":"OBSERVED");
 quote(&out,reason?reason:"");add(&out,"}");emit(id,family,out.s);
}
typedef LONG (NTAPI *QSys)(ULONG,PVOID,ULONG,PULONG);
typedef LONG (NTAPI *QProc)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef LONG (NTAPI *QThread)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef LONG (NTAPI *QObj)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef LONG (NTAPI *NClose)(HANDLE);
typedef LONG (NTAPI *NTime)(PLARGE_INTEGER);
typedef LONG (WINAPI *RVersion)(OSVERSIONINFOW*);
typedef BOOL (WINAPI *Wow2)(HANDLE,USHORT*,USHORT*);
typedef BOOL (WINAPI *MitPolicy)(HANDLE,int,PVOID,SIZE_T);
typedef VOID (WINAPI *PreciseTime)(LPFILETIME);
typedef DWORD (WINAPI *MmTime)(void);
typedef VOID (WINAPI *StackLimits)(PULONG_PTR,PULONG_PTR);
typedef PVOID (NTAPI *PcHeader)(PVOID,PVOID*);
typedef PRUNTIME_FUNCTION (NTAPI *LookupEntry)(DWORD64,PDWORD64,PUNWIND_HISTORY_TABLE);
static QSys qsys;static QProc qproc;static QThread qthread;static QObj qobj;static NClose nclose;
static NTime ntime;static RVersion rversion;static Wow2 wow2;static MitPolicy mitpolicy;
static PreciseTime precise;static MmTime mmtime;static StackLimits stacklimits;static PcHeader pcheader;static LookupEntry lookup;
static SYSTEM_INFO nativeinfo;static DWORD initial_thread_count,initial_thread_error,selfpid;
static HMODULE mm_module,user_module;
static DWORD entry_ids[1024];static unsigned entry_n=0;static int entry_recording=1,entry_truncated=0;
static FARPROC findfn(HMODULE m,const char *n){return m?GetProcAddress(m,n):NULL;}
#define RESOLVE(var,type,m,name) do{FARPROC p=findfn(m,name);memcpy(&(var),&p,sizeof(type));}while(0)
static uint64_t ft64(FILETIME f){return ((uint64_t)f.dwHighDateTime<<32)|f.dwLowDateTime;}
static DWORD thread_count(DWORD *error){
 HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);THREADENTRY32 t;DWORD n=0;
 *error=0;if(snap==INVALID_HANDLE_VALUE){*error=GetLastError();return 0;}memset(&t,0,sizeof(t));t.dwSize=sizeof(t);
 if(Thread32First(snap,&t)){do{if(t.th32OwnerProcessID==GetCurrentProcessId()){n++;if(entry_recording){if(entry_n<1024)entry_ids[entry_n++]=t.th32ThreadID;else entry_truncated=1;}}t.dwSize=sizeof(t);}while(Thread32Next(snap,&t));if(GetLastError()!=ERROR_NO_MORE_FILES)*error=GetLastError();}else *error=GetLastError();CloseHandle(snap);return n;
}
static void init(void){HMODULE nt=GetModuleHandleW(L"ntdll.dll"),k=GetModuleHandleW(L"kernel32.dll");
 selfpid=GetCurrentProcessId();GetNativeSystemInfo(&nativeinfo);
 RESOLVE(qsys,QSys,nt,"NtQuerySystemInformation");RESOLVE(qproc,QProc,nt,"NtQueryInformationProcess");RESOLVE(qthread,QThread,nt,"NtQueryInformationThread");RESOLVE(qobj,QObj,nt,"NtQueryObject");RESOLVE(nclose,NClose,nt,"NtClose");RESOLVE(ntime,NTime,nt,"NtQuerySystemTime");RESOLVE(rversion,RVersion,nt,"RtlGetVersion");
 RESOLVE(wow2,Wow2,k,"IsWow64Process2");RESOLVE(mitpolicy,MitPolicy,k,"GetProcessMitigationPolicy");RESOLVE(precise,PreciseTime,k,"GetSystemTimePreciseAsFileTime");RESOLVE(stacklimits,StackLimits,k,"GetCurrentThreadStackLimits");RESOLVE(pcheader,PcHeader,nt,"RtlPcToFileHeader");RESOLVE(lookup,LookupEntry,nt,"RtlLookupFunctionEntry");
 mm_module=LoadLibraryExW(L"winmm.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);RESOLVE(mmtime,MmTime,mm_module,"timeGetTime");
 user_module=LoadLibraryExW(L"user32.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);
}
static void pointer(Buf *b,const void *p){
 HMODULE m=NULL;WCHAR path[32768];const WCHAR *base;unsigned i;DWORD plen;
 add(b,"{\"absolute\":\"0x%" PRIxPTR "\"",(uintptr_t)p);
 if(p&&GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCWSTR)p,&m)&&(plen=GetModuleFileNameW(m,path,32768))>0&&plen<32768){
  base=path;for(i=0;path[i];i++)if(path[i]=='\\'||path[i]=='/')base=path+i+1;
  add(b,",\"module\":");wquote(b,base,32768);add(b,",\"offset\":%" PRIuPTR,(uintptr_t)p-(uintptr_t)m);
 }else add(b,",\"module\":null,\"offset\":null");add(b,"}");
}
static int ownread(const void *p,void *dest,SIZE_T n){SIZE_T got=0;return ReadProcessMemory(GetCurrentProcess(),p,dest,n,&got)&&got==n;}
typedef struct {LONG ExitStatus;PPEB PebBaseAddress;ULONG_PTR AffinityMask;LONG BasePriority;ULONG_PTR UniqueProcessId;ULONG_PTR InheritedFromUniqueProcessId;} OwnPbi;
static int getpbi(OwnPbi *p){ULONG len=0;memset(p,0,sizeof(*p));return qproc&&qproc(GetCurrentProcess(),0,p,sizeof(*p),&len)>=0;}
static void ntmap(Kind k,unsigned x){LONG st;ULONG len=0xfedcba98U;
 if((k==K_SYSMAP&&!qsys)||(k==K_PROCMAP&&!qproc)||(k==K_THREADMAP&&!qthread)){unsup("entry_point_absent");return;}
 st=k==K_SYSMAP?qsys(x,NULL,0,&len):k==K_PROCMAP?qproc(GetCurrentProcess(),x,NULL,0,&len):qthread(GetCurrentThread(),x,NULL,0,&len);
 add(&raw,"\"class\":%u,\"ntstatus\":\"0x%08lx\",\"return_length\":%lu,\"return_length_written\":%s",x,(unsigned long)(ULONG)st,(unsigned long)len,jb(len!=0xfedcba98U));
 add(&norm,"\"zero_length_probe\":true");add(&comparison,"\"return_status\":\"0x%08lx\",\"return_length_written\":%s",(unsigned long)(ULONG)st,jb(len!=0xfedcba98U));
}
static void system_info(unsigned x){SYSTEM_INFO s;memset(&s,0,sizeof(s));if(x)GetNativeSystemInfo(&s);else GetSystemInfo(&s);
 add(&raw,"\"architecture\":%u,\"reserved\":%u,\"page_size\":%lu,\"minimum_address\":\"0x%" PRIxPTR "\",\"maximum_address\":\"0x%" PRIxPTR "\",\"active_mask\":\"0x%" PRIxPTR "\",\"processors\":%lu,\"processor_type\":%lu,\"allocation_granularity\":%lu,\"processor_level\":%u,\"processor_revision\":%u",s.wProcessorArchitecture,s.wReserved,(unsigned long)s.dwPageSize,(uintptr_t)s.lpMinimumApplicationAddress,(uintptr_t)s.lpMaximumApplicationAddress,(uintptr_t)s.dwActiveProcessorMask,(unsigned long)s.dwNumberOfProcessors,(unsigned long)s.dwProcessorType,(unsigned long)s.dwAllocationGranularity,s.wProcessorLevel,s.wProcessorRevision);add(&raw,",\"dwOemId_alias\":%lu",(unsigned long)s.dwOemId);
 add(&norm,"\"page_power_of_two\":%s,\"granularity_multiple_of_page\":%s,\"address_range_ordered\":%s,\"processor_count_positive\":%s",jb(s.dwPageSize&&!(s.dwPageSize&(s.dwPageSize-1))),jb(s.dwPageSize&&s.dwAllocationGranularity%s.dwPageSize==0),jb((uintptr_t)s.lpMinimumApplicationAddress<(uintptr_t)s.lpMaximumApplicationAddress),jb(s.dwNumberOfProcessors>0));
}
static void topology(unsigned x){DWORD len=0,err,capacity;unsigned rel=x==8?0xffff:x;BYTE *p;BOOL ok;unsigned off=0,count=0;int well=1;
 SetLastError(0);ok=GetLogicalProcessorInformationEx((LOGICAL_PROCESSOR_RELATIONSHIP)rel,NULL,&len);err=GetLastError();
 add(&raw,"\"relationship\":%u,\"probe_ok\":%s,\"probe_error\":%lu,\"needed\":%lu",rel,jb(ok),(unsigned long)err,(unsigned long)len);
 if(!len||len>NT_CAP){unsup(len>NT_CAP?"topology_exceeds_4MiB_bound":"relationship_unavailable");return;}
 capacity=len;p=(BYTE*)calloc(1,len);if(!p)exit(3);SetLastError(0);ok=GetLogicalProcessorInformationEx((LOGICAL_PROCESSOR_RELATIONSHIP)rel,(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)p,&len);err=GetLastError();if(len>capacity){free(p);unsup("topology_output_length_exceeds_allocation");return;}
 add(&raw,",\"ok\":%s,\"error\":%lu,\"records\":[",jb(ok),(unsigned long)(ok?0:err));
 if(ok)while(off<len){PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX q=(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(p+off);unsigned sz;if(len-off<8){well=0;break;}sz=q->Size;if(sz<8||sz>len-off){well=0;break;}if(count++)add(&raw,",");add(&raw,"{\"relationship\":%u,\"size\":%u",(unsigned)q->Relationship,sz);
  if((unsigned)q->Relationship==0||(unsigned)q->Relationship==3||(unsigned)q->Relationship==5||(unsigned)q->Relationship==7){unsigned g,n;size_t need;if(sz<offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,Processor.GroupMask)){well=0;add(&raw,"}");off+=sz;continue;}n=q->Processor.GroupCount;need=offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,Processor.GroupMask)+(size_t)n*sizeof(GROUP_AFFINITY);if(need>sz){well=0;}else{add(&raw,",\"flags\":%u,\"efficiency_class\":%u,\"groups\":[",q->Processor.Flags,q->Processor.EfficiencyClass);for(g=0;g<n;g++){if(g)add(&raw,",");add(&raw,"{\"group\":%u,\"mask\":\"0x%" PRIxPTR "\"}",q->Processor.GroupMask[g].Group,(uintptr_t)q->Processor.GroupMask[g].Mask);}add(&raw,"]");}}
  else if(q->Relationship==RelationCache&&sz>=offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,Cache)+sizeof(CACHE_RELATIONSHIP)){add(&raw,",\"level\":%u,\"associativity\":%u,\"line_size\":%u,\"cache_size\":%lu,\"cache_type\":%u",q->Cache.Level,q->Cache.Associativity,q->Cache.LineSize,(unsigned long)q->Cache.CacheSize,(unsigned)q->Cache.Type);}
  else if(q->Relationship==RelationGroup){unsigned g,n;if(sz<offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,Group.GroupInfo)){well=0;add(&raw,"}");off+=sz;continue;}n=q->Group.ActiveGroupCount;size_t need=offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,Group.GroupInfo)+(size_t)n*sizeof(PROCESSOR_GROUP_INFO);if(need>sz){well=0;}else{add(&raw,",\"maximum_groups\":%u,\"active_groups\":%u,\"group_info\":[",q->Group.MaximumGroupCount,n);for(g=0;g<n;g++){if(g)add(&raw,",");add(&raw,"{\"maximum\":%u,\"active\":%u,\"mask\":\"0x%" PRIxPTR "\"}",q->Group.GroupInfo[g].MaximumProcessorCount,q->Group.GroupInfo[g].ActiveProcessorCount,(uintptr_t)q->Group.GroupInfo[g].ActiveProcessorMask);if(q->Group.GroupInfo[g].ActiveProcessorCount>q->Group.GroupInfo[g].MaximumProcessorCount)well=0;}add(&raw,"]");}}
  else if(q->Relationship==RelationNumaNode&&sz>=offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,NumaNode)+sizeof(NUMA_NODE_RELATIONSHIP)){add(&raw,",\"node\":%lu,\"group\":%u,\"mask\":\"0x%" PRIxPTR "\"}",(unsigned long)q->NumaNode.NodeNumber,q->NumaNode.GroupMask.Group,(uintptr_t)q->NumaNode.GroupMask.Mask);off+=sz;continue;}
  add(&raw,"}");off+=sz;
 }
 add(&raw,"],\"record_count\":%u",count);add(&norm,"\"structures_well_formed\":%s,\"records_cover_buffer\":%s",jb(well),jb(ok&&off==len));free(p);if(!ok)unsup("relationship_query_failed");
}
static void version(unsigned x){
 OSVERSIONINFOEXW v;BOOL ok;DWORD e;memset(&v,0,sizeof(v));v.dwOSVersionInfoSize=sizeof(v);
 if(x==0){unsup("RtlGetVersion_user_export_has_no_documented_user_mode_contract");return;}
 if(x==1){SetLastError(0);ok=GetVersionExW((OSVERSIONINFOW*)&v);e=GetLastError();add(&raw,"\"ok\":%s,\"error\":%lu,\"major\":%lu,\"minor\":%lu,\"build\":%lu,\"platform\":%lu,\"service_pack_major\":%u,\"service_pack_minor\":%u,\"suite\":%u,\"product_type\":%u,\"csd\":",jb(ok),(unsigned long)(ok?0:e),(unsigned long)v.dwMajorVersion,(unsigned long)v.dwMinorVersion,(unsigned long)v.dwBuildNumber,(unsigned long)v.dwPlatformId,v.wServicePackMajor,v.wServicePackMinor,v.wSuiteMask,v.wProductType);wquote(&raw,v.szCSDVersion,128);add(&norm,"\"call_succeeded\":%s",jb(ok));}
 else{DWORDLONG mask=0;v.dwMajorVersion=6;v.dwMinorVersion=2;v.wServicePackMajor=0;mask=VerSetConditionMask(mask,VER_MAJORVERSION,VER_GREATER_EQUAL);mask=VerSetConditionMask(mask,VER_MINORVERSION,VER_GREATER_EQUAL);mask=VerSetConditionMask(mask,VER_SERVICEPACKMAJOR,VER_GREATER_EQUAL);SetLastError(0);ok=VerifyVersionInfoW(&v,VER_MAJORVERSION|VER_MINORVERSION|VER_SERVICEPACKMAJOR,mask);e=GetLastError();add(&raw,"\"target_major\":6,\"target_minor\":2,\"ok\":%s,\"error\":%lu",jb(ok),(unsigned long)(ok?0:e));add(&norm,"\"documented_result\":%s",jb(ok||e==ERROR_OLD_WIN_VERSION));}
}
static void sysdoc(unsigned x){
 unsigned c=sysclasses[x];LONG st;ULONG len=0;union{uint64_t align;BYTE b[256];}u;memset(&u,0,sizeof(u));
 add(&raw,"\"class\":%u",c);
 if(!qsys){unsup("entry_point_absent");return;}
 if(x==9||x==15){unsup("systemwide_process_contents_excluded_self_process_scope");return;}
 if(x==2||x==3||x==5||x==6||x==7||x==8||x==14){unsup("documented_structure_is_opaque_no_fields_to_decode");return;}
 if(x==10){
  BYTE *b;unsigned n,i;ULONG bytes=nativeinfo.dwNumberOfProcessors*48U;typedef struct{LARGE_INTEGER idle,kernel,user,dpc,interrupt;ULONG count;ULONG pad;}PP;
  if(!bytes||bytes>NT_CAP){unsup("processor_array_bound");return;}b=(BYTE*)calloc(1,bytes);if(!b)exit(3);st=qsys(c,b,bytes,&len);n=len/sizeof(PP);add(&raw,",\"ntstatus\":\"0x%08lx\",\"return_length\":%lu,\"processors\":[",(unsigned long)(ULONG)st,(unsigned long)len);
  if(st>=0&&len<=bytes)for(i=0;i<n;i++){PP *p=(PP*)b+i;if(i)add(&raw,",");add(&raw,"{\"idle\":%" PRId64 ",\"kernel\":%" PRId64 ",\"user\":%" PRId64 "}",(int64_t)p->idle.QuadPart,(int64_t)p->kernel.QuadPart,(int64_t)p->user.QuadPart);}add(&raw,"]");add(&norm,"\"array_length_valid\":%s",jb(st>=0&&len<=bytes&&len%sizeof(PP)==0));if(st<0)unsup("documented_class_unavailable");free(b);return;
 }
 if(x==0){struct{BYTE reserved1[24];PVOID reserved2[4];CHAR processors;}b;memset(&b,0,sizeof(b));st=qsys(c,&b,sizeof(b),&len);add(&raw,",\"ntstatus\":\"0x%08lx\",\"return_length\":%lu,\"processors\":%u",(unsigned long)(ULONG)st,(unsigned long)len,(unsigned char)b.processors);add(&norm,"\"processor_count_positive\":%s",jb(st>=0&&(unsigned char)b.processors>0));}
 else{
  ULONG sz=x==1?8:x==5?8:x==12?(ULONG)(8+sizeof(SIZE_T)):4;
  if(x==1)*(ULONG*)u.b=sz;
  if(x==11){unsup("documented_QPC_class_structure_contract_not_bound_in_this_build");return;}
  st=qsys(c,u.b,sz,&len);add(&raw,",\"ntstatus\":\"0x%08lx\",\"return_length\":%lu",(unsigned long)(ULONG)st,(unsigned long)len);
  if(st>=0){if(x==1)add(&raw,",\"length\":%lu,\"code_integrity_options\":%lu",(unsigned long)*(ULONG*)u.b,(unsigned long)*(ULONG*)(u.b+4));else if(x==5)add(&raw,",\"leap_seconds_enabled\":%s",jb(u.b[0]));else if(x==12)add(&raw,",\"registry_quota_allowed\":%lu,\"registry_quota_used\":%lu,\"paged_pool_size\":%" PRIuPTR,(unsigned long)*(ULONG*)u.b,(unsigned long)*(ULONG*)(u.b+4),(uintptr_t)*(SIZE_T*)(u.b+8));else add(&raw,",\"documented_flags\":%lu",(unsigned long)*(ULONG*)u.b);}
  add(&norm,"\"bounded_documented_output\":%s",jb(st<0||len<=sz));
 }
 if(st<0)unsup("documented_class_unavailable");
}
static void procdoc(unsigned x){
 ULONG c=procclasses[x],len=0;LONG st;union{OwnPbi p;ULONG_PTR up;ULONG ul;BYTE b[65536];}u;memset(&u,0,sizeof(u));
 add(&raw,"\"class\":%lu",(unsigned long)c);if(!qproc){unsup("entry_point_absent");return;}if(x==5){unsup("telemetry_structure_variable_layout_not_bound");return;}
 st=qproc(GetCurrentProcess(),c,&u,x==0?sizeof(OwnPbi):x==3?sizeof(u):x==1||x==2?sizeof(ULONG_PTR):sizeof(ULONG),&len);
 add(&raw,",\"ntstatus\":\"0x%08lx\",\"return_length\":%lu",(unsigned long)(ULONG)st,(unsigned long)len);if(st<0){unsup("documented_class_unavailable");return;}
 if(x==0){DWORD exitcode=0;GetExitCodeProcess(GetCurrentProcess(),&exitcode);add(&raw,",\"exit_status\":%ld,\"peb\":",(long)u.p.ExitStatus);pointer(&raw,u.p.PebBaseAddress);add(&raw,",\"affinity_mask\":\"0x%" PRIxPTR "\",\"base_priority\":%ld,\"pid\":%" PRIuPTR ",\"parent_pid\":%" PRIuPTR,(uintptr_t)u.p.AffinityMask,(long)u.p.BasePriority,(uintptr_t)u.p.UniqueProcessId,(uintptr_t)u.p.InheritedFromUniqueProcessId);add(&norm,"\"pid_matches_self\":%s,\"exit_status_matches_api\":%s",jb((DWORD)u.p.UniqueProcessId==selfpid),jb((DWORD)u.p.ExitStatus==exitcode));}
 else if(x==3){UNICODE_STRING *s=(UNICODE_STRING*)u.b;int inside=len>=sizeof(UNICODE_STRING)&&len<=sizeof(u)&&(uintptr_t)s->Buffer>=(uintptr_t)u.b&&(uintptr_t)s->Buffer<=(uintptr_t)u.b+len&&s->Length<=(uintptr_t)u.b+len-(uintptr_t)s->Buffer&&s->Length<=s->MaximumLength&&(s->Length&1)==0;add(&raw,",\"image_name\":");if(inside)wquote(&raw,s->Buffer,s->Length/2);else add(&raw,"null");add(&norm,"\"unicode_buffer_bounded\":%s,\"unicode_length_even\":%s",jb(inside),jb((s->Length&1)==0));}
 else if(x==1){BOOL debug=FALSE;BOOL ok=CheckRemoteDebuggerPresent(GetCurrentProcess(),&debug);add(&raw,",\"debug_port\":\"0x%" PRIxPTR "\"",(uintptr_t)u.up);add(&norm,"\"debugger_flags_agree\":%s",jb(ok&&!!u.up==!!debug));}
 else if(x==2){BOOL w=FALSE;BOOL ok=IsWow64Process(GetCurrentProcess(),&w);add(&raw,",\"wow64_pointer\":\"0x%" PRIxPTR "\"",(uintptr_t)u.up);add(&norm,"\"wow64_flags_agree\":%s",jb(ok&&!!u.up==!!w));}
 else{add(&raw,",\"value\":%lu",(unsigned long)u.ul);add(&norm,"\"documented_scalar_read\":true");add(&comparison,"\"value\":%lu",(unsigned long)u.ul);}
}
typedef char pbi_layout_must_match_x64[(sizeof(OwnPbi)==48&&offsetof(OwnPbi,PebBaseAddress)==8&&offsetof(OwnPbi,UniqueProcessId)==32)?1:-1];
static void peb_cell(unsigned x){OwnPbi p;PEB b;DWORD sid=0;
 if(x==1){unsup("ImageBaseAddress_is_reserved_in_public_PEB_use_GetModuleHandle_null");return;}
 if(!getpbi(&p)||!ownread(p.PebBaseAddress,&b,sizeof(b))){unsup("public_PEB_unavailable");return;}
 if(x==0){add(&raw,"\"being_debugged\":%u",b.BeingDebugged);add(&norm,"\"debugger_flags_agree\":%s",jb(!!b.BeingDebugged==!!IsDebuggerPresent()));}
 else if(x==2){BOOL ok=ProcessIdToSessionId(selfpid,&sid);add(&raw,"\"peb_session\":%lu,\"api_session\":%lu",(unsigned long)b.SessionId,(unsigned long)sid);add(&norm,"\"session_ids_agree\":%s",jb(ok&&sid==b.SessionId));}
 else{add(&raw,"\"ldr\":");pointer(&raw,b.Ldr);add(&norm,"\"ldr_present\":%s",jb(b.Ldr!=NULL));}
}
static void mitigation(unsigned x){union{uint64_t u64[2];DWORD u32[4];}u;BOOL ok;DWORD e;SIZE_T sz=x==0?8:x==5?16:4;memset(&u,0,sizeof(u));
 if(x==19){unsup("ActivationContextTrust_public_structure_contract_not_available");return;}if(!mitpolicy){unsup("entry_point_absent");return;}SetLastError(0);ok=mitpolicy(GetCurrentProcess(),(int)x,&u,sz);e=GetLastError();
 add(&raw,"\"policy\":%u,\"name\":",x);quote(&raw,mitnames[x]);add(&raw,",\"structure_size\":%u,\"ok\":%s,\"error\":%lu,\"words\":[%lu,%lu,%lu,%lu]",(unsigned)sz,jb(ok),(unsigned long)(ok?0:e),(unsigned long)u.u32[0],(unsigned long)u.u32[1],(unsigned long)u.u32[2],(unsigned long)u.u32[3]);
 if(!ok){unsup("policy_unavailable_or_unsupported_by_OS");return;}add(&norm,"\"documented_size_used\":true");add(&comparison,"\"policy_words\":[%lu,%lu,%lu,%lu]",(unsigned long)u.u32[0],(unsigned long)u.u32[1],(unsigned long)u.u32[2],(unsigned long)u.u32[3]);if(x==0)add(&raw,",\"permanent\":%s",jb(((BYTE*)&u)[4]));
}
static void working_set(unsigned x){void *p=NULL;HANDLE map=NULL;DWORD old=0;PSAPI_WORKING_SET_EX_INFORMATION w;MEMORY_BASIC_INFORMATION v;BOOL ok;DWORD e;SIZE_T n=nativeinfo.dwPageSize;
 if(x==5)p=(void*)GetModuleHandleW(NULL);else if(x==4){map=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,(DWORD)n,NULL);if(map)p=MapViewOfFile(map,FILE_MAP_WRITE,0,0,n);if(p)*(volatile BYTE*)p=7;}
 else{p=VirtualAlloc(NULL,n,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(p&&x>0)*(volatile BYTE*)p=7;if(p&&(x==2||x==3)&&!VirtualProtect(p,n,x==2?PAGE_READONLY:PAGE_NOACCESS,&old)){DWORD e=GetLastError();VirtualFree(p,0,MEM_RELEASE);failed(e);return;}}
 if(!p){failed(GetLastError());if(map)CloseHandle(map);return;}
 memset(&w,0,sizeof(w));w.VirtualAddress=p;SetLastError(0);ok=QueryWorkingSetEx(GetCurrentProcess(),&w,sizeof(w));e=GetLastError();memset(&v,0,sizeof(v));if(!VirtualQuery(p,&v,sizeof(v))){DWORD ve=GetLastError();if(x==4){UnmapViewOfFile(p);CloseHandle(map);}else if(x!=5)VirtualFree(p,0,MEM_RELEASE);failed(ve);return;}
 add(&raw,"\"kind\":");quote(&raw,wsnames[x]);add(&raw,",\"ok\":%s,\"error\":%lu,\"address\":",jb(ok),(unsigned long)(ok?0:e));pointer(&raw,p);add(&raw,",\"flags\":\"0x%" PRIxPTR "\",\"valid\":%s,\"state\":%lu,\"type\":%lu,\"protect\":%lu",(uintptr_t)w.VirtualAttributes.Flags,jb(w.VirtualAttributes.Valid),(unsigned long)v.State,(unsigned long)v.Type,(unsigned long)v.Protect);
 if(w.VirtualAttributes.Valid)add(&raw,",\"share_count\":%u,\"win32_protection\":%u,\"shared\":%s,\"node\":%u,\"locked\":%s,\"large_page\":%s",(unsigned)w.VirtualAttributes.ShareCount,(unsigned)w.VirtualAttributes.Win32Protection,jb(w.VirtualAttributes.Shared),(unsigned)w.VirtualAttributes.Node,jb(w.VirtualAttributes.Locked),jb(w.VirtualAttributes.LargePage));
 add(&norm,"\"query_succeeded\":%s,\"expected_mapping_type\":%s",jb(ok),jb(v.Type==(x==5?MEM_IMAGE:x==4?MEM_MAPPED:MEM_PRIVATE)));
 if(x==4){UnmapViewOfFile(p);CloseHandle(map);}else if(x!=5)VirtualFree(p,0,MEM_RELEASE);
}
static DWORD WINAPI own_thread(LPVOID p){(void)p;return 0;}
typedef struct{HANDLE h;DWORD id;} OwnedThread;
static OwnedThread make_thread(void){OwnedThread t;t.id=0;t.h=CreateThread(NULL,0,own_thread,NULL,CREATE_SUSPENDED,&t.id);return t;}
static void dispose_thread(OwnedThread t){if(t.h){if(ResumeThread(t.h)==(DWORD)-1){fputs("thread resume failed\n",stderr);exit(4);}if(WaitForSingleObject(t.h,5000)!=WAIT_OBJECT_0){fputs("thread termination not observed\n",stderr);exit(4);}CloseHandle(t.h);}}
static void threads(unsigned x){DWORD e=0,before_error=0,before=0,after=0;unsigned i,n=x==0?0:x==1?1:4;OwnedThread t[4];int all=1;memset(t,0,sizeof(t));
 if(x==0){add(&raw,"\"count\":%lu,\"owner_pid\":%lu,\"error\":%lu,\"snapshot\":\"first_main_operation\"",(unsigned long)initial_thread_count,(unsigned long)selfpid,(unsigned long)initial_thread_error);add(&norm,"\"entry_snapshot_succeeded\":%s,\"includes_main_thread\":%s",jb(!initial_thread_error&&!entry_truncated),jb(initial_thread_count>=1));add(&raw,",\"threads\":[");for(i=0;i<entry_n;i++){if(i)add(&raw,",");add(&raw,"{\"tid\":%lu,\"owner_pid\":%lu}",(unsigned long)entry_ids[i],(unsigned long)selfpid);}add(&raw,"]");return;}
 before=thread_count(&before_error);for(i=0;i<n;i++){t[i]=make_thread();if(!t[i].h)all=0;}after=thread_count(&e);
 add(&raw,"\"before\":%lu,\"after\":%lu,\"requested\":%u,\"owner_pid\":%lu,\"created\":[",(unsigned long)before,(unsigned long)after,n,(unsigned long)selfpid);for(i=0;i<n;i++){if(i)add(&raw,",");add(&raw,"%lu",(unsigned long)t[i].id);}add(&raw,"]");
 add(&norm,"\"all_created\":%s,\"count_includes_created_threads\":%s",jb(all),jb(all&&after>=n+1));add(&norm,",\"snapshots_succeeded\":%s",jb(!before_error&&!e));add(&raw,",\"before_error\":%lu,\"after_error\":%lu",(unsigned long)before_error,(unsigned long)e);for(i=0;i<n;i++)dispose_thread(t[i]);
}
static void thread_doc(unsigned x){OwnedThread t=make_thread();ULONG c=x==0?9:x==1?16:45,len=0;union{void *p;ULONG n;}u;LONG st;memset(&u,0,sizeof(u));
 if(!qthread){unsup("entry_point_absent");dispose_thread(t);return;}if(!t.h){failed(GetLastError());return;}
 st=qthread(t.h,c,&u,x==0?sizeof(void*):sizeof(ULONG),&len);add(&raw,"\"class\":%lu,\"ntstatus\":\"0x%08lx\",\"return_length\":%lu",(unsigned long)c,(unsigned long)(ULONG)st,(unsigned long)len);
 if(st<0)unsup("documented_thread_class_unavailable");else if(x==0){add(&raw,",\"start\":");pointer(&raw,u.p);add(&norm,"\"start_matches_thread_entry\":%s",jb(u.p==(void*)(uintptr_t)own_thread));}else if(x==1){BOOL pending=FALSE;BOOL ok=GetThreadIOPendingFlag(t.h,&pending);add(&raw,",\"io_pending\":%lu",(unsigned long)u.n);add(&norm,"\"io_pending_matches_api\":%s",jb(ok&&!!u.n==!!pending));}else{add(&raw,",\"subsystem\":%lu",(unsigned long)u.n);add(&norm,"\"documented_scalar_read\":true");add(&comparison,"\"subsystem\":%lu",(unsigned long)u.n);}dispose_thread(t);
}
static void context_dump(Buf *b,const CONTEXT *c){add(b,"{\"flags\":%lu,\"rip\":",(unsigned long)c->ContextFlags);pointer(b,(void*)(uintptr_t)c->Rip);add(b,",\"rsp\":\"0x%" PRIx64 "\",\"eflags\":%lu,\"segments\":[%u,%u,%u,%u,%u,%u],\"dr\":[\"0x%" PRIx64 "\",\"0x%" PRIx64 "\",\"0x%" PRIx64 "\",\"0x%" PRIx64 "\",\"0x%" PRIx64 "\",\"0x%" PRIx64 "\"],\"mxcsr\":%lu,\"x87_control\":%u,\"x87_status\":%u,\"gpr\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]}",(uint64_t)c->Rsp,(unsigned long)c->EFlags,c->SegCs,c->SegSs,c->SegDs,c->SegEs,c->SegFs,c->SegGs,(uint64_t)c->Dr0,(uint64_t)c->Dr1,(uint64_t)c->Dr2,(uint64_t)c->Dr3,(uint64_t)c->Dr6,(uint64_t)c->Dr7,(unsigned long)c->MxCsr,c->FltSave.ControlWord,c->FltSave.StatusWord,(uint64_t)c->Rax,(uint64_t)c->Rbx,(uint64_t)c->Rcx,(uint64_t)c->Rdx,(uint64_t)c->Rbp,(uint64_t)c->Rsi,(uint64_t)c->Rdi,(uint64_t)c->R8,(uint64_t)c->R9,(uint64_t)c->R10,(uint64_t)c->R11,(uint64_t)c->R12,(uint64_t)c->R13,(uint64_t)c->R14,(uint64_t)c->R15);{
 unsigned j;
 /* Reopen the just-written JSON object to add complete legacy FP/XMM payload. */
 b->len--;b->s[b->len]=0;
 add(b,",\"x87_tag\":%u,\"x87_opcode\":%u,\"x87_error_offset\":%lu,\"x87_error_selector\":%u,\"x87_data_offset\":%lu,\"x87_data_selector\":%u,\"mxcsr_mask\":%lu,\"st_mmx\":[",c->FltSave.TagWord,c->FltSave.ErrorOpcode,(unsigned long)c->FltSave.ErrorOffset,c->FltSave.ErrorSelector,(unsigned long)c->FltSave.DataOffset,c->FltSave.DataSelector,(unsigned long)c->FltSave.MxCsr_Mask);
 for(j=0;j<8;j++){if(j)add(b,",");add(b,"[\"0x%" PRIx64 "\",\"0x%" PRIx64 "\"]",(uint64_t)c->FltSave.FloatRegisters[j].Low,(uint64_t)c->FltSave.FloatRegisters[j].High);}
 add(b,"],\"xmm\":[");for(j=0;j<16;j++){if(j)add(b,",");add(b,"[\"0x%" PRIx64 "\",\"0x%" PRIx64 "\"]",(uint64_t)c->FltSave.XmmRegisters[j].Low,(uint64_t)c->FltSave.XmmRegisters[j].High);}add(b,"]}");
 }}
static void context_cell(unsigned x){static const DWORD flags[]={CONTEXT_CONTROL,CONTEXT_INTEGER,CONTEXT_SEGMENTS,CONTEXT_FLOATING_POINT,CONTEXT_DEBUG_REGISTERS,CONTEXT_ALL};CONTEXT a,b;OwnedThread t=make_thread();BOOL ga=FALSE,se=FALSE,gb=FALSE;DWORD e;
 if(!t.h){failed(GetLastError());return;}memset(&a,0,sizeof(a));memset(&b,0,sizeof(b));a.ContextFlags=flags[x];b.ContextFlags=flags[x];SetLastError(0);ga=GetThreadContext(t.h,&a);if(ga)se=SetThreadContext(t.h,&a);if(se)gb=GetThreadContext(t.h,&b);e=GetLastError();
 add(&raw,"\"requested_flags\":%lu,\"get_before\":%s,\"set\":%s,\"get_after\":%s,\"error\":%lu,\"before\":",(unsigned long)flags[x],jb(ga),jb(se),jb(gb),(unsigned long)((ga&&se&&gb)?0:e));context_dump(&raw,&a);add(&raw,",\"after\":");context_dump(&raw,&b);
 add(&norm,"\"roundtrip_calls_succeeded\":%s",jb(ga&&se&&gb));if(x==1||x==5)add(&norm,",\"integer_registers_preserved\":%s",jb(ga&&se&&gb&&a.Rax==b.Rax&&a.Rbx==b.Rbx&&a.Rcx==b.Rcx&&a.Rdx==b.Rdx&&a.Rbp==b.Rbp&&a.Rsi==b.Rsi&&a.Rdi==b.Rdi&&a.R8==b.R8&&a.R9==b.R9&&a.R10==b.R10&&a.R11==b.R11&&a.R12==b.R12&&a.R13==b.R13&&a.R14==b.R14&&a.R15==b.R15));
 if(x==0||x==5)add(&norm,",\"control_addresses_preserved\":%s",jb(a.Rip==b.Rip&&a.Rsp==b.Rsp));
 add(&comparison,"\"context_flags_equal\":%s,\"eflags_equal\":%s,\"segments_equal\":%s,\"debug_registers_equal\":%s,\"mxcsr_equal\":%s,\"x87_control_equal\":%s,\"x87_status_equal\":%s",jb(a.ContextFlags==b.ContextFlags),jb(a.EFlags==b.EFlags),jb(a.SegCs==b.SegCs&&a.SegSs==b.SegSs&&a.SegDs==b.SegDs&&a.SegEs==b.SegEs&&a.SegFs==b.SegFs&&a.SegGs==b.SegGs),jb(a.Dr0==b.Dr0&&a.Dr1==b.Dr1&&a.Dr2==b.Dr2&&a.Dr3==b.Dr3&&a.Dr6==b.Dr6&&a.Dr7==b.Dr7),jb(a.MxCsr==b.MxCsr),jb(a.FltSave.ControlWord==b.FltSave.ControlWord),jb(a.FltSave.StatusWord==b.FltSave.StatusWord));
 dispose_thread(t);
}
static void teb_cell(unsigned x){if(x==0){ULONG_PTR low=0,high=0;BYTE local;if(!stacklimits){unsup("GetCurrentThreadStackLimits_absent");return;}stacklimits(&low,&high);add(&raw,"\"stack_low\":\"0x%" PRIxPTR "\",\"stack_high\":\"0x%" PRIxPTR "\",\"local\":\"0x%" PRIxPTR "\"",(uintptr_t)low,(uintptr_t)high,(uintptr_t)&local);add(&norm,"\"local_within_stack_limits\":%s",jb(low<(uintptr_t)&local&&(uintptr_t)&local<high));}
 else if(x==1){DWORD slot=TlsAlloc();uintptr_t sentinel=0x0087;BOOL ok;void *got;if(slot==TLS_OUT_OF_INDEXES){failed(GetLastError());return;}ok=TlsSetValue(slot,&sentinel);got=TlsGetValue(slot);add(&raw,"\"tls_slot\":%lu,\"set_ok\":%s,\"value\":\"0x%" PRIxPTR "\"",(unsigned long)slot,jb(ok),(uintptr_t)got);add(&norm,"\"tls_roundtrip\":%s",jb(ok&&got==&sentinel));TlsFree(slot);}
 else if(x==2){add(&raw,"\"pid\":%lu,\"tid\":%lu,\"thread_handle_tid\":%lu",(unsigned long)selfpid,(unsigned long)GetCurrentThreadId(),(unsigned long)GetThreadId(GetCurrentThread()));add(&norm,"\"thread_ids_agree\":%s",jb(GetThreadId(GetCurrentThread())==GetCurrentThreadId()));}
 else unsup("direct_TEB_fields_documentation_says_use_APIs_reserved_stack_and_ID_fields_not_read");}
static void suspend_cell(void){OwnedThread t=make_thread();DWORD s,r1,r2;int ok;if(!t.h){failed(GetLastError());return;}s=SuspendThread(t.h);r1=ResumeThread(t.h);r2=ResumeThread(t.h);ok=s==1&&r1==2&&r2==1;add(&raw,"\"create_suspended_initial\":1,\"suspend_previous\":%lu,\"resume1_previous\":%lu,\"resume2_previous\":%lu",(unsigned long)s,(unsigned long)r1,(unsigned long)r2);add(&norm,"\"suspend_count_sequence\":%s",jb(ok));if(!ok){fputs("unexpected suspend sequence; terminating observer without further mutations\n",stderr);exit(4);}if(WaitForSingleObject(t.h,5000)!=WAIT_OBJECT_0)exit(4);CloseHandle(t.h);}
static void priority_cell(unsigned x){static const int pri[]={THREAD_PRIORITY_IDLE,THREAD_PRIORITY_LOWEST,THREAD_PRIORITY_BELOW_NORMAL,THREAD_PRIORITY_NORMAL,THREAD_PRIORITY_ABOVE_NORMAL,THREAD_PRIORITY_HIGHEST,THREAD_PRIORITY_TIME_CRITICAL};OwnedThread t=make_thread();int before,after,restored;BOOL ok,restore;DWORD e;if(!t.h){failed(GetLastError());return;}before=GetThreadPriority(t.h);SetLastError(0);ok=SetThreadPriority(t.h,pri[x]);e=GetLastError();after=GetThreadPriority(t.h);restore=SetThreadPriority(t.h,before);restored=GetThreadPriority(t.h);add(&raw,"\"requested\":%d,\"before\":%d,\"after\":%d,\"restored\":%d,\"set_ok\":%s,\"error\":%lu",pri[x],before,after,restored,jb(ok),(unsigned long)(ok?0:e));add(&norm,"\"successful_set_matches_readback\":%s,\"original_priority_restored\":%s",jb(ok&&after==pri[x]),jb(restore&&restored==before));dispose_thread(t);}
typedef struct{HMODULE m[MOD_CAP];unsigned n;int complete;DWORD error;} Modules;
static Modules modules_psapi(void){Modules a;DWORD need=0;memset(&a,0,sizeof(a));a.complete=EnumProcessModules(GetCurrentProcess(),a.m,sizeof(a.m),&need);a.error=a.complete?0:GetLastError();a.n=need/sizeof(HMODULE);if(a.n>MOD_CAP){a.n=MOD_CAP;a.complete=0;}return a;}
static int has_module(const Modules *a,HMODULE m){unsigned i;for(i=0;i<a->n;i++)if(a->m[i]==m)return 1;return 0;}
static void push_module(Modules *a,HMODULE m){if(has_module(a,m))return;if(a->n>=MOD_CAP){a->complete=0;return;}a->m[a->n++]=m;}
static Modules modules_toolhelp(void){Modules a;MODULEENTRY32W e;HANDLE h;memset(&a,0,sizeof(a));a.complete=1;h=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,selfpid);if(h==INVALID_HANDLE_VALUE){a.complete=0;a.error=GetLastError();return a;}memset(&e,0,sizeof(e));e.dwSize=sizeof(e);if(Module32FirstW(h,&e)){do{push_module(&a,e.hModule);e.dwSize=sizeof(e);}while(Module32NextW(h,&e));if(GetLastError()!=ERROR_NO_MORE_FILES){a.complete=0;a.error=GetLastError();}}else{a.complete=0;a.error=GetLastError();}CloseHandle(h);return a;}
static Modules modules_virtual(void){Modules a;uintptr_t p=(uintptr_t)nativeinfo.lpMinimumApplicationAddress,end=(uintptr_t)nativeinfo.lpMaximumApplicationAddress;MEMORY_BASIC_INFORMATION v;memset(&a,0,sizeof(a));a.complete=1;while(p<end){uintptr_t next;if(!VirtualQuery((void*)p,&v,sizeof(v))){a.complete=0;a.error=GetLastError();break;}if(v.Type==MEM_IMAGE)push_module(&a,(HMODULE)v.AllocationBase);next=(uintptr_t)v.BaseAddress+v.RegionSize;if(next<=p){a.complete=0;break;}p=next;}return a;}
static Modules modules_peb(void){Modules a;OwnPbi p;PEB b;PEB_LDR_DATA ld;LIST_ENTRY *head,*cur;unsigned steps=0;memset(&a,0,sizeof(a));a.complete=1;
 if(!getpbi(&p)||!ownread(p.PebBaseAddress,&b,sizeof(b))||!b.Ldr||!ownread(b.Ldr,&ld,sizeof(ld))){a.complete=0;return a;}
 head=&b.Ldr->InMemoryOrderModuleList;cur=ld.InMemoryOrderModuleList.Flink;
 while(cur!=head){LDR_DATA_TABLE_ENTRY e;void *ep=(BYTE*)cur-offsetof(LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks);if(++steps>MOD_CAP||!ownread(ep,&e,sizeof(e))){a.complete=0;break;}push_module(&a,(HMODULE)e.DllBase);cur=e.InMemoryOrderLinks.Flink;}
 return a;
}
static void modules_raw(Buf *b,const Modules *a){unsigned i;add(b,"{\"complete\":%s,\"error\":%lu,\"count\":%u,\"modules\":[",jb(a->complete),(unsigned long)a->error,a->n);for(i=0;i<a->n;i++){if(i)add(b,",");pointer(b,a->m[i]);}add(b,"]}");}
static int subset(const Modules *a,const Modules *b){unsigned i;for(i=0;i<a->n;i++)if(!has_module(b,a->m[i]))return 0;return 1;}
static void module_inventory(void){Modules p=modules_psapi(),t=modules_toolhelp(),v=modules_virtual(),l=modules_peb();int complete=p.complete&&t.complete&&v.complete&&l.complete;
 add(&raw,"\"psapi\":");modules_raw(&raw,&p);add(&raw,",\"toolhelp\":");modules_raw(&raw,&t);add(&raw,",\"mem_image\":");modules_raw(&raw,&v);add(&raw,",\"peb_in_memory_order\":");modules_raw(&raw,&l);
 add(&norm,"\"psapi_toolhelp_same_set\":%s,\"psapi_peb_same_set\":%s,\"loader_modules_are_mem_image\":%s",jb(subset(&p,&t)&&subset(&t,&p)),jb(subset(&p,&l)&&subset(&l,&p)),jb(subset(&p,&v)));
 if(!complete)unsup("module_enumeration_failed_or_exceeded_256_modules");
 /* Extra SEC_IMAGE mappings need not be loader modules; do not assert reverse subset. */
}
static int image_header(HMODULE m,IMAGE_DOS_HEADER *d,IMAGE_NT_HEADERS64 *n){if(!ownread(m,d,sizeof(*d))||d->e_magic!=IMAGE_DOS_SIGNATURE||d->e_lfanew<0||d->e_lfanew>HEADER_CAP-(int)sizeof(*n))return 0;if(!ownread((BYTE*)m+d->e_lfanew,n,sizeof(*n)))return 0;return n->Signature==IMAGE_NT_SIGNATURE&&n->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC&&n->FileHeader.SizeOfOptionalHeader>=sizeof(IMAGE_OPTIONAL_HEADER64)&&n->OptionalHeader.SizeOfImage>=sizeof(*n);}
static void pe_fields(Buf *b,const IMAGE_NT_HEADERS64 *n){add(b,"{\"machine\":%u,\"sections\":%u,\"timestamp\":%lu,\"characteristics\":%u,\"optional_magic\":%u,\"preferred_base\":\"0x%" PRIx64 "\",\"entry_rva\":%lu,\"image_size\":%lu,\"headers_size\":%lu,\"section_alignment\":%lu,\"file_alignment\":%lu,\"checksum\":%lu,\"dll_characteristics\":%u,\"subsystem\":%u}",n->FileHeader.Machine,n->FileHeader.NumberOfSections,(unsigned long)n->FileHeader.TimeDateStamp,n->FileHeader.Characteristics,n->OptionalHeader.Magic,(uint64_t)n->OptionalHeader.ImageBase,(unsigned long)n->OptionalHeader.AddressOfEntryPoint,(unsigned long)n->OptionalHeader.SizeOfImage,(unsigned long)n->OptionalHeader.SizeOfHeaders,(unsigned long)n->OptionalHeader.SectionAlignment,(unsigned long)n->OptionalHeader.FileAlignment,(unsigned long)n->OptionalHeader.CheckSum,n->OptionalHeader.DllCharacteristics,n->OptionalHeader.Subsystem);}
static int same_headers(const IMAGE_NT_HEADERS64 *a,const IMAGE_NT_HEADERS64 *b){return a->FileHeader.Machine==b->FileHeader.Machine&&a->FileHeader.NumberOfSections==b->FileHeader.NumberOfSections&&a->FileHeader.TimeDateStamp==b->FileHeader.TimeDateStamp&&a->FileHeader.Characteristics==b->FileHeader.Characteristics&&a->OptionalHeader.Magic==b->OptionalHeader.Magic&&a->OptionalHeader.AddressOfEntryPoint==b->OptionalHeader.AddressOfEntryPoint&&a->OptionalHeader.SizeOfImage==b->OptionalHeader.SizeOfImage&&a->OptionalHeader.SizeOfHeaders==b->OptionalHeader.SizeOfHeaders&&a->OptionalHeader.SectionAlignment==b->OptionalHeader.SectionAlignment&&a->OptionalHeader.FileAlignment==b->OptionalHeader.FileAlignment&&a->OptionalHeader.CheckSum==b->OptionalHeader.CheckSum&&a->OptionalHeader.DllCharacteristics==b->OptionalHeader.DllCharacteristics&&a->OptionalHeader.Subsystem==b->OptionalHeader.Subsystem;}
static void module_headers(void){Modules a=modules_psapi();unsigned i;int all=1,complete=a.complete;BYTE *file=(BYTE*)malloc(HEADER_CAP);if(!file)exit(3);add(&raw,"\"modules\":[");
 for(i=0;i<a.n;i++){IMAGE_DOS_HEADER d;IMAGE_NT_HEADERS64 n;WCHAR path[32768];HANDLE h;DWORD got=0,plen=0;int readok=0;if(i)add(&raw,",");add(&raw,"{\"module\":");pointer(&raw,a.m[i]);
  if(!image_header(a.m[i],&d,&n)){add(&raw,",\"error\":\"memory_header_invalid\"}");all=0;continue;}
  add(&raw,",\"memory\":");pe_fields(&raw,&n);add(&raw,",\"relocation_delta\":\"0x%" PRIx64 "\"",(uint64_t)(uintptr_t)a.m[i]-n.OptionalHeader.ImageBase);
  if((plen=GetModuleFileNameW(a.m[i],path,32768))>0&&plen<32768){h=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(h!=INVALID_HANDLE_VALUE){readok=ReadFile(h,file,HEADER_CAP,&got,NULL);CloseHandle(h);}}
  if(readok&&got>=sizeof(IMAGE_DOS_HEADER)){IMAGE_DOS_HEADER *fd=(IMAGE_DOS_HEADER*)file;if(fd->e_magic==IMAGE_DOS_SIGNATURE&&fd->e_lfanew>=0&&(uint64_t)fd->e_lfanew+sizeof(IMAGE_NT_HEADERS64)<=got){IMAGE_NT_HEADERS64 *fn=(IMAGE_NT_HEADERS64*)(file+fd->e_lfanew);int equal=fn->Signature==IMAGE_NT_SIGNATURE&&fn->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC&&fn->FileHeader.SizeOfOptionalHeader>=sizeof(IMAGE_OPTIONAL_HEADER64)&&same_headers(&n,fn);add(&raw,",\"file\":");pe_fields(&raw,fn);add(&raw,",\"stable_fields_equal\":%s",jb(equal));if(!equal)all=0;}else{add(&raw,",\"error\":\"file_header_outside_bound\"");complete=0;}}
  else{add(&raw,",\"error\":\"own_module_file_unreadable\"");complete=0;}add(&raw,"}");
 }add(&raw,"]");add(&norm,"\"stable_header_fields_match\":%s",jb(all));if(!complete)unsup("module_header_read_failed_or_bound_exceeded");free(file);
}
static void module_sections(void){Modules a=modules_psapi();unsigned i;int bounded=1;add(&raw,"\"modules\":[");
 for(i=0;i<a.n;i++){IMAGE_DOS_HEADER d;IMAGE_NT_HEADERS64 n;unsigned j;if(i)add(&raw,",");add(&raw,"{\"module\":");pointer(&raw,a.m[i]);add(&raw,",\"sections\":[");
  if(!image_header(a.m[i],&d,&n)||n.FileHeader.NumberOfSections>96){bounded=0;add(&raw,"]}");continue;}
  for(j=0;j<n.FileHeader.NumberOfSections;j++){IMAGE_SECTION_HEADER s;MEMORY_BASIC_INFORMATION v;uintptr_t addr;SIZE_T queried;void *at=(BYTE*)a.m[i]+d.e_lfanew+4+sizeof(IMAGE_FILE_HEADER)+n.FileHeader.SizeOfOptionalHeader+j*sizeof(s);if(j)add(&raw,",");if(!ownread(at,&s,sizeof(s))){add(&raw,"{\"error\":\"unreadable_section_header\"}");bounded=0;continue;}addr=(uintptr_t)a.m[i]+s.VirtualAddress;memset(&v,0,sizeof(v));queried=VirtualQuery((void*)addr,&v,sizeof(v));if(!queried)bounded=0;add(&raw,"{\"name\":");{char nm[9];memcpy(nm,s.Name,8);nm[8]=0;quote(&raw,nm);}add(&raw,",\"rva\":%lu,\"virtual_size\":%lu,\"raw_size\":%lu,\"characteristics\":\"0x%08lx\",\"memory_state\":%lu,\"memory_type\":%lu,\"memory_protect\":%lu,\"allocation_protect\":%lu}",(unsigned long)s.VirtualAddress,(unsigned long)s.Misc.VirtualSize,(unsigned long)s.SizeOfRawData,(unsigned long)s.Characteristics,(unsigned long)v.State,(unsigned long)v.Type,(unsigned long)v.Protect,(unsigned long)v.AllocationProtect);
    {uint64_t end=(uint64_t)s.VirtualAddress+s.Misc.VirtualSize;uintptr_t scan=addr;unsigned regions=0;
     raw.len--;raw.s[raw.len]=0;add(&raw,",\"regions\":[");
     if(end<=n.OptionalHeader.SizeOfImage)while((uint64_t)(scan-(uintptr_t)a.m[i])<end){
      MEMORY_BASIC_INFORMATION rv;uintptr_t next;SIZE_T rr=VirtualQuery((void*)scan,&rv,sizeof(rv));
      if(!rr||!rv.RegionSize){bounded=0;break;}next=(uintptr_t)rv.BaseAddress+rv.RegionSize;
      if(next<=scan||++regions>65536){bounded=0;break;}if(regions>1)add(&raw,",");
      add(&raw,"{\"offset\":%" PRIuPTR ",\"region_size\":%" PRIuPTR ",\"state\":%lu,\"type\":%lu,\"protect\":%lu}",scan-(uintptr_t)a.m[i],(uintptr_t)rv.RegionSize,(unsigned long)rv.State,(unsigned long)rv.Type,(unsigned long)rv.Protect);scan=next;
     }add(&raw,"]}");
    }if(s.Misc.VirtualSize&&(s.VirtualAddress>=n.OptionalHeader.SizeOfImage||(uint64_t)s.VirtualAddress+s.Misc.VirtualSize>n.OptionalHeader.SizeOfImage))bounded=0;
  }add(&raw,"]}");
 }add(&raw,"]");add(&norm,"\"section_rvas_inside_images\":%s",jb(bounded));if(!a.complete)unsup("module_enumeration_incomplete");
 /* Section characteristics are not blindly equated to current page rights:
  * discardable sections, page sharing, COW and runtime protections are legal. */
}
static void module_address(unsigned x){Modules a=modules_psapi();unsigned i;int agree=1;if(x==1&&!pcheader){unsup("RtlPcToFileHeader_absent");return;}if(x==2&&!lookup){unsup("RtlLookupFunctionEntry_absent");return;}add(&raw,"\"modules\":[");
 for(i=0;i<a.n;i++){IMAGE_DOS_HEADER d;IMAGE_NT_HEADERS64 n;unsigned j;DWORD rvas[3];if(i)add(&raw,",");add(&raw,"{\"module\":");pointer(&raw,a.m[i]);add(&raw,",\"samples\":[");if(!image_header(a.m[i],&d,&n)){agree=0;add(&raw,"]}");continue;}rvas[0]=0;if(n.OptionalHeader.AddressOfEntryPoint>=n.OptionalHeader.SizeOfImage){agree=0;add(&raw,"]}");continue;}rvas[1]=n.OptionalHeader.AddressOfEntryPoint;rvas[2]=n.OptionalHeader.SizeOfImage-1;
  for(j=0;j<3;j++){void *p=(BYTE*)a.m[i]+rvas[j];if(j)add(&raw,",");add(&raw,"{\"rva\":%lu",(unsigned long)rvas[j]);if(x==0){HMODULE got=NULL;BOOL ok=GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCWSTR)p,&got);add(&raw,",\"ok\":%s,\"result\":",jb(ok));pointer(&raw,got);if(!ok||got!=a.m[i])agree=0;}
   else if(x==1){PVOID base=NULL,r=pcheader(p,&base);add(&raw,",\"result\":");pointer(&raw,r);add(&raw,",\"base\":");pointer(&raw,base);if(r!=a.m[i]||base!=a.m[i])agree=0;}
   else{DWORD64 base=0;PRUNTIME_FUNCTION f=lookup((DWORD64)(uintptr_t)p,&base,NULL);add(&raw,",\"image_base\":");pointer(&raw,(void*)(uintptr_t)base);add(&raw,",\"entry\":");pointer(&raw,f);if(f){RUNTIME_FUNCTION v;if(ownread(f,&v,sizeof(v))){add(&raw,",\"begin_rva\":%lu,\"end_rva\":%lu,\"unwind_rva\":%lu",(unsigned long)v.BeginAddress,(unsigned long)v.EndAddress,(unsigned long)v.UnwindData);if(v.BeginAddress>rvas[j]||v.EndAddress<=rvas[j])agree=0;}else agree=0;}}
   add(&raw,"}");}add(&raw,"]}");}
 add(&raw,"]");add(&norm,x==2?"\"returned_function_ranges_cover_pc\":%s":"\"address_lookups_agree\":%s",jb(agree));if(!a.complete)unsup("module_enumeration_incomplete");
}
static int rva_read(HMODULE m,DWORD image,DWORD rva,void *p,size_t size){return rva<=image&&size<=(size_t)image-rva&&ownread((BYTE*)m+rva,p,size);}
static int rva_string(HMODULE m,DWORD image,DWORD rva,char *s,size_t cap){size_t i;for(i=0;i+1<cap;i++){if((uint64_t)rva+i>=image||!ownread((BYTE*)m+rva+i,s+i,1))return 0;if(s[i]==0)return 1;}s[cap-1]=0;return 0;}
static void exports_cell(unsigned x){const WCHAR *names[]={L"kernel32.dll",L"ntdll.dll",L"user32.dll"};HMODULE m=GetModuleHandleW(names[x]);IMAGE_DOS_HEADER d;IMAGE_NT_HEADERS64 n;IMAGE_DATA_DIRECTORY dir;IMAGE_EXPORT_DIRECTORY e;unsigned i,total=0,inside=0,outside=0,forwarded=0,missing=0,ordinal_only=0,eat_nonzero=0;BYTE seen[EXPORT_CAP]={0};int well=1,first=1;
 if(!m){unsup("target_module_not_loaded");return;}if(!image_header(m,&d,&n)){unsup("module_header_unreadable");return;}dir=n.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];if(!dir.VirtualAddress||!rva_read(m,n.OptionalHeader.SizeOfImage,dir.VirtualAddress,&e,sizeof(e))){unsup("export_directory_unavailable");return;}
 if(e.NumberOfNames>EXPORT_CAP||e.NumberOfFunctions>EXPORT_CAP){unsup("export_count_exceeds_65536_bound");return;}if((uint64_t)e.AddressOfNames+(uint64_t)e.NumberOfNames*4>n.OptionalHeader.SizeOfImage||(uint64_t)e.AddressOfNameOrdinals+(uint64_t)e.NumberOfNames*2>n.OptionalHeader.SizeOfImage||(uint64_t)e.AddressOfFunctions+(uint64_t)e.NumberOfFunctions*4>n.OptionalHeader.SizeOfImage){unsup("export_table_bounds_invalid");return;}add(&raw,"\"module\":");pointer(&raw,m);add(&raw,",\"exceptions\":[");
 for(i=0;i<e.NumberOfNames;i++){DWORD nr,fr;WORD ord;char name[1024],fwd[1024];FARPROC p;int isfwd,isinside;
  if(!rva_read(m,n.OptionalHeader.SizeOfImage,e.AddressOfNames+i*4,&nr,4)||!rva_read(m,n.OptionalHeader.SizeOfImage,e.AddressOfNameOrdinals+i*2,&ord,2)||ord>=e.NumberOfFunctions||!rva_read(m,n.OptionalHeader.SizeOfImage,e.AddressOfFunctions+ord*4,&fr,4)||!rva_string(m,n.OptionalHeader.SizeOfImage,nr,name,sizeof(name))){well=0;break;}
  seen[ord]=1;p=GetProcAddress(m,name);total++;isfwd=fr>=dir.VirtualAddress&&(uint64_t)fr<(uint64_t)dir.VirtualAddress+dir.Size;isinside=(uintptr_t)p>=(uintptr_t)m&&(uintptr_t)p<(uintptr_t)m+n.OptionalHeader.SizeOfImage;
  if(isfwd)forwarded++;if(!p)missing++;else if(isinside)inside++;else outside++;
  if(isfwd||!isinside){if(!first)add(&raw,",");first=0;add(&raw,"{\"export\":");quote(&raw,name);add(&raw,",\"ordinal\":%lu,\"export_rva\":%lu,\"forwarder\":",(unsigned long)(ord+e.Base),(unsigned long)fr);if(isfwd&&rva_string(m,n.OptionalHeader.SizeOfImage,fr,fwd,sizeof(fwd)))quote(&raw,fwd);else add(&raw,"null");add(&raw,",\"resolved\":");pointer(&raw,(void*)(uintptr_t)p);add(&raw,"}");}
 }
 for(i=0;i<e.NumberOfFunctions;i++){
  DWORD fr;char fwd[1024];FARPROC p;int isfwd,isinside;uint64_t ordinal=(uint64_t)e.Base+i;
  if(!rva_read(m,n.OptionalHeader.SizeOfImage,e.AddressOfFunctions+i*4,&fr,4)){well=0;break;}
  if(!fr)continue;eat_nonzero++;if(seen[i])continue;
  if(ordinal>65535){well=0;break;}
  ordinal_only++;p=GetProcAddress(m,(LPCSTR)(uintptr_t)ordinal);
  isfwd=fr>=dir.VirtualAddress&&(uint64_t)fr<(uint64_t)dir.VirtualAddress+dir.Size;
  isinside=(uintptr_t)p>=(uintptr_t)m&&(uintptr_t)p<(uintptr_t)m+n.OptionalHeader.SizeOfImage;
  if(isfwd)forwarded++;if(!p)missing++;else if(isinside)inside++;else outside++;
  if(isfwd||!isinside){if(!first)add(&raw,",");first=0;add(&raw,"{\"export\":null,\"ordinal\":%" PRIu64 ",\"export_rva\":%lu,\"forwarder\":",ordinal,(unsigned long)fr);if(isfwd&&rva_string(m,n.OptionalHeader.SizeOfImage,fr,fwd,sizeof(fwd)))quote(&raw,fwd);else add(&raw,"null");add(&raw,",\"resolved\":");pointer(&raw,(void*)(uintptr_t)p);add(&raw,"}");}
 }
 add(&raw,"],\"named_exports\":%lu,\"functions_including_ordinal_only\":%lu,\"visited\":%u,\"inside\":%u,\"outside\":%u,\"forwarders\":%u,\"unresolved\":%u",(unsigned long)e.NumberOfNames,(unsigned long)e.NumberOfFunctions,total,inside,outside,forwarded,missing);
 add(&raw,",\"ordinal_only_visited\":%u,\"nonzero_eat_slots\":%u",ordinal_only,eat_nonzero);add(&norm,"\"export_tables_well_formed\":%s,\"all_named_exports_visited\":%s,\"all_eat_slots_visited\":%s",jb(well),jb(total==e.NumberOfNames),jb(i==e.NumberOfFunctions));if(!well)unsup("export_parser_bound_or_unreadable_image");
}
typedef struct{DWORD code,flags,count;ULONG_PTR params[EXCEPTION_MAXIMUM_PARAMETERS];void *address;} CloseException;
static CloseException close_ex;
#if defined(_MSC_VER)||defined(__clang__)
static LONG close_filter(EXCEPTION_POINTERS *p){DWORD c=p->ExceptionRecord->ExceptionCode;unsigned i;if(c!=0xc0000008U&&c!=0xc0000235U)return EXCEPTION_CONTINUE_SEARCH;close_ex.code=c;close_ex.flags=p->ExceptionRecord->ExceptionFlags;close_ex.address=p->ExceptionRecord->ExceptionAddress;close_ex.count=p->ExceptionRecord->NumberParameters;for(i=0;i<close_ex.count&&i<EXCEPTION_MAXIMUM_PARAMETERS;i++)close_ex.params[i]=p->ExceptionRecord->ExceptionInformation[i];return EXCEPTION_EXECUTE_HANDLER;}
static void guarded_close(HANDLE h,int native,BOOL *ok,LONG *st){__try{if(native)*st=nclose(h);else *ok=CloseHandle(h);}__except(close_filter(GetExceptionInformation())){}}
#endif
static void close_cell(unsigned x){unsigned api=x/3,kind=x%3,i;HANDLE h=NULL;BOOL ok=FALSE,protectok=TRUE;LONG st=(LONG)0xc0000001U;DWORD err=0,flags=0,strict=0;int strict_known=0;
 if(api&&!nclose){unsup("NtClose_absent");return;}
#if !defined(_MSC_VER)&&!defined(__clang__)
 if(kind){unsup("compiler_has_no_supported_SEH_exception_capture");return;}
#endif
 if(kind){strict_known=mitpolicy&&mitpolicy(GetCurrentProcess(),3,&strict,sizeof(strict));if(!strict_known||strict){add(&raw,"\"strict_policy_known\":%s,\"strict_policy_flags\":%lu",jb(strict_known),(unsigned long)strict);unsup("exceptional_close_skipped_when_strict_policy_unknown_or_enabled");return;}}
 if(kind!=1){h=CreateEventW(NULL,TRUE,FALSE,NULL);if(!h){failed(GetLastError());return;}if(kind==2)protectok=SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,HANDLE_FLAG_PROTECT_FROM_CLOSE);}
 if(!protectok){DWORD pe=GetLastError();CloseHandle(h);failed(pe);return;}memset(&close_ex,0,sizeof(close_ex));SetLastError(0);
#if defined(_MSC_VER)||defined(__clang__)
 guarded_close(h,(int)api,&ok,&st);
#else
 if(api)st=nclose(h);else ok=CloseHandle(h);
#endif
 err=GetLastError();
 add(&comparison,"\"returned_normally\":%s,\"returned_success\":",jb(!close_ex.code));
 if(close_ex.code)add(&comparison,"null");else add(&comparison,"%s",jb(api?st>=0:ok));
 add(&comparison,",\"return_status\":");
 if(close_ex.code)add(&comparison,"null");else add(&comparison,"\"0x%08lx\"",(unsigned long)(ULONG)(api?st:(ok?0:err)));
 add(&comparison,",\"exception_code\":\"0x%08lx\"",(unsigned long)close_ex.code);
 add(&raw,"\"api\":\"%s\",\"kind\":%u,\"returned_normally\":%s,\"win32_ok\":",api?"NtClose":"CloseHandle",kind,jb(!close_ex.code));
 if(api||close_ex.code)add(&raw,"null");else add(&raw,"%s",jb(ok));
 add(&raw,",\"ntstatus\":");if(!api||close_ex.code)add(&raw,"null");else add(&raw,"\"0x%08lx\"",(unsigned long)(ULONG)st);
 add(&raw,",\"last_error\":");if(api||close_ex.code||ok)add(&raw,"null");else add(&raw,"%lu",(unsigned long)err);
 add(&raw,",\"exception\":{\"code\":\"0x%08lx\",\"flags\":%lu,\"address\":",(unsigned long)close_ex.code,(unsigned long)close_ex.flags);pointer(&raw,close_ex.address);add(&raw,",\"parameters\":[");
 for(i=0;i<close_ex.count&&i<EXCEPTION_MAXIMUM_PARAMETERS;i++){if(i)add(&raw,",");add(&raw,"\"0x%" PRIxPTR "\"",(uintptr_t)close_ex.params[i]);}add(&raw,"]}");

 if(kind==0)add(&norm,"\"valid_close_succeeded\":%s",jb(!close_ex.code&&(api?st>=0:ok)));
 else if(kind==1)add(&norm,"\"invalid_close_not_success\":%s",jb(close_ex.code||(api?st<0:!ok)));
 else{BOOL survived=GetHandleInformation(h,&flags);add(&raw,",\"handle_survived\":%s",jb(survived));add(&norm,"\"protected_handle_survived\":%s",jb(survived));if(survived){SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,0);CloseHandle(h);}}
}
static void duplicate_cell(unsigned x){HANDLE h=NULL;BOOL ok;DWORD flags=0,id=0;ok=DuplicateHandle(GetCurrentProcess(),x?GetCurrentThread():GetCurrentProcess(),GetCurrentProcess(),&h,0,FALSE,DUPLICATE_SAME_ACCESS);if(ok){GetHandleInformation(h,&flags);id=x?GetThreadId(h):GetProcessId(h);}add(&raw,"\"ok\":%s,\"flags\":%lu,\"id\":%lu",jb(ok),(unsigned long)flags,(unsigned long)id);add(&norm,"\"duplicate_valid\":%s,\"identity_matches_self\":%s",jb(ok),jb(ok&&id==(x?GetCurrentThreadId():selfpid)));if(h)CloseHandle(h);}
static void handle_flags(unsigned x){HANDLE h=CreateEventW(NULL,TRUE,FALSE,NULL);DWORD want=(x&1?HANDLE_FLAG_INHERIT:0)|(x&2?HANDLE_FLAG_PROTECT_FROM_CLOSE:0),got=0;BOOL set=FALSE,get=FALSE;if(!h){failed(GetLastError());return;}set=SetHandleInformation(h,HANDLE_FLAG_INHERIT|HANDLE_FLAG_PROTECT_FROM_CLOSE,want);get=GetHandleInformation(h,&got);add(&raw,"\"requested\":%lu,\"actual\":%lu,\"set\":%s,\"get\":%s",(unsigned long)want,(unsigned long)got,jb(set),jb(get));add(&norm,"\"handle_flags_roundtrip\":%s",jb(set&&get&&got==want));SetHandleInformation(h,HANDLE_FLAG_PROTECT_FROM_CLOSE,0);CloseHandle(h);}
static void object_cell(unsigned x){unsigned kind=x/2,c=x%2?2:0;HANDLE h=NULL;union{uint64_t align;BYTE b[65536];}u;LONG st;ULONG len=0;memset(&u,0,sizeof(u));if(!qobj){unsup("NtQueryObject_absent");return;}
 if(kind==0)h=CreateEventW(NULL,TRUE,FALSE,NULL);else if(kind==1)h=CreateMutexW(NULL,FALSE,NULL);else if(kind==2)h=CreateSemaphoreW(NULL,0,1,NULL);else DuplicateHandle(GetCurrentProcess(),kind==3?GetCurrentProcess():GetCurrentThread(),GetCurrentProcess(),&h,0,FALSE,DUPLICATE_SAME_ACCESS);
 if(!h){failed(GetLastError());return;}st=qobj(h,c,u.b,sizeof(u),&len);add(&raw,"\"class\":%u,\"ntstatus\":\"0x%08lx\",\"return_length\":%lu",c,(unsigned long)(ULONG)st,(unsigned long)len);if(st<0)unsup("object_information_unavailable");
 else if(c==0){ULONG *p=(ULONG*)u.b;if(len<16||len>sizeof(u)){unsup("basic_object_result_length_invalid");CloseHandle(h);return;}add(&raw,",\"attributes\":%lu,\"granted_access\":%lu,\"handle_count\":%lu,\"pointer_count\":%lu",(unsigned long)p[0],(unsigned long)p[1],(unsigned long)p[2],(unsigned long)p[3]);add(&norm,"\"own_handle_count_positive\":%s,\"object_reference_count_positive\":%s",jb(p[2]>=1),jb(p[3]>=1));}
 else{UNICODE_STRING *s=(UNICODE_STRING*)u.b;int bound=len>=sizeof(UNICODE_STRING)&&len<=sizeof(u)&&(uintptr_t)s->Buffer>=(uintptr_t)u.b&&(uintptr_t)s->Buffer<=(uintptr_t)u.b+len&&s->Length<=(uintptr_t)u.b+len-(uintptr_t)s->Buffer&&s->Length<=s->MaximumLength&&(s->Length&1)==0;add(&raw,",\"type_name\":");if(bound)wquote(&raw,s->Buffer,s->Length/2);else add(&raw,"null");if(bound){add(&comparison,"\"type_name\":");wquote(&comparison,s->Buffer,s->Length/2);}add(&norm,"\"type_name_buffer_bounded\":%s,\"type_name_nonempty\":%s",jb(bound),jb(bound&&s->Length>0));}CloseHandle(h);
}
static int clock_value(unsigned x,uint64_t *v){LARGE_INTEGER l;FILETIME f;ULONGLONG u=0;switch(x){case 0:if(!QueryPerformanceCounter(&l))return 0;*v=(uint64_t)l.QuadPart;return 1;case 1:*v=GetTickCount64();return 1;case 2:GetSystemTimeAsFileTime(&f);*v=ft64(f);return 1;case 3:if(!precise)return 0;precise(&f);*v=ft64(f);return 1;case 4:if(!QueryUnbiasedInterruptTime(&u))return 0;*v=u;return 1;case 5:if(!mmtime)return 0;*v=mmtime();return 1;default:if(!ntime||ntime(&l)<0)return 0;*v=(uint64_t)l.QuadPart;return 1;}}
static double clock_units(unsigned x,LONGLONG fq){return x==0?(double)fq:x==1||x==5?1000.0:10000000.0;}
static int cmp_u64(const void *a,const void *b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return x<y?-1:x>y;}
static void timing(unsigned id,const char *kind,unsigned source,const uint64_t *values,unsigned count,LONGLONG fq){unsigned i;printf("TIMING {\"cell\":%u,\"kind\":\"%s\",\"source\":%u,\"qpc_frequency\":%" PRId64 ",\"samples\":[",id,kind,source,(int64_t)fq);for(i=0;i<count;i++)printf("%s%" PRIu64,i?",":"",values[i]);puts("]}");}
static void clock_cell(unsigned id,unsigned x){uint64_t before[7]={0},after[7]={0},q0=0,q1=0;int avail[7],ok;LARGE_INTEGER fq={0};unsigned i;double seconds,ratio;if(!QueryPerformanceFrequency(&fq)||!clock_value(0,&q0)){unsup("QPC_unavailable");return;}for(i=0;i<7;i++)avail[i]=clock_value(i,before+i);Sleep(100);for(i=0;i<7;i++)avail[i]=clock_value(i,after+i)&&avail[i];if(!clock_value(0,&q1)){unsup("QPC_read_failed");return;}ok=avail[x];add(&raw,"\"source\":");quote(&raw,clocknames[x]);add(&raw,",\"available\":[");for(i=0;i<7;i++)add(&raw,"%s%s",i?",":"",jb(avail[i]));add(&raw,"],\"before\":[");for(i=0;i<7;i++)add(&raw,"%s%" PRIu64,i?",":"",before[i]);add(&raw,"],\"after\":[");for(i=0;i<7;i++)add(&raw,"%s%" PRIu64,i?",":"",after[i]);add(&raw,"]");
 if(!ok||fq.QuadPart<=0){unsup("clock_unavailable");return;}seconds=(double)(q1-q0)/(double)fq.QuadPart;{int64_t signed_delta=x==5?(int64_t)(uint32_t)(after[x]-before[x]):(int64_t)after[x]-(int64_t)before[x];ratio=seconds>0?(double)signed_delta/clock_units(x,fq.QuadPart)/seconds:0;add(&raw,",\"signed_source_delta\":%" PRId64 ",\"source_moved_backward\":%s",signed_delta,jb(signed_delta<0));add(&raw,",\"qpc_seconds\":%.9f,\"elapsed_ratio\":%.9f",seconds,ratio);printf("TIMING {\"cell\":%u,\"kind\":\"sleep100_delta\",\"source\":%u,\"qpc_frequency\":%" PRId64 ",\"samples\":[%" PRId64 "]}\n",id,x,(int64_t)fq.QuadPart,signed_delta);}
 add(&norm,"\"qpc_monotonic\":%s",jb(q1>=q0));if(x==0||x==1||x==4)add(&norm,",\"monotonic_source\":%s",jb(after[x]>=before[x]));
 /* Wall clocks may step; timeGetTime wraps. Ratios are empirical, not exact equality. */
}
static void minimum_step(unsigned id,unsigned x){uint64_t prev=0,cur=0,min=UINT64_MAX,changes[SAMPLE_N];unsigned i,n=0,backward=0;LARGE_INTEGER fq={0},begin={0},now={0};if(!QueryPerformanceFrequency(&fq)){unsup("QPC_unavailable");return;}if(!clock_value(x,&prev)||fq.QuadPart<=0){unsup("clock_unavailable");return;}if(!QueryPerformanceCounter(&begin)){unsup("QPC_read_failed");return;}
 for(i=0;i<1000000&&n<SAMPLE_N;i++){if(!clock_value(x,&cur)){unsup("clock_read_failed");return;}if(cur!=prev){uint64_t d=x==5?(uint32_t)(cur-prev):cur-prev;if(cur<prev&&x!=5){backward++;prev=cur;continue;}if(d<min)min=d;changes[n++]=d;prev=cur;}if((i&1023)==0){if(!QueryPerformanceCounter(&now)){unsup("QPC_read_failed");return;}if(now.QuadPart-begin.QuadPart>fq.QuadPart/4)break;}}
 add(&raw,"\"source\":");quote(&raw,clocknames[x]);add(&raw,",\"reads\":%u,\"changes\":%u,\"backward_steps\":%u,\"smallest_step\":",i,n,backward);if(n)add(&raw,"%" PRIu64,min);else add(&raw,"null");add(&norm,"\"bounded_sampling_completed\":true");if(!n)unsup("no_positive_clock_step_observed_within_bound");timing(id,"minimum_step_changes",x,changes,n,fq.QuadPart);
}
static void wait_cell(unsigned id,unsigned x){uint64_t samples[SAMPLE_N],sorted[SAMPLE_N];unsigned i;HANDLE ev=NULL;LARGE_INTEGER a={0},b={0},fq={0};DWORD rc=WAIT_TIMEOUT;int outcomes=1;if(!QueryPerformanceFrequency(&fq)){unsup("QPC_unavailable");return;}if(fq.QuadPart<=0){unsup("QPC_unavailable");return;}if(x>=3){ev=CreateEventW(NULL,TRUE,FALSE,NULL);if(!ev){failed(GetLastError());return;}}
 for(i=0;i<SAMPLE_N;i++){if(!QueryPerformanceCounter(&a)){if(ev)CloseHandle(ev);unsup("QPC_read_failed");return;}if(x==0)Sleep(0);else if(x==1)Sleep(1);else if(x==2)SwitchToThread();else{rc=WaitForSingleObject(ev,x==3?1:x==4?15:16);if(rc!=WAIT_TIMEOUT)outcomes=0;}if(!QueryPerformanceCounter(&b)){if(ev)CloseHandle(ev);unsup("QPC_read_failed");return;}if(b.QuadPart<a.QuadPart)outcomes=0;samples[i]=(uint64_t)(b.QuadPart-a.QuadPart);}if(ev)CloseHandle(ev);memcpy(sorted,samples,sizeof(samples));qsort(sorted,SAMPLE_N,sizeof(uint64_t),cmp_u64);
 add(&raw,"\"operation\":");quote(&raw,waitnames[x]);add(&raw,",\"sample_count\":%u,\"minimum_qpc\":%" PRIu64 ",\"median_qpc\":%" PRIu64 ",\"p99_qpc\":%" PRIu64 ",\"frequency\":%" PRId64 ",\"last_wait_return\":%lu",SAMPLE_N,sorted[0],sorted[SAMPLE_N/2],sorted[99],(int64_t)fq.QuadPart,(unsigned long)rc);add(&norm,"\"wait_outcomes_valid\":%s",jb(outcomes));timing(id,"wait_qpc_deltas",x,samples,SAMPLE_N,fq.QuadPart);
}
/* Prefix copied by field from the public WDK KUSER_SHARED_DATA declaration.
 * Offsets statically verified. No reserved/security cookie/kernel pointers read. */
typedef struct{ULONG LowPart;LONG High1Time;LONG High2Time;} SharedTime;
typedef struct{ULONG TickCountLowDeprecated,TickCountMultiplier;SharedTime InterruptTime,SystemTime,TimeZoneBias;USHORT ImageNumberLow,ImageNumberHigh;WCHAR NtSystemRoot[260];ULONG MaxStackTraceDepth,CryptoExponent,TimeZoneId,LargePageMinimum,AitSamplingValue,AppCompatFlag;ULONGLONG RNGSeedVersion;ULONG GlobalValidationRunlevel;LONG TimeZoneBiasStamp;ULONG NtBuildNumber,NtProductType;BYTE ProductTypeIsValid,Reserved0;USHORT NativeProcessorArchitecture;ULONG NtMajorVersion,NtMinorVersion;BYTE ProcessorFeatures[64];} SharedPrefix;
typedef char shared_layout_check[(offsetof(SharedPrefix,NtBuildNumber)==0x260&&offsetof(SharedPrefix,ProcessorFeatures)==0x274)?1:-1];
static int shared_time(volatile const SharedTime *s,uint64_t *v){unsigned i;for(i=0;i<1000;i++){LONG h1=s->High1Time;ULONG low=s->LowPart;LONG h2=s->High2Time;if(h1==h2){*v=((uint64_t)(ULONG)h1<<32)|low;return 1;}}return 0;}
static void shared_cell(unsigned x){const uintptr_t address=0x7ffe0000U;MEMORY_BASIC_INFORMATION v;volatile const SharedPrefix *s=(volatile const SharedPrefix*)address;int valid;memset(&v,0,sizeof(v));valid=VirtualQuery((void*)address,&v,sizeof(v))==sizeof(v);
 if(x==1){add(&raw,"\"query_succeeded\":%s,\"state\":%lu,\"protect\":%lu,\"type\":%lu,\"region_size\":%" PRIuPTR,jb(valid),(unsigned long)v.State,(unsigned long)v.Protect,(unsigned long)v.Type,(uintptr_t)v.RegionSize);add(&norm,"\"shared_page_query_succeeded\":%s",jb(valid));add(&comparison,"\"state\":%lu,\"protection\":%lu,\"read_only_category\":%s",(unsigned long)v.State,(unsigned long)v.Protect,jb(valid&&(v.Protect&0xff)==PAGE_READONLY));return;}
 if(!valid||v.State!=MEM_COMMIT||(v.Protect&(PAGE_NOACCESS|PAGE_GUARD))){unsup("shared_data_mapping_not_readable");return;}
 {unsigned i,mismatch=0;uint64_t sys=0,intr=0;FILETIME before={0},after={0};int a,b;GetSystemTimeAsFileTime(&before);a=shared_time(&s->SystemTime,&sys);b=shared_time(&s->InterruptTime,&intr);GetSystemTimeAsFileTime(&after);add(&raw,"\"nt_major\":%lu,\"nt_minor\":%lu,\"nt_build\":%lu,\"native_architecture\":%u,\"large_page_minimum\":%lu,\"system_time\":%" PRIu64 ",\"interrupt_time\":%" PRIu64 ",\"processor_features\":[",(unsigned long)s->NtMajorVersion,(unsigned long)s->NtMinorVersion,(unsigned long)s->NtBuildNumber,s->NativeProcessorArchitecture,(unsigned long)s->LargePageMinimum,sys,intr);for(i=0;i<64;i++){BYTE f=s->ProcessorFeatures[i];if(i)add(&raw,",");add(&raw,"%u",f);if(!!f!=!!IsProcessorFeaturePresent(i))mismatch++;}add(&raw,"],\"feature_mismatches\":%u,\"filetime_before\":%" PRIu64 ",\"filetime_after\":%" PRIu64 ",\"shared_time_inside_API_bracket\":%s",mismatch,ft64(before),ft64(after),jb(sys>=ft64(before)&&sys<=ft64(after)));add(&norm,"\"shared_time_reads_consistent\":%s",jb(a&&b));add(&comparison,"\"shared_features_match_API\":%s",jb(!mismatch));}
}
static void run_cell(unsigned id,Kind k,unsigned x,const char *family){reset(&raw);reset(&norm);reset(&comparison);reason=NULL;unsupported=0;
 switch(k){
 case K_SYSINFO:system_info(x);break;
 case K_FEATURE:{BOOL f=IsProcessorFeaturePresent(x);add(&raw,"\"feature\":%u,\"returned_value\":%ld,\"present\":%s",x,(long)f,jb(f));add(&norm,"\"feature_index_within_bound\":%s",jb(x<64));break;}
 case K_TOPO:topology(x);break;case K_VERSION:version(x);break;
 case K_WOW:{USHORT p=0,n=0;BOOL ok;if(!wow2){unsup("IsWow64Process2_absent");break;}ok=wow2(GetCurrentProcess(),&p,&n);add(&raw,"\"ok\":%s,\"process_machine\":%u,\"native_machine\":%u,\"error\":%lu",jb(ok),p,n,(unsigned long)(ok?0:GetLastError()));add(&norm,"\"call_succeeded\":%s",jb(ok));break;}
 case K_MEMORY:{MEMORYSTATUSEX m;BOOL ok;memset(&m,0,sizeof(m));m.dwLength=sizeof(m);ok=GlobalMemoryStatusEx(&m);add(&raw,"\"ok\":%s,\"length\":%lu,\"load_percent\":%lu,\"total_phys\":%" PRIu64 ",\"available_phys\":%" PRIu64 ",\"total_pagefile\":%" PRIu64 ",\"available_pagefile\":%" PRIu64 ",\"total_virtual\":%" PRIu64 ",\"available_virtual\":%" PRIu64 ",\"available_extended_virtual\":%" PRIu64,jb(ok),(unsigned long)m.dwLength,(unsigned long)m.dwMemoryLoad,(uint64_t)m.ullTotalPhys,(uint64_t)m.ullAvailPhys,(uint64_t)m.ullTotalPageFile,(uint64_t)m.ullAvailPageFile,(uint64_t)m.ullTotalVirtual,(uint64_t)m.ullAvailVirtual,(uint64_t)m.ullAvailExtendedVirtual);add(&norm,"\"call_succeeded\":%s,\"load_in_range\":%s,\"physical_ordered\":%s,\"pagefile_ordered\":%s,\"virtual_ordered\":%s",jb(ok),jb(m.dwMemoryLoad<=100),jb(m.ullAvailPhys<=m.ullTotalPhys),jb(m.ullAvailPageFile<=m.ullTotalPageFile),jb(m.ullAvailVirtual<=m.ullTotalVirtual));break;}
 case K_SYSMAP:case K_PROCMAP:case K_THREADMAP:ntmap(k,x);break;
 case K_SYSDOC:sysdoc(x);break;case K_PROCDOC:procdoc(x);break;case K_PEB:peb_cell(x);break;
 case K_DEBUG:{BOOL d=FALSE,ok=TRUE;if(x)ok=CheckRemoteDebuggerPresent(GetCurrentProcess(),&d);else d=IsDebuggerPresent();add(&raw,"\"ok\":%s,\"debugger_present\":%s,\"error\":%lu",jb(ok),jb(d),(unsigned long)(ok?0:GetLastError()));add(&norm,"\"call_succeeded\":%s,\"no_debugger_precondition\":%s",jb(ok),jb(!d));break;}
 case K_MITIGATION:mitigation(x);break;
 case K_AFFINITY:{DWORD_PTR p=0,s=0;BOOL ok=GetProcessAffinityMask(GetCurrentProcess(),&p,&s);add(&raw,"\"ok\":%s,\"process_mask\":\"0x%" PRIxPTR "\",\"system_mask\":\"0x%" PRIxPTR "\"",jb(ok),(uintptr_t)p,(uintptr_t)s);add(&norm,"\"call_succeeded\":%s,\"process_mask_subset_of_system\":%s",jb(ok),jb((p&~s)==0));break;}
 case K_WS:working_set(x);break;
 case K_PROCTIME:{FILETIME c={0},e={0},kern={0},u={0},now={0};BOOL ok=GetProcessTimes(GetCurrentProcess(),&c,&e,&kern,&u);GetSystemTimeAsFileTime(&now);add(&raw,"\"ok\":%s,\"creation\":%" PRIu64 ",\"exit\":%" PRIu64 ",\"kernel\":%" PRIu64 ",\"user\":%" PRIu64 ",\"now\":%" PRIu64,jb(ok),ft64(c),ft64(e),ft64(kern),ft64(u),ft64(now));add(&norm,"\"call_succeeded\":%s",jb(ok));break;}
 case K_THREADS:threads(x);break;case K_THREADDOC:thread_doc(x);break;
 case K_HIDE:unsup("ThreadHideFromDebugger_query_set_is_undocumented_and_not_implemented");break;
 case K_CONTEXT:context_cell(x);break;case K_TEB:teb_cell(x);break;case K_SUSPEND:suspend_cell();break;case K_PRIORITY:priority_cell(x);break;
 case K_MODULES:module_inventory();break;case K_HEADERS:module_headers();break;case K_SECTIONS:module_sections();break;case K_ADDRESS:module_address(x);break;case K_EXPORTS:exports_cell(x);break;
 case K_CLOSE:close_cell(x);break;case K_DUP:duplicate_cell(x);break;case K_HFLAGS:handle_flags(x);break;case K_OBJECT:object_cell(x);break;
 case K_QPF:{LARGE_INTEGER f={0};BOOL ok=QueryPerformanceFrequency(&f);add(&raw,"\"ok\":%s,\"frequency\":%" PRId64,jb(ok),(int64_t)f.QuadPart);add(&norm,"\"frequency_positive\":%s",jb(ok&&f.QuadPart>0));break;}
 case K_CLOCK:clock_cell(id,x);break;case K_STEP:minimum_step(id,x);break;case K_WAIT:wait_cell(id,x);break;case K_SHARED:shared_cell(x);break;
 }
 finish_cell(id,family,k,x);
}
#endif
static int number(const char *s,unsigned *out){char *end;unsigned long n;if(!s||!*s||*s=='-'||*s=='+')return 0;errno=0;n=strtoul(s,&end,10);if(errno||*end||n==0||n>total_cells())return 0;*out=(unsigned)n;return 1;}
int main(int argc,char **argv){unsigned first=1,last=total_cells(),id=0,g,x;int listing=0;const char *mode=NULL;char ax[256],payload[384];
#ifdef _WIN32
 /* Snapshot before any helper thread or optional module is created. */
 initial_thread_count=thread_count(&initial_thread_error);entry_recording=0;
 if(_setmode(_fileno(stdout),_O_BINARY)==-1){fputs("cannot set binary stdout\n",stderr);return 3;}
#endif
 if(argc==2&&!strcmp(argv[1],"list")){listing=1;mode="list";}
 else if(argc==2&&!strcmp(argv[1],"all"))mode="all";
 else if(argc==3&&!strcmp(argv[1],"cell")&&number(argv[2],&first)){last=first;mode="cell";}
 else if(argc==4&&!strcmp(argv[1],"range")&&number(argv[2],&first)&&number(argv[3],&last)&&first<=last)mode="range";
 if(!mode){fprintf(stderr,"usage: %s all | cell N | range A B | list (IDs 1..%u)\n",argv[0],total_cells());return 2;}
#ifndef _WIN32
 if(!listing){fputs("Windows observations require a Windows x64 build; this host build supports list only.\n",stderr);return 2;}
#endif
 printf("META {\"schema\":1,\"source_schema\":\"0087-state-v1\",\"mode\":\"%s\",\"first\":%u,\"last\":%u,\"total_cells\":%u,\"expected_count\":%u",mode,first,last,total_cells(),last-first+1);
#ifdef _WIN32
 if(!listing){init();printf(",\"platform\":\"windows-x64\",\"pointer_bits\":%u,\"pid\":%lu",(unsigned)(8*sizeof(void*)),(unsigned long)selfpid);{OSVERSIONINFOEXW v;USHORT pm=0,nm=0;memset(&v,0,sizeof(v));v.dwOSVersionInfoSize=sizeof(v);if(GetVersionExW((OSVERSIONINFOW*)&v))printf(",\"apparent_version\":[%lu,%lu,%lu]",(unsigned long)v.dwMajorVersion,(unsigned long)v.dwMinorVersion,(unsigned long)v.dwBuildNumber);if(wow2&&wow2(GetCurrentProcess(),&pm,&nm))printf(",\"process_machine\":%u,\"native_machine\":%u",pm,nm);}
#ifdef _MSC_VER
 printf(",\"compiler\":\"MSVC\",\"compiler_version\":%d",_MSC_VER);
#elif defined(__clang__)
 printf(",\"compiler\":\"clang\",\"compiler_major\":%d,\"compiler_minor\":%d",__clang_major__,__clang_minor__);
#elif defined(__GNUC__)
 printf(",\"compiler\":\"gcc\",\"compiler_major\":%d,\"compiler_minor\":%d",__GNUC__,__GNUC_MINOR__);
#endif
 }
#endif
 puts("}");
 for(g=0;g<sizeof(groups)/sizeof(groups[0]);g++)for(x=0;x<groups[g].count;x++){id++;if(id<first||id>last)continue;
  if(listing){axes(ax,sizeof(ax),groups[g].k,x);snprintf(payload,sizeof(payload),"{\"listed\":true,\"axes\":{%s}}",ax);emit(id,groups[g].family,payload);}
#ifdef _WIN32
  else run_cell(id,groups[g].k,x,groups[g].family);
#endif
 }
 printf("DONE count=%u checksum=%016" PRIx64 "\n",emitted,hash);
#ifdef _WIN32
 if(user_module)FreeLibrary(user_module);if(mm_module)FreeLibrary(mm_module);
 free(raw.s);free(norm.s);free(comparison.s);free(out.s);
#endif
 return ferror(stdout)?3:0;
}
