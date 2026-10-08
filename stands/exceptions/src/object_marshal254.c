/* SPDX-License-Identifier: MIT */
/* Synthetic object name/security sizes; no process inspection or game data. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef NTSTATUS (NTAPI *query_object_fn)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *query_security_fn)(HANDLE,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR,ULONG,PULONG);
typedef struct {
    ULONG Attributes,GrantedAccess,HandleCount,PointerCount,PagedPoolCharge,NonPagedPoolCharge,Reserved[3];
    ULONG NameInfoSize,TypeInfoSize,SecurityDescriptorSize; LARGE_INTEGER CreationTime;
} basic_info;
_Static_assert(sizeof(basic_info)==56,"object basic x64 ABI");
_Static_assert(sizeof(UNICODE_STRING)==16,"name header x64 ABI");
static unsigned failures,snapshots;
static query_object_fn query; static query_security_fn security;
static unsigned sid_length(void *base,ULONG bytes,PSID sid) {
    uintptr_t lo=(uintptr_t)base,hi=lo+bytes,p=(uintptr_t)sid;
    if(!sid)return 0;
    if(p<lo||p>hi||hi-p<8){++failures;return 0;}
    unsigned n=((unsigned char *)sid)[1];
    if(n>15||hi-p<8+4*n||!IsValidSid(sid)){++failures;return 0;}
    return GetLengthSid(sid);
}
static unsigned offset(void *base,void *p) { return p ? (unsigned)((uintptr_t)p-(uintptr_t)base) : 0; }
static void snapshot(unsigned kind,unsigned named,HANDLE handle) {
    static const char *types[]={"event","mutex","semaphore"};
    basic_info basic; ULONG basic_used=0xa5a5a5a5u,name_used=0xa5a5a5a5u,sd_used=0xa5a5a5a5u;
    union { uint64_t align; unsigned char data[8192]; } name,sd;
    memset(&basic,0xa5,sizeof(basic));memset(&name,0xa5,sizeof(name));memset(&sd,0xa5,sizeof(sd));
    NTSTATUS bs=query(handle,0,&basic,sizeof(basic),&basic_used);
    NTSTATUS ns=query(handle,1,name.data,sizeof(name.data),&name_used);
    NTSTATUS ss=security(handle,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                         sd.data,sizeof(sd.data),&sd_used);
    printf("OBJECT254_INFO type=%s named=%u basic_status=%08lx basic_used=%lu basic_name=%lu basic_sd=%lu basic_pointer=%lu name_status=%08lx name_used=%lu sd_status=%08lx sd_used=%lu\n",
           types[kind],named,(unsigned long)bs,(unsigned long)basic_used,(unsigned long)basic.NameInfoSize,
           (unsigned long)basic.SecurityDescriptorSize,(unsigned long)basic.PointerCount,
           (unsigned long)ns,(unsigned long)name_used,(unsigned long)ss,(unsigned long)sd_used);
    if(bs||basic_used!=56||ns||name_used>sizeof(name.data)||ss||sd_used>sizeof(sd.data)){++failures;return;}
    UNICODE_STRING *n=(UNICODE_STRING *)name.data;
    uintptr_t p=(uintptr_t)n->Buffer,lo=(uintptr_t)name.data,hi=lo+sizeof(name.data);
    int valid=!n->Length||((n->Length&1)==0&&p>=lo&&p<=hi&&hi-p>=n->Length&&n->Length<=2048);
    printf("OBJECT254_NAME type=%s named=%u state=%s length=%u maximum=%u pointer_offset=%u utf16le=",
           types[kind],named,valid?"PRESENT":"FAILED",n->Length,n->MaximumLength,offset(name.data,n->Buffer));
    if(valid)for(unsigned i=0;i<n->Length;i++)printf("%02x",((unsigned char *)n->Buffer)[i]);
    putchar('\n');if(!valid)++failures;
    PSID owner=0,group=0;PACL dacl=0;BOOL owner_default=0,group_default=0,dacl_present=0,dacl_default=0;
    SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;
    BOOL good=IsValidSecurityDescriptor(sd.data)&&GetSecurityDescriptorControl(sd.data,&control,&revision)&&
              GetSecurityDescriptorOwner(sd.data,&owner,&owner_default)&&GetSecurityDescriptorGroup(sd.data,&group,&group_default)&&
              GetSecurityDescriptorDacl(sd.data,&dacl_present,&dacl,&dacl_default);
    printf("OBJECT254_SD type=%s named=%u state=%s length=%lu revision=%lu control=%04x owner_len=%u owner_offset=%u owner_default=%u group_len=%u group_offset=%u group_default=%u dacl_present=%u dacl_default=%u dacl_offset=%u acl_bytes=%u ace_count=%u\n",
           types[kind],named,good?"PRESENT":"FAILED",good?(unsigned long)GetSecurityDescriptorLength(sd.data):0,
           (unsigned long)revision,(unsigned)control,sid_length(sd.data,sd_used,owner),offset(sd.data,owner),!!owner_default,
           sid_length(sd.data,sd_used,group),offset(sd.data,group),!!group_default,!!dacl_present,!!dacl_default,
           offset(sd.data,dacl),dacl?dacl->AclSize:0,dacl?dacl->AceCount:0);
    if(!good){++failures;return;}
    if(dacl){
        uintptr_t begin=(uintptr_t)dacl,end=(uintptr_t)sd.data+sd_used;
        if(begin<(uintptr_t)sd.data||begin>end||end-begin<sizeof(ACL)||dacl->AclSize>end-begin||dacl->AceCount>64){++failures;return;}
        for(unsigned i=0;i<dacl->AceCount;i++){
            void *raw=0;BOOL ok=GetAce(dacl,i,&raw);ACE_HEADER *h=raw;
            if(!ok||!h||h->AceSize<8||(uintptr_t)h<begin||(uintptr_t)h>end||h->AceSize>end-(uintptr_t)h){++failures;break;}
            DWORD mask;memcpy(&mask,(unsigned char *)raw+4,4);
            printf("OBJECT254_ACE type=%s named=%u index=%u type_code=%u flags=%u bytes=%u mask=%08lx sid_bytes=%u\n",
                   types[kind],named,i,h->AceType,h->AceFlags,h->AceSize,(unsigned long)mask,
                   h->AceType==ACCESS_ALLOWED_ACE_TYPE||h->AceType==ACCESS_DENIED_ACE_TYPE?sid_length(sd.data,sd_used,(unsigned char *)raw+8):0);
        }
    }
    basic_info after;ULONG used=0;memset(&after,0,sizeof(after));NTSTATUS as=query(handle,0,&after,sizeof(after),&used);
    printf("OBJECT254_AFTER type=%s named=%u status=%08lx used=%lu pointer=%lu\n",types[kind],named,(unsigned long)as,(unsigned long)used,(unsigned long)after.PointerCount);
    if(as||used!=56)++failures;
    ++snapshots;
}
int main(void) {
    HMODULE module=GetModuleHandleW(L"ntdll.dll");query=(query_object_fn)GetProcAddress(module,"NtQueryObject");
    security=(query_security_fn)GetProcAddress(module,"NtQuerySecurityObject");if(!query||!security)return 2;
    printf("OBJECT193_BEGIN version=254 basic_bytes=%zu\n",sizeof(basic_info));fflush(stdout);Sleep(1000);
    const WCHAR *names[]={L"MacRunner.OBJECT193.event",L"MacRunner.OBJECT193.mutex",L"MacRunner.OBJECT193.semaphore"};
    for(unsigned kind=0;kind<3;kind++)for(unsigned named=0;named<2;named++){
        SetLastError(0);const WCHAR *name=named?names[kind]:NULL;
        HANDLE handle=kind==0?CreateEventW(NULL,FALSE,FALSE,name):kind==1?CreateMutexW(NULL,FALSE,name):CreateSemaphoreW(NULL,0,3,name);
        if(!handle||(named&&GetLastError()==ERROR_ALREADY_EXISTS)){++failures;if(handle)CloseHandle(handle);continue;}
        snapshot(kind,named,handle);if(!CloseHandle(handle))++failures;
    }
    if(snapshots!=6)++failures;
    printf("OBJECT254_COMPLETE snapshots=%u failures=%u\n",snapshots,failures);
    return failures?1:0;
}
