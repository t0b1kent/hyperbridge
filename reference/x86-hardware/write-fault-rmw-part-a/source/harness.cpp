// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <ucontext.h>
#include <signal.h>
#include <unistd.h>
#include <cpuid.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cerrno>
#include <ctime>
using namespace std;
struct Regs { uint64_t v[17]; };
extern "C" { Regs inp,outp; void *code_addr; uint64_t host_rsp; int avx_enabled; uint32_t xsave_mask; unsigned char vec0[32] __attribute__((aligned(64))),mask0[16],xinit[16384] __attribute__((aligned(64))); void probe_run(); void probe_done(); }
struct Form { const char*name,*group; int width; unsigned char code[32]; int len,legal,align,feature,count,str,df,stack,call; uint64_t reg[17]; unsigned char initial[32]; int initial_len; unsigned char mask[16]; };
#include "forms.h"
constexpr int P=4096,MAXF=12;
constexpr uintptr_t DB=0x500000000000ULL,SB=0x510000000000ULL,STB=0x520000000000ULL,CB=0x530000000000ULL,AB=0x540000000000ULL;
unsigned char *memdata,*source,*stackmem,*codemem,*altmem;
struct Fault { int sig,si_code,trap,err,second_mapped,phase,partial; uint64_t addr; greg_t greg[NGREG]; uint64_t uc_flags,uc_link,ss_sp,ss_size; int ss_flags; unsigned char sigmask[8]; unsigned char fp[16384]; unsigned fp_len; unsigned char pages[2*P]; };
struct Result { int done,status,nfault,terminal,first_done,second_done,clean_equal,ref_done,partial_count,first_mapped,final_mapped; Fault f[MAXF]; Regs final,first,ref; unsigned char initial[2*P],finalmem[2*P],firstmem[2*P],refmem[2*P]; };
Result *res;
const Form *form;
int continuation,layout,destoff,spanlow,spanhigh,mapped2,phase,fatal,features; unsigned char beforemem[8192];
static void fence(){asm volatile("sfence":::"memory");}
static void *mapat(uintptr_t a,size_t n,int prot){void*p=mmap((void*)a,n,prot,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);if(p==MAP_FAILED)_exit(101);return p;}
static void capture(Fault&f,int sig,siginfo_t *si,ucontext_t *u){
 fence();f.sig=sig;f.si_code=si->si_code;f.addr=(uintptr_t)si->si_addr;f.trap=u->uc_mcontext.gregs[REG_TRAPNO];f.err=u->uc_mcontext.gregs[REG_ERR];f.second_mapped=mapped2;f.phase=phase;memcpy(f.greg,u->uc_mcontext.gregs,sizeof f.greg);f.uc_flags=u->uc_flags;f.uc_link=(uintptr_t)u->uc_link;f.ss_sp=(uintptr_t)u->uc_stack.ss_sp;f.ss_size=u->uc_stack.ss_size;f.ss_flags=u->uc_stack.ss_flags;memcpy(f.sigmask,&u->uc_sigmask,8);
 f.fp_len=0;if(u->uc_mcontext.fpregs){unsigned char *fp=(unsigned char*)u->uc_mcontext.fpregs;unsigned magic,ext;memcpy(&magic,fp+464,4);memcpy(&ext,fp+468,4);f.fp_len=magic==0x46505853&&ext>=512&&ext<=16384?ext:512;memcpy(f.fp,fp,f.fp_len);}
 memcpy(f.pages,memdata,P);if(mapped2)memcpy(f.pages+P,memdata+P,P);f.partial=memcmp(f.pages,beforemem,mapped2?2*P:P)!=0;
}
static void handler(int sig,siginfo_t *si,void*ctx){
 asm volatile("cld");if(res->nfault>=MAXF)_exit(102);auto *u=(ucontext_t*)ctx;Fault&f=res->f[res->nfault++];capture(f,sig,si,u);
 if(f.trap!=14 || phase==0 || sig==SIGALRM){res->terminal=f.trap;res->status=2;res->done=1;_exit(0);}
 if(!mapped2){if(mmap(memdata+P,P,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==MAP_FAILED)_exit(103);mapped2=1;memcpy(memdata+P,beforemem+P,P);}
 if(mprotect(memdata,P*2,PROT_READ|PROT_WRITE))_exit(104);
 if(continuation==2)memset(memdata+spanlow,0x3c,spanhigh-spanlow);
}
static void protect_layout(){
 if(!mapped2){if(mmap(memdata+P,P,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==MAP_FAILED)_exit(105);mapped2=1;memcpy(memdata+P,beforemem+P,P);}
 mprotect(memdata,2*P,PROT_READ|PROT_WRITE);
 // 0 control,1 cross RW/RW,2 RW/RO,3 RO/RW,4 RO/RO,5 RW/unmapped,6 inside RO
 if(layout==2||layout==4)mprotect(memdata+P,P,PROT_READ);
 if(layout==3||layout==4||layout==6)mprotect(memdata,P,PROT_READ);
 if(layout==5){munmap(memdata+P,P);mapped2=0;}
}
static void initialize_regs(){memcpy(inp.v,form->reg,sizeof inp.v);inp.v[4]=SB+256;inp.v[5]=DB+destoff;inp.v[7]=form->stack?DB+destoff+form->width:STB+32768;inp.v[16]|=form->df?0x400:0; if(form->str&&form->df)inp.v[4]=SB+256+(form->count-1)*form->width;}
static void second_regs(){inp=outp;inp.v[4]=SB+256+(form->str&&form->df?(form->count-1)*form->width:0);inp.v[5]=DB+destoff;inp.v[7]=form->stack?DB+destoff+form->width:STB+32768;if(form->str)inp.v[2]=form->reg[2];}
static void execute(){probe_run();fence();}
static void child(){
 alarm(3); memdata=(unsigned char*)mapat(DB,2*P,PROT_READ|PROT_WRITE); source=(unsigned char*)mapat(SB,2*P,PROT_READ|PROT_WRITE);stackmem=(unsigned char*)mapat(STB,65536,PROT_READ|PROT_WRITE);codemem=(unsigned char*)mapat(CB,P,PROT_READ|PROT_WRITE);altmem=(unsigned char*)mapat(AB,65536,PROT_READ|PROT_WRITE);mapped2=1;
 stack_t ss{};ss.ss_sp=altmem;ss.ss_size=65536;if(sigaltstack(&ss,nullptr))_exit(106);struct sigaction sa{};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO|SA_ONSTACK;sigemptyset(&sa.sa_mask);for(int s:{SIGSEGV,SIGBUS,SIGILL,SIGALRM})sigaction(s,&sa,nullptr);
 for(int i=0;i<2*P;i++)source[i]=(unsigned char)(0x40+(i&63));memcpy(vec0,"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f",32);memcpy(mask0,form->mask,16);
 memset(xinit,0,sizeof xinit);xinit[0]=0x7f;xinit[1]=3;xinit[24]=0x80;xinit[25]=0x1f;
 memcpy(codemem,form->code,form->len);unsigned char jmp[]={0xff,0x25,0,0,0,0};memcpy(codemem+form->len,jmp,6);void*done=(void*)probe_done;memcpy(codemem+form->len+6,&done,8);mprotect(codemem,P,PROT_READ|PROT_EXEC);code_addr=codemem;
 memset(res->initial,0x11,2*P);if(form->initial_len)memcpy(res->initial+destoff,form->initial,form->initial_len);memcpy(memdata,res->initial,2*P);
 spanlow=destoff;spanhigh=destoff+form->width;if(form->str){if(form->df)spanlow-=(form->count-1)*form->width;else spanhigh+=(form->count-1)*form->width;}
 // Legal, alignment-valid clean reference. Invalid forms still execute only in the protected test.
 memcpy(beforemem,memdata,2*P);phase=0;bool canref=form->legal&&(!(form->align)||(destoff%form->align==0));
 if(canref){initialize_regs();execute();if(continuation==3){second_regs();execute();}res->ref=outp;memcpy(res->refmem,memdata,2*P);res->ref_done=1;}
 memcpy(memdata,res->initial,2*P);initialize_regs();phase=1;memcpy(beforemem,memdata,2*P);protect_layout();execute();res->first=outp;res->first_done=1;res->first_mapped=mapped2;memcpy(res->firstmem,memdata,P);if(mapped2)memcpy(res->firstmem+P,memdata+P,P);
 if(continuation==3){second_regs();memcpy(beforemem,res->initial,2*P);memcpy(beforemem,memdata,P);if(mapped2)memcpy(beforemem+P,memdata+P,P);protect_layout();phase=2;execute();res->second_done=1;}
 res->final=outp;res->final_mapped=mapped2;memcpy(res->finalmem,memdata,P);if(mapped2)memcpy(res->finalmem+P,memdata+P,P);
 res->clean_equal=res->ref_done&&memcmp(res->finalmem,res->refmem,mapped2?2*P:P)==0&&memcmp(&res->final,&res->ref,sizeof(Regs))==0;res->status=0;res->done=1;_exit(0);
}
static string hexbytes(const unsigned char*p,size_t n){const char*x="0123456789abcdef";string s;s.reserve(2*n);for(size_t i=0;i<n;i++){s+=x[p[i]>>4];s+=x[p[i]&15];}return s;}
static string norm(uint64_t x){char b[80];for(auto z:vector<pair<uint64_t,const char*>>{{DB,"data"},{SB,"source"},{STB,"stack"},{CB,"code"},{AB,"altstack"}}){if(x>=z.first-8192&&x<z.first+131072){snprintf(b,sizeof b,"%s%+lld",z.second,(long long)(x-z.first));return b;}}snprintf(b,sizeof b,"0x%016llx",(unsigned long long)x);return b;}
static void regsprint(const Regs&r){const char*n[]={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rflags"};printf("{");for(int i=0;i<17;i++)printf("%s\"%s\":\"%s\"",i?",":"",n[i],norm(r.v[i]).c_str());printf("}");}
static void pagesprint(const unsigned char*p,int mapped){printf("{\"fill\":\"11\",\"size\":8192,\"page2_mapped\":%s,\"patches\":[",mapped?"true":"false");int lim=mapped?2*P:P;bool first=true;for(int i=0;i<lim;){if(p[i]==0x11){i++;continue;}int j=i+1;while(j<lim&&p[j]!=0x11)j++;printf("%s[%d,\"%s\"]",first?"":",",i,hexbytes(p+i,j-i).c_str());first=false;i=j;}printf("]}");}
static void printresult(const char*lay,int offset,int c,int waitstatus){
 printf("{\"form\":\"%s\",\"group\":\"%s\",\"width\":%d,\"layout\":\"%s\",\"cross_offset\":%d,\"destination_offset\":%d,\"continuation\":%d,\"expected_legal\":%s,\"alignment\":%d,\"wait_status\":%d,\"status\":%d,\"done\":%d,\"terminal_trap\":%d,\"ref_done\":%d,\"clean_equal\":%s,\"initial\":",form->name,form->group,form->width,lay,offset,destoff,c,form->legal?"true":"false",form->align,waitstatus,res->status,res->done,res->terminal,res->ref_done,res->clean_equal?"true":"false");pagesprint(res->initial,1);printf(",\"faults\":[");
 const char*gn[]={"r8","r9","r10","r11","r12","r13","r14","r15","rdi","rsi","rbp","rbx","rdx","rax","rcx","rsp","rip","rflags","csgsfs","err","trapno","oldmask","cr2"};
 for(int k=0;k<res->nfault;k++){Fault&f=res->f[k];printf("%s{\"signal\":%d,\"si_code\":%d,\"trap\":%d,\"error\":%d,\"address\":\"%s\",\"gregs\":{",k?",":"",f.sig,f.si_code,f.trap,f.err,norm(f.addr).c_str());for(int i=0;i<NGREG;i++)printf("%s\"%s\":\"%s\"",i?",":"",gn[i],norm(f.greg[i]).c_str());printf("},\"execution_phase\":%d,\"uc_flags\":%llu,\"uc_link\":\"%s\",\"uc_stack\":{\"sp\":\"%s\",\"size\":%llu,\"flags\":%d},\"kernel_sigmask\":\"%s\",\"fpstate_size\":%u,\"fpstate\":\"%s\",\"partial_write\":%s,\"pages\":",f.phase,(unsigned long long)f.uc_flags,norm(f.uc_link).c_str(),norm(f.ss_sp).c_str(),(unsigned long long)f.ss_size,f.ss_flags,hexbytes(f.sigmask,8).c_str(),f.fp_len,hexbytes(f.fp,f.fp_len).c_str(),f.partial?"true":"false");pagesprint(f.pages,f.second_mapped);printf("}");}
 printf("],\"first_completed\":%s,\"first_regs\":",res->first_done?"true":"false");regsprint(res->first);printf(",\"first_pages\":");if(res->first_done)pagesprint(res->firstmem,res->first_mapped);else printf("null");printf(",\"second_completed\":%s,\"final_regs\":",res->second_done?"true":"false");regsprint(res->final);printf(",\"final_pages\":");if(res->status==0)pagesprint(res->finalmem,res->final_mapped);else printf("null");printf(",\"clean_regs\":");regsprint(res->ref);printf(",\"clean_pages\":");if(res->ref_done)pagesprint(res->refmem,1);else printf("null");printf("}\n");
}
int main(int argc,char**argv){
 unsigned a,b,c,d;__cpuid(1,a,b,c,d);avx_enabled=(c&(1u<<27))&&(c&(1u<<28));uint32_t lo=0,hi=0;if(c&(1u<<27))asm("xgetbv":"=a"(lo),"=d"(hi):"c"(0));avx_enabled=avx_enabled&&((lo&6)==6);xsave_mask=(c&(1u<<27))?(lo&0xe7):0;features=1|((c&(1u<<19))?2:0)|(avx_enabled?4:0)|((d&(1u<<8))?8:0)|((c&(1u<<13))?16:0);
 if(argc>1&&string(argv[1])=="--metadata"){struct utsname u;uname(&u);printf("kernel=%s %s %s\npage_size=%ld\ncpuid.1.eax=%08x\ncpuid.1.ebx=%08x\ncpuid.1.ecx=%08x\ncpuid.1.edx=%08x\nxcr0=%08x%08x\n",u.sysname,u.release,u.machine,sysconf(_SC_PAGESIZE),a,b&0x00ffffff,c,d,hi,lo);for(unsigned l:{0u,1u,7u,0xdu,0x80000000u,0x80000001u,0x80000002u,0x80000003u,0x80000004u}){__cpuid_count(l,0,a,b,c,d);if(l==1)b&=0x00ffffff;printf("CPUID %08x:0 %08x %08x %08x %08x\n",l,a,b,c,d);}return 0;}
 if(sysconf(_SC_PAGESIZE)!=P)return 2;res=(Result*)mmap(nullptr,sizeof(Result),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);if(res==MAP_FAILED)return 3;const char*names[]={"inside_rw","cross_rw_rw","cross_rw_ro","cross_ro_rw","cross_ro_ro","cross_rw_unmapped","inside_ro"};
 for(auto&f:allforms){form=&f;if(argc>1&&string(argv[1])!=f.group)continue;if(f.feature&&!(features&f.feature)){fprintf(stderr,"UNSUPPORTED %s feature=%d\n",f.name,f.feature);continue;}for(layout=0;layout<7;layout++){int footprint=f.width*(f.str?f.count:1);int maxoff=(layout>=1&&layout<=5)?footprint-1:0;int start=maxoff?1:0;if(layout>=1&&layout<=5&&footprint==1)continue;if(layout>=1&&layout<=5&&f.align&&string(f.group)=="vector")continue;for(int off=start;off<=maxoff;off++){destoff=(layout>=1&&layout<=5)?P-off+(f.str&&f.df?(f.count-1)*f.width:0):256;for(continuation=1;continuation<=3;continuation++){memset(res,0,sizeof*res);res->status=-1;pid_t p=fork();if(p==0)child();if(p<0)return 4;int ws;while(waitpid(p,&ws,0)<0&&errno==EINTR){}printresult(names[layout],off,continuation,ws);}}}fflush(stdout);fprintf(stderr,"DONE %s\n",f.name);}
}
