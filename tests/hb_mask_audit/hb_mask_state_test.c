/* HBUP0002 absolute x86 mask oracle. All 32*512 bits and mapped bytes checked.
 * Guard cases execute in a child; a raw SIGBUS/SEGV is recorded only if si_addr
 * is in the intentionally inaccessible page. SIGILL is never an expected fault.
 * This tests whether a memory access faults, not Windows exception delivery.
 */
#include "../hb_absolute/common.h"
#ifndef HB_ORACLE_COMPARATOR_ONLY
typedef struct {int status,rc,out_rc,signal;uint64_t pc,steps;uint8_t vec[2048],mem[256];} sample;
/* status: 0 completed, 1 intentional-page memory fault, 2 other execution error. */
static volatile sig_atomic_t trap_fd=-1;
static uintptr_t trap_lo,trap_hi;
static void fault_handler(int sig,siginfo_t*si,void*u){
 (void)u;sample s;memset(&s,0,sizeof(s));uintptr_t p=(uintptr_t)si->si_addr;
 s.signal=sig;s.status=((sig==SIGSEGV||sig==SIGBUS)&&p>=trap_lo&&p<trap_hi)?1:2;s.pc=p;
 if(trap_fd>=0){const char*b=(const char*)&s;size_t off=0;while(off<sizeof(s)){ssize_t n=write(trap_fd,b+off,sizeof(s)-off);if(n<=0)break;off+=(size_t)n;}}
 _exit(s.status==1?0:3);
}
static sample execute(hb_context_t*c,hb_ir_func_t*func,int backend,uint8_t*at,unsigned cl,uint8_t*stack,uint8_t*data,uint8_t*boundary,
                      const uint8_t*in,const uint64_t*k,unsigned mode,unsigned valid){
 sample s={0};hb_seed_base(c,at,stack+32768,data);hb_set_vectors(c,in);memcpy(c->k,k,8*sizeof(uint64_t));
 if(mode==1)c->regs.x64.rbx=(uintptr_t)(boundary-valid);if(mode==2)c->regs.x64.rdi=(uintptr_t)(boundary-valid);
 hb_exec_result_t out;hb_result_t rc=hb_run_program(c,func,at,cl,backend,&out);
 s.rc=rc;s.out_rc=out.result;s.pc=c->pc;s.steps=out.steps_executed;
 if(rc==HB_ERR_MEMORY_FAULT||out.result==HB_ERR_MEMORY_FAULT)s.status=1;
 else if(rc!=HB_OK||out.result!=HB_OK||out.faulted||out.timed_out||!out.steps_executed||c->pc!=(uintptr_t)at+cl)s.status=2;
 hb_get_vectors(c,s.vec);memcpy(s.mem,data,256);return s;
}
static sample isolated(hb_ir_func_t*func,int backend,uint8_t*code,size_t codesize,uint8_t*at,unsigned cl,uint8_t*stack,
                       uint8_t*region,size_t page,const uint8_t*in,const uint64_t*k,unsigned mode,unsigned valid){
 sample s={0};int p[2];if(pipe(p)){s.status=2;return s;}pid_t pid=fork();
 if(pid<0){close(p[0]);close(p[1]);s.status=2;return s;}
 if(pid==0){
  close(p[0]);trap_fd=p[1];trap_lo=(uintptr_t)(region+page);trap_hi=trap_lo+page;
  struct sigaction sa;memset(&sa,0,sizeof(sa));sa.sa_sigaction=fault_handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);
  if(sigaction(SIGSEGV,&sa,NULL)||sigaction(SIGBUS,&sa,NULL)||sigaction(SIGILL,&sa,NULL))_exit(4);
  hb_context_t*c=hb_new_context(backend,code,codesize,stack,65536,region,page);
  if(!c){s.status=2;}else{s=execute(c,func,backend,at,cl,stack,region+page-256,region+page,in,k,mode,valid);}
  size_t done=0;while(done<sizeof(s)){ssize_t n=write(p[1],((char*)&s)+done,sizeof(s)-done);if(n<=0)_exit(5);done+=(size_t)n;}
  /* No source mutation or persistent cache shared with a later guard case. */
  close(p[1]);_exit(0);
 }
 close(p[1]);size_t n=0;while(n<sizeof(s)){ssize_t r=read(p[0],((char*)&s)+n,sizeof(s)-n);if(r<0&&errno==EINTR)continue;if(r<=0)break;n+=(size_t)r;}close(p[0]);int status;while(waitpid(pid,&status,0)<0){if(errno!=EINTR){s.status=2;return s;}}
 if(n!=sizeof(s)||!WIFEXITED(status)||WEXITSTATUS(status)!=0)s.status=2;return s;
}
static int run(FILE*f,const char*filter,int guard_mode){
 char magic[8];hb_need(f,magic,8);if(memcmp(magic,"HBUP0002",8)){fputs("bad HBUP magic\n",stderr);return 2;}
 uint64_t count=hb_le(f,4);if(!count||count>100000){fputs("invalid count\n",stderr);return 2;}
 size_t slot=256,page=(size_t)sysconf(_SC_PAGESIZE),stacksize=65536;
 uint8_t*code=mmap(NULL,count*slot,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 uint8_t*stack=mmap(NULL,stacksize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 uint8_t*region=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(code==MAP_FAILED||stack==MAP_FAILED||region==MAP_FAILED||mprotect(region+page,page,PROT_NONE)){perror("mmap/mprotect");return 2;}
 uint8_t*data=region+page-256;hb_context_t*c[2]={hb_new_context(0,code,count*slot,stack,stacksize,region,page),hb_new_context(1,code,count*slot,stack,stacksize,region,page)};
 hb_ir_func_t**keep=calloc(count,sizeof(*keep));if(!c[0]||!c[1]||!keep)return 2;
 uint64_t selected=0,unsupported=0,ran[2]={0},bad[2]={0},low[2]={0},upper[2]={0},mem_bad[2]={0},fault_bad[2]={0},exec_bad[2]={0},expected_faults=0;
 for(uint64_t i=0;i<count;i++){
  unsigned nl=hb_le(f,2),cl=hb_le(f,2),kind=hb_le(f,4);uint64_t seed=hb_le(f,8),ks[8];for(unsigned j=0;j<8;j++)ks[j]=hb_le(f,8);
  unsigned mode=hb_le(f,4),valid=hb_le(f,4),ef=hb_le(f,4);
  if(!nl||nl>511||!cl||cl>slot||kind!=2||mode>2||valid>64||ef>1){fputs("invalid record\n",stderr);return 2;}
  char name[512];uint8_t bytes[256],in[2048],im[256],expected[2048],em[256];
  hb_need(f,name,nl);name[nl]=0;hb_need(f,bytes,cl);hb_need(f,in,2048);hb_need(f,im,256);hb_need(f,expected,2048);hb_need(f,em,256);
  if((filter&&!strstr(name,filter))||(guard_mode==1&&!mode)||(guard_mode==2&&mode))continue;selected++;expected_faults+=ef;
  uint8_t*at=code+i*slot;memcpy(at,bytes,cl);hb_ir_func_t*func=hb_lift_at(at,cl);
  if(!func){unsupported++;if(unsupported<=40)fprintf(stderr,"UNSUPPORTED %s\n",name);continue;}keep[i]=func;
  for(int k=0;k<2;k++){
   memcpy(data,im,256);sample s=mode?isolated(func,k,code,count*slot,at,cl,stack,region,page,in,ks,mode,valid):execute(c[k],func,k,at,cl,stack,data,region+page,in,ks,mode,valid);ran[k]++;
   int ex=s.status==2,fd=!ex&&((s.status==1)!=ef),ld=0,ud=0,md=0;
   if(!ef&&!ex&&s.status==0){for(unsigned r=0;r<32;r++)for(unsigned q=0;q<8;q++)if(memcmp(s.vec+r*64+q*8,expected+r*64+q*8,8)){if(q<2)ld=1;else ud=1;}md=memcmp(s.mem,em,256)!=0;}
   if(ex)exec_bad[k]++;if(fd)fault_bad[k]++;if(ld)low[k]++;if(ud)upper[k]++;if(md)mem_bad[k]++;
   if(ex||fd||ld||ud||md){bad[k]++;if(bad[k]<=40){fprintf(stderr,"%s %s seed=%"PRIx64" rc=%d out=%d signal=%d expected_fault=%u status=%d low=%d upper=%d memory=%d\n",k?"JIT":"INTERP",name,seed,s.rc,s.out_rc,s.signal,ef,s.status,ld,ud,md);
    if(md){unsigned shown=0;for(unsigned o=0;o<256&&shown<3;o++)if(s.mem[o]!=em[o]){fprintf(stderr," mem[%u] got=%02x expected=%02x initial=%02x\n",o,s.mem[o],em[o],im[o]);shown++;}
     fprintf(stderr," steps=%" PRIu64 " pc_off=%lld\n",s.steps,(long long)(s.pc-(uint64_t)(uintptr_t)(code+i*slot)));}
    unsigned n=0;for(unsigned r=0;r<32&&n<4;r++)for(unsigned q=0;q<8&&n<4;q++)if(!ef&&!s.status&&memcmp(s.vec+r*64+q*8,expected+r*64+q*8,8)){uint64_t g,e;memcpy(&g,s.vec+r*64+q*8,8);memcpy(&e,expected+r*64+q*8,8);fprintf(stderr," zmm%u.q%u got=%016"PRIx64" expected=%016"PRIx64"\n",r,q,g,e);n++;}}
   }
  }
 }
 if(fgetc(f)!=EOF){fputs("trailing bytes\n",stderr);return 2;}
 printf("{\"selected\":%"PRIu64",\"unsupported\":%"PRIu64",\"expected_faults\":%"PRIu64",\"backends\":[",selected,unsupported,expected_faults);
 for(int k=0;k<2;k++)printf("%s{\"backend\":\"%s\",\"executed\":%"PRIu64",\"mismatch_cases\":%"PRIu64",\"low128_mismatch\":%"PRIu64",\"upper_mismatch\":%"PRIu64",\"memory_mismatch\":%"PRIu64",\"fault_mismatch\":%"PRIu64",\"execution_error\":%"PRIu64"}",k?",":"",k?"JIT":"INTERP",ran[k],bad[k],low[k],upper[k],mem_bad[k],fault_bad[k],exec_bad[k]);puts("]}");
 for(int k=0;k<2;k++)hb_free_context(c[k]);for(uint64_t i=0;i<count;i++)if(keep[i])hb_ir_func_destroy(keep[i]);free(keep);munmap(code,count*slot);munmap(stack,stacksize);munmap(region,page*2);
 if(!selected||unsupported)return 2;return(bad[0]||bad[1])?1:0;
}
#endif
int main(int argc,char**argv){
 if(argc==2&&!strcmp(argv[1],"--self-test"))return hb_comparator_selftest();
#ifdef HB_ORACLE_COMPARATOR_ONLY
 fputs("comparator-only binary: --self-test\n",stderr);return 2;
#else
 if(argc<2){fputs("usage: hb_mask_state_test corpus.hbup|- [--filter substring] [--guard-only|--ordinary-only]\n",stderr);return 2;}
 const char*filter=NULL;int guard=0;for(int i=2;i<argc;i++){if(!strcmp(argv[i],"--filter")&&i+1<argc)filter=argv[++i];else if(!strcmp(argv[i],"--guard-only"))guard=1;else if(!strcmp(argv[i],"--ordinary-only"))guard=2;else{fprintf(stderr,"bad option %s\n",argv[i]);return 2;}}
 FILE*f=!strcmp(argv[1],"-")?stdin:fopen(argv[1],"rb");if(!f){perror(argv[1]);return 2;}int rc=run(f,filter,guard);if(f!=stdin)fclose(f);return rc;
#endif
}
