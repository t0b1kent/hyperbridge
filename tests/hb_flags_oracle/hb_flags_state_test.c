/* HBFL0001 absolute native-x86 oracle replay. Not a JIT/interpreter equality test.
 * R8 is captured BEFORE lazy flags are materialized: materialization cannot repair
 * a wrong branch/CMOV/SET retrospectively. Undefined bits remain raw but unscored.
 * Build: clang -O2 -std=c11 -Iinclude tests/hb_flags_oracle/hb_flags_state_test.c libhyperbridge.a -o tests/hb_flags_state_test
 */
#include "../hb_absolute/common.h"
#ifndef HB_ORACLE_COMPARATOR_ONLY
static int run(FILE*f,const char*filter){
 char magic[8];hb_need(f,magic,8);if(memcmp(magic,"HBFL0001",8)){fputs("bad HBFL magic\n",stderr);return 2;}
 uint64_t count=hb_le(f,4);if(!count||count>100000){fputs("invalid count\n",stderr);return 2;}
 size_t slot=256,stacksize=65536,page=(size_t)sysconf(_SC_PAGESIZE);
 uint8_t*code=mmap(NULL,count*slot,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 uint8_t*stack=mmap(NULL,stacksize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 uint8_t*data=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(code==MAP_FAILED||stack==MAP_FAILED||data==MAP_FAILED){perror("mmap");return 2;}
 hb_context_t*c[2]={hb_new_context(0,code,count*slot,stack,stacksize,data,page),hb_new_context(1,code,count*slot,stack,stacksize,data,page)};
 hb_ir_func_t**keep=calloc(count,sizeof(*keep));if(!c[0]||!c[1]||!keep)return 2;
 uint64_t selected=0,unsupported=0,ran[2]={0},bad[2]={0},flags_bad[2]={0},regs_bad[2]={0},exec_bad[2]={0};
 for(uint64_t i=0;i<count;i++){
  unsigned nl=hb_le(f,2),cl=hb_le(f,2);uint64_t seed=hb_le(f,8),ini[7],expected[7],masks[7];
  for(unsigned j=0;j<7;j++)ini[j]=hb_le(f,8);for(unsigned j=0;j<7;j++)expected[j]=hb_le(f,8);for(unsigned j=0;j<7;j++)masks[j]=hb_le(f,8);
  if(!nl||nl>511||!cl||cl>slot){fputs("invalid record\n",stderr);return 2;}
  char name[512];uint8_t bytes[256],mem[64];hb_need(f,name,nl);name[nl]=0;hb_need(f,bytes,cl);hb_need(f,mem,64);
  if(filter&&!strstr(name,filter))continue;selected++;
  uint8_t*at=code+i*slot;memcpy(at,bytes,cl);hb_ir_func_t*func=hb_lift_at(at,cl);
  if(!func){unsupported++;fprintf(stderr,"UNSUPPORTED %s bytes=",name);for(unsigned b=0;b<cl;b++)fprintf(stderr,"%02x",bytes[b]);fputc('\n',stderr);continue;}keep[i]=func;
  for(int k=0;k<2;k++){
   hb_context_t*x=c[k];memcpy(data,mem,64);hb_seed_base(x,at,stack+32768,data);
   x->regs.x64.rax=ini[0];x->regs.x64.rdx=ini[1];x->regs.x64.rcx=ini[2];x->regs.x64.r8=ini[3];x->regs.x64.r9=ini[4];x->regs.x64.rbx=ini[5];hb_set_rflags(x,ini[6]);x->regs.x64.rdi=(uintptr_t)data;
   hb_exec_result_t out;hb_result_t rc=hb_run_program(x,func,at,cl,k,&out);ran[k]++;
   uint64_t got[7]={x->regs.x64.rax,x->regs.x64.rdx,x->regs.x64.rcx,x->regs.x64.r8,x->regs.x64.r9,x->regs.x64.rbx,0};
   hb_result_t fr=HB_OK;got[6]=hb_get_rflags(x,&fr);
   int ex=(rc!=HB_OK||out.result!=HB_OK||out.faulted||out.timed_out||!out.steps_executed||x->pc!=(uintptr_t)at+cl||fr!=HB_OK);
   unsigned rd=hb_diff_words(got,expected,masks,6),fd=hb_diff_words(got+6,expected+6,masks+6,1);
   if(ex)exec_bad[k]++;if(rd)regs_bad[k]++;if(fd)flags_bad[k]++;if(ex||rd||fd){bad[k]++;
    if(bad[k]<=40){fprintf(stderr,"%s %s seed=%"PRIx64" rc=%d flags_rc=%d steps=%"PRIu64"\n",k?"JIT":"INTERP",name,seed,rc,fr,out.steps_executed);
     for(unsigned j=0;j<7;j++)if((got[j]^expected[j])&masks[j])fprintf(stderr," field%u got=%016"PRIx64" expected=%016"PRIx64" mask=%016"PRIx64"\n",j,got[j],expected[j],masks[j]);}
   }
  }
 }
 if(fgetc(f)!=EOF){fputs("trailing bytes\n",stderr);return 2;}
 printf("{\"selected\":%"PRIu64",\"unsupported\":%"PRIu64",\"backends\":[",selected,unsupported);
 for(int k=0;k<2;k++)printf("%s{\"backend\":\"%s\",\"executed\":%"PRIu64",\"mismatch_cases\":%"PRIu64",\"register_mismatch\":%"PRIu64",\"flags_mismatch\":%"PRIu64",\"execution_error\":%"PRIu64"}",k?",":"",k?"JIT":"INTERP",ran[k],bad[k],regs_bad[k],flags_bad[k],exec_bad[k]);puts("]}");
 for(int k=0;k<2;k++)hb_free_context(c[k]);for(uint64_t i=0;i<count;i++)if(keep[i])hb_ir_func_destroy(keep[i]);free(keep);munmap(code,count*slot);munmap(stack,stacksize);munmap(data,page);
 if(!selected||unsupported)return 2;return(bad[0]||bad[1])?1:0;
}
#endif
int main(int argc,char**argv){
 if(argc==2&&!strcmp(argv[1],"--self-test"))return hb_comparator_selftest();
#ifdef HB_ORACLE_COMPARATOR_ONLY
 fputs("comparator-only binary: --self-test\n",stderr);return 2;
#else
 if(argc<2||argc>4||(argc==4&&strcmp(argv[2],"--filter"))){fputs("usage: hb_flags_state_test corpus.hbfl|- [--filter substring]\n",stderr);return 2;}
 FILE*f=!strcmp(argv[1],"-")?stdin:fopen(argv[1],"rb");if(!f){perror(argv[1]);return 2;}int rc=run(f,argc==4?argv[3]:NULL);if(f!=stdin)fclose(f);return rc;
#endif
}
