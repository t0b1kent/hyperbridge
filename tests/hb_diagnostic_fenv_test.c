/* Real L1 periodic/final/term diagnostics must preserve the caller's complete
 * floating environment. Long-lived raw NOP JIT runtimes deliberately cross
 * report thresholds. Public counters additionally exercise distant thresholds
 * without billions of guest executions; their sums do not overflow uint64_t.
 * Percentages retain the existing floating expression and caller RC. This does
 * not claim preservation by unrelated opt-in runtime diagnostics.
 */
#pragma STDC FENV_ACCESS ON
#include "hb_decoder.h"
#include "hb_env.h"
#include "hb_lifter.h"
#include "hb_memory.h"
#include "hb_runtime.h"
#include "hb_x87.h"
#include <errno.h>
#include <fenv.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

enum {PAGE_BYTES=16384,CAPTURE_BYTES=32768};
enum {HOST,STATE,EXECUTION,REPORT,CATEGORIES};
static const uint64_t CODE=UINT64_C(0x4c00000);
static const uint8_t code[]={0x90};
static unsigned checks,failures,executions,reports,proof_lines,category_failures[CATEGORIES];
static unsigned natural_count,seeded_count,final_count,term_count;
static int trap_support=-1;
static int diagnostic_fd=-1;
static char phase[180]="setup";
static const int host_modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
static int check_kind(int ok,const char *what,unsigned category)
{
    ++checks;if(!ok){++failures;++category_failures[category];if(failures<=80)dprintf(diagnostic_fd>=0?diagnostic_fd:STDERR_FILENO,"FAIL %s: %s\n",phase,what);}return ok;
}
static int check(int ok,const char *what){return check_kind(ok,what,STATE);}

typedef struct {int saved,read_fd;size_t used;char text[CAPTURE_BYTES];} capture_t;
static int capture_begin(capture_t *c)
{
    int p[2];memset(c,0,sizeof(*c));c->saved=c->read_fd=-1;
    if(!check(fflush(stderr)==0&&pipe(p)==0,"create owned diagnostic capture pipe"))return 0;
    c->saved=dup(STDERR_FILENO);c->read_fd=p[0];
    if(c->saved<0||fcntl(c->read_fd,F_SETFL,O_NONBLOCK)<0||dup2(p[1],STDERR_FILENO)<0){close(p[1]);if(c->saved>=0)close(c->saved);close(c->read_fd);c->saved=c->read_fd=-1;return check(0,"redirect stderr to owned pipe");}
    close(p[1]);return 1;
}
static void capture_drain(capture_t *c)
{
    if(c->read_fd<0)return;(void)fflush(stderr);
    for(;;){char chunk[2048];ssize_t n=read(c->read_fd,chunk,sizeof(chunk));
        if(n>0){size_t room=sizeof(c->text)-1-c->used,take=(size_t)n<room?(size_t)n:room;
            memcpy(c->text+c->used,chunk,take);c->used+=take;c->text[c->used]=0;
            check_kind(take==(size_t)n,"bounded captured diagnostics not truncated",REPORT);continue;}
        if(n<0&&errno==EINTR)continue;if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK)check(0,"read captured stderr");break;}
}
static void capture_clear(capture_t *c){capture_drain(c);c->used=0;c->text[0]=0;}
static void capture_end(capture_t *c)
{
    capture_drain(c);if(c->saved>=0){check(dup2(c->saved,STDERR_FILENO)>=0,"restore original stderr descriptor");close(c->saved);c->saved=-1;}
    if(c->read_fd>=0){close(c->read_fd);c->read_fd=-1;}
}
static uint64_t field_u64(const char *line,const char *key,int *ok)
{
    const char *p=strstr(line,key);if(!p){*ok=0;return 0;}p+=strlen(key);char *end=NULL;errno=0;unsigned long long n=strtoull(p,&end,10);
    if(errno||end==p)*ok=0;return (uint64_t)n;
}
static int record(capture_t *c,const char *prefix,uint64_t total,uint64_t hits,const char *percent)
{
    const char *p=c->text;int found=0;
    while((p=strstr(p,prefix))!=NULL){const char *end=strchr(p,'\n');size_t n=end?(size_t)(end-p):strlen(p);char line[1024];if(n>=sizeof(line))n=sizeof(line)-1;memcpy(line,p,n);line[n]=0;
        int ok=1;uint64_t actual_total=field_u64(line,"обращений=",&ok),actual_hits=field_u64(line,"попаданий=",&ok);
        if(ok&&actual_total==total&&actual_hits==hits){++found;++reports;
            if(percent){char needle[80];snprintf(needle,sizeof(needle),"доля=%s%%",percent);check_kind(strstr(line,needle)!=NULL,"reported percentage respects existing expression and caller RC",REPORT);}
            if(proof_lines<24){printf("CAPTURED %s\n",line);++proof_lines;}}
        p+=strlen(prefix);}
    return found;
}
static unsigned natural_records(capture_t *c)
{
    const char *p=c->text;unsigned seen=0;
    while((p=strstr(p,"macrunner-hb-l1cache:"))!=NULL){int ok=1;uint64_t total=field_u64(p,"обращений=",&ok),hits=field_u64(p,"попаданий=",&ok);
        if(ok&&(total==4096||total==8192||total==16384)){seen|=total==4096?1:total==8192?2:4;natural_count+=(unsigned)record(c,"macrunner-hb-l1cache:",total,hits,NULL);}p+=strlen("macrunner-hb-l1cache:");}
    return seen;
}
static int has_term_record(capture_t *c)
{
    const char *p=strstr(c->text,"macrunner-hb-l1term:");if(!p)return 0;int ok=1;uint64_t total=field_u64(p,"обращений=",&ok),hits=field_u64(p,"попаданий=",&ok);
    return ok&&total&&hits<=total&&strstr(p,"доля=")!=NULL;
}

typedef struct {fenv_t raw;int rc,status;} host_state_t;
static int host_snapshot(host_state_t *s)
{
    memset(s,0,sizeof(*s));if(fegetenv(&s->raw)!=0)return 0;s->rc=fegetround();s->status=fetestexcept(FE_ALL_EXCEPT);return 1;
}
static int same_host(const host_state_t *a,const host_state_t *b)
{
#if defined(__APPLE__) && defined(__arm64__)
    return a->raw.__fpcr==b->raw.__fpcr&&a->raw.__fpsr==b->raw.__fpsr&&a->rc==b->rc&&a->status==b->status;
#else
    return !memcmp(&a->raw,&b->raw,sizeof(a->raw))&&a->rc==b->rc&&a->status==b->status;
#endif
}
static int seed_host(unsigned rc,unsigned flags,unsigned extra,host_state_t *want)
{
    if(!check(fesetround(host_modes[rc])==0&&feclearexcept(FE_ALL_EXCEPT)==0,"select host RC and clear sticky flags"))return 0;
#if defined(__APPLE__) && defined(__arm64__)
    fenv_t env;if(!check(fegetenv(&env)==0,"read SDK floating environment"))return 0;
    /* Direct SDK status assignment establishes every exact combination,
     * including overflow without inexact, without feraiseexcept dependencies. */
    env.__fpsr=(env.__fpsr&~(unsigned long long)(FE_ALL_EXCEPT|__fpsr_saturation))|flags|((extra&1)?__fpsr_saturation:0);
    env.__fpcr=(env.__fpcr&~(unsigned long long)__fpcr_flush_to_zero)|((extra&2)?__fpcr_flush_to_zero:0);
    if(!check(fesetenv(&env)==0,"seed SDK QC and FZ control"))return 0;
#else
    (void)extra;
    if(!check(feraiseexcept((int)flags)==0,"seed portable supported sticky flags"))return 0;
#endif
    if(!check(host_snapshot(want),"snapshot seeded complete host fenv"))return 0;
#if defined(__APPLE__) && defined(__arm64__)
    check(want->status==(int)flags,"every requested status combination established exactly by readback");
    check((want->raw.__fpsr&__fpsr_saturation)==((extra&1)?__fpsr_saturation:0)&&
          (want->raw.__fpcr&__fpcr_flush_to_zero)==((extra&2)?__fpcr_flush_to_zero:0),"QC/FZ readback establishes actual test state");
#else
    check((want->status&(int)flags)==(int)flags,"portable requested flags present; dependent flags included in snapshot");
#endif
    return 1;
}
static unsigned status_pattern(unsigned pattern)
{
    unsigned result=0,position=0;for(unsigned bit=1;bit;bit<<=1)if((unsigned)FE_ALL_EXCEPT&bit){if(pattern&(1u<<position))result|=bit;++position;}return result;
}
static unsigned pattern_count(void)
{
    unsigned n=0;for(unsigned v=(unsigned)FE_ALL_EXCEPT;v;v>>=1)n+=v&1;return n<8?1u<<n:256;
}

typedef struct {hb_context_t *c;hb_jit_runtime_t *jit;hb_decoder_t *decoder;hb_ir_func_t *func;unsigned enabled;} fixture_t;
static void seed_guest(hb_context_t *c)
{
    memset(&c->regs,0x3c,sizeof(c->regs));if(c->arch==HB_ARCH_X86){c->regs.x86.eip=(uint32_t)CODE;c->regs.x86.eflags=0xa57;memset(&c->x87_64,0x49,sizeof(c->x87_64));}
    else {c->regs.x64.rip=CODE;c->regs.x64.rflags=0xa57;}hb_x87_reset(hb_context_x87(c));
    memset(c->ymm_hi,0x7a,sizeof(c->ymm_hi));memset(c->zmm_hi,0x4b,sizeof(c->zmm_hi));memset(c->k,0x39,sizeof(c->k));
    memset(c->xmm_ext,0x51,sizeof(c->xmm_ext));memset(c->ymm_hi_ext,0x62,sizeof(c->ymm_hi_ext));memset(c->zmm_hi_ext,0x73,sizeof(c->zmm_hi_ext));
    c->flags=(hb_flags_t){.cf=true,.pf=true,.af=true,.zf=true,.of=true};memset(&c->lazy_flags,0,sizeof(c->lazy_flags));c->mxcsr=0x5fa1;
    c->pc=CODE;c->last_result=HB_OK;c->last_fault_kind=HB_FAULT_KIND_NONE;c->last_fault_addr_valid=0;c->step_limit=8;c->block_limit=2;
    c->fs_base=0x11110000;c->gs_base=0x22220000;c->seg_cs=0x33;c->seg_ds=0x2b;c->seg_es=0x31;c->seg_fs=0x53;c->seg_gs=0x61;c->seg_ss=0x69;
}
static void check_guest(hb_context_t *c,const hb_context_t *before,int executed)
{
    hb_context_t e;memcpy(&e,before,sizeof(e));if(executed){e.pc=CODE+1;if(c->arch==HB_ARCH_X86)e.regs.x86.eip=(uint32_t)e.pc;else e.regs.x64.rip=e.pc;}
    check(!memcmp(&c->regs,&e.regs,sizeof(e.regs))&&!memcmp(&c->x87_64,&e.x87_64,sizeof(e.x87_64)),"NOP/report preserves GPR/XMM/x87 state");
    check(c->pc==e.pc&&c->mxcsr==e.mxcsr&&!memcmp(&c->flags,&e.flags,sizeof(e.flags))&&!memcmp(&c->lazy_flags,&e.lazy_flags,sizeof(e.lazy_flags)),"only normal instruction PC advance; flags/MXCSR preserved");
    check(!memcmp(c->ymm_hi,e.ymm_hi,sizeof(e.ymm_hi))&&!memcmp(c->zmm_hi,e.zmm_hi,sizeof(e.zmm_hi))&&!memcmp(c->k,e.k,sizeof(e.k))&&!memcmp(c->xmm_ext,e.xmm_ext,sizeof(e.xmm_ext))&&!memcmp(c->ymm_hi_ext,e.ymm_hi_ext,sizeof(e.ymm_hi_ext))&&!memcmp(c->zmm_hi_ext,e.zmm_hi_ext,sizeof(e.zmm_hi_ext)),"full upper vector/opmask state preserved");
    check(c->fs_base==e.fs_base&&c->gs_base==e.gs_base&&c->seg_cs==e.seg_cs&&c->seg_ds==e.seg_ds&&c->seg_es==e.seg_es&&c->seg_fs==e.seg_fs&&c->seg_gs==e.seg_gs&&c->seg_ss==e.seg_ss,"segments preserved");
}
static int native_present(fixture_t *f)
{
    if(!f->jit||!f->jit->block_cache)return 0;hb_block_cache_t *c=f->jit->block_cache;
    for(size_t i=0;i<c->size;++i)if(c->entries[i].valid&&c->entries[i].guest_addr==CODE&&c->entries[i].native_code&&c->entries[i].native_size)return 1;return 0;
}
static int setup(fixture_t *f,hb_arch_t arch,unsigned enabled)
{
    memset(f,0,sizeof(*f));f->enabled=enabled;
    if(!check(setenv("MACRUNNER_HB_L1_CACHE",enabled?"1":"0",1)==0,"select L1 cache policy"))return 0;hb_env_refresh();
    const char *gate=hb_gate(HB_GATE_HB_L1_CACHE);if(!check(gate&&!strcmp(gate,enabled?"1":"0"),"effective L1 policy"))return 0;
    f->c=hb_context_create(arch,HB_BACKEND_JIT);if(!check(f->c!=NULL,"create context"))return 0;f->c->memory=hb_memory_create(0);
    if(!check(f->c->memory&&hb_memory_map_private(f->c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_WRITE)==HB_OK&&hb_memory_write(f->c->memory,CODE,code,1)==HB_OK&&hb_memory_protect(f->c->memory,CODE,PAGE_BYTES,HB_PERM_READ|HB_PERM_EXEC)==HB_OK,"map private raw NOP"))return 0;
    hb_decoded_t d={0};hb_result_t r=arch==HB_ARCH_X86?hb_decode_x86(code,1,CODE,&d):hb_decode_x64(code,1,CODE,&d);
    if(!check_kind(r==HB_OK&&d.opcode==HB_INS_NOP&&d.len==1,"decode NOP 90",EXECUTION))return 0;
    f->decoder=hb_decoder_create(arch,code,1,CODE);if(!check(f->decoder!=NULL,"create decoder"))return 0;
    r=arch==HB_ARCH_X86?hb_lift_func_x86(f->decoder,&f->func):hb_lift_func_x64(f->decoder,&f->func);if(!check_kind(r==HB_OK&&f->func,"lift raw NOP",EXECUTION))return 0;
    f->jit=hb_jit_runtime_create(f->c);return check(f->jit&&f->jit->block_cache,"create long-lived JIT/cache");
}
static void cleanup(fixture_t *f)
{
    if(f->jit)hb_jit_runtime_destroy(f->jit);if(f->decoder)hb_decoder_destroy(f->decoder);if(f->func)hb_ir_func_destroy(f->func);if(f->c)hb_context_destroy(f->c);memset(f,0,sizeof(*f));
}
static int run_checked(fixture_t *f,capture_t *capture,unsigned rc,unsigned flags,unsigned extra)
{
    seed_guest(f->c);hb_context_t before;memcpy(&before,f->c,sizeof(before));capture_clear(capture);
    host_state_t want,actual;if(!seed_host(rc,flags,extra,&want))return 0;hb_exec_result_t out={0};
    hb_result_t r=hb_jit_runtime_run(f->jit,f->func,&out);int sampled=host_snapshot(&actual);++executions;
    if(!check_kind(sampled&&same_host(&want,&actual),"actual JIT/report call preserves complete host fenv",HOST)&&category_failures[HOST]<=4)
        dprintf(diagnostic_fd,"HOST %s actual rc=%d flags=%x expected rc=%d flags=%x\n",phase,actual.rc,actual.status,want.rc,want.status);
    check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&!out.timed_out&&out.steps_executed&&out.blocks_executed,"native NOP execution completes",EXECUTION);
    check_guest(f->c,&before,1);capture_drain(capture);return 1;
}
static const char *third_percent(unsigned rc){return rc==2?"33.34":"33.33";}
typedef struct {uint64_t total,hits;unsigned percent_kind;} ratio_t;
static const ratio_t ratios[]={
    {4096,1024,1},{4096,1365,2},{8192,4096,3},{16384,4096,1},{3145728,1048576,4},
    {UINT64_C(0x8000000000000000),UINT64_C(0x4000000000000001),0},
    {UINT64_C(0xfffffffffff00000),UINT64_C(0xffffffffffefffff),0}
};
static void seed_ratio(fixture_t *f,const ratio_t *r)
{
    /* Warmed CODE is the first lookup: hit with L1 on, miss with L1 off.
     * The target record itself verifies this assumption and exact counters. */
    f->jit->block_cache->l1_hits=r->hits-(f->enabled?1:0);
    f->jit->block_cache->l1_misses=r->total-1-f->jit->block_cache->l1_hits;
}
static const char *ratio_percent(const ratio_t *r,unsigned rc)
{
    if(r->percent_kind==1)return "25.00";if(r->percent_kind==2)return rc==1||rc==3?"33.32":"33.33";
    if(r->percent_kind==3)return "50.00";if(r->percent_kind==4)return third_percent(rc);return NULL;
}
static void destroy_checked(fixture_t *f,capture_t *capture,unsigned rc,unsigned flags,unsigned extra,uint64_t total,uint64_t hits,const char *percent)
{
    f->jit->block_cache->l1_hits=hits;f->jit->block_cache->l1_misses=total-hits;capture_clear(capture);
    hb_context_t before;memcpy(&before,f->c,sizeof(before));host_state_t want,actual;if(!seed_host(rc,flags,extra,&want))return;
    hb_jit_runtime_destroy(f->jit);f->jit=NULL;int sampled=host_snapshot(&actual);
    check_kind(sampled&&same_host(&want,&actual),"real cache final/term diagnostics preserve full host fenv",HOST);
    check_guest(f->c,&before,0);capture_drain(capture);
    int count=record(capture,"macrunner-hb-l1cache-итог:",total,hits,percent);
    final_count+=(unsigned)count;
    check_kind(f->enabled?count==1:count==0,"final L1 report follows actual allocation policy",REPORT);
    int term=has_term_record(capture);term_count+=(unsigned)term;check_kind(term,"real term-summary diagnostic emitted",REPORT);
}
static void run_policy(hb_arch_t arch,unsigned enabled)
{
    fixture_t f={0};capture_t capture;capture.saved=capture.read_fd=-1;
    snprintf(phase,sizeof(phase),"%s L1=%u setup",arch==HB_ARCH_X86?"x86":"x64",enabled);
    if(!capture_begin(&capture)||!setup(&f,arch,enabled))goto done;
    for(unsigned i=0;i<2;++i)run_checked(&f,&capture,0,0,0);
    if(!check_kind(native_present(&f),"actual native NOP block is cached",EXECUTION))goto done;
    check((f.jit->block_cache->l1!=NULL)==(enabled!=0),"L1 allocation agrees with on/off policy");
    unsigned seen=0,n=0;while(f.jit->block_cache->l1_hits+f.jit->block_cache->l1_misses<16385&&n<20000){
        snprintf(phase,sizeof(phase),"%s L1=%u natural call=%u",arch==HB_ARCH_X86?"x86":"x64",enabled,n);
        run_checked(&f,&capture,n&3,status_pattern((n/4)%pattern_count()),(n/16)&3);seen|=natural_records(&capture);++n;}
    check_kind(seen==7,"same runtime actually emitted 4096/8192/16384 periodic reports",REPORT);
    for(unsigned rc=0;rc<4;++rc)for(unsigned pattern=0;pattern<pattern_count();++pattern)for(unsigned i=0;i<sizeof(ratios)/sizeof(ratios[0]);++i){
        snprintf(phase,sizeof(phase),"%s L1=%u seeded ratio=%u RC=%u flags=%x",arch==HB_ARCH_X86?"x86":"x64",enabled,i,rc,status_pattern(pattern));
        seed_ratio(&f,&ratios[i]);run_checked(&f,&capture,rc,status_pattern(pattern),(pattern+rc)&3);
        int count=record(&capture,"macrunner-hb-l1cache:",ratios[i].total,ratios[i].hits,ratio_percent(&ratios[i],rc));seeded_count+=(unsigned)count;
        check_kind(count==1,"real periodic record has exact seeded counters",REPORT);}
    destroy_checked(&f,&capture,2,FE_ALL_EXCEPT,3,3,1,third_percent(2));
done:
    cleanup(&f);capture_end(&capture);
    /* Destruction is a separate real call for every caller RC, both clean and
     * fully seeded status. Other optional unchain diagnostics remain disabled. */
    for(unsigned rc=0;rc<4;++rc)for(unsigned full=0;full<2;++full){
        snprintf(phase,sizeof(phase),"%s L1=%u destroy RC=%u fullflags=%u",arch==HB_ARCH_X86?"x86":"x64",enabled,rc,full);
        capture.saved=capture.read_fd=-1;if(!capture_begin(&capture)||!setup(&f,arch,enabled)){cleanup(&f);capture_end(&capture);continue;}
        for(unsigned i=0;i<2;++i)run_checked(&f,&capture,0,0,0);
        check_kind(native_present(&f),"destruction fixture executed native NOP",EXECUTION);
        destroy_checked(&f,&capture,rc,full?FE_ALL_EXCEPT:0,(rc+full)&3,full?3:4,1,full?third_percent(rc):"25.00");cleanup(&f);capture_end(&capture);}
}

static int trap_child(void)
{
#if defined(__APPLE__) && defined(__arm64__)
    fixture_t f={0};capture_t capture;capture.saved=capture.read_fd=-1;fenv_t original;int result=1;unsigned initial_failures=failures;
    struct sigaction sa;memset(&sa,0,sizeof(sa));sa.sa_handler=SIG_DFL;sigemptyset(&sa.sa_mask);if(sigaction(SIGFPE,&sa,NULL)!=0)return 1;
    if(fegetenv(&original)!=0)return 1;
    if(!capture_begin(&capture)||!setup(&f,HB_ARCH_X64,1))goto done;
    for(unsigned i=0;i<2;++i)run_checked(&f,&capture,0,0,0);
    for(unsigned stage=0;stage<2;++stage){
        snprintf(phase,sizeof(phase),"private child enabled inexact trap stage=%u",stage);capture_clear(&capture);seed_guest(f.c);
        if(stage==0)seed_ratio(&f,&ratios[1]);else {f.jit->block_cache->l1_hits=1;f.jit->block_cache->l1_misses=2;}
        hb_context_t guest_before;memcpy(&guest_before,f.c,sizeof(guest_before));
        fenv_t armed=original;armed.__fpsr&=~(unsigned long long)FE_ALL_EXCEPT;armed.__fpsr|=__fpsr_saturation;
        armed.__fpcr|=__fpcr_trap_inexact|__fpcr_flush_to_zero;
        if(fesetenv(&armed)!=0)goto done;host_state_t before,after;if(!host_snapshot(&before)){(void)fesetenv(&original);goto done;}
        if(!(before.raw.__fpcr&__fpcr_trap_inexact)){(void)fesetenv(&original);result=77;goto done;}
        hb_exec_result_t out={0};hb_result_t r=HB_OK;
        if(stage==0)r=hb_jit_runtime_run(f.jit,f.func,&out);else {hb_jit_runtime_destroy(f.jit);f.jit=NULL;}
        int sampled=host_snapshot(&after);int restored=fesetenv(&original);
        /* Restore before assertions, formatting, or teardown, even on failure. */
        check(restored==0,"child restores original fenv before assertions");check_kind(sampled&&same_host(&before,&after),"enabled trap/control/status survive real diagnostic",HOST);capture_drain(&capture);
        check_guest(f.c,&guest_before,stage==0);
        if(stage==0){check_kind(r==HB_OK&&out.result==HB_OK&&!out.faulted&&f.c->pc==CODE+1,"trap-enabled raw NOP completed",EXECUTION);
            check_kind(record(&capture,"macrunner-hb-l1cache:",4096,1365,NULL)==1,"trap-enabled periodic report actually emitted",REPORT);}
        else {check_kind(record(&capture,"macrunner-hb-l1cache-итог:",3,1,NULL)==1&&has_term_record(&capture),"trap-enabled final and term reports actually emitted",REPORT);}}
    result=failures==initial_failures?0:1;
done:
    (void)fesetenv(&original);cleanup(&f);capture_end(&capture);return result;
#else
    return 77;
#endif
}
static void run_trap_child(void)
{
    (void)fflush(NULL);pid_t pid=fork();if(!check(pid>=0,"fork isolated trap fixture"))return;
    if(pid==0){int r=trap_child();(void)fflush(NULL);_exit(r);}
    int status=0;pid_t waited;do {waited=waitpid(pid,&status,0);}while(waited<0&&errno==EINTR);
    if(!check(waited==pid,"wait for private trap fixture"))return;
    if(WIFEXITED(status)&&WEXITSTATUS(status)==77){trap_support=0;printf("LIMITATION: SDK trap controls unavailable or inexact-trap bit did not survive hardware readback; no enabled-trap proof claimed.\n");return;}
    trap_support=WIFEXITED(status)&&WEXITSTATUS(status)==0?1:-1;
    check_kind(WIFEXITED(status)&&WEXITSTATUS(status)==0,"enabled-trap child completes without SIGFPE or state loss",HOST);
    if(WIFSIGNALED(status))dprintf(diagnostic_fd,"TRAP CHILD signal=%d\n",WTERMSIG(status));
}

static const struct{const char *name;enum hb_gate_id id;const char *value;} gates[]={
    {"MACRUNNER_HB_JIT_DIRECT_MEM",HB_GATE_HB_JIT_DIRECT_MEM,"0"},{"MACRUNNER_HB_JIT_DIRECT_SCALAR_MEM",HB_GATE_HB_JIT_DIRECT_SCALAR_MEM,"0"},
    {"MACRUNNER_HB_JIT_NATIVE_MEM_IR",HB_GATE_HB_JIT_NATIVE_MEM_IR,"0"},{"MACRUNNER_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS",HB_GATE_HB_JIT_NATIVE_MEM_IR_QWORD_LOADS,"0"},
    {"MACRUNNER_HB_JIT_DIRECT_STACK_X64",HB_GATE_HB_JIT_DIRECT_STACK_X64,"0"},{"MACRUNNER_HB_TSO_RELAXED_LOADS",HB_GATE_HB_TSO_RELAXED_LOADS,"0"},
    {"MACRUNNER_HB_TSO_STACK_RELAXED",HB_GATE_HB_TSO_STACK_RELAXED,"0"},{"MACRUNNER_HB_L1_CACHE",HB_GATE_HB_L1_CACHE,"1"},
    {"MACRUNNER_HB_L1_LAZY",HB_GATE_HB_L1_LAZY,"0"},{"MACRUNNER_HB_L1_VERIFY",HB_GATE_HB_L1_VERIFY,"0"},
    {"MACRUNNER_HB_L1_TERM_STATS",HB_GATE_HB_L1_TERM_STATS,"1"},{"MACRUNNER_HB_UNCHAIN_STATS",HB_GATE_HB_UNCHAIN_STATS,"0"}
};
int main(void)
{
    char *saved[sizeof(gates)/sizeof(gates[0])]={0};size_t saved_count=0;int changed=0,host_saved=0;fenv_t original_host;
    diagnostic_fd=dup(STDERR_FILENO);if(diagnostic_fd<0)return 1;
    for(size_t i=0;i<sizeof(gates)/sizeof(gates[0]);++i){const char *v=getenv(gates[i].name);if(v&&!check((saved[i]=strdup(v))!=NULL,"save gate"))goto done;++saved_count;}
    changed=1;for(size_t i=0;i<saved_count;++i)if(!check(setenv(gates[i].name,gates[i].value,1)==0,"configure explicit memory/cache/diagnostic policy"))goto done;
    hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);if(!check(v&&!strcmp(v,gates[i].value),"effective test gate"))goto done;}
    if(!check(fegetenv(&original_host)==0,"independently snapshot original complete host fenv"))goto done;host_saved=1;
    fenv_t ignored;if(!check(feholdexcept(&ignored)==0,"mask host exceptions for main matrix"))goto done;
#if !defined(__APPLE__) || !defined(__arm64__)
    printf("LIMITATION: portable feraiseexcept may add dependent flags; only actual seeded snapshots are compared, not all exact status combinations or ARM64 QC/FZ.\n");
#endif
    for(unsigned arch=0;arch<2;++arch)for(unsigned enabled=0;enabled<2;++enabled)run_policy(arch?HB_ARCH_X64:HB_ARCH_X86,enabled);
    run_trap_child();
done:
    snprintf(phase,sizeof(phase),"cleanup");if(host_saved)check(fesetenv(&original_host)==0,"restore original complete host fenv");
    if(changed){for(size_t i=0;i<saved_count;++i)check((saved[i]?setenv(gates[i].name,saved[i],1):unsetenv(gates[i].name))==0,"restore gate value or absence");hb_env_refresh();for(size_t i=0;i<saved_count;++i){const char *v=hb_gate(gates[i].id);check(saved[i]?v&&!strcmp(v,saved[i]):!v,"effective original gate restored");}}
    for(size_t i=0;i<saved_count;++i)free(saved[i]);
    printf("hb_diagnostic_fenv_test: %u executions, %u captured target reports, %u checks, %u failures\n",executions,reports,checks,failures);
    printf("failure categories: host=%u state=%u execution=%u report=%u\n",category_failures[HOST],category_failures[STATE],category_failures[EXECUTION],category_failures[REPORT]);
    printf("coverage: natural=%u seeded=%u final=%u term=%u status_patterns=%u traps=%s\n",natural_count,seeded_count,final_count,term_count,pattern_count(),trap_support==1?"verified":trap_support==0?"unsupported":"failed-or-not-run");
    close(diagnostic_fd);return failures?1:0;
}
