// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>
#include <stddef.h>
struct Ctx { uint8_t d[32],a[32],b[32],out[32],maskout[32]; uint8_t *mem; uint64_t gp,gout; };
_Static_assert(offsetof(struct Ctx,mem)==160,"ABI");
#include "movement-generated.h"
static sigjmp_buf jump;
static struct Ctx *active;
static volatile sig_atomic_t fault,trap,err;
static void handler(int sig,siginfo_t *si,void *v){
 (void)si; ucontext_t *u=v; fault=sig; trap=u->uc_mcontext.gregs[REG_TRAPNO]; err=u->uc_mcontext.gregs[REG_ERR];
 uint8_t *x=(uint8_t*)u->uc_mcontext.fpregs;
 if(active && x){
  for(int j=0;j<16;j++){active->out[j]=x[160+j];active->maskout[j]=x[192+j];}
  uint32_t magic; uint64_t bv; memcpy(&magic,x+464,4);memcpy(&bv,x+512,8);
  if(magic==0x46505853 && (bv&4)) for(int j=0;j<16;j++){active->out[j+16]=x[576+j];active->maskout[j+16]=x[608+j];}
  else for(int j=16;j<32;j++){active->out[j]=0;active->maskout[j]=0;}
  active->gout=u->uc_mcontext.gregs[REG_RAX];
 }
 siglongjmp(jump,1);
}
static void run_op(const struct Op *o,struct Ctx *c){
 fault=trap=err=0;active=c;
 if(sigsetjmp(jump,1)==0)o->fn(c);
 active=0;
}
static uint64_t readle(const uint8_t *p,int n){uint64_t v=0;for(int i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void writele(uint8_t *p,int n,uint64_t v){for(int i=0;i<n;i++)p[i]=v>>(8*i);}
static void hex(const uint8_t *p,int n){for(int i=n-1;i>=0;i--)printf("%02x",p[i]);}
static void pattern(uint8_t *p,int mode,int e){
 /* A 128-bit move chunk has no scalar integer element semantics. Build it
    from two well-defined 64-bit pattern units; never shift a uint64_t by >=64. */
 if(e>8)e=8;
 uint64_t mask=e==8?UINT64_MAX:((UINT64_C(1)<<(e*8))-1),sign=UINT64_C(1)<<(e*8-1);
 uint64_t vals[8]={0,1,mask,sign,sign-1,UINT64_C(0xaaaaaaaaaaaaaaaa)&mask,UINT64_C(0x5555555555555555)&mask,2};
 for(int i=0;i<32;i+=e){uint64_t v= mode==0?0:mode==1?0:mode==2?mask:mode==3?1:mode==4?sign:mode==5?sign-1:mode==6?vals[5]:mode==7?vals[6]:vals[(i/e)%8];writele(p+i,e,v);}
 if(!mode)for(int i=0;i<32;i++)p[i]=i;
}
static int masked(const struct Op *o){return o->kind==K_MASKLOAD||o->kind==K_MASKSTORE;}
static int cases(const struct Op *o){return masked(o)?7:o->mem?2:1;}
static int writes(const struct Op *o){return !(o->kind==K_GPRSTORE||o->kind==K_MOVMASK||o->kind==K_SCALARSTORE||o->kind==K_STORE||o->kind==K_HALFSTORE||o->kind==K_EXTRACT||o->kind==K_MASKSTORE||(o->kind==K_EXTRACT128&&o->mem));}
static void model(const struct Op *o,const struct Ctx *c,const uint8_t *mb,uint8_t *d,uint8_t *ma,uint64_t *g){
 memcpy(d,c->d,32);memcpy(ma,mb,32);*g=c->gp;
 int vex=o->enc[0]=='V',e=o->e,w=o->w,i=o->imm;const uint8_t *s=o->mem==1?mb:c->a;
 if(writes(o)&&vex)memset(d+16,0,16);
 switch(o->kind){
 case K_GPRLOAD:memset(d,0,16);writele(d,e,c->gp);break;
 case K_GPRSTORE:*g=readle(c->a,e);break;
 case K_SCALARLOAD:memset(d,0,16);memcpy(d,s,e);break;
 case K_SCALARSTORE:memcpy(ma,c->a,e);break;
 case K_COPY:memcpy(d,s,w);break;
 case K_STORE:memcpy(ma,c->a,w);break;
 case K_SCALARMIX:if(vex){memcpy(d,c->a,16);memcpy(d,c->b,e);}else memcpy(d,c->a,e);break;
 case K_HALFLOAD:if(vex)memcpy(d,c->a,16);memcpy(d+8*o->aux,mb,8);break;
 case K_HALFSTORE:memcpy(ma,c->a+8*o->aux,8);break;
 case K_HALFMIX:
  if(vex)memcpy(d,c->a,16);
  if(o->aux)memcpy(d,(vex?c->b:c->a)+8,8);else memcpy(d+8,vex?c->b:c->a,8);break;
 case K_DUPLICATE:for(int j=0;j<w/e;j++)memcpy(d+j*e,s+((j/2)*2+o->aux)*e,e);break;
 case K_EXTEND:{int out=o->aux&255,sx=o->aux>>8;for(int j=0;j<w/out;j++){uint64_t v=readle(s+j*e,e);if(sx&&(v&(UINT64_C(1)<<(e*8-1))))v|=~((UINT64_C(1)<<(e*8))-1);writele(d+j*out,out,v);}break;}
 case K_MOVMASK:*g=0;for(int j=0;j<w/e;j++)*g|=(uint64_t)(c->a[(j+1)*e-1]>>7)<<j;break;
 case K_MASKSTORE:for(int j=0;j<w/e;j++)if(c->b[(j+1)*e-1]&128)memcpy(ma+j*e,c->a+j*e,e);break;
 case K_MASKLOAD:memset(d,0,w);for(int j=0;j<w/e;j++)if(c->b[(j+1)*e-1]&128)memcpy(d+j*e,mb+j*e,e);break;
 case K_EXTRACT:{int index=i&((16/e)-1);if(o->mem)memcpy(ma,c->a+index*e,e);else *g=readle(c->a+index*e,e);break;}
 case K_INSERT:if(vex)memcpy(d,c->a,16);if(o->mem)memcpy(d+(i&((16/e)-1))*e,mb,e);else writele(d+(i&((16/e)-1))*e,e,c->gp);break;
 case K_INSERTPS:{if(vex)memcpy(d,c->a,16);const uint8_t *p=o->mem?mb:(vex?c->b:c->a)+((i>>6)&3)*4;memcpy(d+((i>>4)&3)*4,p,4);for(int j=0;j<4;j++)if(i&(1<<j))memset(d+j*4,0,4);break;}
 case K_BROADCAST:for(int j=0;j<w;j+=e)memcpy(d+j,s,e);break;
 case K_EXTRACT128:if(o->mem)memcpy(ma,c->a+(i&1)*16,16);else {memcpy(d,c->a+(i&1)*16,16);memset(d+16,0,16);}break;
 case K_INSERT128:memcpy(d,c->a,32);memcpy(d+(i&1)*16,o->mem?mb:c->b,16);break;
 }
}
/* Canonical primary operands: X1 is the actual destination, never a spare
 * tracking register. Full physical-register evidence remains in named extras. */
static int gpr_dest(const struct Op*o){return o->kind==K_GPRSTORE||o->kind==K_MOVMASK||(o->kind==K_EXTRACT&&!o->mem);}
static int mem_dest(const struct Op*o){return o->kind==K_SCALARSTORE||o->kind==K_STORE||o->kind==K_HALFSTORE||o->kind==K_MASKSTORE||(o->kind==K_EXTRACT&&o->mem)||(o->kind==K_EXTRACT128&&o->mem);}
static int dest_bytes(const struct Op*o){
 if(gpr_dest(o))return o->kind==K_MOVMASK?4:o->e==8?8:4;
 if(mem_dest(o)){if(o->kind==K_HALFSTORE)return 8;if(o->kind==K_EXTRACT128)return 16;if(o->kind==K_SCALARSTORE||o->kind==K_EXTRACT)return o->e;return o->w;}
 return o->kind==K_EXTRACT128?16:o->w;
}
static int memory_source_bytes(const struct Op*o){
 switch(o->kind){case K_SCALARLOAD:case K_INSERT:case K_INSERTPS:case K_BROADCAST:return o->e;
 case K_HALFLOAD:return 8;case K_EXTEND:return o->w/(o->aux&255)*o->e;
 case K_INSERT128:return 16;case K_DUPLICATE:return o->e==8&&o->w==16?8:o->w;
 default:return o->w;}
}
static void memvalue(const uint8_t*p,int n,int accessible){if(accessible<n)printf("UNKNOWN");else hex(p,n);}
static void gpvalue(uint64_t v,int n){hex((const uint8_t*)&v,n);}
static void canonical_sources(const struct Op*o,const struct Ctx*c,const uint8_t*mb,int accessible){
 int vex=o->enc[0]=='V';
 if(o->kind==K_GPRLOAD){gpvalue(c->gp,o->e);printf(" -");return;}
 if(o->kind==K_MASKLOAD){hex(c->b,32);printf(" ");memvalue(mb,o->w,accessible);return;}
 if(o->kind==K_MASKSTORE){if(strstr(o->name,"maskmovdqu")){hex(c->a,32);printf(" ");hex(c->b,32);}else{hex(c->b,32);printf(" ");hex(c->a,32);}return;}
 if(o->kind==K_INSERT){if(vex){hex(c->a,32);printf(" ");}if(o->mem)memvalue(mb,o->e,accessible);else gpvalue(c->gp,o->e==8?8:4);if(!vex)printf(" -");return;}
 if(o->kind==K_INSERTPS){if(vex){hex(c->a,32);printf(" ");}if(o->mem)memvalue(mb,4,accessible);else hex(vex?c->b:c->a,32);if(!vex)printf(" -");return;}
 if(o->kind==K_INSERT128){hex(c->a,32);printf(" ");if(o->mem)memvalue(mb,16,accessible);else hex(c->b,32);return;}
 if(o->kind==K_HALFLOAD){if(vex){hex(c->a,32);printf(" ");}memvalue(mb,8,accessible);if(!vex)printf(" -");return;}
 if(o->kind==K_SCALARMIX||o->kind==K_HALFMIX){hex(c->a,32);printf(" ");if(vex)hex(c->b,32);else printf("-");return;}
 if(o->mem==1)memvalue(mb,memory_source_bytes(o),accessible);else hex(c->a,32);printf(" -");
}
int main(void){
 if(!__builtin_cpu_supports("avx2")){fprintf(stderr,"AVX2 unavailable\n");return 2;}
 struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);sigaction(SIGSEGV,&sa,0);sigaction(SIGBUS,&sa,0);sigaction(SIGILL,&sa,0);
 long ps=sysconf(_SC_PAGESIZE);uint8_t *area=mmap(0,ps*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(area==MAP_FAILED||mprotect(area+ps,ps,PROT_READ|PROT_WRITE))return 3;
 uint64_t expected=0,rows=0,checked=0,faults=0;for(size_t z=0;z<sizeof(ops)/sizeof(*ops);z++)expected+=9*cases(ops+z);
 printf("# Native SSE/AVX/AVX2 data movement. Values are full YMM snapshots, most significant byte first.\n");
 printf("# name[imm].encoding.case.pN destination_width X1(actual destination before) X2 X3 -> actual_destination_after; absent source=-; vectors always full YMM\n");
 printf("# UNKNOWN means an unreadable full memory value; named MEM_BEFORE/MEM_AFTER contain only actually readable prefixes. ACCESSIBLE_BYTES gives that prefix length. All memory is process-owned.\n");
 printf("# Patterns: p0 numbered bytes; p1 zero; p2 all ones; p3 element 1; p4 sign minimum; p5 sign maximum; p6 AA; p7 55; p8 mixed edge elements. Expected rows: %llu\n",(unsigned long long)expected);
 FILE *ct=fopen("movement-counts.tsv","w");if(!ct)return 4;fprintf(ct,"name\tencoding\twidth\timmediate\trows\tscalar_checked\tfaults\n");
 for(size_t z=0;z<sizeof(ops)/sizeof(*ops);z++){
  const struct Op *o=ops+z;int oc=0,of=0;
  for(int p=0;p<9;p++)for(int mode=0;mode<cases(o);mode++){
   struct Ctx c={0};uint8_t mb[32]={0},ma[32]={0},md[32],mm[32],src[32];uint64_t mg;int accessible=32;
   for(int j=0;j<32;j++){c.d[j]=(uint8_t)(0xc0+j+p*7);c.b[j]=(uint8_t)(0x91+j*3+p);}
   pattern(c.a,p,o->e);pattern(src,(p+3)%9,o->e); c.gp=readle(src,8);c.gout=c.gp;
   c.mem=area+ps+64+(mode==1);
   if(masked(o)){
    if(mode==2||mode==3){accessible=o->w/2;c.mem=area+ps*2-accessible;}
    if(mode==4){accessible=0;c.mem=area+ps*2;}
    for(int j=0;j<o->w/o->e;j++){int on=(mode==2)?j<o->w/o->e/2:(mode==3||mode==5)?1:(mode==4)?0:(j%2==0);writele(c.b+j*o->e,o->e,on?UINT64_MAX:UINT64_C(0x12345678)&~(UINT64_C(1)<<(o->e*8-1)));}
   }
   for(int j=0;j<accessible;j++)c.mem[j]=o->mem==1?c.a[j]:(uint8_t)(0x60+j+p);
   if(o->mem)memcpy(mb,c.mem,accessible);
   model(o,&c,mb,md,mm,&mg);
   memcpy(c.out,c.d,32);memcpy(c.maskout,c.b,32);run_op(o,&c);
   if(o->mem)memcpy(ma,c.mem,accessible);
   int want_fault=(o->align>1&&mode==1)||(masked(o)&&mode==3);
   int optional_fault=strstr(o->name,"maskmovdqu")&&(mode==2||mode==4);
   if(!optional_fault&&(fault!=0)!=want_fault){fprintf(stderr,"fault mismatch %s %s p%d mode%d got%d expected%d\n",o->name,o->enc,p,mode,fault,want_fault);return 5;}
   if(!fault){
    if(memcmp(c.out,md,32)||memcmp(c.maskout,c.b,32)||c.gout!=mg||(o->mem&&memcmp(ma,mm,accessible))){
     fprintf(stderr,"model mismatch %s %s imm%d p%d mode%d: out=%d mask=%d gp=%d mem=%d\n",o->name,o->enc,o->imm,p,mode,memcmp(c.out,md,32),memcmp(c.maskout,c.b,32),c.gout!=mg,o->mem?memcmp(ma,mm,accessible):0);return 6;
    }
   }else {faults++;of++;
    if(fault!=SIGSEGV || memcmp(c.out,c.d,32) || memcmp(c.maskout,c.b,32) || c.gout!=c.gp){fprintf(stderr,"fault state invariant failed %s\n",o->name);return 7;}
    if(o->mem)for(int j=0;j<accessible;j++)if(ma[j]!=mb[j]&&ma[j]!=mm[j]){fprintf(stderr,"fault memory invariant failed\n");return 8;}
   }
   checked++;oc++;rows++;
   static const char *modes[]={"aligned","unaligned","guard_off","guard_on","alloff_guard","allon","alternating"};
   int db=dest_bytes(o),gd=gpr_dest(o),mdst=mem_dest(o);
   printf("%s",o->name);if(o->imm>=0)printf("[%d]",o->imm);printf(".%s.%s.p%d %d ",o->enc,o->mem?modes[mode]:"reg",p,db*8);
   if(gd)gpvalue(c.gp,db);else if(mdst)memvalue(mb,db,accessible);else hex(c.d,32);
   printf(" ");canonical_sources(o,&c,mb,accessible);printf(" -> ");
   if(gd)gpvalue(c.gout,db);else if(mdst)memvalue(ma,db,accessible);else hex(c.out,32);
   printf(" YMM0_BEFORE=");hex(c.d,32);printf(" YMM0_AFTER=");hex(c.out,32);
   printf(" SOURCE_YMM1=");hex(c.a,32);printf(" INPUT_YMM2=");hex(c.b,32);printf(" MASK_AFTER=");hex(c.maskout,32);
   printf(" MEM_BEFORE=");if(o->mem&&accessible)hex(mb,accessible);else printf("-");
   printf(" MEM_AFTER=");if(o->mem&&accessible)hex(ma,accessible);else printf("-");
   printf(" FAULT=%d TRAP=%d ERROR=%d ACCESSIBLE_BYTES=%d GPR_BEFORE_FULL64=%016llx GPR_AFTER_FULL64=%016llx DEST_KIND=%s ENCODED_BITS=%d\n",fault,trap,err,o->mem?accessible:0,(unsigned long long)c.gp,(unsigned long long)c.gout,gd?"GPR":mdst?"MEM":"YMM",o->w*8);
  }
  fprintf(ct,"%s\t%s\t%d\t%d\t%d\t%d\t%d\n",o->name,o->enc,o->w*8,o->imm,oc,oc,of);
 }
 fclose(ct);fprintf(stderr,"movement rows=%llu expected=%llu scalar_checked=%llu faults=%llu forms=%zu\n",(unsigned long long)rows,(unsigned long long)expected,(unsigned long long)checked,(unsigned long long)faults,sizeof(ops)/sizeof(*ops));
 return rows!=expected;
}
