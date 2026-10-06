/* Original native x86 integer oracle. MIT License. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <cpuid.h>
#include <limits.h>
typedef unsigned __int128 U;
typedef __int128 I;
typedef struct { uint64_t a,b,c,d,f,mem,fb,fa,r1,r2,r3,r4; int trap; } Ctx;
typedef struct { const char *cls,*op; int w; const char *mode; int count; void(*fn)(Ctx*); } Form;
#include "build/forms.h"
static sigjmp_buf escape; static Ctx *volatile active;
static uint64_t rows,expected,checks_r,checks_f,bad_r,bad_f,traps,formcount,capturechecks,capturebad;
static uint64_t pat[4][22]; static U pat128[22];
static const uint64_t fixed[10]={0x0123456789abcdefULL,0xfedcba9876543210ULL,0x9e3779b97f4a7c15ULL,0xd1b54a32d192ed03ULL,0x94d049bb133111ebULL,0x2545f4914f6cdd1dULL,0xdeadbeefcafebabeULL,0x8000000000000001ULL,0x0000000100000080ULL,0x7fffffff00000000ULL};
static uint64_t mask(int w){return w==64?UINT64_MAX:((1ULL<<w)-1);}
static int wi(int w){return w==8?0:w==16?1:w==32?2:3;}
static int bit(uint64_t v,int n){return (v>>n)&1;}
static int parity(uint64_t v){return !__builtin_parity((unsigned)(v&255));}
static unsigned szp(uint64_t x,int w){return (bit(x,w-1)?128:0)|(!x?64:0)|(parity(x)?4:0);}
static unsigned addflags(uint64_t a,uint64_t b,int w,int sub){U m=mask(w);uint64_t r=(sub?a-b:a+b)&m; unsigned cf=sub?(a<b):((U)a+b>m); unsigned of=sub?(((a^b)&(a^r))>>(w-1)&1):((~(a^b)&(a^r))>>(w-1)&1);return szp(r,w)|cf|(((a^b^r)&16)?16:0)|(of<<11);}
static I sx(uint64_t a,int w){return (a&(1ULL<<(w-1)))?(I)a-((I)1<<w):(I)a;}
static void handler(int sig,siginfo_t *info,void *v){(void)sig;(void)info;ucontext_t *u=v;Ctx*c=active;c->r1=u->uc_mcontext.gregs[REG_RAX];c->r2=u->uc_mcontext.gregs[REG_RDX];c->r3=u->uc_mcontext.gregs[REG_RBX];c->r4=u->uc_mcontext.gregs[REG_RCX];c->fa=u->uc_mcontext.gregs[REG_EFL]&65535;c->trap=1;siglongjmp(escape,1);}
static void num(U x,int w){if(w==128)printf("%016llx%016llx",(unsigned long long)(x>>64),(unsigned long long)x);else printf("%0*llx",w/4,(unsigned long long)x&mask(w));}
static void check(int result,int flag,uint64_t fm,uint64_t fe,const Ctx*c,const Form*f){if(result>=0){checks_r++;if(!result){bad_r++;if(bad_r<10)fprintf(stderr,"result mismatch %s/%d/%s/%d row=%llu\n",f->op,f->w,f->mode,f->count,(unsigned long long)rows);}}if(flag){checks_f++;if(((c->fa^fe)&fm)!=0){bad_f++;if(bad_f<10)fprintf(stderr,"flag mismatch %s/%d/%s/%d row=%llu before=%04llx actual=%04llx expected=%04llx mask=%04llx\n",f->op,f->w,f->mode,f->count,(unsigned long long)rows,(unsigned long long)c->fb,(unsigned long long)c->fa,(unsigned long long)fe,(unsigned long long)fm);}}}
/* Pure integer C reference for architecturally specified outputs. Undefined bits are never constrained here. */
static void validate(const Form*f,U A,U B,U Cc,U R1,U R2,Ctx*c){int w=f->w;uint64_t a=A,b=B,z=R1,m=w<=64?mask(w):0;unsigned fm=0,fe=0;int ok=-1;const char*o=f->op;unsigned cnt=(unsigned)f->count&(w==64?63:31);uint64_t q=a,cf=c->fb&1;
 if(!strcmp(f->cls,"shifts")){if(!cnt){q=a;fm=0x8d5;fe=c->fb;}else {if(!strcmp(o,"SAR"))q=(uint64_t)(sx(a,w)>>cnt)&m;else if(!strcmp(o,"SHR"))q=cnt>=w?0:a>>cnt;else q=cnt>=w?0:(a<<cnt)&m;fm=0xc4;fe=szp(q,w);if(cnt<w||!strcmp(o,"SAR")){fm|=1;cf=!strcmp(o,"SAR")?(cnt>=w?bit(a,w-1):bit(a,cnt-1)):!strcmp(o,"SHR")?bit(a,cnt-1):bit(a,w-cnt);fe|=cf;}if(cnt==1){fm|=0x800;fe|=(!strcmp(o,"SAR")?0:!strcmp(o,"SHR")?bit(a,w-1):(bit(q,w-1)^cf))<<11;}}ok=(z==q);}
 else if(!strcmp(f->cls,"rotates")){int carry=cf;unsigned n=cnt;int through=!strcmp(o,"RCL")||!strcmp(o,"RCR");int left=!strcmp(o,"ROL")||!strcmp(o,"RCL");if(through&&w<32)n%=w+1;else if(!through)n%=w;for(unsigned j=0;j<n;j++){if(left){int h=bit(q,w-1);q=((q<<1)|(through?carry:h))&m;carry=h;}else{int l=q&1;q=(q>>1)|((uint64_t)(through?carry:l)<<(w-1));carry=l;}}ok=(z==q);fm=0xd4;fe=c->fb;if(!cnt){fm=0x8d5;fe=c->fb;}else {fm|=1;fe=(fe&~1)|(through?carry:left?(q&1):bit(q,w-1));if(cnt==1){fm|=0x800;fe=(fe&~0x800)|((left?(bit(q,w-1)^(fe&1)):(bit(q,w-1)^bit(q,w-2)))<<11);}}}
 else if(!strcmp(f->cls,"double")){if(!cnt){ok=z==a;fm=0x8d5;fe=c->fb;}else if(cnt<=w){if(!strcmp(o,"SHLD")){q=cnt==w?b:((a<<cnt)|(b>>(w-cnt)))&m;cf=bit(a,w-cnt);}else{q=cnt==w?b:(a>>cnt)|(b<<(w-cnt)&m);cf=bit(a,cnt-1);}ok=z==q;fm=0xc5;fe=szp(q,w)|cf;if(cnt==1){fm|=0x800;fe|=(bit(a,w-1)^bit(q,w-1))<<11;}}}
 else if(!strcmp(f->cls,"multiply")){U p;int overflow;if(!strcmp(o,"MUL")){p=(U)a*b;overflow=(p>>w)!=0;}else{I x=sx(!strcmp(o,"IMUL3")?b:a,w),y=!strcmp(o,"IMUL3")?f->count:sx(b,w);I v=x*y;p=(U)v;overflow=v<sx(1ULL<<(w-1),w)||v>((I)1<<(w-1))-1;}q=p&m;ok=z==q;if(!strcmp(o,"MUL")||!strcmp(o,"IMUL1"))ok=ok&&R2==((p>>w)&m);fm=0x801;fe=overflow?0x801:0;}
 else if(!strcmp(f->cls,"divide")){U dividend=((U)Cc<<w)|a;int shouldtrap=b==0;U quot=0,rem=0;if(!shouldtrap&&!strcmp(o,"DIV")){quot=dividend/b;rem=dividend%b;shouldtrap=quot>m;}else if(!shouldtrap){int neg=(Cc>>(w-1))&1,dneg=bit(b,w-1);U fullmask=w==64?~(U)0:(((U)1<<(2*w))-1);U mag=neg?((~dividend+1)&fullmask):dividend;U dm=dneg?((~(U)b+1)&m):b;U uq=mag/dm,ur=mag%dm;int qneg=neg^dneg;shouldtrap=uq>(qneg?((U)1<<(w-1)):(((U)1<<(w-1))-1));quot=qneg?(-uq&m):uq;rem=neg?(-ur&m):ur;}if(shouldtrap){ok=c->trap&&R1==a&&R2==Cc;fm=0x8d5;fe=c->fb;}else ok=!c->trap&&R1==quot&&R2==rem;}
 else if(!strcmp(f->cls,"bitscan")){if(!strcmp(o,"POPCNT")){q=__builtin_popcountll(b);ok=z==q;fm=0x8d5;fe=b?0:64;}else if(!strcmp(o,"TZCNT")||!strcmp(o,"LZCNT")){q=!b?w:!strcmp(o,"TZCNT")?__builtin_ctzll(b):__builtin_clzll(b)-(64-w);ok=z==q;fm=0x41;fe=(!b?1:0)|(!q?64:0);}else{fm=64;fe=b?0:64;if(b){q=!strcmp(o,"BSF")?__builtin_ctzll(b):63-__builtin_clzll(b);ok=z==q;}}}
 else if(!strcmp(f->cls,"bittest")){uint64_t idx=f->count<0?b:(unsigned)f->count;unsigned pos=idx&(w-1);q=a;cf=bit(a,pos);if(!strcmp(o,"BTS"))q|=1ULL<<pos;else if(!strcmp(o,"BTR"))q&=~(1ULL<<pos);else if(!strcmp(o,"BTC"))q^=1ULL<<pos;ok=z==q;fm=0x41;fe=(c->fb&64)|cf;}
 else if(!strcmp(f->cls,"logic")){q=!strcmp(o,"AND")||!strcmp(o,"TEST")?(a&b):!strcmp(o,"OR")?(a|b):(a^b);ok=z==(!strcmp(o,"TEST")?a:q);fm=0x8c5;fe=szp(q,w);}
 else if(!strcmp(o,"XADD")){q=(a+b)&m;ok=z==q&&R2==a;fm=0x8d5;fe=addflags(a,b,w,0);}
 else if(!strcmp(o,"CMPXCHG")){uint64_t acc=Cc;ok=z==(acc==a?b:a)&&R2==(acc==a?acc:a);fm=0x8d5;fe=addflags(acc,a,w,1);}
 else if(!strcmp(o,"BSWAP16")){fm=0x8d5;fe=c->fb;}
 else if(!strcmp(o,"CMPXCHG8B")||!strcmp(o,"CMPXCHG16B")){int eq=A==B;ok=R1==(eq?A:B)&&R2==(eq?Cc:B);fm=0x8d5;fe=(c->fb&~64)|(eq?64:0);}
 check(ok,fm!=0,fm,fe,c,f);
}
static void run_div(const Form*f,Ctx*c){active=c;if(sigsetjmp(escape,1)==0)f->fn(c);}
static void execute(const Form*f,U A,U B,U Cc,int seed){Ctx c={0};_Alignas(16) unsigned char memory[256];memset(memory,0,sizeof memory);int w=f->w;uint64_t m=w<=64?mask(w):~0ULL;c.a=A;c.b=B;c.c=f->count>=0?f->count:0;c.f=seed?0xad7:0x202;uint64_t*base=(uint64_t*)(memory+128);c.mem=(uintptr_t)base;int membit=!strcmp(f->cls,"bittest")&&!strncmp(f->mode,"mem",3);int indexbyte=0;
 if(!strcmp(f->cls,"divide")){c.d=Cc;if(w==8)c.a=((uint64_t)Cc<<8)|(uint64_t)A;}
 if(!strcmp(f->op,"CMPXCHG")){c.a=Cc;c.b=A;c.c=B;}
 if(!strcmp(f->op,"CMPXCHG8B")){c.a=(uint64_t)A&0xffffffff;c.d=(uint64_t)A>>32;c.b=(uint64_t)Cc&0xffffffff;c.c=(uint64_t)Cc>>32;memcpy(base,&B,8);}
 if(!strcmp(f->op,"CMPXCHG16B")){c.a=A;c.d=A>>64;c.b=Cc;c.c=Cc>>64;memcpy(base,&B,16);}
 if(membit){for(int j=0;j<256;j+=w/8)memcpy(memory+j,&A,w/8);if(f->count<0){I idx=sx(B,w);I word=idx/(I)w;if(idx<0&&idx%w)word--;indexbyte=(int)word*(w/8);}/* Immediate addressing uses imm8 modulo width with no assembler displacement rewrite. */}
 active=&c;if(!strcmp(f->cls,"divide"))run_div(f,&c);else f->fn(&c);
 U r1=c.r1&m,r2=0;int has2=0;
 if(!strcmp(f->cls,"multiply")&&(!strcmp(f->op,"MUL")||!strcmp(f->op,"IMUL1"))){r2=w==8?(c.r1>>8)&255:c.r2&m;has2=1;}
 if(!strcmp(f->cls,"divide")){r2=w==8?(c.r1>>8)&255:c.r2&m;has2=1;}
 if(membit){uint64_t v=0,basev=0;memcpy(&v,memory+128+indexbyte,w/8);memcpy(&basev,base,w/8);r1=v;r2=basev;has2=1;}
 if(!strcmp(f->op,"CMPXCHG")){r1=c.r3&m;r2=c.r1&m;has2=1;}
 if(!strcmp(f->op,"XADD")){r2=c.r3&m;has2=1;}
 if(!strcmp(f->op,"CMPXCHG8B")){r1=((U)(c.r2&0xffffffff)<<32)|(c.r1&0xffffffff);memcpy(&r2,base,8);has2=1;}
 if(!strcmp(f->op,"CMPXCHG16B")){r1=((U)c.r2<<64)|c.r1;memcpy(&r2,base,16);has2=1;}
 printf("%s.%s %d %04llx ",f->op,f->mode,w,(unsigned long long)c.fb);num(A,w);putchar(' ');num(B,w);putchar(' ');
 int hasc=f->count>=0||!strcmp(f->op,"IMUL3")||!strcmp(f->cls,"divide")||!strcmp(f->op,"CMPXCHG")||!strcmp(f->op,"CMPXCHG8B")||!strcmp(f->op,"CMPXCHG16B");if(hasc)num(Cc,w);else putchar('-');printf(" -> %s",c.trap?"TRAP ":"");num(r1,w);putchar(' ');if(has2)num(r2,w);else putchar('-');printf(" %04llx\n",(unsigned long long)c.fa);
 capturechecks++;if(c.fb!=c.f||((c.fa^c.fb)&(0xffff&~0x8d5))){capturebad++;if(capturebad<10)fprintf(stderr,"capture/non-arithmetic flags mismatch %s\n",f->op);}
 rows++;traps+=c.trap;validate(f,A,B,Cc,r1,r2,&c);
}
static int features(const Form*f){unsigned a,b,c,d;if(!strcmp(f->op,"TZCNT")){__cpuid_count(7,0,a,b,c,d);return (b>>3)&1;}if(!strcmp(f->op,"LZCNT")){__cpuid(0x80000001,a,b,c,d);return (c>>5)&1;}if(!strcmp(f->op,"POPCNT")){__cpuid(1,a,b,c,d);return (c>>23)&1;}if(!strcmp(f->op,"CMPXCHG16B")){__cpuid(1,a,b,c,d);return (c>>13)&1;}return 1;}
int main(int argc,char**argv){if(argc!=2)return 2;struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);sigaction(SIGFPE,&sa,0);setvbuf(stdout,0,_IOFBF,1<<20);for(int k=0;k<4;k++){int w=8<<k;uint64_t m=mask(w);uint64_t*p=pat[k];p[0]=0;p[1]=1;p[2]=2;p[3]=3;p[4]=(1ULL<<(w-1))-1;p[5]=1ULL<<(w-1);p[6]=m;p[7]=0x5555555555555555ULL&m;p[8]=0xaaaaaaaaaaaaaaaaULL&m;p[9]=1;p[10]=1ULL<<(w-1);p[11]=1ULL<<(w/2);for(int j=0;j<10;j++)p[j+12]=fixed[j]&m;}
 for(int i=0;i<22;i++){if(i==0)pat128[i]=0;else if(i==1||i==9)pat128[i]=1;else if(i==2||i==3)pat128[i]=i;else if(i==4)pat128[i]=((U)1<<127)-1;else if(i==5||i==10)pat128[i]=(U)1<<127;else if(i==6)pat128[i]=~(U)0;else if(i==7||i==8)pat128[i]=((U)pat[3][i]<<64)|pat[3][i];else if(i==11)pat128[i]=(U)1<<64;else pat128[i]=((U)fixed[(i-12+3)%10]<<64)|fixed[i-12];}
 printf("# Native x86-64 integer oracle; original MIT code; class=%s\n",argv[1]);puts("# OP.form width FLAGS_before A B C -> [TRAP] R1 R2 FLAGS_after; flags are actual low16 RFLAGS");
 for(unsigned n=0;n<sizeof(forms)/sizeof(forms[0]);n++){const Form*f=&forms[n];if(strcmp(argv[1],f->cls))continue;if(!features(f)){printf("# SKIP %s %d missing CPUID feature\n",f->op,f->w);continue;}formcount++;uint64_t*p=pat[wi(f->w)];
  if(!strcmp(f->cls,"shifts")||!strcmp(f->cls,"rotates")||!strcmp(f->op,"BSWAP16")){expected+=22*2;for(int i=0;i<22;i++)for(int s=0;s<2;s++)execute(f,p[i],0,(uint64_t)f->count,s);}
  else if(!strcmp(f->cls,"bittest")){if(f->count>=0){expected+=22*2;for(int i=0;i<22;i++)for(int s=0;s<2;s++)execute(f,p[i],0,f->count,s);}else{int w=f->w;int offsets[]={-2*w-1,-2*w,-w-1,-w,-1,0,1,w/2,w-1,w,w+1,2*w-1,2*w,2*w+1,255};expected+=22*15*2;for(int i=0;i<22;i++)for(int j=0;j<15;j++)for(int s=0;s<2;s++)execute(f,p[i],(uint64_t)offsets[j]&mask(w),0,s);if(!strcmp(f->mode,"reg-reg")){expected+=22*22*2;for(int i=0;i<22;i++)for(int j=0;j<22;j++)for(int s=0;s<2;s++)execute(f,p[i],p[j],0,s);}}}
  else if(!strcmp(f->cls,"divide")){expected+=22*22*22*2;for(int i=0;i<22;i++)for(int j=0;j<22;j++)for(int h=0;h<22;h++)for(int s=0;s<2;s++)execute(f,p[i],p[j],p[h],s);
   /* Quotient boundaries: construct exact double-width dividends around q extrema and +/-1 remainder. */
   for(int j=0;j<22;j++){uint64_t b=p[j];if(!b)continue;for(int e=0;e<4;e++)for(int off=-1;off<=1;off++){I q=e==0?((I)1<<(f->w-1))-1:e==1?-((I)1<<(f->w-1)):e==2?(I)mask(f->w):(I)mask(f->w)+1;U v=!strcmp(f->op,"DIV")?(U)q*b+off:(U)(q*sx(b,f->w))+off;uint64_t a=v&mask(f->w),h=(v>>f->w)&mask(f->w);expected+=2;for(int s=0;s<2;s++)execute(f,a,b,h,s);}}
  }
  else if(!strcmp(f->op,"CMPXCHG")||!strcmp(f->op,"CMPXCHG8B")||!strcmp(f->op,"CMPXCHG16B")){expected+=22*22*22*2;for(int i=0;i<22;i++)for(int j=0;j<22;j++)for(int h=0;h<22;h++)for(int s=0;s<2;s++){U a=p[i],b=p[j],c=p[h];if(f->w==128){a=pat128[i];b=pat128[j];c=pat128[h];}execute(f,a,b,c,s);}}
  else{expected+=22*22*2;for(int i=0;i<22;i++)for(int j=0;j<22;j++)for(int s=0;s<2;s++)execute(f,p[i],p[j],(uint64_t)f->count,s);}
 }
 fprintf(stderr,"class=%s forms=%llu expected_rows=%llu measured_rows=%llu traps=%llu\nC_defined_result_checks=%llu mismatches=%llu\nC_defined_flag_checks=%llu mismatches=%llu\n",argv[1],(unsigned long long)formcount,(unsigned long long)expected,(unsigned long long)rows,(unsigned long long)traps,(unsigned long long)checks_r,(unsigned long long)bad_r,(unsigned long long)checks_f,(unsigned long long)bad_f);
 fprintf(stderr,"capture_and_nonarithmetic_flag_checks=%llu mismatches=%llu\n",(unsigned long long)capturechecks,(unsigned long long)capturebad);
 return bad_r||bad_f||capturebad||rows!=expected?1:0;
}
