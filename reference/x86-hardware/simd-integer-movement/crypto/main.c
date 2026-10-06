/* SPDX-License-Identifier: MIT. Original scalar AES/GF, polynomial CRC32C,
 * carry-less multiply, byte-swap models; no external source code. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cpuid.h>
#include <signal.h>
#include <setjmp.h>
#include <stddef.h>
#include <ucontext.h>
typedef struct {uint8_t d[32],a[32],z[32],o[32],zo[32];uint64_t g,s,go;uint8_t *mp;uint8_t mem[96];uint8_t ao[32];}Ctx;
_Static_assert(offsetof(Ctx,g)==160&&offsetof(Ctx,mp)==184,"assembly offsets");
typedef struct {const char*name;int kind,enc,imm,mem,bits,feature;void(*fn)(Ctx*);}Form;
#include "forms.h"
static int execute(const Form*f,Ctx*c);
static sigjmp_buf env;static volatile sig_atomic_t trapped,trap_number,trap_error,snapshot_valid;
static Ctx *active;
static void handler(int sig,siginfo_t *si,void *v){
 (void)si;ucontext_t *u=v;trapped=sig;trap_number=(sig_atomic_t)u->uc_mcontext.gregs[REG_TRAPNO];trap_error=(sig_atomic_t)u->uc_mcontext.gregs[REG_ERR];
 const uint8_t*x=(const uint8_t*)u->uc_mcontext.fpregs;
 if(active&&x){uint32_t magic,size;uint64_t bv,comp;memcpy(&magic,x+464,4);memcpy(&size,x+468,4);memcpy(&bv,x+512,8);memcpy(&comp,x+520,8);
  /* Poisoned upper halves require an actual, standard-format YMM component.
   * A missing/unknown signal image is fatal, never replaced by guessed bytes. */
  if(magic==0x46505853&&size>=832&&(bv&4)&&!(comp>>63)){
   for(int j=0;j<16;j++){active->o[j]=x[176+j];active->o[j+16]=x[592+j];active->zo[j]=x[160+j];active->zo[j+16]=x[576+j];active->ao[j]=x[192+j];active->ao[j+16]=x[608+j];}
   active->go=(uint64_t)u->uc_mcontext.gregs[REG_RAX];snapshot_valid=1;
  }
 }
 siglongjmp(env,1);
}
static int execute(const Form*f,Ctx*c){trapped=trap_number=trap_error=snapshot_valid=0;active=c;if(sigsetjmp(env,1)==0)f->fn(c);active=NULL;return trapped;}
static void hex(const uint8_t*p,int n){for(int i=n-1;i>=0;i--)printf("%02x",p[i]);}
static void pat(uint8_t*p,int k){for(int i=0;i<32;i++)switch(k%8){case 0:p[i]=0;break;case 1:p[i]=255;break;case 2:p[i]=1;break;case 3:p[i]=128;break;case 4:p[i]=127;break;case 5:p[i]=i%2?0xaa:0x55;break;case 6:p[i]=i;break;default:p[i]=(uint8_t)(0xa7+37*i);break;}}
static void init(Ctx*c,const Form*f,int id){memset(c,0,sizeof *c);pat(c->d,id);pat(c->a,(id+3)%8);pat(c->z,(id+5)%8);for(int i=16;i<32;i++)c->d[i]=(uint8_t)(0xd1+3*i+id);for(int i=0;i<96;i++)c->mem[i]=(uint8_t)(0x39+5*i);uintptr_t addr=((uintptr_t)c->mem+31)&~(uintptr_t)31;c->mp=(uint8_t*)addr+(f->mem==2?1:0);memcpy(c->mp,c->a,32);memcpy(&c->g,c->d,8);memcpy(&c->s,c->a,8);if(f->kind>=14)memcpy(c->mp,&c->s,8);}
static uint8_t mul(uint8_t a,uint8_t b){uint8_t r=0;for(int i=0;i<8;i++){if(b&1)r^=a;uint8_t hi=a>>7;a=(uint8_t)(a<<1);if(hi)a^=0x1b;b>>=1;}return r;}
static uint8_t rot8(uint8_t v,int n){return (uint8_t)((v<<n)|(v>>(8-n)));}
static uint8_t sb[256],ib[256];
static void sboxes(void){for(int x=0;x<256;x++){uint8_t y=1,b=x;int e=254;if(!x)y=0;else while(e){if(e&1)y=mul(y,b);b=mul(b,b);e>>=1;}sb[x]=(uint8_t)(y^rot8(y,1)^rot8(y,2)^rot8(y,3)^rot8(y,4)^0x63);ib[sb[x]]=x;}}
static void mix(uint8_t*p,int inv){uint8_t r[16];for(int c=0;c<4;c++){uint8_t*a=p+4*c;for(int j=0;j<4;j++)r[4*c+j]=inv?(mul(a[j],14)^mul(a[(j+1)%4],11)^mul(a[(j+2)%4],13)^mul(a[(j+3)%4],9)):(mul(a[j],2)^mul(a[(j+1)%4],3)^a[(j+2)%4]^a[(j+3)%4]);}memcpy(p,r,16);}
static void aes(uint8_t*out,const uint8_t*d,const uint8_t*a,int kind,int imm){uint8_t t[16];if(kind==4){memcpy(out,a,16);mix(out,1);return;}if(kind==5){for(int k=0;k<2;k++){for(int j=0;j<4;j++){out[k*8+j]=sb[a[4+8*k+j]];out[k*8+4+j]=sb[a[4+8*k+(j+1)%4]];}out[k*8+4]^=imm;}return;}int inv=kind>=2;for(int r=0;r<4;r++)for(int c=0;c<4;c++)t[4*c+r]=inv?ib[d[4*((c-r+4)%4)+r]]:sb[d[4*((c+r)%4)+r]];if(kind==0||kind==2)mix(t,inv);for(int i=0;i<16;i++)out[i]=t[i]^a[i];}
static void clmul(uint8_t*out,const uint8_t*d,const uint8_t*a,int imm){uint64_t x,y;memcpy(&x,d+((imm&1)?8:0),8);memcpy(&y,a+((imm&16)?8:0),8);uint64_t lo=0,hi=0;for(int i=0;i<64;i++)if(y&(1ull<<i)){lo^=x<<i;if(i)hi^=x>>(64-i);}memcpy(out,&lo,8);memcpy(out+8,&hi,8);}
static uint64_t crc(uint64_t x,uint64_t y,int bits){uint32_t r=x;for(int i=0;i<bits/8;i++){r^=(y>>(8*i))&255;for(int j=0;j<8;j++)r=(r>>1)^((r&1)?0x82f63b78:0);}return r;}
static uint64_t bswap(uint64_t x,int n){uint64_t y=0;for(int i=0;i<n;i++){y=(y<<8)|(x&255);x>>=8;}return y;}
/* SHA models use only uint32_t additions, rotations, XOR/AND and schedule recurrence.
 * SIMD SHA-1 words run high-to-low; SHA-256 message schedules run low-to-high. */
static uint32_t rol32(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
static uint32_t ror32(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static uint32_t sha_s0(uint32_t x){return ror32(x,7)^ror32(x,18)^(x>>3);}
static uint32_t sha_s1(uint32_t x){return ror32(x,17)^ror32(x,19)^(x>>10);}
static uint32_t sha_S0(uint32_t x){return ror32(x,2)^ror32(x,13)^ror32(x,22);}
static uint32_t sha_S1(uint32_t x){return ror32(x,6)^ror32(x,11)^ror32(x,25);}
static void sha(uint8_t*out,const Ctx*c,int kind,int imm){uint32_t d[4],s[4],z[4],r[4];memcpy(d,c->d,16);memcpy(s,c->a,16);memcpy(z,c->z,16);
 if(kind==7){
  static const uint32_t k[4]={0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6};
  uint32_t a=d[3],b=d[2],cc=d[1],dd=d[0],e=0;
  for(int j=0;j<4;j++){uint32_t f=(imm&3)==0?((b&cc)^(~b&dd)):(imm&3)==2?((b&cc)^(b&dd)^(cc&dd)):(b^cc^dd);uint32_t t=rol32(a,5)+f+e+s[3-j]+k[imm&3];e=dd;dd=cc;cc=rol32(b,30);b=a;a=t;}
  r[3]=a;r[2]=b;r[1]=cc;r[0]=dd;
 }else if(kind==8){memcpy(r,s,16);r[3]+=rol32(d[3],30);
 }else if(kind==9){r[3]=d[3]^d[1];r[2]=d[2]^d[0];r[1]=d[1]^s[3];r[0]=d[0]^s[2];
 }else if(kind==10){r[3]=rol32(d[3]^s[2],1);r[2]=rol32(d[2]^s[1],1);r[1]=rol32(d[1]^s[0],1);r[0]=rol32(d[0]^r[3],1);
 }else if(kind==11){uint32_t a=s[3],b=s[2],cc=d[3],dd=d[2],e=s[1],f=s[0],g=d[1],h=d[0];
  for(int j=0;j<2;j++){uint32_t t1=h+sha_S1(e)+((e&f)^(~e&g))+z[j];uint32_t t2=sha_S0(a)+((a&b)^(a&cc)^(b&cc));h=g;g=f;f=e;e=dd+t1;dd=cc;cc=b;b=a;a=t1+t2;}
  r[3]=a;r[2]=b;r[1]=e;r[0]=f;
 }else if(kind==12){r[0]=d[0]+sha_s0(d[1]);r[1]=d[1]+sha_s0(d[2]);r[2]=d[2]+sha_s0(d[3]);r[3]=d[3]+sha_s0(s[0]);
 }else{r[0]=d[0]+sha_s1(s[2]);r[1]=d[1]+sha_s1(s[3]);r[2]=d[2]+sha_s1(r[0]);r[3]=d[3]+sha_s1(r[1]);}
 memcpy(out,r,16);
}
static int model(const Form*f,const Ctx*c,const uint8_t*mem_before){if(f->kind>=7&&f->kind<=13){uint8_t out[32];memcpy(out,c->d,32);sha(out,c,f->kind,f->imm);return !memcmp(out,c->o,32)&&!memcmp(c->z,c->zo,32)&&!memcmp(c->mem,mem_before,96);}
 if(f->kind<7){uint8_t out[32];memcpy(out,c->d,32);int n=f->bits/8;for(int i=0;i<n;i+=16){if(f->kind==6)clmul(out+i,c->d+i,c->a+i,f->imm);else aes(out+i,c->d+i,c->a+i,f->kind,f->imm);}if(f->enc==1)memset(out+16,0,16);return !memcmp(out,c->o,32)&&!memcmp(c->z,c->zo,32)&&!memcmp(c->mem,mem_before,96);}
 uint64_t g=c->g;if(f->kind==14)g=crc(g,c->s,f->bits);else if(f->kind==15){uint64_t val=bswap(c->s,f->bits/8);g=f->bits==16?(g&~65535ull)|val:val;}
 if(g!=c->go)return 0;
 uint8_t expected[96];memcpy(expected,mem_before,96);if(f->kind==16){uint64_t val=bswap(c->g,f->bits/8);memcpy(expected+(c->mp-c->mem),&val,f->bits/8);}return !memcmp(expected,c->mem,96);
}
int main(void){unsigned a,b,c,d;__cpuid(1,a,b,c,d);unsigned ecx=c;__cpuid_count(7,0,a,b,c,d);int features[4]={1,!!(c&(1u<<9)),!!(b&(1u<<29)),!!(c&(1u<<10))};if(!(ecx&(1u<<20))||!(ecx&(1u<<25))||!(ecx&(1u<<1))||!(ecx&(1u<<28))||!(ecx&(1u<<22))){fprintf(stderr,"required CRC32/AES/PCLMUL/AVX/MOVBE absent\n");return 2;}
 struct sigaction sa={0};sa.sa_sigaction=handler;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);sigaction(SIGSEGV,&sa,0);sigaction(SIGBUS,&sa,0);sigaction(SIGILL,&sa,0);sboxes();
 uint64_t rows=0,expected=0,checks=0,bad=0,upper=0,upperbad=0,faults=0,skip=0,counts[17]={0},checked[17]={0},fault_by_kind[17]={0},imm_pairs=0,imm_bad=0,fault_checks=0,fault_bad=0;size_t nf=sizeof(forms)/sizeof(*forms);
 expected=25032ULL+(features[1]?96:0)+(features[2]?6288:0)+(features[3]?6144:0);
 for(size_t k=0;k<nf;k++)if(!features[forms[k].feature])skip++;
 printf("# Native AES/PCLMUL/SHA/CRC32/MOVBE. All imm8 values. 8 fixed cyclic pattern pairs; memory=reg/aligned/+1 unaligned.\n");
 printf("# X1=actual destination before, primary result=actual destination after, width=destination bits. Vector snapshots full256; scalar slots use exact width, full64 registers in metadata. MOVBE stores use memory destination.\n");
 printf("# Fault rows include actual signal-context YMM1/YMM0/YMM2 snapshots, trap and error; missing XSAVE images fail the run.\n");
 printf("# CPUID VAES=%d SHA=%d VPCLMULQDQ=%d\n",features[1],features[2],features[3]);
 for(size_t k=0;k<nf;k++){Form*f=&forms[k];if(!features[f->feature])continue;for(int id=0;id<8;id++){Ctx x;init(&x,f,id);uint8_t oldmem[96];memcpy(oldmem,x.mem,96);int sig=execute(f,&x);
 int want_fault=f->kind<=6&&f->enc==0&&f->mem==2;
 if(sig&&!snapshot_valid){fprintf(stderr,"Missing actual signal snapshot for %s\n",f->name);return 4;}
 if((!!sig)!=want_fault){fprintf(stderr,"Unexpected fault outcome %s enc=%d imm=%d mem=%d case=%d sig=%d\n",f->name,f->enc,f->imm,f->mem,id,sig);return 5;}
 rows++;counts[f->kind]++;
 int dst_bits=f->kind==14?f->enc:f->bits;
 if(f->imm>=0)printf("%s[%02x]",f->name,f->imm);else printf("%s",f->name);printf(" %d ",dst_bits);
 if(f->kind<14){hex(x.d,32);putchar(' ');int ternary=f->enc&&f->kind!=4&&f->kind!=5;if(ternary){hex(x.d,32);putchar(' ');}if(f->mem)hex(oldmem+(x.mp-x.mem),f->bits/8);else hex(x.a,32);if(!ternary){putchar(' ');if(f->kind==11)hex(x.z,32);else putchar('-');}}
 else{if(f->kind==16)hex(oldmem+(x.mp-x.mem),f->bits/8);else hex((const uint8_t*)&x.g,dst_bits/8);putchar(' ');
  if(f->kind==16)hex((const uint8_t*)&x.g,f->bits/8);else if(f->mem)hex(oldmem+(x.mp-x.mem),f->bits/8);else hex((const uint8_t*)&x.s,f->bits/8);printf(" -");}
 printf(" -> ");
 if(f->kind<14){hex(x.o,32);printf(" YMM0_BEFORE=");hex(x.z,32);printf(" YMM0_AFTER=");hex(x.zo,32);printf(" SOURCE_YMM2_BEFORE=");hex(x.a,32);printf(" SOURCE_YMM2_AFTER=");hex(x.ao,32);}else if(f->kind==16)hex(x.mp,f->bits/8);else hex((const uint8_t*)&x.go,dst_bits/8);
 if(sig){printf(" FAULT=%s",sig==SIGSEGV?"SIGSEGV":sig==SIGILL?"SIGILL":"SIGBUS");
  if(f->kind<14){printf(" SOURCE_AFTER=");hex(x.ao,32);}
  printf(" TRAP=%d ERROR=%d",(int)trap_number,(int)trap_error);faults++;fault_by_kind[f->kind]++;
  int good=sig==SIGSEGV&&trap_number==13&&trap_error==0&&!memcmp(x.d,x.o,32)&&!memcmp(x.z,x.zo,32)&&!memcmp(x.a,x.ao,32)&&!memcmp(x.mem,oldmem,96);fault_checks++;if(!good)fault_bad++;}
 if(f->kind>=14){printf(" SRC_BITS=%d GPR64_BEFORE=%016llx GPR64_AFTER=%016llx",f->bits,(unsigned long long)x.g,(unsigned long long)x.go);if(f->mem){printf(" MEM_AFTER=");hex(x.mp,f->bits/8);}}
 printf(" MEM=%d CASE=%d\n",f->mem,id);
 if(sig)continue;
 if(f->kind<14&&memcmp(x.a,x.ao,32)){fprintf(stderr,"Source register changed unexpectedly\n");return 6;}
 int m=model(f,&x,oldmem);if(m>=0){checks++;checked[f->kind]++;if(!m){if(bad<8)fprintf(stderr,"model mismatch %s enc=%d imm=%d mem=%d case=%d\n",f->name,f->enc,f->imm,f->mem,id);bad++;}}
 if(f->kind<14){uint8_t up[16]={0};if(f->enc==0)memcpy(up,x.d+16,16);int good=f->enc==2||!memcmp(x.o+16,up,16);good&=!memcmp(x.zo,x.z,32);if(good)upper++;else upperbad++;}
 if((f->kind==6 && (f->imm&~17))||(f->kind==7&&f->imm>=4)){unsigned baseimm=f->kind==6?f->imm&17:f->imm&3;size_t basex=k-(f->imm-baseimm)*3;Ctx y;init(&y,f,id);int ys=execute(&forms[basex],&y);if(!ys&&!memcmp(x.o,y.o,32))imm_pairs++;else imm_bad++;}
 }}
 fprintf(stderr,"rows=%llu expected=%llu declared_forms=%zu skipped_forms=%llu scalar_checked=%llu scalar_mismatches=%llu faults=%llu\n",(unsigned long long)rows,(unsigned long long)expected,nf,(unsigned long long)skip,(unsigned long long)checks,(unsigned long long)bad,(unsigned long long)faults);
 for(int i=0;i<17;i++)fprintf(stderr,"kind=%d rows=%llu scalar_checked=%llu faults=%llu\n",i,(unsigned long long)counts[i],(unsigned long long)checked[i],(unsigned long long)fault_by_kind[i]);
 fprintf(stderr,"upper_semantics_support=%llu counterexamples=%llu ignored_imm_bits_support=%llu counterexamples=%llu\n",(unsigned long long)upper,(unsigned long long)upperbad,(unsigned long long)imm_pairs,(unsigned long long)imm_bad);
 fprintf(stderr,"fault_snapshot_checked=%llu counterexamples=%llu\n",(unsigned long long)fault_checks,(unsigned long long)fault_bad);
 return nf!=4695||rows!=expected||bad||upperbad||imm_bad||fault_bad;
}
