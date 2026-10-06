/* Original native x86-64 measurement harness and independent scalar C model. MIT. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <inttypes.h>
#include <cpuid.h>
struct input { uint8_t x[4][32]; };
struct output { uint8_t x[32]; uint64_t flags,flags_before; };
struct form {
 const char *cls,*op,*enc,*loc,*mode;
 int width,arity,imm,lane,cases,memslot,memsize;
 void (*fn)(const struct input*,struct output*,const void*);
 char *fault,*resume;
};
#include "core-build/forms.h"
static uintptr_t fault_ip,resume_ip;
static volatile sig_atomic_t fault_sig,fault_code;
static void trapped(int sig,siginfo_t*si,void*p){
 ucontext_t*u=p;
 if((uintptr_t)u->uc_mcontext.gregs[REG_RIP]!=fault_ip)_exit(124);
 fault_sig=sig;fault_code=si->si_code;
 /* Only RIP advances. Linux sigreturn restores all actual fault-time registers,
    including YMM high halves and RFLAGS, before the kernel snapshots them. */
 u->uc_mcontext.gregs[REG_RIP]=(greg_t)resume_ip;
}
static uint64_t maskbits(int b){return b==8?UINT64_MAX:(UINT64_C(1)<<(8*b))-1;}
static uint64_t get(const uint8_t*p,int b){uint64_t v=0;memcpy(&v,p,b);return v;}
static void put(uint8_t*p,int b,uint64_t v){memcpy(p,&v,b);}
static int64_t signedval(uint64_t v,int b){if(b==8)return (int64_t)v;uint64_t s=UINT64_C(1)<<(8*b-1);return v&s?(int64_t)v-(int64_t)(s*2):(int64_t)v;}
static uint64_t sat(int64_t v,int bits,int uns){int64_t lo=uns?0:-(INT64_C(1)<<(bits-1));int64_t hi=uns?(INT64_C(1)<<bits)-1:(INT64_C(1)<<(bits-1))-1;return (uint64_t)(v<lo?lo:v>hi?hi:v);}
static void make_input(const struct form*f,int c,struct input*in){
 int l=f->lane,n=f->width/8;uint64_t mask=maskbits(l>8?1:l);int b=l>8?1:l;uint64_t sign=UINT64_C(1)<<(8*b-1);
 uint64_t vals[]={0,1,mask,sign,sign-1,sign+1,mask-1,UINT64_C(0x5555555555555555)&mask,UINT64_C(0xaaaaaaaaaaaaaaaa)&mask,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,0x7fffffff,0x80000000,0xffffffff,2,mask-2,3,4,0x33333333,0xcccccccc};
 for(int s=0;s<4;s++)for(int j=0;j<32/b;j++)put(in->x[s]+j*b,b,vals[(c*(2*s+1)+j*(s+1)+s*7)%24]&mask);
 if(!strcmp(f->cls,"permutation")){
  for(int s=0;s<4;s++)for(int j=0;j<32;j++)in->x[s][j]=c%4==0?(uint8_t)(j+s*64):c%4==1?(uint8_t)(255-j-s*16):c%4==2?(uint8_t[]){0,15,16,31,0x7f,0x80,0x8f,0xff}[(j+s)%8]:(uint8_t)(j*73+s*41+17);
  if(!strcmp(f->mode,"permvar")||!strcmp(f->mode,"permfull")){
   int slot=!strcmp(f->mode,"permfull")?1:2;
   for(int j=0;j<n/b;j++){uint64_t idx[]={0,1,3,7,8,15,UINT64_MAX,UINT64_C(0x8000000000000000)};put(in->x[slot]+j*b,b,idx[(c+j)%8]);}
  }
 }
 if(!strcmp(f->mode,"shiftcount")){
  uint64_t counts[]={UINT64_MAX,UINT64_C(0x100000000),UINT64_C(0x8000000000000000),UINT64_C(0x100),UINT64_C(0xffff)};
  uint64_t count=c<=b*8+1?(uint64_t)c:counts[c-(b*8+2)];
  memset(in->x[2],0,16);put(in->x[2],8,count);put(in->x[2]+8,8,UINT64_C(0xfedcba9876543210));
 }
 if(!strcmp(f->mode,"shiftvar"))for(int j=0;j<n/b;j++){uint64_t counts[]={0,1,(uint64_t)b*8-1,(uint64_t)b*8,(uint64_t)b*8+1,UINT64_MAX,256,UINT64_C(0x8000000000000000)};put(in->x[2]+j*b,b,counts[(c+j)%8]);}
 /* The destination upper 128 bits are always a distinct nonzero preserved/zeroed canary. */
 for(int j=16;j<32;j++)in->x[0][j]=(uint8_t)(0xa0+j+c%16);
}
static void hex(const uint8_t*p,int n){static const char d[]="0123456789abcdef";char s[65];for(int j=0;j<n;j++){s[2*j]=d[p[n-j-1]>>4];s[2*j+1]=d[p[n-j-1]&15];}s[n*2]=0;fputs(s,stdout);}
/* Return 1 if the C model covers the full vector and (for test ops) defined flags. */
static int model(const struct form*f,const struct input*in,uint8_t*out,uint16_t*flags){
 const char*o=f->op;int n=f->width/8,l=f->lane,v=!strcmp(f->enc,"VEX"),im=f->imm;
 const uint8_t *a=v?in->x[1]:in->x[0],*b=v?in->x[2]:in->x[1];
 if(f->arity==1 && strcmp(f->mode,"shiftimm")&&strcmp(f->mode,"shiftbytes"))a=in->x[1];
 memcpy(out,in->x[0],32);if(v&&n==16)memset(out+16,0,16);
 if(!strcmp(f->mode,"flags")){
  a=in->x[0];b=in->x[1];int z=1,c=1;
  if(!strcmp(o,"ptest")){for(int j=0;j<n;j++){if(a[j]&b[j])z=0;if((uint8_t)~a[j]&b[j])c=0;}}
  else for(int j=l-1;j<n;j+=l){if((a[j]&b[j])&128)z=0;if(((uint8_t)~a[j]&b[j])&128)c=0;}
  *flags=(uint16_t)(0x202+(z?0x40:0)+(c?1:0));memcpy(out,in->x[0],32);return 1;
 }
 if(!strcmp(f->cls,"logic")){
  if(strstr(o,"pcmpeq")||strstr(o,"pcmpgt")){for(int j=0;j<n;j+=l){uint64_t x=get(a+j,l),y=get(b+j,l),s=UINT64_C(1)<<(8*l-1);int ok=strstr(o,"pcmpeq")?x==y:(x^s)>(y^s);put(out+j,l,ok?maskbits(l):0);}return 1;}
  for(int j=0;j<n;j++){out[j]=strstr(o,"andn")?(uint8_t)~a[j]&b[j]:strstr(o,"and")?a[j]&b[j]:strstr(o,"xor")?a[j]^b[j]:a[j]|b[j];}return 1;
 }
 if(!strcmp(f->cls,"shifts")){
  if(!strcmp(f->mode,"shiftbytes")){for(int base=0;base<n;base+=16)for(int j=0;j<16;j++){int k=!strcmp(o,"pslldq")?j-im:j+im;out[base+j]=k<0||k>=16?0:a[base+k];}return 1;}
  for(int j=0;j<n;j+=l){uint64_t count=im>=0?(uint64_t)im:!strcmp(f->mode,"shiftcount")?get(in->x[2],8):get(in->x[2]+j,l);uint64_t x=get(a+j,l),r=0;int bits=l*8;
   if(strstr(o,"psra")){int64_t sx=signedval(x,l);r=count>=(unsigned)bits?(sx<0?maskbits(l):0):(uint64_t)(sx>>count);}
   else if(count<(unsigned)bits)r=strstr(o,"psll")?x<<count:x>>count;
   put(out+j,l,r);
  }return 1;
 }
 if(!strcmp(f->cls,"pack")){
  int d=l/2,uns=strstr(o,"packus")!=0;
  for(int base=0;base<n;base+=16){for(int s=0;s<2;s++)for(int j=0;j<16/l;j++)put(out+base+s*8+j*d,d,sat(signedval(get((s?b:a)+base+j*l,l),l),d*8,uns));}return 1;
 }
 if(!strcmp(f->cls,"arithmetic")){
  if(!strcmp(o,"phminposuw")){uint16_t val=0xffff,idx=0;for(int j=0;j<8;j++){uint16_t x=(uint16_t)get(a+j*2,2);if(x<val){val=x;idx=(uint16_t)j;}}memset(out,0,16);put(out,2,val);put(out+2,2,idx);return 1;}
  if(!strcmp(o,"psadbw")){for(int base=0;base<n;base+=8){unsigned s=0;for(int j=0;j<8;j++)s+=abs((int)a[base+j]-(int)b[base+j]);put(out+base,8,s);}return 1;}
  if(!strcmp(o,"mpsadbw")){for(int base=0;base<n;base+=16){int control=(im>>(base?3:0))&7;int ai=(control&4)?4:0,bi=(control&3)*4;for(int j=0;j<8;j++){unsigned s=0;for(int k=0;k<4;k++)s+=abs((int)a[base+ai+j+k]-(int)b[base+bi+k]);put(out+base+j*2,2,s);}}return 1;}
  if(!strncmp(o,"phadd",5)||!strncmp(o,"phsub",5)){int sub=!strncmp(o,"phsub",5),satur=strstr(o,"sw")!=0;for(int base=0;base<n;base+=16)for(int s=0;s<2;s++)for(int j=0;j<8/l;j++){const uint8_t*p=(s?b:a)+base+j*2*l;int64_t x=signedval(get(p,l),l),y=signedval(get(p+l,l),l),r=sub?x-y:x+y;put(out+base+s*8+j*l,l,satur?sat(r,16,0):(uint64_t)r);}return 1;}
  if(!strcmp(o,"pmaddwd")){for(int j=0;j<n;j+=4){int64_t r=signedval(get(a+j,2),2)*signedval(get(b+j,2),2)+signedval(get(a+j+2,2),2)*signedval(get(b+j+2,2),2);put(out+j,4,(uint64_t)r);}return 1;}
  if(!strcmp(o,"pmaddubsw")){for(int j=0;j<n;j+=2){int64_t r=(int64_t)a[j]*signedval(b[j],1)+(int64_t)a[j+1]*signedval(b[j+1],1);put(out+j,2,sat(r,16,0));}return 1;}
  if(!strcmp(o,"pmuludq")||!strcmp(o,"pmuldq")){for(int j=0;j<n;j+=8){uint64_t x=get(a+j,4),y=get(b+j,4);put(out+j,8,!strcmp(o,"pmuldq")?(uint64_t)(signedval(x,4)*signedval(y,4)):x*y);}return 1;}
  for(int j=0;j<n;j+=l){uint64_t x=get(a+j,l),y=get(b+j,l),r=0;int64_t sx=signedval(x,l),sy=signedval(y,l);
   if(!strncmp(o,"padd",4)||!strncmp(o,"psub",4)){
    int sub=o[1]=='s',satur=strlen(o)>5,uns=strstr(o,"us")!=0;
    r=satur?sat(sub?(uns?(int64_t)x-(int64_t)y:sx-sy):(uns?(int64_t)x+(int64_t)y:sx+sy),l*8,uns):(sub?x-y:x+y);
   }else if(!strncmp(o,"pmin",4)||!strncmp(o,"pmax",4)){int uns=o[4]=='u',less=uns?x<y:sx<sy;r=(!strncmp(o,"pmin",4)?less:!less)?x:y;}
   else if(!strncmp(o,"pabs",4))r=sx<0?0-x:x;
   else if(!strncmp(o,"psign",5))r=sy==0?0:sy<0?0-x:x;
   else if(!strncmp(o,"pavg",4))r=(x+y+1)/2;
   else if(!strcmp(o,"pmullw")||!strcmp(o,"pmulld"))r=x*y;
   else if(!strcmp(o,"pmulhw"))r=(uint64_t)((sx*sy)>>16);
   else if(!strcmp(o,"pmulhuw"))r=(x*y)>>16;
   else if(!strcmp(o,"pmulhrsw"))r=(uint64_t)((sx*sy+0x4000)>>15);
   else return 0;
   put(out+j,l,r);
  }return 1;
 }
 if(!strcmp(f->cls,"permutation")){
  if(!strcmp(o,"pshufd")){for(int base=0;base<n;base+=16)for(int j=0;j<4;j++)memcpy(out+base+j*4,a+base+((im>>(2*j))&3)*4,4);return 1;}
  if(!strcmp(o,"pshuflw")||!strcmp(o,"pshufhw")){memcpy(out,a,n);int off=!strcmp(o,"pshufhw")?8:0;for(int base=0;base<n;base+=16)for(int j=0;j<4;j++)memcpy(out+base+off+j*2,a+base+off+((im>>(2*j))&3)*2,2);return 1;}
  if(!strcmp(o,"pshufb")){for(int base=0;base<n;base+=16)for(int j=0;j<16;j++)out[base+j]=b[base+j]&128?0:a[base+(b[base+j]&15)];return 1;}
  if(!strcmp(o,"palignr")){for(int base=0;base<n;base+=16)for(int j=0;j<16;j++){int k=j+im;out[base+j]=k>=32?0:k>=16?a[base+k-16]:b[base+k];}return 1;}
  if(!strcmp(o,"shufps")){for(int base=0;base<n;base+=16)for(int j=0;j<4;j++)memcpy(out+base+j*4,(j<2?a:b)+base+((im>>(2*j))&3)*4,4);return 1;}
  if(!strcmp(o,"shufpd")){for(int base=0;base<n;base+=16){memcpy(out+base,a+base+((im>>(base/8))&1)*8,8);memcpy(out+base+8,b+base+((im>>(base/8+1))&1)*8,8);}return 1;}
  if(strstr(o,"unpck")){int hi=strstr(o,"unpckh")!=0;for(int base=0;base<n;base+=16)for(int j=0;j<8/l;j++){memcpy(out+base+2*j*l,a+base+(hi?8:0)+j*l,l);memcpy(out+base+(2*j+1)*l,b+base+(hi?8:0)+j*l,l);}return 1;}
  if(strstr(o,"blend")){int var=!strcmp(f->mode,"blendvar");for(int j=0;j<n/l;j++){int select=var?(in->x[3][j*l+l-1]>>7):((im>>(!strcmp(o,"pblendw")?j%8:j))&1);memcpy(out+j*l,(select?b:a)+j*l,l);}return 1;}
  if(!strcmp(o,"permilps")||!strcmp(o,"permilpd")){
   for(int base=0;base<n;base+=16){for(int j=0;j<16/l;j++){uint64_t ctrl=im>=0?(unsigned)im:get(b+base+j*l,l);int k;if(l==4)k=im>=0?(im>>(2*j))&3:ctrl&3;else k=im>=0?(im>>(base/8+j))&1:(ctrl>>1)&1;memcpy(out+base+j*l,a+base+k*l,l);}}return 1;
  }
  if(!strcmp(o,"perm2f128")||!strcmp(o,"perm2i128")){for(int half=0;half<2;half++){int ctrl=(im>>(half*4))&15;if(ctrl&8)memset(out+half*16,0,16);else memcpy(out+half*16,((ctrl&2)?b:a)+(ctrl&1)*16,16);}return 1;}
  if(!strcmp(o,"permd")||!strcmp(o,"permps")){for(int j=0;j<8;j++)memcpy(out+j*4,b+(get(a+j*4,4)&7)*4,4);return 1;}
  if(!strcmp(o,"permq")||!strcmp(o,"permpd")){for(int j=0;j<4;j++)memcpy(out+j*8,a+((im>>(2*j))&3)*8,8);return 1;}
 }
 return 0;
}
int main(int argc,char**argv){
 if(argc!=2){fprintf(stderr,"usage: %s CLASS\n",argv[0]);return 2;}
 unsigned ca,cb,cc,cd;if(!__get_cpuid(1,&ca,&cb,&cc,&cd)||!(cc&bit_AVX)||!(cc&bit_OSXSAVE)){fputs("AVX/OSXSAVE unavailable\n",stderr);return 2;}
 uint32_t xl,xh;__asm__ volatile("xgetbv":"=a"(xl),"=d"(xh):"c"(0));if((xl&6)!=6||!__get_cpuid_count(7,0,&ca,&cb,&cc,&cd)||!(cb&bit_AVX2)){fputs("AVX2/YMM OS state unavailable\n",stderr);return 2;}
 struct sigaction sa={0};sa.sa_sigaction=trapped;sa.sa_flags=SA_SIGINFO;sigemptyset(&sa.sa_mask);if(sigaction(SIGSEGV,&sa,0)||sigaction(SIGBUS,&sa,0)||sigaction(SIGILL,&sa,0)){perror("sigaction");return 2;}
 setvbuf(stdout,0,_IOFBF,1<<20);
 uint64_t expected=0,lines=0,checked=0,bad=0,traps=0,upper=0,upperbad=0;unsigned nf=0;
 for(unsigned k=0;k<sizeof(forms)/sizeof(forms[0]);k++)if(!strcmp(forms[k].cls,argv[1])){nf++;expected+=forms[k].cases;}
 if(!nf)return 2;
 printf("# Native x86-64 integer SIMD reference v1 class=%s forms=%u expected_rows=%"PRIu64"\n",argv[1],nf,expected);
 puts("# name[imm] destination_width X1 X2 X3 -> RESULT; all vector values are full YMM high-byte first. Flag tests use captured low16 FLAGS as X1/result and tested vectors as X2/X3.");
 puts("# X1=actual destination-before; X2/X3=actual sources in destination-first syntax, absent sources are -. Variable blends add mask= after the result. Memory bytes match their source slot, addresses omitted.");
 puts("# TRAP output snapshots actual fault-time registers by sigreturn; only RIP skips tested instruction. No data rows are modified or synthesized.");
 for(unsigned k=0;k<sizeof(forms)/sizeof(forms[0]);k++){
  const struct form*f=forms+k;if(strcmp(f->cls,argv[1]))continue;
  printf("# form=%u encoding=%s operand=%s mode=%s cases=%d memslot=%d memsize=%d\n",k,f->enc,f->loc,f->mode,f->cases,f->memslot,f->memsize);
  for(int c=0;c<f->cases;c++){
   struct input in;struct output out;make_input(f,c,&in);uint8_t memory[96] __attribute__((aligned(32)));uint8_t*mp=memory+(!strcmp(f->loc,"mem-unaligned")?1:0);memset(memory,0x5a,sizeof(memory));memcpy(mp,in.x[f->memslot],32);memset(&out,0,sizeof(out));fault_sig=fault_code=0;fault_ip=(uintptr_t)f->fault;resume_ip=(uintptr_t)f->resume;f->fn(&in,&out,mp);
   if((out.flags_before&0xffff)!=0xad7){bad++;if(bad<8)fprintf(stderr,"initial flags mismatch form=%u\n",k);}
   if(fault_sig){traps++;if(memcmp(out.x,in.x[0],32)){bad++;if(bad<8)fprintf(stderr,"fault destination changed form=%u c=%d\n",k,c);}}
   else {uint8_t ref[32];uint16_t fl=0;if(model(f,&in,ref,&fl)){checked++;if(memcmp(ref,out.x,32)||(!strcmp(f->mode,"flags")&&(out.flags&0xffff)!=fl)){bad++;if(bad<8)fprintf(stderr,"C mismatch form=%u op=%s enc=%s w=%d loc=%s c=%d imm=%d expected_flags=%04x actual=%04x\n",k,f->op,f->enc,f->width,f->loc,c,f->imm,fl,(unsigned)(out.flags&0xffff));}}
    if(f->width==128 && strcmp(f->mode,"flags")){upper++;uint8_t zeros[16]={0};if(memcmp(out.x+16,!strcmp(f->enc,"SSE")?in.x[0]+16:zeros,16))upperbad++;}
   }
   int flagdest=!strcmp(f->mode,"flags");
   printf("%s%s",!strcmp(f->enc,"VEX")?"v":"",f->op);if(f->imm>=0)printf("[%02x]",f->imm);printf(" %d ",flagdest?16:f->width);
   if(flagdest){printf("%04x ",(unsigned)(out.flags_before&0xffff));hex(in.x[0],32);putchar(' ');hex(in.x[1],32);}
   else {hex(in.x[0],32);putchar(' ');if(!strcmp(f->enc,"SSE")&&(!strcmp(f->mode,"shiftimm")||!strcmp(f->mode,"shiftbytes")))putchar('-');else hex(in.x[!strcmp(f->enc,"SSE")&&!strcmp(f->mode,"shiftcount")?2:1],32);putchar(' ');if(!strcmp(f->enc,"VEX")&&f->arity==2)hex(in.x[2],32);else putchar('-');}
   fputs(" -> ",stdout);
   if(flagdest){printf("%04x YMM_BEFORE=",(unsigned)(out.flags&0xffff));hex(in.x[0],32);fputs(" YMM_AFTER=",stdout);hex(out.x,32);printf(" ENCODED_BITS=%d",f->width);}
   else hex(out.x,32);
   if(!strcmp(f->mode,"blendvar")){fputs(" mask=",stdout);hex(in.x[3],32);}
   if(fault_sig)printf(" TRAP(sig=%d,code=%d)",fault_sig,fault_code);
   putchar('\n');lines++;
  }
 }
 printf("# rows=%"PRIu64" expected=%"PRIu64" C_checked=%"PRIu64" C_mismatches=%"PRIu64" traps=%"PRIu64" upper_checked=%"PRIu64" upper_mismatches=%"PRIu64"\n",lines,expected,checked,bad,traps,upper,upperbad);
 fprintf(stderr,"%s forms=%u rows=%"PRIu64" expected=%"PRIu64" C_checked=%"PRIu64" C_mismatches=%"PRIu64" traps=%"PRIu64" upper_checked=%"PRIu64" upper_mismatches=%"PRIu64"\n",argv[1],nf,lines,expected,checked,bad,traps,upper,upperbad);
 return bad||upperbad||lines!=expected;
}
