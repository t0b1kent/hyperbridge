/* Native hardware flags recorder. MIT; see LICENSE. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cpuid.h>
#include <sys/utsname.h>

#if !defined(__x86_64__)
#error This experiment requires native x86-64.
#endif
#define FLAGS UINT64_C(0x8d5)
#define SEED UINT64_C(0x0031c0ffee123456)
#define RANDOMS 4096
typedef uint64_t (*regprobe)(uint64_t, uint64_t, uint64_t *);
typedef void (*stub)(void);
#define DECL(OP,W) extern uint64_t probe_##OP##W(uint64_t,uint64_t,uint64_t *);
#define DECL_WIDTHS(OP) DECL(OP,8) DECL(OP,16) DECL(OP,32) DECL(OP,64)
DECL_WIDTHS(inc) DECL_WIDTHS(dec) DECL_WIDTHS(add) DECL_WIDTHS(sub)
extern uint64_t probe_inc_ah(uint64_t,uint64_t,uint64_t *);
extern uint64_t probe_dec_ch(uint64_t,uint64_t,uint64_t *);
extern uint64_t probe_memory(const void *,uint64_t,stub);
extern uint64_t probe_load_flags(uint64_t);
extern stub table_cmp_m8_i8[256], table_test_m8_i8[256];
extern stub table_cmp_m16_i8[256], table_cmp_m16_i16[65536], table_cmp_m32_i8[256];

static const uint64_t edges[20]={
 0,1,2,0xf,0x10,0x7f,0x80,0xff,0x100,0x7fff,0x8000,0xffff,
 0x10000,0x7fffffff,0x80000000,0xffffffff,0x100000000,
 UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000000000000),UINT64_MAX
};
static const uint64_t states4[4]={0,FLAGS,1,FLAGS^1};
static const uint64_t states2[2]={0,FLAGS};
static const unsigned widths[4]={8,16,32,64};
static uint64_t rowcounts[4];
static uint64_t mask(unsigned w) {return w==64?UINT64_MAX:(UINT64_C(1)<<w)-1;}
static uint64_t rng(uint64_t *s) {
 uint64_t z=(*s+=UINT64_C(0x9e3779b97f4a7c15));
 z=(z^(z>>30))*UINT64_C(0xbf58476d1ce4e5b9);
 z=(z^(z>>27))*UINT64_C(0x94d049bb133111eb);
 return z^(z>>31);
}
static void fail(const char *s) {fprintf(stderr,"ERROR: %s\n",s);exit(1);}
static FILE *csv(const char *dir,const char *name) {
 char path[4096];if(snprintf(path,sizeof path,"%s/%s",dir,name)>=(int)sizeof path)fail("path too long");
 FILE *f=fopen(path,"wb");if(!f)fail("cannot open CSV");
 fputs("op,width,flags_in,a,b,result,flags_out\n",f);return f;
}
static void row(FILE *f,const char *op,unsigned w,uint64_t fi,uint64_t a,uint64_t b,uint64_t r,uint64_t fo,unsigned section) {
 if(fi&~FLAGS || fo&~FLAGS)fail("flags outside six-bit mask");
 if(fprintf(f,"%s,0x%x,0x%03" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ",0x%016" PRIx64 ",0x%03" PRIx64 "\n",op,w,fi,a,b,r,fo)<0)fail("CSV write");
 rowcounts[section]++;
}
static void closecsv(FILE *f) {if(fclose(f))fail("CSV close");}
static size_t values(unsigned w,uint64_t *v) {
 if(w==8) {for(unsigned i=0;i<256;i++)v[i]=i;return 256;}
 for(unsigned i=0;i<20;i++)v[i]=edges[i]&mask(w);
 uint64_t s=SEED^w;
 for(unsigned i=0;i<RANDOMS;i++)v[20+i]=rng(&s)&mask(w);
 return 20+RANDOMS;
}
static void registers(const char *dir,unsigned section) {
 const char *names[2][2]={{"INC","DEC"},{"ADD1","SUB1"}};
 regprobe probes[2][2][4]={
 {{probe_inc8,probe_inc16,probe_inc32,probe_inc64},{probe_dec8,probe_dec16,probe_dec32,probe_dec64}},
 {{probe_add8,probe_add16,probe_add32,probe_add64},{probe_sub8,probe_sub16,probe_sub32,probe_sub64}}
 };
 FILE *f=csv(dir,section==0?"A-inc-dec.csv":"B-add1-sub1.csv");
 for(unsigned op=0;op<2;op++)for(unsigned wi=0;wi<4;wi++) {
  unsigned w=widths[wi];uint64_t v[20+RANDOMS];size_t n=values(w,v);
  for(size_t i=0;i<n;i++)for(unsigned si=0;si<4;si++) {
   uint64_t r=0,fo=probes[section][op][wi](v[i],states4[si],&r);
   row(f,names[section][op],w,states4[si],v[i],section==0?0:1,r&mask(w),fo,section);
  }
 }
 closecsv(f);
}
static void memrow(FILE *f,const char *op,unsigned w,unsigned iw,uint64_t a,uint64_t b,uint64_t fi,stub *table,int test) {
 /* Native little-endian x86 object; verify the complete 64-bit object unchanged. */
 uint64_t memory=UINT64_C(0x1122334455667788);
 memory=(memory&~mask(w))|a;
 uint64_t before=memory,fo=probe_memory(&memory,fi,table[b]);
 if(memory!=before)fail("CMP/TEST unexpectedly modified memory");
 uint64_t effective=b;
 if(iw==8 && w>8 && (b&0x80))effective=b|(mask(w)^UINT64_C(0xff));
 uint64_t result=(test?(a&effective):(a-effective))&mask(w);
 row(f,op,w,fi,a,b,result,fo,2);
}
static void memory_cases(const char *dir) {
 FILE *f=csv(dir,"C-memory-cmp-test.csv");
 for(unsigned test=0;test<2;test++)for(uint64_t a=0;a<256;a++)for(uint64_t b=0;b<256;b++)for(unsigned si=0;si<2;si++)
  memrow(f,test?"TEST_M8_IMM8":"CMP_M8_IMM8",8,8,a,b,states2[si],test?table_test_m8_i8:table_cmp_m8_i8,test);
 const char *names[3]={"CMP_M16_IMM8","CMP_M16_IMM16","CMP_M32_IMM8"};
 const unsigned ws[3]={16,16,32},iws[3]={8,16,8};
 stub *tables[3]={table_cmp_m16_i8,table_cmp_m16_i16,table_cmp_m32_i8};
 for(unsigned k=0;k<3;k++) {
  unsigned w=ws[k],iw=iws[k];
  for(unsigned i=0;i<20;i++)for(unsigned j=0;j<20;j++)for(unsigned si=0;si<2;si++)
   memrow(f,names[k],w,iw,edges[i]&mask(w),edges[j]&mask(iw),states2[si],tables[k],0);
  uint64_t s=SEED^((uint64_t)w<<8)^iw;
  for(unsigned i=0;i<RANDOMS;i++) {
   uint64_t a=rng(&s)&mask(w),b=rng(&s)&mask(iw);
   for(unsigned si=0;si<2;si++)memrow(f,names[k],w,iw,a,b,states2[si],tables[k],0);
  }
 }
 closecsv(f);
}
static void high_cases(const char *dir) {
 FILE *f=csv(dir,"D-high-byte.csv");
 regprobe p[2]={probe_inc_ah,probe_dec_ch};const char *n[2]={"INC_AH","DEC_CH"};
 for(unsigned op=0;op<2;op++)for(uint64_t a=0;a<256;a++)for(unsigned si=0;si<4;si++) {
  uint64_t r=0,fo=p[op](a,states4[si],&r);
  row(f,n[op],8,states4[si],a,0,r,fo,3);
 }
 closecsv(f);
}
static void identity(void) {
 unsigned a,b,c,d; char vendor[13]={0},brand[49]={0};
 __cpuid(0,a,b,c,d);unsigned maxleaf=a;
 memcpy(vendor,&b,4);memcpy(vendor+4,&d,4);memcpy(vendor+8,&c,4);
 printf("CPUID vendor=%s max_basic=0x%x\n",vendor,maxleaf);
 __cpuid(1,a,b,c,d);
 unsigned base_family=(a>>8)&15,family=base_family,model=(a>>4)&15,stepping=a&15;
 if(base_family==15)family+=(a>>20)&255;
 if(base_family==6 || base_family==15)model+=((a>>16)&15)<<4;
 printf("CPUID.1 EAX=0x%08x ECX=0x%08x EDX=0x%08x family=%u model=%u stepping=%u hypervisor_present=%u\n",a,c,d,family,model,stepping,c>>31);
 if(c>>31) {char hv[13]={0};__cpuid(0x40000000,a,b,c,d);memcpy(hv,&b,4);memcpy(hv+4,&c,4);memcpy(hv+8,&d,4);printf("CPUID hypervisor_vendor=%s\n",hv);}
 __cpuid(0x80000000,a,b,c,d);
 if(a>=0x80000004)for(unsigned l=0;l<3;l++) {__cpuid(0x80000002+l,a,b,c,d);memcpy(brand+l*16,&a,4);memcpy(brand+l*16+4,&b,4);memcpy(brand+l*16+8,&c,4);memcpy(brand+l*16+12,&d,4);}
 printf("CPUID brand=%s\n",brand);
 struct utsname u;if(uname(&u))fail("uname");printf("kernel=%s %s architecture=%s\n",u.sysname,u.release,u.machine);
 printf("compiler=%s ABI=ELF System V x86-64 pointer_bits=%zu\n",__VERSION__,sizeof(void*)*8);
 printf("seed=0x%016" PRIx64 " PRNG=SplitMix64\n",SEED);
 for(unsigned i=0;i<4;i++) {
  uint64_t observed=probe_load_flags(states4[i]);
  printf("flag_load requested=0x%03" PRIx64 " measured=0x%03" PRIx64 "\n",states4[i],observed);
  if(observed!=states4[i])fail("POPFQ did not load intended status flags");
 }
}
int main(int argc,char **argv) {
 if(argc!=2) {fputs("usage: ./probe OUTPUT_DIRECTORY\n",stderr);return 2;}
 identity();registers(argv[1],0);registers(argv[1],1);memory_cases(argv[1]);high_cases(argv[1]);
 for(unsigned i=0;i<4;i++)printf("section_%c_data_rows=%" PRIu64 "\n",'A'+i,rowcounts[i]);
 puts("native_recording_complete=1");return 0;
}
