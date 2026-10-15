/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 MacRunner contributors
 * x87 reference stand, Part B: sticky status flags across compares and integer stores.
 * Same CSV layout as Part A (probe.c) so compare_cpu.py works on both tables. See README.md.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <cpuid.h>
#include <sys/utsname.h>
#if !defined(__x86_64__) || !defined(__linux__)
#error This probe requires native Linux x86_64
#endif
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "little endian required");
typedef struct __attribute__((packed)) { uint64_t sig; uint16_t se; } Ext;
typedef struct __attribute__((aligned(16))) { unsigned char b[512]; } State;
typedef struct { const char *name; Ext x; int has64; uint64_t d; } Val;
static Val v[32]; static int nv; static uint64_t rows;
static uint16_t rd16(const void *p) { uint16_t x; memcpy(&x,p,2); return x; }
static Ext ext64(uint64_t d) {
    Ext x={0,(uint16_t)((d>>48)&0x8000)};
    unsigned e=(unsigned)((d>>52)&2047); uint64_t f=d&UINT64_C(0xfffffffffffff);
    if(e==2047) { x.se|=0x7fff; x.sig=UINT64_C(0x8000000000000000)|(f<<11); }
    else if(e) { x.se|=(uint16_t)(e-1023+16383); x.sig=UINT64_C(0x8000000000000000)|(f<<11); }
    else if(f) { int k=63-__builtin_clzll(f); x.se|=(uint16_t)(k-1074+16383); x.sig=f<<(63-k); }
    return x;
}
static void add64(const char *s,uint64_t d) { v[nv++]=(Val){s,ext64(d),1,d}; }
/* Bit patterns and names are the same as in Part A so rows can be read side by side. */
static void values(void) {
#define D(s,x) add64(s,UINT64_C(x))
    D("pzero",0x0000000000000000);D("nzero",0x8000000000000000);D("one",0x3ff0000000000000);D("none",0xbff0000000000000);
    D("two",0x4000000000000000);D("one_half",0x3ff8000000000000);D("dmax",0x7fefffffffffffff);D("int53",0x4340000000000000);
    D("pinfty",0x7ff0000000000000);D("ninfty",0xfff0000000000000);D("qnan_123",0x7ff8000000000123);D("snan_123",0x7ff0000000000123);
    D("i16_above",0x40e0000000000000);D("i32_above",0x41e0000000000000);
#undef D
}
/* Status-word seeds. Bits 0..5 are the sticky exception flags IE DE ZE OE UE PE, bit 9 is C1 (not sticky);
   bits 8, 10 and 14 are C0, C2, C3: seeding them shows whether FCOMI-family compares keep or clear them. */
static const uint16_t seeds[]={0x0000,0x0001,0x003f,0x0200,0x023f,0x4500,0x473f};
static const char *seed_names[]={"seed_none","seed_IE","seed_sticky_IE_DE_ZE_OE_UE_PE","seed_C1","seed_C1_and_sticky",
                                 "seed_C3_C2_C0","seed_C3_C2_C1_C0_and_sticky"};
#define NSEED 7
static void init(uint16_t cw) {
    __asm__ volatile("fninit\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfninit\n\tfldcw %0"::"m"(cw):"memory");
}
static void snap(State *s) { __asm__ volatile("fxsave %0":"=m"(*s)::"memory"); }
static void load80(const Ext *x) { __asm__ volatile("fldt %0"::"m"(*x):"memory"); }
static void reset(void) { __asm__ volatile("fninit":::"memory"); }
/* Seed the status word exactly as Part A does: patch the saved image and reload it with FXRSTOR. */
static void seed_status(State *pre,uint16_t seed) {
    uint16_t sw=(uint16_t)(rd16(pre->b+2)|seed);memcpy(pre->b+2,&sw,2);
    __asm__ volatile("fxrstor %0"::"m"(*pre):"memory","xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7","xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15");
}
static void hex80(Ext x) { printf("%04x%016" PRIx64,x.se,x.sig); }
static void hexmem(const unsigned char *p,int n) { for(int i=n-1;i>=0;i--)printf("%02x",p[i]); }
static void regs(const State *s) {
    unsigned top=(rd16(s->b+2)>>11)&7,tw=s->b[4];
    for(unsigned j=0;j<8;j++) { putchar(','); if(tw&(1u<<((top+j)&7))) hexmem(s->b+32+16*j,10); else putchar('-'); }
}
/* memory_bits carries the stored integer for FIST* and the low 32 bits of RFLAGS (ZF PF CF) for FCOMI*; memory_sw is the
 * status word read right after the operation. SSE columns stay '-' (nothing to compare with). */
static void emit(const char *group,const char *op,uint16_t cw,const char *label,const Val *a,const Val *b,const State *pre,const State *post,const unsigned char *mem,int n,uint16_t sw_after) {
    printf("%" PRIu64 ",%s,%s,%04x,%s,",++rows,group,op,cw,label);
    if(a){printf("%s,",a->name);hex80(a->x);}else printf("-,-");
    putchar(',');if(b){printf("%s,",b->name);hex80(b->x);}else printf("-,-");
    printf(",%04x,%04x,%02x",rd16(pre->b+2),rd16(post->b+2),post->b[4]);regs(post);
    putchar(',');if(n)hexmem(mem,n);else putchar('-');
    if(n)printf(",%04x",sw_after);else printf(",-");
    printf(",-,-,-,NOT_MEASURED,NOT_MEASURED\n");
}
static void compares(uint16_t cw) {
    static const char *ops[]={"fcom","fcomp","fucom","fucomp","fcomi","fcomip","fucomi","fucomip"};
    for(int i=0;i<nv;i++)for(int j=0;j<nv;j++)for(int s=0;s<NSEED;s++)for(unsigned o=0;o<sizeof(ops)/sizeof(*ops);o++) {
        const char *op=ops[o];State pre,post;uint64_t fl=0;unsigned char mem[4]={0};int n=0;uint16_t sw;
        init(cw);load80(&v[j].x);load80(&v[i].x);snap(&pre);seed_status(&pre,seeds[s]);
#define CMP(name,ins) if(!strcmp(op,name)) __asm__ volatile(ins:::"memory","cc")
#define CMPF(name,ins) if(!strcmp(op,name)) __asm__ volatile(ins "\n\tpushfq\n\tpopq %0":"=r"(fl)::"memory","cc")
        CMP("fcom","fcom %%st(1)");else CMP("fcomp","fcomp %%st(1)");else CMP("fucom","fucom %%st(1)");else CMP("fucomp","fucomp %%st(1)");
        else CMPF("fcomi","fcomi %%st(1),%%st");else CMPF("fcomip","fcomip %%st(1),%%st");else CMPF("fucomi","fucomi %%st(1),%%st");else CMPF("fucomip","fucomip %%st(1),%%st");else abort();
#undef CMP
#undef CMPF
        snap(&post);__asm__ volatile("fnstsw %0":"=m"(sw)::"memory");reset();
        if(o>=4){uint32_t f32=(uint32_t)(fl&0x8d5u);memcpy(mem,&f32,4);n=4;} /* CF PF ZF (and SF OF AF bits, all masked to the arithmetic set) */
        emit("seeded-compare",op,cw,seed_names[s],&v[i],&v[j],&pre,&post,mem,n,sw);
    }
    for(int i=0;i<nv;i++)for(int s=0;s<NSEED;s++) {
        State pre,post;uint16_t sw;init(cw);load80(&v[i].x);snap(&pre);seed_status(&pre,seeds[s]);
        __asm__ volatile("ftst":::"memory");snap(&post);__asm__ volatile("fnstsw %0":"=m"(sw)::"memory");reset();
        emit("seeded-compare","ftst",cw,seed_names[s],&v[i],NULL,&pre,&post,NULL,0,sw);
    }
}
static void stores(uint16_t cw,int sse3) {
    static const char *ops[]={"fist_m16","fistp_m16","fist_m32","fistp_m32","fistp_m64","fisttp_m16","fisttp_m32","fisttp_m64"};
    for(int i=0;i<nv;i++)for(int s=0;s<NSEED;s++)for(unsigned o=0;o<sizeof(ops)/sizeof(*ops);o++) {
        const char *op=ops[o];if(o>=5&&!sse3)continue;State pre,post;unsigned char mem[8];memset(mem,0xa5,sizeof(mem));uint16_t sw;
        init(cw);load80(&v[i].x);snap(&pre);seed_status(&pre,seeds[s]);
#define ST(name,ins,T) if(!strcmp(op,name))__asm__ volatile(ins " %0":"=m"(*(T*)mem)::"memory")
        ST("fist_m16","fists",uint16_t);else ST("fistp_m16","fistps",uint16_t);else ST("fist_m32","fistl",uint32_t);else ST("fistp_m32","fistpl",uint32_t);else ST("fistp_m64","fistpq",uint64_t);
        else ST("fisttp_m16","fisttps",uint16_t);else ST("fisttp_m32","fisttpl",uint32_t);else ST("fisttp_m64","fisttpq",uint64_t);else abort();
#undef ST
        snap(&post);__asm__ volatile("fnstsw %0":"=m"(sw)::"memory");reset();int n=strstr(op,"64")?8:strstr(op,"32")?4:2;
        emit("seeded-store",op,cw,seed_names[s],&v[i],NULL,&pre,&post,mem,n,sw);
    }
}
/* Control: the same FADD one+one as Part A's seeded-status group, to tie the two tables together. */
static void control(uint16_t cw) {
    for(int s=0;s<NSEED;s++){State pre,post;uint16_t sw;init(cw);load80(&v[2].x);load80(&v[2].x);snap(&pre);seed_status(&pre,seeds[s]);
        __asm__ volatile("fadd %%st(1),%%st":::"memory");snap(&post);__asm__ volatile("fnstsw %0":"=m"(sw)::"memory");reset();
        emit("seeded-control","fadd",cw,seed_names[s],&v[2],&v[2],&pre,&post,NULL,0,sw);}
}
static void metadata(void) {
    unsigned a,b,c,d;char vendor[13]={0},brand[49]={0};__cpuid(0,a,b,c,d);memcpy(vendor,&b,4);memcpy(vendor+4,&d,4);memcpy(vendor+8,&c,4);
    __cpuid(1,a,b,c,d);unsigned sig=a,hyper=(c>>31)&1;printf("format=x87-native-partB-v1\narchitecture=x86_64\nos=Linux\nvendor=%s\ncpuid_signature=%08x\nhypervisor_bit=%u\nsse3_fisttp=%u\n",vendor,sig,hyper,c&1);
    for(unsigned i=0;i<3;i++){__cpuid(0x80000002+i,a,b,c,d);memcpy(brand+16*i,&a,4);memcpy(brand+16*i+4,&b,4);memcpy(brand+16*i+8,&c,4);memcpy(brand+16*i+12,&d,4);}printf("brand=%s\ncompiler=%s\n",brand,__VERSION__);
    if(hyper){char hv[13]={0};__cpuid(0x40000000,a,b,c,d);memcpy(hv,&b,4);memcpy(hv+4,&c,4);memcpy(hv+8,&d,4);printf("hypervisor_vendor=%s\n",hv);}
    struct utsname u;if(!uname(&u))printf("kernel_release=%s\n",u.release);
    printf("execution=native x87 machine instructions; status word seeded through FXRSTOR; cloud virtualization disclosed; bare-metal not established\nexceptions=all masked\n");
}
int main(int argc,char **argv) {
    if(argc>1&&!strcmp(argv[1],"--metadata")){metadata();return 0;}
    unsigned a,b,c,d;__cpuid(1,a,b,c,d);int sse3=c&1;values();
    printf("row,group,op,cw,case,a_name,a_ext80,b_name,b_ext80,pre_sw,post_sw,post_ftw,st0,st1,st2,st3,st4,st5,st6,st7,memory_bits,memory_sw,sse64_bits,sse_mxcsr,reg_equal_sse,intel_bits,intel_amd_diff\n");
    for(int pc=2;pc<=3;pc++){uint16_t cw=(uint16_t)(0x7f|(pc<<8));compares(cw);control(cw);}
    for(int pc=2;pc<=3;pc++)for(int rc=0;rc<4;rc++){uint16_t cw=(uint16_t)(0x7f|(pc<<8)|(rc<<10));stores(cw,sse3);}
    fprintf(stderr,"rows=%" PRIu64 " values=%d part=B\n",rows,nv);reset();return ferror(stdout)?1:0;
}
