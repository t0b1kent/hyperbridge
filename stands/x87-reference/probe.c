/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 OpenAI
 * Original native x87 numerical oracle. See LICENSE and README.md.
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
static Val v[160]; static int nv; static uint64_t rows;
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
static void add80(const char *s,uint16_t se,uint64_t sig) { v[nv++]=(Val){s,{sig,se},0,0}; }
static void values(void) {
#define D(s,x) add64(s,UINT64_C(x))
    D("pzero",0x0000000000000000);D("nzero",0x8000000000000000);
    D("one",0x3ff0000000000000);D("none",0xbff0000000000000);D("two",0x4000000000000000);D("three",0x4008000000000000);
    D("half",0x3fe0000000000000);D("nhalf",0xbfe0000000000000);D("one_half",0x3ff8000000000000);D("none_half",0xbff8000000000000);
    D("one_lo",0x3fefffffffffffff);D("one_hi",0x3ff0000000000001);D("eps52",0x3cb0000000000000);D("eps53",0x3ca0000000000000);D("eps54",0x3c90000000000000);
    D("dmax",0x7fefffffffffffff);D("ndmax",0xffefffffffffffff);D("dmax_lo",0x7feffffffffffffe);D("pow1023",0x7fe0000000000000);
    D("dminnorm",0x0010000000000000);D("dminnorm_hi",0x0010000000000001);D("dmaxsub",0x000fffffffffffff);
    D("dminsub",0x0000000000000001);D("ndminsub",0x8000000000000001);D("dsub2",0x0000000000000002);D("dsub3",0x0000000000000003);
    D("pinfty",0x7ff0000000000000);D("ninfty",0xfff0000000000000);
    D("qnan_123",0x7ff8000000000123);D("nqnan_456",0xfff8000000000456);D("snan_123",0x7ff0000000000123);D("nsnan_456",0xfff0000000000456);
    D("int53",0x4340000000000000);D("int53_hi",0x4340000000000001);D("int63",0x43e0000000000000);D("nint63",0xc3e0000000000000);
    D("pi2_lo",0x3ff921fb54442d17);D("pi2",0x3ff921fb54442d18);D("pi2_hi",0x3ff921fb54442d19);
    D("pi_lo",0x400921fb54442d17);D("pi",0x400921fb54442d18);D("pi_hi",0x400921fb54442d19);
    D("npi2",0xbff921fb54442d18);D("range63_lo",0x43dfffffffffffff);D("range63",0x43e0000000000000);D("range63_hi",0x43e0000000000001);
    D("fminsub",0x36a0000000000000);D("fminnorm",0x3810000000000000);D("fmax",0x47efffffe0000000);
    D("sqrt2",0x3ff6a09e667f3bcd);D("ten",0x4024000000000000);D("1024",0x4090000000000000);D("n1075",0xc090cc0000000000);
    D("neps53",0xbca0000000000000);
    D("double_round_a",0x1ff0000000000004);D("double_round_b",0x1ffffffffffffffe);
    D("ndouble_round_a",0x9ff0000000000004);
    D("one_half_lo",0x3ff7ffffffffffff);D("one_half_hi",0x3ff8000000000001);
    D("none_lo",0xbff0000000000001);D("none_hi",0xbfefffffffffffff);
    D("two_pi_lo",0x401921fb54442d17);D("two_pi",0x401921fb54442d18);D("two_pi_hi",0x401921fb54442d19);
    D("pi_large_lo",0x413921fb54442d17);D("pi_large",0x413921fb54442d18);D("pi_large_hi",0x413921fb54442d19);
    D("i16_above",0x40e0000000000000);D("i16_tie",0x40dfffe000000000);D("ni16_below",0xc0e0001000000000);
    D("i32_above",0x41e0000000000000);D("i32_tie",0x41dfffffffe00000);D("ni32_below",0xc1e0000000100000);
    D("i64_below",0x43dfffffffffffff);D("ni64_below",0xc3e0000000000001);
#undef D
    add80("one_ext_hi",0x3fff,UINT64_C(0x8000000000000001));
    add80("one_ext_lo",0x3ffe,UINT64_C(0xffffffffffffffff));
    add80("half_double_ulp_plus_ext",0x3fff,UINT64_C(0x8000000000000401));
    add80("pow1024",0x43ff,UINT64_C(0x8000000000000000));
    add80("pow_n1075",0x3bcc,UINT64_C(0x8000000000000000));
    add80("eminnorm",0x0001,UINT64_C(0x8000000000000000));
    add80("eminsub",0x0000,UINT64_C(0x0000000000000001));
    add80("emaxsub",0x0000,UINT64_C(0x7fffffffffffffff));
    add80("emax",0x7ffe,UINT64_C(0xffffffffffffffff));
    add80("qnan_ext_lowpayload",0x7fff,UINT64_C(0xc000000000000123));
    add80("snan_ext_lowpayload",0xffff,UINT64_C(0x8000000000000456));
    add80("pseudo_denormal",0x0000,UINT64_C(0x8000000000000000));
    add80("unsupported_unnormal",0x3fff,UINT64_C(0x4000000000000000));
    add80("pi2_ext_lo",0x3fff,UINT64_C(0xc90fdaa22168c234));
    add80("pi2_ext",0x3fff,UINT64_C(0xc90fdaa22168c235));
    add80("pi2_ext_hi",0x3fff,UINT64_C(0xc90fdaa22168c236));
    add80("pi_ext",0x4000,UINT64_C(0xc90fdaa22168c235));
}
static void init(uint16_t cw) {
    /* Overwrite all physical x87 registers so empty slots cannot leak old data. */
    __asm__ volatile("fninit\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfldz\n\tfninit\n\tfldcw %0"::"m"(cw):"memory");
}
static void snap(State *s) { __asm__ volatile("fxsave %0":"=m"(*s)::"memory"); }
static void load80(const Ext *x) { __asm__ volatile("fldt %0"::"m"(*x):"memory"); }
static void reset(void) { __asm__ volatile("fninit":::"memory"); }
static void hex80(Ext x) { printf("%04x%016" PRIx64,x.se,x.sig); }
static void hexmem(const unsigned char *p,int n) { for(int i=n-1;i>=0;i--)printf("%02x",p[i]); }
static void regs(const State *s) {
    unsigned top=(rd16(s->b+2)>>11)&7,tw=s->b[4];
    for(unsigned j=0;j<8;j++) { putchar(','); if(tw&(1u<<((top+j)&7))) hexmem(s->b+32+16*j,10); else putchar('-'); }
}
static uint64_t sse(const char *op,uint64_t a,uint64_t b,int rc,uint32_t *flags) {
    uint32_t old,mc=(uint32_t)(0x1f80|(rc<<13));uint64_t z=0;
    __asm__ volatile("stmxcsr %0":"=m"(old));
    __asm__ volatile("ldmxcsr %0"::"m"(mc));
#define SSE(name,ins) if(!strcmp(op,name)) __asm__ volatile("movq %1,%%xmm0\n\tmovq %2,%%xmm1\n\t" ins " %%xmm1,%%xmm0\n\tmovq %%xmm0,%0":"=r"(z):"r"(a),"r"(b):"xmm0","xmm1","memory")
    SSE("fadd","addsd");else SSE("fsub","subsd");else SSE("fmul","mulsd");else SSE("fdiv","divsd");
    else if(!strcmp(op,"fsqrt")) __asm__ volatile("movq %1,%%xmm0\n\tsqrtsd %%xmm0,%%xmm0\n\tmovq %%xmm0,%0":"=r"(z):"r"(a):"xmm0","memory");
#undef SSE
    __asm__ volatile("stmxcsr %0":"=m"(*flags));
    __asm__ volatile("ldmxcsr %0"::"m"(old));
    return z;
}
static void emit(const char *group,const char *op,uint16_t cw,const char *label,const Val *a,const Val *b,const State *pre,const State *post,const unsigned char *mem,int n,uint16_t store_sw,int cmp,uint64_t sz,uint32_t smx) {
    printf("%" PRIu64 ",%s,%s,%04x,%s,",++rows,group,op,cw,label);
    if(a){printf("%s,",a->name);hex80(a->x);}else printf("-,-");
    putchar(',');if(b){printf("%s,",b->name);hex80(b->x);}else printf("-,-");
    printf(",%04x,%04x,%02x",rd16(pre->b+2),rd16(post->b+2),post->b[4]);regs(post);
    putchar(',');if(n)hexmem(mem,n);else putchar('-');
    if(n)printf(",%04x",store_sw);else printf(",-");
    if(cmp){Ext sx=ext64(sz);int equal=memcmp(&sx,post->b+32,10)==0;printf(",%016" PRIx64 ",%08x,%d",sz,smx,equal);}
    else printf(",-,-,-");
    printf(",NOT_MEASURED,NOT_MEASURED\n");
}
static void operation(const char *op,uint16_t cw,const Val *a,const Val *b,const char *group,const char *label) {
    State pre,post; unsigned char mem[10]={0};uint16_t ssw=0; init(cw);if(b)load80(&b->x);load80(&a->x);snap(&pre);
#define OP(name,ins) if(!strcmp(op,name)) __asm__ volatile(ins:::"memory")
    OP("fadd","fadd %%st(1),%%st");else OP("fsub","fsub %%st(1),%%st");else OP("fmul","fmul %%st(1),%%st");else OP("fdiv","fdiv %%st(1),%%st");
    else OP("fsqrt","fsqrt");else OP("fprem","fprem");else OP("fprem1","fprem1");else OP("frndint","frndint");else OP("fscale","fscale");
    else OP("fxtract","fxtract");else OP("fabs","fabs");else OP("fchs","fchs");
    else OP("fsin","fsin");else OP("fcos","fcos");else OP("fsincos","fsincos");else OP("fptan","fptan");else OP("fpatan","fpatan");
    else OP("fyl2x","fyl2x");else OP("fyl2xp1","fyl2xp1");else OP("f2xm1","f2xm1");else abort();
#undef OP
    snap(&post);
    int cmp=a->has64&&(!b||b->has64)&&(!strcmp(op,"fadd")||!strcmp(op,"fsub")||!strcmp(op,"fmul")||!strcmp(op,"fdiv")||!strcmp(op,"fsqrt"));
    if(cmp)__asm__ volatile("fstpl %0\n\tfnstsw %1":"=m"(*(uint64_t*)mem),"=m"(ssw)::"memory");
    reset();uint32_t mx=0;uint64_t z=cmp?sse(op,a->d,b?b->d:0,(cw>>10)&3,&mx):0;
    emit(group,op,cw,label,a,b,&pre,&post,mem,cmp?8:0,ssw,cmp,z,mx);
}
static void loads(uint16_t cw) {
    State pre,post;uint64_t d;uint32_t f;Ext e;
    for(int i=0;i<nv;i++) {
        init(cw);snap(&pre);e=v[i].x;load80(&e);snap(&post);reset();emit("load","fld_m80",cw,"direct-memory",&v[i],NULL,&pre,&post,(unsigned char*)&e,10,rd16(post.b+2),0,0,0);
        if(v[i].has64){init(cw);snap(&pre);d=v[i].d;__asm__ volatile("fldl %0"::"m"(d):"memory");snap(&post);reset();emit("load","fld_m64",cw,"direct-memory",&v[i],NULL,&pre,&post,(unsigned char*)&d,8,rd16(post.b+2),0,0,0);}
    }
    static const uint32_t fs[]={0,0x80000000,0x3f800000,0xbf800000,1,0x80000001,0x007fffff,0x00800000,0x7f7fffff,0x7f800000,0xff800000,0x7fc00123,0xffc00456,0x7f800123,0xff800456};
    for(unsigned i=0;i<sizeof(fs)/sizeof(*fs);i++){f=fs[i];init(cw);snap(&pre);__asm__ volatile("flds %0"::"m"(f):"memory");snap(&post);reset();char name[40];snprintf(name,sizeof(name),"bits_%08x",f);emit("load","fld_m32",cw,name,NULL,NULL,&pre,&post,(unsigned char*)&f,4,rd16(post.b+2),0,0,0);}
    static const int64_t is[]={0,1,-1,32767,-32768,32768,2147483647,-INT64_C(2147483648),INT64_C(2147483648),INT64_C(9007199254740991),INT64_C(9007199254740993),INT64_MAX,INT64_MIN};
    for(unsigned i=0;i<sizeof(is)/sizeof(*is);i++)for(int n=2;n<=8;n*=2){int64_t q=is[i];if(n==2&&(q<INT16_MIN||q>INT16_MAX))continue;if(n==4&&(q<INT32_MIN||q>INT32_MAX))continue;init(cw);snap(&pre);
        if(n==2){int16_t k=(int16_t)q;__asm__ volatile("filds %0"::"m"(k):"memory");}else if(n==4){int32_t k=(int32_t)q;__asm__ volatile("fildl %0"::"m"(k):"memory");}else __asm__ volatile("fildq %0"::"m"(q):"memory");
        snap(&post);reset();char name[40],op[24];snprintf(name,sizeof(name),"integer_%" PRId64,q);snprintf(op,sizeof(op),"fild_m%d",n*8);emit("load",op,cw,name,NULL,NULL,&pre,&post,(unsigned char*)&q,n,rd16(post.b+2),0,0,0);
    }
}
static void stores(uint16_t cw,int sse3) {
    static const char *ops[]={"fst_m32","fstp_m32","fst_m64","fstp_m64","fstp_m80","fist_m16","fistp_m16","fist_m32","fistp_m32","fistp_m64","fisttp_m16","fisttp_m32","fisttp_m64"};
    for(int i=0;i<nv;i++)for(unsigned j=0;j<sizeof(ops)/sizeof(*ops);j++) {
        const char *op=ops[j];if(j>=10&&!sse3)continue;State pre,post;unsigned char mem[10];memset(mem,0xa5,sizeof(mem));init(cw);load80(&v[i].x);snap(&pre);
#define ST(name,ins,T) if(!strcmp(op,name))__asm__ volatile(ins " %0":"=m"(*(T*)mem)::"memory")
        ST("fst_m32","fsts",uint32_t);else ST("fstp_m32","fstps",uint32_t);else ST("fst_m64","fstl",uint64_t);else ST("fstp_m64","fstpl",uint64_t);else ST("fstp_m80","fstpt",Ext);
        else ST("fist_m16","fists",uint16_t);else ST("fistp_m16","fistps",uint16_t);else ST("fist_m32","fistl",uint32_t);else ST("fistp_m32","fistpl",uint32_t);else ST("fistp_m64","fistpq",uint64_t);
        else ST("fisttp_m16","fisttps",uint16_t);else ST("fisttp_m32","fisttpl",uint32_t);else ST("fisttp_m64","fisttpq",uint64_t);else abort();
#undef ST
        snap(&post);reset();int n=strstr(op,"80")?10:strstr(op,"64")?8:strstr(op,"32")?4:2;emit("store",op,cw,"direct-memory",&v[i],NULL,&pre,&post,mem,n,rd16(post.b+2),0,0,0);
    }
}
static void stacks(uint16_t cw) {
    const char *ops[]={"fadd_empty","fadd_st1_empty","fsqrt_empty","fxtract_full","fld_full","fstp_empty","fistp_empty","fst_empty"};
    for(int j=0;j<8;j++){State pre,post;uint64_t mem=UINT64_C(0xa5a5a5a5a5a5a5a5);init(cw);
        if(j==1)load80(&v[2].x);
        if(j==3||j==4)for(int k=0;k<8;k++)load80(&v[2].x);
        snap(&pre);
        if(j==0||j==1)__asm__ volatile("fadd %%st(1),%%st":::"memory");else if(j==2)__asm__ volatile("fsqrt":::"memory");else if(j==3)__asm__ volatile("fxtract":::"memory");else if(j==4)load80(&v[2].x);else if(j==5)__asm__ volatile("fstpl %0":"=m"(mem)::"memory");else if(j==6)__asm__ volatile("fistpq %0":"=m"(mem)::"memory");else __asm__ volatile("fstl %0":"=m"(mem)::"memory");
        snap(&post);reset();emit("stack",ops[j],cw,"masked-stack-fault",NULL,NULL,&pre,&post,(unsigned char*)&mem,j>=5?8:0,rd16(post.b+2),0,0,0);
    }
}
static void seeded_flags(uint16_t cw) {
    static const uint16_t seeds[]={0x0200,0x003f,0x023f};
    static const char *names[]={"seed_C1","seed_sticky_IE_DE_ZE_OE_UE_PE","seed_C1_and_sticky"};
    for(int i=0;i<3;i++){
        State pre,post;init(cw);load80(&v[2].x);load80(&v[2].x);snap(&pre);
        uint16_t sw=(uint16_t)(rd16(pre.b+2)|seeds[i]);memcpy(pre.b+2,&sw,2);
        __asm__ volatile("fxrstor %0"::"m"(pre):"memory","xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7","xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15");
        __asm__ volatile("fadd %%st(1),%%st":::"memory");snap(&post);reset();
        emit("seeded-status","fadd",cw,names[i],&v[2],&v[2],&pre,&post,NULL,0,0,0,0,0);
    }
}
static void memory_arithmetic(uint16_t cw) {
    const char *ops[]={"fadd","fsub","fmul","fdiv"};
    int ii[]={0,1,2,3,4,5,16,19,21,22,26,27,28,29,30,31};
    for(int op=0;op<4;op++)for(unsigned i=0;i<sizeof(ii)/sizeof(*ii);i++)for(unsigned j=0;j<sizeof(ii)/sizeof(*ii);j++){
        const Val *a=&v[ii[i]],*b=&v[ii[j]];State pre,post;uint64_t mem=0;uint16_t sw;
        init(cw);load80(&a->x);snap(&pre);
        if(op==0)__asm__ volatile("faddl %0"::"m"(b->d):"memory");
        else if(op==1)__asm__ volatile("fsubl %0"::"m"(b->d):"memory");
        else if(op==2)__asm__ volatile("fmull %0"::"m"(b->d):"memory");
        else __asm__ volatile("fdivl %0"::"m"(b->d):"memory");
        snap(&post);__asm__ volatile("fstpl %0\n\tfnstsw %1":"=m"(mem),"=m"(sw)::"memory");reset();
        uint32_t mx;uint64_t z=sse(ops[op],a->d,b->d,(cw>>10)&3,&mx);
        emit("arithmetic-memory64",ops[op],cw,"b_is_m64",a,b,&pre,&post,(unsigned char*)&mem,8,sw,1,z,mx);
    }
}
static void remainder_sequences(uint16_t cw) {
    int aa[4]={0},bb[3]={0};
    const char *an[]={"pow1023","int63","eminnorm","emax"},*bn[]={"three","half","dminsub"};
    for(int k=0;k<nv;k++){for(int i=0;i<4;i++)if(!strcmp(v[k].name,an[i]))aa[i]=k;for(int i=0;i<3;i++)if(!strcmp(v[k].name,bn[i]))bb[i]=k;}
    for(int p=0;p<2;p++)for(unsigned i=0;i<sizeof(aa)/sizeof(*aa);i++)for(unsigned j=0;j<sizeof(bb)/sizeof(*bb);j++){
        State pre,post;init(cw);load80(&v[bb[j]].x);load80(&v[aa[i]].x);
        for(int k=0;k<1024;k++){snap(&pre);if(p)__asm__ volatile("fprem1":::"memory");else __asm__ volatile("fprem":::"memory");snap(&post);
            /* Formatting happens after resetting, so reload the exact saved x87 state for each next instruction. */
            reset();char label[64];snprintf(label,sizeof(label),"iter_%d",k);emit("remainder-sequence",p?"fprem1":"fprem",cw,label,&v[aa[i]],&v[bb[j]],&pre,&post,NULL,0,0,0,0,0);
            if(!(rd16(post.b+2)&0x400))break;
            __asm__ volatile("fxrstor %0"::"m"(post):"memory","xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7","xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15");
        }reset();
    }
}
static void metadata(void) {
    unsigned a,b,c,d;char vendor[13]={0},brand[49]={0};__cpuid(0,a,b,c,d);memcpy(vendor,&b,4);memcpy(vendor+4,&d,4);memcpy(vendor+8,&c,4);
    __cpuid(1,a,b,c,d);unsigned sig=a,hyper=(c>>31)&1;printf("format=x87-native-partA-v3\narchitecture=x86_64\nos=Linux\nvendor=%s\ncpuid_signature=%08x\nhypervisor_bit=%u\nsse3_fisttp=%u\n",vendor,sig,hyper,c&1);
    for(unsigned i=0;i<3;i++){__cpuid(0x80000002+i,a,b,c,d);memcpy(brand+16*i,&a,4);memcpy(brand+16*i+4,&b,4);memcpy(brand+16*i+8,&c,4);memcpy(brand+16*i+12,&d,4);}printf("brand=%s\ncompiler=%s\n",brand,__VERSION__);
    if(hyper){char hv[13]={0};__cpuid(0x40000000,a,b,c,d);memcpy(hv,&b,4);memcpy(hv+4,&c,4);memcpy(hv+8,&d,4);printf("hypervisor_vendor=%s\n",hv);}
    struct utsname u;if(!uname(&u))printf("kernel_release=%s\n",u.release);
    printf("execution=native x87/SSE2 machine instructions; cloud virtualization disclosed; bare-metal not established\nintel_comparison_dataset=NOT_MEASURED\nftz=0\ndaz=0\nexceptions=all masked\n");
}
int main(int argc,char **argv) {
    if(argc>1&&!strcmp(argv[1],"--metadata")){metadata();return 0;}
    unsigned a,b,c,d;__cpuid(1,a,b,c,d);int sse3=c&1;values();
    printf("row,group,op,cw,case,a_name,a_ext80,b_name,b_ext80,pre_sw,post_sw,post_ftw,st0,st1,st2,st3,st4,st5,st6,st7,memory_bits,memory_sw,sse64_bits,sse_mxcsr,reg_equal_sse,intel_bits,intel_amd_diff\n");
    const char *binary[]={"fadd","fsub","fmul","fdiv","fprem","fprem1","fscale"};const char *unary[]={"fsqrt","frndint","fxtract","fabs","fchs"};
    const char *tu[]={"fsin","fcos","fsincos","fptan","f2xm1"};const char *tb[]={"fpatan","fyl2x","fyl2xp1"};
    int quick=argc>1&&!strcmp(argv[1],"--quick");
    for(int pc=2;pc<=3;pc++)for(int rc=0;rc<4;rc++){
        uint16_t cw=(uint16_t)(0x7f|(pc<<8)|(rc<<10));int count=quick?26:nv;
        for(unsigned op=0;op<sizeof(binary)/sizeof(*binary);op++)for(int i=0;i<count;i++)for(int j=0;j<count;j++)operation(binary[op],cw,&v[i],&v[j],"arithmetic","cartesian");
        for(unsigned op=0;op<sizeof(unary)/sizeof(*unary);op++)for(int i=0;i<count;i++)operation(unary[op],cw,&v[i],NULL,"unary","fixed-grid");
        if(!quick){loads(cw);stores(cw,sse3);stacks(cw);seeded_flags(cw);memory_arithmetic(cw);remainder_sequences(cw);}
    }
    if(!quick)for(int pc=2;pc<=3;pc++){
        uint16_t cw=(uint16_t)(0x7f|(pc<<8));for(unsigned op=0;op<sizeof(tu)/sizeof(*tu);op++)for(int i=0;i<nv;i++)operation(tu[op],cw,&v[i],NULL,"transcendental","fixed-grid");
        for(unsigned op=0;op<sizeof(tb)/sizeof(*tb);op++)for(int i=0;i<nv;i++)for(int j=0;j<nv;j++)operation(tb[op],cw,&v[i],&v[j],"transcendental","cartesian-grid");
    }
    fprintf(stderr,"rows=%" PRIu64 " values=%d mode=%s\n",rows,nv,quick?"quick":"full");reset();return ferror(stdout)?1:0;
}
