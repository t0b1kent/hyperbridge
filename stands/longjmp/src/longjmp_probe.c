/* NEW-0095. Own-process Windows x64 synthetic context probe. See CELLS.md.
 * One translation unit, no assembler dependency. The portable modes generate
 * bytes/list cells only; they NEVER execute generated x64 instructions.
 * Windows runtime validation is NOT_RUN in this submission.
 * Build: cl /nologo /W4 /O2 /TC longjmp_probe.c
 *        x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra longjmp_probe.c -o longjmp_probe.exe
 * Do not add /guard:cf, CET enforcement, /clr, sanitizers or whole-program
 * instrumentation without revalidating generated entrypoints and continuations.
 */
#define _CRT_SECURE_NO_WARNINGS 1
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#include <malloc.h>
#include <intrin.h>
#include <io.h>
#include <fcntl.h>
#include <wchar.h>
#if !defined(_M_X64) && !defined(__x86_64__)
#error Build an x64 executable; run that same executable under x64 emulation on ARM.
#endif
#endif
#ifdef _MSC_VER
#define ALIGNED(n) __declspec(align(n))
#define NOINLINE __declspec(noinline)
#else
#define ALIGNED(n) __attribute__((aligned(n)))
#define NOINLINE __attribute__((noinline))
#endif
#define STATIC_ASSERT(x,n) typedef char static_assert_##n[(x)?1:-1]
#define BASE_ID 950000
#define NF 10
#define ND 4
#define NM 9
#define NP 3
#define NOBS (NF*ND*NM*NP)
#define NSTRESS (NF*2)
#define NCELLS (NOBS+NSTRESS+NF)
#define MAXBLOCKS 20
#define CODE_LIMIT 3072u
#define XDATA_OFFSET 3072u
#define RF_OFFSET 3328u
#define ALLOCATION_SIZE 4096u
#define STATUS_LONGJUMP_VALUE ((uint32_t)0x80000026u)
#define SYNTHETIC_EXCEPTION ((uint32_t)0xe0000095u)
#define FNV_OFFSET UINT64_C(14695981039346656037)
#define FNV_PRIME UINT64_C(1099511628211)
#define ROOT_ALLOC 0x2b8u
#define ROOT_FX 0x40u
#define ROOT_FLAGS 0x240u
#define GPR_COUNT 9
static const int depths[ND]={0,1,3,10};
static const char *flavors[NF]={"ucrt___intrinsic_setjmp_frame0","ucrt___intrinsic_setjmpex_frame","msvcrt_setjmp_frame0","msvcrt_setjmpex_frame","rtl_unwind_longjmp","rtl_restore_null","rtl_restore_longjmp","nt_continue_false","nt_continue_true","msvc_compiler_intrinsic_lowering"};
static const char *modes[NM]={"ordinary","finally","leaf_tail","dynamic_no_table","dynamic_add_table","dynamic_callback","filter","except","veh"};
static const char *profiles[NP]={"abi_clean","df_set","ac_set"};
#ifdef _WIN32
static const char *gpr_names[GPR_COUNT]={"rbx","rbp","rsi","rdi","r12","r13","r14","r15","rsp"};
#endif
static const int gpr_regs[8]={3,5,6,7,12,13,14,15};
#ifdef _WIN32
static const char *doc_abi="https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170";
static const char *doc_restore="https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlrestorecontext";
static const char *doc_unwind="https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwindex";
static const char *doc_setjmp="https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/setjmp?view=msvc-170";
static const char *doc_longjmp="https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/longjmp?view=msvc-170";

#endif

typedef struct Cell { int id,flavor,depth,mode,profile,kind; } Cell;
/* FXSAVE64 layout, not a CONTEXT alias. st[] is logical ST(0)..ST(7);
 * ftw is the abridged PHYSICAL-register tag bitmap. */
typedef struct ALIGNED(16) Fx {
    uint16_t fcw,fsw; uint8_t ftw,reserved1; uint16_t fop;
    uint64_t fip,fdp; uint32_t mxcsr,mxcsr_mask;
    uint8_t st[8][16],xmm[16][16],reserved2[96];
} Fx;
typedef struct ALIGNED(64) Snapshot {
    uint64_t gpr[GPR_COUNT],rflags;
    Fx fx;
    ALIGNED(32) uint8_t ymm[16][32];
    ALIGNED(16) uint8_t fenv[32]; /* FNSTENV writes 28, last four stay zero. */
    uint64_t return_rax;
} Snapshot;
typedef struct ALIGNED(64) Pattern {
    Fx fx; ALIGNED(32) uint8_t ymm[16][32]; uint64_t flags;
} Pattern;
typedef struct ALIGNED(16) JumpBuffer {
    uint64_t Frame,Rbx,Rsp,Rbp,Rsi,Rdi,R12,R13,R14,R15,Rip;
    uint32_t MxCsr; uint16_t FpCsr,Spare; uint8_t Xmm[10][16];
} JumpBuffer;
typedef struct ALIGNED(64) Probe {
    Snapshot seed,changed,post;
    Pattern pattern[3];
    JumpBuffer jump,jump_input;
    ALIGNED(16) uint8_t context[1232],context_input[1232],unwind_context[1232];
    ALIGNED(16) uint8_t record[160];
    uint64_t private_called;
    uint32_t phase,unexpected_return;
} Probe;
typedef struct RuntimeFunction { uint32_t BeginAddress,EndAddress,UnwindData; } RuntimeFunction;
STATIC_ASSERT(sizeof(Fx)==512,fx_size);
STATIC_ASSERT(offsetof(Fx,xmm)==160,fx_xmm_offset);
STATIC_ASSERT(sizeof(JumpBuffer)==256,jump_size);
STATIC_ASSERT(offsetof(JumpBuffer,Xmm)==96,jump_xmm_offset);
STATIC_ASSERT(offsetof(Snapshot,fx)%16==0,snapshot_fx_alignment);
STATIC_ASSERT(offsetof(Snapshot,ymm)%32==0,snapshot_ymm_alignment);
STATIC_ASSERT(offsetof(Snapshot,fenv)%16==0,snapshot_fenv_alignment);
#ifdef _WIN32
STATIC_ASSERT(sizeof(CONTEXT)==1232,windows_context_size);
STATIC_ASSERT(sizeof(EXCEPTION_RECORD)<=160,windows_exception_size);
STATIC_ASSERT(sizeof(RUNTIME_FUNCTION)==sizeof(RuntimeFunction),runtime_function_size);
#endif

typedef struct Buffer { uint8_t *p; size_t n; int bad; } Buffer;
typedef struct Block {
    uint8_t *mem; uint64_t address; size_t code_size,xdata_size;
    int registration,leaf; /* 0 intentionally none, 1 add, 2 callback */
    int installed;
} Block;
typedef struct Program {
    Probe *p; uint64_t paddr,called_addr;
    uint64_t capture,transition,rtl_capture,wrapper,wrapper_arg;
    int avx,portable; Cell cell;
    Block blocks[MAXBLOCKS]; int count; int error;
    uint64_t entry,endpoint;
#ifdef _WIN32
    volatile LONG callback_lookups;
#endif
} Program;
static uint64_t fnv(uint64_t h,const void *data,size_t n) {
    const uint8_t *p=(const uint8_t *)data; while(n--) { h^=*p++; h*=FNV_PRIME; } return h;
}
static int decode(int id,Cell *c) {
    int x=id-BASE_ID;
    if(x<0 || x>=NCELLS) return 0;
    memset(c,0,sizeof(*c)); c->id=id;
    if(x<NOBS) { c->profile=x%NP; x/=NP; c->mode=x%NM; x/=NM; c->depth=depths[x%ND]; x/=ND; c->flavor=x; }
    else if(x<NOBS+NSTRESS) { x-=NOBS; c->kind=1+(x%2); c->flavor=x/2; }
    else { c->kind=3; c->flavor=x-NOBS-NSTRESS; }
    return 1;
}
static const char *family(const Cell *c) { return c->kind==1?"stress_1m":c->kind==2?"stress_8x250k":c->kind==3?"timing":"context"; }
#ifdef _WIN32
static void axes(const Cell *c) {
    printf("\"axes\":{\"transition\":\"%s\",\"depth\":%d,\"frame\":\"%s\",\"flags\":\"%s\",\"mode\":\"%s\",\"has_documented_nonvolatile_contract\":%s,\"field_scope\":\"GPR_nonvolatiles_XMM6_15_MXCSR_control_only; other_state_empirical\",\"sources\":[\"%s\",\"%s\",\"%s\"]}",
        flavors[c->flavor],c->depth,modes[c->mode],profiles[c->profile],family(c),
        (c->mode>=6 || c->profile || c->mode==3 || c->flavor>=7 || c->flavor==0 || c->flavor==2)?"false":"true",doc_abi,
        c->flavor==4?doc_unwind:c->flavor>=5?doc_restore:doc_setjmp,doc_longjmp);
}
static void prefix(const Cell *c) { printf("CELL %d %s => {",c->id,family(c)); axes(c); }
static void simple(const Cell *c,const char *status,const char *reason) {
    prefix(c); printf(",\"status\":\"%s\",\"reason\":\"%s\",\"raw\":{},\"norm\":{}}\n",status,reason);
}
#endif
static const char *unsupported(const Cell *c) {
    if(c->flavor==9) return "compiler_intrinsic_lowering_not_instrumented; export__setjmpex_is_not_claimed_equivalent";
#if !defined(_MSC_VER) || !defined(_WIN32)
    if(c->mode==1 || c->mode==6 || c->mode==7) return "true___try___finally_filter_except_requires_MSVC_x64; no_portability_macro_substitute";
#endif
    if(c->profile && (c->mode==1 || c->mode==5 || c->mode>=6)) return "dirty_DF_AC_would_enter_C_handler_or_callback_before_landing_cleanup";
    return NULL;
}
static void b8(Buffer *b,unsigned x) { if(b->n<CODE_LIMIT) b->p[b->n++]=(uint8_t)x; else b->bad=1; }
static void b32(Buffer *b,uint32_t x) { int i; for(i=0;i<4;i++) b8(b,x>>(i*8)); }
static void b64(Buffer *b,uint64_t x) { int i; for(i=0;i<8;i++) b8(b,(unsigned)(x>>(i*8))); }
static void patch32(Buffer *b,size_t at,uint32_t x) { int i; if(at+4>b->n) { b->bad=1; return; } for(i=0;i<4;i++) b->p[at+i]=(uint8_t)(x>>(i*8)); }
static void movabs_(Buffer *b,int reg,uint64_t value) { b8(b,0x48u|(reg>=8?1u:0u)); b8(b,0xb8u+(unsigned)(reg&7)); b64(b,value); }
static void store11(Buffer *b,int reg,uint32_t disp) { b8(b,0x49u|(reg>=8?4u:0u)); b8(b,0x89); b8(b,0x83u|((unsigned)(reg&7)<<3)); b32(b,disp); }
static void load11(Buffer *b,int reg,uint32_t disp) { b8(b,0x49u|(reg>=8?4u:0u)); b8(b,0x8b); b8(b,0x83u|((unsigned)(reg&7)<<3)); b32(b,disp); }
static void store32_11(Buffer *b,uint32_t disp,uint32_t value) { b8(b,0x41); b8(b,0xc7); b8(b,0x83); b32(b,disp); b32(b,value); }
static void fx11(Buffer *b,int restore,uint32_t disp) { b8(b,0x49); b8(b,0x0f); b8(b,0xae); b8(b,restore?0x8b:0x83); b32(b,disp); }
static void fxrsp(Buffer *b,int restore,uint32_t disp) { b8(b,0x48); b8(b,0x0f); b8(b,0xae); b8(b,restore?0x8c:0x84); b8(b,0x24); b32(b,disp); }
static void ymm11(Buffer *b,int store,int reg,uint32_t disp) { b8(b,0xc4); b8(b,reg<8?0xc1:0x41); b8(b,0x7e); b8(b,store?0x7f:0x6f); b8(b,0x83u|((unsigned)(reg&7)<<3)); b32(b,disp); }
static void callabs(Buffer *b,uint64_t target) { movabs_(b,0,target); b8(b,0xff); b8(b,0xd0); }
static void pushreg(Buffer *b,int r) { if(r>=8)b8(b,0x41); b8(b,0x50u+(unsigned)(r&7)); }
static void popreg(Buffer *b,int r) { if(r>=8)b8(b,0x41); b8(b,0x58u+(unsigned)(r&7)); }
static void subrsp(Buffer *b,uint32_t n) { b8(b,0x48); b8(b,0x81); b8(b,0xec); b32(b,n); }
static void addrsp(Buffer *b,uint32_t n) { b8(b,0x48); b8(b,0x81); b8(b,0xc4); b32(b,n); }
static void clean_flags(Buffer *b) {
    /* Capture is complete before this: clear DF and AC on the stack, no API. */
    b8(b,0x9c); b8(b,0x48); b8(b,0x81); b8(b,0x24); b8(b,0x24); b32(b,~(uint32_t)0x40400); b8(b,0x9d);
}
static void snapshot(Program *p,Buffer *b,size_t off) {
    int i; movabs_(b,11,p->paddr+off);
    /* MOV/PUSH/POP below do not destroy RFLAGS. Save RAX before using it. */
    store11(b,0,(uint32_t)offsetof(Snapshot,return_rax));
    for(i=0;i<8;i++) store11(b,gpr_regs[i],(uint32_t)(offsetof(Snapshot,gpr)+8u*(unsigned)i));
    store11(b,4,(uint32_t)(offsetof(Snapshot,gpr)+64));
    b8(b,0x9c); b8(b,0x58); store11(b,0,(uint32_t)offsetof(Snapshot,rflags));
    fx11(b,0,(uint32_t)offsetof(Snapshot,fx));
    if(p->avx) for(i=0;i<16;i++) ymm11(b,1,i,(uint32_t)(offsetof(Snapshot,ymm)+32u*(unsigned)i));
    /* Full 2-bit x87 tags, FSW and CW. FNSTENV temporarily masks exceptions;
     * FLDENV immediately restores exactly the just-saved environment. */
    b8(b,0x41); b8(b,0xd9); b8(b,0xb3); b32(b,(uint32_t)offsetof(Snapshot,fenv));
    b8(b,0x41); b8(b,0xd9); b8(b,0xa3); b32(b,(uint32_t)offsetof(Snapshot,fenv));
}
static uint64_t gpr_pattern(int which,int reg_index) { return UINT64_C(0x1111000000000000)*(uint64_t)(which+1)+UINT64_C(0x01020304050600)+(uint64_t)(reg_index+1); }
static void seed(Program *p,Buffer *b,int which) {
    int i; movabs_(b,11,p->paddr+offsetof(Probe,pattern)+sizeof(Pattern)*(size_t)which);
    fx11(b,1,(uint32_t)offsetof(Pattern,fx));
    if(p->avx) for(i=0;i<16;i++) ymm11(b,0,i,(uint32_t)(offsetof(Pattern,ymm)+32u*(unsigned)i));
    for(i=0;i<8;i++) movabs_(b,gpr_regs[i],gpr_pattern(which,i));
    /* PUSH qword [r11+disp32]; POPFQ. Setting flags is the last seed action. */
    b8(b,0x41); b8(b,0xff); b8(b,0xb3); b32(b,(uint32_t)offsetof(Pattern,flags)); b8(b,0x9d);
}
static void init_patterns(Probe *p,uint32_t mxmask,int profile) {
    static const uint32_t mx[3]={0x3f81,0xdfe4,0x7f92};
    static const uint16_t cw[3]={0x077f,0x0b7f,0x0f7f};
    static const uint16_t sw[3]={0x0101,(3u<<11)|0x0020,(5u<<11)|0x4004};
    static const uint8_t ftw[3]={0x03,0xf8,0xff};
    int k,i,j;
    for(k=0;k<3;k++) {
        Pattern *s=&p->pattern[k]; memset(s,0,sizeof(*s));
        s->fx.fcw=cw[k]; s->fx.fsw=sw[k]; s->fx.ftw=ftw[k]; s->fx.mxcsr=mx[k]&mxmask; s->fx.mxcsr_mask=mxmask;
        for(i=0;i<8;i++) { uint64_t mant=UINT64_C(0x8000000000000000)|((uint64_t)(i+1)<<40); uint16_t exp=(uint16_t)(0x3fff+k); memcpy(s->fx.st[i],&mant,8); memcpy(s->fx.st[i]+8,&exp,2); }
        for(i=0;i<16;i++) for(j=0;j<32;j++) s->ymm[i][j]=(uint8_t)(0x21+61*k+7*i+j);
        for(i=0;i<16;i++) memcpy(s->fx.xmm[i],s->ymm[i],16);
        s->flags=k==1?UINT64_C(0xa92):UINT64_C(0x247);
    }
    if(profile==1) p->pattern[1].flags|=0x400;
    if(profile==2) p->pattern[1].flags|=0x40000;
}
static void copy_record(Program *p,Buffer *b,size_t from,size_t to,unsigned size) {
    /* Before the changed-state seed; REP MOVSQ cannot contaminate it. */
    movabs_(b,6,p->paddr+from); movabs_(b,7,p->paddr+to);
    b8(b,0xb9); b32(b,size/8); b8(b,0xfc); b8(b,0xf3); b8(b,0x48); b8(b,0xa5);
}
static void changed_state(Program *p,Buffer *b) {
    movabs_(b,11,p->called_addr);
    /* Single-writer, flags-neutral increment also keeps the true leaf leaf-like. */
    b8(b,0x49); b8(b,0x8b); b8(b,0x03); /* mov rax,[r11] */
    b8(b,0x48); b8(b,0x8d); b8(b,0x40); b8(b,1); /* lea rax,[rax+1] */
    b8(b,0x49); b8(b,0x89); b8(b,0x03); /* mov [r11],rax */
    seed(p,b,1);
    snapshot(p,b,offsetof(Probe,changed));
}
static void transfer(Program *p,Buffer *b,int tail) {
    int f=p->cell.flavor;
    if(!tail) changed_state(p,b);
    if(f<4) {
        movabs_(b,1,p->paddr+offsetof(Probe,jump)); movabs_(b,2,7);
    } else if(f==4) {
        movabs_(b,11,p->paddr+offsetof(Probe,jump)); load11(b,1,(uint32_t)offsetof(JumpBuffer,Frame)); load11(b,2,(uint32_t)offsetof(JumpBuffer,Rip));
        movabs_(b,8,p->paddr+offsetof(Probe,record)); movabs_(b,9,7);
        movabs_(b,0,p->paddr+offsetof(Probe,unwind_context));
        /* Stack arguments are at caller rsp+32/+40; tail-jump's return address adds 8. */
        b8(b,0x48); b8(b,0x89); b8(b,0x44); b8(b,0x24); b8(b,tail?0x28:0x20);
        b8(b,0x48); b8(b,0xc7); b8(b,0x44); b8(b,0x24); b8(b,tail?0x30:0x28); b32(b,0);
    } else {
        movabs_(b,1,p->paddr+offsetof(Probe,context));
        movabs_(b,2,f==6?p->paddr+offsetof(Probe,record):(f==8?1:0));
    }
    movabs_(b,0,p->transition); b8(b,0xff); b8(b,tail?0xe0:0xd0);
    if(!tail) {
        movabs_(b,11,p->paddr); store32_11(b,(uint32_t)offsetof(Probe,unexpected_return),1);
        clean_flags(b); b8(b,0x0f); b8(b,0x0b); /* Never turn an API return into success. */
    }
}
static void write16(uint8_t *p,unsigned x) { p[0]=(uint8_t)x; p[1]=(uint8_t)(x>>8); }
static void make_unwind(Block *q,int root) {
    uint8_t *u=q->mem+XDATA_OFFSET; unsigned k=4; int i;
    memset(u,0,128); u[0]=1;
    if(root) {
        /* PUSHES (12 bytes), SUB rsp,imm32 (7), FXSAVE64 [rsp+disp32] (9).
         * Describe ten XMM nonvolatiles in the FXSAVE image, then allocation/pushes. */
        static const uint8_t end[8]={1,2,3,4,6,8,10,12};
        u[1]=28; u[2]=30;
        for(i=15;i>=6;i--) { u[k++]=28; u[k++]=(uint8_t)((i<<4)|8); write16(u+k,(ROOT_FX+160u+16u*(unsigned)i)/16u); k+=2; }
        u[k++]=19; u[k++]=1; write16(u+k,ROOT_ALLOC/8u); k+=2;
        for(i=7;i>=0;i--) { u[k++]=end[i]; u[k++]=(uint8_t)(gpr_regs[i]<<4); }
    } else { u[1]=7; u[2]=1; u[k++]=7; u[k++]=0x62; k+=2; } /* SUB rsp,56 */
    q->xdata_size=k;
    { RuntimeFunction rf; rf.BeginAddress=0; rf.EndAddress=(uint32_t)q->code_size; rf.UnwindData=XDATA_OFFSET; memcpy(q->mem+RF_OFFSET,&rf,sizeof(rf)); }
}
static Block *new_block(Program *p,int registration,int leaf) {
    Block *q;
    if(p->count>=MAXBLOCKS) { p->error=1; return NULL; }
    q=&p->blocks[p->count]; memset(q,0,sizeof(*q)); q->registration=registration; q->leaf=leaf;
#ifdef _WIN32
    if(!p->portable) q->mem=(uint8_t *)VirtualAlloc(NULL,ALLOCATION_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    else
#endif
    q->mem=(uint8_t *)calloc(1,ALLOCATION_SIZE);
    if(!q->mem) { p->error=1; return NULL; }
    q->address=p->portable?(UINT64_C(0x180000000)+(uint64_t)p->count*0x1000u):(uint64_t)(uintptr_t)q->mem;
    p->count++; return q;
}
static void finish_block(Program *p,Block *q,Buffer *b,int root) { q->code_size=b->n; if(b->bad) p->error=1; if(!q->leaf) make_unwind(q,root); }
static uint64_t build_frame(Program *p,uint64_t next,int reg,int leaf,int leaf_caller) {
    Block *q=new_block(p,reg,leaf); Buffer b;
    if(!q) return 0;
    b.p=q->mem; b.n=0; b.bad=0;
    if(!leaf) { int i;for(i=0;i<8;i++)pushreg(&b,gpr_regs[i]);subrsp(&b,ROOT_ALLOC);fxrsp(&b,0,ROOT_FX); }
    if(leaf) transfer(p,&b,1);
    else if(next) { if(leaf_caller)changed_state(p,&b); callabs(&b,next); b8(&b,0x0f); b8(&b,0x0b); }
    else transfer(p,&b,0);
    /* Reachable only if the experiment is changed later. A conventional epilog
     * is retained for unambiguous unwinder/disassembly boundaries. */
    if(!leaf) { int i;fxrsp(&b,1,ROOT_FX);addrsp(&b,ROOT_ALLOC);for(i=7;i>=0;i--)popreg(&b,gpr_regs[i]);b8(&b,0xc3); }
    finish_block(p,q,&b,1); return q->address;
}
static int generate(Program *p) {
    Block *root; Buffer b; uint64_t next=0; int i,m=p->cell.mode; size_t jne;
    /* Endpoint first for C handler wrappers. It has valid own unwind metadata. */
    if(m==1 || m>=6) p->endpoint=build_frame(p,0,1,0,0);
    else if(m==2) next=build_frame(p,0,0,1,0);
    else if(m>=3 && m<=5) next=build_frame(p,0,m==3?0:m==4?1:2,0,0);
    for(i=0;i<p->cell.depth && !(m==1 || m>=6);i++) {
        int seed_leaf=(m==2 && i==0);
        next=build_frame(p,next,1,0,seed_leaf);
    }
    root=new_block(p,1,0); if(!root)return 0; p->entry=root->address; b.p=root->mem; b.n=0; b.bad=0;
    for(i=0;i<8;i++)pushreg(&b,gpr_regs[i]);
    subrsp(&b,ROOT_ALLOC); fxrsp(&b,0,ROOT_FX);
    b8(&b,0x9c); b8(&b,0x58); /* Save original flags in a reserved local. */
    b8(&b,0x48); b8(&b,0x89); b8(&b,0x84); b8(&b,0x24); b32(&b,ROOT_FLAGS);
    seed(p,&b,0); snapshot(p,&b,offsetof(Probe,seed));
    if(p->cell.flavor<=4 || p->cell.flavor==6) {
        movabs_(&b,1,p->paddr+offsetof(Probe,jump));
        if(p->cell.flavor==0 || p->cell.flavor==2) movabs_(&b,2,0);
        else { b8(&b,0x48); b8(&b,0x89); b8(&b,0xe2); } /* mov rdx,rsp = actual establisher frame */
    } else movabs_(&b,1,p->paddr+offsetof(Probe,context));
    callabs(&b,p->capture);
    /* This exact address is the saved continuation. No TEST, API, C prologue,
     * ADD, counter increment or compiler code intervenes before snapshot. */
    snapshot(p,&b,offsetof(Probe,post)); clean_flags(&b);
    movabs_(&b,11,p->paddr); b8(&b,0x41); b8(&b,0x83); b8(&b,0xbb); b32(&b,(uint32_t)offsetof(Probe,phase)); b8(&b,0);
    b8(&b,0x0f); b8(&b,0x85); jne=b.n; b32(&b,0);
    store32_11(&b,(uint32_t)offsetof(Probe,phase),1);
    if(p->cell.flavor<=4 || p->cell.flavor==6) copy_record(p,&b,offsetof(Probe,jump),offsetof(Probe,jump_input),sizeof(JumpBuffer));
    if(p->cell.flavor==6) { seed(p,&b,2); movabs_(&b,1,p->paddr+offsetof(Probe,context)); callabs(&b,p->rtl_capture); }
    if(p->cell.flavor>=5 && p->cell.flavor<=8) copy_record(p,&b,offsetof(Probe,context),offsetof(Probe,context_input),1232);
    if(m==1 || m>=6) {
        movabs_(&b,1,p->wrapper_arg); callabs(&b,p->wrapper); b8(&b,0x0f); b8(&b,0x0b);
    } else if(next) {
        if(m==2 && p->cell.depth==0)changed_state(p,&b);
        callabs(&b,next); b8(&b,0x0f); b8(&b,0x0b);
    } else transfer(p,&b,0);
    patch32(&b,jne,(uint32_t)(b.n-(jne+4)));
    fxrsp(&b,1,ROOT_FX);
    b8(&b,0x48); b8(&b,0x8b); b8(&b,0x84); b8(&b,0x24); b32(&b,ROOT_FLAGS); b8(&b,0x50); b8(&b,0x9d);
    addrsp(&b,ROOT_ALLOC); for(i=7;i>=0;i--)popreg(&b,gpr_regs[i]); b8(&b,0xc3);
    finish_block(p,root,&b,1); return !p->error;
}
static void destroy_program(Program *p) {
    int i; for(i=0;i<p->count;i++) { Block *q=&p->blocks[i];
#ifdef _WIN32
        if(!p->portable) {
            if(q->installed) RtlDeleteFunctionTable(q->registration==2?(PRUNTIME_FUNCTION)(uintptr_t)(q->address|3u):(PRUNTIME_FUNCTION)(void *)(q->mem+RF_OFFSET));
            VirtualFree(q->mem,0,MEM_RELEASE); continue;
        }
#endif
        free(q->mem);
    } p->count=0;
}
static int portable_emit(const Cell *c,const char *dir) {
    Program p; int i; char path[2048]; FILE *f;
    memset(&p,0,sizeof(p)); p.portable=1; p.avx=1; p.cell=*c; p.paddr=UINT64_C(0x12340000000); p.called_addr=UINT64_C(0x12350000000);
    p.capture=UINT64_C(0x7ff000001000); p.transition=UINT64_C(0x7ff000002000); p.rtl_capture=UINT64_C(0x7ff000003000); p.wrapper=UINT64_C(0x7ff000004000); p.wrapper_arg=UINT64_C(0x12360000000);
    if(!generate(&p)) { destroy_program(&p); return 2; }
    snprintf(path,sizeof(path),"%s/manifest.txt",dir); f=fopen(path,"wb"); if(!f){perror(path);destroy_program(&p);return 2;}
    fprintf(f,"Portable byte emission ONLY; never executed. Cell %d. Synthetic fixed addresses.\nentry=%016" PRIx64 " endpoint=%016" PRIx64 " blocks=%d\n",c->id,p.entry,p.endpoint,p.count);
    for(i=0;i<p.count;i++) {
        Block *q=&p.blocks[i]; FILE *out;
        snprintf(path,sizeof(path),"%s/block-%02d.bin",dir,i); out=fopen(path,"wb"); if(!out){fclose(f);destroy_program(&p);return 2;}
        if(fwrite(q->mem,1,q->code_size,out)!=q->code_size){fclose(out);fclose(f);destroy_program(&p);return 2;} fclose(out);
        snprintf(path,sizeof(path),"%s/block-%02d.unwind.bin",dir,i); out=fopen(path,"wb"); if(!out){fclose(f);destroy_program(&p);return 2;}
        fwrite(q->mem+XDATA_OFFSET,1,q->xdata_size,out); fclose(out);
        fprintf(f,"block=%d base=%016" PRIx64 " code=%zu unwind=%zu registration=%d leaf=%d\n",i,q->address,q->code_size,q->xdata_size,q->registration,q->leaf);
    }
    fclose(f); destroy_program(&p); return 0;
}
static int selftest(void) {
    Cell c; int id,generated=0; uint64_t hash=FNV_OFFSET;
    void *pattern_allocation=calloc(1,sizeof(Probe)+63);
    Probe *pattern_test=(Probe *)(((uintptr_t)pattern_allocation+63)&~(uintptr_t)63);
    if(!pattern_allocation)return 2;
    init_patterns(pattern_test,0xffbf,2);
    if(pattern_test->pattern[1].fx.mxcsr&~0xffbfU || !(pattern_test->pattern[1].flags&0x40000))return 2;
    free(pattern_allocation);
    if(fnv(FNV_OFFSET,"hello",5)!=UINT64_C(0xa430d84680aabd0b))return 2;
    for(id=BASE_ID;id<BASE_ID+NCELLS;id++) {
        Program p; int i;
        if(!decode(id,&c))return 2;
        (void)unsupported(&c);
        memset(&p,0,sizeof(p)); p.portable=1; p.avx=id&1; p.cell=c; p.paddr=UINT64_C(0x12340000000); p.called_addr=p.paddr+offsetof(Probe,private_called);
        p.capture=UINT64_C(0x7ff000001000);p.transition=UINT64_C(0x7ff000002000);p.rtl_capture=UINT64_C(0x7ff000003000);p.wrapper=UINT64_C(0x7ff000004000);p.wrapper_arg=p.paddr;
        if(!generate(&p))return 2;
        for(i=0;i<p.count;i++) {
            Block *q=&p.blocks[i]; RuntimeFunction rf;
            if(!q->code_size || q->code_size>CODE_LIMIT)return 2;
            memcpy(&rf,q->mem+RF_OFFSET,sizeof(rf));
            if(!q->leaf && (rf.EndAddress!=q->code_size || rf.UnwindData!=XDATA_OFFSET))return 2;
            hash=fnv(hash,q->mem,q->code_size); generated++;
        }
        destroy_program(&p);
    }
    printf("SELFTEST portable_only=1 executed_machine_code=0 cells=%d generated_blocks=%d fnv1a64=%016" PRIx64 " PASS\n",NCELLS,generated,hash);return 0;
}
#ifdef _WIN32
/* No functions below are entered until dirty flags have been cleared by the
 * landing code, except the exact API under test (out-of-contract DF/AC cells). */
typedef struct ALIGNED(64) Counter {
    volatile LONG64 called,completed;
    uint64_t checksum;
    volatile LONG finished,error;
    uint8_t padding[32];
} Counter;
typedef struct Shared { Counter thread[8]; } Shared;
typedef struct Host {
    HMODULE crt[2],ntdll;
    uint64_t setjmp0[2],setjmpex[2],longjmp_[2];
    uint64_t capture,restore,unwind,ntcontinue;
    uint32_t mxmask; int avx; uint32_t cpuid1_ecx; uint64_t xcr0;
    char crtpath[2][MAX_PATH];
} Host;
typedef struct Run {
    Probe *p; Program program; Cell cell; Host *host; Counter *counter;
    uint64_t iterations; uint64_t checksum;
    volatile LONG finally_count; int finally_order[32];
    volatile LONG veh_count,filter_count,except_count;
    int error; char reason[256]; HANDLE start_gate;
} Run;
static DWORD tls_slot=TLS_OUT_OF_INDEXES;
static void hexbytes(const void *ptr,size_t n) { const uint8_t *p=(const uint8_t *)ptr; putchar('"'); while(n--)printf("%02x",*p++);putchar('"'); }
static void json_string(const char *s) { const unsigned char *p=(const unsigned char *)s; putchar('"'); for(;*p;p++){if(*p=='"'||*p=='\\'){putchar('\\');putchar(*p);}else if(*p<32)printf("\\u%04x",*p);else putchar(*p);}putchar('"'); }
static void cpuid1(uint32_t *ecx) {
#ifdef _MSC_VER
    int v[4]; __cpuid(v,1); *ecx=(uint32_t)v[2];
#else
    unsigned a,b,c,d; __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(1),"c"(0)); *ecx=c;
#endif
}
static uint64_t read_xcr0(void) {
#ifdef _MSC_VER
    return _xgetbv(0);
#else
    unsigned a,d; __asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0)); return ((uint64_t)d<<32)|a;
#endif
}
static HMODULE system_module(const wchar_t *dll) {
    wchar_t path[MAX_PATH]; UINT n=GetSystemDirectoryW(path,MAX_PATH); size_t len=wcslen(dll);
    if(!n || n>=MAX_PATH || n+1+len>=MAX_PATH)return NULL;
    path[n++]=L'\\';memcpy(path+n,dll,(len+1)*sizeof(wchar_t));return LoadLibraryW(path);
}
static uint64_t symbol(HMODULE m,const char *name) { return m?(uint64_t)(uintptr_t)GetProcAddress(m,name):0; }
static int init_host(Host *h) {
    Fx *fx; int i; memset(h,0,sizeof(*h));
    h->ntdll=GetModuleHandleW(L"ntdll.dll");h->crt[0]=system_module(L"ucrtbase.dll");h->crt[1]=system_module(L"msvcrt.dll");
    for(i=0;i<2;i++) { h->setjmp0[i]=symbol(h->crt[i],i?"_setjmp":"__intrinsic_setjmp");h->setjmpex[i]=symbol(h->crt[i],i?"_setjmpex":"__intrinsic_setjmpex");h->longjmp_[i]=symbol(h->crt[i],"longjmp");if(h->crt[i])GetModuleFileNameA(h->crt[i],h->crtpath[i],MAX_PATH); }
    h->capture=symbol(h->ntdll,"RtlCaptureContext");h->restore=symbol(h->ntdll,"RtlRestoreContext");h->unwind=symbol(h->ntdll,"RtlUnwindEx");h->ntcontinue=symbol(h->ntdll,"NtContinue");
    cpuid1(&h->cpuid1_ecx);
    if((h->cpuid1_ecx&(1u<<27)) && (h->cpuid1_ecx&(1u<<26)))h->xcr0=read_xcr0();
    h->avx=((h->cpuid1_ecx&(1u<<28)) && (h->cpuid1_ecx&(1u<<27)) && ((h->xcr0&6)==6))?1:0;
    fx=(Fx *)_aligned_malloc(sizeof(*fx),16);if(!fx)return 0;memset(fx,0,sizeof(*fx));
#ifdef _MSC_VER
    _fxsave64(fx);
#else
    __asm__ volatile("fxsave64 %0":"=m"(*fx));
#endif
    h->mxmask=fx->mxcsr_mask?fx->mxcsr_mask:0xffbf;_aligned_free(fx);return 1;
}
static void host_meta(const Host *h) {
    SYSTEM_INFO si; typedef LONG (WINAPI *VersionFn)(OSVERSIONINFOW *); OSVERSIONINFOW v; VersionFn ver;
    GetNativeSystemInfo(&si);memset(&v,0,sizeof(v));v.dwOSVersionInfoSize=sizeof(v);ver=(VersionFn)(uintptr_t)symbol(h->ntdll,"RtlGetVersion");if(ver)ver(&v);
    printf("META {\"harness\":\"0095-single-c-v1\",\"target\":\"windows-x64\",\"compiler\":\"");
#ifdef _MSC_VER
    printf("MSVC-%d",_MSC_VER);
#else
    printf("MinGW-GCC-%s",__VERSION__);
#endif
    printf("\",\"build_date\":\"%s %s\",\"os_version\":[%lu,%lu,%lu],\"native_architecture\":%u,\"cpuid1_ecx\":\"%08x\",\"xcr0\":\"%016" PRIx64 "\",\"avx_usable\":%s,\"mxcsr_mask\":\"%08x\",\"crt\":[",__DATE__,__TIME__,(unsigned long)v.dwMajorVersion,(unsigned long)v.dwMinorVersion,(unsigned long)v.dwBuildNumber,(unsigned)si.wProcessorArchitecture,h->cpuid1_ecx,h->xcr0,h->avx?"true":"false",h->mxmask);
    { int i;for(i=0;i<2;i++){if(i)putchar(',');printf("{\"module\":\"%s\",\"path\":",i?"msvcrt.dll":"ucrtbase.dll");json_string(h->crtpath[i]);printf(",\"capture_frame0_symbol\":\"%s\",\"capture_frame0_available\":%s,\"capture_frame_symbol\":\"%s\",\"capture_frame_available\":%s,\"longjmp\":%s}",i?"_setjmp":"__intrinsic_setjmp",h->setjmp0[i]?"true":"false",i?"_setjmpex":"__intrinsic_setjmpex",h->setjmpex[i]?"true":"false",h->longjmp_[i]?"true":"false");} }
    printf("],\"ntdll_exports\":{\"RtlCaptureContext\":%s,\"RtlRestoreContext\":%s,\"RtlUnwindEx\":%s,\"NtContinue\":%s},\"runtime_validation_at_submission\":\"NOT_RUN\"}\n",h->capture?"true":"false",h->restore?"true":"false",h->unwind?"true":"false",h->ntcontinue?"true":"false");
}
static PRUNTIME_FUNCTION CALLBACK function_callback(DWORD64 pc,PVOID context) {
    Program *p=(Program *)context;int i;InterlockedIncrement(&p->callback_lookups);
    for(i=0;i<p->count;i++){Block *q=&p->blocks[i];if(q->registration==2 && pc>=q->address && pc<q->address+q->code_size)return (PRUNTIME_FUNCTION)(void *)(q->mem+RF_OFFSET);}return NULL;
}
static int install_program(Program *p) {
    int i;for(i=0;i<p->count;i++) {
        Block *q=&p->blocks[i];DWORD old;
        if(!VirtualProtect(q->mem,ALLOCATION_SIZE,PAGE_EXECUTE_READ,&old))return 0;
        if(!FlushInstructionCache(GetCurrentProcess(),q->mem,ALLOCATION_SIZE))return 0;
        if(q->leaf || !q->registration)continue;
        if(q->registration==1) {
            if(!RtlAddFunctionTable((PRUNTIME_FUNCTION)(void *)(q->mem+RF_OFFSET),1,q->address))return 0;
        } else if(!RtlInstallFunctionTableCallback(q->address|3u,q->address,ALLOCATION_SIZE,function_callback,p,NULL))return 0;
        q->installed=1;
    }return 1;
}
static NOINLINE void endpoint(Run *r) { ((void (*)(void))(uintptr_t)r->program.endpoint)();r->error=1; }
#ifdef _MSC_VER
static NOINLINE void finally_frame(Run *r,int n) {
    __try { if(n>0)finally_frame(r,n-1);else endpoint(r); }
    __finally { LONG i=InterlockedIncrement(&r->finally_count)-1;if(i<32)r->finally_order[i]=n; }
}
static int exception_filter(Run *r,EXCEPTION_POINTERS *ep) {
    if(ep->ExceptionRecord->ExceptionCode!=SYNTHETIC_EXCEPTION)return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&r->filter_count);
    if(r->cell.mode==6)endpoint(r);
    return EXCEPTION_EXECUTE_HANDLER;
}
static NOINLINE void seh_origin(Run *r) {
    __try { RaiseException(SYNTHETIC_EXCEPTION,0,0,NULL); }
    __except(exception_filter(r,GetExceptionInformation())) { InterlockedIncrement(&r->except_count);endpoint(r); }
}
#endif
static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep) {
    Run *r=(Run *)TlsGetValue(tls_slot);
    if(!r || ep->ExceptionRecord->ExceptionCode!=SYNTHETIC_EXCEPTION)return EXCEPTION_CONTINUE_SEARCH;
    InterlockedIncrement(&r->veh_count);endpoint(r);return EXCEPTION_CONTINUE_SEARCH;
}
static NOINLINE void origin_chain(Run *r,int n) {
    volatile int keep=n;
    if(n>0)origin_chain(r,n-1);
    else {
#ifdef _MSC_VER
        if(r->cell.mode==6 || r->cell.mode==7)seh_origin(r);
        else
#endif
        RaiseException(SYNTHETIC_EXCEPTION,0,0,NULL);
    }
    /* Prevent sibling-call elimination: this operation is after the call. */
    if(keep==-12345)r->error=1;
}
static NOINLINE void wrapper(Run *r) {
#ifdef _MSC_VER
    if(r->cell.mode==1)finally_frame(r,r->cell.depth);
    else
#endif
    origin_chain(r,r->cell.depth);
    r->error=1;
}
static int prepare_run(Run *r,Host *h,const Cell *c,Counter *ctr,uint64_t iterations) {
    Program *p=&r->program;int f=c->flavor,crt=f>=2?1:0;const char *why=unsupported(c);
    memset(r,0,sizeof(*r));r->cell=*c;r->host=h;r->counter=ctr;r->iterations=iterations;r->checksum=FNV_OFFSET;
    if(why){snprintf(r->reason,sizeof(r->reason),"%s",why);return 0;}
    r->p=(Probe *)_aligned_malloc(sizeof(Probe),64);if(!r->p){strcpy(r->reason,"allocation_failed");return -1;}memset(r->p,0,sizeof(Probe));
    p->p=r->p;p->paddr=(uint64_t)(uintptr_t)r->p;p->called_addr=(uint64_t)(uintptr_t)&ctr->called;p->cell=*c;p->avx=h->avx;p->rtl_capture=h->capture;
    if(f<4) {
        p->capture=(f&1)?h->setjmpex[crt]:h->setjmp0[crt];p->transition=h->longjmp_[crt];
        if(!p->capture || !p->transition){snprintf(r->reason,sizeof(r->reason),"missing_export:%s:%s%s",crt?"msvcrt.dll":"ucrtbase.dll",!p->capture?((f&1)?(crt?"_setjmpex":"__intrinsic_setjmpex"):(crt?"_setjmp":"__intrinsic_setjmp")):"",!p->transition?",longjmp":"");return 0;}
    } else {
        p->capture=(f==4 || f==6)?h->setjmp0[1]:h->capture;
        p->transition=f==4?h->unwind:f<=6?h->restore:h->ntcontinue;
        if(!p->capture){strcpy(r->reason,(f==4||f==6)?"missing_export:msvcrt.dll:_setjmp_auxiliary_buffer_capture":"missing_export:ntdll.dll:RtlCaptureContext");return 0;}
        if(!p->transition){snprintf(r->reason,sizeof(r->reason),"missing_export:ntdll.dll:%s",f==4?"RtlUnwindEx":f<=6?"RtlRestoreContext":"NtContinue");return 0;}
        if(f==6 && !h->capture){strcpy(r->reason,"missing_export:ntdll.dll:RtlCaptureContext");return 0;}
    }
    p->wrapper=(uint64_t)(uintptr_t)wrapper;p->wrapper_arg=(uint64_t)(uintptr_t)r;
    init_patterns(r->p,h->mxmask,c->profile);
    if(!generate(p) || !install_program(p)){strcpy(r->reason,"code_generation_or_unwind_registration_failed");return -1;}
    return 1;
}
static void free_run(Run *r) { destroy_program(&r->program);if(r->p)_aligned_free(r->p);r->p=NULL; }
static uint64_t hash_snapshot(uint64_t h,const Snapshot *s,int avx) {
    h=fnv(h,s->gpr,sizeof(s->gpr));h=fnv(h,&s->rflags,sizeof(s->rflags));h=fnv(h,&s->fx,sizeof(s->fx));h=fnv(h,s->fenv,28);
    if(avx)h=fnv(h,s->ymm,sizeof(s->ymm));
    return h;
}
static DWORD WINAPI worker(LPVOID parameter) {
    Run *r=(Run *)parameter;uint64_t i;Probe *p=r->p;EXCEPTION_RECORD *rec=(EXCEPTION_RECORD *)(void *)p->record;
    if(r->start_gate && WaitForSingleObject(r->start_gate,INFINITE)!=WAIT_OBJECT_0) { r->counter->error=1;InterlockedExchange(&r->counter->finished,1);return 1; }
    if(!TlsSetValue(tls_slot,r)) { r->counter->error=1;InterlockedExchange(&r->counter->finished,1);return 1; }
    for(i=0;i<r->iterations;i++) {
        p->phase=0;p->unexpected_return=0;
        memset(rec,0,sizeof(*rec));rec->ExceptionCode=STATUS_LONGJUMP_VALUE;rec->NumberParameters=1;rec->ExceptionInformation[0]=(ULONG_PTR)&p->jump;
        ((void (*)(void))(uintptr_t)r->program.entry)();
        if(p->phase!=1 || p->unexpected_return || r->error){r->counter->error=1;r->error=1;break;}
        /* Completion is counted ONLY after the generated saved continuation was
         * reached, its state captured, caller ABI restored, and engine returned. */
        if(r->cell.kind!=3) {
            r->checksum=hash_snapshot(r->checksum,&p->post,r->host->avx);
            r->counter->checksum=r->checksum;
        }
        InterlockedIncrement64(&r->counter->completed);
    }
    if(r->cell.kind==3 && i)r->checksum=hash_snapshot(r->checksum,&p->post,r->host->avx);
    r->counter->checksum=r->checksum;InterlockedExchange(&r->counter->finished,1);TlsSetValue(tls_slot,NULL);return 0;
}
static unsigned popcount8(unsigned v) { unsigned n=0;for(;v;v>>=1)n+=v&1;return n; }
static uint16_t env_word(const Snapshot *s,int off) { uint16_t v;memcpy(&v,s->fenv+off,2);return v; }
static void snapshot_json(const Snapshot *s,int avx) {
    int i;printf("{\"gpr\":{");for(i=0;i<GPR_COUNT;i++){if(i)putchar(',');printf("\"%s\":\"%016" PRIx64 "\"",gpr_names[i],s->gpr[i]);}
    printf("},\"rflags\":\"%016" PRIx64 "\",\"return_rax\":\"%016" PRIx64 "\",\"mxcsr\":\"%08x\",\"mxcsr_mask\":\"%08x\",\"x87_control\":\"%04x\",\"x87_status\":\"%04x\",\"x87_abridged_physical_tags\":\"%02x\",\"x87_full_physical_tags\":\"%04x\",\"x87_top\":%u,\"x87_nonempty_physical_count\":%u,\"x87_env28\":",s->rflags,s->return_rax,s->fx.mxcsr,s->fx.mxcsr_mask,s->fx.fcw,s->fx.fsw,s->fx.ftw,env_word(s,8),(s->fx.fsw>>11)&7,popcount8(s->fx.ftw));
    hexbytes(s->fenv,28);printf(",\"x87_logical_st80\":[");for(i=0;i<8;i++){if(i)putchar(',');hexbytes(s->fx.st[i],10);}printf("],\"xmm\":[");
    for(i=0;i<16;i++){if(i)putchar(',');hexbytes(s->fx.xmm[i],16);}printf("],\"ymm_upper\":");
    if(avx){putchar('[');for(i=0;i<16;i++){if(i)putchar(',');hexbytes(s->ymm[i]+16,16);}putchar(']');}else printf("null");
    printf(",\"fxsave64\":");hexbytes(&s->fx,sizeof(s->fx));putchar('}');
}
static void origin_json(const void *post,const void *jump,const void *context,const void *call,size_t n) {
    printf("{\"jump\":%s,\"context\":%s,\"call\":%s}",jump?(!memcmp(post,jump,n)?"true":"false"):"null",context?(!memcmp(post,context,n)?"true":"false"):"null",!memcmp(post,call,n)?"true":"false");
}
static void origin_mask(uint64_t post,uint64_t jump,uint64_t context,uint64_t call,uint64_t mask,int have_jump,int have_context) {
    post&=mask;jump&=mask;context&=mask;call&=mask;
    origin_json(&post,have_jump?&jump:NULL,have_context?&context:NULL,&call,8);
}
static uint16_t full_tag_from_fx(const Fx *fx) {
    unsigned phys,top=(fx->fsw>>11)&7;uint16_t tags=0;
    /* Intel FXSAVE abridged tags are physical; payload slots are logical.
     * Classify each stored 80-bit value; never call abridged FTW a full tag. */
    for(phys=0;phys<8;phys++) {
        unsigned tag=3;
        if(fx->ftw&(1u<<phys)) {
            unsigned logical=(phys+8-top)&7;uint64_t significand;uint16_t exponent;
            memcpy(&significand,fx->st[logical],8);memcpy(&exponent,fx->st[logical]+8,2);exponent&=0x7fff;
            if(!exponent && !significand)tag=1;
            else if(exponent && exponent<0x7fff && (significand>>63))tag=0;
            else tag=2;
        }
        tags|=(uint16_t)(tag<<(2*phys));
    }return tags;
}
static void norm_json(const Run *r) {
    const Probe *p=r->p;const Snapshot *a=&p->post,*b=&p->changed;const JumpBuffer *j=&p->jump_input;
    const CONTEXT *ctx=(const CONTEXT *)(const void *)p->context_input;Fx ctxfx;int f=r->cell.flavor,i;
    int have_jump=f<=4 || f==6,have_context=f>=5 && f<=8;
    uint64_t jg[9]={j->Rbx,j->Rbp,j->Rsi,j->Rdi,j->R12,j->R13,j->R14,j->R15,j->Rsp};
    uint64_t cg[9]={ctx->Rbx,ctx->Rbp,ctx->Rsi,ctx->Rdi,ctx->R12,ctx->R13,ctx->R14,ctx->R15,ctx->Rsp};
    uint16_t atag=env_word(a,8),btag=env_word(b,8),ctag;unsigned adepth,bdepth,cdepth;
    memcpy(&ctxfx,&ctx->FltSave,sizeof(ctxfx));ctag=full_tag_from_fx(&ctxfx);
    adepth=popcount8(a->fx.ftw);bdepth=popcount8(b->fx.ftw);cdepth=popcount8(ctxfx.ftw);
    printf("{\"comparison\":\"independent_byte_matches; null_means_source_field_absent; equality_is_not_causal_proof_or_an_expected_value\",\"context_full_tags\":\"derived_from_abridged_physical_FTW_and_logical_80bit_payload\",\"gpr\":{");
    for(i=0;i<GPR_COUNT;i++){if(i)putchar(',');printf("\"%s\":",gpr_names[i]);origin_json(&a->gpr[i],have_jump?&jg[i]:NULL,have_context?&cg[i]:NULL,&b->gpr[i],8);}
    printf("},\"xmm\":[");
    for(i=0;i<16;i++){if(i)putchar(',');origin_json(a->fx.xmm[i],have_jump && i>=6?j->Xmm[i-6]:NULL,have_context?ctxfx.xmm[i]:NULL,b->fx.xmm[i],16);}
    printf("],\"ymm_upper\":[");
    for(i=0;i<16;i++){if(i)putchar(',');if(r->host->avx)origin_json(a->ymm[i]+16,NULL,NULL,b->ymm[i]+16,16);else printf("\"unsupported_AVX_OSXSAVE_XCR0\"");}
    printf("],\"mxcsr_top_context\":");origin_json(&a->fx.mxcsr,have_jump?&j->MxCsr:NULL,have_context?&ctx->MxCsr:NULL,&b->fx.mxcsr,4);
    printf(",\"mxcsr_FltSave_context\":");origin_json(&a->fx.mxcsr,have_jump?&j->MxCsr:NULL,have_context?&ctxfx.mxcsr:NULL,&b->fx.mxcsr,4);
    { const char *names[5]={"rounding","exception_masks","DAZ","FZ","sticky_flags"};uint64_t masks_[5]={0x6000,0x1f80,0x40,0x8000,0x3f};
      printf(",\"mxcsr_fields_using_top_context\":{");for(i=0;i<5;i++){if(i)putchar(',');printf("\"%s\":",names[i]);origin_mask(a->fx.mxcsr,j->MxCsr,ctx->MxCsr,b->fx.mxcsr,masks_[i],have_jump,have_context);}putchar('}'); }
    printf(",\"x87_control\":");origin_json(&a->fx.fcw,have_jump?&j->FpCsr:NULL,have_context?&ctxfx.fcw:NULL,&b->fx.fcw,2);
    printf(",\"x87_status\":");origin_json(&a->fx.fsw,NULL,have_context?&ctxfx.fsw:NULL,&b->fx.fsw,2);
    printf(",\"x87_full_tags\":");origin_json(&atag,NULL,have_context?&ctag:NULL,&btag,2);
    printf(",\"x87_abridged_physical_tags\":");origin_json(&a->fx.ftw,NULL,have_context?&ctxfx.ftw:NULL,&b->fx.ftw,1);
    printf(",\"x87_TOP\":");origin_mask(a->fx.fsw,0,ctxfx.fsw,b->fx.fsw,0x3800,0,have_context);
    printf(",\"x87_nonempty_count\":");origin_json(&adepth,NULL,have_context?&cdepth:NULL,&bdepth,sizeof(adepth));
    printf(",\"x87_logical_st80\":[");for(i=0;i<8;i++){if(i)putchar(',');origin_json(a->fx.st[i],NULL,have_context?ctxfx.st[i]:NULL,b->fx.st[i],10);}putchar(']');
    printf(",\"rflags\":");origin_mask(a->rflags,0,ctx->EFlags,b->rflags,UINT64_MAX,0,have_context);
    printf(",\"DF\":");origin_mask(a->rflags,0,ctx->EFlags,b->rflags,0x400,0,have_context);
    printf(",\"AC\":");origin_mask(a->rflags,0,ctx->EFlags,b->rflags,0x40000,0,have_context);
    printf(",\"arithmetic_flags\":");origin_mask(a->rflags,0,ctx->EFlags,b->rflags,0x8d5,0,have_context);putchar('}');
}
static void counters_json(const Shared *s,int n) {
    int i;printf("[");for(i=0;i<n;i++){const Counter *c=&s->thread[i];if(i)putchar(',');printf("{\"thread\":%d,\"called\":%" PRIu64 ",\"completed\":%" PRIu64 ",\"checksum\":\"%016" PRIx64 "\",\"finished\":%ld,\"error\":%ld}",i,(uint64_t)c->called,(uint64_t)c->completed,c->checksum,(long)c->finished,(long)c->error);}putchar(']');
}
static int child(const Cell *c,Shared *shared,uint64_t timing_iterations) {
    Host h;Run runs[8];HANDLE handles[8]={0},gate=NULL;PVOID veh=NULL;int n=c->kind==2?8:1,i,prepared=0,rc=0,bad=0;uint64_t iterations=c->kind==1?1000000:c->kind==2?250000:c->kind==3?timing_iterations:1;LARGE_INTEGER begin,end,freq;const char *why=unsupported(c);
    if(why){simple(c,"unsupported",why);return 0;}
    if(!init_host(&h)){simple(c,"harness_error","host_initialization_failed");return 0;}
    memset(runs,0,sizeof(runs));tls_slot=TlsAlloc();if(tls_slot==TLS_OUT_OF_INDEXES){simple(c,"harness_error","TlsAlloc_failed");return 0;}
    for(i=0;i<n;i++){rc=prepare_run(&runs[i],&h,c,&shared->thread[i],iterations);prepared=i+1;if(rc!=1)break;}
    if(rc!=1){simple(c,rc==0?"unsupported":"harness_error",runs[i].reason);goto cleanup;}
    if(c->mode==8){veh=AddVectoredExceptionHandler(1,veh_handler);if(!veh){simple(c,"harness_error","AddVectoredExceptionHandler_failed");goto cleanup;}}
    QueryPerformanceFrequency(&freq);
    if(n>1) {
        gate=CreateEventW(NULL,TRUE,FALSE,NULL);if(!gate){simple(c,"harness_error","start_gate_creation_failed");goto cleanup;}
        for(i=0;i<n;i++){runs[i].start_gate=gate;handles[i]=CreateThread(NULL,0,worker,&runs[i],0,NULL);if(!handles[i]){simple(c,"harness_error","thread_creation_failed");/* Process exit is safer than releasing live worker memory. */fflush(stdout);ExitProcess(0);}}
        QueryPerformanceCounter(&begin);
        if(!SetEvent(gate) || WaitForMultipleObjects((DWORD)n,handles,TRUE,INFINITE)!=WAIT_OBJECT_0) { simple(c,"harness_error","worker_join_failed; process_exit_without_freeing_live_worker_memory");fflush(stdout);ExitProcess(0); }
        QueryPerformanceCounter(&end);
    } else { QueryPerformanceCounter(&begin);worker(&runs[0]);QueryPerformanceCounter(&end); }
    for(i=0;i<n;i++) if(runs[i].error || shared->thread[i].error || shared->thread[i].finished!=1 || (uint64_t)shared->thread[i].called!=iterations || (uint64_t)shared->thread[i].completed!=iterations)bad=1;
    prefix(c);printf(",\"status\":\"%s\",\"reason\":\"%s\",\"raw\":{\"requested_per_thread\":%" PRIu64 ",\"threads\":",bad?"harness_error":"observed",bad?"engine_or_completed_count_protocol_failed":"no_expected_values_asserted",iterations);counters_json(shared,n);
    printf(",\"avx_usable\":%s,\"mxcsr_mask\":\"%08x\",\"finally_count\":%ld,\"finally_order\":[",h.avx?"true":"false",h.mxmask,(long)runs[0].finally_count);
    for(i=0;i<runs[0].finally_count && i<32;i++){if(i)putchar(',');printf("%d",runs[0].finally_order[i]);}
    printf("],\"filter_count\":%ld,\"except_count\":%ld,\"veh_count\":%ld,\"callback_lookups\":%ld,\"actual_jump_buffer\":",(long)runs[0].filter_count,(long)runs[0].except_count,(long)runs[0].veh_count,(long)runs[0].program.callback_lookups);
    hexbytes(&runs[0].p->jump_input,sizeof(JumpBuffer));printf(",\"post_call_jump_buffer\":");hexbytes(&runs[0].p->jump,sizeof(JumpBuffer));printf(",\"actual_input_CONTEXT\":");hexbytes(runs[0].p->context_input,sizeof(runs[0].p->context_input));
    { const CONTEXT *ci=(const CONTEXT *)(const void *)runs[0].p->context_input;
      printf(",\"context_top_MxCsr\":\"%08lx\",\"context_FltSave_MxCsr\":\"%08lx\",\"context_flags\":\"%08lx\",\"changed_rsp_semantics\":\"caller_rsp_before_CALL; API_entry_rsp_is_minus_8; leaf_tail_does_not_change_it\",\"final_snapshot_thread\":0",(unsigned long)ci->MxCsr,(unsigned long)ci->FltSave.MxCsr,(unsigned long)ci->ContextFlags); }
    printf(",\"seed\":");snapshot_json(&runs[0].p->seed,h.avx);printf(",\"at_call\":");snapshot_json(&runs[0].p->changed,h.avx);printf(",\"after\":");snapshot_json(&runs[0].p->post,h.avx);printf("},\"norm\":");norm_json(&runs[0]);printf("}\n");
    if(c->kind==3) printf("TIMING {\"cell\":%d,\"qpc_frequency\":%" PRIu64 ",\"ticks\":%" PRIu64 ",\"completed\":%" PRIu64 ",\"checksum_mode\":\"last_snapshot_only\",\"includes\":\"capture_seed_transfer_snapshot_completion_counter_loop; setup_excluded\"}\n",c->id,(uint64_t)freq.QuadPart,(uint64_t)(end.QuadPart-begin.QuadPart),(uint64_t)shared->thread[0].completed);
cleanup:
    if(veh)RemoveVectoredExceptionHandler(veh);
    for(i=0;i<n;i++)if(handles[i])CloseHandle(handles[i]);
    if(gate)CloseHandle(gate);
    for(i=0;i<prepared;i++)free_run(&runs[i]);
    TlsFree(tls_slot);tls_slot=TLS_OUT_OF_INDEXES;return 0;
}
static void abnormal(const Cell *c,const char *status,const char *reason,DWORD code,const Shared *shared,int termination_confirmed) {
    prefix(c);printf(",\"status\":\"%s\",\"reason\":\"%s\",\"raw\":{\"exit_code\":\"%08lx\",\"termination_confirmed\":%s,\"threads\":",status,reason,(unsigned long)code,termination_confirmed?"true":"false");counters_json(shared,c->kind==2?8:1);printf("},\"norm\":{}}\n");
}
/* The parent also writes its own CELL through a small capture stream so every
 * result, including timeout/crash, contributes the identical bytes to DONE. */
static int supervise_to_file(const Cell *c,DWORD timeout,uint64_t timing_iterations) {
    wchar_t exe[32768],tmpdir[MAX_PATH],tmpfile[MAX_PATH],command[33000];
    SECURITY_ATTRIBUTES sa;HANDLE log=INVALID_HANDLE_VALUE,mapping=NULL;Shared *shared=NULL;STARTUPINFOW si;PROCESS_INFORMATION pi;DWORD wait=WAIT_FAILED,code=0,got=0;char *bytes=NULL;LARGE_INTEGER size,zero;int ok=0,killed=0;
    /* Child output is buffered in a bounded temporary file, so a large raw
     * snapshot cannot block on a full pipe while the watchdog waits. */
    memset(&sa,0,sizeof(sa));sa.nLength=sizeof(sa);sa.bInheritHandle=TRUE;
    memset(&si,0,sizeof(si));si.cb=sizeof(si);memset(&pi,0,sizeof(pi));zero.QuadPart=0;
    mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,&sa,PAGE_READWRITE,0,(DWORD)sizeof(Shared),NULL);
    if(mapping)shared=(Shared *)MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(Shared));
    if(!shared){simple(c,"harness_error","shared_counter_mapping_failed");goto out;}memset(shared,0,sizeof(*shared));
    if(!GetModuleFileNameW(NULL,exe,32768) || !GetTempPathW(MAX_PATH,tmpdir) || !GetTempFileNameW(tmpdir,L"095",0,tmpfile)){simple(c,"harness_error","watchdog_path_setup_failed");goto out;}
    log=CreateFileW(tmpfile,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,NULL);
    if(log==INVALID_HANDLE_VALUE){DeleteFileW(tmpfile);simple(c,"harness_error","watchdog_output_file_failed");goto out;}
    si.dwFlags=STARTF_USESTDHANDLES;si.hStdOutput=log;si.hStdError=log;si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    _snwprintf(command,sizeof(command)/sizeof(command[0]),L"\"%ls\" --child %d --shared %llu --iterations %llu",exe,c->id,(unsigned long long)(uintptr_t)mapping,(unsigned long long)timing_iterations);command[(sizeof(command)/sizeof(command[0]))-1]=0;
    if(!CreateProcessW(exe,command,NULL,NULL,TRUE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){abnormal(c,"harness_error","CreateProcessW_failed",GetLastError(),shared,0);goto out;}
    wait=WaitForSingleObject(pi.hProcess,timeout);
    if(wait==WAIT_TIMEOUT || wait==WAIT_FAILED) { TerminateProcess(pi.hProcess,0xe0000096u);killed=WaitForSingleObject(pi.hProcess,5000)==WAIT_OBJECT_0; }
    GetExitCodeProcess(pi.hProcess,&code);
    if(wait==WAIT_TIMEOUT){abnormal(c,"timeout","cell_watchdog_expired",code,shared,killed);if(!killed)ok=-1;goto out;}
    if(wait!=WAIT_OBJECT_0){abnormal(c,"harness_error","watchdog_wait_failed",code,shared,killed);if(!killed)ok=-1;goto out;}
    if(code!=0){abnormal(c,"crash","child_exited_nonzero_or_unhandled_exception",code,shared,1);goto out;}
    if(!GetFileSizeEx(log,&size) || size.QuadPart<=0 || size.QuadPart>1024*1024){abnormal(c,"harness_error","missing_or_oversized_child_output",code,shared,1);goto out;}
    bytes=(char *)malloc((size_t)size.QuadPart+1);if(!bytes){abnormal(c,"harness_error","parent_output_allocation_failed",code,shared,1);goto out;}
    SetFilePointerEx(log,zero,NULL,FILE_BEGIN);
    if(!ReadFile(log,bytes,(DWORD)size.QuadPart,&got,NULL) || got!=(DWORD)size.QuadPart){abnormal(c,"harness_error","child_output_read_failed",code,shared,1);goto out;}
    bytes[got]=0;
    { char expected[96],*nl;size_t src,dst;snprintf(expected,sizeof(expected),"CELL %d %s => {",c->id,family(c));
      for(src=dst=0;src<got;src++){if(bytes[src]=='\r' && src+1<got && bytes[src+1]=='\n')continue;bytes[dst++]=bytes[src];}bytes[dst]=0;
      nl=strchr(bytes,'\n');
      if(strncmp(bytes,expected,strlen(expected)) || !nl || (nl[1] && strncmp(nl+1,"TIMING {",8)) || strstr(nl+1,"CELL ")){abnormal(c,"harness_error","malformed_or_unexpected_child_output",code,shared,1);goto out;}
      fputs(bytes,stdout);ok=1;
    }
out:
    if(pi.hThread)CloseHandle(pi.hThread);if(pi.hProcess)CloseHandle(pi.hProcess);if(log!=INVALID_HANDLE_VALUE)CloseHandle(log);if(shared)UnmapViewOfFile(shared);if(mapping)CloseHandle(mapping);free(bytes);return ok;
}
#endif /* _WIN32 */

static int parse_int(const char *s,int *value) { char *end;long v;errno=0;v=strtol(s,&end,10);if(errno || !*s || *end || v<INT_MIN || v>INT_MAX)return 0;*value=(int)v;return 1; }
static int parse_u64(const char *s,uint64_t *value) { char *end;unsigned long long v;if(!*s || *s=='-')return 0;errno=0;v=strtoull(s,&end,10);if(errno || *end)return 0;*value=(uint64_t)v;return 1; }
static void usage(void) {
    printf("NEW-0095 single-C Windows x64 probe\nlist [first last]\ncell ID [--timeout-ms N]\nrange FIRST LAST [--timeout-ms N]\nstress [--timeout-ms N]\ntiming [--iterations N] [--timeout-ms N]\nemit ID EXISTING_DIRECTORY  (portable bytes only, no execution)\nselftest                   (portable generator tests only)\nIDs: %d..%d, observation %d..%d, stress %d..%d, timing %d..%d\nDefault watchdog: observation 10000 ms, stress 600000 ms, timing 120000 ms.\n",BASE_ID,BASE_ID+NCELLS-1,BASE_ID,BASE_ID+NOBS-1,BASE_ID+NOBS,BASE_ID+NOBS+NSTRESS-1,BASE_ID+NOBS+NSTRESS,BASE_ID+NCELLS-1);
}
/* Print a parent-produced CELL into a temporary C stream, replay all lines and
 * hash only the LF-terminated CELL line. This is independent of Windows CRT
 * stdout's text/binary defaults and never hashes META/TIMING. */
static int run_range(int first,int last,uint64_t override_timeout,uint64_t iterations) {
    int id,count=0,fatal=0;uint64_t hash=FNV_OFFSET;
#ifdef _WIN32
    Host h;if(!init_host(&h)){fprintf(stderr,"host initialization failed\n");return 2;}host_meta(&h);
#else
    printf("META {\"harness\":\"0095-single-c-v1\",\"target\":\"portable_catalog_only\",\"runtime\":\"NOT_RUN\"}\n");
    (void)override_timeout;(void)iterations;
#endif
    for(id=first;id<=last;id++) {
        Cell c;FILE *capture;char line[65536];int saved_fd;
        decode(id,&c);
        /* Redirection is only for the parent formatter, never for measured code. */
        capture=tmpfile();if(!capture)return 2;fflush(stdout);
#ifdef _WIN32
        saved_fd=_dup(_fileno(stdout));if(saved_fd<0 || _dup2(_fileno(capture),_fileno(stdout))!=0){fclose(capture);return 2;}
        fatal=supervise_to_file(&c,(DWORD)(override_timeout?override_timeout:(c.kind==1||c.kind==2?600000:c.kind==3?120000:10000)),iterations)<0;
        fflush(stdout);_dup2(saved_fd,_fileno(stdout));_close(saved_fd);
#else
        /* Portable execution never enters the Windows probe. Capture a simple
         * NOT_RUN record without redirecting process descriptors. */
        (void)saved_fd;
        fprintf(capture,"CELL %d %s => {\"axes\":{\"transition\":\"%s\",\"depth\":%d,\"frame\":\"%s\",\"flags\":\"%s\",\"mode\":\"%s\"},\"status\":\"NOT_RUN\",\"reason\":\"Windows_x64_runtime_required; portable_mode_never_executes_probe_code\",\"raw\":{},\"norm\":{}}\n",c.id,family(&c),flavors[c.flavor],c.depth,modes[c.mode],profiles[c.profile],family(&c));
#endif
        rewind(capture);
        while(fgets(line,sizeof(line),capture)) {
            size_t len=strlen(line);if(!len || line[len-1]!='\n'){fclose(capture);fprintf(stderr,"overlong/incomplete result\n");return 2;}
            fputs(line,stdout);if(!strncmp(line,"CELL ",5)){hash=fnv(hash,line,len);count++;}
        }fclose(capture);
        if(fatal)break;
    }
    printf("DONE count=%d checksum=%016" PRIx64 "\n",count,hash);return !fatal && count==last-first+1?0:2;
}
int main(int argc,char **argv) {
    int first=BASE_ID,last=BASE_ID+NOBS-1,i=2;uint64_t timeout=0,iterations=100000;Cell c;
#ifdef _WIN32
    _setmode(_fileno(stdout),_O_BINARY);
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);
    if(argc>=6 && !strcmp(argv[1],"--child")) {
        uint64_t handle=0;Shared *shared;
        if(!parse_int(argv[2],&first) || !decode(first,&c) || strcmp(argv[3],"--shared") || !parse_u64(argv[4],&handle))return 2;
        if(argc==7 && !strcmp(argv[5],"--iterations")){if(!parse_u64(argv[6],&iterations) || !iterations)return 2;}else return 2;
        shared=(Shared *)MapViewOfFile((HANDLE)(uintptr_t)handle,FILE_MAP_ALL_ACCESS,0,0,sizeof(Shared));if(!shared)return 2;
        i=child(&c,shared,iterations);fflush(stdout);UnmapViewOfFile(shared);return i;
    }
#endif
    if(argc<2){usage();return 0;}
    if(!strcmp(argv[1],"selftest"))return argc==2?selftest():2;
    if(!strcmp(argv[1],"emit")){if(argc!=4 || !parse_int(argv[2],&first) || !decode(first,&c))return 2;return portable_emit(&c,argv[3]);}
    if(!strcmp(argv[1],"list")) {
        last=BASE_ID+NCELLS-1;if(argc!=2 && (argc!=4 || !parse_int(argv[2],&first) || !parse_int(argv[3],&last)))return 2;
        if(!decode(first,&c) || !decode(last,&c) || first>last)return 2;
        for(i=first;i<=last;i++){decode(i,&c);printf("%d %s transition=%s depth=%d frame=%s flags=%s\n",i,family(&c),flavors[c.flavor],c.depth,modes[c.mode],profiles[c.profile]);}return 0;
    }
    if(!strcmp(argv[1],"cell")){if(argc<3 || !parse_int(argv[2],&first))return 2;last=first;i=3;}
    else if(!strcmp(argv[1],"range")){if(argc<4 || !parse_int(argv[2],&first) || !parse_int(argv[3],&last))return 2;i=4;}
    else if(!strcmp(argv[1],"stress")){first=BASE_ID+NOBS;last=first+NSTRESS-1;}
    else if(!strcmp(argv[1],"timing")){first=BASE_ID+NOBS+NSTRESS;last=BASE_ID+NCELLS-1;}
    else {usage();return 2;}
    while(i<argc) {
        if(i+1>=argc)return 2;
        if(!strcmp(argv[i],"--timeout-ms")){if(!parse_u64(argv[i+1],&timeout) || !timeout || timeout>=UINT32_MAX)return 2;}
        else if(!strcmp(argv[i],"--iterations")){if(strcmp(argv[1],"timing") || !parse_u64(argv[i+1],&iterations) || !iterations)return 2;}
        else return 2;
        i+=2;
    }
    if(!decode(first,&c) || !decode(last,&c) || first>last)return 2;
    return run_range(first,last,timeout,iterations);
}
